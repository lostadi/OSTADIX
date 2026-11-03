"""Strace parsing and unavailable-tool oracles; no VM or host installation."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("posix_baseline_trace_test",
                                             ROOT / "scripts/trace_okernel_posix_baseline.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class TraceParserTests(unittest.TestCase):
    def test_interleaved_resumed_calls_keep_pid_original_entry_and_exact_fragments(self):
        trace = ('[pid 11] 1700000000.000001 read(3</tmp/a(,])>,  <unfinished ...>\n'
                 '[pid 12] 1700000000.000002 write(1, "\\x78", 1) = 1\n'
                 '[pid 11] 1700000000.000003 <... read resumed>"\\x00\\xff", 2) = 2\n'
                 '[pid 12] 1700000000.000004 +++ exited with 0 +++\n'
                 '[pid 11] 1700000000.000005 +++ exited with 0 +++\n')
        events = module.parse_trace(trace)
        calls = [event for event in events if event['kind'] == 'syscall']
        self.assertEqual([event['name'] for event in calls], ['write', 'read'])
        resumed = calls[1]
        self.assertEqual(resumed['pid'], 11)
        self.assertEqual(resumed['timestamp'], '1700000000.000001')
        self.assertEqual(resumed['finished_timestamp'], '1700000000.000003')
        self.assertEqual(resumed['arguments'], '3</tmp/a(,])>,  "\\x00\\xff", 2')
        self.assertEqual(resumed['return_value'], 2)
        self.assertEqual(len(resumed['raw']), 2)
        self.assertEqual(module.summarize(events)['syscall_entries'], 2)

    def test_errno_nonzero_exit_signals_and_restart_are_not_success_inventions(self):
        trace = ('10 openat(AT_FDCWD, "missing", O_RDONLY) = -1 ENOENT (No such file or directory)\n'
                 '10 read(0, 0x1000, 8) = ? ERESTARTSYS (To be restarted if SA_RESTART is set)\n'
                 '10 --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_USER} ---\n'
                 '10 read(0, "ok", 2) = 2\n'
                 '10 exit_group(1) = ?\n'
                 '10 +++ exited with 1 +++\n')
        events = module.parse_trace(trace)
        summary = module.summarize(events)
        self.assertEqual(summary['errnos'], {'ENOENT': 1, 'ERESTARTSYS': 1})
        self.assertEqual(summary['dispositions'], {'error': 1, 'interrupted-restart': 1, 'nonreturning': 1, 'returned': 1})
        self.assertEqual(summary['process_exits'][0]['exit_status'], 1)
        self.assertEqual(summary['signals'], 1)
        self.assertEqual(summary['syscalls']['read'], 2, 'counts describe observed kernel entries, not user-level call count')

    def test_fd_hex_octal_and_zero_results_keep_original_return_text(self):
        for raw, value in [('3</tmp/file>', 3), ('0x7fa00000', 0x7fa00000), ('022', 0o22), ('0', 0)]:
            with self.subTest(raw=raw):
                result = module.return_result(raw)
                self.assertEqual(result['return_value'], value)
                self.assertEqual(result['return_text'], raw)
                self.assertEqual(result['disposition'], 'returned')

    def test_process_death_preserves_unfinished_call_without_return_or_success(self):
        events = module.parse_trace('read(0,  <unfinished ...>\n+++ killed by SIGKILL +++\n', 101)
        self.assertEqual(events[0]['disposition'], 'unfinished-at-termination')
        self.assertIsNone(events[0]['return_value'])
        self.assertEqual(events[1]['kind'], 'killed')
        self.assertNotIn('returned', module.summarize(events)['dispositions'])

    def test_unknown_return_requires_explicit_death_and_never_becomes_success(self):
        events = module.parse_trace('read(0, 0x1000, 4) = ?\n+++ killed by SIGKILL +++\n', 101)
        self.assertEqual(events[0]['disposition'], 'unavailable-at-termination')
        with self.assertRaises(module.TraceError):
            module.parse_trace('read(0, 0x1000, 4) = ?\n+++ exited with 0 +++\n', 101)
        with self.assertRaises(module.TraceError):
            module.parse_trace('exit_group(0) = ?\ngetpid() = 101\n+++ exited with 0 +++\n', 101)

    def test_sendfile_source_stdin_is_io_even_before_read_fallback(self):
        self.assertTrue(module.stdin_io({'name': 'sendfile', 'arguments': '1<pipe:[2]>, 0<pipe:[1]>, NULL, 16777216'}))
        self.assertFalse(module.stdin_io({'name': 'sendfile', 'arguments': '1<pipe:[2]>, 3</input>, NULL, 16777216'}))
        self.assertTrue(module.stdin_io({'name': 'read', 'arguments': '0<pipe:[1]>, "x", 1'}))

    def test_unmatched_incomplete_diagnostic_and_malformed_traces_fail_closed(self):
        malformed = [
            '<... read resumed>"x", 1) = 1\n+++ exited with 0 +++\n',
            'read(0,  <unfinished ...>\n',
            'read(0,  <unfinished ...>\n<... write resumed>"x", 1) = 1\n+++ exited with 0 +++\n',
            'read(0, <unfinished ...>\nwrite(1, <unfinished ...>\n+++ killed by SIGKILL +++\n',
            'read(0, <unfinished ...>\nwrite(1, "x", 1) = 1\n<... read resumed>"x", 1) = 1\n+++ exited with 0 +++\n',
            'read(0, ["x", 1) = 1\n+++ exited with 0 +++\n',
            'read(0, "x", 1) = invented\n+++ exited with 0 +++\n',
            'getpid() = 10 nonsense\n+++ exited with 0 +++\n',
            'strace: Process 44 detached\n',
            '+++ exited with 0 +++\ngetpid() = 1\n',
            'getpid() = 1\n',
        ]
        for text in malformed:
            with self.subTest(trace=text), self.assertRaises(module.TraceError):
                module.parse_trace(text, 44)

    def test_quotes_nested_structures_and_mb_lines_are_not_split_or_truncated(self):
        payload = '\\x00' * 262144
        trace = 'write(1<pipe:[1]>, "' + payload + '", 262144) = 262144\n+++ exited with 0 +++\n'
        event = module.parse_trace(trace, 90)[0]
        self.assertEqual(len(event['arguments']), len('1<pipe:[1]>, "", 262144') + len(payload))
        self.assertEqual(event['raw'][0], trace.splitlines()[0])
        module.balanced('{a=[1,2], b="quoted ),]\\\"text"}, 0')


class CollectionBoundaryTests(unittest.TestCase):
    def test_unavailable_strace_never_produces_observed_or_pass_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'new-evidence'
            with patch.object(module, 'STRACE', Path(directory) / 'absent-strace'), \
                    patch.object(sys, 'argv', ['trace-baseline', '--output', str(output)]), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(module.main(), 1)
            record = json.loads((output / 'result.json').read_text())
            self.assertFalse(record['ok'])
            self.assertEqual(record['status'], 'unavailable')
            self.assertNotIn('observed_syscall_counts', record)
            self.assertNotIn('cases', record)

    def test_existing_evidence_directory_is_never_reused_or_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            marker = output / 'retained'
            marker.write_bytes(b'old evidence')
            with patch.object(sys, 'argv', ['trace-baseline', '--output', str(output)]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                module.main()
            self.assertEqual(caught.exception.code, 2)
            self.assertEqual(marker.read_bytes(), b'old evidence')
            self.assertFalse((output / 'result.json').exists())


if __name__ == '__main__':
    unittest.main()
