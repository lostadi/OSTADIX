"""Mock-only contracts for the interactive .O subject; no Guix or guest is run."""

import ast
import copy
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import termios
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch


SOURCE = Path(__file__).with_name('guix-session.O').read_text(encoding='utf-8')
assert SOURCE.startswith('python^(\n') and SOURCE.endswith(')_python\n')
BODY = SOURCE[len('python^(\n'):-len(')_python\n')]
CODE = compile(BODY, 'guix-session.O:python', 'exec')
GUIX_BIN = '/var/guix/profiles/per-user/root/current-guix/bin'


class Child:
    def __init__(self, owner, daemon):
        self.owner = owner
        self.daemon = daemon
        self.pid = 42001 if daemon else 42002
        self.returncode = owner.daemon_exit if daemon else None
        self.terminated = False
        self.killed = False
        self.waits = []

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        self.waits.append(timeout)
        if not self.daemon and not self.terminated and self.owner.client_event:
            event, self.owner.client_event = self.owner.client_event, None
            if event == 'interrupt':
                self.owner.handlers[signal.SIGINT](signal.SIGINT, None)
            raise subprocess.TimeoutExpired('mock Guix', timeout)
        if self.terminated and self.owner.terminate_stalls and not self.killed:
            raise subprocess.TimeoutExpired('mock direct-child cleanup', timeout)
        if self.returncode is None:
            self.returncode = self.owner.client_status
        return self.returncode

    def terminate(self):
        self.terminated = True
        if not self.owner.terminate_stalls:
            self.returncode = -signal.SIGTERM

    def kill(self):
        self.killed = True
        self.returncode = -signal.SIGKILL


class SessionHarness:
    """All OS interactions are replaced, including temporary-directory creation."""

    terminal = 71
    directory = '/tmp/o-guix-session-mocked'
    group = 41000
    previous_group = 40000

    def __init__(self, commands='install hello\nexit\n'):
        self.input = bytearray(commands.encode())
        self.env = {'OSTADIX_GUIX_SESSION_GUEST': '1', 'HOST_SECRET': 'not-forwarded'}
        self.platform = 'linux'
        self.uid = 0
        self.runtime_present = True
        self.interactive = True
        self.socket_mode = stat.S_IFSOCK | 0o600
        self.socket_uid = 0
        self.daemon_group = self.group
        self.daemon_exit = None
        self.client_status = 0
        self.client_event = None
        self.terminate_stalls = False
        self.input_ready = True
        self.fail_attribute_restore = False
        self.attributes = [0, 0, 0, 0, 0, 0, [b'\0'] * 32]
        self.attribute_writes = []
        self.group_writes = []
        self.handlers = {number: signal.SIG_DFL for number in
                         (signal.SIGINT, signal.SIGTERM, signal.SIGTTOU)}
        self.output = bytearray()
        self.children = []
        self.invocations = []
        self.select_timeouts = []
        self.namespace = {}
        self.open = Mock(return_value=self.terminal)
        self.close = Mock()
        self.unlink = Mock()
        self.rmdir = Mock()
        self.connect = Mock()

    def popen(self, argv, **kwargs):
        self.invocations.append((argv, kwargs))
        assert not {'shell', 'start_new_session', 'process_group', 'preexec_fn'} & kwargs.keys()
        assert 'HOST_SECRET' not in kwargs['env']
        daemon = argv[0] == GUIX_BIN + '/guix-daemon'
        assert daemon or argv[0] == GUIX_BIN + '/guix'
        child = Child(self, daemon)
        self.children.append(child)
        return child

    def change_signal(self, number, handler):
        previous = self.handlers[number]
        self.handlers[number] = handler
        return previous

    def change_attributes(self, fd, when, attributes):
        assert fd == self.terminal and when == termios.TCSANOW
        assert self.handlers[signal.SIGTTOU] == signal.SIG_IGN
        self.attribute_writes.append(copy.deepcopy(attributes))
        if self.fail_attribute_restore and attributes == self.attributes:
            raise termios.error('mock attribute restoration failure')

    def change_group(self, fd, group):
        assert fd == self.terminal
        assert self.handlers[signal.SIGTTOU] == signal.SIG_IGN
        self.group_writes.append(group)

    def read(self, fd, size):
        assert fd == self.terminal and size == 1
        byte = bytes(self.input[:1])
        del self.input[:1]
        return byte

    def write(self, fd, data):
        assert fd == self.terminal
        self.output.extend(data)
        return len(data)

    def select(self, readers, writers, exceptional, timeout):
        assert readers == [self.terminal] and writers == exceptional == []
        assert 0 < timeout <= 3595
        self.select_timeouts.append(timeout)
        return (readers if self.input_ready else []), [], []

    def socket_stat(self, path):
        assert path == self.directory + '/daemon.sock'
        return SimpleNamespace(st_mode=self.socket_mode, st_uid=self.socket_uid)

    def run(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.connect = self.connect
        replacements = {
            'sys.platform': self.platform,
            'time.monotonic': Mock(return_value=0),
            'time.sleep': Mock(side_effect=AssertionError('Unexpected readiness retry')),
            'os.geteuid': Mock(return_value=self.uid),
            'os.path.isfile': Mock(return_value=self.runtime_present),
            'os.access': Mock(return_value=True),
            'os.open': self.open,
            'os.close': self.close,
            'os.isatty': Mock(return_value=self.interactive),
            'os.getpgrp': Mock(return_value=self.group),
            'os.getpgid': Mock(return_value=self.daemon_group),
            'os.tcgetpgrp': Mock(return_value=self.previous_group),
            'os.tcsetpgrp': self.change_group,
            'os.read': self.read,
            'os.write': self.write,
            'os.stat': self.socket_stat,
            'os.unlink': self.unlink,
            'os.rmdir': self.rmdir,
            'os.killpg': Mock(side_effect=AssertionError('Must not signal an inherited group')),
            'os.setsid': Mock(side_effect=AssertionError('Must not leave O containment')),
            'signal.signal': self.change_signal,
            'termios.tcgetattr': Mock(return_value=self.attributes),
            'termios.tcsetattr': self.change_attributes,
            'select.select': self.select,
            'socket.socket': Mock(return_value=connection),
            'tempfile.mkdtemp': Mock(return_value=self.directory),
            'subprocess.Popen': self.popen,
        }
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, self.env, clear=True))
            for name, replacement in replacements.items():
                stack.enter_context(patch(name, replacement))
            exec(CODE, self.namespace)
        return self.namespace['__oval_result__']


class InteractiveGuixSessionTests(unittest.TestCase):
    def assert_restored(self, harness):
        self.assertEqual(harness.group_writes, [harness.group, harness.previous_group])
        self.assertEqual(harness.attribute_writes[-1], harness.attributes)
        self.assertTrue(all(handler == signal.SIG_DFL for handler in harness.handlers.values()))
        harness.close.assert_called_once_with(harness.terminal)
        harness.unlink.assert_called_once_with(harness.directory + '/daemon.sock')
        harness.rmdir.assert_called_once_with(harness.directory)

    def test_matching_single_block_and_python_syntax(self):
        tree = ast.parse(BODY)
        self.assertIsInstance(tree.body[-1], ast.Assign)
        self.assertEqual(tree.body[-1].targets[0].id, '__oval_result__')

    def test_guards_prevent_host_or_missing_runtime_execution(self):
        for change in ('marker', 'platform', 'root', 'runtime', 'budget'):
            with self.subTest(change=change):
                harness = SessionHarness()
                if change == 'marker':
                    harness.env.pop('OSTADIX_GUIX_SESSION_GUEST')
                elif change == 'platform':
                    harness.platform = 'darwin'
                elif change == 'root':
                    harness.uid = 501
                elif change == 'runtime':
                    harness.runtime_present = False
                else:
                    harness.env['O_BACKEND_OPERATION_TIMEOUT_MS'] = '5000'
                with self.assertRaises(RuntimeError):
                    harness.run()
                harness.open.assert_not_called()
                self.assertEqual(harness.invocations, [])

    def test_actual_guix_argv_private_socket_and_terminal_contract(self):
        harness = SessionHarness()
        self.assertEqual(harness.run(), {'commands': 1, 'last_exit_code': 0, 'session': 'closed'})
        harness.open.assert_called_once_with('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
        daemon, client = harness.invocations
        self.assertEqual(daemon[0], [GUIX_BIN + '/guix-daemon',
                         '--listen=' + harness.directory + '/daemon.sock', '--build-users-group=',
                         '--max-jobs=1', '--cores=1', '--no-offload', '--discover=no'])
        self.assertEqual(client[0], [GUIX_BIN + '/guix', 'install', 'hello'])
        self.assertEqual(daemon[1]['stdin'], subprocess.DEVNULL)
        self.assertEqual(client[1]['cwd'], '/root')
        for _, arguments in harness.invocations:
            self.assertEqual(arguments['stdout'], harness.terminal)
            self.assertEqual(arguments['stderr'], harness.terminal)
            self.assertEqual(arguments['env']['GUIX_DAEMON_SOCKET'], harness.directory + '/daemon.sock')
            self.assertEqual(arguments['env']['HOME'], '/root')
            self.assertNotIn('OSTADIX_GUIX_SESSION_GUEST', arguments['env'])
        self.assertEqual(client[1]['stdin'], harness.terminal)
        session_attributes = harness.attribute_writes[0]
        self.assertTrue(session_attributes[0] & termios.ICRNL)
        self.assertTrue(session_attributes[1] & termios.OPOST)
        self.assertTrue(session_attributes[3] & termios.ICANON)
        self.assertTrue(session_attributes[3] & termios.ISIG)
        self.assertEqual(session_attributes[6][termios.VINTR], b'\x03')
        self.assertEqual(session_attributes[6][termios.VEOF], b'\x04')
        self.assertTrue(harness.children[0].terminated)
        self.assertFalse(harness.children[1].terminated)
        harness.connect.assert_called_once_with(harness.directory + '/daemon.sock')
        self.assertIn(b'Guix exit status: 0', harness.output)
        self.assert_restored(harness)

    def test_shlex_is_direct_argv_not_shell_expansion(self):
        harness = SessionHarness("guix install 'hello world' ';touch /tmp/not-run'\nexit\n")
        harness.run()
        self.assertEqual(harness.invocations[1][0],
                         [GUIX_BIN + '/guix', 'install', 'hello world', ';touch /tmp/not-run'])

    def test_invalid_quote_reports_error_and_allows_another_command(self):
        harness = SessionHarness("install 'unterminated\npackage --list-installed\nquit\n")
        self.assertEqual(harness.run()['commands'], 1)
        self.assertIn(b'Command syntax:', harness.output)
        self.assertEqual(harness.invocations[1][0][1:], ['package', '--list-installed'])

    def test_nonzero_real_status_is_reported_and_not_success(self):
        harness = SessionHarness()
        harness.client_status = 7
        with self.assertRaisesRegex(RuntimeError, 'exit status 7'):
            harness.run()
        self.assertIn(b'Guix exit status: 7', harness.output)
        self.assertNotIn('__oval_result__', harness.namespace)
        self.assert_restored(harness)

    def test_terminal_eof_closes_session_without_spawning_a_client(self):
        harness = SessionHarness('')
        self.assertEqual(harness.run()['commands'], 0)
        self.assertEqual(len(harness.children), 1)
        self.assert_restored(harness)

    def test_cancel_and_timeout_stop_only_direct_handles_then_restore_tty(self):
        for event in ('interrupt', 'timeout'):
            with self.subTest(event=event):
                harness = SessionHarness()
                harness.client_event = event
                expected = RuntimeError if event == 'interrupt' else subprocess.TimeoutExpired
                with self.assertRaises(expected):
                    harness.run()
                self.assertTrue(all(child.terminated for child in harness.children))
                self.assertNotIn('__oval_result__', harness.namespace)
                self.assert_restored(harness)

    def test_direct_handle_cleanup_escalates_and_reaps_with_bounded_waits(self):
        harness = SessionHarness('exit\n')
        harness.terminate_stalls = True
        harness.run()
        child = harness.children[0]
        self.assertTrue(child.terminated and child.killed)
        self.assertEqual(child.waits, [1, 1])
        self.assert_restored(harness)

    def test_invalid_socket_or_direct_daemon_group_fails_closed(self):
        for change in ('type', 'owner', 'group', 'exited'):
            with self.subTest(change=change):
                harness = SessionHarness()
                if change == 'type':
                    harness.socket_mode = stat.S_IFREG | 0o600
                elif change == 'owner':
                    harness.socket_uid = 501
                elif change == 'group':
                    harness.daemon_group = 99000
                else:
                    harness.daemon_exit = 1
                with self.assertRaises(RuntimeError):
                    harness.run()
                self.assertEqual(len(harness.invocations), 1)
                harness.connect.assert_not_called()
                self.assert_restored(harness)

    def test_missing_terminal_does_not_start_daemon(self):
        harness = SessionHarness()
        harness.interactive = False
        with self.assertRaisesRegex(RuntimeError, 'interactive guest terminal'):
            harness.run()
        self.assertEqual(harness.invocations, [])
        harness.close.assert_called_once_with(harness.terminal)

    def test_input_deadline_or_invalid_input_cleans_up(self):
        for change in ('timeout', 'nul', 'length'):
            with self.subTest(change=change):
                harness = SessionHarness()
                if change == 'timeout':
                    harness.input_ready = False
                else:
                    harness.input = bytearray(b'\0\n' if change == 'nul' else b'x' * 4097 + b'\n')
                with self.assertRaises(RuntimeError):
                    harness.run()
                self.assertEqual(len(harness.children), 1)
                self.assert_restored(harness)

    def test_attribute_restore_failure_still_restores_group_and_handlers(self):
        harness = SessionHarness('exit\n')
        harness.fail_attribute_restore = True
        with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
            harness.run()
        self.assert_restored(harness)

    def test_budget_matches_positive_u64_default_and_clamp(self):
        harness = SessionHarness('exit\n')
        harness.run()
        parse = harness.namespace['operation_milliseconds']
        for raw in ('', '0', '-1', ' 6000', '6000 ', 'abc', '18446744073709551616', '+' * 2 + '1'):
            with self.subTest(raw=raw):
                self.assertEqual(parse(raw), 60000)
        for raw, expected in (('1', 1), ('+0006000', 6000), ('0' * 100 + '6000', 6000),
                              ('3600001', 3600000), ('18446744073709551615', 3600000)):
            with self.subTest(raw=raw):
                self.assertEqual(parse(raw), expected)
        self.assertEqual(harness.select_timeouts[0], 55)


if __name__ == '__main__':
    unittest.main()
