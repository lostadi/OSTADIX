"""Check foreground timing markers and PTY-read clock boundaries without a VM."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("unified_latency_test", ROOT / "scripts/verify_okernel_unified_latency.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class ForegroundLatencyTests(unittest.TestCase):
    def test_short_actual_input_echo_cannot_satisfy_output_or_completion(self):
        line, first, done = GATE.command("012345abcdef")
        self.assertLess(len(line.rstrip(b"\n")) + len(b"okernel> "), 80)
        self.assertEqual(GATE.observed(b"okernel> " + line, first, done), (False, None))
        compile(GATE.HELPER, "after-timing-native-validation", "exec")
        for token in ("", "bad\ninput", "x" * 12, "a" * 11):
            with self.subTest(token=token), self.assertRaises(ValueError):
                GATE.command(token)

    def test_only_completed_bare_original_output_lines_are_accepted(self):
        _, first, done = GATE.command("012345abcdef")
        self.assertEqual(GATE.observed(first, first, done), (False, None))
        self.assertEqual(GATE.observed(b"prefix " + first + b"\r\n", first, done), (False, None))
        self.assertEqual(GATE.observed(first + b"\r\n" + done + b":0", first, done), (True, None))
        self.assertEqual(GATE.observed(first + b"\r\n" + done + b":0\r\n", first, done), (True, 0))
        self.assertEqual(GATE.observed(done + b":125\n", first, done), (False, 125))
        for bad in (done + b":no\n", done + b":0\n" + done + b":0\n"):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                GATE.observed(bad, first, done)

    def test_first_output_and_cli_return_are_timestamped_on_separate_pty_reads(self):
        _, first, done = GATE.command("012345abcdef")
        terminal = object.__new__(GATE.TimedTerminal)
        terminal.capture = bytearray()
        terminal.active = {"offset": 0, "first": first, "done": done,
                           "first_time": None, "complete_time": None, "exit_code": None}
        chunks = iter((first + b"\n", done + b":0\n"))
        def read(_, duration):
            terminal.capture.extend(next(chunks))
        with mock.patch.object(GATE.Terminal, "pump", read), mock.patch.object(GATE.time, "monotonic", side_effect=[11., 12.]):
            terminal.pump(.02)
            self.assertEqual(terminal.active["first_time"], 11.)
            self.assertIsNone(terminal.active["complete_time"])
            terminal.pump(.02)
        self.assertEqual(terminal.active["complete_time"], 12.)
        self.assertEqual(terminal.active["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
