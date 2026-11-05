"""Protected logout notices queue once; console text never requests saving."""
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("unified_console_exit", ROOT / "scripts/okernel_unified_world.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class UnifiedConsoleExitTests(unittest.TestCase):
    def setUp(self):
        self.domain = runner.UnifiedDomain.__new__(runner.UnifiedDomain)
        self.domain.service = {"generation": "1234567890abcdef", "instance": "a" * 32}
        self.domain.console_exit_seen = set()
        self.domain.console_exit_request = None
        self.domain.coordinator_events = []
        self.domain.coordinator_read = Mock(return_value=[])
        self.domain.record = {}
        self.domain.recycle_plan9 = Mock()
        self.event = {"event": "console-exit", "generation": "1234567890abcdef", "request_id": "b" * 32}

    @unittest.skipUnless(shutil.which("busybox"), "original BusyBox shell required")
    def test_detached_controller_launch_parses_with_command_status_suffix(self):
        command = runner.COORDINATOR_START + "; _uw_rc=$?; printf '%s\\n' \"$_uw_rc\""
        result = subprocess.run([shutil.which("busybox"), "sh", "-n", "-c", command],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_private_notice_consumed_once_without_native_recycle(self):
        self.domain.coordinator_read.return_value = [self.event, dict(self.event)]
        self.domain.watch_guest_coordinator()
        self.assertEqual(self.domain.take_console_exit_request(), self.event)
        self.assertIsNone(self.domain.take_console_exit_request())
        self.domain.watch_guest_coordinator()  # retransmission remains consumed
        self.assertIsNone(self.domain.take_console_exit_request())
        self.assertEqual(len(self.domain.record["console_exit_requests"]), 1)
        self.domain.recycle_plan9.assert_not_called()

    def test_old_coordinator_generation_cannot_close_current_console(self):
        self.domain.coordinator_read.return_value = [{**self.event, "generation": "ffffffffffffffff"}]
        self.domain.watch_guest_coordinator()
        self.assertIsNone(self.domain.take_console_exit_request())
        self.assertEqual(self.domain.record, {})

    def test_provider_replacement_does_not_invalidate_operator_logout(self):
        self.domain.service["instance"] = "c" * 32
        self.domain.coordinator_read.return_value = [self.event]
        self.domain.watch_guest_coordinator()
        self.assertEqual(self.domain.take_console_exit_request(), self.event)

    def test_malformed_identity_is_rejected_before_save_or_reset(self):
        self.domain.coordinator_read.return_value = [{**self.event, "request_id": "not-hex"}]
        with self.assertRaises(ValueError):
            self.domain.watch_guest_coordinator()
        self.assertIsNone(self.domain.take_console_exit_request())
        self.domain.recycle_plan9.assert_not_called()

    def test_notice_after_frame_ack_in_same_read_is_retained(self):
        self.domain.control_active = False
        self.domain.control_sequence = 0
        self.domain.client_session = Mock(return_value={"state": "ready"})
        self.domain.native_control = Mock()
        self.domain.pump = Mock()
        frame = json.dumps({"seq": 1, "current": {"state": "ready"}}, sort_keys=True, separators=(",", ":")).encode()
        ack = {"seq": 1, "sha256": hashlib.sha256(frame).hexdigest(), "ok": True}
        self.domain.coordinator_read.return_value = [ack, self.event]
        self.domain.coordinator_update()
        self.assertEqual(self.domain.coordinator_events, [self.event])
        self.domain.coordinator_read.return_value = []
        self.domain.watch_guest_coordinator()
        self.assertEqual(self.domain.take_console_exit_request(), self.event)
        self.domain.pump.assert_not_called()


if __name__ == "__main__":
    unittest.main()
