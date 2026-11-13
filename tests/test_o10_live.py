"""Negative controls for the live O10 gate's raw host-shim probe."""
import importlib.util
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("o10_live_gate", ROOT / "scripts/verify_o10_live.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

class O10LiveProbeTests(unittest.TestCase):
    def domain(self):
        return SimpleNamespace(control_sequence=0, stopped=Mock(), write_native=Mock(),
                               qmp=SimpleNamespace(execute=Mock()), ram=99,
                               process=SimpleNamespace(poll=Mock(return_value=None)), pump=Mock())

    def memory(self, reply):
        def read(fd, size, offset):
            self.assertEqual(fd, 99)
            if offset == 0x6d000080 - 0x40000000:
                return struct.pack("<QQ", 1, 1)
            self.assertEqual(offset, gate.runner.O10_PROFILE["completion"] - 0x40000000)
            return reply[:size]
        return read

    def test_native_incomplete_header_error_has_zero_tag(self):
        domain = self.domain()
        frame = struct.pack("<IBH", 6, 178, 32002)
        reply = gate.o10.encode("Rerror", 0, code=gate.o10.O10_EBADMSG, detail=0)
        with patch.object(gate.os, "pread", side_effect=self.memory(reply)):
            wire, decoded = gate.exchange_raw(domain, frame)
        self.assertEqual(wire, reply)
        self.assertEqual(decoded["tag"], 0)
        self.assertEqual(domain.control_sequence, 1)
        self.assertEqual(domain.write_native.call_count, 2)
        self.assertEqual(domain.write_native.call_args_list[0].args[1], frame)

    def test_complete_header_wrong_reply_tag_rejected(self):
        domain = self.domain()
        frame = struct.pack("<IBH", 7, 100, 32001)
        reply = gate.o10.encode("Rerror", 32000, code=gate.o10.O10_EBADMSG, detail=4)
        with patch.object(gate.os, "pread", side_effect=self.memory(reply)):
            with self.assertRaisesRegex(RuntimeError, "reply tag"):
                gate.exchange_raw(domain, frame)
        self.assertEqual(domain.write_native.call_count, 2)
        self.assertEqual(domain.qmp.execute.call_args.args, ("cont",))

    def test_unknown_outcome_is_never_resubmitted(self):
        domain = self.domain()
        frame = gate.o10.encode("Twithdraw", 9, epoch=1, seq=2,
                               dom=(1 << 32) | 1, mode=0, deadline_ms=0)
        with patch.object(gate.time, "monotonic", side_effect=[0, 61]):
            with self.assertRaisesRegex(TimeoutError, "not replayed"):
                gate.exchange_raw(domain, frame)
        self.assertEqual(domain.control_sequence, 1)
        self.assertEqual(domain.write_native.call_count, 2)
        domain.stopped.assert_called_once()

if __name__ == "__main__":
    unittest.main()
