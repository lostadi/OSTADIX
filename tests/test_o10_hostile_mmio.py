"""Additional hostile gate rejects unrelated faults and false survivor proofs."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hostile_gate_test", ROOT / "scripts/verify_o10_hostile_mmio.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class HostileMMIOGateTests(unittest.TestCase):
    def run_fault(self, *, ipa=0x0a0000fc, esr=0x24 << 26, witness=b"0\n",
                  new_domain=False, command_error=False, provider_ok=True):
        domain = MagicMock()
        domain.o10_plan9 = 0x100000001
        domain.session = Path("/unused-private-fixture")
        before = dict(dom=domain.o10_plan9, inst=b"same-instance", state=2)
        after = dict(before, dom=domain.o10_plan9 + (1 << 32) if new_domain else domain.o10_plan9)
        domain.o10_call.side_effect = [before, dict(state=4, esr=esr, ipa=ipa), after]
        domain.native_volume.return_value.get.return_value = b"0\n1\n2\n3\n4\n5\n6\n7\n"
        if command_error:
            domain.command.side_effect = RuntimeError("devmem unavailable")
        invocation = dict(id="qualified-fixture-request")
        with patch.object(gate.provider, "submit", return_value=invocation) as submit, \
             patch.object(gate.provider, "wait_file", return_value=witness), \
             patch.object(gate.provider, "finished", return_value=(SimpleNamespace(ok=provider_ok), {})) as finished, \
             patch.object(gate.provider, "save_capture") as saved:
            record = {}
            try:
                gate.fault_linux(domain, 0x100000000, record)
            finally:
                self.domain, self.record = domain, record
                self.submit, self.finished, self.saved = submit, finished, saved
        return record

    def test_actual_mmio_sent_once_with_original_provider_witness(self):
        record = self.run_fault()
        self.domain.command.assert_called_once()
        self.domain.send.assert_called_once_with(b"\x1e0\x1e0\x15busybox devmem 0x0a0000fc 32 1\n")
        self.assertTrue(all(call.args[0] == "Tstat" for call in self.domain.o10_call.call_args_list))
        self.assertEqual(record["linux_fault"]["ipa"], 0x0a0000fc)
        self.assertTrue(record["plan9_counter"]["after"].startswith(record["plan9_counter"]["before"]))
        self.finished.assert_called_once()
        self.saved.assert_called_once()

    def test_devmem_probe_failure_never_injects_or_submits(self):
        with self.assertRaisesRegex(RuntimeError, "devmem unavailable"):
            self.run_fault(command_error=True)
        self.submit.assert_not_called()
        self.domain.send.assert_not_called()
        self.domain.o10_call.assert_not_called()

    def test_unrelated_fault_address_fails(self):
        with self.assertRaisesRegex(RuntimeError, "identify"):
            self.run_fault(ipa=0)
        self.finished.assert_not_called()

    def test_non_mmio_exception_fails(self):
        with self.assertRaisesRegex(RuntimeError, "identify"):
            self.run_fault(esr=0x16 << 26)
        self.finished.assert_not_called()

    def test_already_finished_counter_cannot_prove_survival(self):
        with self.assertRaisesRegex(RuntimeError, "advance"):
            self.run_fault(witness=b"0\n1\n2\n3\n4\n5\n6\n7\n")
        self.saved.assert_not_called()

    def test_replaced_plan9_cannot_prove_survival(self):
        with self.assertRaisesRegex(RuntimeError, "changed instance"):
            self.run_fault(new_domain=True)
        self.saved.assert_not_called()

    def test_failed_provider_result_is_not_accepted(self):
        with self.assertRaisesRegex(RuntimeError, "workload failed"):
            self.run_fault(provider_ok=False)
        self.saved.assert_not_called()


if __name__ == "__main__":
    unittest.main()
