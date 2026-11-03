"""Separate strict userland admission; no VM or persistent-state operations."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("unified_builder_admission", ROOT / "scripts/build_okernel_unified_world.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
QUALIFIED = Path.home() / ".cache/okernel-plan9-userland/build-7"
OLD = Path.home() / ".local/state/ostadix/okernel/plan9-native-rebuild-20261102-r3"


class AdmissionBoundaryTests(unittest.TestCase):
    def test_recovery_geometry_is_private_disjoint_and_inside_outer_ram(self):
        contract = builder.plan9_recovery_contract(6050448, 530)
        self.assertEqual((contract["control_address"], contract["control_bytes"]), (0x6d000070, 48))
        self.assertEqual((contract["pause"], contract["restart"]), (1, 2))
        backups = [(contract["kernel_backup_address"], contract["kernel_max_bytes"]),
                   (contract["dtb_backup_address"], contract["dtb_max_bytes"])]
        protected = [(0x48000000, 0x20000000), (0xb0000000, 0x20000000),
                     (0x70000000, 0x40000000), (0x6c000000, 0x02000000), (0x6e000000, 0x200000)]
        for start, length in backups:
            self.assertGreaterEqual(start, 0x40000000)
            self.assertLessEqual(start + length, 0x100000000)
            for other, count in protected:
                self.assertFalse(start < other + count and other < start + length)
        self.assertLessEqual(backups[0][0] + backups[0][1], backups[1][0])

    def test_recovery_backup_size_limits_are_strict(self):
        builder.plan9_recovery_contract(0x1000000, 0x10000)
        for kernel, dtb in [(0, 1), (1, 0), (0x1000001, 1), (1, 0x10001), (-1, 1)]:
            with self.subTest(kernel=kernel, dtb=dtb), self.assertRaises(ValueError):
                builder.plan9_recovery_contract(kernel, dtb)

    def test_old_receipt_delegates_to_unchanged_legacy_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "old.json"
            receipt.write_text(json.dumps({"schema": "ostadix.original9front-native-builder/v1"}))
            kernel = {"bytes": 12, "sha256": "legacy-fixture"}
            legacy = SimpleNamespace(admit_derivation=mock.Mock(return_value={"source_commit": "legacy-pin"}))
            admitted = builder.admit_plan9_derivation(receipt, kernel, legacy)
            legacy.admit_derivation.assert_called_once_with(receipt, kernel)
            self.assertEqual(admitted["admission_kind"], "original-kernel")

    def test_new_passed_flag_cannot_fall_back_to_legacy_or_authorize_kernel(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "forged.json"
            receipt.write_text(json.dumps({"schema": "ostadix.original9front-userland-builder/v1", "ok": True}))
            legacy = SimpleNamespace(admit_derivation=mock.Mock())
            with self.assertRaisesRegex(ValueError, "qualified build7 pin"):
                builder.admit_plan9_derivation(receipt, {}, legacy)
            legacy.admit_derivation.assert_not_called()

    def test_nonobject_receipt_rejected_cleanly(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "wrong.json"
            receipt.write_text("[]")
            with self.assertRaisesRegex(ValueError, "must be an object"):
                builder.admit_plan9_derivation(receipt, {}, None)

    def test_capture_remains_bound_to_admitted_bytes_during_race(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"qualified")
            expected = builder.identity(source)
            source.write_bytes(b"substitute")
            with self.assertRaisesRegex(ValueError, "changed while capturing"):
                builder.capture_expected(expected, Path(directory) / "new/snapshot")
            self.assertEqual(source.read_bytes(), b"substitute")


@unittest.skipUnless((QUALIFIED / "FROZEN.json").is_file(), "qualified original9front artifact cache unavailable")
class QualifiedUserlandTests(unittest.TestCase):
    def setUp(self):
        self.receipt = QUALIFIED / "result.json"
        self.kernel = builder.identity(QUALIFIED / "artifacts/KERNEL.U")

    def test_complete_real_original_closure_and_background_provider_accepted(self):
        admitted = builder.admit_userland_derivation(self.receipt, self.kernel)
        self.assertEqual(admitted["admission_kind"], "qualified-original-userland")
        self.assertEqual(admitted["provider_admission"]["files"], 239)
        self.assertEqual(admitted["provider_admission"]["bytes"], 13163590)
        self.assertEqual(admitted["provider_admission"]["service"]["sha256"], builder.SERVICE_SHA)
        self.assertEqual(admitted["provider_admission"]["startup"]["sha256"], builder.STARTUP_SHA)
        self.assertIn("artifacts/USER.PAQ", admitted["admission_copies"])
        self.assertIn("artifacts/USER.TAR", admitted["admission_copies"])

    def test_replaced_frozen_receipt_rejected_without_mutating_cache(self):
        original = builder.fingerprint
        path = QUALIFIED / "FROZEN.json"
        with mock.patch.object(builder, "fingerprint", side_effect=lambda p: "0" * 64 if Path(p) == path else original(p)):
            with self.assertRaisesRegex(ValueError, "FROZEN receipt"):
                builder.admit_userland_derivation(self.receipt, self.kernel)

    def test_mutated_service_paq_kernel_wrapper_and_platform_are_rejected(self):
        original = builder.fingerprint
        cases = [QUALIFIED / "artifacts" / name for name in ("SERVICE", "USER.PAQ", "KERNEL.U")]
        cases += [QUALIFIED / "inputs" / name for name in ("START.RC", "UART.C")]
        cases += [QUALIFIED / "builder.dtb"]
        for changed in cases:
            with self.subTest(changed=changed.name), mock.patch.object(builder, "fingerprint", side_effect=lambda p: "0" * 64 if Path(p) == changed else original(p)):
                with self.assertRaisesRegex(ValueError, "frozen Plan9 derivation evidence changed"):
                    builder.admit_userland_derivation(self.receipt, self.kernel)

    def test_other_kernel_cannot_use_successful_receipt(self):
        wrong = dict(self.kernel, sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "kernel differs"):
            builder.admit_userland_derivation(self.receipt, wrong)

    @unittest.skipUnless((OLD / "result.json").is_file(), "old qualified native kernel cache unavailable")
    def test_actual_old_original_kernel_derivation_still_passes(self):
        spec = importlib.util.spec_from_file_location("unchanged_old_plan9_policy", ROOT / "scripts/probe_okernel_plan9.py")
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        receipt = OLD / "result.json"
        kernel = builder.identity(OLD / "patched-1/artifacts/NATIVE.U")
        admitted = builder.admit_plan9_derivation(receipt, kernel, old)
        self.assertEqual(admitted["admission_kind"], "original-kernel")


if __name__ == "__main__":
    unittest.main()
