"""Runner controls complement the separate real three-ISA bounds execution."""
from pathlib import Path
import argparse
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_ocore_array_bounds as bounds


class BoundsRunnerTests(unittest.TestCase):
    def observed(self, code, output):
        return subprocess.CompletedProcess([], code, output, b"")

    def test_all_case_ids_and_names_are_unique_and_nonempty(self):
        bounds.validate_cases()
        for bad in [[], [bounds.CASES[0], bounds.CASES[0]], [bounds.CASES[1]]]:
            with self.assertRaises(RuntimeError):
                bounds.validate_cases(bad)

    def test_declared_traps_have_required_target_signal(self):
        case = bounds.CASES[16]
        for isa in bounds.TARGETS:
            sig = signal.SIGTRAP if isa == "aarch64" else signal.SIGILL
            bounds.check_observation(isa, case, self.observed(-sig, b"BI"))

    def test_memory_fault_and_success_cannot_stand_in_for_a_bounds_trap(self):
        for code in [-signal.SIGSEGV, -signal.SIGBUS, 0, 1]:
            with self.assertRaisesRegex(RuntimeError, "expected status"):
                bounds.check_observation("x86_64", bounds.CASES[16], self.observed(code, b"BI"))

    def test_rhs_or_duplicate_evaluation_before_trap_fails(self):
        for events in [b"BIR", b"BBI", b"BII", b"IB", b"", b"BIP\n"]:
            with self.assertRaisesRegex(RuntimeError, "event order"):
                bounds.check_observation("x86_64", bounds.CASES[16], self.observed(-signal.SIGILL, events))

    def test_return_and_divergence_require_exact_events_and_status(self):
        bounds.check_observation("riscv64", bounds.CASES[15], self.observed(0, b"BIRP\n"))
        bounds.check_observation("aarch64", bounds.CASES[24], self.observed(43, b"BI"))
        with self.assertRaises(RuntimeError):
            bounds.check_observation("aarch64", bounds.CASES[24], self.observed(0, b"BI"))
        with self.assertRaises(RuntimeError):
            bounds.check_observation("x86_64", bounds.CASES[15], self.observed(0, b"BIR"))

    def test_reduced_matrix_cannot_be_qualified(self):
        with self.assertRaisesRegex(RuntimeError, "required matrix"):
            bounds.validate_cases(bounds.CASES[:-1])
        with patch.object(bounds, "REJECTIONS", {}), self.assertRaisesRegex(RuntimeError, "rejection cases"):
            bounds.validate_cases()

    def test_existing_output_directory_is_refused_before_tools_run(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "preserved"
            marker.write_text("keep")
            result = subprocess.run([sys.executable, str(SCRIPTS / "check_ocore_array_bounds.py"),
                                     "--ocorec", "/missing/compiler", "--output-dir", directory],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("fresh directory", result.stderr)
            self.assertEqual(marker.read_text(), "keep")

    def test_relative_output_is_anchored_to_callers_cwd_before_producers(self):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                argv = ["check_ocore_array_bounds.py", "--ocorec", sys.executable,
                        "--output-dir", "results"]
                with patch.object(sys, "argv", argv), patch.object(bounds, "check") as producer:
                    self.assertEqual(bounds.main(), 0)
                    output = producer.call_args.args[1]
                    self.assertEqual(output, Path(directory).resolve() / "results")
                    self.assertTrue(output.is_absolute())
            finally:
                os.chdir(previous)

    def test_custom_carrier_compiler_keeps_separate_default_assembler_identity(self):
        captured = {}

        class SelectionCaptured(Exception):
            pass

        def capture(sources, tools):
            captured.update(tools)
            raise SelectionCaptured()

        args = argparse.Namespace(ocorec=Path("candidate"), clang="custom-carrier",
                                  qemu_x86_64=None, qemu_aarch64=None, qemu_riscv64=None)
        with patch.object(bounds, "canonical_target_coverage", return_value={}), \
                patch.object(bounds, "tool", side_effect=lambda value, label: "/selected/" + Path(value).name), \
                patch.object(bounds, "execution_prefix", return_value=[]), \
                patch.object(bounds, "RunEvidence", side_effect=capture), \
                self.assertRaises(SelectionCaptured):
            bounds.check(args, Path("/unused"))
        self.assertEqual(captured["clang"], "/selected/custom-carrier")
        self.assertEqual(captured["assembler_clang"], "/selected/clang")


if __name__ == "__main__":
    unittest.main()
