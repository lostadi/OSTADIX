"""M1 gate preflight refuses unqualified builds before touching a VM/state."""
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("resident_gate_test", ROOT / "scripts/verify_o10_resident.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class ResidentGatePreflightTests(unittest.TestCase):
    def command(self, argv):
        return {"argv": argv, "returncode": 0,
                "stdout": "" if "status" in argv else "fixture\n", "stderr": ""}

    def test_kernel_dispatcher_exposes_owner_build_and_gate_arguments(self):
        for action, flag in (("unified-build", "--o10-qualification"),
                             ("o10-resident", "--mcp-release"),
                             ("o10-hostile-mmio", "--mcp-release")):
            with self.subTest(action=action):
                result = subprocess.run(["bash", str(ROOT / "scripts/o-kernel.sh"), action, "--help"],
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(flag, result.stdout)

    def test_production_build_never_forks_or_launches_a_guest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            build.mkdir()
            (build / "monitor-profile.json").write_text(json.dumps({
                "o10": gate.runner.O10_PROFILE, "o10_qualification": False,
                "plan9_recovery": True, "plan9_command_provider": True,
            }))
            session = root / "evidence"
            with patch.object(gate, "command", side_effect=self.command), \
                    patch.object(gate.runner, "validate_profile"), \
                    patch.object(gate.forker, "fork") as fork, \
                    patch.object(gate.runner, "UnifiedDomain") as domain:
                with self.assertRaisesRegex(ValueError, "qualification"):
                    gate.verify(root / "untouched-state", build, session, mcp_release="fixture")
            fork.assert_not_called()
            domain.assert_not_called()
            result = json.loads((session / "result.json").read_text())
            self.assertFalse(result["gate_passed"])
            self.assertFalse(result["milestone_qualified"])
            self.assertIn("qualification", result["error"])

    def test_build_source_mismatch_never_forks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            build.mkdir()
            (build / "monitor-profile.json").write_text(json.dumps({
                "o10": gate.runner.O10_PROFILE, "o10_qualification": True,
                "plan9_recovery": True, "plan9_command_provider": True,
                "source_sha256": {"ocore/runtime/aarch64/unified_world.oc": "0" * 64},
            }))
            session = root / "evidence"
            with patch.object(gate, "command", side_effect=self.command), \
                    patch.object(gate.runner, "validate_profile"), \
                    patch.object(gate.forker, "fork") as fork:
                with self.assertRaisesRegex(ValueError, "build/source mismatch"):
                    gate.verify(root / "untouched-state", build, session, mcp_release="fixture")
            fork.assert_not_called()
            self.assertFalse(json.loads((session / "result.json").read_text())["gate_passed"])

    def test_missing_build_still_writes_failed_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session = root / "evidence"
            with self.assertRaises(FileNotFoundError):
                gate.verify(root / "untouched-state", root / "missing", session, mcp_release="fixture")
            result = json.loads((session / "result.json").read_text())
            self.assertFalse(result["gate_passed"])
            self.assertIn("FileNotFoundError", result["error"])


if __name__ == "__main__":
    unittest.main()
