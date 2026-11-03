"""Exercise wrapper dispatch without compiling or starting a virtual machine."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class KernelConsoleEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "Cargo.toml").touch()
        (self.root / "ocore/kernel").mkdir(parents=True)
        (self.root / "okernel-multikernel").mkdir()
        self.wrapper = self.root / "okernel-multikernel/boot-and-test.sh"
        shutil.copy2(ROOT / "okernel-multikernel/boot-and-test.sh", self.wrapper)
        self.write_executable("ocore/kernel/build.sh", "exit 90\n")
        self.write_executable(
            "ocore/kernel/run-qemu.sh",
            'printf "mode=%s\\nbuild=%s\\nqemu=%s\\n" '
            '"${OCORE_PROBE_MODE:-0}" "${OCORE_BUILD_DIR:-}" "${OCORE_QEMU_BIN:-}"\n'
            'exit "${TEST_RUNNER_EXIT:-0}"\n',
        )
        for tool in ("cargo", "clang", "custom-qemu"):
            self.write_executable(f"bin/{tool}", "exit 91\n")
        self.env = {
            **os.environ,
            "PATH": f"{self.root / 'bin'}:{os.environ['PATH']}",
            "OCORE_QEMU_BIN": str(self.root / "bin/custom-qemu"),
            "OCORE_BUILD_DIR": str(self.root / "custom build"),
        }
        self.env.pop("OCORE_PROBE_MODE", None)

    def write_executable(self, relative, source):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n" + source)
        path.chmod(0o755)

    def run_phase(self, phase):
        return subprocess.run(
            [str(self.wrapper), phase],
            cwd=self.root / "okernel-multikernel",
            env=self.env,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_console_selects_native_mode_and_preserves_runner_configuration(self):
        self.env["OCORE_PROBE_MODE"] = "0"
        result = self.run_phase("console")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mode=16\n", result.stdout)
        self.assertIn(f"build={self.env['OCORE_BUILD_DIR']}\n", result.stdout)
        self.assertIn(f"qemu={self.env['OCORE_QEMU_BIN']}\n", result.stdout)
        self.assertNotIn("baseline runs silently", result.stdout)

    def test_kernel_default_explains_silent_heartbeat(self):
        result = self.run_phase("kernel")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mode=0\n", result.stdout)
        self.assertIn("baseline runs silently after its heartbeat", result.stdout)
        self.assertIn("console phase", result.stdout)

    def test_kernel_preserves_explicit_mode_and_runner_failure(self):
        self.env["OCORE_PROBE_MODE"] = "16"
        self.env["TEST_RUNNER_EXIT"] = "42"
        result = self.run_phase("kernel")
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertIn("mode=16\n", result.stdout)
        self.assertNotIn("baseline runs silently", result.stdout)

    def test_help_advertises_console(self):
        result = self.run_phase("help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("console  Boot the native command console", result.stdout)


if __name__ == "__main__":
    unittest.main()
