"""Status reports observed guest state and the real console controls."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "ocore/guest/linux/package-domain/okernel-status"


class GuestStatusTests(unittest.TestCase):
    def test_status_reports_original_tools_namespace_and_save_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, program in {
                "hostname": "echo okernel\n", "uname": "echo 'Linux okernel aarch64 fixture'\n",
                "df": "echo '/dev/vda 1.0G root-storage-fixture'\n", "apk": "printf 'gcc\\nmake\\n'\n",
                "namespace": "echo 'Native OKernel namespace: /n/okernel'\n",
            }.items():
                path = root / name
                path.write_text("#!/bin/sh\n" + program)
                path.chmod(0o755)
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "OSTADIX_PKG_NAMESPACE_HELPER": str(root / "namespace")}
            result = subprocess.run(["sh", str(HELPER)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for observed in ("Host: okernel", "Linux okernel aarch64", "Common workspace: /n/okernel/work",
                             "root-storage-fixture", "Installed APK packages: 2", "Save and exit: Ctrl+]", "Reconnect from the host: okernel"):
                self.assertIn(observed, result.stdout)
            (root / "namespace").unlink()
            result = subprocess.run(["sh", str(HELPER)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn("Native shared namespace: unavailable", result.stdout)
            self.assertNotIn("Common workspace:", result.stdout)


if __name__ == "__main__":
    unittest.main()
