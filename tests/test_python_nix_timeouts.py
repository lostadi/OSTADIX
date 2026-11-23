"""Nix reference adapters must not impose an implicit execution deadline."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from o_lang.backends.nix_backend import NixBackend
from o_lang.backends.nix_store_backend import NixStoreBackend
from o_lang.ovalue import OInt, OStorePath


class PythonNixTimeoutTests(unittest.TestCase):
    def test_nix_and_store_evaluation_wait_without_an_implicit_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "nix"
            executable.write_text(
                f"#!{sys.executable}\n"
                "import sys, time\ntime.sleep(0.05)\n"
                "print('/nix/store/test-result' if '--raw' in sys.argv else '42')\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            communicate = subprocess.Popen.communicate
            observed = []

            def record_timeout(process, *args, **kwargs):
                observed.append(kwargs.get("timeout"))
                return communicate(process, *args, **kwargs)

            environment = dict(os.environ, PATH=directory + os.pathsep + os.environ.get("PATH", ""))
            with patch.dict(os.environ, environment), patch.object(
                subprocess.Popen, "communicate", record_timeout
            ):
                self.assertEqual(NixBackend().evaluate("40 + 2", None), OInt(42))
                self.assertEqual(
                    NixStoreBackend().evaluate("store-expression", None),
                    OStorePath("/nix/store/test-result"),
                )
            self.assertEqual(observed, [None, None])


if __name__ == "__main__":
    unittest.main()
