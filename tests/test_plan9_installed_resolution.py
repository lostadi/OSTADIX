"""Installed names select original Plan9 paths without running a host program."""
import importlib.machinery
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader("installed_plan9_client_test", str(ROOT / "ocore/guest/linux/package-domain/p9"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
CLIENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CLIENT
LOADER.exec_module(CLIENT)


class InstalledPlan9ResolutionTests(unittest.TestCase):
    def test_installed_executable_precedes_original_provider_and_keeps_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            mount = Path(directory)
            target = mount / "packages/plan9/bin/hello"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"original executable fixture; not run")
            target.chmod(0o755)
            client = CLIENT.Client(mount / "control", None, io.BytesIO(), io.BytesIO())
            session = {"linux_mount": str(mount), "plan9_mount": "/n", "program_dir": "/arm64/bin"}
            args = ["hello", "one argument", "", "quote'\nbytes"]
            self.assertEqual(client._arguments(args, str(mount / "work"), session),
                             ["/n/packages/plan9/bin/hello", *args[1:]])
            self.assertEqual(client._arguments(["echo", "hello"], str(mount), session), ["/arm64/bin/echo", "hello"])
            self.assertEqual(client._arguments(["/arm64/bin/hello"], str(mount), session), ["/arm64/bin/hello"])

    def test_nonexecutables_directories_and_symlinks_do_not_register_names(self):
        with tempfile.TemporaryDirectory() as directory:
            mount = Path(directory)
            installed = mount / "packages/plan9/bin"
            installed.mkdir(parents=True)
            regular = installed / "nonexec"
            regular.write_bytes(b"data")
            regular.chmod(0o644)
            (installed / "folder").mkdir()
            (installed / "alias").symlink_to(regular)
            client = CLIENT.Client(mount / "control", None, io.BytesIO(), io.BytesIO())
            session = {"linux_mount": str(mount), "plan9_mount": "/n", "program_dir": "/arm64/bin"}
            for name in ("missing", "nonexec", "folder", "alias"):
                with self.subTest(name=name):
                    self.assertEqual(client._arguments([name], str(mount), session), ["/arm64/bin/" + name])


if __name__ == "__main__":
    unittest.main()
