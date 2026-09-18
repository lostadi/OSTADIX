"""Installed commands preserve bytes, native identity and existing processes."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_install", ROOT / "scripts/install_native_binaries.py")
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class NativeInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ostadix native install ")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repository"
        self.build = self.repo / "target/release"
        self.destination = Path(self.temp.name) / "installed commands"
        self.build.mkdir(parents=True)
        (self.repo / "backends").mkdir()
        for name in installer.RUST_TOOLS:
            path = self.build / name
            path.write_bytes(b"\x7fELF" + name.encode())
            path.chmod(0o755)

    def test_installs_exact_native_bytes_and_portable_runtime_metadata(self):
        installer.install(self.repo, self.build, self.destination)
        for name in installer.RUST_TOOLS:
            expected = "o-cli" if name == "O" and (self.destination / "O").samefile(self.destination / "o") else name
            self.assertEqual((self.destination / name).read_bytes(), (self.build / expected).read_bytes())
        self.assertEqual((self.destination / "o").read_bytes(), (self.build / "o-cli").read_bytes())
        self.assertEqual((self.destination / "ostadix-evaluator").read_bytes(), (self.build / "O").read_bytes())
        self.assertEqual(json.loads((self.destination / "ostadix-install.json").read_text()),
                         {"schema": 1, "repo_root": str(self.repo.resolve()), "backends_dir": str((self.repo / "backends").resolve())})

    def test_all_inputs_preflight_before_replacing_existing_tool(self):
        self.destination.mkdir()
        current = self.destination / "o"
        current.write_bytes(b"current executable")
        (self.build / "octl").unlink()
        with self.assertRaisesRegex(ValueError, "compiled executable missing"):
            installer.install(self.repo, self.build, self.destination)
        self.assertEqual(current.read_bytes(), b"current executable")
        self.assertFalse((self.destination / "o-cli").exists())

    def test_shell_script_is_rejected_before_installing_anything(self):
        (self.build / "o-cli").write_text("#!/bin/sh\nexit 0\n")
        with self.assertRaisesRegex(ValueError, "expected a compiled executable"):
            installer.install(self.repo, self.build, self.destination)
        self.assertFalse(self.destination.exists())

    def test_atomic_replacement_keeps_open_executable_bytes(self):
        self.destination.mkdir()
        old = self.destination / "o-cli"
        old.write_bytes(b"old process bytes")
        with old.open("rb") as running:
            installer.install(self.repo, self.build, self.destination)
            self.assertEqual(running.read(), b"old process bytes")
        self.assertEqual(old.read_bytes(), (self.build / "o-cli").read_bytes())

    def test_existing_symlink_is_replaced_without_overwriting_its_target(self):
        self.destination.mkdir()
        unrelated = self.repo / "other executable"
        unrelated.write_bytes(b"preserve")
        (self.destination / "o-cli").symlink_to(unrelated)
        installer.install(self.repo, self.build, self.destination)
        self.assertEqual(unrelated.read_bytes(), b"preserve")
        self.assertFalse((self.destination / "o-cli").is_symlink())

    def test_dry_run_does_not_require_built_files_or_create_directories(self):
        plan = installer.install(self.repo, self.repo / "missing", self.destination, dry_run=True)
        self.assertTrue(any("ostadix-evaluator" in entry for entry in plan))
        self.assertFalse(self.destination.exists())

    def test_front_door_install_retains_native_evaluator(self):
        installer.install(self.repo, self.build, self.destination, front_door_only=True)
        self.assertTrue(os.access(self.destination / "ostadix-evaluator", os.X_OK))
        self.assertFalse((self.destination / "octl").exists())

    def test_external_c_build_uses_the_selected_installed_source_root(self):
        build = self.repo / "cmake build"
        build.mkdir()
        for name in ("O", "olangc"):
            path = build / name
            path.write_bytes(b"\x7fELF" + b"external C " + name.encode())
            path.chmod(0o755)
        installer.install(self.repo, self.build, self.destination, include_c=True, c_build_dir=build)
        self.assertEqual((self.destination / "o-c").read_bytes(), (build / "O").read_bytes())
        self.assertEqual((self.destination / "olangc-c").read_bytes(), (build / "olangc").read_bytes())
        metadata = json.loads((self.destination / "ostadix-install.json").read_text())
        self.assertEqual(metadata["repo_root"], str(self.repo.resolve()))

    def test_front_door_never_temporarily_becomes_the_raw_evaluator(self):
        self.destination.mkdir()
        if not installer.case_insensitive_directory(self.destination):
            self.skipTest("O/o collision is specific to case-insensitive filesystems")
        command = self.destination / "o"
        command.write_bytes(b"previous front door")
        copied = installer.atomic_copy
        observations = []
        def observe(source, target):
            copied(source, target)
            observations.append(command.read_bytes())
        with patch.object(installer, "atomic_copy", side_effect=observe):
            installer.install(self.repo, self.build, self.destination)
        self.assertNotIn((self.build / "O").read_bytes(), observations)
        self.assertEqual(observations[-1], (self.build / "o-cli").read_bytes())

    def test_refuses_real_directory_at_a_managed_target(self):
        (self.destination / "olangc").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "target is a directory"):
            installer.install(self.repo, self.build, self.destination)
        self.assertFalse((self.destination / "o-cli").exists())


if __name__ == "__main__":
    unittest.main()
