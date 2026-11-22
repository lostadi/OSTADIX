"""Tests for the pinned Lean installer and Android host wrappers."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install_lean.py"
SPEC = importlib.util.spec_from_file_location("ostadix_install_lean", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {SCRIPT}")
lean = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lean
SPEC.loader.exec_module(lean)


class LeanInstallerTests(unittest.TestCase):
    def test_release_assets_cover_supported_native_architectures(self) -> None:
        self.assertEqual(lean.asset_stem("linux", "x86_64"), "lean-4.24.0-linux")
        self.assertEqual(lean.asset_stem("linux", "aarch64"), "lean-4.24.0-linux_aarch64")
        self.assertEqual(lean.asset_stem("darwin", "arm64"), "lean-4.24.0-darwin_aarch64")
        self.assertEqual(lean.asset_stem("windows", "amd64"), "lean-4.24.0-windows")
        with self.assertRaises(lean.LeanInstallError):
            lean.asset_stem("freebsd", "x86_64")
        with self.assertRaises(lean.LeanInstallError):
            lean.asset_stem("linux", "riscv64")

    def test_archive_extraction_strips_one_root_and_preserves_executable_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            archive_path = fixture / "lean.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                executable = zipfile.ZipInfo("lean-4.24.0-linux/bin/lean")
                executable.external_attr = 0o100755 << 16
                archive.writestr(executable, "#!/bin/sh\n")
                archive.writestr("lean-4.24.0-linux/share/version", "4.24.0\n")
            destination = fixture / "installed"
            lean.extract_archive(archive_path, destination)
            self.assertEqual((destination / "share" / "version").read_text(), "4.24.0\n")
            mode = (destination / "bin" / "lean").stat().st_mode
        self.assertTrue(mode & stat.S_IXUSR)

    def test_archive_extraction_rejects_escape_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            for name, mode in (("../escape", 0o100644), ("root/link", 0o120777)):
                with self.subTest(name=name):
                    archive_path = fixture / "invalid.zip"
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        member = zipfile.ZipInfo(name)
                        member.external_attr = mode << 16
                        archive.writestr(member, "bad")
                    with self.assertRaises(lean.LeanInstallError):
                        lean.extract_archive(archive_path, fixture / "output")

    def test_android_reuse_writes_working_directory_preserving_wrappers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "lean"
            commands = []

            def run(command, **kwargs):
                commands.append(command)
                if command[1] == "list":
                    return subprocess.CompletedProcess(command, 0, stdout="", stderr="  * ostadix-lean\n")
                if "--version" in command:
                    return subprocess.CompletedProcess(
                        command, 0, stdout="Lean (version 4.24.0, aarch64-unknown-linux-gnu, test)\n"
                    )
                raise AssertionError(command)

            with patch.object(lean.shutil, "which", return_value="/usr/bin/proot-distro"), patch.object(
                lean.subprocess, "run", side_effect=run
            ):
                lean.install_termux(root)
            wrapper = (root / "bin" / "lean").read_text(encoding="utf-8")

        self.assertIn('login --work-dir "$PWD" ostadix-lean', wrapper)
        self.assertIn("/opt/lean-4.24.0/bin/lean", wrapper)
        self.assertFalse(any("apt-get" in part for command in commands for part in command))

    def test_local_links_preserve_unmanaged_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            root = fixture / "toolchain"
            bin_directory = fixture / "bin"
            for name in ("lean", "lake", "leanc"):
                source = root / "bin" / name
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("managed", encoding="utf-8")
            bin_directory.mkdir()
            (bin_directory / "lean").write_text("unmanaged", encoding="utf-8")
            lean.link_executables(root, bin_directory, termux=False)
            self.assertEqual((bin_directory / "lean").read_text(encoding="utf-8"), "unmanaged")
            self.assertTrue((bin_directory / "lake").is_symlink())
            self.assertTrue((bin_directory / "leanc").is_symlink())


if __name__ == "__main__":
    unittest.main()
