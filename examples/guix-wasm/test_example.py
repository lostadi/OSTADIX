"""Synthetic unit checks only: these tests do not run Guix, Docker, or Wasm."""

import ast
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent
MARKER = "OSTADIX_GUIX_PACKAGE:42->43"
spec = importlib.util.spec_from_file_location("guix_archive", ROOT / "extract-guix.py")
extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extractor)


def python_body():
    source = (ROOT / "guix-package.O").read_text(encoding="utf-8")
    assert source.startswith("python^(\n") and source.endswith(")_python\n")
    return source[len("python^(\n") : -len(")_python\n")]


class WorkloadTests(unittest.TestCase):
    def test_python_syntax(self):
        ast.parse(python_body())

    def test_mocked_command_uses_absolute_real_guix_and_checked_stdout(self):
        def fake_run(command, **kwargs):
            self.assertEqual(command[:4], [
                "/var/guix/profiles/per-user/root/current-guix/bin/guix",
                "repl", "-q", "--",
            ])
            script = Path(command[4])
            self.assertTrue(script.is_absolute())
            scheme = script.read_text(encoding="utf-8")
            for fragment in ["(guix packages)", "(guix build-system trivial)",
                             "((guix licenses) #:prefix license:)",
                             "(inherit original)", "(source #f)",
                             "OSTADIX_GUIX_INTENTIONAL_FAILURE"]:
                self.assertIn(fragment, scheme)
            self.assertEqual(kwargs["env"]["GUILE_AUTO_COMPILE"], "0")
            self.assertEqual(kwargs["env"]["LC_ALL"], "C")
            self.assertEqual(kwargs["env"].get("HOME"), os.environ.get("HOME"))
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 300)
            self.assertNotIn("shell", kwargs)
            return subprocess.CompletedProcess(command, 0, MARKER + "\n", "")

        namespace = {}
        with mock.patch("subprocess.run", side_effect=fake_run) as run:
            exec(python_body(), namespace)
        run.assert_called_once()
        self.assertEqual(namespace["__oval_result__"], MARKER)

    def test_mocked_guix_failure_is_not_returned_as_success(self):
        failed = subprocess.CompletedProcess([], 7, "", "intentional Guix failure")
        with mock.patch("subprocess.run", return_value=failed):
            with self.assertRaisesRegex(RuntimeError, "exit 7.*intentional Guix failure"):
                exec(python_body(), {})

    def test_mocked_unexpected_stdout_is_rejected(self):
        wrong = subprocess.CompletedProcess([], 0, "a version string is not proof", "")
        with mock.patch("subprocess.run", return_value=wrong):
            with self.assertRaisesRegex(RuntimeError, "unexpected package-language result"):
                exec(python_body(), {})


class ArchiveTests(unittest.TestCase):
    def make_archive(self, path, names):
        with tarfile.open(path, "w:xz") as archive:
            for name in names:
                content = b"synthetic unit-test data, not Guix\n"
                entry = tarfile.TarInfo(name)
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_recipe_and_archive_pins_are_exact(self):
        self.assertEqual(extractor.ARCHIVE_SHA256,
                         "aa41025489c5061543e9c48873eaa829b900b2da75d40f9648913622f5f47817")
        recipe = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertEqual(recipe.count(
            "python:3.11-slim-bookworm@sha256:b1add8a6f2aca6bcfcf0b9c9b522352f7ce0d62a3d556a2f2f32511aa0cca250"), 2)
        self.assertIn("COPY --from=guix-distribution-unpacked /gnu /gnu", recipe)
        self.assertIn("COPY --from=guix-distribution-unpacked /var/guix /var/guix", recipe)
        self.assertNotIn("apt-get", recipe)
        self.assertEqual(recipe.count("RUN --network=none "), 3)
        self.assertIn("guix archive --authorize < /gnu/store/ganla421f3g1p9rh3r68zj9djc9b807m-guix-1.5.0/share/guix/bordeaux.guix.gnu.org.pub", recipe)

    def test_wrong_digest_rejects_before_any_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "fake.tar.xz"
            self.make_archive(archive, ["gnu/store/fake/data"])
            destination = root / "unpacked"
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                extractor.verify_and_extract(archive, destination)
            self.assertFalse(destination.exists())

    def test_synthetic_expected_tree_can_extract(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "fake.tar.xz"
            digest = self.make_archive(archive, ["gnu/store/fake/data", "var/guix/data"])
            destination = root / "unpacked"
            with mock.patch.object(extractor, "ARCHIVE_SHA256", digest):
                extractor.verify_and_extract(archive, destination)
            self.assertTrue((destination / "gnu/store/fake/data").is_file())
            self.assertTrue((destination / "var/guix/data").is_file())

    def test_synthetic_store_links_and_executable_mode_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "fake.tar.xz"
            with tarfile.open(archive, "w:xz") as distribution:
                executable = tarfile.TarInfo("./gnu/store/fake-profile/bin/guix")
                executable.mode = 0o755
                executable.size = 4
                distribution.addfile(executable, io.BytesIO(b"fake"))
                profile = tarfile.TarInfo(
                    "./var/guix/profiles/per-user/root/current-guix"
                )
                profile.type = tarfile.SYMTYPE
                profile.linkname = "/gnu/store/fake-profile"
                distribution.addfile(profile)
                alias = tarfile.TarInfo("./gnu/store/fake-profile/bin/guix-alias")
                alias.type = tarfile.LNKTYPE
                alias.mode = 0o755
                alias.linkname = "./gnu/store/fake-profile/bin/guix"
                distribution.addfile(alias)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            destination = root / "unpacked"
            with mock.patch.object(extractor, "ARCHIVE_SHA256", digest):
                extractor.verify_and_extract(archive, destination)
            self.assertEqual(os.readlink(
                destination / "var/guix/profiles/per-user/root/current-guix"
            ), "/gnu/store/fake-profile")
            executable = destination / "gnu/store/fake-profile/bin/guix"
            alias = destination / "gnu/store/fake-profile/bin/guix-alias"
            self.assertEqual(executable.stat().st_mode & 0o777, 0o755)
            self.assertEqual(executable.stat().st_ino, alias.stat().st_ino)

    def test_unexpected_paths_reject_before_extracting_valid_members(self):
        for invalid in ["etc/passwd", "../escape", "/gnu/store/absolute"]:
            with self.subTest(path=invalid), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive = root / "fake.tar.xz"
                digest = self.make_archive(archive, ["gnu/store/fake/data", invalid])
                destination = root / "unpacked"
                with mock.patch.object(extractor, "ARCHIVE_SHA256", digest):
                    with self.assertRaisesRegex(ValueError, "unexpected archive"):
                        extractor.verify_and_extract(archive, destination)
                self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
