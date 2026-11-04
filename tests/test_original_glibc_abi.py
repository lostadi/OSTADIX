"""Private APT capture contracts and original signature verification boundary."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_glibc_abi", ROOT / "scripts/build_glibc_abi.py")
ABI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ABI)


class OriginalGlibcAbiTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="glibc-abi-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_private_apt_configuration_disables_host_hooks_and_installed_state(self):
        work = self.root / "private-apt"
        config = ABI.apt_config(work)
        self.assertIn(str(work / "state/status"), config)
        self.assertIn(str(work / "etc"), config)
        self.assertIn('Dir::Etc::parts "absent.conf.d"', config)
        self.assertIn('Dir::Etc::trustedparts "absent.trusted.d"', config)
        self.assertIn('APT::Architecture "arm64"', config)
        self.assertIn('APT::Get::AllowUnauthenticated "false"', config)
        self.assertIn('Acquire::Check-Valid-Until "true"', config)
        for name in ("APT::Update::Pre-Invoke", "APT::Update::Post-Invoke", "APT::Update::Post-Invoke-Success",
                     "DPkg::Pre-Invoke", "DPkg::Post-Invoke", "DPkg::Pre-Install-Pkgs"):
            self.assertIn("#clear " + name, config)
        self.assertNotIn("/var/lib/dpkg/status", config)

    def test_original_solver_plan_requires_roots_and_keeps_all_dependencies(self):
        plan = ABI.solver_plan("Inst libc6-dev (2.39 Ubuntu:noble [arm64])\n"
                               "Inst libc6 (2.39 Ubuntu:noble [arm64])\n"
                               "Inst libgcc-s1:arm64 (14.2 Ubuntu:noble [arm64])\n")
        self.assertEqual(plan, {"libc6-dev": "2.39", "libc6": "2.39", "libgcc-s1": "14.2"})
        with self.assertRaisesRegex(ValueError, "both requested roots"):
            ABI.solver_plan("Inst libc6-dev (2.39 Ubuntu:noble [arm64])\n")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            ABI.solver_plan("Inst libc6-dev (2.39)\nInst libc6-dev (2.40)\n")

    def test_multiline_signed_metadata_parsing_and_duplicate_rejection(self):
        records = ABI.paragraphs("Origin: Ubuntu\nSHA256:\n abc 7 main/binary-arm64/Packages\n\n")
        self.assertEqual(records[0]["SHA256"].split(), ["abc", "7", "main/binary-arm64/Packages"])
        with self.assertRaises(ValueError):
            ABI.paragraphs("SHA256: abc\nSHA256: forged\n")
        with self.assertRaises(ValueError):
            ABI.paragraphs(" orphaned-continuation\n")

    def test_manifest_paths_cannot_escape_or_follow_external_symlinks(self):
        (self.root / "metadata").mkdir()
        outside = self.root.parent / (self.root.name + "-private")
        outside.write_bytes(b"private")
        self.addCleanup(outside.unlink)
        (self.root / "metadata/link").symlink_to(outside)
        for name in ("../" + outside.name, str(outside), "metadata/link"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                ABI.relative_file(self.root, name)

    def test_content_addressed_cache_reuses_only_verified_bytes_and_preserves_conflicts(self):
        pool = self.root / "cache"
        pool.mkdir()
        source = self.root / "original.deb"
        source.write_bytes(b"authenticated original archive")
        expected = ABI.identity(source)
        ABI.cache_original(pool, source, expected)
        selected = pool / (expected["sha256"] + ".deb")
        self.assertEqual(selected.read_bytes(), source.read_bytes())
        ABI.cache_original(pool, source, expected)
        selected.chmod(0o644)
        selected.write_bytes(b"preserve unrelated changed entry")
        with self.assertRaisesRegex(ValueError, "preserving"):
            ABI.cache_original(pool, source, expected)
        self.assertEqual(selected.read_bytes(), b"preserve unrelated changed entry")
        selected.unlink()
        selected.symlink_to(source)
        with self.assertRaises(ValueError):
            ABI.cache_original(pool, source, expected)
        self.assertEqual(source.read_bytes(), b"authenticated original archive")

    def test_bundle_is_deterministic_and_preserves_original_symlink_semantics(self):
        for name in ("rootfs", "debs", "metadata"):
            (self.root / name).mkdir()
        file = self.root / "rootfs/library"
        file.write_bytes(b"original bytes")
        file.chmod(0o755)
        (self.root / "rootfs/link").symlink_to("/usr/lib/original.so")
        (self.root / "manifest.json").write_text('{}\n')
        first, second = self.root / "first.tar.gz", self.root / "second.tar.gz"
        ABI.deterministic_bundle(self.root, ("rootfs", "debs", "metadata", "manifest.json"), first)
        os.utime(file, (987654321, 987654321))
        ABI.deterministic_bundle(self.root, ("rootfs", "debs", "metadata", "manifest.json"), second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first) as archive:
            self.assertEqual(archive.getmember("rootfs/link").linkname, "/usr/lib/original.so")
            self.assertTrue(all(member.mtime == 0 and member.uid == 0 and member.gid == 0 for member in archive))

    def forged_capture(self):
        for name in ("rootfs", "debs", "metadata"):
            (self.root / name).mkdir()
        metadata = []
        for pocket in ABI.POCKETS:
            directory = self.root / "metadata" / pocket
            directory.mkdir()
            for name in ("InRelease", "Release", "Packages"):
                path = directory / name
                path.write_bytes(b"self-consistent forged data\n")
                metadata.append({"file": path.relative_to(self.root).as_posix(), **ABI.identity(path)})
        recipe = self.root / "metadata/build_glibc_abi.py"
        recipe.write_bytes(b"captured fake recipe")
        metadata.append({"file": recipe.relative_to(self.root).as_posix(), **ABI.identity(recipe)})
        manifest = {"schema": ABI.SCHEMA, "architecture": "arm64", "requests": list(ABI.REQUESTS),
                    "packages": [], "metadata": metadata, "rootfs": [], "recipe_sha256": ABI.sha256(recipe)}
        (self.root / "manifest.json").write_text(json.dumps(manifest))
        ABI.deterministic_bundle(self.root, ("rootfs", "debs", "metadata", "manifest.json"))
        manifest["bundle"] = ABI.identity(self.root / "glibc-abi.tar.gz")
        (self.root / "glibc-abi.json").write_text(json.dumps(manifest))
        return manifest

    def test_recomputed_inventory_hashes_cannot_replace_original_archive_signature(self):
        self.forged_capture()
        original = ABI.subprocess.run
        calls = []
        def recording(arguments, **kwargs):
            calls.append(arguments)
            return original(arguments, **kwargs)
        with patch.object(ABI.subprocess, "run", side_effect=recording):
            with self.assertRaises(subprocess.CalledProcessError):
                ABI.verify(self.root)
        self.assertEqual(calls[0][0], "gpgv")
        self.assertEqual(calls[0][calls[0].index("--keyring") + 1], str(ABI.KEYRING))
        self.assertFalse(any(command[0] == "apt-get" for command in calls))

    def test_changed_bundle_and_outer_manifest_are_rejected_before_any_tool(self):
        manifest = self.forged_capture()
        manifest["origin"] = "untrusted"
        (self.root / "glibc-abi.json").write_text(json.dumps(manifest))
        with patch.object(ABI.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "outer ABI manifest"):
                ABI.verify(self.root)
            run.assert_not_called()
        (self.root / "glibc-abi.tar.gz").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "bundle bytes"):
            ABI.verify(self.root)

    @unittest.skipUnless(os.environ.get("OSTADIX_GLIBC_ABI_TEST_CAPTURE"), "explicit captured original ABI fixture required")
    def test_actual_original_signatures_complete_solver_and_payload_replay(self):
        manifest = ABI.verify(Path(os.environ["OSTADIX_GLIBC_ABI_TEST_CAPTURE"]))
        self.assertGreater(len(manifest["packages"]), len(ABI.REQUESTS))
        self.assertTrue(all(release["signers"] for release in manifest["signed_releases"]))


if __name__ == "__main__":
    unittest.main()
