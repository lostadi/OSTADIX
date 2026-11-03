"""Grow real private ext4 images; prove failure cannot replace a selected pair."""

import fcntl
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("okernel_disk_growth", ROOT / "scripts/grow_okernel_disk.py")
growth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(growth)


@unittest.skipUnless(all(shutil.which(tool) for tool in ("mke2fs", "debugfs", "e2fsck", "resize2fs")), "e2fsprogs required")
class DiskGrowthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory()
        cls.base = Path(cls.shared.name)
        tree = cls.base / "files"
        for path in ("work", "lib/apk/db", "etc/apk", "usr/local/bin", "empty"):
            (tree / path).mkdir(parents=True)
        (tree / "work/hello").write_bytes(b"retain the user's source and executable\n")
        (tree / "lib/apk/db/installed").write_bytes(b"retain original APK database\n")
        (tree / "etc/apk/repositories").write_bytes(b"https://example.invalid/authenticated-repository\n")
        (tree / "work/alias").symlink_to("hello")
        (tree / "usr/local/bin/user-program").write_text("#!/bin/sh\nprintf 'user executable\\n'\n")
        (tree / "usr/local/bin/user-program").chmod(0o755)
        cls.image = cls.base / "base.ext4"
        with cls.image.open("wb") as stream:
            stream.truncate(536870912)
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", "-b", "4096", "-d", str(tree), str(cls.image)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.shared.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / "state"
        (self.state / "disk-generations").mkdir(parents=True)
        fingerprint = growth.domain.digest(self.image)
        self.source = self.state / "disk-generations" / (fingerprint + ".ext4")
        shutil.copyfile(self.image, self.source)
        self.source.chmod(0o400)
        self.previous = growth.domain.identity(self.source)
        native = self.state / "namespace-generations"
        native.mkdir()
        temporary = native / "initial.raw"
        with temporary.open("wb") as stream:
            stream.write(b"native object identity must survive disk-only growth")
            stream.truncate(0x1000000)
        selected = native / (growth.domain.digest(temporary) + ".raw")
        temporary.rename(selected)
        selected.chmod(0o400)
        self.namespace = growth.domain.identity(selected)
        self.head = self.state / "head.json"
        self.head.write_text(json.dumps({"schema": "ostadix.package-domain-disk-head/v2",
                                         "disk": self.previous, "namespace": self.namespace}))
        self.head_before = self.head.read_bytes()

    def retained(self):
        growth.domain.checked_file(self.source, self.previous)
        growth.domain.checked_file(Path(self.namespace["path"]), self.namespace)

    def test_real_resize_preserves_every_tree_entry_and_exact_namespace_pair(self):
        result = growth.grow(self.state)
        self.assertTrue(result["ok"])
        self.assertTrue(result["full_guest_tree_preserved"])
        head = json.loads(self.head.read_text())
        self.assertEqual(head["schema"], "ostadix.package-domain-disk-head/v2")
        self.assertEqual(head["namespace"], self.namespace)
        self.assertEqual(head["previous_namespace"], self.namespace)
        self.assertEqual(head["previous"], self.previous)
        self.assertEqual(head["disk"]["bytes"], 1073741824)
        image = Path(head["disk"]["path"])
        self.assertEqual(image.stat().st_mode & 0o777, 0o400)
        self.assertEqual(growth.filesystem_bytes(image), 1073741824)
        self.retained()
        growth.domain.checked_file(image, head["disk"])
        self.assertEqual(growth.stager.dump_file(image, "/work/hello", self.state / "readback").read_bytes(),
                         b"retain the user's source and executable\n")
        after = self.head.read_bytes()
        repeat = growth.grow(self.state)
        self.assertTrue(repeat["already_target_size"])
        self.assertEqual(self.head.read_bytes(), after)

    def test_running_domain_lock_prevents_cloning_or_publication(self):
        with (self.state / "domain.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, "stop the running"):
                growth.grow(self.state)
        self.assertFalse((self.state / "disk-migrations").exists())
        self.assertEqual(self.head.read_bytes(), self.head_before)
        self.retained()

    def test_resize_failure_keeps_exact_original_head_and_both_images(self):
        original = subprocess.run

        def fail_resize(argv, **kwargs):
            if argv[0] == "resize2fs":
                return subprocess.CompletedProcess(argv, 7, "", "fixture resize failure")
            return original(argv, **kwargs)

        with patch.object(growth.subprocess, "run", side_effect=fail_resize):
            with self.assertRaisesRegex(RuntimeError, "resize2fs failed"):
                growth.grow(self.state)
        self.assertEqual(self.head.read_bytes(), self.head_before)
        self.retained()

    def test_tree_difference_prevents_publication_even_with_clean_ext4(self):
        original = growth.stager.tree_identity

        def changed(image, guest, output):
            result = original(image, guest, output)
            if output.name == "after-tree":
                result.append({"path": "unexpected-content-change", "mode": 0o644})
            return result

        with patch.object(growth.stager, "tree_identity", side_effect=changed):
            with self.assertRaisesRegex(RuntimeError, "changed guest"):
                growth.grow(self.state)
        self.assertEqual(self.head.read_bytes(), self.head_before)
        self.retained()

    def test_ungranted_target_is_rejected_before_output(self):
        for size in (0, 536870912, 1073741824 + 4096, 2 * 1073741824):
            with self.subTest(size=size), self.assertRaises(ValueError):
                growth.grow(self.state, target_bytes=size)
        self.assertFalse((self.state / "disk-migrations").exists())
        self.assertEqual(self.head.read_bytes(), self.head_before)


if __name__ == "__main__":
    unittest.main()
