"""Real ext4 edits and publication; the upstream authenticated builder is mocked."""

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
SPEC = importlib.util.spec_from_file_location("repository_stage", ROOT / "scripts/stage_okernel_repository.py")
staging = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(staging)


@unittest.skipUnless(all(shutil.which(name) for name in ("mke2fs", "debugfs", "e2fsck")), "e2fsprogs required")
class RepositoryStagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name)
        root = cls.base / "fixture-root"
        for directory in ("etc/apk", "lib/apk/db", "work", "repositories/main/aarch64", "repositories/community/aarch64"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        (root / "etc/apk/world").write_text("busybox\n")
        (root / "etc/apk/repositories").write_text("/repositories/main\n/repositories/community\n")
        (root / "lib/apk/db/installed").write_text("P:busybox\nV:fixture\n")
        (root / "work/hello").write_bytes(b"persistent executable fixture")
        for name in ("main", "community"):
            (root / "repositories" / name / "aarch64/APKINDEX.tar.gz").write_text(name + " fixture index")
        cls.base_image = cls.base / "base.ext4"
        with cls.base_image.open("wb") as stream:
            stream.truncate(536870912)
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", "-b", "4096", "-d", str(root), str(cls.base_image)], check=True)
        cls.base_digest = staging.domain.digest(cls.base_image)

    def setUp(self):
        self.run = Path(tempfile.mkdtemp(dir=self.base, prefix="test-"))
        self.state = self.run / "state"
        (self.state / "rootfs").mkdir(parents=True)
        source = self.state / "rootfs/package-domain.ext4"
        shutil.copyfile(self.base_image, source)
        (self.state / "rootfs/package-domain.json").write_text(json.dumps({
            "schema": "ostadix.linux-package-domain/v1", "architecture": "aarch64",
            "artifacts": {"package-domain.ext4": {"path": str(source), "bytes": 536870912, "sha256": self.base_digest}},
        }))
        self.bad_hash = False

    def bundle(self, output, indexes, cache, packages):
        self.assertIn("busybox", packages)
        self.assertIn("curl", packages)
        records = []
        for name in ("main", "community"):
            directory = output / "repository-cache" / name / "aarch64"
            directory.mkdir(parents=True)
            shutil.copyfile(indexes / name / "aarch64/APKINDEX.tar.gz", directory / "APKINDEX.tar.gz")
            records.append({"name": name, "index_sha256": staging.domain.digest(directory / "APKINDEX.tar.gz"), "signature_verified": True})
        archive = output / "repository-cache/main/aarch64/curl-1-r0.apk"
        archive.write_bytes(b"authenticated-builder fixture archive")
        manifest = {
            "schema": "ostadix.linux-package-repository/v1", "architecture": "aarch64",
            "repositories_path": str(output / "repository-cache"), "repository_snapshots": records,
            "offline_package_closure": [{"repository": "main", "filename": archive.name,
                                         "sha256": "0" * 64 if self.bad_hash else staging.domain.digest(archive),
                                         "signature_verified": True}],
        }
        (output / "repository-bundle.json").write_text(json.dumps(manifest))
        return manifest

    def test_staging_preserves_installed_state_and_publishes_readonly_generation(self):
        with patch.object(staging, "build_repository_bundle", side_effect=self.bundle):
            result = staging.stage(self.state, ["curl"], self.run / "cache")
        self.assertTrue(result["ok"])
        self.assertTrue(result["workspace_and_apk_state_preserved"])
        head = json.loads((self.state / "head.json").read_text())
        image = Path(head["disk"]["path"])
        self.assertEqual(image.parent, self.state / "disk-generations")
        self.assertEqual(image.stat().st_mode & 0o777, 0o400)
        staging.domain.checked_file(image, head["disk"])
        dumped = staging.dump_file(image, "/work/hello", self.run / "hello")
        self.assertEqual(dumped.read_bytes(), b"persistent executable fixture")
        dumped = staging.dump_file(image, "/repositories/main/aarch64/curl-1-r0.apk", self.run / "curl.apk")
        self.assertEqual(dumped.read_bytes(), b"authenticated-builder fixture archive")
        self.assertEqual(staging.domain.digest(self.state / "rootfs/package-domain.ext4"), self.base_digest)
        self.assertEqual(head["previous"]["sha256"], self.base_digest)

    def test_active_domain_lock_prevents_staging(self):
        with (self.state / "domain.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(staging, "build_repository_bundle") as build:
                with self.assertRaisesRegex(RuntimeError, "stop the running"):
                    staging.stage(self.state, ["curl"], self.run / "cache")
                build.assert_not_called()
        self.assertFalse((self.state / "head.json").exists())

    def test_staging_preserves_the_exact_shared_namespace_generation(self):
        generations = self.state / "disk-generations"
        generations.mkdir()
        disk = generations / (self.base_digest + ".ext4")
        shutil.copyfile(self.base_image, disk)
        objects = self.state / "namespace-generations"
        objects.mkdir()
        temporary = objects / "temporary.raw"
        with temporary.open("xb") as stream:
            stream.truncate(0x1000000)
        fingerprint = staging.domain.digest(temporary)
        native = objects / (fingerprint + ".raw")
        temporary.rename(native)
        namespace = staging.domain.identity(native)
        (self.state / "head.json").write_text(json.dumps({
            "schema": "ostadix.package-domain-disk-head/v2",
            "disk": staging.domain.identity(disk), "namespace": namespace}))
        with patch.object(staging, "build_repository_bundle", side_effect=self.bundle):
            staging.stage(self.state, ["curl"], self.run / "cache")
        current = json.loads((self.state / "head.json").read_text())
        self.assertEqual(current["schema"], "ostadix.package-domain-disk-head/v2")
        self.assertEqual(current["namespace"], namespace)
        staging.domain.checked_file(native, namespace)

    def test_payload_identity_failure_does_not_publish_or_mutate_base(self):
        self.bad_hash = True
        with patch.object(staging, "build_repository_bundle", side_effect=self.bundle):
            with self.assertRaisesRegex(ValueError, "payload changed"):
                staging.stage(self.state, ["curl"], self.run / "cache")
        self.assertFalse((self.state / "head.json").exists())
        self.assertEqual(staging.domain.digest(self.state / "rootfs/package-domain.ext4"), self.base_digest)

    def test_unexpected_database_mutation_prevents_publication(self):
        original_import = staging.import_payloads
        def mutate(image, payloads, work):
            original_import(image, payloads, work)
            bad = work / "bad-db"
            bad.write_text("unexpected database change")
            command = work / "mutate.debugfs"
            command.write_text(f'rm /lib/apk/db/installed\nwrite "{bad}" /lib/apk/db/installed\n')
            subprocess.run(["debugfs", "-w", "-f", str(command), str(image)], check=True, capture_output=True)
        with patch.object(staging, "build_repository_bundle", side_effect=self.bundle), patch.object(staging, "import_payloads", side_effect=mutate):
            with self.assertRaisesRegex(RuntimeError, "changed workspace"):
                staging.stage(self.state, ["curl"], self.run / "cache")
        self.assertFalse((self.state / "head.json").exists())
        self.assertEqual(staging.domain.digest(self.state / "rootfs/package-domain.ext4"), self.base_digest)


if __name__ == "__main__":
    unittest.main()
