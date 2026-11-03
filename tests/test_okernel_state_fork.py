"""Saved immutable checkpoint forks must never modify a running source state."""
import copy
import fcntl
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("state_fork", ROOT / "scripts/fork_okernel_state.py")
forker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(forker)


class SavedStateForkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.area = Path(self.temporary.name)
        self.source = self.area / "source"
        self.source.mkdir()
        self.output = self.area / "isolated"
        runner = forker.runner
        disk = self.source / "disk-generations/pending"
        disk.parent.mkdir()
        with disk.open("xb") as stream:
            stream.truncate(536870912)
        fingerprint = runner.digest(disk)
        disk = disk.rename(disk.with_name(fingerprint + ".ext4"))
        native = self.source / "namespace-generations/pending"
        native.parent.mkdir()
        with native.open("xb") as stream:
            stream.truncate(0x1000000)
        fingerprint = runner.digest(native)
        native = native.rename(native.with_name(fingerprint + ".raw"))
        self.head = {"schema": "ostadix.package-domain-disk-head/v2", "disk": runner.identity(disk), "namespace": runner.identity(native)}
        (self.source / "head.json").write_text(json.dumps(self.head))
        self.before = (self.source / "head.json").read_bytes()
        self.profile = {
            "schema": "ostadix.kernel-world-linux-monitor/v1", "profile": "package-domain",
            "backing_base": 0x70000000, "backing_bytes": 536870912,
            "block_backing": {"address": 0x70000000, "bytes": 536870912},
            "guest_ram_ipa": 0x40000000, "guest_ram_pa": 0x48000000, "guest_ram_bytes": 0x20000000,
            "outer_ram_bytes": 0x80000000,
            "loader_addresses": {"Image": 0x48000000, "guest_dtb": 0x4fe00000, "initramfs": 0x50000000},
            "namespace_grant": copy.deepcopy(runner.NAMESPACE_GRANT), "network_grant": copy.deepcopy(runner.NETWORK_GRANT),
            "artifacts": {}}
        (self.source / "monitor").mkdir()
        for name in ("monitor", "profile", "guest_dtb", "Image", "initramfs"):
            artifact = self.source / "monitor" / (name + ".input")
            artifact.write_bytes(name.encode() + b" original bytes")
            self.profile["artifacts"][name] = runner.identity(artifact)
        (self.source / "monitor/monitor-profile.json").write_text(json.dumps(self.profile))

    def test_running_source_can_fork_saved_pair_without_sharing_mutable_inodes(self):
        with (self.source / "domain.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = forker.fork(self.source, self.output)
        self.assertTrue(result["ok"])
        self.assertEqual((self.source / "head.json").read_bytes(), self.before)
        head = json.loads((self.output / "head.json").read_text())
        forker.runner.validate_head(self.output, head)
        for key in ("disk", "namespace"):
            self.assertEqual(head[key]["sha256"], self.head[key]["sha256"])
            self.assertNotEqual(Path(head[key]["path"]).stat().st_ino, Path(self.head[key]["path"]).stat().st_ino)
            self.assertEqual(Path(head[key]["path"]).stat().st_mode & 0o777, 0o400)
        profile = json.loads((self.output / "monitor/monitor-profile.json").read_text())
        for record in profile["artifacts"].values():
            path = Path(record["path"])
            self.assertTrue(path.is_relative_to(self.output))
            forker.runner.checked_file(path, record)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_artifact_tampering_fails_before_creating_output(self):
        Path(self.profile["artifacts"]["monitor"]["path"]).write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            forker.fork(self.source, self.output)
        self.assertFalse(self.output.exists())

    def payload_metadata(self):
        payload = self.source / "payload"
        payload.mkdir()
        config = payload / "linux.config"
        config.write_text("CONFIG_PROC_FS=y\n")
        image = self.profile["artifacts"]["Image"]
        metadata = {"schema": "ostadix.real-linux-payload/v1", "profile": "package-domain",
                    "artifacts": {"Image": {key: image[key] for key in ("bytes", "sha256")},
                                  "linux.config": forker.runner.identity(config)}}
        (payload / "linux-payload.json").write_text(json.dumps(metadata))
        return metadata

    def test_rebuild_metadata_and_configuration_follow_the_exact_image(self):
        metadata = self.payload_metadata()
        forker.fork(self.source, self.output)
        self.assertEqual(json.loads((self.output / "payload/linux-payload.json").read_text()), metadata)
        self.assertEqual((self.output / "payload/linux.config").read_text(), "CONFIG_PROC_FS=y\n")

    def test_stale_payload_metadata_cannot_be_copied_with_new_image(self):
        metadata = self.payload_metadata()
        metadata["artifacts"]["Image"]["sha256"] = "f" * 64
        (self.source / "payload/linux-payload.json").write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, "selected boot Image"):
            forker.fork(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_existing_or_nested_output_is_rejected_without_source_changes(self):
        self.output.mkdir()
        for target in (self.output, self.source / "nested"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                forker.fork(self.source, target)
        self.assertEqual((self.source / "head.json").read_bytes(), self.before)

    def test_failed_copy_does_not_publish_a_partial_head(self):
        original = forker.clone_file
        def fail_namespace(source, target, expected, **kwargs):
            if target.suffix == ".raw":
                raise OSError("simulated copy failure")
            return original(source, target, expected, **kwargs)
        with patch.object(forker, "clone_file", side_effect=fail_namespace):
            with self.assertRaisesRegex(OSError, "copy failure"):
                forker.fork(self.source, self.output)
        self.assertFalse((self.output / "head.json").exists())
        self.assertFalse(json.loads((self.output / "fork.json").read_text())["ok"])
        self.assertEqual((self.source / "head.json").read_bytes(), self.before)


if __name__ == "__main__":
    unittest.main()
