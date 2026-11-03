"""Validate monitor profile binding without building kernels or running VMs."""

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "ocore/kernel/build-aarch64-kernel-world-linux.sh"
SOURCE_SHA = "0fcbbbbcd456e87bbbfc8bf37af541fda62ccfcce76903503424fd101ef7bdee"


class LinuxMonitorProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.payload = self.root / "payload"
        self.payload.mkdir()
        self.build = self.root / "build"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.calls = self.root / "calls.jsonl"
        image = bytearray(64)
        struct.pack_into("<QQ", image, 8, 0, 64)
        image[56:60] = b"ARM\x64"
        (self.payload / "Image").write_bytes(image)
        (self.payload / "initramfs.cpio").write_bytes(b"test initrd")
        self.manifest = {
            "linux_version": "6.12.43", "source_modifications": False,
            "source_archive_sha256": SOURCE_SHA,
            "artifacts": {"Image": {"bytes": len(image), "sha256": hashlib.sha256(image).hexdigest()}},
        }
        tool = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
with Path(os.environ['TEST_COMMAND_LOG']).open('a') as log:
    log.write(json.dumps([Path(sys.argv[0]).name, *sys.argv[1:]]) + '\\n')
args = sys.argv[1:]
if '-o' in args:
    Path(args[args.index('-o')+1]).write_bytes(b'test-build-output')
"""
        for name in ("ocorec", "clang", "dtc", "ld.lld"):
            path = self.tools / name
            path.write_text(tool)
            path.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": str(self.tools) + os.pathsep + os.environ["PATH"],
            "OCORE_LINUX_PAYLOAD_DIR": str(self.payload),
            "OCORE_LINUX_BUILD_DIR": str(self.build),
            "OCORE_LINUX_OCOREC_BIN": str(self.tools / "ocorec"),
            "OCORE_LINUX_LLD": str(self.tools / "ld.lld"),
            "TEST_COMMAND_LOG": str(self.calls),
        }
        self.env.pop("OCORE_LINUX_PROFILE", None)
        self.env.pop("OCORE_LINUX_BACKING_BYTES", None)
        self.env.pop("OCORE_LINUX_NETWORK", None)
        self.env.pop("OCORE_LINUX_NAMESPACE", None)

    def run_builder(self):
        (self.payload / "linux-payload.json").write_text(json.dumps(self.manifest))
        return subprocess.run(["bash", str(BUILDER)], env=self.env, capture_output=True, text=True)

    def test_default_profile_preserves_withdrawal_policy(self):
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        profile = (self.build / "profile.oc").read_text()
        self.assertIn("PERSISTENT: u64 = 0;", profile)
        evidence = json.loads((self.build / "monitor-profile.json").read_text())
        self.assertEqual(evidence["profile"], "withdrawal")
        self.assertEqual(evidence["backing_base"], 0)
        self.assertEqual(evidence["backing_bytes"], 0)
        self.assertIsNone(evidence["block_backing"])
        self.assertFalse(evidence["network_grant"]["enabled"])
        self.assertFalse(evidence["namespace_grant"]["enabled"])
        self.assertTrue(all(value is None for key, value in evidence["namespace_grant"].items() if key != "enabled"))
        self.assertNotIn("virtio_mmio@a000200", (self.build / "guest.dts").read_text())
        self.assertNotIn("virtio_mmio@a000400", (self.build / "guest.dts").read_text())
        self.assertIn("NAMESPACE: u64 = 0;", profile)
        self.assertEqual(evidence["outer_ram_bytes"], 1024 ** 3)
        self.assertIn("-DKW_PACKAGE_PROFILE=0", self.calls.read_text())

    def test_package_profile_binds_explicit_disk_and_idle_input_mode(self):
        self.env["OCORE_LINUX_PROFILE"] = "package-domain"
        self.manifest["profile"] = "package-domain"
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        profile = (self.build / "profile.oc").read_text()
        self.assertIn("PERSISTENT: u64 = 1;", profile)
        self.assertIn("BACKING_BYTES: usize = 536870912;", profile)
        evidence = json.loads((self.build / "monitor-profile.json").read_text())
        self.assertEqual(evidence["profile"], "package-domain")
        self.assertEqual(evidence["backing_base"], 0x70000000)
        self.assertEqual(evidence["backing_bytes"], 512 * 1024 ** 2)
        self.assertEqual(evidence["outer_ram_bytes"], 2 * 1024 ** 3)
        self.assertEqual(evidence["loader_addresses"]["initramfs"], 0x50000000)
        self.assertIn("-DKW_PACKAGE_PROFILE=1", self.calls.read_text())
        self.assertEqual(evidence["artifacts"]["Image"]["sha256"], self.manifest["artifacts"]["Image"]["sha256"])
        self.assertEqual(len(evidence["source_sha256"]), 12)

    def test_package_profile_accepts_explicit_one_gib_disk_with_same_outer_ram(self):
        self.env.update(OCORE_LINUX_PROFILE="package-domain", OCORE_LINUX_BACKING_BYTES="1073741824")
        self.manifest["profile"] = "package-domain"
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads((self.build / "monitor-profile.json").read_text())
        self.assertEqual(evidence["backing_bytes"], 1073741824)
        self.assertEqual(evidence["block_backing"], {"address": 0x70000000, "bytes": 1073741824})
        self.assertEqual(evidence["outer_ram_bytes"], 2 * 1024 ** 3)
        self.assertIn("BACKING_BYTES: usize = 1073741824;", (self.build / "profile.oc").read_text())

    def test_online_network_is_an_explicit_package_only_grant(self):
        self.env["OCORE_LINUX_PROFILE"] = "package-domain"
        self.env["OCORE_LINUX_NETWORK"] = "1"
        self.manifest["profile"] = "package-domain"
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads((self.build / "monitor-profile.json").read_text())
        self.assertTrue(evidence["network_grant"]["enabled"])
        self.assertEqual(evidence["network_grant"]["mac"], "52:54:00:12:34:56")
        self.assertEqual(evidence["network_grant"]["guest_irq"], 49)
        self.assertEqual(evidence["network_grant"]["host_dma_base"], 0x6e000000)
        self.assertIn("NETWORK: u64 = 1;", (self.build / "profile.oc").read_text())
        self.assertIn("virtio_mmio@a000200", (self.build / "guest.dts").read_text())

    def test_withdrawal_rejects_network_before_outputs(self):
        self.env["OCORE_LINUX_NETWORK"] = "1"
        result = self.run_builder()
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.build.exists())
        self.assertFalse(self.calls.exists())

    def test_native_namespace_is_an_explicit_package_only_grant(self):
        self.env["OCORE_LINUX_PROFILE"] = "package-domain"
        self.env["OCORE_LINUX_NAMESPACE"] = "1"
        self.manifest["profile"] = "package-domain"
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads((self.build / "monitor-profile.json").read_text())
        self.assertEqual(evidence["namespace_grant"], {
            "enabled": True, "transport": "native O-core 9P2000 over virtio-mmio",
            "guest_mmio": 0x0a000400, "guest_irq": 50, "mount_tag": "okernel",
            "address": 0x6c000000, "bytes": 0x01000000, "epoch_address": 0x6d000000,
            "quiescence_address": 0x6d000008,
            "clock_address": 0x6d000010,
            "linux_grant": 1, "native_peer_grant": 2,
        })
        profile = (self.build / "profile.oc").read_text()
        self.assertIn("NAMESPACE: u64 = 1;", profile)
        self.assertFalse(evidence["network_grant"]["enabled"])
        self.assertIn("virtio_mmio@a000400", (self.build / "guest.dts").read_text())
        for source in ("ocore/runtime/common/namespace_store.oc", "ocore/runtime/common/namespace_peer.oc",
                       "ocore/runtime/aarch64/kernel_world_9p.oc"):
            self.assertIn(source, evidence["source_sha256"])
            self.assertEqual(evidence["source_sha256"][source], hashlib.sha256((ROOT / source).read_bytes()).hexdigest())

    def test_network_and_namespace_have_distinct_concurrent_devices(self):
        self.env.update(OCORE_LINUX_PROFILE="package-domain", OCORE_LINUX_NAMESPACE="1", OCORE_LINUX_NETWORK="1")
        self.manifest["profile"] = "package-domain"
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads((self.build / "monitor-profile.json").read_text())
        self.assertNotEqual(evidence["namespace_grant"]["guest_irq"], evidence["network_grant"]["guest_irq"])
        dts = (self.build / "guest.dts").read_text()
        self.assertIn("virtio_mmio@a000200", dts)
        self.assertIn("virtio_mmio@a000400", dts)
        self.assertIn("interrupts = <0 17 4>", dts)
        self.assertIn("interrupts = <0 18 4>", dts)

    def test_withdrawal_rejects_namespace_before_outputs(self):
        self.env["OCORE_LINUX_NAMESPACE"] = "1"
        result = self.run_builder()
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.build.exists())
        self.assertFalse(self.calls.exists())

    def test_unknown_namespace_flag_rejected_before_outputs(self):
        for flag in ("yes", "2", "-1"):
            with self.subTest(flag=flag):
                self.env["OCORE_LINUX_NAMESPACE"] = flag
                result = self.run_builder()
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.build.exists())
                self.assertFalse(self.calls.exists())

    def test_package_monitor_rejects_default_linux_payload(self):
        self.env["OCORE_LINUX_PROFILE"] = "package-domain"
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("payload profile does not match", result.stderr)
        self.assertFalse(self.calls.exists())

    def test_default_monitor_rejects_package_linux_payload(self):
        self.manifest["profile"] = "package-domain"
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_unknown_profile_is_rejected_before_outputs(self):
        self.env["OCORE_LINUX_PROFILE"] = "anything"
        result = self.run_builder()
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.build.exists())
        self.assertFalse(self.calls.exists())

    def test_unbounded_or_unaligned_disk_is_rejected(self):
        for size in ("0", "512", "1073745920", "2147483648", "-1", "not-a-size"):
            with self.subTest(size=size):
                self.env["OCORE_LINUX_BACKING_BYTES"] = size
                result = self.run_builder()
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.build.exists())
                self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
