"""Guest mount and metadata semantics; native wire proof is a separate gate."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "ocore/guest/linux/package-domain/pkg-namespace"


class GuestNamespaceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.native = self.root / "native"
        self.native.mkdir()
        self.mounts = self.root / "mounts"
        self.mounts.write_text("")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, program in {
            "sync": "exit 0\n",
            "apk": "printf 'gcc-15.2.0-r0\\nzlib-1.3.2-r1\\n'\n",
            "mount": 'printf "%s\\n" "$*" > "$MOUNT_LOG"; printf "okernel %s 9p rw 0 0\\n" "$OSTADIX_PKG_NAMESPACE" > "$OSTADIX_PKG_MOUNTS"\n',
        }.items():
            path = self.bin / name
            path.write_text("#!/bin/sh\n" + program)
            path.chmod(0o755)
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                    "OSTADIX_PKG_NAMESPACE": str(self.native), "OSTADIX_PKG_MOUNTS": str(self.mounts),
                    "OSTADIX_PKG_VIRTIO_SYSFS": str(self.root / "virtio"), "MOUNT_LOG": str(self.root / "mount.log")}

    def invoke(self, *arguments):
        return subprocess.run(["sh", str(HELPER), *arguments], env=self.env, capture_output=True, text=True)

    def mark_mounted(self):
        self.mounts.write_text(f"okernel {self.native} 9p rw 0 0\n")

    def test_missing_device_never_populates_an_unmounted_local_directory(self):
        result = self.invoke("mount")
        self.assertEqual(result.returncode, 3, result.stderr)
        result = self.invoke("publish-apk", "jq")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(list(self.native.iterdir()), [])
        self.assertFalse((self.root / "mount.log").exists())

    def test_mount_uses_original_linux_9p_client_only_for_exact_granted_tag(self):
        device = self.root / "virtio/virtio3"
        device.mkdir(parents=True)
        (device / "mount_tag").write_text("another-store\n")
        self.assertEqual(self.invoke("mount").returncode, 3)
        (device / "mount_tag").write_text("okernel\n")
        result = self.invoke("mount")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "mount.log").read_text().strip(),
                         f"-t 9p -o trans=virtio,version=9p2000,msize=8192,cache=none okernel {self.native}")
        self.assertTrue((self.native / "work").is_dir())

    def test_source_receipt_preserves_bytes_and_describes_no_apk_ownership(self):
        self.mark_mounted()
        receipt = self.root / "receipt"
        receipt.mkdir()
        names = ("commands.txt", "compiler-version.txt", "compiler.sha256", "environment.txt",
                 "installed-packages.txt", "loader-path.txt", "outputs.sha256", "source-files.sha256", "upstream.sha512")
        for name in names:
            (receipt / name).write_text(f"original {name}\n")
        (receipt / "status").write_text("complete\n")
        result = self.invoke("publish-source", "zlib", str(receipt))
        self.assertEqual(result.returncode, 0, result.stderr)
        route = (self.native / "pkg/zlib").read_text()
        self.assertIn("apk_ownership=false\n", route)
        self.assertIn("metadata_grants_authority=false\n", route)
        destination = next((self.native / "build").iterdir())
        for name in (*names, "status"):
            self.assertEqual((destination / name).read_bytes(), (receipt / name).read_bytes())
        self.assertEqual(destination.name, hashlib.sha256((destination / "manifest.sha256").read_bytes()).hexdigest())
        self.assertEqual(self.invoke("publish-source", "zlib", str(receipt)).returncode, 0)
        (destination / "outputs.sha256").write_text("tampered\n")
        self.assertEqual(self.invoke("publish-source", "zlib", str(receipt)).returncode, 1)

    def test_apk_record_retains_exact_request_and_complete_inventory(self):
        self.mark_mounted()
        result = self.invoke("publish-apk", "jq")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("provider=original-apk\n", (self.native / "pkg/jq").read_text())
        destination = next((self.native / "build").iterdir())
        self.assertEqual((destination / "request.txt").read_text(), "jq\n")
        self.assertIn("gcc-15.2.0", (destination / "installed-packages.txt").read_text())
        self.assertEqual(self.invoke("publish-apk", "bad\nrecord").returncode, 2)

    def test_plan9port_receipt_retains_large_input_inventory_and_original_build_log(self):
        self.mark_mounted()
        receipt = self.root / "receipt"
        receipt.mkdir()
        for name in ("commands.txt", "compiler-version.txt", "compiler.sha256", "environment.txt",
                     "installed-packages.txt", "outputs.sha256", "source-files.sha256", "upstream.sha256"):
            (receipt / name).write_text((name + "\n") * (10000 if name == "source-files.sha256" else 1))
        (receipt / "status").write_text("complete\n")
        (receipt / "build.log").write_text("original compiler output\n")
        result = self.invoke("publish-source", "plan9port", str(receipt))
        self.assertEqual(result.returncode, 0, result.stderr)
        route = (self.native / "pkg/plan9port").read_text()
        self.assertIn("provider=plan9port-upstream-source\n", route)
        self.assertIn("abi=linux-aarch64\n", route)
        destination = next((self.native / "build").iterdir())
        self.assertEqual((destination / "source-files.sha256").read_bytes(), (receipt / "source-files.sha256").read_bytes())
        self.assertEqual((destination / "build.log").read_bytes(), (receipt / "build.log").read_bytes())


if __name__ == "__main__":
    unittest.main()
