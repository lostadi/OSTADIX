"""Installed-source verification, corruption and explicit rebuild semantics."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tests.test_linux_package_domain_builder import builder


HELPER = builder.HERE / "pkg-plan9port"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(directory, exclude=()):
    return "".join(f"{digest(path)}  ./{path.relative_to(directory)}\n" for path in sorted(directory.rglob("*"))
                   if path.is_file() and path.name not in exclude)


class Plan9ProviderVerificationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.work = self.root / "work"
        self.receipt = self.work / "sources/plan9port-build.fixture/receipt"
        self.receipt.mkdir(parents=True)
        self.prefix = self.root / "installed/plan9"
        self.runtime = self.root / "installed/plan9.generations/runtime.fixture"
        (self.runtime / "bin").mkdir(parents=True)
        self.bin = self.root / "commands"
        self.bin.mkdir()
        for command in ("rc", "mk", "9p", "9pserve", "u9fs", "okernel-9p-bridge", "9"):
            path = self.runtime / "bin" / command
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o755)
            if command in ("rc", "mk", "9p", "9"):
                (self.bin / command).symlink_to(self.prefix / "bin" / command)
        self.prefix.symlink_to(self.runtime)
        self.stubs = self.root / "stubs"
        self.stubs.mkdir()
        apk = self.stubs / "apk"
        apk.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$APK_LOG"\nexit 31\n')
        apk.chmod(0o755)
        self.env = {**os.environ, "PATH": str(self.stubs) + os.pathsep + os.environ["PATH"],
                    "OSTADIX_PKG_WORK": str(self.work), "OSTADIX_PLAN9_PREFIX": str(self.prefix),
                    "OSTADIX_PLAN9_BIN": str(self.bin), "APK_LOG": str(self.root / "apk.log"),
                    "OSTADIX_PKG_NAMESPACE_HELPER": str(self.root / "absent-namespace")}
        self.bridge = self.root / "bridge.c"
        self.bridge.write_text("local bridge fixture source\n")
        self.bridge_helper = self.root / "pkg-9p"
        self.bridge_helper.write_text("#!/bin/sh\nexit 0\n")
        self.bridge_helper.chmod(0o755)
        self.u9fs_patch = self.root / "u9fs.patch"
        self.u9fs_patch.write_text("declared hardening fixture patch\n")
        self.env["OSTADIX_PKG_9P_BRIDGE_SOURCE"] = str(self.bridge)
        self.env["OSTADIX_PKG_9P_BRIDGE_HELPER"] = str(self.bridge_helper)
        self.env["OSTADIX_PKG_U9FS_PATCH"] = str(self.u9fs_patch)
        self.glibc_cc = self.root / "glibc-cc"
        self.glibc_cc.write_text("#!/bin/sh\nexit 0\n")
        self.glibc_cc.chmod(0o755)
        self.glibc_bundle = self.root / "glibc-abi.tar.gz"
        self.glibc_bundle.write_bytes(b"fixture ABI identity only; no binary execution\n")
        self.glibc_manifest = self.root / "glibc-abi.json"
        self.glibc_manifest.write_text('{"fixture": true}\n')
        self.glibc_stamp = self.root / "glibc-abi.sha256"
        self.glibc_stamp.write_text(digest(self.glibc_bundle) + "\n")
        self.env.update(OSTADIX_PKG_GLIBC_CC=str(self.glibc_cc), OSTADIX_PKG_GLIBC_BUNDLE=str(self.glibc_bundle),
                        OSTADIX_PKG_GLIBC_MANIFEST=str(self.glibc_manifest), OSTADIX_PKG_GLIBC_SHA256=str(self.glibc_stamp))
        self.activation = builder.HERE / "plan9port-activate"
        self.env["OSTADIX_PKG_PLAN9_ACTIVATION"] = str(self.activation)
        archive = f"plan9port-{builder.PLAN9PORT_REVISION}.tar.gz"
        for name, text in {
            "status": "complete\n",
            "source-revision.txt": f"revision={builder.PLAN9PORT_REVISION}\n",
            "upstream.sha256": f"{builder.PLAN9PORT_SHA256}  {archive}\n",
            "u9fs-source-revision.txt": f"revision={builder.U9FS_REVISION}\n",
            "u9fs-upstream.sha256": f"{builder.U9FS_SHA256}  u9fs-{builder.U9FS_REVISION}.tar.gz\n",
            "provider.sha256": f"{digest(HELPER)}  {HELPER}\n",
            "activation-helper.sha256": f"{digest(self.activation)}  {self.activation}\n",
            "runtime.path": str(self.runtime) + "\n",
            "outputs.sha256": manifest(self.runtime),
        }.items():
            (self.receipt / name).write_text(text)
        (self.receipt / "receipt-files.sha256").write_text(manifest(self.receipt))
        Path(str(self.runtime) + ".receipt").write_text("\n".join((
            "ocore.plan9port-installed/v3", builder.PLAN9PORT_REVISION, builder.PLAN9PORT_SHA256,
            builder.U9FS_REVISION, builder.U9FS_SHA256, digest(self.bridge), digest(self.bridge_helper), digest(self.u9fs_patch),
            digest(self.glibc_cc), digest(self.glibc_bundle), digest(self.glibc_manifest),
            str(self.receipt), digest(self.receipt / "receipt-files.sha256"), "")))

    def invoke(self, mode="install"):
        return subprocess.run(["sh", str(HELPER), mode], env=self.env, capture_output=True, text=True)

    def test_install_verifies_and_reuses_without_fetching_or_copying_source(self):
        before = sorted(str(path) for path in self.root.rglob("*"))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("OKERNEL SOURCE PACKAGE plan9port VERIFIED", result.stdout)
        self.assertNotIn("OKERNEL SOURCE BUILD", result.stdout)
        self.assertFalse((self.root / "apk.log").exists())
        self.assertEqual(sorted(str(path) for path in self.root.rglob("*")), before)

    def test_changed_output_or_extra_file_is_preserved_and_rejected(self):
        target = self.runtime / "bin/rc"
        target.write_text("changed output\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("explicit fresh source build", result.stderr)
        self.assertEqual(target.read_text(), "changed output\n")
        target.write_text("#!/bin/sh\nexit 0\n")
        extra = self.runtime / "unexpected"
        extra.write_text("extra artifact\n")
        self.assertEqual(self.invoke().returncode, 1)
        self.assertTrue(extra.is_file())
        self.assertFalse((self.root / "apk.log").exists())

    def test_receipt_damage_and_missing_executable_bit_are_not_silently_reused(self):
        (self.receipt / "upstream.sha256").write_text("changed receipt\n")
        self.assertEqual(self.invoke().returncode, 1)
        (self.receipt / "upstream.sha256").write_text(
            f"{builder.PLAN9PORT_SHA256}  plan9port-{builder.PLAN9PORT_REVISION}.tar.gz\n")
        (self.runtime / "bin/rc").chmod(0o644)
        self.assertEqual(self.invoke().returncode, 1)
        self.assertFalse((self.root / "apk.log").exists())

    def test_explicit_source_mode_rebuilds_instead_of_verifying_existing_generation(self):
        result = self.invoke("source")
        self.assertEqual(result.returncode, 31, result.stdout + result.stderr)
        self.assertEqual((self.root / "apk.log").read_text(),
                         "add build-base gcc make musl-dev linux-headers curl ca-certificates\n")
        self.assertNotIn("VERIFIED", result.stdout)

    def test_local_bridge_input_changes_and_old_receipt_version_require_fresh_source(self):
        self.bridge.write_text("changed bridge source\n")
        self.assertEqual(self.invoke().returncode, 1)
        self.bridge.write_text("local bridge fixture source\n")
        self.bridge_helper.write_text("changed bridge helper\n")
        self.assertEqual(self.invoke().returncode, 1)
        self.bridge_helper.write_text("#!/bin/sh\nexit 0\n")
        self.u9fs_patch.write_text("changed hardening patch\n")
        self.assertEqual(self.invoke().returncode, 1)
        self.u9fs_patch.write_text("declared hardening fixture patch\n")
        control = Path(str(self.runtime) + ".receipt")
        control.write_text(control.read_text().replace("installed/v3", "installed/v2"))
        self.assertEqual(self.invoke().returncode, 1)
        self.assertFalse((self.root / "apk.log").exists())

    def test_private_gnu_abi_input_changes_are_not_silently_reused(self):
        self.glibc_bundle.write_bytes(b"changed dependency closure\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("failed verification", result.stderr)
        self.assertFalse((self.root / "apk.log").exists())

    def test_reused_receipt_is_republished_and_publication_failure_is_returned(self):
        helper = self.root / "namespace"
        helper.write_text('#!/bin/sh\n[ "$1" = status ] && exit 0\nprintf "%s\\n" "$*" > "$PUBLISH_LOG"\nexit 23\n')
        helper.chmod(0o755)
        self.env["OSTADIX_PKG_NAMESPACE_HELPER"] = str(helper)
        self.env["PUBLISH_LOG"] = str(self.root / "published.log")
        result = self.invoke()
        self.assertEqual(result.returncode, 23)
        self.assertEqual((self.root / "published.log").read_text(), f"publish-source plan9port {self.receipt}\n")
        self.assertNotIn("VERIFIED", result.stdout)


if __name__ == "__main__":
    unittest.main()
