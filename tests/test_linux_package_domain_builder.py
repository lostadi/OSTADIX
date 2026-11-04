"""Rootfs and boot-archive boundaries; no package or kernel builds."""

import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("package_domain_builder", ROOT / "ocore/guest/linux/package-domain/build.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def read_newc(path):
    data = path.read_bytes()
    offset = 0
    entries = {}
    while True:
        header = data[offset:offset + 110]
        assert header[:6] == b"070701"
        fields = [int(header[6 + i * 8:14 + i * 8], 16) for i in range(13)]
        offset += 110
        name = data[offset:offset + fields[11] - 1].decode()
        offset = (offset + fields[11] + 3) & ~3
        content = data[offset:offset + fields[6]]
        offset = (offset + fields[6] + 3) & ~3
        if name == "TRAILER!!!":
            return entries
        entries[name] = (fields, content)


class PackageDomainBuilderTests(unittest.TestCase):
    def test_new_disk_defaults_to_one_gib_and_explicit_legacy_size_is_preserved(self):
        for extra, expected in (([], 1073741824), (["--disk-bytes", "536870912"], 536870912)):
            with self.subTest(arguments=extra), tempfile.TemporaryDirectory() as temporary:
                with patch.object(sys, "argv", ["build.py", "--output", temporary, *extra]), \
                        patch.object(builder.os, "geteuid", return_value=0), \
                        patch.object(builder, "prepare", return_value={"artifacts": {}}) as prepare, \
                        patch.object(sys, "stdout", io.StringIO()):
                    self.assertEqual(builder.main(), 0)
                self.assertEqual(prepare.call_args.args[0].disk_bytes, expected)

    def test_unsafe_archive_paths_are_rejected(self):
        for name in ("../outside", "/etc/passwd", "a/../../outside", "nul\x00byte"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                builder.archive_name(name)
        self.assertEqual(builder.archive_name("./usr/bin/cc"), "usr/bin/cc")

    def test_absolute_guest_symlinks_are_preserved_without_host_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "rootfs.tar"
            with tarfile.open(archive, "w") as tf:
                member = tarfile.TarInfo("./bin/busybox")
                member.mode = 0o755
                member.size = 7
                tf.addfile(member, io.BytesIO(b"fixture"))
                link = tarfile.TarInfo("./bin/sh")
                link.type = tarfile.SYMTYPE
                link.linkname = "/bin/busybox"
                tf.addfile(link)
            root = base / "root"
            with patch.object(builder.os, "chown"):
                builder.extract_rootfs(archive, root)
            self.assertEqual((root / "bin/busybox").read_bytes(), b"fixture")
            self.assertEqual(os.readlink(root / "bin/sh"), "/bin/busybox")
            with self.assertRaisesRegex(ValueError, "symlink"):
                builder.write_file(root, "bin/sh", b"replacement")

    def test_generated_overlay_cannot_follow_upstream_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "etc").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "symlink"):
                builder.write_file(root, "etc/passwd", "must not escape")
            self.assertFalse((outside / "passwd").exists())

    def test_newc_preserves_dynamic_runtime_symlinks_and_console_device(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            (root / "dev").mkdir(parents=True)
            (root / "bin").mkdir()
            (root / "bin/busybox").write_bytes(b"actual fixture bytes")
            (root / "bin/busybox").chmod(0o755)
            (root / "bin/sh").symlink_to("/bin/busybox")
            init = base / "init"
            init.write_text("#!/bin/sh\nexec switch_root /newroot /sbin/package-domain-init\n")
            first, second = base / "first.cpio", base / "second.cpio"
            builder.make_cpio(root, first, init)
            os.utime(root / "bin/busybox", (1000000000, 1000000000))
            builder.make_cpio(root, second, init)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            entries = read_newc(first)
            self.assertEqual(entries["bin/sh"][1], b"/bin/busybox")
            self.assertTrue(stat.S_ISLNK(entries["bin/sh"][0][1]))
            self.assertEqual(entries["bin/busybox"][1], b"actual fixture bytes")
            console = entries["dev/console"][0]
            self.assertTrue(stat.S_ISCHR(console[1]))
            self.assertEqual(console[9:11], [5, 1])
            self.assertEqual(entries["init"][1], init.read_bytes())


class SourceFirstFrontendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.pkg = self.bin / "pkg"
        self.pkg.write_bytes((builder.HERE / "pkg").read_bytes())
        self.pkg.chmod(0o755)
        apk = self.bin / "apk"
        apk.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$APK_LOG"\n')
        apk.chmod(0o755)
        sync = self.bin / "sync"
        sync.write_text("#!/bin/sh\nexit 0\n")
        sync.chmod(0o755)
        sources = self.root / "sources/zlib"
        sources.mkdir(parents=True)
        for name in builder.SOURCE_FILES:
            (sources / name).write_text("source fixture input\n")
        (sources / "SHA512SUMS").write_text("".join(
            f"{builder.digest(sources / name, 'sha512')}  {name}\n" for name in builder.SOURCE_FILES
        ))
        self.tree = self.root / "original/zlib-1.3.2"
        self.tree.mkdir(parents=True)
        (self.tree / "README").write_text("before\n")
        (sources / "CVE-2026-85091.patch").write_text("--- a/README\n+++ b/README\n@@ -1 +1 @@\n-before\n+after\n")
        self.sources = sources
        self.u9fs_patch = self.root / "declared-u9fs.patch"
        self.u9fs_patch.write_text("source fixture input\n")
        self.env = {
            **os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "APK_LOG": str(self.root / "apk.log"),
            "OSTADIX_PKG_SOURCES": str(self.root / "sources"),
            "OSTADIX_PKG_WORK": str(self.root / "work"),
            "OSTADIX_PKG_PREFIX": str(self.root / "installed"),
            "OSTADIX_PKG_LOADER_PATH": str(self.root / "loader.path"),
            "OSTADIX_PKG_9P_BRIDGE_SOURCE": str(builder.HERE / "okernel-9p-bridge.c"),
            "OSTADIX_PKG_9P_BRIDGE_HELPER": str(builder.HERE / "pkg-9p"),
            "OSTADIX_PKG_U9FS_PATCH": str(self.u9fs_patch),
            "OSTADIX_PKG_PLAN9_ACTIVATION": str(builder.HERE / "plan9port-activate"),
        }

    def invoke(self, *arguments):
        if arguments[:2] in (("install", "zlib"), ("source", "zlib")):
            with tarfile.open(self.sources / "zlib-1.3.2.tar.gz", "w:gz") as archive:
                archive.add(self.tree, arcname="zlib-1.3.2")
            (self.sources / "SHA512SUMS").write_text("".join(
                f"{builder.digest(self.sources / name, 'sha512')}  {name}\n" for name in builder.SOURCE_FILES
            ))
        return subprocess.run([str(self.pkg), *arguments], env=self.env, capture_output=True, text=True)

    def test_registered_source_is_preferred_and_original_build_runs(self):
        namespace = self.bin / "pkg-namespace"
        namespace.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$NAMESPACE_LOG"\n')
        namespace.chmod(0o755)
        self.env["OSTADIX_PKG_NAMESPACE_HELPER"] = str(namespace)
        self.env["NAMESPACE_LOG"] = str(self.root / "namespace.log")
        (self.tree / "fixture.c").write_text('int main(void) { return 0; }\n')
        configure = self.tree / "configure"
        configure.write_text('''#!/bin/sh
set -eu
printf 'configured source provider\\n'
''')
        configure.chmod(0o755)
        (self.tree / "Makefile").write_text(
            "all: fixture\nfixture: fixture.c\n\tcc fixture.c -o fixture\n"
            "check: fixture\n\t./fixture\ninstall: fixture\n\tmkdir -p \"$$OSTADIX_PKG_PREFIX/lib\"\n\tcp fixture \"$$OSTADIX_PKG_PREFIX/lib/libz-fixture.a\"\nclean:\n\trm -f fixture\n"
        )
        result = self.invoke("install", "zlib")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        builds = list((self.root / "work/sources").glob("zlib-build.*"))
        self.assertEqual(len(builds), 1)
        self.assertTrue((builds[0] / "zlib-1.3.2/fixture").is_file())
        self.assertFalse((self.tree / "fixture").exists())
        self.assertEqual((self.tree / "README").read_text(), "before\n")
        self.assertEqual((builds[0] / "receipt/status").read_text(), "complete\n")
        self.assertTrue((builds[0] / "receipt/outputs.sha256").read_text())
        source_rows = (builds[0] / "receipt/source-files.sha256").read_text().splitlines()
        source_paths = {row.split("  ", 1)[1] for row in source_rows}
        self.assertEqual(source_paths, {"./Makefile", "./README", "./configure", "./fixture.c"})
        self.assertFalse(any("receipt" in path for path in source_paths))
        for row in source_rows:
            expected, relative = row.split("  ", 1)
            self.assertEqual(builder.digest(builds[0] / "zlib-1.3.2" / relative), expected)
        self.assertIn("OKERNEL SOURCE BUILD zlib PASS", result.stdout)
        self.assertEqual((self.root / "apk.log").read_text().splitlines(), ["add gcc make musl-dev patch", "info -vv"])
        self.assertEqual((self.root / "namespace.log").read_text().splitlines(),
                         ["status", f"publish-source zlib {builds[0] / 'receipt'}"])

    def test_source_failure_is_propagated_without_binary_fallback(self):
        configure = self.tree / "configure"
        configure.write_text("#!/bin/sh\nexit 17\n")
        configure.chmod(0o755)
        result = self.invoke("install", "zlib")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertNotIn("OKERNEL SOURCE BUILD", result.stdout)
        self.assertEqual((self.root / "apk.log").read_text().splitlines(), ["add gcc make musl-dev patch", "info -vv"])

    def test_unregistered_name_uses_original_apk_and_source_only_rejects(self):
        result = self.invoke("install", "jq")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "apk.log").read_text().splitlines(), ["add jq"])
        result = self.invoke("source", "jq")
        self.assertEqual(result.returncode, 2)
        self.assertEqual((self.root / "apk.log").read_text().splitlines(), ["add jq"])

    def test_plan9port_provider_is_source_first_and_failure_has_no_binary_fallback(self):
        helper = self.bin / "pkg-plan9port"
        helper.write_text('#!/bin/sh\nprintf "original-provider-invoked\\n"\nexit 19\n')
        helper.chmod(0o755)
        self.env["OSTADIX_PKG_PLAN9PORT_HELPER"] = str(helper)
        result = self.invoke("install", "plan9port")
        self.assertEqual(result.returncode, 19, result.stdout + result.stderr)
        self.assertIn("original-provider-invoked", result.stdout)
        self.assertFalse((self.root / "apk.log").exists())

    def test_plan9port_rejects_changed_source_before_extract_or_compiler_execution(self):
        archive = self.root / "sources/plan9port" / ("plan9port-" + builder.PLAN9PORT_REVISION + ".tar.gz")
        archive.parent.mkdir()
        archive.write_text("changed untrusted archive\n")
        result = subprocess.run(["sh", str(builder.HERE / "pkg-plan9port")], env=self.env,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED", result.stdout)
        self.assertFalse(list((self.root / "work/sources").glob("plan9port-build.*")))
        self.assertIn(builder.PLAN9PORT_SHA256, (builder.HERE / "pkg-plan9port").read_text())
        self.assertIn(builder.PLAN9PORT_REVISION, (builder.HERE / "pkg-plan9port").read_text())


if __name__ == "__main__":
    unittest.main()
