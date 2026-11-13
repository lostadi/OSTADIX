"""Installer effects in private fixtures; native rename contract separately.

Host fixture publication uses renameat2(NOREPLACE) to model the validated
native Twstat rule. A production O-core wire test below checks that rule;
none of these fixtures claim an installed/running foreign OS qualification.
"""
import ctypes
import contextlib
import errno
import hashlib
import importlib.machinery
import importlib.util
import json
import io
import os
from pathlib import Path
import platform
import shutil
import shlex
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "ocore/guest/linux/package-domain/p9-install"
LOADER = importlib.machinery.SourceFileLoader("p9_installer", str(HELPER))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
INSTALLER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INSTALLER
LOADER.exec_module(INSTALLER)
PRIVATE_RECEIPTS = INSTALLER.private_receipts


def executable():
    text = bytes(range(256)) * 16
    data = b"\0\xff\x11\x13" * 256
    symbols, lines = b"symbols", b"lines"
    entry = 0x10028
    return struct.pack(">8IQ", 0x8C47, len(text), len(data), 1024, len(symbols), entry, 0, len(lines), entry) + text + data + symbols + lines


@unittest.skipUnless(platform.system() == "Linux", "Linux fd-relative fixture required")
class P9InstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p9-install-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.native = self.root / "native"
        self.native.mkdir()
        (self.native / "work").mkdir()
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.source = self.native / "work/source"
        self.data = executable()
        self.source.write_bytes(self.data)
        self.bin = self.native / "packages/plan9/bin"
        self.rename = ctypes.CDLL(None, use_errno=True).renameat2
        self.rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        self.rename.restype = ctypes.c_int

        def publication(source, target, *, src_dir_fd, dst_dir_fd):
            self.assertEqual(os.fstat(src_dir_fd).st_ino, os.fstat(dst_dir_fd).st_ino)
            if self.rename(src_dir_fd, os.fsencode(source), dst_dir_fd, os.fsencode(target), 1):
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))

        self.native_publication = publication

        def mount(fd):
            path = Path(os.readlink("/proc/self/fd/" + str(fd)))
            if path == self.native or self.native in path.parents:
                return {"id": "native", "path": "/n/okernel", "filesystem": "9p", "source": "okernel", "options": {"noextend", "trans=virtio"}}
            return {"id": "private", "path": "/var/lib/okernel/p9-installed", "filesystem": "ext4", "source": "/dev/vda", "options": set()}

        self.open_native = mock.patch.object(INSTALLER, "open_native", side_effect=lambda: (os.open(self.native, os.O_RDONLY | os.O_DIRECTORY), "native"))
        self.private_receipts = mock.patch.object(INSTALLER, "private_receipts", side_effect=lambda: os.open(self.private, os.O_RDONLY | os.O_DIRECTORY))
        self.mount = mock.patch.object(INSTALLER, "mount_identity", side_effect=mount)
        self.publish = mock.patch.object(INSTALLER.os, "rename", side_effect=publication)
        for patch in (self.open_native, self.private_receipts, self.mount, self.publish):
            patch.start()
            self.addCleanup(patch.stop)

    def run_install(self, name="hello"):
        return INSTALLER.install("/n/okernel/work/source", name)

    def assert_no_partial(self):
        if self.bin.exists():
            self.assertFalse(any(p.name.startswith(".p9-install-") for p in self.bin.iterdir()))
        self.assertFalse(any(p.name.startswith(".input-") for p in self.private.iterdir()))
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_exact_binary_mode_and_immutable_input_receipt(self):
        result = self.run_install("user-program")
        self.assertEqual((self.bin / "user-program").read_bytes(), self.data)
        self.assertEqual(stat.S_IMODE((self.bin / "user-program").stat().st_mode), 0o555)
        self.assertEqual(result["path"], "/n/okernel/packages/plan9/bin/user-program")
        self.assertEqual(result["sha256"], hashlib.sha256(self.data).hexdigest())
        self.assertTrue(result["receipt"].startswith("/var/lib/okernel/p9-installed/"))
        receipts = list(self.private.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        record = json.loads(receipts[0].read_text())
        self.assertEqual(record["state"], "verified-install-input")
        self.assertFalse(record["metadata_grants_authority"])
        self.assertEqual(record["input"]["sha256"], result["sha256"])
        self.assertEqual(record["input"]["bytes"], len(self.data))
        self.assertEqual(stat.S_IMODE(receipts[0].stat().st_mode), 0o400)
        self.assert_no_partial()

    def test_partial_write_syscalls_still_copy_every_binary_byte(self):
        original = os.write
        with mock.patch.object(INSTALLER.os, "write", side_effect=lambda fd, data: original(fd, data[:7])):
            self.run_install()
        self.assertEqual((self.bin / "hello").read_bytes(), self.data)
        self.assert_no_partial()

    def test_failed_copy_and_receipt_write_clean_only_owned_partials(self):
        original = INSTALLER.write_all
        for where in ("binary", "receipt"):
            def failing(fd, data):
                receipt = bytes(data).startswith(b"{")
                if receipt == (where == "receipt"):
                    os.write(fd, data[:13])
                    raise OSError(errno.ENOSPC, "fixture full")
                return original(fd, data)
            with self.subTest(where=where), mock.patch.object(INSTALLER, "write_all", side_effect=failing):
                with self.assertRaises(OSError):
                    self.run_install(where)
            self.assertFalse((self.bin / where).exists())
            self.assert_no_partial()

    def test_existing_target_file_directory_or_symlink_never_replaced(self):
        self.bin.mkdir(parents=True)
        (self.bin / "file").write_bytes(b"old")
        (self.bin / "directory").mkdir()
        outside = self.root / "outside"
        outside.write_bytes(b"outside")
        (self.bin / "link").symlink_to(outside)
        for name in ("file", "directory", "link"):
            with self.subTest(name=name), self.assertRaisesRegex(INSTALLER.InstallError, "already exists"):
                self.run_install(name)
        self.assertEqual((self.bin / "file").read_bytes(), b"old")
        self.assertTrue((self.bin / "directory").is_dir())
        self.assertTrue((self.bin / "link").is_symlink())
        self.assertEqual(outside.read_bytes(), b"outside")
        self.assert_no_partial()

    def test_raced_target_uses_atomic_native_no_replace_semantics(self):
        def racing(source, target, **kwargs):
            (self.bin / target).write_bytes(b"raced-existing")
            self.native_publication(source, target, **kwargs)
        with mock.patch.object(INSTALLER.os, "rename", side_effect=racing), self.assertRaises(FileExistsError):
            self.run_install()
        self.assertEqual((self.bin / "hello").read_bytes(), b"raced-existing")
        self.assert_no_partial()

    def test_corrupt_closed_readback_prevents_publication(self):
        original = INSTALLER.snapshot_file
        def changed(fd):
            data, info = original(fd)
            if ".p9-install-" in os.readlink("/proc/self/fd/" + str(fd)):
                return data[:-1] + bytes([data[-1] ^ 1]), info
            return data, info
        with mock.patch.object(INSTALLER, "snapshot_file", side_effect=changed), self.assertRaisesRegex(INSTALLER.InstallError, "verification"):
            self.run_install()
        self.assertFalse((self.bin / "hello").exists())
        self.assert_no_partial()

    def test_failed_publish_receipt_remains_truthful_and_retry_reuses_it(self):
        with mock.patch.object(INSTALLER.os, "rename", side_effect=OSError(errno.EIO, "fixture publication")):
            with self.assertRaises(OSError):
                self.run_install()
        old = {p.name: p.read_bytes() for p in self.private.glob("*.json")}
        self.assertEqual(len(old), 1)
        self.assertEqual(json.loads(next(iter(old.values())))["state"], "verified-install-input")
        self.run_install()
        self.assertEqual(old, {p.name: p.read_bytes() for p in self.private.glob("*.json")})
        self.assert_no_partial()

    def test_cleanup_does_not_delete_a_foreign_replacement(self):
        def replaced(*args):
            pending = next(self.bin.glob(".p9-install-*"))
            # Keep the old inode open so the replacement cannot reuse it.
            held = os.open(pending, os.O_RDONLY)
            self.addCleanup(os.close, held)
            pending.unlink()
            pending.write_bytes(b"foreign replacement")
            raise INSTALLER.InstallError("fixture interruption")
        with mock.patch.object(INSTALLER, "save_receipt", side_effect=replaced), self.assertRaises(INSTALLER.InstallError):
            self.run_install()
        self.assertEqual(next(self.bin.glob(".p9-install-*")).read_bytes(), b"foreign replacement")
        self.assertEqual(self.source.read_bytes(), self.data)
        self.assertFalse((self.bin / "hello").exists())

    def test_source_escape_symlink_and_nested_foreign_mount_rejected(self):
        for source in ("/etc/passwd", "/n/okernel/../outside", "/n/okernel/work/../../work/source"):
            with self.subTest(source=source), self.assertRaises(INSTALLER.InstallError):
                INSTALLER.install(source, "hello")
        self.source.unlink()
        self.source.symlink_to(self.root / "outside")
        (self.root / "outside").write_bytes(self.data)
        with self.assertRaises(OSError):
            self.run_install()
        self.source.unlink()
        self.source.write_bytes(self.data)
        with mock.patch.object(INSTALLER, "mount_identity", return_value={"id": "foreign"}), self.assertRaises(INSTALLER.InstallError):
            self.run_install()
        self.assertFalse(self.bin.exists())

    def test_package_path_symlink_never_writes_its_destination(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.native / "packages").symlink_to(outside)
        with self.assertRaises(OSError):
            self.run_install()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_names_headers_and_help_have_no_install_side_effect(self):
        for name in ("", ".", "..", "../x", "x/y", "a\0b", "x" * 256, "\udcff"):
            with self.subTest(name=name), self.assertRaises(INSTALLER.InstallError):
                self.run_install(name)
        good = self.data
        bad = [b"", b"\x7fELF" + good[4:], good[:39], good[:-1], good + b"x"]
        for offset, value in ((0, 0x80008c47), (0, 0x8a97), (4, 0), (20, 0x1002c)):
            data = bytearray(good)
            struct.pack_into(">I", data, offset, value)
            bad.append(bytes(data))
        data = bytearray(good)
        struct.pack_into(">Q", data, 32, 0xffffffffc0100000)
        bad.append(bytes(data))
        for data in bad:
            self.source.write_bytes(data)
            with self.assertRaises(INSTALLER.InstallError):
                self.run_install()
        result = subprocess.run([sys.executable, str(HELPER), "--help"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SOURCE NAME", result.stdout)
        self.assertFalse(self.bin.exists())
        self.assertEqual(list(self.private.iterdir()), [])

    def test_actual_linux_mount_rendering_accepts_only_admitted_native_dialects(self):
        mount = {"id": "native", "path": "/n/okernel", "filesystem": "9p", "source": "okernel",
                 "options": {"noextend", "trans=virtio"}}
        for options in ({"noextend", "trans=virtio"},
                        {"trans=virtio", "version=9p2000.u"},
                        {"rw", "trans=virtio", "version=9p2000.u", "msize=8192"}):
            with self.subTest(accepted=options):
                self.assertEqual(INSTALLER.require_native_mount({**mount, "options": options}), "native")
        for key, value in (("path", "/tmp/okernel"), ("source", "host"), ("filesystem", "ext4"),
                           ("options", {"trans=virtio"}),
                           ("options", {"trans=virtio", "version=9p2000.L"}),
                           ("options", {"trans=virtio", "version=9p2000"}),
                           ("options", {"trans=tcp", "noextend"}),
                           ("options", {"trans=tcp", "version=9p2000.u"}),
                           ("options", {"trans=virtio", "trans=tcp", "version=9p2000.u"}),
                           ("options", {"trans=virtio", "noextend", "version=9p2000.u"}),
                           ("options", {"trans=virtio", "version=9p2000.u", "version=9p2000.L"})):
            with self.subTest(key=key, value=value), self.assertRaises(INSTALLER.InstallError):
                INSTALLER.require_native_mount({**mount, key: value})

    def test_utf8_name_at_native_byte_limit(self):
        name = "é" * 127 + "x"
        self.run_install(name)
        self.assertEqual((self.bin / name).read_bytes(), self.data)
        with self.assertRaises(INSTALLER.InstallError):
            self.run_install(name + "x")

    def test_printed_command_preserves_name_without_shell_interpretation(self):
        name = "-user'$(not-a-command)"
        output = io.StringIO()
        with mock.patch.object(INSTALLER, "install", return_value={"name": name}), mock.patch.object(sys, "argv", [str(HELPER), "source", "name"]), contextlib.redirect_stdout(output):
            self.assertEqual(INSTALLER.main(), 0)
        command = output.getvalue().splitlines()[1].removeprefix("Run: ")
        self.assertEqual(shlex.split(command), ["p9", "--", name])


class OriginalFormatTests(unittest.TestCase):
    def test_known_original7l_header_and_service_artifact(self):
        service = Path("/home/ustad/.cache/okernel-plan9-userland/build-7/provider/arm64/bin/p9cmdsrv")
        if not service.is_file():
            self.skipTest("original build7 service fixture is unavailable")
        header = INSTALLER.executable_header(service.read_bytes())
        self.assertEqual(header["magic"], 0x8c47)
        self.assertEqual(header["header_bytes"], 40)
        self.assertEqual(header["entry"], 0x1670c)


@unittest.skipUnless(platform.system() == "Linux", "Linux fd-relative fixture required")
class PrivateReceiptPathTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p9-installed-private-path-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "root"
        (self.root / "var/lib").mkdir(parents=True)
        for path in (self.root, self.root / "var", self.root / "var/lib"):
            path.chmod(0o755)
        self.original_open = os.open
        def redirect(path, flags, mode=0o777, *, dir_fd=None):
            if path == "/" and dir_fd is None:
                return self.original_open(self.root, flags, mode)
            return self.original_open(path, flags, mode, dir_fd=dir_fd)
        patch = mock.patch.object(INSTALLER.os, "open", side_effect=redirect)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(INSTALLER, "mount_identity", return_value={"filesystem": "ext4"})
        patch.start()
        self.addCleanup(patch.stop)

    def test_private_var_lib_path_never_changes_world_writable_workspace(self):
        work = self.root / "work"
        work.mkdir()
        work.chmod(0o777)
        (work / "user-file").write_bytes(b"leave workspace alone")
        descriptor = PRIVATE_RECEIPTS()
        try:
            self.assertEqual(os.fstat(descriptor).st_ino, (self.root / "var/lib/okernel/p9-installed").stat().st_ino)
            for path in ("var/lib/okernel", "var/lib/okernel/p9-installed"):
                self.assertEqual(stat.S_IMODE((self.root / path).stat().st_mode), 0o700)
        finally:
            os.close(descriptor)
        self.assertEqual(stat.S_IMODE(work.stat().st_mode), 0o777)
        self.assertEqual((work / "user-file").read_bytes(), b"leave workspace alone")

    def test_writable_root_var_lib_and_nonprivate_internal_directories_fail(self):
        for relative, mode in ((".", 0o777), ("var", 0o775), ("var/lib", 0o777),
                               ("var/lib/okernel", 0o755), ("var/lib/okernel/p9-installed", 0o755)):
            path = self.root / relative
            if not path.exists():
                path.mkdir(parents=True, mode=0o700)
            path.chmod(mode)
            with self.subTest(path=relative), self.assertRaises(INSTALLER.InstallError):
                PRIVATE_RECEIPTS()
            path.chmod(0o755 if relative in (".", "var", "var/lib") else 0o700)

    def test_symlink_ancestry_never_writes_destination(self):
        (self.root / "var/lib").rmdir()
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (self.root / "var/lib").symlink_to(outside)
        with self.assertRaises(OSError):
            PRIVATE_RECEIPTS()
        self.assertEqual(list(outside.iterdir()), [])

    def test_shared_filesystem_cannot_hold_private_receipts(self):
        with mock.patch.object(INSTALLER, "mount_identity", return_value={"filesystem": "9p"}), self.assertRaises(INSTALLER.InstallError):
            PRIVATE_RECEIPTS()
        self.assertFalse((self.root / "var/lib/okernel").exists())


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "production O-core fixture requires Linux x86_64")
class NativePublicationContractTests(unittest.TestCase):
    def test_real_native_twstat_never_replaces_a_sibling(self):
        spec = importlib.util.spec_from_file_location("p9_install_native_wire", ROOT / "tests/test_namespace_store.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        harness = module.HARNESS[:module.HARNESS.rindex("int main(")] + r'''
int main(void){
    initvolume();uint64_t s=session(1);
    assert(walk(s,1,2,"work")==111&&walk(s,2,3,NULL)==111&&create(s,3,"pending",0555,2)==115);
    assert(writefid(s,3,0,"NEW\0\377",5,11)==119);
    assert(walk(s,2,4,NULL)==111&&create(s,4,"existing",0555,2)==115&&writefid(s,4,0,"OLD",3,11)==119);
    assert(wstat(s,3,"existing",UINT64_MAX)==107);
    assert(readfid(s,3,0,8)==117&&rd(response+7,4)==5&&!memcmp(response+11,"NEW\0\377",5));
    assert(readfid(s,4,0,8)==117&&rd(response+7,4)==3&&!memcmp(response+11,"OLD",3));
    assert(wstat(s,3,"fresh",UINT64_MAX)==127&&walk(s,2,5,"pending")==107&&walk(s,2,5,"fresh")==111);
    assert(readfid(s,4,0,8)==117&&rd(response+7,4)==3&&!memcmp(response+11,"OLD",3));
    puts("production native absent-name publication: PASS");return 0;
}
'''
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="p9-native-publish-") as directory:
            out = Path(directory)
            (out / "test.c").write_text(harness)
            for argv in ([str(compiler), str(ROOT / "ocore/runtime/common/namespace_store.oc"), "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(out / "store.o")],
                         [clang, "-O2", "-no-pie", str(out / "test.c"), str(out / "store.o"), "-o", str(out / "test")],
                         [str(out / "test")]):
                result = subprocess.run(argv, text=True, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("production native absent-name publication: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
