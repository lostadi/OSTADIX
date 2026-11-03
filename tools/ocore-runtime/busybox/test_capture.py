"""Exercise archive fidelity and original producer-plan parsing, without VMs."""
import importlib.util
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("original_cat_capture_test", Path(__file__).with_name("capture.py"))
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


class OriginalArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def archive(self, entries):
        path = self.root / "source.tar.bz2"
        with tarfile.open(path, "w:bz2") as stream:
            base = tarfile.TarInfo("busybox-1.36.1")
            base.type, base.mode = tarfile.DIRTYPE, 0o755
            stream.addfile(base)
            for name, kind, value in entries:
                item = tarfile.TarInfo(name)
                item.mode = 0o755 if kind == "executable" else 0o644
                if kind == "symlink":
                    item.type, item.linkname = tarfile.SYMTYPE, value
                    stream.addfile(item)
                else:
                    data = value.encode()
                    item.size = len(data)
                    stream.addfile(item, io.BytesIO(data))
        return path

    def test_archive_import_retains_ignored_files_modes_and_symlinks(self):
        archive = self.archive([
            ("busybox-1.36.1/.gitignore", "file", "*.generated\n"),
            ("busybox-1.36.1/retained.generated", "file", "original ignored release input\n"),
            ("busybox-1.36.1/tool", "executable", "#!/bin/sh\nexit 0\n"),
            ("busybox-1.36.1/tool-link", "symlink", "tool"),
        ])
        source = capture.extract_source(archive, self.root)
        first = capture.git_import(source, self.root / "logs")
        record = capture.verify_archive_import(archive, source, self.root / "equivalence.json")
        self.assertTrue(record["sha256"])
        self.assertEqual((source / "retained.generated").read_text(), "original ignored release input\n")
        self.assertTrue((source / "tool").stat().st_mode & 0o111)
        self.assertEqual((source / "tool-link").readlink(), Path("tool"))
        # A second archive import has the same declared private commit, despite
        # living at a different absolute location.
        second_root = self.root / "second"
        second_root.mkdir()
        second = capture.extract_source(archive, second_root)
        imported = capture.git_import(second, second_root / "logs")
        self.assertEqual(first["revision"], imported["revision"])
        self.assertEqual(first["tree"], imported["tree"])

    def test_changed_release_bytes_cannot_pass_import_equivalence(self):
        archive = self.archive([("busybox-1.36.1/source.c", "file", "int original;\n")])
        source = capture.extract_source(archive, self.root)
        capture.git_import(source, self.root / "logs")
        (source / "source.c").write_text("int replacement;\n")
        with self.assertRaisesRegex(capture.CaptureError, "file bytes changed"):
            capture.verify_archive_import(archive, source, self.root / "bad.json")

    def test_unsafe_archive_names_are_rejected_before_any_extraction(self):
        for name in ["../outside", "/absolute", "busybox-1.36.1/../outside", "busybox-1.36.1/.git/config"]:
            with self.subTest(name=name):
                archive = self.archive([(name, "file", "unsafe")])
                with self.assertRaises(capture.CaptureError):
                    capture.extract_source(archive, self.root)
                self.assertFalse((self.root / "busybox-1.36.1").exists())

    def test_escaping_symlink_and_children_below_symlinks_are_rejected(self):
        for entries in [
            [("busybox-1.36.1/link", "symlink", "../../outside")],
            [("busybox-1.36.1/link", "symlink", "inside"), ("busybox-1.36.1/link/child", "file", "unsafe")],
        ]:
            with self.subTest(entries=entries):
                archive = self.archive(entries)
                with self.assertRaises(capture.CaptureError):
                    capture.extract_source(archive, self.root)
                self.assertFalse((self.root / "busybox-1.36.1").exists())


class OriginalProducerPlanTests(unittest.TestCase):
    def test_real_command_is_not_confused_with_echo_or_fixdep_text(self):
        build = Path("/private/build")
        compiler = str(build / "driver/musl-clang")
        command = compiler + ' -include include/config.h -DNAME="input.c" -c -o libbb/cold.o /original/libbb/cold.c'
        text = "set -e; echo '" + command + "'; " + command + "; fixdep deps libbb/cold.o '" + command + "'\n"
        entries = capture.planned_compiles(text, build, compiler)
        self.assertEqual(set(entries), {"/private/build/libbb/cold.o"})
        self.assertEqual(len(entries["/private/build/libbb/cold.o"]), 1)
        self.assertEqual(entries["/private/build/libbb/cold.o"][0]["source"], "/original/libbb/cold.c")

    def test_ambiguous_and_escaping_producers_fail(self):
        build = Path("/private/build")
        cc = str(build / "driver/musl-clang")
        for args in ["-c a.c -o x.o -o y.o", "-c a.c b.c -o x.o", "-c a.c -o ../outside.o", "-c a.c"]:
            with self.subTest(args=args), self.assertRaises(capture.CaptureError):
                capture.compile_command(cc + " " + args, build, cc)

    def test_target_arguments_must_match_full_native_occurrence(self):
        self.assertTrue(capture.subsequence(["--target=x86_64-unknown-linux-musl", "-c", "cold.c", "-o", "cold.o", "-Lruntime"],
                                            ["-c", "cold.c", "-o", "cold.o"]))
        self.assertFalse(capture.subsequence(["-c", "replacement.c", "-o", "cold.o"], ["-c", "cold.c", "-o", "cold.o"]))


class OriginalElfEvidenceTests(unittest.TestCase):
    def test_static_layout_is_read_from_original_bytes_and_invalid_entry_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reference"
            identity = b"\x7fELF\x02\x01\x01" + b"\0" * 9
            header = struct.pack("<16sHHIQQQIHHHHHH", identity, 2, 62, 1, 0x02000080, 64, 0, 0, 64, 56, 1, 0, 0, 0)
            segment = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x02000000, 0x02000000, 128, 4096, 4096)
            path.write_bytes(header + segment + b"\0" * 8)
            value = capture.elf_profile(path)
            self.assertEqual(value["entry"], 0x02000080)
            self.assertEqual(value["minimum_load_address"], 0x02000000)
            bad = bytearray(path.read_bytes())
            struct.pack_into("<Q", bad, 24, 0x04000000)
            path.write_bytes(bad)
            with self.assertRaisesRegex(capture.CaptureError, "entry is outside"):
                capture.elf_profile(path)


if __name__ == "__main__":
    unittest.main()
