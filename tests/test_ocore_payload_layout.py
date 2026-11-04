"""Compact ELF payloads must preserve the complete virtual load image."""

from pathlib import Path
import os
import shutil
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_image(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected little-endian ELF64")
    entry, phoff = struct.unpack_from("<QQ", data, 24)
    phsize, phcount = struct.unpack_from("<HH", data, 54)
    segments = []
    for index in range(phcount):
        kind, flags, offset, address, physical, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phsize
        )
        if kind != 1:
            continue
        if filesz > memsz or offset + filesz > len(data):
            raise ValueError("invalid load extent")
        if align > 1 and (align & (align - 1) or address % align != offset % align):
            raise ValueError("invalid load alignment")
        if flags & 3 == 3:
            raise ValueError("writable executable load segment")
        segments.append((flags, address, physical,
                         data[offset:offset + filesz] + bytes(memsz - filesz)))
    return entry, segments


class PayloadLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clang = shutil.which("clang")
        cls.lld = os.environ.get("OCORE_LLD") or shutil.which("ld.lld")
        if not cls.lld and shutil.which("rustc"):
            sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip()
            version = subprocess.check_output(["rustc", "-vV"], text=True)
            host = next(line.removeprefix("host: ") for line in version.splitlines()
                        if line.startswith("host: "))
            candidate = Path(sysroot) / "lib/rustlib" / host / "bin/rust-lld"
            if candidate.is_file():
                cls.lld = str(candidate)
        if not cls.clang or not cls.lld:
            raise unittest.SkipTest("requires clang and an LLD linker")

    def test_compaction_preserves_entry_loaded_bytes_zero_fill_and_page_permissions(self):
        with tempfile.TemporaryDirectory(prefix="ocore-payload-layout-") as directory:
            root = Path(directory)
            source = root / "payload.S"
            source.write_text(
                '.section .text.entry,"ax",@progbits\n'
                '.globl _start\n_start:\nret\n.fill 6000,1,0x90\n'
                '.section .rodata,"a",@progbits\n.fill 700,1,0x5a\n'
                '.section .data,"aw",@progbits\n.byte 7,8,9\n'
                '.section .bss,"aw",@nobits\n.zero 512\n'
                '.section .note.GNU-stack,"",@progbits\n', encoding="utf-8"
            )
            object_path = root / "payload.o"
            subprocess.run([self.clang, "-target", "x86_64-unknown-none-elf", "-c",
                            str(source), "-o", str(object_path)], check=True, capture_output=True)
            linker = [self.lld]
            if Path(self.lld).name in ("rust-lld", "lld"):
                linker += ["-flavor", "gnu"]
            linker += ["-m", "elf_x86_64", "-nostdlib", "--build-id=none", "--strip-all",
                       "-z", "max-page-size=0x1000", "-T", str(ROOT / "ocore/user/static-user.ld")]
            original, compact = root / "original.elf", root / "compact.elf"
            for output, extra in ((original, []), (compact, ["--nmagic"])):
                subprocess.run([*linker, *extra, "-o", str(output), str(object_path)],
                               check=True, capture_output=True)
            entry, segments = load_image(compact)
            self.assertEqual((entry, segments), load_image(original))
            self.assertEqual(entry, 0x02000000)
            self.assertEqual([segment[0] for segment in segments], [5, 4, 6])
            self.assertEqual(segments[-1][3], b"\x07\x08\x09" + bytes(512))
            for previous, following in zip(segments, segments[1:]):
                prior_page_end = (previous[1] + len(previous[3]) + 4095) // 4096 * 4096
                self.assertLessEqual(prior_page_end, following[1] // 4096 * 4096)
            self.assertLess(compact.stat().st_size, original.stat().st_size)


if __name__ == "__main__":
    unittest.main()
