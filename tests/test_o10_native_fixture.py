"""The actual guest's aux and reply parsers reject malformed trust inputs."""
from __future__ import annotations

import ctypes
import importlib.util
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from o10_native_fixture import CONTRACT, CORPUS, auxiliary_image, decode_heartbeat


class NativeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc")
        if not compiler:
            raise RuntimeError("native fixture parser tests require a C compiler")
        cls.directory = tempfile.TemporaryDirectory(prefix="o10-native-fixture-parser-")
        binary = Path(cls.directory.name) / "parsers.so"
        result = subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
             "-DO10_FIXTURE_TEST", str(ROOT / "ocore/guest/native/o10_m3/fixture.c"),
             "-o", str(binary)], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr)
        cls.library = ctypes.CDLL(str(binary))
        cls.library.o10_fixture_aux_valid.argtypes = [ctypes.c_void_p]
        cls.library.o10_fixture_reply_valid.argtypes = [
            ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint8, ctypes.c_uint16]

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def aux(self, raw):
        return self.library.o10_fixture_aux_valid(ctypes.create_string_buffer(bytes(raw)))

    def reply(self, raw, kind=117, tag=42):
        return self.library.o10_fixture_reply_valid(
            ctypes.create_string_buffer(bytes(raw)), len(raw), kind, tag)

    def test_exact_aux_contract_and_rejected_addresses_names_and_padding(self):
        original = auxiliary_image()
        self.assertEqual(len(original), 128)
        self.assertEqual(self.aux(original), 1)
        for offset in (0, 8, 12, 16, 24, 32, 36, 71, 119, 120, 127):
            with self.subTest(offset=offset):
                raw = bytearray(original)
                raw[offset] ^= 0xff
                self.assertEqual(self.aux(raw), 0)
        for name in (b"..", b"/work/x", b"a/b", b"", b"../w"):
            raw = bytearray(original)
            raw[40:72] = name.ljust(32, b"\0")
            struct.pack_into("<I", raw, 32, len(name))
            self.assertEqual(self.aux(raw), 0)

    def test_actual_reply_parser_binds_size_type_and_tag(self):
        raw = struct.pack("<IBHI", 11 + len(CORPUS), 117, 42, len(CORPUS)) + CORPUS
        self.assertEqual(self.reply(raw), 1)
        for changed in (raw[:-1], raw + b"x", bytes([0]) + raw[1:],
                        raw[:4] + bytes([107]) + raw[5:],
                        raw[:5] + struct.pack("<H", 43) + raw[7:]):
            self.assertEqual(self.reply(changed), 0)
        for size in range(7):
            self.assertEqual(self.reply(bytes(size)), 0)
        oversized = struct.pack("<IBH", 513, 117, 42) + bytes(506)
        self.assertEqual(self.reply(oversized), 0)

    def test_heartbeat_decodes_stability_and_numeric_fail_closed_errors(self):
        raw = struct.pack("<8s7Q", b"O10M3HB1", 4, 2, 0, 117, len(CORPUS), 3, 6)
        value = decode_heartbeat(raw)
        self.assertTrue(value["stable"])
        self.assertEqual(value["reads"], 2)
        failed = struct.pack("<8s7Q", b"O10M3HB1", 5, 2, 6, 117, 2, 4, 6)
        value = decode_heartbeat(failed)
        self.assertFalse(value["stable"])
        self.assertEqual(value["error_name"], "namespace corpus mismatch")
        for invalid in (raw[:-1], bytes(64)):
            with self.assertRaises(ValueError):
                decode_heartbeat(invalid)


if __name__ == "__main__":
    unittest.main()
