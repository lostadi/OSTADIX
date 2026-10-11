"""Bounds tests and real, freshly serialized Rust LLVM 22 audit fixtures."""

import ctypes as C
import hashlib
import os
from pathlib import Path
import unittest

from scripts.ocore_llvm_bitcode import BitcodeFailure, audit_bitcode


class _Stream:
    """Small fixture writer; native LLVM supplies the integration fixtures."""

    def __init__(self):
        self.bits = []
        self.widths = [2]
        for byte in b"BC\xc0\xde":
            self.fixed(byte, 8)

    def fixed(self, value, width):
        self.bits.extend((value >> index) & 1 for index in range(width))

    def vbr(self, value, width):
        mask = (1 << (width - 1)) - 1
        while value > mask:
            self.fixed((value & mask) | (1 << (width - 1)), width)
            value >>= width - 1
        self.fixed(value, width)

    def align(self):
        self.bits.extend([0] * (-len(self.bits) % 32))

    def begin(self, block_id, width=3):
        self.fixed(1, self.widths[-1])
        self.vbr(block_id, 8)
        self.vbr(width, 4)
        self.align()
        patch = len(self.bits)
        self.fixed(0, 32)
        self.widths.append(width)
        return patch

    def end(self, patch):
        self.fixed(0, self.widths.pop())
        self.align()
        words = (len(self.bits) - patch - 32) // 32
        self.bits[patch:patch + 32] = [(words >> index) & 1 for index in range(32)]

    def record(self, code, values):
        self.fixed(3, self.widths[-1])
        self.vbr(code, 6)
        self.vbr(len(values), 6)
        for value in values:
            self.vbr(value, 6)

    def abbrev(self, operands):
        self.fixed(2, self.widths[-1])
        self.vbr(len(operands), 5)
        for encoding, value in operands:
            self.fixed(encoding == 0, 1)
            if encoding == 0:
                self.vbr(value, 8)
            else:
                self.fixed(encoding, 3)
                if encoding in (1, 2):
                    self.vbr(value, 5)

    def data(self):
        self.align()
        return bytes(sum(bit << offset for offset, bit in enumerate(self.bits[index:index + 8]))
                     for index in range(0, len(self.bits), 8))


def _strtab(stream, data):
    patch = stream.begin(23)
    stream.abbrev([(0, 1), (5, 0)])
    stream.fixed(4, 3)
    stream.vbr(len(data), 6)
    stream.align()
    for byte in data:
        stream.fixed(byte, 8)
    stream.align()
    stream.end(patch)


def _module(globals=(), functions=(), version=2, before=None, aliases=(),
            comdats=(), strtab=None):
    stream = _Stream()
    if before:
        before(stream)
    patch = stream.begin(8)
    stream.record(1, [version])
    for record in comdats:
        stream.record(12, record)
    for record in globals:
        stream.record(7, record)
    for record in functions:
        stream.record(8, record)
    for record in aliases:
        stream.record(14, record)
    stream.end(patch)
    if strtab is not None:
        _strtab(stream, strtab)
    return stream.data()


def _global(extended=False):
    return [0, 1, 0, 2, 0, 0, 0, 0] + ([0] * 12 if extended else [])


def _function():
    return [0] * 21


def _alias():
    return [0, 1] + [0] * 11


class BitstreamAuditTests(unittest.TestCase):
    def reject(self, data, message):
        with self.assertRaisesRegex(BitcodeFailure, message):
            audit_bitcode(data)

    def test_empty_module_and_complete_inventory(self):
        self.assertEqual(audit_bitcode(_module()),
                         {"version": 2, "module_count": 1, "global_count": 0,
                          "function_count": 0, "dso_local_count": 0,
                          "triple": None, "data_layout": None,
                          "global_alignments": [], "function_alignments": [],
                          "alias_count": 0, "alias_contracts": [],
                          "comdat_count": 0, "comdat_contracts": [],
                          "global_comdat_ids": [], "function_comdat_ids": []})
        glob, function = _global(True), _function()
        glob[15], function[17] = 1, 1
        result = audit_bitcode(_module([_global(), glob], [function, _function()]))
        self.assertEqual((result["global_count"], result["function_count"], result["dso_local_count"]),
                         (2, 2, 2))
        self.assertEqual(result["global_alignments"], [0, 0])
        self.assertEqual(result["function_alignments"], [0, 0])

    def test_alias_contracts_keep_all_fields_order_and_raw_enum_encodings(self):
        records = []
        for index, linkage in enumerate((0, 3, 9, 12, 16, 17, 18, 19)):
            record = _alias()
            record[0:3] = [100 + index, 1 + index, 20 + index]
            record[4:7] = [30 + index, linkage, index % 3]
            record[9:12] = [index % 3, index % 2, 200 + index]
            records.append(record)
        result = audit_bitcode(_module(aliases=records))
        self.assertEqual(result["alias_count"], len(records))
        self.assertEqual(result["dso_local_count"], 4)
        keys = ("name_offset", "name_length", "value_type", "address_space",
                "aliasee", "linkage_encoding", "visibility", "dll_storage_class",
                "thread_local_mode", "unnamed_address", "dso_local",
                "partition_offset", "partition_length")
        self.assertEqual(result["alias_contracts"], [dict(zip(keys, record)) for record in records])
        self.assertEqual((result["global_count"], result["function_count"]), (0, 0))

    def test_alias_unknown_layout_and_deprecated_code_reject(self):
        for count in (0, 4, 10, 12, 14):
            with self.subTest(fields=count):
                self.reject(_module(aliases=[[0] * count]), "ALIAS record layout")
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(1, [2])
        stream.record(9, [0] * 4)
        stream.end(patch)
        self.reject(stream.data(), "deprecated ALIAS_OLD")

    def test_alias_blind_fields_are_explicitly_unsupported(self):
        for field, values, label in ((3, (1, 7), "address space"),
                                     (7, (1, 2), "dll_storage_class"),
                                     (8, (1, 2, 3, 4), "thread_local_mode"),
                                     (12, (1, (1 << 64) - 1), "partition_length")):
            for value in values:
                with self.subTest(field=field, value=value):
                    record = _alias()
                    record[field] = value
                    self.reject(_module(aliases=[record]), f"unsupported alias #1 {label}")

    def test_alias_enums_never_truncate_high_bits(self):
        for field, low_values, label in ((3, (0,), "address space"),
                                         (5, (0, 3, 9, 12, 16, 17, 18, 19), "linkage encoding"),
                                         (6, (0, 1, 2), "visibility"),
                                         (7, (0, 1, 2), "dll_storage_class"),
                                         (8, (0, 1, 2, 3, 4), "thread_local_mode"),
                                         (9, (0, 1, 2), "unnamed_address"),
                                         (10, (0, 1), "dso_local")):
            for low in low_values:
                with self.subTest(field=field, low=low):
                    record = _alias()
                    record[field] = (1 << 32) + low
                    self.reject(_module(aliases=[record]), f"invalid alias #1 {label}")
        for linkage in (1, 2, 4, 7, 8, 10, 11, 13, 15, 20):
            record = _alias()
            record[5] = linkage
            self.reject(_module(aliases=[record]), "invalid alias #1 linkage encoding")

    def test_alias_identity_width_and_empty_partition_offset(self):
        record = _alias()
        record[0], record[1], record[11] = (1 << 64) - 1, (1 << 64) - 1, 77
        result = audit_bitcode(_module(aliases=[record]))
        self.assertEqual(result["alias_contracts"][0]["partition_offset"], 77)
        self.assertEqual(result["alias_contracts"][0]["name_offset"], (1 << 64) - 1)
        for field, label in ((2, "value_type"), (4, "aliasee")):
            invalid = _alias()
            invalid[field] = 1 << 32
            self.reject(_module(aliases=[invalid]), f"{label} ID")
        for field in (0, 1, 2, 4, 11):
            invalid = _alias()
            invalid[field] = 1 << 64
            self.reject(_module(aliases=[invalid]), "overflow")

    def test_alias_requires_version_and_no_blob(self):
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(14, _alias())
        stream.end(patch)
        self.reject(stream.data(), "precedes module version")
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(1, [2])
        stream.abbrev([(0, 14), (5, 0)])
        stream.fixed(4, 3)
        stream.vbr(0, 6)
        stream.align()
        stream.end(patch)
        self.reject(stream.data(), "unexpected blob")

    def test_all_alignment_encodings_preserve_full_bytes_and_module_order(self):
        globals, functions = [], []
        for encoded in range(34):
            glob = _global(extended=bool(encoded % 2))
            glob[6] = encoded
            globals.append(glob)
            function = _function()
            function[7] = 33 - encoded
            functions.append(function)
        result = audit_bitcode(_module(globals, functions))
        expected = [0] + [1 << shift for shift in range(33)]
        self.assertEqual(result["global_alignments"], expected)
        self.assertEqual(result["function_alignments"], expected[::-1])
        self.assertEqual((result["global_count"], result["function_count"]), (34, 34))

    def test_alignment_encoding_beyond_llvm_maximum_fails_closed(self):
        for encoded in (34, 64, (1 << 64) - 1):
            for extended in (False, True):
                with self.subTest(encoded=encoded, extended_global=extended):
                    glob = _global(extended)
                    glob[6] = encoded
                    self.reject(_module([glob]), "invalid global #1 alignment encoding")
            with self.subTest(encoded=encoded, function=True):
                function = _function()
                function[7] = encoded
                self.reject(_module(functions=[function]), "invalid function #1 alignment encoding")

    def test_nonzero_blindspot_fields_fail_closed(self):
        for field, label in ((14, "global attributes"), (17, "global partition"),
                             (18, "global sanitizer"), (19, "global code model")):
            with self.subTest(field=field):
                glob = _global(True)
                glob[field] = 1
                self.reject(_module([glob]), label)
        function = _function()
        function[20] = 1
        self.reject(_module(functions=[function]), "function partition")

    def test_empty_partition_offset_is_not_a_partition(self):
        glob, function = _global(True), _function()
        glob[16], function[19] = 17, 31
        audit_bitcode(_module([glob], [function]))

    def test_unknown_record_lengths_are_structured_failures(self):
        for count in (0, 7, 9, 19, 21):
            with self.subTest(global_fields=count):
                self.reject(_module([[0] * count]), "GLOBALVAR record layout")
        for count in (0, 18, 20, 22):
            with self.subTest(function_fields=count):
                self.reject(_module(functions=[[0] * count]), "FUNCTION record layout")

    def test_invalid_dso_local_flag(self):
        glob, function = _global(True), _function()
        glob[15], function[17] = 2, 2
        self.reject(_module([glob]), "dso_local")
        self.reject(_module(functions=[function]), "dso_local")

    def test_version_and_module_presence(self):
        self.reject(_module(version=1), "version 2")
        self.reject(b"BC\xc0\xde", "complete LLVM module")
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(7, _global())
        stream.end(patch)
        self.reject(stream.data(), "precedes module version")
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(1, [2])
        stream.record(1, [2])
        stream.end(patch)
        self.reject(stream.data(), "one LLVM module version")

    def test_repeated_or_nested_module_rejected(self):
        stream = _Stream()
        for _ in range(2):
            patch = stream.begin(8)
            stream.record(1, [2])
            stream.end(patch)
        self.reject(stream.data(), "one top-level MODULE")
        stream = _Stream()
        outer = stream.begin(9)
        inner = stream.begin(8)
        stream.record(1, [2])
        stream.end(inner)
        stream.end(outer)
        self.reject(stream.data(), "one top-level MODULE")

    def test_magic_alignment_and_every_truncated_prefix(self):
        self.reject(b"\x00" * 16, "magic")
        self.reject(bytearray(_module()), "owned bytes")
        data = _module([_global()], [_function()])
        for end in range(len(data)):
            with self.subTest(end=end):
                with self.assertRaises(BitcodeFailure):
                    audit_bitcode(data[:end])

    def test_declared_block_length_and_end_marker(self):
        data = bytearray(_module())
        data[8:12] = (0xffffffff).to_bytes(4, "little")
        self.reject(bytes(data), "exceeds enclosing block")
        data = bytearray(_module())
        data[8:12] = (0).to_bytes(4, "little")
        self.reject(bytes(data), "exceeds enclosing block")
        data = bytearray(_module())
        data[8:12] = (1).to_bytes(4, "little")
        data.extend(b"\x00" * 4)
        self.reject(bytes(data), "top-level END_BLOCK")

    def test_undefined_abbreviation_and_missing_blockinfo_setbid(self):
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(1, [2])
        stream.fixed(4, 3)
        stream.end(patch)
        self.reject(stream.data(), "undefined abbreviation")
        stream = _Stream()
        patch = stream.begin(0)
        stream.abbrev([(0, 7)])
        stream.end(patch)
        self.reject(stream.data(), "precedes SETBID")

    def test_blockinfo_inherited_fixed_and_vbr_global_abbreviation(self):
        def before(stream):
            patch = stream.begin(0)
            stream.record(1, [8])
            stream.abbrev([(0, 7), (1, 4), (2, 6)] + [(0, 0)] * 6)
            stream.end(patch)
        stream = _Stream()
        before(stream)
        patch = stream.begin(8)
        stream.record(1, [2])
        stream.fixed(4, 3)
        stream.fixed(7, 4)
        stream.vbr(127, 6)
        stream.end(patch)
        self.assertEqual(audit_bitcode(stream.data())["global_count"], 1)

    def test_all_array_encodings_and_blob_in_ignored_blocks(self):
        def before(stream):
            patch = stream.begin(99, 4)
            for encoding, width in ((1, 8), (2, 6), (4, 0)):
                stream.abbrev([(0, 42), (3, 0), (encoding, width)])
            stream.abbrev([(0, 43), (5, 0)])
            for abbrev_id, encoding, width in ((4, 1, 8), (5, 2, 6), (6, 4, 6)):
                stream.fixed(abbrev_id, 4)
                stream.vbr(3, 6)
                for value in (1, 7, 31):
                    if encoding == 2:
                        stream.vbr(value, width)
                    else:
                        stream.fixed(value, width)
            stream.fixed(7, 4)
            stream.vbr(5, 6)
            stream.align()
            for value in b"hello":
                stream.fixed(value, 8)
            stream.align()
            stream.end(patch)
        audit_bitcode(_module(before=before))

    def test_invalid_abbreviation_layouts(self):
        for operands in ([], [(3, 0), (1, 8)], [(0, 42), (3, 0)],
                         [(0, 42), (3, 0), (0, 0)], [(0, 42), (5, 0), (0, 1)],
                         [(0, 42), (2, 1)], [(0, 42), (1, 65)], [(0, 42), (6, 0)]):
            with self.subTest(operands=operands):
                stream = _Stream()
                patch = stream.begin(99)
                stream.abbrev(operands)
                stream.end(patch)
                with self.assertRaises(BitcodeFailure):
                    audit_bitcode(stream.data())

    def test_target_strings_are_exact_ascii_without_nul_or_duplicates(self):
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(1, [2])
        stream.record(2, list(b"x86_64-unknown-linux-gnu"))
        stream.record(3, list(b"e-p:64:64"))
        stream.end(patch)
        result = audit_bitcode(stream.data())
        self.assertEqual(result["triple"], "x86_64-unknown-linux-gnu")
        self.assertEqual(result["data_layout"], "e-p:64:64")
        for code in (2, 3):
            for values in ([65, 0, 66], [128], [256]):
                with self.subTest(code=code, values=values):
                    stream = _Stream()
                    patch = stream.begin(8)
                    stream.record(1, [2])
                    stream.record(code, values)
                    stream.end(patch)
                    self.reject(stream.data(), "non-ASCII or embedded NUL")
            stream = _Stream()
            patch = stream.begin(8)
            stream.record(1, [2])
            stream.record(code, [65])
            stream.record(code, [66])
            stream.end(patch)
            self.reject(stream.data(), "duplicate module")

    def test_vbr_overflow_and_impossible_element_count(self):
        for value in (1 << 64, 1 << 100):
            stream = _Stream()
            patch = stream.begin(8)
            stream.record(1, [value])
            stream.end(patch)
            self.reject(stream.data(), "overflow")
        stream = _Stream()
        patch = stream.begin(99)
        stream.fixed(3, 3)
        stream.vbr(42, 6)
        stream.vbr(1 << 30, 6)
        stream.end(patch)
        self.reject(stream.data(), "element count")

    def test_blob_and_fixed_array_bounds_are_checked(self):
        for encoding in (1, 2, 4, 5):
            stream = _Stream()
            patch = stream.begin(99)
            operands = [(0, 42), (5, 0)] if encoding == 5 else [(0, 42), (3, 0), (encoding, 8 if encoding == 1 else 6)]
            stream.abbrev(operands)
            stream.fixed(4, 3)
            stream.vbr(1 << 20, 6)
            stream.end(patch)
            self.reject(stream.data(), "element count")

    def test_deep_nesting_does_not_use_python_recursion(self):
        stream = _Stream()
        patches = [stream.begin(99) for _ in range(1100)]
        for patch in reversed(patches):
            stream.end(patch)
        stream_module = _module()
        self.assertEqual(audit_bitcode(stream.data() + stream_module[4:])["module_count"], 1)


class ComdatBitstreamAuditTests(unittest.TestCase):
    reject = BitstreamAuditTests.reject

    def test_exact_names_selections_and_ordered_memberships(self):
        globals_ = [_global(), _global(True), _global(True)]
        globals_[1][13], globals_[2][13] = 2, 1
        functions = [_function(), _function(), _function()]
        functions[1][14], functions[2][14] = 1, 2
        result = audit_bitcode(_module(
            globals_, functions, comdats=[[0, 5, 1], [5, 6, 4]],
            strtab=b"firstsecond"))
        self.assertEqual(result["comdat_count"], 2)
        self.assertEqual(result["comdat_contracts"], [
            {"name_offset": 0, "name_length": 5, "selection_encoding": 1, "name": "first"},
            {"name_offset": 5, "name_length": 6, "selection_encoding": 4, "name": "second"}])
        self.assertEqual(result["global_comdat_ids"], [0, 2, 1])
        self.assertEqual(result["function_comdat_ids"], [0, 1, 2])

    def test_comdat_record_layout_and_full_unsigned_fields(self):
        for length in (0, 1, 2, 4, 5):
            with self.subTest(length=length):
                self.reject(_module(comdats=[[0] * length], strtab=b"group"),
                            "COMDAT record layout")
        for field in range(3):
            for value in (1 << 32, (1 << 64) - 1):
                record = [0, 5, 1]
                record[field] = value
                with self.subTest(field=field, value=value):
                    self.reject(_module(comdats=[record], strtab=b"group"),
                                "COMDAT record unsigned field")

    def test_other_elf_selection_kinds_and_invalid_encodings_reject(self):
        for selection in (2, 3, 5):
            self.reject(_module(comdats=[[0, 5, selection]], strtab=b"group"),
                        "unsupported ELF COMDAT selection")
        for selection in (0, 6, (1 << 32) - 1):
            self.reject(_module(comdats=[[0, 5, selection]], strtab=b"group"),
                        "invalid COMDAT selection")

    def test_membership_ids_reject_missing_forward_and_truncated_inventory(self):
        for value in (1, 2, 1 << 32, (1 << 64) - 1):
            glob, function = _global(True), _function()
            glob[13], function[14] = value, value
            for groups, strings in (([], None), ([[0, 5, 1]], b"group")):
                if groups and value == 1:
                    continue
                with self.subTest(value=value, groups=groups):
                    self.reject(_module([glob], comdats=groups, strtab=strings),
                                "global #1 COMDAT ID")
                    self.reject(_module(functions=[function], comdats=groups, strtab=strings),
                                "function #1 COMDAT ID")
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(1, [2])
        glob = _global(True)
        glob[13] = 1
        stream.record(7, glob)
        stream.record(12, [0, 5, 1])
        stream.end(patch)
        _strtab(stream, b"group")
        self.reject(stream.data(), "global #1 COMDAT ID")

    def test_name_string_table_bounds_and_absence_fail_closed(self):
        self.reject(_module(comdats=[[0, 5, 1]]), "require the pinned writer string table")
        for offset, length in ((0, 0), (6, 1), (5, 1), (1, 5), ((1 << 32) - 1, 1)):
            with self.subTest(offset=offset, length=length):
                self.reject(_module(comdats=[[offset, length, 1]], strtab=b"group"),
                            "name string-table bounds")

    def test_name_bytes_preserve_unicode_and_reject_nul_invalid_utf8_duplicates(self):
        raw = "membre_é".encode()
        result = audit_bitcode(_module(comdats=[[0, len(raw), 1]], strtab=raw))
        self.assertEqual(result["comdat_contracts"][0]["name"], "membre_é")
        for raw, message in ((b"bad\0group", "embedded NUL"), (b"bad\xffgroup", "invalid UTF-8")):
            self.reject(_module(comdats=[[0, len(raw), 1]], strtab=raw), message)
        self.reject(_module(comdats=[[0, 5, 1], [5, 5, 4]], strtab=b"groupgroup"),
                    "duplicate COMDAT name")

    def test_string_table_must_be_single_top_level_blob(self):
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(1, [2])
        stream.end(patch)
        _strtab(stream, b"group")
        _strtab(stream, b"other")
        self.reject(stream.data(), "one top-level writer string table")
        for code in (1, 2):
            stream = _Stream()
            patch = stream.begin(8)
            stream.record(1, [2])
            stream.end(patch)
            patch = stream.begin(23)
            stream.record(code, [1, 2, 3])
            stream.end(patch)
            self.reject(stream.data(), "writer string-table blob record")
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(1, [2])
        _strtab(stream, b"group")
        stream.end(patch)
        self.reject(stream.data(), "one top-level writer string table")
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(1, [2])
        stream.end(patch)
        patch = stream.begin(23)
        stream.end(patch)
        self.reject(stream.data(), "missing writer string-table blob record")

    def test_comdat_requires_version_and_rejects_blob_instead_of_fields(self):
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(12, [0, 5, 1])
        stream.record(1, [2])
        stream.end(patch)
        self.reject(stream.data(), "record precedes module version")
        stream = _Stream()
        patch = stream.begin(8)
        stream.record(1, [2])
        stream.abbrev([(0, 12), (5, 0)])
        stream.fixed(4, 3)
        stream.vbr(0, 6)
        stream.align()
        stream.end(patch)
        self.reject(stream.data(), "unexpected blob")


class RealLlvmBitcodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rustup = Path(os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")))
        candidates = list((rustup / "toolchains").glob(
            "1.97.1-*/lib/libLLVM.so.22.1-rust-1.97.1-stable"))
        if len(candidates) != 1:
            raise unittest.SkipTest("pinned Rust LLVM 22.1.6 ELF unavailable")
        path = candidates[0]
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != "ed4f320c4e1ed6de7d2db6fd89faccf764d63186c2f877057ddf31065b1fac09":
            raise AssertionError("pinned LLVM fixture library hash mismatch")
        cls.lib = C.CDLL(str(path.resolve()))
        pointer = C.c_void_p
        bindings = {
            "LLVMGetVersion": (None, [C.POINTER(C.c_uint)] * 3),
            "LLVMContextCreate": (pointer, []), "LLVMContextDispose": (None, [pointer]),
            "LLVMCreateMemoryBufferWithMemoryRangeCopy": (pointer, [C.c_char_p, C.c_size_t, C.c_char_p]),
            "LLVMParseIRInContext2": (C.c_int, [pointer, pointer, C.POINTER(pointer), C.POINTER(pointer)]),
            "LLVMVerifyModule": (C.c_int, [pointer, C.c_int, C.POINTER(pointer)]),
            "LLVMWriteBitcodeToMemoryBuffer": (pointer, [pointer]),
            "LLVMGetBufferStart": (pointer, [pointer]), "LLVMGetBufferSize": (C.c_size_t, [pointer]),
            "LLVMDisposeMessage": (None, [pointer]), "LLVMDisposeModule": (None, [pointer]),
            "LLVMDisposeMemoryBuffer": (None, [pointer]),
            "LLVMGetFirstGlobalAlias": (pointer, [pointer]),
            "LLVMGetNextGlobalAlias": (pointer, [pointer]),
            "LLVMGetValueName2": (pointer, [pointer, C.POINTER(C.c_size_t)]),
            "LLVMGetLinkage": (C.c_int, [pointer]),
            "LLVMGetVisibility": (C.c_int, [pointer]),
            "LLVMGetDLLStorageClass": (C.c_int, [pointer]),
            "LLVMGetUnnamedAddress": (C.c_int, [pointer]),
            "LLVMTypeOf": (pointer, [pointer]),
            "LLVMGetPointerAddressSpace": (C.c_uint, [pointer]),
            "LLVMGetFirstGlobal": (pointer, [pointer]),
            "LLVMGetNextGlobal": (pointer, [pointer]),
            "LLVMGetFirstFunction": (pointer, [pointer]),
            "LLVMGetNextFunction": (pointer, [pointer]),
            "LLVMGetComdat": (pointer, [pointer]),
            "LLVMGetComdatSelectionKind": (C.c_int, [pointer]),
            "LLVMGetOrInsertComdat": (pointer, [pointer, C.c_char_p]),
        }
        for name, (result, args) in bindings.items():
            function = getattr(cls.lib, name)
            function.restype, function.argtypes = result, args
        version = [C.c_uint() for _ in range(3)]
        cls.lib.LLVMGetVersion(*(C.byref(value) for value in version))
        if tuple(value.value for value in version) != (22, 1, 6):
            raise AssertionError("fixture library LLVM version mismatch")

    def serialize(self, body, triple="x86_64-unknown-linux-gnu", observe=None):
        lib = self.lib
        source = (f'target triple = "{triple}"\n'
                  'target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"\n' + body).encode()
        context = lib.LLVMContextCreate()
        buffer = lib.LLVMCreateMemoryBufferWithMemoryRangeCopy(source, len(source), b"audit-fixture")
        module, message = C.c_void_p(), C.c_void_p()
        serialized = None
        try:
            if lib.LLVMParseIRInContext2(context, buffer, C.byref(module), C.byref(message)):
                self.fail(C.string_at(message).decode() if message else "LLVM parse failed")
            if message:
                lib.LLVMDisposeMessage(message)
                message = C.c_void_p()
            if lib.LLVMVerifyModule(module, 2, C.byref(message)):
                self.fail(C.string_at(message).decode() if message else "LLVM verification failed")
            if observe is not None:
                observe(module)
            serialized = lib.LLVMWriteBitcodeToMemoryBuffer(module)
            self.assertTrue(serialized)
            return C.string_at(lib.LLVMGetBufferStart(serialized), lib.LLVMGetBufferSize(serialized))
        finally:
            if serialized:
                lib.LLVMDisposeMemoryBuffer(serialized)
            if message:
                lib.LLVMDisposeMessage(message)
            if module:
                lib.LLVMDisposeModule(module)
            lib.LLVMDisposeMemoryBuffer(buffer)
            lib.LLVMContextDispose(context)

    def test_real_comdat_names_membership_ids_and_c_api_selection_agree(self):
        expected_groups = {"shared": 0, "retained": 3}
        observed = {"globals": [], "functions": []}

        def observe(module):
            groups = {name: self.lib.LLVMGetOrInsertComdat(module, name.encode())
                      for name in expected_groups}
            for name, group in groups.items():
                self.assertEqual(self.lib.LLVMGetComdatSelectionKind(group), expected_groups[name])
            for kind, first, next_value in (
                    ("globals", self.lib.LLVMGetFirstGlobal, self.lib.LLVMGetNextGlobal),
                    ("functions", self.lib.LLVMGetFirstFunction, self.lib.LLVMGetNextFunction)):
                value = first(module)
                while value:
                    group = self.lib.LLVMGetComdat(value)
                    name = next((name for name, handle in groups.items() if handle == group), None)
                    self.assertEqual(bool(group), name is not None)
                    observed[kind].append(name)
                    value = next_value(value)

        data = self.serialize('''
$shared = comdat any
$retained = comdat nodeduplicate
@ordinary = global i64 1
@a = linkonce_odr global i64 2, comdat($shared)
@b = internal global i64 3, comdat($shared)
@c = weak_odr global i64 4, comdat($retained)
declare i64 @external(i64)
define linkonce i64 @f(i64 %x) comdat($shared) { ret i64 %x }
define weak_odr i64 @g(i64 %x) comdat($retained) { ret i64 %x }
define i64 @ordinary_function(i64 %x) { ret i64 %x }
''', observe=observe)
        result = audit_bitcode(data)
        self.assertEqual(result["comdat_count"], 2)
        groups = result["comdat_contracts"]
        self.assertEqual({group["name"]: group["selection_encoding"] for group in groups},
                         {"shared": 1, "retained": 4})
        for kind, ids in (("globals", result["global_comdat_ids"]),
                          ("functions", result["function_comdat_ids"])):
            self.assertEqual([groups[value - 1]["name"] if value else None for value in ids],
                             observed[kind])

    def test_real_writer_omits_unused_named_groups_including_unsupported_selection(self):
        def observe(module):
            unused = self.lib.LLVMGetOrInsertComdat(module, b"unused")
            self.assertEqual(self.lib.LLVMGetComdatSelectionKind(unused), 2)

        result = audit_bitcode(self.serialize('''
$used = comdat any
$unused = comdat largest
@a = linkonce_odr global i64 2, comdat($used)
''', observe=observe))
        self.assertEqual(result["comdat_count"], 1)
        self.assertEqual([group["name"] for group in result["comdat_contracts"]], ["used"])
        self.assertEqual(result["global_comdat_ids"], [1])
        result = audit_bitcode(self.serialize('$unused = comdat largest\n', observe=observe))
        self.assertEqual(result["comdat_count"], 0)
        self.assertEqual(result["comdat_contracts"], [])

    def test_real_writer_referenced_non_elf_selections_reject(self):
        for selection, encoded in (("exactmatch", 2), ("largest", 3), ("samesize", 5)):
            with self.subTest(selection=selection):
                data = self.serialize(f'$group = comdat {selection}\n'
                                      '@a = linkonce_odr global i64 1, comdat($group)\n')
                with self.assertRaisesRegex(BitcodeFailure, f"selection encoding {encoded}"):
                    audit_bitcode(data)

    def test_real_writer_preserves_unicode_names_and_rejects_invalid_utf8(self):
        result = audit_bitcode(self.serialize(
            '$"membre_\\C3\\A9" = comdat any\n'
            '@a = linkonce_odr global i64 1, comdat($"membre_\\C3\\A9")\n'))
        self.assertEqual(result["comdat_contracts"][0]["name"], "membre_é")
        data = self.serialize('$"bad\\FFgroup" = comdat any\n'
                              '@a = linkonce_odr global i64 1, comdat($"bad\\FFgroup")\n')
        with self.assertRaisesRegex(BitcodeFailure, "invalid UTF-8"):
            audit_bitcode(data)

    def test_complete_real_module_inventory_and_dso_local(self):
        data = self.serialize('''
@ordinary = global i64 1
@local = dso_local global i32 0
declare i64 @external(i64)
define dso_local i64 @entry(i64 %x) {
  %value = call i64 @external(i64 %x)
  ret i64 %value
}
''')
        result = audit_bitcode(data)
        self.assertEqual((result["global_count"], result["function_count"], result["dso_local_count"]), (2, 2, 2))
        self.assertEqual(result["triple"], "x86_64-unknown-linux-gnu")
        self.assertEqual(result["data_layout"], "e-p:64:64-i64:64-n8:16:32:64-S128")
        self.assertEqual((result["alias_count"], result["alias_contracts"]), (0, []))

    def test_real_alias_writer_encodings_agree_with_ordered_safe_c_getters(self):
        observed = []

        def observe(module):
            lib = self.lib
            alias = lib.LLVMGetFirstGlobalAlias(module)
            # Fresh encodings differ from LLVM-C enums for linkage and unnamed
            # address. No GlobalVariable/GlobalObject getter is used on aliases.
            linkage_encoding = {0: 0, 1: 12, 2: 18, 3: 19, 5: 16, 6: 17, 8: 3, 9: 9}
            unnamed_encoding = {0: 0, 1: 2, 2: 1}
            while alias:
                length = C.c_size_t()
                name = lib.LLVMGetValueName2(alias, C.byref(length))
                observed.append({"name_length": length.value,
                                 "name": C.string_at(name, length.value).decode(),
                                 "address_space": lib.LLVMGetPointerAddressSpace(lib.LLVMTypeOf(alias)),
                                 "linkage_encoding": linkage_encoding[lib.LLVMGetLinkage(alias)],
                                 "visibility": lib.LLVMGetVisibility(alias),
                                 "dll_storage_class": lib.LLVMGetDLLStorageClass(alias),
                                 "unnamed_address": unnamed_encoding[lib.LLVMGetUnnamedAddress(alias)]})
                alias = lib.LLVMGetNextGlobalAlias(alias)

        data = self.serialize('''
@strong = global i32 7
@available = available_externally global i32 9
@external_alias = alias i32, ptr @strong
@internal_alias = internal alias i32, ptr @strong
@private_alias = private alias i32, ptr @strong
@available_alias = available_externally alias i32, ptr @available
@weak_alias = weak dso_local hidden unnamed_addr alias i32, ptr @strong
@weak_odr_alias = weak_odr protected local_unnamed_addr alias i32, ptr @strong
@linkonce_alias = linkonce alias i32, ptr @strong
@linkonce_odr_alias = linkonce_odr alias i32, ptr @strong
define signext i8 @function(i8 signext %value) { ret i8 %value }
@function_alias = alias i8 (i8), ptr @function
''', observe=observe)
        result = audit_bitcode(data)
        self.assertEqual(result["alias_count"], 9)
        self.assertEqual([record["linkage_encoding"] for record in result["alias_contracts"]],
                         [0, 3, 9, 12, 16, 17, 18, 19, 0])
        self.assertEqual([item["name"] for item in observed],
                         ["external_alias", "internal_alias", "private_alias", "available_alias",
                          "weak_alias", "weak_odr_alias", "linkonce_alias", "linkonce_odr_alias",
                          "function_alias"])
        for actual, expected in zip(result["alias_contracts"], observed):
            for key, value in expected.items():
                if key != "name":
                    self.assertEqual(actual[key], value, key)
            self.assertEqual((actual["thread_local_mode"], actual["partition_length"]), (0, 0))
        self.assertEqual(result["dso_local_count"],
                         sum(record["dso_local"] for record in result["alias_contracts"]))

    def test_real_alias_partition_tls_dll_and_address_space_reject(self):
        bodies = [
            ('@g = global i32 7\n@a = alias i32, ptr @g, partition "part"\n', "partition_length"),
            ('@g = global i32 7\n@a = dllexport alias i32, ptr @g\n', "dll_storage_class"),
            ('@g = addrspace(1) global i32 7\n@a = alias i32, ptr addrspace(1) @g\n', "address space"),
        ]
        for tls in ("", "(localdynamic)", "(initialexec)", "(localexec)"):
            bodies.append((f"@g = thread_local{tls} global i32 7\n"
                           f"@a = thread_local{tls} alias i32, ptr @g\n", "thread_local_mode"))
        for body, label in bodies:
            with self.subTest(body=body):
                with self.assertRaisesRegex(BitcodeFailure, label):
                    audit_bitcode(self.serialize(body))

    def test_real_alias_empty_partition_and_address_promises_do_not_add_storage(self):
        data = self.serialize('''
@target = global i64 7
@a = unnamed_addr alias i64, ptr @target, partition ""
@b = local_unnamed_addr alias i64, ptr @target
''')
        result = audit_bitcode(data)
        self.assertEqual((result["global_count"], result["function_count"], result["alias_count"]), (1, 0, 2))
        self.assertEqual([a["unnamed_address"] for a in result["alias_contracts"]], [1, 2])
        self.assertTrue(all(a["partition_length"] == 0 for a in result["alias_contracts"]))

    def test_real_optional_alignments_preserve_maximum_and_inventory_order(self):
        data = self.serialize('''
@unspecified = global i8 0
@one = global i8 0, align 1
@maximum = dso_local global i8 0, align 4294967296
@external = external global i8, align 2147483648
declare void @unspecified_function()
define void @one_function() align 1 { ret void }
declare void @maximum_function() align 4294967296
define dso_local void @high_function() align 2147483648 { ret void }
''')
        result = audit_bitcode(data)
        expected = [0, 1, 1 << 32, 1 << 31]
        self.assertEqual(result["global_alignments"], expected)
        self.assertEqual(result["function_alignments"], expected)
        self.assertEqual((result["global_count"], result["function_count"]), (4, 4))

    def test_real_global_and_function_partitions(self):
        for body in ('@g = global i32 0, partition "other"\n',
                     'define void @f() partition "other" { ret void }\n'):
            with self.subTest(body=body):
                with self.assertRaisesRegex(BitcodeFailure, "partition"):
                    audit_bitcode(self.serialize(body))

    def test_real_global_sanitizer_flags(self):
        for flag in ("no_sanitize_address", "no_sanitize_hwaddress", "sanitize_memtag", "sanitize_address_dyninit"):
            with self.subTest(flag=flag):
                with self.assertRaisesRegex(BitcodeFailure, "sanitizer metadata"):
                    audit_bitcode(self.serialize(f"@g = global i32 0, {flag}\n"))

    def test_real_global_code_model_and_global_attributes(self):
        with self.assertRaisesRegex(BitcodeFailure, "code model"):
            audit_bitcode(self.serialize('@g = global i32 0, code_model "large"\n'))
        with self.assertRaisesRegex(BitcodeFailure, "global attributes"):
            audit_bitcode(self.serialize('@g = global i32 0 #0\nattributes #0 = { "bss-section"=".custom" }\n'))

    def test_real_embedded_nul_in_target_cannot_hide_behind_c_string(self):
        data = self.serialize("define void @f() { ret void }\n",
                              triple=r"x86_64-unknown-linux-gnu\00hidden")
        with self.assertRaisesRegex(BitcodeFailure, "embedded NUL in module triple"):
            audit_bitcode(data)

    def test_function_attributes_and_ir_flags_do_not_confuse_inventory(self):
        data = self.serialize('''
@g = unnamed_addr constant [3 x i8] c"abc"
define noundef i64 @f(i64 noundef %x) nounwind {
  %result = add nuw nsw i64 %x, 1
  ret i64 %result
}
''')
        result = audit_bitcode(data)
        self.assertEqual((result["global_count"], result["function_count"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
