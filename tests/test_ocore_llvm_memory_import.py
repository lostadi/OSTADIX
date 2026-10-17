"""Import real LLVM memory/lifetime units; native execution has separate gates."""

import ctypes as C
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline


ROOT = baseline.ROOT
TRIPLES = baseline.TRIPLES
LAYOUT = "e-p:64:64-i64:64-i128:128-n8:16:32:64-S128"
MEMORY_NAMES = {f"llvm.memset.p0.i{width}" for width in (32, 64)} | {
    f"llvm.{operation}.p0.p0.i{width}" for operation in ("memcpy", "memmove") for width in (32, 64)}
LIFETIME_NAMES = {"llvm.lifetime.start.p0", "llvm.lifetime.end.p0"}


class LlvmMemoryImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-memory-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    def write(self, body, triple=TRIPLES[0]):
        # The pinned bitcode reader supplies AArch64's Fn32 layout component.
        # Include it explicitly so text/binary comparison also checks layout.
        layout = LAYOUT + ("-Fn32" if triple.startswith("aarch64-") else "")
        self.source.write_text(f'target triple = "{triple}"\ntarget datalayout = "{layout}"\n' + body)
        return self.source

    def import_ir(self, body, triple=TRIPLES[0]):
        return importer.import_module(self.write(body, triple), library_path=self.library)

    def reject(self, body, stage="import"):
        with self.assertRaises(importer.ImportFailure) as raised:
            self.import_ir(body)
        self.assertTrue(str(raised.exception).strip())
        self.assertEqual(raised.exception.stage, stage,
                         "a toolchain failure must not masquerade as an input rejection")

    @staticmethod
    def function(module, name):
        return next(function for function in module["functions"] if function["name"] == name)

    @staticmethod
    def instructions(function):
        return [instruction for block in function["blocks"] for instruction in block["instructions"]]

    @classmethod
    def operations(cls, function):
        return [instruction["operation"] for instruction in cls.instructions(function)]

    @staticmethod
    def declaration(operation, width, destination="ptr", source="ptr", extra=""):
        name = (f"llvm.memset.p0.i{width}" if operation == "memset"
                else f"llvm.{operation}.p0.p0.i{width}")
        second = "i8" if operation == "memset" else source
        return name, f"declare void @{name}({destination}, {second}, i{width}, i1 immarg){extra}\n"

    def bitcode(self, source):
        api = importer.LLVM(self.library, getattr(self, "library_sha256", importer.PINNED_SHA256))
        data = source.read_bytes()
        context, module, message = api.ContextCreate(), importer.P(), importer.P()
        buffer = api.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"memory-fixture")
        serialized = None
        try:
            status = api.ParseIRInContext2(context, buffer, C.byref(module), C.byref(message))
            self.assertEqual(status, 0, C.string_at(message).decode() if message else "LLVM parse failed")
            if message:
                api.DisposeMessage(message)
                message = importer.P()
            status = api.VerifyModule(module, 2, C.byref(message))
            self.assertEqual(status, 0, C.string_at(message).decode() if message else "LLVM verify failed")
            serialized = api.WriteBitcodeToMemoryBuffer(module)
            self.assertTrue(serialized)
            binary_data = C.string_at(api.GetBufferStart(serialized), api.GetBufferSize(serialized))
        finally:
            if serialized:
                api.DisposeMemoryBuffer(serialized)
            if message:
                api.DisposeMessage(message)
            if module:
                api.DisposeModule(module)
            api.DisposeMemoryBuffer(buffer)
            api.ContextDispose(context)
        binary = source.with_suffix(".bc")
        binary.write_bytes(binary_data)
        self.assertTrue(binary_data.startswith(b"BC\xc0\xde"))
        return binary

    def assert_roundtrip(self, source):
        text_module = importer.import_module(source, library_path=self.library)
        binary = self.bitcode(source)
        binary_module = importer.import_module(binary, library_path=self.library)
        self.assertEqual({key: value for key, value in binary_module.items()
                          if key not in {"name", "provenance"}},
                         {key: value for key, value in text_module.items()
                          if key not in {"name", "provenance"}})
        for path, module in ((source, text_module), (binary, binary_module)):
            self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        return text_module

    def test_all_memory_names_keep_dynamic_unsigned_lengths_alignment_volatility_and_declarations_all_three_isas(self):
        declarations, definitions = [], []
        for operation in ("memset", "memcpy", "memmove"):
            for width in (32, 64):
                name, declaration = self.declaration(operation, width)
                declarations.append(declaration)
                second = "i8 %value" if operation == "memset" else "ptr %source"
                second_argument = ("i8 %value" if operation == "memset"
                                   else "ptr align 16 dereferenceable_or_null(64) %source")
                volatile = "true" if width == 32 else "false"
                definitions.append(f"define void @{operation}{width}(ptr %destination, {second}, i{width} %length) {{\n"
                                   + f"call void @{name}(ptr align 8 dereferenceable(32) %destination, {second_argument}, i{width} %length, i1 {volatile})\nret void\n}}\n")
        body = "".join(declarations + definitions)
        expected_definitions = {f"{operation}{width}" for operation in ("memset", "memcpy", "memmove")
                                for width in (32, 64)}
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.assert_roundtrip(self.write(body, triple))
                self.assertEqual(module["provenance"]["source_function_count"], 12)
                self.assertEqual(module["provenance"]["source_global_count"], 0)
                self.assertEqual({fn["name"] for fn in module["functions"]}, MEMORY_NAMES | expected_definitions)
                refinements = "\n".join(module["provenance"]["refinements"])
                self.assertIn("dereferenceable=32 validated", refinements)
                self.assertIn("dereferenceable_or_null=64 validated", refinements)
                for name in MEMORY_NAMES:
                    declaration = self.function(module, name)
                    self.assertEqual(declaration["intrinsic"], name)
                    self.assertEqual(declaration["visibility"], "default")
                    self.assertIsNone(declaration["entry"])
                    self.assertEqual(declaration["blocks"], [])
                    self.assertEqual(module["types"][declaration["signature"]["result"]], {"kind": "void"})
                for operation in ("memset", "memcpy", "memmove"):
                    for width in (32, 64):
                        function = self.function(module, f"{operation}{width}")
                        instructions = self.instructions(function)
                        self.assertEqual(len(instructions), 1)
                        self.assertIsNone(instructions[0]["result"])
                        lowered = instructions[0]["operation"]
                        params = [{"kind": "value", "id": param["id"]} for param in function["params"]]
                        self.assertEqual(lowered["destination"], params[0])
                        self.assertEqual(lowered["length"], params[2])
                        self.assertEqual(module["types"][function["params"][2]["ty"]], {"kind": "int", "bits": width})
                        self.assertEqual(lowered["volatile"], width == 32)
                        if operation == "memset":
                            self.assertEqual(lowered["op"], "memory_set")
                            self.assertEqual(lowered["value"], params[1])
                            self.assertEqual(lowered["alignment"], 8)
                        else:
                            self.assertEqual(lowered["op"], "memory_copy")
                            self.assertEqual(lowered["source"], params[1])
                            self.assertEqual(lowered["destination_alignment"], 8)
                            self.assertEqual(lowered["source_alignment"], 16)
                            self.assertEqual(lowered["allow_overlap"], operation == "memmove")

    def test_lifetime_alloca_identity_and_poison_markers_survive_text_and_bitcode_all_three_isas(self):
        body = """
declare void @llvm.lifetime.start.p0(ptr)
declare void @llvm.lifetime.end.p0(ptr)
define void @entry() {
  %first = alloca i8, align 1
  %second = alloca i8, align 1
  call void @llvm.lifetime.start.p0(ptr %first)
  call void @llvm.lifetime.start.p0(ptr %second)
  call void @llvm.lifetime.start.p0(ptr poison)
  store i8 -1, ptr %first, align 1
  call void @llvm.lifetime.end.p0(ptr %first)
  call void @llvm.lifetime.end.p0(ptr poison)
  call void @llvm.lifetime.end.p0(ptr %second)
  ret void
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.assert_roundtrip(self.write(body, triple))
                self.assertEqual(module["provenance"]["source_function_count"], 3)
                function = self.function(module, "entry")
                allocas = [instruction for instruction in self.instructions(function)
                           if instruction["operation"]["op"] == "alloca"]
                self.assertEqual(len(allocas), 2)
                first, second = (instruction["result"]["id"] for instruction in allocas)
                self.assertNotEqual(first, second)
                markers = [operation for operation in self.operations(function) if operation["op"] == "lifetime"]
                self.assertEqual([marker["end"] for marker in markers], [False, False, False, True, True, True])
                self.assertEqual([marker["pointer"] for marker in (markers[0], markers[1], markers[3], markers[5])],
                                 [{"kind": "value", "id": first}, {"kind": "value", "id": second},
                                  {"kind": "value", "id": first}, {"kind": "value", "id": second}])
                for marker in (markers[2], markers[4]):
                    self.assertEqual(marker["pointer"]["kind"], "poison")
                for name in LIFETIME_NAMES:
                    declaration = self.function(module, name)
                    self.assertEqual(declaration["intrinsic"], name)
                    self.assertEqual(declaration["visibility"], "default")
                    self.assertIsNone(declaration["entry"])
                refinements = "\n".join(module["provenance"]["refinements"])
                self.assertIn("alloca storage and address identity", refinements)
                self.assertIn("poison markers have no effect", refinements)

    def test_callsite_alignment_has_no_declaration_fallback_and_keeps_full_64_bit_payload(self):
        body = """
declare void @llvm.memset.p0.i64(ptr align 32, i8, i64, i1 immarg)
declare void @llvm.memcpy.p0.p0.i64(ptr align 32, ptr align 64, i64, i1 immarg)
define void @entry(ptr %destination, ptr %source) {
  call void @llvm.memset.p0.i64(ptr %destination, i8 0, i64 0, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr %destination, ptr %source, i64 0, i1 false)
  call void @llvm.memset.p0.i64(ptr align 4294967296 null, i8 0, i64 0, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %destination, ptr %source, i64 0, i1 false)
  ret void
}
"""
        module = self.import_ir(body)
        operations = self.operations(self.function(module, "entry"))
        self.assertEqual(operations[0]["alignment"], 1)
        self.assertEqual((operations[1]["destination_alignment"], operations[1]["source_alignment"]), (1, 1))
        self.assertEqual(operations[2]["alignment"], 1 << 32)
        self.assertEqual((operations[3]["destination_alignment"], operations[3]["source_alignment"]), (8, 1))

    def test_zero_poison_undef_and_unsigned_maximum_operands_remain_explicit(self):
        body = """
declare void @llvm.memset.p0.i32(ptr, i8, i32, i1 immarg)
declare void @llvm.memmove.p0.p0.i64(ptr, ptr, i64, i1 immarg)
define void @entry(ptr %destination) {
  call void @llvm.memset.p0.i32(ptr null, i8 poison, i32 0, i1 true)
  call void @llvm.memmove.p0.p0.i64(ptr poison, ptr null, i64 0, i1 true)
  call void @llvm.memset.p0.i32(ptr poison, i8 undef, i32 poison, i1 false)
  call void @llvm.memset.p0.i32(ptr %destination, i8 -1, i32 -1, i1 false)
  ret void
}
"""
        module = self.assert_roundtrip(self.write(body))
        operations = self.operations(self.function(module, "entry"))
        self.assertEqual(len(operations), 4)
        self.assertEqual(operations[0]["destination"]["kind"], "null")
        self.assertEqual(operations[0]["value"]["kind"], "poison")
        self.assertEqual(operations[0]["length"]["bits"], "0")
        self.assertTrue(operations[0]["volatile"])
        self.assertEqual(operations[1]["destination"]["kind"], "poison")
        self.assertEqual(operations[1]["length"]["bits"], "0")
        self.assertTrue(operations[1]["allow_overlap"])
        self.assertEqual(operations[2]["value"]["kind"], "undef")
        self.assertEqual(operations[2]["length"]["kind"], "poison")
        self.assertEqual(operations[3]["value"]["bits"], "255")
        self.assertEqual(operations[3]["length"]["bits"], str((1 << 32) - 1))
        self.assertEqual(module["types"][operations[3]["length"]["ty"]], {"kind": "int", "bits": 32})
        refinements = "\n".join(module["provenance"]["refinements"])
        self.assertIn("zero length accesses no memory", refinements)
        self.assertIn("LLVM poison/undef may be refined deterministically", refinements)

    def test_volatile_self_copy_and_bidirectional_memmove_keep_overlap_policy(self):
        module = self.import_ir("""
declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1 immarg)
declare void @llvm.memmove.p0.p0.i64(ptr, ptr, i64, i1 immarg)
define void @entry(ptr %base) {
  %next = getelementptr i8, ptr %base, i64 1
  call void @llvm.memcpy.p0.p0.i64(ptr %base, ptr %base, i64 4, i1 true)
  call void @llvm.memmove.p0.p0.i64(ptr %next, ptr %base, i64 4, i1 false)
  call void @llvm.memmove.p0.p0.i64(ptr %base, ptr %next, i64 4, i1 false)
  ret void
}
""")
        copies = [operation for operation in self.operations(self.function(module, "entry"))
                  if operation["op"] == "memory_copy"]
        self.assertEqual(len(copies), 3)
        self.assertEqual(copies[0]["destination"], copies[0]["source"])
        self.assertTrue(copies[0]["volatile"])
        self.assertEqual([copy["allow_overlap"] for copy in copies], [False, True, True])
        self.assertEqual(copies[1]["destination"], copies[2]["source"])
        self.assertEqual(copies[1]["source"], copies[2]["destination"])

    def test_unused_malformed_owned_declarations_reject_without_waiting_for_calls(self):
        cases = (
            "declare i32 @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)",
            "declare void @llvm.memset.p0.i64(ptr, i32, i64, i1 immarg)",
            "declare void @llvm.memcpy.p0.p0.i64(ptr, i64, i64, i1 immarg)",
            "declare i32 @llvm.lifetime.start.p0(ptr)",
            "declare void @llvm.lifetime.end.p0(i64)",
        )
        for declaration in cases:
            with self.subTest(declaration=declaration):
                self.reject(declaration + "\n")

    def test_bad_used_signature_and_nonconstant_volatile_reject_during_llvm_verification(self):
        self.reject("""
declare i32 @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)
define void @entry(ptr %destination) {
  %unused = call i32 @llvm.memset.p0.i64(ptr %destination, i8 0, i64 0, i1 false)
  ret void
}
""", stage="llvm-verify")
        for volatile in ("%volatile", "undef", "poison"):
            with self.subTest(volatile=volatile):
                self.reject("declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)\n"
                            + "define void @entry(ptr %destination, i1 %volatile) {\n"
                            + f"call void @llvm.memset.p0.i64(ptr %destination, i8 0, i64 0, i1 {volatile})\n"
                            + "ret void\n}\n", stage="llvm-verify")

    def test_lifetime_requires_literal_alloca_or_poison_in_the_verified_module(self):
        for name in LIFETIME_NAMES:
            cases = {
                "argument": f"define void @entry(ptr %pointer) {{ call void @{name}(ptr %pointer)\nret void }}",
                "undef": f"define void @entry() {{ call void @{name}(ptr undef)\nret void }}",
                "null": f"define void @entry() {{ call void @{name}(ptr null)\nret void }}",
                "GEP even with zero offset": f"define void @entry() {{ %local = alloca i8\n%pointer = getelementptr i8, ptr %local, i64 0\ncall void @{name}(ptr %pointer)\nret void }}",
            }
            for label, body in cases.items():
                with self.subTest(intrinsic=name, pointer=label):
                    self.reject(f"declare void @{name}(ptr)\n" + body, stage="llvm-verify")

    def test_unowned_memory_variants_widths_address_spaces_and_names_reject_even_when_unused(self):
        cases = (
            "declare void @llvm.memset.p0.i16(ptr, i8, i16, i1 immarg)",
            "declare void @llvm.memset.p0.i128(ptr, i8, i128, i1 immarg)",
            "declare void @llvm.memcpy.p0.p0.i16(ptr, ptr, i16, i1 immarg)",
            "declare void @llvm.memmove.p0.p0.i128(ptr, ptr, i128, i1 immarg)",
            "declare void @llvm.memset.p1.i64(ptr addrspace(1), i8, i64, i1 immarg)",
            "declare void @llvm.memcpy.p0.p1.i64(ptr, ptr addrspace(1), i64, i1 immarg)",
            "declare void @llvm.lifetime.start.p1(ptr addrspace(1))",
            "declare void @llvm.memset.inline.p0.i64(ptr, i8, i64, i1 immarg)",
            "declare void @llvm.memcpy.inline.p0.p0.i64(ptr, ptr, i64, i1 immarg)",
            "declare void @llvm.memset.element.unordered.atomic.p0.i64(ptr, i8, i64, i32 immarg)",
            "declare void @llvm.memcpy.element.unordered.atomic.p0.p0.i64(ptr, ptr, i64, i32 immarg)",
            "declare void @llvm.memmove.element.unordered.atomic.p0.p0.i64(ptr, ptr, i64, i32 immarg)",
            "declare void @llvm.experimental.memset.pattern.p0.i16.i64(ptr, i16, i64, i1 immarg)",
            "declare void @llvm.memset_unknown.p0.i64(ptr, i8, i64, i1)",
            "declare void @llvm.lifetime.start_unknown.p0(ptr)",
        )
        for declaration in cases:
            with self.subTest(declaration=declaration):
                self.reject(declaration + "\ndefine void @entry() { ret void }\n")

    def test_owned_memory_addresses_cannot_escape_through_globals_or_indirect_calls(self):
        declaration = "declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)\n"
        self.reject(declaration + "@escape = global ptr @llvm.memset.p0.i64\n", stage="llvm-verify")
        self.reject(declaration + """
declare void @ordinary(ptr, i8, i64, i1)
define void @entry(ptr %destination, i1 %condition) {
  %callee = select i1 %condition, ptr @llvm.memset.p0.i64, ptr @ordinary
  call void %callee(ptr %destination, i8 0, i64 0, i1 false)
  ret void
}
""", stage="llvm-verify")

    def test_ordinary_indirect_function_with_memory_signature_remains_a_native_call(self):
        module = self.import_ir("""
define void @entry(ptr %callee, ptr %destination, i8 %value, i64 %length, i1 %volatile) {
  call void %callee(ptr %destination, i8 %value, i64 %length, i1 %volatile)
  ret void
}
""")
        function = self.function(module, "entry")
        operation = self.operations(function)[0]
        self.assertEqual(operation["op"], "call")
        self.assertEqual(operation["callee"], {"kind": "value", "id": function["params"][0]["id"]})
        self.assertEqual(operation["args"], [{"kind": "value", "id": param["id"]} for param in function["params"][1:]])
        self.assertIsNone(function["intrinsic"])

    def test_operand_bundles_abi_extensions_and_nondefault_owned_visibility_reject(self):
        name, declaration = self.declaration("memset", 64)
        self.reject(declaration + f"define void @entry(ptr %destination) {{\n"
                    + f'call void @{name}(ptr %destination, i8 0, i64 0, i1 false) [ "deopt"(i32 0) ]\n'
                    + "ret void\n}\n")
        # Unlike immediate-argument attributes, zeroext is an ABI extension and
        # cannot become part of an owned intrinsic's scalar signature.
        self.reject(declaration + f"define void @entry() {{\n"
                    + f"call void @{name}(ptr null, i8 zeroext 0, i64 0, i1 false)\nret void\n}}\n")
        for visibility in ("hidden", "protected"):
            for declaration in (f"declare {visibility} void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)\n",
                                f"declare {visibility} void @llvm.lifetime.start.p0(ptr)\n"):
                with self.subTest(visibility=visibility, declaration=declaration):
                    self.reject(declaration)

    def test_ordinary_pointer_promises_preserve_scoped_intrinsic_alignment_and_immarg_guards(self):
        for attribute, name in (("align 8", "align"), ("dereferenceable(8)", "dereferenceable")):
            with self.subTest(ordinary_pointer_promise=attribute):
                module = self.import_ir(f"declare void @ordinary(ptr {attribute})\n")
                self.assertEqual(self.function(module, "ordinary")["signature"]["param_attributes"], [[]])
                self.assertIn(f"ordinary: function attribute index 1: erased pointer promise {name}=8;",
                              "\n".join(module["provenance"]["refinements"]))
        self.reject("""
declare void @llvm.lifetime.start.p0(ptr)
define void @entry() {
  %local = alloca i8, align 16
  call void @llvm.lifetime.start.p0(ptr align 16 %local)
  ret void
}
""")
        self.reject("""
declare void @llvm.memset.p0.i64(ptr, i8 immarg, i64, i1 immarg)
define void @entry() {
  call void @llvm.memset.p0.i64(ptr null, i8 immarg 0, i64 0, i1 false)
  ret void
}
""", stage="llvm-verify")
        self.reject("""
declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64 immarg, i1 immarg)
define void @entry() {
  call void @llvm.memcpy.p0.p0.i64(ptr null, ptr null, i64 immarg 0, i1 false)
  ret void
}
""", stage="llvm-verify")
        # LLVM accepts matching callsite immarg attributes. This narrower import
        # profile owns the declaration's fourth parameter contract only.
        self.reject("""
declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)
define void @entry() {
  call void @llvm.memset.p0.i64(ptr null, i8 0, i64 0, i1 immarg false)
  ret void
}
""")
        self.reject("declare void @ordinary(i1 immarg)\n", stage="llvm-verify")

    def test_pinned_reader_canonicalizes_intrinsic_declarations_and_overload_names_with_original_input_sha(self):
        # LLVM rebuilds intrinsic declaration attributes and overloaded names
        # before import. Assertions concern the resulting verified module.
        cases = (
            ("declare void @llvm.memset.p0.i64(ptr, i8 immarg, i64, i1 immarg)", "llvm.memset.p0.i64"),
            ("declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64 immarg, i1 immarg)", "llvm.memcpy.p0.p0.i64"),
            ("declare void @llvm.memset.p0.i64(ptr, i8 zeroext, i64, i1 immarg)", "llvm.memset.p0.i64"),
            ("declare void @llvm.memset.p0.i64(ptr, i8, i32, i1 immarg)", "llvm.memset.p0.i32"),
            ("declare void @llvm.memmove.p0.p0.i32(ptr, ptr, i64, i1 immarg)", "llvm.memmove.p0.p0.i64"),
            ("declare void @llvm.memset.p0.i64.extra(ptr, i8, i64, i1 immarg)", "llvm.memset.p0.i64"),
            ("declare void @llvm.lifetime.start.p0.extra(ptr)", "llvm.lifetime.start.p0"),
        )
        for declaration, normalized_name in cases:
            with self.subTest(declaration=declaration):
                module = self.assert_roundtrip(self.write(declaration + "\n"))
                self.assertEqual(module["provenance"]["source_function_count"], 1)
                self.assertEqual([function["name"] for function in module["functions"]], [normalized_name])
                function = self.function(module, normalized_name)
                self.assertEqual(function["intrinsic"], normalized_name)
                self.assertFalse(any(function["signature"]["param_attributes"]))
                self.assertIsNone(function["entry"])

        module = self.assert_roundtrip(self.write("""
declare void @llvm.memset.p0.i64(ptr, i8, i32, i1 immarg)
define void @entry(ptr %destination, i32 %length) {
  call void @llvm.memset.p0.i64(ptr %destination, i8 7, i32 %length, i1 false)
  ret void
}
"""))
        self.assertEqual({function["name"] for function in module["functions"]}, {"entry", "llvm.memset.p0.i32"})
        entry = self.function(module, "entry")
        operation = self.operations(entry)[0]
        self.assertEqual(operation["op"], "memory_set")
        self.assertEqual(operation["length"], {"kind": "value", "id": entry["params"][1]["id"]})
        self.assertEqual(module["types"][entry["params"][1]["ty"]], {"kind": "int", "bits": 32})

    def test_malformed_memory_alignment_rejects_during_parse(self):
        for alignment in (0, 3, 1 << 33):
            with self.subTest(alignment=alignment):
                self.reject("declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)\n"
                            + "define void @entry() {\n"
                            + f"call void @llvm.memset.p0.i64(ptr align {alignment} null, i8 0, i64 0, i1 false)\n"
                            + "ret void\n}\n", stage="parse")

    def test_rejected_whole_memory_module_preserves_existing_cli_output(self):
        source = self.write("""
declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)
define void @entry(ptr %destination) {
  call void @llvm.memset.p0.i64(ptr %destination, i8 1, i64 4, i1 false)
  ret void
}
""")
        output = self.directory / "existing-good.json"
        command = [sys.executable, str(ROOT / "scripts/ocore_llvm_import.py"), str(source),
                   "--llvm-library", str(self.library), "--output", str(output)]
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        previous = output.read_bytes()
        source.write_text(source.read_text() + "declare void @llvm.memset.inline.p0.i64(ptr, i8, i64, i1 immarg)\n")
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(json.loads(completed.stderr)["error"]["stage"], "import")
        self.assertEqual(output.read_bytes(), previous)

    @staticmethod
    def clang_source():
        return """
typedef unsigned long usize;
unsigned long memory_counter = 7;
extern void observe(unsigned char *, usize);
void imported_set(unsigned char *destination, unsigned char value, usize length) {
  __builtin_memset(destination, value, length);
}
void imported_copy(unsigned char *destination, const unsigned char *source, usize length) {
  __builtin_memcpy(destination, source, length);
}
void imported_move(unsigned char *destination, const unsigned char *source, usize length) {
  __builtin_memmove(destination, source, length);
}
void imported_lifetime(usize value) {
  unsigned char local[32];
  __builtin_memset(local, (unsigned char)value, sizeof(local));
  observe(local, sizeof(local));
  memory_counter += value;
}
"""

    @staticmethod
    def clang_flags():
        # Keep actual -O1 lifetime-marker emission enabled. No source/IR rewrite
        # or marker-removal switch substitutes for importing these operations.
        return ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie",
                "-O1", "-fno-vectorize", "-fno-slp-vectorize", "-emit-llvm"]

    def compile_clang(self, clang, source, triple, suffix):
        output = self.directory / f"{source.stem}-{triple}.{suffix}"
        target_flags = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
        completed = subprocess.run([clang, "--target=" + triple, *target_flags, *self.clang_flags(),
                                    "-S" if suffix == "ll" else "-c", str(source), "-o", str(output)],
                                   cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output

    def test_clang22_complete_memory_lifetime_units_import_unmodified_text_and_bitcode_all_three_isas(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "memory.c"
        source.write_text(self.clang_source())
        expected_definitions = {"imported_set", "imported_copy", "imported_move", "imported_lifetime"}
        expected_intrinsics = {"llvm.memset.p0.i64", "llvm.memcpy.p0.p0.i64", "llvm.memmove.p0.p0.i64"} | LIFETIME_NAMES
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                text = self.compile_clang(clang, source, triple, "ll")
                llvm_ir = text.read_text()
                inventory = dict((name, kind) for kind, name in re.findall(
                    r"^(define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(", llvm_ir, re.MULTILINE))
                globals_ = set(re.findall(r"^@([A-Za-z_][A-Za-z0-9_.$]*)\s*=", llvm_ir, re.MULTILINE))
                self.assertEqual({name for name, kind in inventory.items() if kind == "define"}, expected_definitions)
                self.assertEqual({name for name, kind in inventory.items() if kind == "declare"}, expected_intrinsics | {"observe"})
                self.assertEqual(globals_, {"memory_counter"})
                self.assertIn("call void @llvm.lifetime.start.p0", llvm_ir)
                self.assertIn("call void @llvm.lifetime.end.p0", llvm_ir)
                modules = []
                for path in (text, self.compile_clang(clang, source, triple, "bc")):
                    module = importer.import_module(path, library_path=self.library,
                                                    frontend="Clang", frontend_version=version)
                    modules.append(module)
                    self.assertEqual(module["target"]["triple"], triple)
                    self.assertEqual(module["provenance"]["source_function_count"], len(inventory))
                    self.assertEqual(module["provenance"]["source_global_count"], 1)
                    self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                    self.assertEqual(module["provenance"]["frontend_version"], version)
                    self.assertEqual({fn["name"] for fn in module["functions"]}, set(inventory))
                    self.assertEqual({glob["name"] for glob in module["globals"]}, globals_)
                    self.assertEqual(module["globals"][0]["initializer"], {"bytes": [7] + [0] * 7, "relocations": []})
                    for name in expected_intrinsics:
                        declaration = self.function(module, name)
                        self.assertEqual(declaration["intrinsic"], name)
                        self.assertEqual(declaration["visibility"], "default")
                        self.assertIsNone(declaration["entry"])
                    for name, operation in (("imported_set", "memory_set"), ("imported_copy", "memory_copy"),
                                            ("imported_move", "memory_copy")):
                        function = self.function(module, name)
                        operations = self.operations(function)
                        self.assertEqual([item["op"] for item in operations], [operation])
                        self.assertEqual(operations[0]["length"], {"kind": "value", "id": function["params"][2]["id"]})
                        self.assertFalse(operations[0]["volatile"])
                        if operation == "memory_copy":
                            self.assertEqual(operations[0]["allow_overlap"], name == "imported_move")
                    function = self.function(module, "imported_lifetime")
                    instructions = self.instructions(function)
                    allocation = next(item for item in instructions if item["operation"]["op"] == "alloca")
                    pointer = {"kind": "value", "id": allocation["result"]["id"]}
                    operations = self.operations(function)
                    markers = [item for item in operations if item["op"] == "lifetime"]
                    self.assertEqual([marker["end"] for marker in markers], [False, True])
                    self.assertEqual([marker["pointer"] for marker in markers], [pointer, pointer])
                    local_set = next(item for item in operations if item["op"] == "memory_set")
                    self.assertEqual(local_set["destination"], pointer)
                    self.assertEqual(local_set["length"]["bits"], "32")
                    self.assertEqual(local_set["alignment"], 16 if triple.startswith("x86_64") else 1)
                    call = next(item for item in operations if item["op"] == "call")
                    self.assertEqual(call["callee"]["name"], "observe")
                    self.assertEqual(call["args"][0], pointer)
                    self.assertEqual(call["signature"], self.function(module, "observe")["signature"])
                self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                                 {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})

    def test_clang22_complete_memory_units_preserve_unused_atomic_function_text_and_bitcode_all_three_isas(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "memory-with-atomic.c"
        source.write_text(self.clang_source() + """
void unsupported_atomic(unsigned long *pointer) {
  __atomic_store_n(pointer, 1, __ATOMIC_SEQ_CST);
}
""")
        for triple in TRIPLES:
            for suffix in ("ll", "bc"):
                with self.subTest(triple=triple, suffix=suffix):
                    path = self.compile_clang(clang, source, triple, suffix)
                    if suffix == "ll":
                        llvm_ir = path.read_text()
                        self.assertIn("@imported_set(", llvm_ir)
                        self.assertIn("@unsupported_atomic(", llvm_ir)
                        self.assertIn("store atomic", llvm_ir)
                        inventory = dict((name, kind) for kind, name in re.findall(
                            r"^(define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(", llvm_ir, re.MULTILINE))
                        globals_ = set(re.findall(r"^@([A-Za-z_][A-Za-z0-9_.$]*)\s*=", llvm_ir, re.MULTILINE))
                        self.assertEqual({name for name, kind in inventory.items() if kind == "define"},
                                         {"imported_set", "imported_copy", "imported_move", "imported_lifetime", "unsupported_atomic"})
                    before = path.read_bytes()
                    module = importer.import_module(path, library_path=self.library,
                                                    frontend="Clang", frontend_version=version)
                    self.assertEqual(path.read_bytes(), before)
                    self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(before).hexdigest())
                    self.assertEqual(module["target"]["triple"], triple)
                    self.assertEqual({function["name"] for function in module["functions"]}, set(inventory))
                    self.assertEqual({glob["name"] for glob in module["globals"]}, globals_)
                    self.assertEqual({function["name"] for function in module["functions"] if function["entry"] is not None},
                                     {name for name, kind in inventory.items() if kind == "define"})
                    self.assertEqual(module["provenance"]["source_function_count"], len(inventory))
                    self.assertEqual(module["provenance"]["source_global_count"], len(globals_))
                    operations = self.operations(self.function(module, "unsupported_atomic"))
                    self.assertEqual(len(operations), 1)
                    self.assertEqual(operations[0]["op"], "atomic_store")
                    self.assertEqual(operations[0]["value"]["bits"], "1")
                    self.assertEqual(module["types"][operations[0]["value"]["ty"]], {"kind": "int", "bits": 64})
                    self.assertEqual(operations[0]["ordering"], "seq_cst")
                    self.assertEqual(operations[0]["sync_scope"], 1)
                    self.assertEqual(operations[0]["alignment"], 8)
                    self.assertFalse(operations[0]["volatile"])
                    self.assertEqual(self.operations(self.function(module, "imported_set"))[0]["op"], "memory_set")
                    self.assertTrue(any(op["op"] == "call" and op["callee"]["name"] == "observe"
                                        for op in self.operations(self.function(module, "imported_lifetime"))))
                    self.assertNotIn("atomic_profile", module["target"])


if __name__ == "__main__":
    unittest.main()
