"""Whole-unit allocsize hints retain explicit parsed payloads and ordinary effects.

This is source/API conformance. It does not execute an allocator or establish
native runtime completeness. LLVM-valid contracts outside the supported scalar
profile are distinguished from parser/verifier failures.
"""

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
from tests import test_ocore_llvm_memory_import as memory


TRIPLES = baseline.TRIPLES
FUNCTION_INDEX = 0xffffffff


class LlvmAllocsizeImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-allocsize-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    write = memory.LlvmMemoryImportTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)
    clang_flags = staticmethod(memory.LlvmMemoryImportTests.clang_flags)
    compile_clang = memory.LlvmMemoryImportTests.compile_clang

    @staticmethod
    def realization(module):
        return {key: value for key, value in module.items() if key not in {"name", "provenance"}}

    def assert_original(self, module, path, triple):
        self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(module["target"]["triple"], triple)
        for function in module["functions"]:
            signatures = [function["signature"]] + [op["signature"] for op in self.operations(function) if op["op"] == "call"]
            for signature in signatures:
                self.assertEqual(signature["abi"], "c")
                self.assertFalse(signature["variadic"])
                self.assertNotIn("allocsize", signature)
                self.assertNotIn("return_storage", signature)
                for attributes in signature["param_attributes"] + [signature["result_attributes"]]:
                    self.assertLessEqual(set(attributes), {"signext", "zeroext"})

    def roundtrip(self, body, triple):
        source = self.write(body, triple)
        original = source.read_bytes()
        modules = []
        for path in (source, self.bitcode(source)):
            module = importer.import_module(path, library_path=self.library)
            self.assert_original(module, path, triple)
            modules.append(module)
        self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        self.assertEqual(source.read_bytes(), original)
        return modules

    def assert_hint(self, module, symbol, site, raw, element, count=None):
        number = "absent" if count is None else str(count)
        prefix = f"{symbol}: {site} attribute index {FUNCTION_INDEX}: validated allocsize raw={raw}, element_index={element}, count_index={number}; "
        records = module["provenance"]["refinements"]
        self.assertTrue(any(record.startswith(prefix) for record in records), prefix)
        self.assertIn("original body, calls, memory effects, null results and dependency symbols retained", "\n".join(records))
        self.assertIn("raw uint64 and ordered decoded indices retained without callee inheritance or allocator rewriting", "\n".join(records))

    def reject_verified(self, body, triple, diagnostic=None, symbol=None):
        source = self.write(body, triple)
        original = source.read_bytes()
        # Fresh writer helper independently parses/verifies the complete source.
        for path in (source, self.bitcode(source)):
            with self.subTest(triple=triple, format=path.suffix, body=body):
                with self.assertRaises(importer.ImportFailure) as raised:
                    importer.import_module(path, library_path=self.library)
                self.assertEqual(raised.exception.stage, "import")
                if diagnostic:
                    self.assertIn(diagnostic, str(raised.exception))
                if symbol:
                    self.assertEqual(raised.exception.symbol, symbol)
        self.assertEqual(source.read_bytes(), original)

    def raw_bitcode(self, body, triple, payload, call=False, index=FUNCTION_INDEX):
        """Exercise verified raw IntAttr payloads the text parser cannot spell."""
        source = self.write(body, triple)
        data = source.read_bytes()
        api = importer.LLVM(self.library, importer.PINNED_SHA256)
        context, module, message = api.ContextCreate(), importer.P(), importer.P()
        buffer = api.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"raw-allocsize")
        serialized = None
        try:
            status = api.ParseIRInContext2(context, buffer, C.byref(module), C.byref(message))
            self.assertEqual(status, 0, C.string_at(message).decode() if message else "parse failed")
            if message:
                api.DisposeMessage(message)
                message = importer.P()
            owner = next(fn for fn in api.sequence(api.GetFirstFunction, api.GetNextFunction, module)
                         if api.name(fn) == ("caller" if call else "target"))
            if call:
                owner = next(inst for block in api.sequence(api.GetFirstBasicBlock, api.GetNextBasicBlock, owner)
                             for inst in api.sequence(api.GetFirstInstruction, api.GetNextInstruction, block)
                             if api.GetInstructionOpcode(inst) == 45)
            create = api.lib.LLVMCreateEnumAttribute
            create.restype, create.argtypes = importer.P, [importer.P, importer.U, importer.Q]
            add = getattr(api.lib, "LLVMAddCallSiteAttribute" if call else "LLVMAddAttributeAtIndex")
            add.restype, add.argtypes = None, [importer.P, importer.U, importer.P]
            kind = api.GetEnumAttributeKindForName(b"allocsize", 9)
            attribute = create(context, kind, payload)
            self.assertTrue(api.IsEnumAttribute(attribute))
            self.assertEqual(api.GetEnumAttributeValue(attribute), payload)
            add(owner, index, attribute)
            status = api.VerifyModule(module, 2, C.byref(message))
            diagnostic = C.string_at(message).decode() if message else ""
            serialized = api.WriteBitcodeToMemoryBuffer(module)
            binary = source.with_suffix(".bc")
            binary.write_bytes(C.string_at(api.GetBufferStart(serialized), api.GetBufferSize(serialized)))
            return binary, status, diagnostic
        finally:
            if serialized:
                api.DisposeMemoryBuffer(serialized)
            if message:
                api.DisposeMessage(message)
            if module:
                api.DisposeModule(module)
            api.DisposeMemoryBuffer(buffer)
            api.ContextDispose(context)

    def test_whole_definitions_unused_declarations_alias_direct_indirect_calls_and_allockind_compose_all_three_isas_text_and_bitcode(self):
        body = """
@counter = global i64 0
@allocator_alias = alias ptr(i64, i64), ptr @allocator
@address = global ptr @allocator_alias
declare void @observe(i64)
declare ptr @unused(i64) allocsize(0) allockind("alloc")
declare ptr @external(i64, i64) allocsize(0,1)
define ptr @allocator(i64 %size, i64 %count) allocsize(1,0) allockind("alloc") {
  store volatile i64 %size, ptr @counter, align 8
  call void @observe(i64 %count)
  ret ptr null
}
define ptr @caller(ptr %function, i64 %size) {
  %first = call ptr @external(i64 %size, i64 3) allocsize(0,1)
  %second = call ptr @allocator_alias(i64 %size, i64 0) allocsize(1,0)
  %third = call ptr %function(i64 %size, i64 1) allocsize(0)
  ret ptr %first
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assertEqual({fn["name"] for fn in module["functions"]}, {"allocator", "caller", "observe", "external", "unused"})
                self.assertEqual(module["provenance"]["source_function_count"], 5)
                self.assertEqual(module["provenance"]["source_global_count"], 2)
                self.assertEqual(module["provenance"]["source_alias_count"], 1)
                self.assertEqual(module["aliases"][0]["name"], "allocator_alias")
                self.assertEqual(module["aliases"][0]["aliasee"], "allocator")
                self.assertIsNone(self.function(module, "unused")["entry"])
                allocator = self.function(module, "allocator")
                self.assertEqual([op["op"] for op in self.operations(allocator)], ["store", "call"])
                self.assertTrue(self.operations(allocator)[0]["volatile"])
                self.assertEqual(allocator["blocks"][0]["terminator"]["value"]["kind"], "null")
                calls = self.operations(self.function(module, "caller"))
                self.assertEqual([op["op"] for op in calls], ["call"] * 3)
                self.assertEqual([op["callee"].get("name") for op in calls], ["external", "allocator_alias", None])
                self.assertEqual(calls[2]["callee"]["kind"], "value")
                self.assert_hint(module, "unused", "function", 0xffffffff, 0)
                self.assert_hint(module, "external", "function", 1, 0, 1)
                self.assert_hint(module, "allocator", "function", 1 << 32, 1, 0)
                for raw, element, count in ((1, 0, 1), (1 << 32, 1, 0), (0xffffffff, 0, None)):
                    self.assert_hint(module, "caller", "callsite", raw, element, count)
                self.assertIn("erased allocator description allockind=1", "\n".join(module["provenance"]["refinements"]))
                address = next(g for g in module["globals"] if g["name"] == "address")
                self.assertEqual(address["initializer"]["relocations"], [{"offset": 0, "width": 64, "symbol": "allocator_alias", "addend": 0}])

    def test_every_scalar_integer_width_is_admitted_and_extension_abi_is_preserved_all_three_isas_text_and_bitcode(self):
        body = "".join(f"declare ptr @width{bits}(i{bits} zeroext) allocsize(0)\n" for bits in range(1, 65))
        body += "define ptr @caller(i7 zeroext %size) { %value = call ptr @width7(i7 zeroext %size) allocsize(0)\nret ptr %value }\n"
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assertEqual(module["provenance"]["source_function_count"], 65)
                self.assertEqual({fn["name"] for fn in module["functions"]}, {f"width{bits}" for bits in range(1, 65)} | {"caller"})
                for bits in range(1, 65):
                    function = self.function(module, f"width{bits}")
                    self.assertEqual(module["types"][function["signature"]["params"][0]], {"kind": "int", "bits": bits})
                    self.assertEqual(function["signature"]["param_attributes"], [["zeroext"]])
                    self.assert_hint(module, f"width{bits}", "function", 0xffffffff, 0)
                self.assertEqual(self.operations(self.function(module, "caller"))[0]["signature"]["param_attributes"], [["zeroext"]])

    def test_reserved_count_sentinel_normalizes_to_absence_and_callsite_hints_are_not_inherited_all_three_isas(self):
        body = """
declare ptr @target(i64, i64) allocsize(0,4294967295)
define ptr @caller(i64 %size) {
  %first = call ptr @target(i64 %size, i64 1)
  %second = call ptr @target(i64 %size, i64 2) allocsize(1,4294967295)
  ret ptr %first
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assert_hint(module, "target", "function", 0xffffffff, 0)
                self.assert_hint(module, "caller", "callsite", 0x1ffffffff, 1)
                hints = [r for r in module["provenance"]["refinements"] if r.startswith("caller: callsite") and "validated allocsize" in r]
                self.assertEqual(len(hints), 1)
                self.assertEqual(len(self.operations(self.function(module, "caller"))), 2)
                # The parser's sentinel is absence, regardless of how it was
                # spelled originally; the original input hash still differs.
            explicit = self.roundtrip("declare ptr @target(i64, i64) allocsize(0)\n", triple)[0]
            sentinel = self.roundtrip("declare ptr @target(i64, i64) allocsize(0,4294967295)\n", triple)[0]
            self.assertEqual(self.realization(explicit), self.realization(sentinel))
            self.assertNotEqual(explicit["provenance"]["input_sha256"], sentinel["provenance"]["input_sha256"])

    def test_verified_raw_duplicate_payload_zero_and_one_are_profile_rejections_not_llvm_invalid_all_three_isas(self):
        body = "declare ptr @target(i64, i64)\ndefine ptr @caller(ptr %fn) { %r = call ptr %fn(i64 1, i64 2)\nret ptr %r }\n"
        for triple in TRIPLES:
            for call in (False, True):
                for raw in (0, 0x100000001):
                    binary, status, diagnostic = self.raw_bitcode(body, triple, raw, call)
                    self.assertEqual(status, 0, diagnostic)
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(binary, library_path=self.library)
                    self.assertEqual(raised.exception.stage, "import")
                    self.assertEqual(raised.exception.symbol, "caller" if call else "target")
                    self.assertIn("duplicate indices are unsupported by the own fixed C profile", str(raised.exception))

    def test_raw_payload_absent_index_one_preserves_high_half_and_max_out_of_bounds_fails_verifier_all_three_isas(self):
        body = "declare ptr @target(i64, i64)\n"
        for triple in TRIPLES:
            binary, status, diagnostic = self.raw_bitcode(body, triple, 0x1ffffffff)
            self.assertEqual(status, 0, diagnostic)
            module = importer.import_module(binary, library_path=self.library)
            self.assert_original(module, binary, triple)
            self.assert_hint(module, "target", "function", 0x1ffffffff, 1)
            binary, status, diagnostic = self.raw_bitcode(body, triple, (1 << 64) - 1)
            self.assertNotEqual(status, 0)
            self.assertIn("out of bounds", diagnostic)
            with self.assertRaises(importer.ImportFailure) as raised:
                importer.import_module(binary, library_path=self.library)
            self.assertEqual(raised.exception.stage, "llvm-verify")

    def test_indices_and_integer_parameter_requirements_fail_at_actual_llvm_verify_stage_all_three_isas(self):
        cases = [
            "declare ptr @target(i64) allocsize(1)",
            "declare ptr @target(i64, i64) allocsize(0,2)",
            "declare ptr @target(ptr) allocsize(0)",
            "declare ptr @target(i64, ptr) allocsize(0,1)",
            "declare ptr @target(double) allocsize(0)",
            "declare ptr @target(<2 x i32>) allocsize(0)",
            "declare ptr @target(i64) allocsize(4294967295)",
            "define ptr @caller(ptr %function) { %r = call ptr %function(ptr null) allocsize(0)\nret ptr %r }",
            "define ptr @caller(ptr %function) { %r = call ptr %function(i64 1) allocsize(1)\nret ptr %r }",
        ]
        for triple in TRIPLES:
            for body in cases:
                with self.subTest(triple=triple, body=body):
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(self.write(body + "\n", triple), library_path=self.library)
                    self.assertEqual(raised.exception.stage, "llvm-verify")
                    self.assertIn("allocsize", str(raised.exception))

    def test_text_duplicate_overflow_negative_and_attribute_placements_fail_parser_all_three_isas(self):
        cases = [
            "declare ptr @target(i64) allocsize(0,0)",
            "declare ptr @target(i64, i64) allocsize(1,1)",
            "declare ptr @target(i64) allocsize(4294967296)",
            "declare ptr @target(i64) allocsize(-1)",
            "declare allocsize(0) ptr @target(i64)",
            "declare ptr @target(i64 allocsize(0))",
            "declare ptr @target(i64)\ndefine ptr @caller() { %r = call ptr @target(i64 allocsize(0) 1)\nret ptr %r }",
        ]
        for triple in TRIPLES:
            for body in cases:
                with self.subTest(triple=triple, body=body):
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(self.write(body + "\n", triple), library_path=self.library)
                    self.assertEqual(raised.exception.stage, "parse")

    def test_llvm_verified_result_and_calling_profiles_outside_own_scalar_profile_reject_whole_units_all_three_isas(self):
        cases = [
            ("declare void @unsupported(i64) allocsize(0)", "fixed C profile with an AS0 pointer result"),
            ("declare i64 @unsupported(i64) allocsize(0)", "fixed C profile with an AS0 pointer result"),
            ("declare <2 x i64> @unsupported(i64) allocsize(0)", "unsupported LLVM type kind 13"),
            ("declare ptr addrspace(1) @unsupported(i64) allocsize(0)", "unsupported pointer address space 1"),
            ("declare ptr @unsupported(i65) allocsize(0)", "unsupported integer width i65"),
            ("declare ptr @unsupported(i64, ...) allocsize(0)", "variadic calling convention"),
            ("declare fastcc ptr @unsupported(i64) allocsize(0)", "supported fixed C profile"),
        ]
        for triple in TRIPLES:
            for body, diagnostic in cases:
                self.reject_verified("define i64 @supported() { ret i64 7 }\n" + body + "\n", triple, diagnostic, "unsupported")

    def test_allocsize_preserves_companion_allocalign_and_rejects_abi_security_sections_tls_or_string_attributes_all_three_isas(self):
        cases = [
            ('declare ptr @unsupported(i64 allocalign) allocsize(0) allockind("alloc,aligned")', "unsupported attribute kind", "unsupported"),
            ('declare ptr @unsupported(i64, ptr byval(i8)) allocsize(0)', "unsupported attribute kind", "unsupported"),
            ('declare ptr @unsupported(i64) allocsize(0) sspstrong', "unsupported attribute kind", "unsupported"),
            ('declare ptr @unsupported(i64) allocsize(0) section "special"', "explicit section", "unsupported"),
            ('declare dllimport ptr @unsupported(i64) allocsize(0)', "DLL", "unsupported"),
            ('declare ptr @unsupported(i64) "allocsize"="0"', "unsupported string attribute allocsize=0", "unsupported"),
            ('@unsupported = thread_local global i64 0\ndeclare ptr @unused(i64) allocsize(0)', "TLS", "unsupported"),
        ]
        for triple in TRIPLES:
            for body, diagnostic, symbol in cases:
                complete = "define i64 @supported() { ret i64 7 }\n" + body + "\n"
                if "allocalign" in body:
                    for module in self.roundtrip(complete, triple):
                        self.assertEqual([f["name"] for f in module["functions"]], ["supported", "unsupported"])
                        self.assertEqual(module["globals"], [])
                        self.assertEqual(module["aliases"], [])
                        self.assert_hint(module, "unsupported", "function", 0xffffffff, 0)
                        self.assertTrue(any("function attribute index 1: validated allocator description allocalign=0;" in item
                                            for item in module["provenance"]["refinements"]))
                    continue
                self.reject_verified(complete, triple, diagnostic, symbol)

    @staticmethod
    def clang_source():
        return '''typedef unsigned long word;
volatile word counter;
extern void *external_alloc(word) __attribute__((alloc_size(1)));
extern void *external_product(word, word) __attribute__((alloc_size(1,2)));
void *own_allocator(word) __attribute__((alloc_size(1), noinline));
void *own_allocator(word size) { counter += size; return (void *)0; }
void *cold_unused_allocator(word, word) __attribute__((alloc_size(2,1), cold, noinline));
void *cold_unused_allocator(word size, word count) { counter += count; return (void *)0; }
void *relay(word size) {
  void *result = external_alloc(size);
  external_product(size, 3);
  own_allocator(size);
  return result;
}
'''

    def test_actual_clang22_complete_allocsize_units_keep_cold_unused_null_bodies_calls_globals_and_raw_hints_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "whole-allocsize.c"
        source.write_text(self.clang_source())
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        expected = {"own_allocator", "cold_unused_allocator", "relay", "external_alloc", "external_product"}
        for triple in TRIPLES:
            modules = []
            for suffix in ("ll", "bc"):
                path = self.compile_clang(clang, source, triple, suffix)
                if suffix == "ll":
                    self.assertEqual(set(re.findall(r'^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(', path.read_text(), re.MULTILINE)), expected)
                    self.assertIn("allocsize(0,1)", path.read_text())
                    self.assertIn("allocsize(1,0)", path.read_text())
                module = importer.import_module(path, library_path=self.library, frontend="Clang C", frontend_version=version)
                self.assert_original(module, path, triple)
                modules.append(module)
                self.assertEqual({fn["name"] for fn in module["functions"]}, expected)
                self.assertEqual(module["provenance"]["source_function_count"], 5)
                self.assertEqual({g["name"] for g in module["globals"]}, {"counter"})
                self.assertEqual(sum(fn["entry"] is not None for fn in module["functions"]), 3)
                self.assertEqual(module["aliases"], [])
                self.assert_hint(module, "external_alloc", "function", 0xffffffff, 0)
                self.assert_hint(module, "external_product", "function", 1, 0, 1)
                self.assert_hint(module, "own_allocator", "function", 0xffffffff, 0)
                self.assert_hint(module, "cold_unused_allocator", "function", 1 << 32, 1, 0)
                relay_calls = [op for op in self.operations(self.function(module, "relay")) if op["op"] == "call"]
                self.assertEqual([op["callee"]["name"] for op in relay_calls], ["external_alloc", "external_product", "own_allocator"])
                for name in ("own_allocator", "cold_unused_allocator"):
                    function = self.function(module, name)
                    ops = self.operations(function)
                    self.assertEqual([op["op"] for op in ops], ["load", "binary", "store"])
                    self.assertTrue(ops[0]["volatile"] and ops[2]["volatile"])
                    self.assertEqual(function["blocks"][-1]["terminator"]["value"]["kind"], "null")
            self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)

    def test_actual_clang22_complete_allocsize_units_reject_unused_tls_without_filtering_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "whole-allocsize-with-tls.c"
        source.write_text(self.clang_source() + "_Thread_local word unsupported_tls;\n")
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        for triple in TRIPLES:
            for suffix in ("ll", "bc"):
                path = self.compile_clang(clang, source, triple, suffix)
                with self.subTest(triple=triple, format=suffix):
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(path, library_path=self.library, frontend="Clang C", frontend_version=version)
                    self.assertEqual(raised.exception.stage, "import")
                    self.assertEqual(raised.exception.symbol, "unsupported_tls")
                    self.assertIn("TLS", str(raised.exception))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)

    def test_cli_imports_complete_allocalign_unit_and_preserves_good_output_on_unused_tls_failure_all_three_isas(self):
        output = self.directory / "existing.json"
        output.write_text('{"previous":"good"}\n')
        body = 'define ptr @allocator(i64 %size) allocsize(0) { ret ptr null }\ndeclare ptr @unsupported(i64 allocalign) allocsize(0)\n'
        for triple in TRIPLES:
            source = self.write(body, triple)
            for path in (source, self.bitcode(source)):
                result = subprocess.run([sys.executable, str(baseline.ROOT / "scripts/ocore_llvm_import.py"), str(path),
                    "--output", str(output), "--llvm-library", str(self.library)], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                module = json.loads(output.read_text())
                self.assert_original(module, path, triple)
                self.assertEqual([f["name"] for f in module["functions"]], ["allocator", "unsupported"])
                self.assertEqual(module["globals"], [])
                self.assertEqual(module["aliases"], [])
            original = output.read_bytes()
            rejected = self.write(body + '@unsupported_tls = thread_local global i64 0\n', triple)
            for path in (rejected, self.bitcode(rejected)):
                result = subprocess.run([sys.executable, str(baseline.ROOT / "scripts/ocore_llvm_import.py"), str(path),
                    "--output", str(output), "--llvm-library", str(self.library)], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 1)
                error = json.loads(result.stderr)["error"]
                self.assertEqual(error["stage"], "import")
                self.assertEqual(error["symbol"], "unsupported_tls")
                self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
