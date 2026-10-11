"""Preserve original aggregate signatures and independent C/fastcc contracts.

These source/API checks do not admit or execute a physical native ABI plan.
Whole original frontend units keep their ISA-specific coercions and attributes.
"""

import hashlib
import os
from pathlib import Path
import re
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_aggregates as aggregates


TRIPLES = baseline.TRIPLES


class LlvmAggregateAbiImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-aggregate-abi-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    write = aggregates.LlvmAggregateImportTests.write
    bitcode = aggregates.LlvmAggregateImportTests.bitcode
    function = staticmethod(aggregates.LlvmAggregateImportTests.function)
    instructions = staticmethod(aggregates.LlvmAggregateImportTests.instructions)
    operations = classmethod(aggregates.LlvmAggregateImportTests.operations.__func__)
    shape = classmethod(aggregates.LlvmAggregateImportTests.shape.__func__)
    realization = staticmethod(aggregates.LlvmAggregateImportTests.realization)
    roundtrip = aggregates.LlvmAggregateImportTests.roundtrip
    reject_verified = aggregates.LlvmAggregateImportTests.reject_verified
    record_producer = aggregates.LlvmAggregateImportTests.record_producer
    record_import = aggregates.LlvmAggregateImportTests.record_import
    clang_compile = aggregates.LlvmAggregateImportTests.clang_compile
    rust_compiler = aggregates.LlvmAggregateImportTests.rust_compiler
    rust_compile = aggregates.LlvmAggregateImportTests.rust_compile

    def assert_original(self, module, path, triple):
        self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(module["target"]["triple"], triple)
        for field, key in (("source_function_count", "functions"), ("source_global_count", "globals"), ("source_alias_count", "aliases")):
            self.assertEqual(module["provenance"][field], len(module[key]))
        for function in module["functions"]:
            self.assertEqual([p["ty"] for p in function["params"]], function["signature"]["params"])
            for signature in [function["signature"], *[op["signature"] for op in self.operations(function) if op["op"] == "call"]]:
                self.assertIn(signature["abi"], {"c", "fastcc"})
                self.assertFalse(signature["variadic"])
                self.assertEqual(len(signature["params"]), len(signature["param_attributes"]))
                for ident in [signature["result"], *signature["params"]]:
                    self.assertIn(module["types"][ident]["kind"], {"void", "int", "pointer", "struct", "array"})

    def test_nested_struct_array_c_signatures_keep_original_parameter_order_results_and_unused_inventory_all_three_isas_text_and_bitcode(self):
        body = """
%R = type <{i7, [2 x {i33, ptr}], i64}>
@data = global i64 9
@fn_address = global ptr @ordinary
declare %R @unused([2 x i7], %R, ptr)
define %R @ordinary(%R %record, i7 zeroext %tag, ptr %pointer) {
  %a = insertvalue %R %record, i7 %tag, 0
  %b = insertvalue %R %a, ptr %pointer, 1, 1, 1
  ret %R %b
}
define [0 x i7] @empty([0 x i7] %value, {} %empty) { ret [0 x i7] %value }
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assertEqual({f["name"] for f in module["functions"]}, {"ordinary", "unused", "empty"})
                self.assertEqual({g["name"] for g in module["globals"]}, {"data", "fn_address"})
                fn = self.function(module, "ordinary")
                sig = fn["signature"]
                self.assertEqual(sig["abi"], "c")
                self.assertEqual(sig["params"][0], sig["result"])
                self.assertEqual([module["types"][p]["kind"] for p in sig["params"]], ["struct", "int", "pointer"])
                self.assertTrue(module["types"][sig["result"]]["packed"])
                self.assertEqual(sig["param_attributes"], [[], ["zeroext"], []])
                self.assertEqual([op["op"] for op in self.operations(fn)], ["insert_value", "insert_value"])
                self.assertEqual(fn["blocks"][0]["terminator"]["value"], {"kind": "value", "id": 4})
                empty = self.function(module, "empty")
                self.assertEqual(module["types"][empty["signature"]["result"]]["len"], 0)
                self.assertEqual(module["types"][empty["signature"]["params"][1]]["fields"], [])
                pointer = next(g for g in module["globals"] if g["name"] == "fn_address")
                self.assertEqual(pointer["initializer"]["relocations"], [{"offset": 0, "width": 64, "symbol": "ordinary", "addend": 0}])

    def test_fastcc_direct_alias_and_indirect_calls_keep_logical_types_exact_names_extensions_and_bare_type_contract_all_three_isas(self):
        body = """
%Pair = type {i33, ptr}
@alias = alias %Pair(%Pair, i8), ptr @fast
@address = global ptr @alias
declare fastcc %Pair @unused(%Pair, i8 zeroext)
define internal fastcc %Pair @fast(%Pair %pair, i8 zeroext %tag) {
  %wide = zext i8 %tag to i33
  %r = insertvalue %Pair %pair, i33 %wide, 0
  ret %Pair %r
}
define %Pair @direct(%Pair %p, i8 %tag) { %r = call fastcc %Pair @fast(%Pair %p, i8 zeroext %tag)
  ret %Pair %r }
define %Pair @alias_call(%Pair %p, i8 %tag) { %r = call fastcc %Pair @alias(%Pair %p, i8 zeroext %tag)
  ret %Pair %r }
define %Pair @indirect(ptr %function, %Pair %p, i8 %tag) { %r = call fastcc %Pair %function(%Pair %p, i8 zeroext %tag)
  ret %Pair %r }
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assertEqual({f["name"] for f in module["functions"]}, {"fast", "unused", "direct", "alias_call", "indirect"})
                fast = self.function(module, "fast")["signature"]
                self.assertEqual(fast["abi"], "fastcc")
                self.assertEqual(self.function(module, "unused")["signature"], fast)
                for name, symbol in (("direct", "fast"), ("alias_call", "alias"), ("indirect", None)):
                    fn = self.function(module, name)
                    self.assertEqual(fn["signature"]["abi"], "c")
                    call = self.operations(fn)[0]
                    self.assertEqual(call["signature"], fast)
                    self.assertEqual(call["callee"]["kind"], "symbol" if symbol else "value")
                    if symbol:
                        self.assertEqual(call["callee"]["name"], symbol)
                alias = module["aliases"][0]
                self.assertEqual(alias["aliasee"], "fast")
                self.assertEqual(module["types"][alias["ty"]]["signature"]["abi"], "c", "LLVM function TypeRef carries no owner calling convention")
                self.assertEqual(module["types"][alias["ty"]]["signature"]["param_attributes"], [[], []])
                self.assertEqual(module["globals"][0]["initializer"]["relocations"][0]["symbol"], "alias")
                refinement = "\n".join(module["provenance"]["refinements"])
                self.assertIn("exact calling convention 8 retained as fastcc", refinement)
                self.assertIn("no signature flattening, callee inheritance or convention substitution", refinement)

    def test_fastcc_scalar_register_pressure_remains_ten_original_parameters_and_scalar_abi_extensions_all_three_isas(self):
        params = ", ".join(f"i64 %p{i}" for i in range(10))
        args = ", ".join(f"i64 {i + 1}" for i in range(10))
        body = f"define internal fastcc i64 @ten({params}) {{ %v = add i64 %p0, %p9\nret i64 %v }}\ndefine i64 @caller() {{ %r = call fastcc i64 @ten({args})\nret i64 %r }}\ndefine fastcc signext i7 @narrow(i7 zeroext %n) {{ ret i7 %n }}\n"
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                ten = self.function(module, "ten")
                self.assertEqual(len(ten["params"]), 10)
                self.assertEqual(ten["signature"]["abi"], "fastcc")
                call = self.operations(self.function(module, "caller"))[0]
                self.assertEqual(call["signature"], ten["signature"])
                self.assertEqual([arg["bits"] for arg in call["args"]], [str(i + 1) for i in range(10)])
                narrow = self.function(module, "narrow")["signature"]
                self.assertEqual(narrow["param_attributes"], [["zeroext"]])
                self.assertEqual(narrow["result_attributes"], ["signext"])

    def test_verified_calling_convention_and_extension_mismatches_remain_explicit_for_mandatory_native_verifier_all_three_isas(self):
        body = """
@alias = alias i7(i7), ptr @fast
define fastcc signext i7 @fast(i7 zeroext %x) { ret i7 %x }
define i7 @wrong_cc(i7 %x) { %r = call signext i7 @alias(i7 zeroext %x)
  ret i7 %r }
define i7 @raw_attrs(i7 %x) { %r = call fastcc i7 @fast(i7 %x)
  ret i7 %r }
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                target = self.function(module, "fast")["signature"]
                wrong = self.operations(self.function(module, "wrong_cc"))[0]["signature"]
                self.assertEqual((target["abi"], wrong["abi"]), ("fastcc", "c"))
                raw = self.operations(self.function(module, "raw_attrs"))[0]["signature"]
                self.assertEqual(raw["param_attributes"], [[]])
                self.assertEqual(raw["result_attributes"], [])
                self.assertEqual(target["param_attributes"], [["zeroext"]])
                self.assertEqual(target["result_attributes"], ["signext"])
                # LLVM verifies these raw contracts. Source import preserves
                # them; native signature equality owns final ABI rejection.

    def test_fastcc_typed_sret_keeps_first_or_second_pointer_original_order_and_raw_callsite_storage_all_three_isas(self):
        for position in (0, 1):
            lead = "i64 %prefix, " if position else ""
            call_lead = "i64 9, " if position else ""
            body = f"%R = type {{i7, [2 x i33]}}\ndefine fastcc void @write({lead}ptr sret(%R) align 8 %out, %R %record) {{ store %R %record, ptr %out, align 1\nret void }}\ndefine void @caller(ptr %out) {{ call fastcc void @write({call_lead}ptr sret(%R) %out, %R zeroinitializer)\nret void }}\n"
            for triple in TRIPLES:
                for module in self.roundtrip(body, triple):
                    write = self.function(module, "write")["signature"]
                    call = self.operations(self.function(module, "caller"))[0]["signature"]
                    self.assertEqual(write, call)
                    self.assertEqual(write["abi"], "fastcc")
                    self.assertEqual(write["return_storage"]["param"], position)
                    self.assertEqual(write["return_storage"]["ty"], write["params"][position + 1])
                    self.assertEqual(module["types"][write["result"]]["kind"], "void")
                    refinement = "\n".join(module["provenance"]["refinements"])
                    self.assertIn("explicit alignment 8", refinement)
                    self.assertIn("explicit alignment not explicitly specified", refinement)

    def test_unsupported_conventions_typed_payloads_and_abi_attributes_still_reject_whole_unused_units_all_three_isas(self):
        cases = [
            ("declare coldcc i7 @unsupported()", "unsupported calling convention 9"),
            ("declare cc 10 i7 @unsupported()", "unsupported calling convention 10"),
            ("declare fastcc {i7, i65} @unsupported()", "unsupported integer width i65"),
            ("declare {i7, double} @unsupported()", "unsupported LLVM type kind"),
            ("declare fastcc void @unsupported({i7, <2 x i7>})", "unsupported LLVM type kind"),
            ("declare fastcc void @unsupported({i7, ptr addrspace(1)})", "unsupported pointer address space 1"),
            ("declare void @unsupported(ptr byval({i7,i64}))", "unsupported attribute"),
            ("declare void @unsupported(ptr inreg)", "unsupported attribute"),
            ("declare i7 @unsupported(i64, ...)", "variadic calling convention is unsupported"),
        ]
        for triple in TRIPLES:
            for body, message in cases:
                self.reject_verified("define i7 @supported() { ret i7 7 }\n" + body + "\n", triple, message, "unsupported")

    def test_owned_intrinsic_declarations_and_calls_remain_exact_c_even_when_fastcc_is_llvm_verified_all_three_isas(self):
        cases = [
            ("declare fastcc void @llvm.trap()", "llvm.trap"),
            ("declare fastcc void @llvm.assume(i1)", "llvm.assume"),
            ("declare void @llvm.trap()\ndefine void @bad() { call fastcc void @llvm.trap()\nunreachable }", "bad"),
            ("declare void @llvm.assume(i1)\ndefine void @bad() { call fastcc void @llvm.assume(i1 true)\nret void }", "bad"),
        ]
        for triple in TRIPLES:
            for body, symbol in cases:
                self.reject_verified(body + "\n", triple, "owned intrinsic requires the exact C calling convention", symbol)

    @staticmethod
    def clang_source():
        return '''typedef unsigned long word;
struct Pair { word first; word second; };
struct Pair state = {11,13};
struct Pair pair_make(word first, word second) { struct Pair result = {first, second ^ 37}; return result; }
word pair_read(struct Pair value) { return value.first ^ value.second; }
struct Pair pair_forward(struct Pair value) { value.first += 7; return value; }
extern struct Pair pair_alias(word, word) __attribute__((alias("pair_make")));
struct Pair pair_call(word value) { return pair_alias(value, value + 11); }
struct Pair unused_pair(word value) { return pair_make(value ^ 9, value + 13); }
'''

    def test_actual_clang22_complete_c_and_cpp_pair_units_preserve_genuine_per_isa_frontend_coercions_inventory_and_aliases(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        for cpp in (False, True):
            source = self.directory / ("whole-pair.cpp" if cpp else "whole-pair.c")
            code = self.clang_source()
            source.write_text('extern "C" {\n' + code + '}\n' if cpp else code)
            original = source.read_bytes()
            for triple in TRIPLES:
                modules = []
                for suffix in ("ll", "bc"):
                    path = self.clang_compile(clang, source, triple, suffix, cpp)
                    module = importer.import_module(path, library_path=self.library, frontend="Clang C++" if cpp else "Clang C", frontend_version=version)
                    self.record_import(path, module=module)
                    self.assert_original(module, path, triple)
                    modules.append(module)
                    self.assertEqual({f["name"] for f in module["functions"] if f["entry"] is not None}, {"pair_make", "pair_read", "pair_forward", "pair_call", "unused_pair"})
                    self.assertEqual({g["name"] for g in module["globals"]}, {"state"})
                    self.assertEqual([(a["name"], a["aliasee"]) for a in module["aliases"]], [("pair_alias", "pair_make")])
                    make = self.function(module, "pair_make")["signature"]
                    self.assertEqual(module["types"][make["result"]]["kind"], "struct" if triple == TRIPLES[0] else "array")
                    read = self.function(module, "pair_read")["signature"]
                    self.assertEqual(len(read["params"]), 2 if triple == TRIPLES[0] else 1)
                    if triple != TRIPLES[0]:
                        self.assertEqual(module["types"][read["params"][0]]["kind"], "array")
                    if suffix == "ll":
                        names = set(re.findall(r'^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(', path.read_text(), re.MULTILINE))
                        self.assertEqual({f["name"] for f in module["functions"]}, names)
                self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(source.read_bytes(), original)

    @staticmethod
    def rust_source():
        return '''#![no_std]
#[repr(C)] pub struct Pair { pub first: u64, pub second: u64 }
#[no_mangle] pub static rust_pair_state: Pair = Pair { first: 11, second: 13 };
#[no_mangle] pub extern "C" fn rust_pair_make(first: u64, second: u64) -> Pair { Pair { first, second: second ^ 37 } }
#[no_mangle] pub extern "C" fn rust_pair_read(value: Pair) -> u64 { value.first ^ value.second }
#[no_mangle] pub extern "C" fn rust_pair_forward(value: Pair) -> Pair { Pair { first: value.first.wrapping_add(7), second: value.second } }
#[inline(never)] fn internal_pair(first: u64, second: u64) -> Pair { Pair { first: first.wrapping_add(9), second: second ^ 13 } }
#[no_mangle] pub extern "C" fn rust_pair_call(value: u64) -> Pair { internal_pair(value, value.wrapping_add(11)) }
#[no_mangle] pub extern "C" fn rust_unused_pair(value: u64) -> Pair { Pair { first: value ^ 9, second: value.wrapping_add(13) } }
'''

    def test_actual_rust1971_complete_pair_units_keep_genuine_c_coercions_generated_internal_fastcc_calls_and_lp64d(self):
        rustc, version = self.rust_compiler()
        source = self.directory / "whole-pair.rs"
        source.write_text(self.rust_source())
        original = source.read_bytes()
        expected = {"rust_pair_make", "rust_pair_read", "rust_pair_forward", "rust_pair_call", "rust_unused_pair"}
        for target, triple, abi in ((TRIPLES[0], TRIPLES[0], None), (TRIPLES[1], TRIPLES[1], None), ("riscv64gc-unknown-linux-gnu", TRIPLES[2], "lp64d")):
            modules = []
            for suffix in ("ll", "bc"):
                path = self.rust_compile(rustc, source, target, suffix)
                module = importer.import_module(path, library_path=self.library, frontend="Rust", frontend_version=version)
                self.record_import(path, module=module)
                self.assert_original(module, path, triple)
                modules.append(module)
                self.assertEqual(module["target"].get("abi"), abi)
                definitions = {f["name"] for f in module["functions"] if f["entry"] is not None}
                self.assertTrue(expected <= definitions)
                internals = [f for f in module["functions"] if f["name"] not in expected]
                self.assertEqual(len(internals), 1)
                self.assertIn("internal_pair", internals[0]["name"])
                self.assertEqual(internals[0]["signature"]["abi"], "fastcc")
                call = next(op for op in self.operations(self.function(module, "rust_pair_call")) if op["op"] == "call")
                self.assertEqual(call["signature"], internals[0]["signature"])
                self.assertEqual(call["callee"]["name"], internals[0]["name"])
                self.assertEqual({g["name"] for g in module["globals"]}, {"rust_pair_state"})
                make = self.function(module, "rust_pair_make")["signature"]
                self.assertEqual(module["types"][make["result"]]["kind"], "struct" if triple == TRIPLES[0] else "array")
                if suffix == "ll":
                    names = set(re.findall(r'^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(', path.read_text(), re.MULTILINE))
                    self.assertEqual({f["name"] for f in module["functions"]}, names)
            self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        self.assertEqual(source.read_bytes(), original)

    def test_actual_complete_clang_and_rust_pair_units_reject_retained_unused_float_without_partial_import_all_three_isas(self):
        clang, clang_version = baseline.LlvmImportTests.clang22_frontend(self)
        rustc, rust_version = self.rust_compiler()
        for language in ("c", "rs"):
            source = self.directory / ("whole-pair-bad." + language)
            source.write_text(self.clang_source() + "double unsupported_float(word value) { return (double)value; }\n" if language == "c" else self.rust_source() + '#[no_mangle] pub extern "C" fn unsupported_float(value: u64) -> f64 { value as f64 }\n')
            original = source.read_bytes()
            for triple in TRIPLES:
                for suffix in ("ll", "bc"):
                    path = self.clang_compile(clang, source, triple, suffix, False) if language == "c" else self.rust_compile(rustc, source, "riscv64gc-unknown-linux-gnu" if triple == TRIPLES[2] else triple, suffix)
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(path, library_path=self.library, frontend="Clang C" if language == "c" else "Rust", frontend_version=clang_version if language == "c" else rust_version)
                    self.record_import(path, error=raised.exception)
                    self.assertEqual(raised.exception.stage, "import")
                    self.assertEqual(raised.exception.symbol, "unsupported_float")
                    self.assertIn("unsupported LLVM type kind", str(raised.exception))
            self.assertEqual(source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
