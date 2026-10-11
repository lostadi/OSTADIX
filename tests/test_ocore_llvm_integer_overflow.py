"""Preserve complete LLVM overflow units; native realization has separate gates."""

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_aggregates as aggregates


TRIPLES = baseline.TRIPLES
FAMILIES = ("sadd", "uadd", "ssub", "usub", "smul", "umul")


def name(family, width):
    return f"llvm.{family}.with.overflow.i{width}"


def declaration(family, width):
    return f"declare {{i{width}, i1}} @{name(family, width)}(i{width}, i{width})\n"


class LlvmIntegerOverflowImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-overflow-")
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
    record_producer = aggregates.LlvmAggregateImportTests.record_producer
    record_import = aggregates.LlvmAggregateImportTests.record_import
    clang_compile = aggregates.LlvmAggregateImportTests.clang_compile
    rust_compiler = aggregates.LlvmAggregateImportTests.rust_compiler
    rust_compile = aggregates.LlvmAggregateImportTests.rust_compile

    def record_input(self, path):
        evidence = os.environ.get("OCORE_TEST_AGGREGATE_EVIDENCE")
        if evidence:
            directory = Path(evidence) / "portable-inputs"
            directory.mkdir(parents=True, exist_ok=True)
            (directory / (hashlib.sha256(path.read_bytes()).hexdigest() + path.suffix)).write_bytes(path.read_bytes())

    def assert_original(self, module, path, triple):
        self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(module["target"]["triple"], triple)
        for field, key in (("source_function_count", "functions"), ("source_global_count", "globals"),
                           ("source_alias_count", "aliases")):
            self.assertEqual(module["provenance"][field], len(module[key]))

    def roundtrip(self, body, triple):
        text = self.write(body, triple)
        modules = []
        for path in (text, self.bitcode(text)):
            self.record_input(path)
            module = importer.import_module(path, library_path=self.library)
            self.record_import(path, module=module)
            self.assert_original(module, path, triple)
            modules.append(module)
        self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        return modules

    def reject(self, body, triple, stage="import", binary=True, symbol=None, diagnostic=None):
        text = self.write(body, triple)
        paths = (text, self.bitcode(text)) if binary else (text,)
        for path in paths:
            self.record_input(path)
            with self.assertRaises(importer.ImportFailure) as raised:
                importer.import_module(path, library_path=self.library)
            self.record_import(path, error=raised.exception)
            self.assertEqual(raised.exception.stage, stage, "toolchain failure is not an input rejection")
            if symbol is not None:
                self.assertEqual(raised.exception.symbol, symbol)
            if diagnostic is not None:
                self.assertIn(diagnostic, str(raised.exception))

    def assert_declaration(self, module, family, width):
        intrinsic = name(family, width)
        function = self.function(module, intrinsic)
        self.assertEqual(function["intrinsic"], intrinsic)
        self.assertEqual(function["linkage"], "external")
        self.assertEqual(function["visibility"], "default")
        self.assertEqual(function["blocks"], [])
        self.assertIsNone(function["entry"])
        signature = function["signature"]
        self.assertEqual(signature["abi"], "c")
        self.assertFalse(signature["variadic"])
        self.assertEqual(signature["result_attributes"], [])
        self.assertEqual(signature["param_attributes"], [[], []])
        self.assertEqual(self.shape(module, signature["result"]),
                         {"kind": "struct", "packed": False,
                          "fields": [{"kind": "int", "bits": width}, {"kind": "int", "bits": 1}]})
        self.assertEqual([module["types"][ty] for ty in signature["params"]],
                         [{"kind": "int", "bits": width}] * 2)

    def test_every_six_family_width_1_to_64_contract_in_six_complete_all_three_isa_text_bitcode_units(self):
        bodies, expected = [], set()
        for family in FAMILIES:
            for width in range(1, 65):
                ordinary = f"probe_{family}_{width}"
                expected.update((ordinary, name(family, width)))
                bodies.append(declaration(family, width) + f"""
define {{i{width}, i1}} @{ordinary}(i{width} %a, i{width} %b) {{
  %pair = call {{i{width}, i1}} @{name(family, width)}(i{width} %a, i{width} %b)
  ret {{i{width}, i1}} %pair
}}
""")
        bodies.append("""
@counter = global i64 37
@address = global ptr @probe_sadd_64
@alias = alias {i64, i1}(i64, i64), ptr @probe_sadd_64
declare void @unused_declaration(ptr)
define void @unused_cold(i64 %a, i64 %b) cold {
  %pair = call {i64, i1} @llvm.sadd.with.overflow.i64(i64 %a, i64 %b)
  store volatile i64 %a, ptr @counter, align 8
  ret void
}
""")
        expected.update(("unused_declaration", "unused_cold"))
        for triple in TRIPLES:
            for module in self.roundtrip("".join(bodies), triple):
                self.assertEqual({fn["name"] for fn in module["functions"]}, expected)
                self.assertEqual(len(module["functions"]), 770)
                self.assertEqual({g["name"] for g in module["globals"]}, {"counter", "address"})
                self.assertEqual(module["globals"][1]["initializer"]["relocations"][0]["symbol"], "probe_sadd_64")
                self.assertEqual(module["aliases"][0]["name"], "alias")
                self.assertEqual(module["aliases"][0]["aliasee"], "probe_sadd_64")
                for family in FAMILIES:
                    for width in range(1, 65):
                        self.assert_declaration(module, family, width)
                        function = self.function(module, f"probe_{family}_{width}")
                        instruction, = self.instructions(function)
                        self.assertEqual(instruction["operation"], {"op": "integer_overflow", "kind": family[1:],
                            "signed": family[0] == "s", "lhs": {"kind": "value", "id": function["params"][0]["id"]},
                            "rhs": {"kind": "value", "id": function["params"][1]["id"]}})
                        self.assertEqual(instruction["result"]["ty"], function["signature"]["result"])
                        self.assertEqual(function["blocks"][0]["terminator"]["value"],
                                         {"kind": "value", "id": instruction["result"]["id"]})
                self.assertEqual([op["op"] for op in self.operations(self.function(module, "unused_cold"))],
                                 ["integer_overflow", "store"])
                self.assertTrue(self.operations(self.function(module, "unused_cold"))[1]["volatile"])
                self.assertIsNone(self.function(module, "unused_declaration")["entry"])

    def test_all_384_unused_exact_declarations_are_retained_without_native_helper_bodies_all_three_isas(self):
        body = "".join(declaration(family, width) for family in FAMILIES for width in range(1, 65))
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assertEqual(len(module["functions"]), 384)
                self.assertEqual(module["globals"], [])
                self.assertEqual(module["aliases"], [])
                for family in FAMILIES:
                    for width in range(1, 65):
                        self.assert_declaration(module, family, width)

    def test_constant_operand_order_and_twos_complement_bits_are_retained_without_folding_or_overflow_flags(self):
        body = "".join(declaration(family, width) for family in FAMILIES for width in (1, 7, 33, 64))
        for family in FAMILIES:
            for width in (1, 7, 33, 64):
                body += f"define void @constant_{family}_{width}() {{ %p = call {{i{width}, i1}} @{name(family, width)}(i{width} -1, i{width} 1)\nret void }}\n"
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                for family in FAMILIES:
                    for width in (1, 7, 33, 64):
                        op, = self.operations(self.function(module, f"constant_{family}_{width}"))
                        self.assertEqual(op["kind"], family[1:])
                        self.assertEqual(op["signed"], family[0] == "s")
                        self.assertEqual(op["lhs"]["bits"], str((1 << width) - 1))
                        self.assertEqual(op["rhs"]["bits"], "1")
                        self.assertEqual(module["types"][op["lhs"]["ty"]], {"kind": "int", "bits": width})
                        self.assertNotIn("flags", op)

    def test_overflow_pair_phi_select_freeze_insert_extract_and_memory_keep_full_ssa_graph_and_effect_order(self):
        body = declaration("sadd", 7) + declaration("usub", 7) + """
@slot = global {i7, i1} zeroinitializer
define i7 @flow(i7 %a, i7 %b, i1 %pick) {
entry:
  %left = call {i7, i1} @llvm.sadd.with.overflow.i7(i7 %a, i7 %b)
  %flag = extractvalue {i7, i1} %left, 1
  br i1 %flag, label %bad, label %good
bad:
  %right = call {i7, i1} @llvm.usub.with.overflow.i7(i7 %b, i7 %a)
  br label %merge
good:
  br label %merge
merge:
  %pair = phi {i7, i1} [%right, %bad], [%left, %good]
  %choice = select i1 %pick, {i7, i1} %pair, {i7, i1} zeroinitializer
  %stable = freeze {i7, i1} %choice
  %patched = insertvalue {i7, i1} %stable, i7 %a, 0
  store {i7, i1} %patched, ptr @slot, align 1
  %loaded = load {i7, i1}, ptr @slot, align 1
  %value = extractvalue {i7, i1} %loaded, 0
  ret i7 %value
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                fn = self.function(module, "flow")
                ops = self.operations(fn)
                self.assertEqual([op["op"] for op in ops], ["integer_overflow", "extract_value", "integer_overflow",
                    "phi", "select", "freeze", "insert_value", "store", "load", "extract_value"])
                self.assertEqual([op["indices"] for op in ops if op["op"] == "extract_value"], [[1], [0]])
                self.assertEqual({edge["block"] for edge in ops[3]["incoming"]}, {1, 2})
                self.assertEqual(ops[4]["on_false"]["kind"], "aggregate_zero")
                self.assertEqual(ops[7]["pointer"], {"kind": "symbol", "ty": ops[7]["pointer"]["ty"], "name": "slot"})
                self.assertEqual(fn["blocks"][0]["terminator"]["op"], "branch")

    def test_poison_and_undef_operands_and_pair_freeze_stay_explicit_without_source_value_choices(self):
        body = "".join(declaration(family, 8) for family in FAMILIES)
        for family in FAMILIES:
            for category in ("poison", "undef"):
                body += f"define {{i8, i1}} @{family}_{category}() {{ %p = call {{i8, i1}} @{name(family, 8)}(i8 {category}, i8 3)\n%stable = freeze {{i8, i1}} %p\nret {{i8, i1}} %stable }}\n"
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                for family in FAMILIES:
                    for category in ("poison", "undef"):
                        instructions = self.instructions(self.function(module, family + "_" + category))
                        self.assertEqual([i["operation"]["op"] for i in instructions], ["integer_overflow", "freeze"])
                        self.assertEqual(instructions[0]["operation"]["lhs"]["kind"], category)
                        self.assertEqual(module["types"][instructions[0]["operation"]["lhs"]["ty"]],
                                         {"kind": "int", "bits": 8})
                        self.assertEqual(instructions[1]["operation"]["value"]["id"], instructions[0]["result"]["id"])

    def test_pinned_parser_intrinsic_upgrades_keep_original_sha_and_canonical_contract_with_explicit_packed_reconstruction(self):
        # LLParser/BitcodeReader invoke AutoUpgrade: named/packed intrinsic
        # results become literal unpacked structs, manglings are canonicalized,
        # and intrinsic declaration attributes are replaced by intrinsic attrs.
        # Check the verified parsed boundary rather than rejecting raw tokens.
        bodies = [
            "%Pair = type {i8, i1}\ndeclare %Pair @llvm.sadd.with.overflow.i8(i8, i8)\ndefine %Pair @entry(i8 %a, i8 %b) { %p = call %Pair @llvm.sadd.with.overflow.i8(i8 %a, i8 %b)\nret %Pair %p }\n",
            "declare <{i8, i1}> @llvm.sadd.with.overflow.i8(i8, i8)\ndefine <{i8, i1}> @entry(i8 %a, i8 %b) { %p = call <{i8, i1}> @llvm.sadd.with.overflow.i8(i8 %a, i8 %b)\nret <{i8, i1}> %p }\n",
            "declare {i8, i1} @llvm.sadd.with.overflow.i08(i8, i8)\n",
            "declare {i8, i1} @llvm.sadd.with.overflow.i8(i8 signext, i8 zeroext)\n",
        ]
        for triple in TRIPLES:
            for body in bodies:
                for module in self.roundtrip(body, triple):
                    self.assert_declaration(module, "sadd", 8)
                    self.assertNotIn("llvm.sadd.with.overflow.i08", {fn["name"] for fn in module["functions"]})
                    if "@entry" in body:
                        function = self.function(module, "entry")
                        instructions = self.instructions(function)
                        self.assertEqual(instructions[0]["operation"]["op"], "integer_overflow")
                        self.assertFalse(module["types"][instructions[0]["result"]["ty"]]["packed"])
                        self.assertEqual([op["op"] for op in self.operations(function)],
                                         ["integer_overflow", "extract_value", "insert_value", "extract_value", "insert_value"])
                        self.assertEqual(module["types"][function["signature"]["result"]]["packed"], "<{" in body)

    def test_verified_unused_bad_signatures_and_bad_packed_flag_shape_reject_in_import_all_three_isas(self):
        intrinsic = name("sadd", 8)
        bad = [f"declare i8 @{intrinsic}(i8, i8)\n", f"declare {{i8, i8}} @{intrinsic}(i8, i8)\n",
               f"declare <{{i8, i8}}> @{intrinsic}(i8, i8)\n", f"declare {{i8, i1}} @{intrinsic}(i7, i7)\n",
               f"declare {{i8, i1}} @{intrinsic}(i8)\n", f"declare {{i8, i1}} @{intrinsic}(i8, i8, ...)\n",
               f"declare {{i7, i1}} @{intrinsic}(i8, i8)\n"]
        for triple in TRIPLES:
            for body in bad:
                with self.subTest(triple=triple, body=body):
                    self.reject(body, triple, symbol=intrinsic)

    def test_called_bad_signatures_and_intrinsic_definitions_fail_actual_llvm_verification_all_three_isas(self):
        intrinsic = name("sadd", 8)
        cases = [("i8", "i8, i8", "i8 1, i8 2"), ("{i8, i8}", "i8, i8", "i8 1, i8 2"),
                 ("{i8, i1}", "i7, i7", "i7 1, i7 2"), ("{i8, i1}", "i8", "i8 1")]
        for triple in TRIPLES:
            for result, params, args in cases:
                body = f"declare {result} @{intrinsic}({params})\ndefine {result} @entry() {{ %p = call {result} @{intrinsic}({args})\nret {result} %p }}\n"
                self.reject(body, triple, stage="llvm-verify", binary=False)
            self.reject(f"define {{i8, i1}} @{intrinsic}(i8 %a, i8 %b) {{ ret {{i8, i1}} zeroinitializer }}\n",
                        triple, stage="llvm-verify", binary=False)

    def test_llvm_valid_wide_vector_saturation_and_unknown_families_remain_unsupported_whole_units(self):
        bodies = [declaration("umul", 65), declaration("smul", 128),
                  "declare {<2 x i8>, <2 x i1>} @llvm.uadd.with.overflow.v2i8(<2 x i8>, <2 x i8>)\n",
                  "declare i8 @llvm.sadd.sat.i8(i8, i8)\n",
                  "declare {i8, i1} @llvm.sdiv.with.overflow.i8(i8, i8)\n"]
        for triple in TRIPLES:
            for body in bodies:
                self.reject(body, triple)

    def test_exact_owned_c_visibility_and_no_abi_extension_rules_apply_to_declarations_and_calls(self):
        intrinsic = name("sadd", 8)
        bodies = [f"declare {qualifier} {{i8, i1}} @{intrinsic}(i8, i8)\n" for qualifier in
                  ("hidden", "protected", "extern_weak", "fastcc")]
        bodies += [declaration("sadd", 8) + f"define {{i8, i1}} @entry(i8 %a, i8 %b) {{ %p = call {cc} {{i8, i1}} @{intrinsic}(i8 {attribute}%a, i8 %b)\nret {{i8, i1}} %p }}\n"
                   for cc, attribute in (("fastcc", ""), ("", "signext "), ("", "zeroext "))]
        for triple in TRIPLES:
            for body in bodies:
                self.reject(body, triple)

    def test_callsite_bundles_musttail_security_unwind_and_unknown_metadata_are_not_hidden_by_overflow_lowering(self):
        intrinsic = name("sadd", 8)
        calls = [f"call {{i8, i1}} @{intrinsic}(i8 %a, i8 %b)" + suffix for suffix in
                 (' [ "deopt"() ]', " sanitize_memory", " uwtable", ' "overflow-unknown"="1"', ", !overflow.extra !0")]
        calls.append(f"musttail call {{i8, i1}} @{intrinsic}(i8 %a, i8 %b)")
        for triple in TRIPLES:
            for call in calls:
                body = declaration("sadd", 8) + f"define {{i8, i1}} @entry(i8 %a, i8 %b) {{ %p = {call}\nret {{i8, i1}} %p }}\n!0 = !{{i32 1}}\n"
                self.reject(body, triple, symbol="entry")

    def test_intrinsic_addresses_relocations_aliases_and_indirect_escapes_fail_llvm_verification(self):
        intrinsic = name("sadd", 8)
        bodies = [f"@address = global ptr @{intrinsic}\n", f"@alias = alias {{i8, i1}}(i8, i8), ptr @{intrinsic}\n",
                  f"define ptr @address() {{ ret ptr @{intrinsic} }}\n",
                  f"define ptr @address() {{ ret ptr getelementptr (i8, ptr @{intrinsic}, i64 4) }}\n",
                  f"define {{i8, i1}} @entry(i1 %pick) {{ %f = select i1 %pick, ptr @{intrinsic}, ptr null\n%p = call {{i8, i1}} %f(i8 1, i8 2)\nret {{i8, i1}} %p }}\n"]
        for triple in TRIPLES:
            for body in bodies:
                self.reject(declaration("sadd", 8) + body, triple, stage="llvm-verify", binary=False)

    def test_parser_required_nocreateundeforpoison_realization_is_scoped_to_owned_overflow_function_and_callsite(self):
        intrinsic = name("sadd", 8)
        body = declaration("sadd", 8) + f"define {{i8, i1}} @entry(i8 %a, i8 %b) {{ %p = call {{i8, i1}} @{intrinsic}(i8 %a, i8 %b) nocreateundeforpoison\nret {{i8, i1}} %p }}\n"
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                notes = module["provenance"]["refinements"]
                self.assertTrue(any(intrinsic + ": function nocreateundeforpoison=0 realized" in n for n in notes))
                self.assertTrue(any("entry: callsite nocreateundeforpoison=0 realized" in n for n in notes))
                self.assertEqual(self.operations(self.function(module, "entry"))[0]["op"], "integer_overflow")
            self.reject("declare i8 @ordinary(i8) nocreateundeforpoison\n", triple, symbol="ordinary")
            self.reject(declaration("sadd", 8) + f"define {{i8, i1}} @entry() {{ %p = call {{i8, i1}} @{intrinsic}(i8 1, i8 2) \"nocreateundeforpoison\"\nret {{i8, i1}} %p }}\n", triple)

    def test_ordinary_named_alias_and_indirect_pair_calls_remain_calls_with_original_dependencies(self):
        body = declaration("sadd", 8) + """
@ordinary_alias = alias {i8, i1}(i8, i8), ptr @ordinary
declare void @observe(i8)
define {i8, i1} @ordinary(i8 %a, i8 %b) {
  call void @observe(i8 %a)
  %p = insertvalue {i8, i1} zeroinitializer, i8 %a, 0
  ret {i8, i1} %p
}
define {i8, i1} @entry(ptr %function, i8 %a, i8 %b) {
  %p = call {i8, i1} %function(i8 %a, i8 %b)
  %q = call {i8, i1} @ordinary_alias(i8 %b, i8 %a)
  ret {i8, i1} %q
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                entry = self.function(module, "entry")
                calls = self.operations(entry)
                self.assertEqual([op["op"] for op in calls], ["call", "call"])
                self.assertEqual(calls[0]["callee"], {"kind": "value", "id": entry["params"][0]["id"]})
                self.assertEqual(calls[1]["callee"]["name"], "ordinary_alias")
                self.assertEqual(self.operations(self.function(module, "ordinary"))[0]["callee"]["name"], "observe")

    def test_unknown_named_metadata_and_unused_tls_global_still_reject_complete_overflow_modules(self):
        for triple in TRIPLES:
            self.reject(declaration("sadd", 8) + "!overflow.publication = !{!0}\n!0 = !{i32 1}\n", triple)
            self.reject(declaration("sadd", 8) + "@unused_tls = thread_local global i64 37\n", triple, symbol="unused_tls")

    @staticmethod
    def clang_source():
        return '''long retained_global = 37;
int checked_sadd(long a,long b,long *out) { return __builtin_saddl_overflow(a,b,out); }
int checked_uadd(unsigned long a,unsigned long b,unsigned long *out) { return __builtin_uaddl_overflow(a,b,out); }
int checked_ssub(long a,long b,long *out) { return __builtin_ssubl_overflow(a,b,out); }
int checked_usub(unsigned long a,unsigned long b,unsigned long *out) { return __builtin_usubl_overflow(a,b,out); }
int checked_smul(long a,long b,long *out) { return __builtin_smull_overflow(a,b,out); }
int checked_umul(unsigned long a,unsigned long b,unsigned long *out) { return __builtin_umull_overflow(a,b,out); }
int unused_checked(long a,long b,long *out) { return __builtin_saddl_overflow(a,b,out); }
'''

    @staticmethod
    def rust_source():
        source = '''#![no_std]
#[repr(C)] pub struct Signed { pub value:i64, pub overflow:u8 }
#[repr(C)] pub struct Unsigned { pub value:u64, pub overflow:u8 }
#[no_mangle] pub static RETAINED_GLOBAL:u64 = 37;
'''
        for prefix, ty, pair in (("s", "i64", "Signed"), ("u", "u64", "Unsigned")):
            for operation in ("add", "sub", "mul"):
                source += f'#[no_mangle] pub extern "C" fn checked_{prefix}{operation}(a:{ty},b:{ty})->{pair} {{ let (value,overflow)=a.overflowing_{operation}(b); {pair} {{ value,overflow:overflow as u8 }} }}\n'
        return source + '#[no_mangle] pub extern "C" fn unused_checked(a:i64,b:i64)->Signed { let(value,overflow)=a.overflowing_add(b); Signed { value,overflow:overflow as u8 } }\n'

    def test_actual_clang22_complete_c_cpp_units_keep_all_six_intrinsics_stores_and_unused_inventory_all_three_isas_ll_bc(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        expected = {"checked_" + f for f in FAMILIES} | {"unused_checked"}
        for cpp in (False, True):
            source = self.directory / ("whole-overflow.cpp" if cpp else "whole-overflow.c")
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
                    self.assertEqual({f["name"] for f in module["functions"] if f["entry"] is not None}, expected)
                    self.assertEqual({f["intrinsic"] for f in module["functions"] if f["intrinsic"]}, {name(f, 64) for f in FAMILIES})
                    self.assertEqual({g["name"] for g in module["globals"]}, {"retained_global"})
                    for family in FAMILIES:
                        self.assert_declaration(module, family, 64)
                        ops = self.operations(self.function(module, "checked_" + family))
                        overflow, = [op for op in ops if op["op"] == "integer_overflow"]
                        self.assertEqual((overflow["kind"], overflow["signed"]), (family[1:], family[0] == "s"))
                        self.assertEqual(sum(op["op"] == "store" for op in ops), 1)
                        self.assertCountEqual([op["indices"] for op in ops if op["op"] == "extract_value"], [[0], [1]])
                        instructions = self.instructions(self.function(module, "checked_" + family))
                        wrapped = next(inst for inst in instructions if inst["operation"]["op"] == "extract_value"
                                       and inst["operation"]["indices"] == [0])
                        store = next(op for op in ops if op["op"] == "store")
                        self.assertEqual(store["value"], {"kind": "value", "id": wrapped["result"]["id"]})
                    if suffix == "ll":
                        names = set(re.findall(r'^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(', path.read_text(), re.MULTILINE))
                        self.assertEqual({f["name"] for f in module["functions"]}, names)
                self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(source.read_bytes(), original)

    def test_actual_rust1971_complete_pair_units_keep_emitted_intrinsics_arithmetic_coercions_and_lp64d_all_three_isas_ll_bc(self):
        rustc, version = self.rust_compiler()
        source = self.directory / "whole-overflow.rs"
        source.write_text(self.rust_source())
        original = source.read_bytes()
        # Rust optimizes unsigned addition/subtraction to arithmetic+compare;
        # these whole producer units establish exactly the four emitted families.
        families = {"sadd", "ssub", "smul", "umul"}
        expected = {"checked_" + f for f in FAMILIES} | {"unused_checked"}
        for target, triple in ((TRIPLES[0], TRIPLES[0]), (TRIPLES[1], TRIPLES[1]), ("riscv64gc-unknown-linux-gnu", TRIPLES[2])):
            modules = []
            for suffix in ("ll", "bc"):
                path = self.rust_compile(rustc, source, target, suffix)
                module = importer.import_module(path, library_path=self.library, frontend="Rust", frontend_version=version)
                self.record_import(path, module=module)
                self.assert_original(module, path, triple)
                modules.append(module)
                self.assertEqual({f["name"] for f in module["functions"] if f["entry"] is not None}, expected)
                self.assertEqual({f["intrinsic"] for f in module["functions"] if f["intrinsic"]}, {name(f, 64) for f in families})
                self.assertEqual({g["name"] for g in module["globals"]}, {"RETAINED_GLOBAL"})
                self.assertEqual(module["target"].get("abi"), "lp64d" if triple.startswith("riscv64") else None)
                for family in families:
                    self.assert_declaration(module, family, 64)
                    overflow, = [op for op in self.operations(self.function(module, "checked_" + family)) if op["op"] == "integer_overflow"]
                    self.assertEqual((overflow["kind"], overflow["signed"]), (family[1:], family[0] == "s"))
                for family in ("uadd", "usub"):
                    ops = self.operations(self.function(module, "checked_" + family))
                    self.assertTrue(any(op["op"] == "binary" and op["kind"] == family[1:] for op in ops))
                    self.assertTrue(any(op["op"] == "i_cmp" for op in ops))
                self.assertEqual(module["types"][self.function(module, "checked_sadd")["signature"]["result"]]["kind"],
                                 "struct" if triple == TRIPLES[0] else "array")
                if suffix == "ll":
                    names = set(re.findall(r'^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(', path.read_text(), re.MULTILINE))
                    self.assertEqual({f["name"] for f in module["functions"]}, names)
            self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        self.assertEqual(source.read_bytes(), original)

    def test_actual_whole_c_cpp_rust_overflow_units_reject_retained_unused_float_without_partial_import_all_three_isas_ll_bc(self):
        clang, clang_version = baseline.LlvmImportTests.clang22_frontend(self)
        rustc, rust_version = self.rust_compiler()
        for language in ("c", "cpp", "rust"):
            source = self.directory / ("whole-overflow-negative." + {"c": "c", "cpp": "cpp", "rust": "rs"}[language])
            code = self.rust_source() + '#[no_mangle] pub extern "C" fn unsupported_float(value:u64)->f64 { value as f64 }\n' if language == "rust" else self.clang_source() + "double unsupported_float(unsigned long value) { return (double)value; }\n"
            source.write_text('extern "C" {\n' + code + '}\n' if language == "cpp" else code)
            original = source.read_bytes()
            for triple in TRIPLES:
                for suffix in ("ll", "bc"):
                    target = "riscv64gc-unknown-linux-gnu" if language == "rust" and triple.startswith("riscv64") else triple
                    path = self.rust_compile(rustc, source, target, suffix) if language == "rust" else self.clang_compile(clang, source, triple, suffix, language == "cpp")
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(path, library_path=self.library, frontend=language,
                                               frontend_version=rust_version if language == "rust" else clang_version)
                    self.record_import(path, error=raised.exception)
                    self.assertEqual(raised.exception.stage, "import")
                    self.assertEqual(raised.exception.symbol, "unsupported_float")
                    self.assertIn("unsupported LLVM type kind", str(raised.exception))
            self.assertEqual(source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
