"""Typed struct/array SSA conformance and unsupported payload boundaries.

Every original unit is imported whole. Source tests retain volatile aggregate
flags for the mandatory native backend audit; they do not claim those accesses
have an admitted native realization or execute generated programs.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory


TRIPLES = baseline.TRIPLES


class LlvmAggregateImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-aggregate-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    write = memory.LlvmMemoryImportTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)

    @staticmethod
    def realization(module):
        return {key: value for key, value in module.items() if key not in {"name", "provenance"}}

    @classmethod
    def shape(cls, module, ident):
        ty = module["types"][ident]
        if ty["kind"] == "struct":
            return {"kind": "struct", "packed": ty["packed"], "fields": [cls.shape(module, child) for child in ty["fields"]]}
        if ty["kind"] == "array":
            return {"kind": "array", "len": ty["len"], "element": cls.shape(module, ty["element"])}
        return ty

    def assert_original(self, module, path, triple):
        self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(module["target"]["triple"], triple)
        self.assertEqual(module["provenance"]["source_function_count"], len(module["functions"]))
        self.assertEqual(module["provenance"]["source_global_count"], len(module["globals"]))
        self.assertEqual(module["provenance"]["source_alias_count"], len(module["aliases"]))
        for function in module["functions"]:
            signatures = [function["signature"]] + [op["signature"] for op in self.operations(function) if op["op"] == "call"]
            for signature in signatures:
                self.assertEqual(signature["abi"], "c")
                self.assertFalse(signature["variadic"])
                self.assertIn(module["types"][signature["result"]]["kind"], {"void", "int", "pointer"})
                for parameter in signature["params"]:
                    self.assertIn(module["types"][parameter]["kind"], {"int", "pointer"})

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

    def reject_verified(self, body, triple, diagnostic=None, symbol=None):
        source = self.write(body, triple)
        for path in (source, self.bitcode(source)):
            with self.subTest(triple=triple, format=path.suffix, body=body):
                with self.assertRaises(importer.ImportFailure) as raised:
                    importer.import_module(path, library_path=self.library)
                self.assertEqual(raised.exception.stage, "import")
                if diagnostic:
                    self.assertIn(diagnostic, str(raised.exception))
                if symbol:
                    self.assertEqual(raised.exception.symbol, symbol)

    def assert_constant_tree(self, module, constant, expected=None):
        self.assertNotEqual(constant["kind"], "value", "literal aggregates cannot hide SSA construction")
        self.assertIn("ty", constant)
        if expected is not None:
            self.assertEqual(constant["ty"], expected)
        ty = module["types"][constant["ty"]]
        if constant["kind"] == "aggregate":
            children = ty["fields"] if ty["kind"] == "struct" else [ty["element"]] * ty["len"]
            self.assertEqual(len(constant["elements"]), len(children))
            for child, child_type in zip(constant["elements"], children):
                self.assert_constant_tree(module, child, child_type)
        elif constant["kind"] == "aggregate_zero":
            self.assertIn(ty["kind"], {"struct", "array"})
            self.assertEqual(set(constant), {"kind", "ty"})

    def test_nested_named_packed_struct_array_insert_extract_paths_keep_scalar_signatures_and_full_inventory_all_three_isas(self):
        body = """
%R = type <{i8, [2 x {i21, ptr}], i33}>
@leaf = global i8 3
@leaf_alias = alias i8, ptr @leaf
@address = global ptr @leaf_alias
declare void @unused(ptr)
declare void @observe(i21)
define void @build(ptr %out, i21 %number, ptr %pointer) {
  %a = insertvalue %R poison, i8 11, 0
  %b = insertvalue %R %a, i21 %number, 1, 1, 0
  %c = insertvalue %R %b, ptr %pointer, 1, 1, 1
  %d = insertvalue %R %c, i33 -1, 2
  store %R %d, ptr %out, align 1
  %e = extractvalue %R %d, 1, 1
  %f = extractvalue {i21, ptr} %e, 0
  call void @observe(i21 %f)
  ret void
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assertEqual({fn["name"] for fn in module["functions"]}, {"build", "observe", "unused"})
                self.assertEqual({g["name"] for g in module["globals"]}, {"leaf", "address"})
                self.assertEqual(module["aliases"][0]["name"], "leaf_alias")
                self.assertIsNone(self.function(module, "unused")["entry"])
                function = self.function(module, "build")
                instructions = self.instructions(function)
                ops = self.operations(function)
                self.assertEqual([op["op"] for op in ops], ["insert_value"] * 4 + ["store", "extract_value", "extract_value", "call"])
                self.assertEqual([op["indices"] for op in ops if "indices" in op], [[0], [1, 1, 0], [1, 1, 1], [2], [1, 1], [0]])
                aggregate_ty = instructions[0]["result"]["ty"]
                self.assertTrue(module["types"][aggregate_ty]["packed"])
                self.assertEqual(ops[0]["aggregate"], {"kind": "poison", "ty": aggregate_ty})
                self.assertEqual(ops[3]["value"]["bits"], str((1 << 33) - 1))
                self.assertEqual(module["types"][instructions[5]["result"]["ty"]]["kind"], "struct")
                self.assertEqual(module["types"][instructions[6]["result"]["ty"]], {"kind": "int", "bits": 21})
                self.assertEqual(ops[-1]["callee"]["name"], "observe")
                address = next(g for g in module["globals"] if g["name"] == "address")
                self.assertEqual(address["initializer"]["relocations"][0]["symbol"], "leaf_alias")

    def test_recursive_constant_only_aggregate_children_preserve_poison_undef_symbols_offsets_pointer_bits_and_types_all_three_isas(self):
        body = """
@data = global [8 x i8] zeroinitializer
@data_alias = alias [8 x i8], ptr @data
define i7 @constant() {
  %a = freeze {i7, [2 x {ptr, i33}], i1} {i7 -1, [2 x {ptr, i33}] [{ptr, i33} {ptr getelementptr(i8, ptr @data_alias, i64 3), i33 poison}, {ptr, i33} {ptr inttoptr(i7 127 to ptr), i33 undef}], i1 true}
  %b = extractvalue {i7, [2 x {ptr, i33}], i1} %a, 0
  ret i7 %b
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                constant = self.operations(self.function(module, "constant"))[0]["value"]
                self.assert_constant_tree(module, constant)
                self.assertEqual(constant["kind"], "aggregate")
                self.assertEqual(constant["elements"][0]["bits"], "127")
                pairs = constant["elements"][1]["elements"]
                self.assertEqual(pairs[0]["elements"][0]["kind"], "symbol_offset")
                self.assertEqual(pairs[0]["elements"][0]["name"], "data_alias")
                self.assertEqual(pairs[0]["elements"][0]["addend"], 3)
                self.assertEqual(pairs[0]["elements"][1]["kind"], "poison")
                self.assertEqual(pairs[1]["elements"][0]["kind"], "pointer_bits")
                self.assertEqual(pairs[1]["elements"][0]["bits"], "127")
                self.assertEqual(pairs[1]["elements"][1]["kind"], "undef")

    def test_zero_empty_and_large_aggregate_constants_remain_compact_without_materialized_padding_or_children_all_three_isas(self):
        body = """
define void @zeros(ptr %out) {
  store {} zeroinitializer, ptr %out, align 1
  store [0 x i7] zeroinitializer, ptr %out, align 1
  store [4294967296 x i8] zeroinitializer, ptr %out, align 1
  store {i7, [3 x ptr], i33} zeroinitializer, ptr %out, align 1
  ret void
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                constants = [op["value"] for op in self.operations(self.function(module, "zeros"))]
                for constant in constants:
                    self.assertEqual(constant["kind"], "aggregate_zero")
                    self.assert_constant_tree(module, constant)
                self.assertEqual(module["types"][constants[2]["ty"]]["len"], 1 << 32)
                self.assertEqual(len(module["types"][constants[3]["ty"]]["fields"]), 3)
                self.assertNotIn("elements", constants[2])

    def test_loop_carried_array_phi_keeps_forward_ssa_identity_and_exact_predecessors_all_three_isas(self):
        body = """
define i7 @loop() {
entry: br label %loop
loop:
  %aggregate = phi [2 x i7] [[i7 1, i7 2], %entry], [%next, %body]
  %number = extractvalue [2 x i7] %aggregate, 0
  %continue = icmp eq i7 %number, 1
  br i1 %continue, label %body, label %done
body:
  %next = insertvalue [2 x i7] %aggregate, i7 4, 0
  br label %loop
done: ret i7 %number
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                function = self.function(module, "loop")
                phi = function["blocks"][1]["instructions"][0]
                update = function["blocks"][2]["instructions"][0]
                incoming = phi["operation"]["incoming"]
                self.assertEqual([edge["block"] for edge in incoming], [0, 2])
                self.assert_constant_tree(module, incoming[0]["value"])
                self.assertEqual(incoming[1]["value"], {"kind": "value", "id": update["result"]["id"]})
                self.assertEqual(update["operation"]["aggregate"], {"kind": "value", "id": phi["result"]["id"]})
                self.assertEqual(phi["result"]["ty"], update["result"]["ty"])

    def test_duplicate_phi_edges_coalesce_only_identical_recursive_constant_values_all_three_isas(self):
        body = """
define i7 @duplicate(i1 %condition) {
entry: br i1 %condition, label %merge, label %merge
merge:
  %a = phi {i7, [2 x i7]} [{i7 1, [2 x i7] [i7 2, i7 3]}, %entry], [{i7 1, [2 x i7] [i7 2, i7 3]}, %entry]
  %b = extractvalue {i7, [2 x i7]} %a, 1, 1
  ret i7 %b
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                incoming = self.operations(self.function(module, "duplicate"))[0]["incoming"]
                self.assertEqual(len(incoming), 1)
                self.assert_constant_tree(module, incoming[0]["value"])
                self.assertEqual(incoming[0]["value"]["elements"][1]["elements"][1]["bits"], "3")
                self.assertIn("duplicate: duplicate CFG edges with identical PHI values coalesced", module["provenance"]["refinements"])

    def test_select_freeze_and_extract_preserve_typed_undef_poison_and_aggregate_elementwise_contract_all_three_isas(self):
        body = """
define i7 @choose(i1 %condition) {
  %a = freeze {i7, ptr} undef
  %b = select i1 %condition, {i7, ptr} %a, {i7, ptr} poison
  %c = freeze {i7, ptr} %b
  %d = extractvalue {i7, ptr} %c, 0
  ret i7 %d
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                ops = self.operations(self.function(module, "choose"))
                self.assertEqual([op["op"] for op in ops], ["freeze", "select", "freeze", "extract_value"])
                self.assertEqual(ops[0]["value"]["kind"], "undef")
                self.assertEqual(ops[1]["on_false"]["kind"], "poison")
                self.assertEqual(ops[0]["value"]["ty"], ops[1]["on_false"]["ty"])
                refinement = "\n".join(module["provenance"]["refinements"])
                self.assertIn("element-wise freeze", refinement)
                self.assertIn("padding is not an SSA field", refinement)
                self.assertIn("native aggregate C/fastcc ABI classification remains mandatory", refinement)

    def test_original_datalayout_allocation_stride_leaf_store_footprints_and_padding_are_preserved_in_aggregate_memory_all_three_isas(self):
        body = """
%R = type {i8, [2 x i17], i33, ptr}
@leaf = global i8 5
@record = global %R {i8 7, [2 x i17] [i17 -1, i17 2], i33 -1, ptr @leaf}
define i17 @memory(ptr %out) {
  %a = load %R, ptr @record, align 8
  store %R %a, ptr %out, align 1
  %b = extractvalue %R %a, 1, 0
  ret i17 %b
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                record = next(g for g in module["globals"] if g["name"] == "record")
                self.assertEqual(len(module["types"][record["ty"]]["fields"]), 4)
                expected = bytearray(32)
                expected[0] = 7
                expected[4:7] = ((1 << 17) - 1).to_bytes(3, "little")
                expected[8:11] = (2).to_bytes(3, "little")
                expected[16:21] = ((1 << 33) - 1).to_bytes(5, "little")
                self.assertEqual(record["initializer"]["bytes"], list(expected))
                self.assertEqual(record["initializer"]["relocations"], [{"offset": 24, "width": 64, "symbol": "leaf", "addend": 0}])
                ops = self.operations(self.function(module, "memory"))
                self.assertEqual([op["op"] for op in ops], ["load", "store", "extract_value"])
                self.assertEqual([ops[0]["alignment"], ops[1]["alignment"]], [8, 1])
                self.assertFalse(ops[0]["volatile"] or ops[1]["volatile"])
                self.assertEqual(ops[2]["indices"], [1, 0])

    def test_volatile_aggregate_flags_are_retained_for_mandatory_native_backend_rejection_without_source_admission_claim(self):
        body = "define i7 @volatile_memory(ptr %in, ptr %out) { %a = load volatile {i7,i64}, ptr %in, align 1\nstore volatile {i7,i64} %a, ptr %out, align 1\n%b = extractvalue {i7,i64} %a, 0\nret i7 %b }\n"
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                ops = self.operations(self.function(module, "volatile_memory"))
                self.assertEqual([op["op"] for op in ops], ["load", "store", "extract_value"])
                self.assertTrue(ops[0]["volatile"] and ops[1]["volatile"])
                self.assertEqual(ops[0]["alignment"], 1)
                # This intentionally stops at source import. The native target
                # audit owns rejection of this target-specific access contract.

    def test_unsupported_wide_aggregate_definitions_unused_declarations_direct_alias_and_indirect_abi_boundaries_reject_all_three_isas(self):
        cases = [
            "declare {i7, i65} @unsupported()",
            "declare void @unsupported({i7, i65})",
            "define {i7, i65} @unsupported() { ret {i7, i65} zeroinitializer }",
            "define i7 @unsupported([2 x i65] %value) { %r = extractvalue [2 x i65] %value, 0\nret i7 7 }",
            "define void @unsupported(ptr %function) { %r = call {i7, i65} %function()\nret void }",
            "define void @unsupported(ptr %function) { call void %function({i7, i65} zeroinitializer)\nret void }",
            "@alias = alias {i7, i65}(), ptr @unsupported\ndefine {i7, i65} @unsupported() { ret {i7, i65} poison }",
        ]
        for triple in TRIPLES:
            for body in cases:
                self.reject_verified("define i7 @supported() { ret i7 7 }\n" + body + "\n", triple, "unsupported integer width i65", "unsupported")

    def test_dead_unselected_or_poison_aggregate_fields_do_not_hide_float_wide_vector_or_address_space_types_all_three_isas(self):
        for triple in TRIPLES:
            for unsupported, diagnostic in (("double", "unsupported LLVM type kind"), ("i65", "unsupported integer width i65"),
                                            ("<2 x i7>", "unsupported LLVM type kind"), ("ptr addrspace(1)", "unsupported pointer address space 1")):
                body = f"define i7 @unsupported() {{ %unused = extractvalue {{i7, {unsupported}}} poison, 0\nret i7 7 }}\n"
                self.reject_verified(body, triple, diagnostic, "unsupported")

    def test_nested_symbolic_integer_and_blockaddress_constants_remain_rejected_without_hidden_dependency_escape_all_three_isas(self):
        cases = [
            "@data = global i8 0\ndefine i7 @unsupported() { %a = freeze {i7,i64} {i7 1,i64 ptrtoint(ptr @data to i64)}\nret i7 7 }",
            "define void @target() { entry: br label %label\nlabel: ret void }\ndefine i7 @unsupported() { %a = freeze {i7,ptr} {i7 1,ptr blockaddress(@target,%label)}\nret i7 7 }",
        ]
        for triple in TRIPLES:
            for body in cases:
                self.reject_verified(body + "\n", triple, "unsupported constant expression", "unsupported")

    def test_malformed_paths_wrong_child_types_and_ssa_dominance_fail_at_actual_llvm_boundary_all_three_isas(self):
        cases = [
            ("define i7 @unsupported() { %a = extractvalue {i7,[2 x i64]} poison, 1, 2\nret i7 0 }", "parse"),
            ("define i7 @unsupported(i7 %n) { %a = insertvalue {i7,i64} poison, i7 %n, 1\nret i7 0 }", "parse"),
            ("define i7 @unsupported() { %a = extractvalue {i7,i64} poison\nret i7 0 }", "parse"),
            ("define i7 @unsupported() { %a = extractvalue {i7,i64} poison, -1\nret i7 0 }", "parse"),
            ("define i7 @unsupported(i1 %condition) { entry: br i1 %condition,label %left,label %right\nleft: %a = insertvalue {i7,i64} poison,i7 3,0\nbr label %merge\nright: br label %merge\nmerge: %b = extractvalue {i7,i64} %a,0\nret i7 %b }", "llvm-verify"),
        ]
        for triple in TRIPLES:
            for body, stage in cases:
                with self.subTest(triple=triple, body=body):
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(self.write(body + "\n", triple), library_path=self.library)
                    self.assertEqual(raised.exception.stage, stage)

    @staticmethod
    def clang_source():
        return '''typedef unsigned long word;
struct Record { unsigned char tag; word cells[2]; void *pointer; };
struct Record state = { 9, { 11, 13 }, (void *)0 };
void make_record(struct Record *out, word value) {
  struct Record local = { 7, { value, value ^ 37 }, (void *)0 };
  *out = local;
}
word read_record(const struct Record *record) { return record->cells[0] ^ record->cells[1]; }
word scalar(word value) { return value + state.cells[0]; }
'''

    def clang_compile(self, clang, source, triple, suffix, cpp):
        output = self.directory / f"{source.stem}-{triple}.{suffix}"
        flags = (["-x", "c++", "-std=c++17", "-fno-exceptions", "-fno-rtti"] if cpp else ["-x", "c"])
        targets = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
        command = [clang, "--target=" + triple, *targets, *flags, *memory.LlvmMemoryImportTests.clang_flags(),
                   "-S" if suffix == "ll" else "-c", str(source), "-o", str(output)]
        result = subprocess.run(command, cwd=baseline.ROOT, capture_output=True, text=True, timeout=30)
        self.record_producer(command, result, source, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output

    def record_producer(self, command, result, source, output):
        evidence = os.environ.get("OCORE_TEST_AGGREGATE_EVIDENCE")
        if not evidence:
            return
        directory = Path(evidence) / "producers"
        directory.mkdir(parents=True, exist_ok=True)
        stem = source.name + "-" + output.name
        source_copy = directory / (stem + ".source")
        source_copy.write_bytes(source.read_bytes())
        record = {"command": command, "cwd": str(baseline.ROOT), "exit_code": result.returncode,
                  "stdout": result.stdout, "stderr": result.stderr, "source_original": str(source),
                  "source_copy": str(source_copy), "source_sha256": hashlib.sha256(source_copy.read_bytes()).hexdigest()}
        if output.exists():
            output_copy = directory / (stem + ".input")
            output_copy.write_bytes(output.read_bytes())
            record.update({"input_original": str(output), "input_copy": str(output_copy),
                           "input_sha256": hashlib.sha256(output_copy.read_bytes()).hexdigest()})
        (directory / (stem + ".json")).write_text(json.dumps(record, indent=2) + "\n")

    def record_import(self, path, module=None, error=None):
        evidence = os.environ.get("OCORE_TEST_AGGREGATE_EVIDENCE")
        if not evidence:
            return
        directory = Path(evidence) / "imports"
        directory.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if module is not None:
            (directory / (digest + ".module.json")).write_text(json.dumps(module, indent=2) + "\n")
        if error is not None:
            (directory / (digest + ".error.json")).write_text(json.dumps({"input_sha256": digest,
                "error": {"stage": error.stage, "symbol": error.symbol, "message": str(error)}}, indent=2) + "\n")

    def test_actual_clang22_original_c_and_cpp_complete_record_units_keep_whole_inventory_and_memory_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        expected = {"make_record", "read_record", "scalar"}
        for cpp in (False, True):
            source = self.directory / ("whole-record.cpp" if cpp else "whole-record.c")
            code = self.clang_source()
            source.write_text('extern "C" {\n' + code + '}\n' if cpp else code)
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            for triple in TRIPLES:
                modules = []
                for suffix in ("ll", "bc"):
                    path = self.clang_compile(clang, source, triple, suffix, cpp)
                    module = importer.import_module(path, library_path=self.library, frontend="Clang C++" if cpp else "Clang C", frontend_version=version)
                    self.record_import(path, module=module)
                    self.assert_original(module, path, triple)
                    modules.append(module)
                    self.assertEqual({fn["name"] for fn in module["functions"] if fn["entry"] is not None}, expected)
                    self.assertEqual({g["name"] for g in module["globals"]}, {"state"})
                    if suffix == "ll":
                        names = set(re.findall(r'^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(', path.read_text(), re.MULTILINE))
                        self.assertEqual({fn["name"] for fn in module["functions"]}, names)
                    state = module["globals"][0]
                    self.assertEqual(module["types"][state["ty"]]["kind"], "struct")
                    self.assertEqual(state["initializer"]["bytes"][0], 9)
                    self.assertTrue(any(op["op"] == "store" or op["op"] == "memory_copy" for op in self.operations(self.function(module, "make_record"))))
                self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)

    def test_actual_clang22_original_c_and_cpp_complete_units_reject_unused_float_after_retaining_aggregate_body_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        for cpp in (False, True):
            source = self.directory / ("whole-record-bad.cpp" if cpp else "whole-record-bad.c")
            code = self.clang_source() + "struct Small { word first; word second; };\nstruct Small supported_pair(word value) { struct Small result = {value, value ^ 37}; return result; }\ndouble unsupported_pair(word value) { return (double)value; }\n"
            source.write_text('extern "C" {\n' + code + '}\n' if cpp else code)
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            for triple in TRIPLES:
                for suffix in ("ll", "bc"):
                    path = self.clang_compile(clang, source, triple, suffix, cpp)
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(path, library_path=self.library, frontend="Clang C++" if cpp else "Clang C", frontend_version=version)
                    self.assertEqual(raised.exception.stage, "import")
                    self.record_import(path, error=raised.exception)
                    self.assertEqual(raised.exception.symbol, "unsupported_pair")
                    self.assertIn("unsupported LLVM type kind", str(raised.exception))
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)

    @staticmethod
    def rust_typed_read_source():
        return '''#![no_std]
#[repr(C)]
pub struct Record { pub tag: u8, pub cells: [u64; 2], pub pointer: *mut u8 }
#[no_mangle]
pub static mut rust_state: Record = Record { tag: 9, cells: [11,13], pointer: core::ptr::null_mut() };
#[no_mangle]
pub unsafe extern "C" fn rust_make(out: *mut Record, value: u64) {
  *out = Record { tag: 7, cells: [value, value ^ 37], pointer: core::ptr::null_mut() };
}
#[no_mangle]
pub unsafe extern "C" fn rust_read(record: *const Record) -> u64 { (*record).cells[0] ^ (*record).cells[1] }
#[no_mangle]
pub unsafe extern "C" fn rust_scalar(value: u64) -> u64 { value.wrapping_add(rust_state.cells[0]) }
'''

    @staticmethod
    def rust_source():
        # This separately authored storage fixture copies a record rather than
        # reading typed fields. The original typed-read producer unit is kept
        # below to verify its noundef loads and complete original inventory.
        return '''#![no_std]
#[repr(C)]
pub struct Record { pub tag: u8, pub cells: [u64; 2], pub pointer: *mut u8 }
#[no_mangle]
pub static mut rust_state: Record = Record { tag: 9, cells: [11,13], pointer: core::ptr::null_mut() };
#[no_mangle]
pub unsafe extern "C" fn rust_make(out: *mut Record, value: u64) {
  *out = Record { tag: 7, cells: [value, value ^ 37], pointer: core::ptr::null_mut() };
}
#[no_mangle]
pub unsafe extern "C" fn rust_copy(out: *mut Record, record: *const Record) { core::ptr::copy_nonoverlapping(record, out, 1); }
#[no_mangle]
pub extern "C" fn rust_scalar(value: u64) -> u64 { value.wrapping_add(11) }
'''

    def rust_compiler(self):
        override = os.environ.get("OCORE_TEST_RUSTC")
        rustc = Path(override) if override else Path.home() / ".rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin/rustc"
        if not rustc.is_file():
            if override:
                self.fail(f"requested pinned Rust frontend unavailable: {rustc}")
            self.skipTest("pinned Rust 1.97.1 frontend unavailable")
        version = subprocess.check_output([str(rustc), "--version", "--verbose"], text=True, timeout=15)
        self.assertIn("release: 1.97.1", version)
        self.assertIn("LLVM version: 22.1.6", version)
        return rustc, version

    def rust_compile(self, rustc, source, target, suffix):
        output = self.directory / f"{source.stem}-{target}.{suffix}"
        command = [str(rustc), str(source), "--crate-type=lib", "--edition=2021", "--crate-name=aggregate_fixture",
                   "--target=" + target, "--emit=" + ("llvm-ir" if suffix == "ll" else "llvm-bc"),
                   "-Copt-level=1", "-Cpanic=abort", "-Coverflow-checks=no", "-Ccodegen-units=1", "-Crelocation-model=static", "-o", str(output)]
        result = subprocess.run(command, cwd=baseline.ROOT, capture_output=True, text=True, timeout=30)
        self.record_producer(command, result, source, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output

    def test_actual_rust1971_original_whole_record_units_preserve_genuine_llvm_triples_abi_and_inventory_all_three_isas_text_and_bitcode(self):
        rustc, version = self.rust_compiler()
        source = self.directory / "whole-record.rs"
        source.write_text(self.rust_source())
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        targets = ((TRIPLES[0], TRIPLES[0], None), (TRIPLES[1], TRIPLES[1], None), ("riscv64gc-unknown-linux-gnu", TRIPLES[2], "lp64d"))
        for compiler_target, llvm_triple, abi in targets:
            modules = []
            for suffix in ("ll", "bc"):
                path = self.rust_compile(rustc, source, compiler_target, suffix)
                module = importer.import_module(path, library_path=self.library, frontend="Rust", frontend_version=version)
                self.record_import(path, module=module)
                self.assert_original(module, path, llvm_triple)
                modules.append(module)
                self.assertEqual(module["target"].get("abi"), abi)
                self.assertEqual({fn["name"] for fn in module["functions"] if fn["entry"] is not None}, {"rust_make", "rust_copy", "rust_scalar"})
                self.assertEqual({fn["name"] for fn in module["functions"] if fn["entry"] is None}, {"llvm.memcpy.p0.p0.i64"})
                self.assertEqual([op["op"] for op in self.operations(self.function(module, "rust_copy"))], ["memory_copy"])
                self.assertEqual({g["name"] for g in module["globals"]}, {"rust_state"})
                if suffix == "ll":
                    names = set(re.findall(r'^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(', path.read_text(), re.MULTILINE))
                    self.assertEqual({fn["name"] for fn in module["functions"]}, names)
                self.assertEqual(module["globals"][0]["initializer"]["bytes"][0], 9)
            self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)

    def test_actual_original_rust_typed_read_units_preserve_noundef_loads_and_complete_aggregate_abi_all_three_isas_text_and_bitcode(self):
        rustc, version = self.rust_compiler()
        for unused_pair in (False, True):
            source = self.directory / ("whole-typed-read-bad.rs" if unused_pair else "whole-typed-read.rs")
            code = self.rust_typed_read_source()
            if unused_pair:
                code += '''#[repr(C)] pub struct Small { pub first: u64, pub second: u64 }
#[no_mangle] pub extern "C" fn unsupported_pair(value: u64) -> Small { Small { first: value, second: value ^ 37 } }
'''
            source.write_text(code)
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            for target in (TRIPLES[0], TRIPLES[1], "riscv64gc-unknown-linux-gnu"):
                modules = []
                for suffix in ("ll", "bc"):
                    path = self.rust_compile(rustc, source, target, suffix)
                    if suffix == "ll":
                        self.assertIn("!noundef", path.read_text())
                        self.assertIn("@rust_read(", path.read_text())
                        if unused_pair:
                            self.assertIn("@unsupported_pair(", path.read_text())
                    module = importer.import_module(path, library_path=self.library, frontend="Rust", frontend_version=version)
                    self.record_import(path, module=module)
                    modules.append(module)
                    provenance = module["provenance"]
                    self.assertEqual(provenance["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                    self.assertEqual(module["target"]["triple"], TRIPLES[2] if target.startswith("riscv64gc-") else target)
                    for kind in ("function", "global", "alias"):
                        self.assertEqual(provenance[f"source_{kind}_count"], len(module[kind + "es" if kind == "alias" else kind + "s"]))
                    expected = {"rust_make", "rust_read", "rust_scalar"}
                    if unused_pair:
                        expected.add("unsupported_pair")
                    self.assertEqual({fn["name"] for fn in module["functions"] if fn["entry"] is not None}, expected)
                    self.assertEqual({g["name"] for g in module["globals"]}, {"rust_state"})
                    self.assertEqual(module["globals"][0]["initializer"]["bytes"][0], 9)
                    self.assertEqual(module["aliases"], [])
                    if suffix == "ll":
                        names = set(re.findall(r'^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(', path.read_text(), re.MULTILINE))
                        self.assertEqual({fn["name"] for fn in module["functions"]}, names)
                    loads = [inst for inst in self.instructions(self.function(module, "rust_read")) if inst["operation"]["op"] == "load"]
                    self.assertEqual(len(loads), 2)
                    for load in loads:
                        self.assertEqual(module["types"][load["result"]["ty"]], {"kind": "int", "bits": 64})
                        self.assertEqual(load["operation"]["alignment"], 8)
                        self.assertFalse(load["operation"]["volatile"])
                    refinements = [r for r in provenance["refinements"] if r.startswith("rust_read: block ") and "erased empty !noundef load promise" in r]
                    self.assertEqual(len(refinements), 2)
                self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)

    def test_actual_rust1971_original_whole_units_reject_unused_float_after_retaining_aggregate_return_all_three_isas_text_and_bitcode(self):
        rustc, version = self.rust_compiler()
        source = self.directory / "whole-record-bad.rs"
        source.write_text(self.rust_source() + '''#[repr(C)] pub struct Small { pub first: u64, pub second: u64 }
#[no_mangle] pub extern "C" fn supported_pair(value: u64) -> Small { Small { first: value, second: value ^ 37 } }
#[no_mangle] pub extern "C" fn unsupported_pair(value: u64) -> f64 { value as f64 }
''')
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        for target in (TRIPLES[0], TRIPLES[1], "riscv64gc-unknown-linux-gnu"):
            for suffix in ("ll", "bc"):
                path = self.rust_compile(rustc, source, target, suffix)
                with self.assertRaises(importer.ImportFailure) as raised:
                    importer.import_module(path, library_path=self.library, frontend="Rust", frontend_version=version)
                self.assertEqual(raised.exception.stage, "import")
                self.record_import(path, error=raised.exception)
                self.assertEqual(raised.exception.symbol, "unsupported_pair")
                self.assertIn("unsupported LLVM type kind", str(raised.exception))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)


if __name__ == "__main__":
    unittest.main()
