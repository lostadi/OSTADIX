"""Preserve tracked symbols in constant pointer-address operands."""

import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory


TRIPLES = baseline.TRIPLES


class LlvmSymbolOffsetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-symbol-offset-test-")
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

    def roundtrip(self, body, triple):
        text = self.write(body, triple)
        binary = self.bitcode(text)
        modules = [importer.import_module(path, library_path=self.library) for path in (text, binary)]
        self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                         {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})
        for path, module in zip((text, binary), modules):
            self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(module["target"]["triple"], triple)
        return modules

    def assert_address(self, module, operand, name, addend):
        expected = {"kind": "symbol_offset" if addend else "symbol", "ty": operand["ty"], "name": name}
        if addend:
            expected["addend"] = addend
        self.assertEqual(operand, expected)
        self.assertEqual(module["types"][operand["ty"]], {"kind": "pointer", "address_space": 0})

    def returned(self, module, name):
        function = self.function(module, name)
        returns = [block["terminator"]["value"] for block in function["blocks"]
                   if block["terminator"]["op"] == "return"]
        self.assertEqual(len(returns), 1)
        return returns[0]

    def reject_roundtrip(self, body, triple, stage="import"):
        text = self.write(body, triple)
        for path in (text, self.bitcode(text)):
            with self.assertRaises(importer.ImportFailure) as raised:
                importer.import_module(path, library_path=self.library)
            self.assertEqual(raised.exception.stage, stage)
            self.assertTrue(str(raised.exception).strip())

    def test_symbol_offsets_keep_global_function_alias_identity_in_all_operand_positions_all_three_isas(self):
        body = """
@data = global [8 x i64] zeroinitializer, align 8
@data_alias = alias [8 x i64], ptr @data
@slot = global ptr null
@addresses = global [3 x ptr] [ptr getelementptr (i8, ptr @data, i64 16), ptr getelementptr (i8, ptr @data_alias, i64 -8), ptr getelementptr (i8, ptr @target, i64 4)]
define ptr @target(ptr %pointer) { ret ptr %pointer }
declare ptr @external(ptr)
declare ptr @unused(ptr)
define ptr @contexts(i1 %choose, ptr %function, ptr %pointer) {
entry:
  %compare = icmp eq ptr %pointer, getelementptr (i8, ptr @data, i64 16)
  %selected = select i1 %choose, ptr getelementptr (i8, ptr @data_alias, i64 24), ptr getelementptr (i8, ptr @target, i64 4)
  store ptr getelementptr (i8, ptr @data, i64 40), ptr @slot
  %direct = call ptr @external(ptr getelementptr (i8, ptr @data_alias, i64 -8))
  %indirect = call ptr %function(ptr getelementptr (i8, ptr @data, i64 56))
  br i1 %compare, label %left, label %right
left:
  br label %join
right:
  br label %join
join:
  %merged = phi ptr [getelementptr (i8, ptr @data, i64 8), %left], [getelementptr (i8, ptr @data_alias, i64 48), %right]
  ret ptr %merged
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assertEqual({fn["name"] for fn in module["functions"]}, {"target", "external", "unused", "contexts"})
                self.assertEqual({glob["name"] for glob in module["globals"]}, {"data", "slot", "addresses"})
                self.assertEqual([(alias["name"], alias["aliasee"]) for alias in module["aliases"]], [("data_alias", "data")])
                self.assertIsNone(self.function(module, "unused")["entry"])
                ops = self.operations(self.function(module, "contexts"))
                self.assertEqual([op["op"] for op in ops], ["i_cmp", "select", "store", "call", "call", "phi"])
                self.assert_address(module, ops[0]["rhs"], "data", 16)
                self.assert_address(module, ops[1]["on_true"], "data_alias", 24)
                self.assert_address(module, ops[1]["on_false"], "target", 4)
                self.assert_address(module, ops[2]["value"], "data", 40)
                self.assert_address(module, ops[2]["pointer"], "slot", 0)
                self.assert_address(module, ops[3]["callee"], "external", 0)
                self.assert_address(module, ops[3]["args"][0], "data_alias", -8)
                self.assertEqual(ops[4]["callee"]["kind"], "value")
                self.assert_address(module, ops[4]["args"][0], "data", 56)
                for incoming, name, addend in zip(ops[5]["incoming"], ("data", "data_alias"), (8, 48)):
                    self.assert_address(module, incoming["value"], name, addend)
                self.assertEqual(self.returned(module, "contexts")["kind"], "value")
                addresses = next(glob for glob in module["globals"] if glob["name"] == "addresses")
                self.assertEqual(addresses["initializer"]["relocations"], [
                    {"offset": offset, "width": 64, "symbol": name, "addend": addend}
                    for offset, name, addend in ((0, "data", 16), (8, "data_alias", -8), (16, "target", 4))])
                self.assertTrue(any("original root data_alias and signed i64 byte addend -8" in refinement
                                    for refinement in module["provenance"]["refinements"]))

    def test_nested_gep_and_pointer_bitcast_use_exact_struct_array_and_packed_layout_all_three_isas(self):
        body = """
@record = global { i8, [3 x i64], ptr } zeroinitializer
@record_alias = alias { i8, [3 x i64], ptr }, ptr @record
@packed = global <{ i8, i64 }> zeroinitializer
define ptr @nested() { ret ptr getelementptr (i8, ptr bitcast (ptr getelementptr ({ i8, [3 x i64], ptr }, ptr @record_alias, i64 0, i32 1, i64 2) to ptr), i64 -4) }
define ptr @pointer_field() { ret ptr getelementptr ({ i8, [3 x i64], ptr }, ptr @record, i64 0, i32 2) }
define ptr @packed_field() { ret ptr getelementptr (<{ i8, i64 }>, ptr @packed, i64 0, i32 1) }
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assert_address(module, self.returned(module, "nested"), "record_alias", 20)
                self.assert_address(module, self.returned(module, "pointer_field"), "record", 32)
                self.assert_address(module, self.returned(module, "packed_field"), "packed", 1)
                self.assertEqual({fn["name"] for fn in module["functions"]}, {"nested", "pointer_field", "packed_field"})
                self.assertTrue(all(not self.operations(fn) for fn in module["functions"]))

    def test_signed_indices_and_pointer_wrap_are_normalized_to_signed_i64_all_three_isas(self):
        body = """
@data = global i64 0
define ptr @negative() { ret ptr getelementptr (i8, ptr @data, i8 -128) }
define ptr @one_bit() { ret ptr getelementptr (i8, ptr @data, i1 true) }
define ptr @minimum() { ret ptr getelementptr (i8, ptr @data, i64 -9223372036854775808) }
define ptr @stride_wrap() { ret ptr getelementptr (i64, ptr @data, i64 9223372036854775807) }
define ptr @cancel() { ret ptr getelementptr (i8, ptr getelementptr (i8, ptr @data, i64 9223372036854775807), i64 -9223372036854775807) }
"""
        expected = {"negative": -128, "one_bit": -1, "minimum": -(1 << 63), "stride_wrap": -8, "cancel": 0}
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                for name, addend in expected.items():
                    self.assert_address(module, self.returned(module, name), "data", addend)
                self.assertTrue(any("signed i64 byte addend -8 modulo 2^64" in refinement
                                    for refinement in module["provenance"]["refinements"]))

    def test_function_alias_address_and_offset_call_keep_exact_extension_abi_all_three_isas(self):
        body = """
define signext i32 @target(i32 zeroext %value) { ret i32 %value }
@function_alias = weak hidden alias i32(i32), ptr @target
define ptr @address() { ret ptr getelementptr (i8, ptr @function_alias, i64 4) }
define signext i32 @caller(i32 zeroext %value) {
  %result = call signext i32 getelementptr (i8, ptr @function_alias, i64 4)(i32 zeroext %value)
  ret i32 %result
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assert_address(module, self.returned(module, "address"), "function_alias", 4)
                call = self.operations(self.function(module, "caller"))[0]
                self.assert_address(module, call["callee"], "function_alias", 4)
                self.assertEqual(call["signature"], self.function(module, "target")["signature"])
                self.assertEqual(call["signature"]["param_attributes"], [["zeroext"]])
                self.assertEqual(call["signature"]["result_attributes"], ["signext"])
                self.assertEqual(module["aliases"][0]["visibility"], "hidden")
                self.assertEqual(module["aliases"][0]["aliasee"], "target")

    def test_inbounds_nowrap_inrange_refinement_keeps_tracked_address_all_three_isas(self):
        body = """
@data = global [8 x i64] zeroinitializer
define ptr @address() { ret ptr getelementptr inbounds nuw inrange(-16, 48) (i8, ptr @data, i64 16) }
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assert_address(module, self.returned(module, "address"), "data", 16)
                self.assertIn("address: constant GEP inrange/no-wrap restrictions erased; exact DataLayout address retained",
                              module["provenance"]["refinements"])

    def test_relative_integer_initializers_and_symbolic_integer_roundtrips_stay_rejected_all_three_isas(self):
        bodies = [
            "@data = global i64 0\n@table = global i32 trunc (i64 sub (i64 ptrtoint (ptr @data to i64), i64 ptrtoint (ptr @table to i64)) to i32)\n",
            "@data = global i64 0\ndefine ptr @address() { ret ptr inttoptr (i64 add (i64 ptrtoint (ptr @data to i64), i64 8) to ptr) }\n",
        ]
        for triple in TRIPLES:
            for body in bodies:
                with self.subTest(triple=triple, body=body):
                    self.reject_roundtrip(body, triple)

    def test_unsupported_address_spaces_vectors_and_alias_chains_reject_complete_modules_all_three_isas(self):
        bodies = [
            "@data = addrspace(1) global i64 0\ndefine ptr @address() { ret ptr addrspacecast (ptr addrspace(1) getelementptr (i8, ptr addrspace(1) @data, i64 8) to ptr) }\n",
            "@data = global i64 0\ndefine <2 x ptr> @address() { ret <2 x ptr> getelementptr (i8, <2 x ptr> <ptr @data, ptr @data>, <2 x i64> <i64 8, i64 16>) }\n",
            "@data = global i64 0\n@first = alias i64, ptr @data\n@second = alias i64, ptr @first\ndefine ptr @address() { ret ptr getelementptr (i8, ptr @second, i64 8) }\n",
        ]
        for triple in TRIPLES:
            for body in bodies:
                with self.subTest(triple=triple, body=body):
                    self.reject_roundtrip(body, triple)

    def test_intrinsic_addresses_remain_forbidden_at_the_actual_llvm_verifier_boundary(self):
        body = "declare void @llvm.assume(i1)\ndefine ptr @address() { ret ptr getelementptr (i8, ptr @llvm.assume, i64 4) }\n"
        for triple in TRIPLES:
            with self.assertRaises(importer.ImportFailure) as raised:
                importer.import_module(self.write(body, triple), library_path=self.library)
            self.assertEqual(raised.exception.stage, "llvm-verify")
            self.assertIn("llvm.assume", str(raised.exception))

    def test_actual_clang22_complete_pointer_address_unit_imports_unmodified_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "symbol-addresses.c"
        source.write_text("""
unsigned long data[8] = {3, 5, 7, 11, 13, 17, 19, 23};
void *slot = &data[4];
extern void *external_address(void *);
void *imported_return(void) { return &data[3]; }
int imported_compare(void *pointer) { return pointer == &data[2]; }
void *imported_select(int condition, void *pointer) { return condition ? &data[5] : pointer; }
void *imported_direct(void) { return external_address(&data[1]); }
void *imported_indirect(void *(*function)(void *)) { return function(&data[6]); }
void imported_store(void) { slot = &data[7]; }
""")
        expected = {"imported_return", "imported_compare", "imported_select", "imported_direct",
                    "imported_indirect", "imported_store", "external_address"}
        for triple in TRIPLES:
            text = self.compile_clang(clang, source, triple, "ll")
            inventory = set(re.findall(r"^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(", text.read_text(), re.MULTILINE))
            self.assertEqual(inventory, expected)
            for path in (text, self.compile_clang(clang, source, triple, "bc")):
                module = importer.import_module(path, library_path=self.library, frontend="Clang", frontend_version=version)
                self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(module["provenance"]["frontend_version"], version)
                self.assertEqual({fn["name"] for fn in module["functions"]}, expected)
                self.assertEqual({glob["name"] for glob in module["globals"]}, {"data", "slot"})
                self.assert_address(module, self.returned(module, "imported_return"), "data", 24)
                compare = next(op for op in self.operations(self.function(module, "imported_compare")) if op["op"] == "i_cmp")
                self.assert_address(module, compare["rhs"], "data", 16)
                select_function = self.function(module, "imported_select")
                select_instructions = self.instructions(select_function)
                comparison = next(inst for inst in select_instructions if inst["operation"]["op"] == "i_cmp")
                select = next(inst["operation"] for inst in select_instructions if inst["operation"]["op"] == "select")
                # The unchanged O1 producer tests condition == 0 and swaps
                # source branches; preserve its condition and address branch.
                self.assertEqual(comparison["operation"]["predicate"], "eq")
                self.assertEqual(comparison["operation"]["rhs"]["bits"], "0")
                self.assertEqual(select["condition"], {"kind": "value", "id": comparison["result"]["id"]})
                self.assertEqual(select["on_true"], {"kind": "value", "id": select_function["params"][1]["id"]})
                self.assert_address(module, select["on_false"], "data", 40)
                for name, addend in (("imported_direct", 8), ("imported_indirect", 48)):
                    call = next(op for op in self.operations(self.function(module, name)) if op["op"] == "call")
                    self.assert_address(module, call["args"][0], "data", addend)
                store = next(op for op in self.operations(self.function(module, "imported_store")) if op["op"] == "store")
                self.assert_address(module, store["value"], "data", 56)
                slot = next(glob for glob in module["globals"] if glob["name"] == "slot")
                self.assertEqual(slot["initializer"]["relocations"], [{"offset": 0, "width": 64, "symbol": "data", "addend": 32}])

    def test_actual_clang22_complete_cpp_vtable_address_units_keep_all_entities_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "vtable-addresses.cpp"
        source.write_text("""
class Box {
  unsigned long value;
public:
  Box(unsigned long input) : value(input) {}
  virtual unsigned long read() { return value; }
};
extern void observe(Box *);
extern "C" unsigned long drive(unsigned long input) {
  Box box(input);
  observe(&box);
  return box.read();
}
""")
        for triple in TRIPLES:
            modules = []
            for suffix in ("ll", "bc"):
                output = self.directory / f"cpp-{triple}.{suffix}"
                target_flags = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
                command = [clang, "--target=" + triple, *target_flags, *self.clang_flags(), "-std=c++17",
                           "-fno-exceptions", "-fno-rtti", "-S" if suffix == "ll" else "-c", str(source), "-o", str(output)]
                completed = subprocess.run(command, cwd=baseline.ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                if suffix == "ll":
                    raw = output.read_text()
                    inventory = set(re.findall(r"^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(", raw, re.MULTILINE))
                    global_names = set(re.findall(r"^@([A-Za-z_][A-Za-z0-9_.$]*) =", raw, re.MULTILINE))
                module = importer.import_module(output, library_path=self.library, frontend="Clang C++", frontend_version=version)
                modules.append(module)
                self.assertEqual({fn["name"] for fn in module["functions"]}, inventory)
                self.assertEqual({glob["name"] for glob in module["globals"]} | {alias["name"] for alias in module["aliases"]}, global_names)
                self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
                stores = [op for op in self.operations(self.function(module, "drive")) if op["op"] == "store"]
                address = next(op["value"] for op in stores if op["value"]["kind"] == "symbol_offset")
                self.assert_address(module, address, "_ZTV3Box", 16)
                self.assertEqual(sum(op["op"] == "call" for op in self.operations(self.function(module, "drive"))), 1)
                self.assertIn("_ZTV3Box", {group["name"] for group in module["comdats"]})
            self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                             {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})


if __name__ == "__main__":
    unittest.main()
