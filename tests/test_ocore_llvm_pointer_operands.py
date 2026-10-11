"""Import integral pointer literals; sentinel addresses are never executed."""

import hashlib
from pathlib import Path
import re
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory


TRIPLES = baseline.TRIPLES
U64_MAX = (1 << 64) - 1


class LlvmPointerOperandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-pointer-operand-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    write = memory.LlvmMemoryImportTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode
    import_ir = memory.LlvmMemoryImportTests.import_ir
    reject = baseline.LlvmImportTests.reject
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    clang_flags = staticmethod(memory.LlvmMemoryImportTests.clang_flags)
    compile_clang = memory.LlvmMemoryImportTests.compile_clang

    def roundtrip(self, body, triple=TRIPLES[0]):
        text_path = self.write(body, triple)
        text_module = importer.import_module(text_path, library_path=self.library)
        binary_path = self.bitcode(text_path)
        binary_module = importer.import_module(binary_path, library_path=self.library)
        self.assertEqual({key: value for key, value in text_module.items() if key not in {"name", "provenance"}},
                         {key: value for key, value in binary_module.items() if key not in {"name", "provenance"}})
        for path, module in ((text_path, text_module), (binary_path, binary_module)):
            self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(module["target"]["triple"], triple)
        return text_module, binary_module

    def assert_pointer(self, module, operand, bits):
        self.assertEqual(operand, {"kind": "pointer_bits", "ty": operand["ty"], "bits": str(bits)})
        self.assertEqual(module["types"][operand["ty"]], {"kind": "pointer", "address_space": 0})

    def assert_refinement(self, module, symbol, width):
        self.assertIn(f"{symbol}: constant integer-to-pointer source i{width} retains exact zero-extended integral AS0 "
                      "address bits; no symbol relocation or dereference is introduced",
                      module["provenance"]["refinements"])

    def returned(self, module, symbol):
        function = self.function(module, symbol)
        self.assertEqual(len(function["blocks"]), 1)
        self.assertEqual(function["blocks"][0]["terminator"]["op"], "return")
        return function["blocks"][0]["terminator"]["value"]

    def reject_text_and_bitcode(self, body, triple=TRIPLES[0]):
        source = self.write(body, triple)
        for path in (source, self.bitcode(source)):
            with self.assertRaises(importer.ImportFailure) as raised:
                importer.import_module(path, library_path=self.library)
            self.assertEqual(raised.exception.stage, "import")
            self.assertTrue(str(raised.exception).strip())

    def test_all_literal_source_widths_one_through_64_are_folded_without_executable_integer_types_all_three_isas(self):
        body = "\n".join(f"define ptr @pointer_{width}() {{ ret ptr inttoptr (i{width} -1 to ptr) }}"
                         for width in range(1, 65)) + "\n"
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 64)
                    self.assertEqual(module["provenance"]["source_global_count"], 0)
                    self.assertEqual({fn["name"] for fn in module["functions"]},
                                     {f"pointer_{width}" for width in range(1, 65)})
                    self.assertEqual(module["types"], [{"kind": "pointer", "address_space": 0}])
                    for width in range(1, 65):
                        symbol = f"pointer_{width}"
                        self.assert_pointer(module, self.returned(module, symbol), (1 << width) - 1)
                        self.assert_refinement(module, symbol, width)
                        self.assertEqual(self.operations(self.function(module, symbol)), [])
                        self.assertIsNone(self.function(module, symbol)["intrinsic"])

    def test_pointer_literals_survive_compare_select_phi_return_call_and_store_value_contexts_all_three_isas(self):
        body = """
declare ptr @external(ptr)
declare ptr @unused(ptr)
define i1 @compare(ptr %pointer) {
  %result = icmp eq ptr %pointer, inttoptr (i7 -1 to ptr)
  ret i1 %result
}
define ptr @select_pointer(i1 %condition, ptr %pointer) {
  %result = select i1 %condition, ptr inttoptr (i63 -1 to ptr), ptr %pointer
  ret ptr %result
}
define ptr @phi_pointer(i1 %condition) {
entry:
  br i1 %condition, label %left, label %right
left:
  br label %merge
right:
  br label %merge
merge:
  %result = phi ptr [ inttoptr (i8 -1 to ptr), %left ], [ inttoptr (i64 -1 to ptr), %right ]
  ret ptr %result
}
define ptr @return_pointer() { ret ptr inttoptr (i32 -1 to ptr) }
define ptr @direct() {
  %result = call ptr @external(ptr inttoptr (i64 -1 to ptr))
  ret ptr %result
}
define ptr @indirect(ptr %callee) {
  %result = call ptr %callee(ptr inttoptr (i16 257 to ptr))
  ret ptr %result
}
define void @store_pointer(ptr %destination) {
  store ptr inttoptr (i7 -1 to ptr), ptr %destination, align 8
  ret void
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 9)
                    self.assertEqual(module["globals"], [])
                    self.assertFalse(any(ty == {"kind": "int", "bits": 7} for ty in module["types"]))
                    compare = self.operations(self.function(module, "compare"))[0]
                    self.assertEqual(compare["op"], "i_cmp")
                    self.assert_pointer(module, compare["rhs"], 127)
                    select = self.operations(self.function(module, "select_pointer"))[0]
                    self.assertEqual(select["op"], "select")
                    self.assert_pointer(module, select["on_true"], (1 << 63) - 1)
                    phi = self.operations(self.function(module, "phi_pointer"))[0]
                    self.assertEqual(phi["op"], "phi")
                    self.assertEqual(len(phi["incoming"]), 2)
                    self.assert_pointer(module, phi["incoming"][0]["value"], 255)
                    self.assert_pointer(module, phi["incoming"][1]["value"], U64_MAX)
                    self.assert_pointer(module, self.returned(module, "return_pointer"), (1 << 32) - 1)
                    for symbol, bits in (("direct", U64_MAX), ("indirect", 257)):
                        function = self.function(module, symbol)
                        operations = self.operations(function)
                        self.assertEqual([operation["op"] for operation in operations], ["call"])
                        self.assert_pointer(module, operations[0]["args"][0], bits)
                        self.assertEqual(operations[0]["signature"], self.function(module, "external")["signature"])
                        if symbol == "direct":
                            self.assertEqual(operations[0]["callee"]["name"], "external")
                        else:
                            self.assertEqual(operations[0]["callee"], {"kind": "value", "id": function["params"][0]["id"]})
                    store_function = self.function(module, "store_pointer")
                    stores = self.operations(store_function)
                    self.assertEqual([operation["op"] for operation in stores], ["store"])
                    self.assert_pointer(module, stores[0]["value"], 127)
                    self.assertEqual(stores[0]["pointer"], {"kind": "value", "id": store_function["params"][0]["id"]})
                    for symbol in ("external", "unused"):
                        self.assertIsNone(self.function(module, symbol)["entry"])
                    self.assertFalse(any(operation["op"] == "load" for function in module["functions"]
                                         for operation in self.operations(function)))

    def test_narrow_high_bits_are_zero_extended_and_u64_addresses_remain_unsigned(self):
        cases = ((1, "true", 1), (7, "64", 64), (8, "-1", 255),
                 (63, str(1 << 62), 1 << 62), (64, str(1 << 63), 1 << 63), (64, "-1", U64_MAX))
        for width, literal, bits in cases:
            with self.subTest(width=width, literal=literal):
                for module in self.roundtrip(f"define ptr @entry() {{ ret ptr inttoptr (i{width} {literal} to ptr) }}\n"):
                    self.assert_pointer(module, self.returned(module, "entry"), bits)
                    self.assert_refinement(module, "entry", width)

    def test_zero_poison_and_undef_reader_folding_including_original_wide_sources_is_preserved_all_three_isas(self):
        body = "\n".join(f"define ptr @{name}_{width}() {{ ret ptr inttoptr (i{width} {literal} to ptr) }}"
                         for width in (7, 64, 128)
                         for name, literal in (("zero", "0"), ("poison", "poison"), ("undef", "undef"))) + "\n"
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 9)
                    self.assertEqual(module["types"], [{"kind": "pointer", "address_space": 0}])
                    for width in (7, 64, 128):
                        for name, kind in (("zero", "null"), ("poison", "poison"), ("undef", "undef")):
                            self.assertEqual(self.returned(module, f"{name}_{width}"), {"kind": kind, "ty": 0})
                    self.assertFalse(any("constant integer-to-pointer source" in refinement
                                         for refinement in module["provenance"]["refinements"]))

    def test_surviving_nonzero_wide_literal_expressions_reject_all_three_isas(self):
        for triple in TRIPLES:
            for width, literal in ((65, "-1"), (128, "1"), (128, str((1 << 64) + 1))):
                with self.subTest(triple=triple, width=width, literal=literal):
                    self.reject_text_and_bitcode(f"define ptr @entry() {{ ret ptr inttoptr (i{width} {literal} to ptr) }}\n", triple)

    def test_symbolic_integer_addresses_do_not_become_literal_bits_or_untracked_relocations(self):
        cases = (
            "@data = global i8 0\ndefine ptr @entry() { ret ptr inttoptr (i64 ptrtoint (ptr @data to i64) to ptr) }",
            "@data = global i8 0\ndefine ptr @entry() { ret ptr inttoptr (i64 add (i64 ptrtoint (ptr @data to i64), i64 3) to ptr) }",
            "@left = global i8 0\n@right = global i8 0\ndefine ptr @entry() { ret ptr inttoptr (i64 sub (i64 ptrtoint (ptr @right to i64), i64 ptrtoint (ptr @left to i64)) to ptr) }",
            "declare void @external()\ndefine ptr @entry() { ret ptr inttoptr (i64 ptrtoint (ptr @external to i64) to ptr) }",
        )
        for body in cases:
            with self.subTest(body=body):
                self.reject_text_and_bitcode(body + "\n")

    def test_nonzero_address_space_literals_and_canonical_null_remain_unsupported(self):
        for literal in ("1", "0", "poison", "undef"):
            with self.subTest(literal=literal):
                self.reject_text_and_bitcode(f"define ptr addrspace(1) @entry() {{ ret ptr addrspace(1) inttoptr (i64 {literal} to ptr addrspace(1)) }}\n")

    def test_nonintegral_layout_cannot_admit_pointer_literal_operands_all_three_isas(self):
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                source = self.write("define ptr @entry() { ret ptr inttoptr (i64 1 to ptr) }\n", triple)
                source.write_text(source.read_text().replace('target datalayout = "', 'target datalayout = "ni:1-'))
                with self.assertRaises(importer.ImportFailure) as raised:
                    importer.import_module(source, library_path=self.library)
                self.assertEqual(raised.exception.stage, "import")
                self.assertIn("ni:1", str(raised.exception))

    def test_readnone_pointer_params_record_scope_without_erasing_calls_or_other_memory_effects(self):
        body = """
declare void @external(ptr readnone, ptr)
declare void @unused(ptr readnone)
define i8 @defined(ptr readnone %address, ptr %memory) {
  store i8 9, ptr %memory, align 1
  %loaded = load i8, ptr %memory, align 1
  %equal = icmp eq ptr %address, inttoptr (i7 -1 to ptr)
  %bit = zext i1 %equal to i8
  %result = add i8 %loaded, %bit
  ret i8 %result
}
define void @direct(ptr %address, ptr %memory) {
  store i8 1, ptr %memory, align 1
  call void @external(ptr readnone %address, ptr %memory)
  %loaded = load i8, ptr %memory, align 1
  store i8 %loaded, ptr %memory, align 1
  ret void
}
define void @indirect(ptr %callee, ptr %address, ptr %memory) {
  call void %callee(ptr readnone %address, ptr %memory)
  store i8 2, ptr %memory, align 1
  ret void
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 5)
                    self.assertEqual({function["name"] for function in module["functions"]},
                                     {"external", "unused", "defined", "direct", "indirect"})
                    for symbol, site in (("external", "function"), ("unused", "function"),
                                         ("defined", "function"), ("direct", "callsite"),
                                         ("indirect", "callsite")):
                        self.assertIn(f"{symbol}: {site} attribute index 1: erased optimization assumption readnone=0; "
                                      "all calls, loads and stores retained; no native optimization or function purity is inferred",
                                      module["provenance"]["refinements"])
                    self.assertIn("optimizer promises validated after pinned LLVM parsing and attribute normalization; "
                                  "input_sha256 binds the original bytes", module["provenance"]["refinements"])
                    for function in module["functions"]:
                        self.assertEqual(function["signature"]["result_attributes"], [])
                        self.assertFalse(any(function["signature"]["param_attributes"]))
                        self.assertIsNone(function["intrinsic"])
                    self.assertIsNone(self.function(module, "unused")["entry"])
                    defined = self.operations(self.function(module, "defined"))
                    self.assertEqual([operation["op"] for operation in defined],
                                     ["store", "load", "i_cmp", "cast", "binary"])
                    self.assert_pointer(module, defined[2]["rhs"], 127)
                    direct = self.operations(self.function(module, "direct"))
                    self.assertEqual([operation["op"] for operation in direct], ["store", "call", "load", "store"])
                    self.assertEqual(direct[1]["callee"]["name"], "external")
                    indirect_function = self.function(module, "indirect")
                    indirect = self.operations(indirect_function)
                    self.assertEqual([operation["op"] for operation in indirect], ["call", "store"])
                    self.assertEqual(indirect[0]["callee"], {"kind": "value", "id": indirect_function["params"][0]["id"]})
                    self.assertEqual(direct[1]["signature"], self.function(module, "external")["signature"])
                    self.assertEqual(indirect[0]["signature"], direct[1]["signature"])
        self.reject("declare void @unsupported(ptr readnone inreg)\n")
        self.reject('declare ptr @unused() "readnone"="0"\n')

    def test_actual_clang22_complete_sentinel_pointer_unit_imports_unmodified_text_and_bitcode_all_three_isas(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "pointer-literals.c"
        source.write_text("""
typedef unsigned long usize;
extern void *external_pointer(void *);
void *pointer_slot;
void *imported_return(void) { return (void *)(usize)-1; }
int imported_compare(void *pointer) { return pointer == (void *)(usize)4097; }
void *imported_select(int condition, void *pointer) { return condition ? (void *)(usize)4097 : pointer; }
void *imported_direct(void) { return external_pointer((void *)(usize)4097); }
void *imported_indirect(void *(*function)(void *)) { return function((void *)(usize)4097); }
void imported_store(void **destination) { *destination = (void *)(usize)4097; }
""")
        expected = {"imported_return", "imported_compare", "imported_select", "imported_direct",
                    "imported_indirect", "imported_store", "external_pointer"}
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                text = self.compile_clang(clang, source, triple, "ll")
                llvm_ir = text.read_text()
                inventory = set(re.findall(r"^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(",
                                           llvm_ir, re.MULTILINE))
                self.assertEqual(inventory, expected)
                self.assertIn("inttoptr (i64 4097 to ptr)", llvm_ir)
                modules = []
                for path in (text, self.compile_clang(clang, source, triple, "bc")):
                    module = importer.import_module(path, library_path=self.library,
                                                    frontend="Clang", frontend_version=version)
                    modules.append(module)
                    self.assertEqual(module["provenance"]["source_function_count"], 7)
                    self.assertEqual(module["provenance"]["source_global_count"], 1)
                    self.assertEqual(module["provenance"]["frontend_version"], version)
                    self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                    self.assertEqual({function["name"] for function in module["functions"]}, expected)
                    self.assertEqual([global_["name"] for global_ in module["globals"]], ["pointer_slot"])
                    self.assert_pointer(module, self.returned(module, "imported_return"), U64_MAX)
                    compare = next(operation for operation in self.operations(self.function(module, "imported_compare"))
                                   if operation["op"] == "i_cmp")
                    self.assert_pointer(module, compare["rhs"], 4097)
                    select_function = self.function(module, "imported_select")
                    select = next(operation for operation in self.operations(select_function) if operation["op"] == "select")
                    condition = next(instruction["operation"] for instruction in self.instructions(select_function)
                                     if instruction["result"] and instruction["result"]["id"] == select["condition"]["id"])
                    self.assertEqual(condition["op"], "i_cmp")
                    self.assertEqual(condition["rhs"]["bits"], "0")
                    self.assertIn(condition["predicate"], {"eq", "ne"})
                    self.assert_pointer(module, select["on_true" if condition["predicate"] == "ne" else "on_false"], 4097)
                    self.assertEqual(select["on_false" if condition["predicate"] == "ne" else "on_true"],
                                     {"kind": "value", "id": select_function["params"][1]["id"]})
                    for symbol in ("imported_direct", "imported_indirect"):
                        call = next(operation for operation in self.operations(self.function(module, symbol))
                                    if operation["op"] == "call")
                        self.assert_pointer(module, call["args"][0], 4097)
                    store_function = self.function(module, "imported_store")
                    store = next(operation for operation in self.operations(store_function) if operation["op"] == "store")
                    self.assert_pointer(module, store["value"], 4097)
                    self.assertEqual(store["pointer"], {"kind": "value", "id": store_function["params"][0]["id"]})
                self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                                 {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})


if __name__ == "__main__":
    unittest.main()
