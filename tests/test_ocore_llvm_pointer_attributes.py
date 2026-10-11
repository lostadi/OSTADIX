"""Verify parsed pointer promises without turning them into native ABI features."""

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
PROMISES = {"align": 8, "dereferenceable": 16, "dereferenceable_or_null": 32}


class LlvmPointerAttributeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-pointer-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    write = memory.LlvmMemoryImportTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode
    import_ir = memory.LlvmMemoryImportTests.import_ir
    reject = memory.LlvmMemoryImportTests.reject
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    clang_flags = staticmethod(memory.LlvmMemoryImportTests.clang_flags)
    compile_clang = memory.LlvmMemoryImportTests.compile_clang

    def roundtrip(self, body, triple=TRIPLES[0]):
        source = self.write(body, triple)
        text = importer.import_module(source, library_path=self.library)
        binary = self.bitcode(source)
        parsed_binary = importer.import_module(binary, library_path=self.library)
        self.assertEqual({key: value for key, value in text.items() if key not in {"name", "provenance"}},
                         {key: value for key, value in parsed_binary.items() if key not in {"name", "provenance"}})
        for path, module in ((source, text), (binary, parsed_binary)):
            self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        return text, parsed_binary

    def assert_promise(self, module, symbol, scope, index, name, payload):
        self.assertIn(
            f"{symbol}: {scope} attribute index {index}: erased pointer promise {name}={payload}; "
            "no native optimization, runtime guard, allocation or speculative memory access assumes this promise",
            module["provenance"]["refinements"])
        self.assertIn("pointer promises validated after pinned LLVM parsing and attribute normalization; "
                      "input_sha256 binds the original bytes", module["provenance"]["refinements"])

    def test_pointer_results_and_fixed_params_on_defined_unused_external_direct_and_indirect_scopes_all_three_isas(self):
        attrs = "align 8 dereferenceable(16) dereferenceable_or_null(32)"
        body = f"""
declare {attrs} ptr @external(ptr {attrs})
declare {attrs} ptr @unused(ptr {attrs})
define {attrs} ptr @identity(ptr {attrs} %pointer) {{ ret ptr %pointer }}
define ptr @direct(ptr %pointer) {{
  %result = call {attrs} ptr @external(ptr {attrs} %pointer)
  ret ptr %result
}}
define ptr @indirect(ptr %callee, ptr %pointer) {{
  %result = call {attrs} ptr %callee(ptr {attrs} %pointer)
  ret ptr %result
}}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 5)
                    self.assertEqual({fn["name"] for fn in module["functions"]},
                                     {"external", "unused", "identity", "direct", "indirect"})
                    for symbol, scope in (("external", "function"), ("unused", "function"),
                                          ("identity", "function"), ("direct", "callsite"),
                                          ("indirect", "callsite")):
                        for index in (0, 1):
                            for name, payload in PROMISES.items():
                                self.assert_promise(module, symbol, scope, index, name, payload)
                    for function in module["functions"]:
                        self.assertIsNone(function["intrinsic"])
                        self.assertEqual(function["signature"]["result_attributes"], [])
                        self.assertFalse(any(function["signature"]["param_attributes"]))
                    for symbol in ("external", "unused"):
                        self.assertIsNone(self.function(module, symbol)["entry"])
                    identity = self.function(module, "identity")
                    self.assertEqual(self.operations(identity), [])
                    for symbol in ("direct", "indirect"):
                        function = self.function(module, symbol)
                        operations = self.operations(function)
                        self.assertEqual([operation["op"] for operation in operations], ["call"])
                        self.assertEqual(operations[0]["signature"], self.function(module, "external")["signature"])
                        if symbol == "direct":
                            self.assertEqual(operations[0]["callee"]["name"], "external")
                        else:
                            self.assertEqual(operations[0]["callee"],
                                             {"kind": "value", "id": function["params"][0]["id"]})

    def test_every_supported_alignment_power_is_recorded_at_full_width_and_bitcode_maximum_is_normalized(self):
        body = "\n".join(f"declare align {1 << exponent} ptr @pointer_{exponent}(ptr align {1 << exponent})"
                         for exponent in range(33)) + "\n"
        text, binary = self.roundtrip(body)
        self.assertEqual(len(text["functions"]), 33)
        for exponent in range(33):
            for index in (0, 1):
                self.assert_promise(text, f"pointer_{exponent}", "function", index, "align", 1 << exponent)
                if exponent < 32:
                    self.assert_promise(binary, f"pointer_{exponent}", "function", index, "align", 1 << exponent)
        # The exact pinned reader drops the 2^32 attribute in this serialization;
        # it does not change the scalar ABI or introduce a memory operation.
        self.assertFalse(any("pointer_32: function attribute" in item
                             for item in binary["provenance"]["refinements"]))

    def test_dereferenceability_promises_cover_unsigned_64_bit_extents_without_an_allocation_cap(self):
        for name in ("dereferenceable", "dereferenceable_or_null"):
            for extent in (1, 7, 1 << 32, (1 << 63) + 1, U64_MAX):
                with self.subTest(attribute=name, extent=extent):
                    text, binary = self.roundtrip(
                        f"define {name}({extent}) ptr @identity(ptr {name}({extent}) %pointer) {{ ret ptr %pointer }}\n")
                    for module in (text, binary):
                        for index in (0, 1):
                            self.assert_promise(module, "identity", "function", index, name, extent)
                        self.assertEqual(self.operations(self.function(module, "identity")), [])

    def test_oversized_text_dereferenceability_is_reader_saturated_with_original_sha(self):
        extent = 1 << 64
        text, binary = self.roundtrip(
            f"declare dereferenceable({extent}) ptr @external(ptr dereferenceable_or_null({extent}))\n")
        for module in (text, binary):
            self.assert_promise(module, "external", "function", 0, "dereferenceable", U64_MAX)
            self.assert_promise(module, "external", "function", 1, "dereferenceable_or_null", U64_MAX)

    def test_pointer_promises_do_not_change_existing_integer_abi_extensions_or_operations(self):
        body = """
declare zeroext i8 @external(ptr align 8 dereferenceable(16), i8 signext)
define signext i8 @entry(ptr dereferenceable_or_null(32) %pointer, i8 zeroext %value) {
  %result = call zeroext i8 @external(ptr align 8 %pointer, i8 signext %value)
  ret i8 %result
}
"""
        module, binary = self.roundtrip(body)
        plain = self.import_ir(body.replace(" align 8", "").replace(" dereferenceable(16)", "")
                               .replace(" dereferenceable_or_null(32)", ""))
        self.assertEqual({key: value for key, value in module.items() if key not in {"name", "provenance"}},
                         {key: value for key, value in plain.items() if key not in {"name", "provenance"}})
        for parsed in (module, binary):
            external = self.function(parsed, "external")
            entry = self.function(parsed, "entry")
            self.assertEqual(external["signature"]["param_attributes"], [[], ["signext"]])
            self.assertEqual(external["signature"]["result_attributes"], ["zeroext"])
            self.assertEqual(entry["signature"]["param_attributes"], [[], ["zeroext"]])
            self.assertEqual(entry["signature"]["result_attributes"], ["signext"])
            self.assertEqual(self.operations(entry)[0]["signature"], external["signature"])

    def test_scalar_parameter_result_and_callsite_placements_reject_at_verification(self):
        for attribute in ("align 8", "dereferenceable(8)", "dereferenceable_or_null(8)"):
            cases = (
                f"declare void @external(i64 {attribute})",
                f"declare {attribute} i64 @external()",
                f"define void @entry(i64 {attribute} %value) {{ ret void }}",
                f"declare i64 @external(i64)\ndefine i64 @entry(i64 %value) {{ %result = call {attribute} i64 @external(i64 %value)\nret i64 %result }}",
                f"define void @entry(ptr %callee, i64 %value) {{ call void %callee(i64 {attribute} %value)\nret void }}",
            )
            for body in cases:
                with self.subTest(attribute=attribute, body=body):
                    self.reject(body + "\n", stage="llvm-verify")

    def test_nonzero_address_spaces_remain_unsupported_with_pointer_promises(self):
        for attribute in ("align 8", "dereferenceable(8)", "dereferenceable_or_null(8)"):
            with self.subTest(attribute=attribute):
                self.reject(f"declare ptr addrspace(1) @external(ptr addrspace(1) {attribute})\n")

    def test_zero_nonpower_and_huge_alignment_and_zero_extents_reject_at_parse(self):
        for attribute in ("align 0", "align 3", f"align {1 << 33}", "dereferenceable(0)", "dereferenceable_or_null(0)"):
            with self.subTest(attribute=attribute):
                self.reject(f"declare ptr @external(ptr {attribute})\n", stage="parse")

    def test_string_named_promises_are_not_a_function_scope_whitelist(self):
        for name in PROMISES:
            with self.subTest(attribute=name):
                self.reject(f'declare ptr @external(ptr) "{name}"="8"\n')

    def test_abi_storage_and_special_register_attributes_still_reject_even_unused(self):
        for attribute in ("byval(i8)", "byref(i8)", "sret(i128)", "inalloca(i8)", "preallocated(i8)",
                          "inreg", "nest", "swiftself", "swifterror", "swiftasync", "alignstack(16)"):
            with self.subTest(attribute=attribute):
                self.reject(f"declare void @unsupported(ptr align 8 dereferenceable(16) {attribute})\n")

    def test_other_pointer_codegen_contracts_are_not_admitted_by_promise_erasure(self):
        self.reject("define ptr @identity(ptr dereferenceable(8) %pointer) null_pointer_is_valid { ret ptr %pointer }\n")
        self.reject("declare ptr @external(ptr align 8, ...)\n")

    @staticmethod
    def clang_source():
        return """
extern unsigned char *external_pointer(unsigned char *) __attribute__((assume_aligned(32)));
extern void observe(unsigned char *);
unsigned char pointer_storage[64];
unsigned char *imported_pointer(unsigned char pointer[static 16]) { return external_pointer(pointer); }
void imported_observer(unsigned char pointer[static 32]) { observe(pointer); }
unsigned char *imported_indirect(unsigned char *(*function)(unsigned char *), unsigned char pointer[static 8]) {
  return function(pointer);
}
unsigned char *imported_global(void) { return pointer_storage; }
"""

    def test_actual_clang22_complete_pointer_unit_text_and_bitcode_all_three_isas(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "pointer.c"
        source.write_text(self.clang_source())
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                text = self.compile_clang(clang, source, triple, "ll")
                llvm_ir = text.read_text()
                inventory = dict((name, kind) for kind, name in re.findall(
                    r"^(define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(", llvm_ir, re.MULTILINE))
                expected = {"imported_pointer", "imported_observer", "imported_indirect", "imported_global",
                            "external_pointer", "observe"}
                self.assertEqual(set(inventory), expected)
                self.assertIn("call align 32 ptr @external_pointer", llvm_ir)
                self.assertIn("dereferenceable(16)", llvm_ir)
                self.assertIn("dereferenceable(32)", llvm_ir)
                modules = []
                for path in (text, self.compile_clang(clang, source, triple, "bc")):
                    module = importer.import_module(path, library_path=self.library,
                                                    frontend="Clang", frontend_version=version)
                    modules.append(module)
                    self.assertEqual(module["provenance"]["source_function_count"], 6)
                    self.assertEqual(module["provenance"]["source_global_count"], 1)
                    self.assertEqual(module["provenance"]["frontend_version"], version)
                    self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                    self.assertEqual(module["target"]["triple"], triple)
                    self.assertEqual({fn["name"] for fn in module["functions"]}, expected)
                    self.assertEqual([glob["name"] for glob in module["globals"]], ["pointer_storage"])
                    for symbol, index, extent in (("imported_pointer", 1, 16), ("imported_observer", 1, 32),
                                                  ("imported_indirect", 2, 8)):
                        self.assert_promise(module, symbol, "function", index, "align", 1)
                        self.assert_promise(module, symbol, "function", index, "dereferenceable", extent)
                    self.assert_promise(module, "imported_pointer", "callsite", 0, "align", 32)
                    direct = self.operations(self.function(module, "imported_pointer"))
                    self.assertEqual([operation["op"] for operation in direct], ["call"])
                    self.assertEqual(direct[0]["callee"]["name"], "external_pointer")
                    indirect_function = self.function(module, "imported_indirect")
                    indirect = self.operations(indirect_function)
                    self.assertEqual([operation["op"] for operation in indirect], ["call"])
                    self.assertEqual(indirect[0]["callee"], {"kind": "value", "id": indirect_function["params"][0]["id"]})
                    self.assertEqual(indirect[0]["signature"], direct[0]["signature"])
                    for function in module["functions"]:
                        self.assertIsNone(function["intrinsic"])
                        self.assertEqual(function["signature"]["result_attributes"], [])
                        self.assertFalse(any(function["signature"]["param_attributes"]))
                self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                                 {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})

    def test_actual_clang22_whole_pointer_unit_with_unused_float_function_rejects_all_three_isas_both_formats(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "pointer-with-float.c"
        source.write_text(self.clang_source() + """
double unsupported_float(double value) { return value + 1.0; }
""")
        for triple in TRIPLES:
            for suffix in ("ll", "bc"):
                with self.subTest(triple=triple, suffix=suffix):
                    path = self.compile_clang(clang, source, triple, suffix)
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(path, library_path=self.library,
                                               frontend="Clang", frontend_version=version)
                    self.assertEqual(raised.exception.stage, "import")
                    self.assertEqual(raised.exception.symbol, "unsupported_float")


if __name__ == "__main__":
    unittest.main()
