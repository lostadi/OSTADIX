"""Import explicit traps without losing effects or complete module inventory."""

import hashlib
from pathlib import Path
import re
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory


TRIPLES = baseline.TRIPLES
DECLARATION = "declare void @llvm.trap() cold noreturn nounwind\n"


class LlvmTrapImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-trap-test-")
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

    def assert_declaration(self, module):
        function = self.function(module, "llvm.trap")
        self.assertEqual(function["intrinsic"], "llvm.trap")
        self.assertEqual(function["linkage"], "external")
        self.assertEqual(function["visibility"], "default")
        self.assertEqual(function["params"], [])
        self.assertEqual(function["blocks"], [])
        self.assertIsNone(function["entry"])
        signature = function["signature"]
        self.assertEqual(signature["params"], [])
        self.assertEqual(module["types"][signature["result"]], {"kind": "void"})
        self.assertEqual(signature["abi"], "c")
        self.assertFalse(signature["variadic"])
        self.assertEqual(signature["param_attributes"], [])
        self.assertEqual(signature["result_attributes"], [])

    def assert_trap(self, instruction):
        self.assertEqual(instruction, {"result": None, "operation": {"op": "trap"}})

    def reject_text(self, body, triple, stage):
        with self.assertRaises(importer.ImportFailure) as raised:
            importer.import_module(self.write(body, triple), library_path=self.library)
        self.assertEqual(raised.exception.stage, stage)
        self.assertTrue(str(raised.exception).strip())

    def reject_roundtrip(self, body, triple):
        text = self.write(body, triple)
        for path in (text, self.bitcode(text)):
            with self.assertRaises(importer.ImportFailure) as raised:
                importer.import_module(path, library_path=self.library)
            self.assertEqual(raised.exception.stage, "import")
            self.assertTrue(str(raised.exception).strip())

    def test_unconditional_conditional_and_unused_cold_traps_keep_order_and_complete_inventory_all_three_isas(self):
        body = DECLARATION + """
@counter = global i64 0
@unused_data = global i64 91
declare void @observe(i64)
declare void @unused_declaration(ptr)
define void @stop() {
  store volatile i64 37, ptr @counter, align 8
  call void @observe(i64 37)
  call void @llvm.trap()
  unreachable
}
define void @unused_cold() cold noreturn {
  call void @llvm.trap()
  unreachable
}
define i64 @conditional(i1 %fail, i64 %value) {
entry:
  br i1 %fail, label %bad, label %good
bad:
  call void @observe(i64 %value)
  call void @llvm.trap()
  unreachable
good:
  store i64 %value, ptr @counter, align 8
  ret i64 %value
}
define void @caller() {
  call void @stop()
  unreachable
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assert_declaration(module)
                self.assertEqual({fn["name"] for fn in module["functions"]},
                                 {"llvm.trap", "observe", "unused_declaration", "stop", "unused_cold", "conditional", "caller"})
                self.assertEqual(module["provenance"]["source_function_count"], 7)
                self.assertEqual({glob["name"] for glob in module["globals"]}, {"counter", "unused_data"})
                self.assertEqual(module["provenance"]["source_global_count"], 2)
                self.assertIsNone(self.function(module, "unused_declaration")["entry"])
                stop = self.function(module, "stop")
                instructions = self.instructions(stop)
                self.assertEqual([inst["operation"]["op"] for inst in instructions], ["store", "call", "trap"])
                self.assertTrue(instructions[0]["operation"]["volatile"])
                self.assertEqual(instructions[0]["operation"]["value"]["bits"], "37")
                self.assertEqual(instructions[1]["operation"]["callee"]["name"], "observe")
                self.assert_trap(instructions[2])
                self.assertEqual(stop["blocks"][0]["terminator"], {"op": "unreachable"})
                cold = self.function(module, "unused_cold")
                self.assertIsNotNone(cold["entry"])
                self.assert_trap(self.instructions(cold)[0])
                conditional = self.function(module, "conditional")
                self.assertEqual(conditional["blocks"][0]["terminator"]["op"], "branch")
                trap_block = next(block for block in conditional["blocks"] if any(inst["operation"]["op"] == "trap" for inst in block["instructions"]))
                self.assertEqual([inst["operation"]["op"] for inst in trap_block["instructions"]], ["call", "trap"])
                self.assert_trap(trap_block["instructions"][-1])
                self.assertEqual(trap_block["terminator"], {"op": "unreachable"})
                self.assertTrue(any(block["terminator"]["op"] == "return" for block in conditional["blocks"]))
                ordinary_call = self.operations(self.function(module, "caller"))
                self.assertEqual([op["op"] for op in ordinary_call], ["call"])
                self.assertEqual(ordinary_call[0]["callee"]["name"], "stop")

    def test_unused_exact_trap_declaration_stays_in_the_module_inventory_all_three_isas(self):
        for triple in TRIPLES:
            for module in self.roundtrip(DECLARATION, triple):
                self.assert_declaration(module)
                self.assertEqual(module["provenance"]["source_function_count"], 1)
                self.assertEqual(module["globals"], [])
                self.assertEqual(module["aliases"], [])

    def test_called_invalid_signatures_varargs_and_intrinsic_definitions_reject_during_llvm_verification(self):
        bodies = [
            "declare void @llvm.trap(i32)\ndefine void @entry() { call void @llvm.trap(i32 0)\nunreachable }\n",
            "declare i32 @llvm.trap()\ndefine i32 @entry() { %result = call i32 @llvm.trap()\nret i32 %result }\n",
            "declare void @llvm.trap(...)\ndefine void @entry() { call void (...) @llvm.trap()\nunreachable }\n",
            "define void @llvm.trap() { ret void }\n",
        ]
        for triple in TRIPLES:
            for body in bodies:
                with self.subTest(triple=triple, body=body):
                    self.reject_text(body, triple, "llvm-verify")

    def test_unused_invalid_trap_signatures_still_reject_after_successful_llvm_verification_all_three_isas(self):
        for triple in TRIPLES:
            for declaration in ("declare void @llvm.trap(i32)\n", "declare i32 @llvm.trap()\n", "declare void @llvm.trap(...)\n"):
                with self.subTest(triple=triple, declaration=declaration):
                    self.reject_roundtrip(declaration, triple)

    def test_owned_trap_requires_default_visibility_external_linkage_and_c_abi_all_three_isas(self):
        for triple in TRIPLES:
            for declaration in ("declare hidden void @llvm.trap()\n", "declare protected void @llvm.trap()\n",
                                "declare extern_weak void @llvm.trap()\n", "declare fastcc void @llvm.trap()\n"):
                with self.subTest(triple=triple, declaration=declaration):
                    self.reject_roundtrip(declaration, triple)

    def test_trap_callsite_bundles_musttail_abi_unwind_security_and_unknown_metadata_remain_rejected_all_three_isas(self):
        calls = [
            ('call void @llvm.trap() [ "deopt"() ]', "unreachable"),
            ("musttail call void @llvm.trap()", "ret void"),
            ("call fastcc void @llvm.trap()", "unreachable"),
            ("call void @llvm.trap() uwtable", "unreachable"),
            ("call void @llvm.trap() sanitize_memory", "unreachable"),
            ('call void @llvm.trap() "unknown-trap-guard"="1"', "unreachable"),
            ("call void @llvm.trap(), !trap.extra !0", "unreachable"),
        ]
        for triple in TRIPLES:
            for call, terminator in calls:
                with self.subTest(triple=triple, call=call):
                    self.reject_roundtrip(DECLARATION + "define void @entry() {\n" + call + "\n" + terminator + "\n}\n!0 = !{i32 1}\n", triple)

    def test_trap_addresses_relocations_aliases_and_indirect_intrinsic_escapes_reject_in_llvm_verification(self):
        uses = [
            "@address = global ptr @llvm.trap\n",
            "@alias = alias void(), ptr @llvm.trap\n",
            "define ptr @address() { ret ptr @llvm.trap }\n",
            "define ptr @address() { ret ptr getelementptr (i8, ptr @llvm.trap, i64 4) }\n",
            "define void @entry(i1 %condition) { %function = select i1 %condition, ptr @llvm.trap, ptr null\ncall void %function()\nret void }\n",
        ]
        for triple in TRIPLES:
            for use in uses:
                with self.subTest(triple=triple, use=use):
                    self.reject_text(DECLARATION + use, triple, "llvm-verify")

    def test_trap_function_name_codegen_override_rejects_whole_units_including_unused_functions_all_three_isas(self):
        bodies = [
            (DECLARATION + '''
declare void @replacement()
define void @entry() "trap-func-name"="replacement" {
  call void @llvm.trap()
  unreachable
}
''', "entry"),
            (DECLARATION + '''
declare void @replacement()
define void @entry() { call void @llvm.trap()
  unreachable
}
define void @unused() "trap-func-name"="replacement" {
  ret void
}
''', "unused"),
        ]
        for triple in TRIPLES:
            for body, symbol in bodies:
                text = self.write(body, triple)
                for path in (text, self.bitcode(text)):
                    with self.subTest(triple=triple, format=path.suffix, symbol=symbol):
                        with self.assertRaises(importer.ImportFailure) as raised:
                            importer.import_module(path, library_path=self.library)
                        self.assertEqual(raised.exception.stage, "import")
                        self.assertEqual(raised.exception.symbol, symbol)
                        self.assertIn("unsupported string attribute trap-func-name=replacement", str(raised.exception))

    def test_debugtrap_and_ubsantrap_are_independently_unsupported_all_three_isas(self):
        bodies = [
            "declare void @llvm.debugtrap()\n",
            "declare void @llvm.debugtrap()\ndefine void @entry() { call void @llvm.debugtrap()\nret void }\n",
            "declare void @llvm.ubsantrap(i8 immarg)\n",
            "declare void @llvm.ubsantrap(i8 immarg)\ndefine void @entry() { call void @llvm.ubsantrap(i8 3)\nunreachable }\n",
        ]
        for triple in TRIPLES:
            for body in bodies:
                with self.subTest(triple=triple, body=body):
                    self.reject_roundtrip(DECLARATION + body, triple)

    def test_unknown_named_metadata_is_not_admitted_by_trap_support_all_three_isas(self):
        body = DECLARATION + "define void @entry() { call void @llvm.trap()\nunreachable }\n!trap.publication = !{!0}\n!0 = !{i32 1}\n"
        for triple in TRIPLES:
            self.reject_roundtrip(body, triple)

    def test_ordinary_indirect_and_named_calls_keep_their_calls_and_dependencies_all_three_isas(self):
        body = DECLARATION + """
declare void @observe()
define void @ordinary_trap() { call void @observe()
  ret void
}
define void @entry(ptr %function) {
  call void %function()
  call void @ordinary_trap()
  ret void
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assert_declaration(module)
                self.assertEqual({fn["name"] for fn in module["functions"]}, {"llvm.trap", "observe", "ordinary_trap", "entry"})
                entry = self.function(module, "entry")
                calls = self.operations(entry)
                self.assertEqual([op["op"] for op in calls], ["call", "call"])
                self.assertEqual(calls[0]["callee"], {"kind": "value", "id": entry["params"][0]["id"]})
                self.assertEqual(calls[1]["callee"]["name"], "ordinary_trap")
                self.assertEqual(self.operations(self.function(module, "ordinary_trap"))[0]["callee"]["name"], "observe")

    @staticmethod
    def clang_source():
        return """
typedef unsigned long word;
volatile word counter;
extern void observe(word);
__attribute__((noinline, noreturn)) void unconditional(void) {
  counter = 37;
  observe(37);
  __builtin_trap();
}
word conditional(word value) {
  if (value == 9) { observe(value); __builtin_trap(); }
  counter = value;
  return value + 1;
}
__attribute__((cold, noinline)) void unused_cold(void) { __builtin_trap(); }
void trap_callee(void) { unconditional(); }
"""

    def test_actual_clang22_complete_trap_units_keep_effects_inventory_and_ordinary_calls_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "trap-effects.c"
        source.write_text(self.clang_source())
        expected = {"unconditional", "conditional", "unused_cold", "trap_callee", "observe", "llvm.trap"}
        for triple in TRIPLES:
            text = self.compile_clang(clang, source, triple, "ll")
            inventory = set(re.findall(r"^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(", text.read_text(), re.MULTILINE))
            self.assertEqual(inventory, expected)
            modules = []
            for path in (text, self.compile_clang(clang, source, triple, "bc")):
                module = importer.import_module(path, library_path=self.library, frontend="Clang", frontend_version=version)
                modules.append(module)
                self.assert_declaration(module)
                self.assertEqual({fn["name"] for fn in module["functions"]}, inventory)
                self.assertEqual(module["provenance"]["source_function_count"], 6)
                self.assertEqual([glob["name"] for glob in module["globals"]], ["counter"])
                self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(module["provenance"]["frontend_version"], version)
                instructions = self.instructions(self.function(module, "unconditional"))
                self.assertEqual([inst["operation"]["op"] for inst in instructions], ["store", "call", "trap"])
                self.assertTrue(instructions[0]["operation"]["volatile"])
                self.assertEqual(instructions[1]["operation"]["callee"]["name"], "observe")
                self.assert_trap(instructions[2])
                self.assert_trap(self.instructions(self.function(module, "unused_cold"))[0])
                conditional_traps = [inst for inst in self.instructions(self.function(module, "conditional")) if inst["operation"]["op"] == "trap"]
                self.assertEqual(len(conditional_traps), 1)
                self.assert_trap(conditional_traps[0])
                calls = self.operations(self.function(module, "trap_callee"))
                self.assertEqual([op["op"] for op in calls], ["call"])
                self.assertEqual(calls[0]["callee"]["name"], "unconditional")
            self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                             {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})

    def test_actual_clang22_complete_trap_unit_does_not_drop_unused_unsupported_function_all_three_isas_text_and_bitcode(self):
        clang, _ = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "trap-unused-unsupported.c"
        source.write_text(self.clang_source() + "\ndouble unused_unsupported(double value) { return value * 2.0; }\n")
        for triple in TRIPLES:
            for suffix in ("ll", "bc"):
                path = self.compile_clang(clang, source, triple, suffix)
                with self.assertRaises(importer.ImportFailure) as raised:
                    importer.import_module(path, library_path=self.library)
                self.assertEqual(raised.exception.stage, "import")
                self.assertEqual(raised.exception.symbol, "unused_unsupported")


if __name__ == "__main__":
    unittest.main()
