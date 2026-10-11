"""Retain explicit typed return storage and the original RISC-V ABI identity."""

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory


TRIPLES = baseline.TRIPLES


class LlvmSretImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-sret-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    write = memory.LlvmMemoryImportTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)

    def roundtrip(self, body, triple):
        text = self.write(body, triple)
        modules = []
        for path in (text, self.bitcode(text)):
            module = importer.import_module(path, library_path=self.library)
            self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(module["target"]["triple"], triple)
            modules.append(module)
        self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                         {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})
        return modules

    def assert_storage(self, module, signature, parameter, payload):
        self.assertEqual(module["types"][signature["result"]], {"kind": "void"})
        storage = signature["return_storage"]
        self.assertEqual(set(storage), {"param", "ty"})
        self.assertEqual(storage["param"], parameter)
        self.assertEqual(module["types"][signature["params"][parameter]], {"kind": "pointer", "address_space": 0})
        self.assertEqual(self.type_shape(module, storage["ty"]), payload)
        self.assertFalse(signature["variadic"])
        self.assertEqual(signature["abi"], "c")
        self.assertEqual(signature["param_attributes"][parameter], [])

    @classmethod
    def type_shape(cls, module, ident):
        ty = module["types"][ident]
        if ty["kind"] == "struct":
            return {"kind": "struct", "packed": ty["packed"], "fields": [cls.type_shape(module, field) for field in ty["fields"]]}
        if ty["kind"] == "array":
            return {"kind": "array", "len": ty["len"], "element": cls.type_shape(module, ty["element"])}
        return ty

    def reject_roundtrip(self, body, triple, diagnostic=None, symbol=None):
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

    def test_typed_first_and_second_storage_parameters_keep_definitions_declarations_alias_calls_and_inventory_all_three_isas_text_and_bitcode(self):
        body = """
%R = type {i64, [2 x i17], ptr}
@first_alias = alias void(ptr, i32), ptr @first
@second_alias = alias void(i8, ptr), ptr @second
@addresses = global [2 x ptr] [ptr @first_alias, ptr @second_alias]
declare void @external_first(ptr sret(%R) align 8, i32 signext)
declare void @external_second(i8 zeroext, ptr sret([3 x i17]))
define void @first(ptr sret(%R) align 16 %out, i32 signext %value) {
  store volatile i64 5, ptr %out, align 8
  ret void
}
define void @second(i8 zeroext %value, ptr sret([3 x i17]) %out) {
  store volatile i17 131071, ptr %out, align 4
  ret void
}
define void @caller(ptr %out, ptr %function0, ptr %function1) {
  call void @first_alias(ptr sret(%R) align 8 %out, i32 signext 7)
  call void @external_first(ptr sret(%R) %out, i32 signext 8)
  call void %function0(ptr sret(%R) %out, i32 signext 9)
  call void @second_alias(i8 zeroext 1, ptr sret([3 x i17]) %out)
  call void @external_second(i8 zeroext 2, ptr sret([3 x i17]) %out)
  call void %function1(i8 zeroext 3, ptr sret([3 x i17]) %out)
  ret void
}
"""
        record = {"kind": "struct", "packed": False, "fields": [
            {"kind": "int", "bits": 64}, {"kind": "array", "len": 2, "element": {"kind": "int", "bits": 17}},
            {"kind": "pointer", "address_space": 0}]}
        array = {"kind": "array", "len": 3, "element": {"kind": "int", "bits": 17}}
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assertEqual({fn["name"] for fn in module["functions"]}, {"first", "second", "external_first", "external_second", "caller"})
                self.assertEqual(module["provenance"]["source_function_count"], 5)
                self.assertEqual(module["provenance"]["source_global_count"], 1)
                self.assertEqual(module["provenance"]["source_alias_count"], 2)
                for name, parameter, payload in (("first", 0, record), ("external_first", 0, record), ("second", 1, array), ("external_second", 1, array)):
                    function = self.function(module, name)
                    self.assert_storage(module, function["signature"], parameter, payload)
                    self.assertEqual(function["signature"]["param_attributes"], [[], ["signext"]] if parameter == 0 else [["zeroext"], []])
                self.assertTrue(self.operations(self.function(module, "first"))[0]["volatile"])
                self.assertTrue(self.operations(self.function(module, "second"))[0]["volatile"])
                self.assertNotIn("return_storage", self.function(module, "caller")["signature"])
                calls = self.operations(self.function(module, "caller"))
                self.assertEqual([call["op"] for call in calls], ["call"] * 6)
                for call in calls[:3]:
                    self.assert_storage(module, call["signature"], 0, record)
                    self.assertEqual(call["args"][0], {"kind": "value", "id": self.function(module, "caller")["params"][0]["id"]})
                for call in calls[3:]:
                    self.assert_storage(module, call["signature"], 1, array)
                    self.assertEqual(call["args"][1], {"kind": "value", "id": self.function(module, "caller")["params"][0]["id"]})
                self.assertEqual(calls[0]["callee"]["name"], "first_alias")
                self.assertEqual(calls[3]["callee"]["name"], "second_alias")
                self.assertTrue(all(calls[index]["callee"]["kind"] == "value" for index in (2, 5)))
                self.assertEqual(module["globals"][0]["initializer"]["relocations"],
                                 [{"offset": 0, "width": 64, "symbol": "first_alias", "addend": 0},
                                  {"offset": 8, "width": 64, "symbol": "second_alias", "addend": 0}])
                for alias in module["aliases"]:
                    self.assertNotIn("return_storage", module["types"][alias["ty"]]["signature"])

    def test_unused_sret_declarations_keep_exact_scalar_array_packed_empty_and_pointer_payloads_all_three_isas(self):
        body = """
declare void @scalar(ptr sret(i7))
declare void @array(ptr sret([2 x i33]))
declare void @packed(ptr sret(<{i8, i64}>))
declare void @empty(ptr sret({}))
declare void @pointer(ptr sret(ptr))
declare void @plain(ptr)
"""
        payloads = {
            "scalar": {"kind": "int", "bits": 7},
            "array": {"kind": "array", "len": 2, "element": {"kind": "int", "bits": 33}},
            "packed": {"kind": "struct", "packed": True, "fields": [{"kind": "int", "bits": 8}, {"kind": "int", "bits": 64}]},
            "empty": {"kind": "struct", "packed": False, "fields": []},
            "pointer": {"kind": "pointer", "address_space": 0},
        }
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assertEqual({fn["name"] for fn in module["functions"]}, set(payloads) | {"plain"})
                self.assertEqual(module["provenance"]["source_function_count"], 6)
                self.assertTrue(all(fn["entry"] is None and not fn["blocks"] for fn in module["functions"]))
                for name, payload in payloads.items():
                    self.assert_storage(module, self.function(module, name)["signature"], 0, payload)
                self.assertNotIn("return_storage", self.function(module, "plain")["signature"])

    def test_alignment_promises_are_recorded_independently_without_callee_or_alias_inference_all_three_isas(self):
        body = """
define void @target(ptr sret(i64) align 32 %out) { store i64 7, ptr %out, align 8
  ret void }
@alias = alias void(ptr), ptr @target
define void @caller(ptr %out) {
  call void @target(ptr sret(i64) align 16 %out)
  call void @alias(ptr sret(i64) %out)
  ret void
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                calls = self.operations(self.function(module, "caller"))
                signature = self.function(module, "target")["signature"]
                self.assertTrue(all(call["signature"] == signature for call in calls))
                refinements = "\n".join(module["provenance"]["refinements"])
                self.assertIn("target: function typed sret parameter 0 retains exact in-memory type and explicit alignment 32", refinements)
                self.assertIn("caller: callsite typed sret parameter 0 retains exact in-memory type and explicit alignment 16", refinements)
                self.assertIn("caller: callsite typed sret parameter 0 retains exact in-memory type and explicit alignment not explicitly specified", refinements)
                self.assertIn("no scalar return or callee attribute inference", refinements)

    def test_llvm_verified_unsized_and_unsupported_sret_payloads_reject_before_layout_use_all_three_isas_text_and_bitcode(self):
        cases = [
            ("%T = type opaque\ndeclare void @unsupported(ptr sret(%T))\n", "supported sized in-memory type"),
            ("declare void @unsupported(ptr sret(void()))\n", "supported sized in-memory type"),
            ("declare void @unsupported(ptr sret(i65))\n", "unsupported integer width i65"),
            ("declare void @unsupported(ptr sret({i32, i128}))\n", "unsupported integer width i128"),
            ("declare void @unsupported(ptr sret(double))\n", "unsupported LLVM type kind"),
            ("declare void @unsupported(ptr sret(<2 x i32>))\n", "unsupported LLVM type kind"),
            ("declare void @unsupported(ptr sret(<vscale x 2 x i32>))\n", "unsupported LLVM type kind"),
            ("declare void @unsupported(ptr sret(ptr addrspace(1)))\n", "unsupported pointer address space 1"),
            ("declare void @unsupported(ptr addrspace(1) sret(i32))\n", "unsupported pointer address space 1"),
        ]
        for triple in TRIPLES:
            for body, diagnostic in cases:
                self.reject_roundtrip("define i64 @supported() { ret i64 9 }\n" + body, triple, diagnostic, "unsupported")

    def test_malformed_sret_contracts_reject_at_the_actual_parse_or_verify_boundary_all_three_isas(self):
        cases = [
            ("declare void @unsupported(ptr sret)\n", "parse"),
            ("declare sret(i32) ptr @unsupported()\n", "parse"),
            ("declare void @unsupported(ptr) sret(i32)\n", "parse"),
            ("declare i32 @unsupported(ptr sret(i32))\n", "parse"),
            ("declare void @unsupported(i64 sret(i32))\n", "llvm-verify"),
            ("declare void @unsupported(ptr sret(i32), ptr sret(i64))\n", "llvm-verify"),
            ("declare void @unsupported(i32, i32, ptr sret(i32))\n", "llvm-verify"),
            ("declare void @unsupported(ptr sret(i32) byval(i32))\n", "llvm-verify"),
        ]
        for triple in TRIPLES:
            for body, stage in cases:
                with self.subTest(triple=triple, body=body):
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(self.write(body, triple), library_path=self.library)
                    self.assertEqual(raised.exception.stage, stage)

    def test_verified_nonvoid_callsite_and_companion_abi_contracts_remain_unsupported_all_three_isas(self):
        cases = [
            ("declare i32 @target(ptr)\ndefine i32 @caller(ptr %out) { %value = call i32 @target(ptr sret(i32) %out)\nret i32 %value }\n", "void result"),
            ("declare void @unsupported(ptr sret(i32) inreg)\n", "unsupported attribute kind"),
            ("declare void @unsupported(ptr sret(i32), ptr byref(i32))\n", "unsupported attribute kind"),
            ("declare void @unsupported(ptr sret(i32), ptr byval(i32))\n", "unsupported attribute kind"),
            ("declare void @unsupported(ptr sret(i32), ...)\n", "variadic calling convention"),
            ("declare void @target(ptr sret(i32))\ndefine void @caller(ptr sret(i32) %out) { musttail call void @target(ptr sret(i32) %out)\nret void }\n", "musttail"),
        ]
        for triple in TRIPLES:
            for body, diagnostic in cases:
                self.reject_roundtrip(body, triple, diagnostic)

    def test_function_and_callsite_storage_contracts_stay_explicit_for_mandatory_native_abi_validation_without_inference_all_three_isas(self):
        body = """
declare void @declared(ptr sret(i32))
declare void @plain(ptr)
define void @target(ptr sret(i32) %out) { ret void }
@alias = alias void(ptr), ptr @target
define void @caller(ptr %out, ptr %function) {
  call void @declared(ptr %out)
  call void @declared(ptr sret(i64) %out)
  call void @plain(ptr sret(i32) %out)
  call void @alias(ptr %out)
  call void %function(ptr sret(i7) %out)
  ret void
}
"""
        # LLVM verification accepts these ABI disagreements. Source extraction
        # retains them; this is not native admission. The native verifier must
        # compare explicit call contracts against resolved function/alias ABI.
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assert_storage(module, self.function(module, "declared")["signature"], 0, {"kind": "int", "bits": 32})
                self.assertNotIn("return_storage", self.function(module, "plain")["signature"])
                calls = self.operations(self.function(module, "caller"))
                self.assertNotIn("return_storage", calls[0]["signature"])
                self.assert_storage(module, calls[1]["signature"], 0, {"kind": "int", "bits": 64})
                self.assert_storage(module, calls[2]["signature"], 0, {"kind": "int", "bits": 32})
                self.assertNotIn("return_storage", calls[3]["signature"])
                self.assertEqual(calls[3]["callee"]["name"], "alias")
                self.assert_storage(module, calls[4]["signature"], 0, {"kind": "int", "bits": 7})
                self.assertEqual(calls[4]["callee"]["kind"], "value")

    def test_riscv_lp64_and_lp64d_flags_preserve_exact_original_triples_without_float_admission_text_and_bitcode(self):
        for triple in (TRIPLES[2], "riscv64"):
            for abi in ("lp64", "lp64d"):
                body = 'declare void @unused(ptr sret(i64))\n!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"' + abi + '"}\n'
                for module in self.roundtrip(body, triple):
                    self.assertEqual(module["target"]["abi"], abi)
                    self.assertEqual(module["target"]["triple"], triple)
                    self.assertIn("verified RISC-V " + abi + " target ABI", module["provenance"]["refinements"])
        for abi in ("lp64", "lp64d"):
            for triple in TRIPLES[:2]:
                self.reject_roundtrip('!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"' + abi + '"}\n', triple, "unsupported target ABI")
        for abi in ("lp64f", "lp64e", "lp64q", "ilp32", ""):
            self.reject_roundtrip('!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"' + abi + '"}\n', TRIPLES[2], "unsupported target ABI")
        self.reject_roundtrip('declare double @unsupported(double)\n!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"lp64d"}\n', TRIPLES[2], "unsupported LLVM type kind", "unsupported")

    def test_lp64d_feature_tokens_obey_order_known_dependencies_and_qualified_unknown_implication_limits(self):
        positive = ("", "-d,+d", "-f,+d", "-zicsr,+v", "-d,+v", "-d,+q", "-d,+zcd",
                    "-d,+zve64d", "+e,-e", "-d,+unmodeled,+d", "-d,+f,+d")
        negative = ("-d", "-f", "+d,-f", "+d,-zicsr", "-d,+f", "-d,+zicsr")
        for feature in positive:
            body = 'declare void @unused(ptr sret(i64)) "target-features"="' + feature + '"\n!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"lp64d"}\n'
            for module in self.roundtrip(body, TRIPLES[2]):
                self.assertEqual(module["target"]["abi"], "lp64d")
                refinements = "\n".join(module["provenance"]["refinements"])
                self.assertIn("declared own RV64GC D/F/Zicsr-enabled, E-disabled execution profile", refinements)
                self.assertIn("no original CPU normalization or ABI inference", refinements)
        for feature in negative:
            body = 'declare void @unsupported(ptr sret(i64)) "target-features"="' + feature + '"\n!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"lp64d"}\n'
            self.reject_roundtrip(body, TRIPLES[2], "requires enabled D/F/Zicsr", "unsupported")
        self.reject_roundtrip('declare void @unsupported(ptr sret(i64)) "target-features"="+e"\n!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"lp64d"}\n', TRIPLES[2], "conflicts with the enabled E", "unsupported")
        # The bounded profile does not prove arbitrary positive dependencies.
        # A verified sequence that might restore D is explicitly unsupported,
        # rather than mislabeled a contradiction or silently normalized.
        self.reject_roundtrip('declare void @unsupported(ptr sret(i64)) "target-features"="-d,+unmodeled"\n!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"lp64d"}\n', TRIPLES[2], "unsupported lp64d target-feature implication sequence", "unsupported")

    @staticmethod
    def clang_source():
        return '''typedef unsigned long word;
struct Big { word first; word second; word third; };
struct Big record = { 1, 2, 3 };
struct Big make_big(word value) {
  struct Big result = { value, value ^ 37, value + 5 };
  return result;
}
extern struct Big make_alias(word) __attribute__((alias("make_big")));
typedef struct Big (*Factory)(word);
Factory factory = make_alias;
extern struct Big external_big(word);
struct Big invoke_external(word value) { return external_big(value); }
struct Big invoke_indirect(Factory function, word value) { return function(value); }
'''

    def compile_clang(self, clang, source, triple, abi, suffix):
        output = self.directory / f"{source.stem}-{triple}-{abi}.{suffix}"
        target_flags = ["-march=rv64gc", "-mabi=" + abi] if abi else []
        command = [clang, "--target=" + triple, *target_flags, *memory.LlvmMemoryImportTests.clang_flags(),
                   "-S" if suffix == "ll" else "-c", str(source), "-o", str(output)]
        completed = subprocess.run(command, cwd=baseline.ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output

    def test_actual_clang22_complete_aggregate_return_units_preserve_sret_void_signatures_calls_and_globals_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "whole-sret.c"
        source.write_text(self.clang_source())
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        payload = {"kind": "struct", "packed": False, "fields": [{"kind": "int", "bits": 64}] * 3}
        for triple, abi in ((TRIPLES[0], None), (TRIPLES[1], None), (TRIPLES[2], "lp64"), (TRIPLES[2], "lp64d")):
            modules = []
            for suffix in ("ll", "bc"):
                with self.subTest(triple=triple, abi=abi, format=suffix):
                    path = self.compile_clang(clang, source, triple, abi, suffix)
                    module = importer.import_module(path, library_path=self.library, frontend="Clang C", frontend_version=version)
                    modules.append(module)
                    self.assertEqual(module["target"]["triple"], triple)
                    self.assertEqual(module["target"].get("abi"), abi)
                    self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                    self.assertEqual(module["provenance"]["frontend_version"], version)
                    self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)
                    self.assertEqual({fn["name"] for fn in module["functions"]}, {"make_big", "external_big", "invoke_external", "invoke_indirect"})
                    self.assertEqual({glob["name"] for glob in module["globals"]}, {"record", "factory"})
                    self.assertEqual([(alias["name"], alias["aliasee"]) for alias in module["aliases"]], [("make_alias", "make_big")])
                    self.assertEqual((module["provenance"]["source_function_count"], module["provenance"]["source_global_count"], module["provenance"]["source_alias_count"]), (4, 2, 1))
                    for function in module["functions"]:
                        self.assert_storage(module, function["signature"], 0, payload)
                    for name in ("invoke_external", "invoke_indirect"):
                        function = self.function(module, name)
                        calls = [op for op in self.operations(function) if op["op"] == "call"]
                        self.assertEqual(len(calls), 1)
                        self.assert_storage(module, calls[0]["signature"], 0, payload)
                        self.assertEqual(calls[0]["args"][0], {"kind": "value", "id": function["params"][0]["id"]})
                        self.assertEqual(function["blocks"][-1]["terminator"], {"op": "return", "value": None})
                    self.assertEqual(self.operations(self.function(module, "invoke_external"))[0]["callee"]["name"], "external_big")
                    self.assertEqual(self.operations(self.function(module, "invoke_indirect"))[0]["callee"]["kind"], "value")
                    self.assertEqual(sum(op["op"] == "store" for op in self.operations(self.function(module, "make_big"))), 3)
                    globals_ = {glob["name"]: glob for glob in module["globals"]}
                    self.assertEqual(globals_["record"]["initializer"]["bytes"], list(b"".join(value.to_bytes(8, "little") for value in (1, 2, 3))))
                    # LLVM canonicalizes the source alias initializer to its
                    # same-module definition; the independent alias remains.
                    self.assertEqual(globals_["factory"]["initializer"]["relocations"], [{"offset": 0, "width": 64, "symbol": "make_big", "addend": 0}])
            self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                             {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})

    def test_actual_clang22_complete_units_reject_unused_floating_sret_payload_without_dropping_function_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "whole-sret-with-floating.c"
        source.write_text(self.clang_source() + '''struct Bad { double first; double second; double third; double fourth; double fifth; };
struct Bad unsupported_factory(word value) {
  struct Bad result = { (double)value, 1.5, 2.5, 3.5, 4.5 };
  return result;
}
''')
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        for triple, abi in ((TRIPLES[0], None), (TRIPLES[1], None), (TRIPLES[2], "lp64d")):
            for suffix in ("ll", "bc"):
                path = self.compile_clang(clang, source, triple, abi, suffix)
                with self.subTest(triple=triple, abi=abi, format=suffix):
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(path, library_path=self.library, frontend="Clang C", frontend_version=version)
                    self.assertEqual(raised.exception.stage, "import")
                    self.assertEqual(raised.exception.symbol, "unsupported_factory")
                    self.assertIn("unsupported LLVM type kind", str(raised.exception))
                    self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)


if __name__ == "__main__":
    unittest.main()
