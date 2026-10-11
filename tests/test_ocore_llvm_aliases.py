"""Import symbol aliases without copying bodies or rewriting their references."""

import hashlib
from pathlib import Path
import re
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory


TRIPLES = baseline.TRIPLES


class LlvmAliasImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-alias-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    write = memory.LlvmMemoryImportTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode
    import_ir = memory.LlvmMemoryImportTests.import_ir
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)
    clang_flags = staticmethod(memory.LlvmMemoryImportTests.clang_flags)
    compile_clang = memory.LlvmMemoryImportTests.compile_clang

    def roundtrip(self, body, triple=TRIPLES[0]):
        text_path = self.write(body, triple)
        binary_path = self.bitcode(text_path)
        modules = [importer.import_module(path, library_path=self.library)
                   for path in (text_path, binary_path)]
        self.assertEqual({key: value for key, value in modules[0].items()
                          if key not in {"name", "provenance"}},
                         {key: value for key, value in modules[1].items()
                          if key not in {"name", "provenance"}})
        for path, module in zip((text_path, binary_path), modules):
            self.assertEqual(module["provenance"]["input_sha256"],
                             hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(module["target"]["triple"], triple)
        return modules

    def reject_verified(self, body, stage="import", diagnostic=None, triple=TRIPLES[0]):
        source = self.write(body, triple)
        # The helper separately verifies the complete input before serializing
        # it. A failed parser or verifier cannot hide a missing importer guard.
        for path in (source, self.bitcode(source)):
            with self.assertRaises(importer.ImportFailure) as raised:
                importer.import_module(path, library_path=self.library)
            self.assertEqual(raised.exception.stage, stage)
            self.assertTrue(str(raised.exception).strip())
            if diagnostic is not None:
                self.assertIn(diagnostic, str(raised.exception))

    @staticmethod
    def alias(module, name):
        return next(alias for alias in module["aliases"] if alias["name"] == name)

    def test_all_supported_alias_linkages_visibility_and_references_survive_all_three_isas_text_and_bitcode(self):
        body = """
@function_external = {external_visibility} alias i32 (i32), ptr @target
@function_weak = weak {external_visibility} alias i32 (i32), ptr @target
@function_internal = internal alias i32 (i32), ptr @target
@function_private = private alias i32 (i32), ptr @target
@data_external = {external_visibility} alias i64, ptr @data
@data_weak = weak {external_visibility} alias i64, ptr @data
@data_internal = internal alias i64, ptr @data
@data_private = private alias i64, ptr @data
@array_alias = {external_visibility} alias [2 x i64], ptr @array
@data = global i64 17, align 8
@array = constant [2 x i64] [i64 23, i64 29], align 8
@addresses = constant [3 x ptr] [ptr @function_weak, ptr @data_private, ptr @array_alias], align 8
declare i64 @dependency(i64)
define signext i32 @target(i32 zeroext %value) {{
  %sum = add i32 %value, 7
  ret i32 %sum
}}
define i64 @entry() {{
  %called = call signext i32 @function_external(i32 zeroext 42)
  %wide = sext i32 %called to i64
  %loaded = load i64, ptr @data_external, align 8
  store i64 %wide, ptr @data_external, align 8
  %external = call i64 @dependency(i64 %loaded)
  %sum = add i64 %external, %wide
  ret i64 %sum
}}
define ptr @address() {{ ret ptr @function_private }}
"""
        for triple in TRIPLES:
            for visibility in ("default", "hidden", "protected"):
                with self.subTest(triple=triple, visibility=visibility):
                    modules = self.roundtrip(body.format(
                        external_visibility="" if visibility == "default" else visibility), triple)
                    for module in modules:
                        self.assertEqual(module["provenance"]["source_alias_count"], 9)
                        self.assertEqual(module["provenance"]["source_function_count"], 4)
                        self.assertEqual(module["provenance"]["source_global_count"], 3)
                        self.assertEqual({fn["name"] for fn in module["functions"]},
                                         {"target", "entry", "dependency", "address"})
                        self.assertEqual({glob["name"] for glob in module["globals"]},
                                         {"data", "array", "addresses"})
                        self.assertIsNone(self.function(module, "dependency")["entry"])
                        expected_alias_names = {f"{kind}_{linkage}"
                                                for kind in ("function", "data")
                                                for linkage in ("external", "weak", "internal", "private")} | {"array_alias"}
                        self.assertEqual({alias["name"] for alias in module["aliases"]}, expected_alias_names)
                        for kind in ("function", "data"):
                            for linkage in ("external", "weak", "internal", "private"):
                                alias = self.alias(module, f"{kind}_{linkage}")
                                self.assertEqual(set(alias), {"name", "ty", "aliasee", "linkage", "visibility"})
                                self.assertEqual(alias["aliasee"], "target" if kind == "function" else "data")
                                self.assertEqual(alias["linkage"], linkage)
                                self.assertEqual(alias["visibility"],
                                                 "default" if linkage in {"internal", "private"} else visibility)
                                self.assertIn(
                                    f"{alias['name']}: retained direct zero-offset alias to same-module definition {alias['aliasee']}; "
                                    "calls, addresses and relocations keep the alias name and independent binding/visibility; "
                                    "no body or storage copied and no selected global-name provider substituted",
                                    module["provenance"]["refinements"])
                                value_type = module["types"][alias["ty"]]
                                if kind == "function":
                                    self.assertEqual(value_type["kind"], "function")
                                    signature = value_type["signature"]
                                    self.assertEqual(module["types"][signature["result"]], {"kind": "int", "bits": 32})
                                    self.assertEqual([module["types"][ty] for ty in signature["params"]],
                                                     [{"kind": "int", "bits": 32}])
                                    self.assertFalse(signature["variadic"])
                                else:
                                    self.assertEqual(value_type, {"kind": "int", "bits": 64})
                        array_alias = self.alias(module, "array_alias")
                        array = next(glob for glob in module["globals"] if glob["name"] == "array")
                        self.assertEqual(array_alias["ty"], array["ty"])
                        self.assertEqual(array_alias["aliasee"], "array")
                        self.assertEqual(array_alias["visibility"], visibility)
                        self.assertEqual(array["initializer"]["bytes"], [23] + [0] * 7 + [29] + [0] * 7)
                        addresses = next(glob for glob in module["globals"] if glob["name"] == "addresses")
                        self.assertEqual(addresses["initializer"], {"bytes": [0] * 24, "relocations": [
                            {"offset": offset, "width": 64, "symbol": name, "addend": 0}
                            for offset, name in ((0, "function_weak"), (8, "data_private"), (16, "array_alias"))]})
                        target = self.function(module, "target")
                        self.assertEqual(target["signature"]["param_attributes"], [["zeroext"]])
                        self.assertEqual(target["signature"]["result_attributes"], ["signext"])
                        self.assertEqual([op["op"] for op in self.operations(target)], ["binary"])
                        operations = self.operations(self.function(module, "entry"))
                        self.assertEqual([op["op"] for op in operations],
                                         ["call", "cast", "load", "store", "call", "binary"])
                        self.assertEqual(operations[0]["callee"]["name"], "function_external")
                        self.assertEqual(operations[0]["signature"], target["signature"])
                        self.assertEqual(operations[2]["pointer"]["name"], "data_external")
                        self.assertEqual(operations[3]["pointer"]["name"], "data_external")
                        returned = self.function(module, "address")["blocks"][0]["terminator"]["value"]
                        self.assertEqual(returned["kind"], "symbol")
                        self.assertEqual(returned["name"], "function_private")

    def test_aliases_to_weak_and_local_definitions_retain_distinct_target_bodies_and_storage(self):
        body = """
@weak_alias = alias i64 (i64), ptr @weak_target
@local_alias = alias i64 (i64), ptr @local_target
@storage_alias = alias i64, ptr @private_storage
@private_storage = private global i64 31, align 8
@addresses = global [3 x ptr] [ptr @weak_alias, ptr @weak_target, ptr @storage_alias], align 8
define weak i64 @weak_target(i64 %x) { %v = add i64 %x, 11 ret i64 %v }
define internal i64 @local_target(i64 %x) { %v = sub i64 %x, 13 ret i64 %v }
define i64 @caller(i64 %x) {
  %a = call i64 @weak_alias(i64 %x)
  %b = call i64 @local_alias(i64 %a)
  ret i64 %b
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual({fn["name"] for fn in module["functions"]},
                                     {"weak_target", "local_target", "caller"})
                    self.assertEqual(self.function(module, "weak_target")["linkage"], "weak")
                    self.assertEqual(self.function(module, "local_target")["linkage"], "internal")
                    self.assertEqual(self.operations(self.function(module, "weak_target"))[0]["rhs"]["bits"], "11")
                    self.assertEqual(self.operations(self.function(module, "local_target"))[0]["rhs"]["bits"], "13")
                    self.assertEqual([op["callee"]["name"] for op in self.operations(self.function(module, "caller"))],
                                     ["weak_alias", "local_alias"])
                    storage = next(glob for glob in module["globals"] if glob["name"] == "private_storage")
                    self.assertEqual(storage["linkage"], "private")
                    self.assertEqual(storage["initializer"], {"bytes": [31] + [0] * 7, "relocations": []})
                    addresses = next(glob for glob in module["globals"] if glob["name"] == "addresses")
                    self.assertEqual([reloc["symbol"] for reloc in addresses["initializer"]["relocations"]],
                                     ["weak_alias", "weak_target", "storage_alias"])

    def test_modules_without_aliases_keep_empty_alias_inventory_and_zero_source_count(self):
        for module in self.roundtrip("@data = global i64 7\ndefine i32 @entry() { ret i32 3 }\n"):
            self.assertEqual(module["aliases"], [])
            self.assertEqual(module["provenance"]["source_alias_count"], 0)
            self.assertEqual(module["provenance"]["source_global_count"], 1)
            self.assertEqual(module["provenance"]["source_function_count"], 1)

    def test_unnamed_address_alias_promises_do_not_merge_symbols_or_rewrite_initializer_references(self):
        body = """
@data = constant i64 7
@global_identity = unnamed_addr alias i64, ptr @data
@local_identity = local_unnamed_addr alias i64, ptr @data
@references = constant [3 x ptr] [ptr @global_identity, ptr @local_identity, ptr @data]
"""
        for module in self.roundtrip(body):
            self.assertEqual(module["provenance"]["source_alias_count"], 2)
            self.assertEqual({alias["name"] for alias in module["aliases"]}, {"global_identity", "local_identity"})
            for name in ("global_identity", "local_identity"):
                self.assertEqual(self.alias(module, name)["aliasee"], "data")
                self.assertIn(f"{name}: alias unnamed-address identity optimization assumption erased",
                              module["provenance"]["refinements"])
            self.assertIn("alias contracts validated after pinned LLVM parsing and attribute normalization; "
                          "input_sha256 binds the original bytes", module["provenance"]["refinements"])
            references = next(glob for glob in module["globals"] if glob["name"] == "references")
            self.assertEqual([reloc["symbol"] for reloc in references["initializer"]["relocations"]],
                             ["global_identity", "local_identity", "data"])

    def test_verified_alias_chains_offsets_and_mismatched_value_types_reject_whole_units(self):
        supported = "define i32 @supported() { ret i32 9 }\n"
        cases = (
            "@data = global i64 7\n@first = internal alias i64, ptr @data\n@unused = alias i64, ptr @first\n",
            "@data = global [2 x i64] zeroinitializer\n@unused = alias i64, ptr getelementptr ([2 x i64], ptr @data, i64 0, i64 1)\n",
            "@data = global i64 7\n@unused = alias i32, ptr @data\n",
            "define i64 @target(i64 %x) { ret i64 %x }\n@unused = alias i32 (i32), ptr @target\n",
        )
        for body in cases:
            with self.subTest(body=body):
                self.reject_verified(supported + body)

    def test_nonemitted_alias_targets_and_unsupported_comdat_selections_reject_whole_units(self):
        supported = "define i32 @supported() { ret i32 9 }\n"
        cases = [(
            "@data = available_externally global i64 7\n@unused = available_externally alias i64, ptr @data\n",
            "import")]
        for selection in ("exactmatch", "largest", "samesize"):
            cases += [(
                f"$group = comdat {selection}\n@data = weak global i64 7, comdat($group)\n@unused = alias i64, ptr @data\n",
                "bitcode-audit"), (
                f"$group = comdat {selection}\ndefine weak i64 @target(i64 %x) comdat($group) {{ ret i64 %x }}\n@unused = alias i64 (i64), ptr @target\n",
                "bitcode-audit")]
        for body, stage in cases:
            with self.subTest(body=body):
                self.reject_verified(supported + body, stage=stage)

    def test_hidden_alias_dll_tls_address_space_and_partition_contracts_reject_before_import(self):
        cases = (
            "@data = global i64 7\n@unused = dllexport alias i64, ptr @data\n",
            "@data = thread_local global i64 7\n@unused = thread_local alias i64, ptr @data\n",
            "@data = global i64 7\n@unused = alias i64, ptr addrspace(1) addrspacecast (ptr @data to ptr addrspace(1))\n",
            "@data = global i64 7\n@unused = alias i64, ptr @data, partition \"extra\"\n",
        )
        for body in cases:
            with self.subTest(body=body):
                self.reject_verified("define i32 @supported() { ret i32 9 }\n" + body,
                                     stage="bitcode-audit")

    def test_invalid_aliasees_and_independent_ifunc_abi_section_and_security_contracts_do_not_disappear(self):
        invalid = (
            ("@data = external global i64\n@unused = alias i64, ptr @data\n", "llvm-verify"),
            ("declare i64 @target(i64)\n@unused = alias i64 (i64), ptr @target\n", "llvm-verify"),
            ("@a = internal alias i64, ptr @b\n@b = internal alias i64, ptr @a\n", "llvm-verify"),
            ("declare void @llvm.assume(i1)\n@unused = alias void (i1), ptr @llvm.assume\n", "llvm-verify"),
            ("@data = global i64 7\n@unused = internal hidden alias i64, ptr @data\n", "parse"),
        )
        for body, stage in invalid:
            with self.subTest(body=body):
                with self.assertRaises(importer.ImportFailure) as raised:
                    self.import_ir(body)
                self.assertEqual(raised.exception.stage, stage)
                self.assertTrue(str(raised.exception).strip())
        verified = (
            "define ptr @resolver() { ret ptr null }\n@unused = ifunc i64 (), ptr @resolver\n",
            "define void @target(ptr byval(i64) %x) { ret void }\n@unused = alias void (ptr), ptr @target\n",
            "@data = global i64 7, section \".special\"\n@unused = alias i64, ptr @data\n",
            "define void @target() naked { unreachable }\n@unused = alias void (), ptr @target\n",
            "define void @target() sanitize_address { ret void }\n@unused = alias void (), ptr @target\n",
            "@data = thread_local global i64 7\n@unused = alias i64, ptr @data\n",
        )
        for body in verified:
            with self.subTest(body=body):
                self.reject_verified("define i32 @supported() { ret i32 9 }\n" + body)

    def test_clang22_complete_alias_units_import_unmodified_text_and_bitcode_all_three_isas(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "aliases.c"
        source.write_text("""
typedef unsigned long long word;
volatile word storage = 17;
extern volatile word data_alias __attribute__((alias("storage"), visibility("hidden")));
__attribute__((noinline)) word target(word value) {
    storage += value;
    return storage;
}
extern word function_alias(word) __attribute__((alias("target"), weak, visibility("protected")));
word (*const saved_function)(word) = function_alias;
volatile word *const saved_data = &data_alias;
word drive(word value) {
    word prior = data_alias;
    return function_alias(value) + prior;
}
""")
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                text_path = self.compile_clang(clang, source, triple, "ll")
                llvm_ir = text_path.read_text()
                function_inventory = {name for name in re.findall(
                    r"^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(", llvm_ir, re.MULTILINE)}
                alias_inventory = {name for name in re.findall(
                    r"^@([A-Za-z_][A-Za-z0-9_.$]*)\s*=.*\balias\b", llvm_ir, re.MULTILINE)}
                global_inventory = {name for name in re.findall(
                    r"^@([A-Za-z_][A-Za-z0-9_.$]*)\s*=", llvm_ir, re.MULTILINE)} - alias_inventory
                self.assertEqual(function_inventory, {"target", "drive"})
                self.assertEqual(alias_inventory, {"data_alias", "function_alias"})
                self.assertEqual(global_inventory, {"storage", "saved_function", "saved_data"})
                # Clang itself replaces references to the noninterposable data
                # alias before serializing this unit. Preserve its actual IR;
                # the explicit LLVM fixtures above separately retain both names.
                self.assertRegex(llvm_ir, r"(?m)^@saved_data\s*=.*constant ptr @storage(?:,|$)")
                self.assertRegex(llvm_ir, r"(?m)^@saved_function\s*=.*constant ptr @function_alias(?:,|$)")
                modules = []
                for path in (text_path, self.compile_clang(clang, source, triple, "bc")):
                    module = importer.import_module(path, library_path=self.library,
                                                    frontend="Clang", frontend_version=version)
                    modules.append(module)
                    self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                    self.assertEqual(module["provenance"]["frontend_version"], version)
                    self.assertEqual(module["provenance"]["source_alias_count"], 2)
                    self.assertEqual(module["provenance"]["source_global_count"], 3)
                    self.assertEqual(module["provenance"]["source_function_count"], 2)
                    self.assertEqual({alias["name"] for alias in module["aliases"]}, alias_inventory)
                    self.assertEqual({fn["name"] for fn in module["functions"]}, function_inventory)
                    self.assertEqual({glob["name"] for glob in module["globals"]}, global_inventory)
                    self.assertEqual(self.alias(module, "data_alias")["aliasee"], "storage")
                    self.assertEqual(self.alias(module, "data_alias")["visibility"], "hidden")
                    self.assertEqual(self.alias(module, "function_alias")["aliasee"], "target")
                    self.assertEqual(self.alias(module, "function_alias")["linkage"], "weak")
                    self.assertEqual(self.alias(module, "function_alias")["visibility"], "protected")
                    globals_ = {glob["name"]: glob for glob in module["globals"]}
                    for name, target in (("saved_data", "storage"), ("saved_function", "function_alias")):
                        self.assertEqual(globals_[name]["initializer"], {"bytes": [0] * 8, "relocations": [
                            {"offset": 0, "width": 64, "symbol": target, "addend": 0}]})
                    drive_ops = self.operations(self.function(module, "drive"))
                    calls = [op for op in drive_ops if op["op"] == "call"]
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(calls[0]["callee"]["name"], "function_alias")
                    self.assertTrue(any(op["op"] == "load" and op["volatile"] for op in drive_ops))
                    self.assertTrue(any(op["op"] == "store" and op["volatile"]
                                        for op in self.operations(self.function(module, "target"))))
                self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                                 {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})


if __name__ == "__main__":
    unittest.main()
