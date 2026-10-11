"""Preserve referenced COMDAT groups and binding without dropping members."""

import hashlib
import re
import subprocess
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_aliases as aliases
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory


TRIPLES = baseline.TRIPLES
INVENTORY_NOTE = (
    "COMDAT inventory includes every group referenced by verified normalized LLVM globals/functions; "
    "unused nonexecutable declarations omitted by LLVM serialization are bound only by original "
    "input_sha256, not counted as executable groups"
)


class LlvmComdatImportTests(unittest.TestCase):
    setUpClass = classmethod(aliases.LlvmAliasImportTests.setUpClass.__func__)
    setUp = aliases.LlvmAliasImportTests.setUp
    write = memory.LlvmMemoryImportTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode
    import_ir = memory.LlvmMemoryImportTests.import_ir
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)
    alias = staticmethod(aliases.LlvmAliasImportTests.alias)
    roundtrip = aliases.LlvmAliasImportTests.roundtrip
    reject_verified = aliases.LlvmAliasImportTests.reject_verified

    @staticmethod
    def groups(module):
        return {group["name"]: group["selection"] for group in module["comdats"]}

    def test_mixed_groups_keep_cold_local_members_aliases_and_initializer_relocations_all_three_isas_text_and_bitcode(self):
        body = """
$"_packet.any.$" = comdat any
$"_packet.keep.9" = comdat nodeduplicate
@data = linkonce_odr hidden global i64 11, comdat($"_packet.any.$"), align 8
@references = weak_odr protected constant [3 x ptr] [ptr @function_alias, ptr @data_alias, ptr @keep], comdat($"_packet.any.$"), align 8
@associated = private constant i64 41, comdat($"_packet.any.$"), align 8
@keep_data = weak global i64 17, comdat($"_packet.keep.9"), align 8
@outside = global i64 5, align 8
@function_alias = weak_odr alias i64 (i64), ptr @member
@data_alias = linkonce_odr alias i64, ptr @data
declare i64 @dependency(i64)
define linkonce_odr hidden i64 @member(i64 %x) comdat($"_packet.any.$") {
  %value = load i64, ptr @data, align 8
  %result = add i64 %x, %value
  ret i64 %result
}
define internal void @cold_member() cold comdat($"_packet.any.$") {
  store i64 97, ptr @outside, align 8
  ret void
}
define weak_odr i64 @keep(i64 %x) comdat($"_packet.keep.9") {
  %result = add i64 %x, 19
  ret i64 %result
}
define i64 @entry(i64 %x) {
  %called = call i64 @function_alias(i64 %x)
  %loaded = load i64, ptr @data_alias, align 8
  %sum = add i64 %called, %loaded
  %result = call i64 @dependency(i64 %sum)
  ret i64 %result
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual(self.groups(module), {"_packet.any.$": "any", "_packet.keep.9": "no_deduplicate"})
                    self.assertEqual(module["provenance"]["referenced_comdat_count"], 2)
                    self.assertNotIn("source_comdat_count", module["provenance"])
                    self.assertEqual(module["provenance"]["source_function_count"], 5)
                    self.assertEqual(module["provenance"]["source_global_count"], 5)
                    self.assertEqual(module["provenance"]["source_alias_count"], 2)
                    self.assertIn(INVENTORY_NOTE, module["provenance"]["refinements"])
                    functions = {fn["name"]: fn for fn in module["functions"]}
                    globals_ = {glob["name"]: glob for glob in module["globals"]}
                    self.assertEqual(set(functions), {"member", "cold_member", "keep", "entry", "dependency"})
                    self.assertEqual(set(globals_), {"data", "references", "associated", "keep_data", "outside"})
                    self.assertEqual({name: fn["comdat"] for name, fn in functions.items()}, {
                        "member": "_packet.any.$", "cold_member": "_packet.any.$", "keep": "_packet.keep.9",
                        "entry": None, "dependency": None})
                    self.assertEqual({name: glob["comdat"] for name, glob in globals_.items()}, {
                        "data": "_packet.any.$", "references": "_packet.any.$", "associated": "_packet.any.$",
                        "keep_data": "_packet.keep.9", "outside": None})
                    self.assertEqual(functions["member"]["linkage"], "linkonce_odr")
                    self.assertEqual(functions["keep"]["linkage"], "weak_odr")
                    self.assertEqual(globals_["references"]["linkage"], "weak_odr")
                    self.assertEqual(globals_["keep_data"]["linkage"], "weak")
                    self.assertEqual(globals_["associated"]["linkage"], "private")
                    self.assertEqual(globals_["data"]["visibility"], "hidden")
                    self.assertEqual(globals_["references"]["visibility"], "protected")
                    self.assertIsNone(functions["dependency"]["entry"])
                    self.assertEqual(self.operations(functions["cold_member"])[0]["value"]["bits"], "97")
                    self.assertEqual(self.operations(functions["cold_member"])[0]["op"], "store")
                    self.assertEqual(globals_["associated"]["initializer"], {"bytes": [41] + [0] * 7, "relocations": []})
                    self.assertEqual(globals_["references"]["initializer"], {"bytes": [0] * 24, "relocations": [
                        {"offset": offset, "width": 64, "symbol": name, "addend": 0}
                        for offset, name in ((0, "function_alias"), (8, "data_alias"), (16, "keep"))]})
                    for alias, target in (("function_alias", "member"), ("data_alias", "data")):
                        self.assertEqual(self.alias(module, alias)["aliasee"], target)
                        self.assertNotIn("comdat", self.alias(module, alias))
                    operations = self.operations(functions["entry"])
                    self.assertEqual(operations[0]["callee"]["name"], "function_alias")
                    self.assertEqual(operations[1]["pointer"]["name"], "data_alias")

    def test_linkonce_and_odr_definitions_without_groups_keep_exact_linkage_and_full_inventory(self):
        linkages = ("linkonce", "linkonce_odr", "weak_odr", "weak")
        body = "\n".join(f"@data_{linkage} = {linkage} global i64 {index}, align 8\n"
                         f"define {linkage} i64 @function_{linkage}(i64 %x) {{ %v = add i64 %x, {index} ret i64 %v }}"
                         for index, linkage in enumerate(linkages, 1))
        names = [f"{kind}_{linkage}" for linkage in linkages for kind in ("data", "function")]
        body += "\n@all_references = constant [8 x ptr] [" + ", ".join(f"ptr @{name}" for name in names) + "]\n"
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual(module["comdats"], [])
                    self.assertEqual(module["provenance"]["referenced_comdat_count"], 0)
                    self.assertEqual(module["provenance"]["source_function_count"], 4)
                    self.assertEqual(module["provenance"]["source_global_count"], 5)
                    for index, linkage in enumerate(linkages, 1):
                        fn = self.function(module, f"function_{linkage}")
                        glob = next(glob for glob in module["globals"] if glob["name"] == f"data_{linkage}")
                        self.assertEqual(fn["linkage"], linkage)
                        self.assertEqual(glob["linkage"], linkage)
                        self.assertIsNone(fn["comdat"])
                        self.assertIsNone(glob["comdat"])
                        self.assertEqual(self.operations(fn)[0]["rhs"]["bits"], str(index))
                        self.assertEqual(glob["initializer"], {"bytes": [index] + [0] * 7, "relocations": []})
                    references = next(glob for glob in module["globals"] if glob["name"] == "all_references")
                    self.assertEqual([reloc["symbol"] for reloc in references["initializer"]["relocations"]], names)

    def test_every_supported_alias_binding_inherits_target_group_without_copying_target_visibility_or_abi(self):
        linkages = ("external", "internal", "private", "weak", "linkonce", "linkonce_odr", "weak_odr")
        alias_lines = "\n".join(f"@alias_{linkage} = {'' if linkage == 'external' else linkage} alias i32 (i32), ptr @target"
                                for linkage in linkages)
        names = [f"alias_{linkage}" for linkage in linkages]
        for triple in TRIPLES:
            for visibility in ("default", "hidden", "protected"):
                keyword = "" if visibility == "default" else visibility
                body = ("$target.group = comdat any\n" + alias_lines +
                        "\n@references = constant [7 x ptr] [" + ", ".join(f"ptr @{name}" for name in names) + "]\n" +
                        f"define weak_odr {keyword} signext i32 @target(i32 zeroext %x) comdat($target.group) {{ ret i32 %x }}\n" +
                        "define signext i32 @caller(i32 zeroext %x) { %v = call signext i32 @alias_weak_odr(i32 zeroext %x) ret i32 %v }\n")
                with self.subTest(triple=triple, target_visibility=visibility):
                    for module in self.roundtrip(body, triple):
                        self.assertEqual(self.groups(module), {"target.group": "any"})
                        self.assertEqual(module["provenance"]["source_alias_count"], 7)
                        self.assertEqual({fn["name"] for fn in module["functions"]}, {"target", "caller"})
                        target = self.function(module, "target")
                        self.assertEqual(target["visibility"], visibility)
                        self.assertEqual(target["comdat"], "target.group")
                        for linkage in linkages:
                            alias = self.alias(module, f"alias_{linkage}")
                            self.assertEqual(alias["linkage"], linkage)
                            self.assertEqual(alias["visibility"], "default")
                            self.assertEqual(alias["aliasee"], "target")
                            self.assertEqual(set(alias), {"name", "ty", "aliasee", "linkage", "visibility"})
                        call = self.operations(self.function(module, "caller"))[0]
                        self.assertEqual(call["callee"]["name"], "alias_weak_odr")
                        self.assertEqual(call["signature"], target["signature"])
                        self.assertEqual(call["signature"]["param_attributes"], [["zeroext"]])
                        self.assertEqual(call["signature"]["result_attributes"], ["signext"])
                        self.assertEqual([reloc["symbol"] for reloc in module["globals"][0]["initializer"]["relocations"]], names)

    def test_unsupported_referenced_selection_rejects_unused_cold_members_on_all_three_isas(self):
        for triple in TRIPLES:
            for selection in ("exactmatch", "largest", "samesize"):
                with self.subTest(triple=triple, selection=selection):
                    body = (f"$group = comdat {selection}\n"
                            "@unused_data = linkonce_odr global i64 7, comdat($group)\n"
                            "define internal void @unused_cold() cold comdat($group) { ret void }\n"
                            "define i32 @entry() { ret i32 9 }\n")
                    self.reject_verified(body, stage="bitcode-audit", triple=triple)

    def test_unused_group_declarations_follow_qualified_normalization_without_losing_executable_members(self):
        body = """
$unused.any = comdat any
$unused.keep = comdat nodeduplicate
$unused.exact = comdat exactmatch
$unused.largest = comdat largest
$unused.size = comdat samesize
$used = comdat any
@data = linkonce_odr global i64 23, comdat($used)
@data_alias = alias i64, ptr @data
define i32 @entry() { ret i32 9 }
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual(self.groups(module), {"used": "any"})
                    self.assertEqual(module["provenance"]["referenced_comdat_count"], 1)
                    self.assertIn(INVENTORY_NOTE, module["provenance"]["refinements"])
                    self.assertEqual(module["provenance"]["source_global_count"], 1)
                    self.assertEqual(module["provenance"]["source_function_count"], 1)
                    self.assertEqual(module["provenance"]["source_alias_count"], 1)
                    self.assertEqual(module["globals"][0]["comdat"], "used")
                    self.assertEqual(self.alias(module, "data_alias")["aliasee"], "data")

    def test_declaration_members_invalid_definition_linkages_and_duplicate_keys_reject_at_honest_stages(self):
        cases = (
            ("$group = comdat any\ndeclare i64 @decl(i64) comdat($group)\n", "llvm-verify"),
            ("$group = comdat any\n@decl = external global i64, comdat($group)\n", "llvm-verify"),
            ("$group = comdat any\n@decl = available_externally global i64 7, comdat($group)\n", "llvm-verify"),
            ("$group = comdat any\n$group = comdat nodeduplicate\n@data = global i64 7, comdat($group)\n", "parse"),
            *((f"declare {linkage} void @decl()\n", "parse")
              for linkage in ("linkonce", "linkonce_odr", "weak_odr")),
            ('$"bad\\00group" = comdat any\n@data = global i64 7, comdat($"bad\\00group")\n', "parse"),
        )
        for body, stage in cases:
            with self.subTest(body=body):
                with self.assertRaises(importer.ImportFailure) as raised:
                    self.import_ir(body)
                self.assertEqual(raised.exception.stage, stage)
                self.assertTrue(str(raised.exception).strip())

    def test_supported_groups_do_not_admit_independent_dll_section_tls_abi_security_or_floating_contracts(self):
        cases = (
            "define dllexport i64 @target(i64 %x) comdat($group) { ret i64 %x }\n",
            '@data = global i64 7, section ".special", comdat($group)\n',
            'define i64 @target(i64 %x) section ".special" comdat($group) { ret i64 %x }\n',
            "@data = thread_local global i64 7, comdat($group)\n",
            "define linkonce_odr void @target(ptr byval(i64) %x) comdat($group) { ret void }\n",
            "define weak_odr void @target() naked comdat($group) { unreachable }\n",
            "define linkonce void @target() sanitize_address comdat($group) { ret void }\n",
            "define weak_odr double @unused(double %x) cold comdat($group) { ret double %x }\n",
            "@data = available_externally global i64 7\n",
            "declare extern_weak void @unused()\n",
        )
        for body in cases:
            with self.subTest(body=body):
                self.reject_verified("$group = comdat any\ndefine i32 @entry() { ret i32 9 }\n" + body)

    def test_verified_non_utf8_group_names_reject_at_the_fresh_bitcode_audit_boundary(self):
        self.reject_verified('$"bad\\FFgroup" = comdat any\n@data = global i64 7, comdat($"bad\\FFgroup")\n',
                             stage="bitcode-audit")

    @staticmethod
    def cpp_source():
        return """
typedef unsigned long long word;
template<class T> struct State { static T count; };
template<class T> T State<T>::count = 5;
template<class T> __attribute__((noinline, cold)) T step(T value) {
    State<T>::count += value;
    return State<T>::count;
}
struct Counter {
    word value;
    __attribute__((noinline)) Counter(word);
    __attribute__((noinline, cold)) word add(word);
};
Counter::Counter(word initial) : value(initial) {}
inline word Counter::add(word increment) { value += increment; return value; }
extern "C" word drive(word value) {
    Counter counter(value);
    return step(counter.add(3));
}
"""

    def compile_cpp(self, clang, source, triple, suffix):
        output = self.directory / f"{source.stem}-{triple}.{suffix}"
        target_flags = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
        command = [clang, "--target=" + triple, *target_flags, *memory.LlvmMemoryImportTests.clang_flags(),
                   "-std=c++17", "-fno-exceptions", "-fno-rtti", "-S" if suffix == "ll" else "-c",
                   str(source), "-o", str(output)]
        completed = subprocess.run(command, cwd=baseline.ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output

    def test_clang22_complete_cpp_odr_constructor_alias_units_import_unmodified_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "comdats.cpp"
        source.write_text(self.cpp_source())
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                text_path = self.compile_cpp(clang, source, triple, "ll")
                raw_ir = text_path.read_text()
                function_inventory = set(re.findall(r"^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(", raw_ir, re.MULTILINE))
                alias_inventory = set(re.findall(r"^@([A-Za-z_][A-Za-z0-9_.$]*)\s*=.*\balias\b", raw_ir, re.MULTILINE))
                global_inventory = set(re.findall(r"^@([A-Za-z_][A-Za-z0-9_.$]*)\s*=", raw_ir, re.MULTILINE)) - alias_inventory
                group_inventory = dict(re.findall(r"^\$([A-Za-z_][A-Za-z0-9_.$]*)\s*=\s*comdat\s+(\w+)", raw_ir, re.MULTILINE))
                self.assertGreaterEqual(len(group_inventory), 3)
                self.assertTrue(alias_inventory, "the complete constructor alias must remain present")
                self.assertIn("linkonce_odr", raw_ir)
                self.assertIn("cold", raw_ir)
                drive_ir = re.search(r"^define\b[^\n]*@drive\([^\n]*\)[^\n]*\{\n(.*?)^\}",
                                     raw_ir, re.MULTILINE | re.DOTALL).group(1)
                produced_calls = re.findall(r"\bcall\s+[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)", drive_ir)
                ordinary_calls = [name for name in produced_calls if not name.startswith("llvm.")]
                self.assertEqual(len(ordinary_calls), 3)
                self.assertEqual({name for name in produced_calls if name.startswith("llvm.")},
                                 {"llvm.lifetime.start.p0", "llvm.lifetime.end.p0"})
                modules = []
                for path in (text_path, self.compile_cpp(clang, source, triple, "bc")):
                    module = importer.import_module(path, library_path=self.library, frontend="Clang C++", frontend_version=version)
                    modules.append(module)
                    self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                    self.assertEqual(module["provenance"]["frontend_version"], version)
                    self.assertEqual({fn["name"] for fn in module["functions"]}, function_inventory)
                    self.assertEqual({glob["name"] for glob in module["globals"]}, global_inventory)
                    self.assertEqual({alias["name"] for alias in module["aliases"]}, alias_inventory)
                    self.assertEqual(self.groups(module), group_inventory)
                    self.assertEqual(module["provenance"]["referenced_comdat_count"], len(group_inventory))
                    self.assertEqual(module["provenance"]["source_function_count"], len(function_inventory))
                    self.assertEqual(module["provenance"]["source_global_count"], len(global_inventory))
                    self.assertEqual(module["provenance"]["source_alias_count"], len(alias_inventory))
                    self.assertIn(INVENTORY_NOTE, module["provenance"]["refinements"])
                    members = [item for item in module["functions"] + module["globals"] if item["comdat"] is not None]
                    self.assertTrue(any("step" in item["name"] and item["linkage"] == "linkonce_odr" for item in members))
                    self.assertTrue(any("add" in item["name"] and item["linkage"] == "linkonce_odr" for item in members))
                    self.assertTrue(any("count" in item["name"] and item["linkage"] == "linkonce_odr" for item in members))
                    definitions = {fn["name"]: fn for fn in module["functions"] if fn["entry"] is not None}
                    for alias in module["aliases"]:
                        self.assertIn(alias["aliasee"], definitions)
                        self.assertNotIn("comdat", alias)
                    drive_ops = self.operations(self.function(module, "drive"))
                    self.assertEqual([op["callee"]["name"] for op in drive_ops if op["op"] == "call"], ordinary_calls)
                    self.assertEqual([op["end"] for op in drive_ops if op["op"] == "lifetime"], [False, True])
                self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                                 {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})

    def test_clang22_complete_cpp_unit_with_unused_unsupported_definition_rejects_without_filtering_all_three_isas_text_and_bitcode(self):
        clang, _ = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "unsupported.cpp"
        source.write_text(self.cpp_source() + '\nextern "C" double unused_unsupported(double value) { return value; }\n')
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for suffix in ("ll", "bc"):
                    path = self.compile_cpp(clang, source, triple, suffix)
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(path, library_path=self.library)
                    self.assertEqual(raised.exception.stage, "import")
                    self.assertEqual(raised.exception.symbol, "unused_unsupported")


if __name__ == "__main__":
    unittest.main()
