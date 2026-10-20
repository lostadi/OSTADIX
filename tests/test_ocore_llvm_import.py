"""Exercise real LLVM import, including frontend IR; no native code is emitted."""

import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts import ocore_llvm_import as importer


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/ocore_llvm_import.py"
LAYOUT = "e-p:64:64-i64:64-n8:16:32:64-S128"
TRIPLES = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "riscv64-unknown-linux-gnu",
)


def llvm_library():
    """Select an explicit LLVM ELF or the default Rust LLVM, never a linker script."""
    override = os.environ.get("OCORE_TEST_LLVM_LIBRARY")
    if override:
        candidates = [Path(override)]
    else:
        rustc = shutil.which("rustc")
        if rustc is None:
            raise unittest.SkipTest("Rust LLVM shared library unavailable")
        sysroot = Path(subprocess.check_output(
            [rustc, "--print", "sysroot"], text=True, timeout=15).strip())
        candidates = sorted((sysroot / "lib").glob("libLLVM*.so*"))
    for candidate in candidates:
        if candidate.is_file():
            with candidate.open("rb") as stream:
                if stream.read(4) == b"\x7fELF":
                    return candidate.resolve()
    raise unittest.SkipTest("Rust LLVM ELF shared library unavailable")


class LlvmImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = llvm_library()
        override = os.environ.get("OCORE_TEST_LLVM_LIBRARY")
        expected = os.environ.get("OCORE_TEST_LLVM_SHA256")
        if expected and not override:
            raise RuntimeError("OCORE_TEST_LLVM_SHA256 requires OCORE_TEST_LLVM_LIBRARY")
        cls.library_sha256 = expected if override and expected else importer.PINNED_SHA256
        if not re.fullmatch(r"[0-9a-f]{64}", cls.library_sha256):
            raise RuntimeError("the explicit LLVM parser pin must be a lowercase SHA-256")
        if hashlib.sha256(cls.library.read_bytes()).hexdigest() != cls.library_sha256:
            raise RuntimeError("the actual LLVM parser differs from its selected test pin")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-import-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    def write(self, body, triple=TRIPLES[0], layout=LAYOUT):
        header = f'target triple = "{triple}"\ntarget datalayout = "{layout}"\n'
        self.source.write_text(header + body, encoding="utf-8")
        return self.source

    def import_ir(self, body, **kwargs):
        return importer.import_module(self.write(body, **kwargs), library_path=self.library, expected_sha256=self.library_sha256)

    def reject(self, body, stage="import", **kwargs):
        with self.assertRaises(importer.ImportFailure) as raised:
            self.import_ir(body, **kwargs)
        self.assertTrue(str(raised.exception).strip(), "rejection needs a diagnostic")
        self.assertEqual(raised.exception.stage, stage,
                         "a toolchain failure must not masquerade as an input rejection")

    def function(self, module, name):
        return next(function for function in module["functions"] if function["name"] == name)

    def operations(self, function):
        return [instruction["operation"]
                for block in function["blocks"] for instruction in block["instructions"]]

    def test_inventory_target_and_input_provenance_on_all_three_isas(self):
        body = """
@counter = global i64 0, align 8
@external = external global i32
declare i64 @foreign(i64)
define i64 @entry(i64 %value) {
  %result = call i64 @foreign(i64 %value)
  ret i64 %result
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir(body, triple=triple)
                self.assertEqual(module["format"], "ocore-native-module-v1")
                self.assertEqual(module["semantics"], "llvm_defined_behavior_v1")
                self.assertEqual(module["target"]["triple"], triple)
                self.assertEqual(module["target"]["data_layout"], LAYOUT)
                self.assertEqual(module["target"]["pointer_bits"], 64)
                self.assertTrue(module["target"]["little_endian"])
                self.assertNotIn("abi", module["target"], "no explicit ABI metadata was supplied")
                self.assertEqual({function["name"] for function in module["functions"]},
                                 {"foreign", "entry"})
                self.assertEqual({glob["name"] for glob in module["globals"]},
                                 {"counter", "external"})
                provenance = module["provenance"]
                self.assertEqual(provenance["source_function_count"], 2)
                self.assertEqual(provenance["source_global_count"], 2)
                self.assertEqual(provenance["input_sha256"],
                                 hashlib.sha256(self.source.read_bytes()).hexdigest())
                external = next(glob for glob in module["globals"] if glob["name"] == "external")
                self.assertIsNone(external["initializer"])
                self.assertIsNone(self.function(module, "foreign")["entry"])
                self.assertEqual(self.function(module, "foreign")["blocks"], [])

    def test_weak_definitions_preserve_body_abi_visibility_and_initializer_relocations_all_three_isas_text_and_bitcode(self):
        # Import the helper only after this baseline module has loaded, avoiding
        # the memory suite's deliberate import of this module forming a cycle.
        from tests import test_ocore_llvm_memory_import as memory

        body = """
@strong_data = global i64 17, align 8
@weak_data = weak {visibility} global i64 19, align 8
@weak_data_ptr = weak {visibility} global ptr @strong_data, align 8
@weak_fn_ptr = weak {visibility} constant ptr @weak_fn, align 8
@strong_fn_ptr = global ptr @weak_fn, align 8
declare i64 @dependency(i64)
define weak {visibility} signext i32 @weak_fn(i32 zeroext %value) {{
  %sum = add i32 %value, 7
  ret i32 %sum
}}
define i64 @strong_fn(i64 %value) {{
  %weak = call signext i32 @weak_fn(i32 zeroext 42)
  %wide = sext i32 %weak to i64
  %external = call i64 @dependency(i64 %value)
  %sum = add i64 %wide, %external
  store i64 %sum, ptr @strong_data, align 8
  ret i64 %sum
}}
"""
        for triple in TRIPLES:
            layout = "e-p:64:64-i64:64-i128:128-n8:16:32:64-S128" + ("-Fn32" if triple.startswith("aarch64-") else "")
            for visibility in ("default", "hidden", "protected"):
                with self.subTest(triple=triple, visibility=visibility):
                    source = self.write(body.format(visibility="" if visibility == "default" else visibility),
                                        triple=triple, layout=layout)
                    binary = memory.LlvmMemoryImportTests.bitcode(self, source)
                    modules = []
                    for path in (source, binary):
                        module = importer.import_module(path, library_path=self.library, expected_sha256=self.library_sha256)
                        modules.append(module)
                        self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                        self.assertEqual(module["target"]["triple"], triple)
                        self.assertEqual(module["provenance"]["source_function_count"], 3)
                        self.assertEqual(module["provenance"]["source_global_count"], 5)
                        self.assertEqual({function["name"] for function in module["functions"]},
                                         {"dependency", "weak_fn", "strong_fn"})
                        globals_by_name = {glob["name"]: glob for glob in module["globals"]}
                        self.assertEqual(set(globals_by_name),
                                         {"strong_data", "weak_data", "weak_data_ptr", "weak_fn_ptr", "strong_fn_ptr"})
                        for symbol in (globals_by_name["weak_data"], globals_by_name["weak_data_ptr"],
                                       globals_by_name["weak_fn_ptr"], self.function(module, "weak_fn")):
                            self.assertEqual(symbol["linkage"], "weak")
                            self.assertEqual(symbol["visibility"], visibility)
                            self.assertIn(f"{symbol['name']}: preserved ordinary weak definition (LLVMWeakAnyLinkage=5); "
                                          "native STB_WEAK binding and qualified closure/link selection required; no ODR or COMDAT contract inferred",
                                          module["provenance"]["refinements"])
                        for symbol in (globals_by_name["strong_data"], globals_by_name["strong_fn_ptr"],
                                       self.function(module, "strong_fn"), self.function(module, "dependency")):
                            self.assertEqual(symbol["linkage"], "external")
                            self.assertEqual(symbol["visibility"], "default")
                        self.assertEqual(globals_by_name["weak_data"]["initializer"],
                                         {"bytes": [19] + [0] * 7, "relocations": []})
                        for name, target in (("weak_data_ptr", "strong_data"), ("weak_fn_ptr", "weak_fn"),
                                             ("strong_fn_ptr", "weak_fn")):
                            self.assertEqual(globals_by_name[name]["initializer"],
                                             {"bytes": [0] * 8, "relocations": [
                                                 {"offset": 0, "width": 64, "symbol": target, "addend": 0}]})
                        self.assertTrue(globals_by_name["weak_fn_ptr"]["constant"])
                        self.assertFalse(globals_by_name["weak_data_ptr"]["constant"])
                        weak = self.function(module, "weak_fn")
                        self.assertIsNotNone(weak["entry"])
                        self.assertIsNone(weak["intrinsic"])
                        self.assertEqual(weak["signature"]["param_attributes"], [["zeroext"]])
                        self.assertEqual(weak["signature"]["result_attributes"], ["signext"])
                        self.assertEqual([operation["op"] for operation in self.operations(weak)], ["binary"])
                        self.assertEqual(self.operations(weak)[0]["rhs"]["bits"], "7")
                        strong = self.function(module, "strong_fn")
                        self.assertEqual([operation["op"] for operation in self.operations(strong)],
                                         ["call", "cast", "call", "binary", "store"])
                        calls = [operation for operation in self.operations(strong) if operation["op"] == "call"]
                        self.assertEqual([call["callee"]["name"] for call in calls], ["weak_fn", "dependency"])
                        for call in calls:
                            self.assertEqual(call["signature"], self.function(module, call["callee"]["name"])["signature"])
                        self.assertIsNone(self.function(module, "dependency")["entry"])
                    self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                                     {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})

    def test_weak_declaration_spellings_reject_at_llvm_parse_instead_of_becoming_definitions(self):
        for body in ("declare weak void @unsupported()\n", "@unsupported = weak global i64\n"):
            with self.subTest(body=body):
                self.reject(body, stage="parse")

    def test_weak_definition_support_keeps_unsupported_declarations_and_nonemitted_definitions_rejected(self):
        supported = "@ordinary = weak global i8 3\ndefine i32 @strong() { ret i32 9 }\n"
        cases = (
            "@unsupported = extern_weak global i64",
            "declare extern_weak void @unsupported()",
            "@unsupported = available_externally global i64 0",
            "define available_externally void @unsupported() { ret void }",
        )
        for body in cases:
            with self.subTest(body=body):
                self.reject(supported + body + "\n")

    def test_weak_definitions_preserve_atomic_store_and_keep_independent_abi_section_dll_tls_and_security_guards(self):
        cases = (
            "define weak void @unsupported(ptr byval(i8) %pointer) { ret void }",
            'define weak void @unsupported() section ".unsupported" { ret void }',
            '@unsupported = weak global i64 0, section ".unsupported"',
            "@unsupported = weak dllexport global i8 1",
            "@unsupported = weak thread_local global i64 0",
            "define weak void @unsupported() naked { ret void }",
            "define weak void @unsupported() sanitize_address { ret void }",
        )
        for body in cases:
            with self.subTest(body=body):
                self.reject("@ordinary = weak global i8 3\n" + body + "\n")
        body = "define weak void @unsupported(ptr %pointer) { store atomic i64 1, ptr %pointer seq_cst, align 8\nret void }"
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir("@ordinary = weak global i8 3\n" + body + "\n", triple=triple)
                self.assertEqual([glob["name"] for glob in module["globals"]], ["ordinary"])
                self.assertEqual([function["name"] for function in module["functions"]], ["unsupported"])
                self.assertEqual(module["globals"][0]["linkage"], "weak")
                function = self.function(module, "unsupported")
                self.assertEqual(function["linkage"], "weak")
                self.assertEqual(function["visibility"], "default")
                operations = [row["operation"] for block in function["blocks"] for row in block["instructions"]]
                self.assertEqual(len(operations), 1)
                self.assertEqual(operations[0], {"op": "atomic_store", "pointer": {"kind": "value", "id": function["params"][0]["id"]},
                                                "value": {"kind": "int", "ty": operations[0]["value"]["ty"], "bits": "1"},
                                                "alignment": 8, "volatile": False, "ordering": "seq_cst", "sync_scope": 1})
                self.assertEqual(module["types"][operations[0]["value"]["ty"]], {"kind": "int", "bits": 64})
                self.assertEqual(module["provenance"]["source_function_count"], 1)
                self.assertEqual(module["provenance"]["source_global_count"], 1)
                self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(self.source.read_bytes()).hexdigest())
                self.assertNotIn("atomic_profile", module["target"])

    def test_default_hidden_protected_visibility_preserves_full_inventory_and_symbol_relocations_all_three_isas(self):
        body = """
@data = {visibility} global i64 7, align 8
@external_data = external {visibility} global i64
@unused_data = external {visibility} global i64
@data_ptr = {visibility} global ptr @data, align 8
@external_ptr = {visibility} global ptr @external_data, align 8
@function_ptr = {visibility} global ptr @helper, align 8
@external_function_ptr = {visibility} global ptr @foreign, align 8
declare {visibility} i64 @foreign(i64)
declare {visibility} i64 @unused_function(i64)
define {visibility} i64 @helper(i64 %value) {{ ret i64 %value }}
define {visibility} i64 @entry(i64 %value) {{
  %loaded = load i64, ptr @external_data, align 8
  %sum = add i64 %loaded, %value
  %result = call i64 @foreign(i64 %sum)
  %local = call i64 @helper(i64 %result)
  store i64 %local, ptr @data, align 8
  ret i64 %local
}}
"""
        expected_functions = {"foreign", "unused_function", "helper", "entry"}
        expected_globals = {"data", "external_data", "unused_data", "data_ptr", "external_ptr",
                            "function_ptr", "external_function_ptr"}
        for triple in TRIPLES:
            reference = self.import_ir(body.format(visibility=""), triple=triple)
            for visibility in ("default", "hidden", "protected"):
                with self.subTest(triple=triple, visibility=visibility):
                    keyword = "" if visibility == "default" else visibility
                    module = self.import_ir(body.format(visibility=keyword), triple=triple)
                    self.assertEqual(module["target"]["triple"], triple)
                    self.assertEqual({fn["name"] for fn in module["functions"]}, expected_functions)
                    self.assertEqual({glob["name"] for glob in module["globals"]}, expected_globals)
                    self.assertEqual(module["provenance"]["source_function_count"], 4)
                    self.assertEqual(module["provenance"]["source_global_count"], 7)
                    self.assertEqual(module["provenance"]["input_sha256"],
                                     hashlib.sha256(self.source.read_bytes()).hexdigest())
                    self.assertEqual(module["types"], reference["types"])
                    for collection in ("globals", "functions"):
                        self.assertEqual([{key: value for key, value in symbol.items() if key != "visibility"}
                                          for symbol in module[collection]],
                                         [{key: value for key, value in symbol.items() if key != "visibility"}
                                          for symbol in reference[collection]])
                        for symbol in module[collection]:
                            self.assertEqual(symbol["visibility"], visibility,
                                             "definitions and declarations need explicit visibility")
                            if visibility != "default":
                                self.assert_visibility_provenance(module, symbol["name"], visibility)
                    globals_by_name = {glob["name"]: glob for glob in module["globals"]}
                    for name in ("external_data", "unused_data"):
                        self.assertIsNone(globals_by_name[name]["initializer"])
                    for name in ("foreign", "unused_function"):
                        self.assertIsNone(self.function(module, name)["entry"])
                    for name, target in (("data_ptr", "data"), ("external_ptr", "external_data"),
                                         ("function_ptr", "helper"), ("external_function_ptr", "foreign")):
                        self.assertEqual(globals_by_name[name]["initializer"]["relocations"],
                                         [{"offset": 0, "width": 64, "symbol": target, "addend": 0}])
                    calls = [operation for operation in self.operations(self.function(module, "entry"))
                             if operation["op"] == "call"]
                    self.assertEqual([call["callee"]["name"] for call in calls], ["foreign", "helper"])
                    for call in calls:
                        self.assertEqual(call["signature"],
                                         self.function(module, call["callee"]["name"])["signature"])

    def test_local_linkage_nondefault_visibility_rejects_during_llvm_parsing(self):
        for linkage in ("internal", "private"):
            for visibility in ("hidden", "protected"):
                for body in (f"@data = {linkage} {visibility} global i64 0\n",
                             f"define {linkage} {visibility} i64 @entry() {{ ret i64 0 }}\n"):
                    with self.subTest(linkage=linkage, visibility=visibility, body=body):
                        self.reject(body, stage="parse")

    def test_owned_intrinsics_reject_nondefault_visibility_after_llvm_verification(self):
        for visibility in ("hidden", "protected"):
            for called in (False, True):
                with self.subTest(visibility=visibility, called=called):
                    body = f"declare {visibility} void @llvm.assume(i1)\n"
                    if called:
                        body += "define void @entry() { call void @llvm.assume(i1 true)\nret void }\n"
                    with self.assertRaises(importer.ImportFailure) as raised:
                        self.import_ir(body)
                    self.assertEqual(raised.exception.stage, "import")
                    self.assertEqual(raised.exception.symbol, "llvm.assume")
                    self.assertIn("default symbol visibility", str(raised.exception))

    def test_supported_visibility_keeps_dll_and_explicit_section_guards(self):
        for visibility in ("default", "hidden", "protected"):
            keyword = "" if visibility == "default" else visibility
            cases = {
                "DLL global": f"@data = external {keyword} dllimport global i64\n",
                "DLL function": f"declare {keyword} dllimport i64 @foreign(i64)\n",
                "section global": f'@data = {keyword} global i64 0, section ".explicit"\n',
                "section function": f'define {keyword} i64 @entry() section ".explicit" {{ ret i64 0 }}\n',
            }
            for name, body in cases.items():
                with self.subTest(visibility=visibility, case=name):
                    stage = "llvm-verify" if name.startswith("DLL") and visibility != "default" else "import"
                    self.reject(body, stage=stage)

    def assert_visibility_provenance(self, module, name, visibility):
        refinement = next(item for item in module["provenance"]["refinements"]
                          if f"{name}: preserved {visibility} symbol visibility" in item)
        # LLVM's visibility enum is 0/1/2; ELF's st_other codes are 0/2/3.
        self.assertIn("ELF st_other=" + str({"hidden": 2, "protected": 3}[visibility]), refinement)
        for requirement in ("own-emitter", "definitions and declarations", "included native image"):
            self.assertIn(requirement, refinement)

    def test_scalar_casts_keep_opcode_and_destination_width(self):
        module = self.import_ir("""
define i64 @casts(i8 %byte, i32 %word, ptr %pointer) {
  %unsigned = zext i8 %byte to i64
  %signed = sext i8 %byte to i64
  %small = trunc i32 %word to i8
  %address = ptrtoint ptr %pointer to i64
  %again = inttoptr i64 %address to ptr
  %same = bitcast ptr %again to ptr
  %result = add i64 %unsigned, %signed
  ret i64 %result
}
""")
        casts = [instruction for block in self.function(module, "casts")["blocks"]
                 for instruction in block["instructions"] if instruction["operation"]["op"] == "cast"]
        self.assertEqual([cast["operation"]["kind"] for cast in casts],
                         ["z_ext", "s_ext", "trunc", "ptr_to_int", "int_to_ptr", "bitcast"])
        self.assertEqual([module["types"][cast["result"]["ty"]] for cast in casts],
                         [{"kind": "int", "bits": 64}, {"kind": "int", "bits": 64},
                          {"kind": "int", "bits": 8}, {"kind": "int", "bits": 64},
                          {"kind": "pointer", "address_space": 0},
                          {"kind": "pointer", "address_space": 0}])

    def test_signed_unsigned_operations_and_poison_flags_are_distinct(self):
        module = self.import_ir("""
define i64 @arithmetic(i64 %x, i64 %y) {
  %a = sdiv exact i64 %x, %y
  %b = udiv exact i64 %x, %y
  %c = ashr exact i64 %x, 1
  %d = lshr exact i64 %x, 1
  %e = add nuw nsw i64 %a, %b
  %signed = icmp slt i64 %c, %d
  %unsigned = icmp ult i64 %c, %d
  %picked = select i1 %signed, i64 %e, i64 %d
  ret i64 %picked
}
""")
        operations = self.operations(self.function(module, "arithmetic"))
        binary = [operation for operation in operations if operation["op"] == "binary"]
        self.assertEqual([operation["kind"] for operation in binary],
                         ["s_div", "u_div", "a_shr", "l_shr", "add"])
        self.assertTrue(all(operation["flags"] == ["exact"] for operation in binary[:4]))
        self.assertEqual(set(binary[4]["flags"]), {"nuw", "nsw"})
        comparisons = [operation for operation in operations if operation["op"] == "i_cmp"]
        self.assertEqual([operation["predicate"] for operation in comparisons], ["slt", "ult"])

    def test_modern_llvm_poison_flags_are_retained_or_declared_as_refinements(self):
        module = self.import_ir("""
define i32 @flagged(i8 %byte, i64 %wide) {
  %extended = zext nneg i8 %byte to i32
  %small = trunc nuw nsw i64 %wide to i32
  %combined = or disjoint i32 %extended, %small
  %same_sign = icmp samesign slt i32 %extended, %small
  %result = select i1 %same_sign, i32 %combined, i32 %small
  ret i32 %result
}
""")
        operations = self.operations(self.function(module, "flagged"))
        self.assertEqual(operations[0]["kind"], "z_ext")
        self.assertEqual(operations[1]["kind"], "trunc")
        self.assertEqual(operations[2]["flags"], ["disjoint"])
        self.assertEqual(operations[3]["predicate"], "slt")
        refinements = "\n".join(module["provenance"]["refinements"])
        self.assertIn("nneg", refinements)
        self.assertIn("trunc nowrap", refinements)
        self.assertIn("samesign", refinements)

    def test_negative_integer_constants_keep_exact_bit_pattern(self):
        module = self.import_ir("define i8 @negative() { ret i8 -1 }\n")
        operand = self.function(module, "negative")["blocks"][0]["terminator"]["value"]
        self.assertEqual(operand["kind"], "int")
        self.assertEqual(operand["bits"], "255")
        self.assertEqual(module["types"][operand["ty"]], {"kind": "int", "bits": 8})

    def test_signext_zeroext_survive_declaration_definition_and_callsite(self):
        module = self.import_ir("""
declare signext i8 @foreign(i8 signext)
define zeroext i8 @caller(i8 zeroext %value) {
  %result = call signext i8 @foreign(i8 signext %value)
  ret i8 %result
}
""")
        foreign = self.function(module, "foreign")["signature"]
        caller = self.function(module, "caller")["signature"]
        call = next(operation for operation in self.operations(self.function(module, "caller"))
                    if operation["op"] == "call")
        self.assertEqual(foreign["param_attributes"], [["signext"]])
        self.assertEqual(foreign["result_attributes"], ["signext"])
        self.assertEqual(caller["param_attributes"], [["zeroext"]])
        self.assertEqual(caller["result_attributes"], ["zeroext"])
        self.assertEqual(call["signature"], foreign)

    def test_safe_frontend_assumptions_are_explicitly_recorded_when_erased(self):
        module = self.import_ir("""
define noundef i32 @assumed(i32 noundef %value) nounwind noinline optnone willreturn {
  %result = add i32 %value, 0
  ret i32 %result
}
""")
        function = self.function(module, "assumed")
        self.assertEqual(function["signature"]["param_attributes"], [[]])
        self.assertEqual(function["signature"]["result_attributes"], [])
        refinements = "\n".join(module["provenance"]["refinements"])
        for attribute in ("noundef", "nounwind", "noinline", "optnone", "willreturn"):
            with self.subTest(attribute=attribute):
                self.assertIn(attribute, refinements)

    def test_indirect_call_uses_callsite_signature_for_opaque_pointer(self):
        module = self.import_ir("""
define i32 @dispatch(ptr %callback, i32 %value) {
  %result = call i32 %callback(i32 %value)
  ret i32 %result
}
""")
        function = self.function(module, "dispatch")
        call = self.operations(function)[0]
        self.assertEqual(call["op"], "call")
        self.assertEqual(call["callee"], {"kind": "value", "id": function["params"][0]["id"]})
        self.assertEqual(len(call["signature"]["params"]), 1)
        self.assertEqual(module["types"][call["signature"]["result"]], {"kind": "int", "bits": 32})

    def test_variadic_call_retains_complete_actual_types_and_independent_tail_attributes(self):
        body = """
declare i32 @format(ptr, ...)
define i32 @caller(ptr %pattern, i32 %number) {
  %result = call i32 (ptr, ...) @format(ptr %pattern, i32 signext %number, i64 7, ptr %pattern)
  ret i32 %result
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir(body, triple=triple)
                declaration = self.function(module, "format")["signature"]
                call = self.operations(self.function(module, "caller"))[0]
                self.assertTrue(declaration["variadic"])
                self.assertEqual(len(declaration["params"]), 1)
                self.assertEqual(declaration["param_attributes"], [[]])
                self.assertEqual(len(call["signature"]["params"]), 1)
                self.assertEqual(len(call["args"]), 4)
                self.assertEqual(call["signature"]["param_attributes"], [[], ["signext"], [], []])
                self.assertEqual(module["types"][call["args"][2]["ty"]], {"kind": "int", "bits": 64})
                self.assertEqual(module["provenance"]["source_function_count"], 2)

    def test_variadic_list_lifecycle_retains_exact_owned_calls_and_declarations(self):
        body = """
declare void @llvm.va_start.p0(ptr)
declare void @llvm.va_end.p0(ptr)
declare void @llvm.va_copy.p0(ptr, ptr)
define void @forward(ptr %list, ptr %copy, ...) {
  call void @llvm.va_start.p0(ptr %list)
  call void @llvm.va_copy.p0(ptr %copy, ptr %list)
  call void @llvm.va_end.p0(ptr %copy)
  call void @llvm.va_end.p0(ptr %list)
  ret void
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir(body, triple=triple)
                calls = self.operations(self.function(module, "forward"))
                names = ["llvm.va_start.p0", "llvm.va_copy.p0", "llvm.va_end.p0", "llvm.va_end.p0"]
                self.assertEqual([call["op"] for call in calls], ["call"] * 4)
                self.assertEqual([call["callee"]["name"] for call in calls], names)
                self.assertEqual([len(call["args"]) for call in calls], [1, 2, 1, 1])
                self.assertEqual(len(module["functions"]), 4)
                for name in set(names):
                    declaration = self.function(module, name)
                    self.assertEqual(declaration["intrinsic"], name)
                    self.assertIsNone(declaration["entry"])
                    self.assertFalse(declaration["signature"]["variadic"])
                    self.assertEqual(module["types"][declaration["signature"]["result"]], {"kind": "void"})

    def test_variadic_list_addresses_and_fixed_function_start_remain_rejected(self):
        self.reject("""
declare void @llvm.va_start.p0(ptr)
define void @fixed(ptr %list) {
  call void @llvm.va_start.p0(ptr %list)
  ret void
}
""", stage="llvm-verify")
        self.reject("""
declare void @llvm.va_end.p0(ptr)
define ptr @escape() { ret ptr @llvm.va_end.p0 }
""", stage="llvm-verify")

    def test_dead_on_return_refinement_preserves_every_original_call_and_memory_operation(self):
        body = """
declare void @foreign(ptr dead_on_return)
declare void @variadic(i32, ...)
define i64 @worker(ptr dead_on_return %pointer) {
  store i64 17, ptr %pointer, align 8
  call void @foreign(ptr dead_on_return %pointer)
  call void (i32, ...) @variadic(i32 7, ptr dead_on_return %pointer)
  %value = load i64, ptr %pointer, align 8
  ret i64 %value
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir(body, triple=triple)
                worker = self.function(module, "worker")
                operations = self.operations(worker)
                self.assertEqual([op["op"] for op in operations], ["store", "call", "call", "load"])
                self.assertEqual(operations[1]["callee"]["name"], "foreign")
                self.assertEqual(operations[2]["callee"]["name"], "variadic")
                self.assertEqual(operations[2]["signature"]["param_attributes"], [[], []])
                self.assertEqual(len(operations[2]["args"]), 2)
                self.assertEqual(self.function(module, "foreign")["signature"]["param_attributes"], [[]])
                self.assertEqual(len(module["functions"]), 3)
                self.assertEqual(module["provenance"]["source_function_count"], 3)
                records = [text for text in module["provenance"]["refinements"] if "validated dead_on_return=0" in text]
                self.assertEqual(len(records), 4)
                self.assertTrue(any("callsite argument index 2" in text for text in records))
                self.assertTrue(all("no synthesized poison, store elimination" in text for text in records))

    def test_dead_on_return_invoke_keeps_edges_and_byval_is_still_not_erased(self):
        body = """
declare i32 @__gxx_personality_v0(...)
declare void @foreign(ptr dead_on_return)
define i64 @worker(ptr dead_on_return %pointer) personality ptr @__gxx_personality_v0 {
entry:
  store i64 17, ptr %pointer, align 8
  invoke void @foreign(ptr dead_on_return %pointer) to label %normal unwind label %cleanup
normal:
  %value = load i64, ptr %pointer, align 8
  ret i64 %value
cleanup:
  %exception = landingpad { ptr, i32 } cleanup
  resume { ptr, i32 } %exception
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir(body, triple=triple)
                worker = self.function(module, "worker")
                self.assertEqual(worker["blocks"][0]["terminator"]["op"], "invoke")
                invoke = worker["blocks"][0]["terminator"]
                self.assertEqual(invoke["callee"]["name"], "foreign")
                self.assertEqual(invoke["signature"]["param_attributes"], [[]])
                self.assertNotEqual(invoke["normal"], invoke["unwind"])
                self.assertEqual([op["op"] for op in self.operations(worker)], ["store", "load", "landing_pad"])
                self.assertTrue(any("callsite argument index 1: validated dead_on_return=0" in text
                                    for text in module["provenance"]["refinements"]))
        self.reject("define void @bad(i32 dead_on_return %value) { ret void }", stage="llvm-verify")
        self.reject("define dead_on_return ptr @bad() { ret ptr null }", stage="parse")
        with self.assertRaises(importer.ImportFailure) as raised:
            self.import_ir("declare void @bad(ptr byval(i64))")
        self.assertEqual(raised.exception.stage, "import")
        self.assertIn("unsupported attribute kind 84", str(raised.exception))

    def test_static_alloca_and_memory_access_width_alignment_and_volatility_survive(self):
        module = self.import_ir("""
define i32 @memory(ptr %pointer) {
  %temporary = alloca i32, i64 4, align 16
  store i32 7, ptr %temporary, align 16
  %value = load volatile i32, ptr %pointer, align 1
  store volatile i32 %value, ptr %pointer, align 1
  ret i32 %value
}
""")
        function = self.function(module, "memory")
        operations = self.operations(function)
        self.assertEqual(operations[0], {"op": "alloca", "size": 16, "alignment": 16})
        self.assertEqual(operations[1]["alignment"], 16)
        self.assertFalse(operations[1]["volatile"])
        self.assertEqual(operations[2]["op"], "load")
        self.assertEqual(operations[2]["alignment"], 1)
        self.assertTrue(operations[2]["volatile"])
        self.assertEqual(operations[3]["op"], "store")
        self.assertEqual(operations[3]["alignment"], 1)
        self.assertTrue(operations[3]["volatile"])
        result_type = function["blocks"][0]["instructions"][2]["result"]["ty"]
        self.assertEqual(module["types"][result_type], {"kind": "int", "bits": 32})

    def test_phi_resolves_loop_backedge_forward_value_and_constant_operands(self):
        module = self.import_ir("""
define i64 @loop(i64 %limit) {
entry:
  br label %header
header:
  %counter = phi i64 [ 0, %entry ], [ %next, %body ]
  %keep = icmp ult i64 %counter, %limit
  br i1 %keep, label %body, label %exit
body:
  %next = add i64 %counter, 1
  br label %header
exit:
  ret i64 %counter
}
""")
        function = self.function(module, "loop")
        entry, header, body, exit_block = function["blocks"]
        phi = header["instructions"][0]["operation"]
        self.assertEqual(phi["op"], "phi")
        self.assertEqual([incoming["block"] for incoming in phi["incoming"]],
                         [entry["id"], body["id"]])
        self.assertEqual(phi["incoming"][0]["value"]["bits"], "0")
        self.assertEqual(phi["incoming"][1]["value"],
                         {"kind": "value", "id": body["instructions"][0]["result"]["id"]})
        self.assertEqual(exit_block["terminator"]["op"], "return")

    def test_duplicate_cfg_edges_coalesce_phi_entries_without_changing_the_value(self):
        for common_value in ("%value", "9"):
            with self.subTest(common_value=common_value):
                module = self.import_ir(f"""
define i64 @duplicate(i1 %condition, i64 %value) {{
entry:
  br i1 %condition, label %merge, label %merge
merge:
  %result = phi i64 [ {common_value}, %entry ], [ {common_value}, %entry ]
  ret i64 %result
}}
""")
                function = self.function(module, "duplicate")
                entry, merge = function["blocks"]
                self.assertEqual(entry["terminator"]["on_true"], merge["id"])
                self.assertEqual(entry["terminator"]["on_false"], merge["id"])
                phi = merge["instructions"][0]["operation"]
                self.assertEqual(len(phi["incoming"]), 1)
                self.assertEqual(phi["incoming"][0]["block"], entry["id"])
                incoming_value = phi["incoming"][0]["value"]
                if common_value == "%value":
                    self.assertEqual(incoming_value,
                                     {"kind": "value", "id": function["params"][1]["id"]})
                else:
                    self.assertEqual(incoming_value["kind"], "int")
                    self.assertEqual(incoming_value["bits"], "9")
                self.assertEqual(merge["terminator"]["value"],
                                 {"kind": "value", "id": merge["instructions"][0]["result"]["id"]})
                self.assertTrue(any("duplicate CFG edges with identical PHI values coalesced" in item
                                    for item in module["provenance"]["refinements"]))

    def test_freeze_select_and_phi_preserve_poison_and_undef_operands(self):
        module = self.import_ir("""
define i32 @deferred(i1 %condition) {
entry:
  %frozen = freeze i32 poison
  %choice = select i1 %condition, i32 %frozen, i32 undef
  br i1 %condition, label %left, label %right
left:
  br label %merge
right:
  br label %merge
merge:
  %result = phi i32 [ %choice, %left ], [ poison, %right ]
  ret i32 %result
}
""")
        operations = self.operations(self.function(module, "deferred"))
        self.assertEqual(operations[0]["op"], "freeze")
        self.assertEqual(operations[0]["value"]["kind"], "poison")
        self.assertEqual(operations[1]["on_false"]["kind"], "undef")
        self.assertEqual(operations[2]["incoming"][1]["value"]["kind"], "poison")

    def test_assume_preserves_conditions_and_builtin_declaration_inventory_on_all_three_isas(self):
        body = """
declare void @llvm.assume(i1 noundef) nocallback nofree nosync nounwind willreturn memory(inaccessiblemem: write)
declare void @foreign()
define i32 @entry(i1 %condition) {
  call void @llvm.assume(i1 true)
  call void @llvm.assume(i1 false)
  call void @llvm.assume(i1 %condition)
  call void @llvm.assume(i1 poison)
  ret i32 7
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir(body, triple=triple)
                self.assertEqual({fn["name"] for fn in module["functions"]},
                                 {"llvm.assume", "foreign", "entry"})
                self.assertEqual(module["provenance"]["source_function_count"], 3)
                self.assertEqual(module["provenance"]["source_global_count"], 0)
                builtin = self.function(module, "llvm.assume")
                self.assertEqual(builtin["intrinsic"], "llvm.assume")
                self.assertIsNone(builtin["entry"])
                self.assertEqual(builtin["blocks"], [])
                self.assertEqual(len(builtin["signature"]["params"]), 1)
                self.assertEqual(module["types"][builtin["signature"]["params"][0]],
                                 {"kind": "int", "bits": 1})
                self.assertEqual(module["types"][builtin["signature"]["result"]], {"kind": "void"})
                self.assertEqual(builtin["signature"]["param_attributes"], [[]])
                self.assertEqual(builtin["signature"]["result_attributes"], [])
                self.assertIsNone(self.function(module, "foreign")["intrinsic"])
                function = self.function(module, "entry")
                self.assertIsNone(function["intrinsic"])
                instructions = function["blocks"][0]["instructions"]
                self.assertEqual(len(instructions), 4)
                self.assertTrue(all(instruction["result"] is None for instruction in instructions))
                operations = self.operations(function)
                self.assertTrue(all(set(operation) == {"op", "condition"} for operation in operations))
                self.assertEqual([operation["op"] for operation in operations], ["assume"] * 4)
                conditions = [operation["condition"] for operation in operations]
                self.assertEqual([condition["kind"] for condition in conditions],
                                 ["int", "int", "value", "poison"])
                self.assertEqual([condition["bits"] for condition in conditions[:2]], ["1", "0"])
                self.assertEqual(conditions[2], {"kind": "value", "id": function["params"][0]["id"]})
                for condition in (conditions[0], conditions[1], conditions[3]):
                    self.assertEqual(module["types"][condition["ty"]], {"kind": "int", "bits": 1})

    def test_assume_bundles_and_other_intrinsics_remain_unsupported(self):
        cases = {
            "valid nonnull bundle": """
declare void @llvm.assume(i1)
define void @entry(ptr %pointer) {
  call void @llvm.assume(i1 true) [ "nonnull"(ptr %pointer) ]
  ret void
}
""",
            "other intrinsic declaration": "declare void @llvm.assume(i1)\ndeclare i32 @llvm.ctpop.i32(i32)\n",
            "side effect intrinsic": "declare void @llvm.assume(i1)\ndeclare void @llvm.sideeffect()\n",
            "unknown reserved builtin name": "declare void @llvm.assume(i1)\ndeclare void @llvm.not_a_supported_builtin()\n",
            "callsite ABI extension": "declare void @llvm.assume(i1)\ndefine void @entry() { call void @llvm.assume(i1 zeroext true)\n ret void }\n",
            "callsite semantic attribute": 'declare void @llvm.assume(i1)\ndefine void @entry() { call void @llvm.assume(i1 true) "unknown-semantics"="required"\n ret void }\n',
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                self.reject(body)

    def test_assume_address_cannot_escape_into_globals_returns_or_arguments(self):
        cases = {
            "global initializer": "@slot = global ptr @llvm.assume\ndeclare void @llvm.assume(i1)\n",
            "returned address": "declare void @llvm.assume(i1)\ndefine ptr @entry() { ret ptr @llvm.assume }\n",
            "foreign argument": """
declare void @llvm.assume(i1)
declare void @capture(ptr)
define void @entry() {
  call void @capture(ptr @llvm.assume)
  ret void
}
""",
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                self.reject(body, stage="llvm-verify")

    def test_pinned_llvm_verifier_rejects_called_invalid_assume_signatures_and_definitions(self):
        cases = {
            "argument width": "declare void @llvm.assume(i32)\ndefine void @entry() { call void @llvm.assume(i32 1)\n ret void }\n",
            "return type": "declare i32 @llvm.assume(i1)\ndefine i32 @entry() { %result = call i32 @llvm.assume(i1 true)\n ret i32 %result }\n",
            "argument count": "declare void @llvm.assume(i1, i1)\ndefine void @entry() { call void @llvm.assume(i1 true, i1 true)\n ret void }\n",
            "defined intrinsic body": "define void @llvm.assume(i1 %condition) { ret void }\n",
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                self.reject(body, stage="llvm-verify")

    def test_importer_rejects_invalid_unused_assume_declarations(self):
        # LLVM verifies these unused declarations; native builtin validation
        # must still require the exact void(i1) signature without ABI extensions.
        for declaration in ("declare void @llvm.assume(i32)",
                            "declare i32 @llvm.assume(i1)",
                            "declare void @llvm.assume(i1, i1)"):
            with self.subTest(declaration=declaration):
                self.reject(declaration)

    def test_global_layout_and_data_function_relocations_are_complete(self):
        module = self.import_ir("""
@name = private constant [4 x i8] c"abc\\00", align 1
@table = global { ptr, ptr, i32 } { ptr @name, ptr @callback, i32 -1 }, align 8
@nulls = global [2 x ptr] zeroinitializer, align 8
declare i32 @callback(i32)
""")
        globals_by_name = {glob["name"]: glob for glob in module["globals"]}
        self.assertEqual(globals_by_name["name"]["initializer"]["bytes"], [97, 98, 99, 0])
        initializer = globals_by_name["table"]["initializer"]
        self.assertEqual(initializer["bytes"], [0] * 16 + [255] * 4 + [0] * 4)
        self.assertEqual(initializer["relocations"], [
            {"offset": 0, "width": 64, "symbol": "name", "addend": 0},
            {"offset": 8, "width": 64, "symbol": "callback", "addend": 0},
        ])
        self.assertEqual(globals_by_name["nulls"]["initializer"],
                         {"bytes": [0] * 16, "relocations": []})

    def test_constant_gep_initializer_relocations_keep_positive_and_negative_addends(self):
        module = self.import_ir("""
@name = private constant [4 x i8] c"abc\\00"
@middle = global ptr getelementptr ([4 x i8], ptr @name, i64 0, i64 2)
@before = global ptr getelementptr (i8, ptr @name, i64 -1)
""")
        globals_by_name = {glob["name"]: glob for glob in module["globals"]}
        for name, addend in (("middle", 2), ("before", -1)):
            with self.subTest(global_name=name):
                self.assertEqual(globals_by_name[name]["initializer"], {
                    "bytes": [0] * 8,
                    "relocations": [{"offset": 0, "width": 64,
                                     "symbol": "name", "addend": addend}],
                })

    def test_constant_gep_restrictions_refine_poison_without_changing_addresses(self):
        module = self.import_ir("""
@data = global [4 x i32] zeroinitializer
@inside = global ptr getelementptr inrange(0, 16) ([4 x i32], ptr @data, i64 0, i64 2)
@nowrap = global ptr getelementptr nuw (i32, ptr @data, i64 3)
""")
        globals_by_name = {glob["name"]: glob for glob in module["globals"]}
        for name, addend in (("inside", 8), ("nowrap", 12)):
            with self.subTest(global_name=name):
                self.assertEqual(globals_by_name[name]["initializer"], {
                    "bytes": [0] * 8,
                    "relocations": [{"offset": 0, "width": 64,
                                     "symbol": "data", "addend": addend}],
                })
                refinement = next(item for item in module["provenance"]["refinements"]
                                  if item.startswith(f"{name}: constant GEP"))
                self.assertIn("inrange/no-wrap", refinement)
                self.assertIn("exact DataLayout address retained", refinement)

    def test_missing_or_incompatible_target_contract_is_rejected(self):
        for triple, layout in (("", LAYOUT), (TRIPLES[0], ""),
                               ("wasm32-unknown-unknown", LAYOUT),
                               ("x86_64--linux-gnu", LAYOUT),
                               ("riscv64--none", LAYOUT),
                               (TRIPLES[0], "E-p:64:64"),
                               (TRIPLES[0], "e-p:32:32")):
            with self.subTest(triple=triple, layout=layout):
                self.reject("define i32 @entry() { ret i32 0 }\n", triple=triple, layout=layout)

    def test_explicit_rv64_lp64_abi_preserves_bare_and_qualified_triples(self):
        body = """
@counter = global i64 3, align 8
declare i64 @foreign(i64)
define i64 @entry(i64 %value) {
  %previous = load i64, ptr @counter, align 8
  %next = add i64 %previous, %value
  %result = call i64 @foreign(i64 %next)
  ret i64 %result
}
!llvm.module.flags = !{!0}
!0 = !{i32 1, !"target-abi", !"lp64"}
"""
        for triple in ("riscv64", TRIPLES[2]):
            with self.subTest(triple=triple):
                module = self.import_ir(body, triple=triple)
                self.assertEqual(module["target"], {
                    "triple": triple, "data_layout": LAYOUT, "pointer_bits": 64,
                    "little_endian": True, "abi": "lp64",
                })
                self.assertEqual({function["name"] for function in module["functions"]},
                                 {"foreign", "entry"})
                self.assertEqual({glob["name"] for glob in module["globals"]}, {"counter"})
                self.assertEqual(module["provenance"]["source_function_count"], 2)
                self.assertEqual(module["provenance"]["source_global_count"], 1)
                self.assertEqual(module["provenance"]["input_sha256"],
                                 hashlib.sha256(self.source.read_bytes()).hexdigest())
                call = next(operation for operation in self.operations(self.function(module, "entry"))
                            if operation["op"] == "call")
                self.assertEqual(call["callee"]["name"], "foreign")
                self.assertEqual(call["signature"], self.function(module, "foreign")["signature"])
                self.assertIn("verified RISC-V lp64 target ABI", module["provenance"]["refinements"])

    def test_bare_rv64_requires_lp64_metadata_and_wrong_isa_abi_flags_reject(self):
        entry = "define i32 @entry() { ret i32 0 }\n"
        self.reject(entry, triple="riscv64")
        for triple in ("riscv64", TRIPLES[2]):
            for value in ('!"lp64q"', '!"lp64f"', '!"ilp32"', '!""', "i32 64"):
                with self.subTest(triple=triple, abi_value=value):
                    self.reject(entry + '!llvm.module.flags = !{!0}\n'
                                + f'!0 = !{{i32 1, !"target-abi", {value}}}\n', triple=triple)
        valid_flag = '!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"lp64"}\n'
        for triple in (TRIPLES[0], TRIPLES[1], "x86_64", "aarch64"):
            with self.subTest(triple=triple):
                self.reject(entry + valid_flag, triple=triple)

    def test_conflicting_rv64_abi_flags_reject_during_llvm_verification(self):
        body = """
define i32 @entry() { ret i32 0 }
!llvm.module.flags = !{!0, !1}
!0 = !{i32 1, !"target-abi", !"lp64"}
!1 = !{i32 1, !"target-abi", !"lp64d"}
"""
        for triple in ("riscv64", TRIPLES[2]):
            with self.subTest(triple=triple):
                self.reject(body, triple=triple, stage="llvm-verify")

    def test_rv64_code_model_three_has_audited_static_scalar_relowering(self):
        entry = "define i64 @entry(i64 %value) { ret i64 %value }\n"
        model_only = '!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"Code Model", i32 3}\n'
        model_and_abi = ('!llvm.module.flags = !{!0, !1}\n'
                         '!0 = !{i32 1, !"Code Model", i32 3}\n'
                         '!1 = !{i32 1, !"target-abi", !"lp64"}\n')
        abi_then_model = model_and_abi.replace("!{!0, !1}", "!{!1, !0}")
        cases = (("riscv64", model_and_abi), (TRIPLES[2], model_and_abi),
                 ("riscv64", abi_then_model), (TRIPLES[2], model_only))
        for triple, flags in cases:
            with self.subTest(triple=triple, flags=flags):
                module = self.import_ir(entry + flags, triple=triple)
                self.assertEqual(module["target"]["triple"], triple)
                if flags != model_only:
                    self.assertEqual(module["target"]["abi"], "lp64")
                else:
                    self.assertNotIn("abi", module["target"])
                refinement = next(item for item in module["provenance"]["refinements"]
                                  if "Code Model=3" in item)
                for requirement in ("static", "non-preemptive", "scalar", "relocation"):
                    self.assertIn(requirement, refinement)
                function = self.function(module, "entry")
                self.assertEqual(function["blocks"][0]["terminator"]["value"],
                                 {"kind": "value", "id": function["params"][0]["id"]})

    def test_other_code_models_and_non_rv64_code_model_three_reject(self):
        entry = "define i32 @entry() { ret i32 0 }\n"
        for triple in ("riscv64", TRIPLES[2]):
            for value in ("i32 0", "i32 1", "i32 2", "i32 4", "i32 5", "i32 -1", '!"3"'):
                with self.subTest(triple=triple, code_model=value):
                    self.reject(entry + '!llvm.module.flags = !{!0, !1}\n'
                                + f'!0 = !{{i32 1, !"Code Model", {value}}}\n'
                                + '!1 = !{i32 1, !"target-abi", !"lp64"}\n', triple=triple)
        flag = '!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"Code Model", i32 3}\n'
        for triple in TRIPLES[:2]:
            with self.subTest(triple=triple):
                self.reject(entry + flag, triple=triple)
        self.reject(entry + flag, triple="riscv64")

    def test_pic_and_pie_levels_are_independent_under_the_static_linkage_profile(self):
        body = """
@number = global i64 7, align 8
@slot = global ptr @foreign, align 8
declare i64 @foreign(i64)
define i64 @entry(i64 %value) {
  %previous = load i64, ptr @number, align 8
  %next = add i64 %previous, %value
  %result = call i64 @foreign(i64 %next)
  ret i64 %result
}
"""
        flag_sets = ({}, {"PIC Level": 0}, {"PIC Level": 1}, {"PIC Level": 2},
                     {"PIE Level": 0}, {"PIE Level": 1}, {"PIE Level": 2},
                     {"PIC Level": 0, "PIE Level": 2},
                     {"PIC Level": 1, "PIE Level": 2},
                     {"PIC Level": 2, "PIE Level": 2})
        for triple in TRIPLES:
            for levels in flag_sets:
                with self.subTest(triple=triple, levels=levels):
                    metadata = ""
                    if levels:
                        metadata = "!llvm.module.flags = !{" + ", ".join(
                            f"!{index}" for index in range(len(levels))) + "}\n"
                        for index, (key, level) in enumerate(levels.items()):
                            behavior = 8 if key == "PIC Level" else 7
                            metadata += f'!{index} = !{{i32 {behavior}, !"{key}", i32 {level}}}\n'
                    module = self.import_ir(body + metadata, triple=triple)
                    self.assertEqual(module["target"]["triple"], triple)
                    self.assertEqual(module["provenance"]["source_function_count"], 2)
                    self.assertEqual(module["provenance"]["source_global_count"], 2)
                    self.assertEqual(module["provenance"]["input_sha256"],
                                     hashlib.sha256(self.source.read_bytes()).hexdigest())
                    for key, level in levels.items():
                        self.assert_pic_pie_provenance(module, key, level)
                    relocations = next(glob for glob in module["globals"] if glob["name"] == "slot")["initializer"]["relocations"]
                    self.assertEqual(relocations,
                                     [{"offset": 0, "width": 64, "symbol": "foreign", "addend": 0}])
                    call = next(operation for operation in self.operations(self.function(module, "entry"))
                                if operation["op"] == "call")
                    self.assertEqual(call["callee"]["name"], "foreign")
                    self.assertEqual(call["signature"], self.function(module, "foreign")["signature"])

    def test_pic_pie_reserved_levels_forged_behaviors_and_wrong_integer_widths_reject(self):
        entry = "define i32 @entry() { ret i32 0 }\n"
        for key, expected_behavior in (("PIC Level", 8), ("PIE Level", 7)):
            cases = [(f"i32 {expected_behavior}", f"i32 {level}",
                      "llvm-verify" if key == "PIC Level" and level == -1 else "import")
                     for level in (3, 4, -1)]
            # The upstream reader upgrades legacy Error/Max PIC and Error PIE
            # behaviors; test those separately against their parsed semantics.
            wrong_behaviors = (2, 4) if key == "PIC Level" else (2, 4, 8)
            cases += [(f"i32 {behavior}", "i32 1", "import")
                      for behavior in wrong_behaviors]
            cases += [(f"i32 {expected_behavior}", level, "import")
                      for level in ("i8 1", "i64 2", f"i128 {(1 << 64) + 2}")]
            cases += [(behavior, "i32 1", "import") for behavior in (
                f"i8 {expected_behavior}", f"i64 {expected_behavior}", f"i128 {expected_behavior}")]
            cases.append((f"i128 {(1 << 64) + expected_behavior}", "i32 1", "llvm-verify"))
            for behavior, level, stage in cases:
                with self.subTest(key=key, behavior=behavior, level=level):
                    self.reject(entry + '!llvm.module.flags = !{!0}\n'
                                + f'!0 = !{{{behavior}, !"{key}", {level}}}\n', stage=stage)
        # Accepting relocation hints must not admit adjacent unsupported
        # code-generation requirements that the native profile cannot fulfill.
        self.reject(entry + '!llvm.module.flags = !{!0, !1}\n'
                    + '!0 = !{i32 8, !"PIC Level", i32 2}\n'
                    + '!1 = !{i32 7, !"uwtable", i32 3}\n')

    def test_module_uwtable_defaults_require_explicit_native_realization_on_all_three_isas(self):
        body = """
@slot = global ptr @foreign, align 8
declare i64 @foreign(i64)
define i64 @entry(i64 %value) {
  %result = call i64 @foreign(i64 %value)
  ret i64 %result
}
"""
        for triple in TRIPLES:
            reference = self.import_ir(body, triple=triple)
            for level in (0, 1, 2):
                with self.subTest(triple=triple, level=level):
                    module = self.import_ir(body + '!llvm.module.flags = !{!0}\n'
                                            + f'!0 = !{{i32 7, !"uwtable", i32 {level}}}\n',
                                            triple=triple)
                    self.assertEqual({key: value for key, value in module.items()
                                      if key not in {"name", "provenance"}},
                                     {key: value for key, value in reference.items()
                                      if key not in {"name", "provenance"}})
                    self.assert_module_uwtable_provenance(module, level)
                    self.assertEqual(module["provenance"]["input_sha256"],
                                     hashlib.sha256(self.source.read_bytes()).hexdigest())

    def test_uwtable_module_flags_reject_forged_levels_types_behaviors_and_duplicates(self):
        entry = "define i32 @entry() { ret i32 0 }\n"
        cases = [("i32 7", f"i32 {level}", "import") for level in (3, -1)]
        cases += [(f"i32 {behavior}", "i32 2", "import") for behavior in (1, 2, 4, 8)]
        cases += [("i32 7", level, "import")
                  for level in ("i8 2", "i64 2", "i128 2", f"i128 {(1 << 64) + 2}")]
        cases += [(behavior, "i32 2", "import")
                  for behavior in ("i8 7", "i64 7", "i128 7")]
        cases.append((f"i128 {(1 << 64) + 7}", "i32 2", "llvm-verify"))
        for behavior, level, stage in cases:
            with self.subTest(behavior=behavior, level=level):
                self.reject(entry + '!llvm.module.flags = !{!0}\n'
                            + f'!0 = !{{{behavior}, !"uwtable", {level}}}\n', stage=stage)
        for second_level in (1, 2):
            with self.subTest(duplicate_level=second_level):
                self.reject(entry + '!llvm.module.flags = !{!0, !1}\n'
                            + '!0 = !{i32 7, !"uwtable", i32 1}\n'
                            + f'!1 = !{{i32 7, !"uwtable", i32 {second_level}}}\n',
                            stage="llvm-verify")
        self.reject(entry + '!llvm.module.flags = !{!0, !1}\n'
                    + '!0 = !{i32 7, !"uwtable", i32 1}\n'
                    + '!1 = !{i32 3, !"uwtable", !2}\n!2 = !{!"uwtable", i32 1}\n')

    def test_defined_uwtable_sync_async_attributes_preserve_scalar_body_and_module_independence(self):
        body = """
declare i64 @foreign(i64)
define i64 @entry(i64 %value) {attribute} {{
  %result = call i64 @foreign(i64 %value)
  ret i64 %result
}}
"""
        for triple in TRIPLES:
            reference = self.import_ir(body.format(attribute=""), triple=triple)
            for attribute, level in (("uwtable", 2), ("uwtable(sync)", 1), ("uwtable(async)", 2)):
                for module_level in (None, 0, 2):
                    with self.subTest(triple=triple, attribute=attribute, module_level=module_level):
                        metadata = "" if module_level is None else (
                            '!llvm.module.flags = !{!0}\n'
                            + f'!0 = !{{i32 7, !"uwtable", i32 {module_level}}}\n')
                        module = self.import_ir(body.format(attribute=attribute) + metadata, triple=triple)
                        self.assertEqual({key: value for key, value in module.items()
                                          if key not in {"name", "provenance"}},
                                         {key: value for key, value in reference.items()
                                          if key not in {"name", "provenance"}})
                        self.assert_function_uwtable_provenance(module, "entry", level)
                        if module_level is not None:
                            self.assert_module_uwtable_provenance(module, module_level)

    def test_ordinary_uwtable_declarations_preserve_inventory_and_calls_reject_after_llvm_verification(self):
        for attribute, level in (("uwtable", 2), ("uwtable(sync)", 1), ("uwtable(async)", 2)):
            with self.subTest(placement="unused declaration", attribute=attribute):
                module = self.import_ir(f"declare i32 @foreign() {attribute}\n")
                self.assertEqual(module["provenance"]["source_function_count"], 1)
                declaration = self.function(module, "foreign")
                self.assertIsNone(declaration["entry"])
                self.assertEqual(declaration["blocks"], [])
                self.assertTrue(any(
                    f"foreign: retained ordinary declaration uwtable={level}" in note
                    for note in module["provenance"]["refinements"]))
            with self.subTest(placement="callsite", attribute=attribute):
                self.reject("declare i32 @foreign()\ndefine i32 @entry() {\n"
                            + f"%result = call i32 @foreign() {attribute}\n"
                            + "ret i32 %result\n}\n")

    def test_uwtable_invalid_spellings_and_return_parameter_placements_reject_during_parse(self):
        cases = (
            "define i32 @entry() uwtable(default) { ret i32 0 }",
            "define i32 @entry() uwtable(none) { ret i32 0 }",
            "define uwtable(sync) i32 @entry() { ret i32 0 }",
            "declare uwtable(sync) i32 @foreign()",
            "define i32 @entry(i32 uwtable(sync) %value) { ret i32 %value }",
            "declare i32 @foreign(i32 uwtable(sync))",
            "declare i32 @foreign()\ndefine i32 @entry() { %result = call uwtable(sync) i32 @foreign()\nret i32 %result }",
            "declare i32 @foreign(i32)\ndefine i32 @entry(i32 %value) { %result = call i32 @foreign(i32 uwtable(sync) %value)\nret i32 %result }",
        )
        for body in cases:
            with self.subTest(body=body):
                self.reject(body, stage="parse")

    def test_uwtable_realization_preserves_supported_personality_and_rejects_security_requirements(self):
        body = """
declare i32 @personality(i32, i32, i64, ptr, ptr)
define i32 @entry() uwtable personality ptr @personality { ret i32 0 }
"""
        flags = '!llvm.module.flags = !{!0}\n!0 = !{i32 7, !"uwtable", i32 2}\n'
        for triple in TRIPLES:
            with self.subTest(triple=triple, case="personality with supported scalar signature"):
                module = self.import_ir(body + flags, triple=triple)
                entry = self.function(module, "entry")
                self.assertEqual(entry["exception_handling"]["model"], "itanium_dwarf_v1")
                self.assertEqual(entry["exception_handling"]["personality"]["name"], "personality")
                self.assertEqual({fn["name"] for fn in module["functions"]}, {"entry", "personality"})
                self.assertIsNone(self.function(module, "personality")["entry"])
                self.assertEqual(module["provenance"]["source_function_count"], 2)
                self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(self.source.read_bytes()).hexdigest())
                self.assertTrue(any("entry: realized function uwtable=2" in note for note in module["provenance"]["refinements"]))
            with self.subTest(triple=triple, case="security requirement"):
                with self.assertRaises(importer.ImportFailure) as raised:
                    self.import_ir("define i32 @entry() uwtable shadowcallstack { ret i32 0 }\n" + flags, triple=triple)
                self.assertEqual(raised.exception.stage, "import")
                self.assertEqual(raised.exception.symbol, "entry")

    def test_llvm22_bitcode_uwtable_rejects_surviving_invalid_payloads_and_records_reader_normalization(self):
        api = importer.LLVM(self.library, self.library_sha256)
        create_attribute = api.lib.LLVMCreateEnumAttribute
        create_attribute.restype = importer.P
        create_attribute.argtypes = [importer.P, importer.U, importer.Q]
        add_attribute = api.lib.LLVMAddAttributeAtIndex
        add_attribute.restype = None
        add_attribute.argtypes = [importer.P, importer.U, importer.P]
        kind = api.GetEnumAttributeKindForName(b"uwtable", 7)
        self.assertNotEqual(kind, 0)
        source = self.write("define i32 @entry() { ret i32 19 }\n",
                            layout="e-p:64:64-i64:64-i128:128-n8:16:32:64-S128")
        original = source.read_bytes()
        reference = importer.import_module(source, library_path=self.library, expected_sha256=self.library_sha256)
        # LLVM's reader drops None and narrows UWTableKind's int representation.
        # Admission concerns the parsed module; the original hash remains bound.
        for raw_value, normalized in ((0, None), (1, 1), (2, 2), ((1 << 32) + 2, 2),
                                      (3, "reject"), ((1 << 64) - 1, "reject")):
            with self.subTest(raw_payload=raw_value, parsed_payload=normalized):
                context = api.ContextCreate()
                llvm_module, message = importer.P(), importer.P()
                buffer = api.CreateMemoryBufferWithMemoryRangeCopy(original, len(original), b"uwtable-fixture")
                serialized = None
                try:
                    status = api.ParseIRInContext2(context, buffer, C.byref(llvm_module), C.byref(message))
                    self.assertEqual(status, 0, C.string_at(message).decode() if message else "parse failed")
                    if message:
                        api.DisposeMessage(message)
                        message = importer.P()
                    attribute = create_attribute(context, kind, raw_value)
                    self.assertEqual(api.GetEnumAttributeValue(attribute), raw_value)
                    add_attribute(api.GetFirstFunction(llvm_module), 0xffffffff, attribute)
                    status = api.VerifyModule(llvm_module, 2, C.byref(message))
                    self.assertEqual(status, 0, C.string_at(message).decode() if message else "verify failed")
                    serialized = api.WriteBitcodeToMemoryBuffer(llvm_module)
                    self.assertTrue(serialized)
                    data = C.string_at(api.GetBufferStart(serialized), api.GetBufferSize(serialized))
                finally:
                    if serialized:
                        api.DisposeMemoryBuffer(serialized)
                    if message:
                        api.DisposeMessage(message)
                    if llvm_module:
                        api.DisposeModule(llvm_module)
                    api.DisposeMemoryBuffer(buffer)
                    api.ContextDispose(context)
                binary = self.directory / "uwtable.bc"
                binary.write_bytes(data)
                self.assertTrue(data.startswith(b"BC\xc0\xde"))
                if normalized == "reject":
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(binary, library_path=self.library, expected_sha256=self.library_sha256)
                    self.assertEqual(raised.exception.stage, "import")
                    self.assertEqual(raised.exception.symbol, "entry")
                    continue
                module = importer.import_module(binary, library_path=self.library, expected_sha256=self.library_sha256)
                self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual({key: value for key, value in module.items()
                                  if key not in {"name", "provenance"}},
                                 {key: value for key, value in reference.items()
                                  if key not in {"name", "provenance"}})
                if normalized is None:
                    self.assertFalse(any("function uwtable=" in item
                                         for item in module["provenance"]["refinements"]))
                else:
                    self.assert_function_uwtable_provenance(module, "entry", normalized)

    def assert_module_uwtable_provenance(self, module, level):
        refinement = next(item for item in module["provenance"]["refinements"]
                          if f"module uwtable={level}" in item)
        self.assertIn("behavior=7 (Max)", refinement)
        for requirement in ("realized", "own-emitter", "instruction-precise", "DWARF"):
            self.assertIn(requirement, refinement)
        self.assertNotIn("erased optimization", refinement)

    def assert_function_uwtable_provenance(self, module, name, level):
        refinements = module["provenance"]["refinements"]
        refinement = next(item for item in refinements
                          if f"{name}: realized function uwtable={level}" in item)
        for requirement in ("own-emitter", "instruction-precise", "DWARF"):
            self.assertIn(requirement, refinement)
        self.assertNotIn("erased optimization", refinement)
        self.assertTrue(any("UWTable attributes validated after pinned LLVM parsing" in item
                            and "normalization" in item and "input_sha256" in item
                            for item in refinements))

    def test_llvm_reader_upgrades_legacy_pic_pie_behaviors_without_changing_input_provenance(self):
        entry = "define i32 @entry() { ret i32 19 }\n"
        for triple in TRIPLES:
            for key, old_behavior in (("PIC Level", 1), ("PIC Level", 7), ("PIE Level", 1)):
                # The upstream upgrade also replaces the legacy behavior's
                # integer type. Strict width checks concern the parsed module.
                for width in (8, 32, 64, 128):
                    with self.subTest(triple=triple, key=key, old_behavior=old_behavior, width=width):
                        module = self.import_ir(entry + '!llvm.module.flags = !{!0}\n'
                                                + f'!0 = !{{i{width} {old_behavior}, !"{key}", i32 1}}\n',
                                                triple=triple)
                        self.assert_pic_pie_provenance(module, key, 1)
                        self.assertEqual(module["provenance"]["source_function_count"], 1)
                        self.assertEqual(module["provenance"]["input_sha256"],
                                         hashlib.sha256(self.source.read_bytes()).hexdigest())
                        self.assertIn(f'i{width} {old_behavior}, !"{key}"', self.source.read_text())
                        terminator = self.function(module, "entry")["blocks"][0]["terminator"]
                        self.assertEqual(terminator["op"], "return")
                        self.assertEqual(terminator["value"]["kind"], "int")
                        self.assertEqual(terminator["value"]["bits"], "19")
                        self.assertEqual(module["types"][terminator["value"]["ty"]],
                                         {"kind": "int", "bits": 32})

    def test_conflicting_pic_pie_flags_reject_and_require_behavior_is_not_silently_erased(self):
        entry = "define i32 @entry() { ret i32 0 }\n"
        for key, behavior in (("PIC Level", 8), ("PIE Level", 7)):
            with self.subTest(key=key, case="conflicting ordinary entries"):
                self.reject(entry + '!llvm.module.flags = !{!0, !1}\n'
                            + f'!0 = !{{i32 {behavior}, !"{key}", i32 1}}\n'
                            + f'!1 = !{{i32 {behavior}, !"{key}", i32 2}}\n', stage="llvm-verify")
            with self.subTest(key=key, case="Require payload"):
                self.reject(entry + '!llvm.module.flags = !{!0, !1}\n'
                            + f'!0 = !{{i32 {behavior}, !"{key}", i32 1}}\n'
                            + f'!1 = !{{i32 3, !"{key}", !2}}\n'
                            + f'!2 = !{{!"{key}", i32 1}}\n')

    def assert_pic_pie_provenance(self, module, key, level):
        behavior = 8 if key == "PIC Level" else 7
        refinement = next(item for item in module["provenance"]["refinements"]
                          if f"{key}={level}" in item)
        self.assertIn(f"behavior={behavior}", refinement)
        for requirement in ("static", "non-preemptive", "symbol", "calls", "relocations"):
            self.assertIn(requirement, refinement)

    def test_numeric_module_flags_cannot_truncate_wide_payloads_into_supported_values(self):
        entry = "define i32 @entry() { ret i32 0 }\n"
        valid_low_bits = {"Code Model": 3, "frame-pointer": 2,
                          "RtLibUseGOT": 1, "SmallDataLimit": 8}
        for flag, low_bits in valid_low_bits.items():
            with self.subTest(flag=flag):
                wide_value = (1 << 64) + low_bits
                self.reject(entry + '!llvm.module.flags = !{!0, !1}\n'
                            + f'!0 = !{{i32 1, !"{flag}", i128 {wide_value}}}\n'
                            + '!1 = !{i32 1, !"target-abi", !"lp64"}\n', triple="riscv64")
        self.reject(entry + '!llvm.module.flags = !{!0, !1}\n'
                    + '!0 = !{i32 1, !"Code Model", i8 3}\n'
                    + '!1 = !{i32 1, !"target-abi", !"lp64"}\n', triple="riscv64")

    def test_non_leaf_no_reserve_frame_pointer_policy_is_audited_on_all_three_isas(self):
        body = """
define i64 @entry(i64 %value) "frame-pointer"="non-leaf-no-reserve" {
  ret i64 %value
}
!llvm.module.flags = !{!0}
!0 = !{i32 7, !"frame-pointer", i32 4}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir(body, triple=triple)
                refinements = module["provenance"]["refinements"]
                self.assertTrue(any("frame-pointer=4" in item for item in refinements))
                self.assertTrue(any("frame-pointer=non-leaf-no-reserve" in item for item in refinements))
                function = self.function(module, "entry")
                self.assertEqual(function["blocks"][0]["terminator"]["value"],
                                 {"kind": "value", "id": function["params"][0]["id"]})

    def test_reserved_frame_pointer_enum_and_unknown_policy_strings_reject(self):
        for number in (3, 5):
            with self.subTest(frame_pointer_enum=number):
                self.reject('define i32 @entry() { ret i32 0 }\n!llvm.module.flags = !{!0}\n'
                            + f'!0 = !{{i32 7, !"frame-pointer", i32 {number}}}\n')
        for value in ("reserved", "non-leaf-no-reserve-extra", "unknown"):
            with self.subTest(frame_pointer_string=value):
                stage = "import" if value == "reserved" else "llvm-verify"
                self.reject(f'define i32 @entry() "frame-pointer"="{value}" {{ ret i32 0 }}\n',
                            stage=stage)

    def test_windows_and_darwin_targets_cannot_use_the_elf_c_abi(self):
        for triple in ("x86_64-pc-windows-msvc", "x86_64-w64-windows-gnu",
                       "x86_64-apple-darwin", "aarch64-apple-darwin"):
            with self.subTest(triple=triple):
                self.reject("define i64 @entry(i64 %value) { ret i64 %value }\n",
                            triple=triple)

    def test_llvm_parser_and_verifier_reject_malformed_ssa(self):
        cases = {
            "syntax": "define i32 @entry( { ret i32 0 }",
            "unknown value": "define i32 @entry() { ret i32 %missing }",
            "non-dominating use": """
define i32 @entry(i1 %condition) {
  br i1 %condition, label %left, label %merge
left:
  %only_left = add i32 1, 2
  br label %merge
merge:
  ret i32 %only_left
}
""",
            "incomplete phi": """
define i32 @entry(i1 %condition) {
start:
  br i1 %condition, label %left, label %right
left:
  br label %merge
right:
  br label %merge
merge:
  %result = phi i32 [ 1, %left ]
  ret i32 %result
}
""",
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                stage = "parse" if name in ("syntax", "unknown value") else "llvm-verify"
                self.reject(body, stage=stage)

    def test_unsupported_module_features_are_rejected_instead_of_dropped(self):
        cases = {
            "module assembly": 'module asm "nop"\ndefine i32 @entry() { ret i32 0 }',
            "ifunc": "@indirect = ifunc i32 (), ptr @resolve\ndefine ptr @resolve() { ret ptr null }",
            "TLS": "@thread = thread_local global i32 0",
            "address space": "@foreign = addrspace(1) global i32 0",
            "float declaration": "declare double @unsupported(double)",
            "float hidden in poison aggregate": "@mixed = global {i32, double} {i32 0, double poison}",
            "constructor list": "@llvm.global_ctors = appending global [1 x {i32, ptr, ptr}] [{i32, ptr, ptr} {i32 65535, ptr @initialize, ptr null}]\ndeclare void @initialize()",
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                self.reject(body)

    def test_hidden_module_fields_reject_before_traversal_and_preserve_existing_cli_output(self):
        cases = {
            "global partition": '@g = global i32 0, partition "extra"\n',
            "function partition": 'define void @f() partition "extra" { ret void }\n',
            "global sanitizer metadata": "@g = global i32 0, sanitize_memtag\n",
            "global code model": '@g = global i32 0, code_model "large"\n',
            "global attributes": '@g = global i32 0 #0\nattributes #0 = { "bss-section"=".custom" }\n',
        }
        good_source = self.write("define i32 @entry() { ret i32 42 }\n")
        output = self.directory / "existing-good.json"
        command = [sys.executable, str(SCRIPT), str(good_source), "--output", str(output),
                   "--llvm-library", str(self.library), "--llvm-sha256", self.library_sha256]
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        previous_bytes = output.read_bytes()
        self.assertEqual(json.loads(previous_bytes)["functions"][0]["name"], "entry")
        for name, body in cases.items():
            with self.subTest(case=name):
                # The unsupported declaration also fails traversal. The audit
                # must identify hidden fields before normalizing any function.
                body += "declare double @unsupported_later(double)\n"
                self.reject(body, stage="bitcode-audit")
                completed = subprocess.run(command, cwd=ROOT, capture_output=True,
                                           text=True, timeout=30)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(json.loads(completed.stderr)["error"]["stage"], "bitcode-audit")
                self.assertEqual(completed.stdout, "")
                self.assertEqual(output.read_bytes(), previous_bytes,
                                 "rejected whole-unit import replaced the previous verified artifact")

    def test_llvm_ident_is_self_reported_provenance_and_does_not_override_declared_producer(self):
        source = self.write("""
define i32 @entry() { ret i32 0 }
!llvm.ident = !{!0, !1}
!0 = !{!"vendor frontend 99.0"}
!1 = !{!"custom build"}
""")
        module = importer.import_module(source, library_path=self.library, expected_sha256=self.library_sha256)
        self.assertEqual(module["provenance"]["frontend"], "LLVM IR")
        self.assertEqual(module["provenance"]["frontend_version"],
                         "self-reported !llvm.ident: vendor frontend 99.0; custom build")
        self.assertIn("LLVM 22.1.6", module["provenance"]["importer_version"])
        self.assertTrue(any("descriptive named metadata llvm.ident" in item
                            for item in module["provenance"]["refinements"]))
        declared = importer.import_module(source, library_path=self.library, expected_sha256=self.library_sha256,
                                          frontend="declared frontend", frontend_version="declared version")
        self.assertEqual(declared["provenance"]["frontend"], "declared frontend")
        self.assertEqual(declared["provenance"]["frontend_version"], "declared version")
        anonymous = self.import_ir("define i32 @entry() { ret i32 0 }\n")
        self.assertEqual(anonymous["provenance"]["frontend_version"], "producer version not declared")

    def test_errno_tbaa_named_metadata_erasure_preserves_calls_and_memory_on_all_three_isas(self):
        body = """
@state = global i32 0, align 4
declare void @foreign(ptr)
define i32 @entry() {
  store volatile i32 1, ptr @state, align 4, !tbaa !0
  call void @foreign(ptr @state)
  %value = load volatile i32, ptr @state, align 4, !tbaa !0
  ret i32 %value
}
!llvm.errno.tbaa = !{!0}
!0 = !{!1, !1, i64 0}
!1 = !{!"int", !2, i64 0}
!2 = !{!"omnipotent char", !3, i64 0}
!3 = !{!"Simple C/C++ TBAA"}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir(body, triple=triple)
                self.assertEqual(module["target"]["triple"], triple)
                self.assertEqual(module["provenance"]["source_function_count"], 2)
                self.assertEqual(module["provenance"]["source_global_count"], 1)
                self.assertEqual(module["provenance"]["input_sha256"],
                                 hashlib.sha256(self.source.read_bytes()).hexdigest())
                refinement = next(item for item in module["provenance"]["refinements"]
                                  if "llvm.errno.tbaa" in item)
                self.assertIn("erased", refinement)
                self.assertIn("alias-analysis", refinement)
                operations = self.operations(self.function(module, "entry"))
                self.assertEqual([operation["op"] for operation in operations], ["store", "call", "load"])
                self.assertEqual(operations[0]["value"]["bits"], "1")
                self.assertTrue(operations[0]["volatile"])
                self.assertTrue(operations[2]["volatile"])
                self.assertEqual(operations[1]["callee"]["name"], "foreign")
                self.assertEqual(operations[1]["args"][0]["name"], "state")

    def test_errno_named_metadata_allowlist_does_not_accept_adjacent_unknown_names(self):
        for name in ("llvm.errno.tbaa.extra", "llvm.errno.tbaa2", "llvm.errno"):
            with self.subTest(metadata=name):
                self.reject(f'define i32 @entry() {{ ret i32 0 }}\n!{name} = !{{!0}}\n'
                            + '!0 = !{!1, !1, i64 0}\n!1 = !{!"int", !2, i64 0}\n'
                            + '!2 = !{!"Simple C/C++ TBAA"}\n')

    def test_malformed_errno_tbaa_named_metadata_rejects_during_llvm_verification(self):
        cases = {
            "empty named list": "!llvm.errno.tbaa = !{}\n",
            "empty tag": "!llvm.errno.tbaa = !{!0}\n!0 = !{}\n",
            "old-style tag": '!llvm.errno.tbaa = !{!0}\n!0 = !{!"invalid"}\n',
        }
        for name, metadata in cases.items():
            with self.subTest(case=name):
                self.reject("define i32 @entry() { ret i32 0 }\n" + metadata, stage="llvm-verify")

    def test_poison_or_dead_results_do_not_hide_unsupported_operations(self):
        cases = {
            "floating add": "define i32 @entry() { %unused = fadd double poison, poison\n ret i32 0 }",
            "wide integer": "define i32 @entry() { %unused = add i128 poison, 1\n ret i32 0 }",
            "vector": "define i32 @entry() { %unused = add <2 x i32> poison, poison\n ret i32 0 }",
            "aggregate extraction hidden float": "define i32 @entry() { %unused = extractvalue {i32, double} poison, 0\n ret i32 0 }",
            "intrinsic": "declare i32 @llvm.ctpop.i32(i32)\ndefine i32 @entry() { %unused = call i32 @llvm.ctpop.i32(i32 poison)\n ret i32 0 }",
            "dynamic alloca": "define i32 @entry(i64 %size) { %unused = alloca i8, i64 %size\n ret i32 0 }",
            "inline assembly": 'define void @entry() { call void asm sideeffect "nop", ""()\n ret void }',
            "deopt poison bundle": 'declare void @foreign()\ndefine void @entry() { call void @foreign() [ "deopt"(i32 poison) ]\n ret void }',
            "musttail": "declare void @foreign()\ndefine void @entry() { musttail call void @foreign()\n ret void }",
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                self.reject(body)

    def test_wide_alloca_count_and_repeated_non_entry_allocation_are_rejected(self):
        cases = {
            "count cannot be narrowed through a 64-bit LLVM getter": """
define i32 @entry() {
  %unused = alloca i8, i128 4
  ret i32 0
}
""",
            "loop needs a fresh allocation on every iteration": """
define ptr @entry(i1 %condition) {
start:
  br label %loop
loop:
  %fresh = alloca i8
  br i1 %condition, label %loop, label %exit
exit:
  ret ptr %fresh
}
""",
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                self.reject(body)

    def test_atomic_load_store_read_modify_write_and_fence_are_preserved_without_inferred_native_profile(self):
        instructions = (
            "%unused = load atomic i32, ptr @counter seq_cst, align 4",
            "store atomic i32 1, ptr @counter seq_cst, align 4",
            "%unused = atomicrmw add ptr @counter, i32 1 seq_cst",
            "fence seq_cst",
        )
        for instruction, operation_name in zip(instructions, ("atomic_load", "atomic_store", "atomic_rmw", "atomic_fence")):
            with self.subTest(instruction=instruction):
                module = self.import_ir(f"@counter = global i32 0\ndefine i32 @entry() {{ {instruction}\nret i32 0 }}")
                self.assertEqual([glob["name"] for glob in module["globals"]], ["counter"])
                self.assertEqual([function["name"] for function in module["functions"]], ["entry"])
                function = self.function(module, "entry")
                rows = [row for block in function["blocks"] for row in block["instructions"]]
                self.assertEqual(len(rows), 1)
                operation = rows[0]["operation"]
                self.assertEqual(operation["op"], operation_name)
                self.assertEqual(operation["ordering"], "seq_cst")
                self.assertEqual(operation["sync_scope"], 1)
                if operation_name != "atomic_fence":
                    self.assertEqual(operation["pointer"]["name"], "counter")
                    self.assertEqual(operation["alignment"], 4)
                    self.assertFalse(operation["volatile"])
                if operation_name in {"atomic_store", "atomic_rmw"}:
                    self.assertEqual(operation["value"]["bits"], "1")
                    self.assertEqual(module["types"][operation["value"]["ty"]], {"kind": "int", "bits": 32})
                if operation_name == "atomic_rmw":
                    self.assertEqual(operation["kind"], "add")
                self.assertEqual(rows[0]["result"] is not None, operation_name in {"atomic_load", "atomic_rmw"})
                self.assertEqual(function["blocks"][0]["terminator"]["op"], "return")
                self.assertEqual(function["blocks"][0]["terminator"]["value"]["bits"], "0")
                self.assertNotIn("atomic_profile", module["target"])
                self.assertEqual(module["atomic_sync_scopes"], [{"id": 0, "name": list(b"singlethread")}, {"id": 1, "name": []}])
                self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(self.source.read_bytes()).hexdigest())

    def test_eh_preserves_complete_invoke_landingpad_resume_when_normal_path_returns_a_scalar(self):
        body = """
declare void @may_throw()
declare i32 @personality(...)
define i32 @entry() personality ptr @personality {
  invoke void @may_throw() to label %normal unwind label %cleanup
normal:
  ret i32 0
cleanup:
  %exception = landingpad { ptr, i32 } cleanup
  resume { ptr, i32 } %exception
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir(body, triple=triple)
                self.assertEqual({fn["name"] for fn in module["functions"]}, {"entry", "may_throw", "personality"})
                self.assertEqual(module["provenance"]["source_function_count"], 3)
                self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(self.source.read_bytes()).hexdigest())
                self.assertEqual(module["globals"], [])
                self.assertEqual(module["aliases"], [])
                personality = self.function(module, "personality")
                self.assertIsNone(personality["entry"])
                self.assertTrue(personality["signature"]["variadic"])
                self.assertEqual(personality["signature"]["params"], [])
                entry = self.function(module, "entry")
                self.assertEqual(entry["exception_handling"]["model"], "itanium_dwarf_v1")
                self.assertEqual(entry["exception_handling"]["personality"]["name"], "personality")
                blocks = entry["blocks"]
                self.assertEqual(len(blocks), 3)
                invoke = blocks[0]["terminator"]
                self.assertEqual(invoke["op"], "invoke")
                self.assertEqual(invoke["callee"]["name"], "may_throw")
                self.assertIsNone(invoke["result"])
                self.assertEqual((invoke["normal"], invoke["unwind"]), (blocks[1]["id"], blocks[2]["id"]))
                self.assertEqual(blocks[1]["terminator"]["op"], "return")
                landingpad = blocks[2]["instructions"][0]
                self.assertEqual(landingpad["operation"], {"op": "landing_pad", "cleanup": True, "clauses": []})
                resume = blocks[2]["terminator"]
                self.assertEqual(resume["op"], "resume")
                self.assertEqual(resume["value"]["id"], landingpad["result"]["id"])
                self.assertTrue(any("metadata-only personality declaration i32(...)" in note for note in module["provenance"]["refinements"]))

    def test_unsupported_abi_attributes_are_rejected_on_unused_declarations_and_calls(self):
        cases = {
            "byval declaration": "declare void @foreign(ptr byval(i32))",
            "wide sret storage declaration": "declare void @foreign(ptr sret(i128))",
            "inalloca declaration": "declare void @foreign(ptr inalloca(i32))",
            "byval poison call": "declare void @foreign(ptr)\ndefine void @entry() { call void @foreign(ptr byval(i32) poison)\n ret void }",
            "cold calling convention": "declare coldcc i32 @foreign(i32)",
            "naked": "define void @entry() naked { ret void }",
            "unknown string attribute": 'define i32 @entry() "unknown-semantics"="required" { ret i32 0 }',
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                self.reject(body)

    def test_memory_sanitizer_noundef_and_security_requirements_are_rejected(self):
        # With MemorySanitizer, noundef participates in the instrumented ABI.
        self.reject("""
define noundef i32 @entry(i32 noundef %value) sanitize_memory {
  ret i32 %value
}
""")
        attributes = (
            "ssp", "sspreq", "sspstrong", "safestack", "shadowcallstack",
            "speculative_load_hardening", "sanitize_address", "sanitize_hwaddress",
            '"branch-target-enforcement"="true"', '"sign-return-address"="all"',
        )
        for attribute in attributes:
            with self.subTest(attribute=attribute):
                self.reject(f"define i32 @entry() {attribute} {{ ret i32 0 }}\n")

    def test_clang21_text_and_bitcode_full_unit_inventory_and_symbol_closure_on_all_three_isas(self):
        clang = None
        frontend_version = None
        for candidate in ("clang-21", "clang"):
            executable = shutil.which(candidate)
            if executable is None:
                continue
            completed = subprocess.run([executable, "--version"], capture_output=True,
                                       text=True, timeout=15)
            if completed.returncode == 0 and re.search(r"\bclang version 21\.", completed.stdout):
                clang, frontend_version = executable, completed.stdout.splitlines()[0]
                break
        if clang is None:
            self.skipTest("Clang 21 frontend unavailable")

        flags = ["-O1", "-S", "-emit-llvm", "-ffreestanding", "-fno-builtin",
                 "-fno-vectorize", "-fno-slp-vectorize", "-fno-pic", "-fno-pie",
                 "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
                 "-fno-stack-protector", "-Xclang", "-disable-lifetime-markers"]
        self.check_clang_scalar_unit(clang, frontend_version, flags)

    def test_clang22_text_and_bitcode_unmodified_scalar_unit_on_all_three_isas(self):
        clang, frontend_version = self.clang22_frontend()
        self.check_clang_scalar_unit(clang, frontend_version, self.clang22_frontend_flags(), require_errno=True)

    def test_clang22_hosted_default_unwind_units_import_whole_text_and_bitcode_all_three_isas(self):
        clang, frontend_version = self.clang22_frontend()
        # Hosted targets retain their normal unwind defaults. No unwind flag,
        # source rewrite or IR filtering substitutes for the producer output.
        flags = [flag for flag in self.clang22_frontend_flags() if flag != "-ffreestanding"]
        self.check_clang_scalar_unit(clang, frontend_version, flags,
                                     require_errno=True, require_unwind=True)

    def test_clang22_hidden_visibility_units_import_whole_text_and_bitcode_all_three_isas(self):
        clang, frontend_version = self.clang22_frontend()
        # Retain normal hosted unwind defaults alongside the actual producer's
        # hidden-visibility mode; import the complete unchanged C translation unit.
        flags = [flag for flag in self.clang22_frontend_flags() if flag != "-ffreestanding"]
        self.check_clang_scalar_unit(clang, frontend_version, [*flags, "-fvisibility=hidden"],
                                     require_errno=True, require_unwind=True,
                                     definition_visibility="hidden")

    def test_clang22_pic_pie_scalar_units_import_whole_text_and_bitcode_all_three_isas(self):
        clang, frontend_version = self.clang22_frontend()
        # Request the actual PIC/PIE modes at the producer; keep every other
        # frontend option and the complete original C fixture unchanged.
        common = [flag for flag in self.clang22_frontend_flags()
                  if flag not in {"-fno-pic", "-fno-pie"}]
        for option, levels in (("-fpic", {"PIC Level": 1}),
                               ("-fPIC", {"PIC Level": 2}),
                               ("-fpie", {"PIC Level": 1, "PIE Level": 1}),
                               ("-fPIE", {"PIC Level": 2, "PIE Level": 2})):
            with self.subTest(producer_option=option):
                self.check_clang_scalar_unit(clang, frontend_version, [*common, option],
                                             require_errno=True, relocation_levels=levels)

    def test_clang22_whole_units_with_unused_unsupported_entities_reject_text_and_bitcode_all_three_isas(self):
        clang, frontend_version = self.clang22_frontend()
        flags = self.clang22_frontend_flags()
        fixture = ROOT / "tests/fixtures/ocore_import_scalar.c"
        variants = {
            "unsupported_float": "double unsupported_float(double value) { return value + 1.0; }\n",
            "unsupported_tls": "__thread unsigned long unsupported_tls;\n",
        }
        for symbol, declaration in variants.items():
            # Keep the complete original fixture in this translation unit. Its
            # exported integer functions must not mask an unused unsupported one.
            c_source = self.directory / f"{symbol}.c"
            c_source.write_text(f'#include "{fixture.as_posix()}"\n' + declaration)
            for triple in TRIPLES:
                target_flags = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
                for suffix in ("ll", "bc"):
                    with self.subTest(symbol=symbol, triple=triple, suffix=suffix):
                        source = self.directory / f"{symbol}-{triple}.{suffix}"
                        producer_flags = flags if suffix == "ll" else [flag for flag in flags if flag != "-S"] + ["-c"]
                        completed = subprocess.run(
                            [clang, "--target=" + triple, *target_flags, *producer_flags,
                             str(c_source), "-o", str(source)],
                            cwd=ROOT, capture_output=True, text=True, timeout=30)
                        self.assertEqual(completed.returncode, 0, completed.stderr)
                        if suffix == "ll":
                            llvm_ir = source.read_text()
                            self.assertIn("@imported_unsigned_mix(", llvm_ir)
                            self.assertIn("@" + symbol, llvm_ir)
                            if symbol == "unsupported_tls":
                                self.assertRegex(llvm_ir, r"@unsupported_tls =[^\n]*thread_local")
                            else:
                                self.assertRegex(llvm_ir, r"define[^\n]*double @unsupported_float\(")
                        else:
                            self.assertTrue(source.read_bytes().startswith(b"BC\xc0\xde"))
                        with self.assertRaises(importer.ImportFailure) as raised:
                            importer.import_module(source, library_path=self.library, expected_sha256=self.library_sha256,
                                                   frontend="Clang", frontend_version=frontend_version)
                        self.assertEqual(raised.exception.stage, "import")
                        self.assertEqual(raised.exception.symbol, symbol)

    def clang22_frontend(self):
        override = os.environ.get("OCORE_TEST_CLANG22")
        sdk = Path.home() / ".cache/ostadix-toolchains/llvm-22.1.6/sdk"
        candidates = [override] if override else ["clang-22", "clang22", "clang", *(
            str(path) for path in sorted(sdk.glob("LLVM-22.1.6-*/bin/clang")))]
        clang = None
        frontend_version = None
        for candidate in candidates:
            executable = shutil.which(candidate)
            if executable is None:
                if override:
                    self.fail(f"requested Clang 22 frontend unavailable: {candidate}")
                continue
            completed = subprocess.run([executable, "--version"], capture_output=True,
                                       text=True, timeout=15)
            if completed.returncode == 0 and re.search(r"\bclang version 22\.", completed.stdout):
                clang, frontend_version = executable, completed.stdout.splitlines()[0]
                break
            if override:
                self.fail(f"requested frontend is not usable Clang 22: {completed.stdout}{completed.stderr}")
        if clang is None:
            self.skipTest("Clang 22 producer unavailable; set OCORE_TEST_CLANG22 to require it")
        return clang, frontend_version

    @staticmethod
    def clang22_frontend_flags():
        # Match check_ocore_import_equivalence.py's frontend invocation. The
        # source and resulting IR are imported whole, without metadata removal.
        return ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie",
                "-O1", "-fno-vectorize", "-fno-slp-vectorize", "-Xclang", "-disable-lifetime-markers",
                "-S", "-emit-llvm"]

    def check_clang_scalar_unit(self, clang, frontend_version, flags, require_errno=False,
                                relocation_levels=None, require_unwind=False, definition_visibility=None):
        expected_definitions = {"imported_" + suffix for suffix in (
            "unsigned_mix", "signed_mix", "narrow", "loop", "many", "call",
            "indirect", "table_call", "global", "packed", "memory", "stack",
        )}
        expected_declarations = {"foreign_scalar_sum", "foreign_scalar_callback"}
        fixture = ROOT / "tests/fixtures/ocore_import_scalar.c"

        def symbol_references(value):
            if isinstance(value, dict):
                if value.get("kind") == "symbol":
                    yield value["name"]
                for child in value.values():
                    yield from symbol_references(child)
            elif isinstance(value, list):
                for child in value:
                    yield from symbol_references(child)

        for triple in TRIPLES:
            with self.subTest(triple=triple):
                source = self.directory / f"{triple}.ll"
                target_flags = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
                completed = subprocess.run(
                    [clang, "--target=" + triple, *target_flags, *flags,
                     str(fixture), "-o", str(source)],
                    cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                llvm_ir = source.read_text()
                if require_errno:
                    self.assertIn("!llvm.errno.tbaa =", llvm_ir,
                                  "the producer did not emit the named metadata under test")
                if require_unwind:
                    self.assertIn('!"uwtable", i32 2}', llvm_ir,
                                  "the hosted producer did not emit its default unwind requirement")
                # This fixture uses simple C names. Independently count the
                # frontend inventory so skipped declarations/globals fail here.
                frontend_functions = dict((name, kind) for kind, name in re.findall(
                    r"^(define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(",
                    llvm_ir, re.MULTILINE))
                frontend_globals = set(re.findall(
                    r"^@([A-Za-z_][A-Za-z0-9_.$]*)\s*=", llvm_ir, re.MULTILINE))
                self.assertEqual({name for name, kind in frontend_functions.items() if kind == "define"},
                                 expected_definitions)
                self.assertEqual({name for name, kind in frontend_functions.items() if kind == "declare"},
                                 expected_declarations)
                module = importer.import_module(source, library_path=self.library, expected_sha256=self.library_sha256,
                                                frontend="Clang", frontend_version=frontend_version)
                if require_errno:
                    self.assertTrue(any("llvm.errno.tbaa" in item and "alias-analysis" in item
                                        for item in module["provenance"]["refinements"]))
                for key, level in (relocation_levels or {}).items():
                    self.assert_pic_pie_provenance(module, key, level)
                if require_unwind:
                    self.assert_module_uwtable_provenance(module, 2)
                    for name in expected_definitions:
                        self.assert_function_uwtable_provenance(module, name, 2)
                binary_source = source.with_suffix(".bc")
                binary_flags = [flag for flag in flags if flag != "-S"]
                completed = subprocess.run(
                    [clang, "--target=" + triple, *binary_flags, "-c", *target_flags,
                     str(fixture), "-o", str(binary_source)],
                    cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertTrue(binary_source.read_bytes().startswith(b"BC\xc0\xde"))
                binary_module = importer.import_module(binary_source, library_path=self.library, expected_sha256=self.library_sha256,
                                                       frontend="Clang", frontend_version=frontend_version)
                for key, level in (relocation_levels or {}).items():
                    self.assert_pic_pie_provenance(binary_module, key, level)
                if require_unwind:
                    self.assert_module_uwtable_provenance(binary_module, 2)
                    for name in expected_definitions:
                        self.assert_function_uwtable_provenance(binary_module, name, 2)
                if definition_visibility:
                    for imported in (module, binary_module):
                        for function in imported["functions"]:
                            expected = definition_visibility if function["entry"] is not None else "default"
                            self.assertEqual(function["visibility"], expected)
                            if expected != "default":
                                self.assert_visibility_provenance(imported, function["name"], expected)
                        for glob in imported["globals"]:
                            self.assertEqual(glob["visibility"], "default",
                                             "the fixture's internal global retains default visibility")
                self.assertEqual(binary_module["provenance"]["input_sha256"],
                                 hashlib.sha256(binary_source.read_bytes()).hexdigest())
                self.assertEqual(binary_module["provenance"]["source_function_count"], len(frontend_functions))
                self.assertEqual(binary_module["provenance"]["source_global_count"], len(frontend_globals))
                self.assertEqual(binary_module["provenance"]["frontend_version"], frontend_version)
                # LLVM's bitcode upgrader and text parser may give erased
                # assumption payloads different encodings. All native data,
                # signatures, CFGs, operands and instructions must still agree.
                self.assertEqual({key: value for key, value in binary_module.items()
                                  if key not in {"name", "provenance"}},
                                 {key: value for key, value in module.items()
                                  if key not in {"name", "provenance"}})
                definitions = {fn["name"] for fn in module["functions"] if fn["entry"] is not None}
                declarations = {fn["name"] for fn in module["functions"] if fn["entry"] is None}
                globals_by_name = {glob["name"]: glob for glob in module["globals"]}
                self.assertEqual(definitions, expected_definitions)
                self.assertEqual(declarations, expected_declarations)
                self.assertEqual(set(globals_by_name), frontend_globals)
                self.assertEqual(module["provenance"]["source_function_count"], len(frontend_functions))
                self.assertEqual(module["provenance"]["source_global_count"], len(frontend_globals))
                self.assertEqual(module["provenance"]["input_sha256"],
                                 hashlib.sha256(source.read_bytes()).hexdigest())
                self.assertEqual(module["provenance"]["frontend_version"], frontend_version)
                self.assertEqual(module["target"]["triple"], triple)
                self.assertEqual(module["semantics"], "llvm_defined_behavior_v1")

                symbols = definitions | declarations | set(globals_by_name)
                references = set(symbol_references(module["functions"]))
                for glob in module["globals"]:
                    if glob["initializer"]:
                        references.update(reloc["symbol"] for reloc in glob["initializer"]["relocations"])
                self.assertFalse(references - symbols, "normalization lost the native symbol closure")
                self.assertEqual(references, expected_declarations | {"imported_total"})
                self.assertEqual(globals_by_name["imported_total"]["initializer"],
                                 {"bytes": [7] + [0] * 7, "relocations": []})
                direct = next(operation for operation in self.operations(self.function(module, "imported_call"))
                              if operation["op"] == "call")
                self.assertEqual(direct["callee"]["name"], "foreign_scalar_sum")
                self.assertEqual(len(direct["args"]), 12)
                self.assertEqual([argument["bits"] for argument in direct["args"][1:]],
                                 [str(value) for value in range(2, 13)])
                self.assertEqual(direct["signature"], self.function(module, "foreign_scalar_sum")["signature"])
                indirect = next(operation for operation in self.operations(self.function(module, "imported_indirect"))
                                if operation["op"] == "call")
                self.assertEqual(indirect["callee"]["kind"], "value")
                self.assertEqual(len(indirect["args"]), 1)
                self.assertTrue(any(operation["op"] == "phi"
                                    for operation in self.operations(self.function(module, "imported_loop"))))
                accesses = [operation for operation in self.operations(self.function(module, "imported_global"))
                            if operation["op"] in {"load", "store"}]
                self.assertEqual({operation["op"] for operation in accesses}, {"load", "store"})
                self.assertTrue(all(operation["volatile"] for operation in accesses))

    def test_real_llvm22_binary_input_and_isolated_corrupt_bitcode_rejections(self):
        source = self.write("""
@slot = global ptr @foreign
declare i32 @foreign(i32)
define i32 @entry(i8 %byte) {
  %extended = zext nneg i8 %byte to i32
  %result = call i32 @foreign(i32 %extended)
  ret i32 %result
}
""", layout="e-p:64:64-i64:64-i128:128-n8:16:32:64-S128")
        reference = importer.import_module(source, library_path=self.library, expected_sha256=self.library_sha256)
        api = importer.LLVM(self.library, self.library_sha256)
        data = source.read_bytes()
        context = api.ContextCreate()
        buffer = api.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"llvm22-fixture")
        llvm_module, message = C.c_void_p(), C.c_void_p()
        serialized = None
        try:
            status = api.ParseIRInContext2(context, buffer, C.byref(llvm_module), C.byref(message))
            self.assertEqual(status, 0, C.string_at(message).decode() if message else "LLVM parse failed")
            if message:
                api.DisposeMessage(message)
                message = C.c_void_p()
            status = api.VerifyModule(llvm_module, 2, C.byref(message))
            self.assertEqual(status, 0, C.string_at(message).decode() if message else "LLVM verification failed")
            serialized = api.WriteBitcodeToMemoryBuffer(llvm_module)
            self.assertTrue(serialized)
            binary_data = C.string_at(api.GetBufferStart(serialized), api.GetBufferSize(serialized))
        finally:
            if serialized:
                api.DisposeMemoryBuffer(serialized)
            if message:
                api.DisposeMessage(message)
            if llvm_module:
                api.DisposeModule(llvm_module)
            api.DisposeMemoryBuffer(buffer)
            api.ContextDispose(context)

        self.assertTrue(binary_data.startswith(b"BC\xc0\xde"))
        binary_source = self.directory / "llvm22.bc"
        binary_source.write_bytes(binary_data)
        module = importer.import_module(binary_source, library_path=self.library, expected_sha256=self.library_sha256)
        self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(binary_data).hexdigest())
        self.assertEqual(module["provenance"]["source_function_count"], 2)
        self.assertEqual(module["provenance"]["source_global_count"], 1)
        self.assertEqual({key: value for key, value in module.items()
                          if key not in {"name", "provenance"}},
                         {key: value for key, value in reference.items()
                          if key not in {"name", "provenance"}})
        self.assertEqual(self.operations(self.function(module, "entry"))[0]["kind"], "z_ext")
        self.assertIn("zext nneg poison assumption erased", module["provenance"]["refinements"])
        self.assertEqual(module["globals"][0]["initializer"]["relocations"],
                         [{"offset": 0, "width": 64, "symbol": "foreign", "addend": 0}])

        corruptions = {"magic only": b"BC\xc0\xde",
                       "malformed header": b"BC\xc0\xde" + b"\xff" * 12,
                       "truncated real bitcode": binary_data[:len(binary_data) // 2]}
        for name, corrupt_data in corruptions.items():
            with self.subTest(case=name):
                corrupt_source = self.directory / "corrupt.bc"
                corrupt_source.write_bytes(corrupt_data)
                output = self.directory / "corrupt.json"
                completed = subprocess.run(
                    [sys.executable, str(SCRIPT), str(corrupt_source), "--output", str(output),
                     "--llvm-library", str(self.library), "--llvm-sha256", self.library_sha256],
                    cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertEqual(json.loads(completed.stderr)["error"]["stage"], "parse")
                self.assertFalse(output.exists())

    def test_cli_auto_discovery_explicit_library_and_failure_leave_no_partial_artifact(self):
        source = self.write("define i32 @entry() { ret i32 42 }\n")
        environment = os.environ.copy()
        if os.environ.get("OCORE_TEST_LLVM_LIBRARY") and os.environ.get("OCORE_TEST_LLVM_SHA256"):
            # Exercise the real discovery path with an isolated location for
            # the explicitly pinned alternative distribution. Production's
            # default library identity and digest remain unchanged.
            rustup = self.directory / "discovery-fixture"
            candidate = rustup / "toolchains" / f"{importer.PINNED_RUST}-test" / "lib" / f"libLLVM.so.22.1-rust-{importer.PINNED_RUST}-stable"
            candidate.parent.mkdir(parents=True)
            candidate.symlink_to(self.library)
            environment["RUSTUP_HOME"] = str(rustup)
        for arguments, filename in (([], "auto.json"),
                                    (["--llvm-library", str(self.library), "--llvm-sha256", self.library_sha256], "explicit.json")):
            with self.subTest(arguments=arguments):
                output = self.directory / filename
                completed = subprocess.run(
                    [sys.executable, str(SCRIPT), str(source), "--output", str(output),
                     "--llvm-sha256", self.library_sha256, *arguments],
                    cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(json.loads(output.read_text())["format"], "ocore-native-module-v1")
        source = self.write("define i32 @broken() { ret i32 %undefined }\n")
        output = self.directory / "must-not-exist.json"
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), str(source), "--output", str(output),
             "--llvm-library", str(self.library), "--llvm-sha256", self.library_sha256],
            cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(completed.stderr.strip())
        self.assertEqual(json.loads(completed.stderr)["error"]["stage"], "parse")
        self.assertFalse(output.exists(), "invalid import published a partial artifact")

    def test_explicit_non_elf_library_reports_import_failure(self):
        linker_script = self.directory / "libLLVM.so"
        linker_script.write_text("INPUT(libLLVM-real.so)\n")
        with self.assertRaises(importer.ImportFailure) as raised:
            importer.import_module(self.write("define i32 @entry() { ret i32 0 }\n"),
                                   library_path=linker_script)
        self.assertEqual(raised.exception.stage, "toolchain")


if __name__ == "__main__":
    unittest.main()
