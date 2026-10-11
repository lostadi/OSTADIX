"""Preserve complete LLVM 22 alignment contracts without huge allocations.

LLVMGetAlignment returns uint32 and truncates the legal 2^32-byte promise.
These unchanged text/bitcode fixtures check imported contracts and rejection
of stack/function alignment the native emitter cannot realize. They do not
allocate or assemble a physically 4 GiB aligned object.
"""

import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests.test_ocore_llvm_import import llvm_library


ROOT = Path(__file__).resolve().parents[1]
SDK = (Path.home() / ".cache/ostadix-toolchains/llvm-22.1.6/sdk/"
       "LLVM-22.1.6-Linux-X64/bin")
TRIPLES = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
           "riscv64-unknown-linux-gnu")
LAYOUT = "e-p:64:64-i64:64-i128:128-n8:16:32:64-S128-Fn32"
MAX_ALIGN = 1 << 32
ALIGNMENTS = (("default", None, 8), ("one", 1, 1),
              ("half", 1 << 31, 1 << 31), ("maximum", MAX_ALIGN, MAX_ALIGN))
FUNCTION_ALIGNMENTS = (("default", None, 0), ("one", 1, 1),
                       ("two", 2, 2), ("sixteen", 16, 16),
                       ("half", 1 << 31, 1 << 31),
                       ("maximum", MAX_ALIGN, MAX_ALIGN))
LOW_BITS = f"""
@aligned = global i8 7, align {MAX_ALIGN}
define i64 @global_low_bits() {{
  %address = ptrtoint ptr @aligned to i64
  %low = and i64 %address, {MAX_ALIGN - 1}
  ret i64 %low
}}
define i64 @stack_low_bits() {{
  %pointer = alloca i8, align {MAX_ALIGN}
  %address = ptrtoint ptr %pointer to i64
  %low = and i64 %address, {MAX_ALIGN - 1}
  ret i64 %low
}}
"""
STACK_LOW_BITS = f"""
define i64 @stack_low_bits() {{
  %pointer = alloca i8, align {MAX_ALIGN}
  %address = ptrtoint ptr %pointer to i64
  %low = and i64 %address, {MAX_ALIGN - 1}
  ret i64 %low
}}
"""


def llvm_tool(name):
    override = os.environ.get("OCORE_TEST_" + name.upper().replace("-", "_"))
    candidates = [override] if override else [SDK / name, name + "-22", name]
    for candidate in candidates:
        if candidate is None:
            continue
        found = shutil.which(str(candidate))
        if not found:
            continue
        version = subprocess.run([found, "--version"], capture_output=True,
                                 text=True, timeout=15)
        if version.returncode == 0 and re.search(r"\b22\.1\.6\b", version.stdout):
            return found
        if override:
            raise RuntimeError(f"required {name} must be pinned LLVM 22.1.6: {version}")
    reason = f"pinned LLVM 22.1.6 {name} unavailable"
    if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
        raise RuntimeError(reason)
    raise unittest.SkipTest(reason)


class LlvmAlignmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = llvm_library()
        cls.assembler = llvm_tool("llvm-as")
        cls.disassembler = llvm_tool("llvm-dis")
        cls.optimizer = llvm_tool("opt")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-alignment-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.counter = 0

    def command(self, argv, success=True):
        result = subprocess.run([str(arg) for arg in argv], cwd=ROOT,
                                capture_output=True, text=True, timeout=60)
        if success:
            self.assertEqual(result.returncode, 0,
                             f"{argv!r}\n{result.stdout}\n{result.stderr}")
        return result

    def fixtures(self, body, triple=TRIPLES[0]):
        self.counter += 1
        text = self.directory / f"input-{self.counter}.ll"
        text.write_text(f'target triple = "{triple}"\n'
                        f'target datalayout = "{LAYOUT}"\n' + body)
        original = text.read_bytes()
        bitcode = text.with_suffix(".bc")
        self.command([self.assembler, text, "-o", bitcode])
        self.assertEqual(text.read_bytes(), original)
        self.assertTrue(bitcode.read_bytes().startswith(b"BC\xc0\xde"))
        return text, bitcode

    def import_pairs(self, body, triple=TRIPLES[0]):
        paths = self.fixtures(body, triple)
        modules = []
        for path in paths:
            native = importer.import_module(path, library_path=self.library)
            self.assertEqual(native["provenance"]["input_sha256"],
                             hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(native["provenance"]["source_function_count"],
                             len(native["functions"]))
            self.assertEqual(native["provenance"]["source_global_count"],
                             len(native["globals"]))
            modules.append(native)
        self.assertEqual([{key: value for key, value in native.items()
                           if key not in {"name", "provenance"}} for native in modules],
                         [{key: value for key, value in modules[0].items()
                           if key not in {"name", "provenance"}}] * 2)
        return tuple(zip(paths, modules))

    @staticmethod
    def operations(native, name):
        function = next(fn for fn in native["functions"] if fn["name"] == name)
        return [instruction["operation"] for block in function["blocks"]
                for instruction in block["instructions"]]

    def test_pinned_c_api_truncation_is_observed_for_every_alignment_location(self):
        body = f"""
@maximum = global i64 0, align {MAX_ALIGN}
@half = global i64 0, align {1 << 31}
define i64 @entry(ptr %source) align {MAX_ALIGN} {{
  %pointer = alloca i64, align {MAX_ALIGN}
  %loaded = load i64, ptr %source, align {MAX_ALIGN}
  store i64 %loaded, ptr %pointer, align {MAX_ALIGN}
  ret i64 %loaded
}}
"""
        api = importer.LLVM(self.library, importer.PINNED_SHA256)
        for path in self.fixtures(body):
            with self.subTest(suffix=path.suffix):
                data = path.read_bytes()
                context, module, message = api.ContextCreate(), importer.P(), importer.P()
                buffer = api.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"alignment-proof")
                try:
                    parsed = api.ParseIRInContext2(context, buffer, C.byref(module), C.byref(message))
                    self.assertEqual(parsed, 0, C.string_at(message).decode() if message else "LLVM parse failed")
                    if message:
                        api.DisposeMessage(message)
                        message = importer.P()
                    valid = api.VerifyModule(module, 2, C.byref(message))
                    self.assertEqual(valid, 0, C.string_at(message).decode() if message else "LLVM verify failed")
                    globals_ = list(api.sequence(api.GetFirstGlobal, api.GetNextGlobal, module))
                    self.assertEqual([api.GetAlignment(glob) for glob in globals_], [0, 1 << 31])
                    function = api.GetFirstFunction(module)
                    self.assertEqual(api.GetAlignment(function), 0)
                    block = api.GetFirstBasicBlock(function)
                    instructions = list(api.sequence(api.GetFirstInstruction, api.GetNextInstruction, block))
                    self.assertEqual([api.GetAlignment(inst) for inst in instructions[:3]], [0, 0, 0])
                finally:
                    if message:
                        api.DisposeMessage(message)
                    if module:
                        api.DisposeModule(module)
                    api.DisposeMemoryBuffer(buffer)
                    api.ContextDispose(context)

    def test_defined_and_declared_global_alignment_order_survives_text_and_bitcode_all_isas(self):
        # Interleave definitions/declarations so a decoder/C API ordering
        # mismatch cannot happen to attach the same promise to every symbol.
        declarations = []
        for name, explicit, _ in ALIGNMENTS:
            suffix = "" if explicit is None else f", align {explicit}"
            declarations.extend((f"@defined_{name} = global i64 7{suffix}",
                                 f"@declared_{name} = external global i64{suffix}"))
        body = "\n".join(declarations) + "\ndefine i64 @entry() { ret i64 0 }\n"
        for triple in TRIPLES:
            for path, native in self.import_pairs(body, triple):
                with self.subTest(triple=triple, suffix=path.suffix):
                    globals_ = {glob["name"]: glob for glob in native["globals"]}
                    self.assertEqual(len(globals_), 8)
                    for name, _, expected in ALIGNMENTS:
                        for prefix in ("defined", "declared"):
                            glob = globals_[f"{prefix}_{name}"]
                            self.assertEqual(glob["alignment"], expected)
                            self.assertEqual(glob["initializer"] is None, prefix == "declared")
                    self.assertEqual([fn["name"] for fn in native["functions"]], ["entry"])

    def test_alloca_default_and_full_instruction_alignments_survive_all_isas(self):
        definitions = []
        for name, explicit, _ in ALIGNMENTS:
            suffix = "" if explicit is None else f", align {explicit}"
            definitions.append(f"define i64 @stack_{name}() {{\n"
                               f"%pointer = alloca i64{suffix}\n"
                               "%address = ptrtoint ptr %pointer to i64\nret i64 %address\n}")
        for triple in TRIPLES:
            for path, native in self.import_pairs("\n".join(definitions), triple):
                with self.subTest(triple=triple, suffix=path.suffix):
                    self.assertEqual(len(native["functions"]), 4)
                    for name, _, expected in ALIGNMENTS:
                        alloca = self.operations(native, "stack_" + name)[0]
                        self.assertEqual(alloca, {"op": "alloca", "size": 8,
                                                 "alignment": expected})

    def test_load_and_store_default_and_full_alignments_survive_all_isas(self):
        definitions = []
        for name, explicit, _ in ALIGNMENTS:
            suffix = "" if explicit is None else f", align {explicit}"
            definitions.append(f"define i64 @access_{name}(ptr %source, ptr %destination, i64 %value) {{\n"
                               f"%loaded = load volatile i64, ptr %source{suffix}\n"
                               f"store volatile i64 %value, ptr %destination{suffix}\n"
                               "ret i64 %loaded\n}")
        for triple in TRIPLES:
            for path, native in self.import_pairs("\n".join(definitions), triple):
                with self.subTest(triple=triple, suffix=path.suffix):
                    for name, _, expected in ALIGNMENTS:
                        operations = self.operations(native, "access_" + name)
                        self.assertEqual([op["op"] for op in operations], ["load", "store"])
                        self.assertEqual([op["alignment"] for op in operations], [expected] * 2)
                        self.assertTrue(all(op["volatile"] for op in operations))

    def test_defined_and_declared_function_alignments_and_abi_survive_all_isas(self):
        definitions = []
        expected_order = []
        for name, explicit, _ in FUNCTION_ALIGNMENTS:
            suffix = "" if explicit is None else f" align {explicit}"
            # Interleave declarations and definitions with distinct promises;
            # a decoder/C API traversal mismatch must not move alignments.
            definitions.extend((
                f"declare signext i8 @declared_{name}(i8 zeroext){suffix}",
                f"define signext i8 @defined_{name}(i8 zeroext %value){suffix} {{\n"
                f"%result = call signext i8 @declared_{name}(i8 zeroext %value)\n"
                "ret i8 %result\n}",
            ))
            expected_order.extend(("declared_" + name, "defined_" + name))
        for triple in TRIPLES:
            for path, native in self.import_pairs("\n".join(definitions), triple):
                with self.subTest(triple=triple, suffix=path.suffix):
                    self.assertEqual([fn["name"] for fn in native["functions"]],
                                     expected_order)
                    self.assertEqual(native["globals"], [])
                    functions = {fn["name"]: fn for fn in native["functions"]}
                    for name, _, expected in FUNCTION_ALIGNMENTS:
                        declared = functions["declared_" + name]
                        defined = functions["defined_" + name]
                        self.assertEqual(declared["alignment"], expected)
                        self.assertEqual(defined["alignment"], expected)
                        self.assertIsNone(declared["entry"])
                        self.assertEqual(declared["blocks"], [])
                        self.assertIsNotNone(defined["entry"])
                        self.assertEqual(defined["signature"], declared["signature"])
                        signature = defined["signature"]
                        self.assertEqual(signature["result_attributes"], ["signext"])
                        self.assertEqual(signature["param_attributes"], [["zeroext"]])
                        self.assertEqual([native["types"][ty] for ty in
                                          signature["params"] + [signature["result"]]],
                                         [{"kind": "int", "bits": 8}] * 2)
                        call, = self.operations(native, "defined_" + name)
                        self.assertEqual(call["op"], "call")
                        self.assertEqual(call["callee"]["name"], "declared_" + name)
                        self.assertEqual(call["signature"], signature)

    def test_function_alignment_preserves_supported_personality_and_rejects_gc_data_or_unsupported_abi(self):
        cases = (
            ("gc", 'define i32 @entry() align {alignment} gc "shadow-stack" {{ ret i32 0 }}',
             "unsupported function GC or prefix/prologue data"),
            ("personality", "declare i32 @personality(i32, i32, i64, ptr, ptr)\n"
             "define i32 @entry() align {alignment} personality ptr @personality {{ ret i32 0 }}",
             None),
            ("prefix", "define i32 @entry() align {alignment} prefix i32 7 {{ ret i32 0 }}",
             "unsupported function GC or prefix/prologue data"),
            ("prologue", "define i32 @entry() align {alignment} prologue i32 7 {{ ret i32 0 }}",
             "unsupported function GC or prefix/prologue data"),
            ("calling convention", "define coldcc i32 @entry() align {alignment} {{ ret i32 0 }}",
             "unsupported calling convention"),
            ("ABI attribute", "define void @entry(ptr byval(i8) %pointer) align {alignment} {{ ret void }}",
             "unsupported attribute kind"),
        )
        for triple in TRIPLES:
            for alignment in (1, MAX_ALIGN):
                for label, template, diagnostic in cases:
                    # llvm-as verifies every original whole unit before the
                    # importer guard is exercised, for both text and bitcode.
                    for path in self.fixtures(template.format(alignment=alignment), triple):
                        with self.subTest(triple=triple, alignment=alignment,
                                          case=label, suffix=path.suffix):
                            if label == "personality":
                                module = importer.import_module(path, library_path=self.library)
                                entry = next(f for f in module["functions"] if f["name"] == "entry")
                                self.assertEqual(entry["alignment"], alignment)
                                self.assertEqual(entry["exception_handling"]["model"], "itanium_dwarf_v1")
                                self.assertEqual(entry["exception_handling"]["personality"]["name"], "personality")
                                self.assertEqual({f["name"] for f in module["functions"]}, {"entry", "personality"})
                                self.assertIsNone(next(f for f in module["functions"] if f["name"] == "personality")["entry"])
                                self.assertEqual(module["provenance"]["source_function_count"], 2)
                                self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                                continue
                            with self.assertRaises(importer.ImportFailure) as raised:
                                importer.import_module(path, library_path=self.library)
                            self.assertEqual(raised.exception.stage, "import")
                            self.assertEqual(raised.exception.symbol, "entry")
                            self.assertIn(diagnostic, str(raised.exception))

    def test_memory_intrinsic_uint64_parameter_alignment_retains_original_contract_all_isas(self):
        declarations, definitions = [], []
        for width in (32, 64):
            for operation in ("memset", "memcpy", "memmove"):
                name = (f"llvm.memset.p0.i{width}" if operation == "memset"
                        else f"llvm.{operation}.p0.p0.i{width}")
                second_type = "i8" if operation == "memset" else "ptr"
                declarations.append(f"declare void @{name}(ptr, {second_type}, i{width}, i1 immarg)")
                second_param = "i8 %byte" if operation == "memset" else "ptr %source"
                second_arg = ("i8 %byte" if operation == "memset"
                              else f"ptr align {MAX_ALIGN} %source")
                definitions.append(f"define void @{operation}_{width}(ptr %destination, {second_param}, i{width} %length) {{\n"
                                   f"call void @{name}(ptr align {MAX_ALIGN} %destination, {second_arg}, i{width} %length, i1 true)\n"
                                   "ret void\n}")
        for triple in TRIPLES:
            text, bitcode = self.fixtures("\n".join(declarations + definitions), triple)
            # Pinned SDK LLVM's bitcode writer drops this maximum enum
            # alignment attribute. Confirm the original bitcode actually lacks
            # it; an importer cannot restore a contract absent from its input.
            disassembled = bitcode.with_suffix(".disassembled.ll")
            self.command([self.disassembler, bitcode, "-o", disassembled])
            calls = [line for line in disassembled.read_text().splitlines()
                     if "call void @llvm." in line]
            self.assertEqual(len(calls), 6)
            self.assertTrue(all("align " not in line for line in calls))
            for path in (text, bitcode):
                native = importer.import_module(path, library_path=self.library)
                with self.subTest(triple=triple, suffix=path.suffix):
                    self.assertEqual(native["provenance"]["input_sha256"],
                                     hashlib.sha256(path.read_bytes()).hexdigest())
                    self.assertEqual(len(native["functions"]), 12)
                    expected_alignment = MAX_ALIGN if path.suffix == ".ll" else 1
                    for width in (32, 64):
                        for name in ("memset", "memcpy", "memmove"):
                            operations = self.operations(native, f"{name}_{width}")
                            self.assertEqual(len(operations), 1)
                            operation = operations[0]
                            self.assertTrue(operation["volatile"])
                            if name == "memset":
                                self.assertEqual(operation["alignment"], expected_alignment)
                            else:
                                self.assertEqual(operation["destination_alignment"], expected_alignment)
                                self.assertEqual(operation["source_alignment"], expected_alignment)
                                self.assertEqual(operation["allow_overlap"], name == "memmove")

    def test_original_maximum_aligned_pointer_low_bits_are_known_zero_to_llvm(self):
        for triple in TRIPLES:
            text, bitcode = self.fixtures(LOW_BITS, triple)
            for path in (text, bitcode):
                with self.subTest(triple=triple, suffix=path.suffix):
                    original = path.read_bytes()
                    optimized = self.directory / f"optimized-{self.counter}-{path.suffix[1:]}.ll"
                    self.command([self.optimizer, "-passes=instcombine", "-S", path, "-o", optimized])
                    self.assertEqual(path.read_bytes(), original)
                    output = optimized.read_text()
                    for name in ("global_low_bits", "stack_low_bits"):
                        body = re.search(r"define i64 @" + name + r"\(\).*?\{(.*?)\}", output, re.S)
                        self.assertIsNotNone(body, output)
                        self.assertRegex(body.group(1), r"\bret i64 0\b")
                    native = importer.import_module(path, library_path=self.library)
                    self.assertEqual(native["globals"][0]["alignment"], MAX_ALIGN)
                    stack = self.operations(native, "stack_low_bits")
                    self.assertEqual(stack[0]["alignment"], MAX_ALIGN)
                    # Import the original operations, not the optimized proof.
                    self.assertEqual([operation["op"] for operation in stack],
                                     ["alloca", "cast", "binary"])
                    self.assertEqual(stack[-1]["kind"], "and")

    def test_maximum_aligned_whole_unit_verifies_but_cannot_emit_false_native_artifact(self):
        compiler = Path(os.environ.get("OCOREC", str(ROOT / "target/debug/ocorec")))
        if not compiler.is_file():
            reason = "actual built ocorec is required; this suite never builds Cargo"
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail(reason)
            self.skipTest(reason)
        for triple in TRIPLES:
            isa = triple.split("-")[0]
            # Keep this rejection independent of the native global-alignment
            # limit: the maximum stack promise alone must trigger preflight.
            for path, native in self.import_pairs(STACK_LOW_BITS, triple):
                with self.subTest(triple=triple, suffix=path.suffix):
                    native_path = path.with_suffix(path.suffix + ".json")
                    native_path.write_text(json.dumps(native))
                    receipt = native_path.with_suffix(".receipt.json")
                    self.command([compiler, native_path, "--input-kind", "native-ir",
                                  "--verify-native", "--receipt", receipt])
                    verified = json.loads(receipt.read_text())
                    self.assertTrue(verified["verified"])
                    self.assertEqual(verified["scope"], "structural_ir_verification")
                    self.assertEqual(verified["module_sha256"],
                                     hashlib.sha256(native_path.read_bytes()).hexdigest())
                    self.assertEqual(len(verified["functions"]), 1)
                    self.assertEqual(verified["global_count"], 0)
                    for emission, suffix in (("asm", ".s"), ("obj", ".o")):
                        output = native_path.with_suffix(suffix)
                        rejected = self.command([compiler, native_path, "--input-kind", "native-ir",
                                                 "--target", isa + "-unknown-none", "--emit", emission,
                                                 "-o", output], success=False)
                        self.assertNotEqual(rejected.returncode, 0)
                        self.assertIn("phase: native compilation", rejected.stderr)
                        self.assertIn("over-aligned imported stack allocations", rejected.stderr)
                        self.assertFalse(output.exists(), "unsupported alignment cannot produce an artifact")

    def native_compiler(self):
        compiler = Path(os.environ.get("OCOREC", str(ROOT / "target/debug/ocorec")))
        if not compiler.is_file():
            reason = "actual built ocorec is required; this suite never builds Cargo"
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail(reason)
            self.skipTest(reason)
        return compiler

    def verified_native_input(self, compiler, path, native):
        native_path = path.with_suffix(path.suffix + ".json")
        native_path.write_text(json.dumps(native))
        receipt = native_path.with_suffix(".receipt.json")
        self.command([compiler, native_path, "--input-kind", "native-ir",
                      "--verify-native", "--receipt", receipt])
        verified = json.loads(receipt.read_text())
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["scope"], "structural_ir_verification")
        self.assertEqual(verified["module_sha256"],
                         hashlib.sha256(native_path.read_bytes()).hexdigest())
        self.assertEqual(len(verified["functions"]), len(native["functions"]))
        self.assertEqual(verified["global_count"], len(native["globals"]))
        return native_path

    def test_maximum_function_definition_alignment_rejects_before_asm_and_obj_all_isas(self):
        compiler = self.native_compiler()
        body = f"define i64 @entry() align {MAX_ALIGN} {{ ret i64 7 }}\n"
        for triple in TRIPLES:
            isa = triple.split("-")[0]
            for path, native in self.import_pairs(body, triple):
                with self.subTest(triple=triple, suffix=path.suffix):
                    self.assertEqual(native["functions"][0]["alignment"], MAX_ALIGN)
                    native_path = self.verified_native_input(compiler, path, native)
                    for emission, suffix in (("asm", ".s"), ("obj", ".o")):
                        output = native_path.with_suffix(suffix)
                        rejected = self.command([compiler, native_path, "--input-kind", "native-ir",
                                                 "--target", isa + "-unknown-none", "--emit", emission,
                                                 "-o", output], success=False)
                        self.assertNotEqual(rejected.returncode, 0)
                        self.assertIn("phase: native compilation", rejected.stderr)
                        self.assertIn(f"function code alignment {MAX_ALIGN}", rejected.stderr)
                        self.assertIn("cannot be realized by the native assembler", rejected.stderr)
                        self.assertFalse(output.exists(), "unrealized function alignment cannot produce an artifact")

    def test_maximum_function_declaration_and_small_definitions_emit_all_isas(self):
        compiler = self.native_compiler()
        bodies = [f"declare i64 @foreign(i64) align {MAX_ALIGN}"]
        for name, explicit, _ in FUNCTION_ALIGNMENTS[:4]:
            suffix = "" if explicit is None else f" align {explicit}"
            bodies.append(f"define i64 @entry_{name}(i64 %value){suffix} {{\n"
                          "%result = call i64 @foreign(i64 %value)\n"
                          "ret i64 %result\n}")
        for triple in TRIPLES:
            isa = triple.split("-")[0]
            for path, native in self.import_pairs("\n".join(bodies), triple):
                with self.subTest(triple=triple, suffix=path.suffix):
                    # The declaration promise belongs to dependency closure;
                    # no owned storage or function body is fabricated for it.
                    self.assertEqual(native["functions"][0]["alignment"], MAX_ALIGN)
                    self.assertIsNone(native["functions"][0]["entry"])
                    self.assertEqual([fn["alignment"] for fn in native["functions"][1:]],
                                     [item[2] for item in FUNCTION_ALIGNMENTS[:4]])
                    native_path = self.verified_native_input(compiler, path, native)
                    for emission, suffix in (("asm", ".s"), ("obj", ".o")):
                        output = native_path.with_suffix(suffix)
                        self.command([compiler, native_path, "--input-kind", "native-ir",
                                      "--target", isa + "-unknown-none", "--emit", emission,
                                      "-o", output])
                        if emission == "obj":
                            self.assertTrue(output.read_bytes().startswith(b"\x7fELF"))
                        else:
                            assembly = output.read_text()
                            self.assertNotRegex(assembly, r"(?m)^foreign:\s*$")
                            for name, _, alignment in FUNCTION_ALIGNMENTS[:4]:
                                self.assertIn(f".balign {max(4, alignment)}\n.type entry_{name}, @function\n"
                                              f"entry_{name}:", assembly)


if __name__ == "__main__":
    unittest.main()
