"""Whole-unit switch import tests using verified LLVM 22 inputs.

These tests exercise the importer, not native lowering or runtime coverage.
Every case and destination must survive import, including repeated CFG edges.
"""

import hashlib
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
LAYOUT = "e-p:64:64-i64:64-n8:16:32:64-S128"
TRIPLES = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
           "riscv64-unknown-linux-gnu")


def switches(function):
    return [block["terminator"] for block in function["blocks"]
            if block["terminator"]["op"] == "switch"]


class LlvmSwitchImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-switch-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    def import_ir(self, body, triple=TRIPLES[0]):
        self.source.write_text(f'target triple = "{triple}"\n'
                               f'target datalayout = "{LAYOUT}"\n' + body,
                               encoding="utf-8")
        return importer.import_module(self.source, library_path=self.library)

    def function(self, module, name="entry"):
        return next(fn for fn in module["functions"] if fn["name"] == name)

    def one_switch(self, module, name="entry"):
        found = switches(self.function(module, name))
        self.assertEqual(len(found), 1, "the original switch must remain explicit")
        return found[0]

    def assert_cases(self, module, terminator, width, expected):
        cases = terminator["cases"]
        self.assertEqual(len(cases), len(expected), "cases cannot be filtered or capped")
        self.assertEqual([case["value"]["bits"] for case in cases],
                         [str(number % (1 << width)) for number in expected])
        for case in cases:
            self.assertEqual(case["value"]["kind"], "int")
            self.assertEqual(module["types"][case["value"]["ty"]],
                             {"kind": "int", "bits": width})

    def test_signed_case_bit_patterns_and_exact_widths_on_all_three_isas(self):
        for triple in TRIPLES:
            for width in (8, 16, 32, 64):
                with self.subTest(triple=triple, width=width):
                    minimum = -(1 << (width - 1))
                    expected = [-1, minimum, 0, -minimum - 1]
                    cases = "\n".join(f"i{width} {number}, label %hit"
                                      for number in expected)
                    module = self.import_ir(f"""
define i64 @entry(i{width} %condition) {{
  switch i{width} %condition, label %default [ {cases} ]
default:
  ret i64 73
hit:
  ret i64 19
}}
""", triple)
                    terminator = self.one_switch(module)
                    self.assertEqual(terminator["condition"], {"kind": "value", "id": 0})
                    self.assertEqual(terminator["default"], 1)
                    self.assertEqual([case["target"] for case in terminator["cases"]], [2] * 4)
                    self.assert_cases(module, terminator, width, expected)

    def test_empty_switch_retains_condition_and_default(self):
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir("""
define i32 @entry(i32 %condition) {
  switch i32 %condition, label %default []
default:
  ret i32 7
}
""", triple)
                self.assertEqual(self.one_switch(module), {
                    "op": "switch", "condition": {"kind": "value", "id": 0},
                    "default": 1, "cases": []})
                self.assertEqual(len(self.function(module)["blocks"]), 2)

    def test_duplicate_destinations_keep_all_cases_and_coalesce_identical_phi_edges(self):
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir("""
define i64 @entry(i8 %condition) {
entry:
  switch i8 %condition, label %join [
    i8 0, label %join
    i8 1, label %join
    i8 2, label %other
  ]
join:
  %result = phi i64 [7, %entry], [7, %entry], [7, %entry]
  ret i64 %result
other:
  ret i64 11
}
""", triple)
                terminator = self.one_switch(module)
                self.assertEqual(terminator["default"], 1)
                self.assertEqual([case["target"] for case in terminator["cases"]], [1, 1, 2])
                self.assert_cases(module, terminator, 8, [0, 1, 2])
                phi = self.function(module)["blocks"][1]["instructions"][0]["operation"]
                self.assertEqual(phi["op"], "phi")
                self.assertEqual(len(phi["incoming"]), 1)
                self.assertEqual(phi["incoming"][0]["block"], 0)
                self.assertEqual(phi["incoming"][0]["value"]["bits"], "7")
                self.assertTrue(any("duplicate CFG edges" in item
                                    for item in module["provenance"]["refinements"]))

    def test_large_switch_preserves_all_1922_cases(self):
        count = 1922
        cases = "\n".join(f"i32 {number}, label %hit" for number in range(count))
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir(f"""
define i64 @entry(i32 %condition) {{
  switch i32 %condition, label %default [ {cases} ]
default:
  ret i64 0
hit:
  ret i64 1
}}
""", triple)
                terminator = self.one_switch(module)
                self.assert_cases(module, terminator, 32, range(count))
                self.assertEqual([case["target"] for case in terminator["cases"]], [2] * count)
                self.assertEqual(terminator["default"], 1)
                self.assertEqual(module["provenance"]["source_function_count"], 1)
                self.assertEqual(module["provenance"]["source_global_count"], 0)
                self.assertEqual(module["provenance"]["input_sha256"],
                                 hashlib.sha256(self.source.read_bytes()).hexdigest())

    def test_literal_condition_keeps_its_typed_sign_bit(self):
        for width in (8, 16, 32, 64):
            with self.subTest(width=width):
                condition = -(1 << (width - 1))
                module = self.import_ir(f"""
define i64 @entry() {{
  switch i{width} {condition}, label %default [i{width} {condition}, label %hit]
default:
  ret i64 0
hit:
  ret i64 1
}}
""")
                terminator = self.one_switch(module)
                operand = terminator["condition"]
                self.assertEqual(operand["kind"], "int")
                self.assertEqual(operand["bits"], str(1 << (width - 1)))
                self.assertEqual(module["types"][operand["ty"]], {"kind": "int", "bits": width})
                self.assert_cases(module, terminator, width, [condition])

    def test_ssa_freeze_and_poison_conditions_are_preserved(self):
        body = """
define i64 @frozen(i32 %input) {
  %condition = freeze i32 %input
  switch i32 %condition, label %default [i32 7, label %hit]
default:
  ret i64 0
hit:
  ret i64 1
}
define i64 @frozen_poison() {
  %condition = freeze i32 poison
  switch i32 %condition, label %default [i32 -1, label %hit]
default:
  ret i64 0
hit:
  ret i64 1
}
define i64 @direct_poison() {
  switch i32 poison, label %default [i32 3, label %hit]
default:
  ret i64 0
hit:
  ret i64 1
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                module = self.import_ir(body, triple)
                for name, operand_kind in (("frozen", "value"), ("frozen_poison", "poison")):
                    fn = self.function(module, name)
                    freeze = fn["blocks"][0]["instructions"][0]
                    self.assertEqual(freeze["operation"]["op"], "freeze")
                    self.assertEqual(freeze["operation"]["value"]["kind"], operand_kind)
                    self.assertEqual(self.one_switch(module, name)["condition"],
                                     {"kind": "value", "id": freeze["result"]["id"]})
                poison = self.one_switch(module, "direct_poison")["condition"]
                self.assertEqual(poison["kind"], "poison")
                self.assertEqual(module["types"][poison["ty"]], {"kind": "int", "bits": 32})
                self.assertEqual({fn["name"] for fn in module["functions"]},
                                 {"frozen", "frozen_poison", "direct_poison"})

    def test_duplicate_cases_including_clipped_literals_reject_before_import(self):
        for first, second in ((0, 0), (-1, 255), (0, 256), (128, -128)):
            with self.subTest(first=first, second=second):
                with self.assertRaises(importer.ImportFailure) as raised:
                    self.import_ir(f"""
define i64 @entry(i8 %condition) {{
  switch i8 %condition, label %default [
    i8 {first}, label %hit
    i8 {second}, label %hit
  ]
default:
  ret i64 0
hit:
  ret i64 1
}}
""")
                # LLVM's text parser already rejects these canonicalized
                # duplicates; neither parsing nor verification may admit them.
                self.assertIn(raised.exception.stage, {"parse", "llvm-verify"})
                self.assertIn("duplicate", str(raised.exception).lower())

    def test_wrong_case_width_rejects_before_import(self):
        for condition_width, case_width in ((8, 16), (16, 32), (32, 64), (64, 32)):
            with self.subTest(condition=condition_width, case=case_width):
                with self.assertRaises(importer.ImportFailure) as raised:
                    self.import_ir(f"""
define i64 @entry(i{condition_width} %condition) {{
  switch i{condition_width} %condition, label %default [i{case_width} 7, label %hit]
default:
  ret i64 0
hit:
  ret i64 1
}}
""")
                self.assertIn(raised.exception.stage, {"parse", "llvm-verify"})
                self.assertIn("switch", str(raised.exception).lower())

    def clang22(self):
        override = os.environ.get("OCORE_TEST_CLANG22")
        sdk = Path.home() / ".cache/ostadix-toolchains/llvm-22.1.6/sdk"
        candidates = [override] if override else [*(str(path) for path in sorted(
            sdk.glob("LLVM-22.1.6-*/bin/clang"))), "clang-22", "clang22", "clang"]
        for candidate in candidates:
            executable = shutil.which(candidate)
            if executable is None:
                if override:
                    self.fail(f"requested Clang 22.1.6 frontend unavailable: {candidate}")
                continue
            result = subprocess.run([executable, "--version"], capture_output=True,
                                    text=True, timeout=15)
            if result.returncode == 0 and re.search(r"\bclang version 22\.1\.6\b", result.stdout):
                return executable, result.stdout.splitlines()[0]
            if override:
                self.fail(f"requested frontend is not Clang 22.1.6: {result.stdout}{result.stderr}")
        self.skipTest("Clang 22.1.6 frontend unavailable; set OCORE_TEST_CLANG22 to require it")

    def test_clang22_unmodified_c_switch_unit_text_and_bitcode_on_all_three_isas(self):
        clang, version = self.clang22()
        c_source = self.directory / "switch.c"
        c_source.write_text("""typedef unsigned long long u64;
u64 switch_inventory = 17;
static u64 switch_helper(u64 value) { return value + switch_inventory; }
u64 imported_switch(u64 value) {
    switch (value) {
        case 0: return switch_helper(3);
        case 1: return switch_helper(5);
        case 31: return switch_helper(7);
        case 255: return switch_helper(9);
        case 0x8000000000000000ULL: return switch_helper(11);
        case 0xffffffffffffffffULL: return switch_helper(13);
        default: return switch_helper(value);
    }
}
int imported_signed_switch(int value) {
    switch (value) {
        case (-2147483647 - 1): return 2;
        case -1: return 5;
        case 7: return 11;
        case 32768: return 17;
        default: return value ^ 57;
    }
}
""", encoding="utf-8")
        flags = ["-O0", "-emit-llvm", "-ffreestanding", "-fno-builtin",
                 "-fno-pic", "-fno-pie", "-fno-stack-protector",
                 "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
                 "-Xclang", "-disable-lifetime-markers"]
        for triple in TRIPLES:
            target_flags = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
            for suffix, output_flag in (("ll", "-S"), ("bc", "-c")):
                with self.subTest(triple=triple, suffix=suffix):
                    source = self.directory / f"{triple}.{suffix}"
                    result = subprocess.run([clang, "--target=" + triple, *target_flags,
                                             *flags, output_flag, str(c_source), "-o", str(source)],
                                            cwd=ROOT, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    original = source.read_bytes()
                    if suffix == "ll":
                        self.assertRegex(original.decode(), r"switch i64")
                        self.assertRegex(original.decode(), r"switch i32")
                    else:
                        self.assertTrue(original.startswith(b"BC\xc0\xde"))
                    module = importer.import_module(source, library_path=self.library,
                                                    frontend="Clang", frontend_version=version)
                    self.assertEqual(source.read_bytes(), original, "producer IR must remain unmodified")
                    self.assertEqual({fn["name"] for fn in module["functions"]},
                                     {"imported_switch", "switch_helper", "imported_signed_switch"})
                    self.assertEqual({glob["name"] for glob in module["globals"]}, {"switch_inventory"})
                    self.assertEqual(module["provenance"]["source_function_count"], 3)
                    self.assertEqual(module["provenance"]["source_global_count"], 1)
                    self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(original).hexdigest())
                    self.assertEqual(module["target"]["triple"], triple)
                    self.assert_cases(module, self.one_switch(module, "imported_switch"), 64,
                                      [0, 1, 31, 255, 1 << 63, (1 << 64) - 1])
                    self.assert_cases(module, self.one_switch(module, "imported_signed_switch"), 32,
                                      [-(1 << 31), -1, 7, 32768])
                    self.assertEqual(switches(self.function(module, "switch_helper")), [])


if __name__ == "__main__":
    unittest.main()
