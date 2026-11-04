"""Exact LLVM22 scalar-ctpop promise controls; source proof, not native execution.

The required manifest identifies the unchanged whole LLVM provider units from
the failed native mechanism run. No original unit or declaration is filtered.
Authored negative modules are separate LLVM-verified controls.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
PIN = "8617d27fecff5e31785eed07ee1cd7665e083bb689b6fb13266956d5231afe83"
LIBRARY = Path(os.environ.get("OCORE_TEST_LLVM_LIBRARY", "/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib/riscv64-linux-gnu/libLLVM.so.22.1"))
ASSEMBLER = Path(os.environ.get("OCORE_TEST_LLVM_AS", "/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib/llvm-22/bin/llvm-as"))


def identity(path):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sys.path.insert(0, str(ROOT / "scripts"))
IMPORTER = load("ocore_ctpop_attribute_importer", ROOT / "scripts/ocore_llvm_import.py")
BITCODE_HELPER = Path(sys.modules["ocore_llvm_bitcode"].__file__).resolve(strict=True)
if BITCODE_HELPER != ROOT / "scripts/ocore_llvm_bitcode.py":
    raise AssertionError("the selected importer must use its exact local bitcode helper")
INVENTORY = load("ocore_ctpop_attribute_inventory", ROOT / "tests/ocore_llvm_source_inventory.py")


class PopulationCountAttributeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_path = Path(os.environ["OCORE_CTPOP_ATTRIBUTE_ORIGINALS"]).resolve(strict=True)
        cls.output = Path(os.environ["OCORE_CTPOP_ATTRIBUTE_RETAIN"]).resolve()
        cls.output.mkdir(parents=True, exist_ok=False)
        cls.originals = json.loads(cls.manifest_path.read_text())["originals"]
        if len(cls.originals) != 4 or {row["profile"] for row in cls.originals} != {
            "x86_64", "aarch64", "riscv64-lp64", "riscv64-lp64d"
        }:
            raise AssertionError("all four original provider profiles are required")
        cls.sources = [Path(__file__), ROOT / "scripts/ocore_llvm_import.py", BITCODE_HELPER,
                       ROOT / "tests/ocore_llvm_source_inventory.py", cls.manifest_path,
                       LIBRARY, ASSEMBLER] + [Path(row[key]["path"]) for row in cls.originals
                                                for key in ("input", "source", "case_report")]
        cls.before = [identity(path) for path in cls.sources]
        if identity(LIBRARY)["sha256"] != PIN:
            raise AssertionError("the exact LLVM22 library is required")
        cls.reader = INVENTORY.Reader(LIBRARY, PIN)
        cls.records = []

    @classmethod
    def tearDownClass(cls):
        after = [identity(path) for path in cls.sources]
        stable = after == cls.before
        (cls.output / "source-control-receipt.json").write_text(json.dumps({
            "schema": "ocore-scalar-ctpop-attribute-source-controls-v1",
            "sources_before": cls.before, "sources_after": after, "source_tools_inputs_stable": stable,
            "records": cls.records, "native_verification_qualified": False,
            "native_execution_qualified": False, "runtime_accepted": False,
        }, indent=2) + "\n")
        if not stable:
            raise AssertionError("source, tool, or original input changed during source controls")

    def checked_llvm(self, label, text):
        path = self.output / (label + ".ll")
        path.write_text(text)
        result = subprocess.run([str(ASSEMBLER), str(path), "-o", str(path.with_suffix(".bc"))],
                                capture_output=True, timeout=60)
        self.records.append({"kind": "actual_llvm_verification", "input": identity(path),
                             "argv": result.args, "exit_code": result.returncode,
                             "stderr": result.stderr.decode(errors="replace")})
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return path

    def imported(self, label, path):
        before = identity(path)
        module = IMPORTER.import_module(Path(path), LIBRARY, expected_sha256=PIN)
        native = self.output / (label + ".native.json")
        native.write_text(json.dumps(module, indent=2) + "\n")
        source = self.reader.read(Path(path))
        proof = INVENTORY.check_inventory(source, module)
        source_path, proof_path = self.output / (label + ".source.json"), self.output / (label + ".preservation.json")
        source_path.write_text(json.dumps(source, indent=2) + "\n")
        proof_path.write_text(json.dumps(proof, indent=2) + "\n")
        self.assertEqual(identity(path), before)
        self.assertEqual(module["provenance"]["input_sha256"], before["sha256"])
        self.records.append({"kind": "whole_source_import", "input": before, "native": identity(native),
                             "source_inventory": identity(source_path), "preservation": identity(proof_path)})
        return module

    @staticmethod
    def fixture(width=32, declaration=True, callsite=False, value="%x", name=None, extra=""):
        name = name or "llvm.ctpop.i" + str(width)
        declaration_attrs = " #0" if declaration else ""
        call_attrs = " #0" if callsite else ""
        return ("target triple = \"x86_64-unknown-linux-gnu\"\n"
                "target datalayout = \"e-p:64:64-i64:64-i128:128\"\n"
                "@original_marker = global i64 7, align 8\n"
                f"declare i{width} @{name}(i{width}){declaration_attrs}\n"
                f"define i{width} @original(i{width} %x) {{\n"
                f"  %r = call i{width} @{name}(i{width} {value}){call_attrs}\n"
                f"  ret i{width} %r\n}}\n"
                "define i64 @original_cold() { ret i64 7 }\n"
                "attributes #0 = { nocreateundeforpoison " + extra + " }\n")

    def test_all_four_unchanged_original_whole_provider_units(self):
        for row in self.originals:
            with self.subTest(profile=row["profile"]):
                self.assertEqual(identity(row["input"]["path"]), row["input"])
                self.assertEqual(identity(row["source"]["path"]), row["source"])
                self.assertEqual(identity(row["case_report"]["path"]), row["case_report"])
                module = self.imported("original-" + row["profile"], row["input"]["path"])
                operations = [instruction["operation"] for function in module["functions"]
                              for block in function["blocks"] for instruction in block["instructions"]]
                self.assertEqual(sum(op["op"] == "integer_population_count" for op in operations), 2)
                self.assertTrue({"llvm.ctpop.i32", "llvm.ctpop.i64"}.issubset({f["name"] for f in module["functions"]}))
                refinements = module["provenance"]["refinements"]
                self.assertTrue(any("scalar population-count" in text and "function" in text for text in refinements))

    def test_exact_decl_and_callsite_promises_retain_full_inventory(self):
        for width in (32, 64):
            for location in ("declaration", "callsite", "both"):
                with self.subTest(width=width, location=location):
                    label = f"positive-{width}-{location}"
                    path = self.checked_llvm(label, self.fixture(width, location != "callsite", location != "declaration"))
                    module = self.imported(label, path)
                    if location != "declaration":
                        self.assertTrue(any("callsite nocreateundeforpoison=0" in text
                                            for text in module["provenance"]["refinements"]))

    def test_ordinary_function_or_call_promise_is_not_admitted(self):
        for callsite in (False, True):
            path = self.checked_llvm("ordinary-" + str(callsite), self.fixture(
                declaration=not callsite, callsite=callsite, name="ordinary_count"))
            with self.assertRaisesRegex(IMPORTER.ImportFailure, "unsupported attribute kind 27 at index 4294967295"):
                IMPORTER.import_module(path, LIBRARY, expected_sha256=PIN)

    def test_unknown_attributes_do_not_gain_intrinsic_whitelist_permission(self):
        # Pinned LLVM22 replaces intrinsic declaration attributes with its
        # canonical intrinsic inventory. Its verified callsite attributes and
        # ordinary declarations remain available for the importer to audit.
        unknown = '"ocore-test-unknown"="required"'
        controls = [("intrinsic-callsite", self.fixture(
            declaration=False, callsite=True, extra=unknown))]
        for callsite in (False, True):
            text = self.fixture(declaration=not callsite, callsite=callsite,
                                name="ordinary_count", extra=unknown)
            controls.append(("ordinary-" + str(callsite), text.replace("nocreateundeforpoison ", "")))
        for label, text in controls:
            path = self.checked_llvm("unknown-" + label, text)
            with self.assertRaisesRegex(IMPORTER.ImportFailure, "unsupported string attribute ocore-test-unknown=required"):
                IMPORTER.import_module(path, LIBRARY, expected_sha256=PIN)

    def test_other_overloads_and_wrong_signatures_remain_rejected(self):
        path = self.checked_llvm("unsupported-i8", self.fixture(width=8))
        with self.assertRaisesRegex(IMPORTER.ImportFailure, "requires explicit"):
            IMPORTER.import_module(path, LIBRARY, expected_sha256=PIN)
        # This source contract is invalid LLVM, unlike the well-typed negatives above.
        wrong = self.output / "llvm-invalid-signature.ll"
        wrong.write_text(self.fixture().replace("declare i32 @llvm.ctpop.i32(i32)", "declare i64 @llvm.ctpop.i32(i32)"))
        result = subprocess.run([str(ASSEMBLER), str(wrong), "-o", str(wrong.with_suffix(".bc"))],
                                capture_output=True, timeout=60)
        self.records.append({"kind": "invalid_llvm_signature_control", "input": identity(wrong),
                             "argv": result.args, "exit_code": result.returncode,
                             "stderr": result.stderr.decode(errors="replace")})
        self.assertNotEqual(result.returncode, 0)

    def test_original_poison_and_undef_operands_are_not_rewritten(self):
        for width in (32, 64):
            for value in ("poison", "undef"):
                label = f"operand-{width}-{value}"
                path = self.checked_llvm(label, self.fixture(width, value=value))
                module = self.imported(label, path)
                operations = [instruction["operation"] for function in module["functions"]
                              for block in function["blocks"] for instruction in block["instructions"]]
                operation = next(op for op in operations if op["op"] == "integer_population_count")
                self.assertEqual(operation["value"]["kind"], value)


if __name__ == "__main__":
    unittest.main()
