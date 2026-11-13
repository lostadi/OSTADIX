"""Actual pinned-LLVM import plus independent whole-unit omission controls.

No compiler build, object execution, provider qualification or installation.
The fixture is explicitly authored LLVM, not a filtered original source unit.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.ocore_llvm_source_inventory import Reader, check_inventory, artifact, InventoryMismatch


ROOT = Path(__file__).resolve().parents[1]
PIN = "8617d27fecff5e31785eed07ee1cd7665e083bb689b6fb13266956d5231afe83"
SOURCE = r'''
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "riscv64-unknown-linux-gnu"
@observable = global i64 7, align 8
@array = internal global [3 x i64] [i64 11, i64 22, i64 33], align 8
@offset_pointer = global ptr getelementptr ([3 x i64], ptr @array, i64 0, i64 2), align 8
@function_pointer = global ptr @external, align 8
@nested = global {i8, [2 x ptr], i32} {i8 7, [2 x ptr] [ptr @array, ptr @external], i32 43}, align 8
@packed = global <{i8, i64}> <{i8 1, i64 1234605616436508552}>, align 1
@negative_zero = global double 0x8000000000000000, align 8
@relative = private constant i32 trunc (i64 sub (i64 ptrtoint (ptr @array to i64), i64 ptrtoint (ptr @relative to i64)) to i32), align 4
@array_alias = alias [3 x i64], ptr @array
declare i64 @external(i64)
declare i64 @unused_declaration(i64)
declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)
declare double @llvm.fabs.f64(double)
declare ptr @llvm.load.relative.i32(ptr, i32)
declare ptr @llvm.load.relative.i64(ptr, i64)
define i64 @entry(ptr %destination, i64 %value) {
entry:
  call void @llvm.memset.p0.i64(ptr %destination, i8 0, i64 8, i1 false)
  %absolute = call double @llvm.fabs.f64(double 0x8000000000000000)
  %bits = bitcast double %absolute to i64
  %foreign = call i64 @external(i64 %value)
  %result = xor i64 %foreign, %bits
  ret i64 %result
}
define ptr @relative_i32(ptr %base, i32 %index) {
entry:
  %result = call ptr @llvm.load.relative.i32(ptr %base, i32 %index)
  ret ptr %result
}
define ptr @relative_i64(ptr %base, i64 %index) {
entry:
  %result = call ptr @llvm.load.relative.i64(ptr %base, i64 %index)
  ret ptr %result
}
'''


class SourceInventoryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        retain = os.environ.get("OCORE_INVENTORY_RETAIN")
        cls.directory = Path(tempfile.mkdtemp(prefix="source-inventory-", dir=retain))
        cls.compiler = Path(os.environ.get("OCORE_TEST_OCOREC", ROOT / "target/fp-build-v4/ocorec"))
        cls.library = Path(os.environ.get("OCORE_TEST_LLVM_LIBRARY", "/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib/riscv64-linux-gnu/libLLVM.so.22.1"))
        cls.pin = os.environ.get("OCORE_TEST_LLVM_SHA256", PIN)
        cls.before = {"compiler": artifact(cls.compiler), "library": artifact(cls.library)}
        cls.llvm = cls.directory / "complete-authored-unit.ll"
        cls.native = cls.directory / "complete-authored-unit.native.json"
        cls.llvm.write_text(SOURCE)
        cls.commands = []

        def run(argv):
            result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=120)
            number = len(cls.commands)
            stdout, stderr = cls.directory / f"command-{number}.stdout", cls.directory / f"command-{number}.stderr"
            stdout.write_bytes(result.stdout); stderr.write_bytes(result.stderr)
            cls.commands.append({"argv": list(map(str, argv)), "exit_code": result.returncode,
                                 "stdout": artifact(stdout), "stderr": artifact(stderr)})
            if result.returncode:
                raise AssertionError(result.stderr.decode(errors="replace"))

        cls.run_compiler = staticmethod(run)
        run([cls.compiler, cls.llvm, "--input-kind", "llvm-ir", "--emit", "mir", "--target", "riscv64-unknown-none",
             "--llvm-library", cls.library, "--llvm-sha256", cls.pin, "-o", cls.native])
        cls.verification = cls.directory / "independent-native-verification.json"
        run([cls.compiler, cls.native, "--input-kind", "native-ir", "--verify-native", "--receipt", cls.verification])
        cls.module = json.loads(cls.native.read_text())
        cls.source = Reader(cls.library, cls.pin).read(cls.llvm)
        (cls.directory / "independent-source-inventory.json").write_text(json.dumps(cls.source, indent=2) + "\n")
        cls.receipt = check_inventory(cls.source, cls.module)
        (cls.directory / "preservation.json").write_text(json.dumps(cls.receipt, indent=2) + "\n")
        cls.faults = []

    @classmethod
    def tearDownClass(cls):
        after = {"compiler": artifact(cls.compiler), "library": artifact(cls.library)}
        if after != cls.before:
            raise AssertionError("inventory control tools changed")
        (cls.directory / "controls.json").write_text(json.dumps({
            "schema": "ocore-independent-inventory-controls-v1", "tools_before": cls.before, "tools_after": after,
            "commands": cls.commands, "original_llvm": artifact(cls.llvm), "native_module": artifact(cls.native),
            "independent_native_verification": artifact(cls.verification),
            "source_inventory": artifact(cls.directory / "independent-source-inventory.json"),
            "preservation": artifact(cls.directory / "preservation.json"), "detected_omissions_or_changes": cls.faults,
            "object_execution_attempted": False, "runtime_complete": False,
            "provider_resolution_complete": False}, indent=2) + "\n")

    def rejected(self, label, mutation, message):
        module = copy.deepcopy(self.module)
        mutation(module)
        with self.assertRaisesRegex(InventoryMismatch, message) as caught:
            check_inventory(self.source, module)
        self.faults.append({"fault": label, "diagnostic": str(caught.exception)})

    def test_complete_unit(self):
        self.assertEqual(self.receipt["counts"], {"functions": 9, "globals": 8, "aliases": 1})
        self.assertEqual(len(self.receipt["mappings"]["intrinsic_sites"]), 4)
        self.assertEqual(set(self.receipt["mappings"]["external_declarations"]), {"external", "unused_declaration"})

    def test_missing_observable_global(self):
        self.rejected("unused-public-global-omission", lambda m: m["globals"].__setitem__(slice(None), [g for g in m["globals"] if g["name"] != "observable"]), "globals source/native inventory mismatch")

    def test_initializer_byte_change(self):
        def change(m):
            next(g for g in m["globals"] if g["name"] == "observable")["initializer"]["bytes"][0] ^= 1
        self.rejected("defined-initializer-byte-change", change, "initializer bytes/relocations changed")

    def test_initializer_relocations(self):
        for field, value in (("drop", None), ("addend", 0), ("symbol", "external")):
            def change(m, field=field, value=value):
                rels = next(g for g in m["globals"] if g["name"] == "offset_pointer")["initializer"]["relocations"]
                if field == "drop":
                    rels.clear()
                else:
                    rels[0][field] = value
            with self.subTest(field=field):
                self.rejected("initializer-relocation-" + field, change, "initializer bytes/relocations changed")

    def test_missing_declaration(self):
        self.rejected("unused-declaration-omission", lambda m: m["functions"].__setitem__(slice(None), [f for f in m["functions"] if f["name"] != "unused_declaration"]), "functions source/native inventory mismatch")

    def test_missing_alias(self):
        self.rejected("alias-omission", lambda m: m["aliases"].clear(), "aliases source/native inventory mismatch")

    def test_intrinsic_binding(self):
        def change(m):
            next(f for f in m["functions"] if f["name"] == "llvm.memset.p0.i64")["intrinsic"] = None
        self.rejected("intrinsic-relabeled-external", change, "missing intrinsic semantic binding")

    def test_intrinsic_effect_omission(self):
        def change(m):
            block = next(f for f in m["functions"] if f["name"] == "entry")["blocks"][0]
            block["instructions"] = [i for i in block["instructions"] if i["operation"]["op"] != "memory_set"]
        self.rejected("intrinsic-effect-omission", change, "missing/changed intrinsic operation")

    def test_intrinsic_operand_change(self):
        def change(m):
            block = next(f for f in m["functions"] if f["name"] == "entry")["blocks"][0]
            next(i for i in block["instructions"] if i["operation"]["op"] == "memory_set")["operation"]["length"]["bits"] = "7"
        self.rejected("intrinsic-byte-count-change", change, "missing/changed intrinsic operation")

    def test_relative_displacement_width(self):
        # A 16-bit load followed by valid sign extension remains a well-typed
        # graph, but does not implement LLVM's required 32-bit displacement.
        for suffix in ("i32", "i64"):
            def change(m, suffix=suffix):
                type_id = len(m["types"])
                m["types"].append({"kind": "int", "bits": 16})
                function = next(f for f in m["functions"] if f["name"] == "relative_" + suffix)
                load = next(i for b in function["blocks"] for i in b["instructions"] if i["operation"]["op"] == "load")
                load["result"]["ty"] = type_id
            with self.subTest(suffix=suffix):
                self.rejected("relative-displacement-i16-" + suffix, change, "missing/changed intrinsic operation")
                mutant = copy.deepcopy(self.module)
                change(mutant)
                path = self.directory / (suffix + ".wrong-displacement-width.native.json")
                receipt = self.directory / (suffix + ".wrong-displacement-width.verification.json")
                path.write_text(json.dumps(mutant) + "\n")
                self.run_compiler([self.compiler, path, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
                self.assertTrue(json.loads(receipt.read_text())["verified"])
                self.faults[-1]["well_typed_mutant"] = artifact(path)
                self.faults[-1]["independent_native_verification"] = artifact(receipt)

    def test_relative_extension_width(self):
        for suffix in ("i32", "i64"):
            def change(m, suffix=suffix):
                type_id = next(index for index, ty in enumerate(m["types"]) if ty == {"kind": "int", "bits": 32})
                function = next(f for f in m["functions"] if f["name"] == "relative_" + suffix)
                definitions = {i["result"]["id"]: i for b in function["blocks"] for i in b["instructions"] if i.get("result")}
                result = next(i for i in definitions.values() if i["result"]["id"] == 2)
                extension = definitions[result["operation"]["offset"]["id"]]
                extension["result"]["ty"] = type_id
            with self.subTest(suffix=suffix):
                self.rejected("relative-extension-i32-" + suffix, change, "missing/changed intrinsic operation")


if __name__ == "__main__":
    unittest.main()
