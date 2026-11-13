"""Required exact-translation inventory controls, not executable-body proof.

The full authored LLVM unit retains cold globals, relocations and declarations.
Every changed module must first pass the real native verifier. Flag flips test
literal preservation; a true-to-false flip is not itself called wrong code.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

HELPER = Path(__file__).with_name("ocore_llvm_source_inventory.py")
SPEC = importlib.util.spec_from_file_location("scalar_intrinsic_inventory", HELPER)
INV = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INV
SPEC.loader.exec_module(INV)
EXPECTED_CASES = sorted(["ptrmask.pointer", "ptrmask.mask", "ptrmask.drop_unused", "ptrmask.duplicate_unused"] +
                        [kind + str(bits) + ".value" for kind in ["ctlz", "abs"] for bits in [32, 64]] +
                        [kind + str(bits) + "." + direction for kind in ["ctlz", "abs"] for bits in [32, 64] for direction in ["false_to_true", "true_to_false"]])
SOURCE = r"""source_filename = "independent-scalar-intrinsics.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "riscv64-unknown-linux-gnu"
@cold_global = global i64 42, align 8
@cold_pointer = global ptr @cold_global, align 8
@cold_callback = global ptr @cold_external, align 8
declare i64 @cold_external(i64)
declare ptr @llvm.ptrmask.p0.i64(ptr, i64)
declare i32 @llvm.ctlz.i32(i32, i1 immarg)
declare i64 @llvm.ctlz.i64(i64, i1 immarg)
declare i32 @llvm.abs.i32(i32, i1 immarg)
declare i64 @llvm.abs.i64(i64, i1 immarg)
define i64 @probe(ptr %p, ptr %q, i64 %mask, i64 %other_mask, i32 %x, i32 %y, i64 %a, i64 %b) {
entry:
 %used = call ptr @llvm.ptrmask.p0.i64(ptr %p, i64 %mask)
 %unused = call ptr @llvm.ptrmask.p0.i64(ptr %q, i64 %other_mask)
 %clz32f = call i32 @llvm.ctlz.i32(i32 %x, i1 false)
 %clz32t = call i32 @llvm.ctlz.i32(i32 %y, i1 true)
 %clz64f = call i64 @llvm.ctlz.i64(i64 %a, i1 false)
 %clz64t = call i64 @llvm.ctlz.i64(i64 %b, i1 true)
 %abs32f = call i32 @llvm.abs.i32(i32 %x, i1 false)
 %abs32t = call i32 @llvm.abs.i32(i32 %y, i1 true)
 %abs64f = call i64 @llvm.abs.i64(i64 %a, i1 false)
 %abs64t = call i64 @llvm.abs.i64(i64 %b, i1 true)
 %result = ptrtoint ptr %used to i64
 ret i64 %result
}
"""


def pin(path):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class ScalarIntrinsicInventoryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = Path(os.environ["OCORE_SCALAR_INVENTORY_OUTPUT"])
        cls.out.mkdir(parents=True, exist_ok=False)
        cls.compiler = Path(os.environ["OCORE_SCALAR_INVENTORY_OCOREC"])
        cls.library = Path(os.environ["OCORE_TEST_LLVM_LIBRARY"])
        cls.parser_sha = os.environ["OCORE_TEST_LLVM_SHA256"]
        cls.before = [pin(HELPER), pin(__file__), pin(cls.compiler), pin(cls.library), pin(sys.executable)]
        assert cls.before[2]["sha256"] == os.environ["OCORE_SCALAR_INVENTORY_OCOREC_SHA256"]
        cls.record = {"schema": "ocore-scalar-intrinsic-inventory-controls-v1", "scope": "exact source-call/typed-operation and inventory preservation only; no execution/runtime qualification",
                      "before": cls.before, "commands": [], "cases": [], "expected_case_ids": EXPECTED_CASES,
                      "expected_mutant_count": 16, "flag_contract": "exact imported literal preservation; true-to-false may be a valid LLVM refinement in other transformations",
                      "runtime_accepted": False, "native_execution_qualified": False}
        cls.source_path = cls.out / "original.ll"; cls.source_path.write_text(SOURCE)
        original = cls.out / "original.native-ir.json"
        code = cls.command([cls.compiler, cls.source_path, "--input-kind", "llvm-ir", "--emit", "mir", "--target", "riscv64-unknown-none", "--llvm-library", cls.library, "--llvm-sha256", cls.parser_sha, "-o", original], "import")
        assert code == 0, "actual V5 import failed; see retained import diagnostics"
        cls.module = json.loads(original.read_text())
        cls.reader = INV.Reader(cls.library, cls.parser_sha)
        cls.source = cls.reader.read(cls.source_path)
        cls.verify(cls.module, "baseline")
        # A rejected baseline cannot qualify any subsequent mutation control.
        proof = INV.check_inventory(copy.deepcopy(cls.source), copy.deepcopy(cls.module))
        proof_path = cls.out / "baseline-preservation.json"
        proof_path.write_text(json.dumps(proof, indent=2) + "\n")
        cls.record["baseline_inventory_positive"] = pin(proof_path)
        cls.save()
        cls.record["source"] = pin(cls.source_path); cls.record["baseline"] = pin(original); cls.save()

    @classmethod
    def save(cls):
        (cls.out / "report.json").write_text(json.dumps(cls.record, indent=2) + "\n")

    @classmethod
    def command(cls, argv, label):
        row = {"argv": list(map(str, argv)), "started_epoch": time.time()}
        cls.record["commands"].append(row); cls.save()
        stdout, stderr = cls.out / (label + ".stdout"), cls.out / (label + ".stderr")
        with stdout.open("wb") as out, stderr.open("wb") as err:
            process = subprocess.run(row["argv"], env=os.environ.copy(), stdout=out, stderr=err)
        row.update(exit_code=process.returncode, stdout=pin(stdout), stderr=pin(stderr), finished_epoch=time.time()); cls.save()
        return process.returncode

    @classmethod
    def verify(cls, module, label):
        path = cls.out / (label + ".native-ir.json"); path.write_text(json.dumps(module, indent=2) + "\n")
        receipt = cls.out / (label + ".verification.json")
        code = cls.command([cls.compiler, path, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt], label + "-verify")
        assert code == 0, "mutant/baseline is not structurally valid: " + label
        verified = json.loads(receipt.read_text())
        assert verified["verified"] is True and verified["module_sha256"] == pin(path)["sha256"]
        return pin(path), pin(receipt)

    @staticmethod
    def instructions(module):
        return [(block, index, instruction) for function in module["functions"] for block in function["blocks"]
                for index, instruction in enumerate(block["instructions"])]

    @classmethod
    def unary(cls, module, kind, bits, flag_value):
        op = "integer_count_leading_zeros" if kind == "ctlz" else "integer_abs"
        flag = "zero_is_poison" if kind == "ctlz" else "int_min_is_poison"
        found = [instruction for _, _, instruction in cls.instructions(module)
                 if instruction["operation"]["op"] == op and instruction["operation"][flag] is flag_value
                 and INV.native_shape(module["types"], instruction["result"]["ty"]) == {"kind": "int", "bits": bits}]
        assert len(found) == 1
        return found[0]["operation"]

    def mutation(self, identity, mutate):
        module = copy.deepcopy(self.module); mutate(module)
        native, verification = self.verify(module, identity.replace(".", "-"))
        # Inventory rejection is meaningful only AFTER real structural verification.
        with self.assertRaises(INV.InventoryMismatch) as error:
            INV.check_inventory(copy.deepcopy(self.source), module)
        self.assertRegex(str(error.exception), "missing/changed intrinsic operation|intrinsic site count/order changed|unaccounted scalar intrinsic operation")
        self.record["cases"].append({"id": identity, "native": native, "verification": verification,
                                     "native_verifier_exit_code": 0, "inventory_rejected": True, "diagnostic": str(error.exception)})
        self.save()

    def test_complete_authored_unit_preserves_dynamic_intrinsics_and_cold_inventory(self):
        proof = INV.check_inventory(copy.deepcopy(self.source), copy.deepcopy(self.module))
        (self.out / "positive-preservation.json").write_text(json.dumps(proof, indent=2) + "\n")
        self.assertEqual({row["name"] for row in self.module["globals"]}, {"cold_global", "cold_pointer", "cold_callback"})
        self.assertIn("cold_external", {row["name"] for row in self.module["functions"]})
        self.assertEqual(sum(instruction["operation"]["op"] in {"ptr_mask", "integer_count_leading_zeros", "integer_abs"} for _, _, instruction in self.instructions(self.module)), 10)
        self.record["positive_preservation"] = pin(self.out / "positive-preservation.json"); self.save()

    def test_pointer_and_mask_same_typed_substitutions_are_detected(self):
        for field in ["pointer", "mask"]:
            with self.subTest(field=field):
                def mutate(module, field=field):
                    ops = [i["operation"] for _, _, i in self.instructions(module) if i["operation"]["op"] == "ptr_mask"]
                    ops[0][field] = copy.deepcopy(ops[1][field])
                self.mutation("ptrmask." + field, mutate)

    def test_unary_same_typed_operand_substitutions_are_detected(self):
        for kind in ["ctlz", "abs"]:
            for bits in [32, 64]:
                with self.subTest(kind=kind, bits=bits):
                    def mutate(module, kind=kind, bits=bits):
                        self.unary(module, kind, bits, False)["value"] = copy.deepcopy(self.unary(module, kind, bits, True)["value"])
                    self.mutation(kind + str(bits) + ".value", mutate)

    def test_both_literal_flag_directions_obey_exact_translation_contract(self):
        for kind in ["ctlz", "abs"]:
            for bits in [32, 64]:
                for value in [False, True]:
                    with self.subTest(kind=kind, bits=bits, original_flag=value):
                        def mutate(module, kind=kind, bits=bits, value=value):
                            flag = "zero_is_poison" if kind == "ctlz" else "int_min_is_poison"
                            self.unary(module, kind, bits, value)[flag] = not value
                        self.mutation(kind + str(bits) + (".true_to_false" if value else ".false_to_true"), mutate)

    def test_dropped_unused_pointer_mask_is_detected(self):
        def mutate(module):
            rows = [(b, i) for b, i, instruction in self.instructions(module) if instruction["operation"]["op"] == "ptr_mask"]
            block, index = rows[1]; del block["instructions"][index]
        self.mutation("ptrmask.drop_unused", mutate)

    def test_duplicated_unused_pointer_mask_with_fresh_id_is_detected(self):
        def mutate(module):
            rows = [(b, i, instruction) for b, i, instruction in self.instructions(module) if instruction["operation"]["op"] == "ptr_mask"]
            block, index, instruction = rows[1]; duplicate = copy.deepcopy(instruction)
            ids = [row["id"] for function in module["functions"] for row in function["params"]]
            ids += [row["result"]["id"] for _, _, row in self.instructions(module) if row.get("result")]
            duplicate["result"]["id"] = max(ids) + 1
            block["instructions"].insert(index + 1, duplicate)
        self.mutation("ptrmask.duplicate_unused", mutate)

    @classmethod
    def tearDownClass(cls):
        cls.record["after"] = [pin(HELPER), pin(__file__), pin(cls.compiler), pin(cls.library), pin(sys.executable)]
        cls.record["source_tools_stable"] = cls.record["before"] == cls.record["after"]
        cls.record["actual_case_ids"] = sorted(case["id"] for case in cls.record["cases"])
        cls.record["case_membership_exact"] = cls.record["actual_case_ids"] == EXPECTED_CASES
        cls.record["actual_mutant_count"] = len(cls.record["cases"]); cls.save()
