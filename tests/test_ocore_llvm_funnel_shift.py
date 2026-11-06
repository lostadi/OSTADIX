"""Whole-unit scalar funnel import controls and an explicit new-compiler gate.

FunnelSourceControls uses the candidate Python frontend and pinned LLVM22.
FunnelNativeControls additionally REQUIRES an explicitly selected newly built
compiler; missing prerequisites fail rather than becoming passing skips.
Neither class establishes runtime/provider closure or cross-ISA behavior.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests.ocore_llvm_source_inventory import Reader, check_inventory, InventoryMismatch


ROOT = Path(__file__).resolve().parents[1]
SDK = Path("/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib")
LIBRARY = Path(os.environ.get("OCORE_TEST_LLVM_LIBRARY", SDK / "riscv64-linux-gnu/libLLVM.so.22.1"))
PIN = os.environ.get("OCORE_TEST_LLVM_SHA256", "8617d27fecff5e31785eed07ee1cd7665e083bb689b6fb13266956d5231afe83")
WIDTHS = (1, 2, 4, 8, 16, 32, 64, 128)
TRIPLES = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "riscv64-unknown-linux-gnu")


def identity(path):
    path = Path(path)
    raw = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def fixture(triple=TRIPLES[0], widths=WIDTHS):
    text = (f'target triple = "{triple}"\n'
            'target datalayout = "e-p:64:64-i64:64-i128:128-n8:16:32:64-S128"\n'
            '@original_marker = global i64 123456789, align 8\n'
            'declare i64 @original_unused_provider(i64)\n'
            'define i64 @original_cold() { ret i64 987654321 }\n')
    for width in widths:
        for kind in ("fshl", "fshr"):
            text += (f'declare i{width} @llvm.{kind}.i{width}(i{width}, i{width}, i{width})\n'
                     f'define i{width} @{kind}_{width}(i{width} %a, i{width} %b, i{width} %c) {{\n'
                     f'  %r = call i{width} @llvm.{kind}.i{width}(i{width} %a, i{width} %b, i{width} %c)\n'
                     f'  ret i{width} %r\n}}\n')
    return text.encode()


class FunnelSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        retain = os.environ.get("OCORE_FUNNEL_RETAIN")
        if retain:
            Path(retain).mkdir(parents=True, exist_ok=True)
        cls.directory = Path(tempfile.mkdtemp(prefix="funnel-source-", dir=retain))
        cls.commands, cls.records = [], []
        cls.sources = [ROOT / "scripts/ocore_llvm_import.py", ROOT / "tests/ocore_llvm_source_inventory.py",
                       ROOT / "crates/ostadix-api/src/ocore/native_verify.rs", Path(__file__)]
        cls.tools = [LIBRARY, SDK / "llvm-22/bin/llvm-as"]
        cls.before = [identity(path) for path in cls.sources + cls.tools]
        cls.reader = Reader(LIBRARY, PIN)

    @classmethod
    def tearDownClass(cls):
        after = [identity(path) for path in cls.sources + cls.tools]
        report = {"schema": "ocore-funnel-source-controls-v1", "commands": cls.commands,
                  "records": cls.records, "before": cls.before, "after": after,
                  "stable": cls.before == after, "candidate_worker_only": True,
                  "new_compiler_embedded": False, "native_behavior_qualified": False,
                  "original_runtime_complete": False, "provider_closure_complete": False}
        (cls.directory / "receipt.json").write_text(json.dumps(report, indent=2) + "\n")
        if cls.before != after:
            raise AssertionError("source/tool bytes changed during source controls")

    @classmethod
    def command(cls, argv, success=True):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=120)
        number = len(cls.commands)
        out, err = cls.directory / f"{number}.stdout", cls.directory / f"{number}.stderr"
        out.write_bytes(result.stdout)
        err.write_bytes(result.stderr)
        cls.commands.append({"argv": argv, "exit_code": result.returncode,
                             "stdout": identity(out), "stderr": identity(err)})
        if success and result.returncode:
            raise AssertionError(result.stderr.decode(errors="replace"))
        return result

    def imported(self, label, raw):
        path = self.directory / (label + (".bc" if raw.startswith(b"BC") else ".ll"))
        path.write_bytes(raw)
        module = importer.import_module(path, LIBRARY, expected_sha256=PIN)
        native = self.directory / (label + ".native.json")
        native.write_text(json.dumps(module, indent=2) + "\n")
        original = self.reader.read(path)
        source_inventory = self.directory / (label + ".source-inventory.json")
        source_inventory.write_text(json.dumps(original, indent=2) + "\n")
        preservation = check_inventory(original, module)
        receipt = self.directory / (label + ".preservation.json")
        receipt.write_text(json.dumps(preservation, indent=2) + "\n")
        self.records.append({"original": identity(path), "candidate_native": identity(native),
                             "source_inventory": identity(source_inventory), "preservation": identity(receipt)})
        return path, module, original

    def test_all_admitted_widths_both_directions_three_targets_text_and_bitcode(self):
        for triple in TRIPLES:
            path, module, _ = self.imported(triple, fixture(triple))
            bitcode = path.with_suffix(".bc")
            self.command([SDK / "llvm-22/bin/llvm-as", path, "-o", bitcode])
            _, binary, _ = self.imported(triple + "-bitcode", bitcode.read_bytes())
            for candidate in (module, binary):
                self.assertEqual(len(candidate["functions"]), 34)
                self.assertEqual([g["name"] for g in candidate["globals"]], ["original_marker"])
                for function in candidate["functions"]:
                    if function["name"].startswith(("fshl_", "fshr_")):
                        instructions = function["blocks"][0]["instructions"]
                        self.assertEqual([i["operation"]["op"] for i in instructions[:3]], ["freeze"] * 3)
                        self.assertEqual(instructions[-1]["operation"]["op"], "select")
                        self.assertEqual(instructions[-1]["result"]["id"], 3)

    def test_undef_poison_and_identical_operands_are_frozen_once_per_source_argument(self):
        for value in ("%a", "undef", "poison"):
            raw = fixture(widths=(128,)).replace(b"i128 %a, i128 %b, i128 %c)",
                                               f"i128 {value}, i128 {value}, i128 {value})".encode())
            # Replace call operands only, retaining the original function ABI.
            raw = raw.replace(f"(i128 {value}, i128 {value}, i128 {value}) {{".encode(),
                              b"(i128 %a, i128 %b, i128 %c) {")
            _, module, original = self.imported("nondefined-" + value.strip("%"), raw)
            if value in ("undef", "poison"):
                for direction in ("fshl", "fshr"):
                    arguments = original["functions"][direction + "_128"]["intrinsic_sites"][0]["args"]
                    self.assertEqual([argument["kind"] for argument in arguments], [value] * 3)
                mutant = copy.deepcopy(module)
                function = next(f for f in mutant["functions"] if f["name"] == "fshl_128")
                function["blocks"][0]["instructions"][0]["operation"]["value"]["kind"] = (
                    "poison" if value == "undef" else "undef")
                with self.assertRaisesRegex(InventoryMismatch, "missing/changed intrinsic operation llvm.fshl"):
                    check_inventory(original, mutant)
            for function in module["functions"]:
                if function["name"].startswith(("fshl_", "fshr_")):
                    freezes = [i for i in function["blocks"][0]["instructions"]
                               if i["operation"]["op"] == "freeze"]
                    self.assertEqual(len(freezes), 3)
                    self.assertEqual(len({i["result"]["id"] for i in freezes}), 3)

    def test_well_typed_graph_changes_cannot_pass_independent_source_correspondence(self):
        _, module, original = self.imported("mutant-baseline", fixture(widths=(128,)))
        for fault in ("mask63", "wrong-zero-input", "wrong-direction", "nowrap"):
            mutant = copy.deepcopy(module)
            function = next(f for f in mutant["functions"] if f["name"] == "fshl_128")
            operations = [i["operation"] for i in function["blocks"][0]["instructions"]]
            if fault == "mask63":
                next(op for op in operations if op.get("kind") == "and")["rhs"]["bits"] = "63"
            elif fault == "wrong-zero-input":
                operations[-1]["on_true"] = {"kind": "value", "id": function["blocks"][0]["instructions"][1]["result"]["id"]}
            elif fault == "wrong-direction":
                next(op for op in operations if op.get("kind") == "shl")["kind"] = "l_shr"
            else:
                next(op for op in operations if op.get("kind") == "sub")["flags"] = ["nsw"]
            artifact = self.directory / (fault + ".native.json")
            artifact.write_text(json.dumps(mutant, indent=2) + "\n")
            with self.assertRaisesRegex(InventoryMismatch, "missing/changed intrinsic operation"):
                check_inventory(original, mutant)
            self.records.append({"detected_mutation": fault, "artifact": identity(artifact),
                                 "independent_native_verification_pending": True})

    def test_llvm_valid_unsupported_scalar_vector_and_neighbor_overloads_fail_whole_import(self):
        for width in (3, 65, 256):
            path = self.directory / f"unsupported-{width}.ll"
            path.write_bytes(fixture(widths=(width,)))
            self.command([SDK / "llvm-22/bin/llvm-as", path, "-o", path.with_suffix(".bc")])
            with self.assertRaisesRegex(importer.ImportFailure, "requires explicit"):
                importer.import_module(path, LIBRARY, expected_sha256=PIN)
        for name in ("llvm.fshl.i0128", "llvm.fshr.v2i64", "llvm.fshl.i128.extra"):
            self.assertNotIn(name, importer.Importer.INTEGER_FUNNEL_INTRINSICS)
        vector = (b'target triple = "x86_64-unknown-linux-gnu"\n'
                  b'target datalayout = "e-p:64:64-i64:64"\n'
                  b'declare <2 x i64> @llvm.fshr.v2i64(<2 x i64>, <2 x i64>, <2 x i64>)\n'
                  b'define <2 x i64> @original(<2 x i64> %a, <2 x i64> %b, <2 x i64> %c) {\n'
                  b'%r = call <2 x i64> @llvm.fshr.v2i64(<2 x i64> %a, <2 x i64> %b, <2 x i64> %c)\n'
                  b'ret <2 x i64> %r\n}\n')
        path = self.directory / "unsupported-vector.ll"
        path.write_bytes(vector)
        self.command([SDK / "llvm-22/bin/llvm-as", path, "-o", path.with_suffix(".bc")])
        with self.assertRaises(importer.ImportFailure):
            importer.import_module(path, LIBRARY, expected_sha256=PIN)

    def test_original_full_multf3_units_preserve_their_actual_abi_profiles(self):
        corpus = Path(os.environ.get("OCORE_FUNNEL_MULTF3_ROOT", "/home/orangepi/ostadix-BM/target/oversight-20261020/compiler-rt-whole-units-v4"))
        for profile in ("x86_64", "aarch64", "riscv64-lp64", "riscv64-lp64d"):
            original = corpus / profile / "multf3/original.ll"
            before = identity(original)
            _, module, source = self.imported("original-multf3-" + profile, original.read_bytes())
            self.assertEqual(before, identity(original))
            self.assertIn("__multf3", source["functions"])
            self.assertTrue(any(f["name"] == "llvm.fshl.i128" and f["intrinsic"] == f["name"]
                                for f in module["functions"]))
            mutant = copy.deepcopy(module)
            unary = next(i["operation"] for f in mutant["functions"] for block in f["blocks"]
                         for i in block["instructions"] if i["operation"]["op"] == "integer_count_leading_zeros")
            unary["zero_is_poison"] = not unary["zero_is_poison"]
            with self.assertRaisesRegex(InventoryMismatch, "missing/changed intrinsic operation llvm.ctlz"):
                check_inventory(source, mutant)
            self.records[-1].update({"upstream_original": before, "abi_profile": profile,
                                     "module_target": module["target"], "changed_ctlz_control_rejected": True})


class FunnelNativeControls(FunnelSourceControls):
    """Run ONLY with a genuinely rebuilt compiler containing this candidate.

    Source controls are inherited deliberately; all native gates must also
    pass before this stronger class passes. This still does not execute code.
    """
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        compiler = os.environ.get("OCORE_FUNNEL_OCOREC")
        if not compiler:
            raise AssertionError("unmet new-compiler gate: OCORE_FUNNEL_OCOREC is required")
        cls.compiler = Path(compiler).resolve(strict=True)
        cls.tools.append(cls.compiler)
        cls.before = [identity(path) for path in cls.sources + cls.tools]

    def embedded_import(self, original, output, target):
        self.command([self.compiler, original, "--input-kind", "llvm-ir", "--emit", "mir",
                      "--target", target, "--llvm-library", LIBRARY, "--llvm-sha256", PIN, "-o", output])
        module = json.loads(output.read_text())
        preservation = check_inventory(self.reader.read(original), module)
        self.records.append({"actual_compiler_input": identity(original), "actual_compiler_output": identity(output),
                             "source_correspondence": preservation})
        return module

    def test_independent_native_verification_and_real_object_emission(self):
        for triple in TRIPLES:
            original, _, _ = self.imported("native-" + triple, fixture(triple))
            native = self.directory / ("native-" + triple + ".native.json")
            target = triple.replace("linux-gnu", "none")
            self.embedded_import(original, native, target)
            receipt = native.with_suffix(".verification.json")
            self.command([self.compiler, native, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
            output = native.with_suffix(".o")
            self.command([self.compiler, native, "--input-kind", "native-ir", "--emit", "obj", "--target", target, "-o", output])
            self.assertGreater(output.stat().st_size, 0)
            self.records.append({"native_verification": identity(receipt), "object": identity(output),
                                 "target": target, "native_execution_qualified": False})

    def test_whole_original_multf3_native_verification_and_objects_keep_actual_abi(self):
        corpus = Path(os.environ.get("OCORE_FUNNEL_MULTF3_ROOT", "/home/orangepi/ostadix-BM/target/oversight-20261020/compiler-rt-whole-units-v4"))
        for profile, target in (("x86_64", "x86_64-unknown-none"), ("aarch64", "aarch64-unknown-none"),
                                ("riscv64-lp64", "riscv64-unknown-none"), ("riscv64-lp64d", "riscv64-unknown-none")):
            original = corpus / profile / "multf3/original.ll"
            self.imported("native-original-" + profile, original.read_bytes())
            native = self.directory / ("native-original-" + profile + ".native.json")
            self.embedded_import(original, native, target)
            verification, output = native.with_suffix(".verification.json"), native.with_suffix(".o")
            self.command([self.compiler, native, "--input-kind", "native-ir", "--verify-native", "--receipt", verification])
            self.command([self.compiler, native, "--input-kind", "native-ir", "--emit", "obj", "--target", target, "-o", output])
            self.records.append({"profile": profile, "native_verification": identity(verification),
                                 "object": identity(output), "native_execution_qualified": False})

    def test_unlowered_calls_and_forged_bodies_fail_verification_and_emission(self):
        _, baseline, _ = self.imported("forgery-baseline", fixture(widths=(128,)))
        for fault in ("unlowered-call", "forged-body", "ordinary-provider"):
            mutant = copy.deepcopy(baseline)
            declaration = next(f for f in mutant["functions"] if f["name"] == "llvm.fshl.i128")
            if fault == "unlowered-call":
                function = next(f for f in mutant["functions"] if f["name"] == "fshl_128")
                pointer = len(mutant["types"])
                mutant["types"].append({"kind": "pointer", "address_space": 0})
                function["blocks"][0]["instructions"][-1]["operation"] = {
                    "op": "call", "callee": {"kind": "symbol", "ty": pointer, "name": declaration["name"]},
                    "signature": declaration["signature"], "args": [{"kind": "value", "id": i} for i in range(3)]}
            elif fault == "forged-body":
                declaration["entry"] = 0
                declaration["blocks"] = [{"id": 0, "instructions": [], "terminator": {
                    "op": "return", "value": {"kind": "int", "ty": declaration["signature"]["result"], "bits": "0"}}}]
            else:
                declaration["intrinsic"] = None
            path = self.directory / (fault + ".native.json")
            path.write_text(json.dumps(mutant, indent=2) + "\n")
            for action in (["--verify-native"], ["--emit", "obj", "--target", "x86_64-unknown-none", "-o", str(path) + ".o"]):
                result = self.command([self.compiler, path, "--input-kind", "native-ir", *action], success=False)
                self.assertNotEqual(result.returncode, 0, f"forged intrinsic accepted: {fault}")
                self.assertIn(b"intrinsic", result.stderr)
            self.assertFalse(Path(str(path) + ".o").exists())

    def test_semantic_graph_mutants_are_independently_well_typed(self):
        self.test_well_typed_graph_changes_cannot_pass_independent_source_correspondence()
        for fault in ("mask63", "wrong-zero-input", "wrong-direction", "nowrap"):
            path = self.directory / (fault + ".native.json")
            self.command([self.compiler, path, "--input-kind", "native-ir", "--verify-native"])


if __name__ == "__main__":
    unittest.main()
