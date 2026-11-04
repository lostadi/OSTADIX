"""Real LLVM pointer-promise admission; no native execution qualification."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as base
from tests.ocore_llvm_source_inventory import InventoryMismatch, Reader, check_inventory


def pin(path):
    path = Path(path)
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


class PtrMaskAlignmentTests(base.LlvmImportTests):
    def setUp(self):
        parent = Path(os.environ["OCORE_PTRMASK_ALIGN_RETAIN"])
        parent.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix="align-", dir=parent))
        self.source = self.directory / "input.ll"
        self.record = {"test": self.id(), "commands": [], "modules": [], "rejections": [],
                       "runtime_accepted": False, "native_execution_qualified": False}
        self.counter = 0
        self.compiler = os.environ["OCORE_PTRMASK_ALIGN_VERIFIER"]
        self.reader = Reader(self.library, self.library_sha256)
        self.save()

    def save(self):
        (self.directory / "report.json").write_text(json.dumps(self.record, indent=2) + "\n")

    def verify_original(self, source):
        source = Path(source)
        original_pin = pin(source)
        module = importer.import_module(source, library_path=self.library,
                                        expected_sha256=self.library_sha256,
                                        wide_volatile_profile="ordinary-ram-split-v1")
        self.assertEqual(module["provenance"]["input_sha256"], original_pin["sha256"])
        stem = self.directory / str(self.counter)
        self.counter += 1
        output, receipt = stem.with_suffix(".native.json"), stem.with_suffix(".verify.json")
        output.write_text(json.dumps(module, indent=2) + "\n")
        argv = [self.compiler, str(output), "--input-kind", "native-ir", "--verify-native",
                "--receipt", str(receipt)]
        run = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        self.record["commands"].append({"argv": argv, "exit_code": run.returncode,
                                        "stdout": run.stdout, "stderr": run.stderr})
        self.save()
        self.assertEqual(run.returncode, 0, run.stderr)
        verified = json.loads(receipt.read_text())
        self.assertIs(verified["verified"], True)
        self.assertEqual(verified["module_sha256"], pin(output)["sha256"])
        inventory = self.reader.read(source)
        preservation = check_inventory(inventory, module)
        inventory_path = stem.with_suffix(".inventory.json")
        inventory_path.write_text(json.dumps({"inventory": inventory, "preservation": preservation}, indent=2) + "\n")
        self.assertEqual(pin(source), original_pin)
        self.record["modules"].append({"source": original_pin, "module": pin(output),
                                        "verification": pin(receipt), "inventory": pin(inventory_path)})
        self.save()
        return module

    def authored(self, body, triple=base.TRIPLES[0]):
        self.source = self.directory / ("authored-" + str(self.counter) + ".ll")
        self.write(body, triple=triple, layout=base.LAYOUT + "-i128:128")
        return self.verify_original(self.source)

    def reject_original(self, body, stage, verified_source=False):
        self.source = self.directory / ("rejected-" + str(len(self.record["rejections"])) + ".ll")
        self.write(body)
        original = pin(self.source)
        if verified_source:
            self.reader.read(self.source)
        with self.assertRaises(importer.ImportFailure) as caught:
            importer.import_module(self.source, library_path=self.library,
                                   expected_sha256=self.library_sha256)
        self.record["rejections"].append({"source": original, "stage": caught.exception.stage,
                                          "independent_original_llvm_verified": verified_source,
                                          "error": str(caught.exception)})
        self.save()
        self.assertEqual(caught.exception.stage, stage)
        self.assertEqual(pin(self.source), original)

    def test_proven_result_alignment_is_explicit_on_all_three_isas(self):
        for triple in base.TRIPLES:
            for alignment, mask in ((1, "%mask"), (16, "-16"), (1 << 32, "-4294967296"), (16, "0")):
                with self.subTest(triple=triple, alignment=alignment):
                    module = self.authored(f"""
@anchor = global i64 7, align 8
@slot = global ptr @anchor, align 8
declare align 64 ptr @llvm.ptrmask.p0.i64(ptr align 32, i64)
declare i64 @unused_dependency(i64)
define ptr @mask(ptr %base, i64 %mask) {{
  %r = call align {alignment} ptr @llvm.ptrmask.p0.i64(ptr %base, i64 {mask})
  ret ptr %r
}}
""", triple)
                    function = self.function(module, "mask")
                    expected_mask = ({"kind": "value", "id": function["params"][1]["id"]} if mask == "%mask" else
                                     {"kind": "int", "ty": function["params"][1]["ty"], "bits": str(int(mask) % (1 << 64))})
                    self.assertEqual(self.operations(function), [{"op": "ptr_mask", "return_alignment": alignment,
                        "pointer": {"kind": "value", "id": function["params"][0]["id"]},
                        "mask": expected_mask}])
                    refinements = module["provenance"]["refinements"]
                    self.assertTrue(any(f"callsite attribute index 0: retained ptrmask return_alignment={alignment};" in text
                                        for text in refinements))

    def canonical_declaration(self):
        sdk = Path(os.environ["OCORE_TEST_LLVM22_BIN"])
        bitcode, text = self.directory / "canonical.bc", self.directory / "canonical.ll"
        for argv in ([sdk / "llvm-as", self.source, "-o", bitcode],
                     [sdk / "llvm-dis", bitcode, "-o", text]):
            result = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=30)
            self.record["commands"].append({"argv": list(map(str, argv)), "exit_code": result.returncode,
                                            "stdout": result.stdout, "stderr": result.stderr})
            self.save()
            self.assertEqual(result.returncode, 0, result.stderr)
        declaration, = [line for line in text.read_text().splitlines()
                        if line.startswith("declare") and "@llvm.ptrmask.p0.i64" in line]
        self.assertTrue(declaration.startswith("declare ptr @llvm.ptrmask.p0.i64(ptr, i64)"))
        self.record["llvm22_canonical_intrinsic_declaration"] = {
            "source": pin(self.source), "bitcode": pin(bitcode), "canonical_text": pin(text),
            "declaration": declaration,
            "meaning": "Pinned LLVM22 intrinsic upgrade normalizes custom declaration attrs; the importer does not rewrite raw source or inherit these into calls"}
        self.save()

    def test_declaration_alignment_is_not_inherited_by_callsite(self):
        module = self.authored("""
declare align 64 ptr @llvm.ptrmask.p0.i64(ptr align 32, i64)
define ptr @mask(ptr %base, i64 %mask) {
  %r = call ptr @llvm.ptrmask.p0.i64(ptr %base, i64 %mask)
  ret ptr %r
}
""")
        self.canonical_declaration()
        self.assertNotIn("return_alignment", self.operations(self.function(module, "mask"))[0])
        self.assertFalse(any("retained ptrmask return_alignment=" in text
                             for text in module["provenance"]["refinements"]))

    def test_unproved_masks_and_input_alignment_remain_explicit_unsupported(self):
        prefix = "declare ptr @llvm.ptrmask.p0.i64(ptr, i64)\n"
        for alignment, mask in ((16, "%m"), (16, "-8"), (16, "-1"), (32, "-16")):
            with self.subTest(alignment=alignment, mask=mask):
                self.reject_original(prefix + f"define ptr @mask(ptr %p, i64 %m) {{ %r = call align {alignment} ptr @llvm.ptrmask.p0.i64(ptr %p, i64 {mask})\n ret ptr %r }}", "import", verified_source=True)
        self.reject_original(prefix + "define ptr @mask(ptr %p, i64 %m) { %r = call ptr @llvm.ptrmask.p0.i64(ptr align 8 %p, i64 %m)\n ret ptr %r }", "import", verified_source=True)
        # A previous proved call must not admit a later, unused unproved one.
        self.reject_original(prefix + "define ptr @mask(ptr %p) { %ok = call align 16 ptr @llvm.ptrmask.p0.i64(ptr %p, i64 -16)\n %unused = call align 32 ptr @llvm.ptrmask.p0.i64(ptr %p, i64 -16)\n ret ptr %ok }", "import", verified_source=True)

    def test_verified_constraint_omissions_and_mutations_fail_original_inventory(self):
        baseline = self.authored("""
declare ptr @llvm.ptrmask.p0.i64(ptr, i64)
define ptr @mask(ptr %p) {
  %r = call align 16 ptr @llvm.ptrmask.p0.i64(ptr %p, i64 -16)
  ret ptr %r
}
""")
        inventory = self.reader.read(self.source)
        self.record["mutants"] = []
        for name in ("drop", "weaken1", "weaken8", "change_mask"):
            mutant = json.loads(json.dumps(baseline))
            operation, = self.operations(self.function(mutant, "mask"))
            if name == "drop":
                del operation["return_alignment"]
            elif name == "change_mask":
                operation["mask"]["bits"] = str((1 << 64) - 32)
            else:
                operation["return_alignment"] = 1 if name == "weaken1" else 8
            output, receipt = self.directory / (name + ".json"), self.directory / (name + ".verification.json")
            output.write_text(json.dumps(mutant, indent=2) + "\n")
            argv = [self.compiler, str(output), "--input-kind", "native-ir", "--verify-native", "--receipt", str(receipt)]
            result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
            self.record["commands"].append({"argv": argv, "exit_code": result.returncode,
                                            "stdout": result.stdout, "stderr": result.stderr})
            self.save()
            self.assertEqual(result.returncode, 0, result.stderr)
            verified = json.loads(receipt.read_text())
            self.assertIs(verified["verified"], True)
            self.assertEqual(verified["module_sha256"], pin(output)["sha256"])
            with self.assertRaises(InventoryMismatch):
                check_inventory(inventory, mutant)
            self.record["mutants"].append({"name": name, "module": pin(output), "verification": pin(receipt),
                                            "original_inventory_rejected": True})
            self.save()
        # Deliberately spoof only the input hash to ensure rejection reaches
        # the actual alignment constraint, rather than stopping at identity.
        changed_source = self.directory / "source-align32-only.ll"
        changed_source.write_text(self.source.read_text().replace("call align 16", "call align 32", 1))
        changed_inventory = self.reader.read(changed_source)  # real LLVM verifier accepts it
        original_site, = inventory["functions"]["mask"]["intrinsic_sites"]
        changed_site, = changed_inventory["functions"]["mask"]["intrinsic_sites"]
        self.assertEqual({k: v for k, v in original_site.items() if k != "return_alignment"},
                         {k: v for k, v in changed_site.items() if k != "return_alignment"})
        self.assertEqual((original_site["return_alignment"], changed_site["return_alignment"]), (16, 32))
        unchanged_owned = json.loads(json.dumps(baseline))
        unchanged_owned["provenance"]["input_sha256"] = pin(changed_source)["sha256"]
        output, receipt = self.directory / "source-align32-owned16.json", self.directory / "source-align32-owned16.verify.json"
        output.write_text(json.dumps(unchanged_owned, indent=2) + "\n")
        argv = [self.compiler, str(output), "--input-kind", "native-ir", "--verify-native", "--receipt", str(receipt)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        self.record["commands"].append({"argv": argv, "exit_code": result.returncode,
                                        "stdout": result.stdout, "stderr": result.stderr})
        self.save()
        self.assertEqual(result.returncode, 0, result.stderr)
        verified = json.loads(receipt.read_text())
        self.assertIs(verified["verified"], True)
        self.assertEqual(verified["module_sha256"], pin(output)["sha256"])
        with self.assertRaises(InventoryMismatch):
            check_inventory(changed_inventory, unchanged_owned)
        self.record["mutants"].append({"name": "source_alignment_only_16_to_32_owned_constraint_unchanged",
                                        "source": pin(changed_source), "source_llvm_verified": True,
                                        "module": pin(output), "verification": pin(receipt),
                                        "original_inventory_rejected": True})
        self.save()

    def test_malformed_or_integer_alignment_is_rejected_by_real_llvm(self):
        prefix = "declare ptr @llvm.ptrmask.p0.i64(ptr, i64)\n"
        for alignment in (0, 3, 1 << 33):
            with self.subTest(alignment=alignment):
                self.reject_original(prefix + f"define ptr @mask(ptr %p, i64 %m) {{ %r = call align {alignment} ptr @llvm.ptrmask.p0.i64(ptr %p, i64 %m)\n ret ptr %r }}", "parse")
        self.reject_original(prefix + "define ptr @mask(ptr %p, i64 %m) { %r = call ptr @llvm.ptrmask.p0.i64(ptr %p, i64 align 8 %m)\n ret ptr %r }", "llvm-verify")

    def test_other_ptrmask_attributes_do_not_gain_alignment_admission(self):
        prefix = "declare ptr @llvm.ptrmask.p0.i64(ptr, i64)\n"
        self.reject_original(prefix + "define ptr @mask(ptr %p, i64 %m) { %r = call dereferenceable(8) ptr @llvm.ptrmask.p0.i64(ptr %p, i64 %m)\n ret ptr %r }", "import")
        self.reject_original(prefix + "define ptr @mask(ptr %p, i64 %m) { %r = call ptr @llvm.ptrmask.p0.i64(ptr %p, i64 %m) [\"deopt\"(i32 1)]\n ret ptr %r }", "import")

    def test_all_sixteen_retained_original_provider_and_caller_units(self):
        manifest = Path(os.environ["OCORE_PTRMASK_ALIGN_ORIGINAL_INPUTS"])
        before = pin(manifest)
        data = json.loads(manifest.read_text())
        self.assertEqual(data["schema"], "ocore-retained-fp-eight-original-units-v1")
        expected = {(p, s) for p in ("x86_64", "aarch64", "riscv64-lp64", "riscv64-lp64d")
                    for s in ("floating_variadic", "floating_variadic_quad_first")}
        self.assertEqual({(row["profile"], row["scope"]) for row in data["cases"]}, expected)
        self.assertEqual(len(data["cases"]), 8)
        originals = []
        for row in data["cases"]:
            for role in ("provider", "caller"):
                inputs = [entry for entry in row["original_inputs"]
                          if Path(entry["path"]).name == row["scope"] + "-" + role + ".ll"]
                self.assertEqual(len(inputs), 1)
                self.assertEqual(pin(inputs[0]["path"]), inputs[0])
                originals.append(inputs[0])
        self.assertEqual(len(originals), 16)
        for original in originals:
            with self.subTest(original=original["path"]):
                self.verify_original(original["path"])
                self.assertEqual(pin(original["path"]), original)
        self.assertEqual(pin(manifest), before)


for _name in dir(base.LlvmImportTests):
    if _name.startswith("test_"):
        setattr(PtrMaskAlignmentTests, _name, None)
