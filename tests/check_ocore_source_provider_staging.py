#!/usr/bin/env python3
"""Required actual source/provider staging regression; never runtime acceptance.

Run this script explicitly with a complete original profile and pinned toolchain.
It builds through public olangc, requires the intended unresolved-provider result,
and independently reconstructs capture and verifies every staged source module.
No changed Rust binary is assumed or built by this harness.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest


def pin(path):
    path = Path(path).resolve(strict=True)
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": value.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    profile = json.loads(args.profile.read_text())
    chain = json.loads(args.tools.read_text())
    target = next(row for row in profile["targets"] if row["id"] == args.target_id)
    impl = profile["implementation"]
    tools = chain["tools"]
    for name in ["olangc", "ocorec", "llvm_library", "capture_verifier"]:
        assert name in tools, "missing independently pinned tool: " + name
    for row in tools.values():
        assert all(pin(row["path"])[k] == v for k, v in row.items()), "tool differs from explicit pin"
    recipe = pin(impl["recipe"]["path"])
    assert all(recipe[k] == v for k, v in impl["recipe"].items())
    assert pin(Path(tools["olangc"]["path"]).parent / "ocorec")["sha256"] == tools["ocorec"]["sha256"]
    environment = dict(os.environ, **chain["environment"])
    record = {"schema": "ocore-original-source-provider-staging-regression-v1", "stage": "running",
              "scope": "fresh original source capture/import/verification staging with missing providers; no runtime or complete-artifact qualification",
              "started_epoch": time.time(), "profile": pin(args.profile), "toolchain": pin(args.tools),
              "tools_before": {name: pin(row["path"]) for name, row in tools.items()},
              "harness": pin(__file__), "python": pin(sys.executable), "recipe": recipe,
              "expected_method_names": ["test_all_original_source_units_stage_before_provider_closure"],
              "expected_method_count": 1, "commands": [], "runtime_accepted": False,
              "native_execution_qualified": False, "complete_olangc_artifact": False,
              "effective_environment": {name: environment.get(name) for name in ["PATH", "LD_LIBRARY_PATH", "LANG", "LC_ALL"]},
              "environment_sha256": hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()}
    def save():
        (args.output / "report.json").write_text(json.dumps(record, indent=2) + "\n")
    def command(argv, label):
        row = {"argv": list(map(str, argv)), "started_epoch": time.time()}
        record["commands"].append(row); save()
        stdout, stderr = args.output / (label + ".stdout"), args.output / (label + ".stderr")
        with stdout.open("wb") as out, stderr.open("wb") as err:
            child = subprocess.run(row["argv"], cwd=args.output, env=environment, stdout=out, stderr=err)
        row.update(exit_code=child.returncode, stdout=pin(stdout), stderr=pin(stderr), finished_epoch=time.time()); save()
        return child.returncode
    def source_identity():
        source = Path(impl["source_checkout"])
        head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        changes = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=all"], text=True)
        assert head == impl["revision"] and not changes, "original source is not the pinned clean checkout"
        return {"path": str(source.resolve()), "revision": head}
    record["source_before"] = source_identity(); save()
    class OriginalSourceProviderStaging(unittest.TestCase):
        def test_all_original_source_units_stage_before_provider_closure(self):
            product = args.output / "source-product"
            argv = [tools["olangc"]["path"], recipe["path"], "--native-runtime", "--native-runtime-source", impl["source_checkout"],
                    "--native-runtime-output", "ir", "--native-isa", target["target"], "--native-runtime-unit-inventory", target["unit_inventory"],
                    "--native-runtime-jobs", str(target["jobs"]), "--llvm-library", tools["llvm_library"]["path"],
                    "--llvm-sha256", tools["llvm_library"]["sha256"], "-o", product]
            for flag, role in target["frontend_tools"].items(): argv += [flag, tools[role]["path"]]
            for flag, value in target["import_profiles"].items(): argv += [flag, value]
            self.assertEqual(command(argv, "source-pipeline"), 1, "the missing original providers must remain an intended failure")
            capture_path = product / "capture/report.json"; coverage_path = product / "lowered/coverage.json"
            capture = json.loads(capture_path.read_text()); coverage = json.loads(coverage_path.read_text())
            self.assertIs(capture["capture_complete"], True); self.assertEqual(capture["issues"], [])
            self.assertIs(coverage["capture_complete"], True)
            self.assertIs(coverage["source_lowering_preflight_complete"], True)
            self.assertIs(coverage["provider_admission_complete"], False)
            self.assertIn("declared source dependency lacks a verified included native module-set", coverage["provider_admission_issue"])
            self.assertEqual(coverage["declared_dependencies"], capture["dependencies"])
            for name in ["module_set_complete", "artifact_complete", "native_execution_qualified", "runtime_complete", "native_module_dependency_closure_complete"]:
                self.assertIs(coverage[name], False, name)
            self.assertIsNone(coverage["module_set_artifact"])
            self.assertFalse((product / "lowered/runtime.native-ir.json").exists())
            selected = capture["lowering_unit_ids"]
            self.assertTrue(selected); self.assertEqual(len(set(selected)), len(selected))
            rows = {row["id"]: row for row in coverage["units"] if row.get("required_for_lowering") is True}
            self.assertEqual(set(rows), set(selected))
            self.assertEqual(coverage["required_lowering_unit_count"], len(selected))
            self.assertEqual(coverage["lowered_unit_count"], len(selected)); self.assertIs(coverage["unit_lowering_complete"], True)
            verification = args.output / "independent-capture.json"
            self.assertEqual(command([sys.executable, "-I", tools["capture_verifier"]["path"], "verify-report", capture_path, "--receipt", verification], "capture-replay"), 0)
            proof = json.loads(verification.read_text())
            self.assertIs(proof["verified"], True); self.assertEqual(proof["report"], pin(capture_path))
            self.assertEqual(proof["capture_worker_sha256"], tools["capture_verifier"]["sha256"])
            self.assertEqual(proof["lowering_unit_ids"], selected)
            modules = []
            for index, identity in enumerate(selected):
                row = rows[identity]; self.assertIs(row["lowered"], True); self.assertIs(row["verified"], True)
                module = pin(row["module"]["path"]); self.assertEqual(module["sha256"], row["module"]["sha256"])
                native = json.loads(Path(module["path"]).read_text()); self.assertEqual(native["target"], target["native_target"])
                receipt = args.output / ("independent-native-" + str(index) + ".json")
                self.assertEqual(command([tools["ocorec"]["path"], module["path"], "--input-kind", "native-ir", "--verify-native", "--receipt", receipt], "verify-native-" + str(index)), 0)
                checked = json.loads(receipt.read_text()); self.assertIs(checked["verified"], True); self.assertEqual(checked["module_sha256"], module["sha256"])
                modules.append({"id": identity, "module": module, "independent_verification": pin(receipt)})
            record.update(capture=pin(capture_path), coverage=pin(coverage_path), independent_capture=pin(verification), modules=modules,
                          actual_required_unit_count=len(selected), source_staging_complete=True, provider_closure_complete=False)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(OriginalSourceProviderStaging)
    assert suite.countTestCases() == 1
    with (args.output / "tests.log").open("w") as log:
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    record.update(tests_run=result.testsRun, skips=len(result.skipped), errors=len(result.errors), failures=len(result.failures),
                  source_after=source_identity(), tools_after={name: pin(row["path"]) for name, row in tools.items()},
                  harness_after=pin(__file__), finished_epoch=time.time(), stage="complete")
    record["source_tools_stable"] = record["source_before"] == record["source_after"] and record["tools_before"] == record["tools_after"] and record["harness"] == record["harness_after"]
    record["passed"] = result.wasSuccessful() and result.testsRun == 1 and not result.skipped and record["source_tools_stable"]
    save(); print(json.dumps({"passed": record["passed"], "report": pin(args.output / "report.json"), "runtime_accepted": False}))
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
