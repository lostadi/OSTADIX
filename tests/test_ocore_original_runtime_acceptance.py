"""Infrastructure controls; passing these does not qualify any original runtime."""

import copy
import contextlib
import importlib.util
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest


PATH = Path(__file__).resolve().parents[1] / "tools/ocore-runtime/acceptance/check_runtime.py"
SPEC = importlib.util.spec_from_file_location("original_runtime_acceptance", PATH)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


def profile():
    return {"schema": acceptance.SCHEMA, "name": "infrastructure-control-only",
            "implementation": {"kind": "compiler", "upstream_url": "https://example.invalid/original.git", "revision": "1" * 40,
                               "source_checkout": "/original", "recipe": {"path": "/recipe.json", "sha256": "2" * 64}, "build_step": "original-build"},
            "requirements": {"delivery": "native", "resource_profile": "ostadix-kernel", "compiler_output_routing": True,
                             "jit_generation": False, "jit_publication": False, "jit_invalidation": False},
            "targets": [{"id": "required-real-target", "target": "riscv64-unknown-none", "native_target": None, "jobs": 1,
                         "unit_inventory": "unit-inventory.json", "frontend_tools": {}, "import_profiles": {}, "provider_profiles": [],
                         "programs": [{"name": "original", "kind": "program", "required_units": ["body", "data"], "reference_output": "original", "upstream_targets": ["test-all"], "behavior_driver": None}]}]}


def captures():
    return {"capture_complete": True, "unit_roles_complete": True, "unclassified_unit_ids": [], "lowering_unit_ids": ["a", "b"],
            "units": [{"id": "a"}, {"id": "b"}], "required_units": [{"id": "body", "captured_unit_ids": ["a"]}, {"id": "data", "captured_unit_ids": ["b"]}]}


class OriginalRuntimeAcceptanceControls(unittest.TestCase):
    def test_original_recipe_required_rule_cannot_be_removed_from_capture(self):
        original = {"coverage": {"required_units": [{"id": "body"}, {"id": "cold"}]}}
        forged = {"required_units": [{"id": "body", "captured_unit_ids": ["body"]}]}
        with self.assertRaisesRegex(acceptance.Unmet, "ORIGINAL recipe"):
            acceptance.check_recipe_partition(original, forged)

    def test_required_rule_source_cannot_be_substituted(self):
        original = {"coverage": {"required_units": [{"id": "body", "source": "body.c"}]}}
        forged = {"required_units": [{"id": "body", "source": "rewrite.c", "captured_unit_ids": ["body"]}]}
        with self.assertRaisesRegex(acceptance.Unmet, "rule changed"):
            acceptance.check_recipe_partition(original, forged)

    def test_unverified_evidence_is_never_a_green_stage(self):
        class Harness:
            record = {}
            def save(self): pass
        harness = Harness(); target = {"stages": []}
        def unsupported(): raise acceptance.Unverified("not independently reconstructed")
        row = acceptance.Runner.stage(harness, target, "capture", unsupported)
        self.assertEqual(row["status"], "UNVERIFIED")

    def test_profile_configuration_is_not_qualification(self):
        self.assertEqual(acceptance.validate_profile(profile())["name"], "infrastructure-control-only")
        with self.assertRaisesRegex(acceptance.Unmet, "complete runtime artifact"):
            acceptance.complete_artifact_gate({"artifact_complete": False}, {"artifact_complete": False})

    def test_required_zero_target_matrix_is_not_a_pass(self):
        value = profile(); value["targets"] = []
        with self.assertRaisesRegex(acceptance.Unmet, "cannot be empty"):
            acceptance.validate_profile(value)

    def test_tls_import_profile_preserves_the_declared_string(self):
        value = profile()
        declared = {"--tls-profile": "linux-elf-static-nonpreemptive-v1"}
        value["targets"][0]["import_profiles"] = declared.copy()
        self.assertEqual(acceptance.validate_profile(value)["targets"][0]["import_profiles"], declared)

    def test_unknown_or_malformed_import_profiles_are_rejected(self):
        invalid = [[], None, {"--tls-profil": "x"}, {"--tls-profile=x": "x"},
                   {"--tls-profile": "x", "--unknown-profile": "x"}]
        invalid += [{"--tls-profile": value} for value in [None, 1, True, [], {}]]
        for declaration in invalid:
            with self.subTest(declaration=declaration):
                value = profile(); value["targets"][0]["import_profiles"] = declaration
                with self.assertRaises(acceptance.Unmet):
                    acceptance.validate_profile(value)

    def test_compiler_output_routing_cannot_be_silently_disabled(self):
        value = profile(); value["requirements"]["compiler_output_routing"] = False
        with self.assertRaisesRegex(acceptance.Unmet, "cannot be disabled"):
            acceptance.validate_profile(value)

    def test_all_jit_paths_are_required_for_jit_engine(self):
        value = profile(); value["implementation"]["kind"] = "jit_engine"
        with self.assertRaisesRegex(acceptance.Unmet, "all generated-code gates"):
            acceptance.validate_profile(value)

    def test_supplied_runtime_executable_is_not_an_input_contract(self):
        value = profile(); value["supplied_runtime_executable"] = "/foreign/runtime"
        with self.assertRaisesRegex(acceptance.Unmet, "profile fields differ"):
            acceptance.validate_profile(value)

    def test_handwritten_runtime_and_implementation_ir_interpreter_modes_are_not_accepted(self):
        for mode in ["handwritten-runtime", "implementation-ir-interpreter"]:
            with self.subTest(mode=mode):
                value = profile(); value["implementation"]["kind"] = mode
                with self.assertRaisesRegex(acceptance.Unmet, "implementation role"):
                    acceptance.validate_profile(value)

    def test_original_required_units_cannot_be_silently_dropped(self):
        with self.assertRaisesRegex(acceptance.Unmet, "silently omits"):
            acceptance.check_selected_units(captures(), {"units": [{"id": "a"}]})

    def test_zero_imports_cannot_qualify_a_runtime(self):
        with self.assertRaisesRegex(acceptance.Unmet, "silently omits"):
            acceptance.check_selected_units(captures(), {"units": []})

    def test_duplicate_native_unit_cannot_replace_a_missing_unit(self):
        with self.assertRaisesRegex(acceptance.Unmet, "duplicate native"):
            acceptance.check_selected_units(captures(), {"units": [{"id": "a"}, {"id": "a"}]})

    def test_partial_original_capture_is_not_admitted(self):
        value = captures(); value["capture_complete"] = False
        with self.assertRaisesRegex(acceptance.Unmet, "capture/role inventory incomplete"):
            acceptance.check_selected_units(value, {"units": [{"id": "a"}, {"id": "b"}]})

    def test_program_graph_cannot_drop_data_or_initializer_unit(self):
        programs = copy.deepcopy(profile()["targets"][0]["programs"]); programs[0]["required_units"] = ["body"]
        with self.assertRaisesRegex(acceptance.Unmet, "drops required"):
            acceptance.check_program_graph(captures(), programs)

    def test_program_graph_is_not_complete_artifact_admission(self):
        proof = acceptance.check_program_graph(captures(), profile()["targets"][0]["programs"])
        self.assertEqual(proof["required_units_accounted"], 2)
        self.assertIs(proof["complete_olangc_artifact"], False)

    def test_target_abi_and_profiles_must_match_exactly(self):
        target = {"triple": "riscv64-unknown-linux-gnu", "abi": "lp64d", "data_layout": "original"}
        for field, bad in [("triple", "x86_64-unknown-linux-gnu"), ("abi", "lp64"), ("data_layout", "substituted")]:
            with self.subTest(field=field):
                altered = dict(target, **{field: bad})
                with self.assertRaisesRegex(acceptance.Unmet, "profile mismatch"):
                    acceptance.check_target({"target": altered}, target)

    def test_missing_actual_target_profile_is_red(self):
        with self.assertRaisesRegex(acceptance.Unmet, "not pinned"):
            acceptance.check_target({"target": {}}, None)

    def test_forged_complete_flags_do_not_admit_supplied_manifests_or_manual_links(self):
        with self.assertRaisesRegex(acceptance.Unmet, "public olangc whole-runtime artifact validator"):
            acceptance.complete_artifact_gate({"artifact_complete": True}, {"artifact_complete": True})


    def test_recipe_floor_allows_exact_finalized_inventory_additions(self):
        original = {"coverage": {"required_units": [{"id": "body", "source": "body.c"}]}}
        finalized = {"schema": "ocore-runtime-unit-inventory-v1", "complete": True,
                     "units": [{"id": "inventory:cold", "source": "cold.c"}]}
        capture = {"required_units": [{"id": "body", "source": "body.c", "captured_unit_ids": ["a"]},
                                      {"id": "inventory:cold", "source": "cold.c", "captured_unit_ids": ["b"]}]}
        self.assertEqual(set(acceptance.check_recipe_partition(original, capture, finalized)), {"body", "inventory:cold"})

    def test_finalized_inventory_addition_cannot_be_omitted_from_capture(self):
        original = {"coverage": {"required_units": [{"id": "body"}]}}
        finalized = {"schema": "ocore-runtime-unit-inventory-v1", "complete": True,
                     "units": [{"id": "inventory:cold"}]}
        with self.assertRaisesRegex(acceptance.Unmet, "missing=.*inventory:cold"):
            acceptance.check_recipe_partition(original, {"required_units": [{"id": "body", "captured_unit_ids": ["a"]}]}, finalized)

    def test_capture_cannot_invent_rules_outside_finalized_inventory(self):
        original = {"coverage": {"required_units": [{"id": "body"}]}}
        finalized = {"schema": "ocore-runtime-unit-inventory-v1", "complete": True, "units": [{"id": "inventory:cold"}]}
        capture = {"required_units": [{"id": name, "captured_unit_ids": [name]} for name in ["body", "inventory:cold", "invented"]]}
        with self.assertRaisesRegex(acceptance.Unmet, "added=.*invented"):
            acceptance.check_recipe_partition(original, capture, finalized)

    def _forged_cli(self, pinned_worker, partial_valid=False):
        # Exact retained adversarial producer: a real child process forges flags
        # while omitting a required original unit. This is not a runtime fixture.
        producer = """#!/usr/bin/python3
import pathlib,sys,json,hashlib
out=pathlib.Path(sys.argv[sys.argv.index('-o')+1]);(out/'capture').mkdir(parents=True);(out/'lowered').mkdir()
sibling=pathlib.Path(__file__).parent/'ocorec'
compiler_sha=hashlib.sha256(sibling.read_bytes()).hexdigest()
capture={'capture_complete':True,'unit_roles_complete':True,'unclassified_unit_ids':[],'lowering_unit_ids':['body'],'units':[{'id':'body'}],'required_units':[{'id':'body','captured_unit_ids':['body']}]}
coverage={'compiler_sha256':compiler_sha,'units':[{'id':'body','verified':False,'lowered':False,'failure':'no import ever performed'}],'native_module_dependency_closure_complete':True,'symbol_closure_complete':True,'artifact_complete':True}
for name,value in [('capture/report.json',capture),('lowered/coverage.json',coverage),('source-recipe.json',{'success':True,'capture_complete':True,'artifact_complete':True})]: (out/name).write_text(json.dumps(value))
"""
        self.assertEqual(hashlib.sha256(producer.encode()).hexdigest(), "5e7909da81b98e9011415f9c25ea58fcd94e77d40c15d6ab03e8d6b06064a131")
        retained = os.environ.get("OCORE_ACCEPTANCE_CONTROL_OUTPUT")
        if retained:
            Path(retained).mkdir(parents=True, exist_ok=True)
            context = contextlib.nullcontext(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=retained))
        else:
            context = tempfile.TemporaryDirectory(prefix="ocore-forged-receipt-control-")
        with context as temporary:
            root = Path(temporary); source = root / "synthetic-original"; source.mkdir()
            (source / "body.c").write_text("int body(void) { return 1; }\n")
            (source / "cold.c").write_text("int original_cold_initializer = 42;\n")
            def git(*args):
                return subprocess.check_output(["git", "-C", str(source), *args], text=True, stderr=subprocess.PIPE).strip()
            git("init", "--quiet"); git("add", "body.c", "cold.c")
            git("-c", "user.name=Lee Daghlar Ostadi", "-c", "user.email=ostadi.lee@gmail.com", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "Synthetic acceptance regression fixture only")
            git("remote", "add", "origin", "https://example.invalid/original.git")
            revision = git("rev-parse", "HEAD")
            recipe = {"schema": "ocore-runtime-recipe-v1", "name": "adversarial-original-fixture",
                      "source": {"url": "https://example.invalid/original.git", "revision": revision},
                      "commands": [{"name": "original-build", "argv": ["never-executed-build"]}],
                      "coverage": {"require_full_unit_inventory": True, "required_units": [{"id": n, "kind": "clang", "source": n + ".c"} for n in ["body", "cold"]]}}
            recipe_path = root / "recipe.json"; recipe_path.write_text(json.dumps(recipe))
            producer_path = root / "olangc"; producer_path.write_text(producer); producer_path.chmod(0o700)
            core = root / "ocorec"; core.write_text("#!/usr/bin/python3\nraise SystemExit('unexpected compiler invocation')\n"); core.chmod(0o700)
            library = root / "synthetic-parser"; library.write_bytes(b"unused synthetic parser pin")
            helper = root / "inventory_helper.py"; helper.write_text("# Synthetic negative control: no source inventory calls are permitted.\n")
            if partial_valid:
                # Explicit compiler/inventory test doubles make one candidate
                # GREEN. No real backend or whole-runtime proof is claimed.
                raw = root / "body.ll"; raw.write_text("define i32 @body() { ret i32 1 }\n")
                module = root / "body.native-ir.json"
                module.write_text(json.dumps({"target": {}, "provenance": {"input_sha256": acceptance.digest(raw)}}))
                recipe["coverage"]["required_units"] = recipe["coverage"]["required_units"][:1]
                recipe_path.write_text(json.dumps(recipe))
                helper.write_text("class Reader:\n def __init__(self,*args): pass\n def read(self,path): return {}\ndef check_inventory(*args): return {'synthetic_control_only':True}\n")
                core.write_text(
                    "#!/usr/bin/python3\nimport sys,pathlib,json,hashlib\na=sys.argv\n"
                    "if '--verify-native' in a:\n"
                    " p=pathlib.Path(a[a.index('--receipt')+1]);p.write_text(json.dumps({'verified':True,'module_sha256':hashlib.sha256(pathlib.Path(a[1]).read_bytes()).hexdigest()}))\n"
                    "elif '--emit' in a:\n"
                    " p=pathlib.Path(a[a.index('-o')+1])\n"
                    " if a[a.index('--emit')+1]=='mir':\n"
                    f"  p.write_bytes(pathlib.Path({str(module)!r}).read_bytes())\n"
                    " else: p.write_bytes(b'\\x7fELFsynthetic-control-only')\n"
                    "else: raise SystemExit(1)\n"
                )
                patch = "capture['units'][0]['ir']=" + repr(acceptance.artifact(raw)) + "\n"
                patch += "capture['required_units'][0].update(kind='clang',source='body.c')\n"
                patch += "coverage['units'][0].update(verified=True,lowered=True,module=" + repr(acceptance.artifact(module)) + ")\n"
                patch += "(out/'build').mkdir();(out/'build/unit-inventory.json').write_text(" + repr(json.dumps({"schema":"ocore-runtime-unit-inventory-v1","complete":True,"units":[{"id":"inventory:cold","kind":"clang","source":"cold.c"}]})) + ")\n"
                producer_path.write_text(producer.replace("for name,value in", patch + "for name,value in"))
            value = profile(); value["implementation"].update(source_checkout=str(source), revision=revision, recipe=acceptance.artifact(recipe_path))
            value["targets"][0]["programs"][0]["required_units"] = ["body"] if partial_valid else ["body", "cold"]
            if partial_valid: value["targets"][0]["native_target"] = {}
            profile_path = root / "profile.json"; profile_path.write_text(json.dumps(value))
            tools = {"olangc": acceptance.artifact(producer_path), "ocorec": acceptance.artifact(core), "llvm_library": acceptance.artifact(library), "inventory_helper": acceptance.artifact(helper)}
            if pinned_worker:
                tools["capture_verifier"] = acceptance.artifact(PATH.parents[3] / "scripts/ocore_runtime_capture.py")
            toolchain = root / "tools.json"; toolchain.write_text(json.dumps({"schema": acceptance.TOOL_SCHEMA, "tools": tools, "environment": {}}))
            output = root / "result"
            argv = [sys.executable, "-I", str(PATH), str(profile_path), "--tools", str(toolchain), "--output", str(output)]
            process = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            (root / "cli.stdout").write_text(process.stdout)
            (root / "cli.stderr").write_text(process.stderr)
            invocation = {"schema": "ocore-synthetic-acceptance-cli-control-v1", "method": self._testMethodName,
                          "argv": argv, "exit_code": process.returncode, "profile": acceptance.artifact(profile_path),
                          "toolchain": acceptance.artifact(toolchain), "stdout": acceptance.artifact(root / "cli.stdout"),
                          "stderr": acceptance.artifact(root / "cli.stderr"), "synthetic_control_only": True,
                          "runtime_accepted": False}
            if (output / "report.json").exists(): invocation["report"] = acceptance.artifact(output / "report.json")
            (root / "cli-invocation.json").write_text(json.dumps(invocation, indent=2) + "\n")
            self.assertEqual(process.returncode, 1, process.stderr)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["status"], "RED"); self.assertFalse(report["runtime_accepted"])
            self.assertTrue(report["tools_stable"])
            target = report["targets"][0]; stages = {row["name"]: row for row in target["stages"]}
            self.assertEqual(stages["pinned_source_and_recipe_identity"]["status"], "GREEN")
            self.assertIn("no build execution", stages["pinned_source_and_recipe_identity"]["scope"])
            self.assertEqual(stages["original_source_and_build"]["status"], "UNVERIFIED")
            self.assertIn("does not prove original build execution", stages["original_source_and_build"]["diagnostic"])
            for name in ["olangc_owned_source_pipeline", "independent_capture_admission", "complete_original_unit_selection", "original_program_graph", "original_provider_and_native_symbol_closure"]:
                self.assertNotEqual(stages[name]["status"], "GREEN", name)
            if partial_valid:
                self.assertEqual(stages["complete_original_unit_selection"]["status"], "UNVERIFIED")
                self.assertEqual([row["status"] for row in target["units"]], ["GREEN"])
                self.assertEqual(stages["all_original_units_independently_checked"]["status"], "UNVERIFIED")
            else:
                self.assertEqual(stages["complete_original_unit_selection"]["status"], "RED")
                self.assertTrue(any(row["id"] == "missing-original-rule:cold" for row in target["units"]))
            forbidden = [command for command in report["commands"] if command["argv"][0] == str(core)]
            if partial_valid:
                self.assertEqual(len(forbidden), 5, "only explicitly synthetic verify/canonicalize/import/verify/emit doubles were exercised")
                self.assertTrue(all(command["exit_code"] == 0 for command in forbidden))
                self.assertEqual(sum("--verify-native" in command["argv"] for command in forbidden), 2)
                emits = [command["argv"] for command in forbidden if "--emit" in command["argv"]]
                self.assertEqual([(argv[argv.index("--input-kind") + 1], argv[argv.index("--emit") + 1]) for argv in emits],
                                 [("native-ir", "mir"), ("llvm-ir", "mir"), ("native-ir", "obj")])
            else:
                self.assertEqual(forbidden, [], "no import/verify/emit command actually happened")
            replay = [command for command in report["commands"] if "verify-report" in command["argv"]]
            if pinned_worker:
                self.assertEqual(len(replay), 1); self.assertEqual(replay[0]["exit_code"], 1)
                self.assertEqual(stages["independent_capture_admission"]["status"], "RED")
                self.assertIn("capture verification requires ocore-runtime-capture-v1", Path(replay[0]["stderr"]["path"]).read_text())
            else:
                self.assertEqual(replay, [])
                self.assertEqual(stages["independent_capture_admission"]["status"], "UNVERIFIED")

    def test_actual_cli_source_identity_alone_never_proves_original_build_execution(self):
        self._forged_cli(False)

    def test_actual_cli_available_valid_unit_cannot_establish_unadmitted_full_inventory(self):
        self._forged_cli(False, partial_valid=True)

    def test_actual_cli_retained_forged_producer_never_admits_missing_cold_unit(self):
        self._forged_cli(False)

    def test_actual_cli_pinned_worker_reconstructs_and_rejects_forged_capture(self):
        self._forged_cli(True)


if __name__ == "__main__":
    unittest.main()
