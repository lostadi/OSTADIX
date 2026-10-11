#!/usr/bin/env python3
"""Independent inventory checks; no source builds or downloaded code execute."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("rust_inventory", Path(__file__).with_name("build_inventory.py"))
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source, self.build, self.capture = [self.root / name for name in ("source", "build", "capture")]
        self.source.mkdir()
        self.build.mkdir()
        (self.capture / "events").mkdir(parents=True)
        (self.source / "x.py").write_text("raise RuntimeError('must never execute source code')\n")
        (self.source / "Cargo.lock").write_text("version=4\n")
        (self.source / "Cargo.toml").write_text('[package]\nname="arbitrary_runtime"\nversion="1.0.0"\n')
        (self.build / "bootstrap.toml").write_text('[build]\nextended=true\n[llvm]\ndownload-ci-llvm=false\n')
        self.write(self.capture / "session.json", {
            "source": {"path": str(self.source), "revision": "a" * 40, "submodules": []},
            "build_steps": [{"name": "entire-source-build", "argv": ["x.py", "build", "--stage", "2", "arbitrary_runtime"],
                             "cwd": str(self.source), "started_ns": 1, "finished_ns": 100, "exit_code": 0}],
            "recipe": {"coverage": {"required_outputs": ["final/runtime"]}}})

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n")

    def file(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return {"path": str(path), "bytes": len(data), "sha256": inventory.digest(data)}

    def event(self, id_, *, target="riscv64-unknown-linux-gnu", stage="1", code=0, suffix="-aaa"):
        source = self.file("source/src/lib.rs", b"pub fn original() {}\n")
        ir_a = self.file(f"capture/units/{id_}/original.0.ll", b"original full first CGU\n")
        ir_b = self.file(f"capture/units/{id_}/original.1.ll", b"original full second CGU\n")
        output = self.file(f"build/{target}/release/libarbitrary_runtime{suffix}.rlib", b"opaque real crate output")
        output["archive_members"] = [{"index": 0, "member": "same.o", "sha256": "0" * 64, "bytes": 1},
                                     {"index": 1, "member": "same.o", "sha256": "1" * 64, "bytes": 1}]
        event = {"id": id_, "kind": "rustc", "state": "finished", "exit_code": code,
                 "compiler": "/tools/original-rustc", "cwd": str(self.source),
                 "argv": ["--crate-name", "arbitrary_runtime", "src/lib.rs", "--crate-type=rlib",
                          "--target=" + target, "-C", "codegen-units=2", "-Cmetadata=identity",
                          "-Cextra-filename=" + suffix, "--cfg", 'feature="one"', "-Copt-level=3"],
                 "build_environment": {"RUSTC_STAGE": stage, "CARGO_MANIFEST_DIR": str(self.source)},
                 "sources": [source], "outputs": [output], "capture_errors": [],
                 "build_step": {"name": "entire-source-build", "index": 0},
                 "units": [{"id": id_ + ":0", "kind": "rustc", "source": source, "ir": ir_a, "dependencies": []},
                           {"id": id_ + ":1", "kind": "rustc", "source": source, "ir": ir_b, "dependencies": []}],
                 "link_inputs": {"dependency_closure_complete": False, "files": []}}
        event["expanded_argv"] = event["argv"]
        self.write(self.capture / "events" / (id_ + ".json"), event)
        return event

    def run_inventory(self, **kwargs):
        return inventory.inventory(self.source, self.build, self.capture, self.root / "evidence", **kwargs)

    def test_attempts_stages_targets_cgus_and_duplicate_archive_member_names_are_retained(self):
        first = self.event("first", code=1)
        second = self.event("second")
        self.event("different_stage", stage="2", suffix="-bbb")
        self.event("different_target", target="aarch64-unknown-linux-gnu")
        result = self.run_inventory()
        self.assertEqual(len(result["invocations"]), 4)
        self.assertEqual(len(result["units"]), 8)
        self.assertEqual(len(result["outputs"]), 4)
        group = next(group for group in result["attempt_groups"].values() if "first" in group)
        self.assertEqual(group, ["first", "second"])
        self.assertEqual(result["compiler_stage_environment_values_observed"], ["1", "2"])
        self.assertEqual(result["outputs"][0]["artifact"]["archive_members"], first["outputs"][0]["archive_members"])
        self.assertEqual({u["cgu_output_name"] for u in result["units"]}, {"original.0.ll", "original.1.ll"})
        self.assertTrue(all(u["cgu_to_output_member_mapping"] == "not_proven" for u in result["units"]))
        self.assertEqual(result["invocations"][1]["rust"]["cgu_count_requested"], ["2"])
        self.assertEqual(result["invocations"][1]["rust"]["features"], ["one"])
        self.assertFalse(result["complete"])

    def test_every_journal_is_snapshotted_and_original_corrupt_evidence_is_unchanged(self):
        self.event("real")
        broken = self.capture / "events/broken.json"
        broken.write_bytes(b"")
        before = {path: path.read_bytes() for path in (self.capture / "events").glob("*.json")}
        result = self.run_inventory()
        self.assertEqual(result["summary"]["journals_at_snapshot"], 2)
        self.assertIn("malformed_metadata", result["summary"]["gap_kinds"])
        for artifact in result["metadata_inputs"]:
            data = Path(artifact["snapshot_path"]).read_bytes()
            self.assertEqual(inventory.digest(data), artifact["sha256"])
            self.assertEqual(len(data), artifact["bytes"])
        self.assertEqual(before, {path: path.read_bytes() for path in before})
        self.assertEqual(broken.read_bytes(), b"")

    def test_ir_source_and_output_hash_mismatches_cannot_become_successful_coverage(self):
        event = self.event("real")
        Path(event["units"][0]["ir"]["path"]).write_bytes(b"")
        Path(event["sources"][0]["path"]).write_bytes(b"changed source\n")
        Path(event["outputs"][0]["path"]).write_bytes(b"wrong output")
        result = self.run_inventory()
        self.assertEqual(result["units"][0]["current"]["ir"]["status"], "mismatch")
        self.assertEqual(result["units"][0]["current"]["source"]["status"], "mismatch")
        self.assertEqual(result["outputs"][0]["current"]["status"], "mismatch")
        self.assertIn("output_artifact_integrity", result["summary"]["gap_kinds"])
        self.assertFalse(result["source_production_inventory_complete"])

    def test_binary_and_generated_dependencies_keep_every_use_without_guessing_link_selection(self):
        event = self.event("real")
        binary = self.file("outside/libnative.so.6", b"prebuilt implementation")
        generated = self.file("build/generated/data.rs", b"generated input")
        event["units"][0]["dependencies"] = [binary, generated, binary]
        event["units"][1]["dependencies"] = [binary]
        self.write(self.capture / "events/real.json", event)
        result = self.run_inventory()
        self.assertEqual(len(result["dependency_artifacts"]), 2)
        actual = next(row for row in result["dependency_artifacts"] if row["artifact"] == binary)
        self.assertEqual(len(actual["uses"]), 3)
        self.assertTrue(actual["binary_input"])
        self.assertEqual(actual["same_path_content_producer_ids"], [])
        self.assertIn("binary_dependency_source_production_unproven", result["summary"]["gap_kinds"])
        self.assertIn("generated_input_production_unproven", result["summary"]["gap_kinds"])
        self.assertFalse(result["runtime_output_membership_complete"])
        self.assertFalse(result["dependency_closure_complete"])

    def test_cargo_graph_preserves_distinct_profiles_features_target_kinds_and_edges(self):
        self.event("real")
        unit = {"pkg_id": "opaque-package", "target": {"name": "arbitrary_runtime", "src_path": str(self.source / "src/lib.rs"),
               "kind": ["lib"], "crate_types": ["lib"]}, "profile": {"name": "release", "codegen_units": 10000},
               "platform": "riscv64-unknown-linux-gnu", "mode": "build", "features": ["one"], "dependencies": []}
        altered = dict(unit, profile={"name": "dev", "codegen_units": 1}, features=["two"],
                       platform=None, mode="run-custom-build", dependencies=[{"index": 0, "extern_crate_name": "alias"}])
        graph = self.root / "units.json"
        self.write(graph, {"version": 1, "units": [unit, altered], "roots": [1]})
        result = self.run_inventory(cargo_graphs=[graph])
        actions = result["configured_actions"]
        self.assertEqual(len(actions), 2)
        self.assertNotEqual(actions[0]["id"], actions[1]["id"])
        self.assertEqual(actions[0]["unit"]["profile"]["codegen_units"], 10000)
        self.assertEqual(actions[1]["dependency_ids"], [actions[0]["id"]])
        self.assertTrue(actions[1]["is_root"])
        self.assertEqual(actions[1]["unit"]["features"], ["two"])
        self.assertEqual(actions[1]["configured_profile_matching"], "not_proven_from_source_and_crate_name")
        self.assertIn("cargo_configured_action_not_proven", result["summary"]["gap_kinds"])

    def test_invalid_graph_edges_and_unknown_versions_are_explicit_gaps(self):
        path = self.root / "bad-graph.json"
        self.write(path, {"version": 1, "units": [{"dependencies": [{"index": True}, {"index": -1}, {"index": 2}]}], "roots": [4]})
        result = self.run_inventory(cargo_graphs=[path])
        self.assertEqual(result["summary"]["gap_kinds"]["invalid_cargo_graph_edge"], 3)
        self.assertIn("invalid_cargo_graph_root", result["summary"]["gap_kinds"])
        self.write(path, {"version": 100, "units": []})
        result = self.run_inventory(cargo_graphs=[path])
        self.assertIn("unsupported_cargo_unit_graph", result["summary"]["gap_kinds"])

    def test_absent_optional_graph_inputs_produce_gaps_and_preserve_observed_units(self):
        self.event("real")
        result = self.run_inventory(cargo_graphs=[self.root / "no-cargo.json"],
                                    native_graphs=[self.root / "no-native.json"])
        self.assertEqual(result["summary"]["gap_kinds"]["unavailable_metadata"], 2)
        self.assertEqual(result["summary"]["captured_units"], 2)
        self.assertEqual(result["configured_actions"], [])
        self.assertFalse(result["complete"])

    def test_ninja_escaped_paths_all_edge_classes_and_scope_are_not_shell_tokens(self):
        evidence = inventory.Evidence(self.root / "evidence")
        ninja = self.build / "build.ninja"
        ninja.write_text("base = generated\ninclude rules.ninja\nsubninja child.ninja\n"
                         "build $base/a$ b.o | optional$:.o: compile source$ file.cpp | implicit.h || order.stamp |@ validate.stamp\n"
                         "  command = $(touch MUST_NOT_EXECUTE)\n")
        (self.build / "rules.ninja").write_text("rule compile\n  command = compiler $in -o $out\n")
        (self.build / "child.ninja").write_text("base = child\nbuild $base/generated.rs: generate seed.txt\n")
        actions = inventory.ninja_graph(ninja, evidence)
        self.assertEqual(len(actions), 2)
        self.assertEqual(actions[0]["outputs"]["explicit"], [str(self.build / "child/generated.rs")])
        self.assertEqual(actions[1]["outputs"]["explicit"], [str(self.build / "generated/a b.o")])
        self.assertEqual(actions[1]["outputs"]["implicit"], [str(self.build / "optional:.o")])
        self.assertEqual(actions[1]["inputs"]["explicit"], [str(self.build / "source file.cpp")])
        self.assertEqual(actions[1]["inputs"]["validation"], [str(self.build / "validate.stamp")])
        self.assertEqual(actions[1]["inputs"]["order_only"], [str(self.build / "order.stamp")])
        self.assertEqual(actions[1]["inputs"]["implicit"], [str(self.build / "implicit.h")])
        self.assertFalse((self.build / "MUST_NOT_EXECUTE").exists())
        self.assertFalse(evidence.gaps)

    def test_ninja_unresolved_variables_cycles_and_unknown_records_cannot_disappear(self):
        ninja = self.build / "build.ninja"
        ninja.write_text("include build.ninja\nbuild $missing/out: compile in.c\nunknown directive\n")
        evidence = inventory.Evidence(self.root / "evidence")
        self.assertEqual(inventory.ninja_graph(ninja, evidence), [])
        self.assertEqual({gap["kind"] for gap in evidence.gaps}, {"ninja_include_cycle", "unparsed_ninja_record"})
        self.assertEqual(Path(evidence.inputs[0]["snapshot_path"]).read_bytes(), ninja.read_bytes())

    def test_ninja_v5_v7_logs_retain_repeated_outputs_and_opaque_versioned_hashes(self):
        for version in [5, 7]:
            with self.subTest(version=version):
                log = self.build / ".ninja_log"
                log.write_text(f"# ninja log v{version}\n1\t3\t7\tobj.o\tabcdef\n"
                               "4\t8\t9\tobj.o\t0123456789abcdef\n"
                               "9\t10\t11\tbad.o\t10000000000000000\n")
                evidence = inventory.Evidence(self.root / f"evidence-v{version}")
                rows = inventory.ninja_log(log, evidence)
                self.assertEqual(len(rows), 2)
                self.assertEqual(rows[0]["output"], rows[1]["output"])
                self.assertNotEqual(rows[0]["id"], rows[1]["id"])
                self.assertEqual(rows[0]["log_version"], version)
                self.assertEqual(rows[1]["command_hash"], "0123456789abcdef")
                self.assertFalse(rows[0]["frontend_capture_qualified"])
                self.assertEqual([gap["kind"] for gap in evidence.gaps], ["malformed_ninja_execution_record"])
        log.write_text("# ninja log v999\n1\t2\t3\tobj.o\ta\n")
        evidence = inventory.Evidence(self.root / "unknown-evidence")
        self.assertEqual(inventory.ninja_log(log, evidence), [])
        self.assertEqual(evidence.gaps[0]["kind"], "unsupported_ninja_log_version")

    def test_dependency_tracking_comparison_removes_only_auxiliary_flags(self):
        original = ["-MD", "-MT", "obj.o", "-MFdeps.d", "-MQ", "obj$ .o", "-MP",
                    "-c", "source.cpp", "-o", "obj.o", "-Iinclude", "-DVALUE=1", "-O3", "-include", "forced.h"]
        args, removed = inventory.dependency_tracking_arguments(original)
        self.assertEqual(args, ["-c", "source.cpp", "-o", "obj.o", "-Iinclude", "-DVALUE=1", "-O3", "-include", "forced.h"])
        self.assertEqual([row["arguments"] for row in removed],
                         [["-MD"], ["-MT", "obj.o"], ["-MFdeps.d"], ["-MQ", "obj$ .o"], ["-MP"]])
        self.assertEqual(original[0], "-MD")
        for significant in [["-M"], ["-MM"], ["-MG"], ["-MF"], ["-MT"], ["-MQ"], ["-Wp,-MD,deps.d"],
                            ["-Xclang", "-MD"], ["-Xpreprocessor", "-MD"], ["-include", "-MD"],
                            ["-o", "-MD"], ["--", "-MD"]]:
            with self.subTest(significant=significant):
                kept, _ = inventory.dependency_tracking_arguments(significant)
                self.assertEqual(kept, significant)

    def test_native_depfile_comparison_preserves_semantic_flag_differences_and_occurrences(self):
        source = self.file("source/original.cpp", b"original source")
        obj = self.file("build/original.o", b"native object")
        args = ["-O3", "-Iinclude", "-DVALUE=1", "-include", "forced.h", "-c", source["path"], "-o", obj["path"]]
        event = {"id": "same-id", "kind": "clang", "state": "finished", "exit_code": 0, "cwd": str(self.build),
                 "expanded_argv": ["-MD", "-MT", obj["path"], "-MF", obj["path"] + ".d", *args],
                 "sources": [source], "units": [], "outputs": [obj], "capture_errors": []}
        self.write(self.capture / "events/first.json", event)
        different = dict(event, expanded_argv=[*event["expanded_argv"], "-DOTHER=1"])
        self.write(self.capture / "events/second.json", different)
        graph = self.root / "compile_commands.json"
        self.write(graph, [{"directory": str(self.build), "file": source["path"], "arguments": ["clang", *args]},
                          {"directory": str(self.build), "file": source["path"], "arguments": ["clang", *args, "-O0"]}])
        result = self.run_inventory(native_graphs=[graph])
        first, second = result["configured_actions"]
        self.assertEqual(first["exact_argv_attempt_ids"], [])
        self.assertEqual(len(first["candidate_occurrence_ids"]), 2)
        self.assertEqual(len(set(first["candidate_occurrence_ids"])), 2)
        self.assertEqual(len(first["dependency_tracking_comparison"]), 1)
        self.assertEqual(first["dependency_tracking_comparison"][0]["action_id"], "same-id")
        self.assertEqual(first["dependency_tracking_comparison"][0]["removed_configured_arguments"], [])
        self.assertEqual(second["dependency_tracking_comparison"], [])
        self.assertFalse(first["source_capture_admission_qualified"])
        self.assertIn("duplicate_capture_action_id", result["summary"]["gap_kinds"])
        self.assertEqual(result["summary"]["gap_kinds"]["native_configured_action_unobserved_or_argv_unmatched"], 1)

    def test_raw_record_references_and_tool_digest_resolve_to_retained_bytes(self):
        self.event("real")
        result = self.run_inventory()
        artifact = next(item for item in result["metadata_inputs"]
                        if item["sha256"] == result["units"][0]["record"]["artifact_sha256"])
        raw = json.loads(Path(artifact["snapshot_path"]).read_bytes())
        self.assertEqual(raw["units"][0]["id"], result["units"][0]["id"])
        self.assertNotIn("artifact", result["units"][0]["record"])
        self.assertEqual(inventory.file_digest(Path(result["inventory_tool"]["snapshot_path"])),
                         result["inventory_tool"]["sha256"])

    def test_native_plan_missing_assembly_and_exact_output_argv_matching_are_retained(self):
        source = self.file("source/original.cpp", b"original source")
        obj = self.file("build/original.o", b"native object")
        event = {"id": "native", "kind": "clang", "state": "finished", "exit_code": 0, "cwd": str(self.build),
                 "expanded_argv": ["-c", source["path"], "-o", obj["path"]], "sources": [source],
                 "units": [], "outputs": [obj], "capture_errors": []}
        self.write(self.capture / "events/native.json", event)
        graph = self.root / "compile_commands.json"
        self.write(graph, [{"directory": str(self.build), "file": source["path"], "arguments": ["original-clang", *event["expanded_argv"]]},
                          {"directory": str(self.build), "file": str(self.source / "asm.S"), "arguments": ["clang", "asm.S", "-c"]}])
        result = self.run_inventory(native_graphs=[graph])
        self.assertEqual(len(result["configured_actions"]), 2)
        self.assertEqual(result["configured_actions"][0]["exact_argv_attempt_ids"], ["native"])
        self.assertTrue(result["configured_actions"][1]["assembly"])
        self.assertIn("assembly_requires_explicit_importer", result["summary"]["gap_kinds"])

    def test_manifest_graph_has_no_fixed_crate_allowlist_and_does_not_enable_optional_features(self):
        (self.source / "Cargo.toml").write_text('[workspace]\nmembers=["arbitrary/*"]\n'
                                              '[workspace.dependencies]\nshared={path="outside"}\n')
        for name in ["one", "two"]:
            path = self.source / "arbitrary" / name / "Cargo.toml"
            path.parent.mkdir(parents=True)
            path.write_text('[package]\nname="' + name + '"\nversion="1.0.0"\n[features]\nexperimental=[]\n'
                            '[target.\'cfg(any())\'.dependencies]\noptional={path="../../outside",optional=true}\n')
        (self.source / "outside").mkdir()
        (self.source / "outside/Cargo.toml").write_text('[package]\nname="outside"\nversion="1.0.0"\n')
        result = self.run_inventory()
        rows = result["source_manifest_superset"]
        self.assertEqual(len(rows), 4)
        self.assertEqual({row["package"]["name"] for row in rows if row["package"]}, {"one", "two", "outside"})
        self.assertTrue(all(row["configured_or_built"] is False for row in rows))
        self.assertEqual(next(row for row in rows if row["package"] and row["package"]["name"] == "one")["features"], {"experimental": []})

    def test_ninja_graph_over_five_thousand_actions_has_no_silent_size_ceiling(self):
        path = self.build / "large.ninja"
        path.write_text("rule compile\n  command = false\n" + "".join(
            f"build output/{i}.o: compile input/{i}.cpp\n" for i in range(5001)))
        evidence = inventory.Evidence(self.root / "evidence")
        actions = inventory.ninja_graph(path, evidence)
        self.assertEqual(len(actions), 5001)
        self.assertEqual(len({action["id"] for action in actions}), 5001)
        self.assertFalse(evidence.gaps)

    def test_stat_only_and_all_manifest_successes_never_establish_runtime_or_provider_closure(self):
        self.event("real")
        result = self.run_inventory(verify_artifacts=False)
        self.assertEqual(result["units"][0]["current"]["ir"]["status"], "stat_only")
        for key in ["complete", "source_production_inventory_complete", "runtime_output_membership_complete",
                    "dependency_closure_complete", "native_execution_qualified", "runtime_complete"]:
            self.assertIs(result[key], False, key)
        self.assertIn("bootstrap_stage_graph_coverage_unproven", result["summary"]["gap_kinds"])
        self.assertIn("ordered_provider_closure_not_qualified", result["summary"]["gap_kinds"])


if __name__ == "__main__":
    unittest.main()
