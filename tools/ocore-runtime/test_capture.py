#!/usr/bin/env python3
"""Real frontend smoke tests and fail-closed capture boundary regressions."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ocore_runtime_capture.py"
SPEC = importlib.util.spec_from_file_location("ocore_runtime_capture", SCRIPT)
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


class ArgumentTests(unittest.TestCase):
    def test_clang_replay_preserves_frontend_options_and_separates_linking(self):
        cwd = Path("/tmp/build")
        source = cwd / "one.c"
        args = ["-O2", "-I", "/tmp/header dir", "-include", "forced.c", "-pthread",
                "-MD", "-MF", "native.d", "one.c", "old.o", "-Wl,--as-needed",
                "-L/usr/lib", "-lssl", "-o", "program"]
        replay = capture.clang_replay(args, source, [source], cwd,
                                      cwd / "captured.ll", cwd / "captured.d")
        self.assertEqual(replay[:7], ["-O2", "-I", "/tmp/header dir", "-include", "forced.c", "-pthread", "-S"])
        self.assertNotIn("old.o", replay)
        self.assertNotIn("-lssl", replay)
        self.assertEqual(capture.clang_inputs(args, cwd), [source])
        self.assertEqual(replay[-1], "one.c")

    def test_rust_replay_isolated_from_original_outputs_and_incremental_cache(self):
        args = ["source.rs", "--crate-name", "module", "--emit=dep-info,metadata,link",
                "--out-dir", "original", "-C", "incremental=cache", "-Cextra-filename=-abc",
                "--extern", "other=/tmp/libother.rlib"]
        replay = capture.rust_replay(args, Path("/tmp/capture"))
        self.assertNotIn("original", replay)
        self.assertNotIn("incremental=cache", replay)
        self.assertIn("-Cextra-filename=-abc", replay)
        self.assertIn("other=/tmp/libother.rlib", replay)
        self.assertEqual(replay[-3:], ["--emit=llvm-ir,dep-info", "--out-dir", "/tmp/capture"])

    def test_response_file_languages_and_recursion_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "clang.rsp").write_text('-I "header dir" "source file.c" -c\n')
            args, files = capture.expand_response_files(["@clang.rsp"], root)
            self.assertEqual(args, ["-I", "header dir", "source file.c", "-c"])
            self.assertEqual(len(files), 1)
            (root / "rust.rsp").write_text("--crate-name\nmodule\nsource file.rs\n")
            args, _ = capture.expand_response_files(["@rust.rsp"], root, rust=True)
            self.assertEqual(args[-1], "source file.rs")
            (root / "cycle.rsp").write_text("@cycle.rsp\n")
            with self.assertRaises(capture.CaptureError):
                capture.expand_response_files(["@cycle.rsp"], root)

    def test_tracked_recipes_are_pinned_and_keep_full_scope(self):
        for name in ["cpython", "rust"]:
            recipe = capture.read_json(ROOT / "tools" / "ocore-runtime" / f"{name}.recipe.json")
            capture.validate_recipe(recipe)
            self.assertTrue(recipe["coverage"]["require_full_unit_inventory"])
            self.assertEqual(len(recipe["intended_targets"]), 3)
        rust = capture.read_json(ROOT / "tools" / "ocore-runtime" / "rust.recipe.json")
        self.assertIn("rustc-llvm-backend", {item["id"] for item in rust["coverage"]["required_units"]})
        self.assertIn("panic-unwind", {item["id"] for item in rust["coverage"]["required_units"]})

    def test_link_order_duplicates_and_state_transitions_are_preserved(self):
        args = ["-Lfirst", "-Lsecond", "-Lfirst", "--start-group", "-lleft", "-Bstatic",
                "-lright", "-lleft", "--end-group", "--as-needed", "-Bdynamic", "--no-as-needed"]
        observed = capture.observed_link_inputs(args, Path("/tmp"))
        self.assertEqual(observed["expanded_argv"], args)
        self.assertEqual(observed["libraries"], ["left", "right", "left"])
        self.assertEqual(observed["search_paths"], ["first", "second", "first"])
        self.assertEqual([item["value"] for item in observed["ordered"] if item["kind"] == "transition"],
                         ["--start-group", "-Bstatic", "--end-group", "--as-needed", "-Bdynamic", "--no-as-needed"])
        self.assertFalse(observed["dependency_closure_complete"])

    def test_actual_linker_dependency_path_escaping_retains_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dep = root / "trace.d"
            dep.write_text("out: first\\ path \\\n second$$value first\\ path\n\nfirst\\ path:\n")
            self.assertEqual(capture.ordered_dependency_paths(dep, root),
                             [root / "first path", root / "second$value", root / "first path"])


@unittest.skipUnless(shutil.which("rustc") and shutil.which("cargo"), "real Rust and Cargo required")
class RustBootstrapPreparationTests(unittest.TestCase):
    def test_explicit_initial_tools_and_captured_c_drivers_precede_python_bootstrap(self):
        recipe = capture.read_json(ROOT / "tools/ocore-runtime/rust.recipe.json")
        self.assertEqual(recipe["commands"][0]["name"], "prepare-pinned-source-bootstrap")
        self.assertIn("--config", recipe["commands"][1]["argv"])
        with tempfile.TemporaryDirectory(prefix="ocore-rust-bootstrap-test-") as temporary:
            config = Path(temporary) / "bootstrap.toml"
            argv = [sys.executable, str(ROOT / "tools/ocore-runtime/prepare_rust_bootstrap.py"),
                    "--output", str(config), "--rustc", shutil.which("rustc"),
                    "--cargo", shutil.which("cargo"), "--cc", "/capture/cc",
                    "--cxx", "/capture/cxx", "--jobs", "2"]
            result = subprocess.run(argv, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            metadata = json.loads(result.stdout)
            prepared = tomllib.loads(config.read_text())
            self.assertEqual(prepared["profile"], "dist")
            self.assertEqual(prepared["build"]["rustc"], shutil.which("rustc"))
            self.assertEqual(prepared["build"]["cargo"], shutil.which("cargo"))
            self.assertTrue(prepared["build"]["locked-deps"])
            self.assertFalse(prepared["rust"]["download-rustc"])
            self.assertFalse(prepared["llvm"]["download-ci-llvm"])
            self.assertEqual(prepared["target"][metadata["host"]],
                             {"cc": "/capture/cc", "cxx": "/capture/cxx", "linker": "/capture/cc"})
            self.assertFalse(metadata["runtime_complete"])
            before = config.read_bytes()
            second = subprocess.run(argv, capture_output=True, text=True)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(config.read_bytes(), before)


@unittest.skipUnless(all(shutil.which(tool) for tool in ["clang", "clang++", "llvm-nm", "git"]),
                     "real Clang, C++ driver, llvm-nm and Git required")
class NativeCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ocore-capture-test-")
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.build = self.root / "build"
        self.output = self.root / "capture"
        self.source.mkdir()
        (self.source / "header file.h").write_text("int helper(int);\n")
        (self.source / "one.c").write_text('#include "header file.h"\nint main(void) { return helper(5) != 8; }\n')
        (self.source / "two.cpp").write_text('extern "C" int helper(int x) { return x + 3; }\nextern "C" int cold_path(int x) { return x - 7; }\n')
        (self.source / "extra.c").write_text('int extra_cold_path(void) { return 77; }\n')
        (self.source / "build.py").write_text('''import concurrent.futures, hashlib, json, os, pathlib, shlex, subprocess, sys
source = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
response = pathlib.Path("one.rsp")
pch = "shared.o" if mode == "pch-object-name" else "shared.pch"
if mode in {"pch", "pch-object-name"}:
    subprocess.run([os.environ["CC"], "-O2", "-I", str(source), "-x", "c-header", "-c",
                    str(source / "header file.h"), "-MMD", "-MF", "shared.d", "-o", pch], check=True)
response.write_text(shlex.join(["-O2", "-I", str(source),
    *(["-include-pch", pch] if mode in {"pch", "pch-object-name"} else []),
    "-c", str(source / "one.c"), "-o", "one.o"]))
commands = [[os.environ["CC"], "@one.rsp"], [os.environ["CXX"], "-O2", "-c", str(source / "two.cpp"), "-o", "two.o"]]
if mode in {"omit-cold", "omit-archive", "archive-full", "thin-archive"}:
    commands.append([os.environ["CC"], "-c", str(source / "extra.c"), "-o", "extra.o"])
with concurrent.futures.ThreadPoolExecutor() as pool:
    codes = list(pool.map(lambda argv: subprocess.run(argv).returncode, commands))
if any(codes): sys.exit(1)
if mode == "bypass":
    subprocess.run(["clang", "-c", str(source / "two.cpp"), "-o", "bypass.o"], check=True)
subprocess.run([os.environ["CXX"], "one.o", "two.o", *(["extra.o"] if mode == "omit-cold" else []),
    *(["-fuse-ld=lld"] if mode == "lld" else []),
    *(["-Wl,-v"] if mode == "verbose-linker" else []),
    *(["--ld-path=" + sys.argv[3]] if mode == "linker-bypass" else []), "-o", "app"], check=True)
if mode in {"omit-archive", "archive-full", "thin-archive"}:
    subprocess.run(["ar", "rcs", *(["--thin"] if mode == "thin-archive" else []), "libextra.a", "extra.o"], check=True)
subprocess.run(["./app"], check=True)
if mode != "no-inventory":
    inventory = {"schema": "ocore-runtime-unit-inventory-v1", "complete": True,
        "units": [{"id": "all-c", "kind": "clang", "source": "one.c"}, {"id": "all-cpp", "kind": "clang", "source": "two.cpp"}]}
    if mode == "host-variant":
        inventory["units"][0]["build_step"] = "runtime-build"
    if mode in {"probe", "conflict", "host-variant", "omit-cold", "omit-archive"}:
        app = pathlib.Path("app").resolve()
        inventory["non_lowering_units"] = [{"id": "configure-probe", "kind": "clang",
            "source": str(pathlib.Path("conftest.c").resolve()) if mode == "probe" else "extra.c" if mode in {"omit-cold", "omit-archive"} else "one.c",
            "build_step": "configure" if mode in {"probe", "host-variant"} else "runtime-build",
            "role": "host_build_tool" if mode in {"host-variant", "omit-cold", "omit-archive"} else "configure_probe",
            "evidence": {"reason": "Final app links only one.o and two.o; configure conftest is a separate preceding step.",
                "artifacts": [{"path": str(app), "sha256": hashlib.sha256(app.read_bytes()).hexdigest()}]}}]
    if mode in {"omit-archive", "archive-full", "thin-archive"}:
        archive = pathlib.Path("libextra.a").resolve()
        inventory["runtime_outputs"] = [{"path": str(archive), "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}]
    if mode in {"archive-full", "thin-archive"}:
        inventory["units"].append({"id": "cold-archive", "kind": "clang", "source": "extra.c"})
    pathlib.Path("inventory.json").write_text(json.dumps(inventory))
''')
        for argv in [["git", "init", "-q"], ["git", "add", "."],
                     ["git", "-c", "user.name=Capture Test", "-c", "user.email=capture@example.invalid", "commit", "-qm", "fixture"]]:
            subprocess.run(argv, cwd=self.source, check=True, capture_output=True)
        version = capture.tool_info("clang", "clang")["llvm_version"]
        self.recipe = {"schema": capture.RECIPE_SCHEMA, "name": "actual-frontend-fixture",
                       "source": {"url": "local-test-fixture", "revision": capture.run_text(["git", "rev-parse", "HEAD"], self.source)},
                       "toolchain": {"llvm_version": version},
                       "commands": [{"name": "runtime-build", "argv": [sys.executable, "{source}/build.py", "{source}", "normal"]}],
                       "coverage": {"required_units": [{"id": "c", "kind": "clang", "source": "one.c"},
                                                        {"id": "cpp", "kind": "clang", "source": "two.cpp"}],
                                    "required_outputs": ["app"], "require_full_unit_inventory": True}}
        self.manifest = self.root / "recipe.json"

    def tearDown(self):
        self.temporary.cleanup()

    def execute(self, mode="normal", inventory=True, cc=None, script=None):
        self.recipe["commands"][-1]["argv"][-1] = mode
        if mode == "linker-bypass":
            self.recipe["commands"][-1]["argv"].append(shutil.which("ld"))
        self.manifest.write_text(json.dumps(self.recipe))
        argv = [sys.executable, str(script or SCRIPT), "capture", str(self.manifest), "--source", str(self.source),
                "--build", str(self.build), "--output", str(self.output), "--jobs", "2"]
        if inventory:
            argv.extend(["--unit-inventory", str(self.build / "inventory.json")])
        if cc:
            argv.extend(["--cc", str(cc)])
        result = subprocess.run(argv, capture_output=True, text=True)
        self.assertTrue((self.output / "report.json").is_file(), result.stderr)
        return result, capture.read_json(self.output / "report.json")

    def add_configure_probe(self):
        self.recipe["commands"].insert(0, {"name": "configure", "argv": [sys.executable, "-c",
            "import os,pathlib,subprocess; pathlib.Path('conftest.c').write_text('int main(void) {{ return 0; }}'); "
            "subprocess.run([os.environ['CC'], '-c', 'conftest.c', '-o', 'conftest.o'], check=True)"]})

    def add_host_variant(self):
        self.recipe["commands"].insert(0, {"name": "configure", "argv": [sys.executable, "-c",
            "import os,subprocess,sys; subprocess.run([os.environ['CC'], '-c', sys.argv[1], '-o', 'hostone.o'], check=True)",
            "{source}/one.c"]})

    def test_actual_c_and_cpp_parallel_capture_and_execution(self):
        result, report = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(report["capture_complete"])
        self.assertTrue(report["unit_inventory_complete"])
        self.assertFalse(report["runtime_complete"])
        self.assertFalse(report["dependency_closure_complete"])
        self.assertEqual(len(report["units"]), 2)
        self.assertEqual(set(report["lowering_unit_ids"]), {unit["id"] for unit in report["units"]})
        self.assertTrue(report["unit_roles_complete"])
        self.assertEqual(report["non_lowering_units"], [])
        self.assertEqual(len([event for event in report["invocations"] if event["kind"] == "clang"]), 3)
        self.assertEqual(len([event for event in report["invocations"] if event["kind"] == "linker"]), 1)
        self.assertTrue(any(event["driver_kind"] == "cxx" for event in report["invocations"]))
        self.assertTrue(any(event["response_files"] for event in report["invocations"]))
        self.assertTrue(any(item["path"].endswith("header file.h") for unit in report["units"] for item in unit["dependencies"]))
        self.assertIn("helper", {name for event in report["invocations"] for item in event["outputs"]
                                 for name in item.get("symbols", {}).get("defined", [])})
        for unit in report["units"]:
            self.assertTrue(unit["ir"]["target_triple"])
            self.assertTrue(unit["ir"]["data_layout"])
        cpp = next(unit for unit in report["units"] if unit["source"]["path"].endswith("two.cpp"))
        self.assertIn("@cold_path", Path(cpp["ir"]["path"]).read_text())

    def test_actual_cpp_implicit_providers_are_recorded_without_binary_changes(self):
        result, report = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        linkage = report["native_linkage"]
        self.assertTrue(linkage["provider_identity_complete"], linkage["issues"])
        self.assertFalse(linkage["dependency_closure_complete"])
        self.assertFalse(linkage["source_provider_ownership_complete"])
        trace = next(item for item in linkage["actual_tool_traces"] if item["kind"] == "linker")
        self.assertIn("-lstdc++", trace["ordered_argv"])
        self.assertGreaterEqual(trace["ordered_argv"].count("-lgcc"), 2)
        providers = trace["providers"]
        self.assertTrue(any("libstdc++" in item["spelling"] for item in providers))
        self.assertTrue(any("libstdc++" in item["spelling"] for item in linkage["unowned_native_providers"]))
        for item in providers:
            self.assertEqual(item["original"]["sha256"], item["snapshot"]["sha256"])
            self.assertEqual(capture.file_info(Path(item["snapshot"]["path"])), item["snapshot"])
        before = (self.build / "app").read_bytes()
        session = capture.read_json(self.output / "session.json")
        original = subprocess.run([session["tools"]["cxx"]["invoked_path"], "one.o", "two.o", "-o", "app"],
                                  cwd=self.build, capture_output=True)
        self.assertEqual(original.returncode, 0, original.stderr.decode(errors="replace"))
        self.assertEqual((self.build / "app").read_bytes(), before)
        self.assertTrue(capture.verify_partition(self.output / "report.json")["verified"])

    def test_cold_archive_members_and_source_producers_are_retained(self):
        result, report = self.execute("archive-full")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(report["units"]), 3)
        archive = next(item for item in report["native_linkage"]["actual_tool_traces"] if item["kind"] == "archive")
        self.assertEqual(archive["ordered_argv"], ["rcs", "libextra.a", "extra.o"])
        self.assertEqual([item["member"] for item in archive["archive_members"]], ["extra.o"])
        producer = next(event for event in report["invocations"] if any(item["path"].endswith("extra.c") for item in event["sources"]))
        self.assertEqual(archive["archive_members"][0]["sha256"], producer["outputs"][0]["sha256"])
        self.assertEqual(archive["providers"][0]["original"]["sha256"], producer["outputs"][0]["sha256"])
        self.assertTrue(capture.verify_partition(self.output / "report.json")["verified"])

    def test_absolute_linker_bypass_preserves_host_build_and_rejects_admission(self):
        result, report = self.execute("linker-bypass")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["build_steps"][-1]["exit_code"], 0)
        self.assertFalse(report["capture_complete"])
        self.assertFalse(report["native_linkage"]["provider_identity_complete"])
        self.assertTrue(any("linker bypassed" in issue for issue in report["issues"]))

    def test_changed_actual_native_provider_snapshot_rejects_readmission(self):
        result, report = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        provider = report["native_linkage"]["actual_tool_traces"][0]["providers"][0]
        snapshot = Path(provider["snapshot"]["path"])
        snapshot.chmod(0o644)
        snapshot.write_bytes(snapshot.read_bytes() + b"changed provider")
        with self.assertRaisesRegex(capture.CaptureError, "reconstruction differs|incomplete"):
            capture.verify_partition(self.output / "report.json")

    @unittest.skipUnless(shutil.which("ld.lld"), "actual ELF LLD required")
    def test_actual_lld_trace_keeps_original_driver_selected_tool(self):
        result, report = self.execute("lld")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        linker = next(event for event in report["invocations"] if event["kind"] == "linker")
        driver = next(event for event in report["invocations"] if event["id"] == linker["parent_invocation_id"])
        self.assertEqual(linker["tool"], driver["selected_linker"])
        self.assertIn("LLD", linker["tool"]["version"])
        self.assertTrue(linker["native_linkage"]["complete"])
        self.assertTrue(Path(linker["native_linkage"]["archive_trace"]["path"]).name.endswith(".tsv"))
        self.assertIn("-lstdc++", linker["expanded_argv"])
        self.assertTrue(capture.verify_partition(self.output / "report.json")["verified"])

    def test_verbose_actual_link_is_traced_without_becoming_a_query(self):
        result, report = self.execute("verbose-linker")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        linker = next(event for event in report["invocations"] if event["kind"] == "linker")
        self.assertIn("-v", linker["argv"])
        self.assertEqual(linker["classification"], "native-tool")
        self.assertTrue(linker["native_linkage"]["complete"])
        self.assertTrue(capture.verify_partition(self.output / "report.json")["verified"])

    def test_unsupported_archive_mode_preserves_upstream_result_and_fails_closed(self):
        result, report = self.execute("thin-archive")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["build_steps"][-1]["exit_code"], 0)
        archive = next(event for event in report["invocations"] if event["kind"] == "archive")
        self.assertEqual(archive["exit_code"], 0)
        self.assertIn("--thin", archive["argv"])
        self.assertFalse(archive["native_linkage"]["complete"])
        self.assertFalse(report["capture_complete"])

    def check_actual_pch(self, mode):
        result, report = self.execute(mode)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(report["capture_complete"], report["issues"])
        self.assertEqual(len(report["units"]), 2)
        header = next(event for event in report["invocations"] if event["classification"] == "precompiled-header")
        self.assertFalse(header["translation_required"])
        self.assertEqual(header["units"], [])
        self.assertEqual(header["capture_errors"], [])
        artifact = header["outputs"][0]
        self.assertEqual(artifact["artifact_kind"], "clang-precompiled-header")
        self.assertNotIn("symbols", artifact)
        self.assertEqual(artifact["header_sources"], header["sources"])
        self.assertIn("header file.h", {Path(item["path"]).name for item in artifact["dependencies"]})
        consumer = next(event for event in report["invocations"] if event.get("compiler_inputs"))
        self.assertEqual(consumer["compiler_inputs"][0]["sha256"], artifact["sha256"])
        self.assertNotIn(artifact["path"], {item["path"] for item in consumer["link_inputs"]["files"]})
        self.assertTrue(any("-include-pch" in unit.get("replay_argv", []) for unit in report["units"]))
        cpp = next(unit for unit in report["units"] if unit["source"]["path"].endswith("two.cpp"))
        self.assertIn("@cold_path", Path(cpp["ir"]["path"]).read_text())
        self.assertTrue(capture.verify_partition(self.output / "report.json")["verified"])
        self.assertFalse(report["runtime_complete"])
        return report, artifact

    def test_actual_pch_preserves_cache_context_and_cold_runtime_ir(self):
        self.check_actual_pch("pch")

    def test_actual_pch_named_object_cannot_become_link_dependency(self):
        self.check_actual_pch("pch-object-name")

    def test_changed_pch_and_pch_runtime_root_fail_closed(self):
        report, artifact = self.check_actual_pch("pch")
        path = Path(artifact["path"])
        original = path.read_bytes()
        path.write_bytes(original + b"changed")
        with self.assertRaisesRegex(capture.CaptureError, "reconstruction differs|incomplete"):
            capture.verify_partition(self.output / "report.json")
        path.write_bytes(original)
        membership = capture.runtime_output_membership({"coverage": {"required_outputs": []}},
                         {"runtime_outputs": [artifact]}, report["invocations"], self.build)
        self.assertFalse(membership["complete"])
        self.assertTrue(any("header cache is not an executable" in item for item in membership["issues"]))

    def test_explicit_probe_partition_preserves_all_ir_and_cold_runtime_definitions(self):
        self.add_configure_probe()
        result, report = self.execute(mode="probe")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(report["units"]), 3)
        self.assertEqual(len(report["lowering_unit_ids"]), 2)
        self.assertEqual(len(report["non_lowering_units"]), 1)
        excluded = report["non_lowering_units"][0]
        self.assertEqual(excluded["role"], "configure_probe")
        self.assertEqual(excluded["evidence"]["build_step"]["name"], "configure")
        self.assertTrue(excluded["evidence"]["build_step"]["log"]["sha256"])
        self.assertEqual(excluded["evidence"]["inventory"], report["unit_inventory"]["file"])
        self.assertEqual(set(report["lowering_unit_ids"]) | {excluded["unit_id"]}, {unit["id"] for unit in report["units"]})

    def test_probe_without_inventory_role_fails_closed(self):
        self.add_configure_probe()
        result, report = self.execute()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(report["unit_roles_complete"])
        self.assertFalse(report["unit_inventory_complete"])
        self.assertEqual(len(report["unclassified_unit_ids"]), 1)
        self.assertEqual(len(report["units"]), 3)

    def test_runtime_unit_cannot_also_be_excluded_as_probe(self):
        result, report = self.execute(mode="conflict")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(report["unit_roles_complete"])
        self.assertTrue(any("conflicting role" in issue for issue in report["issues"]))

    def test_changed_non_lowering_evidence_invalidates_partition(self):
        self.add_configure_probe()
        result, report = self.execute(mode="probe")
        self.assertEqual(result.returncode, 0, result.stdout)
        (self.build / "app").write_bytes(b"changed")
        updated = capture.make_report(self.output)
        self.assertFalse(updated["capture_complete"])
        self.assertTrue(any("artifact hash/size mismatch" in issue for issue in updated["issues"]))

    def test_complete_inventory_can_distinguish_same_source_host_and_runtime_variants(self):
        self.add_host_variant()
        result, report = self.execute(mode="host-variant")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(len(report["lowering_unit_ids"]), 2)
        self.assertEqual(len(report["non_lowering_units"]), 1)
        self.assertEqual(report["non_lowering_units"][0]["role"], "host_build_tool")
        floor = next(item for item in report["required_units"] if item["id"] == "c")
        self.assertEqual(len(floor["captured_unit_ids"]), 1)
        self.assertTrue(floor["complete"])

    def test_linked_cold_runtime_unit_cannot_be_declared_host_tool(self):
        result, report = self.execute(mode="omit-cold")
        self.assertEqual(result.returncode, 1)
        self.assertTrue(any("excluded unit contributes to a declared runtime output" in issue for issue in report["issues"]))
        self.assertEqual(len(report["units"]), 3)

    def test_runtime_archive_member_cannot_be_declared_host_tool(self):
        result, report = self.execute(mode="omit-archive")
        self.assertEqual(result.returncode, 1)
        self.assertTrue(any("excluded unit contributes to a declared runtime output" in issue for issue in report["issues"]))
        self.assertTrue(report["runtime_output_membership"]["archive_members"])

    def test_independent_partition_verifier_preserves_original_report_bytes(self):
        self.add_configure_probe()
        result, report = self.execute(mode="probe")
        self.assertEqual(result.returncode, 0, result.stdout)
        report_path = self.output / "report.json"
        before = report_path.read_bytes()
        receipt = capture.verify_partition(report_path)
        self.assertTrue(receipt["verified"])
        self.assertEqual(receipt["lowering_unit_ids"], report["lowering_unit_ids"])
        self.assertFalse(receipt["runtime_complete"])
        self.assertEqual(report_path.read_bytes(), before)

    def test_embedded_stdin_worker_verifies_without_module_file(self):
        self.add_configure_probe()
        result, report = self.execute(mode="probe")
        self.assertEqual(result.returncode, 0, result.stdout)
        # olangc embeds this exact script and supplies a report object. The
        # readmission API must work without an installed script or __file__.
        worker = '''import hashlib, json, sys
payload = json.load(sys.stdin)
namespace = {"__name__": "ocore_capture_readmission"}
exec(compile(payload["source"], "<embedded-capture>", "exec"), namespace)
print(json.dumps(namespace["verify_report"](payload["report"], expected_worker_sha256=hashlib.sha256(payload["source"].encode()).hexdigest())))
'''
        before = (self.output / "report.json").read_bytes()
        result = subprocess.run([sys.executable, "-c", worker],
                                input=json.dumps({"source": SCRIPT.read_text(), "report": report}),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertTrue(receipt["verified"])
        self.assertEqual(receipt["lowering_unit_ids"], report["lowering_unit_ids"])
        self.assertEqual(len(receipt["non_lowering_unit_ids"]), 1)
        self.assertNotIn("report", receipt)  # No raw-file claim for object input.
        self.assertEqual((self.output / "report.json").read_bytes(), before)

    def test_frozen_worker_survives_repository_source_copy_changes(self):
        mutable = self.root / "mutable-capture.py"
        shutil.copyfile(SCRIPT, mutable)
        shutil.copyfile(SCRIPT.with_name(capture.PRODUCER_REGISTRY_FILE),
                        mutable.with_name(capture.PRODUCER_REGISTRY_FILE))
        result, report = self.execute(script=mutable)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        worker = report["capture_worker"]
        self.assertEqual(worker["artifact"]["sha256"], hashlib.sha256(SCRIPT.read_bytes()).hexdigest())
        self.assertTrue(all(event["capture_worker"] == worker["artifact"] for event in report["invocations"]))
        mutable.write_text("raise SystemExit('mutable source must never execute')\n")
        result = subprocess.run([str(self.output / "wrappers/cc"), "--version"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("clang version", result.stdout)
        updated = capture.make_report(self.output, persist=False)
        self.assertTrue(updated["capture_complete"], updated["issues"])
        self.assertTrue(capture.verify_report(updated)["verified"])

    def test_changed_frozen_worker_rejected_before_execution_and_admission(self):
        result, report = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout)
        path = Path(report["capture_worker"]["artifact"]["path"])
        path.chmod(0o644)
        path.write_bytes(path.read_bytes() + b"\n# changed worker\n")
        result = subprocess.run([str(self.output / "wrappers/cc"), "--version"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("worker SHA-256 mismatch", result.stderr)
        with self.assertRaisesRegex(capture.CaptureError, "frozen capture worker artifact changed"):
            capture.verify_report(report)

    def test_mutually_rewritten_worker_session_report_rejected_by_trusted_digest(self):
        result, original = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout)
        trusted = hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
        session = capture.read_json(self.output / "session.json")
        worker = session["capture_worker"]
        path = Path(worker["artifact"]["path"])
        path.chmod(0o644)
        path.write_bytes(path.read_bytes() + b"\n# forged alternate implementation\n")
        worker["artifact"] = capture.file_info(path)
        worker["source"].update(sha256=worker["artifact"]["sha256"], bytes=worker["artifact"]["bytes"])
        for name, kind in capture.wrapper_kinds():
            wrapper = self.output / "wrappers" / name
            wrapper.write_bytes(capture.wrapper_bytes(self.output, kind, worker))
            worker["wrappers"][name] = capture.file_info(wrapper)
        capture.write_json(self.output / "session.json", session)
        for event_path in (self.output / "events").glob("*.json"):
            event = capture.read_json(event_path)
            event["capture_worker"] = worker["artifact"]
            capture.write_json(event_path, event)
        # Internal consistency with an untrusted replacement digest is not
        # sufficient for admission through the independently pinned verifier.
        forged = capture.make_report(self.output, persist=False, expected_worker_sha256=worker["artifact"]["sha256"])
        self.assertTrue(forged["capture_complete"], forged["issues"])
        with self.assertRaisesRegex(capture.CaptureError, "trusted verifier worker SHA-256"):
            capture.verify_report(forged, expected_worker_sha256=trusted)

    def test_rewritten_wrapper_hash_cannot_replace_frozen_execution_path(self):
        result, report = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout)
        session = capture.read_json(self.output / "session.json")
        wrapper = self.output / "wrappers/cc"
        wrapper.write_text("#!/bin/sh\nexec clang \"$@\"\n")
        session["capture_worker"]["wrappers"]["cc"] = capture.file_info(wrapper)
        capture.write_json(self.output / "session.json", session)
        with self.assertRaisesRegex(capture.CaptureError, "wrapper changed or does not execute"):
            capture.verify_report(report)

    def test_legacy_or_mixed_worker_journal_cannot_be_admitted(self):
        result, report = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout)
        event_path = next((self.output / "events").glob("*.json"))
        event = capture.read_json(event_path)
        event["capture_worker"]["sha256"] = "0" * 64
        capture.write_json(event_path, event)
        mixed = capture.make_report(self.output, persist=False)
        self.assertFalse(mixed["capture_complete"])
        self.assertTrue(any("mixed capture worker" in issue for issue in mixed["issues"]))
        with self.assertRaisesRegex(capture.CaptureError, "incomplete"):
            capture.verify_report(mixed)
        session = capture.read_json(self.output / "session.json")
        del session["capture_worker"]
        capture.write_json(self.output / "session.json", session)
        with self.assertRaisesRegex(capture.CaptureError, "legacy/unbound capture worker"):
            capture.verify_report(report)

    def test_rewritten_selected_and_required_lists_cannot_redefine_capture_partition(self):
        result, report = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout)
        cpp = next(unit["id"] for unit in report["units"] if unit["source"]["path"].endswith("two.cpp"))
        report["lowering_unit_ids"].remove(cpp)
        report["required_units"] = [item for item in report["required_units"] if cpp not in item["captured_unit_ids"]]
        report["non_lowering_units"] = [{"unit_id": cpp, "role": "host_build_tool", "rule_id": "rewritten",
                                          "evidence": {"reason": "caller rewrote all lists consistently"}}]
        path = self.output / "report.json"
        capture.write_json(path, report)
        before = path.read_bytes()
        with self.assertRaisesRegex(capture.CaptureError, "capture reconstruction differs"):
            capture.verify_partition(path)
        self.assertEqual(path.read_bytes(), before)

    def test_rewritten_inventory_cannot_exclude_linked_cold_definition(self):
        result, report = self.execute(mode="omit-cold")
        self.assertEqual(result.returncode, 1)
        # Even mutually consistent reported booleans/lists cannot override the
        # actual app->extra.o link membership and original hashed inventory.
        report["capture_complete"] = True
        report["unit_inventory_complete"] = True
        report["unit_roles_complete"] = True
        report["issues"] = []
        capture.write_json(self.output / "report.json", report)
        with self.assertRaisesRegex(capture.CaptureError, "capture reconstruction differs"):
            capture.verify_partition(self.output / "report.json")

    def test_rewritten_inventory_and_report_cannot_replace_original_journal_binding(self):
        result, _ = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout)
        session = capture.read_json(self.output / "session.json")
        inventory_path = Path(session["inventory_path"])
        inventory = capture.read_json(inventory_path)
        inventory["units"][1]["id"] = "rewritten-runtime-requirement"
        capture.write_json(inventory_path, inventory)
        # A caller can regenerate mutually consistent report fields, but cannot
        # silently replace the original journal's finalized inventory artifact.
        forged = capture.make_report(self.output, persist=False)
        forged["capture_complete"] = True
        forged["unit_inventory_complete"] = True
        forged["unit_roles_complete"] = True
        forged["issues"] = []
        with self.assertRaisesRegex(capture.CaptureError, "finalized capture journal artifact"):
            capture.verify_report(forged)

    def test_changed_build_log_cannot_be_rebound_by_rewritten_report(self):
        self.add_configure_probe()
        result, _ = self.execute(mode="probe")
        self.assertEqual(result.returncode, 0, result.stdout)
        log = self.output / "build-0.log"
        log.write_bytes(log.read_bytes() + b"rewritten configure evidence\n")
        forged = capture.make_report(self.output, persist=False)
        self.assertTrue(any("build log differs" in issue for issue in forged["issues"]))
        with self.assertRaisesRegex(capture.CaptureError, "partition is incomplete"):
            capture.verify_report(forged)

    def test_failed_partition_recheck_removes_stale_receipt(self):
        result, report = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout)
        receipt = self.root / "verified.json"
        argv = [sys.executable, str(SCRIPT), "verify-report", str(self.output / "report.json"), "--receipt", str(receipt)]
        first = subprocess.run(argv, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertTrue(receipt.is_file())
        report["lowering_unit_ids"] = []
        capture.write_json(self.output / "report.json", report)
        second = subprocess.run(argv, capture_output=True, text=True)
        self.assertEqual(second.returncode, 1)
        self.assertFalse(receipt.exists())

    def test_partition_receipt_cannot_overwrite_capture_journal(self):
        result, _ = self.execute()
        self.assertEqual(result.returncode, 0)
        session = self.output / "session.json"
        before = session.read_bytes()
        result = subprocess.run([sys.executable, str(SCRIPT), "verify-report", str(self.output / "report.json"),
                                 "--receipt", str(session)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("must not overwrite", result.stderr)
        self.assertEqual(session.read_bytes(), before)

    def test_successful_build_cannot_cover_missing_required_translation_unit(self):
        self.recipe["coverage"]["required_units"].append({"id": "missing", "kind": "clang", "source": "unbuilt.c"})
        result, report = self.execute()
        self.assertEqual(result.returncode, 1)
        self.assertEqual([item["id"] for item in report["failed_required_units"]], ["missing"])

    def test_no_inventory_fails_closed_even_after_successful_execution(self):
        result, report = self.execute(mode="no-inventory", inventory=False)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(report["unit_inventory_complete"])
        self.assertEqual(len(report["units"]), 2)

    def test_absolute_compiler_bypass_detected_by_native_output_audit(self):
        result, report = self.execute(mode="bypass")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(report["uncaptured_outputs"]), 1)
        self.assertTrue(report["uncaptured_outputs"][0]["path"].endswith("bypass.o"))

    def test_source_pin_and_tool_version_mismatches_emit_incomplete_report(self):
        self.recipe["source"]["revision"] = "0" * 40
        result, report = self.execute()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(report["capture_complete"])
        self.assertTrue(any("source commit mismatch" in issue for issue in report["issues"]))
        self.assertEqual(report["units"], [])

    def test_llvm_tool_version_mismatch_stops_before_build(self):
        self.recipe["toolchain"]["llvm_version"] = "0.0.0"
        result, report = self.execute()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["build_steps"], [])
        self.assertTrue(any("version mismatch" in issue for issue in report["issues"]))

    def test_successful_native_compile_with_failed_llvm_replay_fails_closed(self):
        driver = self.root / "clang-with-replay-failure"
        driver.write_text(f"#!{sys.executable}\nimport os, sys\n"
                          "if '-emit-llvm' in sys.argv: sys.exit(42)\n"
                          "os.execvp('clang', ['clang', *sys.argv[1:]])\n")
        driver.chmod(0o755)
        result, report = self.execute(cc=driver)
        self.assertEqual(result.returncode, 1)
        self.assertTrue(any("LLVM replay failed" in issue for issue in report["issues"]))
        failed = next(item for item in report["failed_required_units"] if item["id"] == "c")
        self.assertTrue(failed["failed_invocation_ids"])
        invocation = next(event for event in report["invocations"] if event["id"] in failed["failed_invocation_ids"])
        self.assertEqual(invocation["exit_code"], 0)
        self.assertEqual(invocation["units"][0]["replay_exit_code"], 42)
        self.assertEqual(report["build_steps"][0]["exit_code"], 0)
        self.assertTrue((self.build / "app").is_file())
        self.assertTrue(any(unit["source"]["path"].endswith("two.cpp") for unit in report["units"]))

    def test_ir_tampering_invalidates_recomputed_report(self):
        result, report = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout)
        path = Path(report["units"][0]["ir"]["path"])
        path.write_text(path.read_text() + "\n; changed\n")
        updated = capture.make_report(self.output)
        self.assertFalse(updated["capture_complete"])
        self.assertTrue(any("bytes or target metadata changed" in issue for issue in updated["issues"]))

    def test_failed_required_compile_preserves_invocation_failure(self):
        (self.source / "one.c").write_text("this is not C;\n")
        subprocess.run(["git", "add", "one.c"], cwd=self.source, check=True)
        subprocess.run(["git", "-c", "user.name=Capture Test", "-c", "user.email=capture@example.invalid",
                        "commit", "-qm", "invalid C"], cwd=self.source, check=True)
        self.recipe["source"]["revision"] = capture.run_text(["git", "rev-parse", "HEAD"], self.source)
        result, report = self.execute()
        self.assertEqual(result.returncode, 1)
        failed = next(item for item in report["failed_required_units"] if item["id"] == "c")
        self.assertTrue(failed["failed_invocation_ids"])
        self.assertTrue(any(event["exit_code"] != 0 for event in report["invocations"]))


@unittest.skipUnless(shutil.which("rustc") and shutil.which("llvm-nm"), "real rustc and llvm-nm required")
class RustWrapperTests(unittest.TestCase):
    def test_actual_rust_codegen_units_and_crate_kind_preserved(self):
        with tempfile.TemporaryDirectory(prefix="ocore-rust-capture-test-") as temporary:
            root = Path(temporary)
            (root / "events").mkdir()
            source = root / "program.rs"
            source.write_text('pub fn add(a: u64, b: u64) -> u64 { a.wrapping_add(b) }\n')
            rust = capture.tool_info("rustc", "rustc")
            nm = capture.tool_info("llvm-nm", "llvm-nm")
            session = {"tools": {"rustc": rust, "nm": nm},
                       "recipe": {"toolchain": {"llvm_version": rust["llvm_version"], "rustc_release": rust["release"]}}}
            session["capture_worker"] = capture.snapshot_worker(root)
            capture.write_json(root / "session.json", session)
            old = Path.cwd()
            try:
                os.chdir(root)
                code = subprocess.run([str(root / "wrappers/rustc-wrapper"), rust["invoked_path"], str(source), "--crate-name", "program",
                                         "--crate-type", "rlib", "-C", "codegen-units=2", "--out-dir", str(root)]).returncode
            finally:
                os.chdir(old)
            events = [capture.read_json(path) for path in (root / "events").glob("*.json")]
            self.assertEqual(code, 0, json.dumps(events, indent=2))
            self.assertEqual(len(events), 1)
            event = events[0]
            self.assertTrue(event["units"])
            self.assertTrue(event["outputs"])
            self.assertEqual(event["frontend"]["llvm_version"], rust["llvm_version"])
            self.assertIn("--crate-type", event["replay_argv"])
            self.assertEqual(event["replay_argv"][event["replay_argv"].index("--crate-type") + 1], "rlib")
            for unit in event["units"]:
                self.assertTrue(unit["ir"]["data_layout"])
                self.assertTrue(unit["dependencies"])


if __name__ == "__main__":
    unittest.main()
