#!/usr/bin/env python3
"""Trusted producer selection and detached capture/readmission boundaries.

Native tests reuse the existing small C/C++ fixture. They do not build Rust,
download an engine, or equate capture with O-core/runtime completeness.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("producer_capture_fixture", Path(__file__).with_name("test_capture.py"))
fixture_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture_module)
capture = fixture_module.capture
SCRIPT = fixture_module.SCRIPT
REGISTRY = SCRIPT.with_name(capture.PRODUCER_REGISTRY_FILE)


class RegistryPolicyTests(unittest.TestCase):
    def recipe(self):
        return capture.read_json(fixture_module.ROOT / "tools/ocore-runtime/cpython.recipe.json")

    def test_legacy_kinds_and_explicit_ids_preserve_clang_and_rust_policies(self):
        registry = capture.producer_registry()
        for recipe in (self.recipe(), capture.read_json(fixture_module.ROOT / "tools/ocore-runtime/rust.recipe.json")):
            capture.validate_recipe(recipe)
            for unit in recipe["coverage"]["required_units"]:
                descriptor = capture.registered_producer(unit["kind"], registry=registry)
                unit["producer"] = descriptor["id"]
            capture.validate_recipe(recipe)
        self.assertEqual(dict(capture.wrapper_kinds())["cc"], "clang")
        self.assertEqual(dict(capture.wrapper_kinds())["cxx"], "cxx")
        self.assertEqual(dict(capture.wrapper_kinds())["rustc-wrapper"], "rustc")
        replay = capture.producer_policy("rustc", {"toolchain": {}})
        embedded = capture.producer_policy("rustc", {"toolchain": {"rust_capture_policy": capture.RUST_EMBEDDED_POLICY}})
        self.assertTrue(replay["frontend_replay"])
        self.assertEqual(replay["format"], "llvm-text")
        self.assertFalse(embedded["frontend_replay"])
        self.assertEqual(embedded["format"], "llvm-bitcode")

    def test_unknown_producer_and_recipe_plugins_reject_before_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "must-not-run"
            mutations = [
                lambda r: r["coverage"]["required_units"][0].update(producer="go-native-v1"),
                lambda r: r["coverage"]["required_units"][0].update(kind="go"),
                lambda r: r.update(producer_registry="untrusted.json"),
                lambda r: r["toolchain"].update(producer_plugins=["untrusted.py"]),
                lambda r: r["coverage"]["required_units"][0].update(adapter="untrusted.py"),
            ]
            for mutate in mutations:
                with self.subTest(mutation=mutations.index(mutate)):
                    recipe = self.recipe()
                    recipe["commands"] = [{"argv": [sys.executable, "-c", "from pathlib import Path; Path(" + repr(str(marker)) + ").touch()"]}]
                    mutate(recipe)
                    manifest = root / "recipe.json"
                    manifest.write_text(json.dumps(recipe))
                    result = subprocess.run([sys.executable, str(SCRIPT), "capture", str(manifest),
                        "--source", str(root / "absent-source"), "--build", str(root / "build"),
                        "--output", str(root / "output")], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    evidence = json.loads(result.stdout)
                    self.assertFalse(evidence["capture_complete"])
                    self.assertFalse(evidence["ocore_lowering_complete"])
                    self.assertTrue(evidence["issues"])
                    self.assertFalse(marker.exists())
                    self.assertFalse((root / "output").exists())

    def test_capture_availability_does_not_admit_unknown_ir_or_disabled_import(self):
        registry = capture.producer_registry()
        descriptor = capture.registered_producer("clang", registry=registry)
        self.assertTrue(descriptor["capture"]["available"])
        for format_ in ("go-object", "native", "javascript", "llvm-bitcode", None):
            with self.subTest(format=format_):
                with self.assertRaisesRegex(capture.CaptureError, "unsupported import format"):
                    capture.require_import_format("clang", format_, registry)
        # Capability evaluation remains independent when a future trusted
        # capture adapter has no importer. This data is never loaded as policy.
        unavailable = copy.deepcopy(registry)
        unavailable["producers"][0]["import"]["available"] = False
        self.assertTrue(capture.registered_producer("clang", registry=unavailable)["capture"]["available"])
        with self.assertRaisesRegex(capture.CaptureError, "unsupported import format"):
            capture.require_import_format("clang", "llvm-text", unavailable)

    def test_discovery_is_capability_data_with_no_completion_claim(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "producers"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["registry"], capture.producer_registry())
        for field in ("capture_complete", "ocore_lowering_complete", "dependency_closure_complete",
                      "native_execution_qualified", "runtime_complete"):
            self.assertIs(data[field], False)

    def test_untrusted_resource_bytes_and_ambient_stdin_fallback_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / REGISTRY.name
            path.write_bytes(REGISTRY.read_bytes() + b"\n")
            with self.assertRaisesRegex(capture.CaptureError, "independently registered SHA-256"):
                capture.producer_registry(path)
        namespace = {"__name__": "embedded_registry_test"}
        exec(compile(SCRIPT.read_bytes(), "<embedded-capture>", "exec"), namespace)
        with self.assertRaisesRegex(namespace["CaptureError"], "verified capture snapshot"):
            namespace["producer_registry"]()

    def test_rust_helper_remains_an_independent_resource_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "wrappers").mkdir()
            worker = capture.snapshot_worker(root, capture.RUST_EMBEDDED_POLICY)
            session = {"capture_worker": worker, "recipe": {"toolchain": {"rust_capture_policy": capture.RUST_EMBEDDED_POLICY}}}
            self.assertEqual(capture.verify_worker(session, root), worker)
            helper = worker["rust_payload_extractor"]
            path = Path(helper["artifact"]["path"])
            path.chmod(0o644)
            path.write_bytes(path.read_bytes() + b"\n# substituted helper\n")
            helper["artifact"] = capture.file_info(path)
            helper["source"].update(sha256=helper["artifact"]["sha256"], bytes=helper["artifact"]["bytes"])
            with self.assertRaisesRegex(capture.CaptureError, "registered|changed"):
                capture.verify_worker(session, root)


@unittest.skipUnless(all(shutil.which(tool) for tool in ["clang", "clang++", "llvm-nm", "git"]),
                     "real Clang, C++ driver, llvm-nm and Git required")
class NativeProducerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.NativeCaptureTests(methodName="test_actual_c_and_cpp_parallel_capture_and_execution")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def execute(self, **kwargs):
        result, report = self.fixture.execute(**kwargs)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(report["capture_complete"], report["issues"])
        return report

    def test_actual_alias_capture_with_explicit_producer_keeps_import_unqualified(self):
        for unit in self.fixture.recipe["coverage"]["required_units"]:
            unit["producer"] = capture.registered_producer(unit["kind"])["id"]
        report = self.execute()
        descriptor = capture.registered_producer("clang")
        self.assertTrue(any(event.get("driver_kind") == "cxx" for event in report["invocations"]))
        self.assertTrue(all(unit["producer"] == descriptor["id"] for unit in report["units"]))
        self.assertEqual(report["producer_capabilities"], capture.producer_registry())
        for field in ("ocore_lowering_complete", "dependency_closure_complete", "native_execution_qualified", "runtime_complete"):
            self.assertIs(report[field], False)
        self.assertTrue(capture.verify_report(report)["verified"])

    def test_unit_format_producer_and_missing_unit_cannot_redefine_import(self):
        report = self.execute()
        output = self.fixture.output
        path = next(path for path in (output / "events").glob("*.json") if capture.read_json(path).get("units"))
        original = path.read_bytes()
        mutations = [
            ("unsupported import format", lambda e: e["units"][0]["ir"].update(format="go-object")),
            ("owning compiler producer", lambda e: e["units"][0].update(kind="rustc", producer="rustc-llvm-v1")),
            ("mismatched producer ID", lambda e: e["units"][0].update(producer="unregistered-engine")),
            ("required unit incomplete", lambda e: e.update(units=[])),
        ]
        for diagnostic, mutate in mutations:
            with self.subTest(diagnostic=diagnostic):
                event = json.loads(original)
                mutate(event)
                capture.write_json(path, event)
                rebuilt = capture.make_report(output, persist=False)
                self.assertFalse(rebuilt["capture_complete"])
                self.assertTrue(any(diagnostic in issue for issue in rebuilt["issues"]), rebuilt["issues"])
                with self.assertRaises(capture.CaptureError):
                    capture.verify_report(rebuilt)
                path.write_bytes(original)
        # An allowed format label and a rewritten claimed hash cannot turn
        # another producer's native bytes into LLVM IR.
        event = json.loads(original)
        unit = event["units"][0]
        ir_path = Path(unit["ir"]["path"])
        ir_bytes = ir_path.read_bytes()
        ir_path.write_bytes(b"\x7fELF\x02\x01not-an-llvm-module\x00")
        unit["ir"].update(capture.file_info(ir_path))
        self.assertEqual(unit["ir"]["format"], "llvm-text")
        capture.write_json(path, event)
        rebuilt = capture.make_report(output, persist=False)
        self.assertFalse(rebuilt["capture_complete"])
        self.assertTrue(any("producer unit unavailable" in issue or "LLVM unit bytes or target metadata changed" in issue
                            for issue in rebuilt["issues"]), rebuilt["issues"])
        with self.assertRaises(capture.CaptureError):
            capture.verify_report(rebuilt)
        ir_path.write_bytes(ir_bytes)
        path.write_bytes(original)
        self.assertTrue(capture.verify_report(report)["verified"])

    def test_snapshot_cannot_be_missing_relocated_or_rebound_to_mutated_bytes(self):
        report = self.execute()
        output = self.fixture.output
        path = output / REGISTRY.name
        original = path.read_bytes()
        session = capture.read_json(output / "session.json")
        record = session["capture_worker"]["producer_registry"]
        path.chmod(0o644)
        path.write_bytes(original + b"\n")
        record["artifact"] = capture.file_info(path)
        record["source"].update(sha256=record["artifact"]["sha256"], bytes=record["artifact"]["bytes"])
        capture.write_json(output / "session.json", session)
        with self.assertRaisesRegex(capture.CaptureError, "independently registered SHA-256"):
            capture.verify_report({**report, "capture_worker": session["capture_worker"]})
        result = subprocess.run([str(output / "wrappers/cc"), "--version"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("clang version", result.stdout)
        self.assertIn("registered SHA-256", result.stderr)
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            capture.verified_producer_registry(session, output)
        substitute = self.fixture.root / "substituted-registry.json"
        substitute.write_bytes(original)
        path.symlink_to(substitute)
        record["artifact"] = capture.file_info(path)
        with self.assertRaisesRegex(capture.CaptureError, "snapshot path"):
            capture.verified_producer_registry(session, output)

    def test_detached_driver_and_stdin_readmission_use_only_frozen_resource(self):
        scripts = self.fixture.root / "detached-driver/scripts"
        scripts.mkdir(parents=True)
        driver = scripts / SCRIPT.name
        shutil.copyfile(SCRIPT, driver)
        shutil.copyfile(REGISTRY, scripts / REGISTRY.name)
        report = self.execute(script=driver)
        shutil.rmtree(scripts.parent)
        unrelated = self.fixture.root / "unrelated-cwd"
        unrelated.mkdir()
        (unrelated / REGISTRY.name).write_text("not a trusted registry")
        worker = '''import hashlib,json,sys
payload = json.load(sys.stdin)
namespace = {"__name__": "detached_readmission"}
exec(compile(payload["source"], "<embedded-capture>", "exec"), namespace)
print(json.dumps(namespace["verify_report"](payload["report"], expected_worker_sha256=hashlib.sha256(payload["source"].encode()).hexdigest())))
'''
        before = (self.fixture.output / "report.json").read_bytes()
        result = subprocess.run([sys.executable, "-I", "-c", worker], cwd=unrelated,
            input=json.dumps({"source": SCRIPT.read_text(), "report": report}), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["verified"])
        self.assertEqual(before, (self.fixture.output / "report.json").read_bytes())
        # The snapshot is required even when an adjacent/cwd registry exists.
        (self.fixture.output / REGISTRY.name).unlink()
        result = subprocess.run([sys.executable, "-I", "-c", worker], cwd=unrelated,
            input=json.dumps({"source": SCRIPT.read_text(), "report": report}), capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
