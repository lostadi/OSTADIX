from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("ocore_rust_stage_roles", Path(__file__).with_name("stage_roles.py"))
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class StageRolesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        for name, anchors in module.CONSTRUCTORS.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(anchors) + "\n")
        self.capture = self.root / "capture"
        (self.capture / "events").mkdir(parents=True)
        self.target = self.root / "stage2-rustc"
        self.manifest = self.source / "compiler/demo/Cargo.toml"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text('[package]\nname = "demo"\nversion = "0.0.0"\n')

    def event(self, identity="event", *, producer="stage1/rustc", target=None,
              producer_sha="a" * 64, stage="1", features=None):
        target = target or self.target
        outdir = target / "x86_64-unknown-linux-gnu/release/deps"
        outdir.mkdir(parents=True, exist_ok=True)
        argv = ["--crate-name", "demo", "--crate-type", "lib", "--out-dir", str(outdir),
                "-C", "extra-filename=-1234abcd", "--target=x86_64-unknown-linux-gnu"]
        for feature in features or []:
            argv.extend(["--cfg", "feature=" + json.dumps(feature)])
        value = {"id": identity, "kind": "rustc", "classification": "compile",
                 "exit_code": 0, "argv": argv,
                 "frontend": {"executing_binary": {"path": producer, "sha256": producer_sha, "bytes": 10}},
                 "build_environment": {"RUSTC_STAGE": stage, "RUSTC_REAL": producer,
                   "RUSTC_SYSROOT": producer + "/sysroot", "CARGO_TARGET_DIR": str(target),
                   "CARGO_MANIFEST_DIR": str(self.manifest.parent)}}
        path = self.capture / "events" / (identity + ".json")
        path.write_text(json.dumps(value))
        return value, path

    def fingerprint(self, *, target=None, branch="x86_64-unknown-linux-gnu", filename="lib-demo.json", features=None):
        target = target or self.target
        path = target / branch / "release/.fingerprint/demo-1234abcd" / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"features": json.dumps(features or []), "profile": 9182,
                                   "deps": [[1, "dep", False, 2]], "rustflags": ["-Cpanic=unwind"]}))
        return path

    def acquire(self):
        return module.acquire(self.source, self.capture, self.root / "result.json")

    def test_same_reported_stage_preserves_distinct_producer_generations(self):
        self.event("installed", producer="installed/rustc", target=self.root / "stage1-rustc")
        self.event("built", producer="stage1/rustc")
        result = self.acquire()
        self.assertEqual(2, len(result["groups"]))
        self.assertEqual({"1"}, {g["reported_rustc_stage"] for g in result["groups"]})
        self.assertEqual({"installed/rustc", "stage1/rustc"}, {g["rustc_real"] for g in result["groups"]})

    def test_retries_and_changed_producer_bytes_remain_distinct(self):
        self.event("first")
        self.event("retry")
        self.event("replacement", producer_sha="b" * 64)
        result = self.acquire()
        self.assertEqual(3, len(result["attempts"]))
        self.assertEqual([1, 2], sorted(len(g["attempt_indices"]) for g in result["groups"]))

    def test_fingerprint_branch_and_features_are_checked(self):
        self.event(features=["full", "jit"])
        valid = self.fingerprint(features=["jit", "full"])
        self.fingerprint(branch="other-unknown-target", features=["full", "jit"])
        result = self.acquire()
        candidates = result["attempts"][0]["fingerprint_candidates"]
        self.assertEqual(1, len(candidates))
        self.assertEqual(str(valid.absolute()), candidates[0]["path"])
        self.assertTrue(candidates[0]["match_evidence"]["features_match"])
        self.assertEqual(9182, candidates[0]["opaque_cargo_values"]["profile"])
        self.assertFalse(candidates[0]["configured_unit_graph_proven"])

    def test_changed_fingerprint_features_are_an_explicit_gap(self):
        self.event(features=["full"])
        self.fingerprint(features=["reduced"])
        result = self.acquire()
        self.assertIn("fingerprint_feature_mismatch", {gap["kind"] for gap in result["gaps"]})

    def test_ambiguous_same_hash_fingerprints_are_not_resolved_by_guessing(self):
        self.event()
        self.fingerprint()
        self.fingerprint(filename="bin-demo.json")
        result = self.acquire()
        self.assertEqual(2, len(result["attempts"][0]["fingerprint_candidates"]))
        self.assertIn("ambiguous_fingerprint_match", {gap["kind"] for gap in result["gaps"]})

    def test_raw_journals_and_source_bytes_are_preserved(self):
        _, event = self.event()
        self.fingerprint()
        before = {path: path.read_bytes() for path in [event, self.manifest]}
        result = self.acquire()
        for path, raw in before.items():
            self.assertEqual(raw, path.read_bytes())
            matches = [a for a in result["input_artifacts"] if a["path"] == str(path.absolute())]
            self.assertEqual(1, len(matches))
            self.assertEqual(raw, Path(matches[0]["snapshot_path"]).read_bytes())

    def test_malformed_original_journal_is_retained_and_not_repaired(self):
        path = self.capture / "events/broken.json"
        path.write_bytes(b'{"incomplete":')
        result = self.acquire()
        self.assertEqual(b'{"incomplete":', path.read_bytes())
        self.assertTrue(any(gap["kind"] == "unavailable_or_malformed_metadata" for gap in result["gaps"]))
        self.assertTrue(any(a["path"] == str(path.absolute()) for a in result["input_artifacts"]))

    def test_child_commands_never_establish_parent_command_or_payload_graph(self):
        self.event()
        self.fingerprint()
        result = self.acquire()
        group = result["groups"][0]
        self.assertFalse(group["original_parent_cargo_command_available"])
        self.assertFalse(group["configured_payload_unit_graph_available"])
        self.assertFalse(result["stage_roles_complete"])
        self.assertFalse(result["runtime_complete"])
        self.assertIn("original_parent_cargo_command_and_payload_unit_graph_missing",
                      {gap["kind"] for gap in result["gaps"]})

    def test_existing_output_is_never_rewritten(self):
        output = self.root / "existing.json"
        output.write_bytes(b'original')
        with self.assertRaises(FileExistsError):
            module.acquire(self.source, self.capture, output)
        self.assertEqual(b'original', output.read_bytes())


if __name__ == "__main__":
    unittest.main()
