"""Authored inert observer metadata controls; no real Cargo/capture dispatch.
The sole observe() control replaces Popen, wait_original and finish explicitly.
All other controls call only candidate discovery or metadata observation helpers.
"""
import copy
import importlib.util
import json
import hashlib
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("observer_metadata_candidate", Path(__file__).with_name("observe_cargo.py"))
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class ParentMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.capture = self.root / "capture"
        self.capture.mkdir()
        (self.capture / "evidence").mkdir()
        self.manifest = self.source / "Cargo.toml"
        self.manifest.write_bytes(b"original manifest bytes\n")
        self.lock = self.source / "Cargo.lock"
        self.environment = {"HOME": str(self.root / "home"), "CARGO_HOME": str(self.root / "cargo-home")}
        self.candidates = [{"path": str(self.manifest), "discovery_reasons": ["explicit_parent_manifest_argument"]},
                           {"path": str(self.lock), "discovery_reasons": ["workspace_lock_candidate"]}]

    def event(self, status=0):
        return {"id": M.uuid.uuid4().hex, "cwd": str(self.source),
                "argv": ["/not-executed/cargo", "build"], "parent_source_context": {"path": str(self.source)},
                "capture_errors": [], "upstream_started": True, "upstream_pid": 12345, "upstream_exit_code": status,
                "original_command_observation_v2": {**M._parent_original_lifecycle_empty(),
                    "constructor_entered": True, "constructor_returned": True, "pid": 12345, "wait_returned": True},
                "parent_metadata_v2": M._parent_metadata_empty()}

    def before(self, event):
        with mock.patch.object(M, "_parent_metadata_candidates", return_value=copy.deepcopy(self.candidates)):
            M._parent_metadata_before(self.capture, event, event["argv"][1:], self.environment)

    def after(self, event):
        M._parent_metadata_after(self.capture, event)

    def verify(self, event):
        with mock.patch.object(M, "_parent_metadata_candidates", return_value=copy.deepcopy(self.candidates)):
            M._verify_parent_metadata_v2(event["parent_metadata_v2"], event, self.environment)

    def test_discovery_retains_absent_candidates_and_explicit_roles_in_order(self):
        rows = M._parent_metadata_candidates(["build", "--manifest-path", str(self.manifest),
              "--config", str(self.source / "missing-config")], self.environment,
              {"path": str(self.source)}, self.source)
        self.assertEqual(rows[0]["path"], str(self.manifest))
        self.assertEqual(rows[1]["path"], str(self.source / "missing-config"))
        by_path = {row["path"]: row for row in rows}
        self.assertIn(str(self.lock), by_path)
        self.assertIn("workspace_lock_candidate", by_path[str(self.lock)]["discovery_reasons"])
        self.assertFalse(self.lock.exists())
        self.assertTrue(any(row["path"] == str(self.root / "cargo-home" / "config.toml") for row in rows))

    def test_unchanged_regular_and_absent_metadata_have_verified_private_snapshots(self):
        event = self.event()
        self.before(event)
        self.after(event)
        self.verify(event)
        record = event["parent_metadata_v2"]
        self.assertTrue(record["metadata_unchanged"])
        self.assertEqual([row["state"] for row in record["before_original"]], ["regular", "absent"])
        self.assertEqual(event["capture_errors"], [])
        for phase in ["before_original", "after_attempt"]:
            snapshot = Path(record[phase][0]["snapshot"]["path"])
            self.assertEqual(snapshot.read_bytes(), self.manifest.read_bytes())
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o400)
        self.assertTrue(all(record[field] is False for field in M.ADMISSION_FIELDS))
        self.assertFalse(record["effective_configuration_proven"])
        self.assertFalse(record["cargo_consumption_proven"])

    def test_absent_to_present_is_an_explicit_delta_not_a_capture_or_exit_replacement(self):
        event = self.event(0)
        self.before(event)
        self.lock.write_bytes(b"legitimate generated lock\n")
        self.after(event)
        self.verify(event)
        self.assertEqual(event["upstream_exit_code"], 0)
        self.assertEqual(event["capture_errors"], [])
        self.assertEqual(event["parent_metadata_v2"]["changes"][0]["kind"], "absent_to_present")
        self.assertFalse(event["parent_metadata_v2"]["metadata_unchanged"])

    def test_present_to_absent_preserves_before_bytes_and_nonzero_upstream_exit(self):
        event = self.event(101)
        self.before(event)
        before = event["parent_metadata_v2"]["before_original"][0]
        self.manifest.unlink()
        self.after(event)
        self.verify(event)
        self.assertEqual(event["upstream_exit_code"], 101)
        self.assertEqual(event["capture_errors"], [])
        self.assertEqual(Path(before["snapshot"]["path"]).read_bytes(), b"original manifest bytes\n")
        self.assertEqual(event["parent_metadata_v2"]["changes"][0]["kind"], "present_to_absent")

    def test_byte_and_metadata_only_drift_are_retained_without_normalization(self):
        for kind in ["bytes", "mode"]:
            with self.subTest(kind=kind):
                event = self.event()
                self.before(event)
                if kind == "bytes":
                    self.manifest.write_bytes(b"changed manifest bytes!\n")
                else:
                    self.manifest.chmod(0o600)
                self.after(event)
                self.verify(event)
                record = event["parent_metadata_v2"]
                self.assertEqual(record["changes"][0]["kind"], "metadata_or_state_changed")
                before = record["before_original"][0]
                after = record["after_attempt"][0]
                before_bytes = Path(before["snapshot"]["path"]).read_bytes()
                after_bytes = Path(after["snapshot"]["path"]).read_bytes()
                self.assertEqual(before["snapshot"]["sha256"], hashlib.sha256(before_bytes).hexdigest())
                self.assertEqual(after["snapshot"]["sha256"], hashlib.sha256(after_bytes).hexdigest())
                if kind == "bytes":
                    self.assertEqual(before_bytes, b"original manifest bytes\n")
                    self.assertEqual(after_bytes, b"changed manifest bytes!\n")
                    self.assertNotEqual(before["snapshot"]["sha256"], after["snapshot"]["sha256"])
                else:
                    self.assertEqual(before_bytes, after_bytes)
                    self.assertEqual(before["snapshot"]["sha256"], after["snapshot"]["sha256"])
                    self.assertNotEqual(before["identity"]["mode"], after["identity"]["mode"])
                    self.assertEqual(int(after["identity"]["mode"]) & 0o777, 0o600)
                self.assertEqual(event["capture_errors"], [])
                self.manifest.chmod(0o644)

    def test_candidate_and_ancestor_symlinks_are_observed_without_opening_targets(self):
        target = self.root / "private-target"
        target.write_bytes(b"target must not be read through the candidate symlink")
        real_open = os.open
        for scope in ["candidate", "ancestor"]:
            with self.subTest(scope=scope):
                if scope == "candidate":
                    path = self.root / "link-candidate"
                    path.symlink_to(target)
                else:
                    link = self.root / "linked-directory"
                    link.symlink_to(self.source, target_is_directory=True)
                    path = link / "Cargo.toml"
                opened = []
                def checked_open(value, *args, **kwargs):
                    opened.append(str(value))
                    return real_open(value, *args, **kwargs)
                with mock.patch.object(M.os, "open", side_effect=checked_open), mock.patch.object(M.os, "readlink", wraps=os.readlink) as readlink:
                    row = M._parent_metadata_observe(self.capture, M.uuid.uuid4().hex,
                        {"path": str(path), "discovery_reasons": ["authored_symlink_case"]}, "before_original", 0)
                self.assertEqual(row["state"], "symlink", row)
                self.assertEqual(row["symlink_scope"], scope)
                self.assertTrue(readlink.called)
                self.assertNotIn(str(path), opened)
                self.assertNotIn(str(target), opened)
                self.assertNotIn("snapshot", row)
                self.assertEqual(target.read_bytes(), b"target must not be read through the candidate symlink")

    def test_mutation_during_selected_read_is_reached_and_later_candidates_survive(self):
        event = self.event(17)
        selected = self.manifest.stat()
        real_read = os.read
        reached = []
        def mutate(descriptor, size):
            raw = real_read(descriptor, size)
            value = os.fstat(descriptor)
            if raw and not reached and (value.st_dev, value.st_ino) == (selected.st_dev, selected.st_ino):
                reached.append(descriptor)
                self.manifest.write_bytes(b"X" * selected.st_size)
                os.utime(self.manifest, ns=(0, 0))
            return raw
        with mock.patch.object(M.os, "read", side_effect=mutate):
            self.before(event)
        rows = event["parent_metadata_v2"]["before_original"]
        self.assertTrue(reached)
        self.assertEqual(rows[0]["state"], "error")
        self.assertIn("changed during byte observation", rows[0]["error"]["message"])
        self.assertEqual(rows[1]["state"], "absent")
        self.assertEqual(event["upstream_exit_code"], 17)
        self.assertTrue(event["capture_errors"])

    def test_zero_write_and_close_error_are_both_retained_without_hang_or_status_change(self):
        event = self.event(101)
        selected = []
        real_close = os.close
        def no_progress(descriptor, raw):
            selected.append(descriptor)
            return 0
        def close_then_fail(descriptor):
            real_close(descriptor)
            if selected and descriptor == selected[-1]:
                raise OSError("authored snapshot close failure after real close")
        with mock.patch.object(M.os, "write", side_effect=no_progress), mock.patch.object(M.os, "close", side_effect=close_then_fail):
            self.before(event)
        self.assertTrue(selected)
        row = event["parent_metadata_v2"]["before_original"][0]
        self.assertEqual(row["state"], "error")
        self.assertEqual([p["phase"] for p in row["error"]["problems"]], ["snapshot_write", "snapshot_close"])
        self.assertIn("zero-progress", row["error"]["message"])
        self.assertEqual(event["upstream_exit_code"], 101)
        self.assertTrue(Path(row["snapshot_path"]).exists())
        self.assertEqual(event["parent_metadata_v2"]["before_original"][1]["state"], "absent")

    def test_real_observe_completion_seam_is_inert_and_retains_original_status_on_hook_failure(self):
        for status in [0, 7, -signal.SIGTERM]:
            with self.subTest(status=status):
                calls = []
                retained = []
                session = {"original_cargo": {"path": "/not-executed/cargo"}, "observer_worker": {},
                    "source_capture_worker": {}, "source_capture": str(self.capture),
                    "graph_query_enabled": False, "parent_metadata_schema": M.PARENT_METADATA_SCHEMA}
                def popen(command, **kwargs):
                    calls.append((command, kwargs))
                    return type("InertProcess", (), {"pid": 12345})()
                def finish(directory, event, result):
                    retained.append(copy.deepcopy(event))
                    return result
                expected_environment = dict(os.environ)
                with mock.patch.object(M, "read_artifact", side_effect=OSError("inert preceding capture failure")), \
                     mock.patch.object(M, "write_json", return_value={"path": "/unused", "bytes": 0, "sha256": "0" * 64}), \
                     mock.patch.object(M.subprocess, "Popen", side_effect=popen), \
                     mock.patch.object(M, "wait_original", return_value=(status, None)), \
                     mock.patch.object(M, "finish", side_effect=finish), \
                     mock.patch.object(M, "_parent_metadata_candidates", return_value=[]), \
                     mock.patch.object(M, "_parent_metadata_after", side_effect=RuntimeError("inert final metadata failure")):
                    result = M.observe(self.capture, session, ["build", "--locked"])
                self.assertEqual(result, status)
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0][0], ["/not-executed/cargo", "build", "--locked"])
                self.assertIs(calls[0][1]["close_fds"], False)
                self.assertEqual(calls[0][1]["env"], expected_environment)
                self.assertEqual(set(calls[0][1]), {"env", "close_fds"})
                self.assertEqual(retained[0]["upstream_exit_code"], status)
                self.assertTrue(any("inert final metadata failure" in value for value in retained[0]["capture_errors"]))
                self.assertEqual(retained[0]["parent_metadata_v2"]["hook_errors"][0]["phase"], "after_attempt_hook")


    def test_failed_original_spawn_retains_127_and_final_attempt_metadata(self):
        retained = []
        session = {"original_cargo": {"path": "/not-executed/cargo"}, "observer_worker": {},
            "source_capture_worker": {}, "source_capture": str(self.capture),
            "graph_query_enabled": False, "parent_metadata_schema": M.PARENT_METADATA_SCHEMA}
        def finish(directory, event, status):
            retained.append(copy.deepcopy(event))
            return status
        with mock.patch.object(M, "read_artifact", side_effect=OSError("inert preceding capture failure")), \
             mock.patch.object(M, "write_json", return_value={"path": "/unused", "bytes": 0, "sha256": "0" * 64}), \
             mock.patch.object(M.subprocess, "Popen", side_effect=OSError("inert original spawn failure")) as popen, \
             mock.patch.object(M, "finish", side_effect=finish), \
             mock.patch.object(M, "_parent_metadata_candidates", return_value=[]):
            status = M.observe(self.capture, session, ["build"])
        self.assertEqual(popen.call_count, 1)
        self.assertEqual(status, 127)
        self.assertEqual(retained[0]["upstream_exit_code"], 127)
        self.assertEqual(retained[0]["upstream_spawn_error"], "inert original spawn failure")
        metadata = retained[0]["parent_metadata_v2"]
        self.assertTrue(metadata["after_attempt_observed"])
        self.assertEqual(metadata["original_launch_state"], "UNKNOWN")
        self.assertFalse(metadata["native_completion_known"])
        self.assertIsNone(metadata["native_exit_code"])
        self.assertEqual(metadata["reported_upstream_exit_code"], 127)
        self.assertEqual(metadata["original_completion_kind"], "UNKNOWN")
        self.assertFalse(metadata["quiescence_established"])


    def test_returned_pid_wait_error_keeps_native_completion_unknown(self):
        retained = []
        session = {"original_cargo": {"path": "/not-executed/cargo"}, "observer_worker": {},
            "source_capture_worker": {}, "source_capture": str(self.capture),
            "graph_query_enabled": False, "parent_metadata_schema": M.PARENT_METADATA_SCHEMA}
        def finish(directory, event, status):
            retained.append(copy.deepcopy(event))
            return status
        process = type("InertProcess", (), {"pid": 32123})()
        with mock.patch.object(M, "read_artifact", side_effect=OSError("inert preceding capture failure")), \
             mock.patch.object(M, "write_json", return_value={"path": "/unused", "bytes": 0, "sha256": "0" * 64}), \
             mock.patch.object(M.subprocess, "Popen", return_value=process) as popen, \
             mock.patch.object(M, "wait_original", side_effect=OSError("inert wait failure")), \
             mock.patch.object(M, "finish", side_effect=finish), \
             mock.patch.object(M, "_parent_metadata_candidates", return_value=[]):
            status = M.observe(self.capture, session, ["build"])
        self.assertEqual(popen.call_count, 1)
        self.assertEqual(status, 127)  # Existing adapter report, never claimed native exit.
        event = retained[0]
        lifecycle = event["original_command_observation_v2"]
        self.assertTrue(lifecycle["constructor_entered"])
        self.assertTrue(lifecycle["constructor_returned"])
        self.assertEqual(lifecycle["pid"], 32123)
        self.assertFalse(lifecycle["wait_returned"])
        metadata = event["parent_metadata_v2"]
        self.assertEqual(metadata["original_launch_state"], "pid_returned")
        self.assertEqual(metadata["original_completion_kind"], "UNKNOWN")
        self.assertFalse(metadata["native_completion_known"])
        self.assertIsNone(metadata["native_exit_code"])
        self.assertFalse(metadata["quiescence_established"])
        self.assertEqual(metadata["reported_upstream_exit_code"], 127)

    def test_post_attempt_snapshots_cannot_upgrade_unknown_native_completion(self):
        for returned in [False, True]:
            with self.subTest(returned=returned):
                event = self.event(127)
                lifecycle = event["original_command_observation_v2"]
                lifecycle["wait_returned"] = False
                lifecycle["constructor_returned"] = returned
                lifecycle["pid"] = 12345 if returned else None
                if not returned:
                    event.pop("upstream_started")
                    event.pop("upstream_pid")
                event["upstream_spawn_error"] = "inert unresolved constructor/wait outcome"
                self.before(event)
                self.after(event)
                self.verify(event)
                metadata = event["parent_metadata_v2"]
                self.assertTrue(metadata["after_attempt_observations_complete"])
                self.assertFalse(metadata["native_completion_known"])
                self.assertIsNone(metadata["native_exit_code"])
                self.assertFalse(metadata["quiescence_established"])
                changed = copy.deepcopy(event)
                changed["parent_metadata_v2"]["native_completion_known"] = True
                changed["parent_metadata_v2"]["native_exit_code"] = 127
                with self.assertRaises(ValueError):
                    self.verify(changed)

    def test_verifier_refuses_dropped_reordered_or_promoted_metadata(self):
        event = self.event()
        self.before(event)
        self.after(event)
        self.verify(event)
        for kind in ["drop", "order", "promote", "delta"]:
            changed = copy.deepcopy(event)
            record = changed["parent_metadata_v2"]
            if kind == "drop": record["after_attempt"].pop()
            elif kind == "order": record["before_original"].reverse()
            elif kind == "promote": record["cargo_consumption_proven"] = True
            else: record["changes"] = [{"invented": True}]
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.verify(changed)

    def test_query_cancel_keeps_original_metadata_explicitly_unattempted(self):
        event = self.event()
        event["upstream_started"] = False
        event.pop("upstream_pid")
        event["original_command_observation_v2"] = M._parent_original_lifecycle_empty()
        event["observer_cancelled_before_upstream"] = int(signal.SIGTERM)
        self.assertIs(type(event["observer_cancelled_before_upstream"]), int)
        event.pop("upstream_exit_code")
        M._verify_parent_metadata_v2(event["parent_metadata_v2"], event, self.environment)
        self.assertFalse(event["parent_metadata_v2"]["before_original_attempted"])
        self.assertFalse(event["parent_metadata_v2"]["after_attempt_observed"])
        event["upstream_started"] = True
        with self.assertRaises(ValueError):
            M._verify_parent_metadata_v2(event["parent_metadata_v2"], event, self.environment)


if __name__ == "__main__":
    unittest.main()
