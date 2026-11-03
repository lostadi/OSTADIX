"""An ABI handoff must retain the package disk and fail without replacing a pair."""
import copy
import fcntl
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("plan9_namespace_import", ROOT / "scripts/import_okernel_plan9_namespace.py")
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


class NamespaceHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.area = Path(self.temporary.name)
        self.state = self.area / "fork"
        self.state.mkdir()
        runner = handoff.runner
        (self.state / "disk-generations").mkdir()
        (self.state / "namespace-generations").mkdir()
        disk = self.state / "disk-generations/pending"
        with disk.open("xb") as stream:
            stream.truncate(536870912)
        disk = disk.rename(disk.with_name(runner.digest(disk) + ".ext4"))
        before = self.state / "namespace-generations/pending"
        with before.open("xb") as stream:
            stream.truncate(runner.NAMESPACE_GRANT["bytes"])
        before = before.rename(before.with_name(runner.digest(before) + ".raw"))
        self.head = {"schema": "ostadix.package-domain-disk-head/v2",
                     "disk": runner.identity(disk), "namespace": runner.identity(before),
                     "unrelated": {"retained": True}}
        runner.write_json(self.state / "head.json", self.head)
        self.head_bytes = (self.state / "head.json").read_bytes()
        runner.write_json(self.state / "fork.json", {"schema": "ostadix.okernel-state-fork/v1", "ok": True, "output": str(self.state)})
        after = self.area / "plan9-after.raw"
        with after.open("xb") as stream:
            stream.write(b"test export identity; native store checked by execution gate")
            stream.truncate(runner.NAMESPACE_GRANT["bytes"])
        self.proof = {"schema": "ostadix.plan9-native-namespace-probe/v1", "passed": True,
                      "namespace_before": runner.identity(before), "namespace_after": runner.identity(after),
                      "native_operations_quiescent_before_export": True, "virtual_cpu_stopped_before_export": True,
                      "roundtrip": {"path": "/work/original-plan9-test", "text": "nonce from original rc"}}
        self.proof_file = self.area / "result.json"
        self.write_proof()

    def write_proof(self):
        self.proof_file.write_text(json.dumps(self.proof))

    def assert_retained(self):
        self.assertEqual((self.state / "head.json").read_bytes(), self.head_bytes)

    def test_import_publishes_one_pair_retaining_disk_old_namespace_and_metadata(self):
        selected = handoff.import_namespace(self.state, self.proof_file)
        self.assertEqual(selected["disk"], self.head["disk"])
        self.assertEqual(selected["previous_namespace"], self.head["namespace"])
        self.assertEqual(selected["unrelated"], {"retained": True})
        self.assertEqual(selected["namespace"]["sha256"], self.proof["namespace_after"]["sha256"])
        target = Path(selected["namespace"]["path"])
        self.assertNotEqual(target.stat().st_ino, Path(self.proof["namespace_after"]["path"]).stat().st_ino)
        self.assertEqual(target.stat().st_mode & 0o777, 0o400)
        self.assertTrue(Path(self.head["namespace"]["path"]).is_file())

    def test_live_fork_lock_prevents_import(self):
        with (self.state / "domain.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, "stop the isolated"):
                handoff.import_namespace(self.state, self.proof_file)
        self.assert_retained()

    def test_default_state_and_nonfork_are_not_import_targets(self):
        with patch.object(handoff.runner, "DEFAULT_STATE", self.state):
            with self.assertRaisesRegex(ValueError, "working default"):
                handoff.import_namespace(self.state, self.proof_file)
        (self.state / "fork.json").write_text('{}')
        with self.assertRaisesRegex(ValueError, "isolated state fork"):
            handoff.import_namespace(self.state, self.proof_file)
        self.assert_retained()

    def test_configured_working_state_is_not_an_import_target(self):
        selected = self.area / "custom-parent/package-domain"
        selected.parent.mkdir()
        self.state.rename(selected)
        with patch.dict(handoff.os.environ, {"OSTADIX_OKERNEL_STATE": str(selected.parent)}):
            with self.assertRaisesRegex(ValueError, "working default"):
                handoff.import_namespace(selected, self.proof_file)
        self.assertEqual((selected / "head.json").read_bytes(), self.head_bytes)

    def test_failed_or_nonquiescent_probe_cannot_replace_head(self):
        original = copy.deepcopy(self.proof)
        for flag in ("passed", "native_operations_quiescent_before_export", "virtual_cpu_stopped_before_export"):
            with self.subTest(flag=flag):
                self.proof = copy.deepcopy(original)
                self.proof[flag] = False
                self.write_proof()
                with self.assertRaises(ValueError):
                    handoff.import_namespace(self.state, self.proof_file)
                self.assert_retained()

    def test_tampered_export_is_not_imported(self):
        with Path(self.proof["namespace_after"]["path"]).open("r+b") as stream:
            stream.write(b"tampered")
        with self.assertRaisesRegex(ValueError, "recorded identity"):
            handoff.import_namespace(self.state, self.proof_file)
        self.assert_retained()

    def test_exact_nonce_content_allows_one_trailing_newline_but_no_extra_lines(self):
        self.proof["roundtrip"]["text"] += "\n"
        handoff.validate_proof(self.proof)
        self.proof["roundtrip"]["text"] += "\n"
        with self.assertRaisesRegex(ValueError, "nonce line"):
            handoff.validate_proof(self.proof)

    def test_stale_input_namespace_cannot_replace_newer_pair(self):
        self.proof["namespace_before"] = self.proof["namespace_after"]
        self.proof["namespace_after"] = self.head["namespace"]
        self.write_proof()
        with self.assertRaisesRegex(ValueError, "different namespace"):
            handoff.import_namespace(self.state, self.proof_file)
        self.assert_retained()

    def test_copy_failure_leaves_no_pending_file_or_head_change(self):
        with patch.object(handoff.shutil, "copyfileobj", side_effect=OSError("copy failed")):
            with self.assertRaisesRegex(OSError, "copy failed"):
                handoff.import_namespace(self.state, self.proof_file)
        self.assert_retained()
        self.assertEqual(list((self.state / "namespace-generations").glob("pending-*")), [])

    def test_atomic_publication_failure_retains_old_selected_pair(self):
        with patch.object(handoff.runner, "write_json", side_effect=OSError("publication failed")):
            with self.assertRaisesRegex(OSError, "publication failed"):
                handoff.import_namespace(self.state, self.proof_file)
        self.assert_retained()

    def test_post_replacement_fsync_failure_reports_selected_but_uncertain_durability(self):
        original = handoff.runner.fsync_directory
        def fail_final_sync(path):
            if path == self.state:
                raise OSError("directory sync failed after replacement")
            return original(path)
        with patch.object(handoff.runner, "fsync_directory", side_effect=fail_final_sync):
            with self.assertRaisesRegex(handoff.NamespaceCommitUncertain, "new namespace pair is selected"):
                handoff.import_namespace(self.state, self.proof_file)
        selected = json.loads((self.state / "head.json").read_text())
        self.assertEqual(selected["disk"], self.head["disk"])
        self.assertEqual(selected["namespace"]["sha256"], self.proof["namespace_after"]["sha256"])
        self.assertTrue(Path(self.head["namespace"]["path"]).is_file())

    def test_symlink_control_and_generation_aliases_are_rejected(self):
        for control in ("domain.lock", "head.json"):
            with self.subTest(control=control):
                selected = self.state / control
                original = selected.read_bytes() if selected.exists() else None
                selected.unlink(missing_ok=True)
                selected.symlink_to(self.proof_file)
                with self.assertRaises(ValueError):
                    handoff.import_namespace(self.state, self.proof_file)
                selected.unlink()
                if original is not None:
                    selected.write_bytes(original)
        self.assert_retained()


if __name__ == "__main__":
    unittest.main()
