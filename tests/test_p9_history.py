"""Real file/archive/protocol cleanup tests; no Plan9 execution or guest boot."""
from contextlib import redirect_stdout
import fcntl
from importlib.machinery import SourceFileLoader
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ocore/guest/linux/package-domain/p9-history"
LOADER = SourceFileLoader("p9_history_test", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
history = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(history)


class P9HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p9 history fixture ")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        companion = self.base / "protocol.py"
        companion.write_bytes((ROOT / "ocore/guest/plan9/unified/protocol.py").read_bytes())
        companion.chmod(0o600)
        self.protocol = history.load_protocol(companion)
        self.control, self.root, self.archive = self.base / "control", self.base / "native/services/plan9", self.base / "archive"
        self.control.mkdir(mode=0o700)
        (self.control / "results").mkdir(mode=0o700)
        self.g, self.s = "1234567890abcdef", "1" * 32
        self.current = self.root / ("g" + self.g) / ("s" + self.s)
        self.current.mkdir(parents=True)
        self.put(self.current / "ready", self.protocol.ready_marker(self.g, self.s))
        self.mapping = {"service_root": str(self.root), "linux_mount": str(self.base / "native"), "plan9_mount": "/n"}
        self.session = {"schema": "ostadix.p9.client-session/v1", "generation": self.g, "instance": self.s,
                        **self.mapping, "recovery_mode": "controller-v1", "state": "ready", "program_dir": "/arm64/bin"}
        self.put(self.control / "current.json", history.encoded(self.session))

    def subject(self):
        return history.History(self.control, self.protocol, archive=self.archive, mapping=self.mapping)

    def put(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)

    def job(self, number, *, receipt=True, status=b"", output=b"stdout\x00\xff", flags=0, **changes):
        p = self.protocol
        request_id = "%032x" % number
        path = self.current / ("r" + request_id)
        path.mkdir()
        wire = p.encode_request(self.g, self.s, request_id, ["/arm64/bin/echo", "two words"], cwd="/n/work",
                                stdin=b"input\x00\xff", timeout_ms=30000, stdout_limit=1048576, stderr_limit=1048576)
        result = p.encode_result(wire, flags=flags, stdout=output, stderr=b"stderr\x00\xfe", status=status)
        files = {"request": wire, "submit": p.submit_marker(wire), "started": p.submit_marker(wire), "stdout": output,
                 "stderr": b"stderr\x00\xfe", "status": status, "result": result, "done": p.done_marker(wire, result)}
        for name, data in files.items():
            self.put(path / name, data)
        decoded = p.decode_result(result)
        value = {"schema": "ostadix.p9.client-result/v1", "generation": self.g, "instance": self.s,
                 "request_id": request_id, "request_sha256": history.digest(wire), "service_root": str(self.root),
                 "result_sha256": history.digest(result), "flags": decoded.flags, "status_hex": status.hex(),
                 "stdout_bytes": decoded.stdout_bytes, "stderr_bytes": decoded.stderr_bytes,
                 "stdout_sha256": decoded.stdout_sha256, "stderr_sha256": decoded.stderr_sha256, "recovered": False}
        value.update(changes)
        if receipt:
            location = self.control / "results" / (request_id + ".json")
            self.put(location, json.dumps(value, indent=2).encode() + b"\n")
            os.utime(location, ns=(number * 1000000000, number * 1000000000))
        return path, files

    def published(self):
        return sorted(path for path in self.archive.iterdir() if len(path.name) == 64)

    def files(self, root):
        return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}

    def test_keep_newest_one_and_archive_exact_binary_history_before_deletion(self):
        jobs = [self.job(number, status=b"native failure\xff" if number == 1 else b"") for number in range(1, 4)]
        original_receipts = self.files(self.control / "results")
        with redirect_stdout(io.StringIO()) as output:
            self.subject().collect()
        self.assertEqual(output.getvalue(), "")
        self.assertFalse(jobs[0][0].exists())
        self.assertFalse(jobs[1][0].exists())
        self.assertTrue(all(path.exists() for path, _ in jobs[2:]))
        self.assertEqual(len(self.published()), 2)
        stored = {}
        for folder in self.published():
            manifest = json.loads((folder / "manifest.json").read_text())
            self.assertEqual(manifest["kind"], "completed-job")
            self.assertEqual(folder.name, history.digest(history.encoded(manifest)))
            request_id = Path(manifest["source_relative"]).name[1:]
            self.assertEqual((folder / "receipts" / (request_id + ".json")).read_bytes(), original_receipts[request_id + ".json"])
            stored[request_id] = self.files(folder / "native")
        self.assertEqual(stored["%032x" % 1], jobs[0][1])
        self.assertEqual(stored["%032x" % 2], jobs[1][1])
        self.assertEqual(self.files(self.control / "results"), original_receipts)
        self.assertEqual((self.current / "ready").read_bytes(), self.protocol.ready_marker(self.g, self.s))

    def test_current_unreceipted_incomplete_and_forged_jobs_remain(self):
        for number in range(1, 4):
            self.job(number)
        unreceipted, _ = self.job(50, receipt=False)
        incomplete, _ = self.job(51)
        (incomplete / "done").unlink()
        forged, _ = self.job(52, request_sha256="f" * 64)
        extra, _ = self.job(53)
        self.put(extra / "user-data", b"must survive")
        before = {path: self.files(path) for path in (unreceipted, incomplete, forged, extra)}
        self.subject().collect()
        for path, data in before.items():
            self.assertEqual(self.files(path), data)
        # The newest structurally valid private receipt can decide KEEP even
        # when its source digest is wrong. It never authorizes deletion; every
        # actually evicted older job still receives full protocol validation.
        self.assertEqual(len(self.published()), 3)

    def test_single_large_job_is_archived_even_when_it_is_the_only_job(self):
        large, files = self.job(1, output=b"\x00\xff" * (1048576 // 2))
        self.assertGreater(history.resident_charge(files, [""]), history.RESIDENT_BYTES)
        self.subject().collect()
        self.assertFalse(large.exists())
        self.assertEqual(len(self.published()), 1)
        self.assertEqual(self.files(self.published()[0] / "native"), files)
        self.assertTrue((self.control / "results" / ("%032x.json" % 1)).is_file())

    def test_combined_resident_budget_keeps_newest_fitting_jobs(self):
        first, first_files = self.job(1, output=b"a" * 700000)
        second, _ = self.job(2, output=b"b" * 700000)
        third, _ = self.job(3)
        with patch.object(history, "RESIDENT_JOBS", 8):
            self.subject().collect()
        self.assertFalse(first.exists())
        self.assertTrue(second.exists())
        self.assertTrue(third.exists())
        self.assertEqual(self.files(self.published()[0] / "native"), first_files)

    def test_retained_job_payload_is_never_reopened_or_rehashed(self):
        old, old_files = self.job(1)
        retained, retained_files = self.job(2)
        original = history.read
        def forbid_retained(path, *args, **kwargs):
            if retained == path.parent or retained in path.parents:
                raise AssertionError("retained payload must not be read")
            return original(path, *args, **kwargs)
        with patch.object(history, "read", forbid_retained):
            self.subject().collect()
            self.subject().collect()
        self.assertFalse(old.exists())
        self.assertEqual(self.files(retained), retained_files)
        self.assertEqual(self.files(self.published()[0] / "native"), old_files)

    def test_large_removed_source_archive_payload_is_not_read_again(self):
        job, files = self.job(1, output=b"x" * 1048576)
        self.subject().collect()
        self.assertFalse(job.exists())
        folder = self.published()[0]
        original = history.read
        def only_manifest(path, *args, **kwargs):
            if folder in path.parents and path.name != "manifest.json":
                raise AssertionError("removed-source archive payload/receipts must not be rehashed")
            return original(path, *args, **kwargs)
        with patch.object(history, "read", only_manifest):
            self.subject().collect()
        self.assertEqual(self.files(folder / "native"), files)

    def test_private_metadata_never_authorizes_evicting_changed_public_wire(self):
        old, files = self.job(1)
        self.job(2)
        (old / "request").write_bytes(b"changed unvalidated request")
        self.subject().collect()
        self.assertTrue(old.exists())
        self.assertEqual((old / "request").read_bytes(), b"changed unvalidated request")
        self.assertEqual(self.published(), [])

    def test_large_archive_publication_failure_preserves_original_bytes(self):
        large, files = self.job(1, output=b"L" * 1048576)
        with patch.object(history.os, "rename", side_effect=OSError("large archive refused")):
            with self.assertRaisesRegex(OSError, "large archive refused"):
                self.subject().collect()
        self.assertEqual(self.files(large), files)
        self.assertEqual(self.published(), [])

    def test_cold_generations_and_instances_archive_partial_unknown_bytes_unclassified(self):
        generation = self.root / ("g" + "2" * 16)
        old = generation / ("s" + "3" * 32)
        request = old / ("r" + "4" * 32)
        request.mkdir(parents=True)
        self.put(old / "ready", b"old readiness bytes\n")
        self.put(old / "reset-required", b"partial unknown reset")
        self.put(request / "request", b"unparsed partial wire\x00\xff")
        self.put(request / ".submit.pending.128", b"partial pending marker")
        self.put(request / ".interrupted", b"C")
        self.put(request / ".stdout.truncated", b"1")
        self.put(request / ".stderr.truncated", b"1")
        self.put(request / "..interrupted.pending.384", b"T")
        self.put(request / "..stdout.truncated.pending.76", b"1")
        self.put(request / "..stderr.truncated.pending.77", b"")
        instance = self.current.parent / ("s" + "5" * 32)
        instance.mkdir()
        self.put(instance / ".ready.pending.34", b"incomplete ready")
        expected_generation, expected_instance = self.files(generation), self.files(instance)
        self.subject().collect()
        self.assertFalse(generation.exists())
        self.assertFalse(instance.exists())
        archives = {json.loads((folder / "manifest.json").read_text())["kind"]: self.files(folder / "native") for folder in self.published()}
        self.assertEqual(archives["retired-generation-unclassified"], expected_generation)
        self.assertEqual(archives["retired-instance-unclassified"], expected_instance)
        self.assertTrue(self.current.exists())

    def test_current_truncation_public_result_validates_and_all_internal_bytes_archive(self):
        job, files = self.job(1, flags=self.protocol.FLAG_STDOUT_TRUNCATED | self.protocol.FLAG_STDERR_TRUNCATED)
        internal = {".stdout.truncated": b"1", ".stderr.truncated": b"1", "..stdout.truncated.pending.528": b"partial"}
        for name, data in internal.items():
            self.put(job / name, data)
        for number in range(2, 3):
            self.job(number)
        self.subject().collect()
        self.assertFalse(job.exists())
        self.assertEqual(self.files(self.published()[0] / "native"), {**files, **internal})
        receipt = json.loads(next((self.published()[0] / "receipts").iterdir()).read_text())
        self.assertEqual(receipt["flags"], self.protocol.FLAG_STDOUT_TRUNCATED | self.protocol.FLAG_STDERR_TRUNCATED)

    def test_internal_whitelist_does_not_accept_similar_unknown_names(self):
        for name in (".stdout.truncated.extra", "..stdout.truncated.pending.bad", "..stderr.truncated.pending.0",
                     "..interrupted.pending." + "a" * 24):
            with self.subTest(name=name):
                generation = self.root / ("g" + "2" * 16)
                job = generation / ("s" + "3" * 32) / ("r" + "4" * 32)
                job.mkdir(parents=True, exist_ok=True)
                target = job / name
                self.put(target, b"unknown must survive")
                self.subject().collect()
                self.assertEqual(target.read_bytes(), b"unknown must survive")
                self.assertEqual(self.published(), [])
                target.unlink()

    def test_unknown_extra_in_cold_tree_preserves_whole_generation(self):
        generation = self.root / ("g" + "2" * 16)
        instance = generation / ("s" + "3" * 32)
        instance.mkdir(parents=True)
        self.put(instance / "ready", b"ready")
        self.put(instance / "operator-notes", b"not protocol-owned")
        before = self.files(generation)
        self.subject().collect()
        self.assertEqual(self.files(generation), before)
        self.assertEqual(self.published(), [])

    def test_any_pending_entry_or_busy_client_disables_all_cleanup(self):
        for number in range(1, 4):
            self.job(number)
        before = self.files(self.root)
        self.put(self.control / "pending.json", b"even malformed unknown pending must survive")
        self.subject().collect()
        self.assertFalse(self.archive.exists())
        self.assertEqual(self.files(self.root), before)
        (self.control / "pending.json").unlink()
        fd = os.open(self.control / "client.lock", os.O_RDWR)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.subject().collect()
        self.assertFalse(self.archive.exists())
        self.assertEqual(self.files(self.root), before)

    def test_publish_failure_never_deletes_native_history(self):
        for number in range(1, 4):
            self.job(number)
        before = self.files(self.root)
        with patch.object(history.os, "rename", side_effect=OSError("simulated archive publication failure")):
            with self.assertRaisesRegex(OSError, "publication failure"):
                self.subject().collect()
        self.assertEqual(self.files(self.root), before)
        self.assertEqual(self.published(), [])
        self.subject().collect()
        self.assertEqual(len(self.published()), 2)

    def test_interrupted_native_deletion_resumes_from_verified_published_archive(self):
        jobs = [self.job(number) for number in range(1, 3)]
        original = Path.unlink
        called = False
        def interrupt(path, *args, **kwargs):
            nonlocal called
            if path.parent == jobs[0][0] and called:
                raise OSError("simulated interruption after one deletion")
            if path.parent == jobs[0][0]:
                called = True
            return original(path, *args, **kwargs)
        with patch.object(Path, "unlink", interrupt):
            with self.assertRaisesRegex(OSError, "after one deletion"):
                self.subject().collect()
        self.assertEqual(len(self.published()), 1)
        self.assertTrue(jobs[0][0].exists())
        self.assertLess(len(list(jobs[0][0].iterdir())), 8)
        self.subject().collect()
        self.assertFalse(jobs[0][0].exists())
        self.assertEqual(self.files(self.published()[0] / "native"), jobs[0][1])

    def test_changed_native_bytes_after_publication_are_preserved(self):
        jobs = [self.job(number) for number in range(1, 3)]
        original = history.History.archive_tree
        def changed(subject, *args, **kwargs):
            folder = original(subject, *args, **kwargs)
            (jobs[0][0] / "stdout").write_bytes(b"new unarchived bytes")
            return folder
        with patch.object(history.History, "archive_tree", changed):
            with self.assertRaisesRegex(history.HistoryError, "changed after archive"):
                self.subject().collect()
        self.assertEqual((jobs[0][0] / "stdout").read_bytes(), b"new unarchived bytes")
        self.assertEqual(len(list(jobs[0][0].iterdir())), 8)
        self.assertEqual((self.published()[0] / "native/stdout").read_bytes(), jobs[0][1]["stdout"])

    def test_corrupted_published_archive_cannot_authorize_resumed_deletion(self):
        jobs = [self.job(number) for number in range(1, 3)]
        subject = self.subject()
        with patch.object(subject, "delete_archived", side_effect=OSError("stop before delete")):
            with self.assertRaises(OSError):
                subject.collect()
        folder = self.published()[0]
        (folder / "native/request").write_bytes(b"corrupted archive")
        with self.assertRaisesRegex(history.HistoryError, "archived history bytes differ"):
            self.subject().collect()
        self.assertEqual(self.files(jobs[0][0]), jobs[0][1])

    def test_private_archive_symlink_world_write_and_nonlocal_fs_denial(self):
        for number in range(1, 3):
            self.job(number)
        before = self.files(self.root)
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        self.archive.symlink_to(outside)
        with self.assertRaises(history.HistoryError):
            self.subject().collect()
        self.archive.unlink()
        self.archive.mkdir(mode=0o777)
        self.archive.chmod(0o777)
        with self.assertRaises(history.HistoryError):
            self.subject().collect()
        with patch.object(history, "LOCAL_FS", set()):
            with self.assertRaises(history.HistoryError):
                self.subject().collect()
        self.assertEqual(self.files(self.root), before)
        self.assertEqual(list(outside.iterdir()), [])

    def test_production_archive_path_and_private_missing_parent_creation(self):
        self.assertEqual(history.ARCHIVE, Path("/var/lib/okernel/p9-history"))
        library = self.base / "var/lib"
        library.parent.mkdir(mode=0o755)
        library.mkdir(mode=0o755)
        self.archive = library / "okernel/p9-history"
        self.subject().collect()
        self.assertEqual(self.archive.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.archive.stat().st_mode & 0o777, 0o700)

    def test_world_writable_work_is_not_relaxed_or_used_for_private_archive(self):
        work = self.base / "work"
        work.mkdir(mode=0o777)
        work.chmod(0o777)
        self.archive = work / "private-parent/history"
        with self.assertRaises(history.HistoryError):
            self.subject().collect()
        self.assertEqual(work.stat().st_mode & 0o777, 0o777)
        self.assertFalse((work / "private-parent").exists())

    def test_native_symlink_unknown_jobs_and_invalid_private_mapping_are_preserved(self):
        outside = self.base / "outside"
        outside.mkdir()
        self.put(outside / "ready", b"outside")
        bad = self.current.parent / ("s" + "9" * 32)
        bad.symlink_to(outside, target_is_directory=True)
        self.subject().collect()
        self.assertTrue(bad.is_symlink())
        self.assertEqual((outside / "ready").read_bytes(), b"outside")
        self.session["service_root"] = str(outside)
        self.put(self.control / "current.json", history.encoded(self.session))
        with self.assertRaisesRegex(history.HistoryError, "session/mapping"):
            self.subject().collect()

    def test_recovery_state_and_current_reset_leave_current_jobs_and_markers(self):
        for number in range(1, 3):
            self.job(number)
        self.put(self.current / "reset-required", b"must remain")
        before = self.files(self.current)
        self.subject().collect()
        self.assertEqual(self.files(self.current), before)
        self.session["state"] = "recovering"
        self.put(self.control / "current.json", history.encoded(self.session))
        self.subject().collect()
        self.assertEqual(self.files(self.current), before)

    def test_session_change_after_archive_blocks_native_deletion(self):
        for number in range(1, 3):
            self.job(number)
        before = self.files(self.current)
        original = history.History.archive_tree
        def changed(subject, *args, **kwargs):
            folder = original(subject, *args, **kwargs)
            self.session["state"] = "recovering"
            self.put(self.control / "current.json", history.encoded(self.session))
            return folder
        with patch.object(history.History, "archive_tree", changed):
            with self.assertRaisesRegex(history.HistoryError, "session changed"):
                self.subject().collect()
        self.assertEqual(self.files(self.current), before)

    def test_archive_traversal_and_attempt_to_remove_current_generation_are_rejected(self):
        for name, kind in (("../outside", "retired-generation-unclassified"),
                           ("g" + self.g + "/s" + self.s + "/r../outside", "completed-job")):
            with self.assertRaises(history.HistoryError):
                history.owned_shape(name, kind)
        subject = self.subject()
        subject.collect()
        folder = subject.archive_tree("g" + self.g, "retired-generation-unclassified")
        with self.assertRaisesRegex(history.HistoryError, "current service"):
            subject.delete_archived(folder)
        self.assertTrue(self.current.exists())


if __name__ == "__main__":
    unittest.main()
