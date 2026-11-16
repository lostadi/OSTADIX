"""Synthetic original-archive dispatch/materialization controls; no real extractor qualification."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
# Historical provenance only; never a current-loader fallback.
PAX_PREDECESSOR_WORKER_SHA = "26788e75cfd6906193a759ecf1e207df7369b04adeeb1afe8931e754d514f540"
EXPECTED_WORKER_SHA = "9d39df4e18aae07ee7a869b6c8c1539c6a47bf8e72c3fe6201d8e1f0ad94d20b"
EXPECTED_WORKER_BYTES = 253120


def load_selected_worker():
    path = ROOT / "scripts/ocore_runtime_capture.py"
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                              s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or identity(path.lstat()) != identity(before):
            raise AssertionError("selected archive worker held/named file differs")
        chunks, offset = [], 0
        while True:
            part = os.pread(descriptor, 1048576, offset)
            if not part:
                break
            chunks.append(part)
            offset += len(part)
        raw = b"".join(chunks)
        if len(raw) != EXPECTED_WORKER_BYTES or hashlib.sha256(raw).hexdigest() != EXPECTED_WORKER_SHA:
            raise AssertionError("selected archive worker whole-byte pin differs")
        module = types.ModuleType("selected_original_archive_worker")
        module.__file__ = str(path)
        exec(compile(raw, str(path), "exec"), module.__dict__)
        if identity(os.fstat(descriptor)) != identity(before) or identity(path.lstat()) != identity(before):
            raise AssertionError("selected archive worker post-load native identity differs")
        return module
    finally:
        os.close(descriptor)


class OriginalArchiveOriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker = load_selected_worker()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.input = self.root / "input"
        self.output = self.root / "output"
        self.input.mkdir()
        self.output.mkdir()
        self.archive = self.input / "original.tar"
        self.payload = b"int original_fixture(void) { return 7; }\n"
        self.make_tar([("pkg", "directory", None), ("pkg/hello.c", "file", self.payload)])
        self.tool = self.root / "fixture-extractor"
        self.tool.write_bytes(b"#!/synthetic/extractor-not-executed\n")
        self.tool.chmod(0o500)
        archive_pin = {"file": self.archive.name, "bytes": self.archive.stat().st_size,
                       "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest()}
        tree = {"schema": "ocore-original-archive-logical-source-tree-v1", "entries": [
            {"path": "hello.c", "kind": "file", "mode": 0o644, "bytes": len(self.payload),
             "sha256": hashlib.sha256(self.payload).hexdigest()}]}
        # Selected before the actual dispatch and independent of the production tree reader.
        expected = hashlib.sha256(json.dumps(tree, sort_keys=True, separators=(",", ":"),
                                            ensure_ascii=True).encode("ascii")).hexdigest()
        self.source = {"kind": "original-archive-v1", "name": "fixture-engine", "version": "1",
                       "url": "https://example.invalid/original.tar", "archive": archive_pin,
                       "extractor": {"path": str(self.tool), "bytes": self.tool.stat().st_size,
                                     "sha256": hashlib.sha256(self.tool.read_bytes()).hexdigest()},
                       "extraction": {"profile": "gnu-tar-strip-v1", "strip_components": 1},
                       "expected_tree_sha256": expected, "source_date_epoch": 123,
                       "authentication": {"mode": "caller-pinned"}}
        self.recipe = {"schema": self.worker.RECIPE_SCHEMA, "name": "synthetic-original-archive-control",
                       "source": self.source, "toolchain": {"llvm_version": "22.1.6"},
                       "commands": [{"argv": ["fixture-never-compiled"]}],
                       "coverage": {"required_units": [{"id": "whole-fixture", "source": "hello.c",
                                                          "kind": "clang", "producer": "clang-llvm-v1"}]}}
        self.calls = []

    def make_tar(self, entries):
        with tarfile.open(self.archive, "w", format=tarfile.PAX_FORMAT) as archive:
            for name, kind, value in entries:
                info = tarfile.TarInfo(name)
                info.mode = 0o755 if kind == "directory" else 0o644
                if kind == "directory":
                    info.type = tarfile.DIRTYPE
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = value
                elif kind == "hardlink":
                    info.type = tarfile.LNKTYPE
                    info.linkname = value
                elif kind == "special":
                    info.type = tarfile.FIFOTYPE
                else:
                    info.size = len(value)
                archive.addfile(info, io.BytesIO(value) if kind == "file" else None)

    def fake_extract(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        self.assertEqual(kwargs["env"]["SOURCE_DATE_EPOCH"], "123")
        self.assertEqual(argv[1:3], ["--extract", "--file"])
        self.assertEqual(argv[-4:], ["--strip-components=1", "--no-same-owner", "--same-permissions", "--delay-directory-restore"])
        tool_fd, archive_fd, tree_fd = kwargs["pass_fds"]
        self.assertEqual(argv[0], f"/proc/self/fd/{tool_fd}")
        self.assertEqual(argv[3], f"/proc/self/fd/{archive_fd}")
        self.assertEqual(argv[5], f"/proc/self/fd/{tree_fd}")
        self.assertEqual(os.fstat(archive_fd).st_size, self.source["archive"]["bytes"])
        descriptor = os.open("hello.c", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o644, dir_fd=tree_fd)
        try:
            os.write(descriptor, self.payload)
            os.fchmod(descriptor, 0o644)
        finally:
            os.close(descriptor)
        os.write(kwargs["stdout"], b"synthetic extractor fixture; no native extractor invoked\n")
        return types.SimpleNamespace(returncode=0)

    def materialize(self, action=None):
        with mock.patch.object(self.worker.subprocess, "run", side_effect=action or self.fake_extract):
            return self.worker.verify_source_origin(self.recipe, self.input, directory=self.output)

    def receipt(self):
        return json.loads((self.output / "source-origin/materialization.json").read_bytes())

    def replace_receipt(self, context, mutation):
        path = Path(context["materialization"]["path"])
        value = json.loads(path.read_bytes())
        mutation(value)
        path.chmod(0o600)
        path.write_text(json.dumps(value, sort_keys=True))
        path.chmod(0o400)
        context["materialization"] = self.worker._archive_pin(path)

    def test_real_dispatch_materialization_and_revalidation_preserve_selected_source(self):
        registry_path = ROOT / "scripts/ocore_producer_registry.json"
        registry_raw = registry_path.read_bytes()
        self.assertEqual(hashlib.sha256(registry_raw).hexdigest(), "62d74350f9b97db882f96ccb04fb985ff519e45d648b2f977664c2e631ff4052")
        self.worker.validate_recipe(self.recipe, registry=json.loads(registry_raw))
        before = self.archive.read_bytes()
        context = self.materialize()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.archive.read_bytes(), before)
        self.assertEqual(context["kind"], "original-archive-v1")
        self.assertEqual(Path(context["path"]).joinpath("hello.c").read_bytes(), self.payload)
        self.assertEqual(context["tree"]["sha256"], self.source["expected_tree_sha256"])
        self.assertEqual(context["archive_safety"]["members"], 2)
        self.assertTrue(context["archive_safety"]["all_regular_member_bytes_hashed"])
        self.assertEqual(context["finalization"]["known_close_count"], 8)
        self.assertTrue(all(row["known"] is True for row in context["finalization"]["closes"]))
        self.assertFalse(context["authentication"]["authenticated"])
        for key in ("source_ownership_qualified", "capture_admitted", "runtime_qualified",
                    "extractor_interpreter_children_libraries_qualified"):
            self.assertIs(context[key], False)
        observed = self.worker.verify_source_origin(self.recipe, Path(context["path"]), context=context)
        self.assertIs(observed, context)
        self.assertEqual(len(self.calls), 1)

    def test_descriptor_rejects_mixed_missing_unknown_and_boolean_fields(self):
        changes = [("missing-tree", lambda x: x.pop("expected_tree_sha256")),
                   ("mixed-git", lambda x: x.update(revision="0" * 40)),
                   ("mixed-dsc", lambda x: x.update(dsc={})),
                   ("unknown", lambda x: x.update(extra=True)),
                   ("boolean-epoch", lambda x: x.update(source_date_epoch=False)),
                   ("boolean-strip", lambda x: x["extraction"].update(strip_components=True)),
                   ("unknown-format", lambda x: x["extraction"].update(profile="arbitrary-executable")),
                   ("auth-claim", lambda x: x["authentication"].update(signed_metadata_verified=True)),
                   ("malformed-hash", lambda x: x.update(expected_tree_sha256="not-a-digest"))]
        for name, change in changes:
            with self.subTest(name=name):
                source = copy.deepcopy(self.source)
                change(source)
                with self.assertRaises(self.worker.CaptureError):
                    self.worker.validate_archive_source(source)
        self.assertEqual(self.calls, [])

    def test_legacy_git_and_debian_dispatch_remain_distinct(self):
        git = {"source": {"url": "fixture", "revision": "0" * 40}}
        token = object()
        with mock.patch.object(self.worker, "verify_source", return_value=token) as action:
            self.assertIs(self.worker.verify_source_origin(git, self.input), token)
            action.assert_called_once_with(git, self.input)
        debian = {"source": {"kind": "debian-source-v1"}}
        with mock.patch.object(self.worker, "_debian_materialize", return_value=token) as action:
            self.assertIs(self.worker.verify_source_origin(debian, self.input, directory=self.output), token)
            action.assert_called_once_with(debian, self.input, self.output)
        with mock.patch.object(self.worker, "_debian_revalidate", return_value=token) as action:
            self.assertIs(self.worker.verify_source_origin(debian, self.input, context={}), token)
            action.assert_called_once_with(debian, self.input, {})
        for source in ({"url": "fixture", "revision": "0" * 40, "archive": self.source["archive"]},
                       {"kind": "original-archive-v0"}):
            with self.assertRaises(self.worker.CaptureError):
                self.worker.source_origin_kind(source)

    def test_epoch_is_explicit_and_git_debian_behavior_is_preserved(self):
        environment = {}
        self.worker.source_default_epoch(environment, {"kind": "original-archive-v1", "source_date_epoch": 123})
        self.assertEqual(environment, {"SOURCE_DATE_EPOCH": "123"})
        with self.assertRaisesRegex(self.worker.CaptureError, "epoch"):
            self.worker.source_default_epoch({"SOURCE_DATE_EPOCH": "999"}, {"kind": "original-archive-v1", "source_date_epoch": 123})
        environment = {"SOURCE_DATE_EPOCH": "999"}
        self.worker.source_default_epoch(environment, {"commit_timestamp": "456"})
        self.assertEqual(environment["SOURCE_DATE_EPOCH"], "999")
        self.worker.source_default_epoch(environment, {"kind": "debian-source-v1"})
        self.assertNotIn("SOURCE_DATE_EPOCH", environment)

    def test_complete_tar_preflight_rejects_unsafe_members_without_extracting(self):
        cases = [("absolute", [("/outside", "file", b"x")], "unsafe archive member"),
                 ("traversal", [("pkg/../outside", "file", b"x")], "traversal"),
                 ("duplicate", [("pkg/hello", "file", b"x"), ("pkg/./hello", "file", b"y")], "duplicate"),
                 ("hardlink", [("pkg/link", "hardlink", "pkg/body")], "hardlink"),
                 ("special", [("pkg/fifo", "special", None)], "special"),
                 ("escaping-link", [("pkg/link", "symlink", "../../outside")], "escaping"),
                 ("growing-cycle", [("pkg/a", "symlink", "a/x")], "cyclic"),
                 ("two-link-cycle", [("pkg/a", "symlink", "b"), ("pkg/b", "symlink", "a")], "cyclic"),
                 ("directory-cycle", [("pkg/d", "directory", None), ("pkg/d/back", "symlink", "..")], "cyclic"),
                 ("link-parent", [("pkg/a", "symlink", "inside"), ("pkg/a/body", "file", b"x")], "ancestor"),
                 ("stripped-file", [("body", "file", b"x")], "discard")]
        with mock.patch.object(self.worker.subprocess, "run", side_effect=AssertionError("extractor must not run")) as action:
            for name, entries, reason in cases:
                with self.subTest(name=name):
                    self.make_tar(entries)
                    selected = self.worker._archive_pin(self.archive)
                    with self.assertRaisesRegex(self.worker.CaptureError, reason):
                        self.worker._archive_tar_inventory(self.archive, selected, 1)
            action.assert_not_called()

    def test_safe_internal_and_dangling_links_remain_data_not_authentication(self):
        self.make_tar([("pkg", "directory", None), ("pkg/body", "file", self.payload),
                       ("pkg/link", "symlink", "body"), ("pkg/dangling", "symlink", "later-generated")])
        inventory = self.worker._archive_tar_inventory(self.archive, self.worker._archive_pin(self.archive), 1)
        self.assertEqual(inventory["members"], 4)
        self.assertEqual({row["path"] for row in inventory["manifest"]["entries"]}, {"", "body", "link", "dangling"})
        self.assertTrue(inventory["all_regular_member_bytes_hashed"])
        self.assertFalse(inventory["hardlinks_special_files_symlink_ancestors_allowed"])

    def test_prior_expected_tree_mismatch_retains_known_native_zero_without_context(self):
        self.source["expected_tree_sha256"] = "0" * 64
        with self.assertRaisesRegex(self.worker.CaptureError, "native_exit=0.*logical tree"):
            self.materialize()
        self.assertEqual(len(self.calls), 1)
        receipt = self.receipt()
        self.assertIs(receipt["native_terminal_known"], True)
        self.assertEqual(receipt["exit_code"], 0)
        self.assertIs(receipt["materialization_observed"], False)
        self.assertTrue(receipt["errors"])
        self.assertTrue((self.output / "source-origin/extractor-terminal.json").is_file())

    def test_constructor_exception_never_consumes_generated_log_or_tree(self):
        sentinel = RuntimeError("synthetic constructor entered then raised")
        def action(argv, **kwargs):
            self.fake_extract(argv, **kwargs)
            raise sentinel
        log = self.output / "source-origin/extract.log"
        original_pin, original_held = self.worker._archive_pin, self.worker._archive_held_pin
        counts = {"log_pin": 0, "held_log": 0, "tree": 0}
        def pin(path, *args, **kwargs):
            counts["log_pin"] += Path(path) == log
            return original_pin(path, *args, **kwargs)
        def held(descriptor, path):
            counts["held_log"] += Path(path) == log
            return original_held(descriptor, path)
        with mock.patch.object(self.worker, "_archive_pin", side_effect=pin), \
             mock.patch.object(self.worker, "_archive_held_pin", side_effect=held), \
             mock.patch.object(self.worker, "_archive_source_tree", side_effect=AssertionError("UNKNOWN tree consumption")) as tree:
            with self.assertRaisesRegex(self.worker.CaptureError, "native_terminal_known=False.*synthetic constructor"):
                self.materialize(action)
            tree.assert_not_called()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(counts, {"log_pin": 0, "held_log": 0, "tree": 0})
        self.assertTrue(log.read_bytes())
        self.assertEqual((self.output / "source-origin/source/hello.c").read_bytes(), self.payload)
        receipt = self.receipt()
        self.assertIs(receipt["constructor_entered"], True)
        self.assertIs(receipt["native_terminal_known"], False)
        self.assertIsNone(receipt["exit_code"])
        self.assertIs(receipt["generated_tree_and_log_consumption_skipped_unknown"], True)
        self.assertNotIn("log", receipt)
        self.assertTrue(all(row["known"] is True for row in receipt["file_closes"]))

    def test_boolean_false_returncode_is_unknown_not_success(self):
        def action(argv, **kwargs):
            self.fake_extract(argv, **kwargs)
            return types.SimpleNamespace(returncode=False)
        with mock.patch.object(self.worker, "_archive_source_tree", side_effect=AssertionError("boolean terminal tree consumption")) as tree:
            with self.assertRaisesRegex(self.worker.CaptureError, "not an exact integer"):
                self.materialize(action)
            tree.assert_not_called()
        self.assertEqual(len(self.calls), 1)
        self.assertIs(self.receipt()["native_terminal_known"], False)
        self.assertIsNone(self.receipt()["exit_code"])

    def test_known_nonzero_keeps_diagnostic_log_without_tree_consumption(self):
        def action(argv, **kwargs):
            self.fake_extract(argv, **kwargs)
            return types.SimpleNamespace(returncode=7)
        with mock.patch.object(self.worker, "_archive_source_tree", side_effect=AssertionError("failed extractor tree consumption")) as tree:
            with self.assertRaisesRegex(self.worker.CaptureError, "native_exit=7.*extractor failed"):
                self.materialize(action)
            tree.assert_not_called()
        receipt = self.receipt()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(receipt["exit_code"], 7)
        self.assertIs(receipt["native_terminal_known"], True)
        self.assertTrue(receipt["log"]["bytes"] > 0)

    def test_revalidation_rejects_boolean_exit_even_with_refreshed_exact_receipt_pin(self):
        context = self.materialize()
        self.replace_receipt(context, lambda value: value.update(exit_code=False))
        with self.assertRaisesRegex(self.worker.CaptureError, "exact native zero"):
            self.worker.verify_source_origin(self.recipe, Path(context["path"]), context=context)

    def test_revalidation_rejects_false_errors_and_incomplete_close_inventory(self):
        context = self.materialize()
        missing = copy.deepcopy(context)
        missing["finalization"]["closes"].pop()
        with self.assertRaisesRegex(self.worker.CaptureError, "closes are not known"):
            self.worker.verify_source_origin(self.recipe, Path(context["path"]), context=missing)
        self.replace_receipt(context, lambda value: value.update(errors=False))
        with self.assertRaisesRegex(self.worker.CaptureError, "empty list"):
            self.worker.verify_source_origin(self.recipe, Path(context["path"]), context=context)

    def test_same_bytes_replaced_extractor_inode_is_not_accepted(self):
        context = self.materialize()
        replacement = self.root / "replacement-tool"
        replacement.write_bytes(self.tool.read_bytes())
        replacement.chmod(0o500)
        self.assertNotEqual(replacement.stat().st_ino, self.tool.stat().st_ino)
        os.replace(replacement, self.tool)
        with self.assertRaisesRegex(self.worker.CaptureError, "physical input identity differs before reading"):
            self.worker.verify_source_origin(self.recipe, Path(context["path"]), context=context)

    def test_cold_extra_source_member_and_authenticity_claim_are_not_ignored(self):
        context = self.materialize()
        forged = copy.deepcopy(context)
        forged["authentication"]["authenticated"] = True
        with self.assertRaisesRegex(self.worker.CaptureError, "authenticity/admission"):
            self.worker.verify_source_origin(self.recipe, Path(context["path"]), context=forged)
        Path(context["path"]).joinpath("cold-extra.c").write_bytes(b"unselected cold body")
        with self.assertRaisesRegex(self.worker.CaptureError, "complete source tree"):
            self.worker.verify_source_origin(self.recipe, Path(context["path"]), context=context)

    def test_log_close_failure_is_reached_once_and_never_returns_source_context(self):
        real_close = self.worker.os.close
        reached = {"log_fd": None, "close_calls": 0}
        def action(argv, **kwargs):
            reached["log_fd"] = kwargs["stdout"]
            return self.fake_extract(argv, **kwargs)
        def close(descriptor):
            if descriptor == reached["log_fd"]:
                reached["close_calls"] += 1
                raise OSError("selected log close sentinel")
            return real_close(descriptor)
        try:
            with mock.patch.object(self.worker.os, "close", side_effect=close):
                with self.assertRaisesRegex(self.worker.CaptureError, "selected log close sentinel"):
                    self.materialize(action)
            self.assertEqual(reached["close_calls"], 1)
            self.assertEqual(len(self.calls), 1)
            self.assertTrue(any(row["known"] is False for row in self.receipt()["file_closes"]))
        finally:
            if reached["log_fd"] is not None:
                real_close(reached["log_fd"])

    def test_final_publication_failure_preserves_known_extractor_terminal(self):
        original = self.worker._archive_record
        def record(owner, owner_fd, name, value):
            if name == "materialization.json":
                raise OSError("final publication sentinel")
            return original(owner, owner_fd, name, value)
        with mock.patch.object(self.worker, "_archive_record", side_effect=record):
            with self.assertRaisesRegex(self.worker.CaptureError, "native_exit=0.*final publication sentinel"):
                self.materialize()
        terminal = json.loads((self.output / "source-origin/extractor-terminal.json").read_bytes())
        self.assertEqual(len(self.calls), 1)
        self.assertIs(terminal["native_terminal_known"], True)
        self.assertEqual(terminal["exit_code"], 0)
        self.assertFalse((self.output / "source-origin/materialization.json").exists())


if __name__ == "__main__":
    unittest.main()
