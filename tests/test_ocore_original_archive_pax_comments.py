"""Effective PAX-comment metadata controls; synthetic archives/bodies, no real extractor.

The path/mode/time/comment witness comes from the retained GNU 2.41 inventory.
This module neither reads that original archive nor authenticates/adopts GNU source.
Malformed decoded-header controls deliberately inject TarInfo values at the parser
boundary; they do not claim to qualify Python's raw PAX parser.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_WORKER_SHA = "3d43ce7507a49cf093bcc1e1a88d84e764a31ff6521660a8533e8f01aad9095a"
EXPECTED_WORKER_BYTES = 261585
COMMENT = "74f59e9271cbb4071671e5a474e7d4f1622b186f"
MEMBER = "glibc-2.41/.b4-config"
WITNESS_INVENTORY_SHA = "378ee5c4ab3fa8e1358e97c860aa2b9229996ea9ac72aeb9b8f5a668181deb2b"


def native(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def descriptor_bytes(fd):
    offset, chunks = 0, []
    while True:
        part = os.pread(fd, 1048576, offset)
        if not part:
            return b"".join(chunks)
        chunks.append(part)
        offset += len(part)


class OriginalArchivePaxCommentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker_path = ROOT / "scripts/ocore_runtime_capture.py"
        cls.worker_fd = os.open(cls.worker_path, os.O_RDONLY | os.O_NOFOLLOW)
        cls.addClassCleanup(cls.finish_worker)
        cls.worker_native = native(os.fstat(cls.worker_fd))
        if not stat.S_ISREG(cls.worker_native[2]) or cls.worker_native[5] != 1:
            raise AssertionError("selected PAX worker is not a private regular file")
        if native(cls.worker_path.lstat()) != cls.worker_native:
            raise AssertionError("selected PAX worker held/named mismatch")
        raw = descriptor_bytes(cls.worker_fd)
        if len(raw) != EXPECTED_WORKER_BYTES or hashlib.sha256(raw).hexdigest() != EXPECTED_WORKER_SHA:
            raise AssertionError("selected PAX worker whole-byte pin mismatch")
        cls.worker = types.ModuleType("selected_original_archive_pax_comment_worker")
        cls.worker.__file__ = str(cls.worker_path)
        exec(compile(raw, str(cls.worker_path), "exec"), cls.worker.__dict__)
        if native(os.fstat(cls.worker_fd)) != cls.worker_native or native(cls.worker_path.lstat()) != cls.worker_native:
            raise AssertionError("selected PAX worker changed during load")

    @classmethod
    def finish_worker(cls):
        failures = []
        try:
            raw = descriptor_bytes(cls.worker_fd)
            if native(os.fstat(cls.worker_fd)) != cls.worker_native or native(cls.worker_path.lstat()) != cls.worker_native:
                failures.append("selected PAX worker final held/named native mismatch")
            if len(raw) != EXPECTED_WORKER_BYTES or hashlib.sha256(raw).hexdigest() != EXPECTED_WORKER_SHA:
                failures.append("selected PAX worker final whole-byte pin mismatch")
        except BaseException as error:
            failures.append("selected PAX worker final guard: " + repr(error))
        try:
            os.close(cls.worker_fd)
        except BaseException as error:
            failures.append("selected PAX worker close: " + repr(error))
        if failures:
            raise AssertionError(failures)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.input = self.root / "input"
        self.input.mkdir()
        self.archive = self.input / "synthetic-metadata.tar"
        self.payload = b"synthetic body; original GNU file bytes are not supplied\n"
        self.make_tar()

    def make_tar(self, comment=COMMENT, duplicate=False, mode=0o664, member_name=MEMBER):
        with tarfile.open(self.archive, "w", format=tarfile.PAX_FORMAT) as archive:
            root = tarfile.TarInfo("glibc-2.41")
            root.type, root.mode, root.mtime = tarfile.DIRTYPE, 0o775, 1738085493
            root.uid = root.gid = 0
            root.uname = root.gname = "root"
            root.pax_headers = {"comment": COMMENT}
            archive.addfile(root)
            for _ in range(2 if duplicate else 1):
                item = tarfile.TarInfo(member_name)
                item.mode, item.mtime, item.size = mode, 1738085493, len(self.payload)
                item.uid = item.gid = 0
                item.uname = item.gname = "root"
                item.pax_headers = {"comment": comment}
                archive.addfile(item, io.BytesIO(self.payload))

    def inventory(self):
        selected = self.worker._archive_pin(self.archive)
        return self.worker._archive_tar_inventory(self.archive, selected, 1)

    def assert_refuses(self, action, reason):
        rejected = []
        actual_need = self.worker._archive_need
        def reached(condition, message):
            if not condition:
                rejected.append(str(message))
            return actual_need(condition, message)
        with mock.patch.object(self.worker, "_archive_need", side_effect=reached):
            with self.assertRaisesRegex(BaseException, reason):
                action()
        self.assertTrue(any(reason in item for item in rejected), (reason, rejected))

    def decoded_header(self, mutate, expected_reason=None):
        original_open = self.worker.tarfile.open
        events = {"mutated": 0, "file_bodies": 0}
        class Reader:
            def __init__(inner, *args, **kwargs):
                inner.archive = original_open(*args, **kwargs)
            def __enter__(inner):
                return inner
            def __exit__(inner, *args):
                return inner.archive.__exit__(*args)
            def __iter__(inner):
                for member in inner.archive:
                    if member.name == MEMBER:
                        events["mutated"] += 1
                        mutate(member)
                    yield member
            def extractfile(inner, member):
                events["file_bodies"] += 1
                return inner.archive.extractfile(member)
        with mock.patch.object(self.worker.tarfile, "open", side_effect=Reader):
            if expected_reason is not None:
                self.assert_refuses(self.inventory, expected_reason)
                result = None
            else:
                result = self.inventory()
        self.assertEqual(events["mutated"], 1)
        return result, events

    def test_retained_gnu_member_comment_is_preserved_in_complete_inventory(self):
        before = self.worker._archive_pin(self.archive)
        result = self.inventory()
        rows = result["manifest"]["entries"]
        self.assertEqual(result["members"], 2)
        self.assertEqual([(r["archive_path"], r["path"], r["mode"], r["pax_comment"]) for r in rows],
                         [("glibc-2.41", "", 0o775, COMMENT), (MEMBER, ".b4-config", 0o664, COMMENT)])
        self.assertEqual(rows[1]["bytes"], len(self.payload))
        self.assertEqual(rows[1]["sha256"], hashlib.sha256(self.payload).hexdigest())
        expected = hashlib.sha256(json.dumps(result["manifest"], sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
        self.assertEqual(result["sha256"], expected)
        self.assertTrue(result["all_regular_member_bytes_hashed"])
        self.assertEqual(self.worker._archive_pin(self.archive), before)
        self.assertNotIn("revision", result)
        self.assertNotIn("source_date_epoch", result)

    def test_text_is_not_restricted_to_git_hex_or_an_arbitrary_size_limit(self):
        for value in ["", "ordinary note\nsecond line", "Unicode: \u03bb", "z" * 131073]:
            with self.subTest(characters=len(value)):
                result, events = self.decoded_header(lambda member: member.pax_headers.update(comment=value))
                row = next(r for r in result["manifest"]["entries"] if r["path"] == ".b4-config")
                self.assertEqual(row["pax_comment"], value)
                self.assertEqual(events["file_bodies"], 1)

    def test_nonstring_effective_comments_refuse_before_body_consumption(self):
        for value in [None, False, 7, b"text"]:
            with self.subTest(type=type(value).__name__):
                _, events = self.decoded_header(lambda member: member.pax_headers.update(comment=value),
                                               "unsupported PAX comment text")
                self.assertEqual(events["file_bodies"], 0)

    def test_nul_comment_is_explicitly_outside_the_supported_text_profile(self):
        _, events = self.decoded_header(lambda member: member.pax_headers.update(comment="before\x00after"),
                                       "unsupported PAX comment text")
        self.assertEqual(events["file_bodies"], 0)

    def test_non_utf8_surrogate_refuses_before_body_consumption(self):
        _, events = self.decoded_header(lambda member: member.pax_headers.update(comment="\udcff"),
                                       "PAX comment is not strict UTF-8")
        self.assertEqual(events["file_bodies"], 0)

    def test_comment_never_permits_sparse_xattr_or_other_unknown_attributes(self):
        for key in ["GNU.sparse.major", "GNU.sparse.map", "SCHILY.xattr.user.note",
                    "LIBARCHIVE.xattr.user.note", "future.unknown"]:
            with self.subTest(keyword=key):
                _, events = self.decoded_header(lambda member: member.pax_headers.update({key: "1"}),
                                               "unsupported extended tar attributes")
                self.assertEqual(events["file_bodies"], 0)

    def test_comment_never_waives_duplicate_traversal_or_special_mode_guards(self):
        for settings, reason in [({"duplicate": True}, "duplicate normalized archive member"),
                                 ({"member_name": "glibc-2.41/../escape"}, "archive traversal member"),
                                 ({"mode": 0o4664}, "unsupported special archive mode")]:
            with self.subTest(reason=reason):
                self.make_tar(**settings)
                self.assert_refuses(self.inventory, reason)

    def test_comment_changes_digest_and_revalidation_rejects_a_changed_retained_claim(self):
        initial = self.inventory()
        self.make_tar(comment="different retained comment")
        changed = self.inventory()
        self.assertNotEqual(initial["sha256"], changed["sha256"])
        def logical_projection(result):
            rows = copy.deepcopy(result["manifest"]["entries"])
            for row in rows:
                row.pop("pax_comment", None)
            return rows
        self.assertEqual(logical_projection(initial), logical_projection(changed))
        # Reuse the real materialize/revalidate dispatch with an explicitly inert constructor.
        self.make_tar()
        output = self.root / "output"
        output.mkdir()
        tool = self.root / "inert-extractor"
        tool.write_bytes(b"not executed: synthetic extractor constructor\n")
        tool.chmod(0o500)
        logical = {"schema": "ocore-original-archive-logical-source-tree-v1", "entries": [
            {"path": ".b4-config", "kind": "file", "mode": 0o664, "bytes": len(self.payload),
             "sha256": hashlib.sha256(self.payload).hexdigest()}]}
        source = {"kind": "original-archive-v1", "name": "metadata-fixture", "version": "1",
            "url": "https://example.invalid/synthetic.tar", "archive": {"file": self.archive.name,
            "bytes": self.archive.stat().st_size, "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest()},
            "extractor": {"path": str(tool), "bytes": tool.stat().st_size,
                          "sha256": hashlib.sha256(tool.read_bytes()).hexdigest()},
            "extraction": {"profile": "gnu-tar-strip-v1", "strip_components": 1},
            "expected_tree_sha256": hashlib.sha256(json.dumps(logical, sort_keys=True,
                separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest(),
            "source_date_epoch": 123, "authentication": {"mode": "caller-pinned"}}
        recipe = {"source": source}
        calls = []
        def inert_constructor(argv, **kwargs):
            calls.append((argv, kwargs))
            descriptor = os.open(".b4-config", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o664, dir_fd=kwargs["pass_fds"][2])
            try:
                os.write(descriptor, self.payload)
                os.fchmod(descriptor, 0o664)
            finally:
                os.close(descriptor)
            os.write(kwargs["stdout"], b"inert fixture; no native extractor\n")
            return types.SimpleNamespace(returncode=0)
        with mock.patch.object(self.worker.subprocess, "run", side_effect=inert_constructor):
            context = self.worker.verify_source_origin(recipe, self.input, directory=output)
            self.assertIs(self.worker.verify_source_origin(recipe, Path(context["path"]), context=context), context)
            for item in [context, json.loads(Path(context["materialization"]["path"]).read_bytes())]:
                self.assertEqual(item["archive_safety"]["manifest"]["entries"][1]["pax_comment"], COMMENT)
            bad_context = copy.deepcopy(context)
            bad_context["archive_safety"]["manifest"]["entries"][1]["pax_comment"] = "forged retained comment"
            self.assert_refuses(lambda: self.worker.verify_source_origin(recipe, Path(context["path"]),
                context=bad_context), "complete archive member inventory differs")
        self.assertEqual(len(calls), 1)
        self.assertIs(context["authentication"]["authenticated"], False)
        for key in ["source_ownership_qualified", "capture_admitted", "runtime_qualified",
                    "extractor_interpreter_children_libraries_qualified"]:
            self.assertIs(context[key], False)
