"""Adversarial archive/mandatory-prerequisite controls, using inert tiny inputs."""
import copy
import hashlib
import io
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock

from scripts import prepare_ci_llvm_profile as provision

ROOT = Path(__file__).resolve().parents[1]


def pin(data):
    return {"kind": "regular", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class LlvmProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="llvm-profile-negative-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.body, self.header = b"inert tool fixture\n", b"/* declared fixture header */\n"
        self.profile = {"schema": "ostadix.ci-llvm-minimal-profile/v1", "prefix": "SDK",
                        "members": {"bin/clang-22": pin(self.body),
                                    "bin/clang": dict(pin(self.body), kind="symlink", target="clang-22"),
                                    "lib/clang/22/include/fixture.h": pin(self.header)}}

    def archive(self, changes=None, extra=()):
        rows = [("SDK/bin/clang-22", "regular", self.body),
                ("SDK/bin/clang", "symlink", "clang-22"),
                ("SDK/lib/clang/22/include/fixture.h", "regular", self.header)]
        rows = [changes(row) if changes else row for row in rows]
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:xz") as target:
            for row in rows + list(extra):
                if row is None:
                    continue
                name, kind, value = row
                info = tarfile.TarInfo(name)
                if kind == "symlink":
                    info.type, info.linkname = tarfile.SYMTYPE, value
                elif kind == "hardlink":
                    info.type, info.linkname = tarfile.LNKTYPE, value
                else:
                    info.size, info.mode = len(value), 0o755
                target.addfile(info, io.BytesIO(value) if kind == "regular" else None)
        stream.seek(0)
        return stream

    def test_exact_members_only_and_original_alias(self):
        stream = self.archive(extra=[("SDK/lib/huge-unselected-library.a", "regular", b"unselected")])
        output = self.root / "subset"
        rows = provision.extract_selected(stream, output, self.profile)
        provision.verify_subset(output, self.profile)
        self.assertEqual(len(rows), 3)
        self.assertEqual(os.readlink(output / "bin/clang"), "clang-22")
        self.assertEqual((output / "bin/clang").read_bytes(), self.body)
        self.assertFalse((output / "lib/huge-unselected-library.a").exists())

    def test_complete_archive_hash_and_size_are_both_required(self):
        path = self.root / "archive.tar.xz"
        raw = self.archive().read()
        path.write_bytes(raw)
        profile = dict(self.profile, archive={"size": len(raw), "digest": "sha256:" + hashlib.sha256(raw).hexdigest()})
        with path.open("rb") as stream:
            self.assertEqual(provision.verify_archive(stream, profile)["bytes"], len(raw))
        path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with path.open("rb") as stream, self.assertRaisesRegex(provision.ProfileError, "SHA-256 mismatch"):
            provision.verify_archive(stream, profile)
        path.write_bytes(raw + b"x")
        with path.open("rb") as stream, self.assertRaisesRegex(provision.ProfileError, "size/type mismatch"):
            provision.verify_archive(stream, profile)

    def test_canonical_paths_for_selected_and_unselected_records(self):
        names = ["../escape", "/absolute", "SDK/../escape", "SDK//escape", "SDK/./escape", "SDK\\escape", "OTHER/escape"]
        for index, name in enumerate(names):
            with self.subTest(name=name), self.assertRaises(provision.ProfileError):
                provision.extract_selected(self.archive(extra=[(name, "regular", b"bad")]), self.root / str(index), self.profile)
        self.assertFalse((self.root / "escape").exists())

    def test_duplicate_members_cannot_replace_verified_bytes(self):
        with self.assertRaisesRegex(provision.ProfileError, "duplicate archive member"):
            provision.extract_selected(self.archive(extra=[("SDK/bin/clang-22", "regular", self.body)]), self.root / "subset", self.profile)

    def test_missing_selected_member_is_not_optional(self):
        with self.assertRaisesRegex(provision.ProfileError, "missing selected"):
            provision.extract_selected(self.archive(lambda row: None if row[0].endswith("fixture.h") else row), self.root / "subset", self.profile)

    def test_payload_hash_is_not_replaced_by_authenticated_looking_metadata(self):
        for index, value in enumerate((self.body[:-1] + b"x", self.body + b"x")):
            with self.subTest(value=value), self.assertRaisesRegex(provision.ProfileError, "mismatch"):
                provision.extract_selected(self.archive(lambda row: (row[0], row[1], value) if row[0].endswith("clang-22") else row), self.root / str(index), self.profile)

    def test_alias_must_be_actual_safe_archive_symlink(self):
        for index, (kind, target) in enumerate((("symlink", "../../outside"), ("symlink", "/outside"), ("symlink", "missing"), ("hardlink", "SDK/bin/clang-22"), ("regular", b"not a link"))):
            with self.subTest(kind=kind, target=target), self.assertRaisesRegex(provision.ProfileError, "alias type/target"):
                provision.extract_selected(self.archive(lambda row: (row[0], kind, target) if row[0] == "SDK/bin/clang" else row), self.root / str(index), self.profile)

    def test_member_symlink_cannot_be_followed_as_tool_or_directory(self):
        for index, name in enumerate(("SDK/bin/clang-22", "SDK/lib/clang/22/include/fixture.h")):
            with self.subTest(name=name), self.assertRaisesRegex(provision.ProfileError, "regular member"):
                provision.extract_selected(self.archive(lambda row: (row[0], "symlink", "../../outside") if row[0] == name else row), self.root / str(index), self.profile)

    def test_existing_prefix_and_symlink_are_never_overwritten(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "sentinel").write_bytes(b"preserve")
        link = self.root / "link"
        link.symlink_to(outside, target_is_directory=True)
        for prefix in (outside, link):
            with self.subTest(prefix=prefix), self.assertRaises(FileExistsError):
                provision.extract_selected(self.archive(), prefix, self.profile)
        self.assertEqual(list(outside.iterdir()), [outside / "sentinel"])

    def test_subset_recheck_rejects_tamper_extra_or_retargeted_alias(self):
        for index, change in enumerate(("bytes", "extra", "alias")):
            output = self.root / str(index)
            provision.extract_selected(self.archive(), output, self.profile)
            if change == "bytes":
                (output / "bin/clang-22").write_bytes(b"tampered")
            elif change == "extra":
                (output / "extra").write_bytes(b"unlisted")
            else:
                (output / "bin/clang").unlink()
                (output / "bin/clang").symlink_to("../lib/clang/22/include/fixture.h")
            with self.subTest(change=change), self.assertRaises(provision.ProfileError):
                provision.verify_subset(output, self.profile)

    def test_profile_cannot_make_alias_outside_subset(self):
        for target in ("../outside", "/outside", "not-selected"):
            changed = copy.deepcopy(self.profile)
            changed["members"]["bin/clang"]["target"] = target
            with self.subTest(target=target), self.assertRaises(provision.ProfileError):
                provision.validate_profile(changed)

    def test_cli_has_no_alternate_profile_digest_or_policy_switch(self):
        archive = self.root / "invalid-but-existing.tar.xz"
        archive.write_bytes(b"inert archive fixture; never downloaded")
        for index, option in enumerate(("--profile", "--sha256", "--policy")):
            output, prefix = self.root / ("evidence" + str(index)), self.root / ("prefix" + str(index))
            with self.subTest(option=option):
                status, stdout, stderr = self.bounded_child([
                    sys.executable, "-B", str(ROOT / "scripts/prepare_ci_llvm_profile.py"),
                    "--archive", str(archive), "--prefix", str(prefix), "--output", str(output),
                    "--parser-library", "/missing-parser", "--rustc", "/missing-rustc", option, "unsafe"])
                self.assertEqual(status, 2)
                self.assertEqual(stdout, b"")
                self.assertIn(("unrecognized arguments: " + option + " unsafe").encode(), stderr)
                self.assertNotIn(b"the following arguments are required", stderr)
                self.assertFalse(output.exists())
                self.assertFalse(prefix.exists())

    def test_missing_required_tool_source_or_parser_is_failure_not_skip(self):
        tools = {}
        for key in ("OCOREC_BIN", "OCORE_TEST_CLANG", "OCORE_TEST_LLVM_NM", "OCORE_TEST_LLVM_OBJCOPY", "OCORE_TEST_LLVM_OBJDUMP", "OCORE_TEST_LLVM_LIBRARY"):
            path = self.root / key
            path.write_bytes(b"inert placeholder, never executed")
            tools[key] = str(path)
        source = self.root / "source"
        source.mkdir()
        (source / "configure").touch()
        for key in ("OCORE_TEST_CLANG", "OCORE_TEST_LLVM_LIBRARY", "OCORE_MUSL_SOURCE"):
            environment = dict(os.environ, **tools, OCORE_MUSL_SOURCE=str(source), OCORE_CONSTRAINED_FP_REQUIRED="1", PYTHONDONTWRITEBYTECODE="1")
            environment[key] = str(self.root / "missing")
            result = subprocess.run([sys.executable, "-B", "-m", "unittest", "-v", "tests.test_ocore_native_constrained_fmul"], cwd=ROOT, env=environment, capture_output=True, timeout=30)
            with self.subTest(key=key):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"mandatory constrained FP prerequisites are missing", result.stderr)
                self.assertNotIn(b"skipped=", result.stderr)

    def test_provision_failure_retains_red_receipt_and_no_environment(self):
        archive = self.root / "invalid.tar.xz"
        archive.write_bytes(b"not the official archive")
        output = self.root / "evidence"
        with self.assertRaises(provision.ProfileError):
            provision.provision(archive, self.root / "subset", output, "/missing-parser", "/missing-rustc")
        report = json.loads((output / "result.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertFalse((output / "environment.json").exists())
        self.assertFalse(report["source_lowered"])
        self.assertFalse((self.root / "subset").exists())

    def test_download_publishes_only_complete_digest_checked_bytes(self):
        raw = self.archive().read()
        profile = dict(self.profile, archive={"size": len(raw), "digest": "sha256:" + hashlib.sha256(raw).hexdigest(), "browser_download_url": "https://fixture.invalid/archive"})
        path = self.root / "download.tar.xz"
        with mock.patch.object(provision, "ARCHIVE_SHA256", hashlib.sha256(raw).hexdigest()), mock.patch.object(provision.urllib.request, "urlopen", return_value=io.BytesIO(raw)) as request:
            provision.download_archive(path, profile)
        self.assertEqual(path.read_bytes(), raw)
        request.assert_called_once_with("https://fixture.invalid/archive", timeout=120)
        self.assertFalse(list(self.root.glob("*.partial-*")))
        for index, wrong in enumerate((raw[:-1], raw + b"x", raw[:-1] + bytes([raw[-1] ^ 1]))):
            absent = self.root / ("bad" + str(index))
            with self.subTest(index=index), mock.patch.object(provision, "ARCHIVE_SHA256", hashlib.sha256(raw).hexdigest()), mock.patch.object(provision.urllib.request, "urlopen", return_value=io.BytesIO(wrong)), self.assertRaises(provision.ProfileError):
                provision.download_archive(absent, profile)
            self.assertFalse(absent.exists())
            self.assertFalse(list(self.root.glob("*.partial-*")))

    def test_cold_disk_refusal_precedes_download(self):
        profile = dict(self.profile, archive={"size": 100, "browser_download_url": "https://fixture.invalid/archive"})
        usage = mock.Mock(free=0)
        with mock.patch.object(provision.shutil, "disk_usage", return_value=usage), mock.patch.object(provision.urllib.request, "urlopen") as request, self.assertRaisesRegex(provision.ProfileError, "headroom"):
            provision.download_archive(self.root / "new.tar.xz", profile)
        request.assert_not_called()

    def test_wrong_parser_is_rejected_before_loading_its_code(self):
        profile = provision.load_profile()
        parser = self.root / "wrong-parser.so"
        parser.write_bytes(b"inert wrong library")
        report = {}
        def fake_command(argv, report, name):
            if name == "rustc-version":
                return "release: 1.97.1\ncommit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452\nLLVM version: 22.1.6\n"
            return "LLVM version 22.1.6\n" if name.endswith("-version") else ""
        with mock.patch.object(provision, "command", side_effect=fake_command), mock.patch.object(provision.ctypes, "CDLL") as load, self.assertRaisesRegex(provision.ProfileError, "parser library identity mismatch"):
            provision.inspect_tools(self.root, parser, Path(sys.executable), profile, report)
        load.assert_not_called()

    def bounded_child(self, argv, *, cwd=ROOT):
        # Timeout is a test FAILURE. Only our exact child's live pidfd can be
        # signalled, and every path reaps it; no process-name/group cleanup.
        process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        descriptor = os.pidfd_open(process.pid)
        try:
            try:
                stdout, stderr = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                stdout, stderr = process.communicate(timeout=3)
                self.fail("nonregular input refusal exceeded bounded deadline; owned child reaped")
            return process.returncode, stdout, stderr
        finally:
            if process.poll() is None:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                process.communicate(timeout=3)
            os.close(descriptor)

    def test_actual_archive_fifo_device_directory_and_alias_are_typed_refusals(self):
        fifo = self.root / "archive.fifo"
        os.mkfifo(fifo)
        ordinary = self.root / "ordinary-file"
        ordinary.write_bytes(b"tiny regular fixture")
        alias = self.root / "archive-link"
        alias.symlink_to(ordinary)
        directory = self.root / "archive-directory"
        directory.mkdir()
        for index, source in enumerate((fifo, Path("/dev/null"), directory, alias)):
            evidence, subset = self.root / ("evidence" + str(index)), self.root / ("subset" + str(index))
            with self.subTest(kind=index):
                status, stdout, stderr = self.bounded_child([
                    sys.executable, "-B", str(ROOT / "scripts/prepare_ci_llvm_profile.py"),
                    "--archive", str(source), "--prefix", str(subset), "--output", str(evidence),
                    "--rustc", "/missing-rustc", "--parser-library", "/missing-parser"])
                self.assertEqual(status, 1)
                self.assertEqual(stdout, b"")
                self.assertEqual(stderr, b"LLVM prerequisite REFUSED: archive input must be a regular file without symlinks\n")
                result = json.loads((evidence / "result.json").read_text())
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["error"], {"type": "ProfileError", "message": "archive input must be a regular file without symlinks"})
                self.assertFalse((evidence / "environment.json").exists())
                self.assertFalse(subset.exists())

    def test_other_identity_and_profile_reads_refuse_fifo_before_payload_read(self):
        fifo = self.root / "input.fifo"
        os.mkfifo(fifo)
        for operation, label in (("p.identity(path)", "identity input"), ("p.PROFILE=path; p.load_profile()", "profile input")):
            code = "from pathlib import Path; import sys; from scripts import prepare_ci_llvm_profile as p; path=Path(sys.argv[1]);\ntry:\n " + operation + "\nexcept p.ProfileError as error:\n print(str(error),file=sys.stderr); raise SystemExit(1)\n"
            with self.subTest(operation=operation):
                status, stdout, stderr = self.bounded_child([sys.executable, "-B", "-c", code, str(fifo)])
                self.assertEqual(status, 1)
                self.assertEqual(stdout, b"")
                self.assertEqual(stderr, (label + " must be a regular file without symlinks\n").encode())

    def test_held_regular_archive_descriptor_survives_path_replacement(self):
        path = self.root / "archive.tar.xz"
        raw = self.archive().read()
        path.write_bytes(raw)
        profile = dict(self.profile, archive={"size": len(raw), "digest": "sha256:" + hashlib.sha256(raw).hexdigest()})
        with provision.open_regular_input(path, "archive input") as stream:
            original = os.fstat(stream.fileno())
            path.unlink()
            os.mkfifo(path)
            provision.verify_archive(stream, profile)
            provision.extract_selected(stream, self.root / "subset", profile)
            provision.verify_archive(stream, profile)
            self.assertEqual(os.fstat(stream.fileno()).st_ino, original.st_ino)
        self.assertTrue(stream.closed)
        provision.verify_subset(self.root / "subset", profile)
        with self.assertRaisesRegex(provision.ProfileError, "archive input must be a regular file"):
            with provision.open_regular_input(path, "archive input"):
                self.fail("replacement FIFO was incorrectly admitted")

    def test_type_refusal_closes_its_owned_descriptor(self):
        fifo = self.root / "input.fifo"
        os.mkfifo(fifo)
        before = set(Path("/proc/self/fd").iterdir())
        for _ in range(20):
            with self.assertRaisesRegex(provision.ProfileError, "regular file without symlinks"):
                with provision.open_regular_input(fifo):
                    self.fail("FIFO was incorrectly admitted")
        self.assertEqual(set(Path("/proc/self/fd").iterdir()), before)

    def test_static_profile_declares_exact_minimal_closure(self):
        profile = provision.load_profile()
        members = profile["members"]
        self.assertEqual({name for name, row in members.items() if name.startswith("bin/") and row["kind"] == "regular"}, {"bin/clang-22", "bin/lld", "bin/llvm-nm", "bin/llvm-objcopy", "bin/llvm-objdump", "bin/llvm-ar"})
        self.assertEqual(len([name for name in members if name.startswith("lib/clang/22/include/")]), 305)
        self.assertEqual(sum(row["bytes"] for row in members.values() if row["kind"] == "regular"), 653779274)
        self.assertEqual(profile["parser"]["sha256"], "ed4f320c4e1ed6de7d2db6fd89faccf764d63186c2f877057ddf31065b1fac09")


class RequiredFpContractTests(unittest.TestCase):
    def test_no_missing_zero_skipped_error_or_changed_compiler_can_pass(self):
        for discovered, executed, skipped, errors, failures, unchanged in (
                (0, 0, 0, 0, 0, True), (9, 0, 0, 1, 0, True),
                (8, 8, 0, 0, 0, True), (10, 10, 0, 0, 0, True),
                (9, 9, 1, 0, 0, True), (9, 9, 0, 1, 0, True),
                (9, 9, 0, 0, 1, True), (9, 9, 0, 0, 0, False),
                (9, 9, 0, 0, 0, True)):
            result = unittest.TestResult()
            result.testsRun = executed
            result.skipped = [(None, "unmet")] * skipped
            result.errors = [(None, "error")] * errors
            result.failures = [(None, "failure")] * failures
            report = provision.required_test_report(discovered, result, unchanged)
            with self.subTest(discovered=discovered, executed=executed, skipped=skipped, errors=errors, failures=failures, unchanged=unchanged):
                self.assertEqual(report["passed"], (discovered, executed, skipped, errors, failures, unchanged) == (9, 9, 0, 0, 0, True))
                self.assertFalse(report["whole_musl_lowering"])
                self.assertFalse(report["foreign_ISA_native_execution"])

    def test_actual_expected_failure_is_explicitly_not_a_required_positive(self):
        class UnmetRequiredCase(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                self.fail("unsupported required profile")
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None) for _ in range(8)] + [UnmetRequiredCase()])
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        self.assertTrue(result.wasSuccessful())  # unittest alone allows XFAIL.
        report = provision.required_test_report(9, result, True)
        self.assertEqual(report["executed"], 9)
        self.assertEqual(report["expected_failures"], 1)
        self.assertEqual(report["unexpected_successes"], 0)
        self.assertFalse(report["passed"])
        class UnexpectedRequiredSuccess(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                pass
        other = unittest.TestSuite([unittest.FunctionTestCase(lambda: None) for _ in range(8)] + [UnexpectedRequiredSuccess()])
        result = unittest.TextTestRunner(stream=io.StringIO()).run(other)
        report = provision.required_test_report(9, result, True)
        self.assertEqual(report["expected_failures"], 0)
        self.assertEqual(report["unexpected_successes"], 1)
        self.assertFalse(report["passed"])

    def test_required_lane_and_artifact_are_outside_optional_sdk_block(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        start = workflow.index("  ocore-constrained-fp:\n")
        end = workflow.index("\n  boundary-contract:", start)
        job = workflow[start:end]
        self.assertIn("runs-on: ubuntu-24.04", job)
        self.assertIn("needs: contracts", job)
        self.assertNotIn("continue-on-error", job)
        self.assertNotIn("if sdk is None", job)
        self.assertIn('OCORE_CONSTRAINED_FP_REQUIRED="1"', job)
        self.assertIn("required_test_report(discovered, result, unchanged)", job)
        self.assertIn("if: always()", job)
        self.assertIn("if-no-files-found: error", job)
        required = tomllib.loads((ROOT / "ci/required-jobs.toml").read_text())["required_jobs"]
        suites = tomllib.loads((ROOT / "ci/test-suites.toml").read_text())["suites"]
        self.assertIn("ocore-constrained-fp", required)
        self.assertIn("ocore-constrained-fp", suites)
        aggregate = workflow[workflow.index("  required-ci:\n"):workflow.index("  release-package:\n")]
        self.assertIn("      - ocore-constrained-fp\n", aggregate)
        self.assertIn("needs.ocore-constrained-fp.result", aggregate)
        self.assertIn(" OCORE_CONSTRAINED_FP ", aggregate)

    def test_current_suite_has_nine_real_test_methods(self):
        suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_ocore_native_constrained_fmul")
        self.assertEqual(suite.countTestCases(), 9)


if __name__ == "__main__":
    unittest.main()
