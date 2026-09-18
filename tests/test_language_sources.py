"""Coverage and nonexecution regressions for the complete tracked-source audit."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import check_language_sources as sources


class LanguageSourcesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path, content in {
            "examples/hello.O": "text^(hello)_text\n",
            "tests/example_manifest.py": "# fixture harness\n",
            "examples/manifest.json": json.dumps({"schema_version": 1, "examples": [{"path": "hello.O", "editions": ["rust"], "classification": "unit", "requirements": {"backends": ["text"], "programs": [], "authorities": []}, "expected": {"rust": {"patterns": ["hello"]}}}]}),
        }.items():
            self.write(path, content)
        self.tracked = {"examples/hello.O", "tests/example_manifest.py", "examples/manifest.json"}
        self.data = {"schema": "ostadix.language-sources/v1", "groups": [{"id": "examples", "category": "example", "reason": "Runtime manifest defines prerequisites.", "coverage": [{"path": "tests/example_manifest.py", "kind": "runtime", "conditions": "Honor runtime requirements."}], "sources": ["examples/hello.O"]}], "expected_parse_failures": {}, "mirrors": {}}

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def load(self):
        self.write(sources.MANIFEST, json.dumps(self.data))
        return sources.load_manifest(self.root, self.tracked)

    def test_repository_has_complete_declared_coverage(self):
        entries = sources.load_manifest(sources.ROOT)
        self.assertEqual(set(entries), {p for p in sources.tracked_files(sources.ROOT) if p.endswith((".O", ".oc"))})

    def test_new_tracked_file_requires_classification(self):
        self.tracked.add("new.oc")
        self.write("new.oc", "module new;\n")
        with self.assertRaisesRegex(sources.SourceError, "coverage mismatch.*new.oc"):
            self.load()

    def test_untracked_work_is_not_included(self):
        self.write("unrelated_work.O", "invalid and private")
        self.assertEqual(set(self.load()), {"examples/hello.O"})

    def test_stale_manifest_entry_fails(self):
        self.tracked.remove("examples/hello.O")
        with self.assertRaisesRegex(sources.SourceError, "coverage mismatch.*stale"):
            self.load()

    def test_duplicate_source_fails(self):
        group = copy.deepcopy(self.data["groups"][0])
        group["id"] = "duplicate"
        self.data["groups"].append(group)
        with self.assertRaisesRegex(sources.SourceError, "duplicate source"):
            self.load()

    def test_coverage_must_name_tracked_harness(self):
        self.tracked.remove("tests/example_manifest.py")
        with self.assertRaisesRegex(sources.SourceError, "untracked coverage"):
            self.load()

    def test_paths_cannot_escape_root(self):
        self.data["groups"][0]["coverage"][0]["path"] = "../elsewhere"
        with self.assertRaisesRegex(sources.SourceError, "repository-relative"):
            self.load()

    def test_package_mirror_drift_fails(self):
        self.write("mirror.O", "stale\n")
        self.tracked.add("mirror.O")
        group = copy.deepcopy(self.data["groups"][0])
        group.update(id="mirror", category="package-mirror", sources=["mirror.O"])
        self.data["groups"].append(group)
        self.data["mirrors"]["mirror.O"] = "examples/hello.O"
        with self.assertRaisesRegex(sources.SourceError, "package mirror drift"):
            self.load()

    def test_expected_failure_requires_specific_reason_and_diagnostic(self):
        self.data["expected_parse_failures"]["examples/hello.O"] = {"reason": "", "diagnostic": "error"}
        with self.assertRaisesRegex(sources.SourceError, "reason, and diagnostic"):
            self.load()

    def parse(self, completed, entry=None):
        with mock.patch.object(sources.subprocess, "run", return_value=completed) as run:
            result = sources.parse_source(self.root, "examples/hello.O", entry or {}, Path("/compiler/O"), Path("/compiler/ocorec"), 5)
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["/compiler/O", "--check", "--json"])
        return result

    def test_non_parse_success_cannot_pass(self):
        for output in ("ok", '{"ok":true,"stage":"execute"}', '{"ok":false,"stage":"parse"}'):
            with self.subTest(output=output):
                result = self.parse(subprocess.CompletedProcess([], 0, output, ""))
                self.assertEqual(result["status"], "failed")

    def test_unexpected_success_of_negative_fixture_fails(self):
        entry = {"expected_failure": {"reason": "Malformed closing delimiter", "diagnostic": "unterminated"}}
        result = self.parse(subprocess.CompletedProcess([], 0, '{"ok":true,"stage":"parse"}', ""), entry)
        self.assertEqual(result["status"], "failed")
        result = self.parse(subprocess.CompletedProcess([], 1, "", "unterminated delimiter"), entry)
        self.assertEqual(result["status"], "passed")

    def test_expected_failure_does_not_hide_tool_crash(self):
        entry = {"expected_failure": {"reason": "Malformed closing delimiter", "diagnostic": "unterminated"}}
        result = self.parse(subprocess.CompletedProcess([], -11, "", "unterminated before crash"), entry)
        self.assertEqual(result["status"], "failed")

    def test_timeout_is_failure(self):
        with mock.patch.object(sources.subprocess, "run", side_effect=subprocess.TimeoutExpired("O", 5)):
            result = sources.parse_source(self.root, "examples/hello.O", {}, Path("/compiler/O"), Path("/compiler/ocorec"), 5)
        self.assertEqual(result["status"], "failed")


if __name__ == "__main__":
    unittest.main()
