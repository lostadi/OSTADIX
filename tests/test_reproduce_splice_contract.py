"""Pure contract checks; no O engine or guest language is executed."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "splice_reproduction", ROOT / "scripts/reproduce_splice_contract.py"
)
repro = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repro)


class ReproductionContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.marker = self.directory / "must-not-exist"
        self.fixtures = json.loads(repro.FIXTURES.read_text())

    def result(self, case, executor="graph"):
        source_hash = hashlib.sha256(case["source"].encode()).hexdigest()
        return {
            "executor": executor, "exit_code": 0, "timed_out": False,
            "source_sha256": source_hash, "diagnostic": "",
            "answer": {
                "ok": True, "value": case["expected"],
                "execution_evidence": {
                    "schema": "ostadix.native-execution-evidence/v1",
                    "execution_mode": executor, "source_sha256": source_hash,
                },
            },
        }

    def test_original_inventory_is_exact_and_independently_hash_pinned(self):
        cases = repro.original_cases(self.fixtures)
        self.assertEqual([case["name"] for case in cases], [f"original-{i}" for i in range(1, 8)])
        self.assertEqual([case["accept"] for case in cases], [True, False, False, False, False, True, False])
        for mutation in ("empty", "missing", "duplicate", "reordered", "oracle", "source", "rehashed-source", "baseline"):
            changed = copy.deepcopy(self.fixtures)
            if mutation == "empty":
                changed["witnesses"] = []
            elif mutation == "missing":
                changed["witnesses"].pop()
            elif mutation == "duplicate":
                changed["witnesses"][1] = changed["witnesses"][0]
            elif mutation == "reordered":
                changed["witnesses"].reverse()
            elif mutation == "oracle":
                changed["witnesses"][1]["ordinary_contract_accepts"] = True
            elif mutation in ("source", "rehashed-source"):
                changed["witnesses"][0]["source"] += " "
                if mutation == "rehashed-source":
                    changed["witnesses"][0]["source_sha256_with_final_newline"] = hashlib.sha256(
                        (changed["witnesses"][0]["source"] + "\n").encode()
                    ).hexdigest()
            else:
                changed["baseline_commit"] = "0" * 40
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                repro.original_cases(changed)

    def test_negative_requires_parse_stage_structured_error_and_no_effect(self):
        case = {"source": "negative\n", "accept": False, "expected": None}
        result = self.result(case)
        result.update(exit_code=1, diagnostic="foreign value splice rejected")
        result["answer"] = {
            "ok": False, "stage": "parse", "error": "foreign value splice rejected",
            "execution_evidence": {"schema": "ostadix.native-execution-evidence/v1",
                                   "trace": None, "admission": None, "native_leaves": []},
        }
        self.assertTrue(repro.validate_attempt(result, case, self.marker))
        for mutation in ("eval", "effect", "missing-trace", "nonobject", "unrelated", "timeout", "success-exit"):
            changed = copy.deepcopy(result)
            if mutation == "eval":
                changed["answer"]["stage"] = "eval"
            elif mutation == "effect":
                changed["answer"]["execution_evidence"]["trace"] = {
                    "events": [{"event": "started", "plan_node": 0}]
                }
            elif mutation == "missing-trace":
                del changed["answer"]["execution_evidence"]["trace"]
            elif mutation == "nonobject":
                changed["answer"] = ["foreign value splice"]
            elif mutation == "unrelated":
                changed["answer"]["error"] = "missing runtime"
            elif mutation == "timeout":
                changed["timed_out"] = True
            else:
                changed["exit_code"] = 0
            with self.subTest(mutation=mutation):
                self.assertFalse(repro.validate_attempt(changed, case, self.marker))
        self.marker.write_text("producer ran")
        self.assertFalse(repro.validate_attempt(result, case, self.marker))

    def test_positive_requires_exact_typed_value_and_source_executor_binding(self):
        case = repro.original_cases(self.fixtures)[0]
        result = self.result(case)
        self.assertTrue(repro.validate_attempt(result, case, self.marker))
        for mutation in ("value", "source", "executor", "nonobject"):
            changed = copy.deepcopy(result)
            if mutation == "value":
                changed["answer"]["value"] = repro.text("not the list")
            elif mutation == "source":
                changed["answer"]["execution_evidence"]["source_sha256"] = "0" * 64
            elif mutation == "executor":
                changed["answer"]["execution_evidence"]["execution_mode"] = "serial"
            else:
                changed["answer"] = 1
            with self.subTest(mutation=mutation):
                self.assertFalse(repro.validate_attempt(changed, case, self.marker))

    def test_all_24_attempts_are_persisted_even_after_exceptions_and_bad_json(self):
        cases = [{"name": f"case-{i}", "source": f"source-{i}",
                  "accept": True, "expected": repro.text(str(i))} for i in range(12)]
        calls = 0

        def execute(_binary, _backends, _directory, source, executor, _timeout):
            nonlocal calls
            index = calls
            calls += 1
            if index == 0:
                raise OSError("injected launch failure")
            case = next(case for case in cases if case["source"] == source)
            result = self.result(case, executor)
            if index == 1:
                result["answer"] = []
            return result

        counts = []
        writer = repro.write_report

        def retain(directory, report):
            counts.append(report["asserted_runs"])
            writer(directory, report)

        report = {"ok": False, "runs": []}
        with mock.patch.object(repro, "execute", side_effect=execute), mock.patch.object(
                repro, "write_report", side_effect=retain):
            repro.run_cases(Path("O"), Path("backends"), self.directory, cases,
                            self.marker, 1, report)
        retained = json.loads((self.directory / "result.json").read_text())
        self.assertFalse(retained["ok"])
        self.assertEqual(retained["expected_runs"], 24)
        self.assertEqual(retained["asserted_runs"], 24)
        self.assertEqual(len(retained["runs"]), 24)
        self.assertIn("injected launch failure", retained["runs"][0]["execution_error"])
        self.assertFalse(retained["runs"][1]["passed"])
        self.assertTrue(all(row["passed"] for row in retained["runs"][2:]))
        self.assertEqual(counts, [0, *range(1, 25), 24])

    def test_incomplete_case_list_cannot_be_a_zero_case_pass(self):
        with self.assertRaises(ValueError):
            repro.run_cases(Path("O"), Path("backends"), self.directory, [],
                            self.marker, 1, {"ok": False, "runs": []})

    def test_execute_retains_spawn_failure_with_raw_capture_files(self):
        directory = self.directory / "spawn-failure"
        with mock.patch.object(repro.subprocess, "Popen", side_effect=FileNotFoundError("missing O")):
            result = repro.execute(Path("O"), Path("backends"), directory, "source", "graph", 1)
        self.assertIn("FileNotFoundError", result["execution_error"])
        self.assertIsNone(result["exit_code"])
        self.assertTrue((directory / "witness.O").is_file())
        self.assertEqual(result["stdout"]["bytes"], 0)
        self.assertEqual(result["stderr"]["bytes"], 0)

    def test_timeout_is_failure_and_signals_only_through_owned_cleanup(self):
        class Child:
            pid = 12345
            returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                self.returncode = -signal.SIGINT
                return self.returncode

            def kill(self):
                self.returncode = -signal.SIGKILL

        with mock.patch.object(repro.subprocess, "Popen", return_value=Child()), mock.patch.object(
                repro, "descendants"), mock.patch.object(repro, "terminate_observed") as terminate, mock.patch.object(
                repro.time, "monotonic", side_effect=[0, 1, 2]):
            result = repro.execute(Path("O"), Path("backends"), self.directory / "timeout",
                                   "source", "graph", 0.5)
        self.assertTrue(result["timed_out"])
        self.assertEqual([call.args[1] for call in terminate.call_args_list], [signal.SIGINT, signal.SIGKILL])

    def test_actual_ci_guards_reject_missing_zero_and_skipped_qualifications(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        job = workflow.split("\n  boundary-contract:", 1)[1].split("\n  docker:", 1)[0]
        snippets = []
        for fragment in job.split("          python3 - <<'PY'\n")[1:]:
            snippets.append(textwrap.dedent(fragment.split("\n          PY", 1)[0]))
        self.assertEqual(len(snippets), 2)
        logs = self.directory / "target/boundary-contract-logs"
        logs.mkdir(parents=True)

        def succeeds(index):
            result = subprocess.run([sys.executable, "-B", "-c", snippets[index]],
                                    cwd=self.directory, capture_output=True, text=True, timeout=5)
            return result.returncode == 0

        listing = logs / "sql-test-list.log"
        listing.write_text("0 tests, 0 benchmarks\n")
        self.assertFalse(succeeds(0))
        listing.write_text("backend::tests::sqlite_file_requests_recover_from_syntax_errors_and_marker_collisions: test\n")
        self.assertTrue(succeeds(0))
        (logs / "foreign-splice.log").write_text("test result: ok. 14 passed; 0 failed; 0 ignored;\n")
        (logs / "sql-regression.log").write_text("test result: ok. 1 passed; 0 failed; 0 ignored;\n")
        (logs / "python-contracts.log").write_text("Ran 7 tests in 0.1s\n\nOK\n")
        self.assertTrue(succeeds(1))
        for filename, corrupt in (
            ("sql-regression.log", "test result: ok. 0 passed; 0 failed; 0 ignored;\n"),
            ("foreign-splice.log", "test result: ok. 0 passed; 0 failed; 0 ignored;\n"),
            ("foreign-splice.log", "test result: ok. 13 passed; 0 failed; 1 ignored;\n"),
            ("python-contracts.log", "Ran 0 tests in 0.1s\n\nOK\n"),
            ("python-contracts.log", "Ran 7 tests in 0.1s\n\nOK (skipped=1)\n"),
        ):
            path = logs / filename
            original = path.read_text()
            path.write_text(corrupt)
            with self.subTest(filename=filename, corrupt=corrupt):
                self.assertFalse(succeeds(1))
            path.write_text(original)


if __name__ == "__main__":
    unittest.main()
