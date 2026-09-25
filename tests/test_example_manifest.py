"""Focused schema and evidence regressions for examples/manifest.json."""

from __future__ import annotations

import json
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

import tests.example_manifest as manifest


def entry(*, edition: str = "rust", classification: str = "unit") -> dict:
    expectation = (
        {"result": {"tag": "int", "value": 2}}
        if edition == "python"
        else {"patterns": ["2"]}
    )
    return {
        "path": "hello.O",
        "editions": [edition],
        "classification": classification,
        "requirements": {
            "backends": ["python"],
            "programs": ["python3"],
            "authorities": ["process"],
        },
        "expected": {edition: expectation},
    }


class ManifestFixture:
    def __init__(self, example: dict) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "examples").mkdir()
        (self.root / "examples/hello.O").write_text(
            "python^(\n__oval_result__ = 2\n)_python\n", encoding="utf-8"
        )
        self.write({"schema_version": 1, "examples": [example]})

    def write(self, payload: dict) -> None:
        (self.root / "examples/manifest.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )

    def close(self) -> None:
        self.temporary.cleanup()


class ExampleManifestTests(unittest.TestCase):
    def assert_invalid(self, example: dict, pattern: str) -> None:
        fixture = ManifestFixture(example)
        try:
            with self.assertRaisesRegex(manifest.ManifestError, pattern):
                manifest.load_manifest(fixture.root)
        finally:
            fixture.close()

    def test_rust_result_oracle_is_rejected_instead_of_ignored(self) -> None:
        example = entry()
        example["expected"]["rust"] = {"result": {"tag": "int", "value": 2}}
        self.assert_invalid(example, "result is only supported by the Python")

    def test_unknown_host_authority_is_rejected(self) -> None:
        example = entry()
        example["requirements"]["authorities"] = ["root-everything"]
        self.assert_invalid(example, "unknown host requirements")

    def test_unknown_entry_field_is_rejected(self) -> None:
        example = entry()
        example["timeout_second"] = 99
        self.assert_invalid(example, "unknown fields.*timeout_second")

    def test_timeout_budgets_require_positive_integers(self) -> None:
        for field in ("timeout_seconds", "compile_timeout_seconds"):
            for value in (True, False, 0, -1, 1.5, "3", None):
                with self.subTest(field=field, value=value):
                    example = entry(edition="c17")
                    example["expected"]["c17"]["modes"] = ["aot"]
                    example[field] = value
                    self.assert_invalid(example, field + " must be a positive integer")

    def test_compile_budget_requires_a_compilation_phase(self) -> None:
        for edition in manifest.EDITIONS:
            with self.subTest(edition=edition):
                example = entry(edition=edition)
                example["compile_timeout_seconds"] = 3
                self.assert_invalid(example, "requires a c17 AOT expectation")

    @unittest.skipUnless(os.name == "posix", "executable fixture scripts are POSIX")
    def test_aot_compile_and_execution_budgets_are_independent(self) -> None:
        # Real compiler/payload subprocesses exercise both deadline paths. A
        # larger compile budget must not accidentally relax execution, and the
        # execution budget must not permit a compiler to overrun its own bound.
        cases = (
            (3, 1, 1.25, 0, 0, "[PASS] hello.O (AOT)", True),
            (1, 3, 1.25, 0, 1, "AOT compile: exceeded 1s", False),
            (3, 1, 0, 1.25, 1, "AOT: exceeded 1s", False),
            (None, 1, 1.25, 0, 1, "AOT compile: exceeded 1s", False),
        )
        for compile_budget, run_budget, compile_delay, run_delay, expected_status, diagnostic, ran in cases:
            with self.subTest(compile_budget=compile_budget, run_budget=run_budget,
                              compile_delay=compile_delay, run_delay=run_delay):
                example = entry(edition="c17")
                example["expected"]["c17"]["modes"] = ["aot"]
                example["timeout_seconds"] = run_budget
                if compile_budget is not None:
                    example["compile_timeout_seconds"] = compile_budget
                fixture = ManifestFixture(example)
                original_root = manifest.ROOT
                try:
                    compiler = fixture.root / "compiler"
                    completed = fixture.root / "payload-completed"
                    payload = (
                        f"#!{sys.executable}\nimport pathlib, time\n"
                        f"time.sleep({run_delay!r})\n"
                        f"pathlib.Path({str(completed)!r}).write_text('completed')\n"
                        "print('2')\n"
                    )
                    compiler.write_text(
                        f"#!{sys.executable}\nimport pathlib, sys, time\n"
                        f"time.sleep({compile_delay!r})\n"
                        "output = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
                        f"output.write_text({payload!r})\noutput.chmod(0o700)\n",
                        encoding="utf-8",
                    )
                    compiler.chmod(0o700)
                    manifest.ROOT = fixture.root
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        status = manifest.run_c17_aot_suite(
                            compiler, fixture.root / "backends", {"unit"}
                        )
                    self.assertEqual(status, expected_status, output.getvalue())
                    self.assertIn(diagnostic, output.getvalue())
                    self.assertEqual(completed.exists(), ran, output.getvalue())
                finally:
                    manifest.ROOT = original_root
                    fixture.close()

    def test_unknown_top_level_field_is_rejected(self) -> None:
        fixture = ManifestFixture(entry())
        try:
            fixture.write(
                {
                    "schema_version": 1,
                    "examples": [entry()],
                    "edition": "rust",
                }
            )
            with self.assertRaisesRegex(manifest.ManifestError, "unknown fields.*edition"):
                manifest.load_manifest(fixture.root)
        finally:
            fixture.close()

    def test_requirement_file_must_not_escape_repository(self) -> None:
        example = entry()
        example["requirements"]["files"] = ["../outside"]
        self.assert_invalid(example, "normalized paths below the repository root")

    def test_opt_in_and_python_import_names_are_validated(self) -> None:
        malformed_opt_in = entry()
        malformed_opt_in["requirements"]["opt_in"] = ["NOT_AN_ASSIGNMENT"]
        self.assert_invalid(malformed_opt_in, "malformed assignment")

        malformed_package = entry()
        malformed_package["requirements"]["python_packages"] = ["pkg;exit()"]
        self.assert_invalid(malformed_package, "invalid import name")

    def test_all_skipped_interpreter_sweep_fails(self) -> None:
        fixture = ManifestFixture(entry(classification="manual"))
        original_root = manifest.ROOT
        try:
            manifest.ROOT = fixture.root
            result = manifest.run_interpreter_suite(
                "rust",
                fixture.root / "unused-runner",
                fixture.root / "unused-backends",
                {"unit"},
            )
            self.assertEqual(result, 1)
        finally:
            manifest.ROOT = original_root
            fixture.close()

    @unittest.skipUnless(os.name == "posix", "process-group evidence is POSIX")
    def test_timeout_kills_subprocess_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sentinel = root / "late-write"
            command = [
                "/bin/sh",
                "-c",
                f"(sleep 2; printf late > '{sentinel}') & wait",
            ]
            with self.assertRaises(manifest.CommandTimeout):
                manifest._run_command(
                    command,
                    cwd=root,
                    env=os.environ.copy(),
                    timeout=1,
                )
            time.sleep(1.25)
            self.assertFalse(sentinel.exists(), "timed-out descendant survived")

    def test_checked_in_manifest_has_executable_semantic_cases(self) -> None:
        examples = manifest.load_manifest()
        for edition in manifest.EDITIONS:
            semantic = [
                example
                for example in examples
                if edition in example["editions"]
                and example["classification"] in {"unit", "integration"}
                and "interpreter"
                in example["expected"][edition].get("modes", ["interpreter"])
            ]
            self.assertTrue(semantic, f"{edition} has no semantic interpreter cases")
        c17_aot = [
            example
            for example in examples
            if "c17" in example["editions"]
            and "aot" in example["expected"]["c17"].get("modes", [])
        ]
        self.assertGreaterEqual(len(c17_aot), 2)
        for example in c17_aot:
            self.assertGreater(example["compile_timeout_seconds"],
                               example.get("timeout_seconds", 10))


if __name__ == "__main__":
    unittest.main()
