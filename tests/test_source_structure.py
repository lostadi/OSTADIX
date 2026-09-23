"""Parse-only native CLI metadata regressions; no backend code is executed.

Build: cargo build --release --locked --bin O
Run: python -m unittest discover -s tests -p test_source_structure.py -v
O_SOURCE_STRUCTURE_TEST_BIN may select an already-built evaluator.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("O_SOURCE_STRUCTURE_TEST_BIN", ROOT / "target/release/O"))


class SourceStructureTests(unittest.TestCase):
    def describe(self, source):
        result = subprocess.run([str(BINARY), "--eval", source, "--check", "--json"],
                                cwd=ROOT, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        # Missing initial bindings are descriptive metadata, not a new parser
        # rejection. A host may deliberately supply those bindings later.
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["stage"], "parse")
        structure = payload["source_structure"]
        self.assertEqual(structure["schema"], "ostadix.source-structure/v1")
        self.assertIn("no execution", structure["meaning"])
        return structure

    def test_missing_binding_is_reported_without_rejecting_valid_syntax(self):
        structure = self.describe("python^(__oval_result__ = $missing)_python")
        self.assertEqual(structure["required_initial_bindings"], ["missing"])
        self.assertEqual(structure["languages"], ["python"])
        self.assertFalse(structure["top_level_literal_text"])

    def test_prior_store_resolves_later_load(self):
        structure = self.describe("let data = python^([2, 7, 11])_python\n"
                                  "python^(__oval_result__ = sum($data))_python")
        self.assertEqual(structure["required_initial_bindings"], [])
        self.assertGreater(structure["plan_nodes"], 3)

    def test_forward_store_does_not_satisfy_earlier_load(self):
        structure = self.describe("python^(__oval_result__ = $later)_python\n"
                                  "let later = python^(1)_python")
        self.assertEqual(structure["required_initial_bindings"], ["later"])

    def test_inner_store_stays_scoped_and_cannot_satisfy_outer_load(self):
        structure = self.describe("let answer = O^(let inner = python^(2)_python\n"
                                  "python^(__oval_result__ = $inner)_python)_O\n"
                                  "python^(__oval_result__ = $inner)_python")
        self.assertEqual(structure["required_initial_bindings"], ["inner"])

    def test_shadow_initializer_reads_existing_outer_value(self):
        structure = self.describe("let x = python^(1)_python\n"
                                  "let x = python^(__oval_result__ = $x + 1)_python\n"
                                  "python^(__oval_result__ = $x)_python")
        self.assertEqual(structure["required_initial_bindings"], [])
        missing = self.describe("let x = python^(__oval_result__ = $x + 1)_python")
        self.assertEqual(missing["required_initial_bindings"], ["x"])

    def test_escaped_bash_variable_is_backend_text_not_an_o_binding(self):
        escaped = self.describe(r'bash^(printf "%s" \$HOME)_bash')
        self.assertEqual(escaped["required_initial_bindings"], [])
        self.assertEqual(escaped["languages"], ["bash"])
        splice = self.describe('bash^(printf "%s" $HOME)_bash')
        self.assertEqual(splice["required_initial_bindings"], ["HOME"])

    def test_literal_text_and_exec_are_distinguished(self):
        text = self.describe("Here is the answer: 42")
        self.assertTrue(text["top_level_literal_text"])
        self.assertEqual(text["languages"], [])
        code = self.describe("# source comment\npython^(__oval_result__ = 42)_python\n")
        self.assertFalse(code["top_level_literal_text"])
        self.assertEqual(code["languages"], ["python"])
        mixed = self.describe("Explanation\npython^(__oval_result__ = 42)_python")
        self.assertTrue(mixed["top_level_literal_text"])
        self.assertEqual(mixed["languages"], ["python"])

    def test_quoted_program_does_not_require_its_future_bindings(self):
        structure = self.describe("quote^(python^(__oval_result__ = $future)_python)_quote")
        self.assertEqual(structure["required_initial_bindings"], [])
        self.assertNotIn("python", structure["languages"])

    def test_missing_names_are_sorted_and_deduplicated(self):
        structure = self.describe("python^(__oval_result__ = [$z, $a, $z])_python")
        self.assertEqual(structure["required_initial_bindings"], ["a", "z"])

    def test_parse_check_has_no_backend_side_effects(self):
        with tempfile.TemporaryDirectory(prefix="source-structure-") as temporary:
            marker = Path(temporary) / "must-not-exist"
            source = (f"python^(open({str(marker)!r}, 'w').write('effect')\n"
                      "__oval_result__ = $missing)_python")
            structure = self.describe(source)
            self.assertEqual(structure["required_initial_bindings"], ["missing"])
            self.assertFalse(marker.exists())

    def test_python_result_capture_is_descriptive_and_preserves_intermediate_blocks(self):
        structure = self.describe("python^(a=17;b=25;result=a+b)_python")
        self.assertEqual(structure["backend_syntax_checks"][0]["result_capture"], "none")
        intermediate = self.describe("python^(a=17;b=25)_python\n"
                                     "python^(__oval_result__=a+b)_python")
        self.assertEqual([check["result_capture"] for check in intermediate["backend_syntax_checks"]],
                         ["none", "explicit_result"])
        dynamic = self.describe("python^(__oval_result__=$input)_python")
        self.assertEqual(dynamic["backend_syntax_checks"][0]["state"], "skipped")
        self.assertEqual(dynamic["backend_syntax_checks"][0]["result_capture"], "unknown")


class PythonCaptureDiagnosticTests(unittest.TestCase):
    """Exercise the exact embedded parser, including never evaluating the source."""
    def check_sources(self, sources):
        rust = (ROOT / "src/cli_source_structure.rs").read_text()
        script = re.search(r'const PYTHON_SYNTAX_CHECK: &str = r#"(.*?)"#;', rust, re.S).group(1)
        process = subprocess.run([sys.executable, "-I", "-S", "-c", script],
                                 input=json.dumps([dict(index=i, source=source)
                                                   for i, source in enumerate(sources)]),
                                 text=True, capture_output=True, timeout=5)
        self.assertEqual(process.returncode, 0, process.stderr)
        return json.loads(process.stdout)

    def test_shim_publication_syntax_and_unknown_cases(self):
        cases = [
            ("a=17;b=25;result=a+b", "none"),
            ("__oval_result__=17+25", "explicit_result"),
            ("__oval_result__: int = 42", "explicit_result"),
            ("__oval_result__, other = 42, 1", "explicit_result"),
            ("a=17;b=25\na+b", "trailing_expression"),
            ("print(42)\na=1", "stdout"),
            ("# __oval_result__=42\nresult='__oval_result__=42'", "none"),
            ("def local():\n    __oval_result__=42", "none"),
            ("def local():\n    __oval_result__=42\nlocal()", "trailing_expression"),
            ("def local():\n    __oval_result__=42\nresult=local()", "unknown"),
            ("if condition:\n    __oval_result__=42", "unknown"),
            ("globals()['__oval_result__']=42", "unknown"),
            ("import maybe_prints", "unknown"),
            ("print(42, file=other)\na=1", "unknown"),
            ("None", "trailing_expression"),
        ]
        results = self.check_sources([source for source, expected in cases])
        for (source, expected), result in zip(cases, results):
            with self.subTest(source=source):
                self.assertEqual(result["state"], "valid")
                self.assertEqual(result["result_capture"], expected)

    def test_invalid_source_remains_unknown_and_candidate_effects_never_run(self):
        with tempfile.TemporaryDirectory(prefix="capture-diagnostic-") as directory:
            marker = Path(directory) / "must-not-exist"
            results = self.check_sources(["if:", f"result=open({str(marker)!r}, 'w').write('effect')"])
            self.assertEqual(results[0]["state"], "invalid")
            self.assertEqual(results[0]["result_capture"], "unknown")
            self.assertEqual(results[1]["state"], "valid")
            self.assertEqual(results[1]["result_capture"], "unknown")
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
