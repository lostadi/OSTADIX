"""Python reference integration with the shipped stateless backend shims."""

import math
import os
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from o_lang import EvalContext, OBool, OFloat, OInt, OList, OMap, ONull, OStr, run
from o_lang.backends.shim_backend import ShimBackend, _from_wire
from o_lang.parser import ExpressionNode, LetBinding, TextPart, parse


ROOT = Path(__file__).resolve().parents[1]
LISP_AVAILABLE = any(shutil.which(name) for name in ("sbcl", "ecl", "clisp", "ccl"))


class PythonShimBackendTests(unittest.TestCase):
    def fake_backend(self, directory, source, timeout=2):
        shutil.copyfile(ROOT / "backends" / "o_shim_common.py", Path(directory) / "o_shim_common.py")
        path = Path(directory) / "javascript_shim.py"
        path.write_text(
            f"import sys\nsys.path.insert(0, {str(ROOT / 'backends')!r})\n"
            "from o_shim_common import read_wire_message, write_wire_message\n"
            "request = read_wire_message()\n" + source,
            encoding="utf-8",
        )
        return ShimBackend("javascript", Path(directory), timeout=timeout)

    def test_builtins_work_with_standalone_package_and_missing_shims(self):
        with tempfile.TemporaryDirectory() as directory:
            shutil.copytree(ROOT / "o_lang", Path(directory) / "o_lang",
                            ignore=shutil.ignore_patterns("__pycache__"))
            environment = dict(os.environ, PYTHONPATH=directory,
                               O_BACKENDS_DIR=str(Path(directory) / "absent"))
            result = subprocess.run(
                [sys.executable, "-c", "from o_lang import run, OInt; "
                 "assert run('python^(21 * 2)_python') == OInt(42)"],
                cwd=directory, env=environment, capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_selected_shim_directory_supplies_protocol_and_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            self.fake_backend(directory,
                "write_wire_message({'status': 'ok', 'value': {'t': 'str', 'v': request['code']}})\n")
            with patch.dict(os.environ, O_BACKENDS_DIR=directory):
                self.assertEqual(run("javascript^(selected directory)_javascript"),
                                 OStr("selected directory"))

    def test_missing_protocol_helper_has_actionable_error(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = ShimBackend("javascript", Path(directory))
            with self.assertRaisesRegex(RuntimeError, "set O_BACKENDS_DIR"):
                backend.evaluate("unused", None)

    def test_parser_recognizes_polyglot_binding_rhs_and_preserves_scopes(self):
        document = parse(
            'O^(let phrase = common_lisp^((princ "hello"))_common_lisp '
            'javascript^(console.log("$phrase"))_javascript)_O'
        )
        children = [node for node in document.body[0].body
                    if not (isinstance(node, TextPart) and not node.text.strip())]
        self.assertIsInstance(children[0], LetBinding)
        self.assertEqual(children[0].expr.language, "common_lisp")
        self.assertIsInstance(children[1], ExpressionNode)
        self.assertEqual(children[1].language, "javascript")

    @unittest.skipUnless(LISP_AVAILABLE and shutil.which("node"), "requires Common Lisp and Node.js")
    def test_python_lisp_javascript_binding_chain(self):
        source = (
            'O^(let greeting = python^("hello")_python '
            'let phrase = common_lisp^((princ (concatenate \'string "$greeting" '
            '" from Python and Lisp")))_common_lisp '
            'javascript^(console.log("$phrase" + " and JavaScript!"))_javascript)_O'
        )
        self.assertEqual(run(source), OStr("hello from Python and Lisp and JavaScript!"))

    @unittest.skipUnless(shutil.which("node"), "requires Node.js")
    def test_javascript_typed_stdout_and_generic_splices(self):
        self.assertEqual(
            run('O^(let flag = python^(True)_python '
                'javascript^(console.log(JSON.stringify({flag: $flag, values: [1, null]})))_javascript)_O'),
            OMap((("flag", OBool(True)), ("values", OList((OInt(1), ONull()))))),
        )
        self.assertEqual(run('javascript^(console.log("9223372036854775808"))_javascript'),
                         OInt(9223372036854775808))

    @unittest.skipUnless(shutil.which("node"), "requires Node.js")
    def test_javascript_numeric_environment_matches_stateless_shim(self):
        context = EvalContext()
        run('javascript[4]^(globalThis.remembered = 7)_javascript[4]', context)
        self.assertEqual(run('javascript[4]^(console.log(typeof remembered))_javascript[4]', context),
                         OStr("undefined"))

    @unittest.skipUnless(shutil.which("node"), "requires Node.js")
    def test_javascript_nonfinite_stdout_preserves_float_values(self):
        for expression, expected in (("NaN", math.nan), ("Infinity", math.inf),
                                     ("-Infinity", -math.inf), ('"1e400"', math.inf)):
            with self.subTest(expression=expression):
                value = run(f"javascript^(console.log({expression}))_javascript")
                self.assertIsInstance(value, OFloat)
                if math.isnan(expected):
                    self.assertTrue(math.isnan(value.value))
                else:
                    self.assertEqual(value.value, expected)
        for expression, spelling in (("NaN", "NaN"), ("Infinity", "inf"), ("-Infinity", "-inf")):
            source = (f"O^(let value = javascript^(console.log({expression}))_javascript "
                      'javascript^(console.log("value:$value"))_javascript)_O')
            self.assertEqual(run(source), OStr(f"value:{spelling}"))

    def test_binary_float_wire_bits_preserve_finite_values_and_signed_zero(self):
        for value in (1.5, -0.0, 1e-300):
            bits = struct.pack(">d", value)
            decoded = _from_wire({"t": "number", "v": {
                "kind": "binary_float", "format": "f64", "bits": list(bits)}})
            self.assertIsInstance(decoded, OFloat)
            self.assertEqual(struct.pack(">d", decoded.value), bits)

    def test_malformed_numeric_wire_payloads_are_rejected(self):
        payloads = [
            {"kind": "binary_float", "format": "f32", "bits": [0] * 8},
            {"kind": "binary_float", "format": "f64", "bits": [0] * 7},
            {"kind": "binary_float", "format": "f64", "bits": "00000000"},
            {"kind": "binary_float", "format": "f64", "bits": [0] * 7 + [256]},
            {"kind": "binary_float", "format": "f64", "bits": [0] * 7 + [-1]},
            {"kind": "binary_float", "format": "f64", "bits": [0] * 7 + [True]},
            {"kind": "binary_float", "format": "f64", "bits": [0] * 7 + [0.0]},
            {"kind": "binary_float", "format": "f64"},
            {"kind": "int", "v": True},
            {"kind": "int", "v": "1.5"},
            {"kind": "int", "v": " 1 "},
        ]
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                _from_wire({"t": "number", "v": payload})

    def test_nonfinite_source_splices_match_native_generic_spelling(self):
        for name in ("javascript", "common_lisp"):
            for value, spelling in ((math.nan, "NaN"), (math.inf, "inf"), (-math.inf, "-inf")):
                with self.subTest(name=name, value=value):
                    self.assertEqual(ShimBackend(name).render_child(OFloat(value)), spelling)

    def test_generic_splices_match_native_scalar_and_collection_policy(self):
        backend = ShimBackend("javascript")
        self.assertEqual(backend.render_child(ONull()), "null")
        self.assertEqual(backend.render_child(OBool(True)), "true")
        self.assertEqual(backend.render_child(OStr("hello")), "hello")
        self.assertEqual(backend.render_child(OFloat(1.5)), "1.5")
        self.assertEqual(backend.render_child(OFloat(-0.0)), "-0.0")
        self.assertEqual(backend.render_child(OMap((("z", OInt(2)), ("a", OBool(False))))),
                         '{"a": false, "z": 2}')

    def test_shim_error_is_not_retried_and_retains_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executions"
            backend = self.fake_backend(directory,
                f"with open({str(marker)!r}, 'a') as output: output.write('executed\\n')\n"
                "write_wire_message({'status': 'err', 'message': 'engine failed'})\n")
            context = EvalContext()
            context.backends["javascript"] = backend
            with self.assertRaisesRegex(RuntimeError, "javascript shim: engine failed"):
                run("javascript^(ignored)_javascript", context)
            self.assertEqual(marker.read_text(), "executed\n")

    def test_malformed_or_unsupported_wire_values_are_rejected(self):
        cases = (
            "sys.stdout.buffer.write(b'\\x00\\x00\\x00\\x04bad')\n",
            "write_wire_message({'status': 'ok', 'value': {'t': 'native_handle'}})\n",
            "write_wire_message({'status': 'ok', 'value': {'t': 'bool', 'v': 1}})\n",
            "write_wire_message({'status': 'ok', 'value': {'t': 'null'}})\n"
            "write_wire_message({'status': 'ok', 'value': {'t': 'null'}})\n",
        )
        for source in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                backend = self.fake_backend(directory, source)
                with self.assertRaisesRegex(RuntimeError, "shim protocol error"):
                    backend.evaluate("unused", None)

    def test_nonzero_shim_exit_reports_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = self.fake_backend(directory, "sys.stderr.write('missing engine')\nsys.exit(7)\n")
            with self.assertRaisesRegex(RuntimeError, "exited 7: missing engine"):
                backend.evaluate("unused", None)

    @unittest.skipUnless(os.name == "posix", "process groups require POSIX")
    def test_timeout_terminates_shim_and_engine_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "surviving-engine"
            child = f"import time; time.sleep(0.6); open({str(marker)!r}, 'w').write('alive')"
            backend = self.fake_backend(directory,
                "import subprocess, time\n"
                f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
                "time.sleep(30)\n", timeout=0.2)
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                backend.evaluate("unused", None)
            time.sleep(0.7)
            self.assertFalse(marker.exists(), "timed-out engine continued running")


if __name__ == "__main__":
    unittest.main()
