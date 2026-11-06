#!/usr/bin/env python3
"""Source/extracted-driver controls; these do not execute the new Rust driver.

The real worker refuses an invalid capture. A successful fnmatch control and a
hostile PATH sentinel distinguish interpreter selection without forging an
admitted capture, rerunning an upstream build, or claiming runtime execution.
"""
from pathlib import Path
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/bin/olangc/native_runtime.rs"


def function(name):
    source = SOURCE.read_text()
    start = source.index("fn " + name + "(")
    match = re.search(r"\n(?:pub(?:\([^\n]*\))? )?fn \w+\(", source[start + 1:])
    return source[start:] if match is None else source[start:start + 1 + match.start()]


class ProviderGroupRepairDriverTests(unittest.TestCase):
    def hostile_environment(self, directory):
        sentinel = directory / "python3"
        sentinel.write_text("#!/bin/sh\nprintf 'hostile-python3\\n' >&2\nexit 97\n")
        sentinel.chmod(0o755)
        env = dict(os.environ, PATH=str(directory), TMPDIR=str(directory))
        baseline = subprocess.run(["python3", "-I", "-c", "raise SystemExit(0)"],
                                  env=env, capture_output=True)
        self.assertEqual(baseline.returncode, 97)
        self.assertEqual(baseline.stderr, b"hostile-python3\n")
        return env

    def test_selected_python_runs_original_fnmatch_driver_with_hostile_path(self):
        body = function("lowering_partition")
        match = re.search(r'python_command\(python\)\.args\(\[\s*"-c",\s*("(?:[^"\\]|\\.)*")', body)
        self.assertIsNotNone(match, "partition must invoke the selected interpreter")
        program = json.loads(match.group(1))
        with tempfile.TemporaryDirectory(prefix="provider-python-partition-") as name:
            env = self.hostile_environment(Path(name))
            for pairs, expected in [([["generated/config.c", "generated/*.c"]], 0),
                                    ([["runtime.c", "configure/*.c"]], 1)]:
                child = subprocess.run([str(Path(sys.executable).resolve()), "-I", "-c", program],
                                       input=json.dumps(pairs).encode(), env=env, capture_output=True)
                self.assertEqual(child.returncode, expected, child.stderr.decode())
                self.assertEqual(child.stdout, b"")
                self.assertEqual(child.stderr, b"")

    def test_selected_python_runs_real_capture_refusal_with_hostile_path(self):
        body = function("reverify_capture_with_python")
        self.assertRegex(body, r'python_command\(python\)\s*\.args\(\["-c", program\]\)')
        match = re.search(r'let program = ("(?:[^"\\]|\\.)*");', body)
        self.assertIsNotNone(match)
        program = json.loads(match.group(1))
        worker = (ROOT / "scripts/ocore_runtime_capture.py").read_text()
        import hashlib
        payload = {"source": worker, "worker_sha256": hashlib.sha256(worker.encode()).hexdigest(),
                   "report": {"schema": "intentionally-invalid-control"}}
        with tempfile.TemporaryDirectory(prefix="provider-python-capture-") as name:
            env = self.hostile_environment(Path(name))
            child = subprocess.run([str(Path(sys.executable).resolve()), "-I", "-c", program],
                                   input=json.dumps(payload).encode(), env=env, capture_output=True)
            self.assertEqual(child.returncode, 1)
            self.assertEqual(child.stdout, b"")
            self.assertIn(b"CaptureError: capture verification requires ocore-runtime-capture-v1", child.stderr)
            self.assertNotIn(b"hostile-python3", child.stderr)

    def test_selected_interpreter_is_threaded_through_actual_admission_helpers(self):
        self.assertIn("Command::new(python)", function("python_command"))
        self.assertIn('command.arg("-I")', function("python_command"))
        self.assertIn("python: &Path", function("lowering_partition"))
        self.assertIn("lowering_partition(capture, python)", function("capture_admission_with_python"))
        wrapper = function("lower_with_compiler")
        self.assertRegex(wrapper, r'lower_held_capture_with_compiler\([\s\S]*selected_python,')
        self.assertRegex(function("lower_held_capture_with_compiler"),
                         r'capture_admission_with_python\(\s*&capture,\s*selected_python\.unwrap_or_else')
        for name in ["lowering_partition", "reverify_capture_with_python"]:
            self.assertNotIn('Command::new("python3")', function(name))
        self.assertIn('capture_admission_with_python(capture, Path::new("python3"))',
                      function("capture_admission"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
