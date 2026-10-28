#!/usr/bin/env python3
"""Exercise C17 registration and AOT shim closure without external runtimes."""

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SHIM = '''from o_shim_common import command_loop, write_wire_message
def execute(command):
    write_wire_message({"status": "ok", "value": {"t": "str", "v": command["code"]}})
command_loop(execute)
'''


class BackendRegistrationTests(unittest.TestCase):
    def test_interpreter_and_aot_use_every_shipped_adapter(self):
        with tempfile.TemporaryDirectory(prefix="c17-backends-") as temporary:
            directory = Path(temporary)
            shims = directory / "backends"
            shutil.copytree(ROOT / "backends", shims, ignore=shutil.ignore_patterns("__pycache__"))
            names = sorted(path.name.removesuffix("_shim.py") for path in shims.glob("*_shim.py"))
            # Replace adapters with deterministic wire peers: this tests C17
            # routing/packaging independently of installed language engines.
            for name in names:
                (shims / f"{name}_shim.py").write_text(SHIM)
            source = directory / "registered.O"
            body = "\n".join(f"let value = {name}^({name})_{name}" for name in names)
            result = "|".join(f"{name}^(ok)_{name}" for name in names)
            source.write_text(f"O^(\n{body}\ntext^({result})_text\n)_O\n")
            expected = "|".join("ok" for _ in names)
            interpreter = subprocess.run(
                [RUNNER, str(source), str(shims)], capture_output=True, text=True, timeout=30
            )
            self.assertEqual(interpreter.returncode, 0, interpreter.stderr)
            self.assertEqual(interpreter.stdout, expected)

            executable = directory / "program"
            compile_result = subprocess.run(
                [COMPILER, str(source), "-o", str(executable), "--shim-dir", str(shims)],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            bundled = Path(str(executable) + ".shims")
            for name in names:
                self.assertEqual((bundled / f"{name}_shim.py").read_bytes(), SHIM.encode())
            shutil.rmtree(shims)
            source.unlink()
            aot = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
            self.assertEqual(aot.returncode, 0, aot.stderr)
            self.assertEqual(aot.stdout, expected)


if __name__ == "__main__":
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--runner", required=True)
    arguments.add_argument("--compiler", required=True)
    options = arguments.parse_args()
    RUNNER = str(Path(options.runner).resolve())
    COMPILER = str(Path(options.compiler).resolve())
    unittest.main(argv=[__file__], verbosity=2)
