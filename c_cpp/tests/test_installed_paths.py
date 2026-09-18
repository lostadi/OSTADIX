"""Run copied native C commands from unrelated directories with only PATH set."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "c_cpp/O"
COMPILER = ROOT / "c_cpp/olangc"


class InstalledPathsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ostadix-c-installed-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'runtime ü 界 🦉 "quoted"'
        self.bin = self.root / 'installed commands ü 界 🦉 "quoted"'
        self.cwd = self.root / "unrelated cwd"
        self.bin.mkdir()
        self.cwd.mkdir()
        shutil.copytree(ROOT / "c_cpp/src", self.repo / "c_cpp/src", ignore=shutil.ignore_patterns("*.o"))
        shutil.copytree(ROOT / "c_cpp/include", self.repo / "c_cpp/include")
        shutil.copytree(ROOT / "backends", self.repo / "backends")
        shutil.copy2(RUNNER, self.bin / "o-c")
        shutil.copy2(COMPILER, self.bin / "olangc-c")
        self.program = self.root / "answer ü.O"
        self.program.write_text("python^( __oval_result__ = 6 * 7 )_python\n", encoding="utf-8")
        self.env = {key: value for key, value in os.environ.items() if key not in {"O_BACKENDS_DIR", "BACKENDS_DIR", "O_LANG_ROOT"}}
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env.get("PATH", "")
        self.metadata = {"schema": 1, "repo_root": str(self.repo), "backends_dir": str(self.repo / "backends")}
        self.write_metadata()

    def write_metadata(self):
        # The real installer uses JSON's default Unicode escaping, including
        # surrogate pairs for supplementary codepoints in filesystem paths.
        (self.bin / "ostadix-install.json").write_text(json.dumps(self.metadata), encoding="utf-8")

    def run_command(self, *arguments, env=None, expected=0, cwd=None):
        result = subprocess.run(arguments, cwd=cwd or self.cwd, env=env or self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def assert_42(self, *arguments, env=None, cwd=None):
        self.assertEqual(self.run_command(*arguments, env=env, cwd=cwd).stdout.strip(), "42")

    def compile(self, name="answer", *options, env=None):
        output = self.cwd / name
        self.run_command("olangc-c", str(self.program), "-o", str(output), *options, env=env)
        return output

    def test_copied_interpreter_uses_adjacent_metadata_without_environment(self):
        self.assert_42("o-c", str(self.program))

    def test_relative_metadata_and_named_schema_resolve_beside_executable(self):
        self.metadata = {"schema": "ostadix.install/v1", "repo_root": os.path.relpath(self.repo, self.bin)}
        self.write_metadata()
        self.assert_42("o-c", str(self.program))
        output = self.compile()
        self.assert_42(str(output))

    def test_copied_compiler_builds_relocatable_standalone_bundle(self):
        output = self.compile()
        deployment = self.root / "standalone deployment"
        deployment.mkdir()
        shutil.move(str(output), deployment / "answer")
        shutil.move(str(output) + ".shims", deployment / "answer.shims")
        shutil.rmtree(self.repo)
        shutil.rmtree(self.bin)
        self.assert_42(str(deployment / "answer"))

    def test_explicit_paths_override_environment_and_metadata(self):
        env = dict(self.env, O_BACKENDS_DIR=str(self.root / "missing override"), BACKENDS_DIR=str(self.root / "also missing"))
        self.assert_42("o-c", str(self.program), str(self.repo / "backends"), env=env)
        output = self.compile("explicit", "--shim-dir", str(self.repo / "backends"), env=env)
        self.assert_42(str(output))

    def test_environment_backend_paths_override_metadata(self):
        broken = self.root / "selected override"
        shutil.copytree(self.repo / "backends", broken)
        (broken / "python_shim.py").write_text("raise RuntimeError('SELECTED_BACKEND_OVERRIDE')\n")
        for variable in ("O_BACKENDS_DIR", "BACKENDS_DIR"):
            with self.subTest(variable=variable):
                env = dict(self.env, **{variable: str(broken)})
                result = self.run_command("o-c", str(self.program), env=env, expected=1)
                self.assertIn("SELECTED_BACKEND_OVERRIDE", result.stderr)
                output = self.compile(variable, env=env)
                result = self.run_command(str(output), expected=1)
                self.assertIn("SELECTED_BACKEND_OVERRIDE", result.stderr)

    def test_o_backends_precedes_compatibility_environment(self):
        env = dict(self.env, O_BACKENDS_DIR=str(self.repo / "backends"), BACKENDS_DIR=str(self.root / "missing"))
        self.assert_42("o-c", str(self.program), env=env)

    def test_malformed_or_unknown_metadata_keeps_relative_fallback(self):
        for text in ("not JSON", '{"schema":2,"backends_dir":"/missing"}', '{"schema":true,"backends_dir":"/missing"}'):
            with self.subTest(text=text):
                (self.bin / "ostadix-install.json").write_text(text)
                self.assert_42("o-c", str(self.program), cwd=self.repo)

    def test_build_tree_runtime_source_fallback_remains_usable(self):
        output = self.cwd / "build-tree"
        # CMake exposes src/include beside the binary but does not install
        # metadata or backend adapters. Its existing interface supplies shims.
        self.run_command(str(COMPILER), str(self.program), "-o", str(output), "--shim-dir", str(ROOT / "backends"))
        self.assert_42(str(output))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", type=Path, default=RUNNER)
    parser.add_argument("--compiler", type=Path, default=COMPILER)
    args = parser.parse_args()
    RUNNER, COMPILER = args.runner.resolve(), args.compiler.resolve()
    unittest.main(argv=[__file__], verbosity=2)
