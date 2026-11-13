"""Exercise snapshot custody and compiler selection without building a kernel."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("okernel_repro", ROOT / "scripts/verify_okernel_repro.py")
repro = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repro)


class SourceSnapshotTests(unittest.TestCase):
    def test_snapshot_includes_working_source_without_changing_real_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source, output = base / "repo", base / "evidence"
            source.mkdir()
            output.mkdir()
            def git(*args):
                return subprocess.run(["git", "-C", str(source), *args], check=True, capture_output=True).stdout
            git("init", "-q")
            git("config", "user.name", "Snapshot Test")
            git("config", "user.email", "snapshot@example.invalid")
            (source / "Cargo.lock").write_text("locked dependencies\n")
            (source / "tracked").write_text("base\n")
            (source / "removed").write_text("remove me\n")
            git("add", ".")
            git("commit", "-qm", "base")
            (source / "tracked").write_text("staged\n")
            git("add", "tracked")
            (source / "tracked").write_text("working content\n")
            (source / "new source").write_text("untracked\n")
            (source / "removed").unlink()
            before_index = (source / ".git/index").read_bytes()
            before_head = git("rev-parse", "HEAD")
            snapshot = repro.source_snapshot(source, output)
            self.assertEqual((source / ".git/index").read_bytes(), before_index)
            self.assertEqual(git("rev-parse", "HEAD"), before_head)
            self.assertFalse((output / "snapshot.index").exists())
            with tarfile.open(snapshot["archive"]) as archive:
                self.assertEqual({member.mtime for member in archive.getmembers()}, {1})
                self.assertEqual(archive.extractfile("tracked").read(), b"working content\n")
                self.assertEqual(archive.extractfile("new source").read(), b"untracked\n")
                self.assertNotIn("removed", archive.getnames())
            again = base / "evidence-again"
            again.mkdir()
            self.assertEqual(repro.source_snapshot(source, again)["archive_sha256"], snapshot["archive_sha256"])


class CompilerSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "ocore/kernel").mkdir(parents=True)
        self.script = self.root / "ocore/kernel/build-m5-artifacts.sh"
        self.script.write_bytes((ROOT / "ocore/kernel/build-m5-artifacts.sh").read_bytes())
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.compiler = self.tool("selected-ocorec", 'while [ "$1" != -o ]; do shift; done\nprintf object > "$2"\n')
        self.linker = self.tool("selected-lld", 'while [ "$1" != -o ]; do shift; done\nprintf service > "$2"\n')
        self.tool("cargo", 'printf "%s\\n" "$@" > "$CARGO_LOG"\n')
        self.tool("python3", '''case "$1" in
  */pack_ovfs.py) mkdir -p "$2"; printf image > "$2/root-test.ovfs"; printf '%s/root-test.ovfs\\n' "$2" ;;
  */verify_ovfs.py) exit 0 ;;
  *) exit 92 ;;
esac
''')
        self.env = {
            **os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "OCOREC_BIN": str(self.compiler), "OCORE_LLD": str(self.linker),
            "OCORE_M5_BUILD_DIR": str(self.root / "artifacts"),
            "CARGO_LOG": str(self.root / "cargo.log"),
        }

    def tool(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\nset -eu\n" + body)
        path.chmod(0o755)
        return path

    def run_builder(self):
        return subprocess.run(["bash", str(self.script)], cwd=self.root, env=self.env, capture_output=True, text=True)

    def test_explicit_compiler_skips_cargo_and_keeps_outputs_isolated(self):
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("M5 artifact build: PASS", result.stdout)
        self.assertFalse((self.root / "cargo.log").exists())
        self.assertTrue((self.root / "artifacts/pass-one/repl.elf").is_file())
        self.assertFalse((self.root / "target").exists())

    def test_cargo_target_directory_selects_compiler_and_uses_lockfile(self):
        self.env.pop("OCOREC_BIN")
        target = self.root / "private-target"
        (target / "debug").mkdir(parents=True)
        (target / "debug/ocorec").write_bytes(self.compiler.read_bytes())
        (target / "debug/ocorec").chmod(0o755)
        self.env["CARGO_TARGET_DIR"] = str(target)
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--locked", (self.root / "cargo.log").read_text().splitlines())
        self.assertFalse((self.root / "target").exists())

    def test_invalid_explicit_linker_fails_instead_of_falling_back(self):
        self.env["OCORE_LLD"] = str(self.root / "missing-lld")
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("OCORE_LLD is set but not executable", result.stderr)


if __name__ == "__main__":
    unittest.main()
