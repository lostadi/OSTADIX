"""Exercise hosted boot orchestration against controlled edition processes."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class HostedBootTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ostadix hosted boot ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.scratch = self.root / "tmp"
        self.scratch.mkdir()
        (self.root / "Cargo.toml").touch()
        (self.root / "ocore/kernel").mkdir(parents=True)
        (self.root / "ocore/kernel/build.sh").touch()
        (self.root / "c_cpp").mkdir()
        shutil.copyfile(ROOT / "boot-and-test.sh", self.root / "boot-and-test.sh")

        # A closed PATH makes absent optional tools deterministic even on hosts
        # with several Python/compiler installations. Real Unix utilities still
        # perform transcript creation, comparison, and cleanup.
        for command in ("dirname", "mktemp", "cat", "cmp", "rm"):
            executable = shutil.which(command)
            self.assertIsNotNone(executable, f"test prerequisite missing: {command}")
            (self.bin / command).symlink_to(executable)
        self.install(
            self.bin / "cargo",
            '''printf '%s\\n' "${O_EXECUTOR-unset}" >> "$CASE_DIR/cargo-calls"
case "${O_EXECUTOR-unset}" in
  graph)
    output=graph
    for argument in "$@"; do
      if [ "$argument" = backends ]; then output=graph_backends; fi
    done
    status=${FAKE_GRAPH_STATUS:-0}
    ;;
  serial) output=serial; status=${FAKE_SERIAL_STATUS:-0} ;;
  *) printf 'executor was not selected\\n' >&2; exit 92 ;;
esac
cat "$CASE_DIR/$output-output"
exit "$status"
''',
        )
        self.install(
            self.bin / "python3",
            '''cat "$CASE_DIR/python-output"
exit "${FAKE_PYTHON_STATUS:-0}"
''',
        )
        self.install(
            self.bin / "make",
            '''printf 'C compiler diagnostic\\n'
exit "${FAKE_MAKE_STATUS:-0}"
''',
        )
        self.install(self.bin / "cc", "exit 0\n")
        self.install(
            self.root / "c_cpp/O",
            '''printf 'executed\\n' >> "$CASE_DIR/c17-calls"
cat "$CASE_DIR/c17-output"
exit "${FAKE_C17_STATUS:-0}"
''',
        )
        for edition in ("graph", "graph_backends", "serial", "python", "c17"):
            self.output(edition, b"hello from all editions!\n")

    @staticmethod
    def install(path, body):
        path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
        path.chmod(0o755)

    def output(self, edition, content):
        (self.root / f"{edition}-output").write_bytes(content)

    def run_hosted(self, **overrides):
        environment = {
            "PATH": str(self.bin),
            "TMPDIR": str(self.scratch),
            "CASE_DIR": str(self.root),
            "LC_ALL": "C",
        }
        environment.update(overrides)
        (self.root / "cargo-calls").write_text("", encoding="utf-8")
        result = subprocess.run(
            ["/bin/bash", str(self.root / "boot-and-test.sh"), "hosted"],
            cwd=self.scratch,
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(list(self.scratch.iterdir()), [], "transcripts leaked")
        return result

    def assert_failure(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)
        self.assertNotIn("[skip]", result.stdout + result.stderr)

    def test_matching_executions_pass_and_run_each_reference(self):
        result = self.run_hosted()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("serial oracle agrees (differential check)", result.stdout)
        self.assertIn("python reference ran hello.O", result.stdout)
        self.assertIn("C17 edition ran hello.O", result.stdout)
        self.assertEqual(
            (self.root / "cargo-calls").read_text().splitlines(),
            ["graph", "graph", "serial"],
        )

    def test_serial_result_mismatch_fails_despite_successful_process(self):
        self.output("serial", b"a different successful result\n")
        result = self.run_hosted()
        self.assert_failure(result, "serial oracle output differs from graph executor")
        self.assertNotIn("serial oracle agrees", result.stdout)

    def test_trailing_newlines_are_part_of_the_differential_check(self):
        for serial in (b"hello from all editions!", b"hello from all editions!\n\n"):
            with self.subTest(serial=serial):
                self.output("serial", serial)
                self.assert_failure(
                    self.run_hosted(),
                    "serial oracle output differs from graph executor",
                )

    def test_explicit_backend_graph_result_is_also_compared(self):
        self.output("graph_backends", b"wrong backend result\n")
        self.assert_failure(
            self.run_hosted(), "graph output differs with explicit backends"
        )

    def test_inherited_serial_selection_cannot_bypass_graph_execution(self):
        self.output("serial", b"serial-only result\n")
        result = self.run_hosted(O_EXECUTOR="serial")
        self.assert_failure(result, "serial oracle output differs from graph executor")
        self.assertEqual(
            (self.root / "cargo-calls").read_text().splitlines(),
            ["graph", "graph", "serial"],
        )

    def test_rust_nonzero_exit_fails_even_with_matching_stdout(self):
        for variable, message in (
            ("FAKE_GRAPH_STATUS", "hosted hello.O failed"),
            ("FAKE_SERIAL_STATUS", "serial oracle failed"),
        ):
            with self.subTest(variable=variable):
                self.assert_failure(self.run_hosted(**{variable: "23"}), message)

    def test_available_python_runtime_failure_is_not_a_skip(self):
        self.assert_failure(
            self.run_hosted(FAKE_PYTHON_STATUS="23"), "python reference edition failed"
        )

    def test_c_build_failure_is_not_a_skip_and_preserves_diagnostics(self):
        result = self.run_hosted(FAKE_MAKE_STATUS="23")
        self.assert_failure(result, "C17 edition build failed")
        self.assertIn("C compiler diagnostic", result.stderr)
        self.assertFalse((self.root / "c17-calls").exists())

    def test_available_c_runtime_failure_is_not_a_skip(self):
        self.assert_failure(
            self.run_hosted(FAKE_C17_STATUS="23"), "C17 edition failed"
        )

    def test_absent_optional_tools_are_reported_as_skips(self):
        for command in ("python3", "make", "cc"):
            (self.bin / command).unlink()
        result = self.run_hosted()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("python3 absent", result.stdout)
        self.assertIn("make/cc absent", result.stdout)
        self.assertEqual(result.stdout.count("[skip]"), 2)
        self.assertFalse((self.root / "c17-calls").exists())


if __name__ == "__main__":
    unittest.main()
