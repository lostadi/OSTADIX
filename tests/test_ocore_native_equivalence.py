"""Regression tests for the native gate's artifact and compiler provenance.

The fake tools below are real subprocesses. Only executable ELF validation is
substituted: the fake linker emits Python executables so the producer, fault,
never-return, and receipt paths can run without Clang or QEMU. These tests do
not establish native code-generation conformance.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check_ocore_native_equivalence.py"
SPEC = importlib.util.spec_from_file_location("native_equivalence_gate", SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


@contextmanager
def changed_directory(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


FAKE_TOOL = r'''
import os
from pathlib import Path
import sys

if "--version" in sys.argv:
    print("fake " + str(Path(__file__).resolve()))
    sys.exit(0)

name = Path(__file__).name
mode = Path(__file__).with_name("mode").read_text().strip()
output = Path(sys.argv[sys.argv.index("-o") + 1])
output.parent.mkdir(parents=True, exist_ok=True)
if name == "ocorec":
    if mode == "compiler" or (mode == "reproducible" and "--keep-asm" not in sys.argv):
        sys.exit(0)
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[16:18] = (1).to_bytes(2, "little")
    header[18:20] = (62).to_bytes(2, "little")
    output.write_bytes(header)
    if "--keep-asm" in sys.argv and mode != "assembly":
        output.with_suffix(".s").write_text("fresh assembly\n")
elif name == "clang":
    if mode == output.stem:
        sys.exit(0)
    if any(arg.startswith("-DFAULT_CASE=") for arg in sys.argv):
        body = "import os, signal\nos.kill(os.getpid(), signal.SIGILL)\n"
    elif any(arg.startswith("-DNEVER_CASE=") for arg in sys.argv):
        body = "import sys\nsys.exit(42)\n"
    else:
        body = "print('OCORE-NATIVE-EQUIVALENCE digest=0123456789abcdef cases=12288')\n"
    output.write_text("#!" + sys.executable + "\n" + body)
    output.chmod(0o755)
else:
    raise SystemExit("unexpected fake tool invocation: " + name)
'''


class NativeEvidenceProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repository"
        self.bin = self.root / "bin"
        self.bin.mkdir(parents=True)
        self.mode = self.bin / "mode"
        self.mode.write_text("success")
        self.tool_source = "#!" + sys.executable + "\n" + FAKE_TOOL
        for name in ("ocorec", "clang", "ld.lld"):
            executable = self.bin / name
            executable.write_text(self.tool_source)
            executable.chmod(0o755)
        fixtures = self.root / "tests/fixtures"
        fixtures.mkdir(parents=True)
        for suffix in ("oc", "c"):
            (fixtures / ("ocore_native_equivalence." + suffix)).write_text("test fixture\n")
        self.output = self.root / "evidence"
        self.args = argparse.Namespace(
            ocorec=self.bin / "ocorec", clang=str(self.bin / "clang"),
            qemu_aarch64="unused", qemu_riscv64="unused", targets=["x86_64"],
        )
        self.context = ExitStack()
        self.addCleanup(self.context.close)
        self.context.enter_context(mock.patch.object(gate, "ROOT", self.root))
        self.context.enter_context(mock.patch.dict(os.environ, {
            "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
        }))
        real_elf = gate.elf

        def fixture_elf(path, machine, kind):
            if kind == 1:
                return real_elf(path, machine, kind)
            self.assertTrue(path.read_text().startswith("#!" + sys.executable + "\n"))

        self.context.enter_context(mock.patch.object(gate, "elf", side_effect=fixture_elf))

    def invoke(self):
        command = [str(SCRIPT), "--ocorec", str(self.args.ocorec), "--clang", self.args.clang,
                   "--targets", "x86_64", "--output-dir", str(self.output)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", command), redirect_stdout(stdout), redirect_stderr(stderr):
            status = gate.main()
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_stale_output_rejected(self, mode, artifact):
        status, _, error = self.invoke()
        self.assertEqual(status, 0, error)
        receipt = self.output / "equivalence.json"
        self.assertTrue(receipt.is_file())
        self.assertTrue((self.output / artifact).is_file())
        self.mode.write_text(mode)
        status, _, error = self.invoke()
        self.assertEqual(status, 1, "successful no-output producer was accepted")
        self.assertIn("producer did not create a fresh artifact", error)
        self.assertFalse((self.output / artifact).exists())
        self.assertFalse(receipt.exists(), "failed rerun retained a success receipt")

    def test_success_keeps_existing_output_paths_and_binds_receipt(self):
        status, output, error = self.invoke()
        self.assertEqual(status, 0, error)
        self.assertIn("x86_64: PASS", output)
        expected = {"x86_64.o", "x86_64.s", "reproducible/x86_64.o", "x86_64.elf",
                    "equivalence.json"}
        expected.update(f"x86_64-fault-{case}.elf" for case in range(1, 7))
        expected.update(f"x86_64-never-{case}.elf" for case in (1, 2))
        actual = {str(path.relative_to(self.output)) for path in self.output.rglob("*") if path.is_file()}
        self.assertEqual(actual, expected)
        report = json.loads((self.output / "equivalence.json").read_text())
        self.assertFalse(report["equivalent"], "one target is not three-target equivalence")
        self.assertEqual(report["compiler_sha256"], hashlib.sha256((self.bin / "ocorec").read_bytes()).hexdigest())
        result = report["targets"]["x86_64"]
        self.assertTrue(result["reproducible"])
        self.assertEqual(len(result["faults"]), 6)
        self.assertEqual(result["never_cases"], 2)

    def test_stale_primary_object_cannot_satisfy_no_output_compiler(self):
        self.assert_stale_output_rejected("compiler", "x86_64.o")

    def test_stale_reproducibility_object_cannot_satisfy_no_output_compiler(self):
        self.assert_stale_output_rejected("reproducible", "reproducible/x86_64.o")

    def test_stale_retained_assembly_cannot_satisfy_partial_output_compiler(self):
        self.assert_stale_output_rejected("assembly", "x86_64.s")

    def test_stale_main_executable_cannot_satisfy_no_output_linker(self):
        self.assert_stale_output_rejected("x86_64", "x86_64.elf")

    def test_stale_fault_executable_cannot_satisfy_no_output_linker(self):
        self.assert_stale_output_rejected("x86_64-fault-3", "x86_64-fault-3.elf")

    def test_stale_never_executable_cannot_satisfy_no_output_linker(self):
        self.assert_stale_output_rejected("x86_64-never-2", "x86_64-never-2.elf")

    def test_relative_compiler_executes_and_hashes_the_callers_selected_binary(self):
        caller = Path(self.temporary.name) / "caller"
        caller_bin = caller / "bin"
        caller_bin.mkdir(parents=True)
        selected = caller_bin / "ocorec"
        selected.write_text(self.tool_source + "\n# The caller's distinct compiler.\n")
        selected.chmod(0o755)
        (caller_bin / "mode").write_text("success")
        self.args.ocorec = Path("bin/ocorec")
        with changed_directory(caller):
            status, _, error = self.invoke()
        self.assertEqual(status, 0, error)
        report = json.loads((self.output / "equivalence.json").read_text())
        self.assertEqual(report["compiler"], "fake " + str(selected.resolve()))
        self.assertEqual(report["compiler_sha256"], hashlib.sha256(selected.read_bytes()).hexdigest())


class ProducerArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        root_patch = mock.patch.object(gate, "ROOT", self.directory)
        root_patch.start()
        self.addCleanup(root_patch.stop)

    def test_selected_symlink_preserves_its_command_name_across_cwd_changes(self):
        multicall = self.directory / "multicall"
        multicall.write_text("#!" + sys.executable + "\n"
                             "from pathlib import Path\nimport sys\n"
                             "name = Path(sys.argv[0]).name\n"
                             "print('compiler selected' if name == 'ocorec' else 'multicall usage')\n")
        multicall.chmod(0o755)
        caller = self.directory / "caller"
        alias = caller / "bin/ocorec"
        alias.parent.mkdir(parents=True)
        alias.symlink_to(multicall)
        with changed_directory(caller):
            selected = gate.tool("bin/ocorec", "compiler")
        executed = gate.run([selected, "--version"])
        self.assertEqual(executed.stdout, b"compiler selected\n")
        self.assertEqual(Path(selected), alias.absolute())
        self.assertEqual(hashlib.sha256(Path(selected).read_bytes()).hexdigest(),
                         hashlib.sha256(multicall.read_bytes()).hexdigest())

    def test_stale_symlink_is_unlinked_without_overwriting_its_target(self):
        payload = self.directory / "old-payload"
        payload.write_text("untouched")
        output = self.directory / "output"
        output.symlink_to(payload)
        command = [sys.executable, "-c", "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('fresh')", str(output)]
        gate.produce(command, [output])
        self.assertFalse(output.is_symlink())
        self.assertEqual(output.read_text(), "fresh")
        self.assertEqual(payload.read_text(), "untouched")

    def test_new_empty_symlink_and_directory_outputs_are_rejected(self):
        payload = self.directory / "old-payload"
        payload.write_text("old artifact")
        producers = {
            "empty": "p.touch()",
            "symlink": "p.symlink_to(sys.argv[2])",
            "directory": "p.mkdir()",
        }
        for name, statement in producers.items():
            with self.subTest(kind=name):
                output = self.directory / name
                program = "from pathlib import Path; import sys; p=Path(sys.argv[1]); " + statement
                with self.assertRaisesRegex(RuntimeError, "nonempty regular artifact"):
                    gate.produce([sys.executable, "-c", program, str(output), str(payload)], [output])


if __name__ == "__main__":
    unittest.main()
