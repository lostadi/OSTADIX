"""Opt-in qualification of a freshly compiled Linux-container WASI artifact.

Set OSTADIX_RUN_WASM_CONTAINER_E2E=1 and supply digest-pinned
OLANG_WASM_RUNTIME_IMAGE and OLANG_WASM_BUILDER_IMAGE references. Docker, c2w,
Wasmtime, and Wasmer must already be installed. OLANGC_WASM_TEST_BIN optionally selects
the compiler; the default is target/debug/olangc. This test performs a real
image build and conversion, not a materialization or prebuilt-artifact check.
Set OLANG_WASM_E2E_DIR to a new directory to retain the artifact, command logs,
and receipt.json after either success or failure; an existing path is refused.
The same artifact also runs with three aliases of a fresh empty directory as
preopens, covering startup behavior without granting access to host user files.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Iterator


ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def evidence_workspace(requested: str | Path | None = None) -> Iterator[Path]:
    if requested is not None:
        directory = Path(requested)
        directory.mkdir(mode=0o700, exist_ok=False)
        # This branch deliberately has no cleanup, including on exceptions.
        yield directory.resolve()
    else:
        with tempfile.TemporaryDirectory(prefix="olang-wasm-container-e2e-") as temporary:
            yield Path(temporary)


def write_receipt(directory: Path, receipt: dict) -> None:
    # The enclosing directory is fresh and private. Replacing only this test's
    # receipt keeps the preceding complete JSON intact while an update is written.
    pending = directory / ".receipt.json.next"
    pending.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    pending.replace(directory / "receipt.json")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_recorded(
    command: list[str],
    *,
    directory: Path,
    label: str,
    receipt: dict,
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    stdout_path = directory / "logs" / f"{label}.stdout.log"
    stderr_path = directory / "logs" / f"{label}.stderr.log"
    result = {
        "command": command,
        "cwd": str(cwd),
        "timeout_seconds": timeout,
        "returncode": None,
        "status": "running",
        "assertions_passed": False,
        "stdout_log": str(stdout_path.relative_to(directory)),
        "stderr_log": str(stderr_path.relative_to(directory)),
    }
    receipt["runs"][label] = result
    write_receipt(directory, receipt)
    try:
        # Stream directly to owned files so partial output survives a timeout
        # or test interruption; do not retain only an in-memory capture.
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=os.name == "posix",
            )
            try:
                returncode = process.wait(timeout=timeout)
            except BaseException:
                # Only this invocation's new session is targeted. Killing the
                # group also stops compiler/converter children on interruption
                # or timeout, rather than leaving a build running unattended.
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    result["cleanup_scope"] = "owned_process_group"
                else:
                    process.kill()
                    result["cleanup_scope"] = "direct_process"
                result["returncode"] = process.wait(timeout=10)
                raise
        result["returncode"] = returncode
        result["status"] = "completed"
        return subprocess.CompletedProcess(
            command,
            returncode,
            stdout_path.read_text(encoding="utf-8", errors="replace"),
            stderr_path.read_text(encoding="utf-8", errors="replace"),
        )
    except BaseException as error:
        result["status"] = "timed_out" if isinstance(error, subprocess.TimeoutExpired) else "error"
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        write_receipt(directory, receipt)


class EvidenceWorkspaceTests(unittest.TestCase):
    def test_retained_workspace_survives_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "evidence"
            with evidence_workspace(directory) as owned:
                (owned / "retained.txt").write_text("evidence", encoding="utf-8")
            self.assertEqual((directory / "retained.txt").read_text(), "evidence")

    def test_retained_workspace_is_private_and_survives_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "evidence"
            with self.assertRaisesRegex(RuntimeError, "intentional fixture failure"):
                with evidence_workspace(directory) as owned:
                    (owned / "retained.txt").write_text("evidence", encoding="utf-8")
                    if os.name == "posix":
                        self.assertEqual(owned.stat().st_mode & 0o777, 0o700)
                    raise RuntimeError("intentional fixture failure")
            self.assertEqual((directory / "retained.txt").read_text(), "evidence")

    def test_existing_paths_and_symlinks_are_never_reused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "existing"
            directory.mkdir()
            (directory / "keep.txt").write_text("keep", encoding="utf-8")
            file = root / "existing-file"
            file.write_text("keep file", encoding="utf-8")
            targets = [directory, file]
            if os.name == "posix":
                link = root / "dangling-link"
                link.symlink_to(root / "absent")
                targets.append(link)
            for target in targets:
                with self.subTest(target=target.name):
                    with self.assertRaises(FileExistsError):
                        with evidence_workspace(target):
                            self.fail("an existing output path was accepted")
            self.assertEqual((directory / "keep.txt").read_text(), "keep")
            self.assertEqual(file.read_text(), "keep file")

    def test_default_workspace_is_removed_on_failure(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "temporary fixture failure"):
            with evidence_workspace() as directory:
                self.assertTrue(directory.is_dir())
                raise RuntimeError("temporary fixture failure")
        self.assertFalse(directory.exists())

    def test_receipt_updates_preserve_valid_json_and_hash_exact_bytes(self) -> None:
        with evidence_workspace() as directory:
            artifact = directory / "hash-fixture"
            artifact.write_bytes(b"abc")
            self.assertEqual(
                sha256_file(artifact),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )
            write_receipt(directory, {"status": "running"})
            write_receipt(directory, {"status": "failed", "returncode": 7})
            self.assertEqual(
                json.loads((directory / "receipt.json").read_text()),
                {"status": "failed", "returncode": 7},
            )
            self.assertFalse((directory / ".receipt.json.next").exists())

    def test_recorded_command_preserves_outputs_and_nonzero_exit(self) -> None:
        with evidence_workspace() as directory:
            (directory / "logs").mkdir()
            receipt = {"runs": {}}
            completed = run_recorded(
                [
                    sys.executable,
                    "-c",
                    "import sys; print('recorded stdout'); "
                    "print('recorded stderr', file=sys.stderr); sys.exit(7)",
                ],
                directory=directory,
                label="fixture",
                receipt=receipt,
                cwd=directory,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 7)
            self.assertEqual(completed.stdout, "recorded stdout\n")
            self.assertEqual(completed.stderr, "recorded stderr\n")
            stored = json.loads((directory / "receipt.json").read_text())["runs"]["fixture"]
            self.assertEqual(stored["returncode"], 7)
            self.assertEqual(stored["status"], "completed")
            self.assertFalse(stored["assertions_passed"])
            self.assertEqual((directory / stored["stdout_log"]).read_text(), completed.stdout)
            self.assertEqual((directory / stored["stderr_log"]).read_text(), completed.stderr)

    def test_failed_launch_retains_error_receipt_and_logs(self) -> None:
        with evidence_workspace() as directory:
            (directory / "logs").mkdir()
            receipt = {"runs": {}}
            with self.assertRaises(FileNotFoundError):
                run_recorded(
                    [str(directory / "nonexistent-executable")],
                    directory=directory,
                    label="fixture",
                    receipt=receipt,
                    cwd=directory,
                    timeout=10,
                )
            stored = json.loads((directory / "receipt.json").read_text())["runs"]["fixture"]
            self.assertIsNone(stored["returncode"])
            self.assertEqual(stored["status"], "error")
            self.assertFalse(stored["assertions_passed"])
            self.assertIn("FileNotFoundError", stored["error"])
            self.assertTrue((directory / stored["stdout_log"]).is_file())
            self.assertTrue((directory / stored["stderr_log"]).is_file())

    @unittest.skipUnless(os.name == "posix", "process-group cleanup is POSIX-specific")
    def test_timeout_stops_owned_child_process_and_retains_evidence(self) -> None:
        with evidence_workspace() as directory:
            (directory / "logs").mkdir()
            receipt = {"runs": {}}
            with self.assertRaises(subprocess.TimeoutExpired):
                run_recorded(
                    [
                        sys.executable,
                        "-c",
                        "import subprocess, sys, time\n"
                        "child = subprocess.Popen([sys.executable, '-c', "
                        "'import time; time.sleep(60)'])\n"
                        "print(child.pid, flush=True)\n"
                        "time.sleep(60)\n",
                    ],
                    directory=directory,
                    label="timeout",
                    receipt=receipt,
                    cwd=directory,
                    timeout=1,
                )
            stored = json.loads((directory / "receipt.json").read_text())["runs"]["timeout"]
            self.assertEqual(stored["status"], "timed_out")
            self.assertEqual(stored["returncode"], -signal.SIGKILL)
            self.assertEqual(stored["cleanup_scope"], "owned_process_group")
            self.assertFalse(stored["assertions_passed"])
            child_pid = int((directory / stored["stdout_log"]).read_text().strip())
            stopped = False
            try:
                for _ in range(100):
                    try:
                        os.kill(child_pid, 0)
                    except ProcessLookupError:
                        stopped = True
                        break
                    # A killed orphan can briefly remain as a zombie until
                    # the system reaps it. It is no longer executing either.
                    probe = subprocess.run(
                        ["ps", "-p", str(child_pid), "-o", "stat="],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=2,
                    )
                    state = probe.stdout.strip()
                    self.assertIn(probe.returncode, (0, 1), probe.stderr)
                    if (probe.returncode == 1 and not state) or state.startswith("Z"):
                        stopped = True
                        break
                    time.sleep(0.02)
                self.assertTrue(stopped, "timed-out command left its child running")
            finally:
                if not stopped:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


@unittest.skipUnless(
    os.environ.get("OSTADIX_RUN_WASM_CONTAINER_E2E") == "1",
    "set OSTADIX_RUN_WASM_CONTAINER_E2E=1 for the real Docker/c2w/WASI build",
)
class OlangWasmContainerTests(unittest.TestCase):
    def test_fresh_python_program_executes_inside_linux_wasi_guest(self) -> None:
        with evidence_workspace(os.environ.get("OLANG_WASM_E2E_DIR")) as directory:
            (directory / "logs").mkdir(mode=0o700)
            receipt = {
                "schema": "ostadix.wasm-container-e2e/v1",
                "status": "running",
                "source_sha256": None,
                "artifact_sha256": None,
                "artifact": "artifacts/fixture.wasm",
                "image_pins": {},
                "compiler_path": None,
                "source_deleted_before_execution": False,
                "runs": {},
            }
            write_receipt(directory, receipt)
            try:
                self._qualify(directory, receipt)
            except BaseException as error:
                receipt["status"] = "failed"
                message = f"{type(error).__name__}: {error}"
                # Assertions can contain complete build logs. Keep the JSON
                # small; the separate log files retain the complete output.
                receipt["error"] = message[:2048]
                receipt["error_truncated"] = len(message) > 2048
                raise
            else:
                # unittest subtests record failures without propagating them.
                # Only successful assertions for every invocation qualify this
                # receipt; returning from _qualify alone is not a pass.
                expected = {
                    "build",
                    "wasmtime.success",
                    "wasmtime.failure",
                    "wasmer.success",
                    "wasmer.failure",
                    "wasmtime.empty-preopens.success",
                }
                passed = set(receipt["runs"]) == expected and all(
                    result["assertions_passed"] for result in receipt["runs"].values()
                )
                receipt["status"] = "passed" if passed else "failed"
            finally:
                write_receipt(directory, receipt)

    def _qualify(self, directory: Path, receipt: dict) -> None:
        images = {}
        for name in ("OLANG_WASM_RUNTIME_IMAGE", "OLANG_WASM_BUILDER_IMAGE"):
            value = os.environ.get(name, "")
            self.assertIsNotNone(
                re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", value),
                f"{name} must name a real image pinned as repository@sha256:"
                "<64 lowercase hexadecimal digits>; placeholders are not usable",
            )
            images[name] = value
            receipt["image_pins"][name] = value

        tools = {}
        for name in ("docker", "c2w", "wasmtime", "wasmer"):
            executable = shutil.which(name)
            self.assertIsNotNone(
                executable, f"{name} must be installed before enabling this test"
            )
            tools[name] = str(Path(executable).resolve())

        compiler = Path(
            os.environ.get("OLANGC_WASM_TEST_BIN", ROOT / "target" / "debug" / "olangc")
        ).resolve()
        receipt["compiler_path"] = str(compiler)
        self.assertTrue(compiler.is_file(), f"missing olangc binary: {compiler}")
        self.assertTrue(os.access(compiler, os.X_OK), f"olangc is not executable: {compiler}")

        source_directory = directory / "source"
        output_directory = directory / "artifacts"
        runtime_directory = directory / "unrelated-runtime-cwd"
        source_directory.mkdir()
        output_directory.mkdir()
        runtime_directory.mkdir()
        source = source_directory / "fixture.O"
        artifact = output_directory / "fixture.wasm"
        source.write_text(
            "python^(\n"
            "import os, platform\n"
            "if os.environ.get('OSTADIX_WASM_EXPECT_FAILURE') == '1':\n"
            "    raise RuntimeError('OSTADIX WASM INTENTIONAL FAILURE')\n"
            "__oval_result__ = 'OSTADIX WASM ' + platform.system() + ' ' + str(6 * 7)\n"
            ")_python\n",
            encoding="utf-8",
        )
        receipt["source_sha256"] = sha256_file(source)
        write_receipt(directory, receipt)
        self.assertFalse(artifact.exists(), "the test must build a fresh artifact")

        built = run_recorded(
            [
                str(compiler),
                str(source),
                "--target",
                "wasm",
                "--output",
                str(artifact),
                "--wasm-runtime-image",
                images["OLANG_WASM_RUNTIME_IMAGE"],
                "--wasm-builder-image",
                images["OLANG_WASM_BUILDER_IMAGE"],
            ],
            directory=directory,
            label="build",
            receipt=receipt,
            cwd=source_directory,
            # The low-resource converter compiles Linux, Rust, and Bochs with
            # limited parallelism. A cold build can exceed an hour; this does
            # not extend any of the five guest execution deadlines below.
            timeout=7200,
        )
        self.assertEqual(
            built.returncode,
            0,
            f"real container build failed\nstdout:\n{built.stdout}\nstderr:\n{built.stderr}",
        )
        self.assertTrue(artifact.is_file(), "compiler did not produce its output artifact")
        self.assertFalse(artifact.is_symlink(), "expected a newly written Wasm file")
        with artifact.open("rb") as stream:
            self.assertEqual(stream.read(8), b"\x00asm\x01\x00\x00\x00")
        receipt["artifact_sha256"] = sha256_file(artifact)
        receipt["runs"]["build"]["assertions_passed"] = True
        write_receipt(directory, receipt)

        # Execution cannot obtain the original source through a host path.
        source.unlink()
        source_directory.rmdir()
        receipt["source_deleted_before_execution"] = True
        write_receipt(directory, receipt)
        # Exercise the same source-bound artifact in two engines. The
        # negative invocation takes a real Python exception through O,
        # runc, guest init, and the emulator's WASI proc_exit channel.
        for engine in ("wasmtime", "wasmer"):
            for fail in (False, True):
                with self.subTest(engine=engine, intentional_failure=fail):
                    command = [tools[engine], "run"]
                    if fail:
                        command.append("--env=OSTADIX_WASM_EXPECT_FAILURE=1")
                    command.append(str(artifact))
                    if engine == "wasmer":
                        command.append("--")
                    command.append("--no-stdin")
                    label = f"{engine}.{'failure' if fail else 'success'}"
                    executed = run_recorded(
                        command,
                        directory=directory,
                        label=label,
                        receipt=receipt,
                        cwd=runtime_directory,
                        env={},
                        timeout=600,
                    )
                    try:
                        details = (
                            f"{engine} execution returned {executed.returncode}\n"
                            f"stdout:\n{executed.stdout}\nstderr:\n{executed.stderr}"
                        )
                        self.assertEqual(executed.returncode, 1 if fail else 0, details)
                        if fail:
                            self.assertIn(
                                "OSTADIX WASM INTENTIONAL FAILURE",
                                executed.stdout + executed.stderr,
                                details,
                            )
                            self.assertNotIn("OSTADIX WASM Linux 42", executed.stdout)
                        else:
                            self.assertIn("OSTADIX WASM Linux 42", executed.stdout, details)
                        receipt["runs"][label]["assertions_passed"] = True
                    finally:
                        write_receipt(directory, receipt)

        # Reproduce empty-path resolution with root-like guest aliases. The
        # host side is one new, empty, private directory, never a user root.
        # These aliases must not make the emulator open its default empty MSR
        # filename as a directory and spin forever on a failed read.
        empty_preopens = directory / "empty-preopens"
        empty_preopens.mkdir(mode=0o700)
        self.assertEqual(list(empty_preopens.iterdir()), [])
        with self.subTest(engine="wasmtime", empty_preopens=True):
            label = "wasmtime.empty-preopens.success"
            executed = run_recorded(
                [
                    tools["wasmtime"],
                    "run",
                    *(f"--dir={empty_preopens}::{alias}" for alias in ("/", ".", "//")),
                    str(artifact),
                    "--no-stdin",
                ],
                directory=directory,
                label=label,
                receipt=receipt,
                cwd=runtime_directory,
                env={},
                timeout=600,
            )
            try:
                details = (
                    f"wasmtime empty-preopens execution returned {executed.returncode}\n"
                    f"stdout:\n{executed.stdout}\nstderr:\n{executed.stderr}"
                )
                self.assertEqual(executed.returncode, 0, details)
                self.assertIn("OSTADIX WASM Linux 42", executed.stdout, details)
                receipt["runs"][label]["assertions_passed"] = True
            finally:
                write_receipt(directory, receipt)


if __name__ == "__main__":
    unittest.main()
