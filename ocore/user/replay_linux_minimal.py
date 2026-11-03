#!/usr/bin/env python3
"""Observe the exact minimal corpus on native Linux; never imply a wider ABI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import tempfile

from verify_linux_minimal_corpus import (
    load_oracle,
    verify_elf,
    verify_expected,
    verify_sources,
)


def check_observation(stdout: bytes, stderr: bytes, status: int, trace: str,
                      oracle: dict) -> list[dict]:
    expected = oracle["expected"]
    if (stdout, stderr, status) != (
        expected["stdout_utf8"].encode(),
        expected["stderr_utf8"].encode(),
        expected["exit_status"],
    ):
        raise ValueError("native stdout/stderr/exit status differ from the oracle")
    lines = trace.splitlines()
    if len(lines) != 5 or not re.fullmatch(r'execve\(.*\)\s+= 0', lines[0]):
        raise ValueError("native trace must contain one execve and four corpus syscalls")
    patterns = [
        r'write\(1, "o-core linux stdout\\n", 20\)\s+= 20',
        r'write\(2, "o-core linux stderr\\n", 20\)\s+= 20',
        r'syscall_0x7fffffff\(0, 0, 0, 0, 0, 0\)\s+= -1 ENOSYS \(Function not implemented\)',
        r'exit_group\(42\)\s+= \?',
    ]
    for line, pattern in zip(lines[1:], patterns):
        if not re.fullmatch(pattern, line):
            raise ValueError(f"unexpected native syscall observation: {line}")
    # These normalized records are emitted only after matching every observed
    # argument/result; the unknown syscall's -1 ENOSYS is Linux's raw -38.
    return expected["syscalls"]


def replay(elf: Path, oracle_path: Path, output: Path) -> None:
    if output.resolve() in (elf.resolve(), oracle_path.resolve()):
        raise ValueError("observation output must not replace the ELF or oracle")
    # A failed new attempt must not leave a previous PASS looking current.
    output.unlink(missing_ok=True)
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("native replay requires Linux x86_64 (emulation is not accepted)")
    tracer = shutil.which("strace")
    if tracer is None:
        raise ValueError("native syscall replay requires strace")
    oracle = load_oracle(oracle_path)
    verify_sources(oracle_path.resolve().parent, oracle)
    expected_stdout, expected_stderr = verify_expected(oracle)
    # Execute a private copy of the exact bytes verified here. A concurrent
    # build cannot replace the source ELF between verification and execution.
    with tempfile.TemporaryDirectory(prefix="ocore-linux-replay-") as directory:
        root = Path(directory)
        executable = root / "linux-minimal.elf"
        executable.write_bytes(elf.read_bytes())
        verify_elf(executable, oracle, expected_stdout, expected_stderr)
        executable.chmod(0o500)
        trace_path = root / "syscalls.log"
        process = subprocess.Popen(
            [tracer, "-qq", "-s", "256", "-o", str(trace_path), "--", str(executable)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": os.defpath, "LC_ALL": "C"},
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise ValueError("native syscall replay exceeded its ten-second deadline")
        trace = trace_path.read_text()
        calls = check_observation(stdout, stderr, process.returncode, trace, oracle)
    receipt = {
        "schema": "ocore.linux-minimal-native-observation/v1",
        "scope": oracle["scope"],
        "system": platform.system(),
        "architecture": platform.machine(),
        "kernel_release": platform.release(),
        "elf_sha256": oracle["elf"]["sha256"],
        "oracle_sha256": hashlib.sha256(oracle_path.read_bytes()).hexdigest(),
        "stdout_utf8": stdout.decode(),
        "stderr_utf8": stderr.decode(),
        "exit_status": process.returncode,
        "syscalls": calls,
        "strace": trace,
        "strace_sha256": hashlib.sha256(trace.encode()).hexdigest(),
        "result": "PASS",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    print("native x86_64 Linux minimal syscall replay: PASS (exact pinned corpus only)")
    print(f"native-linux-observation: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("oracle", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        replay(args.elf, args.oracle, args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"native Linux replay: FAIL: {error}\n")


if __name__ == "__main__":
    main()
