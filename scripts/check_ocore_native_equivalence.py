#!/usr/bin/env python3
"""Compile one real O-core corpus and check all three native ISAs by execution.

The freestanding C harness supplies an independent arithmetic reference and C
ABI crossings. Linux startup/syscalls only carry test results; generated O-core
objects keep their freestanding targets. Missing emulators fail the gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "x86_64": ("x86_64-unknown-none", "x86_64-unknown-linux-gnu", 62, []),
    "aarch64": ("aarch64-unknown-none", "aarch64-unknown-linux-gnu", 183, []),
    "riscv64": ("riscv64-unknown-none", "riscv64-unknown-linux-gnu", 243, ["-march=rv64gc", "-mabi=lp64"]),
}


def run(command: list[str], *, timeout: float = 120) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout.decode(errors='replace')}{result.stderr.decode(errors='replace')}")
    return result


def tool(value: str, label: str) -> str:
    resolved = shutil.which(value)
    if not resolved:
        raise RuntimeError(f"{label} missing: {value}")
    return resolved


def elf(path: Path, machine: int, kind: int) -> None:
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise RuntimeError(f"not a little-endian ELF64 artifact: {path}")
    if int.from_bytes(data[16:18], "little") != kind or int.from_bytes(data[18:20], "little") != machine:
        raise RuntimeError(f"incorrect ELF type or ISA: {path}")
    if machine == 243 and int.from_bytes(data[48:52], "little") & 6:
        raise RuntimeError(f"RISC-V artifact must use the scalar LP64 ABI: {path}")


def no_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def check(args: argparse.Namespace, directory: Path) -> dict:
    compiler = tool(str(args.ocorec), "ocorec; build with cargo build --locked --bin ocorec")
    clang = tool(args.clang, "clang")
    assembler = tool("clang", "O-core assembler")
    tool("ld.lld", "LLVM ELF linker")
    emulators = {"x86_64": []}
    for target in args.targets:
        if target != "x86_64":
            value = getattr(args, "qemu_" + target)
            emulators[target] = [tool(value, f"{target} user emulator; install qemu-user")]
    report = {"schema": "ostadix.ocore-native-equivalence/v1", "targets": {}, "compiler": run([compiler, "--version"]).stdout.decode().strip(), "clang": run([clang, "--version"]).stdout.decode().splitlines()[0]}
    report["assembler_clang"] = run([assembler, "--version"]).stdout.decode().splitlines()[0]
    corpus = ROOT / "tests/fixtures/ocore_native_equivalence.oc"
    harness = ROOT / "tests/fixtures/ocore_native_equivalence.c"
    report["source_sha256"] = hashlib.sha256(corpus.read_bytes()).hexdigest()
    report["reference_sha256"] = hashlib.sha256(harness.read_bytes()).hexdigest()
    report["compiler_sha256"] = hashlib.sha256(Path(compiler).read_bytes()).hexdigest()
    reference = None
    for target in args.targets:
        native, hosted, machine, flags = TARGETS[target]
        obj = directory / (target + ".o")
        run([compiler, str(corpus), "--target", native, "--emit", "obj", "--keep-asm", "--function-sections", "-o", str(obj)])
        elf(obj, machine, 1)
        # Rebuilding in another directory must preserve every object byte.
        alternate = directory / "reproducible" / (target + ".o")
        run([compiler, str(corpus), "--target", native, "--emit", "obj", "--function-sections", "-o", str(alternate)])
        if obj.read_bytes() != alternate.read_bytes():
            raise RuntimeError(f"{target} object is not byte reproducible")
        link = [clang, "--target=" + hosted, *flags, "-O2", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-nostdlib", "-static", "-fuse-ld=lld", "-Wl,-e,_start", "-Wl,--build-id=none", str(harness), str(obj)]
        exe = directory / (target + ".elf")
        run([*link, "-o", str(exe)])
        elf(exe, machine, 2)
        executed = run([*emulators[target], str(exe)])
        if not re.fullmatch(rb"OCORE-NATIVE-EQUIVALENCE digest=[0-9a-f]{16} cases=12288\n", executed.stdout):
            raise RuntimeError(f"{target} returned invalid conformance output: {executed.stdout!r}")
        if reference is None:
            reference = executed.stdout
        elif reference != executed.stdout:
            raise RuntimeError(f"{target} result bytes differ from the other ISA(s)")
        faults = []
        for case in range(1, 7):
            fault = directory / f"{target}-fault-{case}.elf"
            run([*link, f"-DFAULT_CASE={case}", "-o", str(fault)])
            trapped = subprocess.run([*emulators[target], str(fault)], cwd=directory, capture_output=True, timeout=30, preexec_fn=no_core_dumps)
            expected_signals = {signal.SIGILL, signal.SIGTRAP, signal.SIGFPE}
            if trapped.returncode not in {-int(s) for s in expected_signals} or trapped.stdout:
                raise RuntimeError(f"{target} fault case {case} did not synchronously trap: exit={trapped.returncode}, stdout={trapped.stdout!r}, stderr={trapped.stderr!r}")
            faults.append({"case": case, "signal": -trapped.returncode})
        for case in (1, 2):
            diverging = directory / f"{target}-never-{case}.elf"
            run([*link, f"-DNEVER_CASE={case}", "-o", str(diverging)])
            exited = subprocess.run([*emulators[target], str(diverging)], cwd=directory, capture_output=True, timeout=30, preexec_fn=no_core_dumps)
            if exited.returncode != 42 or exited.stdout:
                raise RuntimeError(f"{target} never case {case} did not exit immediately: exit={exited.returncode}, stdout={exited.stdout!r}")
        result = {"output": executed.stdout.decode().strip(), "object_sha256": hashlib.sha256(obj.read_bytes()).hexdigest(), "elf_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(), "faults": faults, "never_cases": 2, "reproducible": True}
        if emulators[target]:
            result["emulator"] = run([emulators[target][0], "--version"]).stdout.decode().splitlines()[0]
        report["targets"][target] = result
        print(f"{target}: PASS — {result['output']}; C ABI/memory/atomics; 6 synchronous fault cases; 2 never cases; reproducible object", flush=True)
    report["equivalent"] = len(args.targets) == len(TARGETS)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocorec", type=Path, default=ROOT / "target/debug/ocorec")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--qemu-aarch64", default="qemu-aarch64")
    parser.add_argument("--qemu-riscv64", default="qemu-riscv64")
    parser.add_argument("--targets", nargs="+", choices=list(TARGETS), default=list(TARGETS))
    parser.add_argument("--output-dir", type=Path, help="Keep exact objects, assembly, executables and JSON evidence here")
    args = parser.parse_args()
    if len(set(args.targets)) != len(args.targets):
        parser.error("targets must be unique")
    try:
        if args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            # A failed rerun must never retain an earlier successful receipt.
            (args.output_dir / "equivalence.json").unlink(missing_ok=True)
            report = check(args, args.output_dir.resolve())
            (args.output_dir / "equivalence.json").write_text(json.dumps(report, indent=2) + "\n")
        else:
            with tempfile.TemporaryDirectory(prefix="ocore-equivalence-") as temporary:
                report = check(args, Path(temporary))
        if report["equivalent"]:
            print("All three ISA executions are byte-equivalent to the shared reference corpus.")
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"O-core native equivalence: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
