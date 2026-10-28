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
import os
from pathlib import Path
import platform
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


def tool(value: str, label: str) -> str:
    resolved = shutil.which(value)
    if not resolved:
        raise RuntimeError(f"{label} missing: {value}")
    return resolved


def host_isa() -> str:
    machine = platform.machine().lower()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)


def execution_prefix(isa: str, emulator: str | None = None) -> list[str]:
    system = platform.system()
    # These carriers use Linux ELF and syscalls, even when the ISA matches.
    if system == "Linux" and isa == host_isa():
        return []
    label = f"{isa} user emulator; install qemu-user"
    if system != "Linux":
        label = (f"{isa} Linux ELF runner on {system}; matching ISA alone is insufficient; "
                 "provide a compatible runner or use a Linux host")
    return [tool(emulator or "qemu-" + isa, label)]


def file_identity(path) -> dict:
    invoked = Path(path).absolute()
    resolved = invoked.resolve(strict=True)
    contents = resolved.read_bytes()
    return {"path": str(invoked), "resolved_path": str(resolved),
            "sha256": hashlib.sha256(contents).hexdigest(), "bytes": len(contents)}


class RunEvidence:
    """Check selected file bytes over a run, without claiming dependency closure."""

    def __init__(self, sources=(), tools=None):
        # These are the complete child environments. Never serialize arbitrary
        # inherited values, which can contain unrelated credentials.
        self.environment = {key: os.environ[key] for key in
                            ("PATH", "HOME", "LD_LIBRARY_PATH", "TMPDIR", "RUSTUP_HOME",
                             "CARGO_HOME", "OCORE_CLANG", "O_LANG_ROOT", "O_BACKENDS_DIR")
                            if key in os.environ}
        self.environment["LC_ALL"] = "C"
        configured = {key: re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/\s]*@", r"\1[redacted]@", value)
                      for key, value in self.environment.items()}
        self.environment_record = {
            "configured_values": configured,
            "effective_sha256": hashlib.sha256(json.dumps(self.environment, sort_keys=True,
                                                          separators=(",", ":")).encode()).hexdigest(),
            "url_userinfo_redacted": configured != self.environment,
            "other_inherited_values_forwarded_or_recorded": False,
        }
        self.sources = {}
        self.tools = {}
        self.commands = []
        for module in tuple(sys.modules.values()):
            path = getattr(module, "__file__", None)
            if path and Path(path).suffix == ".py" and Path(path).is_relative_to(ROOT):
                self.watch_source(path)
        for path in sources:
            self.watch_source(path)
        for name, path in (tools or {}).items():
            self.watch_tool(name, path)
        if "OCORE_CLANG" in self.environment:
            override = shutil.which(self.environment["OCORE_CLANG"], path=self.environment.get("PATH"))
            if override is None:
                raise RuntimeError("OCORE_CLANG unavailable: " + self.environment["OCORE_CLANG"])
            self.watch_tool("OCORE_CLANG", override)

    def _watch(self, records, name, path):
        identity = file_identity(path)
        if name in records and records[name] != identity:
            raise RuntimeError("run input changed: " + str(path))
        records[name] = identity

    def watch_source(self, path):
        self._watch(self.sources, str(Path(path).absolute()), path)

    def watch_tool(self, name, path):
        self._watch(self.tools, name, path)

    def verify_unchanged(self):
        after = {"sources": {}, "tools": {}}
        for kind, records in (("sources", self.sources), ("tools", self.tools)):
            for name, identity in records.items():
                try:
                    current = file_identity(identity["path"])
                except OSError as error:
                    raise RuntimeError("run input changed: " + identity["path"]) from error
                if current != identity:
                    raise RuntimeError("run input changed: " + identity["path"])
                after[kind][name] = current
        return after

    def run(self, command, *, cwd=ROOT, timeout=120, preexec_fn=None):
        command = [str(part) for part in command]
        requested = list(command)
        executable = shutil.which(command[0], path=self.environment.get("PATH"))
        if executable is None:
            raise RuntimeError("executed tool unavailable: " + command[0])
        command[0] = executable
        self.watch_tool("executed:" + executable, executable)
        record = {"argv": command, "requested_argv": requested, "cwd": str(cwd),
                  "environment": self.environment_record, "timeout_seconds": timeout,
                  "core_dumps_disabled": preexec_fn is no_core_dumps}
        self.commands.append(record)
        try:
            result = subprocess.run(command, cwd=cwd, env=self.environment, capture_output=True,
                                    timeout=timeout, preexec_fn=preexec_fn)
        except (OSError, subprocess.TimeoutExpired) as error:
            record["execution_error"] = str(error)
            raise
        record.update(exit_code=result.returncode, stdout=result.stdout.decode(errors="replace"),
                      stderr=result.stderr.decode(errors="replace"))
        return result

    def checked_run(self, command, **kwargs):
        result = self.run(command, **kwargs)
        if result.returncode:
            raise RuntimeError(f"command failed ({result.returncode}): {command!r}\n"
                               + result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
        return result

    def finish(self) -> dict:
        after = self.verify_unchanged()
        return {"schema": "ostadix.compiler-conformance-inputs/v1",
                "before": {"sources": self.sources, "tools": self.tools},
                "after": after,
                "inputs_unchanged": True, "tool_shared_library_closure_verified": False,
                "identity_check_scope": "selected file bytes before first use and after the run; files are not sealed",
                "environment": self.environment_record, "commands": self.commands}


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
    linker = tool("ld.lld", "LLVM ELF linker")
    emulators = {target: execution_prefix(target, getattr(args, "qemu_" + target))
                 for target in args.targets}
    corpus = ROOT / "tests/fixtures/ocore_native_equivalence.oc"
    harness = ROOT / "tests/fixtures/ocore_native_equivalence.c"
    evidence = RunEvidence([__file__, corpus, harness],
                           {"ocorec": compiler, "clang": clang, "assembler_clang": assembler,
                            "linker": linker, **{isa: runner[0] for isa, runner in emulators.items() if runner}})
    run = evidence.checked_run
    report = {"schema": "ostadix.ocore-native-equivalence/v1", "targets": {}, "compiler": run([compiler, "--version"]).stdout.decode().strip(), "clang": run([clang, "--version"]).stdout.decode().splitlines()[0]}
    report["assembler_clang"] = run([assembler, "--version"]).stdout.decode().splitlines()[0]
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
        link = [clang, "--target=" + hosted, *flags, "-O2", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-nostdlib", "-static", "--ld-path=" + linker, "-Wl,-e,_start", "-Wl,--build-id=none", str(harness), str(obj)]
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
            trapped = evidence.run([*emulators[target], str(fault)], cwd=directory, timeout=30, preexec_fn=no_core_dumps)
            expected_signals = {signal.SIGILL, signal.SIGTRAP, signal.SIGFPE}
            if trapped.returncode not in {-int(s) for s in expected_signals} or trapped.stdout:
                raise RuntimeError(f"{target} fault case {case} did not synchronously trap: exit={trapped.returncode}, stdout={trapped.stdout!r}, stderr={trapped.stderr!r}")
            faults.append({"case": case, "signal": -trapped.returncode, "artifact": file_identity(fault)})
        never_cases = []
        for case in (1, 2):
            diverging = directory / f"{target}-never-{case}.elf"
            run([*link, f"-DNEVER_CASE={case}", "-o", str(diverging)])
            exited = evidence.run([*emulators[target], str(diverging)], cwd=directory, timeout=30, preexec_fn=no_core_dumps)
            if exited.returncode != 42 or exited.stdout:
                raise RuntimeError(f"{target} never case {case} did not exit immediately: exit={exited.returncode}, stdout={exited.stdout!r}")
            never_cases.append({"case": case, "exit_code": exited.returncode, "artifact": file_identity(diverging)})
        result = {"output": executed.stdout.decode().strip(), "object_sha256": hashlib.sha256(obj.read_bytes()).hexdigest(), "elf_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(), "faults": faults, "never_cases": 2, "reproducible": True,
                  "execution_argv_prefix": emulators[target], "never_artifacts": never_cases,
                  "profile": {"native_target": native, "hosted_target": hosted, "flags": flags},
                  "artifacts": {name: file_identity(path) for name, path in
                                {"object": obj, "reproducible_object": alternate, "assembly": obj.with_suffix(".s"), "executable": exe}.items()}}
        if emulators[target]:
            result["emulator"] = run([emulators[target][0], "--version"]).stdout.decode().splitlines()[0]
        report["targets"][target] = result
        print(f"{target}: PASS — {result['output']}; C ABI/memory/atomics; 6 synchronous fault cases; 2 never cases; reproducible object", flush=True)
    report["equivalent"] = len(args.targets) == len(TARGETS)
    report["provenance"] = evidence.finish()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocorec", type=Path, default=ROOT / "target/debug/ocorec")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--qemu-x86-64", "--qemu-x86_64", dest="qemu_x86_64", default="qemu-x86_64")
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
