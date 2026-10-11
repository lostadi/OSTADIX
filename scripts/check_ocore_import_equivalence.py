#!/usr/bin/env python3
"""Exercise foreign C frontend -> verified O-core IR -> own assembly on three ISAs.

Linux user-mode startup carries this compiler test. It does not qualify native
OSTADIX platform services or a complete foreign runtime/compiler closure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from check_ocore_native_equivalence import ROOT, TARGETS, elf, run, tool


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(args: argparse.Namespace, directory: Path) -> dict:
    compiler = tool(str(args.ocorec), "current ocorec")
    clang = tool(args.clang, "C frontend and independent reference")
    emulators = {"x86_64": []}
    for isa in ("aarch64", "riscv64"):
        emulators[isa] = [tool(getattr(args, "qemu_" + isa), isa + " user emulator")]
    source = ROOT / "tests/fixtures/ocore_import_scalar.c"
    harness = ROOT / "tests/fixtures/ocore_import_harness.c"
    report = {
        "format": "ocore-foreign-import-equivalence-v1",
        "scope": "scalar_compiler_conformance_linux_test_carrier",
        "runtime_complete": False,
        "source_sha256": digest(source),
        "reference_sha256": digest(harness),
        "ocorec_sha256": digest(Path(compiler)),
        "frontend": run([clang, "--version"]).stdout.decode().splitlines()[0],
        "targets": {},
    }
    common = ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie"]
    outputs = []
    for isa, (native, hosted, machine, flags) in TARGETS.items():
        llvm = directory / f"{isa}.ll"
        ir = directory / f"{isa}.native.json"
        receipt = directory / f"{isa}.verified.json"
        obj = directory / f"{isa}.o"
        alternate = directory / f"{isa}.repeated.o"
        reference = directory / f"{isa}.reference.o"
        executable = directory / f"{isa}.elf"
        run([clang, "--target=" + hosted, *flags, *common, "-O1", "-fno-vectorize", "-fno-slp-vectorize", "-S", "-emit-llvm", str(source), "-o", str(llvm)])
        run([compiler, str(llvm), "--input-kind", "llvm-ir", "--target", native, "--emit", "mir", "-o", str(ir)])
        run([compiler, str(ir), "--verify-native", "--receipt", str(receipt)])
        verified = json.loads(receipt.read_bytes())
        if verified["module_sha256"] != digest(ir) or not verified["verified"]:
            raise RuntimeError("verification receipt does not bind imported bytes")
        build = [compiler, str(ir), "--input-kind", "native-ir", "--target", native, "--emit", "obj"]
        run([*build, "-o", str(obj)])
        run([*build, "-o", str(alternate)])
        elf(obj, machine, 1)
        if obj.read_bytes() != alternate.read_bytes():
            raise RuntimeError(f"{isa}: nondeterministic imported object")
        run([clang, "--target=" + hosted, *flags, *common, "-O2", "-DPREFIX=reference_", "-c", str(source), "-o", str(reference)])
        run([clang, "--target=" + hosted, *flags, *common, "-O2", "-nostdlib", "-static", "-fuse-ld=lld", "-Wl,-e,_start", "-Wl,--build-id=none", str(harness), str(reference), str(obj), "-o", str(executable)])
        elf(executable, machine, 2)
        output = run([*emulators[isa], str(executable)]).stdout
        if not re.fullmatch(rb"OCORE-IMPORT digest=[0-9a-f]{16} cases=24576\n", output):
            raise RuntimeError(f"{isa}: unexpected output {output!r}")
        outputs.append(output)
        report["targets"][isa] = {
            "output": output.decode().strip(),
            "llvm_sha256": digest(llvm),
            "module_sha256": digest(ir),
            "object_sha256": digest(obj),
            "executable_sha256": digest(executable),
            "reproducible": True,
        }
        print(f"{isa}: PASS {output.decode().strip()}", flush=True)
    if len(set(outputs)) != 1:
        raise RuntimeError("cross-ISA result bytes diverge")
    # A supported definition beside an unsupported one must not yield a module.
    rejected = directory / "unsupported.ll"
    rejected.write_text('target triple = "x86_64-unknown-linux-gnu"\ntarget datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"\ndefine i64 @valid(i64 %x) { ret i64 %x }\ndefine double @unsupported(double %x) { %r = fadd double %x, 1.0\n ret double %r }\n')
    rejected_out = directory / "must-not-exist.json"
    rejected_out.unlink(missing_ok=True)
    result = subprocess.run([compiler, str(rejected), "--input-kind", "llvm-ir", "--emit", "mir", "-o", str(rejected_out)], cwd=ROOT, capture_output=True, timeout=120)
    if result.returncode == 0 or rejected_out.exists():
        raise RuntimeError("unsupported function was silently omitted or emitted")
    # Frontend ABI/layout is an import requirement, not a backend selection hint.
    wrong = subprocess.run([compiler, str(directory / "x86_64.native.json"), "--input-kind", "native-ir", "--target", "aarch64-unknown-none", "-o", str(directory / "wrong-target.o")], cwd=ROOT, capture_output=True, timeout=120)
    if wrong.returncode == 0:
        raise RuntimeError("x86 frontend IR was silently retargeted to AArch64")
    report["all_three_equivalent"] = True
    report["unsupported_whole_unit_rejected"] = True
    report["wrong_frontend_target_rejected"] = True
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocorec", type=Path, default=ROOT / "target/debug/ocorec")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--qemu-aarch64", default="qemu-aarch64")
    parser.add_argument("--qemu-riscv64", default="qemu-riscv64")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    try:
        if args.output_dir:
            directory = args.output_dir.resolve()
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "equivalence.json").unlink(missing_ok=True)
            report = check(args, directory)
            (directory / "equivalence.json").write_text(json.dumps(report, indent=2) + "\n")
        else:
            with tempfile.TemporaryDirectory(prefix="ocore-import-gate-") as temporary:
                check(args, Path(temporary))
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
        print(f"O-core foreign import: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
