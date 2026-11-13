#!/usr/bin/env python3
"""Exercise foreign C frontend -> verified O-core IR -> own assembly on three ISAs.

Linux user-mode startup carries this compiler test. It does not qualify native
OSTADIX platform services or a complete foreign runtime/compiler closure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from check_ocore_native_equivalence import (ROOT, TARGETS, TARGET_CATALOG, RunEvidence,
                                           canonical_target_coverage, elf,
                                           execution_prefix, tool)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(args: argparse.Namespace, directory: Path) -> dict:
    catalog = canonical_target_coverage()
    compiler = tool(str(args.ocorec), "current ocorec")
    clang = tool(args.clang, "C frontend and independent reference")
    assembler = tool(os.environ.get("OCORE_CLANG", "clang"), "O-core assembler")
    linker = tool(args.linker, "LLVM ELF linker")
    emulators = {isa: execution_prefix(isa, getattr(args, "qemu_" + isa)) for isa in TARGETS}
    source = ROOT / "tests/fixtures/ocore_import_scalar.c"
    harness = ROOT / "tests/fixtures/ocore_import_harness.c"
    evidence = RunEvidence([__file__, source, harness, TARGET_CATALOG],
                           {"ocorec": compiler, "clang": clang, "assembler_clang": assembler,
                            "linker": linker, **{isa: runner[0] for isa, runner in emulators.items() if runner}})
    llvm_options = []
    if args.llvm_library is not None:
        evidence.watch_tool("llvm_parser_library", args.llvm_library)
        llvm_options = ["--llvm-library", str(args.llvm_library), "--llvm-sha256", args.llvm_sha256]
    run = evidence.checked_run
    report = {
        "format": "ocore-foreign-import-equivalence-v1",
        "scope": "scalar_compiler_conformance_linux_test_carrier",
        "runtime_complete": False,
        "backend_catalog": catalog,
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
        run([compiler, str(llvm), "--input-kind", "llvm-ir", "--target", native, "--emit", "mir", *llvm_options, "-o", str(ir)])
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
        run([clang, "--target=" + hosted, *flags, *common, "-O2", "-nostdlib", "-static", "--ld-path=" + linker, "-Wl,-e,_start", "-Wl,--build-id=none", str(harness), str(reference), str(obj), "-o", str(executable)])
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
            "execution_argv_prefix": emulators[isa],
        }
        print(f"{isa}: PASS {output.decode().strip()}", flush=True)
    if len(set(outputs)) != 1:
        raise RuntimeError("cross-ISA result bytes diverge")
    # A supported definition beside an unsupported one must not yield a module.
    rejected = directory / "unsupported.ll"
    rejected.write_text('target triple = "x86_64-unknown-linux-gnu"\ntarget datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"\ndefine i64 @valid(i64 %x) { ret i64 %x }\ndefine coldcc i64 @unsupported(i64 %x) { ret i64 %x }\n')
    evidence.watch_source(rejected)
    # The independent LLVM frontend accepts this complete, well-typed module.
    # O-core must reject its unsupported convention without dropping that body.
    accepted_reference = directory / "unsupported.reference.o"
    run([clang, "--target=x86_64-unknown-linux-gnu", "-x", "ir", "-c", str(rejected), "-o", str(accepted_reference)])
    elf(accepted_reference, TARGETS["x86_64"][2], 1)
    rejected_out = directory / "must-not-exist.json"
    rejected_out.unlink(missing_ok=True)
    result = evidence.run([compiler, str(rejected), "--input-kind", "llvm-ir", "--emit", "mir", *llvm_options, "-o", str(rejected_out)])
    if result.returncode == 0 or rejected_out.exists() or b"unsupported calling convention 9" not in result.stderr:
        raise RuntimeError("unsupported function was silently omitted or emitted")
    # Frontend ABI/layout is an import requirement, not a backend selection hint.
    wrong_out = directory / "wrong-target.o"
    wrong_out.unlink(missing_ok=True)
    wrong = evidence.run([compiler, str(directory / "x86_64.native.json"), "--input-kind", "native-ir", "--target", "aarch64-unknown-none", "-o", str(wrong_out)])
    if wrong.returncode == 0 or wrong_out.exists():
        raise RuntimeError("x86 frontend IR was silently retargeted to AArch64")
    report["executed_native_targets"] = [TARGETS[isa][0] for isa in report["targets"]]
    report["all_three_equivalent"] = set(report["executed_native_targets"]) == set(catalog["canonical_targets"])
    report["unsupported_whole_unit_rejected"] = True
    report["wrong_frontend_target_rejected"] = True
    report["unsupported_convention"] = 9
    report["provenance"] = evidence.finish()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocorec", type=Path, default=ROOT / "target/debug/ocorec")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--linker", default="ld.lld")
    parser.add_argument("--llvm-library", type=Path)
    parser.add_argument("--llvm-sha256")
    parser.add_argument("--qemu-x86-64", "--qemu-x86_64", dest="qemu_x86_64", default="qemu-x86_64")
    parser.add_argument("--qemu-aarch64", default="qemu-aarch64")
    parser.add_argument("--qemu-riscv64", default="qemu-riscv64")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if (args.llvm_library is None) != (args.llvm_sha256 is None):
        parser.error("--llvm-library and --llvm-sha256 must be supplied together")
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
