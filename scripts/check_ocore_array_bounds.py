#!/usr/bin/env python3
"""Execute ordinary array bounds and evaluation order on every native target."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal

from check_ocore_native_equivalence import (
    ROOT, TARGETS, TARGET_CATALOG, RunEvidence, canonical_target_coverage,
    elf, execution_prefix, file_identity, no_core_dumps, produce, tool,
)


# Expected values and event order are stated independently of the compiler.
# B=base, I=index, R=right operand; P is emitted by the primitive C carrier
# only after a checked return value. Trap cases must never reach that carrier.
CASES = [
    (0, "first-last", 44, "", None),
    (1, "equal-length-read", 0, "", "trap"),
    *[(n, "negative-" + ty, 0, "", "trap")
      for n, ty in enumerate(["i8", "i16", "i32", "i64", "isize"], 2)],
    (7, "huge-unsigned", 0, "", "trap"),
    (8, "empty-array", 0, "", "trap"),
    (9, "zero-size-valid", 0, "", None),
    (10, "zero-size-invalid", 0, "", "trap"),
    (11, "nested-struct-valid", 7, "", None),
    (12, "nested-inner-invalid", 0, "", "trap"),
    (13, "nested-outer-invalid", 0, "", "trap"),
    (14, "adjacent-field-read", 0, "", "trap"),
    (15, "assignment-order", 9, "BIR", None),
    (16, "invalid-assignment-before-rhs", 0, "BI", "trap"),
    (17, "compound-order", 31, "BIR", None),
    (18, "invalid-compound-before-rhs", 0, "BI", "trap"),
    (19, "read-order", 33, "BI", None),
    (20, "invalid-read-order", 0, "BI", "trap"),
    (21, "address-order", 33, "BI", None),
    (22, "invalid-address-order", 0, "BI", "trap"),
    (23, "diverging-base", 0, "B", 42),
    (24, "diverging-index", 0, "BI", 43),
    (25, "raw-pointer-index-stays-unchecked", 77, "", None),
    (26, "address-addition-overflow", 0, "", "trap"),
    (27, "negative-zero-size-full-width-length", 0, "", "trap"),
    (28, "unsigned-zero-size-full-width-length", 4096, "", None),
    (29, "unsigned-full-width-address", (1 << 64) - 2, "", None),
    (30, "array-literal-base-once", 9, "RI", None),
    (31, "array-repeat-base-once", 9, "RI", None),
    (32, "empty-zero-size-array", 0, "", "trap"),
    *[(n, "valid-" + ty, 33, "", None)
      for n, ty in enumerate(["i8", "i16", "i32", "i64", "isize",
                              "u8", "u16", "u32", "u64", "usize"], 33)],
    (43, "local-struct-array", 5, "", None),
    (44, "temporary-struct-array", 5, "", None),
    (45, "zero-size-copy-invalid", 0, "", "trap"),
    (46, "zero-size-copy-valid", 123, "", None),
    (47, "invalid-aggregate-assignment-before-rhs", 0, "I", "trap"),
    (48, "aggregate-assignment-order", 9, "IR", None),
    (49, "zero-size-write-invalid", 0, "", "trap"),
    (50, "zero-size-write-valid", 123, "", None),
    (51, "constant-negative-zero-size-full-width", 0, "", "trap"),
    (52, "constant-narrow-signed-valid", 33, "", None),
    (53, "empty-array-index-effect-before-trap", 0, "I", "trap"),
    (54, "constant-zero-offset-forged-base", (1 << 64) - 1, "", None),
    (55, "constant-full-width-address", (1 << 64) - 2, "", None),
    (56, "constant-zero-size-full-width-valid", 4096, "", None),
    (57, "packed-signed-fused-load", (1 << 64) - 2, "I", None),
    (58, "packed-signed-store", (1 << 64) - 9, "I", None),
    (59, "volatile-packed-still-traps-on-alignment", 0, "I", "trap"),
    (60, "volatile-aligned-width", 33, "I", None),
    (61, "fused-boolean-normalization", 1, "I", None),
    (62, "base-pointer-local-changed-by-index", 22, "BI", None),
    (63, "helper-u32-max-length-rejects-u64-index", 0, "", "trap"),
    (64, "helper-full-width-length", 4096, "", None),
    (65, "helper-full-width-element-size", (1 << 32) + 4096, "", None),
    (66, "helper-dynamic-address-carry", 0, "", "trap"),
    (67, "unexpected-selector-fails", 0, "", 97),
]

REJECTIONS = {
    "local-overflow": "fn f()->u64 {let a:[u64;2305843009213693952]=[0;2305843009213693952];return 0;}",
    "static-overflow": "static A:[u64;18446744073709551615]=[0;18446744073709551615];",
    "pointer-array-overflow": "fn f(p:*const [u64;18446744073709551615])->u64{return 0;}",
    "nested-array-overflow": "fn f(p:*const [[u64;65536];35184372088832])->u64{return 0;}",
    "struct-rounding-overflow": "struct S{a:[u8;18446744073709551615],b:u64}",
    "enum-layout-overflow": "enum E{value([u8;18446744073709551615])}",
    "raw-pointer-needs-unsafe": "fn f(p:*const u64)->u64{return p[0];}",
}

REQUIRED_CASES = set("""
first-last equal-length-read huge-unsigned empty-array zero-size-valid
zero-size-invalid nested-struct-valid nested-inner-invalid nested-outer-invalid
adjacent-field-read assignment-order invalid-assignment-before-rhs compound-order
invalid-compound-before-rhs read-order invalid-read-order address-order
invalid-address-order diverging-base diverging-index raw-pointer-index-stays-unchecked
address-addition-overflow negative-zero-size-full-width-length
unsigned-zero-size-full-width-length unsigned-full-width-address array-literal-base-once
array-repeat-base-once empty-zero-size-array local-struct-array temporary-struct-array
zero-size-copy-invalid zero-size-copy-valid invalid-aggregate-assignment-before-rhs
aggregate-assignment-order zero-size-write-invalid zero-size-write-valid
constant-negative-zero-size-full-width constant-narrow-signed-valid
empty-array-index-effect-before-trap constant-zero-offset-forged-base
constant-full-width-address constant-zero-size-full-width-valid
packed-signed-fused-load packed-signed-store volatile-packed-still-traps-on-alignment
volatile-aligned-width fused-boolean-normalization base-pointer-local-changed-by-index
helper-u32-max-length-rejects-u64-index helper-full-width-length
helper-full-width-element-size helper-dynamic-address-carry
unexpected-selector-fails
""".split()) | {"negative-" + ty for ty in ["i8", "i16", "i32", "i64", "isize"]} | {
    "valid-" + ty for ty in ["i8", "i16", "i32", "i64", "isize", "u8", "u16", "u32", "u64", "usize"]}
REQUIRED_REJECTIONS = {"local-overflow", "static-overflow", "pointer-array-overflow",
                       "nested-array-overflow", "struct-rounding-overflow", "enum-layout-overflow",
                       "raw-pointer-needs-unsafe"}


def validate_cases(cases=None):
    cases = CASES if cases is None else cases
    if not cases or [case[0] for case in cases] != list(range(len(cases))):
        raise RuntimeError("bounds corpus must be nonempty with unique contiguous case IDs")
    if len({case[1] for case in cases}) != len(cases):
        raise RuntimeError("duplicate bounds case names")
    if REQUIRED_CASES - {case[1] for case in cases}:
        raise RuntimeError("bounds corpus is missing required matrix cases")
    if REQUIRED_REJECTIONS - set(REJECTIONS):
        raise RuntimeError("bounds corpus is missing required compiler rejection cases")


def check_observation(isa, case, result):
    _, name, _, events, outcome = case
    expected = events.encode() + (b"P\n" if outcome is None else b"")
    if result.stdout != expected:
        raise RuntimeError(f"{isa} {name}: event order differs: {result.stdout!r} != {expected!r}")
    status = (-signal.SIGTRAP if isa == "aarch64" else -signal.SIGILL) if outcome == "trap" else (outcome or 0)
    if result.returncode != status:
        raise RuntimeError(f"{isa} {name}: expected status {status}, observed {result.returncode}")


def check(args, output):
    validate_cases()
    coverage = canonical_target_coverage()
    compiler = tool(str(args.ocorec), "ocorec")
    clang = tool(args.clang, "clang")
    assembler = tool("clang", "O-core assembler")
    linker = tool("ld.lld", "LLVM ELF linker")
    runners = {isa: execution_prefix(isa, getattr(args, "qemu_" + isa)) for isa in TARGETS}
    source = ROOT / "tests/fixtures/ocore_array_bounds.oc"
    carrier = ROOT / "tests/fixtures/ocore_array_bounds.c"
    evidence = RunEvidence([__file__, source, carrier, TARGET_CATALOG,
                            *sorted((ROOT / "crates/ostadix-api/src/ocore").glob("*.rs"))],
                           {"ocorec": compiler, "clang": clang,
                            "assembler_clang": assembler, "linker": linker})
    report = {"schema": "ostadix.ocore-array-bounds/v1", "complete": False,
              "backend_catalog": coverage, "targets": {},
              "scope": "Emitted Linux ELF execution: matching host or user-mode runner; no kernel, hardware or SMP qualification"}
    try:
        for isa, (native, hosted, machine, flags) in TARGETS.items():
            obj = output / (isa + ".o")
            produce([compiler, source, "--target", native, "--emit", "obj", "--keep-asm", "-o", obj],
                    [obj, obj.with_suffix(".s")], runner=evidence.checked_run)
            elf(obj, machine, 1)
            repeat = output / "reproducible" / (isa + ".o")
            produce([compiler, source, "--target", native, "--emit", "obj", "-o", repeat],
                    [repeat], runner=evidence.checked_run)
            if obj.read_bytes() != repeat.read_bytes():
                raise RuntimeError(isa + " bounds object is not reproducible")
            target = {"cases": [], "rejections": [], "object": file_identity(obj),
                      "assembly": file_identity(obj.with_suffix(".s")),
                      "reproducible_object": file_identity(repeat), "runner": runners[isa]}
            report["targets"][isa] = target
            for case in CASES:
                number, name, expected, events, outcome = case
                exe = output / f"{isa}-{number:02d}-{name}.elf"
                produce([clang, "--target=" + hosted, *flags, "-O2", "-ffreestanding", "-fno-builtin",
                         "-fno-stack-protector", "-fno-pic", "-nostdlib", "-static", "--ld-path=" + linker,
                         "-Wl,-e,_start", "-Wl,--build-id=none", f"-DBOUNDS_CASE={number}",
                         f"-DBOUNDS_EXPECTED={expected}ULL", carrier, obj, "-o", exe],
                        [exe], runner=evidence.checked_run)
                elf(exe, machine, 2)
                observed = evidence.run([*runners[isa], exe], preexec_fn=no_core_dumps)
                check_observation(isa, case, observed)
                target["cases"].append({"id": number, "name": name, "expected_value": expected,
                                        "events": events, "outcome": outcome, "exit_code": observed.returncode,
                                        "stdout": observed.stdout.decode(), "executable": file_identity(exe)})
            for name, body in REJECTIONS.items():
                bad = output / "rejections" / (name + ".oc")
                bad.parent.mkdir(exist_ok=True)
                bad.write_text("module rejected;\n" + body + "\n")
                evidence.watch_source(bad)
                bad_obj = output / "rejections" / f"{isa}-{name}.o"
                result = evidence.run([compiler, bad, "--target", native, "--emit", "obj", "-o", bad_obj])
                diagnostic = (result.stdout + result.stderr).decode(errors="replace")
                expected = "unsafe" if name == "raw-pointer-needs-unsafe" else "layout overflows"
                if result.returncode == 0 or bad_obj.exists() or expected not in diagnostic:
                    raise RuntimeError(f"{isa} {name}: required compiler rejection absent: {diagnostic}")
                target["rejections"].append({"name": name, "exit_code": result.returncode,
                                             "source": file_identity(bad), "diagnostic": diagnostic})
            print(f"{isa}: PASS {len(CASES)} executed bounds/order cases and {len(REJECTIONS)} compiler rejections", flush=True)
        report["complete"] = set(report["targets"]) == set(TARGETS)
        report["provenance"] = evidence.finish()
        return report
    finally:
        if "provenance" not in report:
            report["provenance"] = evidence.finish()
        (output / "bounds.json").write_text(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocorec", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--clang", default="clang")
    for isa in TARGETS:
        parser.add_argument("--qemu-" + isa.replace("_", "-"), dest="qemu_" + isa, default="qemu-" + isa)
    args = parser.parse_args()
    if args.output_dir.is_symlink():
        parser.error("--output-dir must be a fresh directory")
    output = args.output_dir.resolve()
    if output.exists():
        parser.error("--output-dir must be a fresh directory")
    output.mkdir(parents=True)
    try:
        check(args, output)
    except (RuntimeError, OSError, ValueError) as error:
        print("FAIL:", error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
