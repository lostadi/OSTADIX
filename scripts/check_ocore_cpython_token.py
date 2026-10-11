#!/usr/bin/env python3
"""Compare whole captured CPython Parser/token.c against its original native object.

Exhaustive byte tuples, int32 boundaries and token-name relocations exercise the
actual imported module. The host-configured x86 capture is never retargeted.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FUNCTIONS = {"_PyToken_OneChar", "_PyToken_TwoChars", "_PyToken_ThreeChars"}
EXPORTS = FUNCTIONS | {"_PyParser_TokenNames"}


def info(path: Path) -> dict:
    path = path.resolve()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def checked(artifact: dict) -> Path:
    path = Path(artifact["path"])
    if not path.is_absolute() or info(path) != {k: artifact[k] for k in ["path", "sha256", "bytes"]}:
        raise ValueError("captured source/IR/original object artifact changed: " + str(path))
    return path


def elf(path: Path, kind: int) -> None:
    header = path.read_bytes()[:64]
    if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[16:18], "little") != kind or int.from_bytes(header[18:20], "little") != 62:
        raise ValueError("expected x86-64 ELF64 artifact: " + str(path))


def execute(argv: list[str], directory: Path, label: str, expected: int = 0) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, capture_output=True, timeout=180)
    (directory / (label + ".stdout")).write_bytes(result.stdout)
    (directory / (label + ".stderr")).write_bytes(result.stderr)
    (directory / (label + ".command.json")).write_text(json.dumps({"argv": argv, "exit_code": result.returncode}, indent=2) + "\n")
    if result.returncode != expected:
        raise RuntimeError(f"{label}: exit {result.returncode}, expected {expected}; " + result.stderr.decode(errors="replace")[:1000] + result.stdout.decode(errors="replace")[:1000])
    return result


def prove(args: argparse.Namespace, directory: Path) -> dict:
    capture_info = info(args.capture)
    native_info = info(args.native_ir)
    own_info = info(args.object)
    report = json.loads(args.capture.read_text())
    if report.get("schema") != "ocore-runtime-capture-v1":
        raise ValueError("expected a source capture report")
    candidates = [(event, unit) for event in report["invocations"] for unit in event["units"]
                  if "ir" in unit and unit["source"]["path"].endswith("/Parser/token.c")]
    if len(candidates) != 1:
        raise ValueError("Parser/token.c must resolve exactly one original whole source unit")
    event, unit = candidates[0]
    if event["exit_code"] != 0 or event["capture_errors"]:
        raise ValueError("original token source capture is incomplete")
    source, llvm = checked(unit["source"]), checked(unit["ir"])
    outputs = [item for item in event["outputs"] if item["path"].endswith("/Parser/token.o")]
    if len(outputs) != 1:
        raise ValueError("original compiled token.o must resolve exactly once")
    original = checked(outputs[0])
    elf(original, 1)
    module = json.loads(args.native_ir.read_text())
    if module.get("format") != "ocore-native-module-v1" or module["provenance"]["input_sha256"] != info(llvm)["sha256"]:
        raise ValueError("native module does not bind the exact captured whole LLVM unit")
    if module["target"]["triple"] != unit["ir"]["target_triple"] or module["target"]["data_layout"] != unit["ir"]["data_layout"]:
        raise ValueError("module changed the original frontend target or DataLayout")
    if module["target"]["triple"].split("-", 1)[0] != "x86_64":
        raise ValueError("original host capture cannot qualify another ISA; configure and capture that target separately")
    if {f["name"] for f in module["functions"]} != FUNCTIONS or any(f["entry"] is None for f in module["functions"]):
        raise ValueError("whole token source requires all three original function definitions")
    text = llvm.read_text()
    if len(re.findall(r"^define\b", text, re.MULTILINE)) != len(module["functions"]) or len(re.findall(r"^@[^\n]* = ", text, re.MULTILINE)) != len(module["globals"]):
        raise ValueError("whole-source function/global inventory was not preserved")
    names = next(g for g in module["globals"] if g["name"] == "_PyParser_TokenNames")
    names_type = module["types"][names["ty"]]
    if names_type["kind"] != "array" or len(names["initializer"]["relocations"]) != names_type["len"]:
        raise ValueError("token names require the original complete pointer relocation table")
    count = names_type["len"]
    own = args.object.resolve()
    elf(own, 1)
    compiler_info = info(args.ocorec)
    compiler = directory / "ocorec"
    shutil.copy2(args.ocorec, compiler)
    if info(compiler)["sha256"] != compiler_info["sha256"]:
        raise ValueError("compiler changed while snapshotting")
    verified = directory / "verification.json"
    execute([str(compiler), str(args.native_ir.resolve()), "--input-kind", "native-ir", "--verify-native", "--receipt", str(verified)], directory, "verify")
    receipt = json.loads(verified.read_text())
    if receipt.get("verified") is not True or receipt["module_sha256"] != info(args.native_ir)["sha256"]:
        raise ValueError("independent verification did not bind the actual native module")
    repeated = directory / "repeated.o"
    execute([str(compiler), str(args.native_ir.resolve()), "--input-kind", "native-ir", "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(repeated)], directory, "emit")
    if repeated.read_bytes() != own.read_bytes():
        raise ValueError("supplied O-core object is not byte-identical to own emission from the verified module")
    symbol_output = execute([args.nm, "--defined-only", "--print-size", "--format=posix", str(original)], directory, "oracle-symbols").stdout.decode()
    public = {line.split()[0]: line.split() for line in symbol_output.splitlines() if line.split() and line.split()[1].isupper()}
    if set(public) != EXPORTS or int(public["_PyParser_TokenNames"][3], 16) != count * 8:
        raise ValueError("original native object exports or token-name array extent differ from the whole imported module")
    oracle = directory / "oracle.o"
    renames = [arg for symbol in sorted(EXPORTS) for arg in ["--redefine-sym", symbol + "=oracle_" + symbol]]
    execute([args.objcopy, *renames, str(original), str(oracle)], directory, "rename-oracle")
    harness = ROOT / "tests/fixtures/ocore_cpython_token_harness.c"
    program = directory / "token.elf"
    link = [args.clang, "--target=x86_64-unknown-linux-gnu", "-O2", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie", "-nostdlib", "-static", "-fuse-ld=lld", "-Wl,-e,_start", "-Wl,--build-id=none", "-DTOKEN_NAME_COUNT=" + str(count), str(harness), str(own)]
    execute([*link, str(oracle), "-o", str(program)], directory, "link")
    elf(program, 2)
    output = execute([str(program)], directory, "execute").stdout
    if not re.fullmatch(rb"OCORE-CPYTHON-TOKEN digest=[0-9a-f]{16} byte_cases=16843008 edge_cases=12719\n", output):
        raise ValueError("unexpected exhaustive differential output: " + repr(output))
    # Corrupt only the independent oracle copy, preserving runtime source and IR.
    corrupted = directory / "corrupted-oracle.o"
    execute([args.objcopy, "--redefine-sym", "oracle__PyToken_OneChar=uncorrupted__PyToken_OneChar", str(oracle), str(corrupted)], directory, "corrupt-oracle-symbol")
    wrapper = directory / "corrupt-oracle.c"
    wrapper.write_text("extern int uncorrupted__PyToken_OneChar(int);\nint oracle__PyToken_OneChar(int c) { return uncorrupted__PyToken_OneChar(c) ^ 1; }\n")
    negative = directory / "corrupted-token.elf"
    execute([*link, str(corrupted), str(wrapper), "-o", str(negative)], directory, "link-negative")
    rejected = execute([str(negative)], directory, "negative-oracle", expected=11)
    if not rejected.stdout.startswith(b"TOKEN-MISMATCH kind=0b args=00000000,"):
        raise ValueError("independently corrupted oracle did not identify the first differing byte case")
    for path, initial in [(args.capture, capture_info), (args.native_ir, native_info), (own, own_info),
                          (source, unit["source"]), (llvm, unit["ir"]), (original, outputs[0])]:
        if info(path) != {key: initial[key] for key in ("path", "sha256", "bytes")}:
            raise ValueError("proof input changed during execution: " + str(path))
    return {"schema": "ocore-cpython-token-development-proof-v1", "scope": "whole-upstream-token-source-hosted-x86-compiler-development-gate",
            "capture": capture_info, "source": info(source), "llvm": info(llvm), "original_oracle_object": info(original),
            "native_module": native_info, "independent_verification": info(verified), "own_object": own_info,
            "compiler": compiler_info, "oracle_copy": info(oracle), "harness": info(harness), "executable": info(program),
            "output": output.decode().strip(), "function_definitions": len(module["functions"]), "globals": len(module["globals"]),
            "token_name_count": count, "exhaustive_byte_cases": {"one": 256, "two": 65536, "three": 16777216},
            "int32_boundary_cases": 12719, "independently_corrupted_oracle_rejected": True, "reproducible_own_object": True,
            "matched_original_object": True, "all_three_equivalent": False, "full_runtime_capture_complete": report["capture_complete"],
            "dependency_closure_complete": False, "native_execution_qualified": False, "runtime_complete": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--native-ir", type=Path, required=True)
    parser.add_argument("--object", type=Path, required=True)
    parser.add_argument("--ocorec", type=Path, default=ROOT / "target/debug/ocorec")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--objcopy", default="llvm-objcopy")
    parser.add_argument("--nm", default="llvm-nm")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        directory = args.output.resolve()
        directory.mkdir(parents=True, exist_ok=False)
        result = prove(args, directory)
        (directory / "proof.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, StopIteration, RuntimeError, subprocess.TimeoutExpired) as error:
        print("O-core CPython token proof: FAIL: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
