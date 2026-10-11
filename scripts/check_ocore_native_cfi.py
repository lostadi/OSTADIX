#!/usr/bin/env python3
"""Check actual O-core object unwind rows at every frame instruction boundary.

This is scalar object-metadata conformance, without runtime execution, exception
handling, personality routines, or a complete foreign runtime qualification.
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
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {
    "x86_64": ("x86_64-unknown-none", "x86_64-unknown-none", []),
    "aarch64": ("aarch64-unknown-none", "aarch64-unknown-none", []),
    "riscv64": ("riscv64-unknown-none", "riscv64-unknown-none-elf", ["-march=rv64gc", "-mabi=lp64"]),
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool(name: str) -> Path:
    found = shutil.which(name)
    if not found:
        raise RuntimeError(f"required tool is absent: {name}")
    # Preserve multicall-tool argv[0] instead of resolving a rustup/lld symlink.
    return Path(found).absolute()


def run(argv: list[str | Path], log: Path) -> str:
    result = subprocess.run([str(a) for a in argv], cwd=ROOT, capture_output=True, timeout=120)
    log.with_suffix(log.suffix + ".stdout").write_bytes(result.stdout)
    log.with_suffix(log.suffix + ".stderr").write_bytes(result.stderr)
    log.with_suffix(log.suffix + ".argv.json").write_text(json.dumps([str(a) for a in argv]) + "\n")
    if result.returncode:
        raise RuntimeError(f"tool exited {result.returncode}; inspect {log}.stderr")
    return result.stdout.decode("utf-8")


def value(identifier: int) -> dict:
    return {"kind": "value", "id": identifier}


def constant(bits: int) -> dict:
    return {"kind": "int", "ty": 2, "bits": str(bits)}


def signature(params: list[int]) -> dict:
    return {"params": params, "result": 2, "abi": "c", "variadic": False}


def fixture(isa: str) -> dict:
    sig12 = signature([2] * 12)
    instructions = []
    for index in range(1, 12):
        instructions.append({"result": {"id": 300 + index, "ty": 2}, "operation": {
            "op": "binary", "kind": "add", "flags": [],
            "lhs": value(100 if index == 1 else 299 + index), "rhs": value(100 + index),
        }})
    functions = [
        {"name": "multi_return", "linkage": "external", "signature": signature([2]),
         "params": [{"id": 1, "ty": 2}], "entry": 10,
         "blocks": [
             {"id": 10, "instructions": [{"result": {"id": 8, "ty": 1}, "operation": {
                 "op": "i_cmp", "predicate": "eq", "lhs": value(1), "rhs": constant(0),
             }}], "terminator": {"op": "branch", "condition": value(8), "on_true": 20, "on_false": 30}},
             {"id": 20, "instructions": [], "terminator": {"op": "return", "value": constant(7)}},
             {"id": 30, "instructions": [], "terminator": {"op": "return", "value": constant(9)}},
         ]},
        {"name": "sum12", "linkage": "external", "signature": sig12,
         "params": [{"id": 100 + i, "ty": 2} for i in range(12)], "entry": 10,
         "blocks": [{"id": 10, "instructions": instructions, "terminator": {"op": "return", "value": value(311)}}]},
        {"name": "probe_caller", "linkage": "external", "signature": signature([2]),
         "params": [{"id": 1, "ty": 2}], "entry": 10,
         "blocks": [{"id": 10, "instructions": [
             {"result": {"id": 700, "ty": 3}, "operation": {"op": "alloca", "size": 12288, "alignment": 16}},
             {"result": {"id": 701, "ty": 2}, "operation": {"op": "call",
              "callee": {"kind": "symbol", "ty": 3, "name": "sum12"}, "signature": sig12,
              "args": [value(1), *[constant(i) for i in range(2, 13)]]}},
         ], "terminator": {"op": "return", "value": value(701)}}]},
    ]
    return {
        "format": "ocore-native-module-v1", "name": "unwind-row-conformance",
        "target": {"triple": PROFILES[isa][0], "data_layout": "e-p:64:64-i64:64-i128:128-n32:64-S128",
                   "pointer_bits": 64, "little_endian": True, "abi": "lp64" if isa == "riscv64" else None},
        "semantics": "llvm_defined_behavior_v1",
        "types": [{"kind": "void"}, {"kind": "int", "bits": 1}, {"kind": "int", "bits": 64},
                  {"kind": "pointer", "address_space": 0}],
        "globals": [], "functions": functions,
        "provenance": {"input_sha256": digest(Path(__file__)), "frontend": "independent-native-fixture",
                       "frontend_version": "1", "importer": "none", "importer_version": "1",
                       "source_function_count": 3, "source_global_count": 0, "refinements": []},
    }


def parse_frames(text: str) -> list[dict]:
    frames = []
    current = None
    for line in text.splitlines():
        match = re.search(r"\bFDE\s+cie=[0-9a-fA-F]+\s+pc=([0-9a-fA-F]+)\.\.\.([0-9a-fA-F]+)", line)
        if match:
            current = {"start": int(match[1], 16), "end": int(match[2], 16), "rows": []}
            frames.append(current)
            continue
        match = re.match(r"\s*0x([0-9a-fA-F]+): CFA=([A-Z0-9]+)([+-]\d+)?(?::\s*(.*))?$", line)
        if match and current is not None:
            rules = {}
            for rule in (match[4] or "").split(","):
                if rule.strip():
                    register, expression = rule.strip().split("=", 1)
                    rules[register] = expression
            current["rows"].append((int(match[1], 16), (match[2], int(match[3] or 0)), rules))
    if not frames or any(not f["rows"] for f in frames):
        raise RuntimeError("object lacks decodable FDE rows for all native functions")
    return frames


def parse_instructions(text: str) -> list[tuple[int, str]]:
    instructions = []
    for line in text.splitlines():
        match = re.match(r"\s*([0-9a-fA-F]+):\s+(.*\S)", line)
        if match:
            instruction = match[2].split("//", 1)[0].strip().lower()
            instruction = re.sub(r"\s+", " ", instruction)
            instruction = re.sub(r"\s*,\s*", ",", instruction)
            instructions.append((int(match[1], 16), instruction))
    return instructions


def expected(isa: str, state: str) -> tuple[tuple[str, int], dict[str, str]]:
    sp, fp, ra = {"x86_64": ("RSP", "RBP", "RIP"), "aarch64": ("WSP", "W29", "W30"),
                  "riscv64": ("X2", "X8", "X1")}[isa]
    if state == "entry":
        return (sp, 8 if isa == "x86_64" else 0), {fp: "same", ra: "[CFA-8]" if isa == "x86_64" else "same"}
    if state == "rv_adjusted":
        return (sp, 16), {fp: "same", ra: "same"}
    if state == "rv_ra_saved":
        return (sp, 16), {fp: "same", ra: "[CFA-8]"}
    if state in {"saved", "unframed"}:
        return (sp, 16), {fp: "[CFA-16]", ra: "[CFA-8]"}
    if state == "body":
        return (fp, 16), {fp: "[CFA-16]", ra: "[CFA-8]"}
    if state == "rv_ra_restored":
        return (sp, 16), {fp: "[CFA-16]", ra: "same"}
    if state == "rv_fp_restored":
        return (sp, 16), {fp: "same", ra: "same"}
    if state == "returned":
        return expected(isa, "entry")
    raise RuntimeError(f"unknown frame state {state}")


def transition(isa: str, state: str, instruction: str) -> str:
    if state == "entry":
        prefix = {"x86_64": "push rbp", "aarch64": "stp x29,x30,[sp,#-0x10]!", "riscv64": "addi sp,sp,-0x10"}[isa]
        if instruction != prefix:
            raise RuntimeError(f"unexpected {isa} entry frame instruction: {instruction}")
        return "rv_adjusted" if isa == "riscv64" else "saved"
    if state == "rv_adjusted":
        if instruction not in {"sd ra,0x8(sp)", "sd ra,8(sp)"}:
            raise RuntimeError("RV prologue did not save RA before changing FP")
        return "rv_ra_saved"
    if state == "rv_ra_saved":
        if instruction not in {"sd s0,0x0(sp)", "sd s0,0(sp)", "sd s0,(sp)"}:
            raise RuntimeError("RV prologue did not preserve caller FP")
        return "saved"
    if state == "saved":
        prefix = {"x86_64": "mov rbp,rsp", "aarch64": "mov x29,sp", "riscv64": "mv s0,sp"}[isa]
        if instruction != prefix:
            raise RuntimeError(f"unexpected {isa} fixed-FP installation: {instruction}")
        return "body"
    if state == "body":
        reset = {"x86_64": "mov rsp,rbp", "aarch64": "mov sp,x29", "riscv64": "mv sp,s0"}[isa]
        return "unframed" if instruction == reset else "body"
    if state == "unframed":
        if isa == "x86_64" and instruction == "pop rbp":
            return "returned"
        if isa == "aarch64" and instruction == "ldp x29,x30,[sp],#0x10":
            return "returned"
        if isa == "riscv64" and instruction in {"ld ra,0x8(sp)", "ld ra,8(sp)"}:
            return "rv_ra_restored"
        raise RuntimeError(f"unexpected {isa} return restoration: {instruction}")
    if state == "rv_ra_restored":
        if instruction not in {"ld s0,0x0(sp)", "ld s0,0(sp)", "ld s0,(sp)"}:
            raise RuntimeError("RV epilogue did not restore caller FP")
        return "rv_fp_restored"
    if state == "rv_fp_restored":
        if instruction not in {"addi sp,sp,0x10", "addi sp,sp,16"}:
            raise RuntimeError("RV epilogue did not restore caller SP")
        return "returned"
    if state == "returned":
        if instruction != "ret":
            raise RuntimeError(f"return instruction missing after {isa} frame restoration")
        # Text after this return belongs to another reachable block, whose
        # incoming path retained the function's body frame, not this epilogue.
        return "body"
    raise RuntimeError(f"unknown frame transition {state}")


def validate(isa: str, symbols: dict[str, tuple[int, int]], frame_text: str, instructions_text: str) -> dict:
    frames = parse_frames(frame_text)
    code = parse_instructions(instructions_text)
    ranges = {(f["start"], f["end"]): f for f in frames}
    if len(ranges) != len(frames) or set(ranges) != {(start, start + size) for start, size in symbols.values()}:
        raise RuntimeError("FDE ranges do not exactly cover the complete emitted function inventory")
    checked = 0
    returns = {}
    for name, (start, size) in symbols.items():
        frame = ranges[(start, start + size)]
        rows = frame["rows"]
        state = "entry"
        count = 0
        # Local labels are retained by some ELF assemblers; function ownership
        # comes from complete STT_FUNC extents, not disassembler label headers.
        instructions = [(pc, op) for pc, op in code if start <= pc < start + size]
        if not instructions or instructions[0][0] != start:
            raise RuntimeError(f"no full disassembly for {name}")
        for pc, instruction in instructions:
            applicable = [row for row in rows if row[0] <= pc]
            if not applicable:
                raise RuntimeError(f"missing initial unwind row for {name}")
            _, cfa, rules = applicable[-1]
            want_cfa, want_rules = expected(isa, state)
            if cfa != want_cfa or any(rules.get(reg) != rule for reg, rule in want_rules.items()):
                raise RuntimeError(f"{isa}:{name}+{pc-start:#x} ({instruction}): wrong unwind row; "
                                   f"got CFA={cfa}, {rules}; expected CFA={want_cfa}, {want_rules}")
            if state == "returned":
                count += 1
            state = transition(isa, state, instruction)
            checked += 1
        if state != "body" or not count:
            raise RuntimeError(f"incomplete return/frame transition inventory for {name}")
        returns[name] = count
    if returns.get("multi_return", 0) != 2:
        raise RuntimeError("fixture lost its separate return blocks")
    probe_start, probe_size = symbols["probe_caller"]
    probe = [(pc, op) for pc, op in code if probe_start <= pc < probe_start + probe_size]
    page_touch = {"x86_64": "mov byte ptr [rsp],0x0", "aarch64": "strb wzr,[sp]", "riscv64": "sb zero,0x0(sp)"}[isa]
    if not any(op == page_touch or (isa == "riscv64" and op == "sb zero,(sp)") for _, op in probe):
        raise RuntimeError("large-frame fixture did not contain actual stack-page probes")
    return {"function_count": len(symbols), "fde_count": len(frames), "instruction_rows_checked": checked,
            "returns": returns, "stack_probe_rows_checked": True}


def object_symbols(text: str) -> dict[str, tuple[int, int]]:
    entries = json.loads(text)
    symbols = {}
    for entry in entries[0]["Symbols"]:
        symbol = entry["Symbol"]
        if symbol["Type"]["Value"] == 2 and symbol["Section"]["Value"] != 0:
            name = symbol["Name"]["Name"]
            if name in symbols:
                raise RuntimeError("duplicate function symbol")
            symbols[name] = (symbol["Value"], symbol["Size"])
    if set(symbols) != {"multi_return", "sum12", "probe_caller"}:
        raise RuntimeError("object differs from complete source fixture inventory")
    return symbols


def check(args: argparse.Namespace, directory: Path) -> dict:
    tools = {name: tool(str(getattr(args, name))) for name in ("ocorec", "clang", "dwarfdump", "objdump", "readobj")}
    hashes = {name: digest(path) for name, path in tools.items()}
    report = {"format": "ocore-native-cfi-v1", "scope": "scalar_object_unwind_metadata_conformance",
              "native_execution_qualified": False, "exception_handling_qualified": False, "runtime_complete": False,
              "source_sha256": digest(Path(__file__)), "tools": {name: {"path": str(path), "sha256": hashes[name]}
                                                                      for name, path in tools.items()}, "targets": {}}
    for isa, (native, assembler_target, flags) in PROFILES.items():
        sub = directory / isa
        sub.mkdir()
        module, assembly, obj, receipt = (sub / name for name in ("fixture.native.json", "fixture.s", "fixture.o", "verification.json"))
        module.write_text(json.dumps(fixture(isa), indent=2) + "\n")
        run([tools["ocorec"], module, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt], sub / "verify")
        verified = json.loads(receipt.read_bytes())
        if verified.get("verified") is not True or verified.get("module_sha256") != digest(module):
            raise RuntimeError("verification receipt does not bind complete fixture")
        command = [tools["ocorec"], module, "--input-kind", "native-ir", "--target", native]
        run([*command, "--emit", "asm", "-o", assembly], sub / "emit-assembly")
        run([*command, "--emit", "obj", "-o", obj], sub / "emit-object")
        def inspect(path: Path, prefix: str) -> tuple[dict, str, str]:
            symbols = object_symbols(run([tools["readobj"], "--symbols", "--elf-output-style=JSON", path], sub / (prefix + "-symbols")))
            frames = run([tools["dwarfdump"], "--eh-frame", path], sub / (prefix + "-frames"))
            disassembly = run([tools["objdump"], "-d", "--no-show-raw-insn", "--x86-asm-syntax=intel", path], sub / (prefix + "-code"))
            return symbols, frames, disassembly
        result = validate(isa, *inspect(obj, "positive"))
        source = assembly.read_text()
        ra = {"x86_64": "rip", "aarch64": "x30", "riscv64": "ra"}[isa]
        corruptions = {
            "missing_cfi": "\n".join(line for line in source.splitlines() if ".cfi_" not in line) + "\n",
            "wrong_ra_offset": source.replace(f".cfi_offset {ra}, -8", f".cfi_offset {ra}, -24", 1),
            "missing_return_state_restore": source.replace("  .cfi_restore_state\n", ""),
        }
        negative = {}
        for name, changed in corruptions.items():
            if changed == source:
                raise RuntimeError(f"negative CFI control made no change: {name}")
            corrupt_source, corrupt_obj = sub / (name + ".s"), sub / (name + ".o")
            corrupt_source.write_text(changed)
            run([tools["clang"], "--target=" + assembler_target, *flags, "-c", corrupt_source, "-o", corrupt_obj], sub / (name + "-assemble"))
            try:
                validate(isa, *inspect(corrupt_obj, name))
            except RuntimeError as error:
                negative[name] = {"rejected": True, "reason": str(error), "object_sha256": digest(corrupt_obj)}
            else:
                raise RuntimeError(f"accepted corrupted unwind object: {isa}:{name}")
        report["targets"][isa] = {**result, "module_sha256": digest(module), "object_sha256": digest(obj),
                                   "assembly_sha256": digest(assembly), "verification_sha256": digest(receipt),
                                   "negative_controls": negative}
        print(f"{isa}: PASS {result['fde_count']} FDEs, {result['instruction_rows_checked']} instruction rows, 3 corrupted objects rejected", flush=True)
    if hashes != {name: digest(path) for name, path in tools.items()} or report["source_sha256"] != digest(Path(__file__)):
        raise RuntimeError("compiler, inspection tools, or fixture source changed during CFI qualification")
    report["all_three_object_cfi_verified"] = True
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocorec", type=Path, default=ROOT / "target/debug/ocorec")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--dwarfdump", default="llvm-dwarfdump-21")
    parser.add_argument("--objdump", default="llvm-objdump-21")
    parser.add_argument("--readobj", default="llvm-readobj-21")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    try:
        if args.output_dir:
            directory = args.output_dir.absolute()
            directory.mkdir(parents=True, exist_ok=False)
            report = check(args, directory)
            (directory / "receipt.json").write_text(json.dumps(report, indent=2) + "\n")
        else:
            with tempfile.TemporaryDirectory(prefix="ocore-native-cfi-") as temporary:
                check(args, Path(temporary))
        return 0
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(f"O-core native CFI: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
