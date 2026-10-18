#!/usr/bin/env python3
"""Diagnose every whole LLVM unit in one recorded runtime build step.

This is a partial-capture capability audit, never a runtime completeness receipt.
It retains all captured units as provenance and performs no IR/source filtering
inside a selected unit. Successful imports receive independent verification and
O-core object generation; every failure retains its exact diagnostic and logs.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

TARGETS = {"x86_64-unknown-none": ("x86_64", 62),
           "aarch64-unknown-none": ("aarch64", 183),
           "riscv64-unknown-none": ("riscv64", 243)}


def file_info(path: Path) -> dict:
    path = path.resolve()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def diagnostic(stderr: str) -> dict:
    # The importer emits a structured first failure after the CLI prefix.
    for match in re.finditer(r"\{", stderr):
        try:
            value, _ = json.JSONDecoder().raw_decode(stderr[match.start():])
            if isinstance(value, dict) and {"stage", "message"} <= value.keys():
                return value
        except ValueError:
            pass
    return {"message": next((line for line in stderr.splitlines() if line.strip()), "compiler failed without a diagnostic")}


def selected_units(report: dict, step_name: str) -> tuple[list[dict], dict]:
    if report.get("schema") != "ocore-runtime-capture-v1":
        raise ValueError("input is not an ocore-runtime-capture-v1 report")
    steps = [(index, step) for index, step in enumerate(report.get("build_steps", []))
             if step.get("name") == step_name]
    if len(steps) != 1:
        raise ValueError("selected build step must resolve exactly once")
    index, step = steps[0]
    if step.get("exit_code") != 0 or "finished_ns" not in step:
        raise ValueError("selected build step did not finish successfully")
    all_units, selection = {}, []
    for event in report.get("invocations", []):
        is_selected = event.get("build_step") == {"index": index, "name": step_name}
        if is_selected and not (step["started_ns"] <= event["started_ns"] <= event["finished_ns"] <= step["finished_ns"]):
            raise ValueError("compiler invocation falls outside its recorded build step")
        for unit in event.get("units", []):
            if "ir" not in unit:
                continue
            if unit["id"] in all_units:
                raise ValueError("duplicate captured LLVM unit ID")
            all_units[unit["id"]] = unit
            if is_selected:
                selection.append(unit)
    listed = report.get("units", [])
    if len(listed) != len(all_units) or {unit["id"]: unit for unit in listed} != all_units:
        raise ValueError("top-level LLVM inventory differs from the invocation journal")
    if not selection:
        raise ValueError("selected recorded build step contains no LLVM units")
    return sorted(selection, key=lambda unit: unit["id"]), {"index": index, **step}


def inspect_elf(path: Path, machine: int) -> dict:
    with path.open("rb") as stream:
        header = stream.read(64)
    if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01":
        raise ValueError("O-core output is not a little-endian ELF64 object")
    kind, actual = struct.unpack_from("<HH", header, 16)
    if kind != 1 or actual != machine:
        raise ValueError("O-core output ELF type or ISA differs from the selected target")
    return {**file_info(path), "elf_type": kind, "machine": actual}



def is_llvm_bitcode(path: Path) -> bool:
    with path.open("rb") as stream:
        return stream.read(4) in {b"BC\xc0\xde", b"\xde\xc0\x17\x0b"}


def snapshot_llvm_decoder(selected: Path | None, directory: Path) -> dict:
    command = str(selected) if selected is not None else shutil.which("llvm-dis")
    if not command:
        raise ValueError("raw LLVM bitcode requires an explicit or PATH llvm-dis22.1.6 decoder")
    original = Path(command).resolve()
    if not original.is_file() or not os.access(original, os.X_OK):
        raise ValueError("LLVM bitcode decoder is not an executable file")
    identity = file_info(original)
    snapshot = directory / "llvm-dis"
    shutil.copy2(original, snapshot)
    if file_info(snapshot)["sha256"] != identity["sha256"] or file_info(original) != identity:
        raise ValueError("LLVM bitcode decoder changed while snapshotting")
    stdout, stderr = directory / "llvm-dis-version.stdout", directory / "llvm-dis-version.stderr"
    argv = [str(snapshot), "--version"]
    with stdout.open("wb") as out, stderr.open("wb") as err:
        result = subprocess.run(argv, stdout=out, stderr=err, stdin=subprocess.DEVNULL)
    versions = re.findall(r"\bLLVM version (\d+\.\d+\.\d+)(?:\s|$)",
                          stdout.read_text(errors="replace") + "\n" + stderr.read_text(errors="replace"))
    if result.returncode or versions != ["22.1.6"]:
        raise ValueError("LLVM bitcode decoder must report exact LLVM22.1.6")
    return {**identity, "snapshot": file_info(snapshot), "llvm_version": "22.1.6",
            "version_argv": argv, "version_exit_code": result.returncode,
            "version_stdout": file_info(stdout), "version_stderr": file_info(stderr)}


def check_unit(unit: dict, directory: Path, compiler: Path, target: str,
               llvm_flags: list[str], llvm_decoder: dict | None = None) -> dict:
    directory.mkdir()
    record = {"id": unit["id"], "source": unit.get("source"), "input": unit["ir"],
              "frontend_version": unit.get("frontend_version"), "stages": [], "status": "failed",
              "runtime_complete": False, "native_execution_qualified": False}
    stage = "input"

    def invoke(name: str, argv: list[str]) -> bool:
        nonlocal stage
        stage = name
        start = time.monotonic()
        stdout, stderr = directory / (name + ".stdout"), directory / (name + ".stderr")
        with stdout.open("wb") as out, stderr.open("wb") as err:
            result = subprocess.run(argv, stdout=out, stderr=err, stdin=subprocess.DEVNULL)
        item = {"stage": name, "argv": argv, "exit_code": result.returncode,
                "seconds": round(time.monotonic() - start, 6), "stdout": file_info(stdout), "stderr": file_info(stderr)}
        record["stages"].append(item)
        if result.returncode:
            text = stderr.read_text(errors="replace")
            record["failed_stage"] = name
            record["first_diagnostic"] = diagnostic(text)
            record["first_stderr_line"] = next((line for line in text.splitlines() if line.strip()), "")
            return False
        return True

    try:
        ir = unit["ir"]
        path = Path(ir["path"])
        actual = file_info(path)
        if not path.is_absolute() or any(actual[key] != ir[key] for key in ["sha256", "bytes"]):
            raise ValueError("captured LLVM input SHA-256/size mismatch")
        if is_llvm_bitcode(path):
            stage = "llvm_decode"
            if llvm_decoder is None:
                raise ValueError("raw LLVM bitcode requires a snapshotted LLVM22.1.6 metadata decoder")
            decoder = llvm_decoder["snapshot"]
            if file_info(Path(decoder["path"])) != decoder:
                raise ValueError("LLVM bitcode decoder snapshot changed")
            decoded, decode_stderr = directory / "decoded.ll", directory / "llvm-decode.stderr"
            decode_argv = [decoder["path"], str(path), "-o", "-"]
            started = time.monotonic()
            with decoded.open("wb") as out, decode_stderr.open("wb") as err:
                result = subprocess.run(decode_argv, stdout=out, stderr=err, stdin=subprocess.DEVNULL)
            record["llvm_decode"] = {"argv": decode_argv, "exit_code": result.returncode,
                "seconds": round(time.monotonic() - started, 6), "input": actual,
                "decoder": decoder, "stdout": file_info(decoded), "stderr": file_info(decode_stderr)}
            if result.returncode:
                record["failed_stage"] = stage
                record["first_diagnostic"] = diagnostic(decode_stderr.read_text(errors="replace"))
                return record
            if file_info(Path(decoder["path"])) != decoder or file_info(path) != actual:
                raise ValueError("LLVM decoder or original bitcode changed during metadata decoding")
            record["decoded_llvm"] = file_info(decoded)
            text = decoded.read_text()
            stage = "input"
        else:
            text = path.read_text()
        for field, keyword in [("target_triple", "triple"), ("data_layout", "datalayout")]:
            match = re.search(r'^target ' + keyword + r' = "([^"]+)"', text, re.MULTILINE)
            if match is None or match.group(1) != ir[field]:
                raise ValueError("captured LLVM target metadata mismatch")
        if ir["target_triple"].split("-", 1)[0] != TARGETS[target][0]:
            raise ValueError("source LLVM architecture differs from the selected O-core ISA")
        module_path = directory / "module.json"
        if not invoke("import", [str(compiler), str(path), "--input-kind", "llvm-ir", "--emit", "mir",
                                 "--target", target, "-o", str(module_path), *llvm_flags]):
            return record
        module = json.loads(module_path.read_text())
        if module.get("provenance", {}).get("input_sha256") != actual["sha256"]:
            raise ValueError("imported module does not bind the captured LLVM input")
        module_target = module.get("target", {})
        if module_target.get("triple") != ir["target_triple"] or module_target.get("data_layout") != ir["data_layout"]:
            raise ValueError("imported module changed frontend target triple/DataLayout")
        record["module"] = file_info(module_path)
        record["definition_counts"] = {"functions": sum(item.get("entry") is not None for item in module["functions"]),
                                       "function_declarations": sum(item.get("entry") is None for item in module["functions"]),
                                       "globals": len(module["globals"])}
        receipt_path = directory / "verification.json"
        if not invoke("verify", [str(compiler), str(module_path), "--input-kind", "native-ir", "--verify-native",
                                 "--receipt", str(receipt_path)]):
            return record
        receipt = json.loads(receipt_path.read_text())
        if receipt.get("verified") is not True or receipt.get("module_sha256") != record["module"]["sha256"]:
            raise ValueError("independent verifier receipt is not bound to the imported module")
        record["verification"] = file_info(receipt_path)
        object_path = directory / "module.o"
        if not invoke("object", [str(compiler), str(module_path), "--input-kind", "native-ir", "--emit", "obj",
                                 "--target", target, "-o", str(object_path)]):
            return record
        record["object"] = inspect_elf(object_path, TARGETS[target][1])
        record["status"] = "verified-object"
    except (OSError, ValueError, KeyError) as error:
        record["failed_stage"] = stage
        record["first_diagnostic"] = {"message": str(error)}
    finally:
        write_json(directory / "receipt.json", record)
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--step", required=True, help="exact recorded build-step name; this is diagnostic selection only")
    parser.add_argument("--ocorec", type=Path, default=Path("target/debug/ocorec"))
    parser.add_argument("--target", choices=TARGETS, default="x86_64-unknown-none")
    parser.add_argument("--llvm-library", type=Path)
    parser.add_argument("--llvm-sha256")
    parser.add_argument("--llvm-dis", type=Path, help="LLVM22.1.6 metadata decoder, required only for raw bitcode (default: PATH llvm-dis)")
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 1, 8))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.jobs < 1 or bool(args.llvm_library) != bool(args.llvm_sha256):
        parser.error("positive --jobs and a paired LLVM library/SHA-256 selection are required")
    output = args.output.resolve()
    try:
        output.mkdir(parents=True, exist_ok=False)
        report_path = args.report.resolve()
        source_info = file_info(report_path)
        source = json.loads(report_path.read_text())
        units, step = selected_units(source, args.step)
        compiler_info = file_info(args.ocorec.resolve())
        tools = output / "tools"
        tools.mkdir()
        compiler = tools / "ocorec"
        shutil.copy2(compiler_info["path"], compiler)
        if file_info(compiler)["sha256"] != compiler_info["sha256"]:
            raise ValueError("compiler changed while snapshotting the actual executable")
        flags = []
        library_info = None
        if args.llvm_library:
            library_info = file_info(args.llvm_library.resolve())
            if library_info["sha256"] != args.llvm_sha256:
                raise ValueError("selected LLVM parser library SHA-256 mismatch")
            flags = ["--llvm-library", library_info["path"], "--llvm-sha256", args.llvm_sha256]
        decoder = snapshot_llvm_decoder(args.llvm_dis, tools) if any(is_llvm_bitcode(Path(unit["ir"]["path"])) for unit in units) else None
        result = {"schema": "ocore-runtime-import-diagnostics-v1", "source_capture": source_info,
                  "capture_complete": source.get("capture_complete", False), "unit_inventory_complete": source.get("unit_inventory_complete", False),
                  "selection": {"mode": "recorded-build-step", "step": step, "for_runtime_acceptance": False},
                  "provenance_unit_count": len(source["units"]),
                  "provenance_units": [{"id": unit["id"], "source": unit.get("source"), "ir": unit["ir"]} for unit in source["units"]],
                  "selected_unit_count": len(units), "tools": {"ocorec": compiler_info, "snapshot": file_info(compiler), "llvm_library": library_info, "llvm_dis": decoder},
                  "target": args.target, "jobs": args.jobs, "units": [], "issues": [], "audit_complete": False,
                  "source_capture_gaps": {"issues": source.get("issues", []), "failed_required_units": source.get("failed_required_units", [])},
                  "dependency_closure_complete": False, "native_execution_qualified": False, "runtime_complete": False}
        write_json(output / "report.json", result)
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
            futures = {executor.submit(check_unit, unit, output / (f"unit-{index:04d}"), compiler, args.target, flags, decoder): unit
                       for index, unit in enumerate(units)}
            for future in concurrent.futures.as_completed(futures):
                result["units"].append(future.result())
                if len(result["units"]) % 25 == 0:
                    print(f"audited {len(result['units'])}/{len(units)} whole units", flush=True)
                    write_json(output / "report.json", result)
        result["units"].sort(key=lambda unit: unit["id"])
        if file_info(report_path) != source_info:
            result["issues"].append("capture report changed during the diagnostic audit")
        if decoder is not None:
            artifacts = [{key: decoder[key] for key in ("path", "bytes", "sha256")},
                         decoder["snapshot"], decoder["version_stdout"], decoder["version_stderr"]]
            for artifact in artifacts:
                try:
                    if file_info(Path(artifact["path"])) != artifact:
                        raise ValueError("artifact bytes changed")
                except (OSError, ValueError) as error:
                    result["issues"].append(f"LLVM bitcode decoder evidence changed: {artifact['path']}: {error}")
        groups = {}
        for unit in result["units"]:
            if unit["status"] == "verified-object":
                continue
            diag = unit["first_diagnostic"]
            if unit["failed_stage"] in {"input", "llvm_decode"}:
                result["issues"].append(f"unit {unit['id']} infrastructure/provenance failure at {unit['failed_stage']}: {diag.get('message', '')}")
                continue
            key = (unit["failed_stage"], diag.get("stage"), diag.get("message", ""))
            groups.setdefault(key, []).append(unit["id"])
        result["first_failure_groups"] = [{"stage": key[0], "diagnostic_stage": key[1], "message": key[2], "unit_ids": ids, "count": len(ids)}
                                          for key, ids in sorted(groups.items(), key=lambda item: (-len(item[1]), str(item[0])))]
        result["verified_object_count"] = sum(unit["status"] == "verified-object" for unit in result["units"])
        result["imported_unit_count"] = sum("module" in unit for unit in result["units"])
        result["independently_verified_unit_count"] = sum("verification" in unit for unit in result["units"])
        result["audit_complete"] = len(result["units"]) == len(units) and not result["issues"]
        result["seconds"] = round(time.monotonic() - start, 3)
        write_json(output / "report.json", result)
        print(json.dumps({"report": str(output / "report.json"), "selected_units": len(units),
                          "imported_units": result["imported_unit_count"], "verified_objects": result["verified_object_count"],
                          "audit_complete": result["audit_complete"], "runtime_complete": False,
                          "first_failure_groups": [{key: value for key, value in group.items() if key != "unit_ids"}
                                                   for group in result["first_failure_groups"]]}, indent=2))
        if not result["audit_complete"]:
            return 2
        return 0 if result["verified_object_count"] == len(units) and source.get("capture_complete") else 1
    except (OSError, ValueError, KeyError) as error:
        print(f"ocore-runtime-import-audit: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
