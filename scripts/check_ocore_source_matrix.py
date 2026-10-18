#!/usr/bin/env python3
"""Audit complete recorded source-build steps with one frozen O-core compiler.

This combines existing whole-unit diagnostics. An audited profile is not a
complete runtime, dependency closure, executable, or language-support claim.
Exit zero means every requested diagnostic finished, including recorded
unsupported units. Read all_units_lowered separately.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import check_ocore_runtime_imports as audit


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def checked_file(record: dict) -> dict:
    actual = audit.file_info(Path(record["path"]))
    require(all(actual[key] == record[key] for key in ("sha256", "bytes")),
            "artifact changed: " + record["path"])
    return actual


def is_bitcode(path: Path) -> bool:
    with path.open("rb") as stream:
        return stream.read(4) in (b"BC\xc0\xde", b"\xde\xc0\x17\x0b")


def load_profiles(manifest: Path) -> list[dict]:
    data = json.loads(manifest.read_text())
    require(isinstance(data, dict) and data.get("schema") == "ocore-source-audit-matrix-v1", "wrong matrix manifest schema")
    require(isinstance(data.get("profiles"), list) and bool(data["profiles"]), "profiles must be a nonempty array")
    profiles, names = [], set()
    for item in data["profiles"]:
        require(isinstance(item, dict) and set(item) == {"name", "language", "capture", "step"},
                "each profile requires exactly name, language, capture and step")
        name = item["name"]
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name),
                "profile name must be a safe directory name")
        require(name not in names, "duplicate profile name: " + name)
        names.add(name)
        require(all(isinstance(item[key], str) and item[key].strip() for key in ("language", "capture", "step")),
                "profile language, capture and step must be nonempty strings")
        capture = (manifest.parent / item["capture"]).resolve(strict=True)
        source = json.loads(capture.read_text())
        require(isinstance(source, dict), "capture report must be an object")
        units, step = audit.selected_units(source, item["step"])
        profiles.append({**item, "capture": str(capture), "capture_file": audit.file_info(capture),
                         "source": source, "selected_units": units, "selected_step": step})
    return profiles


def checked_result(path: Path, profile: dict, compiler_sha256: str, target: str,
                   decoder_sha256: str | None = None) -> dict:
    result = json.loads(path.read_text())
    require(result.get("schema") == "ocore-runtime-import-diagnostics-v1", "wrong diagnostic report schema")
    require(result.get("audit_complete") is True and result.get("issues") == [], "unit diagnostic did not finish")
    require(result.get("target") == target, "diagnostic target changed")
    require(result.get("source_capture") == profile["capture_file"], "diagnostic capture identity changed")
    require(result.get("selection") == {"mode": "recorded-build-step", "step": profile["selected_step"],
                                        "for_runtime_acceptance": False}, "diagnostic selected a different build step")
    expected = {unit["id"]: unit for unit in profile["selected_units"]}
    units = result.get("units", [])
    require(len(units) == len(expected) and {unit["id"] for unit in units} == set(expected),
            "diagnostic omitted, duplicated or added a selected whole unit")
    require(result.get("selected_unit_count") == len(expected), "diagnostic selected count changed")
    provenance = [{"id": unit["id"], "source": unit.get("source"), "ir": unit["ir"]}
                  for unit in profile["source"]["units"]]
    require(result.get("provenance_units") == provenance and result.get("provenance_unit_count") == len(provenance),
            "diagnostic omitted capture provenance units")
    for key in ("ocorec", "snapshot"):
        require(checked_file(result["tools"][key])["sha256"] == compiler_sha256,
                "diagnostic used a different compiler")
    snapshot = Path(result["tools"]["snapshot"]["path"]).resolve()
    decoder = result["tools"].get("llvm_dis")
    needs_decoder = any(is_bitcode(Path(u["ir"]["path"])) for u in expected.values())
    require(bool(decoder) == needs_decoder, "bitcode decoder presence does not match original inputs")
    if needs_decoder:
        require(decoder_sha256 is not None, "bitcode decoder was not frozen by the matrix")
        require(all(checked_file(record)["sha256"] == decoder_sha256
                    for record in (decoder, decoder["snapshot"])), "diagnostic used a different bitcode decoder")
        require(decoder["llvm_version"] == "22.1.6" and decoder["version_exit_code"] == 0 and
                decoder["version_argv"] == [decoder["snapshot"]["path"], "--version"],
                "bitcode decoder version check changed")
        checked_file(decoder["version_stdout"])
        checked_file(decoder["version_stderr"])
        versions = re.findall(r"\bLLVM version (\d+\.\d+\.\d+)(?:\s|$)",
                              Path(decoder["version_stdout"]["path"]).read_text(errors="replace") + "\n" +
                              Path(decoder["version_stderr"]["path"]).read_text(errors="replace"))
        require(versions == ["22.1.6"], "bitcode decoder did not report the pinned LLVM version")
    counts = {"imported_unit_count": 0, "independently_verified_unit_count": 0, "verified_object_count": 0}
    failures = {}
    for unit in units:
        original = expected[unit["id"]]
        require(unit["input"] == original["ir"] and unit.get("source") == original.get("source"),
                "diagnostic changed an original whole-unit input")
        checked_file(unit["input"])
        if is_bitcode(Path(original["ir"]["path"])):
            decode = unit["llvm_decode"]
            require(decode["exit_code"] == 0 and decode["argv"] ==
                    [decoder["snapshot"]["path"], original["ir"]["path"], "-o", "-"],
                    "diagnostic did not decode the complete original bitcode")
            require(decode["input"] == audit.file_info(Path(original["ir"]["path"])) and
                    decode["decoder"] == decoder["snapshot"], "bitcode decode provenance changed")
            checked_file(decode["stderr"])
            checked_file(decode["stdout"])
            require(unit["decoded_llvm"] == decode["stdout"], "decoded LLVM identity changed")
            text = Path(unit["decoded_llvm"]["path"]).read_text()
            for spelling, key in (("triple", "target_triple"), ("datalayout", "data_layout")):
                match = re.search(r'^target ' + spelling + r'\s*=\s*"([^"\n]*)"', text, re.MULTILINE)
                require(match is not None and match.group(1) == original["ir"][key],
                        "decoded bitcode changed the frontend target contract")
        else:
            require("llvm_decode" not in unit and "decoded_llvm" not in unit, "textual LLVM has a forged decode stage")
        stages = unit.get("stages", [])
        require([stage["stage"] for stage in stages] == ["import", "verify", "object"][:len(stages)],
                "unexpected diagnostic stage sequence")
        for stage in stages:
            require(Path(stage["argv"][0]).resolve() == snapshot, "stage executable differs from frozen compiler")
            checked_file(stage["stdout"])
            checked_file(stage["stderr"])
        if stages:
            require(Path(stages[0]["argv"][1]).resolve() == Path(original["ir"]["path"]).resolve(),
                    "import did not consume the complete captured LLVM input")
        if "module" in unit:
            module_file = checked_file(unit["module"])
            module = json.loads(Path(module_file["path"]).read_text())
            require(stages[0]["exit_code"] == 0 and module["provenance"]["input_sha256"] == unit["input"]["sha256"],
                    "module has no successful import bound to its original input")
            require(module["target"]["triple"] == original["ir"]["target_triple"] and
                    module["target"]["data_layout"] == original["ir"]["data_layout"],
                    "module changed the frontend target contract")
            require(module["provenance"]["source_function_count"] == len(module["functions"]) and
                    module["provenance"]["source_global_count"] == len(module["globals"]),
                    "imported module omitted its source definition inventory")
            require(unit["definition_counts"] == {
                "functions": sum(f.get("entry") is not None for f in module["functions"]),
                "function_declarations": sum(f.get("entry") is None for f in module["functions"]),
                "globals": len(module["globals"])}, "module definition counts changed")
            counts["imported_unit_count"] += 1
        if "verification" in unit:
            require("module" in unit and len(stages) >= 2 and stages[1]["exit_code"] == 0,
                    "verification has no successful independent verifier stage")
            checked_file(unit["verification"])
            receipt = json.loads(Path(unit["verification"]["path"]).read_text())
            require(receipt.get("verified") is True and receipt.get("module_sha256") == unit["module"]["sha256"],
                    "verifier receipt is not bound to exact imported module bytes")
            require([{"name": f["name"], "definition": f["definition"]} for f in receipt["functions"]] ==
                    [{"name": f["name"], "definition": f.get("entry") is not None} for f in module["functions"]]
                    and receipt["global_count"] == len(module["globals"])
                    and receipt["target"] == module["target"], "independent verifier inventory changed")
            counts["independently_verified_unit_count"] += 1
        if unit["status"] == "verified-object":
            require("verification" in unit and len(stages) == 3 and all(s["exit_code"] == 0 for s in stages),
                    "object has an unsuccessful or missing compilation stage")
            actual = audit.inspect_elf(Path(unit["object"]["path"]), audit.TARGETS[target][1])
            require(all(actual[key] == unit["object"][key] for key in actual), "object identity/header changed")
            counts["verified_object_count"] += 1
        else:
            require(unit["status"] == "failed" and "object" not in unit, "unexpected whole-unit status")
            diagnostic = unit["first_diagnostic"]
            key = (unit["failed_stage"], diagnostic.get("stage"), diagnostic.get("message", ""))
            failures.setdefault(key, []).append(unit["id"])
    require(all(result.get(key) == count for key, count in counts.items()), "diagnostic aggregate counts changed")
    groups = result["first_failure_groups"]
    grouped = {(g["stage"], g.get("diagnostic_stage"), g["message"]): sorted(g["unit_ids"]) for g in groups}
    require(len(grouped) == len(groups) and all(g["count"] == len(g["unit_ids"]) for g in groups),
            "duplicate or inconsistent first-failure group counts")
    require(grouped == {key: sorted(ids) for key, ids in failures.items()}, "first-failure unit inventory changed")
    require(all(result.get(key) is False for key in ("dependency_closure_complete", "native_execution_qualified", "runtime_complete")),
            "unit audit must not claim runtime qualification")
    return {"name": profile["name"], "language": profile["language"], "step": profile["step"],
            "capture": profile["capture_file"], "source": profile["source"].get("source"),
            "selected_units": len(expected), "attempted_unit_ids": sorted(expected), **counts,
            "capture_complete": profile["source"].get("capture_complete", False),
            "all_units_lowered": counts["verified_object_count"] == len(expected),
            "first_failure_groups": result["first_failure_groups"], "report": audit.file_info(path),
            "audit_complete": True, "native_execution_qualified": False, "runtime_complete": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--ocorec", default="ocorec")
    parser.add_argument("--target", choices=audit.TARGETS, default="riscv64-unknown-none")
    parser.add_argument("--llvm-library", type=Path)
    parser.add_argument("--llvm-sha256")
    parser.add_argument("--llvm-dis", help="LLVM 22.1.6 decoder for original bitcode metadata; compiler input remains raw bitcode")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.jobs < 1 or bool(args.llvm_library) != bool(args.llvm_sha256):
        parser.error("positive --jobs and paired LLVM library/SHA-256 selection required")
    report = None
    output = None
    try:
        manifest = args.manifest.resolve(strict=True)
        manifest_file = audit.file_info(manifest)
        profiles = load_profiles(manifest)
        selected = shutil.which(args.ocorec)
        require(selected is not None, "O-core compiler executable was not found")
        compiler_file = audit.file_info(Path(selected))
        library_file = audit.file_info(args.llvm_library.resolve(strict=True)) if args.llvm_library else None
        require(library_file is None or library_file["sha256"] == args.llvm_sha256, "LLVM library digest mismatch")
        output = args.output.resolve()
        output.mkdir(parents=True, exist_ok=False)
        tools = output / "tools"
        tools.mkdir()
        snapshot = tools / "ocorec"
        shutil.copy2(compiler_file["path"], snapshot)
        require(audit.file_info(snapshot)["sha256"] == compiler_file["sha256"], "compiler changed during snapshot")
        decoder_file = None
        if any(is_bitcode(Path(u["ir"]["path"])) for p in profiles for u in p["selected_units"]):
            selected_decoder = shutil.which(args.llvm_dis or "llvm-dis")
            require(selected_decoder is not None, "LLVM bitcode decoder executable was not found")
            decoder_file = audit.file_info(Path(selected_decoder))
            decoder_snapshot = tools / "llvm-dis"
            shutil.copy2(decoder_file["path"], decoder_snapshot)
            decoder_file["snapshot"] = audit.file_info(decoder_snapshot)
            require(decoder_file["snapshot"]["sha256"] == decoder_file["sha256"], "decoder changed during snapshot")
        worker = Path(audit.__file__).resolve()
        report = {"schema": "ocore-source-audit-matrix-result-v1", "manifest": manifest_file,
                  "runner": audit.file_info(Path(__file__).resolve()), "worker": audit.file_info(worker),
                  "compiler": compiler_file, "snapshot": audit.file_info(snapshot), "llvm_library": library_file,
                  "llvm_dis": decoder_file,
                  "target": args.target, "jobs": args.jobs, "profiles": [], "issues": [],
                  "audit_complete": False, "native_execution_qualified": False, "runtime_complete": False}
        audit.write_json(output / "report.json", report)
        for profile in profiles:
            argv = [sys.executable, str(worker), profile["capture"], "--step", profile["step"],
                    "--ocorec", str(snapshot), "--target", args.target, "--jobs", str(args.jobs),
                    "--output", str(output / profile["name"])]
            if library_file:
                argv.extend(["--llvm-library", library_file["path"], "--llvm-sha256", args.llvm_sha256])
            if decoder_file:
                argv.extend(["--llvm-dis", decoder_file["snapshot"]["path"]])
            log = output / (profile["name"] + ".log")
            with log.open("wb") as stream:
                process = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT)
            try:
                require(process.returncode in (0, 1), "diagnostic process failed before a complete audit")
                checked = checked_result(output / profile["name"] / "report.json", profile,
                                         compiler_file["sha256"], args.target,
                                         decoder_file["sha256"] if decoder_file else None)
                checked.update({"command": argv, "exit_code": process.returncode, "log": audit.file_info(log)})
                report["profiles"].append(checked)
                print(json.dumps({key: checked[key] for key in ("name", "selected_units", "verified_object_count", "audit_complete")}), flush=True)
            except (OSError, ValueError, KeyError, TypeError) as error:
                report["issues"].append({"profile": profile["name"], "error": str(error),
                                         "exit_code": process.returncode, "log": audit.file_info(log)})
            audit.write_json(output / "report.json", report)
        for record in [manifest_file, compiler_file, report["snapshot"], report["runner"], report["worker"],
                       *[profile["capture_file"] for profile in profiles], *([library_file] if library_file else []),
                       *([decoder_file, decoder_file["snapshot"]] if decoder_file else [])]:
            checked_file(record)
        report["audit_complete"] = len(report["profiles"]) == len(profiles) and not report["issues"]
        report["all_units_lowered"] = report["audit_complete"] and all(p["all_units_lowered"] for p in report["profiles"])
        audit.write_json(output / "report.json", report)
        print(json.dumps({"report": str(output / "report.json"), "audit_complete": report["audit_complete"],
                          "all_units_lowered": report["all_units_lowered"], "runtime_complete": False}, indent=2))
        return 0 if report["audit_complete"] else 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        if report is not None:
            report["issues"].append({"profile": None, "error": str(error)})
            report["audit_complete"] = False
            report["all_units_lowered"] = False
            audit.write_json(output / "report.json", report)
        print("ocore-source-matrix: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
