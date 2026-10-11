#!/usr/bin/env python3
"""Whole original threaded LLVM libunwind, with source-built musl inputs.

This is a separately declared Linux/musl profile. Native objects are reference
build evidence; neither those objects nor supplied compiler helpers are admitted
as O-core implementations.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

COMMON_SHA = "fc11249b7820b146fb195175c839df1209e3d3c79ced560560db9a3acb6987e0"
MUSL_COMMIT = "0784374d561435f7c787a555aeab8ede699ed298"
MUSL_PROVENANCE_SHA = {
    "x86_64": "a4637bc4365b8e1a8f23ac1f8bb0f25d04caa980fb4a59c78ffc934da44de97a",
    "aarch64": "81a48df6ce48f2afdfe78f283bc5ace366e0f5344ff58beaf19e823be96fb7ff",
    "riscv64": "312ccfe956a3993c3d78c602be188352b5268e01242714b6731ff02fdaa9ddc5",
}


def load_common():
    path = Path(__file__).with_name("build_inventory.py")
    import hashlib
    if hashlib.sha256(path.read_bytes()).hexdigest() != COMMON_SHA:
        raise ValueError("original inventory dependency differs from its frozen SHA-256")
    spec = importlib.util.spec_from_file_location("ocore_original_unwind_inventory", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ISAS = {isa: {**row, "triple": isa + "-unknown-linux-musl"}
                   for isa, row in module.ISAS.items()}
    return module


base = load_common()
PROFILES = base.ISAS
InventoryError = base.InventoryError
info, write, command = base.info, base.write, base.command


def check_artifact(record: dict) -> dict:
    actual = info(Path(record["path"]))
    if actual != record:
        raise InventoryError(f"source-owned artifact bytes changed: {record['path']}")
    return actual


def verify_musl(path: Path, isa: str) -> dict:
    if info(path)["sha256"] != MUSL_PROVENANCE_SHA[isa]:
        raise InventoryError("original musl target provenance differs from pinned bytes")
    receipt = json.loads(path.read_text())
    if (receipt["isa"] != isa or receipt["triple"] != PROFILES[isa]["triple"]
            or receipt["source"]["revision"] != MUSL_COMMIT):
        raise InventoryError("musl source/target profile differs from the declared dependency")
    if receipt["header_install_build_step"]["exit_code"] != 0:
        raise InventoryError("original musl target headers were not installed successfully")
    check_artifact(receipt["header_install_build_step"]["log_artifact"])
    for key in ["full_source_plan", "complete_native_source_build_inventory", "original_configuration"]:
        check_artifact(receipt[key])
    plan = json.loads(Path(receipt["full_source_plan"]["path"]).read_text())
    inventory = json.loads(Path(receipt["complete_native_source_build_inventory"]["path"]).read_text())
    if (not inventory["complete"] or inventory["issues"]
            or {k: plan["source"][k] for k in ["path", "revision"]} != receipt["source"]
            or inventory["source_plan"] != receipt["full_source_plan"]):
        raise InventoryError("original complete musl source/output inventory is inconsistent")
    source = Path(receipt["source"]["path"])
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True)
    if revision != MUSL_COMMIT or status:
        raise InventoryError("original musl source is no longer the clean pinned checkout")
    for record in plan["source"]["files"] + receipt["generated_headers"]:
        check_artifact(record)
    headers = Path(receipt["headers"]).resolve()
    expected = {Path(row["path"]).resolve() for row in receipt["installed_original_headers"]}
    actual = {p.resolve() for p in headers.rglob("*") if p.is_file()}
    if expected != actual:
        raise InventoryError("installed original musl headers have missing/extra files")
    for record in receipt["installed_original_headers"]:
        check_artifact(record)
    # Keep the entire original provider/startup/compatibility output graph. It is
    # reference build evidence, never opaque native admission.
    outputs = [check_artifact(record) for record in inventory["runtime_outputs"]]
    libc = [row for row in outputs if Path(row["path"]).name == "libc.a"]
    if len(libc) != 1 or len(inventory["original_archive_members"]) < 1:
        raise InventoryError("source-built musl archive/output ownership is absent")
    return {"receipt": info(path), "headers": str(headers), "sysroot": str(headers.parent),
            "library_dir": str(Path(libc[0]["path"]).parent), "source": plan["source"],
            "runtime_outputs": outputs, "original_LIBCC_selection": plan["expanded_graph"]["LIBCC"],
            "source_provider_ocore_complete": False, "dependency_closure_complete": False,
            "native_ostadix_platform_qualified": False}


def cmake_argv(source: Path, build: Path, isa: str, musl: dict,
               cc: str, cxx: str, ar: str, ranlib: str) -> list[str]:
    profile = PROFILES[isa]
    flags = shlex.join(["-nostdlibinc", "-isystem", musl["headers"], *profile["flags"]])
    defines = {
        "LLVM_ENABLE_RUNTIMES": "libunwind", "LLVM_DEFAULT_TARGET_TRIPLE": profile["triple"],
        "LLVM_ENABLE_PER_TARGET_RUNTIME_DIR": "OFF", "CMAKE_BUILD_TYPE": "Release",
        "CMAKE_EXPORT_COMPILE_COMMANDS": "ON", "CMAKE_SYSTEM_NAME": "Linux",
        "CMAKE_SYSTEM_PROCESSOR": profile["processor"], "CMAKE_SYSROOT": musl["sysroot"],
        "CMAKE_TRY_COMPILE_TARGET_TYPE": "STATIC_LIBRARY",
        "CMAKE_C_COMPILER": cc, "CMAKE_CXX_COMPILER": cxx, "CMAKE_ASM_COMPILER": cc,
        "CMAKE_C_COMPILER_TARGET": profile["triple"], "CMAKE_CXX_COMPILER_TARGET": profile["triple"],
        "CMAKE_ASM_COMPILER_TARGET": profile["triple"], "CMAKE_AR": ar, "CMAKE_RANLIB": ranlib,
        "CMAKE_C_FLAGS": flags, "CMAKE_CXX_FLAGS": flags, "CMAKE_ASM_FLAGS": flags,
        "CMAKE_EXE_LINKER_FLAGS": shlex.join(["-fuse-ld=lld", "-static", "-L" + musl["library_dir"]]),
        "LIBUNWIND_ENABLE_STATIC": "ON", "LIBUNWIND_ENABLE_SHARED": "OFF",
        "LIBUNWIND_IS_BAREMETAL": "OFF", "LIBUNWIND_ENABLE_CROSS_UNWINDING": "OFF",
        "LIBUNWIND_ENABLE_THREADS": "ON", "LIBUNWIND_ENABLE_ASSERTIONS": "ON",
        "LIBUNWIND_ENABLE_FRAME_APIS": "ON", "RUNTIMES_USE_LIBC": "system",
    }
    return ["cmake", "-G", "Ninja", "-S", str(source / "runtimes"), "-B", str(build),
            *[f"-D{key}={value}" for key, value in defines.items()]]


def check_cache(text: str, isa: str, musl: dict) -> None:
    values = dict(re.findall(r"^([^#/\n][^:\n]*):[^=\n]*=(.*)$", text, re.M))
    expected = {"LIBUNWIND_ENABLE_STATIC": "ON", "LIBUNWIND_ENABLE_SHARED": "OFF",
                "LIBUNWIND_ENABLE_THREADS": "ON", "LIBUNWIND_ENABLE_ASSERTIONS": "ON",
                "LIBUNWIND_ENABLE_FRAME_APIS": "ON", "LIBUNWIND_IS_BAREMETAL": "OFF",
                "LIBUNWIND_WEAK_PTHREAD_LIB": "OFF",
                "LIBUNWIND_ENABLE_CROSS_UNWINDING": "OFF", "CMAKE_SYSTEM_NAME": "Linux",
                "CMAKE_SYSROOT": musl["sysroot"],
                "CMAKE_C_COMPILER_TARGET": PROFILES[isa]["triple"],
                "CMAKE_CXX_COMPILER_TARGET": PROFILES[isa]["triple"],
                "CMAKE_ASM_COMPILER_TARGET": PROFILES[isa]["triple"]}
    for key, value in expected.items():
        if values.get(key) != value:
            raise InventoryError(f"original Linux/musl threaded profile mismatch: {key}")


def select_units(rows: list[dict], objects: list[Path], source: Path, isa: str, musl: dict) -> list[dict]:
    units = base.select_units(rows, objects, source, isa, True)
    for unit in units:
        args = unit["argv"]
        if any("_LIBUNWIND_IS_BAREMETAL" in arg or "_LIBUNWIND_HAS_NO_THREADS" in arg for arg in args):
            raise InventoryError("Linux threaded provider was changed to baremetal/single-threaded")
        if "-ffast-math" in args or "-ffreestanding" in args:
            raise InventoryError("Linux musl source execution profile was changed")
        for prefix, expected in [("-march=", "-march=rv64gc"), ("-mabi=", "-mabi=lp64d")]:
            if isa == "riscv64" and any(arg.startswith(prefix) and arg != expected for arg in args):
                raise InventoryError("original RV64GC LP64D source flags have conflicting overrides")
        if "--sysroot=" + musl["sysroot"] not in args:
            raise InventoryError("source compiler does not use the original target musl sysroot")
        if "-isystem" not in args or musl["headers"] not in args:
            raise InventoryError("source compiler does not use the authenticated target musl headers")
    return units


def context(source: Path, build: Path, capture: Path, isa: str, musl: dict) -> dict:
    session = json.loads((capture / "session.json").read_text())
    cc = session["tools"]["clang"]["invoked_path"]
    argv = [cc, "--target=" + PROFILES[isa]["triple"], *PROFILES[isa]["flags"],
            "--sysroot=" + musl["sysroot"], "-nostdlibinc", "-isystem", musl["headers"],
            "-I", str(source / "libunwind/include"), "-D_LIBUNWIND_IS_NATIVE_ONLY",
            "-dM", "-E", "-x", "c", "-"]
    row = command(argv, build, build / "provider-evidence/context", b"#include <__libunwind_config.h>\n#include <pthread.h>\n")
    if row["exit_code"]:
        raise InventoryError("original target context/pthread header preprocessing failed")
    check_context_macros(Path(row["stdout"]["path"]).read_text(), isa)
    # A real source-header compile verifies the required rwlock type. No typedef
    # or source override substitutes for the target libc header.
    rwlock = command([*argv[:-5], "-x", "c", "-fsyntax-only", "-"], build,
                     build / "provider-evidence/pthread-rwlock-type",
                     b"#include <pthread.h>\npthread_rwlock_t original_rwlock;\n")
    if rwlock["exit_code"]:
        raise InventoryError("original musl pthread_rwlock_t source header is unavailable")
    return {"macros": row, "pthread_rwlock_type": rwlock, "frontend": info(Path(cc)),
            "header": info(source / "libunwind/include/__libunwind_config.h")}


def check_context_macros(text: str, isa: str) -> None:
    # Empty feature macros must not consume the next line. These are genuine
    # original target-header definitions, not substitutions for libc ABI types.
    values = dict(re.findall(r"^#define[ \t]+(\S+)(?:[ \t]+(.*))?$", text, re.M))
    for name, expected in [("_LIBUNWIND_CONTEXT_SIZE", PROFILES[isa]["context"]),
                           ("_LIBUNWIND_CURSOR_SIZE", PROFILES[isa]["cursor"])]:
        if base.macro_integer(values, name) != expected:
            raise InventoryError("original target context layout differs: " + name)
    if values.get("_LIBUNWIND_TARGET_LINUX") != "1":
        raise InventoryError("original Linux target register context was not selected")
    if isa == "riscv64":
        for key, expected in [("__riscv_xlen", "64"), ("__riscv_flen", "64"), ("__riscv_float_abi_double", "1")]:
            if values.get(key) != expected:
                raise InventoryError("original RV64GC LP64D context differs: " + key)


def worker_scope(capture: Path) -> tuple[dict, dict]:
    session = json.loads((capture / "session.json").read_text())
    row = session["capture_worker"]["artifact"]
    check_artifact(row)
    if row["sha256"] != base.CAPTURE_WORKER_SHA:
        raise InventoryError("capture worker differs from declared frozen worker")
    scope = {"__name__": "ocore_linux_musl_unwind_inventory", "__file__": row["path"]}
    exec(compile(Path(row["path"]).read_bytes(), row["path"], "exec"), scope)
    return scope, session


def without_dependency_outputs(args: list[str]) -> list[str]:
    result, index = [], 0
    while index < len(args):
        if args[index] in {"-MF", "-MT", "-MQ"}:
            if index + 1 >= len(args):
                raise InventoryError("dependency-output flag has no operand")
            index += 2
        elif args[index] in {"-MD", "-MMD", "-MP"}:
            index += 1
        else:
            result.append(args[index])
            index += 1
    return result


def bind_expanded_commands(units: list[dict], text: str, build: Path) -> None:
    """Bind database producers to full evaluated Ninja argv, without changing it."""
    by_output = {}
    for line in text.splitlines():
        args = shlex.split(line)
        if "-c" not in args or "-o" not in args:
            continue
        if any(token in args for token in ["&&", ";", "||", "|", ">", "<"]):
            raise InventoryError("compiler producer has unsupported compound shell semantics")
        if args.count("-o") != 1 or args.index("-o") + 1 == len(args):
            raise InventoryError("expanded original compiler producer has ambiguous output")
        output = (build / args[args.index("-o") + 1]).resolve()
        by_output.setdefault(output, []).append(args)
    if set(by_output) != {Path(unit["native_output"]).resolve() for unit in units}:
        raise InventoryError("expanded Ninja compiler graph differs from original archive producer graph")
    for unit in units:
        candidates = by_output[Path(unit["native_output"]).resolve()]
        if len(candidates) != 1 or without_dependency_outputs(candidates[0]) != without_dependency_outputs(unit["argv"]):
            raise InventoryError("expanded Ninja source behavior differs from compile database producer")
        unit["compile_database_argv"] = unit["argv"]
        unit["argv"] = candidates[0]


def inventory(source: Path, build: Path, capture: Path, isa: str, output: Path, after: bool) -> dict:
    config = json.loads((build / "provider-configuration.json").read_text())
    if config["isa"] != isa or config["profile"] != "linux_musl_threaded":
        raise InventoryError("inventory requested a different original target profile")
    if base.source_identity(source) != config["source"]:
        raise InventoryError("original LLVM source changed after configuration")
    musl = verify_musl(Path(config["musl"]["receipt"]["path"]), isa)
    if musl != config["musl"]:
        raise InventoryError("musl source/build dependency changed after configuration")
    check_cache((build / "CMakeCache.txt").read_text(), isa, musl)
    evidence = build / "provider-evidence" / output.stem
    query = command(["ninja", "-C", str(build), "-t", "query", "lib/libunwind.a"], build, evidence / "archive-query")
    if query["exit_code"]:
        raise InventoryError("configured original archive graph is unavailable")
    objects = base.query_objects(Path(query["stdout"]["path"]).read_text(), build)
    rows = json.loads((build / "compile_commands.json").read_text())
    units = select_units(rows, objects, source, isa, musl)
    expanded = command(["ninja", "-C", str(build), "-t", "commands", "lib/libunwind.a"], build,
                       evidence / "expanded-commands")
    if expanded["exit_code"]:
        raise InventoryError("complete expanded Ninja source command graph is unavailable")
    bind_expanded_commands(units, Path(expanded["stdout"]["path"]).read_text(), build)
    scope, session = worker_scope(capture)
    events = [json.loads(p.read_text()) for p in sorted((capture / "events").glob("*.json"))]
    production = [e for e in events if e.get("kind") == "clang"
                  and e.get("build_step", {}).get("name") == "build-original-provider"]
    issues, blockers = [], []
    for unit in units:
        observed = [e for e in production if e.get("expanded_argv") == unit["argv"][1:]
                    and Path(e["cwd"]).resolve() == Path(unit["directory"]).resolve()]
        unit["invocation_ids"] = [e["id"] for e in observed]
        if after and (len(observed) != 1 or observed[0]["exit_code"] != 0):
            issues.append("missing/ambiguous/failed exact original source producer: " + unit["source"])
        path = Path(unit["native_output"])
        if path.is_file():
            unit["native_output_artifact"] = info(path)
        elif after:
            issues.append("required original source object absent: " + str(path))
        if unit["source_kind"] == "assembly":
            prep = command(base.preprocess_argv(unit["argv"], session["tools"]["clang"]["invoked_path"]),
                           Path(unit["directory"]), evidence / (Path(unit["source"]).stem + "-preprocessed"))
            unit["original_preprocessed_assembly"] = prep
            if prep["exit_code"]:
                issues.append("required original assembly preprocessing failed: " + unit["source"])
            blockers.append("required original source assembly has no O-core importer: " + unit["source"])
    if after and len(production) != len(units):
        issues.append("production invocation count differs from complete original source graph")
    archive = build / "lib/libunwind.a"
    members = scope["native_archive_members"](archive) if archive.is_file() else []
    if after and (not archive.is_file() or not base.archive_matches(units, members)):
        issues.append("complete original archive member order/content is absent or differs")
    deps = command(["ninja", "-C", str(build), "-t", "deps"], build, evidence / "dependencies")
    dependencies, current = [], None
    for line in Path(deps["stdout"]["path"]).read_text().splitlines():
        if line and not line.startswith(" ") and ": #deps " in line:
            current = line.split(": #deps ", 1)[0]
        if line.startswith("    "):
            path = Path(line.strip())
            if not path.is_absolute(): path = build / path
            if path.is_file(): dependencies.append({"native_output": current, "dependency": info(path)})
    value = {"schema": "ocore-runtime-unit-inventory-v1", "complete": not issues,
             "units": [{k: u[k] for k in ["id", "kind", "source", "role"]}
                       | {"build_step": "build-original-provider"} for u in units],
             "runtime_outputs": [info(archive)] if archive.is_file() else [], "non_lowering_units": [],
             "scope": "whole original Linux/musl threaded static libunwind graph; configure evidence not excluded",
             "original_units": units, "archive_members": members, "source": config["source"],
             "configuration": info(build / "provider-configuration.json"), "musl": musl,
             "build_graph_artifacts": [info(build / name) for name in ["compile_commands.json", "build.ninja", "CMakeCache.txt"]],
             "expanded_original_commands": expanded,
             "original_dependencies": dependencies, "dependency_query": deps,
             "generated_headers": [info(p) for p in sorted(build.rglob("*.h")) if p.is_file()],
             "inventory_helper": info(Path(__file__)), "common_helper": info(Path(base.__file__)),
             "issues": issues, "lowering_blockers": blockers, "source_assembly_lowered": False,
             "whole_provider_ocore_complete": False, "dependency_closure_complete": False,
             "full_rust_runtime_complete": False, "native_ostadix_platform_qualified": False}
    write(output, value)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["configure", "inventory"])
    for key in ["source", "build", "capture"]:
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--isa", choices=PROFILES, required=True)
    parser.add_argument("--expected-helper-sha256", required=True)
    for key in ["cc", "cxx", "ar", "ranlib"]: parser.add_argument("--" + key)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--after-build", action="store_true")
    args = parser.parse_args()
    if info(Path(__file__))["sha256"] != args.expected_helper_sha256:
        raise InventoryError("Linux musl inventory helper differs from pinned recipe bytes")
    source, build, capture = args.source.resolve(), args.build.resolve(), args.capture.resolve()
    if args.action == "configure":
        musl = verify_musl(Path(os.environ["OCORE_LIBUNWIND_MUSL_PROVENANCE"]), args.isa)
        config = {"schema": "ocore-original-libunwind-linux-musl-configuration-v1",
                  "source": base.source_identity(source), "isa": args.isa,
                  "profile": "linux_musl_threaded", "musl": musl, "helper": info(Path(__file__)),
                  "common_helper": info(Path(base.__file__)), "whole_provider_ocore_complete": False,
                  "dependency_closure_complete": False, "full_rust_runtime_complete": False,
                  "native_ostadix_platform_qualified": False}
        write(build / "provider-configuration.json", config)
        row = command(cmake_argv(source, build, args.isa, musl, args.cc, args.cxx, args.ar, args.ranlib),
                      build, build / "provider-evidence/configure")
        config["configure"] = row
        if not row["exit_code"]: config["context"] = context(source, build, capture, args.isa, musl)
        write(build / "provider-configuration.json", config)
        return row["exit_code"]
    value = inventory(source, build, capture, args.isa, args.output or build / "unit-inventory.json", args.after_build)
    print(json.dumps({"units": len(value["units"]), "members": len(value["archive_members"]), "issues": value["issues"]}))
    return 0 if value["complete"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InventoryError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print("Linux musl libunwind inventory error: " + str(error), file=__import__("sys").stderr)
        raise SystemExit(1)
