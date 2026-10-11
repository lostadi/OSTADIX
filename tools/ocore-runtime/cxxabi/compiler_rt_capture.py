#!/usr/bin/env python3
"""Complete original target compiler-rt builtins/CRT reference source capture."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

UNWIND_HELPER_SHA = "222699ccb07e93f925d82e010187874d50d97df47954a021af59b1efebf37e41"
LLVM_COMMIT = "dcc3606807c989700e0ac1cac18c31741bcd40d9"
LINUX_UAPI_PACKAGE_SHA = "47ecf11a8e6d4d09ee7dccc1cb83de8d2a424b4e0cd7e5e325b8dea7aa6f701e"


def load_unwind():
    path = Path(__file__).with_name("linux_musl_inventory.py")
    if not path.is_file(): path = Path(__file__).parent.parent / "unwind/linux_musl_inventory.py"
    if hashlib.sha256(path.read_bytes()).hexdigest() != UNWIND_HELPER_SHA:
        raise ValueError("frozen source-built musl/unwind inventory dependency changed")
    spec = importlib.util.spec_from_file_location("ocore_musl_dependency", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dependency = load_unwind()
info, write, command = dependency.info, dependency.write, dependency.command
InventoryError = dependency.InventoryError
PROFILES = dependency.PROFILES


def source_identity(source: Path) -> dict:
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True)
    if revision != LLVM_COMMIT or status:
        raise InventoryError("original LLVM source is not the clean pinned checkout")
    names = subprocess.check_output(["git", "ls-files", "-z", "compiler-rt", "cmake", "third-party/siphash"], cwd=source).split(b"\0")
    return {"path": str(source), "revision": revision, "clean": True,
            "files": [info(source / os.fsdecode(p)) for p in names if p]}


def verify_linux_uapi(path: Path) -> dict:
    value = json.loads(path.read_text())
    pkg = value["package"]
    if (pkg["name"] != "linux-libc-dev-riscv64-cross" or pkg["version"] != "7.0.0-13.13cross1"
            or pkg["built_using"] != "linux (= 7.0.0-13.13)"
            or pkg["artifact"]["sha256"] != LINUX_UAPI_PACKAGE_SHA):
        raise InventoryError("Linux UAPI dependency is not the authenticated original package")
    dependency.check_artifact(pkg["artifact"])
    dependency.check_artifact(value["original_package_metadata"])
    headers = Path(value["headers"]).resolve()
    if {p.resolve() for p in headers.rglob("*") if p.is_file()} != {Path(r["path"]).resolve() for r in value["files"]}:
        raise InventoryError("Linux UAPI header inventory changed")
    for row in value["files"]: dependency.check_artifact(row)
    if not (headers / "linux/unistd.h").is_file() or not (headers / "asm/unistd.h").is_file():
        raise InventoryError("authentic RISC-V Linux syscall headers absent")
    return {"receipt": info(path), "headers": str(headers), "package": pkg,
            "source_header_generation_reproduced": False, "source_closure_complete": False}


def cmake_argv(source: Path, build: Path, isa: str, musl: dict, sdk: Path,
               cc: str, cxx: str, ar: str, ranlib: str, uapi: dict | None = None) -> list[str]:
    profile = PROFILES[isa]
    flags = shlex.join(["-nostdlibinc", "-isystem", musl["headers"],
                        *(["-isystem", uapi["headers"]] if uapi else []), *profile["flags"]])
    values = {
        "CMAKE_BUILD_TYPE": "Release", "CMAKE_EXPORT_COMPILE_COMMANDS": "ON",
        "CMAKE_SYSTEM_NAME": "Linux", "CMAKE_SYSTEM_PROCESSOR": profile["processor"],
        "CMAKE_SYSROOT": musl["sysroot"], "CMAKE_C_COMPILER": cc, "CMAKE_CXX_COMPILER": cxx,
        "CMAKE_ASM_COMPILER": cc, "CMAKE_AR": ar, "CMAKE_RANLIB": ranlib,
        "CMAKE_C_COMPILER_TARGET": profile["triple"], "CMAKE_CXX_COMPILER_TARGET": profile["triple"],
        "CMAKE_ASM_COMPILER_TARGET": profile["triple"],
        "CMAKE_C_FLAGS": flags, "CMAKE_CXX_FLAGS": flags, "CMAKE_ASM_FLAGS": flags,
        "LLVM_CMAKE_DIR": str(sdk / "lib/cmake/llvm"), "COMPILER_RT_OUTPUT_DIR": str(build),
        "COMPILER_RT_DEFAULT_TARGET_ONLY": "ON", "COMPILER_RT_BUILD_CRT": "ON",
        "COMPILER_RT_EXCLUDE_ATOMIC_BUILTIN": "OFF", "COMPILER_RT_BUILTINS_ENABLE_PIC": "ON",
    }
    # Dedicated upstream builtins CMake itself selects STATIC_LIBRARY checks.
    # This setting is never propagated into libc++abi's symbol/link probes.
    return ["cmake", "-G", "Ninja", "-S", str(source / "compiler-rt/lib/builtins"), "-B", str(build),
            *["-D" + key + "=" + value for key, value in values.items()]]


def check_cache(text: str, isa: str, musl: dict, build: Path) -> None:
    values = dict(re.findall(r"^([^#/\n][^:\n]*):[^=\n]*=(.*)$", text, re.M))
    expected = {"CMAKE_SYSTEM_NAME": "Linux", "CMAKE_SYSROOT": musl["sysroot"],
                "COMPILER_RT_DEFAULT_TARGET_ONLY": "ON", "COMPILER_RT_BUILD_CRT": "ON",
                "COMPILER_RT_EXCLUDE_ATOMIC_BUILTIN": "OFF", "COMPILER_RT_BUILTINS_ENABLE_PIC": "ON",
                "COMPILER_RT_OUTPUT_DIR": str(build),
                **{key: PROFILES[isa]["triple"] for key in
                   ["CMAKE_C_COMPILER_TARGET", "CMAKE_CXX_COMPILER_TARGET", "CMAKE_ASM_COMPILER_TARGET"]}}
    for key, value in expected.items():
        if values.get(key) != value: raise InventoryError("original full builtins/CRT profile differs: " + key)


def select_units(rows: list[dict], source: Path, build: Path, isa: str, musl: dict) -> list[dict]:
    units, outputs = [], set()
    for number, row in enumerate(rows):
        args = row.get("arguments") or shlex.split(row["command"])
        frontend_path = Path(os.path.abspath(Path(row["directory"]) / row["file"]))
        path = Path(row.get("original_file", frontend_path)).resolve()
        output = dependency.base.output_of(row)
        if not path.is_relative_to(source / "compiler-rt") or not output.is_relative_to(build):
            raise InventoryError("original compiler-rt source/output escaped declared source/build roots")
        if output in outputs: raise InventoryError("original source output has duplicate producers")
        outputs.add(output)
        targets = [arg.split("=", 1)[1] for arg in args if arg.startswith(("--target=", "-target="))]
        targets += [args[n + 1] for n, arg in enumerate(args[:-1]) if arg in {"--target", "-target"}]
        if not targets or any(target != PROFILES[isa]["triple"] for target in targets):
            raise InventoryError("original target source frontend differs")
        if "--sysroot=" + musl["sysroot"] not in args or musl["headers"] not in args:
            raise InventoryError("original target musl header/sysroot inputs absent")
        if "-ffast-math" in args: raise InventoryError("original compiler-helper FP contract was changed")
        if isa == "riscv64":
            for prefix, wanted in [("-march=", "-march=rv64gc"), ("-mabi=", "-mabi=lp64d")]:
                if wanted not in args or any(a.startswith(prefix) and a != wanted for a in args):
                    raise InventoryError("original RV64GC LP64D helper context changed")
        if row.get("original_file") and frontend_path.is_file() and info(frontend_path)["sha256"] != info(path)["sha256"]:
            raise InventoryError("generated source bytes differ from original upstream source")
        units.append({"id": "original-helper-unit-" + str(number), "kind": "clang", "source": str(path.relative_to(source)),
                      "role": "runtime", "source_kind": "assembly" if path.suffix in {".s", ".S"} else "c",
                      "original_source": info(path), "frontend_source_path": str(frontend_path),
                      "source_generator": row.get("source_generator"),
                      "argv": args, "directory": row["directory"], "native_output": str(output)})
    names = {Path(u["source"]).name for u in units}
    required = {"muldc3.c", "mulsc3.c", "crtbegin.c", "crtend.c", "atomic.c"}
    required |= {"mulxc3.c"} if isa == "x86_64" else {"addtf3.c", "multf3.c", "divtf3.c"}
    if not required <= names: raise InventoryError("configured original helper/CRT graph lost required sources: " + str(sorted(required - names)))
    return units


def target_outputs(text: str, build: Path) -> list[Path]:
    outputs = []
    for line in text.splitlines():
        parts = line.rsplit(": ", 1)
        if len(parts) != 2 or parts[1] == "phony":
            continue
        name = parts[0]
        path = build / name
        if ("libclang_rt.builtins" in path.name and path.suffix == ".a") or ("clang_rt.crt" in path.name and path.suffix == ".o"):
            path = path.resolve()
            if not path.is_relative_to(build): raise InventoryError("original compiler-rt output is outside new build")
            if path not in outputs: outputs.append(path)
    if sum(p.suffix == ".a" for p in outputs) != 1 or sum(p.suffix == ".o" for p in outputs) != 2:
        raise InventoryError("complete original builtin archive/CRT output graph absent")
    return outputs


def complete_source_rows(rows: list[dict], text: str, build: Path) -> list[dict]:
    """Include upstream custom CRT producers and bind every evaluated command."""
    by_output = {dependency.base.output_of(row): dict(row) for row in rows}
    if len(by_output) != len(rows):
        raise InventoryError("compile database has duplicate original source outputs")
    observed, generators = set(), {}
    for line in text.splitlines():
        args = shlex.split(line)
        if len(args) >= 4 and args[0] == "cd" and args[2] == "&&":
            if Path(args[1]).resolve() != build:
                raise InventoryError("source generator has undeclared working directory")
            args = args[3:]
        if len(args) == 5 and args[1:3] in [["-E", "create_symlink"], ["-E", "copy"]]:
            target = Path(os.path.abspath(build / args[4]))
            if target in generators:
                raise InventoryError("generated source has multiple producers")
            generators[target] = {"argv": args, "original": str((build / args[3]).resolve())}
    for line in text.splitlines():
        args = shlex.split(line)
        if "-c" not in args or "-o" not in args:
            continue
        directory = build
        prefix = []
        if len(args) >= 4 and args[0] == "cd" and args[2] == "&&":
            directory = Path(args[1]).resolve()
            prefix, args = args[:3], args[3:]
        if directory != build or any(t in args for t in ["&&", ";", "||", "|", ">", "<"]):
            raise InventoryError("custom compiler producer has unsupported shell/cwd semantics")
        if args.count("-c") != 1 or args.count("-o") != 1:
            raise InventoryError("custom compiler source/output is ambiguous")
        output = (directory / args[args.index("-o") + 1]).resolve()
        if output in observed:
            raise InventoryError("expanded source output has multiple producers")
        observed.add(output)
        source = args[args.index("-c") + 1]
        row = by_output.get(output)
        if row is not None:
            old_args = row.get("arguments") or shlex.split(row["command"])
            if dependency.without_dependency_outputs(args) != dependency.without_dependency_outputs(old_args):
                raise InventoryError("expanded compiler source behavior differs from compile database")
            row["compile_database_argv"] = old_args
        else:
            row = {"file": source, "directory": str(directory), "custom_producer": True}
            by_output[output] = row
        row["arguments"] = args
        row["expanded_shell_prefix"] = prefix
        generated = generators.get(Path(os.path.abspath(directory / source)))
        if generated:
            row["original_file"] = generated["original"]
            row["source_generator"] = generated
    if observed != set(by_output):
        raise InventoryError("complete expanded graph omitted original compile database producers")
    return list(by_output.values())


def inventory(source: Path, build: Path, capture: Path, isa: str, output: Path, after: bool) -> dict:
    config = json.loads((build / "provider-configuration.json").read_text())
    if config["isa"] != isa or source_identity(source) != config["source"]:
        raise InventoryError("original source bytes/profile changed after configuration")
    musl = dependency.verify_musl(Path(config["musl"]["receipt"]["path"]), isa)
    if musl != config["musl"]: raise InventoryError("source-built musl inputs changed")
    if config.get("linux_uapi") and verify_linux_uapi(Path(config["linux_uapi"]["receipt"]["path"])) != config["linux_uapi"]:
        raise InventoryError("authentic Linux UAPI inputs changed")
    check_cache((build / "CMakeCache.txt").read_text(), isa, musl, build)
    evidence = build / "provider-evidence" / output.stem
    targets = command(["ninja", "-C", str(build), "-t", "targets", "all"], build, evidence / "all-targets")
    if targets["exit_code"]: raise InventoryError("original configured output graph unavailable")
    roots = target_outputs(Path(targets["stdout"]["path"]).read_text(), build)
    commands = command(["ninja", "-C", str(build), "-t", "commands", "builtins", "crt"], build, evidence / "expanded-commands")
    if commands["exit_code"]: raise InventoryError("original complete source command graph unavailable")
    rows = complete_source_rows(json.loads((build / "compile_commands.json").read_text()),
                                Path(commands["stdout"]["path"]).read_text(), build)
    units = select_units(rows, source, build, isa, musl)
    for unit, row in zip(units, rows):
        unit["expanded_shell_prefix"] = row["expanded_shell_prefix"]
        unit["compile_database_argv"] = row.get("compile_database_argv")
        unit["custom_producer"] = row.get("custom_producer", False)
    scope, session = dependency.worker_scope(capture)
    events = [json.loads(p.read_text()) for p in sorted((capture / "events").glob("*.json"))]
    production = [e for e in events if e.get("kind") == "clang" and e.get("build_step", {}).get("name") == "build-original-provider"]
    issues, blockers = [], []
    for unit in units:
        matched = [e for e in production if e.get("expanded_argv") == unit["argv"][1:] and Path(e["cwd"]).resolve() == Path(unit["directory"]).resolve()]
        unit["invocation_ids"] = [e["id"] for e in matched]
        if after and (len(matched) != 1 or matched[0]["exit_code"]): issues.append("missing/ambiguous/failed original producer: " + unit["id"])
        path = Path(unit["native_output"])
        if path.is_file(): unit["native_output_artifact"] = info(path)
        elif after: issues.append("required source object absent: " + str(path))
        if unit["source_kind"] == "assembly": blockers.append("required original source assembly has no O-core importer: " + unit["source"])
    if after and len(production) != len(units): issues.append("whole configured source occurrence count differs")
    archives = []
    for path in roots:
        if after and not path.is_file(): issues.append("required original helper/CRT output absent: " + str(path))
        if path.suffix == ".a":
            query = command(["ninja", "-C", str(build), "-t", "query", str(path.relative_to(build))], build, evidence / "archive-query")
            objects = dependency.base.query_objects(Path(query["stdout"]["path"]).read_text(), build)
            producers = {Path(u["native_output"]): u for u in units}
            if any(p not in producers for p in objects): raise InventoryError("archive has unowned original source object")
            members = scope["native_archive_members"](path) if path.is_file() else []
            if after and not dependency.base.archive_matches([producers[p] for p in objects], members): issues.append("actual whole helper archive member order/content differs")
            archives.append({"output": info(path) if path.is_file() else {"path": str(path)}, "objects": [str(p) for p in objects], "members": members, "query": query})
    deps = command(["ninja", "-C", str(build), "-t", "deps"], build, evidence / "dependencies")
    records, owner = [], None
    for line in Path(deps["stdout"]["path"]).read_text().splitlines():
        if line and not line.startswith(" ") and ": #deps " in line: owner = line.split(": #deps ", 1)[0]
        if line.startswith("    "):
            path = Path(line.strip());path = path if path.is_absolute() else build / path
            if path.is_file(): records.append({"native_output": owner, "dependency": info(path)})
    value = {"schema": "ocore-runtime-unit-inventory-v1", "complete": not issues,
             "units": [{k: u[k] for k in ["id", "kind", "source", "role", "invocation_ids"]} | {"build_step": "build-original-provider"} for u in units],
             "runtime_outputs": [info(p) for p in roots if p.is_file()], "non_lowering_units": [],
             "scope": "whole original configured target compiler-rt builtins and CRT; configure evidence retained",
             "original_units": units, "original_archives": archives, "source": config["source"], "musl": musl,
             "configuration": info(build / "provider-configuration.json"), "expanded_commands": commands,
             "build_graph_artifacts": [info(build / n) for n in ["compile_commands.json", "build.ninja", "CMakeCache.txt"]],
             "generated_headers": [info(p) for p in sorted(build.rglob("*.h")) if p.is_file()],
             "original_dependencies": records, "dependency_query": deps, "inventory_helper": info(Path(__file__)),
             "issues": issues, "lowering_blockers": blockers, "source_assembly_lowered": False,
             "whole_provider_ocore_complete": False, "dependency_closure_complete": False,
             "full_rust_runtime_complete": False, "native_ostadix_platform_qualified": False}
    write(output, value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["configure", "inventory"])
    for key in ["source", "build", "capture"]: parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--isa", choices=PROFILES, required=True)
    parser.add_argument("--expected-helper-sha256", required=True)
    for key in ["cc", "cxx", "ar", "ranlib"]: parser.add_argument("--" + key)
    parser.add_argument("--output", type=Path);parser.add_argument("--after-build", action="store_true")
    args = parser.parse_args()
    if info(Path(__file__))["sha256"] != args.expected_helper_sha256: raise InventoryError("source-capture helper differs from frozen recipe bytes")
    source, build, capture = args.source.resolve(), args.build.resolve(), args.capture.resolve()
    if args.action == "configure":
        musl = dependency.verify_musl(Path(os.environ["OCORE_LIBUNWIND_MUSL_PROVENANCE"]), args.isa)
        sdk = Path(os.environ["OCORE_COMPILER_RT_SDK"]).resolve()
        uapi = verify_linux_uapi(Path(os.environ["OCORE_COMPILER_RT_LINUX_UAPI"])) if os.environ.get("OCORE_COMPILER_RT_LINUX_UAPI") else None
        if uapi and args.isa != "riscv64": raise InventoryError("RISC-V Linux UAPI was selected for another ISA")
        config = {"schema": "ocore-original-compiler-rt-configuration-v1", "source": source_identity(source), "musl": musl,
                  "linux_uapi": uapi,
                  "isa": args.isa, "helper": info(Path(__file__)), "dependency_helper": info(Path(dependency.__file__)),
                  "sdk_llvm_config": info(sdk / "lib/cmake/llvm/LLVMConfig.cmake"),
                  "whole_provider_ocore_complete": False, "dependency_closure_complete": False,
                  "full_rust_runtime_complete": False, "native_ostadix_platform_qualified": False}
        write(build / "provider-configuration.json", config)
        row = command(cmake_argv(source, build, args.isa, musl, sdk, args.cc, args.cxx, args.ar, args.ranlib, uapi), build, build / "provider-evidence/configure")
        config["configure"] = row;write(build / "provider-configuration.json", config)
        return row["exit_code"]
    result = inventory(source, build, capture, args.isa, args.output or build / "unit-inventory.json", args.after_build)
    print(json.dumps({"units": len(result["units"]), "issues": result["issues"]}))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (InventoryError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print("original compiler-rt capture error: " + str(error), file=__import__("sys").stderr)
        raise SystemExit(1)
