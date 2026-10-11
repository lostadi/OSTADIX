#!/usr/bin/env python3
"""Whole original threaded libc++abi, with separately source-built providers.

The native archive is reference evidence. This helper never admits supplied
objects as O-core implementations and never disables original threads or TLS.
"""
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

CRT_HELPER_SHA = "4060675327c31ca3bac285a81fc9f85bdcbe6708f07ca3ed69775e27ee81be6f"
LLVM_COMMIT = "dcc3606807c989700e0ac1cac18c31741bcd40d9"
SOURCES = {
    "abort_message.cpp", "cxa_aux_runtime.cpp", "cxa_default_handlers.cpp",
    "cxa_demangle.cpp", "cxa_exception.cpp", "cxa_exception_storage.cpp",
    "cxa_guard.cpp", "cxa_handlers.cpp", "cxa_personality.cpp", "cxa_thread_atexit.cpp",
    "cxa_vector.cpp", "cxa_virtual.cpp", "fallback_malloc.cpp", "private_typeinfo.cpp",
    "stdlib_exception.cpp", "stdlib_new_delete.cpp", "stdlib_stdexcept.cpp", "stdlib_typeinfo.cpp",
}


def load_dependency():
    path = Path(__file__).with_name("compiler_rt_capture.py")
    if hashlib.sha256(path.read_bytes()).hexdigest() != CRT_HELPER_SHA:
        raise ValueError("frozen prerequisite inventory helper changed")
    spec = importlib.util.spec_from_file_location("ocore_original_cxxabi_prerequisites", path)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


crt = load_dependency()
dep = crt.dependency
info, write, command = dep.info, dep.write, dep.command
InventoryError, PROFILES = dep.InventoryError, dep.PROFILES
FALSE_GATES = {name: False for name in ["whole_provider_ocore_complete", "dependency_closure_complete",
                                      "full_rust_runtime_complete", "native_ostadix_platform_qualified",
                                      "native_all_three_eh_qualified"]}


def check_artifact(row: dict) -> dict:
    actual = info(Path(row["path"]))
    if any(actual[key] != row[key] for key in ["path", "bytes", "sha256"]):
        raise InventoryError("source-owned input/output bytes changed: " + row["path"])
    return actual


def source_identity(source: Path) -> dict:
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip() != LLVM_COMMIT:
        raise InventoryError("LLVM provider source revision differs")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True):
        raise InventoryError("LLVM provider source was changed")
    names = subprocess.check_output(["git", "ls-files", "-z", "libcxxabi", "libcxx", "libunwind", "runtimes", "cmake"], cwd=source).split(b"\0")
    return {"path": str(source), "revision": LLVM_COMMIT, "clean": True,
            "files": [info(source / os.fsdecode(p)) for p in names if p]}


def verify_provider(path: Path, isa: str, kind: str, expected_sha256: str | None = None) -> dict:
    """Bind exact original producer outputs, not merely archive bytes to themselves."""
    if expected_sha256 is not None and info(path)["sha256"] != expected_sha256:
        raise InventoryError("prerequisite inventory differs from pinned recipe digest")
    value = json.loads(path.read_text())
    if not value["complete"] or value["issues"] or value["source"]["revision"] != LLVM_COMMIT:
        raise InventoryError("prerequisite original whole source build is incomplete")
    for row in value["source"]["files"] + value["runtime_outputs"] + value["generated_headers"] + value["build_graph_artifacts"]:
        check_artifact(row)
    configuration = check_artifact(value["configuration"])
    config = json.loads(Path(configuration["path"]).read_text())
    if config["isa"] != isa:
        raise InventoryError("prerequisite target differs")
    if kind == "unwind":
        if config["profile"] != "linux_musl_threaded":
            raise InventoryError("threaded original Linux/musl unwinder required")
        if len(value["original_units"]) != 9:
            raise InventoryError("original unwinder source graph is incomplete")
    elif kind != "compiler_rt":
        raise InventoryError("unknown prerequisite profile")
    capture = Path(config["configure"]["argv"][config["configure"]["argv"].index("-B") + 1]).parent / "capture"
    events = [json.loads(p.read_text()) for p in sorted((capture / "events").glob("*.json"))]
    by_id = {row["id"]: row for row in events}
    for unit in value["original_units"]:
        native = check_artifact(unit["native_output_artifact"])
        producers = [by_id[i] for i in unit["invocation_ids"] if i in by_id]
        if len(producers) != 1 or producers[0]["exit_code"] != 0:
            raise InventoryError("original source producer is missing/ambiguous/failed")
        if not any(all(output.get(k) == native[k] for k in ["path", "bytes", "sha256"])
                   for output in producers[0].get("outputs", [])):
            raise InventoryError("source producer output digest differs from prerequisite object")
        check_artifact(unit["original_source"])
        for captured in producers[0].get("units", []):
            check_artifact(captured["ir"])
    artifacts = [check_artifact(row) for row in value["runtime_outputs"]]
    required = {"libunwind.a"} if kind == "unwind" else {
        f"libclang_rt.builtins-{isa}.a", f"clang_rt.crtbegin-{isa}.o", f"clang_rt.crtend-{isa}.o"}
    if {Path(row["path"]).name for row in artifacts} != required:
        raise InventoryError("whole prerequisite output roots differ")
    return {"inventory": info(path), "configuration": configuration, "isa": isa, "kind": kind,
            "runtime_outputs": artifacts, "source_revision": LLVM_COMMIT, **FALSE_GATES}


def stage_inputs(build: Path, musl: dict, compiler_rt: dict, sdk: Path) -> dict:
    """A fresh symlink overlay preserves all authenticated original input bytes."""
    sysroot, resource = build / "target-sysroot", build / "clang-resource"
    (sysroot / "usr").mkdir(parents=True, exist_ok=False)
    (sysroot / "usr/include").symlink_to(musl["headers"], target_is_directory=True)
    (sysroot / "include").symlink_to(musl["headers"], target_is_directory=True)
    (sysroot / "lib").symlink_to(musl["library_dir"], target_is_directory=True)
    (sysroot / "usr/lib").symlink_to(musl["library_dir"], target_is_directory=True)
    original_resource = Path(subprocess.check_output([str(sdk / "bin/clang"), "-print-resource-dir"], text=True).strip())
    (resource / "lib").mkdir(parents=True)
    (resource / "include").symlink_to(original_resource / "include", target_is_directory=True)
    library_dirs = {str(Path(row["path"]).parent) for row in compiler_rt["runtime_outputs"]}
    if len(library_dirs) != 1:
        raise InventoryError("original helper/CRT roots use different resource directories")
    (resource / "lib/linux").symlink_to(next(iter(library_dirs)), target_is_directory=True)
    return {"sysroot": str(sysroot), "resource": str(resource), "original_sdk_resource": str(original_resource),
            "source_built_library_dir": next(iter(library_dirs)), **FALSE_GATES}


def cmake_argv(source: Path, build: Path, capture: Path, isa: str, musl: dict,
               staged: dict, cc: str, cxx: str, ar: str, ranlib: str) -> list[str]:
    profile = PROFILES[isa]
    flags = ["-nostdlibinc", "-isystem", musl["headers"], *profile["flags"],
             "-resource-dir=" + staged["resource"], "--rtlib=compiler-rt", "--unwindlib=none",
             "-Qunused-arguments", "-fno-pie"]
    values = {
        "LLVM_ENABLE_RUNTIMES": "libunwind;libcxxabi;libcxx", "LLVM_DEFAULT_TARGET_TRIPLE": profile["triple"],
        "LLVM_ENABLE_PER_TARGET_RUNTIME_DIR": "OFF", "CMAKE_BUILD_TYPE": "Release", "CMAKE_EXPORT_COMPILE_COMMANDS": "ON",
        "CMAKE_SYSTEM_NAME": "Linux", "CMAKE_SYSTEM_PROCESSOR": profile["processor"],
        "CMAKE_SYSROOT": staged["sysroot"], "CMAKE_TRY_COMPILE_TARGET_TYPE": "EXECUTABLE",
        "CMAKE_C_COMPILER": cc, "CMAKE_CXX_COMPILER": cxx, "CMAKE_ASM_COMPILER": cc,
        "CMAKE_C_COMPILER_TARGET": profile["triple"], "CMAKE_CXX_COMPILER_TARGET": profile["triple"],
        "CMAKE_ASM_COMPILER_TARGET": profile["triple"], "CMAKE_AR": ar, "CMAKE_RANLIB": ranlib,
        "CMAKE_C_FLAGS": shlex.join(flags), "CMAKE_CXX_FLAGS": shlex.join([*flags, "-nostdlib++"]),
        "CMAKE_ASM_FLAGS": shlex.join(flags), "CMAKE_EXE_LINKER_FLAGS": shlex.join([
            "-fuse-ld=lld", "-static", "-no-pie", "-Wl,--eh-frame-hdr"]),
        "RUNTIMES_USE_LIBC": "system", "LLVM_INCLUDE_DOCS": "OFF", "LLVM_INCLUDE_TESTS": "OFF",
        "LIBCXXABI_ENABLE_SHARED": "OFF", "LIBCXXABI_ENABLE_STATIC": "ON", "LIBCXXABI_ENABLE_EXCEPTIONS": "ON",
        "LIBCXXABI_ENABLE_THREADS": "ON", "LIBCXXABI_HAS_PTHREAD_API": "ON", "LIBCXXABI_USE_LLVM_UNWINDER": "ON",
        "LIBCXXABI_USE_COMPILER_RT": "ON", "LIBCXXABI_ENABLE_STATIC_UNWINDER": "ON",
        "LIBCXXABI_STATICALLY_LINK_UNWINDER_IN_STATIC_LIBRARY": "OFF", "LIBCXXABI_ENABLE_NEW_DELETE_DEFINITIONS": "ON",
        "LIBCXXABI_BAREMETAL": "OFF", "LIBCXXABI_SILENT_TERMINATE": "OFF", "LIBCXXABI_NON_DEMANGLING_TERMINATE": "OFF",
        "LIBCXXABI_ENABLE_ASSERTIONS": "ON", "LIBUNWIND_ENABLE_STATIC": "ON", "LIBUNWIND_ENABLE_SHARED": "OFF",
        "LIBUNWIND_ENABLE_THREADS": "ON", "LIBUNWIND_IS_BAREMETAL": "OFF", "LIBUNWIND_WEAK_PTHREAD_LIB": "OFF",
        "LIBUNWIND_ENABLE_FRAME_APIS": "ON", "LIBUNWIND_USE_COMPILER_RT": "ON",
        "LIBCXX_ENABLE_SHARED": "OFF", "LIBCXX_ENABLE_STATIC": "ON", "LIBCXX_CXX_ABI": "libcxxabi",
        "LIBCXX_ENABLE_EXCEPTIONS": "ON", "LIBCXX_ENABLE_RTTI": "ON", "LIBCXX_ENABLE_THREADS": "ON",
        "LIBCXX_HAS_PTHREAD_API": "ON", "LIBCXX_HAS_MUSL_LIBC": "ON",
    }
    return ["cmake", "-G", "Ninja", "-S", str(source / "runtimes"), "-B", str(build),
            *["-D" + k + "=" + v for k, v in values.items()]]


def check_cache(text: str, isa: str, staged: dict) -> None:
    values = dict(re.findall(r"^([^#/\n][^:\n]*):[^=\n]*=(.*)$", text, re.M))
    expected = {"CMAKE_TRY_COMPILE_TARGET_TYPE": "EXECUTABLE", "CMAKE_SYSTEM_NAME": "Linux",
                "CMAKE_SYSROOT": staged["sysroot"], "LIBCXXABI_ENABLE_THREADS": "ON",
                "LIBCXXABI_ENABLE_EXCEPTIONS": "ON", "LIBCXXABI_ENABLE_STATIC": "ON", "LIBCXXABI_ENABLE_SHARED": "OFF",
                "LIBCXXABI_BAREMETAL": "OFF", "LIBCXXABI_USE_LLVM_UNWINDER": "ON", "LIBCXXABI_USE_COMPILER_RT": "ON",
                "LIBCXXABI_ENABLE_NEW_DELETE_DEFINITIONS": "ON", "LIBCXXABI_STATICALLY_LINK_UNWINDER_IN_STATIC_LIBRARY": "OFF",
                "LIBCXX_ENABLE_THREADS": "ON", "LIBCXX_ENABLE_EXCEPTIONS": "ON", "LIBCXX_ENABLE_RTTI": "ON",
                "LIBCXX_HAS_MUSL_LIBC": "ON", "LIBUNWIND_ENABLE_THREADS": "ON"}
    expected.update({k: PROFILES[isa]["triple"] for k in ["CMAKE_C_COMPILER_TARGET", "CMAKE_CXX_COMPILER_TARGET", "CMAKE_ASM_COMPILER_TARGET"]})
    for key, value in expected.items():
        if values.get(key) != value: raise InventoryError("original full libc++abi profile differs: " + key)
    if values.get("LIBCXXABI_HAS_CXA_THREAD_ATEXIT_IMPL", "").lower() not in {"", "0", "false", "off"}:
        raise InventoryError("original musl fallback incorrectly replaced by unavailable __cxa_thread_atexit_impl")


def select_units(rows: list[dict], objects: list[Path], source: Path, build: Path, isa: str,
                 musl: dict, staged: dict) -> list[dict]:
    by_output = {dep.base.output_of(row): row for row in rows}
    if len(by_output) != len(rows): raise InventoryError("configured source outputs have duplicate producers")
    units = []
    for n, output in enumerate(objects):
        if output not in by_output: raise InventoryError("original archive member has no source producer")
        row = by_output[output];path = (Path(row["directory"]) / row["file"]).resolve()
        if not path.is_relative_to(source / "libcxxabi/src") or not output.is_relative_to(build):
            raise InventoryError("original libc++abi source/output escaped declared roots")
        args = row.get("arguments") or shlex.split(row["command"])
        if "--target=" + PROFILES[isa]["triple"] not in args or "--sysroot=" + staged["sysroot"] not in args:
            raise InventoryError("source target/sysroot differs")
        if musl["headers"] not in args or "-resource-dir=" + staged["resource"] not in args:
            raise InventoryError("source-owned target headers/helpers absent")
        if any(any(bad in arg for bad in ["_LIBCXXABI_HAS_NO_THREADS", "_LIBCXXABI_NO_EXCEPTIONS", "HAVE___CXA_THREAD_ATEXIT_IMPL",
                "-fno-threadsafe-statics", "-fno-exceptions", "-ffast-math"]) for arg in args):
            raise InventoryError("original TLS/thread/exception/FP contract was changed")
        if isa == "riscv64" and any(a.startswith(p) and a != want for a in args for p, want in [("-march=", "-march=rv64gc"), ("-mabi=", "-mabi=lp64d")]):
            raise InventoryError("original RV64GC LP64D context differs")
        units.append({"id": "original-cxxabi-unit-" + str(n), "kind": "clang", "source": str(path.relative_to(source)),
                      "role": "runtime", "original_source": info(path), "native_output": str(output),
                      "argv": args, "directory": row["directory"]})
    if len(units) != len(SOURCES) or {Path(u["source"]).name for u in units} != SOURCES:
        raise InventoryError("whole original configured libc++abi source graph is incomplete or changed")
    # The dependency runtimes are configured for authentic headers, not silently
    # counted as libc++abi source bodies or rebuilt instead of frozen providers.
    return units


def archive_command(text: str, build: Path, objects: list[Path]) -> list[str]:
    flags = {"qc", "Dqc", "qcD"}
    candidates = [line for line in text.splitlines() if "lib/libc++abi.a" in shlex.split(line) and flags.intersection(shlex.split(line))]
    if len(candidates) != 1: raise InventoryError("original final archive producer missing/ambiguous")
    tokens = shlex.split(candidates[0])
    positions = [n for n, token in enumerate(tokens) if token in flags]
    if len(positions) != 1: raise InventoryError("original archive flags ambiguous")
    marker = positions[0]
    if marker == 0 or Path(tokens[marker - 1]).name not in {"ar", "llvm-ar"}:
        raise InventoryError("original archive producer is not the declared archiver")
    if tokens[marker + 1] != "lib/libc++abi.a": raise InventoryError("original archive producer target differs")
    actual = []
    for token in tokens[marker + 2:]:
        if token == "&&": break
        actual.append((build / token).resolve())
    if actual != objects: raise InventoryError("original archive command member order differs from declared graph")
    # Execute this exact upstream-generated shell line; do not manufacture an
    # archive command or omit any original object. Parent approved this adapter
    # so frozen libunwind need not be rebuilt via CMake's target dependency.
    return ["/bin/sh", "-c", candidates[0]]


def graph(source: Path, build: Path, isa: str, musl: dict, staged: dict, evidence: Path) -> tuple[list[dict], dict, list[str]]:
    query = command(["ninja", "-C", str(build), "-t", "query", "lib/libc++abi.a"], build, evidence / "archive-query")
    if query["exit_code"]: raise InventoryError("original whole archive graph unavailable")
    objects = dep.base.query_objects(Path(query["stdout"]["path"]).read_text(), build)
    rows = json.loads((build / "compile_commands.json").read_text())
    units = select_units(rows, objects, source, build, isa, musl, staged)
    expanded = command(["ninja", "-C", str(build), "-t", "commands", "lib/libc++abi.a"], build, evidence / "expanded-commands")
    if expanded["exit_code"]: raise InventoryError("original complete source/archive command graph unavailable")
    text = Path(expanded["stdout"]["path"]).read_text()
    own_compile_lines = [line for line in text.splitlines() if "-c" in shlex.split(line) and any(str(source / u["source"]) in shlex.split(line) for u in units)]
    dep.bind_expanded_commands(units, "\n".join(own_compile_lines), build)
    argv = archive_command(text, build, objects)
    return units, {"query": query, "expanded": expanded}, argv


def inventory(source: Path, build: Path, capture: Path, isa: str, output: Path, after: bool) -> dict:
    config = json.loads((build / "provider-configuration.json").read_text())
    if config["isa"] != isa or source_identity(source) != config["source"]:
        raise InventoryError("original provider source/profile changed")
    musl = dep.verify_musl(Path(config["musl"]["receipt"]["path"]), isa)
    providers = {k: verify_provider(Path(v["inventory"]["path"]), isa, k, v["inventory"]["sha256"]) for k, v in config["providers"].items()}
    if musl != config["musl"] or providers != config["providers"]: raise InventoryError("original provider dependency bytes changed")
    check_cache((build / "CMakeCache.txt").read_text(), isa, config["staged"])
    units, evidence, archive_argv = graph(source, build, isa, musl, config["staged"], build / "provider-evidence" / output.stem)
    scope, _ = dep.worker_scope(capture)
    events = [json.loads(p.read_text()) for p in sorted((capture / "events").glob("*.json"))]
    production = [row for row in events if row.get("kind") == "clang" and row.get("build_step", {}).get("name") == "build-original-provider"]
    issues = []
    for unit in units:
        matches = [row for row in production if row.get("expanded_argv") == unit["argv"][1:] and row["cwd"] == unit["directory"]]
        unit["invocation_ids"] = [row["id"] for row in matches]
        native = Path(unit["native_output"])
        if native.is_file(): unit["native_output_artifact"] = info(native)
        if after and (len(matches) != 1 or matches[0]["exit_code"] or not native.is_file()):
            issues.append("required original source producer missing/ambiguous/failed: " + unit["id"])
        elif after and not any(all(row.get(k) == unit["native_output_artifact"][k] for k in ["path", "bytes", "sha256"]) for row in matches[0]["outputs"]):
            issues.append("required source object differs from original captured producer digest: " + unit["id"])
    if after and len(production) != len(units): issues.append("original whole production source occurrence count differs")
    archive = build / "lib/libc++abi.a"
    members = scope["native_archive_members"](archive) if archive.is_file() else []
    if after and (not archive.is_file() or not dep.base.archive_matches(units, members)):
        issues.append("original full archive member order/content differs")
    deps = command(["ninja", "-C", str(build), "-t", "deps"], build, build / "provider-evidence" / output.stem / "dependencies")
    dependency_rows, owners, owner = [], set(), None
    if deps["exit_code"]: issues.append("original dependency query failed")
    for line in Path(deps["stdout"]["path"]).read_text().splitlines():
        if line and not line.startswith(" ") and ": #deps " in line:
            owner = line.split(": #deps ", 1)[0];owners.add((build / owner).resolve())
        elif line.startswith("    "):
            path = Path(line.strip());path = path if path.is_absolute() else build / path
            if path.is_file(): dependency_rows.append({"native_output": owner, "dependency": info(path)})
            else: issues.append("required original dependency file absent: " + str(path))
    if after and not {Path(u["native_output"]) for u in units} <= owners:
        issues.append("required original source dependency records missing")
    value = {"schema": "ocore-runtime-unit-inventory-v1", "complete": not issues,
             "units": [{k: u[k] for k in ["id", "kind", "source", "role", "invocation_ids"]} | {"build_step": "build-original-provider"} for u in units],
             "runtime_outputs": [info(archive)] if archive.is_file() else [], "non_lowering_units": [],
             "scope": "all18 original configured threaded Linux/musl libc++abi source bodies and exact original archive command",
             "original_units": units, "archive_members": members, "original_archive_argv": archive_argv,
             "source": config["source"], "musl": musl, "providers": providers, "staged": config["staged"],
             "configuration": info(build / "provider-configuration.json"), "original_graph": evidence,
             "build_graph_artifacts": [info(build / n) for n in ["compile_commands.json", "build.ninja", "CMakeCache.txt"]],
             "generated_headers": [info(p) for p in sorted(build.rglob("*.h")) if p.is_file() and not p.is_relative_to(build / "target-sysroot")],
             "original_dependencies": dependency_rows, "dependency_query": deps, "inventory_helper": info(Path(__file__)),
             "issues": sorted(set(issues)), "lowering_blockers": ["original EH/personality/TLS/atomics/FP/init-fini/provider bodies not yet whole-lowered"],
             "compiled_libcxx_standard_library_complete": False, "source_built_reference_only": True, **FALSE_GATES}
    write(output, value);return value


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["configure", "inventory", "archive"])
    for key in ["source", "build", "capture"]: p.add_argument("--" + key, type=Path, required=True)
    p.add_argument("--isa", choices=PROFILES, required=True);p.add_argument("--expected-helper-sha256", required=True)
    for key in ["cc", "cxx", "ar", "ranlib"]: p.add_argument("--" + key)
    p.add_argument("--unwind-sha256");p.add_argument("--compiler-rt-sha256")
    p.add_argument("--output", type=Path);p.add_argument("--after-build", action="store_true")
    args = p.parse_args()
    if info(Path(__file__))["sha256"] != args.expected_helper_sha256: raise InventoryError("recipe helper bytes differ")
    source, build, capture = args.source.resolve(), args.build.resolve(), args.capture.resolve()
    if args.action == "configure":
        musl = dep.verify_musl(Path(os.environ["OCORE_LIBUNWIND_MUSL_PROVENANCE"]), args.isa)
        if not args.unwind_sha256 or not args.compiler_rt_sha256: raise InventoryError("exact prerequisite inventory digests required")
        providers = {kind: verify_provider(Path(os.environ[var]), args.isa, kind, sha) for kind, var, sha in [
            ("unwind", "OCORE_CXXABI_UNWIND_INVENTORY", args.unwind_sha256),
            ("compiler_rt", "OCORE_CXXABI_COMPILER_RT_INVENTORY", args.compiler_rt_sha256)]}
        sdk = Path(os.environ["OCORE_COMPILER_RT_SDK"]).resolve()
        staged = stage_inputs(build, musl, providers["compiler_rt"], sdk)
        config = {"schema": "ocore-original-libcxxabi-configuration-v1", "profile": "linux_musl_threaded_full",
                  "isa": args.isa, "source": source_identity(source), "musl": musl, "providers": providers,
                  "staged": staged, "helper": info(Path(__file__)), **FALSE_GATES}
        write(build / "provider-configuration.json", config)
        row = command(cmake_argv(source, build, capture, args.isa, musl, staged, args.cc, args.cxx, args.ar, args.ranlib), build, build / "provider-evidence/configure")
        config["configure"] = row;write(build / "provider-configuration.json", config);return row["exit_code"]
    if args.action == "archive":
        config = json.loads((build / "provider-configuration.json").read_text())
        _, _, argv = graph(source, build, args.isa, config["musl"], config["staged"], build / "provider-evidence/archive")
        row = command(argv, build, build / "provider-evidence/original-final-archive")
        return row["exit_code"]
    result = inventory(source, build, capture, args.isa, args.output or build / "unit-inventory.json", args.after_build)
    print(json.dumps({"units": len(result["units"]), "issues": result["issues"]}));return 0 if result["complete"] else 1


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (InventoryError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print("original libc++abi capture error: " + str(error), file=__import__("sys").stderr);raise SystemExit(1)
