#!/usr/bin/env python3
"""Source-owned LLVM libunwind configuration and diagnostic build inventory.

This tool never admits native objects as O-core implementations.  In particular,
the original assembly and every unresolved platform service remain requirements.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile

LLVM_COMMIT = "dcc3606807c989700e0ac1cac18c31741bcd40d9"
CAPTURE_WORKER_SHA = "4eedaad775ad6283547a0204d01c644822fef0be4fd99d6441384476c97f4777"
HEADER_SHA = "5c90e34938803a087deba5f79417076a71193e4d60c451a26211abbf24190ab9"
KEYRING_SHA = "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31"
SOURCE_ARCHIVES = {
    "newlib_4.6.0.20260123-1.dsc": "54c3169ab4c2580dbfef5d251cd043670beba897fd3723d1a26bcf3d515fa469",
    "newlib_4.6.0.20260123.orig.tar.xz": "a6b78ce7b9a3ac1da104b039f8456ed3277c97d10f3872996e3f63ffa5e85bf9",
    "newlib_4.6.0.20260123-1.debian.tar.xz": "2b68103bdbbbd815b52cbdd473eee21ed271e74393828a1d11de4648af47355c",
}
ISAS = {
    "x86_64": {"triple": "x86_64-unknown-none", "processor": "x86_64", "flags": [],
               "context": 21, "cursor": 33},
    "aarch64": {"triple": "aarch64-unknown-none", "processor": "aarch64", "flags": [],
                "context": 67, "cursor": 79},
    "riscv64": {"triple": "riscv64-unknown-none-elf", "processor": "riscv64",
                "flags": ["-march=rv64gc", "-mabi=lp64d"], "context": 64, "cursor": 76},
}
SOURCE_FLOOR = ["libunwind.cpp", "Unwind-EHABI.cpp", "Unwind-seh.cpp", "UnwindLevel1.c",
                "UnwindLevel1-gcc-ext.c", "Unwind-sjlj.c", "Unwind-wasm.c",
                "UnwindRegistersRestore.S", "UnwindRegistersSave.S"]


class InventoryError(ValueError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def info(path: Path) -> dict:
    path = path.resolve()
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": sha(data)}


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def command(argv: list[str], cwd: Path, prefix: Path, stdin: bytes | None = None) -> dict:
    result = subprocess.run(argv, cwd=cwd, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = prefix.with_suffix(".stdout"), prefix.with_suffix(".stderr")
    stdout.parent.mkdir(parents=True, exist_ok=True)
    stdout.write_bytes(result.stdout)
    stderr.write_bytes(result.stderr)
    receipt = {"argv": argv, "cwd": str(cwd.resolve()), "exit_code": result.returncode,
               "stdout": info(stdout), "stderr": info(stderr)}
    write(prefix.with_suffix(".json"), receipt)
    return receipt


def source_identity(source: Path) -> dict:
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if revision != LLVM_COMMIT:
        raise InventoryError("original LLVM commit differs from pinned source")
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"],
                                     cwd=source, text=True)
    if status:
        raise InventoryError("original LLVM source checkout is modified")
    paths = subprocess.check_output(["git", "ls-files", "-z", "libunwind"], cwd=source).split(b"\0")
    files = [info(source / os.fsdecode(item)) for item in paths if item]
    return {"path": str(source.resolve()), "revision": revision, "clean": True, "files": files}


def verify_headers(package_receipt: Path, source_receipt: Path) -> dict:
    package = json.loads(package_receipt.read_text())
    origin = json.loads(source_receipt.read_text())
    archive = Path(package["package_archive"]["path"])
    if info(archive)["sha256"] != HEADER_SHA or package["package"]["Version"] != "4.6.0.20260123-1":
        raise InventoryError("Newlib header archive/version differs from pinned package")
    keyring = Path(package["trusted_archive_keyring"]["path"])
    release = Path(package["signed_release"]["path"])
    if info(keyring)["sha256"] != KEYRING_SHA or info(release)["sha256"] != package["signed_release"]["sha256"]:
        raise InventoryError("signed package origin/keyring hash mismatch")
    checked = subprocess.run(["gpgv", "--keyring", str(keyring), str(release)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if checked.returncode:
        raise InventoryError("Newlib package origin signature failed")
    record = Path(package["package_record"]["path"])
    if info(record)["sha256"] != package["package_record"]["sha256"]:
        raise InventoryError("package record hash mismatch")
    if f"SHA256: {HEADER_SHA}\n" not in record.read_text():
        raise InventoryError("header archive SHA missing from original package record")
    sources = []
    for item in origin["source_archives"]:
        path = Path(item["path"])
        actual = info(path)
        if SOURCE_ARCHIVES.get(path.name) != actual["sha256"] or item["sha256"] != actual["sha256"]:
            raise InventoryError("original Newlib source archive hash mismatch")
        sources.append(actual)
    if {Path(item["path"]).name for item in sources} != set(SOURCE_ARCHIVES):
        raise InventoryError("original Newlib source archives are incomplete")
    root = Path(package["headers"]).resolve()
    payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(archive)])
    headers = []
    expected = set()
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as tar:
        for entry in tar:
            name = entry.name.removeprefix("./")
            if not name.startswith("usr/include/newlib/") or entry.isdir():
                continue
            relative = name.removeprefix("usr/include/newlib/")
            path = root / relative
            expected.add(relative)
            if entry.issym():
                if not path.is_symlink() or os.readlink(path) != entry.linkname:
                    raise InventoryError(f"original header symlink differs: {relative}")
                headers.append({"path": str(path), "symlink": entry.linkname})
            elif entry.isfile():
                data = tar.extractfile(entry).read()
                actual = info(path)
                if actual["sha256"] != sha(data):
                    raise InventoryError(f"original header bytes differ: {relative}")
                headers.append(actual)
            else:
                raise InventoryError(f"unsupported original header entry: {relative}")
    actual_names = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() or p.is_symlink()}
    if actual_names != expected:
        raise InventoryError("extracted header tree contains missing/extra files")
    return {"package_receipt": info(package_receipt), "source_receipt": info(source_receipt),
            "archive": info(archive), "headers": str(root), "header_files": headers,
            "source_archives": sources, "signed_release": info(release), "keyring": info(keyring),
            "library_source_built": False, "platform_qualified": False}


def cmake_argv(source: Path, build: Path, isa: str, threads: bool, headers: Path,
               cc: str, cxx: str, ar: str, ranlib: str) -> list[str]:
    profile = ISAS[isa]
    flags = shlex.join(["-ffreestanding", "-nostdlibinc", "-isystem", str(headers), *profile["flags"]])
    defines = {
        "LLVM_ENABLE_RUNTIMES": "libunwind", "LLVM_DEFAULT_TARGET_TRIPLE": profile["triple"],
        "LLVM_ENABLE_PER_TARGET_RUNTIME_DIR": "OFF", "CMAKE_BUILD_TYPE": "Release",
        "CMAKE_EXPORT_COMPILE_COMMANDS": "ON", "CMAKE_SYSTEM_NAME": "Generic",
        "CMAKE_SYSTEM_PROCESSOR": profile["processor"], "CMAKE_TRY_COMPILE_TARGET_TYPE": "STATIC_LIBRARY",
        "CMAKE_C_COMPILER": cc, "CMAKE_CXX_COMPILER": cxx, "CMAKE_ASM_COMPILER": cc,
        "CMAKE_C_COMPILER_TARGET": profile["triple"], "CMAKE_CXX_COMPILER_TARGET": profile["triple"],
        "CMAKE_ASM_COMPILER_TARGET": profile["triple"], "CMAKE_AR": ar, "CMAKE_RANLIB": ranlib,
        "CMAKE_C_FLAGS": flags, "CMAKE_CXX_FLAGS": flags, "CMAKE_ASM_FLAGS": flags,
        "LIBUNWIND_ENABLE_STATIC": "ON", "LIBUNWIND_ENABLE_SHARED": "OFF",
        # Generic CMake platforms convert the excluded shared target to static.
        # Give that unbuilt upstream target a distinct name, preserving unwind_static.
        "LIBUNWIND_SHARED_OUTPUT_NAME": "unwind-shared-unbuilt",
        "LIBUNWIND_IS_BAREMETAL": "ON", "LIBUNWIND_ENABLE_CROSS_UNWINDING": "OFF",
        "LIBUNWIND_ENABLE_THREADS": "ON" if threads else "OFF", "LIBUNWIND_ENABLE_ASSERTIONS": "ON",
        "LIBUNWIND_ENABLE_FRAME_APIS": "ON", "RUNTIMES_USE_LIBC": "system",
    }
    return ["cmake", "-G", "Ninja", "-S", str(source / "runtimes"), "-B", str(build),
            *[f"-D{key}={value}" for key, value in defines.items()]]


def output_of(row: dict) -> Path:
    args = row.get("arguments") or shlex.split(row["command"])
    if args.count("-o") != 1:
        raise InventoryError("compile row lacks exact single output")
    return (Path(row["directory"]) / args[args.index("-o") + 1]).resolve()


def query_objects(text: str, build: Path) -> list[Path]:
    objects, in_inputs = [], False
    for line in text.splitlines()[1:]:
        if line.startswith("  input:"):
            in_inputs = True
        elif line.startswith("  outputs:"):
            in_inputs = False
        elif in_inputs and line.startswith("    "):
            item = line.strip()
            if item.endswith((".o", ".obj")) and not item.startswith(("|", "||")):
                objects.append((build / item).resolve())
    if not objects or len(objects) != len(set(objects)):
        raise InventoryError("archive dependency graph lacks unique original object inputs")
    return objects


def select_units(rows: list[dict], objects: list[Path], source: Path, isa: str, threads: bool) -> list[dict]:
    by_output = {}
    for row in rows:
        by_output.setdefault(output_of(row), []).append(row)
    units = []
    for number, output in enumerate(objects):
        candidates = by_output.get(output, [])
        if len(candidates) != 1:
            raise InventoryError(f"archive object has ambiguous/missing compile producer: {output}")
        row = candidates[0]
        path = (Path(row["directory"]) / row["file"]).resolve()
        try:
            relative = str(path.relative_to(source))
        except ValueError as error:
            raise InventoryError("archive source is outside original pinned LLVM tree") from error
        args = row.get("arguments") or shlex.split(row["command"])
        targets = []
        for index, arg in enumerate(args):
            if arg.startswith(("--target=", "-target=")):
                targets.append(arg.split("=", 1)[1])
            elif arg in {"--target", "-target"} and index + 1 < len(args):
                targets.append(args[index + 1])
        if not targets or any(target != ISAS[isa]["triple"] for target in targets):
            raise InventoryError("original compile target differs from declared ISA")
        if path.suffix == ".c" and ("-fexceptions" not in args or "-std=c99" not in args):
            raise InventoryError("original C source exception contract was lost")
        if threads and any("_LIBUNWIND_HAS_NO_THREADS" in arg for arg in args):
            raise InventoryError("threaded profile silently disables original locking")
        if not threads and not any("_LIBUNWIND_HAS_NO_THREADS" in arg for arg in args):
            raise InventoryError("single-thread test profile has mismatching source contract")
        for flag in ISAS[isa]["flags"]:
            if flag not in args:
                raise InventoryError("RV64GC LP64D context contract was lost")
        units.append({"id": f"archive-input-{number:02d}", "kind": "clang", "source": relative,
                      "role": "runtime", "original_source": info(path), "argv": args,
                      "directory": row["directory"], "native_output": str(output),
                      "source_kind": "assembly" if path.suffix == ".S" else "c++" if path.suffix == ".cpp" else "c"})
    missing = set(SOURCE_FLOOR) - {Path(unit["source"]).name for unit in units}
    if missing:
        raise InventoryError(f"configured archive omits required original source units: {sorted(missing)}")
    return units


def macro_integer(values: dict[str, str], name: str, seen: frozenset[str] = frozenset()) -> int:
    if name in seen or name not in values:
        raise InventoryError(f"invalid/cyclic original context macro: {name}")
    def calculate(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name):
            return macro_integer(values, node.id, seen | {name})
        if isinstance(node, ast.BinOp):
            lhs, rhs = calculate(node.left), calculate(node.right)
            if isinstance(node.op, ast.Add):
                return lhs + rhs
            if isinstance(node.op, ast.Sub):
                return lhs - rhs
            if isinstance(node.op, ast.Mult):
                return lhs * rhs
            if isinstance(node.op, ast.Div) and rhs:
                return lhs // rhs
        raise InventoryError(f"unsupported original context macro expression: {name}")
    return calculate(ast.parse(values[name], mode="eval").body)


def check_macros(macros: str, isa: str) -> None:
    values = dict(re.findall(r"^#define\s+(\S+)\s+(.+)$", macros, re.M))
    for name, expected in [("_LIBUNWIND_CONTEXT_SIZE", ISAS[isa]["context"]),
                           ("_LIBUNWIND_CURSOR_SIZE", ISAS[isa]["cursor"])]:
        if macro_integer(values, name) != expected:
            raise InventoryError(f"original {isa} context layout mismatch: {name}")
    if isa == "riscv64":
        for name, expected in [("__riscv_xlen", "64"), ("__riscv_flen", "64"), ("__riscv_float_abi_double", "1")]:
            if values.get(name) != expected:
                raise InventoryError(f"RV64GC LP64D/FLEN64 mismatch: {name}")


def check_cache(text: str, isa: str, threads: bool) -> None:
    values = dict(re.findall(r"^([^#/\n][^:\n]*):[^=\n]*=(.*)$", text, re.M))
    required = {"LIBUNWIND_ENABLE_STATIC": "ON", "LIBUNWIND_ENABLE_SHARED": "OFF",
                "LIBUNWIND_ENABLE_THREADS": "ON" if threads else "OFF", "LIBUNWIND_ENABLE_ASSERTIONS": "ON",
                "LIBUNWIND_ENABLE_FRAME_APIS": "ON", "LIBUNWIND_IS_BAREMETAL": "ON",
                "LIBUNWIND_ENABLE_CROSS_UNWINDING": "OFF", "CMAKE_SYSTEM_NAME": "Generic",
                "CMAKE_C_COMPILER_TARGET": ISAS[isa]["triple"],
                "CMAKE_CXX_COMPILER_TARGET": ISAS[isa]["triple"], "CMAKE_ASM_COMPILER_TARGET": ISAS[isa]["triple"]}
    for key, expected in required.items():
        if values.get(key) != expected:
            raise InventoryError(f"configured original provider profile mismatch: {key}")


def context_receipt(source: Path, build: Path, capture: Path, isa: str, headers: Path) -> dict:
    session = json.loads((capture / "session.json").read_text())
    cc = session["tools"]["clang"]["path"] if "path" in session["tools"]["clang"] else session["tools"]["clang"]["invoked_path"]
    argv = [cc, f"--target={ISAS[isa]['triple']}", *ISAS[isa]["flags"], "-ffreestanding",
            "-nostdlibinc", "-isystem", str(headers), "-I", str(source / "libunwind/include"),
            "-D_LIBUNWIND_IS_NATIVE_ONLY", "-D_LIBUNWIND_IS_BAREMETAL", "-dM", "-E", "-x", "c", "-"]
    receipt = command(argv, build, build / "provider-evidence/context", b"#include <__libunwind_config.h>\n")
    if receipt["exit_code"]:
        raise InventoryError("original context header preprocessing failed")
    check_macros(Path(receipt["stdout"]["path"]).read_text(), isa)
    return {**receipt, "frontend": info(Path(cc)), "header": info(source / "libunwind/include/__libunwind_config.h")}


def preprocess_argv(args: list[str], cc: str) -> list[str]:
    result, index = [cc], 1
    paired = {"-o", "-MF", "-MT", "-MQ"}
    while index < len(args):
        arg = args[index]
        if arg in paired:
            index += 2
            continue
        if arg in {"-c", "-MD", "-MMD", "-MP"}:
            index += 1
            continue
        result.append(arg)
        index += 1
    return [*result, "-E", "-P", "-x", "assembler-with-cpp"]


def archive_matches(units: list[dict], members: list[dict]) -> bool:
    if any("native_output_artifact" not in unit for unit in units):
        return False
    return [(Path(unit["native_output"]).name, unit["native_output_artifact"]["sha256"])
            for unit in units] == [(member["member"], member["sha256"]) for member in members]


def inventory(source: Path, build: Path, capture: Path, isa: str, threads: bool, output: Path) -> dict:
    evidence = build / "provider-evidence" / output.stem
    configuration = json.loads((build / "provider-configuration.json").read_text())
    if configuration["isa"] != isa or configuration["threads"] != threads:
        raise InventoryError("configured execution profile differs from requested inventory")
    original = source_identity(source)
    if original != configuration["source"]:
        raise InventoryError("original source bytes changed after configuration")
    check_cache((build / "CMakeCache.txt").read_text(), isa, threads)
    commands = build / "compile_commands.json"
    query = command(["ninja", "-C", str(build), "-t", "query", "lib/libunwind.a"], build,
                    evidence / "archive-query")
    if query["exit_code"]:
        raise InventoryError("cannot obtain configured archive dependency graph")
    objects = query_objects(Path(query["stdout"]["path"]).read_text(), build)
    rows = json.loads(commands.read_text())
    units = select_units(rows, objects, source, isa, threads)
    artifacts = [info(commands), info(build / "build.ninja"), info(build / "CMakeCache.txt"),
                 info(build / "provider-configuration.json"), query["stdout"]]
    dependency_records = []
    deps = command(["ninja", "-C", str(build), "-t", "deps"], build, evidence / "dependencies")
    dependency_object = None
    for line in Path(deps["stdout"]["path"]).read_text().splitlines():
        if line and not line.startswith(" ") and ": #deps " in line:
            dependency_object = line.split(": #deps ", 1)[0]
        if line.startswith("    "):
            path = Path(line.strip())
            if not path.is_absolute():
                path = build / path
            if path.is_file():
                dependency_records.append({"native_output": dependency_object, "dependency": info(path)})
    archive = build / "lib/libunwind.a"
    issues = []
    for unit in units:
        path = Path(unit["native_output"])
        if path.is_file():
            unit["native_output_artifact"] = info(path)
        else:
            issues.append(f"required original native object is absent: {path}")
        if unit["source_kind"] == "assembly":
            session = json.loads((capture / "session.json").read_text())
            cc = session["tools"]["clang"]["invoked_path"]
            prep = command(preprocess_argv(unit["argv"], cc), Path(unit["directory"]),
                           evidence / f"{Path(unit['source']).stem}-preprocessed")
            unit["original_preprocessed_assembly"] = prep
            issues.append(f"required source assembly is not yet lowered through O-core: {unit['source']}")
    members = []
    if archive.is_file():
        worker = capture / "capture-worker.py"
        # Load this capture's immutable worker; it is evidence parsing, never a build script.
        session = json.loads((capture / "session.json").read_text())
        worker = Path(session["capture_worker"]["artifact"]["path"])
        if info(worker)["sha256"] != session["capture_worker"]["artifact"]["sha256"] or info(worker)["sha256"] != CAPTURE_WORKER_SHA:
            raise InventoryError("immutable capture worker hash mismatch")
        scope = {"__name__": "ocore_unwind_archive_inventory", "__file__": str(worker)}
        exec(compile(worker.read_bytes(), str(worker), "exec"), scope)
        members = scope["native_archive_members"](archive)
        if not archive_matches(units, members):
            issues.append("actual original archive member order/content differs from configured object inputs")
        nm = session["tools"]["nm"]["invoked_path"]
        command([nm, "--undefined-only", str(archive)], build, evidence / "undefined-symbols")
    else:
        issues.append("required original archive is absent")
    inventory_units = [{key: unit[key] for key in ["id", "kind", "source", "role"]} | {"build_step": "build-original-provider"}
                       for unit in units]
    value = {"schema": "ocore-runtime-unit-inventory-v1", "complete": True, "units": inventory_units,
             "runtime_outputs": [info(archive)] if archive.is_file() else [], "non_lowering_units": [],
             "scope": "complete configured original static-archive source graph; configure probes remain explicit unclassified capture evidence",
             "original_units": units, "compile_row_count": len(rows), "archive_input_count": len(objects),
             "source": original, "configuration": info(build / "provider-configuration.json"),
             "inventory_helper": info(Path(__file__)),
             "build_graph_artifacts": artifacts, "dependency_query": deps, "original_dependencies": dependency_records,
             "generated_headers": [info(path) for path in sorted(build.rglob("*.h")) if path.is_file()],
             "archive_members": members, "issues": issues, "source_assembly_lowered": False,
             "whole_provider_ocore_complete": False, "dependency_closure_complete": False,
             "native_ostadix_platform_qualified": False, "full_rust_runtime_complete": False}
    write(output, value)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["configure", "inventory"])
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--isa", choices=ISAS, required=True)
    parser.add_argument("--profile", choices=["threaded", "single_threaded_test"], default="threaded")
    parser.add_argument("--cc")
    parser.add_argument("--cxx")
    parser.add_argument("--ar")
    parser.add_argument("--ranlib")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-helper-sha256", required=True,
                        help="original helper digest pinned by the capture recipe")
    args = parser.parse_args()
    if info(Path(__file__))["sha256"] != args.expected_helper_sha256:
        raise InventoryError("source-owned inventory helper differs from pinned recipe bytes")
    source, build, capture = args.source.resolve(), args.build.resolve(), args.capture.resolve()
    threads = args.profile == "threaded"
    if args.action == "configure":
        original = source_identity(source)
        headers = verify_headers(Path(os.environ["OCORE_LIBUNWIND_HEADER_PROVENANCE"]),
                                 Path(os.environ["OCORE_LIBUNWIND_HEADER_SOURCE_PROVENANCE"]))
        configuration = {"schema": "ocore-original-libunwind-configuration-v1", "source": original,
                         "header_inputs": headers, "isa": args.isa, "threads": threads,
                         "profile": args.profile, "helper": info(Path(__file__)),
                         "source_assembly_lowered": False, "full_rust_runtime_complete": False}
        write(build / "provider-configuration.json", configuration)
        argv = cmake_argv(source, build, args.isa, threads, Path(headers["headers"]),
                          args.cc, args.cxx, args.ar, args.ranlib)
        receipt = command(argv, build, build / "provider-evidence/configure")
        configuration["configure"] = receipt
        if not receipt["exit_code"]:
            configuration["context"] = context_receipt(source, build, capture, args.isa, Path(headers["headers"]))
        write(build / "provider-configuration.json", configuration)
        return receipt["exit_code"]
    value = inventory(source, build, capture, args.isa, threads, args.output or build / "unit-inventory.json")
    print(json.dumps({"units": len(value["units"]), "archive_members": len(value["archive_members"]),
                      "issues": value["issues"], "whole_provider_ocore_complete": False}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InventoryError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"libunwind inventory error: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
