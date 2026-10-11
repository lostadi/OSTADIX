#!/usr/bin/env python3
"""Configure and retain a whole original musl static source/build graph.

Native outputs are source-build references, never opaque O-core providers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

MUSL_COMMIT = "0784374d561435f7c787a555aeab8ede699ed298"
WORKER_SHA = "4eedaad775ad6283547a0204d01c644822fef0be4fd99d6441384476c97f4777"
PROFILES = {
    "x86_64": {"triple": "x86_64-unknown-linux-musl", "flags": []},
    "aarch64": {"triple": "aarch64-unknown-linux-musl", "flags": []},
    "riscv64": {"triple": "riscv64-unknown-linux-musl", "flags": ["-march=rv64gc", "-mabi=lp64d"]},
}
GRAPH_KEYS = ["ARCH", "SUBARCH", "ADD_CFI", "MALLOC_DIR", "BASE_SRCS", "ARCH_SRCS", "REPLACED_OBJS",
              "LIBC_OBJS", "LDSO_OBJS", "CRT_OBJS", "AOBJS", "ALL_LIBS", "ALL_TOOLS", "ALL_INCLUDES",
              "CC", "CFLAGS_ALL", "LIBCC", "SHARED_LIBS", "STATIC_LIBS", "GENH", "GENH_INT",
              "INCLUDES", "ARCH_INCLUDES", "GENERIC_INCLUDES", "AR", "RANLIB"]


class InventoryError(ValueError):
    pass


def info(path: Path) -> dict:
    path = path.resolve()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run(argv: list[str], cwd: Path, prefix: Path, stdin: bytes | None = None) -> dict:
    result = subprocess.run(argv, cwd=cwd, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = prefix.with_suffix(".stdout"), prefix.with_suffix(".stderr")
    stdout.parent.mkdir(parents=True, exist_ok=True)
    stdout.write_bytes(result.stdout)
    stderr.write_bytes(result.stderr)
    receipt = {"argv": argv, "cwd": str(cwd), "exit_code": result.returncode,
               "stdout": info(stdout), "stderr": info(stderr)}
    write(prefix.with_suffix(".json"), receipt)
    return receipt


def identity(source: Path) -> dict:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=source)
    if head != MUSL_COMMIT or dirty:
        raise InventoryError("original musl source must be clean at the exact pinned commit")
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=source).split(b"\0")
    return {"path": str(source), "revision": head, "clean": True,
            "files": [info(source / os.fsdecode(path)) for path in paths if path]}


def configure_argv(source: Path, build: Path, capture: Path, isa: str) -> list[str]:
    profile = PROFILES[isa]
    # musl's early compile-only warning probes otherwise reject the selected
    # linker flag as unused. This diagnostic flag is also upstream's later Clang default.
    cc = shlex.join([str(capture / "wrappers/cc"), f"--target={profile['triple']}",
                     *profile["flags"], "-Qunused-arguments", "-fuse-ld=lld"])
    return [str(source / "configure"), f"--srcdir={source}", f"--target={profile['triple']}",
            "--enable-static", "--disable-shared", f"--prefix={build / 'install'}", f"CC={cc}",
            f"AR={capture / 'wrappers/llvm-ar'}", f"RANLIB={capture / 'wrappers/llvm-ranlib'}"]


def parse_graph(text: str) -> dict[str, str]:
    graph = {}
    for line in text.splitlines():
        if line.startswith("OCORE_MUSL_"):
            key, value = line.removeprefix("OCORE_MUSL_").split("=", 1)
            if key in graph:
                raise InventoryError(f"ambiguous expanded upstream graph field: {key}")
            graph[key] = value
    if set(graph) != set(GRAPH_KEYS):
        raise InventoryError("expanded upstream source/output graph is incomplete")
    return graph


def check_profile(graph: dict[str, str], isa: str) -> None:
    if graph["ARCH"] != isa or graph["SUBARCH"] or graph["MALLOC_DIR"] != "mallocng":
        raise InventoryError("original architecture/allocator profile differs from declaration")
    if graph["STATIC_LIBS"].split() != ["lib/libc.a"] or graph["SHARED_LIBS"].split():
        raise InventoryError("original full static profile was reduced or relabeled")
    if graph["ADD_CFI"] != "no":
        raise InventoryError("unexpected configured assembly transformation; retain as unsupported new profile")
    cc = shlex.split(graph["CC"])
    targets = [arg.split("=", 1)[1] for arg in cc if arg.startswith("--target=")]
    if not targets or any(target != PROFILES[isa]["triple"] for target in targets):
        raise InventoryError("original compiler target differs from declared Linux profile")
    for flag in PROFILES[isa]["flags"]:
        prefix = flag.split("=", 1)[0] + "="
        if [arg for arg in cc if arg.startswith(prefix)] != [flag]:
            raise InventoryError("original RV64GC LP64D context profile was lost")
    if any("fast-math" in flag for flag in shlex.split(graph["CFLAGS_ALL"])):
        raise InventoryError("original IEEE libc/libm source semantics were changed")


def compiler_entries(text: str, source: Path, build: Path, cc: str) -> list[dict]:
    entries, outputs = [], set()
    for number, line in enumerate(text.replace("\\\n", " ").splitlines()):
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        tokens = list(lexer)
        if cc not in tokens:
            continue
        if tokens.count(cc) != 1:
            raise InventoryError("ambiguous compiler command in original build plan")
        start = tokens.index(cc)
        args = []
        for token in tokens[start + 1:]:
            if token and set(token) <= set(";&|"):
                break
            args.append(token)
        if "-c" not in args or args.count("-o") != 1:
            raise InventoryError("original build plan compiler command lacks exact compile/output contract")
        output = (build / args[args.index("-o") + 1]).resolve()
        inputs, index = [], 0
        paired = {"-o", "-I", "-isystem", "-include", "-imacros", "-MF", "-MT", "-MQ", "-x"}
        while index < len(args):
            token = args[index]
            if token in paired:
                index += 2
                continue
            if not token.startswith("-") and Path(token).suffix in {".c", ".s", ".S"}:
                inputs.append((build / token).resolve())
            index += 1
        if len(inputs) != 1 or not inputs[0].is_relative_to(source):
            raise InventoryError("original source producer is missing/ambiguous or outside pinned source tree")
        if output in outputs:
            raise InventoryError("duplicate original compile output producer")
        outputs.add(output)
        entries.append({"id": f"native-source-{len(entries):04d}", "line": number + 1, "command": line,
                        "argv": args, "directory": str(build), "source": info(inputs[0]),
                        "output": str(output), "source_kind": "assembly" if inputs[0].suffix in {".s", ".S"} else "c"})
    if not entries:
        raise InventoryError("original full source build plan contains no compiler commands")
    return entries


def require_graph_producers(graph: dict[str, str], entries: list[dict], build: Path) -> None:
    expected = {(build / path).resolve() for key in ["AOBJS", "CRT_OBJS"] for path in graph[key].split()}
    actual = {Path(entry["output"]) for entry in entries}
    if expected != actual:
        raise InventoryError(f"original complete static producer graph mismatch: missing={sorted(map(str, expected-actual))}, unplanned={sorted(map(str, actual-expected))}")
    sources = {str(Path(entry["source"]["path"]).relative_to(Path(graph["srcdir"])))
               for entry in entries} if "srcdir" in graph else {entry["source"]["path"] for entry in entries}
    for suffix in ["src/thread/pthread_create.c", "src/env/__init_tls.c", "src/malloc/mallocng/malloc.c", "src/stdio/vfprintf.c"]:
        if not any(name.endswith("/" + suffix) or name == suffix for name in sources):
            raise InventoryError(f"required original libc/thread/TLS implementation missing: {suffix}")
    if not any("/src/math/" in entry["source"]["path"] for entry in entries):
        raise InventoryError("complete libc profile lost original libm sources")
    if not any(entry["source_kind"] == "assembly" for entry in entries):
        raise InventoryError("original architecture assembly disappeared from the complete graph")


def plan(source: Path, build: Path, capture: Path, isa: str) -> dict:
    original = identity(source)
    configuration = json.loads((build / "source-configuration.json").read_text())
    if original != configuration["source"] or configuration["isa"] != isa:
        raise InventoryError("original source/profile changed after configuration")
    query_file = build / "source-graph-query.mk"
    query_file.write_text("\n".join(f"$(info OCORE_MUSL_{key}=$({key}))" for key in GRAPH_KEYS) + "\n.PHONY: ocore-source-graph\nocore-source-graph:\n\t@:\n")
    query = run(["make", "--no-print-directory", "-f", "Makefile", "-f", str(query_file), "ocore-source-graph"],
                build, build / "source-evidence/expanded-graph")
    if query["exit_code"]:
        raise InventoryError("upstream expanded source graph query failed")
    graph = parse_graph(Path(query["stdout"]["path"]).read_text())
    check_profile(graph, isa)
    dry = run(["make", "--no-print-directory", "--dry-run", "all"], build, build / "source-evidence/full-build-plan")
    if dry["exit_code"]:
        raise InventoryError("upstream complete static build plan failed")
    entries = compiler_entries(Path(dry["stdout"]["path"]).read_text(), source, build, str(capture / "wrappers/cc"))
    require_graph_producers(graph, entries, build)
    value = {"schema": "ocore-original-musl-source-plan-v1", "source": original, "isa": isa,
             "triple": PROFILES[isa]["triple"], "configuration": info(build / "source-configuration.json"),
             "makefile": info(source / "Makefile"), "configured_makefile": info(build / "config.mak"),
             "graph_query_source": info(query_file), "graph_query": query, "expanded_graph": graph,
             "original_full_build_plan": dry, "entries": entries, "helper": info(Path(__file__)),
             "whole_provider_ocore_complete": False, "dependency_closure_complete": False,
             "native_ostadix_platform_qualified": False, "full_rust_runtime_complete": False}
    write(build / "full-source-plan.json", value)
    return value


def load_worker(capture: Path):
    session = json.loads((capture / "session.json").read_text())
    worker = Path(session["capture_worker"]["artifact"]["path"])
    if info(worker)["sha256"] != WORKER_SHA or info(worker) != session["capture_worker"]["artifact"]:
        raise InventoryError("immutable source capture worker provenance differs")
    scope = {"__name__": "ocore_musl_source_inventory", "__file__": str(worker)}
    exec(compile(worker.read_bytes(), str(worker), "exec"), scope)
    return session, scope


def inventory(source: Path, build: Path, capture: Path, isa: str, output: Path, post: bool) -> dict:
    graph = json.loads((build / "full-source-plan.json").read_text())
    if identity(source) != graph["source"] or info(build / "config.mak") != graph["configured_makefile"]:
        raise InventoryError("original source/configuration bytes changed after complete graph planning")
    check_profile(graph["expanded_graph"], isa)
    session, worker = load_worker(capture)
    events = [json.loads(path.read_text()) for path in sorted((capture / "events").glob("*.json"))]
    units, missing, observed = [], [], []
    for entry in graph["entries"]:
        unit = {"id": entry["id"], "kind": "clang", "source": str(Path(entry["source"]["path"]).relative_to(source)),
                "build_step": "build-original-libc", "role": "runtime-libc-startup-or-compiler-helper"}
        matches = [event for event in events if event.get("build_step", {}).get("name") == "build-original-libc"
                   and event.get("expanded_argv") == entry["argv"] and event.get("cwd") == entry["directory"]]
        if post:
            if len(matches) != 1:
                missing.append(f"ambiguous/missing original compiler invocation for {entry['output']}")
            else:
                unit["invocation_ids"] = [matches[0]["id"]]
                observed.append({"entry": entry["id"], "event": matches[0]["id"], "exit_code": matches[0]["exit_code"],
                                 "native_outputs": matches[0]["outputs"], "capture_errors": matches[0]["capture_errors"]})
        units.append(unit)
    roots, archives = [], []
    for spelling in graph["expanded_graph"]["ALL_LIBS"].split():
        path = build / spelling
        if path.is_file():
            artifact = info(path)
            roots.append(artifact)
            if path.suffix == ".a":
                members = worker["native_archive_members"](path)
                archives.append({"artifact": artifact, "members": members})
                if spelling == "lib/libc.a":
                    objects = [build / name for name in graph["expanded_graph"]["AOBJS"].split()]
                    expected = [(path.name, info(path)["sha256"]) for path in objects if path.is_file()]
                    actual = [(member["member"], member["sha256"]) for member in members]
                    if actual != expected or len(expected) != len(objects):
                        missing.append("original libc archive member order/content does not match entire configured source graph")
        elif post:
            missing.append(f"required configured original native output absent: {spelling}")
    tools = []
    for spelling in graph["expanded_graph"]["ALL_TOOLS"].split():
        path = build / spelling
        if path.is_file():
            tools.append(info(path))
        elif post:
            missing.append(f"required original compiler driver tool absent: {spelling}")
    generated = [info(build / name) for key in ["GENH", "GENH_INT"]
                 for name in graph["expanded_graph"][key].split() if (build / name).is_file()]
    value = {"schema": "ocore-runtime-unit-inventory-v1", "complete": not missing, "scope": "entire evaluated original static profile source graph; admission remains fail-closed",
             "units": units, "runtime_outputs": roots, "non_lowering_units": [],
             "source_plan": info(build / "full-source-plan.json"), "original_source_units": graph["entries"],
             "original_archive_members": archives, "original_compiler_driver_tools": tools,
             "original_generated_headers": generated, "observed_frontend_invocations": observed,
             "issues": missing, "source_assembly_lowered": False, "inline_assembly_and_syscalls_lowered": False,
             "whole_provider_ocore_complete": False, "dependency_closure_complete": False,
             "native_ostadix_platform_qualified": False, "full_rust_runtime_complete": False,
             "helper": info(Path(__file__))}
    write(output, value)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["configure", "plan", "inventory"])
    for name in ["source", "build", "capture"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--isa", choices=PROFILES, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--post", action="store_true")
    parser.add_argument("--expected-helper-sha256", required=True)
    args = parser.parse_args()
    if info(Path(__file__))["sha256"] != args.expected_helper_sha256:
        raise InventoryError("source inventory helper differs from digest-bound recipe")
    source, build, capture = args.source.resolve(), args.build.resolve(), args.capture.resolve()
    if args.action == "configure":
        argv = configure_argv(source, build, capture, args.isa)
        configuration = {"schema": "ocore-original-musl-source-configuration-v1", "source": identity(source),
                         "isa": args.isa, "helper": info(Path(__file__)), "argv": argv,
                         "platform": "Linux-compatible static profile; OSTADIX syscall/TLS services unqualified"}
        write(build / "source-configuration.json", configuration)
        receipt = run(argv, build, build / "source-evidence/configure")
        configuration["result"] = receipt
        write(build / "source-configuration.json", configuration)
        return receipt["exit_code"]
    if args.action == "plan":
        value = plan(source, build, capture, args.isa)
        print(json.dumps({"planned_original_source_units": len(value["entries"]), "ocore_complete": False}))
    else:
        value = inventory(source, build, capture, args.isa, args.output or build / "unit-inventory.json", args.post)
        print(json.dumps({"required_original_source_units": len(value["units"]), "issues": value["issues"], "ocore_complete": False}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InventoryError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"musl source inventory error: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
