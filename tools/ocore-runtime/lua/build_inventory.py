#!/usr/bin/env python3
"""Capture the unchanged pinned Lua Make graph, not a census or rewritten engine.

The resulting inventory feeds ocore_runtime_capture.py and olangc's independent
whole-unit import boundary. Native reference outputs do not qualify O-core code.
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

LUA_COMMIT = "0b29f408433e92953cc72b1d3e06c7ac8139e439"
BUILD_STEP = "build-original-lua"
GROUPS = ("CORE_O", "AUX_O", "LIB_O", "LUA_O", "ALL_O", "CORE_T", "LUA_T", "ALL_T")


def artifact(path: Path) -> dict:
    path = path.resolve()
    data = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def environment() -> dict:
    result = dict(os.environ)
    # Neither a parent's make jobserver nor -e/-f overrides may change the
    # evaluated original graph. Compiler/linker environment stays in capture.
    for name in ("MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEFILES", "MAKEOVERRIDES", "MAKELEVEL",
                 "CPPFLAGS", "TARGET_ARCH"):
        result.pop(name, None)
    return result


def command(argv: list[str], cwd: Path, stdin: str | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, env=environment(), input=stdin,
                            text=True, capture_output=True)
    if result.returncode:
        raise ValueError(f"original Lua command failed ({result.returncode}): {shlex.join(argv)}\n{result.stderr}")
    return result.stdout


def source_identity(source: Path) -> dict:
    if command(["git", "rev-parse", "HEAD"], source).strip() != LUA_COMMIT:
        raise ValueError("Lua source is not the pinned original Git revision")
    if command(["git", "status", "--porcelain", "--untracked-files=normal"], source):
        raise ValueError("original Lua checkout is not clean")
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=source).split(b"\0")
    return {"revision": LUA_COMMIT, "path": str(source), "clean": True,
            "files": [artifact(source / os.fsdecode(name)) for name in names if name]}


def make_argv(source: Path, build: Path, cc: str, ar: str, ranlib: str) -> list[str]:
    # GNU Make VPATH is a whitespace/colon list. Reject ambiguous paths rather
    # than compile a different source when paths contain Make syntax.
    for path in (source, build, Path(cc), Path(ar), Path(ranlib)):
        if re.search(r"[\s:#$\\]", str(path)):
            raise ValueError("Lua's original VPATH Make graph requires paths without Make metacharacters")
    if build == source or source in build.parents or build in source.parents:
        raise ValueError("Lua capture requires a separate out-of-tree build directory")
    return ["make", "--no-print-directory", "-f", str(source / "makefile"),
            "VPATH=" + str(source), "CC=" + cc, "AR=" + ar + " rc", "RANLIB=" + ranlib]


def make_variables(argv: list[str], build: Path) -> dict:
    extra = "\n".join("$(info OCORE_" + name + "=$(" + name + "))" for name in GROUPS)
    extra += "\n.PHONY: ocore-inventory\nocore-inventory:\n\t@:\n"
    text = command([*argv, "-f", "-", "ocore-inventory"], build, extra)
    rows = dict(re.findall(r"^OCORE_(\w+)=(.*)$", text, re.M))
    if set(rows) != set(GROUPS):
        raise ValueError("original evaluated Make object/target groups are missing")
    groups = {name: value.split() for name, value in rows.items()}
    objects = sum((groups[name] for name in GROUPS[:4]), [])
    if not objects or len(objects) != len(set(objects)) or set(objects) != set(groups["ALL_O"]):
        raise ValueError("original ALL_O does not cover each core, auxiliary, library and executable object exactly once")
    if any(not re.fullmatch(r"[A-Za-z0-9_]+\.o", name) for name in objects):
        raise ValueError("unsupported original Make object name")
    if groups["CORE_T"] != ["liblua.a"] or groups["LUA_T"] != ["lua"] or groups["ALL_T"] != ["liblua.a", "lua"]:
        raise ValueError("original full Lua archive and interpreter targets are required")
    return groups


def compile_entries(text: str, source: Path, build: Path, cc: str, groups: dict) -> list[dict]:
    entries = []
    for line in text.replace("\\\n", " ").splitlines():
        args = shlex.split(line)
        if not args or args[0] != cc or "-c" not in args:
            continue
        if any(arg in {";", "&&", "||", "|", ">", "<"} for arg in args):
            raise ValueError("unexpected shell operation in original frontend command")
        inputs = [arg for arg in args if arg.endswith(".c") and not arg.startswith("-")]
        if len(inputs) != 1 or args.count("-o") != 1:
            raise ValueError("original frontend command must have one C source and one native output")
        path, output = (build / inputs[0]).resolve(), (build / args[args.index("-o") + 1]).resolve()
        if path.parent != source or output.parent != build or path.stem != output.stem:
            raise ValueError("original Lua source/object producer escaped its declared roots")
        entries.append({"source": artifact(path), "output": str(output), "argv": args})
    outputs = [Path(row["output"]).name for row in entries]
    if len(outputs) != len(set(outputs)) or set(outputs) != set(groups["ALL_O"]):
        raise ValueError("whole original Make graph has missing, duplicate or unexpected C producers")
    return entries


def plan(source: Path, build: Path, capture: Path) -> dict:
    identity = source_identity(source)
    argv = make_argv(source, build, str(capture / "wrappers/cc"),
                     str(capture / "wrappers/llvm-ar"), str(capture / "wrappers/llvm-ranlib"))
    groups = make_variables(argv, build)
    if any((build / name).exists() for name in groups["ALL_O"] + groups["ALL_T"]):
        raise ValueError("Lua source capture cannot reuse existing native build outputs")
    dry_run = [*argv, "--always-make", "--dry-run", "all"]
    text = command(dry_run, build)
    log = build / "native-build-plan.stdout"
    log.write_text(text)
    return {"schema": "ocore-lua-original-make-plan-v1", "source": identity,
            "makefile": artifact(source / "makefile"), "make_argv": argv,
            "dry_run_argv": dry_run, "dry_run": artifact(log), "groups": groups,
            "entries": compile_entries(text, source, build, str(capture / "wrappers/cc"), groups),
            "execution_profile": "original-hosted-linux-defaults",
            "dependency_closure_complete": False, "native_execution_qualified": False,
            "runtime_complete": False}


def checked_plan(source: Path, build: Path, capture: Path) -> dict:
    graph = json.loads((build / "native-build-plan.json").read_text())
    if graph["schema"] != "ocore-lua-original-make-plan-v1" or graph["source"] != source_identity(source):
        raise ValueError("original Lua source changed after planning")
    argv = make_argv(source, build, str(capture / "wrappers/cc"),
                     str(capture / "wrappers/llvm-ar"), str(capture / "wrappers/llvm-ranlib"))
    if graph["make_argv"] != argv or graph["groups"] != make_variables(argv, build):
        raise ValueError("original evaluated Lua Make graph changed after planning")
    if graph["makefile"] != artifact(source / "makefile") or graph["dry_run"] != artifact(build / "native-build-plan.stdout"):
        raise ValueError("original Lua build-plan evidence changed")
    expected = compile_entries((build / "native-build-plan.stdout").read_text(), source, build,
                               str(capture / "wrappers/cc"), graph["groups"])
    if expected != graph["entries"]:
        raise ValueError("original Lua planned frontend producers changed")
    return graph


def check_events(entries: list[dict], events: list[dict], build: Path) -> None:
    expected = {row["source"]["path"]: row for row in entries}
    seen = set()
    for event in events:
        if event.get("build_step", {}).get("name") != BUILD_STEP or not event.get("sources"):
            continue
        names = [row["path"] for row in event["sources"]]
        if len(names) != 1 or names[0] not in expected or names[0] in seen:
            raise ValueError("original Lua compilation journal has unplanned or duplicate sources")
        seen.add(names[0])
        row = expected[names[0]]
        if (event.get("cwd") != str(build) or event.get("expanded_argv") != row["argv"][1:]
                or event["sources"] != [row["source"]] or event.get("state") != "finished"
                or event.get("exit_code") != 0 or event.get("capture_errors")):
            raise ValueError("actual original Lua frontend invocation differs from its complete Make plan")
        current = artifact(Path(row["output"]))
        if not any(all(output.get(key) == value for key, value in current.items())
                   for output in event.get("outputs", [])):
            raise ValueError("original Lua object bytes lack matching captured production evidence")
    if seen != set(expected):
        raise ValueError("original Lua journal lacks required whole source units: " + str(sorted(set(expected) - seen)))


def archive_members(archive: Path) -> list[tuple[str, bytes]]:
    """Read the original ELF/GNU archive without dispatching a producer wrapper.

    All pinned Lua object names fit GNU short headers. Thin archives, long-name
    references and malformed/truncated records fail rather than invent bytes.
    """
    data = archive.read_bytes()
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("Lua inventory requires a complete regular GNU archive")
    offset, members = 8, []
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:60] != b"`\n" or not header[48:58].strip().isdigit():
            raise ValueError("invalid Lua archive member header")
        size = int(header[48:58])
        start, end = offset + 60, offset + 60 + size
        if end > len(data) or (size % 2 and (end == len(data) or data[end:end + 1] != b"\n")):
            raise ValueError("truncated Lua archive member")
        name = header[:16].decode("ascii").strip()
        if name not in {"/", "/SYM64/"}:
            if not re.fullmatch(r"[A-Za-z0-9_]+\.o/", name):
                raise ValueError("unexpected Lua archive member name")
            members.append((name[:-1], data[start:end]))
        offset = end + size % 2
    return members


def check_archive(archive: Path, objects: list[Path]) -> list[dict]:
    contents = archive_members(archive)
    names = [name for name, data in contents]
    if names != [path.name for path in objects]:
        raise ValueError("original full Lua archive member order/content list differs from Make")
    members = []
    for path, (name, data) in zip(objects, contents):
        if data != path.read_bytes():
            raise ValueError("Lua archive member differs from captured original object: " + path.name)
        members.append({"name": path.name, "object": artifact(path)})
    return members


def inventory(source: Path, build: Path, capture: Path) -> dict:
    graph = checked_plan(source, build, capture)
    events = [json.loads(path.read_text()) for path in sorted((capture / "events").glob("*.json"))]
    check_events(graph["entries"], events, build)
    groups = graph["groups"]
    archive_objects = [build / name for name in sum((groups[name] for name in GROUPS[:3]), [])]
    members = check_archive(build / "liblua.a", archive_objects)
    return {"schema": "ocore-runtime-unit-inventory-v1", "complete": True,
            "units": [{"id": "original-lua-" + Path(row["source"]["path"]).stem,
                       "kind": "clang", "source": Path(row["source"]["path"]).name,
                       "role": "runtime", "build_step": BUILD_STEP} for row in graph["entries"]],
            "non_lowering_units": [],
            "runtime_outputs": [artifact(build / name) for name in groups["ALL_T"]],
            "original_archive_members": members,
            "configured_native_graph": artifact(build / "native-build-plan.json"),
            "declared_external_dependencies": ["libc", "libm", "libdl", "compiler-helpers", "Linux-platform-services"],
            "source_data": graph["source"]["files"], "dependency_closure_complete": False,
            "ocore_lowering_complete": False, "native_execution_qualified": False, "runtime_complete": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "build", "inventory"))
    for name in ("source", "build", "capture"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--expected-helper-sha256", required=True)
    args = parser.parse_args()
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != args.expected_helper_sha256:
        parser.error("pinned original Lua inventory helper changed")
    source, build, capture = (getattr(args, name).resolve() for name in ("source", "build", "capture"))
    if args.action == "build":
        if args.jobs < 1:
            parser.error("--jobs must be positive")
        graph = checked_plan(source, build, capture)
        result = subprocess.run([*graph["make_argv"], "-j" + str(args.jobs), "all"], cwd=build, env=environment())
        raise SystemExit(result.returncode)
    if args.output is None:
        parser.error("--output is required for plan and inventory")
    result = (plan if args.action == "plan" else inventory)(source, build, capture)
    write(args.output, result)
    print(json.dumps({"artifact": artifact(args.output), "runtime_complete": False}))


if __name__ == "__main__":
    main()
