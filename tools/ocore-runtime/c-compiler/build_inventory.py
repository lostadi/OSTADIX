#!/usr/bin/env python3
"""Capture the complete pinned chibicc stage-one Make configuration.

The reference compiler retains its original x86-64 assembly output. This
inventory does not claim that compiler output is routed through O-core.
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

CHIBICC_COMMIT = "90d1f7f199cc55b13c7fdb5839d1409806633fdb"
BUILD_STEP = "build-original-chibicc"
PLAN_SCHEMA = "ocore-chibicc-original-make-plan-v1"


def artifact(path: Path) -> dict:
    path = path.resolve()
    data = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def environment() -> dict:
    result = dict(os.environ)
    for name in ("MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEFILES", "MAKEOVERRIDES",
                 "MAKELEVEL", "CPPFLAGS", "TARGET_ARCH"):
        result.pop(name, None)
    return result


def command(argv: list[str], cwd: Path, stdin: str | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, env=environment(), input=stdin,
                            text=True, capture_output=True)
    if result.returncode:
        raise ValueError(f"original chibicc command failed ({result.returncode}): "
                         f"{shlex.join(argv)}\n{result.stderr}")
    return result.stdout


def source_identity(source: Path) -> dict:
    if command(["git", "rev-parse", "HEAD"], source).strip() != CHIBICC_COMMIT:
        raise ValueError("chibicc source is not the pinned original Git revision")
    if command(["git", "status", "--porcelain", "--untracked-files=all"], source):
        raise ValueError("original chibicc checkout is not clean")
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=source).split(b"\0")
    return {"revision": CHIBICC_COMMIT, "path": str(source), "clean": True,
            "files": [artifact(source / os.fsdecode(name)) for name in names if name]}


def make_groups(source: Path) -> dict:
    names = ("SRCS", "OBJS", "CFLAGS", "LDFLAGS", "TEST_SRCS", "TESTS")
    extra = "\n".join(f"$(info OCORE_{name}=$({name}))" for name in names)
    extra += "\n.PHONY: ocore-inventory\nocore-inventory:\n\t@:\n"
    text = command(["make", "--no-print-directory", "-f", str(source / "Makefile"),
                    "-f", "-", "ocore-inventory"], source, extra)
    values = {}
    for line in text.splitlines():
        if line.startswith("OCORE_"):
            name, value = line[6:].split("=", 1)
            if name in values:
                raise ValueError("duplicate original Make variable")
            values[name] = value
    if set(values) != set(names):
        raise ValueError("original Make variables are incomplete")
    groups = {name: shlex.split(values[name]) for name in names}
    if (not groups["SRCS"] or len(groups["SRCS"]) != len(set(groups["SRCS"]))
            or any(Path(name).name != name or not name.endswith(".c")
                   for name in groups["SRCS"])
            or groups["OBJS"] != [str(Path(name).with_suffix(".o")) for name in groups["SRCS"]]):
        raise ValueError("unsupported or incomplete original chibicc source/object graph")
    return groups


def make_argv(source: Path, build: Path, capture: Path, groups: dict) -> list[str]:
    for path in (source, build, capture):
        if re.search(r"[\s:#$\\]", str(path)):
            raise ValueError("original VPATH Make requires paths without Make metacharacters")
    for left, right in ((source, build), (source, capture), (build, capture)):
        if left == right or left in right.parents or right in left.parents:
            raise ValueError("source, build and capture must be separate, nonnested directories")
    # Evaluate wildcards in the original source cwd above, then preserve that
    # complete result in the separate build cwd. No source body is copied or
    # rewritten, and no object list is chosen by this helper.
    return ["make", "--no-print-directory", "-f", str(source / "Makefile"),
            "VPATH=" + str(source), "CC=" + str(capture / "wrappers/cc"),
            "SRCS=" + " ".join(groups["SRCS"]), "OBJS=" + " ".join(groups["OBJS"])]


def compile_entries(text: str, source: Path, build: Path, cc: str, groups: dict) -> tuple[list, list]:
    entries, links = [], []
    for line in text.replace("\\\n", " ").splitlines():
        args = shlex.split(line)
        if not args:
            continue
        if args[0] != cc or any(arg in {";", "&&", "||", "|", ">", "<"} for arg in args):
            raise ValueError("unexpected command in the original compiler Make graph")
        if args.count("-o") != 1:
            raise ValueError("original producer must have one native output")
        output = (build / args[args.index("-o") + 1]).resolve()
        if "-c" not in args:
            if output != build / "chibicc":
                raise ValueError("unexpected original link output")
            links.append(args)
            continue
        inputs = [arg for arg in args if arg.endswith(".c") and not arg.startswith("-")]
        if len(inputs) != 1:
            raise ValueError("original C producer must have exactly one source")
        path = (build / inputs[0]).resolve()
        if path.parent != source or output.parent != build or path.stem != output.stem:
            raise ValueError("original source/object producer escaped its declared roots")
        entries.append({"source": artifact(path), "output": str(output), "argv": args})
    outputs = [Path(row["output"]).name for row in entries]
    if len(outputs) != len(set(outputs)) or set(outputs) != set(groups["OBJS"]) or len(links) != 1:
        raise ValueError("whole original Make graph has missing, duplicate or unexpected producers")
    return entries, links[0]


def evaluated_graph(source: Path, build: Path, capture: Path) -> tuple[dict, list[str]]:
    identity = source_identity(source)
    groups = make_groups(source)
    tracked_c = {Path(row["path"]).name for row in identity["files"]
                 if Path(row["path"]).parent == source and row["path"].endswith(".c")}
    if set(groups["SRCS"]) != tracked_c:
        raise ValueError("original Make graph does not account for every top-level C unit")
    return {"source": identity, "groups": groups}, make_argv(source, build, capture, groups)


def plan(source: Path, build: Path, capture: Path) -> dict:
    evaluated, argv = evaluated_graph(source, build, capture)
    for directory in (source, build):
        if any((directory / name).exists() for name in evaluated["groups"]["OBJS"] + ["chibicc"]):
            raise ValueError("original compiler capture cannot reuse existing native outputs")
    dry_run = [*argv, "--always-make", "--dry-run", "chibicc"]
    text = command(dry_run, build)
    log = build / "native-build-plan.stdout"
    log.write_text(text)
    entries, link = compile_entries(text, source, build, str(capture / "wrappers/cc"), evaluated["groups"])
    return {"schema": PLAN_SCHEMA, **evaluated, "makefile": artifact(source / "Makefile"),
            "make_argv": argv, "dry_run_argv": dry_run, "dry_run": artifact(log),
            "entries": entries, "link_argv": link,
            "execution_profile": "original-hosted-linux-stage1",
            "compiler_output_profile": "original-x86-64-assembly",
            "compiler_output_routed_through_ocore": False,
            "dependency_closure_complete": False, "native_execution_qualified": False,
            "runtime_complete": False}


def checked_plan(source: Path, build: Path, capture: Path) -> dict:
    graph = json.loads((build / "native-build-plan.json").read_text())
    evaluated, argv = evaluated_graph(source, build, capture)
    if (graph["schema"] != PLAN_SCHEMA or graph["source"] != evaluated["source"]
            or graph["groups"] != evaluated["groups"] or graph["make_argv"] != argv
            or graph["makefile"] != artifact(source / "Makefile")
            or graph["dry_run"] != artifact(build / "native-build-plan.stdout")):
        raise ValueError("original source, evaluated Make graph or planned evidence changed")
    entries, link = compile_entries((build / "native-build-plan.stdout").read_text(), source,
                                    build, str(capture / "wrappers/cc"), graph["groups"])
    if graph["entries"] != entries or graph["link_argv"] != link:
        raise ValueError("original planned producers changed")
    return graph


def check_event(event: dict, argv: list[str], sources: list[dict], output: Path, build: Path) -> None:
    if (event.get("cwd") != str(build) or event.get("expanded_argv") != argv[1:]
            or event.get("sources", []) != sources or event.get("state") != "finished"
            or event.get("exit_code") != 0 or event.get("capture_errors")):
        raise ValueError("actual original frontend invocation differs from its Make plan")
    current = artifact(output)
    if not any(all(record.get(key) == value for key, value in current.items())
               for record in event.get("outputs", [])):
        raise ValueError("native output bytes lack matching captured production evidence")


def check_events(graph: dict, events: list[dict], build: Path) -> None:
    expected = {row["source"]["path"]: row for row in graph["entries"]}
    seen, links = set(), []
    native = []
    for event in events:
        if event.get("build_step", {}).get("name") != BUILD_STEP:
            continue
        if event.get("classification") == "native-tool":
            native.append(event)
            continue
        sources = event.get("sources", [])
        if not sources:
            check_event(event, graph["link_argv"], [], build / "chibicc", build)
            links.append(event)
            continue
        names = [row["path"] for row in sources]
        if len(names) != 1 or names[0] not in expected or names[0] in seen:
            raise ValueError("original journal has duplicate or unplanned C units")
        seen.add(names[0])
        row = expected[names[0]]
        check_event(event, row["argv"], [row["source"]], Path(row["output"]), build)
    if seen != set(expected) or len(links) != 1:
        raise ValueError("original journal lacks complete source and final link production")
    # The capture worker records both the exact Make-level Clang link command
    # and its actual linker child. Keep those records connected instead of
    # mistaking the child for an additional Make command. Trusted replay still
    # independently validates the linker/provider trace and all its hashes.
    link = links[0]
    declared = link.get("native_tool_invocation_ids", [])
    child_ids = [event.get("id") for event in native]
    if (len(child_ids) != len(set(child_ids)) or len(declared) != len(set(declared))
            or set(child_ids) != set(declared)):
        raise ValueError("original linker child inventory differs from its driver evidence")
    current = artifact(build / "chibicc")
    for event in native:
        if (not event.get("id") or not link.get("id")
                or event.get("parent_invocation_id") != link["id"]
                or event.get("kind") != "linker" or event.get("sources")
                or event.get("cwd") != str(build) or event.get("state") != "finished"
                or event.get("exit_code") != 0 or event.get("capture_errors")
                or not any(all(output.get(key) == value for key, value in current.items())
                           for output in event.get("outputs", []))):
            raise ValueError("original actual linker child lacks matching production evidence")


def inventory(source: Path, build: Path, capture: Path) -> dict:
    graph = checked_plan(source, build, capture)
    events = [json.loads(path.read_text()) for path in sorted((capture / "events").glob("*.json"))]
    check_events(graph, events, build)
    return {"schema": "ocore-runtime-unit-inventory-v1", "complete": True,
            "units": [{"id": "original-chibicc-" + Path(row["source"]["path"]).stem,
                       "kind": "clang", "source": Path(row["source"]["path"]).name,
                       "role": "runtime", "build_step": BUILD_STEP} for row in graph["entries"]],
            "non_lowering_units": [], "runtime_outputs": [artifact(build / "chibicc")],
            "configured_native_graph": artifact(build / "native-build-plan.json"),
            "source_data": graph["source"]["files"],
            "declared_external_dependencies": ["libc-and-dynamic-loader", "compiler-helpers", "Linux-platform-services"],
            "compiler_output_profile": graph["compiler_output_profile"],
            "compiler_output_routed_through_ocore": False,
            "dependency_closure_complete": False, "ocore_lowering_complete": False,
            "native_execution_qualified": False, "runtime_complete": False}


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
        parser.error("pinned original compiler inventory helper changed")
    source, build, capture = (getattr(args, name).resolve() for name in ("source", "build", "capture"))
    if args.action == "build":
        if args.jobs < 1:
            parser.error("--jobs must be positive")
        graph = checked_plan(source, build, capture)
        result = subprocess.run([*graph["make_argv"], "-j" + str(args.jobs), "chibicc"],
                                cwd=build, env=environment())
        raise SystemExit(result.returncode)
    if args.output is None:
        parser.error("--output is required for plan and inventory")
    result = (plan if args.action == "plan" else inventory)(source, build, capture)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"artifact": artifact(args.output), "runtime_complete": False}))


if __name__ == "__main__":
    main()
