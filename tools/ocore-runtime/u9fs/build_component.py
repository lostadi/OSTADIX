#!/usr/bin/env python3
"""Capture unchanged u9fs wire codecs and their original musl C dependencies.

These are explicitly scoped library components, never complete u9fs or libc.
All machine code is subsequently imported/emitted by the caller's olangc.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

U9FS_REVISION = "fcec3e1e2e8e8c28b89270e6c44554c4ca9e50a9"
MUSL_REVISION = "0784374d561435f7c787a555aeab8ede699ed298"
CODECS = ("convM2S.c", "convS2M.c", "convM2D.c", "convD2M.c")
MEMORY = ("src/string/memcpy.c", "src/string/memmove.c", "src/string/strlen.c")
ISAS = ("x86_64", "aarch64")
FLAGS = ("-O1", "-ffreestanding", "-fno-builtin", "-fno-vectorize",
         "-fno-slp-vectorize", "-fno-pic", "-fno-pie", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-fno-stack-protector", "-nostdinc")


def identity(path: Path) -> dict:
    path = path.resolve(strict=True)
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": h.hexdigest()}


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def check_source(source: Path, revision: str) -> dict:
    if source.is_symlink() or not source.is_dir():
        raise ValueError("source must be an explicit original checkout directory")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=source)
    if head != revision or dirty:
        raise ValueError("source must remain clean at pinned revision " + revision)
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=source).split(b"\0")
    files = [identity(source / os.fsdecode(name)) for name in tracked if name]
    return {"path": str(source), "revision": head, "files": files}


def musl_headers(source: Path, build: Path, isa: str) -> dict:
    """Use musl's original header generator and original target definitions."""
    generated = build / "include/bits"
    generated.mkdir(parents=True, exist_ok=True)
    args = ["sed", "-f", str(source / "tools/mkalltypes.sed"),
            str(source / f"arch/{isa}/bits/alltypes.h.in"), str(source / "include/alltypes.h.in")]
    result = subprocess.run(args, capture_output=True, check=True)
    (generated / "alltypes.h").write_bytes(result.stdout)
    return {"argv": args, "output": identity(generated / "alltypes.h"),
            "inputs": [identity(source / p) for p in (
                "tools/mkalltypes.sed", f"arch/{isa}/bits/alltypes.h.in", "include/alltypes.h.in")]}


def upstream_codecs(source: Path, build: Path) -> dict:
    """Check the selected component against the evaluated original object list."""
    query = build / "upstream-object-query.mk"
    query.write_text("$(info OCORE_U9FS_OBJECTS=$(OFILES))\n.PHONY: ocore-codec-query\nocore-codec-query:\n\t@:\n")
    args = ["make", "--no-print-directory", "-f", str(source / "makefile"),
            "-f", str(query), "ocore-codec-query"]
    output = subprocess.check_output(args, cwd=build, text=True)
    lines = [line.removeprefix("OCORE_U9FS_OBJECTS=") for line in output.splitlines()
             if line.startswith("OCORE_U9FS_OBJECTS=")]
    if len(lines) != 1:
        raise ValueError("original u9fs object inventory is ambiguous")
    objects = lines[0].split()
    selected = [str(Path(name).with_suffix(".o")) for name in CODECS]
    if len(objects) != len(set(objects)) or not set(selected).issubset(objects):
        raise ValueError("selected codecs are absent from the original u9fs build")
    return {"argv": args, "makefile": identity(source / "makefile"),
            "query": identity(query), "upstream_objects": objects,
            "component_objects": selected}


def build_component(args) -> None:
    source, build = args.source.resolve(strict=True), args.build.resolve(strict=True)
    original = check_source(source, U9FS_REVISION if args.component == "codecs" else MUSL_REVISION)
    if args.component == "codecs":
        spelling = os.environ.get("OCORE_U9FS_MUSL_SOURCE")
        if not spelling:
            raise ValueError("OCORE_U9FS_MUSL_SOURCE must name the explicit pinned original musl checkout")
        musl = Path(spelling).expanduser().resolve(strict=True)
        musl_identity = check_source(musl, MUSL_REVISION)
        upstream = upstream_codecs(source, build)
        selected = CODECS
    else:
        musl, musl_identity, upstream, selected = source, original, None, MEMORY
    headers = musl_headers(musl, build, args.isa)
    include = [source, build / "include", musl / f"arch/{args.isa}", musl / "arch/generic", musl / "include"]
    entries = []
    for name in selected:
        output = build / (Path(name).stem + ".o")
        command = [args.cc, f"--target={args.isa}-unknown-linux-musl", *FLAGS,
                   *["-I" + str(path) for path in include], "-c", str(source / name), "-o", str(output)]
        subprocess.run(command, cwd=build, check=True)
        entries.append({"source": name, "source_identity": identity(source / name),
                        "argv": command, "output": identity(output)})
    if check_source(source, original["revision"]) != original or check_source(musl, MUSL_REVISION) != musl_identity:
        raise ValueError("original source changed during the component build")
    write(build / "component-build.json", {
        "schema": "ocore-original-u9fs-component-build/v1", "component": args.component,
        "isa": args.isa, "source": original, "header_source": musl_identity,
        "generated_headers": headers, "original_build_selection": upstream,
        "entries": entries, "helper": identity(Path(__file__)),
        "scope": "complete explicitly selected codec or generic memory/string component; not full u9fs/libc"})


def inventory(args) -> None:
    source, build = args.source.resolve(strict=True), args.build.resolve(strict=True)
    record = json.loads((build / "component-build.json").read_text())
    selected = CODECS if args.component == "codecs" else MEMORY
    if record["component"] != args.component or record["isa"] != args.isa:
        raise ValueError("component/target changed before inventory")
    if check_source(source, record["source"]["revision"]) != record["source"]:
        raise ValueError("original source changed before inventory")
    if [entry["source"] for entry in record["entries"]] != list(selected):
        raise ValueError("complete selected component source inventory differs")
    for entry in record["entries"]:
        if identity(source / entry["source"]) != entry["source_identity"] or identity(Path(entry["output"]["path"])) != entry["output"]:
            raise ValueError("component source/reference output changed")
    write(build / "unit-inventory.json", {
        "schema": "ocore-runtime-unit-inventory-v1", "complete": True,
        "scope": record["scope"], "units": [
            {"id": "original-" + Path(name).stem, "kind": "clang", "source": name,
             "role": "runtime", "build_step": "build-original-component"} for name in selected],
        "non_lowering_units": [], "runtime_outputs": [entry["output"] for entry in record["entries"]],
        "component_build": identity(build / "component-build.json")})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "inventory"))
    parser.add_argument("--component", choices=("codecs", "memory"), required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--isa", choices=ISAS, required=True)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--expected-helper-sha256", required=True)
    args = parser.parse_args()
    if identity(Path(__file__))["sha256"] != args.expected_helper_sha256:
        parser.error("source component helper differs from its recipe pin")
    (build_component if args.action == "build" else inventory)(args)


if __name__ == "__main__":
    main()
