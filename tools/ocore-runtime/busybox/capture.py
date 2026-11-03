#!/usr/bin/env python3
"""Capture an unchanged upstream basic-cat reference build and its real closure.

This is a Linux reference source build, not O-core application admission. The
generic capture report is retained even when required dependencies or source
features leave admission incomplete.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import time


ROOT = Path(__file__).resolve().parents[3]
VERSION = "1.36.1"
ARCHIVE_SHA = "b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314"
ARCHIVE_BYTES = 2525473
MUSL_REVISION = "0784374d561435f7c787a555aeab8ede699ed298"
SDK_DEFAULT = Path.home() / ".cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64"
SOURCE_DEFAULT = Path.home() / "native-rebuild-20261022/work/busybox-2b8b8f437b6d"
MUSL_DEFAULT = Path.home() / ".cache/okernel-musl-source-current-soc9clfn"
PROFILE = "unchanged-upstream-busybox-1.36.1-basic-cat-static-x86_64-linux-musl"
FRAGMENT = """CONFIG_CAT=y
CONFIG_STATIC=y
# CONFIG_FEATURE_CATN is not set
# CONFIG_FEATURE_CATV is not set
# CONFIG_FEATURE_SUID is not set
# CONFIG_LOCALE_SUPPORT is not set
CONFIG_FEATURE_COPYBUF_KB=4
CONFIG_SH_IS_NONE=y
# CONFIG_SH_IS_ASH is not set
# CONFIG_SH_IS_HUSH is not set
CONFIG_EXTRA_LDFLAGS="-Wl,-Ttext-segment=0x02000000"
"""


class CaptureError(ValueError):
    pass


def info(path: Path) -> dict:
    path = path.resolve(strict=True)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def checked(item: dict) -> Path:
    path = Path(item["path"])
    if path.is_symlink() or not path.is_file() or info(path) != item:
        raise CaptureError("reference artifact identity differs: " + str(path))
    return path


def run(argv, cwd: Path, log: Path, env=None, input_data=b"") -> dict:
    argv = [str(value) for value in argv]
    started = time.monotonic()
    result = subprocess.run(argv, cwd=cwd, env=env, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_bytes(result.stdout)
    return {"argv": argv, "cwd": str(cwd), "exit_code": result.returncode,
            "seconds": time.monotonic() - started, "log": info(log),
            "stdin": {"bytes": len(input_data), "sha256": hashlib.sha256(input_data).hexdigest()}}


def require_run(argv, cwd: Path, log: Path, env=None) -> dict:
    value = run(argv, cwd, log, env)
    if value["exit_code"]:
        raise CaptureError("command failed; retained log: " + str(log))
    return value


def source_pin(archive: Path, dsc: Path, signature: Path) -> dict:
    archive_record = info(archive)
    if archive_record["bytes"] != ARCHIVE_BYTES or archive_record["sha256"] != ARCHIVE_SHA:
        raise CaptureError("original release archive differs from the pinned SHA-256/size")
    line = re.compile(r"^ " + ARCHIVE_SHA + r" " + str(ARCHIVE_BYTES)
                      + r" busybox_1\.36\.1\.orig\.tar\.bz2$", re.M)
    if line.search(dsc.read_text()) is None:
        raise CaptureError("local .dsc does not bind the pinned original release archive")
    return {"archive": archive_record, "local_dsc": info(dsc), "detached_signature": info(signature),
            "scope": "Release archive pin checked against local .dsc checksum; signature trust not verified",
            "debian_patches_applied": False}


def archive_members(archive: Path):
    """Preflight all names before extracting; preserve original file/link bytes."""
    with tarfile.open(archive, "r:bz2") as stream:
        members = stream.getmembers()
        names, links = set(), set()
        for member in members:
            name = member.name.rstrip("/")
            path = PurePosixPath(name)
            if (not name or path.is_absolute() or ".." in path.parts
                    or str(path) != name or path.parts[0] != "busybox-" + VERSION
                    or ".git" in path.parts or name in names):
                raise CaptureError("unsafe or duplicate archive member: " + member.name)
            names.add(name)
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise CaptureError("unsupported archive node type: " + name)
            if member.issym():
                target = PurePosixPath(member.linkname)
                if target.is_absolute():
                    raise CaptureError("absolute archive symlink: " + name)
                parts = list(path.parent.parts)
                for part in target.parts:
                    if part == "..":
                        if len(parts) <= 1:
                            raise CaptureError("escaping archive symlink: " + name)
                        parts.pop()
                    elif part != ".":
                        parts.append(part)
                links.add(name)
            if member.islnk():
                target = PurePosixPath(member.linkname)
                if target.is_absolute() or ".." in target.parts or target.parts[0] != "busybox-" + VERSION:
                    raise CaptureError("escaping archive hardlink: " + name)
        for name in names:
            if any(str(parent) in links for parent in PurePosixPath(name).parents):
                raise CaptureError("archive member below a symlink: " + name)
        return members


def extract_source(archive: Path, parent: Path) -> Path:
    members = archive_members(archive)
    with tarfile.open(archive, "r:bz2") as stream:
        for member in sorted(members, key=lambda item: (not item.isdir(), item.name.count("/"))):
            target = parent / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(member) as source, target.open("xb") as destination:
                    shutil.copyfileobj(source, destination)
            elif member.issym():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(member.linkname)
            elif member.islnk():
                target.parent.mkdir(parents=True, exist_ok=True)
                os.link(parent / member.linkname, target)
            if not member.issym():
                target.chmod(member.mode & 0o777)
    return parent / ("busybox-" + VERSION)


def git_import(source: Path, logs: Path) -> dict:
    environment = os.environ.copy()
    environment.update(GIT_AUTHOR_NAME="Ostadix release archive import", GIT_AUTHOR_EMAIL="archive-import@localhost",
                       GIT_COMMITTER_NAME="Ostadix release archive import", GIT_COMMITTER_EMAIL="archive-import@localhost",
                       GIT_AUTHOR_DATE="2000-01-01T00:00:00+00:00", GIT_COMMITTER_DATE="2000-01-01T00:00:00+00:00")
    commands = []
    for number, args in enumerate((["init", "--quiet"], ["config", "core.autocrlf", "false"],
                                   ["config", "core.filemode", "true"], ["add", "--force", "."],
                                   ["-c", "core.hooksPath=/dev/null", "commit", "--quiet", "--no-gpg-sign", "-m",
                                    "Private unchanged BusyBox 1.36.1 release archive import " + ARCHIVE_SHA])):
        commands.append(require_run(["git", *args], source, logs / f"import-{number}.log", environment))
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=source, text=True).strip()
    modes = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=source)
    (logs / "source-tree-modes.zlist").write_bytes(modes)
    return {"revision": commit, "tree": tree, "mode_inventory": info(logs / "source-tree-modes.zlist"),
            "commands": commands, "scope": "Deterministic private archive-import commit, not upstream Git history or signature proof"}


def verify_archive_import(archive: Path, source: Path, output: Path) -> dict:
    """Bind every release node; Git must contain every non-directory member."""
    nodes, expected = [], {}
    with tarfile.open(archive, "r:bz2") as stream:
        for member in stream.getmembers():
            relative = PurePosixPath(member.name.rstrip("/")).relative_to("busybox-" + VERSION)
            path = source / relative
            value = path.lstat()
            node = {"path": str(relative), "archive_mode": member.mode & 0o777,
                    "extracted_mode": stat.S_IMODE(value.st_mode)}
            if not member.issym() and node["archive_mode"] != node["extracted_mode"]:
                raise CaptureError("release node mode changed: " + str(relative))
            if member.isdir():
                if not stat.S_ISDIR(value.st_mode):
                    raise CaptureError("release directory changed: " + str(relative))
                node["kind"] = "directory"
            else:
                if member.issym():
                    data = os.fsencode(os.readlink(path))
                    if data != os.fsencode(member.linkname):
                        raise CaptureError("release symlink changed: " + str(relative))
                    mode, node["kind"] = "120000", "symlink"
                else:
                    if not stat.S_ISREG(value.st_mode):
                        raise CaptureError("release regular file changed: " + str(relative))
                    data = path.read_bytes()
                    if data != stream.extractfile(member).read():
                        raise CaptureError("release file bytes changed: " + str(relative))
                    mode, node["kind"] = ("100755" if member.mode & 0o111 else "100644"), "file"
                blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                node.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), git_mode=mode, git_blob=blob)
                expected[str(relative)] = (mode, blob)
            nodes.append(node)
    actual = {}
    for item in subprocess.check_output(["git", "ls-tree", "-r", "--full-tree", "-z", "HEAD"], cwd=source).split(b"\0"):
        if not item:
            continue
        fields, name = item.split(b"\t", 1)
        mode, kind, digest = fields.decode().split()
        if kind != "blob":
            raise CaptureError("unexpected imported Git tree node type")
        actual[os.fsdecode(name)] = (mode, digest)
    if actual != expected:
        raise CaptureError("private Git import dropped or changed a release archive member")
    write(output, {"schema": "ostadix.release-archive-private-import-equivalence/v1", "ok": True,
                   "archive": info(archive), "source": str(source), "archive_nodes": nodes,
                   "git_nondirectory_entries": len(actual), "scope": "All files/symlinks and normalized Git modes match; original directories/modes are additionally retained, since Git does not represent empty directories"})
    return info(output)


def bind_musl(reference: Path, destination: Path) -> dict:
    command = json.loads((reference / "result.json").read_text())
    inventory_path = reference / "build/unit-inventory.json"
    inventory = json.loads(inventory_path.read_text())
    source_config = json.loads((reference / "build/source-configuration.json").read_text())
    if (len(command["build_steps"]) != 7 or any(step["exit_code"] for step in command["build_steps"])
            or not command["source_clean_before"] or not command["source_clean_after"]
            or inventory["complete"] is not True or source_config["isa"] != "x86_64"
            or source_config["source"]["revision"] != MUSL_REVISION):
        raise CaptureError("complete pinned original x86-64 musl reference build is required")
    source = Path(source_config["source"]["path"])
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip() != MUSL_REVISION:
        raise CaptureError("original musl source revision changed")
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=source):
        raise CaptureError("original musl source is dirty")
    outputs = {Path(item["path"]).name: item for item in inventory["runtime_outputs"]}
    destination.mkdir()
    (destination / "lib").mkdir()
    bound = []
    for path in sorted((reference / "build/lib").iterdir()):
        record = outputs.get(path.name)
        if record is None or info(path) != record:
            raise CaptureError("musl library/startup output differs from source inventory: " + str(path))
        target = destination / "lib" / path.name
        shutil.copyfile(path, target)
        bound.append({"original": record, "copy": info(target)})
    include = reference / "build/install/include"
    shutil.copytree(include, destination / "include")
    headers = [{"original": info(path), "copy": info(destination / "include" / path.relative_to(include))}
               for path in sorted(include.rglob("*")) if path.is_file()]
    if len(headers) != 218:
        raise CaptureError("original configured musl target header inventory differs")
    templates = {}
    for name in ["musl-clang.in", "ld.musl-clang.in"]:
        path = source / "tools" / name
        templates[name] = {"artifact": info(path), "text": path.read_text()}
    return {"source_build_receipt": info(reference / "result.json"), "full_inventory": info(inventory_path),
            "source_configuration": info(reference / "build/source-configuration.json"), "source_revision": MUSL_REVISION,
            "artifacts": bound, "headers": headers, "driver_templates": templates,
            "scope": "Original source-built Linux reference dependencies, not O-core-lowered libc"}


def make_argv(source: Path, build: Path, capture: Path, jobs=2):
    return ["make", "--no-print-directory", "-C", str(source), "O=" + str(build), "ARCH=x86_64",
            "CC=" + str(build / "driver/musl-clang"), "HOSTCC=" + str(capture / "wrappers/cc"),
            "AR=" + str(capture / "wrappers/llvm-ar"), "LD=" + str(capture / "wrappers/ld.lld"),
            "NM=llvm-nm", "SKIP_STRIP=y", "-j" + str(jobs), "V=1"]


def helper(args):
    if info(Path(__file__))["sha256"] != args.expected_helper_sha256:
        raise CaptureError("builder helper differs from the recipe-bound identity")
    source, build, capture = args.source.resolve(), args.build.resolve(), args.capture.resolve()
    configuration = json.loads(args.configuration.read_text())
    runtime = Path(configuration["runtime"])
    if args.action == "configure":
        driver = build / "driver"
        driver.mkdir()
        substitutions = {"@CC@": str(capture / "wrappers/cc") + " --target=x86_64-unknown-linux-musl -Qunused-arguments",
                         "@PREFIX@": str(runtime), "@INCDIR@": str(runtime / "include"), "@LIBDIR@": str(runtime / "lib"),
                         "@LDSO@": "/lib/ld-musl-x86_64.so.1"}
        for name, item in configuration["musl"]["driver_templates"].items():
            checked(item["artifact"])
            text = item["text"]
            for before, after in substitutions.items():
                text = text.replace(before, after)
            path = driver / name.removesuffix(".in")
            path.write_text(text)
            path.chmod(0o755)
        fragment = build / "basic-cat.config"
        fragment.write_text(FRAGMENT)
        environment = os.environ.copy()
        # This original Kconfig fork resets booleans during allnoconfig even
        # after reading KCONFIG_ALLCONFIG. Its own scripts/kconfig/Makefile
        # documents allnoconfig, selecting symbols in .config, then make.
        environment.pop("KCONFIG_ALLCONFIG", None)
        value = require_run([*make_argv(source, build, capture), "allnoconfig"], build, build / "evidence/configure.log", environment)
        original_config = (build / ".config").read_text()
        (build / "allno-baseline.config").write_text(original_config)
        lines = original_config.splitlines()
        for selection in FRAGMENT.splitlines():
            match = re.fullmatch(r"(?:# )?(CONFIG_[A-Z0-9_]+)(?:=.*| is not set)", selection)
            if match is None:
                raise CaptureError("invalid declared Kconfig selection")
            key = match[1]
            indexes = [i for i, line in enumerate(lines) if line.startswith(key + "=") or line == "# " + key + " is not set"]
            if len(indexes) != 1:
                raise CaptureError("Kconfig selection is absent or ambiguous: " + key)
            lines[indexes[0]] = selection
        (build / ".config").write_text("\n".join(lines) + "\n")
        selected = build / "selected-before-oldconfig.config"
        selected.write_bytes((build / ".config").read_bytes())
        oldconfig = require_run([*make_argv(source, build, capture), "oldconfig"], build, build / "evidence/oldconfig.log", environment)
        config = (build / ".config").read_text()
        for expected in FRAGMENT.splitlines():
            if expected not in config.splitlines():
                raise CaptureError("upstream Kconfig did not select exact basic-cat profile: " + expected)
        fixedpoint = require_run([*make_argv(source, build, capture), "oldconfig"], build,
                                 build / "evidence/oldconfig-fixedpoint.log", environment)
        if (build / ".config").read_text() != config:
            raise CaptureError("original oldconfig did not reach a fixed point")
        # Recursive dry-run cannot discover prerequisites generated by its
        # host tools until original prepare has produced them. This is itself
        # captured; target objects built by prepare remain in the inventory.
        prepared = require_run([*make_argv(source, build, capture), "prepare"], build, build / "evidence/prepare.log", environment)
        write(build / "configuration.json", {"command": value, "oldconfig": oldconfig,
                                             "oldconfig_fixedpoint": fixedpoint, "oldconfig_is_fixedpoint": True,
                                             "selected_before_oldconfig": info(selected),
                                             "declared_config_selections": FRAGMENT.splitlines(),
                                             "prepare": prepared,
                                             "original_selection_workflow": info(source / "scripts/kconfig/Makefile"),
                                             "allno_baseline": info(build / "allno-baseline.config"), "profile": PROFILE, "fragment": info(fragment),
                                             "config": info(build / ".config"), "drivers": [info(p) for p in driver.iterdir()]})
    elif args.action == "plan":
        value = run([*make_argv(source, build, capture), "--dry-run", "--always-make", "busybox"], build, build / "evidence/complete-make-plan.log")
        write(build / "plan.json", value)
        if value["exit_code"]:
            raise CaptureError("upstream dry-run failed; retain full planned failure")
    elif args.action == "build":
        value = run([*make_argv(source, build, capture), "busybox"], build, build / "evidence/build.log")
        write(build / "build-command.json", value)
        if value["exit_code"]:
            raise CaptureError("upstream reference build failed; retained source/build log")
    elif args.action == "inventory":
        make_inventory(source, build, capture)
    else:
        behavior(build)


def compile_command(command: str, directory: Path, compiler: str) -> dict | None:
    """Recognize an exact original Kbuild compiler command, not echo text."""
    tokens = shlex.split(command)
    if not tokens or tokens[0] != compiler or "-c" not in tokens:
        return None
    if tokens.count("-o") != 1:
        raise CaptureError("configured compiler producer has no unique output")
    output = (directory / tokens[tokens.index("-o") + 1]).resolve()
    if not output.is_relative_to(directory) or output.suffix != ".o":
        raise CaptureError("configured compiler output escapes the build")
    inputs, index = [], 1
    paired = {"-o", "-I", "-isystem", "-iquote", "-include", "-imacros", "-MF", "-MT", "-MQ", "-x"}
    while index < len(tokens):
        token = tokens[index]
        if token in paired:
            index += 2
            continue
        if not token.startswith("-") and Path(token).suffix in {".c", ".s", ".S"}:
            inputs.append((directory / token).resolve())
        index += 1
    if len(inputs) != 1:
        raise CaptureError("configured compiler producer has ambiguous source")
    return {"argv": tokens, "source": str(inputs[0]), "output": str(output)}


def planned_compiles(text: str, build: Path, compiler: str) -> dict[str, list[dict]]:
    planned = {}
    for line in text.replace("\\\n", " ").splitlines():
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        tokens = list(lexer)
        for start, token in enumerate(tokens):
            if token != compiler:
                continue
            end = start + 1
            while end < len(tokens) and not (tokens[end] and set(tokens[end]) <= set(";&|")):
                end += 1
            value = compile_command(shlex.join(tokens[start:end]), build, compiler)
            if value:
                planned.setdefault(value["output"], []).append(value)
    return planned


def subsequence(whole: list[str], part: list[str]) -> bool:
    return any(whole[i:i + len(part)] == part for i in range(len(whole) - len(part) + 1))


def worker_scope(capture: Path):
    session = json.loads((capture / "session.json").read_text())
    record = session["capture_worker"]["artifact"]
    path = checked(record)
    scope = {"__name__": "original_busybox_inventory_worker", "__file__": str(path)}
    exec(compile(path.read_bytes(), str(path), "exec"), scope)
    return session, scope


def elf_profile(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise CaptureError("configured application is not ELF64 little-endian version one")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    _, kind, machine, _, entry, offset, _, _, _, size, count, _, _, _ = header
    if size != 56 or offset + count * size > len(data):
        raise CaptureError("configured ELF program header table is invalid")
    segments = []
    for index in range(count):
        typ, flags, file_offset, virtual, physical, file_bytes, memory_bytes, align = struct.unpack_from("<IIQQQQQQ", data, offset + index * size)
        segments.append({"type": typ, "flags": flags, "file_offset": file_offset, "virtual_address": virtual,
                         "physical_address": physical, "file_bytes": file_bytes, "memory_bytes": memory_bytes, "alignment": align})
    loads = [item for item in segments if item["type"] == 1]
    if kind != 2 or machine != 62 or not loads or any(item["type"] == 3 for item in segments):
        raise CaptureError("reference profile must be static x86-64 ET_EXEC without an interpreter")
    if not any(item["flags"] & 1 and item["virtual_address"] <= entry < item["virtual_address"] + item["memory_bytes"] for item in loads):
        raise CaptureError("ELF entry is outside executable load segments")
    return {"artifact": info(path), "elf_type": kind, "machine": machine, "entry": entry,
            "minimum_load_address": min(item["virtual_address"] for item in loads),
            "end_load_address": max(item["virtual_address"] + item["memory_bytes"] for item in loads),
            "program_headers": segments, "has_interpreter": False,
            "scope": "Original Linux reference address layout; no native O-core ABI or execution admission"}


def make_inventory(source: Path, build: Path, capture: Path, output: Path | None = None):
    # Original Kbuild command files and a complete original dry run own source
    # selection. Reachability in the linked cat executable never drops a cold
    # configured archive member from this inventory.
    compiler = str(build / "driver/musl-clang")
    planned = planned_compiles((build / "evidence/complete-make-plan.log").read_text(), build, compiler)
    session, worker = worker_scope(capture)
    raw_events = [json.loads(path.read_text()) for path in sorted((capture / "events").glob("*.json"))]
    metadata, originals, units, hosts, issues = [], {}, [], [], []
    target_outputs = set()
    for path in sorted(build.rglob("*.cmd")):
        text = path.read_text()
        first = text.splitlines()[0]
        if " := " not in first or not first.startswith("cmd_"):
            issues.append("unrecognized original Kbuild command metadata: " + str(path))
            continue
        target, command = first.split(" := ", 1)
        target = (build / target.removeprefix("cmd_")).resolve()
        if not target.is_relative_to(build) or not target.is_file():
            issues.append("original Kbuild output is unavailable: " + str(target))
            continue
        record = {"metadata": info(path), "output": info(target), "command": command}
        metadata.append(record)
        originals[str(target)] = record
        entry = compile_command(command, build, compiler)
        if entry is None:
            # Retain all host/generated/native-link metadata. Do not declare
            # their LLVM units excluded from lowering without the independent
            # output-membership proof required by the generic admission layer.
            if target.suffix == ".o":
                hosts.append(record)
            continue
        target_outputs.add(entry["output"])
        if entry["output"] != str(target):
            issues.append("Kbuild metadata names a different compiler output: " + str(path))
            continue
        if entry["output"] not in planned or entry not in planned[entry["output"]]:
            issues.append("configured compile differs from complete original plan: " + str(target))
        src = Path(entry["source"])
        if not src.is_relative_to(source):
            issues.append("target source is not part of the unchanged release tree: " + str(src))
            continue
        matches = []
        for event in raw_events:
            if event.get("exit_code") != 0 or event.get("kind") != "clang":
                continue
            if (not any(item.get("path") == str(target) and item.get("sha256") == record["output"]["sha256"]
                        for item in event.get("outputs", []))
                    or not any(item == info(src) for item in event.get("sources", []))
                    or not subsequence(event.get("argv", []), entry["argv"][1:])):
                continue
            matches.append(event)
        if len(matches) != 1:
            issues.append("missing/ambiguous exact configured frontend occurrence: " + str(target))
            continue
        event = matches[0]
        units.append({"id": f"configured-runtime-{len(units):04d}", "kind": "clang", "role": "runtime",
                      "source": src.relative_to(source).as_posix(), "invocation_ids": [event["id"]],
                      "build_step": event["build_step"]["name"], "native_output": record["output"],
                      "original_command": entry, "frontend": event["frontend"],
                      "captured_units": event.get("units", []), "source_identity": info(src)})
    if set(planned) != target_outputs:
        issues.append("complete original plan and configured target object sets differ: "
                      + repr({"missing": sorted(set(planned) - target_outputs), "unplanned": sorted(target_outputs - set(planned))}))
    objects = [info(path) for path in sorted(build.rglob("*.o"))]
    if {item["path"] for item in objects} - originals.keys():
        issues.append("native objects lack original Kbuild output metadata")
    archives = []
    for path in sorted(build.rglob("*")):
        if not path.is_file() or path.suffix not in {".a", ".o"}:
            continue
        with path.open("rb") as stream:
            if stream.read(8) not in {b"!<arch>\n", b"!<thin>\n"}:
                continue
        members = worker["native_archive_members"](path)
        original = originals.get(str(path))
        if original is None:
            issues.append("configured archive lacks original Kbuild metadata: " + str(path))
            continue
        tokens = shlex.split(original["command"].replace(";", " ; "))
        ar = str(capture / "wrappers/llvm-ar")
        if tokens.count(ar) != 1:
            issues.append("configured archive producer is ambiguous: " + str(path))
            continue
        index = tokens.index(ar)
        arguments = tokens[index + 1:]
        if len(arguments) < 2 or arguments[0] != "rcs" or (build / arguments[1]).resolve() != path:
            issues.append("configured archive producer differs: " + str(path))
            continue
        expected = [info((build / name).resolve()) for name in arguments[2:]]
        if ([(member["member"], member["sha256"]) for member in members]
                != [(Path(item["path"]).name, item["sha256"]) for item in expected]):
            issues.append("configured archive dropped/reordered/changed an original object: " + str(path))
        archives.append({"artifact": info(path), "members": members, "original_objects": expected, "command": original})
    header_root = build / "include"
    headers = [info(path) for path in sorted(header_root.rglob("*")) if path.is_file()]
    applets = (header_root / "applet_tables.h").read_text()
    if "#define NUM_APPLETS 1" not in applets or '#define SINGLE_APPLET_STR "cat"' not in applets:
        issues.append("original generated applet table is not the declared single-cat profile")
    if not any(item["source"] == "coreutils/cat.c" for item in units):
        issues.append("original cat implementation is missing")
    final_output = info(build / "busybox_unstripped")
    link_events = [event for event in raw_events if event.get("kind") == "linker" and event.get("exit_code") == 0
                   and any(item.get("path") == final_output["path"] and item.get("sha256") == final_output["sha256"]
                           for item in event.get("outputs", []))]
    link = max(link_events, key=lambda event: event["finished_ns"]) if link_events else None
    linker_inputs, selected_members = [], []
    map_path = build / "busybox_unstripped.map"
    if link is None or not map_path.is_file():
        issues.append("actual final linker occurrence and original link map are required")
    else:
        search = [Path(arg[2:]) for arg in link["argv"] if arg.startswith("-L") and len(arg) > 2]
        for arg in link["argv"]:
            candidate = None
            if arg.startswith("-l") and len(arg) > 2:
                matches = [directory / ("lib" + arg[2:] + ".a") for directory in search
                           if (directory / ("lib" + arg[2:] + ".a")).is_file()]
                if len(matches) != 1:
                    issues.append("static reference library cannot be resolved unambiguously: " + arg)
                else:
                    candidate = matches[0]
            elif not arg.startswith("-") and Path(arg).suffix in {".o", ".a", ".so"}:
                candidate = (Path(link["cwd"]) / arg).resolve()
            if candidate is not None:
                if not candidate.is_file():
                    issues.append("actual reference linker input is unavailable: " + str(candidate))
                else:
                    linker_inputs.append({"argument": arg, "artifact": info(candidate),
                                          "configured_object_or_archive": str(candidate) in originals,
                                          "ocore_provider_admitted": False})
        header = map_path.read_text().split("\nDiscarded input sections", 1)[0]
        member_cache = {}
        seen = set()
        for archive_name, member_name in re.findall(r"^\s*(\S+\.a)\(([^)]+)\)", header, re.M):
            archive = (Path(link["cwd"]) / archive_name).resolve()
            identity = (str(archive), member_name)
            if identity in seen:
                continue
            seen.add(identity)
            if archive not in member_cache:
                member_cache[archive] = worker["native_archive_members"](archive)
            candidates = [member for member in member_cache[archive] if member["member"] == member_name]
            if not candidates:
                issues.append("original map names a missing archive member: " + repr(identity))
            selected_members.append({"archive": info(archive), "member": member_name,
                                     "original_member_candidates": candidates,
                                     "source_lowering_admitted": False})
    value = {"schema": "ocore-runtime-unit-inventory-v1", "complete": not issues, "units": units,
             "runtime_outputs": [info(build / "busybox_unstripped"), *[item["artifact"] for item in archives]],
             "non_lowering_units": [], "profile": PROFILE,
             "scope": "Complete unchanged configured target object/archive inventory; host tools/probes remain retained and unclassified for native admission",
             "original_kbuild_command_files": metadata, "configured_objects": objects,
             "configured_archives": archives, "generated_headers": headers, "host_or_native_link_objects": hosts,
             "producer_journal": [info(path) for path in sorted((capture / "events").glob("*.json"))],
             "complete_original_plan": info(build / "evidence/complete-make-plan.log"),
             "actual_final_linker_occurrence": link,
             "reference_elf": elf_profile(build / "busybox_unstripped"),
             "actual_final_linker_inputs": linker_inputs,
             "original_link_map": info(map_path) if map_path.is_file() else None,
             "selected_reference_archive_members": selected_members,
             "issues": issues, "native_ocore_application_qualified": False, "ocore_lowering_complete": False,
             "dependency_closure_complete": False}
    write(output or build / "unit-inventory.json", value)
    return value


def behavior(build: Path):
    binary = build / "busybox_unstripped"
    fixtures = build / "behavior"
    fixtures.mkdir()
    cases = []
    inputs = [bytes((n * 73 ^ (n >> 8)) & 255 for n in range(size)) for size in [0, 4096, 65536, 1048576]]
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}

    def check(name, argv, stdin, expected_stdout, expected_stderr=b"", exit_code=0, stdout_device=None):
        prefix = fixtures / f"case-{len(cases):02d}-{name}"
        Path(str(prefix) + ".stdin").write_bytes(stdin)
        Path(str(prefix) + ".expected.stdout").write_bytes(expected_stdout)
        Path(str(prefix) + ".expected.stderr").write_bytes(expected_stderr)
        if stdout_device is None:
            result = subprocess.run(argv, executable=binary, input=stdin, capture_output=True, env=environment, cwd=fixtures)
            actual_stdout = result.stdout
        else:
            with open(stdout_device, "wb", buffering=0) as device:
                result = subprocess.run(argv, executable=binary, input=stdin, stdout=device, stderr=subprocess.PIPE,
                                        env=environment, cwd=fixtures)
            actual_stdout = b""
        Path(str(prefix) + ".stdout").write_bytes(actual_stdout)
        Path(str(prefix) + ".stderr").write_bytes(result.stderr)
        cases.append({"kind": name, "argv": argv, "cwd": str(fixtures), "environment": environment,
                      "stdin": info(Path(str(prefix) + ".stdin")), "stdout_device": stdout_device,
                      "stdout": info(Path(str(prefix) + ".stdout")), "stderr": info(Path(str(prefix) + ".stderr")),
                      "expected_stdout": info(Path(str(prefix) + ".expected.stdout")),
                      "expected_stderr": info(Path(str(prefix) + ".expected.stderr")),
                      "expected_exit_code": exit_code, "exit_code": result.returncode,
                      "ok": result.returncode == exit_code and actual_stdout == expected_stdout and result.stderr == expected_stderr})

    for index, data in enumerate(inputs):
        path = fixtures / f"input-{len(data)}"
        path.write_bytes(data)
        for name, argv, stdin, expected in [("file", ["cat", str(path)], b"", data), ("stdin", ["cat"], data, data)]:
            check(name, argv, stdin, expected)
    for name in ["absent", "x" * 200]:
        error = b"cat: can't open '" + name.encode() + b"': No such file or directory\n"
        check("missing-file", ["cat", name], b"", b"", error, 1)
    check("unbuffered-option", ["cat", "-u"], inputs[1], inputs[1])
    paths = [fixtures / "input-4096", fixtures / "input-65536"]
    check("multiple-files", ["cat", *map(str, paths)], b"", inputs[1] + inputs[2])
    check("file-stdin-file", ["cat", str(paths[0]), "-", str(paths[1])], b"stdin\0\xff\n", inputs[1] + b"stdin\0\xff\n" + inputs[2])
    check("error-then-valid-file", ["cat", "absent", str(paths[0])], b"", inputs[1],
          b"cat: can't open 'absent': No such file or directory\n", 1)
    check("disabled-number-option", ["cat", "-n"], b"line\n", b"", b"cat: unrecognized option: n\n", 1)
    check("write-enospc", ["cat"], inputs[1], b"", b"cat: write error: No space left on device\n", 1, "/dev/full")
    record = {"schema": "ostadix.busybox-cat-linux-reference-behavior/v1", "ok": all(case["ok"] for case in cases),
              "binary": info(binary), "cases": cases,
              "fixtures": [info(path) for path in sorted(fixtures.glob("input-*"))],
              "oracle": "Expected raw byte streams, original basic-cat option/error semantics, and exact exit codes; no syscall trace is treated as complete dependency coverage",
              "scope": "Original configured binary on host Linux only; not O-core application execution"}
    write(build / "behavior.json", record)
    if not record["ok"]:
        raise CaptureError("original reference application behavior differed")


def outer(args):
    sdk = args.sdk.resolve(strict=True)
    archive_root = args.archive_directory.resolve(strict=True)
    pin = source_pin(archive_root / "busybox_1.36.1.orig.tar.bz2", archive_root / "busybox_1.36.1-6ubuntu3.1.dsc",
                     archive_root / "busybox_1.36.1.orig.tar.bz2.asc")
    output = args.output.resolve()
    # Original musl's compiler wrapper uses shell-word CC configuration. Keep
    # these build paths representable without changing that original wrapper.
    if re.fullmatch(r"[A-Za-z0-9_./+-]+", str(output)) is None:
        raise CaptureError("this original-shell-driver build profile requires a shell-word-safe output path")
    output.mkdir(parents=True, exist_ok=False)
    recipe_dir = output / "recipe"
    recipe_dir.mkdir()
    (recipe_dir / "capture.py").write_bytes(Path(__file__).read_bytes())
    helper_sha = info(recipe_dir / "capture.py")["sha256"]
    archive_parent = output / "sources"
    archive_parent.mkdir()
    source = extract_source(archive_root / "busybox_1.36.1.orig.tar.bz2", archive_parent)
    imported = git_import(source, output / "provenance")
    imported["archive_tree_equivalence"] = verify_archive_import(
        archive_root / "busybox_1.36.1.orig.tar.bz2", source, output / "provenance/archive-tree-equivalence.json")
    runtime = output / "reference-runtime"
    musl = bind_musl(args.musl_reference.resolve(strict=True), runtime)
    configuration = {"schema": "ostadix.original-basic-cat-reference-inputs/v1", "profile": PROFILE, "release": pin,
                     "archive_import": imported, "runtime": str(runtime), "musl": musl,
                     "source_build_is_ocore_lowering": False, "dependency_closure_complete": False}
    config_path = recipe_dir / "configuration.json"
    write(config_path, configuration)
    commands = []
    for action in ["configure", "plan", "build", "inventory", "behavior"]:
        commands.append({"name": "original-basic-cat-" + action,
                         "argv": ["python3", "{recipe_dir}/capture.py", action, "--source", "{source}", "--build", "{build}",
                                  "--capture", "{output}", "--configuration", "{recipe_dir}/configuration.json",
                                  "--expected-helper-sha256", helper_sha]})
    recipe = {"schema": "ocore-runtime-recipe-v1", "name": PROFILE,
              "source": {"url": "local-release-archive-import:sha256:" + ARCHIVE_SHA, "revision": imported["revision"], "submodules": False},
              "upstream_release": pin, "toolchain": {"llvm_version": "22.1.6"}, "commands": commands,
              "coverage": {"require_full_unit_inventory": True, "audit_roots": ["{build}"], "required_outputs": ["busybox_unstripped"],
                           "required_units": [{"id": "original-cat", "kind": "clang", "source": "coreutils/cat.c", "role": "runtime", "build_step": "original-basic-cat-build"}]},
              "dependencies": [{"name": "original-source-built-musl-static-reference", "status": "required-not-ocore-admitted", "receipt": musl["source_build_receipt"]},
                               {"name": "native-Linux-syscalls-TLS-process-file-services", "status": "required-not-qualified"}],
              "blockers": ["This is a reference source build, not a complete O-core application/runtime admission",
                           "Original musl architecture assembly, inline assembly/TLS, helper and native Linux service closure remain required"]}
    recipe_path = recipe_dir / "basic-cat.recipe.json"
    write(recipe_path, recipe)
    for path in recipe_dir.iterdir():
        path.chmod(0o444)
    environment = os.environ.copy()
    environment["PATH"] = str(sdk / "bin") + os.pathsep + environment["PATH"]
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    command = ["python3", "-B", str(ROOT / "scripts/ocore_runtime_capture.py"), "capture", str(recipe_path),
               "--source", str(source), "--build", str(output / "build"), "--output", str(output / "capture"),
               "--cc", str(sdk / "bin/clang"), "--cxx", str(sdk / "bin/clang++"), "--llvm-nm", str(sdk / "bin/llvm-nm"),
               "--unit-inventory", str(output / "build/unit-inventory.json"), "--jobs", "2"]
    print("REFERENCE_CAPTURE", output, flush=True)
    result = run(command, ROOT, output / "capture-command.log", environment)
    report_path = output / "capture/report.json"
    report = json.loads(report_path.read_text()) if report_path.is_file() else {}
    inventory_path = output / "build/unit-inventory.json"
    inventory = json.loads(inventory_path.read_text()) if inventory_path.is_file() else {}
    record = {"schema": "ostadix.original-busybox-cat-reference-capture/v1", "profile": PROFILE, "capture_command": result,
              "configuration": info(config_path), "recipe": info(recipe_path), "source_import": imported,
              "source_archive_equivalence_after": verify_archive_import(
                  archive_root / "busybox_1.36.1.orig.tar.bz2", source, output / "provenance/archive-tree-equivalence-after.json"),
              "source_dirty_after": subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=source, text=True),
              "generic_capture_report": info(report_path) if report_path.is_file() else None,
              "generic_capture_complete": report.get("capture_complete", False),
              "generic_capture_issues": report.get("issues", []),
              "recipe_build_steps": report.get("build_steps", []),
              "configured_unit_inventory": info(inventory_path) if inventory_path.is_file() else None,
              "configured_unit_inventory_complete": inventory.get("complete", False),
              "reference_elf": inventory.get("reference_elf"),
              "declared_native_window_minimum_load_address": 0x02000000,
              "native_ocore_application_qualified": False, "ocore_lowering_complete": False,
              "dependency_closure_complete": False,
              "scope": "Unchanged configured original BusyBox Linux reference source/build capture; generic admission remains fail-closed"}
    ignored = subprocess.check_output(["git", "ls-files", "--others", "--ignored", "--exclude-standard", "-z"], cwd=source)
    record["source_generated_ignored_files"] = [info(source / os.fsdecode(path)) for path in ignored.split(b"\0") if path]
    behavior_path = output / "build/behavior.json"
    record["reference_behavior"] = info(behavior_path) if behavior_path.exists() else None
    record["reference_behavior_passed"] = behavior_path.is_file() and json.loads(behavior_path.read_text())["ok"]
    record["reference_build_steps_complete"] = len(report.get("build_steps", [])) == 5 and all(
        step["exit_code"] == 0 for step in report.get("build_steps", []))
    record["reference_complete"] = bool(record["reference_build_steps_complete"] and record["reference_behavior_passed"]
                                        and record["configured_unit_inventory_complete"] and not record["source_dirty_after"]
                                        and inventory.get("reference_elf", {}).get("minimum_load_address") == 0x02000000)
    write(output / "result.json", record)
    print((output / "capture-command.log").read_text()[-3500:])
    print("RESULT", output / "result.json", flush=True)
    return 0 if record["reference_complete"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["run", "configure", "plan", "build", "inventory", "behavior"])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--archive-directory", type=Path, default=SOURCE_DEFAULT)
    parser.add_argument("--musl-reference", type=Path, default=MUSL_DEFAULT)
    parser.add_argument("--sdk", type=Path, default=SDK_DEFAULT)
    for option in ["source", "build", "capture", "configuration"]:
        parser.add_argument("--" + option, type=Path)
    parser.add_argument("--expected-helper-sha256")
    args = parser.parse_args()
    if args.action == "run":
        if args.output is None:
            parser.error("run requires a new --output directory")
        return outer(args)
    if any(getattr(args, option) is None for option in ["source", "build", "capture", "configuration", "expected_helper_sha256"]):
        parser.error("recipe actions require source/build/capture/configuration/expected-helper-sha256")
    helper(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CaptureError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print("original BusyBox capture: " + str(error), file=sys.stderr)
        raise SystemExit(1)
