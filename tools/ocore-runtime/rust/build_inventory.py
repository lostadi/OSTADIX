#!/usr/bin/env python3
"""Snapshot original Rust build metadata and every observed production attempt.

This is a diagnostic inventory, not a source-capture admission or a linker
closure receipt. It never executes Cargo, x.py, Ninja, a recipe, or a journal.
Whole records are retained by hash; retries, cold archive members and unknown
metadata stay inspectable even when a summary cannot interpret them.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import time
import tomllib


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def absolute(value: str | Path, cwd: Path) -> str:
    """Normalize syntax without erasing symlink/copy identities."""
    return os.path.abspath(os.path.join(str(cwd), str(value)))


def identity(value: object) -> str:
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def record(artifact: dict, **location) -> dict:
    """Reference raw metadata once, without repeating it for each graph use."""
    return {"artifact_sha256": artifact["sha256"], **location}


def dependency_tracking_arguments(argv: list[str]) -> tuple[list[str], list[dict]]:
    """Separate only Clang's auxiliary dependency-file flags for diagnostics.

    Original arguments remain unchanged in the inventory. This comparison does
    not establish frontend equivalence or source-capture admission. In
    particular, includes, macros, compiler mode and source/output paths are
    never removed. Malformed paired flags are left unmatched.
    """
    kept, removed, index = [], [], 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            kept.extend(argv[index:])
            break
        if arg in {"-Xclang", "-Xpreprocessor", "-include", "-imacros", "-I", "-D", "-U", "-o", "-x",
                   "-isystem", "-iquote", "-idirafter", "-isysroot", "--sysroot", "-target", "--target"}:
            kept.append(arg)
            if index + 1 < len(argv):
                index += 1
                kept.append(argv[index])
        elif arg in {"-MD", "-MMD", "-MP"}:
            removed.append({"index": index, "arguments": [arg]})
        elif arg in {"-MF", "-MT", "-MQ"} and index + 1 < len(argv):
            removed.append({"index": index, "arguments": argv[index:index + 2]})
            index += 1
        elif any(arg.startswith(flag) and len(arg) > len(flag) for flag in ("-MF", "-MT", "-MQ")):
            removed.append({"index": index, "arguments": [arg]})
        else:
            kept.append(arg)
        index += 1
    return kept, removed


class Evidence:
    def __init__(self, directory: Path):
        self.directory = directory.absolute()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.inputs: list[dict] = []
        self.gaps: list[dict] = []
        self._cache: dict[tuple, dict] = {}

    def gap(self, kind: str, **detail) -> None:
        self.gaps.append({"kind": kind, **detail})

    def retain(self, path: Path) -> tuple[bytes, dict]:
        before = path.stat()
        raw = path.read_bytes()
        after = path.stat()
        sha = digest(raw)
        saved = self.directory / sha
        try:
            with saved.open("xb") as stream:
                stream.write(raw)
            saved.chmod(0o444)
        except FileExistsError:
            if digest(saved.read_bytes()) != sha:
                raise ValueError("retained evidence content changed: " + str(saved))
        artifact = {"path": str(path.absolute()), "sha256": sha, "bytes": len(raw),
                    "snapshot_path": str(saved), "stable_during_read":
                    (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns)}
        if not artifact["stable_during_read"]:
            self.gap("metadata_changed_during_read", artifact=artifact)
        self.inputs.append(artifact)
        return raw, artifact

    def json(self, path: Path) -> tuple[object | None, dict]:
        try:
            raw, artifact = self.retain(path)
        except OSError as error:
            artifact = {"path": str(path.absolute()), "status": "unavailable"}
            self.gap("unavailable_metadata", artifact=artifact, message=str(error))
            return None, artifact
        try:
            return json.loads(raw), artifact
        except (ValueError, UnicodeError) as error:
            self.gap("malformed_metadata", artifact=artifact, message=str(error))
            return None, artifact

    def observe(self, expected: dict, *, verify: bool = True) -> dict:
        """Check current bytes; a recorded digest is never fresh verification."""
        path = Path(expected["path"])
        base = {"recorded": expected}
        try:
            before = path.stat()
            key = (str(path.absolute()), before.st_dev, before.st_ino,
                   before.st_size, before.st_mtime_ns, before.st_ctime_ns, verify)
            if key not in self._cache:
                actual = {"path": str(path.absolute()), "resolved_path": str(path.resolve()),
                          "bytes": before.st_size}
                if verify:
                    h = hashlib.sha256()
                    with path.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            h.update(chunk)
                    actual["sha256"] = h.hexdigest()
                after = path.stat()
                actual["stable_during_read"] = (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                self._cache[key] = actual
            actual = self._cache[key]
            matches = actual["stable_during_read"] and (
                expected.get("bytes", actual["bytes"]) == actual["bytes"])
            if verify:
                matches = matches and expected.get("sha256", actual["sha256"]) == actual["sha256"]
            base.update(observed=actual, status=("hash_verified" if matches and verify
                                               else "stat_only" if matches else "mismatch"))
        except OSError as error:
            base.update(status="unavailable", message=str(error))
        return base


def rust_arguments(args: list[str]) -> dict:
    """Retain repeated flags and distinguish target, metadata and CGU settings."""
    values: dict[str, list[str]] = defaultdict(list)
    codegen, unstable = [], []
    paired = {"--crate-name", "--crate-type", "--target", "--edition", "--emit",
              "--out-dir", "--extern", "--cfg", "--sysroot", "--manifest-path", "-o", "-L"}
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in paired or arg in {"-C", "-Z"}:
            if index + 1 == len(args):
                values["malformed_flags"].append(arg)
            else:
                index += 1
                if arg == "-C":
                    codegen.append(args[index])
                elif arg == "-Z":
                    unstable.append(args[index])
                else:
                    values[arg].append(args[index])
        elif arg.startswith(("-C", "-Z")) and len(arg) > 2:
            (codegen if arg.startswith("-C") else unstable).append(arg[2:])
        else:
            for flag in paired:
                if arg.startswith(flag + "="):
                    values[flag].append(arg[len(flag) + 1:])
                    break
        index += 1
    cfg = values.get("--cfg", [])
    return {"flags": dict(values), "codegen": codegen, "unstable": unstable,
            "features": sorted({m.group(1) for item in cfg
                                if (m := re.fullmatch(r'feature="(.*)"', item))}),
            "target_explicit": values.get("--target", []),
            "crate_types": [kind for item in values.get("--crate-type", []) for kind in item.split(",")],
            "cgu_count_requested": [x.split("=", 1)[1] for x in codegen if x.startswith("codegen-units=")],
            "metadata_disambiguators": [x.split("=", 1)[1] for x in codegen if x.startswith("metadata=")],
            "extra_filenames": [x.split("=", 1)[1] for x in codegen if x.startswith("extra-filename=")],
            "optimization": [x.split("=", 1)[1] for x in codegen if x.startswith("opt-level=")]}


def ninja_lines(text: str):
    """Join Ninja's escaped physical newlines, preserving original line IDs."""
    pending, start = "", 1
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        else:
            line = line.lstrip()
        pending += line
        trailing = len(pending) - len(pending.rstrip("$"))
        if trailing % 2:
            pending = pending[:-1]
            continue
        yield start, pending
        pending = ""
    if pending:
        raise ValueError("unterminated Ninja line continuation")


def ninja_expand(text: str, variables: dict[str, str]) -> str:
    def replace(match):
        token = match.group(1)
        if token in {"$", " ", ":"}:
            return token
        name = token[1:-1] if token.startswith("{") else token
        if name not in variables:
            raise ValueError("unresolved Ninja variable: " + name)
        return variables[name]
    return re.sub(r"\$(\$| |:|\{[^}]+\}|[A-Za-z0-9_.-]+)", replace, text)


def ninja_paths(text: str, variables: dict[str, str]) -> list[str]:
    """Tokenize before expansion so an escaped space stays within one path."""
    result, token, index = [], "", 0
    while index < len(text):
        char = text[index]
        if char == "$":
            match = re.match(r"\$(\$| |:|\{[^}]+\}|[A-Za-z0-9_.-]+)", text[index:])
            if not match:
                raise ValueError("invalid Ninja escape")
            token += ninja_expand(match.group(0), variables)
            index += len(match.group(0))
            continue
        if char.isspace():
            if token:
                result.append(token)
                token = ""
        elif char == "#" and not token:
            break
        elif char in ":|":
            if token:
                result.append(token)
                token = ""
            delimiter = char
            if char == "|" and index + 1 < len(text) and text[index + 1] in "|@":
                index += 1
                delimiter += text[index]
            result.append(delimiter)
        else:
            token += char
        index += 1
    if token:
        result.append(token)
    return result


def ninja_graph(path: Path, evidence: Evidence) -> list[dict]:
    """Read configured DAG edges, including phony/generator/native tool actions.

    Rule commands remain uninterpreted, SHA-bound metadata. Unknown directives
    or variables produce gaps instead of an invented edge or shell execution.
    """
    actions, active = [], set()
    root = path.parent.absolute()

    def read(current: Path, variables: dict[str, str]):
        name = str(current.absolute())
        if name in active:
            evidence.gap("ninja_include_cycle", path=name)
            return
        active.add(name)
        try:
            raw, artifact = evidence.retain(current)
            last = None
            for line, text in ninja_lines(raw.decode()):
                if not text.strip() or text.lstrip().startswith("#"):
                    continue
                if text[0].isspace():
                    if last is not None:
                        last.setdefault("bindings", []).append({"line": line, "text": text})
                    continue
                last = None
                try:
                    if text.startswith("build "):
                        tokens = ninja_paths(text[6:], variables)
                        colon = tokens.index(":")
                        outputs = {"explicit": [], "implicit": []}
                        category = "explicit"
                        for token in tokens[:colon]:
                            if token == "|":
                                category = "implicit"
                            else:
                                outputs[category].append(absolute(token, root))
                        rule = tokens[colon + 1]
                        inputs = {"explicit": [], "implicit": [], "order_only": [], "validation": []}
                        category = "explicit"
                        for token in tokens[colon + 2:]:
                            if token in {"|", "||", "|@"}:
                                category = {"|": "implicit", "||": "order_only", "|@": "validation"}[token]
                            else:
                                inputs[category].append(absolute(token, root))
                        if not outputs["explicit"]:
                            raise ValueError("Ninja action has no explicit output")
                        last = {"id": f"ninja:{artifact['sha256']}:{line}", "kind": "ninja",
                                "record": record(artifact, line=line), "rule": rule,
                                "outputs": outputs, "inputs": inputs, "variables": dict(variables),
                                "raw": text, "cwd": str(root)}
                        actions.append(last)
                    elif text.startswith(("include ", "subninja ")):
                        directive, target = text.split(None, 1)
                        expanded = ninja_expand(target, variables)
                        read(Path(absolute(expanded, root)), variables if directive == "include" else dict(variables))
                    elif text.startswith(("rule ", "pool ")):
                        last = {"directive": text, "bindings": []}
                    elif text.startswith("default "):
                        ninja_paths(text[8:], variables)
                    elif "=" in text:
                        key, value = text.split("=", 1)
                        variables[key.strip()] = ninja_expand(value.strip(), variables)
                    else:
                        raise ValueError("unknown Ninja directive")
                except (ValueError, IndexError, OSError) as error:
                    evidence.gap("unparsed_ninja_record", artifact=artifact, line=line,
                                 text=text, message=str(error))
        except (OSError, UnicodeError, ValueError) as error:
            evidence.gap("unavailable_ninja_metadata", path=name, message=str(error))
        finally:
            active.remove(name)
    read(path, {})
    return actions


def source_manifests(paths: list[Path], evidence: Evidence) -> list[dict]:
    """Follow all declared local dependency/workspace paths, not a crate allowlist.

    Manifests are a source superset. Optional/cfg/dev dependencies remain recorded;
    resolving a package never proves it was configured, built, or linked.
    """
    rows, seen, queue = [], set(), list(paths)
    while queue:
        path = queue.pop().absolute()
        if str(path) in seen:
            continue
        seen.add(str(path))
        try:
            raw, artifact = evidence.retain(path)
            doc = tomllib.loads(raw.decode())
        except (OSError, ValueError, UnicodeError) as error:
            evidence.gap("unavailable_source_manifest", path=str(path), message=str(error))
            continue
        row = {"artifact": artifact, "package": doc.get("package"),
               "workspace": doc.get("workspace"), "targets": {key: doc[key] for key in
                   ("lib", "bin", "example", "test", "bench") if key in doc},
               "features": doc.get("features", {}), "profiles": doc.get("profile", {}),
               "dependency_tables": [], "configured_or_built": False}
        rows.append(row)
        tables = [(key, value) for key, value in doc.items() if key.endswith("dependencies")]
        tables += [(f"target.{condition}.{key}", value) for condition, target in doc.get("target", {}).items()
                   for key, value in target.items() if key.endswith("dependencies")]
        tables += [("workspace.dependencies", doc.get("workspace", {}).get("dependencies", {}))]
        tables += [(f"patch.{name}", value) for name, value in doc.get("patch", {}).items()]
        for name, table in tables:
            row["dependency_tables"].append({"name": name, "entries": table})
            for dependency in table.values():
                if isinstance(dependency, dict) and "path" in dependency:
                    queue.append(Path(absolute(dependency["path"], path.parent)) / "Cargo.toml")
        for member in doc.get("workspace", {}).get("members", []):
            matches = sorted(path.parent.glob(member))
            if not matches:
                evidence.gap("unavailable_workspace_member", manifest=artifact, pattern=member)
            queue.extend(candidate / "Cargo.toml" for candidate in matches)
    return rows


def cargo_graph(path: Path, evidence: Evidence) -> list[dict]:
    graph, artifact = evidence.json(path)
    if not isinstance(graph, dict) or graph.get("version") != 1 or not isinstance(graph.get("units"), list):
        evidence.gap("unsupported_cargo_unit_graph", artifact=artifact)
        return []
    units = graph["units"]
    rows = []
    for index, unit in enumerate(units):
        if not isinstance(unit, dict):
            evidence.gap("malformed_cargo_unit", artifact=artifact, index=index)
            continue
        dependencies = unit.get("dependencies", [])
        for dep in dependencies:
            if not isinstance(dep, dict) or not isinstance(dep.get("index"), int) or isinstance(dep["index"], bool) or not 0 <= dep["index"] < len(units):
                evidence.gap("invalid_cargo_graph_edge", artifact=artifact, index=index, dependency=dep)
        rows.append({"id": f"cargo:{artifact['sha256']}:{index}", "kind": "cargo",
                     "record": record(artifact, pointer=f"/units/{index}"),
                     "unit": unit, "dependency_ids": [f"cargo:{artifact['sha256']}:{dep['index']}"
                         for dep in dependencies if isinstance(dep, dict) and isinstance(dep.get("index"), int) and
                         not isinstance(dep["index"], bool) and 0 <= dep["index"] < len(units)],
                     "is_root": index in graph.get("roots", [])})
    for root in graph.get("roots", []):
        if not isinstance(root, int) or isinstance(root, bool) or not 0 <= root < len(units):
            evidence.gap("invalid_cargo_graph_root", artifact=artifact, root=root)
    return rows


def ninja_log(path: Path, evidence: Evidence) -> list[dict]:
    raw, artifact = evidence.retain(path)
    rows = []
    version = None
    for line, text in enumerate(raw.decode().splitlines(), 1):
        if line == 1:
            # v5 (Ninja 1.11) and v7 (Ninja 1.13) both serialize these five
            # fields. Preserve the version: their command hashes differ and
            # neither is a source/object content hash or an admission receipt.
            match = re.fullmatch(r"# ninja log v(5|7)", text)
            if not match:
                evidence.gap("unsupported_ninja_log_version", artifact=artifact, header=text)
                return []
            version = int(match.group(1))
            continue
        fields = text.split("\t")
        try:
            if len(fields) != 5:
                raise ValueError("expected five Ninja log fields")
            if not re.fullmatch(r"[0-9a-fA-F]{1,16}", fields[4]):
                raise ValueError("expected an unsigned 64-bit hexadecimal command hash")
            rows.append({"id": f"ninja-log:{artifact['sha256']}:{line}",
                         "record": record(artifact, line=line), "log_version": version,
                         "start_ms": int(fields[0]), "end_ms": int(fields[1]),
                         "mtime": int(fields[2]), "output": absolute(fields[3], path.parent),
                         "command_hash": fields[4], "frontend_capture_qualified": False})
        except ValueError as error:
            evidence.gap("malformed_ninja_execution_record", artifact=artifact, line=line, message=str(error))
    return rows


def compile_commands(path: Path, evidence: Evidence) -> list[dict]:
    graph, artifact = evidence.json(path)
    if not isinstance(graph, list):
        evidence.gap("unsupported_compile_commands", artifact=artifact)
        return []
    rows = []
    for index, entry in enumerate(graph):
        try:
            cwd = Path(entry["directory"])
            argv = entry.get("arguments") or shlex.split(entry["command"])
            if not isinstance(argv, list) or not all(isinstance(arg, str) for arg in argv):
                raise ValueError("compiler arguments require strings")
            output = entry.get("output")
            if output is None and "-o" in argv:
                output = argv[argv.index("-o") + 1]
            rows.append({"id": f"native:{artifact['sha256']}:{index}", "kind": "native_compile",
                         "record": record(artifact, pointer=f"/{index}"),
                         "cwd": str(cwd), "argv": argv, "source": absolute(entry["file"], cwd),
                         "output": absolute(output, cwd) if output else None,
                         "assembly": Path(entry["file"]).suffix.lower() == ".s"})
        except (KeyError, IndexError, TypeError, ValueError) as error:
            evidence.gap("unparsed_compile_command", artifact=artifact, index=index, message=str(error))
    return rows


def inventory(source: Path, build: Path, capture: Path, evidence_dir: Path, *,
              cargo_graphs=(), cargo_metadata=(), cargo_messages=(), native_graphs=(),
              ninja_files=(), manifests=(), extra_metadata=(), verify_artifacts=True) -> dict:
    source, build, capture = source.absolute(), build.absolute(), capture.absolute()
    evidence = Evidence(evidence_dir)
    started = time.time_ns()
    _, inventory_tool = evidence.retain(Path(__file__))
    session, session_artifact = evidence.json(capture / "session.json")
    if not isinstance(session, dict):
        raise ValueError("source capture session metadata must be a JSON object")
    steps = session.get("build_steps", [])
    for index, step in enumerate(steps):
        if step.get("exit_code") != 0 or not step.get("finished_ns"):
            evidence.gap("uncompleted_declared_build_step", index=index, step=step)
    configured, attempts, units, outputs = [], [], [], []
    requirements: dict[tuple, dict] = {}
    event_ids, unit_ids = set(), set()
    retry_groups, source_attempts = defaultdict(list), defaultdict(list)
    manifests = [Path(p) for p in manifests]
    if (source / "Cargo.toml").is_file():
        manifests.append(source / "Cargo.toml")
    for step in steps:
        args = step.get("argv", [])
        for arg in args:
            candidate = Path(absolute(arg, Path(step.get("cwd", str(source))))) / "Cargo.toml"
            if not arg.startswith("-") and candidate.is_file():
                manifests.append(candidate)
    for path in cargo_graphs:
        configured.extend(cargo_graph(Path(path), evidence))
    for path in native_graphs:
        configured.extend(compile_commands(Path(path), evidence))
    for path in ninja_files:
        configured.extend(ninja_graph(Path(path), evidence))
    ninja_executions = []
    for path in ninja_files:
        log = Path(path).parent / ".ninja_log"
        if log.is_file():
            ninja_executions.extend(ninja_log(log, evidence))
    if not cargo_graphs:
        evidence.gap("no_configured_cargo_unit_graph")
    if not native_graphs:
        evidence.gap("no_configured_native_compile_graph")
    if not ninja_files:
        evidence.gap("no_configured_native_action_graph")
    configurations = []
    for path in [build / "bootstrap.toml", source / "x.py", source / "Cargo.lock", *map(Path, extra_metadata)]:
        try:
            raw, artifact = evidence.retain(path)
            if path.suffix == ".toml" or path.name == "Cargo.lock":
                configurations.append({"artifact": artifact, "toml": tomllib.loads(raw.decode())})
        except (OSError, ValueError, UnicodeError) as error:
            evidence.gap("unavailable_build_metadata", path=str(path), message=str(error))
    for path in cargo_metadata:
        metadata, artifact = evidence.json(Path(path))
        if not isinstance(metadata, dict) or not isinstance(metadata.get("packages"), list):
            evidence.gap("unsupported_cargo_package_metadata", artifact=artifact)
            continue
        manifests.extend(Path(package["manifest_path"]) for package in metadata["packages"] if "manifest_path" in package)
        # The complete resolve graph, features, targets and package checksums
        # remain in the retained metadata, not reduced to a fixed crate list.

    messages = []
    for path in cargo_messages:
        raw, artifact = evidence.retain(Path(path))
        for line, text in enumerate(raw.decode().splitlines(), 1):
            try:
                item = json.loads(text)
            except ValueError:
                evidence.gap("non_json_cargo_message", artifact=artifact, line=line)
                continue
            messages.append({"id": f"cargo-message:{artifact['sha256']}:{line}",
                             "record": record(artifact, line=line), "message": item})
            if item.get("manifest_path"):
                manifests.append(Path(item["manifest_path"]))

    journal_paths = sorted((capture / "events").glob("*.json"))
    for path in journal_paths:
        event, artifact = evidence.json(path)
        if not isinstance(event, dict):
            continue
        event_id = event.get("id")
        if not isinstance(event_id, str) or not event_id:
            evidence.gap("missing_capture_action_id", artifact=artifact)
            continue
        if event_id in event_ids:
            evidence.gap("duplicate_capture_action_id", id=event_id, artifact=artifact)
        event_ids.add(event_id)
        cwd = Path(event.get("cwd", str(source)))
        argv = event.get("expanded_argv", event.get("argv", []))
        environment = event.get("build_environment", {})
        group = identity({"kind": event.get("kind"), "compiler": event.get("compiler"),
                          "cwd": str(cwd), "argv": argv, "environment": environment})
        retry_groups[group].append(event_id)
        action = {key: event.get(key) for key in ("id", "kind", "driver_kind", "compiler", "frontend",
                  "cwd", "argv", "expanded_argv", "build_step", "build_environment", "classification",
                  "started_ns", "finished_ns", "state", "exit_code", "replay_argv", "replay_exit_code",
                  "capture_worker", "capture_errors", "translation_required", "response_files", "sources",
                  "parent_invocation_id", "native_tool_invocation_ids", "tool")}
        action.update(record=record(artifact, pointer=""), attempt_group=group,
                      occurrence_id=f"capture:{artifact['sha256']}:{event_id}",
                      unit_ids=[], output_ids=[], rust=(rust_arguments(argv) if event.get("kind") == "rustc" else None),
                      link_inputs_record=record(artifact, pointer="/link_inputs"),
                      native_linkage_record=record(artifact, pointer="/native_linkage"))
        attempts.append(action)
        if environment.get("CARGO_MANIFEST_DIR"):
            manifests.append(Path(environment["CARGO_MANIFEST_DIR"]) / "Cargo.toml")
        if event.get("state") != "finished" or event.get("exit_code") != 0:
            evidence.gap("unfinished_or_failed_capture_action", action_id=event_id)
        for error in event.get("capture_errors", []):
            evidence.gap("capture_action_error", action_id=event_id, message=error)
        for item in event.get("sources", []):
            source_attempts[absolute(item["path"], cwd)].append(action)
        for index, output in enumerate(event.get("outputs", [])):
            out_id = f"{event_id}:output:{index}"
            action["output_ids"].append(out_id)
            outputs.append({"id": out_id, "action_id": event_id,
                            "action_occurrence_id": action["occurrence_id"],
                            "record": record(artifact, pointer=f"/outputs/{index}"),
                            "artifact": output,
                            "current": evidence.observe(output, verify=verify_artifacts)})
            if outputs[-1]["current"]["status"] in {"mismatch", "unavailable"}:
                evidence.gap("output_artifact_integrity", output_id=out_id, current=outputs[-1]["current"])
        for index, unit in enumerate(event.get("units", [])):
            unit_id = unit.get("id")
            if not isinstance(unit_id, str) or unit_id in unit_ids:
                evidence.gap("missing_or_duplicate_capture_unit_id", action_id=event_id, unit_id=unit_id)
            unit_ids.add(unit_id)
            action["unit_ids"].append(unit_id)
            current = {}
            for kind in ["source", "ir"]:
                if kind in unit:
                    current[kind] = evidence.observe(unit[kind], verify=verify_artifacts)
                    if current[kind]["status"] in {"mismatch", "unavailable"}:
                        evidence.gap("captured_input_integrity", unit_id=unit_id, field=kind, current=current[kind])
            units.append({"id": unit_id, "kind": unit.get("kind", event.get("kind")),
                          "source": unit.get("source", {}).get("path"), "source_artifact": unit.get("source"),
                          "ir": unit.get("ir"), "target_triple": unit.get("ir", {}).get("target_triple"),
                          "build_step": event.get("build_step"), "invocation_ids": [event_id],
                          "invocation_occurrence_ids": [action["occurrence_id"]],
                          "record": record(artifact, pointer=f"/units/{index}"),
                          "dependency_count": len(unit.get("dependencies", [])),
                          "dependencies_record": record(artifact, pointer=f"/units/{index}/dependencies"),
                          "cgu_output_name": Path(unit["ir"]["path"]).name if "ir" in unit else None,
                          "event_output_ids": action["output_ids"],
                          "cgu_to_output_member_mapping": "not_proven", "current": current})
            if "ir" not in unit:
                evidence.gap("captured_unit_has_no_llvm_ir", unit_id=unit_id, kind=unit.get("kind"))
            for dep_index, dependency in enumerate(unit.get("dependencies", [])):
                if not isinstance(dependency, dict) or "path" not in dependency:
                    evidence.gap("malformed_dependency_artifact", unit_id=unit_id, index=dep_index)
                    continue
                key = (dependency["path"], dependency.get("sha256"), dependency.get("bytes"))
                if key not in requirements:
                    requirements[key] = {"artifact": dependency, "uses": []}
                requirements[key]["uses"].append({"action_id": event_id, "unit_id": unit_id,
                    "action_occurrence_id": action["occurrence_id"],
                    "record": record(artifact, pointer=f"/units/{index}/dependencies/{dep_index}")})

    for action in configured:
        candidates = []
        if action["kind"] == "native_compile":
            candidates = source_attempts.get(action["source"], [])
            exact = [a for a in candidates if a["cwd"] == action["cwd"]
                     and (a["expanded_argv"] or a["argv"] or []) == action["argv"][1:]]
            plan_args, plan_tracking = dependency_tracking_arguments(action["argv"][1:])
            normalized = []
            for candidate in candidates:
                args, tracking = dependency_tracking_arguments(candidate["expanded_argv"] or candidate["argv"] or [])
                if candidate["cwd"] == action["cwd"] and args == plan_args:
                    normalized.append({"action_id": candidate["id"],
                                       "action_occurrence_id": candidate["occurrence_id"],
                                       "removed_configured_arguments": plan_tracking,
                                       "removed_captured_arguments": tracking})
            action.update(candidate_attempt_ids=[a["id"] for a in candidates],
                          candidate_occurrence_ids=[a["occurrence_id"] for a in candidates],
                          exact_argv_attempt_ids=[a["id"] for a in exact],
                          exact_argv_occurrence_ids=[a["occurrence_id"] for a in exact],
                          dependency_tracking_comparison=normalized,
                          compiler_identity_matching="not_proven_from_argument_comparison",
                          source_capture_admission_qualified=False)
            if action["assembly"]:
                evidence.gap("assembly_requires_explicit_importer", configured_action_id=action["id"], source=action["source"])
            if not normalized:
                evidence.gap("native_configured_action_unobserved_or_argv_unmatched", configured_action_id=action["id"],
                             candidate_attempt_ids=action["candidate_attempt_ids"],
                             candidate_occurrence_ids=action["candidate_occurrence_ids"])
        elif action["kind"] == "cargo":
            unit = action["unit"]
            target = unit.get("target", {})
            src = target.get("src_path")
            candidates = source_attempts.get(absolute(src, source), []) if src else []
            candidates = [a for a in candidates if a["kind"] == "rustc" and
                          target.get("name", "").replace("-", "_") in a["rust"]["flags"].get("--crate-name", [])]
            action["candidate_attempt_ids"] = [a["id"] for a in candidates]
            action["candidate_occurrence_ids"] = [a["occurrence_id"] for a in candidates]
            action["configured_profile_matching"] = "not_proven_from_source_and_crate_name"
            if not candidates or unit.get("mode") == "run-custom-build":
                evidence.gap("cargo_configured_action_not_proven", configured_action_id=action["id"], mode=unit.get("mode"),
                             candidate_attempt_ids=action["candidate_attempt_ids"],
                             candidate_occurrence_ids=action["candidate_occurrence_ids"])
        else:
            action["capture_output_producer_ids"] = []

    producers: dict[tuple, list[str]] = defaultdict(list)
    producer_paths: dict[str, set[str]] = defaultdict(set)
    ninja_producers: dict[str, list[str]] = defaultdict(list)
    for output in outputs:
        recorded = output["artifact"]
        producers[(recorded["path"], recorded.get("sha256"))].append(output["action_id"])
        producer_paths[recorded["path"]].add(output["action_id"])
    for action in configured:
        if action["kind"] == "ninja":
            for filename in action["outputs"]["explicit"] + action["outputs"]["implicit"]:
                ninja_producers[filename].append(action["id"])
            action["capture_output_producer_ids"] = sorted({a for filename in
                action["outputs"]["explicit"] + action["outputs"]["implicit"]
                for a in producer_paths.get(filename, [])})
    # Every dependency occurrence still resolves to its original record. Only
    # the artifact summary is aggregated; repeated uses and attempts are not.
    dependencies = {}
    for key, requirement in requirements.items():
        recorded = requirement["artifact"]
        dependencies[key] = {"artifact": recorded, "uses": requirement["uses"],
                             "current": evidence.observe(recorded, verify=verify_artifacts),
                             "same_path_content_producer_ids": producers.get(key[:2], []),
                             "configured_ninja_producer_ids": ninja_producers.get(recorded["path"], [])}
    for dep in dependencies.values():
        recorded = dep["artifact"]
        native = Path(recorded["path"]).suffix.lower() in {".o", ".obj", ".a", ".rlib", ".rmeta", ".so", ".dylib", ".dll", ".bc"} or bool(re.search(r"\.so(?:\.[0-9]+)+$", recorded["path"]))
        generated = Path(recorded["path"]).is_relative_to(build)
        dep.update(binary_input=native, inside_build_tree=generated)
        if dep["current"]["status"] in {"mismatch", "unavailable"}:
            evidence.gap("dependency_artifact_integrity", artifact=recorded, current=dep["current"])
        if native and not dep["same_path_content_producer_ids"]:
            evidence.gap("binary_dependency_source_production_unproven", artifact=recorded,
                         configured_ninja_producer_ids=dep["configured_ninja_producer_ids"])
        elif generated and not dep["same_path_content_producer_ids"]:
            evidence.gap("generated_input_production_unproven", artifact=recorded,
                         configured_ninja_producer_ids=dep["configured_ninja_producer_ids"])

    required_outputs = []
    for pattern in session.get("recipe", {}).get("coverage", {}).get("required_outputs", []):
        found = sorted(build.glob(pattern))
        required_outputs.append({"pattern": pattern, "observed_paths": [str(p) for p in found],
                                 "source_and_link_membership_qualified": False})
        if not found:
            evidence.gap("required_runtime_output_unobserved", pattern=pattern)
    manifest_rows = source_manifests(manifests, evidence)
    stages = sorted({str((a.get("build_environment") or {}).get("RUSTC_STAGE")) for a in attempts
                     if (a.get("build_environment") or {}).get("RUSTC_STAGE") is not None})
    evidence.gap("bootstrap_stage_graph_coverage_unproven",
                 reason="Supplied Cargo graphs retain their own invocation scope; no graph is inferred for other x.py stages.")
    evidence.gap("ordered_provider_closure_not_qualified",
                 reason="Source-production candidates do not prove archive extraction, linker selection, native dependencies or final output membership.")
    return {"schema": "ocore-runtime-unit-inventory-v1", "inventory_kind": "rust-full-source-build-diagnostic",
            "complete": False, "inventory_tool": inventory_tool,
            "raw_record_reference": "artifact_sha256 identifies a byte-exact entry in metadata_inputs; pointer is an RFC 6901 JSON pointer; line is one-based",
            "source": session.get("source"), "session": session_artifact,
            "build_configurations": configurations, "ninja_execution_records": ninja_executions,
            "requested_build_steps": steps, "compiler_stage_environment_values_observed": stages,
            "source_manifest_superset": manifest_rows, "configured_actions": configured,
            "invocations": attempts, "attempt_groups": dict(retry_groups), "units": units,
            "outputs": outputs, "dependency_artifacts": list(dependencies.values()),
            "cargo_messages": messages, "required_runtime_outputs": required_outputs,
            "metadata_inputs": evidence.inputs, "gaps": evidence.gaps,
            "summary": {"journals_at_snapshot": len(journal_paths), "invocations": len(attempts),
                        "captured_units": len(units), "outputs": len(outputs),
                        "configured_action_kinds": dict(Counter(a["kind"] for a in configured)),
                        "gap_kinds": dict(Counter(g["kind"] for g in evidence.gaps))},
            "observation_started_ns": started, "observation_finished_ns": time.time_ns(),
            "integrity_mode": "hash" if verify_artifacts else "stat_only",
            "non_lowering_units": [], "source_production_inventory_complete": False,
            "runtime_output_membership_complete": False, "dependency_closure_complete": False,
            "native_execution_qualified": False, "runtime_complete": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("source", "build", "capture", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    for flag in ("cargo-unit-graph", "cargo-metadata", "cargo-messages", "compile-commands",
                 "ninja", "manifest", "metadata"):
        parser.add_argument("--" + flag, type=Path, action="append", default=[])
    parser.add_argument("--stat-only", action="store_true",
                        help="Retain expected hashes but explicitly leave current artifact content unverified")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be a new immutable observation path")
    result = inventory(args.source, args.build, args.capture, args.output.with_suffix(".evidence"),
                       cargo_graphs=args.cargo_unit_graph, cargo_metadata=args.cargo_metadata,
                       cargo_messages=args.cargo_messages, native_graphs=args.compile_commands,
                       ninja_files=args.ninja, manifests=args.manifest, extra_metadata=args.metadata,
                       verify_artifacts=not args.stat_only)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        # Lossless compact encoding plus shared raw-record references keeps a
        # full inventory practical without truncating actions or graph edges.
        json.dump(result, stream, separators=(",", ":"), sort_keys=True)
        stream.write("\n")
    print(json.dumps({"path": str(args.output.absolute()), "sha256": file_digest(args.output),
                      "summary": result["summary"], "complete": False, "runtime_complete": False}))


if __name__ == "__main__":
    main()
