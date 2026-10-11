#!/usr/bin/env python3
"""Freeze a Cargo parent-command observer for a new source capture.

The observer runs the original Cargo command with inherited output and records
its actual exit status. A supplementary --unit-graph query retains the exact
observed arguments/environment and is never admitted as source compilation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_artifact(path: Path) -> tuple[bytes, dict]:
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("Cargo observer input changed during observation: " + str(path))
    return raw, {"path": str(path.absolute()), "bytes": len(raw), "sha256": digest(raw)}


def write_json(path: Path, value: object) -> dict:
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
    return {"path": str(path.absolute()), "bytes": len(raw), "sha256": digest(raw)}


def wrapper_source(directory: Path, cargo: str, worker_sha: str, session_sha: str,
                   python: str | None = None) -> str:
    # Literals are Python strings, never shell commands. Fallback preserves the
    # real original command and output when capture provenance is damaged.
    return f'''#!{python or sys.executable}
import hashlib,json,os,pathlib,sys,time,uuid
root=pathlib.Path({str(directory)!r})
cargo={cargo!r}
try:
    worker=(root/'worker.py').read_bytes()
    session=(root/'session.json').read_bytes()
    if hashlib.sha256(worker).hexdigest()!={worker_sha!r}:
        raise ValueError('Cargo observer worker snapshot SHA-256 mismatch')
    if hashlib.sha256(session).hexdigest()!={session_sha!r}:
        raise ValueError('Cargo observer session SHA-256 mismatch')
except Exception as error:
    try:
        path=root/'errors'/(uuid.uuid4().hex+'.json')
        descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(descriptor,'w') as stream:
            json.dump({{'error':str(error),'argv':sys.argv[1:],'time_ns':time.time_ns()}},stream)
    except Exception:
        pass
    os.execv(cargo,[cargo,*sys.argv[1:]])
namespace={{'__name__':'ocore_cargo_observer','__file__':str(root/'worker.py')}}
exec(compile(worker,str(root/'worker.py'),'exec'),namespace)
raise SystemExit(namespace['observe'](root,json.loads(session),sys.argv[1:]))
'''


def prepare(directory: Path, cargo: Path, capture: Path, *, graph_query: bool = True,
            expected_worker_sha256: str | None = None) -> dict:
    directory = directory.absolute()
    capture = capture.absolute()
    cargo = cargo.absolute()
    capture_raw, capture_identity = read_artifact(capture / "session.json")
    capture_session = json.loads(capture_raw)
    capture_worker = capture_session.get("capture_worker")
    if not isinstance(capture_worker, dict) or capture_worker.get("schema") != "ocore-runtime-capture-worker-v1":
        raise ValueError("Cargo observer requires a new snapshot-bound source capture")
    capture_worker_artifact = capture_worker["artifact"]
    worker_raw, worker_identity = read_artifact(Path(capture_worker_artifact["path"]))
    if any(worker_identity[field] != capture_worker_artifact.get(field) for field in ("sha256", "bytes")):
        raise ValueError("source-capture worker does not match its bound snapshot")
    _, cargo_identity = read_artifact(cargo)
    observer_raw, observer_identity = read_artifact(Path(__file__))
    if expected_worker_sha256 is not None and digest(observer_raw) != expected_worker_sha256:
        raise ValueError("Cargo observer source differs from supplied trusted worker SHA-256")
    directory.mkdir(parents=True, exist_ok=False)
    for name in ("events", "queries", "errors", "evidence", "children"):
        (directory / name).mkdir()
    snapshot = directory / "worker.py"
    with snapshot.open("xb") as stream:
        stream.write(observer_raw)
    snapshot.chmod(0o444)
    session = {"schema": "ocore-cargo-parent-observer-session-v1",
        "observer_worker": {"path": str(snapshot), "bytes": len(observer_raw), "sha256": digest(observer_raw)},
        "observer_source": observer_identity, "original_cargo": cargo_identity,
        "python_executable": sys.executable,
        "source_capture": str(capture), "source_capture_session_at_prepare": capture_identity,
        "source_capture_worker": capture_worker, "graph_query_enabled": graph_query,
        "scope": "parent-command/configured-graph evidence only; no compilation or provider admission"}
    session_identity = write_json(directory / "session.json", session)
    (directory / "session.json").chmod(0o444)
    script = wrapper_source(directory, str(cargo), digest(observer_raw), session_identity["sha256"])
    with (directory / "cargo").open("x") as stream:
        stream.write(script)
    (directory / "cargo").chmod(0o555)
    return {"directory": str(directory), "wrapper": str(directory / "cargo"),
            "session": session_identity, "worker_sha256": digest(observer_raw)}


PARENT_VARIABLE = "OCORE_CAPTURE_CARGO_PARENT"
ADMISSION_FIELDS = ("complete", "source_production_inventory_complete", "dependency_closure_complete",
                    "ocore_lowering_complete", "native_execution_qualified", "runtime_complete")


def invocation_id(value: object) -> str:
    if not isinstance(value, str) or len(value) != 32 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("invalid Cargo/compiler invocation ID")
    return value


def checked_artifact(record: dict, expected_path: Path | None = None) -> bytes:
    if not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256"}:
        raise ValueError("invalid Cargo observer artifact identity")
    if (not isinstance(record["path"], str) or type(record["bytes"]) is not int or record["bytes"] < 0 or
            not isinstance(record["sha256"], str) or len(record["sha256"]) != 64 or
            any(c not in "0123456789abcdef" for c in record["sha256"])):
        raise ValueError("invalid Cargo observer artifact identity fields")
    path = Path(record["path"])
    if not path.is_absolute() or path.is_symlink() or (expected_path is not None and path != expected_path.absolute()):
        raise ValueError("Cargo observer artifact path mismatch")
    raw, observed = read_artifact(path)
    if observed != record:
        raise ValueError("Cargo observer artifact identity changed")
    return raw


def parent_binding(directory: Path, session: dict, event_id: str) -> dict:
    _, identity = read_artifact(directory / "session.json")
    return {"id": invocation_id(event_id), "observer_session": identity,
            "observer_worker": session["observer_worker"],
            "source_capture_worker": session["source_capture_worker"]["artifact"]}


def validate_parent_binding(binding: dict, source_worker: dict, trusted_worker_sha256: str,
                            source_capture: str) -> dict:
    if not isinstance(binding, dict) or set(binding) != {
            "id", "observer_session", "observer_worker", "source_capture_worker"}:
        raise ValueError("invalid Cargo parent binding")
    invocation_id(binding["id"])
    session_record = binding["observer_session"]
    root = Path(session_record["path"]).parent
    session = json.loads(checked_artifact(session_record, root / "session.json"))
    if session.get("schema") != "ocore-cargo-parent-observer-session-v1":
        raise ValueError("Cargo parent observer session schema mismatch")
    if session.get("source_capture") != source_capture:
        raise ValueError("Cargo parent source-capture directory mismatch")
    checked_artifact(binding["observer_worker"], root / "worker.py")
    if (binding["observer_worker"] != session.get("observer_worker") or
            binding["observer_worker"]["sha256"] != trusted_worker_sha256):
        raise ValueError("Cargo parent observer worker binding mismatch")
    if (binding["source_capture_worker"] != source_worker or
            session.get("source_capture_worker", {}).get("artifact") != source_worker):
        raise ValueError("Cargo parent source-worker binding mismatch")
    checked_artifact(source_worker)
    return binding


def compiler_children(directory: Path, session: dict, binding: dict, *, check_full_set: bool = False) -> list[dict]:
    """Use only final, explicitly bound receipts; never infer parentage by time."""
    child_directory = directory / "children" / binding["id"]
    result = []
    seen = set()
    if child_directory.exists():
        if not child_directory.is_dir() or child_directory.is_symlink():
            raise ValueError("invalid Cargo compiler-child directory")
        for path in sorted(child_directory.iterdir()):
            if path.suffix != ".json" or not path.is_file() or path.is_symlink():
                raise ValueError("unexpected Cargo compiler-child receipt entry")
            child_id = invocation_id(path.stem)
            raw, receipt_identity = read_artifact(path)
            receipt = json.loads(raw)
            if not isinstance(receipt, dict) or set(receipt) != {
                    "schema", "cargo_parent_invocation_id", "capture_invocation_id", "capture_event",
                    "observer_session", "source_capture_worker"}:
                raise ValueError("invalid Cargo compiler-child receipt schema")
            if (receipt["schema"] != "ocore-cargo-compiler-child-v1" or
                    receipt["cargo_parent_invocation_id"] != binding["id"] or
                    receipt["capture_invocation_id"] != child_id or
                    receipt["observer_session"] != binding["observer_session"] or
                    receipt["source_capture_worker"] != binding["source_capture_worker"]):
                raise ValueError("Cargo compiler-child receipt binding mismatch")
            expected_event = Path(session["source_capture"]) / "events" / (child_id + ".json")
            journal = json.loads(checked_artifact(receipt["capture_event"], expected_event))
            validate_compiler_journal(journal, child_id, binding)
            seen.add(child_id)
            result.append({"receipt": receipt_identity, "capture_invocation_id": child_id,
                           "capture_event": receipt["capture_event"]})
    if check_full_set:
        journal_ids = set()
        for path in (Path(session["source_capture"]) / "events").glob("*.json"):
            journal = json.loads(read_artifact(path)[0])
            if journal.get("cargo_parent_invocation_id") == binding["id"]:
                child_id = invocation_id(journal.get("id"))
                if path.name != child_id + ".json":
                    raise ValueError("Cargo compiler journal filename mismatch")
                validate_compiler_journal(journal, child_id, binding)
                journal_ids.add(child_id)
        if journal_ids != seen:
            raise ValueError("Cargo compiler-child receipt set differs from bound final journals")
    return result


def validate_compiler_journal(journal: dict, child_id: str, binding: dict):
    if (journal.get("id") != child_id or journal.get("kind") not in {"clang", "rustc"} or
            journal.get("state") != "finished" or type(journal.get("exit_code")) is not int or
            journal.get("cargo_parent_invocation_id") != binding["id"] or
            journal.get("cargo_parent") != binding or
            journal.get("capture_worker") != binding["source_capture_worker"]):
        raise ValueError("Cargo compiler journal final parent/worker binding mismatch")


def build_environment(environment: dict[str, str]) -> dict[str, str]:
    prefixes = ("CARGO_", "RUST", "LLVM", "BOOTSTRAP", "CC_", "CXX_", "AR_", "CFLAGS", "CXXFLAGS", "LDFLAGS")
    names = {"PATH", "LD_LIBRARY_PATH", "LIBRARY_PATH", "CC", "CXX", "AR", "RANLIB", "NM", "LD",
             "SOURCE_DATE_EPOCH", "MAKEFLAGS", "MFLAGS", "SCCACHE_DISABLE", "CCACHE_DISABLE"}
    return {key: value for key, value in environment.items() if key in names or key.startswith(prefixes)}


def query_arguments(argv: list[str]) -> list[str] | None:
    # Global Cargo options can precede the command. Do not guess an unknown
    # subcommand or transform rustc's trailing arguments into build options.
    command = None
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in {"-Z", "--config", "--color", "-C"}:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        command = arg
        break
    if command != "build" or "--unit-graph" in argv or "--" in argv:
        return None
    return [*argv, "-Zunstable-options", "--unit-graph"]


def parent_source_inputs(directory: Path, event_id: str, argv: list[str],
                         environment: dict[str, str], source_context: dict) -> list[dict]:
    """Retain declared manifest/lock and configuration candidates before Cargo.

    Discovery candidates are labeled separately from files Cargo actually
    consumed. The configured graph, child journals and dependency inventory
    must establish final source ownership; these snapshots cannot replace them.
    """
    cwd = Path.cwd()
    paths: dict[Path, list[str]] = {}

    def candidate(path: Path, reason: str):
        path = path.absolute()
        if path.is_file():
            paths.setdefault(path, []).append(reason)

    manifest_paths = []
    index = 0
    while index < len(argv):
        value = argv[index]
        if value in {"--manifest-path", "--config"} and index + 1 < len(argv):
            argument = argv[index + 1]
            index += 1
        elif value.startswith("--manifest-path=") or value.startswith("--config="):
            value, argument = value.split("=", 1)
        else:
            index += 1
            continue
        path = Path(argument)
        if not path.is_absolute():
            path = cwd / path
        if value == "--manifest-path":
            manifest_paths.append(path)
            candidate(path, "explicit_parent_manifest_argument")
        elif "=" not in argument:
            candidate(path, "explicit_parent_config_path_candidate")
        index += 1
    for base in [cwd, *(p.parent for p in manifest_paths)]:
        for ancestor in (base, *base.parents):
            candidate(ancestor / "Cargo.toml", "manifest_ancestor_candidate")
            candidate(ancestor / "Cargo.lock", "workspace_lock_candidate")
    for ancestor in (cwd, *cwd.parents):
        for name in ("config", "config.toml"):
            candidate(ancestor / ".cargo" / name, "cwd_ancestor_config_candidate")
    cargo_home = Path(environment.get("CARGO_HOME") or (Path(environment.get("HOME", str(Path.home()))) / ".cargo"))
    for name in ("config", "config.toml"):
        candidate(cargo_home / name, "cargo_home_config_candidate")
    if source_context.get("path"):
        for name in ("Cargo.toml", "Cargo.lock"):
            candidate(Path(source_context["path"]) / name, "declared_capture_source_root")
    result = []
    for index, (path, reasons) in enumerate(paths.items()):
        raw, original = read_artifact(path)
        snapshot = directory / "evidence" / f"{event_id}-source-{index}"
        descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
        result.append({"original": original,
            "snapshot": {"path": str(snapshot.absolute()), "bytes": len(raw), "sha256": digest(raw)},
            "discovery_reasons": reasons, "cargo_consumption_proven": False,
            "source_ownership_admitted": False})
    return result


def wait_original(process: subprocess.Popen) -> tuple[int, int | None]:
    previous = {}
    received = None

    def forward(number, frame):
        nonlocal received
        received = number
        if process.poll() is None:
            process.send_signal(number)

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[sig] = signal.getsignal(sig)
        signal.signal(sig, forward)
    try:
        return process.wait(), received
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def finish(directory: Path, event: dict, status: int) -> int:
    event["finished_ns"] = time.time_ns()
    try:
        write_json(directory / "events" / (event["id"] + ".json"), event)
    except Exception:
        # An unwritable observer cannot interrupt the original source build.
        pass
    if status < 0:
        sig = -status
        if sig not in (signal.SIGKILL, signal.SIGSTOP):
            signal.signal(sig, signal.SIG_DFL)
        os.kill(os.getpid(), sig)
    return status


def observe(directory: Path, session: dict, argv: list[str]) -> int:
    environment = dict(os.environ)
    original_cargo = session["original_cargo"]["path"]
    command = [original_cargo, *argv]
    event_id = uuid.uuid4().hex
    event = {"schema": "ocore-cargo-parent-invocation-v1", "id": event_id,
        "started_ns": time.time_ns(), "cwd": os.getcwd(), "argv": command,
        "observer_worker": session["observer_worker"], "original_cargo": session["original_cargo"],
        "source_capture_worker": session["source_capture_worker"],
        "build_environment": build_environment(environment), "capture_errors": [],
        "graph_query": {"status": "not-applicable"}, "compiler_children": [],
        "cargo_parent_invocation_id": None, "cargo_parent_binding": None,
        "parent_observation_environment": {"variable": PARENT_VARIABLE,
            "inherited": environment.get(PARENT_VARIABLE), "original": environment.get(PARENT_VARIABLE),
            "query": None}, "complete": False,
        "source_production_inventory_complete": False, "dependency_closure_complete": False,
        "ocore_lowering_complete": False, "native_execution_qualified": False, "runtime_complete": False}
    # The complete inherited environment is private evidence. It is never
    # printed. Jobserver descriptors/configuration are retained, not replayable
    # admission credentials.
    original_environment = dict(environment)
    query_environment = dict(environment)
    query_environment.pop(PARENT_VARIABLE, None)
    try:
        event["inherited_environment_record"] = write_json(directory / "evidence" / (event_id + "-environment.json"), environment)
        capture_raw, capture_identity = read_artifact(Path(session["source_capture"]) / "session.json")
        capture_session = json.loads(capture_raw)
        if capture_session.get("capture_worker") != session["source_capture_worker"]:
            raise ValueError("source-capture worker binding changed")
        expected_capture_worker = session["source_capture_worker"]["artifact"]
        _, capture_worker = read_artifact(Path(expected_capture_worker["path"]))
        if any(capture_worker[field] != expected_capture_worker[field] for field in ("sha256", "bytes")):
            raise ValueError("source-capture worker snapshot bytes changed")
        if PARENT_VARIABLE in environment:
            inherited = validate_parent_binding(json.loads(environment[PARENT_VARIABLE]),
                expected_capture_worker, session["observer_worker"]["sha256"], session["source_capture"])
            event["cargo_parent_invocation_id"] = inherited["id"]
        binding = parent_binding(directory, session, event_id)
        event["cargo_parent_binding"] = binding
        original_environment[PARENT_VARIABLE] = json.dumps(binding, sort_keys=True, separators=(",", ":"))
        event["parent_observation_environment"]["original"] = original_environment[PARENT_VARIABLE]
        event["source_capture_session"] = write_json(directory / "evidence" / (event_id + "-capture-session.json"), capture_session)
        event["source_capture_session_original"] = capture_identity
        event["parent_source_context"] = capture_session.get("source", {})
        event["parent_source_inputs"] = parent_source_inputs(directory, event_id, argv, environment,
                                                               event["parent_source_context"])
        _, cargo_identity = read_artifact(Path(original_cargo))
        if any(cargo_identity[field] != session["original_cargo"][field] for field in ("sha256", "bytes")):
            raise ValueError("original Cargo tool bytes changed")
        graph_argv = query_arguments(argv) if session["graph_query_enabled"] else None
        if graph_argv:
            stdout = directory / "queries" / (event_id + "-unit-graph.stdout")
            stderr = directory / "queries" / (event_id + "-unit-graph.stderr")
            query = {"status": "running", "argv": [original_cargo, *graph_argv],
                     "argument_delta": ["-Zunstable-options", "--unit-graph"],
                     "same_parent_environment": PARENT_VARIABLE not in environment, "same_parent_cwd": True,
                     "environment_delta": {PARENT_VARIABLE: {"inherited": environment.get(PARENT_VARIABLE), "query": None}},
                     "source_compilation_admitted": False}
            event["graph_query"] = query
            with stdout.open("xb") as out, stderr.open("xb") as err:
                probe = subprocess.Popen(query["argv"], env=query_environment, stdout=out, stderr=err, close_fds=False)
                query["exit_code"], cancelled = wait_original(probe)
            stdout_raw, query["stdout"] = read_artifact(stdout)
            _, query["stderr"] = read_artifact(stderr)
            changed_metadata = []
            for source_input in event["parent_source_inputs"]:
                _, observed = read_artifact(Path(source_input["original"]["path"]))
                source_input["after_graph_query"] = observed
                unchanged = all(observed[field] == source_input["original"][field] for field in ("sha256", "bytes"))
                source_input["unchanged_after_graph_query"] = unchanged
                if not unchanged:
                    changed_metadata.append(source_input["original"]["path"])
            query["changed_parent_metadata"] = changed_metadata
            if changed_metadata:
                event["capture_errors"].append("supplementary unit-graph query changed parent source metadata")
            if cancelled is not None:
                query["status"] = "cancelled"
                event["upstream_started"] = False
                event["observer_cancelled_before_upstream"] = cancelled
                return finish(directory, event, -cancelled)
            query["status"] = "failed"
            if query["exit_code"] == 0:
                try:
                    graph = json.loads(stdout_raw)
                    if not isinstance(graph, dict) or not isinstance(graph.get("units"), list):
                        raise ValueError("Cargo unit graph lacks units array")
                    query["status"] = "recorded"
                    query["units"] = len(graph["units"])
                    query["graph_version"] = graph.get("version")
                    query["root_unit_indices"] = graph.get("roots")
                except (ValueError, UnicodeError) as error:
                    query["parse_error"] = str(error)
    except Exception as error:
        event["capture_errors"].append(str(error))
        event["graph_query"]["status"] = "capture-error"
    try:
        # Preserve the original command, inherited output streams and environment
        # except the explicitly recorded observation parent binding. Preserve
        # and open non-CLOEXEC descriptors. Capture/query errors never replace
        # an upstream success/failure with a capture-tool status.
        process = subprocess.Popen(command, env=original_environment, close_fds=False)
        event["upstream_started"] = True
        event["upstream_pid"] = process.pid
        status, received = wait_original(process)
        if received is not None:
            event["forwarded_upstream_signal"] = received
    except OSError as error:
        event["upstream_spawn_error"] = str(error)
        status = 127
    event["upstream_exit_code"] = status
    if event["cargo_parent_binding"] is not None:
        try:
            event["compiler_children"] = compiler_children(directory, session, event["cargo_parent_binding"],
                                                           check_full_set=True)
        except Exception as error:
            event["capture_errors"].append("compiler children: " + str(error))
    return finish(directory, event, status)


def verify(directory: Path, expected_worker_sha256: str | None = None) -> dict:
    """Check new observer evidence against an independently trusted worker.

    This checks the observer's own binding, not compiler/source/provider
    admission. A caller embedding the worker supplies its embedded SHA-256.
    """
    expected = expected_worker_sha256 or digest(Path(__file__).read_bytes())
    session_raw, session_identity = read_artifact(directory / "session.json")
    session = json.loads(session_raw)
    if session.get("schema") != "ocore-cargo-parent-observer-session-v1":
        raise ValueError("unsupported Cargo observer session")
    worker_raw, worker_identity = read_artifact(directory / "worker.py")
    if digest(worker_raw) != expected or session["observer_worker"]["sha256"] != expected:
        raise ValueError("Cargo observer differs from trusted worker SHA-256")
    if worker_identity != session["observer_worker"]:
        raise ValueError("Cargo observer worker identity mismatch")
    actual_wrapper, _ = read_artifact(directory / "cargo")
    expected_wrapper = wrapper_source(directory.absolute(), session["original_cargo"]["path"], expected,
                                      session_identity["sha256"], session["python_executable"]).encode()
    if actual_wrapper != expected_wrapper:
        raise ValueError("Cargo observer wrapper differs from bound arguments")
    events = []
    for path in sorted((directory / "events").glob("*.json")):
        raw, identity = read_artifact(path)
        event = json.loads(raw)
        if event.get("observer_worker") != session["observer_worker"] or event.get("original_cargo") != session["original_cargo"]:
            raise ValueError("Cargo parent event differs from observer session")
        if event.get("source_capture_worker") != session["source_capture_worker"]:
            raise ValueError("Cargo parent event source-worker binding mismatch")
        if not event.get("argv") or event["argv"][0] != session["original_cargo"]["path"]:
            raise ValueError("Cargo parent event command mismatch")
        if path.name != invocation_id(event.get("id")) + ".json":
            raise ValueError("Cargo parent event filename mismatch")
        if any(event.get(field) is not False for field in ADMISSION_FIELDS):
            raise ValueError("Cargo observer cannot establish source or lowering admission")
        inherited_env = json.loads(checked_artifact(event["inherited_environment_record"]))
        delta = event.get("parent_observation_environment")
        binding = event.get("cargo_parent_binding")
        expected_original = inherited_env.get(PARENT_VARIABLE)
        if binding is not None:
            expected_binding = parent_binding(directory, session, event["id"])
            if binding != expected_binding:
                raise ValueError("Cargo parent propagation binding mismatch")
            validate_parent_binding(binding, session["source_capture_worker"]["artifact"], expected, session["source_capture"])
            expected_original = json.dumps(binding, sort_keys=True, separators=(",", ":"))
        expected_delta = {"variable": PARENT_VARIABLE, "inherited": inherited_env.get(PARENT_VARIABLE),
                          "original": expected_original, "query": None}
        if delta != expected_delta:
            raise ValueError("Cargo parent environment differences changed")
        nested_parent = None
        if binding is not None and PARENT_VARIABLE in inherited_env:
            nested_parent = validate_parent_binding(json.loads(inherited_env[PARENT_VARIABLE]),
                session["source_capture_worker"]["artifact"], expected, session["source_capture"])["id"]
        if nested_parent is not None:
            inherited_binding = json.loads(inherited_env[PARENT_VARIABLE])
            parent_root = Path(inherited_binding["observer_session"]["path"]).parent
            parent_raw, _ = read_artifact(parent_root / "events" / (nested_parent + ".json"))
            parent_event = json.loads(parent_raw)
            if (nested_parent == event["id"] or parent_event.get("id") != nested_parent or
                    parent_event.get("cargo_parent_binding") != inherited_binding or
                    parent_event.get("observer_worker") != inherited_binding["observer_worker"] or
                    parent_event.get("source_capture_worker") != session["source_capture_worker"]):
                raise ValueError("nested Cargo parent lacks a matching final observer event")
        if event.get("cargo_parent_invocation_id") != nested_parent:
            raise ValueError("nested Cargo parent identity mismatch")
        children = compiler_children(directory, session, binding, check_full_set=True) if binding else []
        if event.get("compiler_children") != children:
            raise ValueError("Cargo parent recorded compiler-child set changed")
        for field in ("inherited_environment_record", "source_capture_session"):
            if field in event:
                _, observed = read_artifact(Path(event[field]["path"]))
                if observed != event[field]:
                    raise ValueError("Cargo parent evidence artifact changed")
        for source_input in event.get("parent_source_inputs", []):
            _, observed = read_artifact(Path(source_input["snapshot"]["path"]))
            if observed != source_input["snapshot"]:
                raise ValueError("Cargo parent source metadata snapshot changed")
        query = event.get("graph_query", {})
        if "argv" in query:
            if (query.get("environment_delta") != {PARENT_VARIABLE: {
                    "inherited": inherited_env.get(PARENT_VARIABLE), "query": None}} or
                    query.get("same_parent_environment") != (PARENT_VARIABLE not in inherited_env)):
                raise ValueError("Cargo query parent exclusion evidence changed")
            derived = query_arguments(event["argv"][1:])
            if derived is None or query["argv"] != [event["argv"][0], *derived]:
                raise ValueError("Cargo unit-graph query changed original arguments")
        for field in ("stdout", "stderr"):
            if field in query:
                _, observed = read_artifact(Path(query[field]["path"]))
                if observed != query[field]:
                    raise ValueError("Cargo unit-graph query artifact changed")
        events.append({"event": identity, "parent_argv": event["argv"],
                       "query_status": query.get("status"), "upstream_exit_code": event.get("upstream_exit_code"),
                       "capture_errors": event.get("capture_errors", []),
                       "cargo_parent_invocation_id": event.get("cargo_parent_invocation_id"),
                       "compiler_children": children})
    event_ids = {Path(event["event"]["path"]).stem for event in events}
    if (directory / "children").is_symlink() or not (directory / "children").is_dir():
        raise ValueError("invalid Cargo compiler-child receipt root")
    for path in (directory / "children").iterdir():
        if path.is_symlink() or not path.is_dir() or invocation_id(path.name) not in event_ids:
            raise ValueError("Cargo compiler-child receipts lack a final parent event")
    # A receipt-free journal for an unknown parent must not disappear merely
    # because no final event enumerates that ID. Only explicit session/worker
    # bindings establish this observer's scope; other capture sessions are not
    # attributed by filenames, timestamps or temporal proximity.
    for path in (Path(session["source_capture"]) / "events").glob("*.json"):
        journal = json.loads(read_artifact(path)[0])
        binding = journal.get("cargo_parent")
        if not isinstance(binding, dict):
            continue
        parent_session = binding.get("observer_session")
        parent_worker = binding.get("observer_worker")
        claims_this_session = (
            isinstance(parent_session, dict) and parent_session.get("path") == session_identity["path"] or
            isinstance(parent_worker, dict) and parent_worker.get("path") == session["observer_worker"]["path"])
        if claims_this_session:
            validate_parent_binding(binding, session["source_capture_worker"]["artifact"], expected, session["source_capture"])
            if binding["observer_session"] != session_identity or binding["id"] not in event_ids:
                raise ValueError("Cargo compiler journal lacks a final parent in its observer session")
            validate_compiler_journal(journal, invocation_id(journal.get("id")), binding)
    errors = [str(path) for path in sorted((directory / "errors").glob("*.json"))]
    return {"schema": "ocore-cargo-observer-verification-v1", "session": session_identity,
            "trusted_worker_sha256": expected, "events": events, "observer_errors": errors,
            "complete": False, "source_production_inventory_complete": False,
            "dependency_closure_complete": False, "ocore_lowering_complete": False,
            "native_execution_qualified": False, "runtime_complete": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--no-unit-graph", action="store_true")
    parser.add_argument("--expected-worker-sha256")
    args = parser.parse_args()
    print(json.dumps(prepare(args.directory, args.cargo, args.capture, graph_query=not args.no_unit_graph,
                             expected_worker_sha256=args.expected_worker_sha256)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
