#!/usr/bin/env python3
"""Capture source-built runtime/compiler LLVM units without claiming O-core support.

By default compiler wrappers execute the original command unchanged, then replay
successful translation units into a separate LLVM-output directory. The explicit
rust-embedded-bc-v1 policy instead records and executes an instrumented Rust
command, retaining same-producer ELF embedded bitcode without a frontend replay.
Every invocation gets an
atomic journal record, including failed probes and unsupported assembly. A capture
is not a linker, an LLVM importer, a sandbox, or an OSTADIX platform port.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

RECIPE_SCHEMA = "ocore-runtime-recipe-v1"
REPORT_SCHEMA = "ocore-runtime-capture-v1"
INVENTORY_SCHEMA = "ocore-runtime-unit-inventory-v1"
CARGO_PARENT_VARIABLE = "OCORE_CAPTURE_CARGO_PARENT"
# Filled only from the independently registered observer implementation. Neither
# a supplied parent record nor its session may choose the production worker.
REGISTERED_CARGO_OBSERVER_SHA256 = "9e10e5fd5a95c196bc1f8403a3180d450b477a419abc4774316a12fbe3f40993"
RUST_EMBEDDED_POLICY = "rust-embedded-bc-v1"
REGISTERED_RUST_PAYLOAD_SHA256 = "0190404305ffa887b60d5f23e9af64029c1fe770ce6c705d19a65ee3a89d6767"
NATIVE_TOOL_KINDS = {"ld": "linker", "ld.lld": "linker", "ld.bfd": "linker",
                     "ld.gold": "linker", "ar": "archive", "llvm-ar": "archive",
                     "ranlib": "archive-index", "llvm-ranlib": "archive-index"}
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".C", ".m", ".mm"}
ASM_SUFFIXES = {".s", ".S", ".asm"}
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx"}
HEADER_LANGUAGES = {"c-header", "c++-header", "objective-c-header", "objective-c++-header"}
PAIR_OPTIONS = {"-o", "-I", "-D", "-U", "-include", "-imacros", "-isystem",
                "-include-pch", "-include-pth",
                "-iquote", "-idirafter", "-isysroot", "--sysroot", "-target",
                "--target", "-x", "-Xclang", "-Xpreprocessor", "-Xlinker",
                "-mllvm", "-B", "-resource-dir", "-MF", "-MT", "-MQ",
                "-gcc-toolchain", "--gcc-toolchain"}


class CaptureError(Exception):
    pass


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise CaptureError(f"{path}: expected a JSON object")
    return value


def file_info(path: Path) -> dict:
    path = path.resolve()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def worker_digest(expected_worker_sha256: str | None = None) -> str:
    if expected_worker_sha256 is None:
        if "__file__" not in globals():
            raise CaptureError("embedded capture verification requires an explicit trusted worker SHA-256")
        expected_worker_sha256 = file_info(Path(__file__))["sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", expected_worker_sha256):
        raise CaptureError("trusted capture worker SHA-256 must be an exact lowercase digest")
    return expected_worker_sha256


def wrapper_bytes(directory: Path, kind: str, worker: dict) -> bytes:
    script = worker["artifact"]["path"]
    digest = worker["artifact"]["sha256"]
    return (f"#!{worker['python']['invoked_path']}\nimport hashlib, pathlib, sys\n"
            f"script = {script!r}\n"
            "source = pathlib.Path(script).read_bytes()\n"
            f"if hashlib.sha256(source).hexdigest() != {digest!r}:\n"
            "    raise SystemExit('frozen capture worker SHA-256 mismatch')\n"
            f"sys.argv = [script, {'_native-tool' if kind in NATIVE_TOOL_KINDS else '_compiler'!r}, '--session', {str(directory)!r}, "
            f"'--kind', {kind!r}, '--', *sys.argv[1:]]\n"
            "exec(compile(source, script, 'exec'), {'__name__': '__main__', '__file__': script})\n").encode()


def snapshot_worker(directory: Path, rust_policy: str | None = None) -> dict:
    """New captures execute one immutable copy, independent of later repo edits."""
    source = Path(__file__).resolve()
    original = file_info(source)
    snapshot = directory / "capture-worker.py"
    snapshot.write_bytes(source.read_bytes())
    snapshot.chmod(0o444)
    artifact = file_info(snapshot)
    if artifact["sha256"] != original["sha256"] or artifact["bytes"] != original["bytes"]:
        raise CaptureError("capture worker source changed while snapshotting")
    worker = {"schema": "ocore-runtime-capture-worker-v1", "source": original, "artifact": artifact,
              "python": {**file_info(Path(sys.executable)), "invoked_path": sys.executable}, "wrappers": {}}
    if rust_policy is not None:
        if rust_policy != RUST_EMBEDDED_POLICY:
            raise CaptureError("unsupported Rust capture policy")
        helper = source.parent.parent / "tools/ocore-runtime/rust/payload_inventory.py"
        original_helper = file_info(helper)
        if original_helper["sha256"] != REGISTERED_RUST_PAYLOAD_SHA256:
            raise CaptureError("Rust payload extractor differs from its independently registered SHA-256")
        helper_snapshot = directory / "rust-payload-extractor.py"
        helper_snapshot.write_bytes(helper.read_bytes())
        helper_snapshot.chmod(0o444)
        worker["rust_payload_extractor"] = {"schema": "ocore-rust-payload-extractor-worker-v1",
            "source": original_helper, "artifact": file_info(helper_snapshot)}
        if worker["rust_payload_extractor"]["artifact"]["sha256"] != REGISTERED_RUST_PAYLOAD_SHA256:
            raise CaptureError("Rust payload extractor changed during snapshotting")
    (directory / "wrappers").mkdir(exist_ok=True)
    for name, kind in wrapper_kinds():
        path = directory / "wrappers" / name
        path.write_bytes(wrapper_bytes(directory, kind, worker))
        path.chmod(0o755)
        worker["wrappers"][name] = file_info(path)
    return worker


def wrapper_kinds() -> list[tuple[str, str]]:
    return [("cc", "clang"), ("cxx", "cxx"), ("rustc-wrapper", "rustc"),
            *[(name, name) for name in NATIVE_TOOL_KINDS]]


def verify_worker(session: dict, directory: Path, expected_worker_sha256: str | None = None) -> dict:
    """A rewritten journal cannot choose a different trusted worker implementation."""
    expected = worker_digest(expected_worker_sha256)
    worker = session.get("capture_worker")
    if not isinstance(worker, dict) or worker.get("schema") != "ocore-runtime-capture-worker-v1":
        raise CaptureError("legacy/unbound capture worker: a fresh immutable worker capture is required")
    artifact = worker["artifact"]
    if artifact["sha256"] != expected:
        raise CaptureError("capture worker differs from the trusted verifier worker SHA-256; recapture is required")
    if Path(artifact["path"]).resolve() != directory.resolve() / "capture-worker.py" or file_info(Path(artifact["path"])) != artifact:
        raise CaptureError("frozen capture worker artifact changed or relocated")
    if worker["source"]["sha256"] != expected or worker["source"]["bytes"] != artifact["bytes"]:
        raise CaptureError("capture worker original-source binding differs from its immutable snapshot")
    python = worker["python"]
    if file_info(Path(python["invoked_path"])) != {key: python[key] for key in ("path", "sha256", "bytes")}:
        raise CaptureError("capture worker Python interpreter changed")
    if set(worker["wrappers"]) != {name for name, _ in wrapper_kinds()}:
        raise CaptureError("capture worker wrapper inventory is incomplete")
    for name, kind in wrapper_kinds():
        path = directory / "wrappers" / name
        if file_info(path) != worker["wrappers"][name] or path.read_bytes() != wrapper_bytes(directory, kind, worker):
            raise CaptureError("capture worker wrapper changed or does not execute the frozen worker: " + name)
    if session.get("recipe", {}).get("toolchain", {}).get("rust_capture_policy") is not None:
        rust_payload_extractor(session, directory)
    return worker


def rust_payload_extractor(session: dict, directory: Path) -> dict:
    record = session.get("capture_worker", {}).get("rust_payload_extractor")
    if (not isinstance(record, dict) or record.get("schema") != "ocore-rust-payload-extractor-worker-v1"
            or session.get("recipe", {}).get("toolchain", {}).get("rust_capture_policy") != RUST_EMBEDDED_POLICY):
        raise CaptureError("embedded Rust capture requires its pinned payload extractor snapshot")
    artifact = record.get("artifact", {})
    path = directory.resolve() / "rust-payload-extractor.py"
    raw = cargo_artifact_bytes(artifact, path)
    if (artifact["sha256"] != REGISTERED_RUST_PAYLOAD_SHA256
            or record.get("source", {}).get("sha256") != REGISTERED_RUST_PAYLOAD_SHA256
            or record.get("source", {}).get("bytes") != artifact["bytes"]):
        raise CaptureError("Rust payload extractor differs from its independently registered SHA-256")
    namespace = {"__name__": "ocore_capture_rust_payload", "__file__": str(path)}
    exec(compile(raw, str(path), "exec"), namespace)
    return namespace


def cargo_invocation_id(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise CaptureError("Cargo/compiler invocation ID must be exact lowercase UUID hex")
    return value


def cargo_artifact_bytes(record: object, expected_path: Path | None = None) -> bytes:
    """Read a typed immutable artifact; do not trust a parent-supplied digest."""
    if (not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256"}
            or not isinstance(record["path"], str)
            or type(record["bytes"]) is not int or record["bytes"] < 0
            or not isinstance(record["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])):
        raise CaptureError("invalid Cargo parent artifact record")
    path = Path(record["path"])
    if (not path.is_absolute() or path.is_symlink()
            or (expected_path is not None and path != expected_path.resolve())):
        raise CaptureError("Cargo parent artifact path mismatch")
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise CaptureError("Cargo parent artifact changed during observation")
    observed = {"path": str(path.resolve()), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    if observed != record:
        raise CaptureError("Cargo parent artifact bytes or identity changed")
    return raw


def validate_cargo_parent(binding: object, session_path: Path, session: dict, source_worker: dict,
                          expected_observer_sha256: str | None = None) -> dict:
    """Bind observation identity; final Cargo collection checks actual parentage.

    The expected-digest argument is an internal hermetic-test seam. Production
    compiler wrappers have no CLI/environment override for the registered pin.
    """
    trusted = REGISTERED_CARGO_OBSERVER_SHA256 if expected_observer_sha256 is None else expected_observer_sha256
    if not isinstance(trusted, str) or not re.fullmatch(r"[0-9a-f]{64}", trusted):
        raise CaptureError("independently registered Cargo observer SHA-256 is required")
    if not isinstance(binding, dict) or set(binding) != {
            "id", "observer_session", "observer_worker", "source_capture_worker"}:
        raise CaptureError("invalid Cargo parent binding fields")
    cargo_invocation_id(binding["id"])
    record = binding["observer_session"]
    if not isinstance(record, dict) or not isinstance(record.get("path"), str):
        raise CaptureError("invalid Cargo observer session artifact")
    observer_root = Path(record["path"]).parent
    observed_session = json.loads(cargo_artifact_bytes(record, observer_root / "session.json"))
    if (not isinstance(observed_session, dict)
            or observed_session.get("schema") != "ocore-cargo-parent-observer-session-v1"):
        raise CaptureError("Cargo observer session schema mismatch")
    cargo_artifact_bytes(binding["observer_worker"], observer_root / "worker.py")
    if (binding["observer_worker"] != observed_session.get("observer_worker")
            or binding["observer_worker"]["sha256"] != trusted):
        raise CaptureError("Cargo observer differs from independently registered worker")
    capture_worker = session.get("capture_worker")
    if (not isinstance(capture_worker, dict)
            or observed_session.get("source_capture") != str(session_path.resolve())
            or observed_session.get("source_capture_worker") != capture_worker
            or binding["source_capture_worker"] != source_worker
            or capture_worker.get("artifact") != source_worker):
        raise CaptureError("Cargo parent belongs to a different source-capture session or worker")
    cargo_artifact_bytes(source_worker, session_path / "capture-worker.py")
    return binding


def write_exclusive_json(path: Path, value: object) -> dict:
    """Publish complete bytes atomically and refuse every existing receipt."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
        os.link(temporary, path)  # An existing destination is never replaced.
    finally:
        temporary.unlink(missing_ok=True)
    return file_info(path)


def publish_cargo_child(binding: dict, session_path: Path, event_path: Path, event: dict,
                        expected_observer_sha256: str | None = None) -> dict:
    """A final journal edge is evidence, never source/compiler admission."""
    child_id = cargo_invocation_id(event.get("id"))
    parent_id = cargo_invocation_id(binding.get("id"))
    if (event.get("kind") not in {"clang", "rustc"} or event.get("state") != "finished"
            or type(event.get("exit_code")) is not int
            or event.get("cargo_parent_invocation_id") != parent_id
            or event.get("cargo_parent") != binding
            or event.get("capture_worker") != binding["source_capture_worker"]
            or event_path.resolve() != session_path.resolve() / "events" / (child_id + ".json")):
        raise CaptureError("Cargo compiler journal final parent/worker binding mismatch")
    current_session = read_json(session_path / "session.json")
    validate_cargo_parent(binding, session_path, current_session, event["capture_worker"], expected_observer_sha256)
    if read_json(event_path) != event:
        raise CaptureError("Cargo compiler journal changed before child publication")
    receipt = {"schema": "ocore-cargo-compiler-child-v1", "cargo_parent_invocation_id": parent_id,
               "capture_invocation_id": child_id, "capture_event": file_info(event_path),
               "observer_session": binding["observer_session"], "source_capture_worker": binding["source_capture_worker"]}
    observer_root = Path(binding["observer_session"]["path"]).parent
    return write_exclusive_json(observer_root / "children" / parent_id / (child_id + ".json"), receipt)


def run_text(argv: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True)
    if result.returncode:
        raise CaptureError(f"command failed ({result.returncode}): {shlex.join(argv)}\n{result.stderr}")
    return result.stdout.strip()


def tool_info(command: str, kind: str) -> dict:
    executable = shutil.which(command)
    if executable is None:
        raise CaptureError(f"missing {kind} executable: {command}")
    path = Path(executable).absolute()
    arguments = [str(path), "-vV"] if kind == "rustc" else [str(path), "--version"]
    version = run_text(arguments)
    result = {"invoked_path": str(path), "version": version, **file_info(path)}
    if kind == "rustc":
        result["release"] = next((line.removeprefix("release: ") for line in version.splitlines()
                                  if line.startswith("release: ")), None)
        result["commit"] = next((line.removeprefix("commit-hash: ") for line in version.splitlines()
                                 if line.startswith("commit-hash: ")), None)
        result["llvm_version"] = next((line.removeprefix("LLVM version: ") for line in version.splitlines()
                                       if line.startswith("LLVM version: ")), None)
        result["default_sysroot"] = run_text([str(path), "--print", "sysroot"])
        sysroot = Path(result["default_sysroot"])
        actual = sysroot / "bin" / "rustc"
        result["actual_producer_identity_complete"] = False
        if actual.is_file():
            candidate = file_info(actual)
            result["queried_sysroot_compiler"] = candidate
            if candidate == {key: result[key] for key in ("path", "sha256", "bytes")}:
                result["executing_binary"] = candidate
                result["actual_producer_identity_complete"] = True
    else:
        match = re.search(r"(?:clang|LLVM) version\s+(\d+\.\d+\.\d+)", version)
        result["llvm_version"] = match.group(1) if match else None
        if kind == "cargo":
            release = re.search(r"^cargo (\d+\.\d+\.\d+)", version)
            result["release"] = release.group(1) if release else None
    return result


def cargo_tool_info(command: str, rust_info: dict) -> dict:
    """Keep a queried Cargo candidate distinct from the selected executable.

    A Rust sysroot query is not observation of Cargo executing. In particular,
    missing Rust producer evidence must not turn cwd/cargo into an identity.
    """
    cargo = tool_info(command, "cargo")
    cargo["actual_producer_identity_complete"] = False
    sysroot = rust_info.get("default_sysroot")
    if isinstance(sysroot, str) and sysroot and Path(sysroot).is_absolute():
        candidate = Path(sysroot) / "bin" / "cargo"
        if candidate.is_file():
            artifact = file_info(candidate)
            cargo["queried_sysroot_cargo"] = artifact
            invoked = {key: cargo[key] for key in ("path", "sha256", "bytes")}
            if artifact == invoked:
                cargo["executing_binary"] = artifact
                cargo["actual_producer_identity_complete"] = True
    return cargo


def validate_recipe(recipe: dict) -> None:
    if recipe.get("schema") != RECIPE_SCHEMA:
        raise CaptureError(f"recipe schema must be {RECIPE_SCHEMA}")
    if not isinstance(recipe.get("name"), str) or not recipe["name"]:
        raise CaptureError("recipe needs a nonempty name")
    source = recipe.get("source", {})
    if not re.fullmatch(r"[0-9a-f]{40}", source.get("revision", "")):
        raise CaptureError("source.revision must pin a full 40-digit Git commit")
    if not isinstance(source.get("url"), str):
        raise CaptureError("source.url must record its origin")
    toolchain = recipe.get("toolchain", {})
    if not re.fullmatch(r"\d+\.\d+\.\d+", toolchain.get("llvm_version", "")):
        raise CaptureError("toolchain.llvm_version must pin an exact version")
    if "rust_capture_policy" in toolchain and toolchain["rust_capture_policy"] != RUST_EMBEDDED_POLICY:
        raise CaptureError("toolchain.rust_capture_policy must be rust-embedded-bc-v1 when present")
    commands = recipe.get("commands")
    if not isinstance(commands, list) or not commands:
        raise CaptureError("recipe needs build commands")
    for command in commands:
        if not isinstance(command, dict) or not isinstance(command.get("argv"), list) or not command["argv"]:
            raise CaptureError("each build command needs an argv array")
        if not all(isinstance(value, str) for value in command["argv"]):
            raise CaptureError("command argv elements must be strings")
    coverage = recipe.get("coverage", {})
    requirements = coverage.get("required_units", [])
    if not isinstance(requirements, list) or not requirements:
        raise CaptureError("coverage.required_units must declare required source units")
    ids = set()
    for item in requirements:
        if not isinstance(item, dict) or not item.get("id") or not item.get("source"):
            raise CaptureError("each required unit needs id and source")
        if item["id"] in ids:
            raise CaptureError(f"duplicate required unit id: {item['id']}")
        ids.add(item["id"])
        if item.get("kind") not in {"clang", "rustc"}:
            raise CaptureError("required unit kind must be clang or rustc")


def verify_source(recipe: dict, source: Path) -> dict:
    head = run_text(["git", "rev-parse", "HEAD"], source)
    if head != recipe["source"]["revision"]:
        raise CaptureError(f"source commit mismatch: expected {recipe['source']['revision']}, got {head}")
    dirty = run_text(["git", "status", "--porcelain", "--untracked-files=normal"], source)
    if dirty:
        raise CaptureError(f"source checkout must be clean before capture:\n{dirty}")
    submodules = run_text(["git", "submodule", "status", "--recursive"], source)
    if any(line.startswith(("-", "+", "U")) for line in submodules.splitlines()):
        raise CaptureError("source submodules must be initialized at their pinned commits")
    return {"path": str(source), "url": recipe["source"]["url"], "revision": head,
            "commit_timestamp": run_text(["git", "show", "-s", "--format=%ct", "HEAD"], source),
            "submodules": submodules.splitlines(), "clean_at_start": True}


def expand_response_files(args: list[str], cwd: Path, depth: int = 0,
                          rust: bool = False) -> tuple[list[str], list[dict]]:
    if depth > 16:
        raise CaptureError("compiler response-file recursion exceeds 16 levels")
    expanded, files = [], []
    for arg in args:
        if arg.startswith("@") and len(arg) > 1:
            path = Path(arg[1:])
            path = path if path.is_absolute() else cwd / path
            # rustc uses one argument per line; Clang uses GNU shell quoting.
            raw = rust_response_lines(path.read_bytes()) if rust else shlex.split(path.read_text())
            # rustc's Expander::push explicitly does not recursively expand
            # response lines. Clang's GNU response semantics are recursive.
            content, nested = (raw, []) if rust else expand_response_files(raw, cwd, depth + 1, rust)
            expanded.extend(content)
            files.append(file_info(path))
            files.extend(nested)
        else:
            expanded.append(arg)
    return expanded, files


def rust_response_lines(raw: bytes) -> list[str]:
    text = raw.decode("utf-8")
    if not text:
        return []
    lines = text.split("\n")
    trailing_newline = text.endswith("\n")
    if trailing_newline:
        lines.pop()
    return [line[:-1] if line.endswith("\r") and (index < len(lines) - 1 or trailing_newline) else line
            for index, line in enumerate(lines)]


def rust_argfile_gap(args: list[str]) -> dict | None:
    if any("\0" in arg for arg in args):
        return {"kind": "rust_nul_response_argument_unsupported",
                "message": "NUL response arguments cannot be flattened into OS argv; original command forwarded"}
    if "--" in args:
        # A -- token may be an option value rather than the getopts terminator.
        # This bounded capture profile does not reinterpret either form.
        return {"kind": "rust_option_terminator_unsupported",
                "message": "Rust -- argument boundaries retain exact original parsing; original command forwarded"}
    if any(arg == "-Zshell-argfiles" or arg == "shell-argfiles" and index > 0 and args[index - 1] == "-Z"
           or arg.startswith("@shell:") for index, arg in enumerate(args)):
        return {"kind": "rust_shell_argfiles_unsupported",
                "message": "stateful shell argfiles require an explicit supported parser; original command forwarded"}
    if any(arg.startswith("@") for arg in args):
        return {"kind": "rust_literal_response_argument_unsupported",
                "message": "literal @ arguments inside original response files must not be recursively flattened; original command forwarded"}
    return None


def clang_inputs(args: list[str], cwd: Path) -> list[Path]:
    result, i = [], 0
    explicit_language = option_value(args, "-x")
    while i < len(args):
        arg = args[i]
        if arg in PAIR_OPTIONS:
            i += 2
            continue
        if not arg.startswith("-") and (Path(arg).suffix in SOURCE_SUFFIXES | ASM_SUFFIXES
                                         or explicit_language in {"c", "c++", "objective-c", "objective-c++"} | HEADER_LANGUAGES
                                         or explicit_language is None and Path(arg).suffix in HEADER_SUFFIXES):
            path = Path(arg)
            result.append((path if path.is_absolute() else cwd / path).resolve())
        i += 1
    return result


def clang_header_compile(args: list[str], inputs: list[Path]) -> bool:
    """A frontend AST cache has no independent executable translation unit."""
    language = option_value(args, "-x")
    return bool(inputs) and (language in HEADER_LANGUAGES or
                            language is None and all(path.suffix in HEADER_SUFFIXES for path in inputs))


def clang_compiler_inputs(args: list[str], cwd: Path) -> list[dict]:
    """Bind explicit compiler caches separately from executable linker inputs."""
    result = []
    for index, arg in enumerate(args):
        if arg in {"-include-pch", "-include-pth"}:
            if index + 1 >= len(args):
                raise CaptureError("missing compiler-cache argument to " + arg)
            path = (cwd / args[index + 1]).resolve()
            result.append({**file_info(path), "artifact_kind": "clang-precompiled-header"})
    return result


def clang_replay(args: list[str], source: Path, inputs: list[Path], cwd: Path,
                 output: Path, depfile: Path) -> list[str]:
    result, i = [], 0
    remove_pairs = {"-o", "-MF", "-MT", "-MQ", "-Xlinker", "-L", "-l"}
    remove_single = {"-c", "-S", "-emit-llvm", "-MD", "-MMD", "-MP", "-MG",
                     "-shared", "-static", "-pie", "-rdynamic", "-s"}
    input_paths = set(inputs)
    while i < len(args):
        arg = args[i]
        if arg in remove_pairs:
            i += 2
            continue
        if arg in remove_single or arg.startswith(("-Wl,", "-L", "-l", "-fuse-ld=")):
            i += 1
            continue
        if arg in PAIR_OPTIONS:
            if i + 1 >= len(args):
                raise CaptureError(f"missing argument to {arg}")
            result.extend(args[i:i + 2])
            i += 2
            continue
        if not arg.startswith("-"):
            path = (cwd / arg).resolve()
            if path in input_paths or path.suffix in {".o", ".obj", ".a", ".so", ".dylib"}:
                i += 1
                continue
        result.append(arg)
        i += 1
    # Keep the original spelling: absolute replay paths change __FILE__/__BASE_FILE__.
    source_arg = next((arg for arg in args if not arg.startswith("-")
                       and (cwd / arg).resolve() == source), str(source))
    return [*result, "-S", "-emit-llvm", "-MD", "-MF", str(depfile),
            "-o", str(output), source_arg]


def rust_replay(args: list[str], output: Path) -> list[str]:
    result, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg in {"-o", "--out-dir", "--emit"}:
            i += 2
            continue
        if arg.startswith(("--out-dir=", "--emit=")):
            i += 1
            continue
        if arg == "-C" and i + 1 < len(args) and args[i + 1].startswith("incremental="):
            i += 2
            continue
        if arg.startswith("-Cincremental="):
            i += 1
            continue
        result.append(arg)
        i += 1
    return [*result, "--emit=llvm-ir,dep-info", "--out-dir", str(output)]


def rust_translation(args: list[str], inputs: list[Path]) -> bool:
    query = any(arg in {"-E", "-M", "-MM", "-fsyntax-only", "--version", "-V", "-vV"}
                or arg.startswith(("--print", "-print", "-dump")) for arg in args)
    emit = option_value(args, "--emit")
    metadata_only = emit is not None and not any(item.split("=", 1)[0] in {
        "link", "obj", "asm", "llvm-ir", "llvm-bc"} for item in emit.split(","))
    return bool(inputs) and not query and not metadata_only


def retained_rust_arguments(event: dict) -> tuple[list[str], list[dict]]:
    """Resolve original @ locators using immutable recorded bytes, not mtime."""
    retained = event.get("rust_response_files")
    if not isinstance(retained, list):
        raise CaptureError("Rust original response-file byte inventory is missing")
    by_path = {}
    for item in retained:
        if not isinstance(item, dict) or set(item) != {"source", "artifact"}:
            raise CaptureError("Rust retained response-file record has invalid fields")
        source = item["source"]
        raw = cargo_artifact_bytes(item["artifact"])
        if (source.get("bytes"), source.get("sha256")) != (len(raw), hashlib.sha256(raw).hexdigest()):
            raise CaptureError("Rust response-file original bytes differ from their immutable snapshot")
        previous = by_path.setdefault(source["path"], (source, raw))
        if previous != (source, raw):
            raise CaptureError("Rust response-file locator has ambiguous original bytes")
    gap = event.get("rust_capture", {}).get("argfile_gap")
    if gap and gap.get("kind") == "rust_argfile_read_unsupported":
        if retained:
            raise CaptureError("opaque original Rust argfile failure has unexpected parsed response bytes")
        return event["argv"], []
    def expand(args):
        result, files = [], []
        for arg in args:
            if arg.startswith("@") and len(arg) > 1:
                path = Path(arg[1:])
                path = (path if path.is_absolute() else Path(event["cwd"]) / path).resolve()
                if str(path) not in by_path:
                    raise CaptureError("Rust original response-file locator lacks retained bytes")
                source, raw = by_path[str(path)]
                result.extend(rust_response_lines(raw))
                files.append(source)
            else:
                result.append(arg)
        return result, files
    expanded, files = expand(event["argv"])
    if files != [item["source"] for item in retained]:
        raise CaptureError("Rust retained response-file inventory differs from original ordered locators")
    return expanded, files


def rust_instrumentation(args: list[str], enabled: bool) -> tuple[list[str], list[dict]]:
    """Canonicalize only capture options; retain every other expanded argument.

    Rust response files are expanded before this call, with original files hashed
    in the journal. No Cargo/stage/CGU filename establishes a producer byte edge.
    """
    if not enabled or rust_argfile_gap(args) is not None:
        return list(args), []
    result, changes, seen, index = [], [], set(), 0
    while index < len(args):
        arg, codegen, count = args[index], None, 1
        if arg in {"-C", "--codegen"} and index + 1 < len(args):
            codegen, count = args[index + 1], 2
        elif arg.startswith("--codegen="):
            codegen = arg[len("--codegen="):]
        elif arg.startswith("-C") and len(arg) > 2:
            codegen = arg[2:]
        name = codegen.split("=", 1)[0] if codegen is not None else None
        if name in {"embed-bitcode", "save-temps"}:
            incoming = args[index:index + count]
            value = codegen.split("=", 1)[1] if "=" in codegen else "yes"
            if value not in {"yes", "no", "true", "false", "on", "off", "y", "n"}:
                # Keep invalid original options for the actual frontend; never
                # erase their diagnostic by changing the value to true.
                seen.add(name)
                result.extend(incoming)
                index += count
                continue
            # One canonical occurrence avoids a later false overriding true.
            replacement = [] if name in seen else ["-C", name + "=yes"]
            seen.add(name)
            result.extend(replacement)
            changes.append({"index": index, "incoming": incoming, "executed": replacement,
                            "reason": "retain-original-producer-embedded-bitcode" if name == "embed-bitcode"
                                      else "retain-original-producer-temporary-artifacts"})
        else:
            result.extend(args[index:index + count])
        index += count
    for name in ("embed-bitcode", "save-temps"):
        if name not in seen:
            result.extend(["-C", name + "=yes"])
            changes.append({"index": len(args), "incoming": [], "executed": ["-C", name + "=yes"],
                            "reason": "explicit-opt-in-capture-option"})
    return result, changes


def option_value(args: list[str], option: str) -> str | None:
    for i, arg in enumerate(args):
        if arg == option and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith(option + "="):
            return arg[len(option) + 1:]
    return None


def native_outputs(kind: str, args: list[str], inputs: list[Path], cwd: Path) -> list[Path]:
    explicit = option_value(args, "-o")
    if explicit:
        return [(cwd / explicit).resolve()]
    if kind == "clang":
        if clang_header_compile(args, inputs):
            return [Path(str(path) + ".gch") for path in inputs]
        if "-c" in args or "-S" in args:
            suffix = ".s" if "-S" in args else ".o"
            return [cwd / (path.stem + suffix) for path in inputs]
        return [cwd / "a.out"] if inputs else []
    directory = (cwd / (option_value(args, "--out-dir") or ".")).resolve()
    name = option_value(args, "--crate-name") or (inputs[0].stem if inputs else None)
    if name is None or not directory.is_dir():
        return []
    extra = ""
    for i, arg in enumerate(args):
        codegen = args[i + 1] if arg == "-C" and i + 1 < len(args) else arg.removeprefix("-C")
        if codegen.startswith("extra-filename="):
            extra = codegen.split("=", 1)[1]
    stems = {name + extra, "lib" + name + extra}
    suffixes = {"", ".rlib", ".rmeta", ".o", ".obj", ".a", ".so", ".dylib", ".dll", ".exe", ".bc", ".ll", ".d", ".s"}
    return [path for path in directory.iterdir() if path.is_file() and path.suffix in suffixes
            and (path.stem in stems or path.name in stems)]


def inspect_symbols(path: Path, nm: str) -> dict:
    result = {}
    for label, flag in [("defined", "--defined-only"), ("undefined", "--undefined-only")]:
        output = run_text([nm, "--format=posix", "--extern-only", flag, str(path)])
        result[label] = sorted({line.split()[0] for line in output.splitlines()
                                if line.strip() and not line.rstrip().endswith(":")})
    return result


def dependency_files(path: Path, cwd: Path) -> list[dict]:
    if not path.is_file():
        raise CaptureError(f"compiler did not emit dependency file: {path}")
    text = path.read_text().replace("\\\n", " ")
    # Rust emits multiple target rules; deduplicate the prerequisites of all rules.
    files = set()
    for line in text.splitlines():
        if ":" not in line:
            continue
        for item in shlex.split(line.split(":", 1)[1]):
            candidate = (cwd / item).resolve()
            if candidate.is_file():
                files.add(candidate)
    return [file_info(item) for item in sorted(files)]


def ir_info(path: Path, decoder: dict | None = None) -> dict:
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic in {b"BC\xc0\xde", b"\xde\xc0\x17\x0b"}:
        if decoder is None:
            raise CaptureError("original embedded bitcode requires a pinned LLVM decoder")
        artifact = {key: decoder[key] for key in ("path", "sha256", "bytes")}
        if file_info(Path(decoder["invoked_path"])) != artifact:
            raise CaptureError("embedded bitcode LLVM decoder artifact changed")
        # Stream complete decoder output. LLVM text is only a metadata view of
        # the exact original BC input, never another compiler invocation.
        command = [decoder["invoked_path"], str(path), "-o", "-"]
        triple = layout = None
        with tempfile.TemporaryFile() as stderr, subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=stderr) as result:
            for line in result.stdout:
                if line.startswith(b'target triple = "'):
                    triple = line.decode().split('"')[1]
                elif line.startswith(b'target datalayout = "'):
                    layout = line.decode().split('"')[1]
            result.stdout.close()
            status = result.wait()
            stderr.seek(0)
            error = stderr.read()
        if status or triple is None or layout is None:
            raise CaptureError("embedded bitcode LLVM decode failed: " + error.decode(errors="replace"))
        if file_info(Path(decoder["invoked_path"])) != artifact:
            raise CaptureError("embedded bitcode LLVM decoder changed during observation")
        return {**file_info(path), "format": "llvm-bitcode", "target_triple": triple,
                "data_layout": layout, "decoder": artifact, "decode_argv": command}
    text = path.read_text()
    triple = re.search(r'^target triple = "([^"]+)"', text, re.MULTILINE)
    layout = re.search(r'^target datalayout = "([^"]+)"', text, re.MULTILINE)
    if not triple or not layout:
        raise CaptureError(f"LLVM unit lacks target triple/DataLayout: {path}")
    return {**file_info(path), "format": "llvm-text", "target_triple": triple.group(1),
            "data_layout": layout.group(1)}


def retain_range(source: dict, offset: int, size: int, destination: Path) -> dict:
    if (type(offset) is not int or type(size) is not int or offset < 0 or size < 0
            or offset + size > source["bytes"]):
        raise CaptureError("original Rust artifact byte range is invalid")
    path = Path(source["path"])
    if file_info(path) != source:
        raise CaptureError("original Rust native output changed before range extraction")
    with path.open("rb") as stream, destination.open("xb") as output:
        stream.seek(offset)
        remaining = size
        while remaining:
            data = stream.read(min(remaining, 1024 * 1024))
            if not data:
                raise CaptureError("original Rust artifact was truncated during range extraction")
            output.write(data)
            remaining -= len(data)
    if file_info(path) != source:
        raise CaptureError("original Rust native output changed during range extraction")
    return file_info(destination)


def rust_output_evidence(event: dict, extractor: dict) -> dict:
    """Reconstruct every original output/member edge, resource and gap."""
    edges, resources, gaps = [], [], []
    for output in event.get("outputs", []):
        artifact = {key: output[key] for key in ("path", "sha256", "bytes")}
        if file_info(Path(artifact["path"])) != artifact:
            raise CaptureError("Rust original producer output changed")
        if Path(artifact["path"]).suffix == ".d":
            resources.append({"artifact": artifact, "kind": "rust_dependency_file",
                "native_code": False, "ownership_qualified": False})
            continue
        with Path(artifact["path"]).open("rb") as stream:
            header = stream.read(8)
        if header == b"rust\0\0\0\x0a" and Path(artifact["path"]).suffix == ".rmeta":
            resources.append({"artifact": artifact, "kind": "rust_v10_metadata",
                "header_bytes": list(header), "native_code": False, "ownership_qualified": False})
            continue
        if header == b"!<arch>\n":
            try:
                with extractor["mapped_artifact"](artifact) as data:
                    members = extractor["archive_members"](data)
                indices = [member["index"] for member in members]
            except extractor["PayloadError"] as error:
                gaps.append({"artifact": artifact, **error.record()})
                continue
        else:
            indices, members = [None], []
        for member_index in indices:
            try:
                edges.append(extractor["extract_embedded_bitcode"](artifact, member_index))
            except extractor["PayloadError"] as error:
                member = members[member_index] if member_index is not None else None
                gap = {"artifact": artifact, "member": member, **error.record()}
                metadata = False
                if error.kind == "embedded_bitcode_missing":
                    with extractor["mapped_artifact"](artifact) as data:
                        begin = member["data_offset"] if member is not None else 0
                        size = member["bytes"] if member is not None else artifact["bytes"]
                        sections = extractor["elf_sections"](data, begin, size)["sections"]
                        metadata = (any(bytes(section["name_bytes"]) in {b".rmeta", b".rmeta-link"}
                                        for section in sections)
                                    and not any(section["flags"] & 6 and section["type"] != 7
                                                for section in sections))
                        if metadata:
                            gap["metadata_sections"] = sections
                (resources if metadata else gaps).append(gap)
    if not edges:
        gaps.append({"kind": "original_native_cgu_edge_missing",
            "message": "no producer-output ELF embedded bitcode edge; save-temp names are not ownership evidence"})
    return {"edges": edges, "resources": resources, "gaps": gaps}


def capture_rust_cgus(event: dict, directory: Path, session: dict) -> None:
    extractor = rust_payload_extractor(session, directory.parents[1])
    evidence = rust_output_evidence(event, extractor)
    event["saved_cgus"] = []
    event["rust_cgu_gaps"], event["rust_native_resources"] = evidence["gaps"], evidence["resources"]
    for edge in evidence["edges"]:
        artifact, index = edge["container"], len(event["saved_cgus"])
        try:
            object_artifact = artifact
            if edge["member"] is not None:
                member = edge["member"]
                object_artifact = retain_range(artifact, member["data_offset"], member["bytes"],
                                              directory / f"cgu-{index}.o")
            bitcode = retain_range(artifact, edge["edge"]["container_offset"], edge["edge"]["bytes"],
                                   directory / f"cgu-{index}.bc")
            record = {"schema": "ocore-rust-native-bitcode-edge-v1",
                "compiler_invocation_id": event["id"],
                "cargo_parent_invocation_id": event.get("cargo_parent_invocation_id"),
                "object": object_artifact, "bitcode": bitcode, "edge": edge["edge"]}
            if edge["member"] is not None:
                record["container"] = {"artifact": artifact, "member": edge["member"]}
            event["saved_cgus"].append(record)
            extractor["verify_saved_cgu"](record, event)
            event["units"].append({"id": f"{event['id']}:{index}", "kind": "rustc",
                "source": event["sources"][0], "ir": ir_info(Path(bitcode["path"]), session["tools"]["llvm_dis"]),
                "frontend_version": event["frontend"]["version"], "dependencies": event["sources"],
                "saved_cgu_index": index, "capture_policy": RUST_EMBEDDED_POLICY,
                "source_production_ownership_verified": False,
                "native_machine_equivalence_verified": False, "post_lto_equivalence_verified": False})
        except (CaptureError, OSError, ValueError, KeyError) as error:
            event["rust_cgu_gaps"].append({"artifact": artifact,
                "member_index": edge["member"]["index"] if edge["member"] is not None else None,
                "kind": "embedded_cgu_capture_failed", "message": str(error)})
    for gap in event["rust_cgu_gaps"]:
        event["capture_errors"].append("Rust embedded CGU gap: " + gap["kind"] + ": " + gap["message"])


def verify_rust_capture_event(event: dict, session: dict, directory: Path) -> None:
    policy = session.get("recipe", {}).get("toolchain", {}).get("rust_capture_policy")
    if policy is None or event.get("kind") != "rustc":
        if event.get("rust_capture") is not None or event.get("saved_cgus") is not None:
            raise CaptureError("Rust embedded CGUs occur outside their explicit capture policy")
        return
    if policy != RUST_EMBEDDED_POLICY:
        raise CaptureError("unsupported Rust capture policy")
    args, responses = retained_rust_arguments(event)
    if args != event.get("expanded_argv") or responses != event.get("response_files"):
        raise CaptureError("Rust incoming response bytes or expanded arguments changed")
    argfile_gap = rust_argfile_gap(args)
    if (event.get("rust_capture", {}).get("argfile_gap") or {}).get("kind") == "rust_argfile_read_unsupported":
        argfile_gap = {"kind": "rust_argfile_read_unsupported",
                      "message": "original Rust argfile could not be decoded by capture; original command forwarded"}
    inputs = [] if argfile_gap is not None else [(Path(event["cwd"]) / arg).resolve() for arg in args
              if not arg.startswith("-") and arg.endswith(".rs")]
    applied = rust_translation(args, inputs) and argfile_gap is None
    executed, changes = rust_instrumentation(args, applied)
    expected = {"policy": policy, "applied": applied, "transformations": changes,
        "original_command_executed": (executed if applied else event["argv"]) == event["argv"], "frontend_replay_used": False,
        "post_lto_equivalence_verified": False, "argfile_gap": argfile_gap}
    if event.get("rust_capture") != expected or event.get("executed_argv") != (executed if applied else event["argv"]):
        raise CaptureError("Rust capture policy or executed arguments differ from original inputs")
    if event.get("replay_argv") is not None or event.get("replay_exit_code") is not None:
        raise CaptureError("embedded Rust capture cannot substitute a frontend replay for a native byte edge")
    if argfile_gap and "Rust argfile capture gap: " + argfile_gap["message"] not in event.get("capture_errors", []):
        raise CaptureError("unsupported Rust argfile diagnostic was omitted")
    if not applied:
        if event.get("saved_cgus") or event.get("units"):
            raise CaptureError("uninstrumented/unsupported Rust command cannot claim captured embedded CGUs")
        return
    extractor = rust_payload_extractor(session, directory)
    records = event.get("saved_cgus", [])
    observed = set()
    for record in records:
        try:
            edge = extractor["verify_saved_cgu"](record, event)
            key = (edge["container"]["path"], edge["container"]["sha256"],
                   edge["member"]["index"] if edge["member"] is not None else None)
            if key in observed:
                raise CaptureError("Rust saved CGU inventory repeats an original object/member edge")
            observed.add(key)
        except extractor["PayloadError"] as error:
            raise CaptureError("Rust saved CGU readmission: " + error.kind + ": " + str(error)) from error
    evidence = rust_output_evidence(event, extractor)
    expected_edges = {(edge["container"]["path"], edge["container"]["sha256"],
                       edge["member"]["index"] if edge["member"] is not None else None)
                      for edge in evidence["edges"]}
    if applied and event.get("exit_code") == 0:
        if event.get("rust_native_resources") != evidence["resources"]:
            raise CaptureError("Rust original resource inventory changed or was omitted")
        derived_gaps = [gap for gap in event.get("rust_cgu_gaps", [])
                        if gap.get("kind") != "embedded_cgu_capture_failed"]
        if derived_gaps != evidence["gaps"]:
            raise CaptureError("Rust original unsupported/missing byte-edge gaps changed or were omitted")
        for gap in evidence["gaps"]:
            message = "Rust embedded CGU gap: " + gap["kind"] + ": " + gap["message"]
            if message not in event.get("capture_errors", []):
                raise CaptureError("Rust original byte-edge gap diagnostic was omitted")
    if observed != expected_edges:
        raise CaptureError("Rust saved CGU inventory differs from all original embedded object/member edges")
    if applied and event.get("exit_code") == 0:
        units = event.get("units", [])
        unit_indices = set()
        for unit in units:
            index = unit.get("saved_cgu_index")
            if type(index) is int and index in unit_indices:
                raise CaptureError("Rust LLVM inventory duplicates an original embedded CGU")
            if type(index) is int:
                unit_indices.add(index)
            if (type(index) is not int or not 0 <= index < len(records)
                    or {key: unit["ir"][key] for key in ("path", "sha256", "bytes")} != records[index]["bitcode"]
                    or unit.get("capture_policy") != policy or unit.get("kind") != "rustc"
                    or unit.get("source_production_ownership_verified") is not False
                    or unit.get("native_machine_equivalence_verified") is not False
                    or unit.get("post_lto_equivalence_verified") is not False):
                raise CaptureError("Rust LLVM unit is not bound to its original embedded bitcode edge")
        if not event.get("capture_errors") and {unit["saved_cgu_index"] for unit in units} != set(range(len(records))):
            raise CaptureError("Rust original embedded CGU inventory is incomplete")


def observed_link_inputs(args: list[str], cwd: Path) -> dict:
    files, libraries, search_paths, ordered = [], [], [], []
    args = [item for arg in args for item in (arg[4:].split(",") if arg.startswith("-Wl,") else [arg])]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {"-l", "-L"} and i + 1 < len(args):
            (libraries if arg == "-l" else search_paths).append(args[i + 1])
            ordered.append({"index": i, "kind": "library" if arg == "-l" else "search-path", "value": args[i + 1]})
            i += 2
            continue
        if arg in PAIR_OPTIONS - {"-Xlinker"}:
            ordered.append({"index": i, "kind": "option", "argv": args[i:i + 2]})
            i += 2
            continue
        if arg == "--extern" and i + 1 < len(args):
            arg = args[i + 1].split("=", 1)[-1]
            i += 1
        elif arg.startswith("--extern="):
            arg = arg[len("--extern="):].split("=", 1)[-1]
        if arg.startswith("-l") and len(arg) > 2:
            libraries.append(arg[2:])
            ordered.append({"index": i, "kind": "library", "value": arg[2:]})
        elif arg.startswith("-L") and len(arg) > 2:
            search_paths.append(arg[2:])
            ordered.append({"index": i, "kind": "search-path", "value": arg[2:]})
        elif not arg.startswith("-"):
            path = (cwd / arg).resolve()
            if path.suffix in {".o", ".obj", ".a", ".so", ".rlib", ".rmeta", ".dylib"} and path.is_file():
                artifact = file_info(path)
                files.append(artifact)
                ordered.append({"index": i, "kind": "file", "spelling": arg, "artifact": artifact})
            else:
                ordered.append({"index": i, "kind": "argument", "value": arg})
        else:
            ordered.append({"index": i, "kind": "transition" if arg in {
                "--start-group", "--end-group", "-(", "-)", "--as-needed", "--no-as-needed",
                "--whole-archive", "--no-whole-archive", "-Bstatic", "-Bdynamic", "-static",
                "--push-state", "--pop-state"} else "argument", "value": arg})
        i += 1
    return {"files": files, "libraries": libraries, "search_paths": search_paths,
            "ordered": ordered, "expanded_argv": args, "dependency_closure_complete": False}


def ordered_dependency_paths(path: Path, cwd: Path) -> list[Path]:
    """Read the first linker Make rule, retaining provider order and escaping."""
    text = path.read_text().replace("\\\n", " ")
    first = text.splitlines()[0]
    split = re.search(r"(?<!\\):", first)
    if split is None:
        raise CaptureError("linker dependency trace has no target rule")
    tokens, token, escaped = [], "", False
    for char in first[split.end():]:
        if escaped:
            token += char
            escaped = False
        elif char == "\\":
            escaped = True
        elif char.isspace():
            if token:
                tokens.append(token.replace("$$", "$"))
                token = ""
        else:
            token += char
    if escaped:
        raise CaptureError("unfinished linker dependency escape")
    if token:
        tokens.append(token.replace("$$", "$"))
    return [(cwd / name).absolute() for name in tokens]


def preserve_native_input(path: Path, directory: Path) -> dict:
    """Keep linker-read temporary inputs before the compiler removes them."""
    original = file_info(path)
    snapshot = directory / "native-inputs" / original["sha256"]
    snapshot.parent.mkdir(exist_ok=True)
    if not snapshot.exists():
        temporary = snapshot.with_name(snapshot.name + "." + uuid.uuid4().hex)
        shutil.copyfile(path, temporary)
        if file_info(temporary)["sha256"] != original["sha256"]:
            temporary.unlink()
            raise CaptureError("native provider changed while snapshotting: " + str(path))
        temporary.chmod(0o444)
        temporary.replace(snapshot)
    artifact = file_info(snapshot)
    if artifact["sha256"] != original["sha256"] or artifact["bytes"] != original["bytes"]:
        raise CaptureError("native provider snapshot changed")
    return {"spelling": str(path), "original": original, "snapshot": artifact}


def native_archive_members(path: Path) -> list[dict]:
    members, names = [], b""
    archive_size = path.stat().st_size

    def bsd_symbol_index(name: str, data: bytes) -> bool:
        if name not in {"__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64", "__.SYMDEF_64 SORTED"}:
            return False
        width = 8 if name.startswith("__.SYMDEF_64") else 4
        if len(data) < width * 2:
            return False
        for byteorder in ("little", "big"):
            entries_size = int.from_bytes(data[:width], byteorder)
            strings_offset = width + entries_size + width
            if entries_size % (width * 2) or strings_offset > len(data):
                continue
            strings_size = int.from_bytes(data[width + entries_size:strings_offset], byteorder)
            if strings_offset + strings_size > len(data) or any(data[strings_offset + strings_size:]):
                continue
            strings = data[strings_offset:strings_offset + strings_size]
            for offset in range(width, width + entries_size, width * 2):
                name_offset = int.from_bytes(data[offset:offset + width], byteorder)
                member_offset = int.from_bytes(data[offset + width:offset + width * 2], byteorder)
                if (name_offset >= len(strings) or b"\0" not in strings[name_offset:]
                        or not 8 <= member_offset < archive_size):
                    break
            else:
                return True
        return False

    with path.open("rb") as stream:
        if stream.read(8) != b"!<arch>\n":
            raise CaptureError("ordinary native archive membership is required: " + str(path))
        while header := stream.read(60):
            if len(header) != 60 or header[58:] != b"`\n":
                raise CaptureError("invalid native archive member header")
            size, name = int(header[48:58].strip()), header[:16].decode().rstrip()
            data = stream.read(size)
            if len(data) != size or size % 2 and len(stream.read(1)) != 1:
                raise CaptureError("truncated native archive member")
            if name == "//":
                names = data
                continue
            if name in {"/", "/SYM64/"}:
                continue
            if name.startswith("#1/"):
                count = int(name[3:])
                if count > len(data):
                    raise CaptureError("invalid extended archive name")
                name, data = data[:count].rstrip(b"\0").decode(), data[count:]
            elif name.startswith("/") and name[1:].isdigit():
                offset = int(name[1:])
                if offset >= len(names):
                    raise CaptureError("invalid archive name-table offset")
                name = names[offset:].split(b"/\n", 1)[0].decode()
            else:
                name = name.rstrip("/")
            if bsd_symbol_index(name, data):
                continue
            members.append({"index": len(members), "member": name,
                            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    return members


def native_tool(session_path: Path, name: str, original_args: list[str]) -> int:
    """Delegate an actual selected native linker/archive tool and journal it.

    Supported ELF linkers receive output-only dependency/map trace options. The
    original arguments and tool remain explicit; unknown tools run unchanged but
    cannot establish complete linkage evidence. No library is resolved by an
    unordered guess at -l flags.
    """
    session = read_json(session_path / "session.json")
    event_id = uuid.uuid4().hex
    directory = session_path / "units" / event_id
    directory.mkdir(parents=True)
    event_path = session_path / "events" / (event_id + ".json")
    cwd = Path.cwd().resolve()
    event = {"id": event_id, "kind": NATIVE_TOOL_KINDS[name], "driver_kind": name,
             "cwd": str(cwd), "argv": original_args, "started_ns": time.time_ns(),
             "state": "running", "sources": [], "units": [], "outputs": [], "capture_errors": [],
             "parent_invocation_id": os.environ.get("OCORE_CAPTURE_PARENT_EVENT"),
             "classification": "native-tool", "translation_required": False}
    if session.get("build_steps") and session["build_steps"][-1].get("exit_code") is None:
        event["build_step"] = {"index": len(session["build_steps"]) - 1, "name": session["build_steps"][-1]["name"]}
    write_json(event_path, event)
    code = 127
    program = None
    executed = False
    try:
        event["capture_worker"] = file_info(Path(__file__))
        verify_worker(session, session_path, event["capture_worker"]["sha256"])
        tool = session["native_tools"][name]
        selected = os.environ.get("OCORE_CAPTURE_LINKER_IDENTITY")
        if selected and event["kind"] == "linker" and event.get("parent_invocation_id"):
            parent = read_json(session_path / "events" / (event["parent_invocation_id"] + ".json"))
            candidate = json.loads(selected)
            if candidate != parent.get("selected_linker") or file_info(Path(candidate["invoked_path"])) != {key: candidate[key] for key in ("path", "sha256", "bytes")}:
                raise CaptureError("driver-selected original linker identity changed")
            tool = candidate
        event["tool"] = tool
        program = tool["invoked_path"]
        args, responses = expand_response_files(original_args, cwd)
        event["expanded_argv"], event["response_files"] = args, responses
        event["link_inputs"] = observed_link_inputs(args, cwd)
        if args and all(arg in {"--version", "-v", "--help", "-V"} for arg in args):
            event["classification"] = "query"
            executed = True
            code = subprocess.run([program, *original_args]).returncode
            return code
        effective = list(original_args)
        output = option_value(args, "-o")
        trace = {"schema": "ocore-native-linkage-v1", "complete": False,
                 "ordered_argv": args, "providers": [], "archive_members": [], "issues": []}
        event["native_linkage"] = trace
        if event["kind"] == "linker":
            supported = "LLD" in tool["version"] or "GNU ld" in tool["version"]
            occupied = any(arg.startswith(("--dependency-file", "--why-extract", "-Map", "--Map")) for arg in args)
            if supported and not occupied and not any(arg in {"--version", "--help", "-V"} for arg in args):
                depfile, mapfile = directory / "link.d", directory / "link.map"
                effective += ["--dependency-file=" + str(depfile)]
                if "LLD" in tool["version"]:
                    mapfile = directory / "why-extract.tsv"
                    effective += ["--why-extract=" + str(mapfile)]
                else:
                    effective += ["-Map=" + str(mapfile)]
                trace["instrumentation"] = "actual-linker-dependency-and-archive-trace"
            else:
                trace["issues"].append("unknown or conflicting linker trace instrumentation")
            event["effective_argv"] = effective
            executed = True
            code = subprocess.run([program, *effective]).returncode
            if code == 0 and not trace["issues"]:
                trace["dependency_trace"] = file_info(depfile)
                trace["archive_trace"] = file_info(mapfile)
                for path in ordered_dependency_paths(depfile, cwd):
                    trace["providers"].append(preserve_native_input(path, session_path))
                trace["complete"] = bool(output and trace["providers"])
        else:
            # Archive contents, including cold/unextracted members, belong to
            # the declared closure. MRI scripts/thin archives remain explicit
            # unsupported cases rather than disappearing from an inventory.
            if event["kind"] == "archive":
                flags = args[0].lstrip("-") if args else ""
                candidates = [arg for arg in args[1:] if not arg.startswith("-")]
                ordinary = bool(flags) and set(flags) <= set("rqcsDUvSu") and bool(set(flags) & set("rq"))
                if not candidates or not ordinary or any(arg.startswith("-") for arg in args[1:]):
                    trace["issues"].append("archive command requires a supported ordinary archive operation")
                else:
                    output = candidates[0]
                    # An update reads retained members from the previous archive.
                    # Preserve that input before ar changes it; a later output
                    # hash cannot reconstruct the cold members' causal history.
                    prior = (cwd / output).resolve()
                    if prior.is_file():
                        trace["providers"].append({**preserve_native_input(prior, session_path),
                                                   "role": "archive-before-update"})
                    for spelling in candidates[1:]:
                        path = (cwd / spelling).resolve()
                        if path.is_file():
                            trace["providers"].append(preserve_native_input(path, session_path))
                        else:
                            trace["issues"].append("archive member input unavailable: " + spelling)
            else:
                output = next((arg for arg in args if not arg.startswith("-")), None)
                if output and (cwd / output).is_file():
                    trace["providers"].append(preserve_native_input(cwd / output, session_path))
            event["effective_argv"] = effective
            executed = True
            code = subprocess.run([program, *effective]).returncode
            trace["complete"] = code == 0 and bool(output) and not trace["issues"]
        if code == 0 and output and (cwd / output).is_file():
            artifact = file_info(cwd / output)
            artifact["symbols"] = inspect_symbols(cwd / output, session["tools"]["nm"]["invoked_path"])
            event["outputs"].append(artifact)
            if event["kind"] in {"archive", "archive-index"}:
                trace["archive_members"] = native_archive_members(cwd / output)
        event["capture_errors"].extend("native linkage: " + issue for issue in trace["issues"])
    except (CaptureError, OSError, ValueError, KeyError) as error:
        event["capture_errors"].append(str(error))
        # A diagnostic recorder failure never substitutes its status for an
        # upstream tool that has not yet executed.
        if not executed and program is not None:
            try:
                event["effective_argv"] = original_args
                code = subprocess.run([program, *original_args]).returncode
            except OSError as native_error:
                event["capture_errors"].append("native tool execution: " + str(native_error))
    finally:
        event.update(exit_code=code, state="finished", finished_ns=time.time_ns())
        write_json(event_path, event)
        if event.get("parent_invocation_id"):
            write_json(session_path / "native-parents" / event["parent_invocation_id"] / (event_id + ".json"),
                       {"event": file_info(event_path)})
    return code


def driver_link_plan(program: str, args: list[str], directory: Path, environment: dict, name: str = "driver-link-plan") -> dict:
    result = subprocess.run([program, *args, "-###"], env=environment, capture_output=True)
    path = directory / (name + ".txt")
    path.write_bytes(result.stdout + result.stderr)
    commands = []
    for line in result.stderr.decode(errors="replace").splitlines():
        if line.lstrip().startswith('"'):
            commands.append(shlex.split(line))
    return {"diagnostic_only": True, "argv": [program, *args, "-###"],
            "exit_code": result.returncode, "artifact": file_info(path), "commands": commands}


def compiler(session_path: Path, kind: str, original_args: list[str], *,
             expected_cargo_observer_sha256: str | None = None) -> int:
    session = read_json(session_path / "session.json")
    driver_kind = kind
    kind = "clang" if kind == "cxx" else kind
    event_id = uuid.uuid4().hex
    directory = session_path / "units" / event_id
    directory.mkdir(parents=True)
    event_path = session_path / "events" / (event_id + ".json")
    cwd = Path.cwd().resolve()
    program = session["tools"][driver_kind]["invoked_path"]
    if kind == "rustc":
        # Cargo RUSTC_WRAPPER passes the actual stage-specific rustc first.
        if not original_args:
            raise CaptureError("Rust wrapper requires the real compiler as its first argument")
        program, original_args = original_args[0], original_args[1:]
    event = {"id": event_id, "kind": kind, "driver_kind": driver_kind, "compiler": program, "cwd": str(cwd),
             "argv": original_args, "started_ns": time.time_ns(), "state": "running",
             "units": [], "capture_errors": [], "outputs": [],
             "parent_invocation_id": os.environ.get("OCORE_CAPTURE_PARENT_EVENT")}
    # Recipes execute steps sequentially; parallel compiler children belong to
    # the currently active step. Older journals can be resolved by timestamps.
    if session.get("build_steps"):
        step = session["build_steps"][-1]
        if step.get("exit_code") is None:
            event["build_step"] = {"index": len(session["build_steps"]) - 1, "name": step["name"]}
    event["build_environment"] = {key: os.environ[key] for key in
        ["CPPFLAGS", "CFLAGS", "CXXFLAGS", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
         "RUSTC_BOOTSTRAP", "RUSTC_WRAPPER", "RUSTC_WRAPPER_REAL", "RUSTC_STAGE",
         "RUSTC_REAL", "RUSTC_SNAPSHOT", "RUSTC_SYSROOT", "RUSTC_LIBDIR", "RUSTC_HOST_LINKER",
         "RUSTC_LINK_STD_INTO_RUSTC_DRIVER", "CARGO_MANIFEST_DIR", "CARGO_TARGET_DIR", "OUT_DIR",
         "HOST", "TARGET", "OPT_LEVEL", "PROFILE", "DEBUG", "NUM_JOBS", "LD_LIBRARY_PATH", "LIBRARY_PATH", "COMPILER_PATH",
         "PKG_CONFIG_PATH", "SOURCE_DATE_EPOCH", CARGO_PARENT_VARIABLE] if key in os.environ}
    write_json(event_path, event)
    native_code = 127
    cargo_parent = None
    try:
        executing_worker = file_info(Path(__file__))
        event["capture_worker"] = executing_worker
        bound = None
        try:
            bound = verify_worker(session, session_path, executing_worker["sha256"])
            if executing_worker != bound["artifact"]:
                bound = None
                raise CaptureError("compiler invocation did not execute its frozen capture worker")
        except (CaptureError, OSError, KeyError, TypeError) as error:
            # Old development captures retain original native behavior and all
            # diagnostic units; they cannot be retroactively admitted as bound.
            event["capture_errors"].append("capture worker provenance: " + str(error))
        if CARGO_PARENT_VARIABLE in os.environ:
            try:
                if bound is None:
                    raise CaptureError("Cargo parent requires the currently executing bound capture worker")
                cargo_parent = validate_cargo_parent(json.loads(os.environ[CARGO_PARENT_VARIABLE]),
                    session_path, session, executing_worker, expected_cargo_observer_sha256)
                event["cargo_parent_invocation_id"] = cargo_parent["id"]
                event["cargo_parent"] = cargo_parent
            except (CaptureError, OSError, ValueError, KeyError, TypeError) as error:
                event["capture_errors"].append("Cargo parent provenance: " + str(error))
        rust_policy = session.get("recipe", {}).get("toolchain", {}).get("rust_capture_policy") if kind == "rustc" else None
        argfile_gap = None
        try:
            args, response_files = expand_response_files(original_args, cwd, rust=kind == "rustc")
        except (CaptureError, OSError, UnicodeError):
            if kind != "rustc" or rust_policy != RUST_EMBEDDED_POLICY:
                raise
            args, response_files = list(original_args), []
            argfile_gap = {"kind": "rust_argfile_read_unsupported",
                "message": "original Rust argfile could not be decoded by capture; original command forwarded"}
        event["expanded_argv"] = args
        event["response_files"] = response_files
        if rust_policy is not None and rust_policy != RUST_EMBEDDED_POLICY:
            raise CaptureError("unsupported Rust capture policy")
        if rust_policy is not None:
            argfile_gap = argfile_gap or rust_argfile_gap(args)
            if argfile_gap:
                event["capture_errors"].append("Rust argfile capture gap: " + argfile_gap["message"])
        event["link_inputs"] = observed_link_inputs(args if argfile_gap is None else [], cwd)
        # Unsupported Rust parsing cannot invent source/link ownership or try
        # to turn a response-file NUL into an OS filesystem path.
        inputs = [] if argfile_gap is not None else (clang_inputs(args, cwd) if kind == "clang" else [
            (cwd / arg).resolve() for arg in args if not arg.startswith("-") and arg.endswith(".rs")])
        event["sources"] = [file_info(path) for path in inputs]
        executed_args = original_args
        if rust_policy is not None:
            event.setdefault("cargo_parent_invocation_id", None)
            event["rust_response_files"] = [{"source": artifact,
                "artifact": retain_range(artifact, 0, artifact["bytes"], directory / f"response-{index}.rsp")}
                for index, artifact in enumerate(response_files)]
            applied = rust_translation(args, inputs) and argfile_gap is None
            instrumented, transformations = rust_instrumentation(args, applied)
            # Queries retain their exact incoming response-file invocation.
            executed_args = instrumented if applied else original_args
            event["rust_capture"] = {"policy": rust_policy, "applied": applied,
                "transformations": transformations, "original_command_executed": executed_args == original_args,
                "frontend_replay_used": False, "post_lto_equivalence_verified": False, "argfile_gap": argfile_gap}
            event["executed_argv"] = executed_args
        header_compile = kind == "clang" and clang_header_compile(args, inputs)
        if kind == "clang":
            try:
                compiler_inputs = clang_compiler_inputs(args, cwd)
                if compiler_inputs:
                    event["compiler_inputs"] = compiler_inputs
            except (OSError, CaptureError) as error:
                # Preserve the original frontend result, including a missing
                # or invalid cache diagnostic, instead of skipping execution.
                event["capture_errors"].append("compiler-cache input: " + str(error))
        if kind == "rustc":
            info = tool_info(program, "rustc")
            explicit_sysroot = option_value(args, "--sysroot")
            info["effective_sysroot"] = (info["default_sysroot"] if explicit_sysroot is None else explicit_sysroot) if argfile_gap is None else None
            info["sysroot_source"] = ("queried-default" if explicit_sysroot is None else "explicit-argv") if argfile_gap is None else "unresolved-argfile"
            event["frontend"] = info
            expected = session["recipe"]["toolchain"]
            if info["llvm_version"] != expected["llvm_version"]:
                raise CaptureError(f"stage rustc uses LLVM {info['llvm_version']}, expected {expected['llvm_version']}")
            if expected.get("rustc_release") and info["release"] != expected["rustc_release"]:
                raise CaptureError(f"stage rustc release mismatch: {info['release']}")
        else:
            event["frontend"] = session["tools"][driver_kind]
        native_environment = dict(os.environ)
        native_environment["OCORE_CAPTURE_PARENT_EVENT"] = event_id
        if kind == "clang" and not any(arg in {"-c", "-S", "-E", "-M", "-MM", "-fsyntax-only", "--version"} for arg in args):
            baseline_environment = dict(native_environment)
            wrapper_dir = str(session_path / "wrappers")
            for key in ["PATH", "COMPILER_PATH"]:
                baseline_environment[key] = os.pathsep.join(part for part in baseline_environment.get(key, "").split(os.pathsep) if part != wrapper_dir)
            event["original_driver_link_plan"] = driver_link_plan(program, original_args, directory, baseline_environment, "original-driver-link-plan")
            event["driver_link_plan"] = driver_link_plan(program, original_args, directory, native_environment)
            links = [command for command in event["original_driver_link_plan"]["commands"]
                     if Path(command[0]).name in {"ld", "ld.lld", "ld.bfd", "ld.gold"}]
            if len(links) == 1:
                event["selected_linker"] = tool_info(links[0][0], "native-tool")
                native_environment["OCORE_CAPTURE_LINKER_IDENTITY"] = json.dumps(event["selected_linker"])
                write_json(event_path, event)
        native_code = subprocess.run([program, *executed_args], env=native_environment).returncode
        event["exit_code"] = native_code
        query = any(arg in {"-E", "-M", "-MM", "-fsyntax-only", "--version", "-V", "-vV"}
                    or arg.startswith(("--print", "-print", "-dump")) for arg in args)
        metadata_only = kind == "rustc" and option_value(args, "--emit") is not None and not any(
            item.split("=", 1)[0] in {"link", "obj", "asm", "llvm-ir", "llvm-bc"}
            for item in option_value(args, "--emit").split(","))
        event["translation_required"] = bool(inputs) and not query and not metadata_only and not header_compile
        event["classification"] = "query" if query else "precompiled-header" if header_compile else "analysis-only" if metadata_only else "compile" if inputs else "link-or-query"
        if native_code == 0 and not query and event.get("driver_link_plan", {}).get("commands"):
            links = [command for command in event["driver_link_plan"]["commands"]
                     if Path(command[0]).name in {"ld", "ld.lld", "ld.bfd", "ld.gold"}]
            event["linkage_capture_required"] = bool(links)
            if links:
                children = [read_json(Path(read_json(path)["event"]["path"]))
                            for path in (session_path / "native-parents" / event_id).glob("*.json")]
                event["native_tool_invocation_ids"] = [child["id"] for child in children
                    if child.get("parent_invocation_id") == event_id and child.get("kind") == "linker"]
                if not event["native_tool_invocation_ids"]:
                    event["capture_errors"].append("actual driver linker bypassed the pinned native-tool wrapper; linkage remains uninstrumented")
        if native_code == 0 and not query and "-" in args:
            event["capture_errors"].append("stdin translation units require replayable source capture and are unsupported")
        if native_code == 0 and not query:
            for path in native_outputs(kind, args, inputs, cwd):
                if path.is_file():
                    item = file_info(path)
                    if header_compile:
                        with path.open("rb") as stream:
                            if stream.read(4) != b"CPCH":
                                raise CaptureError("header-cache invocation did not produce a Clang serialized AST: " + str(path))
                        item["artifact_kind"] = "clang-precompiled-header"
                        item["header_sources"] = event["sources"]
                        depfile = option_value(args, "-MF")
                        if depfile:
                            item["dependencies"] = dependency_files((cwd / depfile).resolve(), cwd)
                    # Metadata/text output is not a native symbol table.
                    if not header_compile and path.suffix not in {".rmeta", ".d", ".ll", ".s"}:
                        try:
                            item["symbols"] = inspect_symbols(path, session["tools"]["nm"]["invoked_path"])
                        except CaptureError as error:
                            item["symbol_error"] = str(error)
                            event["capture_errors"].append(str(error))
                    event["outputs"].append(item)
                    with path.open("rb") as stream:
                        if stream.read(8) == b"!<arch>\n":
                            item["archive_members"] = native_archive_members(path)
        if native_code == 0 and event["translation_required"]:
            if kind == "clang":
                for index, source in enumerate(inputs):
                    if source.suffix in ASM_SUFFIXES:
                        event["capture_errors"].append(f"assembly translation unit requires an explicit target-specific importer: {source}")
                        continue
                    output, depfile = directory / f"unit-{index}.ll", directory / f"unit-{index}.d"
                    replay = [program, *clang_replay(args, source, inputs, cwd, output, depfile)]
                    with (directory / f"unit-{index}.stderr").open("wb") as stderr:
                        result = subprocess.run(replay, stdout=stderr, stderr=stderr)
                    item = {"id": f"{event_id}:{index}", "source": file_info(source), "kind": kind,
                            "frontend_version": event["frontend"]["version"], "replay_argv": replay,
                            "replay_exit_code": result.returncode}
                    if result.returncode == 0:
                        item["ir"] = ir_info(output)
                        item["dependencies"] = dependency_files(depfile, cwd)
                    else:
                        event["capture_errors"].append(f"LLVM replay failed for {source}: exit {result.returncode}")
                    event["units"].append(item)
            elif rust_policy == RUST_EMBEDDED_POLICY:
                capture_rust_cgus(event, directory, session)
            else:
                replay = [program, *rust_replay(args, directory)]
                with (directory / "replay.stderr").open("wb") as stderr:
                    result = subprocess.run(replay, stdout=stderr, stderr=stderr)
                event["replay_argv"] = replay
                event["replay_exit_code"] = result.returncode
                paths = sorted(directory.glob("*.ll"))
                if result.returncode or not paths:
                    event["capture_errors"].append(f"Rust LLVM replay failed or emitted no units: exit {result.returncode}")
                deps = [item for path in directory.glob("*.d") for item in dependency_files(path, cwd)]
                for index, path in enumerate(paths):
                    event["units"].append({"id": f"{event_id}:{index}", "kind": kind,
                                           "source": file_info(inputs[0]), "ir": ir_info(path),
                                           "frontend_version": event["frontend"]["version"], "dependencies": deps})
    except (CaptureError, OSError, ValueError) as error:
        event["capture_errors"].append(str(error))
    finally:
        event["exit_code"] = native_code
        event["state"] = "finished"
        event["finished_ns"] = time.time_ns()
        write_json(event_path, event)
        if cargo_parent is not None:
            try:
                publish_cargo_child(cargo_parent, session_path, event_path, event, expected_cargo_observer_sha256)
            except (CaptureError, OSError, ValueError, KeyError, TypeError) as error:
                # A missing/duplicate/tampered edge is a capture failure; it
                # must not replace the upstream compiler's actual exit status.
                event["capture_errors"].append("Cargo compiler-child receipt: " + str(error))
                write_json(event_path, event)
    # Forward the observed result of the executed command (instrumented only
    # under the explicit Rust policy), never a counterfactual original result.
    # A failed LLVM replay/byte-edge capture is
    # recorded and rejects the final capture, while later required units still
    # get built and inventoried instead of disappearing after the first gap.
    return native_code


def relative_source(path: str, source: Path) -> str:
    try:
        return str(Path(path).relative_to(source))
    except ValueError:
        return path


def check_requirements(requirements: list[dict], events: list[dict], source: Path) -> list[dict]:
    results = []
    for requirement in requirements:
        matching = [event for event in events if event["kind"] == requirement["kind"]
                    and (not requirement.get("build_step") or event.get("build_step", {}).get("name") == requirement["build_step"])
                    and (not requirement.get("invocation_ids") or event["id"] in requirement["invocation_ids"])
                    and any(fnmatch.fnmatchcase(relative_source(item["path"], source), requirement["source"])
                            for item in event.get("sources", []))]
        units = [unit for event in matching for unit in event.get("units", [])
                 if "ir" in unit and fnmatch.fnmatchcase(relative_source(unit["source"]["path"], source), requirement["source"])
                 and (not requirement.get("target_triple") or unit["ir"]["target_triple"] == requirement["target_triple"])]
        failures = [event["id"] for event in matching if event.get("exit_code", 1) != 0
                    or event.get("capture_errors") or event.get("state") != "finished"]
        results.append({**requirement, "captured_unit_ids": [unit["id"] for unit in units],
                        "failed_invocation_ids": failures, "complete": bool(units) and not failures})
    return results


def runtime_output_membership(recipe: dict, inventory: dict | None, events: list[dict], build: Path) -> dict:
    """Trace captured native object production into declared final output roots.

    This proves observed build/link membership, not a complete platform/library
    closure. Explicit inventory roots must include dynamically loaded extensions.
    """
    roots, issues, reached, visited, members = {}, [], set(), {}, []
    producers = {}
    by_hash = {}
    for event in events:
        for output in event.get("outputs", []):
            if output.get("artifact_kind") == "clang-precompiled-header":
                continue
            producers.setdefault((output["path"], output["sha256"]), []).append(event)
            by_hash.setdefault(output["sha256"], []).append((event, output))
    for pattern in recipe["coverage"].get("required_outputs", []):
        for path in build.glob(pattern):
            if path.is_file():
                info = file_info(path)
                roots[info["path"]] = info
    try:
        for artifact in (inventory or {}).get("runtime_outputs", []):
            actual = file_info(Path(artifact["path"]))
            if not Path(artifact["path"]).is_absolute() or actual["sha256"] != artifact.get("sha256"):
                raise CaptureError("explicit runtime output requires an absolute path and matching SHA-256")
            if "bytes" in artifact and actual["bytes"] != artifact["bytes"]:
                raise CaptureError("explicit runtime output size mismatch")
            roots[actual["path"]] = actual
    except (CaptureError, OSError, KeyError, TypeError) as error:
        issues.append(f"runtime output inventory: {error}")
    pending = list(roots.values())
    while pending:
        artifact = pending.pop()
        key = (artifact["path"], artifact["sha256"])
        if key in visited:
            continue
        visited[key] = artifact
        matches = producers.get(key, [])
        if not matches:
            # Exact copies retain the original captured production evidence.
            matches = [event for event, _ in by_hash.get(artifact["sha256"], [])]
        for event in matches:
            reached.add(event["id"])
            pending.extend(event.get("link_inputs", {}).get("files", []))
            pending.extend({**provider["original"], "snapshot": provider["snapshot"]}
                           for provider in event.get("native_linkage", {}).get("providers", []))
        try:
            path = Path(artifact.get("snapshot", {}).get("path", artifact["path"]))
            if not path.is_file() or file_info(path)["sha256"] != artifact["sha256"]:
                raise CaptureError(f"recorded runtime-link input unavailable or changed: {path}")
            with path.open("rb") as archive:
                magic = archive.read(8)
                if magic.startswith(b"CPCH"):
                    raise CaptureError(f"compiler header cache is not an executable runtime-link input: {path}")
                if magic == b"!<thin>\n":
                    raise CaptureError(f"thin archive membership is unsupported: {path}")
                if magic != b"!<arch>\n":
                    continue
                for member in native_archive_members(path):
                    members.append({"archive": artifact["path"], "archive_sha256": artifact["sha256"],
                                    "archive_bytes": artifact["bytes"], **member})
                    for event, output in by_hash.get(member["sha256"], []):
                        # Member names distinguish separately compiled same-source
                        # host helpers from the final runtime's native object.
                        if output["bytes"] == member["bytes"] and Path(output["path"]).name == Path(member["member"]).name:
                            reached.add(event["id"])
                            pending.extend(event.get("link_inputs", {}).get("files", []))
                            pending.extend({**provider["original"], "snapshot": provider["snapshot"]}
                                           for provider in event.get("native_linkage", {}).get("providers", []))
        except (CaptureError, OSError, ValueError, UnicodeError) as error:
            issues.append(f"runtime output membership: {error}")
    return {"roots": [roots[key] for key in sorted(roots)], "referenced_files": list(visited.values()),
            "archive_members": members, "contributing_invocation_ids": sorted(reached),
            "complete": bool(roots) and not issues, "issues": sorted(set(issues))}


def native_source_output(owner: dict, output: dict, identity_cache: dict | None = None) -> dict:
    """Derive an ordinary source/object edge, never an enclosing-crate guess.

    The native output and its LLVM replay came from separate compiler commands.
    Their common source/command provenance does not prove O-core lowering.
    """
    result = {"invocation_id": owner["id"], "output": {key: output[key] for key in ("path", "sha256", "bytes")},
              "native_source_owned": False, "llvm_replay_unit_ids": [], "llvm_replay_owned": False}
    try:
        if owner.get("state") != "finished" or owner.get("exit_code") != 0:
            raise CaptureError("source producer did not finish successfully")
        # Rust rlib/CGU outputs have no recorded native-member-to-LLVM-unit edge.
        # A crate's nonempty units cannot supply one, even for ELF metadata or
        # .bundled_lib wrappers containing a whole prebuilt native archive.
        if owner.get("kind") != "clang":
            raise CaptureError("native output has no supported source-to-object command mapping")
        for identity in (owner["capture_worker"], owner["frontend"]):
            path = identity.get("invoked_path", identity["path"])
            if identity_cache is None:
                actual = file_info(Path(path))
            else:
                stat = Path(path).stat()
                stamp = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
                cached = identity_cache.get(path)
                if cached is None or cached["stat"] != stamp:
                    actual = file_info(Path(path))
                    after = Path(path).stat()
                    if stamp != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise CaptureError("source producer identity changed while hashing")
                    identity_cache[path] = {"artifact": actual, "stat": stamp,
                                            "initial_artifact": cached["initial_artifact"] if cached else actual}
                actual = identity_cache[path]["artifact"]
            if actual != {key: identity[key] for key in ("path", "sha256", "bytes")}:
                raise CaptureError("source producer worker/frontend identity changed")
        args, original, cwd = owner["expanded_argv"], owner["argv"], Path(owner["cwd"])
        if not cwd.is_absolute() or not isinstance(args, list) or not isinstance(original, list) or not all(isinstance(arg, str) for arg in args + original):
            raise CaptureError("source producer lacks original command/cwd provenance")
        expanded, responses = expand_response_files(original, cwd)
        if expanded != args or responses != owner.get("response_files", []):
            raise CaptureError("source producer expanded command/response identity changed")
        if owner["compiler"] != owner["frontend"]["invoked_path"]:
            raise CaptureError("source producer command differs from its recorded frontend")
        if "-c" not in args or any(arg in args for arg in ("-S", "-E", "-emit-llvm", "-fsyntax-only")):
            raise CaptureError("native output is not an ordinary source-to-object compilation")
        inputs = clang_inputs(args, cwd)
        if clang_header_compile(args, inputs) or not inputs:
            raise CaptureError("native output is not a source translation unit")
        sources = owner["sources"]
        if [source["path"] for source in sources] != [str(path) for path in inputs]:
            raise CaptureError("source producer command does not match its recorded inputs")
        explicit = option_value(args, "-o")
        if explicit:
            if len(inputs) != 1:
                raise CaptureError("combined source output lacks a per-unit mapping")
            mapping = [(inputs[0], (cwd / explicit).resolve())]
        else:
            mapping = [(source, (cwd / (source.stem + ".o")).resolve()) for source in inputs]
        matched = [source for source, path in mapping if str(path) == output["path"]]
        if len(matched) != 1:
            raise CaptureError("native output lacks an unambiguous source/object mapping")
        source = next(item for item in sources if item["path"] == str(matched[0]))
        if file_info(matched[0]) != source:
            raise CaptureError("source producer original source identity changed")
        result.update(source=source, native_source_owned=True,
                      command={"argv": original, "expanded_argv": args, "cwd": str(cwd)},
                      capture_worker=owner["capture_worker"], frontend=owner["frontend"])
        units = [unit for unit in owner.get("units", []) if unit.get("source") == source and unit.get("kind") == "clang"]
        valid = []
        for unit in units:
            ir = unit.get("ir")
            if unit.get("replay_exit_code") != 0 or not ir or ir_info(Path(ir["path"])) != ir:
                continue
            dependencies = unit.get("dependencies")
            if (not isinstance(dependencies, list) or source not in dependencies
                    or any(file_info(Path(item["path"])) != item for item in dependencies)):
                continue
            expected = [owner["compiler"], *clang_replay(args, matched[0], inputs, cwd,
                        Path(ir["path"]), Path(ir["path"]).with_suffix(".d"))]
            if unit.get("replay_argv") == expected and unit.get("frontend_version") == owner["frontend"]["version"]:
                valid.append(unit["id"])
        # Multiple matching replays need an explicit association rather than
        # selecting an arbitrary first LLVM unit.
        result["llvm_replay_unit_ids"] = valid
        result["llvm_replay_owned"] = len(units) == 1 and len(valid) == 1
        if not result["llvm_replay_owned"]:
            result["reason"] = "native source origin has no unambiguous corresponding successful LLVM replay"
    except (CaptureError, OSError, KeyError, TypeError, ValueError) as error:
        result["reason"] = str(error)
    return result


def linkage_evidence(events: list[dict], membership: dict) -> dict:
    """Reconstruct member source origin and report LLVM replay separately."""
    issues, traces, unowned, replay_gaps, member_evidence, provider_evidence = [], [], [], [], [], []
    outputs_by_hash, source_cache, provider_cache, identity_cache = {}, {}, {}, {}
    for event in events:
        for output in event.get("outputs", []):
            outputs_by_hash.setdefault(output["sha256"], []).append((event, output))

    def owners(artifact):
        return [(owner, output) for owner, output in outputs_by_hash.get(artifact["sha256"], [])
                if output["bytes"] == artifact["bytes"]]

    def preceding(owner, consumer):
        if consumer is None:
            return True
        start, end, observed = owner.get("started_ns"), owner.get("finished_ns"), consumer.get("started_ns")
        return (isinstance(start, int) and isinstance(end, int) and isinstance(observed, int)
                and 0 <= start <= end <= observed)

    def candidates(artifact, consumer):
        rows = []
        for owner, output in owners(artifact):
            key = (owner["id"], output["path"], output["sha256"], output["bytes"])
            if key not in source_cache:
                source_cache[key] = native_source_output(owner, output, identity_cache)
            row = dict(source_cache[key])
            row["observed_input_match"] = output["path"] == artifact["path"] and preceding(owner, consumer)
            rows.append(row)
        return rows

    def provider_bytes(provider):
        original, snapshot = provider["original"], provider["snapshot"]
        key = (snapshot["path"], snapshot["sha256"], snapshot["bytes"])
        if key not in provider_cache:
            provider_cache[key] = file_info(Path(snapshot["path"])) == snapshot
        if (not provider_cache[key] or snapshot["sha256"] != original["sha256"]
                or snapshot["bytes"] != original["bytes"]):
            raise CaptureError("native provider snapshot changed: " + provider["spelling"])
        return Path(snapshot["path"])

    def member_ownership(archive, member, consumer=None):
        """Walk observed ar/ranlib inputs; preserve old/cold and duplicate members."""
        result = {"archive": archive, "archive_member": member,
                  "candidate_outputs": [],
                  "observed_input_edges": [], "native_source_owned": False, "llvm_replay_owned": False}
        # Content candidates remain visible even when no causal archive input
        # joins them. A matching name or an enclosing Rust CGU supplies no edge.
        result["candidate_outputs"] = candidates({**member, "path": ""}, None)
        pending, seen = [(archive, member, consumer)], set()
        while pending:
            current, current_member, observed = pending.pop()
            key = (current["path"], current["sha256"], current_member["index"],
                   observed["id"] if observed else None)
            if key in seen:
                continue
            seen.add(key)
            for owner, output in owners(current):
                trace = owner.get("native_linkage", {})
                if (owner.get("kind") not in {"archive", "archive-index"}
                        or owner.get("state") != "finished" or owner.get("exit_code") != 0
                        or trace.get("complete") is not True or not preceding(owner, observed)):
                    continue
                tool = owner.get("tool", {})
                if file_info(Path(tool["invoked_path"])) != {field: tool[field] for field in ("path", "sha256", "bytes")}:
                    continue
                for index, provider in enumerate(trace["providers"]):
                    path = provider_bytes(provider)
                    original = provider["original"]
                    if original["sha256"] == current_member["sha256"] and original["bytes"] == current_member["bytes"]:
                        matched = candidates(original, owner)
                        edge = {"archive": current, "archive_member": current_member,
                                "archive_producer_invocation_id": owner["id"], "provider_index": index,
                                "provider": provider, "candidate_outputs": matched}
                        result["observed_input_edges"].append(edge)
                        result["native_source_owned"] |= any(row["observed_input_match"] and row["native_source_owned"] for row in matched)
                        result["llvm_replay_owned"] |= any(row["observed_input_match"] and row["llvm_replay_owned"] for row in matched)
                    else:
                        with path.open("rb") as stream:
                            magic = stream.read(8)
                        if magic == b"!<arch>\n":
                            for prior in native_archive_members(path):
                                if (prior["sha256"], prior["bytes"]) == (current_member["sha256"], current_member["bytes"]):
                                    result["observed_input_edges"].append({
                                        "archive": current, "archive_member": current_member,
                                        "archive_producer_invocation_id": owner["id"],
                                        "provider_index": index, "provider": provider,
                                        "prior_archive_member": prior})
                                    pending.append((original, prior, owner))
        result["complete"] = result["native_source_owned"]
        if not result["native_source_owned"]:
            result["reason"] = "archive member lacks an observed source/object input edge"
        elif not result["llvm_replay_owned"]:
            result["replay_reason"] = "native source origin has no unambiguous corresponding successful LLVM replay"
        member_evidence.append(result)
        return result

    def archive_ownership(artifact, path, identity, consumer=None):
        for member in native_archive_members(path):
            proof = member_ownership(artifact, member, consumer)
            if not proof["native_source_owned"]:
                unowned.append({**identity, "archive_member": member, "reason": proof["reason"]})
            if not proof["llvm_replay_owned"]:
                replay_gaps.append({**identity, "archive_member": member,
                                    "native_source_owned": proof["native_source_owned"],
                                    "reason": proof.get("replay_reason", proof.get("reason"))})

    def ordinary_ownership(artifact, identity, consumer=None):
        rows = candidates(artifact, consumer)
        # Executable/shared or partial-link containers propagate observed linker
        # inputs; their native tool event cannot manufacture a source owner.
        containers = [owner["id"] for owner, _ in owners(artifact)
                      if owner.get("kind") == "linker" and owner.get("state") == "finished"
                      and owner.get("exit_code") == 0 and preceding(owner, consumer)
                      and owner.get("native_linkage", {}).get("complete") is True
                      and owner.get("native_linkage", {}).get("providers")
                      and owner["id"] in reached]
        origin = any(row["observed_input_match"] and row["native_source_owned"] for row in rows)
        replay = any(row["observed_input_match"] and row["llvm_replay_owned"] for row in rows)
        proof = {**identity, "candidate_outputs": rows, "native_source_owned": origin,
                 "llvm_replay_owned": replay, "propagated_linker_invocation_ids": containers,
                 "complete": bool(containers) or origin}
        provider_evidence.append(proof)
        if not proof["complete"]:
            unowned.append({**identity, "reason": "native provider lacks a source/object input edge"})
        if not containers and not replay:
            replay_gaps.append({**identity, "native_source_owned": origin,
                                "reason": "native provider lacks a corresponding successful LLVM replay"})

    reached = set(membership["contributing_invocation_ids"])
    for event in events:
        trace = event.get("native_linkage")
        if trace is None or event["id"] not in reached:
            continue
        traces.append({"invocation_id": event["id"], "kind": event["kind"],
                       "tool": event["tool"], "parent_invocation_id": event.get("parent_invocation_id"),
                       "ordered_argv": trace["ordered_argv"], "link_inputs": event["link_inputs"],
                       "providers": trace["providers"], "archive_members": trace["archive_members"],
                       "complete": trace["complete"]})
        if trace["complete"] is not True:
            issues.append("required native tool has incomplete instrumentation: " + event["id"])
        for artifact in [trace.get("dependency_trace"), trace.get("archive_trace")]:
            if artifact and file_info(Path(artifact["path"])) != artifact:
                issues.append("actual native-tool trace changed: " + event["id"])
        if file_info(Path(event["tool"]["invoked_path"])) != {key: event["tool"][key] for key in ("path", "sha256", "bytes")}:
            issues.append("actual selected native-tool binary changed: " + event["id"])
        for provider in trace["providers"]:
            snapshot, original = provider["snapshot"], provider["original"]
            try:
                path = provider_bytes(provider)
            except CaptureError as error:
                issues.append(str(error))
                continue
            with path.open("rb") as stream:
                magic = stream.read(8)
            identity = {"invocation_id": event["id"], **provider,
                        "producer_invocation_ids": sorted({owner["id"] for owner, _ in owners(original)})}
            if magic == b"!<arch>\n":
                archive_ownership(original, path, identity, event)
            else:
                ordinary_ownership(original, identity, event)
    for root in membership["roots"]:
        root_owners = owners(root)
        with Path(root["path"]).open("rb") as stream:
            header = stream.read(18)
        elf_linked = header.startswith(b"\x7fELF") and len(header) >= 18 and int.from_bytes(header[16:18], "little" if header[5] == 1 else "big") in {2, 3}
        if elf_linked and not any(owner.get("kind") == "linker" and owner.get("state") == "finished"
                                  and owner.get("exit_code") == 0 and owner.get("native_linkage", {}).get("complete") is True
                                  and owner.get("native_linkage", {}).get("providers") and owner["id"] in reached
                                  for owner, _ in root_owners):
            issues.append("native runtime output lacks an actual captured linker trace: " + root["path"])
        if header.startswith(b"!<arch>\n"):
            archive_ownership(root, Path(root["path"]), {"archive": root})
        else:
            ordinary_ownership(root, {"root": root})
    # Rehash each cached identity after the whole traversal. A file replaced
    # during reconstruction cannot leave an earlier candidate silently trusted.
    for path, cached in identity_cache.items():
        try:
            if file_info(Path(path)) != cached["initial_artifact"]:
                issues.append("source producer worker/frontend identity changed during reconstruction: " + path)
        except OSError as error:
            issues.append("source producer worker/frontend identity unavailable: " + str(error))
    all_proofs = member_evidence + provider_evidence
    origin_complete = all(proof["native_source_owned"] or proof.get("propagated_linker_invocation_ids") for proof in all_proofs)
    return {"schema": "ocore-native-linkage-evidence-v1", "actual_tool_traces": traces,
            "provider_identity_complete": bool(membership["roots"]) and not issues,
            "issues": sorted(set(issues)), "unowned_native_providers": unowned,
            "archive_member_ownership": member_evidence, "provider_ownership": provider_evidence,
            "native_source_ownership_complete": bool(traces) and origin_complete and not issues,
            "source_provider_ownership_complete": bool(traces) and not unowned and not issues,
            "llvm_replay_ownership_complete": bool(traces) and not replay_gaps and not issues,
            "unmatched_llvm_replays": replay_gaps,
            "ownership_level": "observed-native-source-object-input-edges; LLVM-replay-coverage-separate",
            "dependency_closure_complete": False,
            "scope": "actual-linker-archive-inputs; dynamic-platform-and-declared-source-closure-still-required"}


def partition_units(units: list[dict], required: list[dict], inventory: dict | None,
                    inventory_info: dict | None, events: list[dict], steps: list[dict],
                    source: Path, recipe_required_count: int = 0, membership: dict | None = None) -> dict:
    """Assign every LLVM unit an explicit role, retaining the complete journal.

    Runtime selections come from the complete build inventory and recipe floors.
    Exclusions require an inventory rule and hashed evidence; source names alone
    never silently turn an implementation unit into a configure probe.
    """
    known = {unit["id"]: unit for unit in units}
    issues = []
    if len(known) != len(units):
        issues.append("duplicate captured LLVM unit IDs")
    # Floors establish necessary runtime capabilities; the full inventory decides
    # which source/target/stage variants are actually runtime implementations.
    selected_requirements = required[recipe_required_count:] if inventory_info else required
    lowering = {unit_id for item in selected_requirements for unit_id in item["captured_unit_ids"]}
    excluded = {}
    owners = {unit["id"]: event for event in events for unit in event.get("units", []) if "ir" in unit}
    step_evidence = {}
    rule_ids = set()

    def step_for(event: dict) -> dict | None:
        # Resolve old journals from actual sequential build-step intervals.
        matches = [(index, step) for index, step in enumerate(steps)
                   if step.get("started_ns", 0) <= event.get("started_ns", -1)
                   and event.get("finished_ns", event.get("started_ns", -1)) <= step.get("finished_ns", -1)]
        if len(matches) != 1:
            return None
        index, step = matches[0]
        recorded = event.get("build_step")
        if recorded is not None and recorded != {"index": index, "name": step["name"]}:
            return None
        if index in step_evidence:
            return step_evidence[index]
        evidence = {"index": index, "name": step["name"], "argv": step["argv"],
                    "cwd": step["cwd"], "exit_code": step["exit_code"]}
        try:
            evidence["log"] = file_info(Path(step["log"]))
        except OSError:
            return None
        step_evidence[index] = evidence
        return evidence

    for rule in (inventory or {}).get("non_lowering_units", []):
        try:
            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str) or not rule["id"]:
                raise CaptureError("non-lowering rule needs an ID")
            if rule["id"] in rule_ids:
                raise CaptureError(f"duplicate non-lowering rule ID: {rule['id']}")
            rule_ids.add(rule["id"])
            if rule.get("role") not in {"configure_probe", "host_build_tool"}:
                raise CaptureError(f"{rule['id']}: non-lowering role must be configure_probe or host_build_tool")
            evidence = rule.get("evidence")
            if not isinstance(evidence, dict) or not isinstance(evidence.get("reason"), str) or not evidence["reason"].strip():
                raise CaptureError(f"{rule['id']}: non-lowering evidence needs an explicit reason")
            artifacts = evidence.get("artifacts")
            if not isinstance(artifacts, list) or not artifacts:
                raise CaptureError(f"{rule['id']}: non-lowering evidence needs hashed build artifacts")
            verified_artifacts = []
            for artifact in artifacts:
                if not Path(artifact["path"]).is_absolute():
                    raise CaptureError(f"{rule['id']}: evidence artifact paths must be absolute")
                actual = file_info(Path(artifact["path"]))
                if actual["sha256"] != artifact.get("sha256") or ("bytes" in artifact and actual["bytes"] != artifact["bytes"]):
                    raise CaptureError(f"{rule['id']}: non-lowering artifact hash/size mismatch")
                verified_artifacts.append(actual)
            if "unit_ids" in rule:
                ids = rule["unit_ids"]
                if not isinstance(ids, list) or not ids or not all(isinstance(item, str) for item in ids):
                    raise CaptureError(f"{rule['id']}: unit_ids must contain exact captured unit IDs")
                if len(set(ids)) != len(ids) or any(item not in known for item in ids):
                    raise CaptureError(f"{rule['id']}: duplicate or unavailable captured unit ID")
                selected = ids
            else:
                if rule.get("kind") not in {"clang", "rustc"} or not isinstance(rule.get("source"), str) or not isinstance(rule.get("build_step"), str):
                    raise CaptureError(f"{rule['id']}: source selectors need kind, source and build_step")
                selected = []
                for unit_id, unit in known.items():
                    event = owners[unit_id]
                    step = step_for(event)
                    if unit["kind"] == rule["kind"] and fnmatch.fnmatchcase(relative_source(unit["source"]["path"], source), rule["source"]) and step and step["name"] == rule["build_step"]:
                        selected.append(unit_id)
                if not selected:
                    raise CaptureError(f"{rule['id']}: non-lowering selector matched no captured units")
            for unit_id in selected:
                if unit_id in lowering or unit_id in excluded:
                    raise CaptureError(f"{rule['id']}: conflicting role for captured unit {unit_id}")
                if membership is None or not membership["complete"]:
                    raise CaptureError(f"{rule['id']}: declared runtime-output membership is incomplete")
                if owners[unit_id]["id"] in membership["contributing_invocation_ids"]:
                    raise CaptureError(f"{rule['id']}: excluded unit contributes to a declared runtime output: {unit_id}")
                step = step_for(owners[unit_id])
                if step is None:
                    raise CaptureError(f"{rule['id']}: captured unit has no unique recorded build step")
                excluded[unit_id] = {"unit_id": unit_id, "role": rule["role"], "rule_id": rule["id"],
                                     "evidence": {"reason": evidence["reason"], "artifacts": verified_artifacts,
                                                  "inventory": inventory_info, "build_step": step}}
        except (CaptureError, OSError, KeyError, TypeError) as error:
            issues.append(f"unit role inventory: {error}")
    for event in events:
        ids = {unit["id"] for unit in event.get("units", []) if "ir" in unit}
        if ids & lowering and ids & set(excluded):
            issues.append(f"frontend invocation has both runtime and non-runtime codegen units: {event['id']}")
    unclassified = sorted(set(known) - lowering - set(excluded))
    if unclassified:
        issues.append(f"{len(unclassified)} captured LLVM units have no explicit lowering/non-lowering role")
    return {"lowering_unit_ids": sorted(lowering),
            "non_lowering_units": [excluded[key] for key in sorted(excluded)],
            "unclassified_unit_ids": unclassified, "complete": not issues, "issues": issues}


def make_report(directory: Path, persist: bool = True, expected_worker_sha256: str | None = None) -> dict:
    session = read_json(directory / "session.json")
    recipe = session["recipe"]
    events = [read_json(path) for path in sorted((directory / "events").glob("*.json"))]
    source, build = Path(session["source"]["path"]), Path(session["build"])
    issues = list(session.get("issues", []))
    try:
        worker = verify_worker(session, directory, expected_worker_sha256)
        for event in events:
            if event.get("capture_worker") != worker["artifact"]:
                issues.append(f"compiler invocation has unbound/mixed capture worker provenance: {event['id']}")
    except (CaptureError, OSError, KeyError, TypeError) as error:
        issues.append("capture worker provenance: " + str(error))
    try:
        if file_info(Path(session["manifest"]["path"]))["sha256"] != session["manifest"]["sha256"]:
            issues.append("recipe bytes changed during capture")
        if session["source"].get("clean_at_start"):
            if run_text(["git", "rev-parse", "HEAD"], source) != session["source"]["revision"]:
                issues.append("source commit changed during capture")
            if run_text(["git", "status", "--porcelain", "--untracked-files=normal"], source):
                issues.append("source checkout changed during capture")
    except (CaptureError, OSError) as error:
        issues.append(f"source/recipe revalidation: {error}")
    requirements = list(recipe["coverage"]["required_units"])
    recipe_required_count = len(requirements)
    inventory_complete = False
    inventory = None
    inventory_info = None
    inventory_path = session.get("inventory_path")
    if inventory_path:
        try:
            inventory = read_json(Path(inventory_path))
            inventory_info = file_info(Path(inventory_path))
            if session.get("inventory_artifact") != inventory_info:
                raise CaptureError("full unit inventory differs from its finalized capture journal artifact")
            if inventory.get("schema") != INVENTORY_SCHEMA or inventory.get("complete") is not True:
                raise CaptureError("expected-unit inventory must use the pinned schema and declare complete:true")
            extra = inventory.get("units")
            if not isinstance(extra, list) or not extra:
                raise CaptureError("expected-unit inventory must contain units")
            validate_recipe({**recipe, "coverage": {"required_units": extra}})
            requirements.extend(extra)
            inventory_complete = True
        except (CaptureError, OSError, ValueError) as error:
            inventory_info = None
            issues.append(f"unit inventory: {error}")
    if recipe["coverage"].get("require_full_unit_inventory", False) and not inventory_complete:
        issues.append("full build-generated source-unit inventory is required and unavailable")
    required = check_requirements(requirements, events, source)
    issues.extend(f"required unit incomplete: {item['id']} ({item['source']})" for item in required if not item["complete"])
    for event in events:
        if event.get("state") != "finished":
            issues.append(f"unfinished compiler invocation: {event['id']}")
        issues.extend(f"invocation {event['id']}: {error}" for error in event.get("capture_errors", []))
        try:
            verify_rust_capture_event(event, session, directory)
        except (CaptureError, OSError, ValueError, KeyError, TypeError) as error:
            issues.append(f"Rust embedded capture readmission {event['id']}: {error}")
        compiler_artifacts = [*event.get("compiler_inputs", []),
                              *[item for item in event.get("outputs", []) if item.get("artifact_kind") == "clang-precompiled-header"]]
        for artifact in compiler_artifacts:
            try:
                if file_info(Path(artifact["path"])) != {key: artifact[key] for key in ("path", "sha256", "bytes")}:
                    issues.append(f"compiler header cache changed: {artifact['path']}")
            except OSError as error:
                issues.append(f"compiler header cache unavailable: {error}")
    for pattern in recipe["coverage"].get("required_outputs", []):
        if not any(build.glob(pattern)):
            issues.append(f"required build output missing: {pattern}")
    outputs = [output for event in events for output in event.get("outputs", [])]
    produced = {output["path"] for output in outputs}
    output_hashes = {output["sha256"]: output["path"] for output in outputs}
    uncaptured = []
    copied_outputs = []
    for root in session["audit_roots"]:
        root_path = Path(root)
        if not root_path.is_dir():
            issues.append(f"audit root missing: {root}")
            continue
        for path in root_path.rglob("*"):
            if path.is_file() and path.suffix in {".o", ".obj", ".rlib"} and str(path.resolve()) not in produced:
                item = file_info(path)
                if item["sha256"] in output_hashes:
                    copied_outputs.append({**item, "captured_origin": output_hashes[item["sha256"]]})
                else:
                    uncaptured.append(item)
    if uncaptured:
        issues.append(f"{len(uncaptured)} native object/archive outputs have no captured compiler invocation")
    build_steps = session.get("build_steps", [])
    if not build_steps or any(step.get("exit_code") != 0 for step in build_steps):
        issues.append("required build did not complete successfully")
    for step in build_steps:
        try:
            if step.get("log_artifact") != file_info(Path(step["log"])):
                issues.append(f"build log differs from its finalized capture journal artifact: {step['name']}")
        except OSError as error:
            issues.append(f"build log unavailable: {step['name']}: {error}")
    units = [unit for event in events for unit in event.get("units", []) if "ir" in unit]
    membership = runtime_output_membership(recipe, inventory, events, build)
    try:
        linkage = linkage_evidence(events, membership)
        issues.extend("native linkage: " + issue for issue in linkage["issues"])
    except (CaptureError, OSError, ValueError, KeyError) as error:
        linkage = {"schema": "ocore-native-linkage-evidence-v1", "provider_identity_complete": False,
                   "source_provider_ownership_complete": False, "native_source_ownership_complete": False,
                   "llvm_replay_ownership_complete": False, "dependency_closure_complete": False,
                   "actual_tool_traces": [], "unowned_native_providers": [], "unmatched_llvm_replays": [],
                   "archive_member_ownership": [], "provider_ownership": [], "issues": [str(error)]}
        issues.append("native linkage reconstruction: " + str(error))
    partition = partition_units(units, required, inventory, inventory_info, events, build_steps, source,
                                recipe_required_count, membership)
    issues.extend(partition["issues"])
    inventory_complete = inventory_complete and partition["complete"]
    if inventory_info:
        for item in required[:recipe_required_count]:
            item["captured_unit_ids"] = sorted(set(item["captured_unit_ids"]) & set(partition["lowering_unit_ids"]))
            item["complete"] = item["complete"] and bool(item["captured_unit_ids"])
            if not item["complete"]:
                issues.append(f"required unit incomplete: {item['id']} ({item['source']})")
    for unit in units:
        try:
            actual = ir_info(Path(unit["ir"]["path"]), session["tools"].get("llvm_dis"))
            if actual != unit["ir"]:
                issues.append(f"LLVM unit bytes or target metadata changed: {unit['id']}")
        except (CaptureError, OSError, ValueError) as error:
            issues.append(f"LLVM unit unavailable: {unit['id']}: {error}")
    defined, undefined = set(), set()
    dependency_files_by_path = {}
    for event in events:
        for output in event.get("outputs", []):
            defined.update(output.get("symbols", {}).get("defined", []))
            undefined.update(output.get("symbols", {}).get("undefined", []))
        for item in event.get("link_inputs", {}).get("files", []):
            dependency_files_by_path[item["path"]] = item
    issues = sorted(set(issues))
    complete = not issues
    report = {"schema": REPORT_SCHEMA, "name": recipe["name"], "manifest": session["manifest"],
              "capture_worker": session.get("capture_worker"),
              "source": session["source"], "build": session["build"], "tools": session["tools"],
              "native_tools": session.get("native_tools", {}), "native_linkage": linkage,
              "build_steps": build_steps, "invocations": events, "units": units,
              "unit_inventory": {"file": inventory_info, "definition": inventory} if inventory_info else None,
              "lowering_unit_ids": partition["lowering_unit_ids"],
              "non_lowering_units": partition["non_lowering_units"],
              "unclassified_unit_ids": partition["unclassified_unit_ids"],
              "unit_roles_complete": partition["complete"],
              "runtime_output_membership": membership,
              "required_units": required, "failed_required_units": [item for item in required if not item["complete"]],
              "uncaptured_outputs": uncaptured, "issues": issues,
              "copies_of_captured_outputs": copied_outputs,
              "capture_complete": complete, "unit_inventory_complete": inventory_complete,
              "dependency_closure_complete": False, "ocore_lowering_complete": False,
              "native_execution_qualified": False, "runtime_complete": False,
              "coverage_scope": "declared-required-units-and-native-output-audit",
              "dependencies": {"declared": recipe.get("dependencies", []),
                               "observed_files": list(dependency_files_by_path.values()),
                               "unresolved_symbols": sorted(undefined - defined), "closed": False},
              "remaining_runtime_requirements": recipe.get("blockers", [])}
    if persist:
        write_json(directory / "report.json", report)
    return report


def verify_report(report: dict, expected_worker_sha256: str | None = None) -> dict:
    """Independently reconstruct capture admission without rewriting evidence.

    Caller-provided selected IDs and required-unit backrefs are compared against
    the original recipe, inventory, journal and actual native output membership.
    Mutually consistent edits to the report cannot redefine that partition.
    """
    if report.get("schema") != REPORT_SCHEMA:
        raise CaptureError(f"capture verification requires {REPORT_SCHEMA}")
    roots = set()
    for unit in report.get("units", []):
        path = Path(unit["ir"]["path"])
        if not path.is_absolute() or len(path.parents) < 3 or path.parent.parent.name != "units":
            raise CaptureError("captured LLVM unit is outside the original journal layout")
        roots.add(path.parents[2].resolve())
    if len(roots) != 1:
        raise CaptureError("captured LLVM units do not resolve one original capture journal")
    directory = roots.pop()
    session = read_json(directory / "session.json")
    trusted_digest = worker_digest(expected_worker_sha256)
    verify_worker(session, directory, trusted_digest)
    original_recipe = read_json(Path(session["manifest"]["path"]))
    validate_recipe(original_recipe)
    if session["recipe"] != original_recipe:
        raise CaptureError("capture session recipe differs from its hashed source artifact")
    if file_info(Path(session["manifest"]["path"])) != session["manifest"]:
        raise CaptureError("capture recipe source artifact changed")
    artifact = session.get("inventory_artifact")
    if artifact is None or file_info(Path(artifact["path"])) != artifact:
        raise CaptureError("full unit inventory differs from its finalized capture journal artifact")
    if session.get("inventory_path") != artifact["path"]:
        raise CaptureError("capture inventory path differs from its finalized journal artifact")
    verify_source(original_recipe, Path(session["source"]["path"]))
    for tool in [*session["tools"].values(), *session.get("native_tools", {}).values()]:
        for artifact in [tool, tool.get("executing_binary")]:
            if artifact is not None and file_info(Path(artifact["path"])) != {key: artifact[key] for key in ["path", "sha256", "bytes"]}:
                raise CaptureError("captured frontend tool artifact changed")
    rebuilt = make_report(directory, persist=False, expected_worker_sha256=trusted_digest)
    differing = sorted(key for key, value in rebuilt.items() if report.get(key) != value)
    if differing:
        raise CaptureError("capture reconstruction differs from reported evidence: " + ", ".join(differing))
    if rebuilt["capture_complete"] is not True or rebuilt["unit_inventory_complete"] is not True or rebuilt["unit_roles_complete"] is not True:
        raise CaptureError("reconstructed source/unit partition is incomplete: " + "; ".join(rebuilt["issues"]))
    if rebuilt["non_lowering_units"] and rebuilt["runtime_output_membership"]["complete"] is not True:
        raise CaptureError("non-lowering roles lack a complete declared runtime-output membership proof")
    return {"schema": "ocore-runtime-capture-verification-v1", "verified": True,
            "scope": "source-capture-unit-role-partition-and-observed-native-output-membership",
            "report_content_sha256": hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "capture_directory": str(directory), "inventory": rebuilt["unit_inventory"]["file"],
            "capture_worker_sha256": trusted_digest,
            "lowering_unit_ids": rebuilt["lowering_unit_ids"],
            "non_lowering_unit_ids": [unit["unit_id"] for unit in rebuilt["non_lowering_units"]],
            "provenance_unit_count": len(rebuilt["units"]),
            "dependency_closure_complete": False, "native_execution_qualified": False, "runtime_complete": False}


def verify_partition(report_path: Path) -> dict:
    """Path API additionally binds the exact input report bytes, without writes."""
    report_path = report_path.resolve()
    result = verify_report(read_json(report_path))
    result["report"] = file_info(report_path)
    return result


def verify_report_cli(arguments: argparse.Namespace) -> int:
    report_path = Path(arguments.report).resolve()
    receipt = Path(arguments.receipt).resolve() if arguments.receipt else None
    if receipt:
        report = read_json(report_path)
        protected = {report_path, report_path.parent / "session.json"}

        def protect(value: object) -> None:
            if isinstance(value, dict):
                if "path" in value and "sha256" in value:
                    protected.add(Path(value["path"]).resolve())
                for child in value.values():
                    protect(child)
            elif isinstance(value, list):
                for child in value:
                    protect(child)

        protect(report)
        protected.update(path.resolve() for path in (report_path.parent / "events").glob("*.json"))
        protected.update(Path(step["log"]).resolve() for step in report.get("build_steps", []))
        if receipt in protected:
            raise CaptureError("verification receipt must not overwrite capture inputs or journal evidence")
        receipt.unlink(missing_ok=True)
    result = verify_partition(report_path)
    if receipt:
        write_json(receipt, result)
    print(json.dumps(result, indent=2))
    return 0


def capture(arguments: argparse.Namespace) -> int:
    recipe_path = Path(arguments.manifest).resolve()
    recipe = read_json(recipe_path)
    validate_recipe(recipe)
    source = Path(arguments.source).resolve()
    build = Path(arguments.build).resolve()
    output = Path(arguments.output).resolve()
    if source == build or source in build.parents:
        raise CaptureError("use an out-of-tree build directory to keep the pinned source checkout clean")
    if output.exists() and any(output.iterdir()):
        raise CaptureError(f"capture output must be empty: {output}")
    if build.exists() and any(build.iterdir()):
        raise CaptureError(f"build directory must be empty; cached/prebuilt units are not complete capture: {build}")
    output.mkdir(parents=True, exist_ok=True)
    build.mkdir(parents=True, exist_ok=True)
    (output / "events").mkdir()
    (output / "wrappers").mkdir()
    session = {"recipe": recipe, "manifest": file_info(recipe_path), "source": {"path": str(source)},
               "build": str(build), "tools": {}, "native_tools": {}, "issues": [], "build_steps": [], "audit_roots": [str(build)],
               "inventory_path": str(Path(arguments.unit_inventory).resolve()) if arguments.unit_inventory else None}
    try:
        rust_policy = recipe["toolchain"].get("rust_capture_policy")
        session["capture_worker"] = snapshot_worker(output, rust_policy)
        session["source"] = verify_source(recipe, source)
        toolchain = recipe["toolchain"]
        for name, command, kind in [("clang", arguments.cc, "clang"), ("cxx", arguments.cxx, "clang"),
                                    ("nm", arguments.llvm_nm, "llvm-nm")]:
            session["tools"][name] = tool_info(command, kind)
            if session["tools"][name]["llvm_version"] != toolchain["llvm_version"]:
                raise CaptureError(f"{name} version mismatch: expected LLVM {toolchain['llvm_version']}, "
                                   f"got {session['tools'][name]['llvm_version']}")
        # Resolve real tools before placing proxies on driver search paths. A
        # proxy delegates this pinned identity rather than selecting a new ld
        # from a reordered -L or ambient PATH after the build has begun.
        for name in NATIVE_TOOL_KINDS:
            executable = shutil.which(name)
            if executable is not None:
                session["native_tools"][name] = tool_info(executable, "native-tool")
        if any(item["kind"] == "rustc" for item in recipe["coverage"]["required_units"]):
            if rust_policy == RUST_EMBEDDED_POLICY:
                session["tools"]["llvm_dis"] = tool_info(arguments.llvm_dis, "llvm-dis")
                if session["tools"]["llvm_dis"]["llvm_version"] != toolchain["llvm_version"]:
                    raise CaptureError("embedded Rust bitcode decoder LLVM version mismatch")
            session["tools"]["rustc"] = tool_info(arguments.rustc, "rustc")
            info = session["tools"]["rustc"]
            for field, actual in [("rustc_release", info["release"]), ("rustc_commit", info["commit"]),
                                  ("llvm_version", info["llvm_version"])]:
                if toolchain.get(field) and toolchain[field] != actual:
                    raise CaptureError(f"Rust toolchain mismatch: expected {field}={toolchain[field]}, got {actual}")
            if toolchain.get("cargo_release"):
                session["tools"]["cargo"] = cargo_tool_info(arguments.cargo, info)
                cargo = session["tools"]["cargo"]
                if cargo["release"] != toolchain["cargo_release"]:
                    raise CaptureError(f"Cargo toolchain mismatch: expected {toolchain['cargo_release']}, got {cargo['release']}")
        write_json(output / "session.json", session)
        # Separate frozen C++ wrapper keeps original driver/linker defaults.
        values = {"source": str(source), "build": str(build), "output": str(output), "jobs": str(arguments.jobs),
                  "recipe_dir": str(recipe_path.parent),
                  "cc": str(output / "wrappers" / "cc"), "cxx": str(output / "wrappers" / "cxx"),
                  "rustc_wrapper": str(output / "wrappers" / "rustc-wrapper"),
                  "ar": str(output / "wrappers" / "ar"), "ranlib": str(output / "wrappers" / "ranlib"),
                  "llvm_ar": str(output / "wrappers" / "llvm-ar"), "llvm_ranlib": str(output / "wrappers" / "llvm-ranlib"),
                  "linker": str(output / "wrappers" / "ld"), "lld": str(output / "wrappers" / "ld.lld"),
                  "cargo": session["tools"].get("cargo", {}).get("invoked_path", arguments.cargo),
                  "rustc": session["tools"].get("rustc", {}).get("invoked_path", arguments.rustc)}
        session["audit_roots"] = [value.format_map(values) for value in recipe["coverage"].get("audit_roots", ["{build}"])]
        environment = dict(os.environ)
        environment.setdefault("SOURCE_DATE_EPOCH", session["source"]["commit_timestamp"])
        environment.update({"CC": values["cc"], "CXX": values["cxx"], "RUSTC_WRAPPER": values["rustc_wrapper"],
                            "AR": values["ar"], "RANLIB": values["ranlib"],
                            "RUSTC": values["rustc"], "CCACHE_DISABLE": "1", "SCCACHE_DISABLE": "1",
                            "CARGO_INCREMENTAL": "0"})
        environment.update({key: value.format_map(values) for key, value in recipe.get("env", {}).items()})
        wrapper_dir = str(output / "wrappers")
        environment["PATH"] = wrapper_dir + os.pathsep + environment.get("PATH", "")
        environment["COMPILER_PATH"] = wrapper_dir + (os.pathsep + environment["COMPILER_PATH"] if environment.get("COMPILER_PATH") else "")
        write_json(output / "session.json", session)
        for index, command in enumerate(recipe["commands"]):
            argv = [value.format_map(values) for value in command["argv"]]
            cwd = Path(command.get("cwd", "{build}").format_map(values))
            step_env = {**environment, **{key: value.format_map(values) for key, value in command.get("env", {}).items()}}
            log = output / f"build-{index}.log"
            step = {"name": command.get("name", str(index)), "argv": argv, "cwd": str(cwd), "log": str(log),
                    "started_ns": time.time_ns(), "exit_code": None}
            session["build_steps"].append(step)
            write_json(output / "session.json", session)
            with log.open("wb") as stream:
                step["exit_code"] = subprocess.run(argv, cwd=cwd, env=step_env, stdout=stream, stderr=stream).returncode
            step["finished_ns"] = time.time_ns()
            step["log_artifact"] = file_info(log)
            write_json(output / "session.json", session)
            if step["exit_code"]:
                break
    except (CaptureError, OSError, ValueError, KeyError) as error:
        session["issues"].append(str(error))
        write_json(output / "session.json", session)
    if session.get("inventory_path"):
        try:
            session["inventory_artifact"] = file_info(Path(session["inventory_path"]))
        except OSError as error:
            session["issues"].append(f"cannot finalize full unit inventory: {error}")
        write_json(output / "session.json", session)
    report = make_report(output)
    print(json.dumps({"report": str(output / "report.json"), "captured_units": len(report["units"]),
                      "capture_complete": report["capture_complete"], "runtime_complete": False,
                      "issues": report["issues"]}, indent=2))
    return 0 if report["capture_complete"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    validate = subparsers.add_parser("validate", help="validate a pinned source/build recipe")
    validate.add_argument("manifest")
    run = subparsers.add_parser("capture", help="execute the declared build through journaling compiler wrappers")
    run.add_argument("manifest")
    run.add_argument("--source", required=True)
    run.add_argument("--build", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    run.add_argument("--cc", default="clang")
    run.add_argument("--cxx", default="clang++")
    run.add_argument("--rustc", default="rustc")
    run.add_argument("--cargo", default="cargo")
    run.add_argument("--llvm-nm", default="llvm-nm")
    run.add_argument("--llvm-dis", default="llvm-dis", help="pinned decoder used only by rust-embedded-bc-v1")
    run.add_argument("--unit-inventory", help="complete build-generated source-unit inventory JSON")
    report = subparsers.add_parser("report", help="recompute completeness from immutable capture events")
    report.add_argument("directory")
    verify = subparsers.add_parser("verify-report", help="independently reconstruct source/unit partition admission")
    verify.add_argument("report")
    verify.add_argument("--receipt")
    internal = subparsers.add_parser("_compiler", help=argparse.SUPPRESS)
    internal.add_argument("--session", required=True)
    internal.add_argument("--kind", choices=["clang", "cxx", "rustc"], required=True)
    internal.add_argument("args", nargs=argparse.REMAINDER)
    native = subparsers.add_parser("_native-tool", help=argparse.SUPPRESS)
    native.add_argument("--session", required=True)
    native.add_argument("--kind", choices=list(NATIVE_TOOL_KINDS), required=True)
    native.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        if args.action == "validate":
            validate_recipe(read_json(Path(args.manifest)))
            print(f"valid {RECIPE_SCHEMA}: {args.manifest}")
            return 0
        if args.action == "capture":
            if args.jobs < 1:
                raise CaptureError("--jobs must be positive")
            return capture(args)
        if args.action == "report":
            result = make_report(Path(args.directory).resolve())
            print(json.dumps({"capture_complete": result["capture_complete"], "issues": result["issues"]}, indent=2))
            return 0 if result["capture_complete"] else 1
        if args.action == "verify-report":
            return verify_report_cli(args)
        original_args = args.args[1:] if args.args[:1] == ["--"] else args.args
        if args.action == "_native-tool":
            return native_tool(Path(args.session), args.kind, original_args)
        return compiler(Path(args.session), args.kind, original_args)
    except (CaptureError, OSError, ValueError) as error:
        print(f"ocore-runtime-capture: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
