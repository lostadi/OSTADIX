#!/usr/bin/env python3
"""Build, qualify, verify, and install native runtime-only Ostadix bundles.

Builds always use the current host, with a clean source commit and locked Cargo
inputs. Foreign runtime providers remain host dependencies; this is not an
O-core whole-program compiler-closure claim.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

try:
    from scripts import install_native_binaries as native_install
    from scripts.smoke_ostadix_mcp import ResponseReader, SmokeError, _send, _content_text
except ModuleNotFoundError:
    import install_native_binaries as native_install
    from smoke_ostadix_mcp import ResponseReader, SmokeError, _send, _content_text

# Setup's recipient baseline is Python3.10. Only source archive construction
# and verification require the existing release tool's Python3.11 tomllib.
# Keep fixed runtime-only smoke usable at the setup baseline.
if sys.version_info >= (3, 11):
    try:
        from scripts import build_source_release as source_release
    except ModuleNotFoundError:
        import build_source_release as source_release
else:
    source_release = None

BUILD_SCHEMA = "ostadix.runtime-build/v1"
BUNDLE_SCHEMA = "ostadix.runtime-bundle/v1"
TOOLS = (*native_install.RUNTIME_TOOLS, "ostadix-mcp")
# Keep installation qualification independent of the public polyglot greeting
# and optional language providers, matching the ordinary setup/MCP fixed smoke.
SMOKE_SOURCE = "O^(\npython^(\n__oval_result__ = 1 + 1\n)_python\n)_O\n"
MAX_FILES = 30000
MAX_BYTES = 768 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
TARGETS = {
    "x86_64-unknown-linux-gnu": {"system": "linux", "architecture": "x86_64"},
    "aarch64-unknown-linux-gnu": {"system": "linux", "architecture": "aarch64"},
    "x86_64-apple-darwin": {"system": "macos", "architecture": "x86_64"},
    "aarch64-apple-darwin": {"system": "macos", "architecture": "aarch64"},
}


class BundleError(ValueError):
    pass


SourceReleaseError = source_release.ReleaseError if source_release is not None else BundleError


def source_api():
    if source_release is None:
        raise BundleError("Native bundle archive operations require Python3.11 or newer; runtime smoke supports Python3.10.")
    return source_release


def require(condition, message):
    if not condition:
        raise BundleError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def record(path):
    path = Path(path)
    return {"sha256": digest(path), "bytes": path.stat().st_size}


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def output(command, *, cwd=None):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, "Command failed: " + command[0])
    return result.stdout.strip()


def host_platform():
    system = {"Linux": "linux", "Darwin": "macos"}.get(platform.system())
    machine = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64", "AMD64": "x86_64"}.get(platform.machine())
    require(system and machine, "Native bundles currently support Linux/macOS on x86_64 and AArch64.")
    return {"system": system, "architecture": machine, "release": platform.release(),
            "libc": list(platform.libc_ver()) if system == "linux" else None}


def native_platform(path):
    """Read ELF/Mach-O target identities without executing an unverified file."""
    with Path(path).open("rb") as stream:
        data = stream.read(32)
    if data.startswith(b"\x7fELF"):
        require(len(data) >= 20 and data[4] == 2 and data[5] in (1, 2), "Unsupported ELF format.")
        machine = struct.unpack(("<" if data[5] == 1 else ">") + "H", data[18:20])[0]
        architecture = {62: "x86_64", 183: "aarch64"}.get(machine)
        require(architecture, "Unsupported ELF machine.")
        return {"system": "linux", "architecture": architecture}
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        require(len(data) == 32, "Truncated Mach-O header.")
        cpu = struct.unpack(("<" if data[:4] == b"\xcf\xfa\xed\xfe" else ">") + "I", data[4:8])[0]
        architecture = {0x01000007: "x86_64", 0x0100000C: "aarch64"}.get(cpu)
        require(architecture, "Unsupported Mach-O CPU.")
        return {"system": "macos", "architecture": architecture}
    raise BundleError("Expected a single-architecture native ELF or Mach-O executable.")


def check_host(expected):
    actual = host_platform()
    require(all(expected.get(k) == actual[k] for k in ("system", "architecture")),
            "Bundle target does not match this host; no binary was executed.")


def checked_run(command, root, env, *, timeout=30):
    started = time.monotonic()
    process = subprocess.Popen([str(v) for v in command], cwd=root, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with selectors.DefaultSelector() as selected:
            for name, stream in [("stdout", process.stdout), ("stderr", process.stderr)]:
                os.set_blocking(stream.fileno(), False)
                selected.register(stream, selectors.EVENT_READ, name)
            while selected.get_map():
                remaining = timeout - (time.monotonic() - started)
                require(remaining > 0, "Native smoke exceeded its execution deadline.")
                for key, _ in selected.select(min(remaining, .1)):
                    block = os.read(key.fileobj.fileno(), 8192)
                    if not block:
                        selected.unregister(key.fileobj)
                        continue
                    captured[key.data].extend(block)
                    require(sum(len(v) for v in captured.values()) <= 1024 * 1024,
                            "Native smoke exceeded its output budget.")
            code = process.wait(timeout=max(.01, timeout - (time.monotonic() - started)))
        require(code == 0, "Native smoke command failed: " + str(command[0]))
    finally:
        stop_group(process)
        for stream in [process.stdout, process.stderr]:
            stream.close()
    return {"argv": [str(v) for v in command], "exitCode": code,
            "elapsedSeconds": round(time.monotonic() - started, 6),
            "stdout": captured["stdout"].decode("utf-8", "replace"),
            "stderr": captured["stderr"].decode("utf-8", "replace")}


def stop_group(process):
    """Terminate the private process group, including pipe-holding descendants."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=.3)
    except subprocess.TimeoutExpired:
        pass
    # A completed leader can still have running descendants in its group.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=3)


class BoundedLines:
    def __init__(self, stream, stopped):
        self.stream, self.total, self.stopped = stream, 0, stopped
        self.pending = bytearray()
        self.selector = selectors.DefaultSelector()
        os.set_blocking(stream.fileno(), False)
        self.selector.register(stream, selectors.EVENT_READ)

    def readline(self):
        while not self.stopped.is_set():
            newline = self.pending.find(b"\n")
            if newline >= 0:
                line = bytes(self.pending[:newline + 1]); del self.pending[:newline + 1]
                return line
            if not self.selector.select(.05):
                continue
            block = os.read(self.stream.fileno(), 8192)
            if not block:
                line = bytes(self.pending); self.pending.clear(); return line
            self.pending.extend(block); self.total += len(block)
            require(len(self.pending) <= 1024 * 1024 and self.total <= 4 * 1024 * 1024,
                    "MCP qualification exceeded its stdout budget.")
        return b""

    def close(self):
        self.selector.close()


def smoke(root, binaries, mcp=None):
    root, binaries = Path(root).resolve(), Path(binaries).resolve()
    env = os.environ.copy()
    env.update(O_LANG_ROOT=str(root), O_BACKENDS_DIR=str(root / "backends"),
               OLANG=str(binaries / "O"), OSTADIX_O_CLI_BIN=str(binaries / "o-cli"),
               O_LANG_EVALUATOR_BIN=str(binaries / "O"), O_LANG_OCLI_BIN=str(binaries / "o-cli"),
               O_LANG_OLANGC_BIN=str(binaries / "olangc"), O_LANG_OCOREC_BIN=str(binaries / "ocorec"),
               PATH=str(binaries) + os.pathsep + env.get("PATH", ""))
    checks = []
    for name in native_install.RUNTIME_TOOLS:
        check_host(native_platform(binaries / name))
    with tempfile.TemporaryDirectory(prefix="ostadix-runtime-smoke-") as temporary:
        program = Path(temporary) / "program.O"
        program.write_text(SMOKE_SOURCE)
        run = checked_run([binaries / "O", program, root / "backends"], root, env)
        require(run["stdout"].strip() in {"2", "[number] 2"},
                "The fixed Python smoke did not produce exactly the expected number 2.")
        checks.append({"name": "native-evaluation", **run})
        checks.append({"name": "native-plan", **checked_run(
            [binaries / "olangc", program, "--target", "ir", "--shim-dir", root / "backends"], root, env)})
    checks.append({"name": "ocore-command", **checked_run([binaries / "ocorec", "--help"], root, env)})
    if mcp:
        mcp = Path(mcp).resolve()
        check_host(native_platform(mcp))
        with tempfile.TemporaryFile() as errors:
            process = subprocess.Popen([str(mcp), "--transport", "stdio"], cwd=root, env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            overflow = threading.Event()
            drain_stopped, read_stopped = threading.Event(), threading.Event()
            def drain_stderr():
                count = 0
                os.set_blocking(process.stderr.fileno(), False)
                with selectors.DefaultSelector() as selected:
                    selected.register(process.stderr, selectors.EVENT_READ)
                    while True:
                        if not selected.select(.05):
                            if drain_stopped.is_set():
                                return
                            continue
                        block = os.read(process.stderr.fileno(), 8192)
                        if not block:
                            return
                        count += len(block)
                        if count > 1024 * 1024:
                            overflow.set()
                            try:
                                os.killpg(process.pid, signal.SIGTERM)
                            except ProcessLookupError:
                                pass
                            return
                        errors.write(block)
            stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
            stderr_thread.start()
            lines = BoundedLines(process.stdout, read_stopped)
            reader = ResponseReader(lines)
            try:
                def request(i, method, params):
                    _send(process, {"jsonrpc": "2.0", "id": i, "method": method, "params": params})
                    return reader.response(i, 30)
                initialized = request(1, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                    "clientInfo": {"name": "runtime-bundle-qualification", "version": "1"}})
                _send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
                tools = request(2, "tools/list", {})
                require({"o_smoke", "o_env", "o_execute"} <= {v["name"] for v in tools["tools"]},
                        "MCP omitted required runtime tools.")
                result = request(3, "tools/call", {"name": "o_smoke", "arguments": {}})
                text = _content_text(result)
                require(not result.get("isError") and "SMOKE_OK" in text,
                        "MCP did not execute the bounded native evaluation successfully.")
                require(not overflow.is_set(), "MCP qualification exceeded its stderr budget.")
                checks.append({"name": "mcp-stdio-execution", "protocolVersion": initialized["protocolVersion"],
                               "toolCount": len(tools["tools"]), "result": result})
            finally:
                if process.stdin:
                    try:
                        process.stdin.close()
                    except OSError:
                        pass
                stop_group(process)
                drain_stopped.set(); read_stopped.set()
                stderr_thread.join(timeout=3)
                require(not stderr_thread.is_alive(), "MCP stderr reader did not stop within its cleanup deadline.")
                reader.join(3)
                lines.close()
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()
                require(not overflow.is_set(), "MCP qualification exceeded its stderr budget.")
    return {"schema": "ostadix.runtime-smoke/v1", "passed": True, "host": host_platform(),
            "checks": checks, "programSha256": hashlib.sha256(SMOKE_SOURCE.encode()).hexdigest(),
            "scope": "Native host executables, fixed Python evaluation/plan and optional MCP stdio execution; not all provider or O-core lowering qualification."}


def build(repo, destination):
    repo, destination = Path(repo).resolve(), Path(destination).resolve()
    source_api().assert_clean_worktree(repo, allow_dirty=False)
    commit = source_api().resolve_commit(repo, "HEAD")
    require(not destination.exists(), "Build output already exists; choose a new directory.")
    destination.mkdir(parents=True)
    rustc = output(["rustc", "-vV"], cwd=repo)
    target = next((line[6:] for line in rustc.splitlines() if line.startswith("host: ")), "")
    require(target in TARGETS, "The toolchain host is not a supported native bundle target.")
    host = host_platform()
    require(target.startswith(host["architecture"] + "-"), "Toolchain host architecture differs from the running machine.")
    build_dir = repo / "target/native-runtime-bundle"
    commands = [["cargo", "build", "--release", "--locked", "--package", "o-lang", "--target", target,
                 "--target-dir", str(build_dir / "root"), *[arg for name in native_install.RUNTIME_TOOLS for arg in ("--bin", name)]],
                ["cargo", "build", "--release", "--locked", "--manifest-path", str(repo / "mcp/ostadix_lang_mcp_server/Cargo.toml"),
                 "--target", target, "--target-dir", str(build_dir / "mcp")]]
    runs = []
    for index, command in enumerate(commands):
        log = destination / f"build-{index}.log"
        started = time.monotonic()
        with log.open("wb") as stream:
            result = subprocess.run(command, cwd=repo, stdout=stream, stderr=subprocess.STDOUT)
        require(result.returncode == 0, "Native build failed; inspect " + str(log))
        runs.append({"argv": command, "exitCode": result.returncode,
                     "elapsedSeconds": round(time.monotonic() - started, 6), "log": {"path": log.name, **record(log)}})
    # Reject concurrent tracked/untracked source edits, rather than labeling them
    # as the clean commit that existed before compilation.
    source_api().assert_clean_worktree(repo, allow_dirty=False)
    require(source_api().resolve_commit(repo, "HEAD") == commit, "Source HEAD changed during build.")
    binaries = destination / "bin"; binaries.mkdir()
    artifacts = {}
    for name in TOOLS:
        origin = build_dir / ("mcp" if name == "ostadix-mcp" else "root") / target / "release" / name
        check_host(native_platform(origin))
        shutil.copy2(origin, binaries / name)
        artifacts[name] = {"path": "bin/" + name, **record(binaries / name), "platform": native_platform(origin)}
    proof = smoke(repo, binaries, binaries / "ostadix-mcp")
    (destination / "SMOKE.json").write_bytes(json_bytes(proof))
    source_api().build_release(repo, commit, destination / "SOURCE.zip", prefix="source")
    manifest = {"schema": BUILD_SCHEMA, "profile": "runtime-only", "source": {"root": str(repo), "commit": commit, "dirty": False},
                "targetTriple": target, "host": host, "toolchain": {"rustc": rustc, "cargo": output(["cargo", "-vV"], cwd=repo)},
                "commands": runs, "artifacts": artifacts, "sourceArchive": record(destination / "SOURCE.zip"),
                "smoke": record(destination / "SMOKE.json"), "qualificationScope": proof["scope"]}
    (destination / "BUILD-MANIFEST.json").write_bytes(json_bytes(manifest))
    return manifest


def safe_name(name):
    pure = PurePosixPath(name)
    require(name and not pure.is_absolute() and ".." not in pure.parts and "\\" not in name
            and name == pure.as_posix() and not any(ord(c) < 32 for c in name), "Unsafe bundle archive path.")
    return pure


def read_members(archive):
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        require(len(infos) <= MAX_FILES and sum(i.file_size for i in infos) <= MAX_BYTES, "Bundle exceeds archive bounds.")
        require(len({i.filename for i in infos}) == len(infos), "Duplicate archive member.")
        for i in infos:
            safe_name(i.filename)
            mode = i.external_attr >> 16
            require(not i.is_dir() and (mode & 0o170000) in (0, 0o100000), "Bundle contains a non-regular file.")
        return {i.filename: z.read(i) for i in infos}


def member_modes(archive):
    with zipfile.ZipFile(archive) as z:
        return {i.filename: (i.external_attr >> 16) & 0o777 for i in z.infolist()}


def _verify_snapshot(archive, expected_sha256=None, *, require_host=False):
    archive = Path(archive)
    if expected_sha256 is not None:
        require(HEX.fullmatch(expected_sha256) and digest(archive) == expected_sha256, "Bundle download checksum mismatch.")
    members = read_members(archive)
    modes = member_modes(archive)
    require("BUNDLE-MANIFEST.json" in members, "Missing bundle manifest.")
    manifest = json.loads(members["BUNDLE-MANIFEST.json"])
    require(manifest.get("schema") == BUNDLE_SCHEMA and manifest.get("profile") == "runtime-only", "Unsupported bundle schema/profile.")
    inventory = manifest.get("files")
    require(isinstance(inventory, dict) and set(inventory) == set(members) - {"BUNDLE-MANIFEST.json"}, "Bundle inventory mismatch.")
    for name, proof in inventory.items():
        data = members[name]
        require(proof.get("sha256") == hashlib.sha256(data).hexdigest() and proof.get("bytes") == len(data), "Bundle file checksum mismatch: " + name)
    required = {"BUILD-MANIFEST.json", "SOURCE.zip", "SMOKE.json", *{"bin/" + n for n in TOOLS}}
    require(required <= set(members), "Bundle is missing required runtime artifacts.")
    build_manifest = json.loads(members["BUILD-MANIFEST.json"])
    require(build_manifest.get("schema") == BUILD_SCHEMA and build_manifest.get("source", {}).get("dirty") is False,
            "A qualified clean build manifest is required.")
    require(build_manifest.get("profile") == "runtime-only" and len(build_manifest.get("commands", [])) == 2
            and all(v.get("exitCode") == 0 for v in build_manifest["commands"]), "Build commands were not successful.")
    require(manifest.get("sourceCommit") == build_manifest["source"].get("commit")
            and manifest.get("targetTriple") == build_manifest.get("targetTriple"), "Bundle/build source or target mismatch.")
    require(isinstance(manifest.get("sourceCommit"), str)
            and re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", manifest["sourceCommit"]), "Invalid source commit identity.")
    proof = json.loads(members["SMOKE.json"])
    require(proof.get("passed") is True and {v.get("name") for v in proof.get("checks", [])} >=
            {"native-evaluation", "native-plan", "ocore-command", "mcp-stdio-execution"}, "Bundle lacks complete native/MCP smoke evidence.")
    expected_platform = {k: build_manifest.get("host", {}).get(k) for k in ("system", "architecture")}
    require(TARGETS.get(manifest.get("targetTriple")) == expected_platform,
            "Declared target triple does not match the native build platform.")
    require(proof.get("host", {}).get("system") == expected_platform["system"]
            and proof.get("host", {}).get("architecture") == expected_platform["architecture"], "Smoke host and build target disagree.")
    checks = {v["name"]: v for v in proof["checks"]}
    require(len(checks) == len(proof["checks"]), "Duplicate native smoke measurement.")
    for name in ("native-evaluation", "native-plan", "ocore-command"):
        item = checks[name]
        require(type(item.get("exitCode")) is int and item["exitCode"] == 0
                and isinstance(item.get("stdout"), str) and isinstance(item.get("stderr"), str)
                and len(item["stdout"].encode()) + len(item["stderr"].encode()) <= 1024 * 1024,
                "Native smoke measurement did not complete successfully.")
    require(re.search(r"(?m)^(?:\[number\]\s*)?2\s*$", checks["native-evaluation"]["stdout"]),
            "Retained native evaluation did not return the expected number 2.")
    mcp = checks["mcp-stdio-execution"]
    require(mcp.get("protocolVersion") in ("2025-03-26", "2025-06-18", "2025-11-25")
            and type(mcp.get("toolCount")) is int and mcp["toolCount"] >= 3
            and isinstance(mcp.get("result"), dict) and mcp["result"].get("isError") is not True
            and "SMOKE_OK" in _content_text(mcp["result"]), "Retained MCP execution measurement did not succeed.")
    if require_host:
        check_host(expected_platform)
    with tempfile.TemporaryDirectory(prefix="ostadix-bundle-verify-") as tmp:
        temp = Path(tmp); (temp / "SOURCE.zip").write_bytes(members["SOURCE.zip"])
        source_members = read_members(temp / "SOURCE.zip")
        source_modes = member_modes(temp / "SOURCE.zip")
        source = source_api().verify_archive(temp / "SOURCE.zip")
        require(source["commit"] == manifest["sourceCommit"], "Source archive belongs to another commit.")
        require(set(source_members) == {n for n in members if n.startswith("source/")}
                and all(members[n] == data and modes[n] == source_modes[n] for n, data in source_members.items()),
                "Unpacked source disagrees with the exact source archive.")
        for name in TOOLS:
            path = temp / name; path.write_bytes(members["bin/" + name])
            actual = native_platform(path)
            binary_proof = build_manifest.get("artifacts", {}).get(name, {})
            require(actual == expected_platform and binary_proof.get("platform") == actual
                    and binary_proof.get("path") == "bin/" + name
                    and binary_proof.get("sha256") == digest(path) and binary_proof.get("bytes") == path.stat().st_size,
                    "Native artifact target/hash disagrees with build manifest: " + name)
            require(modes["bin/" + name] == 0o755, "Native executable mode was not retained.")
    for name, key in [("SOURCE.zip", "sourceArchive"), ("SMOKE.json", "smoke")]:
        require(build_manifest.get(key, {}).get("sha256") == hashlib.sha256(members[name]).hexdigest()
                and build_manifest.get(key, {}).get("bytes") == len(members[name]), "Build evidence checksum mismatch: " + name)
    for command in build_manifest["commands"]:
        log = command.get("log", {})
        name = log.get("path")
        require(name in members and log.get("sha256") == hashlib.sha256(members[name]).hexdigest()
                and log.get("bytes") == len(members[name]), "Retained build log checksum mismatch.")
    return manifest


@contextmanager
def private_archive_copy(archive):
    """Pin externally mutable downloads before verifying or using their bytes."""
    with tempfile.TemporaryDirectory(prefix="ostadix-runtime-download-") as tmp:
        private = Path(tmp) / "runtime.zip"
        descriptor = os.open(archive, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        copied = 0
        with os.fdopen(descriptor, "rb") as source, private.open("xb") as target:
            metadata = os.fstat(source.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= MAX_BYTES,
                    "The compressed bundle must be a bounded regular file.")
            for block in iter(lambda: source.read(1024 * 1024), b""):
                copied += len(block)
                require(copied <= MAX_BYTES, "Compressed bundle exceeds its size limit.")
                target.write(block)
        yield private


def verify(archive, expected_sha256=None, *, require_host=False):
    with private_archive_copy(archive) as private:
        try:
            return _verify_snapshot(private, expected_sha256, require_host=require_host)
        except (TypeError, AttributeError, KeyError, IndexError) as error:
            raise BundleError("Malformed bundle manifest or evidence structure.") from error


def package(build_directory, archive):
    build_directory, archive = Path(build_directory).resolve(), Path(archive).resolve()
    build_manifest = json.loads((build_directory / "BUILD-MANIFEST.json").read_text())
    names = ["BUILD-MANIFEST.json", "SOURCE.zip", "SMOKE.json", *["bin/" + n for n in TOOLS]]
    # Include retained build logs in the downloadable artifact, not just paths
    # pointing into an ephemeral CI runner.
    names.extend(v["log"]["path"] for v in build_manifest["commands"])
    for name in names:
        safe_name(name)
        require((build_directory / name).is_file() and not (build_directory / name).is_symlink(), "Missing regular build artifact.")
    source_members = read_members(build_directory / "SOURCE.zip")
    source_modes = member_modes(build_directory / "SOURCE.zip")
    require(all(n.startswith("source/") for n in source_members), "Source archive must use the source/ prefix.")
    require(not set(source_members) & set(names), "Source/build member collision.")
    inventory = {n: record(build_directory / n) for n in names}
    inventory.update({n: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                      for n, data in source_members.items()})
    manifest = {"schema": BUNDLE_SCHEMA, "profile": "runtime-only", "sourceCommit": build_manifest["source"]["commit"],
                "targetTriple": build_manifest["targetTriple"], "files": inventory,
                "scope": "Ostadix core runtime/compiler/MCP; external language providers are not bundled."}
    archive.parent.mkdir(parents=True, exist_ok=True)
    require(not archive.exists(), "Archive already exists; choose a new output path.")
    with tempfile.NamedTemporaryFile(dir=archive.parent, suffix=".zip", delete=False) as f:
        temporary = Path(f.name)
    try:
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as z:
            for name in sorted([*names, *source_members, "BUNDLE-MANIFEST.json"]):
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)); info.create_system = 3
                mode = source_modes.get(name, 0o755 if name.startswith("bin/") else 0o644)
                info.external_attr = (0o100000 | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                data = (json_bytes(manifest) if name == "BUNDLE-MANIFEST.json" else
                        source_members[name] if name in source_members else (build_directory / name).read_bytes())
                z.writestr(info, data)
        verify(temporary)
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)
    archive.with_suffix(archive.suffix + ".sha256").write_text(digest(archive) + "  " + archive.name + "\n")
    return manifest


def _install_verified(archive, destination, bin_directory, expected_sha256):
    # Validation, including host identity, completes before creating any output
    # or executing native files. An external expected checksum pins the download.
    manifest = verify(archive, expected_sha256, require_host=True)
    destination, bin_directory = Path(destination).expanduser().absolute(), Path(bin_directory).expanduser().absolute()
    require(not destination.exists(), "Permanent bundle destination already exists; choose a new path.")
    require(not bin_directory.exists() or bin_directory.is_dir(), "Command directory is not a directory.")
    for name in [*TOOLS, "o", "ostadix-evaluator", "ostadix-mcp-client", "ostadix-install.json"]:
        require(not (bin_directory / name).is_dir(), "Installation target is a directory: " + name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".ostadix-runtime-", dir=destination.parent))
    try:
        members = read_members(archive)
        modes = member_modes(archive)
        for name, data in members.items():
            path = temporary / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            path.chmod(modes[name])
        require((temporary / "source/backends/python_shim.py").is_file(), "Source archive is not rooted at source/.")
        # Prove relocation before replacing any installed user command.
        relocated = smoke(temporary / "source", temporary / "bin", temporary / "bin/ostadix-mcp")
        (temporary / "INSTALL-SMOKE.json").write_bytes(json_bytes(relocated))
        temporary.rename(destination)
        native_install.install(destination / "source", destination / "bin", bin_directory, runtime_only=True)
        native_install.atomic_copy(destination / "bin/ostadix-mcp", bin_directory / "ostadix-mcp")
        client = destination / "source/scripts/ostadix_mcp_client.py"
        if client.is_file():
            native_install.atomic_copy(client, bin_directory / "ostadix-mcp-client")
        metadata = json.loads((bin_directory / "ostadix-install.json").read_text())
        metadata.update(source_commit=manifest["sourceCommit"], runtime_bundle=str(destination),
                        bundle_sha256=digest(archive), build_manifest=str(destination / "BUILD-MANIFEST.json"))
        descriptor, name = tempfile.mkstemp(prefix=".ostadix-install.bundle-", dir=bin_directory)
        temp_meta = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(json_bytes(metadata))
            temp_meta.chmod(0o644)
            temp_meta.replace(bin_directory / "ostadix-install.json")
        finally:
            temp_meta.unlink(missing_ok=True)
        return {"installed": True, "destination": str(destination), "binDirectory": str(bin_directory),
                "sourceCommit": manifest["sourceCommit"], "targetTriple": manifest["targetTriple"], "relocationSmokePassed": True}
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def install(archive, destination, bin_directory, expected_sha256):
    # Never reopen the caller's mutable pathname after checksum verification.
    # A private 0700 directory binds verification and execution to one copy.
    with private_archive_copy(archive) as private:
        return _install_verified(private, destination, bin_directory, expected_sha256)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    command = subs.add_parser("build"); command.add_argument("--root", type=Path, default=Path.cwd()); command.add_argument("--output-dir", type=Path, required=True)
    command = subs.add_parser("package"); command.add_argument("--build-dir", type=Path, required=True); command.add_argument("--output", type=Path, required=True)
    command = subs.add_parser("verify"); command.add_argument("archive", type=Path); command.add_argument("--sha256")
    command = subs.add_parser("install"); command.add_argument("archive", type=Path); command.add_argument("--sha256", required=True)
    command.add_argument("--destination", type=Path, required=True); command.add_argument("--bin-dir", type=Path, default=Path.home() / ".local/bin")
    command = subs.add_parser("smoke"); command.add_argument("--root", type=Path, required=True); command.add_argument("--bin-dir", type=Path, required=True); command.add_argument("--mcp-bin", type=Path); command.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "build": result = build(args.root, args.output_dir)
        elif args.action == "package": result = package(args.build_dir, args.output)
        elif args.action == "verify": result = verify(args.archive, args.sha256)
        elif args.action == "install": result = install(args.archive, args.destination, args.bin_dir, args.sha256)
        else:
            result = smoke(args.root, args.bin_dir, args.mcp_bin)
            if args.output: args.output.write_bytes(json_bytes(result))
        print(json.dumps(result, indent=2, sort_keys=True)); return 0
    except (BundleError, SmokeError, SourceReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print("Runtime bundle operation failed: " + str(error), file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())
