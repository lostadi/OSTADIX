#!/usr/bin/env python3
"""Qualify implicit p9 CLI compile/link budgets in one isolated real boot.

Commands are automated keystrokes through the original Linux foreground PTY.
Original 9front tools execute beneath the admitted O-core monitor. This tests
the selected client bytes and compatibility profile, not a complete native OS
or a source-lowered original compiler. Never use a working/default OS state.
"""
from __future__ import annotations

import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import inspect
import json
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

from verify_okernel_unified_client import (
    GUEST_HELPER, checked_command, collect, preflight, read_saved_session,
    typed, upload,
)
from verify_okernel_unified_console import Terminal, hash_file
from okernel_unified_world import protocol

ROOT = Path(__file__).resolve().parents[1]
INSTALLED = {
    "/usr/local/bin/p9": "ocore/guest/linux/package-domain/p9",
    "/usr/local/libexec/p9-controller": "ocore/guest/linux/package-domain/p9-controller",
    "/usr/local/libexec/p9-history": "ocore/guest/linux/package-domain/p9-history",
    "/usr/local/bin/p9-install": "ocore/guest/linux/package-domain/p9-install",
    "/usr/lib/okernel/p9_protocol.py": "ocore/guest/plan9/unified/protocol.py",
}
SOURCE_PATHS = (
    "scripts/verify_okernel_p9_default_compile.py",
    "scripts/verify_okernel_unified_client.py",
    "scripts/verify_okernel_unified_console.py",
    "scripts/okernel_unified_world.py",
    "scripts/okernel_package_domain.py",
    "scripts/okernel_native_volume.py",
    *INSTALLED.values(),
)


def identity(path: Path) -> dict:
    return {"path": str(path.resolve()), "bytes": path.stat().st_size,
            "sha256": hash_file(path)}


def host_timeout_contract() -> dict:
    """Check API/wire configuration; local tests qualify actual API dispatch."""
    loader = SourceFileLoader("default_compile_client", str(ROOT / INSTALLED["/usr/local/bin/p9"]))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    # Loading trusted source directly avoids modifying its bytecode cache.
    exec(compile(Path(loader.path).read_bytes(), loader.path, "exec"), module.__dict__)
    api_default = inspect.signature(module.Client.run).parameters["timeout_ms"].default
    if api_default != 30_000 or protocol.MAX_TIMEOUT_MS != 300_000:
        raise RuntimeError("API default or wire maximum changed")
    arguments = ("1234567890abcdef", "1" * 32, "2" * 32, ["/arm64/bin/echo"])
    implicit = protocol.decode_request(protocol.encode_request(*arguments, cwd="/n/work"))
    maximum = protocol.decode_request(protocol.encode_request(
        *arguments, cwd="/n/work", timeout_ms=protocol.MAX_TIMEOUT_MS))
    if implicit.timeout_ms != api_default or maximum.timeout_ms != 300_000:
        raise RuntimeError("protocol timeout configuration changed")
    try:
        protocol.encode_request(*arguments, cwd="/n/work", timeout_ms=300_001)
    except ValueError:
        pass
    else:
        raise RuntimeError("protocol accepted a budget above its maximum")
    return {"client_run_default_ms": api_default, "wire_default_ms": implicit.timeout_ms,
            "wire_maximum_ms": maximum.timeout_ms, "above_maximum_rejected": True}


def guest_helper() -> bytes:
    old = '"cwd":request.cwd,"status_hex"'
    if GUEST_HELPER.count(old) != 1:
        raise RuntimeError("guest evidence helper layout changed")
    helper = GUEST_HELPER.replace(old, '"cwd":request.cwd,"timeout_ms":request.timeout_ms,"status_hex"')
    boundary = ' write(root/("evidence-"+name+".json"),record)'
    assertion = ''' assert request.timeout_ms==120000,request.timeout_ms
 expected={"compile":["/arm64/bin/7c","-o","hello.7","hello.c"],"link":["/arm64/bin/7l","-o","hello","hello.7"],"execute":["/n/work/"+root.name+"/hello"]}
 assert list(request.argv)==expected[name] and request.cwd=="/n/work/"+root.name
 assert request.stdin==b"" and wire["stderr"]==b""
 assert wire["stdout"]==((root/"expected-output").read_bytes() if name=="execute" else b"")
 capture=root/("capture-"+name);capture.mkdir()
 for key,data in wire.items():(capture/key).write_bytes(data)
'''
    if helper.count(boundary) != 1:
        raise RuntimeError("guest assertion publication boundary changed")
    return helper.replace(boundary, assertion + boundary).encode()


def check_installed(terminal: Terminal, sources: dict) -> None:
    checked_command(terminal, " && ".join(
        'test "$(sha256sum ' + path + " | cut -d ' ' -f1)\" = " + sources[source]
        for path, source in INSTALLED.items()))


def verify(state: Path, build: Path) -> dict:
    inputs = preflight(state, build)
    state, build = Path(inputs["state"]), Path(inputs["build"])
    output = Path(tempfile.mkdtemp(prefix="p9-default-compile-", dir=state))
    receipt = output / "result.json"
    sources = {path: hash_file(ROOT / path) for path in SOURCE_PATHS}
    result = {"schema": "ostadix.p9-default-compile/v1", "ok": False,
              "started": time.time(), "inputs": inputs, "source_sha256": sources,
              "scope": "one isolated real boot; typed implicit-default p9 7c/7l/hello through the original Linux client and original Plan9 provider; not source-native compiler or complete OS qualification",
              "source_artifacts": {}, "checks": []}
    terminal = None
    try:
        receipt.write_text(json.dumps(result, indent=2) + "\n")
        for source, expected in sources.items():
            target = output / "sources" / source
            target.parent.mkdir(parents=True, exist_ok=True)
            data = (ROOT / source).read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                raise RuntimeError("source changed before capture: " + source)
            target.write_bytes(data)
            target.chmod(0o400)
            result["source_artifacts"][source] = identity(target)
        result["host_timeout_contract"] = host_timeout_contract()
        result["host_tools"] = {"python": identity(Path(sys.executable))}
        qemu = shutil.which("qemu-system-aarch64")
        if qemu is None:
            raise RuntimeError("qemu-system-aarch64 is missing")
        result["host_tools"]["qemu"] = identity(Path(qemu))
        result["qemu_version"] = subprocess.run(
            [qemu, "--version"], check=True, capture_output=True, text=True, timeout=10).stdout
        result["fork"] = identity(state / "fork.json")
        token = secrets.token_hex(12)
        name = "default-compile-" + token
        workspace, native = "/n/okernel/work/" + name, "/work/" + name
        marker = "P9_DEFAULT_COMPILED_" + token
        expected_output = (marker + "\n").encode()
        source = ('#include <u.h>\n#include <libc.h>\n'
                  'void main(void){print("' + marker + '\\n");exits(nil);}\n').encode()
        helper = "/tmp/p9-default-compile-" + token + ".py"
        directory = output / "terminal"
        directory.mkdir()
        terminal = Terminal(state, build, directory)
        terminal.wait(b"Linux and original Plan 9 share this workspace.", timeout=240)
        session = Path((state / "latest-unified-session").read_text().strip())
        result.update(session=str(session), workspace=workspace,
                      installed_guest_sources={path: sources[source] for path, source in INSTALLED.items()})
        check_installed(terminal, sources)
        checked_command(terminal, "mkdir -p " + shlex.quote(workspace))
        typed(terminal, "cd " + shlex.quote(workspace))
        checked_command(terminal, "test \"$PWD\" = " + shlex.quote(workspace)
                        + " && echo $$ > linux-shell.pid && awk '{print $22}' /proc/$$/stat > linux-shell.start")
        upload(terminal, helper, guest_helper())
        upload(terminal, workspace + "/hello.c", source)
        upload(terminal, workspace + "/expected-output", expected_output)
        for step, command in (("compile", "p9 7c -o hello.7 hello.c"),
                              ("link", "p9 7l -o hello hello.7"),
                              ("execute", "p9 ./hello")):
            collect(terminal, helper, workspace, step, command, timeout=180)
        terminal.wait(marker.encode(), line=True)
        check_installed(terminal, sources)
        checked_command(terminal, "test \"$(cat linux-shell.pid)\" = $$ && test \"$(awk '{print $22}' /proc/$$/stat)\" = \"$(cat linux-shell.start)\"")
        terminal.finish()  # One explicit Ctrl+] and one paired save for this boot.
        record, volume = read_saved_session(state, session)
        terminal.close()
        terminal = None
        if record["before"] != inputs["before"]:
            raise RuntimeError("boot input head differs from preflight")
        if record.get("provider_recoveries") or record.get("provider_failure"):
            raise RuntimeError("default compiler qualification required provider recovery")
        observation = json.loads((session / "native-observation.json").read_text())
        if observation["live_domains"] != 3 or observation["input_dropped"] != 0:
            raise RuntimeError("both native domains were not live without dropped input")
        result["native_observation"] = observation
        result["paired_save"] = identity(session / "result.json")
        result["after"] = record["after"]
        if volume.get(native + "/hello.c") != source or volume.get(native + "/expected-output") != expected_output:
            raise RuntimeError("saved source or fresh output oracle differs")
        expected_argv = {"compile": ["/arm64/bin/7c", "-o", "hello.7", "hello.c"],
                         "link": ["/arm64/bin/7l", "-o", "hello", "hello.7"],
                         "execute": ["/n" + native + "/hello"]}
        seen = set()
        result["commands"] = {}
        for step, argv in expected_argv.items():
            evidence_bytes = volume.get(native + "/evidence-" + step + ".json")
            evidence = json.loads(evidence_bytes)
            local = evidence["receipt"]
            g, s, r = (local[key] for key in ("generation", "instance", "request_id"))
            if (g, s, r) in seen or local["service_root"] != "/n/okernel/services/plan9":
                raise RuntimeError("request identity reused or service root changed")
            seen.add((g, s, r))
            # The current history helper can reclaim earlier service requests
            # before the next invocation. The guest collector copied each
            # exact validated wire set before allowing the next command.
            files = {key: volume.get(native + "/capture-" + step + "/" + key)
                     for key in protocol.REQUEST_FILES}
            request = protocol.validate_submit(files["request"], files["submit"])
            completed = protocol.validate_result(files["request"], files["result"], files["stdout"], files["stderr"],
                                                started=files["started"], done=files["done"], status=files["status"])
            wire_hashes = {key: hashlib.sha256(value).hexdigest() for key, value in files.items()}
            if ((request.generation, request.instance, request.request_id) != (g, s, r)
                    or list(request.argv) != argv or request.cwd != "/n" + native or request.timeout_ms != 120_000
                    or request.stdin != b"" or files["stderr"] != b""
                    or files["stdout"] != (expected_output if step == "execute" else b"")
                    or completed.flags != 0 or completed.status != b"" or not completed.ok
                    or evidence["linux_exit"] != 0 or evidence["argv"] != argv
                    or evidence["cwd"] != request.cwd or evidence["timeout_ms"] != request.timeout_ms
                    or evidence["status_hex"] != "" or evidence["wire_sha256"] != wire_hashes
                    or local["request_sha256"] != wire_hashes["request"]
                    or local["result_sha256"] != wire_hashes["result"] or local["recovered"]):
                raise RuntimeError("saved " + step + " capture differs from exact default-budget contract")
            capture = output / "commands" / step
            capture.mkdir(parents=True)
            (capture / "evidence.json").write_bytes(evidence_bytes)
            for key, data in files.items():
                (capture / key).write_bytes(data)
            result["commands"][step] = {"generation": g, "instance": s, "request_id": r,
                                        "argv": argv, "cwd": request.cwd, "timeout_ms": request.timeout_ms,
                                        "wire_sha256": wire_hashes, "evidence": identity(capture / "evidence.json")}
        result["artifacts"] = {}
        for filename in ("hello.c", "hello.7", "hello"):
            target = output / filename
            target.write_bytes(volume.get(native + "/" + filename))
            if not target.stat().st_size:
                raise RuntimeError("empty original compiler artifact: " + filename)
            target.chmod(0o400)
            result["artifacts"][filename] = identity(target)
        if sources != {path: hash_file(ROOT / path) for path in sources}:
            raise RuntimeError("host sources changed during qualification")
        for captured in result["source_artifacts"].values():
            if identity(Path(captured["path"])) != captured:
                raise RuntimeError("captured source copy changed during qualification")
        result.update(ok=True, finished=time.time(), checks=[
            "exact selected helpers matched the actual guest before and after the typed commands",
            "implicit p9 7c, p9 7l and p9 ./hello each emitted a 120000ms wire request with exact argv/cwd/input/result",
            "original compiler/linker produced a retained executable with exact fresh-nonce output",
            "both native domains remained live and the same Linux shell survived without dropped input",
            "one Ctrl+] produced a quiescent paired save; saved source, full wire captures and compiled artifacts independently validated",
        ])
        print("Original Plan9 p9 default compiler/linker: PASS\nEvidence: " + str(receipt))
    except BaseException as error:
        result["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        try:
            if terminal is not None:
                terminal.close()  # Own controller/QEMU only; never retries commands.
        finally:
            receipt.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args.state.expanduser(), args.build.expanduser())
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
        print("Original Plan9 p9 default compiler/linker: FAIL\n" + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
