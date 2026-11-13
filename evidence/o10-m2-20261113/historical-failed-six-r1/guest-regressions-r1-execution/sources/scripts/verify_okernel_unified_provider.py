#!/usr/bin/env python3
"""Qualify original Plan9 commands/compiler and native recycling beside Linux.

This is an automated component gate in an explicit isolated fork. Requests are
published by the real Linux guest into O-core's native namespace. The original
Plan9 worker, not the host shell, executes every requested original program.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import secrets
import shlex
import sys
import time

from okernel_unified_world import UnifiedDomain, Volume, digest, protocol

ROOT = Path(__file__).resolve().parents[1]


def put(domain, path, data):
    encoded = base64.b64encode(data).decode()
    domain.command("printf %s " + shlex.quote(encoded) + " | base64 -d > " + shlex.quote(path))


def submit(domain, argv, *, cwd="/n/work", stdin=b"", timeout_ms=60000, service=None):
    service = service or dict(domain.service)
    request_id = secrets.token_hex(16)
    request = protocol.encode_request(service["generation"], service["instance"], request_id,
                                      argv, cwd=cwd, stdin=stdin, timeout_ms=timeout_ms)
    paths = protocol.request_paths("/n/okernel/services/plan9", service["generation"],
                                    service["instance"], request_id)
    domain.command("mkdir " + shlex.quote(paths["request"].rsplit("/", 1)[0]))
    put(domain, paths["request"], request)
    temporary = paths["submit"] + ".staged"
    put(domain, temporary, protocol.submit_marker(request))
    domain.command("mv " + shlex.quote(temporary) + " " + shlex.quote(paths["submit"]))
    return {"request": request, "paths": paths, "service": service, "id": request_id}


def native_path(path):
    return path.removeprefix("/n/okernel")


def finished(domain, invocation, *, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        volume = domain.native_volume()
        try:
            files = {name: volume.get(native_path(path)) for name, path in invocation["paths"].items()}
        except FileNotFoundError:
            domain.pump()
            continue
        if files["request"] != invocation["request"]:
            raise RuntimeError("resident request bytes changed after publication")
        protocol.validate_submit(files["request"], files["submit"])
        result = protocol.validate_result(files["request"], files["result"], files["stdout"], files["stderr"],
                                           started=files["started"], done=files["done"], status=files["status"])
        return result, files
    raise TimeoutError("original Plan9 command did not publish a complete result")


def save_capture(directory, invocation, files):
    directory.mkdir()
    for name, data in files.items():
        (directory / name).write_bytes(data)
    (directory / "invocation.json").write_text(json.dumps({key: value for key, value in invocation.items()
                                                            if key != "request"}, indent=2) + "\n")


def wait_file(domain, name, *, expected=None, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            content = domain.native_volume().get(name)
            if (expected is None and content) or content == expected:
                return content
        except FileNotFoundError:
            pass
        domain.pump()
    raise TimeoutError("original command witness missing: " + name)


def verify(state, build, timeout):
    output = state / ("provider-acceptance-" + secrets.token_hex(8))
    output.mkdir()
    receipt = output / "result.json"
    record = {"schema": "ostadix.unified-original-provider/v1", "ok": False,
              "scope": "actual original Linux publication and original Plan9 commands/compiler under one O-core EL2 monitor; automated component acceptance",
              "controller": {"path": str(Path(__file__).resolve()), "sha256": digest(Path(__file__))},
              "started": time.time(), "sessions": [], "checks": []}
    receipt.write_text(json.dumps(record, indent=2) + "\n")
    domain = None
    token = secrets.token_hex(8)
    program = "p9-source-" + token
    source = (b'#include <u.h>\n#include <libc.h>\nvoid main(void){char b[256];long n;'
              b'print("ORIGINAL_PLAN9_COMPILED\\n");fprint(2,"ORIGINAL_PLAN9_STDERR\\n");'
              b'while((n=read(0,b,sizeof b))>0)if(write(1,b,n)!=n)exits("write");exits(n<0?"read":nil);}\n')
    input_bytes = b"unified-original-stdin\x00\xff\n" + secrets.token_bytes(31)
    try:
        domain = UnifiedDomain(state, build, "qemu-system-aarch64", timeout=timeout)
        record["sessions"].append(str(domain.session))
        domain.ready()
        if not domain.service or not domain.provider_ready:
            raise RuntimeError("the original resident provider was not provisioned")
        put(domain, "/n/okernel/work/" + program + ".c", source)
        invocation = submit(domain, ["/arm64/bin/rc", "-I", "-c",
                                      "7c -o " + program + ".7 " + program + ".c && 7l -o " + program + " " +
                                      program + ".7 && ./" + program], stdin=input_bytes)
        result, files = finished(domain, invocation)
        save_capture(output / "original-compile", invocation, files)
        if (not result.ok or files["stdout"] != b"ORIGINAL_PLAN9_COMPILED\n" + input_bytes
                or files["stderr"] != b"ORIGINAL_PLAN9_STDERR\n"):
            raise RuntimeError("original Plan9 compile/execute binary stdin/output/status oracle failed")
        binary = domain.native_volume().get("/work/" + program)
        record["program_sha256"] = __import__("hashlib").sha256(binary).hexdigest()
        record["checks"].append("Linux publishes binary request; original PAQ-only 7c/7l compile and execute source with exact binary stdin, stdout, stderr and empty native status")

        # Preserve a real Linux process identity and native object across reset.
        pidfile = "/work/unified-survivor-" + token
        counter = "/n/okernel/work/survivor-" + token
        domain.command("sh -c 'while :; do date +%s > " + counter + "; sleep 1; done' & echo $! > " + pidfile)
        domain.command("awk '{print $22}' /proc/$(cat " + pidfile + ")/stat > " + pidfile + ".start")
        wait_file(domain, native_path(counter))
        old = dict(domain.service)
        active = "/n/work/active-" + token
        late = "/n/work/forbidden-late-" + token
        child_ready = "/n/work/child-ready-" + token
        release = "/n/work/release-" + token
        command = "{echo CHILD > " + child_ready + "; while(! test -f " + release + ") sleep 1; echo FORBIDDEN > " + late + "} & while(! test -f " + child_ready + ") sleep 1; echo ACTIVE > " + active + "; sleep 60"
        interrupted = submit(domain, ["/arm64/bin/rc", "-I", "-c", command], timeout_ms=30000)
        if wait_file(domain, active.removeprefix("/n"), expected=b"ACTIVE\n") != b"ACTIVE\n":
            raise RuntimeError("original command did not prove active execution before cancellation")
        wait_file(domain, child_ready.removeprefix("/n"), expected=b"CHILD\n")
        cancel = protocol.cancel_marker(interrupted["request"])
        cancel_path = interrupted["paths"]["request"].rsplit("/", 1)[0] + "/cancel"
        put(domain, cancel_path + ".staged", cancel)
        domain.command("mv " + shlex.quote(cancel_path + ".staged") + " " + shlex.quote(cancel_path))
        result, files = finished(domain, interrupted)
        save_capture(output / "cancelled", interrupted, files)
        if not result.flags & protocol.FLAG_CANCELLED:
            raise RuntimeError("active cancellation was not recorded")
        if domain.service == old:
            domain.watch_provider()
        if domain.service == old or not domain.provider_ready:
            raise RuntimeError("interrupted completion exposed before original domain recycling")
        recovery = domain.record.get("provider_recoveries", [])[-1]
        if not recovery.get("ok") or recovery["withdrawn"]["live_domains"] != 1 or recovery["restored"]["live_domains"] != 3:
            raise RuntimeError("native recovery did not withdraw only Plan9 and restore both domains")
        before = Volume.from_file(Path(recovery["namespace_before"]["path"]))
        if before.get(child_ready.removeprefix("/n")) != b"CHILD\n":
            raise RuntimeError("detached original process was not active before native withdrawal")
        for name in (release, late):
            try:
                before.get(name.removeprefix("/n"))
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError("cancellation fixture was already released before native withdrawal")
        domain.command("kill -0 $(cat " + pidfile + ") && test \"$(awk '{print $22}' /proc/$(cat " + pidfile + ")/stat)\" = \"$(cat " + pidfile + ".start)\"")
        # Sample AFTER replacement, then require later nonempty progress.
        before_counter = wait_file(domain, native_path(counter))
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline:
            updated_counter = domain.native_volume().get(native_path(counter))
            if updated_counter.strip().isdigit() and int(updated_counter) > int(before_counter):
                break
            domain.pump()
        else:
            raise RuntimeError("surviving original Linux process stopped making progress")
        # Release only AFTER the recorded native replacement. A wall-clock
        # sleep could expire while the slow test publishes cancellation, so
        # mere later file existence would not establish a surviving process.
        put(domain, "/n/okernel" + release.removeprefix("/n"), b"RELEASE\n")
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            domain.pump(0.1)
        try:
            domain.native_volume().get(late.removeprefix("/n"))
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("old detached Plan9 descendant survived domain replacement")
        stale_effect = "/n/work/stale-effect-" + token
        stale = submit(domain, ["/arm64/bin/rc", "-I", "-c", "echo STALE > " + stale_effect], service=old)
        current = submit(domain, ["/arm64/bin/echo", "FRESH_PROVIDER_" + token])
        result, files = finished(domain, current)
        save_capture(output / "fresh-provider", current, files)
        if not result.ok or files["stdout"] != ("FRESH_PROVIDER_" + token + "\n").encode():
            raise RuntimeError("fresh original provider command failed after recycling")
        domain.pump(0.5)
        try:
            domain.native_volume().get(stale_effect.removeprefix("/n"))
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("old instance submission was replayed")
        domain.command("kill $(cat " + pidfile + ")")
        record["checks"].extend(["native Plan9-only withdrawal/replacement preserves the same Linux PID/start time, progress and native files",
                                  "cancelled original rc detached descendant cannot respond to a release published only after its owning domain is discarded",
                                  "fresh original provider executes new work and ignores a newly published old-instance request"])
        domain.save()
        domain.close()
        domain = None
        # Both kernels really boot again; the executable comes from the saved
        # common namespace, not a host-side rebuild or a substituted engine.
        domain = UnifiedDomain(state, build, "qemu-system-aarch64", timeout=timeout)
        record["sessions"].append(str(domain.session))
        domain.ready()
        invocation = submit(domain, ["/n/work/" + program], stdin=input_bytes)
        result, files = finished(domain, invocation)
        save_capture(output / "restart-original-binary", invocation, files)
        if (not result.ok or files["stdout"] != b"ORIGINAL_PLAN9_COMPILED\n" + input_bytes
                or files["stderr"] != b"ORIGINAL_PLAN9_STDERR\n"
                or domain.native_volume().get("/work/" + program) != binary):
            raise RuntimeError("saved original Plan9 binary did not execute identically after two-kernel restart")
        domain.save()
        record["checks"].append("actual two-kernel restart preserves and re-executes identical original Plan9 executable with fresh provider identities")
        record.update(ok=True, finished=time.time())
        print("Unified original Plan9 compiler/service/recycle/restart: PASS\nEvidence: " + str(receipt))
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if domain is not None:
            domain.close()
        receipt.write_text(json.dumps(record, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    try:
        verify(args.state.expanduser().resolve(), args.build.expanduser().resolve(), args.timeout)
        return 0
    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
        print("Unified original-provider acceptance failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
