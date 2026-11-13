#!/usr/bin/env python3
"""Qualify resident EL2 control on a new private state fork.

This gate faults Linux using an explicit qualification build, withdraws Plan 9,
observes both stopped domains for at least 60 seconds, then restores Plan 9
and validates its original provider marker. It never saves or changes the
source state's head. Full M1 additionally requires same-build regressions.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import o10
import okernel_unified_world as runner

SPEC = importlib.util.spec_from_file_location("o10_resident_fork", ROOT / "scripts/fork_okernel_state.py")
forker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(forker)


def json_default(value):
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    raise TypeError("not evidence-serializable: " + type(value).__name__)


def identity(path):
    path = Path(path)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def command(argv):
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=30)
    return {"argv": argv, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def verify(state, build, session, *, qemu="qemu-system-aarch64", mcp_release,
           fault_linux=None, gate_id="verify_o10_resident"):
    session = session.absolute()
    if session.exists() or session.is_symlink():
        raise ValueError("session must be a new evidence directory")
    session.mkdir(parents=True)
    proof = session / "result.json"
    record = {"schema": "ostadix.o10-resident-gate/v1", "milestone": "M1",
              "gate_id": gate_id, "gate_passed": False,
              "milestone_qualified": False, "started_unix": time.time(),
              "session": str(session), "source_state": str(state.resolve()),
              "build": {"path": str(build.absolute() / "monitor-profile.json")},
              "mcp_release": mcp_release, "commands": [], "samples": [],
              "scope": "QEMU AArch64 resident EL2 control with zero runnable guests and original Plan 9 provider recovery; no physical-board or full-M1 claim."}
    domain = None
    try:
        record["build"] = identity(build / "monitor-profile.json")
        revision = command(["git", "rev-parse", "HEAD"])
        record["commands"].append(revision)
        if revision["returncode"]:
            raise RuntimeError("cannot identify source revision")
        record["source_revision"] = revision["stdout"].strip()
        status = command(["git", "status", "--porcelain"])
        record["commands"].append(status)
        record["source_dirty"] = bool(status["stdout"].strip())
        version = command([qemu, "--version"])
        record["commands"].append(version)
        if version["returncode"]:
            raise RuntimeError("QEMU version check failed")
        record["host"] = {"uname": list(os.uname()), "python": sys.version}
        profile = json.loads((build / "monitor-profile.json").read_text())
        runner.validate_profile(profile)
        if (profile.get("o10_qualification") is not True or profile.get("o10") != runner.O10_PROFILE
                or not profile.get("plan9_recovery") or not profile.get("plan9_command_provider")):
            raise ValueError("resident gate requires an explicit O10 qualification and recovery build")
        for name, sha in profile["source_sha256"].items():
            if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != sha:
                raise ValueError("build/source mismatch: " + name)
        record["checked_build_sources"] = dict(profile["source_sha256"])
        record["source_artifacts"] = {}
        source_names = ["scripts/verify_o10_resident.py", "scripts/okernel_unified_world.py", "scripts/o10.py"]
        if fault_linux is not None:
            source_names += ["scripts/verify_o10_hostile_mmio.py", "scripts/verify_okernel_unified_provider.py"]
        for name in source_names:
            data = (ROOT / name).read_bytes()
            destination = session / "sources" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            record["source_artifacts"][name] = identity(destination)
        private_state = session / "state"
        record["fork"] = forker.fork(state.resolve(), private_state)
        domain = runner.UnifiedDomain(private_state, build.resolve(), qemu, live=True, timeout=180)
        record["guest_session"] = str(domain.session)
        # Record the actual invocation, including machine options and captured
        # kernel artifacts; this comes from the running private child.
        cmdline = Path("/proc") / str(domain.process.pid) / "cmdline"
        record["qemu_argv"] = [x.decode() for x in cmdline.read_bytes().split(b"\0") if x]
        domain.ready()
        domain.control_active = True
        domain.o10_claim()
        linux = (1 << 32) | 0
        if fault_linux is None:
            record["linux_fault"] = domain.o10_call("Tinject", dom=linux, fault=1)
            record["linux_fault_source"] = "qualification Tinjection fault1"
        else:
            record["linux_fault_source"] = "actual Linux guest MMIO"
            fault_linux(domain, linux, record)
        domain.native_control(1)
        stopped = time.monotonic()
        while time.monotonic() - stopped < 60:
            first = domain.o10_call("Tstat", dom=linux)
            second = domain.o10_call("Tstat", dom=domain.o10_plan9)
            if first["state"] != o10.PROVISIONAL_STATE_FAULTED or second["state"] != o10.PROVISIONAL_STATE_WITHDRAWN:
                raise RuntimeError("a domain became runnable during the resident window")
            counters = domain.counters()
            if counters["live_domains"] != 0:
                raise RuntimeError("resident test did not have zero live guests")
            record["samples"].append({"seconds": time.monotonic() - stopped,
                                      "linux": first, "plan9": second, "counters": counters})
            proof.write_text(json.dumps(record, indent=2, default=json_default) + "\n")
            domain.pump(0.25)
        record["zero_runnable_seconds"] = time.monotonic() - stopped
        if len(record["samples"]) < 2:
            raise RuntimeError("resident control lacked repeated observations")
        domain.service = dict(domain.service, instance=secrets.token_hex(16))
        domain.provider_ready = False
        domain.native_control(2, domain.provider_bootstrap())
        ready_path = "/services/plan9/g" + domain.service["generation"] + "/s" + domain.service["instance"] + "/ready"
        expected = runner.protocol.ready_marker(domain.service["generation"], domain.service["instance"])
        deadline = time.monotonic() + domain.timeout
        while True:
            try:
                marker = domain.native_volume().get(ready_path)
            except FileNotFoundError:
                marker = None
            if marker is not None:
                if marker != expected:
                    raise RuntimeError("restored provider marker does not match its fresh instance")
                record["provider"] = {"path": ready_path, "sha256": hashlib.sha256(marker).hexdigest(),
                                      "service": domain.service, "stat": domain.o10_call("Tstat", dom=domain.o10_plan9)}
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("restored original Plan 9 provider did not become ready")
            domain.pump(0.1)
        for name, sha in profile["source_sha256"].items():
            if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != sha:
                raise RuntimeError("build source changed during the resident gate: " + name)
        record["build_sources_unchanged"] = True
        record["gate_passed"] = True
        record["qualification_note"] = ("The live resident gate passed. Full M1 remains unqualified until the exact source/build "
                                        "has aligned MCP provenance, classified-path tests and every required regression without skips.")
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        try:
            if domain is not None:
                domain.close()
        except BaseException as cleanup_error:
            record["gate_passed"] = False
            record["cleanup_error"] = type(cleanup_error).__name__ + ": " + str(cleanup_error)
            raise
        finally:
            record["finished_unix"] = time.time()
            proof.write_text(json.dumps(record, indent=2, default=json_default) + "\n")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True, help="preserved source state; a new fork is created")
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--mcp-release", required=True, help="observed MCP release; metadata alone cannot qualify M1")
    args = parser.parse_args()
    try:
        record = verify(args.state, args.build, args.session, qemu=args.qemu, mcp_release=args.mcp_release)
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
        print("O10 resident gate: FAIL: " + str(error), file=sys.stderr)
        return 1
    print("O10 resident live gate: PASS; full M1 remains unqualified")
    print("Evidence: " + str(Path(record["session"]) / "result.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
