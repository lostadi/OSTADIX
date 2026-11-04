#!/usr/bin/env python3
"""Exercise the original-source native codec in an isolated OKernel domain.

Linux remains the original guest kernel. Only the declared u9fs/musl codec
component is lowered through O-core; this does not qualify a complete OS.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time
import uuid

import okernel_package_domain as runner

COUNTERS = ("ENCODE_CALLS", "DECODE_CALLS", "ENCODE_BYTES", "DECODE_BYTES")


def counter_addresses(monitor: Path) -> dict:
    listing = subprocess.run(["nm", "--defined-only", "--format=posix", str(monitor)],
                             check=True, capture_output=True, text=True).stdout
    addresses = {}
    for line in listing.splitlines():
        fields = line.split()
        for name in COUNTERS:
            if fields[0] == "_O_runtime__common__u9fs_codec__" + name:
                address = int(fields[2], 16)
                if name in addresses or not 0x40080000 <= address < 0x41000000 - 8:
                    raise ValueError("invalid native codec counter location")
                addresses[name] = address
    if set(addresses) != set(COUNTERS):
        raise ValueError("monitor lacks the original-codec execution counters")
    return addresses


def sample(domain, addresses: dict, label: str) -> dict:
    domain.stop_at_snapshot_boundary()
    try:
        values = {}
        for name, address in addresses.items():
            output = domain.session / (label + "-" + name + ".bin")
            domain.qmp.execute("pmemsave", {"val": address, "size": 8,
                                          "filename": str(output)})
            data = output.read_bytes()
            if len(data) != 8:
                raise ValueError("incomplete native execution counter")
            values[name] = int.from_bytes(data, "little")
        return values
    finally:
        domain.qmp.execute("cont")


def exchange(domain, addresses: dict, challenge: str) -> dict:
    before = sample(domain, addresses, "before")
    domain.command("printf '%s\\n' " + shlex.quote(challenge) + " > /n/okernel/work/from-linux")
    generation = f"native-9p-peer generation={domain.namespace_epoch:016x}"
    # Wait for the specific fresh payload as well as this boot's generation;
    # an earlier reply is insufficient even if it was written in this session.
    domain.command("i=0; until grep -qx " + shlex.quote(generation)
                   + " /n/okernel/work/from-plan9 2>/dev/null && grep -qx "
                   + shlex.quote("linux=" + challenge)
                   + " /n/okernel/work/from-plan9 2>/dev/null; do i=$((i+1)); "
                   + "test \"$i\" -lt 100 || break; sleep 0.1; done; "
                   + "grep -qx " + shlex.quote(generation) + " /n/okernel/work/from-plan9 && grep -qx "
                   + shlex.quote("linux=" + challenge) + " /n/okernel/work/from-plan9")
    after = sample(domain, addresses, "after")
    delta = {name: after[name] - before[name] for name in COUNTERS}
    if any(value <= 0 for value in delta.values()):
        raise RuntimeError("fresh namespace exchange did not execute the original native codec")
    return {"challenge": challenge, "epoch": domain.namespace_epoch,
            "before": before, "after": after, "delta": delta}


def verify(state: Path, qemu: str, timeout: float) -> Path:
    if state == runner.DEFAULT_STATE.resolve():
        raise ValueError("verification requires an isolated fork, not the default development state")
    fork = json.loads((state / "fork.json").read_text())
    if (fork.get("schema") != "ostadix.okernel-state-fork/v1" or fork.get("ok") is not True
            or fork.get("output") != str(state) or Path(fork["source"]).resolve() == state):
        raise ValueError("state must have a completed fork receipt identifying this isolated directory")
    profile_path = state / "monitor/monitor-profile.json"
    profile_bytes = profile_path.read_bytes()
    profile = json.loads(profile_bytes)
    component = profile.get("native_9p_codec", {})
    if component.get("schema") != "ostadix.monitor-native-u9fs/v1":
        raise ValueError("build this isolated domain with OCORE_LINUX_NATIVE_9P_MANIFEST first")
    record = {"schema": "ostadix.live-native-u9fs/v1", "ok": False, "started": time.time(),
              "monitor_profile": runner.identity(profile_path), "component": component,
              "scope": "original u9fs/musl codec lowered through O-core inside the live native namespace peer; original Linux kernel remains a guest",
              "sessions": [], "exchanges": []}
    output = state / ("native-codec-live-" + uuid.uuid4().hex + ".json")
    challenge = "native-source-" + uuid.uuid4().hex
    domain = None
    try:
        for iteration in range(2):
            domain = runner.Domain(state, qemu, timeout=timeout)
            record["sessions"].append(str(domain.session))
            executed_profile = domain.session / "monitor-profile.json"
            if executed_profile.read_bytes() != profile_bytes:
                raise RuntimeError("selected monitor/component changed before the isolated boot")
            record.setdefault("executed_profiles", []).append(runner.identity(executed_profile))
            # Inspect the exact ELF snapshot executed in this session.
            addresses = counter_addresses(domain.session / "inputs/monitor")
            record.setdefault("counter_addresses", addresses)
            domain.ready()
            if iteration:
                if domain.namespace_epoch == record["exchanges"][0]["epoch"]:
                    raise RuntimeError("namespace generation was reused")
                domain.command("test \"$(cat /n/okernel/work/native-codec-restart)\" = " + shlex.quote(challenge)
                               + " && /work/native-codec-source")
            record["exchanges"].append(exchange(domain, addresses, challenge + "-" + str(iteration)))
            if iteration == 0:
                source_output = len(domain.capture)
                domain.command("printf '#include <stdio.h>\\nint main(void){puts(\"OKERNEL_NATIVE_CODEC_SOURCE_PASS\");return 0;}\\n' > /n/okernel/work/native-codec.c && cc /n/okernel/work/native-codec.c -o /work/native-codec-source && /work/native-codec-source")
                domain.wait(b"OKERNEL_NATIVE_CODEC_SOURCE_PASS", after=source_output, line=True)
                domain.command("apk info -e gcc && 9 rc -c 'echo native-source-rc > /n/okernel/work/native-codec-rc' && grep -qx native-source-rc /n/okernel/work/native-codec-rc")
                domain.command("printf '%s\\n' " + shlex.quote(challenge) + " > /n/okernel/work/native-codec-restart")
            else:
                domain.command("9 rc -c 'cat /n/okernel/work/native-codec-rc' && grep -qx native-source-rc /n/okernel/work/native-codec-rc")
            domain.save()
            record.setdefault("saved_pairs", []).append(json.loads((state / "head.json").read_text()))
            domain.close()
            domain = None
        record.update(ok=True, finished=time.time(), checks=[
            "fresh Linux/native shared-file exchange executes original native codec on both boots",
            "QMP reads increasing encode/decode counters from the exact running monitor",
            "original guest GCC reads C source from the shared namespace and runs its Linux executable",
            "original Plan9port rc accesses the same live native namespace",
            "paired disk/namespace save survives restart with a fresh namespace generation"])
        print("Original-source native codec live acceptance: PASS\nEvidence: " + str(output), flush=True)
        return output
    except BaseException as error:
        record["error"] = str(error)
        raise
    finally:
        if domain is not None:
            domain.close()
        runner.write_json(output, record)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path,
                        help="isolated package-domain state; verification writes and saves test files")
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=240)
    args = parser.parse_args()
    try:
        verify(args.state.expanduser().resolve(), args.qemu, args.timeout)
        return 0
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
        print("Native codec live acceptance failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
