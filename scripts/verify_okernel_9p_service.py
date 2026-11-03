#!/usr/bin/env python3
"""Qualify original Plan9port 9P access to native shared objects in a test state.

Requires an explicitly selected stopped state; use `okernel fork` so a working
console remains untouched. The original Plan 9 kernel probe is a separate gate.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("service_runner", ROOT / "scripts/okernel_package_domain.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def verify(state: Path, qemu: str, *, build: bool, timeout: float):
    record = {"schema": "ostadix.original-9p-native-service/v1", "ok": False,
              "started": time.time(), "sessions": [], "checks": [],
              "scope": "original Plan9port client/9pserve and declared path-hardened u9fs in the Linux ABI; native O-core owns the exported objects; no original Plan9 kernel/shared-mount claim"}
    receipt = state / "original-9p-acceptance.json"
    if receipt.exists():
        history = state / "acceptance-history"
        history.mkdir(exist_ok=True)
        (history / ("original-9p-" + uuid.uuid4().hex + ".json")).write_bytes(receipt.read_bytes())
    runner.write_json(receipt, record)
    domain = None
    suffix = uuid.uuid4().hex
    name = "work/wire-proof-" + suffix
    challenge = "original-9p-" + suffix
    try:
        domain = runner.Domain(state, qemu, timeout=timeout)
        record["sessions"].append(str(domain.session))
        domain.ready()
        if not domain.namespace:
            raise ValueError("original service qualification requires the native namespace grant")
        if build:
            domain.command("pkg source plan9port", timeout=timeout)
            domain.wait(b"OKERNEL SOURCE BUILD plan9port PASS", line=True)
        domain.command("pkg-9p test", timeout=180)
        domain.wait(b"OKERNEL ORIGINAL 9P SHARED OBJECT ROUNDTRIP PASS", line=True)
        record["checks"].append("original client/server 9P wire read/write/stat reaches mounted native objects; root escape rejected")
        # Checkpoint completed source work before additional test assertions.
        domain.save()
        record["installation_pair"] = json.loads((state / "head.json").read_text())
        domain.close()
        domain = runner.Domain(state, qemu, timeout=timeout)
        record["sessions"].append(str(domain.session))
        domain.ready()
        domain.command("pkg-9p status && test \"$NAMESPACE\" = /run/okernel-9p && 9p -n stat okernel/work")
        domain.command("printf '%s\\n' " + shlex.quote(challenge) + " > /n/okernel/" + name + " && 9p -n read okernel/" + name + " > /work/wire-readback && grep -qx " + shlex.quote(challenge) + " /work/wire-readback")
        domain.command("dd if=/dev/urandom of=/n/okernel/" + name + "-binary bs=4096 count=5 && 9p -n read okernel/" + name + "-binary > /work/wire-binary && cmp /n/okernel/" + name + "-binary /work/wire-binary")
        domain.command(": > /n/okernel/work/from-linux && printf '%s\\n' " + shlex.quote(challenge) + " | 9p -n write okernel/work/from-linux")
        expected = f"native-9p-peer generation={domain.namespace_epoch:016x}"
        domain.command("i=0; until grep -qx " + shlex.quote(expected) + " /n/okernel/work/from-plan9; do i=$((i+1)); test \"$i\" -lt 100 || exit 1; sleep 0.1; done; 9p -n read okernel/work/from-plan9 | grep -qx " + shlex.quote("linux=" + challenge))
        record["checks"].extend(["original 9P client transfers binary data across multiple native messages", "original 9P write and independent native protocol peer exchange exact bytes through the same object store"])
        domain.command("pkg-9p stop && pkg-9p start && pkg-9p test", timeout=180)
        domain.command("pkg install plan9port", timeout=180)
        domain.wait(b"OKERNEL SOURCE PACKAGE plan9port VERIFIED", line=True)
        record["checks"].append("owned service stop/restart and complete installed-package verification/reuse succeed")
        domain.save()
        domain.close()
        domain = runner.Domain(state, qemu, timeout=timeout)
        record["sessions"].append(str(domain.session))
        domain.ready()
        domain.command("pkg-9p status && 9p -n read okernel/" + name + " | grep -qx " + shlex.quote(challenge))
        domain.command("9p -n read okernel/" + name + "-binary > /work/wire-binary-restart && cmp /work/wire-binary /work/wire-binary-restart")
        domain.save()
        record["checks"].append("PID1 restores the service and original clients recover the same objects after a real VM restart")
        record.update(ok=True, finished=time.time(), final_pair=json.loads((state / "head.json").read_text()))
        print("Original 9P/native shared-service acceptance: PASS\nEvidence: " + str(receipt), flush=True)
    except BaseException as error:
        record["error"] = str(error)
        raise
    finally:
        if domain is not None:
            domain.close()
        runner.write_json(receipt, record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--build", action="store_true", help="first rebuild the original source provider with its declared inputs")
    parser.add_argument("--timeout", type=float, default=1800)
    args = parser.parse_args()
    try:
        verify(args.state.expanduser().resolve(), args.qemu, build=args.build, timeout=args.timeout)
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError) as error:
        print("Original 9P/native service verification failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
