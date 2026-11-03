#!/usr/bin/env python3
"""Qualify simultaneous original kernels and bidirectional saved native files.

This is a component gate, not the unified interactive process-service acceptance.
It never uses the default state and requires an explicit stopped test fork.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import secrets
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("two_domain_runner", ROOT / "scripts/okernel_unified_world.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def verify(state: Path, build: Path, qemu: str, timeout: float):
    receipt = state / "two-domain-acceptance.json"
    if receipt.exists():
        history = state / "acceptance-history"
        history.mkdir(exist_ok=True)
        (history / ("two-domains-" + uuid.uuid4().hex + ".json")).write_bytes(receipt.read_bytes())
    result = {"schema": "ostadix.original-linux-plan9-two-domain-acceptance/v1", "ok": False,
              "started": time.time(), "sessions": [], "checks": [],
              "scope": "one O-core EL2 monitor, two simultaneous original kernels and shared native objects; command-service/interactive console qualification remains separate"}
    runner.common.write_json(receipt, result)
    domain = None
    token = secrets.token_hex(16)
    linux_name, plan9_name = "dual-linux-" + token, "dual-plan9-" + token
    linux_text, plan9_text = "LINUX_DUAL_" + token, "PLAN9_DUAL_" + token
    try:
        domain = runner.UnifiedDomain(state, build, qemu, timeout=timeout)
        result["sessions"].append(str(domain.session))
        domain.ready()
        domain.command("i=0; until grep -qx " + domain.ready_value + " /n/okernel/work/" + domain.ready_name +
                       "; do i=$((i+1)); test \"$i\" -lt 100 || exit 1; sleep 0.1; done")
        domain.command("printf '%s\\n' " + linux_text + " > /n/okernel/work/" + linux_name)
        domain.command("printf '#include <stdio.h>\\nint main(void){puts(\"UNIFIED_TWO_DOMAIN_GCC_PASS\");return 0;}\\n' > /n/okernel/work/dual-source.c; cc /n/okernel/work/dual-source.c -o /work/dual-program && /work/dual-program")
        domain.wait(b"UNIFIED_TWO_DOMAIN_GCC_PASS", line=True)
        first = domain.counters()
        if first["live_domains"] != 3 or min(first["linux_exits"], first["plan9_exits"]) < 10 or first["switches"] < 10:
            raise RuntimeError("both original kernels did not sustain scheduled progress")
        result["checks"].extend(["both original kernels boot concurrently beneath one native O-core EL2 monitor",
                                 "original Plan9 writes a fresh native object read by original Linux",
                                 "original guest GCC compiles and executes shared source while Plan9 remains scheduled"])
        result["first_counters"] = first
        result["first_epoch"] = domain.epoch
        domain.save()
        result["first_pair"] = domain.head
        domain.close()
        domain = None

        bootstrap = runner.DEFAULT_BOOTSTRAP
        bootstrap += ("cat /n/work/" + linux_name + "\necho " + plan9_text + " > /n/work/" + plan9_name + "\n").encode()
        domain = runner.UnifiedDomain(state, build, qemu, timeout=timeout, bootstrap=bootstrap)
        result["sessions"].append(str(domain.session))
        domain.ready()
        domain.wait(linux_text.encode(), line=True, plan9=True)
        domain.command("i=0; until grep -qx " + plan9_text + " /n/okernel/work/" + plan9_name +
                       "; do i=$((i+1)); test \"$i\" -lt 100 || exit 1; sleep 0.1; done; " +
                       "grep -qx " + linux_text + " /n/okernel/work/" + linux_name + " && /work/dual-program")
        domain.wait(b"UNIFIED_TWO_DOMAIN_GCC_PASS", line=True)
        if domain.epoch == result["first_epoch"]:
            raise RuntimeError("restart reused ephemeral native session epoch")
        second = domain.counters()
        if second["live_domains"] != 3 or second["switches"] < 10:
            raise RuntimeError("restart lost one of the original kernels")
        domain.save()
        result["checks"].extend(["actual two-kernel restart recovers Linux-created native data and compiled executable",
                                 "original Plan9 cat reads the exact saved Linux nonce and original echo writes a new response",
                                 "original Linux reads exact Plan9 response from the same native store",
                                 "fresh native session epoch and one stopped/quiescent paired save preserve both providers' objects"])
        result.update(ok=True, finished=time.time(), second_counters=second,
                      second_epoch=domain.epoch, final_pair=domain.head)
        print("Original Linux/Plan9 simultaneous-domain shared-store restart: PASS\nEvidence: " + str(receipt))
    except BaseException as error:
        result["error"] = str(error)
        raise
    finally:
        if domain is not None:
            domain.close()
        runner.common.write_json(receipt, result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    try:
        verify(args.state.expanduser().resolve(), args.build.expanduser().resolve(), args.qemu, args.timeout)
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError) as error:
        print("Two-domain acceptance failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

