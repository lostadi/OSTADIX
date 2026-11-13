#!/usr/bin/env python3
"""Additional M1 hostile Linux MMIO gate; does not replace Tinjection gate.

Use a separate private fork and the same qualified ELF as verify_o10_resident.
The original Plan9 provider executes one finite counter workload, which must
continue and finish after Linux performs an invalid virtio-MMIO write. This
then runs the resident60s and Plan9 restore corpus using the shared harness.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import secrets
import sys
import time

import o10
import verify_o10_resident as resident
import verify_okernel_unified_provider as provider


def fault_linux(domain, linux, record):
    harmless = 'test "$(busybox devmem 0x0a000000 32)" = 0x74726976'
    record["mmio_commands"] = [harmless]
    # A failed /dev/mem probe is a failed gate, never grounds for Tinjection.
    domain.command(harmless)
    counter = "/n/work/o10-hostile-" + secrets.token_hex(8)
    loop = "for(i in 0 1 2 3 4 5 6 7) { echo $i; sleep 1 } > " + counter
    invocation = provider.submit(domain, ["/bin/rc", "-c", loop], timeout_ms=120000)
    witness = provider.wait_file(domain, counter.removeprefix("/n"), timeout=60)
    before = domain.o10_call("Tstat", dom=domain.o10_plan9)
    if before["state"] != o10.PROVISIONAL_STATE_RUNNING:
        raise RuntimeError("Plan9 was not running before hostile Linux MMIO")
    record["plan9_counter"] = {"path": counter, "before": witness,
                               "domain_before": before, "request_id": invocation["id"]}
    hostile = "busybox devmem 0x0a0000fc 32 1"
    record["mmio_commands"].append(hostile)
    # Deliberately do not wait for a Linux command completion or replay it.
    domain.send(b"\x1e0\x1e0\x15" + (hostile + "\n").encode())
    deadline = time.monotonic() + 30
    while True:
        stat = domain.o10_call("Tstat", dom=linux)
        if stat["state"] == o10.PROVISIONAL_STATE_FAULTED:
            if stat["esr"] >> 26 != 0x24 or stat["ipa"] != 0x0a0000fc:
                raise RuntimeError("Linux fault did not identify the hostile MMIO access")
            record["linux_fault"] = stat
            break
        if time.monotonic() >= deadline:
            raise TimeoutError("hostile MMIO did not fault Linux; no Tinjection fallback")
        domain.pump(0.1)
    result, files = provider.finished(domain, invocation, timeout=120)
    if not result.ok:
        raise RuntimeError("surviving original Plan9 counter workload failed")
    after = domain.native_volume().get(counter.removeprefix("/n"))
    expected = b"0\n1\n2\n3\n4\n5\n6\n7\n"
    if after != expected or not after.startswith(witness) or len(after) <= len(witness):
        raise RuntimeError("original Plan9 counter did not advance across Linux fault")
    stat = domain.o10_call("Tstat", dom=domain.o10_plan9)
    if stat["dom"] != before["dom"] or stat["inst"] != before["inst"] or stat["state"] != o10.PROVISIONAL_STATE_RUNNING:
        raise RuntimeError("Plan9 changed instance across hostile Linux MMIO")
    record["plan9_counter"].update(after=after, domain_after=stat)
    provider.save_capture(domain.session / "o10-hostile-provider", invocation, files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--mcp-release", required=True)
    args = parser.parse_args()
    try:
        resident.verify(args.state, args.build, args.session, qemu=args.qemu,
                        mcp_release=args.mcp_release, fault_linux=fault_linux,
                        gate_id="verify_o10_hostile_mmio")
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError) as error:
        print("O10 hostile MMIO gate: FAIL: " + str(error), file=sys.stderr)
        return 1
    print("O10 hostile MMIO + resident gate: PASS; full M1 remains unqualified")
    print("Evidence: " + str(args.session / "result.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
