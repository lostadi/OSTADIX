#!/usr/bin/env python3
"""Qualify the M0 O10 host shim on an explicit fresh private QEMU fork.

This component gate does not admit arbitrary monitor hashes to foreground
acceptance. After a real PASS, its exact monitor/profile pair may be explicitly
registered by the existing admission policy. Full M0 still needs all regressions.
No preserved/default state is accepted and no service request is replayed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import time

import o10
import okernel_unified_world as runner
from verify_okernel_unified_provider import submit, finished, save_capture

ROOT = Path(__file__).resolve().parents[1]


def fingerprint(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checked_equal(actual, expected, label):
    if actual != expected:
        raise RuntimeError(label + ": " + repr(actual) + " != " + repr(expected))


def exchange_raw(domain, frame):
    """Test the actual EL2 decoder, including bytes Python refuses to decode."""
    domain.control_sequence += 1
    sequence = domain.control_sequence
    domain.stopped()
    try:
        domain.write_native(runner.O10_PROFILE["submission"], frame)
        domain.write_native(0x6d000070, struct.pack("<QQ", sequence, 10))
    finally:
        domain.qmp.execute("cont")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        acknowledgement, status = struct.unpack("<QQ", os.pread(domain.ram, 16, 0x6d000080 - 0x40000000))
        if acknowledgement == sequence:
            domain.stopped()
            try:
                checked_equal(status, 1, "native mailbox acknowledgement")
                offset = runner.O10_PROFILE["completion"] - 0x40000000
                size_bytes = os.pread(domain.ram, 4, offset)
                if len(size_bytes) != 4:
                    raise RuntimeError("short native completion header")
                size, = struct.unpack("<I", size_bytes)
                if not 7 <= size <= 512:
                    raise RuntimeError("native completion length outside negotiated slot")
                raw = os.pread(domain.ram, size, offset)
                reply = o10.decode(raw)
                if len(frame) >= 7 and struct.unpack_from("<I", frame, 0)[0] >= 7:
                    checked_equal(reply["tag"], struct.unpack_from("<H", frame, 5)[0], "reply tag")
                elif len(frame) >= 4 and struct.unpack_from("<I", frame, 0)[0] < 7:
                    checked_equal(reply["tag"], 0, "incomplete header has no tag")
                return raw, reply
            finally:
                domain.qmp.execute("cont")
        if domain.process.poll() is not None:
            raise RuntimeError("QEMU exited during raw O10 exchange")
        domain.pump(.01)
    raise TimeoutError("raw O10 outcome unknown; mutation not replayed")


def wait_provider_ready(domain, timeout):
    root = "/services/plan9/g" + domain.service["generation"] + "/s" + domain.service["instance"]
    expected = runner.protocol.ready_marker(domain.service["generation"], domain.service["instance"])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            marker = domain.native_volume().get(root + "/ready")
        except FileNotFoundError:
            domain.pump(.1)
            continue
        checked_equal(marker, expected, "replacement provider ready marker")
        domain.provider_ready = True
        return
    raise TimeoutError("replacement provider readiness missing")


def verify(state, build, output, qemu, timeout, mcp_release):
    if state.is_symlink() or build.is_symlink():
        raise ValueError("state/build must not be symlinks")
    state, build = state.resolve(strict=True), build.resolve(strict=True)
    if output.exists() or output.is_symlink():
        raise ValueError("output must be a new evidence directory")
    profile = json.loads((build / "monitor-profile.json").read_text())
    runner.validate_profile(profile)
    checked_equal(profile.get("o10"), runner.O10_PROFILE, "O10 profile")
    for name, expected in profile.get("source_sha256", {}).items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("captured source path escaped checkout")
        checked_equal(fingerprint(ROOT / relative), expected, "same-build source " + name)
    if not profile.get("plan9_recovery") or profile.get("plan9_derivation_kind") != "qualified-original-userland":
        raise ValueError("live O10 gate requires the admitted provider and immutable reset images")
    # UnifiedDomain independently validates the selected fork, head, profile and
    # every captured artifact before any VM starts. Reject symlink args here too.
    if state.is_symlink() or build.is_symlink():
        raise ValueError("state/build must not be symlinks")
    output.mkdir(parents=True, exist_ok=False)
    result_path = output / "result.json"
    source_revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                                     capture_output=True, text=True).stdout.strip()
    source_files = ["scripts/verify_o10_live.py", "scripts/o10.py",
                    "scripts/okernel_unified_world.py", "scripts/verify_okernel_unified_provider.py",
                    "ocore/runtime/common/o10_codec.oc", "ocore/runtime/common/o10_executor.oc",
                    "ocore/runtime/aarch64/unified_world.oc"]
    source_hashes = {name: fingerprint(ROOT / name) for name in source_files}
    record = {"schema": "ostadix.o10-live-component/v1", "milestone": "M0",
              "gate_id": "verify_o10_live", "ok": False, "full_milestone_qualified": False,
              "started": time.time(), "source_revision": source_revision,
              "mcp_release": mcp_release, "host": os.uname().nodename,
              "state": str(state), "build": str(build), "output": str(output),
              "command": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
              "monitor_sha256": profile["artifacts"]["monitor.elf"]["sha256"],
              "profile_sha256": fingerprint(build / "monitor-profile.json"),
              "source_sha256": source_hashes, "build_tools": profile.get("tools"),
              "checks": [], "exchanges": [],
              "scope": "live AArch64 QEMU/TCG preclaim legacy/O10 generation continuity, O10 host shim journal negative controls and Plan9 withdraw/restore/bind with surviving Linux shell; no physical hardware or later milestones; full M0 regression qualification remains separate"}
    domain = None

    def persist():
        result_path.write_text(json.dumps(record, indent=2) + "\n")

    def check(name):
        record["checks"].append(name)
        persist()

    def raw(frame, *, expected_type=None, expected_code=None):
        wire, reply = exchange_raw(domain, frame)
        record["exchanges"].append({"request_hex": frame.hex(), "reply_hex": wire.hex()})
        if expected_type:
            checked_equal(reply["type"], expected_type, "native reply type")
        if expected_code is not None:
            checked_equal(reply.get("code"), expected_code, "native error code")
        return wire, reply

    persist()
    try:
        domain = runner.UnifiedDomain(state, build, qemu, timeout=timeout)
        record["session"] = str(domain.session)
        # Preserve every runner-generated O10 frame and exact completion bytes.
        original_exchange = domain.o10_exchange
        def traced_exchange(frame, **options):
            reply = original_exchange(frame, **options)
            offset = runner.O10_PROFILE["completion"] - 0x40000000
            length, = struct.unpack("<I", os.pread(domain.ram, 4, offset))
            if not 7 <= length <= 512:
                raise RuntimeError("invalid traced completion")
            wire = os.pread(domain.ram, length, offset)
            checked_equal(o10.decode(wire), reply, "traced completion")
            record["exchanges"].append({"request_hex": frame.hex(), "reply_hex": wire.hex()})
            return reply
        domain.o10_exchange = traced_exchange
        domain.ready()
        domain.control_active = True
        if not domain.service or not domain.provider_ready:
            raise RuntimeError("both original guests and admitted provider must be ready")
        checked_equal(domain.legacy_control, False, "O10 path selected")
        checked_equal(domain.counters()["live_domains"], 3, "two live guests")
        record["qemu_argv"] = json.loads((domain.session / "argv.json").read_text()) if (domain.session / "argv.json").exists() else domain.record.get("argv")
        executable = shutil.which(qemu)
        if executable:
            record["qemu"] = {"path": executable, "sha256": fingerprint(executable),
                              "version": subprocess.run([executable, "--version"], capture_output=True,
                                                        text=True, check=True, timeout=10).stdout}
        domain.o10_version()
        checked_equal(domain.o10_epoch, 0, "fresh monitor unclaimed epoch")
        linux_handle = (1 << 32)
        legacy_old = domain.o10_plan9
        checked_equal(legacy_old, (1 << 32) | 1, "boot Plan9 generation one")
        linux_before = domain.o10_call("Tstat", dom=linux_handle)
        checked_equal(domain.o10_call("Tstat", dom=legacy_old)["dom"], legacy_old, "unclaimed old domain reference")
        token = secrets.token_hex(12)
        pid = "/tmp/o10-survivor-" + token
        domain.command("echo $$ > " + pid + "; awk '{print $22}' /proc/$$/stat > " + pid + ".start")
        domain.command("printf '%s\\n' BEFORE_" + token + " > /n/okernel/work/o10-survivor-" + token)
        # Names returned by read-only O10 must become stale when preclaim
        # rollback replaces their domain, just as they do on O10 replacement.
        legacy_service = dict(domain.service)
        domain.legacy_control = True
        if domain.guest_coordinator_online:
            domain.coordinator_update(state="recovering")
        domain.native_control(1)
        checked_equal(domain.counters()["live_domains"], 1, "legacy withdrawal preserves Linux")
        domain.service = {"generation": legacy_service["generation"], "instance": secrets.token_hex(16)}
        domain.provider_ready = False
        domain.native_control(2, domain.provider_bootstrap())
        wait_provider_ready(domain, timeout)
        stale_frame = o10.encode("Tstat", 21001, epoch=0, seq=0, dom=legacy_old)
        _, stale = raw(stale_frame, expected_type="Rerror", expected_code=o10.O10_ESTALE)
        checked_equal(stale["detail"], 2, "legacy restore advances domain generation")
        current = domain.o10_call("Tstat", dom=(2 << 32) | 1)
        checked_equal(current["dom"], (2 << 32) | 1, "legacy replacement current handle")
        domain.o10_plan9 = current["dom"]
        domain.legacy_control = False
        if domain.guest_coordinator_online:
            domain.coordinator_update(state="ready")
        record["preclaim_legacy"] = {"old_dom": legacy_old, "new_dom": current["dom"],
                                    "old_service": legacy_service, "new_service": dict(domain.service),
                                    "mailbox_operations": [1, 2], "old_handle_error": stale}
        check("preclaim-legacy-replacement-invalidates-issued-o10-handle")
        domain.o10_claim()
        plan9_handle = domain.o10_plan9
        plan9_before = domain.o10_call("Tstat", dom=plan9_handle)
        checked_equal(linux_before["type"], "Rstat", "Linux native observation")
        checked_equal(plan9_before["type"], "Rstat", "Plan9 native observation")
        check("both-guests-ready-and-governor-claim")

        tag = 31001
        def request(kind, *, epoch=None, seq=0, **fields):
            nonlocal tag
            tag += 1
            return o10.encode(kind, tag, epoch=domain.o10_epoch if epoch is None else epoch, seq=seq, **fields)

        raw(request("Tstat", dom=plan9_handle + (1 << 32)), expected_type="Rerror", expected_code=o10.O10_ESTALE)
        raw(request("Twithdraw", seq=domain.o10_sequence + 2, dom=plan9_handle, mode=0, deadline_ms=0),
            expected_type="Rerror", expected_code=o10.O10_ESEQ)
        raw(request("Twithdraw", epoch=domain.o10_epoch - 1, seq=domain.o10_sequence + 1,
                    dom=plan9_handle, mode=0, deadline_ms=0),
            expected_type="Rerror", expected_code=o10.O10_ENOTCURRENT)
        raw(struct.pack("<IBH", 7, 100, 32001), expected_type="Rerror", expected_code=o10.O10_EBADMSG)
        raw(struct.pack("<IBH", 6, 178, 32002), expected_type="Rerror", expected_code=o10.O10_EBADMSG)
        domain.o10_version()
        check("stale-handle-gap-stale-epoch-and-malformed-frames-fail-closed")

        if domain.guest_coordinator_online:
            domain.coordinator_update(state="recovering")
        trace_before = len(record["exchanges"])
        domain.native_control(1)
        withdrawal = [x for x in record["exchanges"][trace_before:]
                      if o10.decode(bytes.fromhex(x["request_hex"]))["type"] == "Twithdraw"]
        if len(withdrawal) != 1:
            raise RuntimeError("withdrawal did not use one real O10 mutation")
        item = withdrawal[0]
        frame = bytes.fromhex(item["request_hex"])
        original_reply = bytes.fromhex(item["reply_hex"])
        decoded = o10.decode(frame)
        replay, _ = raw(frame, expected_type="Rwithdraw")
        checked_equal(replay, original_reply, "byte-identical mutation retry")
        changed = dict(decoded)
        changed["mode"] ^= 1
        raw(o10.reencode(changed), expected_type="Rerror", expected_code=o10.O10_ESEQ)
        outcome = domain.o10_call("Toutcome", qseq=decoded["seq"])
        checked_equal(outcome["reply"], original_reply, "outcome journal exact reply")
        checked_equal(outcome["state"], 1, "applied outcome")
        checked_equal(domain.counters()["live_domains"], 1, "Linux survives withdrawal")
        linux_during = domain.o10_call("Tstat", dom=linux_handle)
        checked_equal(linux_during["dom"], linux_before["dom"], "Linux generation unchanged")
        domain.command("test \"$(cat " + pid + ")\" = $$ && test \"$(awk '{print $22}' /proc/$$/stat)\" = \"$(cat " + pid + ".start)\"")
        domain.command("printf '%s\\n' DURING_" + token + " >> /n/okernel/work/o10-survivor-" + token)
        check("withdraw-journal-retry-and-changed-body-rejection")
        check("linux-shell-pid-starttime-and-namespace-survive")

        previous_service = dict(domain.service)
        domain.service = {"generation": previous_service["generation"], "instance": secrets.token_hex(16)}
        domain.provider_ready = False
        domain.native_control(2, domain.provider_bootstrap())
        checked_equal(domain.o10_plan9, (3 << 32) | 1, "O10 restore advances generation two to three")
        raw(request("Tstat", dom=plan9_handle), expected_type="Rerror", expected_code=o10.O10_ESTALE)
        wait_provider_ready(domain, timeout)
        if domain.guest_coordinator_online:
            domain.coordinator_update(state="ready")
        checked_equal(domain.counters()["live_domains"], 3, "both guests live after restore")
        domain.command("test \"$(cat " + pid + ")\" = $$ && test \"$(awk '{print $22}' /proc/$$/stat)\" = \"$(cat " + pid + ".start)\"")
        invocation = submit(domain, ["/arm64/bin/echo", "O10_RESTORED_" + token])
        result, files = finished(domain, invocation, timeout=timeout)
        if not result.ok or files["stdout"] != ("O10_RESTORED_" + token + "\n").encode():
            raise RuntimeError("replacement original provider command failed")
        save_capture(output / "restored-provider", invocation, files)
        observed_types = {bytes.fromhex(x["request_hex"])[4] for x in record["exchanges"]
                          if len(bytes.fromhex(x["request_hex"])) >= 5}
        # The trace intentionally contains malformed frames and 9P type codes;
        # inspecting its type byte must not parse those negatives as valid O10.
        if o10.O10_TRESTORE not in observed_types or o10.O10_TBIND not in observed_types:
            raise RuntimeError("restore and explicit binding were not observed on the wire")
        record["lifecycle"] = {"old_dom": plan9_handle, "new_dom": domain.o10_plan9,
                               "old_service": previous_service, "new_service": domain.service}
        check("restore-new-generation-explicit-bind-and-original-provider-execution")
        domain.save()
        record["paired_save"] = domain.record.get("paired_snapshot") is True
        if not record["paired_save"]:
            raise RuntimeError("private fork paired save incomplete")
        if source_hashes != {name: fingerprint(ROOT / name) for name in source_files}:
            raise RuntimeError("source changed during live qualification")
        checked_equal(fingerprint(build / "monitor-profile.json"), record["profile_sha256"], "build profile unchanged")
        checked_equal(fingerprint(build / "monitor.elf"), record["monitor_sha256"], "monitor unchanged")
        check("private-fork-paired-save")
        record.update(ok=True, finished=time.time())
        print("O10 live component: PASS\nEvidence: " + str(result_path))
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if domain is not None:
            domain.close()
        persist()
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=240)
    parser.add_argument("--mcp-release", default="unknown-observed-current")
    args = parser.parse_args()
    try:
        verify(args.state.expanduser(), args.build.expanduser(), args.output.expanduser(),
               args.qemu, args.timeout, args.mcp_release)
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError) as error:
        print("O10 live component failed: " + str(error), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
