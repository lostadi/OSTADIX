#!/usr/bin/env python3
"""Qualify the resident service in a fresh original-9front private VM.

This exercises actual original executables and their ABI on a private original
filesystem. Simultaneous domains and the native shared transport require the
coordinator's separate integration gate; this verifier makes neither claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts"), str(Path(__file__).parent)]
import build_okernel_plan9_userland as builder
import protocol
from tests import plan9_command_runtime_cases as cases


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def run(build: Path, output: Path, qemu: str, timeout: float, receipt_path: Path | None = None, profile: str = "foreground", timeout_case: str = "timeout", cancel_case: str = "cancel_in_flight") -> dict:
    if output.exists():
        raise ValueError("verification output must be new")
    receipt_path = receipt_path or build / "result.json"
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("schema") != "ostadix.original9front-userland-builder/v1" or receipt.get("ok") is not True:
        raise ValueError("a successful original-userland builder receipt is required")
    for identity in list(receipt["artifacts"].values()) + list(receipt["platform_artifacts"].values()):
        actual = builder.identity(Path(identity["path"]))
        if actual != identity:
            raise ValueError("admitted builder artifact changed: " + identity["path"])
    output.mkdir(parents=True)
    source_dir = output / "controllers"
    source_dir.mkdir()
    controllers = []
    for path in (Path(__file__), Path(protocol.__file__), Path(cases.__file__),
                 Path(builder.__file__), Path(builder.original.__file__)):
        captured = source_dir / path.name
        shutil.copyfile(path,captured)
        controllers.append({"original":builder.identity(path),"snapshot":builder.identity(captured)})
    generation, instance = secrets.token_hex(8), secrets.token_hex(16)
    service_root, cwd = "/tmp/p9-command-root", "/tmp/p9-command-work"
    manifest = cases.prepare(output / "fixtures", generation, instance, cwd)
    interrupted = protocol.FLAG_TIMEOUT | protocol.FLAG_CANCELLED
    stop_profile = profile in ("timeout-stop", "cancel-stop")
    if profile == "timeout-stop":
        manifest["cases"] = [case for case in manifest["cases"] if case["name"] == timeout_case]
        if len(manifest["cases"]) != 1 or not manifest["cases"][0]["flags"] & protocol.FLAG_TIMEOUT:
            raise ValueError("timeout-stop requires one original timeout fixture")
        manifest["scope"] = "timed-out service stops accepting work and requests domain recovery; no descendant cleanup claim"
        (output / "fixtures/cases.json").write_text(json.dumps(manifest,indent=2)+"\n")
    if profile == "cancel-stop":
        manifest["cases"] = [case for case in manifest["cases"] if case["name"] == cancel_case]
        if len(manifest["cases"]) != 1 or not manifest["cases"][0]["flags"] & protocol.FLAG_CANCELLED:
            raise ValueError("cancel-stop requires one original cancellation fixture")
        manifest["scope"] = "request-bound invocation cancellation stops admission and requests domain recovery; no PTY or descendant cleanup claim"
        (output / "fixtures/cases.json").write_text(json.dumps(manifest,indent=2)+"\n")
    if profile == "foreground":
        excluded = [case["name"] for case in manifest["cases"] if case["flags"] & interrupted]
        manifest["cases"] = [case for case in manifest["cases"] if case["name"] not in excluded]
        manifest["explicitly_excluded"] = excluded
        manifest["scope"] = "foreground command/stream/error/non-replay and invalid-cancellation checks; interruption cleanup unqualified"
        (output / "fixtures/cases.json").write_text(json.dumps(manifest,indent=2)+"\n")
    inputs = {"USER.PAQ": Path(receipt["artifacts"]["USER.PAQ"]["path"]),
              "CWD.BIN": output / "fixtures/cwd-proof.bin"}
    service_dir = service_root + "/g" + generation + "/s" + instance
    script = ["#!/bin/rc", "rfork n", "fn fail { echo P9_RUNTIME_FAILED $*; exit $\"* }",
              "@{", "rfork n", "mkdir -p /tmp/p9-provider " + cwd + " " + service_root + " /tmp/captures || exit dirs",
              "paqfs -qav -m /tmp/p9-provider /tmp/USER.PAQ || exit paq",
              "bind /tmp/p9-provider/arm64 /arm64 || exit arch",
              "bind /tmp/p9-provider/sys/include /sys/include || exit includes",
              "bind /tmp/p9-provider/rc /rc || exit rc",
              "bind /arm64/bin /bin || exit bin",
              "cp /tmp/CWD.BIN " + cwd + "/cwd-proof.bin || exit cwdproof",
              "fn await { while(! test -f $1) sleep 1 }",
              f"/arm64/bin/p9cmdsrv {service_root} {generation} {instance} > /tmp/SERVICE.LOG >[2=1] &",
              "servicepid=$apid", "await " + service_dir + "/ready",
              "cp " + service_dir + "/ready /tmp/captures/ready || exit readycapture",
              "echo P9_RUNTIME_READY"]
    for index, case in enumerate(manifest["cases"]):
        folder = output / "fixtures" / case["directory"]
        req, sub = f"Q{index:03}.REQ", f"Q{index:03}.SUB"
        inputs[req], inputs[sub] = folder / "request", folder / "submit"
        directory = service_dir + "/r" + case["request_id"]
        script += ["mkdir " + directory + " || exit requestdir",
                   f"cp /tmp/{req} {directory}/request || exit requestcopy"]
        cancel = case.get("cancel")
        if cancel:
            name = f"Q{index:03}.CAN"
            inputs[name] = folder / "cancel"
            if cancel["timing"] == "before_submit":
                script += [f"cp /tmp/{name} {directory}/cancel-staged || exit precancelcopy",
                           f"mv {directory}/cancel-staged {directory}/cancel || exit precancel"]
        script += [
                   f"cp /tmp/{sub} {directory}/staged || exit commitcopy",
                   f"mv {directory}/staged {directory}/submit || exit commit"]
        if cancel and cancel["timing"] == "after_ready":
            script += ["await " + directory + "/started", "await " + cancel["ready_path"],
                       "await " + cancel["pid_path"],
                       # The command itself writes this proof after producing
                       # its expected streams, before blocking in sleep.
                       "sleep 1", f"cp /tmp/{name} {directory}/cancel-staged || exit cancelcopy",
                       "if(test -f " + directory + "/done) exit commandcompletedbeforecancel",
                       "commandpid=`{cat " + cancel["pid_path"] + "}",
                       "if(! test -f /proc/$commandpid/status) exit commandexitedbeforecancel",
                       f"mv {directory}/cancel-staged {directory}/cancel || exit cancelpublish"]
        script += ["await " + directory + "/done",
                   "mkdir /tmp/captures/" + case["name"] + " || exit capturedir",
                   "cp " + directory + "/* /tmp/captures/" + case["name"] + "/ || exit capture"]
        if cancel and cancel["timing"] == "after_ready":
            script += ["cp " + cancel["ready_path"] + " /tmp/captures/" + case["name"] + "/launch-proof || exit launchproof",
                       "cp " + cancel["pid_path"] + " /tmp/captures/" + case["name"] + "/command-pid || exit pidproof"]
        if cancel and cancel.get("must_remain_absent"):
            script += ["if(test -f " + cancel["must_remain_absent"] + ") exit cancelledcommandlaunched"]
        script += ["echo P9_RUNTIME_CASE " + case["name"]]
    replacement = None
    if not stop_profile:
        once_index, once = next((i,c) for i,c in enumerate(manifest["cases"]) if c["name"] == "admission_once")
        directory = service_dir + "/r" + once["request_id"]
        counter = cwd + "/admission-count"
        if profile == "full":
            script += ["sleep 4", "if(test -f " + cwd + "/background-must-not-write) exit backgroundleak"]
        script += [
                   "cp " + counter + " /tmp/COUNT.FIRST || exit count",
                   # Duplicate existing publication, then erase all persisted claims
                   # and resubmit the same ID: the live accepted ledger must win.
                   "sleep 1", "rm -r " + directory + " || exit cleanup",
                   "mkdir " + directory + " || exit replaydir",
                   f"cp /tmp/Q{once_index:03}.REQ " + directory + "/request || exit replayrequest",
                   f"cp /tmp/Q{once_index:03}.SUB " + directory + "/submit || exit replaysubmit",
                   "sleep 1", "if(test -f " + directory + "/started) exit replayed",
                   "if(! ~ `{cat " + counter + "} once) exit countchanged"]
        # Closed but incomplete publications and stale identities cannot dispatch.
        bad = []
        for index, kind in enumerate(("unpublished", "partial", "old_generation", "old_instance", "claimed")):
            request_id = secrets.token_hex(16)
            g = secrets.token_hex(8) if kind == "old_generation" else generation
            s = secrets.token_hex(16) if kind == "old_instance" else instance
            wire = protocol.encode_request(g, s, request_id,
                ["/bin/rc", "-I", "-c", "/bin/echo forbidden >> " + cwd + "/forbidden"], cwd=cwd)
            req_path, sub_path = output / f"N{index:03}.REQ", output / f"N{index:03}.SUB"
            req_path.write_bytes(wire)
            marker = protocol.submit_marker(wire)
            sub_path.write_bytes(marker[:-1] if kind == "partial" else marker)
            inputs[req_path.name], inputs[sub_path.name] = req_path, sub_path
            directory = service_dir + "/r" + request_id
            bad.append((kind, directory))
            script += ["mkdir " + directory + " || exit negativepath",
                       "cp /tmp/" + req_path.name + " " + directory + "/request || exit negativerequest"]
            if kind == "claimed":
                script += ["echo partialclaim > " + directory + "/started || exit claim"]
            if kind != "unpublished":
                script += ["cp /tmp/" + sub_path.name + " " + directory + "/submit || exit negativecommit"]
        script += ["sleep 1", "if(test -f " + cwd + "/forbidden) exit forbiddeneffect"]
        script += ["if(test -f " + directory + "/started) exit negativeadmission" for kind, directory in bad if kind != "claimed"]
        script += ["echo -n kill > /proc/$servicepid/note || exit stopservice", "sleep 1",
                   f"if(/arm64/bin/p9cmdsrv {service_root} {generation} {instance}) exit reusedinstance"]
        # A fresh process identity does not adopt any old pending request.
        replacement = secrets.token_hex(16)
        newdir = service_root + "/g" + generation + "/s" + replacement
        script += [f"/arm64/bin/p9cmdsrv {service_root} {generation} {replacement} >> /tmp/SERVICE.LOG >[2=1] &",
                   "replacementpid=$apid", "await " + newdir + "/ready",
                   "cp " + newdir + "/ready /tmp/captures/replacement-ready || exit replacementready", "sleep 1",
                   "if(test -f " + cwd + "/forbidden) exit restartreplay",
                   "if(! ~ `{cat " + counter + "} once) exit restartcount",
                   "echo -n kill > /proc/$replacementpid/note || exit stopreplacement"]
    else:
        entry = manifest["cases"][0]
        request_dir = service_dir + "/r" + entry["request_id"]
        script += ["await " + service_dir + "/reset-required",
                   "cp " + service_dir + "/reset-required /tmp/captures/reset-required || exit resetcapture"]
        later_id = secrets.token_hex(16)
        later = protocol.encode_request(generation,instance,later_id,
            ["/bin/rc","-I","-c","/bin/echo forbidden > " + cwd + "/after-interruption"],cwd=cwd)
        (output / "LATER.REQ").write_bytes(later)
        (output / "LATER.SUB").write_bytes(protocol.submit_marker(later))
        inputs["LATER.REQ"],inputs["LATER.SUB"] = output / "LATER.REQ",output / "LATER.SUB"
        later_dir = service_dir + "/r" + later_id
        script += ["mkdir " + later_dir + " || exit laterdir",
                   "cp /tmp/LATER.REQ " + later_dir + "/request || exit laterrequest",
                   "cp /tmp/LATER.SUB " + later_dir + "/submit || exit latercommit", "sleep 1",
                   "if(test -f " + later_dir + "/started) exit interruptedacceptedmore",
                   "if(test -f " + cwd + "/after-interruption) exit interruptedsideeffect",
                   "if(test -f /proc/$servicepid/status) exit interruptedservicestillrunning"]
    script += ["echo P9_RUNTIME_LIFECYCLE_PASS", "cd /tmp || exit capturecwd",
               "tar c captures > CAPTURE.TAR || exit archive", "} || fail originalservice $status",
               "9fs dos /dev/sdG0/data || fail exportmount",
               "cp /tmp/CAPTURE.TAR /n/dos/CAPTURE.TAR || fail export",
               "cp /tmp/SERVICE.LOG /n/dos/SERVICE.LOG || fail log",
               "unmount /n/dos || fail exportunmount", "echo P9_RUNTIME_PASS", "fshalt"]
    program = ("\n".join(script) + "\n").encode()
    (output / "VERIFY.RC").write_bytes(program)
    record = {"schema": "ostadix.original-plan9-command-runtime/v1", "ok": False,
              "scope": "actual original Plan9 command service/rc/tools in isolated original QEMU VM; private filesystem, not unified shared-transport acceptance",
              "controllers":controllers, "profile":profile, "explicitly_excluded":manifest.get("explicitly_excluded",[]),
              "builder_receipt": builder.identity(receipt_path), "generation": generation,
              "instance": instance, "replacement_instance": replacement,
              "service": receipt["artifacts"]["SERVICE"], "fixtures": builder.identity(output / "fixtures/cases.json")}
    try:
        vm = builder.run_script_vm(output / "vm", Path(receipt["official_image"]["path"]),
            Path(receipt["artifacts"]["KERNEL.U"]["path"]), build, program, inputs,
            qemu, timeout, (b"P9_RUNTIME_READY", b"P9_RUNTIME_LIFECYCLE_PASS", b"P9_RUNTIME_PASS"))
        record["vm"] = vm
        archive = output / "CAPTURE.TAR"
        for name in ("CAPTURE.TAR", "SERVICE.LOG"):
            subprocess.run(["mcopy", "-i", str(output / "vm/transfer.fat"), "::/" + name, str(output / name)],
                           check=True, env=builder.original.MTOOLS_ENV)
        with tarfile.open(archive, "r:") as source:
            seen = set()
            for member in source:
                parts = Path(member.name).parts
                if (not parts or parts[0] != "captures" or ".." in parts or member.name in seen
                        or not (member.isfile() or member.isdir())):
                    raise ValueError("unsafe or duplicate capture archive member")
                seen.add(member.name)
                target = output / member.name
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with source.extractfile(member) as incoming, target.open("xb") as outgoing:
                        shutil.copyfileobj(incoming, outgoing)
                    if target.stat().st_size != member.size:
                        raise ValueError("incomplete capture")
        if (output / "captures/ready").read_bytes() != protocol.ready_marker(generation,instance):
            raise ValueError("initial readiness did not bind this generation/instance")
        if replacement is not None and (output / "captures/replacement-ready").read_bytes() != protocol.ready_marker(generation,replacement):
            raise ValueError("restart readiness did not bind its fresh instance")
        results = [cases.verify_case(output / "fixtures", output / "captures", entry) for entry in manifest["cases"]]
        if stop_profile:
            entry = manifest["cases"][0]
            protocol.validate_reset((output / "fixtures" / entry["name"] / "request").read_bytes(),
                (output / "captures" / entry["name"] / "result").read_bytes(),
                (output / "captures/reset-required").read_bytes())
        for source in controllers:
            if builder.identity(Path(source["original"]["path"])) != source["original"]:
                raise ValueError("runtime validation controller changed during execution")
        record.update(ok=True, cases=results, captures=builder.identity(archive),
            lifecycle_checks=(["background descendant killed before delayed write"] if profile == "full" else []) + ["accepted ID not replayed after persistent claim cleanup",
                              "unpublished/partial/stale-generation/stale-instance/preclaimed requests never executed",
                              "reused service instance rejected", "fresh service restart did not replay old requests"])
        if stop_profile:
            record["lifecycle_checks"] = ["interruption recovery marker binds exact request/result", "service exits and does not admit subsequent work"]
            if profile == "cancel-stop":
                record["lifecycle_checks"].append("exact request-bound cancel marker captured and validated")
                record["lifecycle_checks"].append("pre-cancel command effect absent" if manifest["cases"][0]["cancel"]["timing"] == "before_submit" else "command wrote execution/PID witnesses and remained alive without done immediately before cancel publication")
            record["remaining"] = ["coordinator must recycle owning Plan9 domain before exposing interrupted completion or accepting another invocation", "no descendant cleanup guarantee from this userland gate", "invocation cancellation only; no PTY job control"]
        print("Original Plan9 command service runtime: PASS\nEvidence: " + str(output / "result.json"), flush=True)
        return record
    except BaseException as error:
        record["error"] = str(error)
        raise
    finally:
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--profile", choices=("full","foreground","timeout-stop","cancel-stop"), default="foreground")
    parser.add_argument("--timeout-case", choices=("timeout","truncation_then_timeout","background_timeout"), default="timeout")
    parser.add_argument("--cancel-case", choices=("cancel_in_flight","cancel_before_submit","truncation_then_cancel"), default="cancel_in_flight")
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    run(args.build.resolve(), args.output.resolve(), args.qemu, args.timeout, args.receipt.resolve() if args.receipt else None, args.profile, args.timeout_case, args.cancel_case)


if __name__ == "__main__":
    main()
