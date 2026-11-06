#!/usr/bin/env python3
"""Measure actual original-service admission in one private original-9front VM.

The directory is the original filesystem, not the native O-core shared store.
This measures the service's scan/wake behavior; unified transport/CPU rates
require the separate coordinator acceptance. Every captured result is bound
to its exact request and validated after the private VM cleanly halts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(ROOT / "scripts"), str(Path(__file__).parent)]
import build_okernel_plan9_userland as builder
import protocol
from verify_console_coexistence import extract


CLIENT = r'''#include <u.h>
#include <libc.h>
static void fail(char *s){sysfatal("polling fixture: %s: %r",s);}
static uchar *load(char *name,long *length){
    Dir *d;uchar *p;int fd;
    fd=open(name,OREAD);if(fd<0)fail("open");d=dirfstat(fd);if(d==nil)fail("stat");
    *length=d->length;p=malloc(*length+1);if(p==nil)fail("alloc");
    if(readn(fd,p,*length)!=*length)fail("read");close(fd);free(d);return p;
}
static void save(char *name,void *p,long n){
    int fd;long m;
    fd=create(name,OWRITE,0644);if(fd<0)fail("create");
    while(n>0){m=write(fd,p,n);if(m<=0)fail("write");p=(uchar*)p+m;n-=m;}
    close(fd);
}
void main(int argc,char **argv){
    int i,fd;char req[64],sub[64],directory[512],target[560],staged[560],id[33];
    uchar *wire,*marker;long bytes,markerbytes;vlong before,started,done,deadline;
    if(argc!=2)exits("args");
    for(i=0;i<5;i++){
        /* Settle into maximum idle backoff before each independent trial. */
        sleep(1500+31*i);
        snprint(req,sizeof req,"/tmp/Q%03d.REQ",i);wire=load(req,&bytes);
        snprint(sub,sizeof sub,"/tmp/Q%03d.SUB",i);marker=load(sub,&markerbytes);
        if(bytes<112)fail("request");memmove(id,wire+56,32);id[32]=0;
        snprint(directory,sizeof directory,"%s/r%s",argv[1],id);
        fd=create(directory,OREAD,DMDIR|0755);if(fd<0)fail("request directory");close(fd);
        snprint(target,sizeof target,"%s/request",directory);save(target,wire,bytes);
        snprint(staged,sizeof staged,"%s/staged",directory);save(staged,marker,markerbytes);
        before=nsec();
        { Dir rename; nulldir(&rename);rename.name="submit";if(dirwstat(staged,&rename)<0)fail("submit"); }
        snprint(target,sizeof target,"%s/started",directory);deadline=before+10000000000LL;
        while(access(target,AEXIST)<0){if(nsec()>deadline)fail("admission watchdog");sleep(1);}
        started=nsec();snprint(target,sizeof target,"%s/done",directory);
        while(access(target,AEXIST)<0){if(nsec()>deadline)fail("completion watchdog");sleep(1);}
        done=nsec();print("%d %lld %lld\n",i,started-before,done-before);
        free(wire);free(marker);
    }
    exits(nil);
}
'''


def run(build: Path, output: Path, qemu: str, timeout: float) -> dict:
    if output.exists():
        raise ValueError("polling fixture output must be new")
    receipt_path = build / "result.json"
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("schema") != "ostadix.original9front-userland-builder/v1" or receipt.get("ok") is not True:
        raise ValueError("successful original userland build required")
    for identity in list(receipt["artifacts"].values()) + list(receipt["platform_artifacts"].values()):
        if builder.identity(Path(identity["path"])) != identity:
            raise ValueError("admitted original artifact changed")
    output.mkdir(parents=True)
    controllers = []
    (output / "controllers").mkdir()
    for path in (Path(__file__), Path(protocol.__file__), Path(builder.__file__),
                 Path(builder.original.__file__), ROOT / "ocore/guest/plan9/unified/verify_console_coexistence.py"):
        target = output / "controllers" / path.name
        shutil.copyfile(path, target)
        controllers.append({"original": builder.identity(path), "snapshot": builder.identity(target)})
    generation, instance = secrets.token_hex(8), secrets.token_hex(16)
    root, cwd = "/tmp/polling-service", "/tmp/polling-work"
    service = root + "/g" + generation + "/s" + instance
    inputs = {"USER.PAQ": Path(receipt["artifacts"]["USER.PAQ"]["path"])}
    (output / "POLL.C").write_text(CLIENT)
    inputs["POLL.C"] = output / "POLL.C"
    trials = []
    for index in range(5):
        request_id, token = secrets.token_hex(16), secrets.token_hex(12)
        wire = protocol.encode_request(generation, instance, request_id,
            ["/arm64/bin/echo", token], cwd=cwd, timeout_ms=5000)
        for suffix, content in (("REQ", wire), ("SUB", protocol.submit_marker(wire))):
            path = output / f"Q{index:03}.{suffix}"
            path.write_bytes(content); inputs[path.name] = path
        trials.append({"request_id": request_id, "token": token})
    script = ["#!/bin/rc", "rfork n", "fn fail { echo P9_POLL_FAILED $*; exit $\"* }", "@{", "rfork n",
        "mkdir -p /tmp/provider /tmp/captures " + cwd + " " + root + " || exit dirs",
        "paqfs -qav -m /tmp/provider /tmp/USER.PAQ || exit paq",
        "bind /tmp/provider/arm64 /arm64 || exit arch",
        "bind /tmp/provider/sys/include /sys/include || exit headers",
        "bind /tmp/provider/rc /rc || exit rc", "bind /arm64/bin /bin || exit bin",
        "/arm64/bin/7c -o /tmp/POLL.7 /tmp/POLL.C || exit compile",
        "/arm64/bin/7l -o /tmp/POLL /tmp/POLL.7 || exit link",
        "rc /rc/bin/okernel-start " + root + " " + generation + " " + instance + " || exit service",
        "while(! test -f " + service + "/ready) sleep 1",
        "/tmp/POLL " + service + " > /tmp/captures/timings || exit measure"]
    for index, trial in enumerate(trials):
        script += [f"mkdir /tmp/captures/q{index} || exit capture",
                   "cp " + service + "/r" + trial["request_id"] + f"/* /tmp/captures/q{index}/ || exit copy"]
    script += ["cp " + service + "/ready /tmp/captures/ready || exit ready",
        "cd /tmp || exit tmp", "tar c captures > CAPTURE.TAR || exit archive", "} || fail service $status",
        "9fs dos /dev/sdG0/data || fail exportmount", "cp /tmp/CAPTURE.TAR /n/dos/CAPTURE.TAR || fail export",
        "unmount /n/dos || fail unmount", "echo P9_POLL_PASS", "fshalt"]
    program = ("\n".join(script) + "\n").encode()
    (output / "VERIFY.RC").write_bytes(program)
    record = {"schema": "ostadix.original-plan9-polling-latency/v1", "ok": False,
        "scope": "actual original service over original private filesystem; no native transport or full-system efficiency claim",
        "builder_receipt": builder.identity(receipt_path), "service": receipt["artifacts"]["SERVICE"],
        "controllers": controllers, "generation": generation, "instance": instance}
    try:
        record["vm"] = builder.run_script_vm(output / "vm", Path(receipt["official_image"]["path"]),
            Path(receipt["artifacts"]["KERNEL.U"]["path"]), build, program, inputs, qemu, timeout, (b"P9_POLL_PASS",))
        archive = output / "CAPTURE.TAR"
        subprocess.run(["mcopy", "-i", str(output / "vm/transfer.fat"), "::/CAPTURE.TAR", str(archive)],
                       check=True, env=builder.original.MTOOLS_ENV)
        extract(archive, output)
        captures = output / "captures"
        if (captures / "ready").read_bytes() != protocol.ready_marker(generation, instance):
            raise ValueError("ready identity mismatch")
        timings = [line.split() for line in (captures / "timings").read_text().splitlines()]
        if len(timings) != len(trials):
            raise ValueError("missing or extra timing trial")
        for index, (trial, timing) in enumerate(zip(trials, timings)):
            if len(timing) != 3 or int(timing[0]) != index:
                raise ValueError("malformed timing trial")
            admitted, completed = map(int, timing[1:])
            if not 0 <= admitted <= completed <= 10_000_000_000:
                raise ValueError("invalid original-clock interval")
            folder = captures / f"q{index}"
            snapshot = {name: (folder / name).read_bytes() for name in protocol.REQUEST_FILES}
            expected = (output / f"Q{index:03}.REQ").read_bytes()
            if snapshot["request"] != expected or snapshot["submit"] != protocol.submit_marker(expected):
                raise ValueError("captured submission differs from exact request")
            result = protocol.validate_result(expected, snapshot["result"], snapshot["stdout"], snapshot["stderr"],
                started=snapshot["started"], done=snapshot["done"], status=snapshot["status"])
            if not result.ok or result.flags or snapshot["stdout"] != (trial["token"] + "\n").encode() or snapshot["stderr"]:
                raise ValueError("original invocation result mismatch")
            trial.update(admission_guest_nanoseconds=admitted, completion_guest_nanoseconds=completed)
        for controller in controllers:
            if builder.identity(Path(controller["original"]["path"])) != controller["original"]:
                raise ValueError("fixture controller changed during qualification")
        record.update(ok=True, trials=trials, captures=builder.identity(archive))
        print("Original Plan9 polling latency: PASS\nEvidence: " + str(output / "result.json"), flush=True)
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
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    run(args.build.resolve(), args.output.resolve(), args.qemu, args.timeout)


if __name__ == "__main__":
    main()
