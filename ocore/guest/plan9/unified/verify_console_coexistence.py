#!/usr/bin/env python3
"""Exercise original console input and the resident worker in a private VM.

This gate uses the packaged original rc, compiler, linker and service. UART
bytes enter the guest console; no host process emulates their execution.
It does not qualify the coordinator's dual-domain console multiplexer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(ROOT / "scripts"), str(Path(__file__).parent)]
import build_okernel_plan9_userland as builder
import protocol


HELLO = b'''#include <u.h>
#include <libc.h>
void
main(void)
{
    char data[256];
    int n;
    print("P9_RESIDENT_NATIVE_HELLO\\n");
    while((n=read(0,data,sizeof data))>0)
        if(write(1,data,n)!=n) exits("stdout");
    exits(n<0 ? "stdin" : nil);
}
'''


def extract(archive: Path, output: Path) -> None:
    with tarfile.open(archive, "r:") as source:
        seen = set()
        for member in source:
            parts = Path(member.name).parts
            if (not parts or parts[0] != "captures" or ".." in parts
                    or member.name in seen or not (member.isfile() or member.isdir())):
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
                    raise ValueError("incomplete captured file")


def worker_fds(data: bytes) -> list[dict]:
    """Parse the pinned original procfdprint format, preserving path bytes."""
    lines = data.splitlines()
    if not lines:
        raise ValueError("missing original worker descriptor table")
    rows = []
    expression = rb"\s*(\d+)\s+([rw]{1,2})\s+\S+\s+-?\d+\s+\([0-9a-fA-F]+\s+\d+\s+[0-9a-fA-F]+\)\s+-?\d+\s+-?\d+\s+(.+)"
    for line in lines[1:]:
        match = re.fullmatch(expression, line)
        if match is None:
            raise ValueError("unexpected original procfdprint descriptor row")
        rows.append({"fd": int(match[1]), "mode": match[2].decode(), "path": match[3].decode()})
    descriptors = {row["fd"]: row for row in rows}
    if len(descriptors) != len(rows):
        raise ValueError("duplicate original worker descriptor")
    for fd, mode in ((0, "r"), (1, "w"), (2, "w")):
        row = descriptors.get(fd)
        if row is None or row["mode"] != mode or row["path"] not in ("/dev/null", "#c/null"):
            raise ValueError("original worker fd" + str(fd) + " does not identify isolated /dev/null")
    for row in rows:
        if re.search(r"(?:^|/)(?:cons(?:ctl)?|eia[^/]*|uart[^/]*)$", row["path"]):
            raise ValueError("worker retains inherited console descriptor: " + row["path"])
    return rows


def run(build: Path, output: Path, qemu: str, timeout: float) -> dict:
    if output.exists():
        raise ValueError("coexistence output must be new")
    receipt_path = build / "result.json"
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("schema") != "ostadix.original9front-userland-builder/v1" or receipt.get("ok") is not True:
        raise ValueError("successful original-userland build receipt required")
    for identity in list(receipt["artifacts"].values()) + list(receipt["platform_artifacts"].values()):
        if builder.identity(Path(identity["path"])) != identity:
            raise ValueError("admitted native artifact changed: " + identity["path"])
    output.mkdir(parents=True)
    controllers = []
    (output / "controllers").mkdir()
    for path in (Path(__file__), Path(protocol.__file__), Path(builder.__file__), Path(builder.original.__file__)):
        captured = output / "controllers" / path.name
        shutil.copyfile(path, captured)
        controllers.append({"original": builder.identity(path), "snapshot": builder.identity(captured)})
    generation, instance, request_id, token = secrets.token_hex(8), secrets.token_hex(16), secrets.token_hex(16), secrets.token_hex(12)
    service_root, cwd = "/tmp/coexist-service", "/tmp/coexist-work"
    service_dir = service_root + "/g" + generation + "/s" + instance
    request_dir = service_dir + "/r" + request_id
    stdin = b"resident-stdin\x00\xff\nkept-separate-from-console\n"
    console_read = ("console-read-" + token + "\n").encode()
    console_saved = ("console-saved-" + token).encode()
    command = ("objtype=arm64; /arm64/bin/7c -o HELLO.7 HELLO.C || exit compile; "
               "/arm64/bin/7l -o HELLO HELLO.7 || exit link; ./HELLO || exit hello; "
               "/bin/echo active > active; while(! test -f release) /bin/sleep 1; exit ''")
    wire = protocol.encode_request(generation, instance, request_id,
        ["/arm64/bin/rc", "-I", "-c", command], cwd=cwd, stdin=stdin, timeout_ms=60000)
    inputs = {"USER.PAQ": Path(receipt["artifacts"]["USER.PAQ"]["path"])}
    for name, data in (("HELLO.C", HELLO), ("REQUEST", wire), ("SUBMIT", protocol.submit_marker(wire))):
        path = output / name; path.write_bytes(data); inputs[name] = path
    marker_read = ("P9_COEX_UART_READ_" + token).encode()
    marker_shell = ("P9_COEX_UART_SHELL_" + token).encode()
    # Publish one complete rc command line, as the paced bootstrap does. A
    # burst of separate lines can overrun original console input while rc
    # starts an external command; this gate does not assume a terminal mux.
    shell_input = (" if(test -f " + request_dir + "/done) exit premature; "
                   "/bin/echo -n " + console_saved.decode() + " > /tmp/captures/console-saved; "
                   "/bin/echo release > " + cwd + "/release; exit ''\n").encode()
    script = ["#!/bin/rc", "rfork n", "fn fail { echo P9_COEX_FAILED $*; exit $\"* }", "@{", "rfork n",
        "mkdir -p /tmp/coexist-provider /tmp/captures " + cwd + " " + service_root + " || exit dirs",
        "paqfs -qav -m /tmp/coexist-provider /tmp/USER.PAQ || exit paq",
        "bind /tmp/coexist-provider/arm64 /arm64 || exit arch",
        "bind /tmp/coexist-provider/sys/include /sys/include || exit includes",
        "bind /tmp/coexist-provider/rc /rc || exit rc",
        "bind /arm64/bin /bin || exit bin",
        "cp /tmp/HELLO.C " + cwd + "/HELLO.C || exit source",
        "fn await { while(! test -f $1) sleep 1 }",
        "date -n > /tmp/captures/start-before || exit beforetime",
        "/arm64/bin/rc /rc/bin/okernel-start " + service_root + " " + generation + " " + instance + " || exit wrapper",
        "date -n > /tmp/captures/start-after || exit aftertime",
        "echo P9_COEX_WRAPPER_RETURNED", "await " + service_dir + "/ready",
        "cp " + service_dir + "/ready /tmp/captures/ready || exit readycapture",
        "workerargs=`{grep -l '^/arm64/bin/p9cmdsrv ' /proc/*/args}",
        "if(! ~ $#workerargs 1) exit workeridentity",
        "workerpid=`{echo $workerargs | sed 's,/proc/,,; s,/args,,'}",
        "echo $workerpid > /tmp/captures/worker-pid",
        "cp /proc/$workerpid/args /tmp/captures/worker-args || exit workerargs",
        "cp /proc/$workerpid/fd /tmp/captures/worker-fd || exit workerfds",
        "cp /rc/bin/okernel-start /tmp/captures/start.rc || exit startupcapture",
        "sha1sum -2 256 /arm64/bin/7c /arm64/bin/7l /arm64/bin/p9cmdsrv /arm64/bin/rc /arm64/bin/read > /tmp/captures/provider-tools || exit toolhashes",
        "mkdir " + request_dir + " || exit requestdir",
        "cp /tmp/REQUEST " + request_dir + "/request || exit requestcopy",
        "cp /tmp/SUBMIT " + request_dir + "/submit.pending || exit submitcopy",
        "mv " + request_dir + "/submit.pending " + request_dir + "/submit || exit submit",
        "await " + request_dir + "/started", "await " + cwd + "/active",
        "if(test -f " + request_dir + "/done) exit notactive",
        "if(! test -f /proc/$workerpid/status) exit workerdead",
        "echo " + marker_read.decode(),
        "/arm64/bin/read > /tmp/captures/console-read || exit consoleread",
        "if(test -f " + request_dir + "/done) exit inactiveafterread",
        "echo " + marker_shell.decode(), "/arm64/bin/rc -I || exit consoleshell",
        "await " + request_dir + "/done",
        "if(! test -f /proc/$workerpid/status) exit workerexited",
        "mkdir /tmp/captures/request || exit captures",
        "cp " + request_dir + "/* /tmp/captures/request/ || exit requestcapture",
        "cp " + cwd + "/HELLO " + cwd + "/HELLO.7 /tmp/captures/ || exit compiledcapture",
        "cp " + cwd + "/active /tmp/captures/active || exit activecapture",
        "echo -n kill > /proc/$workerpid/note || exit stopworker",
        "echo P9_COEX_NATIVE_PASS", "cd /tmp || exit tmp",
        "tar c captures > CAPTURE.TAR || exit archive", "} || fail native $status",
        "9fs dos /dev/sdG0/data || fail exportmount",
        "cp /tmp/CAPTURE.TAR /n/dos/CAPTURE.TAR || fail export",
        "unmount /n/dos || fail exportunmount", "echo P9_COEX_PASS", "fshalt"]
    program = ("\n".join(script) + "\n").encode()
    (output / "VERIFY.RC").write_bytes(program)
    record = {"schema": "ostadix.original-plan9-console-coexistence/v1", "ok": False,
        "scope": "actual original PAQ-only service/compiler and foreground rc over private QEMU UART; no coordinator mux qualification",
        "builder_receipt": builder.identity(receipt_path), "service": receipt["artifacts"]["SERVICE"],
        "controllers": controllers, "request": builder.identity(output / "REQUEST"),
        "hello_source": builder.identity(output / "HELLO.C"),
        "generation": generation, "instance": instance, "request_id": request_id}
    try:
        record["vm"] = builder.run_script_vm(output / "vm", Path(receipt["official_image"]["path"]),
            Path(receipt["artifacts"]["KERNEL.U"]["path"]), build, program, inputs, qemu, timeout,
            (b"P9_COEX_WRAPPER_RETURNED", marker_read, marker_shell, b"P9_COEX_NATIVE_PASS", b"P9_COEX_PASS"),
            console_exchanges=((marker_read, console_read), (marker_shell, shell_input)))
        archive = output / "CAPTURE.TAR"
        subprocess.run(["mcopy", "-i", str(output / "vm/transfer.fat"), "::/CAPTURE.TAR", str(archive)],
            check=True, env=builder.original.MTOOLS_ENV)
        extract(archive, output)
        capture = output / "captures"
        if (capture / "ready").read_bytes() != protocol.ready_marker(generation, instance):
            raise ValueError("readiness identity mismatch")
        if (capture / "start.rc").read_bytes() != (build / "inputs/START.RC").read_bytes():
            raise ValueError("executed startup differs from admitted wrapper")
        pid = (capture / "worker-pid").read_bytes().strip()
        if not pid.isdigit() or int(pid) <= 0:
            raise ValueError("invalid original service PID")
        arguments = (capture / "worker-args").read_bytes()
        expected_arguments = ("/arm64/bin/p9cmdsrv " + service_root + " " + generation + " " + instance).encode()
        if arguments not in (expected_arguments, expected_arguments + b"\n"):
            raise ValueError("worker arguments do not exactly bind this service instance")
        descriptors = worker_fds((capture / "worker-fd").read_bytes())
        selected = {item["guest_path"]: item["sha256"] for item in receipt["provider_files"]}
        hashes = builder.hash_listing((capture / "provider-tools").read_text())
        if set(hashes) != {"/arm64/bin/" + x for x in ("7c", "7l", "p9cmdsrv", "rc", "read")}:
            raise ValueError("native tool identity set incomplete")
        if any(selected[path] != digest for path, digest in hashes.items()):
            raise ValueError("executed original tool differs from PAQ provider")
        if (capture / "console-read").read_bytes() != console_read:
            raise ValueError("foreground read did not receive exact UART bytes")
        if (capture / "console-saved").read_bytes() != console_saved:
            raise ValueError("foreground rc did not save exact UART-command content")
        if (capture / "active").read_bytes() != b"active\n":
            raise ValueError("resident activity witness differs")
        request = capture / "request"
        if (request / "request").read_bytes() != wire:
            raise ValueError("captured request differs from admitted invocation")
        protocol.validate_submit(wire, (request / "submit").read_bytes())
        stdout, stderr = (request / "stdout").read_bytes(), (request / "stderr").read_bytes()
        result = protocol.validate_result(wire, (request / "result").read_bytes(), stdout, stderr,
            done=(request / "done").read_bytes(), started=(request / "started").read_bytes(),
            status=(request / "status").read_bytes())
        if result.flags or result.status or stderr or stdout != b"P9_RESIDENT_NATIVE_HELLO\n" + stdin:
            raise ValueError("resident original compile/run or isolated stdin differs")
        for controller in controllers:
            if builder.identity(Path(controller["original"]["path"])) != controller["original"]:
                raise ValueError("coexistence controller changed during execution")
        before, after = (int((capture / name).read_text()) for name in ("start-before", "start-after"))
        record.update(ok=True, captures=builder.identity(archive), worker_pid=int(pid),
            worker_descriptors=descriptors, wrapper_return_elapsed_guest_seconds=after-before,
            result=builder.identity(request / "result"), compiled_hello=builder.identity(capture / "HELLO"),
            checks=["packaged startup returned while original resident worker remained alive",
                    "original /proc fd table identifies worker fd0/1/2 as /dev/null and no additional console descriptor",
                    "foreground original read received exact real-UART input while resident invocation remained active",
                    "foreground original rc executed real-UART commands and saved exact bytes",
                    "resident invocation compiled/linked/executed hello with admitted PAQ-only 7c/7l/libc",
                    "resident protocol stdin remained byte-exact and separate from console input",
                    "worker remained alive after command completion; private VM halted cleanly"])
        print("Original Plan9 console/resident coexistence: PASS\nEvidence: " + str(output / "result.json"), flush=True)
        return record
    except BaseException as error:
        record["error"] = str(error)
        raise
    finally:
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    run(args.build.resolve(), args.output.resolve(), args.qemu, args.timeout)


if __name__ == "__main__":
    main()
