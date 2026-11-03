#!/usr/bin/env python3
"""Observe pinned supplied BusyBox cat after one injected sendfile error.

Three Linux-only cases use identical private regular-file bytes and pipe output:
unmodified control, first-sendfile ENOSYS, and first-sendfile EINVAL. Only the
specified operation/error/profile is qualified. No source attribution, native
ABI admission, O-core lowering, general fallback, EPIPE, cancellation or
performance claim follows. No VM or installed file is changed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

import trace_okernel_posix_baseline as baseline
from trace_okernel_posix_baseline import (
    ENVIRONMENT, dependencies, elf_identity, hex_string, identity,
    package_identity, parse_trace, save, summarize,
)

BUSYBOX = Path("/usr/bin/busybox")
STRACE = Path("/usr/bin/strace")
BINARY_SHA256 = "dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14"
HISTORICAL = Path("/home/ustad/.local/state/ostadix/okernel/posix-application-baseline-6cbe4e184d49be63/result.json")
HISTORICAL_SHA256 = "60b778fbe3ea0a54c985946d206c66a851825febf18eb611c7e549035e10f9c5"
PAYLOAD_SEED = b"ostadix-cat-sendfile-fallback-v1"
PAYLOAD_BLOCKS = 32768
PAYLOAD = b"".join(hashlib.sha256(PAYLOAD_SEED + index.to_bytes(8, "little")).digest()
                   for index in range(PAYLOAD_BLOCKS))
CASES = (("control", None), ("sendfile-enosys", "ENOSYS"), ("sendfile-einval", "EINVAL"))


def oracle() -> dict:
    return {"input_bytes": len(PAYLOAD), "input_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
            "input_generator": {"algorithm": "SHA-256 counter blocks", "seed_hex": PAYLOAD_SEED.hex(),
                                "counter_bytes": 8, "counter_endianness": "little", "blocks": PAYLOAD_BLOCKS},
            "expected_exit": 0, "expected_stdout_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
            "expected_stderr_hex": "", "stdin": "/dev/null", "stdout": "pipe", "stderr": "pipe",
            "input_type": "regular", "input_mode": "0400",
            "cases": [{"name": name, "injected_errno": error, "injection_when": 1 if error else None}
                      for name, error in CASES]}


def fd_argument(arguments: str, fd: int) -> bool:
    return re.match(r"^" + str(fd) + r"(?:<[^>]*>)?,", arguments) is not None


def controlled_sendfile(event: dict, fd: int) -> bool:
    return (event["name"] == "sendfile" and re.fullmatch(
        r"1(?:<[^>]*>)?,\s*" + str(fd) + r"(?:<[^>]*>)?,\s*NULL,\s*[0-9]+",
        event["arguments"]) is not None)


def run_case(output: Path, source: Path, name: str, injected_errno: str | None) -> dict:
    directory = output / name
    directory.mkdir(mode=0o700)
    traces = directory / "traces"
    traces.mkdir(mode=0o700)
    arguments = [str(BUSYBOX), "cat", "--", str(source)]
    command = [str(STRACE), "-ff", "-ttt", "-q", "-v", "-s", "0", "-xx", "-yy", "--kill-on-exit",
               "-o", str(traces / "process")]
    if injected_errno is not None:
        command += ["-e", "inject=sendfile:error=" + injected_errno + ":when=1"]
    command += ["--", *arguments]
    receipt = directory / "result.json"
    record = {"ok": False, "name": name, "argv": arguments, "tracer_argv": command,
              "environment": ENVIRONMENT, "cwd": str(directory), "input": identity(source),
              "input_metadata": {"mode": oct(stat.S_IMODE(source.stat().st_mode)),
                                 "regular": stat.S_ISREG(source.stat().st_mode)},
              "frozen_oracle": oracle(), "injected_errno": injected_errno,
              "status": "not-complete", "started": time.time()}
    save(receipt, record)
    try:
        try:
            outcome = subprocess.run(command, cwd=directory, env=ENVIRONMENT,
                                     stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        except subprocess.TimeoutExpired as error:
            (directory / "stdout.bin").write_bytes(error.stdout or b"")
            (directory / "stderr.bin").write_bytes(error.stderr or b"")
            raise
        (directory / "stdout.bin").write_bytes(outcome.stdout)
        (directory / "stderr.bin").write_bytes(outcome.stderr)
        record.update(actual_exit=outcome.returncode, stdout=identity(directory / "stdout.bin"),
                      stderr=identity(directory / "stderr.bin"))
        if outcome.returncode != 0 or outcome.stdout != PAYLOAD or outcome.stderr != b"":
            raise ValueError("actual exit/streams differ from the frozen binary oracle")
        events, processes = [], []
        paths = sorted(traces.glob("process.*"))
        if not paths or any(not path.name.rsplit(".", 1)[1].isdigit() for path in paths):
            raise ValueError("missing or malformed per-PID trace files")
        for path in paths:
            parsed = parse_trace(path.read_text(), int(path.name.rsplit(".", 1)[1]))
            processes.append({"trace": identity(path), "summary": summarize(parsed)})
            events.extend(parsed)
            path.chmod(0o400)
        save(directory / "events.json", {"events": events})
        record.update(events=identity(directory / "events.json"), processes=processes,
                      summary=summarize(events))
        starts = [event for event in events if event.get("name") == "execve"
                  and event["arguments"].startswith(hex_string(BUSYBOX) + ",") and event["return_value"] == 0]
        if len(starts) != 1:
            raise ValueError("trace does not bind one exact successful BusyBox exec")
        pid = starts[0]["pid"]
        ends = [event for event in events if event["pid"] == pid and event["kind"] in ("exit", "killed")]
        if len(ends) != 1 or ends[0].get("exit_status") != outcome.returncode:
            raise ValueError("traced termination does not match the actual command status")
        calls = [event for event in events if event["pid"] == pid and event["kind"] == "syscall"]
        opens = [event for event in calls if event["name"] in ("open", "openat", "openat2")
                 and hex_string(source) in event["arguments"] and event["return_value"] is not None
                 and event["return_value"] >= 0 and event["errno"] is None]
        if len(opens) != 1 or "O_RDONLY" not in opens[0]["arguments"]:
            raise ValueError("controlled input lacks one successful read-only open")
        fd = opens[0]["return_value"]
        copies = [event for event in calls if event["name"] == "sendfile"]
        if not copies or any(not controlled_sendfile(event, fd) for event in copies):
            raise ValueError("sendfile does not use the exact controlled input/output and NULL offset")
        injected = [event for event in events if "(INJECTED)" in (event.get("return_text") or "")]
        if injected_errno is None:
            if injected or any(event["errno"] is not None or event["return_value"] is None
                               or event["return_value"] < 0 for event in copies):
                raise ValueError("unmodified control was injected or sendfile failed")
            positive = [event["return_value"] for event in copies if event["return_value"] > 0]
            if sum(positive) != len(PAYLOAD) or copies[-1]["return_value"] != 0:
                raise ValueError("control sendfile byte sum/EOF differs from the frozen oracle")
            record["controlled_io"] = {"sendfile_returns": [event["return_value"] for event in copies],
                                       "sendfile_positive_bytes": sum(positive), "sendfile_eof": True}
        else:
            error = copies[0]
            if (len(injected) != 1 or injected[0] is not error or error["errno"] != injected_errno
                    or error["return_value"] != -1 or error["disposition"] != "error"):
                raise ValueError("first controlled sendfile lacks the one intended injected errno")
            later = calls[calls.index(error) + 1:]
            reads = [event for event in later if event["name"] == "read" and fd_argument(event["arguments"], fd)]
            writes = [event for event in later if event["name"] == "write" and fd_argument(event["arguments"], 1)]
            read_bytes = sum(event["return_value"] for event in reads if (event["return_value"] or 0) > 0)
            written_bytes = sum(event["return_value"] for event in writes if (event["return_value"] or 0) > 0)
            if (read_bytes != len(PAYLOAD) or written_bytes != len(PAYLOAD)
                    or not reads or reads[-1]["return_value"] != 0):
                raise ValueError("post-error read/write byte sums or input EOF differ from frozen oracle")
            record["controlled_io"] = {"injected_event": error,
                "sendfile_returns": [event["return_value"] for event in copies],
                "read_returns": [event["return_value"] for event in reads],
                "write_returns": [event["return_value"] for event in writes],
                "positive_read_bytes": read_bytes, "positive_write_bytes": written_bytes, "input_eof": True}
        record.update(ok=True, status="observed-supplied-binary-behavior", main_pid=pid,
                      input_fd=fd, output_byte_exact=True, finished=time.time())
    except BaseException as error:
        record.update(error=type(error).__name__ + ": " + str(error), status="failed")
        raise
    finally:
        save(receipt, record)
    return record


def collect(output: Path, report: dict) -> None:
    for path in (BUSYBOX, STRACE):
        if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode) or not os.access(path, os.X_OK):
            raise baseline.Unavailable("required regular installed executable unavailable: " + str(path))
    binary = identity(BUSYBOX)
    if binary["sha256"] != BINARY_SHA256:
        raise baseline.Unavailable("installed BusyBox differs from the exact supplied-binary pin")
    historical = identity(HISTORICAL)
    old = json.loads(HISTORICAL.read_bytes())
    if historical["sha256"] != HISTORICAL_SHA256 or old.get("ok") is not True or old["binary"]["sha256"] != BINARY_SHA256:
        raise baseline.Unavailable("historical Linux reference differs from its qualified supplied-binary pin")
    historical_copy = output / "historical-baseline.json"
    historical_copy.write_bytes(HISTORICAL.read_bytes())
    historical_copy.chmod(0o400)
    if identity(historical_copy)["sha256"] != HISTORICAL_SHA256:
        raise ValueError("historical reference changed during capture")
    report["historical_baseline"] = {"selected": historical, "captured": identity(historical_copy)}
    source_paths = (Path(__file__).resolve(), Path(baseline.__file__).resolve())
    report["sources"] = []
    for path in source_paths:
        selected = identity(path)
        captured = output / path.name
        captured.write_bytes(path.read_bytes())
        captured.chmod(0o400)
        copied = identity(captured)
        if any(copied[key] != selected[key] for key in ("bytes", "sha256")):
            raise ValueError("collector/parser source changed during capture")
        report["sources"].append({"selected": selected, "captured": copied})
    retained = output / "supplied-busybox"
    retained.write_bytes(BUSYBOX.read_bytes())
    retained.chmod(0o400)
    if identity(retained)["sha256"] != BINARY_SHA256:
        raise ValueError("supplied binary changed during evidence copy")
    elf = elf_identity(BUSYBOX)
    if elf["machine"] != 62 or not elf["linkage"].startswith("static"):
        raise ValueError("pinned binary is not the expected static x86-64 ELF profile")
    report.update(binary=binary, retained_binary=identity(retained), elf=elf,
                  package=package_identity(), dependencies=dependencies(elf),
                  tracer={**identity(STRACE), "version": baseline.probe([STRACE, "--version"])})
    source = output / "input.bin"
    source.write_bytes(PAYLOAD)
    source.chmod(0o400)
    input_identity = identity(source)
    if source.is_symlink() or not stat.S_ISREG(source.stat().st_mode) or stat.S_IMODE(source.stat().st_mode) != 0o400:
        raise ValueError("private input is not a regular read-only fixture")
    report["input"] = input_identity
    save(output / "result.json", report)
    for name, error in CASES:
        report["cases"].append(run_case(output, source, name, error))
        if identity(BUSYBOX) != binary or identity(source) != input_identity:
            raise ValueError("installed binary or private input changed during collection")
        save(output / "result.json", report)
    for item in report["sources"]:
        if identity(Path(item["selected"]["path"])) != item["selected"] or identity(Path(item["captured"]["path"])) != item["captured"]:
            raise ValueError("collector/parser source changed during collection")
    if identity(HISTORICAL) != historical or identity(historical_copy)["sha256"] != HISTORICAL_SHA256:
        raise ValueError("historical reference changed during collection")
    if identity(STRACE)["sha256"] != report["tracer"]["sha256"]:
        raise ValueError("tracer changed during collection")
    report.update(ok=True, status="observed-supplied-binary-behavior", installed_binary_unchanged=True,
                  finished=time.time())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new permanent private evidence directory")
    args = parser.parse_args()
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        parser.error("output must be a new directory")
    output.mkdir(mode=0o700, parents=True)
    report = {"schema": "ostadix.cat-sendfile-error-linux-reference/v1", "ok": False,
              "status": "not-complete", "started": time.time(), "scope": __doc__,
              "output": str(output), "host": {"uname": list(os.uname()), "python": sys.version},
              "frozen_oracle": oracle(), "cases": [],
              "historical_baseline_pin": {"path": str(HISTORICAL), "sha256": HISTORICAL_SHA256},
              "not_claimed": ["matching BusyBox/glibc source attribution", "source-built application", "native ABI or O-core lowering/admission",
                              "general fallback or POSIX coverage", "EPIPE or cancellation", "performance or memory efficiency"],
              "reproduce_argv": [sys.executable, "-B", str(Path(__file__).resolve()), "--output", "/path/to/new-private-evidence"]}
    save(output / "result.json", report)
    try:
        collect(output, report)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(ok=False, status="unavailable" if isinstance(error, baseline.Unavailable) else "failed",
                      error=type(error).__name__ + ": " + str(error))
        save(output / "result.json", report)
        print("Supplied BusyBox injected-sendfile reference: FAIL\n" + str(error)
              + "\nEvidence: " + str(output / "result.json"), file=sys.stderr)
        return 1
    save(output / "result.json", report)
    print("Supplied BusyBox injected-sendfile reference: PASS\nEvidence: " + str(output / "result.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
