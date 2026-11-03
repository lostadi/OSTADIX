#!/usr/bin/env python3
"""Observe unchanged installed BusyBox cat behavior on controlled Linux inputs.

This supplies functional/syscall requirements evidence only. The installed
binary is not source-built, lowered through O-core, or admitted as an O-core
application. Observed calls are not complete POSIX coverage or proof that
unobserved calls are unnecessary. strace overhead is not a performance result.
No host installation, VM operation, runtime change or user input file is used.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import subprocess
import sys

SCHEMA = "ostadix.posix-application-linux-trace/v1"
BUSYBOX = Path("/usr/bin/busybox")
STRACE = Path("/usr/bin/strace")
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"}
FILE_IO = {"open", "openat", "openat2", "read", "readv", "pread64", "write", "writev", "pwrite64",
           "lseek", "fstat", "newfstatat", "statx", "close", "ioctl", "sendfile", "copy_file_range",
           "splice", "vmsplice", "tee"}


class TraceError(ValueError):
    pass


class Unavailable(RuntimeError):
    pass


def identity(path):
    path = Path(path)
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            value.update(block)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": value.hexdigest()}


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def balanced(arguments):
    stack, quote, escaped, annotation = [], False, False, False
    pairs = {")": "(", "]": "[", "}": "{"}
    for char in arguments:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == '"':
                quote = False
            continue
        if annotation:
            if char == ">":
                annotation = False
            continue
        if char == '"':
            quote = True
        elif char == "<":
            annotation = True  # -yy file-descriptor annotations are opaque.
        elif char in "([{":
            stack.append(char)
        elif char in ")]}" and (not stack or stack.pop() != pairs[char]):
            raise TraceError("unbalanced syscall arguments")
    if stack or quote or escaped or annotation:
        raise TraceError("incomplete syscall arguments")


def return_result(text):
    match = re.match(r"^(\?|(?:-?0x[0-9a-fA-F]+)|(?:-?[0-9]+))(?=$|\s|<)", text)
    if match is None:
        raise TraceError("unrecognized syscall return: " + text[:120])
    number = match[1]
    value = None
    if number != "?":
        unsigned = number.lstrip("-")
        base = 16 if unsigned.startswith("0x") else 8 if len(unsigned) > 1 and unsigned.startswith("0") and set(unsigned) <= set("01234567") else 10
        value = int(number, base)
    errno = re.match(r"^\s+(E[A-Z0-9_]+)(?:\s|$)", text[match.end():])
    error = errno[1] if errno else None
    suffix = text[match.end():].strip()
    if error:
        if not re.fullmatch(r"E[A-Z0-9_]+(?: \(.*\))?", suffix):
            raise TraceError("malformed syscall errno suffix")
    elif suffix:
        if suffix.startswith("(") and suffix.endswith(")"):
            balanced(suffix)
        elif not (suffix.startswith("<") and suffix.endswith(">")):
            raise TraceError("unrecognized syscall return suffix")
    return {"return_text": text, "return_value": value, "errno": error,
            "disposition": "interrupted-restart" if error and error.startswith("ERESTART")
            else "error" if error else "nonreturning" if value is None else "returned"}


def parse_trace(text, default_pid=None):
    """Parse complete PID streams; retain raw argument/return text losslessly."""
    pending, events, terminal, observed, no_return = {}, [], set(), set(), {}
    for number, original in enumerate(text.splitlines(), 1):
        line = original.strip()
        if not line:
            continue
        pid = default_pid
        match = re.match(r"^\[pid\s+(\d+)\]\s+", line) or re.match(r"^(\d+)\s+", line)
        if match:
            pid = int(match[1])
            line = line[match.end():]
        if type(pid) is not int or pid <= 0:
            raise TraceError("trace line lacks a positive PID")
        timestamp = re.match(r"^(\d+\.\d+)\s+", line)
        stamp = timestamp[1] if timestamp else None
        if timestamp:
            line = line[timestamp.end():]
        if pid in terminal:
            raise TraceError("trace continues after process termination")
        observed.add(pid)
        metadata = {"pid": pid, "timestamp": stamp, "line": number, "raw": [original]}
        exit_ = re.fullmatch(r"\+\+\+ exited with (\d+) \+\+\+", line)
        killed = re.fullmatch(r"\+\+\+ killed by (SIG[A-Z0-9]+)(?: \(core dumped\))? \+\+\+", line)
        if exit_ or killed:
            if pid in no_return and no_return[pid]["name"] not in ("exit", "exit_group"):
                if not killed:
                    raise TraceError("unknown return for an ordinarily returning syscall")
                no_return[pid]["disposition"] = "unavailable-at-termination"
            if pid in pending:
                entry = pending.pop(pid)
                events.append({**entry, "kind": "syscall", "return_text": None, "return_value": None,
                               "errno": None, "disposition": "unfinished-at-termination",
                               "finished_timestamp": stamp, "raw": entry["raw"] + [original]})
            value = {**metadata, "kind": "exit" if exit_ else "killed"}
            if exit_:
                value["exit_status"] = int(exit_[1])
                if value["exit_status"] > 255:
                    raise TraceError("invalid process exit status")
            else:
                value["signal"] = killed[1]
            events.append(value)
            terminal.add(pid)
            continue
        signal = re.match(r"^--- (SIG[A-Z0-9]+) (.*) ---$", line)
        if signal:
            events.append({**metadata, "kind": "signal", "signal": signal[1], "details": signal[2]})
            continue
        unfinished = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\((.*)<unfinished \.\.\.>", line)
        if unfinished:
            if pid in pending or pid in no_return:
                raise TraceError("nested unfinished syscall for one PID")
            pending[pid] = {**metadata, "name": unfinished[1], "arguments": unfinished[2]}
            continue
        resumed = re.fullmatch(r"<\.\.\. ([A-Za-z_][A-Za-z0-9_]*) resumed>(.*)", line)
        if resumed:
            if pid not in pending or pending[pid]["name"] != resumed[1]:
                raise TraceError("resumed syscall has no matching PID/name entry")
            entry = pending.pop(pid)
            line = entry["name"] + "(" + entry["arguments"] + resumed[2]
            metadata.update(timestamp=entry["timestamp"], finished_timestamp=stamp,
                            raw=entry["raw"] + [original], resumed=True)
        elif pid in pending:
            raise TraceError("new syscall precedes pending PID's resumed return")
        if pid in no_return:
            raise TraceError("new syscall follows an unavailable/nonreturning result")
        call = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s+=\s+(.+)", line)
        if call is None:
            raise TraceError("malformed/diagnostic trace line " + str(number) + ": " + line[:160])
        balanced(call[2])
        event = {**metadata, "kind": "syscall", "name": call[1], "arguments": call[2],
                 **return_result(call[3])}
        events.append(event)
        if event["disposition"] == "nonreturning":
            no_return[pid] = event
    if pending or observed != terminal or not observed:
        raise TraceError("trace is incomplete: every PID needs a terminal record and no pending call")
    return events


def summarize(events):
    calls = [event for event in events if event["kind"] == "syscall"]
    return {"syscalls": dict(sorted(Counter(event["name"] for event in calls).items())),
            "errnos": dict(sorted(Counter(event["errno"] for event in calls if event["errno"]).items())),
            "dispositions": dict(sorted(Counter(event["disposition"] for event in calls).items())),
            "syscall_entries": len(calls), "signals": sum(event["kind"] == "signal" for event in events),
            "process_exits": [event for event in events if event["kind"] in ("exit", "killed")]}


def elf_identity(path):
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("baseline requires an installed ELF64 little-endian executable")
    kind, machine = struct.unpack_from("<HH", data, 16)
    phoff = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size != 56 or phoff + count * size > len(data):
        raise ValueError("invalid installed ELF program headers")
    headers = [struct.unpack_from("<IIQQQQQQ", data, phoff + index * size) for index in range(count)]
    interpreter, tags = None, {}
    needed = []
    for header in headers:
        typ, _, offset, _, _, length, _, _ = header
        if offset + length > len(data):
            raise ValueError("ELF segment escaped installed file")
        if typ == 3:
            raw = data[offset:offset + length]
            if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
                raise ValueError("invalid ELF interpreter")
            interpreter = raw[:-1].decode()
        if typ == 2:
            for at in range(offset, offset + length, 16):
                tag, value = struct.unpack_from("<qQ", data, at)
                if tag == 0:
                    break
                if tag == 1:
                    needed.append(value)
                else:
                    tags[tag] = value
    names = []
    if needed:
        address, length = tags[5], tags[10]
        matches = [h for h in headers if h[0] == 1 and h[3] <= address and address + length <= h[3] + h[5]]
        if len(matches) != 1:
            raise ValueError("ELF dynamic string table is not retained in one load segment")
        start = matches[0][2] + address - matches[0][3]
        table = data[start:start + length]
        for at in needed:
            end = table.find(b"\0", at)
            if at >= len(table) or end < 0:
                raise ValueError("invalid ELF dynamic dependency name")
            names.append(table[at:end].decode())
    return {"class": 64, "endianness": "little", "type": kind, "machine": machine,
            "isa": {62: "x86_64", 183: "aarch64", 243: "riscv64"}.get(machine, "unknown"),
            "interpreter": interpreter, "needed": names,
            "linkage": "static/no-PT_INTERP-or-DT_NEEDED" if interpreter is None and not names else "dynamic"}


def probe(argv):
    result = subprocess.run(list(map(str, argv)), env=ENVIRONMENT, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("metadata probe failed: " + str(argv[0]) + ": " + result.stderr[:300])
    return {"argv": list(map(str, argv)), "exit_status": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def prerequisites():
    for path in (BUSYBOX, STRACE, Path("/usr/bin/dpkg-query")):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise Unavailable("required installed command is unavailable: " + str(path))
    if BUSYBOX.is_symlink() or not stat.S_ISREG(BUSYBOX.stat().st_mode):
        raise Unavailable("baseline BusyBox must be the installed regular file")


def package_identity():
    owner = probe(["/usr/bin/dpkg-query", "-S", BUSYBOX])
    lines = [line for line in owner["stdout"].splitlines() if line.endswith(": " + str(BUSYBOX))]
    if len(lines) != 1:
        raise ValueError("installed BusyBox has no unique dpkg owner")
    package = lines[0].rsplit(": ", 1)[0]
    fields = ("${binary:Package}", "${Version}", "${Architecture}", "${db:Status-Status}",
              "${source:Package}", "${source:Version}")
    version = probe(["/usr/bin/dpkg-query", "-W", "-f=" + "\t".join(fields) + "\n", package])
    values = version["stdout"].rstrip("\n").split("\t")
    if len(values) != 6 or values[3] != "installed":
        raise ValueError("BusyBox owner is not an installed package")
    return {"package": values[0], "version": values[1], "architecture": values[2], "status": values[3],
            "source_package": values[4], "source_version": values[5], "queries": [owner, version],
            "scope": "installed dpkg ownership/version evidence; no source build or repository signature claim"}


def dependencies(elf):
    if elf["linkage"].startswith("static"):
        return {"interpreter": None, "shared_objects": [],
                "scope": "ELF declares no interpreter or dynamic dependency; libc code is inside the supplied binary"}
    interpreter = identity(Path(elf["interpreter"])) if elf["interpreter"] else None
    result = probe(["/usr/bin/ldd", BUSYBOX])
    if "not found" in result["stdout"]:
        raise ValueError("installed dynamic dependency closure is incomplete")
    files = {}
    for line in result["stdout"].splitlines():
        match = re.search(r"(?:=>\s+)?(/\S+)\s+\(0x", line)
        if match:
            path = Path(match[1]).resolve(strict=True)
            files[str(path)] = identity(path)
    if not files:
        raise ValueError("no actual dynamic dependency identities were resolved")
    return {"interpreter": interpreter, "shared_objects": list(files.values()), "ldd": result}


def hex_string(value):
    return '"' + "".join("\\x%02x" % byte for byte in os.fsencode(value)) + '"'


def stdin_io(event):
    # Only this subject's controlled fd0/fd1 pipes are considered. The input
    # fd is sendfile's SECOND argument; treating it as startup hides fallback.
    if event["name"] == "sendfile":
        return re.match(r"1(?:<[^>]*>)?,\s*0(?:<[^>]*>)?(?:,|$)", event["arguments"]) is not None
    return (event["name"] in ("read", "readv", "splice", "copy_file_range")
            and re.match(r"0(?:<|,)", event["arguments"]) is not None)


def run_case(output, name, payload, *, pipe=False, missing=False):
    directory = output / name
    directory.mkdir(mode=0o700)
    traces = directory / "traces"
    traces.mkdir(mode=0o700)
    source = directory / ("missing-input.bin" if missing else "input.bin")
    if not missing:
        source.write_bytes(payload)
        source.chmod(0o400)
    arguments = [str(BUSYBOX), "cat"] + ([] if pipe else ["--", str(source)])
    command = [str(STRACE), "-ff", "-ttt", "-q", "-v", "-s", "0", "-xx", "-yy", "--kill-on-exit",
               "-o", str(traces / "process"), "--", *arguments]
    options = {"input": payload} if pipe else {"stdin": subprocess.DEVNULL}
    result = subprocess.run(command, cwd=directory, env=ENVIRONMENT, capture_output=True, timeout=60, **options)
    (directory / "stdout.bin").write_bytes(result.stdout)
    (directory / "stderr.bin").write_bytes(result.stderr)
    expected = b"" if missing else payload
    if result.returncode != (1 if missing else 0) or result.stdout != expected:
        raise ValueError("actual BusyBox output/exit differs in " + name)
    if missing and (os.fsencode(source) not in result.stderr or b"No such file or directory" not in result.stderr):
        raise ValueError("missing file did not produce its actual path/ENOENT diagnostic")
    records, combined = [], []
    paths = sorted(traces.glob("process.*"))
    if not paths or any(not path.name.rsplit(".", 1)[1].isdigit() for path in paths):
        raise TraceError("strace did not retain complete per-process trace files")
    for path in paths:
        pid = int(path.name.rsplit(".", 1)[1])
        events = parse_trace(path.read_text(), pid)
        summary = summarize(events)
        records.append({"pid": pid, "trace": identity(path), "summary": summary})
        combined.extend(events)
        path.chmod(0o400)
    encoded_binary = hex_string(BUSYBOX)
    starts = [event for event in combined if event["kind"] == "syscall" and event["name"] == "execve"
              and event["arguments"].startswith(encoded_binary + ",") and event["return_value"] == 0]
    if len(starts) != 1:
        raise TraceError("trace does not bind exactly one successful exec of installed BusyBox")
    main_pid = starts[0]["pid"]
    ends = [event for event in combined if event["pid"] == main_pid and event["kind"] == "exit"]
    if len(ends) != 1 or ends[0]["exit_status"] != result.returncode:
        raise TraceError("traced process termination differs from actual command status")
    input_token = hex_string(source)
    io = [event for event in combined if event["kind"] == "syscall" and event["pid"] == main_pid]
    first_input = next((index for index, event in enumerate(io)
        if (pipe and stdin_io(event))
        or (not pipe and event["name"] in ("open", "openat", "openat2") and input_token in event["arguments"])), None)
    if first_input is None:
        raise TraceError("no actual I/O on the controlled input was observed")
    if missing and not any(event["name"] in ("open", "openat", "openat2") and event["errno"] == "ENOENT"
                           and input_token in event["arguments"] for event in io):
        raise TraceError("missing-file trace lacks the matching actual ENOENT result")
    save(directory / "events.json", {"events": combined})
    record = {"name": name, "argv": arguments, "tracer_argv": command, "environment": ENVIRONMENT,
              "cwd": str(directory), "stdin": "pipe" if pipe else "/dev/null", "stdout": "pipe",
              "input": {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                        "path": None if missing else str(source)}, "expected_exit": 1 if missing else 0,
              "actual_exit": result.returncode, "stdout_file": identity(directory / "stdout.bin"),
              "stderr_file": identity(directory / "stderr.bin"), "output_byte_exact": True,
              "main_pid": main_pid, "processes": records, "summary": summarize(combined),
              "observed_before_input_io": sorted({event["name"] for event in io[:first_input]}),
              "events": identity(directory / "events.json")}
    save(directory / "result.json", record)
    return record


def collect(output, report):
    prerequisites()
    baseline = identity(BUSYBOX)
    elf = elf_identity(BUSYBOX)
    report.update(binary=baseline, elf=elf, package=package_identity(), dependencies=dependencies(elf),
                  tracer={**identity(STRACE), "version": probe([STRACE, "--version"])},
                  applet_help=probe([BUSYBOX, "cat", "--help"]), controlled_environment=ENVIRONMENT,
                  cases=[])
    source = Path(__file__)
    captured = output / "collector-source.py"
    captured.write_bytes(source.read_bytes())
    captured.chmod(0o400)
    report["collector"] = identity(captured)
    for size in (0, 4096, 65536, 1048576):
        report["cases"].append(run_case(output, "file-" + str(size), bytes(range(256)) * (size // 256)))
        if identity(BUSYBOX) != baseline:
            raise ValueError("installed BusyBox changed during collection")
        save(output / "result.json", report)
    report["cases"].append(run_case(output, "stdin-pipe-65536", bytes(range(256)) * 256, pipe=True))
    report["cases"].append(run_case(output, "missing-file", b"", missing=True))
    if identity(BUSYBOX) != baseline:
        raise ValueError("installed BusyBox changed during collection")
    counts = Counter()
    errors = Counter()
    for case in report["cases"]:
        counts.update(case["summary"]["syscalls"])
        errors.update(case["summary"]["errnos"])
    report.update(observed_syscall_counts=dict(sorted(counts.items())), observed_errno_counts=dict(sorted(errors.items())),
                  observed_file_io_syscalls=sorted(set(counts) & FILE_IO),
                  observed_before_input_io=sorted({name for case in report["cases"] if case["actual_exit"] == 0
                                                  for name in case["observed_before_input_io"]}),
                  inference_limit="Before-input calls are observed startup/setup candidates only. This corpus does not determine every required syscall, complete POSIX semantics, source closure, O-core admission, or performance.",
                  installed_binary_unchanged=True, ok=True, status="observed-linux-behavior")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="new permanent evidence directory")
    args = parser.parse_args()
    output = args.output.expanduser().absolute() if args.output else (
        Path.home() / ".local/state/ostadix/okernel" / ("posix-application-baseline-" + secrets.token_hex(8)))
    if output.exists() or output.is_symlink():
        parser.error("output must be a new directory")
    output.mkdir(mode=0o700, parents=True)
    report = {"schema": SCHEMA, "ok": False, "status": "incomplete", "scope": __doc__, "output": str(output),
              "host": {"uname": list(os.uname()), "python": sys.version},
              "not_claimed": ["source-built application", "O-core lowering/admission", "complete POSIX coverage",
                              "unobserved calls unnecessary", "performance or memory efficiency"]}
    save(output / "result.json", report)
    try:
        collect(output, report)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(ok=False, status="unavailable" if isinstance(error, Unavailable) else "failed",
                      error=type(error).__name__ + ": " + str(error))
        save(output / "result.json", report)
        print("BusyBox Linux syscall baseline: FAIL: " + str(error) + "\nEvidence: " + str(output / "result.json"), file=sys.stderr)
        return 1
    save(output / "result.json", report)
    print("BusyBox Linux functional/syscall baseline: PASS\nEvidence: " + str(output / "result.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
