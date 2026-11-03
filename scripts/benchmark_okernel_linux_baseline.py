#!/usr/bin/env python3
"""Measure real Linux application workloads; no O-core comparison is implied.

Records every sample, monotonic wall time, and wait4 resource usage for each
fresh child. Linux ru_maxrss is KiB, converted to bytes. It is the reported
peak for the child (and waited descendants), not simultaneous process-tree
memory, kernel/service memory, a whole-OS footprint, or steady-state app RSS.
The single O-core/POSIX system remains unimplemented and unqualified here.
No VM, installed package, live state or existing output is modified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time


SCHEMA = "ostadix.linux-application-baseline/v1"
FILE_IO = r'''import hashlib,json,os,sys,time
from pathlib import Path
root=Path(sys.argv[1]);size=int(sys.argv[2])
payload=(bytes(range(256))*((size+255)//256))[:size]
expected=hashlib.sha256(payload).hexdigest()
first=root/'created';second=root/'renamed'
started=time.monotonic_ns()
fd=os.open(first,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try:
    view=memoryview(payload)
    while view:
        count=os.write(fd,view)
        if count<=0:raise RuntimeError('short file write')
        view=view[count:]
    os.fsync(fd)
finally:os.close(fd)
with first.open('rb') as stream:actual=hashlib.sha256(stream.read()).hexdigest()
if actual!=expected or first.stat().st_size!=size:raise RuntimeError('read/hash/stat mismatch')
os.rename(first,second)
if first.exists() or second.stat().st_size!=size:raise RuntimeError('rename/stat mismatch')
with second.open('rb') as stream:renamed=hashlib.sha256(stream.read()).hexdigest()
if renamed!=expected:raise RuntimeError('renamed content changed')
second.unlink()
if second.exists():raise RuntimeError('unlink failed')
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
print(json.dumps({'bytes':size,'sha256':actual,'renamed_sha256':renamed,'internal_elapsed_ns':time.monotonic_ns()-started,
 'operations':['create','write','fsync-file','read-hash','stat','rename','stat','read-hash','unlink','fsync-directory'],
 'passed':True},sort_keys=True))
'''
C_SOURCE = r'''#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char *end = NULL;
    uint64_t count = strtoull(argv[1], &end, 10);
    if (!end || *end) return 3;
    uint64_t value = UINT64_C(1469598103934665603);
    for (uint64_t i = 0; i < count; ++i)
        value = (value ^ (i & UINT64_C(255))) * UINT64_C(1099511628211);
    printf("OKERNEL_BASELINE_C %016" PRIx64 "\n", value);
    return 0;
}
'''


def identity(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1048576), b""):
            digest.update(data)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def executable(name):
    selected = shutil.which(name)
    if selected is None:
        raise ValueError("required original Linux command missing: " + name)
    return Path(selected).resolve(strict=True)


def storage(path):
    path = path.resolve()
    matching = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        left, right = line.split(" - ", 1)
        parts, data = left.split(), right.split()
        mount = Path(parts[4].replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\"))
        if path == mount or mount in path.parents:
            matching.append((len(mount.parts), {"mount": str(mount), "filesystem": data[0], "source": data[1],
                                                "mount_options": parts[5], "super_options": data[2]}))
    result = max(matching, key=lambda item: item[0])[1] if matching else {"filesystem": "unknown"}
    flags = os.statvfs(path)
    result.update(path=str(path), noexec=bool(flags.f_flag & getattr(os, "ST_NOEXEC", 8)),
                  free_bytes=flags.f_bavail * flags.f_frsize,
                  persistence_scope="volatile RAM filesystem" if result["filesystem"] in ("tmpfs", "ramfs") else "non-RAM fallback; backing durability not qualified")
    return result


def c_oracle(count):
    value = 1469598103934665603
    for index in range(count):
        value = ((value ^ (index & 255)) * 1099511628211) & 0xffffffffffffffff
    return "OKERNEL_BASELINE_C %016x\n" % value


def measured_run(argv, cwd, logs, label, *, timeout=30, environment=None):
    """One wait4(pid) per fresh child; never subtract cumulative child maxima."""
    logs.mkdir(parents=True, exist_ok=True)
    stdout_path, stderr_path = logs / (label + ".stdout"), logs / (label + ".stderr")
    timed_out = False
    with stdout_path.open("wb") as out, stderr_path.open("wb") as error:
        started = time.monotonic_ns()
        child = subprocess.Popen([str(arg) for arg in argv], cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=out, stderr=error, start_new_session=True)
        previous = signal.getsignal(signal.SIGALRM)
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        if previous_timer != (0.0, 0.0):
            os.killpg(child.pid, signal.SIGKILL)
            os.wait4(child.pid, 0)
            child.returncode = -signal.SIGKILL
            raise ValueError("baseline requires an unused process alarm timer")
        def expire(signum, frame):
            raise TimeoutError("owned benchmark child exceeded timeout")
        signal.signal(signal.SIGALRM, expire)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        try:
            try:
                _, status, usage = os.wait4(child.pid, 0)
            except TimeoutError:
                timed_out = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _, status, usage = os.wait4(child.pid, 0)
            except BaseException:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _, status, _ = os.wait4(child.pid, 0)
                child.returncode = os.waitstatus_to_exitcode(status)
                raise
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        child.returncode = os.waitstatus_to_exitcode(status)
        elapsed = time.monotonic_ns() - started
    return {"argv": [str(arg) for arg in argv], "cwd": str(cwd), "child_pid": child.pid, "elapsed_ns": elapsed,
            "exit_status": child.returncode, "timed_out": timed_out,
            "wait4_child_reported_maxrss_bytes": int(usage.ru_maxrss) * 1024,
            "wait4_user_seconds": usage.ru_utime, "wait4_system_seconds": usage.ru_stime,
            "wait4_voluntary_context_switches": usage.ru_nvcsw, "wait4_involuntary_context_switches": usage.ru_nivcsw,
            "wait4_input_blocks": usage.ru_inblock, "wait4_output_blocks": usage.ru_oublock,
            "stdout": stdout_path.read_bytes().decode("utf-8", "backslashreplace"),
            "stderr": stderr_path.read_bytes().decode("utf-8", "backslashreplace"),
            "stdout_file": identity(stdout_path), "stderr_file": identity(stderr_path)}


def summary(samples):
    result = {}
    for field in ("elapsed_ns", "wait4_child_reported_maxrss_bytes", "wait4_user_seconds", "wait4_system_seconds"):
        values = [item[field] for item in samples]
        result[field] = quantiles(values)
    internal = [item["validation"]["internal_elapsed_ns"] for item in samples if "internal_elapsed_ns" in item.get("validation", {})]
    if internal:
        result["internal_file_workload_elapsed_ns"] = quantiles(internal)
    return result


def quantiles(values):
    if not values:
        raise ValueError("cannot summarize an empty sample set")
    median = statistics.median(values)
    return {"values": list(values), "median": median, "p50": median,
            "p95": sorted(values)[math.ceil(.95 * len(values)) - 1], "min": min(values), "max": max(values)}


def save(output, value):
    pending = output / "result.json.pending"
    pending.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(pending, output / "result.json")


def run(args, output, record):
    if sys.platform != "linux" or not hasattr(os, "wait4"):
        raise ValueError("this baseline requires Linux wait4 accounting")
    environment = {key: value for key, value in os.environ.items() if key in ("HOME", "USER", "LOGNAME")}
    environment.update(PATH="/usr/bin:/bin", LC_ALL="C", LANG="C", TZ="UTC", PYTHONDONTWRITEBYTECODE="1")
    tools = {name: executable(name) for name in ("cat", "sha256sum", "cc")}
    tools["sh"] = Path("/bin/sh").resolve(strict=True)
    tools["python"] = Path(sys.executable).resolve()
    record["tools"] = {}
    for name, path in tools.items():
        version = subprocess.run([str(path), "--version"], env=environment, capture_output=True, text=True, timeout=10) if name != "sh" else None
        record["tools"][name] = {"identity": identity(path), "version": None if version is None else {
            "exit_status": version.returncode, "stdout": version.stdout, "stderr": version.stderr}}
    # Record actual compiler helper selections when supported; no installation,
    # capture substitution, or use of these objects as an O-core implementation.
    record["compiler_helpers"] = {}
    for helper in ("cc1", "as", "collect2", "ld"):
        selected = subprocess.run([str(tools["cc"]), "-print-prog-name=" + helper], env=environment, capture_output=True, text=True, timeout=10)
        name = selected.stdout.strip()
        path = Path(name) if Path(name).is_absolute() else Path(shutil.which(name) or name)
        if selected.returncode == 0 and path.is_file():
            record["compiler_helpers"][helper] = identity(path.resolve())
    sources = output / "workloads"
    sources.mkdir()
    (sources / "file_io.py").write_text(FILE_IO)
    (sources / "application.c").write_text(C_SOURCE)
    record["workload_sources"] = {name: identity(sources / name) for name in ("file_io.py", "application.c")}
    driver = Path(__file__).resolve()
    record["driver_source"] = identity(driver)
    shutil.copyfile(driver, output / "driver.py")
    (output / "driver.py").chmod(0o444)
    record["driver"] = identity(output / "driver.py")
    if any(record["driver"][key] != record["driver_source"][key] for key in ("bytes", "sha256")):
        raise ValueError("benchmark driver changed while capturing")
    clock = time.get_clock_info("monotonic")
    record["host"] = {"uname": list(os.uname()), "isa": platform.machine(), "python": sys.version,
                      "logical_cpus": os.cpu_count(), "load_average_before": list(os.getloadavg()),
                      "affinity": sorted(os.sched_getaffinity(0)), "clock": {"implementation": clock.implementation,
                      "resolution_seconds": clock.resolution, "monotonic": clock.monotonic, "adjustable": clock.adjustable}}
    record["output_storage"] = storage(output)
    record["environment"] = environment
    record["cache_policy"] = "normal repeated host runs; no cache dropping, CPU isolation, frequency control or background-workload exclusion"
    record["repetitions"], record["bytes_per_file"] = args.repetitions, args.bytes
    parent = Path("/dev/shm")
    fallback = None
    if not parent.is_dir() or not os.access(parent, os.W_OK | os.X_OK) or storage(parent)["free_bytes"] < args.bytes * 4:
        parent = Path(tempfile.gettempdir())
        fallback = "/dev/shm unavailable, unwritable or insufficient free space"
    record["workloads"] = {}
    expected = hashlib.sha256((bytes(range(256)) * ((args.bytes + 255) // 256))[:args.bytes]).hexdigest()
    expected_c = c_oracle(args.bytes)
    with tempfile.TemporaryDirectory(prefix="okernel-linux-baseline-io-", dir=parent) as temporary:
        work = Path(temporary)
        record["file_io_storage"] = storage(work)
        record["file_io_storage"]["fallback_reason"] = fallback
        (work / "pipeline-input").write_bytes((bytes(range(256)) * ((args.bytes + 255) // 256))[:args.bytes])
        compile_parent = work
        if storage(work)["noexec"]:
            compile_parent = Path(tempfile.gettempdir())
            if storage(compile_parent)["noexec"]:
                compile_parent = output
        with tempfile.TemporaryDirectory(prefix="okernel-linux-baseline-cc-", dir=compile_parent) as compile_temp:
            compiler_work = Path(compile_temp)
            record["compile_storage"] = storage(compiler_work)
            record["compile_storage"]["fallback_reason"] = "file-I/O filesystem is noexec" if compile_parent != work else None
            names = ("shell_startup", "file_io", "shell_pipeline", "compile_link_execute")
            for name in names:
                record["workloads"][name] = {"samples": [], "summary": None}
                for index in range(args.repetitions):
                    sample_dir = work / (name + "-%03d" % index)
                    sample_dir.mkdir()
                    if name == "shell_startup":
                        command = [tools["sh"], "-c", "exit 0"]
                    elif name == "file_io":
                        command = [tools["python"], "-B", sources / "file_io.py", sample_dir, str(args.bytes)]
                    elif name == "shell_pipeline":
                        command = [tools["sh"], "-c", '"$1" "$2" | "$3"', "baseline-pipeline",
                                   tools["cat"], work / "pipeline-input", tools["sha256sum"]]
                    else:
                        sample_dir = compiler_work / ("sample-%03d" % index)
                        sample_dir.mkdir()
                        command = [tools["sh"], "-c", '"$1" -O2 -std=c11 -c "$2" -o "$3" && "$1" "$3" -o "$4" && "$4" "$5"',
                                   "baseline-compiler", tools["cc"], sources / "application.c", sample_dir / "application.o",
                                   sample_dir / "application", str(args.bytes)]
                    sample = measured_run(command, sample_dir, output / "samples", name + "-%03d" % index, environment=environment)
                    record["workloads"][name]["samples"].append(sample)
                    if sample["exit_status"] != 0 or sample["timed_out"]:
                        save(output, record)
                        raise ValueError("Linux baseline child failed: " + name)
                    if name == "shell_startup":
                        valid = sample["stdout"] == ""
                        sample["validation"] = {"empty_stdout": valid}
                    elif name == "file_io":
                        validation = json.loads(sample["stdout"])
                        valid = (validation.get("passed") is True and validation.get("bytes") == args.bytes
                                 and validation.get("sha256") == expected and validation.get("renamed_sha256") == expected
                                 and not list(sample_dir.iterdir()))
                        sample["validation"] = validation
                    elif name == "shell_pipeline":
                        valid = sample["stdout"] == expected + "  -\n"
                        sample["validation"] = {"sha256": expected, "exact_pipeline_output": valid}
                    else:
                        valid = sample["stdout"] == expected_c
                        sample["validation"] = {"expected_output": expected_c, "exact_program_output": valid,
                            "object": identity(sample_dir / "application.o"), "executable": identity(sample_dir / "application")}
                    sample["output_verified"] = valid
                    save(output, record)
                    if not valid:
                        raise ValueError("Linux baseline output mismatch: " + name)
                record["workloads"][name]["summary"] = summary(record["workloads"][name]["samples"])
    for item in record["tools"].values():
        if identity(Path(item["identity"]["path"])) != item["identity"]:
            raise ValueError("original tool changed during measurements")
    for item in record["compiler_helpers"].values():
        if identity(Path(item["path"])) != item:
            raise ValueError("compiler helper changed during measurements")
    record["host"]["load_average_after"] = list(os.getloadavg())
    if identity(driver) != record["driver_source"]:
        raise ValueError("benchmark source changed during measurements")
    small = [item["wait4_child_reported_maxrss_bytes"] for name in ("shell_startup", "shell_pipeline")
             for item in record["workloads"][name]["samples"]]
    record["memory_measurement"]["observed_tiny_child_reported_peak_bytes"] = quantiles(small)
    record.update(passed=True, owned_temporary_workspaces_removed=True, tools_unchanged=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory")
    parser.add_argument("--repetitions", type=int, default=7)
    parser.add_argument("--bytes", type=int, default=262144, help="bytes per deterministic file/application input")
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 100 or not 1 <= args.bytes <= 16 * 1048576:
        parser.error("repetitions must be1..100 and bytes1..16777216")
    output = args.output.resolve()
    if output.exists() or output.is_symlink():
        parser.error("output must be a new directory")
    output.mkdir(mode=0o700, parents=True)
    record = {"schema": SCHEMA, "passed": False, "started_unix": time.time(), "output": str(output),
        "scope": "original Linux host application baseline only; file-I/O wall timing includes CPython startup and SHA256 work, with its internal operation timing separately retained",
        "memory_measurement": {"method": "os.wait4(exact_child_pid,0) per run, Linux ru_maxrss KiB multiplied by1024",
            "meaning": "reported child peak including launch and Linux-accounted waited descendants; not simultaneous aggregate process-tree RSS or steady-state-only application RSS",
            "python_parent_launch_floor": "fork/pre-exec inherited Python launcher RSS can set the reported child high-water floor; tiny programs may therefore reflect the harness rather than their steady executable footprint. The floor is not subtracted and these values cannot qualify whole-OS memory savings.",
            "whole_kernel_services_or_OS_memory": False,
            "references": ["https://man7.org/linux/man-pages/man2/wait4.2.html", "https://man7.org/linux/man-pages/man2/getrusage.2.html"]},
        "qualification": {"single_ocore_posix_system_implemented": False, "candidate_measurements_available": False,
            "matched_system_comparison_available": False, "whole_OS_memory_or_boot_qualified": False, "speedup_claim": False},
        "comparison_requirements": ["same workload bytes, semantics and original runtime/compiler configuration",
            "matched ISA, CPU/accelerator, device/backend, RAM and durability/cache policy",
            "separate full kernel/service memory accounting and boot-to-ready measurements",
            "full application and file-I/O correctness before comparing timings"]}
    record["quantile_method"] = {"p50": "sample median; arithmetic mean of the two central samples for even N",
                                 "p95": "nearest rank: sorted_samples[ceil(0.95*N)-1]; for default N=7 this is the maximum",
                                 "all_sample_values_retained": True}
    try:
        run(args, output, record)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        record["error"] = str(error)
        save(output, record)
        print("Linux application baseline: FAIL: " + str(error), file=sys.stderr)
        return 1
    save(output, record)
    print("Linux application baseline: PASS\nEvidence: " + str(output / "result.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
