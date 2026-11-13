#!/usr/bin/env python3
"""Run the six guest regression gates with at most two VMs on one exact M1 O10 build.

Each gate receives a new saved-state fork from an explicitly prepared private
seed. Default behavior prints a plan; --execute is required to start guests.
No failed/unknown guest work is retried. Every gate must exit zero and retain
a passing JSON receipt without skips. Unit/language checks remain separate.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

import okernel_unified_world as runner

ROOT = Path(__file__).resolve().parents[1]
GATES = (
    ("two_domains", "verify_okernel_two_domains.py", "two-domain-acceptance.json"),
    ("provider", "verify_okernel_unified_provider.py", "provider-acceptance-*/result.json"),
    ("client", "verify_okernel_unified_client.py", "client-acceptance-*/result.json"),
    ("recovery", "verify_okernel_unified_recovery.py", "client-crash-acceptance-*/result.json"),
    ("default_compile", "verify_okernel_p9_default_compile.py", "p9-default-compile-*/result.json"),
    ("runtime", "verify_okernel_unified_runtime.py", "runtime-acceptance-*/result.json"),
)

def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()

def document(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected regular receipt: " + str(path))
    result = json.loads(path.read_text())
    if type(result) is not dict:
        raise ValueError("receipt must be a JSON object")
    return result

def contains_skip(value):
    if isinstance(value, dict):
        if value.get("status") in ("skip", "skipped"):
            return True
        for key, item in value.items():
            if key.lower() in ("skip", "skips", "skipped") and item:
                return True
            if contains_skip(item):
                return True
    elif isinstance(value, list):
        return any(contains_skip(item) for item in value)
    return False

def receipt_passes(record):
    return (record.get("ok") is True and not contains_skip(record)
            and not record.get("error") and not record.get("cleanup_stop_error"))

def plan(args):
    states = args.output / "states"
    result = []
    client = digest(ROOT / "ocore/guest/linux/package-domain/p9")
    for name, script, receipt_pattern in GATES:
        state = states / name
        fork = [sys.executable, str(ROOT / "scripts/fork_okernel_state.py"),
                "--source", str(args.seed_state), "--output", str(state)]
        argv = [sys.executable, str(ROOT / "scripts" / script), "--state", str(state)]
        if name == "runtime":
            argv += ["--runtime", str(args.runtime), "--client-sha256", client]
        else:
            argv += ["--build", str(args.build)]
        result.append({"gate_id": name, "script": script, "state": str(state),
                       "fork_argv": fork, "argv": argv, "receipt_pattern": receipt_pattern})
    return result

def execute_command(argv, output, timeout):
    output.mkdir(parents=True, exist_ok=False)
    result = {"argv": argv, "started": time.time(), "returncode": None, "timed_out": False}
    with (output / "stdout.log").open("w") as stdout, (output / "stderr.log").open("w") as stderr:
        child = subprocess.Popen(argv, cwd=ROOT, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            result["returncode"] = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            result["timed_out"] = True
            # Only this newly owned process group is stopped. A failed gate is
            # never continued/retried; detached runtime cleanup remains visible.
            os.killpg(child.pid, signal.SIGTERM)
            try:
                result["returncode"] = child.wait(timeout=60)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                result["returncode"] = child.wait(timeout=10)
    result["finished"] = time.time()
    (output / "command.json").write_text(json.dumps(result, indent=2) + "\n")
    return result

def validate_m1_prerequisites(root, build, profile, revision, resident_path, hostile_path, acceptance_scope="extended"):
    # Reuse the same semantic receipt validator as the final M1 binder. This
    # driver cannot manufacture admission from a count or caller-supplied flag.
    from verify_o10_m1 import validate_resident, contract_id, observe_extra_probe
    contract_id(acceptance_scope)
    primary, primary_sessions, _ = validate_resident(
        root, resident_path, build, profile, revision)
    if acceptance_scope == "draft0":
        if hostile_path is not None:
            observe_extra_probe(hostile_path)  # retained separately, never a prerequisite pass
        return primary, document(hostile_path) if hostile_path is not None else None
    if hostile_path is None:
        raise ValueError("extended acceptance requires actual extra probe result")
    hostile, hostile_sessions, _ = validate_resident(
        root, hostile_path, build, profile, revision, hostile=True)
    if primary_sessions & hostile_sessions:
        raise ValueError("resident and hostile MMIO must use distinct private VM sessions")
    return primary, hostile


def preflight(args):
    profile = document(args.build / "monitor-profile.json")
    runner.validate_profile(profile)
    if profile.get("o10") != runner.O10_PROFILE or profile.get("o10_qualification") is not True:
        raise ValueError("exact M1 O10 qualification build required")
    for name, expected in profile.get("source_sha256", {}).items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or digest(ROOT / relative) != expected:
            raise ValueError("captured build source differs: " + name)
    for name, expected in profile["artifacts"].items():
        runner.checked(args.build / name, expected)
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                              capture_output=True, text=True).stdout.strip()
    if args.mcp_release != revision:
        raise ValueError("observed MCP release must match the M1 branch under test")
    validate_m1_prerequisites(ROOT, args.build, profile, revision,
                              args.resident_result, args.hostile_mmio_result, args.acceptance_scope)
    # Actual qualified component evidence does not silently admit a monitor to
    # foreground tests. Its observed hash pair still needs explicit selection.
    from verify_okernel_unified_client import admitted_monitor_revision
    admitted_monitor_revision(profile["artifacts"]["monitor.elf"]["sha256"],
                              digest(args.build / "monitor-profile.json"))
    frozen = document(args.runtime / "runtime.json")
    from verify_okernel_unified_runtime import validate_inventory
    validate_inventory(args.runtime, frozen)
    if digest(args.runtime / "build/monitor-profile.json") != digest(args.build / "monitor-profile.json"):
        raise ValueError("frozen runtime is not the same selected M1 build")
    for name, identity in frozen["sources"].items():
        if digest(ROOT / name) != identity["frozen"]["sha256"]:
            raise ValueError("frozen runtime source differs from current checkout: " + name)
    fork = document(args.seed_state / "fork.json")
    if not fork.get("ok") or fork.get("output") != str(args.seed_state):
        raise ValueError("seed must itself be a new explicit private fork")
    runner.common.validate_head(args.seed_state, document(args.seed_state / "head.json"))
    sources = sorted({entry[1] for entry in GATES} |
                     {"verify_o10_m1_regressions.py", "verify_o10_m1.py",
                      "verify_o10_resident.py", "verify_o10_hostile_mmio.py",
                      "fork_okernel_state.py", "okernel_unified_world.py",
                      "o10.py", "verify_okernel_unified_console.py", "o-kernel.sh"})
    return profile, revision, {str(Path("scripts") / name): digest(ROOT / "scripts" / name) for name in sources}


def resumable_entries(previous, current):
    # Only completed positive executions can be reused. An interrupted process
    # with a positive child receipt but no observed exit code remains unknown.
    if previous.get("acceptance_scope", "extended") != current.get("acceptance_scope", "extended"):
        raise ValueError("resume acceptance scope differs")
    if previous.get("contract_id") != current.get("contract_id"):
        raise ValueError("resume acceptance contract differs")
    for key in ("resident_result", "hostile_mmio_result"):
        if (previous.get(key) or {}).get("sha256") != (current.get(key) or {}).get("sha256"):
            raise ValueError("resume component prerequisite differs: " + key)
    for field in ("source_revision", "mcp_release", "profile_sha256", "monitor_sha256", "seed_head_sha256"):
        if previous.get(field) != current.get(field):
            raise ValueError("resume identity differs: " + field)
    if previous.get("frozen_runtime", {}).get("sha256") != current.get("frozen_runtime", {}).get("sha256"):
        raise ValueError("resume frozen runtime differs")
    old_sources = previous.get("source_sha256", {})
    new_sources = current.get("source_sha256", {})
    ignored = "scripts/verify_o10_m1_regressions.py"  # bookkeeping only, never a guest gate
    if ({name: value for name, value in old_sources.items() if name != ignored}
            != {name: value for name, value in new_sources.items() if name != ignored}):
        raise ValueError("resume gate source differs")
    completed = {}
    for entry in previous.get("gates", []):
        command = entry.get("command", {})
        if (entry.get("ok") is not True or type(command.get("returncode")) is not int
                or command.get("returncode") != 0 or command.get("timed_out") is not False):
            continue
        retained = entry.get("receipt", {})
        path = Path(retained.get("path", ""))
        actual = document(path)
        if digest(path) != retained.get("sha256") or not receipt_passes(actual):
            raise ValueError("resume receipt changed or unqualified")
        if actual != retained.get("result"):
            raise ValueError("resume retained result differs")
        name = entry.get("gate_id")
        if name not in {item[0] for item in GATES} or name in completed:
            raise ValueError("resume gate identity invalid")
        completed[name] = entry
    return completed


# Conservative retained-state/input/save peaks observed in these fixed gates.
PEAK_GIB = {"two_domains": 5.5, "provider": 5.5, "client": 5.5,
            "recovery": 3.5, "default_compile": 3.5, "runtime": 5.5}


def bounded_results(items, worker, jobs, *, admit=None, on_start=None):
    """Run at most two gates; stop feeding on failure and drain in-flight work."""
    if jobs not in (1, 2):
        raise ValueError("at most two VM workers are allowed")
    iterator = iter(items)
    missing = object()
    candidate = next(iterator, missing)
    failed = False
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        pending = {}
        while pending or (candidate is not missing and not failed):
            while candidate is not missing and not failed and len(pending) < jobs:
                if admit is not None and not admit(candidate, list(pending.values())):
                    if not pending:
                        raise RuntimeError("resource admission refused " + candidate["gate_id"] + "; no gate started")
                    break
                if on_start is not None:
                    on_start(candidate)
                pending[pool.submit(worker, candidate)] = candidate
                candidate = next(iterator, missing)
            if not pending:
                break
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                item = pending.pop(future)
                try:
                    result = future.result()
                except BaseException as error:
                    result = {**item, "ok": False, "error": type(error).__name__ + ": " + str(error)}
                yield item, result
                # The main thread may also disqualify a result after checking
                # source/build stability; honor that before feeding more work.
                failed = failed or result.get("ok") is not True


def run_step(step, args):
    """Worker owns only its entry, fork, subprocesses and log directories."""
    entry = {**step, "ok": False}
    state = Path(step["state"])
    try:
        state.parent.mkdir(parents=True, exist_ok=True)
        entry["free_bytes_before"] = shutil.disk_usage(state.parent).free
        fork_result = execute_command(step["fork_argv"], args.output / (step["gate_id"] + "-fork"), 300)
        entry["fork"] = fork_result
        if fork_result["returncode"] != 0 or fork_result["timed_out"]:
            raise RuntimeError("fresh private fork failed")
        command = execute_command(step["argv"], args.output / (step["gate_id"] + "-gate"), args.gate_timeout)
        entry["command"] = command
        candidates = list(state.glob(step["receipt_pattern"]))
        entry["result_candidates"] = [str(path) for path in candidates]
        if len(candidates) != 1:
            raise RuntimeError("expected one actual gate receipt")
        actual = document(candidates[0])
        entry["receipt"] = {"path": str(candidates[0]), "sha256": digest(candidates[0]), "result": actual}
        entry["ok"] = command["returncode"] == 0 and not command["timed_out"] and receipt_passes(actual)
        if not entry["ok"]:
            entry["error"] = "gate failed or skipped; unknown work is not retried"
    except BaseException as error:
        entry["error"] = type(error).__name__ + ": " + str(error)
    entry["status"] = "passed" if entry["ok"] else "failed"
    (args.output / (step["gate_id"] + "-worker-result.json")).write_text(json.dumps(entry, indent=2) + "\n")
    return entry


def memory_available():
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise RuntimeError("Linux MemAvailable is required for VM resource admission")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--seed-state", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--resident-result", type=Path, required=True)
    parser.add_argument("--hostile-mmio-result", type=Path)
    parser.add_argument("--acceptance-scope", choices=("extended", "draft0"), default="extended")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mcp-release", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--resume-from", type=Path, help="reuse only hash-bound complete positive gate executions; interrupted gates get new forks")
    parser.add_argument("--gate-timeout", type=int, default=5400)
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=1)
    parser.add_argument("--minimum-free-gib", type=float, default=3.5)
    args = parser.parse_args()
    if args.acceptance_scope == "extended" and args.hostile_mmio_result is None:
        parser.error("default extended acceptance requires --hostile-mmio-result")
    from verify_o10_m1 import contract_id, observe_extra_probe
    selected_contract = contract_id(args.acceptance_scope)
    for name in ("build", "seed_state", "runtime", "resident_result", "hostile_mmio_result"):
        value = getattr(args, name)
        if value is None:
            continue
        path = value.expanduser()
        if path.is_symlink():
            parser.error(name + " must not be a symlink")
        setattr(args, name, path.resolve(strict=True))
    args.output = args.output.expanduser().resolve()
    steps = plan(args)
    if not args.execute:
        print(json.dumps({"scope": "plan only; no gate/fork/VM executed", "acceptance_scope": args.acceptance_scope,
                          "contract_id": selected_contract, "steps": steps}, indent=2))
        return 0
    if args.output.exists() or args.output.is_symlink():
        parser.error("execution output must be a new directory; no automatic reruns")
    args.output.mkdir(parents=True, exist_ok=False)
    record = {"schema": "ostadix.o10-guest-regressions/v1", "milestone": "M1",
              "acceptance_scope": args.acceptance_scope, "contract_id": selected_contract,
              "ok": False, "full_milestone_qualified": False, "started": time.time(),
              "scope": "six real guest regression gates on the same captured M1 O10 qualification build, each in a fresh private seed fork; at most two concurrent VMs; unit and language checks are separate",
              "mcp_release": args.mcp_release, "build": str(args.build),
              "seed_state": str(args.seed_state), "runtime": str(args.runtime),
              "max_parallel_vms": args.jobs, "gates": [], "skips": [], "resource_admission": []}
    receipt = args.output / "result.json"
    def save():
        temporary = receipt.with_suffix(".tmp")
        temporary.write_text(json.dumps(record, indent=2) + "\n")
        temporary.replace(receipt)
    save()
    try:
        profile, revision, sources = preflight(args)
        record.update(source_revision=revision, source_sha256=sources,
                      profile_sha256=digest(args.build / "monitor-profile.json"),
                      monitor_sha256=profile["artifacts"]["monitor.elf"]["sha256"],
                      build_tools=profile["tools"], resident_result={"path": str(args.resident_result), "sha256": digest(args.resident_result)},
                      frozen_runtime={"path": str(args.runtime / "runtime.json"), "sha256": digest(args.runtime / "runtime.json")},
                      seed_head_sha256=digest(args.seed_state / "head.json"))
        if args.hostile_mmio_result is not None:
            record["hostile_mmio_result"] = {"path": str(args.hostile_mmio_result), "sha256": digest(args.hostile_mmio_result)}
            if args.acceptance_scope == "draft0":
                record["extra_probe"] = observe_extra_probe(args.hostile_mmio_result)
        save()
        resumed = resumable_entries(document(args.resume_from), record) if args.resume_from else {}
        if args.resume_from:
            record["resume_from"] = {"path": str(args.resume_from.resolve(strict=True)),
                                     "sha256": digest(args.resume_from)}
            save()
        entries = {}
        pending_steps = []
        for step in steps:
            if step["gate_id"] in resumed:
                entry = dict(resumed[step["gate_id"]])
                entry["reused_from"] = record["resume_from"]
                entry["status"] = "passed"
            else:
                entry = {**step, "ok": False, "status": "queued"}
                pending_steps.append(step)
            entries[step["gate_id"]] = entry
        record["gates"] = [entries[item[0]] for item in GATES]
        save()

        def admit(step, active):
            # The main thread serializes reservations before starting workers.
            # Existing allocations already reduce free space; reserving each
            # active gate's full peak again is deliberately conservative.
            free = shutil.disk_usage(args.output).free
            peaks = sum(PEAK_GIB[item["gate_id"]] for item in [*active, step])
            required = max(args.minimum_free_gib, peaks) * 1024 ** 3
            available_memory = memory_available()
            required_memory = (1 + 3.5 * (len(active) + 1)) * 1024 ** 3
            accepted = free >= required and available_memory >= required_memory
            record["resource_admission"].append({
                "gate_id": step["gate_id"], "active": [item["gate_id"] for item in active],
                "free_bytes": free, "reserved_peak_bytes": int(required),
                "memory_available": available_memory, "memory_reserved_peak": int(required_memory),
                "accepted": accepted})
            save()
            return accepted

        def started(step):
            entries[step["gate_id"]]["status"] = "running"
            save()

        failures = []
        for step, entry in bounded_results(pending_steps, lambda item: run_step(item, args),
                                           args.jobs, admit=admit, on_start=started):
            if sources != {name: digest(ROOT / name) for name in sources}:
                entry.update(ok=False, error="gate sources changed during regressions", status="failed")
            if digest(args.build / "monitor-profile.json") != record["profile_sha256"]:
                entry.update(ok=False, error="selected build changed during regressions", status="failed")
            if digest(args.seed_state / "head.json") != record["seed_head_sha256"]:
                entry.update(ok=False, error="private seed changed during regressions", status="failed")
            entries[step["gate_id"]] = entry
            record["gates"] = [entries[item[0]] for item in GATES]
            if not entry["ok"]:
                failures.append(step["gate_id"] + ": " + entry.get("error", "failed"))
            save()
        for entry in record["gates"]:
            if entry.get("status") == "queued":
                entry["status"] = "not_started"
        if failures:
            record["error"] = "; ".join(failures)
        record["ok"] = len(record["gates"]) == len(GATES) and all(item["ok"] for item in record["gates"])
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
    finally:
        record["finished"] = time.time()
        save()
    print(json.dumps({"ok": record["ok"], "result": str(receipt),
                      "full_milestone_qualified": False}, sort_keys=True))
    return 0 if record["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
