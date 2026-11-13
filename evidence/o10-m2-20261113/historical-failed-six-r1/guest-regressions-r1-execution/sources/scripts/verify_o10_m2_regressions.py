#!/usr/bin/env python3
"""Run the original six gates through the unchanged bounded shared scheduler.

M2 first requires its actual restart command/receipt and same-build resident
proof. The default prints a plan. --execute creates new private forks; no
failed or unknown service work is retried. This envelope does not qualify M2.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

import verify_o10_m1_regressions as shared
import verify_o10_m2 as m2

ROOT = Path(__file__).resolve().parents[1]

def delegate_argv(args):
    argv = [sys.executable, str(ROOT / "scripts/verify_o10_m1_regressions.py"),
            "--acceptance-scope", "draft0", "--build", str(args.build),
            "--seed-state", str(args.seed_state), "--runtime", str(args.runtime),
            "--resident-result", str(args.resident_result), "--output", str(args.output / "six-gates"),
            "--mcp-release", args.mcp_release, "--jobs", str(args.jobs),
            "--gate-timeout", str(args.gate_timeout), "--minimum-free-gib", str(args.minimum_free_gib)]
    if args.execute:
        argv.append("--execute")
    return argv

def validate_prerequisites(args):
    revision = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    m2.require(revision == args.mcp_release, "source/MCP release must match the branch under test")
    profile = m2.validate_build(ROOT, args.build)
    primary, primary_sessions = m2.validate_restart(root=ROOT, receipt_path=args.restart_result,
        build=args.build, profile=profile, expected_revision=revision, command_path=args.restart_command)
    _, resident_sessions, _ = m2.shared.validate_resident(
        ROOT, args.resident_result, args.build, profile, revision)
    m2.require(primary_sessions.isdisjoint(resident_sessions), "restart and resident reused a VM")
    return profile, revision

def run(args):
    argv = delegate_argv(args)
    if not args.execute:
        # The existing driver's plan is the one that will execute; no alternate
        # gate list or scheduling implementation is maintained here.
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, check=True)
        return {"schema": m2.REGRESSION_SCHEMA, "milestone": "M2", "contract_id": m2.CONTRACT,
                "scope": "plan only; no fork, guest or qualification", "delegate_argv": argv,
                "shared_plan": json.loads(result.stdout)}
    m2.require(not args.output.exists() and not args.output.is_symlink(),
               "execution output must be a new directory; no automatic reruns")
    args.output.mkdir(parents=True)
    record = {"schema": m2.REGRESSION_SCHEMA, "milestone": "M2", "contract_id": m2.CONTRACT,
              "ok": False, "full_milestone_qualified": False, "started": time.time(), "skips": [],
              "scope": "Six real same-build guest regressions delegated to the unchanged M1 scheduler after actual M2 restart and resident prerequisites; at most two VMs; ordinary checks separate",
              "mcp_release": args.mcp_release, "max_parallel_vms": args.jobs}
    receipt = args.output / "result.json"
    def save():
        tmp = receipt.with_suffix(".tmp")
        tmp.write_text(json.dumps(record, indent=2) + "\n"); tmp.replace(receipt)
    save()
    try:
        profile, revision = validate_prerequisites(args)
        sources = {name: m2.digest(ROOT / name) for name in
                   ("scripts/verify_o10_m2.py", "scripts/verify_o10_m2_regressions.py",
                    "scripts/verify_o10_m1_regressions.py")}
        record.update(source_revision=revision, source_sha256=sources,
                      build=str(args.build), monitor_sha256=m2.digest(args.build / "monitor.elf"),
                      profile_sha256=m2.digest(args.build / "monitor-profile.json"),
                      restart_result=m2.identity(args.restart_result), restart_command=m2.identity(args.restart_command),
                      resident_result=m2.identity(args.resident_result), seed_head=m2.identity(args.seed_state / "head.json"))
        save()
        command = shared.execute_command(argv, args.output / "shared-driver-command", None)
        command.update(stdout=m2.identity(args.output / "shared-driver-command/stdout.log"),
                       stderr=m2.identity(args.output / "shared-driver-command/stderr.log"))
        record["shared_driver_command"] = command
        result_path = args.output / "six-gates/result.json"
        record["shared_result"] = m2.identity(result_path)
        m2.require(sources == {name: m2.digest(ROOT / name) for name in sources}, "M2 wrapper source changed")
        m2.require(m2.digest(args.build / "monitor-profile.json") == record["profile_sha256"]
                   and m2.digest(args.build / "monitor.elf") == record["monitor_sha256"], "selected M2 build changed")
        m2.require(m2.identity(args.seed_state / "head.json") == record["seed_head"], "private seed changed")
        record["ok"] = command.get("returncode") == 0 and command.get("timed_out") is False \
            and shared.receipt_passes(m2.document(result_path))
        if not record["ok"]:
            record["error"] = "shared guest driver did not finish all six gates; unknown work is not retried"
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
    finally:
        record["finished"] = time.time(); save()
    return record

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("build", "seed-state", "runtime", "resident-result", "restart-result", "restart-command", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--mcp-release", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=1)
    parser.add_argument("--gate-timeout", type=int, default=5400)
    parser.add_argument("--minimum-free-gib", type=float, default=3.5)
    args = parser.parse_args()
    for field in ("build", "seed_state", "runtime", "resident_result", "restart_result", "restart_command"):
        path = getattr(args, field).expanduser()
        if path.is_symlink():
            parser.error(field + " must not be a symlink")
        setattr(args, field, path.resolve(strict=True))
    args.output = args.output.expanduser().absolute()
    try:
        value = run(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(value if not args.execute else
                     {"ok": value["ok"], "full_milestone_qualified": False, "result": str(args.output / "result.json")}))
    return 0 if not args.execute or value["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
