#!/usr/bin/env python3
"""Bind completed M0 evidence to one unchanged compiled source/build closure.

This verifier runs no VM, changes no saved state and publishes no claims.
A receipt is produced only from completed, independently inspectable inputs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import time

from build_okernel_unified_world import SOURCES

ROOT = Path(__file__).resolve().parents[1]
GATES = {
    "two_domains": "verify_okernel_two_domains.py",
    "provider": "verify_okernel_unified_provider.py",
    "client": "verify_okernel_unified_client.py",
    "recovery": "verify_okernel_unified_recovery.py",
    "default_compile": "verify_okernel_p9_default_compile.py",
    "runtime": "verify_okernel_unified_runtime.py",
}
CHILD_SCHEMAS = {
    "two_domains": "ostadix.original-linux-plan9-two-domain-acceptance/v1",
    "provider": "ostadix.unified-original-provider/v1",
    "client": "ostadix.unified-foreground-client/v1",
    "recovery": "ostadix.unified-foreground-client-crash/v1",
    "default_compile": "ostadix.p9-default-compile/v1",
    "runtime": "ostadix.unified-frozen-runtime-acceptance/v1",
}
LIVE_CHECKS = {
    "preclaim-legacy-replacement-invalidates-issued-o10-handle",
    "both-guests-ready-and-governor-claim",
    "stale-handle-gap-stale-epoch-and-malformed-frames-fail-closed",
    "withdraw-journal-retry-and-changed-body-rejection",
    "linux-shell-pid-starttime-and-namespace-survive",
    "restore-new-generation-explicit-bind-and-original-provider-execution",
    "private-fork-paired-save",
}
COMPILED = set(SOURCES) | {
    "ocore/kernel/aarch64/unified_world/monitor.S",
    "ocore/kernel/aarch64/unified_world/linker.ld",
    "ocore/kernel/aarch64/kernel_world/guest.dts",
    "ocore/kernel/aarch64/plan9_probe/guest.dts",
    "scripts/build_okernel_unified_world.py", "scripts/probe_okernel_plan9.py",
}

class EvidenceError(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise EvidenceError(message)

def digest(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "not a regular evidence file: " + str(path))
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def document(path):
    digest(path)
    value = json.loads(Path(path).read_text())
    require(isinstance(value, dict), "JSON object required: " + str(path))
    return value

def identity(path):
    return {"path": str(Path(path).resolve()), "sha256": digest(path)}

def reference(value, label):
    require(isinstance(value, dict) and "path" in value and "sha256" in value, label + " reference missing")
    path = Path(value["path"])
    require(digest(path) == value["sha256"], label + " hash changed")
    return document(path)

def zero(value):
    return type(value) is int and value == 0

def completed(command, label):
    require(isinstance(command, dict), label + " command missing")
    require(zero(command.get("returncode", command.get("rc"))), label + " exit status is not observed zero")
    require(command.get("timed_out") is False, label + " timeout status unknown or failed")
    argv = command.get("argv", command.get("command"))
    require(isinstance(argv, list) and bool(argv) and all(isinstance(x, str) for x in argv), label + " argv missing")
    return argv

def clean(value, label):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in ("skip", "skips", "skipped", "error", "cleanup_stop_error"):
                require(not child, label + " contains " + key)
            if key == "status":
                require(str(child).lower() not in ("skip", "skipped", "error", "failed"), label + " failed status")
            clean(child, label)
    elif isinstance(value, list):
        for child in value:
            clean(child, label)

def relative(root, name):
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts and str(path) == name, "unsafe source path")
    result = root / name
    require(result.resolve().is_relative_to(root.resolve()), "source escaped root")
    return result

def source_hashes(root, hashes, required, label):
    require(isinstance(hashes, dict) and set(hashes) >= set(required), label + " source closure incomplete")
    for name, expected in hashes.items():
        require(digest(relative(root, name)) == expected, label + " source drift: " + name)

def unittest_summary(text, label):
    require(isinstance(text, str), label + " test log missing")
    counts = re.findall(r"^Ran ([0-9]+) tests? in ", text, re.M)
    require(len(counts) == 1 and int(counts[0]) > 0, label + " test count missing")
    require(re.search(r"^OK\s*$", text, re.M) is not None, label + " final OK missing")
    require(not re.search(r"^OK \(|^FAILED|^ERROR:|^FAIL:|\.\.\. skipped", text, re.M), label + " failed or skipped tests")
    return int(counts[0])

def tracked_language(root):
    result = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True)
    return {name for name in result.stdout.decode().split("\0") if name.endswith((".oc", ".O"))}

def session_paths(value):
    # Only these schema fields name executed VM sessions. Nested before/head/
    # previous records describe inherited artifact provenance, not new VMs.
    schema = value.get("schema")
    single = {"ostadix.o10-live-component/v1", CHILD_SCHEMAS["recovery"], CHILD_SCHEMAS["default_compile"]}
    multiple = {CHILD_SCHEMAS[name] for name in ("two_domains", "provider", "client")}
    if schema in single:
        entries = [value.get("session")]
    elif schema in multiple:
        entries = value.get("sessions")
    elif schema == CHILD_SCHEMAS["runtime"]:
        records = value.get("sessions")
        require(isinstance(records, list), "runtime session records missing")
        require(all(isinstance(row, dict) for row in records), "invalid runtime session record")
        entries = [row.get("session") for row in records]
    else:
        raise EvidenceError("unsupported VM session receipt schema")
    require(isinstance(entries, list) and bool(entries), "VM sessions missing")
    require(all(isinstance(path, str) and Path(path).is_absolute() for path in entries),
            "invalid VM session path")
    return set(entries)

def validate_acceptance(*, root, build, live_result, guest_result, component_result,
                        unit_result, provenance, compiler, expected_revision):
    root, build = Path(root).resolve(), Path(build).resolve()
    require(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", expected_revision) is not None, "invalid expected revision")
    profile_path, monitor_path = build / "monitor-profile.json", build / "monitor.elf"
    profile = document(profile_path)
    require(profile.get("schema") == "ostadix.unified-world-monitor/v1", "wrong monitor profile schema")
    monitor_sha, profile_sha = digest(monitor_path), digest(profile_path)
    require(profile.get("artifacts", {}).get("monitor.elf", {}).get("sha256") == monitor_sha, "monitor/profile mismatch")
    source_hashes(root, profile.get("source_sha256"), COMPILED, "compiled")
    for name, expected in profile["source_sha256"].items():
        capture = profile.get("source_artifacts", {}).get(name)
        require(isinstance(capture, dict) and capture.get("sha256") == expected, "compiled source capture missing: " + name)
        require(digest(relative(build, capture["path"])) == expected, "compiled source capture changed: " + name)
    for name, artifact in profile["artifacts"].items():
        require(digest(relative(build, artifact["path"])) == artifact["sha256"], "build artifact changed: " + name)
    compiler_sha = digest(compiler)
    require(profile.get("tools", {}).get("ocorec", {}).get("sha256") == compiler_sha, "compiler/build mismatch")

    wrapped = document(provenance)
    require(wrapped.get("isError", False) is False, "MCP provenance returned an error")
    prov = wrapped.get("structuredContent", wrapped)
    require(prov.get("schema") == "ostadix.runtime-provenance/v1", "wrong MCP provenance schema")
    require(prov.get("buildCommitMatchesRuntimeSource") is True, "MCP release/runtime mismatch")
    for field in ("buildSource", "runtimeSource"):
        require(prov.get(field, {}).get("commit") == expected_revision, "MCP commit mismatch")
    require(prov["runtimeSource"].get("status") == "observed", "MCP runtime source was not observed")
    require(Path(prov["buildSource"].get("sourceRoot", "")).resolve() == root, "MCP build source root mismatch")
    require(Path(prov["runtimeSource"].get("canonicalRoot", "")).resolve() == root, "MCP source root mismatch")
    require(prov.get("binary", {}).get("status") == "hashed" and prov["binary"].get("hashSource") == "running_process_inode",
            "MCP running binary identity missing")
    require(digest(prov["binary"]["canonicalPath"]) == prov["binary"]["sha256"], "MCP binary changed")
    observed_tools = {x["name"]: x["binary"] for x in prov.get("tools", [])}
    require("O" in observed_tools, "observed evaluator missing")

    live, guest, component, unit = map(document, (live_result, guest_result, component_result, unit_result))
    for label, receipt in (("live", live), ("guest", guest), ("component", component), ("unit", unit)):
        require(receipt.get("source_revision") == expected_revision and receipt.get("mcp_release") == expected_revision,
                label + " revision mismatch")
    for label, receipt in (("live", live), ("guest", guest)):
        require(receipt.get("ok") is True, label + " not completed successfully")
        require(receipt.get("monitor_sha256") == monitor_sha and receipt.get("profile_sha256") == profile_sha,
                label + " build/profile binding mismatch")
        require(Path(receipt.get("build", "")).resolve() == build, label + " build path mismatch")
        require(receipt.get("build_tools", {}).get("ocorec", {}).get("sha256") == compiler_sha, label + " compiler mismatch")
        source_hashes(root, receipt.get("source_sha256"), (), label)
    source_hashes(root, live.get("source_sha256"), {"scripts/verify_o10_live.py", "scripts/o10.py",
        "scripts/okernel_unified_world.py", "scripts/verify_okernel_unified_provider.py",
        "ocore/runtime/common/o10_codec.oc", "ocore/runtime/common/o10_executor.oc",
        "ocore/runtime/aarch64/unified_world.oc"}, "live")
    source_hashes(root, guest.get("source_sha256"), {"scripts/" + x for x in GATES.values()} |
        {"scripts/fork_okernel_state.py", "scripts/o10.py", "scripts/okernel_unified_world.py"}, "guest")
    require(live.get("schema") == "ostadix.o10-live-component/v1" and live.get("milestone") == "M0", "wrong live receipt")
    require(set(live.get("checks", [])) >= LIVE_CHECKS and live.get("paired_save") is True, "live checks incomplete")
    legacy = live.get("preclaim_legacy")
    require(isinstance(legacy, dict), "preclaim legacy transition missing")
    old_dom, new_dom = legacy.get("old_dom"), legacy.get("new_dom")
    require(type(old_dom) is int and type(new_dom) is int and
            old_dom == (1 << 32) | 1 and new_dom == (2 << 32) | 1,
            "preclaim legacy domain generation transition invalid")
    legacy_error = legacy.get("old_handle_error", {})
    require(legacy_error.get("type") == "Rerror" and type(legacy_error.get("code")) is int and
            legacy_error["code"] == 5 and type(legacy_error.get("detail")) is int and
            legacy_error["detail"] == 2, "preclaim legacy stale handle evidence invalid")
    require(legacy.get("mailbox_operations") == [1, 2], "preclaim legacy mailbox sequence missing")
    lifecycle = live.get("lifecycle", {})
    restored_dom = lifecycle.get("new_dom")
    require(lifecycle.get("old_dom") == new_dom and type(restored_dom) is int and
            restored_dom == new_dom + (1 << 32), "claimed restore did not advance exactly one generation")
    clean(live, "live")
    require(guest.get("schema") == "ostadix.o10-guest-regressions/v1", "wrong guest receipt")
    require(not guest.get("skips"), "guest tests skipped")
    require(reference(guest.get("live_result"), "guest live") == live, "guest references another live result")
    frozen = reference(guest.get("frozen_runtime"), "frozen runtime")
    require(frozen.get("passed") is True, "frozen runtime not admitted")
    runtime_dir = Path(guest["frozen_runtime"]["path"]).parent
    require(digest(runtime_dir / "build/monitor-profile.json") == profile_sha and
            digest(runtime_dir / "build/monitor.elf") == monitor_sha, "frozen runtime uses another build")
    require(digest(Path(guest["seed_state"]) / "head.json") == guest.get("seed_head_sha256"), "seed head changed")
    entries = guest.get("gates", [])
    require(isinstance(entries, list) and len(entries) == 6, "all six guest gates required")
    require({x.get("gate_id") for x in entries} == set(GATES), "missing or duplicate guest gate")
    sessions = session_paths(live)
    require(bool(sessions), "live session missing")
    require(len({x.get("state") for x in entries}) == 6, "guest states reused")
    child_inputs = []
    for entry in entries:
        label = "guest " + entry["gate_id"]
        require(entry.get("ok") is True and entry.get("script") == GATES[entry["gate_id"]], label + " not passed")
        fork_argv = completed(entry.get("fork"), label + " fork")
        state = Path(entry.get("state", "")).resolve()
        require(state != Path(guest["seed_state"]).resolve(), label + " uses seed directly")
        require("--source" in fork_argv and "--output" in fork_argv, label + " fork arguments missing")
        require(all(fork_argv.index(flag) + 1 < len(fork_argv) for flag in ("--source", "--output")),
                label + " fork argument value missing")
        require(Path(fork_argv[fork_argv.index("--source") + 1]).resolve() == Path(guest["seed_state"]).resolve() and
                Path(fork_argv[fork_argv.index("--output") + 1]).resolve() == state, label + " fork binding mismatch")
        argv = completed(entry.get("command"), label)
        require(any(Path(x).name == GATES[entry["gate_id"]] for x in argv), label + " wrong command")
        child = reference(entry.get("receipt"), label)
        require(child == entry["receipt"].get("result") and child.get("ok") is True and
                child.get("schema") == CHILD_SCHEMAS[entry["gate_id"]], label + " receipt mismatch")
        require(Path(entry["receipt"]["path"]).resolve().is_relative_to(state), label + " receipt outside private fork")
        clean(child, label)
        child_sessions = session_paths(child)
        require(bool(child_sessions), label + " real session missing")
        require(all(Path(x).resolve().is_relative_to(state) for x in child_sessions), label + " session outside private fork")
        sessions |= child_sessions
        child_inputs.append(entry["receipt"])
    for session in sessions:
        session = Path(session)
        require(digest(session / "monitor-profile.json") == profile_sha and
                digest(session / "inputs/monitor.elf") == monitor_sha, "session uses a different build: " + str(session))

    required_tests = {str(p.relative_to(root)) for p in (root / "tests").glob("test_o10_*.py")}
    required_helpers = {str(p.relative_to(root)) for p in (root / "scripts").glob("verify_o10_*.py")}
    source_hashes(root, component.get("source_sha256"), set(SOURCES) | required_tests | required_helpers, "component")
    require(component.get("gate_id") == "verify_o10_journal" and component.get("component_ok") is True and
            component.get("source_unchanged") is True and type(component.get("tests_run")) is int,
            "native/Python components not passed")
    require(zero(component.get("failures")) and zero(component.get("errors")) and not component.get("skips"),
            "native/Python component failed or skipped")
    require(component.get("compiler_sha256") == compiler_sha, "component compiler mismatch")
    component_meta = unit.get("component")
    completed(component_meta, "component wrapper")
    require(reference(component_meta, "component wrapper") == component and
            Path(component_meta["path"]).resolve() == Path(component_result).resolve(), "component wrapper receipt mismatch")
    log_path = Path(component_result).parent / "tests.log"
    log = log_path.read_text()
    require(unittest_summary(log, "component") == component.get("tests_run"), "component count mismatch")
    for name in required_tests:
        require(Path(name).stem + "." in log, "component test module omitted: " + name)

    require(unit.get("schema") == "ostadix.o10-m0-unit-regressions/v1" and unit.get("ok") is True and
            unit.get("source_unchanged") is True, "unit run not complete or source changed")
    require(unit.get("compiler_sha256") == compiler_sha, "unit compiler mismatch")
    require(not unit.get("skips") and not unit.get("error"), "unit failed or skipped")
    okernel_tests = {str(p.relative_to(root)) for p in (root / "tests").glob("test_okernel_*.py")}
    source_hashes(root, unit.get("source_sha256"), okernel_tests | required_tests |
                  {"scripts/check_language_sources.py", "ci/language-sources.json"}, "unit")
    groups = unit.get("results", [])
    require({x.get("group") for x in groups} in ({"all"}, {"normal", "ram-disk"}), "unit groups incomplete")
    require(len(groups) in (1, 2), "duplicate unit groups")
    total = 0
    for group in groups:
        argv = completed(group, "unit " + group["group"])
        require("unittest" in argv, "unit command did not invoke unittest")
        require(group.get("skipped") is False, "unit skip status unknown")
        total += unittest_summary(group.get("summary"), "unit")
    require(total == 288, "all 288 okernel unit tests required")
    language_meta = unit.get("language")
    completed(language_meta, "language source check")
    language = reference(language_meta, "language source check")
    require(language.get("schema") == "ostadix.language-source-check/v1" and language.get("action") == "check",
            "wrong language receipt")
    inventory = tracked_language(root)
    rows = language.get("results", [])
    require(language.get("sources") == 261 and len(rows) == 261 and
            {x.get("path") for x in rows} == inventory and len(inventory) == 261, "complete 261-source parse inventory required")
    for row in rows:
        require(row.get("status") == "passed" and type(row.get("exit_code")) is int, "language source did not pass")
        require(zero(row["exit_code"]) or bool(row.get("expected_failure")), "unexpected language parse failure")
        require(digest(relative(root, row["path"])) == row.get("sha256"), "language source drift")
    require(language.get("binaries", {}).get("ocorec", {}).get("sha256") == compiler_sha, "language compiler mismatch")
    require(language.get("binaries", {}).get("O", {}).get("sha256") == observed_tools["O"].get("sha256"),
            "language evaluator differs from observed MCP tool")

    inputs = {name: identity(path) for name, path in {
        "profile": profile_path, "monitor": monitor_path, "live": live_result, "guest": guest_result,
        "component": component_result, "component_log": log_path, "unit": unit_result,
        "language": language_meta["path"], "provenance": provenance, "compiler": compiler,
    }.items()}
    return {"schema": "ostadix.o10-m0-acceptance/v1", "milestone": "M0", "gate_id": "verify_o10_m0",
            "ok": True, "full_milestone_qualified": True, "source_revision": expected_revision,
            "mcp_release": expected_revision, "monitor_sha256": monitor_sha, "profile_sha256": profile_sha,
            "compiler_sha256": compiler_sha, "inputs": inputs, "guest_gate_ids": sorted(GATES),
            "guest_receipts": child_inputs, "sessions_checked": sorted(sessions),
            "okernel_unit_tests": total, "component_tests": component["tests_run"], "language_sources": 261,
            "skips": [], "finished": time.time(),
            "scope": "M0 O10 host shim and synchronous journal on this exact AArch64 QEMU/TCG build, Python/native components and all specified regression gates; no physical hardware or later milestones"}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("build", "live-result", "guest-result", "component-result", "unit-result", "provenance", "compiler", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--supersedes", type=Path, action="append", default=[])
    args = parser.parse_args()
    output = args.output.expanduser()
    if output.exists() or output.is_symlink():
        parser.error("output must be a new receipt; historical evidence is preserved")
    record = {"schema": "ostadix.o10-m0-acceptance/v1", "milestone": "M0", "ok": False,
              "full_milestone_qualified": False, "started": time.time()}
    try:
        record.update(validate_acceptance(root=ROOT, build=args.build, live_result=args.live_result,
            guest_result=args.guest_result, component_result=args.component_result, unit_result=args.unit_result,
            provenance=args.provenance, compiler=args.compiler, expected_revision=args.expected_revision))
        record["superseded_evidence"] = [identity(path) for path in args.supersedes]
        record["supersession_scope"] = "Historical files remain unchanged; this receipt supersedes only their qualification conclusion."
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        record["error"] = type(error).__name__ + ": " + str(error)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"ok": record["ok"], "result": str(output)}))
    return 0 if record["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
