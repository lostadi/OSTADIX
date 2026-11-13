#!/usr/bin/env python3
"""Bind completed M1 evidence to one unchanged compiled source/build closure.

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
            if key in ("skip", "skips", "skipped", "error", "cleanup_stop_error", "cleanup_error"):
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


def bytes_field(value, label):
    require(isinstance(value, dict) and set(value) == {"bytes_hex"} and
            isinstance(value["bytes_hex"], str), label + " bytes missing")
    try:
        return bytes.fromhex(value["bytes_hex"])
    except ValueError as error:
        raise EvidenceError(label + " invalid bytes") from error

def provider_capture(root, session, counter):
    import importlib.util
    import sys
    module_path = root / "ocore/guest/plan9/unified/protocol.py"
    spec = importlib.util.spec_from_file_location("o10_m1_proof_protocol", module_path)
    protocol = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = protocol
    spec.loader.exec_module(protocol)
    directory = session / "o10-hostile-provider"
    invocation = document(directory / "invocation.json")
    require(invocation.get("id") == counter.get("request_id"), "counter request identity mismatch")
    files = {name: (directory / name).read_bytes() for name in
             ("request", "submit", "started", "done", "status", "stdout", "stderr", "result")}
    request = protocol.validate_submit(files["request"], files["submit"])
    expected_loop = "for(i in 0 1 2 3 4 5 6 7) { echo $i; sleep 1 } > " + counter["path"]
    require(request.request_id == counter["request_id"] and
            request.argv == ("/bin/rc", "-c", expected_loop) and request.cwd == "/n/work" and
            request.stdin == b"" and request.timeout_ms == 120000, "counter provider corpus mismatch")
    require(invocation.get("service") == {"generation": request.generation, "instance": request.instance},
            "counter provider service identity mismatch")
    result = protocol.validate_result(files["request"], files["result"], files["stdout"], files["stderr"],
        started=files["started"], done=files["done"], status=files["status"])
    require(result.ok, "original provider counter did not finish successfully")
    return [identity(directory / name) for name in ("invocation.json", *files)]

def validate_resident(root, receipt_path, build, profile, expected_revision, *, hostile=False):
    receipt = document(receipt_path)
    label = "hostile MMIO" if hostile else "resident"
    gate_id = "verify_o10_hostile_mmio" if hostile else "verify_o10_resident"
    require(receipt.get("schema") == "ostadix.o10-resident-gate/v1" and
            receipt.get("milestone") == "M1" and receipt.get("gate_id") == gate_id, label + " wrong receipt")
    require(receipt.get("gate_passed") is True and receipt.get("milestone_qualified") is False,
            label + " gate not passed or claims exceed component gate")
    require(receipt.get("source_revision") == expected_revision and
            receipt.get("mcp_release") == expected_revision, label + " source/MCP mismatch")
    require(reference(receipt.get("build"), label + " build") == profile and
            Path(receipt["build"]["path"]).resolve() == build / "monitor-profile.json", label + " build mismatch")
    require(receipt.get("checked_build_sources") == profile["source_sha256"] and
            receipt.get("build_sources_unchanged") is True, label + " compiled closure unverified")
    artifacts = receipt.get("source_artifacts", {})
    required = {"scripts/verify_o10_resident.py", "scripts/okernel_unified_world.py", "scripts/o10.py"}
    if hostile:
        required |= {"scripts/verify_o10_hostile_mmio.py", "scripts/verify_okernel_unified_provider.py"}
    require(set(artifacts) >= required, label + " gate source capture incomplete")
    for name, record in artifacts.items():
        require(Path(record["path"]).resolve().is_relative_to(Path(receipt_path).resolve().parent),
                label + " gate source capture outside session")
        require(digest(relative(root, name)) == record.get("sha256") and
                digest(record["path"]) == record["sha256"], label + " gate source drift")
    clean(receipt, label)
    require(isinstance(receipt.get("host"), dict) and bool(receipt["host"]), label + " host missing")
    argv = receipt.get("qemu_argv")
    require(isinstance(argv, list) and len(argv) > 2 and all(isinstance(x, str) for x in argv)
            and "-machine" in argv and any("virt" in x for x in argv), label + " actual QEMU argv missing")
    outer = Path(receipt.get("session", "")).resolve()
    require(Path(receipt_path).resolve().parent == outer, label + " receipt session mismatch")
    state = outer / "state"
    fork = receipt.get("fork", {})
    require(fork.get("schema") == "ostadix.okernel-state-fork/v1" and fork.get("ok") is True and
            Path(fork.get("output", "")).resolve() == state and
            Path(fork.get("source", "")).resolve() == Path(receipt.get("source_state", "")).resolve() and
            state != Path(receipt["source_state"]).resolve(), label + " private fork missing")
    require(fork.get("source_head_changed_during_copy") is False, label + " source head moved during fork")
    session = Path(receipt.get("guest_session", "")).resolve()
    require(session.is_relative_to(state), label + " runtime session outside private fork")
    require(digest(session / "monitor-profile.json") == digest(build / "monitor-profile.json") and
            digest(session / "inputs/monitor.elf") == digest(build / "monitor.elf"), label + " VM uses another build")
    duration = receipt.get("zero_runnable_seconds")
    require(type(duration) in (int, float) and 60 <= duration < float("inf"), label + " resident window shorter than 60 seconds")
    samples = receipt.get("samples")
    require(isinstance(samples, list) and len(samples) >= 2, label + " repeated resident observations missing")
    previous = -1.0
    first_linux = samples[0].get("linux", {})
    first_plan9 = samples[0].get("plan9", {})
    linux_dom, plan9_dom = first_linux.get("dom"), first_plan9.get("dom")
    require(type(linux_dom) is int and type(plan9_dom) is int and linux_dom != plan9_dom and
            linux_dom >> 32 > 0 and plan9_dom >> 32 > 0, label + " domain handles invalid")
    for sample in samples:
        seconds = sample.get("seconds")
        require(type(seconds) in (int, float) and previous < seconds <= duration, label + " observation time invalid")
        previous = seconds
        for key, wanted, initial in (("linux", 4, first_linux), ("plan9", 5, first_plan9)):
            stat = sample.get(key, {})
            require(stat.get("type") == "Rstat" and stat.get("state") == wanted and
                    stat.get("dom") == initial.get("dom") and stat.get("inst") == initial.get("inst") and
                    stat.get("leases") == 0, label + " stopped domain changed or holds leases")
        require(type(sample.get("counters", {}).get("live_domains")) is int and
                sample["counters"]["live_domains"] == 0, label + " runnable guest during resident window")
    require(samples[0]["seconds"] < 1 and samples[-1]["seconds"] >= 59,
            label + " observations do not span the resident window")
    expected_source = "actual Linux guest MMIO" if hostile else "qualification Tinjection fault1"
    require(receipt.get("linux_fault_source") == expected_source, label + " wrong fault source")
    fault = receipt.get("linux_fault", {})
    require(fault.get("dom") == linux_dom, label + " fault names another domain")
    captures = []
    if hostile:
        require(fault.get("type") == "Rstat" and fault.get("state") == 4 and
                type(fault.get("esr")) is int and fault["esr"] >> 26 == 0x24 and
                fault.get("ipa") == 0x0a0000fc, "hostile MMIO fault ESR/IPA mismatch")
        require(receipt.get("mmio_commands") == ['test "$(busybox devmem 0x0a000000 32)" = 0x74726976',
            "busybox devmem 0x0a0000fc 32 1"], "hostile MMIO command corpus mismatch")
        counter = receipt.get("plan9_counter", {})
        before, after = bytes_field(counter.get("before"), "counter before"), bytes_field(counter.get("after"), "counter after")
        require(before and after == b"0\n1\n2\n3\n4\n5\n6\n7\n" and after.startswith(before) and len(after) > len(before),
                "Plan9 counter did not advance across Linux fault")
        a, b = counter.get("domain_before", {}), counter.get("domain_after", {})
        require(a.get("type") == b.get("type") == "Rstat" and a.get("state") == b.get("state") == 2 and
                a.get("dom") == b.get("dom") == plan9_dom and a.get("inst") == b.get("inst") == first_plan9.get("inst"),
                "Plan9 counter instance changed")
        require(isinstance(counter.get("path"), str) and counter["path"].startswith("/n/work/o10-hostile-"),
                "counter namespace path invalid")
        captures = provider_capture(root, session, counter)
    else:
        require(fault.get("type") == "Rinject", "resident gate did not use Tinjection")
    provider = receipt.get("provider", {})
    service = provider.get("service", {})
    generation, instance = service.get("generation"), service.get("instance")
    require(isinstance(generation, str) and re.fullmatch(r"[0-9a-f]{16}", generation) and
            isinstance(instance, str) and re.fullmatch(r"[0-9a-f]{32}", instance), label + " provider identity invalid")
    require(provider.get("path") == f"/services/plan9/g{generation}/s{instance}/ready" and
            provider.get("sha256") == hashlib.sha256(f"OC9READY1 {generation} {instance}\n".encode()).hexdigest(),
            label + " fresh provider marker invalid")
    stat = provider.get("stat", {})
    require(stat.get("type") == "Rstat" and stat.get("state") == 2 and stat.get("dom") == plan9_dom + (1 << 32)
            and stat.get("inst") != first_plan9.get("inst"), label + " provider restore generation invalid")
    return receipt, {str(session)}, captures

def validate_acceptance(*, root, build, resident_result, hostile_mmio_result, guest_result, component_result,
                        unit_result, provenance, compiler, expected_revision):
    root, build = Path(root).resolve(), Path(build).resolve()
    require(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", expected_revision) is not None, "invalid expected revision")
    profile_path, monitor_path = build / "monitor-profile.json", build / "monitor.elf"
    profile = document(profile_path)
    require(profile.get('o10_qualification') is True, 'M1 qualification build required')
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

    guest, component, unit = map(document, (guest_result, component_result, unit_result))
    for label, receipt in (("guest", guest), ("component", component), ("unit", unit)):
        require(receipt.get("source_revision") == expected_revision and receipt.get("mcp_release") == expected_revision,
                label + " revision mismatch")
    require(guest.get("ok") is True and guest.get("milestone") == "M1", "guest not completed successfully")
    require(guest.get("monitor_sha256") == monitor_sha and guest.get("profile_sha256") == profile_sha,
            "guest build/profile binding mismatch")
    require(Path(guest.get("build", "")).resolve() == build, "guest build path mismatch")
    require(guest.get("build_tools", {}).get("ocorec", {}).get("sha256") == compiler_sha, "guest compiler mismatch")
    source_hashes(root, guest.get("source_sha256"), {"scripts/" + x for x in GATES.values()} |
        {"scripts/fork_okernel_state.py", "scripts/o10.py", "scripts/okernel_unified_world.py",
         "scripts/verify_o10_m1_regressions.py"}, "guest")
    resident, resident_sessions, resident_captures = validate_resident(root, resident_result, build, profile, expected_revision)
    hostile, hostile_sessions, hostile_captures = validate_resident(root, hostile_mmio_result, build, profile, expected_revision, hostile=True)
    require(resident_sessions.isdisjoint(hostile_sessions), "M1 live gates reused a VM session")
    require(Path(resident["fork"]["output"]).resolve() != Path(hostile["fork"]["output"]).resolve(),
            "M1 live gates reused a private state")
    require(guest.get("schema") == "ostadix.o10-guest-regressions/v1", "wrong guest receipt")
    require(not guest.get("skips"), "guest tests skipped")
    require(reference(guest.get("resident_result"), "guest resident") == resident, "guest references another resident result")
    require(reference(guest.get("hostile_mmio_result"), "guest hostile MMIO") == hostile, "guest references another hostile MMIO result")
    frozen = reference(guest.get("frozen_runtime"), "frozen runtime")
    require(frozen.get("passed") is True, "frozen runtime not admitted")
    runtime_dir = Path(guest["frozen_runtime"]["path"]).parent
    require(digest(runtime_dir / "build/monitor-profile.json") == profile_sha and
            digest(runtime_dir / "build/monitor.elf") == monitor_sha, "frozen runtime uses another build")
    require(digest(Path(guest["seed_state"]) / "head.json") == guest.get("seed_head_sha256"), "seed head changed")
    entries = guest.get("gates", [])
    require(isinstance(entries, list) and len(entries) == 6, "all six guest gates required")
    require({x.get("gate_id") for x in entries} == set(GATES), "missing or duplicate guest gate")
    sessions = resident_sessions | hostile_sessions
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

    require(unit.get("schema") == "ostadix.o10-m1-unit-regressions/v1" and unit.get("ok") is True and
            unit.get("source_unchanged") is True, "unit run not complete or source changed")
    require(unit.get("compiler_sha256") == compiler_sha, "unit compiler mismatch")
    require(not unit.get("skips") and not unit.get("error"), "unit failed or skipped")
    okernel_tests = {str(p.relative_to(root)) for p in (root / "tests").glob("test_okernel_*.py")}
    source_hashes(root, unit.get("source_sha256"), okernel_tests | required_tests |
                  {"scripts/check_language_sources.py", "ci/language-sources.json", "ocore/guest/plan9/unified/protocol.py"}, "unit")
    groups = unit.get("results", [])
    require({x.get("group") for x in groups} in ({"all"}, {"normal", "ram-disk"}), "unit groups incomplete")
    require(len(groups) in (1, 2), "duplicate unit groups")
    total = 0
    for group in groups:
        argv = completed(group, "unit " + group["group"])
        require("unittest" in argv, "unit command did not invoke unittest")
        require(group.get("skipped") is False, "unit skip status unknown")
        total += unittest_summary(group.get("summary"), "unit")
    require(total > 0, "okernel unit tests missing")
    unit_logs = []
    for group in groups:
        log_record = group.get("log")
        require(isinstance(log_record, dict) and digest(log_record["path"]) == log_record.get("sha256"),
                "unit full log hash missing or changed")
        text = Path(log_record["path"]).read_text()
        require(unittest_summary(text, "unit full log") == unittest_summary(group["summary"], "unit summary"),
                "unit summary/full log count mismatch")
        unit_logs.append(text)
    for name in okernel_tests:
        require(any(Path(name).stem + "." in text for text in unit_logs), "okernel test module omitted: " + name)
    language_meta = unit.get("language")
    completed(language_meta, "language source check")
    language = reference(language_meta, "language source check")
    require(language.get("schema") == "ostadix.language-source-check/v1" and language.get("action") == "check",
            "wrong language receipt")
    inventory = tracked_language(root)
    rows = language.get("results", [])
    require(language.get("sources") == len(inventory) and len(rows) == len(inventory) and
            {x.get("path") for x in rows} == inventory and bool(inventory), "complete current language-source parse inventory required")
    for row in rows:
        require(row.get("status") == "passed" and type(row.get("exit_code")) is int, "language source did not pass")
        require(zero(row["exit_code"]) or bool(row.get("expected_failure")), "unexpected language parse failure")
        require(digest(relative(root, row["path"])) == row.get("sha256"), "language source drift")
    require(language.get("binaries", {}).get("ocorec", {}).get("sha256") == compiler_sha, "language compiler mismatch")
    require(language.get("binaries", {}).get("O", {}).get("sha256") == observed_tools["O"].get("sha256"),
            "language evaluator differs from observed MCP tool")

    inputs = {name: identity(path) for name, path in {
        "profile": profile_path, "monitor": monitor_path, "resident": resident_result, "hostile_mmio": hostile_mmio_result, "guest": guest_result,
        "component": component_result, "component_log": log_path, "unit": unit_result,
        "language": language_meta["path"], "provenance": provenance, "compiler": compiler,
    }.items()}
    return {"schema": "ostadix.o10-m1-acceptance/v1", "milestone": "M1", "gate_id": "verify_o10_m1",
            "ok": True, "full_milestone_qualified": True, "source_revision": expected_revision,
            "mcp_release": expected_revision, "monitor_sha256": monitor_sha, "profile_sha256": profile_sha,
            "compiler_sha256": compiler_sha, "inputs": inputs, "guest_gate_ids": sorted(GATES),
            "guest_receipts": child_inputs, "sessions_checked": sorted(sessions),
            "okernel_unit_tests": total, "component_tests": component["tests_run"], "language_sources": len(inventory), "live_captures": resident_captures + hostile_captures,
            "skips": [], "finished": time.time(),
            "scope": "M1 resident EL2 control for at least 60 seconds with both guests stopped, qualification Tinjection and additional actual hostile Linux MMIO survivor corpus, classified native paths, and full regressions on this exact AArch64 QEMU build; no physical hardware or later milestones"}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("build", "resident-result", "hostile-mmio-result", "guest-result", "component-result", "unit-result", "provenance", "compiler", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--supersedes", type=Path, action="append", default=[])
    args = parser.parse_args()
    output = args.output.expanduser()
    if output.exists() or output.is_symlink():
        parser.error("output must be a new receipt; historical evidence is preserved")
    record = {"schema": "ostadix.o10-m1-acceptance/v1", "milestone": "M1", "ok": False,
              "full_milestone_qualified": False, "started": time.time()}
    try:
        record.update(validate_acceptance(root=ROOT, build=args.build, resident_result=args.resident_result, hostile_mmio_result=args.hostile_mmio_result,
            guest_result=args.guest_result, component_result=args.component_result, unit_result=args.unit_result,
            provenance=args.provenance, compiler=args.compiler, expected_revision=args.expected_revision))
        record["superseded_evidence"] = [identity(path) for path in args.supersedes]
        record["supersession_scope"] = "Historical files remain unchanged; this receipt supersedes only their qualification conclusion."
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ImportError, SyntaxError, subprocess.SubprocessError) as error:
        record["error"] = type(error).__name__ + ": " + str(error)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"ok": record["ok"], "result": str(output)}))
    return 0 if record["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
