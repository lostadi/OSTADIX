#!/usr/bin/env python3
"""Bind original Draft 0 M2 evidence to one source, toolchain and QEMU artifact.

This read-only verifier starts no VM and publishes no claim. Component fixtures
are not execution evidence; the actual restart command, raw wire observations,
resident proof, six guest exits and complete ordinary inventories are required.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import importlib.util
import sys
import json
import math
from pathlib import Path
import re
import shlex
import subprocess
import time

import o10
import verify_o10_m1 as shared
import verify_o10_linux_restart as restart

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "O10-Draft0-M2"
RESTART_SCHEMA = "ostadix.o10-linux-restart-gate/v1"
REGRESSION_SCHEMA = "ostadix.o10-m2-guest-regressions/v1"
UNIT_SCHEMAS = {"ostadix.o10-m1-unit-regressions/v1", "ostadix.o10-m2-unit-regressions/v1"}
# Draft 0 section 7: a healthy domain alternates RUNNING and BLOCKED at WFI.
HEALTHY_STATES = frozenset((2, 3))
require = shared.require
digest = shared.digest
document = shared.document
identity = shared.identity
reference = shared.reference
completed = shared.completed
relative = shared.relative
source_hashes = shared.source_hashes
clean = shared.clean

RESTART_SOURCES = {
    "scripts/verify_o10_linux_restart.py", "tests/test_o10_linux_restart.py",
    "scripts/okernel_unified_world.py", "scripts/fork_okernel_state.py",
    "scripts/verify_okernel_unified_provider.py",
    "ocore/guest/plan9/unified/protocol.py", "ocore/guest/plan9/unified/p9cmdsrv.c",
}
NEW_SOURCES = {
    "scripts/verify_o10_m2.py", "tests/test_o10_m2.py",
    "scripts/verify_o10_m2_regressions.py", "tests/test_o10_m2_regressions.py",
}

def raw_reference(row, label, *, under=None, tool=False):
    require(isinstance(row, dict) and isinstance(row.get("path"), str)
            and re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")) is not None,
            label + " reference missing")
    original = Path(row["path"])
    path = original.resolve() if tool else original
    require(digest(path) == row["sha256"], label + " bytes changed")
    if "bytes" in row:
        require(type(row["bytes"]) is int and path.stat().st_size == row["bytes"], label + " length changed")
    if under is not None:
        require(path.resolve().is_relative_to(Path(under).resolve()), label + " outside its evidence session")
    return path

def b64(row, field):
    require(isinstance(row, dict) and isinstance(row.get(field), str), "raw guest output missing: " + field)
    try:
        return base64.b64decode(row[field], validate=True)
    except (ValueError, TypeError) as error:
        raise shared.EvidenceError("invalid guest output encoding: " + field) from error

def validate_build(root, build, compiler=None):
    root, build = Path(root).resolve(), Path(build).resolve()
    profile = document(build / "monitor-profile.json")
    require(profile.get("schema") == "ostadix.unified-world-monitor/v1"
            and profile.get("o10_qualification") is True, "M2 qualification profile required")
    require(profile.get("linux_recovery", {}).get("namespace_version") == "9P2000.u"
            and profile.get("plan9_recovery") and profile.get("plan9_command_provider")
            and profile.get("o10_linux_restart_witness") == restart.WITNESS_CONTRACT,
            "M2 immutable-image, original-provider and native-witness contract required")
    source_hashes(root, profile.get("source_sha256"), shared.COMPILED, "compiled")
    for name, expected in profile["source_sha256"].items():
        capture = profile.get("source_artifacts", {}).get(name)
        require(isinstance(capture, dict) and capture.get("sha256") == expected,
                "compiled source capture missing: " + name)
        require(digest(relative(build, capture["path"])) == expected, "compiled capture changed: " + name)
    for name, row in profile.get("artifacts", {}).items():
        require(digest(relative(build, row["path"])) == row["sha256"], "build artifact changed: " + name)
    require(profile.get("artifacts", {}).get("monitor.elf", {}).get("sha256") == digest(build / "monitor.elf"),
            "monitor/profile mismatch")
    if compiler is not None:
        require(profile.get("tools", {}).get("ocorec", {}).get("sha256") == digest(compiler),
                "compiler/build mismatch")
    return profile

def validate_command(path, *, label="restart"):
    row = document(path)
    argv = completed(row, label)
    require(any(Path(word).name == "verify_o10_linux_restart.py" for word in argv)
            or "o10-linux-restart" in argv, label + " command is not the canonical restart gate")
    for stream in ("stdout", "stderr"):
        raw_reference(row.get(stream), label + " " + stream)
    return row

def decode_exchanges(rows):
    require(isinstance(rows, list) and rows, "actual O10 exchanges missing")
    result = []
    for row in rows:
        require(isinstance(row, dict) and row.get("completion") == "observed", "unknown O10 exchange")
        try:
            request = o10.decode(bytes.fromhex(row["request_hex"]))
            reply = o10.decode(bytes.fromhex(row["reply_hex"]))
        except (ValueError, KeyError, TypeError) as error:
            raise shared.EvidenceError("malformed raw O10 exchange") from error
        require(request["type"].startswith("T") and reply["tag"] == request["tag"],
                "O10 request/reply tag mismatch")
        expected = "R" + request["type"][1:]
        require(reply["type"] in (expected, "Rerror"), "O10 reply type mismatch")
        require(row.get("reply") == restart.safe(reply), "O10 decoded/raw reply differs")
        result.append((request, reply))
    return result

def validate_counter(value):
    require(isinstance(value, dict) and isinstance(value.get("path"), str)
            and value["path"].startswith("/services/plan9/"), "Plan9 counter subtree missing")
    samples = value.get("samples")
    require(isinstance(samples, list) and len(samples) >= 3, "Plan9 counter progress missing")
    before = -1.0
    for index, row in enumerate(samples):
        lo, hi = row.get("earliest_host_seconds"), row.get("observed_host_seconds")
        require(row.get("counter") == index and type(lo) in (int, float) and type(hi) in (int, float)
                and math.isfinite(lo) and math.isfinite(hi) and 0 <= lo <= hi
                and hi >= before, "counter observation brackets invalid")
        before = hi
    try:
        data = bytes.fromhex(value["bytes_hex"])
    except (ValueError, TypeError, KeyError) as error:
        raise shared.EvidenceError("counter bytes missing") from error
    complete = b"".join((str(i) + "\n").encode() for i in range(len(samples)))
    require(data.startswith(complete) and (str(len(samples)) + "\n").encode().startswith(data[len(complete):]),
            "counter append order or retained bytes changed")
    pairs = list(zip(samples, samples[1:]))
    gap = max(b["observed_host_seconds"] - a["observed_host_seconds"] for a, b in pairs)
    bound = max(b["observed_host_seconds"] - a["earliest_host_seconds"] for a, b in pairs)
    require(value.get("largest_observed_gap_seconds") == gap
            and value.get("largest_append_gap_upper_bound_seconds") == bound
            and "host" in value.get("timing_scope", ""), "counter maximum gap was not derived from observations")
    return value

def validate_configuration_uploads(receipt, fixture, prefix, outer):
    rows = receipt.get("guest_configuration_uploads")
    require(isinstance(rows, list) and len(rows) == 2, "both guest configuration uploads required")
    configs = []
    for row in rows:
        require(isinstance(row.get("guest_path", row.get("path")), str), "guest configuration path missing")
        source = row.get("source")
        path = raw_reference(source, "guest configuration source", under=outer)
        data = path.read_bytes()
        require(row.get("sha256") == hashlib.sha256(data).hexdigest()
                and row.get("bytes") == len(data), "guest configuration upload bytes differ")
        value = json.loads(data)
        require(isinstance(value, dict) and value.get("fixture") == fixture, "uploaded fixture differs")
        configs.append(value)
    first, restored = configs
    require("durable_prefix" not in first and restored.get("durable_prefix") == prefix,
            "restored configuration did not preserve the actual durable prefix")
    require({k: v for k, v in restored.items() if k != "durable_prefix"} == first,
            "post-restore configuration replayed or changed the workload")
    token = first.get("nonce")
    require(isinstance(token, str) and re.fullmatch(r"[0-9a-f]{24}", token) is not None,
            "qualification nonce missing")
    require(first.get("run") == "/run/o10-m2-" + token
            and first.get("file") == "/work/o10-m2-" + token + "/file64MiB", "workload path mismatch")
    expected_hook = restart.APK_COMMIT_HOOK_TEMPLATE.replace(b"@NONCE@", token.encode()).replace(
        b"@RUN@", first["run"].encode())
    require(base64.b64decode(first.get("commit_hook_base64", ""), validate=True) == expected_hook,
            "APK hook differs from the declared controlled interruption")
    for row in rows:
        require(row.get("guest_path", row.get("path")) == first["run"] + ".json",
                "configuration upload used another guest path")
    return first

def validate_worker_launch(commands, config, *, outer):
    require(isinstance(commands, list), "worker command trace missing")
    workers = [(i, row) for i, row in enumerate(commands) if " worker " in row.get("command", "")]
    expected = ("{ PYTHONDONTWRITEBYTECODE=1 python3 " + shlex.quote(config["run"] + ".py") +
                " worker " + shlex.quote(config["run"] + ".json") +
                " > " + shlex.quote(config["run"] + "/worker.stdout") +
                " 2> " + shlex.quote(config["run"] + "/worker.stderr") + " & }")
    require(len(workers) == 1 and workers[0][1].get("command") == expected,
            "worker launch helper, config, redirections or grouped corpus differs")
    index, row = workers[0]
    require(row.get("completion") == "observed" and row.get("returncode") == 0,
            "worker launch failed or has an unknown outcome")
    raw_reference(row.get("combined_console"), "worker launch console", under=outer)
    return index

def validate_provider_counter(root, receipt, config, *, outer):
    module_path = Path(root) / "ocore/guest/plan9/unified/protocol.py"
    spec = importlib.util.spec_from_file_location("o10_m2_counter_protocol", module_path)
    protocol = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = protocol; spec.loader.exec_module(protocol)
    invocation = receipt.get("plan9_counter_request", {})
    raw = shared.bytes_field(invocation.get("request"), "counter request")
    request = protocol.decode_request(raw)
    service = {"generation": request.generation, "instance": request.instance}
    path = "/services/plan9/g" + request.generation + "/s" + request.instance + "/m2-counter-" + config["nonce"]
    require(invocation.get("id") == request.request_id and invocation.get("service") == service
            and receipt["plan9_counter"]["path"] == path and request.cwd == "/n/work"
            and request.stdin == b"" and request.timeout_ms == 300000
            and request.argv == ("/arm64/bin/rc", "-I", "-c", restart.plan9_counter_command(path)),
            "original counter request corpus differs")
    paths = protocol.request_paths("/n/okernel/services/plan9",
                                   request.generation, request.instance, request.request_id)
    require(invocation.get("paths") == paths, "counter publication paths differ")
    marker = protocol.submit_marker(raw)
    require(invocation.get("phase") == "submitted"
            and shared.bytes_field(invocation.get("submit_marker"), "counter submit marker") == marker,
            "counter publication is incomplete or has another submit marker")
    publications = invocation.get("publication")
    require(isinstance(publications, list) and len(publications) == 2,
            "both counter publication phases required")
    commands = receipt.get("guest_commands")
    require(isinstance(commands, list), "counter command trace missing")
    positions = []
    def observed_once(command):
        matches = [(i, row) for i, row in enumerate(commands) if row.get("command") == command]
        require(len(matches) == 1, "counter publication command missing or repeated")
        index, row = matches[0]
        require(row.get("completion") == "observed" and row.get("returncode") == 0,
                "counter publication command failed or has an unknown outcome")
        raw_reference(row.get("combined_console"), "counter publication console", under=outer)
        positions.append(index)
    for row, phase, data, destination in zip(publications, ("request", "submit"), (raw, marker),
                                             (paths["request"], paths["submit"] + ".staged")):
        staging = "/run/o10-m2-counter-" + request.request_id + "." + phase
        expected = hashlib.sha256(data).hexdigest()
        require(isinstance(row, dict) and row.get("phase") == phase
                and row.get("destination") == destination
                and row.get("bytes") == len(data) and row.get("sha256") == expected
                and row.get("staging") == {"path": staging, "bytes": len(data), "sha256": expected},
                "counter staging path, phase, bytes or digest differs")
        temporary = staging + ".o10-base64"
        observed_once(": > " + shlex.quote(temporary))
        encoded = base64.b64encode(data).decode()
        for offset in range(0, len(encoded), 512):
            observed_once("printf %s " + shlex.quote(encoded[offset:offset+512]) + " >> " + shlex.quote(temporary))
        observed_once("base64 -d " + shlex.quote(temporary) + " > " + shlex.quote(staging) +
                      " && rm " + shlex.quote(temporary) + " && test \"$(wc -c < " + shlex.quote(staging) +
                      ")\" -eq " + str(len(data)) + " && test \"$(sha256sum " + shlex.quote(staging) +
                      " | cut -d ' ' -f1)\" = " + expected)
        command = ("cat " + shlex.quote(staging) + " > " + shlex.quote(destination) +
                   " && test \"$(wc -c < " + shlex.quote(destination) + ")\" -eq " + str(len(data)) +
                   " && test \"$(sha256sum " + shlex.quote(destination) +
                   " | cut -d ' ' -f1)\" = " + expected)
        require(row.get("command") == command, "counter namespace copy corpus differs")
        observed_once(command)
    submit = "mv " + shlex.quote(paths["submit"] + ".staged") + " " + shlex.quote(paths["submit"])
    require(invocation.get("submit_command") == submit, "counter submission barrier differs")
    observed_once(submit)
    worker_index = validate_worker_launch(commands, config, outer=outer)
    require(positions == sorted(set(positions)) and positions[-1] < worker_index,
            "counter staging, publication, submission or worker ordering differs")
    return service

def validate_restart(*, root, receipt_path, build, profile, expected_revision, command_path=None):
    root, build = Path(root).resolve(), Path(build).resolve()
    outer = Path(receipt_path).resolve().parent
    receipt = document(receipt_path)
    require(receipt.get("schema") == RESTART_SCHEMA and receipt.get("milestone") == "M2"
            and receipt.get("gate_id") == "verify_o10_linux_restart", "wrong M2 restart receipt")
    require(receipt.get("gate_passed") is True and receipt.get("milestone_qualified") is False
            and receipt.get("source_unchanged") is True, "M2 restart did not finish successfully")
    require(receipt.get("source_revision") == expected_revision
            and receipt.get("mcp_release") == expected_revision, "restart source/MCP mismatch")
    require(reference(receipt.get("build"), "restart build") == profile
            and Path(receipt["build"]["path"]).resolve() == build / "monitor-profile.json", "restart build mismatch")
    source_hashes(root, receipt.get("source_sha256"), set(profile["source_sha256"]) | RESTART_SOURCES, "restart")
    require(set(receipt.get("source_artifacts", {})) == set(receipt["source_sha256"]), "restart source capture incomplete")
    for name, row in receipt["source_artifacts"].items():
        require(digest(raw_reference(row, "restart source", under=outer)) == receipt["source_sha256"][name],
                "restart captured source changed")
    clean(receipt, "restart")
    fork = receipt.get("fork", {})
    state = outer / "state"
    require(fork.get("schema") == "ostadix.okernel-state-fork/v1" and fork.get("ok") is True
            and fork.get("source_head_changed_during_copy") is False
            and Path(fork.get("output", "")).resolve() == state
            and Path(fork.get("source", "")).resolve() != state, "restart private fork missing")
    seed_head = raw_reference(receipt.get("seed_head_before"), "restart seed")
    require(seed_head.resolve() == Path(fork["source"]).resolve() / "head.json", "restart seed binding mismatch")
    session = Path(receipt.get("guest_session", "")).resolve()
    require(session.is_relative_to(state), "restart runtime session escaped fork")
    require(digest(session / "monitor-profile.json") == digest(build / "monitor-profile.json")
            and digest(session / "inputs/monitor.elf") == digest(build / "monitor.elf"), "restart VM used another build")
    qemu = receipt.get("qemu_argv")
    require(isinstance(qemu, list) and len(qemu) > 2 and "-machine" in qemu
            and any("virt" in arg for arg in qemu), "actual restart QEMU command missing")
    if command_path is not None:
        command = validate_command(command_path)
        argv = command.get("argv", command.get("command"))
        cwd = Path(command.get("cwd", root)).resolve()
        for flag, expected in (("--build", build), ("--output", outer),
                               ("--seed-state", Path(fork["source"]).resolve()),
                               ("--apk-fixture", Path(receipt.get("fixture", {}).get("path", "")).resolve())):
            require(flag in argv and argv.index(flag) + 1 < len(argv), "restart argument missing: " + flag)
            observed = Path(argv[argv.index(flag) + 1])
            require((observed if observed.is_absolute() else cwd / observed).resolve() == expected,
                    "restart command selected another input: " + flag)
        require("--mcp-release" in argv and argv.index("--mcp-release") + 1 < len(argv)
                and argv[argv.index("--mcp-release") + 1] == expected_revision, "restart command revision differs")

    before = restart.validate_witness(receipt.get("witness_before"), "capture")
    prior_sequence = before["sequence"]
    for field in ("witness_faulted", "witness_restored", "witness_final"):
        observed = restart.validate_witness(receipt.get(field), "check", before)
        require(observed["sequence"] > prior_sequence, "native witness sequence did not advance")
        prior_sequence = observed["sequence"]
    require(receipt.get("plan9_fid_lifetime_confound") == restart.FID_LIFETIME_NOTE,
            "ordinary Plan9 fid lifetime confound was not declared before measurement")
    validate_counter(receipt.get("plan9_counter"))
    fixture = restart.validate_fixture(reference(receipt.get("fixture"), "restart fixture"))
    require(receipt.get("apk_interruption_scope") ==
            "APK3 pre-commit hook before package filesystem changes; not arbitrary transaction crash consistency",
            "APK interruption scope differs")
    prerequisites = receipt.get("guest_prerequisites", {})
    require(prerequisites.get("fixture_verified") is True
            and prerequisites.get("apk_version") == fixture["apk_version_stdout"], "signed APK3 prerequisite missing")
    verification = prerequisites.get("verification", {})
    require(verification.get("argv") == ["apk", "--no-network", "--keys-dir", fixture["keys_directory"], "verify"]
            + [row["path"] for row in fixture["apks"]]
            and verification.get("returncode") == 0, "actual offline signature verification missing")
    b64(verification, "stdout_base64"); b64(verification, "stderr_base64")
    absent = prerequisites.get("package_absent", {})
    require(absent.get("argv") == ["apk", "info", "--installed", fixture["package"]]
            and absent.get("returncode") == 1, "declared package was already installed")
    restart.validate_database(receipt.get("apk_database_before"))
    restart.validate_database(receipt.get("apk_database_after"))
    workload = receipt.get("interrupted_workload", {})
    require(workload.get("ready") is True and workload.get("apk_stage") == "pre-commit"
            and type(workload.get("file_bytes")) is int and 0 < workload["file_bytes"] < restart.FILE_BYTES,
            "partway APK and64MiB writer overlap missing")
    prefix = workload.get("durable_prefix", {})
    require(prefix.get("bytes", restart.FILE_BYTES) < restart.FILE_BYTES
            and prefix["bytes"] <= workload["file_bytes"]
            and prefix.get("sha256") == restart.durable_prefix_sha256(prefix["bytes"]), "fsynced prefix witness invalid")
    config = validate_configuration_uploads(receipt, fixture, prefix, outer)
    require(workload.get("nonce") == config["nonce"], "workload nonce mismatch")
    service = validate_provider_counter(root, receipt, config, outer=outer)
    require(workload.get("apk_argv") == ["apk", "--no-network", "--repositories-file", "/dev/null",
            "--keys-dir", fixture["keys_directory"], "add"] + [row["path"] for row in fixture["apks"]],
            "APK install did not use only the declared offline fixture")
    require(prerequisites.get("hook_path") == "/etc/apk/commit_hooks.d/o10-restart-" + config["nonce"]
            and prerequisites.get("hook_sha256") == hashlib.sha256(base64.b64decode(
                config["commit_hook_base64"], validate=True)).hexdigest(), "actual commit hook mismatch")
    chain = workload.get("hook_process_chain")
    require(isinstance(chain, list) and bool(chain), "actual APK hook parent chain missing")
    for role in ("apk", "writer"):
        row = workload.get(role, {})
        require(type(row.get("pid")) is int and row["pid"] > 1 and row.get("start")
                and row.get("state") in ("R", "S", "D", "I"), role + " was not an active witnessed process")
    require(chain[-1].get("pid") == workload["apk"]["pid"]
            and all(chain[i].get("ppid") == chain[i+1].get("pid") for i in range(len(chain)-1)),
            "pre-commit hook does not belong to witnessed APK process")
    recovered = receipt.get("recovered_file", {})
    require(recovered.get("work_not_replayed") is True
            and recovered.get("durable_prefix_bytes") == prefix["bytes"]
            and recovered.get("durable_prefix_sha256") == prefix["sha256"]
            and type(recovered.get("bytes")) is int and prefix["bytes"] <= recovered["bytes"] <= restart.FILE_BYTES
            and recovered.get("unknown_tail_bytes") == recovered["bytes"] - prefix["bytes"]
            and all(re.fullmatch(r"[0-9a-f]{64}", recovered.get(k, "")) is not None for k in
                    ("unknown_tail_sha256", "file_sha256"))
            and recovered.get("completion") == "unknown interrupted tail; only observed fsynced prefix validated",
            "recovered prefix/tail evidence or non-replay policy differs")

    for row in receipt.get("guest_commands", []):
        require(row.get("completion") == "observed" and row.get("returncode") == 0,
                "guest command completion unknown or failed")
        raw_reference(row.get("combined_console"), "guest console", under=outer)
    commands = receipt.get("guest_commands")
    validate_worker_launch(commands, config, outer=outer)
    helper = raw_reference(receipt.get("guest_helper_source"), "observation helper", under=outer) \
        if receipt.get("guest_helper_source") else outer / "guest-helper.py"
    require(digest(helper) == hashlib.sha256(restart.GUEST_HELPER.encode()).hexdigest()
            == receipt.get("guest_helper_sha256"), "observation helper source changed")
    uploads = receipt.get("guest_helper_uploads")
    require(isinstance(uploads, list) and len(uploads) == 2, "both helper bootstraps required")
    for phase, row in zip(("initial", "restored"), uploads):
        require(row.get("phase") == phase and row.get("path") == config["run"] + ".py", "helper phase/path differs")
        require(row.get("sha256") == receipt["guest_helper_sha256"]
                and row.get("bytes") == helper.stat().st_size, "helper bootstrap content mismatch")
        require(raw_reference(row.get("source"), "helper upload", under=outer).read_bytes() == helper.read_bytes(),
                "helper upload source changed")

    quiesce = receipt.get("quiesce", {})
    remount = quiesce.get("remount", {})
    require(remount.get("argv") == ["mount", "-o", "remount,ro", "/"]
            and remount.get("returncode") == 0, "package volume was not quiesced read-only")
    for field, mode in (("before", "rw"), ("after", "ro")):
        row = quiesce.get(field)
        require(isinstance(row, list) and len(row) >= 4 and row[:3] == ["/dev/vda", "/", "ext4"]
                and mode in row[3].split(","), "package mount observation differs")
    require("rw" not in quiesce["after"][3].split(","), "package volume remained writable")
    snapshot = raw_reference(receipt.get("package_snapshot"), "replayed package image", under=outer)
    require(snapshot.stat().st_size == 1024 ** 3
            and restart.clean_superblock(snapshot) == receipt.get("superblock"), "ext4 replay/clean state mismatch")
    fsck = raw_reference(receipt.get("fsck"), "fsck tool", tool=True)
    result = receipt.get("fsck_result", {})
    invoked = receipt["fsck"].get("invoked_path")
    require(isinstance(invoked, str) and Path(invoked).name in ("fsck.ext4", "e2fsck")
            and Path(invoked).resolve(strict=True) == Path(receipt["fsck"]["path"])
            and fsck == Path(receipt["fsck"]["path"]), "filesystem checker alias/identity differs")
    require(result.get("argv") == [invoked, "-n", str(snapshot)]
            and result.get("returncode") == 0, "actual fsck.ext4 -n did not exit0")
    for field in ("stdout", "stderr"):
        raw_reference(result.get(field), "fsck " + field, under=outer)
    require(digest(snapshot) == receipt["package_snapshot"]["sha256"], "fsck modified its image")
    require(Path(receipt["fsck"]["path"]).name in ("fsck.ext4", "e2fsck") and fsck.is_file(),
            "wrong filesystem checker")

    exchanges = decode_exchanges(receipt.get("o10_exchanges"))
    injections = [(q, a) for q, a in exchanges if q["type"] == "Tinject"]
    restores = [(q, a) for q, a in exchanges if q["type"] == "Trestore"]
    require(len(injections) == len(restores) == 1, "fault/restore repeated or missing")
    iq, ia = injections[0]; rq, ra = restores[0]
    require(all(q["type"] in {"Tversion", "Tclaim", "Tstat", "Tinject", "Trestore", "Tbind"}
                for q, _ in exchanges), "undeclared primary lifecycle operation")
    fault_index = next(i for i, (q, _) in enumerate(exchanges) if q["type"] == "Tinject")
    restore_index = next(i for i, (q, _) in enumerate(exchanges) if q["type"] == "Trestore")
    require(fault_index < restore_index, "restore occurred before the witnessed Linux fault")
    old = iq.get("dom")
    require(type(old) is int and old & 0xffffffff == 0 and old >> 32 > 0 and iq.get("fault") == 1
            and ia.get("type") == "Rinject" and ia.get("dom") == old
            and receipt.get("linux_fault") == restart.safe(ia), "wrong qualification Linux fault")
    require(rq.get("dom") == old and rq.get("img_kernel") == 3 and rq.get("img_aux") == 4
            and ra.get("type") == "Rrestore" and ra.get("dom") == old + (1 << 32), "Linux immutable restore mismatch")
    initial = [a for q, a in exchanges if q["type"] == "Tstat" and q.get("dom") == old
               and a.get("type") == "Rstat" and a.get("state") in HEALTHY_STATES]
    faulted = [a for q, a in exchanges if q["type"] == "Tstat" and q.get("dom") == old
               and a.get("type") == "Rstat" and a.get("state") == 4]
    require(initial and faulted, "actual healthy/faulted Linux observations missing")
    after, final = receipt.get("after", {}), receipt.get("final_states", {})
    linux, plan9 = after.get("linux", {}), after.get("plan9", {})
    require(linux.get("type") == "Rstat" and linux.get("state") in HEALTHY_STATES
            and linux.get("dom") == ra["dom"] and linux.get("inst") != restart.safe(initial[0]).get("inst"),
            "Linux did not resume under a new generation/instance")
    require(plan9.get("type") == "Rstat" and plan9.get("state") in HEALTHY_STATES and plan9.get("dom", 0) & 0xffffffff == 1,
            "surviving Plan9 is not healthy")
    prior_plan9 = [restart.safe(a) for q, a in exchanges if q["type"] == "Tstat"
                   and a.get("type") == "Rstat" and a.get("dom") == plan9["dom"]]
    require(prior_plan9 and all(a.get("state") in HEALTHY_STATES and a.get("inst") == plan9.get("inst") for a in prior_plan9),
            "Plan9 identity changed during Linux recovery")
    for role in ("linux", "plan9"):
        require(final.get(role, {}).get("state") in HEALTHY_STATES and all(final[role].get(k) == after[role].get(k)
                for k in ("dom", "inst")), "domain stopped or changed before gate completion")
    bindings = [(q, a) for q, a in exchanges if q["type"] == "Tbind" and q.get("transport", -1) & 0xffffffff == 0]
    require(len(bindings) == sum(q["type"] == "Tbind" for q, _ in exchanges), "another domain transport was rebound")
    require(1 <= len(bindings) <= 2 and bindings[-1][1].get("type") == "Rbind"
            and all(q.get("transport") == linux["dom"] and q.get("lease", 0) & 0xffffffff == 1 for q, _ in bindings),
            "new Linux transport not bound")
    if len(bindings) == 2:
        require(bindings[0][1].get("type") == "Rerror" and bindings[0][1].get("code") == 5
                and bindings[0][1].get("detail") == bindings[1][0]["lease"] >> 32
                and bindings[1][0]["lease"] > bindings[0][0]["lease"], "bind retried without definite stale outcome")
    bind_index = max(i for i, (q, a) in enumerate(exchanges)
                     if q["type"] == "Tbind" and a.get("type") == "Rbind")
    require(restore_index < bind_index and any(restart.safe(a) == linux for q, a in exchanges[bind_index+1:]
            if q["type"] == "Tstat" and q.get("dom") == linux["dom"]),
            "healthy Linux summary is not a raw post-bind observation")
    for role in ("linux", "plan9"):
        replies = [restart.safe(a) for q, a in exchanges if q["type"] == "Tstat"
                   and q.get("dom") == final[role]["dom"] and a.get("type") == "Rstat"]
        require(replies and final[role] == replies[-1], "final domain summary differs from last raw Tstat")
    recoveries = receipt.get("runner_linux_recoveries")
    require(isinstance(recoveries, list) and len(recoveries) == 1 and recoveries[0].get("ok") is True
            and recoveries[0].get("before", {}).get("state") == 4
            and recoveries[0].get("after", {}).get("dom") == linux["dom"]
            and recoveries[0].get("service_before") == recoveries[0].get("service") == service,
            "host recovery policy evidence missing")
    require(receipt.get("unknown_work_policy") == "Interrupted file/APK work is never automatically replayed",
            "unknown service replay policy changed")
    return receipt, {str(session)}

def validate_provenance(path, root, revision):
    wrapped = document(path)
    require(wrapped.get("isError", False) is False, "MCP provenance error")
    value = wrapped.get("structuredContent", wrapped)
    require(value.get("schema") == "ostadix.runtime-provenance/v1"
            and value.get("buildCommitMatchesRuntimeSource") is True, "source/MCP release mismatch")
    for field in ("buildSource", "runtimeSource"):
        require(value.get(field, {}).get("commit") == revision, "MCP commit differs")
    require(value["runtimeSource"].get("status") == "observed"
            and Path(value["buildSource"].get("sourceRoot", "")).resolve() == root.resolve()
            and Path(value["runtimeSource"].get("canonicalRoot", "")).resolve() == root.resolve(), "MCP root was not observed")
    binary = value.get("binary", {})
    require(binary.get("status") == "hashed" and binary.get("hashSource") == "running_process_inode"
            and digest(binary["canonicalPath"]) == binary.get("sha256"), "running MCP inode changed")
    tools = {row["name"]: row["binary"] for row in value.get("tools", [])}
    require("O" in tools, "observed evaluator missing")
    return value, tools

def validate_regressions(root, path, build, profile, revision, resident_path, restart_path, restart_command_path):
    envelope = document(path)
    require(envelope.get("schema") == REGRESSION_SCHEMA and envelope.get("contract_id") == CONTRACT
            and envelope.get("milestone") == "M2" and envelope.get("ok") is True
            and envelope.get("full_milestone_qualified") is False, "M2 six-gate envelope did not finish")
    require(envelope.get("source_revision") == envelope.get("mcp_release") == revision,
            "M2 regression revision differs")
    for field, expected in (("restart_result", restart_path), ("restart_command", restart_command_path),
                            ("resident_result", resident_path)):
        require(envelope.get(field) == identity(expected), "M2 regression prerequisite differs: " + field)
    source_hashes(root, envelope.get("source_sha256"),
                  {"scripts/verify_o10_m2.py", "scripts/verify_o10_m2_regressions.py",
                   "scripts/verify_o10_m1_regressions.py"}, "M2 wrapper")
    command = envelope.get("shared_driver_command")
    argv = completed(command, "shared six-gate driver")
    require(any(Path(word).name == "verify_o10_m1_regressions.py" for word in argv)
            and "--execute" in argv and "--hostile-mmio-result" not in argv,
            "wrong shared driver invocation")
    require(type(envelope.get("max_parallel_vms")) is int and envelope["max_parallel_vms"] in (1, 2),
            "shared scheduler exceeds two VMs")
    outer = Path(path).resolve().parent
    for stream in ("stdout", "stderr"):
        raw_reference(command.get(stream), "shared driver " + stream, under=outer)
    require(Path(envelope.get("shared_result", {}).get("path", "")).resolve() == outer / "six-gates/result.json",
            "shared result escaped the actual driver output")
    require(not envelope.get("skips") and not envelope.get("error"), "M2 regressions failed/skipped")
    guest = reference(envelope.get("shared_result"), "shared six-gate result")
    require(guest.get("schema") == "ostadix.o10-guest-regressions/v1" and guest.get("milestone") == "M1"
            and guest.get("acceptance_scope") == "draft0" and guest.get("contract_id") == "O10-Draft0-M1"
            and guest.get("ok") is True, "shared six-gate result failed or relabeled")
    require(guest.get("source_revision") == guest.get("mcp_release") == revision
            and guest.get("monitor_sha256") == digest(build / "monitor.elf")
            and guest.get("profile_sha256") == digest(build / "monitor-profile.json")
            and Path(guest.get("build", "")).resolve() == build, "guest build/source identity mismatch")
    for flag, expected in (("--build", str(build)), ("--seed-state", guest["seed_state"]),
                           ("--runtime", str(Path(guest["frozen_runtime"]["path"]).parent)),
                           ("--resident-result", str(Path(resident_path).resolve())),
                           ("--output", str(outer / "six-gates")),
                           ("--mcp-release", revision), ("--jobs", str(envelope["max_parallel_vms"])),
                           ("--acceptance-scope", "draft0")):
        require(flag in argv and argv.index(flag) + 1 < len(argv)
                and argv[argv.index(flag) + 1] == expected, "shared driver argument differs: " + flag)
    require(envelope.get("monitor_sha256") == digest(build / "monitor.elf")
            and envelope.get("profile_sha256") == digest(build / "monitor-profile.json")
            and Path(envelope.get("build", "")).resolve() == build, "M2 envelope build differs")
    require(guest.get("build_tools", {}).get("ocorec", {}).get("sha256") == profile["tools"]["ocorec"]["sha256"],
            "guest compiler differs")
    source_hashes(root, guest.get("source_sha256"), {"scripts/" + name for name in shared.GATES.values()} |
                  {"scripts/fork_okernel_state.py", "scripts/o10.py", "scripts/okernel_unified_world.py",
                   "scripts/verify_o10_m1_regressions.py"}, "shared guest")
    require(reference(guest.get("resident_result"), "shared resident") == document(resident_path),
            "shared driver used another resident proof")
    clean(guest, "shared guest regressions")
    frozen = reference(guest.get("frozen_runtime"), "frozen runtime")
    require(frozen.get("passed") is True, "runtime was not admitted")
    runtime = Path(guest["frozen_runtime"]["path"]).parent
    require(digest(runtime / "build/monitor.elf") == digest(build / "monitor.elf")
            and digest(runtime / "build/monitor-profile.json") == digest(build / "monitor-profile.json"),
            "frozen runtime artifact differs")
    require(digest(Path(guest["seed_state"]) / "head.json") == guest.get("seed_head_sha256"), "regression seed changed")
    entries = guest.get("gates")
    require(isinstance(entries, list) and len(entries) == 6
            and {row.get("gate_id") for row in entries} == set(shared.GATES)
            and len({row.get("state") for row in entries}) == 6, "six independent guest gates required")
    sessions, children = set(), []
    for entry in entries:
        name = entry["gate_id"]; state = Path(entry.get("state", "")).resolve()
        require(entry.get("ok") is True and entry.get("script") == shared.GATES[name], "guest gate not passed")
        fork = completed(entry.get("fork"), name + " fork")
        for flag, expected in (("--source", Path(guest["seed_state"]).resolve()), ("--output", state)):
            require(flag in fork and fork.index(flag) + 1 < len(fork)
                    and Path(fork[fork.index(flag) + 1]).resolve() == expected, "guest fork binding differs")
        require(state == outer / "six-gates/states" / name
                and state != Path(guest["seed_state"]).resolve(), "guest state differs from driver plan")
        argv = completed(entry.get("command"), name)
        require(any(Path(word).name == shared.GATES[name] for word in argv), "wrong guest gate command")
        require("--state" in argv and argv.index("--state") + 1 < len(argv)
                and Path(argv[argv.index("--state") + 1]).resolve() == state, "guest state argument differs")
        selected_flag = "--runtime" if name == "runtime" else "--build"
        selected_path = runtime if name == "runtime" else build
        require(selected_flag in argv and argv.index(selected_flag) + 1 < len(argv)
                and Path(argv[argv.index(selected_flag) + 1]).resolve() == selected_path,
                "guest selected another artifact/runtime")
        child = reference(entry.get("receipt"), name + " receipt")
        require(child == entry["receipt"].get("result") and child.get("ok") is True
                and child.get("schema") == shared.CHILD_SCHEMAS[name]
                and Path(entry["receipt"]["path"]).resolve().is_relative_to(state), "guest receipt differs")
        clean(child, name)
        observed = shared.session_paths(child)
        require(observed and observed.isdisjoint(sessions)
                and all(Path(p).resolve().is_relative_to(state) for p in observed), "guest sessions reused or outside fork")
        sessions |= observed; children.append(entry["receipt"])
    return envelope, guest, sessions, children

def validate_ordinary(root, component_path, unit_path, compiler_sha, evaluator_sha, revision):
    component, unit = document(component_path), document(unit_path)
    for label, receipt in (("component", component), ("unit", unit)):
        require(receipt.get("source_revision") == receipt.get("mcp_release") == revision, label + " revision differs")
        require(receipt.get("source_unchanged") is True and not receipt.get("skips") and not receipt.get("error"),
                label + " failed, skipped or changed")
        require(receipt.get("compiler_sha256") == compiler_sha, label + " compiler differs")
    tests = {str(p.relative_to(root)) for p in (root / "tests").glob("test_o10_*.py")}
    helpers = {str(p.relative_to(root)) for p in (root / "scripts").glob("verify_o10_*.py")}
    source_hashes(root, component.get("source_sha256"), set(shared.SOURCES) | tests | helpers, "component")
    require(component.get("gate_id") == "verify_o10_journal" and component.get("component_ok") is True
            and type(component.get("tests_run")) is int and component["tests_run"] > 0
            and shared.zero(component.get("failures")) and shared.zero(component.get("errors")), "components did not pass")
    wrapper = unit.get("component")
    completed(wrapper, "component wrapper")
    require(reference(wrapper, "component wrapper") == component
            and Path(wrapper["path"]).resolve() == Path(component_path).resolve(), "component wrapper differs")
    log = Path(component_path).parent / "tests.log"
    text = log.read_text()
    require(shared.unittest_summary(text, "component") == component["tests_run"]
            and all(Path(name).stem + "." in text for name in tests), "component inventory/count omitted tests")
    okernel = {str(p.relative_to(root)) for p in (root / "tests").glob("test_okernel_*.py")}
    source_hashes(root, unit.get("source_sha256"), okernel | tests |
                  {"scripts/check_language_sources.py", "ci/language-sources.json",
                   "ocore/guest/plan9/unified/protocol.py"}, "unit")
    require(unit.get("schema") in UNIT_SCHEMAS and unit.get("ok") is True, "wrong or failed ordinary unit receipt")
    groups = unit.get("results")
    require(isinstance(groups, list) and len(groups) in (1, 2)
            and {g.get("group") for g in groups} in ({"all"}, {"normal", "ram-disk"}), "kernel unit groups incomplete")
    total, logs = 0, []
    for group in groups:
        require("unittest" in completed(group, "kernel units") and group.get("skipped") is False,
                "kernel unit command not observed")
        actual = raw_reference(group.get("log"), "kernel unit full log").read_text()
        count = shared.unittest_summary(actual, "kernel full log")
        require(count == shared.unittest_summary(group.get("summary"), "kernel summary"), "unit summary/log count differs")
        total += count; logs.append(actual)
    require(total > 0 and all(any(Path(name).stem + "." in log for log in logs) for name in okernel),
            "kernel unit module omitted")
    meta = unit.get("language")
    completed(meta, "language check")
    language = reference(meta, "language check")
    inventory = shared.tracked_language(root); rows = language.get("results")
    require(language.get("schema") == "ostadix.language-source-check/v1" and language.get("action") == "check"
            and inventory and isinstance(rows, list) and len(rows) == len(inventory)
            and language.get("sources") == len(inventory) and {r.get("path") for r in rows} == inventory,
            "complete tracked language inventory required")
    for row in rows:
        require(row.get("status") == "passed" and type(row.get("exit_code")) is int
                and (row["exit_code"] == 0 or row.get("expected_failure"))
                and digest(relative(root, row["path"])) == row.get("sha256"), "language check failed or source drifted")
    require(language.get("binaries", {}).get("ocorec", {}).get("sha256") == compiler_sha
            and language.get("binaries", {}).get("O", {}).get("sha256") == evaluator_sha,
            "language tool identity differs")
    return component, unit, total, len(inventory), log

def validate_acceptance(*, root, build, restart_result, restart_command, resident_result, guest_result,
                        component_result, unit_result, provenance, compiler, expected_revision):
    root, build = Path(root).resolve(), Path(build).resolve()
    require(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", expected_revision) is not None, "invalid expected revision")
    profile = validate_build(root, build, compiler)
    _, tools = validate_provenance(provenance, root, expected_revision)
    primary, primary_sessions = validate_restart(root=root, receipt_path=restart_result, build=build,
                                                profile=profile, expected_revision=expected_revision,
                                                command_path=restart_command)
    resident, resident_sessions, _ = shared.validate_resident(root, resident_result, build, profile, expected_revision)
    envelope, guest, sessions, children = validate_regressions(
        root, guest_result, build, profile, expected_revision, resident_result, restart_result, restart_command)
    require(primary_sessions.isdisjoint(resident_sessions) and sessions.isdisjoint(primary_sessions | resident_sessions),
            "primary/resident/regression VM sessions reused")
    sessions |= primary_sessions | resident_sessions
    for path in sessions:
        require(digest(Path(path) / "monitor-profile.json") == digest(build / "monitor-profile.json")
                and digest(Path(path) / "inputs/monitor.elf") == digest(build / "monitor.elf"),
                "session artifact differs")
    component, unit, kernel_count, language_count, component_log = validate_ordinary(
        root, component_result, unit_result, digest(compiler), tools["O"]["sha256"], expected_revision)
    inputs = {name: identity(path) for name, path in {
        "profile": build / "monitor-profile.json", "monitor": build / "monitor.elf",
        "restart": restart_result, "restart_command": restart_command, "resident": resident_result,
        "guest": guest_result, "component": component_result, "component_log": component_log,
        "unit": unit_result, "language": unit["language"]["path"], "provenance": provenance, "compiler": compiler,
    }.items()}
    return {"schema": "ostadix.o10-m2-acceptance/v1", "milestone": "M2", "gate_id": "verify_o10_m2",
            "contract_id": CONTRACT, "ok": True, "full_milestone_qualified": True,
            "source_revision": expected_revision, "mcp_release": expected_revision,
            "monitor_sha256": digest(build / "monitor.elf"), "profile_sha256": digest(build / "monitor-profile.json"),
            "compiler_sha256": digest(compiler), "inputs": inputs, "sessions_checked": sorted(sessions),
            "guest_receipts": children, "guest_gate_ids": sorted(shared.GATES), "component_tests": component["tests_run"],
            "okernel_unit_tests": kernel_count, "language_sources": language_count, "skips": [],
            "apk_interruption_scope": primary["apk_interruption_scope"],
            "counter_gap": primary["plan9_counter"]["largest_append_gap_upper_bound_seconds"],
            "scope": "Original Draft0 M2 live Linux fault/replacement and binding, native old-fid ESTALE, surviving Plan9 counter/fids, controlled signed APK3 pre-commit interruption, fsynced-prefix preservation and post-replay read-only fsck; Linux withdrawal and reset paths also have source-bound component coverage; complete same-build regressions; AArch64 QEMU only",
            "finished": time.time()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("build", "restart-result", "restart-command", "resident-result", "guest-result",
                 "component-result", "unit-result", "provenance", "compiler", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--expected-revision", required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("output must be a new immutable receipt")
    value = {"schema": "ostadix.o10-m2-acceptance/v1", "milestone": "M2", "contract_id": CONTRACT,
             "ok": False, "full_milestone_qualified": False, "started": time.time()}
    try:
        options = vars(args).copy(); options.pop("output")
        value.update(validate_acceptance(root=ROOT, **options))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ImportError, subprocess.SubprocessError) as error:
        value["error"] = type(error).__name__ + ": " + str(error)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(value, stream, indent=2); stream.write("\n")
    print(json.dumps({"ok": value["ok"], "result": str(args.output)}))
    return 0 if value["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
