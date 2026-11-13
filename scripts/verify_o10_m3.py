#!/usr/bin/env python3
"""Read-only Draft 0 M3 acceptance over actual gate, process and regression evidence."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import importlib.util
import sys
import math
import os
from pathlib import Path
import re
import subprocess
import time
import tomllib

import o10
import verify_o10_execution as execution
import verify_o10_m1 as shared
import verify_o10_m2 as m2
import verify_o10_three_domains as three
from o10_native_fixture import CONTRACT, CORPUS, decode_heartbeat

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "O10-Draft0-M3"
require, digest, document, identity = shared.require, shared.digest, shared.document, shared.identity
LABELS = {"linux", "plan9", "native"}
HEALTHY = {2, 3}


def observation_bounds(value):
    start, end = value.get("observation_start_monotonic"), value.get("observation_end_monotonic")
    require(type(start) in (int, float) and type(end) in (int, float)
            and math.isfinite(start) and math.isfinite(end) and 0 <= start < end
            and end - start <= three.WINDOW_SECONDS
            and value.get("observation_elapsed_seconds") == end - start, "actual bounded observation clock required")
    return start, end


def progress(value, labels, *, window=three.WINDOW_SECONDS):
    require(isinstance(value, dict) and set(value.get("baseline", {})) == set(labels)
            and set(value.get("after", {})) == set(labels), "complete survivor progress required")
    for label in labels:
        before, after = value["baseline"][label], value["after"][label]
        require(type(before) is int and type(after) is int and 0 <= before < after,
                "survivor did not advance: " + label)
    seconds = value.get("host_seconds")
    require(type(seconds) in (int, float) and math.isfinite(seconds)
            and 0 <= seconds <= window and seconds < three.WINDOW_SECONDS, "progress outside fixed host observation window")


def healthy(values, labels=LABELS):
    require(isinstance(values, dict) and set(values) == set(labels), "complete domain state set required")
    slots = set()
    for label, row in values.items():
        handle = row.get("dom")
        require(type(handle) is int and 0 < handle >> 32 <= 0xffffffff
                and 0 <= handle & 0xffffffff < 8 and row.get("state") in HEALTHY,
                "healthy generation-tagged domain required: " + label)
        require(row.get("kind") == (3 if label == "native" else 2), "domain kind differs")
        inst = shared.bytes_field(row.get("inst"), "domain instance")
        require(len(inst) == 16, "128-bit instance required")
        slots.add(handle & 0xffffffff)
    require(len(slots) == len(labels), "domain slots overlap")


def survivors(before, after, labels):
    require(isinstance(after, dict) and set(labels) <= set(after), "survivor state missing")
    healthy({label: after[label] for label in labels}, labels)
    for label in labels:
        require(before[label]["dom"] == after[label]["dom"]
                and before[label]["inst"] == after[label]["inst"], "survivor identity changed: " + label)


def validate_heartbeats(groups, checks, window):
    require(isinstance(groups, list) and len(groups) == 3, "three native lifetimes required")
    require(len({row.get("dom") for row in groups}) == 3, "native lifetime reused")
    expected = {row["dom"]: row for row in checks}
    for group in groups:
        require(group.get("reset_proof") == expected.get(group.get("dom")), "native reset proof differs")
        samples = group.get("samples")
        require(isinstance(samples, list) and samples, "actual native heartbeat bytes missing")
        last, at, positive = None, -1.0, set()
        for row in samples:
            now = row.get("host_seconds")
            require(type(now) in (int, float) and math.isfinite(now)
                    and at <= now <= window and now < three.WINDOW_SECONDS, "heartbeat host timestamps invalid")
            at = now
            raw = bytes.fromhex(row.get("raw_hex", ""))
            require(len(raw) == CONTRACT["heartbeat_bytes"], "heartbeat byte count differs")
            if raw == bytes(len(raw)):
                require(last is None and row.get("initializing") is True
                        and "decoded" not in row, "heartbeat reset after progress")
                continue
            decoded = decode_heartbeat(raw)
            require(row.get("decoded") == decoded and decoded["error"] == 0 and decoded["stage"] != 4,
                    "native heartbeat decoded/raw data differs or failed")
            if not decoded["stable"]:
                continue
            require(last is None or (decoded["reads"] >= last["reads"] and decoded["seq"] >= last["seq"]),
                    "native heartbeat regressed")
            if decoded["reads"]:
                require(decoded["stage"] == 3 and decoded["seq"] == 2 * decoded["reads"]
                        and decoded["last_reply_type"] == 117 and decoded["last_bytes"] == len(CORPUS),
                        "native heartbeat lacks completed namespace reads")
                positive.add(decoded["reads"])
            last = decoded
        require(last == group.get("last") and len(positive) >= 2 and max(positive) >= 3,
                "fresh native lifetime has insufficient observed progress")


def validate_cycle_records(value, expected_image_sha):
    clock_start, clock_end = observation_bounds(value)
    window = clock_end - clock_start
    initial = value.get("initial_states")
    healthy(initial)
    checks = value.get("native_image_checks")
    require(isinstance(checks, list) and len(checks) == 3
            and [r.get("phase") for r in checks] ==
            ["created-provisioned-unbound", "restored-blocked-unbound", "created-provisioned-unbound"],
            "create/restore/recreate image proof sequence missing")
    for check in checks:
        require(check.get("bytes") == CONTRACT["memory_bytes"]
                and check.get("sha256") == expected_image_sha
                and check.get("exact_image_and_zero_rest") is True and check.get("heartbeat_zero") is True,
                "exact native image plus zero RAM proof missing")
    cycles = value.get("fault_cycles")
    require(isinstance(cycles, list) and [r.get("target") for r in cycles] ==
            ["linux", "plan9", "native"], "every domain must fault once")
    prior = initial
    for row in cycles:
        target, before, after = row["target"], row.get("before"), row.get("after")
        healthy(before); healthy(after)
        survivors(prior, before, LABELS)
        others = LABELS - {target}
        require(row.get("fault", {}).get("type") == "Rinject"
                and row["fault"].get("dom") == before[target]["dom"], "fault target differs")
        survivors(before, row.get("survivors_while_faulted"), others)
        survivors(before, after, others)
        require(after[target]["dom"] == before[target]["dom"] + (1 << 32)
                and after[target]["inst"] != before[target]["inst"], "restore did not change target lifetime")
        progress(row.get("survivor_progress_while_faulted"), others, window=window)
        progress(row.get("all_three_progress_after_restore"), LABELS, window=window)
        prior = after
    zero = value.get("destroyed_ram", {})
    require(zero.get("address") == CONTRACT["private_ram_pa"]
            and zero.get("bytes") == CONTRACT["memory_bytes"] and zero.get("all_zero") is True
            and zero.get("sha256") == hashlib.sha256(bytes(CONTRACT["memory_bytes"])).hexdigest(),
            "destroy did not clear all native private RAM")
    final = value.get("final_states")
    healthy(final)
    survivors(prior, final, {"linux", "plan9"})
    old, new = prior["native"]["dom"], final["native"]["dom"]
    require(old & 0xffffffff == new & 0xffffffff and new >> 32 > old >> 32
            and value.get("native_slot") == new & 0xffffffff, "slot not reused under higher generation")
    require([c["dom"] for c in checks] ==
            [initial["native"]["dom"], prior["native"]["dom"], new], "reset proof lifetime differs")
    progress(value.get("final_progress"), LABELS, window=window)
    rows = value.get("stale_references")
    require(isinstance(rows, list) and len(rows) == 12, "complete stale-reference corpus required")
    expected_old = {initial["native"]["dom"], old}
    for handle in expected_old:
        chosen = [r for r in rows if r.get("dom") == handle]
        require(Counter(r.get("message") for r in chosen) ==
                Counter(["Tstat", "Tstart", "Twithdraw", "Trestore", "Tdestroy"]),
                "old domain operation omitted or duplicated")
        require(all(r.get("error") == {"code": o10.O10_ESTALE, "detail": new >> 32} for r in chosen),
                "old domain reference did not fail ESTALE")
    binding = [r for r in rows if r.get("message") == "Tbind"]
    require({r.get("kind") for r in binding} == {"old-lease", "old-transport"}
            and all(r.get("error", {}).get("code") == o10.O10_ESTALE for r in binding),
            "old lease/transport was accepted")
    for row in binding:
        detail = value.get("final_native_lease_generation") if row["kind"] == "old-lease" else new >> 32
        require(row["error"].get("detail") == detail, "stale binding generation differs")
    validate_heartbeats(value.get("native_heartbeats"), checks, window)

    groups = {group["dom"]: group for group in value["native_heartbeats"]}
    for cycle in cycles:
        for field, states in (("survivor_progress_while_faulted", cycle["before"]),
                              ("all_three_progress_after_restore", cycle["after"])):
            count = cycle[field]["after"].get("native")
            if count is not None:
                available = native_reads_at(groups[states["native"]["dom"]], cycle[field]["host_seconds"])
                require(count <= available, "native phase progress uses future heartbeat reads")
    require(value["final_progress"]["after"]["native"] <=
            native_reads_at(groups[final["native"]["dom"]], value["final_progress"]["host_seconds"]),
            "final native progress uses future heartbeat reads")


def validate_counters(value, root):
    """Re-derive byte/counter evidence and exact submitted Plan9 counter work."""
    window_start, window_end = observation_bounds(value)
    rows = value.get("counters")
    require(isinstance(rows, list) and Counter(r.get("label") for r in rows) ==
            Counter({"linux": 2, "plan9": 2}), "both original and fresh counter lifetimes required")
    require(len({r.get("path") for r in rows}) == 4, "counter service work path reused")
    protocol_path = root / "ocore/guest/plan9/unified/protocol.py"
    spec = importlib.util.spec_from_file_location("o10_m3_evidence_protocol", protocol_path)
    protocol = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = protocol
    spec.loader.exec_module(protocol)
    request_ids = set()
    lifetimes = {"linux": [], "plan9": []}
    for row in rows:
        label, path, invocation = row["label"], row.get("path"), row.get("invocation", {})
        require(isinstance(path, str) and path.startswith(
            "/work/o10-m3-linux-" if label == "linux" else "/services/plan9/g"),
            "counter escaped its declared baseline subtree")
        observed = row.get("observations", {})
        require(observed.get("path") == path and "host" in observed.get("timing_scope", ""),
                "counter observation path/timing scope differs")
        start = observed.get("start_monotonic")
        require(type(start) in (int, float) and math.isfinite(start)
                and window_start <= start <= window_end, "counter monotonic clock anchor missing/outside window")
        samples = observed.get("samples")
        require(isinstance(samples, list) and len(samples) >= 3, "counter observation bytes missing")
        previous = -1.0
        for index, sample in enumerate(samples):
            lo, hi = sample.get("earliest_host_seconds"), sample.get("observed_host_seconds")
            require(sample.get("counter") == index and type(lo) in (int, float)
                    and type(hi) in (int, float) and math.isfinite(lo) and math.isfinite(hi)
                    and 0 <= lo <= hi and hi >= previous
                    and window_start <= start + lo <= start + hi <= window_end, "counter observation brackets invalid")
            previous = hi
        raw = bytes.fromhex(observed.get("bytes_hex", ""))
        complete = b"".join((str(i) + "\n").encode() for i in range(len(samples)))
        require(raw.startswith(complete) and (str(len(samples)) + "\n").encode().startswith(raw[len(complete):]),
                "counter append data/order differs")
        gap = max(b["observed_host_seconds"] - a["observed_host_seconds"] for a, b in zip(samples, samples[1:]))
        bound = max(b["observed_host_seconds"] - a["earliest_host_seconds"] for a, b in zip(samples, samples[1:]))
        require(observed.get("largest_observed_gap_seconds") == gap
                and observed.get("largest_append_gap_upper_bound_seconds") == bound,
                "counter gap not derived from actual brackets")
        index = len(lifetimes[label])
        expected_dom = value["initial_states"][label]["dom"] + (index << 32)
        require(invocation.get("dom") == expected_dom and invocation.get("path") == path,
                "counter holder lifetime differs")
        require(row.get("completion") == ("unknown after a definite domain fault; never replayed" if index == 0
                                         else "active; provider completion unobserved"),
                "interrupted counter completion was replayed or asserted known")
        lifetimes[label].append(observed)
        if label == "linux":
            require(invocation.get("phase") == "launched-once"
                    and invocation.get("command") == three.linux_counter_command(path),
                    "Linux counter command changed or replayed")
        else:
            require(invocation.get("phase") == "submitted-once", "Plan9 counter not submitted exactly once")
            request = invocation.get("plan9_counter_request", {})
            raw_request = shared.bytes_field(request.get("request"), "Plan9 counter request")
            decoded = protocol.decode_request(raw_request)
            service = {"generation": decoded.generation, "instance": decoded.instance}
            require(decoded.request_id not in request_ids and request.get("id") == decoded.request_id
                    and request.get("phase") == "submitted" and request.get("service") == service
                    and invocation.get("service") == service
                    and decoded.cwd == "/n/work" and decoded.stdin == b"" and decoded.timeout_ms == 300000
                    and decoded.argv == ("/arm64/bin/rc", "-I", "-c", three.common.plan9_counter_command(path)),
                    "Plan9 counter work bytes/identity differ")
            request_ids.add(decoded.request_id)
            require(shared.bytes_field(request.get("submit_marker"), "counter submit marker") ==
                    protocol.submit_marker(raw_request), "counter submission marker differs")
            require(request.get("paths") == protocol.request_paths(
                "/n/okernel/services/plan9", decoded.generation, decoded.instance, decoded.request_id),
                "counter publication paths differ")
    # A phase endpoint may only use append observations already available then.
    for cycle in value["fault_cycles"]:
        for field in ("survivor_progress_while_faulted", "all_three_progress_after_restore"):
            endpoint = window_start + cycle[field]["host_seconds"]
            for label, count in cycle[field]["after"].items():
                if label == "native":
                    continue
                generation = (cycle["before"] if field == "survivor_progress_while_faulted" else cycle["after"])[label]["dom"] >> 32
                start_generation = value["initial_states"][label]["dom"] >> 32
                require(0 <= generation - start_generation < 2, "counter lifetime outside observed set")
                observed = lifetimes[label][generation - start_generation]
                available = sum(observed["start_monotonic"] + sample["observed_host_seconds"] <= endpoint
                                for sample in observed["samples"])
                require(count <= available, "phase counter progress uses future append observations")
    endpoint = window_start + value["final_progress"]["host_seconds"]
    for label in ("linux", "plan9"):
        observed = lifetimes[label][-1]
        available = sum(observed["start_monotonic"] + sample["observed_host_seconds"] <= endpoint
                        for sample in observed["samples"])
        require(value["final_progress"]["after"][label] <= available,
                "final progress uses future append observations")
    first = {label: next(row for row in rows if row["label"] == label) for label in ("linux", "plan9")}
    require(value["fault_cycles"][0].get("interrupted_counter") == first["linux"]
            and value["fault_cycles"][1].get("interrupted_counter") == first["plan9"],
            "interrupted counter record differs")
    old_request = first["plan9"]["invocation"]["plan9_counter_request"]
    raw_request = shared.bytes_field(old_request["request"], "unknown Plan9 request")
    require(value["fault_cycles"][1].get("unknown_service_outcome") ==
            dict(request_id=old_request["id"], request_sha256=hashlib.sha256(raw_request).hexdigest()),
            "unknown service completion lost its exact request identity")


def validate_wire(value):
    rows = value.get("o10_exchanges")
    pairs = m2.decode_exchanges(rows)
    unique, seen, wire_counts = [], {}, Counter()
    for row, (request, reply) in zip(rows, pairs):
        key = row["request_hex"]
        wire_counts[(key, row["reply_hex"])] += 1
        if request["type"] == "Tversion" or request.get("seq") == 0:
            continue
        seq = (request["epoch"], request["seq"])
        if seq in seen:
            require(seen[seq] == (key, row["reply_hex"]), "sequence reused with another request or reply")
        else:
            seen[seq] = (key, row["reply_hex"])
            if reply["type"] != "Rerror":
                unique.append((request, reply))
    counts = Counter(r["type"] for r, _ in unique)
    require(all(counts[k] == n for k, n in
                {"Tinject": 3, "Trestore": 3, "Tcreate": 2, "Tstart": 2, "Tdestroy": 1}.items()),
            "actual wire lifecycle corpus incomplete")
    replays = value.get("journal_replays")
    require(isinstance(replays, list) and len(replays) == 3
            and len({r.get("request_hex") for r in replays}) == 3,
            "known-applied create/start journal retransmissions missing")
    replay_kinds = []
    for row in replays:
        req = o10.decode(bytes.fromhex(row.get("request_hex", "")))
        rep = o10.decode(bytes.fromhex(row.get("reply_hex", "")))
        require(req["type"] in ("Tcreate", "Tstart") and rep["type"] == "R" + req["type"][1:],
                "journal replay must name known-applied create/start")
        replay_kinds.append(req["type"])
        require(wire_counts[(row.get("request_hex"), row.get("reply_hex"))] >= 2,
                "journal retransmission lacks two identical actual exchanges")
    require(Counter(replay_kinds) == Counter({"Tcreate": 2, "Tstart": 1}), "create/start replay corpus differs")
    faults = [(r["dom"], r["fault"]) for r, _ in unique if r["type"] == "Tinject"]
    require(faults == [(row["before"][row["target"]]["dom"], 1) for row in value["fault_cycles"]],
            "raw injections differ from observed cycles")



    bindings = value.get("native_bindings")
    require(isinstance(bindings, list) and [row.get("dom") for row in bindings] ==
            [row["dom"] for row in value["native_image_checks"]], "three native binding lifetimes required")
    native_successes = [(i, r, p) for i, (r, p) in enumerate(pairs)
                        if r["type"] == "Tbind" and r.get("lease", 0) & 0xffffffff == 3 and p["type"] == "Rbind"]
    require(len(native_successes) == 3, "three successful native Tbind exchanges required")
    previous_generation, sessions = 0, set()
    for index, (binding, (position, request, reply)) in enumerate(zip(bindings, native_successes)):
        holder, generation = binding["dom"], binding.get("lease_generation")
        require(type(generation) is int and previous_generation < generation <= 0xffffffff
                and request["lease"] == (generation << 32) | 3
                and request["transport"] == holder & ~0xffffffff
                and binding.get("reply") == three.safe(reply)
                and type(reply.get("session")) is int and reply["session"] > 0,
                "native binding lease/transport/session differs")
        previous_generation = generation; sessions.add(reply["session"])
        origin_name, origin_state = ("Trestore", 3) if index == 1 else ("Tcreate", 1)
        origins = [i for i, (r, p) in enumerate(pairs[:position])
                   if r["type"] == origin_name and p["type"] == "R" + origin_name[1:] and p.get("dom") == holder]
        require(origins, "native binding precedes its provisioning")
        origin = min(origins)
        require(any(r["type"] == "Tstat" and r.get("dom") == holder and p["type"] == "Rstat"
                    and p.get("state") == origin_state for r, p in pairs[origin + 1:position]),
                "native pre-bind PROVISIONED/BLOCKED state missing")
        if index != 1:
            starts_at = [i for i, (r, p) in enumerate(pairs) if r["type"] == "Tstart"
                         and r.get("dom") == holder and p["type"] == "Rstart"]
            require(starts_at and min(starts_at) > position
                    and any(r["type"] == "Tstat" and r.get("dom") == holder and p["type"] == "Rstat"
                            and p.get("state") == 1 for r, p in pairs[position + 1:min(starts_at)]),
                    "binding must preserve PROVISIONED until Tstart")
    require(len(sessions) == 3, "native namespace session reused")

    # Bind the named lifetimes and stopped FAULTED observation to raw O10 replies.
    creates = [(r, p) for r, p in unique if r["type"] == "Tcreate"]
    for (request, reply), check in zip(creates, (value["native_image_checks"][0], value["native_image_checks"][2])):
        require(request["kind"] == 3 and request["img_kernel"] == 5 and request["img_aux"] == 6
                and request["mem_bytes"] == CONTRACT["memory_bytes"] and request["vcpus"] == 1
                and reply["dom"] == check["dom"], "raw Tcreate fixture/lifetime differs")
    restores = [(r, p) for r, p in unique if r["type"] == "Trestore"]
    for (request, reply), cycle in zip(restores, value["fault_cycles"]):
        target = cycle["target"]
        images = {"linux": (3, 4), "plan9": (1, 2), "native": (5, 6)}[target]
        require(request["dom"] == cycle["before"][target]["dom"]
                and reply["dom"] == cycle["after"][target]["dom"]
                and (request["img_kernel"], request["img_aux"]) == images
                and request["inst"] == shared.bytes_field(cycle["after"][target]["inst"], "restored instance"),
                "raw restore image/holder/instance differs")
        begin = next(i for i, (r, p) in enumerate(pairs)
                     if r["type"] == "Tinject" and r.get("dom") == request["dom"] and p["type"] == "Rinject")
        end = next(i for i, (r, p) in enumerate(pairs)
                   if i > begin and r["type"] == "Trestore" and r.get("dom") == request["dom"]
                   and p["type"] == "Rrestore")
        require(any(r["type"] == "Tstat" and r.get("dom") == request["dom"]
                    and p["type"] == "Rstat" and p.get("state") == 4 for r, p in pairs[begin + 1:end]),
                "raw stopped FAULTED observation missing")
    starts = [(r, p) for r, p in unique if r["type"] == "Tstart"]
    for (request, reply), state in zip(starts, (value["initial_states"]["native"], value["final_states"]["native"])):
        require(request["dom"] == reply["dom"] == state["dom"]
                and request["inst"] == shared.bytes_field(state["inst"], "started instance"),
                "raw Tstart lifetime differs")
    destroys = [(r, p) for r, p in unique if r["type"] == "Tdestroy"]
    require(destroys[0][0]["dom"] == value["fault_cycles"][-1]["after"]["native"]["dom"]
            and three.safe(destroys[0][1]) == value.get("native_destroy"),
            "raw destroy target/reply differs")
    for row in value["stale_references"]:
        def matching(request):
            if request["type"] != row["message"]:
                return False
            if row["message"] != "Tbind":
                return request.get("dom") == row["dom"]
            lease = value["final_native_lease_generation"]
            new = value["final_states"]["native"]["dom"]
            old = value["fault_cycles"][-1]["after"]["native"]["dom"]
            wanted = ((lease - 1) << 32) | 3 if row["kind"] == "old-lease" else (lease << 32) | 3
            transport = (new if row["kind"] == "old-lease" else old) & ~0xffffffff
            return request.get("lease") == wanted and request.get("transport") == transport
        require(any(matching(r) and p["type"] == "Rerror"
                    and p.get("code") == row["error"]["code"]
                    and p.get("detail") == row["error"]["detail"] for r, p in pairs),
                "stale-reference row lacks matching raw ESTALE")




def validate_ordinary_invocation(path, root, revision):
    value = document(path)
    require(value.get("schema") == "ostadix.o10-ordinary-invocation/v1"
            and value.get("source_revision") == revision
            and Path(value.get("source_root", "")).resolve() == root
            and Path(value.get("cwd", "")).resolve() == root, "reviewed ordinary invocation context required")
    controller = m2.raw_reference(value.get("controller"), "reviewed ordinary controller")
    wrapper = m2.raw_reference(value.get("wrapper"), "reviewed ordinary O wrapper")
    argv = value.get("argv")
    require(isinstance(argv, list) and len(argv) >= 3 and all(isinstance(word, str) for word in argv)
            and Path(argv[0]).resolve() == Path(sys.executable).resolve()
            and argv[1] == "-B" and Path(argv[2]).resolve() == controller, "reviewed controller argv differs")
    inputs = value.get("inputs")
    require(isinstance(inputs, dict) and inputs, "ordinary controller input identities required")
    for name, row in inputs.items():
        require(isinstance(name, str) and name, "ordinary input name invalid")
        m2.raw_reference(row, "ordinary input " + name)
    review = document(m2.raw_reference(value.get("review"), "ordinary invocation review"))
    projection = {name: item for name, item in value.items() if name != "review"}
    projection_sha = hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(",", ":"),
                                              allow_nan=False).encode()).hexdigest()
    require(review.get("ok") is True and review.get("invocation_sha256") == projection_sha,
            "ordinary invocation differs from reviewed source and arguments")
    return value


def native_reads_at(group, seconds):
    return max((row["decoded"]["reads"] for row in group["samples"]
                if row.get("decoded", {}).get("stable") and row["host_seconds"] <= seconds), default=0)


def one_argument(args, flag):
    require(args.count(flag) == 1 and args.index(flag) + 1 < len(args), "one canonical argument required: " + flag)
    return args[args.index(flag) + 1]


def validate_role_request(verified, role, *, root, paths, values, invocation=None):
    api = verified["canonical_api"]
    request = api["arguments"]
    require(Path(request["cwd"]).resolve() == root, "execution request selected another source checkout")
    if role == "ordinary":
        require(api["tool"] == "o_execute" and isinstance(request.get("source"), str)
                and verified.get("inner_command") is not None and isinstance(invocation, dict),
                "ordinary reviewed O execution required")
        inner = document(m2.raw_reference(verified["inner_command"], "ordinary actual controller"))
        argv = shared.completed(inner, "ordinary actual controller")
        controller = m2.raw_reference(invocation["controller"], "reviewed ordinary controller")
        wrapper = m2.raw_reference(invocation["wrapper"], "reviewed ordinary wrapper")
        require(Path(inner["cwd"]).resolve() == root and argv == invocation["argv"]
                and inner.get("controller_source") == invocation["controller"]
                and m2.raw_reference(inner.get("controller_source"), "executed controller source") == controller
                and request["source"].encode() == wrapper.read_bytes(),
                "ordinary job did not run the reviewed controller and wrapper")
        return
    subcommand = {"primary": "o10-three-domains", "resident": "o10-resident", "guest": "o10-m1-regressions"}[role]
    require(api["tool"] == "o_cli" and request.get("command") == "kernel", "canonical kernel API required")
    args = request.get("args")
    require(isinstance(args, list) and args and args[0] == subcommand
            and verified.get("canonical_argv") == ["o", "kernel"] + args,
            "execution selected another milestone gate")
    if role in ("primary", "guest"):
        require(args.count("--execute") == 1, "actual execution flag required")
    if role == "guest":
        require("--resume-from" not in args, "fresh M3 guest regression forks required")
    for flag, path in paths.items():
        require(Path(one_argument(args, flag)).resolve() == Path(path).resolve(),
                "canonical execution selected another input: " + flag)
    for flag, value in values.items():
        require(one_argument(args, flag) == value, "canonical execution value differs: " + flag)


def observe_process(pid):
    require(type(pid) is int and pid > 0, "actual broker PID required")
    process = Path("/proc") / str(pid)
    fields = (process / "stat").read_text().rsplit(")", 1)[1].strip().split()
    start_ticks = int(fields[19])
    executable = process / "exe"
    canonical = Path(os.readlink(executable)).resolve(strict=True)
    with executable.open("rb") as stream:
        info = os.fstat(stream.fileno())
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    return dict(pid=pid, start_ticks=start_ticks,
                executable=dict(path=str(canonical), bytes=info.st_size, sha256=sha, device=info.st_dev, inode=info.st_ino))


def validate_broker(path, provenance_path, provenance, root, revision, executions):
    value = document(path)
    require(value.get("schema") == "ostadix.o10-broker-process/v1"
            and value.get("source_revision") == revision
            and Path(value.get("source_root", "")).resolve() == root, "current broker context required")
    require(m2.raw_reference(value.get("provenance"), "broker provenance") == Path(provenance_path).resolve(),
            "broker selected another observed MCP provenance")
    actual = observe_process(value.get("pid"))
    require(type(value.get("start_ticks")) is int and value["start_ticks"] == actual["start_ticks"],
            "broker process start identity changed")
    executable = m2.raw_reference(value.get("executable"), "broker executable", tool=True)
    require(actual["executable"] == value["executable"]
            and actual["executable"]["sha256"] == provenance["binary"]["sha256"]
            and executable == Path(provenance["binary"]["canonicalPath"]).resolve(),
            "broker actual running inode differs from aligned MCP")
    prefix = value.get("job_prefix")
    require(isinstance(prefix, str) and re.fullmatch(r"job-[1-9][0-9]*-[1-9][0-9]*-[1-9][0-9]*", prefix)
            and prefix.split("-")[1] == str(actual["pid"]), "broker managed producer prefix invalid")
    anchor = execution.status_ref(value.get("status_reference"))
    require(anchor.get("state") == "completed" and type(anchor.get("exit_code")) is int
            and anchor["exit_code"] == 0 and anchor.get("error") is None and anchor.get("signal") is None
            and anchor.get("cleanup", {}).get("child_reaped") is True
            and anchor["cleanup"].get("logs_drained") is True
            and isinstance(anchor.get("job_id"), str) and anchor["job_id"].rsplit("-", 1)[0] == prefix,
            "fresh current-broker help job identity required")
    for row in executions.values():
        job = row["job_id"]
        require(job.startswith(prefix + "-") and job.rsplit("-", 1)[0] == prefix
                and job.rsplit("-", 1)[1].isdigit(), "gate ran through another MCP producer")
    return dict(identity=identity(path), observed_process=actual, job_prefix=prefix)

def validate_compiler(compiler, profile):
    """Bind the selected compiler to the actual compiled-build descriptor."""
    selected = three.identity(compiler)
    require(selected == profile.get("tools", {}).get("ocorec"),
            "primary compiler descriptor differs")
    return selected


def validate_primary(root, path, build, runtime, revision):
    value = document(path)
    require(value.get("schema") == "ostadix.o10-three-domains-gate/v1"
            and value.get("gate_id") == "verify_o10_three_domains" and value.get("gate_passed") is True
            and value.get("milestone_qualified") is False and value.get("source_unchanged") is True,
            "actual three-domain component gate required")
    require(value.get("source_revision") == value.get("mcp_release") == revision
            and not value.get("skips") and not value.get("error") and value.get("pending_mechanism") is None,
            "three-domain result failed, unknown or from another revision")
    require(value.get("native_fixture_contract") == CONTRACT and value.get("observation_window_seconds") == three.WINDOW_SECONDS,
            "native fixture/window contract differs")
    require(value.get("cleanup", {}).get("closed") is True
            and value["cleanup"].get("process_reaped") is True and not value.get("cleanup_error"),
            "three-domain QEMU cleanup incomplete")
    profile = m2.validate_build(root, build)
    require(profile.get("domain_capacity") == 8 and profile.get("native_fixture") == CONTRACT,
            "eight-domain native fixture profile required")
    three.compiled_source_identity(profile, build)
    require(m2.raw_reference(value.get("build"), "primary build") == build / "monitor-profile.json",
            "three-domain selected another build")
    artifacts = {name: shared.relative(build, row["path"]) for name, row in profile["artifacts"].items()}
    require(set(value.get("artifacts", {})) == set(artifacts), "gate artifact inventory incomplete")
    for name, selected in artifacts.items():
        require(m2.raw_reference(value["artifacts"][name], "gate artifact") == selected, "gate artifact changed")
    expected = hashlib.sha256(three.native_image_envelope(artifacts)).hexdigest()
    validate_cycle_records(value, expected); validate_wire(value)
    required = set(profile["source_sha256"]) | {
        "scripts/verify_o10_three_domains.py", "tests/test_o10_three_domains.py", "scripts/o-kernel.sh",
        "scripts/verify_o10_linux_restart.py", "scripts/okernel_unified_world.py", "scripts/o10.py",
        "scripts/o10_native_fixture.py", "scripts/fork_okernel_state.py", "scripts/verify_okernel_unified_provider.py",
        "scripts/freeze_okernel_unified_runtime.py", "scripts/verify_okernel_two_domains_repro.py",
        "scripts/verify_okernel_unified_repro.py", "ocore/guest/plan9/unified/protocol.py",
        "ocore/guest/plan9/unified/p9cmdsrv.c"}
    shared.source_hashes(root, value.get("source_sha256"), required, "three-domain")
    require(set(value.get("source_artifacts", {})) == set(value["source_sha256"]), "gate source captures incomplete")
    for name, expected in value["source_sha256"].items():
        capture = m2.raw_reference(value["source_artifacts"][name], "gate source", under=Path(path).parent)
        require(digest(capture) == expected, "gate capture differs from source")
    validate_counters(value, root)
    require(three.runtime_identity(runtime, build) == value.get("runtime"), "primary runtime closure differs")
    seed = Path(value["seed_head_before"]["path"]).parent
    require(three.pinned_seed(seed, value["seed_requested_sha256"]) == value.get("seed_pin")
            and value["seed_pin"]["identity"] == value.get("seed_head_before"), "original requested seed pin changed")
    fork = value.get("fork", {})
    require(fork.get("ok") is True and fork.get("source_head_changed_during_copy") is False
            and (Path(path).parent / "state/source-head.json").read_bytes().hex() == value["seed_pin"]["raw_hex"],
            "private gate fork selected another seed")
    session = Path(value.get("guest_session", "")).resolve()
    require(session.is_relative_to(Path(path).resolve().parent / "state") and session.is_dir(),
            "private actual gate session missing")
    require(digest(session / "monitor-profile.json") == digest(build / "monitor-profile.json")
            and digest(session / "inputs/monitor.elf") == digest(build / "monitor.elf"), "gate VM artifact differs")
    return value, {str(session)}, profile


def validate_guest_regressions(root, path, build, runtime, revision, resident_path):
    guest = document(path)
    require(guest.get("schema") == "ostadix.o10-guest-regressions/v1" and guest.get("milestone") == "M1"
            and guest.get("ok") is True and guest.get("source_revision") == guest.get("mcp_release") == revision
            and guest.get("acceptance_scope") == "draft0" and guest.get("contract_id") == "O10-Draft0-M1",
            "complete shared six-guest regression driver required")
    require(guest.get("monitor_sha256") == digest(build / "monitor.elf")
            and guest.get("profile_sha256") == digest(build / "monitor-profile.json")
            and Path(guest.get("build", "")).resolve() == build, "guest driver artifact differs")
    shared.clean(guest, "six guest regressions")
    shared.source_hashes(root, guest.get("source_sha256"),
        {"scripts/" + n for n in shared.GATES.values()} |
        {"scripts/fork_okernel_state.py", "scripts/o10.py", "scripts/okernel_unified_world.py",
         "scripts/verify_o10_m1_regressions.py"}, "shared guest")
    require(shared.reference(guest.get("resident_result"), "guest resident") == document(resident_path),
            "guest driver used another resident proof")
    frozen = shared.reference(guest.get("frozen_runtime"), "guest runtime")
    require(Path(guest["frozen_runtime"]["path"]).resolve() == runtime / "runtime.json"
            and frozen.get("passed") is True, "guest runtime differs")
    require(digest(Path(guest["seed_state"]) / "head.json") == guest.get("seed_head_sha256"),
            "regression source seed changed")
    entries = guest.get("gates")
    require(isinstance(entries, list) and len(entries) == 6
            and {r.get("gate_id") for r in entries} == set(shared.GATES)
            and len({r.get("state") for r in entries}) == 6, "six independent guest gates required")
    sessions, children = set(), []
    for entry in entries:
        name = entry["gate_id"]; state = Path(entry["state"]).resolve()
        require(entry.get("ok") is True and entry.get("script") == shared.GATES[name], "guest gate failed")
        fork = shared.completed(entry.get("fork"), name + " fork")
        for flag, selected in (("--source", Path(guest["seed_state"]).resolve()), ("--output", state)):
            require(flag in fork and fork.index(flag) + 1 < len(fork)
                    and Path(fork[fork.index(flag) + 1]).resolve() == selected, "guest fork binding differs")
        require(state != Path(guest["seed_state"]).resolve(), "guest uses source seed directly")
        argv = shared.completed(entry.get("command"), name)
        require(any(Path(x).name == shared.GATES[name] for x in argv), "wrong guest command")
        for flag, selected in (("--state", state), ("--runtime" if name == "runtime" else "--build",
                                                   runtime if name == "runtime" else build)):
            require(flag in argv and argv.index(flag) + 1 < len(argv)
                    and Path(argv[argv.index(flag) + 1]).resolve() == selected, "guest command selects another input")
        child = shared.reference(entry.get("receipt"), name)
        require(child == entry["receipt"].get("result") and child.get("ok") is True
                and child.get("schema") == shared.CHILD_SCHEMAS[name]
                and Path(entry["receipt"]["path"]).resolve().is_relative_to(state), "guest receipt differs")
        shared.clean(child, name)
        observed = shared.session_paths(child)
        require(observed and observed.isdisjoint(sessions)
                and all(Path(p).resolve().is_relative_to(state) for p in observed), "guest sessions reused/outside fork")
        sessions |= observed; children.append(entry["receipt"])
    return guest, sessions, children


def validate_ci(path, root, revision):
    value = document(path)
    require(value.get("head") == revision and value.get("repository") == "lostadi/OSTADIX"
            and value.get("run_status") == "completed" and value.get("run_conclusion") == "success",
            "CI is not successful on exact acceptance source")
    config = m2.raw_reference(value.get("required_job_config"), "required CI config")
    require(config == root / "ci/required-jobs.toml", "CI config from another checkout")
    expected = tomllib.loads(config.read_text())["required_jobs"]
    require(value.get("required_job_ids") == expected and value.get("required_lanes_passed") == len(expected),
            "required CI lane set differs")
    raw = m2.raw_reference(value.get("raw_required_log"), "Required CI raw log").read_text()
    for name in expected:
        require(re.search(r"(?:^|\s)" + re.escape(name.upper().replace("-", "_")) + r"=success(?:\s|$)", raw),
                "required CI lane lacks successful raw result: " + name)
    jobs = value.get("jobs")
    require(isinstance(jobs, list) and len({r.get("id") for r in jobs}) == len(jobs), "actual CI job inventory missing")
    aggregate = [r for r in jobs if r.get("id") == value.get("required_aggregate_job") and r.get("name") == "Required CI"]
    require(len(aggregate) == 1 and aggregate[0].get("status") == "completed"
            and aggregate[0].get("conclusion") == "success", "Required CI aggregate failed/missing")
    runs = document(m2.raw_reference(value.get("api_commit_runs"), "actual API runs"))
    require(runs.get("request", {}).get("tool") == "github.fetch_commit_workflow_runs"
            and runs["request"].get("commit_sha") == revision
            and runs["request"].get("repo_full_name") == "lostadi/OSTADIX",
            "CI API query names another source")
    direct = document(m2.raw_reference(value.get("api_run"), "actual workflow-run API response"))
    require(direct.get("request", {}).get("tool") == "gh.api"
            and direct["request"].get("path") == "repos/lostadi/OSTADIX/actions/runs/" + str(value.get("run_id")),
            "direct workflow API route differs")
    observed_run = direct.get("response", {})
    require(observed_run.get("id") == value.get("run_id") and observed_run.get("head_sha") == revision
            and observed_run.get("event") == "pull_request" and observed_run.get("name") == "CI"
            and observed_run.get("status") == "completed" and observed_run.get("conclusion") == "success"
            and observed_run.get("repository", {}).get("full_name") == "lostadi/OSTADIX",
            "actual workflow run selected another source")
    selected_runs = [r for r in runs.get("response", {}).get("workflow_runs", [])
                     if r.get("id") == value.get("run_id")]
    require(len(selected_runs) == 1 and selected_runs[0].get("name") == "CI"
            and selected_runs[0].get("status") == "completed"
            and selected_runs[0].get("conclusion") == "success"
            and selected_runs[0].get("head_sha", revision) == revision, "CI run API outcome differs")
    api = document(m2.raw_reference(value.get("api_jobs"), "actual API jobs"))
    require(api.get("request", {}).get("tool") == "github.fetch_workflow_run_jobs"
            and api["request"].get("run_id") == value.get("run_id")
            and api["request"].get("repo_full_name") == "lostadi/OSTADIX", "CI jobs API selected another run")
    actual_jobs = api.get("response", {}).get("jobs", [])
    normalized = [{key: row.get(key) for key in ("id", "name", "status", "conclusion")} for row in actual_jobs]
    require(sorted(normalized, key=lambda r: r["id"]) == sorted(jobs, key=lambda r: r["id"])
            and len(jobs) >= len(expected) + 1, "actual CI jobs differ from bound summary")
    return value


def validate_acceptance(*, root, build, runtime, primary_result, primary_execution,
                        resident_result, resident_execution, guest_result, guest_execution,
                        component_result, unit_result, ordinary_execution,
                        provenance, compiler, ci_result, broker_process, ordinary_invocation, expected_revision):
    root, build, runtime = Path(root).resolve(), Path(build).resolve(), Path(runtime).resolve()
    require(root == ROOT.resolve() and re.fullmatch(r"[0-9a-f]{40}", expected_revision), "canonical source/revision required")
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip() == expected_revision
            and not subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip(),
            "clean exact acceptance source required")
    prov, tools = m2.validate_provenance(provenance, root, expected_revision)
    primary, sessions, profile = validate_primary(root, primary_result, build, runtime, expected_revision)
    validate_compiler(compiler, profile)
    resident, resident_sessions, _ = shared.validate_resident(root, resident_result, build, profile, expected_revision)
    guest, guest_sessions, children = validate_guest_regressions(root, guest_result, build, runtime,
                                                                 expected_revision, resident_result)
    require(sessions.isdisjoint(resident_sessions) and guest_sessions.isdisjoint(sessions | resident_sessions),
            "primary/resident/regression VM sessions reused")
    sessions |= resident_sessions | guest_sessions
    for name in sessions:
        session = Path(name)
        require(digest(session / "monitor-profile.json") == digest(build / "monitor-profile.json")
                and digest(session / "inputs/monitor.elf") == digest(build / "monitor.elf"), "mixed-build sessions")
    component, unit, kernel_count, language_count, _ = m2.validate_ordinary(
        root, component_result, unit_result, digest(compiler), tools["O"]["sha256"], expected_revision,
        accepted_unit_schemas=m2.UNIT_SCHEMAS | {"ostadix.o10-m3-unit-regressions/v1"})
    require(guest.get("build_tools", {}).get("ocorec", {}).get("sha256") == digest(compiler),
            "regression compiler differs")
    seen = set()
    proofs = {"primary": (primary_execution, primary_result), "resident": (resident_execution, resident_result),
              "guest": (guest_execution, guest_result), "ordinary": (ordinary_execution, unit_result)}
    executions = {role: execution.validate_execution(proof, result, role, seen)
                  for role, (proof, result) in proofs.items()}
    validate_role_request(executions["primary"], "primary", root=root,
        paths={"--build": build, "--runtime": runtime, "--seed-state": Path(primary["seed_head_before"]["path"]).parent,
               "--output": Path(primary_result).parent},
        values={"--mcp-release": expected_revision, "--seed-head-sha256": primary["seed_requested_sha256"]})
    validate_role_request(executions["resident"], "resident", root=root,
        paths={"--build": build, "--state": Path(resident["source_state"]),
               "--session": Path(resident_result).parent, "--qemu": runtime / "tools/bin/qemu-system-aarch64"},
        values={"--mcp-release": expected_revision})
    validate_role_request(executions["guest"], "guest", root=root,
        paths={"--build": build, "--runtime": runtime, "--seed-state": Path(guest["seed_state"]),
               "--resident-result": resident_result, "--output": Path(guest_result).parent},
        values={"--mcp-release": expected_revision, "--acceptance-scope": "draft0"})
    invocation = validate_ordinary_invocation(ordinary_invocation, root, expected_revision)
    validate_role_request(executions["ordinary"], "ordinary", root=root, paths={}, values={}, invocation=invocation)
    broker = validate_broker(broker_process, provenance, prov, root, expected_revision, executions)
    ci = validate_ci(ci_result, root, expected_revision)
    inputs = {name: identity(path) for name, path in {
        "profile": build / "monitor-profile.json", "monitor": build / "monitor.elf",
        "runtime": runtime / "runtime.json", "primary": primary_result, "primary_execution": primary_execution,
        "resident": resident_result, "guest": guest_result, "resident_execution": resident_execution,
        "guest_execution": guest_execution, "ordinary_execution": ordinary_execution, "broker": broker_process,
        "ordinary_invocation": ordinary_invocation,
        "component": component_result, "unit": unit_result, "language": unit["language"]["path"],
        "provenance": provenance, "compiler": compiler, "ci": ci_result}.items()}
    return dict(schema="ostadix.o10-m3-acceptance/v1", milestone="M3", contract_id=CONTRACT_ID,
                gate_id="verify_o10_m3", ok=True, full_milestone_qualified=True,
                source_revision=expected_revision, mcp_release=expected_revision,
                monitor_sha256=digest(build / "monitor.elf"), profile_sha256=digest(build / "monitor-profile.json"),
                compiler_sha256=digest(compiler), inputs=inputs, executions=executions, broker=broker, sessions_checked=sorted(sessions),
                guest_receipts=children, guest_gate_ids=sorted(shared.GATES),
                component_tests=component["tests_run"], okernel_unit_tests=kernel_count,
                language_sources=language_count, ci_run=ci["run_id"], skips=[], finished=time.time(),
                scope="Draft0 M3: real Linux, Plan9 and native EL1 fixture; each faults while two survivors progress, clean replacement and stale-handle/slot reuse; full aligned regressions. Eight table/context banks are implemented; live scope is three domains on AArch64 QEMU/TCG on X12.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("build", "runtime", "primary-result", "primary-execution", "resident-result", "resident-execution",
                 "guest-result", "guest-execution", "component-result", "unit-result", "ordinary-execution",
                 "provenance", "compiler", "ci-result", "broker-process", "ordinary-invocation", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-revision", required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("new immutable output required")
    value = dict(schema="ostadix.o10-m3-acceptance/v1", milestone="M3", contract_id=CONTRACT_ID,
                 ok=False, full_milestone_qualified=False, started=time.time())
    try:
        options = vars(args).copy(); options.pop("output")
        value.update(validate_acceptance(root=ROOT, **options))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ImportError, subprocess.SubprocessError) as error:
        value["error"] = type(error).__name__ + ": " + str(error)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(value, stream, indent=2); stream.write("\n")
    print(json.dumps(dict(ok=value["ok"], result=str(args.output))))
    return 0 if value["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
