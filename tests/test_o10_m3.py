"""Negative controls for the M3 evidence binder; no VM is launched."""
from __future__ import annotations
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import verify_o10_m3 as binder
import verify_o10_m1 as shared


def handle(generation, slot):
    return (generation << 32) | slot


def state(generation, slot, kind, instance):
    return dict(dom=handle(generation, slot), kind=kind, state=2,
                inst={"bytes_hex": bytes([instance] * 16).hex()})


def advance(labels, offset=0):
    return dict(baseline={n: offset for n in labels},
                after={n: offset + 1 for n in labels}, host_seconds=2 + offset)


def heartbeat(reads):
    raw = struct.pack("<8s7Q", b"O10M3HB1", 2 * reads, reads, 0, 117,
                      len(binder.CORPUS), 3, 0)
    return dict(host_seconds=reads, raw_hex=raw.hex(),
                decoded=binder.decode_heartbeat(raw))


def fixture():
    sha = hashlib.sha256(b"test exact image").hexdigest()
    initial = dict(linux=state(1, 0, 2, 10), plan9=state(1, 1, 2, 11),
                   native=state(1, 2, 3, 12))
    old = deepcopy(initial)
    cycles = []
    for index, target in enumerate(("linux", "plan9", "native")):
        after = deepcopy(old)
        after[target]["dom"] += 1 << 32
        after[target]["inst"] = {"bytes_hex": bytes([20 + index] * 16).hex()}
        others = binder.LABELS - {target}
        cycles.append(dict(target=target, before=deepcopy(old), after=deepcopy(after),
                           fault=dict(type="Rinject", dom=old[target]["dom"]),
                           survivors_while_faulted={n: deepcopy(old[n]) for n in others},
                           survivor_progress_while_faulted=advance(others, index),
                           all_three_progress_after_restore=advance(binder.LABELS, index)))
        old = after
    final = deepcopy(old)
    final["native"] = state(4, 2, 3, 30)
    checks = [dict(phase=phase, dom=dom, bytes=binder.CONTRACT["memory_bytes"],
                   sha256=sha, exact_image_and_zero_rest=True, heartbeat_zero=True)
              for phase, dom in (
                  ("created-provisioned-unbound", initial["native"]["dom"]),
                  ("restored-blocked-unbound", old["native"]["dom"]),
                  ("created-provisioned-unbound", final["native"]["dom"]))]
    timelines = [
        [(1,3),(5,4),(6,5),(8,6),(9,7),(12,8),(13,9)],
        [(15,3),(16,4),(17,5)],
        [(18,5),(19,6)]]
    groups = []
    for check, timeline in zip(checks, timelines):
        samples = []
        for seconds, reads in timeline:
            sample = heartbeat(reads); sample["host_seconds"] = seconds; samples.append(sample)
        groups.append(dict(dom=check["dom"], reset_proof=deepcopy(check),
                           samples=samples, last=samples[-1]["decoded"]))
    for row, times in zip(cycles, ((6,8),(9,12),(14,16))):
        row["survivor_progress_while_faulted"]["host_seconds"] = times[0]
        row["all_three_progress_after_restore"]["host_seconds"] = times[1]
    stale = [dict(message=name, dom=dom, error=dict(code=5, detail=4))
             for dom in (initial["native"]["dom"], old["native"]["dom"])
             for name in ("Tstat", "Tstart", "Twithdraw", "Trestore", "Tdestroy")]
    stale += [dict(message="Tbind", kind="old-lease", error=dict(code=5, detail=3)),
              dict(message="Tbind", kind="old-transport", error=dict(code=5, detail=4))]
    return dict(observation_start_monotonic=10.0, observation_end_monotonic=30.0, observation_elapsed_seconds=20.0,
                initial_states=initial, fault_cycles=cycles, final_states=final,
                native_image_checks=checks, native_heartbeats=groups, native_slot=2,
                final_native_lease_generation=3, stale_references=stale,
                final_progress=dict(advance(binder.LABELS, 4), host_seconds=19),
                destroyed_ram=dict(address=binder.CONTRACT["private_ram_pa"],
                                   bytes=binder.CONTRACT["memory_bytes"], all_zero=True,
                                   sha256=hashlib.sha256(bytes(binder.CONTRACT["memory_bytes"])).hexdigest())), sha


class CycleEvidenceTests(unittest.TestCase):
    def assert_rejected(self, change):
        value, sha = fixture()
        change(value)
        with self.assertRaises((shared.EvidenceError, ValueError)):
            binder.validate_cycle_records(value, sha)

    def test_complete_component_vector_accepted(self):
        value, sha = fixture()
        binder.validate_cycle_records(value, sha)

    def test_missing_fault_and_wrong_survivor_rejected(self):
        self.assert_rejected(lambda v: v["fault_cycles"].pop())
        self.assert_rejected(lambda v: v["fault_cycles"][0]["survivors_while_faulted"]["plan9"].update(dom=handle(2, 1)))

    def test_missing_counter_progress_rejected(self):
        self.assert_rejected(lambda v: v["fault_cycles"][0]["survivor_progress_while_faulted"]["after"].update(plan9=0))
        self.assert_rejected(lambda v: v["final_progress"]["baseline"].pop("native"))

    def test_restore_without_new_generation_or_instance_rejected(self):
        self.assert_rejected(lambda v: v["fault_cycles"][0]["after"]["linux"].update(dom=handle(1, 0)))
        self.assert_rejected(lambda v: v["fault_cycles"][0]["after"]["linux"].update(inst=v["initial_states"]["linux"]["inst"]))

    def test_incomplete_or_retained_ram_rejected(self):
        self.assert_rejected(lambda v: v["native_image_checks"][1].update(heartbeat_zero=False))
        self.assert_rejected(lambda v: v["native_image_checks"][1].update(sha256="0" * 64))
        self.assert_rejected(lambda v: v["destroyed_ram"].update(bytes=64))

    def test_reused_slot_without_new_generation_rejected(self):
        self.assert_rejected(lambda v: v["final_states"]["native"].update(dom=handle(2, 2)))

    def test_missing_old_handle_operation_rejected(self):
        self.assert_rejected(lambda v: v["stale_references"].pop(0))
        self.assert_rejected(lambda v: v["stale_references"][0]["error"].update(code=6))
        self.assert_rejected(lambda v: v["stale_references"][-1]["error"].update(detail=3))

    def test_raw_heartbeat_decode_and_fresh_progress_required(self):
        self.assert_rejected(lambda v: v["native_heartbeats"][1]["samples"][0]["decoded"].update(reads=900))
        self.assert_rejected(lambda v: v["native_heartbeats"][1].update(samples=[heartbeat(4), heartbeat(4)]))
        self.assert_rejected(lambda v: v["native_heartbeats"][1].update(reset_proof=v["native_image_checks"][0]))

    def test_heartbeat_regression_and_error_rejected(self):
        self.assert_rejected(lambda v: v["native_heartbeats"][1].update(samples=[heartbeat(4), heartbeat(3)]))
        def corrupt(v):
            row = v["native_heartbeats"][1]["samples"][0]
            raw = bytearray.fromhex(row["raw_hex"])
            raw[24] = 1
            row["raw_hex"] = raw.hex()
        self.assert_rejected(corrupt)

    def test_wrong_domain_kind_or_duplicate_slot_rejected(self):
        self.assert_rejected(lambda v: v["initial_states"]["native"].update(kind=2))
        self.assert_rejected(lambda v: v["initial_states"]["native"].update(dom=handle(1, 1)))


class ManagedEvidenceTests(unittest.TestCase):

    def test_role_specific_canonical_request_rejects_old_primary_and_wrong_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / "primary"; output.mkdir()
            args = ["o10-three-domains", "--execute", "--output", str(output),
                    "--mcp-release", "a" * 40]
            def verified(vector):
                return dict(canonical_api=dict(tool="o_cli", arguments=dict(
                    command="kernel", args=vector, cwd=str(root))),
                    canonical_argv=["o", "kernel"] + vector)
            options = dict(root=root, paths={"--output": output}, values={"--mcp-release": "a" * 40})
            binder.validate_role_request(verified(args), "primary", **options)
            wrong = list(args); wrong[0] = "o10-linux-restart"
            with self.assertRaises(shared.EvidenceError):
                binder.validate_role_request(verified(wrong), "primary", **options)
            wrong = list(args); wrong[wrong.index("--output") + 1] = str(root / "another")
            with self.assertRaises(shared.EvidenceError):
                binder.validate_role_request(verified(wrong), "primary", **options)
            with self.assertRaises(shared.EvidenceError):
                binder.validate_role_request(verified(args + ["--mcp-release", "a" * 40]), "primary", **options)

    def test_wrong_ci_head_and_missing_raw_lane_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "ci").mkdir()
            config = root / "ci/required-jobs.toml"
            config.write_text('schema = "ostadix.ci-required-jobs/v1"\nrequired_jobs = ["contracts", "python"]\n')
            raw = root / "required.log"; raw.write_text("CONTRACTS=success\nPYTHON=success\n")
            runs, jobs = root / "runs.json", root / "jobs.json"
            runs.write_text("{}"); jobs.write_text("{}")
            revision = "a" * 40
            ci = dict(head=revision, repository="lostadi/OSTADIX", run_status="completed",
                      run_conclusion="success", required_job_config=binder.identity(config),
                      required_job_ids=["contracts", "python"], required_lanes_passed=2,
                      raw_required_log=binder.identity(raw), required_aggregate_job=7,
                      run_id=100,
                      jobs=[dict(id=7, name="Required CI", status="completed", conclusion="success"),
                            dict(id=8, name="Contract surfaces", status="completed", conclusion="success"),
                            dict(id=9, name="Python reference runtime", status="completed", conclusion="success")],
                      api_commit_runs=binder.identity(runs), api_jobs=binder.identity(jobs))
            runs.write_text(json.dumps(dict(request=dict(tool="github.fetch_commit_workflow_runs", commit_sha=revision, repo_full_name="lostadi/OSTADIX"),
                                            response=dict(workflow_runs=[dict(id=100, name="CI", status="completed", conclusion="success")]))))
            jobs.write_text(json.dumps(dict(request=dict(tool="github.fetch_workflow_run_jobs", run_id=100, repo_full_name="lostadi/OSTADIX"),
                                            response=dict(jobs=ci["jobs"]))))
            ci["api_commit_runs"] = binder.identity(runs); ci["api_jobs"] = binder.identity(jobs)
            direct = root / "run.json"
            direct.write_text(json.dumps(dict(request=dict(tool="gh.api", path="repos/lostadi/OSTADIX/actions/runs/100"),
                response=dict(id=100, head_sha=revision, event="pull_request", name="CI", status="completed",
                              conclusion="success", repository=dict(full_name="lostadi/OSTADIX")))))
            ci["api_run"] = binder.identity(direct)
            path = root / "result.json"
            def write():
                path.write_text(json.dumps(ci))
            write(); binder.validate_ci(path, root, revision)
            ci["head"] = "b" * 40; write()
            with self.assertRaises(shared.EvidenceError):
                binder.validate_ci(path, root, revision)
            ci["head"] = revision
            raw.write_text("CONTRACTS=success\n"); ci["raw_required_log"] = binder.identity(raw); write()
            with self.assertRaises(shared.EvidenceError):
                binder.validate_ci(path, root, revision)
            raw.write_text("CONTRACTS=success\nPYTHON=success\n")
            ci["raw_required_log"] = binder.identity(raw)
            response = json.loads(direct.read_text())
            response["response"]["head_sha"] = "b" * 40
            direct.write_text(json.dumps(response)); ci["api_run"] = binder.identity(direct); write()
            with self.assertRaises(shared.EvidenceError):
                binder.validate_ci(path, root, revision)
            response["response"]["head_sha"] = revision
            direct.write_text(json.dumps(response)); ci["api_run"] = binder.identity(direct)
            reply = json.loads(runs.read_text())
            reply["response"]["workflow_runs"][0]["head_sha"] = "b" * 40
            runs.write_text(json.dumps(reply)); ci["api_commit_runs"] = binder.identity(runs); write()
            with self.assertRaises(shared.EvidenceError):
                binder.validate_ci(path, root, revision)


def counter_fixture(value):
    root = binder.three.ROOT
    spec = binder.importlib.util.spec_from_file_location("o10_m3_test_protocol",
        root / "ocore/guest/plan9/unified/protocol.py")
    protocol = binder.importlib.util.module_from_spec(spec)
    binder.sys.modules[spec.name] = protocol; spec.loader.exec_module(protocol)
    rows = []
    for label in ("linux", "plan9"):
        for index in range(2):
            service = dict(generation=f"{index + 1:016x}", instance=f"{index + 10:032x}")
            path = (f"/work/o10-m3-linux-{index}" if label == "linux" else
                    f"/services/plan9/g{service['generation']}/s{service['instance']}/m3-counter-{index}")
            observations = dict(path=path, bytes_hex=b"0\n1\n2\n3\n4\n".hex(),
                start_monotonic=(10.0 if index == 0 else 17.0 if label == "linux" else 20.0), samples=[dict(counter=i, earliest_host_seconds=i,
                              observed_host_seconds=i + .5) for i in range(5)],
                timing_scope="host monotonic observation brackets",
                largest_observed_gap_seconds=1.0, largest_append_gap_upper_bound_seconds=1.5)
            invocation = dict(path=path, dom=value["initial_states"][label]["dom"] + (index << 32))
            if label == "linux":
                invocation.update(phase="launched-once", command=binder.three.linux_counter_command(path))
            else:
                request_id = f"{index + 100:032x}"
                raw = protocol.encode_request(service["generation"], service["instance"], request_id,
                    ["/arm64/bin/rc", "-I", "-c", binder.three.common.plan9_counter_command(path)],
                    cwd="/n/work", stdin=b"", timeout_ms=300000)
                invocation.update(phase="submitted-once", service=service,
                    plan9_counter_request=dict(phase="submitted", id=request_id, service=service,
                        request={"bytes_hex": raw.hex()},
                        submit_marker={"bytes_hex": protocol.submit_marker(raw).hex()},
                        paths=protocol.request_paths("/n/okernel/services/plan9",
                            service["generation"], service["instance"], request_id)))
            rows.append(dict(label=label, path=path, invocation=invocation, observations=observations,
                completion=("unknown after a definite domain fault; never replayed" if index == 0 else
                            "active; provider completion unobserved")))
    value["counters"] = rows
    value["fault_cycles"][0]["interrupted_counter"] = deepcopy(rows[0])
    value["fault_cycles"][1]["interrupted_counter"] = deepcopy(rows[2])
    request = rows[2]["invocation"]["plan9_counter_request"]
    value["fault_cycles"][1]["unknown_service_outcome"] = dict(request_id=request["id"],
        request_sha256=hashlib.sha256(bytes.fromhex(request["request"]["bytes_hex"])).hexdigest())
    return value, root


def wire_fixture(value):
    sequence, tag = 0, 0
    value["o10_exchanges"], value["journal_replays"] = [], []
    def exchange(name, fields, response, result):
        nonlocal sequence, tag
        tag += 1
        read = name in ("Tversion", "Tstat")
        if not read:
            sequence += 1
        request = binder.o10.encode(name, tag, epoch=0 if name == "Tclaim" else 1,
                                   seq=0 if read else sequence, **fields)
        reply = binder.o10.encode(response, tag, **result)
        row = dict(completion="observed", request_hex=request.hex(), reply_hex=reply.hex(),
                   reply=binder.three.safe(binder.o10.decode(reply)))
        value["o10_exchanges"].append(row)
        return row
    def replay(row):
        value["o10_exchanges"].append(deepcopy(row))
        value["journal_replays"].append({k: row[k] for k in ("request_hex", "reply_hex")})
    def create(dom):
        return exchange("Tcreate", dict(kind=3, img_kernel=5, img_aux=6,
            mem_bytes=binder.CONTRACT["memory_bytes"], vcpus=1), "Rcreate", dict(dom=dom))
    def start(row):
        return exchange("Tstart", dict(dom=row["dom"], inst=shared.bytes_field(row["inst"], "inst")),
                        "Rstart", dict(dom=row["dom"]))
    def stat(row, phase):
        return exchange("Tstat", dict(dom=row["dom"]), "Rstat",
            dict(dom=row["dom"], kind=row["kind"], state=phase,
                 inst=shared.bytes_field(row["inst"], "inst"),
                 exits=0, switches=0, esr=0, ipa=0, pc=0, leases=0))
    def bind(row, generation):
        done = exchange("Tbind", dict(lease=(generation << 32) | 3,
                        transport=row["dom"] & ~0xffffffff), "Rbind",
                        dict(session=handle(generation, 3)))
        value.setdefault("native_bindings", []).append(dict(dom=row["dom"],
            previous_lease_generation=max(1, generation - 1), lease_generation=generation,
            reply=deepcopy(done["reply"])))
    exchange("Tclaim", dict(new_epoch=1, expected=0), "Rclaim", dict(epoch=1, last_seq=1, journal_low=1))
    replay(create(value["initial_states"]["native"]["dom"]))
    stat(value["initial_states"]["native"], 1)
    bind(value["initial_states"]["native"], 1)
    stat(value["initial_states"]["native"], 1)
    replay(start(value["initial_states"]["native"]))
    for cycle in value["fault_cycles"]:
        target = cycle["target"]; before, after = cycle["before"][target], cycle["after"][target]
        row = exchange("Tinject", dict(dom=before["dom"], fault=1), "Rinject", dict(dom=before["dom"]))
        cycle["fault"] = deepcopy(row["reply"])
        exchange("Tstat", dict(dom=before["dom"]), "Rstat", dict(dom=before["dom"], kind=before["kind"],
            state=4, inst=shared.bytes_field(before["inst"], "inst"),
            exits=0, switches=0, esr=0, ipa=0, pc=0, leases=0))
        kernel, auxiliary = {"linux": (3, 4), "plan9": (1, 2), "native": (5, 6)}[target]
        exchange("Trestore", dict(dom=before["dom"], inst=shared.bytes_field(after["inst"], "inst"),
                                 img_kernel=kernel, img_aux=auxiliary), "Rrestore", dict(dom=after["dom"]))
        if target == "native":
            stat(after, 3); bind(after, 2); stat(after, 2)
    destroy = exchange("Tdestroy", dict(dom=value["fault_cycles"][-1]["after"]["native"]["dom"]),
                       "Rdestroy", dict(dom=handle(3, 2)))
    value["native_destroy"] = deepcopy(destroy["reply"])
    replay(create(value["final_states"]["native"]["dom"]))
    stat(value["final_states"]["native"], 1)
    bind(value["final_states"]["native"], 3)
    stat(value["final_states"]["native"], 1)
    start(value["final_states"]["native"])
    for row in value["stale_references"]:
        name = row["message"]
        if name == "Tbind":
            lease = value["final_native_lease_generation"]
            new = value["final_states"]["native"]["dom"]
            old = value["fault_cycles"][-1]["after"]["native"]["dom"]
            fields = dict(lease=(((lease - 1) if row["kind"] == "old-lease" else lease) << 32) | 3,
                          transport=(new if row["kind"] == "old-lease" else old) & ~0xffffffff)
        else:
            fields = dict(dom=row["dom"])
            if name in ("Tstart", "Trestore"):
                fields["inst"] = bytes(16)
            if name == "Trestore":
                fields.update(img_kernel=5, img_aux=6)
            if name == "Twithdraw":
                fields.update(mode=0, deadline_ms=0)
        exchange(name, fields, "Rerror", row["error"])
    return value


class CounterAndWireTests(unittest.TestCase):
    def test_counter_raw_bytes_and_unknown_work_positive(self):
        value, _ = fixture(); value, root = counter_fixture(value)
        binder.validate_counters(value, root)

    def test_false_counter_progress_and_completion_rejected(self):
        value, _ = fixture(); value, root = counter_fixture(value)
        value["counters"][0]["observations"]["bytes_hex"] = b"0\n2\n".hex()
        with self.assertRaises(shared.EvidenceError): binder.validate_counters(value, root)
        value, _ = fixture(); value, root = counter_fixture(value)
        value["counters"][0]["completion"] = "completed"
        with self.assertRaises(shared.EvidenceError): binder.validate_counters(value, root)

    def test_unknown_plan9_request_identity_and_replay_rejected(self):
        value, _ = fixture(); value, root = counter_fixture(value)
        value["fault_cycles"][1]["unknown_service_outcome"]["request_sha256"] = "0" * 64
        with self.assertRaises(shared.EvidenceError): binder.validate_counters(value, root)

    def test_actual_codec_trace_positive(self):
        value, _ = fixture(); wire_fixture(value)
        binder.validate_wire(value)

    def test_false_faulted_state_and_restore_metadata_rejected(self):
        value, _ = fixture(); wire_fixture(value)
        value["o10_exchanges"] = [r for r in value["o10_exchanges"]
            if binder.o10.decode(bytes.fromhex(r["request_hex"]))["type"] != "Tstat"]
        with self.assertRaises(shared.EvidenceError): binder.validate_wire(value)
        value, _ = fixture(); wire_fixture(value)
        value["fault_cycles"][0]["after"]["linux"]["dom"] += 1 << 32
        with self.assertRaises(shared.EvidenceError): binder.validate_wire(value)

    def test_missing_wire_stale_request_and_replay_rejected(self):
        value, _ = fixture(); wire_fixture(value)
        value["o10_exchanges"].pop()
        with self.assertRaises(shared.EvidenceError): binder.validate_wire(value)
        value, _ = fixture(); wire_fixture(value)
        value["journal_replays"].pop()
        with self.assertRaises(shared.EvidenceError): binder.validate_wire(value)


class ReviewRegressionTests(unittest.TestCase):
    def test_phase_endpoint_cannot_use_future_native_or_counter_samples(self):
        value, sha = fixture()
        value["fault_cycles"][0]["survivor_progress_while_faulted"]["host_seconds"] = .01
        with self.assertRaises(shared.EvidenceError):
            binder.validate_cycle_records(value, sha)
        value, _ = fixture(); value, root = counter_fixture(value)
        value["fault_cycles"][0]["survivor_progress_while_faulted"]["host_seconds"] = 2.0
        value["fault_cycles"][0]["survivor_progress_while_faulted"]["after"]["plan9"] = 5
        with self.assertRaises(shared.EvidenceError):
            binder.validate_counters(value, root)

    def test_native_summary_cannot_exceed_raw_heartbeat_progress(self):
        value, sha = fixture()
        value["final_progress"]["after"]["native"] = 1000001
        with self.assertRaises(shared.EvidenceError):
            binder.validate_cycle_records(value, sha)

    def test_relative_counter_brackets_must_fit_actual_global_clock(self):
        value, _ = fixture(); value, root = counter_fixture(value)
        for row in value["counters"]:
            for sample in row["observations"]["samples"]:
                sample["earliest_host_seconds"] += 1000000
                sample["observed_host_seconds"] += 1000000
        value["fault_cycles"][0]["interrupted_counter"] = deepcopy(value["counters"][0])
        value["fault_cycles"][1]["interrupted_counter"] = deepcopy(value["counters"][2])
        with self.assertRaises(shared.EvidenceError):
            binder.validate_counters(value, root)

    def test_native_successful_bind_and_prebind_states_are_mandatory(self):
        value, _ = fixture(); wire_fixture(value)
        value["o10_exchanges"] = [row for row in value["o10_exchanges"]
            if not (binder.o10.decode(bytes.fromhex(row["request_hex"]))["type"] == "Tbind"
                    and binder.o10.decode(bytes.fromhex(row["reply_hex"]))["type"] == "Rbind")]
        with self.assertRaises(shared.EvidenceError):
            binder.validate_wire(value)
        value, _ = fixture(); wire_fixture(value)
        value["o10_exchanges"] = [row for row in value["o10_exchanges"]
            if not (binder.o10.decode(bytes.fromhex(row["reply_hex"]))["type"] == "Rstat"
                    and binder.o10.decode(bytes.fromhex(row["reply_hex"]))["state"] in (1, 3))]
        with self.assertRaises(shared.EvidenceError):
            binder.validate_wire(value)

    def test_readonly_replays_cannot_replace_known_mutation_replays(self):
        value, _ = fixture(); wire_fixture(value)
        selected = [row for row in value["o10_exchanges"]
                    if binder.o10.decode(bytes.fromhex(row["request_hex"]))["type"] == "Tstat"][:3]
        value["o10_exchanges"].extend(deepcopy(selected))
        value["journal_replays"] = [{k: row[k] for k in ("request_hex", "reply_hex")} for row in selected]
        with self.assertRaises(shared.EvidenceError):
            binder.validate_wire(value)


class BrokerIdentityTests(unittest.TestCase):
    def test_live_process_inode_start_and_all_four_producers_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            observed = binder.observe_process(binder.os.getpid())
            revision = "a" * 40
            provenance = dict(binary=dict(canonicalPath=observed["executable"]["path"],
                                          sha256=observed["executable"]["sha256"]))
            env = root / "env.json"; env.write_text(json.dumps(provenance))
            prefix = f"job-{observed['pid']}-1234567-1"
            value = dict(schema="ostadix.o10-broker-process/v1", source_revision=revision,
                source_root=str(root), provenance=binder.identity(env), pid=observed["pid"],
                start_ticks=observed["start_ticks"], executable=observed["executable"], job_prefix=prefix)
            status = root / "help-status.json"
            status.write_text(json.dumps(dict(job_id=prefix+"-9", pid=1234, state="completed",
                exit_code=0, error=None, signal=None, cleanup=dict(child_reaped=True, logs_drained=True))))
            value["status_reference"] = dict(binder.identity(status), bytes=status.stat().st_size)
            path = root / "broker.json"
            executions = {role: dict(job_id=prefix + "-" + str(i)) for i, role in
                          enumerate(("primary", "resident", "guest", "ordinary"), 1)}
            def write():
                path.write_text(json.dumps(value))
            write()
            binder.validate_broker(path, env, provenance, root, revision, executions)
            value["start_ticks"] += 1; write()
            with self.assertRaises(shared.EvidenceError):
                binder.validate_broker(path, env, provenance, root, revision, executions)
            value["start_ticks"] -= 1; write()
            executions["guest"]["job_id"] = prefix.replace("1234567", "9876543") + "-3"
            with self.assertRaises(shared.EvidenceError):
                binder.validate_broker(path, env, provenance, root, revision, executions)
            executions["guest"]["job_id"] = prefix + "-3"
            value["executable"] = dict(value["executable"], sha256="0" * 64); write()
            with self.assertRaises(shared.EvidenceError):
                binder.validate_broker(path, env, provenance, root, revision, executions)


class OrdinaryInvocationTests(unittest.TestCase):
    def test_reviewed_source_wrapper_and_argv_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            controller, wrapper, pins = root / "controller.py", root / "wrapper.O", root / "pins.json"
            controller.write_text("print('controller')\n"); wrapper.write_text("true;\n"); pins.write_text("{}\n")
            revision = "a" * 40
            invocation = dict(schema="ostadix.o10-ordinary-invocation/v1", source_revision=revision,
                source_root=str(root), cwd=str(root), controller=binder.identity(controller),
                wrapper=binder.identity(wrapper), argv=[binder.sys.executable, "-B", str(controller)],
                inputs=dict(pins=binder.identity(pins)))
            review = root / "review.json"
            sha = hashlib.sha256(json.dumps(invocation, sort_keys=True, separators=(",", ":"),
                                           allow_nan=False).encode()).hexdigest()
            review.write_text(json.dumps(dict(ok=True, invocation_sha256=sha)))
            invocation["review"] = binder.identity(review)
            path = root / "invocation.json"; path.write_text(json.dumps(invocation))
            checked = binder.validate_ordinary_invocation(path, root, revision)
            inner = root / "inner.json"
            command = dict(argv=checked["argv"], cwd=str(root), returncode=0, timed_out=False,
                           controller_source=checked["controller"])
            inner.write_text(json.dumps(command))
            verified = dict(canonical_api=dict(tool="o_execute", arguments=dict(
                cwd=str(root), source=wrapper.read_text())), inner_command=binder.identity(inner))
            binder.validate_role_request(verified, "ordinary", root=root, paths={}, values={}, invocation=checked)
            arbitrary = root / "arbitrary.py"; arbitrary.write_text("raise RuntimeError('99')\n")
            command["argv"] = [binder.sys.executable, "-B", str(arbitrary)]
            command["controller_source"] = binder.identity(arbitrary)
            inner.write_text(json.dumps(command)); verified["inner_command"] = binder.identity(inner)
            verified["canonical_api"]["arguments"]["source"] = "true"
            with self.assertRaises(shared.EvidenceError):
                binder.validate_role_request(verified, "ordinary", root=root, paths={}, values={}, invocation=checked)
            invocation["argv"].append("--different")
            path.write_text(json.dumps(invocation))
            with self.assertRaises(shared.EvidenceError):
                binder.validate_ordinary_invocation(path, root, revision)


if __name__ == "__main__":
    unittest.main()
