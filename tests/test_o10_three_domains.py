"""Host contract/negative tests for the explicit real three-domain gate.

These checks exercise the gate's real binary observations, authority boundaries,
journal bytes and dispatch guards. They dispatch no QEMU or guest workload.
"""
from __future__ import annotations

import hashlib
import copy
import shutil
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import o10
import verify_o10_three_domains as gate
from o10_native_fixture import CONTRACT


def reset_proof(holder):
    return dict(dom=holder, exact_image_and_zero_rest=True, heartbeat_zero=True)


def heartbeat(reads=3, *, seq=None, error=0, stage=3, reply=117, count=24):
    return struct.pack("<8s7Q", b"O10M3HB1", 2*reads if seq is None else seq,
                       reads, error, reply, count, stage, 7)


class QMP:
    def __init__(self):
        self.calls = []
    def execute(self, command):
        self.calls.append(command)


class WireDomain:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []
    def o10_call(self, kind, **fields):
        self.calls.append((kind, fields))
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply


class ThreeDomainGateTests(unittest.TestCase):
    def test_execute_guard_precedes_output_or_runtime_access(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(gate.common, "load_runtime") as load:
            output = Path(directory) / "evidence"
            with self.assertRaisesRegex(ValueError, "--execute"):
                gate.verify(execute=False, seed="missing", seed_head_sha256="0"*64,
                            build="missing", runtime="missing", output=output, mcp_release="0"*40)
            self.assertFalse(output.exists())
            load.assert_not_called()

    def test_canonical_help_and_missing_execute_do_not_dispatch(self):
        help_ = subprocess.run(["bash", str(ROOT/"scripts/o-kernel.sh"), "o10-three-domains", "--help"],
                               capture_output=True, text=True, timeout=20)
        self.assertEqual(help_.returncode, 0, help_.stderr)
        self.assertIn("--execute", help_.stdout)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/"never-created"
            result = subprocess.run(["bash", str(ROOT/"scripts/o-kernel.sh"), "o10-three-domains",
                "--seed-state", "missing", "--seed-head-sha256", "0"*64, "--build", "missing",
                "--runtime", "missing", "--output", str(output), "--mcp-release", "0"*40],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 2)
            self.assertIn("--execute is required", result.stderr)
            self.assertFalse(output.exists())

    def test_linux_counter_is_one_held_append_and_accepts_runner_suffix(self):
        command = gate.linux_counter_command("/work/o10-m3-linux-declared")
        self.assertEqual(command.count(" >> "), 1)
        self.assertIn("test ! -e ", command)
        result = subprocess.run(["/bin/sh", "-n"], input=command+
             "; _uw_rc=$?; printf '\\nTOKEN %s\\n' \"$_uw_rc\"\n",
             capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaises(ValueError):
            gate.linux_counter_command("/services/plan9/forbidden")

    def test_stopped_ram_observer_reads_only_fixed_native_window(self):
        address = CONTRACT["private_ram_pa"] + CONTRACT["heartbeat_ipa"] - CONTRACT["ram_ipa"]
        with tempfile.TemporaryFile() as memory:
            memory.seek(address-0x40000000)
            memory.write(heartbeat())
            memory.flush()
            domain = SimpleNamespace(ram=memory.fileno(), qmp=QMP(), stopped=mock.Mock())
            self.assertEqual(gate.ram_read(domain, address, 64), heartbeat())
            domain.stopped.assert_called_once()
            self.assertEqual(domain.qmp.calls, ["cont"])
            for base, count in ((0x6d000000,64),(CONTRACT["private_ram_pa"]-1,64),
                                (CONTRACT["private_ram_pa"]+CONTRACT["memory_bytes"]-1,64)):
                with self.assertRaises(ValueError):
                    gate.ram_read(domain, base, count)
            domain.o10_exchange_active = True
            with self.assertRaisesRegex(ValueError, "inside native"):
                gate.ram_read(domain, address, 64)
            self.assertEqual(domain.qmp.calls, ["cont"])

    def test_ram_observer_resumes_cpu_when_stability_check_fails(self):
        domain = SimpleNamespace(ram=42, qmp=QMP(), stopped=mock.Mock())
        with mock.patch.object(gate.os, "pread", side_effect=[b"a"*64,b"b"*64]):
            with self.assertRaisesRegex(ValueError, "observation changed"):
                gate.ram_read(domain, CONTRACT["private_ram_pa"], 64)
        self.assertEqual(domain.qmp.calls, ["cont"])

    def test_observer_defers_exchange_without_advancing_observation_bracket(self):
        now = [10.]
        domain = SimpleNamespace(o10_exchange_active=True, native_volume=mock.Mock())
        observers = gate.Observers(domain, {}, clock=lambda:now[0])
        now[0] = 12.
        observers.poll(force=True)
        self.assertEqual(observers.previous_poll, 10.)
        domain.native_volume.assert_not_called()
        domain.o10_exchange_active = False
        domain.linux_restart_witness_pending = 7
        observers.poll(force=True)
        self.assertEqual(observers.previous_poll, 10.)
        domain.native_volume.assert_not_called()
        domain.linux_restart_witness_pending = None
        domain.native_volume.return_value = SimpleNamespace(get=lambda path:b"0\n1\n2\n")
        row = observers.counter("linux","/work/o10-m3-linux-test",{})
        with mock.patch.object(gate.common.time, "monotonic", return_value=10.):
            # Preserve a controlled initial bracket through both deferrals.
            counter = observers.current["linux"][0]
            counter.start = counter.previous_poll = 10.
        observers.poll(force=True)
        self.assertEqual(row["observations"]["samples"][0]["earliest_host_seconds"],0.)
        self.assertEqual(row["observations"]["samples"][0]["observed_host_seconds"],2.)
        self.assertEqual(observers.previous_poll,12.)

    def test_native_observation_rejects_errors_regression_and_false_namespace_progress(self):
        domain = SimpleNamespace()
        for invalid in (heartbeat(error=5,stage=4), heartbeat(reply=107), heartbeat(count=23),
                        heartbeat(seq=8), heartbeat(reads=2)):
            observers = gate.Observers(domain, {})
            observers.native_start((1<<32)|6, reset_proof((1<<32)|6))  # slot6 is valid; no slot2 assumption.
            with mock.patch.object(gate,"ram_read",return_value=heartbeat()):
                observers.poll(force=True)
            with self.subTest(raw=invalid.hex()), mock.patch.object(gate,"ram_read",return_value=invalid):
                with self.assertRaises(ValueError):
                    observers.poll(force=True)
            self.assertFalse(observers.active)

    def test_native_odd_publication_and_initialization_do_not_count_as_reads(self):
        observers = gate.Observers(SimpleNamespace(),{})
        observers.native_start((1<<32)|7, reset_proof((1<<32)|7))
        with mock.patch.object(gate,"ram_read",return_value=bytes(64)):
            observers.poll(force=True)
        self.assertEqual(observers.values(["native"]),{"native":0})
        with mock.patch.object(gate,"ram_read",return_value=heartbeat(seq=5)):
            observers.poll(force=True)
        self.assertEqual(observers.values(["native"]),{"native":0})
        with mock.patch.object(gate,"ram_read",return_value=heartbeat()):
            observers.poll(force=True)
        self.assertEqual(observers.values(["native"]),{"native":3})
        observers.native_stop()
        observers.native_start((2<<32)|7, reset_proof((2<<32)|7))
        with mock.patch.object(gate,"ram_read",return_value=heartbeat(reads=1)):
            observers.poll(force=True)
        self.assertEqual(observers.values(["native"]),{"native":1})

    def test_window_is_global_and_counter_prefix_is_strict(self):
        now=[0.]
        domain=SimpleNamespace(native_volume=mock.Mock())
        observers=gate.Observers(domain,{},clock=lambda:now[0])
        now[0]=240.
        with self.assertRaisesRegex(ValueError,"240s"):
            observers.poll(force=True)
        domain.native_volume.assert_not_called()
        counter=gate.common.Counter(domain,"/work/declared")
        counter.observe(b"0\n1\n2\n",counter.start+1)
        for malformed in (b"0\n2\n",b"0\n1\n",b"0\n1\n2\n4\n"):
            with self.subTest(data=malformed),self.assertRaises(ValueError):
                counter.observe(malformed,counter.start+2)

    def test_observation_anchors_bind_counter_relative_samples_to_the_global_clock(self):
        now = [10.]
        domain = SimpleNamespace(native_volume=lambda: {"/work/counter": b"0\n1\n2\n"})
        record = {}
        observers = gate.Observers(domain, record, clock=lambda: now[0])
        self.assertEqual(record["observation_start_monotonic"], 10.)
        now[0] = 11.
        with mock.patch.object(gate.common.time, "monotonic", side_effect=lambda: now[0]):
            row = observers.counter("linux", "/work/counter", {})
        now[0] = 14.
        observers.poll(force=True)
        observations = row["observations"]
        self.assertEqual(observations["start_monotonic"], 11.)
        for sample in observations["samples"]:
            lo = observations["start_monotonic"] + sample["earliest_host_seconds"]
            hi = observations["start_monotonic"] + sample["observed_host_seconds"]
            self.assertTrue(10. <= lo <= hi <= 14.)
        original_pump = mock.Mock()
        now[0] = 20.
        self.assertEqual(observers.finish(original_pump), 10.)
        self.assertIs(domain.pump, original_pump)
        self.assertEqual(record["observation_end_monotonic"], 20.)
        self.assertEqual(record["observation_elapsed_seconds"], 10.)

    def test_blocking_counter_or_native_snapshot_cannot_overrun_global_window(self):
        for kind in ("counter", "native"):
            now, record = [10.], {}
            def volume():
                now[0] = 250.1
                return {"/work/counter": b"0\n1\n2\n"}
            domain = SimpleNamespace(native_volume=volume)
            observers = gate.Observers(domain, record, clock=lambda: now[0])
            if kind == "counter":
                with mock.patch.object(gate.common.time, "monotonic", return_value=10.):
                    observers.counter("linux", "/work/counter", {})
            else:
                observers.native_start((1 << 32) | 7, reset_proof((1 << 32) | 7))
            def native_read(*args):
                now[0] = 250.1
                return heartbeat()
            now[0] = 249.9
            with self.subTest(kind=kind), mock.patch.object(gate, "ram_read", side_effect=native_read):
                with self.assertRaisesRegex(ValueError, "exceeded during poll"):
                    observers.poll(force=True)
            self.assertFalse(observers.active)
            self.assertEqual(observers.previous_poll, 250.1)
            # The overrun evidence is retained, while the observation fails.
            if kind == "native":
                self.assertGreater(record["native_heartbeats"][0]["samples"][0]["host_seconds"], 240.)
            else:
                self.assertGreater(record["counters"][0]["observations"]["samples"][0]["observed_host_seconds"], 240.)

    def test_finish_requires_positive_bounded_elapsed_and_always_restores_pump(self):
        for elapsed in (0., -1., 240.001, 240.):
            now, record = [10.], {}
            original = mock.Mock()
            domain = SimpleNamespace(pump=mock.Mock())
            observers = gate.Observers(domain, record, clock=lambda: now[0])
            now[0] += elapsed
            with self.subTest(elapsed=elapsed):
                if 0 < elapsed <= 240:
                    self.assertEqual(observers.finish(original), elapsed)
                else:
                    with self.assertRaisesRegex(ValueError, "ended outside"):
                        observers.finish(original)
            self.assertIs(domain.pump, original)
            self.assertEqual(record["observation_end_monotonic"], now[0])
            self.assertEqual(record["observation_elapsed_seconds"], elapsed)

    def test_verify_freezes_observations_before_closure_checks_and_restores_pump_on_failure(self):
        real_observers = gate.Observers
        for outcome in ("success", "cycles-failed", "window-overrun"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                for name in ("seed", "build", "runtime"):
                    (folder / name).mkdir()
                (folder / "build/monitor-profile.json").write_text("{}")
                now, observed, domains, events = [10.], [], [], []
                frozen = {"complete_frozen_fixture": True}
                pin = {"identity": {"sha256": "a" * 64}}
                class Domain:
                    def __init__(self, state, build, qemu, **kwargs):
                        self.session = state / "host-only-session"
                        self.session.mkdir(parents=True)
                        self.process = SimpleNamespace(pid=os.getpid(), returncode=None, poll=lambda: 0)
                        self.record = {}
                        self.capture = bytearray()
                        self.original_pump = self.pump
                        self.snapshots = 0
                        domains.append(self)
                    def ready(self):
                        pass
                    def o10_claim(self):
                        pass
                    def pump(self, duration=.1):
                        events.append("original-pump")
                    def native_volume(self):
                        self.snapshots += 1
                        return {"/work/counter": b"0\n1\n2\n"}
                    def close(self):
                        self.assert_original("close")
                        now[0] = 30.
                        self.pump()
                        self.process.returncode = 0
                    def assert_original(self, phase):
                        if self.pump != self.original_pump:
                            raise AssertionError("observer pump still installed during " + phase)
                        events.append(phase)
                def make_observers(domain, record):
                    value = real_observers(domain, record, clock=lambda: now[0])
                    observed.append(value)
                    return value
                def cycles(domain, observers, record, *args):
                    now[0] = 11.
                    observers.counter("linux", "/work/counter", {})
                    now[0] = 12.
                    domain.pump()
                    if outcome == "cycles-failed":
                        raise ValueError("original cycle failure")
                    now[0] = 251. if outcome == "window-overrun" else 20.
                def closure(*args):
                    domain = domains[0]
                    domain.assert_original("closure")
                    self.assertEqual(observed[0].record["observation_end_monotonic"], 20.)
                    now[0] = 25.
                    domain.pump()
                    return frozen
                runner = SimpleNamespace(UnifiedDomain=Domain, o10=object())
                with mock.patch.object(gate.common, "load_runtime", return_value=(runner, object(), None)), \
                        mock.patch.object(gate, "preflight", return_value=("b" * 40, {"source_sha256": {}}, {}, frozen, {})), \
                        mock.patch.object(gate, "pinned_seed", return_value=pin), \
                        mock.patch.object(gate, "fork_pinned_seed", return_value={"ok": True}), \
                        mock.patch.object(gate.common, "trace"), \
                        mock.patch.object(gate, "Observers", side_effect=make_observers), \
                        mock.patch.object(gate, "run_cycles", side_effect=cycles), \
                        mock.patch.object(gate, "native_image_envelope", return_value=b"host fixture"), \
                        mock.patch.object(gate, "runtime_identity", side_effect=closure), \
                        mock.patch.object(gate.common.time, "monotonic", side_effect=lambda: now[0]), \
                        mock.patch.object(gate, "command", return_value={"returncode": 0, "stdout": ""}):
                    record = gate.verify(execute=True, seed=folder / "seed", seed_head_sha256="a" * 64,
                                         build=folder / "build", runtime=folder / "runtime",
                                         output=folder / "output", mcp_release="b" * 40)
                self.assertEqual(record["gate_passed"], outcome == "success", record.get("error"))
                self.assertTrue(record["cleanup"]["closed"])
                self.assertEqual(domains[0].snapshots, 1)
                self.assertEqual(len(record["counters"][0]["observations"]["samples"]), 3)
                self.assertEqual(record["counters"][0]["observations"]["start_monotonic"], 11.)
                self.assertIn("close", events)
                if outcome == "success":
                    self.assertLess(events.index("closure"), events.index("close"))
                    self.assertEqual(record["observation_start_monotonic"], 10.)
                    self.assertEqual(record["observation_end_monotonic"], 20.)
                    self.assertEqual(record["observation_elapsed_seconds"], 10.)
                else:
                    self.assertNotIn("closure", events)
                    expected = "original cycle failure" if outcome == "cycles-failed" else "ended outside"
                    self.assertIn(expected, record["error"])

    def test_only_estale_can_refresh_native_lease_and_unknown_is_never_replayed(self):
        domain=WireDomain([o10.O10Error(o10.O10_ESTALE,4),dict(type="Rbind",session=17)])
        record={}
        self.assertEqual(gate.bind_native(domain,o10,(3<<32)|7,3,record),4)
        self.assertEqual([row[1]["lease"] for row in domain.calls],[(3<<32)|3,(4<<32)|3])
        self.assertTrue(all(row[1]["transport"]==3<<32 for row in domain.calls))
        for error in (TimeoutError("unknown"),o10.O10Error(o10.O10_ESTALE,3),
                      o10.O10Error(o10.O10_EDENIED,5)):
            domain=WireDomain([error])
            with self.subTest(error=str(error)),self.assertRaises((ValueError,TimeoutError)):
                gate.bind_native(domain,o10,(3<<32)|7,3,{})
            self.assertEqual(len(domain.calls),1)

    def test_stale_reference_checks_require_exact_error_and_generation(self):
        domain=WireDomain([o10.O10Error(o10.O10_ESTALE,3)])
        self.assertEqual(gate.expect_stale(domain,o10,"Tdestroy",dom=(2<<32)|7,detail=3),
                         {"code":5,"detail":3})
        for reply in (dict(type="Rdestroy",dom=(2<<32)|7),
                      o10.O10Error(o10.O10_ESTATE,3),o10.O10Error(o10.O10_ESTALE,4)):
            with self.subTest(reply=reply),self.assertRaises(ValueError):
                gate.expect_stale(WireDomain([reply]),o10,"Tdestroy",dom=(2<<32)|7,detail=3)

    def test_survivors_allow_wfi_but_require_same_generation_and_instance(self):
        before={"native":{"dom":(1<<32)|7,"inst":b"a"*16,"state":2}}
        gate.same_survivors(before,{"native":dict(before["native"],state=3)})
        for changed in (dict(dom=(2<<32)|7),dict(inst=b"b"*16),dict(state=4)):
            after={"native":dict(before["native"],**changed)}
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                gate.same_survivors(before,after)

    def test_journal_replay_compares_exact_real_codec_bytes(self):
        request=o10.encode("Tcreate",5,epoch=1,seq=2,kind=3,img_kernel=5,img_aux=6,mem_bytes=0x200000,vcpus=1)
        reply=o10.encode("Rcreate",5,dom=(1<<32)|7)
        row=dict(request_hex=request.hex(),reply_hex=reply.hex(),completion="observed")
        record={"o10_exchanges":[row]}
        domain=SimpleNamespace()
        def exchange(frame):
            self.assertEqual(o10.decode(frame)["seq"],2)
            record["o10_exchanges"].append(dict(reply_hex=reply.hex()))
            return o10.decode(reply)
        domain.o10_exchange=exchange
        self.assertEqual(gate.replay_applied(domain,record,row)["dom"],(1<<32)|7)
        self.assertEqual(len(record["journal_replays"]),1)
        def wrong(frame):
            record["o10_exchanges"].append(dict(reply_hex=o10.encode("Rcreate",6,dom=(1<<32)|7).hex()))
        domain.o10_exchange=wrong
        with self.assertRaisesRegex(ValueError,"reply bytes"):
            gate.replay_applied(domain,record,row)


    def test_create_derives_returned_slot_and_replays_known_creation(self):
        for slot in (6,7):
            holder=(1<<32)|slot
            record={"o10_exchanges":[]}
            domain=SimpleNamespace(o10_linux=1<<32,o10_plan9=(1<<32)|1)
            def call(message,**fields):
                if message=="Tcreate":
                    raw=o10.encode(message,4,epoch=1,seq=2,**fields)
                    reply=o10.encode("Rcreate",4,dom=holder)
                    record["o10_exchanges"].append(dict(request_hex=raw.hex(),reply_hex=reply.hex(),completion="observed"))
                    return o10.decode(reply)
                self.assertEqual((message,fields),("Tstat",{"dom":holder}))
                return dict(type="Rstat",dom=holder,state=1)
            def exchange(frame):
                self.assertEqual(o10.decode(frame)["img_kernel"],5)
                reply=o10.encode("Rcreate",4,dom=holder)
                record["o10_exchanges"].append(dict(reply_hex=reply.hex()))
                return o10.decode(reply)
            domain.o10_call,domain.o10_exchange=call,exchange
            envelope=bytes(CONTRACT["memory_bytes"])
            with mock.patch.object(gate,"ram_read",return_value=envelope):
                created,proof=gate.create_native(domain,record,envelope)
            self.assertEqual(created,holder)
            self.assertTrue(proof["heartbeat_zero"])
            self.assertEqual(len(record["journal_replays"]),1)

    def test_both_native_starts_require_exact_post_bind_provisioned_holder(self):
        instance = bytes.fromhex("34" * 16)
        for generation in (1, 9):
            holder = (generation << 32) | 7
            domain = WireDomain([dict(type="Rstat", dom=holder, state=1),
                                 dict(type="Rstart", dom=holder)])
            with self.subTest(generation=generation), mock.patch.object(gate.secrets, "token_bytes", return_value=instance):
                reply = gate.start_native(domain, holder)
            self.assertEqual(reply, dict(type="Rstart", dom=holder))
            self.assertEqual(domain.calls, [("Tstat", dict(dom=holder)),
                                           ("Tstart", dict(dom=holder, inst=instance))])
        holder = (9 << 32) | 7
        for state in (0, 2, 3, 4, 5, True, None, "1"):
            domain = WireDomain([dict(type="Rstat", dom=holder, state=state)])
            with self.subTest(state=state), self.assertRaisesRegex(ValueError, "PROVISIONED"):
                gate.start_native(domain, holder)
            self.assertEqual(domain.calls, [("Tstat", dict(dom=holder))])
        domain = WireDomain([dict(type="Rstat", dom=(8 << 32) | 7, state=1)])
        with self.assertRaisesRegex(ValueError, "exact native holder"):
            gate.start_native(domain, holder)
        self.assertEqual(domain.calls, [("Tstat", dict(dom=holder))])

    def test_plan9_counter_is_armed_before_publication_and_first_append_bracket(self):
        now = [10.]
        data = [b""]
        domain = SimpleNamespace(service=dict(generation="1" * 16, instance="2" * 32),
                                 o10_plan9=(1 << 32) | 6,
                                 native_volume=lambda: {path: data[0]})
        record = {}
        observers = gate.Observers(domain, record, clock=lambda: now[0])
        invocation = dict(id="4" * 32, phase="submitted")
        path = None
        def publish(actual_domain, protocol, actual_path, *, record):
            nonlocal path
            path = actual_path
            self.assertIs(actual_domain, domain)
            self.assertIn("plan9", observers.current, "counter must be armed before publication")
            counter, counter_row = observers.current["plan9"]
            self.assertEqual(counter.path, path)
            self.assertEqual(counter.start, 10.)
            self.assertEqual(counter.data, b"")
            self.assertIs(counter_row["invocation"], record)
            record["plan9_counter_request"] = invocation
            now[0] = 12.
            data[0] = b"0\n1\n2\n"
            return invocation
        with mock.patch.object(gate.common.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(gate.common, "publish_counter", side_effect=publish) as publication:
            actual = gate.start_plan9_counter(domain, observers, record, "nonce", object())
        self.assertIs(actual, invocation)
        publication.assert_called_once()
        observations = record["counters"][0]["observations"]
        self.assertEqual(observations["start_monotonic"], 10.)
        self.assertEqual(observations["samples"][0]["earliest_host_seconds"], 0.)
        self.assertEqual(observations["samples"][0]["observed_host_seconds"], 2.)
        self.assertEqual(record["plan9_counter_invocations"][0]["phase"], "submitted-once")

    def test_unknown_plan9_publication_retains_armed_counter_and_is_not_resubmitted(self):
        now, record = [10.], {}
        domain = SimpleNamespace(service=dict(generation="1" * 16, instance="2" * 32),
                                 o10_plan9=(1 << 32) | 6)
        observers = gate.Observers(domain, record, clock=lambda: now[0])
        unknown = TimeoutError("publication outcome unknown")
        invocation = dict(id="4" * 32, request=b"intended request bytes",
                          phase="submission-pending")
        def publish(actual_domain, protocol, path, *, record):
            self.assertIn("plan9", observers.current, "counter must be armed before publication")
            counter, counter_row = observers.current["plan9"]
            self.assertEqual(counter.start, 10.)
            self.assertEqual(counter.path, path)
            self.assertIs(counter_row["invocation"], record)
            record["plan9_counter_request"] = invocation
            raise unknown
        with mock.patch.object(gate.common.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(gate.common, "publish_counter", side_effect=publish) as publication, \
                mock.patch.object(observers, "progress") as progress:
            with self.assertRaises(TimeoutError) as caught:
                gate.start_plan9_counter(domain, observers, record, "nonce", object())
        self.assertIs(caught.exception, unknown)
        publication.assert_called_once()
        progress.assert_not_called()
        self.assertEqual(len(record["plan9_counter_invocations"]), 1)
        row = record["plan9_counter_invocations"][0]
        self.assertIs(row["plan9_counter_request"], invocation)
        self.assertEqual(row["phase"], "preparing-new-explicit-request")
        self.assertEqual(record["counters"][0]["path"], row["path"])
        self.assertEqual(observers.current["plan9"][0].start, 10.)

    def test_unknown_counter_is_retained_and_new_work_uses_a_different_path(self):
        domain=SimpleNamespace(command=mock.Mock())
        observers=gate.Observers(domain,{})
        domain.o10_linux=(1<<32)|4
        with mock.patch.object(observers,"progress",return_value={}):
            first=gate.start_linux_counter(domain,observers,{}, "nonce")
            unknown=observers.unknown("linux")
            second=gate.start_linux_counter(domain,observers,{}, "nonce")
        self.assertEqual(len(domain.command.call_args_list),2)
        self.assertNotEqual(first["path"],second["path"])
        self.assertIn("never replayed",unknown["completion"])
        self.assertEqual(unknown["invocation"]["path"],first["path"])
        self.assertNotEqual(unknown["invocation"]["command"],second["command"])


    def incomplete_runtime(self, root):
        """The old three-file review reproducer must now fail admission."""
        runtime=root/"runtime";build=root/"build"
        for directory in (runtime/"build",runtime/"tools/bin",runtime/"tools/native",build):
            directory.mkdir(parents=True,exist_ok=True)
        for name,data in (("build/monitor-profile.json",b"{}"),("tools/bin/qemu-system-aarch64",b"wrapper"),
                          ("tools/native/qemu-system-aarch64",b"binary")):
            (runtime/name).write_bytes(data)
        (build/"monitor-profile.json").write_bytes(b"{}")
        inventory={name:{key:gate.identity(runtime/name)[key] for key in ("sha256","bytes")}
                   for name in ("build/monitor-profile.json","tools/bin/qemu-system-aarch64","tools/native/qemu-system-aarch64")}
        manifest=dict(schema=gate.freezer.SCHEMA,passed=True,sources_build_tools_unchanged=True,
                      self_check={"exit_status":0},inventory=inventory)
        (runtime/"runtime.json").write_text(json.dumps(manifest))
        return runtime,build


    def test_manifest_cannot_choose_alternate_engine_or_ldd_before_subprocess(self):
        canonical=dict(engine=gate.identity(Path("/usr/bin/qemu-system-aarch64").resolve()),
                       ldd=gate.identity(Path("/usr/bin/ldd").resolve()))
        for field,alternate in (("engine",Path(sys.executable).resolve()),("ldd",Path("/usr/bin/true").resolve(strict=True))):
            value=dict(schema=gate.freezer.SCHEMA,passed=True,sources_build_tools_unchanged=True,
                       self_check={"exit_status":0},
                       tools={"qemu-system-aarch64":{"selected":canonical["engine"]}},
                       external_host_dependencies={"ldd":canonical["ldd"]})
            # These are valid current host executables, with true identities.
            descriptor=gate.identity(alternate)
            if field=="engine":value["tools"]["qemu-system-aarch64"]["selected"]=descriptor
            else:value["external_host_dependencies"]["ldd"]=descriptor
            with self.subTest(field=field),mock.patch.object(gate.common,"document",return_value=value), \
                 mock.patch.object(gate,"retained_files") as inventory, \
                 mock.patch.object(gate.subprocess,"run") as execute:
                with self.assertRaisesRegex(ValueError,"canonical /usr/bin/"):
                    gate.runtime_identity(Path("/unused-runtime"),Path("/unused-build"))
                execute.assert_not_called()
                inventory.assert_not_called()
        value=dict(tools={"qemu-system-aarch64":{"selected":canonical["engine"]}},
                   external_host_dependencies={"ldd":canonical["ldd"]})
        self.assertEqual(gate.trusted_runtime_tools(value),canonical)

    def test_three_file_runtime_and_unlisted_dependency_are_rejected(self):
        for unlisted in (False,True):
            with self.subTest(unlisted=unlisted),tempfile.TemporaryDirectory() as directory:
                runtime,build=self.incomplete_runtime(Path(directory))
                if unlisted:
                    (runtime/"tools/native/unlisted-dependency.so").write_bytes(b"changed dependency")
                with self.assertRaises(ValueError):
                    gate.runtime_identity(runtime,build)

    def compiled_fixture(self, directory):
        build=Path(directory)/"build"
        names=gate.builder.captured_source_paths("qualified-original-userland",native_fixture=True)
        hashes,captures={},{}
        for name in names:
            path=build/"sources"/name;path.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/name,path)
            hashes[name]=gate.digest(ROOT/name)
            captures[name]={key:gate.identity(path)[key] for key in ("sha256","bytes")}
            captures[name]["path"]="sources/"+name
        return build,dict(plan9_derivation_kind="qualified-original-userland",
                          source_sha256=hashes,source_artifacts=captures)

    def test_canonical_compiled_source_closure_rejects_omissions_and_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            build,profile=self.compiled_fixture(directory)
            verified=gate.compiled_source_identity(profile,build)
            self.assertEqual(set(verified),set(gate.builder.captured_source_paths(
                             "qualified-original-userland",native_fixture=True)))
            for omitted in ("all","ocore/kernel/aarch64/unified_world/monitor.S",
                            "ocore/guest/native/o10_m3/fixture.c","ocore/runtime/aarch64/domain_table.oc"):
                altered=copy.deepcopy(profile)
                if omitted=="all":
                    altered["source_sha256"].clear();altered["source_artifacts"].clear()
                else:
                    del altered["source_sha256"][omitted];del altered["source_artifacts"][omitted]
                with self.subTest(omitted=omitted),self.assertRaisesRegex(ValueError,"complete canonical"):
                    gate.compiled_source_identity(altered,build)
            path=build/"sources/ocore/runtime/aarch64/unified_world.oc"
            path.write_bytes(path.read_bytes()+b"\n// altered capture\n")
            with self.assertRaisesRegex(ValueError,"source capture drift"):
                gate.compiled_source_identity(profile,build)

    def test_builder_and_gate_share_one_native_source_capture_recipe(self):
        names=gate.builder.captured_source_paths("qualified-original-userland",native_fixture=True)
        self.assertEqual(len(names),len(set(names)))
        self.assertTrue(set(gate.builder.SOURCES)<=set(names))
        self.assertTrue(set(gate.builder.native_fixture_builder.SOURCES)<=set(names))
        self.assertIn("scripts/build_o10_native_fixture.py",names)
        self.assertNotIn("ocore/guest/native/o10_m3/fixture.c",
            gate.builder.captured_source_paths("qualified-original-userland",native_fixture=False))
        with self.assertRaises(ValueError):
            gate.builder.captured_source_paths("unsupported",native_fixture=True)

    def test_restored_ram_must_match_images_and_zero_heartbeat_before_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            kernel=Path(directory)/"kernel";aux=Path(directory)/"aux"
            kernel.write_bytes(bytes(range(1,128)));aux.write_bytes(gate.auxiliary_image())
            envelope=gate.native_image_envelope({"inputs/native-fixture.kernel":kernel,
                                                "inputs/native-fixture.aux":aux})
        holder=(2<<32)|7;record={};domain=SimpleNamespace(o10_call=mock.Mock())
        with mock.patch.object(gate,"ram_read",return_value=envelope):
            proof=gate.check_native_image(domain,envelope,record,"restored-blocked-unbound",holder)
        self.assertEqual(proof["sha256"],hashlib.sha256(envelope).hexdigest())
        self.assertTrue(proof["exact_image_and_zero_rest"])
        offsets=(0,0x100000,CONTRACT["heartbeat_ipa"]-CONTRACT["ram_ipa"],0x1f1000,0x1fffff)
        for offset in offsets:
            bad=bytearray(envelope)
            if offset==CONTRACT["heartbeat_ipa"]-CONTRACT["ram_ipa"]:
                bad[offset:offset+64]=heartbeat(reads=12)  # exact sealed review control
            else:
                bad[offset]^=1
            with self.subTest(offset=offset),mock.patch.object(gate,"ram_read",return_value=bytes(bad)):
                with self.assertRaisesRegex(ValueError,"reset not observed before bind"):
                    gate.check_native_image(domain,envelope,record,"restored-blocked-unbound",holder)
        domain.o10_call.assert_not_called()
        observers=gate.Observers(SimpleNamespace(),{})
        with self.assertRaisesRegex(ValueError,"pre-bind reset/image proof"):
            observers.native_start(holder)
        observers.native_start(holder,proof)
        with mock.patch.object(gate,"ram_read",return_value=heartbeat(reads=1)):
            observers.poll(force=True)
        self.assertEqual(observers.values(["native"]),{"native":1})

    def seed_fixture(self, directory):
        seed=Path(directory)/"seed";seed.mkdir()
        head={"schema":"ostadix.package-domain-disk-head/v2",
              "disk":{"path":str(seed/"original.ext4"),"bytes":4,"sha256":hashlib.sha256(b"disk").hexdigest()},
              "namespace":{"path":str(seed/"original.raw"),"bytes":5,"sha256":hashlib.sha256(b"store").hexdigest()}}
        (seed/"head.json").write_text(json.dumps(head)+"\n")
        return seed,gate.pinned_seed(seed,gate.digest(seed/"head.json"))

    def fake_fork(self, seed, state, pin, *, alter=None):
        state.mkdir()
        selected=copy.deepcopy(pin["head"])
        for name,folder,suffix in (("disk","disk-generations",".ext4"),
                                    ("namespace","namespace-generations",".raw")):
            selected[name]["path"]=str(state/folder/(selected[name]["sha256"]+suffix))
        selected["fork_origin"]={"source":str(seed),"head_sha256":pin["identity"]["sha256"]}
        raw=bytes.fromhex(pin["raw_hex"])
        if alter=="head":
            raw=b'{"changed":true}\n'
        if alter in ("disk","namespace"):
            selected[alter]["sha256"]="0"*64
        if alter=="origin":
            selected["fork_origin"]["head_sha256"]="0"*64
        (state/"source-head.json").write_bytes(raw)
        (state/"head.json").write_text(json.dumps(selected))
        return dict(ok=True,source_head_changed_during_copy=False,selected_head=selected)

    def test_requested_seed_pin_survives_recapture_fork_and_pair_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            seed,pin=self.seed_fixture(directory);state=Path(directory)/"fork"
            forker=SimpleNamespace(fork=lambda source,dest:self.fake_fork(source,dest,pin))
            result=gate.fork_pinned_seed(forker,seed,state,pin)
            self.assertEqual(result["selected_head"]["fork_origin"]["head_sha256"],pin["identity"]["sha256"])
        with tempfile.TemporaryDirectory() as directory:
            seed,pin=self.seed_fixture(directory)
            (seed/"head.json").write_text('{"replacement":true}\n')  # synthetic seed only
            forker=SimpleNamespace(fork=mock.Mock())
            with self.assertRaisesRegex(ValueError,"requested seed head changed"):
                gate.fork_pinned_seed(forker,seed,Path(directory)/"fork",pin)
            forker.fork.assert_not_called()
        for altered in ("head","disk","namespace","origin"):
            with self.subTest(altered=altered),tempfile.TemporaryDirectory() as directory:
                seed,pin=self.seed_fixture(directory)
                forker=SimpleNamespace(fork=lambda source,dest:self.fake_fork(source,dest,pin,alter=altered))
                with self.assertRaises(ValueError):
                    gate.fork_pinned_seed(forker,seed,Path(directory)/"fork",pin)

    def test_preflight_rejects_dirty_source_before_any_runtime_or_guest(self):
        with tempfile.TemporaryDirectory() as directory:
            seed=Path(directory)/"seed";seed.mkdir();(seed/"head.json").write_text("{}")
            values=[dict(returncode=0,stdout="a"*40),dict(returncode=0,stdout=" M changed\n")]
            with mock.patch.object(gate,"command",side_effect=values),mock.patch.object(gate,"runtime_identity") as runtime:
                with self.assertRaisesRegex(ValueError,"clean source"):
                    gate.preflight(seed,gate.digest(seed/"head.json"),Path(directory)/"build",
                                   Path(directory)/"runtime","a"*40,SimpleNamespace())
                runtime.assert_not_called()


if __name__ == "__main__":
    unittest.main()
