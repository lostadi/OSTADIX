"""O10 runner transport and lifecycle tests; no QEMU qualification claim."""
import importlib.util
from pathlib import Path
import struct
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("o10_runner", ROOT / "scripts/okernel_unified_world.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
o10 = runner.o10


def domain():
    value = runner.UnifiedDomain.__new__(runner.UnifiedDomain)
    value.recovery = runner.RECOVERY
    value.coordinator_uart = runner.COORDINATOR_UART
    value.o10_profile = runner.O10_PROFILE
    value.legacy_control = False
    value.linux_recovery = None
    value.o10_epoch = value.o10_sequence = value.o10_tag = 0
    value.control_sequence = 0
    value.o10_claimed = False
    value.o10_pending = None
    value.o10_plan9 = (1 << 32) | 1
    value.o10_lease_generation = 1
    value.ram = 12
    value.process = Mock()
    value.process.poll.return_value = None
    value.qmp = Mock()
    value.qmp.execute.return_value = {"running": False}
    value.stopped = Mock()
    value.pump = Mock()
    return value


class O10RunnerTests(unittest.TestCase):
    def test_lifecycle_uses_claim_withdraw_restore_bind_and_new_handles(self):
        value = domain()
        requests = []
        def exchange(frame, *, bootstrap=None):
            request = o10.decode(frame)
            requests.append((request, bootstrap))
            kind = request["type"]
            response = {"type": "R" + kind[1:], "tag": request["tag"]}
            if kind == "Tversion":
                response.update(epoch=0, last_seq=0, version=o10.O10_VERSION, negotiated_msize=512)
            elif kind == "Tclaim":
                response.update(epoch=1, last_seq=1, journal_low=1)
            elif kind == "Twithdraw":
                response.update(dom=request["dom"], leases=1, sessions=1, fids=3)
            elif kind == "Trestore":
                response["dom"] = (2 << 32) | 1
            elif kind == "Tbind":
                response["session"] = (2 << 32) | 4
            return response
        value.o10_exchange = exchange
        value.native_control(1)
        value.native_control(2, b"!rc\n")
        self.assertEqual([item[0]["type"] for item in requests],
                         ["Tversion", "Tclaim", "Twithdraw", "Trestore", "Tbind"])
        self.assertEqual([item[0]["seq"] for item in requests[1:]], [1, 2, 3, 4])
        self.assertEqual(requests[1][0]["expected"], 0)
        self.assertEqual(requests[3][1], b"!rc\n")
        self.assertEqual(requests[4][0]["lease"], (2 << 32) | 4)
        self.assertEqual(requests[4][0]["transport"], 2 << 32)
        self.assertEqual(value.o10_plan9, (2 << 32) | 1)
        self.assertEqual(value.control_sequence, 0)  # fake transport did not send any mailbox ops
        self.assertEqual(value.o10_sequence, 4)

    def test_fault_revocation_refreshes_lease_without_replaying_restore_or_bootstrap(self):
        value = domain()
        value.o10_claimed = True
        value.o10_epoch = 1
        value.o10_sequence = 2
        value.o10_lease_generation = 2
        requests = []
        def exchange(frame, *, bootstrap=None):
            request = o10.decode(frame)
            requests.append((request, bootstrap))
            response = {"type": "R" + request["type"][1:], "tag": request["tag"]}
            if request["type"] == "Trestore":
                response["dom"] = (2 << 32) | 1
            elif request["type"] == "Tversion":
                response.update(epoch=1, last_seq=4, version=o10.O10_VERSION, negotiated_msize=512)
            elif request["lease"] >> 32 == 2:
                response.update(type="Rerror", code=o10.O10_ESTALE, detail=3)
            else:
                response["session"] = (2 << 32) | 4
            return response
        value.o10_exchange = exchange
        value.native_control(2, b"!rc\n")
        self.assertEqual([row[0]["type"] for row in requests],
                         ["Trestore", "Tbind", "Tversion", "Tbind"])
        self.assertEqual([row[0].get("seq") for row in requests], [3, 4, None, 5])
        self.assertEqual([row[1] for row in requests], [b"!rc\n", None, None, None])
        binds = [row[0] for row in requests if row[0]["type"] == "Tbind"]
        self.assertEqual([row["lease"] >> 32 for row in binds], [2, 3])
        self.assertEqual([row["transport"] for row in binds], [2 << 32, 2 << 32])
        self.assertEqual(value.o10_lease_generation, 3)

    def test_bind_refresh_only_accepts_valid_stale_generation(self):
        for code, detail in ((o10.O10_EDENIED, 3), (o10.O10_ESTALE, 0),
                             (o10.O10_ESTALE, 1), (o10.O10_ESTALE, 1 << 32)):
            with self.subTest(code=code, detail=detail):
                value = domain()
                value.o10_claimed = True
                value.o10_call = Mock(side_effect=[
                    {"dom": (2 << 32) | 1},
                    o10.O10Error(code, detail, "rejected"),
                ])
                with self.assertRaises(o10.O10Error):
                    value.native_control(2, b"!rc\n")
                self.assertEqual(value.o10_call.call_count, 2)
                self.assertEqual(value.o10_lease_generation, 1)

    def test_second_stale_bind_failure_propagates_without_another_retry(self):
        value = domain()
        value.o10_claimed = True
        value.o10_call = Mock(side_effect=[
            {"dom": (2 << 32) | 1},
            o10.O10Error(o10.O10_ESTALE, 2, "first stale"),
            o10.O10Error(o10.O10_ESTALE, 3, "second stale"),
        ])
        with self.assertRaisesRegex(o10.O10Error, "second stale"):
            value.native_control(2, b"!rc\n")
        self.assertEqual(value.o10_call.call_count, 3)
        self.assertEqual(value.o10_lease_generation, 2)

    def test_unknown_mutation_retains_exact_frame_and_blocks_new_mutation(self):
        value = domain()
        value.o10_claimed = True
        value.o10_epoch = 3
        value.o10_sequence = 9
        value.o10_exchange = Mock(side_effect=TimeoutError("unknown"))
        with self.assertRaises(TimeoutError):
            value.o10_call("Twithdraw", dom=value.o10_plan9, mode=0, deadline_ms=0)
        pending = value.o10_pending
        self.assertEqual(pending["seq"], 10)
        self.assertEqual(o10.decode(pending["frame"])["epoch"], 3)
        self.assertEqual(value.o10_sequence, 9)
        with self.assertRaisesRegex(RuntimeError, "unresolved"):
            value.o10_call("Twithdraw", dom=value.o10_plan9, mode=0, deadline_ms=0)
        self.assertEqual(value.o10_exchange.call_count, 1)
        self.assertIs(value.o10_pending, pending)

    def test_error_observes_consumed_sequence_without_replay(self):
        for consumed in (False, True):
            with self.subTest(consumed=consumed):
                value = domain()
                requests = []
                def exchange(frame, **kwargs):
                    request = o10.decode(frame)
                    requests.append(request["type"])
                    if request["type"] == "Tversion":
                        return {"type": "Rversion", "tag": request["tag"], "negotiated_msize": 512,
                                "version": o10.O10_VERSION, "epoch": 0, "last_seq": int(consumed)}
                    return {"type": "Rerror", "tag": request["tag"], "code": o10.O10_ESTATE, "detail": 5}
                value.o10_exchange = exchange
                with self.assertRaises(o10.O10Error):
                    value.o10_call("Twithdraw", dom=value.o10_plan9, mode=0, deadline_ms=0)
                self.assertEqual(requests, ["Twithdraw", "Tversion"])
                self.assertEqual(value.o10_sequence, int(consumed))
                self.assertIsNone(value.o10_pending)

    def test_transport_writes_op10_and_reads_completion_after_ack(self):
        value = domain()
        writes = []
        value.write_native = lambda address, data: writes.append((address, data))
        frame = o10.encode("Tversion", 17, negotiated_msize=512, version=o10.O10_VERSION)
        reply = o10.encode("Rversion", 17, negotiated_msize=512, version=o10.O10_VERSION, epoch=0, last_seq=0)
        def pread(fd, count, offset):
            if offset == 0x6d000080 - 0x40000000:
                return struct.pack("<QQ", value.control_sequence, 1)
            self.assertEqual(offset, runner.O10_PROFILE["completion"] - 0x40000000)
            return reply[:count]
        with patch.object(runner.os, "pread", side_effect=pread):
            result = value.o10_exchange(frame)
        self.assertEqual(result["type"], "Rversion")
        self.assertEqual(writes, [(runner.O10_PROFILE["submission"], frame),
                                  (0x6d000070, struct.pack("<QQ", 1, 10))])
        self.assertEqual(value.stopped.call_count, 2)

    def test_transport_rejects_wrong_tag_and_never_writes_completion(self):
        value = domain()
        value.write_native = Mock()
        frame = o10.encode("Tversion", 17, negotiated_msize=512, version=o10.O10_VERSION)
        reply = o10.encode("Rversion", 18, negotiated_msize=512, version=o10.O10_VERSION, epoch=0, last_seq=0)
        def pread(fd, count, offset):
            return struct.pack("<QQ", value.control_sequence, 1) if offset == 0x2d000080 else reply[:count]
        with patch.object(runner.os, "pread", side_effect=pread), self.assertRaisesRegex(RuntimeError, "tag"):
            value.o10_exchange(frame)
        self.assertNotIn(runner.O10_PROFILE["completion"], [call.args[0] for call in value.write_native.call_args_list])

    def test_write_allowlist_protects_reply_slot_and_guest_ram(self):
        value = domain()
        start = runner.O10_PROFILE["submission"]
        with patch.object(runner.os, "pwrite", side_effect=lambda fd, data, offset: len(data)):
            value.write_native(start, bytes(512))
            for address, data in ((start - 1, b"x"), (start + 511, b"xx"),
                                  (runner.O10_PROFILE["completion"], b"x"), (0xb0000000, b"x")):
                with self.assertRaises(ValueError):
                    value.write_native(address, data)
        value.o10_profile = None
        with self.assertRaises(ValueError):
            value.write_native(start, b"x")

    def test_legacy_manifest_or_explicit_rollback_uses_original_operation(self):
        for rollback in (False, True):
            value = domain()
            value.o10_profile = runner.O10_PROFILE if rollback else None
            value.legacy_control = rollback
            value.write_native = Mock()
            value.o10_exchange = Mock(side_effect=AssertionError("O10 must not run"))
            with patch.object(runner.os, "pread", return_value=struct.pack("<QQ", 1, 1)):
                value.native_control(1)
            value.write_native.assert_called_once_with(0x6d000070, struct.pack("<QQ", 1, 1))

    def test_frozen_runtime_file_closure_imports_in_isolated_python(self):
        freezer_spec = importlib.util.spec_from_file_location(
            "o10_runtime_freezer", ROOT / "scripts/freeze_okernel_unified_runtime.py")
        freezer = importlib.util.module_from_spec(freezer_spec)
        freezer_spec.loader.exec_module(freezer)
        with tempfile.TemporaryDirectory(prefix="o10 frozen runtime ") as temporary:
            frozen = Path(temporary) / "runtime"
            for name in freezer.RUNTIME_FILES:
                destination = frozen / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            copied_runner = frozen / "scripts/okernel_unified_world.py"
            check = ("import pathlib,runpy,sys; "
                     "m=runpy.run_path(sys.argv[1],run_name='frozen_import'); "
                     "assert pathlib.Path(m['o10'].__file__).resolve() == "
                     "pathlib.Path(sys.argv[1]).parent / 'o10.py'; "
                     "print('FROZEN_O10_IMPORT_PASS')")
            argv = [sys.executable, "-I", "-B", "-c", check, str(copied_runner)]
            result = subprocess.run(argv, cwd=temporary, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "FROZEN_O10_IMPORT_PASS")
            # Prove the isolated process cannot satisfy a missing captured
            # codec using the checkout, PYTHONPATH, or an earlier module import.
            codec_path = frozen / "scripts/o10.py"
            codec_path.rename(codec_path.with_suffix(".missing"))
            missing = subprocess.run(argv, cwd=temporary, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("No module named 'o10'", missing.stderr)

    def provider_domain(self, live):
        value = domain()
        value.native_store_ready = value.provider_ready = True
        value.provider_failed = value.control_active = False
        value.live = True
        value.service = {"generation": "a" * 16, "instance": "b" * 32}
        value.counters = Mock(return_value={"live_domains": live})
        value.native_control = Mock()
        value.recycle_plan9 = Mock()
        value.native_volume = Mock()
        value.native_volume.return_value.get.side_effect = [
            runner.protocol.ready_marker(**value.service), FileNotFoundError("no reset request")]
        value.selector = Mock()
        value.selector.select.return_value = []
        value.qmp = None
        value.capture = value.plan9_capture = b""
        value.guest_coordinator_online = False
        value.last_provider_poll = value.last_coordinator_poll = 0
        value.record = {}
        value.session = Path("/unused-provider-test")
        return value

    def test_watch_provider_preserves_plan9_when_only_linux_faulted(self):
        for live in (2, 3):
            with self.subTest(live=live):
                value = self.provider_domain(live)
                value.watch_provider()
                self.assertTrue(value.provider_ready)
                value.native_control.assert_not_called()
                value.recycle_plan9.assert_not_called()

    def test_pump_does_not_withdraw_plan9_after_linux_fault(self):
        value = self.provider_domain(2)
        with patch.object(runner.os, "write") as output:
            runner.UnifiedDomain.pump(value, 0)
        self.assertTrue(value.provider_ready)
        self.assertFalse(value.provider_failed)
        value.native_control.assert_not_called()
        value.recycle_plan9.assert_not_called()
        output.assert_not_called()

    def test_plan9_failure_reports_linux_survival_from_actual_live_mask(self):
        for live in (0, 1):
            with self.subTest(live=live):
                value = self.provider_domain(live)
                with patch.object(runner.os, "write") as output, patch.object(runner.common, "write_json"):
                    runner.UnifiedDomain.pump(value, 0)
                self.assertTrue(value.provider_failed)
                self.assertFalse(value.provider_ready)
                value.native_control.assert_called_once_with(1)
                value.recycle_plan9.assert_not_called()
                value.native_volume.assert_not_called()
                self.assertEqual(value.record["provider_failure"]["counters"]["live_domains"], live)
                text = output.call_args.args[1].decode()
                self.assertIn("pending work is not replayed", text)
                self.assertIn("Linux remains available." if live else "Linux is stopped.", text)
                if not live:
                    self.assertNotIn("Linux remains available.", text)

    def test_coordinator_remains_service_operation_three(self):
        value = domain()
        value.o10_exchange = Mock(side_effect=AssertionError("O10 must not carry service payload"))
        value.write_native = Mock()
        with patch.object(runner.os, "pread", return_value=struct.pack("<QQ", 1, 1)):
            value.native_control(3, payload=b"service\n")
        self.assertEqual(value.control_sequence, 1)
        self.assertEqual(value.o10_sequence, 0)
        self.assertEqual(value.write_native.call_args_list[-1].args,
                         (0x6d000070, struct.pack("<QQ", 1, 3)))


if __name__ == "__main__":
    unittest.main()
