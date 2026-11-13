"""Host Governor Linux recovery never replays unknown service work."""
import importlib.util
from pathlib import Path
import tempfile
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("linux_runner_test",ROOT/"scripts/okernel_unified_world.py")
runner=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(runner)
o10=runner.o10


class LinuxRunnerTests(unittest.TestCase):
    def domain(self):
        d=object.__new__(runner.UnifiedDomain)
        d.linux_recovery=runner.LINUX_RECOVERY;d.legacy_control=False
        d.o10_linux=1<<32;d.o10_linux_lease_generation=1
        d.o10_claim=Mock();return d

    def test_linux_restore_refreshes_only_definite_stale_bind_once(self):
        d=self.domain();calls=[]
        def request(kind,**fields):
            calls.append((kind,fields))
            if kind=="Trestore":return {"dom":2<<32}
            if kind=="Tbind" and len(calls)==2:raise o10.O10Error(5,2,"definite journaled stale lease")
            return {"session":(2<<32)|1}
        d.o10_call=Mock(side_effect=request)
        d.linux_control(2)
        self.assertEqual([k for k,_ in calls],["Trestore","Tbind","Tbind"])
        self.assertEqual(calls[0][1]["img_kernel"],3);self.assertEqual(calls[0][1]["img_aux"],4)
        self.assertNotIn("bootstrap",calls[0][1])
        self.assertEqual(calls[1][1]["lease"],(1<<32)|1)
        self.assertEqual(calls[2][1]["lease"],(2<<32)|1)
        self.assertEqual(d.o10_linux,2<<32)

    def test_unknown_restore_or_second_bind_error_is_never_replayed(self):
        for failures in [[TimeoutError("unknown outcome")],
                         [{"dom":2<<32},o10.O10Error(5,2,"stale"),o10.O10Error(5,3,"second stale")],
                         [{"dom":2<<32},o10.O10Error(5,1,"stale lower hint")]]:
            with self.subTest(failures=len(failures)):
                d=self.domain();d.o10_call=Mock(side_effect=failures)
                with self.assertRaises((TimeoutError,o10.O10Error)):d.linux_control(2)
                self.assertEqual(d.o10_call.call_count,len(failures))
                self.assertEqual(d.o10_call.call_args_list[0].args[0],"Trestore")

    def test_linux_policy_resets_only_linux_parsers_and_preserves_plan9_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            d=self.domain();d.session=Path(directory);d.clock=123456
            d.control_active=False;d.service={"generation":"a"*16,"instance":"b"*32}
            d.record={};d.coordinator_events=[{"event":"unknown","request_id":"c"*32}]
            d.coordinator_capture=bytearray(b"old message");d.coordinator_position=99
            d.capture=bytearray(b"old Linux command; APK add outcome unknown")
            d.console_exit_request={"old":True};d.guest_coordinator_online=True
            d.linux_status=Mock(side_effect=[{"state":4,"dom":1<<32},{"state":2,"dom":2<<32}])
            d.linux_control=Mock();d.wait=Mock();d.command=Mock();d.setup_linux_client=Mock()
            d.recover_linux()
            d.linux_control.assert_called_once_with(2)
            self.assertEqual(d.service,{"generation":"a"*16,"instance":"b"*32})
            self.assertEqual(d.coordinator_position,0);self.assertFalse(d.coordinator_events)
            self.assertFalse(d.coordinator_capture);self.assertFalse(d.capture)
            entry=d.record["linux_recoveries"][0]
            self.assertTrue(entry["ok"]);self.assertEqual(len(entry["unknown_coordinator_events"]),1)
            text=" ".join(call.args[0] for call in d.command.call_args_list)
            self.assertNotIn("apk",text.lower());self.assertNotIn("old Linux command",text)
            self.assertFalse(d.control_active)

    def test_recovery_rejects_nonfaulted_domain_without_lifecycle_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            d=self.domain();d.session=Path(directory);d.control_active=False;d.service=None;d.record={}
            d.coordinator_events=[];d.linux_status=Mock(return_value={"state":2})
            d.linux_control=Mock()
            with self.assertRaisesRegex(RuntimeError,"definite native fault"):d.recover_linux()
            d.linux_control.assert_not_called();self.assertFalse(d.control_active)

    def test_plan9_watcher_accepts_linux_dead_and_only_refuses_plan9_dead(self):
        d=self.domain();d.native_store_ready=True;d.provider_ready=True
        d.service={"generation":"a"*16,"instance":"b"*32}
        marker=runner.protocol.ready_marker(**d.service)
        def get(path):
            if path.endswith("/ready"):return marker
            raise FileNotFoundError(path)
        d.native_volume=Mock(return_value=SimpleNamespace(get=get));d.counters=Mock(return_value={"live_domains":2})
        d.watch_provider();self.assertTrue(d.provider_ready)
        d.counters.return_value={"live_domains":1}
        with self.assertRaisesRegex(RuntimeError,"Plan9"):d.watch_provider()

    def test_stale_domain_observation_refreshes_only_readonly_handle(self):
        d=self.domain();d.o10_call=Mock(side_effect=[o10.O10Error(5,2,"new generation"),{"state":2,"dom":2<<32}])
        self.assertEqual(d.linux_status()["dom"],2<<32)
        self.assertEqual([c.args[0] for c in d.o10_call.call_args_list],["Tstat","Tstat"])
        self.assertEqual(d.o10_call.call_args_list[1].kwargs["dom"],2<<32)


    def test_delayed_status_ack_pumps_fault_banner_without_nested_exchange(self):
        d=self.domain()
        d.o10_profile=runner.O10_PROFILE;d.control_sequence=0;d.ram=7
        d.stopped=Mock();d.write_native=Mock();d.qmp=Mock();d.process=Mock()
        d.process.poll.return_value=None
        d.selector=Mock();d.selector.select.return_value=[]
        d.last_console_poll=float("inf");d.live=False;d.control_active=False
        d.capture=bytearray(b"KW unified domain failure: Linux fault\n")
        d.plan9_capture=bytearray();d.native_store_ready=True;d.provider_failed=False
        d.last_linux_poll=0;d.last_provider_poll=0;d.last_coordinator_poll=0
        d.guest_coordinator_online=True;d.service={"generation":"a"*16,"instance":"b"*32}
        d.linux_status=Mock(side_effect=AssertionError("nested status query"))
        d.watch_provider=Mock(side_effect=AssertionError("nested provider watch"))
        d.watch_guest_coordinator=Mock(side_effect=AssertionError("nested coordinator watch"))
        d.recover_linux=Mock(side_effect=AssertionError("nested lifecycle operation"))
        frame=o10.encode("Tstat",17,epoch=1,seq=0,dom=1<<32)
        reply=o10.encode("Rerror",17,code=o10.O10_ESTALE,detail=1)
        missing_ack=True
        def pread(fd,count,offset):
            nonlocal missing_ack
            self.assertEqual(fd,7)
            if offset==0x6d000080-0x40000000:
                if missing_ack:
                    missing_ack=False
                    return struct.pack("<QQ",0,0)
                return struct.pack("<QQ",1,1)
            self.assertEqual(offset,runner.O10_PROFILE["completion"]-0x40000000)
            return reply[:count]
        with patch.object(runner.os,"pread",side_effect=pread):
            result=d.o10_exchange(frame)
        self.assertEqual(result["type"],"Rerror")
        self.assertEqual(d.control_sequence,1)
        self.assertEqual([call.args[0] for call in d.write_native.call_args_list],
                         [runner.O10_PROFILE["submission"],0x6d000070])
        self.assertEqual(d.selector.select.call_count,1)
        d.linux_status.assert_not_called();d.recover_linux.assert_not_called()
        d.watch_provider.assert_not_called();d.watch_guest_coordinator.assert_not_called()
        self.assertFalse(d.o10_exchange_active);self.assertFalse(d.control_active)

    def test_nested_exchange_is_rejected_without_releasing_outer_guard(self):
        d=self.domain();d.o10_exchange_active=True;d.control_sequence=12
        d._o10_exchange_once=Mock()
        with self.assertRaisesRegex(RuntimeError,"another O10 mailbox exchange"):
            d.o10_exchange(b"not dispatched")
        self.assertTrue(d.o10_exchange_active)
        self.assertEqual(d.control_sequence,12)
        d._o10_exchange_once.assert_not_called()

    def test_exchange_failure_releases_guard_and_preserves_unknown_mutation(self):
        d=self.domain();d.o10_pending=None;d.o10_tag=0;d.o10_sequence=7;d.o10_epoch=1
        d._o10_exchange_once=Mock(side_effect=TimeoutError("unknown outcome"))
        with self.assertRaisesRegex(TimeoutError,"unknown outcome"):
            d.o10_call("Twithdraw",dom=d.o10_linux,mode=0,deadline_ms=0)
        self.assertFalse(d.o10_exchange_active)
        pending=d.o10_pending
        self.assertEqual(o10.decode(pending["frame"])["seq"],8)
        self.assertEqual(d.o10_sequence,7)
        with self.assertRaisesRegex(RuntimeError,"unresolved"):
            d.o10_call("Twithdraw",dom=d.o10_linux,mode=0,deadline_ms=0)
        self.assertIs(d.o10_pending,pending)
        self.assertEqual(d._o10_exchange_once.call_count,1)

    def test_exchange_guard_is_released_for_validation_and_io_errors(self):
        for error in (ValueError("invalid frame"),OSError("transport failure")):
            with self.subTest(error=type(error).__name__):
                d=self.domain();d._o10_exchange_once=Mock(side_effect=error)
                with self.assertRaises(type(error)):d.o10_exchange(b"not dispatched")
                self.assertFalse(d.o10_exchange_active)

if __name__=="__main__":
    unittest.main()
