"""Fixed qualification witness decoder/mailbox and admission guards."""
from pathlib import Path
import copy
import runpy
import struct
import types
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
R=runpy.run_path(str(ROOT/"scripts/okernel_unified_world.py"))
def fixture(action="capture",sequence=7):
    b=bytearray(128+2*576)
    b[:8]=b"O10WIT1\0";struct.pack_into("<II7Q3I",b,8,1,0,0,1 if action=="capture" else 2,sequence,3,1,4,1,1,1,2)
    for i in range(2):
        at=128+i*576
        struct.pack_into("<IIQQII",b,at,i,10+i,1,0,11,7)
        struct.pack_into("<IBHI",b,at+32,11,124,i+1,10+i)
        struct.pack_into("<IBH",b,at+48,7,125,i+1)
    return bytes(b)
class LinuxWitnessTests(unittest.TestCase):
    def test_fixed_list_contract_and_raw_bytes(self):
        value=R["decode_linux_restart_witness"](fixture(),"capture",7)
        self.assertEqual(value["capture_scope"],"all-transport-owned-fids")
        self.assertEqual(value["linux"]["fids"],[{"fid":10,"object_generation":1,"mode":0}])
        self.assertEqual(bytes.fromhex(value["plan9"]["exchanges"][0]["request_hex"])[4],124)
        self.assertEqual(value["plan9"]["transport_generation"],1)
    def test_rejects_misbound_malformed_partial_and_nonzero_padding(self):
        for offset,value in [(0,0),(8,2),(24,2),(32,6),(72,0),(80,513),(84,1),(128,1),(128+24,10),(128+28,0),(128+32+4,125),(128+560,1)]:
            with self.subTest(offset=offset):
                b=bytearray(fixture());b[offset]=value&255
                if offset==80:struct.pack_into("<I",b,80,value)
                with self.assertRaises(ValueError):R["decode_linux_restart_witness"](bytes(b),"capture",7)
        for b in [fixture()[:-1],fixture()+b"\0"]:
            with self.assertRaises(ValueError):R["decode_linux_restart_witness"](b,"capture",7)
    def test_production_errors_never_decode_stale_authority(self):
        b=bytearray(fixture());struct.pack_into("<I",b,12,9)
        with self.assertRaisesRegex(RuntimeError,"error 9"):R["decode_linux_restart_witness"](bytes(b),"capture",7)
    def domain(self):
        d=R["UnifiedDomain"].__new__(R["UnifiedDomain"])
        d.linux_restart_witness_profile=dict(R["LINUX_WITNESS"])
        d.control_sequence=6;d.o10_exchange_active=False;d.linux_restart_witness_pending=None
        d.process=types.SimpleNamespace(poll=lambda:None)
        d.qmp=types.SimpleNamespace(execute=mock.Mock())
        d.stopped=mock.Mock();d.write_native=mock.Mock();d.pump=mock.Mock()
        d.ram=123
        return d
    def test_one_observation_uses_only_fixed_action_and_mailbox(self):
        d=self.domain();data=fixture()
        def pread(fd,n,offset):
            self.assertEqual(fd,123)
            if offset==0x6d000080-0x40000000:return struct.pack("<QQ",7,1)
            self.assertEqual(offset,0x6d0b0000-0x40000000)
            return data[:n]
        with mock.patch.object(R["os"],"pread",side_effect=pread):
            result=d.linux_restart_witness("capture")
        self.assertEqual(result["sequence"],7)
        self.assertEqual(d.write_native.call_args_list,[mock.call(0x6d000118,struct.pack("<Q",1)),mock.call(0x6d000070,struct.pack("<QQ",7,11))])
        self.assertIsNone(d.linux_restart_witness_pending);self.assertFalse(d.o10_exchange_active)
    def test_timeout_does_not_resubmit_and_retains_unknown_observation(self):
        d=self.domain()
        with mock.patch.object(R["os"],"pread",return_value=struct.pack("<QQ",0,0)),mock.patch.object(R["time"],"monotonic",side_effect=[0,.1,61]):
            with self.assertRaises(TimeoutError):d.linux_restart_witness("check")
        self.assertEqual(d.write_native.call_count,2);self.assertEqual(d.linux_restart_witness_pending,7);self.assertFalse(d.o10_exchange_active)
        with self.assertRaisesRegex(RuntimeError,"unresolved"):d.linux_restart_witness("check")
        self.assertEqual(d.write_native.call_count,2)
    def test_unsupported_invalid_and_nested_fail_before_writes(self):
        d=self.domain()
        for action in ["token",{"grant":1},None]:
            with self.assertRaises(ValueError):d.linux_restart_witness(action)
        d.linux_restart_witness_profile=None
        with self.assertRaisesRegex(RuntimeError,"unsupported"):d.linux_restart_witness("capture")
        d.linux_restart_witness_profile=R["LINUX_WITNESS"];d.o10_exchange_active=True
        with self.assertRaisesRegex(RuntimeError,"unresolved"):d.linux_restart_witness("capture")
        d.write_native.assert_not_called()
    def test_native_observer_pages_are_outside_all_guest_private_ram(self):
        p=R["LINUX_WITNESS"];start,end=p["address"],p["address"]+p["bytes"]
        self.assertEqual((start,end),(0x6d0b0000,0x6d100000))
        self.assertLessEqual(128+512*576,p["bytes"])
        for guest,limit in [(0x48000000,0x68000000),(0xb0000000,0xd0000000)]:
            self.assertTrue(end<=guest or start>=limit)
        self.assertEqual(p,runpy.run_path(str(ROOT/"scripts/build_okernel_unified_world.py"))["LINUX_WITNESS"])
if __name__=="__main__":unittest.main()
