"""Component-only gate tests: fixtures never stand in for running guest evidence."""
import base64
import copy
import importlib.util
import json
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("linux_restart_gate_under_test",ROOT/"scripts/verify_o10_linux_restart.py")
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)

def frame(kind,body=b"",tag=17):
    return struct.pack("<IBH",7+len(body),kind,tag)+body

def stat(fid,stale=False):
    payload=struct.pack("<H",47)+bytes(47)
    body=struct.pack("<H",5)+b"stale"+struct.pack("<I",116) if stale else struct.pack("<H",len(payload))+payload
    return dict(fid=fid,request_hex=frame(124,struct.pack("<I",fid)).hex(),
                reply_hex=frame(107 if stale else 125,body).hex())

def witness(action="capture",sequence=1):
    return dict(schema="ostadix.o10-linux-store-witness/v1",origin="running-native-store",
                capture_scope="all-transport-owned-fids",action=action,sequence=sequence,
                linux=dict(grant=1,session=17,transport_generation=1,
                           fids=[dict(fid=7,object_generation=3,mode=0)],
                           exchanges=[stat(7,action=="check")]),
                plan9=dict(grant=4,session=18,transport_generation=1,
                           fids=[dict(fid=3,object_generation=2,mode=0)],exchanges=[stat(3)]))

def fixture():
    return dict(schema="ostadix.o10-linux-apk-fixture/v1",package="o10-fixture",version="1.0-r0",
                directory="/opt/o10-fixture",keys_directory="/opt/o10-fixture/keys",
                target_apk="/opt/o10-fixture/package.apk",commit_hook_template_sha256=gate.HOOK_SHA256,commit_hook_contract="apk3-pre-commit-v1",
                apk_version_stdout="apk-tools fixture version\n",
                apks=[dict(path="/opt/o10-fixture/package.apk",sha256="a"*64)],
                keys=[dict(path="/opt/o10-fixture/keys/test.rsa.pub",sha256="b"*64)])

def database(stdout=b"OK: 10 MiB in 7 packages\n",stderr=b"",rc=0):
    return dict(info=dict(argv=["apk","info","-vv"],returncode=0),
                check=dict(argv=gate.DB_ARGV,returncode=rc,
                           stdout_base64=base64.b64encode(stdout).decode(),
                           stderr_base64=base64.b64encode(stderr).decode()))

class LinuxRestartGateTests(unittest.TestCase):
    def test_fixture_declares_archive_keys_target_commit_hook_and_exact_version(self):
        self.assertEqual(gate.validate_fixture(fixture())["package"],"o10-fixture")
        for key,value in [("apks",[]),("keys",[]),("commit_hook_template_sha256","c"*64),
                          ("target_apk","/opt/else/package.apk"),("apk_version_stdout","")]:
            row=fixture();row[key]=value
            with self.subTest(key=key),self.assertRaises(gate.GateError):gate.validate_fixture(row)

    def test_fixture_rejects_traversal_duplicate_and_missing_hash(self):
        for transform in (lambda r:r["apks"][0].update(path="/opt/o10-fixture/../p.apk"),
                          lambda r:r["apks"].append(dict(r["apks"][0])),
                          lambda r:r["keys"][0].pop("sha256")):
            row=fixture();transform(row)
            with self.assertRaises(gate.GateError):gate.validate_fixture(row)

    def test_actual_wire_error_number_is_required_not_error_text(self):
        before=witness();after=witness("check",2)
        self.assertEqual(gate.validate_witness(after,"check",before)["linux"]["fids"][0]["fid"],7)
        after["linux"]["exchanges"][0]["reply_hex"]=frame(107,struct.pack("<H",9)+b"ESTALE116"+struct.pack("<I",1)).hex()
        with self.assertRaises(gate.GateError):gate.validate_witness(after,"check",before)

    def test_changed_plan9_tuple_or_linux_binding_is_rejected(self):
        for transform in (lambda r:r["plan9"]["fids"][0].update(object_generation=3),
                          lambda r:r["plan9"]["fids"][0].update(mode=2),
                          lambda r:r["plan9"].update(session=(7<<32)|4),
                          lambda r:r["linux"].update(session=(9<<32)|1),
                          lambda r:r["linux"].update(transport_generation=2)):
            after=witness("check",2);transform(after)
            with self.subTest(transform=transform),self.assertRaises(gate.GateError):
                gate.validate_witness(after,"check",witness())

    def test_model_origin_missing_wire_or_unfresh_witness_is_rejected(self):
        for transform in (lambda r:r.update(origin="host-register-model"),
                          lambda r:r.update(sequence=1),
                          lambda r:r["plan9"].update(exchanges=[]),
                          lambda r:r["linux"]["exchanges"][0].update(reply_hex=""),
                          lambda r:r["linux"]["exchanges"][0].update(reply_hex=frame(107,struct.pack("<H",0)+struct.pack("<I",116),tag=99).hex())):
            after=witness("check",2);transform(after)
            with self.assertRaises(gate.GateError):gate.validate_witness(after,"check",witness())

    def test_wire_rejects_trailing_bytes_and_wrong_fid(self):
        row=stat(3);row["request_hex"]+="00"
        with self.assertRaises(gate.GateError):gate.stat_exchange(row)
        row=stat(3);row["fid"]=4
        with self.assertRaises(gate.GateError):gate.stat_exchange(row)

    def test_apk_database_must_open_and_need_no_proposed_repair(self):
        gate.validate_database(database())
        for value in (database(rc=1),database(stdout=b"(1/2) Reinstalling fixture\nOK: 7 packages\n"),
                      database(stderr=b"WARNING: database issue\n"),database(stdout=b"not checked\n")):
            with self.assertRaises(gate.GateError):gate.validate_database(value)
        value=database();value["info"]["returncode"]=1
        with self.assertRaises(gate.GateError):gate.validate_database(value)

    def test_fsck_copy_requires_clean_ext4_after_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"disk.ext4"
            for state,feature,expected in [(1,0,True),(1,4,False),(2,0,False),(0,0,False),(3,0,False)]:
                data=bytearray(2048);struct.pack_into("<H",data,1080,0xef53)
                struct.pack_into("<H",data,1082,state);struct.pack_into("<I",data,1120,feature);p.write_bytes(data)
                if expected:self.assertFalse(gate.clean_superblock(p)["needs_recovery"])
                else:
                    with self.subTest(state=state,feature=feature),self.assertRaises(gate.GateError):
                        gate.clean_superblock(p)

    def test_counter_records_conservative_observation_gap_without_rewrites(self):
        counter=gate.Counter(None,"/services/plan9/test/counter")
        start=counter.start
        counter.observe(b"0\n",start+1)
        counter.observe(b"0\n1\n2\n",start+4)
        result=counter.result()
        self.assertEqual(result["largest_observed_gap_seconds"],3)
        self.assertGreaterEqual(result["largest_append_gap_upper_bound_seconds"],4)
        with self.assertRaises(gate.GateError):counter.observe(b"0\n",start+5)

    def test_command_unknown_outcome_is_not_retried_and_raw_output_retained(self):
        domain=SimpleNamespace(capture=bytearray(),command=Mock(),o10_exchange=Mock())
        def fail(*args,**kwargs):
            domain.capture.extend(b"partial guest output\n");raise TimeoutError("unknown")
        domain.command.side_effect=fail
        original=domain.command
        with tempfile.TemporaryDirectory() as directory:
            record={};gate.trace(domain,Path(directory),record)
            with self.assertRaises(TimeoutError):domain.command("apk add explicit-fixture")
            self.assertEqual(original.call_count,1)
            self.assertEqual(record["guest_commands"][0]["completion"],"unknown")
            self.assertIsNone(record["guest_commands"][0]["returncode"])
            self.assertEqual(Path(record["guest_commands"][0]["combined_console"]["path"]).read_bytes(),
                             b"partial guest output\n")

    def test_missing_real_witness_fails_preboot_and_writes_unqualified_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);seed=root/"seed";seed.mkdir();build=root/"build";build.mkdir()
            profile=dict(o10_qualification=True,linux_recovery=dict(namespace_version="9P2000.u"),
                         plan9_recovery=True,plan9_command_provider=True)
            (build/"monitor-profile.json").write_text(json.dumps(profile))
            f=root/"fixture.json";f.write_text(json.dumps(fixture()))
            domain=Mock();runner=SimpleNamespace(UnifiedDomain=domain)
            # Mock has arbitrary attributes: contract is also mandatory, so no
            # fixture/mock method can qualify missing native witness support.
            fork=SimpleNamespace(fork=Mock())
            with patch.object(gate,"load_runtime",return_value=(runner,fork,None)):
                result=gate.verify(seed=seed,build=build,fixture_path=f,output=root/"gate",mcp_release="a"*40)
            self.assertFalse(result["gate_passed"]);self.assertFalse(result["milestone_qualified"])
            self.assertIn("witness unavailable",result["error"])
            domain.assert_not_called();fork.fork.assert_not_called()
            self.assertEqual(result["skips"],[])

    def test_production_profile_never_forks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);seed=root/"seed";seed.mkdir();build=root/"build";build.mkdir()
            (build/"monitor-profile.json").write_text(json.dumps(dict(o10_qualification=False)))
            f=root/"fixture.json";f.write_text(json.dumps(fixture()))
            fork=SimpleNamespace(fork=Mock());runner=SimpleNamespace(UnifiedDomain=Mock())
            with patch.object(gate,"load_runtime",return_value=(runner,fork,None)):
                result=gate.verify(seed=seed,build=build,fixture_path=f,output=root/"gate",mcp_release="a"*40)
            self.assertIn("qualification build required",result["error"]);fork.fork.assert_not_called()

    def test_guest_helper_compiles_and_uses_no_work_replay_or_network_package_fetch(self):
        compile(gate.GUEST_HELPER,"guest-helper","exec")
        self.assertIn('["apk","--no-network","--keys-dir"',gate.GUEST_HELPER)
        self.assertIn('["mount","-o","remount,ro","/"]',gate.GUEST_HELPER)
        self.assertNotIn("devmem",gate.GUEST_HELPER)
        self.assertNotIn("tarfile",gate.GUEST_HELPER)
        self.assertIn('"verify"]+[r["path"]',gate.GUEST_HELPER)
        self.assertNotIn("apk update",gate.GUEST_HELPER)
        self.assertEqual(gate.GUEST_HELPER.count('elif mode=="worker"'),1)

    def test_plan9_same_fid_and_tuple_cannot_silently_change_wire_qid(self):
        after=witness("check",2)
        raw=bytearray.fromhex(after["plan9"]["exchanges"][0]["reply_hex"])
        raw[22]=1
        after["plan9"]["exchanges"][0]["reply_hex"]=raw.hex()
        with self.assertRaisesRegex(gate.GateError,"wire qid"):
            gate.validate_witness(after,"check",witness())

    def test_counter_accepts_only_prefix_of_next_complete_append(self):
        counter=gate.Counter(None,"/counter");start=counter.start
        counter.observe(b"0",start+.5)
        self.assertEqual(counter.entries,[])
        counter.observe(b"0\n1",start+1)
        self.assertEqual(len(counter.entries),1)
        with self.assertRaises(gate.GateError):counter.observe(b"0\n14",start+2)

    def test_mutation_unknown_outcome_retains_exact_frame_without_retry(self):
        original=Mock(side_effect=TimeoutError("unknown mechanism outcome"))
        domain=SimpleNamespace(capture=bytearray(),command=Mock(),o10_exchange=original)
        with tempfile.TemporaryDirectory() as directory:
            record={};gate.trace(domain,Path(directory),record)
            with self.assertRaises(TimeoutError):domain.o10_exchange(b"exact-request")
        original.assert_called_once_with(b"exact-request",bootstrap=None)
        self.assertEqual(record["o10_exchanges"][0]["request_hex"],b"exact-request".hex())
        self.assertEqual(record["o10_exchanges"][0]["completion"],"unknown")

    def test_all_linux_fids_must_receive_numeric_stale_errors(self):
        before=witness()
        before["linux"]["fids"].append(dict(fid=8,object_generation=4,mode=2))
        before["linux"]["exchanges"].append(stat(8))
        after=copy.deepcopy(before);after.update(action="check",sequence=2)
        after["linux"]["exchanges"]=[stat(7,True),stat(8,True)]
        gate.validate_witness(after,"check",before)
        after["linux"]["exchanges"][1]=stat(8,False)
        with self.assertRaises(gate.GateError):gate.validate_witness(after,"check",before)
        after=witness("check",2);after.pop("capture_scope")
        with self.assertRaises(gate.GateError):gate.validate_witness(after,"check",witness())

    def test_generated_held_fid_command_resolves_actual_shell_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"held"
            command=gate.hold_linux_fid_command(str(path))
            self.assertIn("/proc/$$/fd/9",command)
            result=subprocess.run(["/bin/sh","-c",command],capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertTrue(path.is_file())

    def test_chunked_upload_roundtrips_bytes_below_console_line_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/"helper"
            commands=[]
            def execute(command):
                commands.append(command)
                result=subprocess.run(["/bin/sh","-c",command],capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            payload=bytes(range(256))*64
            gate.upload_binary(SimpleNamespace(command=execute),str(target),payload)
            self.assertEqual(target.read_bytes(),payload)
            self.assertLess(max(map(len,commands)),900)

    def test_chunked_upload_unknown_outcome_does_not_repeat_a_chunk(self):
        domain=SimpleNamespace(command=Mock(side_effect=[None,TimeoutError("unknown")]))
        with self.assertRaises(TimeoutError):gate.upload_binary(domain,"/run/test-helper",b"x"*2048)
        self.assertEqual(domain.command.call_count,2)

    def test_rc_counter_outer_block_owns_single_append_redirection(self):
        command=gate.plan9_counter_command("/services/plan9/g1/s2/counter")
        self.assertTrue(command.startswith("{ for(i in 0 1 2 "))
        self.assertTrue(command.endswith(" } } >> /n/services/plan9/g1/s2/counter"))
        self.assertEqual(command.count(">>"),1)
        self.assertIn("sleep 1",command)

    def test_durable_prefix_uses_nonzero_first_chunk(self):
        expected=hashlib.sha256(bytes([1])*1048576).hexdigest()
        self.assertEqual(gate.durable_prefix_sha256(1048576),expected)
        for length in (0,1,1048577,gate.FILE_BYTES+1048576):
            with self.assertRaises(gate.GateError):gate.durable_prefix_sha256(length)

    def test_real_observation_helper_checks_only_fsynced_prefix_and_records_unknown_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);helper=root/"helper.py";helper.write_text(gate.GUEST_HELPER)
            target=root/"interrupted-file";prefix=bytes([1])*1048576;tail=b"unknown un-fsynced tail"
            cfg=dict(run=str(root/"run"),fixture={},file=str(target),
                     durable_prefix=dict(bytes=len(prefix),sha256=hashlib.sha256(prefix).hexdigest()))
            encoded=base64.b64encode(json.dumps(cfg).encode()).decode()
            target.write_bytes(prefix+tail)
            argv=[__import__("sys").executable,str(helper),"recovered-file",encoded]
            result=subprocess.run(argv,capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            observed=json.loads(base64.b64decode(result.stdout.split()[1]))
            self.assertEqual(observed["unknown_tail_bytes"],len(tail))
            self.assertEqual(observed["unknown_tail_sha256"],hashlib.sha256(tail).hexdigest())
            target.write_bytes(bytes(1048576)+tail)
            result=subprocess.run(argv,capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0)

if __name__=="__main__":unittest.main()
