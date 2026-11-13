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
            config_path=root/"config.json";config_path.write_text(json.dumps(cfg))
            target.write_bytes(prefix+tail)
            argv=[__import__("sys").executable,str(helper),"recovered-file",str(config_path)]
            result=subprocess.run(argv,capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            observed=json.loads(base64.b64decode(result.stdout.split()[1]))
            self.assertEqual(observed["unknown_tail_bytes"],len(tail))
            self.assertEqual(observed["unknown_tail_sha256"],hashlib.sha256(tail).hexdigest())
            target.write_bytes(bytes(1048576)+tail)
            result=subprocess.run(argv,capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0)

    def test_large_configuration_roundtrips_through_bounded_console_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);helper=root/"helper.py";target=root/"interrupted-file"
            prefix=bytes([1])*1048576;tail=b"unknown tail"
            target.write_bytes(prefix+tail)
            config=dict(run=str(root/"run"),fixture={"declared_metadata":"x"*32768},
                        file=str(target),durable_prefix=dict(bytes=len(prefix),sha256=hashlib.sha256(prefix).hexdigest()))
            commands=[];capture=bytearray()
            def execute(command):
                commands.append(command)
                result=subprocess.run(["/bin/sh","-c",command],capture_output=True,timeout=5)
                capture.extend(result.stdout)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            domain=SimpleNamespace(command=execute,capture=capture)
            gate.upload_binary(domain,str(helper),gate.GUEST_HELPER.encode())
            record=gate.upload_guest_config(domain,config,root/"initial-source.json")
            self.assertEqual(Path(record["path"]).read_bytes(),Path(record["source"]["path"]).read_bytes())
            self.assertEqual(record["sha256"],record["source"]["sha256"])
            self.assertEqual(record["bytes"],record["source"]["bytes"])
            result=gate.guest_json(domain,str(helper),record["path"],"recovered-file")
            self.assertEqual(result["durable_prefix_sha256"],config["durable_prefix"]["sha256"])
            self.assertEqual(result["unknown_tail_bytes"],len(tail))
            config["durable_prefix"]["observation"]="after restart"
            restored=gate.upload_guest_config(domain,config,root/"restored-source.json")
            self.assertEqual(restored["path"],record["path"])
            self.assertNotEqual(restored["sha256"],record["sha256"])
            self.assertEqual(json.loads(Path(restored["path"]).read_text()),config)
            self.assertLess(max(map(len,commands)),900)
            self.assertTrue(any("recovered-file "+record["path"] in c for c in commands))

    def test_real_worker_passes_config_path_to_writer_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);run=root/"run";run.mkdir();helper=root/"helper.py"
            helper.write_text(gate.GUEST_HELPER)
            config=dict(run=str(run),nonce="component-config-path",fixture=dict(keys_directory="/opt/fixture/keys",
                        apks=[dict(path="/opt/fixture/pkg.apk")],large_metadata="z"*32768),
                        file=str(root/"file"))
            config_path=root/"config.json";config_path.write_text(json.dumps(config))
            calls=[]
            def popen(argv,**kwargs):
                calls.append(argv)
                for name in ("stdout","stderr"):kwargs[name].close()
                return SimpleNamespace(pid=__import__("os").getpid(),poll=lambda:0)
            namespace={"__name__":"__main__","__file__":str(helper)}
            with patch.object(__import__("sys"),"argv",[str(helper),"worker",str(config_path)]),patch.object(subprocess,"Popen",side_effect=popen):
                exec(compile(gate.GUEST_HELPER,str(helper),"exec"),namespace)
            self.assertEqual(len(calls),2)
            self.assertEqual(calls[0],[__import__("sys").executable,str(helper),"writer",str(config_path)])
            self.assertEqual(calls[1],["apk","--no-network","--repositories-file","/dev/null","--keys-dir","/opt/fixture/keys","add","/opt/fixture/pkg.apk"])
            self.assertLess(max(len(argument) for argument in calls[0]),900)
            domain=SimpleNamespace(command=Mock())
            gate.launch_worker(domain,str(helper),str(config_path),str(run))
            domain.command.assert_called_once()
            command=domain.command.call_args.args[0]
            self.assertIn(" worker "+str(config_path),command)
            self.assertLess(len(command),900)

    def test_grouped_worker_parses_with_actual_runner_completion_suffix(self):
        runner,_,_=gate.load_runtime()
        launch=SimpleNamespace(command=Mock())
        gate.launch_worker(launch,"/run/o10-worker.py","/run/o10-config.json","/run/o10-work")
        command=launch.command.call_args.args[0]
        def rendered(candidate):
            capture=bytearray();sent=[]
            def send(data):
                sent.append(data)
                token=__import__("re").search(rb"UNIFIED_COMMAND_[0-9a-f]+",data).group()
                capture.extend(bytes([10])+token+b":0"+bytes([10]))
            carrier=SimpleNamespace(send=send,capture=capture,timeout=1,process=SimpleNamespace(poll=lambda:None),
                                    session=Path("/component-only-no-VM"))
            runner.UnifiedDomain.command(carrier,candidate)
            self.assertEqual(len(sent),1)
            prefix=bytes([30,48,30,48,21])
            self.assertTrue(sent[0].startswith(prefix))
            return sent[0][len(prefix):]
        shell=rendered(command)
        self.assertIn(b"& }; _uw_rc=$?",shell)
        result=subprocess.run(["/bin/sh","-n"],input=shell,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        # The old form reproduces the actual '& ;' parser failure under the
        # exact same runner framing; neither syntax check executes a worker.
        legacy=command.removeprefix("{ ").removesuffix(" }")
        old_shell=rendered(legacy)
        self.assertIn(b"&; _uw_rc=$?",old_shell)
        rejected=subprocess.run(["/bin/sh","-n"],input=old_shell,capture_output=True,timeout=5)
        self.assertNotEqual(rejected.returncode,0)
        self.assertIn(b"Syntax error",rejected.stderr)


    def test_executable_alias_binds_regular_target_without_relaxing_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/"e2fsck";alias=root/"fsck.ext4"
            binary.write_bytes(b"unit tool-identity bytes");binary.chmod(0o755);alias.symlink_to(binary.name)
            record=gate.tool_identity(alias)
            self.assertEqual(record["invoked_path"],str(alias))
            self.assertEqual(record["path"],str(binary.resolve()))
            self.assertEqual(record["sha256"],hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertEqual(record["bytes"],binary.stat().st_size)
            with self.assertRaises(gate.GateError):gate.identity(alias)
            replacement=root/"replacement";replacement.write_bytes(b"other tool bytes")
            alias.unlink();alias.symlink_to(replacement.name)
            self.assertNotEqual(gate.tool_identity(alias),record)

    def counter_publication_transport(self, directory, *, unknown_request_copy=False):
        root=Path(directory);(root/"run").mkdir();namespace=root/"namespace";namespace.mkdir()
        protocol=importlib.import_module("ocore.guest.plan9.unified.protocol")
        service=dict(generation="1"*16,instance="2"*32)
        (namespace/"services/plan9"/("g"+service["generation"])/("s"+service["instance"])).mkdir(parents=True)
        commands=[];capture=bytearray()
        def local(path):
            if path.startswith("/run/"):return root/"run"/path.removeprefix("/run/")
            if path.startswith("/n/okernel/"):return namespace/path.removeprefix("/n/okernel/")
            raise AssertionError("unexpected guest path")
        def execute(command,timeout=None):
            commands.append(command)
            # This transport models the actual .u failure: append is rejected
            # for namespace files, while ordinary writes remain supported.
            if ">>" in command and "/n/okernel/" in command:
                raise gate.GateError("namespace append rejected")
            if unknown_request_copy and command.startswith("cat /run/o10-m2-counter-") and ".request > " in command:
                raise TimeoutError("unknown namespace publication")
            translated=command.replace("/n/okernel/",str(namespace)+"/").replace("/run/",str(root/"run")+"/")
            result=subprocess.run(["/bin/sh","-c",translated],capture_output=True,timeout=5)
            capture.extend(result.stdout+result.stderr)
            if result.returncode:
                raise gate.GateError("component shell failure: "+(result.stdout+result.stderr).decode(errors="replace"))
        domain=SimpleNamespace(command=execute,capture=capture,o10_exchange=Mock(),service=service)
        return domain,protocol,local,commands

    def test_counter_publishes_once_on_transport_that_rejects_namespace_append(self):
        with tempfile.TemporaryDirectory() as directory:
            domain,protocol,local,commands=self.counter_publication_transport(directory)
            with self.assertRaisesRegex(gate.GateError,"namespace append rejected"):
                gate.upload_binary(domain,"/n/okernel/rejected",b"old chunk append")
            record={};gate.trace(domain,Path(directory),record)
            with patch.object(gate.secrets,"token_hex",return_value="3"*32):
                invocation=gate.publish_counter(domain,protocol,"/services/plan9/g1/s2/counter",record=record)
            self.assertEqual(invocation["phase"],"submitted")
            self.assertEqual(local(invocation["paths"]["request"]).read_bytes(),invocation["request"])
            self.assertEqual(local(invocation["paths"]["submit"]).read_bytes(),protocol.submit_marker(invocation["request"]))
            self.assertEqual(invocation["submit_marker"],protocol.submit_marker(invocation["request"]))
            self.assertFalse(local(invocation["paths"]["submit"]+".staged").exists())
            traced=[row["command"] for row in record["guest_commands"]]
            positions=[]
            for phase,row in zip(("request","submit"),invocation["publication"]):
                self.assertEqual(row["phase"],phase)
                self.assertEqual(local(row["staging"]["path"]).read_bytes(),
                                 invocation["request"] if phase=="request" else invocation["submit_marker"])
                self.assertEqual(traced.count(row["command"]),1)
                self.assertNotIn(">>",row["command"])
                self.assertIn("wc -c < ",row["command"]);self.assertIn("sha256sum ",row["command"])
                positions.append(traced.index(row["command"]))
            self.assertEqual(traced.count(invocation["submit_command"]),1)
            self.assertLess(positions[0],positions[1]);self.assertLess(positions[1],traced.index(invocation["submit_command"]))
            self.assertFalse(any(">>" in c and "/n/okernel/" in c for c in traced))
            self.assertTrue(all(row["completion"]=="observed" and row["returncode"]==0 for row in record["guest_commands"]))
            self.assertLess(max(map(len,traced)),900)

    def test_unknown_counter_publication_retains_bytes_phase_and_never_submits(self):
        with tempfile.TemporaryDirectory() as directory:
            domain,protocol,local,commands=self.counter_publication_transport(directory,unknown_request_copy=True)
            record={};gate.trace(domain,Path(directory),record)
            with patch.object(gate.secrets,"token_hex",return_value="3"*32),self.assertRaisesRegex(TimeoutError,"unknown namespace publication"):
                gate.publish_counter(domain,protocol,"/services/plan9/g1/s2/counter",record=record)
            invocation=record["plan9_counter_request"]
            self.assertEqual(protocol.decode_request(invocation["request"]).request_id,invocation["id"])
            self.assertEqual(invocation["submit_marker"],protocol.submit_marker(invocation["request"]))
            self.assertEqual(invocation["phase"],"request-publication-pending")
            self.assertEqual(len(invocation["publication"]),1)
            self.assertEqual(sum(c==invocation["publication"][0]["command"] for c in commands),1)
            self.assertFalse(any(c.startswith("mv ") for c in commands))
            self.assertNotIn("submit_command",invocation)
            self.assertEqual(record["guest_commands"][-1]["completion"],"unknown")
            self.assertIsNone(record["guest_commands"][-1]["returncode"])
            self.assertFalse(local(invocation["paths"]["submit"]).exists())

    def initial_state_result(self, linux_state, plan9_state):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);seed=root/"seed";seed.mkdir();build=root/"build";build.mkdir()
            (seed/"head.json").write_text("{}")
            (build/"monitor-profile.json").write_text("{}")
            fixture_path=root/"fixture.json";fixture_path.write_text(json.dumps(fixture()))
            fsck=root/"fsck.ext4";fsck.write_bytes(b"component tool identity")
            domain=SimpleNamespace(
                session=root/"session",record={"argv":["component-only-no-VM"]},service={},
                ready=Mock(),o10_claim=Mock(),close=Mock(),
                o10_call=Mock(side_effect=[dict(state=linux_state),dict(state=plan9_state)]))
            domain.o10_linux=1<<32;domain.o10_plan9=(1<<32)|1
            runner=SimpleNamespace(UnifiedDomain=Mock(return_value=domain),o10=object())
            fork=SimpleNamespace(fork=Mock(return_value={"ok":True,"source_head_changed_during_copy":False}))
            # Exercise the actual gate's readiness decision, then stop before any
            # guest work; these fixtures cannot qualify VM execution or progress.
            with patch.object(gate,"load_runtime",return_value=(runner,fork,None)), \
                 patch.object(gate,"preflight",return_value={"source_sha256":{}}), \
                 patch.object(gate.shutil,"which",return_value=str(fsck)), \
                 patch.object(gate.subprocess,"check_output",return_value="a"*40+"\n"), \
                 patch.object(gate,"trace"), \
                 patch.object(gate,"upload_binary",side_effect=gate.GateError("component helper-upload boundary")) as upload:
                result=gate.verify(seed=seed,build=build,fixture_path=fixture_path,output=root/"gate",mcp_release="a"*40)
            domain.close.assert_called_once()
            self.assertFalse(result["gate_passed"]);self.assertFalse(result["milestone_qualified"])
            return result,upload.call_count

    def test_running_or_blocked_original_domains_reach_guest_helper_boundary(self):
        for linux_state,plan9_state in ((2,2),(2,3),(3,2),(3,3)):
            with self.subTest(linux_state=linux_state,plan9_state=plan9_state):
                result,uploads=self.initial_state_result(linux_state,plan9_state)
                self.assertEqual(uploads,1)
                self.assertIn("component helper-upload boundary",result["error"])

    def test_nonlive_domain_never_starts_guest_helper(self):
        for state in (0,1,4,5,True,"3",None):
            for role in ("linux","plan9"):
                with self.subTest(role=role,state=state):
                    result,uploads=self.initial_state_result(state if role=="linux" else 3,state if role=="plan9" else 3)
                    self.assertEqual(uploads,0)
                    self.assertIn("two live original guests required",result["error"])

if __name__=="__main__":unittest.main()
