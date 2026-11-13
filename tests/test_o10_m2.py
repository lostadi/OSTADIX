"""Negative controls for M2 receipt binding; fixtures execute no guests."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import struct
import shutil
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_o10_m2 as gate
from tests import test_o10_m1 as m1_fixture
from tests.test_o10_linux_restart import witness, fixture, database


class M2EvidenceTests(unittest.TestCase):
    def setUp(self):
        base = m1_fixture.M1EvidenceTests(methodName="runTest")
        base.setUp()
        self.addCleanup(base.doCleanups)
        self.base = base
        self.root, self.build, self.revision = base.root, base.build, base.revision
        self.write = base.write
        self.paths = {k: v for k, v in base.paths.items() if k != "hostile_mmio_result"}
        self.compiler = base.compiler
        self.outer = self.root / "restart"
        self.token = "a" * 24
        for name in gate.NEW_SOURCES | gate.RESTART_SOURCES:
            if not (self.root / name).exists():
                self.write(name, "fixture " + name)
        profile = gate.document(base.profile)
        profile.update(linux_recovery={"namespace_version": "9P2000.u"},
                       plan9_recovery=True, plan9_command_provider=True,
                       o10_linux_restart_witness=gate.restart.WITNESS_CONTRACT)
        base.profile.write_text(json.dumps(profile))
        for path in self.root.rglob("monitor-profile.json"):
            if path != base.profile:
                path.write_bytes(base.profile.read_bytes())
        self.profile = profile
        profile_sha = gate.digest(base.profile)

        shared_path = self.paths["guest_result"]
        shared = gate.document(shared_path)
        shared.update(acceptance_scope="draft0", contract_id="O10-Draft0-M1", profile_sha256=profile_sha,
                      resident_result=gate.identity(self.paths["resident_result"]))
        shared.pop("hostile_mmio_result", None)
        shared_path.write_text(json.dumps(shared))
        resident = gate.document(self.paths["resident_result"])
        resident["build"] = gate.identity(base.profile)
        self.paths["resident_result"].write_text(json.dumps(resident))
        shared["resident_result"] = gate.identity(self.paths["resident_result"])
        shared_path.write_text(json.dumps(shared))

        extra_names = gate.NEW_SOURCES | gate.RESTART_SOURCES
        component = gate.document(self.paths["component_result"])
        unit = gate.document(self.paths["unit_result"])
        for name in extra_names:
            sha = gate.digest(self.root / name)
            component["source_sha256"][name] = unit["source_sha256"][name] = sha
        log = self.paths["component_result"].parent / "tests.log"
        modules = sorted(p.stem for p in (self.root / "tests").glob("test_o10_*.py"))
        log.write_text("".join("test_fixture (" + name + ".Fixture.test_fixture) ... ok\n" for name in modules)
                       + "\nRan " + str(len(modules)) + " tests in 0.1s\n\nOK\n")
        component["tests_run"] = len(modules)
        self.paths["component_result"].write_text(json.dumps(component))
        unit["component"].update(gate.identity(self.paths["component_result"]))
        self.paths["unit_result"].write_text(json.dumps(unit))

        session = self.outer / "state/session"
        self.write("restart/state/session/monitor-profile.json", base.profile.read_text())
        self.write("restart/state/session/inputs/monitor.elf", (self.build / "monitor.elf").read_text())
        seed = self.write("restart-seed/head.json", {"fixture": "private seed"})
        fsck = self.write("bin/fsck.ext4", "filesystem checker fixture")
        snapshot = self.outer / "replayed-readonly.ext4"
        with snapshot.open("wb") as stream:
            stream.truncate(1024 ** 3)
            stream.seek(1024 + 56); stream.write(struct.pack("<H", 0xef53))
            stream.write(struct.pack("<H", 1))
        self.write("restart/fsck.stdout", "fixture.ext4: clean, 1/1024files, 10/1000blocks\n")
        self.write("restart/fsck.stderr", "")
        source_sha = {name: gate.digest(self.root / name) for name in set(profile["source_sha256"]) | gate.RESTART_SOURCES}
        captures = {}
        for name in source_sha:
            path = self.write("restart/sources/" + name, (self.root / name).read_text())
            captures[name] = gate.identity(path)
        f = fixture()
        fpath = self.write("fixture.json", f)
        prefix = {"bytes": 1048576, "sha256": gate.restart.durable_prefix_sha256(1048576)}
        config = {"run": "/run/o10-m2-" + self.token, "nonce": self.token,
                  "file": "/work/o10-m2-" + self.token + "/file64MiB", "fixture": f}
        hook = gate.restart.APK_COMMIT_HOOK_TEMPLATE.replace(b"@NONCE@", self.token.encode()).replace(
            b"@RUN@", config["run"].encode())
        config["commit_hook_base64"] = base64.b64encode(hook).decode()
        uploads = []
        for phase in ("initial", "restored"):
            value = dict(config)
            if phase == "restored":
                value["durable_prefix"] = prefix
            path = self.write("restart/guest-config-" + phase + ".json", json.dumps(value, sort_keys=True, separators=(",", ":")))
            uploads.append(dict(path=config["run"] + ".json", bytes=path.stat().st_size,
                                sha256=gate.digest(path), source={**gate.identity(path), "bytes": path.stat().st_size}))
        helper = self.write("restart/guest-helper.py", gate.restart.GUEST_HELPER)
        helper_uploads = [dict(path=config["run"] + ".py", bytes=helper.stat().st_size,
                             sha256=gate.digest(helper), source={**gate.identity(helper), "bytes": helper.stat().st_size},
                             phase=phase) for phase in ("initial", "restored")]
        verification = dict(argv=["apk", "--no-network", "--keys-dir", f["keys_directory"], "verify"] +
                                 [r["path"] for r in f["apks"]], returncode=0,
                            stdout_base64=base64.b64encode(b"package:OK\n").decode(), stderr_base64="")
        commands = []
        worker_command=("{ PYTHONDONTWRITEBYTECODE=1 python3 "+config["run"]+".py worker "+config["run"]+".json"+
                        " > "+config["run"]+"/worker.stdout 2> "+config["run"]+"/worker.stderr & }")
        for i, command in enumerate(("helper database config", "helper prepare config", worker_command)):
            output = self.write("restart/command-" + str(i) + ".console", "observed output\n")
            commands.append(dict(command=command, completion="observed", returncode=0,
                                 combined_console=gate.identity(output)))
        self.exchanges = []
        self.tag = 0
        def exchange(kind, answer, **fields):
            self.tag += 1
            req = gate.o10.encode(kind, tag=self.tag, epoch=1, seq=fields.pop("seq", 0), **fields)
            rep = gate.o10.encode(answer.pop("type"), tag=self.tag, **answer)
            row = dict(request_hex=req.hex(), reply_hex=rep.hex(), completion="observed",
                       reply=gate.restart.safe(gate.o10.decode(rep)))
            self.exchanges.append(row)
            return row["reply"]
        def stat(dom, inst):
            return dict(type="Rstat", dom=dom, kind=1, state=2, inst=inst, exits=1, switches=1,
                        esr=0, ipa=0, pc=0, leases=1)
        linux = 1 << 32
        plan9 = linux | 1
        exchange("Tstat", stat(linux, bytes(16)), dom=linux)
        old_plan9 = exchange("Tstat", stat(plan9, bytes(16)), dom=plan9)
        injection = exchange("Tinject", dict(type="Rinject", dom=linux), dom=linux, fault=1, seq=1)
        dead = stat(linux, bytes(16)); dead["state"] = 4; dead["leases"] = 0
        exchange("Tstat", dead, dom=linux)
        exchange("Trestore", dict(type="Rrestore", dom=2 << 32), dom=linux, inst=bytes([2]) * 16,
                 img_kernel=3, img_aux=4, seq=2)
        exchange("Tbind", dict(type="Rbind", session=(2 << 32) | 1), lease=(2 << 32) | 1,
                 transport=2 << 32, seq=3)
        new_linux = exchange("Tstat", stat(2 << 32, bytes([2]) * 16), dom=2 << 32)
        new_plan9 = exchange("Tstat", stat(plan9, bytes(16)), dom=plan9)
        from okernel_unified_world import protocol
        counter_path="/services/plan9/gbbbbbbbbbbbbbbbb/scccccccccccccccccccccccccccccccc/m2-counter-"+self.token
        counter_request=protocol.encode_request("b"*16,"c"*32,"d"*32,
            ["/arm64/bin/rc","-I","-c",gate.restart.plan9_counter_command(counter_path)],cwd="/n/work",timeout_ms=300000)
        service=dict(generation="b"*16,instance="c"*32)
        counter_paths=protocol.request_paths("/n/okernel/services/plan9","b"*16,"c"*32,"d"*32)
        marker=protocol.submit_marker(counter_request)
        publication=[]
        publication_commands=[]
        def observed(command):
            output=self.write("restart/counter-command-"+str(len(publication_commands))+".console","observed publication output\n")
            publication_commands.append(dict(command=command,completion="observed",returncode=0,
                                             combined_console=gate.identity(output)))
        class StagingDomain:
            command=staticmethod(observed)
        for phase,data,destination in (("request",counter_request,counter_paths["request"]),
                                       ("submit",marker,counter_paths["submit"]+".staged")):
            staging=gate.restart.upload_binary(StagingDomain(),"/run/o10-m2-counter-"+"d"*32+"."+phase,data)
            command=gate.restart.namespace_copy_command(staging["path"],destination,data)
            publication.append(dict(phase=phase,staging=staging,destination=destination,
                                    bytes=len(data),sha256=gate.hashlib.sha256(data).hexdigest(),command=command))
            observed(command)
        submit_command="mv "+counter_paths["submit"]+".staged "+counter_paths["submit"]
        observed(submit_command)
        commands[2:2]=publication_commands
        self.primary = dict(schema=gate.RESTART_SCHEMA, milestone="M2", gate_id="verify_o10_linux_restart",
            gate_passed=True, milestone_qualified=False, source_unchanged=True, source_revision=self.revision,
            mcp_release=self.revision, build=gate.identity(base.profile), source_sha256=source_sha,
            source_artifacts=captures, guest_session=str(session),
            qemu_argv=["qemu-system-aarch64", "-machine", "virt"],
            seed_head_before=gate.identity(seed),
            fork=dict(schema="ostadix.okernel-state-fork/v1", ok=True, source=str(seed.parent),
                      output=str(self.outer / "state"), source_head_changed_during_copy=False),
            witness_before=witness(), witness_faulted=witness("check", 2),
            witness_restored=witness("check", 3), witness_final=witness("check", 4),
            plan9_fid_lifetime_confound=gate.restart.FID_LIFETIME_NOTE,
            plan9_counter=dict(path="/services/plan9/gbbbbbbbbbbbbbbbb/scccccccccccccccccccccccccccccccc/m2-counter-" + self.token,
                samples=[dict(counter=i, earliest_host_seconds=i, observed_host_seconds=i+1) for i in range(3)],
                bytes_hex=b"0\n1\n2\n".hex(), largest_observed_gap_seconds=1,
                largest_append_gap_upper_bound_seconds=2, timing_scope="host monotonic brackets"),
            plan9_counter_request=dict(request={"bytes_hex":counter_request.hex()},submit_marker={"bytes_hex":marker.hex()},
                id="d"*32,service=service,paths=counter_paths,phase="submitted",
                publication=publication,submit_command=submit_command),
            fixture=gate.identity(fpath),
            apk_interruption_scope="APK3 pre-commit hook before package filesystem changes; not arbitrary transaction crash consistency",
            guest_prerequisites=dict(fixture_verified=True, apk_version=f["apk_version_stdout"], verification=verification,
                package_absent=dict(argv=["apk", "info", "--installed", f["package"]], returncode=1),
                hook_path="/etc/apk/commit_hooks.d/o10-restart-" + self.token,
                hook_sha256=gate.hashlib.sha256(hook).hexdigest()),
            apk_database_before=database(), apk_database_after=database(),
            interrupted_workload=dict(ready=True, apk_stage="pre-commit", file_bytes=2*1048576,
                durable_prefix=prefix, nonce=self.token, hook_process_chain=[dict(pid=23, ppid=22), dict(pid=22, ppid=1)],
                apk=dict(pid=22, start="100", state="S"), writer=dict(pid=24, start="101", state="S"),
                apk_argv=["apk","--no-network","--repositories-file","/dev/null","--keys-dir",f["keys_directory"],"add"]+
                         [r["path"] for r in f["apks"]]),
            guest_configuration_uploads=uploads, guest_helper_uploads=helper_uploads,
            guest_helper_sha256=gate.digest(helper), guest_commands=commands,
            recovered_file=dict(work_not_replayed=True, durable_prefix_bytes=prefix["bytes"],
                durable_prefix_sha256=prefix["sha256"], bytes=prefix["bytes"]+32, unknown_tail_bytes=32,
                unknown_tail_sha256="c"*64, file_sha256="d"*64,
                completion="unknown interrupted tail; only observed fsynced prefix validated"),
            quiesce=dict(before=["/dev/vda", "/", "ext4", "rw,relatime"],
                         remount=dict(argv=["mount", "-o", "remount,ro", "/"], returncode=0),
                         after=["/dev/vda", "/", "ext4", "ro,relatime"]),
            package_snapshot={**gate.identity(snapshot), "bytes": snapshot.stat().st_size},
            superblock=gate.restart.clean_superblock(snapshot), fsck={**gate.identity(fsck),"invoked_path":str(fsck)},
            fsck_result=dict(argv=[str(fsck), "-n", str(snapshot)], returncode=0,
                stdout=gate.identity(self.outer / "fsck.stdout"), stderr=gate.identity(self.outer / "fsck.stderr")),
            o10_exchanges=self.exchanges, linux_fault=injection,
            after=dict(linux=new_linux, plan9=new_plan9), final_states=dict(linux=new_linux, plan9=new_plan9),
            runner_linux_recoveries=[dict(ok=True, before=dict(state=4), after=dict(dom=new_linux["dom"]),service_before=service,service=service)],
            unknown_work_policy="Interrupted file/APK work is never automatically replayed")
        self.paths["restart_result"] = self.write("restart/result.json", self.primary)
        stdout = self.write("restart-command/stdout.log", "gate_passed:true\n")
        stderr = self.write("restart-command/stderr.log", "")
        self.paths["restart_command"] = self.write("restart-command/command.json",
            dict(argv=["bash", str(self.root / "scripts/o-kernel.sh"), "o10-linux-restart",
                            "--build",str(self.build),"--output",str(self.outer),"--seed-state",str(seed.parent),
                            "--apk-fixture",str(fpath),"--mcp-release",self.revision],
                 returncode=0, timed_out=False, stdout=gate.identity(stdout), stderr=gate.identity(stderr)))
        output=self.root/"m2-regressions"
        nested=output/"six-gates"
        for entry in shared["gates"]:
            old=Path(entry["state"]);new=nested/"states"/entry["gate_id"]
            new.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(old,new)
            childpath=new/"result.json"
            child=json.loads(childpath.read_text().replace(str(old),str(new)))
            childpath.write_text(json.dumps(child))
            entry.update(state=str(new),receipt={**gate.identity(childpath),"result":child})
            fork=entry["fork"]["argv"];fork[fork.index("--output")+1]=str(new)
            entry["command"]["argv"] += ["--state",str(new)]
            entry["command"]["argv"] += ["--runtime",str(self.root/"runtime")] if entry["gate_id"]=="runtime" else ["--build",str(self.build)]
        shared_path=self.write("m2-regressions/six-gates/result.json",shared)
        outlog=self.write("m2-regressions/shared-driver-command/stdout.log","actual shared stdout")
        errlog=self.write("m2-regressions/shared-driver-command/stderr.log","")
        driver=["python3","verify_o10_m1_regressions.py","--execute","--acceptance-scope","draft0",
                "--build",str(self.build),"--seed-state",shared["seed_state"],"--runtime",str(self.root/"runtime"),
                "--resident-result",str(self.paths["resident_result"]),"--output",str(nested),
                "--mcp-release",self.revision,"--jobs","2"]
        envelope = dict(schema=gate.REGRESSION_SCHEMA, milestone="M2", contract_id=gate.CONTRACT,
                        ok=True, full_milestone_qualified=False, source_revision=self.revision, mcp_release=self.revision,
                        restart_result=gate.identity(self.paths["restart_result"]),
                        restart_command=gate.identity(self.paths["restart_command"]),
                        resident_result=gate.identity(self.paths["resident_result"]),
                        source_sha256={n: gate.digest(self.root/n) for n in
                            ("scripts/verify_o10_m2.py", "scripts/verify_o10_m2_regressions.py",
                             "scripts/verify_o10_m1_regressions.py")},
                        shared_driver_command=dict(argv=driver,returncode=0,timed_out=False,
                                                   stdout=gate.identity(outlog),stderr=gate.identity(errlog)),
                        max_parallel_vms=2,build=str(self.build),monitor_sha256=gate.digest(self.build/"monitor.elf"),
                        profile_sha256=gate.digest(self.build/"monitor-profile.json"),
                        shared_result=gate.identity(shared_path), skips=[])
        self.paths["guest_result"] = self.write("m2-regressions/result.json", envelope)

    def save_primary(self):
        self.paths["restart_result"].write_text(json.dumps(self.primary))

    def validate_primary(self):
        return gate.validate_restart(root=self.root, receipt_path=self.paths["restart_result"], build=self.build,
                                     profile=self.profile, expected_revision=self.revision,
                                     command_path=self.paths["restart_command"])

    def validate(self):
        with patch.object(gate.shared, "tracked_language", return_value=self.base.inventory):
            return gate.validate_acceptance(root=self.root, build=self.build, compiler=self.compiler,
                                            expected_revision=self.revision, **self.paths)

    def test_complete_fixture_binds_all_existing_backbone_and_m2_evidence(self):
        value = self.validate()
        self.assertTrue(value["full_milestone_qualified"])
        self.assertEqual(value["contract_id"], gate.CONTRACT)
        self.assertEqual(len(value["sessions_checked"]), 8)

    def set_observed_state(self, index, state):
        row = self.primary["o10_exchanges"][index]
        before = row["reply"]
        reply = gate.o10.decode(bytes.fromhex(row["reply_hex"]))
        reply["state"] = state
        kind = reply.pop("type"); tag = reply.pop("tag")
        raw = gate.o10.encode(kind, tag=tag, **reply)
        after = gate.restart.safe(gate.o10.decode(raw))
        for summaries in ("after", "final_states"):
            for role in ("linux", "plan9"):
                if self.primary[summaries][role] == before:
                    self.primary[summaries][role] = copy.deepcopy(after)
        row.update(reply_hex=raw.hex(), reply=after)

    def test_all_healthy_domains_may_be_blocked_while_progress_evidence_stays_required(self):
        for index, row in enumerate(self.primary["o10_exchanges"]):
            if row["reply"].get("type") == "Rstat" and row["reply"].get("state") == 2:
                self.set_observed_state(index, 3)
        self.save_primary()
        self.validate_primary()
        self.primary["plan9_counter"]["bytes_hex"] = b"0\n".hex()
        self.save_primary()
        with self.assertRaises(ValueError):
            self.validate_primary()

    def test_nonlive_states_rejected_at_each_healthy_observation(self):
        original = copy.deepcopy(self.primary)
        for phase, index in (("initial-linux", 0), ("initial-plan9", 1),
                             ("post-bind-linux", 6), ("final-plan9", 7)):
            for state in (0, 1, 4, 5):
                with self.subTest(phase=phase, state=state):
                    self.primary = copy.deepcopy(original)
                    self.set_observed_state(index, state)
                    self.save_primary()
                    with self.assertRaises(ValueError):
                        self.validate_primary()

    def test_nonlive_final_linux_rejected_after_healthy_post_bind_observation(self):
        original = copy.deepcopy(self.primary)
        for state in (0, 1, 4, 5):
            with self.subTest(state=state):
                self.primary = copy.deepcopy(original)
                row = copy.deepcopy(self.primary["o10_exchanges"][6])
                tag = max(gate.o10.decode(bytes.fromhex(r["request_hex"]))["tag"]
                          for r in self.primary["o10_exchanges"]) + 1
                request = gate.o10.decode(bytes.fromhex(row["request_hex"]))
                kind = request.pop("type"); request["tag"] = tag
                row["request_hex"] = gate.o10.encode(kind, **request).hex()
                reply = gate.o10.decode(bytes.fromhex(row["reply_hex"]))
                kind = reply.pop("type"); reply["tag"] = tag; reply["state"] = state
                raw = gate.o10.encode(kind, **reply)
                row.update(reply_hex=raw.hex(), reply=gate.restart.safe(gate.o10.decode(raw)))
                self.primary["o10_exchanges"].append(row)
                self.primary["final_states"]["linux"] = copy.deepcopy(row["reply"])
                self.save_primary()
                with self.assertRaises(ValueError):
                    self.validate_primary()

    def validate_counter(self):
        config=json.loads(Path(self.primary["guest_configuration_uploads"][0]["source"]["path"]).read_text())
        return gate.validate_provider_counter(self.root,self.primary,config,outer=self.outer)

    def test_counter_submit_marker_and_completed_phase_bind_the_request(self):
        original=copy.deepcopy(self.primary)
        for change in ("marker","phase"):
            with self.subTest(change=change):
                self.primary=copy.deepcopy(original)
                value=self.primary["plan9_counter_request"]
                if change=="marker":
                    value["submit_marker"]["bytes_hex"]=b"unrelated submit\n".hex()
                else:
                    value["phase"]="submission-pending"
                with self.assertRaises(ValueError):
                    self.validate_counter()

    def test_counter_publication_rejects_changed_phase_path_bytes_or_digest(self):
        original=copy.deepcopy(self.primary)
        for phase in (0,1):
            for change in ("phase","staging","destination","bytes","sha256"):
                with self.subTest(phase=phase,change=change):
                    self.primary=copy.deepcopy(original)
                    row=self.primary["plan9_counter_request"]["publication"][phase]
                    if change=="phase":row["phase"]="other"
                    elif change=="staging":row["staging"]["path"]="/n/okernel/request"
                    elif change=="destination":row["destination"]+="-other"
                    elif change=="bytes":row["bytes"]+=1
                    else:row["sha256"]="0"*64
                    with self.assertRaises(ValueError):
                        self.validate_counter()

    def test_counter_publication_requires_exact_normal_copy_and_verified_staging(self):
        original=copy.deepcopy(self.primary)
        publication=self.primary["plan9_counter_request"]["publication"][0]
        command=publication["command"]
        for change in ("append","staging-content","missing-size-check"):
            with self.subTest(change=change):
                self.primary=copy.deepcopy(original)
                publication=self.primary["plan9_counter_request"]["publication"][0]
                if change=="append":
                    publication["command"]=command.replace(" > "," >> ",1)
                    for row in self.primary["guest_commands"]:
                        if row["command"]==command:row["command"]=publication["command"]
                else:
                    row=next(row for row in self.primary["guest_commands"]
                             if (row["command"].startswith("printf %s ") if change=="staging-content"
                                 else row["command"].startswith("base64 -d ")))
                    row["command"]+= " changed"
                with self.assertRaises(ValueError):
                    self.validate_counter()

    def test_counter_publication_requires_once_ordered_observed_submit_before_worker(self):
        original=copy.deepcopy(self.primary)
        submit=self.primary["plan9_counter_request"]["submit_command"]
        for change in ("repeat","unknown","order","after-worker"):
            with self.subTest(change=change):
                self.primary=copy.deepcopy(original)
                rows=self.primary["guest_commands"]
                index=next(i for i,row in enumerate(rows) if row["command"]==submit)
                if change=="repeat":rows.append(copy.deepcopy(rows[index]))
                elif change=="unknown":rows[index]["completion"]="unknown";rows[index]["returncode"]=None
                elif change=="order":rows.insert(2,rows.pop(index))
                else:rows.append(rows.pop(index))
                with self.assertRaises(ValueError):
                    self.validate_counter()

    def test_worker_launch_requires_exact_grouped_helper_config_and_redirections(self):
        config=json.loads(Path(self.primary["guest_configuration_uploads"][0]["source"]["path"]).read_text())
        original=copy.deepcopy(self.primary["guest_commands"])
        gate.validate_worker_launch(original,config,outer=self.outer)
        for change in ("helper","config","stdout","stderr","ungrouped","duplicate","unknown","nonzero"):
            with self.subTest(change=change):
                commands=copy.deepcopy(original)
                row=next(row for row in commands if " worker " in row["command"])
                if change in ("helper","config","stdout","stderr"):
                    suffix={"helper":".py","config":".json","stdout":"/worker.stdout","stderr":"/worker.stderr"}[change]
                    row["command"]=row["command"].replace(config["run"]+suffix,"/run/substituted"+suffix,1)
                elif change=="ungrouped":
                    row["command"]=row["command"][2:-2]
                elif change=="duplicate":
                    commands.append(copy.deepcopy(row))
                elif change=="unknown":
                    row["completion"]="unknown";row["returncode"]=None
                else:
                    row["returncode"]=1
                with self.assertRaises(ValueError):
                    gate.validate_worker_launch(commands,config,outer=self.outer)

    def test_model_or_failed_restart_is_rejected(self):
        self.primary["gate_passed"] = False; self.save_primary()
        with self.assertRaises(ValueError): self.validate_primary()

    def test_restart_command_must_have_actual_zero_exit_and_raw_logs(self):
        for transform in (lambda r:r.update(returncode=None), lambda r:r.update(timed_out=True),
                          lambda r:r.pop("stdout"), lambda r:r.update(argv=["echo", "pass"])):
            data=gate.document(self.paths["restart_command"]); original=copy.deepcopy(data)
            transform(data);self.paths["restart_command"].write_text(json.dumps(data))
            with self.assertRaises(ValueError):self.validate_primary()
            self.paths["restart_command"].write_text(json.dumps(original))

    def test_every_old_linux_fid_requires_numeric_stale_wire_reply(self):
        self.primary["witness_final"]["linux"]["exchanges"][0]["reply_hex"] = \
            self.primary["witness_before"]["linux"]["exchanges"][0]["reply_hex"]
        self.save_primary()
        with self.assertRaises(ValueError):self.validate_primary()

    def test_plan9_identity_change_rejects_current_wire_binding(self):
        self.primary["witness_restored"]["plan9"]["fids"][0]["object_generation"] += 1
        self.save_primary()
        with self.assertRaises(ValueError):self.validate_primary()

    def test_malformed_o10_or_duplicate_restore_is_rejected(self):
        self.primary["o10_exchanges"].append(copy.deepcopy(self.primary["o10_exchanges"][4]))
        self.save_primary()
        with self.assertRaises(ValueError):self.validate_primary()

    def test_apk_signature_and_controlled_scope_are_required(self):
        self.primary["guest_prerequisites"]["verification"]["returncode"] = 1
        self.save_primary()
        with self.assertRaises(ValueError):self.validate_primary()

    def test_post_restore_config_must_include_exact_observed_fsync_prefix(self):
        row = self.primary["guest_configuration_uploads"][1]
        path=Path(row["source"]["path"]);value=json.loads(path.read_text())
        value["durable_prefix"]["bytes"] += 1048576;path.write_text(json.dumps(value))
        row.update(bytes=path.stat().st_size,sha256=gate.digest(path))
        row["source"]={**gate.identity(path),"bytes":path.stat().st_size}
        self.save_primary()
        with self.assertRaises(ValueError):self.validate_primary()

    def test_unknown_tail_cannot_be_claimed_as_replayed_complete_work(self):
        self.primary["recovered_file"]["work_not_replayed"] = False; self.save_primary()
        with self.assertRaises(ValueError):self.validate_primary()

    def test_largest_counter_gap_is_recomputed_from_raw_brackets(self):
        self.primary["plan9_counter"]["largest_observed_gap_seconds"] = 0; self.save_primary()
        with self.assertRaises(ValueError):self.validate_primary()

    def test_fsck_nonzero_and_unclean_snapshot_are_rejected(self):
        self.primary["fsck_result"]["returncode"] = 4; self.save_primary()
        with self.assertRaises(ValueError):self.validate_primary()

    def test_captured_sources_cannot_escape_restart_output(self):
        name = next(iter(self.primary["source_artifacts"]))
        self.primary["source_artifacts"][name] = gate.identity(self.root/name)
        self.save_primary()
        with self.assertRaises(ValueError):self.validate_primary()

    def test_full_binder_rejects_failed_or_reused_guest_receipt(self):
        env=gate.document(self.paths["guest_result"])
        data=gate.document(env["shared_result"]["path"])
        data["gates"][0]["command"]["returncode"]=1
        Path(env["shared_result"]["path"]).write_text(json.dumps(data))
        env["shared_result"]=gate.identity(env["shared_result"]["path"])
        self.paths["guest_result"].write_text(json.dumps(env))
        with self.assertRaises(ValueError):self.validate()

    def test_full_binder_rejects_missing_discovered_component_module(self):
        log=self.paths["component_result"].parent/"tests.log"
        log.write_text(log.read_text().replace("test_o10_m2.Fixture", "omitted.Fixture"))
        with self.assertRaises(ValueError):self.validate()

    def test_full_binder_rejects_partial_language_inventory(self):
        unit=gate.document(self.paths["unit_result"]);path=Path(unit["language"]["path"])
        data=gate.document(path);data["results"].pop();path.write_text(json.dumps(data))
        unit["language"].update(gate.identity(path));self.paths["unit_result"].write_text(json.dumps(unit))
        with self.assertRaises(ValueError):self.validate()

    def test_final_running_summary_must_match_last_raw_linux_rstat(self):
        row=self.primary["o10_exchanges"][-2]
        request=gate.o10.decode(bytes.fromhex(row["request_hex"]))
        reply=gate.o10.decode(bytes.fromhex(row["reply_hex"]))
        reply["state"]=4
        kind=reply.pop("type");tag=reply.pop("tag")
        raw=gate.o10.encode(kind,tag=tag,**reply)
        row.update(reply_hex=raw.hex(),reply=gate.restart.safe(gate.o10.decode(raw)))
        self.save_primary()
        with self.assertRaises(ValueError):self.validate_primary()

    def test_shared_driver_cannot_substitute_another_command(self):
        path=self.paths["guest_result"];value=gate.document(path)
        value["shared_driver_command"]["argv"]=["echo","pass"]
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,"shared driver invocation"):self.validate()

    def test_shared_driver_cannot_exceed_two_vms(self):
        path=self.paths["guest_result"];value=gate.document(path)
        value["max_parallel_vms"]=3;path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,"two VMs"):self.validate()

    def test_standard_fsck_alias_preserves_invocation_and_hashes_resolved_binary(self):
        alias=Path(self.primary["fsck"]["invoked_path"])
        binary=self.root/"bin/e2fsck";binary.write_bytes(alias.read_bytes())
        alias.unlink();alias.symlink_to(binary)
        self.primary["fsck"]={**gate.identity(binary),"invoked_path":str(alias)}
        self.save_primary();self.validate_primary()

    def test_restart_observed_exit_must_bind_actual_inputs(self):
        path=self.paths["restart_command"];value=gate.document(path)
        argv=value["argv"];argv[argv.index("--build")+1]=str(self.root/"another-build")
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,"another input"):self.validate_primary()

    def test_shared_driver_raw_log_hash_is_rechecked(self):
        value=gate.document(self.paths["guest_result"])
        Path(value["shared_driver_command"]["stdout"]["path"]).write_text("changed transcript")
        with self.assertRaisesRegex(ValueError,"bytes changed"):self.validate()

    def test_new_output_does_not_overwrite_historical_receipt(self):
        output=self.root/"existing.json";output.write_text("historical")
        with patch.object(sys,"argv",["verify_o10_m2.py"]+sum(([f"--{k.replace('_','-')}",str(v)] for k,v in self.paths.items()),[])
                          +["--build",str(self.build),"--compiler",str(self.compiler),
                            "--expected-revision",self.revision,"--output",str(output)]):
            with self.assertRaises(SystemExit):gate.main()
        self.assertEqual(output.read_text(),"historical")
