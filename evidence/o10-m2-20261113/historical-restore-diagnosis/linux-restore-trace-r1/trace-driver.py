#!/usr/bin/env python3
"""One fresh debug workload run; CPU trace activated only around its new Linux Trestore."""
import hashlib,json,os,subprocess,sys,time,traceback
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path("/home/ustad/OSTADIX-o10-m2-20261112")
BASE=Path("/home/ustad/.cache/o10-m2-acceptance-20261113/linux-restore-trace-r1")
ACC=BASE.parent;REVISION="619394bafbe2b3f956ee7ec14bd87b0a9202f026"
sys.path.insert(0,str(ROOT/"scripts"))
import okernel_unified_world as runner
import verify_o10_linux_restart as gate
def desc(p):
 p=Path(p);return {"path":str(p),"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
def need(ok,msg):
 if not ok:raise ValueError(msg)
need(not (BASE/"gate").exists() and not (BASE/"debug-result.json").exists(),"debug run already attempted; no automatic rerun")
need(subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,capture_output=True,text=True,check=True).stdout.strip()==REVISION,"source revision changed")
profile=ACC/"unified-build-qualification-r4/monitor-profile.json";need(desc(profile)["sha256"]=="2a7d781ebf005cd32cfd8ddd79b74806ddf48574e0fa5842cce055cfbdcf210d","profile changed")
need(desc(ACC/"unified-build-qualification-r4/monitor.elf")["sha256"]=="e913b8d54f378f706b8ca5d09891e17d4307ce88ee613c8b3fd9479606469869","ELF changed")
before={n:desc(ROOT/n) for n in ["scripts/okernel_unified_world.py","scripts/verify_o10_linux_restart.py"]}
record={"schema":"ostadix.o10-m2-linux-restore-cpu-debug/v1","scope":"One explicitly requested fresh private diagnostic fork of the M2 workload with QEMU CPU/TB address-filtered observation. CPU tracing changes emulation performance. No timeout adjustment, production instrumentation, old unknown request replay, milestone gate or hardware claim.","milestone_qualified":False,"debug_only":True,"source_revision":REVISION,"mcp_release":REVISION,"source_before":before,"profile":desc(profile),"monitor":desc(ACC/"unified-build-qualification-r4/monitor.elf"),"wrapper":desc(BASE/"qemu-trace"),"sites":desc(BASE/"trace-sites.json"),"trace_activations":[],"started_unix":time.time()}
def save(): (BASE/"debug-result.json").write_text(json.dumps(record,indent=2)+"\n")
original=runner.UnifiedDomain._o10_exchange_once
def traced(self,frame,*,bootstrap=None):
 request=runner.o10.decode(frame)
 if request.get("type")!="Trestore" or request.get("dom")&0xffffffff:return original(self,frame,bootstrap=bootstrap)
 need(not record["trace_activations"],"second Linux restore forbidden in this debug run")
 need(hashlib.sha256(frame).hexdigest()!="1606b2b173a10ffc633a1e62d37bddd4169fc2ac2062c4e7830de5ef601ac029","old R6 unknown frame must never be replayed")
 entry={"frame_hex":frame.hex(),"frame_sha256":hashlib.sha256(frame).hexdigest(),"epoch":request["epoch"],"seq":request["seq"],"new_private_session":str(self.session),"qemu_pid":self.process.pid,"actual_qemu_argv":[x.decode() for x in (Path("/proc")/str(self.process.pid)/"cmdline").read_bytes().split(b"\0") if x],"before_enable_unix":time.time()}
 record["trace_activations"].append(entry);save()
 entry["hmp_help_log"]=self.qmp.execute("human-monitor-command",{"command-line":"help log"})
 entry["log_command"]={"command-line":"log cpu,nochain"}
 enabled=self.qmp.execute("human-monitor-command",entry["log_command"]);entry["log_response"]=enabled
 need(enabled=="","QEMU did not accept requested CPU logging")
 save()
 try:
  reply=original(self,frame,bootstrap=bootstrap);entry["completion"]="observed";entry["reply"]=runner.o10_observation(reply);return reply
 except BaseException as error:
  entry.update(completion="unknown",error=type(error).__name__+": "+str(error),traceback=traceback.format_exc())
  raise
 finally:
  entry["finished_unix"]=time.time()
  try:entry["disable_response"]=self.qmp.execute("human-monitor-command",{"command-line":"log none"})
  except BaseException as error:entry["disable_error"]=type(error).__name__+": "+str(error)
  save()
runner.UnifiedDomain._o10_exchange_once=traced
save()
try:
 value=gate.verify(seed=ACC/"fixture-seed",build=ACC/"unified-build-qualification-r4",fixture_path=Path("/home/ustad/.cache/o10-m2-offline-apk-fixture-20261113/fixture.json"),output=BASE/"gate",mcp_release=REVISION,qemu=str(BASE/"qemu-trace"),timeout=180)
 record["wrapped_verifier_returned"]=True
except BaseException as error:
 record.update(error=type(error).__name__+": "+str(error),traceback=traceback.format_exc())
finally:
 record["source_after"]={n:desc(ROOT/n) for n in before};record["source_unchanged"]=record["source_after"]==before
 if (BASE/"restore-cpu.log").exists():record["cpu_trace"]=desc(BASE/"restore-cpu.log")
 if (BASE/"gate/result.json").exists():record["wrapped_verifier_receipt"]=desc(BASE/"gate/result.json")
 record["finished_unix"]=time.time();save()
record["measurement_complete"]=len(record["trace_activations"])==1 and record.get("cpu_trace",{}).get("bytes",0)>0
save()
print(json.dumps({"diagnostic_run_complete":record["measurement_complete"],"debug_only":True,"result":str(BASE/"debug-result.json"),"error":record.get("error"),"activations":len(record["trace_activations"])}))

raise SystemExit(0 if record["measurement_complete"] else 1)
