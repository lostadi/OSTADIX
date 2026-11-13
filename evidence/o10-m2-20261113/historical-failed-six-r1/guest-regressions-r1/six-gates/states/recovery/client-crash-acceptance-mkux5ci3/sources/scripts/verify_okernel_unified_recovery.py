#!/usr/bin/env python3
"""Exercise guest-client SIGKILL recovery through the real foreground console.

This isolated admitted-profile gate performs no compiler rebuild. It distinguishes CLI
preflight time from native admission/streaming, kills only one witnessed Linux
guest client through a pidfd, and requires native unknown-outcome recovery
without automatically submitting the successor's requested command.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import sys
import tempfile
import time

from verify_okernel_unified_client import preflight, typed, checked_command, upload, validate_recovery, read_saved_session
from verify_okernel_unified_console import Terminal, hash_file

ROOT = Path(__file__).resolve().parents[1]
HELPER = r'''
import hashlib,json,os,signal,sys,time
from pathlib import Path
sys.path.insert(0,"/usr/lib/okernel")
import p9_protocol as p
root=Path(sys.argv[1]);action=sys.argv[2];token=sys.argv[3]
control=Path("/run/okernel/p9");local=Path("/run/p9-crash-"+token+".json")
def read(path):return json.loads(path.read_text())
def digest(data):return hashlib.sha256(data).hexdigest()
def write(value):
 data=json.dumps(value,sort_keys=True);local.write_text(data+"\n");(root/"evidence-crash.json").write_text(data+"\n")
def start(pid):return Path("/proc/"+str(pid)+"/stat").read_text().rsplit(")",1)[1].split()[19]
def results():return sorted(x.name for x in (control/"results").glob("*.json"))
def processes(pid,ticks):
 answer=[];queue=[(pid,None,ticks)]
 while queue:
  selected,parent,expected=queue.pop(0)
  try:
   fields=Path("/proc/"+str(selected)+"/stat").read_text().rsplit(")",1)[1].split()
   if (expected is not None and fields[19]!=expected) or (parent is not None and int(fields[1])!=parent):continue
   entry={"pid":selected,"parent":int(fields[1]),"state":fields[0],"start_ticks":fields[19],"args":Path("/proc/"+str(selected)+"/cmdline").read_bytes().replace(b"\0",b" ").decode("utf-8","replace")}
   answer.append(entry)
   children=Path("/proc/"+str(selected)+"/task/"+str(selected)+"/children").read_text().split()
   queue.extend((int(child),selected,None) for child in children)
  except (FileNotFoundError,ProcessLookupError):continue
 return answer
def observe(value,label):
 value["observation"]=label;write(value)
 # Keep the serial diagnostic bounded. Full warmup receipts remain in the
 # evidence file; reprinting them on every milestone distorts UART timings.
 summary={key:value[key] for key in ("observation","client_pid","client_start_ticks","pending_seconds","native_started_seconds","stream_seconds","owned_processes") if key in value}
 print("P9_CLIENT_OBSERVATION_"+token+" "+json.dumps(summary,sort_keys=True),flush=True)
if action=="prepare":
 assert not (control/"pending.json").exists()
 value={"started_monotonic":time.monotonic(),"current":read(control/"current.json"),"results":results(),"warmups":[]};write(value)
elif action=="warmup-begin":
 value=read(local);assert not (control/"pending.json").exists()
 value.update(warmup_started=time.monotonic(),warmup_results=results());write(value)
elif action=="warmup-end":
 assert int(sys.argv[4])==0
 value=read(local);index=int(sys.argv[5]);files=[x for x in (control/"results").glob("*.json") if x.name not in value["warmup_results"]]
 assert len(files)==1
 receipt=read(files[0]);g,s,r=(receipt[k] for k in ("generation","instance","request_id"))
 assert (g,s)==(value["current"]["generation"],value["current"]["instance"])
 directory=Path(receipt["service_root"])/("g"+g)/("s"+s)/("r"+r)
 files={name:(directory/name).read_bytes() for name in p.REQUEST_FILES}
 result=p.validate_result(files["request"],files["result"],files["stdout"],files["stderr"],started=files["started"],done=files["done"],status=files["status"])
 assert result.ok and files["stdout"]==("P9_WARMUP_"+token+"_"+str(index)+"\n").encode()
 value["warmups"].append({"index":index,"seconds":time.monotonic()-value["warmup_started"],"receipt":receipt});write(value)
 print("P9_WARMUP_TIMING_"+token+" "+json.dumps(value["warmups"][-1],sort_keys=True),flush=True)
elif action=="launch":
 value=read(local);assert len(value["warmups"])==10 and not (control/"pending.json").exists()
 assert read(control/"current.json")==value["current"]
 value.update(started_monotonic=time.monotonic(),results=results());write(value)
elif action=="await":
 value=read(local);pid=int((root/"client.pid").read_text());ticks=(root/"client.start").read_text().strip()
 assert pid>1 and start(pid)==ticks
 value.update(client_pid=pid,client_start_ticks=ticks)
 def elapsed():return float(Path("/proc/uptime").read_text().split()[0])-int(ticks)/os.sysconf("SC_CLK_TCK")
 deadline=time.monotonic()+150
 while True:
  assert start(pid)==ticks,"client exited/reused before stream witness"
  if (control/"pending.json").exists():
   pending=read(control/"pending.json")
   if "pending_seconds" not in value:
    value.update(pending_seconds=elapsed(),owned_processes=processes(pid,ticks));observe(value,"pending-observed")
   g,s,r=(pending[k] for k in ("generation","instance","request_id"))
   assert (g,s)==(value["current"]["generation"],value["current"]["instance"])
   wire=bytes.fromhex(pending["request_hex"]);request=p.decode_request(wire)
   assert request.request_id==r and digest(wire)==pending["request_sha256"]
   directory=Path(pending["service_root"])/("g"+g)/("s"+s)/("r"+r)
   if (directory/"started").exists():
    p.validate_submit(wire,(directory/"started").read_bytes())
    if "native_started_seconds" not in value:
     value["native_started_seconds"]=elapsed();observe(value,"native-started-observed")
   if (root/"client.stdout").exists() and ("ABANDON_STREAM_"+token+"\n").encode() in (root/"client.stdout").read_bytes():
    assert pending["phase"]=="submitted" and not (directory/"done").exists()
    value.update(pending=pending,stream_seconds=elapsed());observe(value,"actual-stream-observed");break
  if elapsed()>30 and "slow_start" not in value:
   value.update(slow_start=True,owned_processes=processes(pid,ticks));observe(value,"startup-over30s")
  if time.monotonic()>=deadline:
   value["owned_processes"]=processes(pid,ticks);observe(value,"startup-timeout");raise AssertionError("no submitted original stream within150s")
  time.sleep(.1)
elif action=="kill":
 value=read(local);pid=value["client_pid"];descriptor=os.pidfd_open(pid)
 try:
  assert start(pid)==value["client_start_ticks"]
  argv=Path("/proc/"+str(pid)+"/cmdline").read_bytes().split(b"\0")
  assert b"/usr/local/bin/p9" in argv[:3],argv
  assert read(control/"pending.json")==value["pending"]
  signal.pidfd_send_signal(descriptor,signal.SIGKILL,None,0)
 finally:os.close(descriptor)
 deadline=time.monotonic()+10
 while True:
  try:state=Path("/proc/"+str(pid)+"/stat").read_text().rsplit(")",1)[1].split()[0]
  except FileNotFoundError:break
  if state=="Z":break
  assert time.monotonic()<deadline;time.sleep(.05)
 pending=read(control/"pending.json");assert pending==value["pending"] and pending["phase"]=="submitted"
 assert read(control/"current.json")==value["current"]
 value.update(guest_client_killed=True,retained_phase_before_successor=pending["phase"]);write(value)
elif action=="successor":
 assert int(sys.argv[4])==125
 value=read(local);old=value["current"];pending=value["pending"];g,s,r=(pending[k] for k in ("generation","instance","request_id"))
 assert (root/"successor.stdout").read_bytes()==b""
 assert b"prior request recovered; this invocation was not submitted" in (root/"successor.stderr").read_bytes()
 assert not (control/"pending.json").exists() and results()==value["results"]
 ack=read(control/"recovered"/("g"+g+"-s"+s+"-r"+r+".json"));current=read(control/"current.json")
 expected={"schema":"ostadix.p9.recovered/v1","generation":g,"old_instance":s,"request_id":r,"request_sha256":pending["request_sha256"],"outcome":"unknown","result_sha256":None,"reset_sha256":None,"done_sha256":None}
 assert all(k in ack and ack[k]==v for k,v in expected.items()),ack
 assert current["generation"]==g and current["instance"]==ack["new_instance"]!=s and current["state"]=="ready"
 ready=p.ready_marker(g,current["instance"]);assert ack["ready_sha256"]==digest(ready)
 instance=Path(current["service_root"])/("g"+g)/("s"+current["instance"])
 assert (instance/"ready").read_bytes()==ready and not any(x.is_dir() for x in instance.glob("r*"))
 value.update(private_ack=ack,replacement=current,successor_exit=125,successor_not_submitted=True);write(value)
elif action=="retry":
 assert int(sys.argv[4])==0
 value=read(local);files=[x for x in (control/"results").glob("*.json") if x.name not in value["results"]]
 assert len(files)==1
 receipt=read(files[0]);g,s,r=(receipt[k] for k in ("generation","instance","request_id"))
 assert (g,s)==(value["replacement"]["generation"],value["replacement"]["instance"])
 directory=Path(receipt["service_root"])/("g"+g)/("s"+s)/("r"+r)
 files={name:(directory/name).read_bytes() for name in p.REQUEST_FILES}
 result=p.validate_result(files["request"],files["result"],files["stdout"],files["stderr"],started=files["started"],done=files["done"],status=files["status"])
 assert result.ok and result.status==b"" and files["stdout"]==("EXPLICIT_AFTER_CLIENT_CRASH_"+token+"\n").encode()
 assert receipt["result_sha256"]==digest(files["result"]) and not receipt["recovered"]
 value.update(retry_receipt=receipt,retry_stdout_sha256=digest(files["stdout"]));write(value)
else:raise AssertionError(action)
print("\nP9_CRASH_"+action+"_"+token,flush=True)
'''


def verify(state: Path, build: Path):
    inputs = preflight(state, build)
    state, build = Path(inputs["state"]), Path(inputs["build"])
    output = Path(tempfile.mkdtemp(prefix="client-crash-acceptance-", dir=state))
    proof = output / "result.json"
    paths = ("scripts/verify_okernel_unified_recovery.py", "scripts/verify_okernel_unified_client.py",
             "scripts/verify_okernel_unified_console.py", "scripts/okernel_unified_world.py",
             "scripts/okernel_package_domain.py", "scripts/okernel_native_volume.py",
             "ocore/guest/linux/package-domain/p9", "ocore/guest/linux/package-domain/p9-controller",
             "ocore/guest/linux/package-domain/p9-history", "ocore/guest/plan9/unified/protocol.py")
    sources = {name: hash_file(ROOT / name) for name in paths}
    record = {"schema": "ostadix.unified-foreground-client-crash/v1", "ok": False, "started": time.time(),
              "scope": "actual typed Linux background p9 client with original Plan9 stream; guest pidfd SIGKILL, unknown native recovery, no automatic successor submission, explicit retry and paired save",
              "timing_scope": "guest monotonic/proc-uptime observations; warmup intervals include typed invocation and result validation; full foreground gate independently enforces host-wall30s streaming",
              "inputs": inputs, "source_sha256": sources, "source_artifacts": {}}
    for name, sha in sources.items():
        target = output / "sources" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        data = (ROOT / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise RuntimeError("source changed during capture")
        target.write_bytes(data);target.chmod(0o400)
        record["source_artifacts"][name] = {"path": str(target.relative_to(output)), "bytes": len(data), "sha256": sha}
    proof.write_text(json.dumps(record, indent=2) + "\n")
    terminal = None
    token = secrets.token_hex(10)
    workspace = "/n/okernel/work/client-crash-" + token
    helper = "/tmp/client-crash-" + token + ".py"
    try:
        terminal = Terminal(state, build, output)
        terminal.wait(b"Linux and original Plan 9 share this workspace.", timeout=240)
        session = Path((state / "latest-unified-session").read_text().strip())
        record["session"] = str(session)
        checked_command(terminal, "mkdir -p " + workspace)
        typed(terminal, "cd " + workspace)
        installed = (("/usr/local/bin/p9", "ocore/guest/linux/package-domain/p9"),
                     ("/usr/local/libexec/p9-history", "ocore/guest/linux/package-domain/p9-history"),
                     ("/usr/local/libexec/p9-controller", "ocore/guest/linux/package-domain/p9-controller"),
                     ("/usr/lib/okernel/p9_protocol.py", "ocore/guest/plan9/unified/protocol.py"))
        checked_command(terminal, " && ".join('test "$(sha256sum ' + path + " | cut -d ' ' -f1)\" = " + sources[source]
                                             for path, source in installed))
        upload(terminal, helper, HELPER.encode())
        prefix = "python3 " + shlex.quote(helper) + " " + workspace
        checked_command(terminal, "echo $$ > linux-shell.pid; awk '{print $22}' /proc/$$/stat > linux-shell.start; " + prefix + " prepare " + token)
        for index in range(10):
            checked_command(terminal, prefix + " warmup-begin " + token)
            typed(terminal, "p9 echo P9_WARMUP_" + token + "_" + str(index) + "; p9_crash_rc=$?; "
                  + prefix + " warmup-end " + token + ' "$p9_crash_rc" ' + str(index))
            # A unique typed ACK avoids accepting a preceding setup message.
            terminal.wait(("P9_WARMUP_" + token + "_" + str(index)).encode(), timeout=120, line=True)
            checked_command(terminal, "python3 -c " + shlex.quote("import json;from pathlib import Path;p=json.loads(Path('/run/p9-crash-" + token + ".json').read_text());assert len(p['warmups'])==" + str(index + 1)), timeout=120)
        checked_command(terminal, prefix + " launch " + token)
        typed(terminal, "p9 --timeout-ms 180000 rc -I -c " + shlex.quote("echo ABANDON_STREAM_" + token + "; sleep 120")
              + " > client.stdout 2> client.stderr & p9_crash_pid=$!; echo $p9_crash_pid > client.pid; awk '{print $22}' /proc/$p9_crash_pid/stat > client.start")
        checked_command(terminal, prefix + " await " + token, timeout=180)
        checked_command(terminal, prefix + " kill " + token)
        typed(terminal, "p9 echo MUST_NOT_SUBMIT_" + token + " > successor.stdout 2> successor.stderr; p9_crash_rc=$?; "
              + prefix + " successor " + token + ' "$p9_crash_rc"')
        terminal.wait(("P9_CRASH_successor_" + token).encode(), timeout=180, line=True)
        typed(terminal, "p9 echo EXPLICIT_AFTER_CLIENT_CRASH_" + token + "; p9_crash_rc=$?; "
              + prefix + " retry " + token + ' "$p9_crash_rc"')
        terminal.wait(("P9_CRASH_retry_" + token).encode(), timeout=120, line=True)
        checked_command(terminal, "test \"$(cat linux-shell.pid)\" = $$ && test \"$(awk '{print $22}' /proc/$$/stat)\" = \"$(cat linux-shell.start)\"")
        terminal.finish()
        saved, volume = read_saved_session(state, session)
        evidence = json.loads(volume.get(workspace.removeprefix("/n/okernel") + "/evidence-crash.json"))
        if (evidence.get("retained_phase_before_successor") != "submitted" or evidence.get("guest_client_killed") is not True
                or evidence.get("successor_not_submitted") is not True):
            raise RuntimeError("client crash did not preserve a submitted claim and refuse automatic successor submission")
        recovery = validate_recovery(saved, evidence)
        if recovery.get("unknown") is None or recovery.get("reset") is not None:
            raise RuntimeError("client crash recovery fabricated an interrupted completion")
        if sources != {name: hash_file(ROOT / name) for name in sources}:
            raise RuntimeError("source changed during qualification")
        record.update(ok=True, finished=time.time(), evidence=evidence, native_recovery=recovery,
                      checks=["background original stream is witnessed before guest-only pidfd SIGKILL of the exact clientPID/starttime",
                              "ten typed original p9echo invocations have individually validated native wire results and recorded CLI durations",
                              "submitted pending claim survives crash; successor triggers native unknown recovery and submits no new request",
                              "explicit retry executes on the replacement original Plan9 domain; Linux shellPID/starttime survives",
                              "one explicit Ctrl+] publishes quiescent paired storage and restores full foreground termios"])
        print("Unified foreground abandoned-client recovery: PASS\nEvidence: " + str(proof))
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if terminal is not None:
            terminal.close()
        proof.write_text(json.dumps(record, indent=2) + "\n")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args.state.expanduser(), args.build.expanduser())
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError) as error:
        print("Unified client-crash acceptance failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
