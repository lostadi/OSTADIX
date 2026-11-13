#!/usr/bin/env python3
"""Qualify the p9 client through one real foreground PTY in an isolated fork.

Every command is typed into the Linux shell. Original Plan9 executables run in
the concurrent original9front domain under native O-core, with common objects
provided by its native store. Automated keystrokes are not a human-user claim.
Only explicitly selected monitor byte identities are admitted for this test;
later profiles need a new explicit selection. No main/default state is an
admissible target. Admission alone is not a successful live qualification.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import sys
import tempfile
import time

from verify_okernel_unified_console import Terminal, hash_file
from okernel_unified_world import Volume, checked, common, validate_profile

ROOT = Path(__file__).resolve().parents[1]
R8_MONITOR = "f221ef2150dfbe0446cf6650fb4f4c9677ac95df9adc34e517e83d8b81134089"
R9_MONITOR = "dfea381c44dc59910d418303c0419d58d66780b93f475017508841db8dd65c0b"
R10_MONITOR = "faff09c75e79cfbc5f4baf42bdbb030e5018e75fe683673d7c84b1bc19804ba1"
# O10 live admission: evidence/o10-m0-20261112/fresh-live-3/result.json
O10_M0_MONITOR = "641a0ad14fb96979f7d4b141779f8bbad7b8b854ea1fde4fe1b25d984504aeaf"
O10_M0_PROFILE = "0093b2889160814778975bed6084543bebab3a9cf30ea7c8a408ca756ae0295e"
# R7 resident/normal functional candidate only; no extra-device claim.
# evidence/o10-m1-20261113/resident-r7/result.json
O10_M1_R7_MONITOR = "d8163b97dd9b7c165d7daa761756bb11fa164338598efd899c8b3c0f82927d32"
O10_M1_R7_PROFILE = "4ed18d420aa3f0348d324f4e0d8f38854222eb7faa67b0dce338322313701938"
# Private M2 candidate admission for live/regression gates only; qualification is pending.
# Build: ~/.cache/o10-m2-acceptance-20261113/unified-build-qualification-r5
O10_M2_MONITOR = "30a91b43bb78e9202c983417e39609991554914ff0deb76998b69e19ea01dddb"
O10_M2_PROFILE = "d5a5207a7b0e85963c98e7cefb378a69a32d77c70702aaa8cf783dcc909f964c"
MONITOR_REVISIONS = {O10_M2_MONITOR: "O10-M2-private-candidate", O10_M1_R7_MONITOR: "O10-M1-R7-resident-candidate", O10_M0_MONITOR: "O10-M0-live", R8_MONITOR: "R8", R9_MONITOR: "R9", R10_MONITOR: "R10-idle-traffic"}
MONITOR_PROFILES = {
    O10_M2_MONITOR: O10_M2_PROFILE,
    O10_M1_R7_MONITOR: O10_M1_R7_PROFILE,
    O10_M0_MONITOR: O10_M0_PROFILE,
    R8_MONITOR: "de9938bb381d7db3613cabedc1fdbf0d18b3eb65b4318a8cee7a26f7292bee2c",
    R9_MONITOR: "d16d00728c1c52ba46c04485c9c0a564f4836ec9cd72a8e913622023eeabccba",
    R10_MONITOR: "fa30ee495211844c299173b9c079119e73c333d2716bdc85fd1e0899e8719ca5",
}

# This assertion helper runs only as typed Linux test code. It observes the
# real client's Linux-private records and independently validates the exact
# shared native wire result; it neither dispatches original programs nor
# fabricates controller acknowledgements.
GUEST_HELPER = r'''
import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,"/usr/lib/okernel")
import p9_protocol as p
root=Path(sys.argv[1]); action=sys.argv[2]; name=sys.argv[3]
control=Path("/run/okernel/p9"); local=Path("/run/p9-foreground-acceptance")
local.mkdir(mode=0o700,exist_ok=True)
def read(path):return json.loads(path.read_text())
def write(path,value):path.write_text(json.dumps(value,sort_keys=True)+"\n")
def digest(data):return hashlib.sha256(data).hexdigest()
if action=="begin":
 write(local/(name+".json"),{"current":read(control/"current.json"),"results":sorted(x.name for x in (control/"results").glob("*.json"))})
elif action=="collect":
 code,expected=int(sys.argv[4]),int(sys.argv[5]); assert code==expected,(code,expected)
 before=read(local/(name+".json")); now=read(control/"current.json")
 files=[x for x in (control/"results").glob("*.json") if x.name not in before["results"]]
 assert len(files)==1,[x.name for x in files]
 receipt=read(files[0]); g,s,r=(receipt[k] for k in ("generation","instance","request_id"))
 assert (g,s)==(before["current"]["generation"],before["current"]["instance"])
 directory=Path(receipt["service_root"])/("g"+g)/("s"+s)/("r"+r)
 wire={k:(directory/k).read_bytes() for k in p.REQUEST_FILES}
 result=p.validate_result(wire["request"],wire["result"],wire["stdout"],wire["stderr"],started=wire["started"],done=wire["done"],status=wire["status"])
 assert receipt["status_hex"]==result.status.hex()
 assert receipt["request_sha256"]==digest(wire["request"])
 assert receipt["result_sha256"]==digest(wire["result"])
 request=p.decode_request(wire["request"])
 record={"linux_exit":code,"receipt":receipt,"current":now,"argv":list(request.argv),"cwd":request.cwd,"status_hex":result.status.hex(),"wire_sha256":{k:digest(v) for k,v in wire.items()}}
 if name=="status":
  raw=(root/"status.raw").read_bytes(); assert raw==result.status and raw and raw.endswith((": "+sys.argv[6]).encode()),raw
  assert not result.ok and result.flags==0 and not receipt["recovered"]
 elif name=="cancel":
  assert result.flags&p.FLAG_CANCELLED and receipt["recovered"] is True
  assert (root/"cancel.status").read_bytes()==result.status
  ack=read(control/"recovered"/("g"+g+"-s"+s+"-r"+r+".json"))
  expected_ack={"schema":"ostadix.p9.recovered/v1","generation":g,"old_instance":s,"request_id":r,"request_sha256":digest(wire["request"]),"result_sha256":digest(wire["result"]),"done_sha256":digest(wire["done"]),"outcome":"interrupted"}
  assert all(ack.get(k)==v for k,v in expected_ack.items()),ack
  reset=(directory.parent/"reset-required").read_bytes();p.validate_reset(wire["request"],wire["result"],reset)
  assert ack["reset_sha256"]==digest(reset)
  assert ack["new_instance"]==now["instance"]!=s and now["generation"]==g and now["state"]=="ready"
  ready=p.ready_marker(g,now["instance"]);assert ack["ready_sha256"]==digest(ready)
  assert (directory.parent.parent/("s"+now["instance"])/"ready").read_bytes()==ready
  assert not (control/"pending.json").exists()
  record["private_ack"]=ack
 else:
  assert result.ok and result.flags==0 and result.status==b"" and not receipt["recovered"]
 write(root/("evidence-"+name+".json"),record)
else:raise AssertionError(action)
print("\n"+("P9_BEGIN_" if action=="begin" else "P9_ASSERT_")+name+"_"+root.name,flush=True)
'''

WATCHDOG_HELPER = r'''
import hashlib,json,re,sys,time
from pathlib import Path
sys.path.insert(0,"/usr/lib/okernel")
import p9_protocol as p
root=Path(sys.argv[1]);action=sys.argv[2];control=Path("/run/okernel/p9")
local=Path("/run/p9-foreground-acceptance/watchdog.json")
def read(path):return json.loads(path.read_text())
def digest(data):return hashlib.sha256(data).hexdigest()
def write(path,value):path.write_text(json.dumps(value,sort_keys=True)+"\n")
if action=="prepare":
 current=read(control/"current.json");g,s=current["generation"],current["instance"]
 p.ready_marker(g,s);native="/n/"+str(root.relative_to("/n/okernel"))
 # Exact argv prefix AND fixed current G/S exclude this rc and every unrelated
 # process. Re-evaluate inside the killing invocation: never reuse an old PID.
 find="targets=(); for(d in /proc/[0-9]*) { a=`{cat $d/args >[2]/dev/null}; if(~ $#a 4 && ~ $a(1) /arm64/bin/p9cmdsrv && ~ $a(2) /n/services/plan9 && ~ $a(3) "+g+" && ~ $a(4) "+s+") targets=($targets $d) }; if(! ~ $#targets 1) { echo bad-resident-count >[1=2]; exit resident-target }; echo $targets > "+native+"/watchdog-target; cat $targets/args > "+native+"/watchdog-target.args; "
 (root/"watchdog-find.rc").write_text(find+"echo RESIDENT_FOUND\n")
 (root/"watchdog-kill.rc").write_text(find+"echo kill > $targets/note && echo NOTE_SENT > "+native+"/watchdog-note-sent; sleep 120\n")
 write(local,{"current":current})
elif action=="before":
 value=read(local);assert read(control/"current.json")==value["current"]
 value["results"]=sorted(x.name for x in (control/"results").glob("*.json"));write(local,value)
elif action=="unknown":
 assert int(sys.argv[3])==125
 value=read(local);old=value["current"];pending=read(control/"pending.json")
 assert pending["phase"]=="unknown" and (pending["generation"],pending["instance"])==(old["generation"],old["instance"])
 wire=bytes.fromhex(pending["request_hex"]);request=p.decode_request(wire)
 assert (request.generation,request.instance,request.request_id)==tuple(pending[k] for k in ("generation","instance","request_id"))
 assert digest(wire)==pending["request_sha256"]
 directory=Path(pending["service_root"])/("g"+pending["generation"])/("s"+pending["instance"])/("r"+pending["request_id"])
 assert (directory/"request").read_bytes()==wire;p.validate_submit(wire,(directory/"submit").read_bytes())
 assert not (directory/"done").exists() and not (directory/"result").exists()
 assert sorted(x.name for x in (control/"results").glob("*.json"))==value["results"]
 target=(root/"watchdog-target").read_text().strip();assert re.fullmatch(r"/proc/[1-9][0-9]*",target),target
 assert (root/"watchdog-note-sent").read_bytes()==b"NOTE_SENT\n"
 args=(root/"watchdog-target.args").read_text().split()
 assert args==["/arm64/bin/p9cmdsrv","/n/services/plan9",old["generation"],old["instance"]],args
 value.update(pending=pending,target=target,target_args=args,cli_exit=125);write(local,value)
elif action=="ready":
 value=read(local);pending=value["pending"];g,s,r=(pending[k] for k in ("generation","instance","request_id"))
 ack_path=control/"recovered"/("g"+g+"-s"+s+"-r"+r+".json")
 deadline=time.monotonic()+150
 while True:
  if ack_path.exists():
   ack=read(ack_path);now=read(control/"current.json")
   expected={"schema":"ostadix.p9.recovered/v1","generation":g,"old_instance":s,"request_id":r,"request_sha256":pending["request_sha256"],"outcome":"unknown","result_sha256":None,"reset_sha256":None,"done_sha256":None}
   assert all(k in ack and ack[k]==v for k,v in expected.items()),ack
   assert now["generation"]==g and now["instance"]==ack["new_instance"]!=s and now["state"]=="ready"
   ready=p.ready_marker(g,now["instance"]);assert ack["ready_sha256"]==digest(ready)
   instance=Path(pending["service_root"])/("g"+g)/("s"+now["instance"])
   assert (instance/"ready").read_bytes()==ready
   assert read(control/"pending.json")["phase"]=="unknown"
   value.update(private_ack=ack,current=now,fresh_requests=sorted(x.name for x in instance.glob("r*") if x.is_dir()))
   write(local,value);write(root/"evidence-unknown.json",value);break
  assert time.monotonic()<deadline,"unknown native recovery did not complete"
  time.sleep(.1)
elif action=="cleared":
 assert int(sys.argv[3])==125
 value=read(local);assert not (control/"pending.json").exists()
 assert (root/"watchdog-first.out").read_bytes()==b""
 assert b"prior request recovered; this invocation was not submitted" in (root/"watchdog-first.err").read_bytes()
 assert not (root/"watchdog-effect").exists()
 assert sorted(x.name for x in (control/"results").glob("*.json"))==value["results"]
 current=read(control/"current.json");assert current==value["current"]
 instance=Path(current["service_root"])/("g"+current["generation"])/("s"+current["instance"])
 assert sorted(x.name for x in instance.glob("r*") if x.is_dir())==value["fresh_requests"]
 value["recovery_invocation_not_submitted"]=True;write(local,value);write(root/"evidence-unknown.json",value)
else:raise AssertionError(action)
print("\nP9_WATCHDOG_"+action+"_"+root.name,flush=True)
'''


def admitted_monitor_revision(digest: str, profile_digest: str) -> str:
    if not isinstance(digest, str) or digest not in MONITOR_REVISIONS:
        raise ValueError("monitor byte identity is not explicitly admitted for this acceptance")
    if not isinstance(profile_digest, str) or profile_digest != MONITOR_PROFILES[digest]:
        raise ValueError("monitor profile/input identity differs from the explicitly admitted build")
    return MONITOR_REVISIONS[digest]


def preflight(state: Path, build: Path) -> dict:
    if state.is_symlink() or build.is_symlink():
        raise ValueError("state/build must not be symlinks")
    state, build = state.resolve(strict=True), build.resolve(strict=True)
    configured = Path(os.environ.get("OSTADIX_OKERNEL_STATE") or str(common.DEFAULT_STATE.parent)) / "package-domain"
    if state in (common.DEFAULT_STATE.resolve(), configured.expanduser().resolve()):
        raise ValueError("the working/default OS cannot be a client acceptance target")
    fork = json.loads((state / "fork.json").read_text())
    if fork.get("schema") != "ostadix.okernel-state-fork/v1" or fork.get("ok") is not True or fork.get("output") != str(state):
        raise ValueError("use an explicit isolated state fork")
    profile = json.loads((build / "monitor-profile.json").read_text())
    validate_profile(profile)
    profile_digest = hash_file(build / "monitor-profile.json")
    revision = admitted_monitor_revision(profile["artifacts"]["monitor.elf"]["sha256"], profile_digest)
    if (profile.get("plan9_derivation_kind") != "qualified-original-userland"
            or not profile.get("coordinator_uart") or not profile.get("plan9_recovery")):
        raise ValueError("this acceptance requires an admitted original-userland/controller profile")
    for name, identity in profile["artifacts"].items():
        checked(build / name, identity)
    head = json.loads((state / "head.json").read_text())
    common.validate_head(state, head)
    return {"state": str(state), "build": str(build), "before": head,
            "monitor_revision": revision,
            "profile_sha256": profile_digest,
            "monitor": profile["artifacts"]["monitor.elf"]}


def typed(terminal: Terminal, command: str):
    if "\n" in command or len(command.encode()) > 3500:
        raise ValueError("typed command must fit one bounded canonical terminal line")
    terminal.send(command.encode() + b"\n")


def checked_command(terminal: Terminal, command: str, *, timeout=90) -> str:
    marker = "P9_TYPED_OK_" + secrets.token_hex(12)
    typed(terminal, "( " + command + " ) && printf '%s\\n' " + marker)
    terminal.wait(marker.encode(), timeout=timeout, line=True)
    return marker


def upload(terminal: Terminal, destination: str, data: bytes):
    encoded = base64.b64encode(data).decode()
    for index in range(0, len(encoded), 768):
        operator = ">" if index == 0 else ">>"
        checked_command(terminal, "printf %s " + shlex.quote(encoded[index:index + 768])
                        + " | base64 -d " + operator + " " + shlex.quote(destination))


def collect(terminal: Terminal, helper: str, workspace: str, name: str,
            command: str, *, expected=0, argument="", timeout=90):
    prefix = "python3 " + shlex.quote(helper) + " " + shlex.quote(workspace)
    checked_command(terminal, prefix + " begin " + name)
    invocation = command + "; p9_accept_rc=$?; " + prefix + " collect " + name + ' "$p9_accept_rc" ' + str(expected)
    if argument:
        invocation += " " + shlex.quote(argument)
    typed(terminal, invocation)
    terminal.wait(("P9_ASSERT_" + name + "_" + Path(workspace).name).encode(), timeout=timeout, line=True)


def validate_recovery(record: dict, evidence: dict):
    ack = evidence["private_ack"]
    matches = [item for item in record.get("provider_recoveries", [])
               if item.get("previous") == {"generation": ack["generation"], "instance": ack["old_instance"]}
               and item.get("current") == {"generation": ack["generation"], "instance": ack["new_instance"]}]
    if len(matches) != 1:
        raise RuntimeError("typed cancellation lacks one exact native domain replacement")
    recovery = matches[0]
    if (recovery.get("ok") is not True or recovery.get("withdrawn", {}).get("live_domains") != 1
            or recovery.get("restored", {}).get("live_domains") != 3):
        raise RuntimeError("native cancellation failed to preserve Linux and replace only Plan9")
    updates = record.get("coordinator_updates", [])
    if not any(item.get("frame", {}).get("recovered") == ack and item.get("ack", {}).get("ok") is True for item in updates):
        raise RuntimeError("typed completion lacks the matching Linux-private native UART acknowledgement")
    return recovery


def read_saved_session(state: Path, session: Path) -> tuple[dict, Volume]:
    record = json.loads((session / "result.json").read_text())
    if (not record.get("ok") or not record.get("paired_snapshot")
            or record.get("virtual_cpu_stopped") is not True or record.get("native_operations_quiescent") is not True):
        raise RuntimeError("foreground stop did not publish a quiescent paired snapshot")
    if json.loads((session / "native-observation.json").read_text()).get("input_dropped") != 0:
        raise RuntimeError("typed input was dropped")
    selected = json.loads((state / "head.json").read_text())
    if selected != record.get("after"):
        raise RuntimeError("selected pair differs from the actual typed-session save")
    return record, Volume.from_file(checked(Path(selected["namespace"]["path"]), selected["namespace"]))


def watchdog_gate(terminal: Terminal, helper: str, workspace: str, token: str):
    watchdog = helper + ".watchdog.py"
    upload(terminal, watchdog, WATCHDOG_HELPER.encode())
    prefix = "python3 " + shlex.quote(watchdog) + " " + shlex.quote(workspace)
    checked_command(terminal, prefix + " prepare")
    collect(terminal, helper, workspace, "resident", 'p9 rc -I -c "$(cat watchdog-find.rc)"')
    checked_command(terminal, prefix + " before")
    typed(terminal, 'p9 --timeout-ms 2000 rc -I -c "$(cat watchdog-kill.rc)"; p9_accept_rc=$?; '
          + prefix + ' unknown "$p9_accept_rc"')
    terminal.wait(("P9_WATCHDOG_unknown_" + Path(workspace).name).encode(), timeout=60, line=True)
    checked_command(terminal, prefix + " ready", timeout=180)
    effect = "/n/work/" + Path(workspace).name + "/watchdog-effect"
    command = "p9 rc -I -c " + shlex.quote("echo EXPLICIT_RETRY_" + token + " > " + effect)
    typed(terminal, command + ' > watchdog-first.out 2> watchdog-first.err; p9_accept_rc=$?; '
          + prefix + ' cleared "$p9_accept_rc"')
    terminal.wait(("P9_WATCHDOG_cleared_" + Path(workspace).name).encode(), timeout=90, line=True)
    collect(terminal, helper, workspace, "retry", command)
    checked_command(terminal, 'test "$(cat watchdog-effect)" = EXPLICIT_RETRY_' + token)


def raw_console_gate(terminal: Terminal, token: str):
    terminal.send(b"\x1e1")
    terminal.wait(b"[O-core console: original Plan 9", timeout=30)
    marker = ("RAW_PLAN9_CR_" + token).encode()
    terminal.send(b"echo " + marker + b"\r")
    terminal.wait(marker, timeout=30, line=True)
    ready = ("RAW_CAT_READY_" + token).encode()
    terminal.send(b"echo " + ready + b"; cat\r")
    terminal.wait(ready, timeout=30, line=True)
    streamed = ("RAW_TYPED_LINE_" + token).encode()
    offset = len(terminal.capture)
    terminal.send(streamed + b"\r")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        lines = bytes(terminal.capture[offset:]).replace(b"\r", b"").split(b"\n")[:-1]
        if lines.count(streamed) >= 2:
            break
        if terminal.process.poll() is not None:
            raise RuntimeError("foreground console exited during original raw cat")
        terminal.pump()
    else:
        raise TimeoutError("original Plan9 cat did not stream actual CR-terminated terminal input")
    offset = len(terminal.capture)
    terminal.send(b"\x7f")  # Original Plan9 DEL interrupt, not Linux Ctrl+C.
    deadline = time.monotonic() + 30
    while b"% " not in bytes(terminal.capture[offset:]):
        if time.monotonic() >= deadline or terminal.process.poll() is not None:
            raise TimeoutError("original console did not return after DEL")
        terminal.pump()
    marker = ("RAW_AFTER_DEL_" + token).encode()
    terminal.send(b"echo " + marker + b"\r")
    terminal.wait(marker, timeout=30, line=True)
    terminal.send(b"\x1e0")
    terminal.wait(b"[O-core console: Linux", timeout=30)
    marker = ("LINUX_CR_RETURN_" + token).encode()
    terminal.send(b"echo " + marker + b"\r")
    terminal.wait(marker, timeout=30, line=True)


def verify(state: Path, build: Path, *, watchdog=False, raw_console=False):
    inputs = preflight(state, build)
    state, build = Path(inputs["state"]), Path(inputs["build"])
    output = Path(tempfile.mkdtemp(prefix="client-acceptance-", dir=state))
    receipt = output / "result.json"
    sources = {name: hash_file(ROOT / name) for name in
               ("scripts/verify_okernel_unified_client.py", "scripts/verify_okernel_unified_console.py",
                "scripts/okernel_unified_world.py", "scripts/okernel_package_domain.py",
                "scripts/okernel_native_volume.py", "ocore/guest/linux/package-domain/p9",
                "ocore/guest/linux/package-domain/p9-controller", "ocore/guest/linux/package-domain/p9-history",
                "ocore/guest/linux/package-domain/p9-install",
                "ocore/guest/plan9/unified/protocol.py")}
    result = {"schema": "ostadix.unified-foreground-client/v1", "ok": False, "started": time.time(),
              "scope": "automated keystrokes through a real foreground PTY: original Linux p9 client and concurrent original9front commands/compiler beneath one native O-core monitor; not a human typing claim",
              "inputs": inputs, "source_sha256": sources, "watchdog": watchdog,
              "raw_console": raw_console, "sessions": [], "checks": []}
    result["source_artifacts"] = {}
    for source, expected in sources.items():
        target = output / "sources" / source
        target.parent.mkdir(parents=True, exist_ok=True)
        data = (ROOT / source).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError("source changed while capturing acceptance closure")
        target.write_bytes(data)
        target.chmod(0o400)
        result["source_artifacts"][source] = {"path": str(target.relative_to(output)), "bytes": len(data), "sha256": expected}
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    token = secrets.token_hex(10)
    name = "foreground-" + token
    workspace, native = "/n/okernel/work/" + name, "/work/" + name
    helper = "/tmp/p9-foreground-" + token + ".py"
    program = "original-compiled-" + token
    installed_name = "original-installed-" + token
    installed_native = "/packages/plan9/bin/" + installed_name
    compiled_marker, status_marker = "ORIGINAL_COMPILED_" + token, "NATIVE_STATUS_" + token
    source = ('#include <u.h>\n#include <libc.h>\nvoid main(int argc,char**argv){'
              'if(argc>1 && strcmp(argv[1],"fail")==0)exits("' + status_marker + '");'
              'print("' + compiled_marker + '\\n");exits(nil);}\n').encode()
    binary_printf = r"\000\377\015\012\003\021\023\177ABC"
    expected_binary = b"\0\xff\r\n\x03\x11\x13\x7fABC"
    saved_marker = "SAVED_FOREGROUND_" + token
    terminal = None
    binary = None
    try:
        for phase in range(2):
            directory = output / ("first" if phase == 0 else "restart")
            directory.mkdir()
            terminal = Terminal(state, build, directory)
            terminal.wait(b"Linux and original Plan 9 share this workspace.", timeout=240)
            session = Path((state / "latest-unified-session").read_text().strip())
            result["sessions"].append(str(session))
            installed = (("/usr/local/bin/p9", "ocore/guest/linux/package-domain/p9"),
                         ("/usr/local/libexec/p9-controller", "ocore/guest/linux/package-domain/p9-controller"),
                         ("/usr/local/libexec/p9-history", "ocore/guest/linux/package-domain/p9-history"),
                         ("/usr/local/bin/p9-install", "ocore/guest/linux/package-domain/p9-install"),
                         ("/usr/lib/okernel/p9_protocol.py", "ocore/guest/plan9/unified/protocol.py"))
            checked_command(terminal, " && ".join('test "$(sha256sum ' + path + " | cut -d ' ' -f1)\" = " + sources[source]
                                                   for path, source in installed))
            checked_command(terminal, "mkdir -p " + shlex.quote(workspace) + "; cd " + shlex.quote(workspace))
            # A subshell cannot change the interactive shell's cwd.
            typed(terminal, "cd " + shlex.quote(workspace))
            upload(terminal, helper, GUEST_HELPER.encode())
            if phase == 0:
                echo = "ORIGINAL_BY_NAME_" + token
                collect(terminal, helper, workspace, "name", "p9 echo " + echo)
                terminal.wait(echo.encode(), line=True)
                pipeline = ("printf '" + binary_printf + "' > binary.in; printf '" + binary_printf
                            + "' | p9 cat > binary.out")
                collect(terminal, helper, workspace, "binary", pipeline)
                checked_command(terminal, "cmp binary.in binary.out && test \"$(sha256sum binary.out | cut -d ' ' -f1)\" = "
                                + hashlib.sha256(expected_binary).hexdigest())
                collect(terminal, helper, workspace, "cwd", "p9 pwd > plan9.pwd")
                checked_command(terminal, "test \"$(cat plan9.pwd)\" = " + shlex.quote("/n/work/" + name))
                upload(terminal, workspace + "/" + program + ".c", source)
                collect(terminal, helper, workspace, "compile", "p9 7c -o " + program + ".7 " + program + ".c", timeout=180)
                collect(terminal, helper, workspace, "link", "p9 7l -o " + program + " " + program + ".7", timeout=180)
                collect(terminal, helper, workspace, "execute", "p9 ./" + program)
                terminal.wait(compiled_marker.encode(), line=True)
                checked_command(terminal, "p9-install ./" + program + " " + installed_name
                                + " && cmp " + program + " /n/okernel" + installed_native
                                + ' && test "$(stat -c %a /n/okernel' + installed_native + ')" = 555')
                collect(terminal, helper, workspace, "installed", "p9 " + installed_name)
                collect(terminal, helper, workspace, "status", "p9 --status-file status.raw ./" + program + " fail",
                        expected=1, argument=status_marker)
                checked_command(terminal, "printf '%s\\n' " + saved_marker + " > saved.txt; echo $$ > linux-shell.pid; awk '{print $22}' /proc/$$/stat > linux-shell.start")
                prefix = "python3 " + shlex.quote(helper) + " " + shlex.quote(workspace)
                checked_command(terminal, prefix + " begin cancel")
                stream_marker = "STREAM_READY_" + token
                done = ("P9_ASSERT_cancel_" + name).encode()
                invocation = ("p9 --timeout-ms 180000 --status-file cancel.status rc -I -c "
                              + shlex.quote("echo " + stream_marker + "; sleep 120")
                              + "; p9_accept_rc=$?; " + prefix + ' collect cancel "$p9_accept_rc" 130')
                started = time.monotonic()
                offset = len(terminal.capture)
                typed(terminal, invocation)
                terminal.wait(stream_marker.encode(), timeout=30, line=True)
                result["stream_latency_seconds"] = time.monotonic() - started
                if done in bytes(terminal.capture[offset:]):
                    raise RuntimeError("stream marker was not observed before command completion")
                terminal.send(b"\x03")
                terminal.wait(done, timeout=180, line=True)
                checked_command(terminal, "test \"$(cat linux-shell.pid)\" = $$ && test \"$(awk '{print $22}' /proc/$$/stat)\" = \"$(cat linux-shell.start)\"")
                collect(terminal, helper, workspace, "fresh", "p9 echo FRESH_AFTER_CTRL_C_" + token)
                result["checks"].extend(["typed p9 NAME executes original echo; printf binary pipe through original cat preserves exact hash and bytes",
                                          "actual shared cwd maps to original Plan9 pwd; original7c/7l compile and p9 executes an original-ABI binary",
                                          "p9-install publishes the exact user-compiled original Plan9 bytes mode0555; p9 resolves and executes the new installed name",
                                          "nonempty exact native status is preserved while the Linux CLI returns generic1",
                                          "streamed output precedes real Ctrl+C; CLI130 is accepted only with bound native replacement/private UART ACK; Linux shell PID/start time survives"])
                if watchdog:
                    watchdog_gate(terminal, helper, workspace, token)
                    checked_command(terminal, "test \"$(cat linux-shell.pid)\" = $$ && test \"$(awk '{print $22}' /proc/$$/stat)\" = \"$(cat linux-shell.start)\"")
                if raw_console:
                    raw_console_gate(terminal, token)
                    collect(terminal, helper, workspace, "raw-return", "p9 echo CLIENT_AFTER_RAW_CONSOLE_" + token)
                    result["checks"].append("native mux selects original console; real CR executes both shells, original cat streams typed input, DEL interrupts it, and Linux p9 service remains usable after switching back")
            else:
                checked_command(terminal, "test \"$(cat saved.txt)\" = " + saved_marker)
                collect(terminal, helper, workspace, "restart", "p9 " + installed_name)
                terminal.wait(compiled_marker.encode(), line=True)
                result["checks"].append("a second actual two-kernel boot recovers the saved file and executes the installed NAME with identical original compiled bytes through fresh p9 client identities")
            terminal.finish()  # Exactly one explicit Ctrl+] save per real boot.
            record, volume = read_saved_session(state, session)
            current_binary = volume.get(native + "/" + program)
            if volume.get(installed_native) != current_binary:
                raise RuntimeError("installed original program differs from the actual7l output")
            installation_evidence = json.loads(volume.get(native + "/evidence-" + ("installed" if phase == 0 else "restart") + ".json"))
            if installation_evidence.get("argv") != ["/n" + installed_native]:
                raise RuntimeError("installed NAME did not resolve to the shared original executable")
            if phase == 0:
                binary = current_binary
                cancellation = json.loads(volume.get(native + "/evidence-cancel.json"))
                recovery = validate_recovery(record, cancellation)
                (output / "typed-cancellation.json").write_text(json.dumps(cancellation, indent=2) + "\n")
                result["native_recovery"] = recovery
                if watchdog:
                    unknown = json.loads(volume.get(native + "/evidence-unknown.json"))
                    unknown_recovery = validate_recovery(record, unknown)
                    if (unknown["private_ack"].get("outcome") != "unknown"
                            or unknown_recovery.get("unknown") is None or unknown_recovery.get("reset") is not None
                            or not unknown.get("recovery_invocation_not_submitted")):
                        raise RuntimeError("resident-loss recovery invented a completion or replayed unacknowledged work")
                    result["watchdog_recovery"] = unknown_recovery
                    (output / "typed-unknown.json").write_text(json.dumps(unknown, indent=2) + "\n")
                    if volume.get(native + "/watchdog-effect") != ("EXPLICIT_RETRY_" + token + "\n").encode():
                        raise RuntimeError("the explicit post-recovery retry did not execute")
                    result["checks"].append("only the exact current original resident is killed; CLI125 retains unknown pending, native UART triggers Plan9-only replacement, first recovery invocation submits nothing, subsequent explicit retry executes")
                if volume.get(native + "/binary.out") != expected_binary:
                    raise RuntimeError("saved binary pipe output differs from the exact oracle")
                if volume.get(native + "/" + program + ".c") != source:
                    raise RuntimeError("the saved original compiler input differs from typed source")
                for step in ("name", "binary", "cwd", "compile", "link", "execute", "installed", "status", "fresh"):
                    data = volume.get(native + "/evidence-" + step + ".json")
                    (output / ("typed-" + step + ".json")).write_bytes(data)
            elif current_binary != binary:
                raise RuntimeError("saved original executable bytes changed across actual restart")
            if volume.get(native + "/saved.txt") != (saved_marker + "\n").encode():
                raise RuntimeError("actual paired save lost the fresh typed file")
            result["checks"].append(("first" if phase == 0 else "restart") + ": one Ctrl+] publishes paired quiescent volumes and restores full foreground termios")
            terminal.close()
            terminal = None
        if sources != {name: hash_file(ROOT / name) for name in sources}:
            raise RuntimeError("client/PTY/controller sources changed during qualification")
        result.update(ok=True, finished=time.time(), workspace=workspace,
                      installed_name=installed_name, installed_native_path=installed_native,
                      compiled_sha256=hashlib.sha256(binary).hexdigest(), binary_pipe_sha256=hashlib.sha256(expected_binary).hexdigest())
        print("Unified foreground p9 client/compiler/stream/cancel/save/restart: PASS\nEvidence: " + str(receipt))
    except BaseException as error:
        result["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if terminal is not None:
            terminal.close()
        receipt.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--watchdog", action="store_true", help="also qualify unknown resident-service loss (separate optional scenario)")
    parser.add_argument("--raw-console", action="store_true", help="also exercise raw Plan9 console switching, CR and original DEL cancellation")
    args = parser.parse_args()
    try:
        verify(args.state.expanduser(), args.build.expanduser(), watchdog=args.watchdog, raw_console=args.raw_console)
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError) as error:
        print("Unified foreground client acceptance failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
