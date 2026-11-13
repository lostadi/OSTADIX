#!/usr/bin/env python3
"""Original Draft 0 M2 gate. Real qualification witness and offline fixture required.

No component/model result qualifies Linux reboot, the running store, APK, or fsck.
The gate uses a new private fork and never replays interrupted service work.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import shutil
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
FILE_BYTES = 64 * 1024 * 1024
WITNESS_CONTRACT = "native-store-v1"
FID_LIFETIME_NOTE = {
    "source": "ocore/guest/plan9/unified/p9cmdsrv.c",
    "known_confound": "The cancellation/deadline helper reads the cancel path every50ms; those ordinary lookups can create/clunk transient Plan9 fids.",
    "success_policy": "Exact full fid-tuple and wire identity checks remain strict; no recapture or retry after a mismatch.",
    "failure_scope": "A mismatch remains a failed gate and must be classified as isolation damage or ordinary fid lifetime; status/count/index alone may not reconstruct the full changed current set."
}
DB_ARGV = ["apk", "--no-network", "--simulate", "fix"]
APK_COMMIT_HOOK_TEMPLATE = b"""#!/bin/sh
set -eu
test "$1" = pre-commit || exit 0
printf '%s %s %s %s\\n' '@NONCE@' "$$" "$PPID" "$1" > '@RUN@/apk-hook'
while [ ! -e '@RUN@/release-apk' ]; do sleep 1; done
"""
HOOK_SHA256 = hashlib.sha256(APK_COMMIT_HOOK_TEMPLATE).hexdigest()

class GateError(ValueError):
    pass

def need(condition, message):
    if not condition:
        raise GateError(message)

def live_domain(value):
    # BLOCKED is a live WFI/wakeup state; work and counter evidence prove progress.
    state = value.get("state")
    return type(state) is int and state in (2, 3)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def identity(path):
    p = Path(path)
    need(p.is_file() and not p.is_symlink(), "regular evidence file required: " + str(p))
    return {"path": str(p.resolve()), "sha256": digest(p), "bytes": p.stat().st_size}

def tool_identity(path):
    """Bind an executable's invoked alias to its resolved regular binary."""
    invoked = Path(path).absolute()
    need(invoked.is_file(), "tool executable required: " + str(invoked))
    record = identity(invoked.resolve(strict=True))
    record["invoked_path"] = str(invoked)
    return record

def safe(value):
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, dict):
        return {k: safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe(v) for v in value]
    return value

def document(path):
    identity(path)
    value = json.loads(Path(path).read_text())
    need(isinstance(value, dict), "JSON object required")
    return value

def guest_path(value):
    need(isinstance(value, str) and value.startswith("/") and str(PurePosixPath(value)) == value
         and ".." not in PurePosixPath(value).parts and not re.search(r"[\x00-\x20\x7f]", value),
         "unsafe guest fixture path")
    return value

def hold_linux_fid_command(path):
    return ": > " + shlex.quote(guest_path(path)) + "; exec 9<>" + shlex.quote(path) + "; test -e /proc/$$/fd/9"

def validate_fixture(value):
    """Fixture is preseeded on the private package disk, never fetched by the gate."""
    need(value.get("schema") == "ostadix.o10-linux-apk-fixture/v1", "declared offline APK fixture required")
    for key in ("package", "version"):
        need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.-]*", value.get(key, "")) is not None,
             "invalid declared APK " + key)
    directory = guest_path(value.get("directory"))
    keys = guest_path(value.get("keys_directory"))
    target = guest_path(value.get("target_apk"))
    need(directory.startswith("/opt/") and keys.startswith(directory + "/") and target.startswith(directory + "/"),
         "fixture must remain in its own preseeded /opt subtree")
    need(value.get("commit_hook_template_sha256") == HOOK_SHA256 and
         value.get("commit_hook_contract") == "apk3-pre-commit-v1", "exact APK3 pre-commit hook contract required")
    need(isinstance(value.get("apk_version_stdout"), str) and value["apk_version_stdout"].strip(),
         "exact apk --version output required")
    seen = set()
    for group in ("apks", "keys"):
        rows = value.get(group)
        need(isinstance(rows, list) and rows, "offline archive and signing-key closure required")
        for row in rows:
            name = guest_path(row.get("path"))
            need(name.startswith((keys if group == "keys" else directory) + "/") and name not in seen,
                 "escaped or duplicate fixture member")
            need(re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")) is not None, "fixture digest missing")
            if group == "apks":
                need(name.endswith(".apk"), "APK archive required")
            seen.add(name)
    need(target in {r["path"] for r in value["apks"]}, "target outside declared APK closure")
    return value

def wire(value):
    try:
        data = bytes.fromhex(value)
    except (ValueError, TypeError) as error:
        raise GateError("raw 9P frame required") from error
    need(7 <= len(data) <= 8192 and struct.unpack_from("<I", data)[0] == len(data), "invalid 9P frame length")
    return data, data[4], struct.unpack_from("<H", data, 5)[0]

def stat_exchange(row, stale=False):
    request, kind, tag = wire(row.get("request_hex"))
    reply, rkind, rtag = wire(row.get("reply_hex"))
    need(kind == 124 and len(request) == 11 and struct.unpack_from("<I", request, 7)[0] == row.get("fid"),
         "native witness did not Tstat its recorded fid")
    need(tag == rtag, "9P reply tag mismatch")
    if stale:
        need(rkind == 107 and len(reply) >= 13, "actual old-session Rerror required")
        length = struct.unpack_from("<H", reply, 7)[0]
        need(len(reply) == length + 13 and struct.unpack_from("<I", reply, length + 9)[0] == 116,
             "numeric 9P2000.u ESTALE116 required")
    else:
        need(rkind == 125 and len(reply) >= 58 and struct.unpack_from("<H", reply, 7)[0] == len(reply)-9,
             "complete actual Rstat required")
        payload = reply[9:]
        need(struct.unpack_from("<H", payload)[0] == len(payload)-2, "inner stat length mismatch")
        position = 41
        for _ in range(4):
            need(position+2 <= len(payload), "truncated stat string")
            length = struct.unpack_from("<H", payload, position)[0]
            position += 2+length
            need(position <= len(payload), "truncated stat string payload")
        if position != len(payload):
            need(position+14 <= len(payload), "truncated .u stat")
            length = struct.unpack_from("<H", payload, position)[0]
            need(position+14+length == len(payload), "invalid .u stat extension")
        return reply[17:18]+reply[22:30]

def validate_witness(value, action, before=None):
    """All native-selected fids; caller never nominates any authority."""
    need(isinstance(value, dict) and value.get("schema") == "ostadix.o10-linux-store-witness/v1"
         and value.get("origin") == "running-native-store" and value.get("action") == action
         and value.get("capture_scope") == "all-transport-owned-fids",
         "complete actual qualification store witness required")
    need(type(value.get("sequence")) is int and value["sequence"] > 0, "native witness sequence missing")
    need(action in ("capture", "check"), "unsupported native witness action")
    linux, plan9 = value.get("linux", {}), value.get("plan9", {})
    total = 0
    for role, row, grant in (("linux", linux, 1), ("plan9", plan9, 4)):
        need(type(row.get("session")) is int and 0 < row["session"] < 1 << 64
             and row.get("grant") == grant, "real transport-owned session missing")
        need(type(row.get("transport_generation")) is int and row["transport_generation"] > 0,
             "real transport generation missing")
        fids = row.get("fids")
        need(isinstance(fids, list) and fids, "all " + role + " fid tuples required")
        for fid in fids:
            need(isinstance(fid, dict) and set(fid) == {"fid", "object_generation", "mode"}
                 and all(type(fid[k]) is int and 0 <= fid[k] < 1 << 64 for k in fid)
                 and fid["fid"] < 1 << 32 and fid["object_generation"] > 0,
                 "fid/object-generation/mode tuple invalid")
        numbers = [f["fid"] for f in fids]
        need(numbers == sorted(set(numbers)), "fid tuples not unique and ordered")
        exchanges = row.get("exchanges", [])
        need(isinstance(exchanges, list) and len(exchanges) == len(fids)
             and {r.get("fid") for r in exchanges} == set(numbers), "all fid wire observations required")
        for exchange in exchanges:
            stat_exchange(exchange, stale=role == "linux" and action == "check")
        total += len(fids)
        if before is not None:
            old = before[role]
            need(row["session"] == old["session"] and row["transport_generation"] == old["transport_generation"]
                 and fids == old["fids"], role + " retained session/generation/fid tuples changed")
            if role == "plan9":
                prior = {r["fid"]: r for r in old["exchanges"]}
                need(all(stat_exchange(r) == stat_exchange(prior[r["fid"]]) for r in exchanges),
                     "Plan9 fid now names another wire qid")
    need(total <= 512, "native fid snapshot exceeds complete store capacity")
    need(linux["session"] != plan9["session"], "native session identities aliased")
    if before is not None:
        need(value["sequence"] > before["sequence"], "stale witness observation sequence")
    return value

def durable_prefix_sha256(length):
    need(type(length) is int and 0 < length <= FILE_BYTES and length % 1048576 == 0,
         "known durable prefix must contain complete fsynced chunks")
    value=hashlib.sha256()
    for index in range(length//1048576):
        value.update(bytes([index+1])*1048576)
    return value.hexdigest()

def validate_database(value):
    info, check = value.get("info", {}), value.get("check", {})
    need(info.get("argv") == ["apk", "info", "-vv"] and info.get("returncode") == 0, "APK database did not open")
    need(check.get("argv") == DB_ARGV and check.get("returncode") == 0, "APK database check failed")
    text = "".join(base64.b64decode(check.get(k, ""), validate=True).decode()
                   for k in ("stdout_base64", "stderr_base64"))
    need(re.search(r"(?m)^OK:", text) is not None and
         re.search(r"(?i)installing|upgrading|downgrading|reinstalling|purging|error:|warning:", text) is None,
         "APK check proposed repair or did not report clean")

def clean_superblock(path):
    with Path(path).open("rb") as stream:
        stream.seek(1024)
        block = stream.read(1024)
    need(len(block) == 1024 and struct.unpack_from("<H", block, 56)[0] == 0xef53, "ext4 superblock missing")
    state, incompatible = struct.unpack_from("<H", block, 58)[0], struct.unpack_from("<I", block, 96)[0]
    need(state & 1 and not state & 2 and not incompatible & 4, "unclean ext4 copy or journal replay still required")
    return {"state": state, "incompatible_features": incompatible, "needs_recovery": False}

class Counter:
    def __init__(self, domain, path):
        self.domain, self.path = domain, path
        self.start = self.previous_poll = time.monotonic()
        self.data, self.entries, self.active = b"", [], False

    def poll(self, force=False):
        now = time.monotonic()
        need(now-self.start < 240, "counter qualification window exceeded")
        if self.active or (not force and now-self.previous_poll < .2):
            return
        self.active = True
        try:
            try:
                data = self.domain.native_volume().get(self.path)
            except FileNotFoundError:
                data = b""
            self.observe(data, now)
        finally:
            self.active = False

    def observe(self, data, now):
        need(data.startswith(self.data), "Plan9 counter lost prior bytes")
        lines = data.splitlines(keepends=True)
        partial = lines.pop() if lines and not lines[-1].endswith(b"\n") else b""
        need(all(line == (str(i)+"\n").encode() for i, line in enumerate(lines)) and
             (str(len(lines))+"\n").encode().startswith(partial), "counter append order invalid")
        for i in range(len(self.entries), len(lines)):
            self.entries.append({"counter": i, "earliest_host_seconds": self.previous_poll-self.start,
                                 "observed_host_seconds": now-self.start})
        self.data, self.previous_poll = data, now

    def result(self):
        need(len(self.entries) >= 3, "counter progress insufficient")
        pairs = list(zip(self.entries, self.entries[1:]))
        return {"path": self.path, "samples": self.entries, "bytes_hex": self.data.hex(),
                "largest_observed_gap_seconds": max(b["observed_host_seconds"]-a["observed_host_seconds"] for a,b in pairs),
                "largest_append_gap_upper_bound_seconds": max(b["observed_host_seconds"]-a["earliest_host_seconds"] for a,b in pairs),
                "timing_scope": "host monotonic observation brackets include host/QMP pauses; not exact guest timestamps"}

# Ordinary guest filesystem, process and original APK interfaces; no MMIO.
GUEST_HELPER = r"""
import base64,hashlib,json,os,pathlib,subprocess,sys,time
def emit(v):print("O10_M2_JSON "+base64.b64encode(json.dumps(v,sort_keys=True).encode()).decode(),flush=True)
def capture(argv):
 p=subprocess.run(argv,capture_output=True)
 return dict(argv=argv,returncode=p.returncode,stdout_base64=base64.b64encode(p.stdout).decode(),stderr_base64=base64.b64encode(p.stderr).decode())
def proc(pid):
 p=pathlib.Path("/proc")/str(pid);v=(p/"stat").read_text().rsplit(")",1)[1].split()
 return dict(pid=pid,ppid=int(v[1]),state=v[0],start=v[19],cmdline_base64=base64.b64encode((p/"cmdline").read_bytes()).decode())
def mount():
 r=[l.split() for l in pathlib.Path("/proc/mounts").read_text().splitlines() if l.split()[1]=="/"]
 assert len(r)==1 and r[0][0]=="/dev/vda" and r[0][2]=="ext4"
 return r[0]
mode,config_file=sys.argv[1:3];config_path=pathlib.Path(config_file)
assert config_path.is_file() and not config_path.is_symlink()
cfg=json.loads(config_path.read_text());assert isinstance(cfg,dict)
run=pathlib.Path(cfg["run"]);f=cfg["fixture"]
if mode=="prepare":
 assert not run.exists();run.mkdir(mode=0o700)
 v=subprocess.run(["apk","--version"],capture_output=True,check=True);assert v.stdout.decode()==f["apk_version_stdout"]
 for group in ("apks","keys"):
  for item in f[group]:
   p=pathlib.Path(item["path"]);assert p.is_file() and str(p.resolve())==str(p)
   assert hashlib.sha256(p.read_bytes()).hexdigest()==item["sha256"]
 assert {str(p) for p in pathlib.Path(f["keys_directory"]).iterdir()}=={r["path"] for r in f["keys"]}
 absence=capture(["apk","info","--installed",f["package"]])
 assert absence["returncode"]==1
 verification=capture(["apk","--no-network","--keys-dir",f["keys_directory"],"verify"]+[r["path"] for r in f["apks"]])
 if verification["returncode"]!=0:
  emit(dict(fixture_verified=False,verification=verification));sys.exit(0)
 assert "rw" in mount()[3].split(",")
 hook=pathlib.Path("/etc/apk/commit_hooks.d")/("o10-restart-"+cfg["nonce"])
 assert not hook.exists();hook.parent.mkdir(parents=True,exist_ok=True)
 body=base64.b64decode(cfg["commit_hook_base64"])
 hook.write_bytes(body);hook.chmod(0o755);os.sync()
 emit(dict(fixture_verified=True,apk_version=v.stdout.decode(),mount=mount(),verification=verification,package_absent=absence,
           hook_path=str(hook),hook_sha256=hashlib.sha256(body).hexdigest()))
elif mode=="writer":
 p=pathlib.Path(cfg["file"]);p.parent.mkdir();durable=hashlib.sha256()
 with p.open("xb") as stream:
  for directory in (p.parent.parent,p.parent):
   fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
   try:os.fsync(fd)
   finally:os.close(fd)
  for i in range(64):
   block=bytes([i+1])*1048576
   assert stream.write(block)==len(block)
   stream.flush();os.fsync(stream.fileno());durable.update(block)
   progress=dict(bytes=(i+1)*1048576,sha256=durable.hexdigest(),fsync_complete_monotonic_seconds=time.monotonic())
   temporary=run/"writer-progress.tmp";temporary.write_text(json.dumps(progress))
   os.replace(temporary,run/"writer-progress.json")
   time.sleep(2)
 (run/"writer-done").write_text("complete")
elif mode=="worker":
 env=dict(os.environ,O10_RESTART_DIR=str(run),O10_RESTART_NONCE=cfg["nonce"],PYTHONDONTWRITEBYTECODE="1")
 writer=subprocess.Popen([sys.executable,__file__,"writer",str(config_path)],stdout=(run/"writer.stdout").open("wb"),stderr=(run/"writer.stderr").open("wb"),env=env)
 argv=["apk","--no-network","--repositories-file","/dev/null","--keys-dir",f["keys_directory"],"add"]+[r["path"] for r in f["apks"]]
 apk=subprocess.Popen(argv,stdout=(run/"apk.stdout").open("wb"),stderr=(run/"apk.stderr").open("wb"),env=env)
 (run/"children.json").write_text(json.dumps(dict(writer=proc(writer.pid),apk=proc(apk.pid),apk_argv=argv)))
 while writer.poll() is None or apk.poll() is None:time.sleep(.2)
elif mode=="status":
 logs={}
 for name in ("apk.stdout","apk.stderr","writer.stdout","writer.stderr","worker.stdout","worker.stderr"):
  p=run/name;raw=p.read_bytes() if p.exists() else b"";assert len(raw)<=1048576
  logs[name+"_base64"]=base64.b64encode(raw).decode()
 if not (run/"children.json").exists():
  emit(dict(ready=False,logs=logs))
 else:
  children=json.loads((run/"children.json").read_text());failed=False
  for key in ("writer","apk"):
   try:
    current=proc(children[key]["pid"])
    assert current["start"]==children[key]["start"]
    failed=failed or current["state"]=="Z";children[key]=current
   except FileNotFoundError:failed=True
  if failed:emit(dict(ready=False,failed=True,children=children,logs=logs))
  elif not (run/"apk-hook").exists() or not (run/"writer-progress.json").exists():emit(dict(ready=False,logs=logs))
  else:
   nonce,pid,parent,stage=(run/"apk-hook").read_text().split();assert nonce==cfg["nonce"] and stage=="pre-commit"
   chain=[];current=proc(int(pid))
   for i in range(16):
    chain.append(current)
    if current["pid"]==children["apk"]["pid"]:break
    current=proc(current["ppid"])
   assert chain[-1]["pid"]==children["apk"]["pid"]
   progress=json.loads((run/"writer-progress.json").read_text())
   size=pathlib.Path(cfg["file"]).stat().st_size
   assert 0<progress["bytes"]<=size<67108864 and not (run/"writer-done").exists()
   children.update(ready=True,file_bytes=size,durable_prefix=progress,hook_process_chain=chain,
                   nonce=nonce,apk_stage=stage,logs=logs,observed_monotonic_seconds=time.monotonic())
   emit(children)
elif mode=="cleanup-hook":
 hook=pathlib.Path("/etc/apk/commit_hooks.d")/("o10-restart-"+cfg["nonce"])
 existed=hook.exists()
 if existed:
  assert hook.read_bytes()==base64.b64decode(cfg["commit_hook_base64"])
  hook.unlink()
 emit(dict(removed_owned_hook=existed,hook_path=str(hook)))
elif mode=="database":
 emit(dict(info=capture(["apk","info","-vv"]),check=capture(["apk","--no-network","--simulate","fix"])))
elif mode=="recovered-file":
 p=pathlib.Path(cfg["file"]);size=p.stat().st_size;prefix=cfg["durable_prefix"]
 assert 0<prefix["bytes"]<=size<=67108864
 durable=hashlib.sha256();tail=hashlib.sha256()
 with p.open("rb") as stream:
  offset=0
  while offset<prefix["bytes"]:
   raw=stream.read(min(1048576,prefix["bytes"]-offset))
   assert raw and raw==bytes([offset//1048576+1])*len(raw)
   durable.update(raw);offset+=len(raw)
  assert durable.hexdigest()==prefix["sha256"]
  while True:
   raw=stream.read(1048576)
   if not raw:break
   tail.update(raw)
 emit(dict(bytes=size,durable_prefix_bytes=prefix["bytes"],durable_prefix_sha256=durable.hexdigest(),
           unknown_tail_bytes=size-prefix["bytes"],unknown_tail_sha256=tail.hexdigest(),
           file_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
           completion="unknown interrupted tail; only observed fsynced prefix validated",work_not_replayed=True))
elif mode=="quiesce":
 before=mount();assert "rw" in before[3].split(",");os.sync()
 result=capture(["mount","-o","remount,ro","/"]);assert result["returncode"]==0
 after=mount();assert "ro" in after[3].split(",") and "rw" not in after[3].split(",")
 emit(dict(before=before,remount=result,after=after))
else:raise ValueError("unknown fixed gate action")
"""

def load_runtime():
    if str(ROOT/"scripts") not in sys.path:
        sys.path.insert(0, str(ROOT/"scripts"))
    return tuple(importlib.import_module(n) for n in
                 ("okernel_unified_world", "fork_okernel_state", "verify_okernel_unified_provider"))

def preflight(seed, build, fixture, runner, fsck):
    need(Path(seed).is_dir() and not Path(seed).is_symlink(), "explicit seed directory required")
    p = document(Path(build)/"monitor-profile.json")
    need(p.get("o10_qualification") is True, "explicit qualification build required")
    need(p.get("linux_recovery", {}).get("namespace_version") == "9P2000.u"
         and p.get("plan9_recovery") and p.get("plan9_command_provider"), "immutable Linux/.u/Plan9 recovery profile required")
    need(p.get("o10_linux_restart_witness") == WITNESS_CONTRACT
         and callable(getattr(runner.UnifiedDomain, "linux_restart_witness", None)),
         "actual monitor-owned stale-fid wire witness unavailable")
    runner.validate_profile(p)
    artifacts = {n:Path(build)/v["path"] for n,v in p["artifacts"].items()}
    runner.validate_linux_recovery_inputs(artifacts)
    for name, row in p["artifacts"].items():
        need(digest(artifacts[name]) == row["sha256"], "build artifact drift: "+name)
    for name, expected in p["source_sha256"].items():
        need(digest(ROOT/name) == expected, "compiled source drift: "+name)
    need(fsck and Path(fsck).is_file(), "host fsck.ext4 required")
    validate_fixture(fixture)
    return p

def upload_binary(domain, path, data):
    """Bound console lines; publish exact bytes once and verify their digest."""
    path = guest_path(path)
    encoded = base64.b64encode(data).decode()
    temporary = path + ".o10-base64"
    domain.command(": > " + shlex.quote(temporary))
    for offset in range(0, len(encoded), 512):
        domain.command("printf %s " + shlex.quote(encoded[offset:offset+512]) + " >> " + shlex.quote(temporary))
    expected = hashlib.sha256(data).hexdigest()
    domain.command("base64 -d " + shlex.quote(temporary) + " > " + shlex.quote(path) +
                   " && rm " + shlex.quote(temporary) + " && test \"$(wc -c < " + shlex.quote(path) +
                   ")\" -eq " + str(len(data)) + " && test \"$(sha256sum " + shlex.quote(path) +
                   " | cut -d ' ' -f1)\" = " + expected)
    return {"path": path, "bytes": len(data), "sha256": expected}

def upload_guest_config(domain, config, evidence_path):
    """Publish configuration bytes once; only its short path crosses the console."""
    path = guest_path(config["run"] + ".json")
    data = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
    evidence_path = Path(evidence_path)
    need(not evidence_path.exists() and not evidence_path.is_symlink(),
         "new configuration evidence file required")
    evidence_path.write_bytes(data)
    record = upload_binary(domain, path, data)
    record["source"] = identity(evidence_path)
    return record

def launch_worker(domain, helper, config_path, run):
    """One fresh worker invocation, using the published configuration path."""
    helper, config_path, run = map(guest_path, (helper, config_path, run))
    # The runner appends a completion command after a semicolon; group the
    # asynchronous list so that suffix never forms the invalid sequence "& ;".
    domain.command("{ PYTHONDONTWRITEBYTECODE=1 python3 " + shlex.quote(helper) +
                   " worker " + shlex.quote(config_path) +
                   " > " + shlex.quote(run + "/worker.stdout") +
                   " 2> " + shlex.quote(run + "/worker.stderr") + " & }")

def plan9_counter_command(path):
    # Original rc compound-command redirection: the outer block owns one
    # append descriptor throughout the complete loop, including its sleeps.
    # Pinned rc syn.y grammar: cmd : brace epilog; epilog : redir epilog.
    path = guest_path(path)
    need(path.startswith("/services/plan9/"), "counter must use the surviving Plan9 service subtree")
    return "{ for(i in " + " ".join(str(i) for i in range(280)) + ") { echo $i; sleep 1 } } >> /n" + path

def namespace_copy_command(source, destination, data):
    source, destination = map(guest_path, (source, destination))
    expected = hashlib.sha256(data).hexdigest()
    return ("cat " + shlex.quote(source) + " > " + shlex.quote(destination) +
            " && test \"$(wc -c < " + shlex.quote(destination) + ")\" -eq " + str(len(data)) +
            " && test \"$(sha256sum " + shlex.quote(destination) +
            " | cut -d ' ' -f1)\" = " + expected)

def publish_counter(domain, protocol, path, *, record):
    service = dict(domain.service)
    request_id = secrets.token_hex(16)
    request = protocol.encode_request(service["generation"], service["instance"], request_id,
                                      ["/arm64/bin/rc", "-I", "-c", plan9_counter_command(path)],
                                      cwd="/n/work", stdin=b"", timeout_ms=300000)
    paths = protocol.request_paths("/n/okernel/services/plan9", service["generation"],
                                   service["instance"], request_id)
    marker = protocol.submit_marker(request)
    invocation = dict(request=request, submit_marker=marker, paths=paths, service=service,
                      id=request_id, phase="prepared", publication=[])
    # Keep exact intended bytes and the last confirmed phase even if a command
    # has an unknown outcome. No copy, submission, or service work is retried.
    record["plan9_counter_request"] = invocation
    domain.command("mkdir " + shlex.quote(paths["request"].rsplit("/",1)[0]))
    invocation["phase"] = "directory-created"
    for phase, data, destination in (("request", request, paths["request"]),
                                     ("submit", marker, paths["submit"] + ".staged")):
        staging = upload_binary(domain, "/run/o10-m2-counter-" + request_id + "." + phase, data)
        command = namespace_copy_command(staging["path"], destination, data)
        invocation["publication"].append(dict(phase=phase, staging=staging, destination=destination,
                                               bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                               command=command))
        invocation["phase"] = phase + "-publication-pending"
        domain.command(command)
        invocation["phase"] = phase + "-published"
    invocation["submit_command"] = "mv " + shlex.quote(paths["submit"] + ".staged") + " " + shlex.quote(paths["submit"])
    invocation["phase"] = "submission-pending"
    domain.command(invocation["submit_command"])
    invocation["phase"] = "submitted"
    return invocation

def trace(domain, output, record, protocol=None):
    original_command, original_exchange = domain.command, domain.o10_exchange
    record["guest_commands"], record["o10_exchanges"] = [], []
    def command(text, timeout=None):
        before = len(domain.capture)
        row = dict(command=text, started=time.time(), completion="unknown", returncode=None)
        record["guest_commands"].append(row)
        index = len(record["guest_commands"])
        try:
            original_command(text, timeout=timeout)
            row.update(completion="observed", returncode=0)
        except BaseException as error:
            row["error"] = type(error).__name__+": "+str(error)
            raise
        finally:
            path = output/("command-%04d.console"%index)
            path.write_bytes(bytes(domain.capture[before:]))
            row.update(finished=time.time(), combined_console=identity(path))
    def exchange(frame, *, bootstrap=None):
        row = dict(request_hex=frame.hex(), started=time.time(), completion="unknown")
        record["o10_exchanges"].append(row)
        try:
            reply = original_exchange(frame, bootstrap=bootstrap)
            need(protocol is not None, "raw O10 reply decoder required")
            domain.stopped()
            try:
                offset=domain.o10_profile["completion"]-0x40000000
                header=os.pread(domain.ram,4,offset)
                need(len(header)==4,"raw O10 reply header missing")
                size=struct.unpack("<I",header)[0]
                need(7<=size<=512,"raw O10 reply size invalid")
                raw=os.pread(domain.ram,size,offset)
                need(protocol.decode(raw)==reply,"raw O10 reply changed after exchange")
                row.update(reply=safe(reply),reply_hex=raw.hex(),completion="observed")
            finally:
                domain.qmp.execute("cont")
            return reply
        finally:
            row["finished"] = time.time()
    domain.command, domain.o10_exchange = command, exchange

def guest_json(domain, helper, config_path, action):
    helper, config_path = map(guest_path, (helper, config_path))
    need(action in ("database", "prepare", "status", "cleanup-hook", "recovered-file", "quiesce"),
         "unsupported fixed guest observation")
    before = len(domain.capture)
    domain.command("PYTHONDONTWRITEBYTECODE=1 python3 "+shlex.quote(helper)+" "+action+" "+shlex.quote(config_path))
    rows = [l[12:] for l in bytes(domain.capture[before:]).replace(b"\r\n",b"\n").splitlines() if l.startswith(b"O10_M2_JSON ")]
    need(len(rows)==1, "one complete typed guest result required")
    return json.loads(base64.b64decode(rows[0],validate=True))

def verify(*, seed, build, fixture_path, output, mcp_release, qemu="qemu-system-aarch64", timeout=180):
    output = Path(output).absolute()
    need(not output.exists() and not output.is_symlink(), "new private evidence directory required")
    output.mkdir(parents=True)
    record = dict(schema="ostadix.o10-linux-restart-gate/v1", milestone="M2",gate_id="verify_o10_linux_restart",
                  gate_passed=False,milestone_qualified=False,started=time.time(),mcp_release=mcp_release,skips=[],
                  scope="Original Linux/Plan9 AArch64 QEMU component gate only; full aligned M2 regressions remain required",
                  unknown_work_policy="Interrupted file/APK work is never automatically replayed",
                  apk_interruption_scope="APK3 pre-commit hook before package filesystem changes; not arbitrary transaction crash consistency",
                  plan9_fid_lifetime_confound=FID_LIFETIME_NOTE,
                  apk_documentation="https://raw.githubusercontent.com/alpinelinux/apk-tools/v3.0.8/doc/apk.8.scd")
    domain = None
    try:
        fixture = validate_fixture(document(fixture_path))
        runner,fork,provider = load_runtime()
        fsck = shutil.which("fsck.ext4")
        profile = preflight(seed,build,fixture,runner,fsck)
        revision = subprocess.check_output(["git","-C",str(ROOT),"rev-parse","HEAD"],text=True).strip()
        need(revision==mcp_release,"source/MCP revision mismatch")
        names = set(profile["source_sha256"]) | {"scripts/verify_o10_linux_restart.py","tests/test_o10_linux_restart.py",
                "scripts/okernel_unified_world.py","scripts/fork_okernel_state.py","scripts/verify_okernel_unified_provider.py",
                "ocore/guest/plan9/unified/protocol.py","ocore/guest/plan9/unified/p9cmdsrv.c"}
        record.update(source_revision=revision,build=identity(Path(build)/"monitor-profile.json"),
                      fixture=identity(fixture_path),fsck=tool_identity(fsck),
                      source_sha256={n:digest(ROOT/n) for n in sorted(names)},source_artifacts={},
                      seed_head_before=identity(Path(seed)/"head.json"))
        for name, expected in record["source_sha256"].items():
            p=output/"sources"/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/name).read_bytes())
            need(digest(p)==expected,"source drift during capture")
            record["source_artifacts"][name]=identity(p)
        state=output/"state";record["fork"]=fork.fork(Path(seed),state)
        need(record["fork"].get("ok") is True and record["fork"].get("source_head_changed_during_copy") is False,
             "verified private fork required")
        domain=runner.UnifiedDomain(state,Path(build),qemu,timeout=timeout)
        record["guest_session"]=str(domain.session)
        record["qemu_argv"]=domain.record.get("argv")
        trace(domain,output,record,runner.o10)
        domain.ready();domain.o10_claim()
        domain.control_active=True
        old_linux=domain.o10_call("Tstat",dom=domain.o10_linux)
        old_plan9=domain.o10_call("Tstat",dom=domain.o10_plan9)
        need(live_domain(old_linux) and live_domain(old_plan9),"two live original guests required")
        service=dict(domain.service);token=secrets.token_hex(12)
        helper="/run/o10-m2-"+token+".py"
        config=dict(run="/run/o10-m2-"+token,nonce=token,file="/work/o10-m2-"+token+"/file64MiB",fixture=fixture)
        hook=APK_COMMIT_HOOK_TEMPLATE.replace(b"@NONCE@",token.encode()).replace(b"@RUN@",config["run"].encode())
        config["commit_hook_base64"]=base64.b64encode(hook).decode()
        helper_source=output/"guest-helper.py";helper_source.write_text(GUEST_HELPER)
        helper_upload=upload_binary(domain,helper,GUEST_HELPER.encode())
        helper_upload.update(source=identity(helper_source),phase="initial")
        record["guest_helper_uploads"]=[helper_upload]
        record["guest_helper_sha256"]=helper_upload["sha256"]
        config_upload=upload_guest_config(domain,config,output/"guest-config-initial.json")
        record["guest_configuration_uploads"]=[config_upload]
        config_path=config_upload["path"]
        record["apk_database_before"]=guest_json(domain,helper,config_path,"database")
        validate_database(record["apk_database_before"])
        record["guest_prerequisites"]=guest_json(domain,helper,config_path,"prepare")
        need(record["guest_prerequisites"].get("fixture_verified") is True, "signed offline APK verification failed")
        path="/services/plan9/g"+service["generation"]+"/s"+service["instance"]+"/m2-counter-"+token
        invocation=publish_counter(domain,runner.protocol,path,record=record)
        record["plan9_counter_request"]=safe(invocation)
        counter=Counter(domain,path);original_pump=domain.pump
        def pump(duration=.1):
            original_pump(duration);counter.poll()
        domain.pump=pump
        while len(counter.entries)<3:domain.pump(.05)
        held="/n/okernel/work/o10-held-"+token
        domain.command(hold_linux_fid_command(held))
        before=validate_witness(domain.linux_restart_witness("capture"),"capture")
        record["witness_before"]=before
        launch_worker(domain,helper,config_path,config["run"])
        deadline=time.monotonic()+100
        while True:
            status=guest_json(domain,helper,config_path,"status")
            record["latest_workload_status"]=status
            need(status.get("failed") is not True, "declared workload exited before fault")
            if status.get("ready") is True:break
            need(time.monotonic()<deadline,"actual APK3 pre-commit hook/file writer did not overlap")
            domain.pump(.2)
        need(status["nonce"]==token and 0<status["file_bytes"]<FILE_BYTES,"partway workloads missing")
        prefix=status.get("durable_prefix",{})
        need(prefix.get("bytes",FILE_BYTES)<FILE_BYTES and prefix["bytes"]<=status["file_bytes"]
             and prefix.get("sha256")==durable_prefix_sha256(prefix.get("bytes")),
             "actual fsync completion witness for nonzero durable prefix required")
        config["durable_prefix"]=dict(prefix)
        record["interrupted_workload"]=status
        record["linux_fault"]=domain.o10_call("Tinject",dom=domain.o10_linux,fault=1)
        need(domain.o10_call("Tstat",dom=domain.o10_linux)["state"]==4,"Linux fault not observed")
        record["witness_faulted"]=validate_witness(domain.linux_restart_witness("check"),"check",before)
        count=len(counter.entries)
        while len(counter.entries)<=count:domain.pump(.05)
        domain.control_active=False
        domain.recover_linux()
        domain.control_active=True
        linux=domain.o10_call("Tstat",dom=domain.o10_linux);plan9=domain.o10_call("Tstat",dom=domain.o10_plan9)
        need(live_domain(linux) and linux["dom"]==old_linux["dom"]+(1<<32) and linux["inst"]!=old_linux["inst"],
             "fresh live Linux generation required")
        need(live_domain(plan9) and plan9["dom"]==old_plan9["dom"] and plan9["inst"]==old_plan9["inst"]
             and domain.service==service,"surviving Plan9 identity changed")
        record["witness_restored"]=validate_witness(domain.linux_restart_witness("check"),"check",before)
        need(record["witness_restored"]["sequence"]>record["witness_faulted"]["sequence"],"witness not fresh after restore")
        helper_upload=upload_binary(domain,helper,GUEST_HELPER.encode()) # Fresh observation helper; no worker/APK replay.
        helper_upload.update(source=identity(helper_source),phase="restored")
        record["guest_helper_uploads"].append(helper_upload)
        config_upload=upload_guest_config(domain,config,output/"guest-config-restored.json")
        record["guest_configuration_uploads"].append(config_upload)
        need(config_upload["path"]==config_path,"restored configuration path changed")
        record["hook_cleanup"]=guest_json(domain,helper,config_path,"cleanup-hook")
        record["apk_database_after"]=guest_json(domain,helper,config_path,"database");validate_database(record["apk_database_after"])
        record["recovered_file"]=guest_json(domain,helper,config_path,"recovered-file")
        record["quiesce"]=guest_json(domain,helper,config_path,"quiesce")
        snapshot=output/"replayed-readonly.ext4"
        domain.stopped()
        try:domain.qmp.execute("pmemsave",dict(val=0x70000000,size=runner.DISK_BYTES,filename=str(snapshot)))
        finally:domain.qmp.execute("cont")
        need(snapshot.stat().st_size==runner.DISK_BYTES,"package disk snapshot incomplete")
        record["package_snapshot"]=identity(snapshot);record["superblock"]=clean_superblock(snapshot)
        need(tool_identity(fsck)==record["fsck"],"filesystem checker changed before execution")
        argv=[fsck,"-n",str(snapshot)];checked=subprocess.run(argv,capture_output=True,timeout=90)
        for name,raw in (("fsck.stdout",checked.stdout),("fsck.stderr",checked.stderr)):(output/name).write_bytes(raw)
        record["fsck_result"]=dict(argv=argv,returncode=checked.returncode,stdout=identity(output/"fsck.stdout"),stderr=identity(output/"fsck.stderr"))
        need(tool_identity(fsck)==record["fsck"],"filesystem checker changed during execution")
        need(checked.returncode==0 and digest(snapshot)==record["package_snapshot"]["sha256"],"fsck -n failed or modified copy")
        counter.poll(force=True)
        count=len(counter.entries);deadline=time.monotonic()+5
        while len(counter.entries)<=count:
            need(time.monotonic()<deadline,"Plan9 counter stopped before end of gate")
            domain.pump(.05)
        record["witness_final"]=validate_witness(domain.linux_restart_witness("check"),"check",before)
        need(record["witness_final"]["sequence"]>record["witness_restored"]["sequence"],"final witness not fresh")
        record["plan9_counter"]=counter.result()
        final_linux=domain.o10_call("Tstat",dom=domain.o10_linux)
        final_plan9=domain.o10_call("Tstat",dom=domain.o10_plan9)
        need(live_domain(final_linux) and live_domain(final_plan9) and
             final_linux["dom"]==linux["dom"] and final_linux["inst"]==linux["inst"] and
             final_plan9["dom"]==plan9["dom"] and final_plan9["inst"]==plan9["inst"],
             "a restored/surviving domain stopped before gate completion")
        record["final_states"]=safe(dict(linux=final_linux,plan9=final_plan9))
        record["plan9_counter_request_completion"]="still active at gate completion; private VM teardown does not fabricate a provider completion"
        record["after"]=safe(dict(linux=linux,plan9=plan9))
        record["runner_linux_recoveries"]=safe(domain.record.get("linux_recoveries",[]))
        requests=[runner.o10.decode(bytes.fromhex(r["request_hex"])) for r in record["o10_exchanges"]]
        need(sum(r["type"]=="Tinject" for r in requests)==1 and
             sum(r["type"]=="Trestore" and r["dom"]==old_linux["dom"] for r in requests)==1,
             "Linux fault/restore was not executed exactly once")
        need(record["source_sha256"]=={n:digest(ROOT/n) for n in names},"gate/build source drift")
        need(identity(Path(seed)/"head.json")==record["seed_head_before"],"preserved seed head changed")
        record.update(gate_passed=True,source_unchanged=True)
    except BaseException as error:
        record["error"]=type(error).__name__+": "+str(error)
    finally:
        if domain is not None:
            try:domain.close()
            except BaseException as error:
                record.update(gate_passed=False,cleanup_error=type(error).__name__+": "+str(error))
        record["finished"]=time.time()
        (output/"result.json").write_text(json.dumps(safe(record),indent=2)+"\n")
    return record

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("seed-state","build","apk-fixture","output"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--mcp-release",required=True);parser.add_argument("--qemu",default="qemu-system-aarch64")
    parser.add_argument("--timeout",type=float,default=180);args=parser.parse_args()
    try:
        record=verify(seed=args.seed_state,build=args.build,fixture_path=args.apk_fixture,output=args.output,
                      mcp_release=args.mcp_release,qemu=args.qemu,timeout=args.timeout)
    except (ValueError,OSError) as error:
        print(str(error),file=sys.stderr);return 1
    print(json.dumps(dict(gate_passed=record["gate_passed"],milestone_qualified=False,result=str(args.output/"result.json"))))
    return 0 if record["gate_passed"] else 1

if __name__=="__main__":raise SystemExit(main())
