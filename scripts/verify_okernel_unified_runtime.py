#!/usr/bin/env python3
"""Qualify one explicitly forked frozen runtime through real tmux/PTY lifecycle.

All guest commands are automated terminal keystrokes. The verifier neither
constructs a runtime nor invokes a checkout runner. It starts, detaches,
reattaches, saves, restarts and saves the selected private fork. Python3.10+,
the recorded host shell/tmux and declared QEMU ELF interpreter remain external
host dependencies. A failed check preserves evidence and never replays work.
"""
from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import pty
import pwd
import re
import secrets
import selectors
import shlex
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time

R9_MONITOR = "dfea381c44dc59910d418303c0419d58d66780b93f475017508841db8dd65c0b"
R9_PROFILE = "d16d00728c1c52ba46c04485c9c0a564f4836ec9cd72a8e913622023eeabccba"
RUNTIME_SCHEMA = "ostadix.okernel-unified-runtime/v1"
SESSION_SCHEMA = "ostadix.unified-world-session/v1"
TARGET = "=okernel-unified:console.0"


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            value.update(block)
    return value.hexdigest()


def identity(path):
    path = Path(path)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest(path)}


def document(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected regular JSON: " + str(path))
    value = json.loads(path.read_text())
    if type(value) is not dict:
        raise ValueError("expected a JSON object")
    return value


def write_json(path, value):
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    with temporary.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def private_owner_group(gid):
    """Group-write is safe only when it adds no principal beyond owner/root."""
    try:
        group = grp.getgrgid(gid)
        members = {entry.pw_uid for entry in pwd.getpwall() if entry.pw_gid == gid}
        members.update(pwd.getpwnam(name).pw_uid for name in group.gr_mem)
    except KeyError:
        return False
    return members <= {0, os.geteuid()}


def protected_directory(path):
    path = Path(path).absolute()
    for current in (path, *path.parents):
        info = current.lstat()
        extra_writer = info.st_mode & 0o002 or info.st_mode & 0o020 and not private_owner_group(info.st_gid)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or extra_writer and not info.st_mode & stat.S_ISVTX):
            raise ValueError("unprotected/symlink directory: " + str(current))
    return path.resolve(strict=True)


def checked(path, expected):
    path = Path(path)
    if (path.is_symlink() or not path.is_file() or type(expected.get("bytes")) is not int
            or path.stat().st_size != expected["bytes"] or digest(path) != expected.get("sha256")):
        raise ValueError("file identity differs: " + str(path))
    return path


def validate_inventory(runtime, manifest):
    if manifest.get("schema") != RUNTIME_SCHEMA or manifest.get("passed") is not True:
        raise ValueError("frozen runtime is incomplete")
    inventory = manifest.get("inventory")
    if type(inventory) is not dict or not inventory:
        raise ValueError("runtime has no captured inventory")
    for name, expected in inventory.items():
        parsed = PurePosixPath(name)
        if (not isinstance(name, str) or not name or parsed.is_absolute()
                or str(parsed) != name or ".." in parsed.parts):
            raise ValueError("escaped runtime inventory")
        current = runtime
        for part in parsed.parts:
            current /= part
            if current.is_symlink():
                raise ValueError("runtime inventory symlink: " + name)
        checked(current, expected)
        if current.stat().st_mode & 0o022:
            raise ValueError("runtime file is writable by another uid/group")
    actual = set()
    for path in runtime.rglob("*"):
        if path.is_symlink():
            raise ValueError("runtime contains a symlink")
        if path.is_file():
            actual.add(str(path.relative_to(runtime)))
        elif not path.is_dir():
            raise ValueError("nonregular runtime entry")
    if actual != set(inventory) | {"runtime.json"}:
        raise ValueError("runtime has uncaptured/missing files")
    for name in ("okernel-unified", "runtime/scripts/okernel_unified_world.py",
                 "runtime/scripts/okernel_package_domain.py", "runtime/scripts/okernel_native_volume.py",
                 "runtime/scripts/okernel-unified-console.sh", "runtime/ocore/guest/plan9/unified/protocol.py",
                 "tools/native/qemu-system-aarch64", "tools/bin/qemu-system-aarch64"):
        if name not in inventory:
            raise ValueError("runtime is missing a required frozen component: " + name)


def load_frozen(runtime):
    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    # The runner's one bare companion import resolves to these checked bytes,
    # even if a caller/test process previously imported a checkout companion.
    load("okernel_native_volume", runtime / "runtime/scripts/okernel_native_volume.py")
    return load("runtime_lifecycle_frozen_runner", runtime / "runtime/scripts/okernel_unified_world.py")


def socket_name(state):
    return "ostadix-unified-" + hashlib.sha256(os.fsencode(state)).hexdigest()[:24]


def validate_private_fork(state, default_state):
    configured = Path(os.environ.get("OSTADIX_OKERNEL_STATE") or str(default_state.parent)) / "package-domain"
    forbidden = {default_state.resolve(), configured.expanduser().resolve(),
                 (Path.home() / ".local/state/ostadix/okernel/package-domain").resolve()}
    if state.name == "package-domain" or state in forbidden:
        raise ValueError("the working/default OS cannot be a runtime acceptance target")
    fork = document(state / "fork.json")
    if (fork.get("schema") != "ostadix.okernel-state-fork/v1" or fork.get("ok") is not True
            or fork.get("output") != str(state)):
        raise ValueError("an explicit isolated saved-state fork is required")
    return fork


def exact_line(data, marker):
    return marker in data.replace(b"\r", b"").split(b"\n")[:-1]


def process_start(data):
    # comm can contain spaces or ')'; starttime is field22 after the last ')'.
    tail = data.rsplit(") ", 1)[1].split()
    return int(tail[19])


def elf_machine(path):
    with Path(path).open("rb") as stream:
        header = stream.read(20)
    if not header.startswith(b"\x7fELF"):
        return None
    if len(header) < 20 or header[5] not in (1, 2):
        raise ValueError("invalid mapped ELF")
    return int.from_bytes(header[18:20], "little" if header[5] == 1 else "big")


def inspect_owned_qemu(runtime, manifest, state, session, record, pane_pid, proc=Path("/proc")):
    pid, controller = record.get("qemu_pid"), record.get("controller_pid")
    if (record.get("schema") != SESSION_SCHEMA or type(pid) is not int or pid <= 0
            or type(controller) is not int or controller != pane_pid
            or session.parent != state or not session.name.startswith("unified-session-")):
        raise ValueError("QEMU is not positively bound to this private tmux/controller session")
    process = proc / str(pid)
    started = process_start((process / "stat").read_text())
    status = dict(line.split(":", 1) for line in (process / "status").read_text().splitlines())
    if int(status["PPid"]) != controller:
        raise ValueError("recorded QEMU is not the private controller's child")
    native = runtime / "tools/native/qemu-system-aarch64"
    if (process / "exe").resolve(strict=True) != native:
        raise ValueError("owned QEMU does not execute the frozen native engine")
    checked(native, manifest["inventory"]["tools/native/qemu-system-aarch64"])
    argv = (process / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
    kernel = session / "inputs/monitor.elf"
    if (Path(argv[0]) != native or "-kernel" not in argv
            or Path(argv[argv.index("-kernel") + 1]) != kernel
            or argv[argv.index("-smp") + 1] != "1"):
        raise ValueError("QEMU argv is outside this frozen single-CPU session")
    expected_monitor = record.get("inputs", {}).get("monitor.elf", {})
    checked(kernel, expected_monitor)
    if expected_monitor.get("sha256") != R9_MONITOR:
        raise ValueError("owned process does not run the explicitly qualified R9 monitor")
    checkout_roots = set()
    for name, source in manifest.get("sources", {}).items():
        original = Path(source["original"]["path"])
        checkout_roots.add(original.parents[len(PurePosixPath(name).parts) - 1])
    if any(str(root) in argument for root in checkout_roots for argument in argv):
        raise ValueError("QEMU argv uses a mutable checkout path")
    interpreters = {Path(name).resolve(): expected for name, expected in manifest.get("host_elf_interpreters", {}).items()}
    mapped = []
    maps = (process / "maps").read_text()
    for text in sorted({line.split(None, 5)[5] for line in maps.splitlines()
                        if len(line.split(None, 5)) == 6 and line.split(None, 5)[5].startswith("/")}):
        if text.startswith("/memfd:"):
            continue
        if text.endswith(" (deleted)"):
            raise ValueError("owned QEMU has a deleted file mapping")
        path = Path(text)
        if any(path == root or root in path.parents for root in checkout_roots):
            raise ValueError("owned QEMU maps a mutable checkout file")
        machine = elf_machine(path)
        if machine is not None:
            if runtime in path.parents:
                name = str(path.relative_to(runtime))
                if not name.startswith(("tools/native/", "tools/lib/", "tools/modules/")):
                    raise ValueError("host ELF is outside the frozen QEMU closure")
                checked(path, manifest["inventory"][name])
            elif path.resolve() in interpreters:
                checked(path, interpreters[path.resolve()])
            elif path == kernel and machine == 183:
                checked(path, expected_monitor)
            else:
                raise ValueError("mapped host ELF is outside captured closure/interpreter: " + text)
        mapped.append({**identity(path), "elf_machine": machine})
    if process_start((process / "stat").read_text()) != started:
        raise ValueError("owned QEMU PID changed during process inspection")
    if not any(Path(item["path"]) == native for item in mapped):
        raise ValueError("frozen native executable was not observed in owned QEMU maps")
    if not set(interpreters) <= {Path(item["path"]) for item in mapped}:
        raise ValueError("declared host ELF interpreter was not observed in owned QEMU maps")
    return {"pid": pid, "controller_pid": controller, "start_ticks": started,
            "executable": identity(native), "argv": argv, "maps": maps, "mapped_files": mapped}


class AttachedTerminal:
    def __init__(self, command, environment, directory):
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 120, 0, 0))
        self.before = termios.tcgetattr(self.slave)
        self.log = (directory / "terminal.raw").open("wb")
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.master, selectors.EVENT_READ)
        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        self.process = subprocess.Popen(command, cwd="/tmp", env=environment,
                                        stdin=self.slave, stdout=self.slave, stderr=self.slave,
                                        preexec_fn=controlling_terminal, close_fds=True)

    def pump(self, duration=.02):
        for _, _ in self.selector.select(duration):
            try:
                data = os.read(self.master, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                data = b""
            if data:
                self.log.write(data)
                self.log.flush()

    def send(self, data):
        for index in range(0, len(data), 8):
            chunk = memoryview(data[index:index + 8])
            while chunk:
                written = os.write(self.master, chunk)
                if written <= 0:
                    raise RuntimeError("attach terminal stopped accepting keystrokes")
                chunk = chunk[written:]
            self.pump(.01)

    def detach(self, timeout=15):
        self.send(b"\x02d")
        deadline = time.monotonic() + timeout
        while self.process.poll() is None and time.monotonic() < deadline:
            self.pump()
        self.pump(0)
        if self.process.poll() is None or self.process.returncode != 0:
            raise RuntimeError("frozen attach did not detach cleanly")
        if termios.tcgetattr(self.slave) != self.before:
            raise RuntimeError("tmux attach did not restore all terminal attributes")
        return {"attach_pid": self.process.pid, "exit_status": 0, "full_termios_restored": True}

    def close(self):
        if self.process.poll() is None:
            # Only this verifier's attach client is closed. The tmux pane,
            # controller and QEMU remain owned by the frozen launcher.
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.selector.close()
        os.close(self.master)
        os.close(self.slave)
        self.log.close()


GUEST_HELPER = r'''
import hashlib,json,os,re,shutil,stat,subprocess,sys
from pathlib import Path
sys.path.insert(0,"/usr/lib/okernel")
import p9_protocol as p
root=Path(sys.argv[1]);action=sys.argv[2];phase=sys.argv[3];expected=sys.argv[4]
control=Path("/run/okernel/p9")
def read(path):return json.loads(path.read_text())
def sha(data):return hashlib.sha256(data).hexdigest()
def write(path,value):path.write_text(json.dumps(value,sort_keys=True)+"\n")
def current():
 value=read(control/"current.json")
 assert value["service_root"]=="/n/okernel/services/plan9" and value["state"]=="ready"
 p.ready_marker(value["generation"],value["instance"])
 return value
def requests(value):
 directory=Path(value["service_root"])/("g"+value["generation"])/("s"+value["instance"])
 return {x.name for x in directory.glob("r*") if re.fullmatch("r[0-9a-f]{32}",x.name) and (x/"submit").exists()}
def clients():
 names=("/usr/local/bin/p9","/usr/local/libexec/p9-history","/usr/local/libexec/p9-controller","/usr/local/bin/p9-install","/usr/lib/okernel/p9_protocol.py")
 values={name:{"bytes":Path(name).stat().st_size,"sha256":sha(Path(name).read_bytes())} for name in names}
 assert values["/usr/local/bin/p9"]["sha256"]==expected
 return values
if action=="identity":
 write(root/("guest-"+phase+".json"),{"clients":clients(),"current":current()})
elif action=="tree-before":
 result=subprocess.run(["apk","info","-e","tree"],capture_output=True)
 write(root/"tree-before.json",{"already_installed":result.returncode==0,"stdout_hex":result.stdout.hex(),"stderr_hex":result.stderr.hex()})
elif action=="tree":
 binary=Path(shutil.which("tree"));value={"binary_sha256":sha(binary.read_bytes()),"binary":str(binary),"version_hex":(root/("linux-tree-version-"+phase+".txt")).read_bytes().hex(),"package_hex":(root/("linux-tree-package-"+phase+".txt")).read_bytes().hex()}
 assert value["version_hex"] and value["package_hex"]
 if phase=="first":value["already_installed"]=read(root/"tree-before.json")["already_installed"]
 else:
  previous=read(root/"tree-first.json");assert all(previous[k]==v for k,v in value.items())
 write(root/("tree-"+phase+".json"),value)
elif action=="linux":
 binary=Path(sys.argv[5]);marker=sys.argv[6];data=binary.read_bytes()
 assert data[:6]==b'\x7fELF\x02\x01' and int.from_bytes(data[18:20],"little")==183
 assert (root/("linux-source-"+phase+".out")).read_bytes()==(marker+"\n").encode()
 value={"source_sha256":sha((root/"linux.c").read_bytes()),"binary_sha256":sha(data),"binary":str(binary),"output_hex":(root/("linux-source-"+phase+".out")).read_bytes().hex()}
 if phase=="first":value["compiler_version"]=subprocess.run(["cc","--version"],check=True,capture_output=True,text=True).stdout
 else:
  previous=read(root/"linux-first.json");assert all(previous[k]==v for k,v in value.items())
 write(root/("linux-"+phase+".json"),value)
elif action=="boundary":
 clients();assert not (control/"pending.json").exists()
 archive=Path("/var/lib/okernel/p9-history")
 for path in (archive,*archive.parents):
  info=path.lstat();assert stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and not info.st_mode&0o022
 for kind,manifest in (("keyerror",{"schema":"ostadix.p9.history-archive/v1"}),("typeerror",{"schema":"ostadix.p9.history-archive/v1","source_relative":None,"kind":"completed-job"})):
  before=current();oldresults={x.name for x in (control/"results").glob("*.json")};oldrequests=requests(before)
  # A fresh content-addressed-looking private directory is owned only by this
  # test; record its exact bytes before removing ONLY its own two new entries.
  name=sha((root.name+kind+os.urandom(16).hex()).encode());folder=archive/name
  os.mkdir(folder,0o700);ino=folder.stat().st_ino;wire=json.dumps(manifest,sort_keys=True).encode()+b"\n"
  path=folder/"manifest.json"
  try:
   fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,"wb") as stream:stream.write(wire)
   (root/(kind+"-manifest.json")).write_bytes(wire)
   result=subprocess.run(["/usr/local/bin/p9","--","echo","MUST_NOT_SUBMIT_"+root.name],input=b"supplied\0input\xff",capture_output=True,timeout=120)
   (root/(kind+".stdout")).write_bytes(result.stdout);(root/(kind+".stderr")).write_bytes(result.stderr)
   assert result.returncode==125 and result.stdout==b"" and b"history" in result.stderr.lower() and b"Traceback" not in result.stderr
   assert not (control/"pending.json").exists() and current()==before
   assert not ({x.name for x in (control/"results").glob("*.json")}-oldresults) and not (requests(before)-oldrequests)
   write(root/(kind+"-proof.json"),{"exit_status":125,"no_new_request":True,"no_new_result":True,"current":before,"manifest_sha256":sha(wire),"client_sha256":expected})
  finally:
   assert folder.stat().st_ino==ino and not folder.is_symlink()
   if path.exists() or path.is_symlink():
    assert path.read_bytes()==wire and not path.is_symlink() and {x.name for x in folder.iterdir()}=={"manifest.json"}
    path.unlink()
   assert not list(folder.iterdir());folder.rmdir()
elif action=="begin":
 clients();assert not (control/"pending.json").exists()
 write(root/("before-"+phase+".json"),{"current":current(),"results":sorted(x.name for x in (control/"results").glob("*.json"))})
elif action=="collect":
 code=int(sys.argv[5]);marker=sys.argv[6];argv=json.loads(sys.argv[7]);before=read(root/("before-"+phase+".json"))
 assert code==0 and current()==before["current"] and not (control/"pending.json").exists()
 fresh=[x for x in (control/"results").glob("*.json") if x.name not in before["results"]];assert len(fresh)==1
 receipt=read(fresh[0]);g,s,r=(receipt[k] for k in ("generation","instance","request_id"));assert (g,s)==(before["current"]["generation"],before["current"]["instance"])
 directory=Path(receipt["service_root"])/("g"+g)/("s"+s)/("r"+r)
 wire={name:(directory/name).read_bytes() for name in p.REQUEST_FILES}
 request=p.decode_request(wire["request"]);assert list(request.argv)==argv and request.cwd=="/n/work/"+root.name
 result=p.validate_result(wire["request"],wire["result"],wire["stdout"],wire["stderr"],started=wire["started"],done=wire["done"],status=wire["status"])
 assert result.ok and result.flags==0 and result.status==b"" and receipt["recovered"] is False
 assert receipt["request_sha256"]==sha(wire["request"]) and receipt["result_sha256"]==sha(wire["result"])
 assert (root/(phase+".out")).read_bytes()==wire["stdout"] and marker.encode() in wire["stdout"].splitlines()
 write(root/("proof-"+phase+".json"),{"receipt":receipt,"argv":list(request.argv),"cwd":request.cwd,"stdout_hex":wire["stdout"].hex(),"client_sha256":expected,"wire_sha256":{name:sha(data) for name,data in wire.items()}})
else:raise AssertionError(action)
print("\nRUNTIME_HELPER_"+action+"_"+phase+"_"+root.name,flush=True)
'''


class Verification:
    def __init__(self, args):
        self.args = args
        self.runtime = protected_directory(args.runtime.expanduser())
        self.state = protected_directory(args.state.expanduser())
        self.manifest = document(self.runtime / "runtime.json")
        validate_inventory(self.runtime, self.manifest)
        self.runner = load_frozen(self.runtime)
        self.fork = validate_private_fork(self.state, self.runner.common.DEFAULT_STATE)
        self.profile = document(self.runtime / "build/monitor-profile.json")
        self.runner.validate_profile(self.profile)
        if (digest(self.runtime / "build/monitor-profile.json") != R9_PROFILE
                or self.profile["artifacts"]["monitor.elf"]["sha256"] != R9_MONITOR
                or self.manifest["admitted_manifest"]["sha256"] != R9_PROFILE):
            raise ValueError("runtime is not the explicitly qualified R9 build")
        self.before = document(self.state / "head.json")
        self.runner.common.validate_head(self.state, self.before)
        for key in ("disk", "namespace"):
            checked(Path(self.before[key]["path"]), self.before[key])
        self.environment = os.environ.copy()
        for key in ("TMUX", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"):
            self.environment.pop(key, None)
        self.environment.update(PATH="/usr/bin:/bin", TERM="xterm-256color", PYTHONDONTWRITEBYTECODE="1",
                                PYTHONUNBUFFERED="1")
        self.tmux = Path(self.manifest["external_host_dependencies"]["tmux"]["path"])
        checked(self.tmux, self.manifest["external_host_dependencies"]["tmux"])
        self.socket = socket_name(self.state)
        self.output = self.state / ("runtime-acceptance-" + secrets.token_hex(8))
        self.output.mkdir(mode=0o700)
        for name, data in (("verifier-source.py", Path(__file__).read_bytes()),
                           ("typed-guest-helper.py", GUEST_HELPER.encode())):
            (self.output / name).write_bytes(data)
            (self.output / name).chmod(0o400)
        self.token = secrets.token_hex(12)
        self.workspace = "/n/okernel/work/runtime-" + self.token
        self.helper = self.workspace + "/guest-check.py"
        self.terminal = None
        self.started = False
        self.session = None
        self.result = {"schema": "ostadix.unified-frozen-runtime-acceptance/v1", "ok": False,
                       "scope": __doc__, "started": time.time(), "runtime_manifest": identity(self.runtime / "runtime.json"),
                       "verifier": identity(Path(__file__)),
                       "verifier_capture": identity(self.output / "verifier-source.py"),
                       "typed_guest_helper_capture": identity(self.output / "typed-guest-helper.py"),
                       "typed_guest_helper_sha256": hashlib.sha256(GUEST_HELPER.encode()).hexdigest(),
                       "runtime": str(self.runtime), "state": str(self.state), "before": self.before,
                       "profile": identity(self.runtime / "build/monitor-profile.json"), "monitor": self.profile["artifacts"]["monitor.elf"],
                       "python": {**identity(Path(sys.executable).resolve()), "version": sys.version},
                       "expected_guest_client_sha256": args.client_sha256, "actions": [], "sessions": [],
                       "workspace": self.workspace, "installed_name": args.installed_name, "program_marker": args.program_marker}
        self.record()

    def record(self):
        write_json(self.output / "result.json", self.result)

    def entry(self, action, *, detach=False):
        argv = [sys.executable, "-B", str(self.runtime / "okernel-unified"), action,
                "--state", str(self.state), "--stop-timeout", str(self.args.stop_timeout)]
        if detach:
            argv.append("--detach")
        return argv

    def command(self, argv, *, timeout=120, check=True):
        item = {"argv": list(map(str, argv)), "cwd": "/tmp", "started": time.time()}
        completed = subprocess.run(argv, cwd="/tmp", env=self.environment, capture_output=True,
                                   text=True, timeout=timeout)
        item.update(finished=time.time(), exit_status=completed.returncode,
                    stdout=completed.stdout, stderr=completed.stderr)
        self.result["actions"].append(item)
        self.record()
        if check and completed.returncode:
            raise RuntimeError("frozen runtime command failed; inspect action evidence")
        return completed

    def tm(self, *arguments, check=True):
        return self.command([str(self.tmux), "-L", self.socket, *arguments], check=check)

    def pane_pid(self):
        return int(self.tm("display-message", "-p", "-t", TARGET, "#{pane_pid}").stdout.strip())

    def capture_pane(self, path):
        path.write_text(self.tm("capture-pane", "-p", "-J", "-S", "-2000", "-t", TARGET).stdout)

    def session_record(self):
        return document(self.session / "result.json")

    def qemu_observation(self):
        record = self.session_record()
        observation = inspect_owned_qemu(self.runtime, self.manifest, self.state, self.session,
                                         record, self.pane_pid())
        name = "qemu-observation-" + secrets.token_hex(4) + ".json"
        write_json(self.output / name, observation)
        return {"controller_pid": observation["controller_pid"], "qemu_pid": observation["pid"],
                "qemu_start_ticks": observation["start_ticks"], "evidence": str(self.output / name)}

    def wait_line(self, marker, offset=0, timeout=None):
        deadline = time.monotonic() + (timeout or self.args.timeout)
        while time.monotonic() < deadline:
            if self.terminal is not None:
                self.terminal.pump()
                if self.terminal.process.poll() is not None:
                    raise RuntimeError("attach exited before fresh command output")
            if exact_line((self.session / "linux-console.log").read_bytes()[offset:], marker):
                return
            time.sleep(.02)
        raise TimeoutError("fresh complete-line guest output was not observed: " + marker.decode())

    def typed(self, text):
        if any(byte in text for byte in ("\r", "\n", "\0")) or len(text.encode()) > 3500:
            raise ValueError("typed command must fit one bounded terminal line")
        self.terminal.send(text.encode() + b"\n")

    def checked_guest(self, text, timeout=None):
        marker = ("RUNTIME_TYPED_" + secrets.token_hex(12)).encode()
        offset = (self.session / "linux-console.log").stat().st_size
        self.typed("( " + text + " ) && printf '\\n%s\\n' " + shlex.quote(marker.decode()))
        self.wait_line(marker, offset, timeout)

    def attach(self, label):
        directory = self.output / label
        directory.mkdir()
        self.terminal = AttachedTerminal(self.entry("attach"), self.environment, directory)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            self.terminal.pump()
            clients = self.tm("list-clients", "-F", "#{client_pid}", "-t", "=okernel-unified", check=False)
            if str(self.terminal.process.pid) in clients.stdout.splitlines():
                break
            if self.terminal.process.poll() is not None:
                raise RuntimeError("frozen attach exited before registering its controlling terminal")
            time.sleep(.1)
        else:
            raise TimeoutError("frozen attach did not register as the owned tmux client")
        # A typed nonce is the actual readiness barrier; historical pane output
        # cannot satisfy it and terminal ANSI sequences are not parsed as text.
        self.checked_guest("printf '%s\\n' " + shlex.quote("ATTACHED_" + secrets.token_hex(12)))
        self.capture_pane(directory / "pane.txt")

    def detach(self, label):
        proof = self.terminal.detach()
        self.terminal.close()
        self.terminal = None
        self.capture_pane(self.output / (label + "-pane.txt"))
        return proof

    def start(self):
        previous = (self.state / "latest-unified-session").read_text().strip() if (self.state / "latest-unified-session").exists() else ""
        self.started = True
        self.command(self.entry("start", detach=True))
        deadline = time.monotonic() + self.args.timeout
        while time.monotonic() < deadline:
            latest = self.state / "latest-unified-session"
            if latest.exists():
                path = Path(latest.read_text().strip())
                if str(path) != previous and path.parent == self.state and path.name.startswith("unified-session-"):
                    self.session = path
                    log = path / "linux-console.log"
                    if log.exists() and exact_line(log.read_bytes(), b"Linux and original Plan 9 share this workspace. Use p9 NAME for original Plan 9 programs."):
                        return self.qemu_observation()
            time.sleep(.1)
        raise TimeoutError("new frozen runtime did not reach the Linux/p9 keyboard-ready barrier")

    def helper_command(self, action, phase, *arguments):
        return "python3 " + " ".join(shlex.quote(value) for value in
            (self.helper, self.workspace, action, phase, self.args.client_sha256, *arguments))

    def upload_helper(self):
        self.checked_guest("mkdir -m 700 " + shlex.quote(self.workspace) + " && cd " + shlex.quote(self.workspace))
        encoded = base64.b64encode(GUEST_HELPER.encode()).decode()
        for index in range(0, len(encoded), 768):
            operator = ">" if index == 0 else ">>"
            self.checked_guest("printf %s " + shlex.quote(encoded[index:index + 768]) + " | base64 -d "
                               + operator + " " + shlex.quote(self.helper))

    def p9_proof(self, phase, name, marker, argv):
        self.checked_guest(self.helper_command("begin", phase))
        invocation = "/usr/local/bin/p9 -- " + shlex.quote(name)
        if name == "echo":
            invocation += " " + shlex.quote(marker)
        text = ("cd " + shlex.quote(self.workspace) + " && " + invocation + " > " + shlex.quote(self.workspace + "/" + phase + ".out")
                + " 2> " + shlex.quote(self.workspace + "/" + phase + ".err")
                + "; runtime_rc=$?; " + self.helper_command("collect", phase)
                + ' "$runtime_rc" ' + shlex.quote(marker) + " " + shlex.quote(json.dumps(argv)))
        self.checked_guest(text)

    def linux_workflow(self, phase):
        if phase == "first":
            self.checked_guest(self.helper_command("tree-before", phase))
            self.checked_guest("pkg install tree > " + shlex.quote(self.workspace + "/linux-tree-install.log") + " 2>&1", timeout=180)
        self.checked_guest("apk info -e tree && tree --version > " + shlex.quote(self.workspace + "/linux-tree-version-" + phase + ".txt")
                           + " && apk info -v tree > " + shlex.quote(self.workspace + "/linux-tree-package-" + phase + ".txt"))
        self.checked_guest(self.helper_command("tree", phase))
        binary = "/work/frozen-linux-" + self.token
        marker = "FROZEN_LINUX_SOURCE_" + self.token
        if phase == "first":
            source = ('#include <stdio.h>\nint main(void){puts("' + marker + '");return 0;}\n').encode()
            self.checked_guest("printf %s " + shlex.quote(base64.b64encode(source).decode()) + " | base64 -d > "
                               + shlex.quote(self.workspace + "/linux.c") + " && cc " + shlex.quote(self.workspace + "/linux.c")
                               + " -o " + shlex.quote(binary), timeout=180)
        self.checked_guest(shlex.quote(binary) + " > " + shlex.quote(self.workspace + "/linux-source-" + phase + ".out")
                           + " && " + self.helper_command("linux", phase, binary, marker))

    def stop(self, before, phase):
        session = self.session
        self.command(self.entry("stop"), timeout=self.args.stop_timeout + 60)
        self.started = False
        if self.tm("has-session", "-t", "=okernel-unified", check=False).returncode == 0:
            raise RuntimeError("frozen launcher retained a session after confirmed stop")
        after = document(self.state / "head.json")
        record = document(session / "result.json")
        validate_saved_pair(self.state, session, before, after, record)
        if (Path("/proc") / str(record["qemu_pid"])).exists():
            raise RuntimeError("recorded execution device still exists after launcher confirmed controller exit")
        self.runner.common.validate_head(self.state, after)
        for selected in (before, after):
            for key in ("disk", "namespace"):
                checked(Path(selected[key]["path"]), selected[key])
        native = document(session / "native-observation.json")
        if native.get("input_dropped") != 0 or native.get("live_domains") != 3:
            raise RuntimeError("saved runtime dropped input or lost an original kernel")
        volume = self.runner.Volume.from_file(Path(after["namespace"]["path"]))
        shared = self.workspace.removeprefix("/n/okernel") + "/linux-shared.txt"
        if volume.get(shared) != ("FROZEN_SHARED_" + self.token + "\n").encode():
            raise RuntimeError("paired saved namespace did not retain the freshly typed common file")
        evidence = {}
        names = ["guest-" + phase + ".json", "proof-echo-" + phase + ".json",
                 "tree-" + phase + ".json", "linux-" + phase + ".json"]
        if self.args.installed_name:
            names.append("proof-installed-" + phase + ".json")
        if phase == "first":
            names += ["keyerror-proof.json", "typeerror-proof.json"]
        for name in names:
            payload = volume.get(self.workspace.removeprefix("/n/okernel") + "/" + name)
            (self.output / (phase + "-" + name)).write_bytes(payload)
            evidence[name] = json.loads(payload)
        result = {"session": str(session), "controller_pid": record["controller_pid"], "qemu_pid": record["qemu_pid"],
                  "after": after, "guest_evidence": evidence, "input_dropped": 0, "live_domains": 3}
        self.result["sessions"].append(result)
        self.record()
        return after

    def run(self):
        self.command([sys.executable, "-B", str(self.runtime / "okernel-unified"), "check"])
        if self.tm("list-sessions", check=False).returncode == 0:
            raise ValueError("private tmux socket already has a session; verifier will not adopt it")
        previous_pids = None
        head = self.before
        for phase in ("first", "restart"):
            pids = self.start()
            if previous_pids and (pids["controller_pid"] == previous_pids["controller_pid"]
                                  or pids["qemu_pid"] == previous_pids["qemu_pid"]):
                raise RuntimeError("restart reused the old controller/QEMU process")
            self.attach(phase + "-attach")
            if phase == "first":
                detach = self.detach("first-detach")
                continued = self.qemu_observation()
                if any(continued[key] != pids[key] for key in ("controller_pid", "qemu_pid", "qemu_start_ticks")):
                    raise RuntimeError("detaching restarted the controller or execution device")
                self.result["detach"] = {**detach, "processes_preserved": True, "before": pids, "after": continued}
                self.attach("first-reattach")
                self.upload_helper()
                self.checked_guest(self.helper_command("boundary", "first"), timeout=240)
                self.checked_guest("printf '%s\\n' " + shlex.quote("FROZEN_SHARED_" + self.token)
                                   + " > " + shlex.quote(self.workspace + "/linux-shared.txt"))
            else:
                self.checked_guest("cd " + shlex.quote(self.workspace) + " && test \"$(cat linux-shared.txt)\" = "
                                   + shlex.quote("FROZEN_SHARED_" + self.token))
            self.linux_workflow(phase)
            self.checked_guest(self.helper_command("identity", phase))
            echo = "FROZEN_P9_" + phase.upper() + "_" + secrets.token_hex(12)
            self.p9_proof("echo-" + phase, "echo", echo, ["/arm64/bin/echo", echo])
            if self.args.installed_name:
                self.p9_proof("installed-" + phase, self.args.installed_name, self.args.program_marker,
                              ["/n/packages/plan9/bin/" + self.args.installed_name])
            self.result[phase + "_detach"] = self.detach(phase + "-complete")
            previous_pids = pids
            head = self.stop(head, phase)
        checked(Path(__file__), self.result["verifier"])
        self.result.update(ok=True, finished=time.time(), after=head,
                           checks=["frozen entry launched from /tmp under selected host Python",
                                   "real controlling-PTY attach/detach/reattach restores all terminal attributes",
                                   "detach preserves exact private controller/QEMU identity",
                                   "owned QEMU executable/mapped host ELF closure is frozen or declared interpreter",
                                   "actual patched guest client rejects both malformed history cases with125 and no submission",
                                   "Linux package install-by-name and original guest cc source executable persist unchanged across restart",
                                   "fresh original Plan9 echo and optional installed program validate actual wire receipts",
                                   "two stopped/quiescent paired saves and restart preserve the newly typed common file"])
        self.record()
        return self.result

    def cleanup(self):
        if self.terminal is not None:
            try:
                self.terminal.close()
            finally:
                self.terminal = None
        if self.started:
            try:
                # Explicit save/stop through the same frozen launcher only.
                self.command(self.entry("stop"), timeout=self.args.stop_timeout + 60)
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                self.result["cleanup_stop_error"] = str(error)
            self.record()


def validate_saved_pair(state, session, before, after, record):
    if (after == before or after.get("schema") != "ostadix.package-domain-disk-head/v2"
            or after.get("session") != str(session) or session.parent != state
            or record.get("schema") != SESSION_SCHEMA or record.get("ok") is not True
            or record.get("after") != after or after.get("previous") != before["disk"]
            or after.get("previous_namespace") != before["namespace"]
            or any(record.get(key) is not True for key in
                   ("paired_snapshot", "virtual_cpu_stopped", "native_operations_quiescent"))):
        raise ValueError("frozen launcher did not publish a new confirmed quiescent saved pair")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--client-sha256", required=True)
    parser.add_argument("--installed-name")
    parser.add_argument("--program-marker")
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--stop-timeout", type=int, default=180)
    args = parser.parse_args()
    if not re.fullmatch("[0-9a-f]{64}", args.client_sha256):
        parser.error("--client-sha256 must be the exact staged guest client identity")
    if bool(args.installed_name) != bool(args.program_marker):
        parser.error("--installed-name and --program-marker must be supplied together")
    if args.installed_name and (args.installed_name in (".", "..") or "/" in args.installed_name
                                or "\0" in args.installed_name or len(args.installed_name.encode()) > 255):
        parser.error("installed name must be one bounded UTF-8 basename")
    if args.program_marker and any(char in args.program_marker for char in "\r\n\0"):
        parser.error("program marker must be one exact output line")
    if not 30 <= args.timeout <= 600 or not 1 <= args.stop_timeout <= 600:
        parser.error("timeouts are outside the bounded runtime acceptance interval")
    verification = None
    try:
        verification = Verification(args)
        verification.run()
        print("Frozen unified runtime/tmux/PTY/save/restart: PASS\nEvidence: " + str(verification.output / "result.json"))
        return 0
    except BaseException as error:
        if verification is not None:
            verification.result.update(ok=False, error=type(error).__name__ + ": " + str(error))
            verification.record()
        else:
            preflight = Path(tempfile.mkdtemp(prefix="okernel-frozen-runtime-preflight-"))
            write_json(preflight / "result.json", {"schema": "ostadix.unified-frozen-runtime-preflight-failure/v1",
                "ok": False, "error": type(error).__name__ + ": " + str(error),
                "runtime": str(args.runtime), "state": str(args.state), "vm_launched": False,
                "python": sys.version, "verifier": identity(Path(__file__))})
            print("Preflight evidence: " + str(preflight / "result.json"), file=sys.stderr)
        print("Frozen runtime acceptance failed: " + str(error), file=sys.stderr)
        if verification is not None:
            print("Evidence: " + str(verification.output / "result.json"), file=sys.stderr)
        return 1
    finally:
        if verification is not None:
            verification.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
