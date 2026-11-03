#!/usr/bin/env python3
"""Measure three plain foreground p9echo calls in an explicit isolated fork.

Host monotonic timestamps bracket typed keystrokes, the exact first original
output line, and the shell's report of validated p9 CLI completion. Independent
native-result validation happens AFTER each stopped measurement. No compiler,
hidden command-execution channel, or guest timing helper enters that interval.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import sys
import tempfile
import time

from verify_okernel_unified_client import preflight, checked_command, upload, read_saved_session
from verify_okernel_unified_console import Terminal, hash_file

ROOT = Path(__file__).resolve().parents[1]
HELPER = r'''
import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,"/usr/lib/okernel")
import p9_protocol as p
root=Path(sys.argv[1]);mode=sys.argv[2];token=sys.argv[3]
c=Path("/run/okernel/p9");local=Path("/run/p9-latency-"+token+".json")
def read(path):return json.loads(path.read_text())
def sha(data):return hashlib.sha256(data).hexdigest()
if mode=="begin":
 assert not (c/"pending.json").exists()
 local.write_text(json.dumps({"current":read(c/"current.json"),"results":[x.name for x in (c/"results").glob("*.json")]}))
else:
 before=read(local);files=[x for x in (c/"results").glob("*.json") if x.name not in before["results"]]
 assert len(files)==1
 receipt=read(files[0]);g,s,r=(receipt[k] for k in ("generation","instance","request_id"))
 assert (g,s)==(before["current"]["generation"],before["current"]["instance"])
 directory=Path(receipt["service_root"])/("g"+g)/("s"+s)/("r"+r)
 wire={name:(directory/name).read_bytes() for name in p.REQUEST_FILES}
 request=p.decode_request(wire["request"])
 assert request.argv==("/arm64/bin/echo","FRESH_"+token)
 result=p.validate_result(wire["request"],wire["result"],wire["stdout"],wire["stderr"],started=wire["started"],done=wire["done"],status=wire["status"])
 assert result.ok and result.flags==0 and result.status==b"" and wire["stderr"]==b"" and wire["stdout"]==("FRESH_"+token+"\n").encode()
 assert receipt["request_sha256"]==sha(wire["request"]) and receipt["result_sha256"]==sha(wire["result"]) and not receipt["recovered"]
 (root/("evidence-"+token+".json")).write_text(json.dumps({"receipt":receipt,"argv":list(request.argv),"timeout_ms":request.timeout_ms,"wire_sha256":{k:sha(v) for k,v in wire.items()}},sort_keys=True)+"\n")
print("\nP9_LATENCY_"+mode+"_"+token,flush=True)
'''


def command(token: str) -> tuple[bytes, bytes, bytes]:
    if not isinstance(token, str) or re.fullmatch("[0-9a-f]{12}", token) is None:
        raise ValueError("fresh timing token must be twelve hexadecimal characters")
    first, done = ("FRESH_" + token).encode(), ("DONE_" + token).encode()
    line = b"p9 echo " + first + b"; echo " + done + b":$?\n"
    if len(line.rstrip(b"\n")) >= 80:
        raise ValueError("measurement command must stay below80 columns")
    return line, first, done


def observed(data: bytes, first: bytes, done: bytes) -> tuple[bool, int | None]:
    lines = data.replace(b"\r", b"").split(b"\n")[:-1]
    codes = []
    for line in lines:
        if line.startswith(done + b":"):
            value = line[len(done) + 1:]
            if re.fullmatch(rb"[0-9]{1,3}", value) is None:
                raise RuntimeError("malformed shell completion marker")
            codes.append(int(value))
    if len(codes) > 1:
        raise RuntimeError("duplicate completion marker")
    return first in lines, codes[0] if codes else None


class TimedTerminal(Terminal):
    active = None

    def pump(self, duration=0.1):
        super().pump(duration)
        if self.active is None:
            return
        sample = self.active
        first, code = observed(bytes(self.capture[sample["offset"]:]), sample["first"], sample["done"])
        now = time.monotonic()
        if first and sample["first_time"] is None:
            sample["first_time"] = now
        if code is not None and sample["complete_time"] is None:
            sample.update(complete_time=now, exit_code=code)

    def measure(self, token: str, timeout=180) -> dict:
        line, first, done = command(token)
        sample = {"offset": len(self.capture), "first": first, "done": done,
                  "first_time": None, "complete_time": None, "exit_code": None,
                  "start": time.monotonic()}
        self.active = sample
        try:
            self.send(line)
            deadline = sample["start"] + timeout
            while sample["complete_time"] is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError("plain p9echo did not complete")
                if self.process.poll() is not None:
                    raise RuntimeError("foreground console exited during p9echo")
                self.pump(0.02)
            if sample["exit_code"] != 0 or sample["first_time"] is None:
                raise RuntimeError("plain p9echo failed or lacked its exact bare output line")
            return {"token": token, "typed_line": line.decode().rstrip("\n"),
                    "typed_columns": len(line) - 1, "linux_exit": sample["exit_code"],
                    "first_output_host_seconds": sample["first_time"] - sample["start"],
                    "validated_cli_completion_host_seconds": sample["complete_time"] - sample["start"]}
        finally:
            self.active = None


def verify(state: Path, build: Path):
    inputs = preflight(state, build)
    state, build = Path(inputs["state"]), Path(inputs["build"])
    output = Path(tempfile.mkdtemp(prefix="client-latency-", dir=state))
    receipt = output / "result.json"
    paths = ("scripts/verify_okernel_unified_latency.py", "scripts/verify_okernel_unified_client.py",
             "scripts/verify_okernel_unified_console.py", "scripts/okernel_unified_world.py",
             "scripts/okernel_package_domain.py", "scripts/okernel_native_volume.py",
             "ocore/guest/linux/package-domain/p9", "ocore/guest/linux/package-domain/p9-controller",
             "ocore/guest/linux/package-domain/p9-history", "ocore/guest/plan9/unified/protocol.py")
    sources = {name: hash_file(ROOT / name) for name in paths}
    record = {"schema": "ostadix.unified-foreground-client-latency/v1", "ok": False,
              "started": time.time(), "inputs": inputs, "source_sha256": sources,
              "scope": "three automated short typed commands through one real foreground PTY; actual original Plan9 echo and p9 validation under native O-core; host-wall measurements include keystrokes, exclude later independent helper validation",
              "clock": "host time.monotonic; timestamps on PTY reads during typing and waiting;20ms wait polling",
              "samples": [], "source_artifacts": {}}
    for name, sha in sources.items():
        target = output / "sources" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        data = (ROOT / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise RuntimeError("source changed during capture")
        target.write_bytes(data);target.chmod(0o400)
        record["source_artifacts"][name] = {"path": str(target.relative_to(output)), "bytes": len(data), "sha256": sha}
    receipt.write_text(json.dumps(record, indent=2) + "\n")
    terminal = None
    nonce = secrets.token_hex(8)
    workspace = "/n/okernel/work/latency-" + nonce
    helper = "/tmp/p9-latency-" + nonce + ".py"
    try:
        terminal = TimedTerminal(state, build, output)
        terminal.wait(b"Linux and original Plan 9 share this workspace.", timeout=240)
        session = Path((state / "latest-unified-session").read_text().strip())
        record["session"] = str(session)
        checked_command(terminal, "mkdir -p " + workspace)
        upload(terminal, helper, HELPER.encode())
        installed = (("/usr/local/bin/p9", "ocore/guest/linux/package-domain/p9"),
                     ("/usr/local/libexec/p9-history", "ocore/guest/linux/package-domain/p9-history"),
                     ("/usr/local/libexec/p9-controller", "ocore/guest/linux/package-domain/p9-controller"),
                     ("/usr/lib/okernel/p9_protocol.py", "ocore/guest/plan9/unified/protocol.py"))
        checked_command(terminal, " && ".join('test "$(sha256sum ' + path + " | cut -d ' ' -f1)\" = " + sources[source]
                                             for path, source in installed))
        for index in range(3):
            token = secrets.token_hex(6)
            prefix = "python3 " + shlex.quote(helper) + " " + workspace
            checked_command(terminal, prefix + " begin " + token)
            sample = terminal.measure(token)
            sample["index"] = index
            record["samples"].append(sample)
            receipt.write_text(json.dumps(record, indent=2) + "\n")
            print(json.dumps(sample), flush=True)
            # Measurement is already stopped before any helper launch/read.
            checked_command(terminal, prefix + " verify " + token)
        terminal.finish()
        _, volume = read_saved_session(state, session)
        for sample in record["samples"]:
            data = volume.get(workspace.removeprefix("/n/okernel") + "/evidence-" + sample["token"] + ".json")
            evidence = json.loads(data)
            if evidence["argv"] != ["/arm64/bin/echo", "FRESH_" + sample["token"]] or evidence["timeout_ms"] != 120000:
                raise RuntimeError("measured command differs from the actual originalecho/default-budget request")
            (output / ("native-result-" + str(sample["index"]) + ".json")).write_bytes(data)
            sample["native_receipt"] = evidence["receipt"]
        if sources != {name: hash_file(ROOT / name) for name in sources}:
            raise RuntimeError("source changed during qualification")
        within = all(item["first_output_host_seconds"] < 30 for item in record["samples"])
        record.update(finished=time.time(), first_output_within30s=within, functional_native_results_valid=True,
                      paired_save_and_termios_restored=True)
        if not within:
            raise RuntimeError("at least one plain first output exceeded the unchanged30s UI criterion")
        record["ok"] = True
        print("Unified foreground p9echo host latency: PASS\nEvidence: " + str(receipt))
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if terminal is not None:
            terminal.close()
        receipt.write_text(json.dumps(record, indent=2) + "\n")
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
        print("Unified foreground latency check failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
