#!/usr/bin/env python3
"""Backend shim for bash^(...)_bash blocks.

Executes code in a bash session and captures stdout as the result.

One shim process serves one (language, environment) pair. Plain
bash^(...)_bash blocks get a fresh shim per block, so their variables vanish
when the block finishes. Numbered environments such as bash[0]^(...)_bash[0]
reuse one shim, and its session keeps shell variables, functions, options,
and the working directory across the blocks of that environment only.
Injected let values are visible to one block and are unset afterwards.
"""
import sys
import os
import shlex
import subprocess
import tempfile
import traceback
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from o_shim_common import command_loop, write_wire_message
from o_shim_common import stdout_result

SENTINEL = "__O_BASH_BLOCK_DONE__"
_session = None


def send_ok(value):
    write_wire_message({"status": "ok", "value": value})


def send_err(message):
    write_wire_message({"status": "err", "message": message})


class BashSession:
    def __init__(self):
        self.dir = tempfile.TemporaryDirectory(prefix="o-bash-session-")
        self.proc = subprocess.Popen(
            ["bash", "--noprofile", "--norc", "-s"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True,
        )
        self.serial = 0

    def run(self, code, env):
        self.serial += 1
        base = os.path.join(self.dir.name, f"block-{self.serial}")
        code_path, out_path, err_path = base + ".sh", base + ".out", base + ".err"
        with open(code_path, "w") as f:
            for name, value in env.items():
                f.write(f"export {name}={shlex.quote(value)}\n")
            f.write(code)
            f.write("\n")
        unset = f"unset -v {' '.join(sorted(env))} 2>/dev/null; " if env else ""
        self.proc.stdin.write(
            f"source {shlex.quote(code_path)} </dev/null >{shlex.quote(out_path)} "
            f"2>{shlex.quote(err_path)}; __o_status=$?; {unset}"
            f"printf '\\n{SENTINEL}%d\\n' \"$__o_status\"; unset -v __o_status\n"
        )
        self.proc.stdin.flush()
        status = None
        for line in self.proc.stdout:
            line = line.rstrip("\n")
            if line.startswith(SENTINEL):
                status = int(line[len(SENTINEL):] or "1")
                break
        alive = status is not None
        if not alive:
            status = self.proc.wait()
        stdout = ""
        if os.path.exists(out_path):
            with open(out_path, errors="replace") as f:
                stdout = f.read()
        stderr = ""
        if os.path.exists(err_path):
            with open(err_path, errors="replace") as f:
                stderr = f.read()
        for path in (code_path, out_path, err_path):
            try:
                os.remove(path)
            except OSError:
                pass
        return status, stdout, stderr, alive

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.kill()
            self.proc.wait()
        except Exception:
            pass
        self.dir.cleanup()


def handle_exec(cmd):
    global _session
    code = cmd.get("code", "")
    bindings = cmd.get("bindings", {})

    # Pass bindings as environment variables (string values only).
    env = {}
    for name, oval in bindings.items():
        if oval.get("t") in ("str", "int", "float", "bool"):
            env[name] = str(oval.get("v", ""))

    try:
        if _session is None:
            _session = BashSession()
        returncode, stdout, stderr, alive = _session.run(code, env)
        if not alive:
            _session.close()
            _session = None
        if returncode != 0:
            send_err(f"bash exited with code {returncode}\n{stderr.strip()}")
        else:
            send_ok(stdout_result(stdout))
    except FileNotFoundError:
        send_err("bash is not installed or not in PATH")
    except Exception:
        send_err(traceback.format_exc())


command_loop(handle_exec)
