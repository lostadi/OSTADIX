#!/usr/bin/env python3
"""Backend shim for bash^(...)_bash blocks.

Executes code in a bash session and captures stdout as the result.

One shim process serves one (language, environment) pair. Plain
bash^(...)_bash blocks get a fresh shim per block, so their variables vanish
when the block finishes. Numbered environments such as bash[0]^(...)_bash[0]
reuse one shim, and its session keeps shell variables, functions, options,
and the working directory across the blocks of that environment only.
Received let values are non-exported variables of one block, unset afterwards.
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


def _injection(env):
    """Shell text that assigns the let values, and text that undoes it."""
    inject, restore, unset = [], [], []
    for index, name in enumerate(sorted(env)):
        quoted = shlex.quote(env[name])
        # declare +x so a name the session already exported stays
        # invisible to child processes.
        inject.append(f"declare +x {name}={quoted} || __o_inject_ok=0; ")
        unset.append(name)
    if unset:
        restore.append(f"unset -v {' '.join(unset)} 2>/dev/null || :; ")
    return "".join(inject), "".join(restore)


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
        # the file holds only the user's code so bash's line numbers match.
        with open(code_path, "w") as f:
            f.write(code)
            f.write("\n")
        inject, restore = _injection(env)
        self.proc.stdin.write(
            # injection runs inside the capture and is checked, like the
            # native backend.
            # the refusal sets the status rather than failing a command, so
            # a persisted `set -e` cannot end the session on it.
            f"__o_status=125; {{ __o_inject_ok=1; {inject}if (( __o_inject_ok )); then "
            f"source {shlex.quote(code_path)}; __o_status=$?; else printf 'o: a let value "
            f"could not be assigned, so the block did not run\\n' >&2; fi; }} "
            f"</dev/null >{shlex.quote(out_path)} "
            f"2>{shlex.quote(err_path)}; unset -v __o_inject_ok; {restore}"
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
        # the session temp path is an implementation detail.
        stderr = stderr.replace(code_path, "bash").replace(self.dir.name, "<bash session>")
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


def _scalar(oval):
    """Shell text for a scalar OValue, or None for structured values."""
    tag = oval.get("t")
    value = oval.get("v")
    if tag in ("str", "int", "float"):
        return str(value)
    if tag == "bool":
        return "true" if value else "false"
    if tag == "text" and isinstance(value, dict):
        return value.get("utf8")
    if tag == "number" and isinstance(value, dict) and value.get("kind") == "int":
        return str(value.get("v"))
    return None


def handle_exec(cmd):
    global _session
    code = cmd.get("code", "")
    bindings = cmd.get("bindings", {})

    # Bindings become non-exported shell variables for this block only.
    env = {}
    for name, oval in bindings.items():
        value = _scalar(oval)
        if value is None:
            continue
        if "\0" in value:
            send_err(f"let `{name}` contains a NUL byte, which a bash variable cannot hold")
            return
        env[name] = value

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
