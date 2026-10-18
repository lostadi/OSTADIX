#!/usr/bin/env python3
"""Backend shim for bash^(...)_bash blocks.

Executes code in a bash session and captures stdout as the result.

One shim process serves one (language, environment) pair. Plain
bash^(...)_bash blocks get a fresh shim per block, so their variables vanish
when the block finishes. Numbered environments such as bash[0]^(...)_bash[0]
reuse one shim, and its session keeps shell variables, functions, options,
and the working directory across the blocks of that environment only.
Received let values are non-exported variables of one block, unset afterwards.
A writable bash special such as PATH keeps its export flag, is not unset,
and persists in a numbered session from the first block that names it.
"""
import sys
import os
import decimal
import math
import shlex
import struct
import subprocess
import tempfile
import traceback
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from o_shim_common import command_loop, write_wire_message
from o_shim_common import stdout_result
import o_shim_common

SENTINEL = "__O_BASH_BLOCK_DONE__"
_session = None
# signal that killed the session shell mid-block; every later block fails
# instead of silently starting a fresh shell (its state is gone).
_killed_by = None

# keep in step with BASH_WRITABLE_SPECIAL_NAMES in crates/ostadix-api/src/ir.rs
WRITABLE_SPECIALS = {
    "BASH", "BASH_COMPAT", "BASH_ENV", "BASH_VERSION", "BASH_XTRACEFD", "CDPATH",
    "COLUMNS", "ENV", "FIGNORE", "GLOBIGNORE", "HISTCONTROL", "HISTFILE",
    "HISTFILESIZE", "HISTIGNORE", "HISTSIZE", "HOME", "HOSTNAME", "HOSTTYPE", "IFS",
    "INPUTRC", "LANG", "LINES", "LOGNAME", "MACHTYPE", "MAIL", "MAILCHECK",
    "MAILPATH", "OLDPWD", "OPTARG", "OPTERR", "OPTIND", "OSTYPE", "PATH",
    "POSIXLY_CORRECT", "PROMPT_COMMAND", "PS1", "PS2", "PS3", "PS4", "PWD", "SHELL",
    "SHLVL", "TERM", "TIMEFORMAT", "TMOUT", "TMPDIR", "TZ", "USER",
    "AUTO_RESUME",
    "BASH_ALIASES",
    "BASH_ARGV0",
    "BASH_CMDS",
    "BASH_LOADABLES_PATH",
    "BASH_REMATCH",
    "CHILD_MAX",
    "COMPREPLY",
    "COMP_CWORD",
    "COMP_KEY",
    "COMP_LINE",
    "COMP_POINT",
    "COMP_TYPE",
    "COMP_WORDBREAKS",
    "COMP_WORDS",
    "COPROC",
    "DIRSTACK",
    "EMACS",
    "EXECIGNORE",
    "FCEDIT",
    "FUNCNEST",
    "HISTCHARS",
    "HISTTIMEFORMAT",
    "HOSTFILE",
    "IGNOREEOF",
    "INSIDE_EMACS",
    "MAPFILE",
    "PIPESTATUS",
    "PROMPT_DIRTRIM",
    "PS0",
    "READLINE_ARGUMENT",
    "READLINE_LINE",
    "READLINE_MARK",
    "READLINE_POINT",
    "REPLY",
    "TEXTDOMAIN",
    "TEXTDOMAINDIR",
}


def _is_writable_special(name):
    return name in WRITABLE_SPECIALS or name.startswith("LC_")


def _injection(env):
    """Shell text that assigns the let values, and text that undoes it."""
    inject, restore, unset = [], [], []
    for name in sorted(env):
        quoted = shlex.quote(env[name])
        if _is_writable_special(name):
            # session state such as PATH stays assigned for later blocks.
            inject.append(f"declare -- {name}={quoted} || __o_inject_ok=0; ")
        else:
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
        # once the shell answered, its capture files exist; a missing one
        # means the output is unknown, never empty. a shell that died before
        # answering already fails the block.
        def capture(path, stream):
            try:
                with open(path, errors="replace") as f:
                    return f.read()
            except OSError:
                if not alive:
                    return ""
                raise RuntimeError(f"bash block {stream} capture is missing or unreadable") from None
        stdout = capture(out_path, "stdout")
        stderr = capture(err_path, "stderr")
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
    if tag in ("str", "int"):
        return str(value)
    if tag == "float":
        return _float_text(float(value))
    # bools keep the base shim's python rendering.
    if tag == "bool":
        return str(bool(value))
    if tag == "text" and isinstance(value, dict):
        return value.get("utf8")
    if tag == "number" and isinstance(value, dict):
        return _number(value)
    return None


def _number(number):
    """Shell text for a number OValue: ints and binary floats, as Rust does."""
    kind = number.get("kind")
    if kind == "int":
        return str(number.get("v"))
    if kind == "binary_float":
        bits = bytes(number.get("bits") or [])
        if len(bits) == 8:
            return _float_text(struct.unpack(">d", bits)[0])
        if len(bits) == 4:
            return _float_text(struct.unpack(">f", bits)[0])
    return None


def _float_text(value):
    """Rust's f64 Display: shortest digits, never an exponent, `2` for 2.0."""
    if not math.isfinite(value):
        return None
    if value == int(value):
        return str(int(value))
    return format(decimal.Decimal(repr(value)), "f")


def handle_exec(cmd):
    global _session, _killed_by
    if _killed_by is not None:
        send_err(f"bash session was killed by signal {_killed_by} during an earlier block; its state is gone")
        return
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
            if returncode < 0:
                _killed_by = -returncode
                send_err(f"bash session was killed by signal {_killed_by} during this block; its state is gone")
                return
        if returncode != 0 and not alive:
            # a failing block that ended the session, e.g. under a persisted
            # `set -e`, also dropped its variables, functions, and options.
            send_err(
                "bash session ended during this block, dropping its variables, "
                "functions, and options; the next block starts a fresh session. "
                f"bash exited with code {returncode}\n{stderr.strip()}"
            )
        elif returncode != 0:
            send_err(f"bash exited with code {returncode}\n{stderr.strip()}")
        else:
            send_ok(stdout_result(stdout))
    except FileNotFoundError:
        send_err("bash is not installed or not in PATH")
    except RuntimeError as error:
        send_err(str(error))
    except Exception:
        send_err(traceback.format_exc())


o_shim_common.heartbeat_child_pid = lambda: _session.proc.pid if _session is not None else None
command_loop(handle_exec)
