#!/usr/bin/env python3
"""Backend shim for rust^(...)_rust blocks.

Compiles code with rustc, runs the resulting binary, and captures stdout.
"""
import sys
import json
import subprocess
import tempfile
import os
import traceback
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import o_shim_common
from o_shim_common import command_loop, write_wire_message
from o_shim_common import stdout_result


def send_ok(value):
    write_wire_message({"status": "ok", "value": value})


def send_err(message):
    write_wire_message({"status": "err", "message": message})


def _o_opt_args(kind):
    """Compiler flags for O_OPT, matching NativeOptProfile in backend.rs.

    Unset means release (-O2), so a block compiled through this shim and one
    compiled by the native backend run under the same optimization profile.
    """
    raw = os.environ.get("O_OPT")
    key = "2" if raw is None else raw.strip().lower()
    level = {"": "2", "2": "2", "o2": "2", "release": "2", "default": "2",
             "0": "0", "o0": "0", "debug": "0", "1": "1", "o1": "1",
             "3": "3", "o3": "3", "native": "native"}.get(key)
    if level is None:
        raise ValueError("invalid O_OPT=" + repr(raw)
                         + "; expected one of: 0, 1, 2, 3, debug, release, native")
    if kind == "rust":
        return {"0": [], "1": ["-C", "opt-level=1"], "2": ["-C", "opt-level=2"],
                "3": ["-C", "opt-level=3"],
                "native": ["-C", "opt-level=2", "-C", "target-cpu=native"]}[level]
    import platform
    native = (["-O2", "-mcpu=native"] if platform.machine() in ("arm64", "aarch64")
              else ["-O2", "-march=native"])
    return {"0": ["-O0"], "1": ["-O1"], "2": ["-O2"], "3": ["-O3"], "native": native}[level]


def handle_exec(cmd):
    code = cmd.get("code", "")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "main.rs")
            binary = os.path.join(tmpdir, "main")

            with open(src, "w") as f:
                f.write(code)

            # Compile
            comp = subprocess.run(
                ["rustc", *_o_opt_args("rust"), src, "-o", binary],
                capture_output=True, text=True, timeout=o_shim_common.step_timeout(),
            )
            if comp.returncode != 0:
                stderr = comp.stderr.strip()
                send_err(f"rustc compilation failed\n{stderr}")
                return

            # Run
            result = subprocess.run(
                [binary],
                capture_output=True, text=True, timeout=o_shim_common.step_timeout(),
            )
            if result.returncode != 0:
                stderr = result.stderr.strip()
                send_err(f"rust program exited with code {result.returncode}\n{stderr}")
            else:
                send_ok(stdout_result(result.stdout))

    except subprocess.TimeoutExpired:
        send_err("rust compilation or execution timed out")
    except FileNotFoundError:
        send_err("rustc is not installed or not in PATH")
    except Exception:
        send_err(traceback.format_exc())


command_loop(handle_exec)
