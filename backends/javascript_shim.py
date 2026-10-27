#!/usr/bin/env python3
"""Backend shim for javascript^(...)_javascript blocks.

Executes code via Node.js and captures stdout as the result.
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


_MAX_SAFE_INTEGER = 9007199254740991
_IDENT_RE = o_shim_common.re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _int_literal(val):
    n = int(val)
    if -_MAX_SAFE_INTEGER <= n <= _MAX_SAFE_INTEGER:
        return str(n)
    return f"{n}n"


def _float_literal(val, path):
    f = float(val)
    if not o_shim_common.math.isfinite(f):
        raise ValueError(
            f"javascript binding `{path}` has unsupported non-finite float"
        )
    if f == 0.0 and o_shim_common.math.copysign(1.0, f) < 0.0:
        return "-0"
    return repr(f)


def _number_literal(num, path):
    if not isinstance(num, dict):
        raise ValueError(f"javascript binding `{path}` has invalid number payload")
    kind = num.get("kind")
    if kind == "int":
        return _int_literal(num.get("v", 0))
    if kind == "binary_float":
        fmt = num.get("format")
        bits = bytes(num.get("bits", []))
        if fmt == "f32" and len(bits) == 4:
            val = o_shim_common.struct.unpack(">f", bits)[0]
            return _float_literal(val, path)
        if fmt == "f64" and len(bits) == 8:
            val = o_shim_common.struct.unpack(">d", bits)[0]
            return _float_literal(val, path)
    raise ValueError(
        f"javascript binding `{path}` has unsupported numeric value `{kind}`"
    )


def _oval_to_js_literal(oval, path):
    if not isinstance(oval, dict):
        return json.dumps(oval)
    t = oval.get("t")
    v = oval.get("v")
    if t == "str":
        return json.dumps(v)
    if t == "text":
        return json.dumps(v.get("utf8", "") if isinstance(v, dict) else "")
    if t == "int":
        return _int_literal(v)
    if t == "float":
        return _float_literal(v, path)
    if t == "number":
        return _number_literal(v, path)
    if t == "bool":
        return "true" if v else "false"
    if t == "null":
        return "null"
    if t == "list":
        items = [
            _oval_to_js_literal(item, f"{path}[{idx}]")
            for idx, item in enumerate(v or [])
        ]
        return "[" + ", ".join(items) + "]"
    if t == "map":
        entries = []
        for key in sorted((v or {}).keys()):
            entries.append(
                f"{json.dumps(str(key))}: {_oval_to_js_literal(v[key], f'{path}.{key}')}"
            )
        return "{" + ", ".join(entries) + "}"
    if t == "native":
        return json.dumps(oval)
    raise ValueError(f"javascript binding `{path}` has unsupported value type `{t}`")


def handle_exec(cmd):
    code = cmd.get("code", "")
    bindings = cmd.get("bindings", {})

    # Inject bindings as top-level const declarations.
    preamble = ""
    try:
        for name in sorted(bindings.keys()):
            if not _IDENT_RE.match(name):
                continue
            oval = bindings[name]
            t = oval.get("t") if isinstance(oval, dict) else None
            if t in ("str", "text", "int", "float", "number", "bool", "null", "list", "map", "native"):
                preamble += f"const {name} = {_oval_to_js_literal(oval, name)};\n"
    except ValueError as exc:
        send_err(str(exc))
        return

    full_code = preamble + code

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", delete=False
        ) as f:
            f.write(full_code)
            tmp = f.name

        try:
            result = subprocess.run(
                ["node", tmp],
                capture_output=True, text=True, timeout=o_shim_common.step_timeout(),
            )
        finally:
            os.unlink(tmp)

        if result.returncode != 0:
            stderr = result.stderr.strip()
            send_err(f"node exited with code {result.returncode}\n{stderr}")
        else:
            send_ok(stdout_result(result.stdout))
    except subprocess.TimeoutExpired:
        send_err("javascript execution exceeded the opt-in limit O_BACKEND_STEP_TIMEOUT_MS")
    except FileNotFoundError:
        send_err("node is not installed or not in PATH")
    except Exception:
        send_err(traceback.format_exc())


command_loop(handle_exec)
