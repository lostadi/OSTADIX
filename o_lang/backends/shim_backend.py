"""Stateless external backends using the shipped framed-CBOR shim protocol.

Common Lisp and JavaScript shims run a fresh language process for each block,
including numeric environments. Python's built-in evaluator remains in-process.
This adapter does not claim the native runtime's admission or state protocols.
"""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import sys

from ..ovalue import (
    OBlob, OBool, OFloat, OHtml, OInt, OList, OMap, ONull, OStorePath, OStr,
    OValue,
)


def _from_wire(value: object) -> OValue:
    """Lift supported native wire values without silently stringifying others."""
    if not isinstance(value, dict):
        raise ValueError("shim returned a non-object OValue")
    tag, payload = value.get("t"), value.get("v")
    if tag == "null":
        return ONull()
    scalars = {"bool": (bool, OBool), "int": (int, OInt),
               "float": (float, OFloat), "str": (str, OStr), "html": (str, OHtml)}
    if tag in scalars:
        kind, constructor = scalars[tag]
        if type(payload) is not kind:
            raise ValueError(f"invalid {tag} payload from shim")
        return constructor(payload)
    if tag == "number" and isinstance(payload, dict):
        if payload.get("kind") == "int":
            integer = payload.get("v")
            if not isinstance(integer, str) or not re.fullmatch(r"[+-]?[0-9]+", integer):
                raise ValueError("invalid integer-number payload from shim")
            return OInt(int(integer))
        if payload.get("kind") == "binary_float":
            bits = payload.get("bits")
            if (payload.get("format") != "f64" or not isinstance(bits, list)
                    or len(bits) != 8
                    or any(type(byte) is not int or not 0 <= byte <= 255 for byte in bits)):
                raise ValueError("expected f64 binary-float payload with exactly eight bytes")
            return OFloat(struct.unpack(">d", bytes(bits))[0])
    if tag == "list" and isinstance(payload, list):
        return OList(tuple(_from_wire(item) for item in payload))
    if tag == "map" and isinstance(payload, dict):
        if not all(isinstance(key, str) for key in payload):
            raise ValueError("shim map keys must be strings")
        return OMap(tuple((key, _from_wire(item)) for key, item in payload.items()))
    if tag == "blob" and isinstance(payload, str) and isinstance(value.get("mime"), str):
        return OBlob(base64.b64decode(payload, validate=True), value["mime"])
    if tag == "store_path" and isinstance(value.get("path"), str):
        return OStorePath(value["path"])
    raise ValueError(f"unsupported or malformed shim OValue tag {tag!r}")


def _splice_repr(value: OValue) -> str:
    """Match the native Default renderer used by these two backend tags."""
    if isinstance(value, ONull):
        return "null"
    if isinstance(value, OBool):
        return "true" if value.value else "false"
    if isinstance(value, OFloat) and math.isnan(value.value):
        # Preserve the native generic renderer's spelling. Splices can occur
        # inside strings, so this layer must not guess language-literal context.
        return "NaN"
    if isinstance(value, (OInt, OFloat)):
        return str(value.value)
    if isinstance(value, (OStr, OHtml)):
        return value.value
    if isinstance(value, OStorePath):
        return value.path
    if isinstance(value, OList):
        return "[" + ", ".join(_splice_repr(item) for item in value.items) + "]"
    if isinstance(value, OMap):
        return "{" + ", ".join(
            f"{json.dumps(key, ensure_ascii=False)}: {_splice_repr(item)}"
            for key, item in sorted(value.pairs)
        ) + "}"
    if isinstance(value, OBlob):
        return f"data:{value.mime};base64,{base64.b64encode(value.data).decode('ascii')}"
    raise ValueError(f"unsupported {type(value).__name__} splice for stateless shim")


class ShimBackend:
    def __init__(self, name: str, shim_dir: Path | None = None, timeout: float = 65):
        if name not in {"common_lisp", "javascript"}:
            raise ValueError(f"unsupported stateless shim backend {name!r}")
        self.name = name
        default_shims = Path(__file__).resolve().parents[2] / "backends"
        self.shim_dir = Path(shim_dir or os.environ.get("O_BACKENDS_DIR") or default_shims)
        self.timeout = timeout
        self._wire = None

    def _wire_protocol(self):
        # Built-in backends remain usable when only the o_lang package is
        # installed. Resolve the shared protocol lazily from the selected shims.
        if self._wire is None:
            helper = self.shim_dir / "o_shim_common.py"
            if not helper.is_file():
                raise RuntimeError(
                    f"{self.name} shim protocol helper missing: {helper}; "
                    "set O_BACKENDS_DIR to the shipped backends directory"
                )
            spec = importlib.util.spec_from_file_location("_o_reference_shim_wire", helper)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self._wire = module
        return self._wire

    def make_env(self):
        return None

    def render_child(self, value: OValue) -> str:
        return _splice_repr(value)

    def evaluate(self, body: str, env, ctx=None) -> OValue:
        wire = self._wire_protocol()
        request = io.BytesIO()
        wire.write_wire_message({"cmd": "exec", "code": body}, request)
        script = self.shim_dir / f"{self.name}_shim.py"
        # A private session lets cancellation terminate the shim and its engine.
        with subprocess.Popen(
            [sys.executable, str(script)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
        ) as process:
            try:
                stdout, stderr = process.communicate(request.getvalue(), timeout=self.timeout)
            except BaseException as error:
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.communicate()
                if isinstance(error, subprocess.TimeoutExpired):
                    raise RuntimeError(f"{self.name} shim timed out after {self.timeout}s") from error
                raise
            if process.returncode:
                raise RuntimeError(
                    f"{self.name} shim exited {process.returncode}: "
                    f"{stderr.decode('utf-8', errors='replace').strip()}"
                )

        try:
            stream = io.BytesIO(stdout)
            response = wire.read_wire_message(stream)
            if not isinstance(response, dict) or stream.read():
                raise ValueError("expected exactly one response frame")
            if response.get("status") == "err":
                raise RuntimeError(f"{self.name} shim: {response.get('message', 'execution failed')}")
            if response.get("status") != "ok":
                raise ValueError(f"unexpected shim status {response.get('status')!r}")
            return _from_wire(response.get("value"))
        except (ValueError, TypeError, KeyError, EOFError) as error:
            raise RuntimeError(f"{self.name} shim protocol error: {error}") from error
