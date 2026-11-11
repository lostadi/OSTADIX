"""
Nix backend — Milestone A / B.

Semantics:
  * evaluate() runs `nix eval --json --impure --expr <body>` and lifts the
    JSON result into an OValue.  This covers pure Nix expressions: attrsets,
    lists, integers, strings, booleans, and null.  Nix functions and
    derivations are not JSON-representable and will produce a runtime error
    from the nix tool itself.

  * render_child() converts any OValue into a syntactically valid Nix
    expression fragment so that nested O values can be spliced into a Nix
    body via $var references.

The backend is stateless — every nix^(...) block runs a fresh `nix eval`
invocation.  Persistent envs are a no-op here because Nix is purely
functional: there is no mutable state to preserve between calls.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

from ..ovalue import (
    OBlob, OBool, OFloat, OInt, OList, OMap, ONull, OStorePath, OStr, OValue,
)


def _json_to_oval(x: Any) -> OValue:
    """Recursively lift a Python-parsed JSON value into OValue."""
    if x is None:
        return ONull()
    if isinstance(x, bool):
        return OBool(x)
    if isinstance(x, int):
        return OInt(x)
    if isinstance(x, float):
        return OFloat(x)
    if isinstance(x, str):
        return OStr(x)
    if isinstance(x, list):
        return OList(tuple(_json_to_oval(v) for v in x))
    if isinstance(x, dict):
        return OMap(tuple((str(k), _json_to_oval(v)) for k, v in x.items()))
    # Fallback for unexpected JSON types
    return OStr(str(x))


def _render_nix(v: OValue) -> str:
    """Use the same bounded literal profile as document evaluation."""
    from ..foreign_splice import render_literal
    return render_literal("nix", v)


class NixBackend:
    name = "nix"

    def make_env(self) -> Any:
        return None  # stateless

    def render_child(self, v: OValue) -> str:
        return _render_nix(v)

    def evaluate(self, body: str, env: Any) -> OValue:
        cmd = [
            "nix",
            "--extra-experimental-features", "nix-command",
            "eval",
            "--json",
            "--impure",
            "--expr",
            body,
        ]

        try:
            result = subprocess.run(
                cmd,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "nix executable not found. Install Nix to use nix^(...)_nix blocks."
            )

        if result.returncode != 0:
            raise RuntimeError(
                f"nix eval failed (exit {result.returncode}):\n"
                f"STDERR:\n{result.stderr}\nSTDOUT:\n{result.stdout}"
            )

        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"nix eval produced non-JSON output: {e}\nOutput: {result.stdout!r}"
            )

        return _json_to_oval(parsed)
