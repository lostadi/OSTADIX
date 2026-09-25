#!/usr/bin/env python3
"""
NixOS test shim — Milestone E / F backend process for the Rust O evaluator.

Protocol: length-prefixed canonical CBOR frames (same as all other shims).

exec command:
  code     — Nix attrset body with `nodes` and `testScript` keys.
  bindings — OValue bindings for $var splice resolution.

Returns OMap:
  {"t": "map", "v": {
    "success":    {"t": "bool",       "v": <bool>},
    "log":        {"t": "str",        "v": <str>},
    "store_path": {"t": "store_path", "path": <str>}
  }}
"""

import json
import math
import os
import platform
import subprocess
import sys
import traceback
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from o_shim_common import admitted_tool_path, command_loop, write_wire_message

# Wrapper template: turns the user's attrset fragment into a full
# pkgs.testers.runNixOSTest call.  NIXPKGS_PATH may be overridden by env var.
_WRAPPER = """\
let
  pkgs = import ({nixpkgs}) {{}};
in
  pkgs.testers.runNixOSTest ({body})
"""


def nix_command():
    """Resolve Nix only on the real execution path; the non-Linux stub needs none."""
    return admitted_tool_path("nix")


# ---------------------------------------------------------------------------
# OValue helpers
# ---------------------------------------------------------------------------

def send_ok(value):
    write_wire_message({"status": "ok", "value": value})

def send_err(message):
    write_wire_message({"status": "err", "message": message})

def oval_to_nix(v):
    """Render an OValue dict as a Nix expression fragment for $var splicing."""
    t = v.get("t")
    if t == "null":
        return "null"
    if t == "bool":
        return "true" if v.get("v") else "false"
    if t in ("int", "float"):
        return str(v.get("v"))
    if t in ("str", "html"):
        return json.dumps(v.get("v", ""))
    if t == "store_path":
        return json.dumps(v.get("path", ""))
    if t == "list":
        items = " ".join(oval_to_nix(x) for x in v.get("v", []))
        return f"[ {items} ]"
    if t == "map":
        pairs = " ".join(
            f"{k} = {oval_to_nix(val)};"
            for k, val in v.get("v", {}).items()
        )
        return f"{{ {pairs} }}"
    # Blob and other exotic types: stringify
    return json.dumps(str(v))


# ---------------------------------------------------------------------------
# Core: build and run a NixOS test
# ---------------------------------------------------------------------------

def run_nixos_test(code):
    timeout = nixos_test_timeout_seconds()
    # On non-Linux (e.g. macOS darwin), full NixOS VM tests cannot run
    # without a Linux builder. Return an explicitly unsuccessful stub value.
    # Set NIXPKGS_ALLOW_UNSUPPORTED_SYSTEM=1 (and have a linux builder) to force.
    if platform.system() != "Linux" and os.environ.get("NIXPKGS_ALLOW_UNSUPPORTED_SYSTEM") != "1":
        return {
            "t": "map",
            "v": {
                "success": {"t": "bool", "v": False},
                "log": {"t": "str", "v": "(nixos_test stub: not Linux; set NIXPKGS_ALLOW_UNSUPPORTED_SYSTEM=1 + linux builder to run real test)"},
                "store_path": {"t": "store_path", "path": "/nix/store/00000000000000000000000000000000-stub"},
            }
        }

    nixpkgs = os.environ.get("NIXPKGS_PATH", "<nixpkgs>")
    expr = _WRAPPER.format(nixpkgs=nixpkgs, body=code)

    cmd = [
        nix_command(),
        "--extra-experimental-features", "nix-command",
        "build",
        "--no-link",
        "--print-out-paths",
        "--impure",
        "--expr",
        expr,
    ]

    try:
        completed = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise nixos_test_timeout_error(error, timeout) from error

    if completed.returncode != 0:
        raise RuntimeError(
            f"nixos_test build failed (exit {completed.returncode}):\n"
            f"STDERR:\n{completed.stderr}\nSTDOUT:\n{completed.stdout}"
        )

    store_path = completed.stdout.strip().splitlines()[-1].strip()

    # Read the test log if present under the standard NixOS test output path.
    log_text = ""
    for candidate in ("test-output/log", "log"):
        candidate_path = os.path.join(store_path, candidate)
        try:
            with open(candidate_path) as fh:
                log_text = fh.read()
            break
        except OSError:
            continue
    else:
        log_text = completed.stderr or completed.stdout

    return {
        "t": "map",
        "v": {
            "success":    {"t": "bool",       "v": True},
            "log":        {"t": "str",        "v": log_text},
            "store_path": {"t": "store_path", "path": store_path},
        },
    }


def nixos_test_timeout_seconds():
    name = "O_NIXOS_TEST_TIMEOUT_SECONDS"
    raw = os.environ.get(name, "600")
    try:
        seconds = float(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be a positive finite number of seconds") from error
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError(f"{name} must be a positive finite number of seconds")
    return seconds


def nixos_test_timeout_error(error, seconds):
    def text(value):
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value or ""

    return RuntimeError(
        f"nixos_test timed out after {seconds:g} seconds "
        "(O_NIXOS_TEST_TIMEOUT_SECONDS); completion of daemon-side builds is unknown.\n"
        f"PARTIAL STDERR:\n{text(error.stderr)}\nPARTIAL STDOUT:\n{text(error.stdout)}"
    )


# ---------------------------------------------------------------------------
# Command dispatch loop
# ---------------------------------------------------------------------------

def handle_exec(cmd):
    code     = cmd.get("code", "")
    bindings = cmd.get("bindings", {})

    # Apply variable splicing: replace each binding's repr in the code
    # string by rendering the OValue as a Nix expression fragment.
    for name, oval in bindings.items():
        code = code.replace(f"${name}", oval_to_nix(oval))

    try:
        result = run_nixos_test(code)
        send_ok(result)
    except Exception:
        send_err(traceback.format_exc())

def handle_ping():
    send_ok({"t": "null"})

def handle_cleanup():
    send_ok({"t": "null"})

command_loop(handle_exec, handle_cleanup=handle_cleanup, handle_ping=handle_ping)
