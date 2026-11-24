#!/usr/bin/env python3
"""Backend shim for voice^(...)_voice blocks.

Speaks the trimmed body with macOS say and returns that text as an O string.
Lee Ostadi's Personal Voice is first. Aaron Compact is used only if that voice
does not open. say writes no stdout, so the result is not taken from it.

The same choice lives in the Rust runner and mcp/voice/server.py. This file
stays self-contained apart from the shared wire loop, which C AOT copies.
"""
import os
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import o_shim_common
from o_shim_common import command_loop, write_wire_message

PERSONAL = "Lee Ostadi\u2019s Voice"
FALLBACK = "Aaron Compact"


def send_ok(value):
    write_wire_message({"status": "ok", "value": value})


def send_err(message):
    write_wire_message({"status": "err", "message": message})


def speak_with(voice, text):
    fd, path = tempfile.mkstemp(prefix="o-voice-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        result = subprocess.run(
            ["say", "-v", voice, "-f", path],
            capture_output=True,
            text=True,
            timeout=o_shim_common.step_timeout(),
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(f"say -v {voice} exited {result.returncode}: {detail}")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def handle_exec(cmd):
    text = cmd.get("code", "")
    if not isinstance(text, str):
        send_err("voice body must be text")
        return
    text = text.strip()
    if text == "":
        send_ok({"t": "str", "v": ""})
        return
    try:
        try:
            speak_with(PERSONAL, text)
        except Exception as error:
            personal_error = str(error)
            sys.stderr.write(
                f"voice: {PERSONAL} did not open ({personal_error}); speaking with {FALLBACK}\n"
            )
            try:
                speak_with(FALLBACK, text)
            except Exception as fallback_error:
                send_err(
                    f"{PERSONAL} failed ({personal_error}); {FALLBACK} also failed ({fallback_error})"
                )
                return
        send_ok({"t": "str", "v": text})
    except Exception:
        send_err(traceback.format_exc())


command_loop(handle_exec)
