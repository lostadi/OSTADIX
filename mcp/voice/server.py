#!/usr/bin/env python3
"""Local speech MCP. Newline-framed JSON-RPC on stdin and stdout.

Speaks with macOS say. Lee Ostadi's Personal Voice is first. Aaron Compact
is used only if that voice does not open. Nothing is spoken at startup.
Logs go to stderr. The Ostadix block voice^(...)_voice calls say itself;
this server is the agent-facing tool over the same voice choice.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

PERSONAL = "Lee Ostadi\u2019s Voice"
FALLBACK = "Aaron Compact"
SAY = "/usr/bin/say"
PROTOCOLS = {
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
}
SPEAK = {
    "name": "speak",
    "description": (
        "Speak text aloud on this Mac with Lee Ostadi's Personal Voice. "
        "Uses Aaron Compact only if that voice does not open. "
        "Empty text is returned and is not spoken."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "The words to speak.",
            }
        },
        "required": ["text"],
        "additionalProperties": False,
    },
}


def speak_with(voice: str, text: str) -> None:
    fd, path = tempfile.mkstemp(prefix="voice-mcp-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        result = subprocess.run(
            [SAY, "-v", voice, "-f", path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(f"say -v {voice} exited {result.returncode}: {detail}")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def speak(text: str) -> dict:
    spoken = text.strip()
    if spoken == "":
        return {
            "ok": True,
            "voice": None,
            "say_exit": None,
            "text": "",
            "personal_error": None,
        }
    try:
        speak_with(PERSONAL, spoken)
    except Exception as error:
        personal_error = str(error)
        print(
            f"voice: {PERSONAL} did not open ({personal_error}); speaking with {FALLBACK}",
            file=sys.stderr,
        )
        try:
            speak_with(FALLBACK, spoken)
        except Exception as fallback_error:
            raise RuntimeError(
                f"{PERSONAL} failed ({personal_error}); {FALLBACK} also failed ({fallback_error})"
            ) from fallback_error
        return {
            "ok": True,
            "voice": FALLBACK,
            "say_exit": 0,
            "text": spoken,
            "personal_error": personal_error,
        }
    return {
        "ok": True,
        "voice": PERSONAL,
        "say_exit": 0,
        "text": spoken,
        "personal_error": None,
    }


def report(result: dict) -> str:
    lines = []
    if result["personal_error"]:
        lines.append(f"personal voice did not open: {result['personal_error']}")
    if result["voice"] is None:
        lines.append("nothing spoken")
    else:
        lines.append(f"spoken with {result['voice']}")
        lines.append(f"say exit {result['say_exit']}")
    lines.append(f"text: {result['text']}")
    return "\n".join(lines)


def send(message: dict) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def reply(request_id, result) -> None:
    send({"jsonrpc": "2.0", "id": request_id, "result": result})


def fail(request_id, code: int, message: str) -> None:
    send({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    })


def tool_error(request_id, message: str) -> None:
    reply(request_id, {
        "content": [{"type": "text", "text": message}],
        "isError": True,
    })


def handle(message: dict) -> None:
    method = message.get("method")
    request_id = message.get("id", None)
    params = message.get("params") or {}
    if not isinstance(params, dict):
        params = {}
    if request_id is None:
        return
    if method == "initialize":
        requested = params.get("protocolVersion")
        protocol = requested if requested in PROTOCOLS else "2024-11-05"
        reply(request_id, {
            "protocolVersion": protocol,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "voice", "version": "0.1.0"},
        })
        return
    if method == "ping":
        reply(request_id, {})
        return
    if method == "tools/list":
        reply(request_id, {"tools": [SPEAK]})
        return
    if method == "tools/call":
        if params.get("name") != "speak":
            tool_error(request_id, "unknown tool")
            return
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict) or not isinstance(arguments.get("text"), str):
            tool_error(request_id, "speak requires a string argument named text")
            return
        try:
            result = speak(arguments["text"])
        except Exception as error:
            tool_error(request_id, str(error))
            return
        reply(request_id, {
            "content": [{"type": "text", "text": report(result)}],
            "isError": False,
        })
        return
    fail(request_id, -32601, f"method not found: {method}")


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            send({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "parse error"},
            })
            continue
        if isinstance(message, dict):
            handle(message)
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    raise SystemExit(main())
