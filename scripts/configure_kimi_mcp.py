#!/usr/bin/env python3
"""Idempotently register Ostadix and its Lean toolchain for Kimi Code."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile


def configure(settings_path: Path, command: Path, root: Path, lean: Path | None) -> bool:
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SystemExit(f"refusing to modify invalid Kimi MCP settings: {error}")
        if not isinstance(settings, dict):
            raise SystemExit("refusing to modify Kimi MCP settings that are not a JSON object")
    else:
        settings = {}

    servers = settings.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise SystemExit("refusing to replace non-object Kimi mcpServers settings")

    root = root.resolve()
    environment = {
        "O_LANG_ROOT": os.fspath(root),
        "O_BACKENDS_DIR": os.fspath(root / "backends"),
    }
    if lean is not None:
        environment["OSTADIX_LEAN"] = os.fspath(lean.resolve())
    desired = {
        "command": os.fspath(command.resolve()),
        "args": [],
        "cwd": os.fspath(root),
        "env": environment,
    }
    if servers.get("ostadix") == desired:
        return False
    servers["ostadix"] = desired

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{settings_path.name}.", dir=settings_path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(settings, output, indent=2, sort_keys=False)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, settings_path)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--command", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--lean", type=Path)
    arguments = parser.parse_args()
    changed = configure(
        arguments.settings, arguments.command, arguments.root, arguments.lean
    )
    print(f"Kimi MCP registration: {'updated' if changed else 'already current'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
