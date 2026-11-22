"""Tests for Kimi MCP registration with explicit Lean discovery."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "configure_kimi_mcp.py"


class ConfigureKimiMcpTests(unittest.TestCase):
    def invoke(self, settings: Path, command: Path, root: Path, lean: Path | None = None) -> subprocess.CompletedProcess[str]:
        arguments = [
            sys.executable,
            str(SCRIPT),
            "--settings",
            str(settings),
            "--command",
            str(command),
            "--root",
            str(root),
        ]
        if lean is not None:
            arguments.extend(("--lean", str(lean)))
        return subprocess.run(arguments, text=True, capture_output=True, check=True)

    def test_preserves_settings_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            settings = fixture / ".kimi-code" / "mcp.json"
            settings.parent.mkdir()
            settings.write_text(
                json.dumps({"theme": "dark", "mcpServers": {"other": {"command": "other"}}}),
                encoding="utf-8",
            )
            command = fixture / "bin" / "ostadix-mcp"
            lean = fixture / "lean" / "bin" / "lean"
            command.parent.mkdir()
            lean.parent.mkdir(parents=True)
            command.touch()
            lean.touch()

            first = self.invoke(settings, command, fixture, lean)
            second = self.invoke(settings, command, fixture, lean)
            configured = json.loads(settings.read_text(encoding="utf-8"))

        self.assertEqual(configured["theme"], "dark")
        self.assertEqual(configured["mcpServers"]["other"], {"command": "other"})
        self.assertEqual(
            configured["mcpServers"]["ostadix"],
            {
                "command": str(command.resolve()),
                "args": [],
                "cwd": str(fixture.resolve()),
                "env": {
                    "O_LANG_ROOT": str(fixture.resolve()),
                    "O_BACKENDS_DIR": str((fixture / "backends").resolve()),
                    "OSTADIX_LEAN": str(lean.resolve()),
                },
            },
        )
        self.assertIn("updated", first.stdout)
        self.assertIn("already current", second.stdout)

    def test_omitting_lean_removes_a_stale_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            settings = fixture / "mcp.json"
            self.invoke(settings, fixture / "mcp", fixture, fixture / "lean")
            self.invoke(settings, fixture / "mcp", fixture)
            environment = json.loads(settings.read_text(encoding="utf-8"))["mcpServers"]["ostadix"]["env"]
        self.assertNotIn("OSTADIX_LEAN", environment)

    def test_refuses_invalid_existing_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            settings = fixture / "mcp.json"
            settings.write_text("not json", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--settings",
                    str(settings),
                    "--command",
                    str(fixture / "mcp"),
                    "--root",
                    str(fixture),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            original = settings.read_text(encoding="utf-8")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(original, "not json")


if __name__ == "__main__":
    unittest.main()
