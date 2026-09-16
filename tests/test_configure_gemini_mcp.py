"""Tests for the idempotent Gemini MCP registration helper."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "configure_gemini_mcp.py"


class ConfigureGeminiMcpTests(unittest.TestCase):
    def test_preserves_existing_settings_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = root / ".gemini" / "settings.json"
            settings.parent.mkdir()
            settings.write_text(
                json.dumps({"security": {"auth": {"selectedType": "key"}},
                            "mcpServers": {"other": {"command": "other"}}}),
                encoding="utf-8",
            )
            command = root / "bin" / "ostadix-mcp"
            command.parent.mkdir()
            command.touch()

            first = subprocess.run(
                [sys.executable, str(SCRIPT), "--settings", str(settings),
                 "--command", str(command)],
                text=True, capture_output=True, check=True,
            )
            second = subprocess.run(
                [sys.executable, str(SCRIPT), "--settings", str(settings),
                 "--command", str(command)],
                text=True, capture_output=True, check=True,
            )
            configured = json.loads(settings.read_text(encoding="utf-8"))

        self.assertEqual(configured["security"]["auth"]["selectedType"], "key")
        self.assertEqual(configured["mcpServers"]["other"]["command"], "other")
        self.assertEqual(
            configured["mcpServers"]["ostadix"],
            {"command": str(command.resolve()), "args": []},
        )
        self.assertIn("updated", first.stdout)
        self.assertIn("already current", second.stdout)

    def test_refuses_invalid_existing_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = root / "settings.json"
            settings.write_text("not json", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--settings", str(settings),
                 "--command", str(root / "ostadix-mcp")],
                text=True, capture_output=True, check=False,
            )
            original = settings.read_text(encoding="utf-8")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(original, "not json")


if __name__ == "__main__":
    unittest.main()
