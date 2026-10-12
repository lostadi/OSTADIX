"""Verify actual XML importability, including HTML's non-XML regex characters."""

import importlib.util
import json
from pathlib import Path
import plistlib
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ostadix_textmate_export", HERE / "textmate_export.py")
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)


class TextMateExportTests(unittest.TestCase):
    def test_forbidden_regex_characters_survive_xml_import_as_oniguruma_escapes(self):
        original = {"patterns": [{"match": "[a\x00\x0c\ufffe\uffff]"}]}
        restored = plistlib.loads(plistlib.dumps(export.xml_safe(original)))
        self.assertEqual(restored["patterns"][0]["match"], r"[a\x{0}\x{C}\x{FFFE}\x{FFFF}]")
        self.assertEqual(original["patterns"][0]["match"], "[a\x00\x0c\ufffe\uffff]")

    def test_shipped_sublime_grammars_parse_with_complete_scope_inventory(self):
        package = json.loads((HERE / "vscode/package.json").read_text())
        expected = {row["scopeName"] for row in package["contributes"]["grammars"]}
        actual = set()
        for path in (HERE / "sublime").glob("*.tmLanguage"):
            grammar = plistlib.loads(path.read_bytes())
            actual.add(grammar["scopeName"])
            if grammar["scopeName"] == "source.ostadix":
                self.assertEqual(grammar["fileTypes"], ["O", "olang"])
            else:
                self.assertNotIn("fileTypes", grammar)
                self.assertNotIn("firstLineMatch", grammar)
        self.assertSetEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
