"""Keep editor routing aligned with the registered hosted backend surface."""

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
LANGUAGES = json.loads((Path(__file__).with_name("languages.json")).read_text())


class LanguageRoutingTests(unittest.TestCase):
    def test_catalog_has_exactly_one_highlighting_family_per_tag(self):
        source = (ROOT / LANGUAGES["catalog"]).read_text().split("backend_catalog!", 1)[1]
        expected = []
        for name, aliases in re.findall(r'name: "([^"]+)",\s*aliases: \[([^]]*)\]', source):
            expected.append(name)
            expected.extend(re.findall(r'"([^"]+)"', aliases))
        actual = [tag for family in LANGUAGES["languages"] for tag in family["tags"]]
        self.assertCountEqual(actual, expected)
        self.assertEqual(len(actual), len(set(actual)))
        self.assertEqual(len({row["key"] for row in LANGUAGES["languages"]}),
                         len(LANGUAGES["languages"]))

    def test_platform_bodies_and_native_lisp_use_the_executed_language(self):
        families = {tag: row["key"] for row in LANGUAGES["languages"] for tag in row["tags"]}
        self.assertEqual(families["nixos_test"], "nix")
        self.assertEqual(families["ubuntu_vm"], "shell")
        self.assertEqual(families["ubuntu"], "shell")
        self.assertEqual(families["lisp"], "lisp")
        self.assertEqual(families["common_lisp"], "lisp")
        self.assertNotEqual(families["racket"], families["lisp"])


if __name__ == "__main__":
    unittest.main()
