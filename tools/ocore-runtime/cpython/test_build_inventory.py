#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("inventory", Path(__file__).with_name("build_inventory.py"))
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def test_disabled_missing_and_forged_inapplicable_extension_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, build = root / "source", root / "build"
            (source / "Modules").mkdir(parents=True)
            build.mkdir()
            (source / "Modules/Setup.stdlib.in").write_text("@MODULE__SQLITE3_TRUE@_sqlite3 module.c\n")
            (build / "config.log").write_text("original configure\n")
            for state in ("disabled", "missing", "n/a"):
                (build / "Makefile").write_text(f"MACHDEP=linux\nMODULE__SQLITE3_STATE={state}\n")
                with self.assertRaises(ValueError):
                    inventory.profile(source, build)
            (build / "Makefile").write_text("MACHDEP=linux\nMODULE__SQLITE3_STATE=yes\n")
            self.assertTrue(inventory.profile(source, build)["applicable_modules_enabled"])

    def test_missing_declared_module_cannot_disappear_from_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source/Modules").mkdir(parents=True)
            (root / "build").mkdir()
            (root / "source/Modules/Setup.stdlib.in").write_text("@MODULE__TKINTER_TRUE@_tkinter module.c\n")
            (root / "build/Makefile").write_text("MACHDEP=linux\nMODULE_MATH_STATE=yes\n")
            with self.assertRaisesRegex(ValueError, "absent"):
                inventory.profile(root / "source", root / "build")

    def test_include_cache_depfile_and_output_are_not_translation_units(self):
        command = ("if test 1; then /capture/cc -include-pch /input/header.c "
                   "-MF /tmp/dependency.c -c /source/a.c -o /out/shared.o; fi; "
                   "/capture/cxx -c /source/assembly.S -o /out/assembly.o")
        self.assertEqual(inventory.compiler_sources(command, Path("/build"), "/capture/cc", "/capture/cxx"),
                         ["/source/a.c", "/source/assembly.S"])


if __name__ == "__main__":
    unittest.main()
