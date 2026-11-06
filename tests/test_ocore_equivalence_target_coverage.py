"""Canonical target changes must not silently shrink conformance coverage."""
import sys
from pathlib import Path
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.check_ocore_native_equivalence import TARGETS, TARGET_CATALOG, canonical_target_coverage


class CanonicalTargetCoverageControls(unittest.TestCase):
    def test_actual_compiler_catalog_matches_execution_profiles(self):
        result = canonical_target_coverage()
        self.assertEqual(set(result["canonical_targets"]), {profile[0] for profile in TARGETS.values()})

    def test_missing_existing_backend_profile_fails(self):
        profiles = dict(TARGETS)
        profiles.pop(next(iter(profiles)))
        with self.assertRaisesRegex(RuntimeError, "coverage differs: missing="):
            canonical_target_coverage(profiles)

    def test_new_canonical_backend_without_execution_profile_fails(self):
        # Synthetic source-catalog mutation only; this adds no compiler backend.
        source = TARGET_CATALOG.read_text()
        row = '''    FutureIsaUnknownNone {
        id: "future-isa", architecture: "future-isa",
        name: "future-isa-unknown-none", triple: "future-isa-unknown-none-elf", aliases: []
    },
'''
        changed = source.replace("define_targets! {\n", "define_targets! {\n"+row, 1)
        self.assertNotEqual(source, changed, "catalog fixture did not change the actual macro")
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "common.rs"
            catalog.write_text(changed)
            with self.assertRaisesRegex(RuntimeError, "future-isa-unknown-none"):
                canonical_target_coverage(catalog=catalog)

    def test_unknown_or_partial_macro_rows_and_duplicate_declarations_fail_closed(self):
        source = TARGET_CATALOG.read_text()
        changes = [
            source.replace('id: "rv64gc"', 'id: "x86_64"', 1),
            source.replace('name: "riscv64-unknown-none"', 'name: "x86_64-unknown-none"', 1),
            source.replace('aliases: ["riscv64gc-unknown-none-elf"]', 'aliases: ["x86_64-unknown-none"]', 1),
            source.replace('id: "rv64gc"', 'unknown: "rv64gc"', 1),
            source.replace('triple: "riscv64-unknown-none-elf",', '', 1),
            source.replace('aliases: ["riscv64gc-unknown-none-elf"]', 'aliases: ["a" "b"]', 1),
            source.replace('    Riscv64UnknownNone {', '    },\n    Riscv64UnknownNone {', 1),
        ]
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "common.rs"
            for mutated in changes:
                self.assertNotEqual(source, mutated)
                catalog.write_text(mutated)
                with self.subTest(source=mutated), self.assertRaises(RuntimeError):
                    canonical_target_coverage(catalog=catalog)

    def test_historical_literal_enum_form_still_requires_exact_coverage(self):
        source = "pub enum Target {\n"+"".join(f" V{i},\n" for i in range(len(TARGETS)))+"}\n"
        source += "pub const fn name(self) -> &'static str { match self {\n"
        source += "".join(f' Target::V{i} => "{row[0]}",\n' for i, row in enumerate(TARGETS.values()))+"} }\n"
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "common.rs"
            catalog.write_text(source)
            self.assertEqual(len(canonical_target_coverage(catalog=catalog)["canonical_targets"]), len(TARGETS))
            with self.assertRaisesRegex(RuntimeError, "coverage differs"):
                canonical_target_coverage(dict(list(TARGETS.items())[:-1]), catalog=catalog)


if __name__ == "__main__":
    unittest.main()
