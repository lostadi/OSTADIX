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
        source = source.replace("    Riscv64UnknownNone,\n", "    Riscv64UnknownNone,\n    FutureIsaUnknownNone,\n", 1)
        source = source.replace('            Target::Riscv64UnknownNone => "riscv64-unknown-none",',
                                '            Target::Riscv64UnknownNone => "riscv64-unknown-none",\n            Target::FutureIsaUnknownNone => "future-isa-unknown-none",', 1)
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "common.rs"
            catalog.write_text(source)
            with self.assertRaisesRegex(RuntimeError, "future-isa-unknown-none"):
                canonical_target_coverage(catalog=catalog)


if __name__ == "__main__":
    unittest.main()
