"""Receipt boundaries for the native original-source component publisher."""
import json
from pathlib import Path
import tempfile
import unittest

from build_component import identity
from build_native import completed, object_paths


class NativeComponentReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="u9fs-receipt-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "lowered").mkdir()

    def test_object_bytes_must_remain_bound_to_compiler_receipt(self):
        obj = self.root / "module.o"
        obj.write_bytes(b"compiler-owned-test-object")
        coverage = {"units": [{"required_for_lowering": True, "verified": True,
                               "lowered": True, "object": identity(obj)}]}
        self.assertEqual(object_paths(coverage), [obj])
        obj.write_bytes(b"different-object")
        with self.assertRaisesRegex(ValueError, "differs from its compiler receipt"):
            object_paths(coverage)

    def test_unverified_object_is_never_published(self):
        coverage = {"units": [{"required_for_lowering": True, "verified": False,
                               "lowered": True}]}
        with self.assertRaisesRegex(ValueError, "unverified unit"):
            object_paths(coverage)

    def test_successful_capture_cannot_hide_incomplete_native_dependency(self):
        recipe = {key: True for key in ("success", "capture_complete", "lowering_complete")}
        coverage = {key: True for key in ("capture_complete", "module_set_complete",
                    "native_module_dependency_closure_complete", "symbol_closure_complete")}
        (self.root / "source-recipe.json").write_text(json.dumps(recipe))
        for field in coverage:
            with self.subTest(field=field):
                (self.root / "lowered/coverage.json").write_text(json.dumps({**coverage, field: False}))
                with self.assertRaisesRegex(ValueError, "closure did not complete"):
                    completed(self.root)


if __name__ == "__main__":
    unittest.main()
