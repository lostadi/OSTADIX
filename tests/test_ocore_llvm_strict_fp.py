"""Keep strict floating-environment requirements explicit and fail closed.

These are capability-boundary tests, not evidence of floating-point lowering.
The original musl vfprintf unit requires both strictfp and constrained f80
operations with dynamic rounding; stripping an attribute cannot qualify it.
"""
import hashlib
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory


class StrictFloatingPointTests(unittest.TestCase):
    setUpClass = classmethod(baseline.LlvmImportTests.setUpClass.__func__)
    setUp = baseline.LlvmImportTests.setUp
    write = baseline.LlvmImportTests.write

    def assert_rejected_text_and_bitcode(self, body, fragments, *, text_only=False):
        for triple in baseline.TRIPLES:
            source = self.write(body, triple=triple)
            paths = (source,) if text_only else (
                source, memory.LlvmMemoryImportTests.bitcode(self, source))
            for path in paths:
                with self.subTest(triple=triple, format=path.suffix):
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(path, library_path=self.library,
                                               expected_sha256=self.library_sha256)
                    self.assertEqual(raised.exception.stage, "import")
                    for fragment in fragments:
                        self.assertIn(fragment, str(raised.exception))

    def test_strictfp_integer_signature_does_not_imply_environment_support(self):
        self.assert_rejected_text_and_bitcode('''
define i32 @formatting_entry(ptr %stream, ptr %format, ptr %args) strictfp {
  ret i32 0
}
''', ("strictfp function attribute", "dynamic rounding mode", "exception state",
      "cannot be erased"))

    def test_strictfp_callsite_cannot_hide_behind_an_integer_result(self):
        # LLVM 22 serializes away this standalone callsite flag when its
        # containing function is not strictfp. Exercise the actual text-site
        # contract here; function attributes are covered in both formats.
        self.assert_rejected_text_and_bitcode('''
declare i32 @formatting_provider(ptr)
define i32 @formatting_entry(ptr %args) {
  %r = call i32 @formatting_provider(ptr %args) strictfp
  ret i32 %r
}
''', ("strictfp callsite attribute", "floating value/ABI", "fixed-rounding"), text_only=True)

    def test_constrained_dynamic_rounding_remains_explicit_unsupported(self):
        self.assert_rejected_text_and_bitcode('''
declare double @llvm.experimental.constrained.fadd.f64(double, double, metadata, metadata)
define double @add(double %x, double %y) strictfp {
  %r = call double @llvm.experimental.constrained.fadd.f64(double %x, double %y,
    metadata !"round.dynamic", metadata !"fpexcept.strict") strictfp
  ret double %r
}
''', ("constrained floating-point intrinsic", "rounding-mode", "exception-behavior"))

    def test_existing_integer_admission_and_source_identity_are_preserved(self):
        for triple in baseline.TRIPLES:
            source = self.write('''
define i32 @integer_only(i32 %value) nounwind {
  %r = add i32 %value, 1
  ret i32 %r
}
''', triple=triple)
            module = importer.import_module(source, library_path=self.library,
                                            expected_sha256=self.library_sha256)
            self.assertEqual(module["provenance"]["input_sha256"],
                             hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(module["functions"][0]["name"], "integer_only")


if __name__ == "__main__":
    unittest.main()
