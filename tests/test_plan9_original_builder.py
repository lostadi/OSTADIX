"""Admission and failure guards for the isolated original-toolchain builder."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_okernel_plan9_original.py"
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("original_plan9_builder", SCRIPT)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class OriginalBuilderAdmissionTests(unittest.TestCase):
    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "existing"
            output.mkdir()
            sentinel = output / "keep"
            sentinel.write_bytes(b"existing user files")
            result = subprocess.run([sys.executable, str(SCRIPT), "--output", str(output)], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(sentinel.read_bytes(), b"existing user files")
            self.assertEqual(list(output.iterdir()), [sentinel])

    def test_unpinned_image_stops_before_any_vm_or_external_tool(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "bin"
            binary.mkdir()
            # Tool discovery succeeds, but executing any tool would fail.
            for name in ["qemu-system-aarch64", "qemu-img", "dtc", "clang", "llvm-objcopy", "mkfs.fat", "mcopy"]:
                (binary / name).symlink_to("/usr/bin/false")
            source = root / "untrusted.qcow2"
            source.write_bytes(b"unadmitted image with no execution authority")
            output = root / "new"
            result = subprocess.run([sys.executable, str(SCRIPT), "--image", str(source), "--output", str(output)],
                                    env=dict(os.environ, PATH=str(binary)), capture_output=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            receipt = json.loads((output / "result.json").read_text())
            self.assertFalse(receipt["passed"])
            self.assertIn("explicit observed build12115 pin", receipt["error"])
            self.assertFalse((output / "baseline").exists())
            self.assertEqual(source.read_bytes(), b"unadmitted image with no execution authority")

    def test_platform_patch_rejects_unverified_source(self):
        for source in [b"", b"static Uart qemuuart = {", b"not the admitted original driver"]:
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "pinned unmodified"):
                builder.patched_uart(source)

    def test_both_native_build_profiles_render_valid_fixed_clock_commands(self):
        # Regression: Python interpolation must preserve the original rc
        # command substitutions, rather than trying to evaluate `date` itself.
        for patched in [False, True]:
            script = builder.guest_script("testnonce", patched)
            self.assertIn("echo KW_CLOCK_1 `{date -n}", script)
            self.assertIn("echo KW_CLOCK_2 `{date -n}", script)
            self.assertIn("mk 'CONF=qemu'", script)


if __name__ == "__main__":
    unittest.main()
