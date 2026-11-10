"""Image admission must follow the artifact actually compiled into the kernel."""

import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bind_image", ROOT / "ocore/kernel/bind-image.py")
binder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binder)


class KernelImageBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def image(self, data):
        path = Path(self.tmp.name) / f"root-{hashlib.sha256(data).hexdigest()}.ovfs"
        path.write_bytes(data)
        return path

    def test_m5_size_and_both_digest_representations_track_rebuild(self):
        source = (ROOT / "ocore/kernel/m5.oc").read_text()
        for data in (b"a" * 57960, b"b" * 62056):
            with self.subTest(size=len(data)):
                output, identity = binder.bind(source, self.image(data), "IMAGE_", 65536, True)
                constants = dict(re.findall(r"const (\w+): (?:usize|u64) = (\d+);", output))
                self.assertEqual(int(constants["IMAGE_LENGTH"]), len(data))
                raw = b"".join(int(constants[f"IMAGE_DIGEST_{i}"]).to_bytes(8, "little") for i in range(4))
                command = "".join(f"{int(constants[f'COMMAND_DIGEST_{i}']):016x}" for i in range(4))
                self.assertEqual(raw, hashlib.sha256(data).digest())
                self.assertEqual(command, identity["sha256"])

    def test_linux_binding_preserves_other_image_profiles(self):
        source = (ROOT / "ocore/kernel/m6_linux.oc").read_text()
        output, _ = binder.bind(source, self.image(b"linux"), "LINUX_IMAGE_", 65536)
        self.assertIn("const LINUX_IMAGE_LENGTH: usize = 5;", output)
        before = re.findall(r"^const (?:M7|BOUNDED)_IMAGE_.*", source, re.M)
        after = re.findall(r"^const (?:M7|BOUNDED)_IMAGE_.*", output, re.M)
        self.assertEqual(before, after)

    def test_m7_cli_accepts_numeric_prefix_and_writes_identity(self):
        output = Path(self.tmp.name) / "m6.oc"
        result = subprocess.run([
            sys.executable, str(ROOT / "ocore/kernel/bind-image.py"),
            str(ROOT / "ocore/kernel/m6_linux.oc"), str(self.image(b"m7")),
            str(output), "--prefix", "M7_IMAGE_", "--capacity", "98304",
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("const M7_IMAGE_LENGTH: usize = 2;", output.read_text())
        self.assertTrue(output.with_suffix(".image.json").is_file())

    def test_m4_uses_linker_length_with_current_digest(self):
        source = (ROOT / "ocore/kernel/m4.oc").read_text()
        output, identity = binder.bind(source, self.image(b"m4"), "IMAGE_", 65536,
                                       linker_length=True)
        self.assertNotIn("const IMAGE_LENGTH", output)
        self.assertEqual(identity["bytes"], 2)
        self.assertIn("image_end - image_start", output)

    def test_tampered_content_is_rejected(self):
        image = self.image(b"original")
        image.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "content-addressed"):
            binder.bind("", image, "IMAGE_", 65536)

    def test_capacity_and_template_drift_fail_closed(self):
        for data in (b"", b"x" * 65537):
            with self.assertRaisesRegex(ValueError, "capacity"):
                binder.bind("", self.image(data), "IMAGE_", 65536)
        source = (ROOT / "ocore/kernel/m5.oc").read_text()
        for changed in (source.replace("const IMAGE_LENGTH:", "const OLD_LENGTH:"),
                        source + "\nconst IMAGE_LENGTH: usize = 1;\n"):
            with self.assertRaisesRegex(ValueError, "exactly one IMAGE_LENGTH"):
                binder.bind(changed, self.image(b"valid"), "IMAGE_", 65536, True)


if __name__ == "__main__":
    unittest.main()
