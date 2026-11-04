"""Keep host smoke expectations and native OVFS admission pins in agreement."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "ocore" / "kernel"


def shell_value(source: str, name: str) -> str:
    match = re.search(rf'^{name}="?([0-9a-f]+)"?$', source, re.MULTILINE)
    if match is None:
        raise AssertionError(f"missing fixed shell pin {name}")
    return match[1]


def native_constants(source: str) -> dict[str, int]:
    return {
        name: int(value.replace("_", ""), 0)
        for name, value in re.findall(
            r"^const (\w+): (?:u64|usize) = (0x[0-9a-f_]+|[0-9_]+);$",
            source,
            re.MULTILINE,
        )
    }


class OvfsPinTests(unittest.TestCase):
    def test_host_and_kernel_pin_the_same_artifact(self):
        cases = (
            ("smoke-loader-qemu.sh", "DIGEST", "m4.oc", "IMAGE", "IMAGE_SHA"),
            ("smoke-live-qemu.sh", "DIGEST", "m5.oc", "IMAGE", "COMMAND_DIGEST"),
            ("smoke-personality-qemu.sh", "DIGEST", "m6.oc", "IMAGE", "IMAGE_SHA"),
            ("smoke-personality-qemu.sh", "DIGEST", "m6_linux.oc", "IMAGE", "IMAGE_SHA"),
            ("smoke-live-bounded-personality-qemu.sh", "DIGEST", "m6.oc", "BOUNDED_IMAGE", "BOUNDED_IMAGE_SHA"),
            ("smoke-live-bounded-personality-qemu.sh", "DIGEST", "m6_linux.oc", "BOUNDED_IMAGE", "BOUNDED_IMAGE_SHA"),
            ("smoke-live-linux-personality-qemu.sh", "DIGEST", "m6_linux.oc", "LINUX_IMAGE", "LINUX_IMAGE_SHA"),
            ("smoke-live-linux-plan9-qemu.sh", "IMAGE_DIGEST", "m6_linux.oc", "M7_IMAGE", "M7_IMAGE_SHA"),
            ("smoke-m7b-logical-read-qemu.sh", "IMAGE_DIGEST", "m7b_logical_read.oc", "IMAGE", "IMAGE_SHA"),
        )
        for script, digest_name, native, prefix, sha_prefix in cases:
            with self.subTest(script=script, native=native, prefix=prefix):
                host = (KERNEL / script).read_text()
                expected = bytes.fromhex(shell_value(host, digest_name))
                self.assertEqual(len(expected), 32)
                constants = native_constants((KERNEL / native).read_text())
                raw_digest = b"".join(
                    constants[f"{prefix}_DIGEST_{i}"].to_bytes(8, "little")
                    for i in range(4)
                )
                sha_digest = b"".join(
                    constants[f"{sha_prefix}_{i}"].to_bytes(8, "big")
                    for i in range(4)
                )
                self.assertEqual(raw_digest, expected)
                self.assertEqual(sha_digest, expected)
                self.assertEqual(constants[f"{prefix}_ID"], int.from_bytes(expected[:8], "big"))
                # M4 admits the actual bounded image span; all later modes also
                # pin its length natively. Every host pins the artifact length.
                image_bytes = int(shell_value(host, "IMAGE_BYTES"))
                self.assertGreater(image_bytes, 0)
                if native != "m4.oc":
                    self.assertEqual(constants[f"{prefix}_LENGTH"], image_bytes)

    def test_record_preflight_rejects_drift_before_boot(self):
        scripts = (
            "smoke-loader-qemu.sh",
            "smoke-personality-qemu.sh",
            "smoke-live-bounded-personality-qemu.sh",
        )
        for script in scripts:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                image = directory / "admitted.ovfs"
                image.write_bytes(b"pinned artifact\n")
                record = directory / "image.path"
                record.write_text(f"{image}\n")
                source = (KERNEL / script).read_text()
                start = source.index('if [[ ! -f "$IMAGE_RECORD" ]]')
                message = source.index("artifact identity is not canonical", start)
                end = source.index("\nfi\n", message) + len("\nfi\n")
                preflight = source[start:end]
                env = {
                    **os.environ,
                    "IMAGE_RECORD": str(record),
                    "IMAGE_BYTES": str(image.stat().st_size),
                    "DIGEST": hashlib.sha256(image.read_bytes()).hexdigest(),
                }

                def run_preflight():
                    return subprocess.run(
                        ["bash", "-euc", preflight],
                        env=env,
                        text=True,
                        capture_output=True,
                        check=False,
                    )

                self.assertEqual(run_preflight().returncode, 0)
                # A still-present old artifact must not hide a different image
                # selected by the current build's .incbin path record.
                changed = directory / "changed.ovfs"
                changed.write_bytes(b"changed payload\n")
                self.assertEqual(changed.stat().st_size, image.stat().st_size)
                record.write_text(f"{changed}\n")
                self.assertNotEqual(run_preflight().returncode, 0)
                record.write_text(f"{image}\n")
                image.write_bytes(image.read_bytes() + b"extra")
                self.assertNotEqual(run_preflight().returncode, 0)
                record.write_text(f"{image}\n{image}\n")
                self.assertNotEqual(run_preflight().returncode, 0)
                record.unlink()
                self.assertNotEqual(run_preflight().returncode, 0)

    def test_m5_rejects_build_digest_different_from_native_pin(self):
        source = (KERNEL / "smoke-live-qemu.sh").read_text()
        start = source.index('if [[ -z "$IMAGE"')
        message = source.index("artifact identity is not canonical", start)
        end = source.index("\nfi\n", message) + len("\nfi\n")
        with tempfile.TemporaryDirectory() as tmp:
            payload = b"rebuilt but unadmitted image\n"
            digest = hashlib.sha256(payload).hexdigest()
            image = Path(tmp) / f"root-{digest}.ovfs"
            image.write_bytes(payload)
            result = subprocess.run(
                ["bash", "-euc", source[start:end]],
                env={
                    **os.environ,
                    "IMAGE": str(image),
                    "IMAGE_BYTES": str(len(payload)),
                    "DIGEST": shell_value(source, "DIGEST"),
                    "BUILD_DIGEST": digest,
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("artifact identity is not canonical", result.stderr)


if __name__ == "__main__":
    unittest.main()
