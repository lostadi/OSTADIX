"""Exercise host preflights against actual generated native image bindings.

The dynamic fixtures are opaque image/principal bytes, not executable programs.
The real binder CLI and unchanged shell/Python preflight blocks execute; no
compiler or VM runs, and structural OVFS/ELF/runtime gates remain separate.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "ocore/kernel"


def shell_value(source: str, name: str) -> str:
    match = re.search(rf'^{name}="?([0-9a-f]+)"?$', source, re.MULTILINE)
    if match is None:
        raise AssertionError(f"missing independent shell pin {name}")
    return match[1]


def native_constants(source: str) -> dict[str, int]:
    return {name: int(value.replace("_", ""), 0) for name, value in re.findall(
        r"^const (\w+): (?:u64|usize) = (0x[0-9a-f_]+|[0-9_]+);$", source, re.MULTILINE)}


# script, source template, binding prefix, command SHA prefix, path record,
# independent historical/current layout sizes, and selected capacity.
DYNAMIC = (
    ("smoke-live-qemu.sh", "m5.oc", "IMAGE", "COMMAND_DIGEST", None, (57960, 62056), 65536),
    ("smoke-personality-qemu.sh", "m6.oc", "IMAGE", "IMAGE_SHA", "m6-image.path", (58320, 62104), 98304),
    ("smoke-live-bounded-personality-qemu.sh", "m6.oc", "BOUNDED_IMAGE", "BOUNDED_IMAGE_SHA", "m6b-live-image.path", (61576, 65152), 98304),
    ("smoke-live-linux-personality-qemu.sh", "m6_linux.oc", "LINUX_IMAGE", "LINUX_IMAGE_SHA", "m6-linux-image.path", (60648, 60104), 65536),
    ("smoke-live-linux-plan9-qemu.sh", "m6_linux.oc", "M7_IMAGE", "M7_IMAGE_SHA", "m7-linux-plan9-image.path", (97512, 92872), 98304),
    ("smoke-m7b-logical-read-qemu.sh", "m7b_logical_read.oc", "IMAGE", "IMAGE_SHA", "m7b-logical-read-image.path", (82400, 78304), 98304),
)
PRINCIPALS = {
    "smoke-live-linux-plan9-qemu.sh": (
        ("ocore-m7-linux-plan9-artifacts", "linux-9pd.elf", "DAEMON"),
        ("ocore-m7-linux-plan9-artifacts", "linux-supervisord.elf", "SUPERVISOR"),
        ("ocore-m7-linux-plan9-artifacts", "plan9-namespace-client.elf", "PLAN9_CLIENT")),
    "smoke-m7b-logical-read-qemu.sh": (
        ("ocore-m7b-logical-read-artifacts", "m7b-logical-read.elf", "CLIENT"),
        ("ocore-m7b-logical-read-artifacts", "m7b-9pd.elf", "PROVIDER")),
}


def preflight(source: str, *, m5: bool = False) -> str:
    # Execute the existing admission block, stopping before the structural or
    # QEMU gate. An unrecognizable boundary fails the test instead of falling
    # back to a rewritten imitation of the production checks.
    start = source.index('IMAGE="$(') if m5 else source.index('if [[ ! -f "$IMAGE_RECORD"')
    message = re.search(r'echo "error: [^\n]*is not canonical', source[start:])
    if message is None:
        raise AssertionError("cannot locate actual image identity preflight")
    end = source.index("\nfi\n", start + message.end()) + len("\nfi\n")
    return source[start:end]


class OvfsPinTests(unittest.TestCase):
    @contextmanager
    def fixture(self, case, size=None):
        script, native, prefix, sha_prefix, record_name, sizes, capacity = case
        with tempfile.TemporaryDirectory(prefix="ovfs pin fixtures ") as temporary:
            directory = Path(temporary)
            build = directory / "kernel build"
            build.mkdir()
            size = sizes[0] if size is None else size
            seed = hashlib.sha256(script.encode()).digest()
            payload = (seed * ((size + len(seed) - 1) // len(seed)))[:size]
            digest = hashlib.sha256(payload).hexdigest()
            image = directory / f"root-{digest}.ovfs"
            image.write_bytes(payload)
            generated = build / ("m5.oc" if record_name is None else "m6.oc")
            command = [sys.executable, "-B", str(KERNEL / "bind-image.py"),
                       str(KERNEL / native), str(image), str(generated),
                       "--prefix", prefix + "_", "--capacity", str(capacity)]
            if record_name is None:
                command.append("--command-digest")
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            metadata = generated.with_suffix(".image.json")
            original_metadata = metadata.read_bytes()
            record = build / record_name if record_name is not None else None
            if record:
                record.write_text(str(image) + "\n")
            principal_fields = []
            for group, name, variable in PRINCIPALS.get(script, ()):
                path = directory / "target" / group / "pass-one" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((name + ": fixture original native identity\n").encode())
                principal_fields.extend((str(path.stat().st_size), hashlib.sha256(path.read_bytes()).hexdigest()))
            env = {**os.environ, "ROOT": str(directory), "BUILD_DIR": str(build),
                   "BUILD_OUTPUT": f"unrelated build diagnostic\nm5-image: {image}\nm5-sha256: {digest}\n",
                   "PYTHONDONTWRITEBYTECODE": "1"}
            if record:
                env["IMAGE_RECORD"] = str(record)
            code = preflight((KERNEL / script).read_text(), m5=record is None)
            digest_name = "IMAGE_DIGEST" if script in PRINCIPALS else "DIGEST"
            fields = ['"$IMAGE"', '"$IMAGE_BYTES"', f'"${digest_name}"']
            for _, _, variable in PRINCIPALS.get(script, ()):
                fields.extend((f'"${variable}_BYTES"', f'"${variable}_DIGEST"'))
            code += "\nprintf '%s\\n' " + " ".join(fields) + "\n"

            def run():
                return subprocess.run(["bash", "-euo", "pipefail", "-c", code], env=env,
                                      capture_output=True, text=True, check=False, timeout=15)

            initial_build_output = env["BUILD_OUTPUT"]

            def reset():
                env["BUILD_OUTPUT"] = initial_build_output
                image.write_bytes(payload)
                metadata.write_bytes(original_metadata)
                if record:
                    record.write_text(str(image) + "\n")

            yield {"case": case, "directory": directory, "build": build, "image": image,
                   "payload": payload, "digest": digest, "generated": generated, "metadata": metadata,
                   "identity": json.loads(original_metadata), "record": record, "environment": env,
                   "principal_fields": principal_fields, "run": run, "reset": reset}

    def assert_native_binding(self, source, prefix, sha_prefix, payload):
        constants = native_constants(source)
        expected = hashlib.sha256(payload).digest()
        self.assertEqual(b"".join(constants[f"{prefix}_DIGEST_{i}"].to_bytes(8, "little")
                                  for i in range(4)), expected)
        self.assertEqual(b"".join(constants[f"{sha_prefix}_{i}"].to_bytes(8, "big")
                                  for i in range(4)), expected)
        self.assertEqual(constants[f"{prefix}_ID"], int.from_bytes(expected[:8], "big"))
        self.assertEqual(constants[f"{prefix}_LENGTH"], len(payload))

    def test_static_m4_host_and_kernel_pin_the_same_artifact(self):
        host = (KERNEL / "smoke-loader-qemu.sh").read_text()
        expected = bytes.fromhex(shell_value(host, "DIGEST"))
        constants = native_constants((KERNEL / "m4.oc").read_text())
        self.assertEqual(len(expected), 32)
        self.assertEqual(b"".join(constants[f"IMAGE_DIGEST_{i}"].to_bytes(8, "little") for i in range(4)), expected)
        self.assertEqual(b"".join(constants[f"IMAGE_SHA_{i}"].to_bytes(8, "big") for i in range(4)), expected)
        self.assertEqual(constants["IMAGE_ID"], int.from_bytes(expected[:8], "big"))
        self.assertGreater(int(shell_value(host, "IMAGE_BYTES")), 0)

    def test_dynamic_host_and_generated_native_bindings_agree_across_layouts(self):
        for case in DYNAMIC:
            for size in case[5]:
                with self.subTest(script=case[0], size=size), self.fixture(case, size) as f:
                    self.assert_native_binding(f["generated"].read_text(), case[2], case[3], f["payload"])
                    result = f["run"]()
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stdout.splitlines(), [str(f["image"]), str(size), f["digest"],
                                                                  *f["principal_fields"]])
                    self.assertEqual(f["identity"], {"image": str(f["image"].resolve()), "bytes": size,
                                                    "sha256": f["digest"]})
                    # Binding one profile cannot silently rewrite other image
                    # profiles or immutable payload identities in its template.
                    before = native_constants((KERNEL / case[1]).read_text())
                    after = native_constants(f["generated"].read_text())
                    changed = {name for name in before if before[name] != after[name]}
                    selected = {case[2] + "_ID", case[2] + "_LENGTH"}
                    selected.update(f"{case[2]}_DIGEST_{i}" for i in range(4))
                    selected.update(f"{case[3]}_{i}" for i in range(4))
                    self.assertTrue(changed <= selected, changed - selected)
                    self.assertEqual({name: value for name, value in before.items() if name not in selected},
                                     {name: value for name, value in after.items() if name not in selected})

    def test_dynamic_preflight_rejects_changed_content_size_and_selected_path(self):
        for case in DYNAMIC:
            with self.subTest(script=case[0]), self.fixture(case) as f:
                for mutation in ("same-size-content", "size", "selected-path", "missing-image"):
                    with self.subTest(mutation=mutation):
                        f["reset"]()
                        if mutation == "same-size-content":
                            f["image"].write_bytes(bytes([f["payload"][0] ^ 1]) + f["payload"][1:])
                        elif mutation == "size":
                            f["image"].write_bytes(f["payload"] + b"extra")
                        elif mutation == "missing-image":
                            f["image"].unlink()
                        else:
                            other = f["directory"] / "another selection.ovfs"
                            other.write_bytes(f["payload"])
                            if f["record"]:
                                f["record"].write_text(str(other) + "\n")
                            else:
                                f["environment"]["BUILD_OUTPUT"] = f"m5-image: {other}\nm5-sha256: {f['digest']}\n"
                        self.assertNotEqual(f["run"]().returncode, 0)

    def test_dynamic_preflight_rejects_missing_or_changed_generated_metadata(self):
        for case in DYNAMIC:
            with self.subTest(script=case[0]), self.fixture(case) as f:
                for mutation in ("path", "size", "digest", "missing", "malformed"):
                    with self.subTest(mutation=mutation):
                        f["reset"]()
                        metadata = dict(f["identity"])
                        if mutation == "path":
                            metadata["image"] += ".different"
                        elif mutation == "size":
                            metadata["bytes"] += 1
                        elif mutation == "digest":
                            metadata["sha256"] = "0" * 64
                        elif mutation == "missing":
                            f["metadata"].unlink()
                        else:
                            f["metadata"].write_text("not JSON\n")
                        if mutation in ("path", "size", "digest"):
                            f["metadata"].write_text(json.dumps(metadata))
                        self.assertNotEqual(f["run"]().returncode, 0)

    def test_one_line_image_records_fail_closed_with_binding_metadata_present(self):
        for case in DYNAMIC[1:]:
            with self.subTest(script=case[0]), self.fixture(case) as f:
                for mutation in ("empty", "multiple", "no-newline", "missing"):
                    with self.subTest(mutation=mutation):
                        f["reset"]()
                        if mutation == "empty":
                            f["record"].write_text("")
                        elif mutation == "multiple":
                            f["record"].write_text((str(f["image"]) + "\n") * 2)
                        elif mutation == "no-newline":
                            f["record"].write_text(str(f["image"]))
                        else:
                            f["record"].unlink()
                        self.assertNotEqual(f["run"]().returncode, 0)

    def test_m5_build_report_and_canonical_filename_must_match_generated_binding(self):
        with self.fixture(DYNAMIC[0]) as f:
            f["environment"]["BUILD_OUTPUT"] = f"m5-image: {f['image']}\nm5-sha256: {'0' * 64}\n"
            self.assertNotEqual(f["run"]().returncode, 0)
            # Even coherent metadata cannot replace M5's independent canonical
            # content-addressed filename check with a differently named file.
            misnamed = f["directory"] / "misnamed.ovfs"
            misnamed.write_bytes(f["payload"])
            metadata = {**f["identity"], "image": str(misnamed)}
            f["metadata"].write_text(json.dumps(metadata))
            f["environment"]["BUILD_OUTPUT"] = f"m5-image: {misnamed}\nm5-sha256: {f['digest']}\n"
            result = f["run"]()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("artifact identity is not canonical", result.stderr)

    def test_actual_binder_rejects_noncanonical_image_names_for_every_profile(self):
        for case in DYNAMIC:
            with self.subTest(script=case[0]), self.fixture(case) as f:
                misnamed = f["directory"] / "not-content-addressed.ovfs"
                misnamed.write_bytes(f["payload"])
                output = f["build"] / "must-not-exist.oc"
                result = subprocess.run([sys.executable, "-B", str(KERNEL / "bind-image.py"),
                                         str(KERNEL / case[1]), str(misnamed), str(output),
                                         "--prefix", case[2] + "_", "--capacity", str(case[6])],
                                        capture_output=True, text=True, check=False, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("content-addressed", result.stderr)
                self.assertFalse(output.exists())
                self.assertFalse(output.with_suffix(".image.json").exists())

    def test_static_foreign_and_immutable_object_pins_remain_independent(self):
        oracle = json.loads((ROOT / "ocore/user/linux-minimal-oracle.json").read_text())["elf"]
        builder = (KERNEL / "build-m6-linux-live-artifacts.sh").read_text()
        for script in ("smoke-live-linux-personality-qemu.sh", "smoke-live-linux-plan9-qemu.sh"):
            host = (KERNEL / script).read_text()
            self.assertEqual(shell_value(host, "LINUX_ELF_DIGEST"), oracle["sha256"])
            self.assertEqual(int(shell_value(host, "LINUX_ELF_BYTES")), oracle["size"])
        self.assertEqual(shell_value(builder, "EXPECTED_GUEST_SHA256"), oracle["sha256"])
        self.assertEqual(int(shell_value(builder, "EXPECTED_GUEST_BYTES")), oracle["size"])
        object_bytes = b"m7b-logical-object!\n"
        host = (KERNEL / "smoke-m7b-logical-read-qemu.sh").read_text()
        constants = native_constants((KERNEL / "m7b_logical_read.oc").read_text())
        self.assertEqual(int(shell_value(host, "OBJECT_BYTES")), len(object_bytes))
        self.assertEqual(shell_value(host, "OBJECT_DIGEST"), hashlib.sha256(object_bytes).hexdigest())
        self.assertEqual(b"".join(constants[f"OBJECT_DIGEST_{i}"].to_bytes(8, "little") for i in range(4)),
                         hashlib.sha256(object_bytes).digest())

    def test_static_m4_record_preflight_still_rejects_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            image = directory / "admitted.ovfs"
            image.write_bytes(b"pinned artifact\n")
            payload = image.read_bytes()
            record = directory / "image.path"
            record.write_text(str(image) + "\n")
            code = preflight((KERNEL / "smoke-loader-qemu.sh").read_text())
            env = {**os.environ, "IMAGE_RECORD": str(record), "IMAGE_BYTES": str(len(payload)),
                   "DIGEST": hashlib.sha256(payload).hexdigest()}
            def run():
                return subprocess.run(["bash", "-euc", code], env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(run().returncode, 0)
            other = directory / "changed.ovfs"
            other.write_bytes(b"changed payload\n")
            self.assertEqual(other.stat().st_size, image.stat().st_size)
            record.write_text(str(other) + "\n")
            self.assertNotEqual(run().returncode, 0)
            record.write_text(str(image) + "\n")
            image.write_bytes(payload + b"extra")
            self.assertNotEqual(run().returncode, 0)
            record.write_text((str(image) + "\n") * 2)
            self.assertNotEqual(run().returncode, 0)
            record.unlink()
            self.assertNotEqual(run().returncode, 0)


if __name__ == "__main__":
    unittest.main()
