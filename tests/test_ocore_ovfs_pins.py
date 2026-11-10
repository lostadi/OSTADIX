"""Exercise host preflights against actual generated native image bindings.

The dynamic fixtures are opaque image/principal bytes, not executable programs.
The real binder CLI, generated-source/record verifier and merged shell/Python
preflight blocks execute. No compiler or VM runs; structural payload and
runtime admission remain separately bounded.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
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
SPEC = importlib.util.spec_from_file_location("bind_image", KERNEL / "bind-image.py")
binder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binder)

# Incoming per-build source/metadata/exact-link-record profiles.
PROFILES = (
    ("smoke-loader-qemu.sh", "m4", "m4.oc", "IMAGE_", 65536,
     ("--linker-length",), "m4-image.path"),
    ("smoke-live-qemu.sh", "m5", "m5.oc", "IMAGE_", 65536,
     ("--command-digest",), "m5-image.path"),
    ("smoke-personality-qemu.sh", "m6", "m6.oc", "IMAGE_", 98304,
     (), "m6-image.path"),
    ("smoke-live-bounded-personality-qemu.sh", "m6", "m6.oc", "BOUNDED_IMAGE_", 98304,
     (), "m6b-live-image.path"),
    ("smoke-live-linux-personality-qemu.sh", "m6", "m6_linux.oc", "LINUX_IMAGE_", 65536,
     (), "m6-linux-image.path"),
    ("smoke-live-linux-plan9-qemu.sh", "m6", "m6_linux.oc", "M7_IMAGE_", 98304,
     (), "m7-linux-plan9-image.path"),
    ("smoke-m7b-logical-read-qemu.sh", "m6", "m7b_logical_read.oc", "IMAGE_", 98304,
     (), "m7b-logical-read-image.path"),
)



def shell_value(source: str, name: str) -> str:
    match = re.search(rf'^{name}="?([0-9a-f]+)"?$', source, re.MULTILINE)
    if match is None:
        raise AssertionError(f"missing independent shell pin {name}")
    return match[1]


def native_constants(source: str) -> dict[str, int]:
    return {name: int(value.replace("_", ""), 0) for name, value in re.findall(
        r"^const (\w+): (?:u64|usize) = (0x[0-9a-f_]+|[0-9_]+);$", source, re.MULTILINE)}


# script, source template, binding prefix, command SHA prefix, path record,
# historical/current layout sizes (plus two M4 bounded sizes), and selected capacity.
DYNAMIC = (
    ("smoke-live-qemu.sh", "m5.oc", "IMAGE", "COMMAND_DIGEST", None, (57960, 62056), 65536),
    ("smoke-personality-qemu.sh", "m6.oc", "IMAGE", "IMAGE_SHA", "m6-image.path", (58320, 62104), 98304),
    ("smoke-live-bounded-personality-qemu.sh", "m6.oc", "BOUNDED_IMAGE", "BOUNDED_IMAGE_SHA", "m6b-live-image.path", (61576, 65152), 98304),
    ("smoke-live-linux-personality-qemu.sh", "m6_linux.oc", "LINUX_IMAGE", "LINUX_IMAGE_SHA", "m6-linux-image.path", (60648, 60104), 65536),
    ("smoke-live-linux-plan9-qemu.sh", "m6_linux.oc", "M7_IMAGE", "M7_IMAGE_SHA", "m7-linux-plan9-image.path", (97512, 92872), 98304),
    ("smoke-m7b-logical-read-qemu.sh", "m7b_logical_read.oc", "IMAGE", "IMAGE_SHA", "m7b-logical-read-image.path", (82400, 78304), 98304),
    ("smoke-loader-qemu.sh", "m4.oc", "IMAGE", "IMAGE_SHA", "m4-image.path", (4096, 8192), 65536),
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
    # Run the actual admission/principal lookup blocks and stop before any
    # structural verifier, compiler, or QEMU launch. Exact boundaries fail closed.
    start = source.index('IMAGE="$(') if m5 else source.index('if [[ ! -f "$IMAGE_RECORD"')
    boundary = re.search(
        r'^(?:OVFS_PATHS=|python3 "\$ROOT/ocore/user/verify_ovfs\.py")',
        source[start:], re.MULTILINE,
    )
    if boundary is None:
        raise AssertionError("cannot locate the exact structural-verifier boundary")
    return source[start:start + boundary.start()]


class NativeWorkloadPinTests(unittest.TestCase):
    @contextmanager
    def fixture(self, case, size=None):
        script, native, prefix, sha_prefix, record_name, sizes, capacity = case
        with tempfile.TemporaryDirectory(prefix="ovfs pin fixtures ") as temporary:
            directory = Path(temporary)
            build = directory / "kernel build"
            build.mkdir()
            # Resolve the real external verifier/binder through a fixture-only
            # root; native principal bytes remain outside the checkout.
            (directory / "ocore").mkdir()
            (directory / "ocore/kernel").symlink_to(KERNEL, target_is_directory=True)
            size = sizes[0] if size is None else size
            seed = hashlib.sha256(script.encode()).digest()
            payload = (seed * ((size + len(seed) - 1) // len(seed)))[:size]
            digest = hashlib.sha256(payload).hexdigest()
            image = directory / f"root-{digest}.ovfs"
            image.write_bytes(payload)
            unit = "m4" if native == "m4.oc" else ("m5" if record_name is None else "m6")
            generated = build / (unit + ".oc")
            command = [sys.executable, "-B", str(KERNEL / "bind-image.py"),
                       str(KERNEL / native), str(image), str(generated),
                       "--prefix", prefix + "_", "--capacity", str(capacity)]
            if record_name is None:
                command.append("--command-digest")
            if native == "m4.oc":
                command.append("--linker-length")
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            metadata = generated.with_suffix(".image.json")
            original_metadata = metadata.read_bytes()
            record = build / (record_name or "m5-image.path")
            if record:
                record.write_text(str(image) + "\n")
            principal_fields = []
            for group, name, variable in PRINCIPALS.get(script, ()):
                path = directory / "target" / group / "pass-one" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((name + ": fixture original native identity\n").encode())
                principal_fields.extend((str(path.stat().st_size), hashlib.sha256(path.read_bytes()).hexdigest()))
            env = {key: value for key, value in os.environ.items()
                   if key not in ("OCORE_M7_LINUX_PLAN9_BUILD_DIR", "OCORE_M7_BUILD_DIR")}
            env.update(ROOT=str(directory), BUILD_DIR=str(build),
                       BUILD_OUTPUT=f"unrelated build diagnostic\nm5-image: {image}\nm5-sha256: {digest}\n",
                       PYTHONDONTWRITEBYTECODE="1")
            if record:
                env["IMAGE_RECORD"] = str(record)
            code = preflight((KERNEL / script).read_text(), m5=record_name is None)
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

            # A malformed extraction must never count as an admission negative,
            # even when running just one of the mutation-test methods.
            syntax = subprocess.run(["bash", "-n"], input=code, capture_output=True,
                                    text=True, check=False, timeout=15)
            self.assertEqual(syntax.returncode, 0, syntax.stderr)
            initial = run()
            self.assertEqual(initial.returncode, 0, initial.stdout + initial.stderr)

            yield {"case": case, "directory": directory, "build": build, "image": image,
                   "payload": payload, "digest": digest, "generated": generated, "metadata": metadata,
                   "identity": json.loads(original_metadata), "record": record, "environment": env,
                   "principal_fields": principal_fields, "run": run, "reset": reset}

    def assert_native_binding(self, source, prefix, sha_prefix, payload, *, linker_length=False):
        constants = native_constants(source)
        expected = hashlib.sha256(payload).digest()
        self.assertEqual(b"".join(constants[f"{prefix}_DIGEST_{i}"].to_bytes(8, "little")
                                  for i in range(4)), expected)
        self.assertEqual(b"".join(constants[f"{sha_prefix}_{i}"].to_bytes(8, "big")
                                  for i in range(4)), expected)
        self.assertEqual(constants[f"{prefix}_ID"], int.from_bytes(expected[:8], "big"))
        if linker_length:
            self.assertIn("let image_start: usize = ocore_m4_image_start();", source)
            self.assertIn("let image_end: usize = ocore_m4_image_end();", source)
            self.assertIn("image_end - image_start", source)
        else:
            self.assertEqual(constants[f"{prefix}_LENGTH"], len(payload))

    def test_generated_m4_host_and_kernel_pin_the_same_artifact(self):
        # M4 now follows its selected per-build source/record; its admitted
        # length still comes from the actual linker span rather than a constant.
        with self.fixture(DYNAMIC[-1]) as f:
            self.assert_native_binding(f["generated"].read_text(), "IMAGE", "IMAGE_SHA",
                                       f["payload"], linker_length=True)
            result = f["run"]()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.splitlines(), [str(f["image"]), str(len(f["payload"])), f["digest"]])

    def test_dynamic_host_and_generated_native_bindings_agree_across_layouts(self):
        for case in DYNAMIC:
            for size in case[5]:
                with self.subTest(script=case[0], size=size), self.fixture(case, size) as f:
                    self.assert_native_binding(f["generated"].read_text(), case[2], case[3], f["payload"],
                                               linker_length=case[1] == "m4.oc")
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
        for case in DYNAMIC:
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
            f["record"].write_text(str(misnamed) + "\n")
            f["environment"]["BUILD_OUTPUT"] = f"m5-image: {misnamed}\nm5-sha256: {f['digest']}\n"
            result = f["run"]()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("content-addressed", result.stderr)
            self.assertEqual(result.stdout, "")

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

    def test_generated_m4_record_preflight_still_rejects_drift(self):
        with self.fixture(DYNAMIC[-1]) as f:
            self.assertEqual(f["run"]().returncode, 0)
            for mutation in ("same-size-content", "size", "selected-path", "multiple", "missing"):
                with self.subTest(mutation=mutation):
                    f["reset"]()
                    if mutation == "same-size-content":
                        f["image"].write_bytes(bytes([f["payload"][0] ^ 1]) + f["payload"][1:])
                    elif mutation == "size":
                        f["image"].write_bytes(f["payload"] + b"extra")
                    elif mutation == "selected-path":
                        other = f["directory"] / "another" / f["image"].name
                        other.parent.mkdir()
                        other.write_bytes(f["payload"])
                        f["record"].write_text(str(other) + "\n")
                    elif mutation == "multiple":
                        f["record"].write_text((str(f["image"]) + "\n") * 2)
                    else:
                        f["record"].unlink()
                    self.assertNotEqual(f["run"]().returncode, 0)


    def test_plan9_builder_invocation_honors_same_directory_precedence(self):
        # Execute the actual Mode26 invocation with an inert builder which
        # records its environment using the real builder's selection expression.
        # No artifact builder, compiler, or VM runs in this control.
        source = (KERNEL / "build.sh").read_text()
        call = source.index('"$KERNEL_DIR/build-m7-linux-plan9-artifacts.sh"')
        start = source.rfind('  M7_LINUX_PLAN9_ARTIFACT_OUTPUT="$(', 0, call)
        self.assertGreaterEqual(start, 0)
        end = source.index('\n  )"', call) + len('\n  )"')
        invocation = source[start:end]
        builder = (KERNEL / "build-m7-linux-plan9-artifacts.sh").read_text()
        selection = re.findall(r'^BUILD_DIR=.*$', builder, re.MULTILINE)
        self.assertEqual(len(selection), 1)
        with tempfile.TemporaryDirectory(prefix="ovfs invocation fixture ") as temporary:
            directory = Path(temporary)
            kernel = directory / "inert builder"
            kernel.mkdir()
            recorder = kernel / "build-m7-linux-plan9-artifacts.sh"
            recorder.write_text('#!/usr/bin/env bash\nset -euo pipefail\n' + selection[0]
                                + '\nprintf "%s\\n" "$BUILD_DIR" "$OCOREC_BIN"\n')
            recorder.chmod(0o755)
            base = {key: value for key, value in os.environ.items()
                    if key not in ("OCORE_M7_LINUX_PLAN9_BUILD_DIR", "OCORE_M7_BUILD_DIR")}
            project = directory / "project root"
            compiler = str(directory / "selected compiler is not executed")
            base.update(ROOT=str(project), KERNEL_DIR=str(kernel), OCOREC_BIN=compiler)
            shared = str(directory / "shared build")
            specific = str(directory / "specific build")
            cases = (
                ({}, str(project / "target/ocore-m7-linux-plan9-artifacts")),
                ({"OCORE_M7_BUILD_DIR": shared}, shared),
                ({"OCORE_M7_BUILD_DIR": shared,
                  "OCORE_M7_LINUX_PLAN9_BUILD_DIR": specific}, specific),
            )
            script = invocation + '\nprintf "%s\\n" "$M7_LINUX_PLAN9_ARTIFACT_OUTPUT"\n'
            for overrides, expected in cases:
                with self.subTest(overrides=overrides):
                    result = subprocess.run(["bash", "-euc", script], env={**base, **overrides},
                                            capture_output=True, text=True, check=False, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines(), [expected, compiler])


class GeneratedImageBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def binding(self, profile=PROFILES[2], data=b"current build payload\n"):
        _, unit, template, prefix, capacity, options, record_name = profile
        image = self.directory / f"root-{hashlib.sha256(data).hexdigest()}.ovfs"
        image.write_bytes(data)
        generated, identity = binder.bind(
            (KERNEL / template).read_text(), image, prefix, capacity,
            command_digest="--command-digest" in options,
            linker_length="--linker-length" in options,
        )
        source = self.directory / f"{unit}.oc"
        source.write_text(generated)
        metadata = source.with_suffix(".image.json")
        metadata.write_text(json.dumps(identity))
        record = self.directory / record_name
        record.write_text(f"{image}\n")
        command = [
            sys.executable, str(KERNEL / "verify-image-binding.py"),
            str(metadata), str(record), str(source),
            "--prefix", prefix, "--capacity", str(capacity), *options,
        ]
        return image, source, metadata, record, identity, command

    def run_command(self, command, **kwargs):
        return subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)

    def assert_rejected(self, command):
        result = self.run_command(command)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        return result

    def test_all_profiles_follow_current_build_instead_of_historical_bytes(self):
        for profile in PROFILES:
            for payload in (b"first build\n", b"changed compiler output\n"):
                with self.subTest(profile=profile[0], payload=payload):
                    *_, identity, command = self.binding(profile, payload)
                    result = self.run_command(command)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, f'{identity["bytes"]} {identity["sha256"]}\n')

    def test_missing_empty_or_multiple_link_records_are_rejected(self):
        image, _, _, record, _, command = self.binding()
        for value in ("", "\n", f"{image}", f"{image}\n{image}\n", f"{image}\r\n"):
            with self.subTest(record=value):
                record.write_text(value)
                self.assert_rejected(command)
        record.unlink()
        self.assert_rejected(command)

    def test_record_must_select_the_metadata_image(self):
        image, _, _, record, _, command = self.binding()
        other_dir = self.directory / "other"
        other_dir.mkdir()
        other_image = other_dir / image.name
        other_image.write_bytes(image.read_bytes())
        record.write_text(f"{other_image}\n")
        self.assert_rejected(command)
        record.write_text(f"{self.directory / 'missing.ovfs'}\n")
        self.assert_rejected(command)

    def test_image_mutation_after_binding_is_rejected(self):
        image, _, _, _, _, command = self.binding()
        original = image.read_bytes()
        for payload in (b"x" * len(original), original + b"extra"):
            with self.subTest(payload=payload):
                image.write_bytes(payload)
                self.assert_rejected(command)

    def test_content_addressed_name_is_required(self):
        image, _, metadata, record, identity, command = self.binding()
        wrong_name = image.with_name("root-" + "0" * 64 + ".ovfs")
        image.rename(wrong_name)
        identity["image"] = str(wrong_name)
        metadata.write_text(json.dumps(identity))
        record.write_text(f"{wrong_name}\n")
        self.assert_rejected(command)

    def test_metadata_mismatch_or_malformed_metadata_is_rejected(self):
        _, _, metadata, _, identity, command = self.binding()
        invalid = [
            {**identity, "bytes": identity["bytes"] + 1},
            {**identity, "bytes": str(identity["bytes"])},
            {**identity, "sha256": "0" * 64},
            {**identity, "image": str(self.directory / "missing.ovfs")},
            {key: value for key, value in identity.items() if key != "sha256"},
            [], None,
        ]
        for declared in invalid:
            with self.subTest(metadata=declared):
                metadata.write_text(json.dumps(declared))
                self.assert_rejected(command)
        metadata.write_text("{not JSON")
        self.assert_rejected(command)
        metadata.unlink()
        self.assert_rejected(command)

    def test_every_native_pin_representation_must_match(self):
        _, source, _, _, _, command = self.binding(PROFILES[1])
        generated = source.read_text()
        for name in ("IMAGE_ID", "IMAGE_LENGTH", "IMAGE_DIGEST_0", "COMMAND_DIGEST_0"):
            with self.subTest(pin=name):
                changed, count = re.subn(
                    rf"(?m)^(const {name}: (?:usize|u64) = )[^;]+;",
                    r"\g<1>0;", generated,
                )
                self.assertEqual(count, 1)
                source.write_text(changed)
                self.assert_rejected(command)
        source.write_text(generated.replace("const IMAGE_LENGTH:", "const OLD_LENGTH:"))
        self.assert_rejected(command)
        source.write_text(generated + "\nconst IMAGE_LENGTH: usize = 1;\n")
        self.assert_rejected(command)

    def test_profile_capacity_is_enforced(self):
        *_, command = self.binding(PROFILES[2], b"x" * 70000)
        result = self.run_command(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        command[command.index("--capacity") + 1] = "65536"
        self.assert_rejected(command)

    def test_smoke_preflights_propagate_binding_failure(self):
        # Execute the actual shell preflight, stopping before OVFS/ELF/QEMU work.
        # A failing Python child must stop Bash instead of leaving empty read vars.
        for profile in PROFILES:
            with self.subTest(script=profile[0]):
                image, _, metadata, record, identity, _ = self.binding(profile)
                source = (KERNEL / profile[0]).read_text()
                if profile[0] == "smoke-live-qemu.sh":
                    start = source.index('IMAGE_IDENTITY=')
                    end = source.index('python3 "$ROOT/ocore/user/verify_ovfs.py"', start)
                    preflight = source[start:end]
                else:
                    start = source.index('if [[ ! -f "$IMAGE_RECORD"')
                    end_match = re.search(
                        r'^read -r IMAGE_BYTES (?:IMAGE_)?DIGEST <<< "\$IMAGE_IDENTITY"$',
                        source[start:], re.MULTILINE,
                    )
                    self.assertIsNotNone(end_match)
                    preflight = source[start:start + end_match.end()]
                script = preflight + '\nprintf "%s %s\\n" "$IMAGE_BYTES" "${DIGEST:-${IMAGE_DIGEST:-}}"\n'
                env = {**os.environ, "ROOT": str(ROOT), "BUILD_DIR": str(self.directory),
                       "IMAGE_RECORD": str(record), "IMAGE": str(image),
                       "BUILD_DIGEST": identity["sha256"]}
                result = self.run_command(["bash", "-euc", script], env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f'{identity["bytes"]} {identity["sha256"]}\n')
                if profile[0] == "smoke-live-qemu.sh":
                    result = self.run_command(
                        ["bash", "-euc", script], env={**env, "BUILD_DIGEST": "0" * 64},
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("artifact identity is not canonical", result.stderr)
                    self.assertEqual(result.stdout, "")
                metadata.write_text("{}")
                result = self.run_command(["bash", "-euc", script], env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                metadata.write_text(json.dumps(identity))
                record.write_text(f"{image}\n{image}\n")
                result = self.run_command(["bash", "-euc", script], env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def pack_image(self, entries):
        command = [sys.executable, str(ROOT / "ocore/user/pack_ovfs.py"),
                   str(self.directory / "images"), "--max-image-bytes", "98304"]
        for index, (path, payload, flags) in enumerate(entries):
            host_file = self.directory / f"payload-{index}"
            host_file.write_bytes(payload)
            command.extend(("--entry", path, str(host_file), str(flags)))
        result = self.run_command(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        return Path(result.stdout.strip())

    def test_linux_corpus_stays_pinned_independently_of_current_build(self):
        for name in ("smoke-live-linux-personality-qemu.sh", "smoke-live-linux-plan9-qemu.sh"):
            with self.subTest(script=name):
                source = (KERNEL / name).read_text()
                digest = shell_value(source, "LINUX_ELF_DIGEST")
                size = int(shell_value(source, "LINUX_ELF_BYTES"))
                self.assertEqual(digest, "06240b6a840ed4262835aceff64a94f6ebd77838666f05eb7415d9a0d1b5868d")
                self.assertEqual(size, 8520)
                foreign = b"x" * size
                entries = [("/bin/linux-minimal.elf", foreign, 3)]
                native = (b"daemon", b"supervisor", b"client")
                if name == "smoke-live-linux-plan9-qemu.sh":
                    entries += list(zip(("/sbin/linux-9pd.elf", "/sbin/linux-supervisord.elf",
                                         "/bin/plan9-namespace-client.elf"), native, (3, 3, 3)))
                image = self.pack_image(entries)
                verifier = source.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
                extra = []
                if len(entries) > 1:
                    for data in native:
                        extra.extend((hashlib.sha256(data).hexdigest(), str(len(data))))
                # Positive control: well-formed image and matching principal pins.
                result = self.run_command([sys.executable, "-c", verifier, str(image),
                                           hashlib.sha256(foreign).hexdigest(), str(size), *extra])
                self.assertEqual(result.returncode, 0, result.stderr)
                # Rebinding a generated image must not admit a changed foreign ELF.
                result = self.run_command([sys.executable, "-c", verifier, str(image), digest, str(size), *extra])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("identity mismatch", result.stderr)

    def test_logical_read_object_stays_pinned_independently(self):
        source = (KERNEL / "smoke-m7b-logical-read-qemu.sh").read_text()
        digest = shell_value(source, "OBJECT_DIGEST")
        size = int(shell_value(source, "OBJECT_BYTES"))
        payload = b"m7b-logical-object!\n"
        self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
        self.assertEqual(len(payload), size)
        client, provider = b"current client", b"current provider"
        verifier = source.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        for object_payload in (payload, b"x" * size):
            image = self.pack_image([
                ("/bin/m7b-logical-read.elf", client, 3),
                ("/sbin/m7b-9pd.elf", provider, 3),
                ("/objects/logical-read-v1", object_payload, 1),
            ])
            result = self.run_command([
                sys.executable, "-c", verifier, str(image),
                hashlib.sha256(client).hexdigest(), str(len(client)),
                hashlib.sha256(provider).hexdigest(), str(len(provider)), digest, str(size),
            ])
            if object_payload == payload:
                self.assertEqual(result.returncode, 0, result.stderr)
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("identity mismatch", result.stderr)

    def test_plan9_principal_lookup_honors_builder_directory_precedence(self):
        source = (KERNEL / "smoke-live-linux-plan9-qemu.sh").read_text()
        start = source.index('ARTIFACT_BUILD_DIR=')
        end = source.index('OVFS_PATHS=', start)
        script = source[start:end] + 'printf "%s\\n" "$DAEMON_DIGEST"\n'
        env = {key: value for key, value in os.environ.items()
               if key not in ("OCORE_M7_LINUX_PLAN9_BUILD_DIR", "OCORE_M7_BUILD_DIR")}
        env.update(ROOT=str(ROOT))
        for directory_name in ("general", "specific"):
            artifact_dir = self.directory / directory_name / "pass-one"
            artifact_dir.mkdir(parents=True)
            for name in ("linux-9pd.elf", "linux-supervisord.elf", "plan9-namespace-client.elf"):
                (artifact_dir / name).write_bytes(directory_name.encode())
        env["OCORE_M7_BUILD_DIR"] = str(self.directory / "general")
        result = self.run_command(["bash", "-euc", script], env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), hashlib.sha256(b"general").hexdigest())
        env["OCORE_M7_LINUX_PLAN9_BUILD_DIR"] = str(self.directory / "specific")
        result = self.run_command(["bash", "-euc", script], env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), hashlib.sha256(b"specific").hexdigest())
        (self.directory / "specific/pass-one/linux-9pd.elf").unlink()
        result = self.run_command(["bash", "-euc", script], env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
