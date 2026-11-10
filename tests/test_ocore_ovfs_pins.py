"""Generated admission pins must follow the exact image selected for linking."""

from __future__ import annotations

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
KERNEL = ROOT / "ocore" / "kernel"
SPEC = importlib.util.spec_from_file_location("bind_image", KERNEL / "bind-image.py")
binder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binder)

# script, generated unit, template, prefix, capacity, options, link record
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
        raise AssertionError(f"missing fixed corpus pin {name}")
    return match[1]


class OvfsPinTests(unittest.TestCase):
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
