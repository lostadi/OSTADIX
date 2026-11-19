"""Exercise actual kernel build recipes with inert command recorders.

These checks establish compiler/linker invocation contracts only. They do not
compile a kernel, measure its footprint, or run the native QEMU smoke gate.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]

RECORDER = r'''
import json
import os
from pathlib import Path
import sys

role = Path(sys.argv[0]).name
with Path(os.environ["OCORE_BUILD_TEST_CALLS"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"role": role, "args": sys.argv[1:]}) + "\n")
if role == "cargo":
    if os.environ.get("OCORE_BUILD_TEST_RECORD_PRODUCER") != "1" or sys.argv[-4:] != ["--package", "o-lang", "--bin", "ocore-kernel-world-record"]:
        raise SystemExit("the recipe test must never rebuild the O-core compiler")
    raise SystemExit(0)
if role == "ocore-kernel-world-record":
    Path(sys.argv[sys.argv.index("--output") + 1]).write_bytes(b"inert record fixture")
    raise SystemExit(0)
if "-o" in sys.argv:
    Path(sys.argv[sys.argv.index("-o") + 1]).write_bytes(b"")
'''


class KernelBuildProfileTests(unittest.TestCase):
    def _record_profile(self, mode: int, linker_name: str) -> list[dict]:
        with tempfile.TemporaryDirectory(prefix="ocore-old-profile-") as temporary:
            directory = Path(temporary)
            source_root = ROOT
            if mode in (20, 21, 31):
                # Only the external artifact producer is inert here. Use the
                # actual image binder and source template so the generated
                # kernel source/assembly image arguments remain observable.
                source_root = directory / "source"
                kernel = source_root / "ocore/kernel"
                kernel.mkdir(parents=True)
                for name in ("build.sh", "bind-image.py", "m7b_logical_read.oc"):
                    shutil.copyfile(ROOT / "ocore/kernel" / name, kernel / name)
                image = directory / ("root-" + hashlib.sha256(b"argv fixture").hexdigest() + ".ovfs")
                image.write_bytes(b"argv fixture")
                producer = kernel / "build-m7b-logical-read-artifacts.sh"
                producer.write_text("#!/bin/sh\nprintf '%s\\n' " + shlex.quote("image: " + str(image)) + "\n")
                producer.chmod(0o755)
                if mode in (20, 21):
                    record_tool = source_root / "target/debug/ocore-kernel-world-record"
                    record_tool.parent.mkdir(parents=True)
                    record_tool.write_text(f"#!{sys.executable}\n{RECORDER}")
                    record_tool.chmod(0o755)
            tools = directory / "tools"
            tools.mkdir()
            for name in ("ocorec", "clang", linker_name, "cargo", "file"):
                command = tools / name
                command.write_text(f"#!{sys.executable}\n{RECORDER}", encoding="utf-8")
                command.chmod(0o755)
            calls = directory / "calls.jsonl"
            environment = dict(
                os.environ,
                OCORE_PROBE_MODE=str(mode),
                OCORE_BOOT_INFO_ENABLED="0",
                OCORE_BUILD_DIR=str(directory / "build with spaces"),
                OCOREC_BIN=str(tools / "ocorec"),
                OCORE_LLD=str(tools / linker_name),
                OCORE_BUILD_TEST_CALLS=str(calls),
                PATH=str(tools) + os.pathsep + os.environ.get("PATH", ""),
            )
            if mode in (20, 21):
                environment["OCORE_BUILD_TEST_RECORD_PRODUCER"] = "1"
            result = subprocess.run(
                ["bash", str(source_root / "ocore/kernel/build.sh")], cwd=ROOT,
                env=environment, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            recorded = [json.loads(line) for line in calls.read_text().splitlines()]
            for call in recorded:
                call["args"] = [arg.replace(str(source_root), "$ROOT").replace(str(directory), "$TEST")
                                for arg in call["args"]]
            return recorded

    def test_historical_probe_sections_preserve_mode0_sources_and_linker_contract(self) -> None:
        # Mode 0 already selected the same complete runtime/harness closure.
        # Compare every compiler, assembler and linker argument against that
        # unchanged profile; only the assembly probe selector may differ.
        for linker in ("rust-lld", "ld.lld"):
            baseline = self._record_profile(0, linker)
            self.assertEqual([call["role"] for call in baseline],
                             ["ocorec", "clang", linker, "file", "file"])
            for flag in ("--function-sections", "--data-sections"):
                self.assertEqual(baseline[0]["args"].count(flag), 1)
            self.assertEqual(baseline[2]["args"].count("--gc-sections"), 1)
            for mode in (*range(1, 13), 14):
                with self.subTest(mode=mode, linker=linker):
                    recorded = self._record_profile(mode, linker)
                    self.assertIn(f"-DOCORE_PROBE_MODE={mode}", recorded[1]["args"])
                    recorded[1]["args"] = [
                        "-DOCORE_PROBE_MODE=0" if arg == f"-DOCORE_PROBE_MODE={mode}" else arg
                        for arg in recorded[1]["args"]
                    ]
                    self.assertEqual(recorded, baseline)

    def test_mode31_sections_preserve_bound_image_and_existing_source_profile(self) -> None:
        for linker in ("rust-lld", "ld.lld"):
            with self.subTest(linker=linker):
                baseline = self._record_profile(0, linker)
                recorded = self._record_profile(31, linker)
                expected = []
                for arg in baseline[0]["args"]:
                    if arg == "$ROOT/ocore/runtime/x86_64/image_vfs_storage.oc":
                        arg = "$ROOT/ocore/runtime/x86_64/image_vfs_storage_m7.oc"
                    for name in ("m1", "m2", "m3", "m3_live", "m4"):
                        if arg == f"$ROOT/ocore/kernel/{name}.oc":
                            arg = f"$ROOT/ocore/kernel/{name}_mode25_stub.oc"
                    if arg == "$ROOT/ocore/kernel/m6_stub.oc":
                        arg = "$TEST/build with spaces/m6.oc"
                    expected.append(arg)
                self.assertEqual(recorded[0]["args"], expected)
                self.assertEqual(recorded[2:], baseline[2:])
                assembler = recorded[1]["args"]
                self.assertIn("-DOCORE_PROBE_MODE=31", assembler)
                image_arguments = [arg for arg in assembler if arg.startswith("-DOCORE_M7B_LOGICAL_READ_IMAGE_PATH=")]
                self.assertEqual(len(image_arguments), 1)
                digest = hashlib.sha256(b"argv fixture").hexdigest()
                self.assertEqual(image_arguments[0], f'-DOCORE_M7B_LOGICAL_READ_IMAGE_PATH="$TEST/root-{digest}.ovfs"')

    def test_mode21_sections_preserve_mode20_record_and_real_kernelworld_profile(self) -> None:
        for linker in ("rust-lld", "ld.lld"):
            with self.subTest(linker=linker):
                baseline = self._record_profile(20, linker)
                recorded = self._record_profile(21, linker)
                self.assertEqual([row["role"] for row in recorded],
                                 ["cargo", "ocore-kernel-world-record", "ocore-kernel-world-record",
                                  "ocorec", "clang", linker, "file", "file"])
                self.assertIn("$ROOT/ocore/runtime/x86_64/kernel_world_boot.oc", recorded[3]["args"])
                self.assertIn("$ROOT/ocore/kernel/kernel_world_semantics.oc", recorded[3]["args"])
                self.assertEqual(recorded[5]["args"].count("--gc-sections"), 1)
                recorded[4]["args"] = ["-DOCORE_PROBE_MODE=20" if arg == "-DOCORE_PROBE_MODE=21" else arg
                                       for arg in recorded[4]["args"]]
                self.assertEqual(recorded, baseline)

    def _assert_sections_preserve_sources_and_fixed_linker(self, mode: int) -> None:
        compiler_inputs = []
        for linker_name in ("rust-lld", "ld.lld"):
            with self.subTest(linker=linker_name), tempfile.TemporaryDirectory(
                prefix="ocore-build-profile-"
            ) as temporary:
                directory = Path(temporary)
                tools = directory / "tools"
                tools.mkdir()
                for name in ("ocorec", "clang", linker_name, "cargo", "file"):
                    command = tools / name
                    command.write_text(f"#!{sys.executable}\n{RECORDER}", encoding="utf-8")
                    command.chmod(0o755)

                build = directory / "build with spaces"
                calls_path = directory / "calls.jsonl"
                environment = os.environ.copy()
                environment.update(
                    OCORE_PROBE_MODE=str(mode),
                    OCORE_BOOT_INFO_ENABLED="0",
                    OCORE_BUILD_DIR=str(build),
                    OCOREC_BIN=str(tools / "ocorec"),
                    OCORE_LLD=str(tools / linker_name),
                    OCORE_BUILD_TEST_CALLS=str(calls_path),
                    PATH=str(tools) + os.pathsep + environment.get("PATH", ""),
                )
                result = subprocess.run(
                    ["bash", str(ROOT / "ocore/kernel/build.sh")],
                    cwd=ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                calls = [json.loads(line) for line in calls_path.read_text().splitlines()]
                self.assertEqual(
                    [call["role"] for call in calls],
                    ["ocorec", "clang", linker_name, "file", "file"],
                )
                compiler, assembler, linker = [call["args"] for call in calls[:3]]
                sources = [str(Path(arg).relative_to(ROOT)) for arg in compiler if arg.endswith(".oc")]
                compiler_inputs.append(sources)
                for flag in ("--function-sections", "--data-sections"):
                    self.assertEqual(compiler.count(flag), 1)
                self.assertEqual(compiler[compiler.index("--target") + 1], "x86_64-unknown-none")
                self.assertEqual(compiler[compiler.index("--emit") + 1], "obj")
                self.assertEqual(compiler[compiler.index("-o") + 1], str(build / "kernel.o"))
                self.assertEqual(len(sources), len(set(sources)))
                required_sources = (
                    "ocore/world/identity.oc",
                    "ocore/world/protocol.oc",
                    "ocore/world/value.oc",
                    "ocore/world/sha256.oc",
                    "ocore/world/value_codec.oc",
                    "ocore/world/receipt.oc",
                    "ocore/world/receipt_codec.oc",
                    "ocore/world/native_scalar.oc",
                    "ocore/kernel/world_native_scalar_semantics.oc",
                    "ocore/kernel/main.oc",
                ) if mode == 35 else (
                    "ocore/kernel/m5_selftest.oc",
                    "ocore/kernel/m5_semantics.oc",
                    "ocore/kernel/m1.oc",
                    "ocore/kernel/m2.oc",
                    "ocore/kernel/m3.oc",
                    "ocore/kernel/m3_live.oc",
                    "ocore/kernel/m4.oc",
                    "ocore/runtime/x86_64/thread.oc",
                    "ocore/kernel/main.oc",
                )
                for required in required_sources:
                    self.assertIn(required, sources)
                if mode == 35:
                    self.assertNotIn("ocore/kernel/world_native_scalar_semantics_stub.oc", sources)
                else:
                    self.assertNotIn("ocore/kernel/m5_selftest_stub.oc", sources)
                    self.assertNotIn("ocore/kernel/m5_semantics_stub.oc", sources)
                self.assertIn(f"-DOCORE_PROBE_MODE={mode}", assembler)
                self.assertIn(str(ROOT / "ocore/kernel/boot.S"), assembler)
                self.assertEqual(linker.count("--gc-sections"), 1)
                self.assertEqual(linker[linker.index("-T") + 1], str(ROOT / "ocore/kernel/linker.ld"))
                self.assertEqual(linker[linker.index("-m") + 1], "elf_x86_64")
                self.assertEqual(linker[-2:], [str(build / "boot.o"), str(build / "kernel.o")])
                self.assertEqual("-flavor" in linker, linker_name == "rust-lld")
                self.assertFalse(any(arg.startswith("--defsym") for arg in linker))
        self.assertEqual(compiler_inputs[0], compiler_inputs[1])

    def test_mode35_sections_preserve_scalar_sources_and_fixed_linker(self) -> None:
        self._assert_sections_preserve_sources_and_fixed_linker(35)

    def test_mode17_sections_preserve_semantics_sources_and_fixed_linker(self) -> None:
        self._assert_sections_preserve_sources_and_fixed_linker(17)

    def test_new_transfer_oracle_is_selected_only_for_mode13(self) -> None:
        common_sources = []
        for mode in (0, 13, 19):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                arguments = output / "arguments.json"
                compiler = output / "ocorec"
                compiler.write_text(
                    f"#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n"
                    f"Path({str(arguments)!r}).write_text(json.dumps(sys.argv[1:]))\n"
                    "raise SystemExit(91)\n"
                )
                compiler.chmod(0o755)
                environment = dict(os.environ, OCOREC_BIN=str(compiler),
                                   OCORE_PROBE_MODE=str(mode), OCORE_BOOT_INFO_ENABLED="0",
                                   OCORE_BUILD_DIR=str(output / "build"))
                result = subprocess.run(["bash", str(ROOT / "ocore/kernel/build.sh")],
                                        cwd=ROOT, env=environment, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 91, result.stderr.decode(errors="replace"))
                argv = json.loads(arguments.read_text())
                sources = [str(Path(p).relative_to(ROOT)) for p in argv if p.endswith(".oc")]
                expected = "real" if mode == 13 else "stub"
                oracle = f"ocore/kernel/x86_64/m3_typed_transfer_{expected}.oc"
                self.assertEqual([p for p in sources if "m3_typed_transfer_" in p], [oracle])
                for name in ("m1", "m2", "m3", "m3_live", "m4"):
                    self.assertIn(f"ocore/kernel/{name}.oc", sources)
                    self.assertNotIn(f"ocore/kernel/{name}_mode25_stub.oc", sources)
                if mode in (0, 13):
                    common_sources.append([p for p in sources if p != oracle])
        self.assertEqual(common_sources[0], common_sources[1])


if __name__ == "__main__":
    unittest.main()
