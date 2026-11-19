"""Exercise actual kernel build recipes with inert command recorders.

These checks establish compiler/linker invocation contracts only. They do not
compile a kernel, measure its footprint, or run the native QEMU smoke gate.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
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
    raise SystemExit("the recipe test must never invoke Cargo")
if "-o" in sys.argv:
    Path(sys.argv[sys.argv.index("-o") + 1]).write_bytes(b"")
'''


class KernelBuildProfileTests(unittest.TestCase):
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
