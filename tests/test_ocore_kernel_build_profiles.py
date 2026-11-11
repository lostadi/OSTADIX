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
    def test_mode35_sections_preserve_scalar_sources_and_fixed_linker(self) -> None:
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
                    OCORE_PROBE_MODE="35",
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
                for required in (
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
                ):
                    self.assertIn(required, sources)
                self.assertNotIn("ocore/kernel/world_native_scalar_semantics_stub.oc", sources)
                self.assertIn("-DOCORE_PROBE_MODE=35", assembler)
                self.assertIn(str(ROOT / "ocore/kernel/boot.S"), assembler)
                self.assertEqual(linker.count("--gc-sections"), 1)
                self.assertEqual(linker[linker.index("-T") + 1], str(ROOT / "ocore/kernel/linker.ld"))
                self.assertEqual(linker[linker.index("-m") + 1], "elf_x86_64")
                self.assertEqual(linker[-2:], [str(build / "boot.o"), str(build / "kernel.o")])
                self.assertEqual("-flavor" in linker, linker_name == "rust-lld")
                self.assertFalse(any(arg.startswith("--defsym") for arg in linker))
        self.assertEqual(compiler_inputs[0], compiler_inputs[1])


if __name__ == "__main__":
    unittest.main()
