#!/usr/bin/env python3
"""Build the small native EL1 image used by the O10 M3 three-domain gate."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

from o10_native_fixture import CONTRACT, auxiliary_image

ROOT = Path(__file__).resolve().parents[1]
SOURCES = tuple("ocore/guest/native/o10_m3/" + name
                for name in ("entry.S", "fixture.c", "linker.ld"))


def identity(path: Path) -> dict:
    raw = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def build(output: Path, clang: str = "clang", lld: str = "ld.lld") -> dict:
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("native fixture output must be a new directory")
    # Preserve the ld.lld invocation name: resolving its symlink selects the
    # generic multicall lld driver, which has no ELF flavor by itself.
    tools = {name: Path(shutil.which(value) or value).absolute()
             for name, value in (("clang", clang), ("lld", lld))}
    if any(not p.is_file() or not os.access(p, os.X_OK) for p in tools.values()):
        raise ValueError("native fixture requires clang and ld.lld")
    tracked = (*SOURCES, "scripts/build_o10_native_fixture.py",
               "scripts/o10_native_fixture.py")
    before = {name: identity(ROOT / name) for name in tracked}
    output.mkdir(parents=True)
    for name in tracked:
        target = output / "sources" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
        if identity(target)["sha256"] != before[name]["sha256"]:
            raise ValueError("native fixture source changed during capture")
        target.chmod(0o400)
    guest = output / "sources/ocore/guest/native/o10_m3"
    common = [str(tools["clang"]), "--target=aarch64-none-elf", "-march=armv8-a"]
    commands = [
        [*common, "-c", str(guest / "entry.S"), "-o", str(output / "entry.o")],
        [*common, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
         "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
         "-mgeneral-regs-only", "-mstrict-align", "-fstack-usage",
         "-c", str(guest / "fixture.c"), "-o", str(output / "fixture.o")],
    ]
    link = [str(tools["lld"]), "-m", "aarch64elf", "-nostdlib",
            "--build-id=none", "-T", str(guest / "linker.ld"),
            str(output / "entry.o"), str(output / "fixture.o")]
    commands += [[*link, "-o", str(output / "fixture.elf")],
                 [*link, "--oformat=binary", "-o", str(output / "fixture.bin")]]
    receipts = []
    for number, argv in enumerate(commands):
        result = subprocess.run(argv, capture_output=True, timeout=60)
        for kind, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            (output / f"command-{number}.{kind}").write_bytes(data)
        receipts.append({"argv": argv, "returncode": result.returncode,
                         "stdout": identity(output / f"command-{number}.stdout"),
                         "stderr": identity(output / f"command-{number}.stderr")})
        if result.returncode:
            (output / "commands.json").write_text(json.dumps(receipts, indent=2) + "\n")
            raise RuntimeError("native fixture command failed: " + str(number))
    elf = (output / "fixture.elf").read_bytes()
    if (len(elf) < 64 or elf[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", elf, 18)[0] != 183
            or struct.unpack_from("<Q", elf, 24)[0] != CONTRACT["entry"]):
        raise ValueError("native fixture ELF target or entry mismatch")
    if not 0 < (output / "fixture.bin").stat().st_size <= CONTRACT["kernel_max_bytes"]:
        raise ValueError("native fixture flat image exceeds its immutable window")
    (output / "fixture.aux").write_bytes(auxiliary_image())
    after = {name: identity(ROOT / name) for name in tracked}
    if before != after:
        raise ValueError("native fixture source changed during build")
    artifacts = {name: identity(output / name)
                 for name in ("fixture.elf", "fixture.bin", "fixture.aux", "fixture.su")}
    result = {"schema": "ostadix.o10-m3-native-fixture-build/v1",
              "built": True, "scope": "AArch64 EL1 image compilation; live M3 qualification is separate.",
              "contract": dict(CONTRACT), "source_before": before,
              "source_after": after, "source_unchanged": before == after,
              "tools": {name: identity(path) for name, path in tools.items()},
              "commands": receipts, "artifacts": artifacts}
    (output / "build.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    for path in (output / "fixture.bin", output / "fixture.aux"):
        path.chmod(0o400)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--lld", default="ld.lld")
    args = parser.parse_args()
    try:
        result = build(args.output, args.clang, args.lld)
        print(json.dumps({"built": result["built"], "output": str(args.output),
                          "scope": result["scope"]}))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
