#!/usr/bin/env python3
"""Write an out-of-tree full Rust source-build configuration.

x.py's Python launcher reads this file before the Rust bootstrap executable can
apply --set arguments. This prevents an implicit downloaded stage0 toolchain and
routes LLVM/C dependencies and Rust linkage through the capture wrappers.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess


def configuration(rustc: str, cargo: str, cc: str, cxx: str, jobs: int, host: str) -> str:
    if jobs < 1 or not re.fullmatch(r"[A-Za-z0-9_-]+", host):
        raise ValueError("positive jobs and an ordinary Rust host triple are required")
    quote = json.dumps
    return f'''# Generated for hosted source capture; native OSTADIX is not qualified.
profile = "dist"
[build]
rustc = {quote(rustc)}
cargo = {quote(cargo)}
jobs = {jobs}
locked-deps = true
extended = true
[llvm]
download-ci-llvm = false
link-jobs = 1
ldflags = "-fuse-ld=lld"
[rust]
download-rustc = false
channel = "stable"
bootstrap-override-lld = "external"
[target.{host}]
cc = {quote(cc)}
cxx = {quote(cxx)}
linker = {quote(cc)}
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    for name in ["rustc", "cargo", "cc", "cxx"]:
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--jobs", type=int, required=True)
    args = parser.parse_args()
    version = subprocess.run([args.rustc, "-vV"], check=True, text=True, capture_output=True).stdout
    host = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
    text = configuration(args.rustc, args.cargo, args.cc, args.cxx, args.jobs, host)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        stream.write(text)
    print(json.dumps({"configuration": str(args.output.resolve()), "host": host,
                      "scope": "full-hosted-stdlib-rustc-and-cargo-source-build",
                      "runtime_complete": False, "native_execution_qualified": False}))


if __name__ == "__main__":
    main()
