#!/usr/bin/env python3
"""Bind an already verified build image to a generated kernel source unit.

The artifact builder owns structural/corpus validation and double-rebuild
checks. This step pins the resulting exact bytes, retaining the kernel's
length and SHA-256 admission checks across compiler/linker versions.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re


def bind(source, image, prefix, capacity, command_digest=False, linker_length=False):
    data = image.read_bytes()
    digest = hashlib.sha256(data).digest()
    if not 0 < len(data) <= capacity:
        raise ValueError("image exceeds the selected kernel image capacity")
    if image.name != f"root-{digest.hex()}.ovfs":
        raise ValueError("image content does not match its content-addressed name")
    values = {
        f"{prefix}ID": int.from_bytes(digest[:8], "big"),
    }
    if not linker_length:
        values[f"{prefix}LENGTH"] = len(data)
    for index in range(4):
        chunk = digest[index * 8:(index + 1) * 8]
        values[f"{prefix}DIGEST_{index}"] = int.from_bytes(chunk, "little")
        name = f"COMMAND_DIGEST_{index}" if command_digest else f"{prefix}SHA_{index}"
        values[name] = int.from_bytes(chunk, "big")
    for name, value in values.items():
        source, count = re.subn(
            rf"(?m)^(const {name}: (?:usize|u64) = )[^;]+;",
            lambda match: f"{match[1]}{value};",
            source,
        )
        if count != 1:
            raise ValueError(f"expected exactly one {name} declaration")
    return source, {"image": str(image.resolve()), "bytes": len(data), "sha256": digest.hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("image", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--prefix", default="IMAGE_")
    parser.add_argument("--capacity", type=int, choices=(65536, 98304), default=65536)
    parser.add_argument("--command-digest", action="store_true")
    parser.add_argument("--linker-length", action="store_true",
                        help="source obtains its length directly from linker symbols")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", args.prefix):
        parser.error("invalid constant prefix")
    if args.output.resolve() == args.source.resolve():
        parser.error("generated output must not overwrite the source template")
    try:
        source, identity = bind(args.source.read_text(), args.image, args.prefix,
                                args.capacity, args.command_digest, args.linker_length)
    except (OSError, ValueError) as error:
        parser.exit(1, f"error: {error}\n")
    args.output.write_text(source)
    args.output.with_suffix(".image.json").write_text(json.dumps(identity, indent=2) + "\n")


if __name__ == "__main__":
    main()
