#!/usr/bin/env python3
"""Check that a linked image record agrees with its generated admission pins."""

import argparse
import importlib.util
import json
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "bind_image", Path(__file__).with_name("bind-image.py")
)
binder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binder)


def verify(metadata, record, source, prefix="IMAGE_", capacity=65536,
           command_digest=False, linker_length=False):
    recorded = record.read_bytes().decode("utf-8")
    if not recorded.endswith("\n") or recorded.count("\n") != 1 or "\r" in recorded:
        raise ValueError("expected one exact embedded image path record")
    image_name = recorded[:-1]
    if not image_name:
        raise ValueError("embedded image path is empty")
    image = Path(image_name)
    generated = source.read_text()
    rebound, identity = binder.bind(
        generated, image, prefix, capacity, command_digest, linker_length
    )
    if rebound != generated:
        raise ValueError("generated kernel admission pins do not match the embedded image")
    declared = json.loads(metadata.read_text())
    if declared != identity or type(declared.get("bytes")) is not int:
        raise ValueError("image metadata does not match the exact embedded artifact")
    return identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("record", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("--prefix", default="IMAGE_")
    parser.add_argument("--capacity", type=int, choices=(65536, 98304), default=65536)
    parser.add_argument("--command-digest", action="store_true")
    parser.add_argument("--linker-length", action="store_true")
    args = parser.parse_args()
    try:
        identity = verify(args.metadata, args.record, args.source, args.prefix,
                          args.capacity, args.command_digest, args.linker_length)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        parser.exit(1, f"error: {error}\n")
    print(identity["bytes"], identity["sha256"])


if __name__ == "__main__":
    main()
