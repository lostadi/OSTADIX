#!/usr/bin/env python3
"""Materialize an exact read-only saved pair into a new RAM-owned state.

Only the two schema-declared generation paths are rebased. Original records
remain evidence; arbitrary text and historical absolute paths confer no access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil

SCHEMA = "ostadix.x12-live-state-seed/v1"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            value.update(block)
    return value.hexdigest()


def checked(root: Path, relative: str, expected: dict) -> Path:
    name = PurePosixPath(relative)
    if name.is_absolute() or ".." in name.parts or str(name) != relative:
        raise ValueError("noncanonical seed path")
    path = root
    for part in name.parts:
        path /= part
        if path.is_symlink():
            raise ValueError("seed path contains a symlink")
    if (not path.is_file() or path.stat().st_size != expected.get("bytes")
            or digest(path) != expected.get("sha256")):
        raise ValueError("seed artifact identity mismatch: " + relative)
    return path


def load_seed(root: Path) -> dict:
    if root.is_symlink():
        raise ValueError("seed directory must be regular")
    root = root.resolve(strict=True)
    manifest = root / "seed.json"
    if manifest.is_symlink():
        raise ValueError("seed manifest is a symlink")
    value = json.loads(manifest.read_bytes())
    if value.get("schema") != SCHEMA or value.get("saved_pair") is not True:
        raise ValueError("unsupported or incomplete saved pair")
    if set(value["generations"]) != {"disk", "namespace"}:
        raise ValueError("exact saved pair required")
    for key, folder, suffix, size in (("disk", "disk-generations", ".ext4", 1073741824),
                                      ("namespace", "namespace-generations", ".raw", 16777216)):
        expected = value["generations"][key]
        pin = expected.get("sha256")
        if not isinstance(pin, str) or re.fullmatch(r"[0-9a-f]{64}", pin) is None:
            raise ValueError("invalid generation digest")
        relative = folder + "/" + pin + suffix
        if expected.get("relative_path") != relative or expected.get("bytes") != size:
            raise ValueError("generation path/size outside declared profile")
        checked(root, relative, expected)
    checked(root, "source-head.json", value["source_head"])
    paired_path = checked(root, "paired-save.json", value["paired_save"])
    paired = json.loads(paired_path.read_bytes())
    if (paired.get("schema") != "ostadix.unified-world-session/v1" or paired.get("ok") is not True
            or any(paired.get(key) is not True for key in
                   ("paired_snapshot", "virtual_cpu_stopped", "native_operations_quiescent"))):
        raise ValueError("seed lacks completed quiescent paired save evidence")
    for key in ("disk", "namespace"):
        if any(paired["after"][key].get(field) != value["generations"][key][field]
               for field in ("bytes", "sha256")):
            raise ValueError("seed pair differs from qualified saved snapshot")
    return value


def destination(root: Path, output: Path) -> Path:
    output = output.absolute()
    current = Path(output.anchor)
    for part in output.parts[1:]:
        if part in (".", ".."):
            raise ValueError("noncanonical state path")
        current /= part
        if current.is_symlink():
            raise ValueError("state path contains a symlink")
    if output.exists() or output.is_relative_to(root):
        raise ValueError("state must be a new private directory outside seed")
    return output


def materialize(root: Path, output: Path) -> dict:
    if root.is_symlink():
        raise ValueError("seed directory must not be a symlink")
    root = root.resolve(strict=True)
    output = destination(root, output)
    value = load_seed(root)
    output.mkdir(mode=0o700, parents=True)
    head = {"schema": "ostadix.package-domain-disk-head/v2",
            "fork_origin": {"source": "read-only ISO saved pair",
                            "head_sha256": value["source_head"]["sha256"]}}
    for key, expected in value["generations"].items():
        source = checked(root, expected["relative_path"], expected)
        target = output / expected["relative_path"]
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with source.open("rb") as incoming, target.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing, 1048576)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        if target.stat().st_size != expected["bytes"] or digest(target) != expected["sha256"]:
            raise ValueError("RAM saved generation copy differs")
        target.chmod(0o400)
        head[key] = {"path": str(target), "bytes": expected["bytes"], "sha256": expected["sha256"]}
    (output / "source-head.json").write_bytes((root / "source-head.json").read_bytes())
    (output / "head.json").write_text(json.dumps(head, indent=2) + "\n")
    record = {"schema": "ostadix.okernel-state-fork/v1", "ok": True,
              "source": str(root), "output": str(output), "selected_head": head,
              "source_head_sha256": value["source_head"]["sha256"],
              "scope": "Exact immutable ISO saved pair copied into RAM; no physical filesystem mounted or written"}
    (output / "fork.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=Path, default=Path("/opt/okernel/seed"))
    parser.add_argument("--output", type=Path, default=Path("/run/okernel/state"))
    args = parser.parse_args()
    try:
        result = materialize(args.seed, args.output)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, "OKernel live seed: FAIL: " + str(error) + "\n")
    print("OKERNEL X12 SAVED PAIR: PASS " + result["source_head_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
