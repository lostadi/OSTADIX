#!/usr/bin/env python3
"""Grow a stopped domain's selected ext4 generation from 512 MiB to 1 GiB.

The selected source and previous generations are never modified. The native
namespace stays bound to the exact same generation in one atomic head update.
This operates on image files only, without mounting or writing a host disk.
"""

from __future__ import annotations

import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("okernel_disk_growth_stager", ROOT / "scripts/stage_okernel_repository.py")
stager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stager)
domain = stager.domain
TARGET_BYTES = 1073741824


def filesystem_bytes(image: Path) -> int:
    text = stager.debugfs(image, "stats")
    count = re.search(r"^Block count:\s+(\d+)\s*$", text, re.MULTILINE)
    size = re.search(r"^Block size:\s+(\d+)\s*$", text, re.MULTILINE)
    if count is None or size is None:
        raise ValueError("cannot verify the ext4 filesystem geometry")
    return int(count.group(1)) * int(size.group(1))


def grow(state: Path, *, target_bytes: int = TARGET_BYTES) -> dict:
    if state.is_symlink():
        raise ValueError("--state must not be a symlink")
    state = state.resolve()
    if not state.is_dir():
        raise ValueError("--state must be an existing package-domain state directory")
    if type(target_bytes) is not int or target_bytes != TARGET_BYTES:
        raise ValueError("only the explicitly granted 1GiB target is supported")
    for tool in ("e2fsck", "resize2fs", "debugfs"):
        if shutil.which(tool) is None:
            raise ValueError(f"required ext4 image tool is missing: {tool}")
    lock_path = state / "domain.lock"
    if lock_path.is_symlink():
        raise ValueError("domain lock must not be a symlink")
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("stop the running package domain before growing its disk") from error
        source, previous, head_before = stager.current_disk(state)
        if previous["bytes"] == target_bytes:
            if filesystem_bytes(source) != target_bytes:
                raise ValueError("selected 1GiB image does not contain a full-size ext4 filesystem")
            return {"schema": "ostadix.package-domain-disk-growth/v1", "ok": True,
                    "already_target_size": True, "disk_before": previous, "disk_after": previous}
        if previous["bytes"] != 536870912:
            raise ValueError("growth requires the supported 512MiB source generation")
        namespace = None
        if head_before is not None:
            selected = json.loads(head_before)
            if selected.get("namespace") is not None:
                namespace = selected["namespace"]
                domain.checked_file(Path(namespace["path"]), namespace)
        area = state / "disk-migrations"
        if area.is_symlink():
            raise ValueError("disk migration directory must not be a symlink")
        area.mkdir(exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="grow-", dir=area))
        result = {"schema": "ostadix.package-domain-disk-growth/v1", "ok": False,
                  "disk_before": previous, "target_bytes": target_bytes, "workspace": str(work),
                  "scope": "offline ext4 image growth; complete path/content/mode/symlink tree comparison and full read-only fsck; no host disk writes",
                  "tools": {name: domain.identity(Path(shutil.which(name))) for name in ("e2fsck", "resize2fs", "debugfs")}}
        try:
            candidate = work / "candidate.ext4"
            shutil.copyfile(source, candidate)
            stager.fsck(candidate, work / "filesystem.log", repair=True)
            if filesystem_bytes(candidate) != previous["bytes"]:
                raise ValueError("source ext4 geometry does not match its declared image size")
            before = stager.tree_identity(candidate, "/", work / "before-tree")
            domain.write_json(work / "before-tree.json", {"entries": before})
            # Only the private clone is extended. resize2fs preserves the
            # original filesystem UUID/inodes/data while allocating new space.
            with candidate.open("r+b") as stream:
                stream.truncate(target_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            command = ["resize2fs", str(candidate)]
            resized = subprocess.run(command, capture_output=True, text=True)
            (work / "resize.log").write_text(resized.stdout + resized.stderr)
            result["resize_argv"] = command
            if resized.returncode:
                raise RuntimeError(f"candidate resize2fs failed ({resized.returncode}); inspect {work / 'resize.log'}")
            stager.fsck(candidate, work / "filesystem.log", repair=False)
            if candidate.stat().st_size != target_bytes or filesystem_bytes(candidate) != target_bytes:
                raise ValueError("resized image or ext4 geometry does not match the 1GiB grant")
            after = stager.tree_identity(candidate, "/", work / "after-tree")
            domain.write_json(work / "after-tree.json", {"entries": after})
            if before != after:
                raise RuntimeError("filesystem growth changed guest path/content/mode/symlink identities")
            domain.checked_file(source, previous)
            result.update(full_guest_tree_preserved=True, guest_tree_entries=len(before),
                          ext4_bytes=target_bytes, original_generation_retained=True,
                          namespace_generation_preserved=namespace)
            stager.publish(state, candidate, previous, head_before, work, result,
                           receipt_key="disk_growth", expected_bytes=target_bytes)
            return result
        except Exception as error:
            result.update(ok=False, error=str(error))
            domain.write_json(work / "result.json", result)
            raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=domain.DEFAULT_STATE)
    args = parser.parse_args()
    try:
        result = grow(args.state.expanduser())
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Disk growth failed: {error}\nThe previous generation remains selected unless the atomic publication completed.\n")
    print(json.dumps(result, indent=2))
    print("Disk growth: PASS. Rebuild the monitor to use the selected disk size before starting the domain.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
