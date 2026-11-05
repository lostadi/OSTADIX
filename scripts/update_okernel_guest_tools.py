#!/usr/bin/env python3
"""Atomically upgrade fixed local guest helpers in a stopped package domain.

Only the declared helper files are replaced. Installed APK state, repository
configuration, user files and the previous immutable disk generation remain
available. This is local code deployment, not upstream package qualification.
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
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repository_stager", ROOT / "scripts/stage_okernel_repository.py")
stager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stager)
domain = stager.domain
TOOLS = {
    "/usr/local/bin/pkg": ROOT / "ocore/guest/linux/package-domain/pkg",
    "/usr/local/bin/pkg-net": ROOT / "ocore/guest/linux/package-domain/pkg-net",
    "/usr/local/bin/pkg-namespace": ROOT / "ocore/guest/linux/package-domain/pkg-namespace",
    "/usr/local/libexec/pkg-plan9port": ROOT / "ocore/guest/linux/package-domain/pkg-plan9port",
    "/usr/local/bin/pkg-9p": ROOT / "ocore/guest/linux/package-domain/pkg-9p",
    "/usr/local/libexec/okernel-9p-bridge.c": ROOT / "ocore/guest/linux/package-domain/okernel-9p-bridge.c",
    "/usr/local/libexec/u9fs-path-hardening.patch": ROOT / "ocore/guest/linux/package-domain/u9fs-path-hardening.patch",
    "/usr/local/libexec/glibc-cc": ROOT / "ocore/guest/linux/package-domain/glibc-cc",
    "/usr/local/libexec/plan9port-activate": ROOT / "ocore/guest/linux/package-domain/plan9port-activate",
    "/usr/local/bin/status": ROOT / "ocore/guest/linux/package-domain/okernel-status",
    "/usr/local/bin/okernel-status": ROOT / "ocore/guest/linux/package-domain/okernel-status",
    "/usr/local/libexec/pkg-net-udhcpc": ROOT / "ocore/guest/linux/package-domain/pkg-net-udhcpc",
    "/sbin/package-domain-init": ROOT / "ocore/guest/linux/package-domain/package-domain-init",
    "/usr/local/libexec/okernel-shellrc": ROOT / "ocore/guest/linux/package-domain/okernel-shellrc",
}
TOOL_MODES = {name: 0o644 for name in ("/usr/local/libexec/okernel-shellrc", "/usr/local/libexec/okernel-9p-bridge.c", "/usr/local/libexec/u9fs-path-hardening.patch",
                                     "/usr/local/libexec/glibc-abi.tar.gz", "/usr/local/libexec/glibc-abi.json", "/usr/local/libexec/glibc-abi.sha256")}
PROTECTED = (("work", "/work"), ("apk-configuration", "/etc/apk"), ("apk-database", "/lib/apk/db"))


def install_tools(image: Path, work: Path, additional: dict[str, Path] | None = None) -> list[dict]:
    tools = work / "tools"
    tools.mkdir()
    commands = []
    for directory in ("/usr", "/usr/local", "/usr/local/bin", "/usr/local/libexec", "/sbin"):
        listing = stager.debugfs(image, "stat " + stager.quote(directory))
        if "Inode:" not in listing:
            commands.append("mkdir " + stager.quote(directory))
        elif "Type: directory" not in listing:
            raise ValueError(f"helper parent is not a guest directory: {directory}")
    records = []
    for ordinal, (guest, source) in enumerate({**TOOLS, **(additional or {})}.items()):
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"local helper must be a regular source file: {source}")
        selected = tools / source.name
        shutil.copyfile(source, selected)
        mode = TOOL_MODES.get(guest, 0o755)
        record = {"guest_path": guest, "source": domain.identity(source), "sha256": domain.digest(selected),
                  "bytes": selected.stat().st_size, "mode": f"{mode:04o}", "uid": 0, "gid": 0}
        if record["sha256"] != record["source"]["sha256"]:
            raise RuntimeError("local helper changed while its deployment bytes were copied")
        listing = stager.debugfs(image, "stat " + stager.quote(guest))
        if "Inode:" in listing:
            if "Type: regular" in listing:
                old = stager.dump_file(image, guest, work / "old-tools" / str(ordinal))
                record["previous"] = {"sha256": domain.digest(old), "bytes": old.stat().st_size}
            else:
                record["previous"] = {"stat": listing}
            commands.append("rm " + stager.quote(guest))
        else:
            record["previous"] = None
        commands.append("write " + stager.quote(selected) + " " + stager.quote(guest))
        for field, value in (("uid", "0"), ("gid", "0"), ("mode", f"0{0o100000 | mode:o}"), ("mtime", "0"), ("ctime", "0")):
            commands.append(f"set_inode_field {stager.quote(guest)} {field} {value}")
        records.append(record)
    command_file = work / "tools.debugfs"
    command_file.write_text("\n".join(commands) + "\n")
    result = subprocess.run(["debugfs", "-w", "-f", str(command_file), str(image)], capture_output=True, text=True)
    (work / "tools.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError("guest helper file deployment failed")
    for ordinal, record in enumerate(records):
        copied = stager.dump_file(image, record["guest_path"], work / "readback" / str(ordinal))
        if domain.digest(copied) != record["sha256"]:
            raise RuntimeError(f"guest helper readback differs: {record['guest_path']}")
        listing = stager.debugfs(image, "stat " + stager.quote(record["guest_path"]))
        if not ("Type: regular" in listing and f"Mode:  {record['mode']}" in listing
                and re.search(r"User:\s+0\s+Group:\s+0\b", listing)):
            raise RuntimeError(f"guest helper ownership/mode differs: {record['guest_path']}")
        if domain.digest(Path(record["source"]["path"])) != record["sha256"]:
            raise RuntimeError("local helper changed during deployment; selected disk is unchanged")
    return records


def update(state: Path, glibc_abi: Path | None = None) -> dict:
    abi_manifest = None
    if glibc_abi is not None:
        glibc_abi = glibc_abi.expanduser().resolve()
        abi_spec = importlib.util.spec_from_file_location("original_glibc_abi", ROOT / "scripts/build_glibc_abi.py")
        abi = importlib.util.module_from_spec(abi_spec)
        abi_spec.loader.exec_module(abi)
        try:
            abi_manifest = abi.verify(glibc_abi)
        except subprocess.SubprocessError as error:
            raise RuntimeError("Original GNU ABI signature/dependency verification failed") from error
    state = state.resolve()
    if not state.is_dir():
        raise ValueError("--state must identify an existing package domain")
    lock_path = state / "domain.lock"
    if lock_path.is_symlink():
        raise ValueError("domain lock must not be a symlink")
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("stop the running package domain before updating guest helpers") from error
        source, previous, head_before = stager.current_disk(state)
        area = state / "guest-tools-updates"
        if area.is_symlink():
            raise ValueError("guest helper update directory must not be a symlink")
        area.mkdir(exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="update-", dir=area))
        result = {"schema": "ostadix.package-domain-guest-tools-update/v1", "ok": False,
                  "disk_before": previous, "scope": "fixed local guest helper deployment only; installed APK state and user workspace preserved"}
        try:
            candidate = work / "candidate.ext4"
            shutil.copyfile(source, candidate)
            stager.fsck(candidate, work / "filesystem.log", repair=True)
            before = {name: stager.tree_identity(candidate, guest, work / ("before-" + name)) for name, guest in PROTECTED}
            additional = {}
            expected_abi = {}
            if abi_manifest is not None:
                stamp = work / "glibc-abi.sha256"
                stamp.write_text(abi_manifest["bundle"]["sha256"] + "\n")
                additional = {"/usr/local/libexec/" + name: glibc_abi / name for name in ("glibc-abi.tar.gz", "glibc-abi.json")}
                additional["/usr/local/libexec/glibc-abi.sha256"] = stamp
                expected_abi = {guest: domain.identity(source) for guest, source in additional.items()}
                result["private_gnu_libc_abi"] = {"bundle": abi_manifest["bundle"], "manifest": expected_abi["/usr/local/libexec/glibc-abi.json"],
                                                   "packages": abi_manifest["packages"], "verified": "original signatures, solver closure and reconstructed payloads"}
            result["tools"] = install_tools(candidate, work, additional)
            for record in result["tools"]:
                expected = expected_abi.get(record["guest_path"])
                if expected and (record["sha256"], record["bytes"]) != (expected["sha256"], expected["bytes"]):
                    raise RuntimeError("authenticated GNU ABI input changed during deployment")
            stager.fsck(candidate, work / "filesystem.log", repair=False)
            after = {name: stager.tree_identity(candidate, guest, work / ("after-" + name)) for name, guest in PROTECTED}
            if before != after:
                raise RuntimeError("helper deployment changed the workspace, APK configuration or installed database")
            domain.checked_file(source, previous)
            result["workspace_and_apk_state_preserved"] = True
            domain.write_json(work / "result.json", result)
            stager.publish(state, candidate, previous, head_before, work, result, receipt_key="guest_tools_update")
            try:
                candidate.unlink()
            except OSError:
                pass
            return {**result, "receipt": str(work / "result.json")}
        except BaseException as error:
            result["error"] = str(error)
            domain.write_json(work / "result.json", result)
            raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=domain.DEFAULT_STATE)
    parser.add_argument("--glibc-abi", type=Path, help="fully reverify and stage a captured original GNU libc compiler/runtime dependency bundle")
    args = parser.parse_args()
    try:
        result = update(args.state.expanduser(), args.glibc_abi)
        print("OKernel guest helper update: PASS")
        print(f"Disk generation: {result['disk_after']['path']}")
        print(f"Receipt: {result['receipt']}")
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        print(f"OKernel guest helper update: FAIL\n{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
