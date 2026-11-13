#!/usr/bin/env python3
"""Add authenticated offline APK closures to a stopped persistent domain.

This transports repository bytes into a new disk generation. It does not
install packages, change the installed APK database, execute guest programs,
or claim that staged packages are qualified. Original APK performs installation
and all package scripts inside the O-core-governed Linux guest after restart.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("package_domain_runner", ROOT / "scripts/okernel_package_domain.py")
domain = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(domain)
DEFAULT_CACHE = Path.home() / ".cache/ostadix/package-domain"
PACKAGE = re.compile(r"[a-z0-9][a-zA-Z0-9+_.:=~<>!@-]*\Z")
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]*\.apk\Z")


def quote(value: str | Path) -> str:
    value = str(value)
    if any(character in value for character in "\x00\n\r"):
        raise ValueError("debugfs paths cannot contain NUL or line breaks")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def debugfs(image: Path, command: str, *, log: Path | None = None) -> str:
    result = subprocess.run(["debugfs", "-R", command, str(image)], capture_output=True, text=True)
    if log:
        with log.open("a") as stream:
            stream.write(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"debugfs failed: {(result.stdout + result.stderr)[-2000:]}")
    return result.stdout


def dump_file(image: Path, guest_path: str, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    debugfs(image, f"dump {quote(guest_path)} {quote(output)}")
    if output.is_symlink() or not output.is_file():
        raise ValueError(f"required guest file is missing: {guest_path}")
    return output


def tree_identity(image: Path, guest_path: str, output: Path) -> list[dict]:
    """Capture contents and link identities without following guest symlinks."""
    output.mkdir(parents=True)
    listing = debugfs(image, f"stat {quote(guest_path)}")
    if "Type: directory" not in listing:
        raise ValueError(f"required guest directory is missing or not a directory: {guest_path}")
    debugfs(image, f"rdump {quote(guest_path)} {quote(output)}")
    extracted = output / Path(guest_path).name
    if not extracted.is_dir() or extracted.is_symlink():
        raise ValueError(f"cannot capture guest directory: {guest_path}")
    records = []
    for directory, names, files in os.walk(extracted, followlinks=False):
        for name in sorted([*names, *files]):
            path = Path(directory) / name
            info = path.lstat()
            record = {"path": str(path.relative_to(extracted)), "mode": stat.S_IMODE(info.st_mode)}
            if stat.S_ISLNK(info.st_mode):
                record["symlink"] = os.readlink(path)
            elif stat.S_ISREG(info.st_mode):
                record["sha256"] = domain.digest(path)
            elif not stat.S_ISDIR(info.st_mode):
                record["special_mode"] = stat.S_IFMT(info.st_mode)
            records.append(record)
    return sorted(records, key=lambda record: record["path"])


def fsck(image: Path, log: Path, *, repair: bool) -> None:
    result = subprocess.run(["e2fsck", "-p" if repair else "-fn", str(image)], capture_output=True, text=True)
    with log.open("a") as stream:
        stream.write(result.stdout + result.stderr)
    # A clean private candidate may replay its already-synced ext4 journal.
    if result.returncode not in ((0, 1) if repair else (0,)):
        raise RuntimeError(f"candidate filesystem check failed ({result.returncode}); inspect {log}")


def current_disk(state: Path) -> tuple[Path, dict, bytes | None]:
    head_path = state / "head.json"
    if head_path.is_symlink():
        raise ValueError("disk head must not be a symlink")
    if head_path.exists():
        raw = head_path.read_bytes()
        record = domain.validate_head(state, json.loads(raw))
        source = Path(record["path"])
    else:
        raw = None
        manifest_path = state / "rootfs/package-domain.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError("a validated package-domain base image is required")
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("schema") != "ostadix.linux-package-domain/v1" or manifest.get("architecture") != "aarch64":
            raise ValueError("unsupported package-domain base image manifest")
        record = manifest["artifacts"]["package-domain.ext4"]
        source = state / "rootfs/package-domain.ext4"
        if type(record.get("bytes")) is not int or record["bytes"] not in domain.DISK_SIZES:
            raise ValueError("base disk must match a supported 512MiB or 1GiB device grant")
    domain.checked_file(source, record)
    return source, domain.identity(source), raw


def build_repository_bundle(output: Path, indexes: Path, cache: Path, packages: list[str]) -> dict:
    command = [sys.executable, str(ROOT / "ocore/guest/linux/package-domain/build.py"),
               "--repository-only", "--output", str(output), "--cache", str(cache), "--indexes", str(indexes)]
    for package in packages:
        command += ["--package", package]
    print("Resolving and authenticating the original APK dependency closure.", flush=True)
    result = subprocess.run(command, capture_output=True, text=True)
    output.mkdir(parents=True, exist_ok=True)
    (output / "builder.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"authenticated repository build failed ({result.returncode}); inspect {output / 'builder.log'}")
    manifest = json.loads((output / "repository-bundle.json").read_text())
    if manifest.get("schema") != "ostadix.linux-package-repository/v1" or manifest.get("architecture") != "aarch64":
        raise ValueError("unsupported authenticated repository bundle")
    return manifest


def bundle_payloads(bundle: Path, manifest: dict) -> dict[str, tuple[Path, str]]:
    root = bundle / "repository-cache"
    if Path(manifest["repositories_path"]) != root:
        raise ValueError("repository bundle escaped its private staging directory")
    result = {}
    for record in manifest["repository_snapshots"]:
        if record.get("name") not in {"main", "community"} or record.get("signature_verified") is not True:
            raise ValueError("repository index was not authenticated")
        relative = record["name"] + "/aarch64/APKINDEX.tar.gz"
        result[relative] = (root / relative, record["index_sha256"])
    if set(result) != {"main/aarch64/APKINDEX.tar.gz", "community/aarch64/APKINDEX.tar.gz"}:
        raise ValueError("both exact Alpine repository indexes are required")
    for record in manifest["offline_package_closure"]:
        if record.get("repository") not in {"main", "community"} or not FILENAME.fullmatch(record.get("filename", "")) or record.get("signature_verified") is not True:
            raise ValueError("package archive was not authenticated or has a noncanonical name")
        relative = record["repository"] + "/aarch64/" + record["filename"]
        if relative in result:
            raise ValueError("duplicate package archive in authenticated closure")
        result[relative] = (root / relative, record["sha256"])
    for relative, (path, expected) in result.items():
        if not re.fullmatch(r"[0-9a-f]{64}", expected) or path.is_symlink() or not path.is_file() or domain.digest(path) != expected:
            raise ValueError(f"authenticated repository payload changed: {relative}")
    return result


def import_payloads(image: Path, payloads: dict[str, tuple[Path, str]], work: Path) -> None:
    commands = []
    for directory in ("/repositories", "/repositories/main", "/repositories/community", "/repositories/main/aarch64", "/repositories/community/aarch64"):
        listing = debugfs(image, f"stat {quote(directory)}")
        if "Inode:" not in listing:
            commands.append("mkdir " + quote(directory))
        elif "Type: directory" not in listing:
            raise ValueError(f"guest repository path is not a directory: {directory}")
    # Full closure archives are immutable; never overwrite a conflicting APK.
    check = work / "existing"
    check.mkdir()
    for ordinal, (relative, (source, expected)) in enumerate(sorted(payloads.items())):
        guest = "/repositories/" + relative
        old = check / str(ordinal)
        debugfs(image, f"dump {quote(guest)} {quote(old)}")
        if old.exists():
            if domain.digest(old) == expected:
                continue
            if relative.endswith(".apk"):
                raise ValueError(f"existing immutable package archive conflicts: {relative}")
            commands.append("rm " + quote(guest))
        commands.append("write " + quote(source) + " " + quote(guest))
        for field, value in (("uid", "0"), ("gid", "0"), ("mode", "0100644"), ("mtime", "0"), ("ctime", "0")):
            commands.append(f"set_inode_field {quote(guest)} {field} {value}")
    command_file = work / "import.debugfs"
    command_file.write_text("\n".join(commands) + "\n")
    result = subprocess.run(["debugfs", "-w", "-f", str(command_file), str(image)], capture_output=True, text=True)
    (work / "import.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError("debugfs repository import failed")
    verify = work / "readback"
    verify.mkdir()
    for ordinal, (relative, (_, expected)) in enumerate(sorted(payloads.items())):
        copied = dump_file(image, "/repositories/" + relative, verify / str(ordinal))
        if domain.digest(copied) != expected:
            raise RuntimeError(f"repository import did not preserve complete authenticated bytes: {relative}")


def publish(state: Path, candidate: Path, previous: dict, head_before: bytes | None, work: Path, result: dict,
            *, receipt_key: str = "repository_staging", expected_bytes: int | None = None) -> dict:
    current = state / "head.json"
    if (current.read_bytes() if current.exists() else None) != head_before:
        raise RuntimeError("disk head changed during repository staging")
    generations = state / "disk-generations"
    if generations.is_symlink():
        raise ValueError("disk generation store must not be a symlink")
    generations.mkdir(exist_ok=True)
    with candidate.open("rb") as stream:
        os.fsync(stream.fileno())
    expected_bytes = previous["bytes"] if expected_bytes is None else expected_bytes
    if type(expected_bytes) is not int or expected_bytes not in domain.DISK_SIZES:
        raise ValueError("candidate disk must match a supported device grant")
    fingerprint = domain.digest(candidate)
    domain.checked_file(candidate, {"bytes": expected_bytes, "sha256": fingerprint})
    destination = generations / (fingerprint + ".ext4")
    candidate.chmod(0o400)
    try:
        os.link(candidate, destination)
    except FileExistsError:
        domain.checked_file(destination, {"bytes": expected_bytes, "sha256": fingerprint})
    domain.fsync_directory(generations)
    record = {"schema": "ostadix.package-domain-disk-head/v1", "disk": domain.identity(destination),
              "previous": previous, "session": str(work), receipt_key: str(work / "result.json")}
    if head_before is not None:
        previous_head = json.loads(head_before)
        domain.validate_head(state, previous_head)
        if previous_head.get("namespace") is not None:
            namespace = previous_head["namespace"]
            domain.checked_file(Path(namespace["path"]), namespace)
            record.update(schema="ostadix.package-domain-disk-head/v2", namespace=namespace,
                          previous_namespace=namespace)
    result.update(ok=True, disk_after=record["disk"])
    domain.write_json(work / "result.json", result)
    # This is the commit point: all bytes and the referenced success receipt
    # are durable before the generation can become the selected disk head.
    domain.write_json(current, record)
    return record


def stage(state: Path, packages: list[str], cache: Path) -> dict:
    state = state.resolve()
    if not state.is_dir() or state.is_symlink():
        raise ValueError("--state must be an existing package-domain state directory")
    if not packages or not all(PACKAGE.fullmatch(package) for package in packages):
        raise ValueError("request one or more canonical APK package names/constraints")
    lock_path = state / "domain.lock"
    if lock_path.is_symlink():
        raise ValueError("domain lock must not be a symlink")
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("stop the running package domain before staging repository bytes") from error
        source, previous, head_before = current_disk(state)
        area = state / "repository-staging"
        if area.is_symlink():
            raise ValueError("repository staging directory must not be a symlink")
        area.mkdir(exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="stage-", dir=area))
        result = {"schema": "ostadix.package-domain-repository-staging/v1", "ok": False,
                  "requested_packages": packages, "disk_before": previous,
                  "scope": "authenticated repository bytes staged in a stopped domain; no package installation or execution qualification"}
        try:
            candidate = work / "candidate.ext4"
            shutil.copyfile(source, candidate)
            fsck(candidate, work / "filesystem.log", repair=True)
            before = {name: tree_identity(candidate, guest, work / ("before-" + name)) for name, guest in
                      (("work", "/work"), ("apk-configuration", "/etc/apk"), ("apk-database", "/lib/apk/db"))}
            world_path = dump_file(candidate, "/etc/apk/world", work / "world")
            world = [line.strip() for line in world_path.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]
            if not all(PACKAGE.fullmatch(package) for package in world):
                raise ValueError("guest world contains unsupported APK constraints; original installed state is unchanged")
            indexes = work / "indexes"
            for name in ("main", "community"):
                dump_file(candidate, f"/repositories/{name}/aarch64/APKINDEX.tar.gz", indexes / name / "aarch64/APKINDEX.tar.gz")
            requested = list(dict.fromkeys([*world, *packages]))
            bundle = work / "bundle"
            manifest = build_repository_bundle(bundle, indexes, cache.resolve(), requested)
            payloads = bundle_payloads(bundle, manifest)
            import_payloads(candidate, payloads, work)
            fsck(candidate, work / "filesystem.log", repair=False)
            after = {name: tree_identity(candidate, guest, work / ("after-" + name)) for name, guest in
                     (("work", "/work"), ("apk-configuration", "/etc/apk"), ("apk-database", "/lib/apk/db"))}
            if before != after:
                raise RuntimeError("repository import changed workspace, APK configuration or installed database")
            domain.checked_file(source, previous)
            result.update(bundle=domain.identity(bundle / "repository-bundle.json"),
                          repository_snapshots=manifest["repository_snapshots"],
                          staged_package_closure=manifest["offline_package_closure"],
                          workspace_and_apk_state_preserved=True, world_before=world)
            # Publish durable evidence before its disk head can reference it.
            domain.write_json(work / "result.json", result)
            publish(state, candidate, previous, head_before, work, result)
            try:
                candidate.unlink()
            except OSError:
                pass  # A private redundant hardlink does not undo a commit.
            return {**result, "receipt": str(work / "result.json")}
        except BaseException as error:
            result["error"] = str(error)
            domain.write_json(work / "result.json", result)
            raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=domain.DEFAULT_STATE)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--package", action="append", required=True)
    args = parser.parse_args()
    try:
        result = stage(args.state.expanduser(), args.package, args.cache.expanduser())
        print("OKernel signed repository staging: PASS")
        print(f"Disk generation: {result['disk_after']['path']}")
        print(f"Receipt: {result['receipt']}")
        print("Packages are staged; boot the domain and install by name with original APK or pkg.")
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        print(f"OKernel signed repository staging: FAIL\n{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
