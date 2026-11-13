#!/usr/bin/env python3
"""Inspect stale official Nix profile backups; archive only recognized remnants.

No-argument inspection is read-only. Setup probes --plan-repair before asking
for administrator access; status 3 means a narrowly validated repair is needed.
The privileged invocation validates the files and installation state again.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import grp
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Callable


PROFILES = ("bashrc", "profile.d/nix.sh", "zshrc", "bash.bashrc", "zsh/zshrc")
SUFFIX = ".backup-before-nix"
NIX_BLOCK = re.compile(
    rb"(?:\s*# Nix\nif \[ -e '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh' \]; then\n"
    rb"[ \t]+\. '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh'\nfi\n# End Nix\s*)+"
)


class RecoveryError(Exception):
    """A profile or installation needs manual inspection."""


@dataclass(frozen=True)
class Snapshot:
    path: Path
    identity: tuple[int, ...]
    digest: str


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def check_parents(path: Path, etc: Path, owner: int | None) -> None:
    """Reject redirected or writable profile directories, including absent leaves."""
    current = etc
    for part in (None, *path.relative_to(etc).parts[:-1]):
        if part is not None:
            current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise RecoveryError(f"unsafe profile directory: {current}")
        if owner is not None and info.st_uid != owner:
            raise RecoveryError(f"unexpected profile directory owner: {current}")


def read_snapshot(path: Path, etc: Path, owner: int | None) -> tuple[Snapshot, bytes] | None:
    check_parents(path, etc, owner)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022:
        raise RecoveryError(f"not a private regular profile file: {path}")
    if owner is not None and info.st_uid != owner:
        raise RecoveryError(f"unexpected profile owner: {path}")
    if info.st_size > 131072:
        raise RecoveryError(f"profile too large for automatic recovery: {path}")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        if identity(os.fstat(stream.fileno())) != identity(info):
            raise RecoveryError(f"profile changed while reading: {path}")
        data = stream.read(131073)
    if identity(path.lstat()) != identity(info) or len(data) != info.st_size:
        raise RecoveryError(f"profile changed while reading: {path}")
    return Snapshot(path, identity(info), hashlib.sha256(data).hexdigest()), data


def has_backups(etc: Path) -> bool:
    return any(os.path.lexists(etc / (name + SUFFIX)) for name in PROFILES)


def plan_recovery(etc: Path, *, installed: bool = False,
                  evidence: tuple[str, ...] = (), owner: int | None = None) -> list[Snapshot]:
    if installed or not has_backups(etc):
        return []
    if evidence:
        raise RecoveryError("existing or incomplete Nix installation: " + "; ".join(evidence))
    candidates: list[Snapshot] = []
    for name in PROFILES:
        profile, backup = etc / name, etc / (name + SUFFIX)
        before = read_snapshot(backup, etc, owner)
        active = read_snapshot(profile, etc, owner)
        if before:
            snapshot, data = before
            if data.strip() and not NIX_BLOCK.fullmatch(data):
                raise RecoveryError(f"backup contains custom or unrecognized content: {backup}")
            candidates.append(snapshot)
        if active:
            snapshot, data = active
            if NIX_BLOCK.fullmatch(data) or (before and not data.strip()):
                candidates.append(snapshot)
            elif before or b"/nix/" in data or b"# Nix" in data:
                raise RecoveryError(f"profile contains custom or unrecognized content: {profile}")
    return candidates


def revalidate(plan: list[Snapshot], etc: Path, owner: int | None) -> None:
    for expected in plan:
        current = read_snapshot(expected.path, etc, owner)
        if current is None or current[0] != expected:
            raise RecoveryError(f"profile changed since inspection: {expected.path}")


def archive_profiles(plan: list[Snapshot], etc: Path, *, owner: int | None = None,
                     state_check: Callable[[], tuple[str, ...]] = lambda: ()) -> Path | None:
    if not plan:
        return None
    evidence = state_check()
    if evidence:
        raise RecoveryError("Nix state changed before recovery: " + "; ".join(evidence))
    revalidate(plan, etc, owner)
    archive = Path(tempfile.mkdtemp(prefix="nix-profile-recovery-", dir=etc))
    moved: list[tuple[Snapshot, Path]] = []
    try:
        manifest = [{"original": str(item.path),
                     "archived": item.path.relative_to(etc).as_posix().replace("/", "__"),
                     "sha256": item.digest} for item in plan]
        with (archive / "manifest.json").open("x") as stream:
            json.dump(manifest, stream, indent=2)
            stream.write("\n")
        for item, record in zip(plan, manifest):
            revalidate([item], etc, owner)
            target = archive / record["archived"]
            # A private newly created directory has no pre-existing targets.
            if os.path.lexists(target):
                raise RecoveryError(f"archive destination unexpectedly exists: {target}")
            item.path.rename(target)
            moved.append((item, target))
            if hashlib.sha256(target.read_bytes()).hexdigest() != item.digest:
                raise RecoveryError(f"archived bytes changed: {target}")
    except (OSError, RecoveryError) as error:
        unrestored = []
        for original, target in reversed(moved):
            try:
                check_parents(original.path, etc, owner)
                if os.path.lexists(original.path):
                    raise RecoveryError("original path occupied")
                target.rename(original.path)
            except (OSError, RecoveryError):
                unrestored.append(str(target))
        detail = "; preserved in archive: " + ", ".join(unrestored) if unrestored else "; moved profiles restored"
        raise RecoveryError(f"archival failed: {error}{detail}; receipt: {archive}") from error
    return archive


def user_homes() -> set[Path]:
    homes = {Path.home(), Path(pwd.getpwuid(0).pw_dir)}
    if os.geteuid() == 0 and os.environ.get("SUDO_UID", "").isdigit():
        homes.add(Path(pwd.getpwuid(int(os.environ["SUDO_UID"])).pw_dir))
    return homes


def installation_evidence() -> tuple[str, ...]:
    paths = [Path(p) for p in (
        "/nix", "/etc/nix", "/Library/LaunchDaemons/org.nixos.nix-daemon.plist",
        "/Library/LaunchDaemons/org.nixos.darwin-store.plist",
        "/etc/systemd/system/nix-daemon.service", "/etc/systemd/system/nix-daemon.socket",
        "/usr/lib/systemd/system/nix-daemon.service", "/usr/lib/systemd/system/nix-daemon.socket",
        "/lib/systemd/system/nix-daemon.service", "/lib/systemd/system/nix-daemon.socket",
    )]
    for home in user_homes():
        paths.extend(home / name for name in (".nix-profile", ".nix-defexpr", ".nix-channels"))
    evidence = [str(path) for path in paths if os.path.lexists(path)]
    if shutil.which("nix"):
        evidence.append("nix executable on PATH")
    try:
        grp.getgrnam("nixbld")
        evidence.append("nixbld build group")
    except KeyError:
        pass
    for name in ("/etc/fstab", "/etc/synthetic.conf"):
        path = Path(name)
        if path.exists():
            for line in path.read_text().splitlines():
                fields = line.split()
                if fields and not fields[0].startswith("#") and ("/nix" in fields or fields[0] == "nix"):
                    evidence.append(f"Nix mount configuration in {name}")
    mount = subprocess.run(["/sbin/mount" if sys.platform == "darwin" else "/bin/mount"],
                           capture_output=True, text=True, timeout=10, check=False)
    if mount.returncode:
        raise RecoveryError("cannot inspect mounted filesystems")
    if re.search(r"\son\s/nix(?:\s|/)", mount.stdout):
        evidence.append("mounted Nix filesystem")
    if sys.platform == "darwin":
        daemon = subprocess.run(["/bin/launchctl", "print", "system/org.nixos.nix-daemon"],
                                capture_output=True, timeout=10, check=False)
        if daemon.returncode == 0:
            evidence.append("loaded Nix daemon")
        disks = subprocess.run(["/usr/sbin/diskutil", "apfs", "list", "-plist"],
                               capture_output=True, timeout=10, check=False)
        if disks.returncode:
            raise RecoveryError("cannot inspect APFS Nix volumes")
        for container in plistlib.loads(disks.stdout).get("Containers", []):
            for volume in container.get("Volumes", []):
                if "nix" in volume.get("Name", "").lower():
                    evidence.append("APFS volume " + volume["Name"])
    return tuple(evidence)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--repair", action="store_true", help="archive only verified stale Nix-only profiles and backups")
    mode.add_argument("--plan-repair", action="store_true", help="read-only probe; exit 3 when recovery is possible")
    parser.add_argument("--dry-run", action="store_true", help="report the repair without changing files")
    args = parser.parse_args(argv)
    try:
        etc = Path("/etc").resolve(strict=True)
        installed = shutil.which("nix") is not None or os.access("/nix/var/nix/profiles/default/bin/nix", os.X_OK)
        evidence = installation_evidence() if not installed and has_backups(etc) else ()
        plan = plan_recovery(etc, installed=installed, evidence=evidence, owner=0)
        if not plan:
            return 0
        for item in plan:
            print(f"Nix profile recovery: archive {item.path}")
        if args.plan_repair:
            return 3
        if args.repair and args.dry_run:
            print("[DRY] archive these files in a new private /etc/nix-profile-recovery-* directory")
            return 0
        if args.repair:
            if os.geteuid() != 0:
                raise RecoveryError("administrator access is required to archive system profiles")
            archive = archive_profiles(plan, etc, owner=0, state_check=installation_evidence)
            print(f"Nix profile recovery complete. Originals and manifest preserved at {archive}")
            return 0
        raise RecoveryError("stale Nix profile backups would stop the official installer; rerun setup with --repair-nix-profiles to archive these verified remnants")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, RecoveryError) as error:
        print(f"Error: {error}. No installer was run. Inspect the named files manually or use --no-nix to exclude Nix.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
