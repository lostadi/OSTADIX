#!/usr/bin/env python3
"""Install the pinned Lean 4 toolchain for Ostadix MCP verification."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
import zipfile


VERSION = "4.24.0"
GUEST = "ostadix-lean"
GUEST_ROOT = Path("/opt") / f"lean-{VERSION}"
RELEASE = f"https://github.com/leanprover/lean4/releases/download/v{VERSION}"


class LeanInstallError(RuntimeError):
    pass


def asset_stem(system: str, machine: str) -> str:
    architecture = machine.lower()
    if architecture in ("amd64", "x86_64", "x64"):
        suffix = ""
    elif architecture in ("aarch64", "arm64"):
        suffix = "_aarch64"
    else:
        raise LeanInstallError(f"Lean {VERSION} has no supported archive for {machine}")
    systems = {"linux": "linux", "darwin": "darwin", "windows": "windows"}
    try:
        name = systems[system.lower()]
    except KeyError as error:
        raise LeanInstallError(f"Lean {VERSION} has no supported archive for {system}") from error
    return f"lean-{VERSION}-{name}{suffix}"


def executable_name() -> str:
    return "lean.exe" if platform.system().lower() == "windows" else "lean"


def verify_executable(executable: Path) -> str:
    try:
        result = subprocess.run(
            [os.fspath(executable), "--version"],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except OSError as error:
        raise LeanInstallError(f"cannot execute {executable}: {error}") from error
    identity = result.stdout.strip()
    if result.returncode != 0 or not identity.startswith(f"Lean (version {VERSION},"):
        raise LeanInstallError(
            f"expected Lean {VERSION} from {executable}; got {identity!r} {result.stderr.strip()!r}"
        )
    return identity


def extract_archive(archive_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        roots = {
            PurePosixPath(member.filename).parts[0]
            for member in members
            if PurePosixPath(member.filename).parts
        }
        if len(roots) != 1:
            raise LeanInstallError("Lean archive must contain exactly one top-level directory")
        for member in members:
            path = PurePosixPath(member.filename)
            if (
                not path.parts
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in member.filename
            ):
                raise LeanInstallError(f"unsafe Lean archive member: {member.filename!r}")
            relative = path.parts[1:]
            if not relative:
                continue
            target = destination.joinpath(*relative)
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise LeanInstallError(f"Lean archive symlink is not accepted: {member.filename!r}")
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            if mode:
                target.chmod(stat.S_IMODE(mode))


def install_native(root: Path) -> None:
    executable = root / "bin" / executable_name()
    if root.exists():
        verify_executable(executable)
        return
    stem = asset_stem(platform.system(), platform.machine())
    url = f"{RELEASE}/{stem}.zip"
    root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".lean-install-", dir=root.parent) as temporary:
        workspace = Path(temporary)
        archive_path = workspace / "lean.zip"
        print(f"Downloading {url}")
        with urllib.request.urlopen(url, timeout=120) as response, archive_path.open("wb") as output:
            shutil.copyfileobj(response, output)
        extracted = workspace / "toolchain"
        extract_archive(archive_path, extracted)
        identity = verify_executable(extracted / "bin" / executable_name())
        os.replace(extracted, root)
    print(identity)


def guest_command(proot: str, *arguments: str) -> list[str]:
    return [proot, "login", GUEST, "--", *arguments]


def guest_has_lean(proot: str) -> bool:
    result = subprocess.run(
        guest_command(proot, os.fspath(GUEST_ROOT / "bin" / "lean"), "--version"),
        text=True,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip().startswith(
        f"Lean (version {VERSION},"
    )


def install_termux(root: Path) -> None:
    proot = shutil.which("proot-distro")
    if proot is None:
        raise LeanInstallError(
            "Android setup requires proot-distro; install it with pkg or omit --with-lean"
        )
    listed_result = subprocess.run(
        [proot, "list"], text=True, capture_output=True, check=True
    )
    listed = (listed_result.stdout or "") + (listed_result.stderr or "")
    if not re.search(rf"(?m)^\s*\*\s*{re.escape(GUEST)}\s*$", listed):
        subprocess.run(
            [proot, "install", "-n", GUEST, "debian:stable-slim"], check=True
        )
    if not guest_has_lean(proot):
        for arguments in (
            ("/usr/bin/apt-get", "update"),
            (
                "/usr/bin/apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                "ca-certificates",
                "curl",
                "gcc",
                "make",
                "zstd",
            ),
            ("/bin/mkdir", "-p", os.fspath(GUEST_ROOT)),
        ):
            subprocess.run(guest_command(proot, *arguments), check=True)
        stem = asset_stem("linux", platform.machine())
        url = f"{RELEASE}/{stem}.tar.zst"
        pipeline = (
            f"/usr/bin/curl -fsSL --retry 3 {shlex.quote(url)} | "
            f"/usr/bin/tar -I /usr/bin/zstd -x --strip-components=1 -C {shlex.quote(os.fspath(GUEST_ROOT))}"
        )
        subprocess.run(
            guest_command(proot, "/bin/bash", "-o", "pipefail", "-c", pipeline),
            check=True,
        )
        subprocess.run(
            guest_command(proot, "/bin/rm", "-rf", "/var/lib/apt/lists"), check=True
        )
    result = subprocess.run(
        guest_command(proot, os.fspath(GUEST_ROOT / "bin" / "lean"), "--version"),
        text=True,
        capture_output=True,
        check=True,
    )
    identity = result.stdout.strip()
    if not identity.startswith(f"Lean (version {VERSION},"):
        raise LeanInstallError(f"unexpected Android Lean identity: {identity!r}")
    bin_directory = root / "bin"
    bin_directory.mkdir(parents=True, exist_ok=True)
    for name in ("lean", "lake", "leanc"):
        wrapper = bin_directory / name
        temporary = bin_directory / f".{name}.{os.getpid()}"
        temporary.write_text(
            "#!/bin/sh\n"
            f"exec {shlex.quote(proot)} login --work-dir \"$PWD\" {GUEST} -- "
            f"{GUEST_ROOT / 'bin' / name} \"$@\"\n",
            encoding="utf-8",
        )
        temporary.chmod(0o755)
        os.replace(temporary, wrapper)
    print(identity)


def link_executables(root: Path, bin_directory: Path, termux: bool) -> None:
    bin_directory.mkdir(parents=True, exist_ok=True)
    names = ("lean.exe", "lake.exe", "leanc.exe") if executable_name().endswith(".exe") else ("lean", "lake", "leanc")
    for name in names:
        source = root / "bin" / name
        destination = bin_directory / name
        if destination.is_symlink():
            if destination.resolve() == source.resolve():
                continue
            print(f"Keeping existing unmanaged {destination}")
            continue
        if destination.exists():
            content = destination.read_text(encoding="utf-8", errors="replace") if destination.is_file() else ""
            if not (
                termux
                and content.startswith("#!/bin/sh\n")
                and f"proot-distro login {GUEST} -- {GUEST_ROOT / 'bin' / name}" in content
            ):
                print(f"Keeping existing unmanaged {destination}")
                continue
            destination.unlink()
        try:
            destination.symlink_to(source)
        except OSError as error:
            print(f"Could not link {destination}: {error}; use {source.parent} on PATH")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.home() / ".local" / "share" / "ostadix" / f"lean-{VERSION}",
    )
    parser.add_argument("--bin-dir", type=Path)
    parser.add_argument("--termux", action="store_true", default=bool(os.environ.get("TERMUX_VERSION")))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.expanduser().absolute()
    executable = root / "bin" / ("lean" if arguments.termux else executable_name())
    if arguments.check:
        print(verify_executable(executable))
        return 0
    if arguments.dry_run:
        target = f"Android guest {GUEST}" if arguments.termux else asset_stem(platform.system(), platform.machine())
        print(f"Would install Lean {VERSION} for {target} at {root}")
        if arguments.bin_dir:
            print(f"Would link lean, lake and leanc in {arguments.bin_dir}")
        return 0
    try:
        if arguments.termux:
            install_termux(root)
        else:
            install_native(root)
        if arguments.bin_dir:
            link_executables(root, arguments.bin_dir.expanduser().absolute(), arguments.termux)
        print(f"OSTADIX_LEAN={executable}")
        return 0
    except (LeanInstallError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print(f"Lean installation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
