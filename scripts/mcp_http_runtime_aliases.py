#!/usr/bin/env python3
"""Create checkout-local runtime aliases without replacing the raw evaluator."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import tempfile


def case_insensitive_directory(directory: Path) -> bool:
    """Probe actual directory behavior, including case-sensitive macOS volumes."""
    descriptor, temporary = tempfile.mkstemp(prefix=".ostadix-case-", dir=directory)
    os.close(descriptor)
    probe = Path(temporary)
    try:
        try:
            return probe.samefile(probe.with_name(probe.name.upper()))
        except FileNotFoundError:
            return False
    finally:
        probe.unlink()


def atomic_copy(source: Path, destination: Path) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(descriptor)
    try:
        shutil.copyfile(source, temporary)
        os.chmod(temporary, 0o755)
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def copy_executables(source: Path, destination: Path, names: list[str]) -> None:
    """Install only declared binaries; never retain references to a build cache."""
    for name in names:
        if Path(name).name != name or name in {"", ".", ".."}:
            raise ValueError(f"invalid executable name: {name}")
        executable = source / name
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError(f"compiled executable missing: {executable}")
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        atomic_copy(source / name, destination / name)


def create_runtime_aliases(build: Path) -> str:
    """Preserve raw O and return the usable command-front-door filename."""
    evaluator = build / "O"
    front_door = build / "o-cli"
    for executable in (evaluator, front_door):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError(f"compiled executable missing: {executable}")
    shared_name = case_insensitive_directory(build)
    # Preserve evaluation under a distinct name before creating any CLI alias.
    atomic_copy(evaluator, build / "ostadix-evaluator")
    if shared_name:
        # In a Cargo build directory O must remain the raw evaluator. Unlike
        # user installation directories, replacing its case-folded name would
        # corrupt the compiler output and leave Cargo's fingerprint unchanged.
        return "o-cli"
    atomic_copy(front_door, build / "o")
    return "o"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    aliases = actions.add_parser("aliases", help="preserve evaluator and create filesystem-aware command aliases")
    aliases.add_argument("build_dir", type=Path)
    copy = actions.add_parser("copy", help="atomically copy declared executable files out of a build cache")
    copy.add_argument("source_dir", type=Path)
    copy.add_argument("destination_dir", type=Path)
    copy.add_argument("names", nargs="+")
    args = parser.parse_args()
    try:
        if args.action == "copy":
            copy_executables(args.source_dir, args.destination_dir, args.names)
            print(f"Installed {len(args.names)} binaries into {args.destination_dir}")
        else:
            command = create_runtime_aliases(args.build_dir.resolve())
            print(f"Runtime aliases: raw evaluator O / ostadix-evaluator; command front door {command}")
    except (OSError, ValueError) as error:
        parser.exit(1, f"MCP runtime alias setup failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
