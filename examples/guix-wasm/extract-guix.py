#!/usr/bin/env python3
"""Verify and unpack the pinned Guix distribution inside the image build only."""

import hashlib
from pathlib import Path, PurePosixPath
import sys
import tarfile


ARCHIVE_SHA256 = "aa41025489c5061543e9c48873eaa829b900b2da75d40f9648913622f5f47817"


def verify_and_extract(archive: Path, destination: Path) -> None:
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != ARCHIVE_SHA256:
        raise ValueError("Guix binary archive SHA-256 mismatch; nothing extracted")

    with tarfile.open(archive, mode="r:xz") as distribution:
        members = distribution.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            parts = path.parts
            if path.is_absolute() or ".." in parts:
                raise ValueError(f"unexpected archive path: {member.name!r}")
            allowed = (
                (member.isdir() and parts in [(), ("gnu",), ("var",)])
                or parts[:2] == ("gnu", "store")
                or parts[:2] == ("var", "guix")
            )
            if not allowed or not (
                member.isdir() or member.isfile() or member.issym() or member.islnk()
            ):
                raise ValueError(f"unexpected archive member: {member.name!r}")
        # Store/profile links intentionally contain absolute /gnu/store paths.
        # This trust applies ONLY after the immutable release hash above matches;
        # the generic "data" filter would rewrite/reject the required link layout.
        distribution.extractall(destination, members=members, filter="fully_trusted")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: extract-guix.py ARCHIVE IMAGE_ROOT")
    verify_and_extract(Path(sys.argv[1]), Path(sys.argv[2]))
