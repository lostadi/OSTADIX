#!/usr/bin/env python3
"""Verify the immutable README relocation without requiring old Git objects.

The link map uses Unicode character offsets; its header offset is in bytes.
Current claims live elsewhere. The preserved header and exact map are pinned so
neither can be rewritten to present the historical snapshot as current evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


ORIGINAL_COMMIT = "1da570dcc61ef10285fc8c8b78a20ca087081daf"
ORIGINAL_SHA256 = "3b18f2ef35c2c4449662aa185f1f798918110faab490540ee3aec7483a6b057c"
MAP_SHA256 = "697347ecb1dadd45ad64a21ad962dc750a35f820cc12c58df7ffc7878ad658d1"
HEADER_SHA256 = "03afcf8938a6b0cfd739c0385729a648c389f72a1a361ab824a1794f1cde9741"
RELOCATION_COUNT = 148


class ReferenceError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reconstruct_original(reference: bytes, map_bytes: bytes) -> bytes:
    if sha256(map_bytes) != MAP_SHA256:
        raise ReferenceError("the preserved README link map changed")
    try:
        manifest = json.loads(map_bytes)
    except (ValueError, UnicodeError) as error:
        raise ReferenceError("the README link map is not valid UTF-8 JSON") from error
    if (manifest.get("schema") != "ostadix.readme-relocation/v1"
            or manifest.get("original_commit") != ORIGINAL_COMMIT
            or manifest.get("original_path") != "README.md"
            or manifest.get("original_sha256") != ORIGINAL_SHA256
            or manifest.get("reference_path") != "docs/REFERENCE.md"
            or manifest.get("content_preserved_except_recorded_link_destinations") is not True):
        raise ReferenceError("the README link map has a different source identity")
    header_bytes = manifest.get("reference_header_bytes")
    if type(header_bytes) is not int or header_bytes <= 0:
        raise ReferenceError("the preserved reference header length is invalid")
    if sha256(reference[:header_bytes]) != HEADER_SHA256:
        raise ReferenceError("the preserved reference's historical header changed")
    body_bytes = reference[header_bytes:]
    if sha256(body_bytes) != manifest.get("reference_body_sha256"):
        raise ReferenceError("the preserved reference body changed")
    try:
        body = body_bytes.decode("utf-8", "strict")
    except UnicodeError as error:
        raise ReferenceError("the preserved reference body is not UTF-8") from error
    relocations = manifest.get("link_relocations")
    if not isinstance(relocations, list) or len(relocations) != RELOCATION_COUNT:
        raise ReferenceError("the preserved reference needs all 148 link relocations")
    original_cursor = rendered_cursor = 0
    chunks = []
    for entry in relocations:
        start, end = entry.get("original_start"), entry.get("original_end")
        before, after = entry.get("before"), entry.get("after")
        if (type(start) is not int or type(end) is not int
                or not isinstance(before, str) or not before
                or after != "../" + before or end - start != len(before)
                or start < original_cursor):
            raise ReferenceError("a preserved link relocation is malformed or overlaps")
        gap = start - original_cursor
        unchanged = body[rendered_cursor:rendered_cursor + gap]
        if len(unchanged) != gap:
            raise ReferenceError("the preserved reference ends before a recorded link")
        chunks.append(unchanged)
        rendered_cursor += gap
        if body[rendered_cursor:rendered_cursor + len(after)] != after:
            raise ReferenceError("the preserved reference differs at a recorded link")
        chunks.append(before)
        rendered_cursor += len(after)
        original_cursor = end
    chunks.append(body[rendered_cursor:])
    original = "".join(chunks).encode("utf-8")
    if sha256(original) != ORIGINAL_SHA256:
        raise ReferenceError("reconstructed README differs from the pinned original SHA-256")
    return original


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        original = reconstruct_original(
            (args.root / "docs/REFERENCE.md").read_bytes(),
            (args.root / "docs/readme-link-map.json").read_bytes(),
        )
    except (OSError, ReferenceError) as error:
        print(f"PRESERVED README DRIFT: {error}", file=sys.stderr)
        return 1
    print(f"Preserved README reference: PASS ({ORIGINAL_COMMIT[:8]}, "
          f"SHA-256 {sha256(original)}, {RELOCATION_COUNT} link relocations)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
