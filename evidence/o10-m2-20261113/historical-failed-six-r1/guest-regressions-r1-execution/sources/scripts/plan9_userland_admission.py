"""Read-only inspection of an original Plan 9 provider's captured exports.

This module neither builds nor extracts anything. Its caller must separately
admit the exact build receipt and provenance pins: a self-consistent inventory
alone is not an authenticated original implementation or a lowering proof.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile
import zlib

COMMIT = "350266104f1fed81c78c3d05fa44f523bec0ae4d"
EPOCH = 1793431069
TOOLS = ("rc", "cat", "echo", "ls", "mkdir", "rm", "mv", "cp", "test",
         "sleep", "mount", "bind", "unmount", "grep", "sed", "awk", "sha1sum",
         "tar", "7c", "7a", "7l", "mk", "ar", "size", "pwd", "read", "dd", "date")
LIBRARIES = ("libc.a", "libbio.a", "libsec.a", "libmp.a")
BUILD_TOOLS = tuple("/arm64/bin/" + name for name in
                    ("7c", "7a", "7l", "mk", "rc", "mkpaqfs", "disk/mkfs",
                     "tar", "sha1sum", "aux/aout2uimage"))
EXPORTS = frozenset(("KERNEL.U", "USER.PAQ", "SERVICE", "USER.TAR", "FILES.TXT",
                     "ORIG.TXT", "TOOLS.TXT", "SOURCE.TXT", "COMMIT.TXT", "BUILD.LOG"))
CHUNK = 1024 * 1024


def _stamp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _record(item):
    if (not isinstance(item, dict) or not isinstance(item.get("path"), str)
            or not isinstance(item.get("bytes"), int) or isinstance(item["bytes"], bool)
            or item["bytes"] < 0 or not isinstance(item.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None):
        raise ValueError("invalid provider file identity")
    return item


class _StableFile:
    """Hold a regular read-only descriptor and recheck its path and bytes."""

    def __init__(self, path, expected):
        self.path = Path(path)
        self.expected = _record(expected)
        self.stream = None

    def _digest(self):
        self.stream.seek(0)
        digest, count = hashlib.sha256(), 0
        for block in iter(lambda: self.stream.read(CHUNK), b""):
            digest.update(block)
            count += len(block)
        return count, digest.hexdigest()

    def _check(self):
        if (_stamp(os.fstat(self.stream.fileno())) != self.initial
                or _stamp(self.path.lstat()) != self.initial):
            raise ValueError("provider file changed during read: " + str(self.path))

    def __enter__(self):
        before = self.path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("provider input is not a regular nonsymlink file: " + str(self.path))
        # A path swapped to a FIFO after lstat must fail without waiting for a
        # writer. Nonblocking mode has no effect on accepted regular files.
        descriptor = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise ValueError("provider descriptor is not a regular file: " + str(self.path))
        try:
            self.stream = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        try:
            self.initial = _stamp(before)
            self._check()
            if str(self.path.resolve()) != self.expected["path"]:
                raise ValueError("provider identity path differs from captured location")
            count, digest = self._digest()
            self._check()
            if (count, digest) != (self.expected["bytes"], self.expected["sha256"]):
                raise ValueError("provider input differs from captured identity: " + str(self.path))
            self.stream.seek(0)
            return self
        except BaseException:
            self.stream.close()
            raise

    def __exit__(self, kind, error, traceback):
        try:
            self._check()
            count, digest = self._digest()
            self._check()
            if (count, digest) != (self.expected["bytes"], self.expected["sha256"]):
                raise ValueError("provider bytes changed during verification: " + str(self.path))
        finally:
            self.stream.close()

    def text(self):
        self.stream.seek(0)
        try:
            return self.stream.read().decode("utf-8")
        except UnicodeError as error:
            raise ValueError("provider text inventory is not UTF-8") from error


def _directory(path):
    value = Path(path).lstat()
    if not stat.S_ISDIR(value.st_mode):
        raise ValueError("provider directory is not a nonsymlink directory: " + str(path))
    return _stamp(value)


def _listing(text):
    result = {}
    for line in text.splitlines():
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})[ \t]+(\S+)", line)
        if not match or match[2] in result:
            raise ValueError("invalid or duplicate provider hash inventory")
        result[match[2]] = match[1]
    return result


def _guest_path(name):
    if not isinstance(name, str) or "\0" in name:
        raise ValueError("invalid provider guest path")
    path = PurePosixPath(name)
    if (not path.is_absolute() or len(path.parts) < 2 or ".." in path.parts
            or name != path.as_posix() or name.startswith("//")):
        raise ValueError("noncanonical provider guest path")
    return name


def _archive_path(name):
    if not isinstance(name, str) or "\0" in name:
        raise ValueError("invalid provider archive path")
    path = PurePosixPath(name)
    if (path.is_absolute() or ".." in path.parts or not path.parts
            or path.parts[0] != "qemu.bootfs" or name != path.as_posix()):
        raise ValueError("unsafe or noncanonical provider archive path")
    return path


def _uimage(file):
    stream = file.stream
    stream.seek(0)
    header = stream.read(64)
    if len(header) != 64:
        raise ValueError("truncated original Plan9 uImage header")
    magic, checksum, timestamp, length, load, entry, data_crc, os_id, arch, kind, compression, name = struct.unpack(
        ">7I4B32s", header)
    cleared = header[:4] + bytes(4) + header[8:]
    if magic != 0x27051956 or zlib.crc32(cleared) != checksum:
        raise ValueError("invalid original Plan9 uImage header/CRC")
    if length != file.expected["bytes"] - 64 or not 0 < length <= 0x07000000:
        raise ValueError("invalid original Plan9 uImage payload length")
    if (os_id, arch, kind, compression, load, entry) != (23, 22, 2, 0, 0x40100000, 0x40100000):
        raise ValueError("unexpected original Plan9 ARM64 container/entry contract")
    if timestamp != EPOCH:
        raise ValueError("kernel did not observe fixed build clock")
    crc = 0
    for block in iter(lambda: stream.read(CHUNK), b""):
        crc = zlib.crc32(block, crc)
    if crc != data_crc:
        raise ValueError("invalid original Plan9 uImage payload CRC")
    try:
        title = name.rstrip(b"\0").decode("ascii")
    except UnicodeError as error:
        raise ValueError("original Plan9 uImage name is not ASCII") from error
    return {"os": os_id, "architecture": arch, "kind": kind, "compression": compression,
            "load": load, "entry": entry, "timestamp": timestamp, "name": title,
            "header_crc32": checksum, "payload_crc32": data_crc, "payload_bytes": length}


def _embedded_paq(kernel, paq):
    # Materialize the declared PAQ pattern and retain an overlap window. The
    # TAR, uImage CRC and identity scans stream; this pattern search does not.
    # A physically embedded pattern cannot exceed the admitted kernel payload.
    if not 0 < paq.expected["bytes"] <= kernel.expected["bytes"] - 64:
        raise ValueError("provider PAQ does not fit in the admitted kernel payload")
    paq.stream.seek(0)
    pattern = paq.stream.read()
    if not pattern:
        raise ValueError("provider PAQ is empty")
    kernel.stream.seek(64)
    tail, count, offset, found = b"", 0, 0, None
    for block in iter(lambda: kernel.stream.read(CHUNK), b""):
        window = tail + block
        position = window.find(pattern)
        while position >= 0:
            count += 1
            found = offset - len(tail) + position
            if count > 1:
                raise ValueError("provider PAQ occurs more than once in kernel payload")
            position = window.find(pattern, position + 1)
        tail = window[-(len(pattern) - 1):] if len(pattern) > 1 else b""
        offset += len(block)
    if count != 1:
        raise ValueError("kernel payload does not embed the exact provider PAQ")
    return found


def _provider(archive, hashes, declared, startup, service):
    files, seen = [], {}
    with tarfile.open(fileobj=archive.stream, mode="r:") as members:
        for member in members:
            path = _archive_path(member.name)
            if member.name in seen:
                raise ValueError("duplicate provider archive path")
            for parent in path.parents:
                if seen.get(parent.as_posix()) == "file":
                    raise ValueError("provider archive file is an ancestor")
            if member.isdir():
                if member.size != 0:
                    raise ValueError("provider directory has data")
                seen[member.name] = "directory"
                continue
            if (member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    or member.issparse() or member.sparse is not None or len(path.parts) < 2
                    or member.size < 0):
                raise ValueError("provider archive contains a nonregular member")
            if any(name.startswith(member.name + "/") for name in seen):
                raise ValueError("provider archive file replaces a directory ancestor")
            if member.mode < 0 or member.mode & ~0o777:
                raise ValueError("provider archive contains special permission bits")
            seen[member.name] = "file"
            guest = "/" + "/".join(path.parts[1:])
            if member.name not in hashes or guest not in declared:
                raise ValueError("provider file lacks its native or declared inventory")
            wanted = declared[guest]
            if member.size != wanted["bytes"]:
                raise ValueError("provider archive length differs from declared file")
            source = members.extractfile(member)
            if source is None:
                raise ValueError("provider archive member has no data")
            paired = startup if guest == "/rc/bin/okernel-start" else service if guest == "/arm64/bin/p9cmdsrv" else None
            if paired is not None:
                paired.stream.seek(0)
            digest, count = hashlib.sha256(), 0
            for block in iter(lambda: source.read(CHUNK), b""):
                digest.update(block)
                count += len(block)
                if paired is not None and paired.stream.read(len(block)) != block:
                    raise ValueError("provider startup/service differs from captured export")
            source.close()
            if (count != member.size or digest.hexdigest() != hashes[member.name]
                    or digest.hexdigest() != wanted["sha256"]):
                raise ValueError("provider content differs from complete native inventory")
            if paired is not None and paired.stream.read(1):
                raise ValueError("provider startup/service has a different length")
            files.append(dict(wanted))
        end = members.offset
    archive.stream.seek(end)
    padding = 0
    for block in iter(lambda: archive.stream.read(CHUNK), b""):
        if block.strip(b"\0"):
            raise ValueError("provider archive has nonzero data after its terminator")
        padding += len(block)
    if padding < 1024:
        raise ValueError("provider archive lacks its complete terminator")
    if (set(hashes) != {"qemu.bootfs" + item["guest_path"] for item in files}
            or set(declared) != {item["guest_path"] for item in files}):
        raise ValueError("provider archive omits an inventoried file")
    return files


def verify_exports(output: Path, captured: Path, document: dict) -> dict:
    """Inspect the complete declared exports using read-only descriptors only.

    No temporary files, extraction, chmod, subprocesses or builder imports are
    used. Receipt/source authentication remains the caller's responsibility.
    """
    output, captured = Path(output), Path(captured)
    if (not isinstance(document, dict)
            or document.get("schema") != "ostadix.original9front-userland-builder/v1"
            or document.get("source_commit") != COMMIT
            or document.get("exports_captured_after_halt") is not True):
        raise ValueError("unsupported or incomplete original provider derivation")
    export_dir = output / "artifacts"
    directories = {path: _directory(path) for path in (output, captured, export_dir)}
    names = {entry.name for entry in os.scandir(export_dir)}
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != EXPORTS or names != EXPORTS:
        raise ValueError("provider export set differs from declared complete exports")
    declared = {}
    if not isinstance(document.get("provider_files"), list):
        raise ValueError("provider file inventory is not a list")
    for item in document["provider_files"]:
        _record(item)
        guest = _guest_path(item.get("guest_path"))
        if guest in declared:
            raise ValueError("duplicate declared provider guest path")
        declared[guest] = item
    with ExitStack() as opened:
        exports = {name: opened.enter_context(_StableFile(export_dir / name, artifacts[name]))
                   for name in sorted(EXPORTS)}
        try:
            startup_id = document["inputs"]["START.RC"]
        except (KeyError, TypeError) as error:
            raise ValueError("provider startup lacks captured identity") from error
        startup = opened.enter_context(_StableFile(captured / "START.RC", startup_id))
        if exports["COMMIT.TXT"].text().strip() != COMMIT:
            raise ValueError("native source commit differs from the pinned image")
        tools = _listing(exports["TOOLS.TXT"].text())
        if set(tools) != set(BUILD_TOOLS) or tools != document.get("original_tools"):
            raise ValueError("native compiler/tool inventory is incomplete or changed")
        files = _provider(exports["USER.TAR"], _listing(exports["FILES.TXT"].text()),
                          declared, startup, exports["SERVICE"])
        by_guest = {item["guest_path"]: item for item in files}
        required = {"/arm64/bin/" + name for name in TOOLS}
        required.update("/arm64/lib/" + name for name in LIBRARIES)
        required.update(("/arm64/include/u.h", "/sys/include/libc.h", "/rc/lib/rcmain",
                         "/arm64/mkfile", "/sys/src/mkfile.proto", "/sys/src/cmd/mkone",
                         "/sys/src/cmd/mkmany", "/sys/src/cmd/mklib"))
        required.update(name for name in by_guest if name.startswith(("/arm64/include/", "/sys/include/")))
        if not required.union(("/arm64/bin/p9cmdsrv", "/rc/bin/okernel-start")) <= set(by_guest):
            raise ValueError("native provider closure is missing a required file")
        originals = _listing(exports["ORIG.TXT"].text())
        if not required <= set(originals):
            raise ValueError("original provider inventory omits required tool/header/library bytes")
        for name in required:
            if by_guest[name]["sha256"] != originals[name]:
                raise ValueError("provider changed an original file: " + name)
        for name in set(BUILD_TOOLS).intersection(by_guest):
            if by_guest[name]["sha256"] != tools[name]:
                raise ValueError("provider tool differs from the executed native tool")
        total = sum(item["bytes"] for item in files)
        if total != document.get("provider_bytes"):
            raise ValueError("provider total differs from declared byte count")
        uimage = _uimage(exports["KERNEL.U"])
        if uimage != document.get("uimage"):
            raise ValueError("provider kernel metadata differs from receipt")
        paq_offset = _embedded_paq(exports["KERNEL.U"], exports["USER.PAQ"])
    if names != {entry.name for entry in os.scandir(export_dir)}:
        raise ValueError("provider export set changed during verification")
    for path, expected in directories.items():
        if _directory(path) != expected:
            raise ValueError("provider directory changed during verification")
    return {"ok": True, "artifacts": dict(artifacts), "original_tools": tools,
            "provider_files": files, "provider_bytes": total, "uimage": uimage,
            "paq_payload_offset": paq_offset,
            "checks": ["all declared exports read with stable regular descriptors and rechecked identities",
                       "complete provider TAR and native file inventory matched without extraction",
                       "original tool/header/library closure and exact service/startup matched",
                       "uImage header/payload CRC, fixed epoch and exact metadata matched",
                       "exact readonly provider PAQ occurs once inside kernel payload"],
            "writes": [], "extractions": [], "subprocesses": []}
