"""Read an immutable, quiescent namespace_store v1 snapshot.

The caller must stop the native monitor at its quiescent boundary before
capturing the exact16MiB volume. Checksums establish structural consistency,
not authenticity or quiescence. This module never serves a filesystem, writes
storage, creates a native session or confers native authority.

Validation follows runtime/common/namespace_store.oc::validate. In particular,
never-used node slots must be entirely zero; sealed tombstones retain ignored
historical fields. Unused header/node padding and free-block contents have no
meaning in that native validator and are not reinterpreted here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import struct
from types import MappingProxyType

VOLUME_BYTES = 16_777_216
NODE_COUNT = 1024
NODE_BYTES = 384
DATA_OFFSET = 397_312
BLOCK_COUNT = 3999
BLOCK_BYTES = 4096
BLOCK_DATA = 4088
MAGIC = 0x3130305039534E4F
DIR = 0x80000000
MODE_REJECT = 0x7BFFFE00  # Permit DMTMP0x04000000 as well as directory/permissions.
U32 = 0xFFFFFFFF


class VolumeError(ValueError):
    """The supplied snapshot is not a structurally valid native v1 volume."""


def fnv(data: bytes | memoryview) -> int:
    value = 0xCBF29CE484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value


@dataclass(frozen=True, slots=True)
class _Node:
    number: int
    state: int
    parent: int
    generation: int
    version: int
    mode: int
    length: int
    head: int
    mtime: int
    name: bytes
    blocks: tuple[int, ...] = ()

    @property
    def directory(self) -> bool:
        return bool(self.mode & DIR)


@dataclass(frozen=True, slots=True, init=False)
class Volume:
    """Validated immutable bytes; all returned file data are immutable copies.

    Paths are absolute native paths, with no dot or empty components. Native
    names are byte strings, so str paths/listings use UTF8 surrogateescape.
    FileNotFoundError, NotADirectoryError and IsADirectoryError describe lookup
    errors; VolumeError describes malformed snapshots and path syntax.
    """

    _data: bytes
    _nodes: object
    _children: object
    _used_blocks: frozenset[int]
    clock: int
    sha256: str

    def __init__(self, snapshot: bytes | bytearray | memoryview):
        if not isinstance(snapshot, (bytes, bytearray, memoryview)):
            raise TypeError("snapshot must be captured bytes")
        data = bytes(snapshot)
        if len(data) != VOLUME_BYTES:
            raise VolumeError("namespace snapshot must contain exactly16MiB")
        view = memoryview(data)

        def word(offset):
            return struct.unpack_from("<Q", data, offset)[0]

        if struct.unpack_from("<6Q", data) != (MAGIC, 1, NODE_COUNT, VOLUME_BYTES, DATA_OFFSET, BLOCK_COUNT):
            raise VolumeError("unknown native volume header/layout")
        if word(48) != fnv(view[:48]):
            raise VolumeError("native volume header seal mismatch")
        clock, clock_seal = word(56), word(64)
        if (clock == 0 and clock_seal != 0) or (clock != 0 and (clock > U32 - 1 or clock_seal != fnv(view[56:64]))):
            raise VolumeError("native volume clock seal/range mismatch")

        nodes = {}
        children = {}
        used = set()
        for number in range(1, NODE_COUNT + 1):
            offset = 4096 + (number - 1) * NODE_BYTES
            fields = struct.unpack_from("<9Q", data, offset)
            state, parent, generation, version, mode, length, head, mtime, name_length = fields
            if state > 2:
                raise VolumeError(f"node{number}: invalid state")
            if state == 0:
                if any(view[offset:offset + NODE_BYTES]):
                    raise VolumeError(f"node{number}: nonzero unused slot")
                continue
            if word(offset + 376) != fnv(view[offset:offset + 376]):
                raise VolumeError(f"node{number}: seal mismatch")
            if not 0 < generation <= U32 or mtime > U32 - 1:
                raise VolumeError(f"node{number}: generation/clock range")
            clock = max(clock, mtime)
            if state == 2:
                nodes[number] = _Node(number, state, parent, generation, version, mode, length, head, mtime, b"")
                continue
            if not 0 < version <= U32 or mode & MODE_REJECT:
                raise VolumeError(f"node{number}: version/mode range")
            if number == 1:
                if parent != 1 or not mode & DIR or name_length != 1 or data[offset + 72] != 47:
                    raise VolumeError("invalid native root")
            elif not 0 < name_length <= 255:
                raise VolumeError(f"node{number}: name length")
            name = data[offset + 72:offset + 72 + name_length]
            if number != 1 and (name in (b".", b"..") or b"\0" in name or b"/" in name):
                raise VolumeError(f"node{number}: invalid name")
            if number != 1:
                key = (parent, name)
                if key in children:
                    raise VolumeError(f"node{number}: duplicate sibling name")
                children[key] = number
            if mode & DIR and (length or head):
                raise VolumeError(f"node{number}: directory carries file blocks")
            count = (length + BLOCK_DATA - 1) // BLOCK_DATA
            if count > BLOCK_COUNT:
                raise VolumeError(f"node{number}: file exceeds volume capacity")
            chain = []
            current = head
            for _ in range(count):
                if not 0 < current <= BLOCK_COUNT or current in used:
                    raise VolumeError(f"node{number}: invalid/cyclic/shared block chain")
                used.add(current)
                chain.append(current)
                current = word(DATA_OFFSET + (current - 1) * BLOCK_BYTES)
            if current:
                raise VolumeError(f"node{number}: block chain exceeds file length")
            nodes[number] = _Node(number, state, parent, generation, version, mode, length, head, mtime, name, tuple(chain))

        def live(number):
            node = nodes.get(number)
            return node if node is not None and node.state == 1 else None

        if live(1) is None:
            raise VolumeError("missing native root")
        for number in range(2, 6):
            node = live(number)
            if node is None or not node.directory or node.parent != 1:
                raise VolumeError("missing native provisioned directory")
        for node in nodes.values():
            if node.state != 1 or node.number == 1:
                continue
            seen = set()
            current = node
            while current.number != 1:
                if current.number in seen:
                    raise VolumeError(f"node{node.number}: parent cycle")
                seen.add(current.number)
                parent = live(current.parent)
                if parent is None or not parent.directory:
                    raise VolumeError(f"node{node.number}: missing/non-directory parent")
                current = parent

        object.__setattr__(self, "_data", data)
        object.__setattr__(self, "_nodes", MappingProxyType(nodes))
        object.__setattr__(self, "_children", MappingProxyType(children))
        object.__setattr__(self, "_used_blocks", frozenset(used))
        object.__setattr__(self, "clock", clock)
        object.__setattr__(self, "sha256", hashlib.sha256(data).hexdigest())

    @classmethod
    def from_file(cls, path: str | Path) -> Volume:
        """Read one regular captured snapshot; never follow a final symlink."""
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size != VOLUME_BYTES:
                raise VolumeError("snapshot must be a regular exact16MiB file")
            chunks = []
            remaining = VOLUME_BYTES
            while remaining:
                data = os.read(descriptor, min(remaining, 1 << 20))
                if not data:
                    raise VolumeError("snapshot changed/truncated while reading")
                chunks.append(data)
                remaining -= len(data)
            after = os.fstat(descriptor)
            if os.read(descriptor, 1) or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise VolumeError("snapshot changed while reading")
            return cls(b"".join(chunks))
        finally:
            os.close(descriptor)

    def _resolve(self, path: str | bytes) -> _Node:
        if isinstance(path, str):
            path = path.encode("utf-8", "surrogateescape")
        if not isinstance(path, bytes) or not path.startswith(b"/") or b"\0" in path:
            raise VolumeError("native path must be absolute and contain no NUL")
        if path == b"/":
            return self._nodes[1]
        parts = path[1:].split(b"/")
        if any(not part or part in (b".", b"..") or len(part) > 255 for part in parts):
            raise VolumeError("native path must contain canonical components")
        node = self._nodes[1]
        for part in parts:
            if not node.directory:
                raise NotADirectoryError(path)
            number = self._children.get((node.number, part))
            if number is None:
                raise FileNotFoundError(path)
            node = self._nodes[number]
        return node

    def get(self, path: str | bytes) -> bytes:
        node = self._resolve(path)
        if node.directory:
            raise IsADirectoryError(path)
        chunks = []
        remaining = node.length
        for number in node.blocks:
            offset = DATA_OFFSET + (number - 1) * BLOCK_BYTES + 8
            count = min(remaining, BLOCK_DATA)
            chunks.append(self._data[offset:offset + count])
            remaining -= count
        return b"".join(chunks)

    def listdir(self, path: str | bytes = "/") -> tuple[str, ...]:
        node = self._resolve(path)
        if not node.directory:
            raise NotADirectoryError(path)
        return tuple(name.decode("utf-8", "surrogateescape") for parent, name in sorted(self._children) if parent == node.number)

    def usage(self) -> dict[str, int]:
        live = [node for node in self._nodes.values() if node.state == 1]
        tombstones = sum(node.state == 2 for node in self._nodes.values())
        return {"volume_bytes": VOLUME_BYTES, "node_capacity": NODE_COUNT, "live_nodes": len(live),
                "tombstone_nodes": tombstones, "unused_nodes": NODE_COUNT - len(live) - tombstones,
                "block_capacity": BLOCK_COUNT, "used_blocks": len(self._used_blocks),
                "free_blocks": BLOCK_COUNT - len(self._used_blocks), "block_payload_bytes": BLOCK_DATA,
                "allocated_payload_bytes": len(self._used_blocks) * BLOCK_DATA,
                "file_bytes": sum(node.length for node in live if not node.directory)}
