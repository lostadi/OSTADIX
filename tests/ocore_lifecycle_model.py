"""Independent immutable contract model for O10 and namespace lifecycle tests.

This module does not import the compiler, production transition helpers, or a
candidate runner. Session names are symbolic allocation identities. Their
correspondence with the candidate's opaque integer tokens is checked separately.
Hardware effects are observations of a transition, never part of state equality.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
import struct

U32 = (1 << 32) - 1
U64 = (1 << 64) - 1
SERIAL_MAX = (1 << 63) - 1
ROOTS = {1: 1, 2: 2, 3: 2, 4: 1}
WRITERS = frozenset((1, 2, 4))
DIR = 0x80000000
READ_ME = (b"O-core owns this namespace. Linux and the native Plan 9 wire peer share "
           b"these objects through separately granted 9P2000 sessions. Full Plan 9 ABI is not provided.\n")
ERROR_TEXT = {1: b"Protocol error", 2: b"permission denied", 3: b"file does not exist",
              4: b"fid unknown or out of range", 5: b"No space left on device",
              6: b"file already exists", 7: b"not a directory", 8: b"directory is not empty",
              9: b"Operation not supported"}
ERRNO = {1: 71, 2: 13, 3: 2, 4: 116, 5: 28, 6: 17, 7: 20, 8: 39, 9: 95}


@dataclass(frozen=True)
class Limits:
    domain: int = U32
    lease: int = U32
    block: int = U32
    network: int = U32
    transport: int = U64
    session_epoch: int = U64
    serial: int = SERIAL_MAX
    request_epoch: int = U64
    request_sequence: int = U64
    journal: int = 256
    fids: int = 512
    objects: int = 1024
    incarnation: int = U32

    def __post_init__(self):
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError("positive finite limit required: " + name)
        if self.domain > U32 or self.lease > U32 or self.block > U32 or self.network > U32:
            raise ValueError("packed identity generations are 32 bit")
        if self.transport > U64 or self.session_epoch > U64 or self.serial > SERIAL_MAX:
            raise ValueError("epoch/serial representation exceeded")


@dataclass(frozen=True)
class Token:
    symbol: int
    grant: int
    dotu: bool = False


@dataclass(frozen=True)
class Grant:
    number: int
    generation: int = 0
    current: int = 0
    versioned: bool = False
    msize: int = 8192


@dataclass(frozen=True)
class Object:
    number: int
    parent: int
    name: bytes
    mode: int
    incarnation: int = 1
    version: int = 1
    modified: int = 0
    data: bytes = b""
    live: bool = True

    def qid(self):
        return bytes(((self.mode >> 24) & 255,)) + struct.pack("<IQ", self.version,
                                                               (self.incarnation << 32) | self.number)


@dataclass(frozen=True)
class Fid:
    session: int
    number: int
    object: int
    incarnation: int
    mode: int = 255


@dataclass(frozen=True)
class Namespace:
    grants: tuple[Grant, ...] = tuple(Grant(n) for n in range(1, 5))
    tokens: tuple[Token, ...] = ()
    serial: int = 0
    fids: tuple[Fid, ...] = ()
    objects: tuple[Object, ...] = ()
    clock: int = 6
    ready: bool = True

    @classmethod
    def fresh(cls):
        objects = tuple(Object(n, 1, name, mode, modified=n, data=data)
                        for n, name, mode, data in (
                            (1, b"/", DIR | 0o755, b""), (2, b"work", DIR | 0o755, b""),
                            (3, b"pkg", DIR | 0o755, b""), (4, b"build", DIR | 0o755, b""),
                            (5, b"services", DIR | 0o755, b""), (6, b"nativeREADME", 0o644, READ_ME)))
        return cls(objects=objects)

    def grant(self, number):
        return next((g for g in self.grants if g.number == number), None)

    def token(self, symbol):
        return next((t for t in self.tokens if t.symbol == symbol), None)

    def owner(self, symbol):
        return next((g for g in self.grants if g.current == symbol and symbol), None)

    def change_grant(self, grant):
        return replace(self, grants=tuple(grant if g.number == grant.number else g for g in self.grants))

    def current(self, number):
        grant = self.grant(number)
        return grant.current if self.ready and grant else 0

    def session(self, number, generation, limits=Limits(), expected=None):
        grant = self.grant(number)
        if (not self.ready or grant is None or generation <= 0 or generation > limits.session_epoch
                or generation <= grant.generation or self.serial >= limits.serial
                or (expected is not None and grant.current != expected)):
            return self, 0
        symbol = self.serial + 1
        result = self.change_grant(replace(grant, generation=generation, current=symbol,
                                          versioned=False, msize=8192))
        result = replace(result, serial=symbol, tokens=(*result.tokens, Token(symbol, number)),
                         fids=tuple(f for f in result.fids if f.session != grant.current))
        return result, symbol

    def revoke(self, number, expected=None):
        grant = self.grant(number)
        if (not self.ready or grant is None or (expected is not None
                and (not expected or grant.current != expected))):
            return self, 0
        result = self.change_grant(replace(grant, current=0, versioned=False))
        return replace(result, fids=tuple(f for f in result.fids if f.session != grant.current)), 1

    def reopen(self):
        """A valid persistent volume survives reopen; lifetime serial does too."""
        return replace(self, grants=tuple(Grant(n) for n in range(1, 5)), fids=())

    def version(self, symbol, size, dotu, limits=Limits()):
        grant = self.owner(symbol)
        token = self.token(symbol)
        if grant is None or token is None:
            return self, 4, 0
        if size < 256 or size > U32:
            return self, 1, 0
        result = self
        if token.dotu != dotu:
            if self.serial >= limits.serial:
                # Version negotiation cannot issue a colliding/wrapped token.
                return self, 5, 0
            symbol = self.serial + 1
            result = replace(self, serial=symbol, tokens=(*self.tokens, Token(symbol, grant.number, dotu)))
        result = result.change_grant(replace(grant, current=symbol, versioned=True,
                                             msize=min(size, 8192)))
        result = replace(result, fids=tuple(f for f in result.fids if f.session != token.symbol))
        return result, 0, min(size, 8192)

    def object(self, number):
        return next((o for o in self.objects if o.number == number), None)

    def changed_object(self, obj):
        return replace(self, objects=tuple(obj if o.number == obj.number else o for o in self.objects))

    def fid(self, session, number, *, unopened=False):
        grant = self.owner(session)
        entry = next((f for f in self.fids if f.session == session and f.number == number), None)
        if not grant or not grant.versioned or not entry or (unopened and entry.mode != 255):
            return None
        obj = self.object(entry.object)
        if not obj or not obj.live or obj.incarnation != entry.incarnation:
            return None
        ancestor = obj
        while ancestor.number != ROOTS[grant.number]:
            if ancestor.parent == ancestor.number:
                return None
            ancestor = self.object(ancestor.parent)
            if ancestor is None:
                return None
        return entry

    def bind_fid(self, session, number, obj, limits=Limits()):
        old = next((f for f in self.fids if f.session == session and f.number == number), None)
        if not old and len(self.fids) >= limits.fids:
            return self, 5
        fresh = Fid(session, number, obj.number, obj.incarnation)
        return replace(self, fids=tuple(f for f in self.fids if f != old) + (fresh,)), 0

    def attach(self, session, number, limits=Limits()):
        grant = self.owner(session)
        if grant is None:
            return self, 4, b""
        if not grant.versioned:
            return self, 1, b""
        if number < 0 or number >= U32:
            return self, 1, b""
        if any(f.session == session and f.number == number for f in self.fids):
            return self, 6, b""
        obj = self.object(ROOTS[grant.number])
        result, code = self.bind_fid(session, number, obj, limits)
        return result, code, obj.qid() if not code else b""

    def walk(self, session, number, new_number, names, limits=Limits()):
        fid = self.fid(session, number, unopened=True)
        if fid is None:
            return self, 4, b""
        if new_number >= U32 or number > U32:
            return self, 1, b""
        if number != new_number and any(f.session == session and f.number == new_number for f in self.fids):
            return self, 6, b""
        if number != new_number and len(self.fids) >= limits.fids:
            return self, 5, b""
        grant = self.owner(session)
        obj = self.object(fid.object)
        qids = []
        for name in names:
            if not obj.mode & DIR:
                break
            if name == b".":
                found = obj
            elif name == b"..":
                found = obj if obj.number == ROOTS[grant.number] else self.object(obj.parent)
            else:
                found = next((o for o in self.objects if o.live and o.parent == obj.number and o.name == name), None)
            if found is None:
                break
            obj = found
            qids.append(obj.qid())
        if names and not qids:
            return self, 3, b""
        # A partial walk returns its QIDs but does not publish a new fid.
        if len(qids) != len(names):
            return self, 0, struct.pack("<H", len(qids)) + b"".join(qids)
        result, code = self.bind_fid(session, new_number, obj, limits)
        return result, code, struct.pack("<H", len(qids)) + b"".join(qids) if not code else b""

    def open(self, session, number, mode, limits=Limits(), *, name=None, permission=0o644):
        fid = self.fid(session, number, unopened=True)
        if fid is None:
            return self, 4, b""
        grant = self.owner(session)
        obj = self.object(fid.object)
        access = mode & 3
        if ((access in (1, 2) or mode & 16 or name is not None) and grant.number not in WRITERS
                or mode & 16 and access == 0):
            return self, 2, b""
        if mode & ~0x93:
            return self, 1, b""
        result = self
        if name is not None:
            if not obj.mode & DIR:
                return self, 7, b""
            if not name or len(name) > 255 or b"/" in name or b"\0" in name or name in (b".", b".."):
                return self, 1, b""
            if permission & 0x7bfffe00:
                return self, 1, b""
            if any(o.live and o.parent == obj.number and o.name == name for o in self.objects):
                return self, 6, b""
            if permission & DIR and (access != 0 or mode & 16):
                return self, 2, b""
            if obj.version >= U32 or self.clock > U32 - 3:
                return self, 5, b""
            available = next((o for o in self.objects if not o.live and o.incarnation < limits.incarnation), None)
            if available is None:
                used = {o.number for o in self.objects}
                slot = next((n for n in range(1, limits.objects + 1) if n not in used), 0)
                if not slot:
                    return self, 5, b""
                created = Object(slot, obj.number, name, permission, modified=self.clock + 1)
                result = replace(result, objects=(*result.objects, created))
            else:
                created = Object(available.number, obj.number, name, permission,
                                 incarnation=available.incarnation + 1, modified=self.clock + 1)
                result = result.changed_object(created)
            result = result.changed_object(replace(obj, version=obj.version + 1, modified=self.clock + 2))
            result = replace(result, clock=self.clock + 2)
            obj = created
        elif obj.mode & DIR and (access != 0 or mode & 16):
            return self, 2, b""
        elif mode & 16:
            if obj.version >= U32 or self.clock >= U32 - 1:
                return self, 5, b""
            obj = replace(obj, data=b"", version=obj.version + 1, modified=self.clock + 1)
            result = replace(result.changed_object(obj), clock=self.clock + 1)
        fresh = Fid(session, number, obj.number, obj.incarnation, mode & 0x83)
        result = replace(result, fids=tuple(f for f in result.fids if f != fid) + (fresh,))
        return result, 0, obj.qid() + struct.pack("<I", grant.msize - 24)

    def read(self, session, number, offset, count):
        fid = self.fid(session, number)
        if fid is None or fid.mode == 255:
            return self, 4, b""
        if fid.mode & 3 == 1:
            return self, 2, b""
        obj = self.object(fid.object)
        if obj.mode & DIR:
            raise ValueError("directory listing is outside this bounded model")
        count = min(count, self.owner(session).msize - 11)
        data = obj.data[offset:offset + count]
        return self, 0, struct.pack("<I", len(data)) + data

    def write(self, session, number, offset, data):
        fid = self.fid(session, number)
        if fid is None or fid.mode == 255:
            return self, 4, b""
        grant = self.owner(session)
        if grant.number not in WRITERS or fid.mode & 3 not in (1, 2):
            return self, 2, b""
        obj = self.object(fid.object)
        if obj.mode & DIR:
            return self, 2, b""
        if fid.mode & 128:
            offset = len(obj.data)
        if offset < 0 or offset + len(data) > U64 or obj.version >= U32 or self.clock >= U32 - 1:
            return self, 5, b""
        result = self
        if data:
            content = obj.data.ljust(offset + len(data), b"\0")
            content = content[:offset] + data + content[offset + len(data):]
            result = replace(self.changed_object(replace(obj, data=content, version=obj.version + 1,
                                                        modified=self.clock + 1)), clock=self.clock + 1)
        return result, 0, struct.pack("<I", len(data))

    def clunk(self, session, number, removing=False):
        grant = self.owner(session)
        entry = next((f for f in self.fids if f.session == session and f.number == number), None)
        if grant is None or entry is None:
            return self, 4, b""
        if removing and grant.number not in WRITERS:
            return self, 2, b""
        result = replace(self, fids=tuple(f for f in self.fids if f != entry))
        if not removing:
            return result, 0, b""
        fid = self.fid(session, number)
        if fid is None:
            return result, 4, b""
        obj = self.object(fid.object)
        if obj.number <= 5:
            return result, 2, b""
        if obj.mode & DIR and any(o.live and o.parent == obj.number for o in self.objects if o != obj):
            return result, 8, b""
        parent = self.object(obj.parent)
        if parent.version >= U32 or self.clock >= U32 - 1:
            return result, 5, b""
        result = result.changed_object(replace(obj, live=False, data=b""))
        result = result.changed_object(replace(parent, version=parent.version + 1, modified=self.clock + 1))
        return replace(result, clock=self.clock + 1), 0, b""


def initial_namespace():
    return Namespace.fresh()


def packet(kind, tag, payload=b""):
    return struct.pack("<IBH", len(payload) + 7, kind, tag) + payload


def string(value):
    value = value.encode() if isinstance(value, str) else bytes(value)
    return struct.pack("<H", len(value)) + value


def ns_error(tag, code, dotu=False):
    return packet(107, tag, string(ERROR_TEXT[code]) + (struct.pack("<I", ERRNO[code]) if dotu else b""))


class Body:
    def __init__(self, data):
        self.data = bytes(data)
        self.at = 7

    def take(self, count):
        if self.at + count > len(self.data):
            raise ValueError("short frame")
        result = self.data[self.at:self.at + count]
        self.at += count
        return result

    def integer(self, count):
        return int.from_bytes(self.take(count), "little")

    def string(self):
        return self.take(self.integer(2))

    def end(self):
        if self.at != len(self.data):
            raise ValueError("trailing frame bytes")


def namespace_wire(state, symbol, request, limits=Limits()):
    """Bounded regular-file protocol probes; no directory-listing oracle."""
    if len(request) < 7:
        return state, b""
    size, kind, tag = struct.unpack_from("<IBH", request)
    token = next((t for t in state.tokens if t.symbol == symbol), None)
    dotu = token.dotu if token else False
    if size != len(request):
        return state, ns_error(tag, 1, dotu)
    grant = state.owner(symbol)
    if not grant:
        return state, ns_error(tag, 4, dotu)
    body = Body(request)
    try:
        if kind == 100:
            msize, version = body.integer(4), body.string()
            body.end()
            if version not in (b"9P2000", b"9P2000.u"):
                raise ValueError("unsupported version")
            result, code, agreed = state.version(symbol, msize, version.endswith(b".u"), limits)
            return (state, ns_error(tag, code, dotu)) if code else (result, packet(101, tag, struct.pack("<I", agreed) + string(version)))
        if not grant.versioned or len(request) > grant.msize:
            return state, ns_error(tag, 1, dotu)
        number = body.integer(4)
        if number >= U32 and kind not in (110,):
            raise ValueError("invalid fid")
        result, code, payload = state, 0, b""
        if kind == 104:
            afid = body.integer(4)
            body.string()
            body.string()
            if dotu:
                body.integer(4)
            body.end()
            if afid != U32:
                raise ValueError("authentication fid is unsupported")
            if any(f.session == symbol and f.number == number for f in state.fids):
                code = 6
            else:
                obj = state.object(ROOTS[grant.number])
                result, code = state.bind_fid(symbol, number, obj, limits)
                payload = obj.qid()
        elif kind == 110:
            new_number, count = body.integer(4), body.integer(2)
            names = [body.string() for _ in range(count)]
            body.end()
            result, code, payload = state.walk(symbol, number, new_number, names, limits)
        elif kind in (112, 114):
            name, permission = (body.string(), body.integer(4)) if kind == 114 else (b"", 0)
            mode = body.integer(1)
            if dotu and kind == 114:
                body.string()
            body.end()
            if mode & ~0x93 or permission & 0x7bfffe00:
                raise ValueError("unsupported open flags")
            result, code, payload = state.open(symbol, number, mode, limits,
                                               name=name if kind == 114 else None, permission=permission)
        elif kind == 116:
            offset, count = body.integer(8), body.integer(4)
            body.end()
            result, code, payload = state.read(symbol, number, offset, count)
        elif kind == 118:
            offset, count = body.integer(8), body.integer(4)
            data = body.take(count)
            body.end()
            result, code, payload = state.write(symbol, number, offset, data)
        elif kind in (120, 122):
            body.end()
            result, code, payload = state.clunk(symbol, number, kind == 122)
        elif kind == 124:
            body.end()
            if state.fid(symbol, number) is None:
                code = 4
            else:
                raise ValueError("successful stat is outside this bounded wire probe")
        else:
            return state, ns_error(tag, 9, dotu)
        return result, (ns_error(tag, code, dotu) if code else packet(kind + 1, tag, payload))
    except (ValueError, struct.error):
        return state, ns_error(tag, 1, dotu)


def o10_error(tag, code, detail=0):
    return packet(161, tag, struct.pack("<IQ", code, detail))


def o10_request(kind, *, epoch=1, sequence=0, tag=91, payload=b""):
    if kind == 162:
        return packet(kind, tag, payload)
    return packet(kind, tag, struct.pack("<QQ", epoch, sequence) + payload)


O10_LENGTHS = {162: 19, 164: 39, 166: 31, 172: 36, 174: 63, 176: 31,
               178: 31, 184: 39, 196: 33}
O10_READONLY = frozenset((162, 166, 178, 190, 192))


@dataclass(frozen=True)
class Entry:
    sequence: int
    request: bytes
    reply: bytes


@dataclass(frozen=True)
class Journal:
    epoch: int = 0
    last: int = 0
    msize: int = 512
    entries: tuple[Entry, ...] = ()
    prepared: bytes = b""

    def finish(self, reply, limits=Limits()):
        """A malformed completion retains the pending operation unchanged."""
        if not self.prepared or len(reply) < 7 or len(reply) > 64:
            return self, False
        size, kind, tag = struct.unpack_from("<IBH", reply)
        _, requested, expected_tag = struct.unpack_from("<IBH", self.prepared)
        allowed = (kind == 161 and len(reply) == 19) or (kind == requested + 1 and len(reply) in (15, 27, 31))
        if size != len(reply) or tag != expected_tag or not allowed:
            return self, False
        sequence = int.from_bytes(self.prepared[15:23], "little")
        entries = (*self.entries, Entry(sequence, self.prepared, reply))[-limits.journal:]
        return replace(self, last=sequence, entries=entries, prepared=b""), True

    def admit(self, request, capacity=512, limits=Limits()):
        """Return (state, reply-or-None, admission class). None means dispatch."""
        request = bytes(request)
        tag = int.from_bytes(request[5:7], "little") if len(request) >= 7 else 0
        if capacity < 512:
            return self, o10_error(tag, 1) if capacity >= 19 else b"", "rejected"
        if len(request) < 7 or len(request) > min(self.msize, 512):
            return self, o10_error(tag, 1), "rejected"
        size, kind, _ = struct.unpack_from("<IBH", request)
        if size != len(request) or kind not in O10_LENGTHS or len(request) != O10_LENGTHS[kind]:
            return self, o10_error(tag, 1, 4 if kind not in O10_LENGTHS else 0), "rejected"
        if kind & 1:
            return self, o10_error(tag, 1, 4), "rejected"
        if kind != 162 and kind in O10_READONLY and int.from_bytes(request[15:23], "little"):
            return self, o10_error(tag, 1, 15), "rejected"
        if self.prepared:
            return self, o10_error(tag, 7, int.from_bytes(self.prepared[15:23], "little")), "busy"
        if kind == 162:
            requested = int.from_bytes(request[7:11], "little")
            if request[11:19] != b"O10\0\0\0\0\0" or requested < 78:
                return self, o10_error(tag, 2, 512), "rejected"
            result = replace(self, msize=min(requested, 512))
            reply = packet(163, tag, struct.pack("<I8sQQ", result.msize, b"O10\0\0\0\0\0", self.epoch, self.last))
            return result, reply, "version"
        incoming, sequence = struct.unpack_from("<QQ", request, 7)
        mutation = kind not in O10_READONLY
        if mutation and sequence and sequence <= self.last:
            old = next((e for e in self.entries if e.sequence == sequence), None)
            if old and old.request == request:
                return self, old.reply, "replay"
            return self, o10_error(tag, 4, self.last), "rejected"
        if (mutation and kind != 164 and not self.epoch) or incoming != self.epoch:
            return self, o10_error(tag, 3, self.epoch), "rejected"
        if mutation and (self.last >= limits.request_sequence or sequence != self.last + 1):
            return self, o10_error(tag, 4, self.last), "rejected"
        result = replace(self, prepared=request) if mutation else self
        if kind == 164:
            new_epoch, expected = struct.unpack_from("<QQ", request, 23)
            if expected != self.epoch or new_epoch <= self.epoch or new_epoch > limits.request_epoch:
                reply = o10_error(tag, 3, self.epoch)
            else:
                result = replace(result, epoch=new_epoch)
                reply = packet(165, tag, struct.pack("<QQQ", new_epoch, sequence, max(1, sequence - limits.journal + 1)))
            result, committed = result.finish(reply, limits)
            if not committed:
                raise AssertionError("model claim completion invariant")
            return result, reply, "journalled"
        if kind == 166:
            query = int.from_bytes(request[23:31], "little")
            old = next((e for e in self.entries if e.sequence == query), None)
            state, code, saved = 0, 0, b""
            if query and query <= self.last:
                state = 3
                if old:
                    saved = old.reply
                    state = 2 if saved[4] == 161 else 1
                    code = int.from_bytes(saved[7:11], "little") if state == 2 else 0
            return result, packet(167, tag, struct.pack("<BIH", state, code, len(saved)) + saved), "query"
        return result, None, "prepared" if mutation else "read"


@dataclass(frozen=True)
class Domain:
    generation: int = 1
    lease: int = 1
    session_generation: int = 1
    state: str = "running"
    detached: bool = False
    block: int = 1
    network: int = 1
    transport: int = 1
    session_epoch: int = 1
    active: bool = True
    bound: bool = True
    authority: int = 0
    instance: bytes = bytes(16)

    @property
    def live(self):
        return self.state in ("running", "waiting")

    @property
    def runnable(self):
        return self.state == "running"

    def handle(self, slot):
        return (self.generation << 32) | slot


@dataclass(frozen=True)
class Observation:
    reply: bytes = b""
    value: int = 0
    admission: str = "direct"
    effects: tuple[str, ...] = ()
    terminal: tuple[int, ...] = ()


@dataclass(frozen=True)
class Lifecycle:
    namespace: Namespace
    journal: Journal = Journal()
    domains: tuple[Domain, Domain] = (Domain(), Domain())
    terminal: tuple[int, ...] = ()

    @classmethod
    def fresh(cls, transport=1, plan9_epoch=1, limits=Limits()):
        namespace = Namespace.fresh()
        namespace, linux = namespace.session(1, 1, limits)
        namespace, plan9 = namespace.session(4, plan9_epoch, limits)
        if not linux or not plan9:
            raise ValueError("initial session limits do not admit both domains")
        return cls(namespace=namespace, domains=(Domain(transport=transport, authority=linux),
                                                 Domain(transport=plan9_epoch, session_epoch=plan9_epoch,
                                                        authority=plan9)))

    def domain(self, index, value):
        return replace(self, domains=tuple(value if n == index else d for n, d in enumerate(self.domains)))

    def terminal_failure(self, code, *details, effects=()):
        failure = (code, *details)
        return replace(self, terminal=failure), Observation(terminal=failure, effects=effects)

    def withdraw(self, index, *, contain=False, limits=Limits()):
        """Explicit withdrawal preflights; containment may terminate after stop."""
        domain = self.domains[index]
        if not contain and domain.state == "withdrawn":
            return self, Observation(value=12)
        needs_lease = index == 1 or not domain.detached
        if needs_lease and domain.lease >= limits.lease:
            if contain:
                stopped = self.domain(index, replace(domain, state="faulted"))
                return stopped.terminal_failure(0x1106, index, domain.lease, 0)
            return self, Observation(value=8)
        updated = replace(domain, lease=domain.lease + int(needs_lease),
                          state="faulted" if contain else "withdrawn",
                          detached=(True if index == 0 else domain.detached),
                          active=domain.active if index == 0 and domain.detached else False,
                          bound=domain.bound if index == 0 and domain.detached else False,
                          authority=0)
        namespace, _ = self.namespace.revoke(1 if index == 0 else 4)
        result = replace(self.domain(index, updated), namespace=namespace)
        return result, Observation(effects=("namespace.revoke", "interrupt.clear"))

    def restore(self, index, limits=Limits(), failure=""):
        domain = self.domains[index]
        if domain.live or (index == 0 and not domain.detached):
            return self, Observation(value=12)
        exhausted = domain.generation >= limits.domain
        if index == 0:
            exhausted |= (domain.block >= limits.block or domain.network >= limits.network
                          or domain.transport >= limits.transport)
        if exhausted:
            return self, Observation(value=8)
        if failure == "images":
            return self, Observation(value=12)
        effects = ("copy:" + str(index), "reset:" + str(index))
        if failure in ("reset", "provision", "coordinator"):
            if index == 0:
                return self.terminal_failure(0x1109, 0x1115, 0, 0, effects=effects)
            return self, Observation(value=12, effects=effects)
        fresh = replace(domain, generation=domain.generation + 1, state="waiting",
                        active=True if index == 0 else domain.active, bound=False, authority=0)
        if index == 0:
            fresh = replace(fresh, block=domain.block + 1, network=domain.network + 1,
                            transport=domain.transport + 1)
        return self.domain(index, fresh), Observation(value=fresh.handle(index), effects=effects)

    def bind(self, index, lease_handle, transport_handle, limits=Limits(), failure=""):
        domain = self.domains[index]
        expected_slot = 1 if index == 0 else 4
        if lease_handle >> 32 != domain.lease:
            return self, Observation(value=5)
        if transport_handle >> 32 != domain.generation:
            return self, Observation(value=5)
        if lease_handle & U32 != expected_slot or transport_handle & U32:
            return self, Observation(value=6)
        if not domain.live or (index == 0 and domain.state != "waiting"):
            return self, Observation(value=12)
        if domain.session_generation >= limits.lease or (index == 0 and domain.session_epoch >= limits.session_epoch):
            return self, Observation(value=8)
        if index == 1 and domain.transport >= limits.transport:
            return self.domain(index, replace(domain, active=False)), Observation(value=12)
        next_epoch = domain.session_epoch + 1 if index == 0 else domain.transport + 1
        ns, symbol = self.namespace.session(expected_slot, next_epoch, limits)
        if not symbol or failure in ("bind", "activate"):
            if index == 0:
                return replace(self, namespace=ns).terminal_failure(0x1109, 0x1116, next_epoch, 0)
            failed = self.domain(index, replace(domain, transport=next_epoch, session_epoch=next_epoch,
                                                active=False, authority=0))
            return replace(failed, namespace=ns), Observation(value=12)
        fresh = replace(domain, state="running", session_generation=domain.session_generation + 1,
                        session_epoch=next_epoch, active=True, bound=True, detached=False, authority=symbol)
        if index == 1:
            fresh = replace(fresh, transport=next_epoch)
        result = replace(self.domain(index, fresh), namespace=ns)
        return result, Observation(value=(fresh.session_generation << 32) | expected_slot)

    def platform(self, request, limits=Limits(), failure=""):
        kind, tag = request[4], int.from_bytes(request[5:7], "little")
        handle = int.from_bytes(request[23:31], "little")
        index = handle & U32
        def error(code, detail=0):
            return self, Observation(reply=o10_error(tag, code, detail))
        if kind in (172, 174, 178, 196):
            if index > 1:
                return error(5)
            domain = self.domains[index]
            if handle >> 32 != domain.generation:
                return error(5, domain.generation)
            if kind == 178:
                state = {"running": 2, "waiting": 3, "faulted": 4, "withdrawn": 5}[domain.state]
                payload = (struct.pack("<QBB", handle, 2, state) + domain.instance + bytes(40)
                           + struct.pack("<I", bool(self.namespace.current(1 if index == 0 else 4))))
                return self, Observation(reply=packet(179, tag, payload))
            if kind == 196:
                if int.from_bytes(request[31:33], "little") != 1:
                    return error(9)
                if not domain.live:
                    return error(12, 5 if domain.state == "withdrawn" else 4)
                state, obs = self.withdraw(index, contain=True, limits=limits)
                return state, replace(obs, reply=b"" if obs.terminal else packet(197, tag, struct.pack("<Q", handle)))
            if kind == 172:
                if domain.state == "withdrawn":
                    return error(12, 5)
                if request[31]:
                    return error(9)
                sessions = int(bool(self.namespace.current(1 if index == 0 else 4)))
                fids = sum(f.session == self.namespace.current(1 if index == 0 else 4)
                           for f in self.namespace.fids) if sessions else 0
                state, obs = self.withdraw(index, limits=limits)
                if obs.value:
                    return error(obs.value, U32 if obs.value == 8 else 5)
                return state, replace(obs, reply=packet(173, tag, struct.pack("<QIII", handle, sessions, sessions, fids)))
            if domain.live or (index == 0 and not domain.detached):
                return error(12, 2)
            image, auxiliary = struct.unpack_from("<QQ", request, 47)
            if (image, auxiliary) != ((3, 4) if index == 0 else (1, 2)):
                return error(5)
            state, obs = self.restore(index, limits, failure)
            if obs.terminal:
                return state, obs
            if obs.value not in (8, 12):
                state = state.domain(index, replace(state.domains[index], instance=request[31:47]))
            if obs.value in (8, 12):
                return self, replace(obs, reply=o10_error(tag, obs.value, U32 if obs.value == 8 else 4))
            return state, replace(obs, reply=packet(175, tag, struct.pack("<Q", obs.value)))
        if kind == 184:
            lease, transport = struct.unpack_from("<QQ", request, 23)
            slot = lease & U32
            if slot not in (1, 4):
                return error(6)
            index = 0 if slot == 1 else 1
            domain = self.domains[index]
            if lease >> 32 != domain.lease:
                return error(5, domain.lease)
            if transport >> 32 != domain.generation:
                return error(5, domain.generation)
            if transport & U32:
                return error(6)
            if not domain.live:
                return error(12, 5)
            state, obs = self.bind(index, lease, transport, limits, failure)
            if obs.terminal:
                return state, obs
            if obs.value in (5, 6, 8, 12):
                return state, replace(obs, reply=o10_error(tag, obs.value, U32 if obs.value == 8 else (4 if index else 5) if obs.value == 12 else 0))
            return state, replace(obs, reply=packet(185, tag, struct.pack("<Q", obs.value)))
        return error(9)

    def execute(self, request, limits=Limits(), failure=""):
        if self.terminal:
            raise ValueError("terminal model state cannot execute another operation")
        journal, reply, admission = self.journal.admit(request, limits=limits)
        result = replace(self, journal=journal)
        if reply is not None:
            return result, Observation(reply=reply, admission=admission)
        result, observation = result.platform(request, limits, failure)
        if observation.terminal:
            return result, replace(observation, admission="terminal")
        if journal.prepared:
            completed, ok = result.journal.finish(observation.reply, limits)
            if not ok:
                return result.terminal_failure(0x1107, len(observation.reply), 0, 0,
                                               effects=observation.effects)
            result = replace(result, journal=completed)
        return result, replace(observation, admission="journalled" if journal.prepared else "read")


def explore(initial, actions, transition, *, state_limit=100000):
    """Breadth-first reachable graph; predecessor/effects are outside the key.

    A stopped search is explicitly incomplete. Every discovered edge retains a
    shortest predecessor trace so a candidate mismatch has a minimal witness.
    """
    queue = deque((initial,))
    traces = {initial: ()}
    edges = []
    exhausted = True
    while queue:
        state = queue.popleft()
        if getattr(state, 'terminal', ()):
            continue
        for action in actions:
            new_state, observation = transition(state, action)
            edges.append((traces[state], action, observation))
            if new_state not in traces:
                if len(traces) >= state_limit:
                    exhausted = False
                    queue.clear()
                    break
                traces[new_state] = (*traces[state], action)
                queue.append(new_state)
    return {"states": len(traces), "transitions": len(edges), "exhaustive": exhausted,
            "scope": "reachable finite graph" if exhausted else "state-limited",
            "witnesses": edges}


def session_profile(state_limit=100000):
    limits = Limits(session_epoch=2, serial=3)
    actions = ([('session', grant, epoch) for grant in (1, 3) for epoch in (1, 2)]
               + [('revoke', grant) for grant in (1, 3)]
               + [('version', symbol, dotu) for symbol in (1, 2, 3) for dotu in (False, True)])
    def transition(state, action):
        if action[0] == 'session':
            state, value = state.session(action[1], action[2], limits)
            return state, Observation(value=value)
        if action[0] == 'revoke':
            state, value = state.revoke(action[1])
            return state, Observation(value=value)
        state, code, value = state.version(action[1], 512, action[2], limits)
        return state, Observation(value=code if code else value)
    return explore(Namespace.fresh(), actions, transition, state_limit=state_limit)


def journal_profile(state_limit=100000):
    limits = Limits(request_epoch=2, request_sequence=3, journal=2)
    actions = []
    for tag in (0, 1):
        for incoming, new, expected, sequence in ((0, 1, 0, 1), (1, 2, 1, 2),
                                                  (1, 2, 0, 2), (1, 2, 1, 3)):
            actions.append(('call', o10_request(164, epoch=incoming, sequence=sequence, tag=tag,
                                                payload=struct.pack('<QQ', new, expected))))
        for incoming, sequence in ((0, 2), (1, 2), (1, 3), (2, 3)):
            request = o10_request(176, epoch=incoming, sequence=sequence, tag=tag,
                                  payload=struct.pack('<Q', 0))
            actions.extend((('call', request), ('prepare', request)))
    actions.extend((('commit', True), ('commit', False)))
    def transition(state, action):
        if action[0] == 'commit':
            tag = int.from_bytes(state.prepared[5:7], 'little') if state.prepared else 0
            reply = o10_error(tag if action[1] else tag ^ 1, 9)
            result, success = state.finish(reply, limits)
            return result, Observation(value=int(success))
        result, reply, admission = state.admit(action[1], limits=limits)
        if reply is None and action[0] == 'call':
            reply = o10_error(int.from_bytes(action[1][5:7], 'little'), 9)
            result, success = result.finish(reply, limits)
            if not success:
                raise AssertionError('model platform completion invariant')
            admission = 'journalled'
        return result, Observation(reply=reply or b'', admission=admission)
    return explore(Journal(), actions, transition, state_limit=state_limit)


def replacement_profile(state_limit=100000):
    limits = Limits(domain=2, lease=2, block=2, network=2, transport=2,
                    session_epoch=2, serial=3)
    actions = ([('withdraw', index) for index in (0, 1)]
               + [('contain', index) for index in (0, 1)]
               + [('restore', index) for index in (0, 1)]
               + [('bind', index, lease, generation) for index in (0, 1)
                  for lease in (1, 2) for generation in (1, 2)])
    def transition(state, action):
        if state.terminal:
            return state, Observation(terminal=state.terminal)
        return state.platform(replacement_request(state, action, 1), limits)
    return explore(Lifecycle.fresh(limits=limits), actions, transition, state_limit=state_limit)


def replacement_request(state, action, sequence):
    """Primitive-wire probe for a declared replacement-profile operation."""
    kind, index = action[:2]
    handle = state.domains[index].handle(index)
    if kind == 'withdraw':
        message, payload = 172, struct.pack('<QBI', handle, 0, 0)
    elif kind == 'contain':
        message, payload = 196, struct.pack('<QH', handle, 1)
    elif kind == 'restore':
        message = 174
        payload = struct.pack('<Q', handle) + bytes(16) + struct.pack('<QQ', *( (3, 4) if index == 0 else (1, 2)))
    else:
        message = 184
        payload = struct.pack('<QQ', (action[2] << 32) | (1 if index == 0 else 4), action[3] << 32)
    return o10_request(message, epoch=1, sequence=sequence, payload=payload)


def finite_cases(profile):
    """Translate every finite graph edge's shortest witness into wire probes.

    The graph is independent of test-program register numbers and retry-journal
    history. Replacement explores that policy projection; its wire witnesses
    use fresh, correctly sequenced mutations. The journal has its own profile.
    """
    graph = globals()[profile + '_profile']()
    if not graph['exhaustive']:
        raise ValueError('finite profile did not exhaust its declared graph')
    if profile == 'session':
        limits = Limits(session_epoch=2, serial=3)
        initial = {'transport': 0, 'plan9_epoch': 1}
    elif profile == 'journal':
        limits = Limits(request_epoch=2, request_sequence=3, journal=2)
        initial = {'transport': 0, 'plan9_epoch': 0}
    elif profile == 'replacement':
        limits = Limits(domain=2, lease=2, block=2, network=2, transport=2, session_epoch=2, serial=3)
        initial = {}
    else:
        raise ValueError('unknown finite profile')
    cases = []
    for number, (prefix, action, _) in enumerate(graph['witnesses']):
        reference = TraceModel(initial, limits)
        commands = []
        def add(command):
            commands.append(command)
            reference.step(command, len(commands)-1)
        if profile == 'replacement':
            add({'op': 17, 'data': o10_request(164, epoch=0, sequence=1,
                 payload=struct.pack('<QQ', 1, 0)).hex()})
        for operation in (*prefix, action):
            kind = operation[0]
            if profile == 'session':
                ns = reference.state.namespace
                if kind == 'session':
                    _, symbol = ns.session(operation[1], operation[2], limits)
                    add({'op': 1, 'a': operation[1], 'b': operation[2], 'c': symbol + 8 if symbol else 255})
                elif kind == 'revoke':
                    add({'op': 2, 'a': operation[1]})
                else:
                    symbol, dotu = operation[1:]
                    owner = ns.owner(symbol)
                    changed, _, _ = ns.version(symbol, 512, dotu, limits)
                    new_symbol = changed.current(owner.number) if owner else 0
                    version = b'9P2000.u' if dotu else b'9P2000'
                    add({'op': 6, 'a': symbol + 8, 'b': new_symbol + 8 if new_symbol else 255,
                         'c': owner.number if owner else 1,
                         'data': packet(100, 0, struct.pack('<I', 512) + string(version)).hex()})
            elif profile == 'journal':
                if kind == 'commit':
                    pending = reference.state.journal.prepared
                    tag = int.from_bytes(pending[5:7], 'little') if pending else 0
                    add({'op': 16, 'data': o10_error(tag if operation[1] else tag ^ 1, 9).hex()})
                else:
                    add({'op': 17 if kind == 'call' else 15, 'data': operation[1].hex()})
            else:
                request = replacement_request(reference.state, operation, reference.state.journal.last + 1)
                add({'op': 17, 'data': request.hex()})
        cases.append({'name': profile + '-' + str(number), 'initial': initial,
                      'limits': {k: v for k, v in vars(limits).items() if v != getattr(Limits(), k)},
                      'steps': commands})
    return graph, cases


def finite_profile_contract(profile):
    """State the finite alphabet; exhaustion applies only to this projection."""
    if profile == 'session':
        return {'projection': 'namespace session ownership, freshness and dialect',
                'grants': [1, 3], 'epochs': [1, 2], 'lifetime_serials': [0, 1, 2, 3],
                'stale_session_symbols': [1, 2, 3], 'dialects': ['9P2000', '9P2000.u'],
                'operations': ['session_init', 'revoke', 'version'],
                'files_and_fids': 'not part of this finite projection; full-width wire traces probe them'}
    if profile == 'journal':
        return {'projection': 'retry admission, journalled errors, pending completion and retained replay',
                'epochs': [0, 1, 2], 'mutation_sequences': [1, 2, 3], 'tags': [0, 1], 'journal_slots': 2,
                'operations': ['claim', 'unsupported platform mutation', 'prepare', 'valid/invalid-tag commit'],
                'platform_effects': 'unsupported operation; domain replacement has a separate finite projection'}
    if profile == 'replacement':
        return {'projection': 'two-domain replacement, exhaustion, session ownership and runnable state',
                'domains': [0, 1], 'generation_and_epoch_limits': 2, 'lifetime_session_serial_limit': 3,
                'bind_lease_generations': [1, 2], 'bind_domain_generations': [1, 2],
                'operations': ['withdraw', 'contain', 'restore', 'bind'],
                'journal': 'fresh sequenced wire witnesses; journal history excluded from this state projection',
                'hardware_effects': 'actual production RAM-copy paths; privileged hooks explicitly modeled'}
    raise ValueError('unknown finite profile')


class TokenCorrespondence:
    """Check symbolic freshness without prescribing a concrete token formula."""
    def __init__(self):
        self.forward = {}
        self.reverse = {}

    def observe(self, symbol, concrete):
        if not symbol:
            if concrete:
                raise AssertionError('absent session has a concrete token')
            return
        if not concrete:
            raise AssertionError('live symbolic session has a zero token')
        if symbol in self.forward and self.forward[symbol] != concrete:
            raise AssertionError('symbolic identity changed concrete token')
        if concrete in self.reverse and self.reverse[concrete] != symbol:
            raise AssertionError('concrete token collided with another lifetime identity')
        self.forward[symbol] = concrete
        self.reverse[concrete] = symbol


def image_digest(domain):
    """Independent sparse-fixture FNV: exponentiation skips known zero runs."""
    prime, modulus = 0x100000001b3, 1 << 64
    if domain == 0:
        segments = ((0, bytes(i ^ 0x31 for i in range(37))),
                    (0x7e00000, bytes(i ^ 0x57 for i in range(19))),
                    (0x8000000, bytes(i ^ 0x83 for i in range(73))))
    else:
        dtb = struct.pack('<I', 0xedfe0dd0) + bytes(i ^ 0xb3 for i in range(4, 32))
        segments = ((0, dtb), (0x100000, bytes(i ^ 0xa1 for i in range(32))))
    digest, at = 0xcbf29ce484222325, 0
    for start, data in segments:
        digest = digest * pow(prime, start - at, modulus) % modulus
        for byte in data:
            digest = (digest ^ byte) * prime % modulus
        at = start + len(data)
    return digest * pow(prime, 0x20000000 - at, modulus) % modulus


def interrupt_bank_reset(domain):
    """Fixture's four saved LRs, enabled interface, masked priorities."""
    return [(5, domain, index, 0) for index in range(4)] + [
        (4, domain, 1, 0), (3, domain, 0xff000002, 0)]


class TraceModel:
    """Finite input program interpreter around the independent policy model.

    Register slots select previously returned opaque sessions. They are test
    program variables, not the candidate's token representation. Cumulative
    effect measurements live here, outside the finite-state equivalence key.
    """
    def __init__(self, initial=None, limits=Limits()):
        initial = initial or {}
        self.limits = limits
        self.full_frontends = initial.get('transport', 1) != 0
        if initial.get('transport', 1) == 0:
            namespace = Namespace.fresh() if initial.get('plan9_epoch', 1) else Namespace(ready=False)
            domain = Domain(state='faulted', block=0, network=0, transport=0,
                            session_epoch=0, active=False, bound=False)
            self.state = Lifecycle(namespace, domains=(domain, domain))
        else:
            self.state = Lifecycle.fresh(initial.get('transport', 1), initial.get('plan9_epoch', 1), limits)
        self.registers = {0: 0, 1: self.state.namespace.current(1), 2: self.state.namespace.current(4)}
        if initial.get('serial'):
            self.state = replace(self.state, namespace=replace(self.state.namespace, serial=initial['serial']))
        domain = self.state.domains[0]
        for key, field in (('domain', 'generation'), ('lease', 'lease'), ('session_epoch', 'session_epoch')):
            if initial.get(key):
                domain = replace(domain, **{field: initial[key]})
        self.state = self.state.domain(0, domain)
        self.state = replace(self.state, journal=replace(self.state.journal,
            last=initial.get('last', 0), epoch=initial.get('epoch', 0)))
        self.reset_count = [0, 0]
        self.ram_digest = [0, 0]

    def snapshot(self, step, value=0, reply=b'', value_kind='integer', effects=()):
        state = self.state
        linux, plan9 = state.domains
        terminal = list(state.terminal) if state.terminal else [0, 0, 0, 0]
        if step == U64 and self.full_frontends:
            effects = (*interrupt_bank_reset(0), *interrupt_bank_reset(1))
        return {'step': step, 'value': value, 'value_kind': value_kind, 'reply': reply.hex(),
                'sessions': [state.namespace.current(g) for g in range(1, 5)],
                'namespace_generations': [state.namespace.grant(g).generation for g in range(1, 5)],
                'domain_generations': [d.generation for d in state.domains],
                'leases': [d.lease for d in state.domains],
                'session_generations': [d.session_generation for d in state.domains],
                'states': [{'running': 2, 'waiting': 3, 'faulted': 4, 'withdrawn': 5}[d.state] for d in state.domains],
                'transport': [linux.block, linux.network, linux.transport, linux.session_epoch,
                              int(linux.active), int(linux.bound)],
                'plan9_transport': [plan9.transport, int(plan9.active)],
                'journal': [state.journal.epoch, state.journal.last, int(bool(state.journal.prepared))],
                'reset_count': list(self.reset_count), 'ram_digest': list(self.ram_digest),
                'semantic_effects': [list(e) for e in effects], 'terminal': terminal}

    def step(self, command, index):
        op = command['op']
        a, b, c, d = (command.get(k, 0) for k in ('a', 'b', 'c', 'd'))
        data = bytes.fromhex(command.get('data', ''))
        ns, value, reply, value_kind, effects = self.state.namespace, 0, b'', 'integer', []
        if op == 1:
            ns, value = ns.session(a, b, self.limits)
            self.registers[c] = value
            value_kind = 'session'
        elif op == 2:
            ns, value = ns.revoke(a)
        elif op == 3:
            ns, value = ns.session(a, b, self.limits, self.registers.get(c, 0))
            self.registers[d] = value
            value_kind = 'session'
        elif op == 4:
            ns, value = ns.revoke(a, self.registers.get(b, 0))
        elif op == 5:
            ns, value = ns.reopen(), 1
        elif op == 6:
            symbol = self.registers.get(a, 0)
            if d:
                token = ns.token(symbol)
                reply = ns_error(int.from_bytes(data[5:7], 'little'), 4, not token.dotu if token else True)
            else:
                ns, reply = namespace_wire(ns, symbol, data, self.limits)
            value = len(reply)
            if b:
                self.registers[b] = ns.current(c)
        elif op == 7:
            value = ns.current(a)
            self.registers[b] = value
            value_kind = 'session'
        elif op in (8, 9, 10, 11, 12, 13, 14):
            return self.transport_step(command, index)
        elif op == 15:
            journal, result, _ = self.state.journal.admit(data, limits=self.limits)
            self.state = replace(self.state, journal=journal)
            reply = result or b''
            value = len(reply)
        elif op == 16:
            journal, success = self.state.journal.finish(data, self.limits)
            self.state = replace(self.state, journal=journal)
            value = int(success)
        elif op == 17:
            self.state, observed = self.state.execute(data, self.limits, 'reset' if a else '')
            ns = self.state.namespace
            reply = observed.reply
            value = 0 if observed.terminal else sum(int(domain.live) << n for n, domain in enumerate(self.state.domains))
            for event in observed.effects:
                if event.startswith('reset:'):
                    domain = int(event.split(':')[1])
                    self.reset_count[domain] += 1
                    self.ram_digest[domain] = image_digest(domain)
                    effects.extend(((1, domain, self.ram_digest[domain], 0),
                                    (2, domain, 0x40000000 if domain == 0 else 0x40100000,
                                     0x47e00000 if domain == 0 else 0x40000000)))
                    if not a:
                        effects.extend(interrupt_bank_reset(domain))
        else:
            raise ValueError('unknown trace opcode: ' + str(op))
        self.state = replace(self.state, namespace=ns)
        return self.snapshot(index, value, reply, value_kind, effects)

    def transport_step(self, command, index):
        op = command['op']
        a, b, c = (command.get(k, 0) for k in ('a', 'b', 'c'))
        ns, value = self.state.namespace, 0
        which = 1 if op in (13, 14) else 0
        domain = self.state.domains[which]
        if op == 8 and a and a <= self.limits.transport and a > domain.transport:
            domain = replace(domain, transport=a, active=True, bound=True)
            if domain.session_epoch < self.limits.session_epoch:
                epoch = domain.session_epoch + 1
                ns, symbol = ns.session(1, epoch, self.limits)
                domain = replace(domain, session_epoch=epoch, authority=symbol)
                value = int(bool(symbol))
        elif op == 9:
            current = ns.current(1)
            if a and a == domain.transport and domain.active and current in (0, domain.authority):
                if current:
                    ns, _ = ns.revoke(1, current)
                domain = replace(domain, active=False, bound=False, authority=0)
                value = 1
        elif op == 10 and not domain.active and a and domain.transport < a <= self.limits.transport:
            domain = replace(domain, transport=a, active=True, bound=False, authority=0)
            value = 1
        elif op == 11:
            session = self.registers.get(b, 0)
            if (domain.active and not domain.bound and a == domain.transport and session
                    and 0 < c <= self.limits.session_epoch and c > domain.session_epoch
                    and ns.current(1) == session):
                domain = replace(domain, bound=True, session_epoch=c, authority=session)
                value = 1
        elif op == 12:
            offset = a or 112
            requested = command.get('b', 0)
            if offset != 112 or requested != 0:
                # The focused policy probe attempts DRIVER_OK without a bound
                # session. It must reject even if provisional ACTIVE remains.
                if offset != 112 or requested != 4 or domain.bound:
                    raise ValueError('unsupported transport-status probe')
            elif not domain.bound:
                domain = replace(domain, authority=0)
                value = 1
            elif domain.session_epoch < self.limits.session_epoch:
                epoch = domain.session_epoch + 1
                ns, symbol = ns.session(1, epoch, self.limits)
                domain = replace(domain, session_epoch=epoch, authority=symbol)
                value = int(bool(symbol))
        elif op == 13:
            domain = replace(domain, active=False)
            if a and a <= self.limits.transport and domain.transport < self.limits.transport:
                epoch = max(a, domain.transport + 1)
                ns, symbol = ns.session(4, epoch, self.limits)
                domain = replace(domain, transport=epoch, session_epoch=epoch,
                                 active=bool(symbol), authority=symbol)
                value = int(bool(symbol))
        elif op == 14:
            ns, value = ns.revoke(4)
            domain = replace(domain, active=False, authority=0)
        self.state = replace(self.state.domain(which, domain), namespace=ns)
        return self.snapshot(index, value)


def evaluate_case(case):
    reference = TraceModel(case.get('initial', {}), Limits(**case.get('limits', {})))
    result = [reference.snapshot(U64)]
    for index, command in enumerate(case['steps']):
        if reference.state.terminal:
            raise ValueError('commands follow terminal transition')
        result.append(reference.step(command, index))
    return result
