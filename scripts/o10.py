"""O10 Draft 0 structural wire codec.

The codec grants no authority and executes no lifecycle operations. Enum
assignments and the Rlstat record layout are not specified by Draft 0:
enum fields remain unsigned integers, and Rlstat carries opaque record bytes
until that layout is approved. No provisional wire values are invented here.
"""
import struct

O10_VERSION = b"O10\0\0\0\0\0"
O10_MSIZE = 512
O10_HEADER_SIZE = 7
O10_MUTATION_MAX = 64
O10_JOURNAL_SIZE = 256

ERROR_NAMES = ("EBADMSG", "EVERSION", "ENOTCURRENT", "ESEQ", "ESTALE",
               "EDENIED", "EBUSY", "ECAPACITY", "EUNSUPPORTED", "ETIMEOUT",
               "EOVERFLOW", "ESTATE")
for _code, _name in enumerate(ERROR_NAMES, 1):
    globals()["O10_" + _name] = _code

# Names, widths and order follow section 6, excluding opaque Rlstat.
SCHEMAS = {
    "Rerror": (("code", "I"), ("detail", "Q")),
    "Tversion": (("msize", "I"), ("version", "8s")),
    "Rversion": (("msize", "I"), ("version", "8s"), ("epoch", "Q"), ("last_seq", "Q")),
    "Tclaim": (("new_epoch", "Q"), ("expected", "Q")),
    "Rclaim": (("epoch", "Q"), ("last_seq", "Q"), ("journal_low", "Q")),
    "Toutcome": (("qseq", "Q"),),
    "Routcome": (("state", "B"), ("code", "I"), ("reply", "bytes")),
    "Tcreate": (("kind", "B"), ("img_kernel", "Q"), ("img_aux", "Q"), ("mem_bytes", "Q"), ("vcpus", "H")),
    "Rcreate": (("dom", "Q"),),
    "Tstart": (("dom", "Q"), ("inst", "16s")),
    "Rstart": (("dom", "Q"),),
    "Twithdraw": (("dom", "Q"), ("mode", "B"), ("deadline_ms", "I")),
    "Rwithdraw": (("dom", "Q"), ("leases", "I"), ("sessions", "I"), ("fids", "I")),
    "Trestore": (("dom", "Q"), ("inst", "16s"), ("img_kernel", "Q"), ("img_aux", "Q")),
    "Rrestore": (("dom", "Q"),),
    "Tdestroy": (("dom", "Q"),),
    "Rdestroy": (("dom", "Q"),),
    "Tstat": (("dom", "Q"),),
    "Rstat": (("dom", "Q"), ("kind", "B"), ("state", "B"), ("inst", "16s"),
              ("exits", "Q"), ("switches", "Q"), ("esr", "Q"), ("ipa", "Q"), ("pc", "Q"), ("leases", "I")),
    "Tlease": (("kind", "B"), ("holder", "Q"), ("object", "Q"), ("rights", "Q"), ("class", "B"), ("mode", "B")),
    "Rlease": (("lease", "Q"),),
    "Tderive": (("parent", "Q"), ("holder", "Q"), ("object", "Q"), ("rights", "Q")),
    "Rderive": (("lease", "Q"),),
    "Tbind": (("lease", "Q"), ("transport", "Q")),
    "Rbind": (("session", "Q"),),
    "Trevoke": (("lease", "Q"),),
    "Rrevoke": (("derived", "I"), ("sessions", "I"), ("fids", "I"), ("views", "I")),
    "Tquiesce": (("lease", "Q"), ("deadline_ms", "I")),
    "Rquiesce": (("state", "B"),),
    "Tlstat": (("lease", "Q"),),
    "Rlstat": (("record", "opaque"),),
    "Twait": (("cursor", "Q"), ("mask", "Q"), ("max", "H")),
    "Rwait": (("next", "Q"), ("events", "events")),
    "Tflush": (("oldtag", "H"),),
    "Rflush": (),
    "Tinject": (("dom", "Q"), ("fault", "H")),
    "Rinject": (("dom", "Q"),),
}
_NAMES = ("error", "version", "claim", "outcome", "create", "start", "withdraw",
          "restore", "destroy", "stat", "lease", "derive", "bind", "revoke",
          "quiesce", "lstat", "wait", "flush", "inject")
TYPES = {}
for _index, _name in enumerate(_NAMES):
    for _prefix, _offset in (("T", 0), ("R", 1)):
        _value = 160 + 2 * _index + _offset
        globals()["O10_" + _prefix + _name.upper()] = _value
        if _prefix + _name != "Terror":
            TYPES[_prefix + _name] = _value
TYPE_NAMES = {code: name for name, code in TYPES.items()}
READ_ONLY = frozenset(("Toutcome", "Tstat", "Tlstat", "Twait"))
EVENT_SCHEMA = (("cursor", "Q"), ("type", "H"), ("flags", "H"),
                ("pad", "I"), ("dom", "Q"), ("lease", "Q"),
                ("arg0", "Q"), ("arg1", "Q"))
O10_EVENT_SIZE = 48


class O10Error(ValueError):
    """A structural wire error, with the protocol's numeric error and offset."""

    def __init__(self, code, detail=0, message="invalid O10 frame"):
        super().__init__(message)
        self.code = code
        self.detail = detail


def _bad(offset=0, message="invalid O10 frame"):
    raise O10Error(O10_EBADMSG, offset, message)


def _integer(value, fmt, offset):
    if type(value) is not int or not 0 <= value < 1 << (8 * struct.calcsize("<" + fmt)):
        _bad(offset, "unsigned integer outside field width")
    return struct.pack("<" + fmt, value)


def _bytes(value, offset):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        _bad(offset, "byte field requires bytes")
    return bytes(value)


def _name(message_type):
    if isinstance(message_type, str) and message_type in TYPES:
        return message_type
    if type(message_type) is int and message_type in TYPE_NAMES:
        return TYPE_NAMES[message_type]
    _bad(4, "unknown or illegal O10 message type")


def _limit(msize):
    if type(msize) is not int or not O10_HEADER_SIZE <= msize <= O10_MSIZE:
        _bad(0, "msize outside structural codec bounds")


def _event(event, offset):
    expected = {name for name, _ in EVENT_SCHEMA} - {"pad"}
    if not isinstance(event, dict) or set(event) != expected:
        _bad(offset, "event fields do not match schema")
    body = bytearray()
    for name, fmt in EVENT_SCHEMA:
        body += _integer(0 if name == "pad" else event[name], fmt, offset + len(body))
    return bytes(body)


def encode(message_type, tag=0, *, epoch=None, seq=None, msize=O10_MSIZE, **fields):
    """Encode one complete frame; no authorization or semantic validation.

    The msize keyword is the transport bound. Tversion/Rversion's wire msize
    field is supplied as negotiated_msize to avoid colliding with that bound.
    """
    _limit(msize)
    name = _name(message_type)
    fields = dict(fields)
    if name in ("Tversion", "Rversion") and "negotiated_msize" in fields:
        fields["msize"] = fields.pop("negotiated_msize")
    # Rversion/Rclaim's epoch is a reply body field, not a T prefix.
    if name in ("Rversion", "Rclaim") and epoch is not None:
        fields["epoch"] = epoch
        epoch = None
    schema = SCHEMAS[name]
    if set(fields) != {field for field, _ in schema}:
        _bad(7, "message fields do not match schema")
    body = bytearray()
    if name.startswith("T") and name != "Tversion":
        if epoch is None or seq is None:
            _bad(7, "request requires epoch and seq")
        body += _integer(epoch, "Q", 7)
        body += _integer(seq, "Q", 15)
        if name in READ_ONLY and seq != 0:
            _bad(15, "read-only request requires seq zero")
    elif epoch is not None or seq is not None:
        _bad(7, "message has no request epoch/seq prefix")
    for field, fmt in schema:
        offset = 7 + len(body)
        value = fields[field]
        if fmt in ("bytes", "opaque"):
            data = _bytes(value, offset)
            if fmt == "bytes":
                body += _integer(len(data), "H", offset)
            body += data
        elif fmt == "events":
            if not isinstance(value, (tuple, list)):
                _bad(offset, "events requires a list or tuple")
            body += _integer(len(value), "H", offset)
            for event in value:
                body += _event(event, 7 + len(body))
        elif fmt.endswith("s"):
            data = _bytes(value, offset)
            if len(data) != int(fmt[:-1]):
                _bad(offset, "fixed byte field has wrong length")
            body += data
        else:
            body += _integer(value, fmt, offset)
    size = O10_HEADER_SIZE + len(body)
    if size > msize:
        _bad(0, "frame exceeds msize")
    return struct.pack("<IB", size, TYPES[name]) + _integer(tag, "H", 5) + body


def decode(frame, *, msize=O10_MSIZE):
    """Decode exactly one frame, rejecting truncated and surplus bytes.

    Results contain type/tag, a request prefix where present, and body fields.
    Version messages use negotiated_msize for their wire msize field, so the
    returned mapping may be passed directly to encode after popping type.
    """
    _limit(msize)
    frame = _bytes(frame, 0)
    if len(frame) < O10_HEADER_SIZE:
        _bad(len(frame), "truncated header")
    size, code, tag = struct.unpack_from("<IBH", frame)
    if size != len(frame) or size > msize:
        _bad(0, "frame size mismatch")
    name = _name(code)
    result = {"type": name, "tag": tag}
    cursor = 7

    def take(count):
        nonlocal cursor
        if count > len(frame) - cursor:
            _bad(cursor, "truncated message field")
        data = frame[cursor:cursor + count]
        cursor += count
        return data

    def integer(fmt):
        return struct.unpack("<" + fmt, take(struct.calcsize("<" + fmt)))[0]

    if name.startswith("T") and name != "Tversion":
        result["epoch"], result["seq"] = integer("Q"), integer("Q")
        if name in READ_ONLY and result["seq"] != 0:
            _bad(15, "read-only request requires seq zero")
    for field, fmt in SCHEMAS[name]:
        if fmt == "bytes":
            value = take(integer("H"))
        elif fmt == "opaque":
            value = take(len(frame) - cursor)
        elif fmt == "events":
            count = integer("H")
            if count > (len(frame) - cursor) // O10_EVENT_SIZE:
                _bad(cursor - 2, "event count exceeds frame")
            value = []
            for _ in range(count):
                event = {key: integer(kind) for key, kind in EVENT_SCHEMA}
                if event.pop("pad") != 0:
                    _bad(cursor - O10_EVENT_SIZE + 12, "event padding must be zero")
                value.append(event)
        elif fmt.endswith("s"):
            value = take(int(fmt[:-1]))
        else:
            value = integer(fmt)
        result["negotiated_msize" if field == "msize" else field] = value
    if cursor != len(frame):
        _bad(cursor, "surplus message bytes")
    return result


def reencode(message, *, msize=O10_MSIZE):
    """Encode a decoded message without changing its bytes."""
    fields = dict(message)
    name = fields.pop("type")
    return encode(name, msize=msize, **fields)

# Draft 0 omits enum numbers. These implementation-local assignments require
# protocol review and are deliberately labelled provisional.
PROVISIONAL_DOMAIN_GOVERNOR = 1
PROVISIONAL_DOMAIN_GUEST_KERNEL = 2
PROVISIONAL_DOMAIN_NATIVE_SERVICE = 3
PROVISIONAL_STATE_EMPTY = 0
PROVISIONAL_STATE_PROVISIONED = 1
PROVISIONAL_STATE_RUNNING = 2
PROVISIONAL_STATE_BLOCKED = 3
PROVISIONAL_STATE_FAULTED = 4
PROVISIONAL_STATE_WITHDRAWN = 5

# Normative resource vocabulary and rights from sections 5 and 6.
O10_KIND_MEMORY = 1
O10_KIND_NAMESPACE = 2
O10_KIND_DEVICE = 5
O10_KIND_CONSOLE = 6
O10_RIGHT_READ = 0x001
O10_RIGHT_WRITE = 0x002
O10_RIGHT_CREATE = 0x004
O10_RIGHT_REMOVE = 0x008
O10_RIGHT_WSTAT = 0x010
O10_RIGHT_USE = 0x020
O10_RIGHT_MMIO = 0x040
O10_RIGHT_IRQ = 0x080
O10_RIGHT_DMA = 0x100
O10_RIGHT_MAP = 0x200
MUTATING = frozenset(name for name in TYPES
                     if name.startswith("T") and name != "Tversion" and name not in READ_ONLY)
