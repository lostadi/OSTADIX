"""Audit C API blind spots in freshly serialized, pinned LLVM 22 bitcode.

This is a bitstream reader, not an LLVM IR importer. The caller must first
parse and verify the whole module with its pinned LLVM library, then serialize
that same module with LLVMWriteBitcodeToMemoryBuffer. Arbitrary input bitcode
and ThinLTO summary files are outside this interface's contract.

Record layouts are pinned to rust-lang/llvm-project commit
dcc3606807c989700e0ac1cac18c31741bcd40d9, LLVM 22.1.6:
llvm/include/llvm/Bitstream/{BitCodeEnums,BitCodes}.h and
llvm/lib/Bitcode/Writer/BitcodeWriter.cpp (writeModuleInfo).
Referenced COMDAT records and membership IDs are pinned to writeComdats and
ValueEnumerator::EnumerateValue; unused named declarations are not serialized.
Alignment encoding is pinned to llvm/include/llvm/Support/Alignment.h:
0 is unspecified; 1..33 encode 1..2^32 bytes. LLVMGetAlignment returns
unsigned and cannot distinguish 2^32-byte global/function alignment from 0.
Synchronization scope names are pinned to writeSyncScopeNames,
BitcodeReader::parseSyncScopeNames/convertToString and LLVMContextImpl:
module child block 26, record 1, ordered by context-local ID. Name records
contain uint64 integers converted back to char bytes, including signed-char
promotion by the writer; their raw values need not fit in an unsigned byte.
The caller owns the library hash/version check. No native handles cross here.
"""


class BitcodeFailure(Exception):
    """The serialized module cannot satisfy the pinned audit contract."""


_MAGIC = b"BC\xc0\xde"
_CHAR6 = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._"


class _Bits:
    def __init__(self, data):
        self.data = data
        self.pos = 32
        self.limit = len(data) * 8

    def fail(self, message):
        raise BitcodeFailure(f"{message} at bit {self.pos}")

    def read(self, width):
        if not 0 <= width <= 64 or self.pos + width > self.limit:
            self.fail("truncated or invalid fixed-width field")
        first = self.pos // 8
        shift = self.pos % 8
        size = (shift + width + 7) // 8
        value = int.from_bytes(self.data[first:first + size], "little")
        self.pos += width
        return (value >> shift) & ((1 << width) - 1)

    def vbr(self, width, value_bits=64):
        if not 2 <= width <= 64:
            self.fail("invalid VBR width")
        value, shift = 0, 0
        payload_mask = (1 << (width - 1)) - 1
        while True:
            chunk = self.read(width)
            payload = chunk & payload_mask
            if shift >= value_bits or payload >= (1 << (value_bits - shift)):
                self.fail("VBR integer overflow")
            value |= payload << shift
            if not chunk >> (width - 1):
                return value
            shift += width - 1

    def align(self):
        padding = (-self.pos) % 32
        if self.read(padding):
            self.fail("nonzero bitstream alignment padding")

    def count(self, value, min_bits):
        # Bounds derive from the actual input, with no module-size ceiling.
        if value > (self.limit - self.pos) // min_bits:
            self.fail("element count exceeds enclosing block")


def _abbreviation(bits):
    count = bits.vbr(5, 32)
    if not count:
        bits.fail("empty abbreviation")
    bits.count(count, 4)
    operands = []
    for _ in range(count):
        if bits.read(1):
            operands.append((0, bits.vbr(8)))
            continue
        encoding = bits.read(3)
        if encoding not in (1, 2, 3, 4, 5):
            bits.fail("invalid abbreviation encoding")
        width = bits.vbr(5) if encoding in (1, 2) else 0
        if encoding in (1, 2):
            if not width:
                operands.append((0, 0))
                continue
            if width > 64 or (encoding == 2 and width == 1):
                bits.fail("invalid abbreviation field width")
        operands.append((encoding, width))
    if operands[0][0] in (3, 5):
        bits.fail("abbreviation record code is an array or blob")
    for index, (encoding, _) in enumerate(operands):
        if encoding == 3:
            if index != len(operands) - 2 or operands[index + 1][0] not in (1, 2, 4):
                bits.fail("invalid array abbreviation")
        elif encoding == 5 and index != len(operands) - 1:
            bits.fail("blob abbreviation is not last")
    return operands


def _field(bits, operand):
    encoding, value = operand
    if encoding == 0:
        return value
    if encoding == 1:
        return bits.read(value)
    if encoding == 2:
        return bits.vbr(value)
    if encoding == 4:
        return _CHAR6[bits.read(6)]
    bits.fail("invalid scalar abbreviation operand")


def _record(bits, abbrev_id, abbreviations, keep, keep_blob=False):
    values, blob, blob_range = [], False, None
    if abbrev_id == 3:
        code = bits.vbr(6, 32)
        count = bits.vbr(6, 32)
        bits.count(count, 6)
        for _ in range(count):
            value = bits.vbr(6)
            if keep:
                values.append(value)
        return code, values, blob, blob_range
    index = abbrev_id - 4
    if not 0 <= index < len(abbreviations):
        bits.fail("undefined abbreviation")
    operands = abbreviations[index]
    code = _field(bits, operands[0])
    if code >= 1 << 32:
        bits.fail("record code overflow")
    index = 1
    while index < len(operands):
        operand = operands[index]
        encoding = operand[0]
        if encoding == 3:
            count = bits.vbr(6, 32)
            element = operands[index + 1]
            min_bits = element[1] if element[0] in (1, 2) else 6
            bits.count(count, min_bits)
            if not keep and element[0] in (1, 4):
                bits.pos += count * min_bits
            else:
                for _ in range(count):
                    value = _field(bits, element)
                    if keep:
                        values.append(value)
            index += 2
            continue
        if encoding == 5:
            blob = True
            count = bits.vbr(6, 32)
            bits.align()
            bits.count(count, 8)
            if keep_blob:
                blob_range = (bits.pos // 8, count)
            bits.pos += count * 8
            bits.align()
        else:
            value = _field(bits, operand)
            if keep:
                values.append(value)
        index += 1
    return code, values, blob, blob_range


def _alignment(bits, encoded, context):
    if encoded > 33:
        bits.fail(f"invalid {context} alignment encoding {encoded}; expected 0..33")
    return (1 << (encoded - 1)) if encoded else 0


def _comdat_id(bits, value, result, context):
    if value >= 1 << 32 or value > result["comdat_count"]:
        bits.fail(f"invalid {context} COMDAT ID")
    return value


def _comdat_names(bits, result, strtab_range):
    if result["comdat_count"] and strtab_range is None:
        bits.fail("COMDAT names require the pinned writer string table")
    names = set()
    for index, record in enumerate(result["comdat_contracts"], 1):
        start, size = strtab_range
        offset, length = record["name_offset"], record["name_length"]
        if not length or offset > size or length > size - offset:
            bits.fail(f"invalid COMDAT #{index} name string-table bounds")
        raw = bits.data[start + offset:start + offset + length]
        if b"\0" in raw:
            bits.fail(f"embedded NUL in COMDAT #{index} name")
        try:
            name = raw.decode("utf-8")
        except UnicodeDecodeError:
            bits.fail(f"invalid UTF-8 in COMDAT #{index} name")
        if name in names:
            bits.fail("duplicate COMDAT name in fresh writer inventory")
        names.add(name)
        record["name"] = name


def _sync_scope_record(bits, code, values, blob, names):
    if code != 1 or blob:
        bits.fail("expected one synchronization scope name record")
    # The pinned writer appends char iterators to uint64_t records. The
    # reader appends those integers back to chars; retain the low byte even
    # when a high-byte char was sign-extended, without text decoding.
    raw = bytes(value & 255 for value in values)
    if len(names) < 2 and raw != (b"singlethread", b"")[len(names)]:
        bits.fail("fresh writer synchronization scope builtin ID/name mismatch")
    names.append(raw)


def _module_record(bits, code, values, blob, result):
    if code not in (1, 2, 3, 7, 8, 9, 12, 14):
        return
    if blob:
        bits.fail("unexpected blob in audited module record")
    if code == 1:
        if result["version"] is not None or values != [2]:
            bits.fail("expected one LLVM module version 2 record")
        result["version"] = 2
        return
    if code in (2, 3):
        key = "triple" if code == 2 else "data_layout"
        if result[key] is not None:
            bits.fail(f"duplicate module {key} record")
        if any(not 0 < value < 128 for value in values):
            bits.fail(f"non-ASCII or embedded NUL in module {key}")
        result[key] = bytes(values).decode("ascii")
        return
    if result["version"] != 2:
        bits.fail("global/function/alias/COMDAT record precedes module version")
    if code == 12:
        # BitcodeWriter.cpp:1427-1434 uses SmallVector<unsigned> and emits
        # only the groups discovered through GlobalObject membership.
        if len(values) != 3:
            bits.fail(f"unexpected COMDAT record layout ({len(values)} fields)")
        if any(value >= 1 << 32 for value in values):
            bits.fail("invalid COMDAT record unsigned field")
        selection = values[2]
        if not 1 <= selection <= 5:
            bits.fail("invalid COMDAT selection encoding")
        if selection not in (1, 4):
            bits.fail(f"unsupported ELF COMDAT selection encoding {selection}")
        result["comdat_count"] += 1
        result["comdat_contracts"].append(dict(zip(
            ("name_offset", "name_length", "selection_encoding"), values)))
        return
    if code == 9:
        bits.fail("deprecated ALIAS_OLD record is not emitted by the pinned fresh writer")
    if code == 14:
        if len(values) != 13:
            bits.fail(f"unexpected ALIAS record layout ({len(values)} fields)")
        # llvm-project dcc3606807c989700e0ac1cac18c31741bcd40d9:
        # BitcodeWriter.cpp:1696-1708. These are serialized encodings, not
        # LLVM-C enums (weak is 16, and global unnamed_addr is 1 here).
        record = dict(zip(("name_offset", "name_length", "value_type",
                           "address_space", "aliasee", "linkage_encoding",
                           "visibility", "dll_storage_class", "thread_local_mode",
                           "unnamed_address", "dso_local", "partition_offset",
                           "partition_length"), values))
        context = f"alias #{result['alias_count'] + 1}"
        for key in ("value_type", "aliasee"):
            if record[key] >= 1 << 32:
                bits.fail(f"invalid {context} {key} ID")
        if record["address_space"] >= 1 << 32:
            bits.fail(f"invalid {context} address space")
        if record["address_space"]:
            bits.fail(f"unsupported {context} address space")
        if record["linkage_encoding"] not in (0, 3, 9, 12, 16, 17, 18, 19):
            bits.fail(f"invalid {context} linkage encoding")
        for key, maximum in (("visibility", 2), ("dll_storage_class", 2),
                             ("thread_local_mode", 4), ("unnamed_address", 2),
                             ("dso_local", 1)):
            if record[key] > maximum:
                bits.fail(f"invalid {context} {key}")
        for key in ("dll_storage_class", "thread_local_mode", "partition_length"):
            if record[key]:
                bits.fail(f"unsupported {context} {key}")
        # Empty strings may have a nonzero string-table offset. The verifier
        # and fresh writer own string/identity validity; retain all thirteen
        # fields for ordered binding to the live C API traversal.
        result["alias_count"] += 1
        result["alias_contracts"].append(record)
        result["dso_local_count"] += record["dso_local"]
        return
    if code == 7:
        if len(values) not in (8, 20):
            bits.fail(f"unexpected GLOBALVAR record layout ({len(values)} fields)")
        result["global_count"] += 1
        result["global_alignments"].append(
            _alignment(bits, values[6], f"global #{result['global_count']}"))
        result["global_comdat_ids"].append(_comdat_id(
            bits, values[13] if len(values) == 20 else 0, result,
            f"global #{result['global_count']}"))
        if len(values) == 8:
            return
        for field, label in ((14, "global attributes"), (17, "global partition"),
                             (18, "global sanitizer metadata"), (19, "global code model")):
            if values[field]:
                bits.fail(f"unsupported {label} on global #{result['global_count']}")
        dso_local = values[15]
    else:
        if len(values) != 21:
            bits.fail(f"unexpected FUNCTION record layout ({len(values)} fields)")
        result["function_count"] += 1
        result["function_alignments"].append(
            _alignment(bits, values[7], f"function #{result['function_count']}"))
        result["function_comdat_ids"].append(_comdat_id(
            bits, values[14], result, f"function #{result['function_count']}"))
        if values[20]:
            bits.fail(f"unsupported function partition on function #{result['function_count']}")
        dso_local = values[17]
    if dso_local not in (0, 1):
        bits.fail("invalid dso_local flag")
    result["dso_local_count"] += dso_local


def audit_bitcode(data: bytes) -> dict:
    """Return module inventories and full alignments or raise BitcodeFailure.

    All blocks and records are structurally consumed. MODULE version, target
    strings, COMDAT, GLOBALVAR, FUNCTION and fresh ALIAS records carry semantic
    interpretation. Deprecated ALIAS_OLD records reject.
    Target strings are returned for comparison with the C API; DSO-local
    handling remains the importing execution profile's responsibility.
    global_alignments/function_alignments follow the module's respective
    declaration/definition traversal order. Values are full byte alignments,
    with 0 reserved for unspecified alignment, not the truncated C API value.
    alias_contracts follow alias traversal order and retain all thirteen
    serialized fields. Their enum fields are writer encodings, not C API
    enums; the importer must compare them using the pinned conversion tables.
    comdat_contracts contain exact UTF-8 names from the writer string table
    and raw selection encodings (1=any, 4=no_deduplicate). Ordered membership
    IDs are 1-based, with 0 for absence. comdat_count counts all referenced
    groups in the normalized module; unused named declarations are absent
    from the pinned writer's inventory.
    When the fresh writer's synchronization scope block is present,
    sync_scope_names holds ordered owned bytes indexed by the actual
    context-local ID (0=singlethread, 1=empty system name). Embedded NULs
    and arbitrary bytes are retained. An absent block adds no result key;
    names are never fabricated from instructions or decoded as text.
    """
    if not isinstance(data, bytes):
        raise BitcodeFailure("bitcode audit requires owned bytes")
    if len(data) % 4 or not data.startswith(_MAGIC):
        raise BitcodeFailure("expected aligned raw LLVM bitcode magic")
    bits = _Bits(data)
    result = {"version": None, "module_count": 0, "global_count": 0,
              "function_count": 0, "dso_local_count": 0,
              "alias_count": 0, "alias_contracts": [],
              "comdat_count": 0, "comdat_contracts": [],
              "global_comdat_ids": [], "function_comdat_ids": [],
              "triple": None, "data_layout": None,
              "global_alignments": [], "function_alignments": []}
    inherited = {}
    strtab_seen, strtab_range = False, None
    # Frames avoid a recursion limit for deeply nested bitstreams. Each frame
    # owns its abbreviation namespace and exact declared block endpoint.
    frames = [{"id": None, "width": 2, "end": bits.limit,
               "abbreviations": [], "setbid": None}]
    while frames:
        frame = frames[-1]
        bits.limit = frame["end"]
        if bits.pos == bits.limit:
            if frame["id"] is not None:
                bits.fail("missing END_BLOCK")
            frames.pop()
            break
        abbrev_id = bits.read(frame["width"])
        if abbrev_id == 0:
            if frame["id"] is None:
                bits.fail("unexpected top-level END_BLOCK")
            if frame["id"] == 26 and len(result["sync_scope_names"]) < 2:
                bits.fail("fresh writer synchronization scope inventory misses builtin names")
            bits.align()
            if bits.pos != frame["end"]:
                bits.fail("END_BLOCK disagrees with declared block length")
            frames.pop()
            continue
        if abbrev_id == 1:
            block_id = bits.vbr(8, 32)
            width = bits.vbr(4, 32)
            if not 2 <= width <= 32:
                bits.fail("invalid subblock code width")
            bits.align()
            words = bits.read(32)
            end = bits.pos + words * 32
            if not words or end > frame["end"]:
                bits.fail("subblock exceeds enclosing block")
            if block_id == 8:
                if frame["id"] is not None or result["module_count"]:
                    bits.fail("expected exactly one top-level MODULE block")
                result["module_count"] += 1
            if frame["id"] == 23:
                bits.fail("unexpected subblock in writer string table")
            if frame["id"] == 26:
                bits.fail("unexpected subblock in synchronization scope names")
            if block_id == 23:
                if frame["id"] is not None or strtab_seen:
                    bits.fail("expected one top-level writer string table")
                strtab_seen = True
            if block_id == 26:
                if frame["id"] != 8 or result["version"] != 2:
                    bits.fail("expected synchronization scope names directly in module version 2")
                if "sync_scope_names" in result:
                    bits.fail("duplicate synchronization scope names block")
                result["sync_scope_names"] = []
            frames.append({"id": block_id, "width": width, "end": end,
                           "abbreviations": list(inherited.get(block_id, ())), "setbid": None})
            continue
        if abbrev_id == 2:
            abbreviation = _abbreviation(bits)
            if frame["id"] == 0:
                if frame["setbid"] is None:
                    bits.fail("BLOCKINFO abbreviation precedes SETBID")
                inherited.setdefault(frame["setbid"], []).append(abbreviation)
            else:
                frame["abbreviations"].append(abbreviation)
            continue
        if frame["id"] is None:
            bits.fail("unexpected top-level record")
        code, values, blob, blob_range = _record(
            bits, abbrev_id, frame["abbreviations"], frame["id"] in (0, 8, 23, 26),
            keep_blob=frame["id"] == 23)
        if frame["id"] == 0 and code == 1:
            if blob or len(values) != 1 or values[0] >= 1 << 32:
                bits.fail("invalid BLOCKINFO SETBID record")
            frame["setbid"] = values[0]
        elif frame["id"] == 8:
            _module_record(bits, code, values, blob, result)
        elif frame["id"] == 23:
            if code != 1 or values or not blob or strtab_range is not None:
                bits.fail("expected one writer string-table blob record")
            strtab_range = blob_range
        elif frame["id"] == 26:
            _sync_scope_record(bits, code, values, blob, result["sync_scope_names"])
    if result["module_count"] != 1 or result["version"] != 2:
        raise BitcodeFailure("expected exactly one complete LLVM module version 2")
    if strtab_seen and strtab_range is None:
        raise BitcodeFailure("missing writer string-table blob record")
    _comdat_names(bits, result, strtab_range)
    return result
