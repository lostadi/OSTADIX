#!/usr/bin/env python3
"""Bounded metadata decoder for *already decoded* installed AICore protobufs.

This does not decrypt, download, modify model files, execute inference or infer
unknown field meanings. Field numbers/types come from installed AICore's Java
GeneratedMessageLite metadata; friendly meanings are only added where callers
establish them. Unknown bytes are represented by size/hash, never payload.
"""
import argparse
import hashlib
import json
from pathlib import Path

# number: (label, kind). Repeated fields are always emitted as lists so wire
# duplicates and field presence remain visible. Primitive varints stay numeric.
SCHEMAS = {
    "edd": {1: ("entries", "edb"), 2: ("metadata", "edc"), 3: ("file_map", "map_file")},
    "edb": {1: ("conditions", "eda"), 2: ("file_group", "ect")},
    "eda": {1: ("selectors", "string"), 2: ("d", "opaque"), 3: ("e", "empty")},
    "edc": {1: ("c", "string")},
    "ect": {
        1: ("group_name", "string"), 2: ("files", "ecs"), 3: ("h", "varint"),
        6: ("d", "string"), 10: ("e", "varint"), 11: ("i", "varint"),
        13: ("j", "opaque"), 14: ("k", "varint"), 17: ("m", "opaque"),
        23: ("build_id", "varint"), 25: ("p", "string"), 26: ("o", "string"),
        27: ("f", "opaque"), 28: ("q", "opaque"), 29: ("g", "opaque"),
        30: ("r", "opaque"), 31: ("t", "opaque"), 32: ("s", "varint"),
    },
    "ecs": {
        2: ("download_url", "string"), 4: ("byte_size", "varint"),
        5: ("checksum", "string"), 7: ("file_id", "string"),
        11: ("download_transforms", "hmx"), 12: ("k", "hmx"),
        13: ("l", "opaque"), 14: ("i", "string"), 15: ("f", "varint"),
        16: ("j", "varint"), 17: ("m", "varint"), 19: ("n", "string"),
        20: ("relative_filename", "string"), 21: ("p", "opaque"),
        22: ("q", "string"), 23: ("r", "opaque"),
    },
    "hmx": {1: ("transforms", "hmw")},
    "hmw": {
        1: ("compression_marker", "empty"), 2: ("hmt", "opaque"),
        3: ("hmu", "opaque"), 4: ("hmy", "opaque"),
        5: ("hmq", "opaque"), 6: ("hmr", "empty"),
    },
    "map_file": {1: ("key", "string"), 2: ("value", "ecs")},
    "hid": {1: ("variant_hhz", "hhz"), 2: ("variant_hia", "hia"), 3: ("variant_hib", "hib")},
    "hhz": {1: ("b", "hic"), 2: ("c", "hic"), 3: ("d", "hic"), 4: ("e", "hic"), 7: ("f", "hic"), 8: ("g", "hic")},
    "hia": {3: ("b", "hic")},
    "hib": {3: ("b", "hic")},
    "hic": {1: ("batch_bound_b", "varint"), 3: ("context_bound_c", "varint")},
    "empty": {},
}


def varint(data, offset):
    n = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("truncated varint")
        b = data[offset]
        offset += 1
        if shift == 63 and b > 1:
            raise ValueError("varint exceeds uint64")
        n |= (b & 127) << shift
        if not b & 128:
            return n, offset
    raise ValueError("overlong varint")


def fields(data):
    p = 0
    while p < len(data):
        key, p = varint(data, p)
        number, wire = key >> 3, key & 7
        if not 0 < number < (1 << 29):
            raise ValueError("invalid field number")
        if wire == 0:
            value, p = varint(data, p)
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if size > len(data) - p:
                raise ValueError("truncated fixed field")
            value, p = data[p:p + size], p + size
        elif wire == 2:
            size, p = varint(data, p)
            if size > len(data) - p:
                raise ValueError("truncated length-delimited field")
            value, p = data[p:p + size], p + size
        else:
            raise ValueError(f"unsupported wire type {wire}")
        yield number, wire, value


def summary_bytes(value):
    return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def decode(data, schema, depth=0, counter=None):
    if depth > 32:
        raise ValueError("metadata nesting limit exceeded")
    if counter is None:
        counter = [0]
    out = {}
    for number, wire, value in fields(data):
        counter[0] += 1
        if counter[0] > 100000:
            raise ValueError("metadata field limit exceeded")
        label, kind = SCHEMAS[schema].get(number, ("unknown", "opaque"))
        if kind == "varint" and wire != 0:
            raise ValueError(f"field {schema}.{number} is not a varint")
        if kind in SCHEMAS and wire != 2:
            raise ValueError(f"field {schema}.{number} is not a message")
        if kind == "string":
            if wire != 2:
                raise ValueError(f"field {schema}.{number} is not a string")
            item = value.decode("utf-8")
            if len(item) > 4096:
                item = summary_bytes(value)
        elif kind in SCHEMAS:
            item = decode(value, kind, depth + 1, counter)
        elif isinstance(value, bytes):
            item = summary_bytes(value)
        else:
            item = value
        out.setdefault(f"{number}:{label}", []).append(item)
    return out


def manifest_summary(decoded, factory_root):
    groups = []
    for entry in decoded.get("1:entries", []):
        for group in entry.get("2:file_group", []):
            records = []
            for f in group.get("2:files", []):
                name = f.get("20:relative_filename", [""])[0]
                # Exact cat.m2398c behavior used by bsk's preload map builder.
                local = name
                if "/" in local and not local.startswith("drafter"):
                    local = local.split("/", 1)[1]
                if local.startswith("drafter"):
                    local = "drafter_" + local[8:]
                path = Path(factory_root) / local
                # Probe only contained paths in the fixed model directory.
                contained = path.resolve().is_relative_to(Path(factory_root).resolve())
                transforms = f.get("11:download_transforms", [])
                compressed = any("1:compression_marker" in t for ts in transforms for t in ts.get("1:transforms", []))
                records.append({
                    "file_id": f.get("7:file_id", []),
                    "relative_filename": name,
                    "mapped_factory_filename": local,
                    "checksum": f.get("5:checksum", []),
                    "byte_size": f.get("4:byte_size", []),
                    "compression_marker_present": compressed,
                    "factory_exists": contained and path.is_file(),
                    "factory_disk_bytes": path.stat().st_size if contained and path.is_file() else None,
                })
            groups.append({
                "group_name": group.get("1:group_name", []),
                "build_id": group.get("23:build_id", []),
                "conditions": entry.get("1:conditions", []),
                "files": records,
            })
    return groups


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path)
    ap.add_argument("--schema", choices=("edd", "hid"), required=True)
    ap.add_argument("--factory-root", default="/data/vendor/intelligence")
    args = ap.parse_args()
    if args.input.stat().st_size > 16 * 1024 * 1024:
        raise SystemExit("input exceeds metadata limit")
    b = args.input.read_bytes()
    result = {"input": str(args.input), **summary_bytes(b), "schema": args.schema}
    try:
        result["decoded"] = decode(b, args.schema)
        if args.schema == "edd":
            result["preload_file_groups"] = manifest_summary(result["decoded"], args.factory_root)
    except (ValueError, UnicodeError) as error:
        result["error"] = str(error)
    print(json.dumps(result, indent=2))
    return 1 if "error" in result else 0


if __name__ == "__main__":
    raise SystemExit(main())
