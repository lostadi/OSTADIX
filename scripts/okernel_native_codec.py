#!/usr/bin/env python3
"""Validate and snapshot the optional original-u9fs native monitor dependency.

The seven exact own-emitter objects must match completed compiler-owned source
and coverage receipts. The default monitor never calls this optional helper.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

SYMBOLS = {"convM2S", "convS2M", "convM2D", "convD2M", "sizeD2M", "statcheck", "memcpy", "memmove", "strlen"}
ABI = {"pointer_bits": 64, "Fcall_bytes": 712, "Fcall_alignment": 8, "Qid_bytes": 24}


def identity(path: Path, data: bytes | None = None) -> dict:
    if data is None:
        data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def checked(record: dict) -> tuple[Path, bytes]:
    if not isinstance(record, dict) or not isinstance(record.get("path"), str):
        raise ValueError("native codec identity lacks a path")
    path = Path(record["path"])
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("native codec artifact must be an absolute regular file: " + str(path))
    data = path.read_bytes()
    if type(record.get("bytes")) is not int or len(data) != record["bytes"] or not isinstance(record.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]):
        raise ValueError("invalid native codec byte/digest identity: " + str(path))
    if hashlib.sha256(data).hexdigest() != record["sha256"]:
        raise ValueError("native codec artifact changed: " + str(path))
    return path, data


def key(record: dict) -> tuple:
    return record["path"], record["bytes"], record["sha256"]


def json_record(record: dict, resolver=checked) -> tuple[dict, bytes]:
    _, data = resolver(record)
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError("native codec receipt must be an object")
    return result, data


def require_kernel_platform_record(value) -> None:
    """No Linux-user syscall/credential provider exists in this native monitor.

    Inspect both independently bound records and embedded IR; zero ordinary
    undefined symbols cannot satisfy an external userspace execution interface.
    This is not a generic loader for future kernel platform contracts.
    """
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if (item.get("linux_syscall_profile") is not None
                    or "required_platform_interfaces" in item and (not isinstance(item["required_platform_interfaces"], list) or item["required_platform_interfaces"])
                    or item.get("op") == "linux_syscall"):
                raise ValueError("Linux userspace platform effects cannot bind to the native kernel/monitor")
            for key_, child in item.items():
                if key_ == "native_ir" and isinstance(child, str):
                    try:
                        module = json.loads(child)
                        if not isinstance(module, dict) or module.get("format") != "ocore-native-module-v1":
                            raise ValueError("embedded native IR has no supported module shape")
                        pending.append(module)
                    except (ValueError, TypeError) as error:
                        raise ValueError("embedded native IR cannot be inspected for kernel platform requirements") from error
                else:
                    pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)


def require_kernel_platform_object(data: bytes) -> None:
    """Reject allocated Ocore platform-interface notes before privileged link."""
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("kernel platform check needs an ELF64 little-endian object")
    shoff = struct.unpack_from("<Q", data, 40)[0]
    stride, count = struct.unpack_from("<HH", data, 58)
    if count == 0 and shoff:
        # ELF extended numbering stores the real count in SHT_NULL.sh_size.
        # Never interpret zero e_shnum as an empty table when one is present.
        if stride != 64 or shoff + 64 > len(data) or struct.unpack_from("<I", data, shoff + 4)[0] != 0:
            raise ValueError("kernel platform check found invalid extended ELF section geometry")
        count = struct.unpack_from("<Q", data, shoff + 32)[0]
        if not count:
            raise ValueError("kernel platform check found an empty extended ELF section table")
    if not count or not shoff or stride != 64 or shoff + count * stride > len(data):
        raise ValueError("kernel platform check found invalid ELF section geometry")
    for index in range(count):
        header = shoff + index * stride
        kind = struct.unpack_from("<I", data, header + 4)[0]
        if kind != 7:
            continue
        offset, size = struct.unpack_from("<QQ", data, header + 24)
        if offset + size > len(data):
            raise ValueError("kernel platform note exceeds object bytes")
        notes = data[offset:offset + size]
        cursor = 0
        while cursor < len(notes):
            if cursor + 12 > len(notes):
                raise ValueError("truncated kernel platform ELF note")
            names, description, _ = struct.unpack_from("<III", notes, cursor)
            name_start = cursor + 12
            desc_start = name_start + (names + 3) // 4 * 4
            end = desc_start + (description + 3) // 4 * 4
            if end > len(notes):
                raise ValueError("invalid kernel platform ELF note extent")
            if notes[name_start:name_start + names] == b"Ocore\0":
                raise ValueError("Linux userspace platform object cannot bind to the native kernel/monitor")
            cursor = end


def validate(manifest_path: Path, isa: str, *, resolver=checked) -> dict:
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("native codec manifest must be a regular file")
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict):
        raise ValueError("native codec manifest must be an object")
    if manifest.get("schema") != "ostadix.native-u9fs-codec/v1" or manifest.get("isa") != isa:
        raise ValueError("native codec manifest schema/ISA mismatch")
    if manifest.get("abi") != ABI or manifest.get("unresolved_symbols") != [] or set(manifest.get("symbols", [])) != SYMBOLS:
        raise ValueError("native codec ABI or declared symbol closure mismatch")
    semantic = manifest.get("semantic_test")
    if not isinstance(semantic, dict) or semantic.get("ok") is not True:
        raise ValueError("native codec manifest requires successful original-component semantic execution")
    if len(manifest.get("objects", [])) != 7 or len(manifest.get("source_recipe_receipts", [])) != 2 or len(manifest.get("coverage_receipts", [])) != 2 or len(manifest.get("native_module_sets", [])) != 2:
        raise ValueError("native codec needs four codec and three memory objects with both receipt chains")
    receipts = []
    covered = []
    coverage_ids = {key(item) for item in manifest["coverage_receipts"]}
    module_ids = {key(item) for item in manifest["native_module_sets"]}
    bound_coverage = []
    for item in manifest["source_recipe_receipts"]:
        value, data = json_record(item, resolver)
        require_kernel_platform_record(value)
        if value.get("schema") != "ocore-native-source-recipe-v1" or value.get("stage") != "complete" or value.get("requested_target") != isa + "-unknown-none" or value.get("output_kind") != "obj" or not all(value.get(name) is True for name in ("success", "capture_complete", "lowering_complete")):
            raise ValueError("native source recipe did not complete for the selected target")
        if key(value["lowering_receipt"]) not in coverage_ids:
            raise ValueError("source recipe does not bind a supplied coverage receipt")
        bound_coverage.append(key(value["lowering_receipt"]))
        receipts.append((item, data))
    if Counter(bound_coverage) != Counter(key(item) for item in manifest["coverage_receipts"]):
        raise ValueError("both native source recipe chains must bind distinct coverage receipts")
    bound_modules = []
    for item in manifest["coverage_receipts"]:
        value, data = json_record(item, resolver)
        require_kernel_platform_record(value)
        if value.get("schema") != "ocore-runtime-lowering-v1" or value.get("architecture") != isa or value.get("requested_target") != isa + "-unknown-none" or value.get("output_kind") != "obj" or not all(value.get(name) is True for name in ("capture_complete", "module_set_complete", "native_module_dependency_closure_complete", "symbol_closure_complete")):
            raise ValueError("native coverage/module dependency closure is incomplete")
        if key(value["module_set_artifact"]) not in module_ids:
            raise ValueError("coverage receipt does not bind a supplied native module set")
        units = [unit for unit in value["units"] if unit.get("required_for_lowering") is True]
        if len(units) != value.get("required_lowering_unit_count") or len(units) != value.get("lowered_unit_count") or not all(unit.get("verified") is True and unit.get("lowered") is True for unit in units):
            raise ValueError("native coverage contains missing/unverified required units")
        bound_modules.append(key(value["module_set_artifact"]))
        covered.extend(key(unit["object"]) for unit in units)
        receipts.append((item, data))
    if Counter(bound_modules) != Counter(key(item) for item in manifest["native_module_sets"]):
        raise ValueError("both coverage receipts must bind distinct native module sets")
    if Counter(covered) != Counter(key(item) for item in manifest["objects"]) or len(set(covered)) != 7:
        raise ValueError("native objects differ from compiler-owned lowered unit identities")
    for item in manifest["native_module_sets"]:
        value, data = json_record(item, resolver)
        require_kernel_platform_record(value)
        if value.get("format") != "ocore-native-module-set-v1":
            raise ValueError("invalid native module-set artifact")
        receipts.append((item, data))
    # Bind the producer's semantic report to its exact executable, fixture,
    # carrier and successful recorded invocation. This does not rerun it or
    # independently authenticate the producer; live monitor execution follows.
    evidence = []
    for name in ("binary", "harness", "carrier"):
        item = semantic[name]
        _, data = resolver(item)
        evidence.append((item, data))
    commands, command_bytes = json_record(manifest["commands"], resolver)
    marker = semantic.get("stdout")
    if not isinstance(marker, str) or "Original u9fs and musl via O-core: PASS; checks=" not in marker or not any(
            record.get("exit_code") == 0 and record.get("stdout") == marker
            and record.get("argv", [])[-1:] == [semantic["binary"]["path"]]
            for record in commands.get("commands", [])):
        raise ValueError("native codec semantic execution report lacks its recorded successful invocation")
    evidence.append((manifest["commands"], command_bytes))
    objects = []
    machine = {"x86_64": 62, "aarch64": 183}[isa]
    definitions, undefined = [], set()
    for item in manifest["objects"]:
        path, data = resolver(item)
        if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<HH", data, 16) != (1, machine):
            raise ValueError("native object is not relocatable ELF64 for the selected ISA")
        require_kernel_platform_object(data)
        # Inspect the exact frozen bytes, not a source path that could change
        # between digest validation and symbol inventory.
        with tempfile.NamedTemporaryFile(suffix=".o") as frozen:
            frozen.write(data); frozen.flush()
            listing = subprocess.run(["nm", "--format=posix", "--extern-only", frozen.name], text=True, capture_output=True, check=True).stdout
        for line in listing.splitlines():
            fields = line.split()
            if len(fields) < 2:
                raise ValueError("unrecognized native object symbol inventory")
            name, kind = fields[:2]
            if kind in ("U", "w", "v"):
                undefined.add(name)
            else:
                definitions.append(name)
        objects.append((item, data))
    if set(definitions) != SYMBOLS or len(definitions) != len(SYMBOLS) or undefined - set(definitions):
        raise ValueError("actual native object symbols do not form the exact closed codec component")
    return {"manifest": manifest, "manifest_bytes": manifest_bytes, "manifest_identity": identity(manifest_path, manifest_bytes), "objects": objects, "receipts": receipts, "evidence": evidence}


def validate_capture(capture: dict, build: Path) -> dict:
    """Revalidate a staged closure using only its local captured bytes.

    Original paths inside immutable manifests/receipts are provenance keys.
    They resolve exclusively to the checked snapshots, so a prepared state can
    be forked and run independently of its producer checkout and cache.
    """
    if (not isinstance(capture, dict)
            or capture.get("schema") != "ostadix.monitor-native-u9fs/v1"
            or capture.get("isa") not in {"x86_64", "aarch64"}
            or capture.get("abi") != ABI or set(capture.get("symbols", [])) != SYMBOLS):
        raise ValueError("invalid captured native codec profile")
    build = build.resolve(strict=True)
    snapshots = {}

    def bind(original, snapshot):
        path = Path(snapshot["path"])
        if (not path.is_absolute() or ".." in path.parts
                or not path.is_relative_to(build)):
            raise ValueError("captured native codec escaped its monitor directory")
        current = build
        for part in path.relative_to(build).parts:
            current /= part
            if current.is_symlink():
                raise ValueError("captured native codec contains a symlink")
        _, data = checked(snapshot)
        if (snapshot["bytes"], snapshot["sha256"]) != (original["bytes"], original["sha256"]):
            raise ValueError("captured native codec differs from its source identity")
        snapshots[key(original)] = (path, data)

    bind(capture["source_manifest"], capture["captured_manifest"])
    manifest_path = Path(capture["captured_manifest"]["path"])
    manifest = json.loads(snapshots[key(capture["source_manifest"])][1])
    if not isinstance(manifest, dict):
        raise ValueError("captured native codec manifest must be an object")
    originals = manifest.get("objects", [])
    if len(originals) != 7 or len(capture.get("objects", [])) != 7:
        raise ValueError("captured native codec needs seven objects")
    for original, snapshot in zip(originals, capture["objects"]):
        bind(original, snapshot)
    for group, count in (("receipts", 6), ("semantic_evidence", 4)):
        if len(capture.get(group, [])) != count:
            raise ValueError("captured native codec lacks its complete receipt/evidence snapshots")
        for item in capture[group]:
            bind(item["source"], item["snapshot"])
    expected = [capture["source_manifest"], *originals,
                *manifest["source_recipe_receipts"], *manifest["coverage_receipts"],
                *manifest["native_module_sets"], manifest["commands"],
                *[manifest["semantic_test"][name] for name in ("binary", "harness", "carrier")]]
    if set(snapshots) != {key(item) for item in expected}:
        raise ValueError("captured native codec snapshot membership differs from its manifest")

    def resolve(record):
        try:
            return snapshots[key(record)]
        except KeyError as error:
            raise ValueError("native codec dependency has no captured snapshot") from error

    return validate(manifest_path, capture["isa"], resolver=resolve)


def stage(manifest_path: Path, build: Path, isa: str = "aarch64") -> dict:
    validated = validate(manifest_path, isa)
    build.mkdir(parents=True, exist_ok=True)
    snapshot = Path(tempfile.mkdtemp(prefix="native-u9fs-", dir=build))
    def capture(name, data):
        path = snapshot / name
        with path.open("xb") as stream:
            stream.write(data)
        path.chmod(0o444)
        return identity(path, data)
    manifest_copy = capture("native-codec.json", validated["manifest_bytes"])
    objects = [capture(f"object-{index:02}.o", data) for index, (_, data) in enumerate(validated["objects"])]
    receipts = [{"source": item, "snapshot": capture(f"receipt-{index:02}.json", data)} for index, (item, data) in enumerate(validated["receipts"])]
    evidence = [{"source": item, "snapshot": capture(f"evidence-{index:02}.bin", data)} for index, (item, data) in enumerate(validated["evidence"])]
    result = {"schema": "ostadix.monitor-native-u9fs/v1", "isa": isa, "source_manifest": validated["manifest_identity"], "captured_manifest": manifest_copy, "objects": objects, "receipts": receipts, "semantic_evidence": evidence, "abi": ABI, "symbols": sorted(SYMBOLS), "scope": "native namespace peer request/reply codec; unchanged native object-store authority; not full u9fs or merged OS"}
    pending = snapshot / "monitor-native-codec.json"
    pending.write_text(json.dumps(result, indent=2) + "\n")
    os.replace(pending, build / "native-9p.json")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--isa", choices=("x86_64", "aarch64"), default="aarch64")
    args = parser.parse_args()
    try:
        result = stage(args.manifest.expanduser().absolute(), args.build.expanduser().absolute(), args.isa)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Native codec admission failed: {error}\n")
    for item in result["objects"]:
        sys.stdout.buffer.write(os.fsencode(item["path"]) + b"\0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
