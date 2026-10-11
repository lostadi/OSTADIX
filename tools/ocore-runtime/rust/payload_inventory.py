#!/usr/bin/env python3
"""Verify byte-backed Rust payload edges without claiming compiler completion.

An embedded LLVM bitcode section is an edge in an original producer's artifact.
A matching CGU filename, a separately replayed frontend command, or a stage label
is not that edge. This helper independently reads ELF/archive bytes and original
hash-bound journals. It neither executes a compiler nor changes capture inputs.

Its bounded edge receipt is not a full unit inventory. In particular, embedded
bitcode may precede LTO: byte provenance does not prove native-code equivalence,
O-core admission, complete providers, or an OSTADIX execution profile.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
from typing import Iterator


EVIDENCE_SCHEMA = "ocore-rust-payload-evidence-v1"
RECEIPT_SCHEMA = "ocore-rust-payload-edge-verification-v1"
EDGE_SCHEMA = "ocore-rust-native-bitcode-edge-v1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class PayloadError(ValueError):
    def __init__(self, kind: str, message: str, **detail):
        super().__init__(message)
        self.kind, self.detail = kind, detail

    def record(self) -> dict:
        return {"kind": self.kind, "message": str(self), **self.detail}


def fail(kind: str, message: str, **detail):
    raise PayloadError(kind, message, **detail)


def exact_int(value, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        fail("invalid_evidence", f"{name} must be an integer >= {minimum}")
    return value


def sha_slice(data, offset: int, size: int) -> str:
    digest = hashlib.sha256()
    end = offset + size
    while offset < end:
        next_offset = min(offset + 1024 * 1024, end)
        digest.update(data[offset:next_offset])
        offset = next_offset
    return digest.hexdigest()


def file_info(path: Path) -> dict:
    path = path.absolute()
    with path.open("rb") as stream:
        before = path.stat()
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = path.stat()
    stamp = lambda stat: (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    if stamp(before) != stamp(after):
        fail("artifact_changed", "artifact changed while hashing", path=str(path))
    return {"path": str(path), "sha256": digest, "bytes": after.st_size}


def check_artifact(artifact: dict) -> dict:
    if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
        fail("invalid_evidence", "artifact requires an absolute path, SHA-256 and byte length")
    path = Path(artifact["path"])
    if not path.is_absolute() or not SHA256.fullmatch(str(artifact.get("sha256", ""))):
        fail("invalid_evidence", "artifact path/hash is not canonical", artifact=artifact)
    exact_int(artifact.get("bytes"), "artifact.bytes")
    try:
        actual = file_info(path)
    except OSError as error:
        fail("artifact_unavailable", str(error), artifact=artifact)
    if any(actual[key] != artifact[key] for key in ("path", "sha256", "bytes")):
        fail("artifact_mismatch", "artifact bytes differ from the original record", expected=artifact, actual=actual)
    return actual


@contextmanager
def mapped_artifact(artifact: dict) -> Iterator[mmap.mmap]:
    actual = check_artifact(artifact)
    path = Path(actual["path"])
    if actual["bytes"] == 0:
        fail("malformed_object", "empty object/archive artifact", artifact=actual)
    before = path.stat()
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        # Hash the exact mapped inode used for decoding, too. A path could have
        # been replaced after check_artifact opened it.
        if len(data) != actual["bytes"] or sha_slice(data, 0, len(data)) != actual["sha256"]:
            fail("artifact_changed", "mapped object differs from the hashed artifact", artifact=actual)
        yield data
        after = path.stat()
        stamp = lambda stat: (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        if stamp(before) != stamp(after):
            fail("artifact_changed", "artifact changed while decoding", artifact=actual)


def bounds(offset: int, size: int, limit: int, what: str):
    if offset < 0 or size < 0 or offset > limit or size > limit - offset:
        fail("malformed_object", f"{what} is outside the original bytes", offset=offset, bytes=size, limit=limit)


def bitcode_header(data, offset: int, size: int):
    if size >= 4 and data[offset:offset + 4] == b"BC\xc0\xde":
        return "raw"
    if size >= 20 and data[offset:offset + 4] == b"\xde\xc0\x17\x0b":
        _, version, start, length, _ = struct.unpack_from("<IIIII", data, offset)
        if version != 0 or start < 20 or start % 4 or length < 4:
            fail("malformed_bitcode", "invalid LLVM bitcode wrapper header")
        if start > size or length > size - start:
            fail("malformed_bitcode", "wrapped bitcode is outside the embedded section")
        if data[offset + start:offset + start + 4] != b"BC\xc0\xde":
            fail("malformed_bitcode", "LLVM wrapper does not contain a bitcode payload")
        return "wrapper"
    fail("malformed_bitcode", "embedded section has no supported LLVM bitcode header")


def elf_sections(data, start: int, size: int) -> dict:
    bounds(start, size, len(data), "ELF member")
    ident = data[start:start + 16]
    if ident[:4] != b"\x7fELF":
        fail("unsupported_object", "archive member is not an ELF object")
    bounds(0, 64, size, "ELF header")
    if ident[4:7] != bytes([2, 1, 1]):
        fail("unsupported_object", "embedded-bitcode profile requires ELF64 little-endian version 1")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, start)
    _, kind, machine, version, _, phoff, shoff, _, ehsize, phentsize, phnum, shentsize, shnum, shstr = header
    if kind != 1 or machine not in {62, 183, 243} or version != 1 or ehsize != 64:
        fail("unsupported_object", "embedded-bitcode edge requires an original x86-64/AArch64/RV64 relocatable object")
    if phnum:
        bounds(phoff, phentsize * phnum, size, "ELF program headers")
    if not shoff or shentsize != 64:
        fail("malformed_object", "missing/noncanonical ELF section table")
    bounds(shoff, 64, size, "ELF section zero")
    zero = struct.unpack_from("<IIQQQQIIQQ", data, start + shoff)
    if shnum == 0:
        shnum = zero[5]
    if shstr == 0xffff:
        shstr = zero[6]
    if shnum == 0 or shstr == 0 or shstr >= shnum:
        fail("malformed_object", "invalid ELF section count/name-table index")
    bounds(shoff, shnum * shentsize, size, "ELF section table")
    table = [struct.unpack_from("<IIQQQQIIQQ", data, start + shoff + i * shentsize) for i in range(shnum)]
    names = table[shstr]
    if names[1] != 3:
        fail("malformed_object", "ELF section names do not use a string table")
    bounds(names[4], names[5], size, "ELF section names")
    if names[5] == 0 or data[start + names[4]] != 0:
        fail("malformed_object", "ELF section names lack the initial NUL")
    result = []
    for index, section in enumerate(table):
        name_offset, section_type, flags, _, offset, length, _, _, alignment, _ = section
        if name_offset >= names[5]:
            fail("malformed_object", "ELF section name offset is out of bounds", section_index=index)
        begin = start + names[4] + name_offset
        end = data.find(b"\0", begin, start + names[4] + names[5])
        if end < 0:
            fail("malformed_object", "unterminated ELF section name", section_index=index)
        name = bytes(data[begin:end])
        if index != 0 and section_type != 8:
            bounds(offset, length, size, "ELF section")
        if alignment and alignment & (alignment - 1):
            fail("malformed_object", "ELF section alignment is not a power of two", section_index=index)
        result.append({"index": index, "name_bytes": list(name), "type": section_type,
                       "flags": flags, "offset": offset, "bytes": length})
    return {"machine": machine, "sections": result}


def archive_members(data) -> list[dict]:
    if data[:8] != b"!<arch>\n":
        fail("unsupported_archive", "only ordinary, non-thin archive membership is supported")
    members, names, offset, physical = [], b"", 8, 0
    while offset < len(data):
        bounds(offset, 60, len(data), "archive header")
        header = data[offset:offset + 60]
        if header[58:] != b"`\n":
            fail("malformed_archive", "invalid archive member trailer", header_offset=offset)
        number = header[48:58].strip()
        if not number or not number.isdigit():
            fail("malformed_archive", "invalid archive member size", header_offset=offset)
        size, name = int(number), bytes(header[:16]).rstrip(b" ")
        body = offset + 60
        bounds(body, size, len(data), "archive member")
        next_offset = body + size + (size & 1)
        bounds(body + size, size & 1, len(data), "archive padding")
        raw_offset, raw_size = body, size
        skip = name in {b"/", b"/SYM64/"}
        if name == b"//":
            names, skip = bytes(data[body:body + size]), True
        elif name.startswith(b"#1/"):
            count = name[3:]
            if not count.isdigit() or int(count) > size:
                fail("malformed_archive", "invalid BSD extended member name")
            count = int(count)
            name = bytes(data[body:body + count]).rstrip(b"\0")
            body, size = body + count, size - count
        elif name.startswith(b"/") and name[1:].isdigit():
            position = int(name[1:])
            if position >= len(names) or position and names[position - 1:position + 1] != b"\n" + names[position:position + 1]:
                fail("malformed_archive", "invalid GNU member name-table offset")
            ending = names.find(b"/\n", position)
            if ending < 0:
                fail("malformed_archive", "unterminated GNU archive member name")
            name = names[position:ending]
        else:
            name = name.removesuffix(b"/")
        # BSD ranlib indexes are structural metadata, never compiler CGUs.
        # Conservatively retain them in the physical inventory; extraction by
        # index fails as unsupported rather than silently calling them code.
        if not skip:
            members.append({"index": len(members), "physical_index": physical,
                "name": name.decode("utf-8", errors="surrogateescape"), "name_bytes": list(name),
                "header_offset": offset, "data_offset": body, "bytes": size,
                "raw_data_offset": raw_offset, "raw_bytes": raw_size,
                "sha256": sha_slice(data, body, size)})
        offset, physical = next_offset, physical + 1
    return members


def extract_embedded_bitcode(artifact: dict, member_index: int | None = None) -> dict:
    """Read exact original object/member ranges; never pair CGUs by basename.

    Returns section hashes/ranges, not a claim that LLVM accepted the module or
    that its pre/post-LTO native machine code is equivalent to those bytes.
    ``member_index`` is the logical archive member index; ``physical_index`` and
    raw member/name offsets are also retained for unambiguous reconstruction.
    """
    with mapped_artifact(artifact) as data:
        if data[:8] == b"!<arch>\n":
            members = archive_members(data)
            if member_index is None:
                fail("archive_member_required", "an archive edge requires an exact member index", members=members)
            exact_int(member_index, "member_index")
            if member_index >= len(members):
                fail("archive_member_missing", "requested archive member does not exist", member_index=member_index)
            member = members[member_index]
            start, size = member["data_offset"], member["bytes"]
        else:
            if data[:8] == b"!<thin>\n":
                fail("unsupported_archive", "thin archive members are external inputs, not embedded owned bytes")
            if member_index is not None:
                fail("invalid_evidence", "nonarchive object cannot have an archive member index")
            member, start, size = None, 0, len(data)
        decoded = elf_sections(data, start, size)
        sections = [s for s in decoded["sections"] if s["name_bytes"] == list(b".llvmbc")]
        if not sections:
            fail("embedded_bitcode_missing", "original ELF object has no embedded bitcode section")
        if len(sections) != 1:
            fail("ambiguous_embedded_bitcode", "multiple .llvmbc sections cannot establish a unique byte edge")
        section = sections[0]
        if section["type"] != 1 or section["flags"] & 0x800:
            fail("unsupported_embedded_bitcode", "embedded bitcode must be uncompressed PROGBITS")
        fmt = bitcode_header(data, start + section["offset"], section["bytes"])
        edge = {"kind": "elf_embedded_bitcode", "section_index": section["index"],
                "section_name": ".llvmbc", "section_name_bytes": section["name_bytes"],
                "object_offset": section["offset"], "container_offset": start + section["offset"],
                "bytes": section["bytes"], "sha256": sha_slice(data, start + section["offset"], section["bytes"]),
                "bitcode_header": fmt}
        return {"container": check_artifact(artifact), "member": member,
                "object": {"bytes": size, "sha256": sha_slice(data, start, size), "machine": decoded["machine"]},
                "edge": edge, "scope": "original-ELF-embedded-byte-provenance-only"}


def json_artifact(artifact: dict):
    check_artifact(artifact)
    try:
        return json.loads(Path(artifact["path"]).read_bytes())
    except (OSError, ValueError, UnicodeError) as error:
        fail("malformed_journal", str(error), artifact=artifact)


def identity(artifact: dict) -> tuple:
    return artifact.get("path"), artifact.get("sha256"), artifact.get("bytes")


def trusted_namespace(artifact: dict, expected: str) -> dict:
    """Load only the caller's independently pinned, byte-exact verifier worker."""
    check_artifact(artifact)
    if artifact.get("sha256") != expected:
        fail("trusted_worker_mismatch", "verifier worker differs from externally trusted SHA-256")
    namespace = {"__name__": "ocore_payload_readmission", "__file__": artifact["path"]}
    raw = Path(artifact["path"]).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        fail("artifact_changed", "trusted worker changed before loading")
    try:
        exec(compile(raw, artifact["path"], "exec"), namespace)
    except Exception as error:
        fail("worker_load_failed", "trusted verifier worker could not be loaded", reason=str(error))
    return namespace


def readmission_call(function, *args, **kwargs):
    """Keep a trusted worker's typed rejection as a bounded missing-edge gap."""
    try:
        return function(*args, **kwargs)
    except PayloadError:
        raise
    except Exception as error:
        fail("worker_readmission_rejected", "trusted original worker rejected the evidence",
             api=function.__name__, reason=str(error))


def verify_saved_cgu(record: dict, compiler_event: dict) -> dict:
    """Validate one record against original producer output and embedded bytes."""
    if record.get("schema") != EDGE_SCHEMA or record.get("compiler_invocation_id") != compiler_event.get("id"):
        fail("cgu_parent_mismatch", "saved CGU record does not belong to this original compiler journal")
    if record.get("cargo_parent_invocation_id") != compiler_event.get("cargo_parent_invocation_id"):
        fail("cgu_parent_mismatch", "saved CGU record belongs to another Cargo parent")
    if record not in compiler_event.get("saved_cgus", []):
        fail("cgu_not_journaled", "saved CGU edge is absent from its original compiler journal")
    object_artifact = record.get("object", {})
    check_artifact(object_artifact)
    container = record.get("container")
    if container is None:
        if identity(object_artifact) not in {identity(x) for x in compiler_event.get("outputs", [])}:
            fail("cgu_not_produced", "object is not an output of the original compiler invocation")
        extracted = extract_embedded_bitcode(object_artifact)
    else:
        if not isinstance(container, dict) or not isinstance(container.get("member"), dict):
            fail("invalid_evidence", "archive CGU requires container artifact and exact member record")
        artifact = container.get("artifact", {})
        if identity(artifact) not in {identity(x) for x in compiler_event.get("outputs", [])}:
            fail("cgu_not_produced", "archive is not an output of the original compiler invocation")
        extracted = extract_embedded_bitcode(artifact, container["member"].get("index"))
        for key in ("index", "physical_index", "name", "name_bytes", "header_offset", "data_offset",
                    "raw_data_offset", "raw_bytes", "bytes", "sha256"):
            if container["member"].get(key) != extracted["member"][key]:
                fail("archive_member_mismatch", "archive member identity/range differs from original bytes", field=key)
    if any(extracted["object"][key] != object_artifact[key] for key in ("bytes", "sha256")):
        fail("cgu_object_mismatch", "saved object is not the exact archived object bytes")
    requested = record.get("edge", {})
    for key in ("kind", "section_index", "section_name", "section_name_bytes", "object_offset",
                "container_offset", "bytes", "sha256", "bitcode_header"):
        if requested.get(key) != extracted["edge"][key]:
            fail("embedded_edge_mismatch", "embedded section identity/range/hash differs", field=key)
    bitcode = check_artifact(record.get("bitcode", {}))
    if (bitcode["sha256"], bitcode["bytes"]) != (extracted["edge"]["sha256"], extracted["edge"]["bytes"]):
        fail("bitcode_byte_mismatch", "saved bitcode is not the original embedded byte slice")
    return {"compiler_invocation_id": compiler_event["id"],
            "cargo_parent_invocation_id": compiler_event["cargo_parent_invocation_id"],
            "bitcode": bitcode, **extracted}


def effective_sysroot(event: dict) -> dict:
    argv = event.get("expanded_argv", event.get("argv", []))
    if not isinstance(argv, list) or not all(isinstance(arg, str) for arg in argv):
        fail("invalid_evidence", "compiler argv must be an exact string array")
    explicit = []
    for index, arg in enumerate(argv):
        if arg == "--sysroot":
            if index + 1 >= len(argv):
                fail("sysroot_missing", "original compiler --sysroot has no operand")
            explicit.append(argv[index + 1])
        elif arg.startswith("--sysroot="):
            explicit.append(arg.split("=", 1)[1])
    if len(explicit) > 1:
        fail("ambiguous_sysroot", "multiple --sysroot arguments require an explicit producer resolution")
    selected = explicit[0] if explicit else event.get("frontend", {}).get("default_sysroot")
    if not isinstance(selected, str) or not selected:
        fail("sysroot_missing", "actual producer sysroot query/argument is absent; stage/env labels are insufficient")
    root = Path(selected)
    if not root.is_absolute():
        cwd = event.get("cwd")
        if not isinstance(cwd, str) or not Path(cwd).is_absolute():
            fail("sysroot_missing", "relative --sysroot lacks its original absolute compiler cwd")
        root = Path(cwd) / root
    return {"path": str(root.absolute()), "source": "original_argv" if explicit else "actual_producer_query",
            "artifact_membership_complete": False}


def ordered_link_paths(trace_artifact: dict, cwd: str) -> list[str]:
    """Decode the original linker's first Make dependency rule, in order."""
    check_artifact(trace_artifact)
    if not isinstance(cwd, str) or not Path(cwd).is_absolute():
        fail("invalid_evidence", "linker cwd must be an original absolute path")
    try:
        lines = Path(trace_artifact["path"]).read_text().replace("\\\n", " ").splitlines()
    except (OSError, UnicodeError) as error:
        fail("malformed_link_trace", str(error))
    if not lines:
        fail("malformed_link_trace", "empty original linker dependency trace")
    text, escaped, colon = lines[0], False, None
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            colon = index
            break
    if colon is None:
        fail("malformed_link_trace", "linker dependency trace lacks its target separator")
    paths, word, escaped = [], [], False
    for char in text[colon + 1:]:
        if escaped:
            word.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char.isspace():
            if word:
                paths.append("".join(word).replace("$$", "$")); word = []
        else:
            word.append(char)
    if escaped:
        fail("malformed_link_trace", "unterminated linker dependency escape")
    if word:
        paths.append("".join(word).replace("$$", "$"))
    return [str((Path(cwd) / path).absolute()) for path in paths]


def verify_payload(evidence_path: Path, *, expected_capture_worker_sha256: str,
                   expected_observer_worker_sha256: str) -> dict:
    """Verify bounded raw graph edges; retain every missing provider as a gap.

    Input references the original capture/observer artifacts, not a caller's
    replacement normalized graph. Externally trusted worker hashes are required.
    The receipt deliberately does not become a full unit inventory or establish
    complete source production merely because all requested edges were present.
    """
    result = {"schema": RECEIPT_SCHEMA, "verified": False, "complete": False,
              "source_capture_qualified": False, "source_production_inventory_complete": False,
              "runtime_output_membership_complete": False, "dependency_closure_complete": False,
              "ocore_lowering_complete": False, "native_execution_qualified": False,
              "runtime_complete": False, "post_lto_native_equivalence_verified": False,
              "scope": "hash-bound-original-Cargo/compiler/embedded-byte/ordered-link-edges",
              "compiler_contexts": [], "embedded_edges": [], "ordered_inputs": [],
              "unresolved_providers": [], "gaps": []}

    def gap(error: PayloadError, **where):
        result["gaps"].append({**error.record(), **where})

    try:
        for digest in (expected_capture_worker_sha256, expected_observer_worker_sha256):
            if not isinstance(digest, str) or not SHA256.fullmatch(digest):
                fail("trusted_worker_required", "externally trusted capture and observer SHA-256 values are required")
        evidence = file_info(evidence_path)
        result["evidence"] = evidence
        spec = json_artifact(evidence)
        if not isinstance(spec, dict) or spec.get("schema") != EVIDENCE_SCHEMA:
            fail("invalid_evidence", "unsupported Rust payload evidence schema")
        if set(spec) - {"schema", "capture_report", "capture_session", "observer_verification", "roots"}:
            fail("invalid_evidence", "unknown payload evidence fields cannot supply missing producer edges")
        report = json_artifact(spec.get("capture_report", {}))
        session = json_artifact(spec.get("capture_session", {}))
        observer = json_artifact(spec.get("observer_verification", {}))
        if report.get("schema") != "ocore-runtime-capture-v1" or observer.get("schema") != "ocore-cargo-observer-verification-v1":
            fail("invalid_evidence", "payload input must retain the original capture/observer schemas")
        capture_worker = session.get("capture_worker", {})
        capture_artifact = capture_worker.get("artifact", {})
        check_artifact(capture_artifact)
        if capture_artifact.get("sha256") != expected_capture_worker_sha256 or report.get("capture_worker") != capture_worker:
            fail("capture_worker_mismatch", "capture differs from the externally trusted original worker")
        observer_session_artifact = observer.get("session", {})
        observer_session = json_artifact(observer_session_artifact)
        observer_worker = observer_session.get("observer_worker", {})
        check_artifact(observer_worker)
        if observer_worker.get("sha256") != expected_observer_worker_sha256 or observer.get("trusted_worker_sha256") != expected_observer_worker_sha256:
            fail("observer_worker_mismatch", "Cargo observer differs from externally trusted worker")
        if observer_session.get("source_capture_worker") != capture_worker:
            fail("observer_capture_mismatch", "observer belongs to a different original source capture")
        if observer.get("observer_errors"):
            fail("observer_errors", "original Cargo observer retains errors", errors=observer["observer_errors"])
        result["inputs"] = {key: spec[key] for key in ("capture_report", "capture_session", "observer_verification")}
        result["trusted_workers"] = {"capture": capture_artifact, "observer": observer_worker}
        events = {}
        capture_directory = Path(spec["capture_session"]["path"]).parent
        capture_namespace = trusted_namespace(capture_artifact, expected_capture_worker_sha256)
        required_apis = {"verify_worker", "validate_recipe", "verify_source", "make_report"}
        if not required_apis <= capture_namespace.keys():
            fail("worker_api_missing", "trusted capture worker lacks bounded readmission APIs")
        readmission_call(capture_namespace["verify_worker"], session, capture_directory, expected_capture_worker_sha256)
        original_recipe = json_artifact(session.get("manifest", {}))
        readmission_call(capture_namespace["validate_recipe"], original_recipe)
        if original_recipe != session.get("recipe"):
            fail("capture_recipe_mismatch", "original capture recipe differs from its finalized journal")
        readmission_call(capture_namespace["verify_source"], original_recipe, Path(session["source"]["path"]))
        for tool in [*session.get("tools", {}).values(), *session.get("native_tools", {}).values()]:
            check_artifact(tool)
            if tool.get("executing_binary"):
                check_artifact(tool["executing_binary"])
        # Reconstruct the complete diagnostic report without demanding a unit
        # inventory that this pre-qualification edge step cannot yet establish.
        rebuilt = readmission_call(capture_namespace["make_report"], capture_directory, persist=False,
            expected_worker_sha256=expected_capture_worker_sha256)
        if rebuilt != report:
            fail("capture_reconstruction_mismatch", "original capture report cannot be reconstructed from its bound evidence")
        observer_namespace = trusted_namespace(observer_worker, expected_observer_worker_sha256)
        if "verify" not in observer_namespace:
            fail("worker_api_missing", "trusted observer lacks independent child-set readmission")
        actual_observer = readmission_call(observer_namespace["verify"], Path(observer_session_artifact["path"]).parent,
            expected_worker_sha256=expected_observer_worker_sha256)
        if actual_observer != observer:
            fail("observer_reconstruction_mismatch", "observer receipt differs from original worker readmission")
        raw_paths = sorted((capture_directory / "events").glob("*.json"))
        for raw_path in raw_paths:
            raw_artifact = file_info(raw_path)
            raw = json_artifact(raw_artifact)
            event_id = raw.get("id")
            if not isinstance(event_id, str) or not event_id or event_id in events:
                fail("duplicate_invocation", "raw capture invocation IDs are missing/duplicated")
            if raw.get("capture_worker") != capture_artifact:
                fail("child_worker_mismatch", "original child journal has unbound/different worker", invocation_id=event_id)
            events[event_id] = {"journal": raw_artifact, "event": raw}
        reported = report.get("invocations")
        if not isinstance(reported, list) or any(not isinstance(row, dict) for row in reported):
            fail("invalid_evidence", "original capture report needs every invocation record")
        reported_ids = [row.get("id") for row in reported]
        if len(set(reported_ids)) != len(reported_ids) or set(reported_ids) != set(events):
            fail("capture_inventory_mismatch", "report dropped/added/duplicated original child journals")
        for row in reported:
            if row != events[row["id"]]["event"]:
                fail("capture_inventory_mismatch", "report rewrites an original child journal", invocation_id=row["id"])
        parents, child_anchors = {}, {}
        for item in observer.get("events", []):
            parent_artifact = item.get("event", {})
            parent = json_artifact(parent_artifact)
            parent_id = parent.get("id")
            if not isinstance(parent_id, str) or not parent_id or parent_id in parents:
                fail("duplicate_parent", "original Cargo parent IDs are missing/duplicated")
            if parent.get("observer_worker") != observer_worker or parent.get("source_capture_worker") != capture_worker:
                fail("parent_worker_mismatch", "Cargo parent worker binding differs from original session")
            if parent.get("upstream_exit_code") != 0 or parent.get("capture_errors"):
                fail("parent_incomplete", "original Cargo parent failed or retains capture errors", parent_id=parent_id)
            if item.get("parent_argv") != parent.get("argv") or item.get("upstream_exit_code") != parent.get("upstream_exit_code"):
                fail("parent_receipt_mismatch", "observer receipt rewrites original parent command/status")
            children = parent.get("compiler_children")
            if not isinstance(children, list):
                fail("final_child_inventory_missing", "Cargo parent has no exact final compiler-child journal inventory", parent_id=parent_id)
            for child in children:
                child_id = child.get("capture_invocation_id")
                if child_id in child_anchors:
                    fail("duplicate_child_anchor", "compiler child is owned by multiple Cargo parent records", invocation_id=child_id)
                child_artifact = child.get("capture_event", {})
                receipt = json_artifact(child.get("receipt", {}))
                if set(receipt) != {"schema", "cargo_parent_invocation_id", "capture_invocation_id", "capture_event",
                                    "observer_session", "source_capture_worker"} or receipt != {
                        "schema": "ocore-cargo-compiler-child-v1", "cargo_parent_invocation_id": parent_id,
                        "capture_invocation_id": child_id, "capture_event": child_artifact,
                        "observer_session": observer_session_artifact, "source_capture_worker": capture_artifact}:
                    fail("child_receipt_mismatch", "compiler child receipt has a wrong owner/schema/hash binding")
                raw = json_artifact(child_artifact)
                if child_id not in events or identity(child_artifact) != identity(events[child_id]["journal"]) or raw != events[child_id]["event"]:
                    fail("child_anchor_mismatch", "parent's finalized compiler journal differs from the original capture", invocation_id=child_id)
                child_anchors[child_id] = parent_id
            parents[parent_id] = {"journal": parent_artifact, "event": parent}
        if not parents:
            fail("cargo_parent_missing", "no original Cargo parent commands were observed")
    except (PayloadError, OSError, ValueError, TypeError, KeyError) as error:
        gap(error if isinstance(error, PayloadError) else PayloadError("invalid_evidence", str(error)))
        return result

    for event_id, entry in events.items():
        event = entry["event"]
        if event.get("kind") != "rustc" or event.get("translation_required") is not True:
            continue
        try:
            parent_id = event.get("cargo_parent_invocation_id")
            if parent_id not in parents or child_anchors.get(event_id) != parent_id:
                fail("cargo_parent_missing", "compiler lacks its exact finalized Cargo parent anchor")
            binding = event.get("cargo_parent", {})
            if binding != {"id": parent_id, "observer_session": observer_session_artifact,
                           "observer_worker": observer_worker, "source_capture_worker": capture_artifact}:
                fail("cargo_parent_binding_mismatch", "child's original observer/session/source-worker binding differs")
            if event.get("state") != "finished" or event.get("exit_code") != 0 or event.get("capture_errors"):
                fail("compiler_incomplete", "original Rust compiler invocation failed or retains capture errors")
            producer = event.get("frontend", {}).get("executing_binary")
            if not isinstance(producer, dict):
                fail("actual_producer_missing", "actual compiler binary is absent; stage labels cannot identify its generation")
            check_artifact(producer)
            context = {"invocation_id": event_id, "journal": entry["journal"], "parent_id": parent_id,
                       "parent_journal": parents[parent_id]["journal"], "producer": producer,
                       "sysroot": effective_sysroot(event), "argv": event.get("expanded_argv", event.get("argv")),
                       "reported_stage": event.get("build_environment", {}).get("RUSTC_STAGE")}
            result["compiler_contexts"].append(context)
            records = event.get("saved_cgus")
            if not isinstance(records, list) or not records:
                fail("embedded_edge_missing", "original producer supplied no saved/embedded native bitcode edge")
            seen = set()
            for index, record in enumerate(records):
                try:
                    edge = verify_saved_cgu(record, event)
                    key = (identity(record["object"]), identity(record["bitcode"]), edge["edge"]["section_index"])
                    if key in seen:
                        fail("duplicate_cgu_edge", "duplicate saved CGU edge cannot increase payload coverage")
                    seen.add(key)
                    result["embedded_edges"].append({"journal": entry["journal"], **edge})
                except (PayloadError, OSError, ValueError, TypeError, KeyError) as error:
                    gap(error if isinstance(error, PayloadError) else PayloadError("invalid_evidence", str(error)),
                        invocation_id=event_id, saved_cgu_index=index)
        except (PayloadError, OSError, ValueError, TypeError, KeyError) as error:
            gap(error if isinstance(error, PayloadError) else PayloadError("invalid_evidence", str(error)), invocation_id=event_id)

    roots = spec.get("roots")
    if not isinstance(roots, list) or not roots:
        gap(PayloadError("payload_roots_missing", "explicit final payload roots are required"))
        return result
    output_producers = {}
    for event_id, entry in events.items():
        for output in entry["event"].get("outputs", []):
            output_producers.setdefault(identity(output), []).append(event_id)
    embedded_outputs = set()
    for edge in result["embedded_edges"]:
        embedded_outputs.add(identity(edge["container"]))
    pending, visited = [], set()
    for root in roots:
        try:
            artifact = root.get("artifact", root)
            check_artifact(artifact)
            candidates = output_producers.get(identity(artifact), [])
            selected = root.get("producer_invocation_id")
            if selected is None:
                if len(candidates) != 1:
                    fail("root_producer_ambiguous", "final root needs one exact observed producer", candidates=candidates)
                selected = candidates[0]
            if selected not in candidates:
                fail("root_producer_missing", "selected final root producer did not produce those exact bytes")
            pending.append((selected, artifact))
        except (PayloadError, OSError, ValueError, TypeError, KeyError) as error:
            gap(error if isinstance(error, PayloadError) else PayloadError("invalid_evidence", str(error)), root=root)
    while pending:
        event_id, artifact = pending.pop()
        key = event_id, identity(artifact)
        if key in visited:
            continue
        visited.add(key)
        event = events[event_id]["event"]
        try:
            if event.get("state") != "finished" or event.get("exit_code") != 0 or event.get("capture_errors"):
                fail("native_producer_incomplete", "final artifact producer failed or retains capture errors")
            trace = event.get("native_linkage")
            if not isinstance(trace, dict) or event.get("kind") != "linker":
                if identity(artifact) in embedded_outputs:
                    # This only proves the recorded embedded CGUs. Archive
                    # metadata/other members are retained below as gaps.
                    with Path(artifact["path"]).open("rb") as stream:
                        is_archive = stream.read(8) == b"!<arch>\n"
                    if is_archive:
                        with mapped_artifact(artifact) as data:
                            members = archive_members(data)
                        owned = {(edge["member"]["index"], edge["member"]["sha256"])
                                 for edge in result["embedded_edges"] if edge["member"] is not None
                                 and identity(edge["container"]) == identity(artifact)}
                        for member in members:
                            if (member["index"], member["sha256"]) not in owned:
                                result["unresolved_providers"].append({"artifact": artifact, "member": member,
                                    "reason": "archive member has no independently verified original embedded-BC edge"})
                    continue
                fail("ordered_native_trace_missing", "final native artifact lacks an actual observed ordered linker trace")
            if trace.get("complete") is not True or trace.get("issues"):
                fail("ordered_native_trace_incomplete", "actual native linker retained incomplete trace evidence")
            providers = trace.get("providers")
            if not isinstance(providers, list):
                fail("ordered_native_trace_missing", "native linker provider order is absent")
            dependency_trace = trace.get("dependency_trace", {})
            order = ordered_link_paths(dependency_trace, event.get("cwd"))
            actual_order = [provider.get("original", {}).get("path") for provider in providers]
            if order != actual_order:
                fail("ordered_provider_mismatch", "provider order differs from original linker dependency bytes", original=order, claimed=actual_order)
            check_artifact(trace.get("archive_trace", {}))
            checked = []
            for index, provider in enumerate(providers):
                original, snapshot = provider.get("original", {}), provider.get("snapshot", {})
                check_artifact(snapshot)
                if any(original.get(field) != snapshot.get(field) for field in ("sha256", "bytes")):
                    fail("native_provider_mismatch", "preserved linker input differs from the original input bytes", provider_index=index)
                candidates = output_producers.get(identity(original), [])
                checked.append({"index": index, "original": original, "snapshot": snapshot,
                                "producer_candidates": candidates})
                if len(candidates) == 1:
                    pending.append((candidates[0], original))
                else:
                    result["unresolved_providers"].append({"linker_invocation_id": event_id,
                        "provider_index": index, "original": original, "snapshot": snapshot,
                        "producer_candidates": candidates, "reason": "missing or ambiguous original source producer"})
            result["ordered_inputs"].append({"invocation_id": event_id, "journal": events[event_id]["journal"],
                "output": artifact, "dependency_trace": dependency_trace, "archive_trace": trace["archive_trace"],
                "providers": checked, "archive_extraction_selection_verified": False})
        except (PayloadError, OSError, ValueError, TypeError, KeyError) as error:
            gap(error if isinstance(error, PayloadError) else PayloadError("invalid_evidence", str(error)), invocation_id=event_id)
    if not result["embedded_edges"]:
        gap(PayloadError("embedded_edge_missing", "no original Rust embedded bitcode byte edge was verified"))
    if result["unresolved_providers"]:
        gap(PayloadError("unresolved_native_providers", "all unresolved original archive/provider occurrences remain in the receipt"))
    result["verified"] = not result["gaps"]
    result["counts"] = {"original_child_journals": len(events), "original_cargo_parents": len(parents),
                        "compiler_contexts": len(result["compiler_contexts"]),
                        "embedded_edges": len(result["embedded_edges"]), "ordered_linkers": len(result["ordered_inputs"]),
                        "unresolved_providers": len(result["unresolved_providers"])}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--expected-capture-worker-sha256", required=True)
    parser.add_argument("--expected-observer-worker-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify_payload(args.evidence, expected_capture_worker_sha256=args.expected_capture_worker_sha256,
                            expected_observer_worker_sha256=args.expected_observer_worker_sha256)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(args.output), "verified": result["verified"],
                      "counts": result.get("counts", {}), "gaps": len(result["gaps"]),
                      "complete": False, "runtime_complete": False}))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
