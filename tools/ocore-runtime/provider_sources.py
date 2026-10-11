#!/usr/bin/env python3
"""Map observed native providers to exact source-package candidates.

This read-only diagnostic retains every occurrence and cold archive member. It
does not admit a package database assertion as source ownership, execute builds,
or count supplied native libraries as O-core-lowered dependencies. Source index
authentication belongs to the supplied source-index provenance receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def artifact(path: Path) -> dict:
    before = path.stat()
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    after = path.stat()
    return {"path": str(path.absolute()), "bytes": after.st_size,
            "sha256": h.hexdigest(), "stable_during_read":
            (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns)}


def read_input(path: Path) -> tuple[bytes, dict]:
    """Parse precisely the bytes whose digest is retained in the inventory."""
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    stable = (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if not stable:
        raise ValueError("source-candidate input changed during observation")
    return raw, {"path": str(path.absolute()), "bytes": len(raw),
                 "sha256": hashlib.sha256(raw).hexdigest(), "stable_during_read": True}


def deb822(text: str) -> list[dict]:
    """Keep source-index multiline checksum records without interpreting code."""
    result, current, field = [], {}, None
    for line in [*text.splitlines(), ""]:
        if not line.strip():
            if current:
                result.append(current)
            current, field = {}, None
        elif line.startswith((" ", "\t")):
            if field is None:
                raise ValueError("source metadata continuation has no field")
            current[field] += "\n" + line[1:]
        else:
            field, separator, value = line.partition(":")
            if not separator or not field or field in current:
                raise ValueError("malformed or duplicate source metadata field")
            current[field] = value.lstrip()
    return result


def source_archives(stanza: dict) -> list[dict]:
    result = []
    for line in stanza.get("Checksums-Sha256", "").splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 3:
            raise ValueError("malformed source archive SHA-256 metadata")
        sha, size, name = parts
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise ValueError("invalid source archive SHA-256")
        if Path(name).name != name or name in {".", ".."}:
            raise ValueError("source archive name is not a single filename")
        size = int(size)
        if size < 0:
            raise ValueError("source archive size is negative")
        result.append({"filename": name, "bytes": size, "sha256": sha,
                       "repository_path": stanza.get("Directory", "") + "/" + name})
    if not result:
        raise ValueError("source package lacks SHA-256 archive metadata")
    return result


def inventory(reports: list[Path], catalog_path: Path, metadata_paths: list[Path],
              archives_directory: Path | None = None,
              provenance_paths: list[Path] | None = None,
              observation_paths: list[Path] | None = None) -> dict:
    gaps, providers, inputs = [], {}, []
    for report_path, input_kind in [(path, "capture") for path in reports] + [
            (path, "hosted-loader-observation") for path in (observation_paths or [])]:
        raw, identity = read_input(report_path)
        report = json.loads(raw)
        if input_kind == "capture":
            if report.get("schema") != "ocore-runtime-capture-v1":
                raise ValueError("source candidates require a source-capture report")
            occurrences = report.get("native_linkage", {}).get("unowned_native_providers", [])
            prefix = "/native_linkage/unowned_native_providers/"
        else:
            if report.get("schema") != "ocore-hosted-native-provider-observation-v1":
                raise ValueError("hosted provider observation schema is unsupported")
            occurrences = report.get("providers", [])
            prefix = "/providers/"
        inputs.append(identity)
        for index, occurrence in enumerate(occurrences):
            original = occurrence.get("original") or occurrence.get("archive")
            if not original or not all(k in original for k in ("path", "sha256", "bytes")):
                gaps.append({"kind": "unidentified_provider", "report": identity,
                             "pointer": prefix + str(index)})
                continue
            key = (original["path"], original["sha256"], original["bytes"])
            entry = providers.setdefault(key, {"provider": original,
                "occurrences": [], "archive_members": [], "package_candidates": []})
            reference = {"artifact_sha256": identity["sha256"],
                         "pointer": prefix + str(index), "input_kind": input_kind,
                         "invocation_id": occurrence.get("invocation_id")}
            if "archive_member" in occurrence:
                reference["archive_member"] = occurrence["archive_member"]
            entry["occurrences"].append(reference)
            snapshot = occurrence.get("snapshot")
            if snapshot and "snapshot" not in entry:
                entry["snapshot"] = snapshot
            if "archive_member" in occurrence and occurrence["archive_member"] not in entry["archive_members"]:
                entry["archive_members"].append(occurrence["archive_member"])

    raw, catalog_identity = read_input(catalog_path)
    catalog = json.loads(raw)
    if catalog.get("schema") != "ocore-native-provider-package-candidates-v1":
        raise ValueError("package candidate catalog schema is unsupported")
    inputs.append(catalog_identity)
    packages = catalog.get("packages", [])
    source_metadata = {}
    for metadata_path in metadata_paths:
        raw, identity = read_input(metadata_path)
        inputs.append(identity)
        for index, stanza in enumerate(deb822(raw.decode())):
            if "Package" in stanza and "Version" in stanza:
                source_metadata.setdefault((stanza["Package"], stanza["Version"]), []).append(
                    {"metadata_artifact_sha256": identity["sha256"], "stanza_index": index,
                     "fields": stanza, "archives": source_archives(stanza)})
    sources = {}
    for entry in providers.values():
        expected = entry.get("snapshot") or entry["provider"]
        try:
            observed = artifact(Path(expected["path"]))
            matches = observed["stable_during_read"] and all(observed[k] == expected[k] for k in ("sha256", "bytes"))
            entry["observed"] = observed
            entry["provider_bytes_match_recorded"] = matches
        except OSError as error:
            matches = False
            entry["provider_bytes_match_recorded"] = False
            entry["observation_error"] = str(error)
        if not matches:
            gaps.append({"kind": "provider_bytes_unverified", "provider": entry["provider"]})
        for index, package in enumerate(packages):
            owned = [claim for claim in package.get("providers", [])
                     if claim.get("path") == entry["provider"]["path"]]
            if not owned:
                continue
            if any(claim.get("sha256") != entry["provider"]["sha256"] or
                   claim.get("bytes") != entry["provider"]["bytes"] for claim in owned):
                gaps.append({"kind": "package_provider_hash_mismatch", "package_index": index,
                             "provider": entry["provider"]})
                continue
            source = (package.get("source_package"), package.get("source_version"))
            candidate = {"catalog_artifact_sha256": catalog_identity["sha256"],
                         "pointer": f"/packages/{index}", "binary_package": package.get("binary_package"),
                         "binary_version": package.get("binary_version"), "source_package": source[0],
                         "source_version": source[1], "ownership_claims": owned,
                         "source_ownership_admitted": False}
            entry["package_candidates"].append(candidate)
            source_entry = sources.setdefault(source, {"package": source[0], "version": source[1],
                    "provider_identities": [], "metadata_candidates": source_metadata.get(source, []),
                    "source_implementation_lowered": False})
            source_entry["provider_identities"].append(entry["provider"])
        if not entry["package_candidates"]:
            gaps.append({"kind": "provider_has_no_package_source_candidate", "provider": entry["provider"],
                         "scope": "non-package source producers or unsupported package metadata remain explicit"})

    for source, entry in sources.items():
        if not entry["metadata_candidates"]:
            gaps.append({"kind": "exact_source_version_metadata_missing", "package": source[0], "version": source[1]})
        for metadata in entry["metadata_candidates"]:
            for archive in metadata["archives"]:
                if archives_directory is None:
                    archive["available_and_sha256_verified"] = False
                    continue
                path = archives_directory / archive["filename"]
                try:
                    observed = artifact(path)
                    archive["observed"] = observed
                    archive["available_and_sha256_verified"] = observed["stable_during_read"] and all(
                        archive[k] == observed[k] for k in ("sha256", "bytes"))
                except OSError as error:
                    archive["available_and_sha256_verified"] = False
                    archive["observation_error"] = str(error)
                if not archive["available_and_sha256_verified"]:
                    gaps.append({"kind": "source_archive_unavailable_or_mismatched", "archive": archive})

    provenance = [artifact(path) for path in (provenance_paths or [])]
    return {"schema": "ocore-native-provider-source-candidates-v1",
            "producer": artifact(Path(__file__)),
            "scope": "hash-bound diagnostic candidates; package claims and source-index provenance are not source/lowering admission",
            "input_artifacts": inputs, "source_index_provenance_inputs": provenance,
            "providers": list(providers.values()), "source_packages": list(sources.values()),
            "provider_occurrences": sum(len(entry["occurrences"]) for entry in providers.values()),
            "gaps": gaps, "complete": False, "source_provider_ownership_complete": False,
            "dependency_closure_complete": False, "ocore_lowering_complete": False,
            "native_execution_qualified": False, "runtime_complete": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, action="append", required=True)
    parser.add_argument("--package-catalog", type=Path, required=True)
    parser.add_argument("--source-metadata", type=Path, action="append", default=[])
    parser.add_argument("--source-archives", type=Path)
    parser.add_argument("--source-index-provenance", type=Path, action="append", default=[])
    parser.add_argument("--provider-observation", type=Path, action="append", default=[],
                        help="Explicit hosted loader observation; never an actual linker-capture receipt")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = inventory(args.report, args.package_catalog, args.source_metadata,
                       args.source_archives, args.source_index_provenance, args.provider_observation)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(args.output), "providers": len(report["providers"]),
                      "source_packages": len(report["source_packages"]),
                      "provider_occurrences": report["provider_occurrences"],
                      "gaps": len(report["gaps"]), "runtime_complete": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
