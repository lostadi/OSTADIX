#!/usr/bin/env python3
"""Acquire source-backed Rust stage observations without replaying build commands.

Original compiler attempts and current Cargo fingerprints stay separate from
parent Cargo commands and configured unit graphs. Neither directory names nor
RUSTC_STAGE alone establish a producer generation or payload role.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class Evidence:
    def __init__(self, directory: Path):
        self.directory = directory.absolute()
        self.directory.mkdir(parents=True, exist_ok=False)
        self.inputs: list[dict] = []
        self.gaps: list[dict] = []
        self.cache: dict[str, tuple[bytes, dict]] = {}

    def read(self, path: Path) -> tuple[bytes, dict]:
        key = str(path.absolute())
        if key in self.cache:
            return self.cache[key]
        before = path.stat()
        raw = path.read_bytes()
        after = path.stat()
        stable = (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        digest = sha(raw)
        saved = self.directory / digest
        if not saved.exists():
            with saved.open("xb") as stream:
                stream.write(raw)
            saved.chmod(0o444)
        elif sha(saved.read_bytes()) != digest:
            raise ValueError("retained stage evidence changed")
        artifact = {"path": key, "sha256": digest, "bytes": len(raw),
                    "snapshot_path": str(saved), "stable_during_read": stable}
        self.inputs.append(artifact)
        self.cache[key] = raw, artifact
        if not stable:
            self.gaps.append({"kind": "metadata_changed_during_read", "artifact": artifact})
        return raw, artifact

    def json(self, path: Path) -> tuple[object | None, dict]:
        try:
            raw, artifact = self.read(path)
            return json.loads(raw), artifact
        except (OSError, ValueError, UnicodeError) as error:
            artifact = {"path": str(path.absolute())}
            self.gaps.append({"kind": "unavailable_or_malformed_metadata", "artifact": artifact,
                              "error": str(error)})
            return None, artifact


def reference(artifact: dict, **detail) -> dict:
    return {"artifact_sha256": artifact.get("sha256"), **detail}


def arguments(argv: list[str]) -> dict:
    result: dict[str, list[str]] = {}
    paired = {"--crate-name", "--crate-type", "--target", "--out-dir", "--cfg", "-C", "--extern"}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in paired:
            if i + 1 < len(argv):
                result.setdefault(arg, []).append(argv[i + 1])
                i += 1
            else:
                result.setdefault("malformed_flags", []).append(arg)
        elif any(arg.startswith(flag + "=") for flag in paired if flag != "-C"):
            flag, value = arg.split("=", 1)
            result.setdefault(flag, []).append(value)
        elif arg.startswith("-C") and len(arg) > 2:
            result.setdefault("-C", []).append(arg[2:])
        i += 1
    return result


def event_features(parsed: dict) -> list[str]:
    values = []
    for cfg in parsed.get("--cfg", []):
        if cfg.startswith("feature="):
            try:
                value = json.loads(cfg[len("feature="):])
            except ValueError:
                continue
            if isinstance(value, str):
                values.append(value)
    return values


def fingerprint_candidates(event: dict, parsed: dict, evidence: Evidence,
                           directory_indexes: dict) -> list[dict]:
    environment = event.get("build_environment") or {}
    target_directory = environment.get("CARGO_TARGET_DIR")
    suffixes = [flag.removeprefix("extra-filename=").removeprefix("-")
                for flag in parsed.get("-C", []) if flag.startswith("extra-filename=")]
    if not target_directory or len(suffixes) != 1 or not re.fullmatch(r"[0-9a-f]+", suffixes[0]):
        return []
    root = Path(target_directory)
    key = str(root.absolute())
    if key not in directory_indexes:
        paths = list(root.glob("**/.fingerprint/*/*.json")) if root.is_dir() else []
        index: dict[str, list[Path]] = {}
        for path in paths:
            index.setdefault(path.parent.name.rsplit("-", 1)[-1], []).append(path)
        directory_indexes[key] = index
    candidates = []
    outdirs = parsed.get("--out-dir", [])
    for path in sorted(directory_indexes[key].get(suffixes[0], [])):
        # A host proc macro/build script and a target crate can share a suffix.
        # Require the same profile/target branch, not just a matching basename.
        branch = path.parent.parent.parent
        branch_matches = len(outdirs) == 1 and Path(outdirs[0]).absolute().is_relative_to(branch.absolute())
        if not branch_matches:
            continue
        fingerprint, artifact = evidence.json(path)
        if not isinstance(fingerprint, dict):
            continue
        raw_features = fingerprint.get("features")
        try:
            features = json.loads(raw_features) if isinstance(raw_features, str) else raw_features
        except ValueError:
            features = None
        observed_features = event_features(parsed)
        features_match = (isinstance(features, list) and all(isinstance(v, str) for v in features)
                          and sorted(features) == sorted(observed_features))
        candidates.append({"record": reference(artifact), "path": str(path.absolute()),
            "match_evidence": {"extra_filename_hash": suffixes[0],
                "same_output_branch": branch_matches, "event_features": observed_features,
                "fingerprint_features": features, "features_match": features_match},
            "opaque_cargo_values": {field: fingerprint.get(field) for field in (
                "rustc", "target", "profile", "path", "config", "compile_kind")},
            "dependencies": fingerprint.get("deps", []),
            "rustflags": fingerprint.get("rustflags", []),
            "source_role_proven": False, "configured_unit_graph_proven": False})
    return candidates


CONSTRUCTORS = {
    "src/bootstrap/src/lib.rs": ["let local_version_verbose", "if local_release.split", "fn stage_out"],
    "src/bootstrap/src/core/builder/cargo.rs": ["pub fn bare_cargo", "fn cargo(",
        "let build_compiler_stage", '.env("RUSTC_REAL"', '.env("RUSTC_STAGE"'],
    "src/bootstrap/src/core/build_steps/compile.rs": ["pub fn rustc_cargo", "fn stream_cargo"],
    "src/bootstrap/src/core/build_steps/tool.rs": [],
}


def acquire(source: Path, capture: Path, output: Path, metadata: list[Path] | None = None) -> dict:
    if output.exists():
        raise FileExistsError("stage observation output must be new")
    evidence = Evidence(output.with_suffix(output.suffix + ".evidence"))
    constructors = []
    for relative, anchors in CONSTRUCTORS.items():
        path = source / relative
        try:
            raw, artifact = evidence.read(path)
        except OSError as error:
            evidence.gaps.append({"kind": "source_constructor_unavailable", "path": str(path),
                                  "error": str(error)})
            continue
        lines = raw.decode().splitlines()
        constructors.append({"record": reference(artifact), "path": str(path.absolute()),
            "anchors": [{"text": anchor, "lines": [i + 1 for i, line in enumerate(lines) if anchor in line]}
                        for anchor in anchors],
            "scope": "original constructor bytes; not a captured parent command"})
    metadata_records = []
    for path in metadata or []:
        _, artifact = evidence.read(path)
        metadata_records.append(reference(artifact))
    groups: dict[str, dict] = {}
    attempts = []
    directory_indexes = {}
    for path in sorted((capture / "events").glob("*.json")):
        event, artifact = evidence.json(path)
        if not isinstance(event, dict) or event.get("kind") != "rustc":
            continue
        environment = event.get("build_environment") or {}
        frontend = event.get("frontend") or {}
        producer = frontend.get("executing_binary") or {k: frontend.get(k) for k in ("path", "sha256", "bytes")}
        dimensions = {"reported_rustc_stage": environment.get("RUSTC_STAGE"),
            "rustc_real": environment.get("RUSTC_REAL"), "producer": producer,
            "sysroot": environment.get("RUSTC_SYSROOT"),
            "cargo_target_directory": environment.get("CARGO_TARGET_DIR")}
        group_id = sha(json.dumps(dimensions, sort_keys=True, separators=(",", ":")).encode())
        group = groups.setdefault(group_id, {"id": group_id, **dimensions,
            "attempt_indices": [], "source_manifest_records": [],
            "original_parent_cargo_command_available": False,
            "configured_payload_unit_graph_available": False,
            "producer_dependency_closure_proven": False})
        argv = event.get("expanded_argv") or event.get("argv") or []
        parsed = arguments(argv)
        attempt = {"event_id": event.get("id"), "record": reference(artifact), "group_id": group_id,
            "classification": event.get("classification"), "exit_code": event.get("exit_code"),
            "build_step": event.get("build_step"), "argv_record": reference(artifact, pointer="/expanded_argv" if event.get("expanded_argv") else "/argv"),
            "environment_record": reference(artifact, pointer="/build_environment"),
            "parsed_arguments": parsed, "capture_errors": event.get("capture_errors", []),
            "fingerprint_candidates": fingerprint_candidates(event, parsed, evidence, directory_indexes)}
        matches = attempt["fingerprint_candidates"]
        if len(matches) > 1:
            evidence.gaps.append({"kind": "ambiguous_fingerprint_match", "event_id": event.get("id"),
                                  "candidates": [v["record"] for v in matches]})
        if any(not match["match_evidence"]["features_match"] for match in matches):
            evidence.gaps.append({"kind": "fingerprint_feature_mismatch", "event_id": event.get("id")})
        manifest_dir = environment.get("CARGO_MANIFEST_DIR")
        if manifest_dir:
            try:
                _, manifest = evidence.read(Path(manifest_dir) / "Cargo.toml")
                ref = reference(manifest)
                attempt["source_manifest_record"] = ref
                if ref not in group["source_manifest_records"]:
                    group["source_manifest_records"].append(ref)
            except OSError as error:
                evidence.gaps.append({"kind": "source_manifest_unavailable", "event_id": event.get("id"),
                                      "manifest_directory": manifest_dir, "error": str(error)})
        group["attempt_indices"].append(len(attempts))
        attempts.append(attempt)
    for group in groups.values():
        evidence.gaps.append({"kind": "original_parent_cargo_command_and_payload_unit_graph_missing",
            "group_id": group["id"], "scope": "child rustc argv/fingerprints do not recover complete parent Cargo argv, inherited environment, or configured unit graph"})
    return {"schema": "ocore-rust-stage-role-observation-v1",
        "producer": {"path": str(Path(__file__).absolute()), "sha256": sha(Path(__file__).read_bytes())},
        "source": str(source.absolute()), "capture": str(capture.absolute()),
        "source_constructors": constructors, "metadata_records": metadata_records,
        "input_artifacts": evidence.inputs, "groups": list(groups.values()), "attempts": attempts,
        "summary": {"rustc_attempts": len(attempts), "producer_groups": len(groups),
                    "classifications": dict(Counter(v.get("classification") for v in attempts)),
                    "attempts_with_fingerprint_candidates": sum(bool(v["fingerprint_candidates"]) for v in attempts)},
        "gaps": evidence.gaps, "scope": "hash-bound source and observed child-command evidence; no execution or inferred configured graph",
        "complete": False, "stage_roles_complete": False, "source_production_inventory_complete": False,
        "dependency_closure_complete": False, "ocore_lowering_complete": False,
        "native_execution_qualified": False, "runtime_complete": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = acquire(args.source, args.capture, args.output, args.metadata)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(args.output), **result["summary"],
                      "gaps": len(result["gaps"]), "runtime_complete": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
