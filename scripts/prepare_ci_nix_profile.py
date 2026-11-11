#!/usr/bin/env python3
"""Prepare the original Nix examples' pinned source and local daemon profile.

This is CI preparation, not a replacement Nix backend. Successful qualification
requires the installed Nix client, its daemon, the complete original Nixpkgs
archive, and readable bytes actually materialized in the local /nix/store.
The CI helper requires tarfile.data_filter (Python 3.12+ or a backport); this
tool prerequisite does not change the project's recipient Python floor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
from typing import BinaryIO
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / "ci/nix-example-profile.json"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
PROBE_BYTES = b"OSTADIX CI Nix local daemon materialization\n"


def load_pin(path: Path) -> dict:
    pin = json.loads(path.read_text(encoding="utf-8"))
    revision = pin.get("revision", "")
    if (
        pin.get("schema") != "ostadix.ci-nix-example-profile/v1"
        or pin.get("repository") != "https://github.com/NixOS/nixpkgs"
        or not re.fullmatch(r"[0-9a-f]{40}", revision)
        or pin.get("archive_url")
        != f"https://codeload.github.com/NixOS/nixpkgs/tar.gz/{revision}"
        or not re.fullmatch(r"[0-9a-f]{64}", pin.get("archive_sha256", ""))
        or type(pin.get("archive_bytes")) is not int
        or not 0 < pin["archive_bytes"] <= MAX_ARCHIVE_BYTES
        or not re.fullmatch(r"[0-9]{2}\.[0-9]{2}", pin.get("nixpkgs_version", ""))
        or pin.get("store") != "daemon"
    ):
        raise ValueError("invalid immutable official Nixpkgs/local daemon profile")
    return pin


def copy_verified_archive(stream: BinaryIO, destination: Path, pin: dict) -> None:
    """Bound the download and validate its identity before any extraction."""
    digest = hashlib.sha256()
    size = 0
    created = False
    try:
        with destination.open("xb") as output:
            created = True
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > pin["archive_bytes"]:
                    raise ValueError("Nixpkgs archive exceeds pinned size")
                digest.update(chunk)
                output.write(chunk)
        if size != pin["archive_bytes"] or digest.hexdigest() != pin["archive_sha256"]:
            raise ValueError("Nixpkgs archive identity mismatch")
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def extract_archive(archive: Path, destination: Path, revision: str) -> Path:
    expected_root = f"nixpkgs-{revision}"
    destination.mkdir()
    with tarfile.open(archive, "r:gz") as source:
        # Inspect names before extraction; Python's data filter also checks link
        # destinations, forbids devices, and prevents writes outside this root.
        for member in source:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != expected_root:
                raise ValueError("Nixpkgs archive member escapes its pinned root")
        source.extractall(destination, filter="data")
    source_root = (destination / expected_root).resolve(strict=True)
    if not (source_root / "default.nix").is_file():
        raise ValueError("original Nixpkgs default.nix is absent")
    return source_root


def verify_store_bytes(store_path: str, expected: bytes) -> dict:
    if not re.fullmatch(r"/nix/store/[0-9a-z]{32}-ostadix-ci-profile\.txt", store_path):
        raise ValueError("Nix toFile returned an unexpected local store path")
    raw = Path(store_path).read_bytes()
    if raw != expected:
        raise ValueError("Nix local-store preflight bytes differ")
    return {"path": store_path, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def run_command(argv: list[str], env: dict[str, str], report: dict) -> str:
    record = {"argv": argv}
    report["commands"].append(record)
    result = subprocess.run(argv, env=env, cwd=ROOT, capture_output=True, text=True, timeout=180)
    record.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"Nix profile command failed: {argv!r}: {result.stderr}")
    return result.stdout.strip()


def prepare(work_dir: Path, pin: dict, report: dict) -> dict[str, str]:
    if not hasattr(tarfile, "data_filter"):
        raise RuntimeError("CI Nix preparation requires tarfile.data_filter (Python 3.12+ or backport)")
    # The caller must supply a fresh runner-owned directory, outside Cargo cache.
    work_dir.mkdir(parents=True, exist_ok=False)
    work_dir = work_dir.resolve(strict=True)
    if any(character in str(work_dir) for character in "\r\n:"):
        raise ValueError("Nix search path cannot contain newline or colon")
    archive = work_dir / "nixpkgs.tar.gz"
    with urlopen(pin["archive_url"], timeout=60) as response:
        copy_verified_archive(response, archive, pin)
    report["verified_archive"] = {
        "url": pin["archive_url"], "sha256": pin["archive_sha256"],
        "bytes": archive.stat().st_size,
    }
    nixpkgs = extract_archive(archive, work_dir / "source", pin["revision"])
    report["nixpkgs_source"] = str(nixpkgs)
    executable_name = shutil.which("nix")
    if executable_name is None:
        raise RuntimeError("required installed Nix executable is absent")
    executable = Path(executable_name).resolve(strict=True)
    raw = executable.read_bytes()
    report["nix_client"] = {
        "executable": str(executable), "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    exports = {"NIX_REMOTE": "daemon", "NIX_PATH": f"nixpkgs={nixpkgs}"}
    # Refuse inherited store/config overrides that would make the claimed local
    # daemon profile ambiguous. Ordinary non-Nix environment is preserved.
    overrides = sorted(key for key in os.environ if key.startswith("NIX_") and key not in exports)
    if overrides:
        raise ValueError(f"unexpected inherited Nix profile overrides: {overrides}")
    env = dict(os.environ, **exports)
    nix = [str(executable), "--extra-experimental-features", "nix-command"]
    report["nix_client"]["version"] = run_command([str(executable), "--version"], env, report)
    resolved = run_command(nix + ["eval", "--raw", "--impure", "--expr", "builtins.toString <nixpkgs>"], env, report)
    if resolved != str(nixpkgs):
        raise ValueError("NIX_PATH resolved outside the verified original source")
    version = run_command(nix + ["eval", "--raw", "--impure", "--expr", 'builtins.readFile (<nixpkgs> + "/.version")'], env, report)
    if version != pin["nixpkgs_version"]:
        raise ValueError("pinned original Nixpkgs version differs")
    expression = 'builtins.toFile "ostadix-ci-profile.txt" ' + json.dumps(PROBE_BYTES.decode())
    store_path = run_command(nix + ["eval", "--raw", "--impure", "--expr", expression], env, report)
    valid_path = run_command(nix + ["path-info", store_path], env, report)
    if valid_path != store_path:
        raise ValueError("Nix daemon did not validate the exact preflight store path")
    report["materialized_preflight"] = verify_store_bytes(store_path, PROBE_BYTES)
    # Instantiate the same original package used by the unchanged example.
    # The example itself remains responsible for realise/build qualification.
    drv = run_command(nix + ["eval", "--raw", "--impure", "--expr", "(import <nixpkgs> {}).hello.drvPath"], env, report)
    if not re.fullmatch(r"/nix/store/[0-9a-z]{32}-[^/\r\n]+\.drv", drv):
        raise ValueError("original Nixpkgs hello did not produce a derivation")
    report["hello_derivation"] = drv
    return exports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin", type=Path, default=PIN)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    args = parser.parse_args(argv)
    report = {"schema": "ostadix.ci-nix-example-evidence/v1", "status": "failed", "commands": []}
    try:
        pin = load_pin(args.pin)
        report["pin"] = pin
        report["pin_sha256"] = hashlib.sha256(args.pin.read_bytes()).hexdigest()
        report["source_sha"] = run_command(["git", "rev-parse", "HEAD"], dict(os.environ), report)
        if report["source_sha"] != os.environ["GITHUB_SHA"]:
            raise ValueError("checkout differs from the requested CI source SHA")
        exports = prepare(args.work_dir, pin, report)
        # Export only after every preflight passed. Subsequent original example
        # processes receive this exact local daemon and immutable source profile.
        with args.github_env.open("a", encoding="utf-8") as stream:
            for key, value in exports.items():
                stream.write(f"{key}={value}\n")
        report["exports"] = exports
        report["status"] = "prepared-original-nix-local-daemon-profile"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
        print(report["error"], file=sys.stderr)
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
