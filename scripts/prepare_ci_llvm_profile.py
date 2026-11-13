#!/usr/bin/env python3
"""Provision the declared LLVM22.1.6 subset for required hosted FP tests.

The whole official compressed archive is authenticated before streaming only
named members into a new prefix. This supplies upstream executables; it does
not lower them, capture their source build or make host dependencies hermetic.
The CLI accepts no alternate profile, digest, release or extraction policy.
"""
from __future__ import annotations

import argparse
import ctypes
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "ci/llvm-22.1.6-linux-x64.json"
ARCHIVE_SHA256 = "c5ac8ef89ca39d30cb32e9b83772f995dd891c685ebc188d593c943a64d5f8b5"
ARCHIVE_BYTES = 1937446204
CHUNK = 1024 * 1024


class ProfileError(RuntimeError):
    pass


def digest(stream):
    result = hashlib.sha256()
    for chunk in iter(lambda: stream.read(CHUNK), b""):
        result.update(chunk)
    return result.hexdigest()


@contextmanager
def open_regular_input(path, label="input"):
    """Hold one nonblocking, non-symlink regular-file descriptor before reads.

    NONBLOCK avoids waiting for a FIFO writer before fstat can reject its type.
    The held descriptor, rather than a reopened pathname, feeds authentication
    and archive decoding. Final-component aliases are refused here; declared
    SDK aliases are separately checked then resolved by identity().
    """
    descriptor = None
    error = label + " must be a regular file without symlinks"
    try:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
        except OSError as failure:
            if failure.errno in (errno.ELOOP, errno.ENXIO, errno.ENODEV, errno.EISDIR):
                raise ProfileError(error) from failure
            raise
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ProfileError(error)
        stream = os.fdopen(descriptor, "rb")
        descriptor = None  # stream now owns closure, including exceptional exits.
        with stream:
            yield stream
    finally:
        if descriptor is not None:
            os.close(descriptor)


def stream_identity(stream, path):
    before = os.fstat(stream.fileno())
    stream.seek(0)
    sha256 = digest(stream)
    after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, name) != getattr(after, name) for name in fields):
        raise ProfileError("regular input changed during authentication")
    return {"path": str(Path(path).resolve(strict=True)), "bytes": before.st_size, "sha256": sha256}


def identity(path):
    # Tool aliases are permitted only through their caller's declared alias
    # checks; even the resolved target must be regular before any payload read.
    path = Path(path).resolve(strict=True)
    with open_regular_input(path, "identity input") as stream:
        return stream_identity(stream, path)


def canonical(path):
    if (not isinstance(path, str) or not path or "\\" in path or "\x00" in path
            or "\n" in path or "\r" in path or path.startswith("/")
            or any(part in ("", ".", "..") for part in path.split("/"))
            or PurePosixPath(path).as_posix() != path):
        raise ProfileError("noncanonical archive/profile path")
    return path


def validate_profile(profile):
    if profile.get("schema") != "ostadix.ci-llvm-minimal-profile/v1":
        raise ProfileError("unsupported selection schema")
    canonical(profile["prefix"])
    members = profile["members"]
    if not members:
        raise ProfileError("empty required member set")
    for name, row in members.items():
        canonical(name)
        if row["kind"] not in ("regular", "symlink"):
            raise ProfileError("unsupported selected member type")
        if not isinstance(row["bytes"], int) or row["bytes"] < 0 or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            raise ProfileError("invalid selected member identity")
        if row["kind"] == "symlink":
            canonical(row["target"])
            target = (PurePosixPath(name).parent / row["target"]).as_posix()
            if target not in members or members[target]["kind"] != "regular":
                raise ProfileError("alias must name a selected regular member")
            if (row["bytes"], row["sha256"]) != (members[target]["bytes"], members[target]["sha256"]):
                raise ProfileError("alias target identity differs")
    return profile


def load_profile():
    with open_regular_input(PROFILE, "profile input") as stream:
        profile = validate_profile(json.loads(stream.read().decode("utf-8")))
    archive = profile["archive"]
    if (archive["size"] != ARCHIVE_BYTES or archive["digest"] != "sha256:" + ARCHIVE_SHA256
            or archive["name"] != "LLVM-22.1.6-Linux-X64.tar.xz"
            or archive["browser_download_url"] != "https://github.com/llvm/llvm-project/releases/download/llvmorg-22.1.6/LLVM-22.1.6-Linux-X64.tar.xz"
            or profile["version"] != "22.1.6"):
        raise ProfileError("official release identity changed")
    if (len(profile["members"]) != 315
            or len([p for p in profile["members"] if p.startswith("lib/clang/22/include/")]) != 305):
        raise ProfileError("required tool/resource membership changed")
    return profile


def verify_archive(stream, profile):
    before = os.fstat(stream.fileno())
    if not stat.S_ISREG(before.st_mode) or before.st_size != profile["archive"]["size"]:
        raise ProfileError("compressed archive size/type mismatch")
    expected = profile["archive"]["digest"].removeprefix("sha256:")
    stream.seek(0)
    if digest(stream) != expected:
        raise ProfileError("compressed archive SHA-256 mismatch")
    after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ProfileError("archive changed during authentication")
    stream.seek(0)
    return {"bytes": before.st_size, "sha256": expected}


def extract_selected(stream, prefix, profile):
    """Internal extraction primitive; CLI always supplies the fixed profile.

    Never calls tar.extract: directories and regular files are owned here;
    aliases are installed only after every named regular member is verified.
    """
    validate_profile(profile)
    prefix = Path(prefix)
    prefix.mkdir(parents=False, exist_ok=False)
    members, found, seen, records = profile["members"], set(), set(), []
    selected_total = sum(row["bytes"] for row in members.values() if row["kind"] == "regular")
    if shutil.disk_usage(prefix).free < selected_total + 128 * CHUNK:
        raise ProfileError("insufficient space for selected LLVM subset")
    with tarfile.open(fileobj=stream, mode="r|xz") as archive:
        for member in archive:
            name = member.name.rstrip("/") if member.isdir() else member.name
            canonical(name)
            if name in seen:
                raise ProfileError("duplicate archive member: " + name)
            seen.add(name)
            if name == profile["prefix"] and member.isdir():
                continue
            if not name.startswith(profile["prefix"] + "/"):
                raise ProfileError("archive member outside required root")
            relative = name[len(profile["prefix"]) + 1:]
            row = members.get(relative)
            if row is None:
                # Unselected symlinks/devices are never materialized or followed.
                continue
            destination = prefix / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if row["kind"] == "regular":
                if not member.isreg() or member.size != row["bytes"] or member.mode & 0o7000:
                    raise ProfileError("selected regular member type/size/mode mismatch: " + relative)
                source = archive.extractfile(member)
                if source is None:
                    raise ProfileError("selected member has no payload")
                result, count = hashlib.sha256(), 0
                with destination.open("xb") as output:
                    for chunk in iter(lambda: source.read(CHUNK), b""):
                        count += len(chunk)
                        if count > row["bytes"]:
                            raise ProfileError("oversized member payload")
                        output.write(chunk)
                        result.update(chunk)
                if count != row["bytes"] or result.hexdigest() != row["sha256"]:
                    raise ProfileError("selected member SHA-256 mismatch: " + relative)
                destination.chmod(0o755 if relative.startswith("bin/") else 0o644)
            else:
                if not member.issym() or member.linkname != row["target"] or member.size != 0:
                    raise ProfileError("selected alias type/target mismatch: " + relative)
            found.add(relative)
            records.append({"member": name, "kind": row["kind"],
                            "archive_bytes": member.size, "archive_mode": oct(member.mode),
                            "resolved_regular_bytes": row["bytes"],
                            "sha256": row["sha256"], "target": row.get("target")})
    missing = sorted(set(members) - found)
    if missing:
        raise ProfileError("missing selected archive members: " + ", ".join(missing))
    for name, row in members.items():
        if row["kind"] == "symlink":
            (prefix / name).symlink_to(row["target"])
    return sorted(records, key=lambda row: row["member"])


def verify_subset(prefix, profile):
    prefix = Path(prefix)
    actual = {path.relative_to(prefix).as_posix() for path in prefix.rglob("*") if not path.is_dir() or path.is_symlink()}
    if actual != set(profile["members"]):
        raise ProfileError("subset file membership mismatch")
    for name, row in profile["members"].items():
        path = prefix / name
        if row["kind"] == "symlink":
            if not path.is_symlink() or os.readlink(path) != row["target"]:
                raise ProfileError("subset alias changed: " + name)
        elif not path.is_file() or path.is_symlink():
            raise ProfileError("subset regular member changed: " + name)
        observed = identity(path)
        if (observed["bytes"], observed["sha256"]) != (row["bytes"], row["sha256"]):
            raise ProfileError("subset identity changed: " + name)


def download_archive(path, profile):
    path = Path(path)
    if path.exists() or path.is_symlink():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    need = profile["archive"]["size"] + sum(r["bytes"] for r in profile["members"].values() if r["kind"] == "regular") + 256 * CHUNK
    if shutil.disk_usage(path.parent).free < need:
        raise ProfileError("insufficient cold archive/subset headroom")
    handle, temporary = tempfile.mkstemp(prefix=path.name + ".partial-", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as output, urllib.request.urlopen(profile["archive"]["browser_download_url"], timeout=120) as response:
            count, observed = 0, hashlib.sha256()
            for chunk in iter(lambda: response.read(CHUNK), b""):
                count += len(chunk)
                if count > profile["archive"]["size"]:
                    raise ProfileError("download exceeds pinned archive size")
                observed.update(chunk)
                output.write(chunk)
        if count != profile["archive"]["size"] or observed.hexdigest() != ARCHIVE_SHA256:
            raise ProfileError("downloaded archive identity mismatch")
        # Link-to-absent does not overwrite a concurrently supplied archive.
        os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def command(argv, report, name):
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=120)
    report[name] = {"argv": list(map(str, argv)), "status": result.returncode,
                    "stdout": result.stdout.decode("utf-8", "replace"),
                    "stderr": result.stderr.decode("utf-8", "replace")}
    if result.returncode:
        raise ProfileError("required command failed: " + name)
    return result.stdout.decode("utf-8", "replace")


def inspect_tools(prefix, parser, rustc, profile, report):
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise ProfileError("this supplied SDK requires an x86-64 Linux host")
    dependencies = {}
    ldd = Path(shutil.which("ldd") or "/missing").resolve(strict=True)
    report["dependency_inspector"] = identity(ldd)
    for name in ("clang", "ld.lld", "llvm-ar", "llvm-nm", "llvm-objcopy", "llvm-objdump"):
        path = Path(prefix) / "bin" / name
        text = command([path, "--version"], report, name + "-version")
        if not re.search(r"\b(?:clang version|LLVM version|LLD) 22\.1\.6(?:\s|$)", text):
            raise ProfileError("tool version mismatch: " + name)
        linked = command([ldd, path], report, name + "-ldd")
        if "not found" in linked:
            raise ProfileError("required host DSO missing: " + name)
        for line in linked.splitlines():
            match = re.search(r"(?:=>\s*)?(/[^\s]+)\s+\(", line)
            if match:
                dependency = Path(match.group(1)).resolve(strict=True)
                dependencies[str(dependency)] = identity(dependency)
    report["provided_host_DSOs"] = sorted(dependencies.values(), key=lambda row: row["path"])
    version = command([rustc, "-vV"], report, "rustc-version")
    pin = profile["parser"]
    if ("release: " + pin["rust_release"] + "\n" not in version
            or "commit-hash: " + pin["rust_commit"] + "\n" not in version
            or "LLVM version: " + pin["LLVM_version"] + "\n" not in version):
        raise ProfileError("required Rust/parser toolchain mismatch")
    report["rustc"] = identity(rustc)
    report["parser"] = identity(parser)
    if (report["parser"]["bytes"], report["parser"]["sha256"]) != (pin["bytes"], pin["sha256"]):
        raise ProfileError("required parser library identity mismatch")
    library = ctypes.CDLL(str(Path(parser).resolve(strict=True)))
    function = library.LLVMGetVersion
    function.argtypes = [ctypes.POINTER(ctypes.c_uint)] * 3
    function.restype = None
    a, b, c = ctypes.c_uint(), ctypes.c_uint(), ctypes.c_uint()
    function(ctypes.byref(a), ctypes.byref(b), ctypes.byref(c))
    report["parser_C_API_version"] = [a.value, b.value, c.value]
    if report["parser_C_API_version"] != [22, 1, 6]:
        raise ProfileError("required parser C API version mismatch")
    linked = command([ldd, parser], report, "parser-ldd")
    if "not found" in linked:
        raise ProfileError("required parser host DSO missing")
    for line in linked.splitlines():
        match = re.search(r"(?:=>\s*)?(/[^\s]+)\s+\(", line)
        if match:
            dependency = Path(match.group(1)).resolve(strict=True)
            dependencies[str(dependency)] = identity(dependency)
    report["provided_host_DSOs"] = sorted(dependencies.values(), key=lambda row: row["path"])
    report["parser_after"] = identity(parser)
    if report["parser_after"] != report["parser"]:
        raise ProfileError("parser changed during inspection")


def provision(archive, prefix, output, parser, rustc):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": "ostadix.ci-llvm-provision/v1", "status": "failed",
              "source_lowered": False, "hermetic": False, "FP_kernel_activation": False,
              "full_musl_lowering": False}
    try:
        profile = load_profile()
        report["provisioner"] = identity(Path(__file__))
        report["profile"] = identity(PROFILE)
        report["scope"] = profile["scope"]
        download_archive(archive, profile)
        with open_regular_input(archive, "archive input") as stream:
            report["archive"] = verify_archive(stream, profile)
            report["members"] = extract_selected(stream, prefix, profile)
            verify_archive(stream, profile)
        verify_subset(prefix, profile)
        license_source = ROOT / profile["license"]["path"]
        with open_regular_input(license_source, "license input") as license_stream:
            license_identity = stream_identity(license_stream, license_source)
            if (license_identity["bytes"], license_identity["sha256"]) != (profile["license"]["bytes"], profile["license"]["sha256"]):
                raise ProfileError("supplied complete LLVM license identity changed")
            license_stream.seek(0)
            with (output / "LLVM-LICENSE.TXT").open("xb") as destination:
                shutil.copyfileobj(license_stream, destination)
        report["complete_license"] = license_identity
        inspect_tools(prefix, parser, rustc, profile, report)
        verify_subset(prefix, profile)
        environment = {"OCORE_TEST_CLANG": str(Path(prefix).resolve() / "bin/clang"),
                       "OCORE_TEST_LLVM_NM": str(Path(prefix).resolve() / "bin/llvm-nm"),
                       "OCORE_TEST_LLVM_OBJCOPY": str(Path(prefix).resolve() / "bin/llvm-objcopy"),
                       "OCORE_TEST_LLVM_OBJDUMP": str(Path(prefix).resolve() / "bin/llvm-objdump"),
                       "OCORE_TEST_LLVM_LIBRARY": str(Path(parser).resolve()),
                       "OCORE_TEST_LLVM_SHA256": profile["parser"]["sha256"],
                       "OCORE_CONSTRAINED_FP_REQUIRED": "1"}
        report["provisioner_after"] = identity(Path(__file__))
        report["profile_after"] = identity(PROFILE)
        if report["provisioner_after"] != report["provisioner"] or report["profile_after"] != report["profile"]:
            raise ProfileError("provisioning source/profile changed")
        (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
        report.update(status="passed", prefix=str(Path(prefix).resolve()), selected_regular_bytes=sum(r["bytes"] for r in profile["members"].values() if r["kind"] == "regular"), selected_members=len(profile["members"]))
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def required_test_report(discovered, result, compiler_unchanged):
    """The required lane cannot succeed via missing discovery or SkipTest."""
    return {"schema": "ostadix.ci-constrained-fp-tests/v1", "discovered": discovered,
            "executed": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
            "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
            "unexpected_successes": len(result.unexpectedSuccesses),
            "compiler_unchanged": compiler_unchanged,
            "passed": result.wasSuccessful() and discovered == 9 and result.testsRun == 9
                      and not result.skipped and not result.expectedFailures
                      and not result.unexpectedSuccesses and compiler_unchanged,
            "foreign_ISA_native_execution": False, "whole_musl_lowering": False,
            "FP_kernel_activation": False, "cross_ISA_raw_NaN_identity": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True, help="existing exact archive or absent download destination")
    parser.add_argument("--prefix", type=Path, required=True, help="new absent job-local subset directory")
    parser.add_argument("--output", type=Path, required=True, help="new absent evidence directory")
    parser.add_argument("--parser-library", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = provision(arguments.archive, arguments.prefix, arguments.output, arguments.parser_library, arguments.rustc)
    except Exception as error:
        print("LLVM prerequisite REFUSED: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps({"status": report["status"], "members": report["selected_members"], "selected_regular_bytes": report["selected_regular_bytes"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
