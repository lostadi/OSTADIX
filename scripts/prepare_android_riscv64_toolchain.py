#!/usr/bin/env python3
"""Prepare isolated, checksum-verified libc corrections for Android RISC-V builds.

Python 3.11+ is required. This prepares sources; it does not qualify a toolchain,
change an installed toolchain, or build OSTADIX. See docs/ANDROID_RISCV64_TOOLCHAIN.md.
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
import time
import tomllib
import urllib.request


TARGET = "riscv64-linux-android"
LIBC_SOURCE = Path("src/unix/linux_like/android/b64/riscv64/mod.rs")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
FLAGS = {"O_DIRECT": "40000", "O_DIRECTORY": "200000",
         "O_NOFOLLOW": "400000", "O_LARGEFILE": "100000"}


class PreparationError(Exception):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_toml(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def tree_hashes(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise PreparationError(f"source tree contains a symlink: {path}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = sha256(path)
    return result


def command_output(command: list[str]) -> str:
    return subprocess.run(command, check=True, capture_output=True,
                          text=True, timeout=30).stdout.strip()


def executable(value: str) -> str:
    path = shutil.which(value)
    if path is None:
        raise PreparationError(f"executable not found: {value}")
    # Preserve rustup proxy's argv[0], rather than resolving it to `rustup`.
    return os.path.abspath(path)


def compiler_identity(rustc: str, cargo: str) -> dict:
    rustc, cargo = executable(rustc), executable(cargo)
    return {
        "rustc": rustc, "rustc_verbose_version": command_output([rustc, "-vV"]),
        "rustc_executable_sha256": sha256(Path(rustc)),
        "cargo": cargo, "cargo_verbose_version": command_output([cargo, "-Vv"]),
        "cargo_executable_sha256": sha256(Path(cargo)),
        "sysroot": command_output([rustc, "--print", "sysroot"]),
    }


def locked_libc(path: Path) -> list[dict]:
    packages = [p for p in read_toml(path).get("package", []) if p.get("name") == "libc"]
    if not packages:
        raise PreparationError(f"no locked libc package in {path}")
    for package in packages:
        if (package.get("source") != REGISTRY
                or not re.fullmatch(r"0\.2\.[0-9]+", package.get("version", ""))
                or not re.fullmatch(r"[0-9a-f]{64}", package.get("checksum", ""))):
            raise PreparationError(f"expected an exact checksummed crates.io libc entry in {path}")
    return packages


def obtain_archive(package: dict, directories: list[Path], output: Path,
                   offline: bool) -> tuple[Path, str]:
    name = f"libc-{package['version']}.crate"
    candidates = []
    for directory in directories:
        candidates.append(directory / name)
        candidates.extend(sorted(directory.glob(f"*/{name}")))
    found = next((path for path in candidates if path.is_file()), None)
    destination = output / "archives" / name
    destination.parent.mkdir(exist_ok=True)
    if found:
        shutil.copyfile(found, destination)
        origin = str(found.resolve())
    elif offline:
        raise PreparationError(f"offline archive missing: {name}; supply --archive-dir")
    else:
        origin = f"https://static.crates.io/crates/libc/{name}"
        with urllib.request.urlopen(origin, timeout=30) as response, destination.open("xb") as target:
            shutil.copyfileobj(response, target)
    actual = sha256(destination)
    if actual != package["checksum"]:
        raise PreparationError(f"archive checksum mismatch for {name}: expected "
                               f"{package['checksum']}, got {actual}")
    return destination, origin


def extract_crate(archive: Path, version: str, output: Path) -> Path:
    prefix = f"libc-{version}"
    root = output / "crates" / prefix
    seen = set()
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts
                    or path.parts[0] != prefix or member.name in seen
                    or not (member.isdir() or member.isfile())):
                raise PreparationError(f"unexpected crate archive member: {member.name}")
            seen.add(member.name)
        # Extraction is manual: no links, devices, traversal, or tar permission changes.
        for member in source.getmembers():
            destination = output / "crates" / member.name
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                stream = source.extractfile(member)
                if stream is None:
                    raise PreparationError(f"unreadable crate member: {member.name}")
                with stream, destination.open("xb") as target:
                    shutil.copyfileobj(stream, target)
    manifest = read_toml(root / "Cargo.toml").get("package", {})
    if manifest.get("name") != "libc" or manifest.get("version") != version:
        raise PreparationError(f"crate manifest does not identify libc {version}")
    return root


def patch_constants(root: Path) -> dict:
    source = root / LIBC_SOURCE
    before = sha256(source)
    text = source.read_text(encoding="utf-8")
    for name, digits in FLAGS.items():
        expected = f"pub const {name}: c_int = 0x{digits};"
        definitions = re.findall(rf"^pub const {name}\s*:[^\n]+", text, re.MULTILINE)
        if definitions != [expected]:
            raise PreparationError(f"unexpected {name} definition in {source}: {definitions!r}")
        text = text.replace(expected, f"pub const {name}: c_int = 0o{digits};", 1)
    source.write_text(text, encoding="utf-8")
    return {"file": str(LIBC_SOURCE), "original_sha256": before,
            "derived_sha256": sha256(source)}


def patch_std(library: Path, package: dict, crate: Path) -> None:
    manifest = library / "Cargo.toml"
    parsed = read_toml(manifest)
    if "libc" in parsed.get("patch", {}).get("crates-io", {}):
        raise PreparationError("selected Rust library already patches libc; refusing to replace it")
    text = manifest.read_text(encoding="utf-8")
    entry = f"libc = {{ path = {json.dumps(str(crate))}, version = \"={package['version']}\" }}\n"
    sections = list(re.finditer(r"^\[patch\.crates-io\][ \t]*(?:#.*)?$", text, re.MULTILINE))
    if len(sections) == 1:
        position = sections[0].end()
        text = text[:position] + "\n" + entry.rstrip("\n") + text[position:]
    elif "crates-io" not in parsed.get("patch", {}):
        text += "\n[patch.crates-io]\n" + entry
    else:
        raise PreparationError("unsupported Rust library patch table spelling")
    manifest.write_text(text, encoding="utf-8")
    lock = library / "Cargo.lock"
    text = lock.read_text(encoding="utf-8")
    blocks = re.split(r"(?=^\[\[package\]\][ \t]*$)", text, flags=re.MULTILINE)
    changed = 0
    for index, block in enumerate(blocks):
        if not block.startswith("[[package]]"):
            continue
        item = tomllib.loads(block)["package"][0]
        if item.get("name") == "libc" and item.get("version") == package["version"]:
            if item.get("source") != REGISTRY or item.get("checksum") != package["checksum"]:
                raise PreparationError("Rust library libc lock entry changed during preparation")
            blocks[index] = re.sub(r"^(?:source|checksum) = [^\n]*\n", "", block, flags=re.MULTILINE)
            changed += 1
    if changed != 1:
        raise PreparationError("expected exactly one matching Rust library libc lock entry")
    lock.write_text("".join(blocks), encoding="utf-8")
    expected = dict(package)
    expected.pop("source")
    expected.pop("checksum")
    actual = [p for p in read_toml(lock)["package"] if p.get("name") == "libc"]
    if actual != [expected]:
        raise PreparationError("derived Rust library lock does not match the exact path dependency")


def check_ndk(cc: str, output: Path) -> dict:
    cc = executable(cc)
    source = output / "android-riscv64-flags.c"
    source.write_text(
        "#define _GNU_SOURCE 1\n#include <fcntl.h>\n"
        "#if !defined(__ANDROID__) || !defined(__riscv) || __riscv_xlen != 64\n"
        '#error "expected an Android RISC-V 64 compiler"\n#endif\n'
        '#if __ANDROID_API__ < 37\n#error "expected Android API 37 or newer"\n#endif\n'
        + "".join(f'_Static_assert({name} == 0{digits}, "{name}");\n'
                  for name, digits in FLAGS.items()), encoding="utf-8")
    object_file = output / "android-riscv64-flags.o"
    command = [cc, "-std=c11", "-Werror", "-c", str(source), "-o", str(object_file)]
    process = subprocess.run(command, capture_output=True, text=True, timeout=60)
    record = {"command": command, "compiler_version": command_output([cc, "--version"]),
              "compiler_sha256": sha256(Path(cc)), "exit_status": process.returncode,
              "stdout": process.stdout, "stderr": process.stderr}
    if object_file.is_file():
        record["object_sha256"] = sha256(object_file)
        elf = object_file.read_bytes()[:20]
        record["elf_riscv64"] = (elf[:6] == b"\x7fELF\x02\x01"
                                 and int.from_bytes(elf[18:20], "little") == 243)
    write_json(output / "ndk-header-check.json", record)
    if process.returncode or not record.get("elf_riscv64"):
        raise PreparationError("NDK header static assertions failed; see ndk-header-check.json")
    return record


def prepare(args: argparse.Namespace) -> dict:
    if args.output.exists() or args.output.is_symlink():
        raise PreparationError(f"output already exists: {args.output}")
    output = args.output.resolve()
    identity = compiler_identity(args.rustc, args.cargo)
    library = (args.rust_library or Path(identity["sysroot"]) /
               "lib/rustlib/src/rust/library").resolve(strict=True)
    if output.is_relative_to(library) or output.is_relative_to(Path(identity["sysroot"]).resolve()):
        raise PreparationError("output must be outside the installed toolchain and source library")
    locks = list(dict.fromkeys(path.resolve(strict=True) for path in args.lock))
    applications = []
    for lock in locks:
        packages_for_lock = locked_libc(lock)
        if len(packages_for_lock) != 1:
            raise PreparationError("Cargo paths cannot preserve multiple libc versions in one "
                                   f"workspace; inspect {lock} separately")
        applications.append({"lock": str(lock), "lock_sha256": sha256(lock),
                             "version": packages_for_lock[0]["version"]})
    std_lock = library / "Cargo.lock"
    std_packages = locked_libc(std_lock)
    if len(std_packages) != 1:
        raise PreparationError("Rust library must lock exactly one libc version")
    all_locks = list(dict.fromkeys([*locks, std_lock]))
    lock_hashes = {str(path): sha256(path) for path in all_locks}
    packages: dict[str, dict] = {}
    requirements = []
    for path in all_locks:
        for package in locked_libc(path):
            version = package["version"]
            if version in packages and packages[version]["checksum"] != package["checksum"]:
                raise PreparationError(f"conflicting locked checksums for libc {version}")
            packages[version] = package
            requirements.append({"lock": str(path), "version": version,
                                 "archive_sha256": package["checksum"]})
    original_library = tree_hashes(library)
    cache = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))) / "registry/cache"
    if output.is_relative_to(cache.parent.resolve()):
        raise PreparationError("output must be outside the global Cargo registry")
    directories = [path.resolve() for path in args.archive_dir] + [cache]
    # Exclusive creation is the only mutation before work starts; failed runs are retained.
    output.mkdir(parents=True, exist_ok=False)
    try:
        write_json(output / "status.json", {"status": "preparing", "supported_execution": False})
        crate_records = []
        derived_crates = {}
        for version, package in sorted(packages.items()):
            archive, origin = obtain_archive(package, directories, output, args.offline)
            root = extract_crate(archive, version, output)
            original = tree_hashes(root)
            correction = patch_constants(root)
            derived = tree_hashes(root)
            if [p for p in original if original[p] != derived[p]] != [LIBC_SOURCE.as_posix()]:
                raise PreparationError("unexpected file changes in derived libc")
            write_json(output / f"libc-{version}-file-hashes.json",
                       {"original": original, "derived": derived})
            crate_records.append({"version": version, "archive_origin": origin,
                                  "archive_sha256": sha256(archive), "path": str(root),
                                  "correction": correction})
            derived_crates[version] = root
        copied_library = output / "rust-library"
        shutil.copytree(library, copied_library)
        if tree_hashes(copied_library) != original_library:
            raise PreparationError("copied Rust library differs from the original source snapshot")
        patch_std(copied_library, std_packages[0], derived_crates[std_packages[0]["version"]])
        derived_library = tree_hashes(copied_library)
        if [p for p in original_library if original_library[p] != derived_library[p]] != ["Cargo.lock", "Cargo.toml"]:
            raise PreparationError("unexpected file changes in derived Rust library")
        write_json(output / "rust-library-file-hashes.json",
                   {"original": original_library, "derived": derived_library})
        # Cargo paths overrides match a dependency's compatible range, not its
        # exact locked version. Never put multiple libc versions in one list.
        for application in applications:
            version = application["version"]
            config = output / f"paths-override-{version}.toml"
            config.write_text("paths = " + json.dumps([str(derived_crates[version])]) + "\n",
                              encoding="utf-8")
            application["paths_config"] = str(config)
            application["paths_config_sha256"] = sha256(config)
        environment = {"RUSTC": identity["rustc"], "__CARGO_TESTS_ONLY_SRC_ROOT": str(copied_library),
                       "CARGO_TARGET_DIR": str(output / "target")}
        if args.ndk_cc:
            check_ndk(args.ndk_cc, output)
            environment["CARGO_TARGET_RISCV64_LINUX_ANDROID_LINKER"] = executable(args.ndk_cc)
        write_json(output / "build-environment.json", {
            "environment": environment, "cargo": identity["cargo"],
            "applications": applications,
            "cargo_arguments": ["--locked", "-Z", "build-std", "--target", TARGET],
            "experimental_internal_cargo_hook": "__CARGO_TESTS_ONLY_SRC_ROOT",
        })
        if any(sha256(Path(path)) != digest for path, digest in lock_hashes.items()):
            raise PreparationError("an input lock changed during preparation")
        if tree_hashes(library) != original_library:
            raise PreparationError("input Rust library changed during preparation")
        result = {"schema": "ostadix.android-riscv64-preparation/v1", "status": "prepared_only",
                  "supported_execution": False, "target": TARGET, "compiler": identity,
                  "script_sha256": sha256(Path(__file__)), "input_lock_sha256": lock_hashes,
                  "rust_library_source": str(library), "requirements": requirements,
                  "crates": crate_records, "applications": applications,
                  "build_environment_sha256": sha256(output / "build-environment.json"),
                  "derived_std_manifest_sha256": sha256(copied_library / "Cargo.toml"),
                  "derived_std_lock_sha256": sha256(copied_library / "Cargo.lock"),
                  "ndk_header_check": "passed" if args.ndk_cc else "not_run",
                  "required_acceptance": ["actual Cargo unit graph and compiled source paths",
                                          "native Android RISC-V flag and filesystem probes",
                                          "native OSTADIX acceptance and stress tests"]}
        write_json(output / "provenance.json", result)
        write_json(output / "status.json", {"status": "prepared_only", "supported_execution": False})
        return result
    except Exception as error:
        write_json(output / "status.json", {"status": "failed", "supported_execution": False,
                                            "error": str(error)})
        raise


def workspace_lock(cargo: str, arguments: list[str]) -> Path:
    command = [cargo, "locate-project", "--workspace", "--message-format=plain"]
    manifests = [a.split("=", 1)[1] for a in arguments if a.startswith("--manifest-path=")]
    manifests += [arguments[i + 1] for i, a in enumerate(arguments[:-1]) if a == "--manifest-path"]
    if len(manifests) > 1:
        raise PreparationError("at most one manifest path is supported")
    if manifests:
        command += ["--manifest-path", manifests[0]]
    return Path(command_output(command)).resolve(strict=True).with_name("Cargo.lock")


def run_prepared(output: Path, arguments: list[str]) -> int:
    """Invoke exactly the caller's build action with recorded source selection."""
    output = output.resolve(strict=True)
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    if not arguments or arguments[0] not in {"build", "check", "test"}:
        raise PreparationError("run requires explicit build, check, or test arguments after --")
    # `cargo test -- ...` passes the suffix to tests; those are not Cargo flags.
    cargo_arguments = arguments[:arguments.index("--")] if "--" in arguments else arguments
    targets = [a.split("=", 1)[1] for a in cargo_arguments if a.startswith("--target=")]
    targets += [cargo_arguments[i + 1] for i, a in enumerate(cargo_arguments[:-1]) if a == "--target"]
    if targets != [TARGET]:
        raise PreparationError(f"run requires exactly one explicit --target {TARGET}")
    unstable = [a[2:] for a in cargo_arguments if a.startswith("-Z") and a != "-Z"]
    unstable += [cargo_arguments[i + 1] for i, a in enumerate(cargo_arguments[:-1]) if a == "-Z"]
    std_flags = [flag for flag in unstable if flag.split("=", 1)[0] == "build-std"]
    if (len(std_flags) != 1 or
            (std_flags[0] != "build-std" and "std" not in std_flags[0].split("=", 1)[1].split(","))):
        raise PreparationError("run requires explicit -Z build-std once, including std if components are listed")
    if "--locked" not in cargo_arguments and "--frozen" not in cargo_arguments:
        raise PreparationError("run requires explicit --locked or --frozen")
    if any(a == "--config" or a.startswith("--config=") for a in cargo_arguments):
        raise PreparationError("run owns --config for source selection; use direct Cargo for other configurations")
    if any(a == "--lockfile-path" or a.startswith("--lockfile-path=") for a in cargo_arguments):
        raise PreparationError("run selects the workspace lock; alternate lockfile paths are unsupported")
    provenance = json.loads((output / "provenance.json").read_text())
    if (provenance.get("schema") != "ostadix.android-riscv64-preparation/v1"
            or provenance.get("status") != "prepared_only"):
        raise PreparationError("directory is not a completed preparation")
    if sha256(output / "build-environment.json") != provenance["build_environment_sha256"]:
        raise PreparationError("prepared build-environment.json changed")
    identity = provenance["compiler"]
    if compiler_identity(identity["rustc"], identity["cargo"]) != identity:
        raise PreparationError("recorded Rust compiler or Cargo identity changed; prepare fresh sources")
    trees = [(output / "rust-library", output / "rust-library-file-hashes.json")]
    trees += [(Path(c["path"]), output / f"libc-{c['version']}-file-hashes.json")
              for c in provenance["crates"]]
    for tree, manifest in trees:
        if tree_hashes(tree) != json.loads(manifest.read_text())["derived"]:
            raise PreparationError(f"prepared source tree changed: {tree}")
    configuration = json.loads((output / "build-environment.json").read_text())
    lock = workspace_lock(configuration["cargo"], cargo_arguments)
    lock_before = sha256(lock)
    matches = [a for a in provenance["applications"] if a["lock_sha256"] == lock_before]
    if not matches:
        raise PreparationError(f"workspace lock was not prepared or has changed: {lock}")
    selected = matches[0]
    config = Path(selected["paths_config"])
    if sha256(config) != selected["paths_config_sha256"]:
        raise PreparationError(f"prepared paths config changed: {config}")
    environment = os.environ.copy()
    environment.update(configuration["environment"])
    command = [configuration["cargo"], "--config", str(config), *arguments]
    # Display the exact action and bounded environment overlay, never unrelated secrets.
    record = {"command": command, "cwd": os.getcwd(), "environment": configuration["environment"],
              "supported_execution": False, "provenance_sha256": sha256(output / "provenance.json"),
              "workspace_lock": str(lock), "workspace_lock_sha256": lock_before,
              "application_libc_version": selected["version"]}
    print(json.dumps(record, indent=2), file=sys.stderr, flush=True)
    run_id = str(time.time_ns())
    record["exit_status"] = subprocess.run(command, env=environment, check=False).returncode
    record["locks_unchanged"] = (sha256(lock) == lock_before and
        sha256(output / "rust-library/Cargo.lock") == provenance["derived_std_lock_sha256"])
    write_json(output / f"run-{run_id}.json", record)
    if not record["locks_unchanged"]:
        raise PreparationError("a build lock changed; inspect the retained run receipt")
    return record["exit_status"]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["run"]:
        parser = argparse.ArgumentParser(description="Run recorded Cargo with explicit arguments and isolated corrected sources.")
        parser.add_argument("run", choices=["run"])
        parser.add_argument("prepared", type=Path)
        parser.add_argument("arguments", nargs=argparse.REMAINDER)
        args = parser.parse_args(argv)
        try:
            return run_prepared(args.prepared, args.arguments)
        except (PreparationError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            print(f"android-riscv64 run: {error}", file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new isolated output directory")
    parser.add_argument("--lock", required=True, action="append", type=Path, help="application Cargo.lock; repeat for MCP/other workspaces")
    parser.add_argument("--rustc", default="rustc", help="selected nightly rustc executable")
    parser.add_argument("--cargo", default="cargo", help="matching nightly Cargo executable")
    parser.add_argument("--rust-library", type=Path, help="selected nightly rust/library; default from rustc sysroot")
    parser.add_argument("--archive-dir", action="append", default=[], type=Path, help="read-only directory of .crate archives (repeatable)")
    parser.add_argument("--offline", action="store_true", help="refuse network downloads; discover local Cargo cache")
    parser.add_argument("--ndk-cc", help="optional real Android RISC-V API37 Clang header check")
    args = parser.parse_args(argv)
    try:
        result = prepare(args)
        print(json.dumps({"status": result["status"], "output": str(args.output.absolute()),
                          "versions": [c["version"] for c in result["crates"]],
                          "supported_execution": False}, indent=2))
        return 0
    except (PreparationError, OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"android-riscv64 preparation: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
