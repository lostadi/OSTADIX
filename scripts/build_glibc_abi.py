#!/usr/bin/env python3
"""Capture an authenticated original Ubuntu ARM64 libc build/runtime closure.

APT resolves/downloads into private state with an empty dpkg status. No package
is installed on this host and no package control script is executed. The output
is a compiler/runtime dependency bundle, not an installed Ubuntu system.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
KEYRING = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
ORIGIN = "https://ports.ubuntu.com/ubuntu-ports"
POCKETS = ("noble", "noble-updates", "noble-security")
REQUESTS = ("libc6-dev:arm64", "libgcc-s1:arm64")
SCHEMA = "ostadix.original-glibc-abi/v1"


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def identity(path: Path) -> dict:
    return {"bytes": path.stat().st_size, "sha256": sha256(path)}


def cache_original(pool: Path, source: Path, expected: dict) -> None:
    destination = pool / (expected["sha256"] + ".deb")
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or identity(destination) != expected:
            raise ValueError("preserving a conflicting original package cache entry")
        return
    descriptor, name = tempfile.mkstemp(prefix=".original-deb-", dir=pool)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream, source.open("rb") as original:
            shutil.copyfileobj(original, stream)
        if identity(temporary) != expected:
            raise ValueError("original package changed while entering the cache")
        temporary.chmod(0o444)
        try:
            os.link(temporary, destination)
        except FileExistsError:
            if destination.is_symlink() or identity(destination) != expected:
                raise ValueError("preserving a conflicting original package cache entry")
    finally:
        temporary.unlink(missing_ok=True)


def paragraphs(text: str) -> list[dict[str, str]]:
    result, record, current = [], {}, None
    for line in text.splitlines() + [""]:
        if not line:
            if record:
                result.append(record)
            record, current = {}, None
        elif line[:1].isspace():
            if current is None:
                raise ValueError("control continuation has no field")
            record[current] += "\n" + line[1:]
        else:
            current, separator, value = line.partition(":")
            if not separator or current in record:
                raise ValueError("malformed/duplicate control field")
            record[current] = value.lstrip()
    return result


def apt_config(work: Path) -> str:
    quote = lambda path: json.dumps(str(path))
    return f'''Dir {quote(work)};
Dir::Etc {quote(work / 'etc')};
Dir::Etc::main "absent.conf";
Dir::Etc::parts "absent.conf.d";
Dir::Etc::sourcelist "sources.list";
Dir::Etc::sourceparts "absent.sources.d";
Dir::Etc::trusted "absent.gpg";
Dir::Etc::trustedparts "absent.trusted.d";
Dir::State {quote(work / 'state')};
Dir::State::status {quote(work / 'state/status')};
Dir::State::lists {quote(work / 'state/lists')};
Dir::Cache {quote(work / 'cache')};
Dir::Cache::archives {quote(work / 'cache/archives')};
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Dir::Log {quote(work / 'logs')};
APT::Architecture "arm64";
#clear APT::Architectures;
APT::Architectures {{ "arm64"; }};
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
Acquire::Check-Valid-Until "true";
Acquire::Languages "none";
Acquire::GzipIndexes "false";
Acquire::Retries "3";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
Acquire::IndexTargets::deb::DEP-11::DefaultEnabled "false";
#clear APT::Update::Pre-Invoke;
#clear APT::Update::Post-Invoke;
#clear APT::Update::Post-Invoke-Success;
#clear DPkg::Pre-Invoke;
#clear DPkg::Post-Invoke;
#clear DPkg::Pre-Install-Pkgs;
'''


def solver_plan(text: str) -> dict[str, str]:
    plan = {}
    for name, version in re.findall(r"^Inst (\S+)(?: \[[^]]+\])? \((\S+)", text, re.M):
        name = name.removesuffix(":arm64")
        if name in plan:
            raise ValueError("duplicate package in original APT plan")
        plan[name] = version
    if not all(name.split(":")[0] in plan for name in REQUESTS):
        raise ValueError("original APT solver did not select both requested roots")
    return plan


def inventory(root: Path) -> list[dict]:
    result = []
    for path in sorted(root.rglob("*")):
        status = path.lstat()
        record = {"path": path.relative_to(root).as_posix(), "mode": stat.S_IMODE(status.st_mode)}
        if stat.S_ISLNK(status.st_mode):
            record.update(type="symlink", target=os.readlink(path))
        elif stat.S_ISDIR(status.st_mode):
            record.update(type="directory")
        elif stat.S_ISREG(status.st_mode):
            record.update(type="file", **identity(path))
        else:
            raise ValueError(f"unsupported special file in ABI payload: {path}")
        result.append(record)
    return result


def deterministic_bundle(output: Path, names: tuple[str, ...], destination: Path | None = None):
    with (destination or output / "glibc-abi.tar.gz").open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(mode="w", fileobj=compressed, format=tarfile.PAX_FORMAT) as archive:
                for name in names:
                    for path in [output / name, *sorted((output / name).rglob("*"))] if (output / name).is_dir() else [output / name]:
                        info = archive.gettarinfo(str(path), path.relative_to(output).as_posix())
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mtime = 0
                        info.pax_headers = {}
                        if info.isfile():
                            with path.open("rb") as stream:
                                archive.addfile(info, stream)
                        else:
                            archive.addfile(info)


def relative_file(root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("ABI manifest path escaped its captured directory")
    selected = root / path
    if any(parent.is_symlink() for parent in [selected, *selected.parents] if parent != root.parent):
        raise ValueError("ABI manifest selected a symlink outside its package payload")
    return selected


def verify(output: Path) -> dict:
    manifest = json.loads((output / "glibc-abi.json").read_text())
    if manifest.get("schema") != SCHEMA or manifest.get("architecture") != "arm64" or manifest.get("requests") != list(REQUESTS):
        raise ValueError("unsupported original glibc ABI manifest")
    if identity(output / "glibc-abi.tar.gz") != manifest["bundle"]:
        raise ValueError("glibc ABI bundle bytes changed")
    with tarfile.open(output / "glibc-abi.tar.gz", "r:gz") as archive:
        captured = json.load(archive.extractfile("manifest.json"))
    if captured != {key: value for key, value in manifest.items() if key != "bundle"}:
        raise ValueError("outer ABI manifest differs from its captured bundle manifest")
    if (output / "rootfs").is_symlink():
        raise ValueError("ABI rootfs must be a captured real directory")
    if {record["file"] for record in manifest["packages"]} != {path.name for path in (output / "debs").iterdir()}:
        raise ValueError("ABI package inventory contains undeclared files")
    actual_metadata = {path.relative_to(output).as_posix() for path in (output / "metadata").rglob("*") if path.is_file()}
    if {record["file"] for record in manifest["metadata"]} != actual_metadata:
        raise ValueError("ABI source metadata inventory contains undeclared files")
    if sha256(relative_file(output, "metadata/build_glibc_abi.py")) != manifest["recipe_sha256"]:
        raise ValueError("captured ABI recipe identity changed")
    for record in manifest["packages"]:
        if Path(record["file"]).name != record["file"]:
            raise ValueError("original package filename escaped debs directory")
        path = relative_file(output / "debs", record["file"])
        if path.is_symlink() or identity(path) != {key: record[key] for key in ("bytes", "sha256")}:
            raise ValueError("original package bytes changed")
    for record in manifest["metadata"]:
        path = relative_file(output, record["file"])
        if path.is_symlink() or identity(path) != {key: record[key] for key in ("bytes", "sha256")}:
            raise ValueError("signed source metadata changed")
    if inventory(output / "rootfs") != manifest["rootfs"]:
        raise ValueError("extracted ABI tree changed")
    # Inventory hashes are not a trust anchor. Recheck the original signatures,
    # index/package chain, solver choices and extracted payloads independently.
    with tempfile.TemporaryDirectory(prefix="glibc-abi-verify-") as directory:
        work = Path(directory)
        packages = {}
        trusted = []
        for pocket in POCKETS:
            source = output / "metadata" / pocket
            released = work / (pocket + ".Release")
            result = subprocess.run(["gpgv", "--homedir", str(work), "--keyring", str(KEYRING),
                                     "--status-fd", "1", "--output", str(released), str(source / "InRelease")],
                                    capture_output=True, text=True, timeout=30, check=True)
            signers = re.findall(r"^\[GNUPG:\] VALIDSIG (\S+)", result.stdout, re.M)
            if not signers or released.read_bytes() != (source / "Release").read_bytes():
                raise ValueError("captured Release does not match the trusted original signature")
            trusted.append({"pocket": pocket, "uri": f"{ORIGIN}/dists/{pocket}/InRelease", "signers": signers})
            release = paragraphs(released.read_text())[0]
            entries = [line.split() for line in release["SHA256"].splitlines()
                       if line.split() and line.split()[-1] == "main/binary-arm64/Packages"]
            if len(entries) != 1 or identity(source / "Packages") != {"bytes": int(entries[0][1]), "sha256": entries[0][0]}:
                raise ValueError("captured package index differs from its signed original identity")
            for record in paragraphs((source / "Packages").read_text()):
                key = (record["Package"], record["Version"], record["Architecture"])
                previous = packages.get(key)
                if previous and previous["SHA256"] != record["SHA256"]:
                    raise ValueError("signed archives disagree on original package bytes")
                packages[key] = record
        if trusted != manifest["signed_releases"] or manifest.get("origin") != ORIGIN:
            raise ValueError("ABI archive/signing scope changed")
        apt = work / "private-apt"
        for name in ("etc", "state/lists/partial", "cache/archives/partial", "logs"):
            (apt / name).mkdir(parents=True, exist_ok=True)
        (apt / "state/status").write_text("")
        (apt / "etc/sources.list").write_text("".join(
            f"deb [arch=arm64 signed-by={KEYRING}] {ORIGIN} {pocket} main\n" for pocket in POCKETS))
        configuration = apt / "apt.conf"
        configuration.write_text(apt_config(apt))
        for pocket in POCKETS:
            prefix = apt / "state/lists" / ("ports.ubuntu.com_ubuntu-ports_dists_" + pocket)
            shutil.copyfile(output / "metadata" / pocket / "InRelease", Path(str(prefix) + "_InRelease"))
            shutil.copyfile(output / "metadata" / pocket / "Packages", Path(str(prefix) + "_main_binary-arm64_Packages"))
        result = subprocess.run(["apt-get", "--simulate", "--no-install-recommends", "install", *REQUESTS],
                                env=dict(os.environ, APT_CONFIG=str(configuration), LC_ALL="C"),
                                capture_output=True, text=True, timeout=60, check=True)
        plan = solver_plan(result.stdout)
        declared = {record["name"]: record["version"] for record in manifest["packages"]}
        if plan != declared or len(declared) != len(manifest["packages"]):
            raise ValueError("ABI packages differ from the complete original APT dependency closure")
        baseline = work / "rootfs"
        baseline.mkdir()
        for record in manifest["packages"]:
            authenticated = packages.get((record["name"], record["version"], record["architecture"]))
            if not authenticated or record["sha256"] != authenticated["SHA256"] or record["bytes"] != int(authenticated["Size"]):
                raise ValueError("ABI package identity lacks an authenticated index record")
            if record["file"] != Path(authenticated["Filename"]).name or record["uri"] != ORIGIN + "/" + authenticated["Filename"]:
                raise ValueError("ABI original package origin changed")
            if record["depends"] != authenticated.get("Depends", "") or record["pre_depends"] != authenticated.get("Pre-Depends", ""):
                raise ValueError("ABI package dependency metadata changed")
            subprocess.run(["dpkg-deb", "--extract", str(output / "debs" / record["file"]), str(baseline)],
                           capture_output=True, timeout=30, check=True)
        if inventory(baseline) != manifest["rootfs"]:
            raise ValueError("ABI payload inventory differs from authenticated original packages")
        reproduction = work / "glibc-abi.tar.gz"
        deterministic_bundle(output, ("rootfs", "debs", "metadata", "manifest.json"), reproduction)
        if identity(reproduction) != manifest["bundle"]:
            raise ValueError("ABI bundle is not the canonical capture of verified original files")
    return manifest


def build(output: Path, cache: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("output must be a new directory")
    output.mkdir(parents=True)
    work = output / "private-apt"
    for directory in ("etc", "state/lists/partial", "cache/archives/partial", "logs", "gpg"):
        (work / directory).mkdir(parents=True, exist_ok=True)
    (work / "gpg").chmod(0o700)
    (work / "state/status").write_text("")
    (work / "etc/sources.list").write_text("".join(
        f"deb [arch=arm64 signed-by={KEYRING}] {ORIGIN} {pocket} main\n" for pocket in POCKETS))
    configuration = work / "apt.conf"
    configuration.write_text(apt_config(work))
    environment = dict(os.environ, APT_CONFIG=str(configuration), LC_ALL="C", DEBIAN_FRONTEND="noninteractive")
    commands = []
    def run(arguments, *, stdout=None):
        commands.append([str(value).replace(str(output), "<output>") for value in arguments])
        result = subprocess.run(arguments, env=environment, stdout=stdout or subprocess.PIPE,
                                stderr=subprocess.PIPE, text=stdout is None, timeout=300)
        if result.returncode:
            error = result.stderr.decode() if isinstance(result.stderr, bytes) else result.stderr
            raise RuntimeError(f"original tool failed: {arguments[0]}: {error}")
        return result.stdout
    tools = {}
    for name in ("apt-get", "gpgv", "dpkg-deb", "/usr/lib/apt/apt-helper"):
        selected = shutil.which(name)
        if selected is None:
            raise ValueError(f"required original tool missing: {name}")
        path = Path(selected).resolve()
        tools[name] = {"path": str(path), **identity(path)}
    key_identity = identity(KEYRING)
    metadata = output / "metadata"
    metadata.mkdir()
    shutil.copyfile(KEYRING, metadata / "ubuntu-archive-keyring.gpg")
    shutil.copyfile(Path(__file__), metadata / "build_glibc_abi.py")
    print("Resolving original ARM64 libc dependencies with isolated APT state.", flush=True)
    update = run(["apt-get", "update", "--error-on=any"])
    (work / "logs/update.log").write_text(update)
    package_records, signed = {}, []
    for pocket in POCKETS:
        pocket_dir = metadata / pocket
        pocket_dir.mkdir()
        inrelease = work / "state/lists" / f"ports.ubuntu.com_ubuntu-ports_dists_{pocket}_InRelease"
        shutil.copyfile(inrelease, pocket_dir / "InRelease")
        status_text = run(["gpgv", "--homedir", str(work / "gpg"), "--keyring", str(metadata / "ubuntu-archive-keyring.gpg"),
                           "--status-fd", "1", "--output", str(pocket_dir / "Release"), str(pocket_dir / "InRelease")])
        signatures = re.findall(r"^\[GNUPG:\] VALIDSIG (\S+)", status_text, re.M)
        if not signatures:
            raise ValueError("original gpgv did not validate an archive signature")
        release = paragraphs((pocket_dir / "Release").read_text())[0]
        index_path = "main/binary-arm64/Packages"
        expected = [line.split() for line in release["SHA256"].splitlines() if line.split() and line.split()[-1] == index_path]
        if len(expected) != 1:
            raise ValueError("signed Release lacks the exact ARM64 package index identity")
        indexes = list((work / "state/lists").glob(f"ports.ubuntu.com_ubuntu-ports_dists_{pocket}_main_binary-arm64_Packages*"))
        if len(indexes) != 1:
            raise ValueError("original APT did not preserve one ARM64 package index")
        with (pocket_dir / "Packages").open("wb") as stream:
            run(["/usr/lib/apt/apt-helper", "cat-file", str(indexes[0])], stdout=stream)
        if identity(pocket_dir / "Packages") != {"bytes": int(expected[0][1]), "sha256": expected[0][0]}:
            raise ValueError("package index does not match the signed Release")
        signed.append({"pocket": pocket, "uri": f"{ORIGIN}/dists/{pocket}/InRelease", "signers": signatures})
        for record in paragraphs((pocket_dir / "Packages").read_text()):
            key = (record["Package"], record["Version"], record["Architecture"])
            previous = package_records.get(key)
            if previous and previous["record"]["SHA256"] != record["SHA256"]:
                raise ValueError("archive pockets disagree on identical package version bytes")
            package_records[key] = {"record": record, "pocket": pocket}
    plan_text = run(["apt-get", "--simulate", "--no-install-recommends", "install", *REQUESTS])
    (metadata / "solver-plan.txt").write_text(plan_text)
    plan = solver_plan(plan_text)
    selected = []
    pool = cache / "sha256"
    pool.mkdir(parents=True, exist_ok=True)
    for name, version in sorted(plan.items()):
        entry = package_records.get((name, version, "arm64")) or package_records.get((name, version, "all"))
        if entry is None:
            raise ValueError("resolved package is absent from authenticated indexes")
        record = entry["record"]
        filename = Path(record["Filename"]).name
        if not filename.endswith(".deb") or not re.fullmatch(r"[0-9a-f]{64}", record["SHA256"]):
            raise ValueError("invalid original package filename/digest")
        cached = pool / (record["SHA256"] + ".deb")
        if cached.exists() or cached.is_symlink():
            if cached.is_symlink() or identity(cached) != {"bytes": int(record["Size"]), "sha256": record["SHA256"]}:
                raise ValueError("cached original package identity changed")
            apt_filename = record["Package"] + "_" + record["Version"].replace(":", "%3a") + "_" + record["Architecture"] + ".deb"
            shutil.copyfile(cached, work / "cache/archives" / apt_filename)
        selected.append({"name": name, "version": version, "architecture": record["Architecture"],
                         "file": filename, "bytes": int(record["Size"]), "sha256": record["SHA256"],
                         "uri": ORIGIN + "/" + record["Filename"], "pocket": entry["pocket"],
                         "depends": record.get("Depends", ""), "pre_depends": record.get("Pre-Depends", "")})
    download = run(["apt-get", "--yes", "--download-only", "--no-install-recommends", "install", *REQUESTS])
    (work / "logs/download.log").write_text(download)
    debs, rootfs = output / "debs", output / "rootfs"
    debs.mkdir(); rootfs.mkdir()
    available = {}
    for archive in (work / "cache/archives").glob("*.deb"):
        fields = run(["dpkg-deb", "--field", str(archive), "Package", "Version", "Architecture"])
        control = paragraphs(fields)[0]
        available[(control["Package"], control["Version"], control["Architecture"])] = archive
    if set(available) != {(r["name"], r["version"], r["architecture"]) for r in selected}:
        raise ValueError("downloaded original packages differ from the complete APT solver plan")
    print(f"Verifying and extracting {len(selected)} original packages; no maintainer scripts are run.", flush=True)
    for record in selected:
        source = available[(record["name"], record["version"], record["architecture"])]
        expected = {key: record[key] for key in ("bytes", "sha256")}
        if source.is_symlink() or identity(source) != expected:
            raise ValueError("downloaded package does not match authenticated package index")
        destination = debs / record["file"]
        shutil.copyfile(source, destination)
        run(["dpkg-deb", "--extract", str(destination), str(rootfs)])
        cache_original(pool, source, expected)
    if identity(KEYRING) != key_identity:
        raise ValueError("trusted Ubuntu keyring changed during capture")
    for record in tools.values():
        if identity(Path(record["path"])) != {key: record[key] for key in ("bytes", "sha256")}:
            raise ValueError("original host tool changed during capture")
    metadata_records = [{"file": path.relative_to(output).as_posix(), **identity(path)}
                        for path in sorted(metadata.rglob("*")) if path.is_file()]
    manifest = {"schema": SCHEMA, "architecture": "arm64", "requests": list(REQUESTS),
                "scope": "Original Ubuntu ARM64 compiler/runtime dependency closure; extracted payloads only, no installed Ubuntu OS or executed package scripts",
                "origin": ORIGIN, "signed_releases": signed, "packages": selected,
                "metadata": metadata_records, "rootfs": inventory(rootfs), "host_tools": tools,
                "recipe_sha256": sha256(Path(__file__)), "commands": commands,
                "private_dpkg_status_sha256": sha256(work / "state/status")}
    if (work / "state/status").read_bytes() != b"":
        raise ValueError("private download-only resolver unexpectedly changed dpkg status")
    (output / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    deterministic_bundle(output, ("rootfs", "debs", "metadata", "manifest.json"))
    manifest["bundle"] = identity(output / "glibc-abi.tar.gz")
    (output / "glibc-abi.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    verify(output)
    print(f"Original ARM64 glibc ABI closure: {output / 'glibc-abi.json'}", flush=True)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new output directory")
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache/ostadix-glibc-abi")
    parser.add_argument("--verify", action="store_true", help="revalidate an existing output with original signatures/solver and private extraction, without network")
    args = parser.parse_args()
    try:
        if args.verify:
            verify(args.output.absolute())
            print("Original ARM64 glibc ABI identities: PASS")
        else:
            build(args.output.absolute(), args.cache.expanduser().absolute())
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Original glibc ABI capture failed: {error}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
