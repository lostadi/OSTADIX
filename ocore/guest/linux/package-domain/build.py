#!/usr/bin/env python3
"""Create a normal persistent Alpine root disk for the O-core Linux domain.

The native x86_64 apk tool only resolves and authenticates offline packages on
the build host. All package installation, scripts, source compilation, dynamic
linking, shell commands and filesystem operations run in the real Linux guest.
No host package is installed and no host filesystem is mounted by this builder.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
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
import uuid


HERE = Path(__file__).resolve().parent
ALPINE_VERSION = "3.24.3"
ALPINE_BRANCH = "v3.24"
RELEASE_KEY = "0482D84022F52DF1C4E7CD43293ACD0907D9495A"
BASE_URL = "https://dl-cdn.alpinelinux.org/alpine"
DEFAULT_PACKAGES = ("build-base", "gcc", "make", "musl-dev", "linux-headers", "curl", "ca-certificates", "jq", "tcc")
SOURCE_FILES = {
    "zlib-1.3.2.tar.gz": (
        "https://zlib.net/fossils/zlib-1.3.2.tar.gz",
        "70963771ea5d763614278a69b474f09b7d237ef8f53b675a10fe31d9923aeef601504b35d7ebd1b1e7f347e9ebb048e6b3b47fffdf137e7bdc7e8d5eb4ec4692",
    ),
    "CVE-2026-85091.patch": (
        "https://raw.githubusercontent.com/alpinelinux/aports/3.24-stable/main/zlib/CVE-2026-85091.patch",
        "878888308a51296470f05eca59a79212314d4c9a26c19bbf70c1cb1b8d25eb42e0cce5a001acbe287268aa215c854cb5a9990ff62b7aefa9de221803d172957e",
    ),
}
PLAN9PORT_REVISION = "1f1396913fb5372408f442ed26933f5ae4b399cd"
PLAN9PORT_SHA256 = "b8e7bc424479b9fb86c4ccc9bc7b75b2606b1acbd238b83922eaef9906139375"
PLAN9PORT_URL = "https://codeload.github.com/9fans/plan9port/tar.gz/" + PLAN9PORT_REVISION
U9FS_REVISION = "fcec3e1e2e8e8c28b89270e6c44554c4ca9e50a9"
U9FS_SHA256 = "56887d41253810986cfeb7a8a559b193b5d4c302ace18bff0a03c48f1dea9bcd"
U9FS_URL = "https://codeload.github.com/Plan9-Archive/u9fs/tar.gz/" + U9FS_REVISION


def digest(path: Path, algorithm: str = "sha256") -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def glibc_inputs(directory: Path | None, cache: Path) -> tuple[Path, dict]:
    selected = (directory or (cache / "glibc-abi")).expanduser().resolve()
    tool = HERE.parents[3] / "scripts/build_glibc_abi.py"
    if not selected.exists():
        run([sys.executable, tool, "--output", selected, "--cache", cache / "glibc-packages"])
    run([sys.executable, tool, "--verify", "--output", selected])
    return selected, json.loads((selected / "glibc-abi.json").read_text())


def run(command: list[str | Path], *, log: Path | None = None, env: dict | None = None) -> str:
    result = subprocess.run([str(v) for v in command], env=env, capture_output=True, text=True)
    if log:
        with log.open("a", encoding="utf-8") as stream:
            stream.write(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}: {(result.stdout + result.stderr)[-3000:]}")
    return result.stdout


def fetch(url: str, path: Path) -> Path:
    if not url.startswith("https://"):
        raise ValueError("upstream inputs must use HTTPS")
    if path.is_symlink():
        raise ValueError(f"cache input must not be a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        temporary = path.with_name("." + path.name + ".partial-" + uuid.uuid4().hex)
        try:
            with urllib.request.urlopen(url, timeout=90) as response, temporary.open("xb") as target:
                shutil.copyfileobj(response, target)
                target.flush()
                os.fsync(target.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                if digest(temporary) != digest(path):
                    raise ValueError(f"concurrent download disagreed with immutable cache input: {path}")
        finally:
            temporary.unlink(missing_ok=True)
    return path


def archive_name(name: str) -> str:
    name = name.removeprefix("./")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\x00" in name:
        raise ValueError(f"unsafe archive path: {name}")
    return str(path) if str(path) != "." else ""


def extract_rootfs(archive: Path, root: Path) -> None:
    """Preserve rootfs absolute symlinks, creating them after regular files."""
    root.mkdir()
    with tarfile.open(archive) as tf:
        members = tf.getmembers()
        for member in members:
            name = archive_name(member.name)
            if not name:
                continue
            target = root / name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with tf.extractfile(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
            elif not (member.issym() or member.islnk()):
                raise ValueError(f"unsupported special entry in upstream rootfs: {name}")
            if member.isdir() or member.isfile():
                target.chmod(member.mode)
                os.chown(target, member.uid, member.gid)
        for member in members:
            name = archive_name(member.name)
            if not name:
                continue
            target = root / name
            if member.issym():
                target.symlink_to(member.linkname)
                os.chown(target, member.uid, member.gid, follow_symlinks=False)
            elif member.islnk():
                os.link(root / archive_name(member.linkname), target)


def make_cpio(root: Path, destination: Path, init: Path) -> None:
    """Encode newc without privileged mknod or host cpio conventions."""
    entries = []
    for path in sorted(root.rglob("*")):
        name = str(path.relative_to(root))
        info = path.lstat()
        if path.is_symlink():
            content = os.readlink(path).encode()
        elif path.is_file():
            content = path.read_bytes()
        elif path.is_dir():
            content = b""
        else:
            raise ValueError(f"unsupported initramfs node: {name}")
        entries.append((name, info.st_mode, content, 0, 0))
    entries = [item for item in entries if item[0] not in {"init", "dev/console"}]
    entries.extend([
        ("dev/console", stat.S_IFCHR | 0o600, b"", 5, 1),
        ("init", stat.S_IFREG | 0o755, init.read_bytes(), 0, 0),
    ])
    with destination.open("wb") as stream:
        for inode, (name, mode, content, major, minor) in enumerate(sorted(entries), 1):
            encoded = name.encode() + b"\0"
            fields = [inode, mode, 0, 0, 1, 0, len(content), 0, 0, major, minor, len(encoded), 0]
            header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
            stream.write(header + encoded)
            stream.write(b"\0" * (-stream.tell() % 4))
            stream.write(content)
            stream.write(b"\0" * (-stream.tell() % 4))
        name = b"TRAILER!!!\0"
        fields = [len(entries) + 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(name), 0]
        stream.write(b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + name)
        stream.write(b"\0" * (-stream.tell() % 512))


def write_file(root: Path, name: str, content: str | bytes, mode: int = 0o644) -> None:
    target = root / archive_name(name)
    for parent in target.parents:
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError(f"generated path crosses an upstream symlink: {name}")
    if target.is_symlink():
        raise ValueError(f"generated path would overwrite an upstream symlink: {name}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content.encode() if isinstance(content, str) else content)
    target.chmod(mode)


def prepare(args: argparse.Namespace) -> dict:
    output, cache = args.output.resolve(), args.cache.resolve()
    if output.exists():
        raise ValueError("--output must be new; existing builds and disks are never overwritten")
    if args.disk_bytes < 512 * 1024 * 1024 or args.disk_bytes % 4096:
        raise ValueError("disk must be at least 512MiB and aligned to 4096 bytes")
    for tool in (("gpg",) if args.repository_only else ("gpg", "mke2fs", "debugfs")):
        if shutil.which(tool) is None:
            raise ValueError(f"missing builder dependency: {tool}")
    output.mkdir(parents=True)
    cache.mkdir(parents=True, exist_ok=True)
    metadata = output / "metadata"
    metadata.mkdir()
    # GnuPG still probes its agent socket during public-key import, even with
    # autostart disabled. Keep this public-only temporary home below Unix's
    # socket path limit; retained evidence stays under the requested output.
    gpg_home = tempfile.TemporaryDirectory(prefix="okernel-gpg-")
    gpg = Path(gpg_home.name)
    key = fetch("https://alpinelinux.org/keys/ncopa.asc", cache / "ncopa.asc")
    shutil.copy2(key, metadata / "alpine-release-key.asc")
    # Public-key verification needs no agent. Avoid a background process and
    # Unix-socket path limits in deeply nested private repository stages.
    gpg_command = ["gpg", "--no-options", "--no-autostart", "--homedir", str(gpg), "--batch"]
    run([*gpg_command, "--import", key], log=metadata / "gpg.log")
    fingerprints = run([*gpg_command, "--with-colons", "--fingerprint"])
    if RELEASE_KEY not in fingerprints:
        raise ValueError("upstream release key fingerprint differs from the pinned Alpine trust anchor")
    bootstrap = {}
    for arch in ("x86_64", "aarch64"):
        name = f"alpine-minirootfs-{ALPINE_VERSION}-{arch}.tar.gz"
        url = f"{BASE_URL}/{ALPINE_BRANCH}/releases/{arch}/{name}"
        archive = fetch(url, cache / name)
        signature = fetch(url + ".asc", cache / (name + ".asc"))
        status = run([*gpg_command, "--status-fd", "1", "--verify", signature, archive], log=metadata / "gpg.log")
        if not any(line.startswith("[GNUPG:] VALIDSIG ") and RELEASE_KEY in line.split() for line in status.splitlines()):
            raise ValueError("rootfs signature is not from the pinned Alpine release key")
        bootstrap[arch] = {"url": url, "sha256": digest(archive), "bytes": archive.stat().st_size, "signer": RELEASE_KEY}
        extract_rootfs(archive, output / ("host-tools" if arch == "x86_64" else "rootfs"))
    shutil.copy2(gpg / "pubring.kbx", metadata / "alpine-release-keyring.kbx")
    gpg_home.cleanup()
    host = output / "host-tools"
    root = output / "rootfs"
    apk = [host / "lib/ld-musl-x86_64.so.1", "--library-path", f"{host}/lib:{host}/usr/lib", host / "sbin/apk"]
    keys = host / "usr/share/apk/keys"
    apk_identity = run([*apk, "--version"])
    repositories = output / "repository-cache"
    repository_records = []
    for name in ("main", "community"):
        target = repositories / name / "aarch64"
        target.mkdir(parents=True)
        url = f"{BASE_URL}/{ALPINE_BRANCH}/{name}/aarch64/APKINDEX.tar.gz"
        if args.indexes:
            index = args.indexes.resolve() / name / "aarch64/APKINDEX.tar.gz"
            if index.is_symlink() or not index.is_file():
                raise ValueError(f"expected regular signed repository snapshot: {index}")
        else:
            index = fetch(url, cache / "indexes" / name / "APKINDEX.tar.gz")
        run([*apk, "--keys-dir", keys, "verify", index], log=metadata / "apk-verification.log")
        shutil.copy2(index, target / "APKINDEX.tar.gz")
        repository_records.append({"name": name, "url": url, "index_sha256": digest(index), "signature_verified": True})
    repository_file = output / "solver-repositories"
    repository_file.write_text("\n".join(str(repositories / name) for name in ("main", "community")) + "\n")
    solver = output / "solver-root"
    for name in ("etc/apk", "lib/apk/db", "var/cache/apk"):
        (solver / name).mkdir(parents=True, exist_ok=True)
    apk_cache = output / "apk-cache"
    apk_cache.mkdir()
    packages = list(dict.fromkeys([*DEFAULT_PACKAGES, *(args.package or [])]))
    if not all(re.fullmatch(r"[a-z0-9][a-zA-Z0-9+_.:=~<>!@-]*", name) for name in packages):
        raise ValueError("package names/constraints contain unsupported characters")
    resolution = run([
        *apk, "--arch", "aarch64", "--root", solver, "--keys-dir", keys,
        "--repositories-file", repository_file, "--cache-dir", apk_cache,
        "fetch", "--recursive", "--simulate", "--url", *packages,
    ], log=metadata / "apk-solver.log")
    selected = []
    for line in resolution.splitlines():
        target = Path(line)
        relative = target.relative_to(repositories)
        if len(relative.parts) != 3 or relative.parts[0] not in {"main", "community"} or relative.parts[1] != "aarch64" or target.suffix != ".apk":
            raise ValueError("original apk solver returned an unexpected repository member")
        selected.append((target, f"{BASE_URL}/{ALPINE_BRANCH}/{relative.as_posix()}"))
    if not selected:
        raise ValueError("original apk solver returned no complete package closure")
    def download(item):
        target, url = item
        saved = fetch(url, cache / "packages" / target.name)
        shutil.copy2(saved, target)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(download, selected))
    run([*apk, "--keys-dir", keys, "verify", *[item[0] for item in selected]], log=metadata / "apk-verification.log")
    package_records = [
        {"filename": path.name, "repository": path.parent.parent.name, "url": url, "sha256": digest(path), "bytes": path.stat().st_size, "signature_verified": True}
        for path, url in selected
    ]
    if args.repository_only:
        return {
            "schema": "ostadix.linux-package-repository/v1", "architecture": "aarch64",
            "alpine_version": ALPINE_VERSION, "upstream_bootstrap": bootstrap,
            "apk_host_tool": apk_identity.strip(), "repository_snapshots": repository_records,
            "requested_packages": packages, "offline_package_closure": package_records,
            "repositories_path": str(repositories),
            "scope": "Authenticated offline repository transport only; packages are not installed or executed by this host-side builder.",
        }
    abi_directory, abi_manifest = glibc_inputs(args.glibc_abi, cache)
    shutil.copytree(repositories, root / "repositories")
    write_file(root, "etc/apk/repositories", "/repositories/main\n/repositories/community\n")
    # Alpine's architecture-selected key set is already in the rootfs.
    write_file(root, "sbin/package-domain-init", (HERE / "package-domain-init").read_bytes(), 0o755)
    write_file(root, "usr/local/bin/pkg", (HERE / "pkg").read_bytes(), 0o755)
    write_file(root, "usr/local/bin/pkg-net", (HERE / "pkg-net").read_bytes(), 0o755)
    write_file(root, "usr/local/bin/pkg-namespace", (HERE / "pkg-namespace").read_bytes(), 0o755)
    write_file(root, "usr/local/libexec/pkg-plan9port", (HERE / "pkg-plan9port").read_bytes(), 0o755)
    write_file(root, "usr/local/bin/pkg-9p", (HERE / "pkg-9p").read_bytes(), 0o755)
    write_file(root, "usr/local/libexec/okernel-9p-bridge.c", (HERE / "okernel-9p-bridge.c").read_bytes(), 0o644)
    write_file(root, "usr/local/libexec/u9fs-path-hardening.patch", (HERE / "u9fs-path-hardening.patch").read_bytes(), 0o644)
    write_file(root, "usr/local/libexec/glibc-cc", (HERE / "glibc-cc").read_bytes(), 0o755)
    write_file(root, "usr/local/libexec/plan9port-activate", (HERE / "plan9port-activate").read_bytes(), 0o755)
    for name in ("glibc-abi.tar.gz", "glibc-abi.json"):
        write_file(root, "usr/local/libexec/" + name, (abi_directory / name).read_bytes(), 0o644)
    write_file(root, "usr/local/libexec/glibc-abi.sha256", abi_manifest["bundle"]["sha256"] + "\n", 0o644)
    for command in ("status", "okernel-status"):
        write_file(root, "usr/local/bin/" + command, (HERE / "okernel-status").read_bytes(), 0o755)
    write_file(root, "usr/local/libexec/pkg-net-udhcpc", (HERE / "pkg-net-udhcpc").read_bytes(), 0o755)
    write_file(root, "etc/profile", "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nexport PS1='pkg> '\n")
    for name in ("work", "run", "tmp", "proc", "sys", "dev/pts", "newroot"):
        (root / name).mkdir(parents=True, exist_ok=True)
    source_records = []
    for name, (url, expected) in SOURCE_FILES.items():
        source = fetch(url, cache / "sources" / name)
        if digest(source, "sha512") != expected:
            raise ValueError(f"upstream source differs from pinned Alpine APKBUILD SHA512: {name}")
        write_file(root, "sources/zlib/" + name, source.read_bytes())
        source_records.append({"name": name, "url": url, "sha512": expected, "sha256": digest(source)})
    write_file(root, "sources/zlib/SHA512SUMS", "".join(f"{expected}  {name}\n" for name, (_, expected) in SOURCE_FILES.items()))
    write_file(root, "sources/zlib/PROVENANCE", "Checksums and security patch from Alpine aports 3.24-stable/main/zlib/APKBUILD.\nOriginal upstream zlib configure, Makefile and tests are run inside the Linux guest.\n")
    plan9port_name = "plan9port-" + PLAN9PORT_REVISION + ".tar.gz"
    plan9port_archive = fetch(PLAN9PORT_URL, cache / "plan9port" / plan9port_name)
    if digest(plan9port_archive) != PLAN9PORT_SHA256:
        raise ValueError("upstream Plan9port archive differs from the pinned official source revision")
    write_file(root, "sources/plan9port/" + plan9port_name, plan9port_archive.read_bytes())
    plan9port_records = [{"name": plan9port_name, "url": PLAN9PORT_URL, "revision": PLAN9PORT_REVISION, "sha256": PLAN9PORT_SHA256}]
    u9fs_name = "u9fs-" + U9FS_REVISION + ".tar.gz"
    u9fs_archive = fetch(U9FS_URL, cache / "u9fs" / u9fs_name)
    if digest(u9fs_archive) != U9FS_SHA256:
        raise ValueError("original u9fs archive differs from the pinned source revision")
    write_file(root, "sources/u9fs/" + u9fs_name, u9fs_archive.read_bytes())
    plan9port_records.append({"name": u9fs_name, "url": U9FS_URL, "revision": U9FS_REVISION, "sha256": U9FS_SHA256})
    initramfs = output / "initramfs.cpio"
    # Boot archive only needs the signed mini rootfs, not the repository disk.
    boot_root = output / "boot-rootfs"
    extract_rootfs(cache / f"alpine-minirootfs-{ALPINE_VERSION}-aarch64.tar.gz", boot_root)
    make_cpio(boot_root, initramfs, HERE / "init")
    with initramfs.open("rb") as source, (output / "initramfs.cpio.gz").open("wb") as target:
        with gzip.GzipFile(filename="", fileobj=target, mode="wb", mtime=0) as compressed:
            shutil.copyfileobj(source, compressed)
    # Normalize generated and extracted root metadata under fakeroot.
    for path in [root, *sorted(root.rglob("*"))]:
        os.chown(path, 0, 0, follow_symlinks=False)
        os.utime(path, (0, 0), follow_symlinks=False)
    image = output / "package-domain.ext4"
    with image.open("xb") as stream:
        stream.truncate(args.disk_bytes)
    image_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, "ostadix-package-domain/" + json.dumps([bootstrap, package_records, source_records, plan9port_records, abi_manifest["bundle"]], sort_keys=True)))
    env = {**os.environ, "E2FSPROGS_FAKE_TIME": "1", "SOURCE_DATE_EPOCH": "1"}
    run([
        "mke2fs", "-q", "-t", "ext4", "-F", "-b", "4096", "-m", "0", "-L", "okernel-root",
        "-U", image_uuid, "-E", f"hash_seed={image_uuid},lazy_itable_init=0,lazy_journal_init=0",
        "-d", root, image,
    ], log=metadata / "mke2fs.log", env=env)
    # mke2fs imports host ctime, which utime cannot normalize. Set all copied
    # inode timestamps explicitly so rebuilds do not inherit build-wall-clock.
    timestamps = metadata / "normalize-inodes.debugfs"
    commands = []
    for path in [root, *sorted(root.rglob("*"))]:
        name = "/" + str(path.relative_to(root)) if path != root else "/"
        quoted = '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'
        for field in ("atime", "mtime", "ctime", "crtime"):
            commands.append(f"set_inode_field {quoted} {field} 0")
    timestamps.write_text("\n".join(commands) + "\n")
    run(["debugfs", "-w", "-f", timestamps, image], log=metadata / "mke2fs.log", env=env)
    filesystem = run(["debugfs", "-R", "stats", image])
    (metadata / "filesystem.txt").write_text(filesystem)
    artifacts = {
        name: {"path": str(output / name), "bytes": (output / name).stat().st_size, "sha256": digest(output / name)}
        for name in ("initramfs.cpio", "initramfs.cpio.gz", "package-domain.ext4")
    }
    return {
        "schema": "ostadix.linux-package-domain/v1", "architecture": "aarch64", "alpine_version": ALPINE_VERSION,
        "upstream_bootstrap": bootstrap, "apk_host_tool": apk_identity.strip(), "repository_snapshots": repository_records,
        "requested_packages": packages, "offline_package_closure": package_records, "source_providers": {"zlib": source_records, "plan9port": plan9port_records},
        "private_gnu_libc_abi": {"bundle": abi_manifest["bundle"], "manifest_sha256": digest(abi_directory / "glibc-abi.json"),
                                 "packages": abi_manifest["packages"], "profile": "private original GNU libc for source-compiled u9fs only"},
        "artifacts": artifacts, "disk_uuid": image_uuid, "disk_bytes": args.disk_bytes,
        "guest_ready_marker": "OKERNEL PACKAGE DOMAIN READY", "guest_prompt": "pkg> ",
        "guest_programs": {name: {"sha256": digest(HERE / name)} for name in ("init", "package-domain-init", "pkg", "pkg-net", "pkg-net-udhcpc", "pkg-namespace", "pkg-plan9port", "pkg-9p", "glibc-cc", "plan9port-activate", "okernel-status")},
        "guest_source_inputs": {name: {"sha256": digest(HERE / name)} for name in ("okernel-9p-bridge.c", "u9fs-path-hardening.patch")},
        "scope": "Original Alpine Linux userland and package/source tools inside an O-core-governed Linux guest; not source lowering of Linux or packages to O-core.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache/ostadix/package-domain")
    parser.add_argument("--disk-bytes", type=int, default=1073741824)
    parser.add_argument("--package", action="append", help="stage an additional APK package and its complete dependency closure; repeatable")
    parser.add_argument("--repository-only", action="store_true", help="build only an authenticated offline repository bundle; no root disk")
    parser.add_argument("--indexes", type=Path, help="reuse and reverify exact main/community signed indexes from this directory")
    parser.add_argument("--glibc-abi", type=Path, help="reuse and fully reverify an original signed ARM64 GNU libc dependency bundle")
    args = parser.parse_args()
    if os.geteuid() != 0:
        if shutil.which("fakeroot") is None:
            parser.error("fakeroot is required to preserve guest root ownership without root privileges")
        forwarded = list(sys.argv[1:])
        # Capture/verify APT dependencies before fakeroot changes the identity
        # reported to native tools. The rootfs child rechecks the frozen input.
        if not args.repository_only:
            try:
                directory, _ = glibc_inputs(args.glibc_abi, args.cache.expanduser().resolve())
            except (OSError, ValueError, RuntimeError) as error:
                print(f"Package-domain GNU ABI preparation failed: {error}", file=sys.stderr)
                return 1
            if args.glibc_abi is None:
                forwarded.extend(["--glibc-abi", str(directory)])
        os.execvp("fakeroot", ["fakeroot", "--", sys.executable, str(Path(__file__).resolve()), *forwarded])
    try:
        result = prepare(args)
        manifest = args.output.resolve() / ("repository-bundle.json" if args.repository_only else "package-domain.json")
        manifest.write_text(json.dumps(result, indent=2) + "\n")
        print(f"Package-domain build: PASS\nManifest: {manifest}")
        for name, record in result.get("artifacts", {}).items():
            print(f"{name}: {record['path']} ({record['bytes']} bytes; sha256 {record['sha256']})")
        return 0
    except (OSError, ValueError, RuntimeError, tarfile.TarError) as error:
        print(f"Package-domain build: FAIL\n{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
