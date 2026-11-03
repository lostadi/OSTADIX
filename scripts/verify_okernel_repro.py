#!/usr/bin/env python3
"""Rebuild mode 16 twice from one immutable source snapshot and compare bytes.

This verifies kernel/service reproduction using one supplied, hash-recorded
ocorec binary. It does not claim reproducible compiler bootstrap or a hermetic
host toolchain. Existing source changes, the branch and the real Git index are
preserved. Requires Python 3.12 or later. The output must be a new directory
outside the source checkout.
"""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile


SERVICES = ("init", "supervisor", "pkgd", "repl")
SCOPE = (
    "Two independent source/output directories, one immutable source archive, "
    "and one frozen prebuilt compiler. Proves byte-identical kernel, native "
    "service ELFs and OVFS using the recorded host tools; does not prove "
    "compiler bootstrap reproducibility or hermetic host dependencies."
)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def capture(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(
            f"{command[0]} exited {result.returncode}: {(result.stderr or result.stdout).strip()[-3000:]}"
        )
    return result.stdout.strip()


def executable(value: str | Path) -> Path:
    selected = shutil.which(str(value))
    if selected is None:
        raise ValueError(f"executable not found: {value}")
    path = Path(selected).resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"executable is not a regular file: {path}")
    return path


def tool_identity(path: Path, cwd: Path, version: bool = True) -> dict:
    result = {"path": str(path), "sha256": sha256(path), "bytes": path.stat().st_size}
    if version:
        arguments = ["-flavor", "gnu", "--version"] if path.name in ("rust-lld", "lld") else ["--version"]
        result["version"] = capture([str(path), *arguments], cwd=cwd)
    if sys.platform.startswith("linux") and shutil.which("ldd"):
        linked = subprocess.run(["ldd", str(path)], cwd=cwd, capture_output=True, text=True)
        result["host_dynamic_dependencies"] = (linked.stdout + linked.stderr).strip()
    return result


def source_snapshot(source: Path, output: Path) -> dict:
    """Use a private index to include staged, unstaged and untracked source."""
    index = output / "snapshot.index"
    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(key, None)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    git = ["git", "-C", str(source)]
    top = Path(capture(git + ["rev-parse", "--show-toplevel"], cwd=source, env=env)).resolve()
    if top != source:
        raise ValueError("--source must be the Git checkout root")
    head = capture(git + ["rev-parse", "HEAD"], cwd=source, env=env)
    status = capture(git + ["status", "--short", "--untracked-files=all"], cwd=source, env=env)
    (output / "original-status.txt").write_text(status + "\n", encoding="utf-8")
    env["GIT_INDEX_FILE"] = str(index)
    try:
        capture(git + ["read-tree", "HEAD"], cwd=source, env=env)
        capture(git + ["add", "-A", "--", "."], cwd=source, env=env)
        tree = capture(git + ["write-tree"], cwd=source, env=env)
        capture(git + ["diff", "--quiet", "--no-ext-diff", "--", "."], cwd=source, env=env)
        if capture(git + ["ls-files", "--others", "--exclude-standard"], cwd=source, env=env):
            raise RuntimeError("new source appeared during snapshot; retry after editing finishes")
        archive = output / "source.tar"
        capture(
            git + ["archive", "--format=tar", "--mtime=@0", "--output", str(archive), tree],
            cwd=source, env=env,
        )
    finally:
        index.unlink(missing_ok=True)
        index.with_name(index.name + ".lock").unlink(missing_ok=True)
    entries = []
    with tarfile.open(archive) as tf:
        for member in tf.getmembers():
            if member.isfile():
                stream = tf.extractfile(member)
                assert stream is not None
                entries.append({
                    "path": member.name,
                    "mode": member.mode,
                    "bytes": member.size,
                    "sha256": hashlib.sha256(stream.read()).hexdigest(),
                })
            elif member.issym():
                entries.append({"path": member.name, "mode": member.mode, "symlink": member.linkname})
    (output / "source-files.json").write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return {
        "head": head,
        "tree": tree,
        "archive": str(archive),
        "archive_sha256": sha256(archive),
        "manifest_sha256": sha256(output / "source-files.json"),
        "cargo_lock_sha256": next(entry["sha256"] for entry in entries if entry["path"] == "Cargo.lock"),
    }


def extract_source(archive: Path, destination: Path) -> None:
    destination.mkdir()
    with tarfile.open(archive) as tf:
        tf.extractall(destination, filter="data")
    for required in ("Cargo.lock", "ocore/kernel/build.sh", "ocore/kernel/build-m5-artifacts.sh"):
        if not (destination / required).is_file():
            raise ValueError(f"source archive is missing {required}")


def build(source: Path, destination: Path, compiler: Path, bin_dir: Path, linker: Path) -> dict[str, Path]:
    env = os.environ.copy()
    env.update(
        OCOREC_BIN=str(compiler), OCORE_BUILD_DIR=str(destination),
        OCORE_M5_BUILD_DIR=str(destination / "m5"), OCORE_PROBE_MODE="16",
        OCORE_BOOT_INFO_ENABLED="0", OCORE_LLD=str(linker),
        O_LANG_ROOT=str(source), O_BACKENDS_DIR=str(source / "backends"),
        CARGO_BUILD_JOBS="2", CARGO_NET_OFFLINE="true", LC_ALL="C", TZ="UTC",
        SOURCE_DATE_EPOCH="0", PYTHONDONTWRITEBYTECODE="1",
        PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
    )
    destination.mkdir()
    log = destination / "build.log"
    print(f"Building mode 16: {source} -> {destination}", flush=True)
    with log.open("wb") as stream:
        result = subprocess.run(
            ["bash", str(source / "ocore/kernel/build.sh")], cwd=source,
            env=env, stdout=stream, stderr=subprocess.STDOUT,
        )
    if result.returncode:
        tail = log.read_text(errors="replace")[-3000:]
        raise RuntimeError(f"build failed ({result.returncode}); log: {log}\n{tail}")
    identity = json.loads((destination / "m5.image.json").read_text())
    image = Path(identity["image"])
    if image.parent != destination / "m5" / "images" or sha256(image) != identity["sha256"]:
        raise RuntimeError("M5 image escaped the isolated build or does not match its identity")
    products = {"kernel.elf": destination / "kernel.elf", "root.ovfs": image}
    products.update({f"{name}.elf": destination / "m5" / "pass-one" / f"{name}.elf" for name in SERVICES})
    return products


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory outside source")
    parser.add_argument("--ocorec", type=Path, help="prebuilt compiler; defaults to source/target/debug/ocorec")
    parser.add_argument("--clang", help="assembler executable; defaults to clang from PATH")
    parser.add_argument("--lld", help="LLD executable; defaults to OCORE_LLD or Rust's linker")
    parser.add_argument("--qemu", help="record this QEMU executable (no VM is started by this verifier)")
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        parser.error("Python 3.12 or later is required for safe archive extraction")
    source, output = args.source.resolve(), args.output.resolve()
    if output == source or source in output.parents:
        parser.error("--output must be outside the source checkout")
    if output.exists():
        parser.error("--output must be a new directory; existing evidence is never overwritten")
    output.mkdir(parents=True, mode=0o700)
    evidence: dict = {"ok": False, "scope": SCOPE, "source": {}, "tools": {}, "outputs": {}}
    result_path = output / "result.json"
    try:
        compiler = executable(args.ocorec or os.environ.get("OCOREC_BIN") or source / "target/debug/ocorec")
        clang = executable(args.clang or "clang")
        sysroot = capture(["rustc", "--print", "sysroot"], cwd=source)
        rust_info = capture(["rustc", "-vV"], cwd=source)
        host = next(line.removeprefix("host: ") for line in rust_info.splitlines() if line.startswith("host: "))
        linker = executable(args.lld or os.environ.get("OCORE_LLD") or Path(sysroot) / "lib/rustlib" / host / "bin/rust-lld")
        evidence["host"] = {"platform": platform.platform(), "python": sys.version}
        evidence["source"] = source_snapshot(source, output)
        tools = output / "tools"
        tools.mkdir()
        frozen_compiler = tools / "ocorec"
        shutil.copy2(compiler, frozen_compiler)
        frozen_compiler.chmod(0o755)
        bin_dir = tools / "bin"
        bin_dir.mkdir()
        (bin_dir / "clang").symlink_to(clang)
        (bin_dir / "python3").symlink_to(Path(sys.executable).resolve())
        evidence["tools"]["ocorec"] = tool_identity(compiler, source, version=False)
        evidence["tools"]["ocorec"]["frozen_path"] = str(frozen_compiler)
        if sha256(frozen_compiler) != evidence["tools"]["ocorec"]["sha256"]:
            raise RuntimeError("compiler changed while its frozen copy was being made")
        for name, path in (("clang", clang), ("lld", linker), ("python", Path(sys.executable).resolve())):
            evidence["tools"][name] = tool_identity(path, source)
        for name in ("cargo", "rustc"):
            path = Path(sysroot) / "bin" / name
            evidence["tools"][name] = tool_identity(path, source)
        if args.qemu:
            evidence["tools"]["qemu"] = tool_identity(executable(args.qemu), source)
        result_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        products = []
        for index in (1, 2):
            snapshot = output / f"source-{index}"
            extract_source(Path(evidence["source"]["archive"]), snapshot)
            products.append(build(snapshot, output / f"build-{index}", frozen_compiler, bin_dir, linker))
        for name, first in products[0].items():
            second = products[1][name]
            if not filecmp.cmp(first, second, shallow=False):
                raise RuntimeError(f"{name} is not byte-identical between independent builds")
            evidence["outputs"][name] = {
                "sha256": sha256(first), "bytes": first.stat().st_size,
                "first": str(first), "second": str(second), "byte_identical": True,
            }
        for name in ("clang", "lld", "python", "cargo", "rustc"):
            identity = evidence["tools"][name]
            if sha256(Path(identity["path"])) != identity["sha256"]:
                raise RuntimeError(f"{name} changed during verification")
        if sha256(frozen_compiler) != evidence["tools"]["ocorec"]["sha256"]:
            raise RuntimeError("frozen compiler changed during verification")
        evidence["ok"] = True
        print("OKernel mode-16 independent rebuild: PASS")
        for name, identity in evidence["outputs"].items():
            print(f"{name}: {identity['sha256']} ({identity['bytes']} bytes)")
        print(f"Evidence: {result_path}")
        return 0
    except (OSError, ValueError, RuntimeError, tarfile.TarError, StopIteration) as error:
        evidence["error"] = str(error)
        print(f"OKernel mode-16 independent rebuild: FAIL\n{error}", file=sys.stderr)
        print(f"Evidence: {result_path}", file=sys.stderr)
        return 1
    finally:
        result_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
