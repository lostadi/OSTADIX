#!/usr/bin/env python3
"""Rebuild the native console GPT image twice and boot its exact bytes via UEFI.

Use an immutable source export, such as source-1 from verify_okernel_repro.py.
Only a new output directory is written. No physical device or firmware settings
are opened for writing. QEMU uses read-only firmware/media and no network.
"""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import time


SCOPE = (
    "Two byte-identical mode-16 GPT/ESP images, strict container inspection, "
    "and help/status interaction after booting the first exact image through "
    "OVMF/QEMU TCG. This does not prove physical boot, native shell/filesystem "
    "support, a reproducible compiler bootstrap, or hermetic host tools."
)
SERVICE_MARKERS = tuple(
    f"M5 {service} service ELF: online\n".encode()
    for service in ("init", "supervisor", "pkgd", "repl")
)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def executable(value: str | Path) -> Path:
    found = shutil.which(str(value))
    if found is None:
        raise ValueError(f"executable not found: {value}")
    result = Path(found).resolve(strict=True)
    if not result.is_file():
        raise ValueError(f"not a regular executable file: {result}")
    return result


def identity(path: Path) -> dict:
    result = {"path": str(path), "sha256": sha256(path), "bytes": path.stat().st_size}
    if os.access(path, os.X_OK):
        version = subprocess.run([str(path), "--version"], capture_output=True, text=True)
        result["version_output"] = (version.stdout + version.stderr).strip()[:3000]
    return result


def source_manifest(source: Path) -> tuple[list[dict], str]:
    entries = []
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if relative.parts[0] in {".git", "target", "__pycache__"} or "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            entries.append({"path": str(relative), "link": os.readlink(path)})
        elif path.is_file():
            entries.append({"path": str(relative), "mode": path.stat().st_mode & 0o777, "sha256": sha256(path)})
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return entries, hashlib.sha256(encoded).hexdigest()


def select_linker(source: Path, explicit: str | None) -> Path:
    if explicit or os.environ.get("OCORE_LLD"):
        return executable(explicit or os.environ["OCORE_LLD"])
    sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], cwd=source, text=True).strip()
    version = subprocess.check_output(["rustc", "-vV"], cwd=source, text=True)
    host = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
    return executable(Path(sysroot) / "lib" / "rustlib" / host / "bin" / "rust-lld")


def build_image(source: Path, build: Path, compiler: Path, tools_dir: Path, linker: Path) -> Path:
    build.mkdir()
    image = build / "okernel-console.img"
    env = os.environ.copy()
    for key in ("OSTADIX_BOOT_CHALLENGE", "OCORE_BUILD_DIR", "OCORE_PROBE_MODE"):
        env.pop(key, None)
    env.update(
        OCOREC_BIN=str(compiler), OCORE_LLD=str(linker),
        OCORE_MEDIA_PROBE_MODE="16", OCORE_M5_BUILD_DIR=str(build / "m5"),
        OCORE_MEDIA_KERNEL_BUILD_DIR=str(build / "kernel"), OSTADIX_MEDIA_ROOT=str(build / "media"),
        O_LANG_ROOT=str(source), O_BACKENDS_DIR=str(source / "backends"),
        CARGO_BUILD_JOBS="2", CARGO_NET_OFFLINE="true", PYTHONDONTWRITEBYTECODE="1",
        LC_ALL="C", TZ="UTC", SOURCE_DATE_EPOCH="315532800",
        PATH=str(tools_dir) + os.pathsep + os.environ["PATH"],
    )
    command = ["bash", str(source / "ocore/kernel/build-x86_64-uefi-media.sh"), str(image)]
    (build / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    print(f"Building console UEFI media: {image}", flush=True)
    with (build / "build.log").open("wb") as log:
        process = subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300)
    if process.returncode:
        tail = (build / "build.log").read_text(errors="replace")[-4000:]
        raise RuntimeError(f"media build failed ({process.returncode}): {build / 'build.log'}\n{tail}")
    if not image.is_file() or image.is_symlink():
        raise RuntimeError("media builder did not produce a regular image")
    return image


def boot_console(image: Path, qemu: Path, firmware: Path, output: Path, timeout: float) -> dict:
    # QEMU's -drive parser uses doubled commas within an option value.
    image_option = str(image).replace(",", ",,")
    firmware_option = str(firmware).replace(",", ",,")
    command = [
        str(qemu), "-accel", "tcg", "-machine", "q35", "-m", "128M",
        "-drive", f"if=pflash,unit=0,format=raw,readonly=on,file={firmware_option}",
        "-drive", f"if=none,id=ostadix,format=raw,readonly=on,file={image_option}",
        "-device", "virtio-blk-pci,drive=ostadix", "-nodefaults", "-nic", "none",
        "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot", "-no-shutdown",
    ]
    (output / "qemu-command.json").write_text(json.dumps(command, indent=2) + "\n")
    capture = {"stdout": bytearray(), "stderr": bytearray()}
    inputs = []
    process = None
    started = time.monotonic()
    help_sent = status_sent = False
    healthy_since = None
    with selectors.DefaultSelector() as selector, (output / "serial.log").open("wb") as serial, (output / "qemu-stderr.log").open("wb") as errors:
        streams = {"stdout": serial, "stderr": errors}
        try:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while time.monotonic() - started < timeout:
                if process.poll() is not None:
                    raise RuntimeError(f"QEMU exited before console verification ({process.returncode})")
                for key, _ in selector.select(0.05):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    capture[key.data].extend(chunk)
                    streams[key.data].write(chunk)
                    streams[key.data].flush()
                    if sum(len(value) for value in capture.values()) > 4 * 1024 * 1024:
                        raise RuntimeError("QEMU output exceeded the 4 MiB verification capture bound")
                transcript = bytes(capture["stdout"]).replace(b"\r\n", b"\n")
                lower = (transcript + bytes(capture["stderr"])).lower()
                if any(marker in lower for marker in (b"kernel panic", b"triple fault", b": fail", b"m5 serial command: rejected", b"deliberate fault")):
                    raise RuntimeError("unexpected fault or command rejection during console boot")
                if not help_sent and all(marker in transcript for marker in SERVICE_MARKERS) and transcript.endswith(b"o> "):
                    process.stdin.write(b"help\n")
                    process.stdin.flush()
                    inputs.append({"seconds": time.monotonic() - started, "input": "help\\n"})
                    help_sent = True
                elif help_sent and not status_sent and b"OKernel native service console\n" in transcript and transcript.count(b"o> ") >= 2 and transcript.endswith(b"o> "):
                    process.stdin.write(b"status\n")
                    process.stdin.flush()
                    inputs.append({"seconds": time.monotonic() - started, "input": "status\\n"})
                    status_sent = True
                elif status_sent and b"M5 serial status: PASS\n" in transcript and transcript.count(b"o> ") >= 3:
                    if healthy_since is None:
                        healthy_since = time.monotonic()
                    if time.monotonic() - healthy_since >= 1:
                        return {"help": True, "status": True, "survived_seconds": 1, "inputs": inputs, "argv": command}
            raise RuntimeError(f"UEFI console interaction timed out after {timeout:g} seconds")
        finally:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                for name in ("stdout", "stderr"):
                    stream = getattr(process, name)
                    if stream is not None:
                        tail = stream.read()
                        if tail:
                            capture[name].extend(tail)
                            streams[name].write(tail)
                        stream.close()
                if process.stdin is not None:
                    process.stdin.close()
            (output / "console-inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ocorec", required=True)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--firmware", type=Path, default=Path("/usr/share/OVMF/OVMF_CODE_4M.fd"))
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--lld")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    if output.is_relative_to(source) or source.is_relative_to(output):
        parser.error("--output must be a new directory outside the source tree")
    if not (source / "ocore/kernel/build-x86_64-uefi-media.sh").is_file():
        parser.error("--source lacks the native UEFI media builder")
    if args.timeout < 2 or args.timeout > 300:
        parser.error("--timeout must be between 2 and 300 seconds")
    output.mkdir(parents=True, exist_ok=False)
    evidence = {"schema": "ostadix.okernel-console-media-verification/v1", "ok": False, "scope": SCOPE, "source": str(source), "tools": {}}
    result_path = output / "evidence.json"
    try:
        compiler = executable(args.ocorec)
        qemu = executable(args.qemu)
        firmware = args.firmware.resolve(strict=True)
        if not firmware.is_file():
            raise ValueError("--firmware must be a regular file")
        linker = select_linker(source, args.lld)
        selected = {"ocorec": compiler, "qemu": qemu, "firmware": firmware, "lld": linker, "clang": executable(args.clang)}
        selected.update({name: executable(name) for name in ("grub-mkstandalone", "mformat", "mcopy", "python3")})
        evidence["tools"] = {name: identity(path) for name, path in selected.items()}
        entries, source_hash = source_manifest(source)
        (output / "source-files.json").write_text(json.dumps(entries, indent=2) + "\n")
        evidence["source_sha256"] = source_hash
        bin_dir = output / "bin"
        bin_dir.mkdir()
        for name in ("clang", "grub-mkstandalone", "mformat", "mcopy", "python3"):
            (bin_dir / name).symlink_to(selected[name])
        frozen_compiler = output / "ocorec"
        shutil.copy2(compiler, frozen_compiler)
        if sha256(frozen_compiler) != evidence["tools"]["ocorec"]["sha256"]:
            raise RuntimeError("compiler changed while its frozen copy was being made")
        images = [build_image(source, output / f"build-{number}", frozen_compiler, bin_dir, linker) for number in (1, 2)]
        if not filecmp.cmp(images[0], images[1], shallow=False):
            raise RuntimeError("complete console GPT images are not byte-identical")
        inspector_env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        inspected = subprocess.run([str(selected["python3"]), str(source / "scripts/ostadix_boot_media.py"), "inspect", str(images[0])], cwd=source, env=inspector_env, capture_output=True, text=True, check=True)
        metadata = json.loads(inspected.stdout)
        (output / "inspect.json").write_text(json.dumps(metadata, indent=2) + "\n")
        expected_hash = sha256(images[0])
        if metadata["sha256"] != expected_hash or metadata["bytes"] != images[0].stat().st_size:
            raise RuntimeError("strict inspector disagrees with media bytes")
        evidence["media"] = {"first": str(images[0]), "second": str(images[1]), "sha256": expected_hash, "bytes": images[0].stat().st_size, "byte_identical": True}
        evidence["console"] = boot_console(images[0], qemu, firmware, output, args.timeout)
        if any(sha256(path) != evidence["tools"][name]["sha256"] for name, path in selected.items()):
            raise RuntimeError("a selected build or boot tool changed during verification")
        if sha256(frozen_compiler) != evidence["tools"]["ocorec"]["sha256"]:
            raise RuntimeError("frozen compiler changed during verification")
        if sha256(images[0]) != expected_hash or sha256(images[1]) != expected_hash:
            raise RuntimeError("media bytes changed during read-only boot verification")
        if source_manifest(source)[1] != source_hash:
            raise RuntimeError("source changed during media verification")
        evidence["ok"] = True
        print("OKernel console UEFI media reproduction and interaction: PASS")
        print(f"Media SHA-256: {expected_hash}")
        print(f"Image: {images[0]}\nEvidence: {result_path}")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError, StopIteration) as error:
        evidence["error"] = str(error)
        print(f"OKernel console UEFI media verification: FAIL\n{error}\nEvidence: {result_path}", file=sys.stderr)
        return 1
    finally:
        result_path.write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
