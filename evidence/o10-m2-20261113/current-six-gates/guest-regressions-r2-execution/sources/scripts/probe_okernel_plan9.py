#!/usr/bin/env python3
"""Run the unmodified official 9front ARM64 kernel beneath an isolated O-core EL2.

This component probe never opens the working Linux disk/head, assigns no disk
or network, and does not claim a shared namespace or a complete merged OS.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import secrets
import selectors
import shutil
import socket
import struct
import subprocess
import sys
import time
import zlib


ROOT = Path(__file__).resolve().parents[1]
BUILD = "12115"
COMMIT = "350266104f1fed81c78c3d05fa44f523bec0ae4d"
URL = "https://build.9front.org/9front/9front-12115.arm64.qcow2.gz"
ARCHIVE_BYTES = 297523045
ARCHIVE_SHA256 = "5d148190fba4d0ceab491b2afe2639e01c9abd8cb21f93c1ec7ac814a6f2c584"
QCOW_BYTES = 597164032
UIMAGE_BYTES = 4292048
UIMAGE_SHA256 = "df704b7fff3417eeb9924fed7170fed5e0aeb52829d11fabcbf4e9f6732b34ae"
DERIVATION_BUILDER_SHA256 = "4eec79e738476474c2acc859760be7a97beeb35b9904d460b1cccf06be2c720b"
UART_PATCH_SHA256 = "9e264301ac0f6311e3790caaefe9996138af63e62bd6c15da3fac8073b0593d3"
UART_DERIVED_SHA256 = "f3c0ec64beafeae20bb5f3fc859724fb648ae8d0109045ba6ae7f77f9a0a8c8c"


def identity(path: Path) -> dict:
    with path.open("rb") as stream:
        fingerprint = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": fingerprint}


def inspect_uimage(path: Path) -> tuple[dict, bytes]:
    blob = path.read_bytes()
    if len(blob) < 64:
        raise ValueError("truncated original Plan9 uImage header")
    magic, checksum, timestamp, length, load, entry, data_crc, os_id, arch, kind, compression, name = struct.unpack(">7I4B32s", blob[:64])
    check = bytearray(blob[:64]); check[4:8] = bytes(4)
    if magic != 0x27051956 or zlib.crc32(check) != checksum:
        raise ValueError("invalid original Plan9 uImage header/CRC")
    payload = blob[64:]
    if length != len(payload) or zlib.crc32(payload) != data_crc:
        raise ValueError("invalid original Plan9 uImage payload length/CRC")
    if (os_id, arch, kind, compression, load, entry) != (23, 22, 2, 0, 0x40100000, 0x40100000):
        raise ValueError("unexpected original Plan9 ARM64 container/entry contract")
    if not 0 < length <= 0x07000000:
        raise ValueError("original Plan9 kernel exceeds the explicitly granted RAM layout")
    return {"os": os_id, "architecture": arch, "kind": kind, "compression": compression,
            "load": load, "entry": entry, "timestamp": timestamp, "name": name.rstrip(bytes(1)).decode("ascii"),
            "header_crc32": checksum, "payload_crc32": data_crc, "payload_bytes": length}, payload


def prepare_archive(archive: Path, output: Path, records: dict) -> Path:
    selected = output / "official.qcow2.gz"
    shutil.copyfile(archive, selected)
    admitted = identity(selected)
    if admitted["bytes"] != ARCHIVE_BYTES or admitted["sha256"] != ARCHIVE_SHA256:
        raise ValueError("official archive differs from its explicit observed build12115 pin")
    selected.chmod(0o400)
    records["distribution"] = {"url": URL, "build": BUILD, "source_commit": COMMIT, "archive": admitted,
                               "integrity": "explicit repository-observed SHA256 pin; no upstream signature verification claimed"}
    image = output / "official.qcow2"
    with gzip.open(selected, "rb") as source, image.open("xb") as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
    if image.stat().st_size != QCOW_BYTES:
        raise ValueError("expanded official image differs from its recorded build size")
    records["distribution"]["qcow2"] = identity(image)
    image.chmod(0o400)
    info = subprocess.run(["qemu-img", "info", "--output", "json", "-f", "qcow2", str(image)], check=True, capture_output=True, text=True)
    geometry = json.loads(info.stdout)
    if geometry.get("format") != "qcow2" or geometry.get("backing-filename") or not 0 < geometry.get("virtual-size", 0) <= 8 * 1024 ** 3:
        raise ValueError("official image requires undeclared external backing or geometry")
    raw = output / "official.raw"
    subprocess.run(["qemu-img", "convert", "-f", "qcow2", "-O", "raw", str(image), str(raw)], check=True)
    with raw.open("rb") as stream:
        mbr = stream.read(512)
    if len(mbr) != 512 or mbr[510:] != b"\x55\xaa":
        raise ValueError("official ARM64 image does not have the expected partition table")
    fat = []
    for index in range(4):
        part = mbr[446 + index * 16:462 + index * 16]
        start, sectors = struct.unpack_from("<II", part, 8)
        if part[4] in (11, 12):
            if start == 0 or sectors == 0 or (start + sectors) * 512 > raw.stat().st_size:
                raise ValueError("official FAT boot partition exceeds its image")
            fat.append({"index": index + 1, "offset": start * 512, "bytes": sectors * 512})
    if len(fat) != 1 or fat[0]["offset"] != 4128768:
        raise ValueError("unexpected official ARM64 FAT boot partition")
    records["distribution"]["boot_partition"] = fat[0]
    uimage = output / "9qemu.u"
    environment = dict(os.environ, MTOOLSRC="/dev/null")
    subprocess.run(["mcopy", "-i", str(raw) + "@@" + str(fat[0]["offset"]), "::/9qemu.u", str(uimage)], env=environment, check=True)
    return prepare_kernel(uimage, output, records)


def admit_derivation(receipt: Path, kernel_identity: dict) -> dict:
    document = json.loads(receipt.read_text())
    if (document.get("schema") != "ostadix.original9front-native-builder/v1" or document.get("passed") is not True
            or document.get("byte_identical") is not True or document.get("source_commit") != COMMIT):
        raise ValueError("derived kernel requires a successful pinned original-tool two-build receipt")
    if (document.get("controller_source", {}).get("sha256") != DERIVATION_BUILDER_SHA256
            or document.get("original_kernel", {}).get("container", {}).get("sha256") != UIMAGE_SHA256
            or document.get("official_image", {}).get("sha256") != "67484f032a13eb9760a6287a1c0136a178da38b3c01e19ca7381d2e14a40a20f"):
        raise ValueError("derived kernel receipt is not bound to the admitted original build recipe/image")
    patch = document.get("platform_patch", {})
    if (patch.get("patch", {}).get("sha256") != UART_PATCH_SHA256
            or patch.get("source", {}).get("sha256") != UART_DERIVED_SHA256
            or patch.get("device") != "/dev/eia1" or patch.get("ipa") != 0x09001000 or patch.get("irq") != 50):
        raise ValueError("derived kernel receipt does not describe the exact second-UART platform patch")
    builds = document.get("patched_builds", [])
    if len(builds) != 2:
        raise ValueError("derived kernel receipt must contain two independent builds")
    for build in builds:
        expected = build.get("artifacts", {}).get("NATIVE.U", {})
        if (build.get("passed") is not True or expected.get("bytes") != kernel_identity["bytes"]
                or expected.get("sha256") != kernel_identity["sha256"]):
            raise ValueError("derived kernel bytes differ from the qualified two-build outputs")
    # These files are evidence, not signatures. The explicitly supplied receipt
    # must still bind its actual fixed controller, patch and native source bytes.
    for expected in [document["controller_source"], patch["patch"], patch["source"]]:
        actual = identity(Path(expected["path"]))
        if actual["bytes"] != expected["bytes"] or actual["sha256"] != expected["sha256"]:
            raise ValueError("derived kernel receipt input evidence has changed")
    return document


def prepare_kernel(source: Path, output: Path, records: dict, derivation: Path | None = None) -> Path:
    uimage = output / "9qemu.u"
    if source.resolve() != uimage.resolve():
        shutil.copyfile(source, uimage)
    observed = identity(uimage)
    if derivation is None and (observed["bytes"] != UIMAGE_BYTES or observed["sha256"] != UIMAGE_SHA256):
        raise ValueError("original kernel differs from the observed official build12115 kernel pin")
    if derivation is not None:
        document = admit_derivation(derivation, observed)
        snapshot = output / "kernel-derivation.json"
        shutil.copyfile(derivation, snapshot)
        records["kernel_derivation"] = identity(snapshot)
        records["derived_kernel"] = observed
        records["derivation_scope"] = document["scope"]
    uimage.chmod(0o400)
    metadata, payload = inspect_uimage(uimage)
    records["original_kernel"] = {"container": identity(uimage), "uimage": metadata}
    kernel = output / "kernel.raw"
    kernel.write_bytes(payload); kernel.chmod(0o400)
    records["original_kernel"]["payload"] = identity(kernel)
    return kernel


def namespace_file(image: Path, path: str) -> bytes:
    """Read an expected file from a frozen native-volume artifact for evidence.

    This bounded reader is not an authority server. Native init performs the
    complete structural validation before any original Plan9 request executes.
    """
    blob = image.read_bytes()
    if len(blob) != 16 * 1024 ** 2 or struct.unpack_from("<6Q", blob) != (0x3130305039534e4f, 1, 1024, len(blob), 397312, 3999):
        raise ValueError("unexpected native namespace volume format")
    parts = path.split("/")
    if not path.startswith("/") or any(part in ("", ".", "..") for part in parts[1:]):
        raise ValueError("namespace evidence path must be an absolute ordinary file path")
    current = 1
    for part in parts[1:]:
        matching = []
        for index in range(1024):
            record = blob[4096 + index * 384:4096 + (index + 1) * 384]
            live, parent = struct.unpack_from("<2Q", record)
            length = struct.unpack_from("<Q", record, 64)[0]
            if live == 1 and parent == current and length <= 255 and record[72:72 + length] == part.encode("utf-8"):
                matching.append((index + 1, record))
        if len(matching) != 1:
            raise ValueError("namespace evidence file does not exist or has ambiguous metadata: " + path)
        current, record = matching[0]
    mode, length, block = struct.unpack_from("<3Q", record, 32)
    if mode & 0x80000000 or length > 1024 * 1024:
        raise ValueError("namespace evidence path is not a bounded ordinary file")
    output = bytearray()
    seen = set()
    while len(output) < length:
        if not 1 <= block <= 3999 or block in seen:
            raise ValueError("invalid namespace evidence file block chain")
        seen.add(block)
        page = blob[397312 + (block - 1) * 4096:397312 + block * 4096]
        block = struct.unpack_from("<Q", page)[0]
        output.extend(page[8:8 + min(4088, length - len(output))])
    if block:
        raise ValueError("namespace evidence file has an overlong block chain")
    return bytes(output)


class ProbeQMP:
    def __init__(self, path: Path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(2)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile("rwb", buffering=0)
        if "QMP" not in json.loads(self.stream.readline()):
            raise ValueError("invalid private probe QMP greeting")
        self.serial = 0
        self.execute("qmp_capabilities")

    def execute(self, command: str, arguments: dict | None = None):
        self.serial += 1
        message = {"execute": command, "id": self.serial}
        if arguments is not None:
            message["arguments"] = arguments
        self.stream.write(json.dumps(message).encode() + b"\n")
        while True:
            response = json.loads(self.stream.readline())
            if response.get("id") == self.serial:
                if "error" in response:
                    raise ValueError("private probe QMP failure: " + str(response["error"]))
                return response.get("return")

    def close(self):
        self.stream.close()
        self.socket.close()


def probe_namespace(kernel: Path, build: Path, output: Path, qemu: str,
                    timeout: float, source_volume: Path, expect_path: str, expect_text: str | None = None) -> dict:
    snapshot = output / "namespace-input.raw"
    shutil.copyfile(source_volume, snapshot)
    before = identity(snapshot)
    if before["bytes"] != 16 * 1024 ** 2:
        raise ValueError("namespace snapshot must be exactly16MiB")
    if len(source_volume.stem) == 64 and source_volume.stem != before["sha256"]:
        raise ValueError("namespace CAS filename does not match its content")
    expected = namespace_file(snapshot, expect_path)
    if expect_text is not None and expected != (expect_text + "\n").encode("ascii"):
        raise ValueError("frozen namespace does not contain the expected complete Linux-generated line")
    if not expected or len(expected) > 2048 or any(byte not in b"\t\n\r" and not 32 <= byte <= 126 for byte in expected):
        raise ValueError("expected Linux-written evidence file must contain bounded printable text")
    snapshot.chmod(0o400)
    nonce = "ORIGINAL_PLAN9_" + secrets.token_hex(16)
    roundtrip = {"path": "/work/original-plan9-" + secrets.token_hex(12), "text": nonce + "\n"}
    epoch = secrets.randbits(63) | 1
    clock = int(time.time())
    endpoint = output / "q"
    command = [qemu, "-machine", "virt,virtualization=on,gic-version=3,its=off", "-cpu", "cortex-a57", "-smp", "1", "-m", "1G",
               "-accel", "tcg,thread=single", "-nodefaults", "-nic", "none", "-display", "none", "-monitor", "none",
               "-qmp", f"unix:{endpoint},server=on,wait=off", "-serial", "stdio", "-no-reboot", "-no-shutdown", "-kernel", str(build / "monitor.elf"),
               "-device", f"loader,file={kernel},addr=0x48100000,force-raw=on",
               "-device", f"loader,file={build / 'guest.dtb'},addr=0x48000000,force-raw=on",
               "-device", f"loader,file={snapshot},addr=0x6c000000,force-raw=on",
               "-device", f"loader,addr=0x6d000000,data={epoch},data-len=8",
               "-device", "loader,addr=0x6d000008,data=0,data-len=8",
               "-device", f"loader,addr=0x6d000010,data={clock},data-len=8"]
    received = bytearray()
    stage = 0
    command_index = 0
    passed = False
    quiescent = False
    stopped = False
    qmp = None
    exported = output / "namespace-after.raw"
    with (output / "qemu-stderr.log").open("wb") as errors, (output / "console.log").open("wb") as transcript:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        selector = selectors.DefaultSelector(); selector.register(child.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        def pump():
            for key, _ in selector.select(0.05):
                data = os.read(key.fileobj.fileno(), 65536)
                if data:
                    transcript.write(data); transcript.flush(); received.extend(data)
                    if len(received) > 8 * 1024 ** 2:
                        raise ValueError("native Plan9 namespace console exceeded its capture limit")
        def send(data):
            for position in range(0, len(data), 8):
                child.stdin.write(data[position:position + 8]); child.stdin.flush()
                time.sleep(0.04)
        try:
            while time.monotonic() < deadline and child.poll() is None:
                pump()
                text = bytes(received).replace(b"\r", b"")
                if b"KW Plan9 probe rejected access:" in text or b"panic:" in text:
                    raise ValueError("native Plan9 namespace profile rejected a device/kernel operation")
                if stage == 0 and b"bootargs is" in text:
                    send(b"!rc\n"); stage = 1
                if stage == 1 and (text.endswith(b"% ") or text.endswith(b"; ")):
                    # The entire second UART is pregranted. These ordinary
                    # original-rc commands supply no authority/magic protocol.
                    def quoted(path):
                        return "'" + path.replace("'", "''") + "'"
                    commands = ["mount -n -c /dev/eia1 /n",
                                "echo KW_LINUX_BEGIN_" + nonce + "; cat " + quoted("/n" + expect_path)
                                + "; echo; echo KW_LINUX_END_" + nonce,
                                "echo " + nonce + " > " + quoted("/n" + roundtrip["path"]),
                                "cat " + quoted("/n" + roundtrip["path"]), "echo KW_NS_DONE_" + nonce]
                    send((commands[command_index] + "\n").encode())
                    command_index += 1
                    received.extend(b"\0")  # consume this prompt before the next command
                    if command_index == len(commands):
                        stage = 2
                lines = text.splitlines()
                if stage == 2 and ("KW_NS_DONE_" + nonce).encode() in lines and nonce.encode() not in lines:
                    raise ValueError("original console command/nonce integrity check failed; no snapshot exported")
                prefix = ("\nKW_LINUX_BEGIN_" + nonce + "\n").encode()
                suffix = ("\nKW_LINUX_END_" + nonce + "\n").encode()
                framed = text.partition(prefix)[2].partition(suffix)
                if (stage == 2 and ("KW_NS_DONE_" + nonce).encode() in lines and nonce.encode() in lines
                        and framed[1] and framed[0] == expected.replace(b"\r", b"")):
                    qmp = ProbeQMP(endpoint)
                    for attempt in range(200):
                        qmp.execute("stop")
                        if qmp.execute("query-status").get("running") is not False:
                            raise ValueError("private namespace probe did not stop")
                        busy = output / "busy.bin"
                        qmp.execute("pmemsave", {"val": 0x6d000008, "size": 8, "filename": str(busy)})
                        flag = busy.read_bytes()
                        if flag == bytes(8):
                            stopped = quiescent = True
                            qmp.execute("pmemsave", {"val": 0x6c000000, "size": 16 * 1024 ** 2, "filename": str(exported)})
                            break
                        if flag != b"\x01" + bytes(7):
                            raise ValueError("invalid native transaction quiescence word")
                        qmp.execute("cont"); pump()
                    if not quiescent:
                        raise ValueError("could not stop outside a native namespace transaction")
                    if namespace_file(exported, roundtrip["path"]) != roundtrip["text"].encode():
                        raise ValueError("exported native objects do not contain the original Plan9 nonce write")
                    if namespace_file(exported, expect_path) != expected:
                        raise ValueError("original Linux-written evidence object changed unexpectedly")
                    passed = True
                    break
        finally:
            if qmp is not None:
                qmp.close()
            child.terminate()
            try: child.wait(timeout=3)
            except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)
            selector.close(); child.stdin.close(); child.stdout.close()
    result = {"passed": passed, "argv": command, "qemu": identity(Path(qemu)),
              "namespace_before": before, "namespace_source": identity(source_volume),
              "virtual_cpu_stopped_before_export": stopped,
              "native_operations_quiescent_before_export": quiescent,
              "roundtrip": roundtrip, "source_roundtrip": {"path": expect_path, "text": expected.decode("ascii")},
              "epoch": epoch, "clock_unix_seconds": clock, "console": identity(output / "console.log"), "stage": stage}
    if passed:
        result["namespace_after"] = identity(exported)
    return result


def probe(kernel: Path, build: Path, output: Path, qemu: str, timeout: float) -> dict:
    online = b"KW original Plan9 isolated EL2: online"
    token = b"KW_ORIGINAL_PLAN9_ABI_" + secrets.token_hex(12).encode()
    rtc_floor = int(time.time())
    command = [qemu, "-machine", "virt,virtualization=on,gic-version=3,its=off", "-cpu", "cortex-a57", "-smp", "1", "-m", "1G",
               "-accel", "tcg,thread=single", "-nodefaults", "-nic", "none", "-display", "none", "-monitor", "none",
               "-serial", "stdio", "-no-reboot", "-no-shutdown", "-kernel", str(build / "monitor.elf"),
               "-device", f"loader,file={kernel},addr=0x48100000,force-raw=on",
               "-device", f"loader,file={build / 'guest.dtb'},addr=0x48000000,force-raw=on",
               "-device", f"loader,addr=0x6d000000,data={rtc_floor},data-len=8"]
    received = bytearray(); stage = 0; passed = False
    with (output / "qemu-stderr.log").open("wb") as errors, (output / "console.log").open("wb") as transcript:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        selector = selectors.DefaultSelector(); selector.register(child.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        def send(data):
            for offset in range(0, len(data), 32):
                child.stdin.write(data[offset:offset + 32]); child.stdin.flush()
                time.sleep(0.01)
        try:
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    break
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        break
                    transcript.write(chunk); transcript.flush(); received.extend(chunk)
                    if len(received) > 8 * 1024 ** 2:
                        raise ValueError("original Plan9 console exceeded its diagnostic capture grant")
                complete = bytes(received).replace(b"\r\n", b"\n").split(b"\n")[:-1]
                if any(b"KW Plan9 probe rejected access:" in line or b"panic:" in line for line in complete):
                    break
                if stage == 0 and online in received and b"bootargs is" in received:
                    send(b"!rc\n"); stage = 1
                if stage == 1 and (received.endswith(b"% ") or received.endswith(b"; ")):
                    script = b"echo " + token + b"; echo $cputype; echo original-Plan9-kernel-ABI > /env/ocore_probe; cat /env/ocore_probe; ls /boot\n"
                    send(script); stage = 2
                lines = bytes(received).replace(b"\r\n", b"\n").split(b"\n")[:-1]
                if stage == 2 and token in lines and b"arm64" in lines and b"original-Plan9-kernel-ABI" in lines and b"/boot/paqfs" in lines:
                    passed = True; break
        finally:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=3)
            selector.close(); child.stdin.close(); child.stdout.close()
    return {"passed": passed, "argv": command, "qemu": identity(Path(qemu)), "command_marker": token.decode(),
            "rtc_provision_unix_seconds": rtc_floor,
            "console": identity(output / "console.log"), "stage": stage, "exit_status_after_cleanup": child.returncode}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--archive", type=Path)
    inputs.add_argument("--kernel-uimage", type=Path, help="reuse the exact pinned original kernel already extracted from the official image")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--derivation-receipt", type=Path, help="explicit successful pinned original-tool UART-kernel derivation")
    parser.add_argument("--namespace-state", type=Path, help="frozen isolated16MiB native namespace CAS file; never writes a head")
    parser.add_argument("--expect-path", default="/work/from-linux", help="Linux-generated text object to read using original Plan9 cat")
    parser.add_argument("--expect-text", help="expected complete Linux-generated line, excluding its final newline")
    args = parser.parse_args()
    if args.namespace_state is not None and args.derivation_receipt is None:
        parser.error("namespace profile requires an explicit derived UART kernel receipt")
    if args.derivation_receipt is not None and args.kernel_uimage is None:
        parser.error("kernel derivation requires --kernel-uimage")
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error("output must be a new isolated directory")
    qemu = shutil.which(args.qemu)
    if qemu is None:
        parser.error("qemu-system-aarch64 is required")
    output.mkdir(parents=True)
    shutil.copyfile(Path(__file__), output / "probe-controller.py")
    result = {"schema": "ostadix.original-plan9-isolated-probe/v1", "passed": False,
              "controller_source": identity(output / "probe-controller.py"),
              "scope": "original 9front kernel and original Plan9 user ABI below native O-core EL2 in isolated QEMU; no shared namespace, default OS or hardware qualification"}
    if args.namespace_state is not None:
        result.update(schema="ostadix.plan9-native-namespace-probe/v1",
                      scope="original Plan9 ABI mounts an isolated frozen fork of the native O-core namespace; sequential cross-ABI evidence, no simultaneous domain/default-OS claim")
    try:
        if args.archive is not None:
            kernel = prepare_archive(args.archive.resolve(), output, result)
        else:
            result["distribution"] = {"url": URL, "build": BUILD, "source_commit": COMMIT,
                                      "archive_sha256": ARCHIVE_SHA256, "integrity": "reused exact kernel observed in the pinned official image; no upstream signature verification claimed"}
            kernel = prepare_kernel(args.kernel_uimage.resolve(), output, result,
                                    args.derivation_receipt.resolve() if args.derivation_receipt is not None else None)
        build = output / "monitor"
        environment = dict(os.environ, OCORE_PLAN9_BUILD_DIR=str(build), OCORE_PLAN9_NAMESPACE=str(int(args.namespace_state is not None)))
        with (output / "build.log").open("wb") as log:
            subprocess.run(["bash", str(ROOT / "ocore/kernel/build-aarch64-plan9-probe.sh")], env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
        result["monitor"] = json.loads((build / "monitor-profile.json").read_text())
        if args.namespace_state is not None:
            result.update(probe_namespace(kernel, build, output, qemu, args.timeout,
                                         args.namespace_state.resolve(), args.expect_path, args.expect_text))
        else:
            result["observation"] = probe(kernel, build, output, qemu, args.timeout)
            result["passed"] = result["observation"]["passed"]
    except (Exception, KeyboardInterrupt) as error:
        result["error"] = f"{type(error).__name__}: {error}"
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Original Plan9 isolated O-core probe: {'PASS' if result['passed'] else 'FAIL'}\nEvidence: {output / 'result.json'}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
