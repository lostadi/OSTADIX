#!/usr/bin/env python3
"""Rebuild original ARM64 9front with its native tools in isolated build VMs.

The official disk is admitted by an observed pin and copied before use. Each
build gets a fresh private overlay and a small private input FAT disk. There
is no host filesystem export, network, working OKernel disk, or runtime claim.
An unmodified full source build supplies a frozen boot PAQ; two independent
source builds then qualify the UART platform patch with that admitted PAQ.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import secrets
import selectors
import shutil
import struct
import subprocess
import sys
import time

from probe_okernel_plan9 import COMMIT, inspect_uimage

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ROOT / "ocore/guest/plan9"
IMAGE_BYTES = 597164032
IMAGE_SHA256 = "67484f032a13eb9760a6287a1c0136a178da38b3c01e19ca7381d2e14a40a20f"
UART_SHA256 = "da6be23824c0611c48880e09fb98dccd15df3a7c943a3c63b787499e69140000"
EPOCH = 1793431069
FAT_OFFSET = 4128768
MTOOLS_ENV = dict(os.environ, MTOOLSRC="/dev/null")


def identity(path: Path) -> dict:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest}


def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=True, **kwargs)


def patched_uart(source: bytes) -> bytes:
    if hashlib.sha256(source).hexdigest() != UART_SHA256:
        raise ValueError("UART source differs from pinned unmodified 9front source")
    text = source.decode("ascii")
    declaration = """/* O-core grants this separate byte stream to the native namespace service.
 * The original console remains uart0. No physical device or DMA is assigned. */
static Uart namespaceuart = {
\t.regs\t= (u32int*)(VIRTIO+0x1001000ULL),
\t.name\t= "uart1",
\t.freq\t= 24*Mhz,
\t.baud\t= 115200,
\t.phys\t= &qemuphysuart,
};

"""
    replacements = [
        ("static Uart qemuuart = {", declaration + "static Uart qemuuart = {"),
        ('\t.name\t= "uart0",', '\t.name\t= "uart0",\n\t.next\t= &namespaceuart,'),
        ("intrenable(IRQuart, interrupt, uart, BUSUNKNOWN, uart->name);",
         "intrenable(uart == &namespaceuart ? 50 : IRQuart, interrupt, uart, BUSUNKNOWN, uart->name);"),
    ]
    for before, after in replacements:
        if text.count(before) != 1:
            raise ValueError("pinned UART platform patch context is ambiguous")
        text = text.replace(before, after)
    return text.encode("ascii")


def guest_script(token: str, patched: bool) -> str:
    changes = ""
    if patched:
        changes = "cp /tmp/UART.C uartqemu.c\ncp /tmp/SEED.PAQ qemu.bootfs.paq\n"
    return f"""#!/bin/rc
rfork n
bind /tmp/FIXTIME /dev/bintime || exit clockbind
echo KW_CLOCK_1 `{{date -n}}
sleep 2
echo KW_CLOCK_2 `{{date -n}}
cd /dist/9front
git/query HEAD > /tmp/COMMIT.TXT
cd /sys/src/9/arm64
s=`{{sha1sum -2 256 uartqemu.c}}
if(! ~ $s(1) {UART_SHA256}) exit wrongsource
{changes}NPROC=1
echo KW_NATIVE_BUILD_BEGIN_{token}
mk 'CONF=qemu' > /tmp/BUILD.LOG >[2=1] || {{
    echo KW_NATIVE_BUILD_FAILED_{token}
    tail -n 30 /tmp/BUILD.LOG
    exit buildfailed
}}
sha1sum -2 256 /arm64/bin/7c /arm64/bin/7a /arm64/bin/7l /arm64/bin/mk /arm64/bin/rc /arm64/bin/aux/aout2uimage /arm64/bin/mkpaqfs /arm64/lib/libmemlayer.a /arm64/lib/libmemdraw.a /arm64/lib/libdraw.a /arm64/lib/libip.a /arm64/lib/libsec.a /arm64/lib/libmp.a /arm64/lib/libc.a > /tmp/TOOLS.TXT
du -a /sys/src/9/arm64 /sys/src/9/port /sys/src/9/ip /sys/src/9/boot /sys/include /arm64/include | awk '{{print $2}}' > /tmp/PATHS
{{for(f in `{{cat /tmp/PATHS}}) if(test -f $f) sha1sum -2 256 $f}} > /tmp/SOURCE.TXT
9fs dos /dev/sdF0/dos || exit exportmount
cp 9qemu.u /n/dos/NATIVE.U || exit exportkernel
cmp 9qemu.u /n/dos/NATIVE.U || exit exportcompare
cp qemu.bootfs.paq /n/dos/SEED.PAQ
cp uartqemu.c /n/dos/UART.C
for(f in BUILD.LOG TOOLS.TXT SOURCE.TXT COMMIT.TXT) cp /tmp/$f /n/dos/$f
unmount /n/dos || exit exportunmount
echo KW_NATIVE_BUILD_PASS_{token}
fshalt
"""


def build_vm(output: Path, base: Path, kernel: Path, platform: Path,
             qemu: str, timeout: float, uart: Path | None = None,
             seed: Path | None = None) -> dict:
    output.mkdir()
    token = secrets.token_hex(12)
    script = output / "BUILD.RC"
    script.write_text(guest_script(token, uart is not None))
    fixed = output / "FIXTIME"
    fixed.write_bytes(struct.pack(">4Q", EPOCH * 10**9, 1, 10**9, 10**9))
    input_disk = output / "input.fat"
    run(["mkfs.fat", "-C", str(input_disk), "16384"], stdout=subprocess.DEVNULL)
    inputs = {"BUILD.RC": script, "FIXTIME": fixed}
    if uart is not None:
        inputs.update({"UART.C": uart, "SEED.PAQ": seed})
    for name, path in inputs.items():
        run(["mcopy", "-i", str(input_disk), str(path), "::/" + name], env=MTOOLS_ENV)
    overlay = output / "builder.qcow2"
    run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay)], stdout=subprocess.DEVNULL)
    command = [qemu, "-machine", "virt,highmem=off,virtualization=on,gic-version=3,its=off",
               "-cpu", "cortex-a57", "-smp", "1", "-m", "1G", "-accel", "tcg,thread=single",
               "-nodefaults", "-nic", "none", "-display", "none", "-monitor", "none",
               "-serial", "stdio", "-no-reboot", "-dtb", str(platform / "builder.dtb"),
               "-device", f"loader,file={kernel},addr=0x40100000,force-raw=on",
               "-device", f"loader,file={platform / 'entry.bin'},addr=0x47000000,force-raw=on",
               "-device", "loader,addr=0x47000000,cpu-num=0",
               "-drive", f"if=none,id=root,file={overlay},format=qcow2",
               "-device", "virtio-blk-pci,drive=root,disable-legacy=on",
               "-drive", f"if=none,id=input,file={input_disk},format=raw",
               "-device", "virtio-blk-pci,drive=input,disable-legacy=on"]
    (output / "argv.json").write_text(json.dumps(command, indent=2) + "\n")
    bootstrap = ["bind -a '#S' /dev", "9fs dos /dev/sdG0/data", "cp /n/dos/FIXTIME /tmp/FIXTIME",
                 "cp /n/dos/BUILD.RC /tmp/BUILD.RC"]
    if uart is not None:
        bootstrap += ["cp /n/dos/UART.C /tmp/UART.C", "cp /n/dos/SEED.PAQ /tmp/SEED.PAQ"]
    bootstrap += ["unmount /n/dos", "rc /tmp/BUILD.RC"]
    received = bytearray()
    stage = 0
    halted = False
    pending = bytearray()
    last_send = 0.0
    sent_boot = sent_user = False
    with (output / "console.log").open("wb") as transcript, (output / "stderr.log").open("wb") as errors:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline and child.poll() is None:
                for key, _ in selector.select(0.05):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if data:
                        transcript.write(data); transcript.flush(); received.extend(data)
                        if len(received) > 16 * 1024 ** 2:
                            raise ValueError("private build console exceeded its capture limit")
                text = bytes(received).replace(b"\r", b"")
                if (b"panic:" in text or ("KW_NATIVE_BUILD_FAILED_" + token).encode() in text
                        or ("KW_BOOTSTRAP_FAILED_" + token).encode() in text.splitlines()):
                    raise ValueError("original build VM reported a kernel/build failure")
                if b"bootargs is" in text and not sent_boot:
                    pending.extend(b"\n"); sent_boot = True
                if b"user[glenda]:" in text and not sent_user:
                    pending.extend(b"\n"); sent_user = True
                if not pending and stage < len(bootstrap) and text.endswith(b"% "):
                    pending.extend((" " + bootstrap[stage] + " || echo KW_BOOTSTRAP_FAILED_" + token + "\n").encode())
                    stage += 1
                    received.extend(b"\0")  # do not reuse a previously observed prompt
                if pending and time.monotonic() - last_send >= 0.03:
                    child.stdin.write(pending[:16]); child.stdin.flush()
                    del pending[:16]
                    last_send = time.monotonic()
                if b"done halting" in text:
                    halted = True
                    break
        finally:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=3)
            selector.close(); child.stdin.close(); child.stdout.close()
    text = (output / "console.log").read_bytes().replace(b"\r", b"")
    if not halted or ("KW_NATIVE_BUILD_PASS_" + token).encode() not in text:
        raise ValueError(f"original build did not finish and flush its private filesystem: {output}")
    for marker in [f"KW_CLOCK_1 {EPOCH}", f"KW_CLOCK_2 {EPOCH}"]:
        if marker.encode() not in text:
            raise ValueError("original tools did not observe the fixed build-only clock")
    raw = output / "export.raw"
    run(["qemu-img", "convert", "-f", "qcow2", "-O", "raw", str(overlay), str(raw)])
    exported = output / "artifacts"
    exported.mkdir()
    for name in ["NATIVE.U", "SEED.PAQ", "UART.C", "BUILD.LOG", "TOOLS.TXT", "SOURCE.TXT", "COMMIT.TXT"]:
        run(["mcopy", "-i", str(raw) + "@@" + str(FAT_OFFSET), "::/" + name, str(exported / name)], env=MTOOLS_ENV)
    if (exported / "COMMIT.TXT").read_text().strip() != COMMIT:
        raise ValueError("native source commit receipt differs from the admitted original build")
    metadata, _ = inspect_uimage(exported / "NATIVE.U")
    if metadata["timestamp"] != EPOCH:
        raise ValueError("original uImage writer did not observe the fixed build clock")
    if uart is not None:
        if (exported / "UART.C").read_bytes() != uart.read_bytes():
            raise ValueError("native compiler's UART source differs from the recorded platform patch")
        if (exported / "SEED.PAQ").read_bytes() != seed.read_bytes():
            raise ValueError("admitted boot PAQ was unexpectedly regenerated")
    result = {"passed": True, "argv": command, "inputs": {k: identity(v) for k, v in inputs.items()},
              "artifacts": {p.name: identity(p) for p in exported.iterdir()}, "uimage": metadata,
              "console": identity(output / "console.log")}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, default=Path.home() / ".cache/ostadix/plan9-original/9front-12115-arm64/9front-12115.arm64.qcow2")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=600, help="maximum seconds for each private build VM")
    parser.add_argument("--repeats", type=int, choices=[1, 2], default=2)
    args = parser.parse_args()
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error("output must be a new isolated directory")
    commands = [args.qemu, "qemu-img", "dtc", "clang", "llvm-objcopy", "mkfs.fat", "mcopy"]
    selected = {name: shutil.which(name) for name in commands}
    if not all(selected.values()):
        parser.error("required tools missing: " + ", ".join(k for k, v in selected.items() if not v))
    output.mkdir(parents=True)
    shutil.copyfile(Path(__file__), output / "builder.py")
    shutil.copyfile(ROOT / "scripts/probe_okernel_plan9.py", output / "probe-inputs.py")
    result = {"schema": "ostadix.original9front-native-builder/v1", "passed": False,
              "scope": "original 9front tools/source kernel rebuild in isolated host-QEMU build VMs; not an O-core runtime qualification",
              "source_commit": COMMIT, "epoch": EPOCH,
              "controller_source": identity(output / "builder.py"),
              "container_parser_source": identity(output / "probe-inputs.py"),
              "nonclaims": ["No upstream signature verification: official image uses an explicit observed SHA256 pin",
                            "Native compiler/toolchain and userland are admitted binaries, not bootstrapped from source here",
                            "The first boot PAQ is admitted as a fixed input; its construction is not qualified as byte reproducible",
                            "Second UART is a platform patch only; native shared-store transport is not supplied by this builder"]}
    try:
        base = output / "official.qcow2"
        shutil.copyfile(args.image, base)
        admitted = identity(base)
        if admitted["bytes"] != IMAGE_BYTES or admitted["sha256"] != IMAGE_SHA256:
            raise ValueError("official qcow2 differs from the explicit observed build12115 pin")
        base.chmod(0o400)
        geometry = json.loads(run(["qemu-img", "info", "--output=json", str(base)], capture_output=True, text=True).stdout)
        if geometry.get("format") != "qcow2" or geometry.get("backing-filename"):
            raise ValueError("official qcow2 requires undeclared backing")
        result["official_image"] = admitted
        result["host_tools"] = {k: identity(Path(v)) for k, v in selected.items()}
        platform = output / "platform"
        platform.mkdir()
        for name in ["builder.dts", "builder-entry.S"]:
            shutil.copyfile(PLATFORM / name, platform / name)
        run(["dtc", "-I", "dts", "-O", "dtb", "-o", str(platform / "builder.dtb"), str(platform / "builder.dts")])
        run(["clang", "--target=aarch64-none-elf", "-march=armv8-a", "-c", str(platform / "builder-entry.S"), "-o", str(platform / "entry.o")])
        run(["llvm-objcopy", "-O", "binary", str(platform / "entry.o"), str(platform / "entry.bin")])
        raw = output / "official.raw"
        run(["qemu-img", "convert", "-f", "qcow2", "-O", "raw", str(base), str(raw)])
        original = output / "9qemu.u"
        run(["mcopy", "-i", str(raw) + "@@" + str(FAT_OFFSET), "::/9qemu.u", str(original)], env=MTOOLS_ENV)
        metadata, payload = inspect_uimage(original)
        if hashlib.sha256(original.read_bytes()).hexdigest() != "df704b7fff3417eeb9924fed7170fed5e0aeb52829d11fabcbf4e9f6732b34ae":
            raise ValueError("official kernel differs from the original build12115 pin")
        kernel = output / "kernel.raw"
        kernel.write_bytes(payload)
        result["original_kernel"] = {"container": identity(original), "uimage": metadata}
        print("Building unmodified original kernel with original ARM64 tools...", flush=True)
        baseline = build_vm(output / "baseline", base, kernel, platform, selected[args.qemu], args.timeout)
        result["baseline"] = baseline
        source = output / "baseline/artifacts/UART.C"
        uart = output / "namespace-uart.c"
        uart.write_bytes(patched_uart(source.read_bytes()))
        patch = output / "namespace-uart.patch"
        patch.write_text("".join(difflib.unified_diff(source.read_text().splitlines(True), uart.read_text().splitlines(True),
                                                    fromfile="a/sys/src/9/arm64/uartqemu.c", tofile="b/sys/src/9/arm64/uartqemu.c")))
        if patch.read_bytes() != (PLATFORM / "namespace-uart.patch").read_bytes():
            raise ValueError("generated UART patch differs from its reviewable repository patch")
        result["platform_patch"] = {"source": identity(uart), "patch": identity(patch),
                                    "device": "/dev/eia1", "ipa": 0x09001000, "irq": 50}
        seed = output / "baseline/artifacts/SEED.PAQ"
        builds = []
        for index in range(args.repeats):
            print(f"Building UART platform patch in fresh overlay {index + 1}/{args.repeats}...", flush=True)
            builds.append(build_vm(output / f"patched-{index + 1}", base, kernel, platform, selected[args.qemu], args.timeout, uart, seed))
            result["patched_builds"] = builds
        if len(builds) == 2:
            a = output / "patched-1/artifacts/NATIVE.U"
            b = output / "patched-2/artifacts/NATIVE.U"
            result["byte_identical"] = a.read_bytes() == b.read_bytes()
            if not result["byte_identical"]:
                raise ValueError("two independent original-tool kernel builds differ")
        result["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        result["error"] = f"{type(error).__name__}: {error}"
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Original 9front native-tool rebuild: {'PASS' if result['passed'] else 'FAIL'}\nEvidence: {output / 'result.json'}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
