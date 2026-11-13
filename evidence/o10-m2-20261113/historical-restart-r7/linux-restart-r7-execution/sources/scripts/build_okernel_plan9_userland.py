#!/usr/bin/env python3
"""Build an original 9front command provider in a fresh private build VM.

The admitted image supplies original ARM64 tools, headers and libraries. They
are copied into a readonly boot PAQ, not installed in the shared object store.
The original kernel is rebuilt with the existing UART platform patch and that
PAQ. This is native 9front compilation, not source lowering through O-core.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import selectors
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time

import build_okernel_plan9_original as original
from probe_okernel_plan9 import COMMIT, UIMAGE_SHA256, inspect_uimage

ROOT = Path(__file__).resolve().parents[1]
PROVIDER = ROOT / "ocore/guest/plan9/unified"
TOOLS = ("rc", "cat", "echo", "ls", "mkdir", "rm", "mv", "cp", "test",
         "sleep", "mount", "bind", "unmount", "grep", "sed", "awk", "sha1sum",
         "tar", "7c", "7a", "7l", "mk", "ar", "size", "pwd", "read", "dd", "date")
LIBRARIES = ("libc.a", "libbio.a", "libsec.a", "libmp.a")
BUILD_TOOLS = tuple("/arm64/bin/" + x for x in
                    ("7c", "7a", "7l", "mk", "rc", "mkpaqfs", "disk/mkfs",
                     "tar", "sha1sum", "aux/aout2uimage"))
EXPORTS = ("KERNEL.U", "USER.PAQ", "SERVICE", "USER.TAR", "FILES.TXT",
           "ORIG.TXT", "TOOLS.TXT", "SOURCE.TXT", "COMMIT.TXT", "BUILD.LOG")
HELLO = b'#include <u.h>\n#include <libc.h>\nvoid main(void){print("P9_USERLAND_NATIVE_HELLO\\n");exits(nil);}\n'


def identity(path: Path) -> dict:
    return original.identity(path)


def admit_image(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("official image must be a regular nonsymlink file")
    record = identity(path)
    if (record["bytes"], record["sha256"]) != (original.IMAGE_BYTES, original.IMAGE_SHA256):
        raise ValueError("official image differs from the pinned original build12115")
    return record


def provider_proto() -> str:
    lines = ["arm64", "\tbin", *("\t\t" + name for name in TOOLS),
             "\t\tp9cmdsrv 555 sys sys /tmp/p9cmdsrv", "\tlib",
             *("\t\t" + name for name in LIBRARIES), "\tinclude", "\t\t+", "\tmkfile",
             "sys", "\tinclude", "\t\t+", "\tsrc", "\t\tmkfile.proto", "\t\tcmd",
             "\t\t\tmkone", "\t\t\tmkmany", "\t\t\tmklib", "rc", "\tbin",
             "\t\tokernel-start 555 sys sys /tmp/START.RC", "\tlib", "\t\trcmain"]
    return "\n".join(lines) + "\n"


def hash_listing(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})[ \t]+(\S+)", line)
        if not match or match[2] in result:
            raise ValueError("invalid or duplicate original hash inventory")
        result[match[2]] = match[1]
    return result


def extract_provider(archive: Path, output: Path, hashes: dict[str, str]) -> list[dict]:
    """Extract only ordinary files/directories, with exact native hash binding."""
    records = []
    seen = set()
    with tarfile.open(archive, "r:") as tar:
        for member in tar:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts
                    or path.parts[0] != "qemu.bootfs" or member.name in seen):
                raise ValueError("unsafe or duplicate provider archive path")
            seen.add(member.name)
            relative = Path(*path.parts[1:])
            destination = output / relative
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.issparse() or not path.parts[1:]:
                raise ValueError("provider archive contains a nonregular member")
            if member.name not in hashes:
                raise ValueError("provider file lacks its native hash inventory")
            source = tar.extractfile(member)
            if source is None:
                raise ValueError("provider archive member has no data")
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            length = 0
            with destination.open("xb") as target:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    target.write(block); digest.update(block); length += len(block)
            if length != member.size or digest.hexdigest() != hashes[member.name]:
                raise ValueError("provider content differs from native byte inventory")
            destination.chmod(0o444 | (member.mode & 0o111))
            records.append({"guest_path": "/" + relative.as_posix(), **identity(destination)})
    if {"qemu.bootfs" + record["guest_path"] for record in records} != set(hashes):
        raise ValueError("provider archive omits a native inventoried file")
    return records


def validate_original_files(files: list[dict], originals: dict[str, str]) -> None:
    by_guest = {item["guest_path"]: item for item in files}
    required = {"/arm64/bin/" + name for name in TOOLS}
    required.update("/arm64/lib/" + name for name in LIBRARIES)
    required.update(("/rc/lib/rcmain", "/arm64/mkfile", "/sys/src/mkfile.proto",
                     "/sys/src/cmd/mkone", "/sys/src/cmd/mkmany", "/sys/src/cmd/mklib"))
    required.update(name for name in by_guest if name.startswith(("/arm64/include/", "/sys/include/")))
    if not required <= set(originals):
        raise ValueError("original provider inventory omits required tool/header/library bytes")
    # Original boot prototypes intentionally remap some names (for example
    # rc/bin/nusbrc comes from sys/src/9/boot, not installed rc/bin/nusbrc).
    # Require complete identity equivalence for the explicitly selected
    # provider originals; all other boot bytes retain their native inventory
    # and original boot-prototype/source provenance separately.
    for name in required:
        if name not in by_guest or by_guest[name]["sha256"] != originals[name]:
            raise ValueError("provider changed an original file: " + name)


def guest_script(token: str) -> str:
    tool_names = " ".join(BUILD_TOOLS)
    return f"""#!/bin/rc
rfork n
fn fail {{ if(test -f /tmp/BUILD.LOG) tail -n 40 /tmp/BUILD.LOG; echo P9_PROVIDER_FAIL_{token} $*; exit $"* }}
bind /tmp/FIXTIME /dev/bintime || fail fixedclock
echo P9_CLOCK `{{date -n}}
cd /dist/9front || fail source
git/query HEAD > /tmp/COMMIT.TXT || fail commit
cd /sys/src/9/arm64 || fail kernelpath
s=`{{sha1sum -2 256 uartqemu.c}}
if(! ~ $s(1) {original.UART_SHA256}) fail uartsource
sha1sum -2 256 {tool_names} > /tmp/TOOLS.TXT || fail tools
cp /tmp/UART.C uartqemu.c || fail uartpatch
echo P9_SERVICE_BUILD_BEGIN_{token}
7c -o /tmp/p9cmdsrv.7 /tmp/P9CMDSRV.C > /tmp/BUILD.LOG >[2=1] || fail servicecompile
7l -o /tmp/p9cmdsrv /tmp/p9cmdsrv.7 -lsec -lmp >> /tmp/BUILD.LOG >[2=1] || fail servicelink
echo P9_SERVICE_COMPILED_{token}
rm -rf qemu.bootfs
mkdir qemu.bootfs || fail providerroot
disk/mkfs -s / -d qemu.bootfs ../boot/bootfs.proto ../boot/disk.proto ../boot/devusb.proto /tmp/UNIFIED.PRT >> /tmp/BUILD.LOG >[2=1] || fail providercopy
du -a qemu.bootfs | awk '{{print $2}}' > /tmp/PATHS
{{for(f in `{{cat /tmp/PATHS}}) if(test -f $f) sha1sum -2 256 $f}} > /tmp/FILES.TXT
{{for(f in `{{cat /tmp/PATHS}}) if(test -f $f){{
    p=`{{echo $f | sed 's,^qemu.bootfs,,'}}
    if(test -f $p) sha1sum -2 256 $p
}}}} > /tmp/ORIG.TXT
mkpaqfs -9 -b 65536 -o qemu.bootfs.paq qemu.bootfs >> /tmp/BUILD.LOG >[2=1] || fail pack
paqbefore=`{{sha1sum -2 256 qemu.bootfs.paq}}
mkdir -p /tmp/paqmount || fail mountpoint
paqfs -qav -m /tmp/paqmount qemu.bootfs.paq || fail paqmount
@{{
    rfork n
    bind /tmp/paqmount/arm64 /arm64 || exit bindarch
    bind /tmp/paqmount/sys/include /sys/include || exit bindheaders
    bind /tmp/paqmount/rc /rc || exit bindrc
    bind /arm64/bin /bin || exit bindbin
    cd /tmp || exit tmp
    /arm64/bin/7c -o HELLO.7 HELLO.C || exit hellocompile
    /arm64/bin/7l -o HELLO HELLO.7 || exit hellolink
    ./HELLO || exit helloexecute
}} || fail paqclosure
unmount /tmp/paqmount || fail paqunmount
NPROC=1
echo P9_KERNEL_BUILD_BEGIN_{token}
mk 'CONF=qemu' >> /tmp/BUILD.LOG >[2=1] || fail kernelbuild
paqafter=`{{sha1sum -2 256 qemu.bootfs.paq}}
if(! ~ $paqbefore(1) $paqafter(1)) fail changedpaq
du -a /sys/src/9/arm64 /sys/src/9/port /sys/src/9/ip /sys/src/9/boot /sys/include /arm64/include | awk '{{print $2}}' > /tmp/SRCPATHS
{{for(f in `{{cat /tmp/SRCPATHS}}) if(test -f $f) sha1sum -2 256 $f}} > /tmp/SOURCE.TXT
9fs dos /dev/sdG0/data || fail exportmount
cp 9qemu.u /n/dos/KERNEL.U || fail exportkernel
cp qemu.bootfs.paq /n/dos/USER.PAQ || fail exportpaq
cp /tmp/p9cmdsrv /n/dos/SERVICE || fail exportservice
tar c qemu.bootfs > /n/dos/USER.TAR || fail exporttree
for(f in FILES.TXT ORIG.TXT TOOLS.TXT SOURCE.TXT COMMIT.TXT BUILD.LOG) cp /tmp/$f /n/dos/$f || fail exportreceipt
cmp 9qemu.u /n/dos/KERNEL.U || fail kernelcompare
cmp qemu.bootfs.paq /n/dos/USER.PAQ || fail paqcompare
unmount /n/dos || fail exportunmount
echo P9_PROVIDER_PASS_{token}
fshalt
"""


def run_guest(command: list[str], output: Path, token: str, timeout: float, *,
              bootstrap: list[str] | None = None,
              required_markers: tuple[bytes, ...] | None = None,
              console_exchanges: tuple[tuple[bytes, bytes], ...] = ()) -> None:
    if bootstrap is None:
        bootstrap = ["bind -a '#S' /dev", "9fs dos /dev/sdG0/data"]
        bootstrap += [f"cp /n/dos/{name} /tmp/{name}" for name in
                      ("FIXTIME", "BUILD.RC", "UART.C", "P9CMDSRV.C", "START.RC", "UNIFIED.PRT", "HELLO.C")]
        bootstrap += ["unmount /n/dos", "rc /tmp/BUILD.RC"]
    received = bytearray()
    pending = bytearray()
    stage = 0
    exchange_stage = 0
    sent_boot = sent_user = halted = False
    last_send = 0.0
    with (output / "console.log").open("wb") as log, (output / "stderr.log").open("wb") as errors:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        selector = selectors.DefaultSelector(); selector.register(child.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline and child.poll() is None:
                for key, _ in selector.select(0.05):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if data:
                        log.write(data); log.flush(); received.extend(data)
                text = bytes(received).replace(b"\r", b"")
                if b"panic:" in text or ("P9_PROVIDER_FAIL_" + token).encode() in text.splitlines():
                    raise ValueError("private original build reported failure")
                if re.search(rb"(?m)^P9_PROVIDER_FAIL_" + token.encode() + rb"(?: |$)", text):
                    raise ValueError("private original build reported failure")
                if b"bootargs is" in text and not sent_boot:
                    pending.extend(b"\n"); sent_boot = True
                if b"user[glenda]:" in text and not sent_user:
                    pending.extend(b"\n"); sent_user = True
                if not pending and stage < len(bootstrap) and text.endswith(b"% "):
                    pending.extend((" " + bootstrap[stage] + " || echo P9_PROVIDER_FAIL_" + token + " bootstrap\n").encode())
                    stage += 1; received.extend(b"\0")
                if not pending and stage == len(bootstrap) and exchange_stage < len(console_exchanges):
                    marker, payload = console_exchanges[exchange_stage]
                    if marker in text.splitlines():
                        pending.extend(payload)
                        exchange_stage += 1
                if pending and time.monotonic() - last_send >= 0.03:
                    child.stdin.write(pending[:16]); child.stdin.flush()
                    del pending[:16]; last_send = time.monotonic()
                if b"done halting" in text:
                    halted = True; break
        finally:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=3)
            selector.close(); child.stdin.close(); child.stdout.close()
    lines = (output / "console.log").read_bytes().replace(b"\r", b"").splitlines()
    required = required_markers if required_markers is not None else (
        ("P9_PROVIDER_PASS_" + token).encode(), b"P9_USERLAND_NATIVE_HELLO",
        ("P9_CLOCK " + str(original.EPOCH)).encode())
    if (not halted or any(marker not in lines for marker in required)
            or exchange_stage != len(console_exchanges) or pending):
        raise ValueError("original provider did not finish its native closure test and clean halt")


def run_script_vm(output: Path, base: Path, kernel_uimage: Path, platform: Path,
                  script: bytes, input_files: dict[str, Path], qemu: str,
                  timeout: float, required_markers: tuple[bytes, ...], *,
                  console_exchanges: tuple[tuple[bytes, bytes], ...] = ()) -> dict:
    """Run a caller-owned test script in one NEW private original-9front VM.

    platform contains the native builder's builder.dtb and entry.bin. The
    script must export its evidence to /dev/sdG0/data and finish with fshalt.
    No host filesystem, network, working namespace volume, or head is passed.
    The caller binds the selected derived kernel to its build receipt.
    """
    output = output.absolute()
    if output.exists() or output.is_symlink() or not required_markers:
        raise ValueError("runtime fixture needs a new output and explicit success markers")
    if any(not isinstance(x, bytes) or not x or not x.isascii() or b"\n" in x or b"\r" in x for x in required_markers):
        raise ValueError("runtime success markers must be nonempty individual byte lines")
    seen_markers = set()
    for exchange in console_exchanges:
        if not isinstance(exchange, tuple) or len(exchange) != 2:
            raise ValueError("console exchange must pair an exact marker and byte payload")
        marker, payload = exchange
        if (not isinstance(marker, bytes) or not marker or not marker.isascii()
                or b"\n" in marker or b"\r" in marker or marker in seen_markers
                or not isinstance(payload, bytes) or not payload):
            raise ValueError("console exchange requires unique ASCII marker lines and nonempty byte payloads")
        seen_markers.add(marker)
    seen = {"VERIFY.RC"}
    for name, path in input_files.items():
        if (not re.fullmatch(r"[A-Za-z0-9_]{1,8}(?:\.[A-Za-z0-9_]{1,3})?", name)
                or name.upper() in seen or path.is_symlink() or not path.is_file()):
            raise ValueError("runtime input must have a unique plain FAT name and regular source")
        seen.add(name.upper())
    admitted = admit_image(base)
    metadata, payload = inspect_uimage(kernel_uimage)
    for name in ("builder.dtb", "entry.bin"):
        if not (platform / name).is_file() or (platform / name).is_symlink():
            raise ValueError("runtime fixture requires regular builder platform artifacts")
    tools = {name: shutil.which(name) for name in (qemu, "qemu-img", "mkfs.fat", "mcopy")}
    if not all(tools.values()):
        raise ValueError("private runtime fixture tools are missing")
    output.mkdir(parents=True)
    record = {"schema": "ostadix.original9front-private-script/v1", "ok": False,
              "source_image": admitted, "kernel_source": identity(kernel_uimage), "uimage": metadata,
              "scope": "private original 9front build/test VM; no O-core monitor or shared-store execution"}
    record["console_exchanges"] = [{"marker": marker.decode("ascii"), "payload_hex": payload.hex()}
                                   for marker, payload in console_exchanges]
    commands = []
    def run(argv):
        value = subprocess.run([str(x) for x in argv], env=original.MTOOLS_ENV,
                               capture_output=True, text=True)
        commands.append({"argv": [str(x) for x in argv], "exit_code": value.returncode,
                         "stdout": value.stdout, "stderr": value.stderr})
        value.check_returncode()
    try:
        captured = output / "inputs"; captured.mkdir()
        (captured / "VERIFY.RC").write_bytes(script)
        for name, source in input_files.items():
            shutil.copyfile(source, captured / name)
        for path in captured.iterdir():
            path.chmod(0o444)
        record["inputs"] = {p.name: identity(p) for p in captured.iterdir()}
        copied_base = output / "official.qcow2"; shutil.copyfile(base, copied_base)
        record["official_image"] = admit_image(copied_base); copied_base.chmod(0o400)
        (output / "kernel.raw").write_bytes(payload)
        for name in ("builder.dtb", "entry.bin"):
            shutil.copyfile(platform / name, output / name)
        record["platform_artifacts"] = {name: identity(output / name) for name in ("builder.dtb", "entry.bin", "kernel.raw")}
        record["host_tools"] = {name: identity(Path(path)) for name, path in tools.items()}
        fat = output / "transfer.fat"
        run([tools["mkfs.fat"], "-C", fat, "65536"])
        for path in captured.iterdir():
            run([tools["mcopy"], "-i", fat, path, "::/" + path.name])
        overlay = output / "builder.qcow2"
        run([tools["qemu-img"], "create", "-f", "qcow2", "-F", "qcow2", "-b", copied_base, overlay])
        argv = [tools[qemu], "-machine", "virt,highmem=off,virtualization=on,gic-version=3,its=off",
                "-cpu", "cortex-a57", "-smp", "1", "-m", "1G", "-accel", "tcg,thread=single",
                "-nodefaults", "-nic", "none", "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot",
                "-dtb", str(output / "builder.dtb"), "-device", f"loader,file={output / 'kernel.raw'},addr=0x40100000,force-raw=on",
                "-device", f"loader,file={output / 'entry.bin'},addr=0x47000000,force-raw=on", "-device", "loader,addr=0x47000000,cpu-num=0",
                "-drive", f"if=none,id=root,file={overlay},format=qcow2", "-device", "virtio-blk-pci,drive=root,disable-legacy=on",
                "-drive", f"if=none,id=input,file={fat},format=raw", "-device", "virtio-blk-pci,drive=input,disable-legacy=on"]
        record["argv"] = argv
        (output / "argv.json").write_text(json.dumps(argv, indent=2) + "\n")
        bootstrap = ["bind -a '#S' /dev", "9fs dos /dev/sdG0/data"]
        bootstrap += [f"cp /n/dos/{name} /tmp/{name}" for name in ("VERIFY.RC", *input_files)]
        bootstrap += ["unmount /n/dos", "rc /tmp/VERIFY.RC"]
        run_guest(argv, output, secrets.token_hex(12), timeout,
                  bootstrap=bootstrap, required_markers=required_markers,
                  console_exchanges=console_exchanges)
        record.update(ok=True, transfer_disk=identity(fat), required_markers=[x.decode("ascii") for x in required_markers])
        return record
    except BaseException as error:
        record["error"] = str(error)
        raise
    finally:
        record["commands"] = commands
        if (output / "console.log").exists():
            record["console"] = identity(output / "console.log")
        (output / "runtime-result.json").write_text(json.dumps(record, indent=2) + "\n")


def qualify_exports(output: Path, captured: Path, provider_dir: Path) -> dict:
    exports = output / "artifacts"
    if (exports / "COMMIT.TXT").read_text().strip() != COMMIT:
        raise ValueError("native source commit differs from the pinned image")
    native_tools = hash_listing((exports / "TOOLS.TXT").read_text())
    if set(native_tools) != set(BUILD_TOOLS):
        raise ValueError("native compiler/tool inventory is incomplete")
    files = extract_provider(exports / "USER.TAR", provider_dir, hash_listing((exports / "FILES.TXT").read_text()))
    by_guest = {item["guest_path"]: item for item in files}
    required = ["/arm64/bin/" + name for name in TOOLS] + ["/arm64/lib/" + name for name in LIBRARIES]
    required += ["/arm64/include/u.h", "/sys/include/libc.h", "/rc/lib/rcmain", "/arm64/bin/p9cmdsrv", "/rc/bin/okernel-start"]
    if any(name not in by_guest for name in required):
        raise ValueError("native provider closure is missing a required file")
    validate_original_files(files, hash_listing((exports / "ORIG.TXT").read_text()))
    for name in set(BUILD_TOOLS) & set(by_guest):
        if by_guest[name]["sha256"] != native_tools[name]:
            raise ValueError("provider compiler/tool differs from the executed native tool")
    if Path(by_guest["/rc/bin/okernel-start"]["path"]).read_bytes() != (captured / "START.RC").read_bytes():
        raise ValueError("provider startup differs from captured source")
    if Path(by_guest["/arm64/bin/p9cmdsrv"]["path"]).read_bytes() != (exports / "SERVICE").read_bytes():
        raise ValueError("provider service differs from compiled export")
    uimage, _ = inspect_uimage(exports / "KERNEL.U")
    if uimage["timestamp"] != original.EPOCH:
        raise ValueError("kernel did not observe fixed build clock")
    return {"ok": True, "artifacts": {p.name: identity(p) for p in exports.iterdir()},
            "original_tools": native_tools, "provider_files": files,
            "provider_bytes": sum(x["bytes"] for x in files), "uimage": uimage,
            "checks": ["selected original tool/header/library closure extracted and fully hash-matched",
                       "service compiled by original ARM64 7c/7l with libsec/libmp",
                       "readonly PAQ mounted and its compiler/header/libc closure executed a native hello",
                       "original UART-patched kernel rebuilt embedding the unchanged provider PAQ",
                       "private build filesystems halted before export extraction"]}


def revalidate(output: Path) -> Path:
    """Recheck frozen exports after a host validator correction; never rerun VM."""
    output = output.absolute()
    previous = output / "result.json"
    record = json.loads(previous.read_text())
    destination = output / "result-revalidated.json"
    if destination.exists() or destination.is_symlink():
        raise ValueError("revalidation receipt already exists")
    if record.get("schema") != "ostadix.original9front-userland-builder/v1" or record.get("source_commit") != COMMIT:
        raise ValueError("revalidation requires the pinned original userland builder receipt")
    if (record.get("exports_captured_after_halt") is not True
            or not isinstance(record.get("artifacts"), dict)
            or set(record["artifacts"]) != set(EXPORTS)):
        raise ValueError("revalidation requires export identities sealed before the failed host check")
    def checked(item):
        observed = identity(Path(item["path"]))
        if observed != item:
            raise ValueError("frozen original build evidence changed: " + item["path"])
    for item in record["inputs"].values():
        checked(item)
    for item in record["platform_artifacts"].values():
        checked(item)
    for item in record["host_tools"].values():
        checked(item)
    for item in record["artifacts"].values():
        checked(item)
    checked(record["console"])
    if admit_image(Path(record["official_image"]["path"])) != record["official_image"]:
        raise ValueError("private original image changed")
    captured = output / "inputs"
    script = (captured / "BUILD.RC").read_text()
    tokens = re.findall(r"echo P9_PROVIDER_PASS_([0-9a-f]{24})", script)
    text = Path(record["console"]["path"]).read_bytes().replace(b"\r", b"")
    if len(tokens) != 1 or not text.rstrip(b"\n").endswith(b"done halting"):
        raise ValueError("frozen native build did not cleanly halt")
    required = [("P9_PROVIDER_PASS_" + tokens[0]).encode(), b"P9_USERLAND_NATIVE_HELLO",
                ("P9_CLOCK " + str(original.EPOCH)).encode()]
    if any(marker not in text.splitlines() for marker in required):
        raise ValueError("frozen native build lacks exact success markers")
    if "if(! ~ $paqbefore(1) $paqafter(1)) fail changedpaq" not in script:
        raise ValueError("frozen builder did not check exact PAQ continuity")
    record["prior_failed_receipt"] = identity(previous)
    record["revalidation"] = {"validator": identity(Path(__file__)),
                              "reason": "original boot prototypes remap files; match the complete selected provider originals instead of unrelated installed same-name boot scripts",
                              "scope": "host export validation only; original native execution evidence retained unchanged"}
    record.pop("error", None)
    provider_dir = Path(tempfile.mkdtemp(prefix="provider-revalidated-", dir=output))
    record.update(qualify_exports(output, captured, provider_dir))
    destination.write_text(json.dumps(record, indent=2) + "\n")
    return destination


def build(args) -> dict:
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("output must be a new private directory")
    source_image = admit_image(args.image)
    for path in (args.service, args.startup):
        if path.is_symlink() or not path.is_file():
            raise ValueError("service/startup input must be a regular nonsymlink file")
    names = [args.qemu, "qemu-img", "dtc", "clang", "llvm-objcopy", "mkfs.fat", "mcopy"]
    tools = {name: shutil.which(name) for name in names}
    if not all(tools.values()):
        raise ValueError("required tools missing: " + ", ".join(k for k, v in tools.items() if not v))
    output.mkdir(parents=True)
    record = {"schema": "ostadix.original9front-userland-builder/v1", "ok": False,
              "source_commit": COMMIT, "epoch": original.EPOCH, "source_image": source_image,
              "scope": "original ARM64 tools compile a Plan9 command service and kernel with embedded readonly userland; private host-QEMU build only",
              "nonclaims": ["not O-core source lowering", "not runtime command-service acceptance",
                            "admitted original toolchain binaries are not bootstrapped here",
                            "observed image digest pin, not upstream signature verification"]}
    commands = []
    def run(argv, **kw):
        result = subprocess.run([str(x) for x in argv], capture_output=True, text=True, **kw)
        commands.append({"argv": [str(x) for x in argv], "exit_code": result.returncode,
                         "stdout": result.stdout, "stderr": result.stderr})
        result.check_returncode()
        return result
    try:
        captured = output / "inputs"; captured.mkdir()
        for name, path in (("builder.py", Path(__file__)), ("original-builder.py", Path(original.__file__)),
                           ("probe.py", ROOT / "scripts/probe_okernel_plan9.py"),
                           ("P9CMDSRV.C", args.service), ("START.RC", args.startup),
                           ("builder.dts", original.PLATFORM / "builder.dts"),
                           ("entry.S", original.PLATFORM / "builder-entry.S"),
                           ("uart.patch", original.PLATFORM / "namespace-uart.patch")):
            shutil.copyfile(path, captured / name)
        (captured / "UNIFIED.PRT").write_text(provider_proto())
        (captured / "HELLO.C").write_bytes(HELLO)
        (captured / "FIXTIME").write_bytes(struct.pack(">4Q", original.EPOCH * 10**9, 1, 10**9, 10**9))
        token = secrets.token_hex(12)
        (captured / "BUILD.RC").write_text(guest_script(token))
        base = output / "official.qcow2"; shutil.copyfile(args.image, base)
        record["official_image"] = admit_image(base); base.chmod(0o400)
        info = json.loads(run([tools["qemu-img"], "info", "--output=json", str(base)]).stdout)
        if info.get("format") != "qcow2" or info.get("backing-filename"):
            raise ValueError("original image must have no undeclared backing")
        raw = output / "official.raw"
        run([tools["qemu-img"], "convert", "-f", "qcow2", "-O", "raw", base, raw])
        run([tools["mcopy"], "-i", str(raw) + "@@" + str(original.FAT_OFFSET), "::/9qemu.u", output / "original.u"], env=original.MTOOLS_ENV)
        if identity(output / "original.u")["sha256"] != UIMAGE_SHA256:
            raise ValueError("original boot kernel differs from its pinned image")
        metadata, payload = inspect_uimage(output / "original.u")
        (output / "kernel.raw").write_bytes(payload)
        record["original_kernel"] = {"container": identity(output / "original.u"), "uimage": metadata}
        # Derive only the already reviewed UART patch from its exact original
        # source, supplied by the frozen previous native builder receipt.
        uart_source = args.uart_original
        uart = original.patched_uart(uart_source.read_bytes())
        (captured / "UART.C").write_bytes(uart)
        record["uart_original"] = identity(uart_source)
        record["host_tools"] = {name: identity(Path(path)) for name, path in tools.items()}
        run([tools["dtc"], "-I", "dts", "-O", "dtb", "-o", output / "builder.dtb", captured / "builder.dts"])
        run([tools["clang"], "--target=aarch64-none-elf", "-march=armv8-a", "-c", captured / "entry.S", "-o", output / "entry.o"])
        run([tools["llvm-objcopy"], "-O", "binary", output / "entry.o", output / "entry.bin"])
        fat = output / "transfer.fat"
        run([tools["mkfs.fat"], "-C", fat, "65536"])
        for name in ("FIXTIME", "BUILD.RC", "UART.C", "P9CMDSRV.C", "START.RC", "UNIFIED.PRT", "HELLO.C"):
            run([tools["mcopy"], "-i", fat, captured / name, "::/" + name], env=original.MTOOLS_ENV)
        overlay = output / "builder.qcow2"
        run([tools["qemu-img"], "create", "-f", "qcow2", "-F", "qcow2", "-b", base, overlay])
        argv = [tools[args.qemu], "-machine", "virt,highmem=off,virtualization=on,gic-version=3,its=off",
                "-cpu", "cortex-a57", "-smp", "1", "-m", "1G", "-accel", "tcg,thread=single",
                "-nodefaults", "-nic", "none", "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot",
                "-dtb", str(output / "builder.dtb"), "-device", f"loader,file={output / 'kernel.raw'},addr=0x40100000,force-raw=on",
                "-device", f"loader,file={output / 'entry.bin'},addr=0x47000000,force-raw=on", "-device", "loader,addr=0x47000000,cpu-num=0",
                "-drive", f"if=none,id=root,file={overlay},format=qcow2", "-device", "virtio-blk-pci,drive=root,disable-legacy=on",
                "-drive", f"if=none,id=input,file={fat},format=raw", "-device", "virtio-blk-pci,drive=input,disable-legacy=on"]
        record["argv"] = argv
        for path in captured.iterdir():
            path.chmod(0o444)
        record["inputs"] = {p.name: identity(p) for p in captured.iterdir()}
        record["platform_artifacts"] = {name: identity(output / name) for name in ("builder.dtb", "entry.bin", "kernel.raw")}
        (output / "argv.json").write_text(json.dumps(argv, indent=2) + "\n")
        run_guest(argv, output, token, args.timeout)
        exports = output / "artifacts"; exports.mkdir()
        for name in EXPORTS:
            run([tools["mcopy"], "-i", fat, "::/" + name, exports / name], env=original.MTOOLS_ENV)
        # Bind the completed native exports before host qualification, so a
        # later validator correction cannot promote substituted exports using
        # only an old native success transcript.
        record["artifacts"] = {name: identity(exports / name) for name in EXPORTS}
        record["exports_captured_after_halt"] = True
        record.update(qualify_exports(output, captured, output / "provider"))
        return record
    except BaseException as error:
        record["error"] = str(error)
        raise
    finally:
        record["commands"] = commands
        if (output / "console.log").exists():
            record["console"] = identity(output / "console.log")
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, default=Path.home() / ".cache/ostadix/plan9-original/9front-12115-arm64/9front-12115.arm64.qcow2")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--revalidate", type=Path, help="recheck completed native exports without launching a VM")
    parser.add_argument("--service", type=Path, default=PROVIDER / "p9cmdsrv.c")
    parser.add_argument("--startup", type=Path, default=PROVIDER / "start.rc")
    parser.add_argument("--uart-original", type=Path,
                        help="original UART.C from a preserved pinned native-builder export")
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=900)
    args = parser.parse_args()
    try:
        if args.revalidate is not None:
            path = revalidate(args.revalidate)
            print("Original Plan9 userland revalidation: PASS\nEvidence: " + str(path))
            return 0
        if args.uart_original is None:
            parser.error("--output requires --uart-original")
        result = build(args)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("Original Plan9 userland build failed: " + str(error), file=sys.stderr)
        return 1
    print("Original Plan9 userland build: PASS\nEvidence: " + str(args.output.absolute() / "result.json"))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
