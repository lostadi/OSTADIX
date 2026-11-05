#!/usr/bin/env python3
"""Bounded USB keyboard/VGA proof in one newly owned OVMF/QEMU guest.

Without --launch this prints a plan and starts no process. The launched profile
disables i8042, denies the usbkbd fallback module for this explicit test,
supplies only one USB keyboard, and uses serial input solely for
the explicitly recorded GRUB boot commands. Guest user input is QMP USB key
events. No share or physical disk is attached. This emulated device proof does
not qualify physical X12 hardware, the default boot entry, or the inner runtime.

After launch, inspect progress.json and its PNG screenshots. Append controls to
commands.jsonl in the new output directory, one JSON object per line:
  {"action":"snapshot"}
  {"action":"pause"}
  {"action":"arm_entry_watch","screenshot":"...png"}
  {"action":"entry_prompt_visible","screenshot":"...png",
   "observed_text":"Type n within eight seconds ..."}
  {"action":"network_prompt_visible","screenshot":"...png",
   "observed_text":"Interface (for example ...):"}
  {"action":"invalid_interface_visible","screenshot":"...png",
   "observed_text":"<the recorded token> Invalid interface."}
  {"action":"advance","milliseconds":5}
  {"action":"abort"}
The network confirmation sends the unique token once, then captures bounded
short execution steps and pauses the VM. Advance captures another bounded step.
With --manual-entry, an armed pixel-change watch pauses on new visible content
after the seed-loading banner; it ignores cursor blink and makes no OCR claim.
Confirm the actual paused entry prompt before the one network-entry key pair.
Manual confirmations are recorded as visual observations, not OCR results.
Only the Popen process and private QMP connection created here are controlled.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import zlib


KERNEL_ARGUMENTS = "console=ttyS0,115200n8 console=tty0 rdinit=/init module_blacklist=usbkbd"
REQUIRED_INIT_SHA256 = "2c2ff5a0f8fff20943042512963fd5ccff1a46a43187b8063c322cd5e3fdff64"
BOOT_COMMANDS = (
    "linux /boot/vmlinuz " + KERNEL_ARGUMENTS,
    "initrd /boot/initramfs.gz",
    "boot",
)
HELPER = b"OKERNEL X12 HOTPLUG DRIVER HELPER: /usr/bin/mdev"
PROMPT = "interface (for example"


def identity(path: Path) -> dict:
    path = Path(path)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest}


def terminal_text(raw: bytes) -> bytes:
    raw = re.sub(rb"\x1b\][^\x07]*(?:\x07|\x1b\\)", b"", raw)
    raw = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", raw)
    return raw.replace(b"\r", b"")


def settled_grub_prompt(raw: bytes, idle_seconds: float) -> bool:
    # Dual GRUB terminals redraw the prompt twice. A substring match can see
    # the second old redraw while the previous command is still being typed.
    return idle_seconds >= .25 and terminal_text(raw).rstrip().endswith(b"grub>")


def usb_driver_evidence(text: bytes, *, require_uart_helper=True) -> dict | None:
    if b"usbcore: registered new interface driver usbkbd" in text:
        raise ValueError("usbkbd fallback loaded; this fixture does not qualify the HID child route")
    keyboard = re.search(rb"input:[^\n]*QEMU[^\n]*USB Keyboard", text)
    generic = re.search(rb"hid-generic[^\n]*Keyboard[^\n]*QEMU", text)
    usbhid = b"usbhid: USB HID core driver"
    if (require_uart_helper and HELPER not in text) or keyboard is None or generic is None or usbhid not in text:
        return None
    evidence = {"usb_hid_core_marker": usbhid.decode(),
            "input_registration": keyboard.group().decode(errors="replace"),
            "hid_registration": generic.group().decode(errors="replace")}
    if HELPER in text:
        evidence["helper_readback_uart_marker"] = HELPER.decode()
    return evidence


def iso_file_extent(path: Path, components: tuple[str, ...]) -> tuple[int, int]:
    """Read a bounded ISO9660 directory route; no mount or extraction."""
    with path.open("rb") as stream:
        size = path.stat().st_size
        def both32(raw, offset):
            little = int.from_bytes(raw[offset:offset+4], "little")
            if little != int.from_bytes(raw[offset+4:offset+8], "big"):
                raise ValueError("ISO both-endian field disagrees")
            return little
        def extent(record):
            offset, length = both32(record, 2) * 2048, both32(record, 10)
            if offset + length > size: raise ValueError("ISO file extent leaves image")
            return offset, length
        stream.seek(16 * 2048); pvd = stream.read(2048)
        if pvd[:7] != b"\x01CD001\x01" or both32(pvd, 80) * 2048 != size:
            raise ValueError("invalid or incomplete ISO volume")
        selected = pvd[156:156+pvd[156]]
        for component in components:
            start, length = extent(selected)
            if not selected[25] & 2 or length > 1024 * 1024:
                raise ValueError("ISO route has an invalid directory")
            stream.seek(start); directory = stream.read(length); position = 0; matches = []
            while position < len(directory):
                n = directory[position]
                if n == 0:
                    position = (position // 2048 + 1) * 2048; continue
                record = directory[position:position+n]
                if len(record) != n or n < 34 or 33 + record[32] > n:
                    raise ValueError("invalid ISO directory record")
                name = record[33:33+record[32]].decode("ascii", errors="strict").split(";")[0].rstrip(".")
                # grub-mkrescue's primary ISO names use8.3 truncation. Retain
                # the actual Rock Ridge NM name for rootfs.squashfs.
                system = 33 + record[32] + (record[32] % 2 == 0)
                pieces = []
                while system + 4 <= len(record):
                    entry_length = record[system+2]
                    if entry_length == 0: break
                    if entry_length < 4 or system + entry_length > len(record):
                        raise ValueError("invalid ISO Rock Ridge entry")
                    item = record[system:system+entry_length]
                    if item[:2] == b"NM" and entry_length >= 5 and not item[4] & 6:
                        pieces.append(item[5:])
                    system += entry_length
                if pieces: name = b"".join(pieces).decode("utf-8", errors="strict")
                name = name.upper()
                if name == component: matches.append(record)
                position += n
            if len(matches) != 1: raise ValueError("ISO route is missing or ambiguous: " + component)
            selected = matches[0]
        return extent(selected)


def verify_init_guards(raw: bytes) -> dict:
    statements = [b"set -eu", b"[ -x /usr/bin/mdev ]",
                  b"printf '%s\\n' /usr/bin/mdev > /proc/sys/kernel/hotplug",
                  b'[ "$(cat /proc/sys/kernel/hotplug)" = /usr/bin/mdev ]',
                  b"echo 'OKERNEL X12 HOTPLUG DRIVER HELPER: /usr/bin/mdev' >/dev/console",
                  b"modprobe -a -b -- $aliases 2>/dev/null || true"]
    offsets = [raw.find(item) for item in statements]
    if any(x < 0 for x in offsets) or offsets != sorted(set(offsets)):
        raise ValueError("contained init lacks audited fail-closed helper guards before driver admission")
    return {statement.decode(): offset for statement, offset in zip(statements, offsets)}


def bind_helper_preflight(iso: Path, receipt: dict, *, required_init_sha=REQUIRED_INIT_SHA256) -> dict:
    offset, length = iso_file_extent(iso, ("BOOT", "ROOTFS.SQUASHFS"))
    squash = receipt["squashfs"]
    digest = hashlib.sha256()
    with iso.open("rb") as stream:
        stream.seek(offset); remaining = length
        while remaining:
            block = stream.read(min(remaining, 1024 * 1024))
            if not block: raise ValueError("truncated contained SquashFS")
            digest.update(block); remaining -= len(block)
    if length != squash["bytes"] or digest.hexdigest() != squash["sha256"]:
        raise ValueError("contained SquashFS does not match the completed receipt")
    inv = receipt["root_inventory"]
    tool = Path(shutil.which("unsquashfs") or "/usr/bin/unsquashfs").resolve(strict=True)
    command = [str(tool), "-no-wildcards", "-cat", "-offset", str(offset), str(iso),
               "usr/sbin/init", "usr/share/okernel/image.json"]
    result = subprocess.run(command, capture_output=True, timeout=30)
    if result.returncode: raise ValueError("contained init read failed: " + result.stderr.decode(errors="replace")[-500:])
    expected = inv["usr/sbin/init"]; metadata_pin = inv["usr/share/okernel/image.json"]
    raw, metadata = result.stdout[:expected["bytes"]], result.stdout[expected["bytes"]:]
    if (len(raw) != expected["bytes"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]
            or len(metadata) != metadata_pin["bytes"] or hashlib.sha256(metadata).hexdigest() != metadata_pin["sha256"]):
        raise ValueError("contained init/image metadata identity mismatch")
    if expected["sha256"] != required_init_sha:
        raise ValueError("this fixture requires the reviewed exact helper-readback init")
    image = json.loads(metadata)
    if image["helpers"]["init"] != {key: expected[key] for key in ("bytes", "sha256")}:
        raise ValueError("contained image metadata does not bind the selected init")
    guards = verify_init_guards(raw)
    return {"method": "audited exact contained init with set-e and executable/readback assertions before batch admission",
            "contained_init": {key: expected[key] for key in ("bytes", "sha256")},
            "contained_squashfs": {"bytes": length, "sha256": digest.hexdigest(), "iso_offset": offset},
            "image_metadata": {key: metadata_pin[key] for key in ("bytes", "sha256")},
            "guard_statement_offsets": guards, "read_tool": identity(tool), "read_command": command,
            "requires_actual_entry_prompt": True, "uart_helper_literal_claimed": False,
            "qualification_scope": "VT-primary fixture: source-bound assertions plus actual continued entry prove helper readback succeeded; no invented UART marker"}


def profile(iso: Path, qemu: Path, firmware: Path, memory: int, qmp: Path) -> list[str]:
    return [str(qemu), "-machine", "q35,i8042=off", "-accel", "tcg,thread=multi",
            "-cpu", "max", "-smp", "2", "-m", str(memory), "-nodefaults",
            "-drive", "if=pflash,format=raw,readonly=on,file=" + str(firmware).replace(",", ",,"),
            "-drive", "if=none,id=live,format=raw,media=cdrom,readonly=on,file=" + str(iso).replace(",", ",,"),
            "-device", "ide-cd,drive=live,bus=ide.0", "-device", "VGA",
            "-device", "qemu-xhci,id=xhci", "-device", "usb-kbd,id=usbkbd,bus=xhci.0",
            "-nic", "none", "-display", "none", "-serial", "stdio", "-monitor", "none",
            "-boot", "order=d", "-qmp", "unix:" + str(qmp) + ",server=on,wait=off"]


def new_output(path: Path) -> Path:
    path = path.absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        if part in (".", ".."):
            raise ValueError("output path must be canonical")
        current /= part
        if current.is_symlink():
            raise ValueError("output path contains a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    return path


def ppm_rgb(raw: bytes) -> tuple[int, int, bytes]:
    match = re.match(rb"P6\n([1-9][0-9]*) ([1-9][0-9]*)\n255\n", raw)
    if match is None:
        raise ValueError("unexpected QEMU P6 screenshot header")
    width, height = map(int, match.groups())
    pixels = raw[match.end():]
    if width * height > 16_777_216 or len(pixels) != width * height * 3:
        raise ValueError("screenshot dimensions/data length outside bound")
    return width, height, pixels


def ppm_to_png(raw: bytes) -> bytes:
    """Encode QEMU's P6 RGB screenshot without an image-library dependency."""
    width, height, pixels = ppm_rgb(raw)
    def chunk(kind, content):
        return (struct.pack(">I", len(content)) + kind + content
                + struct.pack(">I", zlib.crc32(kind + content)))
    rows = b"".join(b"\0" + pixels[i:i + width * 3]
                    for i in range(0, len(pixels), width * 3))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 3)) + chunk(b"IEND", b""))


class QMP:
    def __init__(self, path: Path, process, timeout=30):
        deadline = time.monotonic() + timeout
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)
        while True:
            if process.poll() is not None:
                self.socket.close()
                raise RuntimeError("owned QEMU stopped before QMP")
            try:
                self.socket.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    self.socket.close()
                    raise TimeoutError("owned QMP startup deadline")
                time.sleep(.05)
        self.stream = self.socket.makefile("rwb", buffering=0)
        self.sequence = 0
        if "QMP" not in json.loads(self.stream.readline()):
            raise RuntimeError("invalid owned QMP greeting")
        self.execute("qmp_capabilities")

    def execute(self, name: str, arguments=None):
        self.sequence += 1
        self.stream.write((json.dumps({"execute": name, "arguments": arguments or {},
                                      "id": self.sequence}) + "\n").encode())
        while True:
            line = self.stream.readline()
            if not line:
                raise RuntimeError("owned QMP disconnected")
            reply = json.loads(line)
            if reply.get("id") == self.sequence:
                if "error" in reply:
                    raise RuntimeError("QMP " + name + ": " + str(reply["error"]))
                return reply.get("return")

    def close(self):
        self.stream.close()
        self.socket.close()


class SerialBoot:
    """No method permits serial guest input after the recorded boot command."""
    def __init__(self, write, record):
        self.write, self.record = write, record
        self.boot_sent = False

    def send(self, data: bytes):
        if self.boot_sent:
            raise ValueError("serial guest input is prohibited after GRUB boot")
        self.write(data)
        self.record.setdefault("grub_serial_inputs", []).append(data.hex())
        if data.lstrip(b"\x15") == b"boot\r":
            self.boot_sent = True


class USBProof:
    def __init__(self, qmp, record, token, event, screenshot, sleep=time.sleep):
        if re.fullmatch(r"hid[a-z0-9]{10}", token) is None:
            raise ValueError("invalid unique proof interface token")
        self.qmp, self.record, self.token = qmp, record, token
        self.event, self.screenshot, self.sleep = event, screenshot, sleep
        self.stage = "boot"
        self.paused = False
        self.network_keys_sent = False
        self.token_sent = False
        self.screens = {}
        self.entry_watch = None

    def key(self, code):
        if code not in set("abcdefghijklmnopqrstuvwxyz0123456789") | {"ret"}:
            raise ValueError("USB proof key outside fixed alphabet")
        if self.paused:
            raise ValueError("USB input is prohibited while the owned VM is paused")
        binding = self.record.get("helper_readback_evidence", {})
        if binding.get("requires_actual_entry_prompt") and "entry_prompt_evidence" not in self.record:
            raise ValueError("source-bound helper proof requires actual reviewed entry before keys")
        runstate = self.qmp.execute("query-status")
        if not isinstance(runstate, dict) or runstate.get("running") is not True or runstate.get("status") != "running":
            raise ValueError("USB input requires observed QMP running state")
        arguments = {"keys": [{"type": "qcode", "data": code}], "hold-time": 30}
        self.qmp.execute("send-key", arguments)
        self.record.setdefault("usb_key_inputs", []).append({"qcode": code, "stage": self.stage,
                                                             "arguments": arguments,
                                                             "observed_qmp_runstate": runstate})
        # QEMU8.2.2 queues both the press and delayed release. Allow the full
        # stroke to drain while running before sending another key or pausing.
        self.sleep(.08)

    def queue_network_entry(self):
        if self.network_keys_sent:
            raise ValueError("network entry keys already sent; no replay")
        self.network_keys_sent = True
        self.stage = "await-network-prompt"
        self.screenshot("before-network-keys")
        self.key("n"); self.key("ret")
        self.event("usb-network-entry-queued-once")

    def begin_manual_entry(self):
        self.stage = "await-entry-prompt"
        self.screenshot("manual-entry-wait")
        self.event("usb-hid-ready-manual-entry-prompt-review-required")

    def arm_entry_watch(self, command):
        if self.stage != "await-entry-prompt":
            raise ValueError("entry watch is only available before network-entry keys")
        screen = self.screens.get(command.get("screenshot"))
        if screen is None or screen["stage"] != self.stage:
            raise ValueError("entry watch needs a screenshot from this entry phase")
        for kind in ("png", "ppm"):
            if identity(Path(screen[kind]["path"])) != screen[kind]:
                raise ValueError("entry watch screenshot changed")
        self.entry_watch = (screen, ppm_rgb(Path(screen["ppm"]["path"]).read_bytes()))
        self.record["entry_watch_reference"] = screen
        self.resume()
        self.event("entry-content-change-watch-armed-no-ocr")

    def observe_screen(self, screen):
        if self.entry_watch is None or self.stage != "await-entry-prompt":
            return
        reference, (width, height, pixels) = self.entry_watch
        new_width, new_height, new = ppm_rgb(Path(screen["ppm"]["path"]).read_bytes())
        if (width, height) != (new_width, new_height):
            changed = width * height
        else:
            # The seed-loading console's cursor blinks in its final two rows.
            # Any other substantive change pauses for visual review; this does
            # not interpret text or assert that a prompt is present.
            limit = width * max(0, height - 2) * 3
            changed = sum(pixels[i:i+3] != new[i:i+3] for i in range(0, limit, 3))
        if changed > 128:
            self.entry_watch = None
            self.pause()
            self.record["entry_screen_change"] = {"reference": reference["png"],
                "changed": screen["png"], "different_pixels_excluding_cursor_rows": changed}
            self.screenshot("entry-content-change-paused")
            self.event("new-vga-content-paused-for-manual-entry-review")

    def confirm_entry(self, command):
        evidence = self.attest(command, "await-entry-prompt", ["type n within eight seconds"])
        screen = self.screens[command["screenshot"]]
        if not self.paused or not screen["paused"]:
            raise ValueError("entry confirmation requires an actually paused screenshot and VM")
        self.entry_watch = None
        self.record["entry_prompt_evidence"] = evidence
        if "helper_readback_evidence" in self.record:
            self.record["helper_readback_evidence"]["actual_entry_prompt"] = evidence
        self.resume()
        self.sleep(.05)
        self.queue_network_entry()

    def pause(self):
        if not self.paused:
            self.qmp.execute("stop")
            self.paused = True

    def resume(self):
        if self.paused:
            self.qmp.execute("cont")
            self.paused = False

    def attest(self, command, expected_stage, required_text):
        if self.stage != expected_stage:
            raise ValueError("visual confirmation is outside its expected phase")
        name = command.get("screenshot")
        screen = self.screens.get(name)
        if screen is None or screen["stage"] != expected_stage:
            raise ValueError("confirmation must name a screenshot from this proof phase")
        if identity(Path(screen["png"]["path"])) != screen["png"]:
            raise ValueError("confirmed screenshot changed")
        observed = " ".join(str(command.get("observed_text", "")).lower().split())
        if not all(text in observed for text in required_text):
            raise ValueError("visual observation must include the required prompt/token/error")
        return {"method": "manual visual observation", "screenshot": screen["png"],
                "observed_text": command["observed_text"]}

    def send_token(self, command, steps, milliseconds):
        evidence = self.attest(command, "await-network-prompt", [PROMPT])
        if self.token_sent:
            raise ValueError("interface token already sent; no replay")
        self.record["network_prompt_evidence"] = evidence
        self.token_sent = True
        self.resume()
        self.stage = "typing-interface-token"
        for code in self.token:
            self.key(code)
        self.screenshot("typed-interface-token")
        # QEMU drops input events while paused. Send the complete Return stroke
        # while running, then pause/capture the original helper's visible error.
        # No inner commands are sent or workload qualification claimed.
        self.stage = "await-invalid-interface"
        self.key("ret")
        self.pause()
        self.screenshot("return-processed-paused")
        for _ in range(steps):
            self.advance(milliseconds)
        self.event("unique-usb-interface-token-sent-once-vm-paused")

    def advance(self, milliseconds):
        if self.stage not in ("await-invalid-interface", "await-entry-prompt") or not 1 <= milliseconds <= 100:
            raise ValueError("advance requires an entry/error phase and1..100 milliseconds")
        self.resume()
        self.sleep(milliseconds / 1000)
        self.pause()
        self.screenshot("execution-step")

    def confirm_error(self, command):
        evidence = self.attest(command, "await-invalid-interface",
                               [self.token, "invalid interface"])
        binding = self.record.get("helper_readback_evidence", {})
        if binding.get("requires_actual_entry_prompt") and "actual_entry_prompt" not in binding:
            raise ValueError("helper causal binding lacks the actual reviewed entry")
        self.pause()
        self.record["received_usb_input_proof"] = evidence
        self.record["ok"] = True
        self.stage = "complete"
        self.event("visible-token-and-original-invalid-interface-error-confirmed")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--launch", action="store_true", help="explicitly launch the new owned VM; default prints plan only")
    parser.add_argument("--manual-entry", action="store_true", help="pause/review the fresh tty1 entry prompt before the single network-entry key pair")
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--firmware", type=Path, default=Path("/usr/share/OVMF/OVMF_CODE_4M.fd"))
    parser.add_argument("--memory-mib", type=int, default=4096)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--screenshot-interval", type=float, default=5)
    parser.add_argument("--transition-steps", type=int, default=20)
    parser.add_argument("--transition-step-ms", type=int, default=5)
    args = parser.parse_args()
    if not (2048 <= args.memory_mib <= 8192 and 1 <= args.timeout <= 1800
            and 1 <= args.screenshot_interval <= 60 and 1 <= args.transition_steps <= 40
            and 1 <= args.transition_step_ms <= 100):
        parser.error("memory/deadline/screenshot/transition bounds are invalid")
    if args.launch and args.output is None:
        parser.error("--launch requires a new --output directory")
    if args.launch and not args.manual_entry:
        parser.error("this VT-primary fixture requires --manual-entry")
    iso = args.iso.resolve(strict=True)
    firmware = args.firmware.resolve(strict=True)
    qemu = Path(shutil.which(args.qemu) or args.qemu).resolve(strict=True)
    plan = {"schema": "ostadix.x12-usb-hid-proof/v1", "ok": False,
            "iso": identity(iso), "firmware": identity(firmware), "qemu": identity(qemu),
            "verifier": identity(Path(__file__).resolve()), "kernel_arguments": KERNEL_ARGUMENTS,
            "grub_commands": list(BOOT_COMMANDS), "manual_grub_profile": True,
            "serial_input_scope": "GRUB only; guest input after boot exclusively QMP USB keys",
            "keyboard_profile": "i8042 disabled; one usb-kbd on explicit qemu-xhci; no other keyboard",
            "keyboard_runstate_rule": "query-status must report running before every key; complete key stroke drains before pause",
            "keyboard_runstate_primary_source": "https://raw.githubusercontent.com/qemu/qemu/v8.2.2/ui/input.c",
            "test_module_blacklist": ["usbkbd"],
            "test_module_blacklist_scope": "explicit manual GRUB fixture forces usbhid/HID-child/hid-generic route; ISO/defaults unchanged",
            "manual_paused_entry_fixture": args.manual_entry,
            "console_priority": "serial kernel console first, VT0 last; cttyhack selects VT1 for userspace",
            "console_priority_source": "https://raw.githubusercontent.com/mirror/busybox/1_36_1/shell/cttyhack.c",
            "scope": __doc__, "physical_hardware_qualified": False,
            "default_boot_entry_qualified": False, "inner_runtime_qualified": False,
            "existing_vm_actions": [], "events": [], "screenshots": []}
    receipt = iso.parent / "result.json"
    if receipt.is_file():
        bound = json.loads(receipt.read_bytes())
        if bound.get("ok") is not True or any(bound.get("iso", {}).get(k) != plan["iso"][k]
                                              for k in ("bytes", "sha256")):
            parser.error("ISO does not match its completed adjacent receipt")
        plan["iso_build_receipt"] = identity(receipt)
        plan["helper_readback_evidence"] = bind_helper_preflight(iso, bound)
    elif args.launch:
        parser.error("launch requires a completed adjacent image receipt and contained helper binding")
    if not args.launch:
        plan["launch_disabled"] = True
        plan["command_template"] = profile(iso, qemu, firmware, args.memory_mib, Path("OWN_PRIVATE_QMP_SOCKET"))
        print(json.dumps(plan, indent=2))
        return 0

    output = new_output(args.output)
    (output / "verifier.py").write_bytes(Path(__file__).read_bytes())
    controls = output / "commands.jsonl"; controls.touch(mode=0o600, exist_ok=False)
    record = plan
    record.update(output=str(output), timeout_seconds=args.timeout,
                  proof_interface_token="hid" + secrets.token_hex(5), started_unix=time.time())
    process = qmp = proof = serial_log = selector = None
    capture = bytearray(); screenshot_number = 0; next_screen = 0.0
    started = time.monotonic(); control_offset = 0; pending = b""
    control_stat = controls.stat(); control_inode = (control_stat.st_dev, control_stat.st_ino)
    def save(name="progress.json"):
        record["stage"] = proof.stage if proof else "starting"
        record["paused"] = proof.paused if proof else False
        (output / name).write_text(json.dumps(record, indent=2) + "\n")
    def event(name, **fields):
        record["events"].append({"event": name, "seconds": time.monotonic() - started, **fields})
        print("USB HID check: " + name, flush=True)
        save()
    def screenshot(label):
        nonlocal screenshot_number
        if screenshot_number >= 240:
            raise RuntimeError("bounded screenshot count exceeded")
        screenshot_number += 1
        stem = f"{screenshot_number:04d}-{label}"
        ppm = output / (stem + ".ppm"); png = output / (stem + ".png")
        qmp.execute("screendump", {"filename": str(ppm)})
        png.write_bytes(ppm_to_png(ppm.read_bytes()))
        item = {"stage": proof.stage, "seconds": time.monotonic() - started,
                "ppm": identity(ppm), "png": identity(png), "paused": proof.paused}
        record["screenshots"].append(item); proof.screens[png.name] = item
        save()
        proof.observe_screen(item)
        return item
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    previous = {s: signal.signal(s, interrupted) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        with tempfile.TemporaryDirectory(prefix="okhid.", dir="/tmp") as private:
            command = profile(iso, qemu, firmware, args.memory_mib, Path(private) / "q")
            record["command"] = command
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True, bufsize=0)
            record["owned_qemu_pid"] = process.pid
            qmp = QMP(Path(private) / "q", process)
            record["pci_topology"] = qmp.execute("query-pci")
            proof = USBProof(qmp, record, record["proof_interface_token"], event, screenshot)
            def serial_write(data):
                # GRUB's polling serial editor and two terminal redraw paths
                # require paced input; never bulk-feed a later prompt's line.
                for byte in data:
                    process.stdin.write(bytes([byte])); process.stdin.flush()
                    time.sleep(.015)
            serial = SerialBoot(serial_write, record)
            serial_log = (output / "console.log").open("xb")
            selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
            boot_stage = "menu"; grub_after = 0; command_index = 0
            driver_ready = False
            last_serial = time.monotonic()
            event("owned-usb-only-vm-started")
            while time.monotonic() - started < args.timeout:
                for key, _ in selector.select(.05):
                    block = os.read(key.fd, 65536)
                    if block:
                        capture.extend(block); serial_log.write(block); serial_log.flush()
                        last_serial = time.monotonic()
                if len(capture) > 8 * 1024 * 1024:
                    raise RuntimeError("bounded UART capture exceeded")
                text = terminal_text(bytes(capture))
                if any(x in text for x in (b"Kernel panic", b"OKERNEL X12 BOOTSTRAP: FAIL")):
                    raise RuntimeError("kernel/bootstrap failure; inspect console.log")
                if boot_stage == "menu" and b"OKernel serial test console" in text:
                    grub_after = len(capture); serial.send(b"c"); boot_stage = "grub"
                    event("entered-grub-command-line-via-serial")
                if boot_stage == "grub":
                    fresh = terminal_text(bytes(capture[grub_after:]))
                    if b"error:" in fresh.lower():
                        raise RuntimeError("GRUB rejected recorded boot command")
                    if settled_grub_prompt(bytes(capture[grub_after:]), time.monotonic() - last_serial):
                        grub_after = len(capture)
                        line = BOOT_COMMANDS[command_index]
                        serial.send(b"\x15" + line.encode() + b"\r"); command_index += 1
                        if line == "boot":
                            boot_stage = "booted"
                            event("recorded-contained-kernel-dual-console-boot-command-sent")
                if boot_stage == "booted" and not driver_ready:
                    evidence = usb_driver_evidence(text, require_uart_helper=False)
                    if evidence:
                        record["driver_evidence"] = {**evidence, "uart_bytes_at_driver_ready": len(capture)}
                        event("hotplug-helper-readback-and-usb-hid-registration-observed")
                        driver_ready = True
                        if args.manual_entry: proof.begin_manual_entry()
                        else: proof.queue_network_entry()
                        next_screen = time.monotonic() + 1
                metadata = controls.stat()
                if ((metadata.st_dev, metadata.st_ino) != control_inode or metadata.st_size < control_offset
                        or metadata.st_size > 1024 * 1024):
                    raise RuntimeError("control file replaced, truncated, or exceeded bound")
                with controls.open("rb") as commands:
                    commands.seek(control_offset); new = commands.read(); control_offset += len(new)
                pending += new
                if len(pending) > 16384:
                    raise RuntimeError("control line exceeded bound")
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    if not line.strip(): continue
                    control = json.loads(line)
                    record.setdefault("manual_controls", []).append(control)
                    action = control.get("action")
                    if action == "snapshot": screenshot("manual")
                    elif action == "pause": proof.pause(); screenshot("manual-paused")
                    elif action == "resume": proof.resume()
                    elif action == "arm_entry_watch": proof.arm_entry_watch(control)
                    elif action == "entry_prompt_visible": proof.confirm_entry(control)
                    elif action == "network_prompt_visible":
                        proof.send_token(control, args.transition_steps, args.transition_step_ms)
                    elif action == "invalid_interface_visible": proof.confirm_error(control)
                    elif action == "advance": proof.advance(int(control.get("milliseconds", 5)))
                    elif action == "abort": raise RuntimeError("operator stopped this owned proof")
                    else: raise ValueError("unknown bounded control action")
                    save()
                if record["ok"]:
                    break
                if (boot_stage == "booted" and proof.stage in ("boot", "await-entry-prompt", "await-network-prompt")
                        and not proof.paused and time.monotonic() >= next_screen):
                    screenshot("boot-vga" if proof.stage == "boot" else "entry-wait" if not proof.network_keys_sent else "network-wait")
                    next_screen = time.monotonic() + args.screenshot_interval
                if process.poll() is not None:
                    raise RuntimeError("owned QEMU exited before USB visual proof")
            else:
                raise TimeoutError("USB proof deadline; inspect screenshots and console.log")
            record["serial_guest_inputs_after_boot"] = 0
    except BaseException as error:
        record["ok"] = False
        record["error"] = type(error).__name__ + ": " + str(error)
    finally:
        if selector is not None: selector.close()
        if serial_log is not None: serial_log.close()
        if process is not None and process.poll() is None:
            try:
                if qmp is not None: qmp.execute("quit")
            except (OSError, ValueError, RuntimeError): pass
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
        if qmp is not None:
            try: qmp.close()
            except OSError as error: record["qmp_close_error"] = str(error)
        for sig, handler in previous.items(): signal.signal(sig, handler)
        record["owned_qemu_exit"] = process.returncode if process is not None else None
        record["elapsed_seconds"] = time.monotonic() - started
        try:
            record["iso_final_identity"] = identity(iso)
            record["iso_unchanged"] = record["iso_final_identity"] == record["iso"]
        except OSError as error:
            record["iso_unchanged"] = False
            record["iso_final_identity_error"] = str(error)
        if process is not None and process.returncode != 0:
            record["ok"] = False
        if not record["iso_unchanged"]: record["ok"] = False
        save("result.json"); save()
    print("USB HID proof: " + ("PASS" if record["ok"] else "FAIL")
          + "\nEvidence: " + str(output / "result.json"), flush=True)
    return 0 if record["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
