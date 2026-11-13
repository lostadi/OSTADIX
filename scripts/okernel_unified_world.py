#!/usr/bin/env python3
"""Run an explicit isolated Linux/original-Plan9 state below one O-core monitor.

The two kernels share native objects, not guest RAM or host filesystem servers.
This runner cannot select the working package-domain state. Build and live
qualification are separate; original program dispatch is qualified separately.
"""
from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
LINUX_WITNESS = {"operation": 11, "action_address": 0x6d000118,
                 "address": 0x6d0b0000, "bytes": 0x50000,
                 "header_bytes": 128, "record_bytes": 576, "max_fids": 512}

sys.path.insert(0, str(ROOT / "scripts"))
from okernel_native_volume import Volume
import o10

PROTOCOL_SPEC = importlib.util.spec_from_file_location("original_plan9_protocol", ROOT / "ocore/guest/plan9/unified/protocol.py")
protocol = importlib.util.module_from_spec(PROTOCOL_SPEC)
sys.modules[PROTOCOL_SPEC.name] = protocol
PROTOCOL_SPEC.loader.exec_module(protocol)
SPEC = importlib.util.spec_from_file_location("unified_common", ROOT / "scripts/okernel_package_domain.py")
common = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(common)
DISK_BYTES = 0x40000000
STORE_BYTES = 0x1000000
DEFAULT_BOOTSTRAP = b"!rc\nmount -n -c /dev/eia1 /n\necho ORIGINAL_PLAN9_UNIFIED_@TOKEN@ > /n/work/plan9-ready-@TOKEN@\n"
RECOVERY = {"control_address": 0x6d000070, "control_bytes": 48,
            "kernel_backup_address": 0xd0000000, "kernel_max_bytes": 0x1000000,
            "dtb_backup_address": 0xd1000000, "dtb_max_bytes": 0x10000,
            "pause": 1, "restart": 2}
O10_PROFILE = {"version": "O10", "operation": 10, "submission": 0x6d0a0000,
               "completion": 0x6d0a0200, "msize": 512}
LINUX_RECOVERY = {"kernel_image": 3, "aux_image": 4, "namespace_version": "9P2000.u",
                  "kernel_backup_address": 0xd2000000, "kernel_max_bytes": 0x7e00000,
                  "dtb_backup_address": 0xe2000000, "dtb_max_bytes": 0x10000,
                  "initrd_backup_address": 0xda000000, "initrd_max_bytes": 0x8000000,
                  "kernel_bytes_address": 0x6d000100, "dtb_bytes_address": 0x6d000108,
                  "initrd_bytes_address": 0x6d000110}
COORDINATOR_UART = {"guest_address": 0x09001000, "guest_irq": 51,
                    "input_address": 0x6d060000, "input_bytes": 8192,
                    "output_address": 0x6d080000, "output_bytes": 65536}
IDLE_SCHEDULER = {"schema": "ostadix.unified-idle-scheduler/v1",
                  "blocked_mask_address": 0x6d0000a0, "idle_waits_address": 0x6d0000a8,
                  "plan9_9p_requests_address": 0x6d0000b0,
                  "plan9_9p_request_bytes_address": 0x6d0000b8,
                  "plan9_9p_reply_bytes_address": 0x6d0000c0,
                  "native_poll_frequency_divisor": 200,
                  "policy": "park WFI until waking virtual interrupt; WFE remains a hint"}


COORDINATOR_START = "mkdir -p /usr/lib/okernel /run/okernel/p9; chmod 700 /run/okernel/p9; cp /usr/local/libexec/p9_protocol.py /usr/lib/okernel/p9_protocol.py; rm -f /run/okernel/p9/controller.pid; setsid /bin/sh -c 'echo $$ > /run/okernel/p9/controller.pid; exec /usr/local/libexec/p9-controller --device /dev/ttyAMA1 --control-dir /run/okernel/p9' </dev/null > /run/okernel/p9/controller.log 2>&1 & :"

def owned_qemu_child(parent_pid: int):
    """Keep this controller's private QEMU from outliving an abrupt owner exit."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        os._exit(126)
    if os.getppid() != parent_pid:
        os._exit(126)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def identity(path: Path) -> dict:
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest(path)}


def checked(path: Path, expected: dict) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected regular captured input: " + str(path))
    if path.stat().st_size != expected["bytes"] or digest(path) != expected["sha256"]:
        raise ValueError("captured input identity changed: " + str(path))
    return path


def validate_profile(profile: dict) -> None:
    required = {
        "schema": "ostadix.unified-world-monitor/v1", "profile": "linux-original-plan9",
        "outer_ram_bytes": 0xc0000000,
        "domains": [
            {"id": 0, "name": "linux", "guest_ram_ipa": 0x40000000, "guest_ram_pa": 0x48000000,
             "guest_ram_bytes": 0x20000000, "entry": 0x40000000, "x0": 0x47e00000, "vmid": 1},
            {"id": 1, "name": "plan9", "guest_ram_ipa": 0x40000000, "guest_ram_pa": 0xb0000000,
             "guest_ram_bytes": 0x20000000, "entry": 0x40100000, "x0": 0x40000000, "vmid": 2}],
        "loader_addresses": {"inputs/linux.Image": 0x48000000, "linux.dtb": 0x4fe00000,
                             "inputs/linux.initramfs": 0x50000000, "inputs/plan9.kernel": 0xb0100000,
                             "plan9.dtb": 0xb0000000},
        "block_backing": {"address": 0x70000000, "bytes": DISK_BYTES},
        "namespace": {"address": 0x6c000000, "bytes": STORE_BYTES, "epoch_address": 0x6d000000,
                      "quiescence_address": 0x6d000008, "clock_address": 0x6d000010,
                      "linux_grant": 1, "plan9_grant": 4, "native_peer_grant": 2},
        "plan9_console": {"input_address": 0x6d010000, "input_bytes": 4096,
                         "output_address": 0x6d020000, "output_bytes": 65536},
        "console_mux": {"escape": 30, "linux_select": 48, "plan9_select": 49,
                        "linux_output_address": 0x6d040000, "output_bytes": 65536},
        "gic": {"version": 3, "physical_controller": "native monitor only",
                "distributor": [0x08000000, 0x08010000],
                "redistributor": [0x080a0000, 0x080c0000],
                "native_quantum_irq": 26, "quantum_counter_divisor": 100, "lpi_authority": False}}
    if "plan9_recovery" in profile:
        required["plan9_recovery"] = RECOVERY
        required["loader_addresses"].update({"inputs/plan9-recovery.kernel": 0xd0000000,
                                             "inputs/plan9-recovery.dtb": 0xd1000000})
    if "linux_recovery" in profile:
        required["linux_recovery"] = LINUX_RECOVERY
        required["loader_addresses"].update({"inputs/linux-recovery.Image": 0xd2000000,
                                             "inputs/linux-recovery.dtb": 0xe2000000,
                                             "inputs/linux-recovery.initramfs": 0xda000000})
    if "coordinator_uart" in profile:
        required["coordinator_uart"] = COORDINATOR_UART
    if "o10" in profile:
        required["o10"] = O10_PROFILE
    if "o10_linux_restart_witness" in profile or "linux_restart_witness" in profile:
        if profile.get("o10_qualification") is not True:
            raise ValueError("store witness requires a qualification build")
        required["o10_linux_restart_witness"] = "native-store-v1"
        required["linux_restart_witness"] = LINUX_WITNESS
    if "idle_scheduler" in profile:
        required["idle_scheduler"] = IDLE_SCHEDULER
    if any(profile.get(key) != value for key, value in required.items()):
        raise ValueError("expected the exact isolated two-domain memory/interrupt grant")


def validate_recovery_inputs(artifacts: dict[str, Path]) -> None:
    for backup, original, maximum in (("inputs/plan9-recovery.kernel", "inputs/plan9.kernel", 0x1000000),
                                       ("inputs/plan9-recovery.dtb", "plan9.dtb", 0x10000)):
        for name in (backup, original):
            if artifacts[name].is_symlink() or not artifacts[name].is_file():
                raise ValueError("native recovery input must be a captured regular file")
        if (identity(artifacts[backup])["sha256"] != identity(artifacts[original])["sha256"]
                or not 0 < artifacts[backup].stat().st_size <= maximum):
            raise ValueError("native recovery copy differs from admitted original input")


def validate_linux_recovery_inputs(artifacts: dict[str, Path]) -> None:
    for backup, original, maximum in (("inputs/linux-recovery.Image", "inputs/linux.Image", 0x7e00000),
                                      ("inputs/linux-recovery.dtb", "linux.dtb", 0x10000),
                                      ("inputs/linux-recovery.initramfs", "inputs/linux.initramfs", 0x8000000)):
        for name in (backup, original):
            if artifacts[name].is_symlink() or not artifacts[name].is_file():
                raise ValueError("Linux recovery input must be a captured regular file")
        if (identity(artifacts[backup])["sha256"] != identity(artifacts[original])["sha256"]
                or not 0 < artifacts[backup].stat().st_size <= maximum):
            raise ValueError("Linux recovery copy differs from admitted original input")


def decode_linux_restart_witness(raw: bytes, action: str, sequence: int) -> dict:
    """Decode the fixed native diagnostic contract; no authority inputs."""
    if action not in ("capture", "check") or len(raw) < 128:
        raise ValueError("invalid native witness action/header")
    if raw[:8] != b"O10WIT1\0" or struct.unpack_from("<I", raw, 8)[0] != 1:
        raise ValueError("unsupported native witness header")
    status, = struct.unpack_from("<I", raw, 12)
    detail, native_action, native_seq, ls, lg, ps, pg = struct.unpack_from("<7Q", raw, 16)
    if native_action != (1 if action == "capture" else 2) or native_seq != sequence:
        raise ValueError("stale native witness action/sequence")
    if status:
        raise RuntimeError(f"native Linux store witness error {status}, detail {detail}")
    lc, pc, count = struct.unpack_from("<3I", raw, 72)
    if detail or not ls or not ps or ls == ps or not lg or not pg or not lc or not pc:
        raise ValueError("inactive native witness binding")
    if count != lc + pc or count > 512 or len(raw) != 128 + count * 576 or any(raw[84:128]):
        raise ValueError("invalid native witness bounds")
    result = {"schema": "ostadix.o10-linux-store-witness/v1", "origin": "running-native-store",
              "capture_scope": "all-transport-owned-fids", "action": action, "sequence": sequence,
              "linux": {"grant": 1, "session": ls, "transport_generation": lg, "fids": [], "exchanges": []},
              "plan9": {"grant": 4, "session": ps, "transport_generation": pg, "fids": [], "exchanges": []}}
    for index in range(count):
        row = raw[128 + index*576:128 + (index+1)*576]
        role, fid, generation, mode, qlen, rlen = struct.unpack_from("<IIQQII", row)
        if role != int(index >= lc) or not generation or qlen != 11 or not 7 <= rlen <= 512:
            raise ValueError("invalid native witness record")
        request, reply = row[32:43], row[48:48+rlen]
        if (any(row[43:48]) or any(row[48+rlen:]) or
                struct.unpack_from("<I", request)[0] != 11 or request[4] != 124 or
                struct.unpack_from("<I", request, 7)[0] != fid or
                struct.unpack_from("<I", reply)[0] != rlen or request[5:7] != reply[5:7] or
                reply[4] not in (107, 125)):
            raise ValueError("malformed raw native store exchange")
        owner = result["linux" if role == 0 else "plan9"]
        owner["fids"].append({"fid": fid, "object_generation": generation, "mode": mode})
        owner["exchanges"].append({"fid": fid, "request_hex": request.hex(), "reply_hex": reply.hex()})
    for role in ("linux", "plan9"):
        numbers = [row["fid"] for row in result[role]["fids"]]
        if numbers != sorted(set(numbers)):
            raise ValueError("native witness fids are not unique and sorted")
    return result


class UnifiedDomain:
    def __init__(self, state: Path, build: Path, qemu: str, *, bootstrap: bytes = DEFAULT_BOOTSTRAP,
                 live: bool = False, timeout: float = 180, legacy_control: bool = False):
        if state.is_symlink():
            raise ValueError("state must not be a symlink")
        self.state, self.build = state.resolve(strict=True), build.resolve(strict=True)
        configured = Path(os.environ.get("OSTADIX_OKERNEL_STATE") or str(common.DEFAULT_STATE.parent)) / "package-domain"
        if self.state in (common.DEFAULT_STATE.resolve(), configured.expanduser().resolve()):
            raise ValueError("the working package-domain state is not a unified test target")
        fork = json.loads((self.state / "fork.json").read_text())
        if fork.get("schema") != "ostadix.okernel-state-fork/v1" or not fork.get("ok") or fork.get("output") != str(self.state):
            raise ValueError("use an explicitly copied, isolated state fork")
        token = secrets.token_hex(12)
        bootstrap = bootstrap.replace(b"@TOKEN@", token.encode())
        self.ready_name, self.ready_value = "plan9-ready-" + token, "ORIGINAL_PLAN9_UNIFIED_" + token
        if len(bootstrap) > 4096 or b"\0" in bootstrap:
            raise ValueError("Plan9 console bootstrap exceeds its declared input buffer")
        self.lock = (self.state / "domain.lock").open("a+")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            raise RuntimeError("this isolated state is already running") from None
        self.closed = False
        self.process = self.qmp = None
        self.ram = None
        self.control_sequence = 0
        self.legacy_control = legacy_control
        self.o10_profile = None
        self.o10_epoch = self.o10_sequence = self.o10_tag = 0
        self.o10_claimed = False
        self.o10_pending = None
        self.o10_exchange_active = False
        self.o10_plan9 = (1 << 32) | 1
        self.o10_linux = 1 << 32
        self.o10_linux_lease_generation = 1
        self.linux_recovery = None
        self.last_linux_poll = 0.0
        self.o10_lease_generation = 1
        self.control_active = False
        self.last_provider_poll = 0.0
        self.service = None
        self.provider_ready = False
        self.provider_failed = False
        self.native_store_ready = False
        self.guest_coordinator_online = False
        self.coordinator_position = 0
        self.coordinator_capture = bytearray()
        self.coordinator_events = []
        self.console_exit_seen = set()
        self.console_exit_request = None
        self.last_coordinator_poll = 0.0
        self.selector = selectors.DefaultSelector()
        self.live, self.timeout = live, timeout
        self.session = Path(tempfile.mkdtemp(prefix="unified-session-", dir=self.state))
        self.control = None
        self.capture, self.plan9_capture = bytearray(), bytearray()
        self.plan9_position, self.linux_position, self.last_console_poll = 0, 0, 0.0
        self.log = (self.session / "linux-console.log").open("wb")
        self.terminal_log = (self.session / "console.log").open("wb")
        self.plan9_log = (self.session / "plan9-console.log").open("wb")
        self.error_log = (self.session / "qemu-stderr.log").open("wb")
        self.record = {"schema": "ostadix.unified-world-session/v1", "ok": False,
                       "scope": "one native O-core EL2 monitor with original Linux and original9front under QEMU/TCG; live claims require completion checks"}
        try:
            self.control = common.ControlSocket(self.session, prefer_session=False)
            self.record["control_socket"] = {"path": str(self.control.path), "private_runtime": self.control.external}
            controller = self.session / "controller.py"
            shutil.copyfile(Path(__file__), controller)
            controller.chmod(0o400)
            self.record["controller"] = identity(controller)
            manifest_file = self.build / "monitor-profile.json"
            manifest = json.loads(manifest_file.read_text())
            validate_profile(manifest)
            self.idle_scheduler = manifest.get("idle_scheduler")
            self.linux_restart_witness_profile = manifest.get("linux_restart_witness")
            self.linux_restart_witness_pending = None
            common.write_json(self.session / "monitor-profile.json", manifest)
            artifacts = {}
            snapshots = self.session / "inputs"
            snapshots.mkdir()
            for name, expected in manifest["artifacts"].items():
                relative = Path(name)
                if relative.is_absolute() or ".." in relative.parts or expected.get("path") != name:
                    raise ValueError("profile artifact escaped its captured build directory")
                source = checked(self.build / name, expected)
                target = snapshots / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                checked(target, expected).chmod(0o400)
                artifacts[name] = target
            self.head = json.loads((self.state / "head.json").read_text())
            common.validate_head(self.state, self.head)
            consumed = self.head.get("console_exit_consumed", [])
            if not isinstance(consumed, list):
                raise ValueError("saved console exit history must be an array")
            for request_id in consumed:
                protocol._hex(request_id, 32, "saved console exit request ID")
                self.console_exit_seen.add(request_id)
            if self.head["disk"]["bytes"] != DISK_BYTES or not self.head.get("namespace"):
                raise ValueError("unified execution requires a saved1GiB disk/native-store pair")
            for name, key in (("disk.ext4", "disk"), ("namespace.raw", "namespace")):
                expected = self.head[key]
                target = snapshots / name
                shutil.copyfile(checked(Path(expected["path"]), expected), target)
                checked(target, expected).chmod(0o400)
                artifacts[name] = target
            self.epoch = secrets.randbits(64) or 1
            self.clock = int(time.time())
            self.recovery = manifest.get("plan9_recovery")
            self.linux_recovery = manifest.get("linux_recovery")
            if self.linux_recovery:
                validate_linux_recovery_inputs(artifacts)
            self.o10_profile = manifest.get("o10")
            self.coordinator_uart = manifest.get("coordinator_uart")
            if self.recovery:
                validate_recovery_inputs(artifacts)
            self.base_bootstrap = bootstrap
            if manifest.get("plan9_derivation_kind") == "qualified-original-userland":
                if not self.recovery:
                    raise ValueError("original command provider requires native domain recycling")
                self.service = {"generation": f"{self.epoch:016x}", "instance": secrets.token_hex(16)}
                bootstrap = self.provider_bootstrap()
                self.record["plan9_service"] = dict(self.service)
            script = snapshots / "plan9-bootstrap.bin"
            script.write_bytes(struct.pack("<Q", len(bootstrap)) + bootstrap)
            script.chmod(0o400)
            artifacts["plan9-bootstrap.bin"] = script
            # A private anonymous shared RAM file permits the owning controller
            # to write only trusted native controls while QEMU is stopped. It
            # is never a guest filesystem, host path grant, or saved snapshot.
            self.ram = os.memfd_create("ostadix-unified-private-ram", os.MFD_CLOEXEC)
            os.ftruncate(self.ram, 0xc0000000)
            command = [shutil.which(qemu) or qemu, "-machine", "virt,virtualization=on,gic-version=3,its=off,memory-backend=unified-ram",
                       "-object", f"memory-backend-file,id=unified-ram,size=3G,mem-path=/proc/self/fd/{self.ram},share=on",
                       "-accel", "tcg,thread=single", "-cpu", "cortex-a57", "-smp", "1", "-m", "3G",
                       "-nodefaults", "-nic", "none", "-display", "none", "-monitor", "none",
                       "-serial", "stdio", "-no-reboot", "-no-shutdown",
                       "-qmp", "unix:" + str(self.control.path) + ",server=on,wait=off",
                       "-kernel", str(artifacts["monitor.elf"])]
            addresses = {**manifest["loader_addresses"], "disk.ext4": 0x70000000, "namespace.raw": 0x6c000000}
            for name, address in addresses.items():
                command += ["-device", "loader,file=" + str(artifacts[name]).replace(",", ",,") + ",addr=" + hex(address) + ",force-raw=on"]
            command += ["-device", "loader,file=" + str(script).replace(",", ",,") + ",addr=0x6d010000,force-raw=on"]
            for address, value in ((0x6d000000, self.epoch), (0x6d000008, 0), (0x6d000010, self.clock),
                                   (0x6d020000, 0), (0x6d040000, 0)):
                command += ["-device", f"loader,addr={hex(address)},data={value},data-len=8"]
            if self.recovery:
                for address, value in ((0x6d000090, artifacts["inputs/plan9.kernel"].stat().st_size),
                                       (0x6d000098, artifacts["plan9.dtb"].stat().st_size)):
                    command += ["-device", f"loader,addr={hex(address)},data={value},data-len=8"]
            if self.linux_recovery:
                for address, name in ((0x6d000100, "inputs/linux.Image"),
                                      (0x6d000108, "linux.dtb"), (0x6d000110, "inputs/linux.initramfs")):
                    command += ["-device", f"loader,addr={hex(address)},data={artifacts[name].stat().st_size},data-len=8"]
            command += ["-global", "virtio-mmio.force-legacy=false", "-netdev", "user,id=unified-net",
                        "-device", "virtio-net-device,bus=virtio-mmio-bus.31,netdev=unified-net,mac=52:54:00:12:34:56"]
            self.record.update(argv=command, inputs={name: identity(path) for name, path in artifacts.items()},
                               before=self.head, epoch=self.epoch, clock_unix_seconds=self.clock)
            common.write_json(self.session / "result.json", self.record)
            owner = os.getpid()
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, start_new_session=True, bufsize=0, pass_fds=(self.ram,),
                                            preexec_fn=lambda: owned_qemu_child(owner))
            self.record.update(controller_pid=os.getpid(), qemu_pid=self.process.pid)
            common.write_json(self.session / "result.json", self.record)
            (self.state / "latest-unified-session").write_text(str(self.session) + "\n")
            self.selector.register(self.process.stdout, selectors.EVENT_READ, self.terminal_log)
            self.selector.register(self.process.stderr, selectors.EVENT_READ, self.error_log)
            if self.live:
                print("Starting OKernel; loading the saved workspace...", flush=True)
            self.qmp = common.QMP(self.control.path, timeout=self.timeout)
            self.control.connected()
        except BaseException as error:
            self.record["error"] = str(error)
            self.close()
            raise

    def pump(self, duration: float = 0.1):
        for key, _ in self.selector.select(duration):
            data = os.read(key.fileobj.fileno(), 16384)
            if not data:
                self.selector.unregister(key.fileobj)
                continue
            key.data.write(data)
            key.data.flush()
            if key.fileobj is self.process.stdout:
                if self.live:
                    os.write(sys.stdout.fileno(), data)
        if self.qmp is not None and time.monotonic() - self.last_console_poll > 0.2:
            self.last_console_poll = time.monotonic()
            self.plan9_position = self.drain_console(0x6d020000, self.plan9_position, self.plan9_log, self.plan9_capture, "plan9")
            self.linux_position = self.drain_console(0x6d040000, self.linux_position, self.log, self.capture, "linux")
            if b"KW native shared namespace: online\n" in self.capture:
                self.native_store_ready = True
            common.write_json(self.session / "native-observation.json", self.counters())
        if b"KW unified internal invariant:" in self.capture:
            raise RuntimeError("native monitor invariant failed; inspect " + str(self.session))
        if not self.live and not getattr(self, "o10_exchange_active", False) and (b"KW unified domain failure:" in self.capture or b"KW terminal unexpected exit:" in self.capture or b"Kernel panic" in self.capture):
            if not (self.linux_recovery and (self.control_active
                    or self.linux_status()["state"] == o10.PROVISIONAL_STATE_FAULTED)):
                raise RuntimeError("unified domain/monitor failure; inspect " + str(self.session))
        if not self.live and b"panic:" in self.plan9_capture:
            raise RuntimeError("original Plan9 kernel panic; inspect " + str(self.session))
        if not self.control_active and not getattr(self, "o10_exchange_active", False) and self.native_store_ready and self.linux_recovery:
            if time.monotonic() - self.last_linux_poll > 1:
                self.last_linux_poll = time.monotonic()
                if self.linux_status()["state"] == o10.PROVISIONAL_STATE_FAULTED:
                    self.recover_linux()
        if not self.provider_failed and not self.control_active and not getattr(self, "o10_exchange_active", False):
            try:
                if self.service and time.monotonic() - self.last_provider_poll > 1:
                    self.last_provider_poll = time.monotonic()
                    self.watch_provider()
                if self.guest_coordinator_online and time.monotonic() - self.last_coordinator_poll > 1:
                    self.last_coordinator_poll = time.monotonic()
                    self.watch_guest_coordinator()
            except (OSError, ValueError, KeyError, RuntimeError, TimeoutError) as error:
                if not self.live:
                    raise
                self.provider_failed = True
                self.provider_ready = False
                self.control_active = True
                try:
                    self.native_control(1)
                finally:
                    self.control_active = False
                counters = self.counters()
                self.record["provider_failure"] = {"error": str(error), "time": time.time(),
                                                    "counters": counters}
                common.write_json(self.session / "result.json", self.record)
                survivor = "Linux remains available." if counters["live_domains"] & 1 else "Linux is stopped."
                os.write(sys.stdout.fileno(), ("\r\nPlan 9 provider withdrawn: " + str(error) +
                         "\r\n" + survivor + " Save and restart to restore Plan 9; pending work is not replayed.\r\n").encode())

    def provider_bootstrap(self) -> bytes:
        service = self.service
        script = self.base_bootstrap + ("mkdir -p /n/services\nrc /rc/bin/okernel-start /n/services/plan9 " +
                    service["generation"] + " " + service["instance"] + "\n").encode()
        if len(script) > 4096:
            raise ValueError("provider bootstrap exceeds native console input grant")
        return script

    def stopped(self):
        for _ in range(1000):
            self.qmp.execute("stop")
            if self.qmp.execute("query-status").get("running") is not False:
                raise RuntimeError("CPU did not stop")
            busy, = struct.unpack("<Q", os.pread(self.ram, 8, 0x6d000008 - 0x40000000))
            if busy == 0:
                return
            if busy != 1:
                raise RuntimeError("invalid native quiescence word")
            self.qmp.execute("cont")
            time.sleep(0.001)
        raise RuntimeError("native service did not reach a snapshot boundary")

    def native_volume(self):
        self.stopped()
        try:
            captured = os.pread(self.ram, STORE_BYTES, 0x6c000000 - 0x40000000)
        finally:
            self.qmp.execute("cont")
        return Volume(captured)

    def native_control(self, operation: int, bootstrap: bytes | None = None, payload: bytes | None = None):
        if not self.recovery or operation not in (1, 2, 3) or (operation == 3 and not self.coordinator_uart):
            raise ValueError("native recovery is unavailable for this profile")
        if getattr(self, "o10_profile", None) and not getattr(self, "legacy_control", False) and operation in (1, 2):
            if payload is not None:
                raise ValueError("lifecycle control cannot carry coordinator payload")
            if bootstrap is not None and (operation != 2 or len(bootstrap) > 4096 or b"\0" in bootstrap):
                raise ValueError("invalid native recovery bootstrap")
            self.o10_claim()
            if operation == 1:
                self.o10_call("Twithdraw", dom=self.o10_plan9, mode=0, deadline_ms=0)
                self.o10_lease_generation += 1
            else:
                restored = self.o10_call("Trestore", bootstrap=bootstrap, dom=self.o10_plan9,
                                         inst=secrets.token_bytes(16), img_kernel=1, img_aux=2)
                self.o10_plan9 = restored["dom"]
                holder = self.o10_plan9
                transport = holder & ~0xffffffff
                try:
                    self.o10_call("Tbind", lease=(self.o10_lease_generation << 32) | 4,
                                  transport=transport)
                except o10.O10Error as error:
                    # Fault containment may already have revoked the boot grant
                    # before this explicit withdrawal. The definite ESTALE reply
                    # is journaled: refresh only its lease generation and send a
                    # new mechanism request. Never replay restore or bootstrap.
                    if (error.code != o10.O10_ESTALE or not self.o10_lease_generation < error.detail <= 0xffffffff
                            or self.o10_plan9 != holder):
                        raise
                    self.o10_lease_generation = error.detail
                    self.o10_call("Tbind", lease=(self.o10_lease_generation << 32) | 4,
                                  transport=transport)
            return
        self.control_sequence += 1
        self.stopped()
        try:
            if bootstrap is not None:
                if operation != 2 or len(bootstrap) > 4096 or b"\0" in bootstrap:
                    raise ValueError("invalid native recovery bootstrap")
                self.write_native(0x6d010000, struct.pack("<Q", len(bootstrap)) + bootstrap)
            if payload is not None:
                if operation != 3 or not 0 < len(payload) <= 8192:
                    raise ValueError("invalid native coordinator payload")
                self.write_native(0x6d060000, struct.pack("<Q", len(payload)) + payload)
            self.write_native(0x6d000070, struct.pack("<QQ", self.control_sequence, operation))
        finally:
            self.qmp.execute("cont")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            ack, result = struct.unpack("<QQ", os.pread(self.ram, 16, 0x6d000080 - 0x40000000))
            if ack == self.control_sequence:
                # Acknowledgement is published inside a native transaction;
                # require its completed boundary before observing live state.
                self.stopped()
                self.qmp.execute("cont")
                if result != 1:
                    raise RuntimeError("native lifecycle operation EUNSUPPORTED" if result == 9
                                       else "native Plan9 recovery rejected operation " + str(operation))
                return
            if self.process.poll() is not None:
                raise RuntimeError("native supervisor exited during recovery")
            self.pump(0.01)
        raise TimeoutError("native Plan9 recovery acknowledgement missing")

    def o10_exchange(self, frame: bytes, *, bootstrap: bytes | None = None) -> dict:
        """Serialize one mailbox exchange while pump drains ordinary I/O."""
        if getattr(self, "o10_exchange_active", False):
            raise RuntimeError("another O10 mailbox exchange is active")
        self.o10_exchange_active = True
        try:
            return self._o10_exchange_once(frame, bootstrap=bootstrap)
        finally:
            self.o10_exchange_active = False

    def _o10_exchange_once(self, frame: bytes, *, bootstrap: bytes | None = None) -> dict:
        """Send one exact mechanism frame. Timeouts never resubmit the frame."""
        if getattr(self, "o10_profile", None) != O10_PROFILE:
            raise ValueError("O10 is unavailable for this monitor profile")
        request = o10.decode(frame)
        if not request["type"].startswith("T"):
            raise ValueError("O10 transport requires a request")
        self.control_sequence += 1
        mailbox_sequence = self.control_sequence
        self.stopped()
        try:
            if bootstrap is not None:
                if request["type"] != "Trestore" or len(bootstrap) > 4096 or b"\0" in bootstrap:
                    raise ValueError("invalid native recovery bootstrap")
                # Bootstrap is service data on the existing console path, not
                # part of the journaled mechanism request.
                self.write_native(0x6d010000, struct.pack("<Q", len(bootstrap)) + bootstrap)
            self.write_native(O10_PROFILE["submission"], frame)
            self.write_native(0x6d000070, struct.pack("<QQ", mailbox_sequence, 10))
        finally:
            self.qmp.execute("cont")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            ack, result = struct.unpack("<QQ", os.pread(self.ram, 16, 0x6d000080 - 0x40000000))
            if ack == mailbox_sequence:
                self.stopped()
                try:
                    if result != 1:
                        raise RuntimeError("native O10 mailbox rejected frame")
                    offset = O10_PROFILE["completion"] - 0x40000000
                    size_bytes = os.pread(self.ram, 4, offset)
                    if len(size_bytes) != 4:
                        raise RuntimeError("native O10 reply header is incomplete")
                    size, = struct.unpack("<I", size_bytes)
                    if not 7 <= size <= O10_PROFILE["msize"]:
                        raise RuntimeError("native O10 reply size is invalid")
                    reply = o10.decode(os.pread(self.ram, size, offset))
                    if reply["tag"] != request["tag"]:
                        raise RuntimeError("native O10 reply tag does not match request")
                    if reply["type"] not in ("Rerror", "R" + request["type"][1:]):
                        raise RuntimeError("native O10 reply type does not match request")
                    return reply
                finally:
                    self.qmp.execute("cont")
            if self.process.poll() is not None:
                raise RuntimeError("native supervisor exited during O10")
            self.pump(0.01)
        raise TimeoutError("native O10 acknowledgement missing; outcome unresolved")

    def o10_version(self) -> dict:
        self.o10_tag = (self.o10_tag % 65535) + 1
        reply = self.o10_exchange(o10.encode("Tversion", self.o10_tag,
                                             negotiated_msize=512, version=o10.O10_VERSION))
        if reply["type"] != "Rversion" or reply["version"] != o10.O10_VERSION or reply["negotiated_msize"] != 512:
            raise RuntimeError("native O10 version negotiation failed")
        self.o10_epoch, self.o10_sequence = reply["epoch"], reply["last_seq"]
        return reply

    def o10_claim(self):
        if self.o10_claimed:
            return
        if self.o10_pending is not None:
            raise RuntimeError("unresolved O10 mutation requires an explicit outcome query")
        self.o10_version()
        reply = self.o10_call("Tclaim", new_epoch=self.o10_epoch + 1, expected=self.o10_epoch)
        self.o10_epoch = reply["epoch"]
        self.o10_claimed = True

    def o10_call(self, message_type: str, *, bootstrap: bytes | None = None, **fields) -> dict:
        """Apply one request, retaining unknown mutations for outcome inspection."""
        mutation = message_type in o10.MUTATING
        if mutation and self.o10_pending is not None:
            raise RuntimeError("unresolved O10 mutation requires an explicit outcome query")
        self.o10_tag = (self.o10_tag % 65535) + 1
        seq = self.o10_sequence + 1 if mutation else 0
        frame = o10.encode(message_type, self.o10_tag, epoch=self.o10_epoch, seq=seq, **fields)
        if mutation:
            self.o10_pending = {"frame": frame, "epoch": self.o10_epoch, "seq": seq}
        reply = self.o10_exchange(frame, bootstrap=bootstrap)
        if reply["type"] == "Rerror":
            # Some errors occur before sequence admission; dispatched failures
            # are journaled. Observe the position instead of guessing/replaying.
            self.o10_version()
            if mutation:
                self.o10_pending = None
            raise o10.O10Error(reply["code"], reply["detail"], "native O10 request rejected")
        if mutation:
            self.o10_sequence = seq
            self.o10_pending = None
        return reply

    def linux_restart_witness(self, action: str) -> dict:
        """One fixed qualification observer call; timeouts never resubmit."""
        if action not in ("capture", "check"):
            raise ValueError("witness action must be capture or check")
        if getattr(self, "linux_restart_witness_profile", None) != LINUX_WITNESS:
            raise RuntimeError("native Linux store witness is unsupported")
        if getattr(self, "o10_exchange_active", False) or getattr(self, "linux_restart_witness_pending", None):
            raise RuntimeError("another native mailbox observation is unresolved")
        self.o10_exchange_active = True
        self.control_sequence += 1
        sequence = self.control_sequence
        self.linux_restart_witness_pending = sequence
        try:
            self.stopped()
            try:
                self.write_native(LINUX_WITNESS["action_address"], struct.pack("<Q", 1 if action == "capture" else 2))
                self.write_native(0x6d000070, struct.pack("<QQ", sequence, 11))
            finally:
                self.qmp.execute("cont")
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                ack, status = struct.unpack("<QQ", os.pread(self.ram, 16, 0x6d000080 - 0x40000000))
                if ack == sequence:
                    self.stopped()
                    try:
                        if status != 1:
                            raise RuntimeError("native witness mailbox rejected observation")
                        offset = LINUX_WITNESS["address"] - 0x40000000
                        header = os.pread(self.ram, 128, offset)
                        if len(header) != 128:
                            raise RuntimeError("native witness header is incomplete")
                        count, = struct.unpack_from("<I", header, 80)
                        if count > 512:
                            raise ValueError("native witness capacity exceeded")
                        raw = os.pread(self.ram, 128 + count*576, offset)
                        self.linux_restart_witness_pending = None
                        return decode_linux_restart_witness(raw, action, sequence)
                    finally:
                        self.qmp.execute("cont")
                if self.process.poll() is not None:
                    raise RuntimeError("native supervisor exited during witness")
                self.pump(0.01)
            raise TimeoutError("native witness observation unresolved; not resubmitted")
        finally:
            self.o10_exchange_active = False

    def write_native(self, address: int, data: bytes):
        # Called only under stopped(), to these private control/input regions.
        if not ((0x6d000070 <= address and address + len(data) <= 0x6d000080)
                or (getattr(self, "linux_restart_witness_profile", None) == LINUX_WITNESS
                    and 0x6d000118 <= address and address + len(data) <= 0x6d000120)
                or (0x6d010000 <= address and address + len(data) <= 0x6d011008)
                or (0x6d060000 <= address and address + len(data) <= 0x6d062008)
                or (getattr(self, "o10_profile", None) == O10_PROFILE
                    and O10_PROFILE["submission"] <= address
                    and address + len(data) <= O10_PROFILE["submission"] + O10_PROFILE["msize"])):
            raise ValueError("host write escaped native provisioning region")
        if self.qmp.execute("query-status").get("running") is not False:
            raise RuntimeError("native control write requires a stopped CPU")
        if os.pwrite(self.ram, data, address - 0x40000000) != len(data):
            raise RuntimeError("native provisioning write was incomplete")

    def client_session(self, *, state="ready"):
        return {"schema": "ostadix.p9.client-session/v1", **self.service,
                "service_root": "/n/okernel/services/plan9", "linux_mount": "/n/okernel",
                "plan9_mount": "/n", "program_dir": "/arm64/bin",
                "recovery_mode": "controller-v1", "state": state}

    def coordinator_update(self, *, recovered=None, state="ready"):
        active = self.control_active
        self.control_active = True
        try:
            sequence = self.control_sequence + 1
            document = {"seq": sequence, "current": self.client_session(state=state)}
            if recovered is not None:
                document["recovered"] = recovered
            frame = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            expected_hash = hashlib.sha256(frame).hexdigest()
            self.native_control(3, payload=frame + b"\n")
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                accepted = None
                for acknowledgement in self.coordinator_read():
                    if acknowledgement.get("event") in ("unknown", "console-exit"):
                        self.coordinator_events.append(acknowledgement)
                        continue
                    if acknowledgement.get("seq") != sequence:
                        continue
                    if acknowledgement.get("sha256") != expected_hash or acknowledgement.get("ok") is not True:
                        raise RuntimeError("Linux-private coordinator publication failed: " + repr(acknowledgement))
                    accepted = acknowledgement
                if accepted is not None:
                    self.record.setdefault("coordinator_updates", []).append({"frame": document, "ack": accepted})
                    return
                self.pump(0.05)
            raise TimeoutError("Linux-private coordinator acknowledgement missing")
        finally:
            self.control_active = active

    def coordinator_read(self):
        self.stopped()
        try:
            captured = os.pread(self.ram, 65544, 0x6d080000 - 0x40000000)
        finally:
            self.qmp.execute("cont")
        count, = struct.unpack_from("<Q", captured)
        if count < self.coordinator_position or count - self.coordinator_position > 65536:
            raise RuntimeError("Linux coordinator acknowledgement ring overflowed/reset")
        while self.coordinator_position < count:
            offset = self.coordinator_position % 65536
            size = min(count - self.coordinator_position, 65536 - offset)
            self.coordinator_capture.extend(captured[8 + offset:8 + offset + size])
            self.coordinator_position += size
        messages = []
        while b"\n" in self.coordinator_capture:
            line, _, rest = self.coordinator_capture.partition(b"\n")
            self.coordinator_capture[:] = rest
            if len(line) > 8192:
                raise RuntimeError("oversized native coordinator reply")
            message = json.loads(line)
            if not isinstance(message, dict):
                raise RuntimeError("native coordinator reply is not an object")
            messages.append(message)
        if len(self.coordinator_capture) > 8192:
            raise RuntimeError("unterminated native coordinator reply")
        return messages

    def watch_guest_coordinator(self):
        for message in self.coordinator_read():
            if message.get("event") in ("unknown", "console-exit"):
                self.coordinator_events.append(message)
        while self.coordinator_events:
            event = self.coordinator_events.pop(0)
            if event.get("event") == "console-exit":
                protocol._hex(event.get("generation"), 16, "coordinator generation")
                protocol._hex(event.get("request_id"), 32, "console exit request ID")
                if not self.service or event["generation"] != self.service["generation"]:
                    continue
                request_id = event["request_id"]
                if request_id not in self.console_exit_seen:
                    self.console_exit_seen.add(request_id)
                    self.console_exit_request = event
                    self.record.setdefault("console_exit_requests", []).append(dict(event))
                continue
            protocol.ready_marker(event.get("generation"), event.get("instance"))
            protocol._hex(event.get("request_id"), 32, "request ID")
            protocol._hex(event.get("request_sha256"), 64, "request SHA256")
            if any(event[key] != self.service[key] for key in ("generation", "instance")):
                continue  # Historical notice cannot reset a fresh instance.
            root = "/services/plan9/g" + event["generation"] + "/s" + event["instance"]
            volume = self.native_volume()
            try:
                request_bytes = volume.get(root + "/r" + event["request_id"] + "/request")
            except FileNotFoundError:
                # The Linux-private journal can precede request publication.
                # Recycle conservatively; invent neither execution nor result.
                request_bytes = None
            if request_bytes is not None:
                request = protocol.decode_request(request_bytes)
                if ((request.generation, request.instance, request.request_id) !=
                        (event["generation"], event["instance"], event["request_id"])
                        or hashlib.sha256(request_bytes).hexdigest() != event["request_sha256"]):
                    raise RuntimeError("unknown completion notice differs from native request")
            self.recycle_plan9(None, {}, unknown=event)

    def take_console_exit_request(self):
        """Consume operator logout once; saving occurs outside pump/watchers."""
        request = self.console_exit_request
        self.console_exit_request = None
        return request

    def linux_control(self, operation: int):
        """One definite Linux mechanism transition; service work is never replayed."""
        if not self.linux_recovery or self.legacy_control:
            raise ValueError("Linux O10 recovery is unavailable")
        self.o10_claim()
        if operation == 1:
            self.o10_call("Twithdraw", dom=self.o10_linux, mode=0, deadline_ms=0)
            self.o10_linux_lease_generation += 1
            return
        if operation != 2:
            raise ValueError("unsupported Linux lifecycle operation")
        reply = self.o10_call("Trestore", dom=self.o10_linux, inst=secrets.token_bytes(16),
                              img_kernel=3, img_aux=4)
        self.o10_linux = reply["dom"]
        holder = self.o10_linux
        transport = holder & ~0xffffffff
        try:
            self.o10_call("Tbind", lease=(self.o10_linux_lease_generation << 32) | 1,
                          transport=transport)
        except o10.O10Error as error:
            if (error.code != o10.O10_ESTALE
                    or not self.o10_linux_lease_generation < error.detail <= 0xffffffff
                    or self.o10_linux != holder):
                raise
            self.o10_linux_lease_generation = error.detail
            self.o10_call("Tbind", lease=(self.o10_linux_lease_generation << 32) | 1,
                          transport=transport)

    def linux_status(self):
        try:
            return self.o10_call("Tstat", dom=self.o10_linux)
        except o10.O10Error as error:
            generation = self.o10_linux >> 32
            if error.code != o10.O10_ESTALE or not generation < error.detail <= 0xffffffff:
                raise
            self.o10_linux = error.detail << 32
            return self.o10_call("Tstat", dom=self.o10_linux)

    def recover_linux(self):
        """Host Governor policy for a definite native Linux fault only."""
        if self.control_active:
            raise RuntimeError("another lifecycle operation is active")
        self.control_active = True
        service_before = dict(self.service) if self.service else None
        entry = {"time": time.time(), "ok": False, "service_before": service_before,
                 "unknown_coordinator_events": list(self.coordinator_events),
                 "service_work": "completion may be unknown; no command replay"}
        self.record.setdefault("linux_recoveries", []).append(entry)
        try:
            observed = self.linux_status()
            entry["before"] = observed
            if observed["state"] != o10.PROVISIONAL_STATE_FAULTED:
                raise RuntimeError("Linux recovery requires a definite native fault")
            self.guest_coordinator_online = False
            self.coordinator_position = 0
            self.coordinator_capture.clear()
            self.coordinator_events.clear()
            self.console_exit_request = None
            # Historical console remains in linux-console.log. Drop only the
            # current shell's completion parser, never replay its command.
            self.capture.clear()
            self.linux_control(2)
            self.wait(b"OKERNEL PACKAGE DOMAIN READY", line=True)
            self.wait(b"pkg> ")
            self.mount_linux_namespace()
            self.command("date -u -s @" + str(self.clock))
            self.command("pkg-net online", timeout=120)
            self.setup_linux_client()
            if (dict(self.service) if self.service else None) != service_before:
                raise RuntimeError("Linux recovery changed the surviving Plan9 service identity")
            entry.update(ok=True, after=self.linux_status(), service=service_before)
        finally:
            self.control_active = False
            common.write_json(self.session / "result.json", self.record)

    def mount_linux_namespace(self):
        self.command("pkg-namespace mount")
        if self.linux_recovery:
            self.command("awk '$1 == \"okernel\" && $2 == \"/n/okernel\" && $3 == \"9p\" && $4 ~ /(^|,)version=9p2000[.]u(,|$)/ {found=1} END {exit !found}' /proc/mounts")

    def setup_linux_client(self):
        if not self.service or not self.coordinator_uart:
            return
        token = "P9_CLIENT_PRESENT_" + uuid.uuid4().hex
        self.command("if test -x /usr/bin/python3 && test -f /usr/local/libexec/p9-controller && test -x /usr/local/bin/p9; then echo " + token + "; fi")
        if token.encode() in bytes(self.capture).replace(b"\r", b"").split(b"\n"):
            self.command(COORDINATOR_START)
            self.command("i=0; until grep -qx 'p9-controller ready' /run/okernel/p9/controller.log; do if test -s /run/okernel/p9/controller.pid; then kill -0 $(cat /run/okernel/p9/controller.pid) || { cat /run/okernel/p9/controller.log; exit 1; }; fi; i=$((i+1)); test $i -lt 200 || exit 1; sleep 0.05; done")
            self.coordinator_update()
            self.guest_coordinator_online = True
            self.record["plan9_client"] = {"ready": True, "control": "/run/okernel/p9", "transport": "native Linux-only PL011"}
            self.command("cd /n/okernel/work; PS1='okernel> '; export PS1; printf '\\nLinux and original Plan 9 share this workspace. Use p9 NAME for original Plan 9 programs.\\n' ")

    def watch_provider(self):
        # Read a quiescent native snapshot. Guest console text never asks for
        # recovery or changes command authority. Service reset notices are
        # bound to exact current-generation requests and completed captures.
        if not self.native_store_ready:
            return
        if self.provider_ready and not (self.counters()["live_domains"] & 2):
            raise RuntimeError("the original Plan9 domain was withdrawn")
        volume = self.native_volume()
        service = self.service
        root = "/services/plan9/g" + service["generation"] + "/s" + service["instance"]
        try:
            ready = volume.get(root + "/ready")
        except FileNotFoundError:
            return
        if ready != protocol.ready_marker(service["generation"], service["instance"]):
            raise RuntimeError("original Plan9 ready marker has the wrong session binding")
        self.provider_ready = True
        try:
            reset = volume.get(root + "/reset-required")
        except FileNotFoundError:
            return
        fields = protocol._marker(reset, "OC9RESET1", (16, 32, 32, 64, 64))
        if fields[:2] != (service["generation"], service["instance"]):
            raise RuntimeError("Plan9 recovery marker belongs to another active instance")
        request_dir = root + "/r" + fields[2]
        try:
            files = {name: volume.get(request_dir + "/" + name) for name in protocol.REQUEST_FILES}
        except FileNotFoundError:
            # reset-required precedes done; a quiescent snapshot can still be
            # taken between these separate original-service publications.
            return
        protocol.validate_reset(files["request"], files["result"], reset)
        protocol.validate_submit(files["request"], files["submit"])
        protocol.validate_result(files["request"], files["result"], files["stdout"], files["stderr"],
                                 started=files["started"], done=files["done"], status=files["status"])
        self.recycle_plan9(reset, files)

    def recycle_plan9(self, reset: bytes | None, files: dict, *, unknown: dict | None = None):
        previous = dict(self.service)
        recovery = {"previous": previous, "reset": reset.decode("ascii") if reset else None,
                    "unknown": unknown, "started": time.time()}
        self.record.setdefault("provider_recoveries", []).append(recovery)
        self.control_active = True
        try:
            if self.guest_coordinator_online:
                self.coordinator_update(state="recovering")
            self.native_control(1)
            withdrawn = self.counters()
            if withdrawn["live_domains"] != 1:
                raise RuntimeError("Plan9 withdrawal did not preserve only the Linux domain")
            # Preserve the exact common objects at withdrawal, so lifecycle
            # tests can distinguish preexisting effects from later effects.
            captured = self.native_volume()
            snapshot = self.session / ("namespace-before-recycle-" + str(len(self.record["provider_recoveries"])) + ".raw")
            snapshot.write_bytes(captured._data)
            recovery["namespace_before"] = identity(snapshot)
            self.service = {"generation": previous["generation"], "instance": secrets.token_hex(16)}
            self.provider_ready = False
            bootstrap = self.provider_bootstrap()
            self.native_control(2, bootstrap)
            instance_root = "/services/plan9/g" + self.service["generation"] + "/s" + self.service["instance"]
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                volume = self.native_volume()
                try:
                    ready = volume.get(instance_root + "/ready")
                except FileNotFoundError:
                    self.pump(0.1)
                    continue
                if ready != protocol.ready_marker(self.service["generation"], self.service["instance"]):
                    raise RuntimeError("recycled provider evidence does not match the native recovery")
                self.provider_ready = True
                if self.guest_coordinator_online:
                    sha = lambda data: hashlib.sha256(data).hexdigest()
                    request = protocol.decode_request(files["request"]) if not unknown else None
                    acknowledgement = {"schema": "ostadix.p9.recovered/v1", "generation": previous["generation"],
                                       "old_instance": previous["instance"], "request_id": unknown["request_id"] if unknown else request.request_id,
                                       "request_sha256": unknown["request_sha256"] if unknown else sha(files["request"]),
                                       "result_sha256": None if unknown else sha(files["result"]),
                                       "reset_sha256": None if unknown else sha(reset), "done_sha256": None if unknown else sha(files["done"]),
                                       "new_instance": self.service["instance"],
                                       "ready_sha256": sha(ready), "outcome": "unknown" if unknown else "interrupted"}
                    self.coordinator_update(recovered=acknowledgement)
                recovery.update(ok=True, finished=time.time(), current=dict(self.service), withdrawn=withdrawn,
                                restored=self.counters())
                self.record["plan9_service"] = dict(self.service)
                common.write_json(self.session / "result.json", self.record)
                return
            raise TimeoutError("fresh Plan9 provider did not become ready after native recycling")
        finally:
            self.control_active = False

    def drain_console(self, address: int, position: int, log, capture: bytearray, name: str) -> int:
        path = self.session / (name + "-ring.bin")
        self.qmp.execute("pmemsave", {"val": address, "size": 65544, "filename": str(path)})
        snapshot = path.read_bytes()
        count, = struct.unpack_from("<Q", snapshot)
        if count < position or count - position > 65536:
            if not self.live:
                raise RuntimeError(name + " console capture overflowed or reset unexpectedly")
            self.record.setdefault("console_overruns", []).append({"domain": name, "before": position, "after": count})
            position = max(0, count - 65536)
        while position < count:
            offset = position % 65536
            length = min(count - position, 65536 - offset)
            data = snapshot[8 + offset:8 + offset + length]
            log.write(data)
            capture.extend(data)
            position += length
        log.flush()
        if self.live and len(capture) > 1048576:
            del capture[:-1048576]
        return position

    def wait(self, marker: bytes, *, after: int = 0, timeout: float | None = None, plan9: bool = False, line: bool = False,
             prompt_line: bool = False):
        deadline = time.monotonic() + (timeout or self.timeout)
        while time.monotonic() < deadline:
            stream = self.plan9_capture if plan9 else self.capture
            text = bytes(stream[after:]).replace(b"\r\n", b"\n")
            complete = text.split(b"\n")[:-1]
            found = marker in (complete if line else text)
            if line and prompt_line:
                found = found or b"% " + marker in complete or b"; " + marker in complete
            if found:
                return
            if self.process.poll() is not None:
                raise RuntimeError("unified QEMU exited; inspect " + str(self.session))
            self.pump()
        raise TimeoutError("missing " + repr(marker) + "; inspect " + str(self.session))

    def send(self, data: bytes):
        for offset in range(0, len(data), 32):
            self.process.stdin.write(data[offset:offset + 32])
            self.process.stdin.flush()
            self.pump(0.01)

    def command(self, command: str, timeout: float | None = None):
        token = "UNIFIED_COMMAND_" + uuid.uuid4().hex
        # Two selectors converge even if an operator left a dangling prefix;
        # clear any literal selector residue before the fresh shell command.
        self.send(b"\x1e0\x1e0\x15" + (command + "; _uw_rc=$?; printf '\\n" + token + ":%s\\n' \"$_uw_rc\"\n").encode())
        deadline = time.monotonic() + (timeout or self.timeout)
        while time.monotonic() < deadline:
            lines = bytes(self.capture).replace(b"\r\n", b"\n").split(b"\n")[:-1]
            for line in lines:
                status = common.command_completion_status(line, token.encode())
                if status is not None:
                    if status != 0:
                        raise RuntimeError("guest command failed: " + command + "; " + repr(line))
                    return
            if self.process.poll() is not None:
                raise RuntimeError("unified QEMU exited during guest command")
            self.pump()
        raise TimeoutError("guest command timed out: " + command + "; inspect " + str(self.session))

    def ready(self):
        self.wait(b"KW unified Linux/Plan9 EL2: online", line=True)
        self.wait(b"OKERNEL PACKAGE DOMAIN READY", line=True)
        self.wait(b"pkg> ")
        self.mount_linux_namespace()
        self.command("date -u -s @" + str(self.clock))
        self.command("pkg-net online", timeout=120)
        if self.service:
            deadline = time.monotonic() + self.timeout
            while not self.provider_ready and time.monotonic() < deadline:
                self.pump()
            if not self.provider_ready:
                raise TimeoutError("original Plan9 command provider readiness missing")
            self.setup_linux_client()

    def counters(self) -> dict:
        path = self.session / "native-status.bin"
        self.qmp.execute("pmemsave", {"val": 0x6d000020, "size": 80, "filename": str(path)})
        live, switches, linux, plan9, linux_pc, plan9_pc, linux_esr, plan9_esr, console, dropped = struct.unpack("<10Q", path.read_bytes())
        result = {"live_domains": live, "switches": switches, "linux_exits": linux, "plan9_exits": plan9,
                "linux_pc": hex(linux_pc), "plan9_pc": hex(plan9_pc), "linux_esr": hex(linux_esr), "plan9_esr": hex(plan9_esr),
                "console": console, "input_dropped": dropped}
        if getattr(self, "idle_scheduler", None) is not None:
            self.qmp.execute("pmemsave", {"val": IDLE_SCHEDULER["blocked_mask_address"], "size": 40,
                                         "filename": str(path)})
            blocked, waits, requests, sent, received = struct.unpack("<5Q", path.read_bytes())
            if blocked & ~3:
                raise RuntimeError("invalid native idle scheduler state")
            result.update(blocked_domains=blocked, native_idle_waits=waits,
                          plan9_9p_requests=requests, plan9_9p_request_bytes=sent,
                          plan9_9p_reply_bytes=received)
        return result

    def save(self):
        # Confirm that the original Plan9 console accepts commands too. DEL is
        # its original console interrupt key; the host does not substitute an
        # original engine or mistake echoed input for a completed command.
        live = self.counters()["live_domains"]
        if live == 1 and self.provider_failed:
            self.record["plan9_save_state"] = "native authority withdrawn; no Plan9 operations remain"
        else:
            if live != 3:
                raise RuntimeError("save requires both live shells or verified Plan9 withdrawal")
            for attempt in range(2):
                token = "PLAN9_SAVE_READY_" + uuid.uuid4().hex
                self.send(b"\x1e1\x7f\x15")
                self.send(("echo " + token + "\n").encode())
                try:
                    self.wait(token.encode(), plan9=True, line=True, prompt_line=True, timeout=3 if attempt == 0 else 15)
                    break
                except TimeoutError:
                    if attempt:
                        raise
        self.command("sync")
        flag = self.session / "quiescence.bin"
        for attempt in range(1000):
            self.qmp.execute("stop")
            if self.qmp.execute("query-status").get("running") is not False:
                raise RuntimeError("CPU did not stop")
            self.qmp.execute("pmemsave", {"val": 0x6d000008, "size": 8, "filename": str(flag)})
            value = flag.read_bytes()
            if value == bytes(8):
                break
            if value != b"\1" + bytes(7):
                raise RuntimeError("invalid native quiescence word")
            self.qmp.execute("cont")
            self.pump(0.01)
        else:
            raise RuntimeError("native operations did not reach a snapshot boundary")
        selected = {"schema": "ostadix.package-domain-disk-head/v2",
                    "previous": self.head["disk"], "previous_namespace": self.head["namespace"],
                    "session": str(self.session),
                    "console_exit_consumed": sorted(self.console_exit_seen)}
        for key, folder, suffix, address, size in (("disk", "disk-generations", ".ext4", 0x70000000, DISK_BYTES),
                                                   ("namespace", "namespace-generations", ".raw", 0x6c000000, STORE_BYTES)):
            generations = self.state / folder
            if generations.is_symlink():
                raise ValueError("generation store must not be a symlink")
            temporary = generations / ("pending-unified-" + uuid.uuid4().hex + suffix)
            self.qmp.execute("pmemsave", {"val": address, "size": size, "filename": str(temporary)})
            if temporary.stat().st_size != size:
                raise RuntimeError("snapshot export incomplete")
            with temporary.open("rb") as stream:
                os.fsync(stream.fileno())
            expected = identity(temporary)
            target = generations / (expected["sha256"] + suffix)
            if target.exists() or target.is_symlink():
                checked(target, expected)
                temporary.unlink()
            else:
                temporary.chmod(0o400)
                temporary.replace(target)
            common.fsync_directory(generations)
            selected[key] = identity(target)
        common.validate_head(self.state, selected)
        common.write_json(self.state / "head.json", selected)
        self.record.update(ok=True, after=selected, paired_snapshot=True, virtual_cpu_stopped=True,
                           native_operations_quiescent=True, quiescence_attempts=attempt + 1)
        self.head = selected
        return selected

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()
        if self.qmp is not None:
            self.qmp.close()
        if self.ram is not None:
            os.close(self.ram)
        self.selector.close()
        for stream in (self.log, self.plan9_log, self.terminal_log, self.error_log):
            stream.close()
        try:
            common.write_json(self.session / "result.json", self.record)
        finally:
            try:
                if self.control is not None:
                    self.control.cleanup()
            finally:
                self.lock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("test", "run"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--bootstrap", type=Path)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--legacy-control", action="store_true", help="use rollback mailbox operations 1/2")
    args = parser.parse_args()
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    domain = None
    try:
        bootstrap = args.bootstrap.read_bytes() if args.bootstrap else DEFAULT_BOOTSTRAP
        domain = UnifiedDomain(args.state.expanduser(), args.build.expanduser(), args.qemu,
                               bootstrap=bootstrap, live=args.action == "run", timeout=args.timeout, legacy_control=args.legacy_control)
        if args.action == "run":
            if not sys.stdin.isatty():
                raise ValueError("interactive unified console requires a real foreground terminal")
            common.run_interactive(domain)
        else:
            domain.ready()
            domain.command("i=0; until grep -qx " + domain.ready_value + " /n/okernel/work/" + domain.ready_name + "; do i=$((i+1)); test \"$i\" -lt 100 || exit 1; sleep 0.1; done")
            domain.command("printf '#include <stdio.h>\\nint main(void){puts(\"UNIFIED_LINUX_SOURCE_PASS\");return 0;}\\n' > /n/okernel/work/unified-world.c; cc /n/okernel/work/unified-world.c -o /work/unified-world && /work/unified-world")
            domain.wait(b"UNIFIED_LINUX_SOURCE_PASS", line=True)
            counters = domain.counters()
            if counters["live_domains"] != 3 or counters["switches"] < 10:
                raise RuntimeError("both original kernels did not maintain scheduled progress")
            domain.save()
            domain.record["checks"] = ["one O-core monitor booted original Linux and original9front simultaneously",
                                      "original Plan9 wrote native shared object recovered by original Linux",
                                      "original Linux GCC compiled and executed source with Plan9 still scheduled"]
            domain.record["counters"] = counters
            print("Unified two-kernel component gate: PASS\nEvidence: " + str(domain.session / "result.json"))
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError) as error:
        if domain is not None:
            domain.record["error"] = str(error)
        print("Unified execution failed: " + str(error), file=sys.stderr)
        return 1
    except BaseException as error:
        if domain is not None:
            domain.record["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if domain is not None:
            domain.close()


if __name__ == "__main__":
    raise SystemExit(main())
