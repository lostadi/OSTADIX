#!/usr/bin/env python3
"""Run a persistent package-capable Linux guest beneath the real O-core EL2 monitor.

The ARM64 execution profile runs under QEMU/TCG on this host. It does not use
host apk/cc to claim guest success, bypass O-core, or qualify physical x86 boot.
The monitor owns guest RAM, mediates serial I/O and validates every block queue.
Disk generations are saved only after guest sync and a stopped virtual CPU.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import selectors
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import termios
import time
import tty
import uuid

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "ostadix/okernel/package-domain"
READY = b"OKERNEL PACKAGE DOMAIN READY"
PERSISTENT = b"KW Linux package domain: persistent mediated devices online"
DISK_SIZES = (536870912, 1073741824)
NETWORK_GRANT = {"enabled": True, "mac": "52:54:00:12:34:56",
                 "transport": "O-core mediated virtio-mmio Ethernet", "guest_mmio": 0x0a000200,
                 "guest_irq": 49, "host_dma_base": 0x6e000000, "host_dma_limit": 0x6e200000}
NAMESPACE_GRANT = {"enabled": True, "transport": "native O-core 9P2000 over virtio-mmio",
                   "guest_mmio": 0x0a000400, "guest_irq": 50, "mount_tag": "okernel",
                   "address": 0x6c000000, "bytes": 0x01000000, "epoch_address": 0x6d000000,
                   "quiescence_address": 0x6d000008,
                   "clock_address": 0x6d000010,
                   "linux_grant": 1, "native_peer_grant": 2}


def command_completion_status(line: bytes, token: bytes) -> int | None:
    """Read one complete decimal shell-status record, ignoring echoed source.

    Terminal redraw can put the nonce at the beginning of a printf/source
    fragment. Only the full byte line with a Unix status in 0..255 is a record.
    The caller supplies completed lines, never an unfinished output prefix.
    """
    prefix = token + b":"
    if not line.startswith(prefix):
        return None
    digits = line[len(prefix):]
    if not 1 <= len(digits) <= 3 or any(byte < 48 or byte > 57 for byte in digits):
        return None
    status = int(digits)
    return status if status <= 255 else None


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def identity(path: Path) -> dict:
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest(path)}


def write_json(path: Path, value: dict) -> None:
    candidate = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    with candidate.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    candidate.replace(path)
    fsync_directory(path.parent)


def fsync_directory(path: Path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_profile(manifest: dict):
    backing_bytes = manifest.get("backing_bytes")
    if type(backing_bytes) is not int or backing_bytes not in DISK_SIZES:
        raise ValueError("package-domain disk grant must be exactly 512MiB or 1GiB")
    required = {
        "schema": "ostadix.kernel-world-linux-monitor/v1", "profile": "package-domain",
        "backing_base": 0x70000000, "backing_bytes": backing_bytes,
        "block_backing": {"address": 0x70000000, "bytes": backing_bytes},
        "guest_ram_ipa": 0x40000000, "guest_ram_pa": 0x48000000,
        "guest_ram_bytes": 0x20000000, "outer_ram_bytes": 0x80000000,
        "loader_addresses": {"Image": 0x48000000, "guest_dtb": 0x4fe00000, "initramfs": 0x50000000},
    }
    if any(manifest.get(key) != expected for key, expected in required.items()):
        raise ValueError("expected the exact persistent package-domain memory/device grant")
    network = manifest.get("network_grant")
    offline = {key: False if key == "enabled" else None for key in NETWORK_GRANT}
    if network is not None and network not in (offline, NETWORK_GRANT):
        raise ValueError("unsupported or malformed package-domain network grant")
    namespace = manifest.get("namespace_grant")
    disabled = {key: False if key == "enabled" else None for key in NAMESPACE_GRANT}
    if namespace is not None and namespace not in (disabled, NAMESPACE_GRANT):
        raise ValueError("unsupported or malformed native namespace grant")


def validate_head(state: Path, head: dict) -> dict:
    if head.get("schema") not in ("ostadix.package-domain-disk-head/v1", "ostadix.package-domain-disk-head/v2"):
        raise ValueError("unsupported package-domain disk head")
    record = head["disk"]
    if not isinstance(record.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None:
        raise ValueError("invalid disk generation digest")
    expected = state / "disk-generations" / (record["sha256"] + ".ext4")
    if type(record.get("bytes")) is not int or record["bytes"] not in DISK_SIZES or Path(record["path"]) != expected or expected.parent.is_symlink():
        raise ValueError("disk head escaped its granted content-addressed generation store")
    namespace = head.get("namespace")
    if namespace is not None:
        fingerprint = namespace.get("sha256")
        if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
            raise ValueError("invalid namespace generation digest")
        expected = state / "namespace-generations" / (fingerprint + ".raw")
        if namespace.get("bytes") != NAMESPACE_GRANT["bytes"] or Path(namespace["path"]) != expected or expected.parent.is_symlink():
            raise ValueError("namespace head escaped its granted generation store")
    elif head["schema"].endswith("/v2"):
        raise ValueError("a paired generation head requires a native namespace")
    return record


def checked_file(path: Path, expected: dict) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular artifact: {path}")
    if path.stat().st_size != expected["bytes"] or digest(path) != expected["sha256"]:
        raise ValueError(f"artifact does not match its recorded identity: {path}")
    return path


def selected_disk_bytes(state: Path) -> int:
    """Use the selected immutable generation when deriving a device grant."""
    head = state / "head.json"
    if head.is_symlink():
        raise ValueError("disk head must not be a symlink")
    if head.exists():
        selected = validate_head(state, json.loads(head.read_text()))
        source = Path(selected["path"])
    else:
        manifest = state / "rootfs/package-domain.json"
        if manifest.is_symlink():
            raise ValueError("base image manifest must not be a symlink")
        base = json.loads(manifest.read_text())
        if base.get("schema") != "ostadix.linux-package-domain/v1" or base.get("architecture") != "aarch64":
            raise ValueError("unsupported package-domain root filesystem manifest")
        selected = base["artifacts"]["package-domain.ext4"]
        source = state / "rootfs/package-domain.ext4"
    if type(selected.get("bytes")) is not int or selected["bytes"] not in DISK_SIZES:
        raise ValueError("selected root disk does not match a supported device grant")
    checked_file(source, selected)
    return selected["bytes"]


class ControlSocket:
    """One private QMP endpoint, independent of a potentially long state path.

    The caller owns an exclusive newly-created session directory. Short paths
    retain the historical session/control.sock location. Longer paths use a
    fresh private directory under /tmp, never TMPDIR. Only that endpoint and,
    for the fallback, its exact empty directory are eligible for cleanup.
    """
    MAX_PATH_BYTES = 107  # Linux sockaddr_un.sun_path, excluding trailing NUL.
    RUNTIME_ROOT = Path("/tmp")

    @staticmethod
    def _directory(path: Path, *, runtime_root: bool = False):
        value = path.lstat()
        if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode):
            raise ValueError("QMP socket directory must not be a symlink")
        mode = stat.S_IMODE(value.st_mode)
        if runtime_root:
            trusted_tmp = value.st_uid == 0 and bool(mode & stat.S_ISVTX)
            private_owner = value.st_uid == os.geteuid() and mode == 0o700
            if not (trusted_tmp or private_owner):
                raise ValueError("QMP runtime root must be private or root-owned and sticky")
        elif value.st_uid != os.geteuid() or mode != 0o700:
            raise ValueError("QMP socket directory must be owned and mode 0700")
        return value.st_dev, value.st_ino, value.st_uid, mode

    def __init__(self, session: Path, *, prefer_session: bool = True):
        session = Path(os.path.abspath(session))
        self._directory(session)
        candidate = session / "control.sock"
        self.external = not (prefer_session and len(os.fsencode(candidate)) <= self.MAX_PATH_BYTES
                             and "," not in str(candidate))
        if self.external:
            root = self.RUNTIME_ROOT
            self._directory(root, runtime_root=True)
            token = hashlib.sha256(os.fsencode(session)).hexdigest()[:16]
            directory = Path(tempfile.mkdtemp(prefix=f"okernel-qmp-{os.geteuid()}-{token}-", dir=root))
        else:
            directory = session
        self.path = directory / "control.sock"
        self._identity = self._directory(directory)
        self._endpoint = None
        self._closed = False
        if len(os.fsencode(self.path)) > self.MAX_PATH_BYTES:
            if self.external:
                directory.rmdir()
            raise ValueError("QMP runtime root is too long for an AF_UNIX pathname")
        try:
            self.path.lstat()
        except FileNotFoundError:
            pass
        else:
            if self.external:
                directory.rmdir()
            raise FileExistsError("QMP socket path already exists; refusing to replace it")

    @property
    def directory(self) -> Path:
        return self.path.parent

    def _entry(self, descriptor: int):
        try:
            value = os.stat(self.path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if not stat.S_ISSOCK(value.st_mode) or value.st_uid != os.geteuid():
            raise ValueError("QMP endpoint is not an owned socket; preserving it")
        return value.st_dev, value.st_ino, value.st_uid

    def connected(self):
        """Bind cleanup to the actual endpoint after the QMP handshake."""
        if self._directory(self.directory) != self._identity:
            raise ValueError("QMP socket directory identity changed")
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino, current.st_uid, stat.S_IMODE(current.st_mode)) != self._identity:
                raise ValueError("QMP socket directory identity changed")
            self._endpoint = self._entry(descriptor)
            if self._endpoint is None:
                raise ValueError("QMP endpoint disappeared after connection")
        finally:
            os.close(descriptor)

    def cleanup(self):
        if self._closed:
            return
        self._closed = True
        if self._directory(self.directory) != self._identity:
            raise ValueError("QMP socket directory identity changed; preserving it")
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino, current.st_uid, stat.S_IMODE(current.st_mode)) != self._identity:
                raise ValueError("QMP socket directory identity changed; preserving it")
            if self.external and set(os.listdir(descriptor)) - {self.path.name}:
                raise ValueError("unexpected QMP runtime files; preserving directory")
            endpoint = self._entry(descriptor)
            if endpoint is not None:
                if self._endpoint is not None and endpoint != self._endpoint:
                    raise ValueError("QMP endpoint identity changed; preserving it")
                os.unlink(self.path.name, dir_fd=descriptor)
        finally:
            os.close(descriptor)
        if self.external:
            if self._directory(self.directory) != self._identity:
                raise ValueError("QMP socket directory identity changed; preserving it")
            self.directory.rmdir()


class QMP:
    def __init__(self, path: Path, timeout: float = 30):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)
        deadline = time.monotonic() + timeout
        while True:
            try:
                self.socket.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    self.socket.close()
                    raise TimeoutError("QMP control socket was not created")
                time.sleep(0.05)
        self.stream = self.socket.makefile("rwb", buffering=0)
        greeting = json.loads(self.stream.readline())
        if "QMP" not in greeting:
            raise ValueError("invalid QMP greeting")
        self.sequence = 0
        self.execute("qmp_capabilities")

    def execute(self, command: str, arguments: dict | None = None):
        self.sequence += 1
        request = {"execute": command, "id": self.sequence}
        if arguments is not None:
            request["arguments"] = arguments
        self.stream.write(json.dumps(request).encode() + b"\n")
        while True:
            line = self.stream.readline()
            if not line:
                raise RuntimeError("QMP disconnected")
            response = json.loads(line)
            if response.get("id") != self.sequence:
                continue
            if "error" in response:
                raise RuntimeError(f"QMP {command}: {response['error']}")
            return response.get("return")

    def close(self):
        self.stream.close()
        self.socket.close()


class Domain:
    def __init__(self, state: Path, qemu: str, *, live: bool = False, timeout: float = 180):
        self.state, self.live, self.timeout = state.resolve(), live, timeout
        self.state.mkdir(parents=True, exist_ok=True)
        self.lock = (self.state / "domain.lock").open("a+")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            raise RuntimeError("this package domain is already running")
        self.process = self.qmp = None
        self.control = None
        self.closed = False
        self.selector = selectors.DefaultSelector()
        self.capture = bytearray()
        self.last_check = 0
        self.session = Path(tempfile.mkdtemp(prefix="session-", dir=self.state))
        self.log = (self.session / "console.log").open("wb")
        self.errors = (self.session / "qemu-stderr.log").open("wb")
        self.inputs = []
        self.record = {"schema": "ostadix.package-domain-session/v1", "ok": False,
                       "scope": "real Linux below O-core ARM64 EL2 under QEMU/TCG; offline repository transport; no physical qualification"}
        try:
            self.control = ControlSocket(self.session)
            self.record["control_socket"] = {"path": str(self.control.path), "private_runtime": self.control.external}
            manifest_path = self.state / "monitor/monitor-profile.json"
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes)
            validate_profile(manifest)
            self.network = manifest.get("network_grant") == NETWORK_GRANT
            self.namespace = manifest.get("namespace_grant") == NAMESPACE_GRANT
            self.namespace_identity = None
            self.namespace_epoch = secrets.randbits(64) or 1
            self.namespace_clock = int(time.time())
            manifest_snapshot = self.session / "monitor-profile.json"
            manifest_snapshot.write_bytes(manifest_bytes)
            manifest_snapshot.chmod(0o400)
            self.backing = manifest["block_backing"]
            snapshots = self.session / "inputs"
            snapshots.mkdir()
            inputs = {}
            for name in ("monitor", "guest_dtb", "Image", "initramfs"):
                expected = manifest["artifacts"][name]
                source = checked_file(Path(expected["path"]), expected)
                snapshot = snapshots / name
                shutil.copyfile(source, snapshot)
                checked_file(snapshot, expected)
                snapshot.chmod(0o400)
                inputs[name] = snapshot
            head = self.state / "head.json"
            current_head = {}
            if head.exists():
                current_head = json.loads(head.read_text())
                self.disk_identity = validate_head(self.state, current_head)
                source_disk = Path(self.disk_identity["path"])
            else:
                source_disk = self.state / "rootfs/package-domain.ext4"
                base = json.loads((self.state / "rootfs/package-domain.json").read_text())
                if base.get("schema") != "ostadix.linux-package-domain/v1" or base.get("architecture") != "aarch64":
                    raise ValueError("unsupported package-domain root filesystem manifest")
                expected = base["artifacts"]["package-domain.ext4"]
                checked_file(source_disk, expected)
                self.disk_identity = identity(source_disk)
            if self.disk_identity["bytes"] != self.backing["bytes"]:
                raise ValueError("working root disk size does not match monitor grant")
            checked_file(source_disk, self.disk_identity)
            inputs["disk"] = snapshots / "disk.ext4"
            shutil.copyfile(source_disk, inputs["disk"])
            checked_file(inputs["disk"], self.disk_identity)
            inputs["disk"].chmod(0o400)
            if current_head.get("namespace") is not None and not self.namespace:
                raise ValueError("saved shared objects require the native namespace monitor grant")
            if self.namespace:
                inputs["namespace"] = snapshots / "namespace.raw"
                if current_head.get("namespace") is not None:
                    self.namespace_identity = current_head["namespace"]
                    source_namespace = checked_file(Path(self.namespace_identity["path"]), self.namespace_identity)
                    shutil.copyfile(source_namespace, inputs["namespace"])
                    checked_file(inputs["namespace"], self.namespace_identity)
                else:
                    # Formatting belongs to the native store. Only a zeroed,
                    # bounded fresh volume is provisioned by the launcher.
                    with inputs["namespace"].open("xb") as stream:
                        stream.truncate(NAMESPACE_GRANT["bytes"])
                    self.namespace_identity = identity(inputs["namespace"])
                inputs["namespace"].chmod(0o400)
            qemu_path = shutil.which(qemu)
            if not qemu_path:
                raise ValueError(f"QEMU is unavailable: {qemu}")
            command = [qemu_path, "-machine", "virt,virtualization=on,gic-version=2", "-accel", "tcg,thread=single",
                       "-cpu", "cortex-a57", "-smp", "1", "-m", "2G", "-nodefaults", "-nic", "none",
                       "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot", "-no-shutdown",
                       "-qmp", f"unix:{self.control.path},server=on,wait=off",
                       "-kernel", str(inputs["monitor"])]
            addresses = {**manifest["loader_addresses"], "disk": self.backing["address"]}
            if self.namespace:
                addresses["namespace"] = NAMESPACE_GRANT["address"]
            for name, address in addresses.items():
                command += ["-device", f"loader,file={str(inputs[name]).replace(',', ',,')},addr={hex(address)},force-raw=on"]
            if self.namespace:
                command += ["-device", f"loader,addr={hex(NAMESPACE_GRANT['epoch_address'])},data={self.namespace_epoch},data-len=8"]
                command += ["-device", f"loader,addr={hex(NAMESPACE_GRANT['clock_address'])},data={self.namespace_clock},data-len=8"]
                self.record.update(namespace_grant=NAMESPACE_GRANT, namespace_epoch=self.namespace_epoch,
                                   namespace_before=self.namespace_identity, namespace_clock_provision_unix_seconds=self.namespace_clock)
            if self.network:
                command += ["-global", "virtio-mmio.force-legacy=false", "-netdev", "user,id=okernel-net",
                            "-device", "virtio-net-device,bus=virtio-mmio-bus.31,netdev=okernel-net,mac=" + NETWORK_GRANT["mac"]]
                self.record["scope"] = "real Linux below O-core ARM64 EL2 under QEMU/TCG; mediated Ethernet via QEMU user networking; no physical qualification"
                self.record["network_grant"] = NETWORK_GRANT
            self.record.update(argv=command, monitor_manifest=identity(manifest_snapshot), qemu=identity(Path(qemu_path)),
                               inputs={name: identity(path) for name, path in inputs.items()}, disk_before=self.disk_identity)
            write_json(self.session / "result.json", self.record)
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
            (self.state / "latest-session").write_text(str(self.session) + "\n")
            self.selector.register(self.process.stdout, selectors.EVENT_READ, self.log)
            self.selector.register(self.process.stderr, selectors.EVENT_READ, self.errors)
            self.qmp = QMP(self.control.path)
            self.control.connected()
        except BaseException:
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
                self.capture.extend(data)
                if self.live:
                    os.write(sys.stdout.fileno(), data)
        recent = bytes(self.capture[self.last_check:])
        self.last_check = max(0, len(self.capture) - 256)
        if any(marker in recent for marker in (b"Kernel panic", b"KW terminal unexpected exit:", b"KW Linux boot payload header invalid")):
            raise RuntimeError(f"guest/monitor failure; inspect {self.session / 'console.log'}")

    def wait(self, marker: bytes, *, after: int = 0, timeout: float | None = None, line: bool = False):
        deadline = time.monotonic() + (timeout or self.timeout)
        while time.monotonic() < deadline:
            text = bytes(self.capture[after:]).replace(b"\r\n", b"\n")
            if (marker in text.split(b"\n")[:-1] if line else marker in text):
                return
            if self.process.poll() is not None:
                raise RuntimeError(f"QEMU exited {self.process.returncode}; log: {self.session / 'console.log'}")
            self.pump()
        raise TimeoutError(f"did not observe {marker!r}; log: {self.session / 'console.log'}")

    def send(self, data: bytes):
        self.inputs.append({"bytes_hex": data.hex(), "at_output_byte": len(self.capture)})
        for offset in range(0, len(data), 32):
            self.process.stdin.write(data[offset:offset + 32])
            self.process.stdin.flush()
            self.pump(0.01)

    def ready(self):
        self.wait(PERSISTENT)
        self.wait(READY, line=True)
        self.wait(b"pkg> ")
        if self.namespace:
            self.wait(b"KW native shared namespace: online", line=True)
            self.command("pkg-namespace mount")
        if self.network:
            self.wait(b"KW native governed network: online")
            # A real-time anchor is a recorded provisioning input, not host
            # filesystem access or a change to the host's clock. TLS retains
            # its ordinary certificate checks inside the Linux domain.
            epoch = int(time.time())
            self.record["guest_clock_provision_unix_seconds"] = epoch
            self.command("date -u -s @" + str(epoch))
            self.command("pkg-net online", timeout=120)

    def command(self, command: str, *, timeout: float | None = None):
        token = "OKERNEL_COMMAND_" + uuid.uuid4().hex
        after = len(self.capture)
        # A standalone unpredictable line proves command completion, not echo.
        wrapped = command + "; _okernel_rc=$?; printf '\\n" + token + ":%s\\n' \"$_okernel_rc\"\n"
        self.send(wrapped.encode())
        deadline = time.monotonic() + (timeout or self.timeout)
        while time.monotonic() < deadline:
            lines = bytes(self.capture[after:]).replace(b"\r\n", b"\n").split(b"\n")[:-1]
            for line in lines:
                status = command_completion_status(line, token.encode())
                if status is not None:
                    if status != 0:
                        raise RuntimeError(f"guest command failed ({line!r}): {command}")
                    return
            if self.process.poll() is not None:
                raise RuntimeError("guest exited while executing command")
            self.pump()
        raise TimeoutError(f"guest command timed out: {command}; log: {self.session / 'console.log'}")

    def save(self):
        self.command("sync")
        self.stop_at_snapshot_boundary()
        current = {"schema": "ostadix.package-domain-disk-head/v1", "disk": self.export_generation(self.backing, "disk-generations", ".ext4"),
                   "previous": self.disk_identity, "session": str(self.session)}
        if getattr(self, "namespace", False):
            current.update(schema="ostadix.package-domain-disk-head/v2",
                           namespace=self.export_generation(NAMESPACE_GRANT, "namespace-generations", ".raw"),
                           previous_namespace=self.namespace_identity)
        # The single commit point binds BOTH fully durable exports. Failure
        # exporting either artifact leaves the previous pair selected.
        write_json(self.state / "head.json", current)
        self.record.update(ok=True, disk_after=current["disk"], saved_after_guest_sync=True, virtual_cpu_stopped_before_export=True)
        if "namespace" in current:
            self.record.update(namespace_after=current["namespace"], paired_snapshot=True,
                               native_operations_quiescent_before_export=True)
        print(f"Saved persistent disk: {current['disk']['path']}", flush=True)

    def stop_at_snapshot_boundary(self):
        observation = self.session / "native-quiescence.bin"
        for attempt in range(1000):
            self.qmp.execute("stop")
            status = self.qmp.execute("query-status")
            if status.get("running") is not False:
                raise RuntimeError("virtual CPU did not stop before disk export")
            if not getattr(self, "namespace", False):
                return
            self.qmp.execute("pmemsave", {"val": NAMESPACE_GRANT["quiescence_address"],
                                         "size": 8, "filename": str(observation)})
            value = observation.read_bytes()
            if value == bytes(8):
                self.record["quiescence_stop_attempts"] = attempt + 1
                return
            if value != b"\x01" + bytes(7):
                raise RuntimeError("invalid native transaction quiescence word")
            self.qmp.execute("cont")
            self.pump(0.01)
        raise RuntimeError("could not stop between native transactions; the previous snapshot remains selected")

    def export_generation(self, grant: dict, store: str, suffix: str) -> dict:
        generations = self.state / store
        if generations.is_symlink():
            raise ValueError("generation store must not be a symlink")
        generations.mkdir(exist_ok=True)
        candidate = generations / ("pending-" + uuid.uuid4().hex + suffix)
        self.qmp.execute("pmemsave", {"val": grant["address"], "size": grant["bytes"], "filename": str(candidate)})
        if candidate.stat().st_size != grant["bytes"]:
            raise RuntimeError("QMP did not export the complete granted volume")
        with candidate.open("rb") as stream:
            os.fsync(stream.fileno())
        saved = digest(candidate)
        destination = generations / (saved + suffix)
        if destination.exists():
            checked_file(destination, {"bytes": grant["bytes"], "sha256": saved})
            candidate.unlink()
        else:
            candidate.chmod(0o400)
            candidate.replace(destination)
        fsync_directory(generations)
        return identity(destination)

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        if self.process is not None:
            for stream, log in ((self.process.stdout, self.log), (self.process.stderr, self.errors)):
                if stream is not None:
                    os.set_blocking(stream.fileno(), False)
                    while True:
                        try:
                            remaining = os.read(stream.fileno(), 65536)
                        except BlockingIOError:
                            break
                        if not remaining:
                            break
                        log.write(remaining)
                    stream.close()
            if self.process.stdin is not None:
                self.process.stdin.close()
        if self.qmp is not None:
            self.qmp.close()
        self.selector.close()
        for stream in (self.log, self.errors):
            stream.close()
        self.record["inputs_sent"] = self.inputs
        try:
            write_json(self.session / "result.json", self.record)
        finally:
            try:
                if self.control is not None:
                    self.control.cleanup()
            finally:
                self.lock.close()


def prepare(state: Path, *, network: bool = False, namespace: bool = False):
    env = os.environ.copy()
    state.mkdir(parents=True, exist_ok=True)
    payload = state / "payload"
    if not (payload / "linux-payload.json").exists():
        env.update(OCORE_LINUX_PROFILE="package-domain", OCORE_LINUX_TOOLCHAIN="llvm",
                   OCORE_LINUX_PAYLOAD_OUT=str(payload), OCORE_LINUX_JOBS="4")
        subprocess.run(["bash", str(ROOT / "scripts/build-real-linux-payload.sh")], env=env, check=True)
    rootfs = state / "rootfs"
    if not (rootfs / "package-domain.json").exists():
        subprocess.run([sys.executable, str(ROOT / "ocore/guest/linux/package-domain/build.py"),
                        "--output", str(rootfs), "--disk-bytes", "1073741824"], check=True)
    backing_bytes = selected_disk_bytes(state)
    shutil.copyfile(rootfs / "initramfs.cpio", payload / "initramfs.cpio")
    env.update(OCORE_LINUX_PROFILE="package-domain", OCORE_LINUX_PAYLOAD_DIR=str(payload),
               OCORE_LINUX_BUILD_DIR=str(state / "monitor"), OCORE_LINUX_BACKING_BYTES=str(backing_bytes),
               OCORE_LINUX_NETWORK="1" if network else "0", OCORE_LINUX_NAMESPACE="1" if namespace else "0")
    subprocess.run(["bash", str(ROOT / "ocore/kernel/build-aarch64-kernel-world-linux.sh")], env=env, check=True)


def run_interactive(domain):
    """Forward terminal input; only an explicit, completed save ends the VM."""
    descriptor = sys.stdin.fileno()
    original = termios.tcgetattr(descriptor)
    input_open = True
    try:
        tty.setraw(descriptor)
        domain.ready()
        while domain.process.poll() is None:
            readable = select.select([sys.stdin], [], [], 0)[0] if input_open else []
            if readable:
                data = os.read(descriptor, 256)
                if not data:
                    # A disconnected terminal is not permission to discard a
                    # running guest. A tmux pane normally keeps its PTY open.
                    input_open = False
                    print("\r\nConsole input closed; the VM remains running. No save/stop was requested.\r", flush=True)
                else:
                    before, requested, _ = data.partition(b"\x1d")
                    if before:
                        domain.send(before)
                    if requested:
                        try:
                            # Ctrl-U alone is consumed by foreground programs
                            # and cannot cancel an unfinished shell quote.
                            # Interrupt first, then require a fresh nonce-marked
                            # shell roundtrip. This also works with custom PS1.
                            for probe in range(2):
                                domain.send(b"\x03\x15")
                                try:
                                    domain.command("true", timeout=min(domain.timeout, 2 if probe == 0 else 15))
                                except TimeoutError:
                                    if probe:
                                        raise
                                    # ash may flush input while unwinding the
                                    # interrupted foreground job. A fresh nonce
                                    # on the second attempt cannot acknowledge
                                    # an old/echoed probe.
                                else:
                                    break
                            domain.save()
                        except (OSError, ValueError, KeyError, TypeError, RuntimeError,
                                TimeoutError, subprocess.SubprocessError) as error:
                            if domain.process.poll() is not None:
                                raise RuntimeError("guest exited before the requested save completed") from error
                            # A failed export can leave the vCPU stopped. Keep
                            # the same VM and console available for inspection
                            # and another save attempt; never force its exit.
                            try:
                                domain.qmp.execute("cont")
                            except (OSError, ValueError, RuntimeError, TimeoutError) as resume_error:
                                print(f"\r\nCould not resume the VM: {resume_error}\r", flush=True)
                            print(f"\r\nSave not confirmed: {error}\r\n"
                                  f"VM retained; inspect {domain.session / 'console.log'}. "
                                  "Ctrl+] retries saving.\r", flush=True)
                        else:
                            return
            domain.pump(0.02 if input_open else 0.1)
        raise RuntimeError("QEMU exited without a completed interactive save")
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, original)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "test", "run", "status", "stage", "install"))
    parser.add_argument("packages", nargs="*", help="package names for stage or install")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--network", action="store_true", help="build the explicit mediated Ethernet device grant")
    parser.add_argument("--namespace", action="store_true", help="build the shared native Linux/Plan 9 protocol namespace grant")
    parser.add_argument("--timeout", type=float, default=600,
                        help="guest command deadline in seconds; original source builds run under ARM emulation")
    args = parser.parse_intermixed_args()
    state = args.state.expanduser().resolve()
    if args.action in ("stage", "install"):
        if not args.packages:
            parser.error("stage/install requires one or more package names")
        selected_profile = json.loads((state / "monitor/monitor-profile.json").read_text())
        validate_profile(selected_profile)
        if args.action == "stage" or selected_profile.get("network_grant") != NETWORK_GRANT:
            command = [sys.executable, str(ROOT / "scripts/stage_okernel_repository.py"), "--state", str(state)]
            for package in args.packages:
                command += ["--package", package]
            staged = subprocess.run(command)
            if staged.returncode or args.action == "stage":
                return staged.returncode
    elif args.packages:
        parser.error("package names apply only to stage/install")
    if args.action == "build":
        prepare(state, network=args.network, namespace=args.namespace)
        return 0
    if args.action == "status":
        head = state / "head.json"
        print(head.read_text() if head.exists() else "No saved package-domain generation yet.")
        return 0
    domain = None
    try:
        if args.action == "install":
            domain = Domain(state, args.qemu, timeout=args.timeout)
            domain.ready()
            domain.command("pkg install " + shlex.join(args.packages), timeout=args.timeout)
            domain.save()
            print("Package installation inside the O-core-supervised domain: PASS")
        elif args.action == "test":
            acceptance = state / "acceptance.json"
            if acceptance.exists():
                history = state / "acceptance-history"
                history.mkdir(exist_ok=True)
                shutil.copyfile(acceptance, history / (uuid.uuid4().hex + ".json"))
            write_json(acceptance, {"schema": "ostadix.package-domain-acceptance/v1", "ok": False,
                                   "state": "verification in progress", "started": time.time()})
            domain = Domain(state, args.qemu, timeout=args.timeout)
            domain.ready()
            print("Guest shell ready under O-core; installing original Alpine packages.", flush=True)
            domain.command("apk add gcc make musl-dev jq", timeout=args.timeout)
            domain.command("mkdir -p /work; printf '#include <stdio.h>\\nint main(void){puts(\"OKERNEL_SOURCE_EXECUTION_PASS\");return 0;}\\n' > /work/hello.c; cc /work/hello.c -o /work/hello && /work/hello")
            domain.wait(b"OKERNEL_SOURCE_EXECUTION_PASS", line=True)
            domain.command("pkg install zlib", timeout=args.timeout)
            domain.command("test -f /usr/local/lib/libz.a && printf 'persistent-okernel-package-state\\n' > /work/persistence.txt")
            domain.save()
            first = domain.session
            domain.close()
            domain = Domain(state, args.qemu, timeout=args.timeout)
            domain.ready()
            domain.command("apk info -e gcc make musl-dev jq && test -f /usr/local/lib/libz.a && grep -qx persistent-okernel-package-state /work/persistence.txt && /work/hello")
            domain.wait(b"OKERNEL_SOURCE_EXECUTION_PASS", line=True)
            domain.save()
            write_json(state / "acceptance.json", {"schema": "ostadix.package-domain-acceptance/v1", "ok": True,
                        "first_session": str(first), "restart_session": str(domain.session),
                        "checks": ["original signed Alpine package installation by name", "C compilation and execution inside guest",
                                   "original zlib source build and install", "packages/files/source-built output survive restart"],
                        "scope": domain.record["scope"], "remaining": ["online network repository transport", "other repository ecosystems", "native Intel/physical X12 qualification"]})
            print(f"OKernel package/source-build persistence: PASS\nEvidence: {state / 'acceptance.json'}")
        else:
            if not sys.stdin.isatty():
                parser.error("run needs an interactive terminal; test performs automated verification")
            print("Package-domain console. Ctrl+] saves its disk and exits. Ctrl-C goes to the guest.", flush=True)
            domain = Domain(state, args.qemu, live=True, timeout=args.timeout)
            run_interactive(domain)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
        print(f"Package domain failed: {error}", file=sys.stderr)
        return 1
    finally:
        if domain is not None:
            domain.close()


if __name__ == "__main__":
    raise SystemExit(main())
