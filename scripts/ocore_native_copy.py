#!/usr/bin/env python3
"""Prototype observed regular-file cp edges; not registered production admission.

The original argv, stdio and outcome are retained even when observation fails.
A receipt is evidence, never authority: ownership additionally needs this live
controller's observed-operation binding AND an independently verified producer
inventory. This module deliberately has no JSON-to-trusted-inventory loader.
The controller/inventory interfaces are trusted host code, not a sandbox or an
identity boundary against arbitrary Python or another process with host access.
"""
from __future__ import annotations

import abc
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import threading
import time
from typing import Callable, Optional, Sequence

SCHEMA = "ostadix.observed-native-copy/v1"
IDENTITY_SCHEMA = "ostadix.stable-regular-file/v1"


class EvidenceError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"


@dataclasses.dataclass(frozen=True)
class FileIdentity:
    path: str
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str

    def as_dict(self) -> dict:
        return {"schema": IDENTITY_SCHEMA, **dataclasses.asdict(self)}


def _metadata(st: os.stat_result) -> tuple:
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def snapshot(path: Path) -> tuple[FileIdentity, bytes]:
    """Read a regular file without following the final symlink; detect mutation.

    Parent paths are resolved by the trusted controller. The explicit resolved
    spelling is part of the identity; equal bytes at another path are distinct.
    FIFOs/devices/directories are rejected before opening, without blocking.
    """
    path = Path(os.path.abspath(path))
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise EvidenceError(f"not a regular file: {path}")
    resolved = path.resolve(strict=True)
    # A final symlink is already excluded; parent changes must not change path.
    if resolved != path:
        raise EvidenceError(f"non-canonical parent path: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode) or _metadata(first) != _metadata(before):
            raise EvidenceError("file changed before observation")
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        payload = b"".join(chunks)
        last = os.fstat(fd)
    finally:
        os.close(fd)
    after = path.lstat()
    if _metadata(first) != _metadata(last) or _metadata(last) != _metadata(after):
        raise EvidenceError("file changed while observed")
    if len(payload) != after.st_size or path.resolve(strict=True) != resolved:
        raise EvidenceError("file path or length changed while observed")
    return FileIdentity(str(path), after.st_dev, after.st_ino, after.st_mode,
                        after.st_size, after.st_mtime_ns, after.st_ctime_ns,
                        hashlib.sha256(payload).hexdigest()), payload


@dataclasses.dataclass(frozen=True)
class OwnerRecord:
    """Only a trusted inventory may supply one; receipt fields cannot mint it."""
    output: FileIdentity
    completed_mono_ns: int
    producer_event: str
    verified_journal_sha256: str
    source_owned: bool
    llvm_replay_complete: bool
    ocore_lowered: bool
    unsupported: tuple[str, ...]


class VerifiedProducerInventory(abc.ABC):
    """Implemented by the controller's independently verified producer journal.

    Never implement this by looking for a same-hash file, trusting an inventory's
    source_owned flag, or parsing an untrusted earlier-event JSON claim. Producer
    completion and the exact output lifetime must already be established.
    """
    @abc.abstractmethod
    def predecessor(self, source: FileIdentity, before_mono_ns: int) -> Optional[OwnerRecord]:
        raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class Pins:
    tool: Path
    tool_sha256: str
    observer_sha256: str
    registry: Path
    registry_sha256: str


@dataclasses.dataclass
class CopyOutcome:
    event: str
    returncode: Optional[int]
    spawn_error: Optional[BaseException]
    receipt: Optional[Path]
    capture_errors: tuple[str, ...]
    _binding: object = dataclasses.field(repr=False)

    def forward_native_outcome(self) -> None:
        """For a wrapper's final action: preserve actual signal, not 128+signal."""
        if self.spawn_error is not None:
            raise self.spawn_error
        if self.returncode is None:
            raise EvidenceError("original operation has no observed outcome")
        if self.returncode < 0:
            sig = -self.returncode
            if sig not in (signal.SIGKILL, signal.SIGSTOP):
                signal.signal(sig, signal.SIG_DFL)
            if hasattr(signal, "pthread_sigmask"):
                signal.pthread_sigmask(signal.SIG_UNBLOCK, {sig})
            os.kill(os.getpid(), sig)
            raise EvidenceError("signal forwarding unexpectedly returned")
        raise SystemExit(self.returncode)


class _ParentSignalRelay:
    """Opt-in wrapper policy: relay each parent signal at most once, then reap.

    The original child stays in its original process group and keeps its stdio.
    Group delivery may already reach it directly; send_signal first polls/reaps
    it and cannot change the observed native outcome. This is a bounded cp
    wrapper policy, not a general shell/job-control or PTY implementation.
    """
    SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)

    def __init__(self):
        self.process = None
        self.completed = False
        self.pending = []
        self.forwarded = set()
        self.previous = {}

    def _forward(self, number):
        if self.completed or self.process is None or number in self.forwarded:
            return
        self.forwarded.add(number)
        # Popen.send_signal polls before signalling, avoiding an already reaped
        # PID. A signal racing native exit cannot manufacture a new outcome.
        self.process.send_signal(number)

    def _receive(self, number, frame):
        if number not in self.pending:
            self.pending.append(number)
        self._forward(number)

    def __enter__(self):
        if threading.current_thread() is not threading.main_thread():
            raise EvidenceError("parent relay policy requires the main thread")
        try:
            for number in self.SIGNALS:
                self.previous[number] = signal.getsignal(number)
                signal.signal(number, self._receive)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def started(self, process):
        self.process = process
        for number in self.pending:
            self._forward(number)

    def finished(self):
        self.completed = True
        self.process = None

    def __exit__(self, *unused):
        for number, handler in self.previous.items():
            signal.signal(number, handler)


class CaptureController:
    """Owns operation evidence, but delegates source authority to trusted input.

    Production integration must embed/pin this observer and register its adapter
    independently. This cache prototype always reports production_registered=false.
    The live binding prevents self-consistent pasted receipts from becoming copy
    observations. It does not authenticate journals after this controller exits;
    production admission must reconstruct its controller-bound observed set.
    """
    def __init__(self, *, pins: Pins, inventory: VerifiedProducerInventory, evidence: Path):
        if not isinstance(inventory, VerifiedProducerInventory):
            raise TypeError("an independently verified controller inventory is required")
        self.pins = pins
        self.inventory = inventory
        self.evidence = Path(evidence)
        self._observed: dict[str, tuple[object, str, Path]] = {}
        self._lock = threading.Lock()

    def _blob(self, payload: bytes) -> str:
        digest = hashlib.sha256(payload).hexdigest()
        directory = self.evidence / "blobs"
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / digest
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            _, observed = snapshot(target)
            if observed != payload:
                raise EvidenceError("existing content-addressed blob differs")
            return digest
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(0o400)
        except BaseException:
            # Preserve the failed partial file; never re-use it as valid evidence.
            raise
        return digest

    def observe_copy(self, argv: Sequence[str], *, cwd: Path,
                     on_started: Optional[Callable[[int], None]] = None,
                     relay_parent_signals: bool = False) -> CopyOutcome:
        """Execute once. The supervising controller normally owns its signals.

        A standalone transparent wrapper MUST opt in to relay_parent_signals,
        then call outcome.forward_native_outcome() as its final action. This
        suppresses Python KeyboardInterrupt text while preserving child status.
        """
        if relay_parent_signals:
            with _ParentSignalRelay() as relay:
                return self._observe_copy(argv, cwd=cwd, on_started=on_started, relay=relay)
        return self._observe_copy(argv, cwd=cwd, on_started=on_started)

    def _observe_copy(self, argv: Sequence[str], *, cwd: Path,
                      on_started: Optional[Callable[[int], None]] = None,
                      relay: Optional[_ParentSignalRelay] = None) -> CopyOutcome:
        """Execute exactly once with inherited streams, regardless of eligibility.

        argv includes the unchanged original argv[0]. The selected executable is
        supplied by the trusted wrapper resolver; it is not inferred from stdout.
        No stdout/stderr prefix, marker, retry or buffering is introduced here.
        on_started is a trusted controller diagnostic hook, not a source of proof.
        """
        argv = tuple(argv)
        original_cwd = os.fspath(cwd)
        base = Path(os.path.abspath(cwd))
        event = secrets.token_hex(16)
        binding = object()
        errors: list[str] = []
        observed: dict = {}
        checked_started_ns = time.monotonic_ns()
        supported = False
        source: Optional[Path] = None
        destination: Optional[Path] = None

        def attempt(label: str, action: Callable):
            try:
                return action()
            except Exception as error:
                errors.append(f"{label}: {type(error).__name__}: {error}")
                return None

        # Only the exact two-operand, plain transfer profile is classified.
        operands = list(argv[1:])
        if operands[:1] == ["--"]:
            operands = operands[1:]
        if len(operands) == 2 and all(isinstance(value, str) and value and not value.startswith("-") for value in operands):
            source = Path(os.path.abspath(base / operands[0]))
            destination = Path(os.path.abspath(base / operands[1]))
            supported = True
        else:
            errors.append("unsupported argv profile; original command still executed")

        if not self.pins.tool.is_absolute() or not self.pins.registry.is_absolute():
            errors.append("selected tool/registry must be absolute for classified evidence")
        observer = attempt("observer identity", lambda: snapshot(Path(__file__).resolve()))
        if observer:
            observed["observer"] = observer[0].as_dict()
            if observer[0].sha256 != self.pins.observer_sha256:
                errors.append("observer pin differs")
        registry = attempt("registry identity", lambda: snapshot(self.pins.registry))
        if registry:
            observed["registry"] = registry[0].as_dict()
            if registry[0].sha256 != self.pins.registry_sha256:
                errors.append("registry pin differs")
        tool_before = attempt("tool before", lambda: snapshot(self.pins.tool))
        if tool_before:
            observed["tool_before"] = tool_before[0].as_dict()
            if tool_before[0].sha256 != self.pins.tool_sha256:
                errors.append("tool pin differs")
        src_before = attempt("source before", lambda: snapshot(source)) if supported else None
        if src_before:
            observed["source_before"] = src_before[0].as_dict()
            attempt("source blob", lambda: self._blob(src_before[1]))
        if supported:
            if os.path.lexists(destination):
                dst_before = attempt("destination before", lambda: snapshot(destination))
                if dst_before:
                    observed["destination_before"] = dst_before[0].as_dict()
            else:
                observed["destination_before"] = None

        native_started_ns = time.monotonic_ns()
        process = None
        spawn_error: Optional[BaseException] = None
        returncode = None
        try:
            process = subprocess.Popen(argv, executable=os.fspath(self.pins.tool), cwd=original_cwd)
        except (OSError, ValueError) as error:
            spawn_error = error
        if process is not None:
            if relay is not None:
                relay.started(process)
            if on_started is not None:
                attempt("on_started", lambda: on_started(process.pid))
            # The caller owns terminal/process-group interruption. A signal sent
            # to the actual child is reported by wait as a negative returncode.
            returncode = process.wait()
        if relay is not None:
            relay.finished()
        native_completed_ns = time.monotonic_ns()

        tool_after = attempt("tool after", lambda: snapshot(self.pins.tool))
        if tool_after:
            observed["tool_after"] = tool_after[0].as_dict()
        observer_after = attempt("observer after", lambda: snapshot(Path(__file__).resolve()))
        registry_after = attempt("registry after", lambda: snapshot(self.pins.registry))
        for key, value in (("observer_after", observer_after), ("registry_after", registry_after)):
            if value:
                observed[key] = value[0].as_dict()
        if observer and observer_after and observer[0] != observer_after[0]:
            errors.append("observer changed across original operation")
        if registry and registry_after and registry[0] != registry_after[0]:
            errors.append("registry changed across original operation")
        src_after = attempt("source after", lambda: snapshot(source)) if supported else None
        dst_after = attempt("destination after", lambda: snapshot(destination)) if supported else None
        if src_after:
            observed["source_after"] = src_after[0].as_dict()
        if dst_after:
            observed["destination_after"] = dst_after[0].as_dict()
            attempt("destination blob", lambda: self._blob(dst_after[1]))
        if tool_before and tool_after and tool_before[0] != tool_after[0]:
            errors.append("tool changed across original operation")
        if src_before and src_after and src_before[0] != src_after[0]:
            errors.append("source changed across original operation")
        if src_before and dst_after and src_before[1] != dst_after[1]:
            errors.append("destination bytes differ from stable source")
        if returncode != 0:
            errors.append("original operation did not complete successfully")
        if not (tool_before and tool_after and src_before and src_after and dst_after and observer and registry and observer_after and registry_after):
            errors.append("required observation unavailable")
        eligible = supported and not errors and spawn_error is None
        receipt_body = {
            "schema": SCHEMA, "event": event, "production_registered": False,
            "argv": list(argv), "cwd": original_cwd, "canonical_cwd": str(base),
            "checked_started_mono_ns": checked_started_ns,
            "native_started_mono_ns": native_started_ns,
            "native_completed_mono_ns": native_completed_ns,
            "native_returncode": returncode,
            "native_signal": -returncode if returncode is not None and returncode < 0 else None,
            "spawn_error": None if spawn_error is None else {"type": type(spawn_error).__name__, "message": str(spawn_error)},
            "stdio": "inherited-unmodified",
            "parent_signal_policy": "relay-at-most-once-per-signal" if relay is not None else "owned-by-controller",
            "parent_signals_received": [] if relay is None else list(relay.pending),
            "parent_signals_forwarded": [] if relay is None else sorted(relay.forwarded),
            "supported_regular_transfer": supported,
            "eligible_observation": eligible, "observations": observed,
            "capture_errors": errors,
        }
        receipt_path: Optional[Path] = None
        try:
            self.evidence.mkdir(parents=True, exist_ok=True)
            receipt_path = self.evidence / (event + ".json")
            payload = canonical_json(receipt_body)
            with receipt_path.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            receipt_path.chmod(0o400)
            with self._lock:
                self._observed[event] = (binding, hashlib.sha256(payload).hexdigest(), receipt_path)
        except Exception as error:
            errors.append(f"receipt persistence: {type(error).__name__}: {error}")
            receipt_path = None
        return CopyOutcome(event, returncode, spawn_error, receipt_path, tuple(errors), binding)

    def verify_observation(self, outcome: CopyOutcome) -> dict:
        """Verify observed facts, without qualifying the destination's producer.

        Even a genuine cp and exact pre/post bytes do not prove its destination
        inode came from cp if an untracked writer can replace it in the window.
        This prototype has no enforced all-writer/lifetime authority, so its
        output source ownership and destination causality always remain false.
        A checked earlier source producer is reported separately, if available.
        """
        if not isinstance(outcome, CopyOutcome):
            raise EvidenceError("receipt JSON is not an observed controller operation")
        with self._lock:
            bound = self._observed.get(outcome.event)
        if bound is None or bound[0] is not outcome._binding or outcome.receipt != bound[2]:
            raise EvidenceError("operation absent from controller-bound observed set")
        _, payload = snapshot(bound[2])
        if hashlib.sha256(payload).hexdigest() != bound[1]:
            raise EvidenceError("observed receipt differs from controller binding")
        receipt = json.loads(payload)
        if not receipt["eligible_observation"] or outcome.capture_errors:
            raise EvidenceError("copy observation is ineligible: " + "; ".join(outcome.capture_errors))
        observations = receipt["observations"]
        def identity(key: str) -> FileIdentity:
            row = dict(observations[key])
            if row.pop("schema") != IDENTITY_SCHEMA:
                raise EvidenceError("file identity schema differs")
            return FileIdentity(**row)
        src = identity("source_before")
        dst = identity("destination_after")
        if (src != identity("source_after") or identity("tool_before") != identity("tool_after")
                or identity("observer") != identity("observer_after")
                or identity("registry") != identity("registry_after")):
            raise EvidenceError("unstable observed source/tool/observer/registry")
        for item in (src, dst):
            _, blob = snapshot(self.evidence / "blobs" / item.sha256)
            if len(blob) != item.size or hashlib.sha256(blob).hexdigest() != item.sha256:
                raise EvidenceError("captured blob differs")
        if src.sha256 != dst.sha256:
            raise EvidenceError("transfer did not preserve exact bytes")
        predecessor = self.inventory.predecessor(src, receipt["native_started_mono_ns"])
        if predecessor is not None:
            if not isinstance(predecessor, OwnerRecord):
                raise EvidenceError("malformed trusted predecessor contract")
            if (any(type(value) is not bool for value in
                    (predecessor.source_owned, predecessor.llvm_replay_complete, predecessor.ocore_lowered))
                    or not isinstance(predecessor.verified_journal_sha256, str)
                    or len(predecessor.verified_journal_sha256) != 64
                    or any(c not in "0123456789abcdef" for c in predecessor.verified_journal_sha256)
                    or not isinstance(predecessor.producer_event, str) or not predecessor.producer_event
                    or type(predecessor.completed_mono_ns) is not int
                    or not isinstance(predecessor.unsupported, tuple)
                    or any(not isinstance(item, str) for item in predecessor.unsupported)):
                raise EvidenceError("malformed trusted predecessor contract")
            if predecessor.output != src or predecessor.completed_mono_ns >= receipt["checked_started_mono_ns"]:
                raise EvidenceError("predecessor path/lifetime/order differs")
        return {
            "schema": "ostadix.verified-native-copy-observation/v1",
            "production_registered": False, "event": outcome.event,
            "receipt_sha256": bound[1], "source": src.as_dict(), "destination": dst.as_dict(),
            "source_owned": False, "destination_causality_qualified": False,
            "llvm_replay_complete": False, "ocore_lowered": False,
            "predecessor_event": None if predecessor is None else predecessor.producer_event,
            "predecessor_verified_journal_sha256": None if predecessor is None else predecessor.verified_journal_sha256,
            "predecessor_source_owned": False if predecessor is None else predecessor.source_owned,
            "predecessor_llvm_replay_complete": None if predecessor is None else predecessor.llvm_replay_complete,
            "predecessor_ocore_lowered": None if predecessor is None else predecessor.ocore_lowered,
            "predecessor_unsupported": None if predecessor is None else list(predecessor.unsupported),
            "ownership_blocker": "registered owning-controller exclusive output window unavailable",
        }

    def verify_transfer(self, outcome: CopyOutcome) -> dict:
        """Fail closed until production enforces all-writer/output lifetimes.

        No bool, receipt field, JSON claim or cooperative lock can enable this
        gate. Root must implement and independently qualify the registered
        owning capture's real exclusive-window authority before extending it.
        Even the real-Clang fixture inventory is insufficient for admission.
        """
        self.verify_observation(outcome)
        raise EvidenceError("registered owning-controller exclusive output window unavailable; source ownership disabled")
