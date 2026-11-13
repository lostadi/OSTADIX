"""Pure framing and integrity helpers for the original Plan 9 command service.

These messages coordinate one trusted operator. Their IDs and hashes are not
credentials, and these helpers neither publish files nor execute commands.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath
import re
import struct
from typing import Sequence


# Preserve the existing coordinator mount spelling; the original Plan 9
# namespace mounts the same store at /n and uses PLAN9_ROOT instead.
DEFAULT_ROOT = "/n/okernel/services/plan9"
PLAN9_ROOT = "/n/services/plan9"
REQUEST_MAGIC = b"OC9REQ01"
RESULT_MAGIC = b"OC9RES01"
MAX_REQUEST_BYTES = 1_048_576
MAX_STREAM_BYTES = 1_048_576
MAX_STATUS_BYTES = 4096
MAX_ARGUMENTS = 64
MAX_ARGUMENT_BYTES = 65535
MAX_CWD_BYTES = 4095
MAX_TIMEOUT_MS = 300_000
FLAG_TIMEOUT = 1
FLAG_STDOUT_TRUNCATED = 2
FLAG_STDERR_TRUNCATED = 4
FLAG_START_FAILED = 8  # Service preparation, launch, or capture failure.
FLAG_CANCELLED = 16
KNOWN_FLAGS = 31
REQUEST_HEADER = struct.Struct("<8s16s32s32s6I")
RESULT_HEADER = struct.Struct("<8s16s32s32s32s4I32s32s")
REQUEST_FILES = ("request", "submit", "started", "stdout", "stderr", "status", "result", "done")
OPTIONAL_REQUEST_FILES = ("cancel",)


class ProtocolError(ValueError):
    """A message is malformed, outside its limits, or belongs to another run."""


@dataclass(frozen=True)
class Request:
    generation: str
    instance: str
    request_id: str
    argv: tuple[str, ...]
    cwd: str
    stdin: bytes
    timeout_ms: int
    stdout_limit: int
    stderr_limit: int


@dataclass(frozen=True)
class Result:
    generation: str
    instance: str
    request_id: str
    request_sha256: str
    flags: int
    stdout_bytes: int
    stderr_bytes: int
    stdout_sha256: str
    stderr_sha256: str
    status: bytes

    @property
    def ok(self) -> bool:
        return self.flags == 0 and self.status == b""


@dataclass(frozen=True)
class Submission:
    generation: str
    instance: str
    request_id: str
    request_sha256: str


@dataclass(frozen=True)
class Completion:
    generation: str
    instance: str
    request_id: str
    request_sha256: str
    result_sha256: str


def _bytes(value, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ProtocolError(name + " must be bytes")
    return bytes(value)


def _hex(value: str, size: int, name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{" + str(size) + "}", value) is None:
        raise ProtocolError(name + " must be exactly " + str(size) + " lowercase hexadecimal characters")
    return value


def _ids(generation: str, instance: str, request_id: str) -> tuple[str, str, str]:
    return (_generation(generation), _hex(instance, 32, "instance"),
            _hex(request_id, 32, "request ID"))


def _generation(value: str) -> str:
    _hex(value, 16, "generation")
    if value == "0" * 16:
        raise ProtocolError("generation must be nonzero")
    return value


def _integer(value: int, minimum: int, maximum: int, name: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProtocolError(name + " is outside its integer range")
    return value


def _text(value: str, maximum: int, name: str, absolute: bool = False) -> bytes:
    if not isinstance(value, str):
        raise ProtocolError(name + " must be text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise ProtocolError(name + " is not valid UTF-8") from error
    if b"\0" in encoded or len(encoded) > maximum or (absolute and not encoded.startswith(b"/")):
        raise ProtocolError(name + " has an invalid length, NUL, or relative path")
    return encoded


def _decode_text(value: bytes, maximum: int, name: str, absolute: bool = False) -> str:
    try:
        decoded = value.decode("utf-8")
    except UnicodeError as error:
        raise ProtocolError(name + " is not valid UTF-8") from error
    _text(decoded, maximum, name, absolute)
    return decoded


def _decode_ids(values) -> tuple[str, str, str]:
    try:
        return _ids(*(part.decode("ascii") for part in values))
    except UnicodeError as error:
        raise ProtocolError("identity is not ASCII") from error


def encode_request(generation: str, instance: str, request_id: str,
                   argv: Sequence[str], *, cwd: str, stdin: bytes = b"",
                   timeout_ms: int = 30_000, stdout_limit: int = MAX_STREAM_BYTES,
                   stderr_limit: int = MAX_STREAM_BYTES) -> bytes:
    identities = _ids(generation, instance, request_id)
    if isinstance(argv, (str, bytes)):
        raise ProtocolError("argv must be a sequence of arguments")
    try:
        arguments = tuple(argv)
    except TypeError as error:
        raise ProtocolError("argv must be a sequence of arguments") from error
    _integer(len(arguments), 1, MAX_ARGUMENTS, "argc")
    cwd_bytes = _text(cwd, MAX_CWD_BYTES, "cwd", absolute=True)
    argument_bytes = [_text(arg, MAX_ARGUMENT_BYTES, "argument", absolute=index == 0)
                      for index, arg in enumerate(arguments)]
    input_bytes = _bytes(stdin, "stdin")
    _integer(timeout_ms, 1, MAX_TIMEOUT_MS, "timeout")
    _integer(stdout_limit, 0, MAX_STREAM_BYTES, "stdout limit")
    _integer(stderr_limit, 0, MAX_STREAM_BYTES, "stderr limit")
    total = REQUEST_HEADER.size + len(cwd_bytes) + len(input_bytes) + sum(4 + len(arg) for arg in argument_bytes)
    if total > MAX_REQUEST_BYTES:
        raise ProtocolError("request exceeds 1 MiB")
    header = REQUEST_HEADER.pack(REQUEST_MAGIC, *(value.encode("ascii") for value in identities),
                                 len(arguments), len(cwd_bytes), len(input_bytes), timeout_ms,
                                 stdout_limit, stderr_limit)
    return header + cwd_bytes + b"".join(struct.pack("<I", len(arg)) + arg for arg in argument_bytes) + input_bytes


def decode_request(data: bytes) -> Request:
    data = _bytes(data, "request")
    if not REQUEST_HEADER.size <= len(data) <= MAX_REQUEST_BYTES:
        raise ProtocolError("request has an invalid total length")
    magic, generation, instance, request_id, argc, cwd_size, input_size, timeout, outlimit, errlimit = REQUEST_HEADER.unpack_from(data)
    if magic != REQUEST_MAGIC:
        raise ProtocolError("invalid request magic")
    identities = _decode_ids((generation, instance, request_id))
    _integer(argc, 1, MAX_ARGUMENTS, "argc")
    _integer(cwd_size, 1, MAX_CWD_BYTES, "cwd length")
    _integer(timeout, 1, MAX_TIMEOUT_MS, "timeout")
    _integer(outlimit, 0, MAX_STREAM_BYTES, "stdout limit")
    _integer(errlimit, 0, MAX_STREAM_BYTES, "stderr limit")
    position = REQUEST_HEADER.size

    def take(length: int) -> bytes:
        nonlocal position
        if length > len(data) - position:
            raise ProtocolError("request contains a truncated field")
        value = data[position:position + length]
        position += length
        return value

    cwd = _decode_text(take(cwd_size), MAX_CWD_BYTES, "cwd", absolute=True)
    arguments = []
    for index in range(argc):
        size = struct.unpack("<I", take(4))[0]
        _integer(size, 0, MAX_ARGUMENT_BYTES, "argument length")
        arguments.append(_decode_text(take(size), MAX_ARGUMENT_BYTES, "argument", absolute=index == 0))
    stdin = take(input_size)
    if position != len(data):
        raise ProtocolError("request has trailing bytes")
    return Request(*identities, tuple(arguments), cwd, stdin, timeout, outlimit, errlimit)


def encode_result(request_bytes: bytes, *, flags: int, stdout: bytes, stderr: bytes, status: bytes) -> bytes:
    request_bytes = _bytes(request_bytes, "request")
    request = decode_request(request_bytes)
    stdout, stderr, status = _bytes(stdout, "stdout"), _bytes(stderr, "stderr"), _bytes(status, "status")
    _integer(flags, 0, KNOWN_FLAGS, "flags")
    if len(stdout) > request.stdout_limit or len(stderr) > request.stderr_limit or len(status) > MAX_STATUS_BYTES:
        raise ProtocolError("result exceeds request capture or status limits")
    return RESULT_HEADER.pack(RESULT_MAGIC, request.generation.encode(), request.instance.encode(),
                              request.request_id.encode(), hashlib.sha256(request_bytes).digest(),
                              flags, len(stdout), len(stderr), len(status),
                              hashlib.sha256(stdout).digest(), hashlib.sha256(stderr).digest()) + status


def decode_result(data: bytes) -> Result:
    data = _bytes(data, "result")
    if not RESULT_HEADER.size <= len(data) <= RESULT_HEADER.size + MAX_STATUS_BYTES:
        raise ProtocolError("result has an invalid total length")
    magic, generation, instance, request_id, request_hash, flags, stdout_size, stderr_size, status_size, stdout_hash, stderr_hash = RESULT_HEADER.unpack_from(data)
    if magic != RESULT_MAGIC:
        raise ProtocolError("invalid result magic")
    identities = _decode_ids((generation, instance, request_id))
    _integer(flags, 0, KNOWN_FLAGS, "flags")
    _integer(stdout_size, 0, MAX_STREAM_BYTES, "stdout length")
    _integer(stderr_size, 0, MAX_STREAM_BYTES, "stderr length")
    if status_size != len(data) - RESULT_HEADER.size:
        raise ProtocolError("result status length or trailing bytes mismatch")
    return Result(*identities, request_hash.hex(), flags, stdout_size, stderr_size,
                  stdout_hash.hex(), stderr_hash.hex(), data[RESULT_HEADER.size:])


def ready_marker(generation: str, instance: str) -> bytes:
    _generation(generation)
    _hex(instance, 32, "instance")
    return f"OC9READY1 {generation} {instance}\n".encode("ascii")


def _marker(data: bytes, magic: str, lengths: tuple[int, ...]) -> tuple[str, ...]:
    data = _bytes(data, "marker")
    try:
        text = data.decode("ascii")
    except UnicodeError as error:
        raise ProtocolError("marker is not ASCII") from error
    fields = text.removesuffix("\n").split(" ")
    if not text.endswith("\n") or len(fields) != len(lengths) + 1 or fields[0] != magic:
        raise ProtocolError("invalid marker framing")
    values = tuple(_hex(value, size, "marker field") for value, size in zip(fields[1:], lengths))
    _generation(values[0])
    return values


def parse_ready(data: bytes) -> tuple[str, str]:
    return _marker(data, "OC9READY1", (16, 32))


def submit_marker(request_bytes: bytes) -> bytes:
    request_bytes = _bytes(request_bytes, "request")
    request = decode_request(request_bytes)
    return (f"OC9SUB01 {request.generation} {request.instance} {request.request_id} "
            f"{hashlib.sha256(request_bytes).hexdigest()}\n").encode("ascii")


def parse_submit(data: bytes) -> Submission:
    return Submission(*_marker(data, "OC9SUB01", (16, 32, 32, 64)))


def validate_submit(request_bytes: bytes, submit: bytes) -> Request:
    request = decode_request(request_bytes)
    parse_submit(submit)
    if _bytes(submit, "submit") != submit_marker(request_bytes):
        raise ProtocolError("submit is not bound to this exact request")
    return request


def cancel_marker(request_bytes: bytes) -> bytes:
    """Describe cancellation of this request; publication is the caller's job."""
    request_bytes = _bytes(request_bytes, "request")
    request = decode_request(request_bytes)
    return (f"OC9CAN01 {request.generation} {request.instance} {request.request_id} "
            f"{hashlib.sha256(request_bytes).hexdigest()}\n").encode("ascii")


def validate_cancel(request_bytes: bytes, marker: bytes) -> Request:
    """Bind a notice to the caller-selected active request, without cancelling it."""
    request = decode_request(request_bytes)
    _marker(marker, "OC9CAN01", (16, 32, 32, 64))
    if _bytes(marker, "cancel") != cancel_marker(request_bytes):
        raise ProtocolError("cancel is not bound to this exact request")
    return request


def done_marker(request_bytes: bytes, result_bytes: bytes) -> bytes:
    request = decode_request(request_bytes)
    result = decode_result(result_bytes)
    _bind_result(request_bytes, request, result)
    return (f"OC9DONE1 {request.generation} {request.instance} {request.request_id} "
            f"{hashlib.sha256(request_bytes).hexdigest()} {hashlib.sha256(result_bytes).hexdigest()}\n").encode("ascii")


def parse_done(data: bytes) -> Completion:
    return Completion(*_marker(data, "OC9DONE1", (16, 32, 32, 64, 64)))


def reset_marker(request_bytes: bytes, result_bytes: bytes) -> bytes:
    """Describe a timed-out or cancelled result requiring domain reset."""
    request = decode_request(request_bytes)
    result = decode_result(result_bytes)
    _bind_result(request_bytes, request, result)
    if not result.flags & (FLAG_TIMEOUT | FLAG_CANCELLED):
        raise ProtocolError("reset marker requires a timed-out or cancelled result")
    return (f"OC9RESET1 {request.generation} {request.instance} {request.request_id} "
            f"{hashlib.sha256(request_bytes).hexdigest()} {hashlib.sha256(result_bytes).hexdigest()}\n").encode("ascii")


def validate_reset(request_bytes: bytes, result_bytes: bytes, reset: bytes) -> Result:
    """Check the recovery notice's binding; this does not prove domain cleanup.

    Validate captured streams, status and publication separately with
    validate_result. A watchdog requires reset even when no notice exists.
    """
    _marker(reset, "OC9RESET1", (16, 32, 32, 64, 64))
    if _bytes(reset, "reset") != reset_marker(request_bytes, result_bytes):
        raise ProtocolError("reset is not bound to this exact request and result")
    return decode_result(result_bytes)


def _bind_result(request_bytes: bytes, request: Request, result: Result) -> None:
    if (result.generation, result.instance, result.request_id) != (request.generation, request.instance, request.request_id):
        raise ProtocolError("result belongs to another generation, instance, or request")
    if result.request_sha256 != hashlib.sha256(request_bytes).hexdigest():
        raise ProtocolError("result request digest mismatch")
    if result.stdout_bytes > request.stdout_limit or result.stderr_bytes > request.stderr_limit:
        raise ProtocolError("result exceeds request capture limits")


def validate_result(request_bytes: bytes, result_bytes: bytes, stdout: bytes, stderr: bytes,
                    *, done: bytes | None = None, started: bytes | None = None,
                    status: bytes | None = None) -> Result:
    request_bytes, result_bytes = _bytes(request_bytes, "request"), _bytes(result_bytes, "result")
    request, result = decode_request(request_bytes), decode_result(result_bytes)
    _bind_result(request_bytes, request, result)
    for name, value, size, digest in (("stdout", stdout, result.stdout_bytes, result.stdout_sha256),
                                    ("stderr", stderr, result.stderr_bytes, result.stderr_sha256)):
        value = _bytes(value, name)
        if len(value) != size or hashlib.sha256(value).hexdigest() != digest:
            raise ProtocolError(name + " length or digest mismatch")
    if status is not None and _bytes(status, "status") != result.status:
        raise ProtocolError("status file differs from authoritative result status")
    if started is not None:
        validate_submit(request_bytes, started)
    if done is not None:
        parse_done(done)
        if _bytes(done, "done") != done_marker(request_bytes, result_bytes):
            raise ProtocolError("done is not bound to this exact request and result")
    return result


def request_paths(root: str, generation: str, instance: str, request_id: str,
                  *, include_optional: bool = False) -> dict[str, str]:
    """Return required paths, optionally including the cancellation notice path."""
    _ids(generation, instance, request_id)
    _text(root, MAX_CWD_BYTES, "service root", absolute=True)
    path = PurePosixPath(root)
    if str(path) != root or ".." in path.parts or root.startswith("//"):
        raise ProtocolError("service root must be a canonical absolute path")
    directory = path / ("g" + generation) / ("s" + instance) / ("r" + request_id)
    names = REQUEST_FILES + OPTIONAL_REQUEST_FILES if include_optional else REQUEST_FILES
    return {name: str(directory / name) for name in names}
