#!/usr/bin/env python3
"""Bounded cold/repeated-operation benchmark for the JavaScript backend."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import statistics
import subprocess
import sys
import time
from typing import Any, Sequence


SCHEMA = "ostadix.backend-runtime-benchmark/v1"
BENCHMARK = "ostadix-javascript-cold1-warm10-output1mib"
ROOT = Path(__file__).resolve().parents[2]
RUNNER = Path(__file__).resolve()
FIXTURE_DIR = RUNNER.parent
MAX_CAPTURE_BYTES = 4 * 1024 * 1024
LARGE_OUTPUT_BYTES = 1024 * 1024
LARGE_OUTPUT_SHA256 = hashlib.sha256(b"x" * LARGE_OUTPUT_BYTES).hexdigest()
CASES = (
    "javascript_cold1",
    "javascript_warm10",
    "javascript_output_1mib",
)
CASE_ORDERS = (
    list(CASES),
    [CASES[1], CASES[2], CASES[0]],
    [CASES[2], CASES[0], CASES[1]],
    [CASES[2], CASES[1], CASES[0]],
    [CASES[1], CASES[0], CASES[2]],
    [CASES[0], CASES[2], CASES[1]],
)
FIXTURES = {
    "javascript_cold1": FIXTURE_DIR / "javascript_cold1.O",
    "javascript_warm10": FIXTURE_DIR / "javascript_warm10.O",
    "javascript_output_1mib": FIXTURE_DIR / "javascript_output_1mib.O",
}
EXPECTED_SCALARS = {
    "javascript_cold1": {
        "ok": True,
        "type": "number",
        "value": {"t": "number", "v": {"kind": "int", "v": "1"}},
    },
    "javascript_warm10": {
        "ok": True,
        "type": "number",
        "value": {"t": "number", "v": {"kind": "int", "v": "10"}},
    },
}
EXPECTED_DESCRIPTORS = {
    **EXPECTED_SCALARS,
    "javascript_output_1mib": {
        "ok": True,
        "type": "text",
        "value_tag": "text",
        "encoding": "utf-8",
        "payload_bytes": LARGE_OUTPUT_BYTES,
        "payload_sha256": LARGE_OUTPUT_SHA256,
    },
}
REMOVED_CHILD_ENVIRONMENT = (
    "NODE_OPTIONS",
    "NODE_PATH",
    "O_BACKEND_OPERATION_TIMEOUT_MS",
    "O_BACKEND_SHUTDOWN_TIMEOUT_MS",
    "O_EXECUTOR",
    "O_GRAPH_WORKERS",
    "O_LIFECYCLE_TRACE",
    "PYTHONHOME",
    "PYTHONPATH",
)


class BenchmarkError(RuntimeError):
    """An expected benchmark input, runtime, or semantic-contract failure."""


def bounded_integer(name: str, minimum: int, maximum: int):
    def parse(raw: str) -> int:
        try:
            value = int(raw)
        except ValueError as error:
            raise argparse.ArgumentTypeError(f"{name} must be an integer") from error
        if not minimum <= value <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}, got {value}"
            )
        return value

    return parse


def finite_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if not math.isfinite(value):
        raise argparse.ArgumentTypeError("must be finite")
    return value


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure one versus ten dependency-ordered hosted JavaScript operations "
            "and an exact 1 MiB JavaScript result. Every sample is semantically checked; "
            "no performance threshold is applied."
        )
    )
    parser.add_argument(
        "--o-bin",
        type=Path,
        default=Path(os.environ.get("O_RELEASE_BIN", ROOT / "target/release/O")),
        help="O executable (default: target/release/O or O_RELEASE_BIN)",
    )
    parser.add_argument(
        "--backends-dir",
        type=Path,
        default=Path(os.environ.get("O_BACKENDS_DIR", ROOT / "backends")),
        help="backend shim directory (default: backends or O_BACKENDS_DIR)",
    )
    parser.add_argument(
        "--warmups",
        type=bounded_integer("warmups", 0, 20),
        default=2,
        help="checked warmup groups excluded from summaries (default: 2)",
    )
    parser.add_argument(
        "--repetitions",
        type=bounded_integer("repetitions", 1, 100),
        default=9,
        help="measured groups cycling through case orders (default: 9)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=finite_float,
        default=120.0,
        help="timeout for each O process (default: 120)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write JSON here instead of stdout",
    )
    args = parser.parse_args(argv)
    if not 0.1 <= args.timeout_seconds <= 600:
        parser.error("--timeout-seconds must be between 0.1 and 600")
    return args


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise BenchmarkError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def resolve_executable(path: Path, label: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as error:
        raise BenchmarkError(f"{label} does not exist: {path}: {error}") from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise BenchmarkError(f"{label} is not an executable file: {resolved}")
    return resolved


def resolve_directory(path: Path, label: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as error:
        raise BenchmarkError(f"{label} does not exist: {path}: {error}") from error
    if not resolved.is_dir():
        raise BenchmarkError(f"{label} is not a directory: {resolved}")
    return resolved


def child_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in REMOVED_CHILD_ENVIRONMENT:
        environment.pop(name, None)
    environment.update(
        {
            "LC_ALL": "C",
            "TZ": "UTC",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return environment


def terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    else:
        process.terminate()
    try:
        process.communicate(timeout=1)
        return
    except subprocess.TimeoutExpired:
        pass
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        process.kill()
    process.communicate()


def run_process(
    command: Sequence[str], timeout: float, *, measure: bool = True
) -> tuple[int, str, str]:
    started = time.perf_counter_ns()
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=child_environment(),
            start_new_session=os.name == "posix",
        )
    except OSError as error:
        raise BenchmarkError(f"cannot start {command[0]}: {error}") from error
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        terminate_process_tree(process)
        raise BenchmarkError(
            f"command timed out after {timeout:g}s: {' '.join(command[:4])}"
        ) from error
    elapsed_ns = time.perf_counter_ns() - started if measure else 0
    if len(stdout.encode("utf-8")) > MAX_CAPTURE_BYTES:
        raise BenchmarkError("O stdout exceeded the 4 MiB benchmark capture limit")
    if len(stderr.encode("utf-8")) > MAX_CAPTURE_BYTES:
        raise BenchmarkError("O stderr exceeded the 4 MiB benchmark capture limit")
    if process.returncode != 0:
        diagnostic = stderr.strip()
        if len(diagnostic) > 2000:
            diagnostic = diagnostic[:2000] + "..."
        raise BenchmarkError(
            f"command failed with exit {process.returncode}: {' '.join(command[:4])}\n"
            f"{diagnostic}"
        )
    return elapsed_ns, stdout, stderr


def parse_json_object(raw: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise BenchmarkError(f"{label} emitted invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} JSON must be an object")
    return value


def run_case(
    command: Sequence[str], timeout: float, case: str
) -> tuple[int, int, str]:
    wall_ns, stdout, _ = run_process(command, timeout)
    envelope = parse_json_object(stdout, case)
    if envelope.get("ok") is not True:
        raise BenchmarkError(f"{case} reported failure: {envelope!r}")
    semantic = {
        "ok": envelope.get("ok"),
        "type": envelope.get("type"),
        "value": envelope.get("value"),
    }
    if case in EXPECTED_SCALARS and semantic != EXPECTED_SCALARS[case]:
        raise BenchmarkError(
            f"{case} semantic result differs from its checked fixture oracle: "
            f"{canonical_json(semantic)}"
        )
    if case == "javascript_output_1mib":
        value = semantic["value"]
        if (
            semantic["type"] != "text"
            or not isinstance(value, dict)
            or value.get("t") != "text"
            or not isinstance(value.get("v"), dict)
            or value["v"].get("encoding") != "utf-8"
            or not isinstance(value["v"].get("utf8"), str)
        ):
            raise BenchmarkError(
                "javascript_output_1mib did not return canonical UTF-8 text"
            )
        payload = value["v"]["utf8"].encode("utf-8")
        payload_sha256 = sha256_bytes(payload)
        if len(payload) != LARGE_OUTPUT_BYTES or payload_sha256 != LARGE_OUTPUT_SHA256:
            raise BenchmarkError(
                "javascript_output_1mib payload differs from its checked length/digest "
                f"oracle: bytes={len(payload)} sha256={payload_sha256}"
            )
    elapsed_ms = envelope.get("elapsed_ms")
    if isinstance(elapsed_ms, bool) or not isinstance(elapsed_ms, int) or elapsed_ms < 0:
        raise BenchmarkError(f"{case} has invalid elapsed_ms: {elapsed_ms!r}")
    return wall_ns, elapsed_ms, sha256_bytes(canonical_json(semantic).encode("utf-8"))


def median(values: Sequence[int | float]) -> int | float:
    result = statistics.median(values)
    if isinstance(result, float) and result.is_integer():
        return int(result)
    return result


def summarize(values: Sequence[int | float], unit: str) -> dict[str, Any]:
    if not values:
        raise BenchmarkError("cannot summarize an empty sample")
    center = median(values)
    deviations = [abs(value - float(center)) for value in values]
    return {
        "unit": unit,
        "raw": list(values),
        "count": len(values),
        "min": min(values),
        "median": center,
        "max": max(values),
        "median_absolute_deviation": median(deviations),
    }


def git_provenance() -> dict[str, str]:
    def git(*arguments: str) -> str | None:
        try:
            completed = subprocess.run(
                [
                    "git",
                    "-c",
                    f"safe.directory={ROOT}",
                    "-C",
                    str(ROOT),
                    *arguments,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return completed.stdout.strip() if completed.returncode == 0 else None

    commit = git("rev-parse", "HEAD") or "unknown"
    status = git("status", "--porcelain", "--untracked-files=normal")
    state = "unknown" if status is None else "dirty" if status else "clean"
    return {"commit": commit, "tree_state": state}


def cpu_governors() -> list[str]:
    values = set()
    for path in Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_governor"):
        try:
            value = path.read_text(encoding="ascii").strip()
        except OSError:
            continue
        if value:
            values.add(value)
    return sorted(values)


def host_provenance() -> dict[str, Any]:
    uname = platform.uname()
    try:
        affinity: list[int] | str = sorted(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        affinity = "unknown"
    try:
        load_average: list[float] | None = list(os.getloadavg())
    except (AttributeError, OSError):
        load_average = None
    return {
        "system": uname.system,
        "release": uname.release,
        "version": uname.version,
        "machine": uname.machine,
        "processor": platform.processor() or "unknown",
        "logical_cpus": os.cpu_count(),
        "affinity": affinity,
        "cpu_governors": cpu_governors(),
        "load_average": load_average,
    }


def artifact_record(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def optional_compatibility_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {
            "path": str(path),
            "present": False,
            "execution_role": "compatibility/archive; not selected by NativeRust",
        }
    return {
        **artifact_record(path),
        "present": True,
        "execution_role": "compatibility/archive; not selected by NativeRust",
    }


def assert_artifacts_unchanged(records: dict[str, dict[str, Any]]) -> None:
    for label, record in records.items():
        path = Path(record["path"])
        if sha256_file(path) != record["sha256"]:
            raise BenchmarkError(f"{label} changed while the benchmark was running: {path}")


def fixture_record(path: Path, operations: int) -> dict[str, Any]:
    payload = path.read_bytes()
    return {
        "path": str(path),
        "bytes": len(payload),
        "sha256": sha256_bytes(payload),
        "hosted_operations": operations,
        "environment_id": 0,
        "dependency_ordered": operations > 1,
    }


def write_result(result: dict[str, Any], output: Path | None) -> None:
    rendered = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if output is None:
        sys.stdout.write(rendered)
        return
    output = output.expanduser()
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    except OSError as error:
        raise BenchmarkError(f"cannot write result {output}: {error}") from error


def execute(args: argparse.Namespace) -> dict[str, Any]:
    started_at_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    total_started_ns = time.perf_counter_ns()
    o_bin = resolve_executable(args.o_bin, "O executable")
    backends_dir = resolve_directory(args.backends_dir, "backend directory")
    node_invocation = shutil.which("node")
    if node_invocation is None:
        raise BenchmarkError("Node.js executable `node` is not available on PATH")
    node_bin = resolve_executable(Path(node_invocation), "Node.js executable")
    for case, fixture in FIXTURES.items():
        if not fixture.is_file():
            raise BenchmarkError(f"{case} fixture is missing: {fixture}")

    runner_record = artifact_record(RUNNER)
    artifacts = {
        "o_binary": artifact_record(o_bin),
        "node_binary": artifact_record(node_bin),
    }
    compatibility_files = {
        "javascript_python_shim": optional_compatibility_record(
            backends_dir / "javascript_shim.py"
        ),
        "python_shim_common": optional_compatibility_record(
            backends_dir / "o_shim_common.py"
        ),
    }
    fixtures = {
        "javascript_cold1": fixture_record(FIXTURES["javascript_cold1"], 1),
        "javascript_warm10": fixture_record(FIXTURES["javascript_warm10"], 10),
        "javascript_output_1mib": fixture_record(
            FIXTURES["javascript_output_1mib"], 1
        ),
    }
    _, node_version_stdout, node_version_stderr = run_process(
        [str(node_bin), "--version"], min(args.timeout_seconds, 10), measure=False
    )
    node_version_lines = (node_version_stdout or node_version_stderr).strip().splitlines()
    if not node_version_lines:
        raise BenchmarkError("Node.js --version returned no version text")
    node_version = node_version_lines[0]
    _, o_version_stdout, _ = run_process(
        [str(o_bin), "version", "--json"], min(args.timeout_seconds, 10), measure=False
    )
    o_version = parse_json_object(o_version_stdout, "O version --json")

    commands = {
        case: [
            str(o_bin),
            "--executor",
            "serial",
            "--json",
            str(FIXTURES[case]),
            str(backends_dir),
        ]
        for case in CASES
    }
    warmup_samples: list[dict[str, Any]] = []
    measured_samples: list[dict[str, Any]] = []
    total_groups = args.warmups + args.repetitions
    for global_ordinal in range(1, total_groups + 1):
        phase = "warmup" if global_ordinal <= args.warmups else "measured"
        phase_ordinal = (
            global_ordinal if phase == "warmup" else global_ordinal - args.warmups
        )
        order = CASE_ORDERS[(global_ordinal - 1) % len(CASE_ORDERS)]
        print(
            f"{phase} {phase_ordinal}/"
            f"{args.warmups if phase == 'warmup' else args.repetitions} "
            f"order={','.join(order)}",
            file=sys.stderr,
            flush=True,
        )
        sample: dict[str, Any] = {
            "ordinal": phase_ordinal,
            "order": order,
            "wall_time_ns": {},
            "runtime_elapsed_ms": {},
            "semantic_sha256": {},
        }
        for case in order:
            wall_ns, elapsed_ms, semantic_sha256 = run_case(
                commands[case], args.timeout_seconds, case
            )
            sample["wall_time_ns"][case] = wall_ns
            sample["runtime_elapsed_ms"][case] = elapsed_ms
            sample["semantic_sha256"][case] = semantic_sha256
        (warmup_samples if phase == "warmup" else measured_samples).append(sample)

    assert_artifacts_unchanged(
        {
            "runner": runner_record,
            **artifacts,
            **{f"fixture_{name}": record for name, record in fixtures.items()},
        }
    )
    measurements: dict[str, Any] = {}
    for case in CASES:
        measurements[case] = {
            "wall_time": summarize(
                [sample["wall_time_ns"][case] for sample in measured_samples], "ns"
            ),
            "runtime_elapsed": summarize(
                [sample["runtime_elapsed_ms"][case] for sample in measured_samples],
                "ms",
            ),
        }
    incremental = [
        sample["wall_time_ns"]["javascript_warm10"]
        - sample["wall_time_ns"]["javascript_cold1"]
        for sample in measured_samples
    ]
    amortized = [value / 9 for value in incremental]

    return {
        "schema": SCHEMA,
        "benchmark": BENCHMARK,
        "started_at_utc": started_at_utc,
        "completed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_duration_ns": time.perf_counter_ns() - total_started_ns,
        "clock": "time.perf_counter_ns",
        "configuration": {
            "executor": "serial",
            "warmups": args.warmups,
            "repetitions": args.repetitions,
            "timeout_seconds_per_o_process": args.timeout_seconds,
            "cases": list(CASES),
        },
        "provenance": {
            "runner": runner_record,
            "repository_root": str(ROOT),
            "git": git_provenance(),
            "host": host_provenance(),
            "python": {
                "path": sys.executable,
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
            },
            "o_version": o_version,
            "node": {
                "invocation_path": node_invocation,
                "version": node_version,
            },
            "artifacts": artifacts,
            "execution_model": {
                "catalog_adapter": "NativeRust",
                "persistent_component": "O --o-backend javascript proxy",
                "per_operation_component": "fresh Node.js process",
                "python_compatibility_shim_executed": False,
            },
            "compatibility_files_not_executed": compatibility_files,
            "backends_dir": str(backends_dir),
            "child_environment_policy": {
                "set": {
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                "removed": list(REMOVED_CHILD_ENVIRONMENT),
            },
        },
        "fixtures": fixtures,
        "expected_semantics": EXPECTED_DESCRIPTORS,
        "command_templates": {
            case: f"O --executor serial --json {FIXTURES[case].name} BACKENDS"
            for case in CASES
        },
        "samples": {"warmup": warmup_samples, "measured": measured_samples},
        "measurements": measurements,
        "derived": {
            "warm10_minus_cold1_wall_time": summarize(incremental, "ns"),
            "amortized_additional_operation_wall_time": summarize(amortized, "ns"),
            "amortized_formula": "(paired warm10 wall ns - paired cold1 wall ns) / 9",
            "interpretation": (
                "Amortizes evaluator and native-proxy startup; each additional operation "
                "still launches a fresh Node.js subprocess."
            ),
        },
        "semantics": {
            "all_samples_match_checked_oracles": True,
            "checked_groups": total_groups,
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        write_result(execute(args), args.output)
        return 0
    except (BenchmarkError, OSError) as error:
        print(f"backend runtime benchmark error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
