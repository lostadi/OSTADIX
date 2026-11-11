#!/usr/bin/env python3
"""Run the seven review witnesses and safe migrations on a fresh Linux O build.

Uses only Python's standard library. Results are hosted boundary evidence, not
an operating-system, arbitrary guest sandbox, or cross-ISA qualification.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/foreign-splice-witnesses.json"
EXPECTED_WITNESSES = (
    (1, "python_apostrophe", "cb01e3a21acddbe41ddf0517aeecacdad321313e9a280ec72ab99f0b0500e801", True),
    (2, "sql_quoted_control", "13d4eed942b886a9ea499fcefc6a50664b9acf4a65edcf47899aa9013c8b2939", False),
    (3, "sql_quoted_apostrophe", "10d4065f6e886af23101a021509704bf12a8db8a77837ea9ab6d51e2c40faafb", False),
    (4, "sql_union_injection", "93ab3d26124baf3dabd7ce448be14375a2d044fb10cda95820077c0e9b6b695c", False),
    (5, "bash_quoted_injection", "8b5fca05cc7e9dd5fe4015efa33ec91a3f350edd051e091ed2997ab020473e3e", False),
    (6, "bash_native_braces", "9ed5c0fac09cd6abd70508cbcc46b2b2c8f956bcf0cf5e643b43b628ca7cd945", True),
    (7, "python_quoted_hole", "8cc5c37b2860b6b03341303a301f13f3dfd7f8759e83f10138d245d5ac36fba3", False),
)
EXPECTED_CASES = 12
EXPECTED_ATTEMPTS = 24


def write_report(directory: Path, report: dict) -> None:
    temporary = directory / ".result.json.tmp"
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(directory / "result.json")


def identity(path: Path) -> dict:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
    return {"bytes": path.stat().st_size, "sha256": h.hexdigest()}


def task(pid: int) -> tuple[int, int] | None:
    """Linux process start identity and process group; no command/env capture."""
    try:
        path = Path(f"/proc/{pid}")
        if path.stat().st_uid != os.getuid():
            return None
        tail = (path / "stat").read_text().rsplit(")", 1)[1].split()
        return int(tail[19]), int(tail[2])
    except (OSError, ValueError, IndexError):
        return None


def descendants(pid: int, found: dict[int, tuple[int, int]]) -> None:
    pending = [pid]
    seen = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pin = task(current)
        if pin is None:
            continue
        found[current] = pin
        try:
            threads = list(Path(f"/proc/{current}/task").iterdir())
        except OSError:
            continue
        for thread in threads:
            try:
                pending.extend(map(int, (thread / "children").read_text().split()))
            except OSError:
                pass


def terminate_observed(found: dict[int, tuple[int, int]], sig: int) -> None:
    groups = {pin[1] for pid, pin in found.items() if task(pid) == pin}
    assert os.getpgrp() not in groups, "Refuse to signal the invoking process group"
    for group in groups:
        try:
            os.killpg(group, sig)
        except ProcessLookupError:
            pass


def execute(binary: Path, backends: Path, directory: Path, source: str,
            executor: str, timeout: float) -> dict:
    command = [str(binary), "--json", "--executor", executor, "--eval", source, str(backends)]
    owned: dict[int, tuple[int, int]] = {}
    start = time.monotonic()
    timed_out = False
    child = None
    result = {"executor": executor, "exit_code": None, "timed_out": False,
              "answer": None, "diagnostic": "", "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
              "stdout_path": str(directory / "stdout.json"), "stderr_path": str(directory / "stderr.txt")}
    try:
        directory.mkdir()
        (directory / "witness.O").write_text(source)
        with (directory / "stdout.json").open("wb") as out, (directory / "stderr.txt").open("wb") as err:
            child = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=err, start_new_session=True)
            while child.poll() is None:
                descendants(child.pid, owned)
                if time.monotonic() - start >= timeout:
                    timed_out = True
                    for sig, grace in ((signal.SIGINT, 0.5), (signal.SIGTERM, 0.5), (signal.SIGKILL, 1.0)):
                        terminate_observed(owned, sig)
                        try:
                            child.wait(timeout=grace)
                            break
                        except subprocess.TimeoutExpired:
                            continue
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=1)
                    break
                time.sleep(0.02)
            result["exit_code"] = child.wait()
    except Exception as error:
        result["execution_error"] = f"{type(error).__name__}: {error}"
    finally:
        if child is not None and (timed_out or "execution_error" in result or child.poll() is None):
            # Only identities observed beneath this exact child are eligible.
            # This is finite cleanup, not an arbitrary descendant-tree sandbox.
            try:
                descendants(child.pid, owned)
                terminate_observed(owned, signal.SIGKILL)
                if child.poll() is None:
                    child.kill()
                result["exit_code"] = child.wait(timeout=1)
            except (OSError, subprocess.SubprocessError) as error:
                result["cleanup_error"] = f"{type(error).__name__}: {error}"
        result.update(timed_out=timed_out, seconds=time.monotonic() - start)
    for stream, filename in (("stdout", "stdout.json"), ("stderr", "stderr.txt")):
        try:
            result[stream] = identity(directory / filename)
            if stream == "stdout":
                try:
                    result["answer"] = json.loads((directory / filename).read_bytes())
                except (ValueError, UnicodeError) as error:
                    result["json_error"] = str(error)
            else:
                result["diagnostic"] = (directory / filename).read_text(errors="replace")
        except OSError as error:
            result.setdefault("retention_errors", []).append(f"{stream}: {error}")
    return result


def text(value: str) -> dict:
    return {"t": "text", "v": {"utf8": value, "encoding": "utf-8"}}


def original_cases(fixtures: object) -> list[dict]:
    if (not isinstance(fixtures, dict)
            or fixtures.get("schema") != "ostadix.foreign-splice-regression-witnesses/v1"
            or fixtures.get("baseline_commit") != "1da570dcc61ef10285fc8c8b78a20ca087081daf"):
        raise ValueError("unrecognized reviewed witness corpus")
    witnesses = fixtures.get("witnesses")
    if not isinstance(witnesses, list) or len(witnesses) != len(EXPECTED_WITNESSES):
        raise ValueError("the reproduction requires all seven reviewed witnesses")
    cases = []
    for witness, (number, name, digest, accept) in zip(witnesses, EXPECTED_WITNESSES, strict=True):
        if (not isinstance(witness, dict) or type(witness.get("number")) is not int
                or witness["number"] != number or witness.get("name") != name
                or witness.get("ordinary_contract_accepts") is not accept
                or witness.get("source_sha256_with_final_newline") != digest
                or not isinstance(witness.get("source"), str)):
            raise ValueError("reviewed witness inventory, order or oracle changed")
        source = witness["source"] + "\n"
        if hashlib.sha256(source.encode()).hexdigest() != digest:
            raise ValueError(f"reviewed source hash differs for witness {number}")
        expected = None
        if number == 1:
            expected = {"t": "list", "v": [{"t": "number", "v": {"kind": "int", "v": "7"}}, text("O'Brien")]}
        elif number == 6:
            expected = text('[a"; echo SPLICED-AS-CODE; echo "]')
        cases.append({"name": f"original-{number}", "source": source,
                      "accept": accept, "expected": expected})
    return cases


def validate_attempt(result: dict, case: dict, marker: Path) -> bool:
    if (result.get("timed_out") is not False or result.get("execution_error")
            or result.get("cleanup_error") or result.get("retention_errors")
            or type(result.get("exit_code")) is not int
            or result.get("source_sha256") != hashlib.sha256(case["source"].encode()).hexdigest()
            or marker.exists()):
        return False
    answer = result.get("answer")
    if not isinstance(answer, dict):
        return False
    if case["accept"]:
        evidence = answer.get("execution_evidence")
        return (result["exit_code"] == 0 and answer.get("ok") is True
                and answer.get("value") == case["expected"]
                and not answer.get("failed_batch_members")
                and isinstance(evidence, dict)
                and evidence.get("schema") == "ostadix.native-execution-evidence/v1"
                and evidence.get("execution_mode") == result.get("executor")
                and evidence.get("source_sha256") == result["source_sha256"])
    evidence = answer.get("execution_evidence")
    if (not isinstance(evidence, dict)
            or evidence.get("schema") != "ostadix.native-execution-evidence/v1"
            or "trace" not in evidence or evidence.get("admission") is not None
            or evidence.get("native_leaves") != []):
        return False
    trace = evidence.get("trace")
    no_effect = trace is None or (isinstance(trace, dict) and trace.get("events") == []
                                 and not trace.get("source_renderings") and not trace.get("publications"))
    return (result["exit_code"] != 0 and answer.get("ok") is False
            and answer.get("stage") == "parse" and no_effect
            and "foreign value splice" in str(answer.get("error", ""))
            and "foreign value splice" in result.get("diagnostic", ""))


def run_cases(binary: Path, backends: Path, directory: Path, cases: list[dict],
              marker: Path, timeout: float, report: dict) -> None:
    if len(cases) != EXPECTED_CASES or len({case["name"] for case in cases}) != EXPECTED_CASES:
        raise ValueError("the reproduction requires twelve unique cases and 24 attempts")
    report.update(expected_runs=EXPECTED_ATTEMPTS, asserted_runs=0)
    write_report(directory, report)
    for case in cases:
        for executor in ("serial", "graph"):
            attempt = {"case": case["name"], "executor": executor, "passed": False,
                       "source_sha256": hashlib.sha256(case["source"].encode()).hexdigest()}
            try:
                result = execute(binary, backends, directory / (case["name"] + "-" + executor),
                                 case["source"], executor, timeout)
                attempt.update(result)
                attempt["passed"] = bool(validate_attempt(result, case, marker))
            except Exception as error:
                attempt["execution_error"] = f"{type(error).__name__}: {error}"
            report["runs"].append(attempt)
            report["asserted_runs"] = len(report["runs"])
            write_report(directory, report)
    report["producer_marker_absent"] = not marker.exists()
    report["ok"] = (len(report["runs"]) == EXPECTED_ATTEMPTS
                    and all(row["passed"] for row in report["runs"])
                    and report["producer_marker_absent"])
    write_report(directory, report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--o-bin", type=Path, default=ROOT / "target/debug/O")
    parser.add_argument("--backends-dir", type=Path, default=ROOT / "backends")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=5)
    args = parser.parse_args()
    if platform.system() != "Linux" or not Path("/proc/self/task").is_dir():
        parser.error("this bounded process-cleanup harness requires Linux /proc")
    if not 0 < args.timeout <= 120:
        parser.error("--timeout must be positive and at most 120 seconds")
    binary, backends = args.o_bin.resolve(), args.backends_dir.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("build O or pass --o-bin pointing to the fresh executable")
    missing = [name for name in ("python3", "sqlite3", "bash") if shutil.which(name) is None]
    if missing:
        parser.error("required hosted engines unavailable: " + ", ".join(missing))
    if not (backends / "python_shim.py").is_file():
        parser.error("--backends-dir must contain the declared source backends")
    directory = args.output_dir.resolve()
    if directory.exists() and any(directory.iterdir()):
        parser.error("--output-dir must be absent or empty; old evidence is never overwritten")
    directory.mkdir(parents=True, exist_ok=True)
    try:
        fixtures = json.loads(FIXTURES.read_bytes())
        cases = original_cases(fixtures)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    for i, payload in enumerate(("OBrien", "O'Brien", "nobody' UNION SELECT 'spliced-as-code", "line1;line2\n'--")):
        encoded = base64.b64encode(payload.encode()).decode()
        producer = f"let name = python^(__import__('base64').b64decode('{encoded}').decode('utf-8'))_python\n"
        cases.append({"name": f"sql-value-{i}", "source": producer + "sql^( SELECT $name AS who; )_sql\n",
                      "accept": True, "expected": text(payload)})
    marker = directory / "must-not-exist"
    marker_literal = json.dumps(str(marker))
    cases.append({"name": "rejection-before-producer-effect", "source":
                  f"let name = python^(open({marker_literal}, 'w').write('wrong'); __oval_result__ = 'x')_python\n"
                  "sql^(SELECT '$name';)_sql\n", "accept": False, "expected": None})
    git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, capture_output=True, text=True)
    report = {"schema": "ostadix.splice-contract-reproduction/v1", "ok": False,
              "source_commit": git.stdout.strip() if git.returncode == 0 else None,
              "source_dirty": bool(dirty.stdout.strip()) if dirty.returncode == 0 else None,
              "binary": identity(binary), "fixtures": identity(FIXTURES),
              "host": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
              "command_template": "O --json --executor EXECUTOR --eval SOURCE BACKENDS_DIR",
              "scope": "Hosted Python/SQLite/Bash exact review witnesses and migrations. Not arbitrary-language confinement, code sandboxing, native OS or all-ISA qualification.", "runs": []}
    run_cases(binary, backends, directory, cases, marker, args.timeout, report)
    print(json.dumps({"ok": report["ok"], "runs": report["asserted_runs"], "result": str(directory / "result.json")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
