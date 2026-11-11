#!/usr/bin/env python3
"""Compare declared-independent CI work through serial O, graph O and Python."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path("benchmarks/real_world/ci_shards.O")
FIXTURE_SHA256 = "c29037eee57201c519bfe59ff51dee1c1dcdef1ef0ba967ce5cdb6a21fa429ea"
SUITES = ("o-cli", "setup", "boot-iso")
ARMS = ("serial", "graph", "concurrent")
NOOP = "autonomous(batch(\nbash^(:)_bash,\nbash^(:)_bash,\nbash^(:)_bash\n))\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def object_value(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def identity(path: Path) -> dict:
    with path.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest}


def write_json(path: Path, data: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def extract_lanes(source: bytes) -> list[str]:
    if sha256(source) != FIXTURE_SHA256:
        raise ValueError("ci_shards fixture changed and requires a new source review")
    text = re.sub(r"\A(?:#[^\n]*\n)*", "", source.decode("utf-8"))
    parts = re.fullmatch(
        r"autonomous\(batch\(\nbash\^\((.*?)\)_bash,\nbash\^\((.*?)\)_bash,\nbash\^\((.*?)\)_bash\n\)\)\n",
        text, re.DOTALL,
    )
    if parts is None:
        raise ValueError("expected exactly three static Bash lanes")
    lanes = list(parts.groups())
    for body in lanes:
        if re.search(r"[A-Za-z_][A-Za-z0-9_]*\^\(|\)_bash|(?<!\\)\$[A-Za-z_!({]", body):
            raise ValueError("nested O or an unescaped foreign hole is unsupported")
    # Parser::parse_body decodes backslash-dollar and preserves other escapes.
    return [body.replace("\\$", "$") for body in lanes]


def validate_ci(artifacts: Path, outputs: list[str]) -> dict:
    entries = list(artifacts.iterdir())
    if {p.name for p in entries} != {name + ".log" for name in SUITES}:
        raise ValueError("CI artifact inventory has missing or extra entries")
    if any(p.is_symlink() or not p.is_file() for p in entries):
        raise ValueError("CI artifacts must be ordinary log files")
    if len(outputs) != len(SUITES):
        raise ValueError("expected three returned lane summaries")
    records = []
    for suite, output in zip(SUITES, outputs, strict=True):
        text = (artifacts / (suite + ".log")).read_text()
        counts = re.findall(r"^Ran ([0-9]+) tests? in [^\n]+$", text, re.MULTILINE)
        lines = [line for line in text.splitlines() if line.strip()]
        if (len(counts) != 1 or int(counts[0]) <= 0 or not lines
                or lines[-1] != "OK" or lines.count("OK") != 1
                or re.search(r"^(?:FAILED\b|ERROR:|FAIL:)", text, re.MULTILINE)):
            raise ValueError(f"CI shard has no unqualified positive test pass: {suite}")
        summary = f"suite={suite} tests={counts[0]} status=pass"
        if output.removesuffix("\n") != summary:
            raise ValueError(f"returned summary disagrees with actual log: {suite}")
        records.append({"suite": suite, "tests": int(counts[0]), "status": "pass"})
    return {"suites": records, "total_tests": sum(row["tests"] for row in records)}


def plan_operations(document: dict) -> tuple[list[int], dict]:
    document = object_value(document, "inspection")
    prediction = object_value(document.get("prediction"), "prediction")
    admission = object_value(document.get("admission"), "inspection admission")
    bindings = object_value(admission.get("bindings"), "inspection bindings")
    required_bindings = ("admission_sha256", "lowered_oir_sha256", "plan_sha256", "analyzed_graph_sha256")
    prediction_profile = {
        "schema": "oexec.schedule-prediction/v1", "status": "admitted-static",
        "provenance": "evidence-bound-admission", "model": "unit-cost-shim-hosted-tasks",
        "span_unit": "hosted-task-layers",
    }
    if (any(re.fullmatch(r"[0-9a-f]{64}", str(bindings.get(key))) is None for key in required_bindings)
            or document.get("schema") != "oexec.schedule-explanation/v2"
            or admission.get("schema") != "oexec.admission/v6"
            or any(prediction.get(key) != value for key, value in prediction_profile.items())
            or prediction.get("admission_sha256") != bindings.get("admission_sha256")
            or any(type(prediction.get(key)) is not int for key in ("task_count", "predicted_width", "predicted_span"))
            or [prediction.get(key) for key in ("task_count", "predicted_width", "predicted_span")] != [3, 3, 1]):
        raise ValueError("inspection did not admit the declared three-lane topology")
    layers = prediction.get("layers", [])
    if not isinstance(layers, list) or len(layers) != 1:
        raise ValueError("inspection omitted its unique task layer")
    layer = object_value(layers[0], "prediction layer")
    if type(layer.get("index")) is not int or layer["index"] != 1:
        raise ValueError("inspection task layer must have index one")
    operations = layer.get("operations")
    if not isinstance(operations, list) or len(operations) != 3 or any(not re.fullmatch(r"P(?:0|[1-9][0-9]*)", str(v)) for v in operations):
        raise ValueError("inspection omitted exact plan-node IDs")
    ids = [int(value[1:]) for value in operations]
    if len(set(ids)) != 3:
        raise ValueError("inspection repeats a plan-node ID")
    return ids, bindings


def validate_o(document: dict, arm: str, source_sha: str, plan: tuple, workers: int) -> tuple:
    document = object_value(document, "O result")
    if document.get("ok") is not True or document.get("failed_batch_members"):
        raise ValueError("O did not complete every declared lane")
    value = object_value(document.get("value"), "O batch value")
    if value.get("t") != "list" or not isinstance(value.get("v"), list) or len(value["v"]) != 3:
        raise ValueError("O returned a different batch shape")
    outputs = []
    for item in value["v"]:
        item = object_value(item, "O lane value")
        if item.get("t") == "text":
            text = object_value(item.get("v"), "O text").get("utf8")
        elif item.get("t") == "str":
            text = item.get("v")
        else:
            text = None
        if not isinstance(text, str):
            raise ValueError("O returned a non-text CI summary")
        outputs.append(text)
    evidence = object_value(document.get("execution_evidence"), "O execution evidence")
    admission = object_value(evidence.get("admission"), "O runtime admission")
    ids, bindings = plan
    if (evidence.get("execution_mode") != arm or evidence.get("source_sha256") != source_sha
            or admission.get("schema") != "oexec.admission/v6"
            or re.fullmatch(r"[0-9a-f]{64}", str(admission.get("admission_sha256"))) is None
            or admission.get("oir_sha256") != bindings.get("lowered_oir_sha256")
            or admission.get("plan_sha256") != bindings.get("plan_sha256")
            or admission.get("analyzed_graph_sha256") != bindings.get("analyzed_graph_sha256")):
        raise ValueError("O runtime evidence differs from inspected source/plan or requested executor")
    trace = object_value(evidence.get("trace"), "O trace")
    if trace.get("schema") != "ostadix.graph-execution-trace/v1" or not isinstance(trace.get("events"), list):
        raise ValueError("O omitted its complete graph trace")
    active, started, finished, ready = set(), set(), set(), set()
    peak = 0
    for event in trace.get("events", []):
        event = object_value(event, "trace event")
        node, kind = event.get("plan_node"), event.get("event")
        if node not in ids:
            continue
        if type(node) is not int:
            raise ValueError("trace plan-node IDs must be integers")
        if kind == "ready" and node not in ready:
            ready.add(node)
        elif kind == "started" and node in ready and node not in started:
            active.add(node)
            started.add(node)
            peak = max(peak, len(active))
        elif kind == "finished" and node in active and node not in finished:
            active.remove(node)
            finished.add(node)
        else:
            raise ValueError("duplicate, failed or incomplete admitted Bash lifecycle")
    if active or finished != set(ids) or peak > min(3, workers if arm == "graph" else 1):
        raise ValueError("admitted Bash trace is incomplete or exceeds its worker bound")
    return outputs, {"plan_node_ids": ids, "complete": True,
                     "peak_outstanding_admitted_bash_operations": peak,
                     "scope": "submission-to-semantic-settlement events, without process/CPU overlap timestamps"}


def concurrent_child(root: Path, directory: Path, bash: Path, workers: int, profile: str) -> dict:
    commands = extract_lanes((root / FIXTURE).read_bytes()) if profile == "ci" else [":"] * 3
    if profile == "startup":
        commands = []
    started = time.perf_counter_ns()
    lock, active, peak = threading.Lock(), set(), 0

    def lane(index: int) -> dict:
        nonlocal peak
        before = time.perf_counter_ns()
        with (directory / f"lane-{index}.stdout").open("wb") as stdout, (directory / f"lane-{index}.stderr").open("wb") as stderr:
            child = subprocess.Popen([str(bash), "-c", commands[index]], cwd=root,
                                     env=os.environ.copy(), stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr)
            with lock:
                spawned = time.perf_counter_ns()
                active.add(index)
                peak = max(peak, len(active))
            status = child.wait()
            with lock:
                reaped = time.perf_counter_ns()
                active.remove(index)
        return {"lane": index, "pid": child.pid, "returncode": status,
                "request_started_ns": before - started, "spawn_observed_ns": spawned - started,
                "reaped_ns": reaped - started, "wall_ns": reaped - before,
                "stdout": (directory / f"lane-{index}.stdout").read_text()}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        lanes = list(executor.map(lane, range(len(commands))))
    return {"ok": all(row["returncode"] == 0 for row in lanes), "lanes": lanes,
            "outputs": [row["stdout"] for row in lanes], "peak_observed_spawned_unreaped_bash_children": peak,
            "internal_wall_ns": time.perf_counter_ns() - started}


def measured(argv: list[str], directory: Path, environment: dict, timeout: int, root: Path) -> dict:
    started = time.perf_counter_ns()
    expired = threading.Event()
    record = {"argv": argv, "stdout": str(directory / "stdout"), "stderr": str(directory / "stderr")}
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "stdout").open("wb") as stdout, (directory / "stderr").open("wb") as stderr:
            child = subprocess.Popen(argv, cwd=root, env=environment, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            def terminate() -> None:
                expired.set()
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

            timer = threading.Timer(timeout, terminate)
            timer.daemon = True
            timer.start()
            try:
                # A blocking wait avoids timeout-wait polling quantizing short runs.
                record["returncode"] = child.wait()
            finally:
                timer.cancel()
                timer.join()
    except OSError as error:
        record.update(returncode=127 if isinstance(error, FileNotFoundError) else 126,
                      launch_error=str(error))
    record.update(timed_out=expired.is_set(), whole_process_wall_ns=time.perf_counter_ns() - started)
    return record


def source_identity(root: Path, output: Path) -> dict:
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root).split(b"\0")
    files = []
    for name in sorted(set(names) - {b""}):
        path = root / os.fsdecode(name)
        if path.is_relative_to(output):
            continue
        if not path.exists() and not path.is_symlink():
            files.append({"path": os.fsdecode(name), "state": "missing"})
            continue
        data = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        files.append({"path": os.fsdecode(name), "mode": path.lstat().st_mode,
                      "bytes": len(data), "sha256": sha256(data)})
    return {"head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
            "files": files, "content_manifest_sha256": sha256(json.dumps(files, sort_keys=True).encode())}


def run(args: argparse.Namespace) -> dict:
    root, output = args.root.resolve(), args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("evidence directory must be empty")
    for name in ("o_bin", "olangc_bin", "native_cli_bin"):
        path = getattr(args, name)
        if path is None or not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError(f"--{name.replace('_', '-')} must name an executable")
        setattr(args, name, path.resolve())
    source = (root / FIXTURE).read_bytes()
    extract_lanes(source)
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema": "ostadix.concurrent-ci-baseline/v1", "ok": False,
              "workers": args.workers, "binary_profile_declared": args.binary_profile,
              "fixture": identity(root / FIXTURE), "samples": [], "controls": [],
              "declaration": "The fixture declares three independent CI lanes with separate output logs. Python receives the same commands and declaration, without O admission.",
              "timing_scope": "Whole child process startup, work and teardown. O parsing/admission are included. Source inspection and independent artifact validation are timed separately, outside samples.",
              "evidence_cost_scope": "O admission and execution-trace construction/serialization run inside the timed O processes. Python records its own subprocess intervals without equivalent O authority or provenance. Source-file hashing is outside all timed arms.",
              "machine": {"platform": platform.platform(), "machine": platform.machine(),
                          "processor": platform.processor(), "logical_cpus": os.cpu_count()}}
    try:
        tools = {}
        for name in ("bash", "python3", "grep", "sed", "tail", "git"):
            found = shutil.which(name)
            if found is None:
                raise ValueError(f"required tool missing: {name}")
            tools[name] = identity(Path(found).resolve())
        report["tools"] = tools
        report["binaries"] = {name: identity(getattr(args, name)) for name in ("o_bin", "olangc_bin", "native_cli_bin")}
        report["harness"] = identity(Path(__file__).resolve())
        report["python_driver"] = dict(identity(Path(sys.executable).resolve()), version=sys.version)
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.is_file():
            match = re.search(r"(?m)^(?:model name|Hardware)\s*:\s*(.+)$", cpuinfo.read_text())
            report["machine"]["cpu_model"] = match.group(1) if match else "unreported"
        elif shutil.which("sysctl"):
            cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True)
            report["machine"]["cpu_model"] = cpu.stdout.strip() or "unreported"
        source_started = time.perf_counter_ns()
        before = source_identity(root, output)
        report["initial_source_evidence_ns"] = time.perf_counter_ns() - source_started
        write_json(output / "source-manifest.json", before)
        report["source_identity"] = {key: value for key, value in before.items() if key != "files"}
        env = os.environ.copy()
        for name in ("O_EXECUTOR", "O_GRAPH_WORKERS"):
            env.pop(name, None)
        env.update(O_LANG_NATIVE_CLI_BIN=str(args.native_cli_bin), PYTHONDONTWRITEBYTECODE="1")
        report["environment"] = {"removed": ["O_EXECUTOR", "O_GRAPH_WORKERS"],
                                 "inherited_names": sorted(env),
                                 "overrides": {"O_LANG_NATIVE_CLI_BIN": str(args.native_cli_bin), "PYTHONDONTWRITEBYTECODE": "1"}}
        programs = {"ci": root / FIXTURE, "noop": output / "noop.O"}
        programs["noop"].write_text(NOOP)
        plans = {}
        for profile, program in programs.items():
            command = [str(args.olangc_bin), str(program), "--target", "ir", "--explain-schedule", "--format", "json", "--workers", str(args.workers), "--shim-dir", str(root / "backends")]
            record = measured(command, output / (profile + "-inspection"), env, args.timeout, root)
            report.setdefault("inspections", []).append(record)
            if record["returncode"] != 0 or record["timed_out"]:
                raise ValueError("O schedule inspection failed")
            plans[profile] = plan_operations(json.loads(Path(record["stdout"]).read_text()))

        def arm(profile: str, name: str, directory: Path) -> dict:
            artifacts = directory / "artifacts"
            environment = dict(env, O_CI_OUT=str(artifacts))
            if name == "concurrent":
                command = [sys.executable, str(Path(__file__).resolve()), "--child", profile,
                           "--root", str(root), "--output", str(directory),
                           "--workers", str(args.workers), "--bash-bin", tools["bash"]["path"]]
            else:
                command = [str(args.o_bin), "--executor", name, "--workers", str(args.workers),
                           "--json", str(programs[profile]), str(root / "backends")]
            record = {"argv": command, "arm": name, "profile": profile, "ok": False,
                      "artifact_directory": str(artifacts),
                      "stdout": str(directory / "stdout"), "stderr": str(directory / "stderr")}
            try:
                artifacts.mkdir(parents=True)
                record.update(measured(command, directory, environment, args.timeout, root))
                if record["returncode"] != 0 or record["timed_out"]:
                    raise ValueError("benchmark child failed")
                document = object_value(json.loads(Path(record["stdout"]).read_text()), "child result")
                validation_start = time.perf_counter_ns()
                if name == "concurrent":
                    if document.get("ok") is not True or not 0 < document.get("peak_observed_spawned_unreaped_bash_children", 0) <= min(3, args.workers):
                        raise ValueError("concurrent child failed or exceeded its worker budget")
                    outputs = document["outputs"]
                    lanes = document.get("lanes")
                    if (not isinstance(outputs, list) or len(outputs) != 3
                            or any(not isinstance(value, str) for value in outputs)
                            or not isinstance(lanes, list) or len(lanes) != 3
                            or any(not isinstance(lane, dict) or lane.get("lane") != index
                                   or lane.get("returncode") != 0 for index, lane in enumerate(lanes))):
                        raise ValueError("concurrent child omitted complete successful lane records")
                    record["concurrency"] = document
                else:
                    outputs, record["concurrency"] = validate_o(document, name, sha256(programs[profile].read_bytes()), plans[profile], args.workers)
                    record["o_internal_elapsed_ms"] = document.get("elapsed_ms")
                if profile == "ci":
                    record["semantic_manifest"] = validate_ci(artifacts, outputs)
                    record["artifact_files"] = [identity(path) for path in sorted(artifacts.iterdir())]
                elif outputs != [""] * 3 or list(artifacts.iterdir()):
                    raise ValueError("no-op overhead control produced unexpected output")
                record["artifact_validation_ns"] = time.perf_counter_ns() - validation_start
                record["ok"] = True
            except (OSError, ValueError, KeyError, TypeError) as error:
                record.update(ok=False, error=str(error))
            try:
                write_json(directory / "record.json", record)
            except OSError as error:
                record.update(ok=False, record_write_error=str(error))
            return record

        for name, command in (("o", [str(args.o_bin), "version", "--json"]),
                              ("python", [sys.executable, str(Path(__file__).resolve()), "--child", "startup", "--root", str(root), "--output", str(output / "startup-python"), "--workers", str(args.workers), "--bash-bin", tools["bash"]["path"]])):
            record = measured(command, output / ("startup-" + name), env, args.timeout, root)
            report.setdefault("startup_probes", []).append(record)
            if record["returncode"] != 0 or record["timed_out"]:
                raise ValueError("startup probe failed")
        report["startup_probe_scope"] = "O version reporting versus Python imports/empty executor creation. No parser/admission equivalence is claimed."
        for name in ARMS:
            report["controls"].append(arm("noop", name, output / ("noop-" + name)))
        if not all(record["ok"] for record in report["controls"]):
            raise ValueError("no-op overhead control failed")
        for record in report["controls"]:
            record["whole_process_ns_per_noop_operation"] = record["whole_process_wall_ns"] / 3
        report["control_scope"] = "Three Bash ':' operations include process startup and O parsing/admission. Diagnostic only, never subtracted from useful-work timings."
        for ordinal in range(args.warmups + args.repetitions):
            phase = "warmup" if ordinal < args.warmups else "measured"
            order = ARMS[ordinal % 3:] + ARMS[:ordinal % 3]
            group = {"phase": phase, "ordinal": ordinal, "order": list(order), "arms": []}
            report["samples"].append(group)
            for name in order:
                group["arms"].append(arm("ci", name, output / f"{phase}-{ordinal + 1:03d}-{name}"))
            if not all(record["ok"] for record in group["arms"]):
                raise ValueError("a three-arm sample failed validation")
            manifests = [record["semantic_manifest"] for record in group["arms"]]
            if any(manifest != manifests[0] for manifest in manifests[1:]):
                raise ValueError("three-arm semantic manifests differ")
            write_json(output / "result.json", report)
        source_started = time.perf_counter_ns()
        after = source_identity(root, output)
        report["final_source_evidence_ns"] = time.perf_counter_ns() - source_started
        if after != before:
            raise ValueError("source changed during measurement")
        selected = [*report["binaries"].values(), *tools.values(), report["harness"], report["python_driver"]]
        for original in selected:
            current = identity(Path(original["path"]))
            if any(current[key] != original[key] for key in ("bytes", "sha256")):
                raise ValueError(f"selected executable changed during measurement: {original['path']}")
        report["selected_executables_unchanged"] = True
        measured_groups = [group for group in report["samples"] if group["phase"] == "measured"]
        report["measured_order_position_counts"] = {name: [sum(group["order"][position] == name for group in measured_groups) for position in range(3)] for name in ARMS}
        timings = {name: [next(row["whole_process_wall_ns"] for row in group["arms"] if row["arm"] == name) for group in measured_groups] for name in ARMS}
        report["statistics"] = {name: {"raw_whole_process_ns": values, "median_ns": statistics.median(values), "median_absolute_deviation_ns": statistics.median(abs(value-statistics.median(values)) for value in values), "min_ns": min(values), "max_ns": max(values)} for name, values in timings.items()}
        report["paired_geometric_mean_ratios"] = {f"{left}_over_{right}": math.exp(statistics.mean(math.log(a / b) for a, b in zip(timings[left], timings[right], strict=True))) for left, right in (("serial", "graph"), ("serial", "concurrent"), ("concurrent", "graph"))}
        report["ok"] = True
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    finally:
        write_json(output / "result.json", report)
    return report


def positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--o-bin", type=Path)
    parser.add_argument("--olangc-bin", type=Path)
    parser.add_argument("--native-cli-bin", type=Path)
    parser.add_argument("--binary-profile", choices=("release", "debug", "custom"), default="custom")
    parser.add_argument("--workers", type=positive, default=3)
    parser.add_argument("--repetitions", type=positive, default=7)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--timeout", type=positive, default=600)
    parser.add_argument("--child", choices=("ci", "noop", "startup"), help=argparse.SUPPRESS)
    parser.add_argument("--bash-bin", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.warmups < 0:
        parser.error("--warmups must be nonnegative")
    try:
        if args.child:
            if args.bash_bin is None:
                parser.error("child requires --bash-bin")
            result = concurrent_child(args.root.resolve(), args.output.resolve(), args.bash_bin.resolve(), args.workers, args.child)
            print(json.dumps(result))
        else:
            result = run(args)
            print(json.dumps({"ok": result["ok"], "report": str(args.output.resolve() / "result.json"), "error": result.get("error")}))
        return 0 if result["ok"] else 1
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
