#!/usr/bin/env python3
"""Opt-in integration gate for boxing.O on two disposable real mTLS nodes.

Run explicitly after installing/building the native tools:
    python3 tests/test_boxing_nodes.py
    python3 tests/test_boxing_nodes.py --probe-only
    python3 tests/test_boxing_nodes.py --bin-dir target/release

Only this script's child processes and newly created temporary files are owned.
The user's regular node configuration, keys, listeners, and daemon are untouched.
Evidence directories are retained in the system temporary directory after cleanup.
This proves two node processes on one host, not two physical devices.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import uuid


def checked(argv, env, cwd, timeout=30, stdin=None):
    result = subprocess.run(argv, input=stdin, env=env, cwd=cwd, text=True,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv}\n"
                           f"{result.stdout}\n{result.stderr}")
    return result


def stop_owned(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def text_value(value):
    if value.get("t") == "text":
        return value["v"]["utf8"]
    if value.get("t") == "str":
        return value["v"]
    raise RuntimeError(f"expected text OValue, got {value!r}")


def verify_match(directory, controllers):
    data = json.loads((directory / "match.json").read_text())
    assert data["schema"] == "ostadix.boxing.injury-replay/v1"
    result = data["result"]
    assert result["schema"] == "boxing.match/v1"
    assert result["status"] == "concluded", result
    assert result["error"] is None, result
    assert result["controllers"] == controllers, result
    assert result["winner"] in (None, "TITAN", "PHANTOM"), result
    assert result["method"] and result["method"] != "No official result", result
    assert result["engine_sha256"] == hashlib.sha256((directory / "engine.O").read_bytes()).hexdigest()
    assert (directory / "report.html").stat().st_size > 1000
    assert [frame["tick"] for frame in data["frames"]] == list(range(result["ticks"] + 1))
    assert data["frames"][-1]["match_over"] is True
    metric_keys = {metric["key"] for metric in data["metrics"]}
    for frame in data["frames"]:
        assert len(frame["fighters"]) == 2
        for index, side in enumerate(("red", "blue")):
            fighter = frame["fighters"][index]
            assert fighter["controller"] == controllers[side], fighter
            assert metric_keys <= fighter["injury"].keys(), fighter
            assert fighter["sprite"], fighter
    receipt_count = 0
    for tick in range(1, result["ticks"] + 1):
        snapshot_digests = set()
        for side, node_id in controllers.items():
            if node_id == "local":
                continue
            path = directory / "receipts" / f"{tick}-{side}.json"
            receipt = json.loads(path.read_text())
            assert receipt["schema"] == "ostadix.hosted-operation-receipt/v1", path
            assert receipt["node_id"] == node_id, path
            assert receipt["task_id"] == f"boxing-{result['match_id']}-{tick}-{side}", path
            assert receipt["outcome"]["status"] == "succeeded", path
            step = json.loads(text_value(receipt["outcome"]["value"]))
            assert step["schema"] == "boxing.fighter-step/v1", path
            assert step["match_id"] == result["match_id"], path
            assert step["tick"] == tick and step["side"] == side, path
            assert "fighter" in step and len(step["rope_impulses"]) == 3, path
            snapshot_digests.add(step["snapshot_sha256"])
            receipt_count += 1
        assert len(snapshot_digests) <= 1, (tick, snapshot_digests)
    assert not list(directory.glob("receipts/*.error.json"))
    return data, receipt_count


def without_controllers(frames):
    normalized = copy.deepcopy(frames)
    for frame in normalized:
        for fighter in frame["fighters"]:
            fighter.pop("controller", None)
    return normalized


def semantic_result(result):
    """Retain every scoring/policy field while removing per-run placement metadata."""
    return {key: value for key, value in result.items()
            if key not in ("match_id", "controllers", "output_dir")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--bin-dir", type=Path,
                        help="Directory containing native O, o-node, and octl; defaults to PATH")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--seconds", type=int, default=4)
    parser.add_argument("--seed", default="42")
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--probe-only", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    source = (args.source or root / "examples/boxing.O").resolve()
    binary_dir = args.bin_dir.resolve() if args.bin_dir else None
    commands = {}
    for name in ("O", "o-node", "octl", "ostadix-evaluator"):
        candidate = (binary_dir / name) if binary_dir else shutil.which(name)
        if name == "ostadix-evaluator" and (not candidate or not Path(candidate).is_file()):
            candidate = commands.get("O")
        if not candidate:
            raise RuntimeError(f"missing executable on PATH: {name}; use --bin-dir")
        commands[name] = str(Path(candidate).absolute())
    for path in commands.values():
        if not os.access(path, os.X_OK):
            raise RuntimeError(f"missing executable: {path}")
    fixture = Path(tempfile.mkdtemp(prefix="boxing-node-validation-")).resolve()
    print(f"BOXING_NODE_EVIDENCE={fixture}", flush=True)
    client_cwd = fixture / "client-work"
    client_cwd.mkdir()
    out_dir = fixture / "match-output"
    out_dir.mkdir()
    environment = os.environ.copy()
    for key in list(environment):
        if key.startswith("OSTADIX_BOXING_"):
            environment.pop(key)
    for key in ("OSTADIX_RUNTIME_PATH", "OLANG", "A18_WORK"):
        environment.pop(key, None)
    environment.update({
        "O_LANG_ROOT": str(root),
        "O_BACKENDS_DIR": str(root / "backends"),
        "PATH": (str(binary_dir) + os.pathsep if binary_dir else "") + environment.get("PATH", ""),
        "XDG_CONFIG_HOME": str(fixture / "client-config"),
        "XDG_STATE_HOME": str(fixture / "client-state"),
        "XDG_CACHE_HOME": str(fixture / "client-cache"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "RUST_LOG": "warn",
        "OSTADIX_BOXING_OCTL": commands["octl"],
    })
    evidence = {"schema": "boxing-two-node-validation/v1", "fixture": str(fixture),
                "source": str(source), "physical_devices": 1,
                "node_processes": 2, "transport": "tcp+tls1.3+mutual-x509",
                "nodes": {}, "probe_only": args.probe_only}
    processes = []
    logs = []
    try:
        for side in ("red", "blue"):
            node_id = f"boxing-fixture-{side}-{uuid.uuid4().hex[:10]}"
            node_root = fixture / side
            node_root.mkdir()
            pki = node_root / "pki"
            node_env = environment.copy()
            node_env.update({"XDG_CONFIG_HOME": str(node_root / "config"),
                             "XDG_STATE_HOME": str(node_root / "state"),
                             "XDG_CACHE_HOME": str(node_root / "cache"),
                             "BOXING_FIXTURE_NODE": node_id})
            checked([commands["o-node"], "pki", "init", "--directory", str(pki),
                     "--server-name", "localhost"], node_env, node_root)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            address = f"127.0.0.1:{port}"
            peer = fixture / "client-config/ostadix/peers" / node_id
            peer.mkdir(parents=True, mode=0o700)
            for name in ("ca.pem", "client-cert.pem", "client-key.pem"):
                destination = peer / name
                shutil.copyfile(pki / name, destination)
                destination.chmod(0o600)
            metadata = peer / "peer.json"
            metadata.write_text(json.dumps({
                "schema": "ostadix.lan-peer/v1", "node_id": node_id,
                "server_name": "localhost", "address": address,
                "service_port": port, "security_mode": "paired-public-key",
                "supports_v2": False,
            }), encoding="utf-8")
            metadata.chmod(0o600)
            stderr = (node_root / "node.stderr").open("wb")
            logs.append(stderr)
            process = subprocess.Popen([
                commands["o-node"], "serve", "--manual", "--node-id", node_id,
                "--runtime-binary", commands["ostadix-evaluator"],
                "--shim-dir", str(root / "backends"), "--bind", address,
                "--cert", str(pki / "node-cert.pem"),
                "--key", str(pki / "node-key.pem"),
                "--client-ca", str(pki / "ca.pem"),
            ], cwd=node_root, env=node_env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=stderr)
            processes.append(process)
            deadline = time.monotonic() + 20
            profile_args = [commands["octl"], "node", "profile", "--node", node_id,
                            "--address", address, "--connect-timeout-seconds", "1",
                            "--io-timeout-seconds", "1"]
            while True:
                response = subprocess.run(profile_args, env=environment, cwd=client_cwd,
                                          text=True, capture_output=True, timeout=5)
                if response.returncode == 0:
                    profile = json.loads(response.stdout)
                    if profile["node_id"] != node_id:
                        raise RuntimeError("unexpected node identity")
                    break
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"node failed readiness: {response.stderr}")
                time.sleep(0.05)
            probe_source = ('python^(\nimport os, json\n'
                            '__oval_result__ = json.dumps({"node": '
                            'os.environ["BOXING_FIXTURE_NODE"], "value": 42})\n)_python\n')
            probe = checked([
                commands["octl"], "node", "run", "--node", node_id,
                "--address", address, "--expected-catalog-sha256",
                profile["backend_catalog_sha256"], "--task-id", "boxing-probe-" + side,
                "--attempt-id", uuid.uuid4().hex, "-",
            ], environment, client_cwd, stdin=probe_source)
            receipt = json.loads(probe.stdout)
            payload = json.loads(text_value(receipt["outcome"]["value"]))
            if payload != {"node": node_id, "value": 42}:
                raise RuntimeError(f"node probe mismatch: {payload}")
            if receipt["source_sha256"] != hashlib.sha256(probe_source.encode()).hexdigest():
                raise RuntimeError("node probe source digest mismatch")
            (node_root / "probe-receipt.json").write_text(probe.stdout)
            evidence["nodes"][side] = {"id": node_id, "address": address,
                                       "pid": process.pid, "probe_passed": True,
                                       "catalog_sha256": profile["backend_catalog_sha256"]}
            environment["OSTADIX_BOXING_" + side.upper() + "_NODE"] = node_id
        if not args.probe_only:
            environment.update({
                "OSTADIX_BOXING_OUT": str(out_dir), "OSTADIX_BOXING_HEADLESS": "1",
                "OSTADIX_BOXING_SEED": args.seed,
                "OSTADIX_BOXING_ROUNDS": str(args.rounds),
                "OSTADIX_BOXING_ROUND_SECONDS": str(args.seconds),
            })
            evidence["source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            evidence["match_configuration"] = {key: value for key, value in environment.items()
                                                 if key.startswith("OSTADIX_BOXING_")}
            started = time.monotonic()
            with (fixture / "match.stdout").open("wb") as stdout, (
                    fixture / "match.stderr").open("wb") as stderr:
                match = subprocess.run([commands["O"], str(source), str(root / "backends")],
                                       env=environment, cwd=client_cwd, stdout=stdout,
                                       stderr=stderr, timeout=args.timeout)
            evidence["match_exit_code"] = match.returncode
            evidence["elapsed_seconds"] = round(time.monotonic() - started, 3)
            evidence["match_artifacts"] = [str(path.relative_to(fixture))
                                            for path in sorted(out_dir.rglob("*")) if path.is_file()]
            if match.returncode:
                raise RuntimeError(f"boxing exited {match.returncode}; see {fixture}/match.stderr")
            expected_controllers = {side: evidence["nodes"][side]["id"] for side in ("red", "blue")}
            remote_data, receipt_count = verify_match(out_dir, expected_controllers)
            evidence["remote_receipts_verified"] = receipt_count
            evidence["match_result"] = remote_data["result"]
            baseline_dir = fixture / "local-baseline"
            baseline_env = environment.copy()
            baseline_env.update({"OSTADIX_BOXING_RED_NODE": "local", "OSTADIX_BOXING_BLUE_NODE": "local",
                                 "OSTADIX_BOXING_OUT": str(baseline_dir)})
            with (fixture / "baseline.stdout").open("wb") as stdout, (
                    fixture / "baseline.stderr").open("wb") as stderr:
                baseline = subprocess.run([commands["O"], str(source), str(root / "backends")],
                                          env=baseline_env, cwd=client_cwd, stdout=stdout,
                                          stderr=stderr, timeout=args.timeout)
            if baseline.returncode:
                raise RuntimeError(f"local baseline exited {baseline.returncode}")
            local_data, _ = verify_match(baseline_dir, {"red": "local", "blue": "local"})
            assert without_controllers(remote_data["frames"]) == without_controllers(local_data["frames"]), "remote/local trajectories differ"
            assert remote_data["events"] == local_data["events"], "remote/local injury events differ"
            assert semantic_result(remote_data["result"]) == semantic_result(local_data["result"]), "remote/local semantic result differs"
            evidence["local_baseline_equivalence"] = "all fighter snapshots, injury events, scorecards, result"
        evidence["completed"] = True
    except Exception as error:
        evidence["completed"] = False
        evidence["error"] = str(error)
        raise
    finally:
        for process in reversed(processes):
            stop_owned(process)
        for log in logs:
            log.close()
        evidence["owned_nodes_reaped"] = all(process.poll() is not None for process in processes)
        (fixture / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps(evidence, indent=2), flush=True)


if __name__ == "__main__":
    main()
