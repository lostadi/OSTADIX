#!/usr/bin/env python3
"""OSTADIX vs GraalVM polyglot comparison driver.

Cold: one fresh OS process per run, end-to-end wall time, the two systems
interleaved round by round. Warm (GraalVM only): repeated evaluation inside
one Context; OSTADIX has no comparable in-process warm mode in this harness.
Every run's output is checked against the expected value; a mismatch or
failure is recorded, never dropped.

Usage: run.py GRAALVM_JAVA_HOME [ROUNDS]
"""
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Portable: O_LANG_ROOT / O_BIN / O_BACKENDS_DIR from the environment, else
# the O on PATH, else this checkout's own tree.
ROOT = Path(os.environ.get("O_LANG_ROOT") or HERE.parents[1])
O_BIN = Path(os.environ.get("O_BIN") or shutil.which("O") or ROOT / "target" / "release" / "O")
BACKENDS = Path(os.environ.get("O_BACKENDS_DIR") or ROOT / "backends")
NATIVE = HERE / "graal" / "native" / "graalbench"

WORKLOADS = {
    "w1_handoff": "42",
    "w2_compute": "19999998",
    "w3_data": "9999950000",
    "w4_fidelity": "bigint|1267650600228229401496703205376|0.30000000000000004|true",
    "w5_nan": "true",
}


def last_line(text):
    lines = [l for l in text.strip().splitlines() if l.strip()]
    return lines[-1].strip() if lines else ""


def normalize(out):
    # O prints a typed result header such as "[number] 42".
    return out.split("] ", 1)[1] if out.startswith("[") and "] " in out else out


def run(cmd, env=None):
    t0 = time.perf_counter()
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=HERE)
    wall = (time.perf_counter() - t0) * 1000
    return p.returncode, wall, p.stdout, p.stderr


def main():
    java_home = Path(sys.argv[1])
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    java = java_home / "bin" / "java"
    jflags = ["--enable-native-access=org.graalvm.truffle", "--module-path", "lib",
              "--add-modules", "org.graalvm.polyglot", "-cp", "classes", "GraalBench"]
    oenv = dict(os.environ, O_BACKENDS_DIR=str(BACKENDS))

    systems = {
        "ostadix": lambda w: run([str(O_BIN), str(HERE / "ostadix" / f"{w}.O"), str(BACKENDS)], oenv),
        "graalvm": lambda w: _graal(java, jflags, w),
    }
    if NATIVE.exists():
        systems["graalvm_native"] = lambda w: run([str(NATIVE), w])

    records = []
    for r in range(rounds):
        for w, expected in WORKLOADS.items():
            order = list(systems) if r % 2 == 0 else list(reversed(list(systems)))
            for s in order:
                code, wall, out, err = systems[s](w)
                got = normalize(last_line(out))
                records.append({
                    "round": r, "workload": w, "system": s, "exit": code,
                    "wall_ms": round(wall, 2), "output": got,
                    "correct": code == 0 and got == expected,
                    "error": None if code == 0 else last_line(err.replace("WARNING", ""))[:300]
                    or err.strip().splitlines()[0:3],
                })
        print(f"round {r + 1}/{rounds} done", file=sys.stderr)

    warm = {}
    for w in WORKLOADS:
        code, _, out, err = _graal(java, jflags, w, repeats=15)
        iters = [float(l.split()[2]) for l in err.splitlines() if l.startswith("iter ")]
        warm[w] = {"exit": code, "iters_ms": iters,
                   "steady_median_ms": round(statistics.median(iters[5:]), 2) if len(iters) > 5 else None}

    summary = {}
    for w in WORKLOADS:
        for s in systems:
            rs = [x for x in records if x["workload"] == w and x["system"] == s]
            ok = [x["wall_ms"] for x in rs if x["correct"]]
            walls = sorted(x["wall_ms"] for x in rs)
            summary[f"{s}:{w}"] = {
                "runs": len(rs), "correct": len(ok),
                "median_ms": round(statistics.median(walls), 1),
                "min_ms": walls[0], "max_ms": walls[-1],
                "outputs": sorted({x["output"] for x in rs}),
                "errors": sorted({str(x["error"]) for x in rs if x["error"]}),
            }

    def ver(cmd):
        p = subprocess.run(cmd, capture_output=True, text=True)
        return (p.stdout + p.stderr).strip().splitlines()[0] if (p.stdout + p.stderr).strip() else ""

    env_info = {
        "host": platform.platform(), "machine": platform.machine(),
        "cpu": ver(["sysctl", "-n", "machdep.cpu.brand_string"]),
        "ostadix_commit": ver(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "ostadix_python": ver(["python3", "--version"]),
        "o_bin": str(O_BIN),
        "graalvm_native": NATIVE.exists(),
        "node": ver(["node", "--version"]),
        "graalvm_java": ver([str(java), "-version"]),
        "polyglot_artifacts": "org.graalvm.polyglot 25.0.4 (python-community, js-community)",
        "rounds": rounds,
    }
    result = {"env": env_info, "summary": summary, "graal_warm": warm, "records": records}
    (HERE / "results.json").write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({"env": env_info, "summary": summary,
                      "graal_warm_steady_median_ms": {w: v["steady_median_ms"] for w, v in warm.items()}},
                     indent=1))


def _graal(java, jflags, w, repeats=1):
    cmd = [str(java), *jflags, w] + ([str(repeats)] if repeats > 1 else [])
    t0 = time.perf_counter()
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=HERE / "graal")
    wall = (time.perf_counter() - t0) * 1000
    return p.returncode, wall, p.stdout, p.stderr


if __name__ == "__main__":
    main()
