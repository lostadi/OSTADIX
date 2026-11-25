# OSTADIX vs GraalVM polyglot: preliminary run (2026-11-24)

**Status: preliminary.** Recorded while the host was under unrelated load
(load average ~8 on 10 cores, Ollama llama-server active). Rerun on an idle
machine before citing: `python3 run.py <graalvm-java-home> 10`.

Environment: Apple M1 Max, macOS 26.5.2 arm64. OSTADIX `1f4576ae`
(CPython 3.12.16 + Node v26.13.1 backends). Oracle GraalVM JDK 25.0.4 with
org.graalvm.polyglot 25.0.4 python-community + js-community, JVM mode with
runtime compilation enabled (verified: no interpreter-only fallback warning).
GraalVM native-image tested separately below.

Each workload: a Python value is produced, then consumed by JavaScript.
Cold = one fresh process per run, end-to-end wall time, 10 rounds, systems
interleaved. Raw records: `results.json`.

## Cold (fresh process each run), median ms

| Workload | OSTADIX | GraalVM JVM | GraalVM / OSTADIX |
|---|---|---|---|
| w1 handoff (21 → JS, ×2) | 188.7 | 2572.3 | 13.6× |
| w2 compute (5M-iteration loop in each language) | 997.6 | 3109.5 | 3.1× |
| w3 data (200k-float list → JS sum) | 1882.3 | 2773.7 | 1.5× |

All 60 of these runs produced the correct output.

## Cold vs GraalVM native-image (added later the same evening), median of 5, ms

Native image built from the same GraalBench.java with python-community +
js-community 25.0.4 on the classpath (308 MB binary, 8 min build). Not
interleaved; host still under load.

| Workload | OSTADIX | GraalVM native-image | native / OSTADIX |
|---|---|---|---|
| w1 handoff | 164.7 | 66.2 | 0.40 |
| w2 compute | 986.8 | 766.1 | 0.78 |
| w3 data | 1874.2 | 193.5 | 0.10 |
| w4 fidelity | 295.8 | 96.2 | 0.33 |

GraalVM native-image was faster than OSTADIX on every workload. The JVM-mode
cold advantage comes from JVM startup, which native-image removes.

## Warm (GraalVM only, same Context, median of iterations 6–15), ms

| Workload | GraalVM warm |
|---|---|
| w1 handoff | 0.22 |
| w2 compute | 601.25 (≈340 on an earlier, less-loaded check) |
| w3 data | 19.23 |

OSTADIX has no in-process warm mode in this harness; each run is a full
program execution.

## Value fidelity (Python → JavaScript)

| Check | OSTADIX | GraalVM |
|---|---|---|
| `2**100` | JS `bigint`, exact | JS `typeof` = `number`; `String()` exact |
| `0.1 + 0.2` | `0.30000000000000004` | `0.30000000000000004` |
| `-0.0` | preserved | preserved |
| `float("nan")` | **rejected**: "unsupported numeric value … non-finite float … cannot cross as a JavaScript binding" (0/10) | `NaN` (10/10) |

## Reading

- Cold against GraalVM JVM mode, OSTADIX was faster on all three performance workloads (1.5×–13.6×,
  geometric mean ≈4×). The gap is dominated by JVM + polyglot context startup
  and shrinks as the workload grows.
- Warm, GraalVM is far faster (w1 ~850×, w3 ~100×, w2 ~1.7× against the OSTADIX
  cold total). Long-running or in-process polyglot use favors GraalVM.
- OSTADIX keeps Python's arbitrary-precision int as a JS BigInt; GraalVM
  exposes it as a JS number. OSTADIX fails to pass NaN to JavaScript.
- Against native-image, OSTADIX was slower on every workload (1.3x-9.7x).
- Not tested: other language pairs, fine-grained
  cross-language calls (GraalVM calls across languages in-process; OSTADIX
  crosses at block boundaries).
