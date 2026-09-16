# JavaScript backend runtime benchmark

This bounded benchmark measures the current hosted JavaScript adapter at three
scales without network access, user-file access, sleeps, or retained runtime
state across O invocations:

| Case | Work performed | Expected result |
| --- | --- | ---: |
| `javascript_cold1` | One operation in a fresh O process, evaluator, native backend proxy, and Node.js process | `1` |
| `javascript_warm10` | Ten dependency-ordered operations in one O evaluator and persistent environment-0 native proxy | `10` |
| `javascript_output_1mib` | One operation returning exactly 1 MiB of UTF-8 text | Length `1,048,576`, SHA-256 oracle |

“Warm” means repeated operations inside one O evaluator and its persistent
native `O --o-backend javascript` proxy for environment 0. JavaScript is marked
`NativeRust` in the compiled backend catalog: the proxy creates a temporary
`.js` file and launches a fresh Node.js process for each operation. The bundled
[`javascript_shim.py`](../../backends/javascript_shim.py) is a compatibility /
archive implementation and is not the hot path measured here. This benchmark
therefore exposes per-operation Node launch cost; it does not claim that a
JavaScript isolate is persistent. The preflight version probe also warms
executable filesystem pages, so `cold1` means a cold process boundary, not a
dropped operating-system page cache.

Every warmup and measured group must return the checked semantic oracle. The
runner cycles through all six case-order permutations, applies a timeout to
every O child, owns each child process group so a timeout also terminates its
native proxy and Node descendants, and records raw wall-clock nanoseconds plus
O's diagnostic `elapsed_ms`.
Measured summaries contain the median and median absolute deviation. It also
reports the paired approximation `(warm10 - cold1) / 9`; that value amortizes
O/native-proxy startup but currently still includes a new Node process per additional
operation. The 1 MiB payload is checked in memory but never copied into the
benchmark result JSON; only its expected length and digest are retained.

## Run

Build the release evaluator, keep the host idle and thermally stable, then run:

```bash
cargo build --release --locked --package o-lang --bin O
python3 benchmarks/backend_runtime/run.py \
  --warmups 2 \
  --repetitions 9 \
  --timeout-seconds 120 \
  --output target/backend-runtime.json
```

`--o-bin` and `--backends-dir` select an immutable candidate binary and backend
tree. Their defaults are `target/release/O` (or `O_RELEASE_BIN`) and `backends`
(or `O_BACKENDS_DIR`). On a heterogeneous Android device, pin the complete
runner so the evaluator, native proxy, and Node inherit the same affinity:

```bash
taskset -c 7 python3 benchmarks/backend_runtime/run.py \
  --warmups 3 --repetitions 15 \
  --output target/backend-runtime-before.json
```

Repeat the identical command after the change and retain both JSON documents.
The result binds the runner, fixtures, O executable (which also supplies the
native proxy), Node executable, tool versions, Git state, CPU affinity,
governor, and every raw sample. It fails if a bound executable or fixture
changes during a run. When present, the checked-in Python compatibility files
are recorded separately for context and explicitly marked as not executed; they
are not timing inputs. No automatic speed threshold is applied because mobile
frequency and thermal state are not portable constants.

The small fixtures only compute integers and print their result; the bounded
large fixture emits an in-memory 1 MiB string. The adapter's own temporary
JavaScript source is created under the platform temporary directory and deleted
by the native proxy. The runner writes no persistent data unless
`--output` is explicitly supplied.

Exit status is `0` for a valid result and `2` for invalid input, timeout,
runtime failure, artifact drift, malformed output, or semantic divergence.
