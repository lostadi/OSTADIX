# Concurrent CI baseline

`scripts/benchmark_concurrent_baseline.py` compares three execution paths over
the exact three Bash commands in `ci_shards.O`. The fixture explicitly declares
independent test shards. Each arm writes its own `o-cli`, `setup` and `boot-iso`
logs, and receives the same front-door environment and worker budget.

The Python child dispatches these commands with `ThreadPoolExecutor`. Serial O
and graph O both perform their normal parsing and admission. Their complete
process startup, execution, trace serialization and teardown contribute to the
measured wall time. The Python process startup, imports, pool and Bash children
also contribute to its wall time. Python receives the fixture's independence
declaration directly. O additionally records its admission and execution trace.

Run from a checkout with Python 3.11+, Bash, Git, Python's unittest module,
`grep`, `sed` and `tail`. Build matching O, `olangc` and native `o-cli` binaries
first. Their exact hashes and the declared build profile enter the report.

```sh
python3 scripts/benchmark_concurrent_baseline.py \
  --o-bin target/release/O \
  --olangc-bin target/release/olangc \
  --native-cli-bin target/release/o-cli \
  --binary-profile release \
  --workers 3 --warmups 1 --repetitions 7 \
  --output /path/to/empty-evidence-directory
```

Repeat with `--workers 1` and a fresh output directory for a capacity control.
All arms share this limit. The three cyclic execution orders rotate across
samples. Seven measured repetitions give position counts of 3/2/2, recorded
for each arm. A multiple of three repetitions gives equal position counts.
Validated warmups are retained and excluded from the reported ratios.

The output directory preserves each command, exit code, raw stdout/stderr,
full logs, semantic manifests and raw whole-process times. Independent log
validation requires exactly the three expected files, one positive `Ran N`
summary per file, one terminal exact `OK`, and matching returned suite counts.
Skipped, expected-failure, missing, extra and corrupt results fail validation.
Each three-arm sample must produce an identical semantic manifest. A failed
sample retains all three arms and produces a failed report without performance
statistics. Selected source and executable identities are checked again at
completion.

Inspection runs outside the sample timer and binds the three task PlanNodeIds
to the runtime OIR/plan identities. Runtime traces must contain complete,
successful lifecycle events for those exact nodes and respect the configured
worker bound. The reported peak counts outstanding admitted Bash operations
between submission and semantic settlement. Baseline subprocess timestamps
separately count spawned, unreaped children. These measurements describe their
respective lifecycle boundaries. Physical CPU overlap needs additional evidence.

Startup probes record O version reporting and Python imports/empty executor
creation with their distinct scopes. A separate three-operation Bash `:`
control records whole-process cost, including O parsing/admission. Its per-op
field divides this total by three. It measures an amortized control cost with
startup included. Control times are kept separate from useful-work times.

The report provides raw samples, median, median absolute deviation, extrema
and paired geometric mean ratios for serial/graph, serial/concurrent and
concurrent/graph. Ratios are descriptive for the recorded machine, source,
tools, binaries, environment and workload. The harness applies correctness
gates throughout and leaves performance thresholds to the reader.

Fixture extraction accepts the reviewed SHA-256 embedded in the runner and
the exact three-lane static wrapper. It retains body newlines and decodes only
the O parser's backslash-dollar escape. A changed fixture requires another
source review. The focused harness tests use controlled child tools to test
failure handling. Actual workload qualification comes from the retained logs
of a completed run against the selected O binaries.

## Retained public CI results (2026-11-11)

The completed F and H benchmark jobs retained the same reviewed three-lane
fixture. Both complete CI runs failed; their MCP jobs, including the benchmark
steps, passed. These are benchmark results for the exact source checkpoints
below, not whole-CI, native OS or original-runtime qualification.

- F: source `1e060cde0a9f7da653661a766ea9c4db8a9cfef7`,
  [CI run 43002945659](https://github.com/lostadi/OSTADIX/actions/runs/43002945659)
  (failed),
  [MCP job 130464074291](https://github.com/lostadi/OSTADIX/actions/runs/43002945659/job/130464074291)
  (passed). Artifact `13849030300`, ZIP SHA-256
  `b5839216cd1f7915b4cf6b5067eb57812dfb4042c764a531be14fdaadf30bb98`.
- H: source `4ddaafc1fba74f9b390b6677af7cf1eef5f9781f`,
  [CI run 43005360267](https://github.com/lostadi/OSTADIX/actions/runs/43005360267)
  (failed),
  [MCP job 130472618441](https://github.com/lostadi/OSTADIX/actions/runs/43005360267/job/130472618441)
  (passed). Artifact `13849048754`, ZIP SHA-256
  `6ad0ff4aa16f24a15fefa93de3cd3316d9f69f896a1695a7a0528f6a165e073b`.

Both jobs used release binaries and the pinned Rust 1.97.1 CI toolchain. The
recorded host was Linux x86_64, with four logical CPUs on an AMD EPYC 7763
64-Core Processor, glibc 2.43 and Python 3.14.4. The JSON record retains the
exact platform string and selected binary, Python and command-tool hashes.
The binary bytes are not included in the ZIPs; their identities are recorded
by the CI harness and checked again at measurement completion.

Each worker profile retained one validated warmup and seven measured rounds,
with serial O, graph O and matched concurrent Python in each round. Every arm
invocation passed 103 unskipped tests: 23 `o-cli`, 42 `setup` and 38 `boot-iso`.
Each checkpoint therefore retained 48 arm invocations and 144 validated raw
suite logs. Independent artifact review checked all 3,543 source-manifest
files against the corresponding Git objects and recomputed the statistics.

Median whole-process wall time, in seconds:

| Checkpoint | Workers | Serial O | Graph O | Concurrent Python |
|---|---:|---:|---:|---:|
| F | 3 | 9.060721 | 6.286905 | 6.332941 |
| F | 1 | 8.818821 | 8.871311 | 8.926045 |
| H | 3 | 8.153761 | 5.777846 | 5.826227 |
| H | 1 | 8.156919 | 8.126664 | 8.160221 |

Paired geometric mean wall-time ratios, computed from the seven matched
measured rounds:

| Checkpoint | Workers | Serial / graph | Serial / Python | Python / graph |
|---|---:|---:|---:|---:|
| F | 3 | 1.437555 | 1.429341 | 1.005746 |
| F | 1 | 0.996440 | 0.988589 | 1.007941 |
| H | 3 | 1.405428 | 1.401251 | 1.002981 |
| H | 1 | 1.001892 | 1.000809 | 1.001082 |

Graph O and matched concurrent Python are near parity in these records. The
one-worker controls also keep the three paths close. F and H remain separate
observations with their own source and executable identities; the table does
not attribute their timing difference to a source change or establish general
performance superiority.

These times include complete child-process startup, work and teardown. O
parsing, admission and trace construction/serialization are included; Python
does not perform equivalent O authority or provenance work. Source inspection
and independent log validation are outside the sample timer, and the separate
startup/no-op controls are not subtracted. Graph traces show peaks of three
outstanding admitted Bash operations with three workers and one with one
worker. Those peaks describe admission-to-settlement overlap, not physical
CPU overlap. Python's spawned/unreaped child intervals use their own lifecycle
boundary.

[The F/H JSON record](results-F-H-20261111.json) preserves every measured
nanosecond sample, median absolute deviation, extrema, paired ratio, selected
identity and artifact binding. Raw logs remain in the exact CI artifacts;
they are not copied into the source tree. No measurements were rerun to
prepare this dated record.
