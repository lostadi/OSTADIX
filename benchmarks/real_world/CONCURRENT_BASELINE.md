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
