# Measured fidelity results

Recorded on 2026-09-12 from the working tree based on `806399e7`, including
the accompanying crossing-propagation fix and evaluation tests.
Environment: macOS 15.7.7, Python 3.14.7, Node.js v26.7.0, rustc 1.97.1.

The complete structured reports emitted by the tests are retained in
[results.json](results.json). Their typed original/returned values, exact
CBOR payloads, runtime profile assessments, and known-value solver bounds
come from the successful run below. Map field order is not semantic.

```bash
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 OSTADIX_TEST_RUNTIME_POLICY=required cargo test --locked --test fidelity_evaluation --test backend_morphism_v1 -- --nocapture --test-threads=1
```

```text
Running tests/backend_morphism_v1.rs
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.60s

Running tests/fidelity_evaluation.rs
test cbor_preserves_float_but_javascript_crossing_changes_type_dispatch ... ok
test cbor_preserves_integer_but_javascript_crossing_changes_parity ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.15s
```

Debug information and incremental caching were disabled for this run after
the default build exhausted local disk space. Both witnesses ran on both
executors; neither test skipped a runtime. These durations are test-suite
durations, not a performance comparison.

| Observation | Float witness | Integer witness |
| --- | --- | --- |
| Original | binary64 `1.0` | integer `9007199254740993` |
| Returned | integer `1` | integer `9007199254740992` |
| Ordinary scalar CBOR exact | true | true |
| Tagged OValue CBOR exact | true | true |
| Graph and serial results equal | true | true |
| Numeric equality before/after | true | false |
| Downstream behavior before → after | float branch → integer branch | odd → even |
| Runtime JavaScript profile | Structural: TypeTag, NumericExactness | OutsideProfile: IntegerOutOfRange |
| Known-value accumulated verdict | Structural | Structural |

The known-value graph reports equal definite and possible sets in these
concrete cases. The float set is `{TypeTag, NumericExactness}`; the integer
set additionally contains `NumericPrecision`. The second crossing's local
assessment is `Lossless` in both cases, but its accumulated assessment
retains the first crossing's losses. The runtime observation and known-value
graph are separate evidence, with the scope explained in [README.md](README.md).

Related validation passed in the same working tree:

```text
cargo test --locked -p ostadix-api --lib value::tests::fidelity_v2_
24 passed; 0 failed

cargo test --offline --locked -p ostadix-api --lib hgraph::
53 passed; 0 failed

cargo test --offline --locked -p ostadix-api --lib evidence::
47 passed; 0 failed
```

The evaluation test also passed Clippy with `-D warnings`, using the same
reduced debug settings, and formatting/diff whitespace checks passed.

The solver regression covers all six insertion orders of crossing →
dataflow → crossing, including abstract must/may precision and a concrete
large integer. Before the fix it reproduced loss erasure as `Lossless`.
The admission regression starts with parsed `.O` source, builds its canonical
plan, checks the accumulated V2 fact in V6 admission, and rejects an attempt
to replace that fact with `Lossless`.

Both `.O` files also passed `O --check --json`, and `olangc --target ir`
produced the type witness's OIR, ExecutionPlan, and HGraph with explicit
binding dependencies. This does not claim that static analysis infers the
concrete result of opaque Python code.
