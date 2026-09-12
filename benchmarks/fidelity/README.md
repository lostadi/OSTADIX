# Fidelity evaluation: transport success can hide semantic loss

These are semantic counterexamples, not performance benchmarks. Both run a
real `.O` ExecutionPlan through Python → JavaScript → Python and observe a
different downstream decision after an identity-style JavaScript
`console.log` crossing.

| Witness | Python value before / after | Downstream observation | Known-value capability assessment |
| --- | --- | --- | --- |
| [type_tag.O](type_tag.O) | float `1.0` / integer `1` | Numeric equality passes; type dispatch changes from `float branch` to `integer branch` | Structural: definite and possible `TypeTag`, `NumericExactness` |
| [integer_precision.O](integer_precision.O) | `9007199254740993` / `9007199254740992` | Oddness changes from true to false | Structural: definite and possible `TypeTag`, `NumericPrecision`, `NumericExactness` |

The ordinary scalar CBOR controls and tagged OValue CBOR controls preserve
both original values exactly. The ordinary scalar payloads are
`fb3ff0000000000000` (binary64 `1.0`) and `1b0020000000000001`
(integer `9007199254740993`). Thus a successful CBOR round-trip check alone
does not establish preservation through a subsequent host-language adapter.
CBOR causes neither loss here. No claim about the WebAssembly canonical ABI
is made by these experiments.

## Reproduce

From the checkout containing this work, with Python 3 and Node.js available:

```bash
cargo build --locked --bin O --bin olangc
target/debug/O --check --json benchmarks/fidelity/type_tag.O
target/debug/O --check --json benchmarks/fidelity/integer_precision.O
target/debug/olangc benchmarks/fidelity/type_tag.O --target ir --shim-dir backends
target/debug/O --crossing-evidence benchmarks/fidelity/type_tag.O backends
target/debug/O --crossing-evidence benchmarks/fidelity/integer_precision.O backends
OSTADIX_TEST_RUNTIME_POLICY=required cargo test --locked --test fidelity_evaluation -- --nocapture --test-threads=1
```

The `.O` files use explicit `$original` and `$crossed` splices, so their
dependencies appear in the execution graph. Python returns through
`__oval_result__`. The test runs both graph and serial executors, compares
their typed results, checks both CBOR controls, verifies runtime observation
digests and input/result witnesses, and checks accumulated fidelity after
the return crossing. `required` makes a missing runtime fail instead of
silently skipping the experiment. The test prints a structured report for
each case, including the exact CBOR bytes and loss bounds.

## What the evidence establishes

The JavaScript adapter renders OValue numbers as JavaScript numeric source
and lifts scalar stdout back into OValue. JavaScript's binary64 Number
cannot distinguish the two adjacent integers in the precision witness.
For the type witness, stdout `1` lifts as an integer, losing the original
float tag even though numeric equality survives. The final Python block
observes these changes through ordinary type dispatch or parity.

The narrow runtime morphism profile and the capability solver are distinct:
the float witness is within the JavaScript profile and receives a structural
V2 assessment. The large integer is outside that profile and receives
`IntegerOutOfRange`; the capability solver independently reports structural
precision loss. The test checks both responses, rather than treating an
out-of-profile observation as a successful morphism proof.

The precise loss bounds printed under `known-value crossing graph` are
computed by the production HGraph solver using the original and returned
values checked against actual execution. This is a concrete witness graph,
not a claim that static analysis evaluates arbitrary Python source. The
source plan can have `Unsupported` assessments for opaque backend results.
The later JavaScript → Python leg is locally `Lossless`; its accumulated
assessment must still retain the preceding structural loss. A regression
in that wiring makes these tests fail.

Current admission binds and validates V2 facts; it does not automatically
reject every lossy crossing. The examples intentionally complete, making
the changed behavior observable. Neither the assessment nor its proof
restores lost information. These two cases are counterexamples to relying
on transport round-trip success alone, not a coverage or accuracy study
of every backend or every annotation kind.

The domain/order proof and its scope are in
[fidelity-domain.md](../../docs/fidelity-domain.md). Measured local results
are recorded in [RESULTS.md](RESULTS.md).
