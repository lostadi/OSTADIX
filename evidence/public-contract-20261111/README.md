# Reproduce the value/code boundary witnesses

This is a bounded, hosted Python/SQLite/Bash experiment. It distinguishes
ordinary values from explicit code generation; it is not a sandbox for guest
code or a universal foreign-language confinement theorem.

From a Linux checkout with `/proc`, Python 3.10+, Bash, SQLite and the repository
toolchain, build and run the actual evaluator:

```sh
cargo build --locked --package o-lang --bin O
python3 scripts/reproduce_splice_contract.py \
  --o-bin target/debug/O --backends-dir backends \
  --output-dir target/splice-reproduction
```

Use a new output directory for each run. A missing engine, timeout, unexpected
success/failure, changed value or executed producer marker fails the run.
The harness retains every program, stdout/stderr, executable/input digests,
source coordinate, dirty-tree status and per-case result. `result.json` must
have `ok: true`; an output directory alone is not a passing result.

The [seven original witnesses](../../tests/fixtures/foreign-splice-witnesses.json)
are unchanged. The quoted O holes in SQL, Bash and Python are now rejected;
the apostrophe SQL migration is `SELECT $name`, without guest quotes. Bash
native `"${s}"` remains guest variable syntax. Four corrected SQL value cases
include the original injection text and semicolons/newlines. A producer that
would write a file demonstrates rejection before that producer executes.
Both serial and graph paths run every case.

The broader Rust gate additionally exercises deterministic adversarial strings,
JavaScript/Nix value profiles, direct OIR ingress and explicit code authority:

```sh
OSTADIX_TEST_RUNTIME_POLICY=required cargo test --locked --package o-lang \
  --test foreign_splice_contract -- --test-threads=1
```

That gate requires the declared native hosted tools, including Node and Nix;
missing required prerequisites are errors. These host tests do not qualify
original runtime lowering, physical hardware, or other ISAs.

The alternate-edition gate builds the actual C17 interpreter and compiler in
its own cache, executes the Python reference and original shipped engines, and
tests direct AST entry and generated-program contract checks:

```sh
OSTADIX_TEST_RUNTIME_POLICY=required python3 -m unittest -v \
  tests.test_edition_splice_contract
```

It also requires a C17 compiler, Node and Nix. These editions have separate
carriers and execution policies; their passing tests do not establish Rust
admission, trace or general deadline equivalence. The unchanged legacy C++
prototype is outside this gate.

The [historical pre-fix observations](baseline-observations.json) identify the frozen executable separately
from the `1da570dc` source/backends coordinate. Keep their original failures
and timeouts; they are not current validation results. Public CI artifacts
attach new runs to their actual source SHA. See the
[current contract](../../docs/CURRENT_CONTRACT.md) and
[focused note](../../docs/research/fidelity-boundaries.md).

The versioned external publication location for this candidate is
[the public-contract evidence index](https://leeostadi.com/s/ostadix-public-contract-20261111-r1/).
Its manifest identifies the source commit, exact commands, original failures,
completed results and artifact hashes. An absent bundle or a report without a
successful result is not qualification. Public CI retains a separate artifact
for its exact Git source SHA and run attempt; the external index preserves the
source-bound bundle beyond CI artifact retention.
