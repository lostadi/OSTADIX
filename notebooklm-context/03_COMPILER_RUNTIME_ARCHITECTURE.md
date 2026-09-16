# Compiler and runtime architecture

## Crate boundary

The Rust workspace has two packages at version `0.4.0`:

- `crates/ostadix-api` is the independently packageable runtime engine. It owns
  the parser, IR, evaluator, OValue, backend catalog/state, HGraph, evidence,
  admission, executor, projects, placement, hosted remote protocols,
  Information, World records, live system, and O-core compiler modules.
- root package `o-lang` is the compatibility and CLI shell. Its library
  reexports the engine's historical module paths and its binaries expose user
  entry points.

The dependency direction is frozen: `o-lang -> ostadix-api`. The engine must
not depend on the shell. The reexports preserve the same nominal Rust types;
there is not a second evaluator, registry, OValue, or admission compiler in the
root crate.

Primary sources: `Cargo.toml`, `crates/ostadix-api/Cargo.toml`,
`crates/ostadix-api/src/lib.rs`, `src/lib.rs`, `ARCHITECTURE.md`, and
`ci/architecture-roots.toml`.

## Hosted compilation and execution pipeline

Every authoritative Rust hosted entry point follows the same semantic path:

```text
.O bytes
  -> parser / ONode syntax forest
  -> lowering / OIrProgram
  -> validated ExecutionPlan
  -> directed HGraph projection and constraint solve
  -> EvidenceBundleV6
  -> AdmittedExecutionV6
  -> graph coordinator or serial differential oracle
  -> OValue + trace/observation
```

This path is used by the interpreter, REPL, notebook cells,
`olangc --target script`, linked execution, generated hosted binaries, and
source fragments executed by `O.eval`. Production execution does not directly
interpret ONode syntax.

Primary sources: `SPEC.md` section 2.5, `ARCHITECTURE.md` “Evaluation
Pipeline,” and `crates/ostadix-api/src/eval.rs`.

## Stage 1: parse

The parser recognizes registered typed-expression delimiters, aliases,
environment markers, attributes, bindings, variable references, special
calls, source locations, and nested body structure. `ONode` is syntax only.

Parser dependencies are intentionally narrow. The syntax dialect exposes the
registered/canonical spelling and quoted-body behavior needed to recognize
typed regions without making the parser own backend execution.

Key sources:

- `crates/ostadix-api/src/parser.rs`
- `crates/ostadix-api/src/syntax_dialect.rs`
- `tests/parser_proptest.rs`
- `fuzz/fuzz_targets/`

## Stage 2: lower to OIR

`crates/ostadix-api/src/ir.rs` owns the hosted executable representation.
Core OIR instructions are:

| Instruction | Meaning |
|---|---|
| `Text` | Literal body text. |
| `Load` | Read a visible O-scope binding. |
| `Store` | Bind a computed OValue. |
| `Invoke` | Apply an O-level builtin or policy/special form. |
| `Exec` | Execute/render a typed backend region. |

Each `Exec` embeds a `BackendInterface` containing the canonical backend,
purity, renderer, execution mode, required authority, adapter identity, and
other catalog-derived behavior. Each `Invoke` embeds an `InvokeMode` such as
eager, lazy, autonomous, or a group mode. Dispatch policy is therefore frozen
during lowering instead of rediscovered from an independent backend-name table
at runtime.

OIR is recursive and lexical, not SSA. It intentionally retains special
regions such as `O`, `quote`, `lazy`, `autonomous`, and coordination groups.

## Stage 3: build and validate ExecutionPlan

The plan assigns stable identities and records three main dependency types:

- structural edges: child result before parent;
- sequence edges: required source order; and
- data edges: a `Load` depends on the latest visible `Store`.

Validation rejects invalid identities, out-of-range edges, duplicated or
missing roots, and cycles. The evaluator obtains both root and direct-child
orders from this plan.

Planning is non-executing. `olangc FILE.O --target ir` exposes this layer and
the graph derived from it.

## Stage 4: project and solve the HGraph

OIR is projected into a directed execution hypergraph. An executable edge can
consume multiple inputs and produce multiple outputs. Its outputs include:

- one distinguished OValue;
- one successful-completion token; and
- successor versions for every stateful resource it changes.

Inputs can include ordinary data, completion dependencies, resource-state
versions, actor state, and later the materialized admission facts.

The graph solves type, representation, and fidelity constraints before
admission. Current graph identity is the solved executable Graph V2, whose
identity binds the complete canonical `FidelityAssessmentV2`. Graph V1 is
retained only for archival inspection and Execution Intent V1 identity.

Key sources:

- `crates/ostadix-api/src/hgraph/`
- `crates/ostadix-api/src/backend_morphism.rs`
- `tests/hgraph_ontology.rs`
- `tests/hgraph_schedule_proptest.rs`

## Resource ordering

The graph models state explicitly:

- a read consumes the latest writer-state version, does not create a new
  version, and places its completion in the resource's open-reader frontier;
- a write consumes the latest writer state and all open-reader completions,
  creates the next writer-state version, and clears the reader frontier.

This allows reads of one version to overlap while forcing a later writer to
wait. Alias expansion must occur before these dependencies are considered.

Arbitrary hosted source generally has an unknown effect footprint. It
therefore reads and writes the conservative `HostWorld` umbrella. Persistent
backend environments additionally serialize through
`ActorState(canonical-language[n])`. User declarations may add dependencies;
they may not erase unknown `HostWorld` effects or self-certify purity.

## Stage 5: analyze and admit

Pre-execution analysis emits Evidence V6 facts for each operation, including:

- type and fidelity;
- effect and resource footprint;
- dispatch/adapter policy;
- capability policy;
- placement facts;
- failure policy; and
- resource budget/demand vocabulary.

Evidence is digest-bound to the relevant canonical OIR, plan, solved graph,
analyzer identity, current backend-catalog projection, used backend artifacts,
direct executable manifest, execution environment, and descriptive ambient
World snapshot. Exact binding differs for entry points that receive source
versus already-lowered OIR; the specification states the limits explicitly.

Admission validates those facts and freezes an `AdmittedExecutionV6`. The
ordinary coordinator accepts only this current admitted type. It never accepts
a raw graph or archival V5 admission. Before an opaque/deferred launch, runtime
bindings are rechecked.

Evidence is not authority by itself. Admission is the local process contract
that permits this exact coordinator execution; it is not a generic remote
lease, Governor decision, or World membership.

Key sources:

- `crates/ostadix-api/src/evidence/analyze.rs`
- `crates/ostadix-api/src/evidence/admit.rs`
- `crates/ostadix-api/src/evidence/fact.rs`
- `docs/VERSIONING.md`
- `docs/SEMANTIC_CUSTODY.md`

## Backend executable binding

For plan-used shim backends, current admission resolves direct launcher paths,
hashes canonical targets, records file identity, and retains handles through
execution where supported. Dispatch consumes the admitted absolute path rather
than performing a fresh PATH search for a different candidate.

This is a bounded launcher-identity guarantee, not a frozen transitive
execution closure. It does not automatically freeze script interpreters,
dynamic libraries, compiler subtools, child processes launched by user code,
or in-place mutation. The specification also documents a final
verification-to-exec micro-window for path-based launch on some platforms.

## Stage 6: schedule and dispatch

The default `graph_executor` feature enables readiness-driven execution. An
operation becomes graph-ready when every input node is materialized, but
physical dispatch must also satisfy its admitted adapter and execution lane.
The coordinator owns semantic ordering, deterministic failure selection,
publication, resource-state transition, and settlement.

Current local worker behavior is deliberately narrower than “run everything
in parallel”:

- compiler-verified O-scope loads and source-proven trusted inline renderers
  can use the worker pool;
- explicitly autonomous, ephemeral, direct shim group members have a special
  unordered lane while retaining unknown-effect evidence;
- persistent environments, arbitrary declared reads, and most opaque hosted
  work remain coordinator-owned;
- coordinator-owned operations do not run concurrently with outstanding local
  worker tasks in the current bounded implementation.

The pool is per run and is sized from useful admitted wave width and available
parallelism unless a positive worker override is supplied. Static inspection
waves and worker counts are readiness/sizing descriptions, not proof of actual
overlap, backend readiness, CPU/memory fit, or placement.

The serial executor is a differential reference after the same admission. It
is not a bypass around Evidence V6/Admission V6.

Key sources:

- `crates/ostadix-api/src/executor/`
- `SPEC.md` section 2.5
- `tests/executor_*.rs`
- `tests/autonomous_hosted_parallel.rs`

## Stage 7: settle and observe

The coordinator selects deterministic semantic outcomes, materializes graph
values/completions/resource versions, and records trace events. A physically
completed result is not necessarily semantically published or settled. Later
work may be discarded when an earlier failure wins.

Post-execution runtime graphs, traces, receipts, and crossing evidence are
observations. They help prove what happened but do not retroactively become
pre-execution admission or authorize another run.

## Backend runtime protocol

The canonical catalog in `backend_catalog.inc.rs` is expanded into runtime
metadata and also reused by dependency-isolated tooling such as the MCP server.
It records canonical tags, aliases, purity, renderer, execution mode, required
authorities, adapter ownership, runtime alternatives, numerical preservation,
state support, and optional morphism profiles.

Hosted backend processes exchange length-prefixed canonical CBOR OValues.
Persistent processes are keyed by logical backend environment, authority
policy, and current admitted launch generation so reuse cannot cross a changed
authority or executable generation.

Key sources:

- `crates/ostadix-api/src/backend_catalog.inc.rs`
- `crates/ostadix-api/src/backend.rs`
- `crates/ostadix-api/src/backend_state.rs`
- `crates/ostadix-api/src/wire.rs`
- `crates/ostadix-api/src/shims.rs`
- `backends/`

## Separate native pipeline

The O-core compiler lives under `crates/ostadix-api/src/ocore/` and uses:

```text
lexer/parser -> AST -> name-resolved typed HIR -> SSA MIR -> target codegen
```

It does not lower to hosted OIR. See `06_OCORE_KERNEL_AND_WORLD.md` for the
native contract and limitations.

## Architectural enforcement

`scripts/check_architecture_boundaries.py` and
`ci/architecture-roots.toml` make root ownership and permitted cross-root
dependencies executable repository contracts. The check verifies physical
module mapping, compatibility facades, one-way package dependency, declared
roots/edges, and root-level acyclicity. A root-level acyclicity result is not a
claim that every source file is acyclic after macro expansion.
