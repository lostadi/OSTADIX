# Ostadix-lang system overview

## One-sentence definition

Ostadix-lang is a polyglot expression language and evidence-bound execution
runtime in which every hosted expression names its evaluator in the syntax,
and values cross language boundaries through one canonical tagged value model,
OValue.

The repository's canonical phrase is: **“The nesting is the interface.”**

The core expression shape is:

```O
LANG^( body )_LANG
```

For example:

```O
html^(
  <p>The answer is python^(
__oval_result__ = sum(x * x for x in range(10))
)_python.</p>
)_html
```

The inner Python expression runs first. Its result becomes an OValue. The HTML
backend decides how that OValue is represented in HTML. Language nesting is
therefore the composition interface rather than a separate pairwise FFI.

Primary sources: `README.md`, `SPEC.md`, `docs/AI_GUIDE.md`.

Project metadata: the repository is
`https://github.com/lostadi/Ostadix-lang`; the declared human author is Lee
Daghlar Ostadi; and the source license is `LGPL-2.1-only`. See `Cargo.toml`,
`ORIGIN.md`, `CITATION.cff`, `LICENSE`, and `NOTICE` for the exact
legal/citation records.

## Names and layers

These names are related but not interchangeable:

| Name | Meaning |
|---|---|
| O / hosted O | The `.O` orchestration language, parser, evaluator, OIR, HGraph, backend runtime, and CLI behavior. |
| Ostadix-lang / O-lang | The project and hosted language/runtime as a whole. The Cargo root package is named `o-lang`. |
| OValue | The canonical, tagged value family exchanged between hosted evaluators and used at runtime boundaries. |
| O-core | The separate statically typed `.oc` systems language compiled to freestanding object code. It does not use hosted OIR. |
| OKernel | The capability-oriented kernel built through O-core and tested in bounded native/QEMU gates. |
| O-Machine | The architecture-specific resource and virtualization substrate. Its broader contract includes future work beyond current gates. |
| World | The governed identity, resource, namespace, and execution ontology and its versioned records/contracts. A hosted simulator is not itself a qualified native World. |
| OSTADIX | The integrated system formed from the layers above. |
| OSTADIX Alpha | The first integrated-system release that satisfies the defined G0-G13 qualification gates. It is a qualification target, not an automatic synonym for the current checkout. |

Primary sources: opening sections of `README.md`, `docs/OSTADIX_WORLD.md`,
`docs/KERNEL_WORLD_CONTRACT.md`, and `docs/O_MACHINE_CONTRACT.md`.

## Two computational languages

Ostadix deliberately uses different intermediate representations for two
different jobs:

```text
.O  -> ONode -> OIR -> ExecutionPlan -> solved HGraph
    -> Evidence V6 -> Admission V6 -> hosted execution -> OValue/evidence

.oc -> AST -> resolved typed HIR -> SSA MIR -> ELF64 object
    -> linked freestanding runtime/kernel image
```

OIR models evaluator composition, lexical/data dependencies, sequencing,
effects, resources, and dispatch policy. O-core MIR models machine-level typed
values, mutable places, control-flow blocks, phi values, memory, atomics,
hardware operations, ABI, and object emission. Neither representation is
implicitly converted to the other.

Primary sources: `SPEC.md` section 2.5, `ARCHITECTURE.md`, and
`docs/OCORE.md` section 1.

## The source-to-evidence story

The project describes one computation as gaining stronger, separately
inspectable artifacts through this sequence:

```text
source
  -> parsed structure
  -> lowered executable representation
  -> dependency/resource graph
  -> pre-execution evidence
  -> admitted execution
  -> placement/dispatch
  -> result and runtime observation
  -> trace, receipt, or release evidence
```

The boundaries matter:

- Parsing or planning does not execute.
- Evidence describes facts and contracts; it is not admission.
- Admission determines whether the local coordinator may execute the exact
  bound computation; it is not automatically remote placement authority.
- A placement lease authorizes only its named operation/profile and does not
  become World authority.
- A worker candidate is provisional until the coordinator validates,
  publishes, and settles it.
- A trace or receipt records an observation; it does not automatically
  authorize another execution.

Primary sources: `README.md` “How to read Ostadix-lang,” `SPEC.md` section
2.5, `docs/SEMANTIC_CUSTODY.md`, and `docs/OIR_EXECUTION_FABRIC_V1.md`.

## Why the design is unusual

1. Evaluator choice is expression-granular. It is encoded in the delimiter,
   not selected once per file or module.
2. A receiving backend renders OValue into its own source/presentation form.
   This avoids defining a bespoke bridge for every pair of languages.
3. Persistent evaluator state is explicit through an environment marker such
   as `python[0]`, rather than hidden in a notebook-global process.
4. `quote^` and `O.eval` make O code transferable as data across hosted
   language boundaries.
5. Planning, admission, placement, execution, and evidence are deliberately
   distinct, inspectable phases.
6. Hosted orchestration and native systems code use representations suited to
   their own semantics instead of forcing both into one IR.

## Implementations and authority

The authoritative hosted implementation is Rust. The independent engine is
the `ostadix-api` crate; the root `o-lang` crate is an exact-version
compatibility and CLI shell that reexports historical module paths. Dependency
direction is one-way: the shell depends on the engine, and the engine does not
depend on the shell.

The repository also retains:

- an active standalone C17 edition in `c_cpp/` with a documented subset; and
- a readable legacy Python reference in `o_lang/`.

These editions are not feature-identical. In particular, authoritative Rust
supports the full call-expression and current graph/admission behavior; the
Python reference lacks the general autonomous/group call grammar, and C17
executes its documented portable subset.

Primary sources: `Cargo.toml`, `crates/ostadix-api/src/lib.rs`, `src/lib.rs`,
`ARCHITECTURE.md`, `DEVELOPMENT.md`, and `SPEC.md` sections 6-8.

## Current coordinate summary

At this context snapshot:

- Rust package coordinate: `0.4.0`.
- Minimum supported Rust declared by the package: `1.93.1`.
- Pinned release toolchain: `1.97.1`.
- Current solved executable graph: Graph V2.
- Current local pre-execution evidence: `oexec.evidence/v6`.
- Current local admission: `oexec.admission/v6`.
- Current schedule explanation: `oexec.schedule-explanation/v2` and
  `oexec.admission-why/v2`.
- Current backend catalog: `ostadix.backend-catalog/v6`.
- Execution intent remains `oexec.execution-intent/v1`; matching intent is
  authority-free and still requires fresh Graph V2/Evidence V6/Admission V6.

Graph V1 remains the frozen analyzed-geometry input to active, authority-free
Execution Intent V1, but it cannot enter current execution/admission.
Evidence/Admission V5, Schedule Explanation/Why V1, and placement fragment V1
remain archival compatibility/inspection forms and cannot be relabelled or
executed as current authority.

Primary source: `docs/VERSIONING.md`.

## Security posture in one paragraph

Ordinary hosted backends run with the host authority available to the current
O process; the default is intentionally permissive. Backend metadata and
admission bind executable identities and required rights, but arbitrary hosted
source is not a general sandbox. Unknown hosted effects conservatively touch
`HostWorld`. Capability-bearing, referential, and effectful OValues require
special handling, and serialization alone never makes a value safe to cache,
replay, persist, or use as authority. Native kernel capability handles use a
separate generation-tagged boundary; descriptive or deserialized identities
are not kernel authority.

Primary sources: `SPEC.md` sections 2.5 and 3.0-3.0.2, `docs/OCORE.md` section
9, and `README.md` “Exact implementation boundaries.”
