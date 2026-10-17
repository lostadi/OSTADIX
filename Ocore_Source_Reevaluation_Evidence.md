# O-core source reevaluation evidence

O-core owns the intermediate representations and native assembly generators
used by its `.oc` compiler. It is not a syntax frontend that delegates that
route's native code generation to LLVM. LLVM also has an implemented, separate
role in foreign-code import. Backend ownership, graph-level dependency checks,
and preservation of those relationships in native execution are separate claims.

Here, **verified in source** means confirmed in the inspected implementation.
It is not a proof that every accepted program compiles correctly. Execution
evidence must identify the tested inputs, compiler, target and execution profile.

| Claim | Source finding |
|---|---|
| Native `.oc` compilation lowers through LLVM IR. | Contradicted: parsing, O-core type checking, HIR, SSA MIR and owned ISA assembly generation are directly connected in the driver. |
| Initial source type checking happens in MIR. | Contradicted: `typeck::check` produces HIR before `mir::lower` runs. |
| Clang performs this route's native instruction selection. | Contradicted: the driver supplies already generated assembly with `-c -x assembler`. |
| LLVM is only used by a historical feature census. | Contradicted: the CLI implements whole-module LLVM import followed by O-core native-module verification and native emission. |
| Resource-state dependencies and execution provenance are only proposals. | Contradicted: the HGraph projection, readiness scheduler, evidence admission and provenance admission implement concrete representations and checks. |
| Owning a backend establishes complete graph-to-native preservation. | Not established: an explicit general native orchestrator and complete runtime integration remain required. |
| An assembly correspondence map establishes instruction-level execution debugging. | Not established: the implemented map describes generated assembly text, without machine PCs, execution events or HGraph operation bindings. |

## Native O-core source

```text
.oc source -> parsed AST -> typeck::check -> typed HIR -> mir::lower
           -> typed SSA MIR -> O-core target assembly -> assembler -> ELF object
```

[`ocore::driver::compile_with_function_sections`](crates/ostadix-api/src/ocore/driver.rs)
calls the parser, checker and lowering passes in that order. Its target match
selects the x86-64, AArch64 or RISC-V generator. `emit_object` subsequently
invokes Clang as an assembler. These are distinct compiler and assembler stages.

[`ocore::mir`](crates/ostadix-api/src/ocore/mir.rs) represents each temporary as
an SSA `ValueId` with one defining instruction. Mutable locals and statics are
explicit `Place`s; a load produces a new SSA value. This preserves the distinction
between a value definition and the mutable storage from which it was obtained.

The [x86-64](crates/ostadix-api/src/ocore/codegen.rs),
[AArch64](crates/ostadix-api/src/ocore/codegen_aarch64.rs) and
[RV64](crates/ostadix-api/src/ocore/codegen_riscv64.rs) generators construct
assembly from HIR/MIR. For example, x86-64 emits statics and processes MIR
functions through its own `FunctionCodegen`; it does not call an LLVM object
emitter.

## Imported implementations

```text
whole foreign LLVM module -> pinned LLVM parsing and verification
                         -> O-core NativeModule -> independent verification
                         -> O-core ISA assembly -> assembler -> ELF object
```

[`ocorec`](src/bin/ocorec.rs) accepts `--input-kind llvm-ir`, invokes its
embedded import worker and passes the resulting native module to the native
driver. [`ocore_llvm_import.py`](scripts/ocore_llvm_import.py) uses the
digest-pinned LLVM C API and the accompanying
[bitcode audit](scripts/ocore_llvm_bitcode.py). This is an implemented import
route, rather than a census or an implicit property of `.oc` syntax.

[`NativeModule`](crates/ostadix-api/src/ocore/native_ir.rs) retains imported
types, target layout, ABI, symbols, control flow, instructions and provenance.
[`native_verify`](crates/ostadix-api/src/ocore/native_verify.rs) verifies that
representation independently. [`native_codegen`](crates/ostadix-api/src/ocore/native_codegen.rs)
audits the complete module's supported native realization before emitting its
own target assembly. Imported semantics remain distinct from `.oc` semantics.
Unsupported features fail explicitly; partial lowering does not qualify a
complete implementation.

The parser pin is also a real environment requirement. The current importer
requires LLVM 22.1.6 and the admitted library digest. Having Clang 19 or a Rust
compiler installed does not establish that the foreign import route works on
that host. An explicitly supplied library still has to pass its digest, version
and C API checks. The checks must not be weakened to manufacture a successful
runtime result.

## Implemented graph and provenance relationships

[`hgraph::from_oir`](crates/ostadix-api/src/hgraph/from_oir.rs) projects the
validated execution plan into executable hyperedges with separate value,
completion, control, actor and resource-state inputs and outputs. Resource
tracking includes state versions and reader drains. The
[`readiness scheduler`](crates/ostadix-api/src/hgraph/schedule.rs) uses these
relationships as execution blockers; they are operational constraints.

[`evidence::admit`](crates/ostadix-api/src/evidence/admit.rs) checks exact
program, plan, solved graph and runtime bindings before constructing the
private admitted-execution type accepted by the coordinator. Current V6
admission materializes type, effect, dispatch, capability, placement, failure
and resource-demand evidence. Descriptive inspection snapshots and historical
receipts do not authorize a fresh execution.

[`information_provenance`](crates/ostadix-api/src/information_provenance/mod.rs)
also implements admission against the exact execution admission, signed receipt
and terminal output. Its guarantees are those checked bindings; they do not
automatically extend to arbitrary native instructions or all external effects.

The project-specific [planning and execution path](crates/ostadix-api/src/project)
has its own source-plan reconstruction and terminal runtime-graph evidence.
The [executor specification](docs/HGRAPH_EXECUTOR_PLAN.md) describes the limits
between these execution and admission paths.

## Native assembly provenance added in this work

[`native_map`](crates/ostadix-api/src/ocore/native_map.rs) records the exact
half-open UTF-8 assembly byte ranges for imported native instructions,
terminators, block labels, prologues, epilogues and exception-landing stubs.
Zero-width compiler markers and PHIs remain represented. Predecessor terminators
own their lowered PHI copies; exception-landing sites own unwind-edge copies.

The map binds the target, normalized typed module and generated assembly.
The driver additionally binds the exact module-file bytes and final artifact.
Verification re-verifies the module and regenerates every assembly site, then
checks the supplied artifact's digest. A matching object digest identifies the
bytes; it does not prove assembler correctness or execution semantics.

This is a descriptive compiler correspondence for imported native IR. It does
not supply `.oc` source spans, machine-address ranges, a debugger, native
HGraph dispatch, runtime observations or admission authority. Existing plain
emission shares the same emitter and remains byte-identical.

## Executed review validation: October 17, 2026 UTC

The review reconstructed all 2,781 tracked files in published checkpoint
`0c8a1a1218a404765f78a883d2ce63d66e88e74d`, verifying the complete Git tree
`cae24aa2621c75d5275a21b9363b3b892e247b4e`, and then applied the evidence fixes
in this change. A fresh `ocorec` was built with the pinned Rust 1.97.1 toolchain.
The [machine-readable validation record](evidence/ocore/native-review-20261017.json)
binds the tested files, compiler binary, tool versions and resulting artifacts.

| Check | Observed result |
|---|---|
| `cargo build --locked --bin ocorec` | Passed; fresh `ocorec 0.4.0`. |
| `test_ocore_native_equivalence.py` | All 11 regression tests passed. These exercise producer freshness, receipt removal and executable selection, rather than native code generation. |
| `test_ocore_native_map.py` | All 10 tests passed without skips, including assembly and real ELF object maps for x86-64, AArch64 and RV64. |
| `check_ocore_native_equivalence.py` | All three targets passed with digest `b1009525e0d57799` and 12,288 arithmetic comparisons per target. |
| Fault and nonreturning-expression checks | Six synchronous fault cases and two exit-status-42 nonreturning-expression cases passed per target. |
| Object reproducibility | Both independently emitted object files were byte-identical for each target. |
| Driver formatting and patch whitespace | Passed with pinned Rustfmt and `git diff --check`. |
| Tracked HTML exports | All 97 documents matched Marked 18.0.13 after regenerating the stale O-core export. |

The arithmetic count is 4,096 deterministic inputs times three directly
checked C-reference comparisons: unsigned, signed and narrow integer mixes.
The harness compares each result before incorporating it into the common
64-bit digest. Additional ABI, memory, atomic and evaluation-order selftests
are outside that count. Atomic checks in this corpus run in one thread;
they do not establish ordering between concurrent threads.

x86-64 ran directly on the Linux host. AArch64 and RV64 ran under QEMU user
8.2.2. Clang/LLD 18.1.3 compiled the independent C harness, assembled O-core's
generated assembly and linked static Linux test executables. This does not
exercise the foreign importer's separate digest-pinned LLVM 22.1.6 path.

The fixes remove several ways an evidence check could succeed without testing
the intended operation:

- Each compiler or linker invocation must produce fresh, nonempty regular
  artifact files. Old objects, retained assembly and executables can no longer
  satisfy a successful invocation that produces no output. Seven regressions
  against the original checker failed as expected: six stale-artifact cases
  and one selected-compiler identity mismatch.
- Selected executable paths become absolute before any working-directory
  change, while preserving symlink command names needed by multicall tools.
  The compiler executed and the compiler hashed use the same selected path.
- Native artifact alias checks reject dangling or looping symlinks before
  writes, while retaining support for genuinely absent output directories.
- Map tests invoke the implemented `--keep-asm` option and Clang selected from
  `PATH`. They recognize Clang's `x86-64` backend name and require collision
  diagnostics, so an argument-parser error cannot stand in for alias rejection.
- Both Python suites now run in the existing O-core CI job after its compiler
  build. Their successful local runs are recorded separately from CI status.

The nine-test original Lua inventory transcript supplied during this review
refers to newer local work absent from the published checkpoint. Those tests
were not independently rerun here. Their reported success does not establish
complete original Lua lowering or execution, and this review does not include
or replace those unpublished source changes.

## What is still required for the broader completion claim

The acceptance requirements in [OCORE.md](docs/OCORE.md) distinguish source
capture, complete lowering, dependency closure, linking and native execution.
An original runtime or compiler must pass through the owned emitters with every
required function, global, initializer, relocation, ABI feature, helper, library
and module accounted for. Its build must bind the exact source, configuration,
frontend, IR and artifacts. Scripts and declared resource closure must be
included, with native references resolving to verified content.

An explicit OIR/ExecutionPlan-to-O-core runtime interface must then preserve the
admitted value, control and resource relationships at native dispatch and result
publication. Carrying a graph, bundling an unchanged runtime executable or
calling a hosted evaluator does not establish that lowering.

Reference tests and real `.O` execution must compare required values, faults
and effects on x86-64, AArch64 and RV64GC under explicit execution profiles,
after removing dependence on the original runtime executable. Linux hosts and
QEMU user-mode runs provide development evidence; native OSTADIX service
acceptance and physical-device claims require their own gates. Compiling a
compiler implementation and routing its generated programs through O-core are
separate requirements. JIT code publication also needs a verified path.

The stronger architectural claim is therefore precise: ownership of the native
backend makes additional relationships representable and checkable. The source
already implements substantial graph and provenance checks. Complete
preservation through native execution remains an independently testable
obligation, not a consequence of backend ownership alone.
