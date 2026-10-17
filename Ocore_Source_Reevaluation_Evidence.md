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
| Clang lowers `.oc` or LLVM IR into assembly on the `.oc` route. | Contradicted: the driver supplies already generated assembly with `-c -x assembler`. |
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
Assembler encoding, pseudo-instruction expansion and any permitted relaxation
remain separate responsibilities; owning target assembly emission does not mean
that the external assembler or linker is absent from the toolchain.

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

The object inventory also checks actual ELF storage, symbols, fixups and owned
exception metadata. In particular, valid RISC-V difference-relocation pairs
must describe the exact owned FDE extent, CFI advance or LSDA field. The checker
does not treat duplicate offsets as sufficient evidence and rejects changed
endpoints even when their numeric difference is unchanged. These checks establish
owned field geometry; they do not qualify an unwinder or executed CFA recovery.

The parser pin is also a real environment requirement. The current importer
requires LLVM 22.1.6 and the admitted library digest. Having Clang 19 or a Rust
compiler installed does not establish that the foreign import route works on
that host. An explicitly supplied library still has to pass its digest, version
and C API checks. The checks must not be weakened to manufacture a successful
runtime result.

The hosted `.O` binary target is another distinct path:
[`olangc`](src/bin/olangc.rs) generates a Rust evaluator project and invokes
Cargo. Producing that hosted native executable does not establish an
OIR-to-O-core orchestrator. The two O-core native routes above must not be
conflated with hosted evaluator packaging.

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
The driver additionally binds and embeds the exact imported module-file bytes
and binds the final artifact. The embedded snapshot can be recovered even when
LLVM import used a private temporary; it does not require a later import to
reproduce incidental metadata printer provenance.
Verification re-verifies the module and regenerates every assembly site, then
checks the supplied artifact's digest. A matching object digest identifies the
declared bytes in an unsigned sidecar; it does not independently prove
assembly-to-object correspondence, assembler correctness or execution semantics.
An object replacement accompanied by a changed declared digest is outside that
descriptive identity check. Assembly replacement, even with changed hashes,
rejects when it differs from regenerated O-core emission.

This is a descriptive compiler correspondence for imported native IR. It does
not supply `.oc` source spans, machine-address ranges, a debugger, native
HGraph dispatch, runtime observations or admission authority. Existing plain
emission shares the same emitter and remains byte-identical.

## What is still required for the broader completion claim

The compiler now also writes and consumes self-contained
`ocore-native-module-set-v1` packages. The
[package verifier](src/bin/olangc/native_runtime/artifact.rs) re-verifies every
embedded module, target/profile binding, component/unit inventory, dependency
edge and symbol/ABI/COMDAT closure. Direct package input can produce IR or owned
objects without reopening original source, LLVM or capture files. This closes
a concrete artifact and dependency-composition gap; it does not supply scripts,
platform/resource closure, executable linking or native HGraph dispatch.

The [original Lua recipe](tools/ocore-runtime/lua/README.md) captures the whole
pinned upstream Make configuration. The committed recipe now also passed with
actual Clang/LLVM 22.1.6 on this RISC-V host: 34 LLVM units, 33 archive members
and 111 source/data files, independent capture verification, and original-engine
reference smoke. The [SDK evidence](evidence/llvm22_riscv64_20261017.json)
records Debian signed-index/package verification, the exact library hash,
required C-API health, and a scalar imported module's owned-object execution.

The [whole-unit Lua diagnostic](evidence/original_lua_20261017.json) attempted
all 34 original units: 5 reached independently verified O-core IR and owned
RISC-V objects; 29 rejected. First diagnostics identify floating-point types,
variadic interfaces and an unsupported symbolic initializer. These are complete
unit outcomes, not percentages of engine support. The separate full-runtime
route rejects missing verified library/platform dependency module-sets before
unit import. Neither the original Clang-built executable nor these partial
imports establish complete O-core lowering or runtime dependency closure.

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

## Verified development gates for this work

The following local gates passed with the explicit Rust 1.97.1 toolchain and
the built `target/debug/ocorec` and `target/debug/olangc`, rather than assuming
that an installed command reflected changed source:

| Gate | Observed result |
|---|---|
| `/home/orangepi/.cargo/bin/cargo +1.97.1 test --offline --locked -p ostadix-api --lib ocore::native_map` | 4 passed, including all-target exception-landing maps. |
| `python3 -m unittest discover -s tests -p test_ocore_native_map.py -v` | 11 passed without skips, including embedded-snapshot recovery, real LLVM 22 import, assembly/object maps on all three ISAs, collisions, stale maps and rejected forged assembly correspondence. |
| `python3 -m unittest discover -s tests -p test_ocore_native_runtime.py -v` with the pinned LLVM 22 SDK/parser | 17 passed without skips on RISC-V, including actual source capture, verified IR, owned-object native execution and package reuse after source/build/capture removal. |
| `/home/orangepi/.cargo/bin/cargo +1.97.1 test --offline --locked --bin olangc native_runtime::` | 115 passed, including 9 package/composition tests and actual three-target owned exception-table corruption checks. |
| `python3 -m unittest discover -s tools/ocore-runtime/lua -p 'test_*.py' -v` | 9 passed; original source/Make, producer, object and archive substitutions reject. |
| `python3 scripts/check_ocore_native_equivalence.py --ocorec target/debug/ocorec --output-dir target/native-reevaluation-20261017-final` | All three ISAs passed 12,288 shared-reference cases each, digest `b1009525e0d57799`, 6 synchronous fault cases and 2 `never` cases per ISA, with byte-reproducible objects. |
| Actual Clang/LLVM 22.1.6 SDK and unchanged Lua source | Parser C-API health and scalar owned-object execution passed; complete original capture and reference smoke passed; all 34 whole units audited, with 5 owned-object successes and 29 explicit rejections. Full-runtime admission rejected missing included dependency module-sets. |
| `python3 scripts/render_docs.py check --marked /tmp/ostadix-doc-renderer/node_modules/.bin/marked` | All 99 tracked exports matched complete generated bytes using pinned Marked 18.0.13. |

Cargo validation used `CARGO_PROFILE_DEV_OPT_LEVEL=0`,
`CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_OPT_LEVEL=0` and
`CARGO_PROFILE_TEST_DEBUG=0` on this RISC-V Linux development host. The ordinary
shell selected an older system Rust, so commands used the explicit rustup
toolchain. These are bounded compiler and artifact checks; they do not establish
complete runtime lowering or native HGraph execution.
