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

## Bounded native execution beneath the admitted graph

The ordinary `.O` builtin `ocore_i64` now connects a static, embedded
`NativeModule` to an executable graph edge. Its
[adapter](crates/ostadix-api/src/native_leaf.rs) independently verifies the whole
module and audits every function and block, including unused definitions. The
admitted profile consists of defined C-ABI `i64` functions, integer SSA and
acyclic control flow. Memory, globals, external calls, aliases and runtime hooks
reject. An imported `llvm.trap` declaration is retained as metadata for the
explicit trap operation. Register and stack arguments use the target ABI.

Before fresh execution admission, the adapter emits owned assembly, adds its
fixed Linux framing wrapper, and invokes the selected assembler and static
linker. Its manifest binds the descriptor, normalized module, assembly, adapter
executable, exact tools, flags, captured working directory and tool environment,
and generated ELF. The tool executables and resulting ELF are retained as
sealed Linux file descriptors. Tool dynamic dependencies remain part of the
trusted host toolchain; these hashes do not establish a complete independently
lowered toolchain closure.

The [executable lease set](crates/ostadix-api/src/runtime_exec.rs) checks that
the leaf inventory and arities match the source plan. Admission and dispatch
reuse those prepared leases. Dispatch receives graph-ready values, requires
signed `i64` integers or canonical decimal text, and returns through normal
semantic settlement. Invalid arguments and native traps are failures; they
cannot publish a native result or unblock a dependent Store. The source
descriptor, plan node and executable edge participate in the existing hashes
and admission checks.

The CLI's `--json` execution evidence exposes the admitted native inventory,
actual node events and successful value, completion and resource publications,
including on failed runs. An admitted leaf record alone does not establish
that it ran; the trace establishes observed execution. This is a native leaf
under the existing Rust coordinator. General native graph orchestration,
effectful native resource handles and instruction-level debugging remain
separate requirements. The [interface documentation](docs/OCORE.md) gives the
descriptor format and a complete ordinary `.O` example.

Generated `olangc --target binary` evaluators include the same native-leaf
adapter and owned computation core. A shared
[native-core facade](crates/ostadix-api/src/ocore/native_core.rs) supplies the
same types, verifier, ABI planner and emitter to the engine and generated
runtime; [the source inventory](crates/ostadix-api/src/api/aot_source.rs)
copies those files verbatim. The generated main remains a hosted evaluator.
Its prepared-leaf manifest binds that application's executable, rather than
the compiler that generated it.

## Imported binary128 storage and narrow return compatibility

The LLVM importer and independent native emitter now admit IEEE binary128 as
storage with exact 16-byte allocation and alignment. This permits original
aggregate layouts, alloca/GEP, raw copies and exact positive-zero initializers,
including packed fields. It does not admit binary128 arithmetic, scalar
loads/stores, SSA transport or floating-point call classification. Other
128-bit floating formats remain distinct, and changing a declared layout does
not bypass the emitter's independent checks.

An ordinary direct C `i32` call also has one explicit target-specific refinement:
a callee's `signext` return guarantee can satisfy a bare caller on the admitted
64-bit ELF ABIs. Both original attribute vectors remain in the IR. The owned
caller consumes the low 32 bits, while the callee retains its original return
plan. Reverse guarantees, `zeroext` conflicts, parameter changes, aliases,
Invoke and provider-signature equality remain strict. The importer rejects
`musttail` before constructing this ordinary call. This is a deliberately narrow
native rule: [LLVM 22.1.6's ABI documentation](https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-22.1.6/llvm/docs/LangRef.rst)
generally requires ABI attribute agreement and does not license arbitrary
signature mismatches.

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

## Direct original-source recipe orchestration

[`olangc --native-runtime`](src/bin/olangc/native_runtime/source_recipe.rs)
now accepts an original-source build recipe directly. With
`--native-runtime-source`, it invokes its embedded capture worker, independently
re-verifies the resulting build evidence, and passes the admitted whole units
to the existing O-core lowering route. The caller supplies the clean pinned
checkout, exact frontend tools and admitted LLVM parser; the compiler creates
a separate new build/capture/lowering directory. Existing output directories,
output paths within the source checkout (including aliases), and escaping
inventory paths reject before they can be reused.

The source-recipe receipt binds the recipe, embedded worker/helper, capture
report and lowering evidence by exact bytes and SHA-256. Capture completion
requires independent replay admission; successful reference builds alone do
not set it. Failure retains the stage, process arguments, diagnostics and any
admitted evidence. Complete unit lowering remains separate from a complete
runtime, dependency closure, linking and native execution qualification.
The [workflow documentation](tools/ocore-runtime/README.md) and
[unchanged Lua recipe](tools/ocore-runtime/lua/README.md) describe the commands
and their current limits.

The [direct-source development evidence](evidence/native_source_recipe_20261017.json)
records 11 passing CLI cases with native fixture execution, 17 passing existing
capture/package cases, and the unchanged Lua invocation. Lua captured and
independently admitted all 34 units, then stopped before any unit import because
its declared source dependencies lacked verified included module-sets. Its
Clang-built reference engine passed the smoke test; it is not an O-core native
Lua product.

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

The [initial whole-unit Lua diagnostic](evidence/original_lua_20261017.json)
attempted all 34 original units: five produced verified O-core objects and
29 rejected. After the binary128-storage and narrow return-ABI changes,
[a complete repeat audit](evidence/original_lua_whole_unit_frontier_20261017.json)
produced seven verified RISC-V objects: `lopcodes.c`, `lgc.c`, `lstring.c`,
`linit.c`, `lzio.c`, `ltests.c` and `lctype.c`. The configured `ltests.c` unit
contains no function definitions. All 34 units were attempted without function
or body selection. The other 27 first rejections comprise 16 double-precision
type rejections, 10 variadic-interface rejections and the `luaV_execute.disptab`
symbolic initializer in `lvm.c`. These are whole-unit outcomes, not percentages
of engine support; each rejection may conceal further unsupported features.

The [dependency audit](evidence/original_lua_dependency_frontier_20261017.json)
also identifies the actual captured glibc libraries, dynamic loader, GCC
startup objects and compiler helpers. Their presence in a successful reference
link does not supply original implementations lowered through O-core. The
full-runtime route rejects missing verified library/platform module-sets before
unit import. Version-one packages also reject non-null source pins they cannot
independently authenticate. Neither a reference executable nor partial unit
imports establish runtime dependency closure or a runnable O-core Lua engine.

The acceptance requirements in [OCORE.md](docs/OCORE.md) distinguish source
capture, complete lowering, dependency closure, linking and native execution.
An original runtime or compiler must pass through the owned emitters with every
required function, global, initializer, relocation, ABI feature, helper, library
and module accounted for. Its build must bind the exact source, configuration,
frontend, IR and artifacts. Scripts and declared resource closure must be
included, with native references resolving to verified content.

The bounded native leaf above provides one explicit interface between the
ExecutionPlan, owned native computation and semantic publication. A general
OIR/ExecutionPlan-to-O-core runtime interface must extend that preservation to
the required effects, resource handles and orchestration. Carrying a graph,
bundling an unchanged runtime executable or calling a hosted evaluator does
not establish that general lowering.

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

The earlier completed baseline gates below used the explicit Rust 1.97.1
toolchain and built compiler binaries. Their linked receipts identify the
tested artifacts; later source changes do not retroactively change those
historical results:

| Gate | Observed result |
|---|---|
| `/home/orangepi/.cargo/bin/cargo +1.97.1 test --offline --locked -p ostadix-api --lib ocore::native_map` | 4 passed, including all-target exception-landing maps. |
| `python3 -m unittest discover -s tests -p test_ocore_native_map.py -v` | 11 passed without skips, including embedded-snapshot recovery, real LLVM 22 import, assembly/object maps on all three ISAs, collisions, stale maps and rejected forged assembly correspondence. |
| `python3 -m unittest discover -s tests -p test_ocore_llvm_import.py -v` with the pinned LLVM 22 SDK/parser | 71 passed; 1 legacy Clang 21 check skipped because that frontend was unavailable. Actual LLVM 22 text/bitcode and all-three-ISA cases passed; exact commands, environment and compiler hashes are retained in the [CLI regression evidence](evidence/native_cli_llvm22_20261017.json). |
| `python3 -m unittest discover -s tests -p test_ocore_native_runtime.py -v` with the pinned LLVM 22 SDK/parser | 17 passed without skips on RISC-V, including actual source capture, verified IR, owned-object native execution and package reuse after source/build/capture removal. |
| `/home/orangepi/.cargo/bin/cargo +1.97.1 test --offline --locked --bin olangc native_runtime::` | 116 passed, including source/output isolation, 9 package/composition tests and actual three-target owned exception-table corruption checks. |
| `python3 -m unittest discover -s tests -p test_ocore_native_source_recipe.py -v` with the pinned LLVM 22 SDK/parser | 11 passed without skips, including real two-unit source builds, owned-object native execution, path isolation, failure receipts, and capture/package route rejection of source-only options. |
| `python3 -m unittest discover -s tools/ocore-runtime/lua -p 'test_*.py' -v` | 9 passed; original source/Make, producer, object and archive substitutions reject. |
| `python3 scripts/check_ocore_native_equivalence.py --ocorec target/debug/ocorec --output-dir target/native-reevaluation-20261017-final` | All three ISAs passed 12,288 shared-reference cases each, digest `b1009525e0d57799`, 6 synchronous fault cases and 2 `never` cases per ISA, with byte-reproducible objects. |
| Actual Clang/LLVM 22.1.6 SDK and unchanged Lua source | Parser C-API health and scalar owned-object execution passed; complete original capture and reference smoke passed; all 34 whole units audited, with 5 owned-object successes and 29 explicit rejections. Full-runtime admission rejected missing included dependency module-sets. |
| `python3 scripts/render_docs.py check --marked /tmp/ostadix-doc-renderer/node_modules/.bin/marked` | All 99 tracked exports matched complete generated bytes using pinned Marked 18.0.13. |

Cargo validation used `CARGO_PROFILE_DEV_OPT_LEVEL=0`,
`CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_OPT_LEVEL=0` and
`CARGO_PROFILE_TEST_DEBUG=0` on this RISC-V Linux development host. The ordinary
shell selected an older system Rust, so commands used the explicit rustup
toolchain. These are bounded compiler and artifact checks; they do not establish
complete runtime lowering or general native graph orchestration.

## Final native-leaf and storage gates

The [final development evidence](evidence/native_bridge_and_storage_20261017.json)
binds the rebuilt `O`, `olangc` and `ocorec`, monitored source hashes, commands,
profiles and retained logs. The CLI and AOT gates used that final binary set;
the Rust gates compiled the same frozen source. The
[CLI index](evidence/native_bridge_cli_20261017.json) records 129 passing test
methods and one explicit unavailable-Clang-21 skip across seven suites. The
separate AOT suite adds three passing methods without skips.

| Gate | Observed result |
|---|---|
| API `native_leaf` | 16 passed, including independent whole-module purity checks, sealed preparation, graph ordering and failure settlement. |
| API `ocore::native_` | 223 passed, including binary128 storage and strict return-contract controls. |
| API runtime, admission, graph, executor, dispatch and IR filters | Respectively 20, 47, 58, 32, 2 and 43 passed. Filter counts can overlap. |
| `olangc native_runtime::` | 116 passed. |
| Generated-runtime source inventory and project source inventory | Six and one passed; emitted native-core files match their embedded source bytes. |
| Binary128 storage CLI | Eight passed without skips; actual text/bitcode, owned objects and byte-layout execution on all three ISAs, plus whole unchanged Lua storage units. |
| Direct return-ABI CLI | Three passed without skips; owned/reference execution on all three ISAs and strict mismatch controls. |
| Ordinary native-HGraph CLI | Eight passed without skips on this RISC-V Linux host; real Store versions, stack arguments, invalid inputs and native traps. |
| Generated ordinary `.O` applications | Three passed without skips; actual native and plain applications, and a failing trap application with a blocked successor. |
| LLVM import, runtime package, source recipe and native-map regressions | Respectively 71, 17, 11 and 11 passed; only the legacy Clang 21 frontend case skipped. Actual LLVM 22.1.6 cases ran. |
| Formatting | All 30 changed Rust files passed the explicit Rust 1.97.1 formatter check. |

The [AOT evidence](evidence/native_hgraph_aot_20261017.json) retains the real
`olangc` product compile and two further unmodified emitted mains compiled
against the same generated runtime. Fresh execution checks reused that exact
content-verified build after correcting a test expectation for quoted text
display. The separate observer's records are bound to its own executable;
they are not attributed to a product main. Actual product lifecycle records
bind each application's running image and prepared/executed native leaves.

The [whole original storage-unit proof](evidence/original_lua_storage_units_20261017.json)
binds unchanged `lgc.c` and `lstring.c`, their complete frontend inventories,
independent native verification and actual owned objects to the final compiler
set. The complete 34-unit diagnostic above remains bound to its recorded
earlier compiler rather than being relabeled as a new run.

This qualifies the bounded scalar leaf under the existing coordinator. General
native orchestration, effectful native resource handles, machine-PC debugging
and complete original-runtime dependency closure remain outside these results.

## Python, C, and Rust source expansion (2026-10-18)

The [original-source expansion evidence](evidence/original_python_c_rust_expansion_20261018.json)
records complete configured source captures and a completed 370-unit diagnostic
audit with the pinned LLVM 22.1.6 parser and installed O-core compiler. The
matrix reconciles the complete selected build inventory, retains whole modules,
checks tool and input hashes, independently verifies imported modules, and
checks the actual emitted ELF objects. Raw Rust bitcode remains the compiler
input; separately decoded text supplies independently checked metadata.

| Original configured source profile | Units audited | Independently verified modules | Owned objects |
|---|---:|---:|---:|
| CPython runtime and extensions | 360 | 72 | 63 |
| chibicc stage-one C compiler | 9 | 0 | 0 |
| adler2 2.0.1 Rust library, default `std` feature | 1 emitted code-generation unit | 1 | 1 |

These are complete diagnostic results, not complete runtime qualifications.
All nine chibicc units first reject the unsupported variadic calling convention.
In that baseline, Python has import blockers and nine explicit coherent-RAM
execution-profile gates at object generation. Failure groups
record the first rejection of each whole unit, rather than every unsupported
feature that might occur behind it.

The [separate atomic-profile follow-up](evidence/cpython_atomic_profile_followup_20261018.json)
freshly imported those nine exact whole modules with the existing explicit
`coherent-ram-v1` option. All nine independently verified and produced owned
RV64 objects. Every semantic field and function body stayed equal to the
baseline apart from the declared target profile and provenance. This profile
requires ordinary coherent RAM, excludes device memory, and retains the
RISC-V masked-word accessibility and LR/SC progress requirements. It supplies
nine additional profile-qualified objects without relabeling the baseline
audit or establishing runtime execution.

The unchanged hosted CPython build separately passed its reference smoke checks.
Its authenticated local dependency packages establish hosted build interfaces;
they do not establish O-core-built dependency implementations. A separate C
fixture passed actual reference/owned execution with positive and negative
inputs. The complete Rust library unit was freshly imported, verified and
emitted again before its API matched the original implementation on 12 payloads.
A forged substitution of the original native object was rejected before linking.
Those native checks qualify their recorded interfaces and Linux RV64 execution
profile, not full C or Rust compiler/runtime support.

All 154 focused source-expansion regression methods passed without skips. The
[merged-source integration evidence](evidence/python_c_rust_integration_20261018.json)
records 91 additional passing methods without skips, the successful Cargo check
of `olangc` and `ocorec`, architecture and source inventories, and the complete
101-document HTML export check. Complete native
Python and chibicc lowering, dependency closure, compiler-generated program
routing, other-ISA execution and general native graph orchestration remain
separate required gates.

The later LLVM importer refinement was checked through 20 complete memory-import
regression methods using the pinned SDK. A freshly built compiler separately
agreed on six accepted text/bitcode cases across the three ISAs, including
independent verification and owned objects, and 18 intended rejections. Those
checks bind their own merged source tree and compiler; they do not relabel the
earlier whole-source audit or establish native runtime execution.

## Imported C variadic execution (2026-10-20)

The [variadic integration evidence](evidence/native_variadic_integration_20261020.json)
records seven passing methods without skips against the cohesive v2 compiler.
Imported C variadic signatures retain their original fixed prefix, while native
call plans classify every actual trailing integer or AS0-pointer argument and
check its attributes. Direct and indirect callers, zero tails, register
exhaustion, named stack parameters, narrow default promotions, nested calls and
conventional `va_list` forwarding run through the owned emitter. Canonical
`va_start`, `va_copy` and `va_end` preserve target cursor state and raw incoming
register banks. The `.oc` frontend's fixed `extern "C"` interface is unchanged.

| ELF/Linux profile | Integer caller/callee pairings | Integer comparisons | Opaque FP wrapper pairings | Opaque comparisons |
|---|---:|---:|---:|---:|
| x86-64 | 4 | 2,784 | 2 | 192 |
| AArch64 | 4 | 2,784 | 2 | 384 |
| RV64 `lp64` | 4 | 2,784 | 2 | 384 |
| RV64 `lp64d` | 4 | 2,784 | 2 | 384 |

The four integer pairings combine reference/reference, owned/reference,
reference/owned and owned/owned objects built from the same complete Clang22
units. A Python oracle checks 87 cases across eight seeds in each pairing.
Opaque FP gates keep the caller and `va_list` consumer as reference Clang
objects and replace only the forwarding wrapper. That owned module contains no
FP type. Double values cross register/stack boundaries; AArch64 and RV64 also
forward both words of binary128 values. Across all pairings there are 12,480
comparisons, including 9,024 involving at least one owned component.

The initial cohesive run's three failures are retained separately. Two exposed
the pinned LLVM22 `dead_on_return` pointer promise, attribute kind 9, at AArch64
forwarding sites. The final importer records its conservative, nonexploited
refinement without changing the calls or memory operations. The third corrected
a test's numeric assumption: actual trailing typed `byval` is kind 84, not 9.
The final guards require import-stage rejection, exact exit 1 and no native
output for unsupported FP SSA and the actual `byval` form. No original C
fixture was weakened.

The [separate whole-source chibicc follow-up](evidence/chibicc_variadic_followup_20261020.json)
attempted all nine original captured units with the final v2 compiler and
unchanged tool/source hashes. `unicode`, `type`, `preprocess`, `hashmap`,
`strings` and `main` independently verified and produced owned objects.
`parse` first rejects a double-precision value; `tokenize` and `codegen` first
reject binary128 values. The earlier v1 six-object result is retained
separately. Neither follow-up revises the historical 2026-10-18 nine-unit,
zero-object baseline above.

The [complete original Python/C/Rust follow-up](evidence/python_c_rust_variadic_followup_20261020.json)
attempted the same 370 original captured units with all inputs and tools pinned.
CPython independently verified 152 units and emitted 140 default-profile objects,
chibicc emitted six objects, and Rust retained its one object. The aggregate
rose from 64 to 147 objects, with 83 additions and no object regressions. All
223 rejected units returned exit 1 without crash or loader-failure markers.
The original atomic profile remained in force; the separate coherent-RAM
follow-up is excluded. These are whole-unit compilation results, not complete
Python/C/Rust runtime or provider-closure qualification.

Owned FP SSA/callers, general `byval`, exception execution through variadic
frames, complete original-compiler/provider closure and general native graph
or instruction-debugger execution remain separate required gates. Linux
carriers and QEMU qualify their recorded development profiles. The scalar native
reference interpreter's variadic rejection is unchanged.
