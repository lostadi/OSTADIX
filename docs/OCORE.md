# O-core Language and Freestanding Runtime Specification

Status: draft v0.1, normative for the `ocorec` implementation.

The separate [native Ethernet and real Linux integration profiles](NATIVE_DISTRIBUTED_LINUX_STATUS.md)
describe the new executable QEMU paths and their remaining distributed-authority
and physical-device requirements.

O-core is the native systems-programming member of O-lang. It is deliberately
separate from the polyglot orchestration language and its OIR. O-core programs
are statically typed and compile ahead of time to target object files. Foreign
language blocks (`python^`, `rust^`, and similar) are hosted facilities and are
never available in freestanding O-core code.

## 1. Compilation model

The native pipeline is:

```text
O-core source -> AST -> resolved, typed HIR -> SSA MIR -> owned target assembly
             -> assembler -> target object
```

The existing orchestration pipeline remains:

```text
.O source -> ONode -> OIR execution plan -> hosted evaluator/backends
```

OIR and O-core MIR are different representations with different invariants.
OIR models dependency and backend execution. MIR models typed machine-level
computation. Neither is implicitly converted to the other. This internal
separation does not prevent a future complete OIR artifact from containing
verified native O-core modules and explicit realization bindings.

Supported native targets are `x86_64-unknown-none`, `aarch64-unknown-none`, and
`riscv64-unknown-none` (RV64GC). All emit target assembly and little-endian ELF64
objects with an LP64 data model. `extern "C"` selects the target's integer C
calling convention: System V AMD64, AAPCS64, or RISC-V LP64. The default
compiler-versioned `extern "ocore"` convention uses the corresponding scalar
register and stack placement. Explicit `extern "sysv64"` remains AMD64-only.

The `.oc` backends share typed HIR/MIR. A separate verified native-module IR now
accepts a bounded LLVM import profile, including actual C and Rust frontend
output, and has O-core-owned assembly emitters for all three ISAs. It preserves
the existing `.oc` semantics rather than assuming that foreign code shares them.
This bridge does not yet compile a complete external runtime or compiler.

The two native routes are distinct. `.oc` compilation calls `typeck::check`
before `mir::lower`; MIR is typed SSA produced after initial source checking.
Imported LLVM modules instead pass through LLVM parsing/verification and the
independent O-core `NativeModule` verifier before O-core assembly emission.
Clang subsequently assembles the owned assembly with `-c -x assembler`. LLVM's
implemented import role is broader than a historical feature census. See the
[source reevaluation evidence](../Ocore_Source_Reevaluation_Evidence.md).

### Imported native instruction correspondence

`ocorec --native-map PATH` writes a strict `ocore-native-artifact-map-v1`
sidecar for imported native IR or LLVM IR with assembly/object emission:

```sh
ocorec implementation.json --input-kind native-ir --target riscv64-unknown-none \
  --keep-asm --native-map implementation.map.json -o implementation.o
ocorec implementation.json --input-kind native-ir --target riscv64-unknown-none \
  --verify-native-map implementation.map.json \
  --map-assembly implementation.s --map-artifact implementation.o
```

The inner `ocore-native-assembly-map-v1` binds the normalized verified module,
original frontend-input digest, target and exact generated assembly. Every
native instruction has a site, including zero-width PHIs and compiler markers;
terminator sites include normal-edge PHI copies, and per-invoke landing sites
include unwind-edge copies. The outer map binds the exact module-file bytes
and output artifact. Verification re-verifies and re-emits the whole module,
compares every site and byte range, and checks artifact identity. Maps do not
change the existing assembly or object bytes. Input/output/map aliases reject,
and failed compilation removes the requested stale map before import/emission.

Ranges are half-open UTF-8 byte offsets in assembly text, including directives
and labels. They are not machine PCs, object offsets, source lines, HGraph
identities, debug information, runtime observations or execution authority.
The outer object digest checks declared byte identity in an unsigned sidecar;
it does not independently prove assembly-to-object correspondence or assembler
correctness. Replacing an object and changing its declared digest is outside
this descriptive check. `.oc` source mapping and general native/HGraph execution remain
separate work. For LLVM input, retain the exact imported native-module JSON
with `--emit mir` for later map verification; LLVM-input provenance remains
in the inner map and verification uses `--input-kind native-ir`.

### External runtime lowering and script bundles

The primary compiler objective is for `olangc` to fully and automatically
compile existing external runtime and compiler implementations in terms of
O-core, preserving their original language engines. Support for arbitrary
implementations is the architectural objective, including interpreters,
ahead-of-time compilers, and JIT runtimes. This is a required development
direction, not an implemented external-runtime compilation feature.
`olangc` must own source/build recipes, frontend invocation, import,
verification, ABI adaptation, dependency resolution, linking, and artifact
construction. The intended pipeline is:

```text
runtime/compiler implementation source -> frontend/importer -> verified O-core IR/MIR
.O source -> OIR/ExecutionPlan + foreign scripts
O-core modules + orchestration + scripts + adapters + dependency closure
        -> complete OIR program artifact (or native O-core IR artifact)
        -> O-core target codegen + native linking -> executable binary
```

In this objective, "bundling runtimes with scripts" means a complete compiled
program in binary or IR form, including OIR. The binary form contains O-core-generated
native runtime/compiler code and the required scripts, libraries, modules,
adapters, and data. A complete OIR program artifact contains the orchestration
plan and verified native O-core code modules, with their realization bindings,
linkage, script data, ABI, resources, execution profile, and provenance. Native
module references must resolve to included verified content; references to an
unavailable engine or missing dependencies do not constitute a complete
bundle. A native O-core IR artifact is also a valid output when it includes
the program and complete dependency and execution information needed for
later native lowering. Neither IR form may require an
ambient original runtime/compiler executable to supply missing engine code.
The native orchestrator must have an explicit OIR/ExecutionPlan-to-O-core
lowering path; carrying the logical plan does not implement that path.
These complete runtime-bearing IR artifacts are not implemented yet. The
bounded implementation bridge below is the first part of automated lowering.
The existing `olangc --target ir` prints orchestration
inspection output; it does not produce a complete runtime-bearing OIR or
native O-core IR artifact.

The import path should reuse existing implementation-language frontends and
build metadata, for example through LLVM IR or WebAssembly, rather than require
each runtime to be manually rewritten in `.oc`. Generating O-core source in a
polyglot staging block does not meet this automated lowering objective.
Imported arithmetic, memory, ABI, and exception semantics must be preserved
explicitly rather than assumed to match `.oc`.
The importer must reject unsupported features with diagnostics. Native code
produced by another compiler without O-core lowering does not qualify, nor
does an unchanged imported module executed by an embedded IR interpreter.

Acceptance requires an actual complete external runtime or compiler
implementation to enter O-core IR, pass verification, and produce native code
through each of the three O-core emitters. Required functions, globals,
initializers, relocations, ABI features, libraries, compiler helpers, and
modules must be accounted for. A partial import or a feature-census percentage
does not establish this acceptance criterion. The build must identify its
source, configuration, frontend, IR, native artifacts, and complete declared
import/data/library closure.
Runtime reference tests and `.O` execution must verify results and required
effects on each ISA after the original runtime inputs are removed and ambient
runtime executable lookup is unavailable. Full runtime acceptance runs on
native OSTADIX services, potentially through its native ABI personality.
Linux-hosted compilation, user-mode emulation, and source capture provide
development evidence; a Linux guest or host OS does not supply the services
for that acceptance gate. Compiling a runtime does not itself implement them.

The foreign scripts may remain interpreted by the compiled runtime: compiling
CPython's implementation and carrying Python scripts is a valid runtime
compilation model. OIR still owns orchestration and OValue crossings; O-core
MIR owns native computation. A complete OIR artifact can combine these layers
while their internal representations retain their own invariants.
Dynamic `O.eval` requires a resident O evaluator or an explicitly qualified
compiled subset. Rewriting that evaluator in `.oc` and self-hosting the
compiler are separate milestones and do not gate the first runtime importer.
Compiling a compiler implementation does not redirect its output by itself;
the programs it generates also need an explicit frontend/backend interface
into O-core. Both capabilities belong to the overall compiler objective.
For Rust, the acceptance target includes the original `rustc` implementation,
LLVM backend, standard library, Cargo and their complete required dependency
closure. It requires actual native compiler invocations and an O-core path for
the programs they generate on all three ISAs. The scalar Rust fixtures are
backend QA; they do not replace this unfinished compiler acceptance target.

The current [runtime bundle feature](EMBEDDED_RUNTIME_BUNDLES.md) embeds supplied
runtime files. It does not implement this source-to-O-core compilation path.

### Implemented native import boundary

`ocore-native-module-v1` is a serializable, self-contained typed module with
frontend target layout, functions, globals, direct aliases, initializers, symbol relocations,
control-flow graphs, SSA values, and source/tool provenance. The LLVM importer
uses the digest-pinned LLVM C API and a bitcode-record audit, then the independent
Rust verifier checks the entire normalized inventory, including unused bodies.
It checks types, dominance, exact phi predecessors, signatures, layouts and
relocations before an ISA emitter receives the module. A structural verification
receipt binds the exact module SHA-256; it does not establish emitter coverage,
dependency closure, or native execution.

```sh
cargo build --locked --bin ocorec --bin olangc
target/debug/ocorec implementation.ll --input-kind llvm-ir --emit mir -o implementation.json
target/debug/ocorec implementation.json --input-kind native-ir --verify-native --receipt verification.json
target/debug/ocorec implementation.json --input-kind native-ir --target riscv64-unknown-none -o implementation.o
```

Generate frontend IR separately for each ISA. Preserve the original frontend
triple, DataLayout and ABI: x86-64 IR cannot be made RISC-V input by changing the
output flag. The default parser is the pinned Rust 1.97.1 LLVM 22.1.6 library;
an explicitly selected library requires `--llvm-library PATH --llvm-sha256 HASH`.
Clang assembles O-core's emitted assembly; it does not generate imported
implementation machine code. The importer worker is embedded in `ocorec` and
requires Python 3 on the build machine, independently of any compiled engine.

The current ISA profile implements every scalar integer width 1 through 64,
ordinary pointers, fixed integer/pointer C and LLVM `fastcc` calls with scalar
or aggregate values, including indirect and stack-passed calls,
typed struct/array SSA values and storage, globals, byte-offset GEP, loads/stores, static entry-block
allocations, branches, typed integer switches, parallel phi transfers, select,
freeze, lifetime markers, and dynamic byte memory fill/copy/move operations.
Zero-length memory operations perform no accesses; overlapping moves preserve
the source byte snapshot. Switches retain every case and default edge, including shared
destinations; verification compares exact numeric bit patterns for duplicate
cases. Its
`llvm_defined_behavior_v1` contract preserves defined frontend behavior and
records deterministic refinements of poison/undef and erased optimizer
restrictions. LLVM assumptions remain explicit IR operations and are verified;
the unoptimized emitter does not use them to change computation. Intrinsic
declarations remain in the source inventory and cannot escape as native addresses.
This contract is distinct from `.oc` integer division and shift semantics.

The imported scalar `llvm.smin.iN`, `llvm.smax.iN`, `llvm.umin.iN` and
`llvm.umax.iN` families use one typed `integer_min_max` NativeIR operation.
For the current realization, `N` is the original integer width from 1 through
64, and both arguments and the result must have that exact type. Signed
selection compares values at their declared width before narrowing the
result; signed i1 therefore treats the bit `1` as minus one. Each operand is
materialized once. This preserves defined source results and uses the same
recorded poison/undef refinement policy as the other imported scalar
operations. It does not change `.oc` arithmetic rules.

Every intrinsic declaration, including an unused one, must have its canonical
name and exact nonvariadic `T(T, T)` signature. Intrinsic bodies, address
escapes, vector forms and widths outside the current scalar realization
reject the whole module. These restrictions describe current coverage; the
upstream LLVM operations also support wider integers and vector types.

The native min/max conformance gate executes six O-core objects and six
original Clang objects across unchanged LLVM text/bitcode and all three ISAs.
Each positive checks 1,486,530 mathematical results and byte observations,
with digest `fb9259d1bbcbfb30`; together they check 17,838,360 observations.
The six complete own objects retain 1,974 function definitions and 1,974 actual
CFI frame records. Tests include original-width signed/unsigned comparisons,
16 consumed arguments, large volatile stack frames, odd-offset typed storage,
unused functions and defined poison/undef refinements.
All 24 deliberate runtime corruptions, 36 semantic guards, 24 independent
source-oracle controls and 18 ELF/frame-record controls reject.
This qualifies the tested scalar operations on Linux user-mode carriers.
It does not qualify the complete Rust compiler, its dependency closure,
native OSTADIX services or silicon execution.

Imported LLVM atomic loads, stores, fences, read-modify-write operations and
compare-exchanges have separate typed NativeIR operations. Import preserves
the original ordering, alignment, volatility, weak-CAS flag and context-local
synchronization-scope ID. The module includes the original scope table with
raw name bytes. LLVM's built-in system scope has an empty name; a custom scope
named `system` remains a custom contract. Structural verification checks every
atomic instruction, including unused functions and cold blocks, independently
of whether the ISA emitter supports its realization.

Native atomic emission requires an explicit ordinary coherent-RAM profile:

```sh
target/debug/ocorec implementation.ll --input-kind llvm-ir \
  --atomic-profile coherent-ram-v1 --emit mir -o implementation.json
target/debug/ocorec implementation.json --input-kind native-ir \
  --target riscv64-unknown-none -o implementation.o
```

`olangc --native-runtime CAPTURE --atomic-profile coherent-ram-v1` forwards
the same contract to every required imported unit and verifies the returned
profile. This profile excludes device memory. RV64 subword RMW/CAS also
requires the entire aligned containing word to be accessible coherent RAM
and the execution environment to provide the LR/SC eventuality property for
that region. The profile declaration does not establish starvation freedom
or physical memory-order qualification.

The current emitter supports naturally aligned i8/i16/i32/i64 and integral
AS0 pointer atomics in the built-in system and single-thread scopes on all
three ISAs. All fifteen integer RMW kinds are implemented. Compare-exchange
retains its original `{T, i1}` old-value/success result; weak CAS is realized
with a permitted strong retry. LLVM 22 accepts all fifteen combinations of
the five success orders and three failure orders, including a failure order
stronger than success. The hardware realization combines those requirements;
it does not apply the separate `.oc` CAS ordering restriction.

Value width is checked independently of padded allocation size. Underaligned,
wider, floating-point or custom-scope atomics that lack a supported realization
reject the whole module before assembly output. They are not replaced by byte
stores, erased fences or invented provider symbols. The scalar reference
interpreter rejects atomic execution explicitly. Compiler conformance tests
and platform qualification remain separate from complete upstream runtime or
compiler lowering and dependency admission.

`tests/test_ocore_native_atomics.py` executes whole LLVM text/bitcode modules
and unchanged Clang frontend output on x86-64, AArch64 and RV64GC. Its mixed
Clang/O-core pthread test checks neighboring byte/halfword updates, scalar
and pointer CAS, and release/acquire handshakes in both call directions.
The qualified twelve positive executions each produced
`OCORE-ATOMIC digest=5051ce3723e65451 checks=185624 threads=8 steps=2051`.
Separate corrupted-result, concurrency-only, wrong-object, source-contract
and ELF controls must fail. This emulator evidence does not qualify silicon
weak-memory behavior, exclusive-loop progress or the complete upstream
compiler and platform-provider closure.

`llvm.experimental.noalias.scope.decl` retains its exact external
`void(metadata)` declaration and a compiler-only scope marker. Metadata is
unsized and cannot enter ordinary storage, SSA values, native parameter/result
ABIs or address uses. The graph preserves module-local domain, scope and list
identities, distinct/uniqued storage, self references or arbitrary string bytes,
optional descriptions and original instruction sites with exact native ranges.
Verification requires a declaration list containing one actual scope and checks
full dominance between declarations of that scope, including different list
wrappers and cold blocks, without a declaration-count cutoff.
The nonoptimizing emitter emits no marker instruction and uses neither
`alias.scope` nor `noalias` promises to change computation. The declaration
remains in the whole-unit inventory but requires no runtime ABI or provider
symbol; ELF address and relocation uses reject. This conservative annotation
handling does not establish purity, a memory fence, ordinary metadata execution
or complete compiler/runtime support. Source import, native execution and
dependency closure remain separate qualification gates.

The eighteen source/API tests in `tests/test_ocore_llvm_noalias_scope_decl.py`
pass on the pinned LLVM boundary, preserving original graphs, instruction
ranges and whole authored LLVM/C/Rust fixture inventories. The malformed
metadata-global fixture produces `SIGILL` for all three target inputs in both
the pinned reference parser and the importer path; its evidence remains retained.
Those cases do not
establish structured import rejection or general parser safety.

`tests/test_ocore_native_noalias_scope.py` executes six unchanged authored whole
LLVM text/bitcode units on all three ISAs against original Clang 22.1.6 objects.
Twelve own/reference positives each pass 24,833 independent checks with digest
`a942d3ab3fb94d35`; twelve corrupted-oracle controls exit 31. Each unit retains
its complete 88-node graph, 42 scope markers, 13 attachments and eight original
function-owned call-frame entries. The gate also rejects 156 specific NativeIR
controls, twelve independent graph/site-range controls and twelve corrupted
ELF/call-frame objects. The immutable report SHA-256 is
`9da63a4b2ea670bdf46b56de66f4f3eb6d452a30c474e55d5ffa4b0f99a7a34a`.
This compiler regression uses freestanding Linux/QEMU carriers; it does not
qualify an upstream compiler implementation, provider lowering, dependency
closure, native OSTADIX execution or physical silicon.

Integer operations normalize to their declared width. Every legal LLVM shift
count is preserved, including non-power-of-two widths; poison-producing
overshifts remain a separately recorded refinement. Ordinary memory accesses
touch `ceil(width/8)` bytes even when LLVM allocation stride is larger, such as
an `i21` value with three stored bytes and four-byte allocation stride. Loading
an unusual integer width requires the frontend's defined prior-store contract;
unused high padding bits are unspecified. Odd three/five/six/seven-byte
volatile loads and stores reject the complete unit because byte splitting does
not establish equivalent volatile access semantics.
The six LLVM signed/unsigned add, subtract and multiply overflow intrinsics
retain both their width-normalized result and independent representability
flag for every width 1 through 64. Signed one-bit multiplication keeps its
mathematical overflow behavior: multiplying two negative one values overflows.
Their original typed intrinsic declarations remain in the complete inventory.
Aggregate constants retain their recursive types, including zero, empty,
undef/poison and nested pointer or symbol-offset leaves. Typed `extractvalue`
and `insertvalue` preserve their complete index paths. Aggregate phi, select
and freeze operate on the scalar leaves; parallel phi transfers snapshot every
incoming leaf before replacing any destination, including cyclic swaps.
Ordinary aggregate loads and stores use the original DataLayout field offsets,
array allocation strides and access alignment, including packed pointer fields.
Padding is not an SSA value and is not promised to retain a particular byte
pattern after an aggregate store. Empty structs and zero-length arrays have no
value leaves or ordinary memory accesses; their type alignment remains part of
surrounding layouts. Volatile aggregate accesses remain explicit in imported
IR but reject native emission. Fixed C and LLVM `fastcc` call plans retain the
original frontend's recursive integer/pointer parameter and result types,
extension attributes, register-block placement, stack arguments and implicit
result storage. Source-language aggregate coercions remain those of the
original frontend; they are not reconstructed from a struct's byte size.
`byval`, floating-point call classification and variadic calls remain explicit
unsupported whole-unit contracts.
Typed LLVM `sret` keeps a void result and its original pointer parameter in the
first or second position. The signature records the sized in-memory result type
as `return_storage`; declarations, definitions, calls and alias bindings must
agree. x86-64 and RV64 keep the pointer in its ordinary argument position;
AArch64 passes it in `x8` while ordinary arguments use their own register/stack
sequence. x86-64 restores the original result pointer in `rax` on every return,
including after nested calls. Result-pointer metadata performs no initialization
or memory access by itself, and sized empty result types remain valid.
The scalar RV64 profile also preserves explicit `lp64d` frontend ABI metadata
and the actual ELF double-float ABI flags; this admission does not qualify
floating-point computation or aggregate register classification.

PIC/PIE flags are admitted only under a recorded static, nonpreemptive image
contract. Symbol visibility remains explicit: default, hidden and protected
definitions and declarations retain their ELF visibility, and closure combines
the strongest reference constraint. This does not qualify dynamic interposition
or shared-library loading. Defined-function LLVM `UWTable` requirements are
preserved by the instruction-precise call-frame metadata described below.
Ordinary declaration Sync/Async requests retain their parsed level and source
site in provenance, together with the original declarations, calls and
dependencies. Consumer objects emit call-frame entries for their own defined
functions; external provider unwind tables and exception services require
separate qualification. The static Itanium/DWARF exception profile below
preserves recognized personalities and EH operations. Other EH models and
unsupported surviving callsite or intrinsic unwind requests reject the whole
unit. The importer records the original input digest and the pinned parser's
normalized attribute values.

Local constant tables may retain 32-bit relative initializers with explicit
target symbols and signed addends. Their base is the containing private or
internal non-TLS global; targets may be ordinary globals, functions or direct
aliases. Same-section differences retain exact resolved bytes, while other
entries use x86-64 PC32, AArch64 PREL32 or paired RV64 ADD32/SUB32 relocations.
The source `llvm.load.relative.i32` and `.i64` declarations remain in the whole
inventory. Their calls lower to signed byte-offset addressing, a four-byte
load, sign extension and addition to the original base. This is the static,
nonpreemptive image profile; it does not qualify dynamic interposition or
every image-range/code-model combination.

`tests/test_ocore_native_relative.py` executes six unchanged authored LLVM
text/bitcode units on all three ISAs against original Clang 22.1.6 objects.
Twelve owned/reference positives each pass 2,811 checks with digest
`f584e5ddafffa6ab`, including shifted bases, negative in-bounds load offsets,
packed table storage, signed target addends, external/alias targets, valid data
reads and indirect callbacks. An independent ELF decoder checks 108 table
entries across the six owned objects and rejects 30 corrupted byte/relocation
objects; 24 of those also fail actual execution, as do 12 corrupted-oracle
controls. The immutable owned report SHA-256 is
`09845d585cbf595bd8c8be17eb97b193a7944dce6415c6a7ed3ac22756152499`.
This compiler fixture evidence uses Linux/QEMU carriers and explicit test
providers; it does not establish lowering or closure of an upstream engine.

LLVM `weak` function and global definitions retain their bodies, initializers,
relocations and actual ELF weak bindings. Symbol closure selects a compatible
strong definition over weak definitions, or the first weak definition in the
supplied module order. Every candidate must have the exact ABI/storage contract
and sufficient selected-provider alignment, including overridden definitions.
The original build's ordered link membership is separate evidence; a supplied
module order alone does not qualify complete runtime linking. `linkonce`,
`linkonce_odr` and `weak_odr` definitions and direct aliases retain their exact
linkage names and ELF weak bindings. `extern_weak` declarations, common and
`available_externally` definitions remain unsupported whole-unit contracts.

ELF `any` and `nodeduplicate` COMDAT groups keep code, globals and their
relocation sections together. Direct aliases inherit their included root's
group. Selection occurs before ordinary symbol resolution: the first `any`
group wins in supplied module order; every `nodeduplicate` group remains,
including when an `any` group uses the same signature. Nongroup definitions
from losing modules remain. Object admission checks actual group signatures,
flags, member sections and relocation targets against the verified module.
Unsupported ELF selection policies such as `exactmatch`, `largest` and
`samesize` reject the whole unit rather than changing the selection rule.

Direct aliases retain distinct names for existing code or storage in the same
module. The alias value type must exactly match its defined function or global;
alias calls inherit the function's complete ABI contract. Aliases keep their
own linkage and visibility, address operands and relocations, without copying
bodies or data. A strong replacement for a weak root name does not retarget an
alias that still names the original object position; replacing a weak alias
does not replace its strong root. Alias chains, surviving constant expressions,
nonzero offsets, type casts, TLS, IFUNC and unresolved targets remain unsupported
whole-unit contracts.

Alignment import retains the full LLVM maximum of 2^32 bytes even when the
uint32 C API accessor returns zero. Audited bitcode preserves symbol alignments;
mandatory alloca/load/store alignments retain that maximum without substituting
a default. Native emission rejects an alignment it cannot realize before
writing an artifact. Ordinary AS0 pointer results and fixed parameters may
carry validated `align`, `dereferenceable` and `dereferenceable_or_null`
promises. Their full-width payloads remain in provenance; native code does
not optimize, allocate memory, speculate or add guards using these promises.
The pinned LLVM reader/writer may normalize attributes, including dropping
the maximum parameter alignment from serialized bitcode. Imports bind the
exact original bytes and parsed contract; they do not invent a promise absent
from the input module.
Function alignment is explicit independently of signatures. Native definitions
realize at least the requested alignment and the target's instruction alignment;
unmaterializable definitions reject before emission. RISC-V modules disable
assembler relaxation throughout the module so later aligned functions remain
aligned without pending `R_RISCV_ALIGN` or `R_RISCV_RELAX` fixups. The source
frontend and the assembler used for O-core's own code are recorded separately
in the conformance receipts.
Validated pointer-parameter `readnone` and `dead_on_unwind` promises and
function/callsite `allockind` descriptions are recorded and erased without
removing bodies, calls, memory operations or dependency symbols. Their presence
does not establish purity, substitute an allocator or implement unwinding.
Unsupported placements, payloads and actual ABI or exception-handling features
still reject the whole unit.
Validated function and callsite `allocsize` promises retain their exact raw
LLVM payload and zero-based element/count parameter indices. The reserved
count sentinel means no count parameter. Each referenced parameter must have
a supported integer type, and the result must retain the supported pointer
contract. Normalization erases this optimization promise while retaining every
original call, body, memory access and dependency. It does not imply a fresh
allocation, non-null result, pointer uniqueness, purity or an allocator
replacement. Unsupported companion contracts reject the complete unit,
including unused definitions.

Literal integer-to-pointer constants preserve exact 64-bit integral AS0
address representations under [LLVM's zero-extension rule](https://llvm.org/docs/LangRef.html#inttoptr-to-instruction).
Source integers of widths 1 through 64 are compile-time constants: `i8 -1`
becomes 255 and `i64 -1` becomes all ones, without adding unsupported executable
integer widths. Initializers contain these literal bytes without relocations;
verified instruction operands use the typed `pointer_bits` representation.
Symbol and GEP initializer addresses retain real relocations. Constant GEP
operands in executable SSA preserve the tracked symbol or direct alias and
their signed 64-bit byte offset. Layout uses the source's struct, packed and
array types; integral AS0 pointer arithmetic wraps at 64 bits. The emitter
resolves the base address before adding the offset, including negative and
extreme offsets. These address bits do not grant access outside valid storage.
Surviving unsupported wide
integer-to-pointer operands, nonintegral or nonzero address spaces and unresolved
symbolic pointer arithmetic reject the whole unit. The pinned LLVM reader may
already normalize a wider expression into null, poison or undef; supported
parsed pointer contracts remain bound to the exact original input SHA-256.
Literal address bits do not establish mapping or dereference validity.

Unsupported operations, ABI features or hidden bitcode fields reject the whole
unit before code artifacts are written. Floating-point computation and call
classification, `byval`, ordinary variadics, dynamic TLS/DSO loading, additional unwind models,
general dynamic stack allocation,
managed execution and runtime-generated code publication remain required work.
Weak/common/ODR linkage is not silently converted into strong linkage, and
unaligned wide volatile accesses are rejected where the emitter cannot preserve
their required access width. Frames and outgoing arguments probe intervening
stack pages; RISC-V long jumps do not assume a small control-flow graph.
Imported functions emit DWARF call-frame information for their saved frame
pointer and return address, including prologue, epilogue, and multiple-return
states. Their fixed frame pointer anchors unwinding through stack probes and
outgoing argument allocations. Call-frame information alone does not supply
an exception personality or the native platform's unwinder.
`scripts/check_ocore_native_cfi.py` independently decodes the actual object
unwind rows at instruction boundaries for nine functions across the three
ISAs, including stack probes, outgoing arguments and multiple returns. Nine
deliberately corrupted metadata controls must be rejected. This gate checks
call-frame metadata separately from exception handling and runtime execution.

The imported native IR admits the explicit `itanium_dwarf_v1` exception model
for static, nonpreemptive ELF images on all three ISAs. It retains direct and
indirect `invoke` calls, their distinct normal/unwind edges, canonical
`landingpad {ptr, i32}` values, ordered catches and exclusion filters,
`llvm.eh.typeid.for` selector queries and `resume`. A null catch-all, cleanup
selector zero and an empty exclusion filter remain distinct. Invoke results
exist only on the normal edge; shared landing-pad PHIs retain their original
predecessors. Each emitted invoke landing entry saves the exception pointer
and selector before PHI scratch moves, then discards outgoing arguments using
the fixed frame pointer. Fixed entry allocations support alignment through
16 bytes; this profile does not admit dynamic allocas.

Personality references and LSDA/typeinfo table pointers use full 64-bit
absolute relocations. CIE/FDE ranges, call-site intervals, ordered action
chains, reversed type tables and filter byte offsets remain source-bound.
EH-derived sections and relocations stay attached to their source `any` or
`nodeduplicate` COMDAT groups. Metadata-only source `i32 (...)` personality
declarations retain their original signature and require the separate
five-argument C unwinder callback ABI at closure. Ordinary address uses,
including cold code, aggregate constants, aliases and initializer relocations,
remove that exemption. Actual `resume` operations require the typed external
`_Unwind_Resume` interface; no provider implementation is invented. Production
object admission checks these tables, symbol identities and relocation
contracts against the verified IR. Its CFI instructions remain structural
evidence; production admission does not execute CFA rows or establish machine
code equivalence. Other EH models, arbitrary personality signatures, dynamic
interposition and JIT table publication remain required work.

The independent `tests/test_ocore_native_eh_objects.py` gate decodes raw ELF,
CIE/FDE, DWARF CFA instructions and LSDA bytes without the production decoder.
Six unchanged authored whole LLVM text/bitcode inputs pass actual CLI import
and owned object emission on all three ISAs, retaining 12 source functions,
132 globals, two aliases and two COMDAT groups per unit. Their 48 function
FDEs, 168 call-site entries and 672 selected CFA-row checks pass; 84 distinct
corrupted metadata objects reject. Cases include large fixed locals,
16-argument direct/indirect calls, shared landing pads, 130 named typeinfos,
catch-all/cleanup/duplicate and empty filters, cold inventories and grouped
tables. The immutable report SHA-256 is
`e3c5238e36adabd24523a7eb4461d4e070f22d411718405c8d6bfa6bae319dd3`.
This is source import and object metadata evidence; it does not execute an
exception unwinder or qualify a runtime/compiler implementation.

A separate genuine Clang C++ consumer runs with owned code on x86-64 and
under AArch64/RV64 QEMU, linked to complete unchanged source-built Linux/musl
reference providers: musl, libc++abi, libunwind, compiler-rt and startup objects.
Its typed `long long` catch, selector lookup, catch finalization and unmatched
`int` exception resume to the reference caller pass on all three ISAs. These
reference providers have not been lowered through O-core. The execution report
SHA-256 is
`95458ea8007e6a1c9638fd8aa8ea2f0b19f811fddc44d63e63f96c8b2ce023b9`.
This Linux execution witness does not qualify complete upstream rustc/Cargo,
O-core provider closure, OSTADIX kernel services, hardware-silicon behavior,
dynamic loading or JIT publication.

The permanent `tests/test_ocore_native_eh_execution.py` gate extends genuine
Clang C++ execution to RAII cleanup order, typed and shared landing-pad
catches, rethrows, unmatched resume, exclusion filters, 16-argument calls and
32,768-byte fixed frames. Six unchanged LLVM text/bitcode units run owned and
original Clang objects on all three ISAs: 12 positives each pass 160 cases and
1,048 checks with digest `a0b83e958b4b04dd`; all 12 corrupted-oracle controls
fail. Original musl/libc++abi/libunwind/compiler-rt/startup providers remain
hash-bound reference code, with complete ordered link traces. The report
SHA-256 is
`cd46dbd771b6a27e80a7d2083a911317a2b001e01bc6a23d2a6ce4b4eaf2b038`.
This uses the earlier streamed EH compiler freeze, separately from the later
relative-table proof. Provider lowering, entire rustc/Cargo execution, complete
dependencies, OSTADIX services, silicon and JIT publication remain unqualified.
CI reports an explicit skip when the immutable original provider set is absent.

TLS lowering requires explicit `--tls-profile` admission with
`linux-elf-static-nonpreemptive-v1`. The imported globals retain
their original general-dynamic, local-dynamic, initial-exec or local-exec model;
this static, nonpreemptive Linux ELF profile realizes current-thread addresses
using native local-exec access. The verified `thread_local_address` operation
is distinct from an ordinary symbol address. Initialized templates, zero-fill,
source alignment and ordinary pointer relocations retain their source contracts,
and owned ELF storage retains `STT_TLS` symbols and `SHF_TLS` sections. Missing
or incompatible profiles, model/storage mismatches and static initializer
references to a thread-specific address reject the whole unit. Dynamic
interposition, DSO/dlopen TLS and native OSTADIX thread/loader services require
their own supported profiles.

The permanent `tests/test_ocore_native_tls_execution.py` gate preserves six
unchanged genuine Clang C11 LLVM text/bitcode units across all three ISAs. Each
retains four function definitions, 12 globals including ten TLS globals, all
four source model kinds and 51 current-thread address operations, including
cold definitions. Real musl pthreads exercise the main thread and two workers,
32 mutations per worker, 16-argument calls, initialized/zero/packed-pointer
templates and 64-byte alignment. All 12 owned/original positive executions
produce 1,163 checks with digest `177b568fc709ffda`; all 12 corrupted-oracle
controls fail, and all 78 malformed admission contracts reject with their
intended diagnostics. The corrected test supplies the original pointer type to
the raw TLS symbol cases, so those cases reach the semantic address guard.
Final report SHA-256:
`12760ce36bb0f00e47b894720cb9d0a7812bd1fe1682bc38344c6ae29eef3d44`.
The earlier `d313c104` execution evidence remains archived separately; its six
raw-symbol negatives reached a missing-field guard before the intended rule.
The V2 compiler freeze preserves the earlier AArch64 assembly failure and its
unchanged inputs, then qualifies the corrected instruction encoding. The
original musl thread and loader providers remain hash-bound reference code;
provider lowering, complete rustc/Cargo, dependencies, dynamic loading, OSTADIX
services and silicon execution remain unqualified. CI records an explicit skip
when the immutable original provider set is unavailable.

The opt-in `olangc --native-runtime` driver consumes a complete source capture
report and independently imports/verifies every required unit, emits optional
O-core objects, and checks cross-module symbol and ABI closure. Its coverage
receipt retains failures and distinguishes unit lowering from closure and native
qualification. See [capture recipes and driver usage](../tools/ocore-runtime/README.md).
Admission independently reconstructs the unit partition and observed final
output/link/archive graph from the original build journal and hashed source,
inventory, logs and tools. Editing a report's completeness flags or mutually
consistent selection lists cannot replace those checks. Object admission
checks actual definition inventories, executable/storage permissions, symbol
bindings, visibility, alignment and the selected ISA's ABI flags.
Source-defined globals additionally require exact ordinary initializer bytes
and each supported ABS64 relocation's offset, target and addend, with qualified
local-section folding and distinct exported/weak alias identities. A separate
original-Clang data-reader comparison passes on all three ISAs for 15 globals
and 33 absolute relocations. Code and CFI relocation admission remains
structural; these data checks do not establish machine-code or runtime closure.
Compiler wrappers execute a frozen, read-only capture-worker snapshot and bind
each invocation to its digest, wrapper inventory and Python interpreter hash.
Re-admission requires the worker digest trusted by the embedded verifier;
rewriting a journal cannot choose another implementation or mix worker versions.
Legacy unbound captures require a fresh capture for admission. They may still
serve explicitly incomplete diagnostics.

An explicit recipe setting, `toolchain.rust_capture_policy:
"rust-embedded-bc-v1"`, captures the original Rust producer's embedded LLVM
bitcode instead of invoking a second Rust frontend. It records incoming argv,
response-file bytes, executed argv and the capture transformations separately.
Every retained CGU binds the exact object or indexed archive member, its
`.llvmbc` section range and the extracted bitcode bytes. Metadata-only members
remain resources. Missing or unsupported original edges remain gaps; saved
temporary filenames do not establish ownership. The policy is opt-in and does
not change the default capture recipe.

Readmission rederives all original output/member edges and rejects omitted,
duplicated or changed CGUs. Rust response files retain their actual single-level
LF/CRLF line semantics. Unsupported argument forms forward the original
invocation and status while recording a capture gap. A queried sysroot compiler
or Cargo binary remains a candidate unless its resolved path, digest and size
match the executable actually selected for that invocation.

The combined capture gate passes 165 tests with no skips on one frozen worker,
including an original offline three-crate Cargo workspace, its build script,
parallel compilation and a direct response-file invocation. This establishes
the tested capture behavior. Embedded bitcode membership does not establish
source-production ownership, ordered executable CGU membership, post-LTO
equivalence, provider closure or complete Rust compiler lowering. These remain
separate admission requirements.

It does not yet link a complete runtime, attach `.O` scripts, or lower OIR.
The C and Rust differential gates in `scripts/check_ocore_import_equivalence.py`
and `scripts/check_ocore_foreign_frontends.py` exercise actual foreign frontend
output on all three ISAs. Their Linux test carrier is compiler evidence,
not the full native runtime acceptance gate. The Java fixture is a separately
identified reference and method-inventory check, not managed-code lowering.
The 15 tests in `tests/test_ocore_native_runtime.py` exercise a real pinned
Clang 22.1.6 source capture, unused-body retention, own-object execution, and
rejection of altered inventory, role, source, hash and output-graph evidence.
The weak-definition gate in `tests/test_ocore_native_weak.py` compares 24 own
object executions with 24 original Clang 22.1.6 executions across all three
ISAs and both unchanged LLVM text and bitcode inputs. Each execution checks
324 independent results; six corrupted oracle controls reject. It verifies
strong-over-weak and first-weak selection in both object orders, actual ELF
bindings and visibility, unused definitions, globals and pointer relocations.
These compiler checks do not establish that the original Rust compiler or any
complete runtime has been lowered.
The direct-alias gate in `tests/test_ocore_native_alias.py` compares 40 own
executions with 40 original Clang 22.1.6 executions across all three ISAs and
unchanged LLVM text/bitcode; eight corrupted oracle controls reject. Each run
checks 391 values, including indirect calls, writes through alias pointers,
address identity and separate strong overrides of root and alias names. Actual
ELF symbols retain alias position, type, extent, binding and visibility.
The RISC-V gate checks both default and disabled linker relaxation, with 64-byte
alignment on the first function and a later function after a call-containing
body. Original Clang objects may defer alignment to linker fixups; both linked
implementations must realize the source alignment. This remains compiler
conformance on Linux carriers, with complete original compiler/runtime and
native-platform acceptance unfinished.
The COMDAT gate in `tests/test_ocore_native_comdat.py` compares 72 own object
executions with 72 original Clang 22.1.6 executions across all three ISAs and
unchanged text IR/bitcode. Whole-group tests check 395 or 786 results per run;
mixed `any`/`nodeduplicate` tests check 788. Six corrupted oracle controls fail.
Actual ELF checks retain internal helpers, aliases, grouped pointer relocations
and exact ODR bindings. A real partial link retains both non-deduplicating
groups with the same signature; 12 original/own link controls reject duplicate
strong definitions. A separate fresh pinned C++ capture lowers all three
required units in both build orders and checks group winners, alias attachment
and source ownership in the driver's supplied module order. Its linked own
objects execute on the Linux carrier; dependency closure, complete engine
lowering and native-platform qualification remain false.
The symbolic-offset gate in `tests/test_ocore_native_symbol_offsets.py` compares
six own executions with six original Clang 22.1.6 executions across unchanged
text IR/bitcode and all three ISAs. Each run checks 643 byte/address results
with digest `8e7cb2e870717170`; six corrupted oracle controls fail. It covers
packed and negative offsets, nested GEPs, narrow signed indices, alias identity,
comparisons, select/phi/return, pointer stores and valid memory loads. Direct
and indirect calls each pass 16 mixed pointer/integer arguments, including
stack arguments and extreme opaque address bits. The reference records a
static large code model; invalid opaque addresses are never dereferenced.
This remains compiler conformance on Linux carriers.
The trap gate in `tests/test_ocore_native_trap.py` compares six own safe
executions with six original Clang 22.1.6 executions across all three ISAs and
unchanged text IR/bitcode. Each checks 162 results with digest
`c99b255a111e087d`; six corrupted oracle controls fail. Thirty own and thirty
original executions test unconditional, conditional, nested and unused cold
traps. Each own fatal status matches its original reference on the same target:
x86-64 and RV64 report illegal instruction, while AArch64 reports a breakpoint
trap. The complete imported module retains post-trap source continuations and
dead blocks, and emits real unused definitions; those continuations never run.
Numeric fault signals across ISAs, debugger behavior and native OSTADIX fault
delivery require separate execution-profile qualification.
The three tests in `tests/test_ocore_native_integer_widths.py` cover all integer
widths 1 through 64 using 24 executions across all three ISAs and unchanged
text IR/bitcode. All four own/original Clang caller-callee combinations match
an independent Python oracle: 104,352 checks per run produce digest
`9f27d5340f9ad630`, with six corrupted oracle controls. Every legal shift count,
signed comparisons, safe divisions and width conversions are covered. Exact
LLVM signatures exercise direct/indirect unusual-width returns and 16 mixed
integer arguments without mismatched C declarations. Same-type memory round
trips check masked value bits, sentinels and both protected-page edges.
Ninety-six cold odd-byte volatile units reject without object artifacts.
Separately, own and original RV64 LP64 executions check 960 physical ABI values
for explicit `zeroext`/`signext` i32 direct/indirect returns, register arguments
and ninth stack arguments; two corrupted oracle controls fail. These remain
Linux carrier compiler checks, not complete Rust compiler lowering or native
OSTADIX runtime acceptance.
The eighteen source/API methods in
`tests/test_ocore_llvm_integer_overflow.py` extend the rerun 298-method cohort
to 316 distinct passing methods with zero skips on the same frozen importer.
Authored whole C/C++ producer fixtures emit all six intrinsic families; Rust
1.97.1 fixtures emit four, with unsigned add/sub represented by ordinary
arithmetic and comparisons. Original inputs, types, unused inventories and
genuine RV64 LP64D producer contracts remain intact. These contracts refer to
the pinned LLVM 22 parsed module: its AutoUpgrade canonicalizes some named or
packed intrinsic results and declaration attributes, while explicit
extract/insert operations reconstruct the original caller result. Original
input hashes remain bound, and surviving unsupported callsite ABI extensions
reject. No original source or IR is manually rewritten. This source-only
cohort has report SHA-256
`d0f79e15ab9a508a08d8a863cd35ab8810237de82f8e2f5ac559a5ff89a629c9`;
it does not qualify subsequent importer versions or complete implementations.
The two native methods in `tests/test_ocore_native_integer_overflow.py`
qualify all six signed/unsigned overflow families for every width 1 through 64
on unchanged text IR and bitcode across all three ISAs. Six whole units retain
384 intrinsic declarations and matching wrappers per unit, plus unused
definitions, globals and aliases. Twelve own/original positive executions each
match 67,566 cases and 2,229,684 independent checks with digest
`c97fef32dd39d34b`, totaling 26,756,208 successful checks; 24 corrupted oracle
or cold-global controls reject. The unbounded Python oracle exhausts input
pairs for widths 1 through 5 and uses boundary and deterministic full-width
inputs for the remaining widths. Typed scalar stores precede same-type loads;
unused high bits are masked while allocation padding and outside canaries
remain checked. Independent source tracing retains all 384 exact intrinsic
kind, signedness, operand, result and declaration mappings per unit. This
matrix uses RV64 LP64 and Linux test carriers; compile-only whole-source
audits and full compiler/runtime, dependency and native OSTADIX acceptance
remain separate.
The three tests in `tests/test_ocore_native_sret.py` compare 24 own/original
Clang caller-callee executions for unchanged LLVM units across all three ISAs
and text IR/bitcode. Every run checks 24,329 result words, initialized bytes and
canaries with digest `8c7fd0ed8d006ac4`; six corrupted data oracles fail. Exact
signatures exercise first/second-position result pointers, nine ordinary
arguments, aliases, indirect calls, nested clobbers, multiple returns and empty
or no-access bodies. Eight x86 assembly observations per execution check the
original hidden-pointer return; two corrupted pointer oracles fail.
Another 24 mixed executions of genuine unchanged Clang 22.1.6 C++ units check
6,241 values per run, with digest `5b1b22bd3579116b` and six corrupted controls.
They preserve the frontend's actual result-pointer ordering and emit unused
original definitions. Both suites retain genuine RV64 LP64D object and linked
image flags. Ten malformed result-storage contracts reject stale receipts and
object output, with assertions for each intended diagnostic. The non-void
result case uses an unused declaration to isolate that signature guard.
These are typed ABI compiler checks on Linux carriers; complete
original compiler/runtime lowering and native OSTADIX acceptance remain open.
The two tests in `tests/test_ocore_native_allocsize.py` qualify unchanged LLVM
and genuine Clang 22.1.6 C units across text IR/bitcode and all three ISAs.
Twenty-four whole modules retain unused bodies, globals, aliases, raw promises,
direct/indirect calls and ordinary/volatile memory operations. All 48
own/original caller-callee combinations match 130,372 independent checks per
run with digest `4156eb592a5f5175`; 24 corrupted oracle or object controls fail.
Requests include zero, bounded successful sizes, nullable failures and
multiplication overflow. Successful calls retain repeated static pointer
identity and observable effect logs. These qualify metadata normalization on
Linux carriers, with complete runtime/compiler and native-platform gates false.
The aggregate source suite in `tests/test_ocore_llvm_aggregates.py` adds 17
passing methods to the prior 271-method source cohort. It preserves whole
authored LLVM, C/C++ and Rust fixture inventories across all three ISAs and
text IR/bitcode. The generic LLVM cases exercise aggregate SSA; genuine Rust
positives qualify copy/storage and layout fixtures. The original typed-read
fixture with `!noundef` metadata was retained as an explicit whole-unit rejection
for unsupported metadata kind 29 at that historical aggregate-SSA freeze.
No LLVM input filtering or complete Rust compiler
lowering is claimed by these fixture checks.
The two tests in `tests/test_ocore_native_aggregates.py` qualify aggregate SSA
and ordinary memory operations with scalar C call signatures. Twelve unchanged
whole units cover original LLVM and genuine Clang 22.1.6 C output, text
IR/bitcode and all three ISAs. Twenty-four own/original positive executions
each match 169,739 independent checks with digest `82029e218c82bf13`; 48
corrupted oracle or cold-global object controls exit 31. Nested insert/extract,
cyclic aggregate phi swaps, defined freeze results, packed and ordinary
layouts, empty values, pointer aliases and indirect scalar calls are covered.
The oracle checks defined fields, original input padding and external canaries;
padding after aggregate stores is unobserved. Explicit byte-loop `memcpy` and
`memset` helpers are Linux test-platform providers, not imported runtime closure
evidence. Aggregate call ABI, exception handling, complete compiler/runtime
lowering, dependency closure and native-platform qualification remain false
for this scalar-signature gate.
The separate `tests/test_ocore_native_aggregate_edges.py` supplement qualifies
runtime aggregate select, simultaneous phi swaps and packed/natural nested
`i1`/`i21`/`i33`/`i40`/`i63` fields. Six unchanged LLVM text/bitcode units execute
through own and original Clang objects on all three ISAs: 12 positive runs each
match 1,860,803 checks with digest `e22ba1d7f7322bb8`, and 24 corrupted oracle
or cold-global controls exit 31. Original typed scalar stores initialize every
field before aggregate loads, preserving the same-type store contract for
non-byte integer widths. The oracle checks defined integer bits, pointer
identity, original 45/48-byte array strides, input allocation padding and
external canaries. Unused high integer bits and output aggregate padding remain
unobserved. This corrected typed-input receipt is separate from the earlier
byte-initialized attempt; it does not qualify aggregate call ABI or complete
engine/native-platform execution.
The separate `tests/test_ocore_llvm_aggregate_abi.py` adds ten source/API methods
for fixed C and LLVM `fastcc` contracts. Its immutable source cohort contains
298 distinct passing methods with zero skips: the rerun 271-method baseline,
17 aggregate SSA methods and these ten ABI methods. Whole authored LLVM and
genuine C/C++/Rust producer fixtures retain their original types, conventions,
attributes and unused inventories; this source evidence does not qualify a
complete runtime or compiler implementation.
The three methods in `tests/test_ocore_native_aggregate_abi.py` qualify fixed
C/LLVM `fastcc` integer/pointer aggregate boundaries against original Clang
22.1.6 objects. Thirty-six unchanged whole LLVM, C and C++ text/bitcode units
run all four own/original caller-callee combinations on all three ISAs:
72 positive executions and 144 corrupted oracle or cold-global controls.
Raw LLVM runs each match 780,485 checks with digest `0fdd52060e49c397`;
C/C++ runs each match 120,243 checks with digest `2abfb0a55e38535c`.
Direct, indirect and alias calls cover aggregate results, register overflow,
stack arguments, nested clobbers, explicit result storage and large `fastcc`
frames. Independent source inventories retain all calls and 310 exact owned
memory-intrinsic mappings. Seven unsupported `byval` units reject object output
with the intended diagnostics. This matrix uses RV64 LP64; the genuine LP64D
scalar/result-storage evidence above remains separate. The matrix does not
observe x86's implicit hidden-pointer return in `rax`, and aggregate padding
remains unobserved. Floating-point, exception handling, full compiler/runtime
lowering, dependency closure and native OSTADIX qualification remain false.
The eight source/API methods in
`tests/test_ocore_llvm_uwtable_declarations.py` qualify ordinary declaration
Sync/Async/bare requests on the later declaration-UW compiler freeze. Their
231 records preserve complete source inventories, exact parsed levels/sites,
calls, narrow ABI attributes and globals; pinned LLVM intrinsic normalization
and injected surviving-boundary rejections remain separately identified.
The earlier 316-method cohort above is bound to its own importer freeze.
A separate object bridge imports and verifies eighteen authored whole text
IR/bitcode units across all three ISAs. Each own object contains three FDEs
for its three source-defined functions, with no declaration body or unwind
entry. All 54 decoded intervals match the corresponding ELF function value
and size. This qualifies counts and ranges, without CFA-row or runtime
unwinding claims. Its report SHA-256 is
`ac11db1d75921cb123d288b45e25c42880d3cd3157043e8f9058ba149df2a088`.
The same freeze imports, verifies and emits an own x86-64 object for one
unchanged original `unicode-ident` unit, retaining 15 functions, ten function
definitions and 17 globals. Four original panic providers remain undefined.
This unit has an installed/other producer; its final Cargo payload role and
source-built compiler membership are unproven. This compile-only evidence
does not establish execution, provider/dependency closure, exception services
or complete compiler/runtime support. Its report SHA-256 is
`3ab01489cfb707fe00897224e78812e300bd9afb8ef84901927383e4a7ac5ebd`.
The immutable `import-audit-fixed-whole-llvm-aggregate-abi-20261010` diagnostic
attempts all 2,434 whole units in its fixed snapshot of finished original
LLVM source-build units. All 236 imported units pass independent verification
and produce own x86-64 objects, retaining 1,499 original function definitions,
3,314 global definitions, 101 aliases and 533 referenced COMDAT groups. The
normalized inventory also retains declarations: 3,332 functions and 3,542
globals in total. Remaining units retain their explicit whole-unit import or
input failures. All prior 182 admitted units remain, and 54 additional whole
units now produce objects after aggregate ABI support; those additional units
retain 715 function and 2,395 global definitions. In total, 416 units change
their first diagnostic, which does not establish complete unit support.
Updated artifacts differ for 149 prior object/module records, so earlier
byte-identity evidence does not qualify those updated artifacts. Recorded
failures include TLS, special initialization globals, metadata kind 29,
vector/floating-point types, atomic memory operations, additional intrinsics
and unsupported ABI attributes. The completed audit is source-unit object evidence; complete
original Rust/LLVM compiler lowering, dependency closure, generated-program
routing and native execution remain unqualified. Its report SHA-256 is
`60db6badab3b59acf31e24a9bfc08423b2f8022ab5d949ef099a8585e774e7df`.
A separate immutable `import-audit-fixed-whole-rust-aggregate-abi-20261010`
diagnostic attempts all 1,614 captured original Rust LLVM units and produces
208 independently verified own x86-64 objects. Of these, 179 contain no
function or global definitions; only 29 contain definitions, totaling 39
function and 69 global definitions. Producer identities remain distinct: 131 objects
come from source-built producers (117 empty, 14 nonempty, retaining
14 function and 40 global definitions), while 77 come from installed or other
producers (62 empty, 15 nonempty, retaining 25 function and 29 global
definitions). A producer identity does not establish final compiler payload
membership, and these objects do not preserve an original `rustc` or Cargo
compiler implementation. The four additional admitted units contain installed
`core` helper instantiations for a build script; the source-built object count
is unchanged. This audit uses the aggregate-ABI compiler/importer freeze,
before the later overflow-intrinsic support. The diagnostic retains two malformed legacy journals, 1,316
unbound attempts, three original failed build attempts and two missing extra
LLVM outputs. Its completed audit and receipt reconciliation leave complete
Rust compiler lowering, source-production inventory, dependency closure,
generated-program routing and native execution unqualified. Report SHA-256:
`69cdf93d0589e57205e9bae281116c2e2c0c1d0dd455a70bebc19551986fc320`.
The later pre-EH overflow/declaration-UW audit attempts the same 1,614 original
Rust units and produces 265 own objects: 179 empty and 86 with definitions,
retaining 267 function and 267 global definitions. Source-built producers
account for 154 objects (117 empty, 37 nonempty, 108 function and 139 global
definitions); installed/other producers account for 111 (62 empty, 49
nonempty, 159 function and 128 global definitions). The additional source
bodies are genuine dependency/helper implementations, not an admitted rustc
or Cargo compiler implementation. Installed origins and unproven final payload
roles remain separate. No complete compiler, dependency closure, generated
output routing or native-platform qualification follows from these objects.
Report SHA-256:
`cd28d9185a0201134a85cef716720564995242c5a4613e40ab1cae824c2c5c9f`.
The later immutable noalias-scope audit attempts all 1,614 unchanged Rust
units and emits 408 independently verified own x86-64 objects: 229 with
definitions and 179 empty. Source-built producers account for 233 objects
(116 nonempty, 117 empty); installed/other producers account for 175
(113 nonempty, 62 empty). All 375 previously emitted objects remain
byte-identical, and 33 additional whole units retain 280 original function
definitions and 296 global definitions. Across all admitted units the
inventory retains 1,823 function definitions, 3,048 global definitions and
23 aliases. The remaining 1,206 units have explicit import failures.
This source-unit audit precedes atomic support. It does not establish final
compiler payload membership, complete source-production/dependency closure,
generated-program routing, a linked compiler or native compiler execution.
Report SHA-256:
`094027d68fccc1ecfe8cb5730760601d4f777ce8112efe53339e86b4f38d622c`.

The following immutable coherent-RAM atomic audit again attempts all 1,614
unchanged Rust units. It emits 429 independently verified own x86-64 objects:
250 with definitions and 179 empty. Source-built producers account for 247
objects (130 nonempty, 117 empty); installed/other producers account for 182
(120 nonempty, 62 empty). All 408 previous ELF objects remain byte-identical.
The 21 additional whole units retain 112 original function definitions, 190
global definitions and five aliases. The full admitted inventory contains
1,935 function definitions, 3,238 global definitions and 28 aliases. Module
JSON changes retain the newly explicit profile, scope and provenance fields;
the unchanged ELF comparison is a separate check. This remains a partial
source-unit audit, with 1,185 units still unsupported. It does not qualify
final compiler payload membership, complete source production or dependency
closure, generated-program routing, a linked compiler, cross-ISA compiler
execution or an OSTADIX platform port. Report SHA-256:
`91e3e286f255251ef72b144d257afe9e9017d97ede80d272667b432c9fd8a8b1`.

The next immutable integer-min/max audit attempts the same 1,614 unchanged
original Rust build units. It emits 458 independently verified own x86-64
objects: 279 with definitions and 179 empty. All 429 earlier ELF objects
remain byte-identical; 29 additional whole units retain 388 original function
definitions, 758 global definitions and two aliases. The complete admitted
inventory now contains 2,323 function definitions, 3,996 global definitions
and 30 aliases. Source-built producers account for 266 objects (149 nonempty,
117 empty); installed/other producers account for 192 (130 nonempty, 62
empty). Only 18 nonempty units are compiler-source payloads, drawn from nine
source files. These counts include dependencies and repeated symbols and
must not be presented as 458 distinct Rust compiler components or a completed
compiler.

The original sources of the 29 additional units retain 68 integer-min/max
calls, 80 atomic operations and 758 initializers. Independent source and ELF
readback checks the initializer bytes, relocations, original metadata graph
and structural unwind envelopes. It does not establish native body execution,
calling-convention correctness, physical memory ordering or runtime TLS
services. The remaining 1,156 units fail explicitly; vectors, floating-point
operations and formats, wide integers, metadata and other constructs still
require supported realizations. The diagnostic retains each original target
and does not establish retargeting or three-ISA compiler equivalence.
Audit SHA-256:
`1db0e5c99f4ba2d46255a57d95cc554bc23712fd568e4df5ca53b1a14a71ac33`.
Completed independent readback SHA-256:
`515f424741200fa2d016414fbd88ce4ece6ea2f572353bc9281a65b98a93c9d4`.

The Rust completion criterion remains the original, complete compiler
implementation lowered through O-core, linked with its complete declared
dependency and platform closure, and executed as a working compiler. Its
generated programs require their own supported O-core lowering path.
Compiler conformance fixtures and rewritten sample functions establish
neither requirement. This benchmark remains unmet.

Original provider preparation remains separate from implementation lowering.
The pinned [musl source recipes](../tools/ocore-runtime/libc/README.md) build
the complete declared static Linux-compatible profile from unchanged musl
1.2.5 sources on all three ISAs. In x86-64/AArch64/RV64GC order, the builds
retain 1,350/1,350/1,351 source units, 1,345/1,345/1,346 ordered `libc.a`
members plus five startup objects per ISA, and 1,318/1,334/1,339 whole C LLVM
units. The required original assembly units number 32/16/12; each target
also installs 218 original and generated headers. The immutable source-build
observation has SHA-256
`f6df8192764741427588393d7386c6160ec92ee87b37c62edf633c0d667d3210`.
Original assembly, inline assembly, floating-point and long-double math,
atomics, TLS and compiler-helper providers still require complete O-core
lowering and dependency admission. Linux syscall, thread, futex, signal,
memory, file and loader services need explicit verified OSTADIX interfaces.
The static source builds do not qualify a dynamic loader or JIT publication;
capture, provider, dependency-closure and native OSTADIX completion remain
false. The separate [original libunwind recipes](../tools/ocore-runtime/unwind/README.md)
retain both source assembly files and the genuine threaded requirement. The
earlier Newlib threaded profile fails on its authentic missing pthread type;
the separate single-thread test archives do not replace that requirement.
The later Linux/musl threaded source builds finish all nine objects and nine
ordered archive members per ISA, retaining seven whole C/C++ LLVM units with
86/89/90 definitions and both original assembly files. These original provider
builds support the reference execution witness above; their implementation
lowering, dependency admission and OSTADIX services remain unqualified.
The three tests in `tests/test_ocore_native_switch.py` execute own objects on
all three ISAs against independent C and Python results: 16,326 checks per ISA
produce digest `1570cd559d8202fd`. They cover integer widths 1/8/16/32/64,
default edges, shared destinations, parallel phi swaps, and every case in a
1,922-case switch. Both suites use explicitly identified Linux development
carriers and retain the distinction between compiler conformance and complete
native runtime qualification.
An immutable hosted CPython diagnostic, `import-audit-optimizer-promises-first`, attempted
all 346 whole LLVM units from the recorded runtime build while retaining all
834 captured units as provenance. It imported, independently verified and
emitted own x86-64 objects for 39 units; 307 rejected during import. The original
source checkout and a persistent clean clone have since been restored at the
recorded revision. `source-restoration-20261010.json` confirms that all 881
recorded source/dependency artifacts match their original SHA-256 values, with
no capture-report changes. This restores the source evidence; the legacy
capture remains incomplete and requires a fresh bound capture for admission.
The diagnostic does not establish full-driver object admission, dependency
closure or complete runtime support. Separately,
`scripts/check_ocore_cpython_token.py` executes the entire original
`Parser/token.c` unit against its captured Clang object on hosted x86-64:
16,843,008 exhaustive one/two/three-byte inputs, 12,719 int32 boundary cases,
all 67 token names, and an independently corrupted oracle. This source-unit
execution proof does not establish all-three-ISA or native OSTADIX execution.
The two tests in `tests/test_ocore_native_memory.py` execute own memory objects
on all three ISAs against independent C and Python byte snapshots. Each run
checks 2,688 cases with digest `9192493a61abaccd`, including i32/i64 lengths,
narrow fills, volatile-marked and ordinary operations, equal pointers, overlap in both
directions, zero-length invalid pointers, sentinels and protected-page boundaries.
The unchanged Clang 22.1.6 source fixture also runs through text IR and bitcode
on each ISA, with identical own-object bytes and 512 additional local-array
lifetime assertions per run. Corrupted oracle controls fail independently.
These Linux development carriers check byte results and access boundaries;
they do not qualify a full runtime or exact volatile access counts, widths or ordering.
The three tests in `tests/test_ocore_llvm_pointer_constants.py` compare exact
literal and nested packed initializer bytes, including real symbol/GEP
relocations, then execute O-core objects against independently compiled original
Clang 22.1.6 LLVM references on all three ISAs. Both unchanged text IR and
bitcode produce digest `773001a633ffff41` across 119 counted cases, with
corrupted-expected controls. All source integer widths 1 through 64 are covered;
unsupported address profiles and symbolic arithmetic reject entire units.
Reports retain compiler/tool hashes and exclude pointer mapping validity and
full runtime qualification.
The ten optimizer-promise tests cover eight source/API checks and two native
checks. Unchanged LLVM text and bitcode execute own objects against original
Clang references on all three ISAs, producing digest `cde31be09eaca0d6` across
1,792 counted cases per run. Six corrupted oracle controls fail; 54 cold-body
ABI and then-unsupported exception-handling emission attempts reject without
partial artifacts on that historical compiler freeze.
This is scalar compiler conformance on Linux development carriers.
The [native RV64 Rust bridge](../ocore/runtime/riscv64/RUST_BRIDGE.md) separately
executes imported Rust scalar functions on the OSTADIX supervisor bootstrap
under OpenSBI, without Linux services. It is a native compiler proof with an
independent oracle and corruption controls; it does not qualify Rust std,
rustc, CPython, or OpenJDK as complete native runtimes.

### Imported execution profiles and cross-ISA equivalence

The following requirements describe the intended import design; they are not
implemented runtime admission, snapshot, or JIT features.

Lowering, dependency closure, enforcement, and replayability are separate
properties. Compiling a runtime through O-core does not establish that its
clock, entropy, filesystem, scheduling, or CPU-dependent behavior is
deterministic. Purity belongs to an operation and its admitted effects, not to
a runtime name. Recording capability results would require a separately
specified replay protocol; granting a capability alone does not record its
results or make effects safely repeatable.

The required cross-ISA contract compares observable values, faults, and
required effects under the same inputs and declared execution profile.
For a profile admitting pure deterministic execution, this includes
bit-identical canonical results across x86-64, AArch64, and RV64GC. Such a
profile must specify floating-point rounding, contraction, subnormals, NaN
behavior, and the libm implementation and CPU dispatch policy. Carrying one
library source is insufficient if its compiled variants produce different
results. Resource limits and host import behavior are also part of the
profile. Neither a pinned Wasm module nor a C frontend plus libc proves this
contract by itself.

Imported semantics remain explicit. Adopting Wasm rules for a Wasm importer
does not change the existing `.oc` integer rules or establish C semantics.
Record relevant source-build choices such as plain `char` signedness and
signed-overflow flags. LLVM input carries target data layouts, calling
conventions, variadic representations, and possibly target-specific
intrinsics or assembly; x86 LLVM IR is not automatically portable input for
the other two ISAs. A frontend/importer must obtain or normalize the required
target contracts. The existence of O-core `asm!` does not establish support
for foreign assembly constraints.

Dependency derivation may compute a sound over-approximation, including
declared modules and extensions, because runtime-computed import names need
not be exactly predictable from a script. The artifact must distinguish this
declared closure from measured execution coverage. A census of a runtime's
core functions does not qualify its external libraries, extension modules,
or complete execution profile.

JIT runtime implementations remain within the compiler objective. A static
executable-closure profile may forbid new executable code. A dynamic profile
would instead require generated programs to pass through verified O-core
lowering and controlled code publication, with provenance, relocations,
imports, and code lifetime recorded. Compiling an existing native-code emitter
does not automatically redirect the code it generates through O-core.

Per-image function tables are a possible imported representation, not a
replacement for the current native C ABI. Table indices alone are forgeable
integers; bounds and signature checks do not confer entry-specific authority.
They also do not make a runtime heap portable by themselves. Cross-ISA
snapshots require a defined data-pointer representation, object and allocator
layouts, initialization state, and handling of host resources in addition to
code references. Snapshots are an optional startup optimization, not evidence
of runtime-source lowering.

## 2. Source units and modules

Every source file begins with a module declaration:

```ocore
module kernel::serial;
use kernel::arch::outb;
```

An invocation of `ocorec` is one compilation unit and may contain multiple
files. Module names must be unique. Unqualified names resolve in this order:
local bindings, items in the current module, explicitly imported items, and
predeclared intrinsics. Cross-module symbols are mangled unless marked
`@export` or `@no_mangle`.

## 3. Items and control flow

The item forms are functions, extern functions, structures, enumerations,
constants, and statics:

```ocore
struct Slice { data: *const u8, len: usize }
enum Poll { pending, ready(u64), failed(i32) }

const PAGE_SIZE: usize = 4096;
static mut NEXT_PAGE: usize = 0x0020_0000;

extern "sysv64" fn boot_info() -> *const u8;

@export
@link_section(".text.kernel")
unsafe fn kernel_main() -> never {
    loop { asm!("hlt", options(nomem, nostack)); }
}
```

Statements include `let`, assignment, expression statements, `if`/`else`,
`while`, `loop`, `break`, `continue`, `return`, and `unsafe` blocks. Functions
have lexical scope and no implicit fallthrough return unless their return type
is `void`.

Expression operands are evaluated from left to right: a call evaluates its
target before its arguments, and indexing evaluates its base before its index.
Aggregate initializer expressions follow their written order, including named
structure fields written in a different order from their storage layout.
A `never` expression ends its execution path immediately; enclosing calls,
initializers, and returns do not evaluate later operands. Logical `&&` and `||`
evaluate their right operand only when required by their left operand.

## 4. Types

Primitive types are:

```text
bool
u8 u16 u32 u64 usize
i8 i16 i32 i64 isize
f32 f64
void never
```

Compound types are arrays `[T; N]`, immutable and mutable raw pointers
`*const T` and `*mut T`, structures, enumerations, and function pointers
`fn(T, U) -> R` or ABI-qualified `extern "C" fn(T, U) -> R`.

An array repeat `[expr; N]` evaluates `expr` exactly once, including when `N`
is zero. Each element receives that value. Aggregate repeats first capture a
private snapshot and copy it to the elements, so writes during copying cannot
change the repeated value.

There are no implicit numeric conversions except that an unsuffixed integer
literal may be inferred from its expected integer type. All other conversions
use `as`. Data-pointer-to-integer, integer-to-pointer, pointer arithmetic, pointer
dereference, mutable static access, inline assembly, and privileged intrinsics
require an unsafe context.

Extracting a function's integer address is safe. Converting an integer or data
pointer into a function pointer requires an unsafe context, as does changing
a function pointer's signature or ABI.

Function pointers retain the target ABI and parameter/result types. They may
be stored, assigned, and called indirectly; each indirect call requires an
explicit unsafe context because its type does not carry the target's unsafe
or effect contract:

```ocore
unsafe fn invoke(callback: extern "C" fn(u64) -> u64, value: u64) -> u64 {
    return callback(value);
}
```

Function references are relocatable constants, including in static dispatch
tables and aggregate initializers:

```ocore
extern "C" fn foreign_step(value: u64) -> u64;
static DISPATCH: [extern "C" fn(u64) -> u64; 1] = [foreign_step];
```

Floating-point types reserve storage layout; x86_64's internal O-core ABI also
permits bit-preserving transport. AArch64/RISC-V float parameters and returns
remain unsupported even with the O-core ABI. Float literals, arithmetic,
comparisons, casts, indirect float calls, and `C`/`sysv64` float parameters and
returns are compile-time errors.
Target floating-point instructions and calling conventions remain future
work. This boundary is enforced in type checking and defended again in machine
code generation.

Integer results are narrowed to their declared width after each operation.
Shifts operate on the sign- or zero-extended 64-bit operand with the count
modulo 64, then narrow the result; signed right shifts are arithmetic. Division
and remainder trap on a zero divisor and on signed 64-bit minimum divided by
`-1`. Narrow signed minimum divided by `-1` is computed in 64 bits and wraps
when narrowed. These rules are shared by all three backends.

Boolean values are normalized to `0` or `1`. Casting an integer to `bool`
produces `false` for zero and `true` for every nonzero source value, including
values whose low byte is zero. Boolean memory loads and assembly outputs also
normalize nonzero values to `true`. A Boolean call result uses its declared
low byte before normalization; undefined upper ABI register bits do not change
the result.

O-core v0.1 has no garbage collector and no implicit heap allocation. Values
have deterministic destruction-free storage. A later ownership layer may add
checked owning pointers, but it must lower to this explicit storage model.

## 5. Layout and ABI

Primitive sizes and alignments are identical on the three supported targets:

| Type | Size | Alignment |
|---|---:|---:|
| `bool`, `u8`, `i8` | 1 | 1 |
| `u16`, `i16` | 2 | 2 |
| `u32`, `i32`, `f32` | 4 | 4 |
| `u64`, `i64`, `usize`, `isize`, `f64`, pointer | 8 | 8 |
| `void`, `never` | 0 | 1 |

Structures use declaration order. Each field begins at the next address
aligned for that field; structure size is rounded up to maximum field
alignment. `@packed` removes inter-field padding and gives alignment 1.
`@align(N)` may increase alignment to a power of two up to 4096. Local frames
honor that alignment while preserving incoming stack arguments and the
target's callee-preserved registers. Packed scalar fields support unaligned
ordinary loads/stores. Large local frames and arguments beyond the register
set are supported; execution still requires enough actual stack storage.

Enums are a tagged union. The tag is the smallest of `u8`, `u16`, or `u32`
that can represent every variant. The payload begins at its required alignment
after the tag; total size is rounded to maximum tag/payload alignment.

`extern "C"` supports non-variadic integer, Boolean, pointer, and
function-pointer arguments and scalar results, for declarations and function
definitions with bodies. Register overflow arguments
travel on the stack in both direct and indirect calls, with 16-byte call
alignment and correct incoming/outgoing narrow scalar extension:

| Target | Integer argument registers | Scalar result | C ABI |
|---|---|---|---|
| x86_64 | RDI, RSI, RDX, RCX, R8, R9 | RAX | [System V AMD64](https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex) |
| AArch64 | x0--x7 | x0 | [AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst) |
| RISC-V RV64GC | a0--a7 | a0 | [RISC-V LP64 psABI](https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#_integer_calling_convention) |

RISC-V C call/return boundaries apply the psABI's 32-bit sign extension even
for `u32`; unsigned SSA values remain zero-extended internally.
`extern "sysv64"` explicitly selects the AMD64 convention and is rejected on
other targets. Aggregate parameters and returns are forbidden across direct
and indirect calls, including extern calls; pass pointers instead. Variadic
calls and floating-point C ABI classification are not implemented.

`extern "ocore"` is versioned with the compiler and is not a stable foreign
ABI. Interrupt entries use the x86_64-only `@interrupt`; they have no ordinary
arguments or return value and end with `iretq`. AArch64/RISC-V trap-frame glue
must be explicit operand-free `@naked` assembly.

Aggregate assignment has `memmove` semantics, including overlap and identical
source/destination addresses. MIR phi values are assigned simultaneously on
each incoming control-flow edge, including loop-carried cycles.

## 6. Unsafe and hardware operations

Unsafe operations are syntactically visible:

```ocore
unsafe {
    volatile_store(mmio, value);
    let status: u32 = volatile_load(status_reg);
    outb(0x3f8, byte);
}
```

Freestanding intrinsics are:

- `volatile_load(ptr)` and `volatile_store(ptr, value)`;
- `atomic_load(ptr, order)`, `atomic_store(ptr, value, order)`,
  `atomic_exchange`, `atomic_compare_exchange`, and `atomic_fetch_add`;
- `inb`, `inw`, `inl`, `outb`, `outw`, `outl`;
- `enable_interrupts`, `disable_interrupts`, `halt`, and `invalidate_page`;
- `syscall0` through `syscall6` for user-mode stubs;
- `asm!(template, operands..., options(...))`.

Memory order values are `relaxed`, `acquire`, `release`, `acq_rel`, and
`seq_cst`. Invalid load/release and store/acquire combinations are compile-time
errors. Compare-exchange failure order cannot be `release` or `acq_rel` and
cannot be stronger than its success order. Volatile operations prevent compiler
elision and reordering relative
to other volatile operations; they do not provide inter-core synchronization.
The current volatile lowering accepts scalar pointees. Atomic pointees must be
1, 2, 4, or 8-byte integers on all three targets. Volatile scalar access and
atomics require natural width alignment and explicitly trap on a misaligned
address on every target. Ordinary packed loads/stores remain valid, and
aggregate copies transfer bytes. Each backend rechecks pointer, value, result,
and ordering types. RISC-V subword read-modify-write uses masked word LR/SC loops and may
provide stronger ordering than requested.

Inline assembly templates use the selected target's assembler syntax (Intel
syntax on x86_64). Input/output registers are explicit. Non-naked templates
must restore the stack pointer and preserve the target's reserved frame and
platform registers; this is the unsafe assembly author's contract.
`options(nostack)` asserts that the target stack pointer is unchanged.
Assembly operands must be non-floating scalar values because
the current interface exposes general-purpose registers. Assembly is unsafe
even when it contains no privileged instruction. Inputs are prepared together,
and output registers are preserved before output-place address calculation,
so scratch-register operands and indexed destinations retain their values.

## 7. Linkage attributes

Supported attributes are:

- `@export`: externally visible symbol;
- `@no_mangle`: use the source identifier as the linker symbol;
- `@link_section("name")`: place a function or static in a named section;
- `@align(N)`: increase item/type alignment;
- `@used`: retain an otherwise unreferenced static;
- `@packed`: packed structure layout;
- `@interrupt`: x86_64 interrupt entry ABI;
- `@naked`: no compiler prologue/epilogue; body is restricted to assembly.

Section names are emitted verbatim. Applying executable section attributes to
writable statics is rejected unless `@unsafe_linkage` is also present.

## 8. Freestanding runtime boundary

The freestanding runtime may depend only on the target ABI and symbols
provided by the kernel image. It may not depend on subprocesses, JSON,
filesystem access, Python, Nix, libc, Rust `std`, environment variables, or a
host allocator.

The runtime supplies boot entry glue, zeroing `.bss`, serial I/O, IDT
installation, a timer interrupt, fixed-window reclaiming frame allocation,
syscall entry, and panic-to-serial. Allocation in interrupt context is forbidden
until a separate interrupt-safe allocator exists. The current allocator is
single-CPU and relies on boot and syscall entry running with interrupts masked.

## 9. Capabilities and syscalls

A generic or deserialized `OCapability` is not kernel authority. An
`OCapability` emitted by a live hosted broker is a bearer for a private session
binding. Kernel authority itself is represented by an unforgeable
`(slot, generation)` handle tied to a per-process capability table:

```text
CapabilityEntry = { object_id, object_type, rights, generation, state }
CapabilityHandle = (generation << 32) | slot
```

Every capability syscall validates slot bounds, live state, generation, object
type, and requested rights. Handles never contain kernel pointers. Kernel-only
transfer transactions can reserve a destination slot without exposing it as a
live capability, then publish or abort that exact reservation. Close similarly
uses a begin/commit/abort state. Committing a close or aborting an unpublished
reservation advances its generation before reuse; aborting an in-progress
close restores the same exact live capability. Exhausted 32-bit generations
retire instead of wrapping to a value that could revive an old handle.

Initial syscall numbers are:

| Number | Operation |
|---:|---|
| 0 | `debug_write(cap, ptr, len)` |
| 1 | `cap_close(cap)` |
| 2 | `cap_copy(source_cap, destination_endpoint_cap, rights)`; creates an attenuation-only transfer ticket in the M3 scheduler gate |
| 3 | `page_alloc(page_pool_cap, kind)`; returns a generated memory capability |
| 4 | `yield()` |
| 5 | `ticks()` |
| 6 | `exit(status)`; enabled only by a trusted lifecycle harness |
| 7 | `sleep(delta_ticks)`; enabled only while the scheduler is active |
| 8 | `endpoint_create()`; returns a generated endpoint capability |
| 9 | `endpoint_send(endpoint_cap, word0, correlation, transfer_ticket)` |
| 10 | `endpoint_receive(endpoint_cap, message_ptr, 32)` |
| 11 | `endpoint_cancel(endpoint_cap, correlation)` |
| 12 | `serial_read(control_cap, byte_ptr, 1)`; nonblocking and mode-gated |
| 13 | `control_submit(control_cap, command_ptr, len)`; bounded to 192 bytes |
| 14 | `personality_call(call_cap, operation, scalar, timeout_ticks)`; M6A scalar route |
| 15 | `personality_reply(reply_cap, request, status, scalar)`; M6A daemon completion |
| 16 | `personality_supervise(supervise_cap, action, generation, subject)`; M6A policy action |
| 17 | `personality_bounded_call(call_cap, operation, ptr, len, direction, timeout_ticks)`; mode-24 request-scoped bounded-copy route |
| 18 | `personality_view_lookup(reply_cap, request)`; mode-24 daemon view discovery |
| 19 | `personality_view_read(view_cap, offset)`; mode-24 byte read |
| 20 | `personality_view_write(view_cap, offset, byte)`; mode-24 byte write |
| 21 | `personality_bounded_reply(reply_cap, request, view_cap, committed_len, result)`; mode-24 completion |

`page_alloc` accepts anonymous or shared memory from a typed page-pool
capability. It enforces the current CSpace's hard frame quota and distinguishes
quota exhaustion, physical-frame exhaustion, resource-table exhaustion, and an
invalid memory kind. Executable memory remains kernel/loader-only; device memory
is never allocated from the RAM pool. The returned value is a CSpace capability,
not an internal object handle, frame index, or physical address.

`yield` records a request in every mode. It requests an actual scheduler
transition when the Milestone 2 scheduler is active and returns directly in the
bootstrap gate. `exit` abandons a user frame only after the kernel has installed
a trusted lifecycle continuation. `sleep` rejects zero or out-of-range delays
and returns `ERR_NOT_IMPLEMENTED` when the scheduler is inactive. In the M3
gate, `cap_copy` validates an endpoint to derive its receiver CSpace, then
creates an attenuation ticket bound to the exact creating process generation
and that destination CSpace. It does not bind the endpoint object, and the
receiver's CSpace slot remains kernel-selected. The public gate exhausts all 16
ticket records, denies abort by a non-owner process, lets the owner abort each
once, rejects a stale repeat, and proves a fresh prepare succeeds afterward.
Endpoint send/receive/cancel are public CPL3 operations with bounded copy and
real scheduler block/wake behavior. The M5 serial operations require the exact
typed control object installed only in the loaded REPL CSpace.

Mode 18 adds three M6A-only calls: scalar personality call, personality reply,
and supervision. A generation-bound call capability routes the test
personality's scalar operation and input through a kernel request record to an
endpoint owned by the current unprivileged daemon. A typed reply capability is
installed only in that daemon; a rotating typed supervision capability is
installed only in the unprivileged supervisor. The request record arbitrates
reply, supervisor cancellation, deadline expiry, and service death into one
terminal state and one dependent wake. The test personality admits only its
small scalar syscall whitelist; pointer-bearing endpoint operations return
`ERR_NOT_IMPLEMENTED` rather than bypassing a future memory-view protocol.

The hosted `OCapability` wire value may refer to a live kernel capability only
through an authenticated transport endpoint. Its string `identity` is never
accepted directly as a kernel handle.

The hosted `CapabilityBroker` implements this boundary. It generates 256-bit
bearer identities from operating-system entropy and keeps a private per-session
token-to-handle table. Callers use operation-specific `debug_write` and
`cap_close` methods; they cannot select a syscall number, expected kind, or
required-rights mask. A successful kernel close removes the bearer, while a
transport failure or kernel rejection preserves it. Deserialized identities
not already bound in that live broker session are rejected as forged or stale.
Metadata cannot select a slot or add rights.

This prevents guessing, serialized forgery, metadata-based escalation, stale
or revoked token use, and cross-session replay. It does not prevent theft of a
still-live bearer inside the same broker session, broker-process compromise,
or authenticated-transport compromise. Possession of a live bearer is an
explicit delegation of its bounded authority.

## 10. Hosted foreign-language boundary

Foreign blocks remain part of `.O` orchestration. They may construct O-core
source, invoke `ocorec`, link images, launch QEMU, and inspect results. They are
not legal inside `.oc` source and are not linked into freestanding artifacts.
This preserves O-lang's polyglot model without making Python, Rust, Nix, JSON,
or subprocess execution part of the kernel trusted computing base.

### 10.1 Operator CLI and boot boundary

The repository-owned lowercase CLI exposes the authoritative build and QEMU
paths without reimplementing them:

```text
o kernel doctor
o kernel build
o kernel image
o kernel smoke
o kernel boot
o kernel console
o kernel smoke-live
o kernel gates
o kernel doctor-media
o kernel media
o kernel inspect-media
o kernel boot-media
o kernel smoke-media
o kernel iso
o kernel inspect-iso
o kernel boot-iso
o kernel smoke-iso
```

`boot` selects the baseline probe mode. `console` selects mode 16, builds the
content-addressed M5 service image, prints its exact SHA-256, and boots the real
capability-gated CPL3 `o> ` control process. Its implemented interactive
surface is `status`, exact-digest `install`, and exact-digest `activate`.
The launcher does not promote the parser's reserved or incomplete command
spellings into supported behavior.

Interactive images are loaded by QEMU and use a multiplexed serial terminal;
`Ctrl-A X` exits. `smoke` and `smoke-live` are finite asserted alternatives.
`gates` executes the manifest-defined portable evidence set. These commands
prove only their documented QEMU/TCG boundaries, not a physical-machine boot,
SMP, Linux or Plan 9 boot, or hardware-device isolation.

The deterministic x86_64 GPT/UEFI disk path, separate ISO9660/El Torito UEFI
path, and guarded external-media workflow are documented in
[OSTADIX_BOOT.md](OSTADIX_BOOT.md). The disk and ISO smoke gates rebuild their
respective containers twice and boot the exact admitted read-only artifact
through OVMF/QEMU TCG. They are not physical-machine, KVM, SMP, Secure Boot,
measured-boot, hardware-driver, or hardware-isolation evidence. Only the raw
GPT/ESP disk image is accepted by the external-media writer; the ISO is not.

## 11. Implemented bounded O-core milestone boundary

The compiler supports x86_64, AArch64, and RV64GC native assembly/object
generation. All three are stack-spill backends without optimization or a
general register allocator. They implement scalar locals and pointers,
integer operations and casts, direct and unsafe indirect calls with stack
arguments, branches and parallel phi moves, volatile memory, all supported
atomic integer widths, aligned local frames, and overlap-safe aggregate
copies. Aggregates support layout, construction, fields, indexing, locals,
and statics; call boundaries still require pointers to aggregates. Enum
construction is supported; pattern matching is not. MIR structure and codegen
type contracts are checked before unsupported shapes can select machine
instructions. Floating-point computation and full C ABI classification remain
unsupported.

Privileged operations remain architecture-specific. AArch64 implements DAIF
masks, `wfi`, page invalidation, inline assembly, operand-free naked functions,
and `syscall0` through `syscall6` using x8 and x0--x5. RISC-V implements
supervisor interrupt masks, `wfi`, `sfence.vma`, inline assembly, operand-free
naked functions, and `ecall` using a7 and a0--a5. Both reject AMD64 `sysv64`,
x86 port I/O, and the x86 interrupt-entry ABI. The RISC-V compiler backend does
not establish a RISC-V bootable kernel or runtime port.

The same-source execution gate builds `.oc` with the real `ocorec` CLI for all
three targets, links an independent freestanding C reference harness, and
executes x86_64 natively plus AArch64/RISC-V under QEMU user emulation:

```bash
cargo build --locked --bin ocorec
python3 scripts/check_ocore_native_equivalence.py \
  --ocorec target/debug/ocorec --output-dir target/ocore-native-equivalence
```

Run it on an x86_64 Linux host with `clang`, `ld.lld`, `qemu-aarch64`, and
`qemu-riscv64` (`qemu-user`); missing tools fail the gate. The corpus checks
4096 vectors across three
arithmetic functions (12,288 reference comparisons per ISA), C crossings in
both directions, twelve-argument direct/indirect calls, packed and aligned
memory, an 8193-byte local array, overlap-safe copies, volatile memory, and
8/16/32/64-bit atomics. Successful output bytes must agree across targets.
Six separate fault programs per ISA must trap: four division/remainder cases
and two misaligned volatile/atomic accesses. Object bytes must reproduce across
output directories. Two additional executions verify that a `never` call
inside an array repeat or an outer call argument exits immediately with the
expected status. Retained artifacts include
assembly, ELF objects/executables, and `equivalence.json`. This is compiler
conformance evidence for the checked corpus, separate from kernel boot and
subsystem proof.

`ocore/kernel/smoke-aarch64-g2-qemu.sh` builds one deterministic `EM_AARCH64`
image twice, proves semantic markers originate in compiled `.oc`, and boots it
with one vCPU on QEMU/TCG `virt,virtualization=on,gic-version=3`. The image
installs a resident EL2 vector and stack, enters O-core at host EL1, and proves
one domain-separated HVC/ERET round trip with sentinel-register and stack
integrity. That HVC is a host-EL1 bring-up probe, not a guest hypercall or
paravirtual authority interface. It then executes two EL0 principals through real SVC/ERET, endpoint
request/reply, attenuated capability use, contained fault and exit, generation
reuse/stale denial, reclamation, and bounded post-lifecycle architectural
counter progress. It has no stage-2 mappings and remains MMU-off virtual
evidence, not physical AArch64, SMP/G3, KVM/SVM, Linux or Plan 9 boot, a general
foreign ABI, or PCI/DMA/IOMMU/device-assignment evidence.

The future host-EL1-to-EL2 resource boundary, including per-resource
asynchronous completion, memory teardown ordering, G7's no-guest-HVC decision,
and the deferred G8 handle-authentication decision, is specified in
[`O_MACHINE_CONTRACT.md`](O_MACHINE_CONTRACT.md). It is a design contract, not
an implemented G2 claim.

Milestones 0.1 through 0.3 are complete for the bounded single-CPU bootstrap
gate. The kernel enters a linked `native[0]` payload at CPL3, crosses an
architectural `SYSCALL` boundary through CPU-local entry state, validates the
IRET target and RFLAGS, and survives IRQ0 return. Page-granular supervisor
mappings enforce RX, R/NX, and RW/NX roles; guarded user and kernel stacks, a
double-fault IST, normalized exception frames, and exact user-copy fixups bound
the fault surface. The fixed 4..16 MiB QEMU window contains 3,072 reclaiming,
typed, reference-counted frames with generation-safe reuse and zeroing.
Transactional memory objects and per-CSpace quotas back anonymous/shared
`page_alloc` capabilities without exposing object handles or physical
addresses.

`smoke-qemu.sh` is the positive bootstrap and memory-lifecycle gate.
`smoke-faults-qemu.sh` separately boots each fatal Milestone 0.2 probe, requires
the expected trap and later timer, and checks a recoverable missing-PTE user
copy. Its one-process disposition wording applies to that historical bootstrap
scenario only.

Milestone 1 is complete for two bounded native processes on one CPU. Dynamic
processes have generation-tagged domain, process, address-space, mapping, and
CSpace owner identities. Their roots share RX user text and supervisor-only
kernel mappings while using private RW/NX data and guarded stacks. Context
installation changes CR3, TSS.RSP0, GS entry state, PCB, domain, address space,
and CSpace as one transaction. Reap is split across ownership release,
address-space destruction, type-aware CSpace drain, and final generation
advance. `smoke-processes-qemu.sh` boots independent normal-exit and
contained-fault scenarios and requires same-VA physical isolation, stale identity denial,
sibling survival, complete dynamic-frame reclamation, and a post-lifecycle
timer.

Milestone 2 is complete for four TCBs across two processes and one CPU. The
scheduler uses canonical 22-word saved frames, FIFO runnable and blocked queues,
timer preemption, cooperative yield, sleep deadlines, wake reasons, bounded
priority quanta, accounting, and a ring-0 idle path. Its prepare/install/commit
switch transaction keeps registers and guarded stacks aligned with CR3,
TSS.RSP0, GS state, PCB, domain, address space, and CSpace.
`smoke-scheduler-qemu.sh` requires one million forced identity transactions,
progress from two CPU-bound and two sleeping CPL3 threads, wake-once behavior,
cross-thread hostile-RFLAGS sanitization on a syscall-selected TCB, exit during
preemption, hostile saved-RSP TCB containment, sibling progress, stale TCB
denial, frame reclamation, and a post-lifecycle timer. The million-iteration
stress verifies identity installation and a saved-frame canary without entering
CPL3; real frame save/restore and IRETQ switching run in the bounded IRQ/SYSCALL
phase. Failed context installation rolls architectural and PCB identity back to
the verified management state before the prepared TCB is returned to the
runnable queue.

Milestone 3 has a bounded public IPC gate. The original kernel-mechanism
regression remains in `smoke-ipc-foundation-qemu.sh`; `smoke-ipc-qemu.sh` adds
CPL3 endpoint create/send/receive/cancel, real full-queue TCB blocking and
wake-once retry, preemptive cross-domain request/reply, exact attenuated
capability transfer, automatic dead-sender cleanup, and containment of a
deliberately crashing personality while unrelated worlds progress. The gate
then tears down every process and capability generation, reclaims all frames,
and reaches a later timer. It is fixed-capacity and single-CPU and does not
claim every death/cancellation interleaving or the request-scoped foreign-memory
protocol.

Milestone 4 adds a deterministic read-only OVFS importer, freestanding SHA-256
verification, strict static x86_64 ELF validation, BSS and minimal SysV stack
materialization, loaded W^X address spaces, and capability-returning service
lookup. `smoke-loader-qemu.sh` executes two independently linked personalities
at the same virtual addresses in different CR3 roots, rejects malformed,
overlapping, and W+X images, then proves transactional namespace teardown and
reclamation.

Milestone 5 is a bounded native live-system slice. Four separately linked
`init`, supervisor, package-daemon, and REPL ELFs load from one immutable OVFS
image into distinct CSpaces. The REPL owns the sole typed serial/control
capability and performs real line collection; privileged fixed-capacity package
and supervisor state machines enforce exact manifests, grants, health-gated
publication, stale generations, rollback semantics, and targeted restart. In
mode 16, `smoke-live-qemu.sh` drives the real serial install/activate lifecycle,
contains one package-daemon CPL3 fault, withdraws the old service in
`CONTROL_RECOVERING`, health-gates a fresh loaded generation before republication,
and proves final deactivation. Mode 17's `smoke-live-semantics-qemu.sh`
independently executes the broader finite state corpus. These gates do not claim
general retry/backoff, recovery from a replacement fault, unprivileged
endpoint-backed service policy, durable reboot reconstruction, a native
compiler, a dynamic linker, a foreign ABI personality, or a foreign root
filesystem.

M6A is a separate bounded personality-supervision slice in mode 18.
`build-m6-artifacts.sh` deterministically packages a test client, native
personality daemon, native supervisor daemon, and unrelated observer at exact
`/sbin/m6-*.elf` paths in a 62,104-byte immutable OVFS image. Its SHA-256 is
`f5924eeb64b5a3d332e20b5d0fae7b233ae2714eb58b72ea07f08a4d26334417`.
`smoke-personality-qemu.sh` checks the artifact identity and absence of the four
user modules from kernel symbols before boot. In QEMU, the CPL3 supervisor
performs health-before-publication, cancels one held request, observes the
daemon-owned endpoint close after a deliberate daemon fault, requests one
fresh generation, health-gates republication, and requests cooperative stop.
The client proves the pinned ping/add-one/unsupported scalar corpus, timeout and
crash results, a rotated call capability, denial of the stale generation-1
capability, and the generation-2 corpus. Late cancelled, late timed-out,
prior-generation, and duplicate replies are rejected. The router retains a
16-record bounded terminal history and the gate requires history count 9 with
zero eviction; an ancient record outside that horizon would still be denied but
classified conservatively as stale. The supervisor queues the fault watch before
cancellation wakes the client, so endpoint FIFO orders the watch ahead of the
timeout/crash sequence. An unrelated observer continues; all resources are
reclaimed; and a later timer remains live.

This evidence is deliberately named M6A, not full Milestone 6. It has no shared
or request-scoped foreign-process memory view, no pointer-bearing personality
call, no general package dependency resolver or durable reconstruction, no
unbounded retry policy, and no Linux or other foreign operating-system ABI.

M6B's first native mechanism slice is separate mode 19.
`personality_memory_view.oc` uses four fixed-capacity generation-tagged request
views, kernel-owned bounded-copy staging, direction-attenuated nontransferable
capabilities, snapshot input, and written-prefix-only output commit after exact
process/address-space revalidation. View size is capped at 128 bytes and total
charged staging at 256 bytes. Reply, cancellation, timeout, service-death,
process-exit, unmap, and delegated-resource hooks close the service capability
before recording one terminal result and publishing one wake. Process-exit and
unmap hooks also release an undeliverable replied view without publishing a
second result or wake. `delegated_resource.oc` supplies independently revocable
typed leases for memory, filesystem, timer, network, and device classes.
Lease/view binding is exact-request-only, and request-wide revocation leaves
unrelated requests live without ambient fallback. Create-plus-bind is an
authority-publication transaction: an injected bind failure must revoke the
new capability and destroy the exact unbound lease generation.

`smoke-m6b-qemu.sh` exercises that mechanism against a real kernel process and
address space, including bounds/generation/mapping-rights/quota denial, staged
commit, stale/duplicate authority, every implemented terminal hook,
same-request bulk revocation, unrelated-request survival, post-reply cleanup,
CSpace-drain close, and a later timer. Lifecycle and wake hooks are invoked
directly; this is not real process/unmap/scheduler integration. It is not routed
through the M6A CPL3 daemon and does not add a public pointer-bearing
personality call.
Pinned windows, streaming output, actual signal and concurrent mapping-change
integration, Linux-oracle behavior, fuzzing, allocation-failure injection, and
concrete filesystem/network/timer/device services remain future M6B work.

Mode 24 is a bounded M6B vertical slice. It composes the mode-19 view
mechanism with the existing M6A request router and four independently packaged
CPL3 principals. `build-m6b-live-artifacts.sh` deterministically rebuilds a
client, personality daemon, supervisor, and unrelated observer into a
65,152-byte OVFS image whose SHA-256 is
`5b9d2526da2abd75ec90b4770ded5923d856132fad736fb13f241c34f1579887`.
The client issues each call once through syscall 17; the live corpus uses one
exact four-byte `INOUT` view. The daemon discovers only the view correlated to
the received request, accesses it through syscalls 18-20, and completes it
through syscall 21. A generation-1 cancellation and deliberate daemon fault
are followed by a health-gated generation-2 rebind. Generation 2 then covers
supervisor-triggered pre-terminal unmap, request-revoke, delegated-device-
resource-revoke, and caller-exit dispositions while each request is still
waiting. The caller-exit case also leaves the test client's process reapable
and its thread exited; the unrelated observer and a later timer survive.

Those lifecycle operations are bounded dispositions, not a claim that the
gate mutates a mapping or observes an external resource event. The delegated
device resource is one internal typed lease, not a physical device. Mode 24
does not cover a post-reply/pre-consume process-exit or unmap race, pinned
windows, streaming, signals, a general foreign ABI, Linux or Plan 9 boot, a
general guest agent, KVM, PCI, DMA, IOMMU, or physical-device isolation.

Run the live bounded personality evidence gate with:

```bash
./ocore/kernel/smoke-live-bounded-personality-qemu.sh
```

Mode 25 is a bounded execution-and-personality vertical slice. It reuses the
Mode 24 bounded request/view terminal path but admits one exact Linux x86-64
personality instead of broadening the native test ABI. A deterministic builder
packages exactly `/bin/linux-minimal.elf`, `/sbin/linux-personalityd.elf`,
`/sbin/linux-supervisord.elf`, and `/sbin/linux-observer.elf` into one immutable
OVFS image. The foreign payload is independently pinned at 8,520 bytes with
SHA-256
`06240b6a840ed4262835aceff64a94f6ebd77838666f05eb7415d9a0d1b5868d`;
the complete image is 60,104 bytes with SHA-256
`b380e5cbbe50403bd58bdafb11c54f2201f0cc742fc898487fa08ba26e2886e8`.
The live gate pins both identities and rejects any of those packaged principals
linked into the kernel as source modules.

The loaded foreign ELF executes at CPL3. Its required path invokes two bounded
`write` calls, one deliberately unknown syscall, and `exit_group(42)`; a fifth
static syscall site is only the failure path's `exit_group(111)`. The write
bridge snapshots at most 128 bytes through one request-scoped `IN` view,
authorizes fd 1 or fd 2 against the exact caller and personality-service
generation, and installs the terminal result directly into saved `RAX` without
reissuing the syscall. The QEMU transcript must contain each exact stdout and
stderr line once, observe `-ENOSYS`, and preserve exit status 42. Generation 1
completes stdout and then faults deliberately. Its view capability is already
closed by the successful reply; crash handling withdraws generation-1 service
and fd authority while preserving the committed terminal record and its charge
until the client can consume it after generation-2 publication. Generation 2
first rejects generation-1 lookup authority as stale during private startup,
then answers health and is published. The client subsequently consumes the
preserved stdout terminal and completes stderr. The gate also keeps the
unrelated observer schedulable, reclaims every request, view, fd object,
capability, process, address space, and frame, and reaches a later timer while
QEMU remains alive.

Run the live Linux-personality evidence gate with:

```bash
./ocore/kernel/smoke-live-linux-personality-qemu.sh
```

Mode 25 executes a Linux-ABI ELF; it does not boot Linux, Plan 9, firmware, or
a distribution and does not provide a dynamic loader, root filesystem, general
Linux ABI, guest agent, KVM or physical-hardware evidence, PCI/device
assignment, DMA isolation, IOMMU isolation, interrupt remapping, or hardware
reset. The exact ELF still awaits an authoritative replay on native x86-64
Linux. This bounded-copy gate also does not close the broader pinned-window,
streaming, signal, SMP, or general concurrent mapping-race M7 acceptance
matrix.

Mode 26 is a bounded execution-and-service vertical slice. It retains Mode 25's
exact 8,520-byte Linux x86-64 ELF and adds an unprivileged native 9P2000 server,
native supervisor, and independently linked native Plan-9-style client. The
deterministic builder packages exactly `/bin/linux-minimal.elf`,
`/sbin/linux-9pd.elf`, `/sbin/linux-supervisord.elf`, and
`/bin/plan9-namespace-client.elf` into a 92,872-byte OVFS image with SHA-256
`920b014cfb133f033b6761da6fe5b1d22be613bf88112c05ec0af982e1beebd9`.
The builder double-compiles each native principal, rejects dynamic or W+X ELF
profiles, double-packs the image, and runs an independent exact-wire oracle
before the image is admitted.

The Linux ELF again completes the exact stdout and stderr writes through
generation-scoped bounded views. The 9P server snapshots only the corresponding
20-byte result and exposes it at `/srv/linux/status`; the Plan-9-style client
receives only a generation-bound bounded-call capability. With `msize = 128`,
it executes exact 9P2000 version, attach, walk, open, read, and clunk messages.
Generation 1 also proves sequence, unsupported-version, missing-path,
write-open, and excessive-count errors. After the first read and clunk, the
server faults deliberately. O-core withdraws the generation-1 namespace and
call authority, preserves both clients, installs and health-publishes a fresh
server, and denies the stale generation-1 client capability. Generation 2 then
serves the exact stderr snapshot before the Linux `-ENOSYS`, `exit_group(42)`,
supervisor stop, complete reclamation, and later-timer checks finish.

Run the live Linux-to-9P evidence gate with:

```bash
./ocore/kernel/smoke-live-linux-plan9-qemu.sh
```

This is real 9P2000 wire behavior between bounded native CPL3 service
principals; it is not a Plan 9 kernel or binary. Mode 26 does not boot Linux or
Plan 9, provide a distribution, root filesystem, dynamic linker, general Linux
ABI, general 9P server, Plan 9 namespace or mount environment, network
transport, persistent filesystem, or guest-agent framework. QEMU TCG is not
KVM/SVM or physical-hardware evidence. PCI or physical-device assignment, DMA,
IOMMU, interrupt remapping, and hardware reset remain outside this gate.

Mode 26 is not two-provider routing evidence. Generation 2 is a replacement
instance of the same server implementation and serves a later, different
20-byte snapshot after generation 1's read and clunk have completed. There is
no route set for one immutable object, requester-local provider choice, recovery
of one logical read on a second provider, fresh provider-B session/fid
reconstruction, causal multi-attempt trace, or live `OWRECEIPT` emission.

Mode 31 is the bounded M7B-1 mechanism gate. Run it with:

```bash
./ocore/kernel/smoke-m7b-logical-read-qemu.sh
```

The deterministic 78,304-byte OVFS contains one requester-local client/router
ELF, one provider ELF instantiated as two distinct generation-bound CPL3
provider principals, and one exact 20-byte immutable object. Before the request,
O-core admits distinct A/B provider identities, service bindings, endpoints,
and client call capabilities. Provider B's service loop remains staged while A
receives fresh `version`, `attach`, `walk`, `open`, and `read` exchanges. A
returns a valid 9P `Rerror`, faults deliberately, and has its local route and
call authority withdrawn; the client then proves its old A capability stale.
Only afterward does B run a fresh provider-local `version`, `attach`, `walk`,
`open`, `read`, and `clunk` sequence with different fids. The client verifies
the exact bytes and SHA-256, and the kernel checks a volatile causal state before
separately proving A physical/process cleanup, B session/queue cleanup, complete
bounded resource reclamation, unrelated-witness survival, and a later timer.

This passes M7B-1, not the complete M7B milestone described in
[`ODOMAIN_PLAN.md`](ODOMAIN_PLAN.md#m7b-two-provider-immutable-9p-read-fallback).
The requester and route coordinator are one principal, both providers use the
same deterministic implementation artifact, and the route set is fixed local
configuration. The causal state is non-persisted, unsigned diagnostic evidence,
not a live `OWRECEIPT`. Mode 31 does not establish implementation-diverse
providers, general 9P or WorldFS, writes, fid migration, exactly-once effects,
network transport, Governor consensus, G7/G8, a foreign kernel, Linux or Plan 9
boot, hardware virtualization, physical-device assignment, DMA/IOMMU isolation,
or physical-hardware evidence.

Mode 27 is the bounded shared-World-identity PR2 slice. The 20 constitutional
identity atoms--`WorldId`, `WorldEpoch`, `GovernorTerm`, `GovernorLogIndex`,
`NodeId`, `NodeGeneration`, `DomainId`, `DomainGeneration`, `ProcessId`,
`ProcessGeneration`, `ResourceId`, `ResourceGeneration`, `ObjectId`,
`ObjectVersion`, `CapabilityId`, `LeaseId`, `TaskId`, `AttemptGeneration`,
`CheckpointId`, and `ReceiptId`--have matching typed Rust and `.oc`
definitions. The gate admits only strict `OWIDENT` v1 identity records and
requires byte-exact Rust/native O-core convergence under QEMU TCG. Strict
decoding rejects malformed records and zero generation/version/term/index
fields; separate hierarchical current/reference checks reject stale
generations and same-generation logical mismatches.
Current `.oc` aggregate fields are constructible, so native validity is
enforced by the nominal initializers and strict record boundaries rather than
claimed as an unrepresentable raw bit pattern. A raw zero or mistagged
aggregate is not an accepted identity record.

Run the native World-identity evidence gate with:

```bash
./ocore/kernel/smoke-world-identity-qemu.sh
```

Serialized capability IDs remain descriptive non-authority: they are not
bearers, CSpace handles, or delegation. `OWIDENT` v1 remains the identity-only
nested format rather than a transport, OValue envelope, or receipt codec. The
gate supplies no Governor, consensus, native membership, or OSTADIX Alpha
qualification; it passes no G0--G13 gate, and QEMU TCG is not physical or
hardware-isolation evidence.

Mode 28 is the bounded canonical World wire-codec PR3 slice. `OWPROTO` v1 uses
a fixed 16-byte big-endian header, four record kinds, a 16 KiB hard maximum,
and caller/negotiated record limits. Strict decoding requires exact total and
payload lengths, known kinds and schemas, zero reserved fields, valid bounded
schema ranges, and canonical nested `OWIDENT` records. The fixed corpus is
exactly 20 records and 1254 bytes: two offers, one canonical v1 selection, one
disjoint rejection, and all 16 identity-v1 conformance records. Rust and native
`.oc` must produce those bytes exactly under QEMU TCG.

Run the native World-protocol evidence gate with:

```bash
./ocore/kernel/smoke-world-protocol-qemu.sh
```

Schema negotiation is an offline deterministic function over two bounded
offers. It chooses the highest common version and smaller maximum-record limit,
or one exact contextual no-overlap rejection; validation rejects downgrades,
inflated limits, and false rejection. It does not open a stream or network
transport, perform a live handshake, authenticate a peer, establish a session,
provide encryption or replay protection, or carry membership. Decoded identity
and capability descriptions remain non-authority and cannot create bearers,
CSpace handles, or delegation. Mode 28 implements neither PR4 OValues nor PR5
receipts, and supplies no Governor, consensus, WorldFS, Workstream A acceptance,
or G0--G13 qualification. QEMU TCG is not physical or hardware-isolation
evidence.

Mode 29 is the bounded canonical World-value PR4 slice. Its separate
self-framed `OWVALUE` v1 format is not a new `OWPROTO` v1 kind. It admits only
the frozen portable core, uses a 4096-byte record maximum with depth limited to
16 and total nodes limited to 128, orders record fields and scalar-key maps
canonically, and permits a root-only inert versioned extension whose payload
must itself be a portable value. SHA-256 covers the complete canonical record.
The fixed corpus is exactly 19 records and 928 bytes (1856 lowercase hex
digits), with concatenated SHA-256
`264e00550bbbe7561412d9a43f89036667ffbcf27add522131f8e650abef19bc`. It must
encode identically and hash identically in Rust and native `.oc`; strict decoding and reencoding reject malformed, duplicate,
out-of-order, over-limit, or otherwise noncanonical records.

Run the native World-value evidence gate with:

```bash
./ocore/kernel/smoke-world-value-qemu.sh
```

Hosted conversion is an explicit allowlist. Capabilities, capsules, live
references, requests, and other authority-bearing or effectful hosted values
are rejected rather than serialized. Descriptive code and object references do
not become authority, and extensions never auto-dispatch or rehydrate a
capsule. Mode 29 remains an offline codec/hash oracle rather than transport, a
live M9 crossing, authenticated authority, PR5 receipts, execution/grounding
convergence, a Governor, consensus, WorldFS, Workstream A acceptance, or
G0--G13 qualification. It does not make the full hosted `OValue` enum portable
or replace the hosted canonical-CBOR shim format. QEMU TCG is not physical or
hardware-isolation evidence.

Mode 30 is the bounded canonical World-receipt PR5 slice. Its separate
self-framed `OWRECEIPT` v1 format binds bounded descriptive World identities
and generations, SHA-256 content references, capability-right descriptions,
terminal and commit fields, evidence-gate identity, and an algorithm-tagged
signature envelope. Rust and native `.oc` produce the same fixed two-record,
3,239-byte corpus (6,478 lowercase hex digits; SHA-256
`1edd90bf881cd42d08e2031482baae4e7c9a95bd78cfa65f0cbe14147c0a2604`) and
the same 1,575-byte current and 1,546-byte stale signing preimages. Both strictly
reject malformed or noncanonical record structure.

Run the native World-receipt evidence gate with:

```bash
./ocore/kernel/smoke-world-receipt-qemu.sh
```

Hosted Rust performs real Ed25519 sign/verify, tamper rejection, and wrong-key
rejection using a pinned, explicitly non-secret conformance key. Native Mode 30
validates the receipt and signature-envelope structure but is not a general
freestanding Ed25519 verifier. Capability identities and rights in a receipt
remain descriptive rather than bearer authority. The offline corpus is not a
live execution receipt emitted by HGraph, project, live-system, KernelWorld,
O-Git, or evidence components. It supplies no production key lifecycle,
trusted-signer policy, authoritative replay/commit fencing, transport,
Governor, consensus, WorldFS, typed OSTADIX Alpha attestation, Workstream A
acceptance, or G0--G13 qualification. QEMU TCG is not physical or
hardware-isolation evidence.

Mode 32 is the bounded native semantic-structure comparison for a live
hosted-reference project receipt. Its serial oracle accepts one lowercase-hex
OWRECEIPT of at most 4,096 bytes, performs the complete native canonical
decode, exact envelope reencode, and validated signing-preimage construction,
then requires the receipt's commit tag to be `Uncommitted`. Native and hosted
Rust compare
`SHA256("OSTADIX/PROJECT-RECEIPT-SEMANTICS/V1\0" || u32_be(body_length) || canonical_unsigned_body)`;
the signer key ID and signature remain outside that semantic fingerprint.
After the successful comparison, the probe reuses the same receipt-validation
scratch with a malformed envelope and requires
`validated_terminal_and_commit` to fail, proving that early rejection cleared
the prior success-only terminal and commit tags.

The required release gate is the no-argument wrapper. It runs the focused
hosted World-project test to generate a fresh receipt and semantic digest, then
invokes the direct two-argument vector interface shown below it:

```bash
./ocore/kernel/smoke-world-project-runtime-qemu.sh
./ocore/kernel/smoke-world-project-receipt-qemu.sh \
  RECEIPT_HEX_FILE EXPECTED_SEMANTIC_SHA256
```

Mode 32 proves native canonical receipt interpretation and unsigned-body
semantic equality for that bounded record plus fail-closed scratch-tag reset.
The hosted receipt's placement is a caller-supplied coordinator observer, not
the deployment's proposed provider; its attempt is a dedicated coordinator
attempt rather than a route attempt, and its subject leaves package absent
instead of storing the provider implementation. Mode 32 does not independently
validate those hosted architectural choices. It does not execute the project in
O-core, verify Ed25519 natively, establish signer trust, authorize residual
`HostWorld` effects, change the `Uncommitted` fence, or supply Governor
admission/commit, authenticated membership, provider ownership or placement,
capability/lease authority, reservation, remote dispatch, consensus, recovery,
exactly-once execution, OSTADIX Alpha acceptance, a G0--G13 gate,
physical-hardware evidence, or hardware-isolation evidence.

Mode 35 is a supplemental native execution/receipt prerequisite. Trusted boot
code provisions a fixed World, Governor, node, domain, receipt, and task-attempt
identity hierarchy using the shared native identity codec. These are test
fixtures; the named Governor is not running. The native session snapshots the
validated hierarchy and derives a domain-separated context digest. A 64-byte
`ONSCAL1` instruction contains that digest, opcode 1, and two big-endian u64
operands restricted to the u32 range. It cannot supply receipt terminal data,
placement, rights, effects, or a commit claim.

The O-core handler validates the context, opcode, operand bounds, and receipt
capacity before incrementing its execution counter and adding the operands.
The result is a u64 sum, including values larger than u32. Native identity and
OWVALUE codecs then produce a fresh canonical **unsigned OWRECEIPT body** with
the exact context and instruction digest. Its terminal value comes from the
native operation, its commit fence is `Uncommitted`, and its capability,
effect, checkpoint, and evidence observations are empty. The receipt names the
kernel fixture domain without inventing a CPL3 process. Serial transport is
qualification instrumentation outside the scalar operation's receipt scope.

```bash
./ocore/kernel/smoke-world-native-scalar-qemu.sh
```

The gate retains four native result bodies and ten QEMU transcripts beneath
`target/ocore-native-scalar/`. Rust independently constructs the expected
identity bindings and arithmetic results, then decodes every returned native
body through `inspect_unsigned_receipt_v1` and requires exact canonical bytes,
the current fixture hierarchy, and the unconditional uncommitted fence. Native
controls require zero executions for stale context, unknown opcode, and
insufficient receipt capacity, and exactly one after replay rejection. Six
external malformed/stale/range requests must produce no execution or receipt.
A post-test timer establishes kernel liveness after each accepted instruction.

This gate is additional to the 26 required portable release gates. It does not
promote G1 or relabel Mode 32's historical receipt-comparison evidence. The
session's one-attempt counter is an in-memory gate invariant, not persistent
global replay protection. Each QEMU case starts a new session with intentionally
fixed fixture identities; these are not globally unique production receipt IDs.
The unsafe provision API assumes a trusted caller
and does not turn an identity or snapshot into authority. No signature is
emitted or verified natively. G1 still requires native project-route lowering
and provider dispatch tied to the logical HGraph, a live native identity and
admission source, and explicit reconciliation of residual hosted effects with
native execution. Native signing/trust and governed commitment also remain
separate implementation work; the unsigned inspector grants neither.

Mode 20 is a separate bounded KernelWorld supervisor-admission and object-model
gate. A host-side `VerifiedKernelWorld` produces a deterministic `OKWORLD1` V2
normal form that keeps verified package and canonical manifest digests
distinct. The current fixture is exactly 459 bytes with SHA-256
`0ece5f7f37ebe203d03cc7e5213dc8f9257a9a225a73e52d37d1f718424b9232`
and exactly the canonical backend requirements `["npt", "svm"]`. The kernel
verifies that exact record hash before strict parsing. It requires unique
request kinds and binds every device export's explicit `authority_request` to
one exact existing `device.*` request; non-device exports omit the field.
Several exports may share a request, while `max_devices` charges distinct bound
device authorities. Reserved rights are typed: `vm.machine` admits only
`run|stop`, and `device.*` admits only `reset|dma`.

Mode 20 admits at most two worlds through independently registered default-deny
policy keyed by package digest and copied exact request-kind/purpose bytes;
hashes are only a fast reject and never authority. Its nonexecuting VM model
supports at most two VM identities, four vCPU identities, and eight aligned
guest-page attachments backed by anonymous 4 KiB memory objects. The gate proves
exact export-authority and typed-right denial, quota and overlap denial,
generation checks, exact-world revoke/reclaim, an unrelated surviving VM, and a
later timer. The local VM graph may be sealed, but package admission
deliberately remains `ADMITTED`; no provider configured or start lifecycle is
claimed.

These are configuration objects, not a hypervisor. Mode 20 does not start or
health-check a provider, publish exports, boot a guest, enter VMX/SVM, construct
EPT/NPT, execute firmware, inject interrupts, assign devices, map DMA, or
configure an IOMMU.

Mode 21 is the separate AMD hardware-execution gate. The host requires KVM plus
the exact `svm` and `npt` CPU features, and the kernel byte-compares the V2
record's complete requirement vector to exactly `["npt", "svm"]` before SVM
initialization. It enters only a two-page real-mode synthetic guest through a
private NPT, proving one bounded interrupt, a controlled `VMMCALL`, denial of
an unmapped GPA, exact NPT teardown, stop/restart, and unrelated-VM survival.

Mode 22 is a separate TCG-compatible native boot-service lifecycle mechanism
gate. `kernel_world_boot.oc` has fixed capacity for two administrative boot
instances and four published exports. It stages an admitted world with one
configured VM identity and one exact consumer CSpace. `start` requires the
independently materialized `vm.machine:run` grant, but is only an
administrative state transition: it does not enter the vCPU or start a process,
guest, or foreign-kernel provider.

Publication requires a trusted observation of the exact health protocol ID
retained from the admitted record. A published export installs a
nontransferable `OBJECT_KERNEL_WORLD_EXPORT` capability directly into that
consumer CSpace. Every export carries a status right. A device-plane export
also carries only a reset-*request* right, and only when its byte-exact sealed
authority request received the independently granted `device.*:reset` right.
Lookup returns that already-installed exact capability and grants no authority.
Name/protocol resolution compares retained IDs together with the exact consumer
CSpace and required-right set; the native record does not retain the original
name/protocol bytes for byte-exact lookup. Authority comes only from the
already-installed capability. Publication denies a second live binding with the
same consumer-CSpace/name/protocol ID tuple.
The status operation reports the native boot generation; reset success means
only that O-core accepted broker intent for the exact live binding. It does not
dispatch to a provider or reset hardware.

Generic `SYS_CAP_CLOSE` recognizes a KernelWorld export and routes it through
the same registry-aware close transition. The binding becomes unavailable,
the capability is closed, and its service generation advances together.
Closing the final export returns that boot from `ACTIVE` to `HEALTHY`, so it can
publish again or proceed through orderly teardown without orphaned live
metadata.

Failure makes the boot generation unavailable, closes and generation-retires
all issued client capabilities, and only then revokes the exact VM graph.
Admission is retained so the declared `on_failure` policy can authorize one
fresh VM/boot/service generation and rebind; stale capabilities remain denied,
and an unrelated live service survives. Explicit stop leaves a terminal
tombstone: only `always` policy can consume it as a restart; otherwise the
owning uninstall transition first revokes admission and then consumes the
tombstone, but only after proving that no active boot or exact local VM graph
remains. A configured, un-staged replacement makes uninstall fail without
changing its graph, ticket, or admission. There is no separate public
tombstone-abandon operation, so a failed admission revoke cannot reopen the old
generation through ordinary staging.
`smoke-kernel-world-live-qemu.sh` exercises these transitions directly under
QEMU TCG and observes a later timer.

Every externally callable lifecycle or broker transition is serialized by one
single-CPU operation owner and completes at a monotonically advancing
linearization epoch. This rejects re-entry in the current gate; it is not an
SMP lock. A future SMP port must replace the ownership byte with an atomic
kernel lock while preserving the same transition boundaries.

Mode 22 does not enforce the declared health timeout, and its failure hook is
called directly by the bounded semantics gate rather than by a process fault,
trap, scheduler, or vCPU-exit path.

Mode 23 is a separate bounded execution-and-device composition gate. It runs
the AMD SVM/NPT architectural path under QEMU TCG: the outer emulator, rather
than KVM or physical AMD hardware, executes the nested guest entry and VMEXIT
instructions. One generation-tagged execution session is bound to the exact
live boot, admitted-world generation, configured VM, current vCPU, code page,
mailbox page, device-plane export ordinal, and independently granted request.
A cross-world vCPU is rejected before either SVM state or a virtual endpoint is
made live. The VM carries one execution pin while SVM owns its page mappings,
so ordinary boot failure, stop, or graph revocation cannot race that ownership.

The fixed real-mode synthetic guest first exits through the exact `VMMCALL`
expected by the coordinator. The guest supplies no health protocol identifier:
the coordinator derives the retained protocol from the bound admitted world
and only then records health and permits publication. The next guest phase
executes a non-string, non-`REP`, 32-bit `OUT` to port `0xE0`. O-core validates
the complete IOIO exit and dispatches its scalar value only to the
generation-bound kernel-internal endpoint for that session. The sole operation
returns `input XOR 0xA5A55A5A`; the broker disposition is placed in guest RAX
before execution advances beyond the intercepted instruction.

Mode 23 also connects the published reset-request capability to the exact live
virtual endpoint. Reset clears only that endpoint's scalar transaction state
and leaves the assignment owned by its execution session; it is not physical
device reset. An exact nested-page fault is the bounded failure notification.
The coordinator records the NPF, disables SVM and clears NPT while releasing
the execution pin and retained mappings, revokes the virtual endpoint, and
then invokes the boot terminal transition. That transition withdraws the
client capability before revoking the exact VM graph. An unrelated published
service remains usable. The declared `on_failure` policy then creates fresh
generation-2 VM, boot, execution-session, endpoint, and client identities;
the generation-1 session and capability remain stale while the replacement
repeats health and device execution. Orderly stop and uninstall reclaim both
worlds and a later timer remains live.

Run the portable evidence gate with:

```bash
./ocore/kernel/smoke-kernel-world-execution-device-qemu.sh
```

Mode 23 does not boot Linux, Plan 9, firmware, or a supplied user image; its
guest program is the fixed synthetic two-page probe. It provides no general
guest agent, shared queue or ring, asynchronous request processing, or SMP
coordination. Its virtual PIO endpoint is not PCI or physical-device
assignment, DMA, an IOMMU boundary, interrupt remapping, or hardware reset.
The TCG gate is not KVM evidence and establishes no physical-hardware
isolation. Modes 21 and 23 enter the synthetic guest for their separately
scoped gates; Mode 22 deliberately does not enter any guest.
