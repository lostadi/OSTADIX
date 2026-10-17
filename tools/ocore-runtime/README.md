# External runtime source capture

`scripts/ocore_runtime_capture.py` records source-built runtime/compiler frontend
outputs for the O-core importer. It executes each declared build through compiler
wrappers, preserves the original compiler command, and replays successful C/C++
translation units or Rust crates into separate LLVM text units. A successful capture
does not establish O-core lowering, dependency closure, or native OSTADIX execution.

The pinned recipes retain the complete CPython engine and Rust stdlib/compiler
objective. Their current capture profiles are hosted source builds. They do not
pretend that the OSTADIX libc/std platform ports or full-runtime native gates already
exist. CPython source is pinned to
`c35ca4cb6e296d1770fe45f9414b58eb06242e02`; Rust source and initial compiler are
pinned to `8bab26f4f68e0e26f0bb7960be334d5b520ea452` / Rust 1.97.1. Both recipes
require LLVM/Clang/llvm-nm 22.1.6. A different installed version fails admission.

```sh
python3 scripts/ocore_runtime_capture.py validate tools/ocore-runtime/cpython.recipe.json
python3 scripts/ocore_runtime_capture.py validate tools/ocore-runtime/rust.recipe.json
python3 tools/ocore-runtime/test_capture.py -v

python3 scripts/ocore_runtime_capture.py capture tools/ocore-runtime/cpython.recipe.json \
  --source /absolute/pinned-cpython-checkout \
  --build /absolute/empty-cpython-build \
  --output /absolute/empty-cpython-capture \
  --cc clang-22 --cxx clang++-22 --llvm-nm llvm-nm-22 \
  --unit-inventory /absolute/build-generated-cpython-units.json
```

Check out the exact source revision, initialize its pinned submodules recursively,
and keep the checkout clean. Use empty out-of-tree build and capture directories.
The tool does not fetch sources, install tools, or accept a populated build cache
as capture evidence. External libraries need separate pinned recipes; finding a
host library during configure does not source-build that library through O-core.
Build recipes expand `{source}`, `{build}`, `{output}`, `{recipe_dir}`, `{jobs}`,
`{cc}`, `{cxx}`, `{rustc}`, `{cargo}`, and `{rustc_wrapper}` in argv/cwd/environment fields.
The source commit timestamp supplies `SOURCE_DATE_EPOCH` unless explicitly set.
Replay preserves source-argument spelling so `__FILE__` does not become an
absolute-path variant of the original build.

The same `capture` command accepts `rust.recipe.json`, `--rustc rustc`, and
`--cargo cargo`; the initial Rust and Cargo releases are both pinned to 1.97.1.
Its source-bootstrap command requests the library, rustc implementation and Cargo,
disables downloaded rustc/LLVM substitutions, and uses the capture wrapper for Rust
compiler calls. A preparation step writes an out-of-tree `bootstrap.toml` before
`x.py` starts: the Python launcher reads initial Rust/Cargo paths from that file
before the Rust bootstrap can apply command-line `--set` overrides. The generated
configuration uses the upstream `dist` profile, locked dependencies and explicit
captured C/C++ drivers and linker. LLVM builds from the pinned submodule; linking
uses an external `lld` on `PATH`, with one LLVM linker job. Supply the scoped matching
toolchain's library paths when its linker needs compatibility libraries.
The pinned Rust bootstrap forwards an existing wrapper through
`RUSTC_WRAPPER_REAL`; the capture records each actual stage compiler separately.
Its C/C++ configuration must select the supplied wrappers. Object files produced
by a compiler that bypasses them fail the output audit. A complete Rust milestone
also needs native compiler execution and routing newly compiled programs through
O-core; capturing rustc's own implementation provides only one side of that bridge.
The required-unit floor retains `core`, `alloc`, `std`, both panic runtimes, unwind,
proc macros, the test runtime and compiler builtins. Full Cargo unit graphs and LLVM
`compile_commands.json`, together with final output membership, must account for
bootstrap helpers, stage-specific library/compiler variants and source dependencies
before a complete source inventory can be admitted.

## Report contract

### Reusable verified native dependencies

Successful `olangc --native-runtime` lowering writes `runtime.native-ir.json`,
a self-contained `ocore-native-module-set-v1` package. It embeds exact verified
native-module JSON, hashes, original unit and component/capture identities,
target and execution profiles, and the recomputed symbol inventory. Loading a
package never opens its original source, LLVM, capture or native-module paths.
This is a native IR artifact; it does not attach `.O` scripts or implement an
OIR native orchestrator.

Supply one package per declared dependency using repeated options:

```sh
olangc capture/report.json --native-runtime --native-runtime-output ir \
  --native-runtime-dependency /artifacts/libc/runtime.native-ir.json \
  --native-isa riscv64-unknown-none -o /artifacts/engine
olangc /artifacts/engine/runtime.native-ir.json --native-runtime \
  --native-isa riscv64-unknown-none --native-runtime-output obj -o /artifacts/objects
```

The compiler requires exact declared dependency names, checks all embedded
module hashes and structural validity, reconstructs the component/unit
inventory and dependency graph, requires matching target/TLS/atomic profiles,
and recomputes symbol, ABI and COMDAT closure. Missing or unused packages,
conflicting component definitions and forged closure summaries reject. Shared
identical transitive components are included once, preserving explicit module
order for weak/COMDAT selection. Native symbol recursion and cyclic component
dependency edges remain supported when the included closure is complete.
Object output materializes and lowers all modules through the owned emitters.
Explicit non-null source pins reject until the package represents and checks
that source-identity constraint; a matching dependency name cannot satisfy an
unchecked pin. Captured and dependency units use the same qualified identities,
so source-selected unit text cannot merge their private symbol scopes.

Direct package input needs no original capture or LLVM installation. It
rejects implicit retargeting and importer/profile/dependency overrides, because
the package already binds that closure and execution profile. Object emission
still needs `ocorec` and its assembler; it does not link an executable.

The receipt separates `native_module_dependency_closure_complete` and
`module_set_artifact` from whole-runtime `dependency_closure_complete`,
`artifact_complete` and native runtime acceptance. Complete module closure does
not supply platform services, resources, linking, reference execution, a native
HGraph dispatcher or JIT publication. Capture digests are retained provenance
coordinates; an unsigned package is not independent source attestation.

The [Lua source recipe](lua/README.md) supplies a full Make-derived inventory
for the pinned original engine and frontend. It is an additional capture route,
not an assertion that currently unsupported Lua imports have been lowered.

### Capture report fields

`report.json` uses `ocore-runtime-capture-v1`. Important fields are:

| Field | Evidence |
|---|---|
| `manifest`, `source`, `tools` | Recipe hash, exact Git commit/submodule state, compiler version and executable hashes |
| `build_steps` | Exact argument arrays, cwd, logs and exit status |
| `invocations` | Atomic per-call records, expanded response files, relevant build environment, original status, replay status and errors |
| `units[].ir` | LLVM text path, SHA-256, size, frontend target triple and DataLayout |
| `units[].dependencies` | Frontend dependency-file inputs with paths/hashes |
| `lowering_unit_ids`, `non_lowering_units` | Exact partition of runtime units and explicitly evidenced configure probes/host build tools; all IR remains in `units` |
| `unit_inventory`, `unclassified_unit_ids` | Hashed complete inventory and any captured IR without a justified role |
| `runtime_output_membership` | Observed native final-output roots, link inputs, archive members and contributing compiler invocations |
| `invocations[].outputs` | Native reference outputs, hashes and defined/undefined symbols |
| `dependencies` | Observed link inputs, declared external dependencies and unresolved symbols; `closed` remains false |
| `failed_required_units` | Missing, failed or target-mismatched declared units |
| `uncaptured_outputs` | Native objects/Rust archives without matching captured production evidence |

IR hashes and target metadata are checked again when generating a report. Exact
copies of captured object/archive outputs retain their captured origin. LLVM IR is
not retargeted: the importer must preserve or explicitly lower the frontend's ABI
and target-specific semantics. Host tools and native payloads need distinct target
profiles in their full build inventory.

`capture_complete` requires successful build steps, exact source/tool admission,
all declared unit/output requirements, successful LLVM replay, and a clean native
object audit. The pinned runtime recipes also require a complete build-generated
unit inventory. Its schema is `ocore-runtime-unit-inventory-v1`, with `complete:true`
and `units` containing `{id, kind, source, role?, target_triple?}` records. `kind` is
`clang` for C/C++ or `rustc`; `source` is a checkout-relative path/glob. This inventory
must come from the full build/module configuration, including required modules that
configure could otherwise omit. The recipe's required-unit list is a floor, not a
complete standard-library manifest. Without the full inventory the tool retains
all captured evidence, reports incomplete coverage, and exits unsuccessfully.

Every captured LLVM unit must belong to the inventory's lowering source units or
an explicit `non_lowering_units` rule. A rule contains a unique `id`, a `role` of
`configure_probe` or `host_build_tool`, and either exact `unit_ids` or a
`{kind, source, build_step}` selector. Its `evidence` contains a concrete `reason`
and nonempty `artifacts` with absolute paths and SHA-256 hashes. The report binds
each exclusion to those artifacts, the inventory hash and the actual sequential
build step's argv, status and log hash. Conflicting assignments, unmatched rules,
changed evidence and unclassified units reject completeness. Every recipe-required
capability must retain a selected runtime unit. Whole source units remain selected, including
cold functions; selection does not use execution-frequency or percentage cutoffs.

`units` may use `build_step` or exact `invocation_ids` to distinguish host/bootstrap
variants from runtime variants of the same source. The complete inventory determines
the lowering set; each recipe-required capability must still have a selected runtime
unit. One frontend invocation cannot split its Rust codegen units between runtime
and host roles.

Exclusions are also checked against actual native build/link membership. Roots are
the recipe's required final outputs plus `runtime_outputs` entries in the inventory,
each with an absolute `path`, `sha256` and optional `bytes`. Compiler link inputs and
regular GNU/BSD archive member hashes connect those roots to captured object
production. A claimed probe/helper whose object contributes to a declared runtime
output is rejected, even when its function was never exercised. Thin archives and
changed link artifacts cannot establish this exclusion proof. Dynamically loaded
extensions must be explicit runtime roots. This observed graph does not prove that
a caller-declared runtime inventory includes every platform service, library or
resource; dependency closure and native qualification remain separate requirements.

The report always leaves `dependency_closure_complete`, `ocore_lowering_complete`,
`native_execution_qualified`, and `runtime_complete` false. Those require subsequent
source dependency capture, verified O-core imports, linkage/platform implementation,
and native execution gates. Percentages or counts of LLVM units cannot establish
those properties.

## Independent capture re-admission

Recheck the original evidence before importing a saved capture report:

```sh
python3 scripts/ocore_runtime_capture.py verify-report /absolute/capture/report.json \
  --receipt /absolute/new-capture-verification.json
```

Verification reconstructs the report from the original recipe, pinned clean source,
compiler artifacts, invocation journal, full unit inventory and declared native
output graph. It checks every reconstructed report field, including source/stage
selectors, exclusions, cold linked objects and archive members. Rewriting mutually
consistent selected and required unit lists cannot replace that evidence. The final
inventory and build-log hashes are bound in the original capture session, so changing
those artifacts and regenerating a report also fails admission. Keep the
original capture directory and its referenced artifacts available; the command
does not rebuild, recapture or rewrite them. A failed recheck removes a stale receipt
at the requested output path, and receipts cannot overwrite capture inputs.

`verify_report(report: dict)` provides the same read-only reconstruction for the
embedded `olangc` worker. Its `report_content_sha256` hashes canonical JSON; the CLI
also records the exact input file's hash in `report`. The receipt proves the capture
partition and observed declared output membership. It does not establish a complete
platform, dependency closure or native runtime execution.

For an incomplete capture, diagnose all whole LLVM units belonging to one recorded
successful build step without treating that selection as completeness admission:

```sh
python3 scripts/check_ocore_runtime_imports.py /absolute/capture/report.json \
  --step build-runtime-and-extensions --ocorec target/debug/ocorec \
  --llvm-library /absolute/matching/libLLVM.so --llvm-sha256 DIGEST \
  --jobs 8 --output /absolute/new-import-audit
```

The audit snapshots the compiler, preserves every captured unit as provenance and
retains per-unit diagnostics. Successful imports receive independent verification
and O-core object emission. `audit_complete` means every selected unit was attempted;
all runtime completeness and native qualification flags remain false.

## O-core lowering driver

The opt-in `olangc` path consumes a complete capture report before the ordinary
`.O` parser. It imports the explicitly selected runtime units with the matching LLVM parser through
the sibling `ocorec`, verifies the resulting native IR, and optionally emits objects
through O-core's own ISA backend:

```sh
cargo build --locked --bin olangc --bin ocorec
target/debug/olangc /absolute/capture/report.json --native-runtime \
  --native-isa x86_64-unknown-none --native-runtime-output ir \
  -o /absolute/new-native-ir-directory
```

Use `--native-runtime-output obj` for relocatable objects. An explicitly selected
LLVM parser uses `--llvm-library PATH --llvm-sha256 DIGEST`. The frontend module's
architecture must match the selected ISA; its target triple and DataLayout are
preserved. Cross-module platform/layout differences, unresolved declarations,
incompatible ABI contracts, duplicate exported definitions and unverified declared
dependencies fail closed. Module-local/private symbols retain their own scopes.

`coverage.json` binds the capture report, imported module hashes and structural
verification receipts. It records every unit, including failures, and distinguishes
unit lowering from symbol closure and native execution. Partial output directories
remain inspectable after failure. A successful object-set result has not linked or
booted a runtime, executed `.O`, or supplied an engine adapter; `runtime_complete`
and `native_execution_qualified` remain false.

`rust_probe.rs` is a small actual `no_std` Rust frontend probe with three scalar
C-ABI exports. It is not evidence of stdlib/rustc completeness or native compiler
bootstrap. Its floating-point, unwinding and platform dependencies are intentionally
outside this probe's scope, while the full Rust recipe continues to require them.

## Current boundaries

Capture covers calls routed through `CC`, `CXX`, `RUSTC_WRAPPER`, and Rust's forwarded
bootstrap wrapper. It is not a system-wide process tracer. The object audit checks
the declared audit roots; outputs outside those roots are not silently claimed as
covered. Archives/shared libraries supplied by the host are dependency evidence,
not imported implementations. Required-unit inventories and source-built dependency
recipes must account for those paths before a runtime can be complete.

GNU Clang response files and Rust's line-based response files are supported, as
are parallel compilation, multiple C/C++ source files in a command, and multiple
Rust LLVM codegen units. Preprocessing/metadata-only calls and failed feature probes
remain in the journal. Failed declared units fail completeness. Required assembly,
stdin translation units, failed IR replay, and absent target metadata fail capture
instead of disappearing from the inventory. Wrappers preserve the original native
compiler exit status, so later units still build after a replay gap; the final
capture command rejects the resulting incomplete report. LLVM-only builds without native outputs
need a separate artifact policy rather than pretending to satisfy the current native
reference-output audit.

The CPython recipe explicitly requires representative standard-library extensions,
including SSL, SQLite, ctypes, compression and Tk. Missing development dependencies
therefore remain visible failures. It still needs a full extension inventory and
source-built dependency recipes. The Rust recipe retains both panic profiles,
core/alloc/std, rustc's LLVM implementation, Cargo and helper closure; an abort-only
or `no_std` capture does not satisfy the requested full Rust scope.

Relevant upstream contracts are [Clang's LLVM emission options](https://clang.llvm.org/docs/CommandGuide/clang.html),
[rustc output kinds](https://doc.rust-lang.org/rustc/command-line-arguments.html#--emit-specifies-the-types-of-output-files-to-generate),
[the pinned Rust wrapper forwarding](https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/src/bootstrap/src/core/builder/cargo.rs),
[its bootstrap options](https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/bootstrap.example.toml),
and [CPython's extension build inventory](https://github.com/python/cpython/blob/c35ca4cb6e296d1770fe45f9414b58eb06242e02/Modules/Setup.stdlib.in).
