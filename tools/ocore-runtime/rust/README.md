# Original Rust source/build inventory

`build_inventory.py` takes a read-only observation of the configured build and
the original source-capture journals. It does not execute `x.py`, Cargo, Ninja,
build recipes, journal arguments, or source code. It covers whatever the
supplied metadata declares; it has no crate allowlist or action-count limit.

The result retains every configured Cargo unit and dependency edge, native
compile command, Ninja action, observed invocation, retry, LLVM unit, output,
and dependency occurrence. Cargo target, platform, profile, features, build
mode, Rust metadata disambiguators, requested CGUs, recorded stage environment,
and output membership records stay distinct. Duplicate archive-member names
retain their original indices. A CGU is not assigned to an archive member
without evidence. The requested `x.py` steps and actual `RUSTC_STAGE` values
remain separate; a source directory name does not establish the compiler stage.

Supply every available stage's metadata with repeated options:

```bash
python3 tools/ocore-runtime/rust/build_inventory.py \
  --source "$RUST_SOURCE_ROOT" \
  --build "$RUST_BUILD_ROOT" \
  --capture "$RUST_CAPTURE_ROOT" \
  --cargo-unit-graph "$RUST_BUILD_ROOT/bootstrap-unit-graph.json" \
  --compile-commands "$RUST_LLVM_BUILD/compile_commands.json" \
  --ninja "$RUST_LLVM_BUILD/build.ninja" \
  --metadata "$RUST_BUILD_ROOT/bootstrap-unit-graph-receipt.json" \
  --output "$RUST_CAPTURE_ROOT/source-build-inventory-observation.json"
```

`--cargo-metadata` retains the full package/resolve graph and follows package
manifests. `--cargo-messages` retains Cargo's JSON message stream, including
compiler artifacts and build-script messages. `--manifest` adds a source
manifest root; local workspace and dependency paths are followed without
enabling optional features. These manifests are explicitly a source superset,
not a resolved or built graph. `--metadata` preserves additional configuration,
tool, stage, or continuation receipts without interpreting their assertions.

The output must be a new path. Raw metadata is copied by SHA-256 into the
adjacent `.evidence` directory. Each `record.artifact_sha256` resolves through
`metadata_inputs`; `pointer` is an RFC 6901 JSON pointer and `line` is one-based.
These references preserve complete records without repeating a journal for
every graph edge. The inventory includes the helper's own source digest.
Sources, LLVM IR, outputs, and dependencies are hashed as observed, with
recorded and fresh hashes kept separate. `--stat-only` explicitly leaves their
content unverified. A running build is observed over an interval, not as an
atomic filesystem snapshot; changing files and unfinished actions are gaps.

Ninja log versions 5 and 7 preserve all original entries, including repeated
outputs. Their command hashes are opaque versioned build-log values. They are
not source hashes or frontend-admission receipts. Unknown log versions and
unparsed metadata remain explicit gaps with the original bytes retained.

Native compile commands retain exact original arguments. A second, separately
labeled diagnostic comparison ignores only auxiliary dependency tracking
flags (`-MD`, `-MMD`, `-MP`, `-MF`, `-MT`, `-MQ`). It retains the removed flags
and does not erase includes, macros, compiler mode, optimization, or source and
output paths. Matching these arguments does not prove compiler identity or
source-capture admission.

Every report is a **diagnostic draft**: `complete`,
`source_production_inventory_complete`, `runtime_output_membership_complete`,
`dependency_closure_complete`, `native_execution_qualified`, and
`runtime_complete` remain false. Missing stage graphs, assembly, prebuilt
dependencies, generated inputs with unproven producers, original evidence
integrity failures, and unobserved requested runtime outputs stay explicit.
Same-path, same-content source-production candidates do not prove ordered
linker selection, archive extraction, platform providers, or final runtime
membership. The source-capture qualifier and ordered native-tool closure are
separate requirements; this helper cannot repair or qualify old journals.

Focused tests execute only synthetic metadata:

```bash
python3 -m unittest discover -s tools/ocore-runtime/rust \
  -p test_build_inventory.py -v
```

`stage_roles.py` separately records child build attempts, producer identities
and Cargo fingerprint candidates from the original source and capture. It
keeps reported stages, retries, changed compiler bytes and ambiguous matches
distinct. Child observations do not establish the original parent command,
the complete payload graph, final roles or runtime qualification; those gates
remain false.

```bash
python3 tools/ocore-runtime/rust/stage_roles.py \
  --source "$RUST_SOURCE_ROOT" \
  --capture "$RUST_CAPTURE_ROOT" \
  --metadata "$RUST_BUILD_ROOT/bootstrap-unit-graph-receipt.json" \
  --output "$RUST_CAPTURE_ROOT/stage-role-candidates.json"
python3 -m unittest discover -s tools/ocore-runtime/rust \
  -p test_stage_roles.py -v
```

`observe_cargo.py` prepares a wrapper for an original Cargo binary using a new,
snapshot-bound source-capture session. It preserves actual parent commands,
child results and configured unit-graph queries. These are build observations;
they do not establish complete payload membership, provider closure or Rust
compiler lowering. The observer checks its own trusted source digest separately
from the source-capture worker binding.

```bash
python3 tools/ocore-runtime/rust/observe_cargo.py \
  --directory "$RUST_CARGO_OBSERVER_ROOT" \
  --cargo "$RUST_ORIGINAL_CARGO" \
  --capture "$RUST_CAPTURE_ROOT" \
  --expected-worker-sha256 9e10e5fd5a95c196bc1f8403a3180d450b477a419abc4774316a12fbe3f40993
python3 -m unittest discover -s tools/ocore-runtime/rust \
  -p test_observe_cargo.py -v
```

The observer directory must be new. Use its returned `wrapper` path when
invoking Cargo; preparing it alone does not observe a build.
`full.recipe.json` prepares this pinned observer, uses it for the original
bootstrap and verifies its recorded parent events afterward. The inventory
retains every recorded configured graph and parent event; this wiring does
not qualify complete payload membership or provider closure.

The capture worker offers an optional Rust policy. In a separate recipe's
`toolchain` object, retain the existing exact toolchain pins and add:

```json
{ "rust_capture_policy": "rust-embedded-bc-v1" }
```

The checked-in `full.recipe.json` currently omits this policy. Enabling it for
the complete Rust build remains held pending ordered linked-CGU ownership;
format acceptance alone does not establish complete source, dependency or
admission closure. Preparing the observer or selecting this policy
does not establish complete runtime/compiler support.

Without the policy, the worker executes the incoming compiler command
unchanged and captures textual `.ll` with a separate frontend replay. Under
`rust-embedded-bc-v1`, supported Rust translation invocations instead execute
an explicitly instrumented command: recognized `embed-bitcode` and
`save-temps` options become one `-C embed-bitcode=yes` and one
`-C save-temps=yes`, with missing options added. Invalid original option
values remain for the frontend to diagnose. Journals retain incoming `argv`,
`expanded_argv`, exact `executed_argv`, policy transformations and original
response-file bytes. The journal distinguishes the incoming command from the
executed command; this path uses no frontend replay. Capture errors remain
separate from the invoked frontend's result and do not replace its status.

Supported Rust response files use rustc's line-based argument grammar.
Undecodable files, shell argfiles, embedded NULs, literal nested `@` arguments
and `--` boundaries remain explicit gaps: the policy forwards the original
command rather than flattening an unsupported argument boundary. Queries
also retain their incoming command. `frontend.default_sysroot` records the
actual `--print sysroot` query; explicit `--sysroot` arguments determine the
effective sysroot when present. Reported stage environment stays separate
from either sysroot choice.

`payload_inventory.py` checks embedded `.llvmbc` bytes from actual ELF objects
and exact members of ordinary archives, including `.rlib` outputs. Its
`extract_embedded_bitcode(artifact, member_index=None)` API retains container,
logical and physical member indices, original name bytes, section offsets,
sizes and hashes. `verify_saved_cgu(record, compiler_event)` binds those bytes
to the producer's output and saved-CGU journal record. The registered helper
is pinned to SHA-256
`0190404305ffa887b60d5f23e9af64029c1fe770ce6c705d19a65ee3a89d6767`.
Duplicate member names, save-temp filenames and replayed IR do not establish
these byte edges. Cargo parent/child receipts and compiler-context bindings
remain separate checks.

Saved `cgu-N.bc` files are exact extracted bitcode ranges, not the legacy
replayed `.ll` files. The pinned LLVM decoder records their format, target and
layout for capture evidence; decoding or extracting them does not establish
O-core admission, native machine equivalence or post-LTO equivalence.
Focused evidence includes an original three-local-crate Cargo build and
object/archive byte checks, with full ownership and lowering gates still
false.

Executables, dylibs and build-script binaries without embedded bitcode require
ordered linker-input CGU ownership. Installed sysroot providers, archive
selection and complete runtime/compiler dependency closure remain unresolved.
Missing, compressed, ambiguous or unsupported embedded sections and archive
forms stay typed gaps. This policy supplies producer byte evidence; it does
not fill missing provider edges or qualify a complete native runtime/compiler.
