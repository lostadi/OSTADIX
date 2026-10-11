# Original LLD22 source hook candidate

This candidate is additive instrumentation of LLVM/LLD revision `dcc3606807c989700e0ac1cac18c31741bcd40d9`. It has not been compiled or executed. The Python gate uses authored packet fixtures, and one artifact-only readmission of the genuine sealed V3 Rust packets. A source patch, synthetic packet, successful decoder test, or link success does not establish complete Rust, LLVM, provider, or O-core lowering.

## Source-issued edges

* `elf::link` starts a per-Ctx session and records its original ELF-driver argv separately from `/proc/self/cmdline`, actual process image bytes and PID. It records the original return predicate, error count and observed output bytes at return. Fatal/aborted links may lack a finish packet: the capture worker must forward the original process status and retain a lifecycle gap.
* `readFile` snapshots each actual opened buffer before releasing it. `createFiles` retains parsed argument occurrences and positional state. `addFile` records resolved input occurrences, original read identity, static/as-needed/group/whole-archive/start-lib state. Repeated inputs remain separate occurrences even when hashes/names coincide.
* `getArchiveMembers` retains original `Archive::Child` physical index, raw/resolved names, header/data offsets, original container and member bytes. The existing `Archive` implementation performs enumeration and member loading. Each actual constructed `InputFile*` is explicitly bound to its original direct or member occurrence; this fixes the receipt gap where native constructors previously dropped archive offsets. Derivative fat-LTO subbuffers retain exact pointer-range/byte relations.
* `Symbol::extract` records the actual lazy transition and triggering symbol before the original parse. `doParseFile` records actual parsed/loaded input order. Parsing a shared object is separate from its final `isNeeded` decision. These are link membership facts, not proof that every loaded section survives GC/ICF or that an input was source-produced by Rust.
* The original `ExpansionContext` reader invokes an optional callback on the exact original response buffer before BOM/encoding normalization. LLD retains response-expanded argv and plugin-option-normalized argv, with the original quoting/recursion/error behavior. No secondary tokenizer guesses at the submitted arguments.
* Original script/version/dynamic-list/defsym buffers, INCLUDE source resources, and script operand scopes are retained. Resolved nested input occurrences reference their actual script operand. Unsupported/failed source reads remain explicit errors/gaps; a script's bytes alone do not certify its platform semantics.
* Final source symbol resolution includes symbol kind/binding/type/visibility/version/use/preemption and actual InputFile identity. Final shared providers retain SONAME, `isNeeded` and DT_NEEDED requirements. Version rule names/patterns remain byte arrays. Local relocation and transitive loader/provider/source closure are not declared complete.
* The original LTO pre-codegen module hook is chained after existing configuration/save-temp setup without replacing the original callback or its return decision. It snapshots actual module BC/triple/DataLayout/task. Original LTO output/cache buffers are retained by task and source buffer identity. Cache-only/out-of-process/distributed phases and later machine transforms remain explicit gaps. This does not infer equivalence from a pre-LTO module or a saved filename.

## Compatibility with sealed Rust V3

The unchanged V3 source hook already sets `OCORE_RUST_LINK_ATTEMPT` to the exact pending spawn packet before invoking the original selected native driver. The LLD hook can receive an explicit `OCORE_LLD_LINK_CONTEXT`, or derive a unique source-issued context at its own entry from that inherited marker plus:

```
OCORE_LLD_HOOK_REGISTRATION=/absolute/registered-original-lld-image.json
OCORE_LLD_CAPTURE_DIRECTORY=/absolute/worker-owned/per-rust-invocation/link-packets
```

The derived context binds the original spawn artifact, independently selected registration and original LLD PID/invocation counter. It creates distinct packet roots for retries/descendants. It changes no program, argv, linker option, PATH, CC, LD, library path, or original linker algorithm. If GCC/BFD/Gold or another unregistered linker is the actual selection, there is no LLD receipt; collection retains that original attempt/status as a typed gap. Selecting another linker to make a gate pass is not this adapter.

Strict context:
`ocore-lld-link-context-v1 {packet_directory, invocation_id, rust_spawn_seed, linker_registration, driver_trace_seed}`.
Registration:
`ocore-lld-hook-registration-v1 {source_revision, source_patch, linker_image, hook_source_manifest, scope}`.
The worker's trusted registry supplies the expected registration hash. An environment path or packet cannot choose trust.

`python/lld_capture.py`:

```
manifest(packet_root, manifest_outside_packet_root) -> artifact
 decode(manifest, context, registration,
        trusted_registration_sha256=FIXED_RECIPE_REGISTRY_SHA,
        archive_helper=PINNED_019040_ARTIFACT,
        trusted_archive_helper_sha256=019040...,
        producer_observation=original_V3_observation,
        producer_readmission=independently_pinned_original_producer_reader,
        driver_trace=optional_finalized_original_trace,
        trusted_trace_worker_sha256=independent_registry_sha,
        observed_linker_status=optional_original_waited_status)
```

All event sequences, original references, file closure, raw bytes, physical ordinary archive ranges, exact source subbuffers, lazy-selection order, final source symbol owners and registered actual image identity are checked. Dropped/duplicate/tampered metadata/resources fail readmission. The decoder returns separate `ordered_input_occurrences`, `selected_input_occurrences`, `actual_archive_extractions`, original LTO records, provider/version requirements and producer joins. Producer joins require exact original object bytes and independently reconstructed Rust packets; ambiguity stays a gap. Original Rust output-scope association is explicit, with differing/partial output bytes retained as a gap. Linked inputs are never appended to Rust `outputs` or `saved_cgus`.

`python/link_integration.py` is executable artifact-only worker integration:

```
finalize_root(worker_owned_link_root, root_manifest_outside_root) -> artifact
collect(root_manifest, original_producer_observation, producer_readmission=...,
        registration=..., trusted_registration_sha256=...,
        archive_helper=..., trusted_archive_helper_sha256=...,
        packet_manifests={original_packet_root: finalized_manifest},
        driver_traces={original_packet_root: optional_trace}, ...)
```

The capture worker hashes the finalized root and child manifests in the original invocation journal after waiting. Collection independently re-admits the original producer observation. Every original native attempt is retained, including failed/native-other-linker attempts and missing packets. Readmission failures are typed capture gaps; original observed tool status is never overwritten by collector status. The held live capture worker/observer/recipe and sealed V3 images remain untouched.

## Explicit cc-to-linker barrier

`ocore-native-driver-trace-v1` is a prospective independently pinned process-observer packet. It must record original exec/fork generation edges, actual executable byte artifacts, original requested program versus actual kernel image, raw argv/env/cwd and wait statuses. The decoder prototype checks the original V3 waited native-child PID/command, ordered ancestry to the LLD session PID, registered actual image, original process argv, namespace seed and actual LLD status. Its authored trace tests are protocol tests, not a ptrace implementation or execution proof. The current decoder always leaves `actual_driver_descendants_verified:false`.

Actual process tracing must start before original compiler execution, follow fork/vfork/clone/exec/exit, preserve exec generations and distinguish self-exec, shebang/interpreter argv and requested program from kernel executable. It must retain response bytes at original reads and bind any mapped dynamic tool dependencies separately. Source PIDs/environment markers alone are insufficient. Until that original observer is implemented and gated, no whole driver/link closure is admitted.

## Required deployment stages

1. Build a new original LLD/LLVM Support image coherently in a distinct private source/build tree and register its original source/patch/build/image/dependency closure. The callback changes `ExpansionContext` layout: linking new LLD code against old Support objects is invalid. Rebuild Support and affected consumers together. No build has run for this candidate.
2. Gate the additive source hook on real untouched objects/archives, repeated equal names, lazy extraction, whole-archive/groups/scripts/versioned shared providers, response success/failure and LTO/cache. Preserve original selected compiler/driver/linker and original status. Gate all required target ELF profiles against original source tools.
3. Implement/gate the original process observer and integrate the per-invocation markers/root manifests. Missing original selected-linker adapters, trace loss, mapped image ambiguity and unsupported driver/interpreter routes fail closure without native substitution.
4. Join every selected object/member to actual original producer/source/phase receipts. A container hash or successful rlib/link is not source ownership. Native C/C++/ASM/provider/sysroot/compiler-helper builds need their own original producer edges. Thin archive external-member range verification is not yet qualified by the frozen ordinary-archive helper.
5. Resolve all actual provider/symbol/version/script/platform obligations and later LTO/machine semantics before O-core import/verification/link admission. Existing O-core support, stage labels or generic fixture gates do not fill these edges. Full original compiler and generated-output routing remain separate unfinished capabilities.

## Prepared first-build command

```
python3 /home/ustad/.cache/ostadix-research/lld-native-link-capture-r1wbctzh/run_build.py --execute
```

This command is prepared but has not run. It uses the distinct full private source tree at `private-build/source` and the distinct native package at `private-build/llvm-prefix`. Preparation compared 169,028 original source entries and 2,633 package entries, with regular-file inode separation. The original LLVM revision and source-built LLVM/LLD caches remain untouched.

The runner uses pinned `/usr/bin/cmake`, `/usr/bin/ninja`, SDK22 Clang/Clang++/llvm-ar/llvm-ranlib/LLD directly. It preserves the original LLVM configuration and all 19 cached configured target libraries. It rebuilds the changed original Support library and original Demangle dependency, validates generated ABI/feature contracts, copies those rebuilt archives and the matching changed header into the private package, then rebuilds all original LLD components against that package. No original codegenerator feature is disabled and no historical capture wrapper is reused. Jobs are two. Every configure/build argv, original observed return code and log is retained in a unique build-attempt directory. Failure stops that attempt without relabeling it successful.

The new LLD image is not executed by the build runner. Real source-hook qualification must use explicitly declared original tool identities and profiles. A genuine V3 Rust compile whose unchanged selected driver reaches a registered hooked LLD can publish original attempt/output associations via the existing inherited marker. Existing GCC/BFD selections remain missing-adapter gaps; the worker must not silently change PATH, driver or linker to manufacture an LLD receipt. A separately declared LLD development profile is useful for qualifying the source hook, but is not evidence that an unchanged GCC/BFD production selection is captured.

The first real gate should preserve original source-issued receipts for repeated archive occurrences and equal member names, normal/whole-archive/group lazy extraction, response expansion and response failure, scripts and versioned shared providers, ordinary bitcode LTO and cached output. It must independently compare original output status and full archive/container/member byte ranges to the retained input artifacts. Then a genuine V3 bin/dylib/proc-macro/build-script compile should join those original LLD source packets to original producer and output-scope receipts without appending linked files to rustc outputs. The cc-to-linker process observer and selected native/provider source production remain explicit additional prerequisites.
