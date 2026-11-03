# Original APK source-compilation contract: current-base support proposal

This additive proposal follows the coordinator's current component plan. It changes no active source, docs, runtime or VM. No builds, imports, tests, package commands or VM actions were performed. Static ELF inspection and source/metadata hashing are the only new observations. The files here are a proposal and requirements ledger, not a runnable `ocore-runtime-recipe-v1` or native admission receipt. Root retains integration ownership.

## Findings that affect the next capture

1. The retained original APK runtime uses **musl 1.2.6-r3**. The available original musl tree and full-static recipe use **1.2.5**, commit `0784374d561435f7c787a555aeab8ede699ed298`, with the shared loader disabled. That recipe is a useful graph-capture pattern; it is not the matching APK libc/loader profile. The three musl memory units used by u9fs do not close this gap.
2. APK 3.0.8-r0 depends on libapk, zlib and musl; libapk also requires original OpenSSL 3.5.9 libraries. The retained original BusyBox 1.37.0-r31 supplies `/bin/sh` and installation-trigger helpers. `reference-observations.json` records exact original ELF hashes, `DT_NEEDED`, interpreter paths, installed metadata and readelf output without executing those binaries.
3. `DT_NEEDED` is a lower bound. The root includes OpenSSL's original `legacy.so` provider; configured provider loading, trust/config data, original scripts and interpreter/helper execution must be captured from the build and runtime profile. A list of linked DSOs alone is not the whole manager graph.
4. Matching APK/OpenSSL/BusyBox/musl-1.2.6 source trees, full patchsets and configurations were not located in the scoped local inspection. Installed package records provide Alpine packaging commits, not upstream source pins. The retained zlib 1.3.2 archive and declared security patch are useful inputs, but their presence does not supply an admitted complete distro build graph.
5. The historical full-musl source-build receipt named in `tools/ocore-runtime/libc/README.md` is absent at that exact local path. Preserve the README's claim as documentary evidence until its receipt is located or a new isolated capture is coordinated. This observation does not invalidate other historical receipts or the separately qualified seven-unit component.

## Preserve two different qualifications

The earlier APK behavioral proposal requires identical original binary inputs on a matched Linux reference and native ABI candidate. Keep that gate unchanged and label it supplied-original-binary execution. It does not prove implementation lowering.

A source-native profile needs an additional comparison: identical pinned original source, patches, configured features, libraries, trust inputs and package fixtures; one output from the original reference build and one through `olangc` capture/import/verify/link. Those outputs have distinct code hashes. Bind both, compare original observable behavior, and never present the reference ELF or frontend objects as the lowered implementation. If a new static APK/libc profile is selected, declare and qualify it independently on both sides; do not silently substitute it for the retained dynamic profile. Different libc versions or omitted crypto/providers/scripts cannot be normalized away.

## Existing compiler hooks to reuse

| Stage | Current implementation | Proposal use |
|---|---|---|
| Compiler-owned entry | `src/bin/olangc/native_runtime.rs::compile_runtime`; `native_runtime/source_recipe.rs::compile` | Keep recipe dispatch, new output directory checks, embedded capture-worker identity and stage receipts owned by `olangc` |
| Complete original source/build graph | `scripts/ocore_runtime_capture.py::validate_recipe`, `verify_source`, `runtime_output_membership`, `linkage_evidence`, `partition_units`, `make_report`, `verify_report` | Pin clean source/config and actual producer invocations; reconstruct required-unit roles, native output ownership and reference link/archive membership independently |
| Evaluated whole-build inventory | `tools/ocore-runtime/libc/build_inventory.py::plan` and `inventory` | Adapt its evaluated upstream graph, dry-run command plan, per-occurrence argv/cwd, generated headers and ordered archive-member checks to the actual APK/dependency build systems; do not handpick a successful subset |
| Whole-unit import and owned emission | `native_runtime.rs::checked_ir`, `capture_admission`, `reverify_capture`, `compile_with_compiler` | Import all required units, verify exact module hashes with O-core, emit owned objects and retain symbol/relocation inventories |
| Included component dependencies | `tools/ocore-runtime/u9fs/build_native.py::completed`, `object_paths`, and dependency module-set handoff | Reuse receipt checks and hash-bound dependency linking; seven-object/exact-symbol constraints remain specific to u9fs, not a generic manager admission rule |
| Behavioral comparison and consumer admission | u9fs `test_component`; `scripts/okernel_native_codec.py::validate`/`stage` | Keep original reference objects confined to differential tests; use separately declared manager/runtime admission and artifact ownership checks |

Current source hashes for every hook are retained in `input-identities.json`. These are source identities, not proof that an installed compiler executable embeds these same bytes. A future run must bind the actual compiler binary, frontend, LLVM parser library, producer registry, capture worker, linker and helper identities.

## Required graph and receipts

Start from the authentic APK and dependency packaging recipes at the recorded packaging commits. Recover upstream archives/commits, patch ordering, generated configuration/headers, supported original build targets and all tool invocations. Do not invent a Git pin from a version or packaging commit. Current generic source capture requires a full upstream Git revision and clean source; an archive/patch workflow needs a verified provenance binding before it can satisfy that interface. Do not create a synthetic commit and claim it is upstream identity.

The future inventory must contain every required configured source/object and ordered archive member, even cold members not reached by the first test. Record original configure/build probes separately with independently checked exclusions. Include actual final reference link inputs and generated metadata; compile_commands alone does not cover assembly, generated tools or dynamically loaded providers. Host build generators may be declared build dependencies, but their execution cannot stand in for native runtime helpers. Original install scripts remain scripts with their original interpreter closure, not rewritten equivalents.

For each included source component retain the source recipe, capture journal/verification, required-unit inventory, original source/config/patch provenance, full O-core module set, verification and owned object hashes. The current dependency module-set schema rejects non-null `source_pin`; it also does not reverify original source capture merely by replaying a module set. Bind and re-admit the companion source-recipe/capture receipts explicitly in the future source-native profile instead of silently dropping provenance or pretending that schema already checks it.

Inventory every undefined symbol and runtime-loaded/helper edge to an included verified implementation or a declared native platform interface. ABI/platform adapters may translate calls into O-core's governed services; they must not replace package resolution, trust policy, crypto verification, archive/database behavior or scripts with success stubs. Final link, relocations, startup, constructors, loader/TLS behavior and protected syscall services are separate from a structurally valid module/symbol inventory. Preserve OIR orchestration and O-core MIR as distinct, explicitly connected artifacts.

## Known feature gates, without inventing APK failures

Current code explicitly rejects source assembly capture as an unsupported required import, and rejects module assembly/IFUNCs, special constructor/retention globals, dynamic alloca and other unimplemented LLVM forms. TLS/atomics have limited explicit profiles; dynamic ELF/PIE/preemption and full runtime semantics are not implied by their existence. Authentic target triples/DataLayouts are required. The full-musl recipes still report assembly, helper, configure-probe and Linux-interface obligations.

These are inspected importer/profile restrictions, not results of a new APK compilation attempt. The actual source graph must report which units need each unsupported feature. Every required failure blocks admission; source bodies, assembly, globals, initializers, relocations and helpers cannot be removed to make the receipt pass. The capture/import recipes and native runtime receipts intentionally distinguish capture/module closure from complete runtime, artifact, execution and platform qualification. Preserve those false flags until their own gates pass.

The current producer registry contains Clang and rustc adapters. The original Plan 9 `mk`/C/assembly/object route needs a separately verified producer/import/ABI binding; this APK proposal neither adds one nor assumes Linux C preserves Plan 9 semantics. Original driver source reuse likewise needs its actual Kbuild and kernel-API closure, not one driver file or a stacked Linux kernel. Reusing a compiler requires separate proof for its own implementation and the O-core path taken by generated programs.

## Completion sequence

Keep the coordinator's original file-utility/runtime lane first. In parallel, locate and pin matching manager/runtime/crypto/helper sources and construct their whole-build inventory. Then qualify capture, whole-unit import, native dependency/platform closure, owned final artifact, original manager behavior/restart, reproduction and matched efficiency separately. `source-contract.json` lists these obligations with no fabricated passing evidence.

Reuse the prior isolated behavioral proposal at `../original-apk-gate-current-u8n_l6d5/`: direct original APK transactions, original trigger effects, signed negative cases and upgrade/remove/restart. Its missing genuine upgrade pair and conflicting-provider fixture remain unresolved. No source success supersedes those behavioral gates. Online behavior and other package ecosystems remain independent profiles. No whole-system efficiency claim is possible until a matched single-system candidate exists and all kernel/driver/service/manager/helper costs are measured.
