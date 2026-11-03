# Original APK acceptance proposal against the current native foundation

This is an isolated support proposal. No manager, build, test or VM was run, no native package-manager profile is admitted, and the single-system target and efficiency result remain incomplete. `input-identities.json` binds the inspected current sources and retained reference artifacts; `gate-plan.json` records proposed cases and unresolved fixtures. Integration belongs to the main coordinator.

## Concrete findings and usable inputs

The retained reference is Alpine 3.24.3, original APK 3.0.8-r0, AArch64. Its original `/sbin/apk` hashes to `304e62b9494b79cef24d621f4538b83496201252e32fce76c7f7e27760594fee`. The repository bundle contains 44 archives (94,063,364 bytes) and two signed index snapshots. Fresh read-only hashing agreed with every archive/index identity in the retained manifest. Signature validity is a historical manifest assertion here; this inspection did not rerun authentication.

The historical Linux acceptance at `/home/ustad/.local/state/ostadix/okernel/package-domain/acceptance.json` records original signed package installation, guest compilation and persistence. It remains Linux-under-O-core intermediate evidence. Tests that mock APK or an authenticated builder do not establish original-engine rejection behavior. The supplied rootfs/runtime is not an O-core-lowered APK implementation. The inspected paths contain no complete pinned original APK source/build/dependency recipe. Alpine `.PKGINFO` packaging commits must not be reported as upstream apk-tools source pins.

The bootstrap `/etc/apk/repositories` still names HTTPS repositories. A future offline run needs an explicitly bound private repositories file and enforced no-network policy. Archive availability does not select those archives automatically. Record the original architecture policy and trust keys; keep original signature verification enabled. The host x86-64 resolver used by the old builder is neither the AArch64 reference runtime nor a native candidate.

Use original `apk` directly. The current `pkg install NAME...` loops over names and can dispatch source recipes, changing transaction grouping. `pkg add` transparently forwards arguments, but direct APK removes that ambiguity from this acceptance. The harness supplies inputs and compares results; it must never resolve dependencies or write APK's database for the manager.

## Proposed first observable transaction

Use paired fresh environments with identical pinned original runtime bytes, initial database/world/scripts/triggers, repository snapshots, keys, architecture and configuration. Install `jq` and `curl` by name in one original APK transaction. The retained jq/oniguruma and curl/libcurl closures provide actual shared-library and transitive dependencies; allow original APK to choose the full set. Execute jq with a pinned regex workload and curl's original local-file transport, recording exact inputs, outputs and status. Local file retrieval makes no online/TLS claim.

Make the original BusyBox trigger observable rather than accepting its printed label as proof. The original registered 576-byte trigger has SHA256 `c7840b111dd82669de2074ea3c7e345c063928db2bbff650a81289777b3ff98f`; its archive/member are in the identities file. In fresh private fixture copies only, record and remove `/usr/bin/yes`, originally a symlink to `/bin/busybox`. Installation changes `/usr/bin`; the unchanged registered trigger runs the original `busybox --install -s`. First establish on Linux that it restores the exact link and usable command, then require the same effect on the candidate. Preserve script bytes, interpreter and child closure. This is a proposed test, not a result or permission to change a live environment.

Compare before/after original `world`, installed records, scripts archive, trigger state, selected package versions/providers and payload bytes, file types, modes, owners, links and relevant extended metadata. Capture exact original child program identities and exits. Run original manager queries in addition to independently recording raw DB bytes and filesystem state. A printed success or copied executable alone cannot pass. Freeze any normalization of nondeterministic times/paths in advance while retaining raw evidence.

Upgrade, remove and restart remain mandatory. No genuine two-version upgrade pair or qualified incompatible-provider fixture was found in the inspected cache; those are explicit missing inputs. Obtain and pin suitable genuine signed packages/snapshots before claiming either case. Original config-file and script behavior must be observed for the selected upgrade/removal, not assumed. Commit through the declared durable services, restart, then query original manager state and execute retained payloads. Normal restart does not prove crash consistency.

## Negative cases must preserve the original policy

Derive private wrong-key and tampered-index/package fixtures with exact mutations and hashes. Keep the format parseable enough to reach the original authentication boundary; a gzip parse error alone is not a signature-verification proof. Keep every signature/trust option unchanged except the declared test keyset. Do not use `--allow-untrusted`, skipped scripts, a custom resolver, or an extractor as the installation path.

A missing required archive with an otherwise unchanged signed index tests repository availability. It does not prove resolver conflict handling. Unsatisfiable requests and a genuine conflicting-dependency/provider case need their own frozen inputs and observed original outcomes. Compare exit status, diagnostics and resulting DB/filesystem/script effects against Linux; original failures may have documented side effects, so do not invent an all-or-nothing guarantee. Distinguish wrong architecture policy, missing dependency, signature failure and malformed input. Every unrun or unavailable mandatory case remains unqualified.

## Current implementation boundaries that block admission

| Boundary | Current evidence | Required extension before this gate |
|---|---|---|
| Native file access | `posix_namespace_files.oc`: trusted buffers, serialized read-only open/read/lseek/native fstat/close; eight contexts of eight descriptors | Protected process memory/IPC; actual Linux layouts/openat/cwd/flags; writes and complete required metadata, links, permissions, locks, lifetime and commit behavior |
| Shared store | `namespace_store.oc`: native create/write/remove; wstat rejects ownership changes and rename over an existing target | Governed ownership and atomic replacement semantics needed by the original runtime; POSIX open-unlink lifetime and durable commit |
| Manager isolation | Owner/ns labels select descriptor contexts and do not create rooted capabilities; role 1 is exclusively owned | Real per-ecosystem runtime, database and payload namespace views over common services with separately governed authority |
| Linux application ABI | Current x86 personality is bounded write/exit_group; native metadata is not Linux struct stat | Qualified original loader/argv/env/auxv/TLS, memory, processes/signals, clocks/entropy, filesystem and required ioctl/proc/device interfaces |
| Original implementation | Original lowered u9fs/musl codecs are a seven-object component; provided APK bytes are retained | Complete original APK/runtime/helper source and configured build closure, or explicitly separate supplied-binary ABI qualification; no lowering claim from bundling |
| Drivers/interface | Dual experiment retains a whole Linux kernel; POSIX is not the Linux driver API | Original driver/dependency closure and governed IRQ/MMIO/DMA/wait/allocator interfaces; familiar terminal/process behavior independently qualified |

Current native hashes are `13cffe0c…` for store, `920ac6fc…` for codec and `ff161dd8…` for the file adapter; complete hashes are in the manifest. Do not apply the old cache store patch over these bytes. The current native read-only component cannot simply be linked beside the old Linux role-1 transport.

The 94 MB retained package archive set alone exceeds the historical 16 MiB namespace volume. That is not a measured minimum manager closure or an argument to weaken semantics. Keep archive/source caches on a declared governed provider with all capacity, memory, I/O and authority accounted for; declare the writable installed payload/database capacity separately. The candidate must use its real governed services. Host copying, a hidden host filesystem server, host execution of scripts, or a second full kernel cannot stand in for native manager execution.

## Evidence and efficiency receipt

Before execution, bind manager/runtime/helper/source/build identities, keys, index/package hashes, exact argv/env/cwd, initial DB and payload metadata, namespaces, quotas, clocks/entropy policy and durability contract. Give each isolated run a fresh identity; retain all raw output and before/after filesystem/DB snapshots plus original children and exits. Record interrupted/unknown transactions as such, with no automatic resubmission. Reject stale or mixed input identities. Missing ABI behavior must fail visibly, never return invented success or silently skip a hook.

For efficiency, compare the same ISA and execution/protection mode, original versions and features, initial database/cache state, repository bytes/latency and commit contract. Report raw repeated samples and p50/p95, cold/warm startup, end-to-end authentication/resolution/install/script/commit time and application output correctness. Count all kernel, drivers, common services, manager and helper resident/allocated memory; shared physical pages count once. Process RSS and the existing Linux-only timing baseline do not establish total-system memory or speedup. No candidate comparison is currently possible.

Suggested sequencing: native protected original-application/file gate first; original APK closure and missing signed fixtures in parallel; then Linux reference case recording, candidate semantic/restart gates and finally matched measurements. This proposal adds acceptance detail without changing current source, runtime, VM state or the architectural contract.
