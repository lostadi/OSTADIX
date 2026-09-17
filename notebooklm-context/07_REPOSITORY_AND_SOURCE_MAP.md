# Repository and source map

## Top-level ownership

| Path | Role |
|---|---|
| `crates/ostadix-api/` | Authoritative Rust runtime engine and native compiler library. |
| `src/` | Root `o-lang` compatibility library and CLI binaries. |
| `backends/` | Checkout-facing compatibility mirror of hosted backend shims. |
| `examples/` | Manifest-classified hosted `.O` programs and fixtures. |
| `ocore/` | Freestanding `.oc` runtime, kernel, user images, World codecs, build scripts, and gates. |
| `c_cpp/` | Active standalone C17 edition and historical excluded C++ prototype. |
| `o_lang/` | Readable Python reference edition. |
| `tests/` | Rust integration tests plus Python contract/release/system tests. |
| `fuzz/` | Separate-lockfile parser fuzz package, seed corpus, and targets. |
| `docs/` | Specifications, implemented profiles, claim boundaries, plans, and proposals. |
| `evidence/` | Machine-readable native/component and Alpha qualification manifests/ledger. |
| `ci/` | Machine-readable architecture, required-job, and test-prerequisite contracts. |
| `mcp/ostadix_lang_mcp_server/` | Dependency-isolated Rust stdio MCP server with its own lockfile. |
| `scripts/` | Dispatch, evidence, smoke, release, installer, boot, capacity, and maintenance tools. |
| `setup/`, `setup.sh` | Cross-platform setup profiles and environment/wrapper installation. |
| `benchmarks/` | CPU runtime, hosted HGraph, and real-world benchmark fixtures/harnesses. |
| `apps/` | Ancillary application surfaces, including browser WASI and Android/product experiments. Not required to understand the core language. |
| `tools/` | Ancillary tooling such as the LSP and local diagnostics. |

Generated build/state directories such as `target/`, `output/`, caches, and
local receipts are evidence or products only under their exact generating
contract. They are not source-of-truth architecture inputs.

## Core hosted engine files

| File or directory | Question it answers |
|---|---|
| `crates/ostadix-api/src/lib.rs` | Which modules does the independent engine own? |
| `crates/ostadix-api/src/api.rs` | What is the concise embeddable Runtime API? |
| `crates/ostadix-api/src/parser.rs` | How are typed expressions, scopes, calls, attributes, and spans parsed? |
| `crates/ostadix-api/src/syntax_dialect.rs` | What narrow registration/quoted-syntax view may parsing depend on? |
| `crates/ostadix-api/src/ir.rs` | How do ONode, OIR, BackendInterface, and ExecutionPlan work? |
| `crates/ostadix-api/src/backend_catalog.inc.rs` | What canonical backends, aliases, runtime alternatives, purity, adapters, authority, and value capabilities are current? |
| `crates/ostadix-api/src/backend_catalog.rs` | How are the literal catalog records represented and projected? |
| `crates/ostadix-api/src/value.rs` | What OValue variants, wire projections, boundary classes, and safety predicates exist? |
| `crates/ostadix-api/src/wire.rs` | What is the 4-byte-length canonical-CBOR shim framing contract? |
| `crates/ostadix-api/src/eval.rs` | How are parse/lower/plan/graph/evidence/admission/dispatch connected? |
| `crates/ostadix-api/src/hgraph/` | How are executable hyperedges, resources, scheduling, and constraints modeled? |
| `crates/ostadix-api/src/evidence/` | How are current facts, digests, intent, and admission built and checked? |
| `crates/ostadix-api/src/executor/` | How does readiness-driven dispatch, worker preparation, deterministic settlement, cancellation, and tracing work? |
| `crates/ostadix-api/src/process.rs` | How are hosted backend processes started, reused, and retired? |
| `crates/ostadix-api/src/backend_state.rs` | How is backend actor/snapshot lifecycle modeled? |
| `crates/ostadix-api/src/scheduler.rs` | How are autonomous Requests and caches coordinated? |
| `crates/ostadix-api/src/shims.rs` | How are compatibility shims embedded/extracted for generated programs? |
| `crates/ostadix-api/src/backend_morphism.rs` | What experimental shadow-only crossing profile exists? |
| `src/lib.rs` | Which historical paths does the root shell reexport? |
| `src/main.rs` | How does the `O` interpreter/REPL expose the engine? |

## Project, intent, and placement files

| Path | Role |
|---|---|
| `crates/ostadix-api/src/project/` | Project capture, manifest/routes, logical graph, deployment description, materialization, execution, traces, runtime graphs, reuse, and World-bound reference path. |
| `crates/ostadix-api/src/intent/` | Prepared intent, run records/store, selection reuse, and compiled front-door library behavior. |
| `crates/ostadix-api/src/computation_core.rs` | Operation contract/interface/realization descriptor/set records. |
| `crates/ostadix-api/src/computation/` | Operation graph verification, realization planning, and runtime/recovery records. |
| `crates/ostadix-api/src/placement/` | Placement core and projections. |
| `crates/ostadix-api/src/hosted_remote/` | Hosted V1/V2, node, pairing/TLS, LAN hints, mesh, and project-mesh transport. |
| `crates/ostadix-api/src/execution_fabric/` | Frozen pure capsule and provisional candidate. |
| `crates/ostadix-api/src/execution_fabric_authority/` | Additive authenticated transport/lease envelope. |
| `crates/ostadix-api/src/registry/` | Local signed placement registry records/store/verification. |
| `src/bin/o-cli.rs` | Compiled intent-oriented lowercase front-door commands. |
| `src/bin/olink.rs` | Literal and route-preserving project linking. |
| `src/bin/ounlink.rs` | Hardened inverse for literal/project bundles. |
| `src/bin/o-node.rs` | Node service and local node lifecycle. |
| `src/bin/octl.rs` | Authenticated node client/control CLI. |
| `src/bin/o-registry.rs` | Local signed registry CLI. |

## Live, Information, World, and native files

| Path | Role |
|---|---|
| `crates/ostadix-api/src/live_system/` | Hosted package manifest, immutable CAS, protocol, and supervisor reference. |
| `crates/ostadix-api/src/information/` | Authority-free Information V1 records, store, deltas, projections, decisions, loss, and provenance. |
| `crates/ostadix-api/src/information_bridge/` | Explicit lossy native metadata projections. |
| `crates/ostadix-api/src/world/` | Hosted World identity, protocol, value, receipt, codecs, and grounding. |
| `crates/ostadix-api/src/kernel_world.rs` | Host-side KernelWorld strict manifest and lifecycle/oracle types. |
| `crates/ostadix-api/src/ocore/` | O-core lexer, parser, AST, HIR, type checker, MIR, codegen, driver, and hosted capability bridge. |
| `ocore/runtime/x86_64/` | Freestanding x86 runtime, kernel services, capability, scheduler, IPC, personalities, KernelWorld, and machine mechanisms. |
| `ocore/runtime/aarch64/` | Bounded G2 native AArch64 modules. |
| `ocore/kernel/` | Kernel compilation units, boot glue/linkers, artifact builders, and exact QEMU gates. |
| `ocore/user/` | Immutable user-image formats, static ELF/personality fixtures, and verification tooling. |
| `ocore/world/` | Freestanding World identity/protocol/value/receipt/SHA-256 codecs. |
| `okernel-multikernel/` | Design proposal/experiment area; not evidence beyond named implemented gates. |

## Binary source map

Current root manifest declares 15 binaries:

| Binary | Source | Main role |
|---|---|---|
| `O` | `src/main.rs` | Hosted interpreter and REPL. |
| `o-cli` | `src/bin/o-cli.rs` | Compiled run/route/plan/evidence/operation front door. |
| `olangc` | `src/bin/olangc.rs` | Hosted AOT, WASI, script execution, IR, and DOT. |
| `ocorec` | `src/bin/ocorec.rs` | Freestanding O-core compiler. |
| `o-link` | `src/bin/olink.rs` | Literal/project composition and optional execution. |
| `o-unlink` | `src/bin/ounlink.rs` | Restore linked/project files. |
| `o-notebook` | `src/bin/o-notebook.rs` | Feature-gated local notebook server. |
| `ogit` | `src/bin/ogit.rs` | Narrow semantic-ledger demo/diff. |
| `o-live-host` | `src/bin/o-live-host.rs` | Hosted Live-World reference CLI. |
| `o-node` | `src/bin/o-node.rs` | Hosted/mesh/Fabric node service. |
| `octl` | `src/bin/octl.rs` | Node control client. |
| `o-registry` | `src/bin/o-registry.rs` | Local signed registry CLI. |
| `o-info` | `src/bin/o-info.rs` | Authority-free Information store CLI. |
| `ostadix-device` | `src/bin/ostadix-device.rs` | Native Android device-control surface. |
| `ocore-kernel-world-record` | `src/bin/ocore-kernel-world-record.rs` | KernelWorld record helper used by native/hosted-live builds. |

The normal minimal setup build list is narrower than every declared target,
and `o-notebook` requires its feature. Do not infer installation from manifest
declaration alone.

## Documentation map and status

### Normative/current contracts

- `SPEC.md`: hosted language semantics.
- `docs/OCORE.md`: O-core language/ABI/freestanding semantics.
- `docs/VERSIONING.md`: independent version axes and current versus archival
  coordinates.
- `docs/CLAIMS.md`: implemented claims and explicit boundaries.
- `crates/ostadix-api/src/backend_catalog.inc.rs`: current backend authority.
- `evidence/gates.toml`: exact native/component gate claims and non-claims.
- `evidence/world_alpha_gates.toml`: Alpha qualification definitions.

### Implemented profile descriptions

- `ARCHITECTURE.md`
- `docs/HOSTED_PLACEMENT_V6.md`
- `docs/PROJECT_MESH_V1.md`
- `docs/OIR_EXECUTION_FABRIC_V1.md`
- `docs/SEMANTIC_CUSTODY.md`
- `docs/UNIFIED_INTENT_FRONT_DOOR_V1.md`
- `docs/OPERATION_REALIZATION_V1.md`
- `docs/OPERATION_PLANNING_V1.md`
- `docs/KERNEL_WORLD_CONTRACT.md`
- `docs/HOSTED_LIVE_REFERENCE.md`
- `docs/INFORMATION_KERNEL_V1.md`

### Proposals, targets, and roadmaps

Files such as `docs/OSTADIX_WORLD.md`, `docs/O_MACHINE_CONTRACT.md`,
`docs/ODOMAIN_PLAN.md`, and
`okernel-multikernel/MULTIKERNEL_PERSONALITY_PROPOSAL.md` contain important
normative targets or designs. Use their gate/proposal status; do not read them
as a blanket current implementation inventory.

### Orientation and historical material

- `README.md`: broad current overview mixed with clearly labelled historical
  pinned-audit facts.
- `docs/AI_GUIDE.md`: concise agent workflow; its backend list can lag the
  literal catalog.
- `DEVELOPMENT.md`: contributor map and test commands; individual mechanics
  can lag refactors.
- `INVENTORY.md`: dated 2026-08-28 Mac audit, not live truth for this snapshot.
- `ostadix-lang-info.md`: brief technical overview; use normative documents
  and source for detailed behavior.

## Example map

`examples/manifest.json` currently classifies 46 `.O` examples: 20 unit, 25
integration, and 1 manual. The manifest records supported editions, required
backends/programs/authorities/files, opt-ins, expected patterns/results, and
timeouts. Prefer it over guessing whether a missing runtime is a failed
example.

High-value examples:

| Example | Topic |
|---|---|
| `examples/hello.O` | Canonical smoke and Python result. |
| `examples/bindings.O` | `let` and `$value` across blocks. |
| `examples/persist.O` | Reused numeric environment. |
| `examples/ephemeral.O` | Bare environment isolation. |
| `examples/env_split.O` | Two independent numeric environments. |
| `examples/nested_splice.O` | Recursive typed-expression nesting. |
| `examples/meta_eval.O` | Quoting and evaluation. |
| `examples/lazy_defer_attrs_basic.O` | Lazy/defer request construction and cache rules. |
| `examples/coordination_groups.O` | Batch/all/any/race topology. |
| `examples/semantic_custody.O` | Small source-to-intent/crossing demonstration. |
| `examples/sql_create_insert_select.O` | Persistent SQLite environment. |
| `examples/normalize/` | Marked operation/project planning vertical slice. |

## Test and evidence map

- `tests/*.rs`: hosted evaluator, HGraph, admission, placement, remote, project,
  Information, World, operation planning, runtime closure, and CLI integration.
- `tests/test_*.py`: setup, source release, browser/WASI, offline kit,
  governance, claim, hosted-live, boot/media, capacity, and evidence tooling.
- `tests/parser_proptest.rs` plus `fuzz/`: structured and raw parser
  adversarial coverage.
- `ci/test-suites.toml`: executable prerequisites for each CI suite.
- `ci/required-jobs.toml`: required CI job names.
- `evidence/gates.toml`: exact script, tools, markers, positive claims, and
  non-claims for 26 required portable and one supplemental component gate.
- `evidence/world/`: append-only Alpha evidence/supersession ledger consumed by
  `scripts/world_alpha_evidence.py`.

Passing a narrow unit or smoke test establishes only its named boundary.

## What not to upload as core NotebookLM context

Unless a specific question requires them, exclude:

- `target/`, `output/`, binaries, object files, images, caches, and temp state;
- conversation exports and scraped search HTML;
- large generated visual/mascot assets;
- ancillary application trees unrelated to the language/runtime question; and
- secrets, pairing material, state roots, private keys, or local receipts.
