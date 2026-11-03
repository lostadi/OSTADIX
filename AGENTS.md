# OSTADIX — agent instructions

This is **OSTADIX**, the canonical repository for O / Ostadix-lang and
O-core at `lostadi/OSTADIX`.

## Primary compiler objective

The highest compiler priority is for `olangc` to fully and automatically
compile existing external runtime and compiler implementations in terms of
O-core. General support for arbitrary implementations is the architectural
objective; do not restrict it to a fixed language list or interpreter-only
tier. Preserve the original language engines without requiring manual
language-runtime reimplementation.

`olangc` must own the source/build recipe, frontend invocation, O-core import,
verification, ABI adaptation, dependency resolution, linking, and artifact
construction. The result bundles the compiled runtime/compiler, `.O` program,
foreign scripts, and complete declared dependency closure in native binary
form, a complete verified O-core IR artifact, or a complete OIR program
artifact for later native lowering. OIR may contain the orchestration and
verified native O-core modules together, with explicit linkage, scripts,
resources, execution profile, and provenance. Native module references must
resolve within the included dependency closure. All forms must preserve
observable semantics across every ISA in which O-core is implemented.
x86-64, AArch64, and RV64GC remain mandatory minimum targets.
In this objective, "bundling runtimes with scripts" means this compiled whole
program, not merely embedding supplied executable files.

Completeness includes required functions, globals, initializers, relocations,
ABI features, libraries, compiler helpers, modules, and explicit platform
interfaces. Partial imports and feature-census percentages do not establish
complete runtime/compiler support. Report current coverage and unsupported
constructs honestly; the universal objective is not a claim of present support.

Embedding a supplied runtime executable, generating O-core source from a
polyglot block, or shipping an interpreter for an unchanged imported IR is
not evidence that the external runtime itself was lowered through O-core.
Report those mechanisms accurately. Keep OIR/ExecutionPlans and O-core MIR
distinct and connect them through explicit runtime/operation interfaces.
This separation of internal invariants does not forbid a complete OIR
artifact from containing the native modules and their realization bindings.
Foreign scripts may remain interpreted by the O-core-compiled language
runtime. Compiler self-hosting is a separate objective.
Compiling a compiler implementation and routing the programs it generates
through O-core are distinct required capabilities of the overall design.
Reuse existing implementation-language frontends and build metadata to make
the import general. Manual runtime rewrites and O-core text staging do not
satisfy the requested automated foreign-runtime/compiler lowering objective.
Keep lowering and replayability separate. Preserve imported semantics and
qualify cross-ISA equivalence per execution profile; do not infer purity from
a runtime name. JIT implementations remain in scope, with generated-code
lowering and publication requiring their own explicit supported path.

## Compiler expansion and independent review

Lee's explicit expansion request covers Rust, Python, JavaScript, TypeScript,
HTML, LaTeX, Java, C, D, Lua, Common Lisp, Chez Scheme, Go, OCaml, and further
implementations. This is a required expansion matrix, not an exhaustive
language whitelist. Continue every existing runtime and shared-provider
workstream. Track the requirements in
`tools/ocore-runtime/expansion.requirements.json`; its entries define acceptance
work, not claims of implemented or qualified support.

Preserve each selected upstream engine, compiler, standard library, build
configuration, and observable behavior. An additional small engine or library
is a separately named profile, not a substitute for the existing backend's
engine or a full compiler. In particular, keep Node/V8 semantics distinct from
an optional QuickJS profile; distinguish HTML string construction from a DOM,
layout, and rendering engine, and LaTeX text construction from a typesetter
with its package and font closure. Resolve and pin the actual upstream
TypeScript implementation and its producer; do not assume its implementation
language. Extend capture with registered, verified frontend producers for
additional implementation languages rather than mislabeling them as Clang.

Common Lisp requires an explicit selected original implementation, preserving
its compiler/runtime, bootstrap images, GC, libraries and generated-code
paths; record the actual engine selected by any backend fallback. Chez Scheme
means Chez Scheme itself, including original compiler/runtime, boot/library
closure, continuations, tail calls and native-generated code. Go requires the
official compiler/runtime and required standard-library/internal/assembly
closure, including goroutine stacks, scheduling, GC maps/barriers, ABI and
declared cgo/platform behavior. Preserve original upstream semantics and
qualify compiler-body, compiler-output and generated-code paths separately.
OCaml requires the original compiler, bytecode VM/runtime, native runtime and
standard library with their full source/build/bootstrap and native assembly
closure. Qualify bytecode VM/program execution, compiler-body lowering and
native compiler-generated program routing separately. Preserve value tags and
heap/GC roots/barriers, closures/partial application/tail calls, exceptions,
effects/continuations, modules/functors/FFI, data/marshalling/unmarshalling,
systhreads/domains/atomics and platform/provider behavior. Unsupported required
lanes remain explicit unmet work; a reduced bytecode profile does not qualify
the native/compiler or effects/domain paths.
These four families require the same complete artifact and per-ISA acceptance
as the existing families; wrappers, reduced engines and host executables do
not establish lowering.

For every profile, retain separate evidence for original source/build capture,
complete required-unit import, independent verification, ABI and initializer
coverage, provider/dependency closure, final artifact construction, execution,
and per-ISA semantic qualification. Inventory every required unit and retain
all failures; selecting only passing functions, units, examples, or features
does not complete a profile. Compiler-body lowering and lowering compiler-
generated programs require separate gates. JIT profiles also require an
explicit generated-code import, publication, and invalidation path.

Re-run complete original-source inventories after shared compiler fixes, with
frozen tool/input hashes and retained commands, statuses, and logs. Qualify
x86-64, AArch64, and RV64GC using their actual frontend/ABI profiles; do not
blindly retarget imported IR. Compare observable results with the unchanged
upstream reference and include meaningful negative controls. Keep historical
failed checkpoints separate from newer evidence. A fixture, manually linked
object, feature census, or successful source capture remains bounded evidence.
Complete verified IR/OIR artifacts may satisfy artifact construction before
native execution is qualified; report those milestones separately. Do not
declare the expansion complete while required lanes or their gates are open.
Before marking a milestone qualified, obtain an independent review of changed
lowering/code generation, generated-runtime source inclusion, complete unit
inventories, and semantic test oracles. Use a separate reviewer agent when
available, retain its findings and their resolution, and distinguish a review
of code or a plan from actual execution evidence.

Lee's subsequent instruction requires every applicable mechanism to expand to
x86 and ARM as well. Use `tools/ocore-runtime/isa.requirements.json` for the
mechanism-by-ISA acceptance matrix. x86-64, AArch64, and RV64GC remain required
primary targets. Track 32-bit i686 and ARMv7 as additional required expansion
work, including their currently missing target foundations; do not infer their
support from 64-bit emitters or installed emulators. Cover frontend capture,
import/data layout, ABI, relocations/linking, initializers, floating point and
its environment, atomics, TLS/threads, exceptions/unwind, providers, complete
artifacts, generated-runtime source inclusion, native graph/OValue interfaces,
compiler-produced programs, and JIT publication/invalidation. Architecture-
specific operations need explicit corresponding realizations or an explicit
unsupported status. Preserve native-host execution guards: test cross-target
artifacts in their actual matching native or emulated environment instead of
allowing foreign machine code to execute in the host process. Compiler-object
conformance tests alone do not establish whole-runtime/graph/AOT parity.

Lee explicitly requires functional identity across ALL ISAs in which O-core
is implemented. Dynamically enumerate actual source/build/runtime backends
and extend the applicable mechanism/profile matrix when an ISA is added;
the five listed target profiles are minimum obligations, not a whitelist.
Keep missing i686/ARMv7 foundations RED/unmet until implemented and qualified.
Compare unchanged original-reference versus owned behavior on each actual
ISA and pairwise matched owned executions across every implemented ISA under
the same declared semantic/execution profile. Pin workload/input, initial
state, tools/artifacts/providers and comparison rules. Preserve observable
floating-point behavior (including dynamic environment, signed zero and NaNs
where observable), memory/GC/atomics/concurrency and explicitly declared
nondeterministic effects/outcome constraints. Retain raw results and profile
conflicts; do not normalize away mismatches, silently omit targets or use
compilation/object/verification success as functional-identity evidence.
Any missing execution or unresolved semantic gap keeps the affected gate
RED/unmet. Require exact defined deterministic outputs/state/errors/resources
and the same defined allowed-trace semantics for atomics, concurrency and
nondeterministic effects; a few matching schedules or stress samples do not
prove all-trace equivalence. Declare and justify profile differences before
results, never after a mismatch. ISA-specific internal representations may
differ, while defined observable functionality must remain the same.
CI/acceptance must fail closed when the dynamically inventoried canonical
backend set gains an ISA without applicable mechanism, target/frontend/ABI,
guarded runner and independent reference/pairwise oracle coverage. Include an
added-backend omission negative; unsupported features remain RED rather than
being excluded to make a lane pass. Source inclusion, compiler build and
complete artifact construction remain separately reportable milestones,
without implying runtime parity.

The supervising and implementation parent agents have an explicit persistent
work request. Keep advancing concrete unresolved implementation and validation
work after each bounded milestone while the expansion requirements remain
open. Preserve active builds, use independent parallel work where possible,
and retain measured failures and next actions. Finite reviewer/worker tasks
may finish and be reassigned; an idle parent must resume substantive remaining
work rather than repeatedly reporting a checkpoint as completion.

### Primary runtime-lowering acceptance tests

Lee explicitly identifies O-core's ability to lower any original language-runtime implementation as its most important property. Design the primary acceptance tests around that full, extensible pipeline, alongside the other required mechanisms. Drive unchanged, pinned upstream runtime/compiler sources and their declared build metadata through `olangc`-owned frontend invocation, complete O-core import and independent verification, ABI/dependency/provider resolution, complete artifact construction, and reference-versus-owned observable behavior for each declared ISA/execution profile. Reuse producer contracts and profile data; do not turn the named languages into a whitelist or substitute manually rewritten runtimes.

Keep compiler-body lowering, compiler-generated program routing, and JIT code lowering/publication/invalidation as explicit distinct gates where applicable. Test complete native, verified O-core IR, and complete OIR artifact contracts according to their actual delivery form; do not confuse OIR orchestration with lowered runtime bodies. Foreign programs may be interpreted by the original O-core-compiled language engine. An interpreter for unchanged imported implementation IR is not runtime-lowering proof.

Include negative controls for missing required units/functions/globals/initializers/providers/resources, unresolved native references, ABI/target mismatches, opaque supplied-runtime executable embedding, unverified/partial modules, and unsupported generated-code paths. Retain exact failures. Passing capture, registry, rejection, feature, or ABI unit tests must not mark original-runtime acceptance complete. Missing prerequisites or unsupported required profiles remain explicit unmet acceptance results, never silent skips or a passing zero-case suite. Preserve the remaining ISA, semantic, source-ownership, replayability, and platform-interface requirements.

## Scale and ambition

Default to ambitious, full-scope OSTADIX execution. There is no arbitrary
graph-size or complexity ceiling. Never pause, warn, request approval, or
reduce scope solely because a graph exceeds a node, file, or word count.
This includes HTML visualization: no special warning or approval at 5,000 nodes.

Use `.O` programs, OIR/ExecutionPlans, OValue crossings, and real registered
backends as the foundation. Use available resources intensively through
parallelism, batching, streaming, caching, incremental processing, and scalable
rendering. Preserve the complete underlying graph when using aggregated views;
do not silently discard nodes or claim an overview renders every node.

Adapt automatically when measured resource limits require another strategy.
Report concrete failures or capability limits honestly. Respect explicit user
budgets, security boundaries, and task scope; graph size alone is not a gate.
Existing `olang` command, skill, path, and MCP names remain compatibility
identifiers for OSTADIX and are not renamed by this preference.

## Roots

```bash
export O_LANG_ROOT="$HOME/OSTADIX"
export O_BACKENDS_DIR=$O_LANG_ROOT/backends
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$O_LANG_ROOT/target/release:$PATH"
```

Do **not** use `~/O-lang` for builds/runs on this machine.

## Toolchain

| Goal | Command |
|------|---------|
| Parse `.O` or `.oc` | `o check file.O` or `o check file.oc` (no execution) |
| Run `.O` | `O file.O backends` or `o run file.O` |
| IR / plan | `olangc file.O --target ir --shim-dir backends` or `o plan file.O` |
| AOT | `olangc file.O -o out --shim-dir backends` or `o ship file.O` |
| Link | `o-link paths -o app.O` |
| Live-World | `o-live-host demo --state DIR` or `o live demo` |
| O-Git | `ogit demo semantic-receipt` or `o receipt` |
| O-core | `ocorec file.oc --emit mir` |

## MCP server

`mcp/ostadix_lang_mcp_server` — Rust/`rmcp` MCP server with stdio and
Streamable HTTP transports. Prefer
`o_execute` with exactly one complete `source` or existing program/project
`path`. `action` defaults to execute; check is parse-only, plan is static,
and compile explicitly requests an artifact. `mode: admitted` automatically
binds ordinary source and intent before fresh native admission. Placement auto
uses local HGraph for ordinary O and native mesh-prefer for projects;
marked operation directories retain their own planner. Mesh-required never
silently falls back to local execution.
Use `route` for explicit project execute/plan/IR/DOT selection. `node` sends an
ordinary complete document to one authenticated peer through native `octl`;
it is distinct from project mesh and does not partition the ordinary graph.
Node cwd/env configure the local client; cancelling it cannot stop remote
effects. Preserve receipt evidence and do not retry unknown completion.
Use `o_capabilities` (optional query) and `o_guide` (workflow topic) to discover
the full expert command surface. Humans use `o capabilities [QUERY] [--json]`
(alias `o discover`) and `o guide [TOPIC] [--json]` from the same compiled
`src/command_catalog.rs`. `o tool COMMAND [ARGS...]` invokes every catalog
entry through the same resolver as `o_cli`, including supported scripts.
Use `o_operation` with a marked-project `path` and
`action` describe/realizations/plan/explain/run/observe/replan. Only explicit
`run` dispatches; observation retains the native original decision, and replan
requires `without_targets` and never dispatches. Preserve exact `run` IDs for
observation/replanning. Read `o guide operations` for paired human/MCP calls.
`o_cli` accepts exact native argument arrays,
cwd, per-child environment, stdin, optional Unix PTY, and background execution.
`o_eval` runs inline polyglot O source. Long or interactive work uses
`o_job_list`, `o_job_status`, `o_job_read`, `o_job_write`, and `o_job_cancel`;
jobs run independently and retain full output on disk with bounded pages.
`o_job_read` can return lossless base64 bytes. Jobs and intent handles belong to
one MCP session, so short-lived CLI clients should use the persistent local
`scripts/ostadix_mcp_client.py` bridge.

Existing `o_env`, `o_runtimes`, `o_doctor`, `o_smoke`, `o_run`, `o_olangc`,
`o_search_run`, `o_analyze_intent`, `o_execute_intent`, and fixed read-only
`o_information_inspect` remain available. Catalog presence is not installed
version, health, or admission proof; use the listed supported help invocation
to inspect the selected CLI. Complete CLI access retains each command's native
admission rules and does not turn the read-only Information inspector into a
write API. Resources also expose the catalog and its workflow guides. Own
`Cargo.lock` (not a workspace member) so `rmcp`/`tokio full` stay out of the
main O-lang build.

Built by `setup.sh` (`build_mcp_server`, skip with `--no-mcp`) via
`cargo build --release --locked`; installs the native `ostadix-mcp` executable into
`~/.local/bin`. Registered for MCP clients (Claude Code included) via
`.mcp.json` at repo root. Rebuild directly with:

```bash
cargo build --release --locked --manifest-path mcp/ostadix_lang_mcp_server/Cargo.toml
```

## Skills

Load via skill tool when relevant: `olang`, `olang-runtime`, `olang-ocore`, `ostadix-control`, `ostadix-wasm`, `ostadix-term`.

## Native commands and validation

`setup.sh` installs compiled `o` and `ostadix-evaluator` binaries. Shell completion
or terminal configuration is optional. Use `o help`, `o root`, `o doctor`,
`o plan`, `o live`, and `o receipt` directly. Backend adapters and build/kernel
workflows retain their own languages and prerequisites.

The optional terminal kit retains shell conveniences as `o-term pull`,
`o-term update`, `o-term sync`, `o-term ssh`, `o-term scp`, `o-term hosts`,
`o-term new`, `o-term ex` and `o-term test`. `oroot` changes directory;
native `o root` prints the path. Do not shadow compiled `o` with a shell function.

Run `python3 scripts/check_language_sources.py validate` after adding or moving
tracked `.O`/`.oc` files. Run its `check` action with the current `O` and `ocorec`
binaries for complete parse coverage. Runtime checks still follow the example
manifest and named native build/QEMU harnesses. Regenerate tracked HTML exports
with `python3 scripts/render_docs.py write` using the pinned marked version;
`check` verifies complete output bytes.

## Evidence

Show real command output. Smoke: `O examples/hello.O backends` → `2`.
