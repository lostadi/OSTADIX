# Toolchain and workflows

All commands in this file assume the repository root as the current directory.
Use repository-relative paths when moving the project between hosts.

The checked-in `AGENTS.md` identifies `/Users/ustad/Ostadix-lang` as the
canonical owner-machine root and explicitly says not to build from
`~/O-lang`. This generated pack was created in a Termux checkout at
`/data/data/com.termux/files/home/Ostadix-lang`; do not hard-code either path in
portable scripts.

## Setup profiles

Canonical setup entry point:

```bash
./setup.sh --minimal --verify
```

Important profiles/options:

- `--minimal`: minimal hosted build; explicit `--with-*` options still compose;
- `--full`: includes notebook, Racket, Nix, WASI, and O-core/QEMU tools;
- `--with-ocore`: install/verify native compiler/linker and QEMU prerequisites;
- `--with-ocore-media`: also install deterministic UEFI media tools;
- `--with-hosted-runtimes`: install supported open-source backend runtimes;
- `--check`: inspect capabilities without installing;
- `--verify`: verify Rust, C17, AOT, and Python hosted forms;
- `--verify-ocore`: run the bounded x86 O-core QEMU smoke;
- `--dry-run`: show the installation plan without changes;
- `--no-mcp`: skip building the standalone MCP server.

When setup writes its default managed environment, load it with:

```bash
source "$HOME/.config/ostadix/env.sh"
```

Primary source: `setup.sh --help` and `README.md` setup sections.

## Daily hosted commands

```bash
# Run a file with explicit checkout backends.
O examples/hello.O backends

# Same workflow through the lowercase intent front door.
o run examples/hello.O

# Parse without executing.
O --check examples/hello.O
O --json --check examples/hello.O

# Machine-readable execution.
O --json examples/hello.O backends

# One expression without a file.
O --json --eval 'python^(2 + 2)_python'

# Select the differential serial oracle or default graph coordinator.
O --executor serial examples/hello.O backends
O --executor graph examples/hello.O backends
```

`O --json` returns one JSON envelope on stdout. Parse failures and evaluation
failures are separately labelled. Human output such as `[number] 2` is not the
wire representation.

The positional backend directory remains a compatibility form. Use an
absolute `O_BACKENDS_DIR` in automation when the working directory is not
guaranteed.

## Planning and compilation

```bash
# Non-executing OIR, plan, HGraph, evidence/admission explanation.
olangc examples/hello.O --target ir --shim-dir backends
olangc examples/hello.O --target ir --explain-schedule --shim-dir backends

# Focused explanation of one plan node.
olangc examples/hello.O --target ir --why P0 --shim-dir backends

# Graphviz DOT.
olangc examples/hello.O --target dot --shim-dir backends > hello.dot

# Execute the lowered plan inside olangc.
olangc examples/hello.O --target script --shim-dir backends

# Native hosted AOT output (default target).
olangc examples/hello.O -o hello --shim-dir backends

# WASI module; requires the wasm32-wasip1 toolchain and suitable host.
olangc examples/hello.O --target wasm -o hello.wasm --shim-dir backends
```

Current `olangc` target names are `binary`, `wasm`, `script`, `ir`, and `dot`.
Binary and WASI outputs embed source, runtime, and bundled compatibility
adapters. `--materialize-only DIR` creates the exact generated Cargo project
for inspection without invoking Cargo or publishing the requested artifact;
the destination must not already exist. `--browser-bundle DIR` likewise
requires a new destination and packages the WASI module with the repository's
browser host assets; it does not grant hosted/effectful plans synthetic
authority.

An IR schedule is non-executing. Static waves, readiness, and a worker-count
coverage marker do not prove actual overlap, runtime availability, resource
fit, placement, or execution feasibility.

## Lowercase `o` front door

The installed lowercase `o` wrapper delegates to `scripts/o-cli.sh`. That
dispatcher sends intent-oriented operations to the compiled `o-cli`, while
preserving direct evaluator fallback and specialized tools.

Core compiled commands include:

```text
o run TARGET
o routes PROJECT
o optimize PROJECT --route ROUTE_SET
o plan TARGET
o explain ...
o inspect ...
o object root|list|stat|get|verify
o operation PROJECT
o operation inspect KIND FILE
o operation verify ...
o realizations PROJECT
o observe PROJECT
o replan PROJECT --without-target ID
```

Repository `o run` records attempts by default under the configured Ostadix run
state (normally below `${XDG_STATE_HOME:-$HOME/.local/state}`). Use the
documented `--no-record` option when a disposable ordinary run should not
create that history. `o optimize` is not a read-only planner: it executes the
reference and every candidate, validates declared outputs, and requires durable
recording before it selects a winner.

Dispatcher-owned namespaces include `o node`, `o registry`, `o info`,
`o live`, `o receipt`, `o kernel`, `o capacity`, `o device`, and `o why`.

On a case-insensitive filesystem, keep installed wrapper directories ahead of
`target/release` in PATH so the uppercase `O` binary does not shadow lowercase
`o`.

There are two different lowercase shell experiences:

| Surface | Important behavior |
|---|---|
| Repository wrapper `~/.local/bin/o -> scripts/o-cli.sh` | `o run` and `o plan` use compiled `o-cli`; run recording is enabled by default; `o live` delegates to the raw live binary and needs `--state`; unknown forms fall through to `O`. |
| Optional sourced zsh kit `~/.config/ostadix/term/ostadix-term.zsh` | Defines a shell function that shadows the wrapper. Its `o run` calls raw `O`, its `o plan` calls `olangc`, it supplies convenience state for Live, and it adds `doctor`, `build`, `ship`, `link`, and `test`. This is session-specific, not the portable repository CLI contract. |

Thus top-level `o doctor` in `AGENTS.md` assumes the optional terminal kit;
the repository dispatcher itself has `o node doctor`, while the MCP exposes
`o_doctor`.

Primary sources: `scripts/o-cli.sh`, `src/bin/o-cli.rs`, and
`docs/UNIFIED_INTENT_FRONT_DOOR_V1.md`.

## Linking and projects

Literal/source linking:

```bash
o-link path1 path2 -o app.O --literal
o-unlink app.O --dry-run
o-unlink app.O -o restored
```

Route-preserving project lifting:

```bash
o-link ./project --project --list-routes
o-link ./project --project -o project.O
o-link ./project --project --run --route build
```

Important distinction:

- literal linking wraps selected UTF-8 files as backend blocks and can run
  them when explicitly requested;
- project linking preserves files and route contracts in a source-closed
  ProjectBundle and executes only a selected/default project route;
- a bare single directory historically links and runs; use `--project` when
  safe route preservation is the intention and `--literal` when literal
  link-only behavior is intended.

Parallel/mesh controls are explicit. `--parallel=autonomous` authorizes eligible
fresh hosted members to overlap despite unknown external effects;
`--parallel=verified` keeps hosted shims sequential and overlaps only verified
pure inline work. Mesh execution requires an already running authenticated
peer and its configured fallback policy.

Primary sources: `o-link --help`, `README.md` “Compiler and composition
tools,” and `docs/PROJECT_MESH_V1.md`.

## O-core commands

```bash
# Inspect the native compiler pipeline.
ocorec ocore/examples/minimal.oc --emit hir -o -
ocorec ocore/examples/minimal.oc --emit mir -o -

# Emit a freestanding object.
ocorec ocore/examples/minimal.oc --emit obj -o minimal.o

# Bounded AArch64 subset.
ocorec ocore/examples/minimal.oc \
  --target aarch64-unknown-none --emit obj -o minimal-aarch64.o

# Operator workflow through the repository dispatcher.
o kernel doctor
o kernel build
o kernel smoke
o kernel gates
```

Current `ocorec --emit` values are `ast`, `hir`, `mir`, `asm`, and `obj`; the
default target is `x86_64-unknown-none`.

See `06_OCORE_KERNEL_AND_WORLD.md` before interpreting a successful QEMU gate
as a broader operating-system or hardware claim.

## Live-World, Information, and O-Git

Hosted Live-World reference:

```bash
LIVE_STATE=/path/to/disposable-or-persistent-state
o live demo --state "$LIVE_STATE"
# Direct binary: o-live-host demo --state "$LIVE_STATE"
```

Its command set covers pack, install, activate, upgrade, invoke, compose,
rollback, restart, status, and demo over a hosted content-addressed package
store. The raw binary and repository wrapper require an explicit state path;
only the optional terminal kit supplies a convenience default. It is a bounded
hosted reference/oracle, not a qualified native World. `demo` is an executing,
state-mutating acceptance scenario, so point it at a disposable directory when
you do not want to retain its package/service state.

Authority-free Information store:

```bash
o info --help
# Direct binary: o-info init|keygen|record|verify|import|head
```

O-Git semantic demo:

```bash
o receipt
# Equivalent default: ogit demo semantic-receipt
```

O-Git currently provides a deliberately narrow semantic-ledger demo and
meaning-level diff; it is not the World receipt/Governor system. The receipt
demo is not read-only: it requires a C compiler, generates or replaces its
named demo C/executable/graph/report artifacts, and writes
`.ogit/receipts/semantic-receipt-001.json`.

## Hosted node and mesh workflow

```bash
o node start
o node status
o node pair
o node doctor
```

The direct node binary serves bounded Hosted V1, optional durable Hosted V2,
Project Mesh, and explicitly authorized Fabric V1 protocols over TLS 1.3 mTLS.
The front door does not automatically start a node for a mesh run. Pairing and
LAN advertisements provide authenticated peer configuration and routing hints,
not Internet traversal or World membership. `start` writes node/process state
and launches a detached service; `pair` writes durable trust/credential state
and requires the documented two-party passcode exchange. Treat neither as a
read-only diagnostic.

## MCP server for agents

`mcp/ostadix_lang_mcp_server` is a dependency-isolated Rust stdio server with
its own `Cargo.lock`; it is intentionally excluded from the main workspace. It
is registered by the root `.mcp.json`, built by setup unless `--no-mcp` is
selected, and installed through an `ostadix-mcp` wrapper.

Current tool surface:

| Tool | Purpose |
|---|---|
| `o_env` | Resolve roots, binaries, backends, and catalog snapshot. |
| `o_runtimes` | Report catalog runtime alternatives and discovered executables. |
| `o_doctor` | Check the environment, shims, and runtime inventory. |
| `o_smoke` | Run the canonical hello smoke with an absolute backend path. |
| `o_analyze_intent` | Compute an expiring, one-use authority-free same-intent handle without executing. |
| `o_execute_intent` | Consume that handle, require intent/source recomputation, then perform fresh current admission and execution. |
| `o_run` | Direct compatibility execution with safe path resolution. |
| `o_olangc` | Compiler wrapper with absolute shim/path handling and bounded materialization. |
| `o_search_run` | Run one strictly bounded leaf from an approved example/search directory. |
| `o_information_inspect` | Bounded read-only head inspection of an existing local Information root. |

The server is a local stdio child and inherits the MCP client's process
authority. It has no network listener or MCP-level authentication. A matching
intent handle is not authorization or retained admission; execution still
performs fresh Graph V2/Evidence V6/Admission V6 checks.

Rebuild directly:

```bash
cargo build --release --locked \
  --manifest-path mcp/ostadix_lang_mcp_server/Cargo.toml
```

Primary source: `mcp/ostadix_lang_mcp_server/README.md` and `AGENTS.md`.

## Current binary surface

The current root `Cargo.toml` declares 15 binaries:

```text
O, o-cli, olangc, ocorec, o-link, o-unlink, o-notebook,
ogit, o-live-host, o-node, octl, o-registry, o-info,
ostadix-device, ocore-kernel-world-record
```

`o-notebook` requires the `notebook` feature. A README count of 14 refers to an
older pinned snapshot, not the current manifest.

## Verification ladder

Use the smallest gate appropriate to the claim:

```bash
# Hosted smoke.
O examples/hello.O backends

# Baseline repository contracts.
python3 scripts/local_ci_posture.py --profile baseline
python3 scripts/contract_surfaces.py validate

# Rust tests/quality when prerequisites are present.
cargo test --all-targets --all-features
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings

# Example manifest and reference editions.
python3 tests/example_manifest.py validate
python3 -m tests.test_parser
python3 -m tests.test_evaluator
make -C c_cpp test

# Native portable aggregate; expensive and prerequisite-heavy.
./boot-and-test.sh smoke
```

The machine-readable CI contracts are `ci/required-jobs.toml` and
`ci/test-suites.toml`. The current required-jobs manifest names 12 jobs. The
current native `evidence/gates.toml` declares 26 required portable gates and
one supplemental hardware gate. A stale comment elsewhere that says 24 does
not override the manifest field.

A skipped test or unavailable runtime is not a pass. Report the command,
environment, actual outcome, and what remains untested.

## Side-effect guide

| Class | Representative commands |
|---|---|
| Parse/inspect without target execution | `O --check`, `olangc --target ir`, `olangc --target dot`, `o routes`, ordinary `o plan`, operation-record inspect/verify. |
| Execute user/project work | `O`, `o run`, `olangc --target script`, `o optimize`; `o run` normally also writes run records. |
| Create build/composition artifacts | `olangc` binary/wasm targets, `o-link`; remember that bare `o-link DIR` infers execution. |
| Mutate Live state | Live demo, install, activate, upgrade, rollback, and restart. `pack` verifies only; status can reconstruct/health-check under the state lock. |
| Mutate node/trust state | `o node start|stop|restart|pair|pki|identity|admin`; status/profile/doctor are the inspection-oriented forms under their exact CLI. |
| Install/build environment | ordinary `setup.sh`; `--check` is non-installing and `--dry-run` prints the plan. |
| Generate semantic demo artifacts | `o receipt` / `ogit demo semantic-receipt`. |
