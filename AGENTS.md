# Ostadix-lang — agent instructions

This is the **canonical** O / Ostadix-lang runtime monorepo.

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
export O_LANG_ROOT=/Users/ustad/Ostadix-lang
export O_BACKENDS_DIR=$O_LANG_ROOT/backends
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$O_LANG_ROOT/target/release:$PATH"
```

Do **not** use `~/O-lang` for builds/runs on this machine.

## Toolchain

| Goal | Command |
|------|---------|
| Run `.O` | `O file.O backends` or `o run file.O` |
| IR / plan | `olangc file.O --target ir --shim-dir backends` or `o plan file.O` |
| AOT | `olangc file.O -o out --shim-dir backends` or `o ship file.O` |
| Link | `o-link paths -o app.O` |
| Live-World | `o-live-host demo --state DIR` or `o live demo` |
| O-Git | `ogit demo semantic-receipt` or `o receipt` |
| O-core | `ocorec file.oc --emit mir` |

## MCP server

`mcp/ostadix_lang_mcp_server` — Rust/`rmcp` stdio MCP server exposing `o_env`,
`o_doctor`, `o_smoke`, `o_run`, `o_olangc`, `o_search_run` so agents don't
rediscover the relative-`backends` / `$VAR`-splice traps by hand. Own
`Cargo.lock` (not a workspace member) so `rmcp`/`tokio full` stay out of the
main O-lang build.

Built by `setup.sh` (`build_mcp_server`, skip with `--no-mcp`) via
`cargo build --release --locked`; installs the `ostadix-mcp` wrapper into
`~/.local/bin`. Registered for MCP clients (Claude Code included) via
`.mcp.json` at repo root. Rebuild directly with:

```bash
cargo build --release --locked --manifest-path mcp/ostadix_lang_mcp_server/Cargo.toml
```

## Skills

Load via skill tool when relevant: `olang`, `olang-runtime`, `olang-ocore`, `ostadix-control`, `ostadix-wasm`, `ostadix-term`.

## Terminal kit

`~/.config/ostadix/term/ostadix-term.zsh` — `o doctor`, `o plan`, `o live`, `o receipt`.

## Evidence

Show real command output. Smoke: `O examples/hello.O backends` → `2`.
