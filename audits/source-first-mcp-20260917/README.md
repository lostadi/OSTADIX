# Historical source-first snapshot

This directory records an earlier MCP implementation. The canonical advertised
schema subsequently evolved; do not use this snapshot as its current contract.
See the [current assistant/MCP audit](../gemini-nano-rebuild-20260917/LOCAL-ASSISTANT-RESULT.md)
and its fresh schema/lifted-project capture for the canonical binary tested on
2026-09-17.

# Source-first MCP acceptance — 2026-09-17

## Accepted boundary

`o_execute` is the ordinary model-facing operation:

```text
complete .O source + optional JSON bindings/constraints
  -> RuntimeRequest
  -> parse / OIR / plan / HGraph / admission / execution
  -> typed OValue + structure counts + canonical evidence identities
```

The MCP schema requires only `source`. It does not accept a compiler mode,
backend path, runtime choice, OIR, HGraph, task identifier, node identifier, or
OCTL command. The server assigns correlation identities and creates an
independent embedded `Runtime` for each call. MCP cancellation is propagated to
the request's cooperative cancellation token.

## Heterogeneous one-call result

Source: `examples/ai_heterogeneous_one_call.O`

The program forks Python, Rust, and Bash work, then passes the three results to
a dependent Python join. The retained MCP proof is
`OSTADIX-MCP-HETEROGENEOUS-20260917.json`.

Recorded result:

```text
sum=42
runtimes=bash,python,rust
all_three_overlap=true
overlap_ns=817921719
plan_nodes=19
hgraph_nodes=35
hgraph_exec_edges=8
elapsed_ms=1932
source_sha256=ef50d8c6c25215fa6254cfc0a16a94c334e279d04f672c7068f2c001a07b72a1
execution_intent_sha256=a3e7958c74880085f474315208d02347ba47cf53f70556822b7c450972cd3c79
```

The lifecycle trace records Bash, Rust, and Python `worker.exec_sent` events
before the first coordinator completion. The fourth execution event is the
dependent Python join.

The same transport run cancelled an already dispatched 30-second Bash request
in 410 ms. The structured failure reports that the actor was forcibly
reaped. A following embedded request returned the typed integer `7`.

The tested release binary and installed `~/.local/bin/ostadix-mcp` both had
SHA-256 `b13dccf929139fbff08d4aeb635b9e11f54d8be0cf52922d205c6355da1a4ca4`.

## Reproduce

```bash
cargo test --locked --offline \
  --manifest-path mcp/ostadix_lang_mcp_server/Cargo.toml
cargo clippy --locked --offline \
  --manifest-path mcp/ostadix_lang_mcp_server/Cargo.toml -- -D warnings
cargo build --release --locked --offline \
  --manifest-path mcp/ostadix_lang_mcp_server/Cargo.toml
python3 scripts/smoke_ostadix_mcp.py --timeout 180 \
  --require-heterogeneous \
  --heterogeneous-evidence-output \
  audits/source-first-mcp-20260917/OSTADIX-MCP-HETEROGENEOUS-20260917.json
```

## Distributed placement boundary

`RuntimeRequest` remains free of caller-selected node fields. `Runtime` now has
the host-owned `with_remote_pure_execution(...)` builder, which installs the
existing Fabric V1 physical-attempt adapter for supported pure renderers.

- Fabric V1 is connected at the graph coordinator's physical attempt seam and
  can now be selected by an embedding host through `Runtime`. It supports only
  preconfigured pure inline renderer operations.
- Hosted V2 can run one source-closed shim fragment under Placement V6
  authority, but is not a graph attempt driver.
- Project Mesh discovers and ranks peers for project route islands, not
  ordinary OIR operations.
- MCP `o_run.placement=node` submits a complete document through OCTL and makes
  placement a caller choice.

A self-contained test configures an unavailable pinned Fabric target and proves
that a trusted text renderer reaches Fabric transport and fails without local
fallback. A successful network proof still requires a provisioned authenticated
Fabric provider. The adapter validates the terminal receipt internally but
returns only `OValue`, so `RuntimeRequestResult` does not yet retain sound
physical placement or receipt evidence. General Python, C, Rust, or shell
branch placement still requires a selective Hosted V2 graph attempt adapter.
