# OSTADIX technical overview

- **Author:** Lee Daghlar Ostadi
- **License:** LGPL-2.1-only

OSTADIX brings together hosted polyglot execution, a native systems language,
and kernel and distributed-runtime components. Ostadix-lang and O-core are
components of the system with distinct source languages and execution models.

## Hosted language and runtime

Ostadix-lang uses typed expression boundaries, `LANG^( body )_LANG`, to select
an evaluator within a program. Nested expressions exchange values through
OValue. A complete `.O` source document can compose registered backends while
preserving explicit data, sequence, and resource dependencies.

The hosted pipeline parses source, lowers it to OIR and an execution plan,
projects the execution graph, analyzes evidence, admits execution, and schedules
work. Execution observations and receipts record results; they do not substitute
for admission or establish broader execution guarantees.

The independently packageable runtime engine lives in `crates/ostadix-api/`.
The root `o-lang` package supplies compatibility exports and command-line
programs. The canonical backend catalog and embedded shim assets belong to the
engine; the root `backends/` directory provides compatibility shim paths.

## Native systems components

O-core compiles `.oc` source through a typed HIR and SSA MIR to target object
files. It is separate from hosted `.O` orchestration. The primary freestanding
target is x86_64, with a bounded AArch64 scalar target.

The `ocore/` tree contains the native runtime, kernel, and associated validation
harnesses. Kernel, guest, device, network, and physical-hardware claims depend on
their specific evidence and do not follow from a successful hosted example.

## Tools and source map

| Surface | Purpose |
|---|---|
| `O` | Execute hosted `.O` programs |
| `olangc` | Compile `.O` source and inspect IR and execution plans |
| `o-link` / `o-unlink` | Combine and recover source documents |
| `ocorec` | Compile and inspect O-core programs |
| `o-node` / `octl` | Native node and distributed execution interfaces |
| `mcp/ostadix_lang_mcp_server/` | MCP access to the toolchain |
| `c_cpp/` | C17 implementation |
| `o_lang/` | Python reference implementation |

For syntax and semantics, see [SPEC.md](SPEC.md). For component boundaries and
implementation locations, see [ARCHITECTURE.md](ARCHITECTURE.md). The native
language is specified in [docs/OCORE.md](docs/OCORE.md).
[docs/CLAIMS.md](docs/CLAIMS.md), [docs/VERSIONING.md](docs/VERSIONING.md), and the
retained evidence records distinguish current guarantees, bounded profiles,
archival interfaces, and proposed work.

This overview describes repository structure and contracts. It does not assert
that every backend is installed or that all native, distributed, or hardware
validation gates have passed.
