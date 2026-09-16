# Ostadix-lang NotebookLM context pack

This folder is a curated, standalone context set for asking NotebookLM about
Ostadix-lang. Upload every numbered Markdown file in this folder as sources in
one notebook. The numeric prefixes give the intended reading order.

Google's source-upload documentation listed Markdown (`.md`) as a supported
format when this pack was generated:
`https://support.google.com/gemininotebook/answer/16215270`.

## What this pack covers

- the identity and scope of Ostadix-lang, O-core, OKernel, O-Machine, World,
  and OSTADIX Alpha;
- hosted `.O` syntax, OValue, backends, environments, requests, and groups;
- the parser, OIR, ExecutionPlan, HGraph, evidence, admission, and execution
  pipeline;
- the CLI, compiler, linker, MCP server, project, placement, mesh, Live-World,
  O-Git, and Information surfaces;
- the separate `.oc` compiler and bounded native kernel evidence;
- current limitations, explicit non-claims, source locations, and vocabulary.

This is an orientation layer, not a replacement for the normative repository
documents. It deliberately summarizes the tree instead of copying thousands of
lines from the main README.

## Snapshot and provenance

- Generated from the working tree at
  `/data/data/com.termux/files/home/Ostadix-lang` on 2026-09-09 UTC.
- Git HEAD while generated:
  `bf575bd9d1027a976c3e067c59689a928886d717`.
- HEAD subject: `Merge pull request #17 from lostadi/codex/complete-execution-integration`.
- Root package version: `0.4.0`.
- The working tree already contained unrelated uncommitted changes. These
  context files summarize the files as read, but they are not a clean-release
  attestation.
- All source references are repository-relative paths.

## Source authority rules

When two sources seem inconsistent, use this order and state the conflict:

1. Current code, manifests, schema constants, and executable behavior.
2. Normative specifications: `SPEC.md` for hosted O and `docs/OCORE.md` for
   O-core.
3. `docs/VERSIONING.md`, `docs/CLAIMS.md`, and the README's exact-boundaries
   section for current/archival status and careful non-claims.
4. Implemented-profile contracts such as `docs/HOSTED_PLACEMENT_V6.md`,
   `docs/PROJECT_MESH_V1.md`, and `docs/OIR_EXECUTION_FABRIC_V1.md`.
5. Architecture and developer explanations.
6. Proposals, plans, historical audits, and generated summaries.

In particular:

- `crates/ostadix-api/src/backend_catalog.inc.rs` is the current backend
  catalog. A prose backend table that omits `c` or `ubuntu_vm`, or omits the
  `ubuntu` alias, is older than the catalog.
- Current local execution uses solved Graph V2, Evidence V6, and Admission V6.
  Graph V1 remains the frozen identity input for active, authority-free
  Execution Intent V1, but cannot enter current execution/admission;
  Evidence/Admission V5 are archival inspection surfaces.
- The `V6` in Hosted Placement V6 is a milestone name. It is not the same
  version axis as `oexec.evidence/v6`, `oexec.admission/v6`, or backend catalog
  V6.
- `INVENTORY.md` is a useful dated audit from 2026-08-28, not a live inventory
  of this later checkout.
- A document describing a target architecture, acceptance gate, or future
  work does not prove that target is implemented.

## How NotebookLM should answer

Ask it to follow these rules:

1. Use `Ostadix-lang` for the project and `O` for the hosted language/runtime.
   Do not silently change the project name to “Ostadux.”
2. Separate hosted `.O` orchestration from freestanding `.oc` machine code.
3. Label a statement as implemented, bounded/experimental, archival,
   proposed, or future when that status matters.
4. Prefer exact schema names and file paths over an unqualified version number.
5. Treat evidence, admission, placement, execution, and post-execution
   observation as distinct stages and authorities.
6. Never infer physical hardware, heterogeneous hosts, World authority,
   effect rollback, or general operating-system support from a narrower local
   or QEMU test.
7. Cite the most specific numbered context file and, when available, the
   repository path named inside it.

## Optional raw sources

For line-level or implementation research, add these repository files to the
same NotebookLM notebook after the numbered context pack:

- `SPEC.md`
- `ARCHITECTURE.md`
- `docs/AI_GUIDE.md`
- `docs/OCORE.md`
- `docs/VERSIONING.md`
- `docs/CLAIMS.md`
- `docs/HOSTED_PLACEMENT_V6.md`
- `docs/PROJECT_MESH_V1.md`
- `docs/OIR_EXECUTION_FABRIC_V1.md`
- `Ostadix-lang_Technical_Whitepaper.pdf`

Do not upload generated build products, `target/`, local state directories, or
the conversational transcript `ostadix-lang-info.md` as primary authorities.

## Suggested first prompt

> Build a mental model of Ostadix-lang from these sources. Keep hosted O,
> O-core, OKernel, O-Machine, World, and OSTADIX Alpha distinct. For every
> capability claim, say whether it is implemented, bounded/experimental,
> archival, proposed, or future, and cite the repository path that supports it.
