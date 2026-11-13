# O10 M0 acceptance evidence

M0 passed `verify_o10_m0`: [acceptance-r3d.json](acceptance-r3d.json).
The verifier binds the exact compiled sources, compiler, running MCP identity,
eleven VM sessions and every required completed regression receipt.

The scope is the O10 host shim and synchronous journal on the recorded
AArch64 QEMU/TCG build, plus Python and x86_64 native component execution.
The Governor runs in the host runner and the namespace uses the existing grants.

| Check | Result | Receipt |
|---|---|---|
| Live O10 lifecycle and journal | Seven checks passed | fresh-live-3/result.json |
| Six guest gates | All passed, actual exits 0, zero skips | full-guest-results-r3/aggregate.json |
| O10 components and evidence guards | 67 passed, zero skips | final-unit-r3d/component/result.json |
| Existing kernel unit suite | 288 passed: 283 normal + 5 RAM-disk fixtures | final-unit-r3d/result.json |
| Admission and runtime packaging | 35 passed | final-unit-r3d/admission-and-freezer.stderr |
| Language inventory | 261 classified and checked, zero failures | final-unit-r3d/language.json |

The six guest gates are two_domains, provider, client, recovery, default_compile
and runtime. Each ran on a new private fork. The live gate also proves that a
preclaim legacy replacement advances the Plan 9 domain generation from 1 to 2,
rejects its old handle with ESTALE, and that O10 restore advances it once to 3.

## Identity and custody

Both canonical OSTADIX and ostadix-BM master were fetched at
`a8742f638c265d68cde6977aa2783cfad74ccc2a`; final-master-fetch.json records the
authenticated refresh. The qualification source base and rebuilt MCP release are
`5fb254ae13c978ce2e6010bb3080c3d1c32caa5c`. The checkout was dirty during
qualification; captured per-file hashes identify the exact admitted working
sources, including the shared legacy/O10 generation correction.

- Monitor ELF SHA256: `641a0ad14fb96979f7d4b141779f8bbad7b8b854ea1fde4fe1b25d984504aeaf`.
- Profile SHA256: `0093b2889160814778975bed6084543bebab3a9cf30ea7c8a408ca756ae0295e`.
- Compiler SHA256: `11cca4ce2543497423b188d68a20f1701b518992c775244e05591a2c04a32c42`.

fresh-toolchain contains the actual reconnected MCP provenance, schema discovery
and environment checks. fresh-monitor-build-r3/monitor-profile.json,
session-manifests-r3 and review-artifact-copies.json preserve the exact small
review artifacts; large immutable images and VM assets remain on X12.

Original workspaces, seed states and immutable inputs were preserved. Authorized
cleanup removed generated Cargo caches and explicitly inventoried superseded
private test disk copies. sparse-r3 records byte-identical zero-extent compaction
of closed private copies, with matching hashes, lengths, inodes and modes.

## Historical runs

Earlier failed and partial results remain in this directory. They include
missing-fixture/space failures, the old compiler identity discrepancy, a timed
out controller, pre-correction monitor runs and the first overly broad evidence
session collector. acceptance-r3d.json is the current qualification conclusion.

The first final-unit controller completed its child commands before an OValue
projection error; its successful child logs and independent readback are
retained in final-unit-r3. The final accepted run is final-unit-r3d and completed
its entire command set. Repository-staging fixtures use private RAM storage.
archive-repro-diagnosis records the installed Git's relative interpretation of
the shorthand timestamp and the deterministic explicit ISO timestamp fix.

## ISA coordination and continuation

X12 is x86_64. Authenticated probes verified orangepirv as riscv64 and m1max as
an Apple M1 Max, arm64, with 64 GiB RAM. Existing owners and workspaces were
preserved, and separate conformance/review tasks received hash-verified source
bundles. isa-coordination-rv-online records the bounded coordination evidence.

Remote Codex tool-approval controls rejected MCP execution requests under their
`never` policy; the retained remote reports qualify source review and staged
hashes. ARM/RV execution results are separate from M0's X12 gates.

M1 residency and M2 Linux replacement are subsequent branches. Draft 0's seven
open policy decisions remain with Lee. The full supplied Google Doc text,
revision and URL are retained in source-spec.txt/json.
