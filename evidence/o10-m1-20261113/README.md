# O10 M1: qualified Draft 0 resident monitor

`acceptance-draft0-r7.json` reports `ok: true` and
`full_milestone_qualified: true` for `O10-Draft0-M1`.
SHA-256: `61a17588a627e83c3671c89208d0f933d9e0ef91cc29cf985478ffa3b501ef86`.

The exact source/MCP release is `cb53ca51c5e8ef3e4692870640d71935a82556fa`
plus the source-bound helper/test bytes captured by the receipts. The compiled
R7 source closure is captured in `build-r7/monitor-profile.json` and the build's
immutable source artifacts. ELF SHA-256:
`d8163b97dd9b7c165d7daa761756bb11fa164338598efd899c8b3c0f82927d32`.
Profile SHA-256:
`4ed18d420aa3f0348d324f4e0d8f38854222eb7faa67b0dce338322313701938`.
`qualified-toolchain-r7/fresh-env.json` records the running MCP inode and tools;
`acceptance-draft0-r7-command.json` and its MCP result retain the exact command.

The resident gate faults Linux with qualification `Tinject`, withdraws Plan 9,
answers 182 observations across 60.243712 seconds with both guests stopped, then
restores a fresh original Plan 9 provider. All six guest regression commands
exited 0 on this same R7 artifact, in distinct private seed forks. The ten guest
regression sessions and the independent resident session retain their profiles,
ELF identities, results, native observations and logs. The ordinary seal passed
147 O10 component tests, 288 kernel unit tests, 74 targeted tests and all 261
language sources, with zero skips. The classification mapping binds all four
former `uw_handle_exit` MAX-return sites to their outcomes and executed tests.
Its 124 native host register-model scenarios are separately scoped from the
four actual EL2 context tests in the targeted run. The 0x1104 test exercises the
diagnostic directly; it does not claim valid-state reachability of that guard.

Claim scope: O10 Draft 0 M1 residency, containment classification and provider
restoration on AArch64 QEMU/TCG, executed on x86_64 X12. The additional guest-MMIO
probe is retained as unqualified. Its precondition failed, and later planning
was rejected by automatic approval review with the stated reason “possible
cybersecurity risk”; that work stopped. Default `extended` acceptance still
requires its own passing evidence. Draft 0 acceptance follows the original
resident/classification/regression contract.

Earlier runs and failed/skipped fixture attempts remain in their original
receipts. `ordinary-final-r7c` is the accepted complete unit run. Copies retain
original execution paths and byte identities; `qualified-copies-index.json`
and `full-guest-results-r7-draft0/session-manifests/index.json` locate them.
Space-retirement receipts identify the closed private disk/namespace copies
that were removed after validation; those disposable heads are nonresumable.
Original saved states, source inputs, runtime/build images and execution logs
remain preserved.

Implementation, test orchestration and independent source/evidence reviews used
OpenAI Codex agents through Ostadix MCP. Lee is the maintainer/publication identity
under `docs/AI_ASSISTED_DEVELOPMENT.md`; the record claims no human review.
