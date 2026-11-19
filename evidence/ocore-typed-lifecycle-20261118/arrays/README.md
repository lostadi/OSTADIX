# Checked array indexing

Ordinary `[T; N]` indexing checks negative indices, range and address overflow.
The compiler captures the base and index once, checks an assignment target
before its right-hand side, and uses the checked address for reads, writes,
compound assignments and address-of. Empty arrays and zero-sized elements
follow the same bounds rule. Unsafe raw-pointer indexing keeps its existing
contract.

The retained final compiler has SHA-256
`3b1f147354a2d96ac740da6fa2c83ee674b0d6b0f798ef2e9441e2310b19590a`.
It passes 107 focused Rust checks and 72 bounds, ordering, dispatch and section
cases plus seven source rejections on each of x86-64, AArch64 and RV64GC.
Twelve runner controls check failure admission and evidence handling. Native
arithmetic, wrappers, indirect calls, narrow signed merges and reproducible
objects also pass. AArch64 and RV64GC execution uses user-mode QEMU.

Dynamic checks stay inline in functions with explicit executable sections.
The native fixture maps the shared helper read-only without execute permission
and checks the actual page-rounded ELF mappings. A placed function must return
or take its own bounds trap. The previous compiler's cross-section helper call
fails the valid case on all three ISAs. The corrected Mode 14 gate passes. Its run predates the final capability-tail
factoring; the final four integrated gates below have their own source closure.
The failed kernel and native counterfactuals remain retained.

The final compiler and typed runtime pass x86-64 QEMU kernel Modes 0, 13, 19
and 24. The Mode 24 image ends at the unchanged `0x380000` limit. Its final size
correction shares only the identical sentinel/type/rights/object-ID tail of
two capability validators. Distinct owner lookup and live-slot checks retain
their order. The existing state-predicate, initialization and poison-tail
factoring remains in place; authority, fail-stop paths, layouts and limits
keep their contracts.

Older probe profiles use the existing function/data sections and linker
reachability collection. Their source choices and limits stay fixed. Five
separate M1 smoke scripts cover 14 TCG builds on the exact runtime source and
reviewed overlays. Separate Mode 21 compile/link and record-production receipts
identify their own retained source build. Its hardware execution was not performed.

The final compiler also passes 33 lifecycle traces and 535 observations per
ISA, all 27,714 compiled finite edge witnesses, and all 14 actual policy
mutations. Failing command prefixes are reproduced and their immediate
predecessors pass; the initialization-only divergence has no command
predecessor. The r11 oracle's 35 checks and the independent final projection
review are identified in the receipts.

The earlier observation-carrier alignment failure remains retained. Its fixed
scalar reader was checked against the exact previously failing production
object at an address eight bytes past a 16-byte boundary. The new compiler's
full lifecycle run is separate from that focused regression and from the
previous `c4785679` qualification.

[Qualification](integration.json), [bounds](bounds.json),
[kernel gates](kernel-gates.json), and the [final lifecycle
projection](lifecycle-final.json) bind these claims to the executed source,
tools and artifacts. Full reports and executable closures remain retained
separately with their SHA-256 identities in these projections.

Fresh same-build AArch64 full-system replacement still requires admitted
payloads, private fixtures and observed runtime provenance. Physical RV
execution remains pending the remote agent's acknowledgment. These results
supply neither qualification.

The required CI lanes are defined, with lifecycle conformance in its own job.
The final combined publication commit and final native/MCP installation need
their separate observations. Missing tools or incomplete target coverage fail
qualification; diagnostic subsets cannot produce a full pass.
