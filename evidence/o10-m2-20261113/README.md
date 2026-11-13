# O10 M2 evidence — November 13, 2026

[acceptance-r2.json](acceptance-r2.json) records `ok: true` and
`full_milestone_qualified: true` for Draft 0 M2, gate `verify_o10_m2`.
SHA-256: `7781ee645075d700fed24c51ffca0fc95c742a6e75494584d9b2b6cec6fc73d0`.

The gate proves live Linux fault/replacement and rebinding, old-fid ESTALE,
surviving Plan 9 counter/fids, a controlled signed APK3 pre-commit interruption,
an intact observed fsynced file prefix and successful read-only fsck after
journal replay. Scope: AArch64 QEMU/TCG on X12's x86_64 host. The APK test
interrupts before package filesystem changes. Unknown service completion and
the unobserved write tail remain unknown and unreplayed.

| Evidence | Passing result |
| --- | --- |
| Linux restart R8 | Five old Linux fids return numeric ESTALE 116; six Plan 9 session/fid/QID identities survive; fsck and APK checks return 0 |
| Plan 9 counter | 100 observations, 0..99; largest host gap 11.07714055 s; conservative append bound 12.11191960 s including host/QMP pauses |
| Resident R4 | 181 observations over 60.289850 s with no runnable guests, followed by Plan 9 provider restore |
| Guest regressions R2 | two_domains, provider, client, recovery, default_compile, runtime; 12 disjoint actual VM sessions including restart/resident |
| Ordinary R6 | 652 tests: 247 O10 + 292 kernel + 113 targeted; 267 language-source checks; zero test skips |
| Classified paths | 124 host register-model scenarios, with six distinct synthetic EL2 methods recorded separately |
| Source72e CI | GitHub Actions 43436854460; Required CI and all fourteen required lanes pass |

The source and running MCP release are
`72e90d76420ff5c331232b5e3fe7c20e30761e41`.
The monitor ELF is `30a91b43bb78e9202c983417e39609991554914ff0deb76998b69e19ea01dddb`;
its profile is `d5a5207a7b0e85963c98e7cefb378a69a32d77c70702aaa8cf783dcc909f964c`.
The running MCP inode is `694ae45ecd21bc376ae0047afee3e70975ddd835c942a37a984b3d3d2b069f3a`.
The compiler is `ca56a947e675f713bde6b81595220833799dcd304c415b0737f8703b8eb9eca7`;
its actual build origin is retained as the full 7c12 revision in the tool
records. Source helper overlays and their independent reviews are explicit.

The six-gate helper seed head is
`70c65d8119b98ad073f46e8e3776241a0df9b82304a3d7332b3c6f3dbee3183c`;
its selected disk is
`6ebe6a01cc0c209ecea57e4ae4d019a643a900045cffe8996b9c11cd149480db`.
Only the captured p9-install helper changed when preparing this private seed.
The original seed and APK fixture remain preserved.

Use [copy-receipt.json](copy-receipt.json) to map each original absolute
artifact path to its repository path, exact byte length and SHA-256.
It records 1,962 newly copied files, 37,831,649 bytes, with unchanged original
bytes; the pre-existing native-store-witness packet is retained too.
[evidence-inventory-r4.json](evidence-inventory-r4.json) distinguishes included
receipts and raw logs from external binary and disk identities. Exact commands,
MCP job identifiers/completion records, host/QEMU versions, machine options and
session directories are retained alongside each result:

- [Linux restart](current-restart/linux-restart-r8/result.json) and
  [submitted canonical command](current-restart/linux-restart-r8-execution/restart-command.json).
  The expanded verifier process argv was not sampled; the record expressly
  says so and retains the exact submitted MCP CLI request and actual job logs.
- [Resident test](current-resident/resident-r4/result.json) and
  [classification](current-resident-classification/classification-current-r4/classification.json).
- [Guest regression wrapper](current-six-gates/guest-regressions-r2/result.json)
  and the six original child receipts embedded by the acceptance binder.
- [Ordinary tests](current-ordinary/ordinary-regressions-r6/result.json).
- [Independent final readiness review](independent/final-readiness-review.json)
  and [actual installed-client readback](independent/client-r2-product-readback-r1.json).

Each managed gate's completed exit status, reaped child and drained logs are
recorded. Failed R5/R6 restore attempts, the earlier client-installer regression,
diagnosis, fixes and later successful runs retain distinct historical groups.
Unknown old outcomes have not been retried as guest service work.

[publication-integration-r1.json](publication-integration-r1.json) records the
normal integration of master `9d4f04964f32fac88788e877b4b508eb8c36baaf`
with the accepted source. All 44 captured guest/runtime/gate source hashes are
unchanged. Publication CI checks the integrated branch separately; the live
qualification remains tied to source72e and the exact monitor above.

The Git packet contains source captures, raw logs, profiles, hashes and
receipts. Large monitor/compiler binaries, runtime payloads and VM disks retain
their original local paths and content identities in the inventory. Closed
private working copies may be retired under the user's cleanup authorization;
their identities and raw results stay recorded. Original preserved seeds,
states, tools and source are protected. [Cleanup aggregate](cleanup-aggregate-r3.json)
records earlier exact authorized cache/working-copy retirements.

Implementation and review were AI assisted. Publication identity follows
[COMMIT_AUTHORS](../../docs/COMMIT_AUTHORS.md) and
[AI_ASSISTED_DEVELOPMENT](../../docs/AI_ASSISTED_DEVELOPMENT.md).
