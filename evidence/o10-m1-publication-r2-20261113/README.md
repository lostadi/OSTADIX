# O10 M1 publication integration

The original Draft 0 M1 acceptance remains bound to cb53ca51 and R7 in
`evidence/o10-m1-20261113/acceptance-draft0-r7.json` (SHA-256
61a17588a627e83c3671c89208d0f933d9e0ef91cc29cf985478ffa3b501ef86).
Final source/evidence commit132d08f1 was integrated with both public masters at
6390bf2d. Their14 incoming paths overlap none of the23 R7 compiled source files.
All462 Rust/Cargo files and four reused binary identities were verified.

The first integration attempt caught missing M1 files in the source-release
required closure. Focused source fix55cf34d4 adds the five tests, their four
verifier helpers and canonical kernel dispatcher. The original completeness
assertion and first failed result remain unchanged.

The second integration run used a fresh private MCP stamped to
55cf34d4a3bc0cec0bf948e5c529baa918eeaff6 and this publication checkout.
`result.json` reports PASS for127 affected release/native tests,3 inventory
contract tests,147 O10 tests and261 language sources, zero skips; documentation
and publication-identity checks also passed. Its SHA-256 is
`e2c66b22c847355a8f05d373e6257ef6fbe6128e69bad570ffff76ec8b68a555`.
The23-file R7 compiled closure is unchanged. These are merged-source integration
checks; the original11 R7 guest sessions retain their recorded execution
identity. The final evidence-only commit preserves both identities.

Codex agents performed implementation, MCP orchestration and independent
source/evidence reviews. Lee is the maintainer and publication identity under
`docs/AI_ASSISTED_DEVELOPMENT.md`.
