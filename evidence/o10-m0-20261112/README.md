# O10 M0 implementation evidence

Implementation branch: `work/o10-m0-20261112` on X12.
Source checkout: `/home/ustad/OSTADIX-o10-m0-20261112`.

The canonical OSTADIX master was fetched at
`a8742f638c265d68cde6977aa2783cfad74ccc2a`.
Implementation commits are `5fb4b3d7ebee36c510b7887a1cb4a08142cd3b51`
and packaging correction `1fc414e7e21b577cbdb9c032a94f51182a0ff96c`.
The original working checkout and preserved VM states retain their prior contents.
The Google Doc's complete text, URL and revision are in source-spec.txt/json.

## Executed checks

| Check | Result | Scope / receipt |
|---|---|---|
| O10 wire, journal, runner and mailbox | 24 passed, zero skips | journal-components-packaged/result.json; exact code revision 1fc414e7 |
| Existing test_okernel_*.py suite | 288 passed, zero skips | unit-regressions-reviewed.json; exact code revision 5fb4b3d7, before the separately tested packaging correction |
| Frozen runtime tests | 8 passed, zero skips | freezer-final.log; packaging correction 1fc414e7 |
| Language-source check | 261 classified and parsed, zero failures | language-sources.json/stdout; no programs executed |
| AArch64 monitor graph | Object emitted successfully | aarch64-compile.json; exact argv, compiler output and object digest; profile in compile-profile.oc.txt |
| Installation doctor | ready=true, Python smoke passed | doctor.stdout and doctor-command.json |
| Commit authorship | Passed for implementation commit | command recorded by MCP: python3 scripts/check_commit_authors.py --head HEAD |

The initial broad unit run retained seven ENOSPC errors and thirteen fixture
skips. The disk tests were rerun using a private /dev/shm directory; the original
source fixtures were located and explicitly supplied. The final 288-test record
has no errors or skips. Both failed and successful records are retained.

The implementation and these checks were produced with coordinated coding
agents through Ostadix MCP. Native platform tests execute the real wire journal,
mailbox handler and namespace store in an x86 harness. Architectural entrypoints
outside that corpus terminate through test sentinels. AArch64 evidence here is
compilation.

## Acceptance and continuation

Full M0 acceptance remains pending. The source identity of the running MCP
release is unverified. The installed compiler's observed hash differs from the
historical tool metadata; environment.json records both values explicitly.
A fresh source-aligned toolchain and MCP, followed by reconnect and the complete
QEMU guest regression set, are the next gate.

The root filesystem had about 0.85 GiB available. Provision build storage before
the fresh release build; preserved experiments and saved states need Lee's
approval before deletion. Setup's inspected runtime-only dry run builds O,
o-cli, olangc, ocorec and MCP, and also installs Cargo-bin commands even when
--no-local-bins is selected. Use an isolated install destination to retain the
current tools and preserve their hashes.

After source/release alignment, rebuild an admitted monitor from the immutable
Linux and Plan 9 inputs, fork a saved state for every guest gate, and run the full
section-9 regression set. Gate outputs must retain the exact build and source
identities. Only then accept M0 and proceed with the resident-monitor milestone.

O10 draft clarifications are documented in docs/O10.md: exact frame retry,
synchronous sequence admission/error journaling, provisional enum values,
minimum msize and the restored domain's explicit bind wait. Rlstat's record
layout and asynchronous takeover need definition before their milestones.

The fallback repository ostadix-BM could not be fetched: HTTPS requested
credentials, and the SSH attempt lacked an existing trusted GitHub host key.
Canonical OSTADIX's fetched revision is the base actually used.

## ISA coordination

X12 supplies x86_64 execution.
isa-coordination.json records the existing Orange Pi thread IDs, account,
prepared handoff and bounded connection checks. The Orange Pi RV was offline;
M1 Max was online and required Tailscale's additional SSH identity check.
The authorization link was presented in chat. Resume authenticated remote
coordination, inspect the existing agent ownership and source/tool revisions,
then assign separate RV64 and ARM evidence against the agreed source.
