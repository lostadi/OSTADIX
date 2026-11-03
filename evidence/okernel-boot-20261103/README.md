# Source-native boot integration: qualification and preservation

The repository's ordinary boot entry now selects the prepared persistent Linux
system under the AArch64 O-core monitor, using the seven-object original-source
u9fs/musl codec. The existing native x86 kernel remains accessible with
`boot/boot.sh native` (Mode 16) and `boot/boot.sh baseline` (Mode 0).

The default entry is `boot/boot.sh`; `boot-and-test.sh kernel` delegates to it.
Preparation is explicit and requires a new state. Runtime startup validates
the selected component and state without rebuilding or selecting another profile.
The [boot guide](../../boot/README.md) describes preparation and overrides.

## Preserved capabilities

- No tracked source files or existing public O-core names were deleted.
- The existing x86 runtime, kernel assembly, kernel builder, QEMU runner, smoke
  registry, and CI workflow remain unchanged. Both baseline and Mode 16 live
  lifecycle gates passed.
- The updated AArch64 implementation retains its original withdrawal profile.
  Its live gate passed with a newly built monitor, including service quiescence,
  mapping withdrawal, revoked-access containment, and subsequent EL2 progress.
- The compiler port changes the funnel-shift importer/verifier and three compact
  stack-address methods. The existing division, leaf, and fidelity fixes remain.
- `ostadix-BM` keeps its own architecture-boundary files and explicit variadic
  imports. Its actual compiler build passed after the integration.
- Existing saved development states were read only for preparation. The new
  default state is an independent verified fork. The earlier Linux/original
  9front experiment and its frozen runtime remain separate and available.

Source releases also preserve the new boot entry, required runtime/guest/recipe
files, and the exact upstream hardening patch. An existing release-inventory
mismatch for private `progress`/`step_knobs` helpers was repaired by retaining
those source files without exposing them as public APIs. No previously allowed
release path was excluded.

## Observed checks

| Check | Result |
|---|---|
| Fresh original codec builds | Seven objects, no unresolved symbols, 114,573 semantic checks on each of x86-64 and AArch64 |
| Compiler import regression | 76 methods, one expected Clang21 skip |
| Funnel-shift conformance | Four tests; 40,058 oracle checks per executable across three ISAs |
| Stack addressing | 2,304 checks per ISA and large-offset assembly checks |
| Boot dispatch/validation | 20 focused tests passed |
| Native backend/store/transports/codec | 15 production native fixtures passed, no skips |
| Package/fork host checks | 111 methods, one explicit unavailable original GNU ABI fixture |
| Ordinary boot entry | Actual PTY startup, tool/shared-file use, paired save and restart passed from both repository roots |
| Native-codec monitor | Two real boots with fresh exchanges, native counters, original GCC/Plan9port use, and paired persistence passed |
| Preserved x86 profiles | Mode 0 smoke and Mode 16 protected-principal lifecycle gates passed |
| Preserved AArch64 withdrawal | Live original Linux/EL2 withdrawal gate passed |
| Source classification and parsing | All 242 classified sources parsed as expected; no programs executed by this check |
| Source release | 87 release tests and nine facade tests passed, including real-tree deterministic ZIP construction and verification |
| BM-specific validation | 124 host tests, actual compiler build, and API compile check passed |

The ordinary boot tests use the real entry scripts with a terminal, execute
original tools, save a fresh nonce file in the shared namespace, request save
through Ctrl+], and observe the same bytes after restart. The code and component
identities, actual command lines, and selected raw test outputs are recorded in
the [qualification](qualification.json), [validation output](validation-output.json),
and [artifact index](manifest.json).

## Existing limitation

`ostadix-BM` has one preexisting architecture-policy failure concerning
`shims.rs` and `private_dir.inc.rs`. A pristine archived baseline reproduces the
same failure; all five relevant tracked blobs remain identical. The other 145
architecture tests pass. That policy was retained, and the failed check is
recorded in [the baseline proof](bm-architecture-baseline-failure.json).
These results do not claim that every repository-wide check passes.

This is a QEMU system integration. Linux and Plan9port tools still run as guest
code; the selected original codec is lowered through O-core. Full kernel/source
lowering, the separate original-9front profile, physical hardware qualification,
and whole-system efficiency remain distinct work. The evidence collection omits
generated disks and executables; retained absolute paths identify local artifacts.
