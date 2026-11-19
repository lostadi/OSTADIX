# Checked array indexing

Ordinary `[T; N]` indexing checks negative indices, range and address overflow.
The compiler captures the base and index once, checks an assignment target
before its right-hand side, and uses the checked address for reads, writes,
compound assignments and address-of. Empty arrays and zero-sized elements
follow the same bounds rule. Unsafe raw-pointer indexing keeps its existing
contract.

The checked-address MIR operation retains the actual array type. Each emitter
validates it before generating instructions. Constant checks and shared native
helpers preserve the same trap and evaluation point. Oversized standalone,
nested and pointer-to-array layouts diagnose before emission.

The retained compiler has SHA-256
`c478567942292073383dc5a13600166a771cdd69a06d73f501db0e3276ed08d2`.
Its corpus executes 68 bounds, ordering and dispatch cases and seven source
rejections on each of x86-64, AArch64 and RV64GC. The arithmetic, wrapper,
indirect-call, narrow signed merge and reproducible-object checks also pass.
AArch64 and RV64GC component execution uses user-mode QEMU.

The integrated typed runtime passes x86-64 QEMU kernel Modes 0, 13, 19 and 24.
The Mode 24 image ends at the unchanged `0x380000` limit. Identical CSpace
state predicates, valid request-identity initialization and poison/error tails
share code; authority checks, fail-stop paths, layouts, profile selection and
limits remain in place. The original over-limit build and the reviewed
compaction are retained with the passing build.

The lifecycle corpus also passes with this compiler: 33 traces and 535
observations per ISA, all 27,714 compiled finite edge witnesses, and all 14
actual policy mutations. Failing mutation prefixes are reproduced and their
immediate predecessors must pass. The first final
run exposed an observation-carrier alignment assumption: a C array read used
a 16-byte-aligned instruction against an eight-byte-aligned O-core symbol.
The corrected carrier reads the declared scalar widths and passes the strict
all-target run. A focused regression links it to the exact previously failing
production object at an address eight bytes past a 16-byte boundary. The failed
run remains retained beside that result. [Qualification](integration.json),
[bounds](bounds.json), [kernel gates](kernel-gates.json), and the
[final lifecycle projection](lifecycle-final.json) bind these claims to the
executed inputs and artifacts. Full reports and executable closures are
retained separately, with their SHA-256 identities in these projections.

Fresh same-build AArch64 full-system replacement still requires its admitted
payloads, private fixtures and observed runtime provenance. These component
and x86-64 kernel results do not supply that evidence. Physical RV execution
also remains pending the remote agent's acknowledgment.

CI runs the full lifecycle runner in a separate required job. The existing
O-core job also executes the bounds and identity runners and crossed-kind
compiler rejections. Missing tools or incomplete target coverage fail the
qualification; diagnostic subsets do not produce a full pass.
