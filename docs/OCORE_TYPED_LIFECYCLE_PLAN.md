---
title: "O-core / OKernel Implementation Guide"
subtitle: "Distinct identities, preserved lifecycle rules, and executable checks"
author: "Prepared for Lee Ostadi"
date: "18 November 2026"
lang: en-US
---

# O-core / OKernel implementation

The first result is a compiler error: a namespace transport epoch cannot be
passed as an O10 domain generation, and a process handle cannot be passed as a
capability handle. A value with the right type can still be stale, belong to a
different owner, or lack rights. Those checks remain in the runtime.

This record tracks implementation against the live repository. It does not
turn the supplied source review or historical execution receipts into fresh
qualification. A stage is complete only when its own acceptance checks pass.

## Starting point

The supplied guide reviewed `OSTADIX-master (1).zip`, 53,290,717 bytes, with
SHA-256 `06d6e3711498caa126f9b0715772a0b41e2af1a5b939b13cc1f7a2825172141d`.
That archive is not present on this implementation host, so its identity has
not been independently recomputed here. It is a snapshot reference, without
Git history, rather than the implementation baseline.

The live checkout was clean at `50ebf8663079406db02260eddc9574b1e9a09232`.
Both shared masters were observed at
`88fc0de62d1064025bf8e31abde68352d1f1d7c9`; the checkout was fast-forwarded
to that commit. Its tree is `aed6638582267f78f9548a624dbaa7d9fd1914ab`.
Implementation uses `work/ocore-typed-lifecycle-20261118`. A separate clean,
detached checkout retains the baseline while candidate sources change.

The Rust pin is 1.97.1. The initial host is Linux x86-64 with Clang 21.1.8 and
LLD. The compiler still lacks the two proposed structure attributes at this
baseline. The installed MCP process was built from an older source revision;
its observed identity is retained separately from the current source and new
compiler builds. It is not current-source qualification.

## Compiler contract

`@transparent` applies only to a brace-style structure with one direct
primitive integer field: `u8/u16/u32/u64`, `i8/i16/i32/i64`, or `usize/isize`.
Its field offset is zero and its size and alignment equal that integer.
Zero or multiple fields, nested wrappers, arrays, pointers, Boolean and float
fields, `@packed`, and explicit `@align` combinations reject.

The structure keeps its nominal identity in HIR, MIR and callbacks. Copying,
locals, statics, arrays, control-flow merges, and internal arguments/results
are admitted. Only the O-core internal ABI transports the wrapper by value.
C/SysV, syscall, assembly, and wire boundaries retain primitive signatures.
There are no implicit conversions, direct casts, or automatically inherited
arithmetic, comparison, bit, shift, or atomic operations, including in unsafe
source. Representation queries do not change source assignability.

`@opaque` records the canonical defining module. Only that module constructs
literals or reads, writes, or takes field addresses. The rule also covers
constants, statics, and imported aliases after identity resolution. Copying
an owner-provided value remains legal. The attributes are independent; an
opaque aggregate without transparency keeps the old aggregate-call limits.
Existing unannotated structures and general `pub` behavior stay unchanged.

Constants use explicit unseen/evaluating/ready dependency states. Forward and
cross-module references resolve before statics consume them. Cycles diagnose;
an actual zero value is never an unevaluated marker. Wrappers receive no
implicit zero initializer. The owner supplies valid initial constants and
checked status/output-pointer constructors. Null, invalid range and
exhaustion fail before mutation; failure leaves the output unchanged. A
maximum current value has no successor and never wraps to zero. Pointer
safety requirements and unsafe declarations remain explicit.

Typed wrap/unwrap or equivalent representation copies must validate width,
identity, and call/result ABI. All three emitters must execute the admitted
signed and unsigned widths, narrow normalization, stack arguments, indirect
calls, and merges. Foreign imported `NativeModule` semantics are outside this
change.

## Lifecycle and authority contract

| Identity | Policy retained |
|---|---|
| O10 domain generation | `1..=0xffff_ffff` in `u64`; maximum is valid, without a successor |
| Namespace transport epoch | Nonzero full-width `u64`, separate from session epoch |
| Namespace session epoch | Separate nonzero full-width `u64` |
| Namespace session serial | At most `2^63 - 1`; dialect bit remains reserved |
| Capability generation | Last live value `0xffff_fffe`; `0xffff_ffff` retired |
| Transfer/view/resource slot generations | Existing maximum-live and retire-on-next-release behavior |

The separate `world::identity::DomainGeneration` vocabulary is not narrowed.
The initial common owner defines `O10DomainGeneration`,
`NamespaceTransportEpoch`, and `NamespaceSessionEpoch`, all with `u64`
representation. Existing handle packing, kind tags, rights, owners, quotas,
table sizes, frame offsets, symbols, wire fields, reply bytes, errors and
retry semantics remain stable. Raw external adapters decode and validate
before entering one typed implementation; they do not duplicate a state
machine.

The O10 pilot follows domain extraction, restore preflight, advancement,
namespace provision and binding. It retains full-width transport values past
`0xffff_ffff`, including exhaustion and session-token collision regressions.
Restoration leaves Linux waiting for binding; stale Linux authority rejects
while unrelated Plan9 identities and contents survive.

Capability transfer keeps exact creator/source/destination identities,
attenuation, invisible reservation, retained references, publication order,
owner-death cancellation and poison/quarantine on impossible cleanup failure.
A capability's slot does not establish its CSpace owner. Request-bound views
keep exact request/process/address-space/service identity, bounds, direction,
snapshot, staging charge and written-prefix checks. Terminal publication
retains `capability close < terminal result < wake`. Irreversible impossible
failures remain fail-stop. The synchronization scope remains masked
interrupts on one CPU; types add no SMP guarantee.

## Independent lifecycle oracle

Write the policy model before using it to qualify the migrations. Keep domain,
lease, block, network, transport and session limits distinct, with symbolic
fresh sessions mapped to observed concrete tokens. Compare statuses, defined
reply bytes, handles, fid/QID behavior, namespace contents, runnable/binding
state and ordered effects against compiled production policy.

Pre-admission rejection, journalled platform rejection, exact retained replay,
invalid historical requests, preparation and terminal failure are distinct.
Retained replay precedes the current-epoch check; retry identity includes all
request bytes and the tag. Read-only sequence zero is not mutation replay.
An error can advance the journal without changing protected lifecycle state.

Separate finite profiles cover sessions, journal and replacement. State keys
exclude predecessor traces/effects and retain bounded stale identities.
Exhaustive means the reachable finite space was exhausted; bounded searches
say so. Full-width production instructions and exact failure/effect ordering
remain required. Candidate mutations must expose transport narrowing, wrap,
missing owner/generation checks, session collisions, survivor revocation,
premature runnable state, repeated reset/retry, and runner/evidence omissions.

Component carriers execute production policy on every implemented canonical
target. Privileged-hook effects are recorded and explicitly modeled. Their
results do not qualify physical hardware, SMP, or a full-system replacement.
Fresh same-build AArch64 resident/restart/regression/provenance acceptance is
separate and retains exact-pair admission and reviewed artifact identities.

## Separate array-indexing change

Ordinary `[T; N]` indexing checks signed negativity and unsigned range,
including empty arrays and zero-sized elements. Reads, writes, compound
assignment and address-of share the rule. `&array[N]` traps; explicit unsafe
pointer arithmetic remains the one-past route. Raw-pointer indexing keeps
its unsafe, unchecked contract.

Capture base and index once in left-to-right order. Check an assignment
target before its RHS and preserve divergence. A checked-element-address
MIR operation is emitted in `lower_place`, retains the actual array type,
derives layout, rejects offset/address overflow, and returns a typed element
pointer. Every array layout is validated before use, including standalone,
nested and pointer-to-array layouts. Malformed MIR rejects.

This is a language behavior change with its own diff, review and execution
corpus. Real isolated traps and side effects must execute on x86-64,
AArch64 and RV64GC. It is not folded into the identity migration.

## Qualification and task record

Retain exact source/tool identities, commands, environment, inputs, assembly,
objects, executables, outputs and statuses. A required skip is incomplete.
Historical receipts, fake-tool runner tests, compile-only results and an
artifact named pass are not fresh execution evidence. Register new sources,
update explicit builders and mirrors, render changed documentation, and
preserve historical evidence. Reviewed milestones reach both shared masters
through fast-forward integration, preserving concurrent work.

| Stage | Source | Changed files | Checks executed | Evidence | Review | Status | Remaining blocker |
|---|---|---|---|---|---|---|---|
| M0 baseline | `88fc0de6` | This contract record | Clean build; 77 focused Rust checks; native equivalence on all three ISAs; x86 O10/namespace characterization; kernel Modes 0/13/19/24 | Retained baseline artifacts | Source baseline reconciled | Passed within recorded scope | Orange Pi contact and fresh guest fixtures remain unavailable |
| M1 wrappers | Canonical PR120 / origin PR61; matching tree `a6a310ef` | HIR/checker/MIR/three emitters and native corpus | 96 focused Rust checks; 16 runner/coverage checks; native arithmetic/wrappers/traps/Phi on all three ISAs; 460 source parses; clippy and formatting | [M1 receipts](../evidence/ocore-typed-lifecycle-20261118/m1/README.md) | Independent findings resolved | Passed within compiler scope; merged to both masters with 22 CI checks each | None |
| M2 O10/namespace | Source-bound candidate | Lifecycle owner and complete caller path | Constructor/layout and crossed-domain checks on all three ISAs; native lifecycle suites, namespace-off resident and independent full-width/finite/mutation corpus | [Runtime receipts](../evidence/ocore-typed-lifecycle-20261118/runtime/README.md) | Namespace-off and release-closure findings corrected | Component checks passed; guest qualification blocked | Fresh same-build AArch64 fixtures, admission and observed provenance |
| M3a transfer | Frozen reviewed source manifest | Capability/process/transfer owners and Mode 13 oracle | Modes 13/0; actual crossed-kind rejection; independent Mode 13 rerun; maximum ticket retirement | [Runtime receipts](../evidence/ocore-typed-lifecycle-20261118/runtime/README.md) | Raw cleanup-key finding corrected; final compact adapters reviewed | Passed with the retained M1 compiler | Requalification with the separate final array compiler |
| M3b views | Frozen reviewed source manifest | Request/view/resource/bounded-RPC owners | Modes 19/24; typed lifecycle and generation retirement; actual API compiler negatives; source mirror and ABI/storage audits | [Runtime receipts](../evidence/ocore-typed-lifecycle-20261118/runtime/README.md) | Typed resource destruction omission corrected; no remaining findings | Passed with the retained M1 compiler | Requalification with the separate final array compiler |
| M4 model | Frozen oracle plus source-bound candidate | Independent model, vectors, carrier and strict runner | 33 traces and 535 observations per ISA; 27,714 finite edge witnesses; 14 actual policy mutations; 32 model/runner checks | [Runtime receipts](../evidence/ocore-typed-lifecycle-20261118/runtime/README.md) | Framing, effect comparison and source-copy isolation reviewed; baseline refinements retained | Passed with the retained M1 compiler | Final guarded runner with the separate array compiler |
| M5 arrays | Separate candidate checkout | Checked-address MIR, three emitters and bounds corpus | Original adjacent-field read reproduced; 51 bounds/order cases and seven source rejections per ISA; native arithmetic/wrapper regression; Mode 0 | Retained characterization and candidate artifacts | Static-layout diagnostic finding corrected; final review continuing | Implementing | Fresh final-source execution and fixed-limit Mode 24 build |
| M6 integration | Pending | Evidence, inventories and documentation | Not run | Pending | Pending | Not run | Required stages and fresh guest gates |

General aggregate ABI support, generics, borrow checking, affine authority,
new ISAs, changed wire/syscall layouts, larger quotas, normalized generation
policies and SMP synchronization remain outside this assignment.

### Baseline differences and qualification blockers

The old console-mux component test already fails at the clean baseline because
its provider omits `kw_linux_detach`. Its failure is retained separately from
this change. It is not counted as a passing regression check.

The fresh AArch64 guest workflow needs admitted Linux and Plan9 payloads, a
private seed state and offline APK fixture, and fresh runtime/provenance inputs.
The historical cache paths referenced by the old acceptance record are absent
on this host. Component execution does not fill that gap or admit a new
monitor/profile pair. The private RV coordination request is open without an
acknowledged agent session.

The compiler milestone also repairs a baseline architecture declaration: the
assembly inventory keeps its existing module identity and source filename,
using a manifest-owned compiled fragment. The checker is unchanged. Its 147
boundary tests and 49 affected Rust tests passed. The original failed CI run
is retained separately from the repaired candidate.

### Runtime implementation notes

The raw entry points retain one mutation body and their original rejection
accounting. Typed internal calls extract or project identities at explicit
storage boundaries. Shared capability lookup checks keep the exact owner,
slot, state, generation, object-type and rights predicates. A nonzero cleanup
key with no matching escrow still returns zero.

The new transfer mutation oracle has a dedicated real/stub leaf, selected
only for Mode 13. Existing module choices and fixed linker limits remain in
place. The live memory-view build fits those limits after removing redundant
forwarding and sharing identical read-only capability predicates. Those changes
alter generated instructions, with behavior checked by the mechanism and live
gates.

The finite model distinguishes a provisioned namespace frontend from bound
authority. After withdraw, restore, then withdraw before binding, the baseline
can retain an active frontend with no bound session. Fresh baseline and
candidate traces reject device activation and stale namespace access while
the domain remains withdrawn and unrunnable. The model records that state
rather than treating the active flag as authority.

The component carrier executes the production RAM-copy paths. Privileged
reset and interrupt-interface hooks remain explicitly modeled; raw effects
are retained. Its finite profiles exhaust 561 session states and 6,732 edges,
95 replacement states and 868 edges, and 63 journal states and 1,638 edges.
Each edge has a shortest predecessor witness. The initial independent model
covers O10 and namespaces; transfer and views use their compiled kernel
oracles.
