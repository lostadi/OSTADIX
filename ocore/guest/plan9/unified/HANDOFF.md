# Original Plan 9 resident command provider

The additive userland component is implemented and tested with original
9front ARM64 tools and programs. Wiring this resident provider into the
coordinator's concurrent O-core domains is a separate acceptance gate.
No existing monitor, probe, native store,
package builder, updater, setup script, working VM, or saved head was changed
for this assignment.

## Coordinator follow-up, 2026-11-03

The coordinator's current R9 profile already admits the later build 7 selected
below through its separate strict userland-derivation validator. The earlier
build-4 receipt `ac0cf6414f549b2eee071784f643543aa45e5c64eebe95d4dcc61c2b52f29121`
and its artifacts remain preserved; they do not replace the current admission.

Root-owned integration has separate passing evidence:

- [Original compiler, common native store, cancellation replacement and restart](/home/ustad/.local/state/ostadix/okernel/unified-development-20261102/provider-acceptance-0ed7efeb98a24045/result.json).
- [Detached-child timeout and whole Plan 9 domain replacement](/home/ustad/.local/state/ostadix/okernel/plan9-timeout-domain-recycle-20261103-xeq88n9w/result.json), including an independent audit and retained before/after namespace snapshots.
- [Accepted provider lifecycle contract](/home/ustad/.local/state/ostadix/okernel/plan9-provider-lifecycle-contract-20261103-zmngifcs/decision.json).

Those are bounded AArch64/QEMU compatibility-profile results. They do not
reclassify the resident-only background-leak failures, qualify original-engine
lowering through O-core, or complete the requested single native OS. The
component receipts and limitations below retain their original scope. Current
working VMs, saved heads and old proof artifacts have not been replaced.

The current source admission path verifies exports using
`scripts/plan9_userland_admission.py`: stable read-only descriptors, streamed
TAR/content/CRC checks and exact receipt/export/inventory matching. It does not
call the original builder's mutating `qualify_exports` or `revalidate` functions.
The PAQ search holds its bounded declared pattern and overlap in memory; it
does not extract it. New build captures bind the verifier source explicitly.
Previously frozen builds retain their original source and qualification scope.

## Entry points and admitted artifact

- `scripts/build_okernel_plan9_userland.py`: admits the pinned official image,
  uses a fresh private overlay and FAT transfer disk, builds the service with
  original `7c`/`7l`, packages a read-only PAQ, proves native source compilation,
  and rebuilds the original kernel with the existing UART platform patch.
- `p9cmdsrv.c`: resident original-ABI service; original `exec`, `rc`, pipes,
  process APIs, cwd and raw `Waitmsg.msg` status. No host-shell or Plan9port path.
- `start.rc`: original-rc background startup wrapper with isolated standard
  descriptors. The original console remains available.
- `protocol.py` and `PROTOCOL.md`: exact request/result framing and pure host
  validation helpers. These helpers neither dispatch commands nor grant rights.
- `verify_service.py`: private original-9front VM acceptance, with independent
  byte oracles from `tests/plan9_command_runtime_cases.py`.
- `verify_console_coexistence.py`: original UART console and resident-worker
  coexistence, including a resident native source build.

Use the qualified background-worker build:

`/home/ustad/.cache/okernel-plan9-userland/build-7/result.json`

Receipt SHA-256:
`89bb766092b001a646a60ddc77c3507e05d926528bbde9e92000f006d4b9d9f7`.

The exact service source is
`3606d5182bfb7e03b296e93b84bd5712c63b0cfd1076b21926331a8839a2df98`.
`build-7/FROZEN.json` binds the preserved receipt and outputs. Artifacts are
under `build-7/artifacts/`; `KERNEL.U` is the new kernel, `USER.PAQ` its embedded
provider, and `SERVICE` the compiled resident executable. The complete provider
file inventory, original identities, tools, inputs, platform, build commands,
kernel source inventory and console are bound by the receipt.

Build 7 packages the background startup wrapper, SHA-256
`f5f77df25eca46543906e49c80ab6e1a2cd937077a123b2b8a2fe88b2bac79f8`.
Its service executable is byte-for-byte identical to build 5, SHA-256
`a53dd1cc3874881524f41be0441b4f2b5396b12585f65bda600225235f4a1675`;
the existing 22 command/cancellation cases bind that same executable.

This is a **new derivation**, with schema
`ostadix.original9front-userland-builder/v1`. Do not pass it off as an older
standalone kernel derivation or relax that old probe's admission. The original
image is build 12115, commit `350266104f1fed81c78c3d05fa44f523bec0ae4d`.
Observed digest pins provide the declared provenance; upstream signatures and
compiler bootstrapping are not claimed.

## Trusted startup and common objects

Original boot exposes the PAQ's `/arm64`, `/sys`, and `/rc` directories before
the diskless `!rc` prompt. It does not expose these beneath `/boot`.

The existing original namespace transport has a known valid `/n` mountpoint:

```rc
mount -n -c /dev/eia1 /n
mkdir -p /n/services
rc /rc/bin/okernel-start /n/services/plan9 GENERATION16 INSTANCE32
```

Supply actual fresh lowercase hexadecimal values, not those placeholder words.
Keep this worker in the background with isolated standard descriptors. Its
request jobs receive separate stdin/stdout/stderr pipes; its own stdin never
serves a command. The original rc console remains available for keyboard and
save probes. Validate fresh `ready(G,S)` after launching; a returned shell
prompt or a successful launcher exit is not a readiness acknowledgement.
Run the wrapper separately as shown; sourcing its `exit` into the interactive
shell would close that shell. The equivalent direct launch is:

```rc
/arm64/bin/p9cmdsrv /n/services/plan9 GENERATION16 INSTANCE32 </dev/null >/dev/null >[2=1] &
```

The wrapper uses explicit `exit ''`: original rc preserves the prior condition
status across asynchronous launch, so a bare `exit` can incorrectly report
failure. A native test caught this in build 6; that failed run is preserved.

The service root is an explicit argv parameter. A host using Linux's
`/n/okernel` resolves the same native objects at, for example,
`/n/okernel/services/plan9`; Plan 9 uses `/n/services/plan9`. Translate logical
cwd consistently, such as Linux `/n/okernel/work` to Plan 9 `/n/work`.
Do not assume the read-only boot filesystem already has `/n/okernel` as a
mountpoint. Neither prefix conveys a new native capability.

The native grant remains fixed, trusted, single-operator root RW grant 4.
Request text, IDs, hashes, uid/mode labels and ready markers are descriptive
and provide integrity/session binding, not authorization. Commands execute
with the service's existing original Plan 9 authority.

The service rejects a reused instance directory. It remembers every accepted
request ID in memory, so deleting old result files cannot make an accepted ID
executable again within that instance. Old generations/instances are not
scanned. A partial existing `started` claim also forbids replay. The shared
store is RAM, not a crash journal; coordinator snapshot quiescence still owns
durability. Never automatically retry an unknown completion.

## Console adapter and cancellation

The exact wire format and pure helpers are in `PROTOCOL.md` and `protocol.py`.
Choose fresh trusted `G`/`S` before rendering the bootstrap input. The one-shot
trusted console bootstrap is sufficient to start this resident process; all
subsequent commands, cancellation and output use the native shared files.
Neither a host filesystem server nor another guest VM is required for that
transport. Qualification of this route in the unified monitor remains the
coordinator's gate.

Publish an immutable request followed by its exact `submit` marker. The request
declares absolute argv[0], argument vector, cwd, binary stdin, timeout and two
capture limits. Stdout and stderr are written concurrently and can be read as
provisional appended prefixes; only exact `done` plus validated result, streams,
status and `started` makes final captured output authoritative. Input is bounded
invocation data, not a PTY or a persistent interactive shell session.

Cancellation uses optional request-file `cancel`, with exact bytes
`OC9CAN01 G S R REQUESTSHA\n`. Use `cancel_marker(request_bytes)` and publish
by same-directory rename to an absent basename. The service ignores malformed,
stale or mismatched markers. A valid cancellation already present before launch
prevents any command child from being created. In-flight cancellation is polled
at a target interval of 50 ms; native I/O and scheduling prevent a hard latency
guarantee. The first observed cancellation/deadline wins. Late cancellation does
not alter a completed result. Result flag 16 means cancelled; flag 1 remains
timeout. Other capture/error flags can coexist.

## Required interruption recovery boundary

**Timeout or cancellation requires the coordinator to recycle the owning Plan 9
domain, discarding its previous running processes, before exposing final
interrupted completion or accepting another Plan 9 command.**
Pausing alone, resuming the same domain, or restarting only this resident
process is insufficient. Use a fresh instance ID under the current coordinator
generation and validate its new ready marker; a restarted coordinator also
requires a fresh generation. Do not replay old pending requests. A host watchdog
with no complete result has the same unknown-completion recovery requirement.

Every timeout leaves normal command completion and command effects uncertain,
including one with a validated captured timeout result. Keep that exact result
as interruption evidence: the existing `interrupted` recovery acknowledgement
binds its hashes. Missing or invalid completion instead uses `unknown` and null
completion hashes. Neither case permits automatic replay, and neither proves
that a userland note-group kill stopped all descendants. Domain discard stops
further execution without undoing earlier effects. No finer native job-control
authority is currently qualified for this provider; use its owned domain as
the recovery boundary.

Original rc deliberately compiles every background `&` with `rfork s`, creating
a new note group. Group notes therefore cannot prove all descendants stopped.
The old full lifecycle test caught a real delayed background write; that
failure is retained under `runtime-1` and `runtime-2`. Original rc was not
rewritten, and unrelated processes are not killed through a global PID diff.

On timeout or cancellation the final service freezes captured outputs, publishes
the bound instance-level `reset-required` marker before `done`, and exits.
It cannot admit a later request. `validate_reset` verifies the exact IDs and
request/result hashes; it does not perform or prove domain recovery. The
coordinator must enforce this boundary in its own runner/monitor. Until then,
do not advertise timeout cleanup or a completed unified runtime.

## Actual qualification

Build 7's new console/worker gate passed at
`runtime-coexistence-7-paced/result.json`, SHA-256
`cb50edb12fd4e9d526d01e28318c7990a3ee6eee8d9700a447c532725ad5d318`.
It observed the packaged wrapper return while the worker remained alive, and
the original `/proc` descriptor table contained exactly fd0 read, fd1 write,
and fd2 write, all `/dev/null`. This describes the tested launcher; arbitrary
extra descriptors inherited from a different launcher need their own checks.

While a resident request was active, foreground original `read` received exact
UART bytes and original rc executed a UART-supplied command that saved exact
content. The resident used the admitted PAQ-only original `7c`/`7l`/libc closure
to compile and run hello in its declared cwd. All 44 binary stdin bytes remained
separate from console input; stdout was exactly the hello prefix plus those
bytes, and stderr/status were empty with flags 0. The worker remained alive
after completion and the private VM halted cleanly. Independent evidence review
checked the result, captured files, descriptors and artifact bindings.

`qualification-7/result.json`, SHA-256
`5bc82280fe6f33e5f69ae7a965c6f3eb99e944b7212c7c3cbd707fb9917dad9b`,
binds build 7, 26 focused tests, that new gate, and the earlier behavioral
evidence for the identical service executable. It also binds the two preserved
failed attempts: build 6's wrapper-status failure and the first build-7 UART
test's multi-line burst transport failure. The passing gate sends one complete
compound command line. It does not establish lossless arbitrary console bursts
or qualify the coordinator's dual-domain mux.

These preserved behavioral receipts use build 5's identical service executable
and freeze/hash their controllers,
generated request files, original VM inputs and captured response bytes:

| Receipt under `/home/ustad/.cache/okernel-plan9-userland/` | Observed result |
| --- | --- |
| `runtime-foreground-5/result.json` | 18 original program cases: prior 12 command/stream/launch cases plus six malformed, partial, stale or wrong-hash cancellation notices ignored |
| `runtime-foreground-5/result.json` | Accepted-ID replay blocked after deleting claims; unpublished, partial, stale and preclaimed requests ignored; reused instance rejected; fresh service restart ignored old work |
| `runtime-cancel-active-5/result.json` | Live original command/PID witness before cancellation, exact stdout/stderr, flag 16, bound reset, resident exit, later request not admitted |
| `runtime-cancel-before-5/result.json` | Valid cancellation before submit: flag 16, exact status, empty streams and no command side effect; resident exit and later request rejection |
| `runtime-cancel-truncated-5/result.json` | Live original command, flags 18, exact 33-byte stdout prefix, bound reset, resident exit and later request rejection |
| `runtime-timeout-5/result.json` | Timeout regression with flag 1, bound reset, resident exit and later request rejection |

The five gates contain 22 actual original command cases. Their receipts and
the 25 focused tests are bound by `qualification-5/result.json`, SHA-256
`0d2a8c902978a87239344feeb16f5268f5e4bcd32da7cf3c2b1e47abc95c7edd`.
Earlier build-4 timeout, truncation-plus-timeout and background-timeout receipts remain
preserved under `timeout-final`, `truncation-timeout-final` and
`background-timeout-final`. None establishes descendant death or domain reset.

The original compiler/header/library closure inside the PAQ also built and ran
a native hello program. This verifies original source compilation by the
original tools; it is not O-core lowering of those tools or a full ABI claim.
The runtime gates above use a private original filesystem. The simultaneous
O-core domain/native shared-store gate belongs to coordinator integration.

The current 16 protocol tests and 10 builder tests pass. The actual original-VM gates
listed above pass for their stated scope. The failed historical group-cleanup
gate has not been relabeled as passing.

## Measured declared closure

| Group/artifact | Bytes |
| --- | ---: |
| Resident service + original rc + rcmain | 275,551 |
| Ten basic original tools | 617,210 |
| Original 7c + 7l + libc.a | 2,613,122 |
| All 128 declared architecture/system headers | 362,700 |
| Complete tested provider, including original boot helpers, additional tools/libraries: 239 files | 13,163,590 |
| Compressed read-only provider PAQ | 4,763,221 |
| Rebuilt original kernel including PAQ | 6,050,512 |
| Compiled resident service alone | 110,761 |

`closure-measurements-build7.json` in that cache root binds each measured group to
exact files. The smaller groups are inventories, not independently booted
minimal distributions. The full tested PAQ is the admitted closure. Static
archives remain in this PAQ instead of occupying the 16 MiB/1024-object shared
workspace. The 1 MiB request and stream-capture limits belong to the command
protocol; the current native file format instead permits up to 3,999 blocks of
4,088 data bytes per file, subject to the entire volume's shared free blocks.
Future large source caches require the separately governed provider disk from
the coordinator.

Read `BUILDER.md` for rebuild commands. The local private test command is:

```sh
source scripts/bm-dev-env.sh
python3 ocore/guest/plan9/unified/verify_service.py \
  --build /home/ustad/.cache/okernel-plan9-userland/build-7 \
  --output /absolute/new/private/output --profile foreground
```

The `timeout-stop` profile runs one timeout case in a fresh private VM; select
`--timeout-case timeout`, `truncation_then_timeout`, or `background_timeout`.
The `cancel-stop` profile similarly runs a single cancellation case in a fresh
private VM; select `--cancel-case cancel_in_flight`, `cancel_before_submit`, or
`truncation_then_cancel`. These commands never launch or modify the default
working VM or old heads.

Use `verify_console_coexistence.py` with the same `--build` and a fresh
`--output` to repeat the original UART/resident/compile coexistence gate.
