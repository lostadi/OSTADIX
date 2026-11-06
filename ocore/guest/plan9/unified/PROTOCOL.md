# Original Plan 9 resident command protocol, version 1

This protocol carries commands between the coordinator and an original Plan 9
resident service over the native shared namespace. The service executes an
absolute original Plan 9 program with an explicit argument vector, working
directory and byte input. Calling `/bin/rc` explicitly selects original rc
syntax. The host helper does no dispatch or filesystem writes.

The trust profile is one trusted operator and one coordinator, with at most one
request in flight per service instance. Linux and original Plan 9 already hold
separate native root read/write grants (1 and 4). Names, IDs, modes, user labels
and hashes do not confer authority or authenticate another user. Commands have
the resident service's existing authority. This is not a sandbox for hostile
commands or a multi-user authentication protocol.

## Identity and paths

- `G`: exactly 16 lowercase hexadecimal ASCII characters, nonzero, supplied by
  trusted startup for this coordinator generation.
- `S`: exactly 32 lowercase hexadecimal ASCII characters, freshly supplied by
  trusted startup for this resident process instance.
- `R`: exactly 32 lowercase hexadecimal ASCII characters, a new request ID.

The service receives `G` and `S` through trusted startup arguments. It never
adopts an identity discovered in persistent request files. A replacement
resident process gets a new `S`; a restarted coordinator gets a fresh `G` and
`S`. Neither identity is recovered from old on-disk ready markers. Reusing a
previous `(G,S)` is outside this protocol's restart contract.

Default service root: `/n/services/plan9` in the original Plan 9 namespace,
where the native store is mounted at `/n`. The coordinator resolves the same
native objects through its own mount; the textual mount prefix need not be
identical. Python exposes this guest spelling as `PLAN9_ROOT`. Its existing
`DEFAULT_ROOT = "/n/okernel/services/plan9"` remains a compatibility spelling
for callers with that coordinator mount; it does not name the guest mount.
Pass the configured namespace's root explicitly to `request_paths`.
Startup creates `ROOT` itself, not missing ancestor directories. Before
starting the service at `PLAN9_ROOT`, the coordinator's guest bootstrap must
run `mkdir -p /n/services`, or choose an existing-parent, one-level root.

```text
ROOT/gG/sS/ready
ROOT/gG/sS/reset-required
ROOT/gG/sS/rR/request
ROOT/gG/sS/rR/submit
ROOT/gG/sS/rR/cancel
ROOT/gG/sS/rR/started
ROOT/gG/sS/rR/stdout
ROOT/gG/sS/rR/stderr
ROOT/gG/sS/rR/status
ROOT/gG/sS/rR/result
ROOT/gG/sS/rR/done
```

The literal `g`, `s`, and `r` precede the identity text. IDs cannot contain path
separators. Request bytes are immutable after publication.
`cancel` is optional. `REQUEST_FILES` continues to list the required request
files; `OPTIONAL_REQUEST_FILES` lists `cancel`. Call
`request_paths(..., include_optional=True)` to include its path without
requiring that a cancellation file exist.

## Background startup and console ownership

Execute `/rc/bin/okernel-start` as a separate original rc invocation,
passing exactly three arguments: the Plan 9 service root, `G`, and `S`.
Do not source it into the interactive console: its final `exit` belongs to
the startup invocation. After checking the admitted userland closure, it runs:

```rc
/arm64/bin/p9cmdsrv $* </dev/null >/dev/null >[2=1] &
exit ''
```

The pinned original rc gives the asynchronous child a separate note group
and does not wait for it when the startup invocation exits. The explicit
redirections give the resident null standard input, output, and error, leaving
the original foreground console available. Returning from the wrapper only
means launch was attempted. The coordinator must observe and validate the
exact fresh `ready` marker before dispatch; the wrapper's exit status or
background PID alone cannot establish service readiness.
The explicit empty exit status is required because original rc's asynchronous
launch preserves the preceding condition's status; bare `exit` can report
failure after a successful launch.

The wrapper redirects descriptors 0, 1, and 2 and original rc closes its
temporary redirection and script-input descriptors on exec. It does not
promise to close arbitrary extra descriptors inherited from a custom launcher.
The trusted launcher must avoid passing console descriptors through those
extra slots; native coexistence qualification inspects the resident's actual
descriptor table. Console input belongs to the foreground console path, not
the resident request queue. The service supplies each command with a separate
pipe containing exactly that request's bounded stdin bytes, followed by EOF,
and separate stdout and stderr capture pipes. Null resident stdin therefore
does not discard request input or turn it into console input.

A shared working directory is selected by native-store identity, then spelled
for the target namespace. With Linux mounted at `/n/okernel` and Plan 9 at
`/n`, logical shared directory `/work/project` is Linux
`/n/okernel/work/project` and Plan 9 `/n/work/project`. The coordinator puts
the Plan 9 spelling in each request's `cwd`; selecting the same shared cwd
does not require changing the resident process's directory. Resolve paths
against the configured mount roots by path components, rather than replacing
arbitrary argument text. Provider-local executable paths such as
`/arm64/bin/7c` remain original Plan 9 paths. A child `cd` affects that
invocation only and does not establish a persistent shell session.

## Request bytes

All integers are unsigned 32-bit little-endian values. There is no padding or
NUL terminator, and extra bytes after the payload are invalid.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 8 | ASCII `OC9REQ01` |
| 8 | 16 | `G`, ASCII |
| 24 | 32 | `S`, ASCII |
| 56 | 32 | `R`, ASCII |
| 88 | 4 | Argument count |
| 92 | 4 | Working-directory byte length |
| 96 | 4 | Standard-input byte length |
| 100 | 4 | Timeout in milliseconds |
| 104 | 4 | Captured stdout byte limit |
| 108 | 4 | Captured stderr byte limit |
| 112 | variable | Working-directory UTF-8 bytes |
| following | variable | For each argument: 4-byte length, then UTF-8 bytes |
| following | variable | Exact raw standard-input bytes |

The entire request is at most 1,048,576 bytes, including the header and lengths.
This is the protocol admission limit, not the native volume's overall capacity.
The working directory is absolute, 1–4095 encoded bytes, with no NUL. There are
1–64 arguments; each is at most 65,535 encoded bytes and contains no NUL.
Argument zero must be absolute. Other arguments may be empty. UTF-8 is strict;
spaces, quotes and newlines are data, never an implicit shell interpolation.
Standard input is binary and may contain any byte. Timeout is 1–300,000 ms.
Each output capture limit is 0–1,048,576 bytes; zero captures no bytes.

The working directory is applied to this invocation. A `cd` inside a child rc
does not change the C service's directory or automatically persist into the
next request. Persistent shell-state behavior requires a separately explicit
session interface; this protocol reports invocation results. Standard input
is the bounded byte payload of this invocation, not a live input stream.
There is no PTY or persistent interactive shell session in this contract.

## Publication and non-replay

Every marker below is ASCII with exactly one space between fields and exactly
one final LF. Hashes are 64 lowercase hexadecimal characters representing
SHA-256 of the complete named byte sequence.

```text
ready:   OC9READY1 G S\n
submit:  OC9SUB01 G S R REQUESTSHA\n
cancel:  OC9CAN01 G S R REQUESTSHA\n
started: OC9SUB01 G S R REQUESTSHA\n
done:    OC9DONE1 G S R REQUESTSHA RESULTSHA\n
reset-required: OC9RESET1 G S R REQUESTSHA RESULTSHA\n
```

The `\n` notation above denotes one LF byte, not a backslash followed by `n`.

1. Trusted startup chooses fresh identities. The resident publishes `ready`
   only after initialization, and the coordinator requires the exact expected
   `(G,S)` before dispatch.
2. The coordinator writes and closes the complete request. It publishes the
   matching `submit` last. Stage a marker under a unique temporary basename,
   write and close it, then rename it to its previously absent final basename.
3. The service checks the active identities, path identity, exact request hash,
   framing and limits. Before any command side effect, it records the exact
   submission as `started`. A pre-existing claim, even a partial or malformed
   one, is never permission to execute again. A duplicate identical submission
   can only observe the original execution/result; different bytes under the
   same identity are rejected.
4. The service writes the streams and raw status, then the complete result.
   Only after those files are closed and capture is finalized does it publish
   the matching `done` marker last. The coordinator validates all identities,
   lengths and hashes before treating the result as complete. A timed-out or
   cancelled result additionally requires the domain recovery procedure below
   before the coordinator exposes final timeout or cancellation completion.

Publication depends on same-directory rename to an absent name. The native
store does not support overwrite-by-rename, cross-directory rename, exclusive
file locks or filesystem transactions. Do not update a reusable `current`
marker through remove-then-rename and describe that as atomic replacement.
The existing original mount uses `mount -n -c`: `-c` permits creation;
uppercase `-C`, which enables client caching, is not used.

Between commands, the resident retains one open service-directory descriptor
and rewinds it before each fresh enumeration. It does not cache the listing or
use its qid version to infer that files inside existing request directories
have not changed. Idle scan sleeps back off from 50 through 100 and 200 to a
maximum of 250 ms; admitting a command resets the next sleep to 50 ms. This
bounds the intended idle admission polling interval, not wall-clock command
latency: native I/O and scheduling still take time. A directory rewind/read
failure stops the instance rather than skipping work or electing another
instance. The independent in-flight cancellation/deadline loop retains its
50 ms target interval.

The process-local accepted-ID ledger remains authoritative after completed
request files are cleaned up; a duplicate ID must not become executable merely
because its old directory was removed. Retain claims for the active instance,
or retain an in-memory accepted-ID set until it ends. Completed data may be
archived and removed only under that invariant. Unknown completion, service
loss, or a coordinator timeout never causes automatic resubmission under a new
ID. Old generations and old instances are not scanned for work. Their results
may remain readable as historical evidence.

This provides at-most-once admission under the stated instance lifecycle. It
does not provide transactional exactly-once external effects: a crash after
`started` but before `done` leaves an unknown outcome. The shared RAM store is
not a crash journal; persistent snapshots require the existing monitor
quiescence procedure.

## Cancellation

The coordinator may publish the optional request-level `cancel` file with the
exact `OC9CAN01` marker above. It binds `G`, `S`, `R`, and the SHA-256 of the
complete immutable request. Publish it once by writing and closing a uniquely
named temporary file in the request directory, then renaming to the absent
`cancel` name. Never overwrite it or use remove-then-rename as atomic replacement.
A cancellation notice does not submit a request or grant authority to execute.

Only a valid notice matching the currently admitted request can cancel it.
Malformed, partial, stale-generation, stale-instance, wrong-ID and wrong-digest
notices are ignored by the service. If a valid notice is already present
before execution begins, the service records admission and produces a cancelled
result without spawning the command. During execution the service samples for
cancellation with a target interval of at most 50 ms. Native I/O and scheduling
can delay observation, so this is not a hard cancellation-latency guarantee.

The first cancellation or timeout condition observed by the service wins;
there is no promise to order them by the times the coordinator published a
file or a deadline elapsed. Cancellation selected as the winning condition
sets result flag 16. A notice arriving after `done` has no effect on that
completed result. Publishing or validating a cancellation notice alone is
not cancellation acknowledgement: require a validated result, `done`, and the
domain recovery below. A watchdog with missing completion remains an unknown
outcome and must not cause automatic replay under another request ID.

`cancel_marker(request_bytes)` constructs the exact marker.
`validate_cancel(request_bytes, marker)` rejects malformed or mismatched
markers and returns the decoded request. These helpers do not know which
request is active, publish a file, or interrupt execution. The caller must
select the trusted active request, and the resident must apply its lifecycle
checks before acting on a valid notice.

The resident's running-command controller records its selected interruption
in the request's internal `.interrupted` file: exactly one ASCII byte `C` for
cancellation or `T` for timeout. It publishes this decision before sending
termination notes. The parent reads the record after collecting its helpers,
so timer/collector exit ordering or killing the timer during cleanup cannot
erase the selected interruption flag. Pre-spawn cancellation needs no running
controller or decision file. This internal record is neither authority nor
`done`; callers still require the final result and recovery procedure.
Failure to publish or read a complete decision leaves execution incomplete
and cannot permit another dispatch. The coordinator's watchdog must then
apply unknown-completion recovery of the owned domain.

## Timeout, cancellation, and unknown-completion recovery

Every observed command timeout or cancellation, coordinator watchdog expiry,
or loss of service with unknown completion requires the coordinator to stop
admitting Plan 9 commands and pause/recycle the owned Plan 9 execution domain.
It MUST complete that domain recovery before exposing a final timeout or
cancellation result or admitting another Plan 9 command. This requirement also
applies to cancellation detected before command spawn. Restarting only the
resident process is insufficient: original rc background jobs can change note
groups and survive that process. Recovery must discard the previous domain's
running processes, then establish a fresh `S` under the current coordinator's
`G` and validate that instance's new `ready` marker. If the coordinator itself
restarts, both `G` and `S` must be fresh. Pausing alone is not a
completed recovery, and resuming the same running domain is not recycling it.

Every timeout leaves normal command completion and the complete set of command
effects uncertain. A validated timeout result records the service's observed
timeout and exact retained output/status; it does not prove successful or
complete command execution, descendant termination, or rollback. Preserve that
captured evidence. The recovery acknowledgement uses `outcome: interrupted`
and its complete hashes when the timeout capture validates. This describes
known interruption evidence, not known normal program completion. If no valid
complete capture exists, use `outcome: unknown` with null completion hashes;
do not invent a result. Both cases require the same domain recovery and forbid
automatic replay. A client timeout exit code reports the observed timeout only
after recovery, not an original Plan 9 program's numeric exit status.

When the resident detects timeout or cancellation and can finish capture, it
first publishes the request's `status` and `result`, then publishes the
instance-level `reset-required` marker, then the request's `done`. It exits
permanently without accepting another request. The reset marker binds the interrupted request
and result bytes through the same identities and SHA-256 digests as `done`.
Its result must have flag 1 or flag 16 set. The marker describes recovery need;
it grants no authority and does not prove that descendant processes have stopped.

The coordinator still validates all captured stream lengths and hashes, raw
status, `started`, and `done`; recovery does not relax those checks. If a
watchdog fires before complete evidence exists, the outcome remains unknown.
Missing, malformed, or mismatched recovery/completion markers never authorize
continued dispatch or imply that a reset is unnecessary. Keep available
evidence, recover the domain, and report unknown completion without inventing
a result or automatically retrying the request. A timeout, cancellation or reset
does not undo earlier filesystem or other external effects.

`reset_marker(request_bytes, result_bytes)` creates this descriptive marker.
`validate_reset(request_bytes, result_bytes, reset)` checks exact framing,
identities, digests and a timeout or cancellation flag and returns the decoded
result. These pure helpers perform no pause, reset, publication, or authority
check, and they do not replace `validate_result` for captured stream and status validation.
The coordinator must implement and qualify the recovery procedure separately.
Foreground success and stable captured streams do not establish that arbitrary
detached background processes have terminated; this protocol makes no such
descendant-cleanup claim.

## Result bytes

The authoritative result has a 200-byte fixed header followed by the raw Plan
9 wait-status bytes. It contains no padding or trailing bytes.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 8 | ASCII `OC9RES01` |
| 8 | 16 | `G`, ASCII |
| 24 | 32 | `S`, ASCII |
| 56 | 32 | `R`, ASCII |
| 88 | 32 | SHA-256 of complete request, raw digest bytes |
| 120 | 4 | Flags |
| 124 | 4 | Captured stdout length |
| 128 | 4 | Captured stderr length |
| 132 | 4 | Raw status length |
| 136 | 32 | SHA-256 of captured stdout, raw digest bytes |
| 168 | 32 | SHA-256 of captured stderr, raw digest bytes |
| 200 | variable | Raw Plan 9 status bytes, at most 4096 bytes |

| Flag | Meaning |
| ---: | --- |
| 1 | Command timeout occurred |
| 2 | Stdout exceeded its capture limit |
| 4 | Stderr exceeded its capture limit |
| 8 | Service preparation, command launch, or output capture failed |
| 16 | Cancellation was observed for this request |

Flags may be combined; other bits are invalid. Lengths describe retained bytes,
not total produced bytes, and may not exceed the request's capture limits.
Hashes cover exactly the retained bytes. Reaching a limit exactly does not
alone establish truncation; seeing another byte does. After a capture limit,
drain or terminate the producer deliberately instead of leaving a full pipe
that prevents the command from exiting. A zero limit still permits detecting
and reporting discarded output.

The resident may create internal `.stdout.truncated` and `.stderr.truncated`
files containing the single ASCII byte `1` as soon as overflow is observed.
These preserve overflow evidence if a later interruption kills a collector before
it can report its exit status. They are not completion markers; the final
result's flags remain authoritative for the coordinator. Temporary publication
names have the form `.<name>.pending.<pid>` and are never executable requests.
An actual capture failure and interruption may both be reported; a collector
killed solely by timeout or cancellation does not itself imply an additional
capture-failure flag.

The `status` file must equal the result's status bytes. Original Plan 9 status
is a string: empty means successful normal exit. Preserve nonempty status
bytes rather than converting them into an invented POSIX exit number. The
helper's `Result.ok` is true only when the status is empty and all flags are
zero. Timeout, cancellation, truncation and launch errors are thus visibly
distinct from complete successful execution.

Only publish `done` once both output streams are stable. Waiting for rc alone
does not establish that background descendants have closed inherited output
descriptors. Two pipe collectors must drain concurrently; close every unused
pipe end in every child and wait for capture completion. Direct-file capture
must not silently report success after a storage write failure. The 16 MiB
native volume and 1024 metadata nodes are shared resources; failure to retain
or publish a complete result leaves it incomplete, not implicitly successful.
Streams are captured concurrently into growing retained prefixes. A caller may
use original file reads and reopen the files to obtain newly appended bytes,
but bytes observed before `done` are provisional. Only the completed result
and validated final captures are authoritative. This tentative output view
does not add backpressure-controlled interactive stdin or PTY semantics.

## Original Plan 9 implementation notes

The pinned upstream commit is
`350266104f1fed81c78c3d05fa44f523bec0ae4d` (official ARM64 build 12115).

- The original C APIs include `rfork`, `chdir`, `dup`, `exec`, `wait`,
  `nulldir`, `dirwstat`, `readn`, and `write`. A child created with
  `RFPROC|RFFDG|RFENVG|RFNAMEG|RFNOTEG|RFREND` can copy the parent's file,
  environment and namespace groups while getting a separate note group.
  Check every setup call. Close protocol descriptors in the child, or use
  `OCEXEC` where appropriate. [Pinned libc header](https://raw.githubusercontent.com/9front/9front/350266104f1fed81c78c3d05fa44f523bec0ae4d/sys/include/libc.h),
  [rfork semantics](https://raw.githubusercontent.com/9front/9front/350266104f1fed81c78c3d05fa44f523bec0ae4d/sys/man/2/fork).
- `wait()` returns allocated `Waitmsg` records; select the command's PID and
  preserve `msg`, then free the record. Collector-child exits are separate.
  `await()` returns a byte count without a terminal NUL, so using `wait()`
  avoids hand-parsing that format. [Pinned wait documentation](https://raw.githubusercontent.com/9front/9front/350266104f1fed81c78c3d05fa44f523bec0ae4d/sys/man/2/wait).
- Explicit `/bin/rc -I SCRIPT` executes original rc non-interactively while
  descriptor zero remains available to the command's input. Quoted rc strings
  use doubled apostrophes, not POSIX shell escapes; argument-vector execution
  avoids this translation entirely. [Pinned rc documentation](https://raw.githubusercontent.com/9front/9front/350266104f1fed81c78c3d05fa44f523bec0ae4d/sys/man/1/rc).
- Original `sha2_256` and `SHA2_256dlen` are declared in `<libsec.h>`, whose
  library pragma selects `libsec.a`. This supplies request and stream hashes
  without a replacement hash implementation. [Pinned libsec header](https://raw.githubusercontent.com/9front/9front/350266104f1fed81c78c3d05fa44f523bec0ae4d/sys/include/libsec.h).
- `postnote(PNGROUP, pid, "kill")` targets one note group. A live supervisor
  keeps that group addressable after the immediate command exits, but cannot
  contain every descendant. Original rc inserts `rfork s` for background `&`
  jobs, which creates another note group. Group notes therefore do not replace
  the required domain recovery on timeout, cancellation or unknown completion. [Pinned
  postnote documentation](https://raw.githubusercontent.com/9front/9front/350266104f1fed81c78c3d05fa44f523bec0ae4d/sys/man/2/postnote),
  [pinned rc compiler](https://raw.githubusercontent.com/9front/9front/350266104f1fed81c78c3d05fa44f523bec0ae4d/sys/src/cmd/rc/code.c).
- The unmodified upstream boot PAQ recipe includes rc, cat, mkdir, mv, sleep,
  test and awk, but does not list 7c, 7l or sha1sum. The admitted expanded
  build-7 provider does include those original tools, the compiled service,
  and its declared compiler/header/library closure. Its separate PAQ-only
  native compilation gate establishes that closure; a kernel build alone
  would not. See `BUILDER.md` and `HANDOFF.md` for the exact receipt and
  inventory. [Pinned upstream bootfs recipe](https://raw.githubusercontent.com/9front/9front/350266104f1fed81c78c3d05fa44f523bec0ae4d/sys/src/9/boot/bootfs.proto).

The host implementation is `protocol.py`; independent framing, limit,
corruption and replay-binding cases are in
`tests/test_plan9_command_protocol.py`. These tests qualify framing and
validation, not a boot, resident execution, timeout delivery, or authority
boundary. Those require the original guest integration tests.
