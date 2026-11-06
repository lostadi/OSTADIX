# Native x86 thread FS state

`native-thread-fs-x86_64` is an isolated protected-boundary test. It adds real
per-TCB FS selector/base state to the production native file profile. It is not
an original musl/application admission, a shell, or the completed unified OS.

```sh
python3 -B ocore/kernel/native_tls/verify.py \
  --output "$HOME/.cache/native-thread-fs-new" \
  --codec-manifest "$HOME/.cache/okernel-u9fs-native-recipe/runs/x86_64-O1-final/native-codec.json"
```

The output directory must be new. The test starts and stops only its own QEMU
process and retains source/tool identities, two native kernel builds, console,
interrupt trace and independent stopped-machine observations. Existing VMs,
saved heads, installed launchers and preserved kernel artifacts are untouched.

## Architecture and lifetime

`thread.oc` owns selector/base metadata under the existing generation-tagged
TCB identity. Initialization, termination, cancellation and reap clear it.
`boot.S` captures the actual hardware selector and `IA32_FS_BASE` on CPL3
syscall, timer and exception entry, after the general registers are saved and
kernel GS is active. It sets kernel FS selector/base to zero before O-core
callbacks. The selected TCB's state is restored immediately before user return.
Management context also has zero FS state. Capturing the actual registers is
necessary because a user `MOV` to FS can change the base without `arch_prctl`.

Callbacks execute on the guarded kernel stack before RSP is switched to a
synthetic saved TCB frame. That frame is metadata, not callback stack space.
The normalized 22-word register frame and scheduler transaction are unchanged.
This adds register operations and callbacks at user boundaries; no system
efficiency improvement is claimed.

The opt-in `linux_tls_syscalls.oc` component implements syscall 158 operations
`ARCH_SET_FS` and `ARCH_GET_FS`. It derives authority from the real current
TCB/process/address-space identities. SET accepts zero or an unmapped lower
user base below the four-level Linux `TASK_SIZE_MAX` value
`(1 << 47) - 4096`, with EPERM for higher values. A base value is not a mapping
grant; ordinary CPL3 page permissions still apply. SET selects the null FS
selector; GET copies eight bytes through the existing checked user-memory API.
Unsupported operations return an explicit error. GS, LDT, GDT TLS,
`set_thread_area`, clone, `set_tid_address`, clear-child-TID and futex behavior
are not supplied. Syscall 218 remains ENOSYS.

The declared profile has one CPU, four-level paging and FSGSBASE disabled.
Allowed captured FS selectors are null selectors and this platform's existing
readable CPL3 data/code descriptors, including every legal RPL variant
`0x18..0x1b` and `0x20..0x23`. Capture and restoration retain the exact RPL.
LDT selectors and high-bit aliases are rejected. LA57, arbitrary user descriptor tables,
asynchronous kernel TLS and multiprocessor state ownership require separate
qualification. Unscheduled bootstrap payloads retain their legacy zero-FS
return and cannot use the thread-owned `arch_prctl` interface.

## Qualification

The fixture uses four distinct TLS base virtual addresses in four private
loaded address spaces. User canaries survive syscall yields and timer
preemption. All four threads load each of the eight legal data/code selector
variants with `MOV FS`, then check exact selector and zero base through GET,
yield and timer preemption. QMP reads per-thread completion masks and the
32 exact captured selectors; hardware traces independently include all eight
selector variants at actual CPL3 timer entries. The fixture also checks
SET's null-selector behavior, bad destinations, invalid bases, unsupported
operations and acceptance of an unmapped user base without granting access.
The designated faulted principal's TCB state is cleared while survivors retain
their own values. The existing real copy page-fault and file-authority tests
remain in this profile.

QEMU's interrupt trace independently records a CPL3 timer entry for every
distinct base. QMP reads the actual TCB arrays, completed fixture flags and
management registers. The two kernel builds must match using the same sealed
seven-object original u9fs/musl codec input closure; this is not two upstream
source/toolchain rebuilds.

Passing hardware receipt:
`/home/ustad/.cache/okernel-native-tls-selectors-green-20261103/result.json`.
The corresponding old-whitelist failure, source snapshots and exact-kernel
replay are retained under
`/home/ustad/.cache/okernel-native-tls-selectors-red-20261103/`.
That replay independently observed legal CPL3 `FS=0018` followed by the old
capture validation's fatal halt. Only `thread.oc` differs between the red and
green execution inputs; fixture and OVFS bytes match.

The preceding r1/r2 runs remain preserved historical evidence; their narrower
selector coverage did not detect that whitelist bug. The unchanged file fixture
with zero initial FS state passes at
`/home/ustad/.cache/okernel-native-fs-zero-fixed-20261103/result.json`.
The earlier failed implementation attempt is preserved at
`/home/ustad/.cache/okernel-native-fs-zero-baseline-20261103/`; it identified the
callback-stack issue above and is not counted as acceptance.

`tests/test_linux_tls.py` separately executes the real thread, process,
address-space and capability registries in a hosted native carrier, including
stale/reaped TCB generation reuse. That carrier replaces five architectural
CR3/copy functions and does not establish hardware execution by itself:

```sh
OCORE_U9FS_MANIFEST="$HOME/.cache/okernel-u9fs-native-recipe/runs/x86_64-O1-final/native-codec.json" \
  python3 -B -m unittest tests.test_linux_tls -v
```

This is the kernel FS-register substrate needed by original runtime startup.
It does not implement original musl TLS construction, admit its assembly or
module assembly, provide allocation/process/exit semantics, or lower a complete
original application through O-core.

## Opt-in single-task Linux startup services

Add `--linux-task-startup` to the verifier command to exercise syscall 186
(`gettid`) and 218 (`set_tid_address`) alongside the existing protected TLS and
regular-file checks. This is one loaded task per address space; the fixture
runs four independent spaces. The ordinary TLS profile retains its native
4101/4201 process/thread identities and rejects 218 as unsupported.

Trusted kernel policy admits a generation-valid loaded TCB only when its
existing positive 32-bit thread ID equals its owning process ID and it holds
the sole thread reference. Syscalls recheck the current TCB, PCB, address
space, CSpace, domain and operation authority. IDs are not translated or
fabricated. The startup fixture rejects the ordinary nonleader IDs before
installing actual equal process/thread IDs.

Registration retains the raw pointer, including NULL, unaligned, unmapped and
noncanonical values. It neither probes the address nor writes a TID there.
Each task's registration survives syscall yields independently. Committed
native containment, cancellation and process termination discard registration
before reap; reaped handles cannot authorize a new task. Boot-only registry
initialization remains nonrepeatable. These are the sole-mm-user semantics
of the declared profile, consistent with [Linux v6.12 fork.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/fork.c).
Shared-mm clearing and futex wake are not implemented by this component.

`--linux-task-id-base 2147483644` exercises the largest permitted `pid_t` in
the fourth task. Base 2147483645 must instead reject that task before any user
dispatch. This is an expected negative gate, not a successful application run.
Both options are trusted test configuration and grant no user authority.

Linux exit syscalls 60/231, clone, futex, robust lists, multi-thread groups and PID
namespaces remain unsupported here. This does not admit original musl startup
or any complete original application. The original engines and their required
assembly/provider closure remain separate source-lowering obligations.
