# Native sole-task Linux exit boundary

This component provides Linux x86-64 `exit(60)` and `exit_group(231)` for an
explicitly admitted loaded sole-task/sole-mm process leader. It uses native
O-core process, thread, namespace and scheduler services. It is not a complete
Linux process ABI, an interactive OS, or original libc source lowering.

Identity admission through `thread::admit_linux_single_task` alone does not
enable exit. Trusted boot must first admit the native empty-runqueue idle
policy, then call `linux_process_syscalls::arm()` before any task runs. Arm
requires a nonzero matching trusted provider ID, complete management-context
preconditions and the existing scheduler's exact boot history. The component
has no guest-callable admission or ID argument. Provider callbacks are native,
read-only queries over trusted generation-bound metadata. They do not confer
capabilities through namespace text, status values or numeric compatibility IDs.

At request and cleanup, `current_linux_tid()` rechecks the actual loaded TCB,
PCB, address space, CSpace, native domain and sole held thread reference, with
positive int32 TID equal to PID. The boot provider must also recognize that
exact TCB/PCB/TID/AS/CSpace tuple. Requests with no policy, mismatched provider,
withdrawn identity or existing pending action return Linux `-ENOSYS` (-38)
without replacing pending work. Native internal `-8` never leaks as the Linux
refusal code. Ordinary -31/-32 return values do not select scheduling.

Both exit numbers encode only `(raw_status & 255) << 8`, matching the pinned
[Linux v6.12 exit implementation](https://github.com/torvalds/linux/blob/v6.12/kernel/exit.c).
The scheduler marks a distinct kernel-owned terminal action bound to this
masked syscall's entry serial, original number, guarded frame and current
TCB/PCB generations. Route and cleanup revalidate the transaction. Source
CS/SS, normalized vector/error, fixed RFLAGS bit, current CR3/TSS/entry stack,
and the scoped FS/GS boundary remain checked. Source user RIP/RSP do not need
to be resumable: successful Linux exit never publishes or returns that frame.
Legacy native action4 and ordinary blocking/fault paths keep their existing
resumable-frame validation and status semantics.

The matching cleanup provider must call `cleanup_allowed(owner,status)` before
any resource mutation. The controlled profile closes only the exiting owner's
file context through the existing checked synchronous supervisor aperture,
then lets the scheduler commit PCB exit, TCB termination, reference release and
reapability. It does not reset the shared store or close another owner's
handles. A rejected cleanup stops the scheduling transaction and does not
pretend the process exited. A dependency cleanup failure can have prior
resource effects; there is no general rollback claim. Final file-context
retirement remains a separate trusted action after the exact PCB generation
has been destroyed, never during exit or merely on becoming reapable.

Existing sole-mm clear-child-TID metadata is discarded by the real TCB EXITED
paths without touching its raw address. This is the sole-mm branch of
[Linux v6.12 mm_release](https://github.com/torvalds/linux/blob/v6.12/kernel/fork.c),
not shared-mm clear/futex wake. The hardware fixture registers invalid raw
addresses and valid private sentinels; independent stopped-memory reads must
show the sentinels unchanged after exit and the TCB metadata cleared.

Run the explicit owned profile with matching Clang/LLD on PATH:

```bash
python3 -B ocore/kernel/native_linux_exit/verify.py \
  --output /absolute/new-output \
  --compiler /absolute/ocorec \
  --codec-manifest /absolute/native-codec.json
```

The controlled C carrier is authored ABI/lifecycle test code. It executes real
CPL3 syscall instructions under four separately loaded address spaces; it is
not an upstream application or a rewritten libc implementation. Two kernel
builds must match exactly. The provider uses the existing original-source
O-core codec closure and common store/file services. Every run retains the
exact source inputs before compilation, commands, tool identities, generated
probe and any composed same-module test fragment, serial/interrupt logs,
QMP-stopped native state and sentinel bytes. It starts and closes only its own
128MiB, one-CPU QEMU.

Status groups cover both syscall numbers with 0, 1, 42, 255, 256, -1, high64,
and raw -31/-32 values. A surviving client checks real FS-relative private TLS
and binary file-offset continuity after sibling exits. The last task must
leave an ACTIVE, nonfailed kernel in the nm-derived dedicated management idle
function with actual HLT=1, IF=1, management stack/CR3, FS=0 and expected GS.
There can be no after-exit user instruction or bounded-completion shortcut.
A separate actual positive uses an invalid user RSP with each exit number.

Build-time negative cases are scoped test controls, never application options
or new production grants. They cover absent provider/identity, sole-refcount
withdrawal, stale generation-bound provider metadata, refusing a second
request without replacing pending sleep, provider withdrawal before cleanup,
and real cleanup dependency failure. Cases 6–14 append an exact captured
`scheduler_test_hooks.oc.inc` fragment to an exact captured production prefix.
It supplies stale serials, forged terminal bits/actions/status, changed
original syscall number, wrong source-frame pointer and invalid RFLAGS.
Compiler/linker failures do not count as passing runtime controls.

The old default/startup profiles continue to return ENOSYS for 60/231. This
new profile retains the native idle foundation's serialized x86-64 bootCPU,
maskable-interrupt and null-user-GS-selector restrictions. Async user MOVGS
isolation, SMP/NMI/SMI, clone/shared mm, futex, wait, signals, general process
groups, persistent shell/UI, comprehensive drivers and full native OS
acceptance remain unmet. A future unchanged source-lowered musl `_Exit` test
must preserve its original exit_group-then-exit fallback and be qualified as a
separate actual CPL3 component integration; this authored carrier proves none
of that original-source provenance by itself.
