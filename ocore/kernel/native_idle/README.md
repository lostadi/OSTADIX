# Native empty-runqueue idle boundary

This is an explicitly opted-in x86-64 boot-CPU scheduling foundation. It is not
Linux exit60/exit_group231, an upstream application, a persistent console, an
SMP mechanism, or a complete native operating system.

The ordinary scheduler remains the default. Its bounded acceptance completion
hooks and legacy syscall control values keep their existing behavior. Trusted
kernel setup may call `enable_personality_idle()` once after `arm_personality`
with four correctly loaded Linux-minimal principals and no current task. It
must already be on the complete normalized management context, with IF masked.
Admission is read-only until its final policy publication. A negative decision
changes neither the policy nor architectural state.

The read-only assembly predicate checks the real management stack bounds,
CR3, TSS.RSP0, per-CPU entry stack/scratch, FS selector/base, active/inactive GS
bases, kernel selectors, and IF. The opt-in syscall boundary supports a null user GS selector only; legal nonzero user selectors are explicitly unsupported and fail closed before policy dispatch. This is not general GS TLS or selector preservation. This profile excludes native SYS_EXIT before
any native-personality dispatcher can mutate its PCB. Existing Linux task-ID
admission does not enable this policy or Linux exit syscalls.

For this policy, actual masked syscall entry binds the guarded normalized
frame, original syscall number, vector/error, and exact current TCB/PCB to a
kernel-lifetime entry serial. Admission also rejects any prior dispatch/timer history. Pending scheduler requests must belong to that
entry. Route, schedule and idle consumption are separate one-shot phases.
A second request cannot overwrite an already-pending action. Raw results -31
and -32 remain ordinary results; their numeric values cannot grant control.
Invalid entry/route/selection is terminal and never returns an obsolete frame.
Only the failing entry's tagged pending work is cleared, preserving unrelated
pending state for diagnosis rather than misattributing ownership.

After successful source-frame save and block/retirement, genuine queue
emptiness publishes a private idle disposition. Failed context installation,
deferral or queue validation cannot publish it. Assembly consumes the
out-of-band disposition, restores management CR3/TSS/per-CPU state, switches to
the owned management stack, sets FS=0 and GS_BASE=percpu/KERNEL_GS_BASE=0,
rearms the existing one-shot PIT and enters a dedicated adjacent `sti; hlt`
loop. Maskable interrupt recognition is delayed across STI's following
instruction, so a pending PIT interrupt cannot be handled between enabling
interrupts and HLT. See Intel's [STI instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).

The existing timer path wakes actual blocked TCBs, validates the selected frame
and restores exact CPL3 context and thread-owned FS state. With no runnable
work it returns to the owned kernel idle frame. The new policy excludes the
old phase-one bounded completion predicate, while retaining native cleanup,
identity, deferral, request-expiration and queue checks. Default policy keeps
the original bounded completion path.

Run the owned hardware gate with pinned tools and original codec closure:

```bash
python3 -B ocore/kernel/native_idle/verify.py \
  --output /absolute/new-output \
  --compiler /absolute/ocorec \
  --codec-manifest /absolute/native-codec.json
```

Use the matching Clang/LLD SDK in PATH. Each run builds the native kernel twice,
compares exact ELF bytes, boots only its own 128MiB/one-CPU QEMU, captures serial
and interrupt traces, stops that QEMU through its own QMP socket, reads native
state and live registers, then closes its process. Positive acceptance additionally requires a stopped HLT=1/IF=1 sample within the nm-derived dedicated idle function and actual management stack range; bounded resume/stop retries retain every sample. Input/source/tool identities
and every compiler/linker command are retained in the output.

The positive fixture uses four separately loaded CPL3 address spaces with real
FS-relative canary loads at four distinct nonzero virtual FS bases. All four tasks sleep, leaving a genuine empty
runqueue, then timer wake restores their private TLS and existing file offsets.
All four then retire via fixture-owned trusted action4 cleanup. No after-retire
user instruction may execute. Timers continue while all PCBs are reapable and
all TCBs exited; scheduler ACTIVE remains true, COMPLETE/FAILED false. The
owned fixture's original-codec/common-file operations use the existing native
store. This is scoped hardware architecture evidence, not a lowered original
application or a Linux process ABI claim.

`--negative-case N` selects a trusted test fixture at build time, never an
application flag or production syscall. Cases 1–10 and 18–20 append the exact captured
`scheduler_test_hooks.oc.inc` fragment to an exact captured production scheduler
prefix. The fragment is deliberately not a standalone O-core module and is
never part of a normal kernel build. It constructs invalid trusted-native state
for: reentry, foreign pending serial, changed syscall number, IRQ-vector frame,
forged idle with a current task, pointer-valued idle, failed next-context install,
wrong scheduling frame, invalid disposition and exhausted serial. Each must
reach its exact independent stopped-state failure oracle; compiler/linker
failures do not count as passing negatives. Cases 11–15 use the unmodified
production scheduler: wrong GS, wrong FS, wrong stack, native-personality
configuration and no-policy idle consumption. Admission rejection must preserve
all measured hardware state and keep policy disabled. Case 16 performs a real syscall from an invalid user RSP and requires containment plus surviving CPL3 timer progress; case 17 performs a real user MOVGS and requires rejection before that syscall is dispatched. Case 18 constructs prior-dispatch history and requires effect-free admission rejection. Cases 19–20 supply a wrong live CR3 or TSS/entry stack to actual entry, requiring rejection before frame capture or a follow-on dispatcher effect.

Only the declared serialized one-CPU x86-64 PIT wake path is qualified here.
Async user MOVGS followed by IRQ/context switch does not yet have isolated GS-selector preservation; that lane remains unmet, separately from syscall-entry rejection. General fault cleanup, NMI/SMI policy, SMP, other ISAs, arbitrary management
relaunch, Linux60/231 cleanup/status policy, shared-mm/futex, complete drivers,
original libc/application admission and final interactive OS acceptance remain
separate work. Native resource retirement remains generation-aware and must
not be replaced by global store/service reset.
