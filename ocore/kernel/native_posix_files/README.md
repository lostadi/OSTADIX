# Protected native regular-file probe

`native-posix-files-x86_64` is an isolated native O-core boundary test. It
reuses selector25's production boot, syscall router and personality scheduler
machinery with its own explicit probe and immutable fixture image. It is not
the historical Mode25 Linux corpus, a shell, an original application admission,
or the completed unified OS.

Run into a **new output directory**:

```sh
python3 -B ocore/kernel/native_posix_files/verify.py \
  --output "$HOME/.cache/native-posix-files-new" \
  --codec-manifest "$HOME/.cache/okernel-u9fs-native-recipe/runs/x86_64-O1-final/native-codec.json"
```

The default tool paths select the existing O-core compiler and the installed
QEMU11.1.3. Options allow explicit compiler/QEMU paths. The build validates and
copies the completed seven-object original u9fs/musl component closure. It
compiles the production kernel, real SYSCALL/IRET and fault-copy assembly,
plus a separately linked freestanding fixture ELF. No user fixture is linked
as kernel code. The root OVFS is structurally verified and digest-bound in
native loader admission. Native kernel/boot/platform objects are built twice;
the kernel ELFs must match exactly using the same frozen component objects.
This is not two fresh upstream compiler/source builds.

The harness starts and terminates only its owned QEMU process, with one CPU and
128MiB RAM. Existing consoles, VMs, saved heads, launchers, default kernel
artifacts and the preserved Mode26 `.O` are not used or modified.

## Actual protected operations

Four production process/TCB/CSpace identities have private loaded address
spaces at the same preferred executable address. Real CPL3 code verifies the
configured argv, environment and auxv before issuing native file calls through
the architectural syscall entry. The fixture checks binary12KiB reads,
independent descriptors, offsets/EOF, invalid and overflowing user pointers,
read-only output mappings, supervisor-volume pointers, explicit unsupported
calls, scoped context withdrawal and generation2 reprovisioning.

One unprovisioned principal first verifies authority denial, then deliberately
executes `UD2` in its designated slot. The existing production scheduler
contains that exact fault while the other three continue. Its inherited
four-principal/quiescence choreography is an explicit test requirement, not
arbitrary application fault containment or a generalized process lifecycle.

For one8192-byte read, trusted fixture control temporarily makes the second
user-data PTE non-present without changing the metadata permission check. The
real kernel copy primitive therefore incurs a CPL0 page fault. Its exact RIP,
vector, access-error bits and loaded-window CR2 are recorded independently in
QEMU's interrupt trace and bound to the actual assembly symbols. The copy
fixup returns failure; the file boundary restores the failed chunk's offset
and returns only the completed4096-byte prefix. The PTE is restored and the
remaining file data is read successfully. The private result counter is
inferred from that operation; the separate QEMU trace is the architectural
fault evidence.

## Linked writable files and shared open descriptions

The native common file provider now implements regular-file read/write access,
creation/exclusive creation, truncation and append through the same shared
store and original source-built u9fs codec. Kernel writes copy each user chunk
before changing the file; earlier acknowledged chunks remain the only reported
progress if a later copy fails. Read-only user mappings are valid write sources.
Access-mode errors are checked before user-memory access.

`dup` and `dup2` within this provider's reserved regular-file pool3–10 share
one native open description: offset, access/append flags and server fid.
Closing an alias keeps the description alive; its final close or process
withdrawal clunks the fid exactly once. Descriptors0–2 await composition with
the terminal/pipe provider and cannot be replaced by this component. Append
selects the current shared EOF and commits the offset only after positive
write acknowledgement, under complete-call serialization with all store
frontends. This is not SMP append synchronization.

The protected fixture additionally creates a distinct output file, writes and
reads12KiB binary data, shares offsets through aliases, closes the original
before using an alias, writes from read-only text, rejects supervisor/invalid
pointers, checks exclusive creation and observes truncation. Host component
regressions inject first/later copy failures and fill the actual shared volume
to verify ENOSPC partial progress. Those injected copy-from failures are not
additional architectural page-fault evidence; the original copy-to hardware
fault check remains independently retained.

These operations add no invented credentials or persistence. Trusted policy
supplies creation permission metadata; process umask, UID/GID checks and
close-on-exec are not implemented. Unlinked-open objects still report ESTALE
under the unchanged store contract. Linux `stat`, `fsync`, relative cwd/dirfd,
pipes and a complete POSIX ABI remain unsupported. No success is fabricated for
these operations.

## Explicit platform memory grant

The unchanged native volume format requires16MiB. This probe reserves physical
64–80MiB, outside the kernel,4–16MiB frame pool and declared user regions. A
private platform helper temporarily maps those pages supervisor-only RW/NX
while interrupts are masked, rejecting existing mappings and nesting. It
checks exact PDE identities, currentCR3 and masked flags, then clears every
entry and flushes the TLB before ordinary user/scheduler returns. Production
`loaded_protections_hold` passes before and after the operation; its rules are
not relaxed. An unrecoverable kernel fault halts instead of resuming a user
with an aperture open. This is a synchronous one-CPU probe adaptation, not an
SMP memory service, DMA policy or generic physical-memory allocation API.

The extra transient mappings, repeated validation and CR3/TLB flushes have
cost. No system-efficiency improvement follows from these tests.

## Retained qualification

- Before architectural fix: `/home/ustad/.cache/okernel-native-cpl3-build4-20261102/red-proof.json`.
  The actual copy write at RIP`0x101e78` faulted at CR2`0x02005000`, CPL0,
  error`0x2`, and halted because the inherited assembly fixup admitted only the
  earlier bootstrap user window.
- Passing current profile: `/home/ustad/.cache/okernel-native-cpl3-build5-20261102/result.json`.
  Both kernel builds match; all four fixture roles complete, the designated
  fault is contained, one actual loaded-window copy fault recovers, and the
  final transient aperture is absent. The native codec records79 exchanges.
- `/home/ustad/.cache/okernel-native-cpl3-build5-20261102/artifact-audit.json`
  verifies198 retained artifact/source references and confirms that the sole
  production-source change between red and green was the narrow boot assembly
  recovery-range fix. Verifier instrumentation also changed checksum timing
  and early-fatal reporting; the workload did not change.

The architectural fix now admits the union of the existing bootstrap and
existing static-loaded user windows, retaining the gap, exact copy-instruction,
direction and CPU-local-operation checks. It does not implement arbitrary
`mmap` recovery, signals or Linux process memory semantics.

Remaining work includes full file metadata, open-unlink/fsync and composed
stdio/pipe/exec descriptor semantics, a real exec input-copy and entropy/credential policy, complete
original application/libc lowering, drivers, package managers, native Plan9
ABI, persistent interactive packaging and matched whole-system measurements.
The fixture's private control operations must never be exposed as a finished
operating-system API.
