# One O-core service system with Linux compatibility

This plan follows the [consolidated user requirements](/home/ustad/okernel-unified-requirements.md),
which govern the architecture and acceptance criteria. Historical guest builds
and packaging records below retain their experimental scope.

The target is one protected O-core system with Plan 9 namespace/service
semantics, POSIX and required Linux ABI compatibility, familiar Linux
interfaces, original Linux drivers and original package managers.
Shared native services own the objects and resources. ABI adaptation translates
calling conventions and required semantics without duplicating whole operating
systems as the completed design. Original application/runtime implementations
remain the source of application behavior.

The existing concurrent Linux/9front profile is a preserved compatibility
experiment. Its supervision, namespace exchange and recovery results remain
valid within their recorded scope. Running those two complete kernels is not
the completed merge and does not establish an efficiency improvement. A
supplied executable running beneath O-core is also distinct from its
implementation being lowered through O-core.

Existing live systems and evidence remain intact. The preserved experiment
uses an additive ARM64 EL2 execution profile and private test states. Its
qualification remains QEMU/TCG; physical X12 boot and foreign compiler/runtime
lowering through O-core are separate work.

## Interface and authority contract

Linux supplies the main operator interface and the driver environment. Normal
Linux programs and original Plan 9 programs are used from that interface;
`p9 NAME` reaches the original Plan 9 execution provider. Selecting its raw
console is an optional diagnostic facility, not a required second user session.

O-core retains authority over execution and resource boundaries: CPU scheduling,
guest memory, interrupts, device/DMA grants and native service sessions. Linux
drivers consume their granted interfaces; they do not acquire the native
store's memory or another provider's resources by choosing a pathname. The
shared native 9P namespace is the common object/service backend. Original
Plan 9 and POSIX interfaces must resolve to those same governed services. The
experiment currently supplies the original Plan 9 ABI with a complete 9front
kernel; replacing that kernel requires an actual native loader/personality.

Original rc background jobs create separate note groups. The failed resident
tests `runtime-1` and `runtime-2` retain a real delayed-write escape; completing
their command cases did not establish descendant cleanup. The preserved
provider's source-compiled hello/tool closure remains separately qualified.

The experimental coordinator requires whole owning-domain replacement on
timeout, cancellation or unknown completion. The resident freezes capture,
publishes request-bound recovery evidence and stops accepting work. Trusted
native control withdraws Plan 9, revokes its transport, discards its private
RAM and architectural/interrupt state, and starts a fresh service instance.
The coordinator validates its new ready marker and an exact Linux-private
recovery acknowledgement before exposing interrupted completion or accepting
new work. The current coordinator generation stays fixed while the instance
changes; restarting the coordinator also changes its generation. Unknown
requests are never automatically retried. Recovery does not undo effects
already committed to shared services. Existing actual cancellation evidence
includes a detached child released only after domain replacement; the private
userland timeout-stop checks alone do not qualify that boundary.

Every timeout leaves normal command completion and the full effect set
uncertain. A validated timed-out capture remains known interruption evidence
with exact hashes; the existing `interrupted` acknowledgement does not assert
normal completion. Missing or invalid capture uses `unknown` with null
completion hashes. Both require domain discard and forbid automatic replay.
A finer native job boundary needs unescapable kernel-owned membership across
every fork/rfork/exec, atomic spawn withdrawal, whole-job termination/reaping
and resource revocation. No such primitive is currently qualified for the
original provider. Domain ownership is its accepted recovery boundary.

A separate actual timeout gate now passes for that same recovery boundary.
The original rc child and foreground parent write witnesses before timeout;
the service reports timeout without cancellation. The native coordinator
replaces Plan 9 and receives a request-bound private acknowledgement, then
publishes the child's release. The forbidden write remains absent while a new
original provider command succeeds and the same Linux PID/start time survives.
The retained evidence and replay preflight are under
`~/.local/state/ostadix/okernel/plan9-timeout-domain-recycle-20261103-xeq88n9w/`.
Independent review validates the binary transactions and before/after native
snapshots. Numeric Linux counter progression was asserted by the harness; its
intermediate numeric pair was not independently retained. This test does not
newly qualify CLI exit 124, paired save/restart, original-engine lowering or the
completed native OS. Existing failed resident receipts remain failed.

For future hardware profiles, Linux driver services must receive explicit
device grants and expose governed services through this namespace. The current
QEMU profile qualifies mediated virtual devices. It does not place the physical
X12's host Linux Mint system under O-core authority.

The final `.O` entry point must open a persistent interactive terminal or
desktop. Automated boot/lifecycle validation is a separately identified test
operation. The preserved Mode26 `.O` and the current guest launchers remain
experimental artifacts rather than that final entry point.

Linux, Plan 9-compatible and native commands must resolve their working
directory and services through the common namespace, with correct pipelines,
standard streams, errors, exit status, cancellation and authority. Normal use
must not require manual VM selection or exporting/importing files between
systems. Service replacement must invalidate that service's stale handles
while other clients remain usable; restart must restore a consistent package
and shared-service state.

The common service model does not require encoding a 9P message for every
local call. A direct native path may use the same governed objects, authority
and lifecycle semantics; a wire path serves actual execution or network
boundaries. Correctness equivalence must be verified before comparing or
substituting these paths. A local fast path must not introduce a second
authoritative filesystem or bypass checks to obtain a favorable benchmark.

## Source compilation and component selection

Original Linux and Plan 9 source may be compiled into the native O-core
system wherever required. O-core remains the common execution/resource
nucleus. Reused implementations become services, libraries, drivers or ABI
providers with explicit native interfaces and complete dependency closures.
Compiling and stacking two whole kernels is not the selected final design.

| Part | Source reuse decision | Present evidence |
|---|---|---|
| Common execution and authority | Retain O-core scheduling, address spaces, capabilities, IPC and governed native objects | Existing native primitives; protected POSIX/application integration remains unfinished |
| Plan 9 wire and metadata libraries | Reuse the original u9fs codecs and their original musl memory/string dependencies | Four codec units plus three dependency units are genuinely lowered for the qualified x86-64/AArch64 profiles; this is not the full server, libc or Plan 9 kernel |
| Plan 9 namespaces and file services | Reuse appropriate original namespace/fileserver/library implementations, with O-core authority and object lifetimes at the platform boundary | The current common store/file adapter is native O-core platform code; broader original Plan 9 implementation lowering remains unqualified |
| Linux interface and utilities | Capture the complete configured original shell/core-tool application and libc profiles using their build metadata | Original basic BusyBox CAT now has a source/build reference with 16 passing Linux behavior cases; native O-core application admission remains blocked |
| Runtime and Linux ABI | Reuse original libc/loader/helper source; bind real O-core process, memory, file, IPC and device services | A fresh complete original x86-64 static source build is recorded; full O-core capture/admission still rejects required assembly and unclassified producer events. Assembly/TLS/helper and OS-interface closure remain unfinished |
| Original package managers | Start with an original APK source/build/dependency profile, then qualify other original managers independently | Guest APK works; no complete native manager profile is admitted |
| Linux drivers | Select a real driver/configuration from its original Kbuild graph, including required Linux kernel APIs and generated metadata | Current virtual devices use drivers inside Linux; standalone driver reuse remains unqualified |
| Original Plan 9 programs and tools | Preserve original implementations and capture their `mk`/compiler/library graphs; provide the required native ABI/frontend bindings | Existing `7c`/`7l`/`mk` builds are original 9front compilation, explicitly not O-core lowering |

The first source/application lane is the original file utility and its runtime
closure over the native file service, followed by the real shell/terminal and
original package-manager profiles. Driver selection starts by measuring the
actual original dependency graph, not assuming one driver C file is independent
of its kernel. A required large dependency closure must be reported and
governed, not replaced by dummy functions or described as a lightweight service
without measurement.

The compiler-owned route is:

1. Pin the upstream source/configuration and retain its complete evaluated
   Make/Kbuild/`mk` graph, generated headers and producer invocations.
2. Use the existing implementation-language frontend and authentic target ABI.
   Capture every required source/object, including initializers, cold members,
   assembly, globals, relocations and compiler helpers.
3. Import complete supported units into O-core, verify them and resolve every
   required dependency and explicit platform interface. Unsupported units stop
   admission; declarations, source bodies and semantics are not dropped.
4. Link only the verified included native/IR/OIR closure. Reference frontend
   objects or embedded executable bytes do not substitute for implementation
   lowering. OIR orchestration and verified native O-core modules remain
   distinct, explicitly connected artifacts.
5. Qualify observable behavior and platform operations against the original
   implementation for each declared ISA/profile. Reproducibility and efficiency
   receive their own evidence.
6. For a reused compiler, qualify both its implementation and the route taken
   by programs it generates. Compiling the compiler alone does not establish
   that its generated code passes through O-core.

The existing `olangc --native-runtime` route,
[`ocore_runtime_capture.py`](../scripts/ocore_runtime_capture.py),
[`ocore_llvm_import.py`](../scripts/ocore_llvm_import.py) and the
[original u9fs component builder](../tools/ocore-runtime/u9fs/build_native.py)
provide the current capture/import/verification/dependency/emission pattern.
The full [musl recipes](../tools/ocore-runtime/libc/README.md) describe a broader
source graph but do not establish complete runtime or native platform support.
Their historical full-capture receipt under
`~/.cache/ostadix-runtime-captures/original-musl-0784374d-20261010/`
is absent on this device. The pinned source used by the codec component is
available. A fresh x86-64 run at
`~/.cache/okernel-musl-source-current-soc9clfn/` completed every configured
upstream build and header-install step, with 1,350 original source units and
1,345 ordered `libc.a` members verified against the evaluated graph. Its
generic capture still returns failure: required architecture assembly and 56
unclassified frontend/probe events prevent complete admission. These events
remain recorded; no source or producer was silently excluded. The strict
inventory helper now accepts exactly the retained and updated worker digests;
all three recipes bind that helper. Both versions reproduce all 1,345 archive
member names and hashes. The source worker now preserves original GNU map
arguments with immutable map snapshots and uses independent LLD traces;
15 real-linker tests pass. The current compiler binary still embeds the older
worker and was not replaced. This is source-build/capture evidence, not full
libc lowering or execution. One existing Cargo-parent error was reproduced on
the unchanged old worker; the other 61 existing checks passed with no skips.

Plan 9-specific C, assembly and object formats require a verified producer and
import binding where the current frontend route does not support them. A
successful original `mk` build or an ordinary Linux-C frontend invocation must
not be assumed to preserve the complete Plan 9 source/ABI semantics. Likewise,
an ordinary Linux Kbuild kernel image is source-built but is not thereby an
O-core-lowered driver or kernel. Manual runtime replacements, generated O-core
text staging and bundled original binaries do not satisfy source lowering.

The pinned original
[9front ARM64 compiler](https://raw.githubusercontent.com/9front/9front/350266104f1fed81c78c3d05fa44f523bec0ae4d/sys/src/cmd/7c/gc.h)
declares 32-bit `long` with 64-bit pointers and `vlong`. Its
[types and varargs header](https://raw.githubusercontent.com/9front/9front/350266104f1fed81c78c3d05fa44f523bec0ae4d/arm64/include/u.h)
therefore cannot be treated as the qualified Unix u9fs component's LP64 ABI.
Native structures, calling conventions, varargs and syscall interfaces require
their own original producer and explicit binding; a shared ISA or wire format
does not establish their equivalence.

POSIX compatibility alone does not establish support for arbitrary Linux
binaries, Linux kernel drivers, or distro package managers. User-space Linux
ABI requirements and driver/kernel API requirements must each be implemented
and qualified. The main interface must retain familiar Linux shell/terminal
behavior and its required PTY, job-control, signal and filesystem interfaces;
graphical programs additionally need their real display/input service closure.

## Original package managers

The target retains the original package managers and their complete declared
dependency closures. O-core supplies governed services beneath them. Signature
verification, trusted keys, dependency resolution, architecture/version rules,
conflicts, provider selection, database handling and declared installation
scripts/triggers remain the original manager's behavior. A wrapper may route a
name to its declared environment; it must not replace the resolver or weaken
signature/dependency checks to make installation appear successful.

Each repository ecosystem needs its own qualified manager/runtime environment.
For example, APK, APT/dpkg and RPM-based environments cannot be assumed
interchangeable or installed into a shared package database. Their governed
namespace views may share services and workspace objects while preserving
their original runtime, database and payload ownership rules. Supporting one
ecosystem does not qualify another.

The preserved experiment really runs original APK inside Linux. The `pkg`
helper dispatches to that manager or an explicitly registered source recipe.
The private APT/GNU ABI capture downloads and extracts a fixed authenticated
dependency closure without installing an Ubuntu system or running maintainer
scripts. Neither result establishes native O-core package-manager execution.
No complete source-native APK/APT/dpkg manager profile is currently admitted.

The first native manager gate uses a pinned original APK build and the same
trusted keys and signed offline repository snapshots on Linux and the O-core
candidate. It must install a package by name with nontrivial dependencies,
execute the installed program, verify database/world and payload metadata plus
script effects, upgrade/remove, and preserve the results across restart.
Tampered indexes/packages, wrong keys, and unsatisfied/conflicting dependencies
must produce the original manager's expected failures and state effects.
Online HTTPS behavior is qualified separately. Other managers receive the same
standard through their own original engines, not a custom format extractor.

The archived [original APK acceptance proposal](acceptance/original-apk/PROPOSAL.md)
specifies 13 unexecuted cases, including one direct `apk add jq curl`
transaction and an observable effect from the unchanged original BusyBox
trigger. A genuine signed two-version upgrade pair and a genuine dependency
conflict remain mandatory missing fixtures. The [snapshot record](acceptance/original-apk/capture.json)
pins the received plan and manifests, including their updated hashes and two
changed documentation/progress references that need refreshing before an
execution manifest is frozen. Byte checks here do not reverify signatures;
native APK execution, durability and efficiency remain unqualified.

The separate [source-compilation contract](acceptance/apk-source/PROPOSAL.md)
retains the original APK/libapk, crypto-provider, script and helper closure
requirements. The retained dynamic musl 1.2.6 profile cannot use the existing
static musl 1.2.5 recipe as matching provenance. Its [snapshot record](acceptance/apk-source/capture.json)
maps six recorded hook/doc differences to this integration base and notes the
newer, still-incomplete 1.2.5 source capture. Authentic upstream sources, distro
patches/configuration, the whole evaluated build graph and separately bound
reference/O-core outputs remain required. This source gate preserves the
same-binary ABI gate above; no runnable APK source recipe or native manager
profile is admitted.

Required native services include real user-memory/syscall layouts, ELF startup,
TLS/allocation, writable filesystem metadata and links, permissions, locks,
open-file lifetimes, replacement/commit behavior, subprocesses, signals,
clocks/entropy and the necessary network services. Installation scripts may
require additional Linux interfaces; a silent no-op is not an implementation.
The complete configured source/build/dependency graph and representative
behavior qualify this boundary; traces alone cannot prove completeness.

## Native implementation work

The existing x86-64 O-core process/address-space/scheduler/IPC path is the
starting point for protected native applications. Its Linux personality
currently handles a bounded write/exit corpus. It is not a POSIX implementation.
The AArch64 G2 EL0 path likewise remains a fixed-principal scaffold.

The next application-facing service is a general regular-file adapter over
the common native namespace: `openat`, `read`, `write`, `lseek`, `fstat` and
`close`, with process/namespace/service-generation checked descriptor and
open-description lifetimes. User memory transfers must use the existing
bounded memory-view/IPC ownership checks. File behavior belongs to the common
service; it must not become another canned file responder or parallel VFS.
POSIX open-file lifetime, atomic replacement, interruption, offsets and durable
commit semantics need explicit implementation and qualification.

The first implemented component is
[`posix_namespace_files.oc`](../ocore/runtime/common/posix_namespace_files.oc).
It supplies `open_read`, chunked binary `read`, `lseek`, native metadata
`fstat`, and `close` over the same object store and original lowered u9fs
codecs. An independent 9P client creates and mutates the tested files. Owner,
namespace-key and generation checks isolate descriptor tables; guarded native
session claims preserve another frontend's ownership. Native session tokens
are monotonic and survive volume reinitialization without reuse.

This component handles trusted native buffers and requires serialization over
each whole public operation. Namespace IDs identify descriptor contexts; they
are not per-process rooted namespace capabilities. Current resource quotas are
eight lifetime context pairs and eight descriptors per context. It is read-only
and has no user-memory/EL0 syscall boundary, application startup, writes,
`dup`, POSIX open-unlink lifetime or durable `fsync` implementation. It is not
linked into the preserved dual-kernel profile, whose Linux frontend already
owns native role 1.

The additive x86-64
[`posix_file_syscalls.oc`](../ocore/runtime/x86_64/posix_file_syscalls.oc)
component derives its file context from the real current process and address
space. Trusted provisioning binds namespace and generation; syscall arguments
cannot select another process's authority. It copies NUL-terminated absolute
paths and staged read results through the existing checked user-memory API.
Bad destinations do not advance the file offset; a later fault returns only
completed chunks and restores the failing chunk's offset. A faulting copy may
have partially touched that chunk's user buffer. Reads, seeks and closes use
the common service, while missing full Linux `stat`, cwd and writable semantics
return explicit unsupported results.

The native fixture links the production process, capability, page, mapping,
address-space, file and original-codec implementations. Its five architecture
imports provide host CR3 addresses and fault-injectable copy primitives.
This exercises kernel-side policy and state, including real process and
address-space generation reuse; it does not switch hardware page tables or
enter a protected user process. The dispatcher is not installed in the default
kernel profile.

The existing [ELF loader](../ocore/runtime/x86_64/elf_loader.oc) also has an
explicit trusted-native startup configuration. It copies arguments,
environment, executable name, platform-supplied credentials and 16 supplied
random bytes into an aligned user stack. Auxiliary program-header pointers
appear only when the validated image actually maps the complete table.
Invalid configuration preserves the previous stack, and lifecycle teardown
clears configured data. Its native fixture enters a small fixture ELF on that
stack; this is startup ABI evidence, not an unchanged upstream application.
The legacy empty startup remains supported. Static ET_EXEC, the existing load
window and 16 KiB stack remain the declared profile; dynamic loading, runtime
TLS construction and an exec syscall are unfinished. The new per-plan images
and scratch add 80 KiB
of static storage; no whole-system efficiency benefit is claimed.

The separate
[`native-posix-files-x86_64` acceptance profile](../ocore/kernel/native_posix_files/README.md)
now exercises these components through the real architectural syscall entry,
user-copy assembly and four private loaded CPL3 address spaces. The controlled
fixture checks copied startup data, binary reads, descriptor isolation,
unprovisioned denial, invalid pointers, context withdrawal and reprovisioning.
It uses a reserved RAM volume through a temporary supervisor-only RW/NX mapping
which is closed before user or scheduler return. This is an explicit masked,
synchronous one-CPU platform adaptation, not a general memory-service API.

The first run exposed a real mismatch: checked copies allowed the static ELF
image range, but assembly page-fault recovery admitted only the bootstrap
range. The narrow boot fix retains the exact instruction, direction and
CPU-local-operation checks while admitting both declared ranges and rejecting
the gap. QEMU's actual CPL0 page-fault trace and independent QMP reads confirm
recovery, the completed four-principal state and no residual volume mapping.
Two kernel builds match with the same frozen seven-object codec closure; all
nine original bootstrap fault/recovery validators still pass. This is a
protected fixture qualification, not unchanged upstream application admission,
full POSIX or an interactive OS. Arbitrary mmap recovery remains unsupported.

The additive
[`native-thread-fs-x86_64` profile](../ocore/kernel/native_tls/README.md)
now qualifies per-thread FS selector/base preservation across actual CPL3
syscalls, yields and timer preemption. Architectural entry captures the user
state before clearing kernel FS; user return restores the selected TCB's state.
The `arch_prctl` SET/GET FS adapter checks current process/address-space identity
and copies results through the checked user-memory API. TCB teardown clears
the state. It does not grant access to an address merely by selecting a base.

Independent review found that a user can legally load all RPL variants of the
existing readable DPL3 GDT descriptors. The original whitelist halted on
`FS=0x18`; that failing hardware replay is retained. The corrected kernel passes
all eight legal variants in each of four private address spaces, with actual
timer observations, independent QMP state reads and interrupt traces. Two
builds match exactly. Final-source regression also passes the nine original
bootstrap fault/recovery probes and three hosted native registry/file/startup
tests. These results are recorded under
`~/.cache/okernel-native-tls-selectors-green-20261103/` and
`~/.cache/okernel-final-fs-regressions-p2owmy87/`.

This remains a one-CPU, four-level-paging profile with FSGSBASE and LA57 off.
The adapter supports FS SET/GET only; syscall 218 remains unsupported. Original
runtime TLS construction, real TID/clear-child-TID/exit behavior, general memory
and process services, and complete application admission remain unfinished.
The controlled fixtures do not qualify general floating-point/SIMD context
management or full original runtime execution.

The host controllers also now select short private QMP socket paths when a
session path would exceed the AF_UNIX byte limit. Session logs and snapshots
remain in the requested state directory. Real socket and controller-failure
tests cover long Unicode paths and owned cleanup. Existing running controllers
and frozen runtime bundles were not restarted or rewritten; future bundles
must capture these updated controller sources explicitly.

One complete unchanged upstream application profile must exercise that path.
The initial Linux `busybox cat` traces record real startup and file-I/O
behavior on synthetic binary files. They are requirements evidence, not an
O-core application admission or proof of complete syscall coverage. Loader
arguments/auxv, allocation, TLS and other required startup services must be
implemented before claiming the application works natively. A handwritten
replacement for the application does not satisfy that gate.

The original basic BusyBox CAT static profile now has a separate source/build
capture lane under `tools/ocore-runtime/busybox/`. The immutable R4 reference at
`~/.cache/okernel-busybox-cat-reference-20261103-r4/` passes 16 Linux behavior
cases and retains all 137 C and five assembly producer units, archive/link
inputs and generated-header provenance. The basic CAT profile explicitly
disables CATN/CATV and binds its original static link at the native load window.
Its private release-import commit is not an upstream Git revision; source
archive identity is checked, while signature trust remains unverified.
This is a reproducible reference profile, with native admission flags false.
Original musl's startup requires per-thread
FS/TLS, TID and exit behavior; its x86 `open` uses syscall 2, now routed through
the same checked file implementation as `openat`. Output and diagnostic paths
also require `write`/`writev`. Long errors reach allocation and the complete
`vfprintf` implementation, so their dependencies remain required even when a
short successful copy uses only stack buffers.

Actual whole-unit importer attempts are retained at
`~/.cache/okernel-musl-required-unit-admission-gjx38sxe/result.json`.
They reject original `crt1` module assembly, `vfprintf`'s strict-floating-point
attribute and `__init_tls`'s external-weak `_DYNAMIC` linkage. These are the
observed first rejections, not an exhaustive feature census. Required
architecture assembly, floating-point/long-double semantics, compiler startup
and helper providers, and native operating-system services still need complete
admission. Neither source branches nor map flags are removed to make the
reference profile appear lowered.

The original u9fs/musl codec dependency component is genuinely lowered and
can be reused for wire boundaries. It does not constitute full libc, POSIX,
Plan 9 ABI or Linux driver support. The full original musl recipes retain
assembly, TLS, helper and OS-interface closure obligations. Driver reuse needs
an admitted original driver/dependency closure and explicit O-core MMIO, IRQ,
DMA, allocator and wait interfaces; the experiment's complete Linux kernel
does not establish that native boundary.

Running a supplied original ELF through a native Linux ABI and lowering its
implementation through O-core remain separately reported qualifications. Both
must preserve the original program's observable semantics; supplied binaries,
headers or captured source files alone do not establish implementation lowering.

## Efficiency acceptance

Efficiency is measured separately from architectural correctness. Comparisons
must use the same ISA, CPU/execution mode, protection policy, features, inputs,
cache state and durability contract. An x86 host run and an ARM TCG guest run
cannot establish a system speedup. A RAM store and ext4 durable `fsync` are
different services and cannot be treated as equivalent file-I/O measurements.

| Area | Required measurements |
|---|---|
| Memory | Total kernel, driver, service and application resident/allocated memory; shared physical pages counted once; peak and idle values |
| Startup | OS entry to usable interface, application admission to first output and exit/reap; separate cold and warm runs |
| Files | Correctness-checked metadata, 4 KiB/64 KiB/larger transfers, copies and IPC wakeups; identical persistence semantics |
| Processes and IPC | Creation/exec/exit/reap, pipes, request/reply, cancellation and service restart; checked results, copies, transitions and wakeups |
| Applications | Complete original file application, shell pipeline and source-build workloads; exact inputs/outputs, tool identities and dependency profile |
| Package managers | Original resolution/authentication/unpacking/scripts/commit workloads, installed-program execution and restart persistence; identical initial databases, repository bytes, trust policy and helper closures |

Retain individual samples, repetitions, p50/p95, measurement overhead and
regressions. A component benchmark or per-child RSS is useful diagnostic data,
but cannot stand in for total-system memory or boot measurements. Missing
services, mismatched conditions or missing candidate measurements leave
efficiency unqualified. Removing a kernel or an adapter is a hypothesis until
the matched measurements show the benefit without hiding lost functionality.
Package-manager comparisons must also match repository latency, dependency
versions and features, initial database/cache state and durable commit policy.
Kernel, drivers, services, manager and helper processes all contribute to the
memory total; a missing subsystem cannot be counted as an optimization.

The Linux-side collectors can be repeated into new evidence directories:

```sh
python3 scripts/benchmark_okernel_linux_baseline.py \
  --output "$HOME/.cache/okernel-linux-baseline-next" --repetitions 7
python3 scripts/trace_okernel_posix_baseline.py \
  --output "$HOME/.local/state/ostadix/okernel/posix-application-baseline-next"
```

The timing collector reports file-workload internal time separately from its
Python process startup and hashing overhead. Its `wait4` peak includes fork
and launcher effects; the observed Python launch floor is recorded and is not
subtracted or presented as application steady-state RAM. The trace collector
records unchanged installed BusyBox behavior, not source-built application
admission. Both leave candidate/whole-system efficiency claims unqualified.

## Ownership

- Root: `unified_world.oc`, additive build/profile/DTBs, unified host runner,
  console dispatch integration and end-to-end acceptance.
- `boot_program_audit`: new `ocore/kernel/aarch64/unified_world/monitor.S` and
  linker script, complete virtual CPU context, stage-2 banks and preemption.
- `console_usability`: new `unified_gic.oc` and production tests; per-domain
  GICv3 emulation and hardware list-register injection.
- `repro_audit`: independent memory/interrupt/namespace isolation review and
  focused validation, with new test ownership agreed separately.
- Support thread `01a19c43-52c3-77a1-abe6-b209f40a3529`: new original Plan 9
  userland/command service under `ocore/guest/plan9/unified/`, original-tool
  packaging, `scripts/build_okernel_plan9_userland.py` and focused new tests.
  The support thread also owns isolated native backend proposals and their
  regressions; root reviews and integrates validated changes against the current
  source identities. Live systems are outside that independent patch workspace.

Support coordination uses `codex queue --thread THREAD --message TEXT --resume`.
The first task was queued as `01a19d30-8bff-7c42-9767-8612d9e2340a`.
No existing monitor, probe, setup, provider recipe or saved head is overwritten
as part of initial implementation. All agents share this working tree.

The earlier session-token, Linux baseline and application-trace lanes have
returned their validated work. Root owns current native architecture and
integration. The original-CAT capture, per-thread FS and linker-map agents have
also returned ownership; coordinate before changing their shared files.
The independent support thread retains its original Plan 9 provider lane.
New dual-kernel packaging is stopped. Live experiments and their saved states
remain preserved while the native design is developed.

One small common-driver adapter is required: Linux UART interrupt delivery now
uses `kw_uart_irq_level`, like the existing block/network/9P IRQ hooks. The old
assembly profile supplies the same physical IRQ33 behavior; the new profile
supplies Linux's private virtual IRQ33. This source refactor does not replace
any previously built artifact or live state and requires a private old-profile
regression run.

## Preserved experiment: physical memory contract

Outer QEMU RAM is 3 GiB beginning at `0x40000000`.

| Resource | Guest IPA | Native physical interval |
|---|---|---|
| Linux RAM | `0x40000000..0x60000000` | `0x48000000..0x68000000` |
| Plan 9 RAM | `0x40000000..0x60000000` | `0xb0000000..0xd0000000` |
| Native shared store | not guest mapped | `0x6c000000..0x6d000000` |
| Native control words/console rings | not guest mapped | `0x6d000000..0x6e000000` |
| Governed NIC private DMA | not guest mapped | `0x6e000000..0x6e200000` |
| Linux package disk | block interface only | `0x70000000..0xb0000000` |

The monitor, its stacks and stage-2 tables occupy native low RAM below the
Linux physical interval. VMIDs are 1 and 2. No common guest-RAM mapping or
direct native store pointer is granted to either guest.

Both guests see mediated GICv3 distributor/redistributor windows. There is no
direct physical controller mapping or LPI/ITS table DMA grant. Linux already
has `CONFIG_ARM_GIC_V3=y`; its DTB must select the GICv3 profile explicitly.

## Assembly and dispatcher contract

`uw_init() -> 1` initializes the native services and provisions both domains
using `uw_domain_init(domain, pc, x0, pstate)`:

| Domain | ID | Entry | Initial x0 | PSTATE |
|---|---|---|---|---|
| Linux | 0 | `0x40000000` | `0x47e00000` | `0x3c5` |
| Original Plan 9 | 1 | `0x40100000` | `0x40000000` | `0x3c5` |

`uw_handle_exit(frame, reason, esr, far, hpfar)` returns the next domain ID;
values outside 0/1 stop execution. Reason 0 denotes a lower-EL synchronous
exception; reason 1 denotes a physical interrupt. The frame begins with
`x0..x30`, guest PC, and PSTATE. Assembly saves all remaining architectural
state before calling O-core and restores the selected bank afterward.

Context includes SP_EL0/SP_EL1, translation/control/exception/TLS registers,
SIMD q0..q31 plus FPCR/FPSR, physical/virtual timer state, and GIC virtualization
registers. EL2 handlers keep interrupts masked throughout native transactions.
An EL2 physical timer (PPI 26) provides preemption even during CPU-bound guest
execution; a guest WFI also yields. Physical guest timer PPIs 27/30 remain
masked in the native controller; saved timer expiry drives virtual interrupts.

The GIC hooks operate on **saved context banks**, avoiding an update to live
list registers being overwritten by the subsequent context restore:

```text
uw_current_domain()
uw_counter_read(), uw_counter_frequency()
uw_irq_ack(), uw_irq_eoi(id)
uw_timer_pending(domain, kind)        # kind 0: CNTV, 1: CNTP
uw_vgic_lr_count()
uw_vgic_lr_read(domain, index), uw_vgic_lr_write(domain, index, value)
uw_vgic_vmcr_read(domain), uw_vgic_vmcr_write(domain, value)
uw_vgic_hcr_read(domain), uw_vgic_hcr_write(domain, value)
```

Native IRQ callbacks select a domain explicitly: Linux UART 33, block 48,
network 49 and namespace 50; Plan 9 console 33 and namespace UART 50. Neither
guest can enable or reprogram native controller interrupts through a guest
MMIO write. Native preemption and other guests' pending/active state are not
guest resources.

## Common objects and command services

Initialize the native store exactly once per system epoch. Linux virtio-9P and
Plan 9 UART-9P retain distinct trusted grants and session generations; resetting
one transport must preserve the other's fids and authority. Existing production
transport tests cover this interleaving, but do not themselves boot two kernels.

Linux uses native grant 1 and original Plan 9 uses native grant 4. The support
fix for their earlier shared-grant collision was integrated before the R9
build and is included in the frozen R9b runtime. The retained support patch
describes that historical correction; its older store copy lacks subsequent
original-compiler DMTMP compatibility and must not replace the current store.

The original Plan 9 service executes original programs inside the original
kernel, with declared cwd, stdin, stdout, stderr and exit status. Requests and
completion records bind a fresh provider generation and request ID. Stale
requests must not automatically execute after restart. Text metadata is not
native capability authority; the initial operator/service policy must be
explicit. Source/compiler engines are preserved and their dependency closure
and build provenance recorded.

Large original tool/source closures must have a governed provider backing;
the common native volume remains 16 MiB and 1,024 objects. Measured capacity
failures must preserve the existing committed store.

## Preserved experiment: live acceptance

1. Boot both original kernels within one QEMU instance and one O-core monitor.
2. Show timer-driven progress of both domains while one runs a CPU-bound task.
3. Maintain separate RAM, translation, timer, interrupt and transport state.
4. Run original Linux and original Plan 9 commands through one foreground
   terminal with real input and streaming output; distinguish automated typing
   from a separately observed human acceptance session.
5. Compile and execute source using the appropriate original provider tools.
6. Exchange exact binary data through the common native object store, including
   rename/truncate and transport restart isolation.
7. Preserve installed tools and newly created shared files across a coordinated
   disk/store save and actual system restart, with new ephemeral sessions.
8. Contain a provider failure, reject stale service requests and retain the
   surviving provider's namespace and command access.

Source presence, host fixtures, preloaded console commands and older component
proofs must be reported as such until this live acceptance succeeds.
