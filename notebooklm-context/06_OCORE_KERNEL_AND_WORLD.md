# O-core, OKernel, O-Machine, and World

## O-core identity

O-core is Ostadix-lang's statically typed, freestanding systems language. Its
source extension is `.oc`. It is deliberately separate from hosted `.O`
orchestration: hosted Python, Nix, shell, JSON, subprocess, and OIR facilities
are not available inside freestanding O-core code.

Normative implementation specification: `docs/OCORE.md` (draft v0.1).

## Compiler pipeline

```text
.oc source
  -> lexer/parser
  -> AST
  -> name-resolved, typed HIR
  -> SSA MIR
  -> target assembly
  -> freestanding little-endian ELF64 object
```

`ocorec` accepts one or more source modules as one compilation unit. Current
output forms are AST, HIR, MIR, assembly, and object. The primary target is
`x86_64-unknown-none`; a bounded conservative scalar backend targets
`aarch64-unknown-none`.

Implementation: `crates/ostadix-api/src/ocore/` and `src/bin/ocorec.rs`.

## Language surface

Each source file begins with a module declaration and may import items:

```ocore
module kernel::serial;
use kernel::arch::outb;
```

Implemented item/control forms include functions, extern functions, structs,
enums, constants, mutable/static data, lexical locals, assignment,
conditionals, loops, break/continue, return, and explicit unsafe blocks.

Primitive types include booleans, signed/unsigned integers, pointer-sized
integers, `f32`, `f64`, `void`, and `never`. Compound forms include arrays,
raw pointers, structs, enums, and function-pointer types. The language uses an
LP64 layout. Struct layout is deterministic and declaration-ordered; packed
and explicit alignment attributes are supported. Enums are tagged unions.

Unsafe syntax is required for raw pointer conversions/arithmetic/dereference,
mutable statics, volatile/atomic access, hardware I/O, privileged intrinsics,
and inline assembly. Implemented operations include volatile scalar access,
integer atomics with checked memory orderings, x86 port I/O, interrupt control,
page invalidation, syscall stubs, halt/wait operations, and constrained inline
assembly.

Linkage attributes include export/no-mangle, section placement, alignment,
used, packed, interrupt, and naked-function forms under their documented
constraints.

Primary source: `docs/OCORE.md` sections 2-7.

## ABI and freestanding boundary

The x86_64 default foreign convention is System V AMD64. Scalar integer and
pointer arguments/results use the documented registers; aggregate call
boundaries currently use pointers. `extern "ocore"` is compiler-versioned and
is not a stable foreign ABI. The bounded AArch64 target uses scalar AAPCS64-like
placement for its O-core convention and rejects AMD64 `sysv64`.

Freestanding runtime code may not depend on libc, Rust `std`, a host allocator,
Python, Nix, JSON, environment variables, subprocesses, or a host filesystem.
The hosted compiler/test harness may use those tools, but they are not linked
into the kernel artifact.

## Current compiler limits

- no optimization pipeline or general register allocator;
- direct calls are lowered, but indirect calls through represented function
  pointer types are not;
- aggregate layout, construction, fields, indexing, statics, locals, and copy
  are supported, but aggregate parameters/returns cross current ABIs by pointer;
- enum construction exists, but general pattern matching does not;
- floating types have storage layouts and bit-preserving transport, while
  literals, arithmetic, comparisons, casts, and float ABI crossings are
  rejected;
- the AArch64 backend is a narrower scalar subset and rejects x86-specific
  port I/O, current atomics, inline assembly, interrupt/naked functions,
  floating point, and wider call shapes.

A successful object build is evidence for that target/compiler path, not a
claim of optimization, full language completeness, or hosted-language support
inside `.oc`.

## Native capability model

Kernel authority is a generation-tagged handle in a per-process capability
space, not a pointer and not an arbitrary serialized OCapability:

```text
handle = (generation << 32) | slot
```

Every capability syscall checks bounds, live state, generation, object kind,
and rights. Close and transfer operations have transactional lifecycle rules;
generation exhaustion retires rather than wraps. A hosted OCapability is useful
only when its opaque bearer resolves through a private live broker/session to a
kernel handle. Descriptive metadata, guessed identities, stale tokens, and
cross-session deserialization do not mint native authority.

Primary source: `docs/OCORE.md` section 9.

## OKernel bounded milestones

The `ocore/` tree contains the runtime modules, kernel sources, linker scripts,
boot glue, user images, World codecs, and positive/negative QEMU gates. The
implemented evidence is intentionally divided into bounded milestones rather
than one general-purpose operating-system claim.

Representative implemented gate families include:

- M0.x: CPL3 entry, syscall/interrupt return, W^X, faults, typed frame/memory
  lifecycle, and capability denials;
- M1: bounded two-process isolation and teardown on one CPU;
- M2: bounded four-TCB scheduler behavior on one CPU;
- M3: fixed-capacity endpoint IPC, block/wake, transfer-ticket, stale and
  failure-containment scenarios;
- M4: deterministic immutable OVFS loading and bounded static ELF lifecycle;
- M5: fixed-capacity native package/control/activation and one health-gated
  restart scenario;
- M6A/M6B: bounded unprivileged personality supervision, scalar RPC, and a
  request-scoped bounded-copy mechanism;
- Mode 25: one exact static Linux x86-64 ELF corpus with a tiny allowed syscall
  behavior, not a general Linux ABI;
- Mode 26: one bounded Linux/Plan-9-style 9P2000 data path;
- Mode 31: one bounded local LogicalRead provider-fallback scenario;
- Modes 20/22/23: KernelWorld manifest/object, lifecycle, and synthetic
  execution/device composition gates;
- Mode 34: exact four-vCPU QEMU AP startup/barrier probe, after which APs park;
  it does not make every subsystem SMP-safe.

The exact positive claims, tools, markers, and non-claims are data in
`evidence/gates.toml`. Prose should not broaden them.

## KernelWorld

KernelWorld is a strict manifest and lifecycle boundary for a contained foreign
kernel or driver world. A verified package and `ocore.kernel-world/v1` manifest
bind exact image, machine profile, integration style, health, quotas,
capability requests, services, and package content.

Current evidence separates distinct slices:

- Mode 20 verifies/adopts the record and creates generation-bound
  nonexecuting VM/vCPU/guest-page objects; it does not enter a guest.
- Mode 21 is a supplemental AMD SVM/NPT hardware-dependent gate requiring
  nested SVM and writable `/dev/kvm`; it is outside the 26 required portable
  set.
- Mode 22 exercises bounded administrative lifecycle and generation-safe
  restart/reclaim behavior without enforcing every future timeout/fault hook.
- Mode 23 executes a fixed synthetic guest through AMD SVM/NPT instructions
  under QEMU TCG and connects one virtual scalar PIO endpoint. It is not a real
  Linux/Plan 9 boot, KVM evidence, PCI/device assignment, DMA/IOMMU isolation,
  general guest agent, or physical reset.

The Alpha G7 “real KernelWorld” gate explicitly rejects Modes 21 and 23 as
substitutes for booting a pinned real kernel under the full governed contract.

Primary sources: `docs/KERNEL_WORLD_CONTRACT.md`, `docs/O_MACHINE_CONTRACT.md`,
and `evidence/world_alpha_gates.toml`.

## World record families

The repository implements bounded, architecture-independent Rust/O-core
conformance surfaces:

| Record | Scope | Key non-claim |
|---|---|---|
| `OWIDENT` V1 | Exact World identity atoms and stale/current comparisons | Serialized capability identities are descriptive, not bearers or CSpace handles. |
| `OWPROTO` V1 | Bounded canonical records and offline version/size negotiation | Not transport, a live handshake, authentication, membership, or consensus. |
| `OWVALUE` V1 | Explicit portable inert-value allowlist with hard size/depth/node bounds | Not the full hosted OValue enum and not the hosted canonical-CBOR shim wire format. |
| `OWRECEIPT` V1 | Bounded canonical receipt and signing-preimage convergence | Signature correctness does not establish authorization, current World state, Governor commit, or production key custody. |

These formats are separate. OWVALUE is not an extra OWPROTO kind, and none of
them grants authority merely by decoding successfully.

Mode 32 bridges one caller-signed, uncommitted hosted project receipt into a
native canonical/semantic comparison. O-core decodes/reencodes and checks the
signing preimage and semantic hash but does not execute the project natively or
perform a general native Ed25519 verification. The receipt remains
`Uncommitted`; it is not Governor admission or G1 passage.

Primary sources: `crates/ostadix-api/src/world/`, `ocore/world/`,
`tests/world_*.rs`, and the corresponding entries in `evidence/gates.toml`.

## O-Machine

O-Machine names the future/general architecture-resource and virtualization
contract between host O-core layers and contained worlds. Its contract covers
resource-class-specific allocation, mapping, revocation, acknowledgment,
interrupts, devices, DMA isolation, teardown, and guest-interface decisions.

Parts of the repository exercise bounded mechanisms that inform this contract,
but `docs/O_MACHINE_CONTRACT.md` is not itself evidence that G7/G8 device and
foreign-kernel requirements are implemented. A synthetic virtual endpoint,
guest page fault, KVM availability, or reset intent is not physical device
assignment or an IOMMU/SMMU proof.

## OSTADIX World constitution and Alpha gates

`docs/OSTADIX_WORLD.md` and `evidence/world_alpha_gates.toml` define a
qualification program with 14 dependency-ordered gates, G0 through G13:

```text
G0  constitutional baseline
G1  semantic continuity
G2  AArch64 native compiler
G3  multicore O-core
G4  native World transport
G5  replicated authority
G6  WorldFS
G7  real KernelWorld
G8  real driver service
G9  native Debian personality
G10 distributed execution
G11 accelerator fabric
G12 three-node native World
G13 eight-node OSTADIX Alpha
```

Each gate declares required evidence classes, dependencies, acceptance text,
and prohibited substitutes. Hosted reference behavior, local daemons,
synthetic guests, static Linux ELF slices, QEMU-only messages, or planner labels
cannot substitute for a gate that requires physical, multinode, governed, or
fault-injected evidence.

## Component gates versus Alpha qualification

`evidence/gates.toml` currently declares:

- 26 required portable component gates; and
- 1 supplemental hardware-dependent gate.

Those gates validate exact bounded compiler/kernel/codec scenarios. They are
not numerically or semantically equivalent to the G0-G13 qualification
registry. A successful 26-gate portable run therefore does not mean all Alpha
gates passed.

During creation of this context pack, invoking
`python3 scripts/world_alpha_evidence.py` did not produce a qualification
status: it failed because a referenced attribution-history source commit was
not available in this local Git object database. Consequently this pack makes
no fresh claim about the current derived G0-G13 status.

## Broad native non-claims

Unless a newer exact gate says otherwise, do not infer:

- a general Linux or Debian ABI/userland;
- general dynamically linked foreign binaries;
- a production package manager, shell, filesystem, network stack, or driver
  model;
- subsystem-wide SMP safety;
- a general foreign-kernel boot from synthetic guest probes;
- physical-machine, Secure Boot, measured boot, KVM, device, DMA, or IOMMU
  isolation from QEMU TCG;
- production key custody, trusted signer policy, Governor consensus, WorldFS,
  or native multinode World;
- transparent live migration, exactly-once external effects, or universal
  failure recovery.

Always cite the precise gate's `positive_claims` and `nonclaims` fields from
`evidence/gates.toml`.
