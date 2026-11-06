# Original-source Linux syscall component

The compiler's opt-in `--linux-syscall-profile linux-user-raw-v1` preserves
supported original LLVM inline syscall implementations as a typed, ordered
Linux-compatible **userspace** ABI operation. It supports the seven raw arities
on x86-64, AArch64 and RV64 LP64D. It does not implement Linux kernel services.

The `*.getuid.recipe.json` recipes build the complete unchanged musl 1.2.5
`src/unistd/getuid.c` unit at revision
`0784374d561435f7c787a555aeab8ede699ed298`. The pinned helper evaluates the
original Makefile's libc object graph and invokes that Makefile for its declared
`getuid.o` component, including original generated headers. Its explicit
component configuration is separate from the full-library configured capture.
Reference objects are build evidence; the delivered objects come from O-core.
The helper never rewrites upstream source or removes flags from a captured
invocation to gain admission.

With a separately built compiler and matching pinned LLVM 22.1.6 tools selected:

```sh
olangc tools/ocore-runtime/linux-syscall/x86_64.getuid.recipe.json \
  --native-runtime --native-isa x86_64-unknown-none \
  --native-runtime-source /absolute/path/to/pinned/musl \
  --native-runtime-output obj --native-runtime-jobs 2 \
  --linux-syscall-profile linux-user-raw-v1 \
  --llvm-library /absolute/path/to/libLLVM.so.22.1 \
  --llvm-sha256 EXPECTED_PARSER_SHA256 -o /absolute/new/output
```

The realization is explicitly selected and versioned. Default imports and the
old `integer_only_v1` strict-FP profile retain their existing boundaries. The
new `integer_linux_syscall_v1` admits only the separately audited integer,
pointer and raw-syscall realization. Source assembly bytes, constraints, fixed
registers, call attributes, operands and contextual typed `srcloc` tuples remain
in a source witness. The emitter writes owned `syscall`, `svc #0` or `ecall`
instructions; it does not copy source assembly into executable output. Unknown
forms and unsupported attributes fail closed. No syscall-number whitelist or
number translation is introduced.

The verifier derives required platform interfaces independently of ordinary ELF
undefined symbols. Object notes, source/coverage receipts, module sets and
fresh-source readmission preserve the requirement even when ordinary C symbol
closure is complete. The normative contract is a Linux-compatible user process,
with `user_mode_only` placement; it does not mandate one kernel implementation.
A future native O-core provider would need to qualify the required compatible
semantics, resources, process/context and lifecycle before binding it. Current
native monitor/kernel admission rejects these requirements. The scalar native
interpreter and pure `.O` leaf also refuse this effect before execution.

Supported scalar callsite `range` attributes use a separate typed source
witness. The importer obtains the actual owner, argument/result slot, integer
type and attribute kind from the pinned LLVM C API. The complete call printer
supplies candidate endpoint bits only: reconstruction with the public
constant-range constructor in that same context must return the exact original
attribute handle. An independent source reader repeats this proof. Numeric
kind IDs are never a source contract.

Endpoints retain their unsigned, width-specific lower-inclusive/upper-exclusive
modular representation, including wrapping ranges and the empty `0,0` form.
Other equal endpoints and unsupported storage, slots or types are refused
before the constructor or native operand access. Outside-range source values
are poison; preserving the witness does not establish that callers satisfy
its precondition. It does not narrow the raw syscall ABI, optimize the call,
infer purity or discharge the Linux-compatible userspace requirement. Source
schema V2 is used exactly when the constant-range vector is nonempty; legacy
V1 packets and enum-only attributes keep their prior canonical bytes. Full
fresh-source equality includes the complete typed range vector.

The unchanged original musl `_Exit` unit is a source-compilation witness for
the sign-extended `i32` range on both original raw syscall calls. Its source,
loop and flags are preserved. Separately authored range-bearing LLVM fixtures
exercise all seven arities, result/argument association, defined memory effects
and floating-point environment preservation. These fixtures are not original
musl source or a replacement libc implementation.

Execution tests bind their actual external Linux kernel, static Clang test
driver/bootstrap and guarded foreign-ISA emulator separately. They preserve raw
results, errors, file/memory effects and defined FP control/sticky state. Those
external facilities are **not** lowered original implementation closure. The
arity wrappers are authored tests using unchanged original syscall headers;
they are distinct from the unchanged `getuid` component.

This component does not qualify every Linux syscall, all inline assembly, the
60 original standalone assembly units, TLS/gettid lowering, full libc or CRT,
ABI-compatible native kernel services, i686/ARMv7, a physical hardware driver
set, a complete OS, or whole-system efficiency. Full original captures and
unsupported whole-unit results remain visible; a capability census does not
admit a failed runtime capture.
