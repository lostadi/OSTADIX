# O-core typed identities: compiler qualification

The compiler rejects crossed identity domains while transporting each wrapper
with its declared integer representation. Runtime owner, rights and liveness
checks remain necessary. This milestone also adds the three lifecycle owner
types and checks their constructors, layout and exhaustion behavior. O10 caller
migration, capability transfer, memory views and checked arrays have separate
qualification.

The retained receipts bind execution to the tested source files, compiler,
assembler/linker, runners, inputs and generated artifacts. The source was based
on `88fc0de62d1064025bf8e31abde68352d1f1d7c9` with the file identities recorded
in `focused-gates.json`; it was not yet a clean commit when executed.

- `qualification.json` records scope, counts and limitations.
- `native-equivalence.json` records actual native arithmetic, wrapper transport,
  trap and reproducibility checks on all three implemented ISAs.
- `wrapper-phi.json` records typed internal-call and merge execution.
- `lifecycle-identities.json` records 64 constructor/layout checks and two crossed
  domain compiler rejections per ISA.
- `focused-gates.json` records commands, statuses and the unchanged compiler
  source closure.

AArch64 and RV64GC ran under user-mode QEMU. These results do not establish
physical hardware, SMP, or full-system guest replacement. Assembly, objects,
executables and complete logs are retained in the run archive; the receipts
identify those artifacts by SHA-256. The commands in each receipt are the exact
commands executed. Repeated runs require fresh output directories.
