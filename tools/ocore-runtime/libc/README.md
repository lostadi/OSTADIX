# Original musl source capture

These independently declared Linux-compatible static profiles capture the unchanged complete configured musl 1.2.5 implementation at commit `0784374d561435f7c787a555aeab8ede699ed298`. They retain libc, libm, pthread, TLS, allocation, stdio, startup objects, architecture assembly, compatibility archives and every configured upstream compiler-driver tool. They do not replace existing GNU or Generic/Newlib profiles. Source-build success does not establish O-core implementation lowering, full Rust compiler execution, or native OSTADIX platform support.

Each ISA receives a genuine Clang/LLVM 22.1.6 source frontend: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, or `riscv64-unknown-linux-musl`. RV64GC uses `-march=rv64gc -mabi=lp64d`; original floating-point math, register context and helpers remain requirements. The recipes select the original `--enable-static --disable-shared` profile and build upstream `make all`. No libc, pthread, TLS or math source is rewritten or disabled. The separately declared static profile alone cannot qualify the dynamic loader, JIT publication or complete Rust native dependency profile.

The original configure script chooses optimization, math, assembler, allocator and helper-library settings. The controlled driver selects scoped lld explicitly. `-Qunused-arguments` is supplied before configure's compile-only probes so the linker-selection flag does not corrupt flag detection; upstream also selects that diagnostic flag later for Clang. No `LIBCC` empty override, fast-math flag, source-body filter, host-header typedef substitution, or LLVM triple/DataLayout rewrite is used. Original `LIBCC` decisions and actual archive symbol providers remain dependency evidence, not admission of supplied compiler-helper objects.

`build_inventory.py` queries the complete evaluated original GNU Make graph and records the expanded source, replacement, startup, output, header and archive lists. It binds every planned compiler output to an original source and exact argv, including cold members and architecture overrides. Before building, `make --dry-run all` establishes the entire command plan. After building, each production frontend occurrence must match that plan exactly, and the full ordered `libc.a` member names and bytes must match the evaluated `AOBJS` graph. Generated `bits/alltypes.h`, `bits/syscall.h` and the source version header retain their original producer graph. No supplied native object is treated as an O-core implementation.

The 2026-10-10 original source builds completed every configured upstream `make all` output and `make install-headers` on all three targets. The complete evaluated graph produced these results:

| Target | Original source units | Ordered `libc.a` members | Whole C LLVM inputs | Required original assembly |
| --- | ---: | ---: | ---: | ---: |
| x86-64 | 1,350 | 1,345 | 1,318 | 32 |
| AArch64 | 1,350 | 1,345 | 1,334 | 16 |
| RV64GC LP64D | 1,351 | 1,346 | 1,339 | 12 |

Each graph also retains five startup objects and installs 218 original/generated target headers. Every source object passed ELF64 target-machine checks; RV objects retained LP64D flags. Archive member order and bytes, original source hashes, complete C LLVM input hashes, exact production invocation plans and generated-header provenance were verified. The immutable local receipt is `~/.cache/ostadix-runtime-captures/original-musl-0784374d-20261010/whole-source-build-observation-v1.json`, SHA-256 `f6df8192764741427588393d7386c6160ec92ee87b37c62edf633c0d667d3210`.

All three capture reports remain incomplete: original assembly is a required unsupported import, and configure probes still require independently verified role exclusions. Original `LIBCC` selection was `-lgcc -lgcc_eh` on x86-64 and empty on the two cross targets where the matching helper libraries were unavailable; no override supplied those decisions. Full-archive symbol receipts retain required complex arithmetic helpers on x86-64, additional quad-precision arithmetic/conversion/comparison helpers on AArch64/RV64GC, and linker-owned `_DYNAMIC` and init/fini boundary symbols. Their source ownership and final-link applicability remain unresolved closure obligations. These source builds do not qualify libc/TLS/thread execution or any O-core provider, runtime/compiler or OSTADIX execution profile.

On X12, the historical receipt path above is absent. A fresh x86-64 reproduction
is retained at `/home/ustad/.cache/okernel-musl-source-current-soc9clfn/`.
All seven configured recipe steps succeeded, including upstream `make all`,
ordered archive validation and header installation. The source remained clean;
the evaluated graph has 1,350 units (1,318 C and 32 assembly) and 1,345 ordered
`libc.a` members. The generic capture command still exits 1 with
`capture_complete: false`: required assembly and 56 unclassified frontend/probe
events prevent admission. This does not qualify original libc execution or
full O-core lowering. The failed preceding attempt is retained at
`/home/ustad/.cache/okernel-musl-source-before-9gbsub8u/`; it stopped at a stale
inventory-worker digest. That reproduction accepted exactly two pinned worker
versions: `a18a349afb994a8a3035209bc43f480cfeb399be4198022b29ef4d776cfc7779`
and `0f3cee8f19faa091281bc11033d20b18a6aad10915b07713cedc8a93a89de059`.
All three recipes bound the corresponding helper digest. Both workers were checked
against all 1,345 original archive member names and hashes; this preserves
compatibility with the existing compiler's embedded worker. Earlier receipts
and their qualification limits remain historical evidence.

The new source worker preserves upstream GNU linker-map arguments and captures
an immutable copy of the selected map; LLD uses independent dependency traces.
Fifteen real-linker tests compare executable bytes, map output, streams and exit
status with the original invocation. Unsupported map destinations still stop
complete capture without changing upstream behavior. The installed compiler
binary was not rebuilt: its embedded worker remains the older pinned version.
Using the updated standalone source worker and rebuilding a compiler that
embeds it are separate operations. This change does not admit original assembly
or resolve the unclassified producer events.

The earlier combined source also accepted the independently reviewed C-family stdin
capture worker, SHA-256
`758bec4a31a3384113d31f4517d2a9ef16ddbf6a1824dc071aace756433c7c36`.
That helper admitted only those three exact executable revisions, and every
recipe binds the exact updated helper bytes. A self-consistent session record
for any other worker is rejected before execution. Fourteen original-frontend
stdin cases cover byte fidelity and unsupported/ambiguous capture boundaries;
they do not qualify complete libc import. The older source-build counts and
failures above remain historical receipts, not a rerun with the merged compiler.

The current inventory helper also admits the exact reviewed capture worker
`303aac632cac6caff5179372811d98081e57eb98bfae34b43db9e1ecf90033b0`,
which preserves original compiler results while rejecting malformed or unbound
capture claims. All four revisions are explicit digest pins; a session cannot
select an arbitrary self-consistent worker. Every invocation in the three
static recipes binds the updated helper bytes. Loader and recipe regressions
cover current-worker loading, mutated/unknown worker refusal and stale helper
rejection before source configuration. This compatibility repair does not
rerun the full source builds, resolve assembly/probe/provider obligations or
qualify libc execution, complete O-core lowering or the native OS.

Prerequisites are GNU Make, a clean complete original source checkout at the pinned commit, the matching scoped LLVM 22.1.6 SDK and any installation-specific compatibility libraries. Headers come from the original source and its per-architecture Make generation; they require no manually supplied pthread definitions or POSIX ABI macros. A recipe and helper snapshot should be placed in a new empty directory before starting:

```bash
export MUSL_SOURCE=/path/to/pinned/musl
export MUSL_SDK=/path/to/LLVM-22.1.6-Linux-X64
export PATH="$MUSL_SDK/bin:$PATH"
export MUSL_RUN=/path/to/new/riscv64-musl-static-capture
mkdir -p "$MUSL_RUN/recipe"
cp tools/ocore-runtime/libc/build_inventory.py "$MUSL_RUN/recipe/"
cp tools/ocore-runtime/libc/riscv64.static.recipe.json "$MUSL_RUN/recipe/"
chmod a-w "$MUSL_RUN/recipe/"*
python3 scripts/ocore_runtime_capture.py capture \
  "$MUSL_RUN/recipe/riscv64.static.recipe.json" \
  --source "$MUSL_SOURCE" --build "$MUSL_RUN/build" \
  --output "$MUSL_RUN/capture" --cc "$MUSL_SDK/bin/clang" \
  --cxx "$MUSL_SDK/bin/clang++" --llvm-nm "$MUSL_SDK/bin/llvm-nm" \
  --unit-inventory "$MUSL_RUN/build/unit-inventory.json" --jobs 2
```

Use the correspondingly named x86-64/AArch64 recipes with fresh frontends. SDK compatibility libraries may require the installation's recorded `LD_LIBRARY_PATH`. Each helper invocation checks the digest bound by its recipe, and the generic capture worker retains its own immutable snapshot and event binding. The build uses Make `-k` so independent required sources are attempted after another source fails. The original upstream status, raw failures, journals and reports remain evidence; an independent later diagnostic never rewrites them.

The required source assembly, inline assembly, full floating-point/long-double operations, atomics and TLS accesses still need supported O-core import and emission. Linux-compatible syscall semantics—including futex, clone, memory mapping/protection, signals, clocks, thread pointer/TLS, cancellation, files, processes and networking—need compiled dependencies or explicit verified OSTADIX interfaces. Authentic headers alone do not implement those services. Configure probes remain unclassified provenance unless their roles and absence from every runtime output are independently verified. All engine, provider, dependency-closure and native OSTADIX qualification flags remain false.

Run the inventory regression gate with:

```bash
python3 -m unittest discover -s tools/ocore-runtime/libc -p 'test_*.py' -v
```

## Observed-copy foundation

`scripts/ocore_native_copy.py` is an experimental host observer for the original
regular-file `cp` operation. It records the exact argv, original exit or signal,
stable file identities, execution interval and captured bytes. Observation
failure does not skip, rewrite or retry the original operation. Its library
caller owns signal handling; a standalone wrapper explicitly opts into parent
signal relay and forwards the recorded native outcome after collecting evidence.
This is not a registered capture producer or an original runtime implementation.

An in-memory controller binding establishes that an observation was actually
made. A separate trusted `VerifiedProducerInventory` can identify an earlier
source producer; there is no JSON loader that promotes receipt fields to this
authority. These are trusted host interfaces, not authentication against arbitrary
host Python code. Selected executable hashes do not establish complete dynamic
loader or library provenance.

The distinction between an observed copy and output-source ownership matters.
Another writer can replace the destination after the original command exits but
before the observer reads it. Equal bytes, a successful real compiler and copy,
or a cooperative lock cannot prove which operation produced that inode.
`verify_observation` therefore always returns `source_owned: false`,
`destination_causality_qualified: false` and false output lowering/replay flags.
Any checked predecessor facts are reported separately. `verify_transfer` always
refuses until a registered owning controller enforces and verifies every writer
and output lifetime. No caller flag or self-consistent receipt enables it.

Run the self-contained component tests with:

```bash
python3 -m unittest -v tests.test_ocore_native_copy
```

The 46 cases use authored C/assembly fixtures compiled by the selected original
Clang, real `cp`, real signals and a destination-replacement race. They compare
bytes, statuses and streams, reject forged or mutated observations and retain
the missing ownership authority. Prerequisites are Linux, Python 3.10 or later,
Clang, GNU `cp`, `/proc`, `pidfd_open` and POSIX signals. Select tools through
`NATIVE_COPY_TEST_CLANG` and `NATIVE_COPY_TEST_CP`; set `NATIVE_COPY_TEST_OUTPUT`
to an existing private directory to retain fixture evidence. The selected tools
and inputs are recorded. This is host component execution, not O-core lowering,
an all-ISA test or a hermetic toolchain bootstrap. Current capture keeps file
bytes in memory; large-file streaming and broader host profiles remain unqualified.

The observer is not wired into the original musl recipes or independent runtime
admission. The five startup-copy ownership gaps therefore remain unresolved,
alongside required assembly, configure-role and LLVM replay obligations. A fresh
whole-source capture and independent verification are required after actual
producer integration; historical failed reports cannot be repaired with new text.

Primary source contracts are the pinned original [Makefile](https://git.musl-libc.org/cgit/musl/tree/Makefile?id=0784374d561435f7c787a555aeab8ede699ed298), [configure script](https://git.musl-libc.org/cgit/musl/tree/configure?id=0784374d561435f7c787a555aeab8ede699ed298), [pthread declarations](https://git.musl-libc.org/cgit/musl/tree/include/pthread.h?id=0784374d561435f7c787a555aeab8ede699ed298), [generated type inputs](https://git.musl-libc.org/cgit/musl/tree/include/alltypes.h.in?id=0784374d561435f7c787a555aeab8ede699ed298), and [thread creation implementation](https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_create.c?id=0784374d561435f7c787a555aeab8ede699ed298).
