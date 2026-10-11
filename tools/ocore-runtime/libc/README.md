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

Primary source contracts are the pinned original [Makefile](https://git.musl-libc.org/cgit/musl/tree/Makefile?id=0784374d561435f7c787a555aeab8ede699ed298), [configure script](https://git.musl-libc.org/cgit/musl/tree/configure?id=0784374d561435f7c787a555aeab8ede699ed298), [pthread declarations](https://git.musl-libc.org/cgit/musl/tree/include/pthread.h?id=0784374d561435f7c787a555aeab8ede699ed298), [generated type inputs](https://git.musl-libc.org/cgit/musl/tree/include/alltypes.h.in?id=0784374d561435f7c787a555aeab8ede699ed298), and [thread creation implementation](https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_create.c?id=0784374d561435f7c787a555aeab8ede699ed298).
