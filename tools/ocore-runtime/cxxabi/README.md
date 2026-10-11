# Original threaded C++ exception providers

These recipes capture the complete original LLVM compiler-rt builtins/CRT and
libc++abi source builds for x86-64, AArch64, and RV64GC Linux/musl profiles.
They prepare reference providers for testing imported EH code. Native source
builds do not establish O-core provider lowering, complete Rust compiler
support, dependency closure, or execution on the native OSTADIX kernel.

The source pin is the unchanged Rust LLVM fork commit
`dcc3606807c989700e0ac1cac18c31741bcd40d9`. The frontend is the authenticated
LLVM 22.1.6 SDK. Each ISA uses its own original frontend target and generated
LLVM inputs. RV64 keeps `-march=rv64gc -mabi=lp64d`, including the original
floating-point register context. Existing GNU, Generic/Newlib, and separate
Linux/musl provider captures remain distinct and unchanged.

## Complete compiler-rt prerequisite

The dedicated upstream `compiler-rt/lib/builtins` CMake project builds its
complete configured `builtins` and `crt` targets. Atomic builtins remain
enabled; default floating-point/complex helpers, architecture assembly, and
generated AArch64 outline-atomic variants remain required. The inventory
combines `compile_commands.json` with all evaluated Ninja compiler commands:
upstream custom CRT producers and generated source producers are included.
Original source bytes, source-generator commands, frontend arguments, object
producers, complete archive membership/order, generated headers, and native
outputs remain recorded. Phony output aliases do not become extra physical
archive roots.

The original source builds completed on all three ISAs. The immutable receipt
is `original-compiler-rt-dcc36068-20261010/whole-source-build-observation-v1.json`
under the runtime capture cache, SHA-256
`e8df897cccfafd452e11e459956eaad2eea158424858e4a769a7cf49d0917518`.

| ISA | Required source occurrences | Original assembly occurrences | Builtins archive members | CRT outputs |
| --- | ---: | ---: | ---: | ---: |
| x86-64 | 176 | 3 | 174 | 2 |
| AArch64 | 290 | 128 | 288 | 2 |
| RV64GC | 162 | 3 | 160 | 2 |

RV64's original `clear_cache.c` requires `<linux/unistd.h>`. Its separate
successful profile retains authenticated Linux UAPI headers from
`linux-libc-dev-riscv64-cross` version `7.0.0-13.13cross1`, package SHA-256
`47ecf11a8e6d4d09ee7dccc1cb83de8d2a424b4e0cd7e5e325b8dea7aa6f701e`,
with `Built-Using: linux (= 7.0.0-13.13)`. The scoped package receipt records
all 1,013 installed headers. Original package headers are input evidence;
reproducing their Linux source-generation closure remains a separate gate.
The earlier missing-header build remains intact.

Every mandatory assembly unit remains an explicit missing O-core importer
requirement. Configure LLVM units also remain unclassified evidence. Capture
and whole-provider lowering therefore remain incomplete despite successful
source builds and whole native archives.

## Complete libc++abi recipe

The runtimes project configures original `libunwind;libcxxabi;libcxx` to obtain
authentic configured libc++ headers. The selected library retains all 18
original libc++abi translation units, including personality, demangling,
RTTI, allocation, exception storage, vector operations, static guards, and
thread-exit support. Threads, TLS, exceptions, RTTI, new/delete, assertions,
and the normal terminate handlers remain enabled.

Original source-built musl supplies headers, libc, startup, pthread and TLS
interfaces. The frozen complete original threaded LLVM libunwind archive is a
separate dependency. Full compiler-rt builtins and its genuine `crtbegin` and
`crtend` supply compiler helpers and initialization/finalization support.
Fresh symlink overlays preserve these input bytes without changing existing
provider builds. Original source object hashes are checked against their
captured producer outputs; prerequisite inventory digests are pinned in each
recipe.

Libc++abi uses **executable** CMake feature probes. Archive-only probes could
incorrectly classify unresolved functions as available. Genuine musl lacks
`__cxa_thread_atexit_impl`; the original upstream weak-symbol/TLS-destructor
fallback must remain selected. The recipe never forces that feature on or
disables threads to avoid it. The original compiler-rt bootstrap's own
archive-only checks remain isolated from these runtime probes.

The recipe builds every original `cxxabi_static_objects` source and
`generate-cxx-headers`, then executes the exact original final archive command
obtained from the hashed Ninja graph. This avoids rebuilding the already
frozen separate unwinder while preserving every original libc++abi object and
archive member order. Configured libc++ headers do not establish that the
compiled libc++ standard library bodies have been captured or lowered.

The carrier profile is static, non-PIE Linux/musl with `--eh-frame-hdr` and
genuine startup/CRT objects. Linker selection uses ordinary `-fuse-ld=lld` so
the capture worker records the genuine SDK linker as the original provider
and instruments the actual invocation. An earlier recipe pointed directly
at its linker wrapper and recursively selected that wrapper; those raw
unfinished configure records remain preserved, with no source-build success
claim. Fresh corrected builds use separate directories and receipts.

The corrected `*-threaded-v3` source builds completed all six declared steps
on every ISA. Each produced all 18 original objects and 18 ordered archive
members, verified 3,161 dependency occurrences, and generated all 1,679
configured headers. The immutable
`whole-threaded-source-build-observation-v1.json` receipt has SHA-256
`8d8129dd993780cd29fce50f51c585c6629116dee30f27a0feae8ffd3acec609`.
Each source capture retains 18 production LLVM modules and 64 configure
modules. Unclassified configure modules and an original configure linker
trace conflict keep capture admission incomplete.

A separate same-source native reference program passed on x86-64 and under
the scoped AArch64/RV64 QEMU Linux carriers. It exercised global initialization,
512 exception cleanups, 256 catch/rethrow pairs, two pthread TLS destructors,
and one concurrent static initialization guard; every run produced exactly
`37 512 256 256 2 1` and exited zero. The reference receipt SHA-256 is
`184ee2c0f5a572e2b1f88f851cbc00b771f90ae2b5353a7dba31014719ba20a4`.
These runs validate original native source-provider behavior for this carrier
profile. They do not validate O-core-generated EH, 64-bit CIE/LSDA encoding,
whole original Rust compiler lowering, or the native OSTADIX platform.

Before capture, set `OCORE_LIBUNWIND_MUSL_PROVENANCE` to the exact matching
original musl target-header receipt, `OCORE_COMPILER_RT_SDK` to the scoped
SDK, `OCORE_CXXABI_UNWIND_INVENTORY` to the complete matching original
threaded-unwind inventory, and `OCORE_CXXABI_COMPILER_RT_INVENTORY` to the
complete matching original compiler-rt inventory. Copy each recipe's pinned
helper dependencies into its immutable recipe directory. Then run:

```bash
python3 scripts/ocore_runtime_capture.py validate \
  tools/ocore-runtime/cxxabi/x86_64.libcxxabi.recipe.json
python3 scripts/ocore_runtime_capture.py capture RECIPE_SNAPSHOT \
  --source ORIGINAL_LLVM_SOURCE --build NEW_BUILD --output NEW_CAPTURE \
  --cc SCOPED_SDK/bin/clang --cxx SCOPED_SDK/bin/clang++ \
  --llvm-nm SCOPED_SDK/bin/llvm-nm \
  --unit-inventory NEW_BUILD/unit-inventory.json --jobs 2
python3 -m unittest discover -s tools/ocore-runtime/cxxabi -p 'test*.py' -v
```

Use the matching AArch64 or RV64 recipe for those targets. Preserve original
failed attempts and raw journals; corrections require fresh recipe snapshots
and capture directories. No supplied native provider object is admitted as
an O-core implementation by these tools.

The pinned primary sources define the
[full compiler-rt target source sets and CRT](https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/compiler-rt/lib/builtins/CMakeLists.txt),
[libc++abi source and archive graph](https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/libcxxabi/src/CMakeLists.txt),
and [original thread-exit fallback](https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/libcxxabi/src/cxa_thread_atexit.cpp).
