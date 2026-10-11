# Original LLVM libunwind source capture

These recipes build the unchanged LLVM libunwind implementation from the Rust LLVM fork at commit `dcc3606807c989700e0ac1cac18c31741bcd40d9`. They retain the complete configured static-archive source graph, including both original assembly files. This is source-build and capture evidence; no recipe establishes complete O-core provider lowering, full Rust runtime support, dependency closure, or native OSTADIX execution.

The declared ELF64 baremetal profile enables assertions, frame registration APIs and native architecture context, with cross-unwinding disabled. Each ISA has a required `threaded` recipe and a separately named `single_threaded_test` recipe. The latter disables locking explicitly and cannot qualify the required full Rust threaded profile. Shared output is disabled; `LIBUNWIND_SHARED_OUTPUT_NAME=unwind-shared-unbuilt` gives the upstream excluded shared target a distinct filename because CMake's Generic platform otherwise converts that target to static and collides with the genuine `libunwind.a` output. The original static target and source implementation remain unchanged.

RISC-V uses `-march=rv64gc -mabi=lp64d`; the original header confirms XLEN64, FLEN64, the double-float ABI, a 64-word context and a 76-word cursor. x86-64 context/cursor sizes are 21/33 words; AArch64 sizes are 67/79. Original save/restore assembly retains floating registers, assembler loops, directives and relocations. Preprocessing is evidence of the original source input, not an assembly importer. Every C source keeps upstream `-std=c99 -fexceptions`; upstream C++ flags, PIC, visibility and architecture-dependent bodies are preserved.

`build_inventory.py` matches each ordered archive object input from the actual Ninja graph to exactly one original compile command. It keeps all compile rows, source hashes, dependency occurrences with their object owners, generated headers, original preprocessed assembly, archive member names/order/content hashes, raw tool output and configuration provenance. `complete:true` in its unit inventory refers only to enumeration of that configured source graph. Missing objects, required assembly lowering and other completion gaps remain separate explicit issues. The original archive objects are reference build outputs and are never admitted as O-core implementations.

Build prerequisites are CMake, Ninja, a matching scoped LLVM/Clang 22.1.6 SDK, a clean complete checkout at the pinned commit, and authentic target-compatible C headers. The current diagnostic header input is Ubuntu's `libnewlib-dev` 4.6.0.20260123-1, SHA-256 `5c90e34938803a087deba5f79417076a71193e4d60c451a26211abbf24190ab9`. Its release signature, signed package/source records, original source archives and exact extracted header bytes are retained and checked. These headers do not constitute a source-built libc or a native platform interface. No invented POSIX macros or pthread typedefs are supplied.

With authenticated header receipts prepared, use a new empty source-build and capture directory. Snapshot the recipe and helper before starting:

```bash
export UNWIND_SOURCE=/path/to/pinned/llvm-project
export UNWIND_SDK=/path/to/LLVM-22.1.6-Linux-X64
export OCORE_LIBUNWIND_HEADER_PROVENANCE=/path/to/header-provenance.json
export OCORE_LIBUNWIND_HEADER_SOURCE_PROVENANCE=/path/to/header-source-provenance.json
export PATH="$UNWIND_SDK/bin:$PATH"
export UNWIND_RUN=/path/to/new/riscv64-threaded-capture
mkdir -p "$UNWIND_RUN/recipe"
cp tools/ocore-runtime/unwind/build_inventory.py "$UNWIND_RUN/recipe/"
cp tools/ocore-runtime/unwind/riscv64.threaded.recipe.json "$UNWIND_RUN/recipe/"
chmod a-w "$UNWIND_RUN/recipe/"*
python3 scripts/ocore_runtime_capture.py capture \
  "$UNWIND_RUN/recipe/riscv64.threaded.recipe.json" \
  --source "$UNWIND_SOURCE" --build "$UNWIND_RUN/build" \
  --output "$UNWIND_RUN/capture" --cc "$UNWIND_SDK/bin/clang" \
  --cxx "$UNWIND_SDK/bin/clang++" --llvm-nm "$UNWIND_SDK/bin/llvm-nm" \
  --unit-inventory "$UNWIND_RUN/build/unit-inventory.json" --jobs 2
```

Use the correspondingly named x86-64/AArch64 recipes for their own fresh frontends; never retarget an existing LLVM module by editing its triple or DataLayout. SDK compatibility libraries may require the installation's recorded `LD_LIBRARY_PATH`. A recipe failure is preserved with the original upstream status. The build uses Ninja `-k0` so independent required source units are still attempted after another source fails. The post-build inventory uses separate evidence paths; a failed build can receive a new independent post-failure inventory without rewriting its capture journal or original report.

On 2026-10-10, all three genuine threaded builds attempted the complete nine-source graph and failed in original `RWMutex.hpp:72` because the generic Newlib profile has no `pthread_rwlock_t`. Each produced eight native reference objects, including both assembly objects, but no complete archive. The separate single-thread test builds all succeeded upstream: nine ordered archive members from seven C/C++ sources and two assembly sources. Each capture retains 55 LLVM units, including seven complete original provider C/C++ units and 48 configure units; captures remain incomplete because the required assembly importers are absent, configure roles remain unclassified, and one configure linker trace is unsupported. The original seven provider units retain 82/85/84 function definitions for x86-64/AArch64/RV64GC respectively. These counts describe whole source inputs, not a runtime acceptance percentage.

The immutable observation is `original-libunwind-dcc36068-20261010/whole-source-build-observation-v1.json` under the runtime capture cache, SHA-256 `721bf9443cceeab31d3d4706e525cd0cbfef2a251d258abc93abd52c538e2074`. It binds actual commands, logs, original source and LLVM units, preprocessed assembly, contexts and complete configured inventories. Independent symbol receipts resolve intra-archive references before retaining external requirements: memory/allocation, environment, abort/assertion, stdio and Newlib's `_impure_ptr`, plus `__eh_frame_{start,end}` and `__eh_frame_hdr_{start,end}` platform bounds. Full native Rust additionally needs genuine thread/TLS services, panic/personality support, frame discovery, dynamic registration/JIT publication and the complete compiled provider dependency closure. The existing hosted Rust GNU `gcc_s` selection has not been replaced by these test profiles.

`threaded-provider-candidate.json` records a separately inspected original musl 1.2.5 source candidate at commit `0784374d561435f7c787a555aeab8ede699ed298`, with hashes of the actual header generation, rwlock, thread and TLS sources. Its original pthread declarations and per-architecture generated `bits/alltypes.h` can supply a genuine coherent header ABI for a future declared profile. Its implementation also depends on Linux-oriented futex/clone/memory mapping/signals/time and architecture thread-pointer services. Those services need an explicit OSTADIX platform contract and the complete original compiled libc closure. No musl library was built or substituted, and no GNU or Newlib profile was relabeled. Mixing existing Newlib stdio/assertion objects with a musl provider would violate the source ABI.

Run the inventory regression gate with:

```bash
python3 -m unittest discover -s tools/ocore-runtime/unwind -p 'test_*.py' -v
```

Primary source contracts are the pinned upstream [source list and C exception flags](https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/libunwind/src/CMakeLists.txt), [profile options](https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/libunwind/CMakeLists.txt), [original context layout](https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/libunwind/include/__libunwind_config.h), [locking implementation](https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/libunwind/src/RWMutex.hpp), and the [Itanium exception ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).
