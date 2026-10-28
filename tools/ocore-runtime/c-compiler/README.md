# Original C compiler capture and C program execution

`chibicc.recipe.json` captures the unchanged original compiler from
<https://github.com/rui314/chibicc> at revision
`90d1f7f199cc55b13c7fdb5839d1409806633fdb`. The default stage-one Make graph
contains nine whole C translation units and 75 tracked source/data files.
Upstream tests and self-hosted stage-two builds are separate configurations.

Importing the compiler implementation and compiling a C program through
Clang LLVM IR are separate gates. The original chibicc backend emits x86-64
assembly; its output does not automatically pass through O-core.

## Capture the original compiler

Use a clean checkout at the exact revision above, matching Clang/LLVM 22.1.6
tools, and a new output directory. Capture does not fetch or rewrite source.
The original VPATH Make route requires separate source/build/capture paths
without whitespace or Make metacharacters.

```bash
olangc tools/ocore-runtime/c-compiler/chibicc.recipe.json --native-runtime \
  --native-runtime-source /absolute/clean/chibicc \
  --native-runtime-cc /absolute/llvm22/bin/clang \
  --native-runtime-cxx /absolute/llvm22/bin/clang++ \
  --native-runtime-llvm-nm /absolute/llvm22/bin/llvm-nm \
  --native-runtime-llvm-dis /absolute/llvm22/bin/llvm-dis \
  --native-runtime-jobs 2 --native-isa riscv64-unknown-none \
  --native-runtime-output obj \
  --llvm-library /absolute/llvm22/libLLVM.so.22.1 \
  --llvm-sha256 ACTUAL_VALIDATED_LIBRARY_SHA256 \
  -o /absolute/new/chibicc-product
```

The helper evaluates original Make variables in the source directory and
preserves the complete source/object lists in the separate empty build. It
records every Make producer and checks actual frontend arguments, source and
object hashes, the final driver link, and its connected actual linker child
records. The capture worker independently rechecks native linker/provider
evidence. Cached objects, missing units, changed source or arguments,
disconnected children, and replaced output bytes fail the inventory.

The nine units are `codegen.c`, `hashmap.c`, `main.c`, `parse.c`, `preprocess.c`,
`strings.c`, `tokenize.c`, `type.c`, and `unicode.c`. Retained outputs include
`build/native-build-plan.json`, `build/unit-inventory.json`, the original
reference `build/chibicc`, `capture/report.json`, `lowered/coverage.json`, and
`source-recipe.json`. Capture can succeed before the command fails a later
dependency or lowering gate; inspect the receipt flags and diagnostics.

## Audit every original unit

Create a source matrix with this profile:

```json
{
  "schema": "ocore-source-audit-matrix-v1",
  "profiles": [{
    "name": "c-chibicc", "language": "c",
    "capture": "/absolute/chibicc-product/capture/report.json",
    "step": "build-original-chibicc"
  }]
}
```

```bash
python3 scripts/check_ocore_source_matrix.py /absolute/matrix.json \
  --ocorec /absolute/bin/ocorec --target riscv64-unknown-none \
  --llvm-library /absolute/llvm22/libLLVM.so.22.1 \
  --llvm-sha256 ACTUAL_VALIDATED_LIBRARY_SHA256 --jobs 2 \
  --output /absolute/new/chibicc-audit
```

Matrix exit zero means the diagnostic audit completed. Read
`all_units_lowered` and verified-object counts to determine compiler coverage.
No declaration, function, or source body is removed to make a unit pass.

The completed 2026-10-18 RISC-V matrix audited all nine whole units from the
clean current capture. Every unit first failed import with
`variadic calling convention is unsupported`: zero imported modules,
independently verified modules, or O-core objects. The source route retained
`capture_complete=true` and stopped at unresolved provider closure. The
original reference compiler passed its `-S` smoke test; its generated x86-64
assembly remains reference output.

The [frozen evidence](../../../evidence/original_python_c_rust_expansion_20261018.json)
records the current capture report SHA-256
`d7883256853bb11b7de7b9023242df5047be4d9dfa171b7c78fa2b732a9c6bf0`,
installed `olangc`
`18b458ff49b2e12b005c90ebefad66340d411d0165ddd03c6a7455213b597a29`,
and embedded capture worker
`5a2d41eac94d024e7d9c3b7fbfe81c42a35d82c11e0c4a818d189a176c36136e`.
It also binds the source receipt and successful separate C-program execution
gate on the actual RV64 Linux host. These results leave original compiler
lowering and runtime/provider qualification incomplete.

## Execute a C program through O-core

The opt-in language gate uses the same unchanged C fixture for a Clang
reference object and LLVM IR. Its pointer, stack storage, loop, and non-inlined
call pass through whole-module import and O-core assembly/object emission.
An artifact-bound descriptive map is independently verified. The reference
and owned objects are linked to the same static Linux syscall harness and
must actually execute with positive and negative inputs on the current host.

```bash
OCORE_TEST_C_NATIVE=1 \
OCORE_TEST_LLVM22_BIN=/absolute/llvm22/bin \
OCORE_TEST_LLVM_LIBRARY=/absolute/llvm22/libLLVM.so.22.1 \
OCORE_TEST_LLVM_SHA256=ACTUAL_VALIDATED_LIBRARY_SHA256 \
OCOREC=/absolute/bin/ocorec \
python3 -m unittest discover -s tools/ocore-runtime/c-compiler \
  -p test_c_native_program.py -v
```

Provide an ELF `ld.lld` on PATH or with `OCORE_TEST_LLD`. Set
`OCORE_C_NATIVE_OUTPUT` to an existing directory to retain exact source, IR,
owned assembly/object/map, executables, commands, and hashes. The gate supports
the current x86-64, AArch64, or RISC-V Linux host. These fixtures demonstrate
the C language route and are separate from original compiler evidence.

Run the nine lightweight synthetic inventory guards with:

```bash
python3 -m unittest discover -s tools/ocore-runtime/c-compiler \
  -p test_build_inventory.py -v
```

Dependency closure, original compiler lowering, its generated-code route,
self-hosting, other-ISA execution, and native OSTADIX kernel execution remain
separate qualifications. `runtime_complete` stays false.
