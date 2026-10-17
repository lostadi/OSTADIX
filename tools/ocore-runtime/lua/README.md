# Original Lua implementation capture

`full.recipe.json` captures the unchanged original Lua implementation at Git
commit `0b29f408433e92953cc72b1d3e06c7ac8139e439`. The upstream Linux Make
defaults retain the interpreter, compiler, allocator, garbage collector,
coroutines, every configured standard library, floating point, varargs,
setjmp/longjmp and dynamic module loading. No original C body is filtered,
rewritten or replaced by a native executable supplied from another compiler.

The build runs the original `makefile` with GNU Make `VPATH` in a separate empty
directory. Only the compiler and archive tool paths select capture wrappers.
The helper records all 111 tracked original source/data files, expands
`CORE_O`, `AUX_O`, `LIB_O`, `LUA_O` and `ALL_O`, and captures every dry-run C
producer. This pinned source has 34 whole C translation units, 33 archive
members and the `lua` executable. `ltests.c` remains in the original configured
graph even when its default preprocessor context makes its object empty.
The final inventory verifies actual frontend arguments, source/object hashes,
every required source occurrence, and the archive's complete ordered members
against the original plan. A native build cache cannot replace this evidence.

Use the matching Clang/LLVM 22.1.6 frontend and symbol tools required by the
existing capture/import boundary. The source checkout must be clean at the
pinned revision; the capture tool does not fetch or alter it. The runtime,
build and capture directories must be separate, and this upstream VPATH route
requires their paths to contain no whitespace or Make metacharacters.

## One compiler invocation

The compiler can own the original source build, capture, independent re-admission
and attempted O-core lowering from the recipe directly:

```bash
target/debug/olangc tools/ocore-runtime/lua/full.recipe.json --native-runtime \
  --native-runtime-source /absolute/clean/lua \
  --native-runtime-cc /absolute/llvm22/bin/clang \
  --native-runtime-cxx /absolute/llvm22/bin/clang++ \
  --native-runtime-llvm-nm /absolute/llvm22/bin/llvm-nm \
  --native-runtime-llvm-dis /absolute/llvm22/bin/llvm-dis \
  --native-runtime-jobs 2 \
  --native-isa riscv64-unknown-none --native-runtime-output obj \
  --llvm-library /absolute/matching/libLLVM.so.22.1 \
  --llvm-sha256 EXACT_LLVM_LIBRARY_SHA256 \
  -o /absolute/new/lua-source-build
```

Replace the tool/library paths and digest with the verified matching LLVM 22.1.6
SDK. Scope its archive/link tools on `PATH` and any required shared-library search
paths for that invocation. The new output directory must have an existing parent
and be outside the clean pinned checkout. The recipe generates
`build/unit-inventory.json`, which is the
driver's default inventory path.

The result retains `driver/`, the original `build/`, `capture/report.json`,
`capture.log` and `source-recipe.json`. A lowering attempt records
`lowered/coverage.json`; successful closure also writes
`lowered/runtime.native-ir.json`, with owned objects under `lowered/` when
requested. The summary distinguishes the capture worker's
report from independently admitted capture and completed native module closure.
The original `build/lua` executable is frontend-produced build/reference evidence;
O-core products belong under `lowered/`.

With the current unresolved dependency declarations, the command is expected to
retain the capture evidence and fail lowering until matching verified packages
are supplied through repeated `--native-runtime-dependency PATH` options. Supplying
those packages still requires every original Lua unit to pass the supported
whole-unit import and native backend gates. The existing floating-point, variadic
and computed-goto blockers below remain. This command does not establish a
complete Lua runtime, OIR bundle, `.O` execution or native engine adapter.

## Separate capture and lowering

The existing explicit capture, re-admission and lowering workflow remains available:

```bash
python3 scripts/ocore_runtime_capture.py capture \
  tools/ocore-runtime/lua/full.recipe.json \
  --source /absolute/clean/lua \
  --build /absolute/new/lua-build \
  --output /absolute/new/lua-capture \
  --cc /absolute/llvm22/bin/clang \
  --cxx /absolute/llvm22/bin/clang++ \
  --llvm-nm /absolute/llvm22/bin/llvm-nm \
  --unit-inventory /absolute/new/lua-build/unit-inventory.json --jobs 2

python3 scripts/ocore_runtime_capture.py verify-report \
  /absolute/new/lua-capture/report.json \
  --receipt /absolute/new/lua-capture-verification.json

target/debug/olangc /absolute/new/lua-capture/report.json --native-runtime \
  --native-isa riscv64-unknown-none --native-runtime-output obj \
  -o /absolute/new/lua-ocore-objects
```

These commands feed the captured original `.ll` units into the existing
whole-module LLVM importer, independent O-core verifier and owned ISA emitter.
Use a frontend targeting the requested ISA and preserve its original ABI and
DataLayout; this recipe does not retarget existing IR. Scope the matching SDK
archive/link tools on `PATH` as required by the generic capture workflow.
Unsupported constructs must reject an entire source unit. Partial successful
imports remain diagnostics rather than complete engine support.

The inventory's `complete` flag establishes coverage of this original Make
configuration. `dependency_closure_complete`, `ocore_lowering_complete`,
`native_execution_qualified` and `runtime_complete` remain false. The original
libc/libm/libdl, dynamic loader, compiler helpers and Linux platform interfaces
are declared unresolved dependencies, not admitted host-library substitutes.
The source data manifest includes the original Lua tests and manual; it does
not claim a runtime-bearing OIR bundle or an OValue engine adapter. Full
acceptance still requires verified dependency lowering, linking, scripts,
engine/OS interfaces, and native OSTADIX execution on all three ISAs.

The pinned LLVM 22.1.6 development run on RISC-V retained all 34 units,
33 archive members and 111 source/data files. Independent capture verification
and the original-engine smoke passed. The initial whole-unit diagnostic produced five
verified owned objects and 29 explicit rejections for floating-point types,
variadic interfaces or the original computed-goto blockaddress table. The full
runtime route separately rejected missing included dependency module-sets before
import. See the [exact SDK evidence](../../../evidence/llvm22_riscv64_20261017.json)
and [original-source results](../../../evidence/original_lua_20261017.json).
The five unit successes include an empty configured translation unit and do not
establish runnable engine support.

The subsequent [whole-unit audit](../../../evidence/original_lua_whole_unit_frontier_20261017.json)
attempted all 34 original units again after binary128 storage and narrow direct
`i32` return-ABI compatibility were implemented. Seven produced independently
verified owned RISC-V objects: `lopcodes.c`, `lgc.c`, `lstring.c`, `linit.c`,
`lzio.c`, `ltests.c` and `lctype.c`. `ltests.c` remains an empty configured unit.
The other 27 first rejections comprise 16 LLVM double-precision types,
10 variadic interfaces and the `luaV_execute.disptab` symbolic initializer in
`lvm.c`. This records complete unit attempts without selecting function bodies;
it does not establish that resolving each first diagnostic would complete that
unit or the engine.

The [captured dependency frontier](../../../evidence/original_lua_dependency_frontier_20261017.json)
retains the actual glibc, dynamic-loader, GCC startup and helper providers.
Host binaries and linker scripts do not satisfy original-source lowering.
Version-one module sets reject source pins that they cannot authenticate;
declaring a repository URL and revision alone does not make provider identity
verified. Dependency closure, full lowering, linking and native engine execution
remain false in both records.

## Inventory regression gate

Run the inventory regression gate with:

```bash
python3 -m unittest discover -s tools/ocore-runtime/lua -p 'test_*.py' -v
```
