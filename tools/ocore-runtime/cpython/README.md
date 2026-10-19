# Full CPython source capture

`full.recipe.json` pins the original CPython implementation at
`c35ca4cb6e296d1770fe45f9414b58eb06242e02` and uses the frozen capture worker.
Its build-inventory helper is additionally bound to exact SHA-256 bytes in each
manifest command. The earlier flat recipe and its recorded captures remain
unchanged.

This is a hosted Linux source-build profile. SQLite, Tcl/Tk, readline, DBM/GDBM,
and the other applicable standard-library extensions must configure as enabled.
Missing or disabled modules fail before the native build. The Darwin-only
`_scproxy` module is explicitly inapplicable in this profile; arbitrary `n/a`
reclassification is rejected.

Provide the complete hosted development headers/library interfaces through
`CPPFLAGS`, `LDFLAGS`, and the upstream dependency flag variables, including
`LIBSQLITE3_CFLAGS`/`LIBSQLITE3_LIBS`, `TCLTK_CFLAGS`/`TCLTK_LIBS`,
`GDBM_CFLAGS`/`GDBM_LIBS`, `LIBREADLINE_CFLAGS`/`LIBREADLINE_LIBS`, and
`LIBUUID_CFLAGS`/`LIBUUID_LIBS` where needed. Record exact package/source
receipts. Extracting hosted libraries does not lower their implementations
through O-core.

The 2026-10-18 RV64 prerequisite run authenticated the Debian package index and
verified each of 72 downloaded archive hashes before extracting that archive
locally. No global packages changed. A hosted header/API preflight compiled and
ran with Clang 22.1.6 and 13 library link flags.

The pkg-config output contained an unrelocated `-I/usr/include/uuid`.
The unchanged `_uuid` implementation requires the extracted `uuid.h` directory.
With `CPYTHON_HOSTED_ROOT` set to that extracted root and the other scoped
interface flags already supplied, use:

```sh
export LIBUUID_CFLAGS="-I${CPYTHON_HOSTED_ROOT}/usr/include/uuid"
export LIBUUID_LIBS="-L${CPYTHON_HOSTED_ROOT}/usr/lib/riscv64-linux-gnu -luuid"
export CPPFLAGS="${CPPFLAGS} ${LIBUUID_CFLAGS}"
```

Check `pkg-config --cflags` and `--libs` separately. Combining them with
`--modversion` printed only the version in the initial prerequisite check;
`--define-prefix` also left this UUID include path unrelocated.

Run the generic source-capture command with empty build/capture directories and
matching LLVM 22.1.6 drivers:

```sh
python3 scripts/ocore_runtime_capture.py capture \
  tools/ocore-runtime/cpython/full.recipe.json \
  --source SOURCE --build BUILD --output CAPTURE --jobs 2 \
  --unit-inventory BUILD/full-unit-inventory.json \
  --cc CLANG --cxx CLANGXX --llvm-nm LLVM_NM
```

The helper records the original upstream `make --dry-run all` commands, checks
the actual native source invocations against the entire configured graph, and
includes archive and extension outputs in membership evidence. Implementation
helpers remain selected for lowering. Configure probes retain explicit stage,
log, and membership evidence. Assembly sources remain required and fail closed
until their import path exists.

The completed 2026-10-18 RV64 capture retained 876 LLVM units and accounted for
all 360 configured implementation units. The original Clang-built CPython
passed the hosted reference smoke, including bytecode compilation, SQLite,
DBM, compression, libffi, TLS context creation, Tcl, and test-extension imports.

The whole-unit audit attempted all 360 selected units: 72 imported and passed
independent O-core verification; 63 produced owned native objects. The dominant
first import failures were 113 double-precision type rejections, 101 variadic
signature rejections, 33 requests for an explicit TLS profile, and 13 opaque
structure layouts. All nine subsequent object-stage failures requested the
explicit `coherent_ram_v1` atomic execution profile. This baseline selected
neither an atomic nor a TLS profile. Exact unit IDs, remaining diagnostics,
tool/source hashes, and the hosted reference receipt are bound in the
[completed expansion evidence](../../../evidence/original_python_c_rust_expansion_20261018.json).

A separate follow-up reimported exactly those nine whole inputs with
`--atomic-profile coherent-ram-v1`; all nine passed independent verification and
produced RV64 objects. Complete function/global/alias inventories and instruction
semantics remained unchanged. This contract excludes device memory, requires
accessible containing words for masked subword atomics, and requires RV64 LR/SC
eventuality. It establishes no native execution or provider qualification. The
[atomic-profile evidence](../../../evidence/cpython_atomic_profile_followup_20261018.json)
retains the separate result; the baseline above remains unchanged.

This inventory establishes source-build accounting only. Complete imported
functions/globals, dependency implementations, native OSTADIX platform services,
linking, resources, compiler witnesses, and all-three-ISA execution remain
separate required gates. A successful hosted build is not a completed native
runtime or compiler.

```sh
python3 tools/ocore-runtime/cpython/test_build_inventory.py -v
```
