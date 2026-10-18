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
ran with Clang 22.1.6 and 13 library link flags. The full source capture and
whole-unit audit are still pending.

The first build exposed an unrelocated `-I/usr/include/uuid` from pkg-config.
The unchanged `_uuid` implementation requires the extracted `uuid.h` directory.
With `CPYTHON_HOSTED_ROOT` set to that extracted root and the other scoped interface flags
already supplied, the fresh attempt uses:

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

This inventory establishes source-build accounting only. Complete imported
functions/globals, dependency implementations, native OSTADIX platform services,
linking, resources, compiler witnesses, and all-three-ISA execution remain
separate required gates. A successful hosted build is not a completed native
runtime or compiler.

```sh
python3 tools/ocore-runtime/cpython/test_build_inventory.py -v
```
