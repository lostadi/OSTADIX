# ostadix-runtime-census v1

Measurements behind the answer about compiling foreign language runtimes into O-core.
Everything here is analysis of compiler output (LLVM IR text from clang 18, -O0, x86-64) plus one libm probe;
no runtime was compiled through O-core, because nothing in the tree can do that yet.

## What the census measures

For every function definition in the IR, the census records which feature classes it needs that O-core v0.1 lacks:
FUNCPTR (indirect call or function address as a value), FLOAT, AGG_ABI (struct by value, via `byval`/`sret`/`.coerce`),
VARARGS, SETJMP, ATOMIC, I128, INDIRECTBR (computed goto), DYNALLOCA, TLS, VECTOR. Inline asm is counted as supported,
because O-core has `asm!`. A function is "closed-ready" when it and every directly called defined function need nothing
missing. Indirect calls are not followed, so the closure numbers understate how much a missing feature blocks.

"Missing" comes from earlier probes of `ocorec` (function pointers, f64 operators, aggregates across calls, atomics on
AArch64/RV64) and a grep of the front end (no variadics, i128, TLS, alloca, setjmp). Struct-by-value is seen through
x86-64 SysV coercion in the IR, so small structs coerced to a single integer are undercounted.

## Results (portable configurations; sources and revisions in run_all.sh and below)

See `results/*.json` and `python3 -I tools/summarize.py results/*.json`.

| runtime | functions | IR instructions | closed-ready today (functions / IR) |
|---|---|---|---|
| Lua 5.5.1, `LUA_USE_JUMPTABLE=0` | 1,124 | 68,769 | 24.7% / 19.3% |
| QuickJS 2026-06-04, `DIRECT_DISPATCH 0` | 1,935 | 254,230 | 25.7% / 8.9% |
| SQLite 3.53.4, `SQLITE_DISABLE_INTRINSIC` | 2,591 | 275,284 | 26.6% / 12.0% |
| CPython 3.13 core (Python, Objects, Parser), computed gotos off | 8,561 | 807,418 | 21.1% / 8.9% |

`*_default.json` are the default configurations (computed goto, `__int128` paths enabled).

## CPython recipe (not in run_all.sh; about 15 minutes on two cores)

```
git clone --depth 1 --branch 3.13 https://github.com/python/cpython src/cpython     # revision used: c35ca4cb6e296d1770fe45f9414b58eb06242e02
mkdir build && cd build
CC="$PWD/../tools/ccir" OPT="-fwrapv -O0" ../src/cpython/configure --disable-test-modules --without-ensurepip
make -j2 > ../make.log                      # ccir writes a .ll next to every .o
python3 -I ../tools/census.py cpython-core Python Objects Parser --have ASM --out ../cpython_core_default.json
# portable dispatch: take the Python/ceval.c command line from ../make.log, drop -c/-o/-O*, and run it with
#   -S -emit-llvm -O0 -w -DUSE_COMPUTED_GOTOS=0
# then repeat the census with that ceval.ll substituted.
```

## libm probe

`tools/libm2.py` generates 200,000 inputs per function (no libm calls while generating; an earlier version used `10 ** x`,
which itself calls `pow`, and the two runs got different inputs), runs `math.*` once with default glibc CPU dispatch and once with
`GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX2,-FMA,-FMA4,-AVX512F`, and `tools/libm2_cmp.py` compares both to a 400-bit mpmath reference.
Measured here: Ubuntu glibc 2.39, Python 3.13.16, one x86-64 machine with FMA and AVX2.
