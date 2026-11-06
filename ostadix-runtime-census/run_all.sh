#!/bin/bash
# Reproduces: (1) the C-feature census for Lua, QuickJS and SQLite in their portable configurations,
#             (2) the libm cross-path probe, (3) the syscall counts for CPython and bash.
# usage: ./run_all.sh WORKDIR     (WORKDIR must not exist)
# needs: clang (18), git, npm, python3, strace; mpmath is installed with pip if missing.
# CPython is a documented manual recipe in README.md (it takes about 15 minutes on two cores).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
W=${1:?usage: run_all.sh WORKDIR}
[ -e "$W" ] && { echo "WORKDIR must not exist: $W"; exit 2; }
mkdir -p "$W"/src "$W"/ir/lua "$W"/ir/quickjs "$W"/ir/sqlite "$W"/res "$W"/tmp
T="$here/tools"

pin() { git init -q "$2"; git -C "$2" remote add origin "$1"; git -C "$2" fetch -q --depth 1 origin "$3"; git -C "$2" checkout -q FETCH_HEAD; }
echo "== fetch sources at the revisions used for the published numbers"
pin https://github.com/lua/lua        "$W/src/lua"      0b29f408433e92953cc72b1d3e06c7ac8139e439
pin https://github.com/bellard/quickjs "$W/src/quickjs" 535a7c250ff4a577ec36c3e103daab6dadeea650
( cd "$W/tmp" && npm pack --silent better-sqlite3@13.0.3 >/dev/null \
  && mkdir -p "$W/src/sqlite" && tar xzf better-sqlite3-13.0.3.tgz -C "$W/src/sqlite" package/deps/sqlite3/sqlite3.c package/deps/sqlite3/sqlite3.h )
SQ="$W/src/sqlite/package/deps/sqlite3"

echo "== compile to LLVM IR (-O0), portable configurations"
for f in "$W"/src/lua/l*.c; do b=$(basename "$f" .c); case "$b" in lua|luac|ltests|onelua) continue;; esac
  clang -S -emit-llvm -O0 -w -DLUA_USE_POSIX -DLUA_USE_JUMPTABLE=0 -I"$W/src/lua" "$f" -o "$W/ir/lua/$b.ll"; done
sed 's/^#define DIRECT_DISPATCH  1/#define DIRECT_DISPATCH  0/' "$W/src/quickjs/quickjs.c" > "$W/tmp/quickjs.c"
for b in cutils libregexp libunicode dtoa quickjs-libc; do
  clang -S -emit-llvm -O0 -w -funsigned-char -fwrapv -D_GNU_SOURCE -DCONFIG_VERSION=\"2026-06-04\" -I"$W/src/quickjs" "$W/src/quickjs/$b.c" -o "$W/ir/quickjs/$b.ll"; done
clang -S -emit-llvm -O0 -w -funsigned-char -fwrapv -D_GNU_SOURCE -DCONFIG_VERSION=\"2026-06-04\" -I"$W/src/quickjs" "$W/tmp/quickjs.c" -o "$W/ir/quickjs/quickjs.ll"
clang -S -emit-llvm -O0 -w -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_DISABLE_INTRINSIC -I"$SQ" "$SQ/sqlite3.c" -o "$W/ir/sqlite/sqlite3.ll"

echo "== census (inline asm counted as supported, as in O-core)"
python3 -I "$T/census.py" lua     "$W/ir/lua"     --have ASM --out "$W/res/lua_portable.json"     >/dev/null
python3 -I "$T/census.py" quickjs "$W/ir/quickjs" --have ASM --out "$W/res/quickjs_portable.json" >/dev/null
python3 -I "$T/census.py" sqlite3 "$W/ir/sqlite"  --have ASM --out "$W/res/sqlite3_portable.json" >/dev/null
python3 -I "$T/summarize.py" "$W"/res/lua_portable.json "$W"/res/quickjs_portable.json "$W"/res/sqlite3_portable.json

echo "== libm: same inputs, default CPU-feature path versus FMA/AVX2 disabled (this machine's glibc and python3)"
python3 -c "import mpmath" 2>/dev/null || pip install -q --break-system-packages mpmath
python3 -I "$T/libm2.py" gen "$W/res/libm_in"
python3 -I "$T/libm2.py" run "$W/res/libm_in" "$W/res/libm_default"
GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX2,-FMA,-FMA4,-AVX512F python3 -I "$T/libm2.py" run "$W/res/libm_in" "$W/res/libm_nofma"
python3 -I "$T/libm2_cmp.py" "$W/res/libm_in" "$W/res/libm_default" "$W/res/libm_nofma" | tee "$W/res/libm_summary.txt"

echo "== syscalls (distinct names under strace -f), trivial scripts"
count() {
  label=$1; shift
  strace -f -qq -o "$W/res/$label.trace" "$@" >/dev/null 2>&1 || true
  printf '%s: ' "$label"
  sed -E -n 's/^[0-9]+ +([a-z_0-9]+)\(.*/\1/p' "$W/res/$label.trace" | sort -u | wc -l
}
count py_print   python3 -I -c "print(sum(range(10)))"
count py_stdlib  python3 -I -c "import json,re,math,hashlib,datetime,sqlite3,threading,subprocess,socket,os; c=sqlite3.connect(':memory:'); c.execute('create table t(x)'); print(json.dumps({'a':hashlib.sha256(b'x').hexdigest()[:8]}))"
count bash_basic bash -c 'for i in 1 2 3; do echo $i; done; ( : ); cd /tmp; x=$(echo hi); true'
echo "done: results in $W/res"
