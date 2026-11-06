#!/usr/bin/env python3
"""Feature census of C runtimes from LLVM IR text (clang 18, opaque pointers).

usage: python3 -I census.py NAME IR_DIR [IR_DIR ...] --out result.json

For every function definition we record which "front-end/backend feature classes" it needs
that O-core v0.1 lacks (measured earlier by probes), then compute, per runtime:
  * how many functions need each feature,
  * how many functions are "closed-ready" (they and every directly-called defined function
    need no missing feature) under a growing supported set,
  * a greedy order in which to add features so the closed-ready fraction grows fastest.
"""
import hashlib
import json
import os
import re
import sys
from collections import defaultdict

FEATURES = [
    "FUNCPTR",      # indirect call, or a function's address used as a value
    "FLOAT",        # any floating-point type/operation
    "AGG_ABI",      # struct passed/returned by value (coerce/byval/sret)
    "VARARGS",      # defines or calls a variadic function
    "SETJMP",       # setjmp/longjmp family
    "ATOMIC",       # atomic RMW/cmpxchg/fence/atomic load-store
    "I128",         # 128-bit integers
    "ASM",          # inline assembly
    "INDIRECTBR",   # computed goto
    "DYNALLOCA",    # alloca/VLA with a run-time size
    "TLS",          # thread-local storage
    "VECTOR",       # SIMD vector types
]
INFO = ["SWITCH", "MEMINTRIN", "BITINTRIN", "OVERFLOWINTRIN"]

SETJMP_NAMES = {
    "setjmp", "_setjmp", "__sigsetjmp", "sigsetjmp", "longjmp", "_longjmp", "siglongjmp",
    "__longjmp_chk", "__builtin_setjmp", "__builtin_longjmp",
}
LIBM = set("""sin cos tan asin acos atan atan2 sinh cosh tanh asinh acosh atanh exp exp2 expm1 log log2
log10 log1p pow sqrt cbrt hypot fabs floor ceil trunc round rint nearbyint lround llround lrint llrint
fmod remainder frexp ldexp scalbn modf erf erfc lgamma tgamma copysign nextafter fma fmin fmax fdim
ilogb logb isnan isinf isfinite signbit""".split())

DEF_RE = re.compile(r'^define\b(?P<head>.*?)@(?P<name>"[^"]+"|[\w.$\-]+)\((?P<rest>.*)$')
CALL_RE = re.compile(r'\bcall\b.*?(?P<callee>[@%](?:"[^"]+"|[\w.$\-]+))\(')
NAME_TOKEN = re.compile(r'[%@](?:"[^"]*"|[\w.$\-]+)')
FLOAT_OPS = re.compile(r'\b(fadd|fsub|fmul|fdiv|frem|fneg|fcmp|fptosi|fptoui|sitofp|uitofp|fpext|fptrunc)\b')
FLOAT_TYPES = re.compile(r'\b(double|float|x86_fp80|fp128|ppc_fp128|half|bfloat)\b')
ATOMIC_RE = re.compile(r'\b(atomicrmw|cmpxchg|fence)\b|\b(load|store) atomic\b')
DYNALLOCA_RE = re.compile(r'=\s*alloca\s+[^,\n]+,\s*i(?:32|64)\s+%')
VECTOR_RE = re.compile(r'<\s*\d+\s+x\s+')
BIT_INTRIN = re.compile(r'@llvm\.(ctlz|cttz|ctpop|bswap|bitreverse|fshl|fshr)\b')
OVF_INTRIN = re.compile(r'@llvm\.[us](add|sub|mul)\.with\.overflow')
MEM_INTRIN = re.compile(r'@llvm\.(memcpy|memmove|memset)\b')


def load_module(path):
    """Yield (name, linkage, signature_line, body_lines) for each defined function; also
    return declared names and global-initializer function-pointer count."""
    funcs, declared = [], set()
    cur = None
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if cur is None:
                if line.startswith("define "):
                    m = DEF_RE.match(line)
                    if not m:
                        continue
                    head = m.group("head")
                    linkage = "internal" if " internal " in (" " + head + " ") else (
                        "linkonce_odr" if "linkonce_odr" in head else "external")
                    cur = {"name": m.group("name").strip('"'), "linkage": linkage,
                           "sig": line.rstrip("\n"), "body": []}
                elif line.startswith("declare "):
                    m = re.search(r'@(?P<n>"[^"]+"|[\w.$\-]+)\(', line)
                    if m:
                        declared.add(m.group("n").strip('"'))
            else:
                if line.startswith("}"):
                    funcs.append(cur)
                    cur = None
                else:
                    cur["body"].append(line.rstrip("\n"))
    return funcs, declared


def analyse(func, fn_names):
    """Return (features, info, callees, extern_calls, instruction_count)."""
    feats, info = set(), set()
    callees = set()
    sig = func["sig"]
    stripped_sig = NAME_TOKEN.sub(" ", sig)
    # Parameter-level tells, from the signature.
    if "byval(" in sig or "sret(" in sig or "inalloca(" in sig or re.search(r'\.coerce\d*\b', sig):
        feats.add("AGG_ABI")
    if re.search(r'define\b[^@]*\{', sig.split("@")[0]):
        feats.add("AGG_ABI")  # literal-struct return
    if "..." in sig.split("{")[0]:
        feats.add("VARARGS")
    if FLOAT_TYPES.search(stripped_sig):
        feats.add("FLOAT")
    if "i128" in stripped_sig:
        feats.add("I128")
    instr = 0
    for raw in func["body"]:
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.endswith(":") and " " not in line.rstrip(":"):
            continue  # basic-block label
        if re.match(r'^[\w.$\-"]+:\s*(;.*)?$', line):
            continue
        instr += 1
        callee = None
        is_call = " call " in (" " + line + " ") or line.startswith("call ")
        if is_call:
            m = CALL_RE.search(line)
            if m:
                callee = m.group("callee")
            if re.search(r'\bcall\b[^@%]*\basm\b', line) or " asm " in line:
                feats.add("ASM")
            if re.search(r'\bcall\b[^@%(]*\([^()]*\.\.\.\)', line):
                feats.add("VARARGS")
            if " = call {" in line or line.startswith("call {"):
                feats.add("AGG_ABI")
        body = line
        if callee:
            if callee.startswith("%"):
                feats.add("FUNCPTR")
            else:
                cname = callee[1:].strip('"')
                body = body.replace(callee + "(", " (", 1)
                if cname.startswith("llvm."):
                    if cname.startswith("llvm.va_"):
                        feats.add("VARARGS")
                    if cname.startswith("llvm.threadlocal"):
                        feats.add("TLS")
                    if cname.startswith("llvm.eh.sjlj"):
                        feats.add("SETJMP")
                else:
                    callees.add(cname)
                    if cname in SETJMP_NAMES:
                        feats.add("SETJMP")
        # function address used as an ordinary operand
        for tok in NAME_TOKEN.findall(body):
            if tok.startswith("@"):
                n = tok[1:].strip('"')
                if n in fn_names and not n.startswith("llvm."):
                    feats.add("FUNCPTR")
        text = NAME_TOKEN.sub(" ", body)
        if FLOAT_OPS.search(text) or FLOAT_TYPES.search(text):
            feats.add("FLOAT")
        if ATOMIC_RE.search(text):
            feats.add("ATOMIC")
        if "i128" in text:
            feats.add("I128")
        if "indirectbr" in text:
            feats.add("INDIRECTBR")
        if DYNALLOCA_RE.search(line):
            feats.add("DYNALLOCA")
        if VECTOR_RE.search(text):
            feats.add("VECTOR")
        if re.match(r'^switch\b', text.strip()) or re.search(r'= switch\b', text):
            info.add("SWITCH")
        if MEM_INTRIN.search(line):
            info.add("MEMINTRIN")
        if BIT_INTRIN.search(line):
            info.add("BITINTRIN")
        if OVF_INTRIN.search(line):
            info.add("OVERFLOWINTRIN")
    return feats, info, callees, instr


def main():
    args = sys.argv[1:]
    out = None
    have = set()
    if "--have" in args:
        i = args.index("--have")
        have = set(args[i + 1].split(","))
        del args[i:i + 2]
    if "--out" in args:
        i = args.index("--out")
        out = args[i + 1]
        del args[i:i + 2]
    name, dirs = args[0], args[1:]
    files = []
    for d in dirs:
        for dp, _dn, fn in os.walk(d):
            for f in fn:
                if f.endswith(".ll"):
                    files.append(os.path.join(dp, f))
    files.sort()

    modules = []
    all_defined, all_declared = set(), set()
    for path in files:
        funcs, declared = load_module(path)
        modules.append((path, funcs))
        all_declared |= declared
        for fn in funcs:
            if fn["linkage"] == "external":
                all_defined.add(fn["name"])
    fn_names = set(all_defined) | all_declared
    for _p, funcs in modules:
        for fn in funcs:
            fn_names.add(fn["name"])

    # analyse, dedupe header-inline duplicates
    records = {}
    seen_hash = set()
    for path, funcs in modules:
        for fn in funcs:
            key = (fn["name"],) if fn["linkage"] == "external" else (path, fn["name"])
            if fn["linkage"] != "external":
                digest = hashlib.sha256(("\n".join(fn["body"]) + fn["sig"]).encode()).hexdigest()
                if (fn["name"], digest) in seen_hash:
                    continue
                seen_hash.add((fn["name"], digest))
            if key in records:
                continue
            feats, info, callees, instr = analyse(fn, fn_names)
            records[key] = {"path": path, "file": os.path.relpath(path), "name": fn["name"], "linkage": fn["linkage"],
                            "feats": feats, "info": info, "callees": callees, "instr": instr}

    # resolve direct-call edges inside the corpus
    by_name = defaultdict(list)
    for key, rec in records.items():
        by_name[rec["name"]].append(key)
    edges = {}
    undefined = set()
    for key, rec in records.items():
        targets = set()
        for callee in rec["callees"]:
            cands = by_name.get(callee, [])
            ext = [k for k in cands if len(k) == 1]
            same = [k for k in cands if len(k) == 2 and k[0] == rec["path"]]
            resolved = ext or same
            if resolved:
                targets.update(resolved)
            else:
                undefined.add(callee)
        edges[key] = targets

    # externs referenced but not defined (libc/OS surface)
    extern_syms = sorted(s for s in undefined if not s.startswith("llvm."))
    libm = [s for s in extern_syms if s in LIBM or (s.endswith("f") and s[:-1] in LIBM) or (s.endswith("l") and s[:-1] in LIBM)]

    total = len(records)
    total_instr = sum(r["instr"] for r in records.values())

    rev = defaultdict(list)
    for k, ts in edges.items():
        for t in ts:
            rev[t].append(k)

    def closed_ready(supported):
        bad = {k for k, r in records.items() if not r["feats"] <= supported}
        stack = list(bad)
        while stack:
            t = stack.pop()
            for c in rev[t]:
                if c not in bad:
                    bad.add(c)
                    stack.append(c)
        return set(records) - bad

    def stats(ok):
        return (len(ok), sum(records[k]["instr"] for k in ok))

    census = {f: sum(1 for r in records.values() if f in r["feats"]) for f in FEATURES}
    census_mass = {f: sum(r["instr"] for r in records.values() if f in r["feats"]) for f in FEATURES}
    info_census = {f: sum(1 for r in records.values() if f in r["info"]) for f in INFO}
    only_one = defaultdict(int)
    for r in records.values():
        if len(r["feats"]) == 1:
            only_one[next(iter(r["feats"]))] += 1

    supported, order = set(have), []
    base_ok = closed_ready(supported)
    base = stats(base_ok)
    cur_ok = base_ok
    remaining = [f for f in FEATURES if f not in have]
    while remaining:
        best = None
        for f in remaining:
            ok = closed_ready(supported | {f})
            gain = stats(ok)
            if best is None or gain[1] > best[2][1]:
                best = (f, ok, gain)
        f, ok, gain = best
        supported.add(f)
        remaining.remove(f)
        order.append({"feature": f, "closed_ready_functions": gain[0], "closed_ready_instr": gain[1]})
        cur_ok = ok

    hot = {}
    for hot_name in ["luaV_execute", "JS_CallInternal", "sqlite3VdbeExec", "_PyEval_EvalFrameDefault",
                     "lua_pcallk", "luaD_rawrunprotected", "JS_Eval", "sqlite3_step", "PyObject_Call"]:
        for k, r in records.items():
            if r["name"] == hot_name:
                hot[hot_name] = {"feats": sorted(r["feats"]), "instr": r["instr"], "file": r["file"]}

    result = {
        "name": name, "files": len(files), "functions": total, "instr": total_instr,
        "census_functions": census, "census_instr": census_mass, "info": info_census,
        "exactly_one_feature_functions": dict(only_one),
        "baseline_closed_ready": {"functions": base[0], "instr": base[1]},
        "greedy_order": order,
        "extern_symbols": len(extern_syms), "libm_symbols": len(libm),
        "extern_sample": extern_syms,
        "hot": hot,
        "feature_free_functions": sum(1 for r in records.values() if not r["feats"]),
    }
    if out:
        with open(out, "w") as handle:
            json.dump(result, handle, indent=1)
    # brief console report
    print(f"== {name}: {total} functions, {total_instr} IR instructions, {len(files)} files")
    print("functions needing each feature:", {k: v for k, v in census.items() if v})
    print("exactly-one-feature functions:", dict(only_one))
    print(f"closed-ready today: {base[0]}/{total} fn ({100*base[0]/total:.1f}%), {base[1]}/{total_instr} instr ({100*base[1]/total_instr:.1f}%)")
    for step in order:
        if step["closed_ready_instr"] == 0 and step["closed_ready_functions"] == 0:
            pass
    cum = []
    for step in order:
        cum.append(f"+{step['feature']}: {100*step['closed_ready_functions']/total:.1f}% fn / {100*step['closed_ready_instr']/total_instr:.1f}% instr")
    print("greedy:", " | ".join(cum))
    print(f"externs: {len(extern_syms)} distinct undefined symbols ({len(libm)} libm)")
    for hn, hv in hot.items():
        print("hot", hn, hv)


if __name__ == "__main__":
    main()
