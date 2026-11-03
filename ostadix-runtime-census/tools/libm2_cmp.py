import os, struct, sys
sys.path.insert(0, os.path.dirname(__file__))
import libm2 as P
from mpmath import mp, mpf
mp.prec = 400
indir, da, db = sys.argv[1:4]

def ref(name, a):
    t = {"sin": mp.sin, "cos": mp.cos, "tan": mp.tan, "asin": mp.asin, "acos": mp.acos, "atan": mp.atan,
         "sinh": mp.sinh, "cosh": mp.cosh, "tanh": mp.tanh, "asinh": mp.asinh, "acosh": mp.acosh, "atanh": mp.atanh,
         "exp": mp.exp, "exp2": lambda v: mp.power(2, v), "expm1": mp.expm1, "log": mp.log, "log2": lambda v: mp.log(v, 2),
         "log10": mp.log10, "log1p": mp.log1p, "cbrt": mp.cbrt, "erf": mp.erf, "erfc": mp.erfc,
         "lgamma": lambda v: mp.log(abs(mp.gamma(v))), "gamma": mp.gamma}
    if name in t: return t[name](mpf(a[0]))
    if name == "atan2": return mp.atan2(mpf(a[0]), mpf(a[1]))
    if name == "pow": return mp.power(mpf(a[0]), mpf(a[1]))
    return mp.sqrt(mpf(a[0])**2 + mpf(a[1])**2)

def key(v):
    i = struct.unpack("<q", struct.pack("<d", v))[0]
    return i if i >= 0 else -(i & 0x7fffffffffffffff)
def ud(a, b): return abs(key(a) - key(b))

tot = dict(results=0, diff=0, A_ok=0, B_ok=0, A_gt1=0, B_gt1=0)
print(f"{'fn':7s} {'differ':>6s}  {'A=truth':>7s} {'B=truth':>7s}  {'A>1ulp':>6s} {'B>1ulp':>6s}  worst ulp A/B   max |A-B| ulp")
for name in P.F1 + P.F2:
    a = open(os.path.join(da, name + ".bin"), "rb").read(); b = open(os.path.join(db, name + ".bin"), "rb").read()
    n = len(a) // 8; tot["results"] += n
    if a == b: continue
    va = struct.unpack("<%dd" % n, a); vb = struct.unpack("<%dd" % n, b)
    raw = open(os.path.join(indir, name + ".in"), "rb").read(); iv = struct.unpack("<%dd" % (len(raw) // 8), raw)
    step = 2 if name in P.F2 else 1
    c = dict(diff=0, A_ok=0, B_ok=0, A_gt1=0, B_gt1=0, aw=0, bw=0, ab=0)
    for i in range(n):
        if struct.pack("<d", va[i]) == struct.pack("<d", vb[i]): continue
        c["diff"] += 1
        if va[i] != va[i] or vb[i] != vb[i]: continue
        c["ab"] = max(c["ab"], ud(va[i], vb[i]))
        t = float(ref(name, iv[i*step:(i+1)*step]))
        ea, eb = ud(va[i], t), ud(vb[i], t)
        c["A_ok"] += ea == 0; c["B_ok"] += eb == 0
        c["A_gt1"] += ea > 1; c["B_gt1"] += eb > 1
        c["aw"] = max(c["aw"], ea); c["bw"] = max(c["bw"], eb)
    for k in ("diff","A_ok","B_ok","A_gt1","B_gt1"): tot[k] += c[k]
    print(f"{name:7s} {c['diff']:6d}  {c['A_ok']:7d} {c['B_ok']:7d}  {c['A_gt1']:6d} {c['B_gt1']:6d}  {c['aw']:5d}/{c['bw']:<5d}      {c['ab']}")
print("TOTAL", tot)
