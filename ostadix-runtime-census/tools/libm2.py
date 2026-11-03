"""libm cross-variant probe, v2. Inputs are generated once, with no libm calls, and stored;
every run reads the same input bytes (v1 generated inputs with 10**u, which itself calls pow)."""
import hashlib, math, os, random, struct, sys

N = 200000
F1 = ["sin","cos","tan","asin","acos","atan","sinh","cosh","tanh","asinh","acosh","atanh",
      "exp","exp2","expm1","log","log2","log10","log1p","cbrt","erf","erfc","lgamma","gamma"]
F2 = ["atan2","pow","hypot"]
ERR = struct.unpack("<d", struct.pack("<Q", 0x7ff8dead00000001))[0]

def draw(rng, name):
    k = rng.randrange(4)
    if k == 0:   x = rng.uniform(-50.0, 50.0)
    elif k == 1: x = rng.uniform(-1.0, 1.0)
    elif k == 2: x = math.ldexp(1.0 + rng.random(), rng.randint(-100, 100)) * rng.choice([-1.0, 1.0])
    else:
        x = rng.uniform(-700.0, 700.0) if name in ("exp","exp2","expm1","sinh","cosh") else rng.uniform(0.0, 1000.0)
    return x

def gen(indir):
    os.makedirs(indir, exist_ok=True)
    for name in F1 + F2:
        rng = random.Random(int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], "little"))
        rows = []
        for _ in range(N):
            x = draw(rng, name)
            if name in F2:
                y = draw(rng, name)
                if name == "pow": x, y = (abs(x) % 50.0) + 0.01, (y % 40.0) - 20.0
                rows += [x, y]
            else:
                rows.append(x)
        open(os.path.join(indir, name + ".in"), "wb").write(struct.pack("<%dd" % len(rows), *rows))

def run(indir, outdir):
    os.makedirs(outdir, exist_ok=True)
    for name in F1 + F2:
        raw = open(os.path.join(indir, name + ".in"), "rb").read()
        vals = struct.unpack("<%dd" % (len(raw) // 8), raw)
        f = getattr(math, name); out = []
        step = 2 if name in F2 else 1
        for i in range(0, len(vals), step):
            try: out.append(f(*vals[i:i+step]))
            except (ValueError, OverflowError): out.append(ERR)
        open(os.path.join(outdir, name + ".bin"), "wb").write(struct.pack("<%dd" % len(out), *out))

if __name__ == "__main__":
    {"gen": lambda: gen(sys.argv[2]), "run": lambda: run(sys.argv[2], sys.argv[3])}[sys.argv[1]]()
