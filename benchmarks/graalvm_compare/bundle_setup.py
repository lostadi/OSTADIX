# Body of the python block in graalvm_compare_bundle.O (pack.O inserts it,
# after a PAYLOAD line). Rebuilds the OSTADIX vs GraalVM comparison on this
# machine. It must not contain a dollar sign or an O block opener/closer,
# because O splices dollar identifiers and parses typed parens; pack.O
# refuses to pack it if it does.
#
# Environment (all optional):
#   OSTADIX_BENCH_DIR     where to rebuild (default ~/ostadix-graalvm-compare)
#   OSTADIX_BENCH_NATIVE  1 = also build the GraalVM native image (~8 min, ~2 GB RAM)
#   OSTADIX_BENCH_ROUNDS  N = run the full comparison with N rounds when setup ends
import base64
import hashlib
import io
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

GRAAL_VERSION = "25.0.4"
GRAAL_SHA256 = {
    "macos-aarch64": "0b79e23c133facbad2f7aa55a3b76d17bd59d2fa15e2735bb63391ace223fd13",
    "linux-x64": "76007c309f821aaf435bce63162ea0395587fc77350801c81643fe7feea37276",
    "linux-aarch64": "7031aead8da4c6a7816c4e2be4eabfddaf7f4abcfe8e5f16134c4da69a5e70de",
}
# group, artifact, sha256 of artifact-25.0.4.jar on Maven Central
JARS = [
    ("org.graalvm.sdk", "collections", "f78840945e4d746ca37aadd3d04a3266c3b7fd644a303d5b85fb03aa012b4fd4"),
    ("org.graalvm.shadowed", "icu4j", "58f46bc96b93a09b91fcea6d3a18d914013beb49593a32b0a914d435452bcde3"),
    ("org.graalvm.sdk", "jniutils", "e61bb126ccba8ad37e4439216988bead5428ff64ae9126b9456590f164e1a261"),
    ("org.graalvm.js", "js-language", "5840cf29df9d2a71fa236d9ba35cd004664bc67b7bb46cbab39cb446c9f174ed"),
    ("org.graalvm.shadowed", "json", "6c1fbde877a59674693d41743f7ed4ca147ce5b4c1f589e753fbd5611c97e58c"),
    ("org.graalvm.sdk", "nativeimage", "a42f260174e9a059ecfbbca2aa5b8243e80e84b9dc3f70096a5213aebbeac450"),
    ("org.graalvm.polyglot", "polyglot", "2f0de83536f9754a1bb4c0e4405f8332b2b9c2e949023da070379e5b3b656b87"),
    ("org.graalvm.tools", "profiler-tool", "029b6d9a8335ebd5185055ad61582747f06700a44922449052a9b3b992f244ba"),
    ("org.graalvm.python", "python-language", "91f91e0b63dd869f91a57b33523876283b1ec12bd5d41ed5b6ee2aa7e617f04c"),
    ("org.graalvm.python", "python-resources", "4bffd1b3b15da4aa096251d20db3fc73d684ecf700d78ee24d5a6c6863d4014e"),
    ("org.graalvm.regex", "regex", "a838ae2e635f3cc4d44a0361a17f0cda6b05b15f39de765ba7cce1e8e176bd67"),
    ("org.graalvm.truffle", "truffle-api", "c437c6e221c0cae2db96f00a829b6d59df4852e484b0bdd16377a21afa210a9e"),
    ("org.graalvm.truffle", "truffle-compiler", "3e9973775adb2f6c276fadfff2ef12ac4f20e71f8bbc12c773d36c90c8471c00"),
    ("org.graalvm.truffle", "truffle-nfi", "b8b32084542a54abcd5ff57b43bc3ce9db21f0e8b38b4c1557009b8c0168814c"),
    ("org.graalvm.truffle", "truffle-nfi-libffi", "14d1a9b0b8fdee070ff174ccbf0879bf925a87fd622af7b60fe00fe7ec17bbe3"),
    ("org.graalvm.truffle", "truffle-nfi-panama", "574329ae1490579b7ff961896c95350937e175f6dc30d8f32338eb76fc4ae0b9"),
    ("org.graalvm.truffle", "truffle-runtime", "611e3bea983366c1b04146870a1ddf765bc899201e0348de8a5ebcfbde3bae64"),
    ("org.graalvm.sdk", "word", "b91cd74e61e6257416f52dac5925e3a9d03b756035d48f4e8c56106fe11d7eff"),
    ("org.graalvm.shadowed", "xz", "96de136c6b9ea378ed3f87bc8db05b78792db776e770cb0dbf7e56efd1055b0d"),
]
WORKLOADS = ["w1_handoff", "w2_compute", "w3_data", "w4_fidelity", "w5_nan"]


def log(msg):
    sys.stderr.write("[graalvm-compare] " + msg + "\n")
    sys.stderr.flush()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url, dest, expected):
    if dest.exists() and sha256(dest) == expected:
        return
    log("download " + url)
    tmp = dest.with_name(dest.name + ".part")
    with urllib.request.urlopen(url) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)
    got = sha256(tmp)
    if got != expected:
        tmp.unlink()
        raise RuntimeError("sha256 mismatch for " + url + ": got " + got + ", expected " + expected)
    tmp.replace(dest)


def platform_key():
    system = {"darwin": "macos", "linux": "linux"}.get(sys.platform)
    machine = platform.machine().lower()
    arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x64", "amd64": "x64"}.get(machine)
    key = (system or sys.platform) + "-" + (arch or machine)
    if key not in GRAAL_SHA256:
        raise RuntimeError("no pinned GraalVM " + GRAAL_VERSION + " archive for " + key
                           + " (Oracle publishes macos-aarch64, linux-x64, linux-aarch64)")
    return key


def find_o():
    root = os.environ.get("O_LANG_ROOT")
    o_bin = os.environ.get("O_BIN") or shutil.which("O")
    if not o_bin and root and (Path(root) / "target" / "release" / "O").exists():
        o_bin = str(Path(root) / "target" / "release" / "O")
    if not o_bin:
        raise RuntimeError("cannot find the O binary: set O_BIN or O_LANG_ROOT, or put O on PATH")
    backends = os.environ.get("O_BACKENDS_DIR") or (str(Path(root) / "backends") if root else None)
    if not backends or not Path(backends).is_dir():
        raise RuntimeError("cannot find OSTADIX backends: set O_BACKENDS_DIR or O_LANG_ROOT")
    return o_bin, backends


def main():
    dest = Path(os.environ.get("OSTADIX_BENCH_DIR") or Path.home() / "ostadix-graalvm-compare")
    dest.mkdir(parents=True, exist_ok=True)
    report = {"dir": str(dest)}

    # 1. Unpack the bundled sources.
    with tarfile.open(fileobj=io.BytesIO(base64.b64decode(PAYLOAD)), mode="r:gz") as tar:
        tar.extractall(dest, filter="data")
    log("sources unpacked into " + str(dest))

    # 2. Tool prerequisites.
    for tool in ("python3", "node"):
        if not shutil.which(tool):
            raise RuntimeError(tool + " is required on PATH")
    o_bin, backends = find_o()
    report["o_bin"] = o_bin

    # 3. GraalVM JDK, pinned version and checksum for this platform.
    key = platform_key()
    cache = dest / ".cache"
    cache.mkdir(exist_ok=True)
    archive = cache / ("graalvm-jdk-" + GRAAL_VERSION + "_" + key + "_bin.tar.gz")
    fetch("https://download.oracle.com/graalvm/25/archive/graalvm-jdk-" + GRAAL_VERSION
          + "_" + key + "_bin.tar.gz", archive, GRAAL_SHA256[key])
    gdir = dest / "graalvm"
    if not gdir.exists():
        log("extract GraalVM")
        gdir.mkdir()
        with tarfile.open(archive) as tar:
            tar.extractall(gdir, filter="tar")
    top = next(p for p in gdir.iterdir() if p.is_dir())
    java_home = top / "Contents" / "Home" if (top / "Contents" / "Home").exists() else top
    report["java_home"] = str(java_home)

    # 4. Polyglot jars, pinned by checksum (same set Gradle resolves for 25.0.4).
    lib = dest / "graal" / "lib"
    lib.mkdir(parents=True, exist_ok=True)
    for group, artifact, digest in JARS:
        name = artifact + "-" + GRAAL_VERSION + ".jar"
        url = ("https://repo1.maven.org/maven2/" + group.replace(".", "/") + "/" + artifact
               + "/" + GRAAL_VERSION + "/" + name)
        fetch(url, lib / name, digest)
    log("GraalVM and " + str(len(JARS)) + " polyglot jars verified")

    # 5. Compile the GraalVM host.
    gwork = dest / "graal"
    jars = sorted(str(p) for p in lib.glob("*.jar"))
    subprocess.run([str(java_home / "bin" / "javac"), "-cp", os.pathsep.join(jars),
                    "-d", str(gwork / "classes"), str(gwork / "GraalBench.java")], check=True)

    # 6. Smoke both systems; refuse an interpreter-only GraalVM.
    java_cmd = [str(java_home / "bin" / "java"), "--enable-native-access=org.graalvm.truffle",
                "--module-path", "lib", "--add-modules", "org.graalvm.polyglot", "-cp", "classes",
                "GraalBench"]
    smoke = {}
    for w in WORKLOADS:
        g = subprocess.run(java_cmd + [w], cwd=gwork, capture_output=True, text=True)
        if "fallback runtime" in g.stderr:
            raise RuntimeError("GraalVM runs without runtime compilation (version mismatch?)")
        o = subprocess.run([o_bin, str(dest / "ostadix" / (w + ".O")), backends],
                           capture_output=True, text=True,
                           env=dict(os.environ, O_BACKENDS_DIR=backends))
        smoke[w] = {
            "graalvm": g.stdout.strip().splitlines()[-1] if g.returncode == 0 and g.stdout.strip() else "FAILED",
            "ostadix": o.stdout.strip().splitlines()[-1] if o.returncode == 0 and o.stdout.strip() else "FAILED",
        }
        log(w + ": graalvm=" + smoke[w]["graalvm"] + " ostadix=" + smoke[w]["ostadix"])
    report["smoke"] = smoke

    # 7. Optional native image.
    if os.environ.get("OSTADIX_BENCH_NATIVE") == "1":
        native = gwork / "native"
        native.mkdir(exist_ok=True)
        log("building GraalVM native image (about 8 minutes on an M1 Max)")
        subprocess.run([str(java_home / "bin" / "native-image"), "-cp",
                        os.pathsep.join(["classes"] + jars), "-o", "native/graalbench",
                        "GraalBench"], cwd=gwork, check=True)
        report["native"] = str(native / "graalbench")

    # 8. Optional full run.
    rounds = os.environ.get("OSTADIX_BENCH_ROUNDS")
    if rounds:
        log("running the comparison, " + rounds + " rounds")
        subprocess.run([sys.executable, str(dest / "run.py"), str(java_home), rounds], cwd=dest,
                       check=True, env=dict(os.environ, O_BIN=o_bin, O_BACKENDS_DIR=backends))
        report["results"] = str(dest / "results.json")

    report["next"] = ("cd " + str(dest) + " && O_BIN=" + o_bin + " O_BACKENDS_DIR=" + backends
                      + " python3 run.py " + str(java_home) + " 10")
    return report


__oval_result__ = main()
