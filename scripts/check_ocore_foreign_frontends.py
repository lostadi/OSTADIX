#!/usr/bin/env python3
"""Execute real Rust -> LLVM -> verified O-core -> own ISA emission probes.

All three independently generated Rust targets are required for the gate. Java
executes an original host-JVM reference and records every concrete method for a
future managed importer; it never counts that execution as O-core lowering.
Linux syscalls are only the freestanding test carrier, not OSTADIX kernel proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts import ocore_java_inventory as java_inventory

RUST_RELEASE = "1.97.1"
LLVM_VERSION = "22.1.6"
TARGETS = {
    "x86_64": ("x86_64-unknown-linux-gnu", "x86_64-unknown-none", "x86_64-unknown-linux-gnu", 62, []),
    "aarch64": ("aarch64-unknown-linux-gnu", "aarch64-unknown-none", "aarch64-unknown-linux-gnu", 183, []),
    # This real Rust core target has LP64, not the currently unsupported LP64D.
    "riscv64": ("riscv64imac-unknown-none-elf", "riscv64-unknown-none", "riscv64-unknown-linux-gnu", 243,
                ["-march=rv64gc", "-mabi=lp64"]),
}
RUST_FLAGS = ["--edition=2024", "--crate-type=lib", "--emit=llvm-ir",
              "--crate-name=ocore_import_scalar", "-C", "opt-level=1",
              "-C", "panic=abort", "-C", "overflow-checks=off",
              "-C", "relocation-model=static", "-C", "force-unwind-tables=no",
              "-C", "no-vectorize-loops", "-C", "no-vectorize-slp",
              "-C", "codegen-units=1", "-C", "debuginfo=0"]
RUST_FUNCTIONS = {"rust_scalar_" + suffix for suffix in
                  ("helper", "mix", "choose", "narrow", "loop", "u32", "many")}

# The reference uses unsigned arithmetic throughout: overflow and sign
# extension are explicit bit operations rather than C signed-overflow UB.
HARNESS = r'''/* Independent scalar reference and Linux carrier; no libc. */
typedef unsigned long long u64;
typedef long long i64;
typedef unsigned int u32;
extern u64 rust_scalar_helper(u64,u64);
extern u64 rust_scalar_mix(u64,u64,u32);
extern u64 rust_scalar_choose(i64,i64);
extern u64 rust_scalar_narrow(u64);
extern u64 rust_scalar_loop(u64,u32);
extern u32 rust_scalar_u32(u32,u32);
extern u64 rust_scalar_many(u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64);

static u64 syscall3(u64 number, u64 first, u64 second, u64 third) {
#if defined(__x86_64__)
    register u64 rax __asm__("rax") = number;
    __asm__ volatile("syscall" : "+a"(rax) : "D"(first),"S"(second),"d"(third) : "rcx","r11","memory");
    return rax;
#elif defined(__aarch64__)
    register u64 x0 __asm__("x0") = first;
    register u64 x1 __asm__("x1") = second;
    register u64 x2 __asm__("x2") = third;
    register u64 x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x8) : "memory");
    return x0;
#elif defined(__riscv) && __riscv_xlen == 64
    register u64 a0 __asm__("a0") = first;
    register u64 a1 __asm__("a1") = second;
    register u64 a2 __asm__("a2") = third;
    register u64 a7 __asm__("a7") = number;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1),"r"(a2),"r"(a7) : "memory");
    return a0;
#else
#error Unsupported test architecture
#endif
}
static u64 signed_bits(u64 value, u32 width) {
    u64 sign = 1ULL << (width - 1);
    u64 mask = (1ULL << width) - 1;
    return ((value & mask) ^ sign) - sign;
}
static u64 reference_helper(u64 a, u64 b) { return 17*a+b; }
static u64 reference_mix(u64 a, u64 b, u32 shift) {
    return reference_helper((a+b)^(a-b)^(a*b),b) ^ (a<<(shift&63)) ^ (a>>(shift&63));
}
static u64 reference_choose(u64 a, u64 b) {
    return (a ^ (1ULL<<63)) < (b ^ (1ULL<<63)) ? a-b : a+b;
}
static u64 reference_narrow(u64 a) {
    return signed_bits(a,8)+(a&255)+signed_bits(a>>8,16)+((a>>24)&65535)
        +signed_bits(a>>32,32)+(a>>32);
}
static u64 reference_loop(u64 seed, u32 count) {
    for (u32 i=0;i<(count&31);++i) seed=33*seed+i;
    return seed;
}
static u32 reference_u32(u32 value, u32 shift) {
    return (value*0x9e3779b9U+0xf1234567U)^(value>>(shift&31))^(value<<(shift&31));
}
static u64 reference_many(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,u64 g,u64 h,u64 i,u64 j,u64 k,u64 l) {
    return a+2*b+3*c+4*d+5*e+6*f+7*g+8*h+9*i+10*j+11*k+12*l;
}

#ifdef CORRUPT_REFERENCE
#define REF(value) ((value)^1ULL)
#else
#define REF(value) (value)
#endif
#ifdef REFERENCE_ONLY
#define HELPER reference_helper
#define MIX reference_mix
#define CHOOSE reference_choose
#define NARROW reference_narrow
#define LOOP reference_loop
#define U32 reference_u32
#define MANY reference_many
#else
#define HELPER rust_scalar_helper
#define MIX rust_scalar_mix
#define CHOOSE rust_scalar_choose
#define NARROW rust_scalar_narrow
#define LOOP rust_scalar_loop
#define U32 rust_scalar_u32
#define MANY rust_scalar_many
#endif

int conformance_main(void) {
    u64 state=0x9e3779b97f4a7c15ULL, digest=0xcbf29ce484222325ULL;
    for (u32 index=0;index<4096;++index) {
        state^=state<<13;state^=state>>7;state^=state<<17;
        u64 a=state,b=state^(state>>31),got;
        got=HELPER(a,b); if (got!=REF(reference_helper(a,b))) return 11;
        digest=(digest^got)*0x100000001b3ULL;
        got=MIX(a,b,index); if (got!=REF(reference_mix(a,b,index))) return 12;
        digest=(digest^got)*0x100000001b3ULL;
        got=CHOOSE((i64)a,(i64)b); if (got!=REF(reference_choose(a,b))) return 13;
        digest=(digest^got)*0x100000001b3ULL;
        got=NARROW(a); if (got!=REF(reference_narrow(a))) return 14;
        digest=(digest^got)*0x100000001b3ULL;
        got=LOOP(a,index); if (got!=REF(reference_loop(a,index))) return 15;
        digest=(digest^got)*0x100000001b3ULL;
        got=U32((u32)a,index); if (got!=REF(reference_u32((u32)a,index))) return 16;
        digest=(digest^got)*0x100000001b3ULL;
        got=MANY(a,b,3,4,5,6,7,8,9,10,11,12);
        if (got!=REF(reference_many(a,b,3,4,5,6,7,8,9,10,11,12))) return 17;
        digest=(digest^got)*0x100000001b3ULL;
    }
    char output[]="OCORE-RUST-FRONTEND digest=0000000000000000 cases=28672\n";
    for (u32 i=0;i<16;++i) {
        u32 nibble=(u32)(digest>>(60-4*i))&15;
        output[sizeof("OCORE-RUST-FRONTEND digest=")-1+i]=(char)(nibble<10?'0'+nibble:'a'+nibble-10);
    }
    const char *data=output;u64 left=sizeof(output)-1;
    while (left) {
#if defined(__x86_64__)
        u64 written=syscall3(1,1,(u64)data,left);
#else
        u64 written=syscall3(64,1,(u64)data,left);
#endif
        if (!written || written>left) return 99;
        data+=written;left-=written;
    }
    return 0;
}
#if defined(__x86_64__)
__asm__(".text\n.globl _start\n_start:\n xor %ebp,%ebp\n and $-16,%rsp\n call conformance_main\n mov %eax,%edi\n mov $60,%eax\n syscall\n ud2\n");
#elif defined(__aarch64__)
__asm__(".text\n.globl _start\n_start:\n bl conformance_main\n mov x8,#93\n svc #0\n brk #0\n");
#else
__asm__(".text\n.globl _start\n_start:\n call conformance_main\n li a7,93\n ecall\n ebreak\n");
#endif
'''

JAVA_COMPILER = '''import javax.tools.ToolProvider;
public class CompileOcoreScalarProbe {
    public static void main(String[] args) {
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("original javac implementation unavailable");
        // A runtime image may retain jdk.compiler without JDK ct.sym. Use its
        // actual Java 25 runtime APIs, not an absent cross-release symbol image.
        int result = compiler.run(null, null, null, "-source", "25", "-target", "25", "-g:none", "-d", args[0], args[1]);
        if (result != 0) throw new IllegalStateException("javac failed: " + result);
    }
}
'''


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(command: list[str], *, timeout: float = 120) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n"
                           + (result.stdout + result.stderr).decode(errors="replace"))
    return result


def tool(value: str | Path, label: str) -> str:
    executable = shutil.which(str(value))
    if executable is None:
        raise RuntimeError(f"{label} missing: {value}")
    # rustc is commonly a rustup argv[0] proxy. Resolving that symlink and
    # executing "rustup -vV" would change the tool we actually invoke.
    return str(Path(executable).absolute())


def elf(path: Path, machine: int, kind: int) -> None:
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise RuntimeError(f"not a little-endian ELF64 artifact: {path}")
    if int.from_bytes(data[16:18], "little") != kind or int.from_bytes(data[18:20], "little") != machine:
        raise RuntimeError(f"incorrect ELF type or ISA: {path}")
    if machine == 243 and int.from_bytes(data[48:52], "little") & 6:
        raise RuntimeError("RISC-V scalar probe requires LP64 artifacts")


def golden_java() -> bytes:
    """Independent bit arithmetic, including Java overflow and shift counts."""
    lines = []
    def emit(name: str, value: int, width: int):
        lines.append(f"{name}={value & ((1 << width)-1):0{width//4}x}")
    emit("int_add_wrap", 1 << 31, 32)
    emit("long_add_wrap", 1 << 63, 64)
    emit("int_mul_wrap", 0x40000001*4, 32)
    emit("long_mul_wrap", 0x4000000000000001*4, 64)
    emit("class_initializer",41,32)
    for shift in (0, 31, 32, 33, 63, 64, 65, -1):
        for name, width, value in (("int",32,0x81234567),("long",64,0x8123456789abcdef)):
            count = shift & (width-1)
            signed = value - (1 << width)
            emit(f"{name}_shl_{shift}", value << count, width)
            emit(f"{name}_shr_{shift}", signed >> count, width)
            emit(f"{name}_ushr_{shift}", value >> count, width)
    for operation, value32, value64 in (("min_div_minus1",1<<31,1<<63),
                                      ("min_rem_minus1",0,0),
                                      ("negative_div",-2,-2),
                                      ("negative_rem",-1,-1)):
        emit("int_"+operation, value32, 32)
        emit("long_"+operation, value64, 64)
    for name, value, width in (("byte_sign_extend",-128,32), ("short_sign_extend",-32768,32),
                              ("char_zero_extend",65535,32), ("long_to_int",0x89abcdef,32),
                              ("int_to_long",0x81234567-(1<<32),64)):
        emit(name,value,width)
    for name in ("int_div_zero", "long_div_zero", "int_rem_zero", "long_rem_zero"):
        lines.append(name+"=java/lang/ArithmeticException")
    return ("\n".join(lines)+"\n").encode("ascii")


def check_java(java: str, directory: Path) -> dict:
    versions = run([java, "-version"]).stderr.decode().splitlines()
    if not versions:
        raise RuntimeError("Java runtime returned no version evidence")
    version = versions[0]
    if not re.search(r'version "25(?:\.|\")', version):
        raise RuntimeError(f"Java reference requires a Java 25 compiler/runtime: {version}")
    classes = directory / "java-classes"
    classes.mkdir()
    helper = directory / "CompileOcoreScalarProbe.java"
    helper.write_text(JAVA_COMPILER, encoding="utf-8")
    source = ROOT / "tests/fixtures/OcoreScalarProbe.java"
    run([java, str(helper), str(classes), str(source)])
    executed = run([java, "-cp", str(classes), "OcoreScalarProbe"])
    expected = golden_java()
    (directory / "java-reference.expected.txt").write_bytes(expected)
    (directory / "java-reference.actual.txt").write_bytes(executed.stdout)
    if executed.stdout != expected:
        raise RuntimeError("original Java integer reference differs from independently computed golden bytes")
    inventory = java_inventory.inventory([("ocore.scalar.probe", classes)], loader_namespace="application")
    methods = inventory["methods"]
    required = {("<init>","()V"), ("<clinit>","()V"), ("main","([Ljava/lang/String;)V"), ("divideInt","(II)I"),
                ("divideLong","(JJ)J"), ("remainderInt","(II)I"), ("remainderLong","(JJ)J")}
    concrete = {(entry["identity"]["method_name"],entry["identity"]["descriptor"])
                for entry in methods if entry["kind"] == "code"}
    if not required <= concrete or any(entry["kind"] != "code" for entry in methods):
        raise RuntimeError("Java fixture inventory omitted concrete private/constructor/main methods")
    java_inventory.write_json(directory / "java-method-inventory.json", inventory)
    print(f"Java: REFERENCE ONLY — {len(expected.splitlines())} golden cases; "
          f"{len(concrete)} concrete methods inventoried; 0 O-core method bodies", flush=True)
    return {"status":"reference_only", "source_sha256":digest(source), "java_version":version,
            "java_sha256":digest(Path(java)), "golden_sha256":hashlib.sha256(expected).hexdigest(),
            "golden_cases":len(expected.splitlines()), "concrete_method_count":len(concrete),
            "inventory_sha256":digest(directory / "java-method-inventory.json"),
            "verified_ocore_method_count":0, "lowering_complete":False, "runtime_complete":False}


def rust_environment(args: argparse.Namespace) -> dict:
    rustc = tool(args.rustc, "rustc")
    version = run([rustc,"-vV"]).stdout.decode()
    fields = dict(line.split(": ",1) for line in version.splitlines() if ": " in line)
    if fields.get("release") != RUST_RELEASE or fields.get("LLVM version") != LLVM_VERSION:
        raise RuntimeError(f"Rust frontend requires rustc {RUST_RELEASE} with LLVM {LLVM_VERSION}:\n{version}")
    sysroot = Path(run([rustc,"--print","sysroot"]).stdout.decode().strip())
    if args.llvm_library:
        library = args.llvm_library.resolve()
    else:
        candidates = []
        for candidate in (sysroot / "lib").glob("libLLVM*.so*"):
            if candidate.is_file():
                with candidate.open("rb") as stream:
                    if stream.read(4) == b"\x7fELF":
                        candidates.append(candidate.resolve())
        if len(set(candidates)) != 1:
            raise RuntimeError("exactly one Rust LLVM ELF is required; pass --llvm-library")
        library = candidates[0]
    return {"rustc":rustc, "version":version, "sysroot":sysroot, "library":library,
            "library_sha256":digest(library), "ocorec":tool(args.ocorec,"ocorec"),
            "clang":tool(args.clang,"Clang test carrier"), "assembler":tool("clang","O-core assembler")}


def check_rust(target: str, args: argparse.Namespace, env: dict, directory: Path) -> dict:
    rust_target, native, hosted, machine, flags = TARGETS[target]
    core_dir = env["sysroot"] / "lib/rustlib" / rust_target / "lib"
    core = sorted(core_dir.glob("libcore-*.rlib"))
    if len(core) != 1:
        raise RuntimeError(f"Rust libcore unavailable for {rust_target}; "
                           f"install with rustup target add --toolchain {RUST_RELEASE} {rust_target}")
    emulator = [] if target == "x86_64" else [tool(getattr(args,"qemu_"+target),target+" QEMU")]
    work = directory / target
    work.mkdir()
    fixture = ROOT / "tests/fixtures/ocore_import_scalar.rs"
    llvm = work / "rust.ll"
    frontend = [env["rustc"], str(fixture), *RUST_FLAGS, "--target="+rust_target, "-o", str(llvm)]
    run(frontend)
    text = llvm.read_text()
    definitions = set(re.findall(r"^define\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(",text,re.MULTILINE))
    if definitions != RUST_FUNCTIONS:
        raise RuntimeError(f"unexpected whole-unit Rust function inventory: {sorted(definitions)}")
    module = work / "native.json"
    import_command = [env["ocorec"],str(llvm),"--input-kind","llvm-ir","--target",native,
                      "--llvm-library",str(env["library"]),"--llvm-sha256",env["library_sha256"]]
    run([*import_command,"--emit","mir","-o",str(module)])
    normalized = json.loads(module.read_text())
    imported = {entry["name"] for entry in normalized["functions"] if entry["entry"] is not None}
    if imported != definitions:
        raise RuntimeError("O-core whole-unit import lost or invented a Rust implementation body")
    if normalized["provenance"]["input_sha256"] != digest(llvm):
        raise RuntimeError("O-core import provenance is not tied to the original Rust frontend bytes")
    receipt = work / "verification.json"
    run([env["ocorec"],str(module),"--verify-native","--receipt",str(receipt)])
    verified = json.loads(receipt.read_text())
    if (verified.get("format") != "ocore-native-verification-v1" or
        verified.get("verifier") != "ocore-native-v1" or verified.get("verified") is not True or
        verified.get("module_sha256") != digest(module)):
        raise RuntimeError("invalid or stale structural native verification receipt")
    obj = work / "rust.o"
    run([*import_command,"--emit","obj","--keep-asm","-o",str(obj)])
    elf(obj,machine,1)
    alternate = work / "reproducible" / "rust.o"
    run([env["ocorec"],str(module),"--input-kind","native-ir","--target",native,
         "--emit","obj","-o",str(alternate)])
    if obj.read_bytes() != alternate.read_bytes():
        raise RuntimeError("LLVM input and independently verified NativeModule emitted different object bytes")
    harness = directory / "rust-reference.c"
    link = [env["clang"],"--target="+hosted,*flags,"-O2","-ffreestanding","-fno-builtin",
            "-fno-stack-protector","-fno-pic","-nostdlib","-static","-fuse-ld=lld",
            "-Wl,-e,_start","-Wl,--build-id=none",str(harness)]
    reference = work / "reference.elf"
    run([*link,"-DREFERENCE_ONLY","-o",str(reference)])
    elf(reference,machine,2)
    expected = run([*emulator,str(reference)]).stdout
    if not re.fullmatch(rb"OCORE-RUST-FRONTEND digest=[0-9a-f]{16} cases=28672\n",expected):
        raise RuntimeError(f"invalid C reference output: {expected!r}")
    executable = work / "rust.elf"
    run([*link,str(obj),"-o",str(executable)])
    elf(executable,machine,2)
    actual = run([*emulator,str(executable)]).stdout
    if actual != expected:
        raise RuntimeError(f"{target} Rust execution differs from independent C reference bytes")
    # A deliberately broken oracle must be detected, not emit a false pass.
    negative = work / "negative-reference.elf"
    run([*link,str(obj),"-DCORRUPT_REFERENCE","-o",str(negative)])
    rejected = subprocess.run([*emulator,str(negative)],cwd=ROOT,capture_output=True,timeout=30)
    if rejected.returncode != 11 or rejected.stdout:
        raise RuntimeError("broken-reference negative control failed to detect its first arithmetic mismatch")
    (work / "actual.txt").write_bytes(actual)
    print(f"{target}: PASS — actual rustc LLVM import; 7 verified bodies; {actual.decode().strip()}",flush=True)
    return {"status":"pass", "rust_target":rust_target, "frontend_argv":frontend,
            "libcore_sha256":digest(core[0]), "llvm_sha256":digest(llvm),
            "native_module_sha256":digest(module), "verification_receipt_sha256":digest(receipt),
            "object_sha256":digest(obj), "elf_sha256":digest(executable), "output":actual.decode(),
            "functions":sorted(imported), "cases":28672, "negative_reference_rejected":True,
            "reproducible":True, "emulator":emulator}


def check(args: argparse.Namespace, directory: Path) -> dict:
    report = {"format":"ocore-foreign-frontend-conformance-v1", "rust":{}, "java":{},
              "scope":"Rust scalar native lowering and Java host reference/method inventory",
              "all_three_rust_isas_passed":False, "java_lowering_complete":False,
              "full_runtime_complete":False, "kernel_execution_verified":False, "errors":[],
              "artifact_directory":str(directory),
              "rust_source_sha256":digest(ROOT/"tests/fixtures/ocore_import_scalar.rs"),
              "reference_sha256":hashlib.sha256(HARNESS.encode()).hexdigest(),
              "rust_profile":RUST_FLAGS}
    (directory / "rust-reference.c").write_text(HARNESS,encoding="utf-8")
    try:
        report["java"] = check_java(tool(args.java,"original Java 25 runtime/compiler"),directory)
    except (OSError,RuntimeError,ValueError,subprocess.TimeoutExpired) as error:
        report["java"] = {"status":"fail","lowering_complete":False,"error":str(error)}
        report["errors"].append("Java reference: "+str(error))
    try:
        env = rust_environment(args)
        report["rust_toolchain"] = {"rustc_version":env["version"], "rustc_sha256":digest(Path(env["rustc"])),
                                    "rustc_driver_sha256":digest(env["sysroot"]/"bin/rustc"),
                                    "llvm_library":str(env["library"]), "llvm_sha256":env["library_sha256"],
                                    "ocorec_sha256":digest(Path(env["ocorec"])),
                                    "carrier_clang":run([env["clang"],"--version"]).stdout.decode().splitlines()[0],
                                    "assembler_clang":run([env["assembler"],"--version"]).stdout.decode().splitlines()[0]}
        for target in args.targets:
            try:
                report["rust"][target] = check_rust(target,args,env,directory)
            except (OSError,RuntimeError,ValueError,KeyError,subprocess.TimeoutExpired) as error:
                report["rust"][target] = {"status":"fail","error":str(error)}
                report["errors"].append(target+": "+str(error))
        passed = [value["output"] for value in report["rust"].values() if value["status"] == "pass"]
        if len(set(passed)) > 1:
            report["errors"].append("Rust scalar output bytes differ across ISAs")
        report["all_three_rust_isas_passed"] = (set(args.targets) == set(TARGETS) and
                len(passed) == len(TARGETS) and len(set(passed)) == 1)
    except (OSError,RuntimeError,ValueError,subprocess.TimeoutExpired) as error:
        report["errors"].append("Rust toolchain: "+str(error))
    if set(args.targets) != set(TARGETS):
        report["errors"].append("Full conformance requires all three independently compiled Rust targets")
    report["conformance_gate_passed"] = (report["all_three_rust_isas_passed"] and
                report["java"].get("status") == "reference_only" and not report["errors"])
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocorec",type=Path,default=ROOT/"target/debug/ocorec")
    parser.add_argument("--rustc",default="rustc")
    parser.add_argument("--llvm-library",type=Path)
    parser.add_argument("--clang",default="clang")
    parser.add_argument("--java",default="java")
    parser.add_argument("--qemu-aarch64",default="qemu-aarch64")
    parser.add_argument("--qemu-riscv64",default="qemu-riscv64")
    parser.add_argument("--targets",nargs="+",choices=list(TARGETS),default=list(TARGETS),
                        help="Diagnostic subset; a subset never passes the full gate")
    parser.add_argument("--output-dir",type=Path)
    args = parser.parse_args()
    if len(set(args.targets)) != len(args.targets):
        parser.error("targets must be unique")
    try:
        if args.output_dir:
            args.output_dir.mkdir(parents=True,exist_ok=True)
            output = args.output_dir.resolve()
            # Every run is isolated, and failed reruns replace prior successful
            # evidence with explicit failures. Old objects are never reused.
            (output/"conformance.json").unlink(missing_ok=True)
            # Keep the exact paths in compiler argv and Java source inventory
            # valid for replay and subsequent method-body coverage verification.
            artifacts = Path(tempfile.mkdtemp(prefix="run-",dir=output))
            report = check(args,artifacts)
            (output/"conformance.json").write_text(json.dumps(report,indent=2)+"\n")
        else:
            with tempfile.TemporaryDirectory(prefix="ocore-foreign-frontends-") as temporary:
                report = check(args,Path(temporary))
        if not report["conformance_gate_passed"]:
            for error in report["errors"]:
                print("Foreign frontend conformance: FAIL: "+error,file=sys.stderr)
            return 1
        print("All three Rust ISA probes pass. Java evidence remains reference/inventory only.")
        return 0
    except (OSError,RuntimeError,ValueError,subprocess.TimeoutExpired) as error:
        print("Foreign frontend conformance: FAIL: "+str(error),file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
