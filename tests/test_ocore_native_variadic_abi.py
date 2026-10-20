"""Whole Clang22 units across the reference/owned C variadic ABI boundary.

Linux syscalls, LLD and optional QEMU are explicit development carriers. The
fixture has no target libc dependency. Four ownership combinations prevent a
matching caller/callee defect from serving as its own oracle. No Cargo build or
installation is performed. Set OCOREC (or OCORE_TEST_OCOREC) to a fresh binary;
OCORE_VARARGS_RETAIN retains all commands, original inputs and artifacts.
"""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SDK = Path.home() / ".local/share/ostadix/llvm22/rootfs/usr/lib"
LLVM_SHA256 = "8617d27fecff5e31785eed07ee1cd7665e083bb689b6fb13266956d5231afe83"
MASK = (1 << 64) - 1
BIAS = 0x9E3779B97F4A7C15
OFFSET = 0xCBF29CE484222325
PRIME = 0x100000001B3
LENGTHS = (0, 1, 4, 5, 6, 7, 8, 9, 15, 16, 17, 24)
SEEDS = (0, 1, 127, 0xFFFFFFFF, 0x8000000000000000, MASK,
         0x0123456789ABCDEF, 0xFEDCBA9876543210)
CASES = [(kind, count) for kind in
         ("words", "copy", "nested", "forward", "pointers", "named", "indirect")
         for count in LENGTHS] + [("promoted", 0), ("zero", 0), ("tail", 1)]
PROFILES = {
    "x86_64": ("x86_64", "elf_x86_64", 62, ()),
    "aarch64": ("aarch64", "aarch64elf", 183, ()),
    "riscv64-lp64": ("riscv64", "elf64lriscv", 243,
                     ("-march=rv64gc", "-mabi=lp64", "-msmall-data-limit=0")),
    "riscv64-lp64d": ("riscv64", "elf64lriscv", 243,
                      ("-march=rv64gc", "-mabi=lp64d", "-msmall-data-limit=0")),
}

PRELUDE = r"""
typedef unsigned long long u64;
typedef __builtin_va_list va_list;
#define va_start(ap,last) __builtin_va_start(ap,last)
#define va_arg(ap,type) __builtin_va_arg(ap,type)
#define va_copy(dst,src) __builtin_va_copy(dst,src)
#define va_end(ap) __builtin_va_end(ap)
static __attribute__((always_inline)) inline u64 mix(u64 h,u64 x) {
    return (h^x)*0x100000001b3ULL;
}
"""
NAMED = ",".join(f"u64 a{i}" for i in range(12))
NOISE_DECL = "extern u64 abi_clobber(" + ",".join(["u64"] * 12) + ");\n"
NOISE_CALL = "abi_clobber(" + ",".join(str(i) + "ULL" for i in range(1, 13)) + ");\n"


def provider_source():
    text = PRELUDE + NOISE_DECL + r"""
__attribute__((noinline)) u64 fold_list(unsigned count,va_list ap) {
    u64 h=0xcbf29ce484222325ULL;
    for(unsigned i=0;i<count;++i)h=mix(h,va_arg(ap,u64));
    return h;
}
u64 take_words(unsigned count,...) {
    va_list ap;va_start(ap,count);u64 h=0xcbf29ce484222325ULL;
    for(unsigned i=0;i<count;++i)h=mix(h,va_arg(ap,u64));
    va_end(ap);return h;
}
u64 take_copy(unsigned count,...) {
    va_list ap,other;va_start(ap,count);
    u64 first=count?va_arg(ap,u64):0;
    va_copy(other,ap);
""" + NOISE_CALL + r"""
    u64 left=0xcbf29ce484222325ULL,right=0xcbf29ce484222325ULL;
    for(unsigned i=1;i<count;++i)left=mix(left,va_arg(ap,u64));
    for(unsigned i=1;i<count;++i)right=mix(right,va_arg(other,u64));
    va_end(other);va_end(ap);return mix(mix(first,left),right);
}
u64 take_nested(unsigned count,...) {
""" + NOISE_CALL + r"""
    va_list ap;va_start(ap,count);u64 h=0xcbf29ce484222325ULL;
    for(unsigned i=0;i<count;++i) {
        h=mix(h,va_arg(ap,u64));
""" + NOISE_CALL + r"""
    }
    va_end(ap);return h;
}
u64 take_forward(unsigned count,...) {
    va_list ap,other;va_start(ap,count);va_copy(other,ap);
    u64 left=fold_list(count,ap),right=fold_list(count,other);
    va_end(other);va_end(ap);return mix(mix(0x1234ULL,left),right);
}
u64 take_pointers(unsigned count,...) {
    va_list ap;va_start(ap,count);u64 h=0xcbf29ce484222325ULL;
    for(unsigned i=0;i<count;++i) {
        u64 *pointer=va_arg(ap,u64*);h=mix(h,*pointer);*pointer^=0x5a5aULL;
    }
    va_end(ap);return h;
}
u64 take_promoted(unsigned cookie,...) {
    va_list ap;va_start(ap,cookie);u64 h=cookie;
    for(unsigned i=0;i<5;++i)h=mix(h,(u64)(long long)va_arg(ap,int));
    h=mix(h,(u64)va_arg(ap,unsigned int));
    h=mix(h,(u64)va_arg(ap,long long));
    h=mix(h,*va_arg(ap,u64*));va_end(ap);return h;
}
u64 take_zero(unsigned cookie,...) {
    va_list ap,copy;va_start(ap,cookie);va_copy(copy,ap);
    va_end(copy);va_end(ap);return (u64)cookie^0x123456789abcdef0ULL;
}
"""
    text += f"u64 take_named({NAMED},unsigned count,...) {{\n"
    text += "u64 h=0xcbf29ce484222325ULL;\n"
    text += "".join(f"h=mix(h,a{i});\n" for i in range(12))
    text += r"""
    va_list ap;va_start(ap,count);
    for(unsigned i=0;i<count;++i)h=mix(h,va_arg(ap,u64));
    va_end(ap);return h;
}
"""
    return text


def word(seed, index):
    return seed ^ ((BIAS * (index + 1)) & MASK)


def fold(values, initial=OFFSET):
    h = initial
    for value in values:
        h = ((h ^ (value & MASK)) * PRIME) & MASK
    return h


def oracle(kind, count, seed):
    values = [word(seed, i) for i in range(count)]
    if kind in ("words", "indirect", "nested", "tail"):
        return fold(values)
    if kind == "named":
        return fold(values, fold(word(seed, i + 100) for i in range(12)))
    if kind == "copy":
        h = fold(values[1:])
        return fold((h, h), values[0] if values else 0)
    if kind == "forward":
        h = fold(values)
        return fold((h, h), 0x1234)
    if kind == "pointers":
        # Distinct pointees make pointer identity irrelevant to ELF placement.
        return fold(word(seed, i + 100) for i in range(count))
    if kind == "promoted":
        return fold((-101, 243, -30001, 60001, 1, 0xF1234567,
                     -0x123456789AB, word(seed, 100)), 0xACE1)
    if kind == "zero":
        return 0xACE1 ^ 0x123456789ABCDEF0
    raise AssertionError(kind)


def caller_source():
    text = PRELUDE
    for name in ("words", "copy", "nested", "forward", "pointers", "promoted", "zero"):
        text += f"extern u64 take_{name}(unsigned,...);\n"
    text += f"extern u64 take_named({NAMED},unsigned,...);\n"
    text += "static u64 pointees[24];\n"
    text += "u64 tail_forward(u64 value){return take_words(1,value);}\n"
    text += "u64 variadic_case(u64 identifier,u64 seed){\n"
    text += "for(unsigned i=0;i<24;++i)pointees[i]=seed^(0x9e3779b97f4a7c15ULL*(i+101ULL));\n"
    text += "switch(identifier){\n"
    for identifier, (kind, count) in enumerate(CASES):
        words = [f"(seed^(0x9e3779b97f4a7c15ULL*{i+1}ULL))" for i in range(count)]
        args = ",".join([str(count)] + words)
        if kind == "indirect":
            body = "u64(*volatile target)(unsigned,...)=take_words;return target(" + args + ");"
        elif kind == "named":
            fixed = [f"(seed^(0x9e3779b97f4a7c15ULL*{i+101}ULL))" for i in range(12)]
            body = "return take_named(" + ",".join(fixed + [str(count)] + words) + ");"
        elif kind == "pointers":
            args = ",".join([str(count)] + [f"&pointees[{i}]" for i in range(count)])
            body = "u64 h=take_pointers(" + args + ");"
            body += "for(unsigned i=0;i<24;++i){u64 expected=seed^(0x9e3779b97f4a7c15ULL*(i+101ULL));"
            body += f"if(i<{count})expected^=0x5a5aULL;"
            body += "if(pointees[i]!=expected)return h^0xffffffffffffffffULL;}return h;"
        elif kind == "promoted":
            body = "signed char sc=-101;unsigned char uc=243;short ss=-30001;unsigned short us=60001;_Bool yes=1;"
            body += "return take_promoted(0xace1,sc,uc,ss,us,yes,0xf1234567U,-0x123456789abLL,&pointees[0]);"
        elif kind == "zero":
            body = "return take_zero(0xace1);"
        elif kind == "tail":
            body = "return tail_forward(seed^0x9e3779b97f4a7c15ULL);"
        else:
            body = f"return take_{kind}({args});"
        text += f"case {identifier}:{{{body}}}\n"
    return text + "default:return 0;}\n}\n"


def carrier_source():
    text = PRELUDE + "extern u64 variadic_case(u64,u64);\n"
    text += "static volatile u64 clobber_effect;\n"
    text += f"u64 abi_clobber({NAMED}){{u64 h=0xcbf29ce484222325ULL;\n"
    text += "".join(f"h=mix(h,a{i});\n" for i in range(12))
    text += "clobber_effect=h;return h;}\n"
    text += "static const u64 seeds[]={" + ",".join(f"{s}ULL" for s in SEEDS) + "};\n"
    text += f"static u64 output[{len(CASES)*len(SEEDS)}];\n"
    text += r"""
static long write_bytes(const void *pointer,u64 length) {
#if defined(__x86_64__)
    register long number __asm__("rax")=1;
    __asm__ volatile("syscall":"+a"(number):"D"(1L),"S"(pointer),"d"(length):"rcx","r11","memory");return number;
#elif defined(__aarch64__)
    register long x0 __asm__("x0")=1;
    register const void *x1 __asm__("x1")=pointer;
    register u64 x2 __asm__("x2")=length;
    register long x8 __asm__("x8")=64;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x8):"memory");return x0;
#else
    register long a0 __asm__("a0")=1;
    register const void *a1 __asm__("a1")=pointer;
    register u64 a2 __asm__("a2")=length;
    register long a7 __asm__("a7")=64;
    __asm__ volatile("ecall":"+r"(a0):"r"(a1),"r"(a2),"r"(a7):"memory");return a0;
#endif
}
int conformance_main(void) {
    unsigned next=0;
"""
    text += f"for(unsigned test=0;test<{len(CASES)};++test)\n"
    text += f"for(unsigned seed=0;seed<{len(SEEDS)};++seed)output[next++]=variadic_case(test,seeds[seed]);\n"
    text += "const unsigned char *p=(const unsigned char*)output;u64 left=sizeof(output);\n"
    text += "while(left){long done=write_bytes(p,left);if(done<=0)return 81;p+=done;left-=(u64)done;}return 0;}\n"
    text += r"""
#if defined(__x86_64__)
__asm__(".text\n.globl _start\n_start:\nxor %ebp,%ebp\nandq $-16,%rsp\ncall conformance_main\nmov %eax,%edi\nmov $60,%eax\nsyscall\n");
#elif defined(__aarch64__)
__asm__(".text\n.globl _start\n_start:\nmov x29,xzr\nmov x30,xzr\nbl conformance_main\nmov x8,#93\nsvc #0\n");
#else
__asm__(".text\n.globl _start\n_start:\nli s0,0\nandi sp,sp,-16\ncall conformance_main\nli a7,93\necall\n");
#endif
"""
    return text


def artifact(path):
    path = Path(path).resolve()
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for data in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(data)
    return {"path": str(path), "sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def opaque_floating_sources(profile):
    """FP values exist only in the original reference caller and consumer."""
    long_double = PROFILES[profile][0] != "x86_64"
    cases = [(0, n) for n in LENGTHS]
    if long_double:
        cases += [(1, n) for n in LENGTHS]
    wrapper = PRELUDE + r"""
extern u64 foreign_vfloating(unsigned,va_list);
u64 opaque_forward(unsigned selector,...) {
    va_list ap;va_start(ap,selector);
    u64 result=foreign_vfloating(selector,ap);va_end(ap);return result;
}
"""
    foreign = PRELUDE + r"""
extern u64 opaque_forward(unsigned,...);
static u64 dbits(u64 seed,unsigned i) {
    return ((seed^(0x9e3779b97f4a7c15ULL*(i+1ULL)))&0x000fffffffffffffULL)
        |0x3ff0000000000000ULL|(((seed^i)&1ULL)<<63);
}
static double dvalue(u64 seed,unsigned i) {union{u64 bits;double value;}v;v.bits=dbits(seed,i);return v.value;}
"""
    if long_double:
        foreign += r"""
_Static_assert(sizeof(long double)==16,"this witness requires binary128 storage");
static long double qvalue(u64 seed,unsigned i) {
    union{u64 words[2];long double value;}v;
    v.words[0]=seed^(0x9e3779b97f4a7c15ULL*(i+1ULL));
    v.words[1]=0x3fff000000000000ULL|((seed^(0x123456789abULL*(i+1ULL)))&0x0000ffffffffffffULL)
        |(((seed^i)&1ULL)<<63);return v.value;
}
"""
    foreign += "u64 foreign_vfloating(unsigned selector,va_list ap){u64 h=0xcbf29ce484222325ULL;unsigned n=selector&255;\n"
    if long_double:
        foreign += r"""
if(selector&256){for(unsigned i=0;i<n;++i){union{u64 words[2];long double value;}v;
v.value=va_arg(ap,long double);h=mix(mix(h,v.words[0]),v.words[1]);}return h;}
"""
    foreign += "for(unsigned i=0;i<n;++i){union{u64 bits;double value;}v;v.value=va_arg(ap,double);h=mix(h,v.bits);}return h;}\n"
    foreign += "u64 variadic_case(u64 identifier,u64 seed){switch(identifier){\n"
    for index, (kind, count) in enumerate(cases):
        values = [f"{'qvalue' if kind else 'dvalue'}(seed,{i})" for i in range(count)]
        foreign += f"case {index}:return opaque_forward(" + ",".join([str(kind * 256 + count)] + values) + ");\n"
    foreign += "default:return 0;}}\n"
    carrier = carrier_source().replace(f"output[{len(CASES)*len(SEEDS)}]", f"output[{len(cases)*len(SEEDS)}]")
    carrier = carrier.replace(f"test<{len(CASES)}", f"test<{len(cases)}")
    expected = []
    for kind, count in cases:
        for seed in SEEDS:
            values = []
            for i in range(count):
                sign = ((seed ^ i) & 1) << 63
                if kind:
                    values += [word(seed, i), 0x3FFF000000000000 | ((seed ^ (0x123456789AB * (i + 1))) & 0xFFFFFFFFFFFF) | sign]
                else:
                    values += [0x3FF0000000000000 | (word(seed, i) & 0xFFFFFFFFFFFFF) | sign]
            expected.append(fold(values))
    return wrapper, foreign, carrier, cases, expected


class NativeVariadicAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = os.environ.get("OCORE_TEST_OCOREC", os.environ.get("OCOREC", str(ROOT / "target/debug/ocorec")))
        cls.clang = os.environ.get("OCORE_TEST_CLANG22", str(SDK / "llvm-22/bin/clang"))
        cls.linker = os.environ.get("OCORE_TEST_LLD", shutil.which("ld.lld"))
        cls.library = os.environ.get("OCORE_TEST_LLVM_LIBRARY", str(SDK / "riscv64-linux-gnu/libLLVM.so.22.1"))
        cls.pin = os.environ.get("OCORE_TEST_LLVM_SHA256", LLVM_SHA256)
        for name, path in (("compiler", cls.compiler), ("clang", cls.clang), ("linker", cls.linker), ("library", cls.library)):
            if not path or not Path(path).is_file():
                if os.environ.get("OCORE_REQUIRE_ALL_ISAS") == "1":
                    raise AssertionError(f"selected {name} unavailable for the required complete matrix")
                raise unittest.SkipTest(f"{name} unavailable; select its explicit test tool path")
        if artifact(cls.library)["sha256"] != cls.pin:
            raise AssertionError("selected LLVM parser does not match its explicit SHA256")
        cls.environment = dict(os.environ)
        cls.environment["PATH"] = str(Path(cls.clang).parent) + os.pathsep + cls.environment.get("PATH", "")
        cls.environment["LD_LIBRARY_PATH"] = str(Path(cls.library).parent) + os.pathsep + str(SDK / "llvm-22/lib")
        version = subprocess.run([cls.clang, "--version"], capture_output=True, text=True,
                                 env=cls.environment, timeout=30)
        versions = re.findall(r"\bclang version\s+([0-9]+\.[0-9]+\.[0-9]+)(?![0-9.])", version.stdout + "\n" + version.stderr)
        if version.returncode or versions != ["22.1.6"]:
            raise AssertionError(f"selected frontend must be exactly Clang22.1.6: {version.stdout}{version.stderr}")
        cls.identities = {key: artifact(path) for key, path in
                          (("ocorec", cls.compiler), ("clang", cls.clang),
                           ("linker", cls.linker), ("llvm_library", cls.library))}

    @classmethod
    def tearDownClass(cls):
        for name, before in cls.identities.items():
            if artifact(before["path"]) != before:
                raise AssertionError(f"selected {name} changed during qualification")

    def setUp(self):
        retain = os.environ.get("OCORE_VARARGS_RETAIN")
        if retain:
            Path(retain).mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="variadic-", dir=retain))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-variadic-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.record = {"schema": "ocore-variadic-interoperability-v1", "test": self.id(),
                       "tools": self.identities, "commands": [], "pairings": [],
                       "complete": False, "native_execution_qualified": False,
                       "runtime_complete": False, "provider_closure_complete": False,
                       "execution_profile": "Linux development ELF carrier; native host or explicit QEMU"}
        self.save()

    def save(self):
        (self.directory / "report.json").write_text(json.dumps(self.record, indent=2) + "\n")

    def command(self, argv, expected=0, timeout=120):
        result = subprocess.run(list(map(str, argv)), cwd=ROOT, env=self.environment,
                                capture_output=True, timeout=timeout)
        index = len(self.record["commands"])
        stdout, stderr = self.directory / f"command-{index}.stdout", self.directory / f"command-{index}.stderr"
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        self.record["commands"].append({"argv": list(map(str, argv)), "exit_code": result.returncode,
                                        "stdout": artifact(stdout), "stderr": artifact(stderr)})
        self.save()
        self.assertEqual(result.returncode, expected, f"{argv!r}\n{result.stderr.decode(errors='replace')}")
        return result

    def importer_error(self, result):
        """Require a real importer rejection, never a loader/tool failure."""
        self.assertEqual(result.returncode, 1)
        stderr = result.stderr.decode()
        self.assertIn('{"error":', stderr)
        parsed, _ = json.JSONDecoder().raw_decode(stderr[stderr.index('{"error":'):])
        error = parsed["error"]
        self.assertEqual(error["stage"], "import")
        self.assertTrue(error["message"])
        return error

    def frontend_flags(self, profile):
        isa, _, _, flags = PROFILES[profile]
        return ["--target=" + isa + "-unknown-linux-gnu", *flags, "-O1", "-ffreestanding", "-fno-builtin",
                "-fno-stack-protector", "-fno-pic", "-fno-pie", "-fno-vectorize", "-fno-slp-vectorize"]

    def original(self, name, source, profile):
        c, llvm, obj = (self.directory / (name + extension) for extension in (".c", ".ll", ".reference.o"))
        c.write_text(source)
        self.command([self.clang, *self.frontend_flags(profile), "-S", "-emit-llvm", c, "-o", llvm])
        self.command([self.clang, *self.frontend_flags(profile), "-x", "ir", "-c", llvm, "-o", obj])
        return c, llvm, obj

    def owned(self, name, llvm, profile):
        isa = PROFILES[profile][0]
        module, verification, assembly, obj = (self.directory / (name + extension) for extension in
                                              (".native.json", ".verification.json", ".owned.s", ".owned.o"))
        self.command([self.compiler, llvm, "--input-kind", "llvm-ir", "--emit", "mir", "--target", isa + "-unknown-none",
                      "--llvm-library", self.library, "--llvm-sha256", self.pin, "-o", module])
        data = json.loads(module.read_text())
        self.assertEqual(data["provenance"]["input_sha256"], artifact(llvm)["sha256"])
        defined = set(re.findall(r"^define\b[^\n]*@([A-Za-z_.$][A-Za-z_0-9.$]*)\(", llvm.read_text(), re.M))
        self.assertEqual({f["name"] for f in data["functions"] if f["entry"] is not None}, defined)
        self.command([self.compiler, module, "--input-kind", "native-ir", "--verify-native", "--receipt", verification])
        receipt = json.loads(verification.read_text())
        self.assertIs(receipt["verified"], True)
        self.assertEqual(receipt["module_sha256"], artifact(module)["sha256"])
        self.assertEqual(len(receipt["functions"]), len(data["functions"]))
        self.command([self.compiler, module, "--input-kind", "native-ir", "--emit", "asm", "--target", isa + "-unknown-none", "-o", assembly])
        self.command([self.clang, *self.frontend_flags(profile), "-x", "assembler", "-c", assembly, "-o", obj])
        self.assert_elf(obj, PROFILES[profile][2], 1)
        self.record.setdefault("owned_modules", []).append({"input": artifact(llvm), "module": artifact(module),
            "verification": artifact(verification), "assembly": artifact(assembly), "object": artifact(obj),
            "original_defined_functions": sorted(defined)})
        self.save()
        return obj

    def assert_elf(self, path, machine, kind):
        header = Path(path).read_bytes()[:64]
        self.assertEqual(header[:6], b"\x7fELF\x02\x01")
        self.assertEqual(struct.unpack_from("<HH", header, 16), (kind, machine))

    def execution_prefix(self, isa):
        host = platform.machine().lower()
        native = {"x86_64": ("x86_64", "amd64"), "aarch64": ("aarch64", "arm64"), "riscv64": ("riscv64",)}
        if host in native[isa]:
            return []
        emulator = shutil.which("qemu-" + isa)
        if not emulator:
            if os.environ.get("OCORE_REQUIRE_ALL_ISAS") == "1":
                self.fail(f"qemu-{isa} required for the requested complete matrix")
            self.skipTest(f"qemu-{isa} unavailable for the nonhost ISA")
        return [emulator]

    def check_profile(self, profile, reference_only=False):
        isa, mode, machine, _ = PROFILES[profile]
        runner = self.execution_prefix(isa)
        self.record.update(profile=profile, execution_argv_prefix=runner, reference_only=reference_only)
        provider_c, provider_ll, provider_ref = self.original("provider", provider_source(), profile)
        caller_c, caller_ll, caller_ref = self.original("caller", caller_source(), profile)
        carrier_c, _, carrier_obj = self.original("carrier", carrier_source(), profile)
        before = [artifact(p) for p in (provider_c, provider_ll, caller_c, caller_ll, carrier_c)]
        self.record["original_inputs"] = before
        self.assertIn("@llvm.va_start", provider_ll.read_text())
        self.assertIn("@llvm.va_end", provider_ll.read_text())
        # Clang's target frontend may lower va_copy as a memory copy instead of
        # preserving an intrinsic; the unchanged source always exercises it.
        self.assertIn("va_copy(other,ap)", provider_c.read_text())
        self.assertRegex(caller_ll.read_text(), r"\btail call\b")
        provider_own = None if reference_only else self.owned("provider", provider_ll, profile)
        caller_own = None if reference_only else self.owned("caller", caller_ll, profile)
        expected_values = [oracle(kind, count, seed) for kind, count in CASES for seed in SEEDS]
        expected = struct.pack("<" + "Q" * len(expected_values), *expected_values)
        self.record.update(cases_per_pairing=len(expected_values), source_cases=CASES,
                           seeds=list(SEEDS), expected_output_sha256=hashlib.sha256(expected).hexdigest())
        callers = (("reference", caller_ref),) if reference_only else (("reference", caller_ref), ("owned", caller_own))
        providers = (("reference", provider_ref),) if reference_only else (("reference", provider_ref), ("owned", provider_own))
        for caller_name, caller in callers:
            for provider_name, provider in providers:
                executable = self.directory / f"{caller_name}-caller-{provider_name}-provider.elf"
                self.command([self.linker, "-static", "--no-relax", "-m", mode, "-e", "_start",
                              carrier_obj, caller, provider, "-o", executable])
                self.assert_elf(executable, machine, 2)
                result = self.command([*runner, executable], timeout=30)
                if result.stdout != expected:
                    actual = list(struct.unpack("<" + "Q" * (len(result.stdout) // 8), result.stdout)) if len(result.stdout) % 8 == 0 else []
                    mismatch = next((i for i, (a, b) in enumerate(zip(actual, expected_values)) if a != b), min(len(actual), len(expected_values)))
                    case = CASES[mismatch // len(SEEDS)] if mismatch < len(expected_values) else None
                    self.fail(f"{profile} {caller_name}/{provider_name}: first mismatch {mismatch}, case={case}; actual bytes={len(result.stdout)}, expected bytes={len(expected)}")
                self.record["pairings"].append({"caller": caller_name, "provider": provider_name,
                    "caller_object": artifact(caller), "provider_object": artifact(provider),
                    "carrier_object": artifact(carrier_obj), "executable": artifact(executable),
                    "comparisons": len(expected_values), "stdout_sha256": hashlib.sha256(result.stdout).hexdigest()})
                self.save()
        self.assertEqual([artifact(p["path"]) for p in before], before)
        self.record["reference_control_complete"] = True
        self.record["complete"] = not reference_only
        self.save()

    def test_x86_64_integer_pointer_interoperability(self):
        self.check_profile("x86_64")

    def test_aarch64_integer_pointer_interoperability(self):
        self.check_profile("aarch64")

    def test_riscv64_lp64_integer_pointer_interoperability(self):
        self.check_profile("riscv64-lp64")

    def test_riscv64_lp64d_integer_pointer_interoperability(self):
        self.check_profile("riscv64-lp64d")

    def test_reference_floating_callers_cross_owned_opaque_va_list_wrapper(self):
        self.record.update(opaque_floating_forwarding=True, owned_floating_caller=False,
                           owned_first_class_floating_values=False)
        for profile, (isa, mode, machine, _) in PROFILES.items():
            with self.subTest(profile=profile):
                runner = self.execution_prefix(isa)
                wrapper, foreign, carrier, cases, values = opaque_floating_sources(profile)
                wc, wl, wr = self.original("opaque-wrapper-" + profile, wrapper, profile)
                fc, fl, fo = self.original("floating-reference-" + profile, foreign, profile)
                cc, _, co = self.original("floating-carrier-" + profile, carrier, profile)
                originals = [artifact(p) for p in (wc, wl, fc, fl, cc)]
                wo = self.owned("opaque-wrapper-" + profile, wl, profile)
                module = json.loads((self.directory / ("opaque-wrapper-" + profile + ".native.json")).read_text())
                self.assertFalse(any(t["kind"] == "float" for t in module["types"]),
                                 "the owned wrapper must have no first-class FP type")
                expected = struct.pack("<" + "Q" * len(values), *values)
                for ownership, obj in (("reference", wr), ("owned", wo)):
                    executable = self.directory / f"opaque-{profile}-{ownership}.elf"
                    self.command([self.linker, "-static", "--no-relax", "-m", mode, "-e", "_start",
                                  co, fo, obj, "-o", executable])
                    self.assert_elf(executable, machine, 2)
                    result = self.command([*runner, executable], timeout=30)
                    self.assertEqual(result.stdout, expected,
                                     f"{profile}/{ownership} opaque FP forwarding disagrees with bit oracle")
                    self.record["pairings"].append({"scope": "opaque-fp-va-list-forwarding",
                        "profile": profile, "caller": "reference", "consumer": "reference",
                        "wrapper": ownership, "wrapper_object": artifact(obj),
                        "foreign_object": artifact(fo), "executable": artifact(executable),
                        "source_cases": cases, "comparisons": len(values),
                        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest()})
                    self.save()
                self.assertEqual([artifact(p["path"]) for p in originals], originals)
                self.record.setdefault("opaque_reference_only_inputs", []).append({
                    "profile": profile, "originals": originals,
                    "owned_floating_caller": False, "owned_first_class_floating_values": False})
                self.save()
        self.record["complete"] = len(self.record.get("opaque_reference_only_inputs", [])) == len(PROFILES)
        self.save()

    def test_default_promoted_float_extra_argument_requires_float_abi(self):
        source = PRELUDE + "extern u64 sink(unsigned,...);u64 bad(void){return sink(1,1.25f);}\n"
        for profile in ("x86_64", "aarch64", "riscv64-lp64d"):
            with self.subTest(profile=profile):
                _, llvm, _ = self.original("float-" + profile, source, profile)
                self.assertRegex(llvm.read_text(), r"@sink\(i32[^\n]*double")
                output = llvm.with_suffix(".native.json")
                result = self.command([self.compiler, llvm, "--input-kind", "llvm-ir", "--emit", "mir", "--target",
                    PROFILES[profile][0] + "-unknown-none", "--llvm-library", self.library, "--llvm-sha256", self.pin, "-o", output], expected=1)
                error = self.importer_error(result)
                self.assertIn("unsupported LLVM type kind 3", error["message"])
                self.assertFalse(output.exists())
        self.record["complete"] = True
        self.save()

    def test_clang_x86_byval_ellipsis_argument_requires_aggregate_abi(self):
        # This genuine Clang form carries its aggregate contract on an actual
        # trailing operand, outside Signature.param_attributes' fixed prefix.
        source = PRELUDE + r"""
struct Big {u64 words[3];};
extern u64 sink(unsigned,...);
u64 bad(u64 value){struct Big data={{value,value+1,value+2}};return sink(1,data);}
"""
        _, llvm, _ = self.original("byval-extra", source, "x86_64")
        self.assertRegex(llvm.read_text(), r"@sink\(i32[^\n]*byval\(")
        output = llvm.with_suffix(".native.json")
        result = self.command([self.compiler, llvm, "--input-kind", "llvm-ir", "--emit", "mir",
            "--target", "x86_64-unknown-none", "--llvm-library", self.library,
            "--llvm-sha256", self.pin, "-o", output], expected=1)
        error = self.importer_error(result)
        self.assertEqual(error["message"], "unsupported attribute kind 84 at index 2")
        self.assertFalse(output.exists())
        self.record["complete"] = True
        self.save()


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--reference-only":
        output = Path(sys.argv[2]).resolve()
        output.mkdir(parents=True, exist_ok=False)
        os.environ["OCORE_VARARGS_RETAIN"] = str(output)
        NativeVariadicAbiTests.setUpClass()
        rows = []
        try:
            for profile in PROFILES:
                test = NativeVariadicAbiTests("test_x86_64_integer_pointer_interoperability")
                test.setUp()
                test.check_profile(profile, reference_only=True)
                row = {"profile": profile, "report": artifact(test.directory / "report.json"),
                       "reference_comparisons": len(CASES) * len(SEEDS)}
                rows.append(row)
                print(json.dumps(row), flush=True)
            summary = {"schema": "ocore-variadic-reference-controls-v1", "profiles": rows,
                       "owned_compilation_attempted": False, "runtime_complete": False}
            (output / "reference-controls.json").write_text(json.dumps(summary, indent=2) + "\n")
        finally:
            NativeVariadicAbiTests.tearDownClass()
    else:
        unittest.main()
