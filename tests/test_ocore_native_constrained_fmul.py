"""Whole original musl units exercising generic constrained scalar multiplication.

Provided original musl source and exact Clang22 are prerequisites. These hosted
Linux tests do not lower libc/fenv providers or qualify foreign-ISA execution.
All foreign objects are guarded from host execution; absence is an unmet gate.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import struct
import tempfile
import unittest

from tests.ocore_llvm_source_inventory import Reader, check_inventory, InventoryMismatch

ROOT = Path(__file__).resolve().parents[1]
MUSL = "0784374d561435f7c787a555aeab8ede699ed298"
NAMES = ("scalbn", "scalbnf", "__math_xflow", "__math_xflowf")
PROFILES = {"x86_64": ("x86_64-unknown-linux-musl", []),
            "aarch64": ("aarch64-unknown-linux-musl", []),
            "riscv64": ("riscv64-unknown-linux-musl", ["-march=rv64gc", "-mabi=lp64d"])}

def identity(path):
    path = Path(path).resolve()
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}



def require_elf_arch(path, isa, kinds):
    raw=Path(path).read_bytes()
    expected={"x86_64":62,"aarch64":183,"riscv64":243}[isa]
    if raw[:6]!=b"\x7fELF\x02\x01" or struct.unpack_from("<H",raw,18)[0]!=expected or struct.unpack_from("<H",raw,16)[0] not in kinds:
        raise AssertionError("native ELF machine/class/endian/profile mismatch before execution")

def require_catalog_profiles(catalog):
    expected={"x86_64":"x86_64", "aarch64":"aarch64", "rv64gc":"riscv64"}
    if catalog.get("schema")!="ocore-target-catalog-v1":
        raise AssertionError("canonical target catalog schema is missing")
    rows=catalog["targets"]
    if (len(rows)!=len(expected) or {row["id"] for row in rows}!=set(expected)
            or any(expected.get(row["id"])!=row["architecture"] or row["architecture"] not in PROFILES for row in rows)):
        raise AssertionError("uncovered canonical constrained-FP target/profile")

CARRIER = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fenv.h>
#pragma STDC FENV_ACCESS ON
extern double reference_scalbn(double,int),owned_scalbn(double,int);
extern float reference_scalbnf(float,int),owned_scalbnf(float,int);
extern double reference___math_xflow(unsigned,double),owned___math_xflow(unsigned,double);
extern float reference___math_xflowf(unsigned,float),owned___math_xflowf(unsigned,float);
static const uint64_t d[]={0,0x8000000000000000ULL,1,0xfffffffffffffULL,0x10000000000000ULL,0x3ff0000000000000ULL,0xbff0000000000000ULL,0x3ff0000000000001ULL,0x7fefffffffffffffULL,0xffefffffffffffffULL,0x7ff0000000000000ULL,0xfff0000000000000ULL,0x7ff8000000001234ULL,0xfff8000000004321ULL,0x7ff0000000001234ULL,0xfff0000000004321ULL};
static const uint32_t f[]={0,0x80000000U,1,0x7fffffU,0x800000U,0x3f800000U,0xbf800000U,0x3f800001U,0x7f7fffffU,0xff7fffffU,0x7f800000U,0xff800000U,0x7fc01234U,0xffc04321U,0x7f801234U,0xff804321U};
static const int exponents[]={-2147483647-1,-3000,-2100,-1076,-1075,-1074,-1073,-1023,-1022,-1000,-150,-149,-148,-127,-126,-1,0,1,127,128,1023,1024,2046,3000,2147483647};
struct outcome {uint64_t bits;unsigned flags,mxcsr;unsigned short cw,sw;int mode;};
static void context(struct outcome *v){
 v->flags=(unsigned)fetestexcept(FE_ALL_EXCEPT);v->mode=fegetround();
#if defined(__x86_64__)
 __asm__ volatile("stmxcsr %0":"=m"(v->mxcsr));__asm__ volatile("fnstcw %0":"=m"(v->cw));__asm__ volatile("fnstsw %0":"=m"(v->sw));
#elif defined(__aarch64__)
 uint64_t control,status;__asm__ volatile("mrs %0,fpcr":"=r"(control));__asm__ volatile("mrs %0,fpsr":"=r"(status));v->mxcsr=(unsigned)control;v->cw=(unsigned short)status;v->sw=(unsigned short)(status>>16);
#elif defined(__riscv) && __riscv_xlen==64 && __riscv_flen==64
 unsigned csr;__asm__ volatile("frcsr %0":"=r"(csr));v->mxcsr=csr;v->cw=0;v->sw=0;
#else
#error A matching declared native FP environment carrier is required
#endif
}
static struct outcome call(unsigned which,int original,uint64_t bits,int n,int mode,int seed){
 if(fesetround(mode)||feclearexcept(FE_ALL_EXCEPT)||feraiseexcept(seed))exit(91);
 struct outcome out={0};
 if(which&1){union{uint32_t u;float v;}x={(uint32_t)bits},y;
 y.v=which==1?(original?reference_scalbnf(x.v,n):owned_scalbnf(x.v,n)):(original?reference___math_xflowf((unsigned)n,x.v):owned___math_xflowf((unsigned)n,x.v));out.bits=y.u;
 }else{union{uint64_t u;double v;}x={bits},y;
 y.v=which==0?(original?reference_scalbn(x.v,n):owned_scalbn(x.v,n)):(original?reference___math_xflow((unsigned)n,x.v):owned___math_xflow((unsigned)n,x.v));out.bits=y.u;}
 context(&out);return out;
}
int main(void){
 const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};const int seeds[]={0,FE_INVALID,FE_OVERFLOW|FE_INEXACT};
 unsigned cases=0;fenv_t saved;if(fegetenv(&saved))return 91;
 for(unsigned which=0;which<4;which++)for(unsigned m=0;m<4;m++)for(unsigned s=0;s<3;s++)for(unsigned i=0;i<16;i++)for(unsigned e=0;e<(which<2?sizeof exponents/sizeof exponents[0]:2);e++){
 uint64_t bits=(which&1)?f[i]:d[i];int n=which<2?exponents[e]:(int)e;
 struct outcome a=call(which,1,bits,n,modes[m],seeds[s]);struct outcome b=call(which,0,bits,n,modes[m],seeds[s]);
 printf("%u %u %u %016llx %d %016llx %x %x %x %x %x %016llx %x %x %x %x %x\n",which,m,s,(unsigned long long)bits,n,(unsigned long long)a.bits,a.flags,a.mxcsr,a.cw,a.sw,a.mode,(unsigned long long)b.bits,b.flags,b.mxcsr,b.cw,b.sw,b.mode);
 if(a.bits!=b.bits||a.flags!=b.flags||a.mxcsr!=b.mxcsr||a.cw!=b.cw||a.sw!=b.sw||a.mode!=b.mode){fprintf(stderr,"constrained multiply mismatch case=%u function=%u mode=%u seed=%u input=%016llx n=%d\n",cases,which,m,s,(unsigned long long)bits,n);fesetenv(&saved);return 93;}
 cases++;
 }
 if(fesetenv(&saved))return 91;fprintf(stderr,"constrained multiply exact cases=%u\n",cases);return 0;
}
'''

class ConstrainedMultiplyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec")).resolve()
        cls.source = Path(os.environ.get("OCORE_MUSL_SOURCE", "/missing"))
        cls.clang = Path(os.environ.get("OCORE_TEST_CLANG", shutil.which("clang") or "/missing")).resolve()
        cls.nm = Path(os.environ.get("OCORE_TEST_LLVM_NM", cls.clang.parent / "llvm-nm")).resolve()
        cls.objcopy = Path(os.environ.get("OCORE_TEST_LLVM_OBJCOPY", cls.clang.parent / "llvm-objcopy")).resolve()
        cls.objdump = Path(os.environ.get("OCORE_TEST_LLVM_OBJDUMP", cls.clang.parent / "llvm-objdump")).resolve()
        cls.library = Path(os.environ.get("OCORE_TEST_LLVM_LIBRARY", "/missing")).resolve()
        cls.library_sha = os.environ.get("OCORE_TEST_LLVM_SHA256", "")
        if any(not p.is_file() for p in (cls.compiler, cls.clang, cls.nm, cls.objcopy, cls.objdump, cls.library)) or not (cls.source/"configure").is_file():
            if os.environ.get("OCORE_CONSTRAINED_FP_REQUIRED") == "1":
                raise AssertionError("mandatory constrained FP prerequisites are missing")
            raise unittest.SkipTest("provided pinned musl/Clang22/LLVM/compiler prerequisites are required")
        if os.environ.get("OCOREC_BIN_SHA256") and identity(cls.compiler)["sha256"] != os.environ["OCOREC_BIN_SHA256"]:
            raise AssertionError("selected compiler digest changed")
        assert identity(cls.library)["sha256"] == cls.library_sha
        assert subprocess.check_output(["git", "-C", cls.source, "rev-parse", "HEAD"]).decode().strip() == MUSL
        assert not subprocess.check_output(["git", "-C", cls.source, "status", "--porcelain"])
        version = subprocess.check_output([cls.clang, "--version"]).decode()
        assert re.findall(r"clang version (\d+\.\d+\.\d+)", version) == ["22.1.6"]
        selected = os.environ.get("OCORE_CONSTRAINED_FP_OUTPUT")
        cls.cleanup = None if selected else tempfile.TemporaryDirectory(prefix="ocore-constrained-fmul-")
        cls.out = Path(selected or cls.cleanup.name)
        if selected: cls.out.mkdir(exist_ok=False)
        cls.commands, cls.units = [], {}
        cls.pins = [identity(p) for p in (cls.compiler, cls.clang, cls.nm, cls.objcopy, cls.objdump, cls.library,
                    ROOT/"scripts/ocore_llvm_import.py", ROOT/"tests/ocore_llvm_source_inventory.py", Path(__file__))]
        cls.pins += [identity(cls.source/"src/math"/(n+".c")) for n in (*NAMES,"scalbnl")]
        cls.reader = Reader(cls.library, cls.library_sha)
        cls.catalog=json.loads(cls.command("canonical-targets",[cls.compiler,"--list-targets"]).stdout)
        require_catalog_profiles(cls.catalog)
        cls.prepare_profiles()

    @classmethod
    def command(cls, name, argv, *, cwd=None, expected=0):
        environment = dict(os.environ)
        environment.update(CFLAGS="", CPPFLAGS="", LDFLAGS="")
        result = subprocess.run(list(map(str, argv)), cwd=cwd or cls.out, capture_output=True, timeout=120, env=environment)
        a,b=cls.out/(name+".stdout"),cls.out/(name+".stderr");a.write_bytes(result.stdout);b.write_bytes(result.stderr)
        cls.commands.append({"name":name,"argv":list(map(str,argv)),"cwd":str(cwd or cls.out),"status":result.returncode,"stdout":identity(a),"stderr":identity(b)})
        (cls.out/"commands.json").write_text(json.dumps(cls.commands,indent=2)+"\n")
        if expected is not None and result.returncode != expected:
            raise AssertionError(name+": "+str(result.returncode)+" "+result.stderr.decode(errors="replace"))
        return result

    @classmethod
    def prepare_profiles(cls):
        for isa,(triple,flags) in PROFILES.items():
            build=cls.out/isa;build.mkdir();cc=[str(cls.clang),"--target="+triple,*flags,"-Qunused-arguments","-fuse-ld=lld"]
            cls.command(isa+"-configure",[cls.source/"configure","--srcdir="+str(cls.source),"--target="+triple,"--enable-static","--disable-shared","--prefix="+str(build/"install"),"CC="+shlex.join(cc),"AR="+str(cls.clang.parent/"llvm-ar"),"RANLIB="+str(cls.clang.parent/"llvm-ranlib")],cwd=build)
            cls.command(isa+"-headers",["make","obj/include/bits/alltypes.h","obj/include/bits/syscall.h","obj/src/internal/version.h"],cwd=build)
            for name in (*NAMES,"scalbnl"):
                source=cls.source/"src/math"/(name+".c")
                plan=cls.command(isa+"-"+name+"-plan",["make","-n",f"obj/src/math/{name}.lo"],cwd=build).stdout.decode()
                commands=[shlex.split(line) for line in plan.splitlines() if str(source) in line and " -c " in " "+line+" "]
                assert len(commands)==1;argv=commands[0];at=argv.index("-o");del argv[at:at+2];argv.remove("-c")
                ir=build/(name+".ll");ref=build/(name+".reference.o")
                cls.command(isa+"-"+name+"-frontend",[*argv,"-S","-emit-llvm","-o",ir],cwd=build)
                cls.command(isa+"-"+name+"-reference",[*argv,"-c","-o",ref],cwd=build)
                cls.units[isa,name]={"source":source,"ir":ir,"reference":ref}
                if name=="scalbnl":continue
                module=build/(name+".native.json");receipt=build/(name+".verification.json");assembly=build/(name+".s");obj=build/(name+".owned.o")
                imported=cls.command(isa+"-"+name+"-import",[cls.compiler,ir,"--input-kind","llvm-ir","--emit","mir","--target",isa+"-unknown-none","--llvm-library",cls.library,"--llvm-sha256",cls.library_sha,"-o",module],expected=None)
                if imported.returncode:
                    raise AssertionError(isa+"/"+name+": "+imported.stderr.decode(errors="replace"))
                cls.command(isa+"-"+name+"-verify",[cls.compiler,module,"--input-kind","native-ir","--verify-native","--receipt",receipt])
                data=json.loads(module.read_text());original=cls.reader.read(ir);preserved=check_inventory(original,data)
                (build/(name+".source-inventory.json")).write_text(json.dumps(original,indent=2)+"\n")
                (build/(name+".source-preservation.json")).write_text(json.dumps(preserved,indent=2)+"\n")
                cls.command(isa+"-"+name+"-emit",[cls.compiler,module,"--input-kind","native-ir","--emit","asm","--target",isa+"-unknown-none","-o",assembly])
                cls.command(isa+"-"+name+"-assemble",[cls.clang,"--target="+triple,*flags,"-c","-x","assembler",assembly,"-o",obj])
                cls.units[isa,name].update(module=module,assembly=assembly,owned=obj,inventory=original)

    @classmethod
    def tearDownClass(cls):
        after=[identity(v["path"]) for v in cls.pins]
        matrix=[{"isa":isa,"unit":name,"IR":identity(unit["ir"]),"original_object":identity(unit["reference"]),"status":"UNMET" if "unmet" in unit else "owned-object-only" if "owned" in unit else "long-double-UNMET", "reason":unit.get("unmet"),"owned":identity(unit["owned"]) if "owned" in unit else None} for (isa,name),unit in cls.units.items()]
        (cls.out/"result.json").write_text(json.dumps({"schema":"ostadix.constrained-mul-focused-tests/v1","commands":cls.commands,"inputs_before":cls.pins,"inputs_after":after,"inputs_unchanged":after==cls.pins,"scope":__doc__,"unit_target_matrix":matrix,"canonical_target_catalog":cls.catalog,"required_unimplemented_target_foundations":["i686","armv7"],"overall_whole_unit_ISA_qualification":False,"FP_kernel_activation":False,"full_musl_lowering":False,"foreign_ISA_native_execution":False},indent=2)+"\n")
        assert after==cls.pins
        if cls.cleanup:cls.cleanup.cleanup()

    def test_added_canonical_backend_requires_coverage(self):
        require_catalog_profiles(self.catalog)
        added=copy.deepcopy(self.catalog)
        added["targets"].append({"id":"added-backend","architecture":"new-isa","target":"new-isa-unknown-none"})
        with self.assertRaisesRegex(AssertionError,"uncovered canonical"):
            require_catalog_profiles(added)
        # Another backend sharing an architecture must not disappear in a set.
        alias=copy.deepcopy(self.catalog)
        alias["targets"].append({"id":"rv64-added-abi","architecture":"riscv64","target":"riscv64-unknown-none"})
        with self.assertRaisesRegex(AssertionError,"uncovered canonical"):
            require_catalog_profiles(alias)

    def test_whole_unit_objects_and_target_rounding(self):
        for isa in PROFILES:
            for name in NAMES:
                unit=self.units[isa,name]
                data=json.loads(unit["module"].read_text())
                has_barrier = 'asm sideeffect "", "=w,0"' in unit["ir"].read_text()
                expected_profile = "scalar_dynamic_mul_register_barrier_v1" if has_barrier else "scalar_dynamic_mul_v1"
                self.assertEqual(data["target"]["strict_fp_profile"], expected_profile)
                for kind in ("reference","owned"):
                    require_elf_arch(unit[kind],isa,{1})
                    result=self.command(isa+name+kind+"-undefined",[self.nm,"-u",unit[kind]])
                    self.assertEqual(result.stdout,b"")
                asm=unit["assembly"].read_text()
                self.assertIn("fmul.",asm) if isa=="riscv64" else self.assertIn("fmul" if isa=="aarch64" else "mul",asm)
                if isa=="riscv64":
                    self.assertIn(", dyn",asm)
                    self.assertNotRegex(asm,r"fmul\.[sd][^\n]*, rne")
                    dis=self.command(name+"-rv-disassembly",[self.objdump,"-d",unit["owned"]]).stdout.decode()
                    words=re.findall(r"^\s*[0-9a-f]+:\s+([0-9a-f]{8})\s+fmul\.[sd]\b",dis,re.M)
                    self.assertTrue(words,"actual RV multiply machine instructions must exist")
                    self.assertTrue(all((int(word,16)>>12)&7==7 for word in words),"actual RV rm must encode DYN=111")

    def test_actual_host_original_bits_rounding_and_flags(self):
        host = {"x86_64":"x86_64", "aarch64":"aarch64", "riscv64":"riscv64"}.get(platform.machine())
        if platform.system()!="Linux" or host is None:
            self.fail("native gate requires a matching declared Linux ISA; foreign machine code must not execute")
        caller=self.out/"caller.c";caller.write_text(CARRIER)
        objects=[]
        for name in NAMES:
            for key,prefix in (("reference","reference_"),("owned","owned_")):
                self.assertNotIn("unmet",self.units[host,name],"native whole-unit execution remains UNMET on this host profile")
                src=self.units[host,name][key];obj=self.out/(name+"."+key+".renamed.o")
                self.command(name+key+"-symbols",[self.objcopy,"--prefix-symbols="+prefix,src,obj]);objects.append(obj)
        binary=self.out/("oracle-"+host)
        self.command("native-oracle-link",[self.clang,"-O2","-frounding-math","-ffp-contract=off",caller,*objects,"-lm","-o",binary])
        require_elf_arch(binary,host,{2,3})
        r=self.command("native-oracle-execute",[binary])
        self.assertEqual(r.stderr,b"constrained multiply exact cases=10368\n")
        self.assertEqual(len(r.stdout.splitlines()),10368)
        self.assertTrue(all(len(row.split())==17 for row in r.stdout.splitlines()))

    def test_fixed_rounding_mutant_has_exact_semantic_failure(self):
        if platform.system()!="Linux" or platform.machine()!="x86_64":
            self.fail("fixed-rounding emitted-assembly control currently requires its actual x86 host")
        assembly=self.units["x86_64","scalbn"]["assembly"].read_text()
        def fixed(match):
            return ("  sub rsp, 16\n  stmxcsr dword ptr [rsp]\n  mov eax, dword ptr [rsp]\n"
                    "  and eax, 0xffff9fff\n  mov dword ptr [rsp+4], eax\n  ldmxcsr dword ptr [rsp+4]\n"
                    +match.group(0)+"\n  stmxcsr dword ptr [rsp+8]\n  mov eax, dword ptr [rsp+8]\n"
                    "  and eax, 63\n  or dword ptr [rsp], eax\n  ldmxcsr dword ptr [rsp]\n  add rsp, 16")
        mutated,count=re.subn(r"  mulsd xmm14, xmm15",fixed,assembly)
        self.assertGreater(count,0)
        source=self.out/"fixed-rne.s";source.write_text(mutated);obj=self.out/"fixed-rne.o"
        self.command("fixed-rne-assemble",[self.clang,"-c","-x","assembler",source,"-o",obj])
        caller=self.out/"mutant-caller.c";caller.write_text(CARRIER);objects=[]
        for name in NAMES:
            for key,prefix in (("reference","reference_"),("owned","owned_")):
                src=obj if name=="scalbn" and key=="owned" else self.units["x86_64",name][key]
                renamed=self.out/("mutant-"+name+"."+key+".o")
                self.command("mutant-"+name+key+"-rename",[self.objcopy,"--prefix-symbols="+prefix,src,renamed]);objects.append(renamed)
        binary=self.out/"fixed-rne-mutant"
        self.command("fixed-rne-link",[self.clang,"-O2","-frounding-math","-ffp-contract=off",caller,*objects,"-lm","-o",binary])
        require_elf_arch(binary,"x86_64",{2,3})
        result=self.command("fixed-rne-semantic-control",[binary],expected=93)
        self.assertRegex(result.stderr,rb"^constrained multiply mismatch case=\d+ function=0 mode=\d+ seed=\d+ input=[0-9a-f]{16} n=-?\d+\n$")
        last=result.stdout.splitlines()[-1].split()
        self.assertNotEqual(last[5],last[11],"the oracle must detect wrong result bits, not an unrelated error")
        self.assertEqual(last[10],last[16],"mutant restores caller rounding control")

    def test_independent_inventory_refuses_corruptions(self):
        unit=self.units["x86_64","scalbn"];module=json.loads(unit["module"].read_text());original=unit["inventory"]
        mutations=[]
        bad=copy.deepcopy(module);bad["target"]["strict_fp_profile"]="integer_only_v1";mutations.append(bad)
        bad=copy.deepcopy(module);f=next(f for f in bad["functions"] if (f.get("intrinsic") or "").startswith("llvm.experimental.constrained.fmul"));f["signature"]["params"].pop();mutations.append(bad)
        bad=copy.deepcopy(module);instruction=next(i for f in bad["functions"] for b in f["blocks"] for i in b["instructions"] if i["operation"]["op"]=="constrained_float_binary");instruction["operation"]["rounding"]="tonearest";mutations.append(bad)
        bad=copy.deepcopy(module);instruction=next(i for f in bad["functions"] for b in f["blocks"] for i in b["instructions"] if i["operation"]["op"]=="constrained_float_binary");instruction["operation"]={"op":"freeze","value":instruction["operation"]["lhs"]};mutations.append(bad)
        for bad in mutations:
            with self.assertRaises(InventoryMismatch):check_inventory(original,bad)
        src=copy.deepcopy(original);site=next(s for f in src["functions"].values() for s in f["intrinsic_sites"] if s["name"].startswith("llvm.experimental.constrained.fmul"));site["args"][2]["mdstring_bytes"]=list(b"round.tonearest")
        with self.assertRaises(InventoryMismatch):check_inventory(src,module)
        for field,value in (("actual_intrinsic_id",0),("enclosing_strictfp",False),("call_or_declaration_strictfp",False)):
            src=copy.deepcopy(original)
            site=next(s for f in src["functions"].values() for s in f["intrinsic_sites"] if s["name"].startswith("llvm.experimental.constrained.fmul"))
            site["constrained_fp_source"][field]=value
            with self.assertRaises(InventoryMismatch):check_inventory(src,module)

    def test_actual_source_fast_math_cannot_evade_independent_inventory(self):
        unit=self.units["x86_64","scalbn"];text=unit["ir"].read_text()
        fast=text.replace("tail call double @llvm.experimental.constrained.fmul", "tail call fast double @llvm.experimental.constrained.fmul")
        self.assertNotEqual(text,fast)
        f=self.out/"actual-fast-call.ll";f.write_text(fast)
        original=self.reader.read(f)
        actual=[site["fast_math"] for fun in original["functions"].values() for site in fun["intrinsic_sites"] if site["name"].startswith("llvm.experimental.constrained.fmul")]
        self.assertTrue(actual and all(value==127 for value in actual))
        module=json.loads(unit["module"].read_text());module["provenance"]["input_sha256"]=identity(f)["sha256"]
        with self.assertRaisesRegex(InventoryMismatch,"constrained multiply"):
            check_inventory(original,module)
        result=self.command("actual-fast-source-refuse",[self.compiler,f,"--input-kind","llvm-ir","--emit","mir","--target","x86_64-unknown-none","--llvm-library",self.library,"--llvm-sha256",self.library_sha,"-o",self.out/"fast.rejected.json"],expected=1)
        self.assertIn(b"nonzero fast-math",result.stderr)
        self.assertFalse((self.out/"fast.rejected.json").exists())

    def test_genuine_intrinsic_and_metadata_source_boundaries(self):
        unit=self.units["x86_64","scalbn"];original=unit["ir"].read_text()
        variants={
            "metadata-tuple":(original.replace('metadata !"round.dynamic"','metadata !{!"round.dynamic"}'),b"invalid rounding mode argument"),
            "ordinary-fake":(original.replace('@llvm.experimental.constrained.fmul.f64','@fake_constrained_fmul'),b"metadata parameter but isn't an intrinsic"),
            "wrong-family":(original.replace('@llvm.experimental.constrained.fmul.f64','@llvm.experimental.constrained.fdiv.f64'),b"intrinsic llvm.experimental.constrained.fdiv.f64 requires explicit call lowering")}
        for name,(text,diagnostic) in variants.items():
            f=self.out/(name+".ll");f.write_text(text);output=self.out/(name+".refused.json")
            result=self.command(name+"-genuine-boundary",[self.compiler,f,"--input-kind","llvm-ir","--emit","mir","--target","x86_64-unknown-none","--llvm-library",self.library,"--llvm-sha256",self.library_sha,"-o",output],expected=1)
            self.assertIn(diagnostic,result.stderr);self.assertFalse(output.exists())
        # LLVM22 canonicalizes an incorrectly spelled overloaded name to its
        # actual type. This is not a fabricated-ID refusal: bind original bytes
        # and independently verify the genuine parsed f64 declaration instead.
        normalized=original.replace('@llvm.experimental.constrained.fmul.f64','@llvm.experimental.constrained.fmul.f32')
        f=self.out/"canonicalized-overload.ll";f.write_text(normalized);output=self.out/"canonicalized-overload.json"
        self.command("canonicalized-overload",[self.compiler,f,"--input-kind","llvm-ir","--emit","mir","--target","x86_64-unknown-none","--llvm-library",self.library,"--llvm-sha256",self.library_sha,"-o",output])
        module=json.loads(output.read_text());self.assertEqual(module["provenance"]["input_sha256"],identity(f)["sha256"])
        self.assertTrue(any(fun["name"]=="llvm.experimental.constrained.fmul.f64" for fun in module["functions"]))
        check_inventory(self.reader.read(f),module)

    def test_source_and_native_contract_rejections(self):
        ir=self.units["x86_64","scalbn"]["ir"].read_text()
        variants={"rounding":ir.replace('!"round.dynamic"','!"round.tonearest"'),"exceptions":ir.replace('!"fpexcept.ignore"','!"fpexcept.strict"'),"definition":re.sub(r'(attributes #0 = \{[^\n]*)\bstrictfp\b',r'\1',ir,count=1)}
        self.assertTrue(all(text!=ir for text in variants.values()))
        for name,text in variants.items():
            f=self.out/("rejected-"+name+".ll");f.write_text(text)
            r=self.command("source-reject-"+name,[self.compiler,f,"--input-kind","llvm-ir","--emit","mir","--target","x86_64-unknown-none","--llvm-library",self.library,"--llvm-sha256",self.library_sha,"-o",self.out/(name+".rejected.json")],expected=None)
            self.assertEqual(r.returncode,1);self.assertIn(b"constrained multiply",r.stderr)
        module=json.loads(self.units["x86_64","scalbn"]["module"].read_text())
        for name in ("profile","declaration","unreachable"):
            bad=copy.deepcopy(module)
            if name=="profile":bad["target"].pop("strict_fp_profile")
            elif name=="declaration":
                bad["functions"]=[f for f in bad["functions"] if not f["name"].startswith("llvm.experimental.constrained.fmul")]
                bad["provenance"]["source_function_count"]=len(bad["functions"])
            else:
                function=next(f for f in bad["functions"] if f["entry"] is not None)
                ins=copy.deepcopy(next(i for b in function["blocks"] for i in b["instructions"] if i["operation"]["op"]=="constrained_float_binary"));ins["result"]["id"]=999999;ins["operation"]["kind"]="add"
                function["blocks"].append({"id":999999,"instructions":[ins],"terminator":{"op":"return","value":{"kind":"value","id":999999}}})
            f=self.out/("native-rejected-"+name+".json");f.write_text(json.dumps(bad))
            r=self.command("native-reject-"+name,[self.compiler,f,"--input-kind","native-ir","--verify-native"],expected=None)
            self.assertEqual(r.returncode,1);self.assertIn(b"constrained multiply",r.stderr)
            emitted=self.out/(name+".rejected.s")
            r=self.command("native-emit-reject-"+name,[self.compiler,f,"--input-kind","native-ir","--emit","asm","--target","x86_64-unknown-none","-o",emitted],expected=1)
            self.assertIn(b"constrained multiply",r.stderr);self.assertFalse(emitted.exists())

    def test_long_double_stays_explicitly_unsupported(self):
        for isa in PROFILES:
            ir=self.units[isa,"scalbnl"]["ir"]
            self.assertIn("x86_fp80" if isa=="x86_64" else "fp128",ir.read_text())
            r=self.command(isa+"-long-double-refuse",[self.compiler,ir,"--input-kind","llvm-ir","--emit","mir","--target",isa+"-unknown-none","--llvm-library",self.library,"--llvm-sha256",self.library_sha,"-o",self.out/(isa+".unsupported.json")],expected=None)
            self.assertEqual(r.returncode,1)
            self.assertIn(b"unsupported integer width i80" if isa=="x86_64" else b"intrinsic llvm.experimental.constrained.fmul.f128 requires explicit",r.stderr)

if __name__=="__main__":unittest.main()
