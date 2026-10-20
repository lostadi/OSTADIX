"""Execute ordinary C helper calls beside backend-generated FP helper calls.

The environment qualification is deliberately bounded: default nearest-even,
gradual underflow, default NaNs, and masked traps. Sticky exception flags are
recorded, not qualified as observable results. Off-profile rejection belongs to
this fixture's explicit guard, not to production admission. Strict/constrained
floating environments remain a separate unsupported whole-input boundary.
"""

from fractions import Fraction
import json
import os
from pathlib import Path
import re
import struct
import sys
import unittest

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import test_ocore_native_floating_abi as fp


HELPERS = (
    ("add", "wide", "wide a,wide b", "a+b", "__addtf3", "a,b"),
    ("sub", "wide", "wide a,wide b", "a-b", "__subtf3", "a,b"),
    ("mul", "wide", "wide a,wide b", "a*b", "__multf3", "a,b"),
    ("div", "wide", "wide a,wide b", "a/b", "__divtf3", "a,b"),
    ("to_f32", "float", "wide a", "(float)a", "__trunctfsf2", "a"),
    ("to_f64", "double", "wide a", "(double)a", "__trunctfdf2", "a"),
    ("from_f32", "wide", "float a", "(wide)a", "__extendsftf2", "a"),
    ("from_f64", "wide", "double a", "(wide)a", "__extenddftf2", "a"),
    ("from_i64", "wide", "long long a", "(wide)a", "__floatditf", "a"),
    ("from_u64", "wide", "u64 a", "(wide)a", "__floatunditf", "a"),
    ("to_i64", "long long", "wide a", "(long long)a", "__fixtfdi", "a"),
    ("to_u64", "u64", "wide a", "(u64)a", "__fixunstfdi", "a"),
)
CANONICAL_QUAD = "if((r.words[1]&0x7fff000000000000ULL)==0x7fff000000000000ULL&&((r.words[1]&0x0000ffffffffffffULL)||r.words[0])){r.words[0]=0;r.words[1]=0x7fff800000000000ULL;}"


def sources(profile):
    common = fp.C_COMMON + fp.wide_type(profile) + "\ntypedef union{wide value;u64 words[2];}W;\n"
    provider, caller = common, common
    for name, result, params, expression, helper, arguments in HELPERS:
        provider += f"extern {result} {helper}({params});\n"
        for route in ("operation", "source_call"):
            body = expression if route == "operation" else f"{helper}({arguments})"
            provider += f"{result} {name}_{route}({params}){{return {body};}}\n"
            caller += f"extern {result} {name}_{route}({params});\n"
    for suffix,typ in (("f","float"),("d","double")):
        provider += f"{typ} hardware_environment_{suffix}(unsigned op,{typ} a,{typ} b){{return op?a*b:a/b;}}\n"
        caller += f"extern {typ} hardware_environment_{suffix}(unsigned,{typ},{typ});\n"
    caller += fp.array("lows", [v & fp.support.MASK for v in fp.WIDE_VECTORS])
    caller += fp.array("highs", [v >> 64 for v in fp.WIDE_VECTORS])
    caller += fp.array("f32_bits", fp.VECTORS[32]) + fp.array("f64_bits", fp.VECTORS[64])
    caller += fp.array("signed_values", fp.SIGNED) + fp.array("unsigned_values", fp.UNSIGNED)
    caller += "u64 floating_case(u64 id,u64 seed){W a,b,r;switch(id){\n"
    bodies, cases, expected = [], [], []

    def add(label, body, oracle):
        bodies.append(f"case {len(cases)}:{{{body}}}\n")
        cases.append(label)
        expected.extend(oracle(seed) & fp.support.MASK for seed in fp.SEEDS)

    n = len(fp.WIDE_VECTORS)
    for route in ("operation", "source_call"):
        for op in ("add", "sub", "mul", "div"):
            for index in range(n):
                body = f"a.words[0]=lows[{index}];a.words[1]=highs[{index}];b.words[0]=lows[(seed+{index})%{n}];b.words[1]=highs[(seed+{index})%{n}];r.value={op}_{route}(a.value,b.value);" + CANONICAL_QUAD
                for word in (0, 1):
                    add([op, route, index, word], body + f"return r.words[{word}];",
                        lambda seed, o=op, i=index, w=word: fp.calculate(o, fp.WIDE_VECTORS[i], fp.WIDE_VECTORS[(seed+i)%n], 128) >> (w*64))
        for width, suffix in ((32, "f"), (64, "d")):
            for index, value in enumerate(fp.WIDE_VECTORS):
                add(["fptrunc", route, width, index], f"a.words[0]=lows[{index}];a.words[1]=highs[{index}];return canonical_{suffix}(to_f{width}_{route}(a.value));",
                    lambda seed, v=value, w=width: fp.convert(v,128,w))
            for index, value in enumerate(fp.VECTORS[width]):
                union = "F32" if width == 32 else "F64"
                body = f"{union} v;v.bits=f{width}_bits[{index}];r.value=from_f{width}_{route}(v.value);" + CANONICAL_QUAD
                for word in (0, 1):
                    add(["fpext", route, width, index, word], body + f"return r.words[{word}];",
                        lambda seed, v=value, w=width, k=word: fp.convert(v,w,128) >> (k*64))
        for signedness, values, array, typ in (("i64", fp.SIGNED, "signed_values", "long long"),
                                                ("u64", fp.UNSIGNED, "unsigned_values", "u64")):
            for index, value in enumerate(values):
                for word in (0, 1):
                    add(["int-to-quad", route, signedness, value, word], f"r.value=from_{signedness}_{route}(({typ}){array}[{index}]);return r.words[{word}];",
                        lambda seed, v=value, k=word: fp.round_fraction(Fraction(v),128) >> (k*64))
                bits = fp.round_fraction(Fraction(value),128)
                add(["quad-to-int", route, signedness, value], f"a.words[0]={bits & fp.support.MASK}ULL;a.words[1]={bits >> 64}ULL;return(u64)to_{signedness}_{route}(a.value);",
                    lambda seed, v=value: v)
    # Observe real hardware FP flags as well as software quad helper paths.
    # Flag values are retained, never compared as a qualified result contract.
    for width,suffix,union in ((32,"f","F32"),(64,"d","F64")):
        ebits,precision=fp.FORMATS[width]
        one=fp.round_fraction(Fraction(1),width)
        two=fp.round_fraction(Fraction(2),width)
        three=fp.round_fraction(Fraction(3),width)
        minimum_normal=1<<(precision-1)
        maximum_finite=(((1<<ebits)-2)<<(precision-1))|((1<<(precision-1))-1)
        for label,op,left,right in (("inexact","div",one,three),("invalid","div",0,0),
                                    ("division-by-zero","div",one,0),
                                    ("gradual-underflow","div",minimum_normal,two),
                                    ("overflow","mul",maximum_finite,two)):
            add(["hardware-environment",width,label],f"{union} a,b;a.bits={left}ULL;b.bits={right}ULL;return canonical_{suffix}(hardware_environment_{suffix}({int(op=='mul')},a.value,b.value));",
                lambda seed,w=width,o=op,a=left,b=right:fp.calculate(o,a,b,w))
    return provider, caller + "".join(bodies) + "default:return 0;}}\n", cases, expected


ENVIRONMENT_CODE = r"""
static int read_environment(u64 *out) {
#if defined(__x86_64__)
    unsigned csr;unsigned short control;
    __asm__ volatile("stmxcsr %0":"=m"(csr)::"memory");
    __asm__ volatile("fnstcw %0":"=m"(control)::"memory");
    out[0]=csr;out[1]=control;
    return !(csr&((3U<<13)|(1U<<15)|(1U<<6)))
        &&(csr&0x1f80U)==0x1f80U&&(control&0x3fU)==0x3fU
        &&!(control&(3U<<10))&&(control&(3U<<8))==(3U<<8);
#elif defined(__aarch64__)
    u64 control,status;
    __asm__ volatile("mrs %0,fpcr":"=r"(control)::"memory");
    __asm__ volatile("mrs %0,fpsr":"=r"(status)::"memory");
    out[0]=control;out[1]=status;
    return !(control&((3ULL<<22)|(1ULL<<24)|(1ULL<<25)|(1ULL<<19)|0x9f03ULL));
#else
    u64 csr;__asm__ volatile("frcsr %0":"=r"(csr)::"memory");
    out[0]=csr;out[1]=0;return !(csr&0xe0ULL);
#endif
}
static void set_nondefault_environment(void) {
#if defined(__x86_64__)
    unsigned csr;unsigned short control;
    __asm__ volatile("stmxcsr %0":"=m"(csr)::"memory");csr=(csr&~(3U<<13))|(1U<<13);
    __asm__ volatile("ldmxcsr %0"::"m"(csr):"memory");
    __asm__ volatile("fnstcw %0":"=m"(control)::"memory");control=(control&~(3U<<10))|(1U<<10);
    __asm__ volatile("fldcw %0"::"m"(control):"memory");
#elif defined(__aarch64__)
    u64 control;__asm__ volatile("mrs %0,fpcr":"=r"(control)::"memory");control|=1ULL<<22;
    __asm__ volatile("msr fpcr,%0"::"r"(control):"memory");
#else
    u64 csr;__asm__ volatile("frcsr %0":"=r"(csr)::"memory");csr=(csr&~0xe0ULL)|0x40ULL;
    __asm__ volatile("fscsr %0"::"r"(csr):"memory");
#endif
}
"""


def environment_carrier(source, negative=False):
    start = source.index("static long write_bytes(")
    end = source.index("int conformance_main(void)", start)
    writer = source[start:end].replace("write_bytes", "write_environment")
    writer = writer.replace('"D"(1L)', '"D"(2L)')
    writer = writer.replace('register long x0 __asm__("x0")=1;', 'register long x0 __asm__("x0")=2;')
    writer = writer.replace('register long a0 __asm__("a0")=1;', 'register long a0 __asm__("a0")=2;')
    source = source[:end] + ENVIRONMENT_CODE + writer + source[end:]
    before = "u64 environment[4];" + ("set_nondefault_environment();" if negative else "")
    before += "if(!read_environment(environment)){write_environment(environment,16);return 197;}"
    source = source.replace("unsigned next=0;", before + "unsigned next=0;")
    source = source.replace("const unsigned char *p=(const unsigned char*)output;",
                            "if(!read_environment(environment+2))return 198;write_environment(environment,32);const unsigned char *p=(const unsigned char*)output;")
    return source


def default_environment(profile, first, second):
    if profile == "x86_64":
        return (not first & ((3 << 13) | (1 << 15) | (1 << 6))
                and first & 0x1F80 == 0x1F80 and second & 0x3F == 0x3F
                and not second & (3 << 10) and second & (3 << 8) == 3 << 8)
    if profile == "aarch64":
        return not first & ((3 << 22) | (1 << 24) | (1 << 25) | (1 << 19) | 0x9F03)
    return not first & 0xE0


class NativeFpHelperInterfaceTests(fp.NativeFloatingAbiTests):
    def original(self, name, source, profile):
        if name.endswith("-carrier"):
            source = environment_carrier(source)
            self.environment_source = source
        result = super().original(name, source, profile)
        if name.endswith("-provider"):
            text = result[1].read_text()
            for _, _, _, _, helper, _ in HELPERS:
                self.assertRegex(text, r"\bcall\b[^\n]*@" + helper + r"\(",
                                 "the original explicit C helper call must remain in the complete unit")
            for opcode in ("fadd", "fsub", "fmul", "fdiv", "fptrunc", "fpext", "fptosi", "fptoui", "sitofp", "uitofp"):
                self.assertRegex(text, r"\b" + opcode + r"\b")
        return result

    def qualify_environment(self, profile):
        observations = []
        for pairing in self.record["pairings"]:
            path = pairing["executable"]["path"]
            expected_argv=[*self.record["execution_argv_prefix"],path]
            command = next(c for c in self.record["commands"] if c["argv"] == expected_argv)
            raw = Path(command["stderr"]["path"]).read_bytes()
            self.assertEqual(len(raw), 32, "the reference carrier must publish real before/after hardware environment words")
            before0,before1,after0,after1 = struct.unpack("<4Q", raw)
            self.assertTrue(default_environment(profile,before0,before1))
            self.assertTrue(default_environment(profile,after0,after1))
            if profile == "x86_64":
                self.assertEqual(before0 & ~0x3F, after0 & ~0x3F)
                self.assertEqual(before1,after1)
            elif profile == "aarch64":
                self.assertEqual(before0,after0)
            else:
                self.assertEqual(before0 & ~0x1F,after0 & ~0x1F)
            observations.append({"caller":pairing["caller"],"provider":pairing["provider"],
                "raw_environment_stderr":command["stderr"],"before":[before0,before1],"after":[after0,after1]})
        self.record["floating_environment"] = {"profile":"default IEEE nearest-even; gradual underflow; no default-NaN mode; masked traps",
            "observations":observations,"controls_unchanged":True,"sticky_flags_recorded":True,
            "sticky_flags_qualified_as_observable_results":False,"dynamic_or_strict_environment_qualified":False}
        self.save()

    def negative_environment(self, profile):
        # This is an explicit carrier precondition, never a claim that the
        # production compiler or admission layer automatically checks FPCR.
        source = self.environment_source.replace("u64 environment[4];if", "u64 environment[4];set_nondefault_environment();if")
        self.assertIn("set_nondefault_environment();if(!read_environment", source)
        _, _, carrier = super().original("nondefault-environment-control", source, profile)
        pairing = self.record["pairings"][-1]
        executable = self.directory / "nondefault-environment.elf"
        isa,mode,machine,_ = fp.support.PROFILES[profile]
        self.command([self.linker,"-static","--no-relax","-m",mode,"-e","_start",carrier,
            pairing["caller_object"]["path"],pairing["provider_object"]["path"],
            *[p["path"] for p in pairing["runtime_archives"]],"-o",executable])
        self.assert_elf(executable,machine,2)
        result = self.command([*self.execution_prefix(isa),executable],expected=197)
        self.assertEqual(result.stdout,b"")
        self.assertEqual(len(result.stderr),16)
        values = struct.unpack("<2Q",result.stderr)
        self.assertFalse(default_environment(profile,*values))
        self.record["floating_environment"]["nondefault_control"] = {
            "executable":fp.support.artifact(executable),"exit_code":197,"observed_words":list(values),
            "fixture_guard_rejected_before_workload":True,"production_admission_qualification":False}
        self.save()

    def strict_environment_boundary(self, profile):
        source = "#pragma STDC FENV_ACCESS ON\ndouble strict_environment(double a,double b){return a+b;}\n"
        _, llvm, _ = super().original("strict-environment-input",source,profile)
        self.assertIn("llvm.experimental.constrained.fadd",llvm.read_text())
        if fp.REFERENCE_ONLY:
            self.record["strict_environment"] = {"original_llvm":fp.support.artifact(llvm),
                "constrained_intrinsic_present":True,"owned_import_attempted":False}
            self.save()
            return
        output = self.directory / "strict-environment.native.json"
        result = self.command([self.compiler,llvm,"--input-kind","llvm-ir","--emit","mir","--target",
            fp.support.PROFILES[profile][0]+"-unknown-none","--llvm-library",self.library,
            "--llvm-sha256",self.pin,"-o",output],expected=1)
        error = self.importer_error(result)
        self.assertFalse(output.exists())
        self.assertTrue("constrained" in error["message"] or "strictfp" in error["message"],
                        "retain the actual unsupported strict-FP diagnostic; unrelated import failures do not qualify this gate")
        self.record["strict_environment"] = {"original_llvm":fp.support.artifact(llvm),
            "constrained_intrinsic_present":True,"owned_import_attempted":True,"exit_code":1,
            "importer_diagnostic":error,"native_artifact_absent":True}
        self.save()

    def denormal_environment_boundary(self,profile):
        source=self.directory/"non-ieee-denormals.c"
        llvm=source.with_suffix(".ll")
        source.write_text("double non_ieee_denormals(double a,double b){return a+b;}\n")
        self.command([self.clang,*self.frontend_flags(profile),"-fdenormal-fp-math=preserve-sign",
                      "-S","-emit-llvm",source,"-o",llvm])
        self.assertRegex(llvm.read_text(),r'"denormal-fp-math"\s*=\s*"preserve-sign,preserve-sign"')
        if fp.REFERENCE_ONLY:
            self.record["denormal_environment"]={"original_llvm":fp.support.artifact(llvm),
                "non_ieee_function_attribute_present":True,"owned_import_attempted":False}
            self.save()
            return
        output=self.directory/"non-ieee-denormals.native.json"
        result=self.command([self.compiler,llvm,"--input-kind","llvm-ir","--emit","mir","--target",
            fp.support.PROFILES[profile][0]+"-unknown-none","--llvm-library",self.library,
            "--llvm-sha256",self.pin,"-o",output],expected=1)
        error=self.importer_error(result)
        self.assertIn("denormal",error["message"])
        self.assertFalse(output.exists())
        self.record["denormal_environment"]={"original_llvm":fp.support.artifact(llvm),
            "non_ieee_function_attribute_present":True,"owned_import_attempted":True,
            "exit_code":1,"importer_diagnostic":error,"native_artifact_absent":True}
        self.save()

    def oracle_negative(self,profile):
        # Deliberately corrupt a test-carrier result after the real helper
        # workload. Original helper implementations and archive bytes stay put.
        source=self.environment_source.replace("const unsigned char *p=(const unsigned char*)output;",
            "output[0]^=1;const unsigned char *p=(const unsigned char*)output;")
        self.assertIn("output[0]^=1;",source)
        _,_,carrier=super().original("oracle-corruption-carrier-control",source,profile)
        pair=self.record["pairings"][0]
        isa,mode,machine,_=fp.support.PROFILES[profile]
        executable=self.directory/"oracle-corruption.elf"
        self.command([self.linker,"-static","--no-relax","-m",mode,"-e","_start",carrier,
            pair["caller_object"]["path"],pair["provider_object"]["path"],
            *[p["path"] for p in pair["runtime_archives"]],"-o",executable])
        self.assert_elf(executable,machine,2)
        result=self.command([*self.execution_prefix(isa),executable])
        expected_values=sources(profile)[3]
        expected=struct.pack("<"+"Q"*len(expected_values),*expected_values)
        self.assertEqual(len(result.stdout),len(expected))
        self.assertNotEqual(result.stdout,expected)
        self.assertEqual(result.stdout[8:],expected[8:])
        self.assertEqual(struct.unpack_from("<Q",result.stdout)[0],expected_values[0]^1)
        self.record["oracle_corruption_control"]={"executable":fp.support.artifact(executable),
            "exit_code":0,"test_carrier_output_word0_xor":1,"oracle_rejected_output":True,
            "first_mismatch":0,"helper_implementation_modified":False}
        self.save()


for _name in dir(fp.NativeFloatingAbiTests):
    if _name.startswith("test_"):
        setattr(NativeFpHelperInterfaceTests,_name,None)

for _profile in fp.support.PROFILES:
    def _test(self,profile=_profile):
        self.matrix(profile,"source_helpers_and_backend_helpers",sources(profile))
        self.record["complete"]=False
        self.record["helper_environment_controls_complete"]=False
        self.save()
        self.qualify_environment(profile)
        self.negative_environment(profile)
        self.strict_environment_boundary(profile)
        self.denormal_environment_boundary(profile)
        self.oracle_negative(profile)
        self.record["helper_environment_controls_complete"]=True
        self.record["complete"]=not fp.REFERENCE_ONLY
        self.save()
    setattr(NativeFpHelperInterfaceTests,"test_"+_profile.replace("-","_")+"_source_and_generated_helper_interfaces",_test)


if __name__ == "__main__":
    if len(sys.argv)==3 and sys.argv[1]=="--reference-only":
        fp.REFERENCE_ONLY=True
        output=Path(sys.argv[2]).resolve();output.mkdir(parents=True,exist_ok=False)
        os.environ["OCORE_FP_RETAIN"]=str(output)
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeFpHelperInterfaceTests))
        reports=[fp.support.artifact(p) for p in sorted(output.glob("floating-*/report.json"))]
        (output/"reference-controls.json").write_text(json.dumps({"schema":"ocore-fp-helper-interface-reference-controls-v1",
            "test_methods":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),
            "skips":len(result.skipped),"reports":reports,"owned_compilation_attempted":False,
            "runtime_complete":False,"dynamic_fenv_qualified":False},indent=2)+"\n")
        raise SystemExit(not result.wasSuccessful())
    unittest.main()
