"""Additional finite f32/f64 diagnostic, separate from the full FP ABI suite.

The complete failing fixtures remain unchanged. This smaller original-C unit
does not canonicalize NaNs, use i128, or perform volatile floating accesses.
Its carrier observes the actual default floating environment; that fixture
precondition is not production environment admission or engine qualification.
"""

import json
import os
from pathlib import Path
import re
import sys
import unittest

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import test_ocore_native_fp_helper_interfaces as environment


fp = environment.fp
FINITE = {
    32: (0, 0x80000000, 0x3F800000, 0xBF800000, 0x3FC00000,
         0xC0100000, 1, 0x80000001, 0x00800000, 0x80800000),
    64: (0, 0x8000000000000000, 0x3FF0000000000000, 0xBFF0000000000000,
         0x3FF8000000000000, 0xC002000000000000, 1, 0x8000000000000001,
         0x0010000000000000, 0x8010000000000000),
}
DENOMINATORS = {
    32: (0x3F800000, 0xBF800000, 0x3FC00000, 0x40000000, 0x40400000),
    64: (0x3FF0000000000000, 0xBFF0000000000000, 0x3FF8000000000000,
         0x4000000000000000, 0x4008000000000000),
}


def sources():
    prelude = fp.support.PRELUDE + "\n"
    prelude += "typedef union{float value;unsigned bits;} F32;\n"
    prelude += "typedef union{double value;u64 bits;} F64;\n"
    provider = prelude
    caller = prelude
    for suffix, typ in (("f", "float"), ("d", "double")):
        provider += f"{typ} arithmetic_{suffix}(unsigned op,{typ} a,{typ} b){{switch(op){{"
        provider += "case 0:return a+b;case 1:return a-b;case 2:return a*b;case 3:return a/b;default:return -a;}}\n"
        provider += f"u64 compare_{suffix}({typ} a,{typ} b){{return "
        provider += "(u64)(a==b)|((u64)(a!=b)<<1)|((u64)(a<b)<<2)|((u64)(a<=b)<<3)|((u64)(a>b)<<4)|((u64)(a>=b)<<5)|((u64)__builtin_isunordered(a,b)<<6)|((u64)!__builtin_isunordered(a,b)<<7);}\n"
        caller += f"extern {typ} arithmetic_{suffix}(unsigned,{typ},{typ});extern u64 compare_{suffix}({typ},{typ});\n"
    for width in FINITE:
        caller += fp.array(f"finite_{width}", FINITE[width])
        caller += fp.array(f"denominators_{width}", DENOMINATORS[width])
    bodies, labels, expected = [], [], []

    def add(label, body, oracle):
        bodies.append(f"case {len(labels)}:{{{body}}}\n")
        labels.append(label)
        expected.extend(oracle(seed) & fp.support.MASK for seed in fp.SEEDS)

    for width, suffix, union in ((32, "f", "F32"), (64, "d", "F64")):
        for opnum, operation in enumerate(("add", "sub", "mul", "div", "neg")):
            for index in range(len(FINITE[width])):
                body = f"{union} a,b,r;a.bits=finite_{width}[{index}];b.bits=denominators_{width}[(seed+{index})%5];r.value=arithmetic_{suffix}({opnum},a.value,b.value);return r.bits;"
                add([operation, width, index], body,
                    lambda seed, w=width, op=operation, i=index:
                    fp.calculate(op, FINITE[w][i], DENOMINATORS[w][(seed+i) % 5], w))
        for index in range(len(FINITE[width])):
            body = f"{union} a,b;a.bits=finite_{width}[{index}];b.bits=finite_{width}[(seed+{index})%10];return compare_{suffix}(a.value,b.value);"
            add(["compare", width, index], body,
                lambda seed, w=width, i=index:
                fp.comparisons(FINITE[w][i], FINITE[w][(seed+i) % 10], w))
    caller += "u64 floating_case(u64 id,u64 seed){switch(id){" + "".join(bodies) + "default:return 0;}}\n"
    return provider, caller, labels, expected


class NativeFiniteScalarAbiTests(environment.NativeFpHelperInterfaceTests):
    def original(self, name, source, profile):
        if name.endswith("-carrier"):
            source = environment.environment_carrier(source)
            self.environment_source = source
        result = fp.NativeFloatingAbiTests.original(self, name, source, profile)
        if name.endswith(("-caller", "-provider")):
            llvm = result[1].read_text()
            self.assertNotIn("@llvm.fabs", llvm)
            # Ignore layout/alignment strings: reject actual i128 LLVM types.
            self.assertNotRegex("\n".join(line for line in llvm.splitlines()
                                        if not line.startswith("target datalayout")), r"\bi128\b")
            self.assertNotRegex(llvm, r"\b(?:load|store)\s+volatile\s+(?:float|double)\b")
        if name.endswith("-provider"):
            for opcode in ("fadd", "fsub", "fmul", "fdiv", "fneg", "fcmp"):
                self.assertRegex(result[1].read_text(), r"\b" + opcode + r"\b")
        return result


for _name in dir(environment.NativeFpHelperInterfaceTests):
    if _name.startswith("test_"):
        setattr(NativeFiniteScalarAbiTests, _name, None)

for _profile in fp.support.PROFILES:
    def _test(self, profile=_profile):
        self.record["qualification_scope"] = {
            "kind": "additional bounded finite f32/f64 diagnostic",
            "full_floating_suite_qualification": False,
            "nan_payload_or_class_qualification": False,
            "wide_float_or_i128_qualification": False,
            "strict_or_dynamic_environment_qualification": False,
            "production_environment_admission_qualification": False,
            "sticky_exception_flags_qualified_as_observable_results": False,
        }
        self.matrix(profile, "finite_scalar_diagnostic", sources())
        self.record["complete"] = False
        self.save()
        self.qualify_environment(profile)
        self.negative_environment(profile)
        self.record["finite_scalar_environment_controls_complete"] = True
        self.record["complete"] = not fp.REFERENCE_ONLY
        self.save()
    setattr(NativeFiniteScalarAbiTests,
            "test_" + _profile.replace("-", "_") + "_finite_scalar_diagnostic", _test)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--reference-only":
        fp.REFERENCE_ONLY = True
        output = Path(sys.argv[2]).resolve()
        output.mkdir(parents=True, exist_ok=False)
        os.environ["OCORE_FP_RETAIN"] = str(output)
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(NativeFiniteScalarAbiTests))
        reports = [fp.support.artifact(p) for p in sorted(output.glob("floating-*/report.json"))]
        (output / "reference-controls.json").write_text(json.dumps({
            "schema": "ocore-finite-scalar-reference-controls-v1",
            "test_methods": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skips": len(result.skipped), "reports": reports,
            "owned_compilation_attempted": False, "runtime_complete": False,
            "full_floating_suite_qualification": False}, indent=2) + "\n")
        raise SystemExit(not result.wasSuccessful())
    unittest.main()
