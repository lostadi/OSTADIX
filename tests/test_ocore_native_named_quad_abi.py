"""Named scalar quad ABI boundaries, separate from the frozen FP core suite."""

import json
import os
from pathlib import Path
import sys
import unittest

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import test_ocore_native_floating_abi as fp


FRACTION = 0x0000FFFFFFFFFFFF


def quad(seed, index):
    return (seed ^ ((fp.support.BIAS * (index + 1)) & fp.support.MASK),
            0x3FFF000000000000 | (((seed >> 32) ^ (0x123456789AB * (index + 1))) & FRACTION))


def sources(profile):
    common = fp.C_COMMON + fp.wide_type(profile) + "\ntypedef union{wide value;u64 words[2];}W;\n"
    provider, caller = common, common
    bodies, cases, expected = [], [], []
    shapes = [("gp-prefix", n) for n in (5, 6, 7, 8, 9)]
    shapes += [("nine-quads", 0)] + [("independent-banks", n) for n in (0, 7, 9)]
    for shape_index, (kind, gp_count) in enumerate(shapes):
        name = "quad_boundary_" + str(shape_index)
        params = [f"u64 g{i}" for i in range(gp_count)]
        if kind == "independent-banks":
            params += [f"double d{i}" for i in range(9)]
        quad_count = 9 if kind == "nine-quads" else 1
        params += [f"wide q{i}" for i in range(quad_count)] + ["u64 tag"]
        signature = ",".join(params)
        provider += f"wide {name}({signature}){{u64 h=tag;W v;"
        for i in range(gp_count):
            provider += f"h=mix(h,g{i});"
        if kind == "independent-banks":
            for i in range(9):
                provider += f"{{F64 d;d.value=d{i};h=mix(h,d.bits);}}"
        for i in range(quad_count):
            provider += f"v.value=q{i};h=mix(mix(h,v.words[0]),v.words[1]);"
        provider += f"v.value=q{quad_count-1};v.words[0]^=h;v.words[1]^=h&0x0000ffffffffffffULL;return v.value;}}\n"
        caller += f"extern wide {name}({signature});\n"
        declarations = ""
        for i in range(quad_count):
            declarations += f"W q{i};q{i}.words[0]=seed^(0x9e3779b97f4a7c15ULL*{i+1}ULL);q{i}.words[1]=0x3fff000000000000ULL|(((seed>>32)^(0x123456789abULL*{i+1}ULL))&0x0000ffffffffffffULL);"
        arguments = [f"seed^{i+100}ULL" for i in range(gp_count)]
        if kind == "independent-banks":
            for i in range(9):
                declarations += f"F64 d{i};d{i}.bits=0x3ff0000000000000ULL|((seed^{i+200}ULL)&0x000fffffffffffffULL);"
            arguments += [f"d{i}.value" for i in range(9)]
        arguments += [f"q{i}.value" for i in range(quad_count)] + ["seed"]
        for mode in ("direct", "indirect"):
            if mode == "direct":
                call = f"r.value={name}(" + ",".join(arguments) + ");"
            else:
                call = f"wide(*volatile target)({signature})={name};r.value=target(" + ",".join(arguments) + ");"
            for word in (0, 1):
                bodies.append(f"case {len(cases)}:{{{declarations}W r;{call}return r.words[{word}];}}\n")
                cases.append([kind, gp_count, quad_count, mode, word])
                for seed in fp.SEEDS:
                    values = [seed ^ (i + 100) for i in range(gp_count)]
                    if kind == "independent-banks":
                        values += [0x3FF0000000000000 | ((seed ^ (i + 200)) & 0xFFFFFFFFFFFFF) for i in range(9)]
                    for i in range(quad_count):
                        values += quad(seed, i)
                    h = fp.support.fold(values, seed)
                    value = quad(seed, quad_count-1)[word] ^ (h if word == 0 else h & FRACTION)
                    expected.append(value)
    caller += "u64 floating_case(u64 id,u64 seed){switch(id){" + "".join(bodies) + "default:return 0;}}\n"
    return provider, caller, cases, expected


class NativeNamedQuadBoundaryTests(fp.NativeFloatingAbiTests):
    pass


# Import the shared module through an alias and suppress its unrelated tests.
for _name in dir(fp.NativeFloatingAbiTests):
    if _name.startswith("test_"):
        setattr(NativeNamedQuadBoundaryTests, _name, None)

for _profile in fp.support.PROFILES:
    def _test(self, profile=_profile):
        self.matrix(profile, "named_quad_boundaries", sources(profile))
    setattr(NativeNamedQuadBoundaryTests, "test_" + _profile.replace("-", "_") + "_named_quad_boundaries", _test)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--reference-only":
        fp.REFERENCE_ONLY = True
        output = Path(sys.argv[2]).resolve()
        output.mkdir(parents=True, exist_ok=False)
        os.environ["OCORE_FP_RETAIN"] = str(output)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeNamedQuadBoundaryTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        reports = [fp.support.artifact(p) for p in sorted(output.glob("floating-*/report.json"))]
        (output / "reference-controls.json").write_text(json.dumps({
            "schema": "ocore-named-quad-reference-controls-v1", "test_methods": result.testsRun,
            "failures": len(result.failures), "errors": len(result.errors), "skips": len(result.skipped),
            "reports": reports, "owned_compilation_attempted": False, "runtime_complete": False}, indent=2) + "\n")
        raise SystemExit(not result.wasSuccessful())
    unittest.main()
