"""Original complete C fixtures for scalar i128 execution, separate from engines.

Each profile uses the four independent caller/provider ownership combinations
and a Python integer oracle. Division has a separate complete translation unit
and requires explicitly pinned original compiler-runtime reference providers.
These fixtures do not establish complete engine or provider-body lowering.
"""

import hashlib
import json
import os
from pathlib import Path
import unittest

from tests import test_ocore_native_floating_abi as fp

MASK128 = (1 << 128) - 1
VALUES = (0, 1, 2, (1 << 63) - 1, 1 << 63, (1 << 64) - 1,
          1 << 64, (1 << 64) + 1, (1 << 127) - 1, 1 << 127,
          (1 << 127) + 1, MASK128 - 1, MASK128,
          0x0123456789ABCDEFFEDCBA9876543210,
          0xFEDCBA98765432100123456789ABCDEF,
          0x8000000000000000FFFFFFFFFFFFFFFF)
SHIFTS = (0, 1, 63, 64, 65, 127)
PRELUDE = fp.support.PRELUDE + "\ntypedef unsigned __int128 U;typedef __int128 S;\n"


def signed(value):
    return value - (1 << 128) if value >> 127 else value


def quotient(a, b):
    return (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)


def fixture(group):
    provider = PRELUDE
    caller = PRELUDE
    if group == "core":
        provider += "U wide(unsigned op,U a,U b,unsigned n){switch(op){"
        provider += "case 0:return a+b;case 1:return a-b;case 2:return a*b;"
        provider += "case 3:return a&b;case 4:return a|b;case 5:return a^b;"
        provider += "case 6:return 0-a;case 7:return a<<n;case 8:return a>>n;"
        provider += "default:return (U)((S)a>>n);}}\n"
        caller += "extern U wide(unsigned,U,U,unsigned);\n"
    elif group == "compare_cast":
        provider += "u64 comparisons(U a,U b){return (u64)(a==b)|((u64)(a!=b)<<1)|"
        provider += "((u64)(a<b)<<2)|((u64)(a<=b)<<3)|((u64)(a>b)<<4)|((u64)(a>=b)<<5)|"
        provider += "((u64)((S)a<(S)b)<<6)|((u64)((S)a<=(S)b)<<7)|"
        provider += "((u64)((S)a>(S)b)<<8)|((u64)((S)a>=(S)b)<<9);}\n"
        provider += "U signed_extend(long long a){return (U)(S)a;}U zero_extend(u64 a){return (U)a;}\n"
        caller += "extern u64 comparisons(U,U);extern U signed_extend(long long);extern U zero_extend(u64);\n"
    elif group == "division":
        provider += "U divide(unsigned op,U a,U b){switch(op){case 0:return a/b;"
        provider += "case 1:return a%b;case 2:return (U)((S)a/(S)b);default:return (U)((S)a%(S)b);}}\n"
        caller += "extern U divide(unsigned,U,U);\n"
    else:
        raise ValueError(group)
    caller += fp.array("lo", [v & fp.support.MASK for v in VALUES])
    caller += fp.array("hi", [v >> 64 for v in VALUES])
    caller += "static U input(unsigned i){return ((U)hi[i]<<64)|lo[i];}\n"
    cases, bodies, expected = [], [], []

    def add(label, body, oracle):
        cases.append(label)
        bodies.append(f"case {len(cases)-1}:{{{body}}}\n")
        expected.extend(oracle(seed) & fp.support.MASK for seed in fp.SEEDS)

    for index, a in enumerate(VALUES):
        if group == "core":
            for op in range(10):
                for shift in (SHIFTS if op >= 7 else (0,)):
                    for word in (0, 1):
                        def oracle(seed, op=op, shift=shift, word=word, a=a, index=index):
                            b = VALUES[((seed + index + 3) & fp.support.MASK) % len(VALUES)]
                            result = (a+b, a-b, a*b, a&b, a|b, a^b, -a,
                                      a << shift, a >> shift, signed(a) >> shift)[op]
                            return ((result & MASK128) >> (64 * word))
                        body = f"U r=wide({op},input({index}),input((seed+{index+3}ULL)%{len(VALUES)}),{shift});return (u64)(r>>{64*word});"
                        add(["core", op, index, shift, word], body, oracle)
        elif group == "compare_cast":
            def oracle(seed, a=a, index=index):
                b = VALUES[((seed + index + 3) & fp.support.MASK) % len(VALUES)]
                flags = (a == b, a != b, a < b, a <= b, a > b, a >= b,
                         signed(a) < signed(b), signed(a) <= signed(b),
                         signed(a) > signed(b), signed(a) >= signed(b))
                return sum(int(value) << bit for bit, value in enumerate(flags))
            add(["comparisons", index], f"return comparisons(input({index}),input((seed+{index+3}ULL)%{len(VALUES)}));", oracle)
            for is_signed in (False, True):
                for word in (0, 1):
                    function = "signed_extend" if is_signed else "zero_extend"
                    def extend(seed, index=index, word=word, is_signed=is_signed):
                        value = (seed ^ (VALUES[index] & fp.support.MASK)) & fp.support.MASK
                        if is_signed and value >> 63:
                            value -= 1 << 64
                        return ((value & MASK128) >> (64 * word))
                    add([function, index, word], f"U r={function}(seed^lo[{index}]);return (u64)(r>>{64*word});", extend)
        else:
            for denominator_index in (1, 2, 5, 6, 8, 9, 10, 12, 14, 15):
                b = VALUES[denominator_index]
                for op in range(4):
                    # Exclude only the undefined signed MIN/-1 operation;
                    # every authored function and full translation unit stays.
                    if op >= 2 and signed(a) == -(1 << 127) and signed(b) == -1:
                        continue
                    for word in (0, 1):
                        if op == 0:
                            result = a // b
                        elif op == 1:
                            result = a % b
                        else:
                            sa, sb = signed(a), signed(b)
                            q = quotient(sa, sb)
                            result = q if op == 2 else sa - q * sb
                        body = f"U r=divide({op},input({index}),input({denominator_index}));return (u64)(r>>{64*word});"
                        add(["division", op, index, denominator_index, word], body,
                            lambda seed, result=result, word=word: (result & MASK128) >> (64 * word))
    caller += "u64 floating_case(u64 id,u64 seed){switch(id){" + "".join(bodies) + "default:return 0;}}\n"
    return provider, caller, cases, expected


class NativeWideIntegerAbiTests(fp.NativeFloatingAbiTests):
    def required_archives(self, profile, objects):
        result = self.command([self.nm, "--undefined-only", *objects])
        import re
        helpers = sorted(set(re.findall(r"\b(__[A-Za-z0-9_]+)\s*$", result.stdout.decode(), re.M)))
        if not helpers:
            return []
        manifest_path = os.environ.get("OCORE_I128_BUILTINS_MANIFEST")
        self.assertTrue(manifest_path, f"Original i128 reference helpers {helpers} need an explicit pinned provider manifest")
        manifest = json.loads(Path(manifest_path).read_text())
        self.assertEqual(manifest["schema"], "ocore-i128-original-reference-provider-v1")
        self.assertEqual(manifest["source_commit"], "fc4aad7b5db3fff421df9a9637605b9ca5667881")
        self.assertEqual(manifest["stage"], "complete")
        self.assertTrue(manifest["sources_stable"])
        self.assertFalse(manifest["helpers_lowered_through_ocore"])
        for item in manifest["source_files"]:
            raw = Path(item["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["sha256"])
            self.assertEqual(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(), item["git_blob_sha"])
        archive = manifest["profiles"][profile]["archive"]
        self.assertEqual(fp.support.artifact(archive["path"]), archive)
        self.record.setdefault("original_runtime_provider_manifests", []).append(fp.support.artifact(manifest_path))
        self.save()
        return [Path(archive["path"])]


for _name in dir(fp.NativeFloatingAbiTests):
    if _name.startswith("test_"):
        setattr(NativeWideIntegerAbiTests, _name, None)
for _profile in fp.support.PROFILES:
    for _group in ("core", "compare_cast", "division"):
        def _test(self, profile=_profile, group=_group):
            self.record["qualification_scope"] = "Original complete scalar-i128 C fixtures; no original-engine or provider-body qualification"
            self.matrix(profile, "i128_" + group, fixture(group))
        setattr(NativeWideIntegerAbiTests, "test_" + _profile.replace("-", "_") + "_" + _group, _test)


if __name__ == "__main__":
    unittest.main()
