"""Complete authored C units for owned ctlz/abs32/64 execution.

The normal matrix compares only the original program's defined domain. A
separate owned-provider matrix checks a permitted zero/MIN poison refinement;
no reference value is asserted for those undefined original inputs. These are
mechanism fixtures, not an original-runtime acceptance profile.
"""
import hashlib
import json
import re
import struct
import unittest
from tests import test_ocore_native_floating_abi as fp

MASK = (1 << 64) - 1
GROUPS = ("total", "defined_partial", "poison_refinement")
PROFILES = tuple(fp.support.PROFILES)


def inputs(width):
    mask = (1 << width) - 1
    values = {0, 1, mask, 1 << (width - 1), (1 << (width - 1)) - 1}
    for bit in range(width):
        values.update(((1 << bit) + delta) & mask for delta in (-1, 0, 1))
    state = 0x9e3779b97f4a7c15
    for _ in range(32):
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK
        values.add(state & mask)
    if width == 32:
        values.update(value | 0xdeadbeef00000000 for value in tuple(values))
    return sorted(values)


def oracle(kind, width, value):
    mask = (1 << width) - 1
    value &= mask
    if kind == "ctlz":
        return width - value.bit_length()
    signed = value if value < 1 << (width - 1) else value - (1 << width)
    return abs(signed) & mask


def fixture(group):
    partial = group != "total"
    provider = "typedef unsigned long long u64;\n"
    if partial:
        provider += r"""
u64 ctlz32(u64 x) { return __builtin_clz((unsigned)x); }
u64 ctlz64(u64 x) { return __builtin_clzll(x); }
u64 abs32(u64 x) { return (unsigned)__builtin_abs((int)x); }
u64 abs64(u64 x) { return (u64)__builtin_llabs((long long)x); }
"""
    else:
        provider += r"""
u64 ctlz32(u64 x) { return __builtin_clzg((unsigned)x, 32); }
u64 ctlz64(u64 x) { return __builtin_clzg(x, 64); }
u64 abs32(u64 x) { unsigned u=(unsigned)x; return (int)u<0 ? 0u-u : u; }
u64 abs64(u64 x) { return (long long)x<0 ? 0ULL-x : x; }
"""
    caller = "typedef unsigned long long u64;\n"
    cases, expected, domains = [], [], []
    operations = (("ctlz", 32), ("ctlz", 64), ("abs", 32), ("abs", 64))
    for kind, width in operations:
        name = kind + str(width)
        values = inputs(width)
        undefined = [value for value in values if
                     (value & ((1 << width) - 1)) == (0 if kind == "ctlz" else 1 << (width - 1))]
        if group == "defined_partial":
            values = [value for value in values if value not in undefined]
        elif group == "poison_refinement":
            values = [0 if kind == "ctlz" else 1 << (width - 1)]
        caller += "extern u64 " + name + "(u64);\n"
        caller += "static const u64 " + name + "_inputs[]={" + ",".join(str(v) + "ULL" for v in values) + "};\n"
        domains.append({"operation": kind, "width": width, "unique_arguments": values,
                        "excluded_undefined_arguments": undefined if group == "defined_partial" else [],
                        "poison_flag": partial})
        for index, value in enumerate(values):
            cases.append({"operation": kind, "width": width, "argument_index": index,
                          "base_argument": value})
            expected.extend(oracle(kind, width, values[(index + offset) % len(values)])
                            for offset in range(len(fp.SEEDS)))
    caller += "u64 floating_case(u64 id,u64 seed) { unsigned offset=0;\n"
    for offset, seed in enumerate(fp.SEEDS[1:], 1):
        caller += ("if" if offset == 1 else "else if") + "(seed==" + str(seed) + "ULL)offset=" + str(offset) + ";\n"
    for domain in domains:
        name = domain["operation"] + str(domain["width"])
        length = len(domain["unique_arguments"])
        # For the single poison vector each seed invokes the same permitted
        # refinement. Defined matrices rotate through distinct original inputs.
        caller += "if(id<" + str(length) + "ULL){u64 i=id+(offset%" + str(length) + "U);"
        caller += "if(i>=" + str(length) + "ULL)i-=" + str(length) + "ULL;return " + name + "(" + name + "_inputs[i]);}id-=" + str(length) + "ULL;\n"
    caller += "return 0; }\n"
    return provider, caller, cases, expected, domains


class NativeIntegerUnaryTests(fp.NativeFloatingAbiTests):
    def original(self, name, source, profile):
        result = super().original(name, source, profile)
        if name.endswith("-provider"):
            llvm = result[1].read_text()
            calls = re.findall(r"@llvm\.(ctlz|abs)\.i(32|64)\(i(?:32|64) [^,\n]+, i1 (true|false)\)", llvm)
            flag = "false" if self.unary_group == "total" else "true"
            expected = {(kind, str(width), flag) for kind in ("ctlz", "abs") for width in (32, 64)}
            self.assertEqual(set(calls), expected,
                             "Original Clang frontend must emit every intended literal intrinsic control; no IR rewriting")
            self.assertEqual(len(calls), 4)
            self.record["actual_frontend_intrinsics"] = [list(row) for row in calls]
            self.save()
        return result

    def required_archives(self, profile, objects):
        # This mechanism is implemented directly. An accidental hidden runtime
        # helper is a failure, never a supplied replacement implementation.
        result = self.command([self.nm, "--undefined-only", *objects])
        helpers = re.findall(r"\b(__[A-Za-z0-9_]+)\s*$", result.stdout.decode(), re.M)
        self.assertEqual(helpers, [], "ctlz/abs fixtures must not gain compiler runtime helpers")
        return []

    def unary(self, profile, group):
        self.unary_group = group
        provider, caller, cases, expected, domains = fixture(group)
        self.record.update(qualification_scope="Authored complete C mechanism fixtures; no original-engine qualification",
                           unary_domains=domains, poison_comparison_policy=(
                               "Owned deterministic N/MIN is a permitted refinement; no original-reference comparison"
                               if group == "poison_refinement" else "Reference equality only on the original defined domain"))
        self.save()
        if group != "poison_refinement":
            self.matrix(profile, "integer_unary_" + group, (provider, caller, cases, expected))
            return
        self.poison_matrix(profile, provider, caller, cases, expected)

    def poison_matrix(self, profile, provider_source, caller_source, cases, expected_values):
        isa, mode, machine, _ = fp.support.PROFILES[profile]
        runner = self.execution_prefix(isa)
        provider_c, provider_ll, _ = self.original("integer-poison-provider", provider_source, profile)
        caller_c, caller_ll, caller_ref = self.original("integer-poison-caller", caller_source, profile)
        carrier = fp.support.carrier_source().replace("variadic_case", "floating_case")
        carrier = carrier.replace(f"output[{len(fp.support.CASES)*len(fp.support.SEEDS)}]", f"output[{len(cases)*len(fp.SEEDS)}]")
        carrier = carrier.replace(f"test<{len(fp.support.CASES)}", f"test<{len(cases)}")
        carrier = carrier.replace(f"seed<{len(fp.support.SEEDS)}", f"seed<{len(fp.SEEDS)}")
        carrier = carrier.replace("static const u64 seeds[]={" + ",".join(f"{s}ULL" for s in fp.support.SEEDS) + "};", fp.array("seeds", fp.SEEDS).strip())
        carrier_c, carrier_ll, carrier_obj = self.original("integer-poison-carrier", carrier, profile)
        originals = [fp.support.artifact(p) for p in (provider_c, provider_ll, caller_c, caller_ll, carrier_c, carrier_ll)]
        provider_owned = self.owned("integer-poison-provider", provider_ll, profile)
        caller_owned = self.owned("integer-poison-caller", caller_ll, profile)
        expected = struct.pack("<" + "Q" * len(expected_values), *expected_values)
        self.record.update(profile=profile, scope="integer_unary_poison_refinement", original_inputs=originals,
                           source_cases=cases, seeds=list(fp.SEEDS), comparisons_per_pairing=len(expected_values),
                           expected_output_sha256=hashlib.sha256(expected).hexdigest(),
                           reference_control_complete=False, reference_control_not_applicable="Original poison inputs have no required value")
        self.save()
        for caller_name, caller in (("reference", caller_ref), ("owned", caller_owned)):
            self.required_archives(profile, [provider_owned, caller])
            executable = self.directory / (caller_name + "-caller-owned-provider.elf")
            self.command([self.linker, "-static", "--no-relax", "-m", mode, "-e", "_start", carrier_obj, caller, provider_owned, "-o", executable])
            self.assert_elf(executable, machine, 2)
            result = self.command([*runner, executable], timeout=60)
            self.assertEqual(result.stdout, expected, "Selected native N/MIN poison refinement changed")
            self.record["pairings"].append({"caller": caller_name, "provider": "owned",
                "comparison_kind": "permitted_native_poison_refinement", "comparisons": len(expected_values),
                "caller_object": fp.support.artifact(caller), "provider_object": fp.support.artifact(provider_owned),
                "carrier_object": fp.support.artifact(carrier_obj), "executable": fp.support.artifact(executable),
                "stdout_sha256": hashlib.sha256(result.stdout).hexdigest()})
            self.save()
        self.assertEqual([fp.support.artifact(row["path"]) for row in originals], originals)
        self.record["complete"] = True
        self.save()


# Reuse fixture machinery, not its unrelated floating tests. This module owns
# exactly the following twelve unary methods; upstream C units are not filtered.
for _name in dir(fp.NativeFloatingAbiTests):
    if _name.startswith("test_"):
        setattr(NativeIntegerUnaryTests, _name, None)
for _profile in PROFILES:
    for _group in GROUPS:
        def _test(self, profile=_profile, group=_group):
            self.unary(profile, group)
        setattr(NativeIntegerUnaryTests, "test_" + _profile.replace("-", "_") + "_" + _group, _test)

if __name__ == "__main__":
    unittest.main()
