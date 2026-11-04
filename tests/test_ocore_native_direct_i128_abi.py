"""Authored LLVM ABI probes with real per-target Clang profile anchors.

Both caller and provider retain literal i128 signatures. These are explicitly
authored IR fixtures, separate from the original-C and original-engine gates.
"""

from pathlib import Path
import unittest

from tests import test_ocore_native_wide_integer_abi as wide

fp = wide.fp
PREFIXES = (0, 1, 4, 5, 6, 7, 8, 9)
LOW = 0x0123456789ABCDEF
HIGH = 0xFEDCBA9876543210
TAG = 0x9876543210FEDCBA


def signature(count, names=False):
    parts = [f"i64 %g{i}" if names else "i64" for i in range(count)]
    return ", ".join(parts + (["i128 %value", "i64 %tag"] if names else ["i128", "i64"]))


def sources():
    provider, caller = ["; OSTADIX authored literal-i128 ABI provider"], ["; OSTADIX authored literal-i128 ABI caller"]
    cases, expected, blocks, switch = [], [], [], []
    for count in PREFIXES:
        declaration = signature(count)
        definition = signature(count, True)
        provider += [f"define i128 @abi_{count}({definition}) noinline {{", "entry:"]
        accumulator = "0"
        for index in range(count):
            provider += [f"  %weighted{index} = mul i64 %g{index}, {2*index+3}",
                         f"  %sum{index} = add i64 {accumulator}, %weighted{index}"]
            accumulator = f"%sum{index}"
        provider += [f"  %low = zext i64 {accumulator} to i128", "  %high0 = zext i64 %tag to i128",
                     "  %high = shl i128 %high0, 64", "  %mask = or i128 %low, %high",
                     "  %result = xor i128 %value, %mask", "  ret i128 %result", "}"]
        args = ", ".join([f"i64 %g{i}" for i in range(count)] + ["i128 %value", "i64 %tag"])
        provider += [f"define i128 @wrap_{count}({definition}) noinline {{", "entry:",
                     f"  %result = call i128 @abi_{count}({args})", "  ret i128 %result", "}"]
        caller += [f"declare i128 @wrap_{count}({declaration})",
                   f"@dispatch_{count} = global ptr @wrap_{count}, align 8"]
        for indirect in (False, True):
            for word in (0, 1):
                case = len(cases)
                cases.append(["authored-literal-i128", count, "indirect" if indirect else "direct", word])
                switch.append(f"    i64 {case}, label %case{case}")
                block = [f"case{case}:", f"  %lo{case} = xor i64 %seed, {LOW}",
                         f"  %hi{case} = xor i64 %seed, {HIGH}", f"  %lo128_{case} = zext i64 %lo{case} to i128",
                         f"  %hi128_{case} = zext i64 %hi{case} to i128", f"  %shifted{case} = shl i128 %hi128_{case}, 64",
                         f"  %value{case} = or i128 %lo128_{case}, %shifted{case}", f"  %tag{case} = add i64 %seed, {TAG}"]
                args = []
                for index in range(count):
                    block.append(f"  %g{case}_{index} = add i64 %seed, {0x101+index*0x123}")
                    args.append(f"i64 %g{case}_{index}")
                args += [f"i128 %value{case}", f"i64 %tag{case}"]
                callee = f"@wrap_{count}"
                if indirect:
                    block.append(f"  %callee{case} = load volatile ptr, ptr @dispatch_{count}, align 8")
                    callee = f"%callee{case}"
                block.append(f"  %result{case} = call i128 {callee}({', '.join(args)})")
                result = f"%result{case}"
                if word:
                    block.append(f"  %word{case} = lshr i128 {result}, 64")
                    result = f"%word{case}"
                block += [f"  %truncated{case} = trunc i128 {result} to i64", f"  ret i64 %truncated{case}"]
                blocks += block
                for seed in fp.SEEDS:
                    total = sum((((seed + 0x101 + index*0x123) & fp.support.MASK) * (2*index+3)) for index in range(count)) & fp.support.MASK
                    expected.append(((seed ^ LOW) ^ total) & fp.support.MASK if word == 0 else ((seed ^ HIGH) ^ ((seed + TAG) & fp.support.MASK)) & fp.support.MASK)
    caller += ["define i64 @floating_case(i64 %id, i64 %seed) {", "entry:", "  switch i64 %id, label %bad [", *switch,
               "  ]", *blocks, "bad:", "  ret i64 0", "}"]
    return "\n".join(provider)+"\n", "\n".join(caller)+"\n", cases, expected


class NativeDirectI128AbiTests(wide.NativeWideIntegerAbiTests):
    def original(self, name, source, profile):
        if not source.startswith("; OSTADIX authored literal-i128 ABI"):
            return super().original(name, source, profile)
        anchor_c, anchor_ir, _ = super().original(name + "-profile-anchor", "unsigned long long profile_anchor(unsigned long long x){return x;}\n", profile)
        anchor = anchor_ir.read_text().splitlines()
        layout = [line for line in anchor if line.startswith(("target datalayout =", "target triple ="))]
        self.assertEqual(len(layout), 2)
        metadata = [line for line in anchor if line.startswith("!")]
        llvm = self.directory / (name + ".ll")
        llvm.write_text("\n".join(layout) + "\n" + source + "\n" + "\n".join(metadata) + "\n")
        obj = self.directory / (name + ".reference.o")
        self.command([self.clang, *self.frontend_flags(profile), "-x", "ir", "-c", llvm, "-o", obj])
        self.record.setdefault("authored_ir_profile_anchors", []).append({"source_kind": "authored LLVM, not an original C or engine body", "input": fp.support.artifact(llvm), "anchor_c": fp.support.artifact(anchor_c), "anchor_ir": fp.support.artifact(anchor_ir), "preserved_target_directives": layout, "preserved_target_metadata": metadata})
        self.save()
        return anchor_c, llvm, obj


for _name in dir(wide.NativeWideIntegerAbiTests):
    if _name.startswith("test_"):
        setattr(NativeDirectI128AbiTests, _name, None)
for _profile in fp.support.PROFILES:
    def _test(self, profile=_profile):
        self.record["qualification_scope"] = "Authored literal-i128 signatures with real target-profile anchors; direct/indirect nested ABI probe, not complete C ABI or engine support"
        self.matrix(profile, "authored_direct_i128_abi", sources())
    setattr(NativeDirectI128AbiTests, "test_"+_profile.replace("-", "_")+"_direct", _test)


if __name__ == "__main__":
    unittest.main()
