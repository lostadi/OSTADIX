"""Original Clang22 scalar FP units across reference/owned ELF ABI boundaries.

This harness performs no Cargo build or installation. Linux syscall carriers,
LLD, QEMU and any selected original compiler-runtime archive are explicit test
dependencies. Whole original LLVM units are imported and independently verified.
The integer/bit oracle does not use an owned result as a reference.
"""

from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import test_ocore_native_variadic_abi as support


ROOT = Path(__file__).resolve().parents[1]
SEEDS = (0, 1, 0x8000000000000000, 0xFEDCBA9876543210)
REFERENCE_ONLY = False
FORMATS = {32: (8, 24), 64: (11, 53), 128: (15, 113)}
VECTORS = {
    32: (0, 0x80000000, 0x3F800000, 0xBF800000, 0x3FC00000,
         0xC0100000, 1, 0x007FFFFF, 0x00800000, 0x7F7FFFFF,
         0x7F800000, 0xFF800000, 0x7FC00001, 0x3F800001),
    64: (0, 0x8000000000000000, 0x3FF0000000000000, 0xBFF0000000000000,
         0x3FF8000000000000, 0xC002000000000000, 1, 0x000FFFFFFFFFFFFF,
         0x0010000000000000, 0x7FEFFFFFFFFFFFFF, 0x7FF0000000000000,
         0xFFF0000000000000, 0x7FF8000000000001, 0x3FF0000000000001),
}
SIGNED = (0, 1, -1, 16777217, -16777217, 9007199254740993,
          -9007199254740993, -(1 << 63), (1 << 63) - 1)
UNSIGNED = (0, 1, 16777217, 9007199254740993, (1 << 63) - 1,
            1 << 63, (1 << 63) + 1, (1 << 64) - 1)
SAFE_INTS = (-2147483648, -16777217, -30001, -1, 0, 1, 60001,
             16777217, 2147483520)
WIDE_VECTORS = (0, 1 << 127, 0x3FFF << 112, (0xBFFF << 112),
                (0x3FFF << 112) | (1 << 111), 1, (1 << 112) - 1,
                1 << 112, (0x7FFE << 112) | ((1 << 112) - 1),
                0x7FFF << 112, 0xFFFF << 112, (0x7FFF << 112) | (1 << 111),
                (0x3FFF << 112) | (1 << 59),
                (0x3FFF << 112) | (1 << 59) | 1,
                (0x3FFF << 112) | (1 << 88),
                (0x3FFF << 112) | (1 << 88) | 1)
LENGTHS = (0, 1, 2, 5, 7, 8, 9, 12, 17)


def unpack(bits, width):
    ebits, precision = FORMATS[width]
    fraction = bits & ((1 << (precision - 1)) - 1)
    exponent = (bits >> (precision - 1)) & ((1 << ebits) - 1)
    sign = bits >> (width - 1)
    if exponent == (1 << ebits) - 1:
        return sign, "nan" if fraction else "inf", None
    if not exponent and not fraction:
        return sign, "zero", Fraction(0)
    mantissa = fraction if not exponent else fraction | (1 << (precision - 1))
    power = (exponent or 1) - ((1 << (ebits - 1)) - 1) - (precision - 1)
    value = Fraction(mantissa << max(power, 0), 1 << max(-power, 0))
    return sign, "finite", -value if sign else value


def special(width, kind, sign=0):
    ebits, precision = FORMATS[width]
    bits = ((1 << ebits) - 1) << (precision - 1)
    if kind == "nan":
        return bits | (1 << (precision - 2))
    if kind == "zero":
        bits = 0
    return bits | (sign << (width - 1))


def round_fraction(value, width, zero_sign=0):
    """Exact rational rounding to IEEE round-to-nearest, ties-to-even."""
    if not value:
        return special(width, "zero", zero_sign)
    sign = int(value < 0)
    value = abs(value)
    ebits, precision = FORMATS[width]
    bias = (1 << (ebits - 1)) - 1
    exponent = value.numerator.bit_length() - value.denominator.bit_length()
    if value < Fraction(1 << max(exponent, 0), 1 << max(-exponent, 0)):
        exponent -= 1
    shift = max(exponent, 1 - bias) - precision + 1
    scaled = value * Fraction(1 << max(-shift, 0), 1 << max(shift, 0))
    significand, remainder = divmod(scaled.numerator, scaled.denominator)
    if 2 * remainder > scaled.denominator or (2 * remainder == scaled.denominator and significand & 1):
        significand += 1
    if significand >= 1 << precision:
        significand >>= 1
        exponent += 1
    if exponent > bias:
        return special(width, "inf", sign)
    encoded_exponent = max(exponent, 1 - bias) + bias if significand >= 1 << (precision - 1) else 0
    return ((sign << (width - 1)) | (encoded_exponent << (precision - 1))
            | (significand & ((1 << (precision - 1)) - 1)))


def convert(bits, source, destination):
    sign, kind, value = unpack(bits, source)
    return special(destination, kind, sign) if kind in ("nan", "inf", "zero") else round_fraction(value, destination)


def calculate(op, a, b, width):
    sa, ka, va = unpack(a, width)
    sb, kb, vb = unpack(b, width)
    if op == "neg":
        return special(width, "nan") if ka == "nan" else a ^ (1 << (width - 1))
    if "nan" in (ka, kb):
        return special(width, "nan")
    if op == "sub":
        b ^= 1 << (width - 1)
        sb, kb, vb = unpack(b, width)
        op = "add"
    if op == "add":
        if ka == kb == "inf" and sa != sb:
            return special(width, "nan")
        if ka == "inf" or kb == "inf":
            return special(width, "inf", sa if ka == "inf" else sb)
        return round_fraction(va + vb, width, sa & sb)
    if op == "mul":
        if "inf" in (ka, kb) and "zero" in (ka, kb):
            return special(width, "nan")
        if "inf" in (ka, kb):
            return special(width, "inf", sa ^ sb)
        return round_fraction(va * vb, width, sa ^ sb)
    if op == "div":
        if ka == kb == "inf" or ka == kb == "zero":
            return special(width, "nan")
        if ka == "inf" or kb == "zero":
            return special(width, "inf", sa ^ sb)
        if ka == "zero" or kb == "inf":
            return special(width, "zero", sa ^ sb)
        return round_fraction(va / vb, width)
    raise AssertionError(op)


def comparisons(a, b, width):
    sa, ka, va = unpack(a, width)
    sb, kb, vb = unpack(b, width)
    unordered = "nan" in (ka, kb)
    if ka == "inf":
        va = -math.inf if sa else math.inf
    if kb == "inf":
        vb = -math.inf if sb else math.inf
    tests = (False, True, False, False, False, False, True, False) if unordered else (
        va == vb, va != vb, va < vb, va <= vb, va > vb, va >= vb, False, True)
    return sum(int(x) << i for i, x in enumerate(tests))


def canonical(bits, width):
    return special(width, "nan") if unpack(bits, width)[1] == "nan" else bits


C_COMMON = support.PRELUDE + r"""
typedef union {float value;unsigned bits;} F32;
typedef union {double value;u64 bits;} F64;
static u64 canonical_f(float x){F32 v;v.value=x;unsigned b=v.bits;
    return (b&0x7fffffffU)>0x7f800000U?0x7fc00000U:b;}
static u64 canonical_d(double x){F64 v;v.value=x;u64 b=v.bits;
    return (b&0x7fffffffffffffffULL)>0x7ff0000000000000ULL?0x7ff8000000000000ULL:b;}
"""


def array(name, values):
    return f"static const u64 {name}[]={{" + ",".join(f"{x & support.MASK}ULL" for x in values) + "};\n"


def scalar_sources():
    provider = C_COMMON
    for suffix, typ in (("f", "float"), ("d", "double")):
        provider += f"{typ} arithmetic_{suffix}(unsigned op,{typ} a,{typ} b){{switch(op){{"
        provider += "case 0:return a+b;case 1:return a-b;case 2:return a*b;case 3:return a/b;default:return -a;}}\n"
        provider += f"u64 compare_{suffix}({typ} a,{typ} b){{return "
        provider += "(u64)(a==b)|((u64)(a!=b)<<1)|((u64)(a<b)<<2)|((u64)(a<=b)<<3)|((u64)(a>b)<<4)|((u64)(a>=b)<<5)|((u64)__builtin_isunordered(a,b)<<6)|((u64)!__builtin_isunordered(a,b)<<7);}\n"
        provider += f"{typ} select_{suffix}(unsigned c,{typ} a,{typ} b){{return c?a:b;}}\n"
        provider += f"{typ} signed_{suffix}(long long v){{return ({typ})v;}}\n"
        provider += f"{typ} unsigned_{suffix}(u64 v){{return ({typ})v;}}\n"
        provider += f"long long integer_{suffix}({typ} v){{return (long long)v;}}\n"
        provider += f"u64 uinteger_{suffix}({typ} v){{return (u64)v;}}\n"
        provider += f"{typ} boolean_{suffix}(_Bool v){{return ({typ})v;}}\n"
        provider += f"{typ} schar_{suffix}(signed char v){{return ({typ})v;}}\n"
        provider += f"signed char narrow_integer_{suffix}({typ} v){{return(signed char)v;}}\n"
    provider += "float narrow(double v){return (float)v;}\ndouble widen(float v){return (double)v;}\n"
    caller = C_COMMON + array("f32_bits", VECTORS[32]) + array("f64_bits", VECTORS[64])
    caller += array("signed_values", SIGNED) + array("unsigned_values", UNSIGNED) + array("integer_values", SAFE_INTS)
    for suffix, typ in (("f", "float"), ("d", "double")):
        caller += f"extern {typ} arithmetic_{suffix}(unsigned,{typ},{typ}),select_{suffix}(unsigned,{typ},{typ}),signed_{suffix}(long long),unsigned_{suffix}(u64);\n"
        caller += f"extern u64 compare_{suffix}({typ},{typ}),uinteger_{suffix}({typ});extern long long integer_{suffix}({typ});\n"
        caller += f"extern {typ} boolean_{suffix}(_Bool),schar_{suffix}(signed char);extern signed char narrow_integer_{suffix}({typ});\n"
    caller += "extern float narrow(double);extern double widen(float);\nu64 floating_case(u64 id,u64 seed){switch(id){\n"
    cases, expected = [], []

    def add(label, body, oracle):
        caller_parts.append(f"case {len(cases)}:{{{body}}}\n")
        cases.append(label)
        expected.extend(oracle(seed) & support.MASK for seed in SEEDS)

    caller_parts = []
    for width, suffix, union in ((32, "f", "F32"), (64, "d", "F64")):
        n = len(VECTORS[width])
        for opnum, op in enumerate(("add", "sub", "mul", "div", "neg")):
            for i in range(n):
                # Each seed selects another counterpart, keeping NaNs, signed
                # zero, subnormals, normal boundaries and overflow observable.
                body = f"{union} a,b;a.bits=f{width}_bits[{i}];b.bits=f{width}_bits[(seed+{i})%{n}];return canonical_{suffix}(arithmetic_{suffix}({opnum},a.value,b.value));"
                add([op, width, i], body, lambda seed, w=width, o=op, j=i: calculate(o, VECTORS[w][j], VECTORS[w][(seed+j) % n], w))
        for i in range(n):
            body = f"{union} a,b;a.bits=f{width}_bits[{i}];b.bits=f{width}_bits[(seed+{i})%{n}];return compare_{suffix}(a.value,b.value);"
            add(["compare", width, i], body, lambda seed, w=width, j=i: comparisons(VECTORS[w][j], VECTORS[w][(seed+j) % len(VECTORS[w])], w))
            body = f"{union} a,b;a.bits=f{width}_bits[{i}];b.bits=f{width}_bits[(seed+{i})%{n}];return canonical_{suffix}(select_{suffix}(seed&1,a.value,b.value));"
            add(["select", width, i], body, lambda seed, w=width, j=i: canonical(VECTORS[w][j if seed & 1 else (seed+j) % len(VECTORS[w])], w))
        for i, value in enumerate(SIGNED):
            add(["sitofp", width, value], f"return canonical_{suffix}(signed_{suffix}((long long)signed_values[{i}]));", lambda seed, w=width, v=value: round_fraction(Fraction(v), w))
        for i, value in enumerate(UNSIGNED):
            add(["uitofp", width, value], f"return canonical_{suffix}(unsigned_{suffix}(unsigned_values[{i}]));", lambda seed, w=width, v=value: round_fraction(Fraction(v), w))
        for i, value in enumerate(SAFE_INTS):
            add(["fptosi", width, value], f"return (u64)integer_{suffix}(({('float' if width == 32 else 'double')})(long long)integer_values[{i}]);", lambda seed, w=width, v=value: int(unpack(round_fraction(Fraction(v), w), w)[2]))
            if value >= 0:
                add(["fptoui", width, value], f"return uinteger_{suffix}(({('float' if width == 32 else 'double')})integer_values[{i}]);", lambda seed, w=width, v=value: int(unpack(round_fraction(Fraction(v), w), w)[2]))
        for value in (False, True):
            add(["i1-to-fp", width, value], f"return canonical_{suffix}(boolean_{suffix}({int(value)}));", lambda seed, w=width, v=value: round_fraction(Fraction(int(v)), w))
        for value in (-128, -101, -1, 0, 1, 127):
            add(["i8-to-fp", width, value], f"return canonical_{suffix}(schar_{suffix}({value}));", lambda seed, w=width, v=value: round_fraction(Fraction(v), w))
            add(["fp-to-i8", width, value], f"return(u64)(long long)narrow_integer_{suffix}({value}.0);", lambda seed, v=value: v)
        # Every conversion below is within the C defined domain. In particular
        # rounded2^64 and positive2^63 are never converted to an out-of-range int.
        step = 1 << (64 - FORMATS[width][1])
        for value in ((1 << 63)-step, 1 << 63, (1 << 63)+2*step, (1 << 64)-2*step):
            bits = round_fraction(Fraction(value), width)
            add(["fp-to-u64-boundary", width, value], f"{union} v;v.bits={bits}ULL;return uinteger_{suffix}(v.value);", lambda seed, w=width, b=bits: int(unpack(b,w)[2]))
        for value in (-(1 << 63), -(1 << 63)+step, (1 << 63)-step):
            bits = round_fraction(Fraction(value), width)
            add(["fp-to-i64-boundary", width, value], f"{union} v;v.bits={bits}ULL;return(u64)integer_{suffix}(v.value);", lambda seed, w=width, b=bits: int(unpack(b,w)[2]))
    for width, operation, result_width, union, result_suffix in ((64, "narrow", 32, "F64", "f"), (32, "widen", 64, "F32", "d")):
        for i, value in enumerate(VECTORS[width]):
            add([operation, width, i], f"{union} v;v.bits=f{width}_bits[{i}];return canonical_{result_suffix}({operation}(v.value));", lambda seed, w=width, v=value, r=result_width: convert(v, w, r))
    return provider, caller + "".join(caller_parts) + "default:return 0;}}\n", cases, expected


def bank_sources():
    provider, caller = C_COMMON, C_COMMON
    cases, expected = [], []
    caller_bodies = []
    # Independent FP and GP counters, FP exhaustion, and named stack slots.
    for count in (0, 1, 7, 8, 9, 12):
        for width, suffix, typ in ((32, "f", "float"), (64, "d", "double")):
            name = f"bank_{suffix}_{count}"
            params = [f"u64 g{i}" for i in range(count)] + [f"{typ} f{i}" for i in range(count)] + ["u64 tag"]
            signature = ",".join(params)
            provider += f"u64 {name}({signature}){{u64 h=tag;"
            provider += "".join(f"h=mix(h,g{i});h=mix(h,canonical_{suffix}(f{i}));" for i in range(count)) + "return h;}\n"
            caller += f"extern u64 {name}({signature});\n"
            args = [f"seed^{i+100}ULL" for i in range(count)] + [f"({typ}){i+1}.5" for i in range(count)] + ["seed"]
            direct = f"return {name}(" + ",".join(args) + ");"
            indirect = f"u64(*volatile target)({signature})={name};return target(" + ",".join(args) + ");"
            for mode, body in (("direct", direct), ("indirect", indirect)):
                caller_bodies.append(f"case {len(cases)}:{{{body}}}\n")
                cases.append(["named-banks", mode, width, count])
                for seed in SEEDS:
                    values = []
                    for i in range(count):
                        values.extend((seed ^ (i + 100), round_fraction(Fraction(2*i+3, 2), width)))
                    expected.append(support.fold(values, seed))
    caller += "u64 floating_case(u64 id,u64 seed){switch(id){" + "".join(caller_bodies) + "default:return 0;}}\n"
    return provider, caller, cases, expected


def wide_type(profile):
    return "typedef __float128 wide;" if profile == "x86_64" else "typedef long double wide;"


def wide_sources(profile, conversions=False, extended=False):
    prelude = C_COMMON + ("typedef long double wide;" if extended else wide_type(profile))
    prelude += "\ntypedef union{wide value;u64 words[2];} W;\n"
    bits = ([(0, 0), (0, 0x8000), (0x8000000000000000, 0x3FFF),
             (0x8000000000000000, 0xBFFF), (0xC000000000000000, 0x3FFF),
             (1, 0), (0x8000000000000000, 1), (0x8000000000000000, 0x7FFF)]
            if extended else [(x & support.MASK, x >> 64) for x in WIDE_VECTORS])
    mask = 0xFFFF if extended else support.MASK
    prelude += f'_Static_assert(sizeof(wide)==16,"wide storage must occupy16bytes");\n'
    provider = prelude + "wide transport(wide v,volatile wide*slot){*slot=v;return *slot;}\n"
    if conversions:
        provider += "double to_double(wide v){return(double)v;}float to_float(wide v){return(float)v;}wide from_double(double v){return(wide)v;}wide from_float(float v){return(wide)v;}\n"
    caller = prelude + "extern wide transport(wide,volatile wide*);\nstatic volatile wide slot;\n"
    if conversions:
        caller += "extern double to_double(wide);extern float to_float(wide);extern wide from_double(double);extern wide from_float(float);\n"
    caller += array("lows", [a for a, b in bits]) + array("highs", [b for a, b in bits])
    caller += array("double_bits", VECTORS[64])
    caller += array("float_bits", VECTORS[32])
    caller += "u64 floating_case(u64 id,u64 seed){W v,r;switch(id){\n"
    cases, expected, bodies = [], [], []

    def add(label, body, value):
        cases.append(label)
        bodies.append(f"case {len(cases)-1}:{{{body}}}\n")
        expected.extend([value & support.MASK] * len(SEEDS))

    for i, (low, high) in enumerate(bits):
        body = f"v.words[0]=lows[{i}];v.words[1]=highs[{i}];r.value=transport(v.value,&slot);"
        add(["wide-transport", 80 if extended else 128, i], body + f"return mix(r.words[0],r.words[1]&{mask}ULL);", support.fold([high & mask], low))
        if conversions:
            for width, name, suffix in ((64, "to_double", "d"), (32, "to_float", "f")):
                add(["fptrunc", 128, width, i], f"v.words[0]=lows[{i}];v.words[1]=highs[{i}];return canonical_{suffix}({name}(v.value));", convert(low | high << 64, 128, width))
    if conversions:
        for i, value in enumerate(VECTORS[64]):
            wide = convert(value, 64, 128)
            # IEEE payload is intentionally canonicalised by masking neither
            # payload nor sign here: these fpext cases exclude NaN.
            if unpack(value, 64)[1] == "nan":
                continue
            add(["fpext", 64, 128, i], f"F64 d;d.bits=double_bits[{i}];r.value=from_double(d.value);return mix(r.words[0],r.words[1]);", support.fold([wide >> 64], wide & support.MASK))
        for i, value in enumerate(VECTORS[32]):
            if unpack(value, 32)[1] == "nan":
                continue
            wide = convert(value, 32, 128)
            add(["fpext", 32, 128, i], f"F32 f;f.bits=float_bits[{i}];r.value=from_float(f.value);return mix(r.words[0],r.words[1]);", support.fold([wide >> 64], wide & support.MASK))
    return provider, caller + "".join(bodies) + "default:return 0;}}\n", cases, expected


def quad_arithmetic_sources(profile):
    prelude = C_COMMON + wide_type(profile) + "\ntypedef union{wide value;u64 words[2];} W;\n"
    provider = prelude + "wide wide_arithmetic(unsigned op,wide a,wide b){switch(op){case0:return a+b;case1:return a-b;case2:return a*b;case3:return a/b;default:return -a;}}\n".replace("case0", "case 0").replace("case1", "case 1").replace("case2", "case 2").replace("case3", "case 3")
    provider += "wide wide_signed(long long v){return(wide)v;}wide wide_unsigned(u64 v){return(wide)v;}long long wide_to_signed(wide v){return(long long)v;}u64 wide_to_unsigned(wide v){return(u64)v;}\n"
    caller = prelude + "extern wide wide_arithmetic(unsigned,wide,wide),wide_signed(long long),wide_unsigned(u64);extern long long wide_to_signed(wide);extern u64 wide_to_unsigned(wide);\n"
    caller += array("lows", [x & support.MASK for x in WIDE_VECTORS]) + array("highs", [x >> 64 for x in WIDE_VECTORS])
    caller += array("signed_values", SIGNED) + array("unsigned_values", UNSIGNED)
    caller += "u64 floating_case(u64 id,u64 seed){W a,b,r;switch(id){\n"
    cases, expected, bodies = [], [], []
    n = len(WIDE_VECTORS)

    def add(label, body, oracle):
        bodies.append(f"case {len(cases)}:{{{body}}}\n")
        cases.append(label)
        expected.extend(oracle(seed) & support.MASK for seed in SEEDS)

    for opnum, op in enumerate(("add", "sub", "mul", "div", "neg")):
        for i in range(n):
            body = f"a.words[0]=lows[{i}];a.words[1]=highs[{i}];b.words[0]=lows[(seed+{i})%{n}];b.words[1]=highs[(seed+{i})%{n}];r.value=wide_arithmetic({opnum},a.value,b.value);"
            body += "if((r.words[1]&0x7fff000000000000ULL)==0x7fff000000000000ULL&&((r.words[1]&0x0000ffffffffffffULL)||r.words[0])){r.words[0]=0;r.words[1]=0x7fff800000000000ULL;}"
            for word in (0, 1):
                add(["quad-"+op, i, word], body + f"return r.words[{word}];", lambda seed, o=op, j=i, w=word: calculate(o,WIDE_VECTORS[j],WIDE_VECTORS[(seed+j)%n],128) >> (64*w))
    for name, values in (("signed", SIGNED), ("unsigned", UNSIGNED)):
        for i, value in enumerate(values):
            bits = round_fraction(Fraction(value), 128)
            for word in (0, 1):
                add([name+"-to-quad", value, word], f"r.value=wide_{name}(({('long long' if name=='signed' else 'u64')}){name}_values[{i}]);return r.words[{word}];", lambda seed, b=bits, w=word: b >> (64*w))
            add(["quad-to-"+name, value], f"a.words[0]={bits & support.MASK}ULL;a.words[1]={bits >> 64}ULL;return(u64)wide_to_{name}(a.value);", lambda seed, v=value: v)
    return provider, caller + "".join(bodies) + "default:return 0;}}\n", cases, expected


def variadic_sources(profile, reverse=False):
    prelude = C_COMMON + wide_type(profile) + "\ntypedef union{wide value;u64 words[2];} W;\n"
    provider = prelude
    caller = prelude
    cases, expected, bodies = [], [], []
    for named_gp in (1, 7, 9):
        for named_fp in (0, 7, 9):
            name = f"variadic_{named_gp}_{named_fp}" + ("_quad_first" if reverse else "")
            parameters = ["unsigned n"] + [f"u64 g{i}" for i in range(named_gp - 1)] + [f"double d{i}" for i in range(named_fp)]
            last = f"d{named_fp-1}" if named_fp else (f"g{named_gp-2}" if named_gp > 1 else "n")
            signature = ",".join(parameters) + ",..."
            provider += f"u64 {name}({signature}){{va_list ap,copy;va_start(ap,{last});u64 h=0xcbf29ce484222325ULL;"
            # Copy after consuming one pair; a zero-tail call still starts and
            # copies both lists without reading a nonexistent argument.
            read = "q.value=va_arg(ap,wide);d.value=va_arg(ap,double);" if reverse else "d.value=va_arg(ap,double);q.value=va_arg(ap,wide);"
            provider += "if(n){F64 d;W q;" + read + "h=mix(mix(mix(h,d.bits),q.words[0]),q.words[1]);}va_copy(copy,ap);u64 other=h;"
            provider += "for(unsigned i=1;i<n;++i){F64 d;W q;" + read + "h=mix(mix(mix(h,d.bits),q.words[0]),q.words[1]);}"
            provider += "for(unsigned i=1;i<n;++i){F64 d;W q;" + read.replace("(ap,", "(copy,") + "other=mix(mix(mix(other,d.bits),q.words[0]),q.words[1]);}va_end(copy);va_end(ap);return mix(mix(0x1234ULL,h),other);}\n"
            caller += f"extern u64 {name}({signature});\n"
            for count in LENGTHS:
                args = [str(count)] + [f"{i+100}ULL" for i in range(named_gp - 1)] + [f"{i+1}.5" for i in range(named_fp)]
                for i in range(count):
                    pair = [f"(float){i+1}.5f", f"q{i}.value"]
                    args += pair[::-1] if reverse else pair
                body = "".join(f"W q{i};q{i}.words[0]=seed^{i+1}ULL;q{i}.words[1]=0x3fff000000000000ULL;" for i in range(count))
                body += f"return {name}(" + ",".join(args) + ");"
                bodies.append(f"case {len(cases)}:{{{body}}}\n")
                cases.append(["variadic-quad-double-copy" if reverse else "variadic-double-quad-copy", named_gp, named_fp, count])
                for seed in SEEDS:
                    values = []
                    for i in range(count):
                        values += [round_fraction(Fraction(2*i+3, 2), 64), seed ^ (i+1), 0x3FFF000000000000]
                    h = support.fold(values)
                    expected.append(support.fold([h, h], 0x1234))
    caller += "u64 floating_case(u64 id,u64 seed){switch(id){" + "".join(bodies) + "default:return 0;}}\n"
    return provider, caller, cases, expected


class NativeFloatingAbiTests(support.NativeVariadicAbiTests):
    @classmethod
    def setUpClass(cls):
        cls.compiler = os.environ.get("OCORE_TEST_OCOREC", os.environ.get("OCOREC", str(ROOT / "target/debug/ocorec")))
        cls.clang = os.environ.get("OCORE_TEST_CLANG22", str(support.SDK / "llvm-22/bin/clang"))
        cls.linker = os.environ.get("OCORE_TEST_LLD", shutil.which("ld.lld"))
        cls.library = os.environ.get("OCORE_TEST_LLVM_LIBRARY", str(support.SDK / "riscv64-linux-gnu/libLLVM.so.22.1"))
        cls.pin = os.environ.get("OCORE_TEST_LLVM_SHA256", support.LLVM_SHA256)
        cls.nm = os.environ.get("OCORE_TEST_LLVM_NM", str(support.SDK / "llvm-22/bin/llvm-nm"))
        tools = [("clang", cls.clang), ("linker", cls.linker), ("llvm_library", cls.library), ("llvm_nm", cls.nm)]
        if not REFERENCE_ONLY:
            tools.append(("ocorec", cls.compiler))
        for name, path in tools:
            if not path or not Path(path).is_file():
                raise AssertionError(f"selected {name} unavailable; no incomplete matrix is counted as a pass")
        cls.identities = {key: support.artifact(path) for key, path in tools}
        if cls.identities["llvm_library"]["sha256"] != cls.pin:
            raise AssertionError("selected LLVM parser does not match its explicit SHA256")
        cls.environment = dict(os.environ)
        cls.environment["PATH"] = str(Path(cls.clang).parent) + os.pathsep + cls.environment.get("PATH", "")
        cls.environment["LD_LIBRARY_PATH"] = str(Path(cls.library).parent) + os.pathsep + str(support.SDK / "llvm-22/lib")
        version = subprocess.run([cls.clang, "--version"], capture_output=True, text=True, env=cls.environment, timeout=30)
        versions = re.findall(r"\bclang version\s+([0-9]+\.[0-9]+\.[0-9]+)(?![0-9.])", version.stdout + "\n" + version.stderr)
        if version.returncode or versions != ["22.1.6"]:
            raise AssertionError("selected frontend must be exactly Clang22.1.6")

    def setUp(self):
        retain = os.environ.get("OCORE_FP_RETAIN")
        if retain:
            Path(retain).mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="floating-", dir=retain))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-floating-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.record = {"schema": "ocore-floating-interoperability-v1", "test": self.id(),
                       "tools": self.identities, "commands": [], "pairings": [], "complete": False,
                       "reference_only": REFERENCE_ONLY, "runtime_complete": False,
                       "provider_closure_complete": False, "native_execution_qualified": False,
                       "execution_profile": "Linux development ELF carrier; native host or explicit QEMU"}
        self.save()

    def frontend_flags(self, profile):
        return super().frontend_flags(profile) + ["-ffp-contract=off"]

    def original(self, name, source, profile):
        # The original C module and Clang LLVM remain a single full input unit.
        return super().original(name, source, profile)

    def owned(self, name, llvm, profile):
        obj = super().owned(name, llvm, profile)
        # The shared helper preserves exact original defined functions and the
        # independent verifier receipt. NativeModule representation is not
        # handcrafted or filtered by this execution harness.
        return obj

    def required_archives(self, profile, objects):
        result = self.command([self.nm, "--undefined-only", *objects])
        helpers = sorted(set(re.findall(r"\b(__[A-Za-z0-9_]+)\s*$", result.stdout.decode(), re.M)))
        if not helpers:
            return []
        variable = "OCORE_FP_BUILTINS_" + profile.upper().replace("-", "_")
        path = os.environ.get(variable)
        self.record.setdefault("compiler_runtime_dependencies", []).append({"profile": profile,
            "required_symbols": helpers, "selection_variable": variable, "archive": support.artifact(path) if path and Path(path).is_file() else None})
        self.save()
        self.assertTrue(path and Path(path).is_file(),
                        f"original compiler-runtime helpers {helpers} require an explicitly selected archive via {variable}")
        manifest_path = os.environ.get("OCORE_FP_BUILTINS_MANIFEST")
        self.assertTrue(manifest_path and Path(manifest_path).is_file(),
                        "compiler-runtime archives require OCORE_FP_BUILTINS_MANIFEST with exact original source/build evidence")
        manifest = json.loads(Path(manifest_path).read_text())
        self.assertEqual(manifest["schema"], "ocore-fp-original-compiler-runtime-provider-v1")
        self.assertEqual(manifest["source_release"], "llvmorg-22.1.6")
        self.assertEqual(manifest["source_commit"], "fc4aad7b5db3fff421df9a9637605b9ca5667881")
        self.assertEqual(manifest["stage"], "complete")
        self.assertIs(manifest["sources_stable"], True)
        self.assertIs(manifest["helpers_lowered_through_ocore"], False)
        self.assertEqual(manifest["profiles"][profile]["archive"], support.artifact(path))
        for file in manifest["source_files"]:
            actual = support.artifact(file["path"])
            self.assertEqual(actual, {key: file[key] for key in actual})
            raw = Path(file["path"]).read_bytes()
            self.assertEqual(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(), file["git_blob_sha"])
        for dependency in manifest["profiles"][profile]["all_compile_dependencies"]:
            self.assertEqual(support.artifact(dependency["path"]), dependency)
        self.record.setdefault("original_runtime_provider_manifests", []).append(support.artifact(manifest_path))
        self.save()
        return [Path(path)]

    def matrix(self, profile, scope, fixture):
        provider_source, caller_source, cases, expected_values = fixture
        isa, mode, machine, _ = support.PROFILES[profile]
        runner = self.execution_prefix(isa)
        provider_c, provider_ll, provider_ref = self.original(scope + "-provider", provider_source, profile)
        caller_c, caller_ll, caller_ref = self.original(scope + "-caller", caller_source, profile)
        carrier = support.carrier_source().replace("variadic_case", "floating_case")
        carrier = carrier.replace(f"output[{len(support.CASES)*len(support.SEEDS)}]", f"output[{len(cases)*len(SEEDS)}]")
        carrier = carrier.replace(f"test<{len(support.CASES)}", f"test<{len(cases)}")
        carrier = carrier.replace(f"seed<{len(support.SEEDS)}", f"seed<{len(SEEDS)}")
        carrier = carrier.replace("static const u64 seeds[]={" + ",".join(f"{s}ULL" for s in support.SEEDS) + "};", array("seeds", SEEDS).strip())
        carrier_c, carrier_ll, carrier_obj = self.original(scope + "-carrier", carrier, profile)
        originals = [support.artifact(p) for p in (provider_c, provider_ll, caller_c, caller_ll, carrier_c, carrier_ll)]
        self.record.update(profile=profile, scope=scope, original_inputs=originals,
                           source_cases=cases, seeds=list(SEEDS), comparisons_per_pairing=len(expected_values),
                           execution_argv_prefix=runner)
        self.save()
        providers = [("reference", provider_ref)]
        callers = [("reference", caller_ref)]
        if not REFERENCE_ONLY:
            providers.append(("owned", self.owned(scope + "-provider", provider_ll, profile)))
            callers.append(("owned", self.owned(scope + "-caller", caller_ll, profile)))
        expected = struct.pack("<" + "Q" * len(expected_values), *expected_values)
        self.record["expected_output_sha256"] = hashlib.sha256(expected).hexdigest()
        for caller_name, caller in callers:
            for provider_name, provider in providers:
                archives = self.required_archives(profile, [provider, caller])
                archive_pins = [support.artifact(p) for p in archives]
                executable = self.directory / f"{caller_name}-caller-{provider_name}-provider.elf"
                self.command([self.linker, "-static", "--no-relax", "-m", mode, "-e", "_start",
                              carrier_obj, caller, provider, *archives, "-o", executable])
                self.assert_elf(executable, machine, 2)
                result = self.command([*runner, executable], timeout=60)
                if result.stdout != expected:
                    actual = list(struct.unpack("<" + "Q" * (len(result.stdout)//8), result.stdout)) if len(result.stdout) % 8 == 0 else []
                    index = next((i for i, pair in enumerate(zip(actual, expected_values)) if pair[0] != pair[1]), min(len(actual), len(expected_values)))
                    case = cases[index//len(SEEDS)] if index < len(expected_values) else None
                    self.fail(f"{profile}/{scope}/{caller_name}/{provider_name}: first mismatch {index},case={case}, actual={actual[index:index+1]},expected={expected_values[index:index+1]}; bytes={len(result.stdout)}/{len(expected)}")
                self.assertEqual([support.artifact(p) for p in archives], archive_pins)
                self.record["pairings"].append({"caller": caller_name, "provider": provider_name,
                    "caller_object": support.artifact(caller), "provider_object": support.artifact(provider),
                    "carrier_object": support.artifact(carrier_obj), "executable": support.artifact(executable),
                    "runtime_archives": [support.artifact(p) for p in archives],
                    "comparisons": len(expected_values), "stdout_sha256": hashlib.sha256(result.stdout).hexdigest()})
                self.save()
        self.assertEqual([support.artifact(p["path"]) for p in originals], originals)
        for provider_manifest in self.record.get("original_runtime_provider_manifests", []):
            self.assertEqual(support.artifact(provider_manifest["path"]), provider_manifest)
        self.record["reference_control_complete"] = True
        self.record["complete"] = not REFERENCE_ONLY
        self.save()


# Reuse the strict shared command/import/verification/ELF helpers, not its
# unrelated integer tests. unittest only discovers callable test attributes.
for _name in dir(support.NativeVariadicAbiTests):
    if _name.startswith("test_"):
        setattr(NativeFloatingAbiTests, _name, None)


def register_tests():
    for profile in support.PROFILES:
        for scope, builder in (("scalar", lambda p: scalar_sources()), ("named_banks", lambda p: bank_sources()),
                               ("wide_transport", wide_sources),
                               ("wide_conversions", lambda p: wide_sources(p, conversions=True)),
                               ("quad_arithmetic", quad_arithmetic_sources),
                               ("floating_variadic", variadic_sources),
                               ("floating_variadic_quad_first", lambda p: variadic_sources(p, reverse=True))):
            def method(self, p=profile, s=scope, b=builder):
                self.matrix(p, s, b(p))
            setattr(NativeFloatingAbiTests, "test_" + profile.replace("-", "_") + "_" + scope, method)
    def extended(self):
        self.matrix("x86_64", "x87_transport", wide_sources("x86_64", extended=True))
    NativeFloatingAbiTests.test_x86_64_x87_transport = extended


register_tests()


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--reference-only":
        REFERENCE_ONLY = True
        output = Path(sys.argv[2]).resolve()
        output.mkdir(parents=True, exist_ok=False)
        os.environ["OCORE_FP_RETAIN"] = str(output)
        selected = sys.argv[3:] or ["scalar", "named_banks", "wide_transport", "floating_variadic", "floating_variadic_quad_first", "x87_transport"]
        allowed = {"scalar", "named_banks", "wide_transport", "wide_conversions", "quad_arithmetic", "floating_variadic", "floating_variadic_quad_first", "x87_transport"}
        if set(selected) - allowed:
            raise SystemExit("unknown reference scope")
        suite = unittest.TestSuite(NativeFloatingAbiTests(name) for name in unittest.defaultTestLoader.getTestCaseNames(NativeFloatingAbiTests)
                                   if any(name.endswith("_" + scope) for scope in selected))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        rows = [support.artifact(p) for p in sorted(output.glob("floating-*/report.json"))]
        (output / "reference-controls.json").write_text(json.dumps({"schema": "ocore-floating-reference-controls-v1",
            "selected_scopes": selected, "test_methods": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skips": len(result.skipped), "reports": rows,
            "owned_compilation_attempted": False, "runtime_complete": False}, indent=2) + "\n")
        raise SystemExit(not result.wasSuccessful())
    unittest.main()
