"""Aggregate SSA and memory conformance with scalar-only C ABI entry points.

Original LLVM and genuine Clang C units are never rewritten or interpreted.
Python specifies defined field bytes, pointer identities and scalar results;
padding is deliberately unobserved after aggregate stores. Linux/QEMU carries
the comparison, not full runtime, exception-handling or kernel qualification.
"""

import copy
import ctypes as C
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_native_equivalence import TARGETS, elf
from tests import test_ocore_native_allocsize as census
from tests import test_ocore_native_weak as weak


MASK = weak.MASK
ANCHOR, CALLBACK_BIAS = 0x123456789abcdef0, 0x9e3779b97f4a7c15
TYPES = """
%Empty = type {}
%Leaf = type {i32, ptr}
%Bundle = type {i8, [2 x %Leaf], [3 x i16]}
%Packed = type <{i8, %Bundle, i32}>
%Outer = type {%Empty, [0 x i64], %Packed, [2 x i8]}
"""
LITERAL = "%Bundle {i8 5, [2 x %Leaf] [%Leaf {i32 11, ptr @anchor_alias}, %Leaf {i32 22, ptr @callback_alias}], [3 x i16] [i16 33, i16 44, i16 55]}"
SEEDS = (0, 1, 255, 256, 65535, 65536, (1 << 31), (1 << 32),
         (1 << 63) - 1, (1 << 63), MASK - 1, MASK)
ROUNDS = (0, 1, 2, 3, 7, 8, 31, 32)
LAYOUTS = {"Empty": (0, 1, []), "Leaf": (16, 8, [0, 8]),
           "Bundle": (48, 8, [0, 8, 40]), "Packed": (53, 1, [0, 1, 49]),
           "Outer": (56, 8, [0, 0, 0, 53])}


def bundle(tag, first, second, words, pointers=(1, 2)):
    return {"tag": tag & 255, "numbers": [first & 0xffffffff, second & 0xffffffff],
            "pointers": list(pointers), "words": [value & 65535 for value in words]}


def input_bundle(seed):
    return bundle(17, seed * 3, (seed >> 32) ^ 0xffffffff,
                  [seed, seed >> 16, seed >> 48])


def literal_bundle():
    return bundle(5, 11, 22, [33, 44, 55])


def transformed(seed, rounds, mode):
    first, second = copy.deepcopy(input_bundle(seed)), copy.deepcopy(input_bundle(seed))
    first["tag"] = (seed ^ 0x5a) & 255
    first["words"][1] = (seed ^ 0x1357) & 65535
    second["numbers"][0] = second["numbers"][1] ^ 0x89abcdef
    second["words"][2] = ((seed >> 32) ^ 0x2468) & 65535
    # This model follows simultaneous swaps, independently of SSA allocation.
    for _ in range(rounds):
        first, second = second, first
    selected, other = (second, first) if mode else (first, second)
    undef = bundle(seed ^ 0xd3, seed >> 17, seed * 5,
                   [seed, seed >> 32, (seed >> 16) ^ 0xabcd])
    poison = copy.deepcopy(undef)
    poison["tag"] = (seed ^ 0xe7) & 255
    return {"selected": selected, "other": other, "undef": undef, "poison": poison,
            "zero": bundle(0, 0, 0, [0, 0, 0], (0, 0)), "literal": literal_bundle(),
            "packed": (0x6b, selected, ((seed >> 13) ^ 0x10203040) & 0xffffffff),
            "outer": (0xc7, other, (seed ^ 0xa55a5aa5) & 0xffffffff, [0x34, (seed >> 48) & 255])}


def image(values):
    data, mask, pointers = [0xa5] * 512, [1] * 512, []

    def integer(at, value, width):
        data[at:at+width] = list(value.to_bytes(width, "little"))
        mask[at:at+width] = [1] * width

    def write_bundle(at, value):
        mask[at:at+48] = [0] * 48
        integer(at, value["tag"], 1)
        for index in range(2):
            integer(at+8+16*index, value["numbers"][index], 4)
            pointer_at = at+16+16*index
            mask[pointer_at:pointer_at+8] = [2] * 8
            pointers.append((pointer_at, value["pointers"][index]))
        for index, word in enumerate(value["words"]):
            integer(at+40+2*index, word, 2)

    for at, key in ((0, "selected"), (64, "other"), (256, "undef"),
                    (320, "poison"), (384, "zero"), (448, "literal")):
        write_bundle(at, values[key])
    for at, key, size in ((128, "packed", 53), (192, "outer", 56)):
        mask[at:at+size] = [0] * size
        tag, nested, last, *tail = values[key]
        integer(at, tag, 1)
        write_bundle(at+1, nested)
        integer(at+49, last, 4)
        if tail:
            integer(at+53, tail[0][0], 1)
            integer(at+54, tail[0][1], 1)
    return data, mask, pointers


def scalar_result(seed, values):
    selected, other = values["selected"], values["other"]
    return ((seed ^ CALLBACK_BIAS) ^ ANCHOR ^ selected["numbers"][0]
            ^ (selected["numbers"][1] << 32) ^ selected["tag"]
            ^ selected["words"][1] ^ other["numbers"][0]
            ^ (((seed >> 48) & 255) << 56)) & MASK


def observation(seed, rounds, mode, unaligned):
    values = transformed(seed, rounds, mode)
    data, mask, pointers = image(values)
    result = [scalar_result(seed, values)]
    # Prefix/suffix and gaps are ordinary canaries. Aggregate padding and
    # relocation address bytes are replaced by explicit identity observations.
    start = 33 if unaligned else 32
    result.extend([0xa5] * start)
    result.extend(value for value, keep in zip(data, mask) if keep == 1)
    result.extend([0xa5] * (576-start-512))
    result.extend([1] * len(pointers))
    # The input must remain byte-identical, including its initialized padding.
    input_data, input_mask, _ = image({"selected": input_bundle(seed), "other": input_bundle(seed),
                                     "undef": input_bundle(seed), "poison": input_bundle(seed),
                                     "zero": input_bundle(seed), "literal": input_bundle(seed),
                                     "packed": (0, input_bundle(seed), 0),
                                     "outer": (0, input_bundle(seed), 0, [0, 0])})
    initial = [0xa5] * 128
    for index in range(48):
        if input_mask[index] == 1:
            initial[start+index] = input_data[index]
    result.extend(value for index, value in enumerate(initial)
                  if not (start+16 <= index < start+24 or start+32 <= index < start+40))
    result.extend([1, 1])
    return result


def golden():
    values = [ANCHOR, 1, 1, 5, 11, 22, 33, 44, 55, 1, 1]
    for seed in SEEDS:
        for rounds in ROUNDS:
            for mode in (0, 1):
                for unaligned in (0, 1):
                    values.extend(observation(seed, rounds, mode, unaligned))
    digest = 0xcbf29ce484222325
    for value in values:
        digest = ((digest ^ value) * 0x100000001b3) & MASK
    return f"OCORE-AGGREGATES digest={digest:016x} checks={len(values)}\n".encode()


def llvm_function(name, alignment):
    lines = [f"define i64 @{name}(ptr %input, ptr %output, i64 %seed, i64 %rounds, i64 %mode) {{", "entry:",
             f"  %base = load %Bundle, ptr %input, align {alignment}",
             "  %tag64 = xor i64 %seed, 90", "  %tag = trunc i64 %tag64 to i8",
             "  %word64 = xor i64 %seed, 4951", "  %word = trunc i64 %word64 to i16",
             "  %left0 = insertvalue %Bundle %base, i8 %tag, 0",
             "  %left = insertvalue %Bundle %left0, i16 %word, 2, 1",
             "  %number = extractvalue %Bundle %base, 1, 1, 0",
             "  %changed = xor i32 %number, 2309737967",
             "  %high = lshr i64 %seed, 32", "  %right_word64 = xor i64 %high, 9320",
             "  %right_word = trunc i64 %right_word64 to i16",
             "  %right0 = insertvalue %Bundle %base, i32 %changed, 1, 0, 0",
             "  %right1 = insertvalue %Bundle %right0, ptr @anchor, 1, 0, 1",
             "  %right = insertvalue %Bundle %right1, i16 %right_word, 2, 2",
             "  br label %loop", "loop:",
             "  %a = phi %Bundle [%left, %entry], [%b, %body]",
             "  %b = phi %Bundle [%right, %entry], [%a, %body]",
             "  %index = phi i64 [0, %entry], [%next, %body]",
             "  %done = icmp eq i64 %index, %rounds", "  br i1 %done, label %exit, label %body",
             "body:", "  %next = add i64 %index, 1", "  br label %loop", "exit:",
             "  %frozen_a = freeze %Bundle %a", "  %frozen_b = freeze %Bundle %b",
             "  %bit = and i64 %mode, 1", "  %condition = icmp eq i64 %bit, 0",
             "  br i1 %condition, label %choose_a, label %choose_b",
             "choose_a:", "  br label %join", "choose_b:", "  br label %join", "join:",
             "  %selected = phi %Bundle [%frozen_a, %choose_a], [%frozen_b, %choose_b]",
             "  %other = phi %Bundle [%frozen_b, %choose_a], [%frozen_a, %choose_b]",
             f"  store %Bundle %selected, ptr %output, align {alignment}",
             "  %slot64 = getelementptr i8, ptr %output, i64 64",
             f"  store %Bundle %other, ptr %slot64, align {alignment}",
             "  %last_shift = lshr i64 %seed, 13", "  %last_xor = xor i64 %last_shift, 270544960",
             "  %last = trunc i64 %last_xor to i32",
             "  %packed0 = insertvalue %Packed zeroinitializer, i8 107, 0",
             "  %packed1 = insertvalue %Packed %packed0, %Bundle %selected, 1",
             "  %packed = insertvalue %Packed %packed1, i32 %last, 2",
             "  %slot128 = getelementptr i8, ptr %output, i64 128",
             "  store %Packed %packed, ptr %slot128, align 1",
             "  %outer_last64 = xor i64 %seed, 2774162085", "  %outer_last = trunc i64 %outer_last64 to i32",
             "  %outer_packed0 = insertvalue %Packed zeroinitializer, i8 199, 0",
             "  %outer_packed1 = insertvalue %Packed %outer_packed0, %Bundle %other, 1",
             "  %outer_packed = insertvalue %Packed %outer_packed1, i32 %outer_last, 2",
             "  %tail64 = lshr i64 %seed, 48", "  %tail = trunc i64 %tail64 to i8",
             "  %outer0 = insertvalue %Outer zeroinitializer, %Packed %outer_packed, 2",
             "  %outer1 = insertvalue %Outer %outer0, i8 52, 3, 0",
             "  %outer = insertvalue %Outer %outer1, i8 %tail, 3, 1",
             "  %slot192 = getelementptr i8, ptr %output, i64 192",
             f"  store %Outer %outer, ptr %slot192, align {alignment}",
             "  %small0 = trunc i64 %seed to i16", "  %small1 = trunc i64 %high to i16",
             "  %middle = lshr i64 %seed, 16", "  %small264 = xor i64 %middle, 43981",
             "  %small2 = trunc i64 %small264 to i16", "  %first64 = lshr i64 %seed, 17",
             "  %first32 = trunc i64 %first64 to i32", "  %second64 = mul i64 %seed, 5",
             "  %second32 = trunc i64 %second64 to i32"]
    fields = [("i8", "%scratch_tag", "0"), ("i32", "%first32", "1, 0, 0"),
              ("ptr", "@anchor_alias", "1, 0, 1"), ("i32", "%second32", "1, 1, 0"),
              ("ptr", "@callback_alias", "1, 1, 1"), ("i16", "%small0", "2, 0"),
              ("i16", "%small1", "2, 1"), ("i16", "%small2", "2, 2")]
    for stem, initial, xor, slot in (("u", "undef", 211, 256), ("p", "poison", 231, 320)):
        lines += [f"  %{stem}_base = freeze %Bundle {initial}",
                  f"  %{stem}_tag64 = xor i64 %seed, {xor}", f"  %{stem}_tag = trunc i64 %{stem}_tag64 to i8"]
        for index, (ty, operand, path) in enumerate(fields):
            previous = f"%{stem}_base" if index == 0 else f"%{stem}{index-1}"
            operand = f"%{stem}_tag" if operand == "%scratch_tag" else operand
            lines.append(f"  %{stem}{index} = insertvalue %Bundle {previous}, {ty} {operand}, {path}")
        lines += [f"  %{stem}_slot = getelementptr i8, ptr %output, i64 {slot}",
                  f"  store %Bundle %{stem}7, ptr %{stem}_slot, align {alignment}"]
    lines += ["  %zero = freeze %Bundle zeroinitializer", "  %slot384 = getelementptr i8, ptr %output, i64 384",
              f"  store %Bundle %zero, ptr %slot384, align {alignment}",
              "  %literal = freeze " + LITERAL, "  %slot448 = getelementptr i8, ptr %output, i64 448",
              f"  store %Bundle %literal, ptr %slot448, align {alignment}",
              "  %empty = freeze %Empty zeroinitializer", "  %empty_array = freeze [0 x i64] zeroinitializer",
              "  %end = getelementptr i8, ptr %output, i64 512", "  store %Empty %empty, ptr %end, align 1",
              f"  store [0 x i64] %empty_array, ptr %end, align {alignment}",
              "  %tag_value = extractvalue %Bundle %selected, 0", "  %tag_wide = zext i8 %tag_value to i64",
              "  %n0 = extractvalue %Bundle %selected, 1, 0, 0", "  %n0_wide = zext i32 %n0 to i64",
              "  %n1 = extractvalue %Bundle %selected, 1, 1, 0", "  %n1_wide = zext i32 %n1 to i64",
              "  %n1_shift = shl i64 %n1_wide, 32", "  %array = extractvalue %Bundle %selected, 2",
              "  %array_word = extractvalue [3 x i16] %array, 1", "  %word_wide = zext i16 %array_word to i64",
              "  %nested = extractvalue %Outer %outer, 2, 1", "  %other_n0 = extractvalue %Bundle %nested, 1, 0, 0",
              "  %other_n0_wide = zext i32 %other_n0 to i64", "  %outer_tail = extractvalue %Outer %outer, 3",
              "  %outer_tail_byte = extractvalue [2 x i8] %outer_tail, 1", "  %tail_wide = zext i8 %outer_tail_byte to i64",
              "  %tail_shift = shl i64 %tail_wide, 56", "  %data_pointer = extractvalue %Bundle %selected, 1, 0, 1",
              "  %data_value = load i64, ptr %data_pointer, align 8",
              "  %function_pointer = extractvalue %Bundle %selected, 1, 1, 1",
              "  %called = call i64 %function_pointer(i64 %seed)", "  %r0 = xor i64 %called, %data_value",
              "  %r1 = xor i64 %r0, %n0_wide", "  %r2 = xor i64 %r1, %n1_shift",
              "  %r3 = xor i64 %r2, %tag_wide", "  %r4 = xor i64 %r3, %word_wide",
              "  %r5 = xor i64 %r4, %other_n0_wide", "  %result = xor i64 %r5, %tail_shift",
              "  ret i64 %result", "}"]
    return "\n".join(lines) + "\n"


def llvm_source():
    return TYPES + f"""
@anchor = global i64 {ANCHOR}, align 8
@anchor_alias = alias i64, ptr @anchor
@cold_bundle = constant {LITERAL}, align 8
@cold_empty = constant %Empty zeroinitializer
@cold_empty_array = constant [0 x i64] zeroinitializer, align 8
define i64 @callback(i64 %seed) {{ %result = xor i64 %seed, {CALLBACK_BIAS}
 ret i64 %result }}
@callback_alias = alias i64(i64), ptr @callback
define i64 @unused_aggregate(i64 %seed) {{
 %value = freeze {LITERAL}
 %array = extractvalue %Bundle %value, 2
 %word = extractvalue [3 x i16] %array, 1
 %wide = zext i16 %word to i64
 %result = add i64 %seed, %wide
 ret i64 %result
}}
""" + llvm_function("aggregate_align1", 1) + llvm_function("aggregate_default", 8)


C_TYPES = """
typedef unsigned long long u64; typedef unsigned int u32;
typedef unsigned short u16; typedef unsigned char u8;
struct Empty {};
struct Leaf {u32 number; void *pointer;};
struct Bundle {u8 tag; struct Leaf leaves[2]; u16 words[3];};
struct __attribute__((packed)) Packed {u8 tag; struct Bundle bundle; u32 last;};
struct Outer {struct Empty empty; u64 nothing[0]; struct Packed packed; u8 tail[2];};
"""


def c_function(name, unaligned):
    load = "__builtin_memcpy(&base,input,sizeof base);" if unaligned else "base=*(const struct Bundle*)input;"
    text = f"u64 {name}(const void *input,void *output,u64 seed,u64 rounds,u64 mode){{\nstruct Bundle base;{load}\n"
    text += """
 struct Bundle a=base,b=base;
 a.tag=(u8)(seed^0x5a);a.words[1]=(u16)(seed^0x1357);
 b.leaves[0].number=b.leaves[1].number^0x89abcdefU;b.leaves[0].pointer=&anchor;
 b.words[2]=(u16)((seed>>32)^0x2468);
 for(u64 i=0;i<rounds;++i){struct Bundle temporary=a;a=b;b=temporary;}
 struct Bundle selected=(mode&1)?b:a,other=(mode&1)?a:b;
 struct Packed packed={0x6b,selected,(u32)((seed>>13)^0x10203040)};
 struct Outer outer={.empty={},.nothing={},.packed={0xc7,other,(u32)(seed^0xa55a5aa5)},.tail={0x34,(u8)(seed>>48)}};
 struct Bundle undef,poison;
 undef.tag=(u8)(seed^0xd3);undef.leaves[0].number=(u32)(seed>>17);undef.leaves[0].pointer=&anchor_alias;
 undef.leaves[1].number=(u32)(seed*5);undef.leaves[1].pointer=(void*)callback_alias;
 undef.words[0]=(u16)seed;undef.words[1]=(u16)(seed>>32);undef.words[2]=(u16)((seed>>16)^0xabcd);
 poison=undef;poison.tag=(u8)(seed^0xe7);
 struct Bundle zero={0},literal={5,{{11,&anchor_alias},{22,(void*)callback_alias}},{33,44,55}};
"""
    for at, ty, value in ((0, "Bundle", "selected"), (64, "Bundle", "other"), (128, "Packed", "packed"),
                          (192, "Outer", "outer"), (256, "Bundle", "undef"), (320, "Bundle", "poison"),
                          (384, "Bundle", "zero"), (448, "Bundle", "literal")):
        if unaligned or ty == "Packed":
            text += f"__builtin_memcpy((u8*)output+{at},&{value},sizeof {value});\n"
        else:
            text += f"*(struct {ty}*)((u8*)output+{at})={value};\n"
    text += """
 struct Empty empty={};u64 empty_array[0]={};
 __builtin_memcpy((u8*)output+512,&empty,sizeof empty);
 __builtin_memcpy((u8*)output+512,empty_array,sizeof empty_array);
 return ((u64(*)(u64))selected.leaves[1].pointer)(seed)^*(u64*)selected.leaves[0].pointer^
        selected.leaves[0].number^((u64)selected.leaves[1].number<<32)^selected.tag^selected.words[1]^
        outer.packed.bundle.leaves[0].number^((u64)outer.tail[1]<<56);
}
"""
    return text


def c_source():
    return C_TYPES + f"""
u64 anchor={ANCHOR}ULL;
extern u64 anchor_alias __attribute__((alias("anchor")));
u64 callback(u64 seed){{return seed^{CALLBACK_BIAS}ULL;}}
extern u64 callback_alias(u64) __attribute__((alias("callback")));
const struct Bundle cold_bundle={{5,{{{{11,&anchor_alias}},{{22,(void*)callback_alias}}}},{{33,44,55}}}};
const struct Empty cold_empty={{}};const u64 cold_empty_array[0]={{}};
u64 unused_aggregate(u64 seed){{return seed+cold_bundle.words[1];}}
""" + c_function("aggregate_align1", True) + c_function("aggregate_default", False)


def carrier():
    reusable = weak.carrier(11)
    text = reusable[:reusable.index("extern u64 chosen_global")]
    text += C_TYPES
    # The original Clang reference may lower ordinary aggregate copies to
    # libc-shaped calls. These explicit carrier providers are test platform
    # dependencies, not evidence of a complete imported runtime closure.
    # Volatile byte accesses keep the helpers from lowering back to themselves.
    text += r"""
__attribute__((noinline)) void *memcpy(void *destination,const void *source,u64 length){
 volatile u8 *out=(volatile u8*)destination;const volatile u8 *in=(const volatile u8*)source;
 for(u64 i=0;i<length;++i)out[i]=in[i];return destination;
}
__attribute__((noinline)) void *memset(void *destination,int value,u64 length){
 volatile u8 *out=(volatile u8*)destination;
 for(u64 i=0;i<length;++i)out[i]=(u8)value;return destination;
}
"""
    text += "extern u64 anchor,anchor_alias;\nextern u64 callback(u64),callback_alias(u64);\n"
    for name in ("aggregate_align1", "aggregate_default"):
        text += f"extern u64 {name}(const void*,void*,u64,u64,u64);\n"
    text += "extern const struct Bundle cold_bundle;\n"
    text += """
struct OutputLayout {
 struct Bundle selected;u8 gap0[16];struct Bundle other;u8 gap1[16];
 struct Packed packed;u8 gap2[11];struct Outer outer;u8 gap3[8];
 struct Bundle undef;u8 gap4[16];struct Bundle poison;u8 gap5[16];
 struct Bundle zero;u8 gap6[16];struct Bundle literal;u8 gap7[16];
};
"""
    rows, models = [], []
    for seed in SEEDS:
        for rounds in ROUNDS:
            for mode in (0, 1):
                values = transformed(seed, rounds, mode)
                model = image(values)
                try:
                    index = models.index(model)
                except ValueError:
                    index = len(models)
                    models.append(model)
                rows.append((seed, rounds, mode, scalar_result(seed, values), index))
    text += "static const u64 rows[][5]={" + ",\n".join("{"+",".join(f"{value}ULL" for value in row)+"}" for row in rows) + "};\n"
    text += "static const unsigned char expected[][512]={" + ",\n".join("{"+",".join(map(str, model[0]))+"}" for model in models) + "};\n"
    text += "static const unsigned char masks[512]={" + ",".join(map(str, models[0][1])) + "};\n"
    text += "static const unsigned short pointer_slots[][2]={" + ",".join("{"+str(at)+",0}" for at, _ in models[0][2]) + "};\n"
    text += "static const unsigned char pointer_targets[][16]={" + ",\n".join("{"+",".join(str(target) for _, target in model[2])+"}" for model in models) + "};\n"
    input_images = []
    for seed in SEEDS:
        value = input_bundle(seed)
        output = [0xa5] * 48
        output[0] = value["tag"]
        for index in range(2):
            output[8+16*index:12+16*index] = list(value["numbers"][index].to_bytes(4, "little"))
        for index, word in enumerate(value["words"]):
            output[40+2*index:42+2*index] = list(word.to_bytes(2, "little"))
        input_images.append(output)
    text += "static const unsigned char inputs[][48]={" + ",\n".join("{"+",".join(map(str, row))+"}" for row in input_images) + "};\n"
    text += r"""
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected){
#ifdef CORRUPT_ORACLE
 expected^=1;
#endif
 if(got!=expected)return 31;
 digest=(digest^got)*0x100000001b3ULL;++checks;return 0;
}
static u64 get64(const unsigned char *p){u64 x=0;for(u64 i=0;i<8;++i)x|=(u64)p[i]<<(8*i);return x;}
static void put64(unsigned char *p,u64 x){for(u64 i=0;i<8;++i)p[i]=(unsigned char)(x>>(8*i));}
static u64 pointer_target(unsigned int kind){return kind==1?(u64)&anchor_alias:kind==2?(u64)callback_alias:0;}
int conformance_main(void){
 u64 volatile addresses[]={(u64)&anchor,(u64)&anchor_alias,(u64)callback,(u64)callback_alias};
 const unsigned char *cold=(const unsigned char*)&cold_bundle;
"""
    text += f"if(add(anchor,{ANCHOR}ULL)||add(addresses[0]==addresses[1],1)||add(addresses[2]==addresses[3],1))return 31;\n"
    for value, expression in ((5, "cold[0]"), (11, "get64(cold+8)&0xffffffffULL"),
                              (22, "get64(cold+24)&0xffffffffULL"), (33, "cold[40]|((u64)cold[41]<<8)"),
                              (44, "cold[42]|((u64)cold[43]<<8)"), (55, "cold[44]|((u64)cold[45]<<8)")):
        text += f"if(add({expression},{value}))return 31;\n"
    text += "if(add(get64(cold+16)==(u64)&anchor_alias,1)||add(get64(cold+32)==(u64)callback_alias,1))return 31;\n"
    text += f"""
 for(u64 row=0;row<sizeof(rows)/sizeof(rows[0]);++row)for(u64 unaligned=0;unaligned<2;++unaligned){{
  union {{struct {{u8 prefix[32];struct Bundle value;u8 suffix[48];}} typed;u8 bytes[128];}} input_storage __attribute__((aligned(16)));
  union {{struct {{u8 prefix[32];struct OutputLayout value;u8 suffix[32];}} typed;u8 bytes[576];}} output_storage __attribute__((aligned(16)));
  unsigned char *input=input_storage.bytes,*output=output_storage.bytes;
  u64 start=unaligned?33:32,model=rows[row][4],seed_index=row/{len(ROUNDS)*2};
  for(u64 i=0;i<128;++i)input[i]=0xa5;for(u64 i=0;i<576;++i)output[i]=0xa5;
  for(u64 i=0;i<48;++i)input[start+i]=inputs[seed_index][i];
  put64(input+start+16,(u64)&anchor_alias);put64(input+start+32,(u64)callback_alias);
  u64 actual=unaligned?aggregate_align1(input+start,output+start,rows[row][0],rows[row][1],rows[row][2]):aggregate_default(input+start,output+start,rows[row][0],rows[row][1],rows[row][2]);
  if(add(actual,rows[row][3]))return 31;
  for(u64 i=0;i<576;++i){{
   if(i>=start&&i<start+512){{if(masks[i-start]!=1)continue;if(add(output[i],expected[model][i-start]))return 31;}}
   else if(add(output[i],0xa5))return 31;
  }}
  for(u64 i=0;i<16;++i)if(add(get64(output+start+pointer_slots[i][0])==pointer_target(pointer_targets[model][i]),1))return 31;
  for(u64 i=0;i<128;++i){{
   if((i>=start+16&&i<start+24)||(i>=start+32&&i<start+40))continue;
   u64 wanted=i>=start&&i<start+48?inputs[seed_index][i-start]:0xa5;
   if(add(input[i],wanted))return 31;
  }}
  if(add(get64(input+start+16)==(u64)&anchor_alias,1)||add(get64(input+start+32)==(u64)callback_alias,1))return 31;
 }}
"""
    expected = golden().decode().rstrip()
    prefix = expected.index("digest=") + len("digest=")
    text += f"if(checks!={expected.split('checks=')[1]})return 37;\n"
    text += 'static char output[]="' + expected[:prefix] + "0"*16 + expected[prefix+16:] + '\\n";\n'
    text += f"for(u64 i=0;i<16;++i){{u64 n=(digest>>(60-4*i))&15;output[{prefix}+i]=(char)(n<10?'0'+n:'a'+n-10);}}\n"
    text += r"""
#if defined(__x86_64__)
 if(syscall3(1,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#else
 if(syscall3(64,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#endif
 return 0;
}
#if defined(__x86_64__)
__asm__""" + reusable.split('#if defined(__x86_64__)\n__asm__', 1)[1]
    return text


class AggregateNativeTests(unittest.TestCase):
    setUpClass = classmethod(weak.WeakNativeTests.setUpClass.__func__)
    command = weak.WeakNativeTests.command
    emulators = census.AllocsizeNativeTests.emulators
    original_inventory = census.AllocsizeNativeTests.original_inventory

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_AGGREGATES_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-aggregates-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)
        self.sequence = 0
        self.compiler_sha = weak.artifact(self.compiler)["sha256"]
        self.library = importer.LLVM(importer.discover_library(), importer.PINNED_SHA256)

    def sources(self, isa, triple, flags, frontend):
        if frontend == "llvm":
            source = self.directory / (isa + "-aggregate.ll")
            source.write_text(weak.promises.module_text(triple, llvm_source()))
            binary = source.with_suffix(".bc")
            self.command([self.sdk / "llvm-as", source, "-o", binary])
        else:
            original = self.directory / (isa + "-aggregate.c"); original.write_text(c_source())
            source, binary = original.with_suffix(".c.ll"), original.with_suffix(".c.bc")
            for output, mode in ((source, "-S"), (binary, "-c")):
                self.command([self.sdk / "clang", "--target="+triple, *flags, "-std=gnu11", "-O0",
                              "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-pie", "-fno-stack-protector",
                              "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-emit-llvm", mode, original, "-o", output])
        return source, binary

    def layouts(self, source, frontend):
        a = self.library; data = source.read_bytes(); context = a.ContextCreate()
        buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"aggregate-layout")
        module, error = importer.P(), importer.P()
        self.assertEqual(a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error)), 0)
        target_data = a.CreateTargetData(a.GetDataLayoutStr(module))
        get_type = a.lib.LLVMGetTypeByName2; get_type.restype, get_type.argtypes = importer.P, [importer.P, C.c_char_p]
        rows = {}
        try:
            for name, expected in LAYOUTS.items():
                # Clang omits the empty C member from its LLVM storage type;
                # the zero-length array still contributes alignment eight.
                if frontend == "c" and name == "Outer":
                    expected = (56, 8, [0, 0, 53])
                ty = get_type(context, (("struct." if frontend == "c" else "")+name).encode())
                self.assertTrue(ty, "missing original named type: "+name)
                actual = (a.ABISizeOfType(target_data, ty), a.ABIAlignmentOfType(target_data, ty),
                          [a.OffsetOfElement(target_data, ty, index) for index in range(a.CountStructElementTypes(ty))])
                self.assertEqual(actual, expected, name)
                rows[name] = {"size": actual[0], "alignment": actual[1], "offsets": actual[2]}
        finally:
            a.DisposeTargetData(target_data); a.DisposeModule(module); a.ContextDispose(context)
        return rows

    def object(self, source, triple, flags, target, own):
        output = source.with_name(source.name + (".own.o" if own else ".clang.o"))
        if own:
            self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "-o", output])
        else:
            self.command([self.sdk / "clang", "--target="+triple, *flags, "-O0", "-fno-pic", "-fno-pie", "-c", source, "-o", output])
        return output

    def verify(self, source, target, original):
        native = source.with_name(source.name + ".native.json"); receipt = source.with_name(source.name + ".verified.json")
        self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "--emit", "mir", "-o", native])
        self.command([self.compiler, native, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
        module = json.loads(native.read_text()); provenance = module["provenance"]
        self.assertEqual(provenance["input_sha256"], weak.artifact(source)["sha256"])
        for field, count in (("functions", "source_function_count"), ("globals", "source_global_count"), ("aliases", "source_alias_count")):
            self.assertEqual({entry["name"] for entry in module[field]}, set(original[field]))
            self.assertEqual(provenance[count], len(original[field]))
        self.assertEqual({entry["name"] for entry in module["functions"] if entry["entry"] is not None}, set(original["definitions"]))
        self.assertEqual(json.loads(receipt.read_text())["module_sha256"], weak.artifact(native)["sha256"])
        return {"module": weak.artifact(native), "verification": weak.artifact(receipt)}

    def differential(self, own):
        emulators = self.emulators()
        report = {"scope": "aggregate SSA/memory generic compiler conformance with scalar-only C ABI",
                  "runtime_complete": False, "exception_handling_verified": False, "aggregate_abi_verified": False,
                  "kernel_execution_verified": False, "dependency_closure_complete": False,
                  "compiler_implementation_lowered": False, "ocore_objects_tested": own,
                  "compiler_sha256": self.compiler_sha, "test_source": weak.artifact(__file__),
                  "expected_stdout": golden().decode(), "padding_policy": "aggregate-store padding unobserved; input padding and all external canaries exact",
                  "carrier_platform_providers": ["memcpy byte loop", "memset byte loop", "freestanding Linux syscall startup/output"],
                  "tools": {name: weak.artifact(path) for name, path in {"ocorec": self.compiler,
                      "reference_clang": self.sdk/"clang", "llvm-as": self.sdk/"llvm-as", "linker": self.linker,
                      "own_assembler": self.assembler, "llvm_library": importer.discover_library(), **emulators}.items()}, "targets": {}}
        for isa, (target, triple, machine, flags) in TARGETS.items():
            harness = self.directory / (isa + "-carrier.c"); harness.write_text(carrier())
            carrier_objects = {}
            for corrupt in (False, True):
                obj = harness.with_suffix(".corrupt.o" if corrupt else ".o")
                argv = [self.sdk/"clang", "--target="+triple, *flags, "-O1", "-ffreestanding", "-fno-builtin",
                        "-fno-stack-protector", "-fno-pic", "-fno-pie", "-c", harness, "-o", obj]
                if corrupt: argv.append("-DCORRUPT_ORACLE")
                self.command(argv); carrier_objects[corrupt] = obj
            records = []
            for frontend in ("llvm", "c"):
                for source in self.sources(isa, triple, flags, frontend):
                    original_bytes = source.read_bytes(); inventory = self.original_inventory(source)
                    record = {"frontend": frontend, "input": weak.artifact(source), "original_inventory": inventory,
                              "layout": self.layouts(source, frontend), "executions": []}
                    self.assertIn("unused_aggregate", inventory["definitions"])
                    self.assertTrue({"cold_bundle", "cold_empty", "cold_empty_array"}.issubset(inventory["globals"]))
                    if frontend == "c": record["c_source"] = weak.artifact(self.directory/(isa+"-aggregate.c"))
                    providers = ("original_clang", "own") if own else ("original_clang",)
                    if own: record.update(self.verify(source, target, inventory))
                    for provider in providers:
                        object_ = self.object(source, triple, flags, target, provider == "own"); elf(object_, machine, 1)
                        for name in inventory["definitions"]: self.assertGreater(weak.elf_symbols(object_)[name]["size"], 0)
                        record[provider+"_object"] = weak.artifact(object_)
                        for control in ("positive", "oracle", "object"):
                            selected = object_; mutation = None
                            if control == "object":
                                selected = object_.with_name(object_.name+".corrupt")
                                data = bytearray(object_.read_bytes()); symbol = weak.elf_symbols(object_)["cold_bundle"]
                                table = struct.unpack_from("<Q", data, 40)[0]
                                section = struct.unpack_from("<IIQQQQIIQQ", data, table+64*symbol["section"])
                                at = section[4]+symbol["value"]; self.assertEqual(data[at], 5); data[at] ^= 1
                                selected.write_bytes(data); mutation = {"symbol": "cold_bundle", "file_offset": at, "object": weak.artifact(selected)}
                            executable = source.with_name(source.name+"-"+provider+"-"+control)
                            self.command([self.sdk/"clang", "--target="+triple, *flags, "--ld-path="+self.linker,
                                          "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-e,_start",
                                          carrier_objects[control == "oracle"], selected, "-o", executable])
                            elf(executable, machine, 2)
                            result = self.command([executable] if isa == "x86_64" else [emulators[isa], executable], success=control == "positive")
                            self.assertEqual(result.stdout, golden() if control == "positive" else b"")
                            self.assertEqual(result.returncode, 0 if control == "positive" else 31)
                            record["executions"].append({"provider": provider, "control": control,
                                "executable": weak.artifact(executable), "stdout": result.stdout.decode(), "exit_code": result.returncode, "mutation": mutation})
                    self.assertEqual(source.read_bytes(), original_bytes); records.append(record)
            report["targets"][isa] = {"profile": {"triple": triple, "flags": flags}, "modules": records,
                                       "carrier_source": weak.artifact(harness), "carrier_object": weak.artifact(carrier_objects[False])}
        self.assertEqual(weak.artifact(self.compiler)["sha256"], self.compiler_sha)
        name = "aggregates-own-conformance.json" if own else "aggregates-original-clang-oracle.json"
        (self.directory/name).write_text(json.dumps(report, indent=2)+"\n")
        print(("Own/reference" if own else "Original Clang")+" aggregates all three: "+golden().decode().strip(), flush=True)

    def test_original_clang_oracle_nested_packed_phi_undef_poison_ll_bc_all_three(self):
        self.differential(own=False)

    def test_own_aggregate_objects_match_original_clang_defined_fields_all_three(self):
        if os.environ.get("OCORE_TEST_AGGREGATES_REFERENCE_ONLY") == "1":
            self.skipTest("reference-first qualification before aggregate compiler freeze")
        self.differential(own=True)


if __name__ == "__main__":
    unittest.main()
