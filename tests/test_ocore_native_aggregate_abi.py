"""Aggregate ABI boundaries against unchanged LLVM and genuine C/C++ inputs.

Original Clang caller/callee objects qualify the independent field oracle first.
All four compiler pairings then test the same whole units. Linux startup, byte
copy helpers, and QEMU are declared test providers, not a runtime dependency
closure or proof that any external language engine was compiled completely.
"""

import ctypes as C
import copy
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_native_equivalence import TARGETS, elf
from tests import test_ocore_native_allocsize as census
from tests import test_ocore_native_weak as weak


ROOT, MASK = weak.ROOT, weak.MASK
BIAS, FIELD_BIAS = 0x9e3779b97f4a7c15, 0x1020304050607081
MARKER, COLD = 0x123456789abcdef0, 0x1122334455667788
TRAILING, HASH_ARGUMENTS, STORAGE = 13, 19, 96
SEEDS = tuple(weak.inputs())


def structure(*fields, packed=False):
    return ("struct", fields, packed)


def array(count, element):
    return ("array", count, element)


NODES = {
    "Empty": structure(), "Zero64": array(0, 64),
    "Narrow": structure(1, 9, 16), "Pair": structure(64, "ptr"),
    "Packed": structure(8, 32, "ptr", packed=True),
    "Array16": array(3, 16), "Array64": array(3, 64),
    "Nested": structure(8, structure(32, "ptr"), array(2, 16)),
    "Triple": structure(64, 64, 64), "Big": structure(array(3, 64), "ptr"),
    "Nine": structure(array(9, 64)),
    "Tiny": structure(8, 16), "SmallArray": structure(array(3, 16)),
}
RAW_CASES = [(name.lower(), name, 0, False) for name in NODES if name not in {"Tiny", "SmallArray"}]
RAW_CASES += [("array64_late", "Array64", 6, False), ("big_sret", "Big", 0, True)]
C_CASES = [("tiny", "Tiny", 0, False), ("pair", "Pair", 0, False),
           ("array", "SmallArray", 0, False), ("big", "Big", 0, False)]


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def layout(node, path=(), start=0):
    """Independent LP64 integer layout, checked against original TargetData."""
    if node == "ptr" or isinstance(node, int):
        size = 8 if node == "ptr" else (node + 7) // 8
        alignment = 1 << (size - 1).bit_length()
        return size, alignment, [(path, node, start)]
    if node[0] == "array":
        _, count, element = node
        size, alignment, _ = layout(element)
        stride = align(size, alignment)
        leaves = []
        for index in range(count):
            leaves += layout(element, (*path, index), start + index * stride)[2]
        return count * stride, alignment, leaves
    _, fields, packed = node
    extent, alignment, leaves = 0, 1, []
    for index, field in enumerate(fields):
        size, field_alignment, _ = layout(field)
        field_alignment = 1 if packed else field_alignment
        extent = align(extent, field_alignment)
        leaves += layout(field, (*path, index), start + extent)[2]
        extent += size
        alignment = max(alignment, field_alignment)
    return align(extent, alignment), alignment, leaves


def llvm_type(node):
    if node == "ptr": return "ptr"
    if isinstance(node, int): return "i" + str(node)
    if node[0] == "array": return f"[{node[1]} x {llvm_type(node[2])}]"
    fields = ", ".join(llvm_type(field) for field in node[1])
    return "<{" + fields + "}>" if node[2] else "{" + fields + "}"


RAW_TYPES = "\n".join(f"%{name} = type {llvm_type(NODES[name])}" for name in NODES if name not in {"Tiny", "SmallArray"}) + "\n"


def arguments(seed, prefix=0):
    values = [(seed + BIAS * (index + 1)) & MASK for index in range(prefix + TRAILING)]
    return values + [0] * (HASH_ARGUMENTS - len(values))


def hash_values(values):
    digest = 0xcbf29ce484222325
    for value in values: digest = ((digest ^ value) * 0x100000001b3) & MASK
    return digest


def input_values(name, seed):
    values = []
    for index, (_, bits, _) in enumerate(layout(NODES[name])[2]):
        values.append(None if bits == "ptr" else ((seed >> ((index * 7) % 64)) ^
                      ((FIELD_BIAS + index * 0x1357) & MASK)) & ((1 << bits) - 1))
    return values


def result_values(name, seed, prefix=0):
    nested = hash_values(arguments(seed, prefix))
    values = []
    for index, ((_, bits, _), value) in enumerate(zip(layout(NODES[name])[2], input_values(name, seed))):
        values.append(None if bits == "ptr" else
                      (value ^ (nested >> ((index * 9) % 64)) ^ (0xa55a1234 + 17 * index)) & ((1 << bits) - 1))
    return values


def expected(name, seed, prefix=0):
    size, _, leaves = layout(NODES[name]); assert size <= STORAGE
    values = result_values(name, seed, prefix)
    bytes_, masks = [0xa5] * STORAGE, [255] * STORAGE
    for index in range(size): masks[index] = 0  # Aggregate padding is unobserved.
    pointers, result = [], seed
    for (_, bits, offset), value in zip(leaves, values):
        if bits == "ptr":
            pointers.append(offset)
            continue
        result ^= value
        for byte in range((bits + 7) // 8):
            masks[offset + byte] = min(255, (1 << max(0, bits - 8 * byte)) - 1)
            bytes_[offset + byte] = (value >> (8 * byte)) & masks[offset + byte]
    observed = [result, *[bytes_[at] & masks[at] for at in range(STORAGE) if masks[at]],
                *([1] * len(pointers)), *([0xa5] * 32)]
    return bytes_, masks, pointers, result, observed


def paths(frontend):
    if frontend == "llvm":
        return [(f"run_{cc}_{case}_{path}", ty, prefix)
                for cc in ("c", "fast") for case, ty, prefix, _ in RAW_CASES
                for path in ("direct", "alias", "indirect")]
    return [(f"run_{case}_{path}", ty, prefix) for case, ty, prefix, _ in C_CASES
            for path in ("direct", "alias", "indirect")]


def golden(frontend):
    values = [MARKER, COLD, 1]
    for seed in SEEDS:
        for _, ty, prefix in paths(frontend): values += expected(ty, seed, prefix)[4]
    if frontend == "llvm": values += [167, len(SEEDS) * 3 * (len(RAW_CASES) + 1)]
    return f"OCORE-AGGREGATE-ABI digest={hash_values(values):016x} checks={len(values)}\n".encode()


def cc_text(cc): return "fastcc " if cc == "fast" else ""


def scalar_params(prefix):
    return [(f"p{index}", "i64") for index in range(prefix)] + [(f"a{index}", "i64") for index in range(TRAILING)]


def engine_parameters(ty, prefix, storage, declaration=False):
    params = [(name, type_) for name, type_ in scalar_params(prefix)[:prefix]]
    if storage: params += [("receiver", "ptr"), ("out", f"ptr sret(%{ty}) align {layout(NODES[ty])[1]}")]
    params += [("aggregate", "%" + ty)] + scalar_params(prefix)[prefix:]
    return ", ".join(type_ if declaration else type_ + " %" + name for name, type_ in params)


def alias_type(ty, prefix, storage):
    params = engine_parameters(ty, prefix, storage, True)
    if storage: params = params.replace(f"ptr sret(%{ty}) align {layout(NODES[ty])[1]}", "ptr")
    return ("void" if storage else "%" + ty) + " (" + params + ")"


def llvm_hash(cc):
    lines = [f"define internal {cc_text(cc)}i64 @nested_clobber_{cc}(" +
             ", ".join(f"i64 %h{i}" for i in range(HASH_ARGUMENTS)) + ") {"]
    previous = "14695981039346656037"
    for index in range(HASH_ARGUMENTS):
        lines += [f"  %x{index} = xor i64 {previous}, %h{index}",
                  f"  %m{index} = mul i64 %x{index}, 1099511628211"]
        previous = "%m" + str(index)
    return "\n".join(lines + [f"  ret i64 {previous}", "}"]) + "\n"


def llvm_engine(cc, case, ty, prefix, storage):
    name = f"engine_{cc}_{case}"
    result = "void" if storage else "%" + ty
    lines = [f"define {cc_text(cc)}{result} @{name}({engine_parameters(ty, prefix, storage)}) {{"]
    if cc == "fast":
        # Force real page probing before any parameter use. Incoming fastcc
        # t3-t6 must survive frame construction, not just the nested call.
        lines += ["  %probe_storage = alloca [8192 x i8], align 16",
                  "  %probe_last = getelementptr [8192 x i8], ptr %probe_storage, i64 0, i64 8191",
                  "  store volatile i8 167, ptr %probe_last, align 1",
                  "  %probe_value = load volatile i8, ptr %probe_last, align 1",
                  "  store volatile i8 %probe_value, ptr @probe_marker, align 1",
                  "  %probe_old = load volatile i64, ptr @probe_count, align 8",
                  "  %probe_next = add i64 %probe_old, 1",
                  "  store volatile i64 %probe_next, ptr @probe_count, align 8"]
    if storage:
        # Both the implicit larger-result call and explicit typed sret are real
        # original LLVM calls; no handwritten physical-ABI adapter is used.
        args = [f"%{ty} %aggregate", *[f"i64 %a{i}" for i in range(TRAILING)]]
        lines += [f"  %nested = call {cc_text(cc)}%{ty} @engine_{cc}_big(" + ", ".join(args) + ")",
                  f"  store %{ty} %nested, ptr %out, align {layout(NODES[ty])[1]}", "  ret void", "}"]
    else:
        args = ["i64 %" + name for name, _ in scalar_params(prefix)]
        args += ["i64 0"] * (HASH_ARGUMENTS - len(args))
        lines += [f"  %hash = call {cc_text(cc)}i64 @nested_clobber_{cc}(" + ", ".join(args) + ")"]
        value = "zeroinitializer"
        for index, (indices, bits, _) in enumerate(layout(NODES[ty])[2]):
            indices_text = ", ".join(map(str, indices)); leaf = "ptr" if bits == "ptr" else "i" + str(bits)
            lines += [f"  %field{index} = extractvalue %{ty} %aggregate, {indices_text}"]
            if bits == "ptr": inserted = "%field" + str(index)
            else:
                lines += [f"  %shift{index} = lshr i64 %hash, {(index * 9) % 64}"]
                amount = "%shift" + str(index)
                if bits != 64:
                    lines.append(f"  %narrow{index} = trunc i64 {amount} to {leaf}"); amount = "%narrow" + str(index)
                lines += [f"  %mix{index} = xor {leaf} %field{index}, {amount}",
                          f"  %value{index} = xor {leaf} %mix{index}, {(0xa55a1234 + index * 17) & ((1 << bits) - 1)}"]
                inserted = "%value" + str(index)
            lines.append(f"  %insert{index} = insertvalue %{ty} {value}, {leaf} {inserted}, {indices_text}")
            value = "%insert" + str(index)
        lines += [f"  ret %{ty} {value}", "}"]
    lines += [f"@{name}_alias = alias {alias_type(ty, prefix, storage)}, ptr @{name}",
              f"@{name}_pointer = constant ptr @{name}_alias, align 8"]
    return "\n".join(lines) + "\n"


def llvm_callee():
    text = RAW_TYPES + f"@anchor = global i64 {MARKER}, align 8\n@anchor_alias = alias i64, ptr @anchor\n"
    text += "@probe_marker = global i8 0, align 1\n@probe_count = global i64 0, align 8\n"
    text += f"@cold_marker = constant i64 {COLD}, align 8\n@cold_pointer = constant ptr @unused_native_pair, align 8\n"
    text += "define %Pair @unused_native_pair(i64 %seed) {\n %a=insertvalue %Pair zeroinitializer, i64 %seed, 0\n %b=insertvalue %Pair %a, ptr @anchor_alias, 1\n ret %Pair %b\n}\n"
    for cc in ("c", "fast"):
        text += llvm_hash(cc)
        for case in RAW_CASES: text += llvm_engine(cc, *case)
    return text


def llvm_wrapper(cc, case, ty, prefix, storage, path):
    engine = f"engine_{cc}_{case}"; name = f"run_{cc}_{case}_{path}"
    lines = [f"define i64 @{name}(ptr %out, i64 %seed) {{"]
    value = "zeroinitializer"
    for index, (indices, bits, _) in enumerate(layout(NODES[ty])[2]):
        leaf = "ptr" if bits == "ptr" else "i" + str(bits)
        if bits == "ptr": inserted = "@anchor_alias"
        else:
            lines += [f"  %shift{index} = lshr i64 %seed, {(index * 7) % 64}",
                      f"  %bits{index} = xor i64 %shift{index}, {(FIELD_BIAS + index * 0x1357) & MASK}"]
            inserted = "%bits" + str(index)
            if bits != 64:
                lines.append(f"  %input{index} = trunc i64 {inserted} to {leaf}"); inserted = "%input" + str(index)
        lines.append(f"  %in{index} = insertvalue %{ty} {value}, {leaf} {inserted}, " + ", ".join(map(str, indices)))
        value = "%in" + str(index)
    names = scalar_params(prefix)
    for index, (name_, _) in enumerate(names): lines.append(f"  %{name_} = add i64 %seed, {(BIAS * (index + 1)) & MASK}")
    args = [f"i64 %p{i}" for i in range(prefix)]
    if storage: args += ["ptr @anchor_alias", f"ptr sret(%{ty}) align {layout(NODES[ty])[1]} %out"]
    args += [f"%{ty} {value}", *[f"i64 %a{i}" for i in range(TRAILING)]]
    callee = "@" + engine + ("_alias" if path == "alias" else "")
    if path == "indirect":
        lines.append(f"  %callee = load ptr, ptr @{engine}_pointer, align 8"); callee = "%callee"
    if storage:
        lines += [f"  call {cc_text(cc)}void {callee}(" + ", ".join(args) + ")",
                  f"  %result = load %{ty}, ptr %out, align {layout(NODES[ty])[1]}"]
    else:
        lines += [f"  %result = call {cc_text(cc)}%{ty} {callee}(" + ", ".join(args) + ")",
                  f"  store %{ty} %result, ptr %out, align {layout(NODES[ty])[1]}"]
    fold = "%seed"
    for index, (indices, bits, _) in enumerate(layout(NODES[ty])[2]):
        if bits == "ptr": continue
        lines.append(f"  %r{index} = extractvalue %{ty} %result, " + ", ".join(map(str, indices)))
        extracted = "%r" + str(index)
        if bits != 64:
            lines.append(f"  %wide{index} = zext i{bits} {extracted} to i64"); extracted = "%wide" + str(index)
        lines.append(f"  %fold{index} = xor i64 {fold}, {extracted}"); fold = "%fold" + str(index)
    return "\n".join(lines + [f"  ret i64 {fold}", "}"]) + "\n"


def llvm_caller():
    text = RAW_TYPES + "@anchor_alias = external global i64\n"
    for cc in ("c", "fast"):
        for case, ty, prefix, storage in RAW_CASES:
            name = f"engine_{cc}_{case}"; result = "void" if storage else "%" + ty
            for suffix in ("", "_alias"):
                text += f"declare {cc_text(cc)}{result} @{name}{suffix}({engine_parameters(ty, prefix, storage, True)})\n"
            text += f"@{name}_pointer = external constant ptr\n"
            for path in ("direct", "alias", "indirect"):
                text += llvm_wrapper(cc, case, ty, prefix, storage, path)
    return text


C_TYPES = """
typedef unsigned long long u64;typedef unsigned int u32;typedef unsigned short u16;typedef unsigned char u8;
struct Tiny {u8 a;u16 b;};struct Pair {u64 a;void *p;};
struct SmallArray {u16 a[3];};struct Big {u64 a[3];void *p;};
"""
C_FIELDS = {"Tiny": ["a", "b"], "Pair": ["a", "p"],
            "SmallArray": ["a[0]", "a[1]", "a[2]"],
            "Big": ["a[0]", "a[1]", "a[2]", "p"]}


def c_parameters(ty, declaration=False):
    first = "u64 seed" if ty == "Big" else f"struct {ty} aggregate"
    return ", ".join([first, *[f"u64 a{i}" for i in range(TRAILING)]])


def c_input(ty, variable="aggregate"):
    text = f"struct {ty} {variable};\n"
    for index, ((_, bits, _), field) in enumerate(zip(layout(NODES[ty])[2], C_FIELDS[ty])):
        expression = "&anchor_alias" if bits == "ptr" else f"(seed>>{(index * 7) % 64})^{(FIELD_BIAS + index * 0x1357) & MASK}ULL"
        text += f"{variable}.{field}={expression};\n"
    return text


def c_source(role, cpp=False):
    text = C_TYPES + ('extern "C" {\n' if cpp else "")
    if role == "callee":
        const_linkage = "extern " if cpp else ""
        text += f"u64 anchor={MARKER}ULL;extern u64 anchor_alias __attribute__((alias(\"anchor\")));\n{const_linkage}const u64 cold_marker={COLD}ULL;\n"
        text += "__attribute__((noinline)) static u64 nested_clobber(" + ",".join(f"u64 h{i}" for i in range(HASH_ARGUMENTS)) + "){\n"
        text += "u64 words[19]={" + ",".join(f"h{i}" for i in range(HASH_ARGUMENTS)) + "},result=0xcbf29ce484222325ULL;\n"
        text += "for(u64 i=0;i<19;++i)result=(result^words[i])*0x100000001b3ULL;return result;}\n"
        text += "struct Pair unused_native_pair(u64 seed){struct Pair result={seed,&anchor_alias};return result;}\n" + const_linkage + "void *const cold_pointer=(void*)unused_native_pair;\n"
        for case, ty, _, _ in C_CASES:
            text += f"struct {ty} engine_{case}({c_parameters(ty)}){{\n"
            if ty == "Big": text += c_input(ty)
            text += "u64 hash=nested_clobber(" + ",".join([*[f"a{i}" for i in range(TRAILING)], *(["0"] * 6)]) + ");\n"
            for index, ((_, bits, _), field) in enumerate(zip(layout(NODES[ty])[2], C_FIELDS[ty])):
                if bits != "ptr": text += f"aggregate.{field}^=(hash>>{(index * 9) % 64})^{0xa55a1234 + index * 17}ULL;\n"
            text += "return aggregate;}\n"
            text += f"extern struct {ty} engine_{case}_alias({c_parameters(ty)}) __attribute__((alias(\"engine_{case}\")));\n"
            text += f"{const_linkage}struct {ty}(*const engine_{case}_pointer)({c_parameters(ty)})=engine_{case}_alias;\n"
    else:
        text += "extern u64 anchor_alias;\n"
        for case, ty, _, _ in C_CASES:
            for suffix in ("", "_alias"): text += f"extern struct {ty} engine_{case}{suffix}({c_parameters(ty)});\n"
            text += f"extern struct {ty}(*const engine_{case}_pointer)({c_parameters(ty)});\n"
            for path in ("direct", "alias", "indirect"):
                text += f"u64 run_{case}_{path}(void *out,u64 seed){{\n"
                if ty != "Big": text += c_input(ty)
                callee = "engine_" + case + ("_alias" if path == "alias" else "_pointer" if path == "indirect" else "")
                args = ["seed" if ty == "Big" else "aggregate", *[f"seed+{(BIAS * (i + 1)) & MASK}ULL" for i in range(TRAILING)]]
                text += f"struct {ty} result={callee}(" + ",".join(args) + ");\n__builtin_memcpy(out,&result,sizeof result);\nu64 folded=seed;\n"
                for field, (_, bits, _) in zip(C_FIELDS[ty], layout(NODES[ty])[2]):
                    if bits != "ptr": text += f"folded^=result.{field};\n"
                text += "return folded;}\n"
    return text + ("}\n" if cpp else "")


def carrier(frontend):
    reusable = weak.carrier(11); text = reusable[:reusable.index("extern u64 chosen_global")]
    # Test providers for original frontend copies; not imported runtime proof.
    text += """
__attribute__((noinline)) void *memcpy(void *out,const void *in,u64 n){volatile unsigned char*d=out;const volatile unsigned char*s=in;for(u64 i=0;i<n;++i)d[i]=s[i];return out;}
__attribute__((noinline)) void *memset(void *out,int v,u64 n){volatile unsigned char*d=out;for(u64 i=0;i<n;++i)d[i]=(unsigned char)v;return out;}
extern u64 anchor,anchor_alias,cold_marker;
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 wanted){
#ifdef CORRUPT_ORACLE
 wanted^=1;
#endif
 if(got!=wanted)return 31;digest=(digest^got)*0x100000001b3ULL;++checks;return 0;}
static u64 get64(const unsigned char*p){u64 value=0;for(u64 i=0;i<8;++i)value|=(u64)p[i]<<(i*8);return value;}
"""
    declarations, runners, models = [], [], []
    path_list = paths(frontend)
    for name, _, _ in path_list:
        declarations.append(f"extern u64 {name}(void*,u64);"); runners.append(name)
    text += "\n".join(declarations) + "\nstatic u64(*const runners[])(void*,u64)={" + ",".join(runners) + "};\n"
    text += "static const u64 seeds[]={" + ",".join(str(seed) + "ULL" for seed in SEEDS) + "};\n"
    text += "static const u64 scalar_expected[][" + str(len(path_list)) + "]={" + ",\n".join(
        "{" + ",".join(str(expected(ty, seed, prefix)[3]) + "ULL" for _, ty, prefix in path_list) + "}" for seed in SEEDS) + "};\n"
    for seed in SEEDS:
        for _, ty, prefix in path_list: models.append(expected(ty, seed, prefix))
    text += "static const unsigned char bytes_expected[][96]={" + ",\n".join("{" + ",".join(map(str, model[0])) + "}" for model in models) + "};\n"
    text += "static const unsigned char masks[][96]={" + ",\n".join("{" + ",".join(map(str, expected(ty, 0, prefix)[1])) + "}" for _, ty, prefix in path_list) + "};\n"
    text += "static const unsigned char pointer_counts[]={" + ",".join(str(len(expected(ty, 0, prefix)[2])) for _, ty, prefix in path_list) + "};\n"
    text += "static const unsigned char pointer_offsets[][1]={" + ",".join("{" + str((expected(ty, 0, prefix)[2] or [0])[0]) + "}" for _, ty, prefix in path_list) + "};\n"
    text += f"int conformance_main(void){{if(add(anchor,{MARKER}ULL)||add(cold_marker,{COLD}ULL))return 31;\n"
    text += "u64 volatile addresses[2]={(u64)&anchor,(u64)&anchor_alias};if(add(addresses[0]==addresses[1],1))return 31;\n"
    text += f"for(u64 seed=0;seed<{len(SEEDS)};++seed)for(u64 path=0;path<{len(path_list)};++path){{\n"
    text += "unsigned char storage[128] __attribute__((aligned(16)));for(u64 i=0;i<128;++i)storage[i]=0xa5;\n"
    text += "if(add(runners[path](storage+16,seeds[seed]),scalar_expected[seed][path]))return 31;\n"
    text += f"for(u64 i=0;i<96;++i)if(masks[path][i]&&add(storage[16+i]&masks[path][i],bytes_expected[seed*{len(path_list)}+path][i]&masks[path][i]))return 31;\n"
    text += "for(u64 i=0;i<pointer_counts[path];++i)if(add(get64(storage+16+pointer_offsets[path][i])==(u64)&anchor_alias,1))return 31;\n"
    text += "for(u64 i=0;i<16;++i)if(add(storage[i],0xa5)||add(storage[112+i],0xa5))return 31;}\n"
    if frontend == "llvm":
        text += f"extern unsigned char probe_marker;extern u64 probe_count;if(add(probe_marker,167)||add(probe_count,{len(SEEDS) * 3 * (len(RAW_CASES) + 1)}))return 31;\n"
    output = golden(frontend).decode().rstrip(); begin = output.index("digest=") + len("digest=")
    text += f"if(checks!={output.split('checks=')[1]})return 37;\n"
    text += 'static char output[]="' + output[:begin] + "0" * 16 + output[begin + 16:] + '\\n";\n'
    text += f"for(u64 i=0;i<16;++i){{u64 n=(digest>>(60-4*i))&15;output[{begin}+i]=(char)(n<10?'0'+n:'a'+n-10);}}\n"
    text += """
#if defined(__x86_64__)
 if(syscall3(1,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#else
 if(syscall3(64,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#endif
 return 0;}
#if defined(__x86_64__)
__asm__""" + reusable.split('#if defined(__x86_64__)\n__asm__', 1)[1]
    return text


class AggregateAbiNativeTests(unittest.TestCase):
    setUpClass = classmethod(weak.WeakNativeTests.setUpClass.__func__)
    command = weak.WeakNativeTests.command
    emulators = census.AllocsizeNativeTests.emulators
    original_inventory = census.AllocsizeNativeTests.original_inventory

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_AGGREGATE_ABI_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-aggregate-abi-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)
        self.sequence = 0; self.compiler_sha = weak.artifact(self.compiler)["sha256"]
        self.library = importer.LLVM(importer.discover_library(), importer.PINNED_SHA256)

    def original_effect_trace(self, source):
        """Independent pinned CAPI inventory of every call and owned memop.

        Source SSA ordinals are the importer's retained value identities:
        parameters first, then all original non-void instructions in original
        block order. Synthetic GEP helper values are outside this inventory.
        This audits operand binding; the independent execution oracle checks
        behavior without reproducing machine register or frame decisions.
        """
        a = self.library; data = source.read_bytes(); context = a.ContextCreate()
        buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"aggregate-abi-original-effects")
        module, error = importer.P(), importer.P()
        self.assertEqual(a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error)), 0)
        rows = {}; align_kind = int(a.GetEnumAttributeKindForName(b"align", 5))
        is_call = a.lib.LLVMIsACallInst; is_call.restype, is_call.argtypes = importer.P, [importer.P]
        try:
            def type_shape(ty):
                kind = a.GetTypeKind(ty)
                if kind == 0: return {"kind": "void"}
                if kind == 8: return {"kind": "int", "bits": int(a.GetIntTypeWidth(ty))}
                if kind == 12: return {"kind": "pointer", "address_space": int(a.GetPointerAddressSpace(ty))}
                self.fail("owned memory intrinsic has a non-scalar signature")
            def call_alignment(call, index):
                count = a.GetCallSiteAttributeCount(call, index); attrs = (importer.P * count)()
                a.GetCallSiteAttributes(call, index, attrs)
                aligns = [int(a.GetEnumAttributeValue(attr)) for attr in attrs
                          if a.IsEnumAttribute(attr) and a.GetEnumAttributeKind(attr) == align_kind]
                self.assertLessEqual(len(aligns), 1)
                return aligns[0] if aligns else 1
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                params = (importer.P * a.CountParams(function))(); a.GetParams(function, params)
                instructions = [inst for block in a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function)
                                for inst in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block)]
                values = [*params, *[inst for inst in instructions if a.GetTypeKind(a.TypeOf(inst)) != 0]]
                identities = {value: index for index, value in enumerate(values)}
                def operand(value):
                    if value in identities: return {"kind": "value", "id": identities[value]}
                    if a.IsAConstantInt(value): return {"kind": "int", "bits": str(int(a.ConstIntGetZExtValue(value)))}
                    if a.IsAGlobalVariable(value) or a.IsAFunction(value) or a.IsAGlobalAlias(value):
                        return {"kind": "symbol", "name": a.name(value)}
                    self.fail("unexpected memory intrinsic operand in original fixture")
                trace = []
                for inst in instructions:
                    if not is_call(inst): continue
                    callee = a.GetCalledValue(inst)
                    name = a.name(callee) if a.IsAFunction(callee) or a.IsAGlobalAlias(callee) else None
                    if name and name.startswith(("llvm.memcpy.", "llvm.memmove.", "llvm.memset.")):
                        self.assertEqual(int(a.GetNumArgOperands(inst)), 4)
                        args = [a.GetOperand(inst, index) for index in range(4)]
                        self.assertTrue(a.IsAConstantInt(args[3])); self.assertIn(int(a.ConstIntGetZExtValue(args[3])), (0, 1))
                        signature = a.GetCalledFunctionType(inst); types = (importer.P * a.CountParamTypes(signature))()
                        a.GetParamTypes(signature, types)
                        typed_signature = {"params": [type_shape(ty) for ty in types], "result": type_shape(a.GetReturnType(signature)),
                                           "abi": "c", "variadic": bool(a.IsFunctionVarArg(signature))}
                        self.assertEqual(int(a.GetInstructionCallConv(inst)), 0)
                        operation = {"op": "memory_set" if name.startswith("llvm.memset.") else "memory_copy",
                                     "destination": operand(args[0]), "length": operand(args[2]),
                                     "volatile": bool(a.ConstIntGetZExtValue(args[3]))}
                        if operation["op"] == "memory_copy":
                            operation.update(source=operand(args[1]), destination_alignment=call_alignment(inst, 1),
                                             source_alignment=call_alignment(inst, 2), allow_overlap=name.startswith("llvm.memmove."))
                        else: operation.update(value=operand(args[1]), alignment=call_alignment(inst, 1))
                        trace.append({"operation": operation, "intrinsic": name, "signature": typed_signature})
                    else: trace.append({"operation": {"op": "call", "callee": name}, "intrinsic": None})
                rows[a.name(function)] = trace
        finally:
            a.DisposeModule(module); a.ContextDispose(context)
        return rows

    def verify_module(self, source, target, original):
        effects = self.original_effect_trace(source)
        ordinary = copy.deepcopy(original)
        ordinary["body_calls"] = {name: [entry["operation"]["callee"] for entry in trace
                                         if entry["operation"]["op"] == "call"] for name, trace in effects.items()}
        result = census.AllocsizeNativeTests.verify_module(self, source, target, ordinary)
        module = json.loads(Path(result["module"]["path"]).read_text())
        functions = {function["name"]: function for function in module["functions"]}
        def without_type(operand): return {key: value for key, value in operand.items() if key != "ty"}
        for name, original_trace in effects.items():
            instructions = [i["operation"] for block in functions[name]["blocks"] for i in block["instructions"]]
            actual_trace = []
            for operation in instructions:
                if operation["op"] == "call":
                    actual_trace.append({"op": "call", "callee": operation["callee"].get("name") if operation["callee"]["kind"] == "symbol" else None})
                elif operation["op"] in {"memory_set", "memory_copy"}:
                    actual_trace.append({key: without_type(value) if isinstance(value, dict) else value for key, value in operation.items()})
            self.assertEqual(actual_trace, [entry["operation"] for entry in original_trace],
                             "every ordinary call and every exact owned intrinsic operand/effect must survive in original order")
            for entry in original_trace:
                if entry["intrinsic"] is None: continue
                signature = functions[entry["intrinsic"]]["signature"]
                actual_signature = {"params": [module["types"][ty] for ty in signature["params"]],
                                    "result": module["types"][signature["result"]], "abi": signature["abi"], "variadic": signature["variadic"]}
                self.assertEqual(actual_signature, entry["signature"])
                self.assertIsNone(functions[entry["intrinsic"]]["entry"], "intrinsic declaration remains included")
                self.assertFalse(signature["result_attributes"]); self.assertFalse(any(signature["param_attributes"]))
        result["original_call_and_owned_intrinsic_effect_trace"] = effects
        return result

    def sources(self, isa, triple, flags, frontend, role):
        stem = self.directory / (isa + "-" + frontend + "-" + role)
        if frontend == "llvm":
            source = stem.with_suffix(".ll"); source.write_text(weak.promises.module_text(triple, llvm_caller() if role == "caller" else llvm_callee()))
            binary = stem.with_suffix(".bc"); self.command([self.sdk / "llvm-as", source, "-o", binary])
        else:
            original = stem.with_suffix(".cpp" if frontend == "cpp" else ".c"); original.write_text(c_source(role, frontend == "cpp"))
            source, binary = stem.with_suffix(".ll"), stem.with_suffix(".bc")
            for output, mode in ((source, "-S"), (binary, "-c")):
                argv = [self.sdk / ("clang++" if frontend == "cpp" else "clang"), "--target=" + triple, *flags,
                        "-O0", "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-pie", "-fno-stack-protector",
                        "-fno-unwind-tables", "-fno-asynchronous-unwind-tables"]
                if frontend == "cpp": argv += ["-fno-exceptions", "-fno-rtti"]
                self.command([*argv, "-emit-llvm", mode, original, "-o", output])
        return source, binary

    def original_layouts(self, source, frontend):
        a = self.library; data = source.read_bytes(); context = a.ContextCreate()
        buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"aggregate-abi-original-layout")
        module, error = importer.P(), importer.P()
        self.assertEqual(a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error)), 0)
        target_data = a.CreateTargetData(a.GetDataLayoutStr(module))
        get_type = a.lib.LLVMGetTypeByName2; get_type.restype, get_type.argtypes = importer.P, [importer.P, C.c_char_p]
        rows = {}
        try:
            names = set(ty for _, ty, _, _ in (RAW_CASES if frontend == "llvm" else C_CASES))
            def leaves(ty, path=(), offset=0):
                kind = a.GetTypeKind(ty)
                if kind == 8: return [(path, int(a.GetIntTypeWidth(ty)), offset)]
                if kind == 12: return [(path, "ptr", offset)]
                if kind == 10:
                    children = (importer.P * a.CountStructElementTypes(ty))(); a.GetStructElementTypes(ty, children)
                    return [leaf for index, child in enumerate(children)
                            for leaf in leaves(child, (*path, index), offset + int(a.OffsetOfElement(target_data, ty, index)))]
                if kind == 11:
                    child = a.GetElementType(ty); stride = int(a.ABISizeOfType(target_data, child))
                    return [leaf for index in range(int(a.GetArrayLength2(ty)))
                            for leaf in leaves(child, (*path, index), offset + index * stride)]
                self.fail("unexpected original ABI field type: " + str(kind))
            for name in names:
                ty = get_type(context, (("struct." if frontend != "llvm" else "") + name).encode())
                if not ty and frontend == "llvm":
                    # LLVM textual names for arrays are aliases, not identified
                    # struct types. Inspect the original function result handle.
                    case = next(case for case, ty_name, _, storage in RAW_CASES if ty_name == name and not storage)
                    function = next(function for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module)
                                    if a.name(function) == "engine_c_" + case)
                    ty = a.GetReturnType(a.GlobalGetValueType(function))
                # Frontend-produced types can be absent from a caller which
                # scalarizes the type completely; its callee remains checked.
                if not ty and frontend != "llvm": continue
                self.assertTrue(ty, name)
                actual = (int(a.ABISizeOfType(target_data, ty)), int(a.ABIAlignmentOfType(target_data, ty)), leaves(ty))
                self.assertEqual(actual, layout(NODES[name]), name)
                rows[name] = {"size": actual[0], "alignment": actual[1], "leaves": actual[2]}
        finally:
            a.DisposeTargetData(target_data); a.DisposeModule(module); a.ContextDispose(context)
        return rows

    def object(self, source, triple, flags, machine, own, target):
        output = source.with_name(source.name + (".own.o" if own else ".clang.o"))
        self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "-o", output] if own else
                     [self.sdk / "clang", "--target=" + triple, *flags, "-O0", "-fno-pic", "-fno-pie", "-c", source, "-o", output])
        elf(output, machine, 1); return output

    def differential(self, own):
        emulators = self.emulators()
        report = {"scope": "fixed C/LLVM fastcc integer-pointer aggregate ABI conformance",
                  "runtime_complete": False, "compiler_implementation_lowered": False,
                  "kernel_execution_verified": False, "dependency_closure_complete": False,
                  "exception_handling_verified": False, "floating_point_verified": False,
                  "ocore_objects_tested": own, "compiler_sha256": self.compiler_sha,
                  "test_source": weak.artifact(__file__),
                  "carrier_platform_providers": ["memcpy byte loop", "memset byte loop", "Linux syscall startup/output"],
                  "padding_policy": "aggregate padding and partial integer-byte padding unobserved; external canaries exact",
                  "tools": {name: weak.artifact(path) for name, path in {"ocorec": self.compiler,
                      "reference_clang": self.sdk / "clang", "frontend_clang++": self.sdk / "clang++",
                      "llvm-as": self.sdk / "llvm-as", "linker": self.linker, "own_assembler": self.assembler,
                      "llvm_library": importer.discover_library(), **emulators}.items()}, "targets": {}}
        for isa, (target, triple, machine, flags) in TARGETS.items():
            target_rows = []
            for frontend in ("llvm", "c", "cpp"):
                harness = self.directory / (isa + "-" + frontend + "-carrier.c"); harness.write_text(carrier(frontend))
                carriers = {}
                for corrupt in (False, True):
                    output = harness.with_suffix(".corrupt.o" if corrupt else ".o")
                    argv = [self.sdk / "clang", "--target=" + triple, *flags, "-O1", "-ffreestanding", "-fno-builtin",
                            "-fno-stack-protector", "-fno-pic", "-fno-pie", "-c", harness, "-o", output]
                    self.command([*argv, "-DCORRUPT_ORACLE"] if corrupt else argv); carriers[corrupt] = output
                objects, units, executions = {}, [], []
                for role in ("caller", "callee"):
                    for source in self.sources(isa, triple, flags, frontend, role):
                        original_bytes = source.read_bytes(); inventory = self.original_inventory(source)
                        record = {"role": role, "input": weak.artifact(source), "original_inventory": inventory,
                                  "original_layouts": self.original_layouts(source, frontend)}
                        if frontend != "llvm": record["frontend_source"] = weak.artifact(source.with_suffix(".cpp" if frontend == "cpp" else ".c"))
                        if own: record.update(self.verify_module(source, target, inventory))
                        for provider in (("original_clang", "own") if own else ("original_clang",)):
                            obj = self.object(source, triple, flags, machine, provider == "own", target)
                            symbols = weak.elf_symbols(obj)
                            for name in inventory["definitions"]: self.assertGreater(symbols[name]["size"], 0)
                            objects[role, source.suffix, provider] = obj; record[provider + "_object"] = weak.artifact(obj)
                        self.assertEqual(source.read_bytes(), original_bytes); units.append(record)
                for suffix in (".ll", ".bc"):
                    for caller in (("original_clang", "own") if own else ("original_clang",)):
                        for callee in (("original_clang", "own") if own else ("original_clang",)):
                            for control in ("positive", "oracle", "object"):
                                selected = objects["callee", suffix, callee]; mutation = None
                                if control == "object":
                                    mutated = selected.with_name(selected.name + ".corrupt")
                                    data = bytearray(selected.read_bytes()); symbol = weak.elf_symbols(selected)["cold_marker"]
                                    table = struct.unpack_from("<Q", data, 40)[0]; section = struct.unpack_from("<IIQQQQIIQQ", data, table + 64 * symbol["section"])
                                    offset = section[4] + symbol["value"]; self.assertEqual(data[offset], COLD & 255)
                                    data[offset] ^= 1; mutated.write_bytes(data); selected = mutated
                                    mutation = {"symbol": "cold_marker", "file_offset": offset, "object": weak.artifact(mutated)}
                                executable = self.directory / (isa + "-" + frontend + suffix + "-" + caller + "-" + callee + "-" + control)
                                self.command([self.sdk / "clang", "--target=" + triple, *flags, "--ld-path=" + self.linker,
                                              "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-e,_start",
                                              carriers[control == "oracle"], objects["caller", suffix, caller], selected, "-o", executable])
                                elf(executable, machine, 2)
                                result = self.command([executable] if isa == "x86_64" else [emulators[isa], executable], success=control == "positive")
                                self.assertEqual(result.returncode, 0 if control == "positive" else 31)
                                self.assertEqual(result.stdout, golden(frontend) if control == "positive" else b"")
                                executions.append({"input_kind": suffix, "caller": caller, "callee": callee, "control": control,
                                                   "executable": weak.artifact(executable), "stdout": result.stdout.decode(),
                                                   "exit_code": result.returncode, "mutation": mutation})
                target_rows.append({"frontend": frontend, "expected_stdout": golden(frontend).decode(),
                                    "carrier_source": weak.artifact(harness), "carrier_object": weak.artifact(carriers[False]),
                                    "modules": units, "executions": executions})
            report["targets"][isa] = {"profile": {"triple": triple, "flags": flags}, "frontends": target_rows}
        self.assertEqual(weak.artifact(self.compiler)["sha256"], self.compiler_sha)
        name = "aggregate-abi-own-conformance.json" if own else "aggregate-abi-original-clang-oracle.json"
        (self.directory / name).write_text(json.dumps(report, indent=2) + "\n")
        print(("Own/reference" if own else "Original Clang") + " aggregate ABI all three: " +
              "; ".join(golden(frontend).decode().strip() for frontend in ("llvm", "c", "cpp")), flush=True)

    def test_original_clang_reference_fixed_c_fastcc_and_genuine_c_cpp_ll_bc_all_three(self):
        self.differential(False)

    def test_own_aggregate_abi_four_compiler_pairings_match_original_clang_all_three(self):
        if os.environ.get("OCORE_TEST_AGGREGATE_ABI_REFERENCE_ONLY") == "1":
            self.skipTest("reference-first ABI qualification before owned compiler freeze")
        self.differential(True)

    def test_original_byval_parameters_remain_explicit_unsupported_whole_units(self):
        reference_only = os.environ.get("OCORE_TEST_AGGREGATE_ABI_REFERENCE_ONLY") == "1"
        byval_kind = int(self.library.GetEnumAttributeKindForName(b"byval", 5))
        report = {"scope": "original fixed aggregate byval ABI unsupported-profile guards",
                  "runtime_complete": False, "compiler_implementation_lowered": False,
                  "test_source": weak.artifact(__file__), "compiler_sha256": self.compiler_sha,
                  "own_rejections_tested": not reference_only, "targets": {}}
        for isa, (target, triple, machine, flags) in TARGETS.items():
            # A genuine C frontend emits byval on x86, while other target ABIs
            # may lower this same source to an ordinary indirect pointer.
            genuine = self.directory / (isa + "-unsupported-byval.c")
            genuine.write_text(C_TYPES + "u64 abi_source(struct Big value){return value.a[2];}\n")
            genuine_ir = genuine.with_suffix(".ll")
            self.command([self.sdk / "clang", "--target=" + triple, *flags, "-O0", "-ffreestanding", "-fno-pic", "-fno-pie", "-emit-llvm", "-S", genuine, "-o", genuine_ir])
            observed_byval = "byval(" in genuine_ir.read_text()
            if isa == "x86_64": self.assertTrue(observed_byval)
            source = self.directory / (isa + "-explicit-byval.ll")
            source.write_text(weak.promises.module_text(triple, "%Nine = type {[9 x i64]}\n"
                "@cold = constant i64 17\ndefine i64 @unsupported_argument(ptr byval(%Nine) align 8 %input){\n"
                " %last=getelementptr %Nine,ptr %input,i64 0,i32 0,i64 8\n %value=load i64,ptr %last,align 8\n ret i64 %value\n}\n"))
            binary = source.with_suffix(".bc"); self.command([self.sdk / "llvm-as", source, "-o", binary])
            inputs = []
            for input_ in (source, binary, genuine_ir):
                inventory = self.original_inventory(input_)
                original = self.object(input_, triple, flags, machine, False, target)
                row = {"input": weak.artifact(input_), "original_inventory": inventory, "original_object": weak.artifact(original)}
                if not reference_only and (input_ != genuine_ir or observed_byval):
                    output = input_.with_name(input_.name + ".rejected.o")
                    failure = self.command([self.compiler, input_, "--input-kind", "llvm-ir", "--target", target, "-o", output], success=False)
                    self.assertNotEqual(failure.returncode, 0)
                    self.assertIn(f"unsupported attribute kind {byval_kind} at index 1".encode(), failure.stderr)
                    self.assertFalse(output.exists())
                    row["own_rejection"] = {"exit_code": failure.returncode, "stderr": failure.stderr.decode()}
                inputs.append(row)
            report["targets"][isa] = {"genuine_source": weak.artifact(genuine), "genuine_c_emits_byval": observed_byval, "inputs": inputs}
        self.assertEqual(weak.artifact(self.compiler)["sha256"], self.compiler_sha)
        (self.directory / "aggregate-abi-byval-profile.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__": unittest.main()
