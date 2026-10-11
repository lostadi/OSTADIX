"""Allocsize promises preserve original calls, effects, and pointer identity.

Both LLVM and genuine C frontend units are imported whole and never rewritten.
The original bounded arena implementations supply the tested behavior; this is
a metadata conformance probe, not a rewritten runtime or allocator bridge.
Linux/QEMU carries the test; full runtime/kernel/dependency gates remain false.
"""

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
from tests import test_ocore_native_weak as weak


ROOT, MASK = weak.ROOT, weak.MASK
CAPACITY, ARENA_BYTES, OFFSET = 256, 384, 32
MARKER = 0x1122334455667788
PATHS = ("one_direct", "one_alias", "one_indirect", "two_direct",
         "two_alias", "two_indirect", "site_only")
FUNCTION_TYPES = {
    "one_direct": "one", "one_alias": "one_alias",
    "two_direct": "two", "two_alias": "two_alias", "site_only": "plain",
}


def cases():
    """Independent request vectors include zero, boundaries, and overflow."""
    sizes = (0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128,
             255, 256, 257, MASK, MASK - 1, 1 << 63)
    rows = []
    for index, size in enumerate(sizes):
        # Both successful and nullable outcomes occur for each boundary.
        for odd in (0, 1):
            count = (0, 1, 2, 3, 0xffffffff)[index % 5]
            element = (size, MASK, 128, 1 << 63)[index % 4]
            seed = ((0x9e3779b97f4a7c14 * (index + 1)) & MASK) | odd
            rows.append((size, count, element, seed))
    rows += [(256, 2, 128, 0), (0, 0, MASK, 0), (3, 2, MASK, 2),
             (7, 0xffffffff, MASK, 4), (31, 3, 85, 6), (255, 1, 256, 8),
             (256, 1, 257, 10), (MASK, 0xffffffff, 0, 12)]
    return rows


def expectation(request, path):
    size, count, element, seed = request
    two = path.startswith("two_")
    mathematical_size = count * element if two else size
    requested_bits = mathematical_size & MASK
    valid = mathematical_size <= CAPACITY and not (seed & 1)
    tag = 29 if two else 17
    initial_log = seed ^ 0x6a09e667f3bcc908
    initial_calls = (seed * 7 + 123) & MASK
    log = ((initial_log * 0x100000001b3) & MASK) ^ requested_bits ^ seed ^ tag
    arena = [0xa5] * ARENA_BYTES
    if valid:
        for index in range(mathematical_size):
            arena[OFFSET + index] = ((seed >> 8) + 13 * index + tag) & 255
    return [int(not valid), int(valid), (initial_calls + 1) & MASK, log, *arena]


def golden():
    values = [MARKER, 1, 1, 1]
    for request in cases():
        for path in PATHS:
            values.extend(expectation(request, path))
    digest = 0xcbf29ce484222325
    for value in values:
        digest = ((digest ^ value) * 0x100000001b3) & MASK
    return f"OCORE-ALLOCSIZE digest={digest:016x} checks={len(values)}\n".encode()


def llvm_callee():
    return f"""
@arena = global [{ARENA_BYTES} x i8] zeroinitializer, align 16
@effect_log = global i64 0, align 8
@call_count = global i64 0, align 8
@cold_marker = constant i64 {MARKER}, align 8
@one_pointer = constant ptr @one_alias, align 8
@two_pointer = constant ptr @two_alias, align 8
@cold_pointer = constant ptr @unused_allocator, align 8
define internal void @record(i64 %size, i64 %seed, i64 %tag) {{
  %old = load volatile i64, ptr @effect_log, align 8
  %multiplied = mul i64 %old, 1099511628211
  %sized = xor i64 %multiplied, %size
  %seeded = xor i64 %sized, %seed
  %next = xor i64 %seeded, %tag
  store volatile i64 %next, ptr @effect_log, align 8
  %count = load volatile i64, ptr @call_count, align 8
  %incremented = add i64 %count, 1
  store volatile i64 %incremented, ptr @call_count, align 8
  ret void
}}
define internal void @fill(i64 %length, i64 %seed, i64 %tag) {{
entry:
  %base = lshr i64 %seed, 8
  br label %loop
loop:
  %index = phi i64 [0, %entry], [%next, %write]
  %done = icmp eq i64 %index, %length
  br i1 %done, label %exit, label %write
write:
  %position = add i64 %index, {OFFSET}
  %pointer = getelementptr [{ARENA_BYTES} x i8], ptr @arena, i64 0, i64 %position
  %scaled = mul i64 %index, 13
  %biased = add i64 %base, %scaled
  %tagged = add i64 %biased, %tag
  %byte = trunc i64 %tagged to i8
  store i8 %byte, ptr %pointer, align 1
  %next = add i64 %index, 1
  br label %loop
exit:
  ret void
}}
define ptr @one(i64 %size, i64 %seed) allocsize(0) {{
  call void @record(i64 %size, i64 %seed, i64 17)
  %large = icmp ugt i64 %size, {CAPACITY}
  %bit = and i64 %seed, 1
  %nullable = icmp ne i64 %bit, 0
  %reject = or i1 %large, %nullable
  br i1 %reject, label %null, label %valid
valid:
  call void @fill(i64 %size, i64 %seed, i64 17)
  ret ptr getelementptr ([{ARENA_BYTES} x i8], ptr @arena, i64 0, i64 {OFFSET})
null:
  ret ptr null
}}
define ptr @two(i32 %count, i64 %seed, i64 %element) allocsize(2,0) {{
entry:
  %wide_count = zext i32 %count to i64
  %length = mul i64 %wide_count, %element
  call void @record(i64 %length, i64 %seed, i64 29)
  %zero = icmp eq i64 %wide_count, 0
  br i1 %zero, label %check, label %nonzero
nonzero:
  %limit = udiv i64 -1, %wide_count
  %overflow = icmp ugt i64 %element, %limit
  br i1 %overflow, label %null, label %check
check:
  %large = icmp ugt i64 %length, {CAPACITY}
  %bit = and i64 %seed, 1
  %nullable = icmp ne i64 %bit, 0
  %reject = or i1 %large, %nullable
  br i1 %reject, label %null, label %valid
valid:
  call void @fill(i64 %length, i64 %seed, i64 29)
  ret ptr getelementptr ([{ARENA_BYTES} x i8], ptr @arena, i64 0, i64 {OFFSET})
null:
  ret ptr null
}}
@one_alias = alias ptr(i64,i64), ptr @one
@two_alias = alias ptr(i32,i64,i64), ptr @two
define ptr @plain(i64 %size, i64 %seed) {{
  %pointer = call ptr @one(i64 %size, i64 %seed)
  ret ptr %pointer
}}
define ptr @unused_allocator(i1 %flag, i64 %size) allocsize(1) {{
  call void @record(i64 %size, i64 123, i64 43)
  ret ptr null
}}
define i64 @unused_scalar(i64 %value) {{
  %result = xor i64 %value, {MARKER}
  ret i64 %result
}}
"""


def llvm_caller():
    lines = ["@one_pointer = external constant ptr", "@two_pointer = external constant ptr",
             "@unused_caller_global = constant i64 7, align 8"]
    for name in ("one", "one_alias", "plain"):
        lines.append(f"declare ptr @{name}(i64,i64)" + (" allocsize(0)" if name != "plain" else ""))
    for name in ("two", "two_alias"):
        lines.append(f"declare ptr @{name}(i32,i64,i64) allocsize(2,0)")
    for path in PATHS:
        lines.append(f"define ptr @run_{path}(i64 %size, i64 %count, i64 %element, i64 %seed) {{")
        two = path.startswith("two_")
        if two:
            lines.append("  %narrow = trunc i64 %count to i32")
        if path.endswith("indirect"):
            lines.append(f"  %callee = load ptr, ptr @{'two' if two else 'one'}_pointer, align 8")
            callee = "%callee"
        else:
            callee = "@" + FUNCTION_TYPES[path]
        arguments = "i32 %narrow, i64 %seed, i64 %element" if two else "i64 %size, i64 %seed"
        lines.extend((f"  %pointer = call ptr {callee}({arguments}) allocsize({'2,0' if two else '0'})",
                      "  ret ptr %pointer", "}"))
    lines.extend(("define i64 @unused_caller(i64 %value) {", "  %result = add i64 %value, 7",
                  "  ret i64 %result", "}"))
    return "\n".join(lines) + "\n"


C_CALLEE = f"""
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
u8 arena[{ARENA_BYTES}];
volatile u64 effect_log,call_count;
const u64 cold_marker={MARKER}ULL;
static void record(u64 size,u64 seed,u64 tag){{
 effect_log=(effect_log*0x100000001b3ULL)^size^seed^tag; ++call_count;
}}
static void fill(u64 length,u64 seed,u64 tag){{
 for(u64 i=0;i<length;++i)arena[{OFFSET}+i]=(u8)((seed>>8)+13*i+tag);
}}
void *one(u64 size,u64 seed) __attribute__((alloc_size(1)));
void *one(u64 size,u64 seed){{
 record(size,seed,17);if(size>{CAPACITY}||(seed&1))return 0;
 fill(size,seed,17);return arena+{OFFSET};
}}
void *two(u32 count,u64 seed,u64 element) __attribute__((alloc_size(3,1)));
void *two(u32 count,u64 seed,u64 element){{
 u64 length=(u64)count*element;record(length,seed,29);
 if((count&&element>~0ULL/count)||length>{CAPACITY}||(seed&1))return 0;
 fill(length,seed,29);return arena+{OFFSET};
}}
void *one_alias(u64,u64) __attribute__((alias("one")));
void *two_alias(u32,u64,u64) __attribute__((alias("two")));
void *(*const one_pointer)(u64,u64)=one_alias;
void *(*const two_pointer)(u32,u64,u64)=two_alias;
void *plain(u64 size,u64 seed){{return one(size,seed);}}
void *unused_allocator(_Bool flag,u64 size) __attribute__((alloc_size(2)));
void *unused_allocator(_Bool flag,u64 size){{record(size,123,43);return 0;}}
void *(*const cold_pointer)(_Bool,u64)=unused_allocator;
u64 unused_scalar(u64 value){{return value^{MARKER}ULL;}}
"""


def c_caller():
    lines = ["typedef unsigned long long u64; typedef unsigned int u32;",
             "extern void *(*const one_pointer)(u64,u64);",
             "extern void *(*const two_pointer)(u32,u64,u64);",
             "const u64 unused_caller_global=7;"]
    for name in ("one", "one_alias", "plain"):
        suffix = " __attribute__((alloc_size(1)))" if name != "plain" else ""
        lines.append(f"extern void *{name}(u64,u64){suffix};")
    for name in ("two", "two_alias"):
        lines.append(f"extern void *{name}(u32,u64,u64) __attribute__((alloc_size(3,1)));")
    for path in PATHS:
        two = path.startswith("two_")
        name = ("two_pointer" if two else "one_pointer") if path.endswith("indirect") else FUNCTION_TYPES[path]
        args = "(u32)count,seed,element" if two else "size,seed"
        lines.append(f"void *run_{path}(u64 size,u64 count,u64 element,u64 seed){{return {name}({args});}}")
    lines.append("u64 unused_caller(u64 value){return value+7;}")
    return "\n".join(lines) + "\n"


def carrier():
    reusable = weak.carrier(11)
    text = reusable[:reusable.index("extern u64 chosen_global")]
    text += f"extern unsigned char arena[{ARENA_BYTES}];\nextern volatile u64 effect_log,call_count;\n"
    text += "extern const u64 cold_marker;\nextern void *one(u64,u64),*one_alias(u64,u64);\n"
    text += "extern void *two(unsigned int,u64,u64),*two_alias(unsigned int,u64,u64);\n"
    text += "extern void *(*const one_pointer)(u64,u64);\nextern void *(*const two_pointer)(unsigned int,u64,u64);\n"
    for path in PATHS:
        text += f"extern void *run_{path}(u64,u64,u64,u64);\n"
    text += "static void*(*const runners[])(u64,u64,u64,u64)={" + ",".join("run_" + p for p in PATHS) + "};\n"
    rows = []
    for request in cases():
        one, two = expectation(request, "one_direct"), expectation(request, "two_direct")
        rows.append("{" + ",".join(f"{n}ULL" for n in (*request, one[1], two[1], one[2], one[3], two[3])) + "}")
    text += "static const u64 requests[][9]={" + ",\n".join(rows) + "};\n"
    text += r"""
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected){
#ifdef CORRUPT_ORACLE
 expected^=1;
#endif
 if(got!=expected)return 31;
 digest=(digest^got)*0x100000001b3ULL;++checks;return 0;
}
int conformance_main(void){
 u64 volatile addresses[]={(u64)one,(u64)one_alias,(u64)two,(u64)two_alias};
"""
    text += f"if(add(cold_marker,{MARKER}ULL)||add(addresses[0]==addresses[1],1)||add(addresses[2]==addresses[3],1)||add(one_pointer==one_alias&&two_pointer==two_alias,1))return 31;\n"
    text += f"""
 for(u64 row=0;row<sizeof(requests)/sizeof(requests[0]);++row)for(u64 path=0;path<{len(PATHS)};++path){{
  const u64 *request=requests[row];u64 size=request[0],count=request[1],element=request[2],seed=request[3];
  int two=path>=3&&path<=5;u64 valid=request[two?5:4],length=two?count*element:size,tag=two?29:17;
  for(u64 index=0;index<{ARENA_BYTES};++index)arena[index]=0xa5;
  effect_log=seed^0x6a09e667f3bcc908ULL;call_count=seed*7+123;
  void *result=runners[path](size,count,element,seed);
  if(add(result==0,!valid)||add(result==arena+{OFFSET},valid)||add(call_count,request[6])||add(effect_log,request[two?8:7]))return 31;
  for(u64 index=0;index<{ARENA_BYTES};++index){{
   u64 expected=valid&&index>={OFFSET}&&index<{OFFSET}+length?((seed>>8)+13*(index-{OFFSET})+tag)&255:0xa5;
   if(add(arena[index],expected))return 31;
  }}
 }}
 if(checks!={4+len(cases())*len(PATHS)*(4+ARENA_BYTES)})return 37;
"""
    expected = golden().decode().rstrip()
    prefix = expected.index("digest=") + len("digest=")
    text += 'static char output[]="' + expected[:prefix] + "0" * 16 + expected[prefix + 16:] + '\\n";\n'
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


def corrupt_marker_object(source, output):
    """Patch one named, initialized global in a copy of the real object."""
    data = bytearray(Path(source).read_bytes())
    symbol = weak.elf_symbols(source)["cold_marker"]
    table = struct.unpack_from("<Q", data, 40)[0]
    section = struct.unpack_from("<IIQQQQIIQQ", data, table + 64 * symbol["section"])
    offset = section[4] + symbol["value"]
    if symbol["size"] != 8 or bytes(data[offset:offset+8]) != MARKER.to_bytes(8, "little"):
        raise AssertionError("marker corruption must target the exact real initializer")
    data[offset] ^= 1
    Path(output).write_bytes(data)
    return {"symbol": "cold_marker", "file_offset": offset,
            "original": weak.artifact(source), "corrupted": weak.artifact(output)}


class AllocsizeNativeTests(unittest.TestCase):
    setUpClass = classmethod(weak.WeakNativeTests.setUpClass.__func__)
    command = weak.WeakNativeTests.command

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_ALLOCSIZE_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-allocsize-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.compiler_sha = weak.artifact(self.compiler)["sha256"]
        self.sequence = 0
        self.library = importer.LLVM(importer.discover_library(), importer.PINNED_SHA256)

    def emulators(self):
        values = {isa: shutil.which(os.environ.get("OCORE_TEST_QEMU_" + isa.upper(), "qemu-" + isa))
                  for isa in ("aarch64", "riscv64")}
        if platform.machine() not in {"x86_64", "AMD64"} or not all(values.values()):
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail("all-three execution tools required")
            self.skipTest("all-three execution tools unavailable")
        return values

    def sources(self, stem, triple, flags, role, frontend):
        if frontend == "llvm":
            source = self.directory / (stem + ".ll")
            body = llvm_caller() if role == "caller" else llvm_callee()
            source.write_text(weak.promises.module_text(triple, body))
            binary = source.with_suffix(".bc")
            self.command([self.sdk / "llvm-as", source, "-o", binary])
        else:
            original = self.directory / (stem + ".c")
            original.write_text(c_caller() if role == "caller" else C_CALLEE)
            source, binary = original.with_suffix(".ll"), original.with_suffix(".bc")
            for output, mode in ((source, "-S"), (binary, "-c")):
                self.command([self.sdk / "clang", "--target=" + triple, *flags,
                              "-O0", "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-pie",
                              "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
                              "-emit-llvm", mode, original, "-o", output])
        return source, binary

    def original_inventory(self, source):
        """Read original pinned LLVM handles without using import normalization."""
        a = self.library
        data = source.read_bytes()
        context = a.ContextCreate()
        module, error, message = importer.P(), importer.P(), importer.P()
        buffer = None
        try:
            buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"allocsize-oracle")
            parsed = a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error))
            if parsed:
                self.fail(C.string_at(error).decode() if error else "LLVM parse failed")
            self.assertEqual(a.VerifyModule(module, 2, C.byref(message)), 0)
            kind = a.GetEnumAttributeKindForName(b"allocsize", 9)
            rows, function_names, definitions, body_calls, body_accesses = [], [], [], {}, {}

            def record(owner, name, call):
                count = (a.GetCallSiteAttributeCount if call else a.GetAttributeCountAtIndex)(owner, 0xffffffff)
                attributes = (importer.P * count)()
                (a.GetCallSiteAttributes if call else a.GetAttributesAtIndex)(owner, 0xffffffff, attributes)
                for attribute in attributes:
                    if a.IsEnumAttribute(attribute) and a.GetEnumAttributeKind(attribute) == kind:
                        raw = int(a.GetEnumAttributeValue(attribute))
                        rows.append({"owner": name, "site": "callsite" if call else "function",
                                     "index": 0xffffffff, "raw": raw, "element": raw >> 32,
                                     "count": None if raw & 0xffffffff == 0xffffffff else raw & 0xffffffff})

            is_call = a.lib.LLVMIsACallInst
            is_call.restype, is_call.argtypes = importer.P, [importer.P]
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                name = a.name(function)
                function_names.append(name)
                body_calls[name], body_accesses[name] = [], []
                if a.GetFirstBasicBlock(function):
                    definitions.append(name)
                record(function, name, False)
                for block in a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function):
                    for instruction in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                        if is_call(instruction):
                            record(instruction, name, True)
                            callee = a.GetCalledValue(instruction)
                            body_calls[name].append(a.name(callee) if a.IsAFunction(callee) or a.IsAGlobalAlias(callee) else None)
                        opcode = a.GetInstructionOpcode(instruction)
                        # LLVM's public opcode enum: load=27, store=28.
                        if opcode in (27, 28):
                            body_accesses[name].append(("load" if opcode == 27 else "store", bool(a.GetVolatile(instruction))))
            globals_ = [a.name(value) for value in a.sequence(a.GetFirstGlobal, a.GetNextGlobal, module)]
            aliases = [a.name(value) for value in a.sequence(a.GetFirstGlobalAlias, a.GetNextGlobalAlias, module)]
            return {"functions": function_names, "definitions": definitions,
                    "globals": globals_, "aliases": aliases, "allocsize": rows,
                    "body_calls": body_calls, "body_accesses": body_accesses}
        finally:
            if message:
                a.DisposeMessage(message)
            if error:
                a.DisposeMessage(error)
            if module:
                a.DisposeModule(module)
            if buffer:
                a.DisposeMemoryBuffer(buffer)
            if context:
                a.ContextDispose(context)

    def object(self, source, triple, flags, machine, own=False, target=None):
        output = source.with_name(source.name + (".own.o" if own else ".clang.o"))
        if own:
            self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "-o", output])
        else:
            self.command([self.sdk / "clang", "--target=" + triple, *flags,
                          "-O0", "-fno-pic", "-fno-pie", "-c", source, "-o", output])
        elf(output, machine, 1)
        return output

    def verify_module(self, source, target, original):
        output = source.with_name(source.name + ".native.json")
        receipt = source.with_name(source.name + ".verified.json")
        self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target,
                      "--emit", "mir", "-o", output])
        self.command([self.compiler, output, "--input-kind", "native-ir",
                      "--verify-native", "--receipt", receipt])
        module = json.loads(output.read_text())
        provenance = module["provenance"]
        self.assertEqual(provenance["input_sha256"], weak.artifact(source)["sha256"])
        self.assertEqual({item["name"] for item in module["functions"]}, set(original["functions"]))
        self.assertEqual({item["name"] for item in module["globals"]}, set(original["globals"]))
        self.assertEqual({item["name"] for item in module["aliases"]}, set(original["aliases"]))
        for category in ("function", "global", "alias"):
            self.assertEqual(provenance["source_" + category + "_count"], len(original[category + "s" if category != "alias" else "aliases"]))
        self.assertEqual({item["name"] for item in module["functions"] if item["entry"] is not None}, set(original["definitions"]))
        self.assertEqual(json.loads(receipt.read_text())["module_sha256"], weak.artifact(output)["sha256"])
        for function in module["functions"]:
            operations = [instruction["operation"] for block in function["blocks"] for instruction in block["instructions"]]
            calls = [operation["callee"].get("name") if operation["callee"]["kind"] == "symbol" else None
                     for operation in operations if operation["op"] == "call"]
            accesses = [(operation["op"], operation.get("volatile", False)) for operation in operations
                        if operation["op"] in {"load", "store"}]
            self.assertEqual(calls, original["body_calls"][function["name"]], "every original direct/indirect call must survive, including unused bodies")
            self.assertEqual(accesses, original["body_accesses"][function["name"]], "all original ordinary/volatile accesses must survive")
        refinements = provenance["refinements"]
        for promise in original["allocsize"]:
            count = "absent" if promise["count"] is None else str(promise["count"])
            exact = f"allocsize raw={promise['raw']}, element_index={promise['element']}, count_index={count}"
            matching = [text for text in refinements if promise["owner"] + ":" in text
                        and promise["site"] in text and exact in text]
            self.assertTrue(matching, f"missing exact allocsize provenance: {promise}")
            self.assertTrue(any("4294967295" in text for text in matching))
        return {"module": weak.artifact(output), "verification": weak.artifact(receipt)}

    def carrier_object(self, isa, triple, flags, corrupt=False):
        source = self.directory / (isa + "-carrier.c")
        if not source.exists():
            source.write_text(carrier())
        output = source.with_suffix(".corrupt.o" if corrupt else ".o")
        argv = [self.sdk / "clang", "--target=" + triple, *flags, "-O1", "-ffreestanding",
                "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie", "-c", source, "-o", output]
        if corrupt:
            argv.append("-DCORRUPT_ORACLE")
        self.command(argv)
        return output

    def link(self, triple, flags, objects, output):
        self.command([self.sdk / "clang", "--target=" + triple, *flags,
                      "--ld-path=" + self.linker, "-nostdlib", "-static", "-Wl,--no-relax",
                      "-Wl,-e,_start", *objects, "-o", output])

    def differential(self, own):
        emulators = self.emulators()
        report = {"scope": "allocsize metadata erasure original LLVM/C conformance on Linux carriers",
                  "runtime_complete": False, "kernel_execution_verified": False,
                  "dependency_closure_complete": False, "compiler_implementation_lowered": False,
                  "ocore_objects_tested": own, "compiler_sha256": self.compiler_sha,
                  "test_source": weak.artifact(__file__), "expected_stdout": golden().decode(),
                  "tools": {name: weak.artifact(path) for name, path in {
                      "ocorec": self.compiler, "reference_clang": self.sdk / "clang", "llvm-as": self.sdk / "llvm-as",
                      "own_assembler": self.assembler, "linker": self.linker,
                      "llvm_library": importer.discover_library(), **emulators}.items()}, "targets": {}}
        for isa, (target, triple, machine, flags) in TARGETS.items():
            carrier_object = self.carrier_object(isa, triple, flags)
            broken_oracle = self.carrier_object(isa, triple, flags, True)
            profiles = {}
            for frontend in ("llvm", "c"):
                objects, records, executions = {}, [], []
                for role in ("caller", "callee"):
                    sources = self.sources(isa + "-" + frontend + "-" + role, triple, flags, role, frontend)
                    for source in sources:
                        original_bytes = source.read_bytes()
                        inventory = self.original_inventory(source)
                        self.assertTrue(inventory["allocsize"])
                        self.assertIn("unused_caller" if role == "caller" else "unused_allocator", inventory["definitions"])
                        self.assertIn("unused_caller_global" if role == "caller" else "cold_pointer", inventory["globals"])
                        references = self.object(source, triple, flags, machine)
                        objects[role, source.suffix, "original_clang"] = references
                        record = {"role": role, "input": weak.artifact(source), "original_inventory": inventory,
                                  "original_clang_object": weak.artifact(references)}
                        if frontend == "c":
                            record["original_c_source"] = weak.artifact(source.with_suffix(".c"))
                        if own:
                            record.update(self.verify_module(source, target, inventory))
                            lowered = self.object(source, triple, flags, machine, True, target)
                            objects[role, source.suffix, "own"] = lowered
                            record["own_object"] = weak.artifact(lowered)
                        for name in inventory["definitions"]:
                            for object_ in ([references, lowered] if own else [references]):
                                self.assertGreater(weak.elf_symbols(object_)[name]["size"], 0)
                        self.assertEqual(source.read_bytes(), original_bytes)
                        records.append(record)
                providers = ("own", "original_clang") if own else ("original_clang",)
                for suffix in (".ll", ".bc"):
                    for caller in providers:
                        for callee in providers:
                            stem = isa + "-" + frontend + suffix + "-" + caller + "-" + callee
                            output = self.directory / stem
                            selected = [objects["caller", suffix, caller], objects["callee", suffix, callee]]
                            self.link(triple, flags, [carrier_object, *selected], output)
                            elf(output, machine, 2)
                            result = self.command([output] if isa == "x86_64" else [emulators[isa], output])
                            self.assertEqual(result.stdout, golden())
                            executions.append({"input_kind": suffix, "caller": caller, "callee": callee,
                                               "executable": weak.artifact(output), "stdout": result.stdout.decode(), "exit_code": 0})
                            if caller == callee == ("own" if own else "original_clang"):
                                for control in ("oracle", "object"):
                                    corrupt = self.directory / (stem + ".corrupt-" + control)
                                    if control == "oracle":
                                        linked = [broken_oracle, *selected]
                                        corruption = None
                                    else:
                                        mutant = self.directory / (stem + ".corrupt-data.o")
                                        corruption = corrupt_marker_object(selected[1], mutant)
                                        linked = [carrier_object, selected[0], mutant]
                                    self.link(triple, flags, linked, corrupt)
                                    failed = self.command([corrupt] if isa == "x86_64" else [emulators[isa], corrupt], success=False)
                                    self.assertEqual(failed.returncode, 31)
                                    self.assertEqual(failed.stdout, b"")
                                    executions.append({"input_kind": suffix, "corrupt_" + control: True,
                                                       "executable": weak.artifact(corrupt), "mutation": corruption, "exit_code": 31})
                profiles[frontend] = {"modules": records, "executions": executions}
            report["targets"][isa] = {"profile": {"triple": triple, "flags": flags}, "frontends": profiles}
        self.assertEqual(weak.artifact(self.compiler)["sha256"], self.compiler_sha)
        name = "allocsize-own-conformance.json" if own else "allocsize-original-clang-oracle.json"
        (self.directory / name).write_text(json.dumps(report, indent=2) + "\n")
        print(("Own/reference" if own else "Original Clang") + " allocsize all three: " + golden().decode().strip(), flush=True)

    def test_original_clang_oracle_ll_bc_and_genuine_c_frontend_all_three(self):
        self.differential(own=False)

    def test_own_objects_all_four_caller_callee_combinations_ll_bc_all_three(self):
        if os.environ.get("OCORE_TEST_ALLOCSIZE_REFERENCE_ONLY") == "1":
            self.skipTest("reference-only qualification before the new importer/compiler freeze")
        self.differential(own=True)


if __name__ == "__main__":
    unittest.main()
