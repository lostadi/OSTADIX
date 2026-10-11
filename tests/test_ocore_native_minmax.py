"""Original whole-module LLVM integer min/max against a mathematical oracle.

All four families and every scalar width1..64 cross real target-native Clang
and owned ELF objects. Odd-width typed memory, stack arguments, cold symbols,
and defined observations of undef/poison refinements remain in the complete
LL/BC inputs. Linux startup and QEMU carry test results; these authored compiler
tests do not establish complete runtime/provider/compiler or kernel support.
"""

import copy
import ctypes as C
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_native_equivalence import TARGETS, elf
from tests import test_ocore_native_allocsize as census
from tests import test_ocore_native_eh_objects as frames
from tests import test_ocore_native_integer_overflow as overflow
from tests import test_ocore_native_weak as weak

MASK = (1 << 64) - 1
FAMILIES = ("smin", "smax", "umin", "umax")
# Independently recorded LLVM22 generated intrinsic IDs; no import resolver is
# used by the original-source census below.
INTRINSIC_IDS = {"smin": 343, "smax": 342, "umin": 380, "umax": 379}
SPECIAL_WIDTHS = (1, 9, 21, 33, 63, 64)
MARKER, COLD, MIX = 0x183947abcdef1245, 0x5522448899113377, sum(range(11, 24)) ^ 0xa5
STORAGE, DESTINATION = 32, 9


def minmax(family, width, left, right):
    """Unbounded ordering on the original mathematical signed/unsigned domain."""
    modulus = 1 << width
    left, right = left % modulus, right % modulus
    a, b = left, right
    if family.startswith("s"):
        a = a - modulus if a >= modulus // 2 else a
        b = b - modulus if b >= modulus // 2 else b
    if family.endswith("min"):
        return left if a <= b else right
    return left if a >= b else right


@lru_cache(maxsize=None)
def pairs(width):
    # Reuse deterministic inputs, not the overflow arithmetic or the imported
    # instruction decoder. Small widths include every original input pair.
    return overflow.pairs(width)


def bound(family, width):
    return {"smin": 1 << (width-1), "smax": (1 << (width-1))-1,
            "umin": 0, "umax": (1 << width)-1}[family]


def specials():
    return [(f"minmax_{mode}_{family}_{width}", 1 if mode == "poison" else bound(family, width))
            for width in SPECIAL_WIDTHS for family in FAMILIES for mode in ("undef", "frozen", "poison")]


def observed(family, width, lhs, rhs):
    value = minmax(family, width, lhs, rhs)
    bytes_, masks = [0xa5] * STORAGE, [255] * STORAGE
    for byte in range((width + 7)//8):
        at = DESTINATION + byte
        masks[at] = min(255, ((1 << width)-1) >> (8*byte))
        bytes_[at] = (value >> (8*byte)) & masks[at]
    return [value ^ MIX, *[byte & mask for byte, mask in zip(bytes_, masks)]]


def call_count():
    return 4 * sum(len(pairs(width)) for width in range(1, 65))


@lru_cache(maxsize=None)
def golden():
    digest, count = 0xcbf29ce484222325, 0
    def add(value):
        nonlocal digest, count
        digest = ((digest ^ value) * 0x100000001b3) & MASK
        count += 1
    for value in (MARKER, COLD, 1, 1, 1): add(value)
    for width in range(1, 65):
        for lhs, rhs in pairs(width):
            for family in FAMILIES:
                for value in observed(family, width, lhs, rhs): add(value)
    for _, value in specials(): add(value)
    add(call_count())
    return f"OCORE-INTEGER-MINMAX digest={digest:016x} checks={count}\n".encode()


def wrapper(family, width):
    ty = f"i{width}"
    parameters = "ptr %destination, i64 %lhs, i64 %rhs, " + ", ".join(f"i64 %extra{i}" for i in range(13))
    lines = [f"define i64 @minmax_{family}_{width}({parameters}) {{", "entry:",
             "  %frame = alloca [8193 x i8], align 16",
             "  %last = getelementptr [8193 x i8], ptr %frame, i64 0, i64 8192",
             "  store volatile i8 165, ptr %last, align 1",
             "  %canary = load volatile i8, ptr %last, align 1",
             "  %count = load i64, ptr @minmax_counter, align 8",
             "  %next = add i64 %count, 1", "  store i64 %next, ptr @minmax_counter, align 8"]
    lines += (["  %a = or i64 %lhs, 0", "  %b = or i64 %rhs, 0"] if width == 64 else
              [f"  %a = trunc i64 %lhs to {ty}", f"  %b = trunc i64 %rhs to {ty}"])
    lines += [f"  %result = call {ty} @llvm.{family}.{ty}({ty} %a, {ty} %b)",
              f"  store {ty} %result, ptr %destination, align 1",
              f"  %loaded = load {ty}, ptr %destination, align 1"]
    wide = "%loaded"
    if width < 64:
        lines.append(f"  %wide = zext {ty} %loaded to i64"); wide = "%wide"
    prior = "%extra0"
    for index in range(1, 13):
        lines.append(f"  %sum{index} = add i64 {prior}, %extra{index}"); prior = f"%sum{index}"
    lines += ["  %canary64 = zext i8 %canary to i64", f"  %mix = xor i64 {prior}, %canary64",
              f"  %answer = xor i64 {wide}, %mix", "  ret i64 %answer", "}"]
    return "\n".join(lines)+"\n"


def special_body(family, width, mode):
    ty, limit = f"i{width}", bound(family, width)
    lines = [f"define i64 @minmax_{mode}_{family}_{width}() {{", "entry:"]
    operand = "undef"
    if mode == "frozen":
        lines.append(f"  %frozen_input = freeze {ty} undef"); operand = "%frozen_input"
    elif mode == "poison": operand = "poison"
    lines.append(f"  %result = call {ty} @llvm.{family}.{ty}({ty} {operand}, {ty} {limit})")
    if mode == "poison":
        # The arbitrary freeze bits are not compared between implementations.
        # Reusing one frozen SSA value produces the defined observation true.
        lines += [f"  %frozen_result = freeze {ty} %result",
                  f"  %same = icmp eq {ty} %frozen_result, %frozen_result", "  %answer = zext i1 %same to i64"]
        result = "%answer"
    elif width < 64:
        lines.append(f"  %answer = zext {ty} %result to i64"); result = "%answer"
    else: result = "%result"
    return "\n".join([*lines, f"  ret i64 {result}", "}"])+"\n"


def source_text():
    text = f"@minmax_anchor = global i64 {MARKER}, align 8\n@minmax_cold = constant i64 {COLD}, align 8\n"
    text += "@minmax_counter = global i64 0, align 8\n@minmax_alias = alias i64, ptr @minmax_anchor\n"
    text += "@minmax_address = constant ptr @minmax_alias, align 8\n@minmax_callback = constant ptr @minmax_cold_entry, align 8\n"
    text += "@minmax_cold_entry = alias i64 (i64), ptr @unused_minmax\n"
    for width in range(1, 65):
        for family in FAMILIES:
            text += f"declare i{width} @llvm.{family}.i{width}(i{width}, i{width})\n"
            text += wrapper(family, width)
    text += "define i64 @unused_minmax(i64 %value) {\nentry:\n %answer = call i64 @llvm.umin.i64(i64 %value, i64 111)\n ret i64 %answer\n}\n"
    for width in SPECIAL_WIDTHS:
        for family in FAMILIES:
            for mode in ("undef", "frozen", "poison"): text += special_body(family, width, mode)
    return text


@lru_cache(maxsize=None)
def carrier():
    reusable = weak.carrier(11)
    text = reusable[:reusable.index("extern u64 chosen_global")]
    text += "extern u64 minmax_anchor,minmax_cold,minmax_counter,minmax_alias;\nextern u64 *minmax_address;\nextern u64 (*minmax_callback)(u64);\nextern u64 unused_minmax(u64),minmax_cold_entry(u64);\n"
    prototype = "void*," + ",".join(["u64"]*15)
    names = [f"minmax_{family}_{width}" for width in range(1, 65) for family in FAMILIES]
    text += "".join(f"extern u64 {name}({prototype});\n" for name in names)
    text += f"static u64(*const functions[])({prototype})={{" + ",".join(names)+"};\n"
    starts, rows = [0], []
    for width in range(1, 65):
        for lhs, rhs in pairs(width): rows.append([lhs, rhs, *[minmax(family, width, lhs, rhs) for family in FAMILIES]])
        starts.append(len(rows))
    text += "static const u64 starts[]={"+",".join(map(str, starts))+"};\n"
    text += "static const u64 rows[][6]={"+",\n".join("{"+",".join(str(value)+"ULL" for value in row)+"}" for row in rows)+"};\n"
    text += "".join(f"extern u64 {name}(void);\n" for name, _ in specials())
    text += "static u64(*const special_functions[])(void)={"+",".join(name for name, _ in specials())+"};\n"
    text += "static const u64 special_values[]={"+",".join(str(value)+"ULL" for _, value in specials())+"};\n"
    text += """
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected){
#ifdef CORRUPT_ORACLE
 if(!checks)expected^=1;
#endif
 if(got!=expected)return 31;digest=(digest^got)*0x100000001b3ULL;++checks;return 0;}
"""
    text += f"int conformance_main(void){{if(add(minmax_anchor,{MARKER}ULL)||add(minmax_cold,{COLD}ULL))return 31;\n"
    text += "u64 volatile identities[]={(u64)&minmax_anchor,(u64)&minmax_alias,(u64)&unused_minmax,(u64)&minmax_cold_entry};\n"
    text += "if(add(identities[0]==identities[1]&&minmax_address==&minmax_alias,1)||add(identities[2]==identities[3],1)||add(minmax_callback==minmax_cold_entry,1))return 31;\n"
    text += "for(u64 width=1;width<=64;++width){u64 bytes=(width+7)/8;for(u64 row=starts[width-1];row<starts[width];++row)for(u64 family=0;family<4;++family){\n"
    text += "unsigned char memory[32] __attribute__((aligned(16)));for(u64 byte=0;byte<32;++byte)memory[byte]=0xa5;\n"
    extras = ",".join(map(str, range(11, 24)))
    text += f"u64 value=rows[row][2+family];if(add(functions[(width-1)*4+family](memory+{DESTINATION},rows[row][0],rows[row][1],{extras}),value^{MIX}ULL))return 31;\n"
    text += f"for(u64 byte=0;byte<{STORAGE};++byte){{u64 expected=0xa5,mask=255;if(byte>={DESTINATION}&&byte<{DESTINATION}+bytes){{u64 shift=8*(byte-{DESTINATION});expected=(value>>shift)&255;if(width-shift<8)mask=(1ULL<<(width-shift))-1;}}if(add(memory[byte]&mask,expected&mask))return 31;}}}}}}\n"
    text += "for(u64 i=0;i<sizeof(special_values)/sizeof(special_values[0]);++i)if(add(special_functions[i](),special_values[i]))return 31;\n"
    text += f"if(add(minmax_counter,{call_count()}ULL))return 31;\n"
    output = golden().decode().rstrip(); start = output.index("digest=")+len("digest=")
    text += f"if(checks!={output.split('checks=')[1]})return 37;\nstatic char output[]=\""+output[:start]+"0"*16+output[start+16:]+'\\n";\n'
    text += f"for(u64 i=0;i<16;++i){{u64 n=(digest>>(60-4*i))&15;output[{start}+i]=(char)(n<10?'0'+n:'a'+n-10);}}\n"
    text += """
#if defined(__x86_64__)
 if(syscall3(1,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#else
 if(syscall3(64,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#endif
 return 0;}
#if defined(__x86_64__)
__asm__"""+reusable.split('#if defined(__x86_64__)\n__asm__', 1)[1]
    return text


class IntegerMinmaxOracleTests(unittest.TestCase):
    def test_signed_one_bit_and_all_width_ordering_boundaries(self):
        for lhs in range(2):
            for rhs in range(2):
                self.assertEqual([minmax(f, 1, lhs, rhs) for f in FAMILIES], [lhs | rhs, lhs & rhs, lhs & rhs, lhs | rhs])
        for width in range(1, 65):
            for family in FAMILIES:
                for value in (0, 1, (1 << width)-1, 1 << (width-1)):
                    self.assertEqual(minmax(family, width, value, bound(family, width)), bound(family, width))
                    self.assertEqual(minmax(family, width, value, value), value)
                for lhs, rhs in pairs(width):
                    self.assertIn(minmax(family, width, lhs, rhs), (lhs % (1 << width), rhs % (1 << width)))
                    self.assertEqual(minmax(family, width, lhs, rhs), minmax(family, width, rhs, lhs))


class IntegerMinmaxNativeTests(unittest.TestCase):
    emulators = census.AllocsizeNativeTests.emulators
    original_inventory = census.AllocsizeNativeTests.original_inventory

    @classmethod
    def setUpClass(cls):
        cls.compiler = Path(os.environ.get("OCOREC", str(weak.ROOT/"target/debug/ocorec"))).resolve()
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(weak.SDK))).resolve()
        cls.linker = shutil.which(os.environ.get("LD_LLD", "ld.lld"))
        required = [cls.sdk/name for name in ("clang", "llvm-as", "llvm-readobj")]
        if os.environ.get("OCORE_TEST_MINMAX_REFERENCE_ONLY") != "1": required.append(cls.compiler)
        missing = [str(path) for path in required if not path.is_file()]
        if cls.linker is None: missing.append("LD_LLD/ld.lld")
        if missing:
            reason = "exact LLVM22 reference tools and coherent owned compiler required: "+", ".join(missing)
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1": raise RuntimeError(reason)
            raise unittest.SkipTest(reason)
        for path in required:
            if path == cls.compiler: continue
            result = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=15)
            if result.returncode or not re.search(r"\b(?:clang version|LLVM version) 22\.1\.6\b", result.stdout):
                raise RuntimeError("exact LLVM22.1.6 required: "+str(path))

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_MINMAX_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-minmax-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)
        self.sequence, self.bound = 0, {}
        self.library = importer.LLVM(importer.discover_library(), importer.PINNED_SHA256)

    def bind(self, path):
        record = weak.artifact(path)
        if record["path"] in self.bound: self.assertEqual(record, self.bound[record["path"]], "bound artifact changed")
        self.bound[record["path"]] = record
        return record

    def command(self, argv, success=True, cwd=weak.ROOT):
        argv = [str(item) for item in argv]
        started = time.monotonic(); record = {"argv": argv, "cwd": str(cwd), "execution_timeout_seconds": 120}
        try:
            result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=120)
            record.update(exit_code=result.returncode, stdout=result.stdout.decode(errors="replace"),
                          stderr=result.stderr.decode(errors="replace"), timeout=False)
        except subprocess.TimeoutExpired as error:
            record.update(exit_code=None, timeout=True, stdout=(error.stdout or b"").decode(errors="replace"),
                          stderr=(error.stderr or b"").decode(errors="replace")); raise
        finally:
            record["elapsed_seconds"] = time.monotonic()-started
            path = self.directory/f"command-{self.sequence:03}.json"
            path.write_text(json.dumps(record, indent=2)+"\n"); self.bind(path); self.sequence += 1
        if success: self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result

    def original_contract(self, source):
        """Read original LLVM call handles, types and SSA identities directly."""
        a = self.library
        context, module, error, message = a.ContextCreate(), importer.P(), importer.P(), importer.P()
        buffer, layout = None, None
        try:
            data = source.read_bytes()
            buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"independent-minmax-original")
            parsed = a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error))
            self.assertEqual(parsed, 0, C.string_at(error).decode() if error else "LLVM parse failed")
            verified = a.VerifyModule(module, 2, C.byref(message))
            self.assertEqual(verified, 0, C.string_at(message).decode() if message else "LLVM verification failed")
            layout = a.CreateTargetData(a.GetDataLayoutStr(module))
            is_call = a.lib.LLVMIsACallInst; is_call.restype, is_call.argtypes = importer.P, [importer.P]
            def ty(value):
                kind = a.GetTypeKind(value)
                if kind == 8: return {"kind": "int", "bits": int(a.GetIntTypeWidth(value))}
                if kind == 12: return {"kind": "pointer", "address_space": int(a.GetPointerAddressSpace(value))}
                self.fail("unsupported original scalar shape in independent minmax oracle")
            rows, memory_rows, block_rows, parameter_counts, function_handles = {}, {}, {}, {}, {}
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                name = a.name(function); function_handles[name] = function
                rows[name], memory_rows[name], block_rows[name] = [], [], []
                params = (importer.P*a.CountParams(function))(); a.GetParams(function, params)
                parameter_counts[name] = len(params)
                blocks = list(a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function))
                values = {value: index for index, value in enumerate(params)}
                for block in blocks:
                    for instruction in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                        if a.GetTypeKind(a.TypeOf(instruction)) != 0: values[instruction] = len(values)
                def operand(value):
                    if value in values: return {"kind": "value", "id": values[value]}
                    shape = ty(a.TypeOf(value))
                    if a.IsAPoisonValue(value): return {"kind": "poison", "type": shape}
                    if a.IsAUndefValue(value): return {"kind": "undef", "type": shape}
                    if a.IsAGlobalVariable(value) or a.IsAGlobalAlias(value) or a.IsAFunction(value):
                        return {"kind": "symbol", "type": shape, "name": a.name(value)}
                    self.assertTrue(a.IsAConstantInt(value), "fixture constant requires an explicit independent contract")
                    return {"kind": "int", "type": shape, "bits": str(a.ConstIntGetZExtValue(value))}
                for block_index, block in enumerate(blocks):
                    instructions = list(a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block))
                    terminator = a.GetBasicBlockTerminator(block)
                    spans = []
                    for ordinal, instruction in enumerate(instructions):
                        opcode = int(a.GetInstructionOpcode(instruction))
                        operation = {26: "alloca", 27: "load", 28: "store", 29: "gep", 42: "i_cmp", 68: "freeze"}.get(opcode)
                        if 8 <= opcode <= 25: operation = "binary"
                        if 30 <= opcode <= 41 or opcode == 60: operation = "cast"
                        if instruction == terminator:
                            self.assertEqual(opcode, 1); count, operation = 0, None
                        else:
                            count = 1
                            if opcode == 29:
                                self.assertTrue(all(a.IsAConstantInt(a.GetOperand(instruction, index))
                                                    for index in range(1, a.GetNumOperands(instruction))),
                                                "constant GEP must preserve its one-native-instruction span")
                            if is_call(instruction):
                                callee = a.GetCalledValue(instruction); self.assertTrue(a.IsAFunction(callee))
                                callee_name = a.name(callee)
                                match = re.fullmatch(r"llvm\.(smin|smax|umin|umax)\.i([1-9][0-9]*)", callee_name)
                                self.assertIsNotNone(match); family, width = match[1], int(match[2])
                                self.assertEqual(a.GetIntrinsicID(callee), INTRINSIC_IDS[family])
                                signature = a.GetCalledFunctionType(instruction)
                                self.assertEqual(a.CountParamTypes(signature), 2); self.assertFalse(a.IsFunctionVarArg(signature))
                                parameters = (importer.P*2)(); a.GetParamTypes(signature, parameters)
                                self.assertEqual([ty(value) for value in parameters], [{"kind": "int", "bits": width}]*2)
                                self.assertEqual(ty(a.GetReturnType(signature)), {"kind": "int", "bits": width})
                                self.assertEqual(a.GetNumArgOperands(instruction), 2)
                                self.assertEqual(a.GetInstructionCallConv(instruction), 0)
                                rows[name].append({"function": name, "block": block_index, "source_instruction": ordinal,
                                    "native_instruction": ordinal, "native_instruction_count": 1,
                                    "result": {"id": values[instruction], "type": ty(a.TypeOf(instruction))},
                                    "intrinsic": callee_name, "kind": family, "width": width,
                                    "lhs": operand(a.GetOperand(instruction, 0)), "rhs": operand(a.GetOperand(instruction, 1))})
                                operation = "integer_min_max"
                            self.assertIsNotNone(operation, "source opcode needs an explicit independent span contract")
                            if opcode in (27, 28):
                                row = {"function": name, "block": block_index, "native_instruction": ordinal,
                                       "op": "load" if opcode == 27 else "store", "alignment": int(a.GetAlignment(instruction)),
                                       "volatile": bool(a.GetVolatile(instruction)),
                                       "pointer": operand(a.GetOperand(instruction, 0 if opcode == 27 else 1)),
                                       "result": {"id": values[instruction], "type": ty(a.TypeOf(instruction))} if opcode == 27 else None}
                                if opcode == 28: row["value"] = operand(a.GetOperand(instruction, 0))
                                memory_rows[name].append(row)
                        spans.append({"source_instruction": ordinal, "source_opcode": opcode,
                                      "native_instruction": ordinal, "native_instruction_count": count,
                                      "native_final_operation": operation, "source_result_id": values.get(instruction)})
                    block_rows[name].append({"id": block_index, "native_instruction_count": len(instructions)-1,
                                             "source_instruction_spans": spans})
            layouts = {}
            for width in range(1, 65):
                # Read an existing original parameter type rather than creating
                # a replacement module/type on behalf of the frontend.
                function = function_handles[f"llvm.smin.i{width}"]
                signature = a.GlobalGetValueType(function); value = a.GetReturnType(signature)
                layouts[str(width)] = {"store_bytes": int(a.StoreSizeOfType(layout, value)),
                                       "allocation_bytes": int(a.ABISizeOfType(layout, value)),
                                       "alignment": int(a.ABIAlignmentOfType(layout, value))}
                self.assertEqual(layouts[str(width)]["store_bytes"], (width+7)//8)
            return {"input": self.bind(source), "target_triple": a.GetTarget(module).decode(),
                    "data_layout": a.GetDataLayoutStr(module).decode(), "call_trace": rows,
                    "memory_trace": memory_rows, "blocks_contract": block_rows,
                    "parameter_counts": parameter_counts, "integer_layouts": layouts}
        finally:
            if message: a.DisposeMessage(message)
            if error: a.DisposeMessage(error)
            if module: a.DisposeModule(module)
            if buffer: a.DisposeMemoryBuffer(buffer)
            if layout: a.DisposeTargetData(layout)
            a.ContextDispose(context)

    def preserve_minmax(self, module, original):
        self.assertEqual(module["target"]["triple"], original["target_triple"])
        self.assertEqual(module["target"]["data_layout"], original["data_layout"])
        def shape(identifier): return module["types"][identifier]
        def operand(value):
            value = dict(value)
            if "ty" in value: value["type"] = shape(value.pop("ty"))
            return value
        functions = {function["name"]: function for function in module["functions"]}
        for name, trace in original["call_trace"].items():
            function = functions[name]
            self.assertEqual(len(function["params"]), original["parameter_counts"][name])
            contracts = original["blocks_contract"][name]
            self.assertEqual(len(function["blocks"]), len(contracts))
            actual, memory = [], []
            for block in function["blocks"]:
                contract = next(row for row in contracts if row["id"] == block["id"])
                self.assertEqual(len(block["instructions"]), contract["native_instruction_count"], "complete source block expansion retained")
                for span in contract["source_instruction_spans"]:
                    if not span["native_instruction_count"]: continue
                    instruction = block["instructions"][span["native_instruction"]]
                    self.assertEqual(instruction["operation"]["op"], span["native_final_operation"], "source ordinal owns exact expected native operation")
                    self.assertEqual(None if instruction["result"] is None else instruction["result"]["id"], span["source_result_id"])
                for index, instruction in enumerate(block["instructions"]):
                    op = instruction["operation"]
                    if op["op"] in ("load", "store"):
                        row = {"function": name, "block": block["id"], "native_instruction": index,
                               "op": op["op"], "alignment": op["alignment"], "volatile": op["volatile"],
                               "pointer": operand(op["pointer"]),
                               "result": None if instruction["result"] is None else
                               {"id": instruction["result"]["id"], "type": shape(instruction["result"]["ty"])}}
                        if op["op"] == "store": row["value"] = operand(op["value"])
                        memory.append(row)
                    if op["op"] != "integer_min_max": continue
                    actual.append({"function": name, "block": block["id"], "native_instruction": index,
                        "native_instruction_count": 1, "result": {"id": instruction["result"]["id"], "type": shape(instruction["result"]["ty"])},
                        "kind": op["kind"], "lhs": operand(op["lhs"]), "rhs": operand(op["rhs"])})
            expected = [{key: value for key, value in row.items() if key not in {"source_instruction", "intrinsic", "width"}} for row in trace]
            self.assertEqual(actual, expected, "literal original minmax kinds/types/operand identities survive")
            self.assertEqual(memory, original["memory_trace"][name], "literal memory widths/alignments/volatility/pointers/values survive")
            for row in trace:
                declaration = functions[row["intrinsic"]]; signature = declaration["signature"]
                self.assertIsNone(declaration["entry"]); self.assertEqual(declaration["intrinsic"], row["intrinsic"])
                self.assertEqual(shape(signature["result"]), {"kind": "int", "bits": row["width"]})
                self.assertEqual([shape(ty) for ty in signature["params"]], [{"kind": "int", "bits": row["width"]}]*2)
                self.assertEqual(signature["abi"], "c"); self.assertFalse(signature["variadic"])
                self.assertFalse(signature["result_attributes"]); self.assertFalse(any(signature["param_attributes"]))

    def verify_module(self, source, target, inventory, original):
        ordinary = copy.deepcopy(inventory); ordinary["body_calls"] = {name: [] for name in inventory["functions"]}
        record = census.AllocsizeNativeTests.verify_module(self, source, target, ordinary)
        module = json.loads(Path(record["module"]["path"]).read_text())
        self.preserve_minmax(module, original)
        record["module"] = self.bind(record["module"]["path"])
        record["verification"] = self.bind(record["verification"]["path"])
        return record, module

    def owned_object(self, path, isa, machine, module):
        elf(path, machine, 1)
        decoded = frames.Elf(path.read_bytes())
        names = {f["name"] for f in module["functions"] if f["entry"] is not None}
        aliases = {a["name"]: a["aliasee"] for a in module["aliases"] if a["aliasee"] in names}
        symbols = [s for s in decoded.symbols if s["section"] and s["info"] & 15 == 2]
        self.assertEqual(len({s["name"] for s in symbols}), len(symbols), "duplicate actual function symbol records")
        self.assertEqual({s["name"] for s in symbols}, names | set(aliases))
        for name in names | set(aliases):
            self.assertEqual(sum(s["name"] == name for s in decoded.symbols), 1, "source function requires exactly one named symbol")
        actual = {s["name"]: s for s in symbols}; definitions = [actual[name] for name in names]
        self.assertTrue(all(s["size"] > 0 for s in definitions))
        extents = {(s["section"], s["value"], s["size"]) for s in definitions}
        self.assertEqual(len(extents), len(names), "original bodies need distinct extents")
        prior = []
        for s in definitions:
            section = decoded.sections[s["section"]]
            self.assertTrue(section["flags"] & 4, "function section must be executable")
            self.assertLessEqual(s["value"]+s["size"], len(decoded.section_data(s["section"])), "function extent must fit section")
            for other in prior:
                if other["section"] == s["section"]:
                    self.assertTrue(other["value"]+other["size"] <= s["value"] or s["value"]+s["size"] <= other["value"], "source bodies may not overlap")
            prior.append(s)
        fdes = frames.dwarf_frames(decoded, isa)
        self.assertEqual(len(fdes), len(extents))
        self.assertEqual({(f["code_section"], f["start"], f["size"]) for f in fdes}, extents, "complete actual FDE ownership must match source bodies")
        self.assertTrue(all(f["cie"]["personality"] is None and f["lsda"] is None for f in fdes))
        for name, target in aliases.items():
            self.assertEqual(tuple(actual[name][key] for key in ("section", "value", "size")),
                             tuple(actual[target][key] for key in ("section", "value", "size")))
        for global_ in module["globals"]:
            if global_["initializer"] is None: continue
            symbol = decoded.named[global_["name"]]; section = decoded.sections[symbol["section"]]
            data = bytes(symbol["size"]) if section["kind"] == 8 else decoded.section_data(symbol["section"])[symbol["value"]:symbol["value"]+symbol["size"]]
            self.assertEqual(data, bytes(global_["initializer"]["bytes"]))
            for relocation in global_["initializer"]["relocations"]:
                r = decoded.relocation(symbol["section"], symbol["value"]+relocation["offset"])
                self.assertEqual(decoded.symbols[r["symbol"]]["name"], relocation["symbol"])
                self.assertEqual(r["addend"], relocation["addend"])
        undefined = {s["name"] for s in decoded.symbols if s["name"] and not s["section"]}
        self.assertFalse(undefined, "complete fixture must not depend on a runtime minmax helper or undefined provider")
        self.assertFalse(any(s["name"].startswith("llvm.") for s in decoded.symbols), "owned declarations are compiler operations, never native bodies/helpers")
        return {"object": self.bind(path), "source_function_definitions": len(names), "actual_fdes": len(fdes),
                "function_aliases": aliases, "undefined_symbols": sorted(undefined)}

    def controls(self, original, module, isa, machine, target):
        result = {"source_oracle": [], "semantic": [], "object": []}
        def function(m): return next(f for f in m["functions"] if f["name"] == "minmax_smin_9")
        def instruction(m): return next(i for i in function(m)["blocks"][0]["instructions"] if i["operation"]["op"] == "integer_min_max")
        for label in ("changed_kind", "swapped_source_operands", "changed_source_result", "changed_memory_alignment"):
            bad = copy.deepcopy(module); i = instruction(bad)
            if label == "changed_kind": i["operation"]["kind"] = "smax"
            elif label == "swapped_source_operands":
                i["operation"]["lhs"], i["operation"]["rhs"] = i["operation"]["rhs"], i["operation"]["lhs"]
            elif label == "changed_source_result": i["result"]["id"] += 10000
            else:
                store = next(x for x in function(bad)["blocks"][0]["instructions"]
                             if x["operation"]["op"] == "store" and x["operation"]["value"].get("id") == i["result"]["id"])
                store["operation"]["alignment"] = 8
            with self.assertRaises(AssertionError): self.preserve_minmax(bad, original)
            path = self.directory/(isa+"-oracle-control-"+str(self.sequence)+"-"+label+".json")
            path.write_text(json.dumps(bad, indent=2)+"\n")
            result["source_oracle"].append({"case": label, "mutated_module": self.bind(path), "rejected": True})
        cases = []
        bad = copy.deepcopy(module); instruction(bad)["operation"]["rhs"] = {"kind": "value", "id": 999999}
        cases.append(("undefined_input", bad, "undefined SSA value"))
        bad = copy.deepcopy(module); instruction(bad)["operation"]["lhs"] = {"kind": "value", "id": instruction(bad)["result"]["id"]}
        cases.append(("self_reference", bad, "does not dominate"))
        bad = copy.deepcopy(module); ty = next(index for index, value in enumerate(bad["types"]) if value == {"kind": "int", "bits": 1})
        instruction(bad)["operation"]["rhs"] = {"kind": "int", "ty": ty, "bits": "0"}
        cases.append(("different_operand_width", bad, "type mismatch"))
        bad = copy.deepcopy(module); d = next(f for f in bad["functions"] if f["name"] == "llvm.smin.i9"); d["signature"]["variadic"] = True
        cases.append(("wrong_owned_declaration", bad, "intrinsic declaration"))
        bad = copy.deepcopy(module); cold = next(f for f in bad["functions"] if f["name"] == "unused_minmax")
        cold["blocks"][0]["instructions"][0]["operation"]["rhs"] = {"kind": "value", "id": 999999}
        cases.append(("cold_invalid_body", bad, "undefined SSA value"))
        bad = copy.deepcopy(module); next(g for g in bad["globals"] if g["name"] == "minmax_callback")["initializer"]["relocations"][0]["symbol"] = "llvm.smin.i9"
        cases.append(("escaped_owned_intrinsic", bad, "relocation cannot reference an intrinsic address"))
        for label, bad, diagnostic in cases:
            path = self.directory/(isa+"-semantic-control-"+str(self.sequence)+"-"+label+".json")
            path.write_text(json.dumps(bad, indent=2)+"\n")
            receipt = path.with_suffix(".receipt.json")
            command = self.command([self.compiler, path, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt], success=False)
            self.assertNotEqual(command.returncode, 0)
            self.assertIn(diagnostic, command.stderr.decode(errors="replace")); self.assertFalse(receipt.exists())
            result["semantic"].append({"case": label, "input": self.bind(path), "expected_diagnostic": diagnostic, "exit_code": command.returncode})
        return result

    def object_controls(self, path, isa, machine, module):
        data = path.read_bytes(); decoded = frames.Elf(data)
        names = {f["name"] for f in module["functions"] if f["entry"] is not None}
        symbols = sorted((s for s in decoded.symbols if s["name"] in names), key=lambda s: (s["section"], s["value"]))
        first, second = symbols[:2]; section = decoded.sections[first["section"]]; cases = []
        bad = bytearray(data); struct.pack_into("<I", bad, second["file_offset"], struct.unpack_from("<I", data, first["file_offset"])[0])
        cases.append(("duplicate_function_record", bad, "duplicate actual function symbol records"))
        bad = bytearray(data); struct.pack_into("<Q", bad, section["header"]+8, section["flags"] & ~4)
        cases.append(("non_executable_body", bad, "function section must be executable"))
        frame = frames.dwarf_frames(decoded, isa)[0]
        bad = bytearray(data); struct.pack_into("<I", bad, decoded.sections[frame["section"]]["offset"]+frame["range_position"], frame["size"]+1)
        cases.append(("wrong_actual_fde_range", bad, "complete actual FDE ownership"))
        result = []
        for label, bad, diagnostic in cases:
            output = path.with_name(path.name+".control-"+label); output.write_bytes(bad)
            with self.assertRaisesRegex(AssertionError, diagnostic): self.owned_object(output, isa, machine, module)
            result.append({"case": label, "corrupted_copy": self.bind(output), "expected_diagnostic": diagnostic, "rejected": True})
        return result

    def differential(self, own):
        emulators = self.emulators()
        report = {"scope": "whole original LL/BC all4 LLVM integer minmax families, scalar1..64, exact native conformance",
                  "runtime_complete": False, "compiler_implementation_lowered": False, "dependency_closure_complete": False,
                  "kernel_execution_verified": False, "silicon_execution_verified": False,
                  "literal_poison_propagation_verified": False, "undef_poison_policy": "llvm_defined_behavior_v1 stable refinement; only defined freeze/extremal observations compared",
                  "oracle": "Python unbounded original-width signed/unsigned ordering; exhaustive i1..i5 pairs, boundaries plus deterministic full-i64 noise",
                  "carrier_oracle": "expected values share the Python mathematical oracle; independent of Clang and O-core lowering",
                  "memory_policy": "typed iN store then same-type load; only undefined high bits in last partial scalar byte ignored; padding/outside canaries exact",
                  "test_source": self.bind(__file__), "expected_stdout": golden().decode(), "case_count": call_count(),
                  "families": list(FAMILIES), "widths": list(range(1, 65)), "special_defined_observations": len(specials()),
                  "targets": {}, "complete": False}
        dependencies = [__file__, importer.__file__, census.__file__, frames.__file__, overflow.__file__, weak.__file__, weak.promises.__file__]
        report["helper_sources"] = [self.bind(path) for path in dependencies]
        tool_paths = {"reference_clang": self.sdk/"clang", "llvm_as": self.sdk/"llvm-as", "llvm_readobj": self.sdk/"llvm-readobj",
                      "linker": self.linker, "llvm_library": importer.discover_library(), **emulators}
        if own: tool_paths["ocorec"] = self.compiler
        report["tools"] = {name: self.bind(path) for name, path in tool_paths.items()}
        receipt = self.directory/"report.json"
        try:
            for isa, (target, triple, machine, flags) in TARGETS.items():
                profile = {"triple": triple, "flags": flags, "abi": "lp64" if isa == "riscv64" else "target-native fixed integer C"}
                rows = report["targets"][isa] = {"profile": profile, "modules": []}
                # Genuine target frontend supplies the header/ABI. The raw LL
                # body is authored separately, never a retargeted compiled IR.
                probe = self.directory/(isa+"-profile-probe.c"); probe.write_text("unsigned long long minmax_target_probe(unsigned long long x){return x;}\n")
                probe_ir = probe.with_suffix(".ll")
                self.command([self.sdk/"clang", "--target="+triple, *flags, "-O0", "-ffreestanding", "-emit-llvm", "-S", probe, "-o", probe_ir])
                header = "\n".join(re.findall(r'^target (?:triple|datalayout) = .*$', probe_ir.read_text(), re.M))+"\n"
                abi_flags = re.findall(r'^(![0-9]+) = !\{i32 ([0-9]+), !"target-abi", !"([^"\n]+)"\}$', probe_ir.read_text(), re.M)
                self.assertEqual(len(abi_flags), int(isa == "riscv64"))
                if abi_flags:
                    identifier, behavior, abi = abi_flags[0]; self.assertEqual(abi, "lp64")
                    header += "!llvm.module.flags = !{"+identifier+"}\n"+identifier+' = !{i32 '+behavior+', !"target-abi", !"'+abi+'"}\n'
                rows["profile_frontend_source"], rows["profile_frontend_ir"] = self.bind(probe), self.bind(probe_ir)
                source = self.directory/(isa+"-minmax.ll"); source.write_text(header+source_text())
                binary = source.with_suffix(".bc"); self.command([self.sdk/"llvm-as", source, "-o", binary])
                harness = self.directory/(isa+"-carrier.c"); harness.write_text(carrier()); carriers = {}
                for corrupt in (False, True):
                    output = harness.with_suffix(".corrupt.o" if corrupt else ".o")
                    argv = [self.sdk/"clang", "--target="+triple, *flags, "-O1", "-ffreestanding", "-fno-builtin",
                            "-fno-stack-protector", "-fno-pic", "-fno-pie", "-c", harness, "-o", output]
                    self.command([*argv, "-DCORRUPT_ORACLE"] if corrupt else argv); carriers[corrupt] = output
                rows["carrier_source"], rows["carrier_objects"] = self.bind(harness), {str(k): self.bind(v) for k, v in carriers.items()}
                for input_ in (source, binary):
                    before = input_.read_bytes(); inventory, original = self.original_inventory(input_), self.original_contract(input_)
                    self.assertEqual(len(inventory["functions"]), 585); self.assertEqual(len(inventory["definitions"]), 329)
                    self.assertEqual(set(inventory["globals"]), {"minmax_anchor", "minmax_cold", "minmax_counter", "minmax_address", "minmax_callback"})
                    self.assertEqual(set(inventory["aliases"]), {"minmax_alias", "minmax_cold_entry"})
                    self.assertEqual(sum(len(trace) for trace in original["call_trace"].values()), 329)
                    self.assertEqual(sum(len(calls) for calls in inventory["body_calls"].values()), 329)
                    record = {"input": self.bind(input_), "original_inventory": inventory,
                              "original_intrinsic_contract": original, "executions": []}; rows["modules"].append(record)
                    if own:
                        verified, module = self.verify_module(input_, target, inventory, original); record.update(verified)
                        record["controls"] = self.controls(original, module, isa, machine, target)
                    for provider in (("original_clang", "own") if own else ("original_clang",)):
                        object_ = input_.with_name(input_.name+(".clang.o" if provider == "original_clang" else ".own.o"))
                        self.command([self.sdk/"clang", "--target="+triple, *flags, "-O0", "-fno-pic", "-fno-pie", "-c", input_, "-o", object_] if provider == "original_clang" else
                                     [self.compiler, input_, "--input-kind", "llvm-ir", "--target", target, "-o", object_])
                        elf(object_, machine, 1); record[provider+"_object"] = self.bind(object_)
                        if own and provider == "own":
                            record["owned_object_inventory"] = self.owned_object(object_, isa, machine, module)
                            record["object_controls"] = self.object_controls(object_, isa, machine, module)
                        symbols = weak.elf_symbols(object_)
                        for name in inventory["definitions"]: self.assertGreater(symbols[name]["size"], 0)
                        for control in ("positive", "oracle", "object"):
                            selected, mutation = object_, None
                            if control == "object":
                                selected = object_.with_name(object_.name+".wrong-cold-object")
                                data = bytearray(object_.read_bytes()); symbol = symbols["minmax_cold"]
                                table = struct.unpack_from("<Q", data, 40)[0]
                                section = struct.unpack_from("<IIQQQQIIQQ", data, table+64*symbol["section"])
                                at = section[4]+symbol["value"]; self.assertEqual(data[at], COLD & 255)
                                data[at] ^= 1; selected.write_bytes(data)
                                mutation = {"symbol": "minmax_cold", "file_offset": at, "object": self.bind(selected)}
                            executable = input_.with_name(input_.name+"-"+provider+"-"+control)
                            self.command([self.sdk/"clang", "--target="+triple, *flags, "--ld-path="+self.linker,
                                          "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-e,_start", carriers[control == "oracle"], selected, "-o", executable])
                            elf(executable, machine, 2)
                            result = self.command([executable] if isa == "x86_64" else [emulators[isa], executable], success=control == "positive")
                            self.assertEqual(result.returncode, 0 if control == "positive" else 31)
                            self.assertEqual(result.stdout, golden() if control == "positive" else b"")
                            record["executions"].append({"provider": provider, "control": control, "exit_code": result.returncode,
                                                       "stdout": result.stdout.decode(), "executable": self.bind(executable), "mutation": mutation})
                    self.assertEqual(input_.read_bytes(), before)
            for path, original in self.bound.items(): self.assertEqual(weak.artifact(path), original, "bound source/tool/input/output changed")
            report["complete"], report["bound_artifacts"] = True, list(self.bound.values())
        except BaseException as error:
            report["error"] = {"type": type(error).__name__, "message": str(error)}
            raise
        finally:
            receipt.write_text(json.dumps(report, indent=2)+"\n")
        print(("Own/reference" if own else "Original LLVM")+" integer minmax all3: "+golden().decode().strip()+"; report "+str(receipt), flush=True)

    def test_original_llvm_all_four_families_all_widths_ll_bc_against_unbounded_oracle(self):
        self.differential(False)

    def test_owned_lowering_all_four_families_all_widths_ll_bc_preserves_whole_module(self):
        if os.environ.get("OCORE_TEST_MINMAX_REFERENCE_ONLY") == "1":
            self.skipTest("explicit reference-only phase; minmax-enabled owned compiler qualification is separate")
        self.differential(True)


if __name__ == "__main__": unittest.main()
