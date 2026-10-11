"""Exact LLVM integer overflow on every width, with an independent oracle.

The unchanged original ll/bc units retain all six intrinsic families and all
functions/globals/aliases. Python unbounded arithmetic computes both the
modular value and representability flag. Scalar typed stores initialize odd
integer memory before same-type loads. Linux startup/QEMU are test providers;
these probes do not establish whole-runtime/compiler or native-kernel support.
"""

import copy
import ctypes as C
from functools import lru_cache
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


MASK, BIAS = weak.MASK, 0x9e3779b97f4a7c15
MARKER, COLD = 0x123456789abcdef0, 0x1122334455667788
FAMILIES = ("uadd", "usub", "umul", "sadd", "ssub", "smul")
STORAGE, DESTINATION = 32, 8


def overflow(family, width, lhs, rhs):
    """LLVM's mathematical arithmetic, independent of register algorithms."""
    modulus = 1 << width
    left, right = lhs % modulus, rhs % modulus
    signed = family[0] == "s"
    if signed:
        left = left - modulus if left >= modulus // 2 else left
        right = right - modulus if right >= modulus // 2 else right
    operation = family[1:]
    exact = left + right if operation == "add" else left - right if operation == "sub" else left * right
    lower, upper = (-modulus // 2, modulus // 2 - 1) if signed else (0, modulus - 1)
    return exact % modulus, int(not lower <= exact <= upper)


@lru_cache(maxsize=None)
def pairs(width):
    limit, sign = (1 << width) - 1, 1 << (width - 1)
    if width <= 5:
        result = [(left, right) for left in range(limit + 1) for right in range(limit + 1)]
    else:
        boundary = sorted({value & limit for value in (0, 1, 2, limit, limit - 1, sign, sign - 1, sign + 1, sign - 2)})
        result = [(left, right) for left in boundary for right in boundary]
    # Full i64 inputs also test truncation, sign boundaries and high-bit noise.
    seeds = weak.inputs()
    result += [(value, seeds[(index + width * 7) % len(seeds)]) for index, value in enumerate(seeds)]
    return tuple(dict.fromkeys(result))


def integer_layout(width):
    store_bytes = (width + 7) // 8
    alignment = 1 << (store_bytes - 1).bit_length()
    return store_bytes, alignment, 2 * alignment


def observed(family, width, lhs, rhs):
    value, flag = overflow(family, width, lhs, rhs)
    store_bytes, flag_offset, _ = integer_layout(width)
    bytes_, masks = [0xa5] * STORAGE, [255] * STORAGE
    for byte in range(store_bytes):
        masks[DESTINATION + byte] = min(255, ((1 << width) - 1) >> (8 * byte))
        bytes_[DESTINATION + byte] = (value >> (8 * byte)) & masks[DESTINATION + byte]
    masks[DESTINATION + flag_offset] = 1
    bytes_[DESTINATION + flag_offset] = flag
    return [value ^ (BIAS if flag else 0), *[byte & mask for byte, mask in zip(bytes_, masks)]]


def call_count():
    return 6 * sum(len(pairs(width)) for width in range(1, 65))


@lru_cache(maxsize=None)
def golden():
    digest, count = 0xcbf29ce484222325, 0
    def add(value):
        nonlocal digest, count
        digest = ((digest ^ value) * 0x100000001b3) & MASK
        count += 1
    for value in (MARKER, COLD, 1, 1, 0x55 ^ 111): add(value)
    for width in range(1, 65):
        for left, right in pairs(width):
            for family in FAMILIES:
                for value in observed(family, width, left, right): add(value)
    add(call_count())
    return f"OCORE-INTEGER-OVERFLOW digest={digest:016x} checks={count}\n".encode()


def wrapper(family, width):
    ty = f"i{width}"
    operands = (["  %a = or i64 %lhs, 0", "  %b = or i64 %rhs, 0"] if width == 64 else
                [f"  %a = trunc i64 %lhs to {ty}", f"  %b = trunc i64 %rhs to {ty}"])
    lines = [f"define i64 @overflow_{family}_{width}(ptr %destination, i64 %lhs, i64 %rhs) {{", "entry:", *operands,
             "  %count = load i64, ptr @overflow_counter, align 8", "  %next = add i64 %count, 1",
             "  store i64 %next, ptr @overflow_counter, align 8",
             f"  %pair = call {{ {ty}, i1 }} @llvm.{family}.with.overflow.{ty}({ty} %a, {ty} %b)",
             f"  %result = extractvalue {{ {ty}, i1 }} %pair, 0",
             f"  %flag = extractvalue {{ {ty}, i1 }} %pair, 1",
             f"  %flag_pointer = getelementptr %Ov{width}, ptr %destination, i64 0, i32 1",
             f"  store {ty} %result, ptr %destination, align 1", "  store i1 %flag, ptr %flag_pointer, align 1",
             f"  %loaded = load {ty}, ptr %destination, align 1", "  %loaded_flag = load i1, ptr %flag_pointer, align 1"]
    wide = "%loaded"
    if width < 64:
        lines.append(f"  %wide = zext {ty} %loaded to i64"); wide = "%wide"
    return "\n".join(lines + [f"  %flag_value = select i1 %loaded_flag, i64 {BIAS}, i64 0",
                               f"  %answer = xor i64 {wide}, %flag_value", "  ret i64 %answer", "}"]) + "\n"


def source_text():
    text = "".join(f"%Ov{width} = type {{i{width}, i1}}\n" for width in range(1, 65))
    text += f"@overflow_anchor = global i64 {MARKER}, align 8\n@overflow_cold = constant i64 {COLD}, align 8\n"
    text += "@overflow_counter = global i64 0, align 8\n@overflow_alias = alias i64, ptr @overflow_anchor\n"
    text += "@overflow_address = constant ptr @overflow_alias, align 8\n@overflow_callback = constant ptr @overflow_cold_entry, align 8\n"
    text += "@overflow_cold_entry = alias i64 (i64), ptr @unused_overflow\n"
    text += "define i64 @unused_overflow(i64 %value) { %result = xor i64 %value, 111\n ret i64 %result\n}\n"
    for width in range(1, 65):
        for family in FAMILIES:
            text += f"declare {{i{width}, i1}} @llvm.{family}.with.overflow.i{width}(i{width}, i{width})\n"
            text += wrapper(family, width)
    return text


@lru_cache(maxsize=None)
def carrier():
    reusable = weak.carrier(11); text = reusable[:reusable.index("extern u64 chosen_global")]
    text += "extern u64 overflow_anchor,overflow_cold,overflow_counter,overflow_alias;\nextern u64 *overflow_address;\nextern u64 (*overflow_callback)(u64);\nextern u64 unused_overflow(u64),overflow_cold_entry(u64);\n"
    names = [f"overflow_{family}_{width}" for width in range(1, 65) for family in FAMILIES]
    text += "".join(f"extern u64 {name}(void*,u64,u64);\n" for name in names)
    text += "static u64(*const functions[])(void*,u64,u64)={" + ",".join(names) + "};\n"
    starts, rows = [0], []
    for width in range(1, 65):
        for left, right in pairs(width):
            answers = [overflow(family, width, left, right) for family in FAMILIES]
            rows.append([left, right, *[answer[0] for answer in answers], sum(answer[1] << index for index, answer in enumerate(answers))])
        starts.append(len(rows))
    text += "static const u64 starts[]={" + ",".join(map(str, starts)) + "};\n"
    text += "static const u64 rows[][9]={" + ",\n".join("{" + ",".join(str(value) + "ULL" for value in row) + "}" for row in rows) + "};\n"
    text += """
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected){
#ifdef CORRUPT_ORACLE
 expected^=1;
#endif
 if(got!=expected)return 31;digest=(digest^got)*0x100000001b3ULL;++checks;return 0;}
"""
    text += f"int conformance_main(void){{if(add(overflow_anchor,{MARKER}ULL)||add(overflow_cold,{COLD}ULL))return 31;\n"
    text += "u64 volatile identities[]={(u64)&overflow_anchor,(u64)&overflow_alias,(u64)&unused_overflow,(u64)&overflow_cold_entry};\n"
    text += "if(add(identities[0]==identities[1]&&overflow_address==&overflow_alias,1)||add(identities[2]==identities[3],1)||add(overflow_callback(0x55),0x55^111))return 31;\n"
    text += "for(u64 width=1;width<=64;++width){u64 bytes=(width+7)/8,allocation=1;while(allocation<bytes)allocation*=2;\n"
    text += "for(u64 row=starts[width-1];row<starts[width];++row)for(u64 family=0;family<6;++family){\n"
    text += "unsigned char memory[32] __attribute__((aligned(16)));for(u64 byte=0;byte<32;++byte)memory[byte]=0xa5;\n"
    text += f"u64 flag=(rows[row][8]>>family)&1,value=rows[row][2+family];if(add(functions[(width-1)*6+family](memory+8,rows[row][0],rows[row][1]),value^(flag?{BIAS}ULL:0)))return 31;\n"
    text += "for(u64 byte=0;byte<32;++byte){u64 expected=0xa5,mask=255;if(byte>=8&&byte<8+bytes){u64 shift=8*(byte-8);expected=(value>>shift)&255;if(width-shift<8)mask=(1ULL<<(width-shift))-1;}else if(byte==8+allocation){expected=flag;mask=1;}if(add(memory[byte]&mask,expected&mask))return 31;}}}\n"
    text += f"if(add(overflow_counter,{call_count()}ULL))return 31;\n"
    output = golden().decode().rstrip(); begin = output.index("digest=") + len("digest=")
    text += f"if(checks!={output.split('checks=')[1]})return 37;\nstatic char output[]=\"" + output[:begin] + "0" * 16 + output[begin + 16:] + '\\n";\n'
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


class IntegerOverflowOracleTests(unittest.TestCase):
    def test_unbounded_signed_product_i1_and_64_bit_boundaries(self):
        self.assertEqual(overflow("smul", 1, 1, 1), (1, 1))
        self.assertEqual(overflow("smul", 1, 1, 0), (0, 0))
        self.assertEqual(overflow("sadd", 1, 1, 1), (0, 1))
        self.assertEqual(overflow("ssub", 1, 0, 1), (1, 1))
        self.assertEqual(overflow("umul", 64, MASK, MASK), (1, 1))
        self.assertEqual(overflow("smul", 64, 1 << 63, MASK), (1 << 63, 1))
        self.assertEqual(overflow("smul", 64, MASK, MASK), (1, 0))
        self.assertEqual(overflow("sadd", 64, (1 << 63) - 1, 1), (1 << 63, 1))
        self.assertEqual(overflow("usub", 64, 0, 1), (MASK, 1))
        for width in range(1, 65):
            for family in FAMILIES:
                expected_flags = {0} if width == 1 and family == "umul" else {0, 1}
                self.assertEqual({overflow(family, width, *pair)[1] for pair in pairs(width)}, expected_flags, (family, width))


class IntegerOverflowNativeTests(unittest.TestCase):
    setUpClass = classmethod(weak.WeakNativeTests.setUpClass.__func__)
    command = weak.WeakNativeTests.command
    emulators = census.AllocsizeNativeTests.emulators
    original_inventory = census.AllocsizeNativeTests.original_inventory

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_INTEGER_OVERFLOW_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-integer-overflow-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)
        self.sequence = 0; self.compiler_sha = weak.artifact(self.compiler)["sha256"]
        self.library = importer.LLVM(importer.discover_library(), importer.PINNED_SHA256)

    def original_contract(self, source):
        """Read literal original calls/types/SSA identities using pinned CAPI."""
        a = self.library; data = source.read_bytes(); context = a.ContextCreate()
        buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"integer-overflow-original")
        module, error = importer.P(), importer.P()
        self.assertEqual(a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error)), 0)
        target_data = a.CreateTargetData(a.GetDataLayoutStr(module)); rows, layouts = {}, {}
        get_type = a.lib.LLVMGetTypeByName2; get_type.restype, get_type.argtypes = importer.P, [importer.P, C.c_char_p]
        is_call = a.lib.LLVMIsACallInst; is_call.restype, is_call.argtypes = importer.P, [importer.P]
        try:
            for width in range(1, 65):
                ty = get_type(context, f"Ov{width}".encode()); self.assertTrue(ty)
                fields = (importer.P * 2)(); a.GetStructElementTypes(ty, fields)
                expected = integer_layout(width)
                actual = (int(a.StoreSizeOfType(target_data, fields[0])), int(a.OffsetOfElement(target_data, ty, 1)), int(a.ABISizeOfType(target_data, ty)))
                self.assertEqual(actual, expected)
                layouts[str(width)] = {"integer_store_bytes": actual[0], "flag_offset": actual[1], "tuple_allocation_bytes": actual[2],
                                       "integer_allocation_bytes": int(a.ABISizeOfType(target_data, fields[0])), "alignment": int(a.ABIAlignmentOfType(target_data, ty))}
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                params = (importer.P * a.CountParams(function))(); a.GetParams(function, params)
                instructions = [instruction for block in a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function)
                                for instruction in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block)]
                values = [*params, *[instruction for instruction in instructions if a.GetTypeKind(a.TypeOf(instruction)) != 0]]
                identities = {value: index for index, value in enumerate(values)}; trace = []
                for instruction in instructions:
                    if not is_call(instruction): continue
                    callee = a.GetCalledValue(instruction); name = a.name(callee)
                    self.assertTrue(a.IsAFunction(callee)); pieces = name.split(".")
                    self.assertEqual(pieces[0], "llvm"); self.assertIn(pieces[1], FAMILIES)
                    self.assertEqual(pieces[2:4], ["with", "overflow"])
                    width = int(pieces[4][1:]); self.assertIn(width, range(1, 65))
                    signature = a.GetCalledFunctionType(instruction); result = a.GetReturnType(signature)
                    self.assertEqual(a.CountParamTypes(signature), 2); self.assertEqual(a.GetTypeKind(result), 10)
                    self.assertEqual(a.CountStructElementTypes(result), 2)
                    children = (importer.P * 2)(); a.GetStructElementTypes(result, children)
                    parameters = (importer.P * 2)(); a.GetParamTypes(signature, parameters)
                    self.assertEqual([int(a.GetIntTypeWidth(child)) for child in children], [width, 1])
                    self.assertEqual([int(a.GetIntTypeWidth(parameter)) for parameter in parameters], [width, width])
                    self.assertEqual(int(a.GetInstructionCallConv(instruction)), 0); self.assertFalse(a.IsFunctionVarArg(signature))
                    arguments = [a.GetOperand(instruction, index) for index in range(2)]
                    self.assertEqual(int(a.GetNumArgOperands(instruction)), 2)
                    trace.append({"intrinsic": name, "result_id": identities[instruction], "width": width,
                                  "operation": {"op": "integer_overflow", "kind": pieces[1][1:], "signed": pieces[1][0] == "s",
                                                "lhs": {"kind": "value", "id": identities[arguments[0]]},
                                                "rhs": {"kind": "value", "id": identities[arguments[1]]}}})
                rows[a.name(function)] = trace
        finally:
            a.DisposeTargetData(target_data); a.DisposeModule(module); a.ContextDispose(context)
        return {"layouts": layouts, "call_trace": rows}

    def verify_module(self, source, target, inventory, original):
        ordinary = copy.deepcopy(inventory); ordinary["body_calls"] = {name: [] for name in inventory["functions"]}
        result = census.AllocsizeNativeTests.verify_module(self, source, target, ordinary)
        module = json.loads(Path(result["module"]["path"]).read_text()); functions = {function["name"]: function for function in module["functions"]}
        def shape(ty):
            item = module["types"][ty]
            if item["kind"] == "struct":
                return {"kind": "struct", "fields": [shape(field) for field in item["fields"]], "packed": item["packed"]}
            return item
        for name, trace in original["call_trace"].items():
            actual = [instruction for block in functions[name]["blocks"] for instruction in block["instructions"]
                      if instruction["operation"]["op"] == "integer_overflow"]
            self.assertEqual(len(actual), len(trace))
            for instruction, entry in zip(actual, trace):
                operation = {key: {k: v for k, v in value.items() if k != "ty"} if isinstance(value, dict) else value
                             for key, value in instruction["operation"].items()}
                self.assertEqual(operation, entry["operation"], "literal original intrinsic kind, signedness and exact source operand identities survive")
                self.assertEqual(instruction["result"]["id"], entry["result_id"])
                expected = {"kind": "struct", "fields": [{"kind": "int", "bits": entry["width"]}, {"kind": "int", "bits": 1}], "packed": False}
                self.assertEqual(shape(instruction["result"]["ty"]), expected)
                declaration = functions[entry["intrinsic"]]; signature = declaration["signature"]
                self.assertIsNone(declaration["entry"]); self.assertEqual(shape(signature["result"]), expected)
                self.assertEqual([shape(ty) for ty in signature["params"]], [{"kind": "int", "bits": entry["width"]}] * 2)
                self.assertEqual(signature["abi"], "c"); self.assertFalse(signature["variadic"])
                self.assertFalse(signature["result_attributes"]); self.assertFalse(any(signature["param_attributes"]))
        result["original_intrinsic_contract"] = original
        return result

    def differential(self, own):
        emulators = self.emulators()
        report = {"scope": "six exact LLVM integer overflow families, all widths 1..64, original whole-module conformance",
                  "runtime_complete": False, "compiler_implementation_lowered": False, "kernel_execution_verified": False,
                  "dependency_closure_complete": False, "exception_handling_verified": False, "aggregate_abi_verified": False,
                  "test_source": weak.artifact(__file__), "compiler_sha256": self.compiler_sha, "expected_stdout": golden().decode(),
                  "case_count": call_count(), "families": list(FAMILIES), "widths": list(range(1, 65)),
                  "oracle": "Python arbitrary precision arithmetic; exhaustive input pairs widths 1..5, edges and deterministic full-i64 vectors widths 6..64; signed i1 full multiplication",
                  "memory_policy": "typed iN and i1 scalar stores before same-type loads; only partial integer high bits ignored; allocation padding and outside canaries exact",
                  "tools": {name: weak.artifact(path) for name, path in {"ocorec": self.compiler, "reference_clang": self.sdk / "clang",
                      "llvm-as": self.sdk / "llvm-as", "linker": self.linker, "own_assembler": self.assembler,
                      "llvm_library": importer.discover_library(), **emulators}.items()}, "targets": {}}
        for isa, (target, triple, machine, flags) in TARGETS.items():
            source = self.directory / (isa + "-overflow.ll"); source.write_text(weak.promises.module_text(triple, source_text()))
            binary = source.with_suffix(".bc"); self.command([self.sdk / "llvm-as", source, "-o", binary])
            harness = self.directory / (isa + "-carrier.c"); harness.write_text(carrier()); carriers = {}
            for corrupt in (False, True):
                output = harness.with_suffix(".corrupt.o" if corrupt else ".o")
                argv = [self.sdk / "clang", "--target=" + triple, *flags, "-O1", "-ffreestanding", "-fno-builtin",
                        "-fno-stack-protector", "-fno-pic", "-fno-pie", "-c", harness, "-o", output]
                self.command([*argv, "-DCORRUPT_ORACLE"] if corrupt else argv); carriers[corrupt] = output
            records = []
            for input_ in (source, binary):
                before = input_.read_bytes(); inventory, original = self.original_inventory(input_), self.original_contract(input_)
                self.assertEqual(len(inventory["functions"]), 769); self.assertEqual(len(inventory["definitions"]), 385)
                self.assertEqual(set(inventory["globals"]), {"overflow_anchor", "overflow_cold", "overflow_counter", "overflow_address", "overflow_callback"})
                self.assertEqual(set(inventory["aliases"]), {"overflow_alias", "overflow_cold_entry"})
                self.assertEqual(sum(len(trace) for trace in original["call_trace"].values()), 384)
                self.assertEqual(sum(len(calls) for calls in inventory["body_calls"].values()), 384)
                record = {"input": weak.artifact(input_), "original_inventory": inventory, "original_intrinsic_contract": original, "executions": []}
                if own: record.update(self.verify_module(input_, target, inventory, original))
                for provider in (("original_clang", "own") if own else ("original_clang",)):
                    object_ = input_.with_name(input_.name + (".clang.o" if provider == "original_clang" else ".own.o"))
                    self.command([self.sdk / "clang", "--target=" + triple, *flags, "-O0", "-fno-pic", "-fno-pie", "-c", input_, "-o", object_] if provider == "original_clang" else
                                 [self.compiler, input_, "--input-kind", "llvm-ir", "--target", target, "-o", object_])
                    elf(object_, machine, 1); record[provider + "_object"] = weak.artifact(object_)
                    symbols = weak.elf_symbols(object_)
                    for name in inventory["definitions"]: self.assertGreater(symbols[name]["size"], 0)
                    for control in ("positive", "oracle", "object"):
                        selected, mutation = object_, None
                        if control == "object":
                            selected = object_.with_name(object_.name + ".corrupt"); data = bytearray(object_.read_bytes())
                            symbol = symbols["overflow_cold"]; table = struct.unpack_from("<Q", data, 40)[0]
                            section = struct.unpack_from("<IIQQQQIIQQ", data, table + 64 * symbol["section"]); at = section[4] + symbol["value"]
                            self.assertEqual(data[at], COLD & 255); data[at] ^= 1; selected.write_bytes(data)
                            mutation = {"symbol": "overflow_cold", "file_offset": at, "object": weak.artifact(selected)}
                        executable = input_.with_name(input_.name + "-" + provider + "-" + control)
                        self.command([self.sdk / "clang", "--target=" + triple, *flags, "--ld-path=" + self.linker,
                                      "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-e,_start", carriers[control == "oracle"], selected, "-o", executable])
                        elf(executable, machine, 2)
                        result = self.command([executable] if isa == "x86_64" else [emulators[isa], executable], success=control == "positive")
                        self.assertEqual(result.returncode, 0 if control == "positive" else 31)
                        self.assertEqual(result.stdout, golden() if control == "positive" else b"")
                        record["executions"].append({"provider": provider, "control": control, "exit_code": result.returncode,
                            "stdout": result.stdout.decode(), "executable": weak.artifact(executable), "mutation": mutation})
                self.assertEqual(input_.read_bytes(), before); records.append(record)
            report["targets"][isa] = {"profile": {"triple": triple, "flags": flags, "abi": "lp64" if isa == "riscv64" else "target fixed integer C"},
                                      "carrier_source": weak.artifact(harness), "carrier_object": weak.artifact(carriers[False]),
                                      "corrupt_oracle_object": weak.artifact(carriers[True]), "modules": records}
        self.assertEqual(weak.artifact(self.compiler)["sha256"], self.compiler_sha)
        receipt = self.directory / ("integer-overflow-own-conformance.json" if own else "integer-overflow-original-clang-oracle.json")
        receipt.write_text(json.dumps(report, indent=2) + "\n")
        print(("Own/reference" if own else "Original LLVM") + " integer overflow all three: " + golden().decode().strip(), flush=True)

    def test_original_llvm_all_six_families_all_64_widths_ll_bc_against_unbounded_oracle(self):
        self.differential(False)

    def test_owned_lowering_all_six_families_all_64_widths_ll_bc_preserves_calls_and_memory(self):
        if os.environ.get("OCORE_TEST_INTEGER_OVERFLOW_REFERENCE_ONLY") == "1":
            self.skipTest("explicit reference-only phase; own overflow-enabled compiler qualification is separate")
        self.differential(True)


if __name__ == "__main__": unittest.main()
