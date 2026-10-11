"""Runtime aggregate select and odd-width memory against original LLVM objects.

Complete unchanged ll/bc units execute under Linux test carriers on each ISA.
Padding is deliberately unobserved; defined integer bits, pointer identity,
original DataLayout strides, input bytes, and outside canaries are checked.
This supplement does not broaden the prior SSA receipt into an engine proof.
"""

import ctypes as C
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


MASK, MARKER = weak.MASK, 0x123456789abcdef0
COLD, STORAGE, INPUT_BYTES = 0x1122334455667788, 512, 128
SEEDS, CONDITIONS, ROUNDS = tuple(weak.inputs()), (0, 1, 2, 1 << 63, MASK), (0, 1, 2, 7)
WIDTHS = (1, 21, 33, 40, 63, 63)
PATHS = ((0,), (1,), (2, 0), (2, 1), (3, 0), (3, 1))
LAYOUTS = {"Packed": (45, 1, (0, 1, 5, 13, 21, 29, 37)),
           "Natural": (48, 8, (0, 4, 8, 16, 24, 32, 40))}


def values(seed, row):
    return [((seed >> ((index * 7) % 64)) ^ (0x1020304050607081 * (row + 1) + index * 17)) &
            ((1 << bits) - 1) for index, bits in enumerate(WIDTHS)]


def model(seed, condition, rounds, ty):
    size, _, offsets = LAYOUTS[ty]
    left, right = values(seed, 0), values(seed, 1)
    left[5] = (seed ^ 0x789abcdef0123456) & ((1 << 63) - 1)
    right[3] = ((seed >> 21) ^ 0x123456789a) & ((1 << 40) - 1)
    left_pointer, right_pointer = 1, 2
    for _ in range(rounds):
        left, right = right, left
        left_pointer, right_pointer = right_pointer, left_pointer
    selected, other = (left, right) if condition else (right, left)
    selected_pointer, other_pointer = (left_pointer, right_pointer) if condition else (right_pointer, left_pointer)
    bytes_, masks, pointers = [0xa5] * STORAGE, [255] * STORAGE, []
    def store(at, fields, pointer):
        for byte in range(size): masks[at + byte] = 0
        for value, bits, offset in zip(fields, WIDTHS, offsets):
            for byte in range((bits + 7) // 8):
                bitmask = min(255, (1 << max(0, bits - 8 * byte)) - 1)
                masks[at + offset + byte] = bitmask
                bytes_[at + offset + byte] = (value >> (8 * byte)) & bitmask
        pointers.append((at + offsets[6], pointer))
    store(0, selected, selected_pointer); store(128, other, other_pointer)
    store(256, [0] * 6, 0); store(320, selected, selected_pointer); store(320 + size, other, other_pointer)
    signed = selected[1] - (1 << 21) if selected[1] & (1 << 20) else selected[1]
    result = seed ^ (signed & MASK) ^ other[2]
    for value in selected: result ^= value
    input_ = [0xa5] * INPUT_BYTES
    input_masks = [255] * INPUT_BYTES
    input_pointers = []
    for row in (0, 1):
        for value, bits, offset in zip(values(seed, row), WIDTHS, offsets):
            for byte in range((bits + 7) // 8):
                input_[row * size + offset + byte] = (value >> (8 * byte)) & 255
                input_masks[row * size + offset + byte] = min(255, (1 << max(0, bits - 8 * byte)) - 1)
        input_pointers.append((row * size + offsets[6], row + 1))
        for byte in range(8): input_masks[row * size + offsets[6] + byte] = 0
    observed = [result, *[bytes_[at] & masks[at] for at in range(STORAGE) if masks[at]],
                *([1] * len(pointers)), *([0xa5] * 32),
                *[byte & input_masks[at] for at, byte in enumerate(input_) if input_masks[at]],
                *([1] * len(input_pointers))]
    return bytes_, masks, pointers, result, input_, input_pointers, input_masks, observed


def golden():
    observed = [MARKER, COLD, 1]
    for seed in SEEDS:
        for condition in CONDITIONS:
            for rounds in ROUNDS:
                for ty in LAYOUTS: observed += model(seed, condition, rounds, ty)[7]
    digest = 0xcbf29ce484222325
    for value in observed: digest = ((digest ^ value) * 0x100000001b3) & MASK
    return f"OCORE-AGGREGATE-EDGES digest={digest:016x} checks={len(observed)}\n".encode()


def function(ty):
    alignment = LAYOUTS[ty][1]
    lines = [f"define i64 @edge_{ty.lower()}(ptr %input, ptr %output, i64 %seed, i64 %condition, i64 %rounds) {{", "entry:"]
    # LLVM non-byte integer loads require preceding writes with the same
    # integer type. C byte initialization alone does not establish that
    # contract. The original LLVM unit performs these typed scalar stores
    # before the tested aggregate loads; only unspecified padding bits are
    # excluded from the independent input byte oracle.
    for row in (0, 1):
        for index, (path, bits) in enumerate(zip(PATHS, WIDTHS)):
            stem = f"initialize_{row}_{index}"
            indices = ", ".join(["i64 0", f"i64 {row}", *[f"i32 {field}" for field in path]])
            lines += [f"  %{stem}_shift = lshr i64 %seed, {(index * 7) % 64}",
                      f"  %{stem}_bits = xor i64 %{stem}_shift, {(0x1020304050607081 * (row + 1) + index * 17) & MASK}",
                      f"  %{stem}_value = trunc i64 %{stem}_bits to i{bits}",
                      f"  %{stem}_pointer = getelementptr [2 x %{ty}], ptr %input, {indices}",
                      f"  store i{bits} %{stem}_value, ptr %{stem}_pointer, align 1"]
        pointer = "@anchor_alias" if row == 0 else "@cold_marker"
        lines += [f"  %initialize_pointer_{row} = getelementptr [2 x %{ty}], ptr %input, i64 0, i64 {row}, i32 4",
                  f"  store ptr {pointer}, ptr %initialize_pointer_{row}, align 1"]
    lines += [
             f"  %left_input = load %{ty}, ptr %input, align {alignment}",
             f"  %right_pointer = getelementptr [2 x %{ty}], ptr %input, i64 0, i64 1",
             f"  %right_input = load %{ty}, ptr %right_pointer, align {alignment}",
             "  %left_bits = xor i64 %seed, 8690466096661279830", "  %left_narrow = trunc i64 %left_bits to i63",
             f"  %left = insertvalue %{ty} %left_input, i63 %left_narrow, 3, 1",
             "  %right_shift = lshr i64 %seed, 21", "  %right_bits = xor i64 %right_shift, 78187493530",
             "  %right_narrow = trunc i64 %right_bits to i40",
             f"  %right = insertvalue %{ty} %right_input, i40 %right_narrow, 2, 1", "  br label %loop", "loop:",
             f"  %a = phi %{ty} [%left, %entry], [%b, %swap]",
             f"  %b = phi %{ty} [%right, %entry], [%a, %swap]",
             "  %index = phi i64 [0, %entry], [%next, %swap]", "  %done = icmp eq i64 %index, %rounds",
             "  br i1 %done, label %select, label %swap", "swap:", "  %next = add i64 %index, 1", "  br label %loop", "select:",
             "  %flag = icmp ne i64 %condition, 0",
             f"  %selected = select i1 %flag, %{ty} %a, %{ty} %b",
             f"  %other = select i1 %flag, %{ty} %b, %{ty} %a",
             f"  store %{ty} %selected, ptr %output, align {alignment}",
             "  %other_output = getelementptr i8, ptr %output, i64 128",
             f"  store %{ty} %other, ptr %other_output, align {alignment}",
             "  %zero_output = getelementptr i8, ptr %output, i64 256",
             f"  store %{ty} zeroinitializer, ptr %zero_output, align {alignment}",
             "  %array_output = getelementptr i8, ptr %output, i64 320",
             f"  %array_next = getelementptr [2 x %{ty}], ptr %array_output, i64 0, i64 1",
             f"  store %{ty} %selected, ptr %array_output, align {alignment}",
             f"  store %{ty} %other, ptr %array_next, align {alignment}",
             f"  %signed21 = extractvalue %{ty} %selected, 1", "  %signed = sext i21 %signed21 to i64",
             f"  %other33 = extractvalue %{ty} %other, 2, 0", "  %wide_other = zext i33 %other33 to i64",
             "  %start = xor i64 %seed, %signed", "  %initial = xor i64 %start, %wide_other"]
    previous = "%initial"
    for index, (path, bits) in enumerate(zip(PATHS, WIDTHS)):
        lines += [f"  %field{index} = extractvalue %{ty} %selected, " + ", ".join(map(str, path)),
                  f"  %wide{index} = zext i{bits} %field{index} to i64",
                  f"  %fold{index} = xor i64 {previous}, %wide{index}"]
        previous = "%fold" + str(index)
    return "\n".join(lines + [f"  ret i64 {previous}", "}"]) + "\n"


def source_text():
    text = "%Packed = type <{i1, i21, {i33, i40}, [2 x i63], ptr}>\n%Natural = type {i1, i21, {i33, i40}, [2 x i63], ptr}\n"
    text += f"@anchor = global i64 {MARKER}, align 8\n@anchor_alias = alias i64, ptr @anchor\n@cold_marker = constant i64 {COLD}, align 8\n"
    text += "@cold_native = constant %Natural {i1 true, i21 2097151, {i33, i40} {i33 8589934591, i40 1099511627775}, [2 x i63] [i63 9223372036854775807, i63 17], ptr @anchor_alias}, align 8\n"
    text += "define i64 @unused_edge(i64 %x) { %y=xor i64 %x, 51\n ret i64 %y\n}\n"
    return text + "".join(function(ty) for ty in LAYOUTS)


def carrier():
    reusable = weak.carrier(11); text = reusable[:reusable.index("extern u64 chosen_global")]
    text += "extern u64 anchor,anchor_alias,cold_marker;\nextern u64 edge_packed(void*,void*,u64,u64,u64),edge_natural(void*,void*,u64,u64,u64);\n"
    text += "static u64(*const functions[])(void*,void*,u64,u64,u64)={edge_packed,edge_natural};\n"
    rows, models, input_images = [], [], []
    for seed in SEEDS:
        for condition in CONDITIONS:
            for rounds in ROUNDS:
                for index, ty in enumerate(LAYOUTS):
                    value = model(seed, condition, rounds, ty)
                    image = value[:4]
                    if image not in models: models.append(image)
                    if value[4] not in input_images: input_images.append(value[4])
                    rows.append((seed, condition, rounds, index, models.index(image), input_images.index(value[4])))
    text += "static const u64 rows[][6]={" + ",\n".join("{" + ",".join(str(value) + "ULL" for value in row) + "}" for row in rows) + "};\n"
    for name, images in (("expected", [model[0] for model in models]), ("inputs", input_images)):
        text += f"static const unsigned char {name}[][{len(images[0])}]={{" + ",\n".join("{" + ",".join(map(str, image)) + "}" for image in images) + "};\n"
    text += "static const unsigned char masks[][512]={" + ",\n".join("{" + ",".join(map(str, model[1])) + "}" for model in models) + "};\n"
    text += "static const unsigned short pointer_offsets[][5]={" + ",\n".join("{" + ",".join(str(at) for at, _ in model[2]) + "}" for model in models) + "};\n"
    text += "static const unsigned char pointer_targets[][5]={" + ",\n".join("{" + ",".join(str(target) for _, target in model[2]) + "}" for model in models) + "};\n"
    text += "static const u64 scalar_expected[]={" + ",".join(str(model[3]) + "ULL" for model in models) + "};\n"
    text += "static const unsigned char input_pointer_offsets[][2]={{37,82},{40,88}};\n"
    text += "static const unsigned char input_masks[][128]={" + ",\n".join("{" + ",".join(map(str, model(0, 0, 0, ty)[6])) + "}" for ty in LAYOUTS) + "};\n"
    text += """
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 wanted){
#ifdef CORRUPT_ORACLE
 wanted^=1;
#endif
 if(got!=wanted)return 31;digest=(digest^got)*0x100000001b3ULL;++checks;return 0;}
static u64 get64(const unsigned char*p){u64 value=0;for(u64 i=0;i<8;++i)value|=(u64)p[i]<<(8*i);return value;}
static void put64(unsigned char*p,u64 value){for(u64 i=0;i<8;++i)p[i]=(unsigned char)(value>>(8*i));}
static u64 target(u64 kind){return kind==1?(u64)&anchor_alias:kind==2?(u64)&cold_marker:0;}
"""
    text += f"int conformance_main(void){{if(add(anchor,{MARKER}ULL)||add(cold_marker,{COLD}ULL))return 31;\n"
    text += "u64 volatile addresses[]={(u64)&anchor,(u64)&anchor_alias};if(add(addresses[0]==addresses[1],1))return 31;\n"
    text += "for(u64 row=0;row<sizeof(rows)/sizeof(rows[0]);++row){\nunsigned char input[128] __attribute__((aligned(16))),output[544] __attribute__((aligned(16)));\n"
    text += "u64 ty=rows[row][3],model=rows[row][4],image=rows[row][5];for(u64 i=0;i<128;++i)input[i]=inputs[image][i];for(u64 i=0;i<544;++i)output[i]=0xa5;\n"
    text += "for(u64 i=0;i<2;++i)put64(input+input_pointer_offsets[ty][i],target(i+1));\n"
    text += "if(add(functions[ty](input,output+16,rows[row][0],rows[row][1],rows[row][2]),scalar_expected[model]))return 31;\n"
    text += "for(u64 i=0;i<512;++i)if(masks[model][i]&&add(output[16+i]&masks[model][i],expected[model][i]&masks[model][i]))return 31;\n"
    text += "for(u64 i=0;i<5;++i)if(add(get64(output+16+pointer_offsets[model][i])==target(pointer_targets[model][i]),1))return 31;\n"
    text += "for(u64 i=0;i<16;++i)if(add(output[i],0xa5)||add(output[528+i],0xa5))return 31;\n"
    text += "for(u64 i=0;i<128;++i)if(input_masks[ty][i]&&add(input[i]&input_masks[ty][i],inputs[image][i]&input_masks[ty][i]))return 31;\n"
    text += "for(u64 i=0;i<2;++i)if(add(get64(input+input_pointer_offsets[ty][i])==target(i+1),1))return 31;}\n"
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


class AggregateEdgesNativeTests(unittest.TestCase):
    setUpClass = classmethod(weak.WeakNativeTests.setUpClass.__func__)
    command = weak.WeakNativeTests.command
    emulators = census.AllocsizeNativeTests.emulators
    original_inventory = census.AllocsizeNativeTests.original_inventory
    verify_module = census.AllocsizeNativeTests.verify_module

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_AGGREGATE_EDGES_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-aggregate-edges-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)
        self.sequence = 0; self.compiler_sha = weak.artifact(self.compiler)["sha256"]
        self.library = importer.LLVM(importer.discover_library(), importer.PINNED_SHA256)

    def original_layouts(self, source):
        a = self.library; data = source.read_bytes(); context = a.ContextCreate()
        buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"aggregate-edges-original-layout")
        module, error = importer.P(), importer.P(); self.assertEqual(a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error)), 0)
        target_data = a.CreateTargetData(a.GetDataLayoutStr(module))
        get_type = a.lib.LLVMGetTypeByName2; get_type.restype, get_type.argtypes = importer.P, [importer.P, C.c_char_p]
        rows = {}
        try:
            for name, (size, alignment, offsets) in LAYOUTS.items():
                ty = get_type(context, name.encode()); self.assertTrue(ty)
                children = (importer.P * a.CountStructElementTypes(ty))(); a.GetStructElementTypes(ty, children)
                top = [int(a.OffsetOfElement(target_data, ty, i)) for i in range(5)]
                inner = children[2]
                actual = (int(a.ABISizeOfType(target_data, ty)), int(a.ABIAlignmentOfType(target_data, ty)),
                          (top[0], top[1], top[2] + int(a.OffsetOfElement(target_data, inner, 0)),
                           top[2] + int(a.OffsetOfElement(target_data, inner, 1)), top[3], top[3] + 8, top[4]))
                self.assertEqual(actual, (size, alignment, offsets)); rows[name] = {"allocation_size": size, "alignment": alignment, "leaf_offsets": offsets}
                # Array stride is the allocation extent, not the sum of scalar
                # store bytes; i21/i33/i40 must retain their original padding.
                self.assertEqual(int(a.ABISizeOfType(target_data, children[1])), 4)
                self.assertEqual(int(a.ABISizeOfType(target_data, a.GetElementType(children[3]))), 8)
        finally:
            a.DisposeTargetData(target_data); a.DisposeModule(module); a.ContextDispose(context)
        return rows

    def differential(self):
        emulators = self.emulators()
        report = {"scope": "original LLVM runtime aggregate select and odd-width SSA/memory supplement",
                  "runtime_complete": False, "compiler_implementation_lowered": False, "aggregate_abi_verified": False,
                  "kernel_execution_verified": False, "dependency_closure_complete": False, "exception_handling_verified": False,
                  "compiler_sha256": self.compiler_sha, "test_source": weak.artifact(__file__), "expected_stdout": golden().decode(),
                  "padding_policy": "original LLVM typed leaf stores initialize non-byte integers; aggregate and partial integer-byte padding unobserved; allocation padding and outside canaries exact",
                  "tools": {name: weak.artifact(path) for name, path in {"ocorec": self.compiler, "reference_clang": self.sdk / "clang",
                      "llvm-as": self.sdk / "llvm-as", "linker": self.linker, "own_assembler": self.assembler,
                      "llvm_library": importer.discover_library(), **emulators}.items()}, "targets": {}}
        for isa, (target, triple, machine, flags) in TARGETS.items():
            source = self.directory / (isa + "-edges.ll"); source.write_text(weak.promises.module_text(triple, source_text()))
            binary = source.with_suffix(".bc"); self.command([self.sdk / "llvm-as", source, "-o", binary])
            harness = self.directory / (isa + "-carrier.c"); harness.write_text(carrier())
            carriers = {}
            for corrupt in (False, True):
                output = harness.with_suffix(".corrupt.o" if corrupt else ".o")
                argv = [self.sdk / "clang", "--target=" + triple, *flags, "-O1", "-ffreestanding", "-fno-builtin",
                        "-fno-stack-protector", "-fno-pic", "-fno-pie", "-c", harness, "-o", output]
                self.command([*argv, "-DCORRUPT_ORACLE"] if corrupt else argv); carriers[corrupt] = output
            records = []
            for input_ in (source, binary):
                original = input_.read_bytes(); inventory = self.original_inventory(input_)
                record = {"input": weak.artifact(input_), "original_inventory": inventory, "original_layouts": self.original_layouts(input_), "executions": []}
                self.assertEqual(set(inventory["definitions"]), {"unused_edge", "edge_packed", "edge_natural"})
                self.assertEqual(set(inventory["globals"]), {"anchor", "cold_marker", "cold_native"})
                record.update(self.verify_module(input_, target, inventory))
                module = json.loads(Path(record["module"]["path"]).read_text())
                ops = [i["operation"] for f in module["functions"] for b in f["blocks"] for i in b["instructions"]]
                self.assertEqual(sum(op["op"] == "select" for op in ops), 4)
                self.assertEqual(sum(op["op"] == "phi" for op in ops), 6)
                for provider in ("original_clang", "own"):
                    object_ = input_.with_name(input_.name + (".clang.o" if provider == "original_clang" else ".own.o"))
                    self.command([self.sdk / "clang", "--target=" + triple, *flags, "-O0", "-fno-pic", "-fno-pie", "-c", input_, "-o", object_] if provider == "original_clang" else
                                 [self.compiler, input_, "--input-kind", "llvm-ir", "--target", target, "-o", object_])
                    elf(object_, machine, 1); record[provider + "_object"] = weak.artifact(object_)
                    for name in inventory["definitions"]: self.assertGreater(weak.elf_symbols(object_)[name]["size"], 0)
                    for control in ("positive", "oracle", "object"):
                        selected, mutation = object_, None
                        if control == "object":
                            selected = object_.with_name(object_.name + ".corrupt"); data = bytearray(object_.read_bytes())
                            symbol = weak.elf_symbols(object_)["cold_marker"]; table = struct.unpack_from("<Q", data, 40)[0]
                            section = struct.unpack_from("<IIQQQQIIQQ", data, table + 64 * symbol["section"]); at = section[4] + symbol["value"]
                            self.assertEqual(data[at], COLD & 255); data[at] ^= 1; selected.write_bytes(data)
                            mutation = {"symbol": "cold_marker", "file_offset": at, "object": weak.artifact(selected)}
                        executable = input_.with_name(input_.name + "-" + provider + "-" + control)
                        self.command([self.sdk / "clang", "--target=" + triple, *flags, "--ld-path=" + self.linker,
                                      "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-e,_start", carriers[control == "oracle"], selected, "-o", executable])
                        elf(executable, machine, 2)
                        result = self.command([executable] if isa == "x86_64" else [emulators[isa], executable], success=control == "positive")
                        self.assertEqual(result.returncode, 0 if control == "positive" else 31); self.assertEqual(result.stdout, golden() if control == "positive" else b"")
                        record["executions"].append({"provider": provider, "control": control, "exit_code": result.returncode,
                            "stdout": result.stdout.decode(), "executable": weak.artifact(executable), "mutation": mutation})
                self.assertEqual(input_.read_bytes(), original); records.append(record)
            report["targets"][isa] = {"profile": {"triple": triple, "flags": flags}, "carrier_source": weak.artifact(harness),
                                      "carrier_object": weak.artifact(carriers[False]), "modules": records}
        self.assertEqual(weak.artifact(self.compiler)["sha256"], self.compiler_sha)
        (self.directory / "aggregate-edges-conformance.json").write_text(json.dumps(report, indent=2) + "\n")
        print("Own/reference aggregate edges all three: " + golden().decode().strip(), flush=True)

    def test_original_llvm_runtime_select_odd_widths_packed_nested_arrays_phi_ll_bc_all_three(self):
        self.differential()


if __name__ == "__main__": unittest.main()
