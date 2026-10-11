"""Original LLVM relative tables through real objects on all three ISAs.

These authored whole units qualify bounded static relative-address lowering on
Linux/QEMU carriers. Original Clang is an independent native reference; the
Python/C oracle checks identities, bytes and callbacks without implementing the
emitter. No upstream engine, provider closure, OSTADIX or JIT claim follows.
"""

import json
import os
from pathlib import Path
import platform
import shutil
import struct
import tempfile
import unittest

from scripts.check_ocore_native_equivalence import TARGETS, elf
from tests import test_ocore_native_weak as weak


ROOT, MASK = weak.ROOT, weak.MASK
TABLES = (("rel_private", 0), ("rel_internal", 4))
SHIFTS = (0, 4, 8, 12)
DATA = {name: tuple((factor * index + salt) & 255 for index in range(128))
        for name, factor, salt in (("private_data", 17, 3), ("internal_data", 29, 7),
                                  ("exported_data", 37, 11), ("external_data", 41, 19))}
COLD = (23, 59, 101, 167, 211, 251, 43)
# The base is always the entire containing local global. Addends belong to the
# target; interior table storage offsets do not silently change that base.
ENTRIES = (("private_data", 0), ("internal_data", 7), ("exported_data_alias", 31),
           ("external_data", 17), ("exported_function_alias", 0),
           ("external_function", 0), ("private_function", 0), (None, 0),
           ("private_data", -4))
CALLBACKS = ((0x123456789ABCDEF0, 17), (0x8877665544332211, 29), (0xFEDCBA9876543210, 43))


def relative_constant(target, base, addend):
    address = f"@{target}" if not addend else f"getelementptr (i8, ptr @{target}, i64 {addend})"
    return (f"i32 trunc (i64 sub (i64 ptrtoint (ptr {address} to i64), "
            f"i64 ptrtoint (ptr @{base} to i64)) to i32)")


def module_body():
    lines = []
    for name in ("private_data", "internal_data", "exported_data"):
        linkage = "private " if name == "private_data" else "internal " if name == "internal_data" else ""
        storage = "constant" if name != "exported_data" else "global"
        values = ", ".join(f"i8 {value}" for value in DATA[name])
        lines.append(f"@{name} = {linkage}{storage} [128 x i8] [{values}], align 16")
    lines += ["@exported_data_alias = alias [128 x i8], ptr @exported_data",
              "@external_data = external global [128 x i8]",
              "@cold_bytes = constant [7 x i8] [" + ", ".join(f"i8 {v}" for v in COLD) + "], align 1"]
    for table, prefix in TABLES:
        values = ", ".join(relative_constant(target or table, table, addend) for target, addend in ENTRIES)
        if prefix:
            lines.append(f"@{table} = internal constant <{{ [4 x i8], [9 x i32], i32 }}> "
                         f"<{{ [4 x i8] [i8 71, i8 83, i8 97, i8 109], [9 x i32] [{values}], i32 305419896 }}>, align 4")
        else:
            lines.append(f"@{table} = private constant [9 x i32] [{values}], align 4")
    lines += ["@exported_function_alias = alias i64 (i64), ptr @exported_function",
              "declare i64 @external_function(i64)",
              "declare ptr @llvm.load.relative.i32(ptr, i32) nounwind memory(argmem: read)",
              "declare ptr @llvm.load.relative.i64(ptr, i64) nounwind memory(argmem: read)"]
    for name in ("private_data", "internal_data", "private_function", *[table for table, _ in TABLES]):
        lines.append(f"define ptr @address_{name}() {{ ret ptr @{name} }}")
    for name, (salt, increment), linkage in (("exported_function", CALLBACKS[0], ""),
                                           ("private_function", CALLBACKS[2], "private ")):
        lines.append(f"define {linkage}i64 @{name}(i64 %seed) {{\n"
                     f"  %mixed = xor i64 %seed, {salt}\n  %result = add i64 %mixed, {increment}\n  ret i64 %result\n}}")
    for width in (32, 64):
        offset = "%offset"
        conversion = ""
        if width == 32:
            conversion, offset = "  %narrow = trunc i64 %offset to i32\n", "%narrow"
        lines.append(f"define ptr @relative_read{width}(ptr %base, i64 %offset) {{\n{conversion}"
                     f"  %result = call ptr @llvm.load.relative.i{width}(ptr %base, i{width} {offset})\n"
                     "  ret ptr %result\n}")
        lines.append(f"define i64 @relative_dispatch{width}(ptr %base, i64 %offset, i64 %seed) {{\n{conversion}"
                     f"  %callee = call ptr @llvm.load.relative.i{width}(ptr %base, i{width} {offset})\n"
                     "  %result = call i64 %callee(i64 %seed)\n  ret i64 %result\n}")
    lines.append("define i64 @cold_function() { ret i64 123456789 }")
    return "\n".join(lines) + "\n"


def golden():
    values = []
    for data in DATA.values():
        values.extend(data)
    values.extend(COLD)
    values.append(123456789)
    for _, prefix in TABLES:
        if prefix:
            values.extend((71, 83, 97, 109, 0x12345678))
        for index, (_, addend) in enumerate(ENTRIES):
            values.extend((0, 1))  # raw low32 difference and signed reconstruction
            for shift in SHIFTS:
                for _ in range(3):  # i32, noisy upper i32 carrier, i64
                    values.append(1)
                    if index in (0, 1, 2, 3) or index == 8 and shift >= 4:
                        name = ("private_data", "internal_data", "exported_data", "external_data")[index] if index < 4 else "private_data"
                        values.append(DATA[name][addend + shift])
                if index in (4, 5, 6) and shift == 0:
                    salt, increment = CALLBACKS[index - 4]
                    for seed in weak.inputs():
                        result = ((seed ^ salt) + increment) & MASK
                        values.extend((result, result, result, result))
    digest = 0xCBF29CE484222325
    for value in values:
        digest = ((digest ^ value) * 0x100000001B3) & MASK
    return f"OCORE-RELATIVE32 digest={digest:016x} checks={len(values)}\n".encode()


def carrier():
    reusable = weak.carrier(11)
    text = reusable[:reusable.index("extern u64 chosen_global")]
    text += "typedef u64 (*callback)(u64);\n"
    # Clang may initialize carrier-local arrays with these C library helpers.
    # They are explicit test-platform providers, not lowered runtime claims.
    text += "__attribute__((noinline)) void *memset(void *p,int value,u64 n){volatile unsigned char *d=p;for(u64 i=0;i<n;++i)d[i]=(unsigned char)value;return p;}\n"
    text += "__attribute__((noinline)) void *memcpy(void *p,const void *s,u64 n){volatile unsigned char *d=p;const volatile unsigned char *a=s;for(u64 i=0;i<n;++i)d[i]=a[i];return p;}\n"
    text += "extern unsigned char exported_data[],exported_data_alias[],cold_bytes[];\n"
    text += "unsigned char external_data[128]={" + ",".join(str(v) for v in DATA["external_data"]) + "};\n"
    text += "__attribute__((noinline)) u64 external_function(u64 seed){return (seed^0x8877665544332211ULL)+29;}\n"
    text += "extern u64 exported_function(u64),exported_function_alias(u64),cold_function(void);\n"
    text += "extern void *address_private_data(void),*address_internal_data(void),*address_private_function(void),*address_rel_private(void),*address_rel_internal(void);\n"
    text += "extern void *relative_read32(void*,u64),*relative_read64(void*,u64);\n"
    text += "extern u64 relative_dispatch32(void*,u64,u64),relative_dispatch64(void*,u64,u64);\n"
    text += r"""
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected){
#ifdef CORRUPT_ORACLE
 expected^=1;
#endif
 if(got!=expected)return 31;
 digest=(digest^got)*0x100000001b3ULL;++checks;return 0;
}
static u64 little32(const unsigned char *p){return (u64)p[0]|((u64)p[1]<<8)|((u64)p[2]<<16)|((u64)p[3]<<24);}
int conformance_main(void){
 unsigned char *data[]={address_private_data(),address_internal_data(),exported_data,external_data};
 const u64 factors[]={17,29,37,41},salts[]={3,7,11,19};
 for(u64 k=0;k<4;++k)for(u64 j=0;j<128;++j)if(add(data[k][j],(factors[k]*j+salts[k])&255))return 31;
 const unsigned char cold[]={23,59,101,167,211,251,43};
 for(u64 j=0;j<7;++j)if(add(cold_bytes[j],cold[j]))return 31;
 if(add(cold_function(),123456789))return 31;
 unsigned char *tables[]={address_rel_private(),address_rel_internal()};
 const u64 prefixes[]={0,4},addends[]={0,7,31,17,0,0,0,0,~3ULL};
 u64 targets[]={(u64)data[0],(u64)data[1],(u64)exported_data_alias,(u64)external_data,
                (u64)exported_function_alias,(u64)external_function,(u64)address_private_function(),0,(u64)data[0]};
 const u64 callback_salts[]={0x123456789abcdef0ULL,0x8877665544332211ULL,0xfedcba9876543210ULL};
 const u64 increments[]={17,29,43};
 for(u64 t=0;t<2;++t){
  u64 base=(u64)tables[t];
  if(t){const unsigned char prefix[]={71,83,97,109};for(u64 j=0;j<4;++j)if(add(tables[t][j],prefix[j]))return 31;
   if(add(little32(tables[t]+40),0x12345678))return 31;}
  for(u64 i=0;i<9;++i){
   u64 target=(i==7?base:targets[i])+addends[i],raw=little32(tables[t]+prefixes[t]+4*i);
   if(add(raw^((target-base)&0xffffffffULL),0))return 31;
   u64 signed_raw=(raw&0x80000000ULL)?raw+0xffffffff00000000ULL:raw;
   if(add(base+signed_raw==target,1))return 31;
   for(u64 shift=0;shift<=12;shift+=4){
    /* All loads remain within the owning table. The shifted base makes
       negative source offsets observable without any invalid dereference. */
    u64 offset=prefixes[t]+4*i-shift;void *shifted=(void*)(base+shift);
    void *resolved[]={relative_read32(shifted,offset),relative_read32(shifted,offset^0xa5c37e1900000000ULL),relative_read64(shifted,offset)};
    for(u64 k=0;k<3;++k){
     if(add((u64)resolved[k]==target+shift,1))return 31;
     if(i<4 || (i==8 && shift>=4)){
      u64 d=i<4?i:0,at=addends[i]+shift;
      if(add(*(unsigned char*)resolved[k],(factors[d]*at+salts[d])&255))return 31;
     }
    }
    if(i>=4 && i<=6 && shift==0){
     for(u64 j=0;j<sizeof(values)/sizeof(values[0]);++j){u64 seed=values[j],expected=(seed^callback_salts[i-4])+increments[i-4];
      if(add(((callback)resolved[0])(seed),expected)||add(((callback)resolved[2])(seed),expected)||
         add(relative_dispatch32(shifted,offset,seed),expected)||add(relative_dispatch64(shifted,offset,seed),expected))return 31;
     }
    }
   }
  }
 }
"""
    output = golden().decode().rstrip()
    count = int(output.split("checks=")[1])
    start = output.index("digest=") + len("digest=")
    text += f"if(checks!={count})return 37;\n"
    text += 'static char output[]="' + output[:start] + "0" * 16 + output[start+16:] + '\\n";\n'
    text += f"for(u64 i=0;i<16;++i){{u64 n=(digest>>(60-4*i))&15;output[{start}+i]=(char)(n<10?'0'+n:'a'+n-10);}}\n"
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


class Elf64:
    """Small independent ELF64 container retaining paired RELA records."""

    def __init__(self, path):
        self.data = bytearray(Path(path).read_bytes())
        if self.data[:6] != b"\x7fELF\x02\x01":
            raise AssertionError("expected little-endian ELF64")
        at = struct.unpack_from("<Q", self.data, 40)[0]
        stride, count = struct.unpack_from("<HH", self.data, 58)
        if stride != 64 or at + count * stride > len(self.data):
            raise AssertionError("invalid section inventory")
        self.sections = [struct.unpack_from("<IIQQQQIIQQ", self.data, at + i * stride) for i in range(count)]
        self.symbols, tables = {}, {}
        for index, section in enumerate(self.sections):
            if section[1] != 2:
                continue
            if section[9] != 24 or section[5] % 24:
                raise AssertionError("invalid symbol table")
            strings = self.sections[section[6]]
            names = self.data[strings[4]:strings[4] + strings[5]]
            records = []
            for pos in range(section[4], section[4] + section[5], 24):
                name, info, other, owned, value, size = struct.unpack_from("<IBBHQQ", self.data, pos)
                end = names.find(0, name)
                if end < 0:
                    raise AssertionError("invalid symbol name")
                symbol = {"name": bytes(names[name:end]).decode(), "binding": info >> 4,
                          "type": info & 15, "visibility": other & 3, "section": owned,
                          "value": value, "size": size, "record": pos}
                records.append(symbol)
                if symbol["name"]:
                    self.symbols[symbol["name"]] = symbol
            tables[index] = records
        self.relocations = []
        for section in self.sections:
            if section[1] != 4:
                continue
            if section[9] != 24 or section[5] % 24:
                raise AssertionError("invalid RELA table")
            for pos in range(section[4], section[4] + section[5], 24):
                offset, info, addend = struct.unpack_from("<QQq", self.data, pos)
                self.relocations.append({"section": section[7], "offset": offset, "type": info & 0xffffffff,
                                         "symbol": tables[section[6]][info >> 32], "addend": addend,
                                         "record": pos, "info": info})

    def global_span(self, name):
        symbol = self.symbols[name]
        section = self.sections[symbol["section"]]
        if not symbol["section"] or symbol["value"] + symbol["size"] > section[5]:
            raise AssertionError("invalid source global extent")
        return section[4] + symbol["value"], symbol["size"]


def audit_initializers(path, isa, module):
    """Compare exact source-defined bytes and relative identities with ELF.

    The expected formulas come from the authored source table, then NativeIR
    must retain them exactly. Local section-symbol folding is allowed only
    when its original position reconstructs that same local source symbol.
    """
    parsed = Elf64(path)
    globals_by_name = {item["name"]: item for item in module["globals"]}
    known = {item["name"]: item for item in [*module["globals"], *module["functions"], *module["aliases"]]}
    for item in [*module["globals"], *module["functions"]]:
        defined = item.get("initializer") is not None or item.get("entry") is not None
        if item.get("intrinsic") is not None:
            continue
        symbol = parsed.symbols.get(item["name"])
        if symbol is None:
            raise AssertionError("cold or required original source symbol was omitted")
        binding = 0 if item["linkage"] in {"private", "internal"} else 1
        visibility = {"default": 0, "hidden": 2, "protected": 3}[item["visibility"]]
        if symbol["binding"] != binding or symbol["visibility"] != visibility:
            raise AssertionError("original source symbol binding differs")
        if defined:
            kind = 1 if item["name"] in globals_by_name else 2
            if not symbol["section"] or symbol["type"] != kind:
                raise AssertionError("source definition is not its required ELF symbol kind")
        elif symbol["section"] != 0 or symbol["value"] != 0 or symbol["size"] != 0:
            raise AssertionError("ordinary provider declaration was silently replaced")
    for item in module["aliases"]:
        alias, target = parsed.symbols[item["name"]], parsed.symbols[item["aliasee"]]
        if any(alias[field] != target[field] for field in ("section", "value", "type", "size")):
            raise AssertionError("original alias is detached from its source object")
        if alias["binding"] != 1 or alias["visibility"] != 0:
            raise AssertionError("original alias binding differs")
    expected_count, resolved, records, names = 0, 0, 0, []
    for name, source in globals_by_name.items():
        initializer = source.get("initializer")
        if initializer is None:
            continue
        start, size = parsed.global_span(name)
        symbol = parsed.symbols[name]
        expected = bytes(initializer["bytes"])
        if size != len(expected):
            raise AssertionError("source global size differs")
        relocations = initializer.get("relocations", [])
        if name in dict(TABLES):
            prefix = dict(TABLES)[name]
            formulas = [{"offset": prefix + 4 * i, "width": 32, "symbol": target or name,
                         "addend": addend, "relative_to": name} for i, (target, addend) in enumerate(ENTRIES)]
            if relocations != formulas:
                raise AssertionError("relative source formulas were not retained exactly")
        elif relocations:
            raise AssertionError("unexpected authored non-table relocation")
        covered = set()
        for relocation in relocations:
            offset, target_name, addend = relocation["offset"], relocation["symbol"], relocation["addend"]
            covered.update(range(offset, offset + 4))
            expected_count += 1
            matches = [r for r in parsed.relocations if r["section"] == symbol["section"] and r["offset"] == symbol["value"] + offset]
            target = parsed.symbols.get(target_name)
            fixed = target is not None and target["section"] == symbol["section"] and known[target_name]["linkage"] in {"private", "internal", "external"}
            if fixed:
                wanted = (target["value"] + addend - symbol["value"]) & 0xffffffff
                if matches or bytes(parsed.data[start+offset:start+offset+4]) != wanted.to_bytes(4, "little"):
                    raise AssertionError("resolved source relative32 bytes differ")
                resolved += 1
                continue
            expected_types = [35, 39] if isa == "riscv64" else [2 if isa == "x86_64" else 261]
            if sorted(r["type"] for r in matches) != sorted(expected_types):
                raise AssertionError("relative32 relocation kinds or paired inventory differ")
            if bytes(parsed.data[start+offset:start+offset+4]) != b"\0" * 4:
                raise AssertionError("relative relocation placeholder bytes differ")
            for record in matches:
                subtract = isa == "riscv64" and record["type"] == 39
                wanted_name = name if subtract else target_name
                wanted_addend = 0 if subtract else addend if isa == "riscv64" else addend + offset
                wanted = parsed.symbols.get(wanted_name)
                found = record["symbol"]
                direct = found["name"] == wanted_name and record["addend"] == wanted_addend
                if direct and wanted is not None:
                    direct = all(found[field] == wanted[field] for field in ("binding", "type", "visibility", "section", "value", "size"))
                local = known[wanted_name]["linkage"] in {"private", "internal"}
                folded = (local and wanted is not None and found["type"] == 3 and found["binding"] == 0
                          and found["section"] == wanted["section"] and record["addend"] == wanted_addend + wanted["value"])
                if not direct and not folded:
                    raise AssertionError("relative32 relocation symbol or addend differs")
                records += 1
                names.append(wanted_name)
        for offset, value in enumerate(expected):
            if offset not in covered and parsed.data[start + offset] != value:
                raise AssertionError("ordinary source initializer byte differs")
        expected_positions = {symbol["value"] + r["offset"] for r in relocations}
        if any(r["section"] == symbol["section"] and symbol["value"] <= r["offset"] < symbol["value"] + size
               and r["offset"] not in expected_positions for r in parsed.relocations):
            raise AssertionError("extra initializer relocation")
    if expected_count != 18 or resolved < 2:
        raise AssertionError("authored table coverage is incomplete")
    return {"relative32_entries": expected_count, "resolved_entries": resolved,
            "relocation_records": records, "relocation_symbols": names,
            "ordinary_bytes_exact": True, "machine_code_semantics_verified": False}


class RelativeNativeTests(unittest.TestCase):
    setUpClass = classmethod(weak.WeakNativeTests.setUpClass.__func__)
    command = weak.WeakNativeTests.command
    inputs = weak.WeakNativeTests.inputs

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_RELATIVE_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-relative-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.sequence = 0
        self.frozen_source = self.directory / "frozen-test-source.py"
        self.frozen_source.write_bytes(Path(__file__).read_bytes())
        self.compiler_sha = weak.artifact(self.compiler)["sha256"]

    def emulators(self):
        result = {isa: shutil.which(os.environ.get("OCORE_TEST_QEMU_" + isa.upper(), "qemu-" + isa))
                  for isa in ("aarch64", "riscv64")}
        if platform.machine() not in {"x86_64", "AMD64"} or not all(result.values()):
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail("all-three proof requires x86 host and both QEMU user emulators")
            self.skipTest("all-three execution tools unavailable")
        return result

    def report(self, emulators):
        return {"scope": "bounded static relative32 tables on Linux/QEMU compiler carriers",
                "runtime_complete": False, "compiler_implementation_complete": False,
                "dependency_closure_complete": False, "kernel_execution_verified": False,
                "jit_publication_verified": False, "table_range_exhaustive": False,
                "test_platform_providers": ["Linux startup/syscalls", "external_data", "external_function", "memset", "memcpy"],
                "test_source": weak.artifact(self.frozen_source), "compiler_sha256": self.compiler_sha,
                "reference_profile": ["-O0", "-fno-pic", "-fno-pie"],
                "tools": {name: weak.artifact(path) for name, path in {
                    "ocorec": self.compiler, "reference_clang": self.sdk / "clang", "llvm-as": self.sdk / "llvm-as",
                    "own_assembler": self.assembler, "linker": self.linker, **emulators}.items()}, "targets": {}}

    def execute(self, isa, triple, flags, source, obj, implementation, emulators, corrupt=False, expected_exit=0):
        harness = self.directory / (isa + "-carrier.c")
        if not harness.exists():
            harness.write_text(carrier())
        output = source.with_name(source.name + "." + implementation + (".corrupt" if corrupt else ""))
        argv = [self.sdk / "clang", "--target=" + triple, *flags, "--ld-path=" + self.linker, "-O1",
                "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie",
                "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-e,_start", harness, obj]
        if corrupt:
            argv.append("-DCORRUPT_ORACLE")
        self.command([*argv, "-o", output])
        result = self.command([output] if isa == "x86_64" else [emulators[isa], output], success=False)
        wanted_exit = 31 if corrupt else expected_exit
        self.assertEqual(result.returncode, wanted_exit, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, b"" if wanted_exit else golden())
        return {"input_kind": source.suffix, "implementation": implementation, "corrupt_oracle": corrupt,
                "executable": weak.artifact(output), "stdout": result.stdout.decode(), "exit_code": result.returncode,
                "carrier_source": weak.artifact(harness)}

    def test_original_clang_relative_tables_ll_bc_all_three(self):
        emulators = self.emulators()
        report = self.report(emulators)
        report["own_object_execution_verified"] = False
        for isa, (_, triple, machine, flags) in TARGETS.items():
            units, executions = [], []
            for source in self.inputs(isa, triple, module_body()):
                before = weak.artifact(source)
                reference = source.with_name(source.name + ".clang.o")
                self.command([self.sdk / "clang", "--target=" + triple, *flags, *report["reference_profile"], "-c", source, "-o", reference])
                elf(reference, machine, 1)
                self.assertEqual(weak.artifact(source), before)
                self.assertGreater(weak.elf_symbols(reference)["cold_function"]["size"], 0)
                units.append({"input": before, "original_clang_object": weak.artifact(reference)})
                executions.append(self.execute(isa, triple, flags, source, reference, "original_clang", emulators))
                executions.append(self.execute(isa, triple, flags, source, reference, "original_clang", emulators, True))
            report["targets"][isa] = {"modules": units, "executions": executions}
        self.assertEqual(weak.artifact(self.compiler)["sha256"], self.compiler_sha)
        (self.directory / "relative-original-clang-oracle.json").write_text(json.dumps(report, indent=2) + "\n")

    def test_own_relative_tables_exact_initializers_and_execution_all_three(self):
        if os.environ.get("OCORE_TEST_RELATIVE_REFERENCE_ONLY") == "1":
            self.skipTest("explicit reference preparation; no own-object qualification")
        emulators = self.emulators()
        report = self.report(emulators)
        report["own_object_execution_verified"] = True
        for isa, (target, triple, machine, flags) in TARGETS.items():
            units, executions, mutations = [], [], []
            for source in self.inputs(isa, triple, module_body()):
                before = weak.artifact(source)
                normalized, receipt = source.with_name(source.name + ".native.json"), source.with_name(source.name + ".verification.json")
                own, reference = source.with_name(source.name + ".own.o"), source.with_name(source.name + ".clang.o")
                self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "--emit", "mir", "-o", normalized])
                self.command([self.compiler, normalized, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
                self.assertEqual(json.loads(receipt.read_text())["module_sha256"], weak.artifact(normalized)["sha256"])
                self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "-o", own])
                self.command([self.sdk / "clang", "--target=" + triple, *flags, *report["reference_profile"], "-c", source, "-o", reference])
                self.assertEqual(weak.artifact(source), before)
                module = json.loads(normalized.read_text())
                self.assertEqual({item["name"] for item in module["functions"]}, {
                    "external_function", "llvm.load.relative.i32", "llvm.load.relative.i64", "address_private_data",
                    "address_internal_data", "address_private_function", "address_rel_private", "address_rel_internal",
                    "exported_function", "private_function", "relative_read32", "relative_read64", "relative_dispatch32",
                    "relative_dispatch64", "cold_function"})
                self.assertEqual({item["name"] for item in module["globals"]}, {
                    "private_data", "internal_data", "exported_data", "external_data", "cold_bytes", "rel_private", "rel_internal"})
                self.assertEqual({item["name"] for item in module["aliases"]}, {"exported_data_alias", "exported_function_alias"})
                self.assertEqual(module["provenance"]["source_function_count"], 15)
                self.assertEqual(module["provenance"]["source_global_count"], 7)
                self.assertEqual(module["provenance"]["source_alias_count"], 2)
                self.assertEqual(module["provenance"]["input_sha256"], before["sha256"])
                for obj in (own, reference):
                    elf(obj, machine, 1)
                audit = audit_initializers(own, isa, module)
                units.append({"input": before, "module": weak.artifact(normalized), "verification": weak.artifact(receipt),
                              "own_object": weak.artifact(own), "original_clang_object": weak.artifact(reference), "initializer_audit": audit})
                for implementation, obj in (("own", own), ("original_clang", reference)):
                    executions.append(self.execute(isa, triple, flags, source, obj, implementation, emulators))
                    executions.append(self.execute(isa, triple, flags, source, obj, implementation, emulators, True))
                parsed = Elf64(own)
                cold_start, _ = parsed.global_span("cold_bytes")
                self_start, _ = parsed.global_span("rel_private")
                relocation = next(r for r in parsed.relocations if r["section"] == parsed.symbols["rel_private"]["section"]
                                  and r["offset"] == parsed.symbols["rel_private"]["value"] + 12 and r["type"] != 39)
                other_target = next(r for r in parsed.relocations if r["symbol"]["name"] == "external_function" and r["type"] != 39)
                for label in ("cold-byte", "resolved-self-byte", "relocation-addend", "relocation-target", "relocation-kind"):
                    mutant = source.with_name(source.name + "." + label + ".o")
                    changed = bytearray(parsed.data)
                    if label == "cold-byte":
                        changed[cold_start] ^= 1
                    elif label == "resolved-self-byte":
                        changed[self_start + 28] ^= 1
                    elif label == "relocation-addend":
                        struct.pack_into("<q", changed, relocation["record"] + 16, relocation["addend"] + 1)
                    elif label == "relocation-target":
                        struct.pack_into("<Q", changed, relocation["record"] + 8,
                                         (other_target["info"] & ~0xffffffff) | relocation["type"])
                    else:
                        struct.pack_into("<Q", changed, relocation["record"] + 8, (relocation["info"] & ~0xffffffff) | 1)
                    mutant.write_bytes(changed)
                    diagnostic = {"cold-byte": "ordinary source initializer byte differs",
                                  "resolved-self-byte": "resolved source relative32 bytes differ",
                                  "relocation-addend": "relative32 relocation symbol or addend differs",
                                  "relocation-target": "relative32 relocation symbol or addend differs",
                                  "relocation-kind": "relative32 relocation kinds or paired inventory differ"}[label]
                    with self.assertRaisesRegex(AssertionError, diagnostic) as rejected:
                        audit_initializers(mutant, isa, module)
                    mutations.append({"object": weak.artifact(mutant), "mutation": label,
                                      "independent_initializer_audit_rejected": True, "diagnostic": str(rejected.exception)})
                    if label != "relocation-kind":
                        # Identity is checked before any returned address is
                        # dereferenced, so these byte/addend controls exit31.
                        harness_result = self.execute(isa, triple, flags, source, mutant, "mutant-" + label, emulators, expected_exit=31)
                        mutations[-1]["execution"] = harness_result
            report["targets"][isa] = {"modules": units, "executions": executions, "metadata_mutations": mutations}
        self.assertEqual(weak.artifact(self.compiler)["sha256"], self.compiler_sha)
        (self.directory / "relative-own-conformance.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
