"""Whole ELF group selection through unchanged LLVM and all own ISA objects.

These are generic compiler/linker regressions required by original compiler
implementations. Linux/QEMU carries the comparison; no full runtime/compiler,
dependency closure or native OSTADIX qualification is inferred from fixtures.
"""

import json
import os
from pathlib import Path
import platform
import shutil
import struct
import sys
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_native_equivalence import TARGETS, elf
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory
from tests import test_ocore_llvm_optimizer_promises as promises
from tests import test_ocore_native_alias as alias_qa
from tests import test_ocore_native_runtime as capture_qa
from tests import test_ocore_native_weak as weak


ROOT, MASK = weak.ROOT, weak.MASK
MARKERS = {"a": 11, "b": 53}


def provider(tag, selection="any", prefix="shared", linkage=None):
    marker = {**MARKERS, "c": 211}[tag] if linkage is None else 11
    # A single winning group must resolve duplicate strong definitions before
    # ordinary symbol selection. Mixed weak/strong members of duplicate groups
    # can make LLD resolve a strong symbol into a discarded group; the original
    # reference rejects such a link, so that is not a positive execution oracle.
    fn_linkage = linkage if linkage is not None else "external"
    global_linkage = linkage if linkage is not None else "external"
    group = "bundle.key" if selection == "any" else "retained.batch"
    fn = "" if fn_linkage == "external" else fn_linkage + " "
    data = "" if global_linkage == "external" else global_linkage + " "
    alias_binding = linkage + " " if linkage is not None else ""
    return f"""
${group} = comdat {selection}
@{prefix}_value = {data}global i64 {marker}, comdat(${group}), align 16
@{prefix}_pointer = {data}constant ptr @{prefix}_alias, comdat(${group}), align 8
@{prefix}_function_pointer = {data}constant ptr @{prefix}_function_alias, comdat(${group}), align 8
@outside_{tag}_value = global i64 {marker+101}, align 8
@{prefix}_alias = {alias_binding}alias i64, ptr @{prefix}_value
@{prefix}_function_alias = {alias_binding}alias i64(i64), ptr @{prefix}_function
define internal i64 @{prefix}_helper(i64 %x) align 64 comdat(${group}) {{
  %v = add i64 %x, {3*marker}
  ret i64 %v
}}
define {fn}i64 @{prefix}_function(i64 %x) align 64 comdat(${group}) {{
  %h = call i64 @{prefix}_helper(i64 %x)
  %a = load i64, ptr @{prefix}_value, align 16
  %pointer = load ptr, ptr @{prefix}_pointer, align 8
  %b = load i64, ptr %pointer, align 8
  %ab = add i64 %a, %b
  %result = add i64 %h, %ab
  ret i64 %result
}}
define i64 @outside_{tag}_function() {{ ret i64 {marker+97} }}
define i64 @outside_{tag}_write(i64 %value) {{
  %pointer = load ptr, ptr @{prefix}_pointer, align 8
  store i64 %value, ptr %pointer, align 8
  %result = call i64 @{prefix}_function(i64 7)
  ret i64 %result
}}
"""


def golden(active, outside):
    result = []
    for prefix, marker, writer in active:
        result.extend((marker, marker, marker, 1, 1, 1, 1))
    for tag, marker in outside:
        result.extend((marker + 101, marker + 97))
    for value in weak.inputs():
        for prefix, marker, writer in active:
            result.extend([((value + 5 * marker) & MASK)] * 4)
    for value in weak.inputs()[:16]:
        for prefix, marker, writer in active:
            result.extend(((7 + 3 * marker + 2 * value) & MASK, value, value, value))
    digest = 0xCBF29CE484222325
    for value in result:
        digest = ((digest ^ value) * 0x100000001B3) & MASK
    return f"OCORE-COMDAT digest={digest:016x} checks={len(result)}\n".encode()


def carrier(active, outside):
    reusable = weak.carrier(11)
    text = reusable[:reusable.index("extern u64 chosen_global")]
    for prefix, marker, writer in active:
        text += f"extern u64 {prefix}_value,{prefix}_alias;extern u64 *{prefix}_pointer;\n"
        text += f"extern u64 {prefix}_function(u64),{prefix}_function_alias(u64);extern u64 (*{prefix}_function_pointer)(u64);\n"
    for tag, marker in outside:
        text += f"extern u64 outside_{tag}_value,outside_{tag}_function(void),outside_{tag}_write(u64);\n"
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
"""
    for index, (prefix, marker, writer) in enumerate(active):
        text += f"u64 volatile address_{index}[]={{(u64)&{prefix}_value,(u64)&{prefix}_alias,(u64){prefix}_function,(u64){prefix}_function_alias}};\n"
        text += f"if(add({prefix}_value,{marker})||add({prefix}_alias,{marker})||add(*{prefix}_pointer,{marker})||add({prefix}_pointer==&{prefix}_alias,1)||add(address_{index}[0]==address_{index}[1],1)||add(address_{index}[2]==address_{index}[3],1)||add({prefix}_function_pointer=={prefix}_function_alias,1))return 31;\n"
    for tag, marker in outside:
        text += f"if(add(outside_{tag}_value,{marker+101})||add(outside_{tag}_function(),{marker+97}))return 31;\n"
    for index, (prefix, marker, writer) in enumerate(active):
        text += f"u64(*volatile indirect_{index})(u64)={prefix}_function_alias;\n"
    text += "for(u64 i=0;i<sizeof(values)/sizeof(values[0]);++i){u64 x=values[i];\n"
    for index, (prefix, marker, writer) in enumerate(active):
        text += f"if(add({prefix}_function(x),x+{5*marker})||add({prefix}_function_alias(x),x+{5*marker})||add({prefix}_function_pointer(x),x+{5*marker})||add(indirect_{index}(x),x+{5*marker}))return 31;\n"
    text += "}\nfor(u64 i=0;i<16;++i){u64 x=values[i];\n"
    for prefix, marker, writer in active:
        # Any group has two surviving nongroup callers; alternate them so the
        # losing input module's code must still resolve the selected group.
        call = f"(i&1?outside_a_write(x):outside_b_write(x))" if writer == "both" else f"outside_{writer}_write(x)"
        text += f"if(add({call},7+{3*marker}+2*x)||add({prefix}_value,x)||add({prefix}_alias,x)||add(*{prefix}_pointer,x))return 31;\n"
    count = int(golden(active, outside).decode().split("checks=")[1])
    text += f"}}\nif(checks!={count})return 37;\n"
    output = golden(active, outside).decode().rstrip()
    start = output.index("digest=") + len("digest=")
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


def elf_groups(path):
    """Independent ELF64 SHT_GROUP/member reader, including relocation sections."""
    data = Path(path).read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise AssertionError("expected ELF64 little-endian")
    table = struct.unpack_from("<Q", data, 40)[0]
    stride, count, names_index = struct.unpack_from("<HHH", data, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, table + index * stride) for index in range(count)]
    names = data[sections[names_index][4]:sections[names_index][4] + sections[names_index][5]]
    def string(strings, offset):
        end = strings.find(b"\0", offset)
        if end < 0:
            raise AssertionError("unterminated ELF string")
        return strings[offset:end].decode()
    result = []
    for index, section in enumerate(sections):
        if section[1] != 17:
            continue
        symtab = sections[section[6]]
        strings_section = sections[symtab[6]]
        strings = data[strings_section[4]:strings_section[4] + strings_section[5]]
        signature = struct.unpack_from("<I", data, symtab[4] + 24 * section[7])[0]
        if section[5] < 8 or section[5] % 4:
            raise AssertionError("invalid ELF group size")
        values = struct.unpack_from("<" + "I" * (section[5] // 4), data, section[4])
        members = []
        for member in values[1:]:
            entry = sections[member]
            if not entry[2] & 0x200:
                raise AssertionError("group member lacks SHF_GROUP")
            members.append({"index": member, "name": string(names, entry[0]), "type": entry[1],
                            "flags": entry[2], "relocation_target": entry[7] if entry[1] in (4, 9) else None})
        result.append({"signature": string(strings, signature), "flags": values[0], "section": index, "members": members})
    return result


class ComdatSourceApiTests(unittest.TestCase):
    setUpClass = classmethod(weak.WeakSourceApiTests.setUpClass.__func__)
    setUp = weak.WeakSourceApiTests.setUp
    roundtrip = weak.WeakSourceApiTests.roundtrip

    def test_any_and_nodeduplicate_groups_keep_exact_members_aliases_and_internal_helper_ll_bc_all_three(self):
        for triple in baseline.TRIPLES:
            for selection, expected in (("any", "any"), ("nodeduplicate", "no_deduplicate")):
                for module in self.roundtrip(provider("a", selection), triple):
                    name = "bundle.key" if selection == "any" else "retained.batch"
                    self.assertEqual(module["comdats"], [{"name": name, "selection": expected}])
                    self.assertEqual(module["provenance"]["referenced_comdat_count"], 1)
                    members = {item["name"] for item in [*module["globals"], *module["functions"]] if item["comdat"] == name}
                    self.assertEqual(members, {"shared_value", "shared_pointer", "shared_function_pointer", "shared_function", "shared_helper"})
                    self.assertEqual({item["name"] for item in module["aliases"]}, {"shared_alias", "shared_function_alias"})
                    self.assertEqual(len(module["functions"]), 4)
                    self.assertEqual(len(module["globals"]), 4)

    def test_linkonce_linkonce_odr_and_weak_odr_are_not_collapsed_into_ordinary_weak(self):
        for triple in baseline.TRIPLES:
            for linkage in ("linkonce", "linkonce_odr", "weak_odr"):
                for module in self.roundtrip(provider("a", linkage=linkage), triple):
                    for item in [*module["globals"], *module["functions"]]:
                        if item["name"] in {"shared_value", "shared_pointer", "shared_function_pointer", "shared_function"}:
                            self.assertEqual(item["linkage"], linkage)
                    self.assertTrue(all(item["linkage"] == linkage for item in module["aliases"]))

    def test_unsupported_elf_selection_kinds_reject_entire_original_ll_bc_units(self):
        for triple in baseline.TRIPLES:
            for selection in ("exactmatch", "largest", "samesize"):
                source = self.directory / "unsupported.ll"
                source.write_text(promises.module_text(triple, provider("a").replace("comdat any", "comdat " + selection)))
                binary = memory.LlvmMemoryImportTests.bitcode(self, source)
                for path in (source, binary):
                    with self.assertRaises(importer.ImportFailure) as failure:
                        importer.import_module(path, library_path=self.library)
                    self.assertRegex(str(failure.exception), "COMDAT|comdat")


class ComdatNativeTests(alias_qa.AliasNativeTests):
    test_actual_alias_identity_and_independent_strong_overrides_match_original_clang_all_three = None

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_COMDAT_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-comdat-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.compiler_sha = weak.artifact(self.compiler)["sha256"]
        self.sequence = 0

    def test_whole_groups_and_odr_linkages_match_original_clang_all_three(self):
        emulators = {isa: shutil.which(os.environ.get("OCORE_TEST_QEMU_" + isa.upper(), "qemu-" + isa))
                     for isa in ("aarch64", "riscv64")}
        if platform.machine() not in {"x86_64", "AMD64"} or not all(emulators.values()):
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail("all-three execution requires x86 host and both QEMU user emulators")
            self.skipTest("all-three execution tools unavailable")
        report = {"scope": "whole COMDAT group and ODR compiler conformance on Linux carriers",
                  "runtime_complete": False, "kernel_execution_verified": False, "dependency_closure_complete": False,
                  "compiler_sha256": self.compiler_sha, "test_source": weak.artifact(__file__),
                  "tools": {name: weak.artifact(path) for name, path in {"ocorec": self.compiler, "reference_clang": self.sdk / "clang",
                      "own_assembler": self.assembler, "llvm-as": self.sdk / "llvm-as", "linker": self.linker, **emulators}.items()}, "targets": {}}
        profiles = ["any", "nodeduplicate", "linkonce", "linkonce_odr", "weak_odr"]
        for isa, (target, triple, machine, flags) in TARGETS.items():
            units, executions = [], []
            for profile in profiles:
                objects = {}
                for tag in MARKERS:
                    selection = "nodeduplicate" if profile == "nodeduplicate" else "any"
                    prefix = "keep_" + tag if profile == "nodeduplicate" else "shared"
                    linkage = profile if profile not in {"any", "nodeduplicate"} else None
                    for source in self.inputs(isa + "-" + profile + "-" + tag, triple, provider(tag, selection, prefix, linkage)):
                        original = source.read_bytes()
                        normalized = source.with_name(source.name + ".native.json")
                        receipt = source.with_name(source.name + ".verification.json")
                        own = source.with_name(source.name + ".own.o")
                        reference = source.with_name(source.name + ".clang.o")
                        self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "--emit", "mir", "-o", normalized])
                        self.command([self.compiler, normalized, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
                        self.assertEqual(json.loads(receipt.read_text())["module_sha256"], weak.artifact(normalized)["sha256"])
                        self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "-o", own])
                        self.command([self.sdk / "clang", "--target=" + triple, *flags, "-O0", "-c", source, "-o", reference])
                        self.assertEqual(source.read_bytes(), original)
                        module = json.loads(normalized.read_text())
                        inventories = {}
                        for implementation, obj in (("own", own), ("original_clang", reference)):
                            elf(obj, machine, 1)
                            groups = elf_groups(obj)
                            self.assertEqual(len(groups), 1)
                            group = groups[0]
                            self.assertEqual(group["signature"], "retained.batch" if selection == "nodeduplicate" else "bundle.key")
                            self.assertEqual(group["flags"], 0 if selection == "nodeduplicate" else 1)
                            members = {entry["index"] for entry in group["members"]}
                            symbols = weak.elf_symbols(obj)
                            for definition in [*module["globals"], *module["functions"]]:
                                self.assertEqual(symbols[definition["name"]]["section"] in members, definition["comdat"] is not None)
                                self.assertEqual(symbols[definition["name"]]["binding"],
                                    {"external": 1, "internal": 0, "private": 0, "weak": 2,
                                     "linkonce": 2, "linkonce_odr": 2, "weak_odr": 2}[definition["linkage"]])
                            for alias in module["aliases"]:
                                symbol, root = symbols[alias["name"]], symbols[alias["aliasee"]]
                                self.assertIn(symbol["section"], members)
                                self.assertEqual(symbol["binding"], 1 if alias["linkage"] == "external" else 2)
                                for field in ("section", "value", "size", "type"):
                                    self.assertEqual(symbol[field], root[field])
                            self.assertTrue(any(entry["type"] in (4, 9) for entry in group["members"]), "grouped pointer relocations retained")
                            for entry in group["members"]:
                                if entry["relocation_target"] is not None:
                                    self.assertIn(entry["relocation_target"], members)
                            inventories[implementation] = {"groups": groups, "symbols": symbols}
                        units.append({"profile": profile, "tag": tag, "input": weak.artifact(source), "module": weak.artifact(normalized),
                                      "verification": weak.artifact(receipt), "own_object": weak.artifact(own),
                                      "original_clang_object": weak.artifact(reference), "elf": inventories})
                        objects[tag, source.suffix] = own, reference
                for suffix in (".ll", ".bc"):
                    if profile == "nodeduplicate":
                        for implementation, index in (("own", 0), ("original_clang", 1)):
                            combined = self.directory / (isa + "-retained" + suffix + "." + implementation + ".o")
                            self.command([self.linker, "-r", objects["a", suffix][index], objects["b", suffix][index], "-o", combined])
                            groups = elf_groups(combined)
                            self.assertEqual(len(groups), 2, "same-signature non-deduplicating groups both survive a real partial link")
                            self.assertEqual([(group["signature"], group["flags"]) for group in groups], [("retained.batch", 0)] * 2)
                    for order in (("a", "b"), ("b", "a")):
                        outside = [(tag, MARKERS[tag] if profile in {"any", "nodeduplicate"} else 11) for tag in ("a", "b")]
                        active = [("keep_" + tag, MARKERS[tag], tag) for tag in ("a", "b")] if profile == "nodeduplicate" else [("shared", MARKERS[order[0]] if profile == "any" else 11, "both")]
                        harness = self.directory / (isa + "-" + profile + "-" + "-".join(order) + suffix + ".c")
                        harness.write_text(carrier(active, outside))
                        for implementation, index in (("own", 0), ("original_clang", 1)):
                            output = harness.with_name(harness.name + "." + implementation)
                            argv = [self.sdk / "clang", "--target=" + triple, *flags, "--ld-path=" + self.linker,
                                    "-O1", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie",
                                    "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-e,_start", harness,
                                    *[objects[tag, suffix][index] for tag in order], "-o", output]
                            self.command(argv)
                            result = self.command([output] if isa == "x86_64" else [emulators[isa], output])
                            self.assertEqual(result.stdout, golden(active, outside))
                            executions.append({"profile": profile, "input_kind": suffix, "order": list(order), "implementation": implementation,
                                               "executable": weak.artifact(output), "stdout": result.stdout.decode(), "exit_code": 0})
                            if profile == "any" and order == ("a", "b") and implementation == "own":
                                corrupt = output.with_name(output.name + ".corrupt")
                                self.command([*argv[:-2], "-DCORRUPT_ORACLE", "-o", corrupt])
                                failed = self.command([corrupt] if isa == "x86_64" else [emulators[isa], corrupt], success=False)
                                self.assertEqual(failed.returncode, 31)
                                self.assertEqual(failed.stdout, b"")
                                executions.append({"profile": profile, "input_kind": suffix, "order": list(order), "corrupt_oracle": True,
                                                   "executable": weak.artifact(corrupt), "exit_code": 31})
            report["targets"][isa] = {"modules": units, "executions": executions}
        self.assertEqual(weak.artifact(self.compiler)["sha256"], self.compiler_sha)
        (self.directory / "comdat-conformance.json").write_text(json.dumps(report, indent=2) + "\n")

    def test_nodeduplicate_same_signature_keeps_both_groups_and_duplicate_strong_link_rejects(self):
        records = []
        for isa, (target, triple, machine, flags) in TARGETS.items():
            objects = {}
            for tag in MARKERS:
                for source in self.inputs(isa + "-duplicate-" + tag, triple, provider(tag, "nodeduplicate")):
                    own, reference = source.with_name(source.name + ".own.o"), source.with_name(source.name + ".clang.o")
                    self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "-o", own])
                    self.command([self.sdk / "clang", "--target=" + triple, *flags, "-O0", "-c", source, "-o", reference])
                    for obj in (own, reference):
                        groups = elf_groups(obj)
                        self.assertEqual(len(groups), 1)
                        self.assertEqual(groups[0]["flags"], 0)
                    objects[tag, source.suffix] = own, reference
            for suffix in (".ll", ".bc"):
                for implementation, index in (("own", 0), ("original_clang", 1)):
                    output = self.directory / (isa + "-duplicate" + suffix + "." + implementation + ".o")
                    result = self.command([self.linker, "-r", objects["a", suffix][index], objects["b", suffix][index], "-o", output], success=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("duplicate symbol", result.stderr.decode())
                    self.assertFalse(output.exists())
                    records.append({"isa": isa, "input_kind": suffix, "implementation": implementation, "exit_code": result.returncode,
                                    "diagnostic": result.stderr.decode(), "objects": [weak.artifact(objects[tag, suffix][index]) for tag in MARKERS]})
        (self.directory / "nodeduplicate-negative.json").write_text(json.dumps({"scope": "actual ELF non-deduplicating duplicate-strong rejection",
            "runtime_complete": False, "kernel_execution_verified": False, "dependency_closure_complete": False,
            "compiler_sha256": self.compiler_sha, "test_source": weak.artifact(__file__),
            "tools": {name: weak.artifact(path) for name, path in {"reference_clang": self.sdk / "clang",
                "own_assembler": self.assembler, "linker": self.linker, "llvm-as": self.sdk / "llvm-as"}.items()},
            "records": records}, indent=2) + "\n")

    def test_mixed_any_and_nodeduplicate_same_key_retains_every_nodeduplicate_and_first_any(self):
        emulators = {isa: shutil.which(os.environ.get("OCORE_TEST_QEMU_" + isa.upper(), "qemu-" + isa))
                     for isa in ("aarch64", "riscv64")}
        if platform.machine() not in {"x86_64", "AMD64"} or not all(emulators.values()):
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail("all-three execution requires x86 host and both QEMU user emulators")
            self.skipTest("all-three execution tools unavailable")
        records = []
        for isa, (target, triple, machine, flags) in TARGETS.items():
            objects = {}
            for tag in ("a", "b", "c"):
                body = provider(tag, "nodeduplicate", "keep_c").replace("$retained.batch", "$bundle.key") if tag == "c" else provider(tag)
                for source in self.inputs(isa + "-mixed-" + tag, triple, body):
                    own, reference = source.with_name(source.name + ".own.o"), source.with_name(source.name + ".clang.o")
                    self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "-o", own])
                    self.command([self.sdk / "clang", "--target=" + triple, *flags, "-O0", "-c", source, "-o", reference])
                    for obj in (own, reference):
                        groups = elf_groups(obj)
                        self.assertEqual([(group["signature"], group["flags"]) for group in groups], [("bundle.key", 0 if tag == "c" else 1)])
                    objects[tag, source.suffix] = own, reference
            for suffix in (".ll", ".bc"):
                for order in (("a", "c", "b"), ("b", "c", "a")):
                    active = [("shared", MARKERS[order[0]], "both"), ("keep_c", 211, "c")]
                    outside = [("a", 11), ("b", 53), ("c", 211)]
                    harness = self.directory / (isa + "-mixed-" + "-".join(order) + suffix + ".c")
                    harness.write_text(carrier(active, outside))
                    for implementation, index in (("own", 0), ("original_clang", 1)):
                        output = harness.with_name(harness.name + "." + implementation)
                        argv = [self.sdk / "clang", "--target=" + triple, *flags, "--ld-path=" + self.linker,
                                "-O1", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie",
                                "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-e,_start", harness,
                                *[objects[tag, suffix][index] for tag in order], "-o", output]
                        self.command(argv)
                        result = self.command([output] if isa == "x86_64" else [emulators[isa], output])
                        self.assertEqual(result.stdout, golden(active, outside))
                        records.append({"isa": isa, "input_kind": suffix, "order": list(order), "implementation": implementation,
                                        "executable": weak.artifact(output), "stdout": result.stdout.decode(), "exit_code": 0})
        (self.directory / "mixed-comdat-conformance.json").write_text(json.dumps({
            "scope": "mixed ELF Any/NoDedup same-key group compiler conformance on Linux carriers",
            "runtime_complete": False, "kernel_execution_verified": False, "dependency_closure_complete": False,
            "compiler_sha256": self.compiler_sha, "test_source": weak.artifact(__file__),
            "tools": {name: weak.artifact(path) for name, path in {"reference_clang": self.sdk / "clang",
                "own_assembler": self.assembler, "linker": self.linker, "llvm-as": self.sdk / "llvm-as", **emulators}.items()},
            "records": records}, indent=2) + "\n")


class ComdatRuntimeClosureTests(ComdatNativeTests):
    test_whole_groups_and_odr_linkages_match_original_clang_all_three = None
    test_nodeduplicate_same_signature_keeps_both_groups_and_duplicate_strong_link_rejects = None
    test_mixed_any_and_nodeduplicate_same_key_retains_every_nodeduplicate_and_first_any = None

    def test_actual_cxx_capture_resolves_whole_groups_aliases_and_source_ownership_in_both_orders(self):
        olangc = Path(os.environ.get("OLANGC", str(ROOT / "target/debug/olangc"))).resolve()
        if not olangc.is_file() or not (self.sdk / "clang++").is_file() or not shutil.which("git"):
            self.skipTest("actual olangc/Git/Clang++ required for capture admission")
        records = []
        for order in (("first", "second"), ("second", "first")):
            root = self.directory / "-".join(order)
            source = root / "source"
            source.mkdir(parents=True)
            for tag, marker in (("first", 101), ("second", 307)):
                (source / (tag + ".cpp")).write_text('extern "C" {\n'
                    'inline __attribute__((noinline)) unsigned long long shared_function(unsigned long long x){return x+11;}\n'
                    'inline unsigned long long shared_value=11;\n'
                    'extern unsigned long long shared_function_alias(unsigned long long) __attribute__((alias("shared_function")));\n'
                    'extern unsigned long long shared_value_alias __attribute__((alias("shared_value")));\n'
                    f'unsigned long long outside_{tag}_value={marker};\n'
                    f'unsigned long long outside_{tag}_function(void){{return {marker+7};}}\n'
                    '}\n')
            (source / "main.c").write_text('extern unsigned long long shared_value,shared_value_alias,outside_first_value,outside_second_value;\n'
                'extern unsigned long long shared_function(unsigned long long),shared_function_alias(unsigned long long);\n'
                'extern unsigned long long outside_first_function(void),outside_second_function(void);\n'
                'int main(void){void *volatile root_data=(void*)&shared_value,*volatile alias_data=(void*)&shared_value_alias,*volatile root_code=(void*)shared_function,*volatile alias_code=(void*)shared_function_alias;'
                'return shared_value!=11 || shared_value_alias!=11 || shared_function(7)!=18 || shared_function_alias(7)!=18 || root_data!=alias_data || root_code!=alias_code || outside_first_value!=101 || outside_second_value!=307 || outside_first_function()!=108 || outside_second_function()!=314;}\n')
            (source / "build.py").write_text('''import json,os,pathlib,subprocess,sys
source=pathlib.Path(sys.argv[1]);flags=json.loads(sys.argv[2]);order=json.loads(sys.argv[3]);names=[tag+".cpp" for tag in order]+["main.c"]
for name in names:
 driver=os.environ["CXX"] if name.endswith(".cpp") else os.environ["CC"]
 subprocess.run([driver,*flags,*(["-std=c++17"] if name.endswith(".cpp") else []),"-c",str(source/name),"-o",name+".o"],check=True)
subprocess.run([os.environ["CC"],*[name+".o" for name in names],"-no-pie","-o","app"],check=True)
subprocess.run(["./app"],check=True)
pathlib.Path("inventory.json").write_text(json.dumps({"schema":"ocore-runtime-unit-inventory-v1","complete":True,"units":[{"id":name,"kind":"clang","source":name,"role":"runtime","build_step":"runtime-build"} for name in names]}))
''')
            for argv in (("git", "init", "-q"), ("git", "add", "."),
                         ("git", "-c", "user.name=COMDAT Closure Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "whole original C++ COMDAT units")):
                self.command(argv, cwd=source)
            revision = self.command(["git", "rev-parse", "HEAD"], cwd=source).stdout.decode().strip()
            names = [tag + ".cpp" for tag in order] + ["main.c"]
            recipe = {"schema": "ocore-runtime-recipe-v1", "name": "comdat-cxx-capture-" + "-".join(order),
                      "source": {"url": "local-pinned-comdat-regression", "revision": revision},
                      "toolchain": {"llvm_version": "22.1.6"},
                      "commands": [{"name": "runtime-build", "argv": [sys.executable, "{source}/build.py", "{source}", json.dumps(capture_qa.FLAGS), json.dumps(order)]}],
                      "coverage": {"required_units": [{"id": name, "kind": "clang", "source": name, "role": "runtime"} for name in names],
                                   "required_outputs": ["app"], "require_full_unit_inventory": True}}
            recipe_path = root / "recipe.json"
            recipe_path.write_text(json.dumps(recipe))
            build, capture, output = root / "build", root / "capture", root / "lowered"
            self.command([sys.executable, ROOT / "scripts/ocore_runtime_capture.py", "capture", recipe_path,
                          "--source", source, "--build", build, "--output", capture, "--unit-inventory", build / "inventory.json",
                          "--cc", self.sdk / "clang", "--cxx", self.sdk / "clang++", "--llvm-nm", self.sdk / "llvm-nm"])
            report = json.loads((capture / "report.json").read_text())
            self.assertTrue(report["capture_complete"])
            self.assertEqual(len(report["lowering_unit_ids"]), 3)
            self.command([olangc, capture / "report.json", "--native-runtime", "--native-isa", "x86_64-unknown-none",
                          "--native-runtime-output", "obj", "-o", output])
            receipt = json.loads((output / "coverage.json").read_text())
            self.assertTrue(receipt["unit_lowering_complete"])
            self.assertTrue(receipt["module_set_complete"])
            self.assertTrue(receipt["symbol_closure_complete"])
            self.assertEqual(receipt["lowered_unit_count"], 3)
            self.assertEqual(receipt["source"]["revision"], revision)
            inventory = receipt["symbol_inventory"]
            groups = inventory["comdat_resolutions"]
            self.assertEqual({group["group"] for group in groups}, {"shared_value", "shared_function"})
            definitions = inventory["definitions"]
            provider_units = {item["unit"] for item in definitions if item["symbol"] in {"outside_first_value", "outside_second_value"}}
            self.assertEqual(len(provider_units), 2)
            # Capture IDs are journal identifiers, not original link-order
            # ordinals. This receipt qualifies the driver's supplied module
            # order; the original ordered link remains separate evidence.
            supplied_provider_order = [unit["id"] for unit in receipt["units"] if unit["id"] in provider_units]
            self.assertEqual(len(supplied_provider_order), 2)
            first_unit = supplied_provider_order[0]
            for group in groups:
                self.assertTrue(group["compatible"])
                self.assertEqual(group["selection"], "any")
                self.assertEqual(group["selected_units"], [first_unit])
                self.assertEqual([candidate["unit"] for candidate in group["candidates"]], supplied_provider_order)
            alias_definitions = [item for item in definitions if item["alias_of"] is not None]
            self.assertEqual(len(alias_definitions), 4, "both original source units remain fully represented")
            for item in alias_definitions:
                original_root = next(candidate for candidate in definitions
                                     if candidate["unit"] == item["unit"] and candidate["symbol"] == item["alias_of"])
                self.assertEqual(item["comdat"], original_root["comdat"])
                self.assertEqual(item["retained_group"], item["unit"] == first_unit)
                resolution = next(candidate for candidate in inventory["export_resolutions"] if candidate["symbol"] == item["symbol"])
                self.assertEqual(resolution["selected_unit"], first_unit)
            for field in ("runtime_complete", "native_execution_qualified", "dependency_closure_complete", "artifact_complete", "link_performed"):
                self.assertFalse(receipt[field], field)
            objects = list(output.glob("unit-*/module.o"))
            self.assertEqual(len(objects), 3)
            executable = root / "own-linked-group-selection"
            self.command([self.sdk / "clang", *objects, "-no-pie", "-o", executable])
            self.command([executable])
            records.append({"order": list(order), "source_revision": revision, "capture": weak.artifact(capture / "report.json"),
                            "receipt": weak.artifact(output / "coverage.json"), "own_executable": weak.artifact(executable)})
        (self.directory / "comdat-capture-closure.json").write_text(json.dumps({
            "scope": "typed C++ COMDAT group and alias source-ownership closure regression",
            "runtime_complete": False, "dependency_closure_complete": False, "native_execution_qualified": False,
            "test_source": weak.artifact(__file__), "olangc": weak.artifact(olangc), "records": records}, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
