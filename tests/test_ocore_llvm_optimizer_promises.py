"""LLVM promises remain provenance; real bodies/calls supply all effects.

These synthetic compiler conformance units are imported whole, never rewritten.
Linux/QEMU only carries the execution comparison, not native OSTADIX runtime
qualification. Exception handling and allocator dependency closure remain
separate requirements. This file does not build Cargo or install tools.
"""

import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_foreign_frontends import HARNESS as LINUX_CARRIER
from scripts.check_ocore_native_equivalence import TARGETS, elf
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory


ROOT = baseline.ROOT
SDK = Path.home() / ".cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin"
TRIPLES = baseline.TRIPLES
LAYOUT = memory.LAYOUT
MASK = (1 << 64) - 1
ALLOC_PAYLOADS = (1, 9, 17, 33, 41, 49, 2, 10, 18, 34, 42, 50, 4)
ALLOC_NAMES = ((1, "alloc"), (2, "realloc"), (4, "free"),
               (8, "uninitialized"), (16, "zeroed"), (32, "aligned"))


def module_text(triple, body):
    layout = LAYOUT + ("-Fn32" if triple.startswith("aarch64-") else "")
    return f'target triple = "{triple}"\ntarget datalayout = "{layout}"\n' + body


def artifact(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size}


def functional_body():
    # The allocator implementation comes from a declared platform interface;
    # these original IR bodies retain every call and every normal-return store.
    # malloc/free are deliberately ordinary arithmetic symbol names here.
    return """
declare ptr @carrier_allocate(i64)
declare void @carrier_free(ptr)
declare void @unused(ptr readnone, ptr dead_on_unwind)
define ptr @promise_alloc(i64 %size) allockind("alloc,uninitialized") {
  %result = call ptr @carrier_allocate(i64 %size)
  ret ptr %result
}
define void @promise_free(ptr %pointer) allockind("free") {
  call void @carrier_free(ptr %pointer)
  ret void
}
define ptr @allocate_direct(i64 %size) {
  %result = call ptr @promise_alloc(i64 %size) allockind("alloc,uninitialized")
  ret ptr %result
}
define ptr @allocate_indirect(ptr %callee, i64 %size) {
  %result = call ptr %callee(i64 %size) allockind("alloc,uninitialized")
  ret ptr %result
}
define void @free_direct(ptr %pointer) {
  call void @promise_free(ptr %pointer) allockind("free")
  ret void
}
define void @free_indirect(ptr %callee, ptr %pointer) {
  call void %callee(ptr %pointer) allockind("free")
  ret void
}
define i64 @read_other(ptr readnone %ignored, ptr %access) {
  %result = load i64, ptr %access, align 8
  ret i64 %result
}
define i64 @read_direct(ptr %ignored, ptr %access) {
  %result = call i64 @read_other(ptr readnone %ignored, ptr %access)
  ret i64 %result
}
define i64 @read_indirect(ptr %callee, ptr %ignored, ptr %access) {
  %result = call i64 %callee(ptr readnone %ignored, ptr %access)
  ret i64 %result
}
define void @write_normal(ptr dead_on_unwind %out, i64 %value) {
  store i64 %value, ptr %out, align 8
  ret void
}
define void @write_direct(ptr %out, i64 %value) {
  call void @write_normal(ptr dead_on_unwind %out, i64 %value)
  ret void
}
define void @write_indirect(ptr %callee, ptr %out, i64 %value) {
  call void %callee(ptr dead_on_unwind %out, i64 %value)
  ret void
}
define i64 @malloc(i64 %value) {
  %result = xor i64 %value, 1234605616436508552
  ret i64 %result
}
define i64 @free(i64 %value) {
  %result = add i64 %value, 17
  ret i64 %result
}
"""


class LlvmOptimizerPromiseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-optimizer-promises-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    write = memory.LlvmMemoryImportTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode
    import_ir = memory.LlvmMemoryImportTests.import_ir
    reject = memory.LlvmMemoryImportTests.reject
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)

    def roundtrip(self, body, triple=TRIPLES[0]):
        text_path = self.write(body, triple)
        original = text_path.read_bytes()
        binary_path = self.bitcode(text_path)
        modules = [importer.import_module(path, library_path=self.library)
                   for path in (text_path, binary_path)]
        self.assertEqual({k: v for k, v in modules[0].items() if k not in {"name", "provenance"}},
                         {k: v for k, v in modules[1].items() if k not in {"name", "provenance"}})
        self.assertEqual(text_path.read_bytes(), original)
        for path, module in zip((text_path, binary_path), modules):
            self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(module["target"]["triple"], triple)
        return modules

    def assert_promise(self, module, symbol, scope, index, name, payload):
        # Require scope and full numeric payload, not a generic attribute census.
        pattern = (rf"^{re.escape(symbol)}: {scope} attribute index {index}: "
                   rf".*\b{re.escape(name)}={payload}(?:\b|;)")
        self.assertTrue(any(re.search(pattern, item) for item in module["provenance"]["refinements"]),
                        (pattern, module["provenance"]["refinements"]))

    def test_readnone_and_dead_on_unwind_placements_keep_whole_body_inventory_all_three_isas(self):
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(functional_body(), triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 17)
                    self.assertEqual(module["provenance"]["source_global_count"], 0)
                    self.assertEqual(len(module["functions"]), 17)
                    self.assert_promise(module, "unused", "function", 1, "readnone", 0)
                    self.assert_promise(module, "unused", "function", 2, "dead_on_unwind", 0)
                    self.assert_promise(module, "read_other", "function", 1, "readnone", 0)
                    for name in ("read_direct", "read_indirect"):
                        self.assert_promise(module, name, "callsite", 1, "readnone", 0)
                    self.assert_promise(module, "write_normal", "function", 1, "dead_on_unwind", 0)
                    for name in ("write_direct", "write_indirect"):
                        self.assert_promise(module, name, "callsite", 1, "dead_on_unwind", 0)
                    self.assertEqual([op["op"] for op in self.operations(self.function(module, "read_other"))], ["load"])
                    self.assertEqual([op["op"] for op in self.operations(self.function(module, "write_normal"))], ["store"])
                    for name in ("read_direct", "read_indirect", "write_direct", "write_indirect", "promise_alloc", "promise_free",
                                 "allocate_direct", "allocate_indirect", "free_direct", "free_indirect"):
                        self.assertEqual([op["op"] for op in self.operations(self.function(module, name))], ["call"])
                    for function in module["functions"]:
                        self.assertIsNone(function["intrinsic"])
                        self.assertEqual(function["signature"]["result_attributes"], [])
                        self.assertFalse(any(function["signature"]["param_attributes"]))
                    self.assertIsNone(self.function(module, "unused")["entry"])

    def test_all_known_allockind_payloads_preserve_function_and_callsite_contexts_all_three_isas(self):
        declarations = []
        for payload in ALLOC_PAYLOADS:
            spelling = ",".join(name for bit, name in ALLOC_NAMES if payload & bit)
            result = "void" if payload == 4 else "ptr"
            declarations.append(f'declare {result} @allocator_{payload}(ptr) allockind("{spelling}")')
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip("\n".join(declarations) + "\n" + functional_body(), triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 30)
                    for payload in ALLOC_PAYLOADS:
                        self.assert_promise(module, f"allocator_{payload}", "function", 0xffffffff, "allockind", payload)
                        self.assertIsNone(self.function(module, f"allocator_{payload}")["entry"])
                    for symbol, scope, payload in (("promise_alloc", "function", 9), ("promise_free", "function", 4),
                                                   ("allocate_direct", "callsite", 9), ("allocate_indirect", "callsite", 9),
                                                   ("free_direct", "callsite", 4), ("free_indirect", "callsite", 4)):
                        self.assert_promise(module, symbol, scope, 0xffffffff, "allockind", payload)

    def test_promises_do_not_change_integer_abi_extensions_or_alias_access(self):
        body = """
declare zeroext i8 @external(ptr readnone, ptr dead_on_unwind, i8 signext)
define signext i8 @entry(ptr readnone %p, ptr dead_on_unwind %q, i8 zeroext %v) {
  %result = call zeroext i8 @external(ptr readnone %p, ptr dead_on_unwind %q, i8 signext %v)
  ret i8 %result
}
"""
        plain = self.import_ir(body.replace(" readnone", "").replace(" dead_on_unwind", ""))
        for module in self.roundtrip(body):
            self.assertEqual({k: v for k, v in module.items() if k not in {"name", "provenance"}},
                             {k: v for k, v in plain.items() if k not in {"name", "provenance"}})
            self.assertEqual(self.function(module, "external")["signature"]["result_attributes"], ["zeroext"])
            self.assertEqual(self.function(module, "external")["signature"]["param_attributes"], [[], [], ["signext"]])
            self.assertEqual(self.function(module, "entry")["signature"]["result_attributes"], ["signext"])
            self.assertEqual(self.function(module, "entry")["signature"]["param_attributes"], [[], [], ["zeroext"]])

    def test_parameter_only_promises_reject_return_function_and_scalar_placements(self):
        for attribute in ("readnone", "dead_on_unwind"):
            self.reject(f"declare {attribute} ptr @bad()\n", stage="parse")
            self.reject(f"declare void @bad(i64 {attribute})\n", stage="llvm-verify")
            self.reject(f"declare ptr @external()\ndefine ptr @entry() {{ %result = call {attribute} ptr @external()\nret ptr %result }}\n", stage="parse")
            self.reject(f"declare void @external(i64)\ndefine void @entry() {{ call void @external(i64 {attribute} 7)\nret void }}\n", stage="llvm-verify")
            self.reject(f"define void @entry(ptr %callee) {{ call void %callee(i64 {attribute} 7)\nret void }}\n", stage="llvm-verify")
            # Legacy function readnone is normalized by LLVM into memory(none).
            # dead_on_unwind has no such legacy function-level spelling.
            if attribute == "dead_on_unwind":
                self.reject(f"declare void @bad() {attribute}\n", stage="parse")
            self.reject(f"declare void @bad(ptr {attribute}(1))\n", stage="parse")

    def test_legacy_function_readnone_is_reader_normalized_into_memory_none(self):
        for triple in TRIPLES:
            for module in self.roundtrip("define i64 @entry(i64 %value) readnone { ret i64 %value }\n", triple):
                refinements = "\n".join(module["provenance"]["refinements"])
                self.assertIn("entry: attribute index 4294967295: erased optimization assumption memory=0", refinements)
                self.assertNotIn("readnone=", refinements)
                self.assertEqual(self.operations(self.function(module, "entry")), [])
                self.assertIsNone(self.function(module, "entry")["intrinsic"])

    def test_invalid_allockind_text_payloads_and_slots_reject_before_import(self):
        for spelling in ("", "unknown", "alloc,realloc", "free,zeroed", "alloc,zeroed,uninitialized"):
            with self.subTest(spelling=spelling):
                with self.assertRaises(importer.ImportFailure) as raised:
                    self.import_ir(f'declare ptr @bad(ptr) allockind("{spelling}")\n')
                self.assertIn(raised.exception.stage, {"parse", "llvm-verify"})
        for body in ('declare allockind("alloc") ptr @bad()',
                     'declare void @bad(ptr allockind("free"))'):
            with self.subTest(body=body):
                self.reject(body + "\n", stage="parse")
        # Pinned LLVM verifier does not check this documented return restriction.
        self.reject('declare ptr @bad(ptr) allockind("free")\n')
        for body in (
            'declare ptr @external(ptr)\ndefine ptr @entry(ptr %p) { %result = call ptr @external(ptr %p) allockind("free")\nret ptr %result }\n',
            'define ptr @entry(ptr %callee, ptr %p) { %result = call ptr %callee(ptr %p) allockind("free")\nret ptr %result }\n',
        ):
            with self.subTest(nonvoid_call=body):
                with self.assertRaises(importer.ImportFailure) as raised:
                    self.import_ir(body)
                self.assertEqual(raised.exception.stage, "import")
                self.assertIn("allockind free requires a void result", str(raised.exception))

    def mutated_allockind_bitcode(self, payload):
        """Construct hostile valid-container BC without trusting printed-IR text."""
        api = importer.LLVM(self.library, importer.PINNED_SHA256)
        create = api.lib.LLVMCreateEnumAttribute
        create.restype, create.argtypes = importer.P, [importer.P, importer.U, importer.Q]
        add = api.lib.LLVMAddAttributeAtIndex
        add.restype, add.argtypes = None, [importer.P, importer.U, importer.P]
        named = api.lib.LLVMGetNamedFunction
        named.restype, named.argtypes = importer.P, [importer.P, C.c_char_p]
        data = self.write("declare ptr @bad()\n").read_bytes()
        context, module, message = api.ContextCreate(), importer.P(), importer.P()
        buffer = api.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"bad-payload")
        serialized = None
        try:
            self.assertEqual(api.ParseIRInContext2(context, buffer, C.byref(module), C.byref(message)), 0)
            kind = api.GetEnumAttributeKindForName(b"allockind", len("allockind"))
            self.assertEqual(kind, 90, "exact pinned LLVM22 enum contract")
            add(named(module, b"bad"), 0xffffffff, create(context, kind, payload))
            # Deliberately do not verify this hostile module before serialization:
            # independent input verification is the behavior under test.
            serialized = api.WriteBitcodeToMemoryBuffer(module)
            data = C.string_at(api.GetBufferStart(serialized), api.GetBufferSize(serialized))
        finally:
            if serialized:
                api.DisposeMemoryBuffer(serialized)
            if message:
                api.DisposeMessage(message)
            if module:
                api.DisposeModule(module)
            api.DisposeMemoryBuffer(buffer)
            api.ContextDispose(context)
        path = self.directory / f"allockind-{payload}.bc"
        path.write_bytes(data)
        self.assertTrue(data.startswith(b"BC\xc0\xde"))
        return path

    def test_malformed_bitcode_integer_payloads_cannot_bypass_verifier_or_normalizer(self):
        for payload in (0, 3, 5, 6, 7, 12, 20, 28, 25, 64, 65, (1 << 63) | 1):
            with self.subTest(payload=payload):
                path = self.mutated_allockind_bitcode(payload)
                with self.assertRaises(importer.ImportFailure) as raised:
                    importer.import_module(path, library_path=self.library)
                self.assertIn(raised.exception.stage, {"llvm-verify", "import"})
                self.assertTrue(str(raised.exception).strip())

    def test_allocator_descriptions_are_preserved_while_unrelated_abi_and_pointer_codegen_contracts_reject_even_unused(self):
        for attribute in ("byval(i8)", "byref(i8)", "sret(i128)", "inalloca(i8)", "preallocated(i8)",
                          "inreg", "nest", "swiftself", "swifterror", "swiftasync", "alignstack(16)"):
            with self.subTest(attribute=attribute):
                self.reject(f"declare void @unused(ptr dead_on_unwind {attribute})\n")
        for name in ("readnone", "dead_on_unwind", "allockind"):
            with self.subTest(string_attribute=name):
                self.reject(f'declare void @unused(ptr) "{name}"="0"\n')
        self.reject("declare void @unused(ptr addrspace(1) readnone)\n")
        self.reject("declare void @unused(ptr addrspace(1) dead_on_unwind writable)\n")
        descriptions = (
            ('declare ptr @unused(i64 allocalign) allockind("alloc,aligned")\n', 33, "allocalign"),
            ('declare void @unused(ptr allocptr) allockind("free")\n', 4, "allocptr"),
            ('declare ptr @unused(i64 allocalign) allockind("alloc,aligned") allocsize(0)\n', 33, "allocalign"),
            ('declare ptr @unused(i64) allockind("alloc") "alloc-family"="malloc"\n', 1, "alloc-family"),
        )
        for body, payload, description in descriptions:
            for triple in TRIPLES:
                for module in self.roundtrip(body, triple):
                    with self.subTest(description=description, triple=triple):
                        self.assertEqual([f["name"] for f in module["functions"]], ["unused"])
                        self.assertEqual(module["globals"], [])
                        self.assertEqual(module["aliases"], [])
                        self.assertEqual(module["provenance"]["source_function_count"], 1)
                        function = self.function(module, "unused")
                        self.assertIsNone(function["entry"])
                        self.assertEqual(function["blocks"], [])
                        self.assertEqual(function["signature"]["abi"], "c")
                        self.assertEqual(function["signature"]["param_attributes"], [[]])
                        self.assert_promise(module, "unused", "function", 0xffffffff, "allockind", payload)
                        if description == "alloc-family":
                            self.assertTrue(any("function attribute index 4294967295: validated allocator description alloc-family='malloc';" in item
                                                for item in module["provenance"]["refinements"]))
                        else:
                            self.assert_promise(module, "unused", "function", 1, description, 0)


def expected_output():
    digest = 0xcbf29ce484222325
    for index in range(128):
        value = ((index * 0x9e3779b97f4a7c15) ^ 0xa57b91327e0562d9) & MASK
        words = [value, value, value, value, (value + 1) & MASK, (value + 2) & MASK,
                 value ^ 0x1122334455667788, (value + 17) & MASK]
        data = b"".join(word.to_bytes(8, "little") for word in words) + bytes([(index + mode) & 255 for mode in range(3)])
        for byte in data:
            digest = ((digest ^ byte) * 0x100000001b3) & MASK
    return f"OCORE-OPTIMIZER-PROMISES digest={digest:016x} checks=1792\n".encode()


def carrier():
    syscall = LINUX_CARRIER.split("static u64 syscall3", 1)[1].split("static u64 signed_bits", 1)[0]
    startup = LINUX_CARRIER.split("#if defined(__x86_64__)\n__asm__", 1)[1]
    text = "typedef unsigned long long u64;typedef unsigned char byte;\nstatic u64 syscall3" + syscall
    text += r"""
static u64 syscall6(u64 number,u64 first,u64 second,u64 third,u64 fourth,u64 fifth,u64 sixth) {
#if defined(__x86_64__)
    register u64 rax __asm__("rax")=number,r10 __asm__("r10")=fourth,r8 __asm__("r8")=fifth,r9 __asm__("r9")=sixth;
    __asm__ volatile("syscall":"+a"(rax):"D"(first),"S"(second),"d"(third),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return rax;
#elif defined(__aarch64__)
    register u64 x0 __asm__("x0")=first,x1 __asm__("x1")=second,x2 __asm__("x2")=third;
    register u64 x3 __asm__("x3")=fourth,x4 __asm__("x4")=fifth,x5 __asm__("x5")=sixth,x8 __asm__("x8")=number;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory");return x0;
#else
    register u64 a0 __asm__("a0")=first,a1 __asm__("a1")=second,a2 __asm__("a2")=third;
    register u64 a3 __asm__("a3")=fourth,a4 __asm__("a4")=fifth,a5 __asm__("a5")=sixth,a7 __asm__("a7")=number;
    __asm__ volatile("ecall":"+r"(a0):"r"(a1),"r"(a2),"r"(a3),"r"(a4),"r"(a5),"r"(a7):"memory");return a0;
#endif
}
static u64 allocations=0,frees=0,free_errors=0;
byte* carrier_allocate(u64 size) {
    if(!size||size>4096)return (byte*)0;
#if defined(__x86_64__)
    u64 address=syscall6(9,0,4096,3,34,~0ULL,0);
#else
    u64 address=syscall6(222,0,4096,3,34,~0ULL,0);
#endif
    if(address>=(u64)-4095)return (byte*)0;
    ++allocations;return (byte*)address;
}
void carrier_free(byte* pointer) {
#if defined(__x86_64__)
    u64 result=syscall3(11,(u64)pointer,4096,0);
#else
    u64 result=syscall3(215,(u64)pointer,4096,0);
#endif
    if(result)++free_errors;else ++frees;
}
extern byte* promise_alloc(u64),*oracle_promise_alloc(u64),*allocate_direct(u64),*oracle_allocate_direct(u64);
extern byte* allocate_indirect(byte*(*)(u64),u64),*oracle_allocate_indirect(byte*(*)(u64),u64);
extern void promise_free(byte*),oracle_promise_free(byte*),free_direct(byte*),oracle_free_direct(byte*);
extern void free_indirect(void(*)(byte*),byte*),oracle_free_indirect(void(*)(byte*),byte*);
extern u64 read_other(const u64*,const u64*),oracle_read_other(const u64*,const u64*);
extern u64 read_direct(const u64*,const u64*),oracle_read_direct(const u64*,const u64*);
extern u64 read_indirect(u64(*)(const u64*,const u64*),const u64*,const u64*),oracle_read_indirect(u64(*)(const u64*,const u64*),const u64*,const u64*);
extern void write_normal(u64*,u64),oracle_write_normal(u64*,u64),write_direct(u64*,u64),oracle_write_direct(u64*,u64);
extern void write_indirect(void(*)(u64*,u64),u64*,u64),oracle_write_indirect(void(*)(u64*,u64),u64*,u64);
extern u64 named_malloc(u64) __asm__("malloc"),named_free(u64) __asm__("free"),oracle_malloc(u64),oracle_free(u64);
static u64 digest=0xcbf29ce484222325ULL;
static void add(byte b){digest=(digest^b)*0x100000001b3ULL;}
static void add_word(u64 word){for(u64 i=0;i<8;++i)add((byte)(word>>(8*i)));}
int conformance_main(void) {
    u64 checks=0;
    for(u64 index=0;index<128;++index) {
        u64 value=(index*0x9e3779b97f4a7c15ULL)^0xa57b91327e0562d9ULL;
        u64 expected=value;
#ifdef CORRUPT_EXPECTED
        if(!index)expected^=1;
#endif
        /* Aliasing through the second pointer is legal under readnone. */
        u64 own=read_other(&value,&value),reference=oracle_read_other(&value,&value);
        if(own!=expected||reference!=expected||own!=reference)return 31;
        add_word(own);++checks;
        own=read_direct(&value,&value);reference=oracle_read_direct(&value,&value);
        if(own!=value||reference!=value)return 31;
        add_word(own);++checks;
        own=read_indirect(read_other,&value,&value);reference=oracle_read_indirect(oracle_read_other,&value,&value);
        if(own!=value||reference!=value)return 31;
        add_word(own);++checks;
        for(u64 mode=0;mode<3;++mode) {
            u64 first=0,second=0,target=value+mode;
            if(!mode){write_normal(&first,target);oracle_write_normal(&second,target);}
            else if(mode==1){write_direct(&first,target);oracle_write_direct(&second,target);}
            else {write_indirect(write_normal,&first,target);oracle_write_indirect(oracle_write_normal,&second,target);}
            if(first!=target||second!=target)return 32;
            add_word(first);++checks;
        }
        own=named_malloc(value);reference=oracle_malloc(value);
        if(own!=(value^0x1122334455667788ULL)||reference!=own)return 33;
        add_word(own);++checks;
        own=named_free(value);reference=oracle_free(value);
        if(own!=value+17||reference!=own)return 34;
        add_word(own);++checks;
        for(u64 mode=0;mode<3;++mode) {
            byte *first,*second;u64 size=index%32+1;
            if(!mode){first=promise_alloc(size);second=oracle_promise_alloc(size);}
            else if(mode==1){first=allocate_direct(size);second=oracle_allocate_direct(size);}
            else {first=allocate_indirect(promise_alloc,size);second=oracle_allocate_indirect(oracle_promise_alloc,size);}
            if(!first||!second||first==second)return 35;
            ++checks;byte mark=(byte)(index+mode);first[size-1]=mark;second[size-1]=mark;
            if(first[size-1]!=mark||second[size-1]!=mark)return 36;
            add(first[size-1]);++checks;
            if(!mode){promise_free(first);oracle_promise_free(second);}
            else if(mode==1){free_direct(first);oracle_free_direct(second);}
            else {free_indirect(promise_free,first);oracle_free_indirect(oracle_promise_free,second);}
        }
    }
    if(checks!=1792||allocations!=768||frees!=768||free_errors)return 37;
"""
    output = expected_output().decode().rstrip()
    old_digest = output.split("digest=", 1)[1].split(" ", 1)[0]
    text += 'static char output[]="' + output.replace(old_digest, "0" * 16) + '\\n";\n'
    text += r"""
    for(u64 i=0;i<16;++i){u64 nibble=(digest>>(60-4*i))&15;output[sizeof("OCORE-OPTIMIZER-PROMISES digest=")-1+i]=(char)(nibble<10?'0'+nibble:'a'+nibble-10);}
#if defined(__x86_64__)
    if(syscall3(1,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#else
    if(syscall3(64,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#endif
    return 0;
}
#if defined(__x86_64__)
__asm__""" + startup
    return text


class LlvmOptimizerPromiseNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = Path(os.environ.get("OCOREC", str(ROOT / "target/debug/ocorec"))).resolve()
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(SDK))).resolve()
        missing = [str(path) for path in [cls.compiler, *(cls.sdk / name for name in ("clang", "llvm-as", "llvm-nm", "llvm-objcopy"))] if not path.is_file()]
        if missing:
            reason = "real built compiler and exact LLVM22 SDK required: " + ", ".join(missing)
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                raise RuntimeError(reason)
            raise unittest.SkipTest(reason)
        for name in ("clang", "llvm-as", "llvm-nm", "llvm-objcopy"):
            result = subprocess.run([str(cls.sdk / name), "--version"], capture_output=True, text=True, timeout=15)
            if result.returncode or not re.search(r"\b(?:clang version|LLVM version) 22\.1\.6(?:\s|$)", result.stdout):
                raise RuntimeError("reference requires exact LLVM22.1.6: " + name)

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_OPTIMIZER_PROMISES_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-optimizer-native-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.compiler_sha256 = hashlib.sha256(self.compiler.read_bytes()).hexdigest()
        self.sequence = 0

    def command(self, argv, success=True):
        argv = [str(arg) for arg in argv]
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=120)
        (self.directory / f"command-{self.sequence:03}.json").write_text(json.dumps({
            "argv": argv, "exit_code": result.returncode,
            "stdout": result.stdout.decode(errors="replace"), "stderr": result.stderr.decode(errors="replace")}, indent=2))
        self.sequence += 1
        if success:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace") + result.stdout.decode(errors="replace"))
        return result

    def inputs(self, name, triple, body):
        source = self.directory / (name + ".ll")
        source.write_text(module_text(triple, body))
        binary = source.with_suffix(".bc")
        self.command([self.sdk / "llvm-as", source, "-o", binary])
        self.assertTrue(binary.read_bytes().startswith(b"BC\xc0\xde"))
        return source, binary

    def test_unsupported_cold_abi_and_real_eh_cannot_emit_partial_artifacts_all_three_isas(self):
        cases = {
            "cold_abi": "declare void @unsupported(ptr dead_on_unwind byval(i8))\n",
            "personality": "declare i32 @personality()\ndefine void @unwinder(ptr dead_on_unwind %p) personality ptr @personality { ret void }\n",
            "invoke": """
declare i32 @personality()
declare void @throwing(ptr)
define void @unwinder(ptr dead_on_unwind %p) personality ptr @personality {
entry:
  invoke void @throwing(ptr dead_on_unwind %p) to label %normal unwind label %exception
normal:
  ret void
exception:
  %landing = landingpad {ptr, i32} cleanup
  resume {ptr, i32} %landing
}
""",
        }
        for isa, (target, triple, _, _) in TARGETS.items():
            for name, body in cases.items():
                for source in self.inputs(isa + "-" + name, triple, functional_body() + body):
                    for emit in ("mir", "asm", "obj"):
                        with self.subTest(isa=isa, case=name, input=source.suffix, emit=emit):
                            output = source.with_name(source.name + "." + emit)
                            result = self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target,
                                                   "--emit", emit, "-o", output], success=False)
                            self.assertNotEqual(result.returncode, 0)
                            self.assertTrue(result.stderr.strip())
                            self.assertFalse(output.exists(), "unsupported cold functions must reject the whole unit")
                            diagnostic = result.stderr.decode(errors="replace")
                            if name == "cold_abi":
                                self.assertIn("unsupported attribute", diagnostic)
                            else:
                                self.assertIn("unsupported function GC, personality or prefix/prologue data", diagnostic)
                                self.assertNotIn("variadic calling convention", diagnostic)
        self.assertEqual(hashlib.sha256(self.compiler.read_bytes()).hexdigest(), self.compiler_sha256)

    def test_unmodified_ll_and_bc_own_objects_match_original_clang_reference_all_three_isas(self):
        linker = shutil.which(os.environ.get("LD_LLD", "ld.lld"))
        emulators = {isa: shutil.which(os.environ.get("OCORE_TEST_QEMU_" + isa.upper(), "qemu-" + isa))
                     for isa in ("aarch64", "riscv64")}
        if not linker or not all(emulators.values()) or platform.machine() not in {"x86_64", "AMD64"}:
            reason = "strict all3 execution requires x86 host, exact linker and both real QEMU user emulators"
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail(reason)
            self.skipTest(reason)
        harness = self.directory / "carrier.c"
        harness.write_text(carrier())
        report = {"scope": "optimizer promises on Linux compiler conformance carriers", "runtime_complete": False,
                  "kernel_execution_verified": False, "exception_handling_qualified": False,
                  "compiler_sha256": self.compiler_sha256, "targets": {},
                  "tools": {name: artifact(path) for name, path in {
                      "ocorec": self.compiler, "clang": self.sdk / "clang", "llvm-as": self.sdk / "llvm-as",
                      "llvm-nm": self.sdk / "llvm-nm", "llvm-objcopy": self.sdk / "llvm-objcopy",
                      "ld.lld": linker, **emulators}.items()}}
        for isa, (target, triple, machine, flags) in TARGETS.items():
            records = []
            for source in self.inputs(isa, triple, functional_body()):
                with self.subTest(isa=isa, input=source.suffix):
                    original_bytes = source.read_bytes()
                    native_path = source.with_name(source.stem + "-" + source.suffix[1:] + ".native.json")
                    self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target,
                                  "--emit", "mir", "-o", native_path])
                    native = json.loads(native_path.read_text())
                    self.assertEqual(native["provenance"]["input_sha256"], hashlib.sha256(original_bytes).hexdigest())
                    self.assertEqual(native["provenance"]["source_function_count"], 17)
                    self.assertEqual(len(native["functions"]), 17)
                    original_names = set(re.findall(r"^(?:declare|define)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(",
                                                    functional_body(), re.MULTILINE))
                    self.assertEqual({fn["name"] for fn in native["functions"]}, original_names)
                    own = native_path.with_suffix(".o")
                    receipt = native_path.with_suffix(".verified.json")
                    self.command([self.compiler, native_path, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
                    self.assertTrue(json.loads(receipt.read_text())["verified"])
                    self.command([self.compiler, native_path, "--input-kind", "native-ir", "--target", target, "--emit", "obj", "-o", own])
                    elf(own, machine, 1)
                    reference = own.with_name(own.stem + "-reference.o")
                    self.command([self.sdk / "clang", "--target=" + triple, *flags, "-O0", "-fno-pic", "-fno-pie",
                                  "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-c", source, "-o", reference])
                    elf(reference, machine, 1)
                    definitions = {fn["name"] for fn in native["functions"] if fn["entry"] is not None}
                    own_symbols = self.command([self.sdk / "llvm-nm", "--defined-only", "--format=posix", own]).stdout.decode()
                    self.assertEqual({line.split()[0] for line in own_symbols.splitlines() if line.split()[1].isupper()}, definitions)
                    symbols = self.command([self.sdk / "llvm-nm", "--defined-only", "--format=posix", reference]).stdout.decode()
                    self.assertEqual({line.split()[0] for line in symbols.splitlines() if line.split()[1].isupper()}, definitions)
                    oracle = own.with_name(own.stem + "-oracle.o")
                    renames = [arg for name in sorted(definitions) for arg in ("--redefine-sym", name + "=oracle_" + name)]
                    self.command([self.sdk / "llvm-objcopy", *renames, reference, oracle])
                    link = [self.sdk / "clang", "--target=" + triple, *flags, "-O2", "-ffreestanding", "-fno-builtin",
                            "-fno-stack-protector", "-fno-pic", "-fno-pie", "-nostdlib", "-static", "-fuse-ld=lld",
                            "--ld-path=" + linker, "-Wl,-e,_start", "-Wl,--build-id=none", harness, own, oracle]
                    executable = own.with_suffix(".elf")
                    self.command([*link, "-o", executable])
                    elf(executable, machine, 2)
                    emulator = [] if isa == "x86_64" else [emulators[isa]]
                    actual = self.command([*emulator, executable]).stdout
                    self.assertEqual(actual, expected_output())
                    broken = own.with_suffix(".broken.elf")
                    self.command([*link, "-DCORRUPT_EXPECTED", "-o", broken])
                    rejected = self.command([*emulator, broken], success=False)
                    self.assertEqual(rejected.returncode, 31)
                    self.assertEqual(rejected.stdout, b"")
                    self.assertEqual(source.read_bytes(), original_bytes)
                    records.append({"original_input_sha256": hashlib.sha256(original_bytes).hexdigest(),
                                    "native_module_sha256": hashlib.sha256(native_path.read_bytes()).hexdigest(),
                                    "verified_receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
                                    "own_object_sha256": hashlib.sha256(own.read_bytes()).hexdigest(),
                                    "reference_object_sha256": hashlib.sha256(reference.read_bytes()).hexdigest(),
                                    "output": actual.decode(), "corrupted_expected_exit": 31})
            self.assertEqual(len(records), 2)
            report["targets"][isa] = records
        self.assertEqual(hashlib.sha256(self.compiler.read_bytes()).hexdigest(), self.compiler_sha256)
        self.assertEqual(len(report["targets"]), 3)
        report["all_three_executions_passed"] = True
        (self.directory / "optimizer-promise-conformance.json").write_text(json.dumps(report, indent=2))
        print("All three own optimizer promises: " + expected_output().decode().strip(), flush=True)


if __name__ == "__main__":
    unittest.main()
