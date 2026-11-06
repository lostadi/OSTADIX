"""External weak declarations retain missing=zero and provider selection.

Native objects execute on Linux test carriers. These tests do not qualify an OS
runtime or relax a compiler-owned component's separate dependency-closure gate.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_foreign_frontends import HARNESS
from scripts.check_ocore_native_equivalence import TARGETS, execution_prefix
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory
from tests.test_ocore_native_weak import elf_symbols

SDK = Path.home()/'.cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin'
BODY = '''
@optional_data = extern_weak global i64
@optional_hidden = extern_weak hidden global i64
@optional_protected = extern_weak protected global i64
@address_slot = global ptr @optional_data
@offset_slot = global ptr getelementptr (i8, ptr @optional_data, i64 3)
declare extern_weak i64 @optional_function(i64)
define i64 @probe() {
  %exists = icmp ne ptr @optional_data, null
  br i1 %exists, label %present, label %absent
present:
  %value = load i64, ptr @optional_data
  %called = call i64 @optional_function(i64 %value)
  %hidden = load i64, ptr @optional_hidden
  %result = add i64 %called, %hidden
  ret i64 %result
absent:
  ret i64 97
}
define ptr @function_address() { ret ptr @optional_function }
define ptr @data_offset() {
  %p = getelementptr i8, ptr @optional_data, i64 3
  ret ptr %p
}
define ptr @hidden_address() { ret ptr @optional_hidden }
define ptr @protected_address() { ret ptr @optional_protected }
'''
PROVIDER = '''
@optional_data = global i64 11
@optional_hidden = hidden global i64 13
@optional_protected = protected global i64 17
define i64 @optional_function(i64 %x) { %v = add i64 %x, 7 ret i64 %v }
'''

RELATIVE = '@relative_slot = private constant i32 trunc (i64 sub (i64 ptrtoint (ptr @optional_data to i64), i64 ptrtoint (ptr @relative_slot to i64)) to i32)\ndefine ptr @relative_address() {\n  %d = load i32, ptr @relative_slot, align 4\n  %offset = sext i32 %d to i64\n  %p = getelementptr i8, ptr @relative_slot, i64 %offset\n  ret ptr %p\n}\n'


class ExternWeakImportTests(unittest.TestCase):
    setUpClass = classmethod(baseline.LlvmImportTests.setUpClass.__func__)
    setUp = baseline.LlvmImportTests.setUp
    write = baseline.LlvmImportTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode

    def test_text_bitcode_and_three_isas_preserve_declarations_and_relocations(self):
        for triple in baseline.TRIPLES:
            with self.subTest(triple=triple):
                source = self.write(BODY+RELATIVE, triple=triple)
                for path in (source, self.bitcode(source)):
                    module = importer.import_module(path, library_path=self.library,
                                                    expected_sha256=self.library_sha256)
                    for g in module['globals']:
                        if g['name'].startswith('optional_'):
                            self.assertEqual(g['linkage'], 'extern_weak')
                            self.assertIsNone(g['initializer'])
                    f = next(f for f in module['functions'] if f['name']=='optional_function')
                    self.assertEqual(f['linkage'], 'extern_weak')
                    self.assertIsNone(f['entry'])
                    g = next(g for g in module['globals'] if g['name']=='offset_slot')
                    self.assertEqual(g['initializer']['relocations'][0]['addend'], 3)
                    self.assertTrue(any('LLVMExternalWeakLinkage=12' in r for r in module['provenance']['refinements']))

    def test_external_weak_tls_is_explicitly_rejected(self):
        path = self.write('@optional = extern_weak thread_local global i64\n')
        with self.assertRaisesRegex(importer.ImportFailure, 'non-TLS declaration'):
            importer.import_module(path, library_path=self.library, expected_sha256=self.library_sha256)


class ExternWeakNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = Path(os.environ.get('OCOREC', str(baseline.ROOT/'target/debug/ocorec')))
        if not cls.compiler.is_file() or not (SDK/'clang').is_file():
            raise unittest.SkipTest('built O-core compiler and exact LLVM22 SDK required')
        cls.library = baseline.llvm_library()
        cls.library_sha256 = importer.PINNED_SHA256
        cls.runners = {isa:execution_prefix(isa, os.environ.get('OCORE_TEST_QEMU_'+isa.upper())) for isa in TARGETS}

    def command(self, argv):
        result = subprocess.run([str(x) for x in argv],capture_output=True,timeout=90)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        return result

    def test_missing_present_and_archive_only_providers_match_clang_on_all_three_isas(self):
        with tempfile.TemporaryDirectory(prefix='ocore-extern-weak-') as temporary:
            directory = Path(temporary)
            for isa,(target,triple,_,flags) in TARGETS.items():
                with self.subTest(isa=isa):
                    source = directory/(isa+'.ll')
                    source.write_text(f'target triple = "{triple}"\ntarget datalayout = "{baseline.LAYOUT}"\n'+BODY+(RELATIVE if isa!='aarch64' else ''))
                    module = importer.import_module(source,library_path=self.library,expected_sha256=self.library_sha256)
                    normalized=directory/(isa+'.json');normalized.write_text(json.dumps(module))
                    own=directory/(isa+'.own.o');reference=directory/(isa+'.ref.o')
                    self.command([self.compiler,normalized,'--input-kind','native-ir','--target',target,'-o',own])
                    self.command([SDK/'clang','--target='+triple,*flags,'-O0','-c',source,'-o',reference])
                    symbols=elf_symbols(own)
                    for name in ('optional_data','optional_hidden','optional_protected','optional_function'):
                        self.assertEqual(symbols[name]['binding'],2)
                        self.assertEqual(symbols[name]['section'],0)
                        self.assertEqual(symbols[name]['visibility'],2 if name=='optional_hidden' else 3 if name=='optional_protected' else 0)
                    provider=directory/(isa+'.provider.ll');provider.write_text(f'target triple = "{triple}"\n'+PROVIDER)
                    provider_obj=directory/(isa+'.provider.o')
                    self.command([SDK/'clang','--target='+triple,*flags,'-c',provider,'-o',provider_obj])
                    archive=directory/(isa+'.a')
                    self.command([SDK/'llvm-ar','rcs',archive,provider_obj])
                    weak_provider=directory/(isa+'.weak-provider.ll')
                    weak_provider.write_text(f'target triple = "{triple}"\n'+PROVIDER.replace('= global i64 11','= weak global i64 17').replace('= hidden global i64 13','= weak hidden global i64 19').replace('= protected global i64 17','= weak protected global i64 23').replace('define i64','define weak i64').replace('%x, 7','%x, 23'))
                    weak_obj=directory/(isa+'.weak-provider.o')
                    self.command([SDK/'clang','--target='+triple,*flags,'-c',weak_provider,'-o',weak_obj])
                    for scenario in ('missing','present','weak','weak-strong','strong-weak','archive'):
                        present=int(scenario not in ('missing','archive'))
                        carrier=directory/(isa+'.'+scenario+'.c')
                        startup='#if defined(__x86_64__)\n__asm__'+HARNESS.split('#if defined(__x86_64__)\n__asm__',1)[1]
                        carrier.write_text('''typedef unsigned long u64;
extern u64 probe(void);
extern void *function_address(void), *data_offset(void), *hidden_address(void);
extern void *protected_address(void), *relative_address(void);
extern void *address_slot,*offset_slot;
extern u64 optional_data __attribute__((weak));
extern u64 optional_hidden __attribute__((weak,visibility("hidden")));
extern u64 optional_protected __attribute__((weak,visibility("protected")));
extern u64 optional_function(u64) __attribute__((weak));
int conformance_main(void) {
 if(probe()!=EXPECTED)return 11;
 if(function_address()!=(void*)optional_function)return 12;
 if((u64)data_offset()!=(u64)&optional_data+3)return 13;
 if(address_slot!=(void*)&optional_data)return 14;
 if((u64)offset_slot!=(u64)&optional_data+3)return 15;
 if(hidden_address()!=(void*)&optional_hidden)return 16;
 if(protected_address()!=(void*)&optional_protected)return 19;
#ifdef TEST_RELATIVE
 if(relative_address()!=(void*)&optional_data)return 20;
#endif
 if(PRESENT && (!function_address() || !address_slot || !hidden_address()))return 17;
 if(!PRESENT && (function_address() || address_slot || hidden_address()))return 18;
 return 0;
}
'''.replace('EXPECTED','59' if scenario=='weak' else '31' if present else '97').replace('PRESENT',str(present))+startup)
                        for tag,obj in [('own',own),('clang',reference)]:
                            binary=directory/(isa+'.'+scenario+'.'+tag)
                            providers={'missing':[], 'present':[provider_obj], 'weak':[weak_obj],
                                       'weak-strong':[weak_obj,provider_obj], 'strong-weak':[provider_obj,weak_obj],
                                       'archive':[archive]}[scenario]
                            self.command([SDK/'clang','--target='+triple,*flags,*(['-DTEST_RELATIVE'] if isa!='aarch64' else []),'-nostdlib','-static','-no-pie','-fno-pie','-fno-stack-protector','-fuse-ld=lld','-Wl,-e,_start',carrier,obj,*providers,'-o',binary])
                            self.command([*self.runners[isa],binary])

    def test_external_weak_variadic_call_preserves_indirect_target_and_arguments_all_three_isas(self):
        body = '''
declare extern_weak i64 @optional_variadic(i64, ...)
define i64 @variadic_probe() {
  %present = icmp ne ptr @optional_variadic, null
  br i1 %present, label %call, label %absent
call:
  %v = call i64 (i64, ...) @optional_variadic(i64 9, i64 5, i32 7)
  ret i64 %v
absent:
  ret i64 113
}
'''
        with tempfile.TemporaryDirectory(prefix='ocore-extern-weak-variadic-') as temporary:
            directory=Path(temporary)
            for isa,(target,triple,_,flags) in TARGETS.items():
                with self.subTest(isa=isa):
                    source=directory/(isa+'.ll')
                    source.write_text(f'target triple = "{triple}"\ntarget datalayout = "{baseline.LAYOUT}"\n'+body)
                    module=importer.import_module(source,library_path=self.library,expected_sha256=self.library_sha256)
                    normalized=directory/(isa+'.json');normalized.write_text(json.dumps(module))
                    own=directory/(isa+'.own.o');reference=directory/(isa+'.ref.o')
                    self.command([self.compiler,normalized,'--input-kind','native-ir','--target',target,'-o',own])
                    self.command([SDK/'clang','--target='+triple,*flags,'-O0','-c',source,'-o',reference])
                    provider=directory/(isa+'.provider.c')
                    provider.write_text('''#include <stdarg.h>
unsigned long optional_variadic(unsigned long first, ...) {
 va_list ap; va_start(ap,first);
 unsigned long second=va_arg(ap,unsigned long);
 int third=va_arg(ap,int);
 va_end(ap); return first+second+(unsigned)third;
}
''')
                    provider_obj=directory/(isa+'.provider.o')
                    self.command([SDK/'clang','--target='+triple,*flags,'-ffreestanding','-fno-stack-protector','-O1','-c',provider,'-o',provider_obj])
                    startup='#if defined(__x86_64__)\n__asm__'+HARNESS.split('#if defined(__x86_64__)\n__asm__',1)[1]
                    for present in (False,True):
                        carrier=directory/(isa+str(present)+'.c')
                        carrier.write_text('extern unsigned long variadic_probe(void);\nint conformance_main(void) { return variadic_probe()!='+('21' if present else '113')+'; }\n'+startup)
                        for tag,obj in [('own',own),('clang',reference)]:
                            binary=directory/(isa+str(present)+tag)
                            providers=[provider_obj] if present else []
                            self.command([SDK/'clang','--target='+triple,*flags,'-nostdlib','-static','-no-pie','-fno-pie','-fno-stack-protector','-fuse-ld=lld','-Wl,-e,_start',carrier,obj,*providers,'-o',binary])
                            self.command([*self.runners[isa],binary])

    def test_aarch64_external_weak_relative_initializer_rejects_before_object_publication(self):
        with tempfile.TemporaryDirectory(prefix='ocore-extern-weak-prel-') as temporary:
            directory=Path(temporary);source=directory/'input.ll'
            source.write_text(f'target triple = "aarch64-unknown-linux-gnu"\ntarget datalayout = "{baseline.LAYOUT}"\n'+BODY+RELATIVE)
            module=importer.import_module(source,library_path=self.library,expected_sha256=self.library_sha256)
            normalized=directory/'input.json';normalized.write_text(json.dumps(module))
            output=directory/'unsupported.o'
            result=subprocess.run([str(self.compiler),str(normalized),'--input-kind','native-ir','--target','aarch64-unknown-none','-o',str(output)],capture_output=True)
            self.assertNotEqual(result.returncode,0);self.assertFalse(output.exists())
            self.assertIn('AArch64 source-relative initializer targeting extern_weak',result.stderr.decode())

    def test_forged_external_weak_definitions_and_tls_reject_before_object_publication(self):
        import copy
        with tempfile.TemporaryDirectory(prefix='ocore-extern-weak-reject-') as temporary:
            directory=Path(temporary);source=directory/'input.ll'
            source.write_text(f'target triple = "{baseline.TRIPLES[0]}"\ntarget datalayout = "{baseline.LAYOUT}"\n'+BODY)
            original=importer.import_module(source,library_path=self.library,expected_sha256=self.library_sha256)
            for kind in ('global','function','tls'):
                module=copy.deepcopy(original)
                if kind=='global':
                    g=next(g for g in module['globals'] if g['name']=='address_slot');g['linkage']='extern_weak'
                elif kind=='function':
                    f=next(f for f in module['functions'] if f['name']=='probe');f['linkage']='extern_weak'
                else:
                    g=next(g for g in module['globals'] if g['name']=='optional_data');g['thread_local']=True
                path=directory/(kind+'.json');path.write_text(json.dumps(module));out=directory/(kind+'.o')
                result=subprocess.run([str(self.compiler),str(path),'--input-kind','native-ir','-o',str(out)],capture_output=True)
                self.assertNotEqual(result.returncode,0);self.assertFalse(out.exists())
                self.assertIn('extern_weak',result.stderr.decode())
