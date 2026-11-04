"""Pinned-parser ctlz/abs whole-unit contracts, not runtime acceptance."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from scripts import ocore_llvm_import as importer

SDK=Path('/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib')
LIB=Path(os.environ.get('OCORE_LLVM_LIBRARY',str(SDK/'riscv64-linux-gnu/libLLVM.so.22.1')))
SHA=os.environ.get('OCORE_LLVM_SHA256','8617d27fecff5e31785eed07ee1cd7665e083bb689b6fb13266956d5231afe83')

def source(kind='ctlz',width=32,flag='false',attributes='',callattrs=''):
    return f'''target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-p:64:64-i64:64"
@original_marker = global i64 123456789
declare {attributes} i{width} @llvm.{kind}.i{width}(i{width}, i1 immarg)
define i{width} @calculate(i{width} %x) {{
  %v = call {callattrs} i{width} @llvm.{kind}.i{width}(i{width} %x, i1 {flag})
  ret i{width} %v
}}
define i64 @original_cold() {{ ret i64 987654321 }}
'''.encode()

def load(raw):
    with tempfile.TemporaryDirectory(prefix='ocore-unary-input-') as tmp:
        path=Path(tmp)/('unit.bc' if raw.startswith(b'BC') else 'unit.ll')
        path.write_bytes(raw)
        return importer.import_module(path,library_path=LIB,expected_sha256=SHA)

class IntegerUnaryImport(unittest.TestCase):
    def test_text_and_bitcode_preserve_all_original_symbols_and_poison_controls(self):
        tool=SDK/'llvm-22/bin/llvm-as'
        version=subprocess.run([str(tool),'--version'],capture_output=True,check=True).stdout.decode()
        self.assertIn('22.1.6',version)
        with tempfile.TemporaryDirectory(prefix='ocore-unary-import-') as tmp:
            root=Path(tmp)
            for kind in ['ctlz','abs']:
                for width in [32,64]:
                    for flag in ['false','true']:
                        raw=source(kind,width,flag); ll=root/'unit.ll';bc=root/'unit.bc';ll.write_bytes(raw)
                        subprocess.run([str(tool),str(ll),'-o',str(bc)],capture_output=True,check=True)
                        for original in [raw,bc.read_bytes()]:
                            module=load(original)
                            self.assertEqual(module['provenance']['input_sha256'],hashlib.sha256(original).hexdigest())
                            self.assertEqual(module['provenance']['source_function_count'],3)
                            self.assertEqual(module['provenance']['source_global_count'],1)
                            self.assertEqual({f['name'] for f in module['functions']},{'calculate','original_cold',f'llvm.{kind}.i{width}'})
                            self.assertEqual([g['name'] for g in module['globals']],['original_marker'])
                            instruction=next(f for f in module['functions'] if f['name']=='calculate')['blocks'][0]['instructions'][0]
                            operation=instruction['operation'];field='zero_is_poison' if kind=='ctlz' else 'int_min_is_poison'
                            self.assertEqual(operation['op'],'integer_count_leading_zeros' if kind=='ctlz' else 'integer_abs')
                            self.assertIs(operation[field],flag=='true')
                            self.assertEqual(module['types'][instruction['result']['ty']],{'kind':'int','bits':width})
                            self.assertTrue(any('constant poison flag=' in s for s in module['provenance']['refinements']))

    def test_unsupported_overloads_and_nonliteral_flags_refuse_whole_units(self):
        for kind in ['ctlz','abs']:
            for width in [16,128]:
                with self.subTest(kind=kind,width=width),self.assertRaises(importer.ImportFailure): load(source(kind,width))
            raw=source(kind,64,'%control').replace(b'@calculate(i64 %x)',b'@calculate(i64 %x, i1 %control)')
            with self.assertRaises(importer.ImportFailure):load(raw)
            for flag in ['undef','poison']:
                with self.subTest(kind=kind,flag=flag),self.assertRaises(importer.ImportFailure):load(source(kind,64,flag))

    def test_callsite_abi_attributes_and_pinned_declaration_normalization_are_distinct(self):
        # llvmorg-22.1.6 AutoUpgrade.cpp: UpgradeIntrinsicFunction resets a
        # valid intrinsic declaration to Intrinsic::getAttributes. The pinned
        # parser performs that normalization before the importer sees it.
        # Ordinary declaration attributes remain ABI contracts; call sites do
        # not inherit normalized intrinsic declaration attributes.
        for kind in ['ctlz','abs']:
            for attribute in ['signext','zeroext']:
                with self.subTest(kind=kind,attribute=attribute):
                    raw=source(kind,32,attributes=attribute)
                    raw+=f'declare {attribute} i32 @ordinary_dependency(i32)\n'.encode()
                    with tempfile.TemporaryDirectory(prefix='ocore-unary-attributes-') as tmp:
                        ll=Path(tmp)/'original.ll';bc=Path(tmp)/'normalized.bc';ll.write_bytes(raw)
                        subprocess.run([str(SDK/'llvm-22/bin/llvm-as'),str(ll),'-o',str(bc)],capture_output=True,check=True)
                        printed=subprocess.run([str(SDK/'llvm-22/bin/llvm-dis'),str(bc),'-o','-'],capture_output=True,check=True).stdout.decode()
                        intrinsic_line=next(line for line in printed.splitlines() if line.startswith('declare ') and f'@llvm.{kind}.i32(' in line)
                        ordinary_line=next(line for line in printed.splitlines() if line.startswith('declare ') and '@ordinary_dependency(' in line)
                        self.assertNotIn(attribute,intrinsic_line)
                        self.assertIn(attribute,ordinary_line)
                        for original in [raw,bc.read_bytes()]:
                            module=load(original)
                            self.assertEqual(module['provenance']['input_sha256'],hashlib.sha256(original).hexdigest())
                            intrinsic=next(f for f in module['functions'] if f['name']==f'llvm.{kind}.i32')
                            ordinary=next(f for f in module['functions'] if f['name']=='ordinary_dependency')
                            self.assertEqual(intrinsic['signature']['result_attributes'],[])
                            self.assertEqual(ordinary['signature']['result_attributes'],[attribute])
                            self.assertTrue(any('UpgradeIntrinsicFunction attribute normalization' in text for text in module['provenance']['refinements']))
                    with self.assertRaises(importer.ImportFailure):
                        load(source(kind,32,callattrs=attribute))

    def test_identity_table_is_exact_and_parser_ids_are_real(self):
        api=importer.LLVM(LIB,SHA)
        for kind in ['ctlz','abs']:
            base=f'llvm.{kind}'.encode();self.assertGreater(api.LookupIntrinsicID(base,len(base)),0)
            for width in [32,64]:self.assertEqual(importer.Importer.INTEGER_UNARY_INTRINSICS[f'llvm.{kind}.i{width}'],(kind,width))
        for name in ['llvm.ctlz.i032','llvm.abs.i064','llvm.ctlz.v2i32','llvm.abs.i128']:
            self.assertNotIn(name,importer.Importer.INTEGER_UNARY_INTRINSICS)

if __name__=='__main__':unittest.main()
