"""Whole-unit exact LLVM22 scalar ctpop parsing; not engine acceptance."""
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
def source(width=64,callattrs=''):
    return f'''target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-p:64:64-i64:64"
@original_marker = global i64 123456789
declare i{width} @llvm.ctpop.i{width}(i{width})
define i{width} @calculate(i{width} %x) {{
  %v = call {callattrs} i{width} @llvm.ctpop.i{width}(i{width} %x)
  ret i{width} %v
}}
define i64 @original_cold() {{ ret i64 987654321 }}
'''.encode()
def load(raw):
    with tempfile.TemporaryDirectory(prefix='ocore-popcount-input-') as tmp:
        p=Path(tmp)/('original.bc' if raw.startswith(b'BC') else 'original.ll');p.write_bytes(raw)
        return importer.import_module(p,library_path=LIB,expected_sha256=SHA)
class PopulationCountImport(unittest.TestCase):
    def test_text_and_bitcode_keep_complete_units_and_one_original_operand(self):
        tool=SDK/'llvm-22/bin/llvm-as'
        self.assertIn('22.1.6',subprocess.run([str(tool),'--version'],capture_output=True,check=True).stdout.decode())
        with tempfile.TemporaryDirectory(prefix='ocore-popcount-') as tmp:
            for width in [32,64]:
                ll=Path(tmp)/'original.ll';bc=Path(tmp)/'original.bc';ll.write_bytes(source(width))
                subprocess.run([str(tool),str(ll),'-o',str(bc)],capture_output=True,check=True)
                for raw in [ll.read_bytes(),bc.read_bytes()]:
                    module=load(raw)
                    self.assertEqual(module['provenance']['input_sha256'],hashlib.sha256(raw).hexdigest())
                    self.assertEqual(module['provenance']['source_function_count'],3)
                    self.assertEqual(module['provenance']['source_global_count'],1)
                    self.assertEqual({f['name'] for f in module['functions']},{'calculate','original_cold',f'llvm.ctpop.i{width}'})
                    self.assertEqual([g['name'] for g in module['globals']],['original_marker'])
                    fn=next(f for f in module['functions'] if f['name']=='calculate')
                    insn=fn['blocks'][0]['instructions'][0]
                    self.assertEqual(insn['operation'],{'op':'integer_population_count','value':{'kind':'value','id':0}})
                    self.assertEqual(module['types'][insn['result']['ty']],{'kind':'int','bits':width})
    def test_unsupported_widths_refuse_the_entire_original_unit(self):
        for width in [16,128]:
            with self.subTest(width=width),self.assertRaises(importer.ImportFailure) as failure:load(source(width))
            self.assertEqual(failure.exception.stage,'import')
    def test_callsite_abi_contracts_are_not_erased(self):
        for attribute in ['signext','zeroext']:
            with self.subTest(attribute=attribute),self.assertRaises(importer.ImportFailure) as failure:load(source(32,attribute))
            self.assertEqual(failure.exception.stage,'import')
    def test_exact_intrinsic_identity_and_same_width_overloads(self):
        api=importer.LLVM(LIB,SHA);self.assertGreater(api.LookupIntrinsicID(b'llvm.ctpop',10),0)
        self.assertEqual(importer.Importer.INTEGER_POPULATION_COUNT_INTRINSICS,{'llvm.ctpop.i32':32,'llvm.ctpop.i64':64})
        for name in ['llvm.ctpop.i032','llvm.ctpop.i16','llvm.ctpop.i128','llvm.ctpop.v2i32']:
            self.assertNotIn(name,importer.Importer.INTEGER_POPULATION_COUNT_INTRINSICS)
if __name__=='__main__':unittest.main()
