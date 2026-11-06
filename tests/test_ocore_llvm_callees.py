"""Original SSA and named-direct target promise transport, source controls only.

These inspect full imported units. They never execute implementation IR,
claim native verification, or resolve the original platform providers.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests.ocore_llvm_source_inventory import Reader, check_inventory, InventoryMismatch

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = Path('/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib/riscv64-linux-gnu/libLLVM.so.22.1')
PIN = '8617d27fecff5e31785eed07ee1cd7665e083bb689b6fb13266956d5231afe83'
LLVM_AS = Path('/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib/llvm-22/bin/llvm-as')
AS_PIN = 'a65178bc8c07c44ece640ed8181dda3c9267c9215d596ea480ec983fc2428e23'
ORIGINAL = Path('/home/orangepi/ostadix-BM/target/original-lua-source-recipe-20261017-ndpqjeew/compiled/capture/units/6ec41392aaee4825b7ec102e7584f9dc/unit-0.ll')
ORIGINAL_PIN = 'd101905dae5e4120423c2291ce657c6db815c3d7ce0b520cfbb8cd5a7af1f6ff'


CPYTHON_ORIGINALS = [('mathmodule', '/home/orangepi/ostadix-BM/target/cpython-expansion-20261018/original-cpython-source-recipe-20261018-uuidfix/compiled/capture/units/3af5f7c4c4154b3c832a2adb4a3ea7b0/unit-0.ll', '5c3d9258f19bca0934c4b1725e1094873a97ceb1d3902b8b0bb6cd734bf1ad55', 3, 2), ('zlibmodule', '/home/orangepi/ostadix-BM/target/cpython-expansion-20261018/original-cpython-source-recipe-20261018-uuidfix/compiled/capture/units/3c3e4854e3e54464b2570d719bee6f6d/unit-0.ll', '4cd2b5cf11d9555bc4872577150abf46ecb557e98599cb2508a2115078fbcbb0', 2, 0), ('pyexpat', '/home/orangepi/ostadix-BM/target/cpython-expansion-20261018/original-cpython-source-recipe-20261018-uuidfix/compiled/capture/units/64344c519ce94722a5c499b7a42dce43/unit-0.ll', 'e4fec66828fb9e2a8b37224bc1dcaca411d5adf0f8119e7485f354f381a210ee', 4, 0)]


def identity(path):
    p = Path(path).resolve(strict=True)
    raw = p.read_bytes()
    return {'path': str(p), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def fixture(triple='x86_64-unknown-linux-gnu'):
    return (f'target triple = "{triple}"\n' + '''target datalayout = "e-p:64:64-i64:64-i128:128-n8:16:32:64-S128"
@resource = global i64 17, align 8
@initial = global ptr @left, align 8
declare i64 @provider(i64)
define i64 @left(i64 %x) { %a = add i64 %x, 1 ret i64 %a }
define i64 @right(i64 %x) { %a = sub i64 %x, 1 ret i64 %a }
define i64 @cold(ptr %f, i64 %x) {
 %r = call i64 %f(i64 %x), !callees !2
 ret i64 %r
}
define i64 @driver(ptr %f, ptr %g, i64 %x) {
 %r = call i64 %f(i64 %x), !callees !0
 %s = call i64 %f(i64 %r)
 %t = call i64 %g(i64 %s), !callees !1
 ret i64 %t
}
!0 = !{ptr @left, ptr @right, ptr @left}
!1 = !{}
!2 = !{ptr @provider}
''').encode()


class CalleesSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert __debug__ and __import__('sys').flags.optimize == 0
        cls.directory = Path(tempfile.mkdtemp(prefix='callees-source-', dir=os.environ.get('OCORE_CALLEES_RETAIN', '/tmp')))
        cls.inputs = [ROOT / p for p in ('scripts/ocore_llvm_import.py', 'scripts/ocore_llvm_bitcode.py',
                      'tests/ocore_llvm_source_inventory.py', 'crates/ostadix-api/src/ocore/native_ir.rs',
                      'crates/ostadix-api/src/ocore/native_verify.rs', 'tests/test_ocore_llvm_callees.py')]
        cls.inputs += [LIBRARY, LLVM_AS, ORIGINAL] + [Path(row[1]) for row in CPYTHON_ORIGINALS]
        cls.before = [identity(p) for p in cls.inputs]
        assert identity(LLVM_AS)['sha256'] == AS_PIN
        assert identity(ORIGINAL)['sha256'] == ORIGINAL_PIN
        cls.reader = Reader(LIBRARY, PIN)
        cls.records = []

    @classmethod
    def tearDownClass(cls):
        after = [identity(p) for p in cls.inputs]
        report = {'schema': 'ocore-callees-source-controls/v1', 'before': cls.before, 'after': after,
                  'source_and_tools_stable': cls.before == after, 'records': cls.records,
                  'native_compiler_run': False, 'native_verifier_run': False,
                  'native_execution_qualified': False, 'provider_closure_complete': False, 'runtime_accepted': False}
        (cls.directory / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
        if cls.before != after:
            raise AssertionError('source or tool drift')

    def imported(self, label, raw):
        path = self.directory / (label + '.ll')
        path.write_bytes(raw)
        module = importer.import_module(path, LIBRARY, expected_sha256=PIN)
        native = self.directory / (label + '.candidate.native.json')
        native.write_text(json.dumps(module, indent=2) + '\n')
        source = self.reader.read(path)
        report = check_inventory(source, module)
        self.records.append({'original': identity(path), 'candidate': identity(native), 'inventory': report})
        return module, source

    def test_whole_profile_units_preserve_cold_functions_initializers_and_all_calls(self):
        for triple in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'riscv64-unknown-linux-gnu'):
            module, source = self.imported(triple, fixture(triple))
            self.assertEqual(len(module['functions']), 5)
            self.assertEqual(len(module['globals']), 2)
            self.assertEqual(sum(len(f['ssa_indirect_calls']) for f in source['functions'].values()), 4)
            self.assertEqual(sum(len(f.get('call_target_constraints', [])) for f in module['functions']), 3)

    def test_whole_original_lua_cli_retains_all_three_exact_target_promises(self):
        raw = ORIGINAL.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), ORIGINAL_PIN)
        module, source = self.imported('original-lua-cli', raw)
        constraints = [c for f in module['functions'] for c in f['call_target_constraints']]
        self.assertEqual(len(constraints), 3)
        self.assertTrue(all(c['callees'] == ['getenv', 'no_getenv'] for c in constraints))
        self.assertEqual([(c['site']['function'], c['site']['block'], c['site']['source_instruction']) for c in constraints],
                         [('pmain', 30, 4), ('pmain', 31, 1), ('doREPL', 0, 5)])
        self.assertGreater(len(source['functions']), 10)
        self.assertTrue(source['globals'])

    def test_absent_empty_duplicate_and_metadata_only_declaration_are_distinct(self):
        module, source = self.imported('distinct-lists', fixture())
        driver = next(f for f in module['functions'] if f['name'] == 'driver')
        self.assertEqual([c['callees'] for c in driver['call_target_constraints']], [['left', 'right', 'left'], []])
        self.assertEqual([c['site']['instruction'] for c in driver['call_target_constraints']], [0, 2])
        cold = next(f for f in module['functions'] if f['name'] == 'cold')
        self.assertEqual(cold['call_target_constraints'][0]['callees'], ['provider'])
        # Metadata retains a relation to the original declaration; it does not
        # manufacture an executable symbol operand, call, or linker dependency.
        self.assertNotIn('provider', source['functions']['cold']['symbol_references'])
        self.assertNotIn('provider', json.dumps(cold['blocks']))
        self.assertEqual(len(driver['blocks'][0]['instructions']), 3)

    def test_independent_inventory_rejects_same_typed_constraint_and_call_mutations(self):
        module, source = self.imported('mutations', fixture())
        for fault in ('drop', 'change-member', 'drop-duplicate', 'empty-to-absent', 'copy-to-unannotated',
                      'source-site', 'callee-ssa', 'argument', 'surplus-call', 'unused-declaration'):
            changed = copy.deepcopy(module)
            driver = next(f for f in changed['functions'] if f['name'] == 'driver')
            constraints = driver['call_target_constraints']
            calls = driver['blocks'][0]['instructions']
            if fault == 'drop': constraints.clear()
            elif fault == 'change-member': constraints[0]['callees'] = ['right']
            elif fault == 'drop-duplicate': constraints[0]['callees'].pop()
            elif fault == 'empty-to-absent': constraints.pop()
            elif fault == 'copy-to-unannotated': constraints[0]['site']['instruction'] = 1
            elif fault == 'source-site': constraints[0]['site']['source_instruction'] += 1
            elif fault == 'callee-ssa': calls[0]['operation']['callee'] = {'kind': 'value', 'id': driver['params'][1]['id']}
            elif fault == 'argument': calls[0]['operation']['args'][0] = {'kind': 'int', 'ty': driver['signature']['result'], 'bits': '0'}
            elif fault == 'surplus-call':
                extra = copy.deepcopy(calls[0]);extra['result']['id'] = 10000;calls.append(extra)
            else:
                declaration = next(f for f in changed['functions'] if f['name'] == 'provider')
                declaration['call_target_constraints'] = copy.deepcopy(constraints)
            with self.assertRaises(InventoryMismatch, msg=fault): check_inventory(source, changed)
            path = self.directory / (fault + '.mutation.native.json')
            path.write_text(json.dumps(changed, indent=2) + '\n')
            self.records.append({'mutation': fault, 'identity': identity(path), 'new_native_verifier_pending': True})

    def test_malformed_owners_members_and_unsupported_profiles_fail_closed_after_llvm_acceptance(self):
        raw = fixture().decode()
        cases = {
            'direct-outside-set': raw.replace('%r = call i64 %f(i64 %x), !callees !0', '%r = call i64 @provider(i64 %x), !callees !0'),
            'direct-empty': raw.replace('%r = call i64 %f(i64 %x), !callees !0', '%r = call i64 @left(i64 %x), !callees !1'),
            'direct-mixed-ABI': raw.replace('%r = call i64 %f(i64 %x), !callees !0', '%r = call i64 @left(i64 %x), !callees !0').replace('define i64 @right', 'define fastcc i64 @right'),
            'direct-alias': raw.replace('@resource =', '@left_alias = alias i64 (i64), ptr @left\n@resource =').replace('%r = call i64 %f(i64 %x), !callees !0', '%r = call i64 @left_alias(i64 %x), !callees !0'),
            'global-member': raw.replace('!0 = !{ptr @left, ptr @right, ptr @left}', '!0 = !{ptr @resource}'),
            'integer-member': raw.replace('!0 = !{ptr @left, ptr @right, ptr @left}', '!0 = !{i64 0}'),
            'add-owner': raw.replace('%a = add i64 %x, 1 ret i64 %a', '%a = add i64 %x, 1, !callees !0 ret i64 %a'),
            'function-owner': raw.replace('define i64 @left(i64 %x) {', 'define i64 @left(i64 %x) !callees !0 {'),
            'variadic-indirect': raw.replace('%r = call i64 %f(i64 %x), !callees !0', '%r = call i64 (i64, ...) %f(i64 %x), !callees !0'),
        }
        for label, text in cases.items():
            path = self.directory / (label + '.ll');path.write_text(text)
            bitcode = self.directory / (label + '.bc')
            argv = [str(LLVM_AS), str(path), '-o', str(bitcode)]
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.records.append({'negative': label, 'original': identity(path), 'llvm_as_argv': argv,
                                 'llvm_as_exit_code': p.returncode, 'stderr': p.stderr.decode(errors='replace')})
            self.assertEqual(p.returncode, 0, label)
            with self.assertRaises(importer.ImportFailure) as caught:
                importer.import_module(path, LIBRARY, expected_sha256=PIN)
            self.assertEqual(caught.exception.stage, 'import', (label, str(caught.exception)))
            self.assertIn('callees', str(caught.exception))

    def test_named_direct_and_ssa_promises_keep_whole_unit(self):
        raw = fixture().replace(b'%r = call i64 %f(i64 %x), !callees !0', b'%r = call i64 @left(i64 %x), !callees !0')
        module, source = self.imported('direct-and-ssa', raw)
        driver = next(f for f in module['functions'] if f['name'] == 'driver')
        self.assertEqual(driver['blocks'][0]['instructions'][0]['operation']['callee']['name'], 'left')
        self.assertEqual(driver['call_target_constraints'][0]['callees'], ['left', 'right', 'left'])
        self.assertEqual(sum(len(f['ssa_indirect_calls']) for f in source['functions'].values()), 3)
        self.assertEqual(len(module['functions']), 5)
        self.assertEqual(len(module['globals']), 2)

    def test_direct_target_and_promise_inventory_mutations_refuse(self):
        raw = fixture().replace(b'%r = call i64 %f(i64 %x), !callees !0', b'%r = call i64 @left(i64 %x), !callees !0')
        module, source = self.imported('direct-mutations', raw)
        for fault in ('operand-in-set', 'drop', 'reorder', 'site', 'cold-global'):
            with self.subTest(fault=fault):
                changed = copy.deepcopy(module)
                driver = next(f for f in changed['functions'] if f['name'] == 'driver')
                if fault == 'operand-in-set': driver['blocks'][0]['instructions'][0]['operation']['callee']['name'] = 'right'
                elif fault == 'drop': driver['call_target_constraints'].pop(0)
                elif fault == 'reorder': driver['call_target_constraints'][0]['callees'] = ['left', 'left', 'right']
                elif fault == 'site': driver['call_target_constraints'][0]['site']['source_instruction'] += 1
                else:
                    changed['globals'] = [g for g in changed['globals'] if g['name'] != 'resource']
                    changed['provenance']['source_global_count'] -= 1
                with self.assertRaises(InventoryMismatch): check_inventory(source, changed)
                path = self.directory / ('direct-' + fault + '.mutation.native.json')
                path.write_text(json.dumps(changed, indent=2) + '\n')
                self.records.append({'mutation': 'direct-' + fault, 'identity': identity(path), 'new_native_verifier_pending': True})

    def original_cpython(self, index):
        label, path, sha, direct_count, ssa_count = CPYTHON_ORIGINALS[index]
        raw = Path(path).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), sha)
        module, source = self.imported('original-cpython-' + label, raw)
        direct = sum(site.get('callees') is not None for f in source['functions'].values() for site in f['direct_call_sites'])
        ssa = sum(site['callees'] is not None for f in source['functions'].values() for site in f['ssa_indirect_calls'])
        self.assertEqual((direct, ssa), (direct_count, ssa_count))
        self.assertEqual(sum(len(f.get('call_target_constraints', [])) for f in module['functions']), direct + ssa)
        self.assertTrue(source['globals'])

    def test_whole_original_cpython_mathmodule(self):
        self.original_cpython(0)

    def test_whole_original_cpython_zlibmodule(self):
        self.original_cpython(1)

    def test_whole_original_cpython_pyexpat(self):
        self.original_cpython(2)

    def test_invoke_promise_preserves_its_zero_width_terminator_site(self):
        raw = b'''target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-p:64:64-i64:64-i128:128-n8:16:32:64-S128"
declare i32 @__gxx_personality_v0(...)
define i64 @left(i64 %x) { ret i64 %x }
define i64 @driver(ptr %f, i64 %x) personality ptr @__gxx_personality_v0 {
entry:
 %r = invoke i64 %f(i64 %x) to label %done unwind label %bad, !callees !0
done:
 ret i64 %r
bad:
 %e = landingpad {ptr, i32} cleanup
 resume {ptr, i32} %e
}
!0 = !{ptr @left}
'''
        for label, original in [('invoke', raw), ('direct-invoke', raw.replace(b'invoke i64 %f(', b'invoke i64 @left('))]:
            with self.subTest(label=label):
                module, _ = self.imported(label, original)
                driver = next(f for f in module['functions'] if f['name'] == 'driver')
                constraint = driver['call_target_constraints'][0]
                self.assertEqual(constraint['site']['instruction_count'], 0)
                self.assertEqual(constraint['site']['instruction'], len(driver['blocks'][0]['instructions']))
                self.assertEqual(driver['blocks'][0]['terminator']['op'], 'invoke')
                if label == 'direct-invoke':
                    self.assertEqual(driver['blocks'][0]['terminator']['callee']['name'], 'left')
                self.assertEqual(constraint['callees'], ['left'])
