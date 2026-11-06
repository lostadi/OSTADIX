"""Original whole-unit opaque declarations; source controls, never runtime proof."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
SDK = Path('/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib')
LIB = SDK/'riscv64-linux-gnu/libLLVM.so.22.1'
PIN = '8617d27fecff5e31785eed07ee1cd7665e083bb689b6fb13266956d5231afe83'
AUDIT = Path('/home/orangepi/ostadix-BM/target/oversight-20261021/cpython-opaque-external-global-provider-audit-r3/audit.json')
AUDIT_SHA = '95d383291ceb42b93b560195e15621e936eac388d4e79ab557bf169cbe38aec3'
SOURCE_BUFFERS = {}
RETENTION_ADAPTER = None  # Optional, explicit lossless evidence sink; source inputs remain plain.
package = types.ModuleType('scripts')
package.__path__ = [str(ROOT/'scripts')]
sys.modules['scripts'] = package


def artifact(path):
    path = Path(path)
    if RETENTION_ADAPTER is not None:
        encoded = RETENTION_ADAPTER.record_for(path)
        if encoded is not None:
            return encoded
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def load(name, path):
    data = path.read_bytes()
    SOURCE_BUFFERS[str(path)] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = name.rpartition('.')[0]
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


importer = load('scripts.ocore_llvm_import', ROOT/'scripts/ocore_llvm_import.py')
inventory = load('opaque_independent_inventory', ROOT/'tests/ocore_llvm_source_inventory.py')
HEADER = ('target triple = "riscv64-unknown-linux-gnu"\n'
          'target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"\n')
NAMED = HEADER + '''%original.forward = type opaque
%original.empty = type {}
@opaque_a = external global %original.forward, align 1
@opaque_b = external constant %original.forward, align 8
@original_empty = external global %original.empty, align 1
@original_cold = global i64 8675309, align 8
define ptr @original_address() { ret ptr @opaque_a }
define i64 @original_cold_body() { ret i64 123456789 }
'''
ANONYMOUS = HEADER + '''%0 = type opaque
%1 = type opaque
@first = external global %0, align 1
@shared = external global %0, align 1
@distinct = external global %1, align 1
define ptr @original_address() { ret ptr @first }
'''


class OpaqueGlobalSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent = Path(os.environ.get('OCORE_OPAQUE_RETAIN', '/tmp'))
        parent.mkdir(parents=True, exist_ok=True)
        cls.directory = Path(tempfile.mkdtemp(prefix='opaque-whole-units-', dir=parent))
        cls.reader = inventory.Reader(LIB, PIN)
        cls.records = []
        cls.audit_pin = artifact(AUDIT)
        if cls.audit_pin['sha256'] != AUDIT_SHA:
            raise AssertionError('original consumer/provider discovery identity changed')
        cls.original = json.loads(AUDIT.read_bytes())
        if (cls.original['consumer_count'], cls.original['symbol_count'], cls.original['provider_unit_count']) != (13, 17, 14):
            raise AssertionError('original opaque cohort membership changed')

    @classmethod
    def tearDownClass(cls):
        (cls.directory/'source-controls.json').write_text(json.dumps({
            'records': cls.records, 'original_discovery': cls.audit_pin,
            'exact_executed_support_buffers': SOURCE_BUFFERS,
            'native_verifier_executed': False, 'new_rust_tests_executed': False,
            'native_execution_qualified': False, 'provider_closure_complete': False,
            'runtime_accepted': False, 'all_isa_qualified': False,
        }, indent=2) + '\n')
        if artifact(AUDIT) != cls.audit_pin:
            raise AssertionError('original discovery changed during source controls')

    def read_original(self, label, text=None, path=None):
        original = Path(path) if path is not None else self.directory/(label+'.ll')
        if path is None:
            original.write_text(text)
        before = artifact(original)
        module = importer.import_module(original, LIB, expected_sha256=PIN)
        source = self.reader.read(original)
        proof = inventory.check_inventory(source, module)
        outputs = {}
        for kind, value in [('module', module), ('source', source), ('inventory', proof)]:
            out = self.directory/(label+'.'+kind+'.json')
            out.write_text(json.dumps(value, indent=2) + '\n')
            outputs[kind] = artifact(out)
        self.assertEqual(artifact(original), before)
        self.records.append({'positive': label, 'original': before, **outputs})
        return module, source

    def mutation(self, label, module, source, message):
        path = self.directory/(label+'.mutant.native.json')
        path.write_text(json.dumps(module, indent=2) + '\n')
        with self.assertRaisesRegex(inventory.InventoryMismatch, message):
            inventory.check_inventory(source, module)
        self.records.append({'mutation': label, 'module': artifact(path),
                             'expected_diagnostic': message, 'rust_verifier_validity_unrun': True})

    def test_all_thirteen_unchanged_complete_original_cpython_units(self):
        ids = [row['id'] for row in self.original['consumers']]
        self.assertEqual(len(ids), 13)
        self.assertEqual(len(set(ids)), 13)
        names = set()
        for row in self.original['consumers']:
            with self.subTest(unit=row['id']):
                self.assertEqual(artifact(row['input']['path']), {k: row['input'][k] for k in ['path', 'bytes', 'sha256']})
                source_pin = artifact(row['source']['path'])
                self.assertEqual(source_pin, {k: row['source'][k] for k in ['path', 'bytes', 'sha256']})
                module, source = self.read_original('original-'+row['id'].replace(':', '-'), path=row['input']['path'])
                self.assertEqual({f['name'] for f in module['functions']}, set(source['functions']))
                self.assertEqual({g['name'] for g in module['globals']}, set(source['globals']))
                self.assertEqual(module['provenance']['source_function_count'], len(source['functions']))
                self.assertEqual(module['provenance']['source_global_count'], len(source['globals']))
                for global_ in module['globals']:
                    if module['types'][global_['ty']]['kind'] == 'opaque_struct':
                        names.add(global_['name'])
                        self.assertIsNone(global_['initializer'])
                        self.assertEqual(global_['alignment'], 1)
                self.assertEqual(artifact(row['source']['path']), source_pin)
        self.assertEqual(names, set(self.original['distinct_opaque_external_symbols']))
        self.assertEqual(len(names), 17)

    def test_named_opaque_empty_structure_and_unused_original_symbols_are_distinct(self):
        module, source = self.read_original('named-and-empty', NAMED)
        globals_ = {g['name']: g for g in module['globals']}
        self.assertEqual(module['types'][globals_['opaque_a']['ty']], {'kind': 'opaque_struct', 'name': 'original.forward'})
        self.assertEqual(globals_['opaque_a']['ty'], globals_['opaque_b']['ty'])
        self.assertEqual(module['types'][globals_['original_empty']['ty']], {'kind': 'struct', 'fields': [], 'packed': False})
        self.assertEqual(source['opaque_global_types'], [{'name': 'original.forward', 'globals': ['opaque_a', 'opaque_b']}])
        self.assertEqual(len(module['functions']), 2)
        self.assertEqual(len(module['globals']), 4)
        self.assertEqual(globals_['opaque_b']['alignment'], 8)
        self.assertTrue(globals_['opaque_b']['constant'])

    def test_anonymous_type_identity_partition_retains_shared_and_distinct_types(self):
        module, source = self.read_original('anonymous-partition', ANONYMOUS)
        globals_ = {g['name']: g for g in module['globals']}
        self.assertEqual(globals_['first']['ty'], globals_['shared']['ty'])
        self.assertNotEqual(globals_['first']['ty'], globals_['distinct']['ty'])
        self.assertEqual(source['opaque_global_types'], [
            {'name': None, 'globals': ['distinct']}, {'name': None, 'globals': ['first', 'shared']}])

    def test_welltyped_identity_empty_structure_omission_and_alignment_mutations_refuse(self):
        module, source = self.read_original('mutation-baseline', ANONYMOUS)
        for mutation in ['merge', 'split', 'empty', 'rename', 'omission', 'alignment', 'constant']:
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(module)
                globals_ = {g['name']: g for g in changed['globals']}
                ident = globals_['first']['ty']
                message = 'opaque global type identity partition changed'
                if mutation == 'merge':
                    old_distinct = globals_['distinct']['ty']
                    self.assertNotEqual(old_distinct, ident)
                    self.assertEqual(changed['types'][old_distinct]['kind'], 'opaque_struct')
                    globals_['distinct']['ty'] = ident
                    changed['types'][old_distinct] = {'kind': 'int', 'bits': 64}
                elif mutation == 'split':
                    changed['types'].append(copy.deepcopy(changed['types'][ident]))
                    globals_['shared']['ty'] = len(changed['types'])-1
                elif mutation == 'empty':
                    changed['types'][ident] = {'kind': 'struct', 'fields': [], 'packed': False}
                elif mutation == 'rename':
                    changed['types'][ident]['name'] = 'invented.source.name'
                elif mutation == 'omission':
                    changed['globals'].remove(globals_['shared'])
                    changed['provenance']['source_global_count'] -= 1
                    self.assertEqual(changed['provenance']['source_global_count'], len(changed['globals']))
                elif mutation == 'alignment':
                    globals_['first']['alignment'] = 8
                    message = 'global alignment changed'
                else:
                    globals_['first']['constant'] = True
                    message = 'global storage contract changed'
                self.mutation(mutation, changed, source, message)

    def test_text_and_bitcode_preserve_exact_opaque_declaration_identity(self):
        tool = SDK/'llvm-22/bin/llvm-as'
        before = artifact(tool)
        original = self.directory/'opaque-original.ll'
        bitcode = self.directory/'opaque-original.bc'
        original.write_text(ANONYMOUS)
        command = [str(tool), str(original), '-o', str(bitcode)]
        completed = subprocess.run(command, capture_output=True, check=True)
        self.records.append({'command': command, 'returncode': completed.returncode,
                             'stdout_hex': completed.stdout.hex(), 'stderr_hex': completed.stderr.hex(), 'tool': before})
        module, source = self.read_original('bitcode-original', path=bitcode)
        self.assertEqual(module['provenance']['input_sha256'], artifact(bitcode)['sha256'])
        self.assertEqual(len(source['opaque_global_types']), 2)
        self.assertEqual(artifact(tool), before)

    def test_unsupported_unsized_aggregate_tls_and_address_space_keep_explicit_refusals(self):
        cases = {
            'nested': '%O = type opaque\n%Holder = type { %O }\n@unsupported = external global %Holder\n',
            'tls': '%O = type opaque\n@unsupported = external thread_local global %O\n',
            'address-space': '%O = type opaque\n@unsupported = external addrspace(1) global %O\n',
        }
        for label, body in cases.items():
            with self.subTest(profile=label):
                path = self.directory/('unsupported-'+label+'.ll')
                path.write_text(HEADER+body)
                before = artifact(path)
                with self.assertRaises(importer.ImportFailure) as caught:
                    importer.import_module(path, LIB, expected_sha256=PIN)
                self.records.append({'refused_original': before, 'diagnostic': str(caught.exception),
                                     'scope': 'Python import refusal, not new Rust verifier execution'})
                self.assertEqual(artifact(path), before)

    def test_all_fourteen_original_provider_units_retain_real_sized_definitions(self):
        definitions = {}
        names = set(self.original['distinct_opaque_external_symbols'])
        self.assertEqual(len(self.original['provider_units']), 14)
        for row in self.original['provider_units']:
            with self.subTest(provider=row['id']):
                before = artifact(row['input']['path'])
                self.assertEqual(before, {k: row['input'][k] for k in ['path', 'bytes', 'sha256']})
                source_pin = artifact(row['source']['path'])
                self.assertEqual(source_pin, {k: row['source'][k] for k in ['path', 'bytes', 'sha256']})
                source = self.reader.read(row['input']['path'])
                output = self.directory/('provider-'+row['id'].replace(':', '-')+'.source.json')
                output.write_text(json.dumps(source, indent=2)+'\n')
                for name in names & source['globals'].keys():
                    global_ = source['globals'][name]
                    if global_['initializer'] is not None:
                        self.assertEqual(global_['type']['kind'], 'struct')
                        self.assertTrue(global_['type']['fields'])
                        self.assertNotIn(name, definitions)
                        definitions[name] = {'unit': row['id'], 'original': before, 'type': global_['type']}
                self.assertEqual(artifact(row['input']['path']), before)
                self.assertEqual(artifact(row['source']['path']), source_pin)
                self.records.append({'original_provider_source_only': row['id'], 'original': before,
                                     'full_source_inventory': artifact(output), 'provider_lowered_or_closed': False})
        self.assertEqual(set(definitions), names)
        self.records.append({'original_sized_definition_discovery': definitions,
                             'new_runtime_refinement_rust_tests_unrun': True})


if __name__ == '__main__':
    unittest.main(verbosity=2)
