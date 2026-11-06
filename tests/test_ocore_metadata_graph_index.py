"""Exact before/after verification for borrowed scoped-alias block indexing.

The timing carrier uses byte-extracted production graph-check bodies in one
matched executable. It excludes parsing and all other compiler/verifier work.
Original-unit readmission remains a source gate, not runtime qualification.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {
    "x86_64": ("x86_64-unknown-linux-musl", "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"),
    "aarch64": ("aarch64-unknown-linux-musl", "e-m:e-p270:32:32-p271:32:32-p272:64:64-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32"),
    "riscv64": ("riscv64-unknown-linux-musl", "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"),
}
METADATA = r'''
!0 = distinct !{!0, !"domain\00\FF<0xCAFE>"}
!1 = distinct !{!1, !0, !"same"}
!2 = distinct !{!2, !0, !"same"}
!3 = !{!1}
!4 = !{!2, !1, !2}
'''


def pin(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def source(isa, functions, blocks, duplicate_declaration=False):
    triple, layout = PROFILES[isa]
    lines = [f'target triple = "{triple}"', f'target datalayout = "{layout}"',
             'declare void @llvm.experimental.noalias.scope.decl(metadata)']
    for function in range(functions):
        lines += [f'define i64 @f{function}(ptr %p) {{']
        for block in range(blocks):
            lines += [f'b{block}:']
            if block == 0 or (duplicate_declaration and block == blocks - 1):
                lines += [' call void @llvm.experimental.noalias.scope.decl(metadata !3), !noalias !4, !alias.scope !3']
            attachment = '!alias.scope !3, !noalias !4' if block % 2 else '!noalias !4, !alias.scope !3'
            lines += [f' %v{block} = load i64, ptr %p, align 8, {attachment}']
            lines += [f' br label %b{block + 1}' if block + 1 < blocks else f' ret i64 %v{block}']
        lines += ['}']
    return '\n'.join(lines) + '\n' + METADATA


class MetadataGraphIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before = Path(os.environ['OCORE_METADATA_INDEX_BEFORE'])
        cls.after = Path(os.environ['OCORE_METADATA_INDEX_AFTER'])
        cls.library = Path(os.environ['OCORE_METADATA_LLVM_LIBRARY'])
        cls.sdk = Path(os.environ['OCORE_METADATA_LLVM_BIN'])
        cls.environment = dict(os.environ, PATH=str(cls.sdk) + ':' + os.environ['PATH'], PYTHONDONTWRITEBYTECODE='1')
        cls.temporary = None
        if os.environ.get('OCORE_METADATA_INDEX_OUTPUT'):
            cls.output = Path(os.environ['OCORE_METADATA_INDEX_OUTPUT'])
            cls.output.mkdir(parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='ocore-metadata-index-')
            cls.output = Path(cls.temporary.name)
        helper = Path(__file__).with_name('ocore_metadata_graph_oracle.py')
        spec = importlib.util.spec_from_file_location('index_independent_llvm_oracle', helper)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.oracle = module.GraphOracle(cls.library)
        cls.pins = [pin(x) for x in [cls.before, cls.after, cls.library, cls.sdk / 'llvm-as', helper,
                    Path(__file__), ROOT / 'crates/ostadix-api/src/ocore/native_verify.rs',
                    ROOT / 'scripts/ocore_llvm_import.py', ROOT / 'tools/ocore-runtime/acceptance/check_runtime.py',
                    ROOT / 'src/bin/olangc/native_runtime/source_inventory.py']]
        cls.commands = []
        cls.fixtures = {}
        for label, compiler in [('before', cls.before), ('after', cls.after)]:
            catalog = json.loads(cls.command([compiler, '--list-targets'], label + '-catalog').stdout)
            if {x['target'] for x in catalog['targets']} != {x + '-unknown-none' for x in PROFILES}:
                raise AssertionError('new implemented ISA requires an explicit graph-index profile')

    @classmethod
    def tearDownClass(cls):
        write(cls.output / 'commands.json', cls.commands)
        after = [pin(x['path']) for x in cls.pins]
        if after != cls.pins:
            raise AssertionError('source/tool bytes changed during graph-index tests')
        write(cls.output / 'source-tools.json', {'before': cls.pins, 'after': after})
        write(cls.output / 'inventory.json', [pin(x) for x in cls.output.rglob('*') if x.is_file()])
        if cls.temporary:
            cls.temporary.cleanup()

    @classmethod
    def command(cls, argv, label, success=True):
        result = subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=cls.environment, timeout=300)
        index = len(cls.commands)
        stdout = cls.output / f'{index:04d}-{label}.stdout'
        stderr = cls.output / f'{index:04d}-{label}.stderr'
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        cls.commands.append({'argv': [str(x) for x in argv], 'exit': result.returncode,
                             'stdout': pin(stdout), 'stderr': pin(stderr)})
        if success and result.returncode:
            raise AssertionError(f'{argv}: {result.stderr.decode(errors="replace")}')
        return result

    @classmethod
    def import_pair(cls, path, isa, label, success=True):
        modules = []
        for variant, compiler in [('before', cls.before), ('after', cls.after)]:
            output = cls.output / f'{label}-{variant}.native-ir.json'
            raw = cls.output / f'{label}-{variant}.raw.json'
            result = cls.command([compiler, path, '--input-kind', 'llvm-ir', '--emit', 'mir',
                '--target', isa + '-unknown-none', '--llvm-library', cls.library,
                '--llvm-sha256', pin(cls.library)['sha256'], '--llvm-metadata-diagnostics', raw,
                '-o', output], label + '-' + variant, success)
            modules.append((output, raw, result))
        if success:
            if modules[0][0].read_bytes() != modules[1][0].read_bytes():
                raise AssertionError('indexing changed a canonical source/module byte')
            data = json.loads(modules[1][0].read_text())
            graph = data['provenance']['noalias_metadata_graph_source']
            oracle = cls.oracle.read(path)
            if graph['nodes'] != oracle['nodes'] or graph['roots'] != oracle['roots']:
                raise AssertionError('public module differs from independent original LLVM graph')
            for _, raw, _ in modules:
                sidecar = json.loads(raw.read_text())
                if (sidecar['graph_source'] != graph or sidecar['input_sha256'] != pin(path)['sha256']
                        or sidecar['parser']['sha256'] != pin(cls.library)['sha256']):
                    raise AssertionError('raw diagnostic source/parser/graph binding changed')
        else:
            for output, _, result in modules:
                if result.returncode == 0 or output.exists():
                    raise AssertionError('invalid original metadata was admitted')
            if modules[0][2].stderr != modules[1][2].stderr:
                raise AssertionError('first verifier error changed')
        return modules

    @classmethod
    def fixture(cls, isa, functions, blocks, bitcode=False):
        key = (isa, functions, blocks, bitcode)
        if key not in cls.fixtures:
            label = f'{isa}-{functions}f-{blocks}b-' + ('bc' if bitcode else 'll')
            text = cls.output / (label + '.ll')
            text.write_text(source(isa, functions, blocks))
            path = text
            if bitcode:
                path = cls.output / (label + '.bc')
                cls.command([cls.sdk / 'llvm-as', text, '-o', path], label + '-serialize')
            pair = cls.import_pair(path, isa, label)
            cls.fixtures[key] = (path, pair[1][0])
        return cls.fixtures[key]

    def test_many_functions_blocks_preserve_exact_graph_provenance_and_order(self):
        for isa in PROFILES:
            for bitcode in [False, True]:
                with self.subTest(isa=isa, bitcode=bitcode):
                    _, path = self.fixture(isa, 16, 8, bitcode)
                    module = json.loads(path.read_text())
                    self.assertEqual(len(module['noalias_metadata']['attachments']), 16 * 9)
                    self.assertEqual(len(module['provenance']['noalias_metadata_graph_source']['roots']), 16 * 19)
        functions = int(os.environ.get('OCORE_METADATA_INDEX_STRESS_FUNCTIONS', '128'))
        blocks = int(os.environ.get('OCORE_METADATA_INDEX_STRESS_BLOCKS', '32'))
        _, path = self.fixture('x86_64', functions, blocks)
        module = json.loads(path.read_text())
        self.assertEqual(len(module['noalias_metadata']['attachments']), functions * (blocks + 1))
        write(self.output / 'stress-shape.json', {'functions': functions, 'blocks_per_function': blocks,
            'blocks': functions * blocks, 'attachments': functions * (blocks + 1), 'module': pin(path),
            'scope': 'authored compiler graph stress, no application/runtime equivalence qualification'})

    def test_order_dominance_and_graph_rejection_parity(self):
        _, path = self.fixture('x86_64', 3, 4)
        good = json.loads(path.read_text())
        cases = []
        def variant(label, change):
            changed = copy.deepcopy(good)
            change(changed)
            cases.append((label, changed))
        variant('swap-inventory', lambda m: m['noalias_metadata']['attachments'].__setitem__(slice(0, 2), list(reversed(m['noalias_metadata']['attachments'][:2]))))
        variant('duplicate-site', lambda m: m['noalias_metadata']['attachments'].insert(0, copy.deepcopy(m['noalias_metadata']['attachments'][0])))
        variant('wrong-function', lambda m: m['noalias_metadata']['attachments'][0]['site'].__setitem__('function', 'f_missing'))
        variant('wrong-block', lambda m: m['noalias_metadata']['attachments'][0]['site'].__setitem__('block', 9000))
        variant('attachment-order', lambda m: m['noalias_metadata']['attachments'][0]['source_order'].reverse())
        variant('root-order', lambda m: m['provenance']['noalias_metadata_graph_source']['roots'].reverse())
        variant('missing-root', lambda m: m['provenance']['noalias_metadata_graph_source']['roots'].pop())
        variant('unknown-graph', lambda m: m['provenance']['noalias_metadata_graph_source'].__setitem__('schema', 'unknown-v999'))
        graph = good['provenance']['noalias_metadata_graph_source']
        string = next(n['id'] for n in graph['nodes'] if n['kind'] == 'string' and n['bytes'])
        variant('opaque-byte', lambda m: m['provenance']['noalias_metadata_graph_source']['nodes'][string]['bytes'].__setitem__(0, 0))
        records = []
        for label, changed in cases:
            forged = self.output / (label + '.json')
            write(forged, changed)
            errors = []
            for name, compiler in [('before', self.before), ('after', self.after)]:
                result = self.command([compiler, forged, '--input-kind', 'native-ir', '--verify-native'], label + '-' + name, False)
                self.assertNotEqual(result.returncode, 0)
                errors.append(result.stderr)
            self.assertEqual(errors[0], errors[1])
            records.append({'label': label, 'input': pin(forged), 'same_rejection': True})
        for isa in PROFILES:
            text = self.output / (isa + '-dominated.ll')
            text.write_text(source(isa, 3, 4, duplicate_declaration=True))
            bc = self.output / (isa + '-dominated.bc')
            self.command([self.sdk / 'llvm-as', text, '-o', bc], isa + '-dominated-serialize')
            for kind, original in [('ll', text), ('bc', bc)]:
                self.import_pair(original, isa, isa + '-dominated-' + kind, False)
        write(self.output / 'negative-parity.json', records)

    def test_isolated_production_graph_checker_timing(self):
        carrier = Path(os.environ['OCORE_METADATA_INDEX_BENCH'])
        functions = int(os.environ.get('OCORE_METADATA_INDEX_STRESS_FUNCTIONS', '128'))
        blocks = int(os.environ.get('OCORE_METADATA_INDEX_STRESS_BLOCKS', '32'))
        samples = []
        for count, width in [(16, 8), (64, 16), (functions, blocks)]:
            _, module = self.fixture('x86_64', count, width)
            result = self.command([carrier, module, '7'], f'benchmark-{count}f-{width}b')
            record = json.loads(result.stdout)
            self.assertTrue(record['before_accepted'] and record['after_accepted'])
            self.assertEqual(len(record['before_ns']), 7)
            self.assertEqual(len(record['after_ns']), 7)
            samples.append(dict(record, module=pin(module), functions=count, blocks_per_function=width))
        write(self.output / 'isolated-graph-timing.json', {'carrier': pin(carrier), 'samples': samples,
            'scope': 'same-binary exact extracted graph reconstruction/check only; parsing/compiler/other verifier passes excluded; no total compile or OS speedup claim'})

    def test_all_thirteen_original_units_remain_exact_and_strictly_readmitted(self):
        records = json.loads(Path(os.environ['OCORE_METADATA_INDEX_ORIGINAL_CASES']).read_text())['units']
        self.assertEqual(len(records), 13)
        outputs = []
        for index, record in enumerate(records):
            original = Path(record['input']['path'])
            self.assertEqual(pin(original), record['input'])
            pair = self.import_pair(original, record['isa'], f'original-{index:02}')
            module_path = pair[1][0]
            self.assertEqual(module_path.read_bytes(), Path(record['modules'][0]['path']).read_bytes())
            module = json.loads(module_path.read_text())
            request = self.output / f'original-{index:02}-request.json'
            tools = self.output / f'original-{index:02}-tools.json'
            write(request, {'schema': 'ocore-original-unit-readmission-request-v1', 'unit_id': record['unit_id'],
                'original_unit': {'id': record['unit_id'], 'llvm_ir': pin(original)}, 'claimed_module': pin(module_path),
                'target': {'target': record['isa'] + '-unknown-none', 'native_target': module['target'], 'import_profiles': {}}})
            write(tools, {'schema': 'ocore-original-runtime-toolchain-v1', 'tools': {'ocorec': pin(self.after),
                'llvm_library': pin(self.library), 'inventory_helper': pin(ROOT / 'src/bin/olangc/native_runtime/source_inventory.py')},
                'environment': {'PATH': self.environment['PATH'], 'PYTHONDONTWRITEBYTECODE': '1'}})
            directory = self.output / f'original-{index:02}-readmission'
            self.command(['/usr/bin/python3', '-I', ROOT / 'tools/ocore-runtime/acceptance/check_runtime.py',
                          'readmit-unit', request, '--tools', tools, '--output', directory], f'original-{index:02}-readmit')
            report = json.loads((directory / 'report.json').read_text())
            self.assertTrue(report['unit_readmission_complete'])
            self.assertFalse(report['runtime_accepted'])
            self.assertFalse(report['complete'])
            outputs.append({'unit_id': record['unit_id'], 'isa': record['isa'], 'input': pin(original),
                            'canonical': pin(module_path), 'readmission': pin(directory / 'report.json')})
        write(self.output / 'original-thirteen.json', {'ok': True, 'records': outputs, 'runtime_accepted': False})


if __name__ == '__main__':
    unittest.main()
