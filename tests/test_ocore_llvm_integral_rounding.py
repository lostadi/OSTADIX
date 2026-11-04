"""Source-only IEEE rounding controls; no native or runtime acceptance.

The arithmetic oracle uses exact rational/integer mathematics. The evaluator
is test-only inspection of the expanded graph, never a product execution path.
"""
import copy
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests.ocore_llvm_source_inventory import Reader, check_inventory, InventoryMismatch

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = Path('/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib/riscv64-linux-gnu/libLLVM.so.22.1')
PIN = '8617d27fecff5e31785eed07ee1cd7665e083bb689b6fb13266956d5231afe83'
LLVM_AS = Path('/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib/llvm-22/bin/llvm-as')
FORMATS = {32: ('float', 23, 8), 64: ('double', 52, 11), 128: ('fp128', 112, 15)}


def identity(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def fixture(triple='x86_64-unknown-linux-gnu'):
    lines = [f'target triple = "{triple}"',
             'target datalayout = "e-p:64:64-i64:64-i128:128-n8:16:32:64-S128"',
             '@original_marker = global i64 12345, align 8',
             'declare i64 @original_provider(i64)',
             'define i64 @original_cold() { ret i64 98765 }']
    for width, (ty, _, _) in FORMATS.items():
        for kind in ('floor', 'ceil', 'trunc'):
            lines.extend([f'declare {ty} @llvm.{kind}.f{width}({ty})',
                f'define {ty} @{kind}_{width}({ty} %x) {{',
                f'%r = call {ty} @llvm.{kind}.f{width}({ty} %x)', f'ret {ty} %r }}'])
    return '\n'.join(lines).encode()


def exact_oracle(raw, width, kind):
    _, fraction, exponent = FORMATS[width]
    sign = raw >> (width - 1)
    mantissa = raw & ((1 << fraction) - 1)
    exp = (raw >> fraction) & ((1 << exponent) - 1)
    bias = (1 << (exponent - 1)) - 1
    if exp == (1 << exponent) - 1:
        return raw | (1 << (fraction - 1)) if mantissa else raw
    if not exp and not mantissa:
        return raw
    # Large finite inputs already have no fractional bits.
    if exp >= bias + fraction:
        return raw
    numerator = mantissa + ((1 << fraction) if exp else 0)
    power = (exp if exp else 1) - bias - fraction
    value = Fraction(numerator, 1 << -power) if power < 0 else Fraction(numerator << power)
    if sign:
        value = -value
    if kind == 'floor':
        whole = value.numerator // value.denominator
    elif kind == 'ceil':
        whole = -((-value.numerator) // value.denominator)
    else:
        whole = abs(value.numerator) // value.denominator
        whole = -whole if value < 0 else whole
    if whole == 0:
        return sign << (width - 1)
    magnitude, output_sign = abs(whole), int(whole < 0)
    top = magnitude.bit_length() - 1
    significand = magnitude << (fraction - top) if top <= fraction else magnitude >> (top - fraction)
    return (output_sign << (width - 1)) | ((top + bias) << fraction) | (significand & ((1 << fraction) - 1))


def evaluate_graph(module, function, raw):
    types = module['types']
    values = {function['params'][0]['id']: raw}
    def operand(item):
        if item['kind'] == 'value':
            return values[item['id']]
        if item['kind'] == 'int':
            return int(item['bits'])
        raise AssertionError(('unexpected test-only operand', item))
    for instruction in function['blocks'][0]['instructions']:
        operation = instruction['operation']
        ty = types[instruction['result']['ty']]
        mask = (1 << ty['bits']) - 1
        op = operation['op']
        if op in ('freeze', 'cast'):
            result = operand(operation['value'])
        elif op == 'select':
            result = operand(operation['on_true'] if operand(operation['condition']) else operation['on_false'])
        elif op == 'i_cmp':
            a, b = operand(operation['lhs']), operand(operation['rhs'])
            result = {'eq': lambda: a == b, 'ne': lambda: a != b,
                      'ult': lambda: a < b, 'uge': lambda: a >= b}[operation['predicate']]()
        elif op == 'binary':
            a, b = operand(operation['lhs']), operand(operation['rhs'])
            kind = operation['kind']
            if kind in ('shl', 'l_shr'):
                assert 0 <= b < ty['bits'], ('poisoning test-only shift', b, ty)
            result = {'and': lambda: a & b, 'or': lambda: a | b, 'xor': lambda: a ^ b,
                      'add': lambda: a + b, 'sub': lambda: a - b,
                      'shl': lambda: a << b, 'l_shr': lambda: a >> b}[kind]()
        else:
            raise AssertionError(('unexpected test-only operation', op))
        values[instruction['result']['id']] = int(result) & mask
    return operand(function['blocks'][0]['terminator']['value'])


class IntegralRoundingSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(tempfile.mkdtemp(prefix='integral-rounding-',
                              dir=os.environ.get('OCORE_INTEGRAL_ROUNDING_RETAIN', '/tmp')))
        cls.sources = [ROOT / 'scripts/ocore_llvm_import.py', ROOT / 'tests/ocore_llvm_source_inventory.py',
                       ROOT / 'crates/ostadix-api/src/ocore/native_verify.rs', Path(__file__), LIBRARY, LLVM_AS]
        cls.before = [identity(p) for p in cls.sources]
        cls.records = []
        cls.reader = Reader(LIBRARY, PIN)

    @classmethod
    def tearDownClass(cls):
        after = [identity(p) for p in cls.sources]
        record = {'before': cls.before, 'after': after, 'stable': cls.before == after,
                  'records': cls.records, 'native_compiler_run': False, 'native_execution': False,
                  'runtime_qualified': False, 'whole_provider_closure': False}
        (cls.directory / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
        if cls.before != after:
            raise AssertionError('source/tool drift during source controls')

    def imported(self, label, raw):
        source = self.directory / (label + '.ll'); source.write_bytes(raw)
        module = importer.import_module(source, LIBRARY, expected_sha256=PIN)
        path = self.directory / (label + '.candidate.native.json')
        path.write_text(json.dumps(module, indent=2) + '\n')
        inventory = self.reader.read(source)
        checked = check_inventory(inventory, module)
        self.records.append({'original': identity(source), 'native': identity(path), 'inventory': checked})
        return module, inventory

    def test_whole_units_all_nine_overloads_three_target_profiles(self):
        for triple in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'riscv64-unknown-linux-gnu'):
            module, original = self.imported(triple, fixture(triple))
            self.assertEqual(len(original['functions']), 20)
            self.assertEqual(len(module['globals']), 1)

    def test_exact_rational_oracle_signed_zero_subnormal_boundaries_and_nan_choice(self):
        module, _ = self.imported('arithmetic', fixture())
        rng = random.Random(0x1E6A1)
        cases = comparisons = 0
        for width, (_, fraction, exponent) in FORMATS.items():
            bias = (1 << (exponent - 1)) - 1
            exponents = {0, 1, bias - 2, bias - 1, bias, bias + 1,
                         bias + fraction - 1, bias + fraction, bias + fraction + 1,
                         (1 << exponent) - 2, (1 << exponent) - 1}
            corpus = {(sign << (width - 1)) | (e << fraction) | f for sign in (0, 1)
                      for e in exponents for f in (0, 1, (1 << (fraction - 1)) - 1,
                                                    1 << (fraction - 1), (1 << fraction) - 1)}
            corpus.update(rng.getrandbits(width) for _ in range(2048))
            for kind in ('floor', 'ceil', 'trunc'):
                function = next(f for f in module['functions'] if f['name'] == f'{kind}_{width}')
                for raw in sorted(corpus):
                    self.assertEqual(evaluate_graph(module, function, raw), exact_oracle(raw, width, kind),
                                     (kind, width, hex(raw)))
                    comparisons += 1
            cases += len(corpus)
        self.records.append({'independent_raw_input_cases': cases, 'source_graph_comparisons': comparisons,
                             'oracle': 'exact rational mathematics, no host floating arithmetic',
                             'native_execution': False})

    def test_inventory_detects_semantic_graph_mutations(self):
        module, original = self.imported('mutations', fixture())
        for fault in ('unsafe-shift', 'direction', 'zero-sign', 'quiet-nan', 'wrong-operand', 'arithmetic-flag'):
            changed = copy.deepcopy(module)
            function = next(f for f in changed['functions'] if f['name'] == 'floor_64')
            operations = [i['operation'] for i in function['blocks'][0]['instructions']]
            if fault == 'unsafe-shift':
                next(o for o in operations if o['op'] == 'binary' and o['kind'] == 'shl')['rhs'] = {'kind': 'int', 'ty': next(i for i,t in enumerate(changed['types']) if t == {'kind':'int','bits':64}), 'bits':'64'}
            elif fault == 'direction':
                next(o for o in operations if o['op'] == 'i_cmp' and o['predicate'] == 'ne')['predicate'] = 'eq'
            elif fault == 'zero-sign':
                next(o for o in operations if o['op'] == 'binary' and o['kind'] == 'and')['rhs']['bits'] = '0'
            elif fault == 'quiet-nan':
                next(o for o in operations if o['op'] == 'binary' and o['kind'] == 'or')['rhs']['bits'] = '0'
            elif fault == 'wrong-operand':
                next(o for o in operations if o['op'] == 'freeze')['value'] = {'kind':'float','ty':function['signature']['result'],'bits':'0'}
            else:
                next(o for o in operations if o['op'] == 'binary')['flags'] = ['nsw']
            with self.assertRaises(InventoryMismatch):
                check_inventory(original, changed)
            path = self.directory / (fault + '.native.json');path.write_text(json.dumps(changed))
            self.records.append({'semantic_mutation': fault, 'retained': identity(path),
                                 'independent_native_verification_pending': True})

    def test_nondefault_environment_and_fast_math_are_explicitly_unmet(self):
        for suffix, call in [('strictfp', ''), ('"denormal-fp-math"="preserve-sign,preserve-sign"', ''), ('', 'nnan ')]:
            raw = ('target triple = "x86_64-unknown-linux-gnu"\n'
                   'target datalayout = "e-p:64:64-i64:64"\n'
                   'declare double @llvm.floor.f64(double)\n'
                   f'define double @original(double %x) {suffix} {{\n'
                   f'%r = call {call}double @llvm.floor.f64(double %x)\nret double %r }}\n').encode()
            path = self.directory / f'unsupported-profile-{len(self.records)}.ll';path.write_bytes(raw)
            self.reader.read(path)  # actual independent LLVM acceptance, never count malformed input
            with self.assertRaises(importer.ImportFailure):
                importer.import_module(path, LIBRARY, expected_sha256=PIN)
            self.records.append({'explicit_unsupported_profile': identity(path)})

    def test_original_poison_and_undef_are_single_stable_refinements(self):
        lines = ['target triple = "x86_64-unknown-linux-gnu"',
                 'target datalayout = "e-p:64:64-i64:64"',
                 'declare double @llvm.floor.f64(double)']
        for argument in ('poison', 'undef'):
            lines.extend([f'define double @choice_{argument}() {{',
                f'%r = call double @llvm.floor.f64(double {argument})', 'ret double %r }'])
        module, _ = self.imported('undef-poison', '\n'.join(lines).encode())
        for argument in ('poison', 'undef'):
            function = next(f for f in module['functions'] if f['name'] == 'choice_' + argument)
            freezes = [i['operation'] for b in function['blocks'] for i in b['instructions']
                       if i['operation']['op'] == 'freeze']
            self.assertEqual(len(freezes), 1)
            self.assertEqual(freezes[0]['value']['kind'], argument)

    def test_llvm_valid_neighboring_formats_remain_explicitly_unsupported(self):
        for ty, suffix in [('half', 'f16'), ('x86_fp80', 'f80'), ('<2 x double>', 'v2f64')]:
            raw = ('target triple = "x86_64-unknown-linux-gnu"\n'
                   'target datalayout = "e-p:64:64-i64:64-f80:128"\n'
                   f'declare {ty} @llvm.floor.{suffix}({ty})\n'
                   f'define {ty} @original({ty} %x) {{\n'
                   f'%r = call {ty} @llvm.floor.{suffix}({ty} %x)\nret {ty} %r }}\n').encode()
            path = self.directory / ('unsupported-' + suffix + '.ll');path.write_bytes(raw)
            # The inventory reader deliberately has no half/vector type model.
            # Establish valid LLVM with the pinned real assembler instead of
            # treating an inventory type rejection as LLVM verification.
            bitcode = path.with_suffix('.bc')
            argv = [str(LLVM_AS), str(path), '-o', str(bitcode)]
            result = subprocess.run(argv, capture_output=True, timeout=120)
            out, err = path.with_suffix('.stdout'), path.with_suffix('.stderr')
            out.write_bytes(result.stdout); err.write_bytes(result.stderr)
            self.records.append({'independent_llvm_verification_argv': argv,
                                 'exit_code': result.returncode,
                                 'stdout': identity(out), 'stderr': identity(err)})
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            with self.assertRaises(importer.ImportFailure):
                importer.import_module(path, LIBRARY, expected_sha256=PIN)
            self.records.append({'explicit_unsupported_format': identity(path),
                                 'llvm_verified_bitcode': identity(bitcode)})

    def test_complete_unchanged_original_lua_lobject_and_lmathlib_units(self):
        corpus = Path('/home/orangepi/ostadix-BM/target/original-lua-source-recipe-20261017-ndpqjeew/compiled/capture/units')
        for label, unit, digest in [
                ('lobject', 'c17f95b1ed6a426488efdea7424dc3de', 'ad8ab6b34fcf2c620c5ad9d819e94655bd8ea5c25c718c5875d42f4e33ecea01'),
                ('lmathlib', '5ded601a2e1e4f97896f011cd602ff86', 'f4f48dba08657862273bf14a01594ba8ab65322ff382012fed69e9717fd0dd88')]:
            original = corpus/unit/'unit-0.ll'
            before = identity(original)
            self.assertEqual(before['sha256'], digest)
            _, inventory = self.imported('original-' + label, original.read_bytes())
            self.assertEqual(identity(original), before)
            self.records[-1].update({'upstream_original': before,
                                     'whole_original_unit': True, 'frontend_regenerated': False,
                                     'native_verification_pending': True})
            self.assertGreater(len(inventory['functions']), 10)

    def test_unused_extra_graph_and_cross_call_sharing_are_not_inventory_preservation(self):
        module, original = self.imported('surplus', fixture())
        changed = copy.deepcopy(module)
        function = next(f for f in changed['functions'] if f['name'] == 'floor_64')
        instructions = function['blocks'][0]['instructions']
        next_id = 1 + max(i['result']['id'] for i in instructions)
        replacement = {i['result']['id']: next_id + n for n,i in enumerate(instructions)}
        extra = copy.deepcopy(instructions)
        def rewrite(value):
            if isinstance(value, list):
                for item in value: rewrite(item)
            elif isinstance(value, dict):
                if value.get('kind') == 'value' and value['id'] in replacement:
                    value['id'] = replacement[value['id']]
                for item in value.values(): rewrite(item)
        for instruction in extra:
            rewrite(instruction['operation'])
            instruction['result']['id'] = replacement[instruction['result']['id']]
        instructions.extend(extra)
        with self.assertRaisesRegex(InventoryMismatch, 'graph primitive inventory changed'):
            check_inventory(original, changed)
        path = self.directory/'unused-extra-whole-graph.native.json';path.write_text(json.dumps(changed))
        self.records.append({'unused_extra_graph_rejected': identity(path),
                             'independent_native_verification_pending': True})

        cast_extra = copy.deepcopy(module)
        function = next(f for f in cast_extra['functions'] if f['name'] == 'floor_64')
        block = function['blocks'][0]
        original_bitcast = next(i for i in block['instructions']
                                if i['operation']['op'] == 'cast'
                                and cast_extra['types'][i['result']['ty']] == {'kind':'int','bits':64})
        narrow_type = len(cast_extra['types']);cast_extra['types'].append({'kind':'int','bits':32})
        next_id = 1 + max(i['result']['id'] for i in block['instructions'])
        block['instructions'].append({'result': {'id': next_id, 'ty': narrow_type},
            'operation': {'op':'cast','kind':'trunc',
                          'value': {'kind':'value','id':original_bitcast['result']['id']}}})
        with self.assertRaisesRegex(InventoryMismatch, 'graph primitive inventory changed'):
            check_inventory(original, cast_extra)
        path = self.directory/'unused-extra-cast.native.json';path.write_text(json.dumps(cast_extra))
        self.records.append({'unused_extra_cast_rejected': identity(path),
                             'independent_native_verification_pending': True})

        raw = ('target triple = "x86_64-unknown-linux-gnu"\n'
               'target datalayout = "e-p:64:64-i64:64"\n'
               'declare double @llvm.floor.f64(double)\n'
               'define double @two(double %x) {\n'
               '%a = call double @llvm.floor.f64(double %x)\n'
               '%b = call double @llvm.floor.f64(double %x)\nret double %b }\n').encode()
        baseline, source = self.imported('separate-call-graphs', raw)
        sharing = copy.deepcopy(baseline)
        function = next(f for f in sharing['functions'] if f['name'] == 'two')
        roots = [i for i in function['blocks'][0]['instructions'] if i['result']['id'] in (1,2)]
        self.assertEqual(len(roots), 2)
        roots[1]['operation']['value'] = copy.deepcopy(roots[0]['operation']['value'])
        with self.assertRaisesRegex(InventoryMismatch, 'shared/missing rounding graph nodes'):
            check_inventory(source, sharing)
        path = self.directory/'cross-call-graph-sharing.native.json';path.write_text(json.dumps(sharing))
        self.records.append({'cross_call_graph_sharing_rejected': identity(path),
                             'independent_native_verification_pending': True})
