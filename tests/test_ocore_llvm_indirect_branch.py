"""Owned block-address lowering controls; source gates are not native proof.

Run SourceControls explicitly for pinned-LLVM/front-end/inventory checks.
NativeControls requires an explicitly selected freshly built candidate compiler;
it never treats old compiler rejection, absent prerequisites or zero cases as a
qualified native result. Whole original runtime/artifact acceptance stays open.
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
LIBRARY_SHA = '8617d27fecff5e31785eed07ee1cd7665e083bb689b6fb13266956d5231afe83'
PROFILES = (
    ('x86_64-unknown-linux-gnu', 'e-m:e-p:64:64-i64:64-i128:128-n8:16:32:64-S128', 'x86_64-unknown-none'),
    ('aarch64-unknown-linux-gnu', 'e-m:e-p:64:64-i64:64-i128:128-n32:64-S128', 'aarch64-unknown-none'),
    ('riscv64-unknown-linux-gnu', 'e-m:e-p:64:64-i64:64-i128:128-n32:64-S128', 'riscv64-unknown-none'),
)
BODY = r'''
@targets = internal constant [3 x ptr] [ptr blockaddress(@dispatch, %left), ptr blockaddress(@dispatch, %right), ptr blockaddress(@cold_owner, %cold)], align 8
@plus_seven = global ptr getelementptr (i8, ptr blockaddress(@dispatch, %left), i64 7), align 8
@minus_three = global ptr getelementptr (i8, ptr blockaddress(@cold_owner, %cold), i64 -3), align 8
declare i64 @unused_provider(i64)
define i64 @dispatch(i64 %choice) {
entry:
  %index = and i64 %choice, 1
  %slot = getelementptr [3 x ptr], ptr @targets, i64 0, i64 %index
  %address = load ptr, ptr %slot, align 8
  indirectbr ptr %address, [label %left, label %right, label %left]
left:
  %r = phi i64 [13, %entry], [13, %entry]
  ret i64 %r
right:
  ret i64 29
}
define internal i64 @cold_owner(i64 %value) {
entry:
  br label %cold
cold:
  ret i64 %value
}
define i64 @parallel_loop(i64 %count) {
entry:
  br label %header
header:
  %a = phi i64 [5, %entry], [%b, %header], [%b, %header]
  %b = phi i64 [9, %entry], [%a, %header], [%a, %header]
  %n = phi i64 [%count, %entry], [%next, %header], [%next, %header]
  %done = icmp eq i64 %n, 0
  %next = sub i64 %n, 1
  %address = select i1 %done, ptr blockaddress(@parallel_loop, %exit), ptr blockaddress(@parallel_loop, %header)
  indirectbr ptr %address, [label %header, label %exit, label %header]
exit:
  %answer = sub i64 %a, %b
  ret i64 %answer
}
define i64 @recovered_address(i1 %take) {
entry:
  %address = select i1 %take, ptr blockaddress(@recovered_address, %yes), ptr blockaddress(@recovered_address, %no)
  %bits = ptrtoint ptr %address to i64
  %biased = add i64 %bits, 19
  %restored = sub i64 %biased, 19
  %pointer = inttoptr i64 %restored to ptr
  %nonnull = icmp ne ptr %pointer, null
  br i1 %nonnull, label %dispatch, label %null
null:
  ret i64 -1
dispatch:
  indirectbr ptr %pointer, [label %yes, label %no]
yes:
  ret i64 41
no:
  ret i64 43
}
define ptr @returned_label() {
entry:
  ret ptr blockaddress(@cold_owner, %cold)
}
define void @empty_destination(ptr %address) {
entry:
  indirectbr ptr %address, []
}
'''


def pin(path):
    path = Path(path)
    raw = path.read_bytes()
    return {'path': str(path.resolve()), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def invalidate_differential(report):
    report['authored_fixture_all_canonical_isa_differential_passed'] = False
    report['native_execution_qualified'] = False
    report['original_runtime_accepted'] = False
    for profile in report.get('differential_targets', {}).values():
        profile['provenance_qualified'] = False


def finalize_differential(report, evidence, canonical_targets):
    """Observed comparisons qualify only after successful actual input rehash."""
    invalidate_differential(report)
    report['provenance_finalization'] = {'attempted': True, 'verified': False}
    try:
        report['execution_provenance'] = evidence.finish()
        report['provenance_finalization']['verified'] = True
        profiles = report.get('differential_targets', {})
        pairings = {f'{a}-caller-{b}-provider' for a in ('reference', 'owned') for b in ('reference', 'owned')}
        if not canonical_targets or set(profiles) != set(canonical_targets):
            raise ValueError('missing actual canonical-target comparisons')
        if report.get('compiler_import_executed') is not True or report.get('native_executed') is not True:
            raise ValueError('no actual import/native execution can qualify')
        for profile in profiles.values():
            if (profile.get('comparison_complete') is not True
                    or profile.get('cases_per_pairing') != 194
                    or set(profile.get('outputs', {})) != pairings
                    or len(set(profile['outputs'].values())) != 1):
                raise ValueError('incomplete actual four-pairing behavior comparison')
        if len({next(iter(p['outputs'].values())) for p in profiles.values()}) != 1:
            raise ValueError('canonical ISA observable output bytes differ')
        for profile in profiles.values():
            profile['provenance_qualified'] = True
        report['authored_fixture_all_canonical_isa_differential_passed'] = True
    except BaseException:
        invalidate_differential(report)
        raise


def publish_differential(report, save):
    """A failed publication must never leave a stale true qualification."""
    try:
        save()
    except BaseException as error:
        invalidate_differential(report)
        report['publication_failure'] = {'type': type(error).__name__, 'message': str(error)}
        try:
            save()
        except BaseException:
            pass  # Re-raise original publication error; no valid report assumed.
        raise


def require_elf64_object_profile(path, machine, flags):
    """Check the declared ELF header profile, not whole-object correctness."""
    data = Path(path).read_bytes()
    if (len(data) < 64 or data[:6] != b'\x7fELF\x02\x01'
            or int.from_bytes(data[16:18], 'little') != 1
            or int.from_bytes(data[18:20], 'little') != machine
            or int.from_bytes(data[48:52], 'little') != flags):
        raise ValueError(f'object does not preserve ELF64 machine={machine} flags={flags}')
    return {'class_bits': 64, 'little_endian': True, 'type': 1,
            'machine': machine, 'flags': flags, 'scope': 'ELF header profile only'}


def retain_original_unit_failure(gate, evidence, dependency_path, dependency_pin, error, artifacts=()):
    """Keep failed commands and observed drift without qualifying a partial unit."""
    from scripts.check_ocore_native_equivalence import file_identity
    gate['complete'] = False
    gate['failure'] = {'type': type(error).__name__, 'message': str(error)}
    gate['partial_execution_provenance'] = {
        'before': {'sources': dict(evidence.sources), 'tools': dict(evidence.tools)},
        'environment': evidence.environment_record, 'commands': list(evidence.commands),
        'final_provenance_qualification': False}
    gate['provenance_finalization'] = {'attempted': True, 'verified': False}
    try:
        gate['failure_provenance'] = evidence.finish()
        gate['provenance_finalization']['verified'] = True
    except BaseException as finalization_error:
        gate['provenance_finalization']['error'] = {
            'type': type(finalization_error).__name__, 'message': str(finalization_error)}
    observed = {'sources': {}, 'tools': {}}
    for kind, records in (('sources', evidence.sources), ('tools', evidence.tools)):
        for name, identity in records.items():
            try:
                observed[kind][name] = file_identity(identity['path'])
            except BaseException as identity_error:
                observed[kind][name] = {'path': identity['path'], 'read_error': {
                    'type': type(identity_error).__name__, 'message': str(identity_error)}}
    gate['partial_execution_provenance']['after_observed'] = observed
    try:
        gate['captured_dependency_report_after'] = dependency_pin(dependency_path)
    except BaseException as dependency_error:
        gate['captured_dependency_report_after_error'] = {
            'type': type(dependency_error).__name__, 'message': str(dependency_error)}
    gate['partial_artifacts'] = []
    for artifact in artifacts:
        try:
            gate['partial_artifacts'].append(pin(artifact))
        except BaseException as artifact_error:
            gate['partial_artifacts'].append({'path': str(artifact), 'read_error': {
                'type': type(artifact_error).__name__, 'message': str(artifact_error)}})


def audited_native_binding(compiler, build_path, build_sha, audit_path, audit_sha):
    """Bind explicitly pinned independent build/source evidence before dispatch.

    This is a test-launcher prerequisite. A source review is not execution
    qualification, and the inventory helper is not a compiler depfile input.
    """
    from scripts.check_ocore_native_equivalence import TARGET_CATALOG
    build_pin, audit_pin = pin(build_path), pin(audit_path)
    if build_pin['sha256'] != build_sha or audit_pin['sha256'] != audit_sha:
        raise ValueError('explicit independently audited build/source pin mismatch')
    build, audit = json.loads(Path(build_path).read_text()), json.loads(Path(audit_path).read_text())
    if audit.get('schema') != 'ostadix.blockaddress-audited-source-map/v1':
        raise ValueError('unknown independently audited blockaddress source map')
    for label, actual in (('build_receipt', build_pin), ('compiler', compiler)):
        reviewed = audit.get(label)
        if (not isinstance(reviewed, dict) or reviewed.get('sha256') != actual['sha256']
                or not reviewed.get('path')
                or Path(reviewed['path']).resolve() != Path(actual['path']).resolve()):
            raise ValueError('independent audit does not bind exact selected ' + label)
    if not audit.get('build_schema') or build.get('schema') != audit['build_schema']:
        raise ValueError('unknown/mismatched compiler build receipt schema')
    if (build.get('stage') != 'complete' or build.get('exit_code') != 0
            or build.get('compiler_build_qualified') is not True):
        raise ValueError('selected compiler build is not terminal and qualified')
    before, after = build.get('source_before'), build.get('source_after')
    if not isinstance(before, dict) or not before or before != after:
        raise ValueError('missing/unstable complete compiler build source maps')
    source_map_sha = hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if audit.get('full_compiled_source_map_sha256') != source_map_sha:
        raise ValueError('complete compiled-source map differs from independent audit')
    required = {'scripts/ocore_llvm_import.py', 'src/bin/olangc/native_runtime.rs'} | {
        'crates/ostadix-api/src/ocore/' + name + '.rs' for name in
        ('common', 'driver', 'native_ir', 'native_verify', 'native_codegen', 'native_map', 'native_interpret')}
    expected = audit.get('sources')
    if (not isinstance(expected, dict) or not required.issubset(expected)
            or audit.get('blockaddress_semantics_reviewed') is not True):
        raise ValueError('independent review must bind the combined blockaddress source and catalog')
    for name, digest in expected.items():
        if not isinstance(digest, str) or before.get(name) != digest:
            raise ValueError('compiler build differs from audited combined source: ' + name)
    if expected['crates/ostadix-api/src/ocore/common.rs'] != pin(TARGET_CATALOG)['sha256']:
        raise ValueError('canonical catalog differs from actually audited compiled source')
    selected = build.get('binaries', {}).get('ocorec', {}).get('copied_executable')
    if (not isinstance(selected, dict) or selected.get('sha256') != compiler['sha256']
            or Path(selected.get('path', '')).resolve() != Path(compiler['path']).resolve()):
        raise ValueError('build receipt does not bind the selected copied compiler bytes/path')
    support = {'independent_inventory_helper': ROOT / 'tests/ocore_llvm_source_inventory.py',
               'execution_helper': ROOT / 'scripts/check_ocore_native_equivalence.py',
               'test_source': Path(__file__), 'target_catalog': TARGET_CATALOG}
    identities = {'build_receipt': build_pin, 'independent_source_audit': audit_pin}
    for label, path in support.items():
        actual, reviewed = pin(path), audit.get(label)
        if (not isinstance(reviewed, dict) or reviewed.get('independently_reviewed') is not True
                or reviewed.get('sha256') != actual['sha256'] or not reviewed.get('path')
                or Path(reviewed['path']).resolve() != Path(actual['path'])):
            raise ValueError('selected support source differs from independently pinned audit: ' + label)
        identities[label] = actual
    return {'inputs': identities, 'compiled_source_map': expected,
            'catalog_bound_to_actual_compiler_build': True,
            'independent_inventory_helper_is_compiler_depfile_input': False,
            'native_execution_qualified_here': False}


class SourceControls(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix='blockaddress-', dir=os.environ['OCORE_BLOCKADDRESS_RETAIN']))
        self.library = Path(os.environ.get('OCORE_TEST_LLVM_LIBRARY', LIBRARY))
        self.library_sha = os.environ.get('OCORE_TEST_LLVM_SHA256', LIBRARY_SHA)
        self.reader = Reader(self.library, self.library_sha)
        self.report = {'test': self.id(), 'commands': [], 'cases': [],
                       'compiler_embedded_candidate_verified': False,
                       'native_execution_qualified': False, 'original_runtime_accepted': False}
        self.sequence = 0
        self.save()

    def save(self):
        (self.directory / 'report.json').write_text(json.dumps(self.report, indent=2) + '\n')

    def authored(self, profile=PROFILES[0], body=BODY):
        triple, layout, _ = profile
        source = self.directory / f'case-{self.sequence}.ll'
        self.sequence += 1
        source.write_text(f'target triple = "{triple}"\ntarget datalayout = "{layout}"\n' + body)
        before = pin(source)
        original = self.reader.read(source)  # Independent pinned LLVM parse + VerifyModule.
        module = importer.import_module(source, library_path=self.library, expected_sha256=self.library_sha)
        preservation = check_inventory(original, module)
        native = source.with_suffix('.native.json')
        native.write_text(json.dumps(module, indent=2) + '\n')
        inventory = source.with_suffix('.inventory.json')
        inventory.write_text(json.dumps({'original': original, 'preservation': preservation}, indent=2) + '\n')
        self.assertEqual(before, pin(source))
        self.report['cases'].append({'source': before, 'native_module': pin(native), 'inventory': pin(inventory),
                                     'independent_original_llvm_verified': True,
                                     'candidate_native_mir_verified': False})
        self.save()
        return source, original, module

    def test_original_objects_and_full_indirect_cfg_preserved_on_three_profiles(self):
        for profile in PROFILES:
            with self.subTest(triple=profile[0]):
                _, original, module = self.authored(profile)
                functions = {item['name']: item for item in module['functions']}
                term = functions['dispatch']['blocks'][0]['terminator']
                self.assertEqual(term['destinations'], [1, 2, 1])
                self.assertEqual(len(functions['dispatch']['blocks'][1]['instructions'][0]['operation']['incoming']), 1)
                self.assertEqual(original['functions']['dispatch']['phis'][0]['incoming'], [
                    {'block': 0, 'value': {'kind': 'int', 'type': {'kind': 'int', 'bits': 64}, 'bits': '13'}}] * 2)
                table = next(item for item in module['globals'] if item['name'] == 'targets')
                self.assertEqual([item['block'] for item in table['initializer']['relocations']], [
                    {'function': 'dispatch', 'block': 1}, {'function': 'dispatch', 'block': 2},
                    {'function': 'cold_owner', 'block': 1}])
                self.assertEqual([item['addend'] for item in module['globals'][1]['initializer']['relocations']], [7])
                self.assertEqual(functions['empty_destination']['blocks'][0]['terminator']['destinations'], [])

    def test_independent_inventory_rejects_well_typed_graph_and_cold_table_mutants(self):
        _, original, module = self.authored()
        faults = []
        def reject(label, mutate):
            changed = copy.deepcopy(module)
            mutate(changed)
            with self.assertRaises(InventoryMismatch) as caught:
                check_inventory(original, changed)
            faults.append({'name': label, 'error': str(caught.exception),
                           'independent_native_verification_pending': True})
        reject('swapped_original_table_block', lambda m: m['globals'][0]['initializer']['relocations'][0]['block'].update(block=2))
        reject('omitted_cold_owner', lambda m: m['functions'].pop(next(i for i, f in enumerate(m['functions']) if f['name'] == 'cold_owner')))
        reject('changed_nonzero_addend', lambda m: m['globals'][1]['initializer']['relocations'][0].update(addend=8))
        reject('omitted_duplicate_destination', lambda m: m['functions'][1]['blocks'][0]['terminator']['destinations'].pop())
        reject('reordered_destination_list', lambda m: m['functions'][1]['blocks'][0]['terminator'].update(destinations=[2, 1, 1]))
        reject('changed_phi_value', lambda m: m['functions'][1]['blocks'][1]['instructions'][0]['operation']['incoming'][0]['value'].update(bits='14'))
        reject('same_owner_select_target', lambda m: next(i['operation'] for i in next(f for f in m['functions'] if f['name'] == 'parallel_loop')['blocks'][1]['instructions'] if i['operation']['op'] == 'select')['on_true'].update(block=1))
        reject('returned_label_addend', lambda m: next(f for f in m['functions'] if f['name'] == 'returned_label')['blocks'][0]['terminator']['value'].update(addend=1))
        self.report['inventory_mutants'] = faults
        self.save()

    def test_pinned_llvm_rejects_entry_block_address(self):
        source = self.directory / 'invalid-entry.ll'
        source.write_text('define ptr @invalid() { entry: ret ptr blockaddress(@invalid, %entry) }\n')
        with self.assertRaises(InventoryMismatch) as caught:
            self.reader.read(source)
        self.report['original_llvm_rejections'] = [{'source': pin(source), 'error': str(caught.exception)}]
        self.save()

    def test_public_llvm_assembler_and_disassembler_retain_block_identities(self):
        source, _, _ = self.authored()
        sdk = Path(os.environ['OCORE_TEST_LLVM22_BIN'])
        bitcode, text = source.with_suffix('.bc'), source.with_suffix('.canonical.ll')
        for argv in ([sdk / 'llvm-as', source, '-o', bitcode], [sdk / 'llvm-dis', bitcode, '-o', text]):
            argv = list(map(str, argv))
            run = subprocess.run(argv, capture_output=True, timeout=60)
            self.report['commands'].append({'argv': argv, 'exit_code': run.returncode,
                'stdout': run.stdout.decode(errors='replace'), 'stderr': run.stderr.decode(errors='replace'),
                'tool': pin(argv[0])})
            self.save()
            self.assertEqual(run.returncode, 0, run.stderr.decode(errors='replace'))
        before = self.reader.read(source)
        after = self.reader.read(text)
        self.assertEqual(before['globals'], after['globals'])
        self.assertEqual(before['functions'], after['functions'])
        self.report['canonical_artifacts'] = [pin(bitcode), pin(text)]
        self.save()

    def test_complete_unchanged_cpython_source_inventories_and_open_import_gates(self):
        capture = Path('/home/orangepi/ostadix-BM/target/cpython-expansion-20261018/original-cpython-source-recipe-20261018-uuidfix/compiled/capture/units')
        originals = (
            ('ceval', '721ca9776d304daeaa4c9140291063d3',
             '716ede7e2598a5eb538b28db816c201dccbd320b73ea37080c5059ea56cb07d5',
             {'_PyEval_EvalFrameDefault.opcode_targets': 256}),
            ('sre', '6522827a7092474da2e3ce9dabd6a04e',
             '76b22ec7e2dfcdf40eb2718dd3e3687e04c6f03ff6aa677a1696c5b37fa3c42c',
             {f'sre_ucs{width}_match.sre_targets': 43 for width in (1, 2, 4)}),
        )
        self.report['unchanged_original_units'] = []
        for label, unit, digest, tables in originals:
            source = capture / unit / 'unit-0.ll'
            before = pin(source)
            self.assertEqual(before['sha256'], digest)
            original = self.reader.read(source)
            inventory = self.directory / f'{label}.complete-source-inventory.json'
            inventory.write_text(json.dumps(original, indent=2) + '\n')
            table_records = {}
            for name, count in tables.items():
                table = original['globals'][name]
                self.assertEqual(table['type']['len'], count)
                relocations = table['initializer']['relocations']
                self.assertEqual(len(relocations), count)
                self.assertTrue(all(item.get('block') and item['symbol'] == '' for item in relocations))
                table_records[name] = {'entries': count, 'relocations': relocations}
            record = {'source': before, 'complete_source_inventory': pin(inventory),
                      'tables': table_records,
                      'functions': len(original['functions']), 'globals': len(original['globals']),
                      'indirect_branches': sum(len(f['indirect_branches']) for f in original['functions'].values()),
                      'original_target_abi': 'lp64d', 'target_rewritten': False,
                      'independent_native_verification': False, 'native_execution_qualified': False,
                      'original_runtime_accepted': False}
            try:
                module = importer.import_module(source, library_path=self.library, expected_sha256=self.library_sha)
            except importer.ImportFailure as error:
                record['candidate_whole_unit_import'] = {'status': 'UNSUPPORTED',
                    'stage': error.stage, 'error': str(error),
                    'interpretation': 'Unmet whole-unit gate; source inventory is not import acceptance'}
            else:
                preservation = check_inventory(original, module)
                native = self.directory / f'{label}.native.json'
                native.write_text(json.dumps(module, indent=2) + '\n')
                record['candidate_whole_unit_import'] = {'status': 'SOURCE_WORKER_ONLY',
                    'module': pin(native), 'preservation': preservation,
                    'interpretation': 'Uncompiled Python candidate; compiler import/verification/emission still pending'}
            self.assertEqual(before, pin(source))
            self.report['unchanged_original_units'].append(record)
            self.save()

    def test_complete_unchanged_lua_vm_source_inventory_and_open_import_gate(self):
        source = Path('/home/orangepi/ostadix-BM/target/original-lua-source-recipe-20261017-ndpqjeew/compiled/capture/units/4dd6545d80ac447bb8b41e290c96195d/unit-0.ll')
        before = pin(source)
        self.assertEqual(before['sha256'], 'e43c1954085e17bdc229b7884a8ea273e88c3b3a3fb603f06677474fffa578c0')
        original = self.reader.read(source)
        inventory = self.directory / 'lua-vm.complete-source-inventory.json'
        inventory.write_text(json.dumps(original, indent=2) + '\n')
        table = original['globals']['luaV_execute.disptab']
        self.assertEqual(table['type']['len'], 85)
        self.assertEqual(len(table['initializer']['relocations']), 85)
        self.assertTrue(all(item.get('block') and item['block']['function'] == 'luaV_execute'
                            for item in table['initializer']['relocations']))
        record = {'source': before, 'complete_source_inventory': pin(inventory),
                  'functions': len(original['functions']), 'globals': len(original['globals']),
                  'dispatch_table_entries': 85,
                  'indirect_branches': sum(len(f['indirect_branches']) for f in original['functions'].values()),
                  'original_target_abi': 'lp64d', 'target_rewritten': False,
                  'independent_native_verification': False, 'native_execution_qualified': False,
                  'original_runtime_accepted': False}
        try:
            module = importer.import_module(source, library_path=self.library, expected_sha256=self.library_sha)
        except importer.ImportFailure as error:
            record['candidate_whole_unit_import'] = {'status': 'UNSUPPORTED', 'stage': error.stage,
                'error': str(error), 'interpretation': 'Unmet whole-unit gate, not source inventory acceptance'}
        else:
            preservation = check_inventory(original, module)
            native = self.directory / 'lua-vm.native.json'
            native.write_text(json.dumps(module, indent=2) + '\n')
            record['candidate_whole_unit_import'] = {'status': 'SOURCE_WORKER_ONLY',
                'module': pin(native), 'preservation': preservation,
                'interpretation': 'Uncompiled Python candidate; compiler import/verification/emission still pending'}
        self.assertEqual(before, pin(source))
        self.report['unchanged_original_units'] = [record]
        self.save()


    def test_actual_source_drift_and_publication_failure_clear_qualification(self):
        import sys
        from scripts.check_ocore_native_equivalence import RunEvidence
        watched = self.directory / 'watched-source.txt'
        watched.write_text('original bytes\n')
        evidence = RunEvidence([watched])
        drifted = {'authored_fixture_all_canonical_isa_differential_passed': True,
                   'differential_targets': {'observed': {'comparison_complete': True,
                       'cases_per_pairing': 194, 'provenance_qualified': True}}}
        before = pin(watched)
        watched.write_text('changed bytes\n')
        with self.assertRaises(RuntimeError) as caught:
            finalize_differential(drifted, evidence, ['observed'])
        self.assertIn('run input changed', str(caught.exception))
        self.assertIs(drifted['authored_fixture_all_canonical_isa_differential_passed'], False)
        self.assertIs(drifted['differential_targets']['observed']['provenance_qualified'], False)
        self.assertIs(drifted['differential_targets']['observed']['comparison_complete'], True)
        publication = {'authored_fixture_all_canonical_isa_differential_passed': True,
                       'differential_targets': {}}
        destination = self.directory / 'publication-failure-control.json'
        writes = 0
        def fail_after_actual_write():
            nonlocal writes
            writes += 1
            destination.write_text(json.dumps(publication, indent=2) + '\n')
            if writes == 1:
                raise OSError('forced publication error after real write')
        with self.assertRaises(OSError):
            publish_differential(publication, fail_after_actual_write)
        self.assertIs(json.loads(destination.read_text())['authored_fixture_all_canonical_isa_differential_passed'], False)
        self.report['negative_finalization_controls'] = {
            'watched_before': before, 'watched_after': pin(watched), 'actual_drift_error': str(caught.exception),
            'retained_unqualified_observations': drifted, 'publication_report': pin(destination),
            'actual_publication_writes': writes, 'scope': 'failure cleanup only; no native execution'}
        failed_input = self.directory / 'failed-original-unit-input.txt'
        dependency = self.directory / 'failed-original-unit-dependency.json'
        failed_input.write_text('original input\n')
        dependency.write_text('{"original": true}\n')
        failed_evidence = RunEvidence([failed_input, dependency])
        dependency_before = pin(dependency)
        with self.assertRaises(RuntimeError) as command_error:
            failed_evidence.checked_run([sys.executable, '-c',
                'import sys; sys.stderr.write("retained failure marker\\n"); sys.exit(7)'])
        failed_input.write_text('changed after failed command\n')
        dependency.write_text('{"changed": true}\n')
        failed_gate = {'complete': True, 'captured_dependency_report_before': dependency_before}
        retain_original_unit_failure(failed_gate, failed_evidence, dependency, pin, command_error.exception)
        self.assertIs(failed_gate['complete'], False)
        self.assertEqual(failed_gate['partial_execution_provenance']['commands'][0]['exit_code'], 7)
        self.assertIn('retained failure marker', failed_gate['partial_execution_provenance']['commands'][0]['stderr'])
        self.assertIs(failed_gate['provenance_finalization']['verified'], False)
        self.assertIn('run input changed', failed_gate['provenance_finalization']['error']['message'])
        self.assertEqual(failed_gate['captured_dependency_report_after'], pin(dependency))
        self.assertNotEqual(failed_gate['captured_dependency_report_after'], dependency_before)
        dependency.unlink()
        missing_gate = {'complete': True}
        retain_original_unit_failure(missing_gate, failed_evidence, dependency, pin, command_error.exception)
        self.assertIs(missing_gate['complete'], False)
        self.assertEqual(missing_gate['captured_dependency_report_after_error']['type'], 'FileNotFoundError')
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        header[16:18] = (1).to_bytes(2, 'little')
        header[18:20] = (243).to_bytes(2, 'little')
        header[48:52] = (5).to_bytes(4, 'little')
        profile_object = self.directory / 'elf-header-profile-control.o'
        profile_object.write_bytes(header)
        self.assertEqual(require_elf64_object_profile(profile_object, 243, 5)['flags'], 5)
        header[48:52] = (0).to_bytes(4, 'little')
        profile_object.write_bytes(header)
        with self.assertRaises(ValueError):
            require_elf64_object_profile(profile_object, 243, 5)
        self.report['negative_finalization_controls']['original_unit_failure_retention'] = failed_gate
        self.report['negative_finalization_controls']['missing_dependency_retention'] = missing_gate
        self.report['negative_finalization_controls']['elf_header_profile_control'] = {
            'original_lp64d_flags_5_accepted': True, 'lp64_downgrade_rejected': True,
            'scope': 'synthetic header guard only; not a verified or emitted object'}
        self.save()


class NativeControls(SourceControls):
    """Explicit fresh-compiler gate; not run by the source-only control command."""
    def setUp(self):
        super().setUp()
        self.compiler = Path(os.environ['OCORE_BLOCKADDRESS_COMPILER']).resolve()
        self.compiler_before = pin(self.compiler)
        expected = os.environ['OCORE_BLOCKADDRESS_COMPILER_SHA256']
        self.assertEqual(self.compiler_before['sha256'], expected)
        self.report['compiler'] = self.compiler_before
        self.native_binding = audited_native_binding(self.compiler_before,
            Path(os.environ['OCORE_BLOCKADDRESS_BUILD_RECEIPT']), os.environ['OCORE_BLOCKADDRESS_BUILD_SHA256'],
            Path(os.environ['OCORE_BLOCKADDRESS_SOURCE_AUDIT']), os.environ['OCORE_BLOCKADDRESS_SOURCE_AUDIT_SHA256'])
        self.report['audited_native_binding'] = self.native_binding
        self.save()

    def verify_binding_inputs(self):
        for label, expected in self.native_binding['inputs'].items():
            self.assertEqual(pin(expected['path']), expected, 'native-launch audit input changed: ' + label)

    def run_compiler(self, argv, expect_success=True):
        self.verify_binding_inputs()
        argv = [str(self.compiler), *map(str, argv)]
        run = subprocess.run(argv, capture_output=True, timeout=120)
        self.report['commands'].append({'argv': argv, 'exit_code': run.returncode,
            'stdout': run.stdout.decode(errors='replace'), 'stderr': run.stderr.decode(errors='replace')})
        self.save()
        self.assertEqual(pin(self.compiler), self.compiler_before)
        self.verify_binding_inputs()
        if expect_success:
            self.assertEqual(run.returncode, 0, run.stderr.decode(errors='replace'))
        else:
            self.assertNotEqual(run.returncode, 0)
        return run

    def test_actual_import_reimport_verification_and_emission(self):
        for profile in PROFILES:
            source, original, _ = self.authored(profile)
            native, obj, receipt = source.with_suffix('.compiled.json'), source.with_suffix('.o'), source.with_suffix('.verification.json')
            self.run_compiler([source, '--input-kind', 'llvm-ir', '--emit', 'mir', '--target', profile[2],
                '--llvm-library', self.library, '--llvm-sha256', self.library_sha, '-o', native])
            self.run_compiler([native, '--input-kind', 'native-ir', '--verify-native', '--receipt', receipt])
            check_inventory(original, json.loads(native.read_text()))
            verified = json.loads(receipt.read_text())
            self.assertIs(verified['verified'], True)
            self.assertEqual(verified['module_sha256'], pin(native)['sha256'])
            self.run_compiler([native, '--input-kind', 'native-ir', '--emit', 'obj', '--target', profile[2], '-o', obj])
            self.report['cases'][-1]['actual_compiler_artifacts'] = list(map(pin, (native, obj, receipt)))
            self.save()

    def test_well_typed_mutants_verified_before_inventory_rejection(self):
        _, original, module = self.authored()
        def function(m, name):
            return next(f for f in m['functions'] if f['name'] == name)
        mutations = (
            ('table_existing_block', lambda m: m['globals'][0]['initializer']['relocations'][0]['block'].update(block=2)),
            ('table_addend', lambda m: m['globals'][1]['initializer']['relocations'][0].update(addend=8)),
            ('removed_duplicate_destination', lambda m: function(m, 'dispatch')['blocks'][0]['terminator']['destinations'].pop()),
            ('destination_order', lambda m: function(m, 'dispatch')['blocks'][0]['terminator'].update(destinations=[2, 1, 1])),
            ('phi_value', lambda m: function(m, 'dispatch')['blocks'][1]['instructions'][0]['operation']['incoming'][0]['value'].update(bits='14')),
            ('same_owner_select_block', lambda m: next(i['operation'] for i in function(m, 'parallel_loop')['blocks'][1]['instructions'] if i['operation']['op'] == 'select')['on_true'].update(block=1)),
            ('returned_block_addend', lambda m: function(m, 'returned_label')['blocks'][0]['terminator']['value'].update(addend=1)),
        )
        self.report['independently_verified_mutants'] = []
        for label, mutate in mutations:
            changed = copy.deepcopy(module)
            mutate(changed)
            native, receipt = self.directory / f'{label}.native.json', self.directory / f'{label}.verification.json'
            native.write_text(json.dumps(changed, indent=2) + '\n')
            self.run_compiler([native, '--input-kind', 'native-ir', '--verify-native', '--receipt', receipt])
            verification = json.loads(receipt.read_text())
            self.assertIs(verification['verified'], True)
            self.assertEqual(verification['module_sha256'], pin(native)['sha256'])
            with self.assertRaises(InventoryMismatch) as caught:
                check_inventory(original, changed)
            self.report['independently_verified_mutants'].append({'name': label,
                'module': pin(native), 'verification': pin(receipt), 'inventory_error': str(caught.exception)})
            self.save()

    def test_reference_and_owned_observable_results_on_every_canonical_isa(self):
        from scripts.check_ocore_native_equivalence import (
            TARGETS, TARGET_CATALOG, RunEvidence, canonical_target_coverage,
            execution_prefix, elf, tool,
        )
        catalog = canonical_target_coverage()
        self.assertEqual({profile[2] for profile in PROFILES}, set(catalog['canonical_targets']))
        clang = tool(os.environ['OCORE_BLOCKADDRESS_CLANG'], 'pinned reference clang')
        linker = tool(os.environ.get('OCORE_BLOCKADDRESS_LINKER', 'ld.lld'), 'ELF linker')
        self.assertEqual(Path(tool(os.environ['OCORE_CLANG'], 'owned assembler')).resolve(), Path(clang).resolve())
        harness = self.directory / 'observable.c'
        harness.write_text(r'''typedef unsigned long long U;
extern int exercise(U *digest_out);
static long syscall3(long number, long first, long second, long third) {
#if defined(__x86_64__)
  long result;
  __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(first), "S"(second), "d"(third) : "rcx", "r11", "memory");
  return result;
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = number;
  register long x0 __asm__("x0") = first;
  register long x1 __asm__("x1") = second;
  register long x2 __asm__("x2") = third;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
  return x0;
#elif defined(__riscv) && __riscv_xlen == 64
  register long a7 __asm__("a7") = number;
  register long a0 __asm__("a0") = first;
  register long a1 __asm__("a1") = second;
  register long a2 __asm__("a2") = third;
  __asm__ volatile("ecall" : "+r"(a0) : "r"(a7), "r"(a1), "r"(a2) : "memory");
  return a0;
#else
#error missing canonical ISA syscall profile
#endif
}
__attribute__((noreturn)) static void finish(long result) {
#if defined(__x86_64__)
  syscall3(60, result, 0, 0);
#else
  syscall3(93, result, 0, 0);
#endif
  __builtin_trap();
}
__attribute__((noreturn,used)) void blockaddress_platform_runner(void) {
  U digest;
  int status = exercise(&digest);
  if (status) finish(status);
  char output[] = "OCORE-BLOCKADDRESS cases=194 digest=0000000000000000\n";
  unsigned position = sizeof(output) - 3;
  for (unsigned digit = 0; digit != 16; ++digit) {
    output[position - digit] = "0123456789abcdef"[digest & 15];
    digest >>= 4;
  }
#if defined(__x86_64__)
  long written = syscall3(1, 1, (long)output, sizeof(output) - 1);
#else
  long written = syscall3(64, 1, (long)output, sizeof(output) - 1);
#endif
  finish(written == sizeof(output) - 1 ? 0 : 14);
}

#if defined(__x86_64__)
/* Linux entry has rsp%16==0; call supplies the C ABI's return-address slot. */
__asm__(".text\n.globl _start\n.type _start,@function\n_start:\n"
        "xor %rbp,%rbp\nandq $-16,%rsp\ncall blockaddress_platform_runner\nud2\n"
        ".size _start,.-_start\n");
#else
/* AArch64/RV64 calls keep SP aligned and carry return addresses in registers. */
__attribute__((noreturn)) void _start(void) { blockaddress_platform_runner(); }
#endif
''')
        caller = self.directory / 'caller.c'
        caller.write_text(r'''
typedef unsigned long long U;
extern U dispatch(U);
extern U parallel_loop(U);
extern U recovered_address(_Bool);
int exercise(U *digest_out) {
  U digest = 0;
  for (U index = 0; index != 128; ++index) {
    U actual = dispatch(index), expected = (index & 1) ? 29 : 13;
    if (actual != expected) return 11;
    digest = digest * 131 + actual;
  }
  for (U index = 0; index != 64; ++index) {
    U actual = parallel_loop(index), expected = (index & 1) ? 4 : (U)-4;
    if (actual != expected) return 12;
    digest = digest * 131 + actual;
  }
  for (U index = 0; index != 2; ++index) {
    U actual = recovered_address((_Bool)index), expected = index ? 41 : 43;
    if (actual != expected) return 13;
    digest = digest * 131 + actual;
  }
  *digest_out = digest;
  return 0;
}
''')
        self.verify_binding_inputs()
        evidence = RunEvidence([__file__, harness, caller, TARGET_CATALOG,
                               *(entry['path'] for entry in self.native_binding['inputs'].values())],
            {'compiler': self.compiler, 'reference_clang': clang, 'linker': linker, 'llvm_parser': self.library})
        self.assertEqual(evidence.tools['llvm_parser']['sha256'], self.library_sha)
        self.report['backend_catalog'] = catalog
        self.report['differential_targets'] = {}
        invalidate_differential(self.report)
        try:
            for profile in PROFILES:
                source, original, _ = self.authored(profile)
                isa = profile[0].split('-')[0]
                native_target, hosted, machine, flags = TARGETS[isa]
                self.assertEqual((native_target, hosted), (profile[2], profile[0]))
                runner = execution_prefix(isa)
                native = source.with_suffix('.compiled.json')
                owned, reference = source.with_suffix('.owned.o'), source.with_suffix('.reference.o')
                receipt = source.with_suffix('.verification.json')
                evidence.watch_source(source)
                run = evidence.checked_run
                run([self.compiler, source, '--input-kind', 'llvm-ir', '--emit', 'mir', '--target', native_target,
                    '--llvm-library', self.library, '--llvm-sha256', self.library_sha, '-o', native])
                evidence.watch_source(native)
                run([self.compiler, native, '--input-kind', 'native-ir', '--verify-native', '--receipt', receipt])
                evidence.watch_source(receipt)
                verification = json.loads(receipt.read_text())
                self.assertIs(verification['verified'], True)
                self.assertEqual(verification['module_sha256'], pin(native)['sha256'])
                check_inventory(original, json.loads(native.read_text()))
                run([self.compiler, native, '--input-kind', 'native-ir', '--emit', 'obj', '--target', native_target,
                     '--function-sections', '--keep-asm', '-o', owned])
                evidence.watch_source(owned)
                run([clang, '--target=' + hosted, *flags, '-O0', '-c', source, '-o', reference])
                evidence.watch_source(reference)
                caller_llvm = self.directory / f'{isa}.caller.ll'
                caller_native = self.directory / f'{isa}.caller.native.json'
                caller_receipt = self.directory / f'{isa}.caller.verification.json'
                caller_reference = self.directory / f'{isa}.caller.reference.o'
                caller_owned = self.directory / f'{isa}.caller.owned.o'
                run([clang, '--target=' + hosted, *flags, '-O1', '-ffreestanding', '-fno-builtin',
                     '-fno-stack-protector', '-S', '-emit-llvm', caller, '-o', caller_llvm])
                evidence.watch_source(caller_llvm)
                caller_inventory = self.reader.read(caller_llvm)
                run([self.compiler, caller_llvm, '--input-kind', 'llvm-ir', '--emit', 'mir', '--target', native_target,
                     '--llvm-library', self.library, '--llvm-sha256', self.library_sha, '-o', caller_native])
                evidence.watch_source(caller_native)
                run([self.compiler, caller_native, '--input-kind', 'native-ir', '--verify-native', '--receipt', caller_receipt])
                evidence.watch_source(caller_receipt)
                caller_verification = json.loads(caller_receipt.read_text())
                self.assertIs(caller_verification['verified'], True)
                self.assertEqual(caller_verification['module_sha256'], pin(caller_native)['sha256'])
                check_inventory(caller_inventory, json.loads(caller_native.read_text()))
                self.report['compiler_import_executed'] = True
                run([self.compiler, caller_native, '--input-kind', 'native-ir', '--emit', 'obj', '--target', native_target,
                     '--function-sections', '-o', caller_owned])
                evidence.watch_source(caller_owned)
                run([clang, '--target=' + hosted, *flags, '-O1', '-c', caller_llvm, '-o', caller_reference])
                evidence.watch_source(caller_reference)
                outputs, artifacts = {}, [pin(source), pin(native), pin(receipt), pin(caller_llvm),
                                           pin(caller_native), pin(caller_receipt)]
                for caller_label, caller_path in (('reference', caller_reference), ('owned', caller_owned)):
                    for provider_label, object_path in (('reference', reference), ('owned', owned)):
                        label = caller_label + '-caller-' + provider_label + '-provider'
                        elf(object_path, machine, 1)
                        elf(caller_path, machine, 1)
                        executable = self.directory / f'{isa}-{label}.elf'
                        run([clang, '--target=' + hosted, *flags, '-O2', '-ffreestanding', '-fno-builtin',
                             '-fno-stack-protector', '-fno-pic', '-fno-pie', '-nostdlib', '-static',
                             '--ld-path=' + linker, '-Wl,-e,_start', '-Wl,--build-id=none',
                             harness, caller_path, object_path, '-o', executable])
                        elf(executable, machine, 2)
                        evidence.watch_source(executable)
                        executed = run([*runner, executable], timeout=30)
                        self.report['native_executed'] = True
                        self.assertRegex(executed.stdout, rb'^OCORE-BLOCKADDRESS cases=194 digest=[0-9a-f]{16}\n$')
                        outputs[label] = executed.stdout.decode()
                        artifacts.extend((pin(object_path), pin(executable)))
                self.assertEqual(len(outputs), 4)
                self.assertEqual(len(set(outputs.values())), 1)
                self.report['differential_targets'][native_target] = {
                    'outputs': outputs, 'artifacts': artifacts, 'execution_argv_prefix': runner,
                    'comparison_complete': True, 'cases_per_pairing': 194, 'provenance_qualified': False,
                    'actual_frontend_profile': {'triple': hosted, 'flags': flags},
                    'scope': 'Authored integer/AS0 computed-goto fixture; whole original runtime/closure remains unqualified'}
                self.save()
            self.assertEqual(set(self.report['differential_targets']), set(catalog['canonical_targets']))
            self.assertEqual(len({r['outputs']['owned-caller-owned-provider'] for r in self.report['differential_targets'].values()}), 1)
            self.verify_binding_inputs()
            finalize_differential(self.report, evidence, catalog['canonical_targets'])
            publish_differential(self.report, self.save)
        except BaseException as error:
            invalidate_differential(self.report)
            self.report['failure'] = {'type': type(error).__name__, 'message': str(error)}
            try:
                self.report['failure_provenance'] = evidence.finish()
            except BaseException as finalization_error:
                self.report['failure_provenance_error'] = str(finalization_error)
            publish_differential(self.report, self.save)
            raise

    def test_unchanged_complete_sre_cli_import_verify_and_lp64d_object(self):
        """One whole original unit, with its real ABI; runtime closure stays open."""
        from scripts.check_ocore_native_equivalence import RunEvidence, TARGET_CATALOG
        capture = Path('/home/orangepi/ostadix-BM/target/cpython-expansion-20261018/original-cpython-source-recipe-20261018-uuidfix/compiled/capture')
        source = capture / 'units/6522827a7092474da2e3ce9dabd6a04e/unit-0.ll'
        upstream = Path('/home/orangepi/ostadix-census-rv64-20261015-102303/src/cpython/Modules/_sre/sre.c')
        dependency_evidence = capture / 'report.json'
        def streaming_pin(path):
            path = Path(path).resolve()
            digest, size = hashlib.sha256(), 0
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
                    size += len(chunk)
            return {'path': str(path), 'bytes': size, 'sha256': digest.hexdigest()}
        original = pin(source)
        self.assertEqual(original['sha256'], '76b22ec7e2dfcdf40eb2718dd3e3687e04c6f03ff6aa677a1696c5b37fa3c42c')
        self.assertEqual(pin(upstream)['sha256'], '14a0f69cf3906098a0222438bc06ed4b808c944dd79bae45be7323552299f5e9')
        dependencies_before = streaming_pin(dependency_evidence)
        self.assertEqual(dependencies_before['sha256'], 'fb9f04225d02f9925c8a8341da14de740a0324f6622974430ed8dfc37586e9d1')
        self.verify_binding_inputs()
        evidence = RunEvidence([__file__, source, upstream, TARGET_CATALOG,
                                *(entry['path'] for entry in self.native_binding['inputs'].values())],
                               {'compiler': self.compiler, 'llvm_parser': self.library})
        self.assertEqual(evidence.tools['llvm_parser']['sha256'], self.library_sha)
        self.report['original_sre_object_gate'] = {
            'complete': False, 'original_llvm': original, 'original_c_source': pin(upstream),
            'captured_dependency_report_before': dependencies_before,
            'declared_dependency_pins_anchored_by_complete_capture_report': True,
            'captured_dependency_files_revalidated_here': False,
            'fresh_frontend_capture_executed_here': False,
            'profile': {'original_triple': 'riscv64-unknown-linux-gnu', 'original_abi': 'lp64d',
                        'realization_target': 'riscv64-unknown-none', 'retargeted': False,
                        'expected_elf_flags': 5},
            'olangc_object_admission_executed': False, 'provider_closure_complete': False,
            'native_execution_qualified': False, 'original_runtime_accepted': False}
        self.save()
        try:
            native = self.directory / 'original-sre.native.json'
            receipt = self.directory / 'original-sre.verification.json'
            obj = self.directory / 'original-sre.o'
            run = evidence.checked_run
            run([self.compiler, source, '--input-kind', 'llvm-ir', '--emit', 'mir',
                 '--target', 'riscv64-unknown-none', '--llvm-library', self.library,
                 '--llvm-sha256', self.library_sha, '-o', native])
            evidence.watch_source(native)
            run([self.compiler, native, '--input-kind', 'native-ir', '--verify-native', '--receipt', receipt])
            evidence.watch_source(receipt)
            verification = json.loads(receipt.read_text())
            self.assertIs(verification['verified'], True)
            self.assertEqual(verification['module_sha256'], pin(native)['sha256'])
            module = json.loads(native.read_text())
            self.assertEqual(module['target']['triple'], 'riscv64-unknown-linux-gnu')
            self.assertEqual(module['target']['abi'], 'lp64d')
            inventory = self.reader.read(source)
            preservation = check_inventory(inventory, module)
            preservation_path = self.directory / 'original-sre.independent-preservation.json'
            preservation_path.write_text(json.dumps({'inventory': inventory, 'preservation': preservation}, indent=2) + '\n')
            run([self.compiler, native, '--input-kind', 'native-ir', '--emit', 'obj',
                 '--target', 'riscv64-unknown-none', '--function-sections', '--keep-asm', '-o', obj])
            evidence.watch_source(obj)
            elf_profile = require_elf64_object_profile(obj, 243, 5)
            gate = self.report['original_sre_object_gate']
            gate['observed_elf_header_profile'] = elf_profile
            gate['artifacts'] = list(map(pin, (native, receipt, obj, preservation_path)))
            gate['source_counts'] = preservation['counts']
            gate['captured_dependency_report_after'] = streaming_pin(dependency_evidence)
            self.assertEqual(gate['captured_dependency_report_after'], dependencies_before)
            self.verify_binding_inputs()
            self.report['execution_provenance'] = evidence.finish()
            gate['complete'] = True
            self.save()
        except BaseException as error:
            retain_original_unit_failure(self.report['original_sre_object_gate'], evidence,
                dependency_evidence, streaming_pin, error,
                (self.directory / name for name in ('original-sre.native.json',
                    'original-sre.verification.json', 'original-sre.o',
                    'original-sre.independent-preservation.json')))
            self.report['failure'] = {'type': type(error).__name__, 'message': str(error)}
            try:
                self.save()
            except BaseException as publication_error:
                self.report['original_sre_object_gate']['failure_report_publication_error'] = {
                    'type': type(publication_error).__name__, 'message': str(publication_error)}
                try:
                    self.save()
                except BaseException:
                    pass  # No valid persisted report is assumed after repeated publication failure.
            raise
