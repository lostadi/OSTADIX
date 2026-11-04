"""INERT DATA oracles derived from actual worker/payload field schemas.
No original compiler, Rust/Clang, subprocess, ELF/bitcode readmission or engine.
The helper remains a consistency join, never an admission authority.
"""
from pathlib import Path
import copy
import hashlib
import json
import types
import unittest

ROOTS = {'source': '/old/source', 'build': '/old/build', 'capture': '/old/capture'}
FRESH_ROOTS = {k: v.replace('/old/', '/fresh/') for k, v in ROOTS.items()}


def artifact(path, size=64, sha='1'):
    return {'path': path, 'bytes': size, 'sha256': sha * 64}


def native(count=2, archive=True):
    source = artifact('/old/source/lib.rs', 24)
    output = artifact('/old/build/libengine.a' if archive else '/old/build/engine.o', 512 if archive else 64, '9')
    output['artifact_kind'] = 'archive' if archive else 'object'
    argv = ['/tool/rustc', '--crate-name', 'engine', source['path'], '-o', output['path']]
    event = {'id': 'a', 'state': 'finished', 'exit_code': 0, 'capture_errors': [],
             'producer': 'rustc-llvm-v1', 'kind': 'rustc', 'driver_kind': 'rustc',
             'compiler': '/tool/rustc', 'cwd': '/old/source', 'argv': argv,
             'expanded_argv': argv, 'executed_argv': argv + ['-C', 'embed-bitcode=yes'],
             'build_environment': {'LANG': 'C'}, 'build_step': {'name': 'compile-original', 'index': 0},
             'capture_worker': artifact('/tool/capture.py', 154484, 'a'),
             'frontend': {**artifact('/tool/rustc', 1024, '4'), 'version': 'rustc 1.97.1', 'llvm_version': '22.1.6'},
             'sources': [source], 'response_files': [], 'outputs': [output],
             'cargo_parent_invocation_id': None,
             'rust_capture': {'policy': 'rust-embedded-bc-v1', 'applied': True,
                              'transformations': [], 'original_command_executed': False,
                              'frontend_replay_used': False, 'post_lto_equivalence_verified': False,
                              'argfile_gap': None},
             'rust_cgu_gaps': [], 'rust_native_resources': [], 'saved_cgus': [], 'units': []}
    for index in range(count):
        bitcode = artifact('/old/capture/cgu-' + str(index) + '.bc', 8, '5' if index == 0 else '6')
        obj = artifact('/old/capture/cgu-' + str(index) + '.o', 64, '7' if index == 0 else '8') if archive else dict(output)
        name = 'engine.main.rcgu.o' if index == 0 else 'engine.cold.rcgu.o'
        member = {'index': index, 'physical_index': index, 'name': name, 'name_bytes': list(name.encode()),
                  'header_offset': 8 + index * 124, 'data_offset': 68 + index * 124,
                  'raw_data_offset': 68 + index * 124, 'raw_bytes': 64, 'bytes': 64, 'sha256': obj['sha256']}
        edge = {'kind': 'elf_embedded_bitcode', 'section_index': 1, 'section_name': '.llvmbc',
                'section_name_bytes': list(b'.llvmbc'), 'object_offset': 16,
                'container_offset': member['data_offset'] + 16 if archive else 16,
                'bytes': 8, 'sha256': bitcode['sha256'], 'bitcode_header': {'kind': 'raw'}}
        record = {'schema': 'ocore-rust-native-bitcode-edge-v1', 'compiler_invocation_id': 'a',
                  'cargo_parent_invocation_id': None, 'object': obj, 'bitcode': bitcode, 'edge': edge}
        if archive:
            record['container'] = {'artifact': dict(output), 'member': member}
        event['saved_cgus'].append(record)
        event['units'].append({'id': 'a:' + str(index), 'kind': 'rustc', 'source': source,
            'ir': {**bitcode, 'format': 'llvm-bitcode', 'target_triple': 'riscv64-unknown-linux-gnu',
                   'data_layout': 'e-m:e-p:64:64-i64:64-n32:64-S128'},
            'frontend_version': 'rustc 1.97.1', 'dependencies': [source], 'saved_cgu_index': index,
            'capture_policy': 'rust-embedded-bc-v1', 'source_production_ownership_verified': False,
            'native_machine_equivalence_verified': False, 'post_lto_equivalence_verified': False})
    return event


def replay(count=2):
    event = native(1)
    for key in ['saved_cgus', 'rust_capture', 'rust_cgu_gaps', 'rust_native_resources']:
        event.pop(key)
    event.update(producer='clang-llvm-v1', kind='clang', driver_kind='clang', compiler='/tool/clang')
    event['frontend'] = {**artifact('/tool/clang', 1024, '4'), 'version': 'clang 22.1.6', 'llvm_version': '22.1.6'}
    event['sources'] = [artifact('/old/source/' + ('main.c' if i == 0 else 'cold.c'), 24, str(i + 1)) for i in range(count)]
    event['argv'] = ['/tool/clang', '-c', *[s['path'] for s in event['sources']]]
    event['expanded_argv'] = event['argv'];event['executed_argv'] = event['argv']
    event['outputs'] = [{**artifact('/old/build/' + str(i) + '.o'), 'artifact_kind': 'object'} for i in range(count)]
    event['units'] = []
    for i, source in enumerate(event['sources']):
        ir = {**artifact('/old/capture/' + str(i) + '/module.ll'), 'format': 'llvm-text',
              'target_triple': 'riscv64-unknown-linux-gnu', 'data_layout': 'e-m:e-p:64:64-i64:64-n32:64-S128'}
        event['units'].append({'id': 'a:' + str(i), 'kind': 'clang', 'producer': 'clang-llvm-v1',
            'source': source, 'ir': ir, 'dependencies': [source], 'replay_exit_code': 0,
            'replay_argv': ['/tool/clang', '-S', '-emit-llvm', source['path'], '-o', ir['path'], '-MF', ir['path'] + '.d']})
    return event


def fresh(event):
    def visit(value):
        if type(value) is str:
            return value.replace('/old/', '/fresh/')
        if type(value) is list:
            return [visit(v) for v in value]
        if type(value) is dict:
            return {k: visit(v) for k, v in value.items()}
        return value
    event = visit(copy.deepcopy(event));event['id'] = 'b'
    for i, unit in enumerate(event['units']):
        unit['id'] = 'b:' + str(i)
    for record in event.get('saved_cgus', []):
        record['compiler_invocation_id'] = 'b'
    return event



class GeneralBridgeProtocolControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=Path(__file__).resolve().parents[1]
        path=cls.root/'src/bin/olangc/native_runtime/general_source_order_join.py'
        raw=path.read_bytes()
        assert hashlib.sha256(raw).hexdigest()=='87476f092eb0e01d4410c8f5a09e5293b69eb9d9a577a2502437739fc630def5'
        cls.h=types.ModuleType('checked_production_general_bridge')
        exec(compile(raw,str(path),'exec'),cls.h.__dict__)
        cls.registry=(cls.root/'scripts/ocore_producer_registry.json').read_bytes()
        assert hashlib.sha256(cls.registry).hexdigest()=='62d74350f9b97db882f96ccb04fb985ff519e45d648b2f977664c2e631ff4052'
        cls.profiles={'rustc-llvm-v1':{'rust-embedded-bc-v1':'native-container-member-name-v1'},
                      'clang-llvm-v1':{'frontend-replay-v1':'replay-source-command-v1'}}
        cls.policy=cls.h.encode({'schema':'ocore-original-provider-order-v3','fixture':'authored-no-native-authority'})

    def requests(self, original=None, current=None):
        original=native() if original is None else original
        current=fresh(original) if current is None else current
        ids=[u['id'] for u in original['units']]
        req={'schema':'Main-source-order-helper-request/v2','operation':'commit',
             'original_events':[self.h.encode(original).decode()], 'required_unit_ids':ids,
             'original_roots':ROOTS,'original_occurrences':list(reversed(ids))+ids[:1],
             'original_order_raw':self.policy.decode(),'registry_raw':self.registry.decode(),
             'selected_profiles':self.profiles}
        committed=self.h.bridge(req)
        resolve={**req,'operation':'resolve','commitment':committed['commitment'],
                 'fresh_events':[self.h.encode(current).decode()],'fresh_roots':FRESH_ROOTS}
        return req, resolve

    def test_versioned_bridge_native_positive_preserves_false_admission(self):
        _,req=self.requests()
        result=self.h.bridge(req)
        self.assertEqual(result['schema'],'ocore-original-ordered-multi-output-join-v2')
        self.assertEqual(result['unit_mapping'],{'a:0':'b:0','a:1':'b:1'})
        self.assertFalse(result['capture_admitted']);self.assertFalse(result['runtime_qualified'])
        self.assertFalse(result['Cargo_parent_semantic_join_supported'])

    def test_versioned_bridge_archive_permutation_uses_raw_member_selector(self):
        original=native();current=fresh(original)
        current['saved_cgus'].reverse()
        for unit in current['units']:
            unit['saved_cgu_index']=1-unit['saved_cgu_index'];unit['id']='b:'+str(unit['saved_cgu_index'])
        current['units'].reverse()
        _,req=self.requests(original,current);result=self.h.bridge(req)
        self.assertEqual(result['unit_mapping'],{'a:0':'b:1','a:1':'b:0'})
        self.assertEqual(result['fresh_occurrences'],['b:0','b:1','b:1'])

    def test_wrong_protocol_version_is_actually_rejected(self):
        req,_=self.requests();req['schema']='Main-source-order-helper-request/v1'
        self.assertEqual(req['schema'],'Main-source-order-helper-request/v1')
        with self.assertRaisesRegex(self.h.JoinError,'bridge request schema'):self.h.bridge(req)

    def test_missing_selected_contract_field_is_actually_rejected(self):
        req,_=self.requests();del req['selected_profiles'];self.assertNotIn('selected_profiles',req)
        with self.assertRaisesRegex(self.h.JoinError,'bridge request fields differ'):self.h.bridge(req)

    def test_native_replay_cannot_be_injected_through_bridge(self):
        original=native();current=fresh(original);current['replay_argv']=['invented']
        self.assertEqual(current['replay_argv'],['invented'])
        _,req=self.requests(original,current)
        with self.assertRaisesRegex(self.h.JoinError,'cannot substitute frontend replay'):self.h.bridge(req)

    def test_non_none_cargo_parent_is_not_normalized(self):
        original=native();current=fresh(original);current['cargo_parent_invocation_id']='new-parent'
        self.assertEqual(current['cargo_parent_invocation_id'],'new-parent')
        _,req=self.requests(original,current)
        with self.assertRaisesRegex(self.h.JoinError,'Cargo parent semantic context unsupported'):self.h.bridge(req)

    def test_changed_registry_after_commit_is_not_rebound(self):
        _,req=self.requests();before=req['registry_raw'];req['registry_raw']=before+'\n'
        self.assertNotEqual(req['registry_raw'],before)
        self.assertEqual(json.loads(req['registry_raw']),json.loads(before))
        with self.assertRaisesRegex(self.h.JoinError,'pre-stage original action/order/contract commitment changed'):
            self.h.bridge(req)

    def test_resource_hash_change_remains_explicit_profile_conflict(self):
        original=native();dep=artifact('/old/build/engine.d',128,'d')
        original['outputs'].append({**dep,'artifact_kind':'dependency'})
        original['rust_native_resources'].append({'artifact':dep,'kind':'rust_dependency_file',
            'native_code':False,'ownership_qualified':False})
        current=fresh(original)
        current['outputs'][1]['sha256']='e'*64
        current['rust_native_resources'][0]['artifact']['sha256']='e'*64
        self.assertNotEqual(current['outputs'][1]['sha256'],original['outputs'][1]['sha256'])
        _,req=self.requests(original,current)
        with self.assertRaisesRegex(self.h.JoinError,'fresh owning action contract differs'):self.h.bridge(req)

    def test_versioned_bridge_registered_replay_retains_required_replay_proof(self):
        original=replay();current=fresh(original);current['units'].reverse();current['outputs'].reverse()
        _,req=self.requests(original,current);result=self.h.bridge(req)
        self.assertEqual(result['unit_mapping'],{'a:0':'b:0','a:1':'b:1'})
        self.assertFalse(result['capture_admitted']);self.assertNotIn('rust_capture',current)
        del current['units'][0]['replay_exit_code']
        self.assertNotIn('replay_exit_code',current['units'][0])
        _,req=self.requests(original,current)
        with self.assertRaisesRegex(self.h.JoinError,'IR production did not succeed'):self.h.bridge(req)
