"""AUTHORED DATA controls for the default rustc frontend replay worker contract.
UNRUN source. No filesystem/capture/compiler/decoder/process effects in these controls.
Conditional consistency is not original order, provider, admission or runtime authority.
"""
import copy
import hashlib
import json
from collections import Counter

PROFILE = 'rust-replay-emitted-module-name-v1'
PRODUCER = 'rustc-llvm-v1'
POLICY = 'frontend-replay-v1'
VERSION = ('rustc 1.91.1 (authored-data 2026-10-01)\n'
           'binary: rustc\ncommit-hash: authored-data-only\n'
           'commit-date: 2026-10-01\nhost: aarch64-unknown-linux-gnu\n'
           'release: 1.91.1\nLLVM version: 21.1.2\n')


def run_controls(baseline, candidate, registry_raw):
    """Main must consume exact verified source bytes with optimize=0.

    All pins/documents below are explicitly authored DATA. A two-output action
    and deliberately permuted fresh capture indices exercise selector consistency;
    the permutation is not evidence that the worker itself emitted unsorted units.
    """
    assert __debug__
    encode = candidate['encode']
    decode = candidate['decode']
    rows = []

    def pin(path, label):
        raw = ('AUTHORED DATA ' + label).encode()
        return {'path': path, 'bytes': len(raw),
                'sha256': hashlib.sha256(raw).hexdigest()}

    def fixture(prefix, invocation, reverse=False):
        roots = {'source': prefix + '/src', 'build': prefix + '/build',
                 'capture': prefix + '/capture'}
        source = pin(roots['source'] + '/lib.rs', 'source')
        header_a = pin(roots['source'] + '/include/a.rs', 'dependency-a')
        header_b = pin(roots['source'] + '/include/b.rs', 'dependency-b')
        directory = roots['capture'] + '/units/' + invocation
        preserved = ['--crate-name', 'sample', source['path'], '--crate-type',
                     'rlib', '--edition=2021', '-Copt-level=2']
        argv = preserved + ['--emit=link', '--out-dir', roots['build']]
        frontend = pin('/tools/rustc', 'same-rustc-tool')
        frontend.update({'version': VERSION, 'llvm_version': '21.1.2',
                         'release': '1.91.1', 'commit': 'authored-data-only',
                         'default_sysroot': '/sdk/rust',
                         'effective_sysroot': '/sdk/rust',
                         'sysroot_source': 'queried-default',
                         'unknown_frontend_metadata': {
                             'diagnostic_policy': 'authored-stable',
                             'search_root': '/sdk/rust/lib'}})
        names = ['beta.ll', 'alpha.ll'] if reverse else ['alpha.ll', 'beta.ll']
        units = []
        by_name = {}
        for index, name in enumerate(names):
            unit = {'id': invocation + ':' + str(index), 'kind': 'rustc',
                    'producer': PRODUCER, 'source': copy.deepcopy(source),
                    'ir': {**pin(directory + '/' + name, prefix + ':' + name),
                           'format': 'llvm-text',
                           'target_triple': 'aarch64-unknown-linux-gnu',
                           'data_layout': 'e-m:e-i64:64-i128:128-n32:64-S128',
                           'unknown_ir_metadata': {'semantic_profile': 'strict'}},
                    'frontend_version': VERSION,
                    'dependencies': copy.deepcopy([source, header_a, header_b])}
            assert 'replay_argv' not in unit and 'replay_exit_code' not in unit
            units.append(unit)
            by_name[name] = unit['id']
        event = {'id': invocation, 'state': 'finished', 'exit_code': 0,
                 'capture_errors': [], 'kind': 'rustc', 'producer': PRODUCER,
                 'driver_kind': 'rustc', 'compiler': '/tools/rustc',
                 'capture_worker': pin('/tools/ocore_runtime_capture.py', 'same-worker'),
                 'cwd': roots['source'], 'argv': argv,
                 'expanded_argv': list(argv), 'build_environment': {'LANG': 'C.UTF-8'},
                 'build_step': {'name': 'authored-rust-build', 'index': 0},
                 'sources': [source], 'response_files': [],
                 'outputs': [{**pin(roots['build'] + '/libsample.rlib', prefix + ':rlib'),
                              'artifact_kind': 'rlib'}],
                 'frontend': frontend,
                 'replay_argv': ['/tools/rustc', *preserved,
                                 '--emit=llvm-ir,dep-info', '--out-dir', directory],
                 'replay_exit_code': 0, 'units': units}
        assert 'executed_argv' not in event and 'rust_capture' not in event
        assert 'saved_cgus' not in event
        return event, roots, by_name

    original, original_roots, old = fixture(
        '/original', '11111111-1111-4111-8111-111111111111')
    fresh, fresh_roots, new = fixture(
        '/fresh', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', True)
    before = copy.deepcopy((original, fresh))
    required = [old['alpha.ll'], old['beta.ll']]
    occurrences = [old['beta.ll'], old['alpha.ll'], old['beta.ll']]
    order_raw = encode({'schema': 'ocore-original-provider-order-v3',
                        'scope': 'AUTHORED conditional policy DATA only',
                        'occurrences': list(occurrences)})
    selected = {PRODUCER: {POLICY: PROFILE}}
    selected_baseline = {PRODUCER: {POLICY: 'replay-source-command-v1'}}
    registry = decode(registry_raw)
    registered = [p for p in registry['producers'] if p['id'] == PRODUCER]
    assert len(registered) == 1 and registered[0]['adapter'] == 'rustc'
    assert registered[0]['capture']['policies'][POLICY] == {
        'format': 'llvm-text', 'frontend_replay': True}

    def rejection(name, function, expected, evidence):
        assert evidence, name + ': direct mutation/reach witness absent'
        try:
            function()
        except candidate['JoinError'] as error:
            assert str(error) == expected, (name, str(error), expected)
            rows.append({'name': name, 'pass': True, 'expected_reason': expected,
                         'actual_reason': str(error), 'mutation_witness': True})
        else:
            raise AssertionError(name + ': changed DATA was accepted')

    # The old registered profile reaches its real missing-per-unit-replay gate.
    # It must not fail merely because the new profile was selected for old code.
    try:
        baseline['commit_order_v2']([baseline['encode'](original)], required,
            original_roots, occurrences, order_raw, registry_raw, selected_baseline)
    except baseline['JoinError'] as error:
        assert str(error) == 'implementation IR production did not succeed', str(error)
        rows.append({'name': 'baseline_actual_worker_shape_reaches_missing_unit_replay',
                     'pass': True, 'actual_reason': str(error),
                     'no_per_unit_replay': all('replay_exit_code' not in u
                                              for u in original['units'])})
    else:
        raise AssertionError('baseline unexpectedly accepted actual default replay shape')

    committed = candidate['commit_order_v2']([encode(original)], required,
        original_roots, occurrences, order_raw, registry_raw, selected)

    def resolve(mutant=None, changed_occurrences=None):
        return candidate['resolve_order_v2'](committed, [encode(original)], required,
            occurrences if changed_occurrences is None else changed_occurrences,
            [encode(fresh if mutant is None else mutant)], original_roots, fresh_roots,
            order_raw, registry_raw, selected)

    result = resolve()
    expected_mapping = {old[name]: new[name] for name in ['alpha.ll', 'beta.ll']}
    assert result['unit_mapping'] == expected_mapping
    assert result['original_occurrences'] == occurrences
    assert result['fresh_occurrences'] == [new['beta.ll'], new['alpha.ll'], new['beta.ll']]
    assert result['fresh_capture_order'] == [new['beta.ll'], new['alpha.ll']]
    assert result['consistency_join_complete'] is True
    for key in ['capture_admitted', 'Cargo_parent_semantic_join_supported',
                'original_order_producer_qualified', 'provider_closure_qualified',
                'runtime_qualified']:
        assert result[key] is False, key
    action = result['fresh_actions_and_complete_lineage'][0]
    assert action['projection']['contract']['selector_profile'] == PROFILE
    assert {u['selector']['emitted_filename'] for u in action['units']} == {'alpha.ll', 'beta.ll'}
    rows.append({'name': 'candidate_maps_complete_emitted_names_across_uuid_index_reorder',
                 'pass': True, 'mapping': result['unit_mapping'],
                 'repeated_occurrences': result['fresh_occurrences'],
                 'capture_order': result['fresh_capture_order']})

    committed_action = decode(committed)['actions'][0]
    for projected, event in [(committed_action, original), (action, fresh)]:
        assert projected['projection']['frontend_metadata'] == {
            k: v for k, v in event['frontend'].items()
            if k not in {'path', 'bytes', 'sha256'}}
        assert projected['projection']['frontend_metadata']['version'] == VERSION
        assert '\n' in VERSION and VERSION.endswith('\n')
        assert projected['projection']['frontend_metadata']['effective_sysroot'] == '/sdk/rust'
        assert projected['projection']['frontend_metadata']['sysroot_source'] == 'queried-default'
        assert projected['projection']['frontend_replay']['argv'][-1] == {
            'action_artifact_directory': 'rust-frontend-replay'}
        for unit, raw_unit in zip(projected['units'], event['units']):
            assert unit['lineage']['unit'] == raw_unit
            assert unit['lineage']['replay_argv'] == event['replay_argv']
            assert unit['lineage']['replay_exit_code'] == 0
            assert unit['projection']['dependencies'] == [
                candidate['Paths'](original_roots if event is original else fresh_roots).artifact(d)
                for d in raw_unit['dependencies']]
    assert (original, fresh) == before
    rows.append({'name': 'multiline_frontend_metadata_raw_lineage_and_inputs_retained',
                 'pass': True, 'multiline_version': True, 'raw_unit_and_replay': True,
                 'full_frontend_metadata': True, 'dependency_order_preserved': True,
                 'input_fixtures_unchanged': True})

    def mutant(name, edit, expected, witness):
        value = copy.deepcopy(fresh)
        previous = copy.deepcopy(value)
        edit(value)
        assert value != previous, name + ': edit did not change DATA'
        rejection(name, lambda: resolve(value), expected, witness(previous, value))

    inventory = 'fresh stable output inventory differs'
    owner = 'Rust replay unit producer/frontend differs from owner'
    directory_error = 'Rust replay unit is outside its owning output directory'
    action_error = 'fresh owning action contract differs'
    unit_error = 'fresh unit source/profile/dependency differs'
    command_error = 'Rust replay command differs from the registered output contract'

    mutant('missing_emitted_output_is_not_partial_success',
        lambda e: e['units'].pop(), inventory,
        lambda p, e: len(p['units']) == 2 and len(e['units']) == 1)

    def add_output(e):
        extra = copy.deepcopy(e['units'][0])
        extra['id'] = e['id'] + ':2'
        extra['ir']['path'] = e['replay_argv'][-1] + '/gamma.ll'
        e['units'].append(extra)
    mutant('extra_emitted_output_rejects_complete_inventory', add_output, inventory,
        lambda p, e: len(e['units']) == 3 and e['units'][-1]['ir']['path'].endswith('/gamma.ll'))
    mutant('duplicate_emitted_filename_with_distinct_ids_is_ambiguous',
        lambda e: e['units'][1]['ir'].__setitem__('path', e['units'][0]['ir']['path']),
        'ambiguous stable output selector',
        lambda p, e: e['units'][0]['id'] != e['units'][1]['id'] and
                     e['units'][0]['ir']['path'] == e['units'][1]['ir']['path'])
    mutant('duplicate_capture_unit_id_with_distinct_filenames_rejects',
        lambda e: e['units'][1].__setitem__('id', e['units'][0]['id']),
        'duplicate owning-action unit',
        lambda p, e: e['units'][0]['id'] == e['units'][1]['id'] and
                     e['units'][0]['ir']['path'] != e['units'][1]['ir']['path'])
    mutant('ir_must_belong_to_exact_replay_directory',
        lambda e: e['units'][0]['ir'].__setitem__('path',
            fresh_roots['capture'] + '/units/other-owner/beta.ll'), directory_error,
        lambda p, e: e['units'][0]['ir']['path'].rsplit('/', 1)[0] != e['replay_argv'][-1])
    mutant('emitted_artifact_requires_ll_suffix',
        lambda e: e['units'][0]['ir'].__setitem__('path', e['replay_argv'][-1] + '/beta.bc'),
        directory_error, lambda p, e: e['units'][0]['ir']['path'].endswith('.bc'))
    mutant('wrong_replay_emit_contract_rejects',
        lambda e: e['replay_argv'].__setitem__(-3, '--emit=llvm-bc,dep-info'), command_error,
        lambda p, e: p['replay_argv'][-3] != e['replay_argv'][-3])
    mutant('different_replay_outdir_cannot_rebind_existing_units',
        lambda e: e['replay_argv'].__setitem__(-1, fresh_roots['capture'] + '/units/other-owner'),
        directory_error, lambda p, e: p['replay_argv'][-1] != e['replay_argv'][-1])
    mutant('noncanonical_replay_directory_rejects',
        lambda e: e['replay_argv'].__setitem__(-1, e['replay_argv'][-1] + '/../other'),
        'Rust replay output directory is not canonical',
        lambda p, e: '/../' in e['replay_argv'][-1])
    mutant('duplicate_replay_emit_option_rejects',
        lambda e: e['replay_argv'].insert(1, '--emit=link'), command_error,
        lambda p, e: sum(v.startswith('--emit') for v in e['replay_argv']) == 2)
    mutant('separate_output_option_cannot_replace_worker_contract',
        lambda e: e['replay_argv'].insert(1, '-o'), command_error,
        lambda p, e: '-o' not in p['replay_argv'] and '-o' in e['replay_argv'])

    def per_unit_command(e):
        e['units'][0]['replay_argv'] = list(e['replay_argv'])
        e['units'][0]['replay_exit_code'] = 0
    mutant('per_unit_replay_command_is_not_default_worker_evidence', per_unit_command,
        'Rust replay unit cannot invent a per-unit command',
        lambda p, e: 'replay_argv' not in p['units'][0] and
                     e['units'][0]['replay_argv'] == e['replay_argv'])
    mutant('actual_event_replay_failure_rejects',
        lambda e: e.__setitem__('replay_exit_code', 7), 'Rust frontend replay did not succeed',
        lambda p, e: p['replay_exit_code'] == 0 and e['replay_exit_code'] == 7)
    mutant('injected_executed_argv_is_not_default_worker_evidence',
        lambda e: e.__setitem__('executed_argv', list(e['replay_argv'])),
        'default Rust replay has no separately recorded executed argv',
        lambda p, e: 'executed_argv' not in p and 'executed_argv' in e)
    mutant('unit_producer_must_match_owning_registered_rustc',
        lambda e: e['units'][0].__setitem__('producer', 'clang-llvm-v1'), owner,
        lambda p, e: p['units'][0]['producer'] != e['units'][0]['producer'])
    mutant('unit_kind_must_match_owning_rustc',
        lambda e: e['units'][0].__setitem__('kind', 'clang'), owner,
        lambda p, e: p['units'][0]['kind'] != e['units'][0]['kind'])
    mutant('unit_frontend_version_must_equal_full_owner_version',
        lambda e: e['units'][0].__setitem__('frontend_version', 'rustc 1.91.1'), owner,
        lambda p, e: p['units'][0]['frontend_version'] == VERSION and
                     e['units'][0]['frontend_version'] != e['frontend']['version'])
    mutant('unknown_frontend_metadata_drift_changes_action',
        lambda e: e['frontend']['unknown_frontend_metadata'].__setitem__('diagnostic_policy', 'changed'),
        action_error, lambda p, e: p['frontend']['unknown_frontend_metadata'] !=
                                  e['frontend']['unknown_frontend_metadata'])
    mutant('effective_sysroot_drift_changes_action',
        lambda e: e['frontend'].__setitem__('effective_sysroot', '/sdk/other-rust'), action_error,
        lambda p, e: p['frontend']['effective_sysroot'] != e['frontend']['effective_sysroot'])
    mutant('default_sysroot_drift_changes_action',
        lambda e: e['frontend'].__setitem__('default_sysroot', '/sdk/other-default'), action_error,
        lambda p, e: p['frontend']['default_sysroot'] != e['frontend']['default_sysroot'])
    mutant('sysroot_source_drift_changes_action',
        lambda e: e['frontend'].__setitem__('sysroot_source', 'explicit-argv'), action_error,
        lambda p, e: p['frontend']['sysroot_source'] != e['frontend']['sysroot_source'])
    mutant('ir_layout_drift_changes_unit',
        lambda e: e['units'][0]['ir'].__setitem__('data_layout', 'e-p:32:32-i64:64-n32-S64'),
        unit_error, lambda p, e: p['units'][0]['ir']['data_layout'] != e['units'][0]['ir']['data_layout'])
    mutant('unknown_ir_metadata_drift_changes_unit',
        lambda e: e['units'][0]['ir']['unknown_ir_metadata'].__setitem__('semantic_profile', 'changed'),
        unit_error, lambda p, e: p['units'][0]['ir']['unknown_ir_metadata'] !=
                                e['units'][0]['ir']['unknown_ir_metadata'])

    def reorder_dependencies(e):
        deps = e['units'][0]['dependencies']
        deps[1], deps[2] = deps[2], deps[1]
    mutant('recorded_dependency_order_is_not_sorted_away', reorder_dependencies, unit_error,
        lambda p, e: p['units'][0]['dependencies'] != e['units'][0]['dependencies'] and
        Counter(encode(v) for v in p['units'][0]['dependencies']) ==
        Counter(encode(v) for v in e['units'][0]['dependencies']))
    mutant('missing_dependency_changes_unit',
        lambda e: e['units'][0]['dependencies'].pop(), unit_error,
        lambda p, e: len(p['units'][0]['dependencies']) == 3 and
                     len(e['units'][0]['dependencies']) == 2)

    def semantic_flags(e):
        for key in ['argv', 'expanded_argv', 'replay_argv']:
            index = e[key].index('-Copt-level=2')
            e[key][index] = '-Copt-level=3'
    mutant('semantic_flags_drift_changes_actual_action_contract', semantic_flags, action_error,
        lambda p, e: all('-Copt-level=2' in p[k] and '-Copt-level=3' in e[k]
                         for k in ['argv', 'expanded_argv', 'replay_argv']))
    mutant('cargo_parent_remains_explicitly_unsupported',
        lambda e: e.__setitem__('cargo_parent_invocation_id', 'authored-cargo-parent'),
        'Cargo parent semantic context unsupported; independently admitted observer action required',
        lambda p, e: p.get('cargo_parent_invocation_id') is None and
                     e['cargo_parent_invocation_id'] == 'authored-cargo-parent')

    # Reuse the ONE committed original. Recomputing it with the changed sequence
    # would authorize a different policy and would make this oracle meaningless.
    reordered = [old['beta.ll'], old['beta.ll'], old['alpha.ll']]
    rejection('sealed_occurrence_order_rejects_equal_counter_reordering',
        lambda: resolve(changed_occurrences=reordered),
        'pre-stage original action/order/contract commitment changed',
        reordered != occurrences and Counter(reordered) == Counter(occurrences))
    changed_multiplicity = [old['beta.ll'], old['alpha.ll'], old['alpha.ll']]
    rejection('sealed_occurrence_multiplicity_rejects_independently',
        lambda: resolve(changed_occurrences=changed_multiplicity),
        'pre-stage original action/order/contract commitment changed',
        set(changed_multiplicity) == set(occurrences) and
        Counter(changed_multiplicity) != Counter(occurrences))
    assert (original, fresh) == before
    assert len({row['name'] for row in rows}) == len(rows)
    return {'schema': 'rust-replay-emitted-module-name-AUTHORED-DATA-controls-v1',
            'all_pass': all(row['pass'] for row in rows), 'controls': rows,
            'scope': 'conditional DATA consistency only; no actual rustc/worker/capture execution',
            'capture_admitted': False, 'compiler_execution': False,
            'decoder_execution': False, 'original_order_producer_qualified': False,
            'provider_closure_qualified': False, 'runtime_qualified': False,
            'cross_ISA_qualified': False, 'PYC_native_semantics_qualified': False}
