#!/usr/bin/env python3
"""Compare independently specified lifecycle traces with actual native policy.

The component carrier models privileged architecture hooks. This runner does
not qualify guest boots, physical hardware, SMP, transfer escrows or views.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import ocore_lifecycle_model as model

SPEC = importlib.util.spec_from_file_location('ocore_native_evidence', ROOT / 'scripts/check_ocore_native_equivalence.py')
native = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native
SPEC.loader.exec_module(native)

WORLD_WRAPPER = ('\npub unsafe fn lifecycle_test_init() -> u64 { LIVE[0]=1; LIVE[1]=1; return gic_init(); }\n'
                 'pub unsafe fn lifecycle_test_request() -> u64 { native_control(); return LIVE[0] | (LIVE[1] << 1); }\n')
MONITOR_WRAPPER = '\npub unsafe fn lifecycle_test_admit() -> void { RAM_LIVE=1; }\n'
PROFILE = ('module runtime::aarch64::kernel_world_profile;\n'
           'pub const PERSISTENT:u64=1;\npub const NETWORK:u64=1;\npub const NAMESPACE:u64=1;\n'
           'pub const BACKING_BASE:usize=0x70000000;\npub const BACKING_BYTES:usize=4096;\n'
           'pub const O10_QUALIFICATION:u64=1;\n')
PRIVATE = {
    'runtime__common__namespace_store': ('SERIAL', 'GENERATION'),
    'runtime__common__o10_executor': ('LAST', 'EPOCH'),
    'runtime__aarch64__kernel_world_9p': ('SESSION_EPOCH', 'ACTIVE'),
    'runtime__aarch64__plan9_namespace_uart': ('ACTIVE',),
    'runtime__aarch64__unified_world': ('O10_DOMAIN_GENERATION', 'LINUX_LEASE_GENERATION',
        'O10_LEASE_GENERATION', 'LINUX_SESSION_GENERATION', 'O10_SESSION_GENERATION',
        'LIVE', 'BLOCKED', 'LINUX_WAIT_BIND', 'O10_WAIT_BIND', 'LINUX_DETACHED',
        'LINUX_WITHDRAWN', 'PLAN9_WITHDRAWN'),
}
MODELED_HOOKS = frozenset(('kw_memory_barrier', 'uw_memory_barrier', 'uw_domain_reset',
    'uw_counter_read', 'uw_serial_putc', 'uw_vgic_lr_count', 'uw_vgic_lr_read',
    'uw_vgic_lr_write', 'uw_vgic_vmcr_read', 'uw_vgic_vmcr_write',
    'uw_vgic_hcr_read', 'uw_vgic_hcr_write', 'uw_halt'))


def load_vectors(path):
    document = json.loads(Path(path).read_text())
    if not isinstance(document, dict) or document.get('schema') != 'ostadix.ocore-lifecycle-vectors/v1':
        raise RuntimeError('unsupported lifecycle corpus schema')
    cases = document.get('cases')
    if not isinstance(cases, list) or not cases:
        raise RuntimeError('empty lifecycle corpus cannot qualify')
    seen = set()
    for case in cases:
        if not isinstance(case, dict):
            raise RuntimeError('lifecycle case must be an object')
        name = case.get('name', '')
        if not isinstance(name, str) or not re.fullmatch('[a-zA-Z0-9_.-]+', name) or name in seen:
            raise RuntimeError('invalid or duplicate lifecycle case name')
        seen.add(name)
        initial = case.get('initial', {})
        if (not isinstance(initial, dict) or set(initial) - {'transport', 'plan9_epoch', 'serial',
                'domain', 'lease', 'session_epoch', 'last', 'epoch'}
                or any(type(value) is not int or not 0 <= value <= model.U64 for value in initial.values())):
            raise RuntimeError('invalid lifecycle initial scalar state')
        if not isinstance(case.get('steps'), list) or not 1 <= len(case['steps']) <= 10000:
            raise RuntimeError('empty or oversized lifecycle trace: ' + name)
        for step in case['steps']:
            if not isinstance(step, dict) or set(step) - {'op', 'a', 'b', 'c', 'd', 'data'}:
                raise RuntimeError('unknown lifecycle command fields')
            if type(step.get('op')) is not int or not 1 <= step['op'] <= 17:
                raise RuntimeError('unknown lifecycle opcode')
            for field in ('a', 'b', 'c', 'd'):
                value = step.get(field, 0)
                if type(value) is not int or not 0 <= value <= model.U64:
                    raise RuntimeError('invalid lifecycle scalar input')
            try:
                data = bytes.fromhex(step.get('data', ''))
            except (ValueError, TypeError) as error:
                raise RuntimeError('invalid lifecycle frame hex') from error
            if len(data) > 512:
                raise RuntimeError('carrier frame capacity exceeded')
        expected = model.evaluate_case(case)
        if case.get('expected') != expected:
            raise RuntimeError('stored oracle expectations differ: ' + name)
    return document


def corpus_admission(path, diagnostic):
    canonical = native.file_identity(ROOT / 'tests/fixtures/ocore_lifecycle_vectors.json')
    selected = native.file_identity(path)
    matches = selected['sha256'] == canonical['sha256']
    if not matches and not diagnostic:
        raise RuntimeError('differing custom corpus requires --diagnostic-component-only')
    return {'canonical': canonical, 'selected': selected, 'canonical_bytes': matches,
            'scope': 'canonical full-width corpus' if matches else 'custom diagnostic corpus'}


def case_bytes(case):
    initial = case.get('initial', {})
    fields = [initial.get('transport', 1), initial.get('plan9_epoch', 1)]
    fields.extend(initial.get(k, 0) for k in ('serial', 'domain', 'lease', 'session_epoch', 'last', 'epoch'))
    output = struct.pack('<Q9Q', 0x31434c4f434f, *fields, len(case['steps']))
    for step in case['steps']:
        payload = bytes.fromhex(step.get('data', ''))
        output += struct.pack('<6Q', step['op'], *(step.get(k, 0) for k in ('a', 'b', 'c', 'd')), len(payload)) + payload
    return output


def canonical_effects(events):
    """Compare complete saved-bank resets while allowing redundant writes.

    These are modeled virtual-interface hooks, not physical interrupt proof.
    A bank reset must clear every fixture LR and establish HCR/VMCR state;
    duplicate same-value writes do not change that observable reset. Ordering
    relative to RAM-copy/reset effects and other domains remains significant.
    """
    result, at = [], 0
    while at < len(events):
        event = events[at]
        if event[0] < 3:
            result.append(event)
            at += 1
            continue
        domain, writes = event[1], {}
        while at < len(events) and events[at][0] >= 3 and events[at][1] == domain:
            kind, _, first, second = events[at]
            key = (kind, first if kind == 5 else 0)
            observed = second if kind == 5 else first
            if key in writes and writes[key] != observed:
                raise RuntimeError('interrupt-bank reset contains changing writes')
            writes[key] = observed
            at += 1
        # Every fixture starts with empty saved LRs, and these probes never
        # inject an interrupt into them. Rewriting only those zero registers
        # while folding a rejected device request leaves the bank unchanged.
        if writes and all(key[0] == 5 and value == 0 for key, value in writes.items()):
            continue
        required = {(5, index): 0 for index in range(4)} | {(4, 0): 1, (3, 0): 0xff000002}
        if writes != required:
            raise RuntimeError('incomplete or incorrect modeled interrupt-bank reset')
        result.extend([list(row) for row in model.interrupt_bank_reset(domain)])
    return result


def compare_case(case, stdout, exit_code):
    try:
        text = stdout.decode('utf-8') if isinstance(stdout, bytes) else stdout
        actual = [json.loads(line) for line in text.splitlines()]
    except (UnicodeDecodeError, ValueError) as error:
        raise RuntimeError('invalid lifecycle observation encoding') from error
    expected = model.evaluate_case(case)
    if len(actual) != len(expected):
        raise RuntimeError(f"{case['name']}: observation count {len(actual)} != {len(expected)}")
    wanted_exit = 86 if any(expected[-1]['terminal']) else 0
    if exit_code != wanted_exit:
        raise RuntimeError(f"{case['name']}: exit {exit_code} != {wanted_exit}")
    mapping = model.TokenCorrespondence()
    for reference, observed in zip(expected, actual):
        step = reference['step']
        required = (set(reference) - {'value_kind', 'semantic_effects'}) | {'effects'}
        if not isinstance(observed, dict) or set(observed) != required:
            raise RuntimeError(f"{case['name']} step {step}: observation schema differs")
        for key in required - {'reply', 'effects'}:
            values = observed[key] if isinstance(observed[key], list) else [observed[key]]
            if any(type(value) is not int or not 0 <= value <= model.U64 for value in values):
                raise RuntimeError('non-u64 lifecycle observation: ' + key)
        if len(observed['sessions']) != 4:
            raise RuntimeError('session observation coverage differs')
        try:
            for symbol, concrete in zip(reference['sessions'], observed['sessions']):
                mapping.observe(symbol, concrete)
            if reference['value_kind'] == 'session':
                mapping.observe(reference['value'], observed['value'])
        except AssertionError as error:
            raise RuntimeError(f"{case['name']} step {step}: {error}") from error
        effects = observed['effects']
        if not isinstance(effects, list) or len(effects) > 512:
            raise RuntimeError('unbounded lifecycle effect record')
        for event in effects:
            if (not isinstance(event, list) or len(event) != 4
                    or any(type(x) is not int or not 0 <= x <= model.U64 for x in event)
                    or not 1 <= event[0] <= 5 or event[1] > 1
                    or (event[0] == 5 and event[2] >= 4)):
                raise RuntimeError('invalid modeled privileged effect')
        for key, value in reference.items():
            if key in ('sessions', 'value_kind') or key == 'value' and reference['value_kind'] == 'session':
                continue
            candidate = canonical_effects(effects) if key == 'semantic_effects' else observed[key]
            if value != candidate:
                raise RuntimeError(f"{case['name']} step {step}: {key} expected {value!r}, observed {candidate!r}")
    return {'name': case['name'], 'observations': len(actual), 'exit_code': exit_code,
            'symbolic_to_concrete': {str(k): v for k, v in mapping.forward.items()},
            'observation_sha256': hashlib.sha256(text.encode()).hexdigest(), 'matched': True}


def production_sources(root):
    inventory = root / 'scripts/build_okernel_unified_world.py'
    tree = ast.parse(inventory.read_text())
    nodes = [n.value for n in tree.body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == 'SOURCES' for t in n.targets)]
    if len(nodes) != 1:
        raise RuntimeError('unrecognized policy source inventory')
    names = ast.literal_eval(nodes[0])
    if not isinstance(names, (tuple, list)) or not names or len(names) != len(set(names)):
        raise RuntimeError('empty or duplicate policy sources')
    paths = []
    for name in names:
        if not isinstance(name, str) or not name.endswith('.oc'):
            raise RuntimeError('invalid policy source')
        relative = Path(name)
        if (relative.is_absolute() or relative.as_posix() != name
                or any(part in ('.', '..') for part in relative.parts)):
            raise RuntimeError('policy source must be a normalized relative path')
        path = (root / name).resolve(strict=True)
        if not path.is_relative_to(root):
            raise RuntimeError('policy source escapes checkout')
        paths.append((name, path))
    return paths


def prepare_inputs(args, directory, evidence, mutations=()):
    inputs, captured = [], []
    profile = directory / 'generated/profile.oc'
    profile.parent.mkdir(parents=True)
    profile.write_text(PROFILE)
    evidence.watch_source(profile)
    inputs.append(profile)
    for name, original in production_sources(args.source_root):
        evidence.watch_source(original)
        content = original.read_text()
        for mutation in mutations:
            if mutation['path'] == name:
                old, new = mutation['old'], mutation['new']
                if content.count(old) != mutation.get('count', 1):
                    raise RuntimeError('mutation anchor changed: ' + mutation['name'])
                content = content.replace(old, new)
        if name == 'ocore/runtime/aarch64/unified_world.oc':
            content += WORLD_WRAPPER
        elif name == 'ocore/runtime/aarch64/kernel_world_monitor.oc':
            content += MONITOR_WRAPPER
        target = directory / 'generated' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        evidence.watch_source(target)
        inputs.append(target)
        captured.append({'source': native.file_identity(original), 'compiled': native.file_identity(target)})
    carrier = directory / 'generated/carrier.c'
    carrier.write_bytes((ROOT / 'tests/fixtures/ocore_lifecycle_carrier.c').read_bytes())
    evidence.watch_source(carrier)
    return inputs, carrier, captured


def build_target(args, isa, inputs, carrier, directory, evidence):
    directory.mkdir(parents=True)
    target, hosted, machine, flags = native.TARGETS[isa]
    obj = directory / 'policy.o'
    native.produce([str(args.ocorec), *map(str, inputs), '--target', target, '--emit', 'obj',
                    '--keep-asm', '--function-sections', '-o', str(obj)],
                   [obj, obj.with_suffix('.s')], runner=evidence.checked_run, timeout=180)
    native.elf(obj, machine, 1)
    observable = directory / 'observable.o'
    symbols = ['_O_' + module + '__' + name for module, names in PRIVATE.items() for name in names]
    native.produce([args.objcopy, *['--globalize-symbol=' + name for name in symbols], str(obj), str(observable)],
                   [observable], runner=evidence.checked_run)
    imports = evidence.checked_run([args.nm, '--undefined-only', str(observable)]).stdout.decode()
    names = {line.split()[-1] for line in imports.splitlines() if line.split()}
    unknown = sorted({name for name in names if name.startswith(('uw_', 'kw_'))} - MODELED_HOOKS)
    sentinels = directory / 'unexpected-hooks.c'
    sentinels.write_text('extern void lifecycle_unexpected(void);\n' + ''.join(
        'void ' + name + '(void) { lifecycle_unexpected(); }\n' for name in unknown))
    evidence.watch_source(sentinels)
    executable = directory / 'carrier.elf'
    native.produce([args.clang, '--target=' + hosted, *flags, '-O2', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', '-fno-pic', '-nostdlib', '-static', '--ld-path=' + args.linker,
                    '-Wl,-e,_start', '-Wl,--gc-sections', '-Wl,--build-id=none', str(carrier),
                    str(sentinels), str(observable), '-o', str(executable)],
                   [executable], runner=evidence.checked_run, timeout=180)
    native.elf(executable, machine, 2)
    return executable, {'native_target': target, 'hosted_target': hosted, 'flags': flags,
                        'unmodeled_hook_sentinels': unknown,
                        'artifacts': {p.name: native.file_identity(p) for p in
                                      (obj, obj.with_suffix('.s'), observable, executable, sentinels)}}


def execute_cases(cases, executable, prefix, directory, evidence):
    directory.mkdir(parents=True)
    results = []
    for case in cases:
        data = directory / (case['name'] + '.case')
        data.write_bytes(case_bytes(case))
        evidence.watch_source(data)
        run = evidence.run([*prefix, str(executable), str(data)], cwd=directory,
                           timeout=180, preexec_fn=native.no_core_dumps)
        stdout, stderr = directory / (case['name'] + '.stdout'), directory / (case['name'] + '.stderr')
        stdout.write_bytes(run.stdout)
        stderr.write_bytes(run.stderr)
        try:
            comparison = compare_case(case, run.stdout, run.returncode)
        except RuntimeError as error:
            failure = {'case': case['name'], 'trace': case['steps'], 'error': str(error),
                       'input': native.file_identity(data), 'stdout': native.file_identity(stdout),
                       'stderr': native.file_identity(stderr), 'exit_code': run.returncode}
            (directory / 'failing-trace.json').write_text(json.dumps(failure, indent=2) + '\n')
            raise
        results.append({**comparison, 'input': native.file_identity(data),
                        'stdout': native.file_identity(stdout), 'stderr': native.file_identity(stderr),
                        'exit_code': run.returncode})
    if not results:
        raise RuntimeError('no compiled lifecycle traces executed')
    return results


def execute_batch(cases, executable, prefix, directory, evidence):
    """Fork isolated traces from one initialized production-state snapshot."""
    if not cases or len(cases) > 10000:
        raise RuntimeError('invalid finite witness batch size')
    if any(case.get('initial', {}) != cases[0].get('initial', {}) for case in cases):
        raise RuntimeError('batch initial states differ')
    directory.mkdir(parents=True)
    # A shortest predecessor is executed once, then each outgoing action runs
    # in its own fork. This shares real initialized state and RAM pages while
    # preserving process isolation; no candidate transition is substituted.
    groups, case_group = [], {}
    for number, case in enumerate(cases):
        key = json.dumps(case['steps'][:-1], sort_keys=True)
        if not groups or groups[-1][0] != key:
            groups.append((key, case['steps'][:-1], []))
        groups[-1][2].append(case['steps'][-1])
        case_group[number] = len(groups)-1
    header = case_bytes(cases[0])[:72]
    data = struct.pack('<Q', 0x33434c4f434f) + header[8:] + struct.pack('<Q', len(groups))
    for _, predecessor, actions in groups:
        for steps in (predecessor, actions):
            data += case_bytes({'initial': cases[0].get('initial', {}), 'steps': steps})[72:]
    path = directory / 'witnesses.batch'
    path.write_bytes(data)
    evidence.watch_source(path)
    run = evidence.run([*prefix, str(executable), str(path)], cwd=directory,
                       timeout=1800, preexec_fn=native.no_core_dumps)
    stdout = directory / 'batch.stdout'
    stderr = directory / 'batch.stderr'
    stdout.write_bytes(run.stdout)
    stderr.write_bytes(run.stderr)
    if run.returncode:
        raise RuntimeError('finite witness batch failed with exit ' + str(run.returncode))
    rows, prefixes, started, exits, order = {}, {}, set(), {}, []
    for line in run.stdout.splitlines():
        try:
            item = json.loads(line)
        except ValueError as error:
            raise RuntimeError('invalid batch observation encoding') from error
        if isinstance(item, dict) and set(item) == {'prefix', 'record'}:
            group = item['prefix']
            if (type(group) is not int or len(exits) >= len(cases)
                    or group != case_group[len(exits)] or group in started):
                raise RuntimeError('batch predecessor observations are reordered')
            prefixes.setdefault(group, []).append(item['record'])
            continue
        if (not isinstance(item, dict) or type(item.get('case')) is not int
                or not 0 <= item['case'] < len(cases)):
            raise RuntimeError('invalid batch case identity')
        number = item['case']
        if number != len(exits):
            raise RuntimeError('batch observations are reordered or follow completion')
        started.add(case_group[number])
        if set(item) == {'case', 'record'}:
            rows.setdefault(number, []).append(item['record'])
        elif set(item) == {'case', 'exit'} and type(item['exit']) is int:
            exits[number] = item['exit']
            order.append(number)
        else:
            raise RuntimeError('invalid batch observation schema')
    if order != list(range(len(cases))):
        raise RuntimeError('required finite witnesses were skipped')
    results = []
    for number, case in enumerate(cases):
        observations = prefixes.get(case_group[number], []) + rows.get(number, [])
        output = '\n'.join(json.dumps(row, separators=(',', ':')) for row in observations) + '\n'
        case_output = directory / (case['name'] + '.stdout')
        case_output.write_text(output)
        try:
            comparison = compare_case(case, output, exits[number])
        except RuntimeError as error:
            failure = {'case': case['name'], 'trace': case['steps'], 'error': str(error),
                       'batch_index': number, 'input': native.file_identity(path),
                       'stdout': native.file_identity(case_output), 'exit_code': exits[number]}
            (directory / 'failing-trace.json').write_text(json.dumps(failure, indent=2) + '\n')
            raise
        results.append({**comparison, 'batch_index': number, 'stdout': native.file_identity(case_output)})
    return results


def reduced_modifications(root, profile):
    """Inject finite policy limits into isolated test copies, never bindings.

    Only lifecycle capacity predicates and journal storage are narrowed. Handle
    packing, wire widths, errors and privileged entry signatures stay intact.
    Each exact changed span and replacement is retained with the build inputs.
    """
    modifications = []
    def literal(path, old, new, count=None):
        text = (root / path).read_text()
        found = text.count(old)
        if found == 0 or count is not None and found != count:
            raise RuntimeError('finite-profile injection anchor changed: ' + path + ': ' + old)
        modifications.append({'name': 'finite-' + profile, 'path': path,
                              'old': old, 'new': new, 'count': found})
    namespace = 'ocore/runtime/common/namespace_store.oc'
    executor = 'ocore/runtime/common/o10_executor.oc'
    world = 'ocore/runtime/aarch64/unified_world.oc'
    if profile == 'journal':
        text = (root / executor).read_text()
        for old, new in (('16384', '128'), ('256', '2'), ('255', '1')):
            for match in sorted(set(re.findall(r'\b' + old + r'\b', text))):
                literal(executor, match, new)
        literal(executor, 'LAST == 0xffff_ffff_ffff_ffff', 'LAST == 3', 1)
    elif profile == 'replacement':
        literal(namespace, 'SERIAL == 0x7fff_ffff_ffff_ffff', 'SERIAL == 3', 2)
        literal('ocore/runtime/aarch64/kernel_world_9p.oc',
                'SESSION_EPOCH == 0xffff_ffff_ffff_ffff', 'SESSION_EPOCH == 2')
        literal('ocore/runtime/aarch64/plan9_namespace_uart.oc', 'GENERATION == MAX', 'GENERATION == 2', 1)
        text = (root / world).read_text()
        guards = (r'(?:O10_DOMAIN_GENERATION\[[01]\]|(?:LINUX|O10)_(?:LEASE|SESSION)_GENERATION'
                  r'|linux_(?:block|net|namespace)_generation\(\)'
                  r'|o10_domain_generation_raw\(O10_DOMAIN_GENERATION\[[01]\]\)) == 0xffff_ffff(?:_ffff_ffff)?')
        matches = sorted(set(re.findall(guards, text)))
        if len(matches) < 7:
            raise RuntimeError('finite replacement lifecycle guard inventory changed')
        for match in matches:
            literal(world, match, match.split(' == ')[0] + ' == 2')
        if 'linux_namespace_generation() == MAX' in text:
            literal(world, 'linux_namespace_generation() == MAX', 'linux_namespace_generation() == 2', 1)
        owner = 'ocore/runtime/common/lifecycle_identity.oc'
        if (root / owner).exists():
            literal(owner, 'raw > 0xffff_ffff', 'raw > 2', 1)
            literal(owner, 'current.raw >= 0xffff_ffff', 'current.raw >= 2', 1)
            literal(owner, 'current.raw == 0xffff_ffff_ffff_ffff', 'current.raw == 2', 2)
    else:
        raise ValueError('unknown compiled finite policy profile')
    return modifications


def execute_finite_profiles(args, directory, evidence, prefixes):
    report = {}
    for build_profile, profiles in (('replacement', ('session', 'replacement')), ('journal', ('journal',))):
        build_dir = directory / ('finite-' + build_profile)
        modifications = reduced_modifications(args.source_root, build_profile)
        inputs, carrier, captured = prepare_inputs(args, build_dir, evidence, modifications)
        report[build_profile] = {'injections': modifications, 'production_input_closure': captured, 'targets': {}}
        generated = {}
        for profile in profiles:
            graph, cases = model.finite_cases(profile)
            corpus_path = build_dir / (profile + '-witnesses.json')
            corpus_path.write_text(json.dumps(cases, separators=(',', ':')) + '\n')
            evidence.watch_source(corpus_path)
            generated[profile] = (graph, cases)
        for isa in args.targets:
            target_dir = build_dir / isa
            executable, artifacts = build_target(args, isa, inputs, carrier, target_dir, evidence)
            profiles_report = {}
            for profile, (graph, cases) in generated.items():
                results = execute_batch(cases, executable, prefixes[isa], target_dir / profile, evidence)
                profiles_report[profile] = {**{k: v for k, v in graph.items() if k != 'witnesses'},
                    'executed_witnesses': len(results), 'cases': results,
                    'finite_contract': model.finite_profile_contract(profile),
                    'coverage': 'every reachable edge, each with its shortest predecessor witness', 'passed': True}
                print(isa + ': finite ' + profile + ' matched ' + str(len(results)) + ' edge witnesses', flush=True)
            report[build_profile]['targets'][isa] = {**artifacts, 'execution_prefix': prefixes[isa], 'profiles': profiles_report}
    return report


def mutation_specs(root):
    """Negative controls change candidate copies; the oracle stays fixed."""
    namespace = 'ocore/runtime/common/namespace_store.oc'
    executor = 'ocore/runtime/common/o10_executor.oc'
    transport = 'ocore/runtime/aarch64/kernel_world_9p.oc'
    world = 'ocore/runtime/aarch64/unified_world.oc'
    result = []
    def add(name, changes, cases):
        changes = [dict(change, name=name) for change in changes]
        result.append({'name': name, 'changes': changes, 'case_names': cases})
    def change(path, old, new, count=1):
        return {'path': path, 'old': old, 'new': new, 'count': count}
    add('namespace-transport-32-bit-cap', [change(transport,
        '|| next == 0 || next <= GENERATION', '|| next > 0xffff_ffff || next == 0 || next <= GENERATION')],
        ['linux-replacement-0xffffffff'])
    add('zero-session-generation', [change(namespace,
        '|| generation == 0 { return 0; }', '{ return 0; }', 2), change(namespace,
        'generation <= GENERATION[slot]', 'generation < GENERATION[slot]')],
        ['zero-generation-on-unused-grant'])
    add('wrapped-session-serial', [change(namespace,
        ' || SERIAL == 0x7fff_ffff_ffff_ffff', '')], ['last-session-token-usable-then-exhausted'])
    typed = ('if o10_domain_handle_generation(&mut generation, handle) != 1\n'
             '        || !o10_domain_generation_equal(generation, O10_DOMAIN_GENERATION[index as usize]) { return MAX; }')
    raw = 'if (handle >> 32) != O10_DOMAIN_GENERATION[index as usize] { return MAX; }'
    source = (root / world).read_text()
    add('omitted-domain-generation-check', [change(world, typed if typed in source else raw, '')],
        ['stale-domain-and-wrong-image-journalled'])
    add('omitted-transport-owner-check', [change(transport,
        'if current != 0 && current != SESSION { return 0; }', '')], ['transport-owner-check-before-detach'])
    add('reset-lifetime-session-serial', [change(namespace,
        'BASE = base; EPOCH = epoch; CLOCK = 0;', 'BASE = base; EPOCH = epoch; CLOCK = 0; SERIAL = 0;')],
        ['lifetime-serial-survives-reopen'])
    add('colliding-session-token', [change(namespace,
        'let handle: u64 = SERIAL << 1;', 'let handle: u64 = generation << 1;')], ['linux-replacement-0x1'])
    add('revoke-unrelated-grant', [change(namespace,
        'let slot: usize = grant as usize; clear_fids(SESSION[slot]);',
        'let slot: usize = 1; clear_fids(SESSION[slot]);')], ['uart-crafted-epoch-isolation'])
    add('read-only-grant-gains-write', [change(namespace,
        'return grant == 1 || grant == 2 || grant == 4;', 'return grant == 1 || grant == 2 || grant == 3 || grant == 4;')],
        ['readonly-grant-cannot-create'])
    add('provisioned-counts-as-bound', [change(transport,
        'ACTIVE = 1; BOUND = 0; SESSION = 0;', 'ACTIVE = 1; BOUND = 1; SESSION = 0;')], ['provisioned-not-bound'])
    add('restored-linux-runnable-before-bind', [change(world,
        'LINUX_WITHDRAWN = 0; LINUX_WAIT_BIND = 1; BLOCKED[0] = 1; LIVE[0] = 1;',
        'LINUX_WITHDRAWN = 0; LINUX_WAIT_BIND = 0; BLOCKED[0] = 0; LIVE[0] = 1;')], ['linux-replacement-0x1'])
    replay_reset = ('\n    if length != 0 && o10_pending() == 0 && o10_read(request, 4, 1) == 174'
                    ' && o10_read(response as *const u8, 4, 1) == 175 {\n'
                    '        uw_domain_reset(0, 0x4000_0000, 0x47e0_0000, 0x3c5);\n    }')
    anchor = 'let mut length: usize = o10_prepare(request, size, response, 512);'
    add('reset-repeated-on-retained-retry', [change(world, anchor, anchor + replay_reset)], ['linux-replacement-0x1'])
    add('changed-bytes-accepted-as-retry', [change(executor,
        '&& equal(request, (&REQUESTS[slot * 64]), length) == 1', '')], ['changed-tag-not-same-retry'])
    add('omitted-restored-interrupt-bank-reset', [change(world,
        ' || gic_reset(0) != 1', '')], ['linux-replacement-0x1'])
    return result


def execute_mutations(args, directory, evidence, corpus, prefixes):
    # One actual implemented ISA is sufficient for these policy negative
    # controls. The unmodified candidate and finite profiles still run on all.
    isa = args.targets[0]
    cases_by_name = {case['name']: case for case in corpus['cases']}
    result = []
    for mutation in mutation_specs(args.source_root):
        mutation_dir = directory / 'mutations' / mutation['name']
        inputs, carrier, captured = prepare_inputs(args, mutation_dir, evidence, mutation['changes'])
        executable, artifacts = build_target(args, isa, inputs, carrier, mutation_dir / isa, evidence)
        killed = None
        for name in mutation['case_names']:
            if name not in cases_by_name:
                raise RuntimeError('required mutation probe absent: ' + name)
            case = cases_by_name[name]
            run_dir = mutation_dir / 'witness'
            try:
                execute_cases([case], executable, prefixes[isa], run_dir, evidence)
            except RuntimeError:
                failure_file = run_dir / 'failing-trace.json'
                if not failure_file.exists():
                    raise
                failure = json.loads(failure_file.read_text())
                if failure['exit_code'] not in (0, 86):
                    raise RuntimeError('mutation runtime is inconclusive: ' + mutation['name'])
                killed = failure
                # The comparator walks observations in order. Its first
                # mismatching step supplies a minimal prefix of this witness.
                found = re.search(r' step (\d+):', failure['error'])
                if found:
                    count = int(found[1]) + 1 if int(found[1]) != model.U64 else 0
                    shortened = dict(case, steps=case['steps'][:count])
                    try:
                        execute_cases([shortened], executable, prefixes[isa], mutation_dir / 'minimal-prefix', evidence)
                    except RuntimeError:
                        minimal = mutation_dir / 'minimal-prefix/failing-trace.json'
                        if not minimal.exists():
                            raise
                        killed = json.loads(minimal.read_text())
                    else:
                        raise RuntimeError('mutation prefix did not reproduce: ' + mutation['name'])
                break
        if killed is None:
            raise RuntimeError('policy mutation survived: ' + mutation['name'])
        result.append({'name': mutation['name'], 'isa': isa, 'changes': mutation['changes'],
                       'production_input_closure': captured, 'artifacts': artifacts,
                       'status': 'killed-by-observation-mismatch', 'witness': killed,
                       'minimality': 'first divergent prefix of the specified probe; not global trace minimization'})
        print(isa + ': killed policy mutation ' + mutation['name'], flush=True)
    return result


def check(args, directory):
    args.source_root = args.source_root.resolve(strict=True)
    args.ocorec = Path(native.tool(str(args.ocorec), 'O-core compiler'))
    for name, default in (('clang', 'clang'), ('linker', 'ld.lld'), ('objcopy', 'llvm-objcopy'), ('nm', 'llvm-nm')):
        setattr(args, name, native.tool(getattr(args, name, None) or default, name))
    prefixes = {isa: native.execution_prefix(isa, getattr(args, 'qemu_' + isa, None)) for isa in args.targets}
    tools = {'ocorec': str(args.ocorec), 'clang': args.clang, 'linker': args.linker,
             'objcopy': args.objcopy, 'nm': args.nm, 'compiler_assembler_clang': native.tool('clang', 'O-core assembler'),
             'python_interpreter': sys.executable,
             **{isa + '_runner': prefix[0] for isa, prefix in prefixes.items() if prefix}}
    sources = [__file__, args.vectors, ROOT / 'tests/ocore_lifecycle_model.py',
               ROOT / 'tests/fixtures/ocore_lifecycle_vectors.json',
               ROOT / 'tests/fixtures/ocore_lifecycle_carrier.c',
               args.source_root / 'crates/ostadix-api/src/ocore/common.rs',
               args.source_root / 'scripts/build_okernel_unified_world.py']
    evidence = native.RunEvidence(sources, tools)
    corpus_identity = corpus_admission(args.vectors, args.diagnostic_component_only)
    catalog = native.canonical_target_coverage(catalog=args.source_root / 'crates/ostadix-api/src/ocore/common.rs')
    corpus = load_vectors(args.vectors)
    revision = evidence.checked_run(['git', 'rev-parse', 'HEAD'], cwd=args.source_root).stdout.decode().strip()
    status = evidence.checked_run(['git', 'status', '--porcelain=v1', '--untracked-files=all'], cwd=args.source_root).stdout.decode()
    report = {'schema': 'ostadix.ocore-lifecycle-conformance/v1', 'qualified': False,
              'source_root': str(args.source_root), 'source_revision': revision,
              'source_worktree_status': status, 'backend_catalog': catalog,
              'corpus_admission': corpus_identity, 'reference_python': {'version': sys.version, 'executable': sys.executable},
              'compiler_version': evidence.checked_run([str(args.ocorec), '--version']).stdout.decode().strip(),
              'targets': {}, 'case_count': len(corpus['cases']),
              'scope': 'compiled policy and explicit modeled privileged hooks; not guest, physical, SMP, escrow or memory-view qualification'}
    inputs, carrier, captured = prepare_inputs(args, directory, evidence)
    report['production_input_closure'] = captured
    report['finite_model_profiles'] = {name: {k: v for k, v in getattr(model, name)().items() if k != 'witnesses'}
                                       for name in ('session_profile', 'journal_profile', 'replacement_profile')}
    for isa in args.targets:
        target_dir = directory / isa
        executable, artifacts = build_target(args, isa, inputs, carrier, target_dir, evidence)
        results = execute_cases(corpus['cases'], executable, prefixes[isa], target_dir / 'full-width', evidence)
        report['targets'][isa] = {**artifacts, 'execution_prefix': prefixes[isa], 'cases': results,
                                  'observations': sum(item['observations'] for item in results), 'full_width_passed': True}
        print(isa + ': all ' + str(len(results)) + ' full-width lifecycle traces matched', flush=True)
    report['full_width_passed'] = set(args.targets) == set(native.TARGETS)
    if not args.diagnostic_component_only:
        report['compiled_finite_profiles'] = execute_finite_profiles(args, directory, evidence, prefixes)
        report['mutation_controls'] = execute_mutations(args, directory, evidence, corpus, prefixes)
    report['provenance'] = evidence.finish()
    report['remaining_acceptance'] = (['compiled reduced-limit profiles', 'candidate mutation controls']
                                      if args.diagnostic_component_only else [])
    report['qualified'] = bool(report['full_width_passed'] and not report['remaining_acceptance'])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ocorec', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--vectors', type=Path, default=ROOT / 'tests/fixtures/ocore_lifecycle_vectors.json')
    parser.add_argument('--targets', nargs='+', choices=list(native.TARGETS), default=list(native.TARGETS))
    parser.add_argument('--diagnostic-component-only', action='store_true',
                        help='Report component execution without claiming full M4 qualification')
    for name in ('clang', 'linker', 'objcopy', 'nm'):
        parser.add_argument('--' + name)
    for isa in native.TARGETS:
        parser.add_argument('--qemu-' + isa.replace('_', '-'), dest='qemu_' + isa)
    args = parser.parse_args()
    if len(args.targets) != len(set(args.targets)):
        parser.error('duplicate targets')
    created_here = False
    try:
        if args.output_dir.exists():
            raise RuntimeError('output directory must be fresh: ' + str(args.output_dir))
        args.output_dir.mkdir(parents=True)
        created_here = True
        report = check(args, args.output_dir.resolve())
        (args.output_dir / 'lifecycle.json').write_text(json.dumps(report, indent=2) + '\n')
        return 0 if report['qualified'] or args.diagnostic_component_only else 1
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        if created_here and args.output_dir.is_dir():
            (args.output_dir / 'failure.json').write_text(json.dumps({'qualified': False, 'error': str(error)}, indent=2) + '\n')
        print('O-core lifecycle conformance: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
