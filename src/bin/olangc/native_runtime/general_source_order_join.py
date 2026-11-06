"""Additive registered-producer/multi-output consistency DATA candidate.
No filesystem, subprocess, capture admission or runtime qualification.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re


class JoinError(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise JoinError(reason)


def _pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def decode(raw):
    require(type(raw) is bytes, "input must be exact bytes")
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              JoinError("nonfinite JSON number")))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise JoinError("invalid JSON") from error


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(value, name):
    require(type(value) is str and value and value.strip() == value
            and not any(ord(c) < 32 for c in value), name)
    return value


def _pin(value):
    require(type(value) is dict, "artifact identity must be an object")
    identity(value.get("path"), "artifact path absent")
    require(type(value.get("bytes")) is int and value["bytes"] >= 0,
            "artifact length must be an integer")
    require(type(value.get("sha256")) is str and
            re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None,
            "artifact SHA-256 absent")
    return {k: value[k] for k in ("path", "bytes", "sha256")}


class Paths:
    """Explicit lexical namespace correspondence; no filesystem or retargeting.

    Only whole paths and the listed attached path-option spellings are mapped.
    Embedded root strings in macros, environment command strings, response-file
    contents, or unknown flag syntaxes reject instead of being normalized away.
    Paths outside supplied roots remain literal and therefore must match exactly.
    """
    def __init__(self, roots):
        require(type(roots) is dict, "root bindings must be an object")
        self.roots = []
        for alias, root in roots.items():
            require(type(alias) is str and re.fullmatch("[A-Za-z][A-Za-z0-9_]*", alias),
                    "invalid namespace alias")
            require(type(root) is str and root.startswith("/") and root != "/"
                    and posixpath.normpath(root) == root, "invalid namespace root")
            self.roots.append((alias, root))
        for index, (_, root) in enumerate(self.roots):
            for _, other in self.roots[index + 1:]:
                require(root != other and not root.startswith(other + "/")
                        and not other.startswith(root + "/"), "overlapping namespace roots")

    def path(self, value):
        require(type(value) is str and "\0" not in value, "path is not a string")
        for alias, root in self.roots:
            if value == root or value.startswith(root + "/"):
                require(posixpath.normpath(value) == value, "noncanonical mapped path")
                return {"root": alias, "relative": value[len(root):]}
        return value

    def token(self, value):
        # Empty arguments and whitespace have actual compiler semantics. Keep
        # them verbatim, rather than applying the identifier grammar to argv.
        require(type(value) is str and "\0" not in value, "command/environment token type")
        mapped = self.path(value)
        if type(mapped) is dict:
            return mapped
        for prefix in ("--sysroot=", "-isystem", "-iquote", "-I", "-L", "-B", "@"):
            if value.startswith(prefix) and len(value) > len(prefix):
                mapped = self.path(value[len(prefix):])
                if type(mapped) is dict:
                    return {"option": prefix, "path": mapped}
        require(not any(root in value for _, root in self.roots),
                "unmapped embedded namespace path")
        return value

    def artifact(self, value):
        result = _pin(value)
        result["path"] = self.path(result["path"])
        return result


def _tokens(values, paths):
    require(type(values) is list and values, "argv must be a nonempty array")
    return [paths.token(value) for value in values]


def _legacy_replay_action(raw, roots):
    event = decode(raw)
    require(type(event) is dict, "compiler event must be an object")
    event_id = identity(event.get("id"), "compiler invocation identity absent")
    require(event.get("state") == "finished" and type(event.get("exit_code")) is int
            and event["exit_code"] == 0, "compiler action did not succeed")
    require(event.get("capture_errors") == [], "compiler capture has errors")
    paths = Paths(roots)
    units = event.get("units")
    require(type(units) is list and len(units) == 1,
            "action needs a stable producer selector for multiple/absent units")
    unit = units[0]
    require(type(unit) is dict, "unit must be an object")
    unit_id = identity(unit.get("id"), "unit identity absent")
    require(type(unit.get("replay_exit_code")) is int and unit["replay_exit_code"] == 0,
            "implementation IR production did not succeed")
    require(unit.get("kind") == event.get("kind"), "unit/producer kind differs")
    source = _pin(unit.get("source"))
    sources = event.get("sources")
    require(type(sources) is list and sources and source in [_pin(s) for s in sources],
            "unit source lacks an owning invocation source")
    ir = unit.get("ir")
    _pin(ir)
    for field in ("format", "target_triple", "data_layout"):
        identity(ir.get(field), "IR profile field absent: " + field)
    # All additional IR profile metadata remains in the key. Only the actual
    # artifact location/length/hash are evidence, not action identity.
    ir_profile = {k: v for k, v in ir.items() if k not in ("path", "bytes", "sha256")}
    replay = unit.get("replay_argv")
    require(type(replay) is list and replay, "IR producer argv absent")
    replay_key = []
    for index, token in enumerate(replay):
        if index and replay[index - 1] == "-o":
            require(token == ir["path"], "IR output argv differs from captured unit")
            replay_key.append({"unit_artifact": "ir"})
        elif index and replay[index - 1] == "-MF":
            require(type(token) is str and token.endswith(".d")
                    and posixpath.dirname(token) == posixpath.dirname(ir["path"]),
                    "IR dependency output is not in the owning unit directory")
            replay_key.append({"unit_artifact": "dependency"})
        else:
            replay_key.append(paths.token(token))
    require(replay.count("-o") == 1, "IR output option must appear once")
    frontend = event.get("frontend")
    _pin(frontend)
    dependencies = unit.get("dependencies")
    require(type(dependencies) is list,
            "original included-source inventory absent")
    environment = event.get("build_environment")
    require(type(environment) is dict and all(type(k) is str for k in environment),
            "build environment absent")
    step = event.get("build_step")
    require(type(step) is dict and set(step) == {"name", "index"}
            and type(step["index"]) is int and step["index"] >= 0, "build-step binding absent")
    identity(step["name"], "build-step name absent")
    responses = event.get("response_files")
    outputs = event.get("outputs")
    require(type(responses) is list and type(outputs) is list and outputs,
            "response/native-output inventory absent")
    projection = {
        "kind": identity(event.get("kind"), "producer kind absent"),
        "producer": event.get("producer"),
        "driver_kind": identity(event.get("driver_kind"), "driver kind absent"),
        "compiler": paths.token(identity(event.get("compiler"), "compiler path absent")),
        "capture_worker": paths.artifact(event.get("capture_worker")),
        "cwd": paths.path(event.get("cwd")),
        "argv": _tokens(event.get("argv"), paths),
        "expanded_argv": _tokens(event.get("expanded_argv"), paths),
        "environment": {k: paths.token(v) for k, v in environment.items()},
        "build_step": step,
        "frontend": {**paths.artifact(frontend), "version": frontend.get("version"),
                     "llvm_version": frontend.get("llvm_version")},
        "sources": [paths.artifact(s) for s in sources],
        "response_files": [paths.artifact(s) for s in responses],
        "native_outputs": [{"path": paths.path(_pin(s)["path"]),
                            "artifact_kind": s.get("artifact_kind")} for s in outputs],
        "unit": {"kind": unit["kind"], "producer": unit.get("producer"),
                 "source": paths.artifact(source), "ir_profile": ir_profile,
                 "replay_argv": replay_key,
                 "dependencies": [paths.artifact(s) for s in dependencies],
                 "other_metadata": {k: v for k, v in unit.items() if k not in
                     {"id", "kind", "producer", "source", "ir", "replay_argv",
                      "replay_exit_code", "dependencies"}}},
    }
    return {"action_key": digest(encode(projection)), "projection": projection,
            "original_invocation_id": event_id, "original_unit_id": unit_id,
            "event_sha256": digest(raw), "event_bytes": len(raw)}



# This is consistency DATA code. AdmittedCapture/registered worker remain the
# only capture admission authority. These profiles do not add producer support.
PROFILE_BY_POLICY = {'frontend-replay-v1': 'replay-source-command-v1',
                     'rust-embedded-bc-v1': 'native-container-member-name-v1'}
EDGE_FIELDS = {'kind', 'section_index', 'section_name', 'section_name_bytes',
               'object_offset', 'container_offset', 'bytes', 'sha256', 'bitcode_header'}
MEMBER_FIELDS = {'index', 'physical_index', 'name', 'name_bytes', 'header_offset',
                 'data_offset', 'raw_data_offset', 'raw_bytes', 'bytes', 'sha256'}


def _metadata(value, paths):
    if type(value) is str:
        return paths.token(value)
    if type(value) is list:
        return [_metadata(v, paths) for v in value]
    if type(value) is dict:
        require(all(type(k) is str for k in value), 'metadata key type')
        return {k: _metadata(v, paths) for k, v in value.items()}
    require(value is None or type(value) in {int, bool}, 'unsupported metadata scalar')
    return value


def _contracts(registry_raw, selected):
    registry = decode(registry_raw)
    require(type(registry) is dict and registry.get('schema') == 'ocore-producer-registry-v1'
            and type(registry.get('producers')) is list, 'producer registry schema')
    require(type(selected) is dict and selected, 'selected producer profiles absent')
    table = {}
    kinds = set()
    for item in registry['producers']:
        require(type(item) is dict, 'registered producer shape')
        producer_id = identity(item.get('id'), 'registered producer ID absent')
        kind = identity(item.get('unit_kind'), 'registered producer kind absent')
        require(producer_id not in table and kind not in kinds, 'duplicate registered producer')
        table[producer_id] = item
        kinds.add(kind)
    require(set(selected) <= set(table), 'unregistered producer profile selection')
    for producer_id, policies in selected.items():
        producer = table[producer_id]
        require(type(policies) is dict and policies, 'selected producer policy absent')
        require(producer.get('capture', {}).get('available') is True,
                'registered capture adapter unavailable')
        for policy, profile in policies.items():
            registered = producer.get('capture', {}).get('policies', {}).get(policy)
            require(type(registered) is dict and policy in PROFILE_BY_POLICY
                    and profile == _selector_profile(producer, policy), 'unregistered selector profile')
            require(registered.get('frontend_replay') is (policy == 'frontend-replay-v1'),
                    'registered evidence policy differs')
            if policy == 'rust-embedded-bc-v1':
                require(producer.get('adapter') == 'rustc' and producer.get('unit_kind') == 'rustc'
                        and registered.get('format') == 'llvm-bitcode',
                        'native edge policy requires its implemented registered adapter')
    return table


def _select_contract(event, table, selected):
    producer_id = identity(event.get('producer'), 'owning producer identity absent')
    require(producer_id in table and producer_id in selected, 'unregistered or unselected producer')
    producer = table[producer_id]
    require(event.get('kind') == producer.get('unit_kind'), 'owning producer kind mismatch')
    wrappers = producer.get('wrappers')
    require(type(wrappers) is list and event.get('driver_kind') in
            {w.get('kind') for w in wrappers if type(w) is dict}, 'registered wrapper mismatch')
    capture = event.get('rust_capture')
    policy = capture.get('policy') if type(capture) is dict else 'frontend-replay-v1'
    require(policy in selected[producer_id], 'producer evidence policy not selected')
    registered = producer['capture']['policies'][policy]
    return producer, policy, registered


def _ir_profile(unit, registered):
    ir = unit.get('ir')
    _pin(ir)
    for key in ['format', 'target_triple', 'data_layout']:
        identity(ir.get(key), 'IR profile field absent: ' + key)
    require(ir['format'] == registered['format'], 'IR format differs from producer policy')
    return {k: v for k, v in ir.items() if k not in {'path', 'bytes', 'sha256'}}


def _source(unit, event, paths):
    source = _pin(unit.get('source'))
    require(source in [_pin(v) for v in event['sources']], 'unit source lacks owning invocation')
    require(unit.get('kind') == event['kind'] and
            unit.get('producer') in {None, event['producer']}, 'unit producer differs from owner')
    return paths.artifact(source)


RUST_REPLAY_PROFILE = 'rust-replay-emitted-module-name-v1'


def _selector_profile(producer, policy):
    if policy == 'frontend-replay-v1' and producer.get('adapter') == 'rustc':
        return RUST_REPLAY_PROFILE
    return PROFILE_BY_POLICY.get(policy)


def _producer_action_context(event, paths):
    # The same original command/environment context as the native-edge branch.
    # Producer evidence is added separately, never synthesized from this data.
    frontend = event.get('frontend'); _pin(frontend)
    responses = event.get('response_files')
    environment, step = event.get('build_environment'), event.get('build_step')
    require(type(responses) is list and type(environment) is dict and
            all(type(k) is str for k in environment), 'native response/environment inventory absent')
    require(type(step) is dict and set(step) == {'name', 'index'}
            and type(step['index']) is int and step['index'] >= 0, 'native build-step binding absent')
    identity(step['name'], 'native build-step name absent')
    return {'kind': event['kind'], 'producer': event['producer'], 'driver_kind': event['driver_kind'],
            'compiler': paths.token(identity(event.get('compiler'), 'native compiler path absent')),
            'capture_worker': paths.artifact(event.get('capture_worker')),
            'cwd': paths.path(event.get('cwd')), 'argv': _tokens(event.get('argv'), paths),
            'expanded_argv': _tokens(event.get('expanded_argv'), paths),
            'environment': {k: paths.token(v) for k, v in environment.items()}, 'build_step': step,
            'frontend': {**paths.artifact(frontend), 'version': frontend.get('version'),
                         'llvm_version': frontend.get('llvm_version')},
            'sources': [paths.artifact(v) for v in event['sources']],
            'response_files': [paths.artifact(v) for v in responses],
            'native_outputs': [{'path': paths.path(_pin(v)['path']),
                                'artifact_kind': v.get('artifact_kind')} for v in event['outputs']]}


def _rust_replay_units(event, paths, registered, producer):
    # The implemented worker invokes rustc once into an owning replay directory.
    # Its units have no per-unit replay command. Actual emitted filenames, not
    # capture indices, distinguish the complete set of outputs from that action.
    require('executed_argv' not in event,
            'default Rust replay has no separately recorded executed argv')
    require(producer.get('adapter') == 'rustc' and producer.get('unit_kind') == 'rustc',
            'Rust replay selector requires its registered adapter')
    require(event.get('saved_cgus') in [None, []] and event.get('rust_capture') is None
            and event.get('rust_native_resources') in [None, []],
            'Rust replay cannot substitute native-edge evidence')
    require(type(event.get('replay_exit_code')) is int and event['replay_exit_code'] == 0,
            'Rust frontend replay did not succeed')
    replay = event.get('replay_argv')
    require(type(replay) is list and len(replay) >= 4
            and all(type(token) is str for token in replay), 'Rust replay command absent')
    require(replay[-3:-1] == ['--emit=llvm-ir,dep-info', '--out-dir']
            and sum(token.startswith('--emit') for token in replay) == 1
            and sum(token.startswith('--out-dir') for token in replay) == 1
            and not any(token.startswith('-o') for token in replay),
            'Rust replay command differs from the registered output contract')
    directory = identity(replay[-1], 'Rust replay output directory absent')
    require(posixpath.isabs(directory) and posixpath.normpath(directory) == directory,
            'Rust replay output directory is not canonical')
    replay_key = [paths.token(token) for token in replay[:-1]] + [
        {'action_artifact_directory': 'rust-frontend-replay'}]
    shared = _producer_action_context(event, paths)
    shared['frontend_replay'] = {'argv': replay_key, 'exit_code': event['replay_exit_code']}
    shared['frontend_metadata'] = _metadata({key: value for key, value in event['frontend'].items() if key not in {'path', 'bytes', 'sha256'}}, paths)
    version = event['frontend'].get('version')
    require(type(version) is str and version and '\0' not in version, 'Rust frontend version absent')
    units = []
    for unit in event['units']:
        require(type(unit) is dict and unit.get('kind') == producer['unit_kind']
                and unit.get('producer') == producer['id']
                and unit.get('frontend_version') == version,
                'Rust replay unit producer/frontend differs from owner')
        require(unit.get('capture_policy') in [None, 'frontend-replay-v1']
                and unit.get('replay_argv') is None and unit.get('replay_exit_code') is None,
                'Rust replay unit cannot invent a per-unit command')
        ir = unit.get('ir'); _pin(ir)
        require(posixpath.normpath(ir['path']) == ir['path']
                and posixpath.dirname(ir['path']) == directory
                and posixpath.basename(ir['path']).endswith('.ll'),
                'Rust replay unit is outside its owning output directory')
        filename = posixpath.basename(ir['path'])
        source = _source(unit, event, paths)
        dependencies = unit.get('dependencies')
        require(type(dependencies) is list, 'Rust replay dependency inventory absent')
        projected = {'source': source, 'ir_profile': _ir_profile(unit, registered),
                     'dependencies': [paths.artifact(value) for value in dependencies],
                     'metadata': _metadata({key: value for key, value in unit.items()
                         if key not in {'id', 'source', 'ir', 'dependencies'}}, paths)}
        units.append({'unit_id': identity(unit.get('id'), 'unit identity absent'),
                      'selector': {'profile': RUST_REPLAY_PROFILE, 'emitted_filename': filename},
                      'projection': projected,
                      'lineage': {'unit': unit, 'replay_argv': replay,
                                  'replay_exit_code': event['replay_exit_code']}})
    return units, shared


def _natural(value, reason):
    require(type(value) is int and value >= 0, reason)
    return value


def _byte_name(value, name, reason):
    require(type(value) is list and all(type(v) is int and 0 <= v <= 255 for v in value), reason)
    require(type(name) is str and bytes(value).decode('utf-8', 'surrogateescape') == name, reason)
    return value


def _native_units(event, paths, registered):
    capture = event.get('rust_capture')
    require(type(capture) is dict and capture.get('policy') == 'rust-embedded-bc-v1'
            and capture.get('frontend_replay_used') is False, 'native capture evidence policy differs')
    require(event.get('replay_argv') is None and event.get('replay_exit_code') is None,
            'native edge cannot substitute frontend replay')
    # Parent UUID is lineage, not an original-to-fresh semantic selector. No
    # invented UUID normalization or caller declaration grants Cargo authority.
    require(event.get('cargo_parent_invocation_id') is None,
            'Cargo parent semantic context unsupported; independently admitted observer action required')
    records = event.get('saved_cgus')
    require(type(records) is list and records and len(records) == len(event['units']),
            'complete native saved-edge/unit inventory differs')
    require(event.get('rust_cgu_gaps') == [] and type(event.get('rust_native_resources')) is list,
            'native gaps/resources omitted or unsupported')
    indices, selections, covered, physical_edges = set(), [], set(), set()
    outputs = [_pin(v) for v in event['outputs']]
    require(len({encode(v) for v in outputs}) == len(outputs), 'duplicate native output identity')
    for resource in event['rust_native_resources']:
        require(type(resource) is dict, 'native resource record type')
        artifact = _pin(resource.get('artifact'))
        require(artifact in outputs, 'native resource lacks original output')
        kind = resource.get('kind')
        if kind in {'rust_dependency_file', 'rust_v10_metadata'}:
            member_index = None
            require(resource.get('native_code') is False and resource.get('ownership_qualified') is False,
                    'native resource qualification cannot be promoted')
            if kind == 'rust_dependency_file':
                require(artifact['path'].endswith('.d'), 'dependency resource suffix differs')
            else:
                require(artifact['path'].endswith('.rmeta') and
                        resource.get('header_bytes') == list(b'rust\0\0\0\x0a'), 'metadata resource header differs')
        else:
            sections = resource.get('metadata_sections')
            require(kind == 'embedded_bitcode_missing' and type(sections) is list and
                    all(type(s) is dict and type(s.get('flags')) is int and type(s.get('type')) is int
                        for s in sections) and
                    any(s.get('name_bytes') in [list(b'.rmeta'), list(b'.rmeta-link')] for s in sections) and
                    not any(s['flags'] & 6 and s['type'] != 7 for s in sections),
                    'unsupported or native-code-bearing resource gap')
            member = resource.get('member')
            member_index = None if member is None else _natural(member.get('index'), 'resource member index')
            if member is not None:
                require(type(member) is dict and MEMBER_FIELDS <= set(member), 'resource member fields omitted')
                for field in ['index', 'physical_index', 'header_offset', 'data_offset', 'raw_data_offset',
                              'raw_bytes', 'bytes']:
                    _natural(member.get(field), 'resource member integer field: ' + field)
                _byte_name(member['name_bytes'], member['name'], 'resource member byte name differs')
                require(member['data_offset'] + member['bytes'] <= artifact['bytes'],
                        'resource member range exceeds native output')
        key = (encode(artifact), member_index)
        require(key not in physical_edges, 'duplicate native resource/member edge')
        physical_edges.add(key)
        covered.add(encode(artifact))
    for unit in event['units']:
        index = _natural(unit.get('saved_cgu_index'), 'native saved-edge index type')
        require(index < len(records) and index not in indices, 'native saved-edge index missing/duplicate')
        indices.add(index)
        record = records[index]
        require(type(record) is dict and set(record) in [
            {'schema', 'compiler_invocation_id', 'cargo_parent_invocation_id', 'object', 'bitcode', 'edge'},
            {'schema', 'compiler_invocation_id', 'cargo_parent_invocation_id', 'object', 'bitcode', 'edge', 'container'}],
            'native edge record fields differ')
        require(record['schema'] == 'ocore-rust-native-bitcode-edge-v1'
                and record['compiler_invocation_id'] == event['id']
                and record['cargo_parent_invocation_id'] == event.get('cargo_parent_invocation_id'),
                'native compiler/Cargo parent lineage differs')
        require(unit.get('capture_policy') == 'rust-embedded-bc-v1'
                and unit.get('replay_argv') is None and unit.get('replay_exit_code') is None,
                'native unit policy/replay differs')
        for field in ['source_production_ownership_verified', 'native_machine_equivalence_verified',
                      'post_lto_equivalence_verified']:
            require(unit.get(field) is False, 'native unit qualification flags cannot be promoted')
        obj, bitcode = _pin(record['object']), _pin(record['bitcode'])
        require(_pin(unit['ir']) == bitcode, 'unit IR differs from exact saved bitcode')
        edge = record['edge']
        require(type(edge) is dict and EDGE_FIELDS <= set(edge), 'native embedded edge fields omitted')
        for field in ['section_index', 'object_offset', 'container_offset', 'bytes']:
            _natural(edge.get(field), 'native edge integer field: ' + field)
        require(edge['bytes'] == bitcode['bytes'] > 0 and edge['sha256'] == bitcode['sha256']
                and edge['object_offset'] + edge['bytes'] <= obj['bytes'],
                'native embedded byte range/hash differs')
        _byte_name(edge['section_name_bytes'], edge['section_name'], 'native section byte name differs')
        container = record.get('container')
        if container is None:
            artifact, member = obj, None
            require(edge['container_offset'] == edge['object_offset'], 'native object edge offset differs')
        else:
            require(type(container) is dict and set(container) == {'artifact', 'member'},
                    'native archive container fields differ')
            artifact, member = _pin(container['artifact']), container['member']
            require(type(member) is dict and MEMBER_FIELDS <= set(member), 'native member fields omitted')
            for field in ['index', 'physical_index', 'header_offset', 'data_offset', 'raw_data_offset',
                          'raw_bytes', 'bytes']:
                _natural(member.get(field), 'native member integer field: ' + field)
            _byte_name(member['name_bytes'], member['name'], 'native member byte name differs')
            require(member['name_bytes'] and obj['bytes'] == member['bytes']
                    and obj['sha256'] == member['sha256']
                    and member['data_offset'] + member['bytes'] <= artifact['bytes']
                    and edge['container_offset'] == member['data_offset'] + edge['object_offset'],
                    'native archive member range/hash differs')
        require(artifact in outputs and edge['container_offset'] + edge['bytes'] <= artifact['bytes'],
                'native edge lacks original output container')
        physical_key = (encode(artifact), None if member is None else member['index'])
        require(physical_key not in physical_edges, 'duplicate native physical/member edge')
        physical_edges.add(physical_key)
        covered.add(encode(artifact))
        require(unit.get('dependencies') == event['sources'], 'native source dependency evidence differs')
        selector = {'profile': 'native-container-member-name-v1',
                    'container': paths.path(artifact['path']),
                    'member_name_bytes': None if member is None else member['name_bytes']}
        source = _source(unit, event, paths)
        projection = {'source': source, 'ir_profile': _ir_profile(unit, registered),
                      'embedded_section_contract': {k: edge[k] for k in
                          ['kind', 'section_name_bytes', 'bitcode_header']},
                      'metadata': _metadata({k: v for k, v in unit.items() if k not in
                          {'id', 'ir', 'source', 'saved_cgu_index'}}, paths)}
        selections.append({'unit_id': identity(unit.get('id'), 'unit identity absent'),
                           'selector': selector, 'projection': projection,
                           'lineage': {'saved_cgu_index': index, 'saved_record': record}})
    require(indices == set(range(len(records))), 'native saved-edge inventory incomplete')
    require(covered == {encode(v) for v in outputs}, 'unassigned original native output/resource')
    return selections


def _action_v2(raw, roots, table, selected):
    event = decode(raw)
    require(type(event) is dict and event.get('state') == 'finished'
            and type(event.get('exit_code')) is int and event['exit_code'] == 0,
            'compiler action did not succeed')
    identity(event.get('id'), 'compiler invocation identity absent')
    require(event.get('capture_errors') == [], 'compiler capture has errors')
    require(type(event.get('units')) is list and event['units'], 'owning action outputs absent')
    require(type(event.get('sources')) is list and event['sources'], 'owning action sources absent')
    require(type(event.get('outputs')) is list and event['outputs'], 'native outputs absent')
    producer, policy, registered = _select_contract(event, table, selected)
    require(event.get('cargo_parent_invocation_id') is None,
            'Cargo parent semantic context unsupported; independently admitted observer action required')
    paths = Paths(roots)
    if policy == 'frontend-replay-v1' and producer.get('adapter') == 'rustc':
        units, shared = _rust_replay_units(event, paths, registered, producer)
    elif policy == 'frontend-replay-v1':
        require(event.get('saved_cgus') in [None, []] and event.get('rust_capture') is None,
                'frontend replay cannot invent native-edge evidence')
        units, shared = [], None
        for unit in event['units']:
            require(unit.get('capture_policy') in {None, 'frontend-replay-v1'},
                    'frontend unit evidence policy differs')
            _ir_profile(unit, registered)
            _source(unit, event, paths)
            one = _legacy_replay_action(encode({**event, 'units': [unit]}), roots)['projection']
            projected = one.pop('unit')
            require(shared is None or shared == one, 'owning replay action projection differs')
            shared = one
            selector = {'profile': 'replay-source-command-v1', 'source': projected['source'],
                        'ir_profile': projected['ir_profile'], 'replay_argv': projected['replay_argv']}
            units.append({'unit_id': unit['id'], 'selector': selector, 'projection': projected,
                          'lineage': {'unit': unit}})
    else:
        units = _native_units(event, paths, registered)
        shared = {**_producer_action_context(event, paths),
                  'executed_argv': _tokens(event.get('executed_argv'), paths),
                  'rust_capture': _metadata(event['rust_capture'], paths),
                  'rust_native_resources': _metadata(event['rust_native_resources'], paths)}
    # Producer-record arrays do not declare link order. Their complete identities
    # are compared as selector inventories; original policy order stays separate.
    shared['native_outputs'] = sorted(shared['native_outputs'], key=encode)
    require(len({encode(v) for v in shared['native_outputs']}) == len(shared['native_outputs']),
            'duplicate native output container')
    require(len({encode(v['selector']) for v in units}) == len(units), 'ambiguous stable output selector')
    require(len({v['unit_id'] for v in units}) == len(units), 'duplicate owning-action unit')
    shared['contract'] = {'producer': producer['id'], 'policy': policy,
                          'selector_profile': selected[producer['id']][policy]}
    return {'action_key': digest(encode(shared)), 'projection': shared, 'units': units,
            'invocation_id': event['id'], 'event_sha256': digest(raw), 'event_bytes': len(raw),
            'native_output_order': event['outputs']}


def commit_order_v2(original_events, required_unit_ids, roots, original_occurrences,
                    original_order_raw, registry_raw, selected_profiles):
    require(type(original_events) is list and original_events, 'original actions absent')
    require(type(required_unit_ids) is list and required_unit_ids and
            all(type(u) is str and u for u in required_unit_ids) and
            len(set(required_unit_ids)) == len(required_unit_ids), 'independent required unit floor absent/duplicate')
    require(type(original_occurrences) is list and original_occurrences and
            all(type(u) is str for u in original_occurrences) and
            set(original_occurrences) == set(required_unit_ids), 'original occurrence sequence differs')
    policy = decode(original_order_raw)
    require(type(policy) is dict and policy.get('schema') == 'ocore-original-provider-order-v3',
            'original order policy schema differs')
    table = _contracts(registry_raw, selected_profiles)
    actions = [_action_v2(raw, roots, table, selected_profiles) for raw in original_events]
    require(len({a['action_key'] for a in actions}) == len(actions), 'ambiguous original owning action')
    require(len({a['invocation_id'] for a in actions}) == len(actions), 'duplicate original invocation')
    ids = [u['unit_id'] for a in actions for u in a['units']]
    require(len(ids) == len(set(ids)) and set(ids) == set(required_unit_ids), 'complete original required unit floor differs')
    return encode({'schema': 'ocore-original-ordered-multi-output-commitment-v2',
                   'registry': {'bytes': len(registry_raw), 'sha256': digest(registry_raw)},
                   'selected_profiles': selected_profiles, 'required_unit_ids': required_unit_ids,
                   'actions': actions, 'original_occurrences': original_occurrences,
                   'original_order': {'bytes': len(original_order_raw), 'sha256': digest(original_order_raw)}})


def resolve_order_v2(committed_raw, original_events, required_unit_ids, original_occurrences,
                     fresh_events, original_roots, fresh_roots, original_order_raw,
                     registry_raw, selected_profiles):
    require(committed_raw == commit_order_v2(original_events, required_unit_ids, original_roots,
            original_occurrences, original_order_raw, registry_raw, selected_profiles),
            'pre-stage original action/order/contract commitment changed')
    require(type(fresh_events) is list and fresh_events and set(original_roots) == set(fresh_roots),
            'fresh actions/namespace aliases differ')
    table = _contracts(registry_raw, selected_profiles)
    original = decode(committed_raw)['actions']
    fresh = [_action_v2(raw, fresh_roots, table, selected_profiles) for raw in fresh_events]
    require(len({a['action_key'] for a in fresh}) == len(fresh)
            and len({a['invocation_id'] for a in fresh}) == len(fresh), 'ambiguous fresh owning action')
    by_key = {a['action_key']: a for a in fresh}
    require(set(by_key) == {a['action_key'] for a in original}, 'fresh owning action contract differs')
    mapping = {}
    fresh_ids = []
    for action in original:
        candidate = by_key[action['action_key']]
        chosen = {encode(u['selector']): u for u in candidate['units']}
        expected = {encode(u['selector']): u for u in action['units']}
        require(set(chosen) == set(expected), 'fresh stable output inventory differs')
        for selector, unit in expected.items():
            other = chosen[selector]
            require(unit['projection'] == other['projection'], 'fresh unit source/profile/dependency differs')
            mapping[unit['unit_id']] = other['unit_id'];fresh_ids.append(other['unit_id'])
    require(len(fresh_ids) == len(set(fresh_ids)), 'fresh unit identity reused across actions')
    return {'schema': 'ocore-original-ordered-multi-output-join-v2',
            'commitment_sha256': digest(committed_raw), 'unit_mapping': mapping,
            'original_occurrences': list(original_occurrences),
            'fresh_occurrences': [mapping[u] for u in original_occurrences],
            'fresh_capture_order': [u['unit_id'] for a in fresh for u in a['units']],
            'fresh_actions_and_complete_lineage': fresh,
            'consistency_join_complete': True, 'capture_admitted': False,
            'Cargo_parent_semantic_join_supported': False, 'original_order_producer_qualified': False,
            'provider_closure_qualified': False, 'runtime_qualified': False}


# Versioned, exact checked-buffer bridge used by the production Rust consumer.
# The original31 core oracles concern the unchanged functions above. This API
# selects consistency policy only; AdmittedCapture remains the admission owner.
def bridge(request):
    require(type(request) is dict, 'bridge request must be an object')
    common = {'schema', 'operation', 'original_events', 'required_unit_ids',
              'original_roots', 'original_occurrences', 'original_order_raw',
              'registry_raw', 'selected_profiles'}
    require(request.get('schema') == 'Main-source-order-helper-request/v2', 'bridge request schema')
    operation = request.get('operation')
    require(operation in {'commit', 'resolve'}, 'unsupported bridge operation')
    expected = common if operation == 'commit' else common | {'commitment', 'fresh_events', 'fresh_roots'}
    require(set(request) == expected, 'bridge request fields differ')
    def buffers(name):
        values = request[name]
        require(type(values) is list and all(type(v) is str for v in values),
                'event buffers must be JSON strings')
        return [v.encode('utf-8', 'strict') for v in values]
    require(type(request['original_order_raw']) is str and type(request['registry_raw']) is str,
            'held order/registry buffers must be JSON strings')
    original = buffers('original_events')
    order = request['original_order_raw'].encode('utf-8', 'strict')
    registry = request['registry_raw'].encode('utf-8', 'strict')
    if operation == 'commit':
        return {'commitment': commit_order_v2(original, request['required_unit_ids'],
            request['original_roots'], request['original_occurrences'], order,
            registry, request['selected_profiles']).decode('utf-8', 'strict')}
    require(type(request['commitment']) is str, 'commitment buffer must be a JSON string')
    return resolve_order_v2(request['commitment'].encode('utf-8', 'strict'), original,
        request['required_unit_ids'], request['original_occurrences'], buffers('fresh_events'),
        request['original_roots'], request['fresh_roots'], order, registry, request['selected_profiles'])
