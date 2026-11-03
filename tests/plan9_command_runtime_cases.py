#!/usr/bin/env python3
"""Prepare/check original-guest fixtures; never execute or emulate Plan 9 here.

The private VM runner owns publication, lifecycle and captured-file provenance.
This module supplies independent byte oracles and verifies the returned files.
Running ``prepare`` is fixture generation, not runtime qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


SOURCE = Path(__file__).resolve().parents[1] / "ocore/guest/plan9/unified/protocol.py"
SPEC = importlib.util.spec_from_file_location("plan9_runtime_case_protocol", SOURCE)
protocol = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = protocol
SPEC.loader.exec_module(protocol)


def _quote_rc(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def prepare(output: Path, generation: str, instance: str, cwd: str) -> dict:
    """Create private input fixtures and a manifest; output must not exist."""
    protocol.ready_marker(generation, instance)
    protocol.request_paths(protocol.DEFAULT_ROOT, generation, instance, "0" * 32)
    output.mkdir(parents=True, exist_ok=False)
    cases = []
    binary = bytes(range(256)) * 257 + b"\0tail\r\n\xff"
    cwd_proof = b"working directory bytes\0\xff\n"
    (output / "cwd-proof.bin").write_bytes(cwd_proof)
    delayed_path = cwd.rstrip("/") + "/background-must-not-write"
    counter_path = cwd.rstrip("/") + "/admission-count"

    def add(name, argv, *, stdin=b"", stdout=b"", stderr=b"", flags=0,
            status_contains=None, status_empty=True, timeout_ms=10000,
            stdout_limit=1048576, stderr_limit=1048576, case_cwd=None,
            stderr_contains=None, status_exact=None):
        request_id = hashlib.sha256((generation + instance + name).encode()).hexdigest()[:32]
        encoded = protocol.encode_request(generation, instance, request_id, argv,
                                          cwd=cwd if case_cwd is None else case_cwd, stdin=stdin,
                                          timeout_ms=timeout_ms, stdout_limit=stdout_limit,
                                          stderr_limit=stderr_limit)
        directory = output / name
        directory.mkdir()
        (directory / "request").write_bytes(encoded)
        (directory / "submit").write_bytes(protocol.submit_marker(encoded))
        (directory / "expected-stdout").write_bytes(stdout)
        (directory / "expected-stderr").write_bytes(stderr)
        entry = {'name': name, 'request_id': request_id, 'directory': name,
                 'request_sha256': hashlib.sha256(encoded).hexdigest(),
                 'flags': flags, 'status_empty': status_empty,
                 'status_contains': status_contains, 'stderr_contains': stderr_contains,
                 'status_exact': status_exact}
        cases.append(entry)
        return entry

    add('binary_stdin', ['/bin/cat'], stdin=binary, stdout=binary)
    add('cwd_relative_read', ['/bin/cat', 'cwd-proof.bin'], stdout=cwd_proof)
    add('exact_argv', ['/bin/echo', '-n', 'one two', "quote'arg", '', 'é'],
        stdout="one two quote'arg  é".encode())
    add('separate_streams', ['/bin/rc', '-I', '-c',
                            '/bin/echo -n stdout; /bin/echo -n stderr >[1=2]'],
        stdout=b'stdout', stderr=b'stderr')
    add('nonempty_status', ['/bin/rc', '-I', '-c', "exit 'expected failure'"],
        status_empty=False, status_contains='expected failure')
    add('stdout_truncated', ['/bin/cat'], stdin=binary, stdout=binary[:33],
        flags=protocol.FLAG_STDOUT_TRUNCATED, stdout_limit=33)
    add('stderr_truncated', ['/bin/rc', '-I', '-c', '/bin/cat >[1=2]'],
        stdin=binary, stderr=binary[:29], flags=protocol.FLAG_STDERR_TRUNCATED, stderr_limit=29)
    add('zero_capture', ['/bin/cat'], stdin=binary, flags=protocol.FLAG_STDOUT_TRUNCATED,
        stdout_limit=0, stderr_limit=0)
    add('exact_capture_limit', ['/bin/cat'], stdin=binary[:33], stdout=binary[:33], stdout_limit=33)
    add('timeout', ['/bin/sleep', '3'], timeout_ms=500,
        flags=protocol.FLAG_TIMEOUT, status_empty=False)
    add('truncation_then_timeout', ['/bin/rc', '-I', '-c', '/bin/cat; /bin/sleep 3'],
        stdin=binary, stdout=binary[:33], timeout_ms=1000, stdout_limit=33,
        flags=protocol.FLAG_TIMEOUT | protocol.FLAG_STDOUT_TRUNCATED, status_empty=False)
    add('missing_executable', ['/bin/definitely-missing-p9-protocol-test'],
        flags=protocol.FLAG_START_FAILED, status_empty=False, status_contains='exec', stderr_contains='exec')
    add('missing_cwd', ['/bin/cat'], case_cwd=cwd.rstrip('/') + '/definitely-missing-directory',
        flags=protocol.FLAG_START_FAILED, status_empty=False, status_contains='chdir', stderr_contains='chdir')
    add('background_timeout', ['/bin/rc', '-I', '-c',
                               '{ /bin/sleep 3; /bin/echo late > ' + _quote_rc(delayed_path) + '; } & exit'],
        timeout_ms=500, flags=protocol.FLAG_TIMEOUT, status_empty=None)
    once = add('admission_once', ['/bin/rc', '-I', '-c',
                                 '/bin/echo once >> ' + _quote_rc(counter_path)])
    # Cancellation is a request-file operation. These fixtures do not inject
    # terminal input or claim that the service can reclaim all descendants.
    cancel_effect = cwd.rstrip('/') + '/cancel-must-not-launch'
    before = add('cancel_before_submit', ['/bin/rc', '-I', '-c',
                 '/bin/echo forbidden > ' + _quote_rc(cancel_effect)],
                 flags=protocol.FLAG_CANCELLED, status_empty=False,
                 status_exact='service: command cancelled')
    before['cancel'] = {'timing': 'before_submit', 'valid': True,
                        'must_remain_absent': cancel_effect}
    for name, truncated in (('cancel_in_flight', False), ('truncation_then_cancel', True)):
        ready = cwd.rstrip('/') + '/' + name + '-running'
        pid_path = ready + '-pid'
        command = ('/bin/cat' if truncated else '/bin/echo -n before-cancel; /bin/echo -n before-stderr >[1=2]')
        command += '; /bin/echo running > ' + _quote_rc(ready)
        command += '; /bin/echo $pid > ' + _quote_rc(pid_path) + '; /bin/sleep 30'
        entry = add(name, ['/bin/rc', '-I', '-c', command],
                    stdin=binary if truncated else b'',
                    stdout=binary[:33] if truncated else b'before-cancel',
                    stderr=b'' if truncated else b'before-stderr',
                    flags=protocol.FLAG_CANCELLED | (protocol.FLAG_STDOUT_TRUNCATED if truncated else 0),
                    status_empty=False, timeout_ms=15000,
                    stdout_limit=33 if truncated else 1048576)
        entry['cancel'] = {'timing': 'after_ready', 'valid': True, 'ready_path': ready,
                           'ready_bytes_hex': b'running\n'.hex(), 'pid_path': pid_path}
    for kind in ('partial', 'extra', 'generation', 'instance', 'request', 'hash'):
        name = 'cancel_ignored_' + kind
        entry = add(name, ['/bin/rc', '-I', '-c', '/bin/sleep 1; /bin/echo -n ' + kind],
                    stdout=kind.encode())
        entry['cancel'] = {'timing': 'before_submit', 'valid': False, 'invalid_kind': kind}
    for entry in cases:
        if 'cancel' not in entry:
            continue
        directory = output / entry['directory']
        marker = protocol.cancel_marker((directory / 'request').read_bytes())
        kind = entry['cancel'].get('invalid_kind')
        if kind == 'partial':
            marker = marker[:-1]
        elif kind == 'extra':
            marker += b'extra\n'
        elif kind is not None:
            fields = marker[:-1].split(b' ')
            index = {'generation': 1, 'instance': 2, 'request': 3, 'hash': 4}[kind]
            fields[index] = (b'0' if fields[index][:1] != b'0' else b'1') + fields[index][1:]
            marker = b' '.join(fields) + b'\n'
        (directory / 'cancel').write_bytes(marker)
        entry['cancel']['sha256'] = hashlib.sha256(marker).hexdigest()
    document = {
        'schema': 'ostadix.original-plan9-command-runtime-fixtures/v1',
        'runtime_execution_performed': False,
        'generation': generation, 'instance': instance, 'cwd': cwd,
        'protocol_source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'cases': cases,
        'setup': {'copy_fixture': 'cwd-proof.bin', 'guest_destination': cwd.rstrip('/') + '/cwd-proof.bin',
                  'must_be_absent': [delayed_path, counter_path]},
        'lifecycle_checks': [
            {'kind': 'background_cleanup', 'after_case': 'background_timeout',
             'wait_guest_seconds': 4, 'must_remain_absent': delayed_path,
             'reason': 'Historical full-profile probe only; original rc background groups require domain recovery.'},
            {'kind': 'duplicate_submission', 'after_case': 'admission_once',
             'request_id': once['request_id'], 'poll_guest_ms': 250,
             'resubmit_exact_existing_bytes': True, 'file': counter_path, 'expected_hex': b'once\n'.hex()},
            {'kind': 'changed_bytes_same_id', 'after_case': 'admission_once',
             'request_id': once['request_id'], 'poll_guest_ms': 250,
             'change_request_and_submit_but_preserve_started': True,
             'file': counter_path, 'expected_hex': b'once\n'.hex()},
            {'kind': 'unpublished_request', 'poll_guest_ms': 250,
             'instruction': 'Stage a fresh effectful request without submit; require no started marker and no effect.'},
            {'kind': 'partial_submit', 'poll_guest_ms': 250,
             'instruction': 'Stage a fresh effectful request with submit missing LF; require no started marker and no effect.'},
            {'kind': 'old_generation', 'poll_guest_ms': 250,
             'instruction': 'Stage a request from a different G; require no started marker and no effect.'},
            {'kind': 'old_instance', 'poll_guest_ms': 250,
             'instruction': 'Stage a request from a different S; require no started marker and no effect.'},
            {'kind': 'preexisting_started', 'poll_guest_ms': 250,
             'instruction': 'Stage a fresh effectful request with a pre-existing started claim; require no execution.'},
        ],
        'runner_requirements': [
            'Run only in the isolated original 9front VM with the admitted native service binary.',
            'Wait for exact ready(G,S) before creating request directories; service requires a fresh instance directory.',
            'Stage each complete request and publish submit last; wait/validate done before submitting the next case.',
            'Capture request, submit, started, stdout, stderr, status, result and done without text decoding.',
            'Capture hashes of native source/binary/toolchain, pinned image, invocation and VM transcript separately.',
            'The verifier qualifies captured response bytes; original guest execution requires the runner provenance.',
        ],
    }
    (output / 'cases.json').write_text(json.dumps(document, indent=2) + '\n')
    return document


def verify_case(fixtures: Path, captures: Path, entry: dict) -> dict:
    expected = fixtures / entry['directory']
    actual = captures / entry['directory']
    encoded = (expected / 'request').read_bytes()
    if hashlib.sha256(encoded).hexdigest() != entry['request_sha256']:
        raise ValueError('input fixture changed: ' + entry['name'])
    if (actual / 'request').read_bytes() != encoded:
        raise ValueError('captured request differs from fixture: ' + entry['name'])
    protocol.validate_submit(encoded, (actual / 'submit').read_bytes())
    stdout, stderr = (actual / 'stdout').read_bytes(), (actual / 'stderr').read_bytes()
    result = protocol.validate_result(encoded, (actual / 'result').read_bytes(), stdout, stderr,
                                      done=(actual / 'done').read_bytes(),
                                      started=(actual / 'started').read_bytes(),
                                      status=(actual / 'status').read_bytes())
    if result.flags != entry['flags']:
        raise ValueError('unexpected result flags: ' + entry['name'] + ': ' + str(result.flags))
    if stdout != (expected / 'expected-stdout').read_bytes():
        raise ValueError('stdout oracle mismatch: ' + entry['name'])
    if entry['stderr_contains'] is None:
        if stderr != (expected / 'expected-stderr').read_bytes():
            raise ValueError('stderr oracle mismatch: ' + entry['name'])
    elif entry['stderr_contains'].encode() not in stderr:
        raise ValueError('missing launch diagnostic: ' + entry['name'])
    if entry['status_empty'] is not None and (result.status == b'') != entry['status_empty']:
        raise ValueError('unexpected raw status emptiness: ' + entry['name'])
    if entry['status_contains'] is not None and entry['status_contains'].encode() not in result.status:
        raise ValueError('missing raw status marker: ' + entry['name'])
    if entry.get('status_exact') is not None and result.status != entry['status_exact'].encode():
        raise ValueError('raw status oracle mismatch: ' + entry['name'])
    cancel = entry.get('cancel')
    if cancel:
        marker = (expected / 'cancel').read_bytes()
        if hashlib.sha256(marker).hexdigest() != cancel['sha256'] or (actual / 'cancel').read_bytes() != marker:
            raise ValueError('cancel marker differs from fixture: ' + entry['name'])
        if cancel['valid']:
            protocol.validate_cancel(encoded, marker)
        else:
            try:
                protocol.validate_cancel(encoded, marker)
            except ValueError:
                pass
            else:
                raise ValueError('negative cancellation fixture is valid: ' + entry['name'])
        if cancel['timing'] == 'after_ready' and (actual / 'launch-proof').read_bytes() != bytes.fromhex(cancel['ready_bytes_hex']):
            raise ValueError('command did not establish the pre-cancel execution proof: ' + entry['name'])
        if cancel['timing'] == 'after_ready':
            pid = (actual / 'command-pid').read_bytes()
            if not pid.endswith(b'\n') or not pid[:-1].isdigit() or int(pid) <= 0:
                raise ValueError('command PID witness is invalid: ' + entry['name'])
    return {'name': entry['name'], 'passed': True, 'flags': result.flags,
            'stdout_bytes': result.stdout_bytes, 'stderr_bytes': result.stderr_bytes,
            'status_hex': result.status.hex(), 'result_sha256': hashlib.sha256((actual / 'result').read_bytes()).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    create = actions.add_parser('prepare')
    create.add_argument('--output', required=True, type=Path)
    create.add_argument('--generation', required=True)
    create.add_argument('--instance', required=True)
    create.add_argument('--cwd', required=True)
    check = actions.add_parser('verify')
    check.add_argument('--fixtures', required=True, type=Path)
    check.add_argument('--captures', required=True, type=Path)
    args = parser.parse_args()
    if args.action == 'prepare':
        manifest = prepare(args.output, args.generation, args.instance, args.cwd)
        print(json.dumps({'runtime_execution_performed': False, 'cases': len(manifest['cases']),
                          'manifest': str(args.output / 'cases.json')}, indent=2))
    else:
        manifest = json.loads((args.fixtures / 'cases.json').read_text())
        results = [verify_case(args.fixtures, args.captures, entry) for entry in manifest['cases']]
        print(json.dumps({'schema': 'ostadix.plan9-captured-response-validation/v1',
                          'captured_responses_valid': True, 'original_guest_execution_claimed': False,
                          'lifecycle_checks_not_validated_here': manifest['lifecycle_checks'],
                          'cases': results}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
