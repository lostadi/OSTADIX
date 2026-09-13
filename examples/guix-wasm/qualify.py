# Heavy opt-in test controller; the subject is the real guix-package.O program.
# Requires a new external evidence directory and a pinned image; never prunes caches.
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def main():
    root = Path.cwd().resolve()
    original = root / 'examples/guix-wasm/guix-package.O'
    harness = root / 'apps/olang-browser-wasi/test-browser.mjs'
    require(original.is_file() and harness.is_file() and (root / 'Cargo.toml').is_file(),
            'Run qualify.py from the Ostadix repository root')
    requested = os.environ.get('OLANG_GUIX_EVIDENCE_DIR', '')
    require(requested, 'Set OLANG_GUIX_EVIDENCE_DIR to a new directory outside the checkout')
    evidence = Path(requested).absolute()
    evidence = evidence.parent.resolve(strict=True) / evidence.name
    require(evidence != root and root not in evidence.parents, 'Evidence must be outside the checkout')
    evidence.mkdir(mode=0o700)  # No exist_ok: never reuse or overwrite caller evidence.
    receipt = {'schema': 'ostadix.guix-wasm-qualification/v1', 'status': 'running', 'runs': {}}

    def save():
        pending = evidence / '.receipt.json.next'
        pending.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
        pending.replace(evidence / 'receipt.json')

    def progress(message):
        print(message, file=sys.stderr, flush=True)

    def interrupted(signum, frame):
        raise KeyboardInterrupt('qualification interrupted by signal ' + str(signum))

    def run(label, argv, deadline, cwd, env=None, expected=0, build=False):
        start = time.monotonic()
        record = {'argv': argv, 'cwd': str(cwd), 'started_at': datetime.now(timezone.utc).isoformat(),
                  'deadline_seconds': deadline, 'status': 'running', 'assertions_passed': False,
                  'environment': 'empty' if env == {} else 'explicit-browser' if label == 'browser' else 'host',
                  'stdout_log': label + '.stdout.log', 'stderr_log': label + '.stderr.log'}
        receipt['runs'][label] = record
        save()
        progress(label + ': ' + str(evidence / record['stdout_log']) + ' ; ' + str(evidence / record['stderr_log']))
        process = None
        try:
            with (evidence / record['stdout_log']).open('xb') as out, (evidence / record['stderr_log']).open('xb') as err:
                if build:
                    require(min(shutil.disk_usage(evidence).free, shutil.disk_usage(tempfile.gettempdir()).free)
                            >= 1536 * 1024 * 1024, 'Build refused: less than 1.5 GiB free')
                process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                           stdout=out, stderr=err, start_new_session=True)
                while True:
                    if build:
                        free = min(shutil.disk_usage(evidence).free, shutil.disk_usage(tempfile.gettempdir()).free)
                        record['last_free_bytes'] = free
                        require(free >= 1536 * 1024 * 1024, 'Build stopped: less than 1.5 GiB free')
                    remaining = deadline - (time.monotonic() - start)
                    require(remaining > 0, label + ' exceeded its deadline')
                    try:
                        process.wait(timeout=min(30, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        save()
                        progress(label + ': still running (' + str(int(time.monotonic() - start)) + 's)')
                require(process.returncode == expected, label + ': unexpected exit ' + str(process.returncode))
                record['status'] = 'completed'
        except BaseException as error:
            record['status'] = 'failed'
            record['error'] = (type(error).__name__ + ': ' + str(error))[:2048]
            if process is not None:
                try:
                    # Let the browser harness close its separately owned Chrome group.
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
                record['cleanup_scope'] = 'owned_process_group'
            raise
        finally:
            record['returncode'] = process.returncode if process is not None else None
            record['duration_seconds'] = round(time.monotonic() - start, 3)
            save()
        return record

    profile, stop_attempted, build_started = '', False, False
    previous_signals = {}
    try:
        save()
        for number in (signal.SIGINT, signal.SIGTERM):
            previous_signals[number] = signal.signal(number, interrupted)
        runtime = os.environ.get('OLANG_GUIX_RUNTIME_IMAGE', '')
        require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._/:\-]*@sha256:[0-9a-f]{64}', runtime),
                'OLANG_GUIX_RUNTIME_IMAGE must be a digest-pinned OCI manifest reference')
        builder = 'docker.io/library/rust:1.97.1-slim-bookworm@sha256:39f68a3e8e3ff425f8945ffa91128e60ff930d53e17fbb5214e95824bdd46f1b'
        profile = os.environ.get('OLANG_GUIX_BUILDER_PROFILE', '')
        require(profile in ('', 'ostadix-wasm'), 'Only the explicitly owned ostadix-wasm Colima profile may be stopped')
        tools = {}
        for name in ('docker', 'c2w', 'wasmtime', 'wasmer', 'node') + (('colima',) if profile else ()):
            executable = shutil.which(name)
            require(executable, 'Missing required executable: ' + name)
            tools[name] = str(Path(executable).resolve())
        compiler = Path(os.environ.get('OLANGC_GUIX_TEST_BIN', root / 'target/release/olangc')).resolve()
        require(compiler.is_file() and os.access(compiler, os.X_OK), 'Missing executable compiler: ' + str(compiler))
        receipt.update(runtime_image=runtime, builder_image=builder, compiler=str(compiler),
                       compiler_sha256=digest(compiler), builder_profile=profile or None)
        source_dir, bundle, unrelated = evidence / 'input', evidence / 'bundle', evidence / 'unrelated-runtime-cwd'
        source_dir.mkdir(mode=0o700)
        unrelated.mkdir(mode=0o700)
        source = source_dir / 'guix-package.O'
        with source.open('xb') as stream:
            stream.write(original.read_bytes())
        receipt['source_sha256'] = digest(source)
        build_started = True
        built = run('build', [str(compiler), str(source), '--target', 'wasm', '--browser-bundle', str(bundle),
                    '--wasm-runtime-image', runtime, '--wasm-builder-image', builder], 10800, root, build=True)
        if profile:
            stop_attempted = True
            run('stop-builder', [tools['colima'], 'stop', profile], 120, root)['assertions_passed'] = True
        source.unlink()  # Only our exact source copy is removed; retain the emitted bundle source.
        source_dir.rmdir()
        receipt['input_copy_deleted_before_execution'] = True
        receipt['source_retained_in_bundle'] = True
        manifest = json.loads((bundle / 'manifest.json').read_text())
        require(manifest['schema'] == 'ostadix.olang-linux-browser-bundle/v1', 'Wrong browser execution route')

        def verify_file(record):
            path = bundle / record['path']
            require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(bundle.resolve()),
                    'Bundle record escapes its regular-file tree')
            require(path.stat().st_size == record['bytes'] and digest(path) == record['sha256'],
                    'Bundle file digest/length mismatch: ' + record['path'])

        for key, path in (('source', 'program.O'), ('artifact', 'program.wasm'),
                          ('plan', 'program.plan.txt'), ('build', 'wasm-build.json')):
            require(manifest[key]['path'] == path, 'Unexpected bundle record path: ' + key)
            verify_file(manifest[key])
        for record in manifest['assets'] + [adapter['file'] for adapter in manifest['adapters']]:
            verify_file(record)
        build_record = json.loads((bundle / 'wasm-build.json').read_text())
        require(build_record['schema'] == 'ostadix.olang-wasm-container-build/v1'
                and build_record['profile'] == 'embedded-linux-amd64-wasi-experimental', 'Wrong build record')
        require(build_record['source_sha256'] == manifest['source']['sha256'] == receipt['source_sha256']
                and build_record['plan_sha256'] == manifest['plan']['sha256'], 'Source/plan binding mismatch')
        require(build_record['runtime_image'] == runtime and build_record['builder_image'] == builder
                and build_record['backend_grants'] == manifest['backend_grants'] == []
                and build_record['adapters'] == [{'name': item['name'], 'sha256': item['file']['sha256']}
                                               for item in manifest['adapters']], 'Build inputs mismatch')
        artifact = bundle / 'program.wasm'
        with artifact.open('rb') as stream:
            require(stream.read(8) == b'\x00asm\x01\x00\x00\x00', 'Invalid Wasm header')
        receipt.update(artifact_sha256=manifest['artifact']['sha256'], plan_sha256=manifest['plan']['sha256'],
                       build_record_sha256=manifest['build']['sha256'], bundle='bundle')
        built['assertions_passed'] = True
        save()
        success, failure = 'OSTADIX_GUIX_PACKAGE:42->43', 'OSTADIX_GUIX_INTENTIONAL_FAILURE'
        for engine in ('wasmtime', 'wasmer'):
            for fail in (False, True):
                label = engine + ('.failure' if fail else '.success')
                argv = [tools[engine], 'run'] + (['--env=OSTADIX_GUIX_FORCE_FAILURE=1'] if fail else [])
                argv += [str(artifact)] + (['--'] if engine == 'wasmer' else []) + ['--no-stdin']
                record = run(label, argv, 600, unrelated, env={}, expected=1 if fail else 0)
                stdout = (evidence / record['stdout_log']).read_text(errors='replace')
                stderr = (evidence / record['stderr_log']).read_text(errors='replace')
                require((failure in stdout + stderr and success not in stdout + stderr) if fail else success in stdout,
                        label + ': missing expected marker or unexpected success')
                require(digest(artifact) == receipt['artifact_sha256'], 'Artifact changed during execution')
                record['assertions_passed'] = True
                save()
        browser_env = os.environ.copy()
        browser_env.update(OLANG_BROWSER_EVIDENCE_DIR=str(evidence / 'browser'),
                           OLANG_BROWSER_FAILURE_ENV='OSTADIX_GUIX_FORCE_FAILURE', OLANG_BROWSER_FAILURE_MARKER=failure)
        checked = run('browser', [tools['node'], str(harness), str(bundle), success], 1300, unrelated, env=browser_env)
        browser = json.loads((evidence / 'browser/receipt.json').read_text())
        require(browser['schema'] == 'ostadix.browser-qualification/v1' and browser['status'] == 'passed'
                and browser['profile'] == manifest['schema'] and browser['source_sha256'] == receipt['source_sha256']
                and browser['artifact_sha256'] == receipt['artifact_sha256'], 'Browser receipt is not a pass for this artifact')
        require(digest(artifact) == receipt['artifact_sha256'], 'Artifact changed during browser qualification')
        checked['assertions_passed'] = True
        require(all(record['assertions_passed'] for record in receipt['runs'].values()), 'Incomplete qualification')
        receipt['status'] = 'passed'
    except BaseException as error:
        receipt.update(status='failed', error=(type(error).__name__ + ': ' + str(error))[:2048])
        if profile == 'ostadix-wasm' and build_started and not stop_attempted:
            stop_attempted = True
            try:
                run('stop-builder-after-abort', [tools['colima'], 'stop', profile], 120, root)
            except BaseException as cleanup_error:
                receipt['builder_stop_error'] = str(cleanup_error)[:2048]
        progress(receipt['error'])
        return 1
    finally:
        save()
        for number, previous in previous_signals.items():
            signal.signal(number, previous)
        progress('Qualification ' + receipt['status'] + ': ' + str(evidence / 'receipt.json'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
