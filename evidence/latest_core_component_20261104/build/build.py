"""Fresh non-test core-component build; no original-runtime qualification."""
import hashlib
import json
import os
import shlex
import signal
import stat
import subprocess
import time
from pathlib import Path

ROOT = Path('/home/orangepi/ostadix-BM')
OUT = Path(__file__).resolve().parent
SOURCE = Path('/tmp/Main-SourceO-assembly-r1-20261101/source')
OLD = Path('/tmp/Main-A-core-fresh-build-r2-20261102/before.json')
RECIPE = Path('/tmp/Main-A-fresh-core-library-r2-20261102/stages/api.sh')
FLOOR = 33554432
FORECAST = 159383552


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def meta(s):
    return dict(dev=str(s.st_dev), ino=str(s.st_ino), bytes=s.st_size,
                mode=stat.S_IMODE(s.st_mode), nlink=str(s.st_nlink),
                uid=s.st_uid, gid=s.st_gid, mtime_ns=str(s.st_mtime_ns),
                ctime_ns=str(s.st_ctime_ns))


def resolve(path):
    pending, current, links = str(path).split('/')[1:], '/', []
    while pending:
        part = pending.pop(0)
        if not part or part == '.':
            continue
        if part == '..':
            current = os.path.dirname(current)
            continue
        candidate = os.path.join(current, part)
        s = os.lstat(candidate)
        if stat.S_ISLNK(s.st_mode):
            if len(links) >= 40:
                raise ValueError('symlink resolution limit exceeded')
            target = os.readlink(candidate)
            links.append(dict(path=candidate, target=target, metadata=meta(s)))
            if target.startswith('/'):
                current = '/'
            pending = target.split('/') + pending
        else:
            current = candidate
    return current, links


def checked(pin, fresh=False):
    path = pin['path']
    target, links = resolve(path)
    if target != pin['realpath']:
        raise ValueError('selected realpath changed: ' + path)
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        first = meta(os.fstat(fd))
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('selected target is not regular: ' + path)
        if not fresh and (any(str(first[k]) != str(pin[k]) for k in first)
                          or links != pin['links']):
            raise ValueError('fresh selected metadata changed: ' + path)
        h, size = hashlib.sha256(), 0
        while True:
            b = os.read(fd, 1048576)
            if not b:
                break
            size += len(b)
            h.update(b)
        if size != pin['bytes'] or h.hexdigest() != pin['sha256']:
            raise ValueError('selected content changed: ' + path)
        if first != meta(os.fstat(fd)) or first != meta(os.stat(path)) \
                or (target, links) != resolve(path):
            raise ValueError('selected input changed during read: ' + path)
        return dict(pin, **first, named=first, links=links)
    finally:
        os.close(fd)


def memberships(groups):
    for group in groups:
        actual = sorted(str(p) for p in Path(group['root']).rglob('*')
                        if not p.is_dir() or p.is_symlink())
        if actual != sorted(group['paths']):
            raise ValueError('selected directory membership changed: ' + group['root'])


def resources():
    def free(path):
        s = os.statvfs(path)
        return s.f_bavail * s.f_frsize
    memory = next(int(line.split()[1]) * 1024 for line in
                  Path('/proc/meminfo').read_text().splitlines()
                  if line.startswith('MemAvailable:'))
    return dict(root=free(ROOT), tmp=free('/tmp'), memory=memory)


def save(name, data):
    raw = (json.dumps(data, indent=2) + '\n').encode()
    with (OUT / name).open('xb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def output_pin(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        first = meta(os.fstat(fd))
        if not stat.S_ISREG(os.fstat(fd).st_mode) or first['nlink'] != '1':
            raise ValueError('output type/link count differs: ' + str(path))
        h, header = hashlib.sha256(), os.read(fd, 8)
        h.update(header)
        while True:
            chunk = os.read(fd, 1048576)
            if not chunk:
                break
            h.update(chunk)
        if first != meta(os.fstat(fd)) or first != meta(os.lstat(path)):
            raise ValueError('output changed during held read: ' + str(path))
        return dict(path=str(path), bytes=first['bytes'], sha256=h.hexdigest(),
                    metadata=first, first_eight_hex=header.hex())
    finally:
        os.close(fd)


def main():
    report = dict(schema='ostadix-fresh-core-library-build/v1', success=False,
                  full_API=False, full_compiler=False, qualification=False,
                  trace_FD_exec_admission=False, compiler_dispatched=False,
                  errors=[], resources_before=resources())
    proc, current = None, None
    try:
        raw = OLD.read_bytes()
        if sha(raw) != 'efb6b788de2e7673d7f1c19d6df58dd4dc31d69e325b5bb6144548621808b562':
            raise ValueError('historical selection hash differs')
        before = json.loads(raw)
        current = [checked(pin, fresh=True) for pin in before['inputs']]
        memberships(before['membership'])
        changes = [dict(path=old['path'], changed_metadata=[k for k in meta(os.stat(old['path']))
                   if str(old.get(k)) != str(new[k])])
                   for old, new in zip(before['inputs'], current)
                   if any(str(old.get(k)) != str(new[k]) for k in meta(os.stat(old['path'])))]
        base_path = ROOT / 'target/oversight-20261104/core-library-fresh-r4/selected-inputs.json'
        base_raw = base_path.read_bytes()
        prior = json.loads(base_raw)
        if prior['inputs'] != current or prior['membership'] != before['membership']:
            raise ValueError('fresh r5 inputs differ from checked r4 selection')
        save('selected-inputs.json', dict(base_path=str(base_path), base_sha256=sha(base_raw),
             original_selection_sha256=sha(raw), freshly_checked_inputs=len(current),
             historical_metadata_differences=changes))
        recipe = RECIPE.read_bytes()
        if sha(recipe) != 'b74fe057e1e4b2f146748e42e8338491f5e39fcef058978d4d3741ce1f6ddeea':
            raise ValueError('recipe hash differs')
        tokens = shlex.split(recipe.decode())
        tokens = tokens[:next(i for i, s in enumerate(tokens)
                              if s.startswith('>') or s.startswith('2>'))]
        if tokens[:3] != ['exec', '/usr/bin/env', '-i']:
            raise ValueError('recipe invocation differs')
        env, i = {}, 3
        while '=' in tokens[i] and not tokens[i].startswith('/'):
            key, value = tokens[i].split('=', 1)
            env[key] = value
            i += 1
        argv = tokens[i:]
        if not argv[0].endswith('/1.97.1-riscv64gc-unknown-linux-gnu/bin/rustc'):
            raise ValueError('compiler selection differs')
        if argv.count('codegen-units=16') != 1:
            raise ValueError('original codegen-units selector differs')
        argv[argv.index('codegen-units=16')] = 'codegen-units=1'
        report['build_profile_change'] = dict(old='codegen-units=16', new='codegen-units=1',
            reason='Measured r4 memory cancellation; reduce parallel backend work.',
            semantic_qualification=False)
        argv[argv.index('-o') + 1] = str(OUT / 'libo_lang.rlib')
        argv[argv.index('--emit') + 1] = 'link,dep-info=' + str(OUT / 'api.d')
        (OUT / 'tmp').mkdir()
        env['TMPDIR'] = str(OUT / 'tmp')
        report.update(argv=argv, environment=env, declared_inputs=len(current),
                      historical_metadata_differences=changes, resources_at_dispatch=resources())
        save('selection.json', report)
        r = resources()
        if r['root'] < FORECAST + FLOOR or r['tmp'] < FLOOR or r['memory'] < 536870912:
            raise ValueError('fresh build capacity admission unmet: ' + str(r))
        with (OUT / 'stdout.log').open('xb') as stdout, (OUT / 'stderr.log').open('xb') as stderr:
            proc = subprocess.Popen(argv, env=env, cwd=SOURCE, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, process_group=0)
            report.update(compiler_dispatched=True, pid=proc.pid, process_group=proc.pid)
            save('dispatch.json', report)
            minimum = dict(r)
            last = 0
            while proc.poll() is None:
                r = resources()
                minimum = {k: min(v, r[k]) for k, v in minimum.items()}
                if r['root'] < FLOOR or r['memory'] < 268435456:
                    report['capacity_cancel'] = r
                    os.killpg(proc.pid, signal.SIGKILL)
                    break
                if time.monotonic() - last > 30:
                    print(json.dumps(dict(phase='compiling', pid=proc.pid, resources=r)), flush=True)
                    last = time.monotonic()
                time.sleep(0.25)
            report.update(exit_code=proc.wait(), minimum_resources=minimum)
        for pin in current:
            checked(pin)
        memberships(before['membership'])
        report['input_postguards_passed'] = True
        artifact = OUT / 'libo_lang.rlib'
        if report['exit_code'] == 0 and artifact.is_file() and not report.get('capacity_cancel'):
            pin = output_pin(artifact)
            depfile = output_pin(OUT / 'api.d')
            if pin['first_eight_hex'] != b'!<arch>\n'.hex() or depfile['bytes'] <= 0:
                raise ValueError('rlib or dependency artifact contract differs')
            report.update(artifact=pin, dependency_file=depfile, success=True)
    except BaseException as error:
        report['errors'].append(dict(type=type(error).__name__, message=str(error)))
    finally:
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            report['exit_code'] = proc.wait()
        if report['compiler_dispatched'] and not report.get('input_postguards_passed'):
            failures = []
            for pin in current:
                try:
                    checked(pin)
                except BaseException as error:
                    failures.append(dict(path=pin['path'], error=str(error)))
            try:
                memberships(before['membership'])
            except BaseException as error:
                failures.append(dict(error=str(error)))
            report['input_postguard_failures'] = failures
            report['input_postguards_passed'] = not failures
            if failures:
                report['success'] = False
        report['resources_after'] = resources()
        if report['resources_after']['root'] < FLOOR + 1048576 or \
                report['resources_after']['memory'] < 268435456:
            report['success'] = False
            report['errors'].append(dict(type='FinalResourceFloor',
                                         message='Final resource reserve unmet'))
        save('terminal.json', report)
    print(json.dumps(dict(success=report['success'], exit_code=report.get('exit_code'),
          errors=report['errors'], receipt=str(OUT / 'terminal.json'))), flush=True)
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
