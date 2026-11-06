"""Fresh-r3 source/tool/SDK guards. This module never launches a compiler."""
import hashlib
import os
import stat


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb', buffering=0) as stream:
        while True:
            b = stream.read(1048576)
            if not b:
                return h.hexdigest()
            h.update(b)


def metadata(s):
    return {'dev': str(s.st_dev), 'ino': str(s.st_ino),
            'bytes': s.st_size, 'mode': stat.S_IMODE(s.st_mode),
            'nlink': str(s.st_nlink), 'uid': s.st_uid, 'gid': s.st_gid,
            'mtime_ns': str(s.st_mtime_ns), 'ctime_ns': str(s.st_ctime_ns)}


def check_pin(pin):
    path = pin['path']
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode):
            raise ValueError('selected input is not a regular file')
        actual = metadata(first)
        for key in actual:
            if key in pin and str(actual[key]) != str(pin[key]):
                raise ValueError('selected metadata differs: ' + key)
        if actual != metadata(os.lstat(path)):
            raise ValueError('held/named metadata differs before read')
        h, size = hashlib.sha256(), 0
        while True:
            b = os.read(fd, 1048576)
            if not b:
                break
            size += len(b)
            h.update(b)
        if size != pin['bytes'] or h.hexdigest() != pin['sha256']:
            raise ValueError('selected input bytes/hash differ')
        if actual != metadata(os.fstat(fd)) or actual != metadata(os.lstat(path)):
            raise ValueError('selected input changed during read')
        if 'realpath' in pin and os.path.realpath(path) != pin['realpath']:
            raise ValueError('selected input realpath differs')
    finally:
        os.close(fd)


def members(root):
    found, pending = [], [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(entry.path)
                else:
                    found.append(entry.path)
    return sorted(found)


def inventory(before):
    failures = []
    for pin in before['inputs']:
        try:
            check_pin(pin)
        except BaseException as error:
            failures.append({'path': pin['path'], 'type': type(error).__name__,
                             'error': str(error)[:2048]})
    for group in before['membership']:
        try:
            actual, expected = members(group['root']), sorted(group['paths'])
            if actual != expected:
                failures.append({'root': group['root'], 'error': 'directory membership differs',
                                 'missing': sorted(set(expected) - set(actual)),
                                 'extra': sorted(set(actual) - set(expected))})
        except BaseException as error:
            failures.append({'root': group['root'], 'type': type(error).__name__,
                             'error': str(error)[:2048]})
    return {'checked_inputs': len(before['inputs']),
            'checked_memberships': len(before['membership']),
            'failures': failures, 'success': not failures}


def resources(root):
    def free(path):
        s = os.statvfs(path)
        return s.f_bavail * s.f_frsize
    with open('/proc/meminfo', 'r', encoding='ascii') as stream:
        rows = dict(line.split(':', 1) for line in stream if ':' in line)
    return {'root_available': free(root), 'tmp_available': free('/tmp'),
            'memory_available': int(rows['MemAvailable'].split()[0]) * 1024,
            'reservation': False}


def group_members(group):
    rows = []
    for entry in os.scandir('/proc'):
        if not entry.name.isdecimal():
            continue
        try:
            with open(entry.path + '/stat', encoding='ascii') as stream:
                text = stream.read()
            tail = text[text.rfind(')') + 2:].split()
            if int(tail[2]) == group and int(tail[3]) == group:
                rows.append({'pid': int(entry.name), 'state': tail[0],
                             'start_ticks': int(tail[19])})
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    return rows
