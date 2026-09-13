"""Create only a new build-local ext4 image and export bounded sparse extents.

Never invoked against browser state, host block devices, or an existing file.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess

profile = json.loads(Path('/work/state-profile.json').read_bytes())
if (not isinstance(profile, dict)
        or set(profile) != {'schema', 'uuid', 'bytes', 'runtime_image', 'layout'}
        or profile['schema'] != 'ostadix.guix-state/v1'
        or type(profile['bytes']) is not int or profile['bytes'] != 2147483648
        or type(profile['layout']) is not int or profile['layout'] != 1
        or not isinstance(profile['uuid'], str)
        or not isinstance(profile['runtime_image'], str) or len(profile['runtime_image']) > 512
        or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}', profile['runtime_image'])
        or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', profile['uuid'])):
    raise ValueError('Invalid immutable disk profile')
identity = bytearray(hashlib.sha256(profile['runtime_image'].encode()).digest()[:16])
identity[6] = (identity[6] & 0x0f) | 0x40
identity[8] = (identity[8] & 0x3f) | 0x80
encoded = identity.hex()
expected_uuid = '-'.join((encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]))
if profile['uuid'] != expected_uuid:
    raise ValueError('State UUID must match its pinned runtime image, as required by guest init')
seed = Path('/work/seed')
seed.mkdir(mode=0o700)
for name in ('store', 'var-guix', 'root'):
    (seed / name).mkdir(mode=0o700)
    for part in ('upper', 'work'):
        # Overlayfs exposes the upper root's mode at the merged destination.
        # Store/build users need search access; backing/work paths stay private.
        # These directories are newly created build assets, never existing OPFS.
        mode = 0o755 if part == 'upper' and name != 'root' else 0o700
        directory = seed / name / part
        directory.mkdir(mode=mode)
        directory.chmod(mode)
with (seed / '.ostadix-guix-state.json').open('xb') as stream:
    stream.write(json.dumps(profile, sort_keys=True).encode())
image = Path('/work/state.img')
with image.open('xb') as stream:
    stream.truncate(profile['bytes'])
subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext4', '-b', '4096', '-I', '256',
                '-m', '0', '-U', profile['uuid'], '-L', 'OGUIXSTATE', '-O', '^64bit',
                '-E', 'lazy_itable_init=0,lazy_journal_init=0', '-d', str(seed), str(image)],
               check=True, timeout=600)
output = Path('/out')
output.mkdir()
(output / 'disk-chunks').mkdir()
chunks, retained = [], 0
def emit(offset, data):
    global retained
    retained += len(data)
    if retained > 67108864 or len(chunks) >= 4096:
        raise ValueError('Initial filesystem metadata exceeds its bounded asset profile')
    path = f'disk-chunks/{len(chunks):04}.bin'
    with (output / path).open('xb') as stream:
        stream.write(data)
    chunks.append({'path': path, 'offset': offset, 'bytes': len(data),
                   'sha256': hashlib.sha256(data).hexdigest()})
with image.open('rb') as stream:
    offset, start, pending = 0, 0, bytearray()
    while True:
        page = stream.read(4096)
        if not page:
            break
        if any(page):
            if not pending:
                start = offset
            pending.extend(page)
            if len(pending) == 1048576:
                emit(start, pending)
                pending = bytearray()
        elif pending:
            emit(start, pending)
            pending = bytearray()
        offset += len(page)
    if pending:
        emit(start, pending)
    if offset != profile['bytes']:
        raise ValueError('Unexpected filesystem image length')
with (output / 'initial-disk.json').open('x') as stream:
    json.dump({'schema': 'ostadix.sparse-disk/v1', 'bytes': profile['bytes'],
               'block_bytes': 4096, 'chunks': chunks}, stream, sort_keys=True)
