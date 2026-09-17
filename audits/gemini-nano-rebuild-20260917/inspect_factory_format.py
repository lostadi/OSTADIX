#!/usr/bin/env python3
"""Read-only inventory/static loader inspection; never invokes the model/HAL."""
import collections
import hashlib
import json
import math
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path('/data/vendor/intelligence')
JAVA = Path('/data/local/tmp/ostadix-ai-audit-20260915/aicore-jadx/sources/p000')
NATIVE = Path('/data/local/tmp/ostadix-ai-audit-20260915/aicore-native/libgoogle3.so')
THRESHOLD = 104857600


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    result = {'factory_root': str(ROOT), 'loader_threshold_bytes': THRESHOLD}
    counts = collections.Counter()
    inventory = []
    for path in sorted(ROOT.iterdir()):
        if not path.is_file():
            continue
        size = path.stat().st_size
        with path.open('rb') as f:
            h = f.read(16)
        tfl3 = h[4:8] == b'TFL3'
        direct = size >= THRESHOLD
        counts[f'{"direct" if direct else "trusty"}_{"TFL3" if tfl3 else "other"}'] += 1
        inventory.append({'name': path.name, 'bytes': size, 'header16': h.hex(),
                          'loader_branch_from_static_size_rule': 'direct' if direct else 'trusty',
                          'tfl3_identifier': tfl3, 'multiple_of_4096': size % 4096 == 0})
    result['inventory'] = inventory
    result['counts'] = dict(counts)
    result['metadata_sha256'] = {name: sha(ROOT / name) for name in
                                 ('config.binarypb', 'manifest.binarypb', 'checkpoint.binarypb')}
    data0 = ROOT / 'data0'
    with data0.open('rb') as f:
        sample = f.read(1024 * 1024)
    candidate_stats = []
    for stride in (18, 32, 34, 36, 64, 128):
        count = len(sample) // stride
        values = [struct.unpack_from('<e', sample, i * stride)[0] for i in range(count)]
        candidate_stats.append({'stride_bytes': stride, 'blocks': count,
                                'finite_fp16_at_start': sum(map(math.isfinite, values)),
                                'positive_fp16_le_point1_at_start': sum(0 < v <= 0.1 for v in values)})
    result['data0_sample'] = {'sample_bytes': len(sample), 'sample_sha256': hashlib.sha256(sample).hexdigest(),
                              'statistics': candidate_stats,
                              'interpretation_limit': 'Structured numeric pattern consistent with quantized blocks; not a complete tensor-layout validation.'}
    selected = {
        'cat.java': r'104857600|FileInputStream|TrustyDecrypt|iRemaining|i4 =|i4 <=|limit\(i4\)|mo9287e|SharedMemory|_SC_PAGE_SIZE',
        'ivv.java': r'TrustyDecrypt|m1332b|axb.m1338c|readInt',
        'buu.java': r'case 1:|case 3:|m2397b|hak.m7242v\(edd|parse preloaded',
        'bsk.java': r'm2398c|new bss\(|f4536g.put|f19898b',
        'bim.java': r'case 10:|f19898b == 1',
        'btn.java': r'config.binarypb|hidVar|Failed to load config',
        'edd.java': r'return new hby',
        'edb.java': r'return new hby',
        'ect.java': r'return new hby',
        'ecs.java': r'return new hby',
        'hid.java': r'return new hby',
    }
    result['loader_source_evidence'] = {}
    for name, pattern in selected.items():
        p = JAVA / name
        result['loader_source_evidence'][name] = {
            'path': str(p), 'sha256': sha(p),
            'selected_lines': [{'line': i, 'text': line.strip()}
                               for i, line in enumerate(p.read_text().splitlines(), 1)
                               if re.search(pattern, line)]}
    process = subprocess.run(['/system/bin/service', 'list'], capture_output=True, text=True, check=True)
    result['live_services_selected'] = [line for line in process.stdout.splitlines() if 'TrustyDecrypt' in line]
    paths = [Path('/vendor/bin/hw/vendor.google.plat_security-service'), NATIVE]
    result['native_evidence'] = []
    for p in paths:
        process = subprocess.run(['strings', str(p)], capture_output=True, text=True, check=True)
        needle = (r'ITrustyDecrypt|com.android.trusty.ml_prot|Output buffer size|input file size' if p != NATIVE
                  else r'^q4_0$|aicore.GgmlCheckpoint|sizeof\(block_q4_0\)|checkpoint.ParseFromString|ReadCheckpointFile_and_ParseFile|^config.binarypb$|^checkpoint.binarypb$|^darwinn_external_parameter$')
        result['native_evidence'].append({'path': str(p), 'sha256': sha(p),
                                          'matching_strings': [s for s in process.stdout.splitlines() if re.search(needle, s)]})
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
