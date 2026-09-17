#!/usr/bin/env python3
"""Inspect decoded static metadata; do not export weights or tokenizer pieces.

The two inputs must already exist. This script does not call Trusty, network,
load inference libraries or change Android state. Numeric config fields remain
field-numbered because the slim Java proto omits much of the native schema.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
from decode_factory_metadata import fields, summary_bytes


def structure(data, depth=0):
    if depth > 12:
        return summary_bytes(data)
    out = []
    for number, wire, value in fields(data):
        entry = {'field': number, 'wire': wire}
        if not isinstance(value, bytes):
            entry['value'] = value
        else:
            try:
                text = value.decode('utf-8')
                printable = bool(text) and len(text) <= 512 and all(32 <= ord(c) < 127 for c in text)
            except UnicodeError:
                printable = False
            if printable:
                entry['text'] = text
            else:
                try:
                    entry['message'] = structure(value, depth + 1)
                except ValueError:
                    entry['opaque'] = summary_bytes(value)
        out.append(entry)
    return out


def one(data, number, default=None):
    values = [v for n, _, v in fields(data) if n == number]
    if len(values) > 1:
        raise ValueError('expected singular metadata field')
    return values[0] if values else default


def inspect(checkpoint_path, config_path, manifest_path, factory_root):
    config = config_path.read_bytes()
    checkpoint = checkpoint_path.read_bytes()
    result = {'config': {'path': str(config_path), **summary_bytes(config), 'field_structure': structure(config)},
              'checkpoint': {'path': str(checkpoint_path), **summary_bytes(checkpoint)},
              'schema_note': 'Native field semantics are partly inferred from matching byte ranges. Slim installed Java schema only covers a subset.'}
    c = result['checkpoint']
    c['scalar_and_small_metadata'] = []
    c['external_files'] = []
    c['parameter_slices'] = []
    for n, w, v in fields(checkpoint):
        if n == 2:
            counts = collections.Counter((fn, fw) for fn, fw, _ in fields(v))
            c['field_2_embedded_tokenizer_candidate'] = {**summary_bytes(v),
                'direct_field_counts': {f'{fn}:{fw}': count for (fn, fw), count in counts.items()},
                'pieces_exported': False}
        elif n == 3:
            name = one(v, 1).decode('utf-8')
            c['external_files'].append(name)
        elif n == 4:
            c['parameter_slices'].append({
                'tensor_name': one(v, 1).decode('utf-8'), 'file_index': one(v, 2, 0),
                'offset': one(v, 3, 0), 'bytes': one(v, 4, 0)})
        elif n == 5:
            c['field_5_identity_bytes'] = summary_bytes(v)
        elif isinstance(v, bytes):
            c['scalar_and_small_metadata'].append({'field': n, 'wire': w, 'message': structure(v)})
        else:
            c['scalar_and_small_metadata'].append({'field': n, 'wire': w, 'value': v})
    c['external_file_coverage'] = []
    for index, name in enumerate(c['external_files']):
        path = factory_root / name
        if not path.resolve().is_relative_to(factory_root.resolve()):
            raise ValueError('external metadata path escapes factory directory')
        slices = sorted((s for s in c['parameter_slices'] if s['file_index'] == index), key=lambda s: s['offset'])
        end = 0
        contiguous = True
        for s in slices:
            contiguous &= s['offset'] == end
            end = s['offset'] + s['bytes']
        size = path.stat().st_size if path.is_file() else None
        c['external_file_coverage'].append({'name': name, 'disk_bytes': size, 'range_end': end,
                                            'contiguous_from_zero': contiguous,
                                            'exact_disk_size_match': size == end and contiguous})
    manifest = json.loads(manifest_path.read_text())
    records = [r for g in manifest['preload_file_groups'] for r in g['files']]
    matches = []
    for name, data in (('config.binarypb', config), ('checkpoint.binarypb', checkpoint)):
        r = next(r for r in records if r['mapped_factory_filename'] == name)
        digest = hashlib.sha1(data).hexdigest()
        matches.append({'name': name, 'actual_bytes': len(data), 'actual_sha1': digest,
                        'manifest_byte_size_match': r['byte_size'] == [len(data)],
                        'manifest_sha1_match': r['checksum'] == [digest]})
    result['manifest_consistency'] = matches
    result['manifest_absent_factory_files'] = [r for r in records if not r['factory_exists']]
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--decoded-dir', type=Path, default=Path('/data/local/tmp/ostadix-nano-rebuild-20260917'))
    ap.add_argument('--manifest-json', type=Path, default=Path(__file__).with_name('manifest-decoded-metadata.json'))
    args = ap.parse_args()
    for name in ('checkpoint', 'config'):
        if (args.decoded_dir / f'{name}.decoded.pb').stat().st_size > 16 * 1024 * 1024:
            raise SystemExit('metadata size limit exceeded')
    print(json.dumps(inspect(args.decoded_dir / 'checkpoint.decoded.pb', args.decoded_dir / 'config.decoded.pb',
                             args.manifest_json, Path('/data/vendor/intelligence')), indent=2))


if __name__ == '__main__':
    main()
