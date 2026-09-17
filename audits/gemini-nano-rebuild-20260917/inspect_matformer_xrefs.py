#!/usr/bin/env python3
"""Read-only adjacent AArch64 ADRP/ADD references to matformer strings."""
import array
import argparse
import hashlib
import json
import struct
from pathlib import Path

LIBRARY = Path('/data/local/tmp/ostadix-ai-audit-20260915/aicore-native/libgoogle3.so')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--needle', action='append', default=[])
    args = parser.parse_args()
    needles = [s.encode('ascii') for s in args.needle] or [b'matformer']
    data = LIBRARY.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('expected little-endian ELF64')
    shoff, = struct.unpack_from('<Q', data, 40)
    shsize, shnum, shstrings = struct.unpack_from('<HHH', data, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize)
                for i in range(shnum)]
    strings_section = sections[shstrings]
    names = data[strings_section[4]:strings_section[4] + strings_section[5]]
    by_name = {names[s[0]:].split(b'\0', 1)[0].decode(): s for s in sections}
    ro = by_name['.rodata']
    text = by_name['.text']
    targets = {}
    position = ro[4]
    end = position + ro[5]
    while position < end:
        stop = data.find(b'\0', position, end)
        if stop < 0:
            break
        value = data[position:stop]
        if any(needle in value for needle in needles) and len(value) < 512:
            try:
                targets[position - ro[4] + ro[3]] = value.decode('ascii')
            except UnicodeDecodeError:
                pass
        position = stop + 1
    words = array.array('I', data[text[4]:text[4] + text[5]])
    xrefs = []
    for i in range(len(words) - 1):
        instruction = words[i]
        if instruction & 0x9f000000 != 0x90000000:  # ADRP
            continue
        register = instruction & 31
        immediate = ((instruction >> 29) & 3) | (((instruction >> 5) & 0x7ffff) << 2)
        if immediate & (1 << 20):
            immediate -= 1 << 21
        pc = text[3] + i * 4
        page = (pc & ~4095) + (immediate << 12)
        following = words[i + 1]
        if following & 0xff000000 != 0x91000000 or (following >> 5) & 31 != register:
            continue
        offset = ((following >> 10) & 4095) << (12 if following & (1 << 22) else 0)
        address = page + offset
        if address in targets:
            xrefs.append({'adrp_pc': hex(pc), 'add_pc': hex(pc + 4),
                          'string_address': hex(address), 'string': targets[address]})
    print(json.dumps({'library': str(LIBRARY), 'sha256': hashlib.sha256(data).hexdigest(),
                      'limitation': 'Adjacent ADRP/ADD only; absence is not proof of no reference.',
                      'strings': {hex(k): v for k, v in targets.items()}, 'xrefs': xrefs}, indent=2))


if __name__ == '__main__':
    main()
