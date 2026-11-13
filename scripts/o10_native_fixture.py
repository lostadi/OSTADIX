"""Fixed boot-image and observation contract for the M3 native EL1 guest."""
from __future__ import annotations

import struct

NAME = b"o10-m3-witness"
CORPUS = b"O10_M3_NATIVE_NAMESPACE\n"
CONTRACT = {
    "schema": "ostadix.o10-m3-native-fixture/v1",
    "kind": 3, "kernel_image": 5, "aux_image": 6,
    "memory_bytes": 0x200000, "vcpus": 1,
    "private_ram_pa": 0xe2200000, "ram_ipa": 0x40000000,
    "entry": 0x40000000, "x0": 0x40100000,
    "stack_bottom": 0x401f1000, "stack_top": 0x40200000,
    "kernel_backup_pa": 0xe2400000, "kernel_max_bytes": 0x100000,
    "aux_backup_pa": 0xe2500000, "aux_bytes": 128,
    "kernel_bytes_address": 0x6d000120, "aux_bytes_address": 0x6d000128,
    "heartbeat_ipa": 0x401f0000, "heartbeat_bytes": 64,
    "namespace_uart_ipa": 0x09001000, "transport": 0, "irq": 50,
    "baseline_grant": 3, "namespace_root": "/work",
    "corpus_name": NAME.decode(), "corpus_text": CORPUS.decode(),
    "error_trap": "BRK #0x10",
}
ERRORS = {
    1: "invalid immutable auxiliary image", 2: "UART transmit timeout",
    3: "UART receive timeout", 4: "malformed or unexpected 9P reply",
    5: "namespace store Rerror", 6: "namespace corpus mismatch",
    7: "local framing overflow", 8: "observation counter exhausted",
}


def auxiliary_image() -> bytes:
    data = bytearray(128)
    struct.pack_into("<8sIIQQII", data, 0, b"O10M3N1\0", 1, 128,
                     CONTRACT["heartbeat_ipa"], CONTRACT["namespace_uart_ipa"],
                     len(NAME), len(CORPUS))
    data[40:40 + len(NAME)] = NAME
    data[72:72 + len(CORPUS)] = CORPUS
    return bytes(data)


def decode_heartbeat(raw: bytes) -> dict:
    if len(raw) != 64:
        raise ValueError("native heartbeat must be exactly64 bytes")
    magic, seq, reads, error, reply, count, stage, tag = struct.unpack("<8s7Q", raw)
    if magic != b"O10M3HB1" or stage not in (1, 2, 3, 4):
        raise ValueError("native heartbeat is not initialized")
    return {"seq": seq, "stable": not bool(seq & 1), "reads": reads,
            "error": error, "error_name": ERRORS.get(error, "" if error == 0 else "unknown"),
            "last_reply_type": reply, "last_bytes": count, "stage": stage,
            "last_tag": tag}
