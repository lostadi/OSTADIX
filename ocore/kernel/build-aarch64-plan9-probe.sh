#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${OCORE_PLAN9_BUILD_DIR:?set OCORE_PLAN9_BUILD_DIR to a new isolated build directory}"
OCOREC="${OCORE_PLAN9_OCOREC_BIN:-$ROOT/target/debug/ocorec}"
LLD="${OCORE_PLAN9_LLD:-ld.lld}"
NAMESPACE="${OCORE_PLAN9_NAMESPACE:-0}"
[[ "$NAMESPACE" == 0 || "$NAMESPACE" == 1 ]] || { echo 'OCORE_PLAN9_NAMESPACE must be 0 or 1' >&2; exit 2; }
platform_flags=()
if [[ "$NAMESPACE" == 1 ]]; then platform_flags+=(-DP9_NAMESPACE); fi
for tool in clang dtc python3 "$LLD"; do
    command -v "$tool" >/dev/null || { echo "missing Plan9 probe build tool: $tool" >&2; exit 2; }
done
[[ -x "$OCOREC" ]] || { echo "missing already-built O-core compiler: $OCOREC" >&2; exit 2; }
[[ ! -e "$BUILD" ]] || { echo 'Plan9 probe build directory must be new' >&2; exit 2; }
mkdir -p "$BUILD"
"$OCOREC" "$ROOT/ocore/runtime/common/namespace_store.oc" "$ROOT/ocore/runtime/common/namespace_peer.oc" \
    "$ROOT/ocore/runtime/aarch64/plan9_namespace_uart.oc" "$ROOT/ocore/runtime/aarch64/plan9_probe.oc" --target aarch64-unknown-none \
    --emit obj --keep-asm -o "$BUILD/kernel.o"
clang -target aarch64-unknown-none-elf -ffreestanding -fno-stack-protector \
    "${platform_flags[@]}" \
    -c "$ROOT/ocore/kernel/aarch64/plan9_probe/monitor.S" -o "$BUILD/monitor.o"
"$LLD" -m aarch64elf -nostdlib --build-id=none -z max-page-size=0x1000 \
    -T "$ROOT/ocore/kernel/aarch64/plan9_probe/linker.ld" \
    -o "$BUILD/monitor.elf" "$BUILD/monitor.o" "$BUILD/kernel.o"
dtc -I dts -O dtb -o "$BUILD/guest.dtb" "$ROOT/ocore/kernel/aarch64/plan9_probe/guest.dts"
python3 - "$ROOT" "$BUILD" "$NAMESPACE" "$OCOREC" "$LLD" <<'PY'
import hashlib
import json
from pathlib import Path
import shutil
import sys
root, build = map(Path, sys.argv[1:3])
namespace = sys.argv[3] == "1"
def identity(path):
    return {"path": str(path.resolve()), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
source = ("ocore/runtime/aarch64/plan9_probe.oc", "ocore/kernel/aarch64/plan9_probe/monitor.S",
          "ocore/kernel/aarch64/plan9_probe/linker.ld", "ocore/kernel/aarch64/plan9_probe/guest.dts",
          "ocore/kernel/build-aarch64-plan9-probe.sh", "ocore/runtime/common/namespace_store.oc",
          "ocore/runtime/common/namespace_peer.oc", "ocore/runtime/aarch64/plan9_namespace_uart.oc")
manifest = {
    "schema": "ostadix.original-plan9-isolated-monitor/v1",
    "scope": "single original Plan9 kernel at EL1 beneath native O-core EL2; no default-OS replacement or shared namespace mount qualification",
    "profile": "native-namespace" if namespace else "original-serial-only",
    "guest_ram": {"ipa": 0x40000000, "pa": 0x48000000, "bytes": 0x20000000},
    "loader_addresses": {"dtb": 0x48000000, "kernel": 0x48100000},
    "kernel_entry_ipa": 0x40100000,
    "gic_assignment": {"version": 3, "distributor": [0x08000000, 0x08010000],
                       "redistributor_sgi_ppi": [0x080b0000, 0x080c0000],
                       "redistributor_rd": {"ipa": [0x080a0000, 0x080b0000], "transport": "native read-only fixed register facade",
                                            "read32_offsets": [0, 4, 8, 12, 20], "writes": "denied", "lpi_authority": False},
                       "its": False, "scope": "one emulated interrupt controller, no LPI table DMA grant"},
    "uart": {"ipa": 0x09000000, "bytes": 4096, "irq": 33, "transport": "native O-core mediated PL011"},
    "rtc": {"ipa": 0x09010000, "bytes": 4, "access": "read-only PL031 data register",
            "private_unix_floor_address": 0x6d000010 if namespace else 0x6d000000, "clock": "trusted Unix-second floor plus native counter elapsed time"},
    "pci": "empty configuration bus; no device, BAR, disk, network or DMA assignment",
    "artifacts": {name: {**identity(build / name), "path": name} for name in ("monitor.elf", "guest.dtb")},
    "tools": {name: identity(Path(shutil.which(command) or command))
              for name, command in (("ocorec", sys.argv[4]), ("clang", "clang"), ("lld", sys.argv[5]), ("dtc", "dtc"))},
    "source_sha256": {name: identity(root / name)["sha256"] for name in source},
}
if namespace:
    manifest["scope"] = "isolated original Plan9 ABI with a frozen fork of the native namespace; no default-OS mutation or simultaneous domain claim"
    manifest["namespace_grant"] = {"address": 0x6c000000, "bytes": 16 * 1024 * 1024,
                                   "epoch_address": 0x6d000000, "quiescence_address": 0x6d000008,
                                   "clock_address": 0x6d000010, "plan9_grant": 4, "native_peer_grant": 2,
                                   "uart": {"ipa": 0x09001000, "bytes": 4096, "irq": 50},
                                   "dma": False}
(build / "monitor-profile.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY
printf 'Original Plan9 isolated monitor: %s\n' "$BUILD/monitor.elf"
