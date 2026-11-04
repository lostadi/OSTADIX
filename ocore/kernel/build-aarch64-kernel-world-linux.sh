#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${OCORE_LINUX_BUILD_DIR:-$ROOT/target/ocore-real-linux/monitor}"
PAYLOAD="${OCORE_LINUX_PAYLOAD_DIR:-$ROOT/target/ocore-real-linux/payload}"
OCOREC="${OCORE_LINUX_OCOREC_BIN:-$ROOT/target/debug/ocorec}"
LLD="${OCORE_LINUX_LLD:-ld.lld}"
PROFILE="${OCORE_LINUX_PROFILE:-withdrawal}"
BACKING_BYTES="${OCORE_LINUX_BACKING_BYTES:-536870912}"
NETWORK="${OCORE_LINUX_NETWORK:-0}"
NAMESPACE="${OCORE_LINUX_NAMESPACE:-0}"
NATIVE_9P_MANIFEST="${OCORE_LINUX_NATIVE_9P_MANIFEST:-}"
case "$PROFILE" in
    withdrawal) PACKAGE_PROFILE=0 ;;
    package-domain) PACKAGE_PROFILE=1 ;;
    *) echo 'OCORE_LINUX_PROFILE must be withdrawal or package-domain' >&2; exit 2 ;;
esac
if [[ "$NETWORK" != 0 && "$NETWORK" != 1 ]] \
    || [[ "$NETWORK" == 1 && "$PROFILE" != package-domain ]]; then
    echo 'OCORE_LINUX_NETWORK must be 0 or 1; 1 requires package-domain profile' >&2
    exit 2
fi
if [[ "$NAMESPACE" != 0 && "$NAMESPACE" != 1 ]] \
    || [[ "$NAMESPACE" == 1 && "$PROFILE" != package-domain ]]; then
    echo 'OCORE_LINUX_NAMESPACE must be 0 or 1; 1 requires package-domain profile' >&2
    exit 2
fi
if [[ -n "$NATIVE_9P_MANIFEST" && ( "$NAMESPACE" != 1 || "$PROFILE" != package-domain ) ]]; then
    echo 'OCORE_LINUX_NATIVE_9P_MANIFEST requires namespace=1 and package-domain profile' >&2
    exit 2
fi
if [[ ! "$BACKING_BYTES" =~ ^[0-9]+$ ]] \
    || (( BACKING_BYTES == 0 || BACKING_BYTES > 1073741824 || BACKING_BYTES % 4096 != 0 )); then
    echo 'OCORE_LINUX_BACKING_BYTES must be page-aligned and within 1..1073741824' >&2
    exit 2
fi
for tool in clang dtc python3 "$LLD"; do
    command -v "$tool" >/dev/null || { echo "missing monitor build tool: $tool" >&2; exit 2; }
done
[[ -x "$OCOREC" ]] || { echo "missing already-built compiler: $OCOREC" >&2; exit 2; }
mkdir -p "$BUILD"
NAMESPACE_PEER_SOURCES=("$ROOT/ocore/runtime/common/namespace_peer.oc")
NATIVE_9P_OBJECTS=()
if [[ -n "$NATIVE_9P_MANIFEST" ]]; then
    python3 "$ROOT/scripts/okernel_native_codec.py" --manifest "$NATIVE_9P_MANIFEST" \
        --build "$BUILD" --isa aarch64 > "$BUILD/native-9p.objects"
    mapfile -d '' -t NATIVE_9P_OBJECTS < "$BUILD/native-9p.objects"
    NAMESPACE_PEER_SOURCES=("$ROOT/ocore/runtime/common/u9fs_codec.oc" \
        "$ROOT/ocore/runtime/common/u9fs_namespace_peer.oc")
fi
python3 - "$PAYLOAD" "$ROOT/ocore/kernel/aarch64/kernel_world/guest.dts" "$BUILD/guest.dts" "$PROFILE" "$NETWORK" "$NAMESPACE" <<'PY'
import hashlib
import json
from pathlib import Path
import struct
import sys

payload, template, output = map(Path, sys.argv[1:4])
profile = sys.argv[4]
network = sys.argv[5] == "1"
namespace = sys.argv[6] == "1"
manifest = json.loads((payload / "linux-payload.json").read_text())
if manifest.get("profile", "withdrawal") != profile:
    raise SystemExit("Linux payload profile does not match OCORE_LINUX_PROFILE")
if manifest["linux_version"] != "6.12.43" or manifest["source_modifications"] is not False:
    raise SystemExit("unexpected pinned Linux payload identity")
if manifest["source_archive_sha256"] != "0fcbbbbcd456e87bbbfc8bf37af541fda62ccfcce76903503424fd101ef7bdee":
    raise SystemExit("unexpected upstream source digest")
image = (payload / "Image").read_bytes()
if len(image) != manifest["artifacts"]["Image"]["bytes"] or hashlib.sha256(image).hexdigest() != manifest["artifacts"]["Image"]["sha256"]:
    raise SystemExit("Linux Image differs from payload manifest")
offset, size = struct.unpack_from("<QQ", image, 8)
if image[56:60] != b"ARM\x64" or offset != 0 or not 0 < size <= 0x07000000:
    raise SystemExit("Linux Image exceeds the bounded direct-boot layout")
initrd_size = (payload / "initramfs.cpio").stat().st_size
if not 0 < initrd_size <= 0x08000000:
    raise SystemExit("initramfs exceeds its 128MiB payload window")
network_device = ""
if network:
    network_device = '''virtio_mmio@a000200 {
        compatible = "virtio,mmio";
        reg = <0 0x0a000200 0 0x200>;
        interrupts = <0 17 4>;
        dma-coherent;
    };'''
namespace_device = '''virtio_mmio@a000400 {
        compatible = "virtio,mmio";
        reg = <0 0x0a000400 0 0x200>;
        interrupts = <0 18 4>;
        dma-coherent;
    };''' if namespace else ""
output.write_text(template.read_text().replace("INITRD_END", hex(0x48000000 + initrd_size)).replace("NETWORK_DEVICE", network_device).replace("NAMESPACE_DEVICE", namespace_device))
PY
dtc -I dts -O dtb -o "$BUILD/guest.dtb" "$BUILD/guest.dts"
cat > "$BUILD/profile.oc" <<EOF
module runtime::aarch64::kernel_world_profile;
pub const PERSISTENT: u64 = $PACKAGE_PROFILE;
pub const BACKING_BASE: usize = 0x7000_0000;
pub const BACKING_BYTES: usize = $BACKING_BYTES;
pub const NETWORK: u64 = $NETWORK;
pub const NAMESPACE: u64 = $NAMESPACE;
EOF
"$OCOREC" \
    "$BUILD/profile.oc" \
    "$ROOT/ocore/runtime/aarch64/kernel_world_monitor.oc" \
    "$ROOT/ocore/runtime/aarch64/kernel_world_virtio.oc" \
    "$ROOT/ocore/runtime/aarch64/kernel_world_virtio_selftest.oc" \
    "$ROOT/ocore/runtime/aarch64/kernel_world_net_host.oc" \
    "$ROOT/ocore/runtime/aarch64/kernel_world_net.oc" \
    "$ROOT/ocore/runtime/aarch64/kernel_world_9p.oc" \
    "$ROOT/ocore/runtime/common/namespace_store.oc" \
    "${NAMESPACE_PEER_SOURCES[@]}" \
    --target aarch64-unknown-none --emit obj --keep-asm -o "$BUILD/kernel.o"
clang -target aarch64-unknown-none-elf -ffreestanding -fno-stack-protector \
    -DKW_PACKAGE_PROFILE="$PACKAGE_PROFILE" \
    -c "$ROOT/ocore/kernel/aarch64/kernel_world/monitor.S" -o "$BUILD/monitor.o"
"$LLD" -m aarch64elf -nostdlib --build-id=none -z max-page-size=0x1000 \
    -T "$ROOT/ocore/kernel/aarch64/kernel_world/linker.ld" \
    -o "$BUILD/monitor.elf" "$BUILD/monitor.o" "$BUILD/kernel.o" "${NATIVE_9P_OBJECTS[@]}"
python3 - "$BUILD" "$PROFILE" "$BACKING_BYTES" "$PAYLOAD" "$ROOT" "$NETWORK" "$NAMESPACE" "$NATIVE_9P_MANIFEST" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

build, profile, backing_bytes, payload = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), Path(sys.argv[4])
root = Path(sys.argv[5])
network = sys.argv[6] == "1"
namespace = sys.argv[7] == "1"
native_codec = bool(sys.argv[8])
peer_sources = ("ocore/runtime/common/u9fs_codec.oc", "ocore/runtime/common/u9fs_namespace_peer.oc", "scripts/okernel_native_codec.py") if native_codec else ("ocore/runtime/common/namespace_peer.oc",)
paths = {
    "monitor": build / "monitor.elf", "guest_dtb": build / "guest.dtb",
    "profile": build / "profile.oc", "Image": payload / "Image",
    "initramfs": payload / "initramfs.cpio",
}
manifest = {
    "schema": "ostadix.kernel-world-linux-monitor/v1",
    "profile": profile,
    "backing_base": 0x70000000 if profile == "package-domain" else 0,
    "backing_bytes": backing_bytes if profile == "package-domain" else 0,
    "network_grant": {
        "enabled": network,
        "mac": "52:54:00:12:34:56" if network else None,
        "transport": "O-core mediated virtio-mmio Ethernet" if network else None,
        "guest_mmio": 0x0a000200 if network else None,
        "guest_irq": 49 if network else None,
        "host_dma_base": 0x6e000000 if network else None,
        "host_dma_limit": 0x6e200000 if network else None,
    },
    "namespace_grant": {
        "enabled": namespace,
        "transport": "native O-core 9P2000 over virtio-mmio" if namespace else None,
        "guest_mmio": 0x0a000400 if namespace else None,
        "guest_irq": 50 if namespace else None,
        "mount_tag": "okernel" if namespace else None,
        "address": 0x6c000000 if namespace else None,
        "bytes": 0x01000000 if namespace else None,
        "epoch_address": 0x6d000000 if namespace else None,
        "quiescence_address": 0x6d000008 if namespace else None,
        "clock_address": 0x6d000010 if namespace else None,
        "linux_grant": 1 if namespace else None,
        "native_peer_grant": 2 if namespace else None,
    },
    "guest_ram_ipa": 0x40000000,
    "guest_ram_pa": 0x48000000,
    "guest_ram_bytes": 0x20000000,
    "loader_addresses": {"Image": 0x48000000, "guest_dtb": 0x4fe00000, "initramfs": 0x50000000},
    "block_backing": {"address": 0x70000000, "bytes": backing_bytes} if profile == "package-domain" else None,
    "outer_ram_bytes": 0x80000000 if profile == "package-domain" else 0x40000000,
    "artifacts": {
        name: {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for name, path in paths.items()
    },
    "source_sha256": {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in (
            "ocore/runtime/aarch64/kernel_world_monitor.oc",
            "ocore/runtime/aarch64/kernel_world_virtio.oc",
            "ocore/runtime/aarch64/kernel_world_virtio_selftest.oc",
            "ocore/runtime/aarch64/kernel_world_net_host.oc",
            "ocore/runtime/aarch64/kernel_world_net.oc",
            "ocore/runtime/aarch64/kernel_world_9p.oc",
            "ocore/runtime/common/namespace_store.oc",
            *peer_sources,
            "ocore/kernel/aarch64/kernel_world/monitor.S",
            "ocore/kernel/aarch64/kernel_world/guest.dts",
            "ocore/kernel/aarch64/kernel_world/linker.ld",
            "ocore/kernel/build-aarch64-kernel-world-linux.sh",
        )
    },
    "scope": "AArch64 EL2 monitor under QEMU; no physical-hardware qualification",
}
if native_codec:
    manifest["native_9p_codec"] = json.loads((build / "native-9p.json").read_text())
(build / "monitor-profile.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY
printf 'KernelWorld AArch64 monitor: %s\n' "$BUILD/monitor.elf"
