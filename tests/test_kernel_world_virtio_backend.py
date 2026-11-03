"""Execute the production O-core virtio backend and adversarial native tests.

The host fixture supplies only memory translation, IRQ signaling and barriers.
The actual queue parser, block copies, feature negotiation and tests are
compiled from the same .oc modules linked into the AArch64 EL2 monitor.
"""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

uintptr_t kw_guest_address(uint64_t gpa, uint64_t length) {
    if (!length || gpa < 0x40000000ull || length > 0x20000000ull
        || gpa - 0x40000000ull > 0x20000000ull - length) return 0;
    return gpa + 0x08000000ull;
}
void kw_memory_barrier(void) { __sync_synchronize(); }
void kw_irq_level(uint64_t asserted) { (void)asserted; }
extern uint64_t _O_runtime__aarch64__kernel_world_virtio_selftest__run(uint64_t);
extern uint64_t _O_runtime__aarch64__kernel_world_virtio_selftest__run_backing(uint64_t, uintptr_t);
extern uint64_t _O_runtime__aarch64__kernel_world_virtio__configure_backing(uintptr_t,uintptr_t,uint64_t);
extern uint64_t _O_runtime__aarch64__kernel_world_virtio__init(uint64_t,uint64_t,uint64_t);
extern uint64_t _O_runtime__aarch64__kernel_world_virtio__mmio_read(uint64_t);

int main(void) {
    void *guest = mmap((void *)0x48000000ull, 0x20000000ull,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    void *backing = mmap((void *)0x6fff0000ull, 0x10000,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (guest == MAP_FAILED || backing == MAP_FAILED) { perror("isolated mmap"); return 2; }
    uint64_t readonly = _O_runtime__aarch64__kernel_world_virtio_selftest__run(0x5ff00000ull);
    if (readonly != 5) { fprintf(stderr, "readonly generation=%llu\n", (unsigned long long)readonly); return 3; }
    uint64_t writable = _O_runtime__aarch64__kernel_world_virtio_selftest__run_backing(0x5ff00000ull, 0x6fff0000ull);
    if (writable != 11) { fprintf(stderr, "backed generation=%llu\n", (unsigned long long)writable); return 4; }
    if (_O_runtime__aarch64__kernel_world_virtio__configure_backing(0x70000000,0x40001000,1)!=0
        || _O_runtime__aarch64__kernel_world_virtio__configure_backing(0xaffff000,8192,1)!=0
        || _O_runtime__aarch64__kernel_world_virtio__configure_backing(0xb0000000,4096,1)!=0
        || _O_runtime__aarch64__kernel_world_virtio__configure_backing(0x70000000,0x40000000,1)!=1
        || _O_runtime__aarch64__kernel_world_virtio__init(0x40000000,0x20000000,11)!=1
        || _O_runtime__aarch64__kernel_world_virtio__mmio_read(256)!=2097152
        || _O_runtime__aarch64__kernel_world_virtio__mmio_read(260)!=0) return 5;
    puts("historical readonly and backed block production selftests: PASS");
    return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "host execution fixture requires Linux x86_64; AArch64 boot runs the same selftests")
class KernelWorldVirtioBackendTests(unittest.TestCase):
    def test_production_block_backend_selftests(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="ocore-virtio-backend-") as directory:
            output = Path(directory)
            source = output / "memory-stubs.c"
            source.write_text(HARNESS)
            commands = [
                [str(compiler), str(ROOT / "ocore/runtime/aarch64/kernel_world_virtio.oc"),
                 str(ROOT / "ocore/runtime/aarch64/kernel_world_virtio_selftest.oc"),
                 "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(output / "block.o")],
                [clang, "-O2", "-no-pie", str(source), str(output / "block.o"), "-o", str(output / "selftest")],
                [str(output / "selftest")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("production selftests: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
