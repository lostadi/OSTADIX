"""Original-kernel container admission and production native MMIO guards."""

import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("original_plan9_probe", ROOT / "scripts/probe_okernel_plan9.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class OriginalKernelAdmissionTests(unittest.TestCase):
    def container(self, payload=b"original kernel fixture", **changes):
        values = dict(magic=0x27051956, crc=0, timestamp=1793431073, size=len(payload), load=0x40100000,
                      entry=0x40100000, data_crc=zlib.crc32(payload), os_id=23, arch=22, kind=2, compression=0)
        values.update(changes)
        header = struct.pack(">7I4B32s", *values.values(), b"9qemu")
        header = header[:4] + struct.pack(">I", zlib.crc32(header)) + header[8:]
        return header + payload

    def test_exact_plan9_arm64_uimage_contract_and_crcs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "9qemu.u"
            path.write_bytes(self.container())
            metadata, payload = probe.inspect_uimage(path)
            self.assertEqual(metadata["entry"], 0x40100000)
            self.assertEqual(payload, b"original kernel fixture")
            for change in ({"entry": 0x40080000}, {"load": 0x40080000}, {"os_id": 5}, {"arch": 2},
                           {"compression": 1}, {"kind": 3}, {"size": 0xffffffff}):
                path.write_bytes(self.container(**change))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    probe.inspect_uimage(path)
            for offset in (0, 8, 40, 64):
                data = bytearray(self.container()); data[offset] ^= 1; path.write_bytes(data)
                with self.subTest(corruption=offset), self.assertRaises(ValueError):
                    probe.inspect_uimage(path)
            for length in (0, 4, 63):
                path.write_bytes(self.container()[:length])
                with self.subTest(truncated=length), self.assertRaises(ValueError):
                    probe.inspect_uimage(path)

    def test_derived_kernel_requires_exact_original_build_and_patch_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            kernel = output / "candidate.u"
            kernel.write_bytes(self.container())
            with self.assertRaisesRegex(ValueError, "official build12115 kernel pin"):
                probe.prepare_kernel(kernel, output, {})
            receipt = output / "derivation.json"
            receipt.write_text(json.dumps({"schema": "ostadix.original9front-native-builder/v1",
                                          "passed": True, "byte_identical": True, "source_commit": probe.COMMIT,
                                          "controller_source": {"sha256": "unadmitted-builder"}}))
            with self.assertRaisesRegex(ValueError, "admitted original build recipe"):
                probe.admit_derivation(receipt, probe.identity(kernel))


HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
extern uint64_t p9_probe_init(void),p9_probe_exit(uintptr_t,uint64_t,uint64_t,uint64_t);
static jmp_buf stopped;
static uint64_t frame[34],counter=1000,namespace_profile=0;
static unsigned saw_busy,saw_idle;
static uint8_t output[4096];static size_t output_length;
static uint64_t inputs[8];static unsigned input_at,input_count;
void p9_serial_putc(uint64_t byte) { assert(output_length<sizeof output);output[output_length++]=(uint8_t)byte; }
uint64_t p9_serial_try_read(void) { return input_at<input_count?inputs[input_at++]:0; }
void p9_serial_init(void) {}
uint64_t p9_counter_read(void) { return counter; }
uint64_t p9_counter_frequency(void) { return 62500000; }
uint64_t p9_namespace_enabled(void) { return namespace_profile; }
void p9_memory_barrier(void) {
    __sync_synchronize();
    if(namespace_profile) { if(*(uint64_t *)0x6d000008==1)saw_busy=1;else if(*(uint64_t *)0x6d000008==0)saw_idle=1; }
}
__attribute__((noreturn)) void p9_halt(void) { longjmp(stopped,1); }
static void map(uintptr_t p,size_t n) { assert(mmap((void *)p,n,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)!=MAP_FAILED); }
static uint64_t access32(uint64_t ipa,int writing,uint64_t value) {
    memset(frame,0,sizeof frame);frame[0]=value;frame[31]=0x40101234;
    uint64_t esr=UINT64_C(0x93800006)|(writing?64:0);
    assert(p9_probe_exit((uintptr_t)frame,esr,ipa,(ipa&~UINT64_C(4095))>>8)==0);
    assert(frame[31]==0x40101238);return frame[0];
}
static void denied(uint64_t ipa,int writing) {
    uint8_t original[65536];memcpy(original,(void *)0x080a0000,sizeof original);
    if(!setjmp(stopped)) { access32(ipa,writing,0xffffffff);assert(!"ungranted MMIO accepted"); }
    assert(!memcmp(original,(void *)0x080a0000,sizeof original));
}
int main(void) {
    map(0x08000000,65536);map(0x080a0000,65536);map(0x48000000,4096);map(0x6d000000,4096);
    memset((void *)0x080a0000,0xcc,65536);*(uint32_t *)0x080a0000=0;
    *(uint32_t *)0x48000000=0xedfe0dd0;*(uint64_t *)0x6d000000=1793620000;
    assert(p9_probe_init()==1);
    // Synthetic RD registers cannot disclose or program physical LPI tables.
    assert(access32(0x080a0000,0,0)==0);
    assert(access32(0x080a0004,0,0)==0x43b);
    assert(access32(0x080a0008,0,0)==0x10);
    assert(access32(0x080a000c,0,0)==0);
    assert(access32(0x080a0014,0,0)==0);
    const uint32_t offsets[]={0,4,8,12,0x14,0x40,0x48,0x70,0x78,0xa0,0xb0,0xc0,0xfffc};
    for(unsigned i=0;i<sizeof offsets/sizeof *offsets;i++)denied(0x080a0000+offsets[i],1);
    const uint32_t readable_denied[]={0x40,0x48,0x70,0x78,0xa0,0xb0,0xc0,0xfffc};
    for(unsigned i=0;i<sizeof readable_denied/sizeof *readable_denied;i++)denied(0x080a0000+readable_denied[i],0);
    counter+=62500000*3;assert(access32(0x09010000,0,0)==1793620003);
    denied(0x09010000,1);denied(0x09010004,0);
    assert(access32(0x3f000000,0,0)==0xffffffff);denied(0x3f000000,1);denied(0x0a000000,0);denied(0x6c000000,1);
    denied(0x09001000,1); // Namespace UART has no default-profile authority.
    // Real UART input keeps NUL distinct from no character.
    inputs[0]=0x141;inputs[1]=0x100;input_count=2;input_at=0;
    access32(0x09000038,1,0x50);assert(*(uint32_t *)0x08000204==2);
    assert((access32(0x09000018,0,0)&0x10)==0);
    assert(access32(0x09000000,0,0)=='A' && access32(0x09000000,0,0)==0);
    assert((access32(0x09000018,0,0)&0x10)!=0 && *(uint32_t *)0x08000284==2);
    // HVC ELR already points after the call; HCR.TSC SMC ELR does not.
    memset(frame,0,sizeof frame);frame[0]=0x84000000;frame[31]=0x40102000;
    assert(p9_probe_exit((uintptr_t)frame,UINT64_C(0x16)<<26,0,0)==0 && frame[0]==2 && frame[31]==0x40102000);
    frame[0]=0x84000000;
    assert(p9_probe_exit((uintptr_t)frame,UINT64_C(0x17)<<26,0,0)==0 && frame[0]==2 && frame[31]==0x40102004);
    // The optional facade routes real binary 9P through the native store,
    // raises only IRQ50 and returns only outside a native transaction.
    map(0x6c000000,16*1024*1024);namespace_profile=1;
    *(uint64_t *)0x6d000000=23;*(uint64_t *)0x6d000008=0;*(uint64_t *)0x6d000010=1793620000;
    assert(p9_probe_init()==1 && *(uint64_t *)0x6d000008==0);
    assert((access32(0x09001018,0,0)&0x10)!=0);
    access32(0x0900102c,1,0x70);access32(0x09001038,1,0x50);access32(0x09001030,1,0x301);
    const uint8_t version[]={19,0,0,0,100,0xff,0xff,0,32,0,0,6,0,'9','P','2','0','0','0'};
    for(unsigned i=0;i<sizeof version;i++) {access32(0x09001000,1,version[i]);assert(*(uint64_t *)0x6d000008==0);}
    assert(*(uint32_t *)0x08000204==0x40000);
    uint8_t response[19];for(unsigned i=0;i<sizeof response;i++)response[i]=access32(0x09001000,0,0);
    assert(response[0]==19 && response[4]==101 && response[5]==0xff && !memcmp(response+13,"9P2000",6));
    assert(saw_busy && saw_idle && *(uint64_t *)0x6d000008==0);
    // Component reset recovery is not production-profile recovery: malformed
    // 9P causes a terminal monitor rejection, and even a subsequent test-host
    // attempt to write CR is rejected before the component can reacquire.
    if(!setjmp(stopped)) {
        access32(0x09001000,1,6);access32(0x09001000,1,0);
        access32(0x09001000,1,0);access32(0x09001000,1,0);
        assert(!"malformed frame escaped production fail-stop");
    }
    assert(*(uint64_t *)0x6d000008==1);
    if(!setjmp(stopped)) { access32(0x09001030,1,0x301);assert(!"guest reset escaped terminal monitor state"); }
    assert(*(uint64_t *)0x6d000008==1);
    puts("production Plan9 MMIO/LPI/ELR and optional native9P/quiescence guards: PASS");return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native fixture requires Linux x86_64")
class NativePlatformGuardTests(unittest.TestCase):
    def test_real_native_lpi_ownership_guards_and_return_pc(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang required")
        with tempfile.TemporaryDirectory(prefix="ocore-plan9-guards-") as directory:
            output = Path(directory)
            (output / "fixture.c").write_text(HARNESS)
            source = str(ROOT / "ocore/runtime/aarch64/plan9_probe.oc")
            sources = [str(ROOT / name) for name in ("ocore/runtime/common/namespace_store.oc",
                       "ocore/runtime/common/namespace_peer.oc", "ocore/runtime/aarch64/plan9_namespace_uart.oc")]
            sources.append(source)
            commands = [
                [str(compiler), *sources, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(output / "arm.mir")],
                [str(compiler), *sources, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(output / "probe.o")],
                [clang, "-O2", "-no-pie", str(output / "fixture.c"), str(output / "probe.o"), "-o", str(output / "selftest")],
                [str(output / "selftest")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
