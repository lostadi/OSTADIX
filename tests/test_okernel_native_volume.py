"""Read production namespace snapshots; cross-check corruptions in O-core."""
import dataclasses
import importlib.util
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("okernel_native_volume", ROOT / "scripts/okernel_native_volume.py")
volume_module = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = volume_module
SPEC.loader.exec_module(volume_module)
Volume, VolumeError = volume_module.Volume, volume_module.VolumeError

C = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#define NS(n) _O_runtime__common__namespace_store__##n
extern uint64_t NS(init)(uintptr_t,size_t,uint64_t),NS(provision_clock)(uint64_t),NS(session_init)(uint64_t,uint64_t);
extern size_t NS(handle)(uint64_t,const uint8_t*,size_t,uint8_t*,size_t);
static uint8_t request[8192],response[8192],pattern[6000];static size_t pos;static uint64_t session;
static void put(uint64_t v,unsigned n){for(unsigned i=0;i<n;i++)request[pos++]=(uint8_t)(v>>(8*i));}
static void string(const char*s){size_t n=strlen(s);put(n,2);memcpy(request+pos,s,n);pos+=n;}
static void begin(unsigned kind){memset(request,0,sizeof(request));pos=7;request[4]=kind;request[5]=1;}
static void call(unsigned kind){for(unsigned i=0;i<4;i++)request[i]=(uint8_t)(pos>>(8*i));assert(NS(handle)(session,request,pos,response,sizeof(response))>=7&&response[4]==kind);}
static void walk(unsigned old,unsigned fresh,const char *name){begin(110);put(old,4);put(fresh,4);put(1,2);string(name);call(111);}
static void create(unsigned fid,const char *name,unsigned mode,unsigned access){begin(114);put(fid,4);string(name);put(mode,4);put(access,1);call(115);}
static void write_(unsigned fid,unsigned offset,const void*data,unsigned n){begin(118);put(fid,4);put(offset,8);put(n,4);memcpy(request+pos,data,n);pos+=n;call(119);}
int main(int argc,char**argv){
    assert(argc==3);void *data=mmap(NULL,16777216,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(data!=MAP_FAILED);
    if(!strcmp(argv[1],"check")){FILE*f=fopen(argv[2],"rb");assert(f&&fread(data,1,16777216,f)==16777216&&fgetc(f)==EOF);fclose(f);printf("%llu\n",(unsigned long long)NS(init)((uintptr_t)data,16777216,999));return 0;}
    assert((!strcmp(argv[1],"create")||!strcmp(argv[1],"create-temp"))&&NS(init)((uintptr_t)data,16777216,100)==1&&NS(provision_clock)(1700000000)==1);
    unsigned temporary=!strcmp(argv[1],"create-temp")?0x04000000:0;
    session=NS(session_init)(1,1);assert(session);begin(100);put(8192,4);string("9P2000");call(101);
    begin(104);put(1,4);put(UINT32_MAX,4);string("ignored");string("");call(105);
    walk(1,2,"work");create(2,"requests",0x800001ed|temporary,0);
    walk(1,3,"work");walk(3,4,"requests");create(4,"binary",0644|temporary,2);
    for(unsigned i=0;i<sizeof(pattern);i++)pattern[i]=(uint8_t)(i*19+7);
    write_(4,0,pattern,sizeof(pattern));write_(4,9000,"\0\21\23\377x",5);
    walk(1,5,"work");create(5,"raw-\xff",0644,2);write_(5,0,"raw",3);
    walk(1,6,"work");create(6,"empty",0644,2);
    walk(1,7,"work");create(7,"removed",0644,2);write_(7,0,"gone",4);begin(122);put(7,4);call(123);
    assert(NS(init)((uintptr_t)data,16777216,200)==1);
    FILE*f=fopen(argv[2],"wb");assert(f&&fwrite(data,1,16777216,f)==16777216&&!fclose(f));return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "production fixture requires Linux x86_64")
class NativeVolumeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            raise unittest.SkipTest("already-built ocorec and clang are required")
        cls.temporary = tempfile.TemporaryDirectory(prefix="native-volume-reader-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        (cls.directory / "fixture.c").write_text(C)
        cls.executable = cls.directory / "fixture"
        commands = [
            [str(compiler), str(ROOT / "ocore/runtime/common/namespace_store.oc"), "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(cls.directory / "store.o")],
            [clang, "-O2", "-no-pie", str(cls.directory / "fixture.c"), str(cls.directory / "store.o"), "-o", str(cls.executable)],
            [str(cls.executable), "create", str(cls.directory / "snapshot.raw")],
        ]
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
        cls.snapshot = (cls.directory / "snapshot.raw").read_bytes()

    def native_accepts(self, data):
        path = self.directory / "candidate.raw"
        path.write_bytes(data)
        result = subprocess.run([str(self.executable), "check", str(path)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout.strip() == "1"

    @staticmethod
    def offset(number):
        return 4096 + (number - 1) * 384

    def node(self, data, number, offset, value):
        start = self.offset(number)
        struct.pack_into("<Q", data, start + offset, value)
        struct.pack_into("<Q", data, start + 376, volume_module.fnv(data[start:start + 376]))

    def test_reads_actual_production_multiblock_sparse_binary_and_names(self):
        self.assertTrue(self.native_accepts(self.snapshot))
        volume = Volume.from_file(self.directory / "snapshot.raw")
        expected = bytes((i * 19 + 7) & 255 for i in range(6000)) + bytes(3000) + b"\0\x11\x13\xffx"
        self.assertEqual(volume.get("/work/requests/binary"), expected)
        self.assertEqual(volume.get(b"/work/raw-\xff"), b"raw")
        self.assertEqual(volume.get("/work/raw-\udcff"), b"raw")
        self.assertEqual(volume.get("/work/empty"), b"")
        self.assertEqual(volume.listdir("/work"), ("empty", "raw-\udcff", "requests"))
        self.assertEqual(volume.listdir("/work/requests"), ("binary",))
        self.assertEqual(volume.listdir(), ("build", "nativeREADME", "pkg", "services", "work"))
        self.assertEqual(volume.usage()["used_blocks"], 5)
        self.assertEqual(volume.usage()["tombstone_nodes"], 1)
        self.assertEqual(volume.usage()["file_bytes"], len(expected) + 3 + 163)
        self.assertEqual(volume.usage()["free_blocks"], 3994)

    def test_immutable_copy_and_lookup_failures(self):
        mutable = bytearray(self.snapshot)
        volume = Volume(mutable)
        mutable[:] = bytes(len(mutable))
        self.assertEqual(volume.get("/work/raw-\udcff"), b"raw")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            volume.clock = 0
        with self.assertRaises(TypeError):
            volume._children[(1, b"escape")] = 1
        for path in ("work", "/work/../services", "/work/./empty", "/work//empty", "/work/", "/work/\0"):
            with self.subTest(path=path), self.assertRaises(VolumeError):
                volume.get(path)
        with self.assertRaises(FileNotFoundError):
            volume.get("/work/removed")
        with self.assertRaises(IsADirectoryError):
            volume.get("/work")
        with self.assertRaises(NotADirectoryError):
            volume.get("/work/empty/child")
        with self.assertRaises(NotADirectoryError):
            volume.listdir("/work/empty")

    def test_actual_temporary_file_directory_snapshot_and_other_flags(self):
        path = self.directory / "temporary.raw"
        result = subprocess.run([str(self.executable), "create-temp", str(path)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = path.read_bytes()
        self.assertTrue(self.native_accepts(data))
        volume = Volume.from_file(path)
        self.assertEqual(volume._nodes[8].mode, 0x04000000 | 0o644)
        self.assertEqual(volume._nodes[7].mode, 0x840001ed)
        self.assertEqual(volume.get("/work/requests/binary"), Volume(self.snapshot).get("/work/requests/binary"))
        cleared = bytearray(data)
        self.node(cleared, 8, 32, 0o644)
        self.node(cleared, 7, 32, 0x800001ed)
        self.assertTrue(self.native_accepts(cleared))
        self.assertEqual(Volume(cleared).get("/work/requests/binary"), volume.get("/work/requests/binary"))
        # Accepting the compiler's archive hint must not accept append-only,
        # exclusive, authentication, device or other reserved mode semantics.
        for bit in range(9, 31):
            if bit == 26:
                continue
            unsupported = bytearray(data)
            self.node(unsupported, 8, 32, 0x04000000 | 0o644 | (1 << bit))
            with self.subTest(bit=bit):
                self.assertFalse(self.native_accepts(unsupported))
                with self.assertRaises(VolumeError):
                    Volume(unsupported)

    def test_rejects_header_clock_and_unused_state_corruptions_in_native_validator_too(self):
        for label, offset in (("magic", 0), ("layout", 16), ("header seal", 48), ("clock seal", 56), ("unused node", self.offset(1024) + 72), ("metadata seal", self.offset(8) + 72)):
            data = bytearray(self.snapshot)
            data[offset] ^= 1
            with self.subTest(label=label):
                self.assertFalse(self.native_accepts(data))
                with self.assertRaises(VolumeError):
                    Volume(data)
        for data in (b"", self.snapshot[:-1], self.snapshot + b"x", bytes(16777216)):
            with self.assertRaises(VolumeError):
                Volume(data)

    def test_resealed_metadata_corruptions_match_native_validator(self):
        # Actual production fixture IDs: requests7,binary8,raw9,empty10,removed11.
        changes = (("state", 8, 0, 3), ("generation zero", 8, 16, 0), ("generation range", 8, 16, 1 << 32),
                   ("version zero", 8, 24, 0), ("mode", 8, 32, 0x200), ("clock", 8, 56, 0xffffffff),
                   ("missing parent", 8, 8, 1024), ("file parent", 8, 8, 9), ("parent cycle", 7, 8, 7),
                   ("missing granted dir", 2, 0, 2), ("root parent", 1, 8, 2), ("root mode", 1, 32, 0o755),
                   ("directory length", 7, 40, 1), ("directory head", 7, 48, 1),
                   ("excess length", 8, 40, 3999 * 4088 + 1), ("missing chain", 8, 48, 0),
                   ("foreign chain", 8, 48, 4000), ("shared chain", 8, 48, 1),
                   ("empty trailing chain", 10, 48, 1), ("name length", 8, 64, 256),
                   ("tombstone generation", 11, 16, 0))
        for label, number, offset, value in changes:
            data = bytearray(self.snapshot)
            self.node(data, number, offset, value)
            with self.subTest(label=label):
                self.assertFalse(self.native_accepts(data))
                with self.assertRaises(VolumeError):
                    Volume(data)
        for name in (b"", b".", b"..", b"bad/name", b"nul\0name"):
            data = bytearray(self.snapshot)
            start = self.offset(8)
            data[start + 72:start + 328] = bytes(256)
            data[start + 72:start + 72 + len(name)] = name
            self.node(data, 8, 64, len(name))
            self.assertFalse(self.native_accepts(data))
            with self.assertRaises(VolumeError):
                Volume(data)
        # Duplicate sibling names remain invalid with both metadata seals valid.
        data = bytearray(self.snapshot)
        start = self.offset(9)
        data[start + 72:start + 328] = bytes(256)
        data[start + 72:start + 77] = b"empty"
        self.node(data, 9, 64, 5)
        self.assertFalse(self.native_accepts(data))
        with self.assertRaises(VolumeError):
            Volume(data)

    def test_cycle_short_long_and_crossfile_block_chains(self):
        original = Volume(self.snapshot)
        binary = original._nodes[8]
        for label, block, next_ in (("cycle", binary.blocks[0], binary.blocks[0]),
                                    ("short", binary.blocks[0], 0),
                                    ("out of range", binary.blocks[0], 4000),
                                    ("long", binary.blocks[-1], 3999),
                                    ("alias other file", binary.blocks[0], original._nodes[9].head)):
            data = bytearray(self.snapshot)
            struct.pack_into("<Q", data, 397312 + (block - 1) * 4096, next_)
            with self.subTest(label=label):
                self.assertFalse(self.native_accepts(data))
                with self.assertRaises(VolumeError):
                    Volume(data)

    def test_legacy_clock_and_native_ignored_padding_compatibility(self):
        data = bytearray(self.snapshot)
        data[56:72] = bytes(16)
        self.assertTrue(self.native_accepts(data))
        self.assertGreaterEqual(Volume(data).clock, 1700000000)
        # These bytes are deliberately not interpreted as state/authority.
        data = bytearray(self.snapshot)
        data[100] = 0xa5
        data[397312 + (3999 - 1) * 4096 + 100] = 0xff
        self.node(data, 11, 48, 3999)  # Ignored historical tombstone field.
        self.assertTrue(self.native_accepts(data))
        self.assertEqual(Volume(data).get("/work/empty"), b"")

    def test_file_reader_rejects_symlink_directory_and_wrong_size(self):
        link = self.directory / "linked.raw"
        link.symlink_to(self.directory / "snapshot.raw")
        with self.assertRaises(OSError):
            Volume.from_file(link)
        with self.assertRaises(VolumeError):
            Volume.from_file(self.directory)
        small = self.directory / "small.raw"
        small.write_bytes(b"x")
        with self.assertRaises(VolumeError):
            Volume.from_file(small)


if __name__ == "__main__":
    unittest.main()
