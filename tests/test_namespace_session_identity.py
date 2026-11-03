"""Native production session isolation regressions using valid trusted inputs.

The constants below are counterexamples to the admitted R9 handle formula.
No test depends on the replacement handle representation. C constructs wire
requests and guest RAM; the unchanged fixture supplies both real transports
and the production store. Every scenario executes in a fresh native process.
This qualifies host-native component behavior, not an AArch64 guest boot.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

_fixture_path = Path(__file__).with_name("test_unified_namespace_transports.py")
_fixture_spec = importlib.util.spec_from_file_location("session_identity_transport_fixture", _fixture_path)
_fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(_fixture)
TRANSPORT_HARNESS = _fixture.HARNESS

ROOT = Path(__file__).resolve().parents[1]
SOURCE_NAMES = (
    "ocore/runtime/common/namespace_store.oc",
    "ocore/runtime/aarch64/kernel_world_9p.oc",
    "ocore/runtime/aarch64/plan9_namespace_uart.oc",
)

CASES = r'''
#include <sys/resource.h>
static const uint8_t marker[] = {0,0x11,0x13,0xff,'n','a','t','i','v','e',0};
static void initialize(void) {
    memory=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    volume=mmap(NULL,0x1000000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(memory!=MAP_FAILED && volume!=MAP_FAILED);
    assert(S(init)((uintptr_t)volume,0x1000000,7)==1);
}
static void direct_handshake(uint64_t session) {
    assert(session);version();direct(session,101);attach(10);direct(session,105);
}
static void direct_create_marker(uint64_t session,const char *name) {
    walk(10,11,"work",NULL);direct(session,111);create(11,name,2);direct(session,115);
    write_bytes(11,marker,sizeof(marker));direct(session,119);
}
static void direct_read_marker(uint64_t session) {
    read_(11,sizeof(marker));check_bytes(direct(session,117),marker,sizeof(marker));
}
static void direct_open_marker(uint64_t session,const char *name) {
    walk(10,11,"work",name);direct(session,111);open_(11,2);direct(session,113);
}
static void root_collision(void) {
    uint64_t linux_session=S(session_init)(1,1);direct_handshake(linux_session);direct_create_marker(linux_session,"root-shared");
    // Original serials 1/2: these two legal generations produced one handle.
    uint64_t plan9=S(session_init)(4,UINT64_C(0xa7598acb81de843e));assert(plan9);
    version();direct(plan9,101);
    direct_read_marker(linux_session); // A different client's version must not clunk Linux.
    attach(10);direct(plan9,105);direct_open_marker(plan9,"root-shared");direct_read_marker(plan9);
    assert(S(revoke)(4)==1);direct_read_marker(linux_session);
    read_(11,1);direct(plan9,107);assert(linux_session!=plan9);
}
static void readonly_collision(uint64_t first_generation,uint64_t ro_generation) {
    uint64_t linux_session=S(session_init)(1,first_generation);direct_handshake(linux_session);direct_create_marker(linux_session,"protected");
    uint64_t readonly=S(session_init)(3,ro_generation);direct_handshake(readonly);
    // A collided token formerly selected grant1, giving this RO client root RW.
    create(10,"must-not-create",2);direct(readonly,107);
    walk(10,12,"pkg",NULL);direct(readonly,107); // RO grant is rooted at /work.
    walk(10,11,"protected",NULL);direct(readonly,111);open_(11,0);direct(readonly,113);
    direct_read_marker(readonly);direct_read_marker(linux_session);
    assert(S(revoke)(3)==1);direct_read_marker(linux_session);
    read_(11,1);direct(readonly,107);assert(linux_session!=readonly);
}
static void same_grant_stale(void) {
    uint64_t old=S(session_init)(1,1);direct_handshake(old);direct_create_marker(old,"old-session");
    uint64_t fresh=S(session_init)(1,UINT64_C(0xa2598acb81de843e));direct_handshake(fresh);
    direct_create_marker(fresh,"fresh-session");
    // Reusing a numeric fid in the replacement session must not revive old authority.
    read_(11,sizeof(marker));direct(old,107);direct_read_marker(fresh);assert(old!=fresh);
}
static void reopen_stale(void) {
    uint64_t old=S(session_init)(1,1);direct_handshake(old);direct_create_marker(old,"persisted");
    assert(S(init)((uintptr_t)volume,0x1000000,8)==1);
    // Old formula resets serial on init: epoch7/gen1 and epoch8/gen14 alias.
    uint64_t fresh=S(session_init)(1,14);direct_handshake(fresh);direct_open_marker(fresh,"persisted");
    read_(11,sizeof(marker));direct(old,107);direct_read_marker(fresh);assert(old!=fresh);
    // Same-epoch trusted reinitialization also invalidates all old handles.
    assert(S(init)((uintptr_t)volume,0x1000000,8)==1);
    uint64_t again=S(session_init)(1,14);direct_handshake(again);direct_open_marker(again,"persisted");
    read_(11,1);direct(fresh,107);read_(11,1);direct(old,107);direct_read_marker(again);
}
static void transport_linux(void) {
    // init issues serial1/gen1, setup's driver reset issues serial2/gen2.
    assert(N(init)(GPA,65536,1)==1);setup();
    version();exchange(101,8192);attach(10);exchange(105,8192);
    walk(10,11,"work",NULL);exchange(111,8192);create(11,"transport-shared",2);exchange(115,8192);
    write_bytes(11,marker,sizeof(marker));exchange(119,8192);
}
static void linux_read_marker(void) {
    read_(11,sizeof(marker));check_bytes(exchange(117,8192),marker,sizeof(marker));
}
static void transport_collision(unsigned version_first) {
    transport_linux();
    // Trusted UART init issues serial3 at this epoch. Enabling directly avoids
    // an extra driver-disable reset, preserving the actual counterexample.
    assert(U(init)(UINT64_C(0xe3c89e5e834b8c17))==1);uw(0x30,0x301);
    linux_read_marker();
    if(version_first) {
        version();uexchange(101);linux_read_marker();
        attach(10);uexchange(105);walk(10,11,"work","transport-shared");uexchange(111);
        open_(11,2);uexchange(113);read_(11,sizeof(marker));check_bytes(uexchange(117),marker,sizeof(marker));
    }
    assert(U(revoke)()==1 && U(healthy)()==0);linux_read_marker();
    assert(U(mmio_write)(0x30,0x301)==0);linux_read_marker();
}
static void rejected_generation(void) {
    uint64_t linux_session=S(session_init)(1,50);direct_handshake(linux_session);direct_create_marker(linux_session,"retained");
    uint64_t plan9=S(session_init)(4,70);direct_handshake(plan9);direct_open_marker(plan9,"retained");
    const uint64_t rejected[]={0,1,49,50};
    for(unsigned i=0;i<sizeof(rejected)/sizeof(rejected[0]);i++) {
        assert(S(session_init)(1,rejected[i])==0);direct_read_marker(linux_session);direct_read_marker(plan9);
    }
    assert(S(session_init)(0,1)==0 && S(session_init)(5,1)==0 && S(session_init)(UINT64_MAX,1)==0);
    assert(S(revoke)(0)==0 && S(revoke)(5)==0);direct_read_marker(linux_session);direct_read_marker(plan9);
    assert(S(revoke)(1)==1);
    assert(S(session_init)(1,50)==0);read_(11,1);direct(linux_session,107);direct_read_marker(plan9);
    uint64_t fresh=S(session_init)(1,51);direct_handshake(fresh);direct_open_marker(fresh,"retained");
    read_(11,1);direct(linux_session,107);direct_read_marker(fresh);direct_read_marker(plan9);
}
int main(int argc,char **argv) {
    struct rlimit no_core={0,0};assert(setrlimit(RLIMIT_CORE,&no_core)==0);
    setvbuf(stdout,NULL,_IONBF,0);assert(argc==2);initialize();
    printf("native session scenario: %s\n",argv[1]);
    if(!strcmp(argv[1],"root_collision"))root_collision();
    else if(!strcmp(argv[1],"readonly_collision"))readonly_collision(1,UINT64_C(0xa0598acb81de843e));
    else if(!strcmp(argv[1],"zero_remap_collision"))
        readonly_collision(UINT64_C(0x9f3779b97f4a7c12),UINT64_C(0xc0910c8d016b07d2));
    else if(!strcmp(argv[1],"same_grant_stale"))same_grant_stale();
    else if(!strcmp(argv[1],"reopen_stale"))reopen_stale();
    else if(!strcmp(argv[1],"transport_version"))transport_collision(1);
    else if(!strcmp(argv[1],"transport_revoke"))transport_collision(0);
    else if(!strcmp(argv[1],"rejected_generation"))rejected_generation();
    else assert(!"unknown scenario");
    printf("native production session scenario %s: PASS\n",argv[1]);return 0;
}
'''

HARNESS = TRANSPORT_HARNESS.split("int main(void) {", 1)[0] + CASES


def identity(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native fixture requires Linux x86_64")
class NamespaceSessionIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            raise unittest.SkipTest("already-built ocorec and clang are required")
        compiler = compiler.resolve(strict=True)
        cls.out = Path(tempfile.mkdtemp(prefix="namespace-session-identity-"))
        cls.receipt = {"scope": "native x86_64 production-store/transport fixtures; AArch64 MIR validation only",
                       "compiler": identity(compiler), "clang": identity(Path(clang).resolve()),
                       "sources": [identity(ROOT / name) for name in SOURCE_NAMES],
                       "test": identity(Path(__file__).resolve()),
                       "fixture": identity(Path(__file__).with_name("test_unified_namespace_transports.py")),
                       "commands": [], "scenarios": {}}
        print("Session identity artifacts: " + str(cls.out), flush=True)
        (cls.out / "harness.c").write_text(HARNESS)
        sources = [str(ROOT / name) for name in SOURCE_NAMES]
        commands = [
            [str(compiler), *sources, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(cls.out / "aarch64.mir")],
            [str(compiler), *sources, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(cls.out / "production.o")],
            [clang, "-O2", "-no-pie", str(cls.out / "harness.c"), str(cls.out / "production.o"), "-o", str(cls.out / "native-test")],
        ]
        for number, command in enumerate(commands):
            result = subprocess.run(command, capture_output=True, timeout=120)
            (cls.out / (str(number) + ".stdout")).write_bytes(result.stdout)
            (cls.out / (str(number) + ".stderr")).write_bytes(result.stderr)
            cls.receipt["commands"].append({"argv": command, "returncode": result.returncode})
            cls.save_receipt()
            if result.returncode:
                raise AssertionError(result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))

    @classmethod
    def save_receipt(cls):
        (cls.out / "fixture-results.json").write_text(json.dumps(cls.receipt, indent=2) + "\n")

    @classmethod
    def tearDownClass(cls):
        cls.receipt["sources_unchanged"] = cls.receipt["sources"] == [identity(ROOT / name) for name in SOURCE_NAMES]
        cls.receipt["artifacts"] = [identity(cls.out / name) for name in ("harness.c", "aarch64.mir", "production.o", "native-test")]
        cls.save_receipt()
        if not cls.receipt["sources_unchanged"]:
            raise AssertionError("production sources changed during qualification")

    def scenario(self, name):
        result = subprocess.run([str(self.out / "native-test"), name], capture_output=True, timeout=30)
        (self.out / (name + ".stdout")).write_bytes(result.stdout)
        (self.out / (name + ".stderr")).write_bytes(result.stderr)
        self.receipt["scenarios"][name] = {"returncode": result.returncode,
                                          "stdout": identity(self.out / (name + ".stdout")),
                                          "stderr": identity(self.out / (name + ".stderr"))}
        self.save_receipt()
        self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
        self.assertIn(("native production session scenario " + name + ": PASS").encode(), result.stdout)

    def test_concurrent_root_grants_preserve_fids(self):
        self.scenario("root_collision")

    def test_concurrent_readonly_grant_retains_authority(self):
        self.scenario("readonly_collision")

    def test_zero_remapping_does_not_alias_readonly_grant(self):
        self.scenario("zero_remap_collision")

    def test_replacement_never_resurrects_stale_session(self):
        self.scenario("same_grant_stale")

    def test_store_reopen_never_resurrects_stale_session(self):
        self.scenario("reopen_stale")

    def test_actual_uart_version_preserves_live_linux_fid(self):
        self.scenario("transport_version")

    def test_actual_uart_revocation_preserves_live_linux_fid(self):
        self.scenario("transport_revoke")

    def test_rejected_generations_preserve_live_sessions(self):
        self.scenario("rejected_generation")


if __name__ == "__main__":
    unittest.main()
