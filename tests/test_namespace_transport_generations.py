"""Exercise both production transports with a formerly colliding generation.

The generation is a valid trusted native UART provisioning input, not a guest
request. C supplies guest RAM, wire bytes and IRQ hooks; O-core implements the
transports and store. Each scenario runs in a fresh native process. This is
host-native component coverage, not guest-boot or whole-OS qualification.
"""

import importlib.util
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE_NAMES = (
    "ocore/runtime/common/namespace_store.oc",
    "ocore/runtime/aarch64/kernel_world_9p.oc",
    "ocore/runtime/aarch64/plan9_namespace_uart.oc",
)
_fixture_path = Path(__file__).with_name("test_unified_namespace_transports.py")
_fixture_spec = importlib.util.spec_from_file_location("transport_generation_fixture", _fixture_path)
_fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(_fixture)
_main = "int main(void) {"
if _fixture.HARNESS.count(_main) != 1:
    raise RuntimeError("combined transport fixture must have exactly one main entry")

CASES = r'''
#include <sys/resource.h>
static const uint8_t marker[] = {0,0x11,0x13,0xff,'n','a','t','i','v','e',0};
static void linux_read_marker(const char *phase) {
    printf("Linux live-fid check: %s\n",phase);
    read_(11,sizeof(marker));check_bytes(exchange(117,8192),marker,sizeof(marker));
}
static void transport_collision(unsigned version_first) {
    memory=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    volume=mmap(NULL,0x1000000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(memory!=MAP_FAILED && volume!=MAP_FAILED);
    assert(S(init)((uintptr_t)volume,0x1000000,7)==1);
    // init and the driver's status=0 reset allocate the first two sessions.
    assert(N(init)(GPA,65536,1)==1);setup();
    version();exchange(101,8192);attach(10);exchange(105,8192);
    walk(10,11,"work",NULL);exchange(111,8192);create(11,"transport-shared",2);exchange(115,8192);
    write_bytes(11,marker,sizeof(marker));exchange(119,8192);
    // This trusted provisioning value collided with Linux under the old XOR
    // formula. Enable directly: ureset() would allocate an extra session and
    // stop exercising that counterexample. Do not inspect token representation.
    assert(U(init)(UINT64_C(0xe3c89e5e834b8c17))==1);uw(0x30,0x301);
    linux_read_marker("after trusted UART initialization");
    if(version_first) {
        version();uexchange(101);linux_read_marker("after UART Tversion");
        // Identical numeric fids remain independent while accessing one object.
        attach(10);uexchange(105);walk(10,11,"work","transport-shared");uexchange(111);
        open_(11,2);uexchange(113);
        read_(11,sizeof(marker));check_bytes(uexchange(117),marker,sizeof(marker));
    }
    assert(U(revoke)()==1 && U(healthy)()==0);
    linux_read_marker("after trusted UART revocation");
    assert(U(mmio_write)(0x30,0x301)==0);
    linux_read_marker("after rejected UART reenable");
}
int main(int argc,char **argv) {
    struct rlimit no_core={0,0};assert(setrlimit(RLIMIT_CORE,&no_core)==0);
    setvbuf(stdout,NULL,_IONBF,0);assert(argc==2);
    if(!strcmp(argv[1],"version"))transport_collision(1);
    else if(!strcmp(argv[1],"revoke"))transport_collision(0);
    else assert(!"unknown scenario");
    printf("native transport generation %s: PASS\n",argv[1]);return 0;
}
'''
HARNESS = _fixture.HARNESS.split(_main, 1)[0] + CASES


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "native production fixture requires Linux x86_64")
class NamespaceTransportGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            raise unittest.SkipTest("already-built ocorec and clang are required")
        directory = tempfile.TemporaryDirectory(prefix="namespace-transport-generations-")
        cls.addClassCleanup(directory.cleanup)
        cls.out = Path(directory.name)
        (cls.out / "harness.c").write_text(HARNESS)
        sources = [str(ROOT / name) for name in SOURCE_NAMES]
        commands = [
            [str(compiler), *sources, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(cls.out / "arm.mir")],
            [str(compiler), *sources, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(cls.out / "production.o")],
            [clang, "-O2", "-no-pie", str(cls.out / "harness.c"), str(cls.out / "production.o"), "-o", str(cls.out / "selftest")],
        ]
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True, timeout=60, cwd=cls.out)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)

    def scenario(self, name):
        # Reinitializing the store does not reset its lifetime token counter;
        # a separate process is required to replay the trusted call sequence.
        result = subprocess.run([str(self.out / "selftest"), name], capture_output=True,
                                text=True, timeout=30, cwd=self.out)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("native transport generation " + name + ": PASS", result.stdout)

    def test_uart_version_preserves_linux_fid_at_crafted_generation(self):
        self.scenario("version")

    def test_uart_revoke_before_version_preserves_linux_fid_at_crafted_generation(self):
        self.scenario("revoke")


if __name__ == "__main__":
    unittest.main()
