"""Execute the production private-libc binding with real host GCC/glibc.

The host fixture uses the binding's directory layout with native host GNU
objects. It tests startup/header isolation/linking, not ARM64 qualification.
"""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "ocore/guest/linux/package-domain/glibc-cc"


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "the real GNU host fixture requires Linux x86_64")
class OriginalGnuBindingTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which("gcc"):
            self.skipTest("original host GCC is required")
        temporary = tempfile.TemporaryDirectory(prefix="okernel-gnu-binding-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sysroot = self.root / "abi"
        self.libraries = self.sysroot / "usr/lib/aarch64-linux-gnu"
        self.libraries.mkdir(parents=True)
        original = Path("/usr/lib/x86_64-linux-gnu")
        for name in ("crt1.o", "crti.o", "crtn.o", "libc.so.6", "libc_nonshared.a", "libgcc_s.so.1"):
            if not (original / name).is_file():
                self.skipTest(f"original GNU object absent: {name}")
            (self.libraries / name).symlink_to(original / name)
        loader = Path("/lib64/ld-linux-x86-64.so.2")
        if not loader.is_file():
            self.skipTest("original GNU ELF loader is required")
        self.loader = self.libraries / "ld-linux-aarch64.so.1"
        self.loader.symlink_to(loader)
        includes = self.sysroot / "usr/include"
        includes.mkdir()
        for header in Path("/usr/include").iterdir():
            (includes / header.name).symlink_to(header, target_is_directory=header.is_dir())
        architecture = includes / "aarch64-linux-gnu"
        architecture.mkdir()
        for header in Path("/usr/include/x86_64-linux-gnu").iterdir():
            (architecture / header.name).symlink_to(header, target_is_directory=header.is_dir())
        (architecture / "okernel_private_abi.h").write_text("#define OKERNEL_PRIVATE_ABI_SELECTED 8675309\n")
        poison = self.root / "ambient-headers"
        poison.mkdir()
        (poison / "stdio.h").write_text("#error ambient libc header was imported\n")
        self.env = {**os.environ, "OSTADIX_GLIBC_SYSROOT": str(self.sysroot),
                    "OSTADIX_GLIBC_INTERPRETER": str(self.loader), "C_INCLUDE_PATH": str(poison), "CPATH": str(poison)}
        self.source = self.root / "fixture.c"
        self.source.write_text('''#define _DEFAULT_SOURCE
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <okernel_private_abi.h>
static int initialized;
__attribute__((constructor)) static void initialize(void) { initialized=1; }
int main(int argc,char **argv) {
 if(!initialized || argc!=2 || strcmp(argv[1],"preserved-argument")) return 4;
 if(OKERNEL_PRIVATE_ABI_SELECTED!=8675309) return 6;
 if(ruserok("localhost",0,"okernel-no-such-user","okernel-no-such-user")!=-1) return 5;
 puts("ORIGINAL_GNU_LIBC_BINDING_PASS"); return 0;
}
''')

    def test_original_gcc_startup_headers_arguments_and_full_libc_auth_api(self):
        output = self.root / "program"
        result = subprocess.run(["sh", str(BINDING), "-O2", "-g0", str(self.source), "-o", str(output)],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        env = {**os.environ, "LD_LIBRARY_PATH": str(self.libraries)}
        result = subprocess.run([str(output), "preserved-argument"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "ORIGINAL_GNU_LIBC_BINDING_PASS\n")
        result = subprocess.run([str(self.loader), "--list", str(output)], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(str(self.libraries / "libc.so.6"), result.stdout)

    def test_missing_private_crt_is_an_error_instead_of_global_libc_fallback(self):
        (self.libraries / "crt1.o").unlink()
        output = self.root / "program"
        result = subprocess.run(["sh", str(BINDING), str(self.source), "-o", str(output)],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing original GNU ABI input", result.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
