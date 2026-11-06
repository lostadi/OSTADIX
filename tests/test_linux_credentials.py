"""Execute immutable credential metadata with real native process registries.

The host supplies privileged architecture hooks and immutable image delivery.
No Linux getter is implemented by the C carrier, and these tests do not prove
a CPL3 syscall route, original libc lowering, permissions or full Linux ABI.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

from tests import test_exec_startup_capture as BASE

ROOT = Path(__file__).resolve().parents[1]
MODULES = [*BASE.MODULES, "linux_credentials"]
HARNESS = BASE.HARNESS.split("int main(int argc,char **argv)", 1)[0] + r'''
#define C(n) _O_runtime__linux_credentials__##n
extern uint64_t C(init)(void),C(admit)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t),C(retire)(uint64_t);
extern int64_t C(read_for)(uint64_t,size_t),C(dispatch)(uint64_t);
extern uint64_t P(stop_process)(uint64_t,uint64_t),P(begin_reap)(uint64_t),P(finalize_reap)(uint64_t);
extern uint64_t P(process_handle_for_slot)(size_t),P(is_live)(uint64_t),P(process_state)(uint64_t);
extern uint64_t D(create_domain)(size_t,uint64_t,uint64_t,uint64_t);
extern uint64_t A(destroy)(uint64_t),CAP(begin_cspace_drain)(uint64_t),CAP(destroy_cspace)(uint64_t),CAP(create_cspace)(size_t);
// These are private O-core arrays, explicitly eight-byte aligned. C's default
// alignment assumption for externally visible large arrays is not their ABI.
extern uint64_t P(ADDRESS_SPACE_HANDLES)[4] __attribute__((aligned(8)));
extern uint64_t P(CSPACE_HANDLES)[4] __attribute__((aligned(8)));
extern uint64_t C(OWNERS)[4] __attribute__((aligned(8)));
extern uint64_t C(SPACES)[4] __attribute__((aligned(8)));
extern uint64_t C(CSPACES)[4] __attribute__((aligned(8)));
extern uint64_t C(VALUES)[16] __attribute__((aligned(8)));
static const uint64_t numbers[4]={102,107,104,108};
static unsigned checks;
#define CHECK(x) do{checks++;assert(x);}while(0)
static void empty_context(void){for(unsigned i=0;i<4;i++)CHECK(C(dispatch)(numbers[i])==-3);CHECK(C(dispatch)(999)==-38);}
static void getters(uint64_t owner,const uint64_t values[4]){
 for(unsigned i=0;i<4;i++){CHECK(C(read_for)(owner,i)==(int64_t)values[i]);CHECK(C(dispatch)(numbers[i])==(int64_t)values[i]);}
 CHECK(C(read_for)(owner,4)==-22);CHECK(C(dispatch)(105)==-38); // No setuid success stub.
}
static void reap(uint64_t owner,uint64_t as,uint64_t cs){
 CHECK(P(stop_process)(owner,0)==1);CHECK(C(retire)(owner)==0);
 CHECK(P(begin_reap)(owner)==1);CHECK(C(retire)(owner)==0);
 CHECK(A(destroy)(as)==1);CHECK(CAP(begin_cspace_drain)(cs)==1);
 CHECK(CAP(destroy_cspace)(cs)==1);CHECK(P(finalize_reap)(owner)==1);CHECK(!P(is_live)(owner));
}
static uint64_t credentials[4][4];
static uint64_t saved_values[16];
static void snapshot(void){
 memcpy(credentials[0],C(OWNERS),sizeof credentials[0]);memcpy(credentials[1],C(SPACES),sizeof credentials[1]);
 memcpy(credentials[2],C(CSPACES),sizeof credentials[2]);
 memcpy(saved_values,C(VALUES),sizeof saved_values);
}
static void credentials_unchanged(void){
 CHECK(!memcmp(credentials[0],C(OWNERS),sizeof credentials[0]));CHECK(!memcmp(credentials[1],C(SPACES),sizeof credentials[1]));
 CHECK(!memcmp(credentials[2],C(CSPACES),sizeof credentials[2]));
 CHECK(!memcmp(saved_values,C(VALUES),sizeof saved_values));
}
int main(int argc,char **argv){
 CHECK(argc==2);FILE *f=fopen(argv[1],"rb");CHECK(f);CHECK(!fseek(f,0,SEEK_END));image_size=ftell(f);rewind(f);
 image=malloc(image_size);CHECK(image&&fread(image,1,image_size,f)==image_size);fclose(f);
 empty_context();CHECK(C(admit)(1,0,0,0,0)==0);CHECK(C(retire)(1)==0);
 CHECK(C(init)()==1);CHECK(C(init)()==0);empty_context();
 void *frames=NULL;CHECK(!posix_memalign(&frames,4096,1048576));
 CHECK(FR(init)((uintptr_t)frames,(uintptr_t)frames+1048576)&&CAP(init)()&&M(init)()&&MAP(init)());
 uint64_t native=D(init)();CHECK(native&&P(init)()&&A(install_bootstrap)((uintptr_t)root_table));
 uint64_t linux_domain=D(create_domain)(1,55,3,1);CHECK(linux_domain);
 uint64_t cs[4],as[4],owners[4];
 for(unsigned i=0;i<4;i++)cs[i]=CAP(cspace_handle_for_slot)(i);
 as[0]=1;for(unsigned i=1;i<4;i++){CHECK(M(set_quota_for_owner)(cs[i],8));as[i]=A(create_native_for_owner)(cs[i]);CHECK(as[i]);}
 for(unsigned i=0;i<4;i++){owners[i]=P(install_for_owner)(i,100+i,i?linux_domain:native,as[i],cs[i],0x7000+0x1000*i,0x01000000,0x01400000);CHECK(owners[i]);}
 // UID0 is valid only when explicitly admitted. Values are never invented.
 const uint64_t v1[4]={1000,1001,1002,1003},v2[4]={0,4000000000U,2,4294967294U};
 snapshot();CHECK(!C(admit)(owners[0],0,0,0,0));CHECK(!C(admit)(0,0,0,0,0));credentials_unchanged();
 for(unsigned i=0;i<4;i++){
  uint64_t invalid[4]={1000,1001,1002,1003};invalid[i]=UINT32_MAX;
  snapshot();CHECK(!C(admit)(owners[1],invalid[0],invalid[1],invalid[2],invalid[3]));credentials_unchanged();
  invalid[i]=UINT64_MAX;CHECK(!C(admit)(owners[1],invalid[0],invalid[1],invalid[2],invalid[3]));credentials_unchanged();
 }
 CHECK(C(admit)(owners[1],v1[0],v1[1],v1[2],v1[3])==1);
 CHECK(C(admit)(owners[2],v2[0],v2[1],v2[2],v2[3])==1);
 snapshot();CHECK(!C(admit)(owners[1],7,8,9,10));CHECK(!C(retire)(owners[1]));CHECK(!C(init)());credentials_unchanged();
 CHECK(P(scheduler_switch_to)(owners[1])==101);getters(owners[1],v1);
 CHECK(!C(admit)(owners[3],7,8,9,10));CHECK(!C(retire)(owners[2]));
 // Trusted-start owner derives initial auxv from the same immutable record.
 CHECK(L(init)()==1);uint64_t p=plan();descriptor();
 for(unsigned i=0;i<16;i++)random_bytes[i]=(unsigned char)(0x80+i);
 for(unsigned i=0;i<4;i++)config[10+i]=(uint64_t)C(read_for)(owners[1],i);
 CHECK(L(configure_startup)(p,config,15)==1);capture(p,stack);
 for(unsigned i=0;i<4;i++)CHECK(aux(p,11+i)==v1[i]);
 CHECK(L(abort)(p)==1);CHECK(!refs);
 // Corrupt only private carrier registry state to exercise independent bindings.
 // These writes are not a public or guest API; each exact original is restored.
 uint64_t old=P(ADDRESS_SPACE_HANDLES)[1];P(ADDRESS_SPACE_HANDLES)[1]=as[2];
 CHECK(C(dispatch)(102)==-3);CHECK(C(read_for)(owners[1],0)==-3);P(ADDRESS_SPACE_HANDLES)[1]=old;
 old=P(CSPACE_HANDLES)[1];P(CSPACE_HANDLES)[1]=cs[2];
 CHECK(C(dispatch)(102)==-3);CHECK(C(read_for)(owners[1],0)==-3);P(CSPACE_HANDLES)[1]=old;getters(owners[1],v1);
 CHECK(P(scheduler_switch_to)(owners[2])==102);getters(owners[2],v2);
 CHECK(P(scheduler_switch_to)(owners[3])==103);for(unsigned i=0;i<4;i++)CHECK(C(dispatch)(numbers[i])==-3);
 CHECK(P(scheduler_deschedule_current)()==owners[3]);empty_context();
 CHECK(C(read_for)(owners[1]^(UINT64_C(1)<<32),0)==-3);CHECK(!C(retire)(owners[1]^(UINT64_C(1)<<32)));
 // A real two-phase teardown invalidates the old PCB/AS/CSpace generations.
 reap(owners[1],as[1],cs[1]);CHECK(C(read_for)(owners[1],0)==-3);
 cs[1]=CAP(create_cspace)(1);CHECK(cs[1]&&M(set_quota_for_owner)(cs[1],8));as[1]=A(create_native_for_owner)(cs[1]);CHECK(as[1]);
 uint64_t replacement=P(install_for_owner)(1,201,linux_domain,as[1],cs[1],0x8000,0x01000000,0x01400000);CHECK(replacement&&replacement!=owners[1]);
 CHECK(C(read_for)(replacement,0)==-3);CHECK(!C(admit)(replacement,7,8,9,10)); // Explicit retirement required.
 CHECK(C(retire)(owners[1])==1);CHECK(C(retire)(owners[1])==0);
 CHECK(C(admit)(replacement,7,8,9,10)==1);CHECK(P(scheduler_switch_to)(replacement)==201);
 const uint64_t v3[4]={7,8,9,10};getters(replacement,v3);CHECK(C(read_for)(owners[1],0)==-3);
 CHECK(P(scheduler_deschedule_current)()==replacement);reap(replacement,as[1],cs[1]);CHECK(C(retire)(replacement)==1);
 for(unsigned i=0;i<4;i++)CHECK(C(VALUES)[4+i]==0);CHECK(!C(OWNERS)[1]&&!C(SPACES)[1]&&!C(CSPACES)[1]);
 CHECK(P(scheduler_switch_to)(owners[2])==102);getters(owners[2],v2);CHECK(P(scheduler_deschedule_current)()==owners[2]);
 printf("Native immutable Linux credential metadata: PASS (%u checks)\n",checks);return 0;
}
'''


def identity(path):
    data = Path(path).read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def allocated_sections(path):
    data = Path(path).read_bytes()
    assert data[:7] == b"\x7fELF\x02\x01\x01"
    start = struct.unpack_from("<Q", data, 40)[0]
    stride, count = struct.unpack_from("<HH", data, 58)
    assert stride == 64 and count and start + stride * count <= len(data)
    result = []
    for index in range(count):
        _, kind, flags, address, offset, size = struct.unpack_from("<IIQQQQ", data, start+index*stride)
        if flags & 2:
            assert kind == 8 or offset + size <= len(data)
            payload = b"" if kind == 8 else data[offset:offset+size]
            result.append((kind, flags, address, size, hashlib.sha256(payload).hexdigest()))
    return result


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native x86-64 carrier")
class LinuxCredentialTests(unittest.TestCase):
    def test_real_immutable_identity_auxv_and_generation_lifetime(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        objcopy = shutil.which("objcopy")
        if not compiler.is_file() or clang is None or objcopy is None:
            self.skipTest("already-built ocorec, clang and objcopy are required")
        selected = os.environ.get("OCORE_CREDENTIAL_TEST_ROOT")
        temporary = None if selected else tempfile.TemporaryDirectory(prefix="okernel-credentials-")
        out = Path(selected or temporary.name)
        out.mkdir(parents=True, exist_ok=True)
        commands = []
        sources = [ROOT / f"ocore/runtime/x86_64/{name}.oc" for name in MODULES]
        before = [identity(p) for p in sources]
        for source in [*sources, Path(__file__), ROOT / "tests/test_exec_startup_capture.py", ROOT / "tests/test_linux_initial_stack.py"]:
            destination = out / "source" / source.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o444)
        for name, text in {"provider.oc": BASE.BASE.PROVIDER, "entry.S": BASE.BASE.ENTRY,
                           "probe.c": BASE.BASE.PROBE, "harness.c": HARNESS}.items():
            (out / name).write_text(text)
        def run(name, argv, success=True):
            start = time.monotonic()
            r = subprocess.run(list(map(str, argv)), cwd=ROOT, capture_output=True, timeout=120)
            (out / (name + ".stdout")).write_bytes(r.stdout)
            (out / (name + ".stderr")).write_bytes(r.stderr)
            commands.append({"name": name, "argv": list(map(str, argv)), "returncode": r.returncode,
                             "seconds": time.monotonic()-start, "stdout": identity(out/(name+".stdout")),
                             "stderr": identity(out/(name+".stderr"))})
            if success:
                self.assertEqual(r.returncode, 0, (r.stdout+r.stderr).decode(errors="replace"))
            else:
                self.assertNotEqual(r.returncode, 0, "semantic mutant escaped the native oracle")
            return r
        report = {"ok": False, "sources_before": before, "test_source": identity(Path(__file__)), "compiler": identity(compiler), "commands": commands,
                  "scope": __doc__, "initial_syntax_correction": "Private initial draft used unsupported chained else-if; corrected to independent exact-number branches before native compilation."}
        private_symbols = ["_O_runtime__linux_credentials__"+n for n in ["OWNERS", "SPACES", "CSPACES", "VALUES"]] + ["_O_runtime__process__"+n for n in ["ADDRESS_SPACE_HANDLES", "CSPACE_HANDLES"]]
        report["private_symbol_access"] = "Test-only ELF symbol binding changes expose private data for full-state read snapshots and two explicit registry corruption controls; every allocated section byte must remain exact. Production source visibility/API is unchanged."
        def globalize(name, original, visible):
            run(name, [objcopy, *["--globalize-symbol="+n for n in private_symbols], original, visible])
            self.assertEqual(allocated_sections(original), allocated_sections(visible))
        try:
            run("compile", [compiler, out/"provider.oc", *sources, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", out/"runtime.o"])
            globalize("test-symbols", out/"runtime.o", out/"runtime-visible.o")
            run("probe", [clang, "-O2", "-fno-stack-protector", "-fno-builtin", "-nostdlib", "-static", "-no-pie", "-Wl,-Ttext-segment=0x02000000", out/"entry.S", out/"probe.c", "-o", out/"probe"])
            run("link", [clang, "-O2", "-no-pie", out/"harness.c", out/"runtime-visible.o", "-o", out/"selftest"])
            result = run("native", [out/"selftest", out/"probe"])
            self.assertIn(b"Native immutable Linux credential metadata: PASS", result.stdout)
            report["native_output"] = result.stdout.decode()
            original = (ROOT / "ocore/runtime/x86_64/linux_credentials.oc").read_text()
            mutations = {
                "constant-uid": ("return VALUES[slot * 4 + field] as i64;", "return 1000;"),
                "overwrite-admission": ("slot >= MAX_PROCESSES || OWNERS[slot] != 0", "slot >= MAX_PROCESSES"),
                "missing-as-binding": ("|| SPACES[slot] != address_space_for(process)", ""),
                "premature-retirement": (" || process_is_live(process)", ""),
            }
            for name, (needle, replacement) in mutations.items():
                self.assertEqual(original.count(needle), 1)
                mutant = out / (name + ".oc")
                mutant.write_text(original.replace(needle, replacement))
                altered = [p if p.name != "linux_credentials.oc" else mutant for p in sources]
                run(name+"-compile", [compiler, out/"provider.oc", *altered, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", out/(name+".o")])
                globalize(name+"-test-symbols", out/(name+".o"), out/(name+"-visible.o"))
                run(name+"-link", [clang, "-O2", "-no-pie", out/"harness.c", out/(name+"-visible.o"), "-o", out/name])
                run(name+"-rejected", [out/name, out/"probe"], success=False)
            report["ok"] = True
        finally:
            report["sources_after"] = [identity(p) for p in sources]
            report["source_stable"] = before == report["sources_after"]
            report["ok"] = report["ok"] and report["source_stable"]
            (out/"result.json").write_text(json.dumps(report, indent=2)+"\n")
            if temporary:
                temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
