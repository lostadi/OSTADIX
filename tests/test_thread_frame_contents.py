"""Compare original/refactored frame validation with actual native registries.

The private content helper is not lifecycle authority. C exposes only test
views of real process/thread fields, supplies three privileged architecture
hooks and delivers one authored ELF fixture through the loader's image API.
It does not implement registries or claim closed INSTALL/FP/CPU admission.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("frame_process_fixture", ROOT / "tests/test_process_current_identity.py")
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
MODULES = [*BASE.MODULES, "thread"]
PROVIDER = r'''
module runtime::image_vfs;
extern "C" fn fixture_object_length(object: u64) -> usize;
extern "C" fn fixture_read(object: u64, offset: usize, result: *mut u8) -> u64;
extern "C" fn fixture_release(object: u64) -> u64;
pub unsafe fn object_length(object: u64) -> usize { return fixture_object_length(object); }
pub unsafe fn read_retained_byte(object: u64, offset: usize, result: *mut u8) -> u64 { return fixture_read(object, offset, result); }
pub unsafe fn release_object(object: u64) -> u64 { return fixture_release(object); }
'''
ENTRY = r'''
.text
.global _start
_start:
    nop
    ud2
.section .note.GNU-stack,"",@progbits
'''

HARNESS = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define P(n) _O_runtime__process__##n
#define T(n) _O_runtime__thread__##n
#define A(n) _O_runtime__address_space__##n
#define C(n) _O_runtime__capability__##n
#define M(n) _O_runtime__memory_object__##n
#define D(n) _O_runtime__domain__##n
#define FR(n) _O_runtime__pages__##n
#define MAP(n) _O_runtime__mapping__##n
#define L(n) _O_runtime__elf_loader__##n
extern uint64_t P(init)(void),P(current_process_matches)(uint64_t);
extern uint64_t P(install_for_owner)(size_t,uint64_t,uint64_t,uint64_t,uint64_t,uintptr_t,uintptr_t,uintptr_t);
extern uint64_t P(scheduler_switch_to)(uint64_t),P(scheduler_deschedule_current)(void);
extern uint64_t T(init)(void),T(prepare_next)(void),T(commit_next)(uint64_t),T(abort_next)(uint64_t);
extern uint64_t T(install)(size_t,uint64_t,uint64_t,uintptr_t,size_t,uintptr_t,uint64_t,uint64_t,uint64_t);
extern uint64_t T(install_loaded)(size_t,uint64_t,uint64_t,uintptr_t,uintptr_t,uintptr_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t T(frame_pointer)(uint64_t),T(save_current)(const uint64_t*),T(preempt_current)(void);
extern uint64_t T(block_current)(uint64_t),T(wake_due)(uint64_t),T(cancel)(uint64_t),T(reap)(uint64_t);
extern bool T(queue_invariants_hold)(void),T(validate_frame_words)(size_t,const uint64_t*);
#ifdef NEW_CONTENT
extern bool T(validate_frame_contents)(size_t,const uint64_t*);
#endif
extern uint64_t A(install_bootstrap)(uintptr_t),A(create_loaded_for_owner)(uint64_t,uint64_t);
extern uintptr_t A(loaded_entry)(uint64_t),A(loaded_stack_pointer)(uint64_t);
extern uint64_t C(init)(void),C(cspace_handle_for_slot)(size_t),M(init)(void),M(set_quota_for_owner)(uint64_t,size_t),D(init)(void);
extern uint64_t FR(init)(uintptr_t,uintptr_t),MAP(init)(void),L(init)(void),L(validate)(uint64_t),L(release_plan)(uint64_t);
/* DECLARATIONS */
static uint64_t kernel_tables[1024] __attribute__((aligned(4096)));
static uint64_t root_table[512] __attribute__((aligned(4096)));
uintptr_t ocore_current_cr3(void){return (uintptr_t)root_table;}
uintptr_t ocore_management_cr3(void){return (uintptr_t)root_table;}
uintptr_t ocore_kernel_p1_address(void){return (uintptr_t)kernel_tables;}
static unsigned checks,observations,image_calls,refs;
static uint64_t digest=UINT64_C(1469598103934665603);
static unsigned char *image;static size_t image_size;
static void check(int ok,unsigned line){checks++;if(!ok){fprintf(stderr,"fixture check failed at line %u\n",line);exit(92);}}
#define CHECK(x) check(!!(x),__LINE__)
size_t fixture_object_length(uint64_t object){image_calls++;return object==1&&refs?image_size:0;}
uint64_t fixture_read(uint64_t object,size_t at,unsigned char *out){image_calls++;if(object!=1||!refs||at>=image_size||!out)return 0;*out=image[at];return 1;}
uint64_t fixture_release(uint64_t object){image_calls++;if(object!=1||!refs)return 0;refs--;return 1;}
struct field {const void *pointer;size_t bytes;};
static const struct field fields[]={/* VIEWS */};
static size_t snapshot(unsigned char *out){size_t n=0;for(size_t i=0;i<sizeof fields/sizeof fields[0];i++){
 CHECK(n+fields[i].bytes<=4096);memcpy(out+n,fields[i].pointer,fields[i].bytes);n+=fields[i].bytes;
}return n;}
static void hash(const void *data,size_t n){const unsigned char *p=data;for(size_t i=0;i<n;i++){digest^=p[i];digest*=UINT64_C(1099511628211);}}
static void observe(unsigned id,bool content,size_t slot,const uint64_t *frame,bool expected){
 unsigned char before[4096],after[4096];uint64_t input[22],saved[22];size_t n=snapshot(before);unsigned calls=image_calls;
 if(frame)memcpy(input,frame,sizeof input);
 bool result;
#ifdef NEW_CONTENT
 result=content?T(validate_frame_contents)(slot,frame):T(validate_frame_words)(slot,frame);
#else
 result=T(validate_frame_words)(slot,frame);
#endif
 CHECK(snapshot(after)==n&&!memcmp(before,after,n)&&calls==image_calls);
 if(frame){memcpy(saved,frame,sizeof saved);CHECK(!memcmp(input,saved,sizeof input));}
 if(result!=expected){fprintf(stderr,"frame validation id=%u expected=%u observed=%u\n",id,expected,result);exit(93);}
 observations++;hash(&id,sizeof id);hash(&result,sizeof result);hash(after,n);
}
static uint64_t owners[2],threads[3];
static void setup(const char *path){
 FILE *f=fopen(path,"rb");CHECK(f&&!fseek(f,0,SEEK_END));long length=ftell(f);CHECK(length>0);rewind(f);
 image_size=(size_t)length;image=malloc(image_size);CHECK(image&&fread(image,1,image_size,f)==image_size);fclose(f);
 void *pool=NULL;CHECK(!posix_memalign(&pool,4096,1048576));
 CHECK(FR(init)((uintptr_t)pool,(uintptr_t)pool+1048576)&&C(init)()&&M(init)()&&MAP(init)());
 uint64_t domain=D(init)();CHECK(domain&&P(init)()&&T(init)()&&L(init)());CHECK(A(install_bootstrap)((uintptr_t)root_table));
 uint64_t cs0=C(cspace_handle_for_slot)(0),cs1=C(cspace_handle_for_slot)(1);CHECK(cs0&&cs1&&M(set_quota_for_owner)(cs1,64));
 refs=1;uint64_t plan=L(validate)(1);CHECK(plan);uint64_t loaded=A(create_loaded_for_owner)(cs1,plan);CHECK(loaded&&!refs&&L(release_plan)(plan));
 owners[0]=P(install_for_owner)(0,101,domain,1,cs0,0x7000,0x01000000,0x01400000);
 owners[1]=P(install_for_owner)(1,102,domain,loaded,cs1,0x9000,A(loaded_entry)(loaded),A(loaded_stack_pointer)(loaded));CHECK(owners[0]&&owners[1]);
 threads[0]=T(install)(0,201,owners[0],0x01000000,0,0x7000,17,1,1);
 threads[1]=T(install)(1,202,owners[0],0x01000000,1,0x8000,18,2,2);
 threads[2]=T(install_loaded)(2,203,owners[1],A(loaded_entry)(loaded),A(loaded_stack_pointer)(loaded),0x9000,19,20,1,1);
 CHECK(threads[0]&&threads[1]&&threads[2]&&T(queue_invariants_hold)());
}
static void formats(bool content,unsigned base){
 uint64_t frame[22];
 for(size_t slot=0;slot<3;slot++){
  memcpy(frame,&T(FRAMES)[slot*22],sizeof frame);observe(base++,content,slot,frame,true);
  const size_t fields_to_change[]={18,21,19,17,20};
  const uint64_t bad[]={0x1b,0x23,0,0,0};
  for(size_t j=0;j<5;j++){uint64_t old=frame[fields_to_change[j]];frame[fields_to_change[j]]=bad[j];observe(base++,content,slot,frame,false);frame[fields_to_change[j]]=old;}
  uint64_t flags=frame[19];frame[19]=2;observe(base++,content,slot,frame,true);frame[19]=0x4202;observe(base++,content,slot,frame,true);frame[19]=flags;
  uint64_t old=frame[20];frame[20]=0x01400001;observe(base++,content,slot,frame,false);frame[20]=old;
  uint8_t ordinal=T(STACK_ORDINALS)[slot];T(STACK_ORDINALS)[slot]=255;observe(base++,content,slot,frame,false);T(STACK_ORDINALS)[slot]=ordinal;
  uint64_t as=T(ADDRESS_SPACE_HANDLES)[slot];T(ADDRESS_SPACE_HANDLES)[slot]=0;observe(base++,content,slot,frame,false);T(ADDRESS_SPACE_HANDLES)[slot]=as;
  observe(base++,content,slot,NULL,false);
 }
 memcpy(frame,&T(FRAMES)[0],sizeof frame);observe(base++,content,4,frame,false);observe(base++,content,SIZE_MAX,frame,false);
 frame[20]=0x013fe000;observe(base++,content,0,frame,false);frame[20]=0x013fe001;observe(base++,content,0,frame,true);
 frame[20]=0x013fd001;observe(base++,content,0,frame,false);
 memcpy(frame,&T(FRAMES)[44],sizeof frame);frame[20]=0x013fc000;observe(base++,content,2,frame,false);
 frame[20]=0x013fc001;observe(base++,content,2,frame,true);frame[20]=0x013fd001;observe(base++,content,2,frame,true);
 frame[20]=0x01400000;observe(base++,content,2,frame,true);
 CHECK(T(queue_invariants_hold)());
}
static void states(bool content,unsigned base){
 uint64_t frame[22];memcpy(frame,T(FRAMES),sizeof frame);uint8_t original=T(STATES)[0];
 for(uint8_t state=0;state<8;state++){
  T(STATES)[0]=state;bool active=state==1||state==2||state==3||state==5;
  observe(base++,content,0,frame,content||active);
  CHECK(!!T(frame_pointer)(threads[0])==active);
 }T(STATES)[0]=original;
 if(!content){
  /* The existing private words predicate has no initialization gate; the
     public frame API retains checked_thread's initialization refusal. */
  uint8_t initialized=T(INITIALIZED);T(INITIALIZED)=0;
  observe(base++,false,0,frame,true);CHECK(!T(frame_pointer)(threads[0]));
  T(INITIALIZED)=initialized;
 }
 CHECK(T(queue_invariants_hold)());
}
static void lifecycle(void){
 uint64_t frame[22];CHECK(T(prepare_next)()==threads[0]);memcpy(frame,T(FRAMES),sizeof frame);observe(400,false,0,frame,true);
 CHECK(P(scheduler_switch_to)(owners[0])==101&&T(commit_next)(threads[0])==threads[0]);observe(401,false,0,frame,true);
 unsigned char before[4096],after[4096];size_t n=snapshot(before);frame[18]=0x1b;
 CHECK(!T(save_current)(frame)&&snapshot(after)==n&&!memcmp(before,after,n));
 frame[18]=0x23;frame[14]=1234;CHECK(T(save_current)(frame)==threads[0]);CHECK(T(FRAMES)[14]==1234);
 CHECK(T(block_current)(7)==threads[0]&&P(scheduler_deschedule_current)()==owners[0]);observe(402,false,0,frame,true);
 CHECK(T(prepare_next)()==threads[1]&&T(abort_next)(threads[1])==threads[1]);CHECK(T(wake_due)(7)==1);
 CHECK(T(cancel)(threads[1])==1);observe(403,false,1,&T(FRAMES)[22],false);CHECK(!T(frame_pointer)(threads[1]));
 CHECK(T(reap)(threads[1])==1);observe(404,false,1,&T(FRAMES)[22],false);CHECK(!T(frame_pointer)(threads[1]));
 CHECK(T(queue_invariants_hold)());n=snapshot(before);hash(before,n);
}
int main(int argc,char **argv){
 CHECK(argc==3);setup(argv[1]);
 if(!strcmp(argv[2],"public")){
  formats(false,100);states(false,300);lifecycle();
  printf("Frame public behavior: observations=%u digest=%016llx checks=%u\n",observations,(unsigned long long)digest,checks);return 0;
 }
#ifdef NEW_CONTENT
 CHECK(!strcmp(argv[2],"content"));formats(true,500);states(true,700);
 /* EMPTY/ref1 is only a test visibility case, not an authenticated install. */
 uint64_t frame[22];memcpy(frame,T(FRAMES),sizeof frame);T(STATES)[0]=0;T(PROCESS_REF_HELD)[0]=1;
 observe(800,true,0,frame,true);observe(801,false,0,frame,false);CHECK(!T(frame_pointer)(threads[0]));
 T(STATES)[0]=1;CHECK(T(queue_invariants_hold)());CHECK(T(cancel)(threads[1])==1);
 observe(802,true,1,&T(FRAMES)[22],true);observe(803,false,1,&T(FRAMES)[22],false);
 CHECK(!T(frame_pointer)(threads[1])&&T(queue_invariants_hold)());
 printf("Private content predicate only: observations=%u digest=%016llx checks=%u\n",observations,(unsigned long long)digest,checks);return 0;
#else
 CHECK(0);return 1;
#endif
}
'''


def identity(path):
    return BASE.identity(path)


def field_metadata():
    source = (ROOT / "ocore/runtime/x86_64/thread.oc").read_text()
    fields = re.findall(r"(?m)^static mut (\w+): (\[[^\]]+\]|\w+) =", source)
    if len(fields) != 36:
        raise AssertionError("all 36 current thread fields must be snapshotted")
    types = {"u8": "uint8_t", "u16": "uint16_t", "u32": "uint32_t", "u64": "uint64_t", "usize": "uintptr_t"}
    result = []
    for name, spelling in fields:
        matched = re.fullmatch(r"\[(\w+); (\d+)\]", spelling)
        kind, count = (matched[1], int(matched[2])) if matched else (spelling, 0)
        result.append((name, types[kind], count))
    return result


def carrier(thread_fields):
    declarations, views = [], []
    all_fields = [("P", name, kind, count) for name, (kind, count) in BASE.FIELDS.items()]
    all_fields += [("T", *item) for item in thread_fields]
    for prefix, name, kind, count in all_fields:
        declarations.append(f"extern {kind} {prefix}({name})" + (f"[{count}]" if count else "") + " __attribute__((aligned(8)));")
        views.append(f"{{&{prefix}({name}),sizeof {prefix}({name})}}")
    return HARNESS.replace("/* DECLARATIONS */", "\n".join(declarations)).replace("/* VIEWS */", ",".join(views))


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native registry carrier requires Linux x86_64")
class ThreadFrameContentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = [Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec")), *[shutil.which(n) for n in ("clang", "objcopy", "nm")]]
        if any(p is None or not Path(p).is_file() for p in selected):
            if os.environ.get("OCORE_THREAD_FRAME_REQUIRED") == "1":
                raise AssertionError("built ocorec and native compiler/object tools are required")
            raise unittest.SkipTest("built ocorec and native compiler/object tools are required")
        cls.compiler, cls.clang, cls.objcopy, cls.nm = [Path(p).resolve() for p in selected]
        expected = os.environ.get("OCOREC_BIN_SHA256")
        if expected and identity(cls.compiler)["sha256"] != expected:
            raise AssertionError("compiler digest mismatch")
        selected_output = os.environ.get("OCORE_THREAD_FRAME_TEST_OUTPUT")
        cls.cleanup = None if selected_output else tempfile.TemporaryDirectory(prefix="native-thread-frame-")
        cls.output = Path(selected_output or cls.cleanup.name)
        if selected_output:
            cls.output.mkdir(parents=False, exist_ok=False)
        cls.sources = [ROOT / "ocore/runtime/x86_64" / (n + ".oc") for n in MODULES]
        cls.source_before = [identity(p) for p in [*cls.sources, Path(__file__), ROOT / "tests/test_process_current_identity.py"]]
        cls.tools = [identity(p) for p in [cls.compiler, cls.clang, cls.objcopy, cls.nm, Path(sys.executable)]]
        cls.commands = []
        cls.public_symbols = {}
        cls.thread_fields = field_metadata()
        cls.report = {"schema": "ostadix.thread-frame-content/v1", "scope": __doc__, "commands": cls.commands,
                      "sources_before": cls.source_before, "tools": cls.tools, "native_FP_admission": False,
                      "complete_INSTALL_authority": False, "cross_ISA_runtime_parity": False}
        (cls.output / "provider.oc").write_text(PROVIDER)
        (cls.output / "entry.S").write_text(ENTRY)
        (cls.output / "harness.c").write_text(carrier(cls.thread_fields))
        cls.command("fixture-ELF", [cls.clang, "-nostdlib", "-static", "-no-pie", "-Wl,-Ttext-segment=0x02000000", cls.output / "entry.S", "-o", cls.output / "fixture.elf"])
        cls.current = cls.sources[-1].read_text()
        start = cls.current.index("// Content validation is deliberately separate from slot lifecycle authority.")
        end = cls.current.index("\nunsafe fn validate_frame(slot:", start)
        content_start = cls.current.index("unsafe fn validate_frame_contents(", start)
        wrapper_start = cls.current.index("\nunsafe fn validate_frame_words(", content_start)
        cls.content = cls.current[content_start:wrapper_start]
        old = cls.content.replace("unsafe fn validate_frame_contents(", "unsafe fn validate_frame_words(", 1).replace(
            "    if slot >= MAX_THREADS || frame as usize == 0 {\n",
            "    if slot >= MAX_THREADS\n        || frame as usize == 0\n        || !active_state(STATES[slot]) {\n", 1)
        cls.original = cls.current[:start] + old + cls.current[end:]
        before = cls.output / "before-thread.oc"
        before.write_text(cls.original)
        cls.build("before", [*cls.sources[:-1], before], False)
        cls.build("candidate", cls.sources, True)

    @classmethod
    def command(cls, name, argv, semantic_failure=False):
        start = time.monotonic()
        r = subprocess.run(list(map(str, argv)), cwd=cls.output, capture_output=True, timeout=120)
        out, err = cls.output / (name + ".stdout"), cls.output / (name + ".stderr")
        out.write_bytes(r.stdout)
        err.write_bytes(r.stderr)
        cls.commands.append({"name": name, "argv": list(map(str, argv)), "status": r.returncode,
                             "seconds": time.monotonic() - start, "stdout": identity(out), "stderr": identity(err)})
        if semantic_failure:
            match = re.fullmatch(rb"frame validation id=\d+ expected=([01]) observed=([01])\n", r.stderr)
            if r.returncode != 93 or match is None or match[1] == match[2]:
                raise AssertionError(f"{name}: not an exact semantic rejection: {r.returncode} {r.stderr!r}")
        elif r.returncode:
            raise AssertionError(f"{name}: {r.returncode}: {(r.stdout + r.stderr).decode(errors='replace')}")
        return r

    @classmethod
    def build(cls, name, sources, content):
        obj, visible = cls.output / (name + ".o"), cls.output / (name + "-visible.o")
        cls.command(name + "-compile", [cls.compiler, cls.output / "provider.oc", *sources, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", obj])
        undefined = cls.command(name + "-undefined", [cls.nm, "-u", obj]).stdout.decode()
        if {line.split()[-1] for line in undefined.splitlines()} != {
            "ocore_current_cr3", "ocore_management_cr3", "ocore_kernel_p1_address",
            "fixture_object_length", "fixture_read", "fixture_release",
        }:
            raise AssertionError("unexpected architecture or registry implementation")
        defined = cls.command(name + "-symbols", [cls.nm, "--defined-only", obj]).stdout.decode()
        symbols = {row.split()[-1]: row.split()[-2] for row in defined.splitlines() if len(row.split()) >= 3}
        for helper in ["validate_frame_words", *(["validate_frame_contents"] if content else [])]:
            if symbols.get("_O_runtime__thread__" + helper) != "t":
                raise AssertionError("frame validator must remain a private code symbol")
        cls.public_symbols[name] = {key for key, kind in symbols.items() if kind.isupper()}
        names = ["_O_runtime__process__" + n for n in BASE.FIELDS]
        names += ["_O_runtime__thread__" + n for n, _, _ in cls.thread_fields]
        names += ["_O_runtime__thread__validate_frame_words"]
        if content:
            names += ["_O_runtime__thread__validate_frame_contents"]
        cls.command(name + "-visibility", [cls.objcopy, *["--globalize-symbol=" + n for n in names], obj, visible])
        if BASE.allocated_sections(obj) != BASE.allocated_sections(visible):
            raise AssertionError("test symbol visibility changed allocated bytes")
        cls.command(name + "-link", [cls.clang, "-O2", "-fno-pie", "-no-pie", *(["-DNEW_CONTENT=1"] if content else []), cls.output / "harness.c", visible, "-o", cls.output / name])

    @classmethod
    def tearDownClass(cls):
        cls.report["sources_after"] = [identity(p) for p in [*cls.sources, Path(__file__), ROOT / "tests/test_process_current_identity.py"]]
        cls.report["tools_after"] = [identity(p["path"]) for p in cls.tools]
        cls.report["inputs_unchanged"] = cls.source_before == cls.report["sources_after"] and cls.tools == cls.report["tools_after"]
        cls.report["artifacts"] = [identity(p) for p in sorted(cls.output.iterdir()) if p.is_file()]
        (cls.output / "result.json").write_text(json.dumps(cls.report, indent=2) + "\n")
        if not cls.report["inputs_unchanged"]:
            raise AssertionError("source/tool mutation during frame qualification")
        if cls.cleanup:
            cls.cleanup.cleanup()

    def test_exact_before_after_ordinary_behavior(self):
        before = self.command("before-public", [self.output / "before", self.output / "fixture.elf", "public"])
        after = self.command("candidate-public", [self.output / "candidate", self.output / "fixture.elf", "public"])
        self.assertEqual(before.stdout, after.stdout)
        self.assertEqual(self.public_symbols["before"], self.public_symbols["candidate"])
        self.assertIn(b"Frame public behavior:", after.stdout)

    def test_private_contents_do_not_grant_lifecycle_authority(self):
        r = self.command("candidate-content", [self.output / "candidate", self.output / "fixture.elf", "content"])
        self.assertIn(b"Private content predicate only:", r.stdout)

    def test_specific_wrong_guards_have_semantic_failures(self):
        needle = "        || !active_state(STATES[slot])"
        wrapper = self.current.index("unsafe fn validate_frame_words(")
        content = self.content
        variants = {
            "missing-active": self.current[:wrapper] + self.current[wrapper:].replace(needle, "", 1),
            "missing-CS": self.current.replace(content, content.replace("volatile_load(frame + FRAME_CS) != 0x23", "false", 1), 1),
            "missing-SS": self.current.replace(content, content.replace("volatile_load(frame + FRAME_SS) != 0x1b", "false", 1), 1),
            "missing-rflags": self.current.replace(content, content.replace("(volatile_load(frame + FRAME_RFLAGS) & 2) == 0", "false", 1), 1),
            "native-stack-bypass": self.current.replace(content, content.replace("return stack_allows(ADDRESS_SPACE_HANDLES[slot], ordinal, stack);", "return true;", 1), 1),
        }
        for name, text in variants.items():
            with self.subTest(name=name):
                self.assertNotEqual(text, self.current)
                path = self.output / (name + ".oc")
                path.write_text(text)
                self.build(name, [*self.sources[:-1], path], True)
                self.command(name + "-rejected", [self.output / name, self.output / "fixture.elf", "public"], semantic_failure=True)


if __name__ == "__main__":
    unittest.main()
