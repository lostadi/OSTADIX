"""Wire-preserving typed-core extraction against the exact previous store.

Both complete production stores execute as native x86-64 objects. The fixture
changes only the historical module name and ELF symbol visibility, allowing a
byte comparison of the whole volume and authoritative session/fid state after
every operation. No C model implements store policy. All callers remain wire
clients in this checkpoint; this is not a local-backend or guest-boot proof.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from tests import test_namespace_store as WIRE

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tests/fixtures/namespace_store_before_local.oc.txt"
BASELINE_SHA256 = "13cffe0c19b455314f23e8a53914b585ba43d19d606c07c3f6706793c5f41c53"
SYMBOL = "_O_runtime__common__namespace_store__"
OLD_SYMBOL = "_O_runtime__common__namespace_store_baseline__"
STATE = ("READY", "EPOCH", "SERIAL", "CLOCK", "USED", "FREE_BLOCKS",
         "SESSION", "GENERATION", "VERSIONED", "MSIZE", "F_SESSION",
         "F_NUMBER", "F_OBJECT", "F_GENERATION", "F_MODE")

PAIR = r'''
#define REF(n) _O_runtime__common__namespace_store_baseline__##n
#define NEW(n) _O_runtime__common__namespace_store__##n
#define DECLARE(P) \
 extern uint64_t P(init)(uintptr_t,size_t,uint64_t),P(healthy)(void); \
 extern uint64_t P(session_init)(uint64_t,uint64_t),P(revoke)(uint64_t),P(provision_clock)(uint64_t); \
 extern uint64_t P(session_claim)(uint64_t,uint64_t,uint64_t),P(session_is_current)(uint64_t,uint64_t),P(revoke_if_current)(uint64_t,uint64_t); \
 extern size_t P(handle)(uint64_t,const uint8_t*,size_t,uint8_t*,size_t); \
 extern uint64_t P(READY),P(EPOCH),P(SERIAL),P(CLOCK); \
 extern uint8_t P(USED)[3999],P(VERSIONED)[5]; \
 extern size_t P(FREE_BLOCKS),P(MSIZE)[5],P(F_OBJECT)[512]; \
 extern uint64_t P(SESSION)[5],P(GENERATION)[5],P(F_SESSION)[512],P(F_NUMBER)[512],P(F_GENERATION)[512],P(F_MODE)[512];
DECLARE(REF)
DECLARE(NEW)
static uint8_t *pair_original,*pair_candidate;
static uint64_t pair_operations,pair_states;
#define SAME(n) do { if(memcmp(&NEW(n),&REF(n),sizeof NEW(n))){fprintf(stderr,"state differs: %s at operation %llu\n",#n,(unsigned long long)pair_operations);abort();} }while(0)
static void pair_state(void){
 SAME(READY);SAME(EPOCH);SAME(SERIAL);SAME(CLOCK);SAME(USED);SAME(FREE_BLOCKS);
 SAME(SESSION);SAME(GENERATION);SAME(VERSIONED);SAME(MSIZE);SAME(F_SESSION);
 SAME(F_NUMBER);SAME(F_OBJECT);SAME(F_GENERATION);SAME(F_MODE);
 if(pair_original)assert(!memcmp(pair_original,pair_candidate,16777216));
 pair_states++;
}
uint64_t PAIR_init(uintptr_t address,size_t length,uint64_t epoch){
 assert(length==16777216);
 if(!pair_candidate){pair_candidate=mmap(NULL,length,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(pair_candidate!=MAP_FAILED);}
 pair_original=(uint8_t*)address;
 // The historical fixtures deliberately corrupt/migrate backing bytes before
 // init. Apply the identical external input to both stores; prior operation
 // effects have already been compared byte-for-byte, never copied over here.
 memcpy(pair_candidate,pair_original,length);
 uint64_t a=REF(init)(address,length,epoch),b=NEW(init)((uintptr_t)pair_candidate,length,epoch);
 pair_operations++;assert(a==b);pair_state();return a;
}
uint64_t PAIR_healthy(void){uint64_t a=REF(healthy)(),b=NEW(healthy)();assert(a==b);pair_state();return a;}
uint64_t PAIR_provision_clock(uint64_t x){uint64_t a=REF(provision_clock)(x),b=NEW(provision_clock)(x);pair_operations++;assert(a==b);pair_state();return a;}
uint64_t PAIR_session_init(uint64_t g,uint64_t e){uint64_t a=REF(session_init)(g,e),b=NEW(session_init)(g,e);pair_operations++;assert(a==b);pair_state();return a;}
uint64_t PAIR_revoke(uint64_t g){uint64_t a=REF(revoke)(g),b=NEW(revoke)(g);pair_operations++;assert(a==b);pair_state();return a;}
uint64_t PAIR_session_claim(uint64_t g,uint64_t e,uint64_t old){uint64_t a=REF(session_claim)(g,e,old),b=NEW(session_claim)(g,e,old);pair_operations++;assert(a==b);pair_state();return a;}
uint64_t PAIR_session_is_current(uint64_t g,uint64_t old){uint64_t a=REF(session_is_current)(g,old),b=NEW(session_is_current)(g,old);pair_operations++;assert(a==b);pair_state();return a;}
uint64_t PAIR_revoke_if_current(uint64_t g,uint64_t old){uint64_t a=REF(revoke_if_current)(g,old),b=NEW(revoke_if_current)(g,old);pair_operations++;assert(a==b);pair_state();return a;}
size_t PAIR_handle(uint64_t session,const uint8_t *request,size_t length,uint8_t *response,size_t capacity){
 uint8_t input[8192],output[8192];
 if(request)memcpy(input,request,length<sizeof input?length:sizeof input);
 if(response)memcpy(output,response,sizeof output);
 const uint8_t *candidate_request=request?input:NULL;
 if(request==response&&request){memcpy(output,response,sizeof output);candidate_request=output;}
 size_t a=REF(handle)(session,request,length,response,capacity);
 size_t b=NEW(handle)(session,candidate_request,length,response?output:NULL,capacity);
 pair_operations++;
 if(a!=b||(response&&memcmp(response,output,sizeof output))){fprintf(stderr,"wire differs: operation %llu kind %u cap %zu lengths %zu/%zu\n",(unsigned long long)pair_operations,request?request[4]:0,capacity,a,b);abort();}
 pair_state();return a;
}
#define NS(name) PAIR_##name
'''

EXTRA = r'''
static void barriers(void){
 uint64_t s=session(1);assert(walk(s,1,2,"work")==111);
 const uint8_t bytes[]={0,0xff,'a',0x11,0x13,'z'};
 // Every response capacity around success and Rerror sizes. Failed create
 // leaves the fid unopened; retrying it must create exactly one object.
 for(size_t cap=0;cap<=40;cap++){
  char name[32];snprintf(name,sizeof name,"cap-%02zu",cap);
  assert(walk(s,2,3,NULL)==111);unsigned kind;
  if(cap<24){assert(create(s,3,name,0644,2)==115);assert(removefid(s,3)==123);assert(walk(s,2,3,NULL)==111);}
  begin(114);put(3,4);str(name);put(0644,4);put(2,1);kind=callcap(s,cap);
  if(cap<24){assert(kind==0);assert(create(s,3,name,0644,2)==115);}else assert(kind==115);
  assert(writefid(s,3,9,bytes,sizeof bytes,10)==0);
  assert(readfid(s,3,0,100)==117&&rd(response+7,4)==0);
  assert(writefid(s,3,9,bytes,sizeof bytes,11)==119);
  // Exact regular-read clamp by both MSIZE and response capacity, then EOF.
  begin(116);put(3,4);put(9,8);put(UINT32_MAX,4);kind=callcap(s,cap);
  if(cap<11)assert(kind==0);else{size_t n=cap-11;if(n>sizeof bytes)n=sizeof bytes;assert(kind==117&&rd(response+7,4)==n&&!memcmp(response+11,bytes,n));}
  assert(clunk(s,3)==121);
  assert(walk(s,2,3,name)==111);
  begin(112);put(3,4);put(0x12,1);kind=callcap(s,cap);
  if(cap<24){assert(kind==0);assert(openfid(s,3,0)==113);assert(readfid(s,3,9,sizeof bytes)==117&&rd(response+7,4)==sizeof bytes);}else{assert(kind==113&&readfid(s,3,0,1)==117&&rd(response+7,4)==0);}
  assert(clunk(s,3)==121);
 }
 // Multiwalk parses later components even after a miss; incomplete input
 // returns protocol error without binding or replacing either destination.
 begin(110);put(1,4);put(20,4);put(3,2);str("work");str("absent");put(4,2);put('x',1);assert(call(s)==107);
 assert(statfid(s,20)==107);
 begin(110);put(1,4);put(1,4);put(2,2);str("work");str("absent");assert(call(s)==111&&rd(response+7,2)==1);
 assert(walk(s,1,20,"work")==111&&clunk(s,20)==121); // original root fid survives partial same-fid walk
 uint64_t peer=session(2),ro=session(3),uart=session(4);
 assert(walk(peer,1,2,"..")==111&&walk(peer,2,3,"pkg")==107);
 assert(walk(ro,1,2,NULL)==111&&create(ro,2,"denied",0644,1)==107);
 assert(walk(uart,1,2,"work")==111&&walk(uart,2,3,"cap-00")==111&&openfid(uart,3,0)==113);
 assert(NS(revoke_if_current)(4,uart+1)==0&&readfid(uart,3,9,sizeof bytes)==117);
 assert(NS(session_claim)(4,100,uart+1)==0&&readfid(uart,3,9,sizeof bytes)==117);
 uint64_t replacement=NS(session_claim)(4,100,uart);assert(replacement&&replacement!=uart&&readfid(uart,3,0,1)==107);
 handshake(replacement,1,"");assert(NS(revoke_if_current)(4,uart)==0&&NS(session_is_current)(4,replacement)==1);
 assert(NS(revoke_if_current)(4,replacement)==1&&NS(session_is_current)(4,replacement)==0);
}
static void frame_matrix(void){
 uint64_t s=session(1);assert(walk(s,1,2,"work")==111&&create(s,2,"frames",0644,2)==115);
 uint8_t data[8169];for(size_t n=0;n<sizeof data;n++)data[n]=(uint8_t)(n^0x93);
 // msize8192 permits only8169 payload bytes, and read replies only8181.
 assert(writefid(s,2,0,data,sizeof data,8192)==119);
 assert(readfid(s,2,0,UINT32_MAX)==117&&rd(response+7,4)==sizeof data&&!memcmp(response+11,data,sizeof data));
 assert(writefid(s,2,UINT64_MAX,data,1,8192)==107);
 begin(100);put(256,4);str("9P2000");assert(call(s)==101&&rd(response+7,4)==256);
 begin(104);put(1,4);put(UINT32_MAX,4);str("root");str("");assert(call(s)==105);
 assert(walk(s,1,2,"work")==111&&walk(s,2,3,"frames")==111&&openfid(s,3,2)==113);
 assert(readfid(s,3,0,UINT32_MAX)==117&&rd(response+7,4)==245&&!memcmp(response+11,data,245));
 assert(writefid(s,3,0,data,233,11)==119);
 assert(writefid(s,3,0,data,234,8192)==107); // MSIZE request cap, no partial mutation
 begin(118);put(3,4);put(0,8);put(232,4);memcpy(request+pos,data,233);pos+=233;assert(call(s)==107);
 // All truncations and output-capacity boundaries of a valid Twrite.
 begin(118);put(3,4);put(7,8);put(17,4);memcpy(request+pos,data,17);pos+=17;
 uint8_t frame[128];size_t full=pos;memcpy(frame,request,full);
 for(size_t n=0;n<=full;n++)for(size_t cap=0;cap<=36;cap++){
  memcpy(request,frame,full);pos=n;callcap(s,cap);
 }
 // A declared-length mismatch is rejected before session lookup; unsupported
 // types, invalid sessions and every one-bit payload mutation use both stores.
 uint64_t rng=0x13579bdf;
 for(unsigned trial=0;trial<2048;trial++){
  memcpy(request,frame,full);pos=full;rng=rng*6364136223846793005ULL+1;
  size_t at=(rng>>32)%full;request[at]^=(uint8_t)(1u<<(trial%8));
  callcap(trial%5?s:UINT64_MAX,trial%41);
 }
 memcpy(request,frame,full);st(request,full+1,4);
 assert(NS(handle)(s,request,full,response,sizeof response)>0&&response[4]==107);
 // Renegotiation with insufficient output capacity must retain open fids.
 begin(100);put(8192,4);str("9P2000");assert(callcap(s,18)==0);
 assert(readfid(s,3,0,1)==117);
 assert(NS(provision_clock)(UINT32_MAX-1)==1);
 assert(writefid(s,3,0,data,0,8192)==107); // zero Twrite still checks clock exhaustion
 assert(walk(s,2,4,"frames")==111);
 begin(112);put(4,4);put(0x12,1);assert(callcap(s,23)==0); // capacity precedes truncation clock error
 assert(openfid(s,4,0x12)==107);
}
'''


def _harness():
    text = WIRE.HARNESS.replace("#define NS(name) _O_runtime__common__namespace_store__##name", PAIR)
    # The added mutation matrix also changes request tags. The reference
    # fixture's fixed-tag assertion must compare the actual submitted tag.
    text = text.replace("rd(response+5,2)==0x1234", "rd(response+5,2)==rd(request+5,2)")
    text = text.replace("int main(int argc,char **argv) {", EXTRA + "\nint main(int argc,char **argv) {")
    text = text.replace('    printf("native namespace scenario',
                        '    if(scenario==14)barriers();\n    if(scenario==15)frame_matrix();\n'
                        '    printf("paired operations=%llu whole-volume/state comparisons=%llu\\n",(unsigned long long)pair_operations,(unsigned long long)pair_states);\n'
                        '    printf("native namespace scenario')
    return text


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "actual production-object fixture requires Linux x86_64")
class NamespaceTypedCoreTests(unittest.TestCase):
    def test_wire_and_authoritative_state_match_previous_store(self):
        compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec"))
        clang, objcopy = shutil.which("clang"), shutil.which("objcopy")
        if not compiler.is_file() or not clang or not objcopy:
            self.skipTest("already-built ocorec, clang and objcopy are required")
        baseline = BASELINE.read_bytes()
        self.assertEqual(hashlib.sha256(baseline).hexdigest(), BASELINE_SHA256)
        keep = os.environ.get("OCORE_NAMESPACE_LOCAL_TEST_OUTPUT")
        temporary = None if keep else tempfile.TemporaryDirectory(prefix="namespace-typed-core-")
        output = Path(keep or temporary.name)
        output.mkdir(parents=True, exist_ok=True)
        try:
            (output / "baseline.oc").write_bytes(baseline.replace(b"module runtime::common::namespace_store;", b"module runtime::common::namespace_store_baseline;", 1))
            (output / "harness.c").write_text(_harness())
            source = ROOT / "ocore/runtime/common/namespace_store.oc"
            commands = []
            for label, path, symbol in (("baseline", output / "baseline.oc", OLD_SYMBOL), ("current", source, SYMBOL)):
                commands.extend([
                    [str(compiler), str(path), "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(output / f"{label}.arm.mir")],
                    [str(compiler), str(path), "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(output / f"{label}.o")],
                    [objcopy, *["--globalize-symbol=" + symbol + name for name in STATE], str(output / f"{label}.o"), str(output / f"{label}.inspectable.o")],
                ])
            commands.append([clang, "-O2", "-no-pie", str(output / "harness.c"), str(output / "baseline.inspectable.o"), str(output / "current.inspectable.o"), "-o", str(output / "selftest")])
            records = []
            for index, command in enumerate(commands):
                result = subprocess.run(command, capture_output=True, text=True, timeout=120)
                (output / f"build-{index}.log").write_text(result.stdout + result.stderr)
                records.append({"command": command, "exit_code": result.returncode})
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for scenario in range(16):
                with self.subTest(scenario=scenario):
                    result = subprocess.run([str(output / "selftest"), str(scenario)], capture_output=True, text=True, timeout=120)
                    (output / f"scenario-{scenario}.log").write_text(result.stdout + result.stderr)
                    records.append({"scenario": scenario, "exit_code": result.returncode, "stdout": result.stdout})
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            (output / "results.json").write_text(json.dumps({"commands_and_cases": records, "baseline_sha256": BASELINE_SHA256, "current_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}, indent=2) + "\n")
        finally:
            if temporary:
                temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
