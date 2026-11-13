"""Native O10 wire and exactly-once component checks.

Runs the real O-core codec/executor as an x86_64 executable. This does not
qualify AArch64 EL2 behavior, QEMU lifecycle reset, or guest regressions.
"""
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define C(n) _O_runtime__common__o10_codec__##n
#define E(n) _O_runtime__common__o10_executor__##n
extern uint64_t C(read)(const unsigned char*,size_t,size_t);
extern void C(write)(unsigned char*,size_t,uint64_t,size_t);
extern uint64_t C(validate)(const unsigned char*,size_t,size_t),C(bad_offset)(void);
extern size_t E(prepare)(const unsigned char*,size_t,unsigned char*,size_t);
extern uint64_t E(commit)(const unsigned char*,size_t),E(pending)(void),E(epoch)(void),E(last_seq)(void);
static unsigned char q[512],r[512],saved[64],old[64];
static uint64_t rd(const unsigned char*p,size_t n){return C(read)(p,0,n);}
static void st(unsigned char*p,uint64_t v,size_t n){C(write)(p,0,v,n);}
static void frame(unsigned t,size_t n,uint64_t epoch,uint64_t seq){
 memset(q,0,sizeof q);st(q,n,4);q[4]=t;st(q+5,77,2);
 if(t!=162){st(q+7,epoch,8);st(q+15,seq,8);}
}
static size_t prepare(size_t n){memset(r,0,sizeof r);return E(prepare)(q,n,r,sizeof r);}
static void err(size_t n,unsigned code){assert(prepare(n)==19);assert(r[4]==161&&rd(r+7,4)==code);}
int main(void){
 CORPUS
 // Negotiate actual executor versions before any Governor exists.
 frame(162,19,0,0);st(q+7,77,4);memcpy(q+11,"O10\0\0\0\0\0",8);
 err(19,2);assert(rd(r+11,8)==512&&E(epoch)()==0&&E(last_seq)()==0);
 st(q+7,512,4);q[13]='1';err(19,2);q[13]='0';
 st(q+7,78,4);assert(prepare(19)==35&&r[4]==163&&rd(r+7,4)==78);
 assert(rd(r+19,8)==0&&rd(r+27,8)==0);
 assert(!memcmp(r+11,"O10\0\0\0\0\0",8));
 st(q+7,0xffffffffU,4);assert(prepare(19)==35&&rd(r+7,4)==512);
 st(q+7,128,4);assert(prepare(19)==35&&rd(r+7,4)==128);
 st(q+7,512,4);assert(prepare(19)==35&&rd(r+7,4)==512);
 // Mutation requires a claimed Governor; rejection does not consume a sequence.
 frame(172,36,0,1);err(36,3);assert(E(last_seq)()==0);
 frame(164,39,0,1);st(q+23,1,8);assert(prepare(39)==31);
 assert(r[4]==165&&E(epoch)()==1&&E(last_seq)()==1);
 memcpy(old,q,39);memcpy(saved,r,31);
 assert(prepare(39)==31&&!memcmp(saved,r,31));
 q[5]++;err(39,4);memcpy(q,old,39);
 // Gaps and stale epochs are refused without advancing the journal.
 frame(172,36,1,3);err(36,4);
 frame(172,36,0,2);err(36,3);assert(E(last_seq)()==1);
 // External mutation is serialized; malformed completion cannot clear it.
 frame(170,47,1,2);assert(prepare(47)==0&&E(pending)()==1);
 unsigned char reply[15]={15,0,0,0,173,77,0};
 assert(E(commit)(reply,15)==0&&E(pending)()==1);
 reply[4]=171;reply[5]=78;assert(E(commit)(reply,15)==0);
 reply[5]=77;
 memcpy(old,q,47);
 frame(176,31,1,3);err(31,7);
 assert(E(commit)(reply,15)==1&&E(last_seq)()==2);
 memcpy(q,old,47);assert(prepare(47)==15&&!memcmp(r,reply,15));
 q[31]=1;err(47,4);
 // Failed dispatched mutations are journaled just like successful mutations.
 frame(176,31,1,3);assert(prepare(31)==0);
 unsigned char failure[19]={19,0,0,0,161,77,0,9};
 assert(E(commit)(failure,19)==1&&E(last_seq)()==3);
 assert(prepare(31)==19&&!memcmp(r,failure,19));
 // More than 256 outcomes evict old entries; old mutations never dispatch.
 for(uint64_t seq=4;seq<=260;seq++){
  frame(176,31,1,seq);assert(prepare(31)==0);
  unsigned char done[15]={15,0,0,0,177,77,0};
  assert(E(commit)(done,15)==1);
 }
 frame(166,31,1,0);st(q+23,1,8);assert(prepare(31)>0&&r[4]==167&&r[7]==3);
 frame(166,31,1,0);st(q+23,260,8);assert(prepare(31)>0&&r[4]==167&&r[7]==1);
 frame(176,31,1,1);err(31,4);
 frame(164,39,1,261);st(q+23,2,8);st(q+31,0,8);err(39,3);
 assert(E(last_seq)()==261&&E(epoch)()==1);
 assert(prepare(39)==19&&rd(r+7,4)==3);
 frame(164,39,1,262);st(q+23,2,8);st(q+31,1,8);
 assert(prepare(39)==31&&E(epoch)()==2&&E(last_seq)()==262);
 frame(176,31,1,260);assert(prepare(31)==15&&r[4]==177);
 frame(176,31,1,263);err(31,3);
 // Independent little-endian vectors catch high-word truncation in both APIs.
 const unsigned char wide_bytes[8]={0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01};
 assert(C(read)(wide_bytes,0,8)==UINT64_C(0x0123456789abcdef));
 unsigned char written[10]={0xaa,0,0,0,0,0,0,0,0,0xbb};
 C(write)(written,1,UINT64_C(0x0123456789abcdef),8);
 assert(written[0]==0xaa&&written[9]==0xbb&&!memcmp(written+1,wide_bytes,8));
 // A wide epoch survives claim/reply/version, and a low-word alias is stale.
 frame(164,39,2,263);st(q+23,UINT64_C(0x123456789abcdef0),8);st(q+31,2,8);
 assert(prepare(39)==31&&E(epoch)()==UINT64_C(0x123456789abcdef0)&&E(last_seq)()==263);
 const unsigned char epoch_bytes[8]={0xf0,0xde,0xbc,0x9a,0x78,0x56,0x34,0x12};
 assert(!memcmp(r+7,epoch_bytes,8));memcpy(old,q,39);memcpy(saved,r,31);
 assert(prepare(39)==31&&!memcmp(saved,r,31));
 frame(176,31,UINT64_C(0x9abcdef0),264);err(31,3);assert(!memcmp(r+11,epoch_bytes,8));
 frame(176,31,UINT64_C(0x123456789abcdef0),UINT64_C(0x100000108));
 err(31,4);assert(rd(r+11,8)==263&&E(last_seq)()==263);
 frame(176,31,UINT64_C(0x123456789abcdef0),264);assert(prepare(31)==0);
 unsigned char wide_reply[15]={15,0,0,0,177,77,0,0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01};
 assert(E(commit)(wide_reply,15)==1&&E(last_seq)()==264);
 assert(prepare(31)==15&&!memcmp(r,wide_reply,15));
 // Same journal slot under a high-word query is NOT_APPLIED, never replayed.
 frame(166,31,UINT64_C(0x123456789abcdef0),0);st(q+23,UINT64_C(0x100000108),8);
 assert(prepare(31)==14&&r[7]==0&&rd(r+12,2)==0);
 st(q+23,264,8);assert(prepare(31)==29&&r[7]==1&&!memcmp(r+14,wide_reply,15));
 frame(162,19,0,0);st(q+7,512,4);memcpy(q+11,"O10\0\0\0\0\0",8);
 assert(prepare(19)==35&&!memcmp(r+19,epoch_bytes,8)&&rd(r+27,8)==264);
 puts("O10 native corpus and journal PASS");return 0;
}
"""

class O10NativeTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                         "unqualified: native harness requires Linux x86_64")
    def test_wire_corpus_and_exactly_once_journal(self):
        compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec"))
        clang = shutil.which("clang")
        self.assertTrue(compiler.is_file(), "existing OCOREC_BIN required; missing tools do not qualify")
        self.assertIsNotNone(clang, "clang required; missing tools do not qualify")
        spec = importlib.util.spec_from_file_location("o10_test_corpus", ROOT / "tests/test_o10_codec.py")
        corpus = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(corpus)
        statements = []
        for index, wire in enumerate(corpus.fixtures()):
            data = ",".join(str(byte) for byte in wire)
            statements.append(f"unsigned char f{index}[]={{ {data} }};")
            statements.append(f"assert(C(validate)(f{index},sizeof f{index},512)==1);")
            statements.append(f"memset(r,0,512);for(size_t i=0;i<sizeof f{index};i++) C(write)(r,i,C(read)(f{index},i,1),1);")
            statements.append(f"assert(!memcmp(r,f{index},sizeof f{index}));")
            statements.append(f"assert(C(validate)(f{index},sizeof f{index}-1,512)==0);")
            if wire[4] != corpus.codec.O10_RLSTAT:
                # Rewrite the outer size too: these reach message-body bounds.
                statements.append(f"unsigned char short{index}[sizeof f{index}];memcpy(short{index},f{index},sizeof f{index});")
                statements.append(f"C(write)(short{index},0,sizeof f{index}-1,4);assert(C(validate)(short{index},sizeof f{index}-1,512)==0);")
                statements.append(f"unsigned char extra{index}[sizeof f{index}+1];memcpy(extra{index},f{index},sizeof f{index});extra{index}[sizeof f{index}]=0;")
                statements.append(f"C(write)(extra{index},0,sizeof extra{index},4);assert(C(validate)(extra{index},sizeof extra{index},512)==0);")
        statements.extend([
            "frame(100,7,0,0);assert(C(validate)(q,7,512)==0);",
            "frame(178,31,1,1);assert(C(validate)(q,31,512)==0&&C(bad_offset)()==15);",
            # Actual 513 accessible bytes and a matching header, not a header mismatch.
            "unsigned char oversized[513]={0};C(write)(oversized,0,513,4);oversized[4]=191;assert(C(validate)(oversized,sizeof oversized,512)==0);",
            "assert(C(validate)(oversized,sizeof oversized,513)==0);",
            "unsigned char flush[7]={7,0,0,0,195,0,0};assert(C(validate)(flush,7,7)==1);",
            "assert(C(validate)(flush,7,513)==0&&C(bad_offset)()==0);",
            "assert(C(validate)(flush,7,6)==0);",
            "frame(191,512,0,0);assert(C(validate)(q,512,512)==1);",
            # Length-correct variable bodies with inconsistent embedded lengths/counts.
            "unsigned char outcome[21]={21,0,0,0,167,0,0,1,0,0,0,0,7,0,7,0,0,0,195,0,0};",
            "assert(C(validate)(outcome,21,512)==1);outcome[12]=8;assert(C(validate)(outcome,21,512)==0);",
            "outcome[12]=6;assert(C(validate)(outcome,21,512)==0);",
            "unsigned char wait[65]={65,0,0,0,193,0,0};wait[15]=1;assert(C(validate)(wait,65,512)==1);",
            "wait[15]=2;assert(C(validate)(wait,65,512)==0);wait[15]=0;assert(C(validate)(wait,65,512)==0);",
            "wait[15]=1;wait[29]=1;assert(C(validate)(wait,65,512)==0&&C(bad_offset)()==29);",
        ])
        with tempfile.TemporaryDirectory(prefix="o10-native-") as directory:
            output = Path(directory)
            (output / "harness.c").write_text(HARNESS.replace("CORPUS", "\n".join(statements)))
            commands = [
                [str(compiler), str(ROOT / "ocore/runtime/common/o10_codec.oc"),
                 str(ROOT / "ocore/runtime/common/o10_executor.oc"), "--target",
                 "x86_64-unknown-none", "--emit", "obj", "-o", str(output / "native.o")],
                [clang, "-O2", "-no-pie", str(output / "harness.c"), str(output / "native.o"),
                 "-o", str(output / "selftest")],
                [str(output / "selftest")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=120)
                if os.environ.get("O10_COMMAND_LOG"):
                    with open(os.environ["O10_COMMAND_LOG"], "a") as log:
                        log.write(json.dumps({"argv": command, "returncode": result.returncode,
                                              "stdout": result.stdout, "stderr": result.stderr}) + "\n")
                self.assertEqual(result.returncode, 0, " ".join(command) + "\n" + result.stdout + result.stderr)

if __name__ == "__main__":
    unittest.main()
