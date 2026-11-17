"""Eight vGIC banks and explicit transport ownership: native component proof.

The production O-core module executes on x86-64 with saved-register hooks
modeled by C, and lowers to an AArch64 object. Whole-kernel M3 qualification
requires the separate three-domain gate.
"""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from tests import test_unified_gic as BASE
from tests import test_unified_gic_hotpath as HOT

ROOT = Path(__file__).resolve().parents[1]

INSPECTION = HOT.INSPECTION.replace("    return BAD;\n}", """    if kind == 5 { return CONFIGURED[domain as usize]; }
    if kind == 6 { return BINDING_GENERATION[domain as usize]; }
    if kind == 7 { return DIRTY[domain as usize]; }
    if kind == 23 { return CACHE[slot(domain,index)]; }
    if kind == 30 { return TRANSPORT_IRQS[(domain * 4 + index) as usize]; }
    return BAD;
}""")

PREFIX = BASE.HARNESS.split("static void driver_registers", 1)[0]
PREFIX = PREFIX.replace("banks[2][16],vmcr[2],hcr[2]", "banks[8][16],vmcr[8],hcr[8]")
PREFIX = PREFIX.replace("d<2", "d<8").replace("forbidden_domain=2", "forbidden_domain=8")

HARNESS = PREFIX + r"""
extern uint64_t G(binding_generation)(uint64_t);
extern uint64_t G(transport_irqs)(uint64_t,uint64_t,uint64_t);
extern uint64_t G(unconfigure)(uint64_t,uint64_t);
extern uint64_t G(set_transport_level)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t G(test_inspect)(uint64_t,uint64_t,uint64_t);
static uint64_t generation(unsigned d){return 10+d;}
static unsigned capture(unsigned d,uint64_t *out){
 unsigned n=0;
 for(unsigned kind=1;kind<=7;kind++)out[n++]=G(test_inspect)(d,kind,0);
 for(unsigned kind=10;kind<=18;kind++)
  for(unsigned irq=0;irq<64;irq++)out[n++]=G(test_inspect)(d,kind,irq);
 for(unsigned irq=0;irq<64;irq++)out[n++]=G(test_inspect)(d,20,irq);
 for(unsigned kind=21;kind<=23;kind++)
  for(unsigned lr=0;lr<16;lr++)out[n++]=G(test_inspect)(d,kind,lr);
 for(unsigned t=0;t<4;t++)out[n++]=G(test_inspect)(d,30,t);
 for(unsigned lr=0;lr<16;lr++)out[n++]=banks[d][lr];
 out[n++]=vmcr[d];out[n++]=hcr[d];assert(n<=768);return n;
}
static uint64_t before[8][768],after[8][768];
static void capture_all(uint64_t (*out)[768]){
 for(unsigned d=0;d<8;d++)assert(capture(d,out[d])==capture(0,out[0]));
}
static void same_all_except(unsigned excluded){
 for(unsigned d=0;d<8;d++)if(d!=excluded)
  assert(!memcmp(before[d],after[d],sizeof(before[d])));
}
static void closed_and_bad_configuration(void){
 assert(G(init)()==1);
 for(unsigned d=0;d<8;d++){
  assert(!G(healthy)(d)&&!G(binding_generation)(d));
  assert(!G(reset)(d)&&!G(set_level)(d,50,1));
  assert(G(mmio_read)(d,D,4)==UINT64_MAX);
 }
 assert(!G(configure)(8,1,1ull<<50,0,0,0));
 assert(!G(configure)(UINT64_MAX,1,1ull<<50,0,0,0));
 capture_all(before);uint64_t old_writes=writes;
 assert(!G(configure)(7,0,1ull<<50,0,0,0));
 assert(!G(configure)(7,1ull<<32,1ull<<50,0,0,0));
 assert(!G(configure)(7,1,1ull<<50,1ull<<50,0,0));
 assert(!G(configure)(7,1,1ull<<27,0,0,0));
 capture_all(after);same_all_except(8);assert(writes==old_writes);
 assert(!G(binding_generation)(8)&&!G(transport_irqs)(8,1,0));
 puts("eight closed banks and atomic checked configuration: PASS");
}
static void configure_all_and_isolate(void){
 for(unsigned d=0;d<8;d++){
  assert(G(configure)(d,generation(d),1ull<<50,1ull<<48,0,1ull<<33));
  assert(G(binding_generation)(d)==generation(d));
  assert(G(transport_irqs)(d,generation(d),0)==(1ull<<50));
  assert(!G(transport_irqs)(d,generation(d)-1,0));
  assert(!G(transport_irqs)(d,generation(d),4));
  ready(d);enable(d,50);
 }
 capture_all(before);uint64_t old_writes=writes;
 for(unsigned d=0;d<8;d++){
  assert(!G(configure)(d,generation(d)+1,1ull<<50,0,0,0));
  assert(!G(set_transport_level)(d,generation(d)-1,0,50,1));
  assert(!G(set_transport_level)(d,generation(d),1,50,1));
  assert(!G(set_transport_level)(d,generation(d),4,50,1));
  assert(!G(set_transport_level)(d,generation(d),0,64,1));
 }
 capture_all(after);same_all_except(8);assert(writes==old_writes);
 for(unsigned d=0;d<8;d++){
  assert(G(set_transport_level)(d,generation(d),0,50,1));poll_(d);
  assert(entries(d)==1&&state(d,50)==1);
  for(unsigned other=d+1;other<8;other++)assert(entries(other)==0);
 }
 puts("explicit namespace transport0 and eight isolated same-number IRQs: PASS");
}
static void target_reset_and_generation_reuse(void){
 for(unsigned d=0;d<8;d++){ack(d,50);poll_(d);assert(state(d,50)==2);}
 capture_all(before);uint64_t old_writes=writes;
 assert(G(reset)(7));capture_all(after);
 same_all_except(7);assert(writes==old_writes+count);
 assert(G(binding_generation)(7)==generation(7)&&entries(7)==0);
 assert(G(transport_irqs)(7,generation(7),0)==(1ull<<50));
 capture_all(before);old_writes=writes;
 assert(!G(unconfigure)(7,generation(7)-1));
 capture_all(after);same_all_except(8);assert(writes==old_writes);
 assert(G(unconfigure)(7,generation(7)));assert(!G(healthy)(7)&&!G(binding_generation)(7));
 assert(!G(configure)(7,generation(7),1ull<<50,0,0,0));
 assert(!G(set_transport_level)(7,generation(7),0,50,1));
 assert(G(configure)(7,generation(7)+1,1ull<<50,0,0,1ull<<33));
 assert(!G(set_transport_level)(7,generation(7),0,50,1));
 ready(7);enable(7,50);poll_(7);assert(entries(7)==0);
 assert(G(set_transport_level)(7,generation(7)+1,0,50,1));poll_(7);
 assert(entries(7)==1&&state(7,50)==1);
 capture_all(after);same_all_except(7);
 puts("target-only reset, monotonic binding reuse and stale-owner denial: PASS");
}
int main(void){
 closed_and_bad_configuration();configure_all_and_isolate();target_reset_and_generation_reuse();
 puts("eight-domain production vGIC ownership: PASS");return 0;
}
"""

@unittest.skipUnless(platform.system()=="Linux" and platform.machine()=="x86_64",
                     "native register-model profile requires Linux x86-64")
class DomainBankTests(unittest.TestCase):
    def test_actual_eight_gic_banks_transport_ownership_and_target_reset(self):
        compiler=Path(os.environ.get("OCOREC_BIN",ROOT/"target/debug/ocorec"))
        clang=shutil.which("clang")
        if not compiler.is_file() or not clang:
            self.skipTest("existing ocorec and clang required")
        with tempfile.TemporaryDirectory(prefix="o10-eight-gic-") as directory:
            out=Path(directory);source=out/"observed.oc"
            source.write_text((ROOT/"ocore/runtime/aarch64/unified_gic.oc").read_text()+INSPECTION)
            (out/"fixture.c").write_text(HARNESS)
            commands=[
                [str(compiler),str(ROOT/"ocore/runtime/aarch64/unified_gic.oc"),"--target","aarch64-unknown-none","--emit","obj","-o",str(out/"arm.o")],
                [str(compiler),str(source),"--target","x86_64-unknown-none","--emit","obj","-o",str(out/"native.o")],
                [clang,"-O2","-no-pie",str(out/"fixture.c"),str(out/"native.o"),"-o",str(out/"test")],
                [str(out/"test")]]
            for command in commands:
                result=subprocess.run(command,capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn("eight-domain production vGIC ownership: PASS",result.stdout)

if __name__=="__main__":unittest.main()
