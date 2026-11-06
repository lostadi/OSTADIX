"""Production directory-fid semantics and actual service polling policy.

Native O-core store objects are executed; the service scan loop and C nextscan
policy are taken verbatim from p9cmdsrv.c with mount-client hooks. This fixture does not boot original userland, measure
wall-clock guest latency, or qualify full-system efficiency.
"""
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import unittest

from tests.test_namespace_store import HARNESS as STORE_HARNESS

ROOT = Path(__file__).resolve().parents[1]
CASES = r'''
static unsigned listing(uint64_t s,unsigned fid) {
    assert(readfid(s,fid,0,8192)==117);
    size_t end=11+rd(response+7,4),at=11;unsigned names=0;
    while(at<end) {
        size_t size=rd(response+at,2)+2,n=rd(response+at+41,2);
        assert(size>=64 && at+size<=end);
        if(n==5 && !memcmp(response+at+43,"ready",5))names|=1;
        if(n==3 && !memcmp(response+at+43,"one",3))names|=2;
        if(n==3 && !memcmp(response+at+43,"two",3))names|=4;
        at+=size;
    }
    assert(at==end);return names;
}
static void rootdir(uint64_t s) {
    assert(walk(s,1,2,"services")==111);
    assert(create(s,2,"polling",0x80000000u|0755,0)==115 && clunk(s,2)==121);
    assert(walk(s,1,2,"services")==111 && walk(s,2,2,"polling")==111);
    assert(walk(s,2,3,NULL)==111 && create(s,3,"ready",0644,1)==115);
    assert(writefid(s,3,0,"ready",5,11)==119 && clunk(s,3)==121);
}
static uint64_t provider(void) {
    uint64_t s=session(4);
    assert(walk(s,1,2,"services")==111 && walk(s,2,3,"polling")==111);
    assert(walk(s,3,6,NULL)==111 && openfid(s,6,0)==113);return s;
}
static void freshness(void) {
    uint64_t l=session(1);rootdir(l);uint64_t p=provider();
    assert(listing(p,6)==1);
    assert(walk(l,2,4,NULL)==111 && create(l,4,"one",0x80000000u|0755,0)==115 && clunk(l,4)==121);
    assert(walk(l,2,4,"one")==111);
    assert(listing(p,6)==3);
    assert(walk(p,3,4,"one")==111 && walk(p,4,5,"submit")==107);
    /* A submit inside an existing request directory does not change its
       parent listing: persistent fid + fresh scans must still discover it. */
    assert(walk(l,4,5,NULL)==111 && create(l,5,"submit",0644,1)==115);
    assert(writefid(l,5,0,"commit",6,11)==119 && clunk(l,5)==121);
    assert(listing(p,6)==3 && walk(p,4,5,"submit")==111 && clunk(p,5)==121);
    assert(walk(l,4,5,"submit")==111 && removefid(l,5)==123 && removefid(l,4)==123);
    assert(listing(p,6)==1);
    assert(walk(l,2,4,NULL)==111 && create(l,4,"two",0x80000000u|0755,0)==115);
    assert(listing(p,6)==5);
    assert(NS(revoke)(4)==1 && readfid(p,6,0,8192)==107);
    puts("retained directory fid sees create/late-submit/remove/create; revoked fid errors: PASS");
}
static void service_loop(void);
static uint64_t fixture_provider,fixture_linux;
static unsigned fixture_activity,fixture_published,fixture_admitted,fixture_after_active;
static unsigned fixture_time,fixture_scans,fixture_fd;
static uint64_t fixture_offset;
static jmp_buf fixture_finish;
static void scans(void) {
    uint64_t l=session(1);rootdir(l);uint64_t p=provider();
    unsigned before_requests=requests;uint64_t before_bytes=wirebytes;
    unsigned scans=0;
    /* Old service: walk/open/read-to-EOF/clunk on each 50ms scan. */
    for(unsigned time=0;time<5000;time+=50) {
        assert(walk(p,3,4,NULL)==111 && openfid(p,4,0)==113);
        assert(readfid(p,4,0,8192)==117);unsigned length=rd(response+7,4);
        assert(length && readfid(p,4,length,8192)==117 && rd(response+7,4)==0);
        assert(clunk(p,4)==121);scans++;
    }
    unsigned oldrequests=requests-before_requests;uint64_t oldbytes=wirebytes-before_bytes;
    assert(scans==100 && oldrequests==500);
    before_requests=requests;before_bytes=wirebytes;
    fixture_provider=p;fixture_time=fixture_scans=0;fixture_fd=0;
    /* The actual production loop drives native 9P calls through the fixture
       mount-client hooks below; only invocation execution is out of scope. */
    if(setjmp(fixture_finish)==0)service_loop();
    scans=fixture_scans;
    unsigned newrequests=requests-before_requests;uint64_t newbytes=wirebytes-before_bytes;
    assert(scans==22 && newrequests==46 && newrequests<oldrequests/10);
    assert(nextscan(250,1)==50 && nextscan(50,0)==100 && nextscan(100,0)==200 && nextscan(200,0)==250);
    int delay=250;for(unsigned i=0;i<10000;i++){delay=nextscan(delay,0);assert(delay==250);}
    printf("5s policy-driven native 9P workload: old=%u requests/%llu bytes; new=%u requests/%llu bytes; max idle delay250ms; active reset50ms: PASS\n",
        oldrequests,(unsigned long long)oldbytes,newrequests,(unsigned long long)newbytes);
}
typedef struct Dir Dir;
struct Dir { unsigned mode;char name[256]; };
enum { OREAD=0, OCEXEC=32, DMDIR=0x80000000u };
static char *servicedir="/fixture/services/polling";
static int fixture_open(char *path,unsigned mode) {
    assert(!strcmp(path,servicedir) && mode==(OREAD|OCEXEC));
    assert(fixture_fd==0 && walk(fixture_provider,3,4,NULL)==111 && openfid(fixture_provider,4,0)==113);
    fixture_fd=4;fixture_offset=0;return 4;
}
static int fixture_close(int fd) {
    assert(fd==4 && fixture_fd==4 && clunk(fixture_provider,4)==121);fixture_fd=0;return 0;
}
static long long fixture_seek(int fd,long long offset,int whence) {
    assert(fd==4 && fixture_fd==4 && offset==0 && whence==0);fixture_offset=0;return 0;
}
static int fixture_dirreadall(int fd,Dir **entries) {
    assert(fd==4 && fixture_fd==4 && fixture_offset==0);
    assert(readfid(fixture_provider,4,fixture_offset,8192)==117);
    unsigned length=rd(response+7,4);size_t at=11,end=at+length;unsigned count=0;
    *entries=calloc(64,sizeof **entries);assert(*entries);
    while(at<end){
        size_t size=rd(response+at,2)+2,n=rd(response+at+41,2);
        assert(count<64 && n<256 && at+size<=end);
        (*entries)[count].mode=rd(response+at+21,4);memcpy((*entries)[count].name,response+at+43,n);
        count++;at+=size;
    }
    fixture_offset+=length;
    assert(readfid(fixture_provider,4,fixture_offset,8192)==117 && rd(response+7,4)==0);
    fixture_scans++;return count;
}
static int fixture_consider(char *name) {
    assert(fixture_activity && !strcmp(name,"one"));
    if(fixture_admitted)return 0;fixture_admitted=fixture_time;return 1;
}
static void fixture_sleep(int delay) {
    assert(delay>=50 && delay<=250);
    if(fixture_admitted && !fixture_after_active){assert(delay==50);fixture_after_active=1;}
    fixture_time+=delay;
    if(fixture_activity && !fixture_published && fixture_time>=1000){
        assert(walk(fixture_linux,2,4,NULL)==111 && create(fixture_linux,4,"one",0x80000000u|0755,0)==115);
        fixture_published=fixture_time;
    }
    if(fixture_time>=5000)longjmp(fixture_finish,1);
}
static void fixture_fatal(char *message) { fprintf(stderr,"unexpected service fatal:%s\n",message);abort(); }
#define open fixture_open
#define close fixture_close
#define seek fixture_seek
#define dirreadall fixture_dirreadall
#define consider fixture_consider
#define sleep fixture_sleep
#define fatal fixture_fatal
static void service_loop(void) {
    int fd,n,i,delay,active;Dir *entries;
/* PRODUCTION_LOOP */
}
#undef open
#undef close
#undef seek
#undef dirreadall
#undef consider
#undef sleep
#undef fatal
static void active_reset(void) {
    fixture_linux=session(1);rootdir(fixture_linux);fixture_provider=provider();
    fixture_activity=1;fixture_time=fixture_scans=fixture_fd=0;
    if(setjmp(fixture_finish)==0)service_loop();
    assert(fixture_published && fixture_admitted>=fixture_published && fixture_admitted-fixture_published<=250);
    assert(fixture_after_active==1);
    puts("new directory observed through production scan loop; idle admission<=250ms policy time and next sleep reset50ms: PASS");
}
int main(int argc,char **argv) {
    assert(argc==2);initvolume();unsigned c=atoi(argv[1]);
    if(c==0)freshness();else if(c==1)scans();else active_reset();return 0;
}
'''


def harness():
    source = (ROOT / "ocore/guest/plan9/unified/p9cmdsrv.c").read_text()
    policy = re.search(r"static int\nnextscan\(int delay, int active\)\n\{.*?\n\}", source, re.S)
    limits = re.search(r"Scanmin = ([0-9]+), Scanmax = ([0-9]+)", source)
    if not policy or not limits:
        raise AssertionError("production service polling policy missing")
    loop = source[source.index("\tfd=open(servicedir,OREAD|OCEXEC);"):source.rfind("\n}")]
    base = STORE_HARNESS.split("int main(int argc,char **argv) {")[0]
    base = base.replace("static uint64_t serial=1;", "static uint64_t serial=1,wirebytes;static unsigned requests;")
    base = base.replace("received=NS(handle)(session,request,pos,response,cap);",
                        "received=NS(handle)(session,request,pos,response,cap);requests++;wirebytes+=pos+received;")
    return "#include <setjmp.h>\n" + base + "\nenum {Scanmin=" + limits[1] + ",Scanmax=" + limits[2] + "};\n" + policy[0] + CASES.replace("/* PRODUCTION_LOOP */", loop)


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native Linux x86_64 fixture")
class Plan9ServicePollingTests(unittest.TestCase):
    def test_current_directory_fid_and_bounded_polling_traffic(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or not clang:
            self.skipTest("already-built ocorec and clang required")
        with tempfile.TemporaryDirectory(prefix="ocore-p9-polling-") as tmp:
            out = Path(tmp);(out / "test.c").write_text(harness())
            source = str(ROOT / "ocore/runtime/common/namespace_store.oc")
            for command in ([str(compiler),source,"--target","aarch64-unknown-none","--emit","mir","-o",str(out / "arm.mir")],
                            [str(compiler),source,"--target","x86_64-unknown-none","--emit","obj","-o",str(out / "native.o")],
                            [clang,"-O2","-no-pie",str(out / "test.c"),str(out / "native.o"),"-o",str(out / "test")]):
                result = subprocess.run(command,capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            for case in ("0","1","2"):
                result = subprocess.run([str(out / "test"),case],capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertIn("PASS",result.stdout)


if __name__ == "__main__":
    unittest.main()
