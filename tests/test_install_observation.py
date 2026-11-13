"""Actual INSTALL-path software observations; no FP/ledger/CPU admission.

The exact6390 reference is source-bound in fixtures. The candidate production
checkpoint is inert; a COPIED object source instruments it for observation and
injects a reversible final-invariant failure, never a registry implementation.
"""
import hashlib, importlib.util, json, os, platform, re, shutil, subprocess, sys, tempfile, time, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('install_frame_base', ROOT / 'tests/test_thread_frame_contents.py')
FRAME = importlib.util.module_from_spec(spec)
spec.loader.exec_module(FRAME)
REFERENCE = ROOT / 'tests/fixtures/thread-6390-before-install-observation.oc.txt'
REFERENCE_SHA = 'eb53d1fd6d748970e3afa5bc3510aba77e1af74f2ef5b9cd8637f76de7aa86d8'
EXTRA = ['INSTALL_CAPSULE', 'INSTALL_RUNNABLE_BEFORE', 'INSTALL_BLOCKED_BEFORE', 'INSTALL_NEXT_OBSERVATION_SERIAL', 'INSTALL_OBSERVATION_EXHAUSTED', 'INSTALL_CURRENT_OBSERVATION_SERIAL', 'INSTALL_LAST_CLOSED_OBSERVATION_SERIAL']
C=r'''
static unsigned mode,stage_queries,checkpoint_count,fail_final;
static uint64_t geometry[4]={0x7000,0x8000,0x9000,0xa000};
uintptr_t ocore_process_kernel_stack_top(size_t n){return n<4?geometry[n]:0;}
uint64_t fixture_force_post_enqueue_failure(void){if(fail_final){fail_final=0;return 1;}return 0;}
#ifdef STAGED
extern bool T(install_observation_snapshot)(uint64_t*);
extern uint64_t T(INSTALL_CAPSULE)[32] __attribute__((aligned(8))),T(INSTALL_RUNNABLE_BEFORE)[4] __attribute__((aligned(8))),T(INSTALL_BLOCKED_BEFORE)[4] __attribute__((aligned(8)));
extern uint64_t T(INSTALL_NEXT_OBSERVATION_SERIAL),T(INSTALL_CURRENT_OBSERVATION_SERIAL),T(INSTALL_LAST_CLOSED_OBSERVATION_SERIAL);
extern uint8_t T(INSTALL_OBSERVATION_EXHAUSTED);
static uint64_t old_packet[40],old_capsule[32],old_run[4],old_block[4],old_serial;
static void semantic(unsigned id,bool result,bool expected){if(result!=expected){fprintf(stderr,"install observation id=%u expected=%u observed=%u\n",id,expected,result);exit(93);}}
static size_t all_state(unsigned char *out){size_t n=snapshot(out);
#define ADD(v) do{CHECK(n+sizeof(v)<8192);memcpy(out+n,&(v),sizeof(v));n+=sizeof(v);}while(0)
 ADD(T(INSTALL_CAPSULE));ADD(T(INSTALL_RUNNABLE_BEFORE));ADD(T(INSTALL_BLOCKED_BEFORE));
 ADD(T(INSTALL_NEXT_OBSERVATION_SERIAL));ADD(T(INSTALL_CURRENT_OBSERVATION_SERIAL));ADD(T(INSTALL_LAST_CLOSED_OBSERVATION_SERIAL));ADD(T(INSTALL_OBSERVATION_EXHAUSTED));
#undef ADD
 return n;}
static void query(unsigned id,bool expected){unsigned char before[8192],after[8192];uint64_t out[40];for(unsigned i=0;i<40;i++)out[i]=UINT64_MAX;size_t n=all_state(before);unsigned calls=image_calls;uint64_t arch[4];memcpy(arch,geometry,sizeof arch);
 bool result=T(install_observation_snapshot)(out);CHECK(all_state(after)==n&&!memcmp(before,after,n)&&calls==image_calls&&!memcmp(arch,geometry,sizeof arch));semantic(id,result,expected);
 if(result){CHECK(out[0]==UINT64_C(0x494e53544f425301)&&out[1]==T(INSTALL_CAPSULE)[1]&&out[2]==T(INSTALL_CURRENT_OBSERVATION_SERIAL)&&out[3]==1);CHECK(!out[4]&&!out[5]&&!out[6]&&!out[7]);for(unsigned i=16;i<40;i++)CHECK(!out[i]);CHECK(out[8]==T(INSTALL_CAPSULE)[5]&&out[9]==T(INSTALL_CAPSULE)[7]&&out[10]==T(INSTALL_CAPSULE)[9]&&out[11]==T(INSTALL_CAPSULE)[10]&&out[12]==T(INSTALL_CAPSULE)[8]);}
 else for(unsigned i=0;i<40;i++)CHECK(!out[i]);stage_queries++;
}
#define BAD(id,lvalue,value) do{__typeof__(lvalue) saved=(lvalue);(lvalue)=(value);query(id,false);(lvalue)=saved;query((id)+1000,true);}while(0)
static void negatives(void){size_t s=T(INSTALL_CAPSULE)[3];
 for(size_t i=0;i<32;i++){uint64_t saved=T(INSTALL_CAPSULE)[i];T(INSTALL_CAPSULE)[i]= i==3?4:(i==0||i==1||i==6||i==18||i==19||i==21||i==22||i==23?0:saved+1);query(100+(unsigned)i,false);T(INSTALL_CAPSULE)[i]=saved;}
 BAD(201,T(INITIALIZED),2);BAD(202,T(CURRENT_THREAD),1);BAD(203,T(PREPARED_THREAD),1);BAD(204,P(CURRENT_PROCESS),1);BAD(205,P(INITIALIZED),2);
 BAD(206,T(GENERATIONS)[s],T(GENERATIONS)[s]+1);BAD(207,T(PROCESS_REF_HELD)[s],0);BAD(208,T(PROCESS_REF_HELD)[s],2);
 BAD(209,T(STATES)[s],1);BAD(210,T(THREAD_IDS)[s],T(THREAD_IDS)[s]+1);BAD(211,T(USER_FS_BASES)[s],1);BAD(212,T(ROLES)[s],0);
 BAD(213,T(FRAMES)[s*22+8],T(FRAMES)[s*22+8]^1);BAD(214,T(FRAMES)[s*22+19],2);BAD(215,geometry[3],0);BAD(216,geometry[1],geometry[0]);
 BAD(217,T(INSTALL_CURRENT_OBSERVATION_SERIAL),0);BAD(218,T(INSTALL_LAST_CLOSED_OBSERVATION_SERIAL),T(INSTALL_CURRENT_OBSERVATION_SERIAL));
 BAD(219,T(INSTALL_RUNNABLE_BEFORE)[0],T(INSTALL_RUNNABLE_BEFORE)[0]^1);
 uint8_t st=P(STATES)[0];P(STATES)[0]=2;query(220,false);P(STATES)[0]=st;
 CHECK(!T(frame_pointer)(T(INSTALL_CAPSULE)[5]));CHECK(!T(queue_invariants_hold)());
}
#endif
void fixture_install_checkpoint(uint64_t point){
#ifdef STAGED
 if(!mode)return;checkpoint_count++;
 if(point==6){query(600,false);semantic(601,T(INSTALL_CURRENT_OBSERVATION_SERIAL)!=0,false);return;}
 if(point==5){query(500,false);return;}
 query((unsigned)point,mode!=3);
 if(mode!=3&&T(INSTALL_CURRENT_OBSERVATION_SERIAL)==UINT64_MAX){uint64_t next=T(INSTALL_NEXT_OBSERVATION_SERIAL);uint8_t exhausted=T(INSTALL_OBSERVATION_EXHAUSTED);T(INSTALL_NEXT_OBSERVATION_SERIAL)=0;T(INSTALL_OBSERVATION_EXHAUSTED)=0;query(850,false);T(INSTALL_NEXT_OBSERVATION_SERIAL)=next;T(INSTALL_OBSERVATION_EXHAUSTED)=exhausted;query(1850,true);}
 if(point==2&&mode==2)negatives();
 if(point==3){memcpy(old_capsule,T(INSTALL_CAPSULE),sizeof old_capsule);memcpy(old_run,T(INSTALL_RUNNABLE_BEFORE),sizeof old_run);memcpy(old_block,T(INSTALL_BLOCKED_BEFORE),sizeof old_block);old_serial=T(INSTALL_CURRENT_OBSERVATION_SERIAL);}
#endif
}
static void recycle_native(void){CHECK(T(cancel)(threads[1])==1&&T(reap)(threads[1])==1);threads[1]=0;}
static uint64_t install_again(uintptr_t stack){return T(install)(1,300,owners[0],0x01000000,1,stack,23,1,1);}
int main(int argc,char **argv){CHECK(argc==3);mode=!strcmp(argv[2],"proof")?2:!strcmp(argv[2],"serial")?1:0;setup(argv[1]);
 if(!strcmp(argv[2],"default")){lifecycle();unsigned char state[4096];size_t n=snapshot(state);hash(state,n);printf("Default ABI: digest=%016llx checks=%u\n",(unsigned long long)digest,checks);return 0;}
 if(!strcmp(argv[2],"rollback")){recycle_native();fail_final=1;CHECK(!install_again(0x8000));CHECK(T(queue_invariants_hold)());unsigned char state[4096];size_t n=snapshot(state);hash(state,n);printf("Default rollback: digest=%016llx checks=%u\n",(unsigned long long)digest,checks);return 0;}
 if(!strcmp(argv[2],"unqualified")){recycle_native();CHECK(install_again(0x7100));CHECK(T(queue_invariants_hold)());CHECK(T(prepare_next)()==threads[0]&&T(commit_next)(threads[0])==threads[0]&&P(scheduler_switch_to)(owners[0])==101);CHECK(T(preempt_current)()==threads[0]&&P(scheduler_deschedule_current)()==owners[0]);unsigned char state[4096];size_t n=snapshot(state);hash(state,n);printf("Default unqualified: digest=%016llx checks=%u\n",(unsigned long long)digest,checks);return 0;}
 if(!strcmp(argv[2],"current-unqualified")){recycle_native();CHECK(T(prepare_next)()==threads[0]&&T(commit_next)(threads[0])==threads[0]&&P(scheduler_switch_to)(owners[0])==101);CHECK(install_again(0x8000)&&T(queue_invariants_hold)());CHECK(T(preempt_current)()==threads[0]&&P(scheduler_deschedule_current)()==owners[0]);unsigned char state[4096];size_t n=snapshot(state);hash(state,n);printf("Default real-current install: digest=%016llx checks=%u\n",(unsigned long long)digest,checks);return 0;}
 if(!strcmp(argv[2],"retain-failure")){recycle_native();uint32_t old=P(THREAD_REFS)[0];P(THREAD_REFS)[0]=UINT32_MAX;unsigned char before[4096],after[4096];size_t n=snapshot(before);CHECK(!install_again(0x8000)&&snapshot(after)==n&&!memcmp(before,after,n));P(THREAD_REFS)[0]=old;CHECK(T(queue_invariants_hold)());hash(before,n);printf("Default saturated retain: digest=%016llx checks=%u\n",(unsigned long long)digest,checks);return 0;}
#ifdef STAGED
 if(!strcmp(argv[2],"unqualified-proof")){recycle_native();mode=3;uint64_t fresh=install_again(0x7100);CHECK(fresh&&T(cancel)(fresh)&&T(reap)(fresh));CHECK(T(prepare_next)()==threads[0]&&T(commit_next)(threads[0])==threads[0]&&P(scheduler_switch_to)(owners[0])==101);fresh=install_again(0x8000);CHECK(fresh&&T(queue_invariants_hold)());mode=0;CHECK(T(preempt_current)()==threads[0]&&P(scheduler_deschedule_current)()==owners[0]);printf("Strict unqualified default operations preserved: queries=%u checks=%u\n",stage_queries,checks);return 0;}
 if(!strcmp(argv[2],"proof")){
  query(700,false);uint64_t saved_next=T(INSTALL_NEXT_OBSERVATION_SERIAL),saved_closed=T(INSTALL_LAST_CLOSED_OBSERVATION_SERIAL);
  memcpy(T(INSTALL_CAPSULE),old_capsule,sizeof old_capsule);memcpy(T(INSTALL_RUNNABLE_BEFORE),old_run,sizeof old_run);memcpy(T(INSTALL_BLOCKED_BEFORE),old_block,sizeof old_block);T(INSTALL_CURRENT_OBSERVATION_SERIAL)=old_serial;query(701,false);
  memset(T(INSTALL_CAPSULE),0,sizeof old_capsule);memset(T(INSTALL_RUNNABLE_BEFORE),0,sizeof old_run);memset(T(INSTALL_BLOCKED_BEFORE),0,sizeof old_block);T(INSTALL_CURRENT_OBSERVATION_SERIAL)=0;CHECK(T(INSTALL_NEXT_OBSERVATION_SERIAL)==saved_next&&T(INSTALL_LAST_CLOSED_OBSERVATION_SERIAL)==saved_closed);
  recycle_native();mode=1;fail_final=1;CHECK(!install_again(0x8000));query(702,false);CHECK(T(queue_invariants_hold)());
  printf("Closed observation only: queries=%u checkpoints=%u checks=%u\n",stage_queries,checkpoint_count,checks);return 0;
 }
 if(!strcmp(argv[2],"serial")){
  recycle_native();T(INSTALL_NEXT_OBSERVATION_SERIAL)=UINT64_MAX-1;uint64_t first=install_again(0x8000);CHECK(first&&T(INSTALL_LAST_CLOSED_OBSERVATION_SERIAL)==UINT64_MAX-1);CHECK(T(cancel)(first)&&T(reap)(first));
  uint64_t last=install_again(0x8000);CHECK(last&&T(INSTALL_LAST_CLOSED_OBSERVATION_SERIAL)==UINT64_MAX&&T(INSTALL_OBSERVATION_EXHAUSTED)==1);CHECK(T(cancel)(last)&&T(reap)(last));unsigned old=checkpoint_count;CHECK(install_again(0x8000)&&checkpoint_count==old+1);query(800,false);CHECK(T(queue_invariants_hold)());
  printf("Observation exhaustion preserves default ABI: queries=%u checks=%u\n",stage_queries,checks);return 0;
 }
#endif
 CHECK(0);return 1;
}
'''

def metadata(source):
    types = {'u8': 'uint8_t', 'u16': 'uint16_t', 'u32': 'uint32_t', 'u64': 'uint64_t', 'usize': 'uintptr_t'}
    result = []
    for name, typ in re.findall('(?m)^static mut (\\w+): (\\[[^\\]]+\\]|\\w+) =', source):
        a = re.fullmatch('\\[(\\w+); (\\d+)\\]', typ)
        kind, count = (a[1], int(a[2])) if a else (typ, 0)
        result.append((name, types[kind], count))
    return result

@unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'actual x86 native carrier requires Linux x86_64')
class InstallObservationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.compiler = Path(os.environ.get('OCOREC_BIN', ROOT / 'target/debug/ocorec')).resolve()
        cls.clang = Path(shutil.which('clang') or '/missing')
        cls.nm = Path(shutil.which('nm') or '/missing')
        cls.objcopy = Path(shutil.which('objcopy') or '/missing')
        for f in [cls.compiler, cls.clang, cls.nm, cls.objcopy]:
            if not f.is_file():
                if os.environ.get('OCORE_INSTALL_OBSERVATION_REQUIRED') == '1':
                    raise AssertionError('required native tool missing: ' + str(f))
                raise unittest.SkipTest('built native compiler and host tools required')
        if os.environ.get('OCOREC_BIN_SHA256') and FRAME.identity(cls.compiler)['sha256'] != os.environ['OCOREC_BIN_SHA256']:
            raise AssertionError('compiler hash mismatch')
        cls.reference = REFERENCE.read_bytes()
        assert hashlib.sha256(cls.reference).hexdigest() == REFERENCE_SHA
        cls.source = ROOT / 'ocore/runtime/x86_64/thread.oc'
        cls.current = cls.source.read_text()
        cls.sources = [ROOT / 'ocore/runtime/x86_64' / (n + '.oc') for n in FRAME.MODULES]
        selected_output = os.environ.get('OCORE_INSTALL_OBSERVATION_OUTPUT')
        cls.cleanup = None if selected_output else tempfile.TemporaryDirectory(prefix='native-install-observation-')
        cls.output = Path(selected_output or cls.cleanup.name)
        if selected_output:
            cls.output.mkdir(exist_ok=False)
        cls.commands = []
        cls.publics = {}
        cls.pins = [FRAME.identity(f) for f in [*cls.sources, REFERENCE, Path(__file__), ROOT / 'tests/test_thread_frame_contents.py', ROOT / 'tests/test_process_current_identity.py', cls.compiler, cls.clang, cls.nm, cls.objcopy, Path(sys.executable)]]
        (cls.output / 'provider.oc').write_text(FRAME.PROVIDER)
        (cls.output / 'entry.S').write_text(FRAME.ENTRY)
        cls.run_command('elf', [cls.clang, '-nostdlib', '-static', '-no-pie', '-Wl,-Ttext-segment=0x02000000', cls.output / 'entry.S', '-o', cls.output / 'fixture.elf'])
        baseline = metadata(cls.reference.decode())
        assert len(baseline) == 36
        assert metadata(cls.current) == FRAME.field_metadata()
        assert {n for n, _, _ in metadata(cls.current)} == {n for n, _, _ in baseline} | set(EXTRA)
        harness = FRAME.carrier(baseline).split('int main(', 1)[0]
        harness = harness.replace('uintptr_t ocore_process_kernel_stack_top(size_t slot){return slot<4?0x7000+slot*0x1000:0;}\n', '')
        (cls.output / 'harness.c').write_text(harness + C)
        cls.build('before', cls.reference.decode(), False, False)
        cls.build('before-fault', cls.reference.decode(), False, False, True)
        cls.build('production', cls.current, True, False)
        cls.build('observed', cls.current, True, True)

    @classmethod
    def run_command(cls, name, argv, semantic=False):
        r = subprocess.run(list(map(str, argv)), cwd=cls.output, capture_output=True, timeout=120)
        out = cls.output / (name + '.stdout')
        err = cls.output / (name + '.stderr')
        out.write_bytes(r.stdout)
        err.write_bytes(r.stderr)
        cls.commands.append({'name': name, 'argv': list(map(str, argv)), 'status': r.returncode, 'stdout': FRAME.identity(out), 'stderr': FRAME.identity(err)})
        if semantic:
            m = re.fullmatch(b'install observation id=\\d+ expected=([01]) observed=([01])\\n', r.stderr)
            if r.returncode != 93 or m is None or m[1] == m[2]:
                raise AssertionError('not exact semantic93: ' + repr((r.returncode, r.stdout, r.stderr)))
        elif r.returncode:
            raise AssertionError(name + ': ' + str(r.returncode) + ' ' + r.stderr.decode(errors='replace'))
        return r

    @classmethod
    def build(cls, name, text, staged, instrument, fault=False):
        if instrument:
            text = text.replace('unsafe fn install_observation_checkpoint(point: u64) -> void {\n}', 'extern "C" fn fixture_install_checkpoint(point: u64) -> void;\nextern "C" fn fixture_force_post_enqueue_failure() -> u64;\nunsafe fn install_observation_checkpoint(point: u64) -> void { fixture_install_checkpoint(point); }', 1)
        elif fault:
            text = text.replace('pub const MAX_THREADS:', 'extern "C" fn fixture_force_post_enqueue_failure() -> u64;\npub const MAX_THREADS:', 1)
        if instrument or fault:
            text = text.replace('|| !queue_invariants_hold() {\n        runnable_remove(handle);', '|| !queue_invariants_hold() || fixture_force_post_enqueue_failure() != 0 {\n        runnable_remove(handle);')
        f = cls.output / (name + '.oc')
        f.write_text(text)
        obj = cls.output / (name + '.o')
        visible = cls.output / (name + '-visible.o')
        cls.run_command(name + '-compile', [cls.compiler, cls.output / 'provider.oc', *cls.sources[:-1], f, '--target', 'x86_64-unknown-none', '--emit', 'obj', '-o', obj])
        required = {'ocore_current_cr3', 'ocore_management_cr3', 'ocore_kernel_p1_address', 'fixture_object_length', 'fixture_read', 'fixture_release'}
        if staged:
            required.add('ocore_process_kernel_stack_top')
        if instrument:
            required.add('fixture_install_checkpoint')
        if instrument or fault:
            required.add('fixture_force_post_enqueue_failure')
        undefined = cls.run_command(name + '-undefined', [cls.nm, '-u', obj]).stdout.decode()
        if {r.split()[-1] for r in undefined.splitlines()} != required:
            raise AssertionError('unexpected architecture, test hook or registry implementation')
        symbols = cls.run_command(name + '-symbols', [cls.nm, '--defined-only', obj]).stdout.decode()
        symbols = {r.split()[-1]: r.split()[-2] for r in symbols.splitlines() if len(r.split()) >= 3}
        cls.publics[name] = {k for k, v in symbols.items() if v.isupper()}
        names = ['_O_runtime__process__' + n for n in FRAME.BASE.FIELDS] + ['_O_runtime__thread__' + n for n, _, _ in metadata(text)] + ['_O_runtime__thread__validate_frame_words']
        for field, _, _ in metadata(text):
            if symbols.get('_O_runtime__thread__' + field) not in {'b', 'd'}:
                raise AssertionError('private field exported or missing: ' + field)
        if staged:
            names += ['_O_runtime__thread__install_observation_snapshot']
            if symbols.get(names[-1]) != 't':
                raise AssertionError('private stage query exported')
        cls.run_command(name + '-visibility', [cls.objcopy, *['--globalize-symbol=' + n for n in names], obj, visible])
        assert FRAME.BASE.allocated_sections(obj) == FRAME.BASE.allocated_sections(visible)
        cls.run_command(name + '-link', [cls.clang, '-O2', '-fno-pie', '-no-pie', *(['-DSTAGED=1'] if staged else []), cls.output / 'harness.c', visible, '-o', cls.output / name])

    @classmethod
    def tearDownClass(cls):
        after = [FRAME.identity(p['path']) for p in cls.pins]
        report = {'commands': cls.commands, 'inputs_before': cls.pins, 'inputs_after': after, 'inputs_unchanged': after == cls.pins, 'scope': __doc__, 'FP_admission': False, 'ledger_tickets': False, 'environment': {'platform': platform.platform(), 'python': sys.version, 'ambient_host_C_headers_and_libraries_captured': False, 'hermetic_toolchain': False}}
        (cls.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        assert after == cls.pins
        if cls.cleanup:
            cls.cleanup.cleanup()

    def test_exact6390_default_public_abi(self):
        self.assertEqual(self.publics['before'], self.publics['production'])
        for mode in ['default', 'unqualified', 'current-unqualified', 'retain-failure']:
            rows = [self.run_command(n + '-' + mode, [self.output / n, self.output / 'fixture.elf', mode]).stdout for n in ['before', 'production', 'observed']]
            self.assertEqual(rows[0], rows[1])
            self.assertEqual(rows[0], rows[2])
        rows = [self.run_command(n + '-rollback', [self.output / n, self.output / 'fixture.elf', 'rollback']).stdout for n in ['before-fault', 'observed']]
        self.assertEqual(rows[0], rows[1])

    def test_actual_phases_and_corruption_refusals(self):
        self.run_command('actual-proof', [self.output / 'observed', self.output / 'fixture.elf', 'proof'])

    def test_strict_refusals_do_not_tighten_default_abi(self):
        self.run_command('unqualified-proof', [self.output / 'observed', self.output / 'fixture.elf', 'unqualified-proof'])

    def test_serial_exhaustion_preserves_ordinary_installs(self):
        self.run_command('serial', [self.output / 'observed', self.output / 'fixture.elf', 'serial'])

    def test_strict_semantic_mutations(self):
        variants = {'serial': self.current.replace('|| INSTALL_CAPSULE[2] != serial', '', 1), 'retain': self.current.replace('if INSTALL_CAPSULE[21] != 1 ||', 'if false ||', 1), 'initialized': self.current.replace('if INITIALIZED != 1 || serial == 0', 'if false || serial == 0', 1), 'frame': self.current.replace('if FRAMES[frame_index(slot, word)] != expected { return false; }', 'if false { return false; }', 1), 'closed': self.current.replace('|| serial <= INSTALL_LAST_CLOSED_OBSERVATION_SERIAL', '', 1), 'counter-zero': self.current.replace('|| INSTALL_CAPSULE[2] != serial || INSTALL_NEXT_OBSERVATION_SERIAL == 0', '|| INSTALL_CAPSULE[2] != serial', 1)}
        for name, text in variants.items():
            with self.subTest(name=name):
                self.assertNotEqual(text, self.current)
                self.build('mutant-' + name, text, True, True)
                self.run_command('mutant-' + name + '-negative', [self.output / ('mutant-' + name), self.output / 'fixture.elf', 'serial' if name == 'counter-zero' else 'proof'], semantic=True)
if __name__ == '__main__':
    unittest.main()
