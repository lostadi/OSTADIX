import os,json,hashlib,struct,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
PRE=ROOT.parent/'core-library-native-smoke-r3'
CASES=[(19,23,42),(-7,11,4),(0,0,0),(1<<40,-3,(1<<40)-3)]
SPEC={'x86_64':('x86_64-unknown-none','elf_x86_64',62),'aarch64':('aarch64-unknown-none','aarch64elf',183),'riscv64':('riscv64-unknown-none','elf64lriscv',243)}
SYMBOL='_O_smoke__addition__add'
def pin(p):
    p=Path(p); before=p.stat(); data=p.read_bytes(); after=p.stat()
    keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
    assert all(getattr(before,k)==getattr(after,k) for k in keys),str(p)
    return {'path':str(p),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
def arm(reg,v):
    v &= (1<<64)-1
    return [f'movz {reg}, #{v&65535}']+[f'movk {reg}, #{(v>>s)&65535}, lsl #{s}' for s in (16,32,48) if (v>>s)&65535]
def harness(target,negative):
    out=['.text','.balign 16','.global _start','_start:']
    for i,(a,b,c) in enumerate(CASES,1):
        if negative and i==4:c+=1
        if target=='x86_64':out += [f'mov rdi, {a}',f'mov rsi, {b}',f'call {SYMBOL}',f'mov r10, {c}','cmp rax, r10',f'jne .L_fail_{i}']
        elif target=='aarch64':out += arm('x0',a)+arm('x1',b)+[f'bl {SYMBOL}']+arm('x9',c)+['cmp x0, x9',f'b.ne .L_fail_{i}']
        else:out += [f'li a0, {a}',f'li a1, {b}',f'call {SYMBOL}',f'li t0, {c}',f'bne a0, t0, .L_fail_{i}']
    def exit_code(n):
        if target=='x86_64':return [f'mov rdi, {n}','mov rax, 60','syscall','ud2']
        if target=='aarch64':return [f'mov x0, #{n}','mov x8, #93','svc #0','brk #0']
        return [f'li a0, {n}','li a7, 93','ecall','unimp']
    out+=exit_code(0)
    for i in range(1,5):out += [f'.L_fail_{i}:']+exit_code(i)
    return '\n'.join(out)+'\n'
def run(argv,label):
    r=subprocess.run(argv,capture_output=True,timeout=30)
    (ROOT/(label+'.stdout')).write_bytes(r.stdout);(ROOT/(label+'.stderr')).write_bytes(r.stderr)
    row={'argv':argv,'exit_code':r.returncode,'stdout':pin(ROOT/(label+'.stdout')),'stderr':pin(ROOT/(label+'.stderr'))}
    report['commands'].append(row)
    return r.returncode
def resources():
    m=next(int(x.split()[1])*1024 for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
    v=os.statvfs(ROOT);return {'disk_available':v.f_bavail*v.f_frsize,'memory_available':m}
report={'schema':'ostadix-bounded-generated-add-execution/v1','success':False,'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'cases':CASES,'commands':[],'targets':{},'errors':[],'qualification':False,'full_API':False,'full_compiler':False,'whole_runtime_ISA_qualified':False,'scope':'Four nonoverflowing i64 additions per target under explicit user-mode QEMU; original O-core assembly prefix unchanged; wrong final expected-result control must exit 4. No original foreign runtime is lowered by this harness.','resources_before':resources()}
try:
    terminal=json.loads((PRE/'terminal.json').read_text());assert terminal['success']
    tools=[Path('/usr/bin/clang'),Path('/usr/bin/ld.lld')]+[Path('/usr/bin/qemu-'+x) for x in SPEC]
    report['tools_before']=[pin(p.resolve()) for p in tools]
    for target,(triple,emu,machine) in SPEC.items():
        original=PRE/'cases'/(target+'.s');before=pin(original)
        assert before['sha256']==terminal['outputs'][target+'.s']['sha256']
        source=original.read_bytes();row={'original_assembly':before,'runs':[]};report['targets'][target]=row
        for negative in (False,True):
            label=target+('-negative' if negative else '-positive')
            asm=ROOT/(label+'.s');obj=ROOT/(label+'.o');exe=ROOT/label
            asm.write_bytes(source+b'\n'+harness(target,negative).encode())
            assert asm.read_bytes().startswith(source)
            argv=['/usr/bin/clang','--target='+triple,'-c','-x','assembler',str(asm),'-o',str(obj)]
            if target=='riscv64':argv.insert(2,'-march=rv64gc')
            assert run(argv,label+'-assemble')==0,label+' assemble'
            assert run(['/usr/bin/ld.lld','-m',emu,'-static','-e','_start',str(obj),'-o',str(exe)],label+'-link')==0,label+' link'
            b=exe.read_bytes();assert b[:6]==b'\x7fELF\x02\x01'
            assert struct.unpack_from('<HH',b,16)==(2,machine),label+' ELF'
            code=run(['/usr/bin/qemu-'+target,str(exe)],label+'-execute')
            assert code==(4 if negative else 0),label+' execution'
            row['runs'].append({'negative_wrong_final_expectation':negative,'expected_exit':4 if negative else 0,'observed_exit':code,'assembly':pin(asm),'object':pin(obj),'executable':pin(exe),'ELF_type':2,'machine':machine})
        assert pin(original)==before
    assert [pin(p.resolve()) for p in tools]==report['tools_before']
    report['success']=True
except BaseException as exc:
    report['errors'].append(type(exc).__name__+': '+str(exc))
finally:
    report['resources_after']=resources();(ROOT/'terminal.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'success':report['success'],'targets':list(report['targets']),'errors':report['errors']}))
raise SystemExit(0 if report['success'] else 1)
