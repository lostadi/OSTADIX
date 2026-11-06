
# Linux-only owned-child containment; no existing process is signalled.
import ctypes, os, signal
_owned_parent_pid = os.getpid()
def _owned_parent_death():
 libc = ctypes.CDLL(None, use_errno=True)
 if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
  os._exit(126)
 if os.getppid() != _owned_parent_pid:
  os._exit(126)

from pathlib import Path
import sys,subprocess,shutil,json,hashlib,time,struct,traceback
B=Path(__file__).resolve().parent;W=B.parent;SDK=Path('/home/ustad/.cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin');mode=sys.argv[1];assert mode in('baseline','v1r4','v1r6');O=B/sys.argv[2];O.mkdir();S=O/'source';S.mkdir()
def pin(p):p=Path(p);d=p.read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
inputs=[B/'boot.S',B/'real.S',Path(__file__)];before=[pin(p)for p in inputs]
for p in inputs:shutil.copyfile(p,S/p.name)
Q=W/(mode+'-bin')/'qemu-system-x86_64';BIOS=W/'source/qemu-11.1.3/pc-bios/bios-256k.bin';tools=[Q,BIOS,SDK/'clang',SDK/'ld.lld',SDK/'llvm-objcopy',SDK/'llvm-objdump',SDK/'llvm-nm'];R={'collection_ok':False,'conformance':False,'source_before':before,'tools_before':[pin(p)for p in tools],'commands':[],'checks':[],'scope':'Authored bootsector+real16originalemulator ENVformat/reset/roundtrip only; no nativeOS/arithmetic/fullFPU admission'}
def save():(O/'result.json').write_text(json.dumps(R,indent=2)+'\n')
def check(n,a,e):R['checks'].append(dict(name=n,actual=a,expected=e,passed=a==e))
def run(n,argv):
 p=subprocess.run(list(map(str,argv)),cwd=O,capture_output=True,timeout=30);(O/(n+'.stdout')).write_bytes(p.stdout);(O/(n+'.stderr')).write_bytes(p.stderr);R['commands'].append(dict(name=n,argv=list(map(str,argv)),exit_code=p.returncode,stdout=pin(O/(n+'.stdout')),stderr=pin(O/(n+'.stderr'))));save();assert p.returncode==0,(n,p.stderr)
try:
 for n,base in [('boot','0x7c00'),('real','0')]:
  run(n+'-assemble',[SDK/'clang','--target=i386-unknown-none','-c',S/(n+'.S'),'-o',O/(n+'.o')]);run(n+'-link',[SDK/'ld.lld','-m','elf_i386','--image-base=0','-Ttext='+base,'--entry='+('_start'if n=='boot'else'real_entry'),'--build-id=none','-o',O/(n+'.elf'),O/(n+'.o')]);run(n+'-binary',[SDK/'llvm-objcopy','-O','binary',O/(n+'.elf'),O/(n+'.bin')]);run(n+'-disassembly',[SDK/'llvm-objdump','-d','--x86-asm-syntax=intel','--triple=i386','--mattr=+16bit-mode,-32bit-mode',O/(n+'.elf')]);run(n+'-symbols',[SDK/'llvm-nm','-n',O/(n+'.elf')])
 boot=(O/'boot.bin').read_bytes();real=(O/'real.bin').read_bytes();assert len(boot)==512 and boot[-2:]==b'\x55\xaa'and len(real)<=4096
 disk=O/'boot.img';disk.write_bytes(boot+real+bytes(1474560-512-len(real)));R['boot_image_before']=pin(disk);serial=O/'serial.bin';argv=[str(Q),'-machine','pc','-accel','tcg','-cpu','Nehalem-v1,+x2apic','-m','128M','-smp','1','-nodefaults','-display','none','-monitor','none','-serial','file:'+str(serial),'-nic','none','-no-reboot','-bios',str(BIOS),'-L',str(BIOS.parent),'-drive','if=floppy,format=raw,readonly=on,file='+str(disk),'-boot','order=a','-device','isa-debug-exit,iobase=0xf4,iosize=0x04']
 with(O/'qemu.stdout').open('wb')as so,(O/'qemu.stderr').open('wb')as se:
  p=subprocess.Popen(argv,cwd=O,stdout=so,stderr=se,start_new_session=True,preexec_fn=_owned_parent_death);R['owned_process']=dict(pid=p.pid,pgid=p.pid,start_ticks=Path(f'/proc/{p.pid}/stat').read_text().split()[21],argv=argv);save();start=time.monotonic()
  try:status=p.wait(timeout=60)
  except subprocess.TimeoutExpired:
   p.terminate();p.wait(timeout=3);raise TimeoutError('ownedreal16diagnostic')
 R['qemu_status']=status;R['seconds']=time.monotonic()-start;assert status==33,('qemustatus',status)
 raw=serial.read_bytes();assert raw.count(b'FPREAL01')==1;raw=raw.split(b'FPREAL01')[1];lengths={'meta':32,'initial':512,'env32':28,'env16':14,'after32':512,'env32_again':28,'after16':512,'fsave':108,'after_fsave':512,'after_frstor':512};records={};D=O/'decoded';D.mkdir()
 for n,l in lengths.items():records[n]=raw[:l];raw=raw[l:];(D/(n+'.bin')).write_bytes(records[n])
 assert raw.startswith(b'FPREALOK');meta=records['meta'];u16=lambda b,o:struct.unpack_from('<H',b,o)[0];u32=lambda b,o:struct.unpack_from('<I',b,o)[0];symbols={line.split()[2]:int(line.split()[0],16)for line in(O/'real-symbols.stdout').read_text().splitlines()if len(line.split())==3};off=symbols['real_fault'];check('runtime_CS',u16(meta,0),0x800);check('runtime_DS',u16(meta,2),0x9000);check('runtime_fault_offset',u16(meta,16),off);check('actual_CR0_real',u32(meta,8)&1,0);assert real[off:off+4]==bytes.fromhex('dc364012');fop=0x436;ip=0x8000+off;dp=0x91240
 b=records['initial']
 for k,o,w,v in [('fop',6,2,fop),('ip_offset',8,4,off),('cs',12,2,0x800),('dp_offset',16,4,0x1240),('ds',20,2,0x9000)]:check('fx_legacy_'+k,int.from_bytes(b[o:o+w],'little'),v)
 for n in('env32','env32_again'):
  b=records[n];ei=(u32(b,12)&0xffff)|((u32(b,16)&0x0ffff000)<<4);ed=(u32(b,20)&0xffff)|((u32(b,24)&0x0ffff000)<<4);check(n+'_linear_ip',ei,ip);check(n+'_linear_dp',ed,dp);check(n+'_fop',u32(b,16)&0x7ff,fop)
 b=records['env16'];ei=u16(b,6)|((u16(b,8)&0xf000)<<4);ed=u16(b,10)|((u16(b,12)&0xf000)<<4);check('env16_linear_ip',ei,ip&0xfffff);check('env16_linear_dp',ed,dp&0xfffff);check('env16_fop',u16(b,8)&0x7ff,fop)
 for n in('after32','after16','after_frstor'):
  b=records[n]
  for k,o,w,v in [('fop',6,2,fop),('linear_ip',8,4,ip),('cleared_cs',12,2,0),('linear_dp',16,4,dp),('cleared_ds',20,2,0)]:check(n+'_'+k,int.from_bytes(b[o:o+w],'little'),v)
 b=records['after_fsave']
 for k,o,w,v in [('fcw',0,2,0x37f),('fsw',2,2,0),('ftw',4,1,0),('fop',6,2,0),('ip',8,4,0),('dp',16,4,0)]:check('fnsave_resets_'+k,int.from_bytes(b[o:o+w],'little'),v)
 for n in('initial','after32','after16','after_fsave','after_frstor'):check(n+'_MXCSR_preserved',u32(records[n],24),0x5f80);check(n+'_XMM0_preserved',records[n][160:176].hex(),'78563412f0debc9a1032547698badcfe')
 R['collection_ok']=True;R['conformance']=all(x['passed']for x in R['checks']);R['failed']=sum(not x['passed']for x in R['checks']);R['runtime_bindings']=dict(cs=0x800,ds=0x9000,fault_offset=off,physical_fip=ip,physical_fdp=dp,fop=fop,instruction=real[off:off+4].hex());R['records']=[pin(D/(n+'.bin'))for n in lengths]
except Exception as e:R['error']=repr(e);(O/'controller-error.log').write_text(traceback.format_exc())
finally:R['source_after']=[pin(p)for p in inputs];R['sources_unchanged']=before==R['source_after'];R['tools_after']=[pin(p)for p in tools];R['tools_unchanged']=R['tools_before']==R['tools_after'];save()
print(json.dumps({'result':pin(O/'result.json'),'collection':R['collection_ok'],'conformance':R['conformance'],'checks':len(R['checks']),'error':R.get('error')}))
