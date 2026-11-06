"""Independent integer-only PE/serial decoder; never runs machine code.

The input EFI app is authored. Constants/field rules come from Intel093.
Collection success is distinct from architectural pointer conformance.
"""
import hashlib,json,re,struct
from pathlib import Path

def sha(b):return hashlib.sha256(b).hexdigest()
def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def u64(b,o):return struct.unpack_from('<Q',b,o)[0]
def inspect_pe(data):
 assert data[:2]==b'MZ';pe=u32(data,0x3c);assert data[pe:pe+4]==b'PE\0\0'
 machine,nsects,stamp,symtab,nsyms,optsize,flags=struct.unpack_from('<HHIIIHH',data,pe+4)
 assert machine==0x8664
 opt=pe+24;assert u16(data,opt)==0x20b and u16(data,opt+68)==10
 imagebase=u64(data,opt+24);entry=u32(data,opt+16);sections=[]
 for i in range(nsects):
  o=opt+optsize+i*40;name=data[o:o+8].split(b'\0')[0].decode();vs,va,rs,ro=struct.unpack_from('<IIII',data,o+8);sf=u32(data,o+36);assert ro+rs<=len(data)
  sections.append(dict(name=name,virtual=va,virtual_bytes=vs,raw=ro,raw_bytes=rs,flags=sf))
 def offset(rva,n=1):
  ss=[s for s in sections if s['virtual']<=rva and rva+n<=s['virtual']+s['raw_bytes']];assert len(ss)==1,(rva,n)
  return ss[0]['raw']+rva-ss[0]['virtual']
 er,esz=struct.unpack_from('<II',data,opt+112);eo=offset(er,40)
 _,_,_,_,_,base,nfunc,nnames,fa,na,oa=struct.unpack_from('<IIHHIIIIIII',data,eo)
 exports={}
 for i in range(nnames):
  nr=u32(data,offset(na+4*i,4));no=offset(nr);end=data.index(b'\0',no);name=data[no:end].decode();ordinal=u16(data,offset(oa+2*i,2));assert ordinal<nfunc
  exports[name]=u32(data,offset(fa+4*ordinal,4))
 assert exports['efi_main']==entry
 return {'imagebase':imagebase,'entry_rva':entry,'sections':sections,'exports':exports,'offset':offset}

def analyze(pe_path,serial_path,output):
 output=Path(output);output.mkdir(exist_ok=False)
 data=Path(pe_path).read_bytes();pe=inspect_pe(data);serial=Path(serial_path).read_bytes()
 lengths={'metadata':128,'cpuid':64,'controls':64,'normal_fx':512,'normal_env':28,'a_w':512,'a_l':512,'a_env':28,'b_w':512,'b_env':28,'after_w':512,'after_w_env':28,'crafted':512,'after_crafted':512,'after_crafted_env':28,'after_l_w':512,'after_l_l':512,'after_l_env':28}
 rows=re.findall(rb'(?m)^FPREC ([a-z_]+) ([0-9a-f]{16}) ([0-9a-f]+)\r?$',serial);records={}
 for n,l,h in rows:
  name=n.decode();assert name in lengths and name not in records,name;raw=bytes.fromhex(h.decode());assert len(raw)==int(l,16)==lengths[name],name;records[name]=raw;(output/(name+'.bin')).write_bytes(raw)
 assert set(records)==set(lengths),(set(records),set(lengths));assert b'FPEND COMPLETE' in serial
 meta=list(struct.unpack('<16Q',records['metadata']));assert meta[0]==0x4650505452303031
 base=meta[1]-pe['entry_rva'];bindings={}
 for i,name in [(1,'efi_main'),(2,'fp_load_normal'),(3,'operand_a'),(4,'fp_fault_a'),(5,'zero_a'),(6,'fp_load_b'),(7,'operand_b'),(8,'fp_fault_b'),(9,'zero_b'),(10,'fx_a_w'),(11,'fx_a_l'),(12,'fx_crafted')]:
  assert meta[i]==base+pe['exports'][name],(i,name,meta[i],base,pe['exports'][name]);bindings[name]=meta[i]
 assert all(meta[i]%16==0 for i in (10,11,12))
 cpuid=struct.unpack('<16I',records['cpuid']);vendor=struct.pack('<III',cpuid[1],cpuid[3],cpuid[2]).decode();eax=cpuid[4]
 family=(eax>>8)&15;model=(eax>>4)&15
 if family==15:family+=(eax>>20)&255
 if family in (6,15):model|=((eax>>16)&15)<<4
 assert (vendor,family,model,eax&15)==('GenuineIntel',6,26,3),(vendor,family,model,eax&15)
 assert cpuid[7]&0x07000001==0x07000001 and not cpuid[6]&0x1c000000
 fdp_exception_only=bool(cpuid[9]&(1<<6));selectors_deprecated=bool(cpuid[9]&(1<<13))
 controls=struct.unpack('<8Q',records['controls']);assert controls[4]&0x22==0x22 and not controls[4]&12;assert controls[5]&0x600==0x600 and not controls[5]&(1<<18);assert not controls[6]&(1<<14) and not controls[7]&512
 instructions={}
 for name,operand,second in [('fp_load_normal','operand_a',5),('fp_fault_a','zero_a',0x35),('fp_fault_b','zero_b',0x3d)]:
  rva=pe['exports'][name];o=pe['offset'](rva,6);b=data[o:o+6]
  assert b[:2] in (bytes([0xdd,5]),bytes([0xdc,0x35]),bytes([0xdc,0x3d])) and b[1]==second,(name,b.hex())
  disp=struct.unpack_from('<i',b,2)[0];assert base+rva+6+disp==bindings[operand]
  instructions[name]={'rva':rva,'runtime':base+rva,'bytes':b.hex(),'operand':bindings[operand],'derived_fop':((b[0]&7)<<8)|b[1]}
 # Verify distinct full-width and legacy encodings, not mnemonic labels alone.
 enc={}
 for name,prefix,target,operation in [('save_a_w',b'\x48\x0f\xae','fx_a_w',0),('save_a_l',b'\x0f\xae','fx_a_l',0),('restore_a_w',b'\x48\x0f\xae','fx_a_w',1),('restore_crafted_w',b'\x48\x0f\xae','fx_crafted',1),('restore_a_l',b'\x0f\xae','fx_a_l',1)]:
  n=len(prefix)+5;rva=pe['exports'][name];o=pe['offset'](rva,n);b=data[o:o+n];assert b.startswith(prefix),(name,b.hex())
  modrm=b[len(prefix)];assert modrm&0xc7==5 and (modrm>>3)&7==operation,(name,hex(modrm),operation)
  displacement=struct.unpack_from('<i',b,len(prefix)+1)[0];actual_target=base+rva+n+displacement;assert actual_target==bindings[target],(name,actual_target,bindings[target])
  enc[name]={'bytes':b.hex(),'operation_selector':operation,'rip_relative':True,'target_name':target,'runtime_target':actual_target}
 def env(name):
  b=records[name];return {'fcw':u16(b,0),'fsw':u16(b,4),'ftw':u16(b,8),'fip_low32':u32(b,12),'fcs':u16(b,16),'fop':u16(b,18)&0x7ff,'fdp_low32':u32(b,20),'fds':u16(b,24)}
 def fx(name,wide=True):
  b=records[name];return {'fcw':u16(b,0),'fsw':u16(b,2),'ftw':b[4],'fop':u16(b,6)&0x7ff,'fip':u64(b,8)if wide else u32(b,8),'fdp':u64(b,16)if wide else u32(b,16),'mxcsr':u32(b,24),'mxcsr_mask':u32(b,28),'st0':b[32:42].hex(),'xmm0':b[160:176].hex(),'xmm15':b[400:416].hex()}
 envs={n:env(n)for n in records if n.endswith('_env') or n=='normal_env'};fxs={n:fx(n,not n.endswith('_l'))for n in records if len(records[n])==512}
 # Capture quality binds real arithmetic/nonzero XMM and unmasked ES evidence.
 assert fxs['a_w']['fcw']&4==0 and fxs['a_w']['fsw']&0x84==0x84
 assert fxs['b_w']['fcw']&1==0 and fxs['b_w']['fsw']&0x81==0x81
 assert fxs['a_w']['mxcsr']==0x1f80 and fxs['b_w']['mxcsr']==0x5f80
 assert fxs['a_w']['xmm0']==struct.pack('<QQ',0x0123456789abcdef,0xfedcba9876543210).hex()
 assert fxs['b_w']['xmm0']==struct.pack('<QQ',0x8877665544332211,0x0011223344556677).hex()
 assert fxs['a_w']['st0']!=fxs['b_w']['st0']
 tests=[]
 def check(name,actual,expected):tests.append({'name':name,'actual':actual,'expected':expected,'passed':actual==expected})
 check('ordinary_masked_fnstenv_fip',envs['normal_env']['fip_low32'],bindings['fp_load_normal']&0xffffffff)
 if not fdp_exception_only:check('ordinary_masked_fnstenv_fdp',envs['normal_env']['fdp_low32'],bindings['operand_a']&0xffffffff)
 for phase,en,fn,op in [('normal','normal_env','fp_load_normal','operand_a'),('a_w','a_env','fp_fault_a','zero_a'),('b_w','b_env','fp_fault_b','zero_b')]:
  f=fxs['normal_fx'if phase=='normal'else phase];e=envs[en]
  check(phase+'_fx_fip',f['fip'],bindings[fn])
  if phase!='normal' or not fdp_exception_only:check(phase+'_fx_fdp',f['fdp'],bindings[op])
  if phase!='normal':
   expected=instructions[fn]['derived_fop'];check(phase+'_fx_fop',f['fop'],expected);check(phase+'_env_fop',e['fop'],expected)
   check(phase+'_env_fip',e['fip_low32'],bindings[fn]&0xffffffff);check(phase+'_env_fdp',e['fdp_low32'],bindings[op]&0xffffffff)
 for field,expected in [('fip',bindings['fp_fault_a']&0xffffffff),('fdp',bindings['zero_a']&0xffffffff),('fop',instructions['fp_fault_a']['derived_fop'])]:check('legacy_a_save_'+field,fxs['a_l'][field],expected)
 if selectors_deprecated:
  for name,e in envs.items():
   check(name+'_deprecated_fcs',e['fcs'],0);check(name+'_deprecated_fds',e['fds'],0)
 for tag,expected_fip,expected_fdp,expected_fop in [('after_w',bindings['fp_fault_a'],bindings['zero_a'],instructions['fp_fault_a']['derived_fop']),('after_crafted',0x0000000112345678,0x0000000223456780,instructions['fp_fault_a']['derived_fop']),('after_l',bindings['fp_fault_a']&0xffffffff,bindings['zero_a']&0xffffffff,instructions['fp_fault_a']['derived_fop'])]:
  e=envs[tag+'_env'];f=fxs[tag if tag!='after_l'else'after_l_w']
  if tag!='after_l':
   check(tag+'_rexw_clears_fcs',e['fcs'],0);check(tag+'_rexw_clears_fds',e['fds'],0)
  else:
   check(tag+'_legacy_restores_fcs',e['fcs'],u16(records['a_l'],12));check(tag+'_legacy_restores_fds',e['fds'],u16(records['a_l'],20))
  check(tag+'_env_fip',e['fip_low32'],expected_fip&0xffffffff);check(tag+'_env_fdp',e['fdp_low32'],expected_fdp&0xffffffff);check(tag+'_env_fop',e['fop'],expected_fop)
  check(tag+'_fx_fip',f['fip'],expected_fip);check(tag+'_fx_fdp',f['fdp'],expected_fdp);check(tag+'_fx_fop',f['fop'],expected_fop)
  for field in ['fcw','fsw','ftw','mxcsr','st0','xmm0','xmm15']:check(tag+'_nonpointer_'+field,f[field],fxs['a_w'][field])
 changes=[i for i,(a,b)in enumerate(zip(records['a_w'],records['crafted']))if a!=b];assert changes and all(6<=i<24 for i in changes)
 assert u64(records['crafted'],8)==0x0000000112345678 and u64(records['crafted'],16)==0x0000000223456780
 result={'collection_ok':True,'isa_pointer_conformance':all(t['passed']for t in tests if '_nonpointer_'not in t['name']),'all_checked_fields_conform':all(t['passed']for t in tests),'full_state_profile_admitted':False,'scope':'Actual selected source-built QEMU TCG CPL0 diagnostic only. No native O-core/physical hardware/FP context qualification. Unmasked pending state captured before FNSTENV masks it; masked FOP is deliberately not asserted.','model':{'vendor':vendor,'family':family,'model':model,'stepping':eax&15,'cpu_arg':'Nehalem-v1,+x2apic','cpuid7_ebx':cpuid[9],'fdp_exception_only':fdp_exception_only,'selectors_deprecated':selectors_deprecated},'runtime_image_base':base,'controls':list(controls),'bindings':bindings,'instructions':instructions,'save_restore_encodings':enc,'environments':envs,'images':fxs,'crafted_changed_offsets':changes,'checks':tests,'records':[{'name':n,'bytes':len(b),'sha256':sha(b),'path':str(output/(n+'.bin'))}for n,b in records.items()],'inputs':{'efi_sha256':sha(data),'serial_sha256':sha(serial)},'reference':'Intel093 Vol1 8.1.8/8.1.9; Vol2A FXSAVE/FXRSTOR, runtime-labelled instruction/operand addresses. FOP required only for actual unmasked exception cases; no masked-FOP normalization.'}
 (output/'analysis.json').write_text(json.dumps(result,indent=2)+'\n');return result
