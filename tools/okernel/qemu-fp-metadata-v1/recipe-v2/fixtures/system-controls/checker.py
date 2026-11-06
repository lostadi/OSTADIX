"""Integer-only actual fault/state decoder; no guest execution or normalization."""
from pathlib import Path
import json,re,struct,hashlib,importlib.util
P=Path(__file__).resolve().parents[1]/'pointer/checker.py'
spec=importlib.util.spec_from_file_location('original_pe',P);pe_mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(pe_mod)
def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def u64(b,o):return struct.unpack_from('<Q',b,o)[0]
def fields(b):return dict(fcw=u16(b,0),fsw=u16(b,2),ftw=b[4],fop=u16(b,6),fip=u64(b,8),fdp=u64(b,16),mxcsr=u32(b,24),mxcsr_mask=u32(b,28),st=[b[32+16*i:42+16*i].hex()for i in range(8)],xmm=[b[160+16*i:176+16*i].hex()for i in range(16)])
def defined(b):return b[:5]+b[6:28]+b''.join(b[32+16*i:42+16*i]for i in range(8))+b[160:416]
def analyze(image,serial,out,description):
 out=Path(out);out.mkdir();pe=pe_mod.inspect_pe(Path(image).read_bytes());desc=json.loads(Path(description).read_text());records={};tests=[]
 def check(n,a,e):tests.append(dict(name=n,actual=a,expected=e,passed=a==e))
 text=Path(serial).read_bytes();assert b'FPCTRL COMPLETE' in text
 for n,l,h in re.findall(rb'(?m)^FPREC ([a-z_0-9]+) ([0-9a-f]{16}) ([0-9a-f]+)\r?$',text):
  n=n.decode();assert n in desc['records']and n not in records;raw=bytes.fromhex(h.decode());assert len(raw)==int(l,16)==desc['records'][n];records[n]=raw;(out/(n+'.bin')).write_bytes(raw)
 assert set(records)==set(desc['records']),(set(records),set(desc['records']))
 meta=struct.unpack('<16Q',records['meta']);assert meta[0]==0x46504354524c3031;runtime=meta[1]-pe['entry_rva'];bindings={n:runtime+v for n,v in pe['exports'].items()};assert meta[9]==bindings['ro_env'] and meta[10]==bindings['pml4'];assert bindings['bss_end']<0x200000;assert meta[7]&0xffffffff==0x106a3;assert meta[8]&((1<<6)|(1<<13))==0
 cases={};expected={'fldenv_ro':None,'bad_fx':13,'legacy':None,'bad_mxcsr':13,'unaligned':13,'ts':7,'em':7,'fstenv_ro':14,'pending_wait':16,'pending_invalid':6,'pending_fresh_invalid':6,'pending_unmapped':16,'clex':None,'init':None}
 for n in desc['cases']:
  b=records['case_'+n];ev=list(struct.unpack('<8Q',b[:64]));before=b[64:576];after=b[576:1088];cases[n]=dict(event=ev,before=fields(before),after=fields(after))
  check(n+'_fault_count',ev[7],0 if expected[n]is None else 1)
  if expected[n]is not None:
   check(n+'_fault_vector',ev[0],expected[n]);check(n+'_fault_site',ev[2],bindings['op_'+n]);check(n+'_fault_IF_masked',bool(ev[6]&512),False)
   if n in('fstenv_ro',):check(n+'_fault_linear_address',ev[3],bindings['ro_env']);check(n+'_fault_write',bool(ev[1]&2),True)
   if n=='ts':check('ts_actual_CR0_TS',bool(ev[4]&8),True)
   if n=='em':check('em_actual_CR0_EM',bool(ev[4]&4),True)
  if n not in('fldenv_ro','legacy','clex','init'):check(n+'_no_defined_FP_mutation',defined(after).hex(),defined(before).hex())
  if n in('pending_wait','pending_invalid','pending_fresh_invalid','pending_unmapped','fstenv_ro','clex'):check(n+'_unmasked_pending_precondition',u16(before,2)&0x8084,0x8084)
 # Decode actual operands/operation selectors independently of mnemonic labels.
 imagebytes=Path(image).read_bytes();encodings={}
 for site,target,prefix,reg in [('op_bad_fx','bad_image',b'\x48\x0f\xae',1),('op_bad_mxcsr','bad_mxcsr',b'\x0f\xae',2),('op_legacy','legacy_source',b'\x0f\xae',1)]:
  rva=pe['exports'][site];size=len(prefix)+5;off=pe['offset'](rva,size);raw=imagebytes[off:off+size];assert raw.startswith(prefix);m=raw[len(prefix)];assert m&0xc7==5 and(m>>3)&7==reg;disp=struct.unpack_from('<i',raw,len(prefix)+1)[0];assert bindings[site]+size+disp==bindings[target];encodings[site]=raw.hex()
 assert bindings['bad_image']%16==0 and bindings['legacy_source']%16==0
 check('bad_image_reserved_MXCSR_precondition',u32(records['bad_image'],24),0x10000)
 check('bad_image_contrasting_control_precondition',u16(records['bad_image'],0),0x077f)
 check('bad_image_contrasts_live_MXCSR',cases['bad_fx']['before']['mxcsr']==u32(records['bad_image'],24),False)
 for n,off,v in [('fcs',12,0x1234),('fds',20,0x5678)]:
  check('legacy_source_distinct_'+n,u16(records['legacy_source'],off),v);check('legacy_restored_'+n,u16(records['legacy_after_l'],off),v)
 check('legacy_restored_env_fcs',u16(records['legacy_env'],16),0x1234);check('legacy_restored_env_fds',u16(records['legacy_env'],24),0x5678)
 for k,v in dict(fop=0x435,fip=0x12345678,fdp=0x23456780).items():check('legacy_restored_'+k,cases['legacy']['after'][k],v)
 for i,(cw,sw)in enumerate([(0x037f,0x3804),(0x037b,0xb884),(0x037f,0x3804),(0x037b,0xb884),(0x037f,0)]):
  b=records['mask_'+str(i)];check('mask_'+str(i)+'_fcw',u16(b,0),cw);check('mask_'+str(i)+'_fsw',u16(b,2),sw)
 check('fnstenv_stored_pre_mask_control',u16(records['mask_env'],0),0x037b);check('fnstenv_stored_pre_mask_status',u16(records['mask_env'],4),0xb884)
 for k,v in dict(fcw=0x0b7f,fsw=0,ftw=0,fop=0x435,fip=0x12345678,fdp=0x23456780).items():check('fldenv_readonly_complete_'+k,cases['fldenv_ro']['after'][k],v)
 a=cases['clex'];check('fnclex_clears_exception_summary',a['after']['fsw'],a['before']['fsw']&0x7f00)
 for k in('fcw','ftw','fip','fdp','fop','mxcsr','st','xmm'):check('fnclex_preserves_'+k,a['after'][k],a['before'][k])
 a=cases['init']
 for k,v in dict(fcw=0x037f,fsw=0,ftw=0,fop=0,fip=0,fdp=0).items():check('fninit_resets_'+k,a['after'][k],v)
 for k in('mxcsr','xmm'):check('fninit_preserves_'+k,a['after'][k],a['before'][k])
 check('fninit_nonzero_restore_precondition',[a['before'][k]for k in('fop','fip','fdp')],[0x435,0x112345678,0x223456780])
 fs=fields(records['fs_fx']);fs_masked=fields(records['fs_masked_fx']);fs_relation={'base':meta[11],'offset':0x28,'linear':meta[11]+0x28,'unmasked':fs,'masked':fs_masked,'scope':'Raw offset-vs-linear relation pending independent actualhost/primary interpretation; not waived or admitted'}
 check('fs_actual_unmasked_flags',fs['fsw']&0x84,0x84);check('fs_actual_fault_fip',fs['fip'],bindings['op_fs_fault'])
 # Exact FS prefix/SIB/absolute displacement, not a mnemonic or text claim.
 o=pe['offset'](pe['exports']['op_fs_fault'],8);assert imagebytes[o:o+8]==bytes.fromhex('64dc342528000000')
 check('fs_actual_unmasked_fop',fs['fop'],0x434)
 check('fs_actual_unmasked_linear_FDP',fs['fdp'],meta[11]+0x28)
 check('fs_actual_masked_linear_FDP',fs_masked['fdp'],meta[11]+0x28)
 check('fs_fnstenv_linear_FDP_low32',u32(records['fs_env'],20),(meta[11]+0x28)&0xffffffff)
 fs_relation['scope']='64-bit linear-FDP observation checked against independently captured actualhost FS+unmasked-memory reference; no broadvendor/nativeprofile admission'
 r=dict(collection_ok=True,conformance=all(t['passed']for t in tests),checks=tests,passed=sum(t['passed']for t in tests),failed=sum(not t['passed']for t in tests),bindings=bindings,encodings=encodings,meta=list(meta),cases=cases,fs_address_relation=fs_relation,scope='Authored original-emulator fault/order/control test; not fullarithmetic/nativeFP/OS admission',records=[{'path':str(out/(n+'.bin')),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}for n,b in records.items()]);(out/'analysis.json').write_text(json.dumps(r,indent=2)+'\n');return r
