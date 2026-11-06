import json,struct,re,hashlib,importlib.util
from pathlib import Path
P=Path(__file__).resolve().parents[1]/'pointer/checker.py';spec=importlib.util.spec_from_file_location('original_pe',P);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def u64(b,o):return struct.unpack_from('<Q',b,o)[0]
def defined(b):return b[:5]+b[6:28]+b''.join(b[32+16*i:42+16*i]for i in range(8))+b[160:416]
def analyze(image,serial,out,description):
 out=Path(out);out.mkdir();desc=json.loads(Path(description).read_text());text=Path(serial).read_bytes();assert b'FPCTRL COMPLETE'in text;pe=mod.inspect_pe(Path(image).read_bytes());records={};checks=[]
 def check(n,a,e):checks.append(dict(name=n,actual=a,expected=e,passed=a==e))
 for n,l,h in re.findall(rb'(?m)^FPREC ([a-z_0-9]+) ([0-9a-f]{16}) ([0-9a-f]+)\r?$',text):
  n=n.decode();b=bytes.fromhex(h.decode());assert n not in records and len(b)==int(l,16)==desc['records'][n];records[n]=b;(out/(n+'.bin')).write_bytes(b)
 assert set(records)==set(desc['records']);meta=struct.unpack('<16Q',records['meta']);base=meta[1]-pe['entry_rva'];bindings={n:base+rva for n,rva in pe['exports'].items()};assert meta[0]==0x46504354524c3031 and meta[9]==bindings['ro_env']and meta[10]==bindings['pml4'];assert bindings['bss_end']<0x200000;check('actual_named_CPU',meta[7]&0xffffffff,0x206a1);check('actual_XSAVE_feature',bool(meta[12]&(1<<26)),True);check('actual_OSXSAVE_control',bool(meta[13]&(1<<18)),True);check('actual_XCR0',meta[14],3)
 for name,w in [('xwide',True),('xlegacy',False)]:
  b=records[name];check(name+'_XSTATE_BV',u64(b,512),3);check(name+'_header_reserved',b[520:576].hex(),bytes(56).hex());check(name+'_fop',u16(b,6),0x435);check(name+'_FIP',u64(b,8)if w else u32(b,8),0x112345678 if w else 0x12345678);check(name+'_FDP',u64(b,16)if w else u32(b,16),0x223456780 if w else 0x23456780)
  if not w:check('saved_legacy_FCS',u16(b,12),0x1234);check('saved_legacy_FDS',u16(b,20),0x5678)
 for n in desc['cases']:
  b=records['case_'+n];ev=struct.unpack('<8Q',b[:64]);before=b[64:576];after=b[576:1088];bad=n.startswith('bad');check(n+'_fault_count',ev[7],1 if bad else 0)
  if bad:
   check(n+'_GP',ev[0],13);check(n+'_exact_fault_site',ev[2],bindings['op_'+n]);check(n+'_no_partial_defined_state',defined(after).hex(),defined(before).hex())
  elif n in('xrstorw','xrstorl'):
   source=records['xwide'if n=='xrstorw'else'xlegacy'];expected=bytearray(source[:512])
   if n=='xrstorl':expected[8:16]=u32(source,8).to_bytes(8,'little');expected[16:24]=u32(source,16).to_bytes(8,'little')
   check(n+'_complete_defined_restore',defined(after).hex(),defined(expected).hex())
  else:
   for k,o,w,v in [('FCW',0,2,0x37f),('FSW',2,2,0),('FTW',4,1,0),('FOP',6,2,0),('FIP',8,8,0),('FDP',16,8,0)]:check(n+'_init_'+k,int.from_bytes(after[o:o+w],'little'),v)
   check(n+'_standard_MXCSR_loaded',u32(after,24),u32(records['xwide'],24));check(n+'_FP_payload_init',b''.join(after[32+16*i:42+16*i]for i in range(8)).hex(),bytes(80).hex());check(n+'_XMM_init_or_restore',after[160:416].hex(),records['xwide'][160:416].hex()if n=='initfp'else bytes(256).hex())
 for name,offset,v in [('legacy_FCS',12,0x1234),('legacy_FDS',20,0x5678)]:check('restored_'+name,u16(records['after_legacy'],offset),v)
 check('restored_legacy_ENV_FCS',u16(records['after_legacy_env'],16),0x1234);check('restored_legacy_ENV_FDS',u16(records['after_legacy_env'],24),0x5678)
 # Exact source images and operand encoding/alignment prove these#GPs are
 # caused by the intended header/MXCSR condition, not a substituted address.
 check('bad_MXCSR_source',u32(records['xbad'],24),0x10000);check('bad_XCOMP_source',u64(records['xbadhdr'],520),1<<63);check('bad_XSTATE_source',u64(records['xbadbit'],512),7)
 enc={};raw=Path(image).read_bytes()
 for site,target,wide,selector in [('op_xsavew','xwide',True,4),('op_xsavel','xlegacy',False,4),('op_badmxcsr','xbad',True,5),('op_badheader','xbadhdr',True,5),('op_badstatebit','xbadbit',True,5),('op_xrstorw','xwide',True,5),('op_xrstorl','xlegacy',False,5),('op_initfp','xinitfp',True,5),('op_initall','xinitall',True,5)]:
  prefix=b'\x48\x0f\xae'if wide else b'\x0f\xae';n=len(prefix)+5;rva=pe['exports'][site];o=pe['offset'](rva,n);b=raw[o:o+n];assert b.startswith(prefix);m=b[len(prefix)];assert m&0xc7==5 and(m>>3)&7==selector;disp=struct.unpack_from('<i',b,len(prefix)+1)[0];assert bindings[site]+n+disp==bindings[target]and bindings[target]%64==0;enc[site]=b.hex()
 r=dict(collection_ok=True,conformance=all(t['passed']for t in checks),checks=checks,passed=sum(t['passed']for t in checks),failed=sum(not t['passed']for t in checks),meta=list(meta),bindings=bindings,encodings=enc,scope=desc['scope']);(out/'analysis.json').write_text(json.dumps(r,indent=2)+'\n');return r
