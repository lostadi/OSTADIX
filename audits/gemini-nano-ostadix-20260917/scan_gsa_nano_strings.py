import struct,zipfile,json,re,pathlib
apk=json.loads(pathlib.Path('audits/gemini-ostadix-20260917/googleapp/apk-index.json').read_text())['apk']
def uleb(d,o):
 v=0;s=0
 while True:
  b=d[o];o+=1;v|=(b&127)<<s;s+=7
  if b<128:return v,o
out=[]
with zipfile.ZipFile(apk) as z:
 for name in z.namelist():
  if not re.fullmatch(r'classes\d*\.dex',name):continue
  d=z.read(name);U=lambda o:struct.unpack_from('<I',d,o)[0]
  ss,so=U(56),U(60);ts,to=U(64),U(68);ms,mo=U(88),U(92);cs,co=U(96),U(100)
  strings=[]
  for i in range(ss):
   _,o=uleb(d,U(so+4*i));end=d.find(b'\x00',o);strings.append(d[o:end].decode('utf-8','replace'))
  hits={i:s for i,s in enumerate(strings) if len(s)<1000 and re.search(r'aicore|gemini.?nano|OnDeviceInferenceResult|generativelanguage.googleapis.com',s,re.I)}
  types=[strings[U(to+4*i)] for i in range(ts)]
  methods=[]
  for i in range(ms):
   cls,proto,sidx=struct.unpack_from('<HHI',d,mo+8*i);methods.append(types[cls]+'->'+strings[sidx])
  for ci in range(cs):
   cd=U(co+ci*32+24)
   if not cd:continue
   sf,cd=uleb(d,cd);inf,cd=uleb(d,cd);dm,cd=uleb(d,cd);vm,cd=uleb(d,cd)
   for fi in range(sf+inf):
    _,cd=uleb(d,cd);_,cd=uleb(d,cd)
   for mc in [dm,vm]:
    mi=0
    for _ in range(mc):
     delta,cd=uleb(d,cd);mi+=delta;flags,cd=uleb(d,cd);code,cd=uleb(d,cd)
     if not code:continue
     n=U(code+12);start=code+16
     refs=set()
     o=start
     while o < start+n*2:
      op=d[o];unit=struct.unpack_from('<H',d,o)[0]
      if op==0x1a:
       sidx=struct.unpack_from('<H',d,o+2)[0]
       if sidx in hits:refs.add(sidx)
      elif op==0x1b:
       sidx=U(o+2)
       if sidx in hits:refs.add(sidx)
      if op==0 and unit==0x100:w=4+2*struct.unpack_from('<H',d,o+2)[0]
      elif op==0 and unit==0x200:w=2+4*struct.unpack_from('<H',d,o+2)[0]
      elif op==0 and unit==0x300:w=4+(struct.unpack_from('<H',d,o+2)[0]*U(o+4)+1)//2
      elif op in [0x18]:w=5
      elif op in [0xfa,0xfb]:w=4
      elif op in [3,6,9,0x14,0x17,0x1b,0x24,0x25,0x26,0x2a,0x2b,0x2c,0xfc,0xfd] or 0x6e<=op<=0x72 or 0x74<=op<=0x78:w=3
      elif op in [2,5,8,0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,0x20,0x22,0x23,0x29,0xfe,0xff] or 0x2d<=op<=0x3d or 0x44<=op<=0x6d or 0x90<=op<=0xaf or 0xd0<=op<=0xe2:w=2
      else:w=1
      o+=w*2
     for i in refs:out.append({'dex':name,'method':methods[mi],'text':hits[i]})
print(json.dumps(out,indent=2))
