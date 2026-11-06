"""USER note-retention parser controls; no original two-unit/runtime claim.

Run with explicit OCORE_ORIGINAL_PROCESS_NOTE_OBJECT pointing to an already
qualified x86 Linux USER getuid object. The authored entry is never executed.
"""
import hashlib,importlib.util,os,shutil,struct,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];HERE=ROOT/'ocore/kernel/native_original_process'
spec=importlib.util.spec_from_file_location('original_process_artifact_gate',HERE/'verify.py');gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
class UserNotes(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if not os.environ.get('OCORE_ORIGINAL_PROCESS_NOTE_OBJECT'):raise unittest.SkipTest('requires explicit retained Linux USER getuid object/profile; no automatic component qualification')
  cls.object=Path(os.environ['OCORE_ORIGINAL_PROCESS_NOTE_OBJECT']).resolve(strict=True);cls.scratch=tempfile.TemporaryDirectory(prefix='original-process-notes.');cls.dir=Path(cls.scratch.name);cls.src=cls.dir/'entry.c';cls.src.write_text('extern unsigned getuid(void); void _start(void){ volatile unsigned x=getuid(); (void)x; __asm__ volatile("ud2"); }\n');cls.entry=cls.dir/'entry.o';cls.final=cls.dir/'user.elf';cls.commands=[]
  for argv in [[shutil.which('clang'),'-O2','-ffreestanding','-fno-stack-protector','-fno-pic','-fno-pie','-c',str(cls.src),'-o',str(cls.entry)],[shutil.which('ld.lld'),'-m','elf_x86_64','-nostdlib','--build-id=none','-z','max-page-size=0x1000','-T',str(HERE/'user.ld'),'-o',str(cls.final),str(cls.entry),str(cls.object)]]:
   p=subprocess.run(argv,capture_output=True);cls.commands.append({'argv':argv,'status':p.returncode,'stdout_hex':p.stdout.hex(),'stderr_hex':p.stderr.hex()});assert p.returncode==0,p.stderr
  cls.before=gate.info(cls.object);cls.data=cls.final.read_bytes();cls.expected=gate.elf(cls.object)['notes'];assert len(cls.expected)==1
 @classmethod
 def tearDownClass(cls):
  assert gate.info(cls.object)==cls.before
  archive=os.environ.get('OCORE_ORIGINAL_PROCESS_NOTE_ARCHIVE')
  if archive:
   out=Path(archive);out.mkdir(exist_ok=False);rows=[]
   for p in cls.dir.iterdir():
    d=out/p.name;d.write_bytes(p.read_bytes());rows.append(gate.info(d))
   import json
   (out/'carriers.json').write_text(json.dumps({'scope':__doc__,'source_object':cls.before,'commands':cls.commands,'artifacts':rows},indent=2)+'\n')
  cls.scratch.cleanup()
 def modified(self,changes):
  b=bytearray(self.data)
  for offset,value,fmt in changes:struct.pack_into(fmt,b,offset,value)
  p=self.dir/('negative-'+str(len(list(self.dir.glob('negative-*'))))+'.elf');p.write_bytes(b);return p
 def ph(self):
  off=struct.unpack_from('<Q',self.data,32)[0];size,num=struct.unpack_from('<HH',self.data,54);return[(off+i*size,struct.unpack_from('<IIQQQQQQ',self.data,off+i*size))for i in range(num)]
 def test_actual_note_kept_readonly_and_source_bound(self):
  actual=gate.elf(self.final);self.assertEqual(actual['notes'],self.expected);self.assertFalse(actual['undefined']);self.assertEqual(actual['symbols']['getuid']['bytes'],gate.elf(self.object)['symbols']['getuid']['bytes'])
 def test_missing_note_program_header_rejected(self):
  offset,_=next(x for x in self.ph()if x[1][0]==4)
  with self.assertRaisesRegex(AssertionError,'PT_NOTE'):gate.elf(self.modified([(offset,0,'<I')]))
 def test_writable_note_program_header_rejected(self):
  offset,_=next(x for x in self.ph()if x[1][0]==4)
  with self.assertRaisesRegex(AssertionError,'PT_NOTE'):gate.elf(self.modified([(offset+4,6,'<I')]))
 def test_writable_note_load_rejected(self):
  _,note=next(x for x in self.ph()if x[1][0]==4);offset,_=next(x for x in self.ph()if x[1][0]==1 and x[1][2]<=note[2]<x[1][2]+x[1][5])
  with self.assertRaisesRegex(AssertionError,'readonly nonexec PT_LOAD'):gate.elf(self.modified([(offset+4,6,'<I')]))
 def test_wrong_note_owner_rejected(self):
  _,note=next(x for x in self.ph()if x[1][0]==4)
  with self.assertRaises(AssertionError):gate.elf(self.modified([(note[2]+12,88,'<B')]))
 def test_truncated_note_descriptor_rejected(self):
  _,note=next(x for x in self.ph()if x[1][0]==4);size=struct.unpack_from('<I',self.data,note[2]+4)[0]
  with self.assertRaises((AssertionError,ValueError)):gate.elf(self.modified([(note[2]+4,size+8,'<I')]))
 def test_existing_one_unit_packet_is_not_two_unit_admission(self):
  product=Path(os.environ['OCORE_ORIGINAL_PROCESS_ONE_UNIT_PRODUCT']);reopened=Path(os.environ['OCORE_ORIGINAL_PROCESS_ONE_UNIT_REOPENED'])
  with self.assertRaises(AssertionError):gate.source_objects(product,reopened)
if __name__=='__main__':unittest.main()
