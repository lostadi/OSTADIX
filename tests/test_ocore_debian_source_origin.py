#!/usr/bin/env python3
"""Authored source-origin controls, UNRUN in publication. Real tiny dpkg-source
extraction is intentional. No compiler/LLVM/source build or runtime qualification.
All mkdtemp fixtures are retained. Main must select exact extractor bytes first.
"""
import argparse, ast, contextlib, hashlib, io, json, os
from pathlib import Path
import stat, subprocess, tarfile, tempfile, types, unittest
from unittest import mock
WORKER_SHA='758bec4a31a3384113d31f4517d2a9ef16ddbf6a1824dc071aace756433c7c36'
# Parse the frozen legacy source with the selected Python so optional AST
# dump-field formatting differences across recipient Python versions are harmless.
GIT_VERIFY_SOURCE = r'''def verify_source(recipe: dict, source: Path) -> dict:
    head = run_text(["git", "rev-parse", "HEAD"], source)
    if head != recipe["source"]["revision"]:
        raise CaptureError(f"source commit mismatch: expected {recipe['source']['revision']}, got {head}")
    dirty = run_text(["git", "status", "--porcelain", "--untracked-files=normal"], source)
    if dirty:
        raise CaptureError(f"source checkout must be clean before capture:\n{dirty}")
    submodules = run_text(["git", "submodule", "status", "--recursive"], source)
    if any(line.startswith(("-", "+", "U")) for line in submodules.splitlines()):
        raise CaptureError("source submodules must be initialized at their pinned commits")
    return {"path": str(source), "url": recipe["source"]["url"], "revision": head,
            "commit_timestamp": run_text(["git", "show", "-s", "--format=%ct", "HEAD"], source),
            "submodules": submodules.splitlines(), "clean_at_start": True}'''
ROOT=Path(__file__).resolve().parents[1]
WORKER=ROOT/'scripts/ocore_runtime_capture.py'
raw=WORKER.read_bytes()
if hashlib.sha256(raw).hexdigest()!=WORKER_SHA: raise RuntimeError('selected worker bytes differ')
capture=types.ModuleType('selected_capture'); capture.__file__=str(WORKER)
exec(compile(raw,str(WORKER),'exec'),capture.__dict__)

def independent_tree(root):
    rows=[]
    for p in sorted(root.rglob('*'),key=lambda x:x.relative_to(root).as_posix()):
        s=p.lstat(); row={'path':p.relative_to(root).as_posix(),'mode':stat.S_IMODE(s.st_mode)}
        if p.is_symlink(): row.update(kind='symlink',target=os.readlink(p))
        elif p.is_dir(): row.update(kind='directory')
        else:
            data=p.read_bytes(); row.update(kind='file',bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
        rows.append(row)
    data=json.dumps({'schema':'ocore-debian-logical-source-tree-v1','entries':rows},sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    return hashlib.sha256(data).hexdigest()

class DebianSourceOriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(os.environ['OSTADIX_DEBIAN_ORIGIN_TEST_DPKG_SOURCE']).resolve()
        expected=os.environ['OSTADIX_DEBIAN_ORIGIN_TEST_DPKG_SHA256']
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected: raise RuntimeError('selected real dpkg-source differs')
        cls.extractor={'path':str(path),'bytes':len(raw),'sha256':expected}
    def setUp(self):
        self.root=Path(tempfile.mkdtemp(prefix='ostadix-debian-origin-fixture-')).resolve()
        self.bundle=self.root/'bundle'; self.bundle.mkdir()
        self.build=self.root/'build'; self.build.mkdir()
        self.archive('tiny_1.0.orig.tar.xz',{'tiny-1.0/value.txt':b'before\n','tiny-1.0/main.c':b'int main(void){return 0;}\n'})
        self.archive('tiny_1.0-1.debian.tar.xz',{
            'debian/source/format':b'3.0 (quilt)\n',
            'debian/control':b'Source: tiny\nSection: misc\nPriority: optional\nMaintainer: Fixture <fixture@example.invalid>\nStandards-Version: 4.7.0\n\nPackage: tiny\nArchitecture: any\nDescription: source-origin data fixture\n',
            'debian/changelog':b'tiny (1.0-1) unstable; urgency=low\n\n  * Authored fixture.\n\n -- Fixture <fixture@example.invalid>  Thu, 01 Jan 1970 00:00:00 +0000\n',
            'debian/rules':b'#!/usr/bin/make -f\n%:\n\t:\n',
            'debian/patches/series':b'one.patch\n',
            'debian/patches/one.patch':b'--- a/value.txt\n+++ b/value.txt\n@@ -1 +1 @@\n-before\n+after\n'})
        archives=[self.descriptor(n) for n in ('tiny_1.0.orig.tar.xz','tiny_1.0-1.debian.tar.xz')]
        self.write_dsc(archives)
        reference=self.root/'independent-reference'
        result=subprocess.run([self.extractor['path'],'--extract',str(self.bundle/'tiny.dsc'),str(reference)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode,0,result.stdout.decode(errors='replace'))
        self.assertEqual((reference/'value.txt').read_bytes(),b'after\n')
        self.recipe={'schema':capture.RECIPE_SCHEMA,'name':'tiny-debian-data','source':{
            'kind':'debian-source-v1','package':'tiny','version':'1.0-1','dsc':self.descriptor('tiny.dsc'),'archives':archives,
            'extractor':dict(self.extractor),'expected_tree_sha256':independent_tree(reference),'authentication':{'mode':'caller-pinned'}},
            'toolchain':{'llvm_version':'22.1.6'},'commands':[{'argv':['/definitely-absent-source-build']}],
            'coverage':{'required_units':[{'id':'main','source':'main.c','kind':'clang'}]},'dependencies':[]}
    def descriptor(self,name):
        b=(self.bundle/name).read_bytes(); return {'file':name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
    def archive(self,name,files,extra=None):
        with tarfile.open(self.bundle/name,'w:xz') as t:
            for path,data in files.items():
                h=tarfile.TarInfo(path); h.size=len(data); h.mode=0o755 if path.endswith('/rules') else 0o644; h.mtime=0
                t.addfile(h,io.BytesIO(data))
            if extra is not None: t.addfile(extra)
    def write_dsc(self,archives,format='3.0 (quilt)'):
        rows=''.join(' '+p['sha256']+' '+str(p['bytes'])+' '+p['file']+'\n' for p in archives)
        md5=''.join(' '+hashlib.md5((self.bundle/p['file']).read_bytes()).hexdigest()+' '+str(p['bytes'])+' '+p['file']+'\n' for p in archives)
        (self.bundle/'tiny.dsc').write_text('Format: '+format+'\nSource: tiny\nBinary: tiny\nArchitecture: any\nVersion: 1.0-1\nMaintainer: Fixture <fixture@example.invalid>\nChecksums-Sha256:\n'+rows+'Files:\n'+md5)
    def owner(self):
        p=self.root/('capture-'+next(tempfile._get_candidate_names())); p.mkdir(); return p
    def materialize(self):
        return capture.verify_source_origin(self.recipe,self.bundle,directory=self.owner())
    def before_tool_refusal(self,reason):
        with mock.patch.object(capture.subprocess,'run',side_effect=AssertionError('fresh extractor unexpectedly reached')) as run:
            with self.assertRaisesRegex(capture.CaptureError,reason): self.materialize()
            self.assertEqual(run.call_count,0)
    def ordinary_capture(self):
        recipe=self.root/'recipe.json'; recipe.write_text(json.dumps(self.recipe)); output=self.root/('ordinary-'+next(tempfile._get_candidate_names()))
        args=argparse.Namespace(manifest=str(recipe),source=str(self.bundle),build=str(self.build),output=str(output),unit_inventory=None,jobs=1,
            cc='/absent/clang',cxx='/absent/clang++',llvm_nm='/absent/nm',llvm_dis='/absent/dis',rustc='/absent/rustc',cargo='/absent/cargo')
        with mock.patch.object(capture,'snapshot_worker',return_value={}),mock.patch.object(capture,'tool_info',side_effect=capture.CaptureError('source-only controlled stop before frontend')),contextlib.redirect_stdout(io.StringIO()):
            rc=capture.capture(args)
        self.assertEqual(rc,1)
        return output,json.loads((output/'session.json').read_text())
    def test_real_quilt_materialization_matches_preheld_tree_and_rechecks(self):
        state=self.materialize(); self.assertEqual((Path(state['path'])/'value.txt').read_bytes(),b'after\n')
        self.assertEqual(state['tree']['sha256'],self.recipe['source']['expected_tree_sha256'])
        self.assertEqual(state['patches']['applied'],['one.patch'])
        self.assertNotIn('revision',state); self.assertNotIn('commit_timestamp',state)
        self.assertEqual(capture.verify_source_origin(self.recipe,Path(state['path']),context=state),state)
        self.assertFalse(state['authentication']['signed_metadata_verified'])
    def test_actual_capture_dispatch_retains_realized_tree_before_frontend_stop(self):
        output,session=self.ordinary_capture(); source=session['source']
        self.assertEqual(source['kind'],'debian-source-v1'); self.assertNotEqual(source['path'],str(self.bundle))
        self.assertEqual(source['input_root'],str(self.bundle)); self.assertTrue(Path(source['path']).is_relative_to(output))
        report=json.loads((output/'report.json').read_text()); self.assertFalse(report['capture_complete'])
        self.assertIsNotNone(report['source_origin_attempt'])
        self.assertIn('source-only controlled stop before frontend',session['issues'])
    def test_make_report_missing_tag_cannot_bypass_via_clean_at_start(self):
        output,session=self.ordinary_capture(); session['source'].pop('kind'); session['source'].pop('clean_at_start',None)
        capture.write_json(output/'session.json',session)
        report=capture.make_report(output,persist=False)
        self.assertTrue(any('tagged materialized source record is missing' in s for s in report['issues']),report['issues'])
        self.assertFalse(report['capture_complete'])
    def test_verify_report_rechecks_tagged_source_before_reconstruction(self):
        state=self.materialize(); directory=self.owner(); units=directory/'units/u'; units.mkdir(parents=True)
        recipe=self.root/'readmission-recipe.json'; recipe.write_text(json.dumps(self.recipe)); inventory=directory/'inventory.json'; inventory.write_text('{}')
        session={'recipe':self.recipe,'manifest':capture.file_info(recipe),'source':state,'inventory_path':str(inventory),'inventory_artifact':capture.file_info(inventory),'tools':{}}
        capture.write_json(directory/'session.json',session)
        report={'schema':capture.REPORT_SCHEMA,'units':[{'ir':{'path':str(units/'unit.ll')}}]}
        registry=json.loads((ROOT/'scripts/ocore_producer_registry.json').read_text())
        with mock.patch.object(capture,'verify_worker'),mock.patch.object(capture,'verified_producer_registry',return_value=registry),mock.patch.object(capture,'make_report',side_effect=RuntimeError('after-real-origin-check')) as rebuilt:
            with self.assertRaisesRegex(RuntimeError,'after-real-origin-check'): capture.verify_report(report,WORKER_SHA)
            self.assertEqual(rebuilt.call_count,1); rebuilt.reset_mock()
            (Path(state['path'])/'value.txt').write_text('mutated\n')
            with self.assertRaisesRegex(capture.CaptureError,'complete source tree'): capture.verify_report(report,WORKER_SHA)
            self.assertEqual(rebuilt.call_count,0)
    def test_missing_archive_row_fails_before_fresh_extractor(self):
        self.recipe['source']['archives'].pop(); self.before_tool_refusal('complete ordered dsc archive list differs')
    def test_reordered_complete_archive_rows_fail_before_fresh_extractor(self):
        before=list(self.recipe['source']['archives']); self.recipe['source']['archives'].reverse()
        self.assertCountEqual(before,self.recipe['source']['archives']); self.assertNotEqual(before,self.recipe['source']['archives'])
        self.before_tool_refusal('complete ordered dsc archive list differs')
    def test_archive_byte_mismatch_fails_before_fresh_extractor(self):
        path=self.bundle/self.recipe['source']['archives'][0]['file']; path.write_bytes(path.read_bytes()+b'x')
        self.before_tool_refusal('selected input bytes/SHA256 differ')
    def test_malformed_dsc_checksum_row_is_reached_after_valid_pin(self):
        p=self.bundle/'tiny.dsc'; p.write_text(p.read_text().replace('Checksums-Sha256:\n','Checksums-Sha256:\n invalid row\n'))
        self.recipe['source']['dsc']=self.descriptor('tiny.dsc'); self.before_tool_refusal('malformed dsc Checksums-Sha256 row')
    def test_unsupported_source_format_is_explicit_before_fresh_extractor(self):
        self.write_dsc(self.recipe['source']['archives'],'1.0'); self.recipe['source']['dsc']=self.descriptor('tiny.dsc')
        self.before_tool_refusal('unsupported source format')
    def unsafe_archive(self,entry,reason):
        name=self.recipe['source']['archives'][0]['file']; self.archive(name,{'tiny-1.0/value.txt':b'before\n'},entry)
        self.recipe['source']['archives'][0]=self.descriptor(name); self.write_dsc(self.recipe['source']['archives']); self.recipe['source']['dsc']=self.descriptor('tiny.dsc')
        self.before_tool_refusal(reason)
    def test_parent_traversal_archive_member_fails_before_tool(self):
        h=tarfile.TarInfo('tiny-1.0/../escaped'); h.size=0; self.unsafe_archive(h,'unsafe archive member path')
    def test_escaping_symlink_fails_before_tool(self):
        h=tarfile.TarInfo('tiny-1.0/link'); h.type=tarfile.SYMTYPE; h.linkname='../escaped'
        self.unsafe_archive(h,'escaping archive symlink')
    def test_special_archive_member_fails_before_tool(self):
        h=tarfile.TarInfo('tiny-1.0/fifo'); h.type=tarfile.FIFOTYPE; self.unsafe_archive(h,'unsupported special/hardlink')
    def test_wrong_expected_tree_rejects_after_real_extraction_before_build(self):
        self.recipe['source']['expected_tree_sha256']='0'*64; owner=self.owner()
        with self.assertRaisesRegex(capture.CaptureError,'materialized tree differs from caller-held expected digest'):
            capture.verify_source_origin(self.recipe,self.bundle,directory=owner)
        result=json.loads((owner/'source-origin/materialization.json').read_text())
        self.assertEqual(result['exit_code'],0); self.assertFalse(result['success']); self.assertTrue(result['errors'])
        self.assertEqual((owner/'source-origin/source/value.txt').read_bytes(),b'after\n'); self.assertTrue(Path(result['log']['path']).is_file())
    def test_postbuild_content_mode_and_membership_mutations_fail(self):
        for mutation in ('content','mode','extra','missing'):
            with self.subTest(mutation=mutation):
                state=self.materialize(); root=Path(state['path']); p=root/'value.txt'
                if mutation=='content': p.write_text('changed\n')
                elif mutation=='mode': p.chmod(0o600)
                elif mutation=='extra': (root/'unselected').write_text('x')
                else: p.unlink()
                with self.assertRaisesRegex(capture.CaptureError,'complete source tree'): capture.verify_source_origin(self.recipe,root,context=state)
    def test_git_verifier_ast_and_epoch_behavior_are_preserved(self):
        tree=ast.parse(raw); node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='verify_source')
        self.assertEqual(ast.dump(node,include_attributes=False),
                         ast.dump(ast.parse(GIT_VERIFY_SOURCE).body[0],include_attributes=False))
        env={}; capture.source_default_epoch(env,{'commit_timestamp':'123'}); self.assertEqual(env,{'SOURCE_DATE_EPOCH':'123'})
        env={'SOURCE_DATE_EPOCH':'999'}; capture.source_default_epoch(env,{'commit_timestamp':'123'}); self.assertEqual(env['SOURCE_DATE_EPOCH'],'999')
        capture.source_default_epoch(env,{'kind':'debian-source-v1'}); self.assertNotIn('SOURCE_DATE_EPOCH',env)
        env.update({'SOURCE_DATE_EPOCH':'explicit-recipe-value'}); self.assertEqual(env['SOURCE_DATE_EPOCH'],'explicit-recipe-value')

    def test_readmission_coherent_input_record_forgery_cannot_replace_recipe_pins(self):
        state=self.materialize(); root=Path(state['path'])
        self.assertEqual(capture.verify_source_origin(self.recipe,root,context=state),state)
        selected=dict(self.recipe['source']['archives'][0]); item=state['inputs'][1]
        self.assertEqual(item['selected'],selected)
        for role in ('original','snapshot'):
            p=Path(item[role]['path']); p.chmod(0o600); p.write_bytes(p.read_bytes()+b'coherent-unselected-byte-change')
            item[role]=capture._debian_pin(p)
            self.assertNotEqual(item[role]['sha256'],selected['sha256'])
            self.assertGreater(item[role]['bytes'],selected['bytes'])
        receipt_path=Path(state['materialization']['path']); receipt=json.loads(receipt_path.read_text())
        receipt['inputs']=state['inputs']; capture.write_json(receipt_path,receipt)
        state['materialization']=capture._debian_pin(receipt_path)
        self.assertEqual(state['inputs'][1]['selected'],selected)
        self.assertEqual(self.recipe['source']['archives'][0],selected)
        with self.assertRaisesRegex(capture.CaptureError,'selected input bytes/SHA256 differ'):
            capture.verify_source_origin(self.recipe,root,context=state)
    def test_missing_or_malformed_expected_tree_digest_refuses_before_tools(self):
        selected=self.recipe['source']['expected_tree_sha256']
        del self.recipe['source']['expected_tree_sha256']
        self.assertNotIn('expected_tree_sha256',self.recipe['source'])
        self.before_tool_refusal('recipe source fields differ')
        self.recipe['source']['expected_tree_sha256']='g'*64
        self.assertNotEqual(self.recipe['source']['expected_tree_sha256'],selected)
        self.before_tool_refusal('caller-held expected tree digest is missing or malformed')
    def test_boolean_input_length_is_rejected_before_tools(self):
        original=self.recipe['source']['dsc']['bytes']; self.assertIs(type(original),int)
        self.recipe['source']['dsc']['bytes']=True
        self.assertIs(type(self.recipe['source']['dsc']['bytes']),bool)
        self.before_tool_refusal('selected input length is not a nonnegative integer')

    def test_unknown_and_mixed_origin_tags_refuse_before_git_or_extractor(self):
        for tag in ('git','future-origin-v1',None):
            with self.subTest(tag=tag):
                recipe={'source':{'kind':tag,'url':'https://example.invalid/upstream','revision':'a'*40}}
                self.assertIn('kind',recipe['source']); self.assertNotEqual(tag,'debian-source-v1')
                with mock.patch.object(capture,'run_text',side_effect=AssertionError('Git reached')) as git,mock.patch.object(capture.subprocess,'run',side_effect=AssertionError('extractor reached')) as tool:
                    with self.assertRaisesRegex(capture.CaptureError,'unsupported source origin tag'):
                        capture.verify_source_origin(recipe,self.bundle,directory=self.owner())
                    self.assertEqual(git.call_count,0); self.assertEqual(tool.call_count,0)
        mixed=json.loads(json.dumps(self.recipe)); mixed['source']['revision']='a'*40
        self.assertEqual(mixed['source']['kind'],'debian-source-v1'); self.assertIn('revision',mixed['source'])
        with mock.patch.object(capture,'run_text',side_effect=AssertionError('Git reached')) as git,mock.patch.object(capture.subprocess,'run',side_effect=AssertionError('extractor reached')) as tool:
            with self.assertRaisesRegex(capture.CaptureError,'recipe source fields differ'):
                capture.verify_source_origin(mixed,self.bundle,directory=self.owner())
            self.assertEqual(git.call_count,0); self.assertEqual(tool.call_count,0)
        output,session=self.ordinary_capture(); session['recipe']['source']['kind']='future-origin-v1'; capture.write_json(output/'session.json',session)
        with mock.patch.object(capture,'run_text',side_effect=AssertionError('Git reached')) as git:
            report=capture.make_report(output,persist=False)
            self.assertTrue(any('unsupported source origin tag' in s for s in report['issues']),report['issues'])
            self.assertFalse(report['capture_complete']); self.assertEqual(git.call_count,0)
    def test_legacy_git_keeps_version_metadata_but_rejects_debian_fields_and_tags(self):
        source={'url':'https://example.invalid/upstream','revision':'a'*40,'version':'2.41-12+deb13u4'}
        calls=[]
        def git(argv,cwd=None):
            calls.append((argv,cwd))
            if argv==['git','rev-parse','HEAD']: return 'a'*40
            if argv==['git','status','--porcelain','--untracked-files=normal']: return ''
            if argv==['git','submodule','status','--recursive']: return ''
            if argv==['git','show','-s','--format=%ct','HEAD']: return '123'
            raise AssertionError(argv)
        with mock.patch.object(capture,'run_text',side_effect=git),mock.patch.object(capture.subprocess,'run',side_effect=AssertionError('extractor reached')) as tool:
            result=capture.verify_source_origin({'source':source},self.bundle)
            self.assertEqual(result['revision'],'a'*40); self.assertEqual(result['commit_timestamp'],'123')
            self.assertEqual(source['version'],'2.41-12+deb13u4'); self.assertEqual(len(calls),4)
            self.assertTrue(all(cwd==self.bundle for _,cwd in calls)); self.assertEqual(tool.call_count,0)
        for field,value in (('dsc',{}),('archives',[]),('extractor',{}),('expected_tree_sha256','0'*64)):
            with self.subTest(field=field):
                mixed={**source,field:value}; self.assertIn(field,mixed)
                with mock.patch.object(capture,'run_text',side_effect=AssertionError('Git reached')) as git,mock.patch.object(capture.subprocess,'run',side_effect=AssertionError('extractor reached')) as tool:
                    with self.assertRaisesRegex(capture.CaptureError,'legacy Git source cannot carry Debian origin fields'):
                        capture.verify_source_origin({'source':mixed},self.bundle)
                    self.assertEqual(git.call_count,0); self.assertEqual(tool.call_count,0)
        for tag in ('debian-source-v1','git'):
            with self.subTest(context_tag=tag),mock.patch.object(capture,'run_text',side_effect=AssertionError('Git reached')) as git:
                with self.assertRaisesRegex(capture.CaptureError,'legacy Git recipe/source origin tag differs'):
                    capture.verify_source_origin({'source':source},self.bundle,context={'kind':tag})
                self.assertEqual(git.call_count,0)
    def test_primary_orig_root_symlink_is_rejected_before_prefix_stripping(self):
        h=tarfile.TarInfo('tiny-1.0'); h.type=tarfile.SYMTYPE; h.linkname='/outside'
        self.assertEqual(h.name,'tiny-1.0'); self.assertEqual(h.type,tarfile.SYMTYPE)
        self.assertEqual(h.linkname,'/outside'); self.assertFalse(h.isdir()); self.assertTrue(h.issym())
        self.unsafe_archive(h,'non-directory orig leading-root member')
    def coherent_materialization_receipt(self,mutate):
        state=self.materialize(); root=Path(state['path'])
        self.assertEqual(capture.verify_source_origin(self.recipe,root,context=state),state)
        expected_recipe=json.dumps(self.recipe,sort_keys=True)
        path=Path(state['materialization']['path']); before=dict(state['materialization']); receipt=json.loads(path.read_text())
        self.assertEqual(receipt['schema'],'ocore-debian-source-materialization-v1')
        self.assertIs(type(receipt['exit_code']),int); self.assertEqual(receipt['exit_code'],0)
        self.assertIs(type(receipt['errors']),list); self.assertEqual(receipt['errors'],[])
        mutate(receipt); capture.write_json(path,receipt); state['materialization']=capture._debian_pin(path)
        self.assertNotEqual(state['materialization']['sha256'],before['sha256'])
        self.assertEqual(capture._debian_pin(path),state['materialization'])
        self.assertEqual(json.dumps(self.recipe,sort_keys=True),expected_recipe)
        self.assertEqual(capture.debian_source_tree(root),state['tree'])
        for item in state['inputs']:
            for role in ('original','snapshot'):
                self.assertEqual(capture._debian_pin(Path(item[role]['path']),item['selected']),item[role])
        return state,json.loads(path.read_text())
    def test_recorded_materialization_schema_is_exact_after_coherent_pin_update(self):
        for variant in ('missing','wrong'):
            with self.subTest(variant=variant):
                def mutate(doc):
                    if variant=='missing': doc.pop('schema')
                    else: doc['schema']='wrong-materialization-schema/v1'
                state,receipt=self.coherent_materialization_receipt(mutate)
                if variant=='missing': self.assertNotIn('schema',receipt)
                else: self.assertEqual(receipt['schema'],'wrong-materialization-schema/v1')
                with self.assertRaisesRegex(capture.CaptureError,'materialization receipt schema differs'):
                    capture.verify_source_origin(self.recipe,Path(state['path']),context=state)
    def test_recorded_exit_requires_exact_integer_zero_after_coherent_pin_update(self):
        for value in (False,0.0):
            with self.subTest(value=value,type=type(value).__name__):
                state,receipt=self.coherent_materialization_receipt(lambda doc:doc.__setitem__('exit_code',value))
                self.assertIs(type(receipt['exit_code']),type(value)); self.assertEqual(receipt['exit_code'],0)
                self.assertIsNot(type(receipt['exit_code']),int)
                with self.assertRaisesRegex(capture.CaptureError,'materialization exit_code must be exact integer zero'):
                    capture.verify_source_origin(self.recipe,Path(state['path']),context=state)
    def test_recorded_errors_require_actual_empty_list_after_coherent_pin_update(self):
        for variant in ('missing','none','dict'):
            with self.subTest(variant=variant):
                def mutate(doc):
                    if variant=='missing': doc.pop('errors')
                    elif variant=='none': doc['errors']=None
                    else: doc['errors']={}
                state,receipt=self.coherent_materialization_receipt(mutate)
                if variant=='missing': self.assertNotIn('errors',receipt)
                elif variant=='none': self.assertIsNone(receipt['errors'])
                else: self.assertIs(type(receipt['errors']),dict); self.assertEqual(receipt['errors'],{})
                with self.assertRaisesRegex(capture.CaptureError,'materialization errors must be an actual empty list'):
                    capture.verify_source_origin(self.recipe,Path(state['path']),context=state)

    def test_legacy_git_actual_checkout_revision_and_dirty_guards(self):
        root=self.root/'original-git-fixture'; root.mkdir()
        source=root/'main.c'; source.write_text('int main(void){return 0;}\n')
        def git(*args):
            result=subprocess.run(['git',*args],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
            return result.stdout.decode().strip()
        git('init','-q'); git('add','main.c')
        git('-c','user.name=Lee Daghlar Ostadi','-c','user.email=ostadi.lee@gmail.com',
            '-c','commit.gpgsign=false','commit','-qm','Authored Git source-origin fixture')
        revision=git('rev-parse','HEAD')
        recipe={'source':{'revision':revision,'url':'https://example.invalid/authored-fixture'}}
        self.assertTrue(capture.verify_source(recipe,root)['clean_at_start'])
        wrong={'source':{**recipe['source'],'revision':'0'*40}}
        with self.assertRaisesRegex(capture.CaptureError,'source commit mismatch'):
            capture.verify_source(wrong,root)
        source.write_text('int main(void){return 1;}\n')
        with self.assertRaisesRegex(capture.CaptureError,'source checkout must be clean'):
            capture.verify_source(recipe,root)
        source.write_text('int main(void){return 0;}\n')
        (root/'unexpected.c').write_text('untracked source\n')
        with self.assertRaisesRegex(capture.CaptureError,'source checkout must be clean'):
            capture.verify_source(recipe,root)

if __name__=='__main__': unittest.main()
