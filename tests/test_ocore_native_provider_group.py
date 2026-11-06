"""Actual olangc-owned original-build group integration; no fake compiler.

These authored complete-source fixtures test infrastructure, not an upstream
engine. Missing explicit compiled tools is an ERROR, never a passing skip.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]

def pin(path):
    path=Path(path).absolute()
    if not path.is_file():raise RuntimeError(f'required actual tool missing: {path}')
    return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

def required(name):
    value=os.environ.get(name)
    if not value:raise RuntimeError(f'{name} must explicitly select a real tool for required integration')
    return Path(value).absolute()

def run(argv,cwd=None):
    return subprocess.run(list(map(str,argv)),cwd=cwd,capture_output=True,text=True,timeout=300)

class NativeProviderGroupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.olangc=required('OCORE_PROVIDER_GROUP_OLANGC')
        cls.ocorec=cls.olangc.parent/'ocorec'
        cls.tools={'python':pin(Path(sys.executable).resolve()),
            **{key:pin(required('OCORE_PROVIDER_GROUP_'+key.upper())) for key in
                ('llvm_library','cc','cxx','rustc','cargo','llvm_nm','llvm_dis')},
            'compiler_sha256':pin(cls.ocorec)['sha256']}
        cls.compiler_before=pin(cls.olangc)
        cls.target=os.environ.get('OCORE_PROVIDER_GROUP_TARGET',platform.machine()+'-unknown-none')
        for tool in ('git','make'):
            if not shutil.which(tool):raise RuntimeError(f'required original build tool missing: {tool}')
        help_result=run([cls.olangc,'--help'])
        if help_result.returncode or '--native-runtime-provider-plan' not in help_result.stdout:
            raise RuntimeError('selected compiler does not implement the real provider-group CLI')
        root=required('OCORE_PROVIDER_GROUP_EVIDENCE')
        root.mkdir(exist_ok=True,parents=True)
        cls.directory=Path(tempfile.mkdtemp(prefix='actual-provider-group-',dir=root))
        source=ast.parse((ROOT/'tests/test_ocore_native_source_recipe.py').read_text())
        cls.inventory=next(ast.literal_eval(n.value) for n in source.body if isinstance(n,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id=='INVENTORY_SOURCE' for t in n.targets))

    def setUp(self):
        self.case=Path(tempfile.mkdtemp(prefix=self._testMethodName+'-',dir=self.directory))
        self.nodes=[]
        for name,other in [('alpha','beta'),('beta','alpha')]:
            source=self.case/name;source.mkdir()
            runtime=('extern unsigned long long provider(unsigned long long);\n'
                'unsigned long long engine(unsigned long long x) { return provider(x)+1; }\n'
                'void *retained_provider_reference=(void *)&provider;\n') if name=='alpha' else (
                'extern unsigned long long engine(unsigned long long);\n'
                'unsigned long long provider(unsigned long long x) { return x+2; }\n'
                'void *retained_engine_reference=(void *)&engine;\n')
            (source/'runtime.c').write_text(runtime)
            (source/'cold.c').write_text('const unsigned long long cold_data_'+name+'=0x1122334455667788ULL;\n'
                'unsigned long long cold_'+name+'(unsigned long long x) { return x-7; }\n')
            (source/'inventory.py').write_text(self.inventory)
            (source/'Makefile').write_text('SOURCES := runtime.c cold.c\nOBJECTS := $(addprefix $(BUILDDIR)/,$(SOURCES:.c=.o))\n'
                '.PHONY: all list-sources\nall: $(OBJECTS)\n$(BUILDDIR)/%.o: $(SOURCE)/%.c\n'
                '\t$(CC) $(CFLAGS) -c $< -o $@\nlist-sources:\n\t@printf \'%s\\n\' $(SOURCES)\n')
            for argv in [['git','init','-q'],['git','add','.'],['git','-c','user.name=Lee Daghlar Ostadi',
                '-c','user.email=ostadi.lee@gmail.com','commit','-qm','complete authored provider-group infrastructure fixture']]:
                result=run(argv,cwd=source);self.assertEqual(result.returncode,0,result.stderr)
            revision=run(['git','rev-parse','HEAD'],cwd=source).stdout.strip()
            recipe={'schema':'ocore-runtime-recipe-v1','name':name,'source':{'url':'local-original-provider-group-fixture','revision':revision},
                'toolchain':{'llvm_version':'22.1.6'},'dependencies':[{'name':'original-other','source_pin':None}],
                'commands':[{'name':'build-original-fixture','argv':['make','--no-print-directory','-f','{source}/Makefile',
                    'SOURCE={source}','BUILDDIR={build}','CC={cc}','CFLAGS=-O0 -fno-builtin -fno-stack-protector','all']},
                    {'name':'inventory-original-build','argv':[self.tools['python']['path'],'{source}/inventory.py','{source}','{build}','{build}/unit-inventory.json']}],
                'coverage':{'require_full_unit_inventory':True,'audit_roots':['{build}'],'required_outputs':['runtime.o','cold.o'],
                    'required_units':[{'id':'floor-runtime','kind':'clang','source':'runtime.c','role':'runtime'},
                                      {'id':'floor-cold','kind':'clang','source':'cold.c','role':'runtime'}]}}
            recipe_path=self.case/(name+'.recipe.json');recipe_path.write_text(json.dumps(recipe))
            self.nodes.append({'id':name,'recipe':pin(recipe_path),'source':str(source.resolve()),'dependencies':{'original-other':other}})
        self.plan={'schema':'ocore-native-provider-plan-v1','root':'alpha','tools':self.tools,'components':self.nodes}
        self.policy=self.case/'provider-plan.json';self.write_policy()
        self.before=self.source_snapshot()

    def write_policy(self):self.policy.write_text(json.dumps(self.plan))
    def source_snapshot(self):
        return {str(p.relative_to(self.case)):hashlib.sha256(p.read_bytes()).hexdigest() for n in self.nodes
            for p in Path(n['source']).rglob('*') if p.is_file() and '.git' not in p.relative_to(n['source']).parts}
    def tearDown(self):
        self.assertEqual(self.before,self.source_snapshot())
        self.assertEqual(self.compiler_before,pin(self.olangc))
        self.assertEqual(self.tools['compiler_sha256'],pin(self.ocorec)['sha256'])
        for key,value in self.tools.items():
            if isinstance(value,dict):self.assertEqual(value,pin(value['path']))
    def invoke(self,name='product',kind='ir',input_path=None):
        source_route=input_path is None
        input_path=input_path or self.nodes[0]['recipe']['path']
        argv=[self.olangc,input_path,'--native-runtime','--native-runtime-provider-plan',self.policy,
            '--native-isa',self.target,'--native-runtime-output',kind,'--llvm-library',self.tools['llvm_library']['path'],
            '--llvm-sha256',self.tools['llvm_library']['sha256'],'-o',self.case/name]
        if source_route:argv.extend(['--native-runtime-source',self.nodes[0]['source'],'--native-runtime-jobs','1'])
        result=run(argv)
        (self.case/(name+'.command.json')).write_text(json.dumps({'argv':list(map(str,argv)),'exit_code':result.returncode}))
        (self.case/(name+'.stdout')).write_text(result.stdout);(self.case/(name+'.stderr')).write_text(result.stderr)
        return result,self.case/name
    def success(self):
        result,output=self.invoke();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        report=json.loads((output/'provider-group.json').read_text())
        self.assertTrue(report['source_group_complete']);self.assertTrue(report['lowering_complete'])
        self.assertEqual(len(report['components']),2)
        self.assertTrue(all(c['source_inventory_complete'] for c in report['components']))
        for field in ('artifact_complete','platform_resource_closure_complete','native_execution_qualified','runtime_complete'):
            self.assertFalse(report[field])
        path=output/'source-group.native-ir.json';package=json.loads(path.read_text())
        self.assertEqual(len(package['module_set']['modules']),4)
        names={g['name'] for m in package['module_set']['modules'] for g in json.loads(m['native_ir'])['globals']}
        self.assertTrue({'cold_data_alpha','cold_data_beta','retained_engine_reference','retained_provider_reference'}<=names)
        return path,package
    def test_actual_owned_source_cycles_and_public_original_ir_readmission_to_objects(self):
        path,_=self.success();result,output=self.invoke('readmitted','obj',path)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        report=json.loads((output/'source-readmission.json').read_text())
        self.assertTrue(report['included_original_ir_body_consistency'])
        self.assertFalse(report['original_checkout_build_reverified'])
        self.assertEqual(len(report['units']),4)
        for unit in report['units']:
            rebound=unit['diagnostic_name_rebinding']
            self.assertEqual(rebound['rebound_field'],'name')
            self.assertNotEqual(rebound['captured'],rebound['fresh'])
            self.assertTrue(Path(rebound['fresh']).is_absolute())
            self.assertEqual(Path(rebound['fresh']).name,'original.ll')
            self.assertTrue(unit['fresh_typed_import_match'])
        self.assertEqual(len(list((output/'lowered').glob('unit-*/module.o'))),4)
    def test_missing_original_provider_remains_red_after_all_original_units_stage(self):
        self.plan['components'][0]['dependencies']={};self.plan['components'][1]['dependencies']={}
        # Keep only the root reachable; the missing original provider is not a supplied artifact.
        self.plan['components']=self.plan['components'][:1];self.write_policy()
        result,output=self.invoke();self.assertEqual(result.returncode,1,result.stderr)
        report=json.loads((output/'provider-group.json').read_text())
        self.assertTrue(report['components'][0]['source_inventory_complete'])
        self.assertIn('unresolved or ambiguous original dependency original-other',' '.join(report['issues']))
        self.assertFalse(report['source_group_complete']);self.assertFalse((output/'source-group.native-ir.json').exists())
    def test_public_reader_rejects_omitted_cold_original_unit(self):
        _,package=self.success()
        component=package['components'][0]
        capture=json.loads(component['capture_json'])
        cold=next(u['id'] for u in capture['units'] if Path(u['source']['path']).name=='cold.c')
        component['units']=[u for u in component['units'] if u['id']!=cold]
        path=self.case/'partial.json';path.write_text(json.dumps(package))
        result,_=self.invoke('reject-cold',input_path=path)
        self.assertEqual(result.returncode,1);self.assertIn('source group omitted selected original units',result.stderr)
    def verified_mutant(self,package,mutate,name):
        embedded=next(m for m in package['module_set']['modules'] if m['component']=='alpha'
            and any(f['name']=='engine' for f in json.loads(m['native_ir'])['functions']))
        module=json.loads(embedded['native_ir']);mutate(module)
        data=json.dumps(module);module_path=self.case/(name+'.native-ir.json');module_path.write_text(data)
        verification=self.case/(name+'.verification.json')
        argv=[self.ocorec,module_path,'--input-kind','native-ir','--verify-native','--receipt',verification]
        result=run(argv)
        (self.case/(name+'.verify-command.json')).write_text(json.dumps({'argv':list(map(str,argv)),'exit_code':result.returncode,
            'stdout':result.stdout,'stderr':result.stderr}))
        self.assertEqual(result.returncode,0,result.stderr)
        proof=json.loads(verification.read_text());self.assertTrue(proof['verified'])
        self.assertEqual(proof['module_sha256'],hashlib.sha256(data.encode()).hexdigest())
        embedded['native_ir']=data;embedded['sha256']=hashlib.sha256(data.encode()).hexdigest()
        path=self.case/(name+'.group.json');path.write_text(json.dumps(package));return path
    def test_well_typed_forged_arithmetic_fails_genuine_fresh_original_body_readmission(self):
        _,package=self.success()
        def mutate(module):
            engine=next(f for f in module['functions'] if f['name']=='engine')
            additions=[i['operation'] for b in engine['blocks'] for i in b['instructions']
                if i['operation']['op']=='binary' and i['operation']['kind']=='add'
                and i['operation']['rhs'].get('kind')=='int' and i['operation']['rhs']['bits']=='1']
            self.assertEqual(len(additions),1,'fixture must retain the original arithmetic')
            additions[0]['rhs']['bits']='2'
        path=self.verified_mutant(package,mutate,'forged-body')
        result,output=self.invoke('reject-forged-body',input_path=path)
        self.assertEqual(result.returncode,1)
        self.assertIn('fresh original LLVM import does not match embedded typed NativeModule',(output/'source-readmission.json').read_text())
    def test_well_typed_initializer_change_fails_independent_original_global_accounting(self):
        _,package=self.success()
        def mutate(module):
            # A data byte remains a valid native initializer. Only comparison
            # with the unchanged complete original LLVM detects this change.
            reference=next(g for g in module['globals'] if g['name']=='retained_provider_reference')
            self.assertTrue(reference['initializer']['relocations'])
            reference['initializer']['relocations'][0]['addend']+=8
        path=self.verified_mutant(package,mutate,'forged-initializer')
        result,output=self.invoke('reject-forged-initializer',input_path=path)
        self.assertEqual(result.returncode,1)
        self.assertIn('independent source inventory failed',(output/'source-readmission.json').read_text())
    def test_opaque_supplied_engine_cannot_satisfy_source_group_contract(self):
        path=self.case/'supplied-engine';path.write_bytes(self.olangc.read_bytes())
        result,output=self.invoke('reject-elf',input_path=path)
        self.assertEqual(result.returncode,1);self.assertFalse(output.exists())
    def test_pinned_tool_mismatch_rejects_before_any_build_output(self):
        self.plan['tools']=json.loads(json.dumps(self.tools));self.plan['tools']['compiler_sha256']='0'*64;self.write_policy()
        result,output=self.invoke();self.assertEqual(result.returncode,1)
        self.assertIn('compiler pin differs',result.stderr);self.assertFalse(output.exists())

if __name__=='__main__':unittest.main(verbosity=2)
