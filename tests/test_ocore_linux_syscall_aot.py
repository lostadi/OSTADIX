"""An actual generated .O executable must refuse opaque platform effects.

This is a negative pure-leaf integration gate, not a Linux execution provider.
The complete authored one-function unit uses unchanged original syscall headers.
The selected safe number is getuid only if a regression wrongly executes it.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


def identity(path):
    path=Path(path)
    return {'path':str(path.resolve()),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}


class LinuxSyscallAotRefusalTests(unittest.TestCase):
    def test_actual_interpreter_and_compiled_o_refuse_user_platform_effect_before_leaf_preparation(self):
        if not os.environ.get('OCOREC_BIN') or not os.environ.get('OLANGC_BIN'):
            self.skipTest('explicit separately built OCOREC_BIN and OLANGC_BIN required; no implicit tool build')
        compiler=Path(os.environ['OCOREC_BIN']).resolve();olangc=Path(os.environ['OLANGC_BIN']).resolve();o=compiler.parent/'O'
        self.assertTrue(o.is_file(),'the actual O interpreter is required')
        sdk=Path(os.environ.get('OCORE_TEST_LLVM_BIN',str(Path.home()/'.cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin')))
        library=Path.home()/'.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/lib/libLLVM.so.22.1-rust-1.97.1-stable'
        rust=Path.home()/'.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin'
        selected=os.environ.get('OCORE_TEST_LINUX_SYSCALL_AOT_OUTPUT_DIR')
        output=Path(selected) if selected else Path(tempfile.mkdtemp(prefix='ocore-linux-aot-refusal-'))
        output.mkdir(parents=True,exist_ok=False) if selected else None
        env=os.environ.copy();env.pop('CARGO_TARGET_DIR',None)
        env.update(PATH=str(sdk)+':'+env.get('PATH',''),CARGO=str(Path.home()/'.cargo/bin/cargo'),RUSTC=str(rust/'rustc'),RUSTUP_TOOLCHAIN='1.97.1',CARGO_NET_OFFLINE='true',CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='1',
            CARGO_PROFILE_RELEASE_OPT_LEVEL='0',CARGO_PROFILE_RELEASE_DEBUG='0',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_RELEASE_LTO='false',CARGO_PROFILE_RELEASE_CODEGEN_UNITS='16')
        tmp=output/'tmp';tmp.mkdir();env['TMPDIR']=str(tmp)
        commands=[]
        def command(argv,label,success=True,timeout=300):
            p=subprocess.run(list(map(str,argv)),env=env,cwd=ROOT,capture_output=True,timeout=timeout)
            out=output/(label+'.stdout');err=output/(label+'.stderr');out.write_bytes(p.stdout);err.write_bytes(p.stderr)
            commands.append({'argv':list(map(str,argv)),'cwd':str(ROOT),'exit':p.returncode,'stdout':identity(out),'stderr':identity(err)})
            (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
            if success:self.assertEqual(p.returncode,0,p.stderr.decode(errors='replace'))
            return p
        before=[identity(p) for p in [compiler,olangc,o,library,ROOT/'crates/ostadix-api/src/native_leaf.rs',ROOT/'crates/ostadix-api/src/ocore/native_platform.rs',ROOT/'crates/ostadix-api/src/api/aot_source.rs']]
        (output/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n')
        isa={'arm64':'aarch64'}.get(platform.machine(),platform.machine());self.assertIn(isa,{'x86_64','aarch64','riscv64'})
        header=Path.home()/'.cache/okernel-u9fs-native-recipe/sources/musl/arch'/isa/'syscall_arch.h'
        source=output/'raw0.c';source.write_text('#include "syscall_arch.h"\nlong raw0(long number){ return __syscall0(number); }\n')
        llvm=output/'raw0.ll';flags=['-march=rv64gc','-mabi=lp64d'] if isa=='riscv64' else []
        command([sdk/'clang','--target='+isa+'-unknown-linux-musl',*flags,'-O2','-ffreestanding','-fno-builtin','-frounding-math','-I',header.parent,'-S','-emit-llvm',source,'-o',llvm],'frontend')
        native=output/'raw0.native.json'
        command([compiler,llvm,'--input-kind','llvm-ir','--target',isa+'-unknown-none','--emit','mir','--linux-syscall-profile','linux-user-raw-v1','--llvm-library',library,'--llvm-sha256','ed4f320c4e1ed6de7d2db6fd89faccf764d63186c2f877057ddf31065b1fac09','-o',native],'whole-import')
        command([compiler,native,'--input-kind','native-ir','--verify-native','--receipt',output/'verify.json'],'verify')
        module=json.loads(native.read_text());self.assertEqual(len(module['functions']),1);self.assertFalse(module['globals'])
        function=module['functions'][0];self.assertEqual(function['name'],'raw0')
        self.assertTrue(all(module['types'][ty]=={'kind':'int','bits':64} for ty in [function['signature']['result'],*function['signature']['params']]))
        descriptor=json.dumps({'schema':'ocore-native-i64-leaf-v1','entry':'raw0','module':module},separators=(',',':'))
        nr=102 if isa=='x86_64' else 174
        program=output/'platform-refusal.O';program.write_text(f'let x = text^({nr})_text;\nlet x = ocore_i64(text^({descriptor})_text, $x);\ntext^(UNREACHABLE-PLATFORM-EFFECT:$x)_text\n')
        interpreted=command([o,program],'interpreted',success=False)
        self.assertNotEqual(interpreted.returncode,0)
        self.assertIn(b'native scalar leaf excludes external Linux platform effects',interpreted.stderr)
        self.assertNotIn(b'UNREACHABLE-PLATFORM-EFFECT',interpreted.stdout)
        product=output/'program'
        built=command([olangc,program,'--target','binary','-o',product,'--keep-build-dir'],'actual-aot-build',timeout=600)
        projects=re.findall(rb'^olangc: keeping build directory: (.+)$',built.stderr,re.M);self.assertEqual(len(projects),1)
        project=Path(os.fsdecode(projects[0]));self.assertEqual(product.read_bytes()[:4],b'\x7fELF')
        for name,source_path in [('native_leaf.rs',ROOT/'crates/ostadix-api/src/native_leaf.rs'),('ocore/native_platform.rs',ROOT/'crates/ostadix-api/src/ocore/native_platform.rs'),('ocore/mod.rs',ROOT/'crates/ostadix-api/src/ocore/native_core.rs')]:
            self.assertEqual((project/'src'/name).read_bytes(),source_path.read_bytes())
        compiled=command([product],'actual-aot-refusal',success=False)
        self.assertNotEqual(compiled.returncode,0)
        self.assertIn(b'native scalar leaf excludes external Linux platform effects',compiled.stderr)
        self.assertNotIn(b'UNREACHABLE-PLATFORM-EFFECT',compiled.stdout)
        after=[identity(record['path']) for record in before];self.assertEqual(before,after)
        (output/'result.json').write_text(json.dumps({'scope':'actual interpreted and generated .O pure-leaf refusal; no raw platform effect/provider execution admitted','passed':True,'source_unit':identity(source),'original_header':identity(header),'llvm':identity(llvm),'native_module':identity(native),'program':identity(program),'product':identity(product),'generated_project':str(project),'inputs_before':before,'inputs_after':after,'commands':commands,'native_linux_provider_qualified':False,'runtime_complete':False},indent=2)+'\n')


if __name__=='__main__':unittest.main()
