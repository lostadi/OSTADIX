"""Generic executable pointer constants, not an original runtime/OS profile.

Original source targets/layouts are reused, never retargeted. Authored LLVM
units test the primitive. Static Clang test entry/driver and Linux/QEMU-user
are explicit external test dependencies, not lowered implementation closure.
"""
import copy
import json
import os
from pathlib import Path
import re
import struct
import sys
import unittest

from tests import test_ocore_linux_syscall as base

ADDEND = 0x7654321087654329
HIGH_ADDEND = -(1 << 63) + 0x13579
WIDTHS = [*range(1,65),128]


def source_header(original):
    return '\n'.join(line for line in original.splitlines() if line.startswith(('target datalayout','target triple')))


def width_module(isa,original):
    lines=[source_header(original),'@data = hidden global i64 72991, align 8']
    for width in WIDTHS:
        addend=HIGH_ADDEND if width==128 else ADDEND
        expression=f'ptrtoint (ptr getelementptr (i8, ptr @data, i64 {addend}) to i{width})'
        lines.append(f'define i{width} @p{width}() strictfp {{\n ret i{width} {expression}\n}}')
        if width<64:
            lines.append(f'define i64 @b{width}() strictfp {{\n %r=call i{width} @p{width}() strictfp\n %z=zext i{width} %r to i64\n ret i64 %z\n}}')
        elif width==64:
            lines.append('define i64 @b64() strictfp {\n %r=call i64 @p64() strictfp\n ret i64 %r\n}')
        else:
            lines.append('define i64 @b128lo() strictfp {\n %r=call i128 @p128() strictfp\n %z=trunc i128 %r to i64\n ret i64 %z\n}')
            lines.append('define i64 @b128hi() strictfp {\n %r=call i128 @p128() strictfp\n %s=lshr i128 %r, 64\n %z=trunc i128 %s to i64\n ret i64 %z\n}')
    # A missing narrow mask is observable before the first comparison; an ABI
    # caller's later zero-extension cannot hide this regression.
    lines.append(f'define i64 @cmp3() strictfp {{\n %r=icmp eq i3 ptrtoint (ptr getelementptr (i8, ptr @data, i64 {ADDEND}) to i3), 1\n %z=zext i1 %r to i64\n ret i64 %z\n}}')
    if isa=='riscv64':lines+=['!llvm.module.flags = !{!0}','!0 = !{i32 1, !"target-abi", !"lp64d"}']
    return '\n'.join(lines)+'\n'


def width_carrier():
    prefix=base.CARRIER.split('static U observed')[0]
    entry=base.CARRIER[base.CARRIER.rindex('#if defined(__x86_64__)'):]
    funcs=[('b'+str(width),f'(((U)&data+{ADDEND}UL)&'+(str((1<<width)-1)+'UL)' if width<64 else '~0UL)')) for width in range(1,65)]
    funcs += [('b128lo',f'((U)&data+{(1<<63)+0x13579}UL)'),('b128hi','0'),('cmp3','1')]
    declarations='extern U data;\n'+'\n'.join(f'extern U {name}(void);'for name,_ in funcs)
    code=r'''
static U observed[67];
static int capture(U index,U result,U expected,U *before){
 U after[3];fenv_get(after);
#ifdef CORRUPT_ORACLE
 if(index==0)expected^=1;
#endif
 U record[10]={index,result,expected,FENV_ROUND,before[0],before[1],before[2],after[0],after[1],after[2]};
 if(setup(NR_WRITE,2,(U)record,sizeof(record),0,0,0)!=sizeof(record))return 33;
 for(U i=0;i<3;i++)if(before[i]!=after[i])return 31;
 if(!fenv_expected(before)||result!=expected)return 31;
 observed[index]=result;return 0;
}
int conformance_main(void){
 if((U)&data!=0x600000UL||data!=72991)return 32;
 U before[3],value;int failed;
'''
    for i,(fn,expect)in enumerate(funcs):
        code+=f' fenv_set();fenv_get(before);value={fn}();failed=capture({i},value,{expect},before);if(failed)return failed;\n'
    code+=' if(!(observed[64]>>63)||observed[65]!=0||observed[66]!=1)return 31;\n if(setup(NR_WRITE,1,(U)observed,sizeof(observed),0,0,0)!=sizeof(observed))return 34;\n return 0;\n}\n'
    return prefix+declarations+code+entry


LINK_SCRIPT='''ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x400000;
 .text : { *(.text .text.*) } :text
 .rodata : { *(.rodata .rodata.*) } :text
 . = 0x600000;
 .data : { *(.data .data.* .sdata .sdata.*) *(.got .got.*) } :data
 .bss : { *(.bss .bss.* .sbss .sbss.* COMMON) } :data
 /DISCARD/ : { *(.comment) *(.note.GNU-stack) }
}
'''


def rich_module(isa,original):
    high=f'ptrtoint (ptr getelementptr (i8, ptr @data, i64 {HIGH_ADDEND}) to i128)'
    lines=[source_header(original),'@data = hidden global i64 72991, align 8',
           '@alias_data = alias i64, ptr @data','@must = external global i64, align 8',
           '@optional = extern_weak global i64, align 8',
           'declare extern_weak i64 @optional_fn(i64)',
           '@anchor = global ptr blockaddress(@block_probe, %destination), align 8']
    for name,symbol in [('alias_addr','alias_data'),('must_addr','must'),('optional_addr','optional'),('optional_fn_addr','optional_fn')]:
        lines.append(f'define i64 @{name}() strictfp {{\n ret i64 ptrtoint (ptr @{symbol} to i64)\n}}')
    lines.append('define i64 @negative_gep() strictfp {\n ret i64 ptrtoint (ptr getelementptr (i8, ptr @data, i64 -37) to i64)\n}')
    for name,tail in [('aggregate_lo','%r=trunc i128 %v to i64'),('aggregate_hi','%s=lshr i128 %v, 64\n %r=trunc i128 %s to i64')]:
        lines.append(f'define i64 @{name}() strictfp {{\n %v=extractvalue {{i64,i128}} {{i64 ptrtoint (ptr @data to i64),i128 {high}}},1\n {tail}\n ret i64 %r\n}}')
    lines.append('define i64 @select_source(i1 %c) strictfp {\n %v=select i1 %c, i64 ptrtoint (ptr @data to i64), i64 ptrtoint (ptr @alias_data to i64)\n ret i64 %v\n}')
    lines.append('define i64 @phi_source(i1 %c) strictfp {\n br i1 %c,label %left,label %right\nleft:\n br label %join\nright:\n br label %join\njoin:\n %v=phi i64 [ptrtoint (ptr @data to i64),%left],[ptrtoint (ptr @alias_data to i64),%right]\n ret i64 %v\n}')
    lines.append('define i64 @identity(i64 %x) strictfp {ret i64 %x}\ndefine i64 @call_source() strictfp {\n %v=call i64 @identity(i64 ptrtoint (ptr getelementptr (i8,ptr @data,i64 13)to i64)) strictfp\n ret i64 %v\n}')
    lines.append('define i64 @block_probe() strictfp {\n br label %destination\ndestination:\n ret i64 ptrtoint (ptr blockaddress(@block_probe,%destination)to i64)\n}')
    lines.append('define i64 @block_low32() strictfp {\n %v=zext i32 ptrtoint (ptr blockaddress(@block_probe,%destination)to i32)to i64\n ret i64 %v\n}')
    if isa=='riscv64':lines+=['!llvm.module.flags = !{!0}','!0 = !{i32 1,!"target-abi",!"lp64d"}']
    return '\n'.join(lines)+'\n'


def rich_carrier():
    prefix=base.CARRIER.split('static U observed')[0];entry=base.CARRIER[base.CARRIER.rindex('#if defined(__x86_64__)'):]
    declarations=r'''
extern U data,must;
extern U optional __attribute__((weak));
extern U optional_fn(U) __attribute__((weak));
extern void *anchor;
extern U alias_addr(void),must_addr(void),optional_addr(void),optional_fn_addr(void),negative_gep(void),aggregate_lo(void),aggregate_hi(void),select_source(_Bool),phi_source(_Bool),call_source(void),block_probe(void),block_low32(void);
'''
    cases=[('alias_addr()','(U)&data'),('must_addr()','(U)&must'),('optional_addr()','(U)&optional'),('optional_fn_addr()','(U)&optional_fn'),('negative_gep()','(U)&data-37'),('aggregate_lo()',f'(U)&data+{(1<<63)+0x13579}UL'),('aggregate_hi()','0'),('select_source(0)','(U)&data'),('select_source(1)','(U)&data'),('phi_source(0)','(U)&data'),('phi_source(1)','(U)&data'),('call_source()','(U)&data+13'),('block_probe()','(U)anchor'),('block_low32()','(U)anchor&0xffffffffUL')]
    body=r'''
static U observed[14];
static int capture(U i,U value,U expected,U *before){
 U after[3];fenv_get(after);U record[10]={i,value,expected,FENV_ROUND,before[0],before[1],before[2],after[0],after[1],after[2]};
 if(setup(NR_WRITE,2,(U)record,sizeof(record),0,0,0)!=sizeof(record))return 33;
 for(U j=0;j<3;j++)if(before[j]!=after[j])return 31;
 if(!fenv_expected(before)||value!=expected)return 31;
 observed[i]=value;return 0;
}
int conformance_main(void){
 if((U)&data!=0x600000UL||data!=72991||must!=0x731)return 32;
#if PROVIDER_MODE==0
 if(&optional||optional_fn)return 32;
#else
 if(!&optional||!optional_fn)return 32;
 if(optional!=(PROVIDER_MODE==1?0x111:0x222))return 32;
 if(optional_fn(0xabc)!=(0xabcUL^(PROVIDER_MODE==1?0x111UL:0x222UL)))return 32;
#endif
 if(!anchor)return 32;
 U before[3],value;int failed;
'''
    for i,(call,expect)in enumerate(cases):body+=f' fenv_set();fenv_get(before);value={call};failed=capture({i},value,{expect},before);if(failed)return failed;\n'
    body+=' if(setup(NR_WRITE,1,(U)observed,sizeof(observed),0,0,0)!=sizeof(observed))return 34;return 0;\n}\n'
    return prefix+declarations+body+entry


RICH_LINK_SCRIPT=LINK_SCRIPT.replace(' .bss :',' . = 0x700000;\n .provider_data : { *(.provider_data) } :data\n .bss :').replace(' .rodata :',' . = 0x500000;\n .provider_code : { *(.provider_code) } :text\n .rodata :')


def linked_symbols(path):
    data=Path(path).read_bytes();assert data[:7]==b'\x7fELF\x02\x01\x01'
    offset=struct.unpack_from('<Q',data,40)[0];stride,count=struct.unpack_from('<HH',data,58);assert stride==64 and count
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,offset+stride*i)for i in range(count)];symbols={}
    for section in sections:
        if section[1]!=2:continue
        strings=sections[section[6]];names=data[strings[4]:strings[4]+strings[5]];assert section[9]==24
        for pos in range(section[4],section[4]+section[5],24):
            name,info,other,index,value,size=struct.unpack_from('<IBBHQQ',data,pos);end=names.index(0,name);key=names[name:end].decode()
            if key:symbols[key]={'value':value,'binding':info>>4,'type':info&15,'section':index,'size':size,'other':other}
    return symbols


ORIGINAL_STRINGS=['','.', '/', '0', 'A', 'z', 'zzzzz', 'zzzzzz', 'bad#tail', '000000', 'a', 'Invalid!']
ORIGINAL_NUMBERS=[0,1,63,64,0x7fffffff,0x80000000,0xffffffff,0x12345678]


def original_component_carrier():
    digits='./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    def decode(text):
        value=0
        for index,char in enumerate(text[:6]):
            if char not in digits:break
            value=(value|(digits.index(char)<<(index*6)))&0xffffffff
        return value-(1<<32)if value>>31 else value
    def encode(value):
        text=''
        while value:text+=digits[value&63];value>>=6
        return int.from_bytes(text.encode(),'little')
    prefix=base.CARRIER.split('static U observed')[0];entry=base.CARRIER[base.CARRIER.rindex('#if defined(__x86_64__)'):]
    body='extern long a64l(const char*);\nextern char*l64a(long);\nstatic U observed[20];\n'
    body+=r'''
static int capture(U index,U value,U expected,U compare,U *before){
 U after[3];fenv_get(after);U record[10]={index,value,expected,FENV_ROUND,before[0],before[1],before[2],after[0],after[1],after[2]};
 if(setup(NR_WRITE,2,(U)record,sizeof(record),0,0,0)!=sizeof(record))return 33;
 for(U j=0;j<3;j++)if(before[j]!=after[j])return 31;
 if(!fenv_expected(before)||(compare&&value!=expected))return 31;return 0;
}
int conformance_main(void){U before[3],value;int failed;char *text;
'''
    for index,text in enumerate(ORIGINAL_STRINGS):
        body+=f' fenv_set();fenv_get(before);value=(U)a64l({json.dumps(text)});failed=capture({index},value,{decode(text)&((1<<64)-1)}UL,1,before);if(failed)return failed;observed[{index}]=value;\n'
    for index,value in enumerate(ORIGINAL_NUMBERS,len(ORIGINAL_STRINGS)):
        expected=encode(value)
        body+=f' fenv_set();fenv_get(before);text=l64a({value}UL);failed=capture({index},(U)text,0,0,before);if(failed)return failed;if(!text)return 32;value=0;U n{index}=0;for(;n{index}<7&&text[n{index}];n{index}++)value|=(U)(unsigned char)text[n{index}]<<(8*n{index});if(n{index}>6||value!={expected}UL)return 31;observed[{index}]=value;\n'
    body+=' if(setup(NR_WRITE,1,(U)observed,sizeof(observed),0,0,0)!=sizeof(observed))return 34;return 0;}\n'
    return prefix+body+entry


class ConstantPointerTests(base.LinuxSyscallTests):
    test_compiler_owned_original_recipe_provider_and_strict_source_readmission=None
    test_original_complete_getuid_three_isa_source_and_required_linux_provider=None
    test_owned_child_all_twenty_one_register_forms_and_fenv_against_original=None
    test_original_call_contracts_do_not_become_generic_assembly_or_metadata_waivers=None
    test_source_witness_and_profile_negative_controls_fail_closed=None

    def test_complete_original_a64l_unit_and_explicit_unmet_dependency_group(self):
        records=[]
        for isa in base.UNITS:
            case=self.directory/isa;case.mkdir();rust=Path.home()/'.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin'
            def pin(path):return{'path':str(Path(path).resolve()),'sha256':base.identity(path)['sha256']}
            tools={'python':pin(Path(sys.executable).resolve()),'llvm_library':pin(self.library),**{key:pin(self.sdk/name)for key,name in [('cc','clang'),('cxx','clang++'),('llvm_nm','llvm-nm'),('llvm_dis','llvm-dis')]},'rustc':pin(rust/'rustc'),'cargo':pin(rust/'cargo'),'compiler_sha256':base.identity(self.compiler)['sha256']}
            recipe=base.ROOT/'tools/ocore-runtime/constant-ptrtoint'/(isa+'.a64l.recipe.json');name=json.loads(recipe.read_text())['name'];musl=Path.home()/'.cache/okernel-u9fs-native-recipe/sources/musl';plan=case/'provider-plan.json'
            plan.write_text(json.dumps({'schema':'ocore-native-provider-plan-v1','root':name,'tools':tools,'components':[{'id':name,'recipe':pin(recipe),'source':str(musl),'dependencies':{}}]},indent=2)+'\n')
            def arguments(input_,output):return[self.olangc,input_,'--native-runtime','--native-runtime-provider-plan',plan,'--native-isa',isa+'-unknown-none','--native-runtime-output','obj','--llvm-library',self.library,'--llvm-sha256',base.LIB_SHA,'-o',output]
            product=case/'product'
            rejected=self.command([*arguments(recipe,product),'--native-runtime-source',musl,'--native-runtime-jobs','2'],success=False,timeout=300)
            group=json.loads((product/'provider-group.json').read_text())
            self.assertFalse(group['source_group_complete']);self.assertFalse(group['artifact_complete'])
            self.assertIn('unresolved',str(group['issues']));self.assertIn('strchr',str(group['issues']))
            component=product/'component-000000';coverage=json.loads((component/'lowered/coverage.json').read_text())
            self.assertTrue(coverage['unit_lowering_complete']);self.assertFalse(coverage['symbol_closure_complete'])
            self.assertTrue(group['components'][0]['source_inventory_complete']);self.assertTrue(group['components'][0]['capture_complete'])
            path=component/'lowered/unit-000000/module.native-ir.json';original=component/'lowered/unit-000000/original-input.ll';module=json.loads(path.read_text());functions={f['name']:f for f in module['functions']}
            self.assertEqual(set(functions),{'a64l','l64a','strchr'});self.assertTrue(all(functions[n]['entry']is not None for n in ['a64l','l64a']));self.assertIsNone(functions['strchr']['entry']);self.assertEqual(module['provenance']['source_function_count'],3)
            self.inventory.audit_native_module(original,module,self.library,base.LIB_SHA)
            fresh=case/'fresh-native.json';self.command([self.compiler,original,'--input-kind','llvm-ir','--target',isa+'-unknown-none','--emit','mir','--llvm-library',self.library,'--llvm-sha256',base.LIB_SHA,'-o',fresh]);self.assertEqual(json.loads(fresh.read_text()),module,'complete fresh original input import, no body/name/field exclusions')
            owned=case/'owned-component.o';self.command([self.compiler,path,'--input-kind','native-ir','--target',isa+'-unknown-none','-o',owned]);reference=component/'build/obj/src/misc/a64l.o'
            # The unchanged unit's strong strchr provider is the separately
            # inventoried original libc archive, not a handwritten replacement
            # or an invented O-core closure. Link maps retain selected members.
            archive=self.source_root/isa/'build/lib/libc.a';self.assertTrue(archive.is_file());archive_before=base.identity(archive);carrier=case/'external-component-bootstrap.c';carrier.write_text(original_component_carrier());triple=module['target']['triple'];flags=['-march=rv64gc','-mabi=lp64d']if isa=='riscv64'else[];prefix=[]if isa==os.uname().machine else[Path.home()/'.local/share/ostadix/bm-dev/host/usr/bin'/('qemu-'+isa)];observations=[]
            for mode in range(5 if isa=='riscv64'else 4):
                pair=[]
                for implementation,obj in [('reference',reference),('owned',owned)]:
                    exe=case/(implementation+'-fenv-'+str(mode));map_=exe.with_suffix('.map');self.command([self.sdk/'clang','--target='+triple,*flags,'--ld-path='+str(self.sdk/'ld.lld'),'-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-vectorize','-fno-slp-vectorize','-fno-pic','-fno-pie','-nostdlib','-static','-Wl,--no-relax','-Wl,-e,_start','-Wl,-Map='+str(map_),'-DFENV_ROUND='+str(mode),carrier,obj,archive,'-o',exe]);base.executable_elf(exe,isa);child=self.command([*prefix,exe],timeout=30);self.assertEqual(len(child.stdout),20*8);self.assertEqual(len(child.stderr),20*80);values=list(struct.unpack('<20Q',child.stdout));raw=[list(struct.unpack_from('<10Q',child.stderr,i*80))for i in range(20)];self.assertEqual([x[0]for x in raw],list(range(20)));self.assertTrue(all(x[3]==mode and x[4:7]==x[7:10]for x in raw));self.assertTrue(all(x[1]==x[2]for x in raw[:12]));self.assertTrue(all(x[1]and x[2]==0 for x in raw[12:]));symbols=linked_symbols(exe);self.assertTrue(all(x[1]==symbols['l64a.s']['value']for x in raw[12:]));self.assertNotEqual(symbols['l64a.s']['value'],symbols['digits']['value']);self.assertEqual(symbols['strchrnul']['binding'],2);self.assertEqual(symbols['strchrnul']['value'],symbols['__strchrnul']['value']);pair.append(values);observations.append({'implementation':implementation,'mode':mode,'executable':base.identity(exe),'link_map':base.identity(map_),'values':values,'raw_records':raw,'runtime_symbol_bindings':{name:symbols[name]for name in ['digits','l64a.s','a64l','l64a','strchr','__strchrnul','strchrnul','strlen']}})
                self.assertEqual(pair[0],pair[1])
            self.assertEqual(base.identity(archive),archive_before)
            records.append({'isa':isa,'provider_group_refusal':base.identity(product/'provider-group.json'),'original_ir':base.identity(original),'owned':base.identity(owned),'reference':base.identity(reference),'external_original_libc_archive':base.identity(archive),'test_bootstrap':base.identity(carrier),'unresolved_original_unit_provider':'strchr','observations':observations,'predeclared_nondeterministic_raw_return_indices':list(range(12,20)),'original_unit_complete':True,'lowered_provider_or_runtime_closure_complete':False})
        (self.directory/'original-component-execution.json').write_text(json.dumps(records,indent=2)+'\n')

    def test_complete_original_a64l_string_group_readmission_and_owned_dependency_execution(self):
        records=[]
        for isa in base.UNITS:
            case=self.directory/isa;case.mkdir();rust=Path.home()/'.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin'
            def pin(path):return{'path':str(Path(path).resolve()),'sha256':base.identity(path)['sha256']}
            tools={'python':pin(Path(sys.executable).resolve()),'llvm_library':pin(self.library),**{key:pin(self.sdk/name)for key,name in [('cc','clang'),('cxx','clang++'),('llvm_nm','llvm-nm'),('llvm_dis','llvm-dis')]},'rustc':pin(rust/'rustc'),'cargo':pin(rust/'cargo'),'compiler_sha256':base.identity(self.compiler)['sha256']}
            recipe=base.ROOT/'tools/ocore-runtime/constant-ptrtoint'/(isa+'.a64l-group.recipe.json');name=json.loads(recipe.read_text())['name'];musl=Path.home()/'.cache/okernel-u9fs-native-recipe/sources/musl';plan=case/'provider-plan.json'
            plan.write_text(json.dumps({'schema':'ocore-native-provider-plan-v1','root':name,'tools':tools,'components':[{'id':name,'recipe':pin(recipe),'source':str(musl),'dependencies':{}}]},indent=2)+'\n')
            def arguments(input_,output):return[self.olangc,input_,'--native-runtime','--native-runtime-provider-plan',plan,'--native-isa',isa+'-unknown-none','--native-runtime-output','obj','--llvm-library',self.library,'--llvm-sha256',base.LIB_SHA,'-o',output]
            product=case/'product';self.command([*arguments(recipe,product),'--native-runtime-source',musl,'--native-runtime-jobs','2'],timeout=300)
            provider=json.loads((product/'provider-group.json').read_text());self.assertTrue(provider['source_group_complete']);self.assertFalse(provider['runtime_complete'])
            packet_path=product/'source-group.native-ir.json';packet=json.loads(packet_path.read_text());self.assertEqual(len(packet['module_set']['modules']),4)
            modules=[json.loads(m['native_ir'])for m in packet['module_set']['modules']];self.assertEqual({f['name']for m in modules for f in m['functions']if f['entry']is not None},{'a64l','l64a','strchr','__strchrnul','strlen'})
            module=next(m for m in modules if any(f['name']=='a64l'and f['entry']is not None for f in m['functions']));self.assertEqual(len(module['functions']),3)
            reopened=case/'reopened';self.command(arguments(packet_path,reopened),timeout=300);self.assertTrue(json.loads((reopened/'source-readmission.json').read_text())['included_original_ir_body_consistency'])
            owned=sorted((reopened/'lowered').glob('unit-*/module.o'));self.assertEqual(len(owned),4);component=product/'component-000000';reference=[component/'build'/name for name in ['obj/src/misc/a64l.o','obj/src/string/strchr.o','obj/src/string/strchrnul.o','obj/src/string/strlen.o']];self.assertTrue(all(p.is_file()for p in reference));source_copies=[]
            for index,embedded in enumerate(packet['module_set']['modules']):
                original=case/('original-unit-'+str(index)+'.ll');original.write_bytes(bytes.fromhex(packet['components'][0]['units'][index]['original_ir_hex']));self.inventory.audit_native_module(original,json.loads(embedded['native_ir']),self.library,base.LIB_SHA);source_copies.append(base.identity(original))
            # Both sides use exactly the four declared unit objects. No
            # original libc archive or hidden reference helper is linked into
            # the owned execution. Source closure is still not full libc/CRT.
            carrier=case/'external-component-bootstrap.c';carrier.write_text(original_component_carrier());triple=module['target']['triple'];flags=['-march=rv64gc','-mabi=lp64d']if isa=='riscv64'else[];prefix=[]if isa==os.uname().machine else[Path.home()/'.local/share/ostadix/bm-dev/host/usr/bin'/('qemu-'+isa)];observations=[]
            for mode in range(5 if isa=='riscv64'else 4):
                pair=[]
                for implementation,obj in [('reference',reference),('owned',owned)]:
                    exe=case/(implementation+'-fenv-'+str(mode));map_=exe.with_suffix('.map');self.command([self.sdk/'clang','--target='+triple,*flags,'--ld-path='+str(self.sdk/'ld.lld'),'-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-vectorize','-fno-slp-vectorize','-fno-pic','-fno-pie','-nostdlib','-static','-Wl,--no-relax','-Wl,-e,_start','-Wl,-Map='+str(map_),'-DFENV_ROUND='+str(mode),carrier,*obj,'-o',exe]);base.executable_elf(exe,isa);child=self.command([*prefix,exe],timeout=30);self.assertEqual(len(child.stdout),20*8);self.assertEqual(len(child.stderr),20*80);values=list(struct.unpack('<20Q',child.stdout));raw=[list(struct.unpack_from('<10Q',child.stderr,i*80))for i in range(20)];self.assertEqual([x[0]for x in raw],list(range(20)));self.assertTrue(all(x[3]==mode and x[4:7]==x[7:10]for x in raw));self.assertTrue(all(x[1]==x[2]for x in raw[:12]));self.assertTrue(all(x[1]and x[2]==0 for x in raw[12:]));symbols=linked_symbols(exe);self.assertTrue(all(x[1]==symbols['l64a.s']['value']for x in raw[12:]));self.assertNotEqual(symbols['l64a.s']['value'],symbols['digits']['value']);self.assertEqual(symbols['strchrnul']['binding'],2);self.assertEqual(symbols['strchrnul']['value'],symbols['__strchrnul']['value']);pair.append(values);observations.append({'implementation':implementation,'mode':mode,'executable':base.identity(exe),'link_map':base.identity(map_),'values':values,'raw_records':raw,'runtime_symbol_bindings':{name:symbols[name]for name in ['digits','l64a.s','a64l','l64a','strchr','__strchrnul','strchrnul','strlen']}})
                self.assertEqual(pair[0],pair[1])
            records.append({'isa':isa,'packet':base.identity(packet_path),'readmission':base.identity(reopened/'source-readmission.json'),'original_inputs':source_copies,'owned_objects':[base.identity(p)for p in owned],'reference_objects':[base.identity(p)for p in reference],'test_bootstrap':base.identity(carrier),'observations':observations,'predeclared_nondeterministic_raw_return_indices':list(range(12,20)),'original_selected_component_source_symbol_closure_complete':True,'external_reference_runtime_linked_into_owned':False,'full_libc_crt_platform_runtime_closure_complete':False})
        (self.directory/'original-component-execution.json').write_text(json.dumps(records,indent=2)+'\n')

    def test_closed_authored_source_group_fresh_readmission_and_coherent_forgers(self):
        import hashlib
        records=[]
        for isa in base.UNITS:
            case=self.directory/isa;case.mkdir();source=case/'source';source.mkdir()
            (source/'fixture.c').write_text('unsigned long data=72991;\nunsigned long pointer_word(void){return (unsigned long)&data;}\nlong body_probe(long x){return x+17;}\n')
            flags=['--target='+isa+'-unknown-linux-musl','-O2','-ffreestanding','-fno-builtin','-frounding-math']+(['-march=rv64gc','-mabi=lp64d']if isa=='riscv64'else[])
            (source/'build.py').write_text("import json,os,pathlib,subprocess,sys\nsource=pathlib.Path(sys.argv[1]);flags=json.loads(sys.argv[2]);subprocess.run([os.environ['CC'],*flags,'-c',str(source/'fixture.c'),'-o','fixture.o'],check=True);pathlib.Path('unit-inventory.json').write_text(json.dumps({'schema':'ocore-runtime-unit-inventory-v1','complete':True,'units':[{'id':'complete-fixture','kind':'clang','source':'fixture.c','role':'runtime','build_step':'original-authored-build'}]}))\n")
            for argv in [['git','init','-q'],['git','add','.'],['git','-c','user.name=Pointer Constant Test','-c','user.email=test@example.invalid','commit','-qm','complete authored source fixture']]:self.command(argv,cwd=source)
            revision=self.command(['git','rev-parse','HEAD'],cwd=source).stdout.decode().strip()
            recipe=case/'recipe.json';recipe.write_text(json.dumps({'schema':'ocore-runtime-recipe-v1','name':'authored-pointer-constant-'+isa,'source':{'url':'local-pinned-authored-pointer-constant-fixture','revision':revision},'toolchain':{'llvm_version':'22.1.6'},'dependencies':[],'commands':[{'name':'original-authored-build','argv':[sys.executable,'{source}/build.py','{source}',json.dumps(flags)]}],'coverage':{'required_units':[{'id':'complete-fixture','kind':'clang','source':'fixture.c','role':'runtime','build_step':'original-authored-build'}],'required_outputs':['fixture.o'],'require_full_unit_inventory':True}}))
            rust=Path.home()/'.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin'
            def pin(path):return{'path':str(Path(path).resolve()),'sha256':base.identity(path)['sha256']}
            tools={'python':pin(Path(sys.executable).resolve()),'llvm_library':pin(self.library),**{key:pin(self.sdk/name)for key,name in [('cc','clang'),('cxx','clang++'),('llvm_nm','llvm-nm'),('llvm_dis','llvm-dis')]},'rustc':pin(rust/'rustc'),'cargo':pin(rust/'cargo'),'compiler_sha256':base.identity(self.compiler)['sha256']}
            name=json.loads(recipe.read_text())['name'];plan=case/'provider-plan.json';plan.write_text(json.dumps({'schema':'ocore-native-provider-plan-v1','root':name,'tools':tools,'components':[{'id':name,'recipe':pin(recipe),'source':str(source),'dependencies':{}}]},indent=2)+'\n')
            def arguments(input_,output):return[self.olangc,input_,'--native-runtime','--native-runtime-provider-plan',plan,'--native-isa',isa+'-unknown-none','--native-runtime-output','obj','--llvm-library',self.library,'--llvm-sha256',base.LIB_SHA,'-o',output]
            product=case/'product';self.command([*arguments(recipe,product),'--native-runtime-source',source,'--native-runtime-jobs','2'],timeout=300)
            packet_path=product/'source-group.native-ir.json';packet=json.loads(packet_path.read_text());self.assertEqual(len(packet['module_set']['modules']),1);module=json.loads(packet['module_set']['modules'][0]['native_ir']);self.assertEqual(len(module['functions']),2);self.assertEqual({f['name']for f in module['functions']},{'pointer_word','body_probe'})
            reopened=case/'reopened';self.command(arguments(packet_path,reopened),timeout=300);self.assertTrue(json.loads((reopened/'source-readmission.json').read_text())['included_original_ir_body_consistency'])
            for kind in ['pointer-child','ordinary-body']:
                forged=copy.deepcopy(packet);changed=json.loads(forged['module_set']['modules'][0]['native_ir']);function=next(f for f in changed['functions']if f['name']==('pointer_word'if kind=='pointer-child'else'body_probe'))
                if kind=='pointer-child':
                    value=function['blocks'][0]['terminator']['value'];self.assertEqual(value['kind'],'pointer_to_integer');child=value['pointer'];value['pointer']={'kind':'symbol_offset','ty':child['ty'],'name':child['name'],'addend':1}
                else:
                    function['blocks'][0]['terminator']['value']={'kind':'int','ty':function['signature']['result'],'bits':'7'}
                encoded=json.dumps(changed);candidate=case/(kind+'.native.json');candidate.write_text(encoded);self.command([self.compiler,candidate,'--input-kind','native-ir','--verify-native']);forged['module_set']['modules'][0]['native_ir']=encoded;forged['module_set']['modules'][0]['sha256']=hashlib.sha256(encoded.encode()).hexdigest();forger=case/(kind+'.source-group.json');forger.write_text(json.dumps(forged));rejected=case/('reject-'+kind);self.command(arguments(forger,rejected),success=False,timeout=300);failure=(rejected/'source-readmission.json').read_text();self.assertIn('independent source inventory failed'if kind=='pointer-child'else'fresh original LLVM import does not match embedded typed NativeModule',failure)
            records.append({'isa':isa,'authored_complete_source':True,'original_musl':False,'packet':base.identity(packet_path),'readmission':base.identity(reopened/'source-readmission.json'),'source':base.identity(source/'fixture.c'),'build':base.identity(source/'build.py'),'reference_object':base.identity(product/'component-000000/build/fixture.o'),'runtime_or_provider_qualification':False})
        (self.directory/'closed-authored-readmission.json').write_text(json.dumps(records,indent=2)+'\n')

    def test_all_native_integer_widths_ll_bc_objects_reference_execution_and_fenv(self):
        records=[];self.__class__.width_products={}
        for isa in base.UNITS:
            case=self.directory/isa;case.mkdir();source=case/'all-widths.ll';source.write_text(width_module(isa,self.original(isa).read_text()))
            bc=case/'all-widths.bc';self.command([self.sdk/'llvm-as',source,'-o',bc])
            objects={}
            for form,input_ in [('ll',source),('bc',bc)]:
                native=case/(form+'.native.json');self.command([self.compiler,input_,'--input-kind','llvm-ir','--target',isa+'-unknown-none','--emit','mir','--llvm-library',self.library,'--llvm-sha256',base.LIB_SHA,'-o',native])
                module=json.loads(native.read_text());self.assertEqual(len(module['functions']),132);self.assertEqual(len(module['globals']),1)
                casts=[i['value'] for f in module['functions'] for b in f['blocks'] for i in [b['terminator']] if i['op']=='return'and i.get('value',{}).get('kind')=='pointer_to_integer']
                self.assertEqual(len(casts),65);self.assertEqual(sorted(module['types'][o['ty']]['bits']for o in casts),WIDTHS)
                proof=self.inventory.audit_native_module(input_,module,self.library,base.LIB_SHA);(case/(form+'.source-proof.json')).write_text(json.dumps(proof,indent=2)+'\n')
                self.command([self.compiler,native,'--input-kind','native-ir','--verify-native','--receipt',case/(form+'.verify.json')])
                obj=case/(form+'.own.o');self.command([self.compiler,native,'--input-kind','native-ir','--target',isa+'-unknown-none','-o',obj]);objects[form]=obj
            # Identical source LL/BC representations must yield identical owned
            # object bytes; no field/body exclusions are made to compare them.
            self.assertEqual(objects['ll'].read_bytes(),objects['bc'].read_bytes())
            triple=re.search(r'target triple = "([^"]+)"',source.read_text())[1];flags=['-march=rv64gc','-mabi=lp64d']if isa=='riscv64'else[]
            reference=case/'reference.o';self.command([self.sdk/'clang','--target='+triple,*flags,'-O0','-c',source,'-o',reference])
            self.command([self.compiler,case/'ll.native.json','--input-kind','native-ir','--target',isa+'-unknown-none','--emit','asm','-o',case/'owned.s'])
            carrier=case/'external-test-bootstrap.c';carrier.write_text(width_carrier());linker=case/'fixed-test-layout.ld';linker.write_text(LINK_SCRIPT)
            prefix=[]
            if isa!=os.uname().machine:
                runner=Path.home()/'.local/share/ostadix/bm-dev/host/usr/bin'/('qemu-'+isa);self.assertTrue(runner.is_file());prefix=[runner];self.command([runner,'--version'])
            observations=[]
            for mode in range(5 if isa=='riscv64'else 4):
                pair=[]
                for implementation,obj in [('reference',reference),('owned',objects['ll'])]:
                    exe=case/(implementation+'-mode-'+str(mode));self.command([self.sdk/'clang','--target='+triple,*flags,'--ld-path='+str(self.sdk/'ld.lld'),'-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-vectorize','-fno-slp-vectorize','-fno-pic','-fno-pie','-nostdlib','-static','-Wl,--no-relax','-Wl,-e,_start','-Wl,-T,'+str(linker),'-DFENV_ROUND='+str(mode),carrier,obj,'-o',exe]);base.executable_elf(exe,isa)
                    child=self.command([*prefix,exe],timeout=30);self.assertEqual(len(child.stdout),67*8);self.assertEqual(len(child.stderr),67*10*8)
                    values=list(struct.unpack('<67Q',child.stdout));raw=[list(struct.unpack_from('<10Q',child.stderr,i*80))for i in range(67)];self.assertEqual([x[0]for x in raw],list(range(67)));self.assertEqual([x[1]for x in raw],values);self.assertTrue(all(x[1]==x[2]and x[3]==mode and x[4:7]==x[7:10]for x in raw));self.assertEqual(values[64]>>63,1);self.assertEqual(values[65],0);self.assertEqual(values[66],1)
                    pair.append((values,raw));observations.append({'implementation':implementation,'mode':mode,'executable':base.identity(exe),'values':values,'immediate_records':raw})
                    if implementation=='reference'and mode==0:
                        bad=case/'corrupt-oracle';argv=[self.sdk/'clang','--target='+triple,*flags,'--ld-path='+str(self.sdk/'ld.lld'),'-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-vectorize','-fno-slp-vectorize','-fno-pic','-fno-pie','-nostdlib','-static','-Wl,--no-relax','-Wl,-e,_start','-Wl,-T,'+str(linker),'-DCORRUPT_ORACLE','-DFENV_ROUND=0',carrier,obj,'-o',bad];self.command(argv);q=self.command([*prefix,bad],success=False,timeout=30);self.assertEqual(q.returncode,31);self.assertEqual(q.stdout,b'');self.assertEqual(len(q.stderr),80);first=struct.unpack('<10Q',q.stderr);self.assertEqual(first[0],0);self.assertEqual(first[1]^first[2],1)
                self.assertEqual(pair[0],pair[1],'fixed object layout admits exact raw result/FENV equality, not address normalization')
            self.__class__.width_products[isa]=case
            records.append({'isa':isa,'source':base.identity(source),'bitcode':base.identity(bc),'owned':base.identity(objects['ll']),'reference':base.identity(reference),'linker_profile':base.identity(linker),'observations':observations,'integer_widths':WIDTHS,'external_test_environment':['Clang static test bootstrap','actual Linux provider',*map(str,prefix)],'runtime_complete':False})
        (self.directory/'execution.json').write_text(json.dumps({'scope':'authored scalar pointer-constant all-width transport/emission/FENV conformance; no original runtime/provider/OS qualification','records':records},indent=2)+'\n')


    def test_narrow_and_wide_emission_corruption_are_causal_on_each_isa(self):
        if not getattr(self.__class__,'width_products',None):
            self.test_all_native_integer_widths_ll_bc_objects_reference_execution_and_fenv()
        controls=[]
        patterns={
            'x86_64':{'narrow':('cmp3','  and rax, 7\n',''), 'wide':('p128','  mov rax, 0\n','  mov rax, 1\n')},
            'aarch64':{'narrow':('cmp3','  ubfx x9, x9, #0, #3\n',''), 'wide':('p128','  movz x9, #0\n','  movz x9, #1\n')},
            'riscv64':{'narrow':('cmp3','  slli t0, t0, 61\n  srli t0, t0, 61\n',''), 'wide':('p128','  li t0, 0\n','  li t0, 1\n')},
        }
        for isa,case in self.__class__.width_products.items():
            output=self.directory/isa;output.mkdir(exist_ok=True);original=case/'owned.s';source=case/'all-widths.ll';triple=re.search(r'target triple = "([^"]+)"',source.read_text())[1];flags=['-march=rv64gc','-mabi=lp64d']if isa=='riscv64'else[];prefix=[]if isa==os.uname().machine else[Path.home()/'.local/share/ostadix/bm-dev/host/usr/bin'/('qemu-'+isa)]
            text=original.read_text()
            for kind,(function,needle,replacement)in patterns[isa].items():
                start=text.index(function+':\n');end=text.index('.size '+function,start);body=text[start:end];self.assertEqual(body.count(needle),1,'control must mutate exactly one intended emitted operation')
                altered=text[:start]+body.replace(needle,replacement)+text[end:];asm=output/(kind+'.s');asm.write_text(altered);obj=output/(kind+'.o');self.command([self.sdk/'clang','--target='+triple,*flags,'-c',asm,'-o',obj]);exe=output/(kind+'-run')
                self.command([self.sdk/'clang','--target='+triple,*flags,'--ld-path='+str(self.sdk/'ld.lld'),'-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-vectorize','-fno-slp-vectorize','-fno-pic','-fno-pie','-nostdlib','-static','-Wl,--no-relax','-Wl,-e,_start','-Wl,-T,'+str(case/'fixed-test-layout.ld'),'-DFENV_ROUND=0',case/'external-test-bootstrap.c',obj,'-o',exe]);base.executable_elf(exe,isa)
                child=self.command([*prefix,exe],success=False,timeout=30);self.assertEqual(child.returncode,31);self.assertEqual(child.stdout,b'');index=66 if kind=='narrow'else 65;self.assertEqual(len(child.stderr),(index+1)*80);last=struct.unpack_from('<10Q',child.stderr,index*80);self.assertEqual(last[0],index);self.assertNotEqual(last[1],last[2]);self.assertEqual(last[4:7],last[7:10]);self.assertEqual((last[1],last[2]),(0,1)if kind=='narrow'else(1,0))
                controls.append({'isa':isa,'kind':kind,'source_assembly':base.identity(original),'mutated_assembly':base.identity(asm),'exact_removed':needle,'exact_inserted':replacement,'function':function,'matches':1,'object':base.identity(obj),'executable':base.identity(exe),'actual_exit':child.returncode,'last_raw_record':list(last),'scope':'test artifact mutation only; product/source/IR unchanged'})
        (self.directory/'emission-controls.json').write_text(json.dumps(controls,indent=2)+'\n')


    def test_symbol_gep_alias_aggregate_phi_call_weak_and_block_identity_three_isas(self):
        summaries=[]
        for isa in base.UNITS:
            case=self.directory/isa;case.mkdir();source=case/'rich.ll';source.write_text(rich_module(isa,self.original(isa).read_text()));native=case/'rich.native.json'
            self.command([self.compiler,source,'--input-kind','llvm-ir','--target',isa+'-unknown-none','--emit','mir','--llvm-library',self.library,'--llvm-sha256',base.LIB_SHA,'-o',native]);module=json.loads(native.read_text());self.inventory.audit_native_module(source,module,self.library,base.LIB_SHA);self.command([self.compiler,native,'--input-kind','native-ir','--verify-native','--receipt',case/'verified.json'])
            triple=module['target']['triple'];flags=['-march=rv64gc','-mabi=lp64d']if isa=='riscv64'else[];owned=case/'owned.o';reference=case/'reference.o';self.command([self.compiler,native,'--input-kind','native-ir','--target',isa+'-unknown-none','-o',owned]);self.command([self.sdk/'clang','--target='+triple,*flags,'-O0','-c',source,'-o',reference]);self.command([self.compiler,native,'--input-kind','native-ir','--target',isa+'-unknown-none','--emit','asm','-o',case/'owned.s'])
            carrier=case/'external-rich-bootstrap.c';carrier.write_text(rich_carrier());linker=case/'fixed-rich-layout.ld';linker.write_text(RICH_LINK_SCRIPT);mandatory=case/'mandatory.c';mandatory.write_text('unsigned long must __attribute__((section(".provider_data")))=0x731;\n');weak=case/'weak-provider.c';weak.write_text('unsigned long optional __attribute__((weak,section(".provider_data")))=0x111;\n__attribute__((weak,section(".provider_code"))) unsigned long optional_fn(unsigned long x){return x^0x111;}\n');strong=case/'strong-provider.c';strong.write_text('unsigned long optional __attribute__((section(".provider_data")))=0x222;\n__attribute__((section(".provider_code"))) unsigned long optional_fn(unsigned long x){return x^0x222;}\n');provider_objects=[]
            for src in [mandatory,weak,strong]:
                obj=src.with_suffix('.o');self.command([self.sdk/'clang','--target='+triple,*flags,'-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-fno-pie','-c',src,'-o',obj]);provider_objects.append(obj)
            prefix=[]if isa==os.uname().machine else[Path.home()/'.local/share/ostadix/bm-dev/host/usr/bin'/('qemu-'+isa)];observations=[]
            for provider_mode in range(3):
                providers=provider_objects[:1]if provider_mode==0 else provider_objects[:2]if provider_mode==1 else provider_objects
                for mode in range(5 if isa=='riscv64'else 4):
                    pair=[]
                    for implementation,obj in [('reference',reference),('owned',owned)]:
                        exe=case/(implementation+'-providers-'+str(provider_mode)+'-fenv-'+str(mode));self.command([self.sdk/'clang','--target='+triple,*flags,'--ld-path='+str(self.sdk/'ld.lld'),'-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-vectorize','-fno-slp-vectorize','-fno-pic','-fno-pie','-nostdlib','-static','-Wl,--no-relax','-Wl,-e,_start','-Wl,-T,'+str(linker),'-DFENV_ROUND='+str(mode),'-DPROVIDER_MODE='+str(provider_mode),carrier,obj,*providers,'-o',exe]);base.executable_elf(exe,isa);symbols=linked_symbols(exe);self.assertEqual(symbols['alias_data']['value'],symbols['data']['value']);self.assertEqual(symbols['data']['value'],0x600000)
                        if provider_mode==0:self.assertEqual(symbols['optional']['section'],0);self.assertEqual(symbols['optional_fn']['section'],0)
                        else:self.assertEqual(symbols['optional']['binding'],2 if provider_mode==1 else 1);self.assertEqual(symbols['optional_fn']['binding'],2 if provider_mode==1 else 1)
                        child=self.command([*prefix,exe],timeout=30);self.assertEqual(len(child.stdout),14*8);self.assertEqual(len(child.stderr),14*80);values=list(struct.unpack('<14Q',child.stdout));raw=[list(struct.unpack_from('<10Q',child.stderr,i*80))for i in range(14)];self.assertEqual([x[0]for x in raw],list(range(14)));self.assertTrue(all(x[1]==x[2]and x[3]==mode and x[4:7]==x[7:10]for x in raw));self.assertEqual([x[1]for x in raw],values);self.assertTrue(values[12]);self.assertEqual(values[13],values[12]&0xffffffff);self.assertEqual(values[6],0);self.assertEqual(values[5]>>63,1)
                        if provider_mode==0:self.assertEqual(values[2:4],[0,0])
                        else:self.assertTrue(all(values[2:4]))
                        pair.append((values,raw));observations.append({'implementation':implementation,'provider_mode':provider_mode,'fenv_mode':mode,'executable':base.identity(exe),'values':values,'immediate_records':raw,'block_address_relation':'actual returned block pointer equals own linked anchor contents; code-label numeric addresses are implementation-layout values'})
                    # Global/function provider addresses are fixed and compare
                    # exactly. Code-block addresses are retained raw and checked
                    # against each independently linked anchor, never normalized
                    # after a failure or treated as ordinary function pointers.
                    self.assertEqual(pair[0][0][:12],pair[1][0][:12]);self.assertEqual([x[:1]+x[3:]for x in pair[0][1]],[x[:1]+x[3:]for x in pair[1][1]])
            summaries.append({'isa':isa,'source':base.identity(source),'native':base.identity(native),'owned_object':base.identity(owned),'reference_object':base.identity(reference),'external_test_providers':[base.identity(p)for p in [mandatory,weak,strong,*provider_objects]],'linker_profile':base.identity(linker),'observations':observations,'predeclared_nondeterministic_value_indices':[12,13],'source_body_or_provider_closure_qualified':False})
        (self.directory/'rich-execution.json').write_text(json.dumps({'scope':'authored symbolic/aggregate/block/weak pointer primitive conformance, external test data/providers/bootstrap/Linux; not original runtime closure','summaries':summaries},indent=2)+'\n')


    def test_source_sites_structural_neighbors_and_coherent_forgeries_fail_closed(self):
        records=[]
        for isa in base.UNITS:
            case=self.directory/isa;case.mkdir()
            original=self.original(isa).read_text()
            source=case/'positions.ll'
            source.write_text(rich_module(isa,original)+'''\ndefine i64 @branch_source() strictfp {
 br i1 ptrtoint (ptr @data to i1), label %yes, label %no
yes:
 ret i64 1
no:
 ret i64 0
}
''')
            path=case/'valid.native.json'
            self.command([self.compiler,source,'--input-kind','llvm-ir','--target',isa+'-unknown-none','--emit','mir','--llvm-library',self.library,'--llvm-sha256',base.LIB_SHA,'-o',path])
            valid=json.loads(path.read_text())
            proof=self.inventory.audit_native_module(source,valid,self.library,base.LIB_SHA)
            (case/'source-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
            self.command([self.compiler,path,'--input-kind','native-ir','--verify-native'])
            def function(module,name):return next(f for f in module['functions']if f['name']==name)
            def returned(module,name):return function(module,name)['blocks'][-1]['terminator']['value']
            def operation(module,name,op):return next(i['operation']for b in function(module,name)['blocks']for i in b['instructions']if i['operation']['op']==op)
            def aggregate_cast(module):return operation(module,'aggregate_lo','extract_value')['aggregate']['elements'][1]
            def swap_select(module):
                op=operation(module,'select_source','select');op['on_true'],op['on_false']=op['on_false'],op['on_true']
            def swap_phi(module):
                op=operation(module,'phi_source','phi');op['incoming'][0]['value'],op['incoming'][1]['value']=op['incoming'][1]['value'],op['incoming'][0]['value']
            forgers={
                'same-valued-alias-child':lambda m:returned(m,'alias_addr')['pointer'].__setitem__('name','data'),
                'negative-gep-addend':lambda m:returned(m,'negative_gep')['pointer'].__setitem__('addend',-36),
                'aggregate-nested-addend':lambda m:aggregate_cast(m)['pointer'].__setitem__('addend',HIGH_ADDEND+1),
                'same-symbol-set-select-position':swap_select,
                'same-symbol-set-phi-edge':swap_phi,
                'conditional-branch-child':lambda m:function(m,'branch_source')['blocks'][0]['terminator']['condition']['pointer'].__setitem__('name','alias_data'),
            }
            for name,mutate in forgers.items():
                changed=copy.deepcopy(valid);mutate(changed);candidate=case/(name+'.json');candidate.write_text(json.dumps(changed))
                self.command([self.compiler,candidate,'--input-kind','native-ir','--verify-native'])
                with self.assertRaisesRegex(self.inventory.InventoryMismatch,'constant ptrtoint.*changed'):
                    self.inventory.audit_native_module(source,changed,self.library,base.LIB_SHA)
                records.append({'isa':isa,'case':name,'structurally_valid':True,'source_rejected':True,'candidate':base.identity(candidate)})
            pointer_ty=returned(valid,'alias_addr')['pointer']['ty']
            integer_ty=returned(valid,'alias_addr')['ty']
            # Every malformed native child is checked independently, before
            # an emitter/interpreter can turn it into a host address.
            negatives={
                'integer-child':lambda m:returned(m,'alias_addr').__setitem__('pointer',{'kind':'int','ty':integer_ty,'bits':'7'}),
                'ssa-child':lambda m:returned(m,'select_source').__setitem__('pointer',{'kind':'value','id':function(m,'select_source')['params'][0]['id']}),
                'undef-child':lambda m:returned(m,'alias_addr').__setitem__('pointer',{'kind':'undef','ty':pointer_ty}),
                'poison-child':lambda m:returned(m,'alias_addr').__setitem__('pointer',{'kind':'poison','ty':pointer_ty}),
                'undeclared-symbol':lambda m:returned(m,'alias_addr')['pointer'].__setitem__('name','not_declared'),
                'non-pointer-child-type':lambda m:returned(m,'alias_addr')['pointer'].__setitem__('ty',integer_ty),
                'non-scalar-result':lambda m:returned(m,'alias_addr').__setitem__('ty',pointer_ty),
                'non-integral-as0':lambda m:m['target'].__setitem__('data_layout',m['target']['data_layout']+'-ni:0'),
                'nondefault-address-space':lambda m:m['target'].__setitem__('data_layout',m['target']['data_layout']+'-G1'),
                'pointer-index-width':lambda m:m['target'].__setitem__('data_layout',m['target']['data_layout']+'-p:64:64:64:32'),
            }
            for name,mutate in negatives.items():
                changed=copy.deepcopy(valid)
                if name=='ssa-child':
                    # The return itself is normally SSA. Put a bad constant
                    # child in a genuine select arm with an in-scope SSA id.
                    op=operation(changed,'select_source','select')
                    op['on_true']['pointer']={'kind':'value','id':function(changed,'select_source')['params'][0]['id']}
                else:mutate(changed)
                candidate=case/(name+'.json');candidate.write_text(json.dumps(changed))
                self.command([self.compiler,candidate,'--input-kind','native-ir','--verify-native'],success=False)
                records.append({'isa':isa,'case':name,'structurally_rejected':True,'candidate':base.identity(candidate)})
            # Absolute integer object initialization is not inferred from a
            # nested ptrtoint leaf in the already-supported relative32 lane.
            unsupported={
                'i65-result':source_header(original)+'\n@data=global i64 0,align 8\ndefine i65 @f(){ret i65 ptrtoint(ptr @data to i65)}\n',
                'absolute-i64-initializer':source_header(original)+'\n@data=global i64 0,align 8\n@absolute=global i64 ptrtoint(ptr @data to i64),align 8\n',
                'packed-vector-lanes':source_header(original)+'\n@data=global i64 0,align 8\ndefine <2 x i64> @f(){ret <2 x i64> <i64 ptrtoint(ptr @data to i64),i64 0>}\n',
                'tls-symbol':source_header(original)+'\n@data=thread_local global i64 0,align 8\ndefine i64 @f(){ret i64 ptrtoint(ptr @data to i64)}\n',
            }
            for name,text in unsupported.items():
                input_=case/(name+'.ll');input_.write_text(text);output=case/(name+'.native.json')
                self.command([self.compiler,input_,'--input-kind','llvm-ir','--target',isa+'-unknown-none','--emit','mir','--llvm-library',self.library,'--llvm-sha256',base.LIB_SHA,'-o',output],success=False)
                self.assertFalse(output.exists(),'a rejected complete source unit cannot publish partial IR')
                records.append({'isa':isa,'case':name,'source_rejected':True,'input':base.identity(input_)})
        (self.directory/'negative-controls.json').write_text(json.dumps(records,indent=2)+'\n')


if __name__=='__main__':unittest.main()
