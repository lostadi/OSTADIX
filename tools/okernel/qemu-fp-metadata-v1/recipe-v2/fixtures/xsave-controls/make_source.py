from pathlib import Path
import json
B=Path(__file__).resolve().parent;P=B.parent/'system-controls/controls.S';s=P.read_text();s=s[:s.index('tests:\n')]+s[s.index('common_isr:'):];a=s.index('\nreports:\n');b=s.index('\ncpuid_store:',a);s=s[:a]+s[b:];s=s.replace(' call tests\n',' call xsave_tests\n');s=s.replace(' mov [rip+meta+60],edx',' mov [rip+meta+60],edx\n mov [rip+meta+96],ecx\n test ecx,1<<26\n jz unsupported');s=s.replace(' or rax,0x600\n and rax,-262145\n mov cr4,rax',' or rax,0x40600\n mov cr4,rax\n mov [rip+meta+104],rax\n xor ecx,ecx\n mov eax,3\n xor edx,edx\n xsetbv\n xgetbv\n mov [rip+meta+112],rax');s=s.replace(' call reports\n',' call xreports\n')
# Old case/export directives are harmless same-source declarations but remove
# all undefined export directives and irrelevant data-name declarations.
s='\n'.join(line for line in s.splitlines()if not line.startswith('.globl op_')and not line.startswith('.globl resume_'))+'\n'
body=r'''
xsave_tests:
 call install_b
 fxsave64 [rip+valid_image]
 mov word ptr [rip+valid_image+6],0x435
 movabs rax,0x112345678
 mov [rip+valid_image+8],rax
 movabs rax,0x223456780
 mov [rip+valid_image+16],rax
 fxrstor64 [rip+valid_image]
 mov eax,3
 xor edx,edx
.globl op_xsavew
op_xsavew:
 xsave64 [rip+xwide]
 mov dword ptr [rip+valid_image+8],0x12345678
 mov word ptr [rip+valid_image+12],0x1234
 mov word ptr [rip+valid_image+14],0
 mov dword ptr [rip+valid_image+16],0x23456780
 mov word ptr [rip+valid_image+20],0x5678
 mov word ptr [rip+valid_image+22],0
 fxrstor [rip+valid_image]
 mov eax,3
 xor edx,edx
.globl op_xsavel
op_xsavel:
 xsave [rip+xlegacy]
 # Independently initialized standard headers and contrasting invalid bits.
 lea rsi,[rip+xwide]
 lea rdi,[rip+xinitfp]
 mov ecx,128
 rep movsq
 mov qword ptr [rip+xinitfp+512],2
 lea rsi,[rip+xwide]
 lea rdi,[rip+xinitall]
 mov ecx,128
 rep movsq
 mov qword ptr [rip+xinitall+512],0
 lea rsi,[rip+xwide]
 lea rdi,[rip+xbad]
 mov ecx,128
 rep movsq
 mov dword ptr [rip+xbad+24],0x10000
 lea rsi,[rip+xwide]
 lea rdi,[rip+xbadhdr]
 mov ecx,128
 rep movsq
 movabs rax,0x8000000000000000
 mov [rip+xbadhdr+520],rax
 lea rsi,[rip+xwide]
 lea rdi,[rip+xbadbit]
 mov ecx,128
 rep movsq
 mov qword ptr [rip+xbadbit+512],7
 START xrstorw
 mov eax,3
 xor edx,edx
.globl op_xrstorw
op_xrstorw:
 xrstor64 [rip+xwide]
 END xrstorw
 START xrstorl
 mov eax,3
 xor edx,edx
.globl op_xrstorl
op_xrstorl:
 xrstor [rip+xlegacy]
 fxsave [rip+after_legacy]
 fnstenv [rip+after_legacy_env]
 END xrstorl
 START initfp
 fxrstor64 [rip+xwide]
 fxsave64 [r15+64]
 mov eax,3
 xor edx,edx
.globl op_initfp
op_initfp:
 xrstor64 [rip+xinitfp]
 END initfp
 START initall
 fxrstor64 [rip+xwide]
 fxsave64 [r15+64]
 mov eax,3
 xor edx,edx
.globl op_initall
op_initall:
 xrstor64 [rip+xinitall]
 END initall
 START badmxcsr
 mov eax,3
 xor edx,edx
.globl op_badmxcsr
op_badmxcsr:
 xrstor64 [rip+xbad]
 END badmxcsr
 START badheader
 mov eax,3
 xor edx,edx
.globl op_badheader
op_badheader:
 xrstor64 [rip+xbadhdr]
 END badheader
 START badstatebit
 mov eax,3
 xor edx,edx
.globl op_badstatebit
op_badstatebit:
 xrstor64 [rip+xbadbit]
 END badstatebit
 ret
'''
s=s.replace('\ncommon_isr:',body+'\ncommon_isr:')
cases=['xrstorw','xrstorl','initfp','initall','badmxcsr','badheader','badstatebit'];buffers=['xwide','xlegacy','xinitfp','xinitall','xbad','xbadhdr','xbadbit'];records={'meta':128,'after_legacy':512,'after_legacy_env':28};records.update({n:1024 for n in buffers});records.update({'case_'+n:1088 for n in cases});s+='\n.text\nxreports:\n'
for n,l in records.items():s+=f' lea rdi,[rip+xname_{n}]\n lea rsi,[rip+{n}]\n mov edx,{l}\n call record\n'
s+=' ret\n.section .rdata,"dr"\n'
for n in records:s+=f'xname_{n}: .asciz "{n}"\n'
s+='\n.bss\n'
for n in buffers:s+=f'.p2align 6\n{n}: .zero 1024\n'
s+='after_legacy: .zero 512\nafter_legacy_env: .zero 32\n'
for n in cases:s+=f'.p2align 6\ncase_{n}: .zero 1088\n'
# bss_end is a guard and must include the appended test-only state.
s=s.replace('\nbss_end:\n','\nold_bss_end:\n');s+='\nbss_end:\n'
exports=['efi_main','bss_end','ro_env','pml4','op_xsavew','op_xsavel','after_legacy']+['op_'+n for n in cases]+['resume_'+n for n in cases]+buffers
s+=''.join('.globl '+n+'\n'for n in exports);(B/'xsave.S').write_text(s);(B/'description.json').write_text(json.dumps({'exports':exports,'cases':cases,'records':records,'scope':'Actual namedSandyBridgev1,XCR0=3,standardFP+SSE format/init/error subset; AVX/XSAVEOPT optimization/othercomponents/fullXSAVE/nativeFPunqualified'},indent=2)+'\n')
