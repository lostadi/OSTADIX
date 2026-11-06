from pathlib import Path
import json
B=Path(__file__).resolve().parent;P=(Path(__file__).resolve().parents[1]/'pointer/probe.S').read_text();utils=P[P.index('cpuid_store:'):P.index('\n.section .rdata')]
s=r'''.intel_syntax noprefix
.text
.globl efi_main
efi_main:
 cli
 lea rsp,[rip+stack_top]
 and rsp,-16
 lea rdi,[rip+bss_begin]
 xor eax,eax
 lea rcx,[rip+bss_end]
 sub rcx,rdi
 shr rcx,3
 rep stosq
 call serial_init
 mov rax,cr0
 or rax,0x22
 and rax,-13
 mov cr0,rax
 mov [rip+metadata+16],rax
 mov rax,cr4
 or rax,0x600
 and rax,-262145
 mov cr4,rax
 mov [rip+metadata+24],rax
 movabs rax,0x46504d4947523031
 mov [rip+metadata],rax
 lea rax,[rip+efi_main]
 mov [rip+metadata+8],rax
 mov eax,1
 cpuid
 mov [rip+metadata+32],eax
 mov [rip+metadata+36],edx
 mov eax,7
 xor ecx,ecx
 cpuid
 mov [rip+metadata+40],ebx
 lea rsi,[rip+command_text]
 call print_str
command_loop:
 mov dx,0x3fd
 in al,dx
 test al,1
 jz command_loop
 mov dx,0x3f8
 in al,dx
 cmp al,0x51
 je done
 cmp al,0x52
 je report
 cmp al,0x53
 je seed_selectors
 cmp al,0x48
 je seed_high
 cmp al,0x5a
 je seed_zero
 jmp command_loop
seed_high:
 call seed_common
 mov byte ptr [rip+state],0x48
 movabs rax,0x112345678
 mov [rip+image+8],rax
 movabs rax,0x223456780
 mov [rip+image+16],rax
 fxrstor64 [rip+image]
 jmp report
seed_selectors:
 call seed_common
 mov byte ptr [rip+state],0x53
 mov dword ptr [rip+image+8],0x12345678
 mov word ptr [rip+image+12],0x1234
 mov dword ptr [rip+image+16],0x23456780
 mov word ptr [rip+image+20],0x5678
 fxrstor [rip+image]
 jmp report
seed_zero:
 call seed_common
 mov byte ptr [rip+state],0x5a
 fninit
 jmp report
seed_common:
 fninit
 ldmxcsr [rip+mxcsr_value]
 movdqu xmm0,[rip+xmm0_value]
 movdqu xmm15,[rip+xmm15_value]
 fld qword ptr [rip+operand]
 fxsave64 [rip+image]
 mov word ptr [rip+image],0x0b7f
 mov word ptr [rip+image+6],0x435
 ret
report:
 fxsave64 [rip+actual_w]
 fxsave [rip+actual_l]
 fnstenv [rip+actual_env]
 movzx eax,byte ptr [rip+state]
 mov [rip+metadata+48],rax
 lea rdi,[rip+name_metadata]
 lea rsi,[rip+metadata]
 mov edx,64
 call record
 lea rdi,[rip+name_w]
 lea rsi,[rip+actual_w]
 mov edx,512
 call record
 lea rdi,[rip+name_l]
 lea rsi,[rip+actual_l]
 mov edx,512
 call record
 lea rdi,[rip+name_env]
 lea rsi,[rip+actual_env]
 mov edx,28
 call record
 lea rsi,[rip+ready_text]
 call print_str
 mov al,[rip+state]
 call putc
 mov al,10
 call putc
 jmp command_loop
done:
 mov dx,0xf4
 mov eax,0x10
 out dx,eax
 cli
 hlt
 jmp done
'''+utils+r'''
.section .rdata,"dr"
.p2align 3
operand: .quad 0x3ff8000000000000
.p2align 2
mxcsr_value: .long 0x5f80
.p2align 4
xmm0_value: .quad 0x123456789abcdef,0xfedcba9876543210
xmm15_value: .quad 0xdeadbeefcafebabe,0x0123012301230123
relocation_anchor: .quad efi_main
command_text: .asciz "\nMIGCOMMAND\n"
ready_text: .asciz "\nMIGREADY "
record_text: .asciz "\nFPREC "
name_metadata: .asciz "metadata"
name_w: .asciz "wide"
name_l: .asciz "legacy"
name_env: .asciz "env"
.bss
.p2align 6
bss_begin:
metadata: .zero 64
state: .zero 8
.p2align 6
image: .zero 512
actual_w: .zero 512
actual_l: .zero 512
actual_env: .zero 32
.p2align 4
stack_bottom: .zero 16384
stack_top:
bss_end:
'''
(B/'migration.S').write_text(s);(B/'description.json').write_text(json.dumps({'exports':['efi_main','image','command_loop','actual_w','actual_l','actual_env','state'],'state_seeds':{'H':{'fop':0x435,'fip':0x112345678,'fdp':0x223456780,'fcs':0,'fds':0},'S':{'fop':0x435,'fip':0x12345678,'fdp':0x23456780,'fcs':0x1234,'fds':0x5678},'Z':{'fop':0,'fip':0,'fdp':0,'fcs':0,'fds':0}},'scope':'Authored soleCPU emulator metadata snapshot fixture; no nativekernel orfullFPU qualification'},indent=2)+'\n')
with(B/'migration.S').open('a')as f:f.write('\n'+''.join('.globl '+n+'\n'for n in json.loads((B/'description.json').read_text())['exports']))
