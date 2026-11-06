from pathlib import Path
B=Path(__file__).resolve().parent
P=(Path(__file__).resolve().parents[1]/'pointer/probe.S').read_text()
utils=P[P.index('cpuid_store:'):P.index('\n.section .rdata')]
head=r'''.intel_syntax noprefix
.text
.globl efi_main
.p2align 4
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
 lea rax,[rip+efi_main]
 mov [rip+meta+8],rax
 movabs rax,0x46504354524c3031
 mov [rip+meta],rax
 xor eax,eax
 mov ax,cs
 mov [rip+meta+16],rax
 mov ax,ds
 mov [rip+meta+24],rax
 mov rax,cr0
 mov [rip+meta+32],rax
 mov rax,cr3
 mov [rip+meta+40],rax
 mov rax,cr4
 mov [rip+meta+48],rax
 mov eax,1
 cpuid
 mov [rip+meta+56],eax
 mov [rip+meta+60],edx
 mov eax,7
 xor ecx,ecx
 cpuid
 mov [rip+meta+64],ebx
 mov rax,cr0
 or rax,0x10022
 and rax,-13
 mov cr0,rax
 mov rax,cr4
 or rax,0x600
 and rax,-262145
 mov cr4,rax
 # All code, data, own stack and page tables must be below 2MiB.
 lea rax,[rip+bss_end]
 cmp rax,0x200000
 jae unsupported
 # Fixed private identity map, 128MiB, with 4KiB granularity below2MiB.
 lea rax,[rip+pdpt]
 or rax,3
 mov [rip+pml4],rax
 lea rax,[rip+pd]
 or rax,3
 mov [rip+pdpt],rax
 lea rax,[rip+pt]
 or rax,3
 mov [rip+pd],rax
 lea rdi,[rip+pd+8]
 mov eax,0x200083
 mov ecx,63
1: stosq
 add rax,0x200000
 loop 1b
 lea rdi,[rip+pt]
 mov eax,3
 mov ecx,512
2: stosq
 add rax,4096
 loop 2b
 # Initialize read-only ENV page before activating protection.
 lea rsi,[rip+source_env]
 lea rdi,[rip+ro_env]
 mov ecx,7
 rep movsd
 lea rax,[rip+ro_env]
 mov [rip+meta+72],rax
 mov rcx,rax
 shr rcx,12
 lea rdi,[rip+pt]
 or rax,1
 mov [rdi+rcx*8],rax
 # Own32-gate IDT; exact current CS, fixed interrupt gates, no IST.
 lea rsi,[rip+isr_table]
 lea rdi,[rip+idt]
 mov ecx,32
3: lodsq
 mov [rdi],ax
 mov dx,cs
 mov [rdi+2],dx
 mov word ptr [rdi+4],0x8e00
 shr rax,16
 mov [rdi+6],ax
 shr rax,16
 mov [rdi+8],eax
 mov dword ptr [rdi+12],0
 add rdi,16
 loop 3b
 lidt [rip+idtr]
 lea rax,[rip+pml4]
 mov cr3,rax
 mov [rip+meta+80],rax
 call tests
 call reports
 lea rsi,[rip+done_text]
 call print_str
 mov dx,0xf4
 mov eax,0x10
 out dx,eax
halt:
 cli
 hlt
 jmp halt
unsupported:
 lea rsi,[rip+unsupported_text]
 call print_str
 mov dx,0xf4
 mov eax,0x11
 out dx,eax
 jmp halt

# R15 is not guest authority: it selects only the authored active case buffer.
# Each case has64 event bytes,512 before,512 after. Only a fixed owned label
# can resume; every exception vector/error/RIP/CR2/CR0 is retained, never hidden.
.macro START name
 call install_b
 lea r15,[rip+case_\name]
 mov [rip+active_case],r15
 lea rax,[rip+resume_\name]
 mov [rip+resume_pc],rax
 fxsave64 [r15+64]
.endm
.macro END name
resume_\name:
 mov rax,cr0
 and rax,-13
 mov cr0,rax
 fxsave64 [r15+576]
 fninit
 mov qword ptr [rip+active_case],0
.endm
install_b:
 fninit
 ldmxcsr [rip+mxcsr_b]
 movdqu xmm0,[rip+xmm_b]
 movdqu xmm15,[rip+xmm_b15]
 fld qword ptr [rip+operand_b]
 ret

# Deliberately masked ZE followed by real FLDCW unmask. No waiting instruction
# follows until the tested instruction; FX and FNSTENV are non-waiting.
make_pending:
 fninit
 ldmxcsr [rip+mxcsr_b]
 movdqu xmm0,[rip+xmm_b]
 movdqu xmm15,[rip+xmm_b15]
 fld qword ptr [rip+operand_a]
.globl masked_divide
masked_divide:
 fdiv qword ptr [rip+zero]
 fldcw [rip+cw_unmask]
 ret

make_fresh_pending:
 call install_b
 fninit
 fld qword ptr [rip+operand_a]
 fldcw [rip+cw_unmask]
.globl unmasked_divide
unmasked_divide:
 fdiv qword ptr [rip+zero]
 ret

tests:
 # Summary/mask boundary snapshots independently compared with actual host.
 fninit
 fld qword ptr [rip+operand_a]
 fdiv qword ptr [rip+zero]
 fxsave64 [rip+mask_0]
 fldcw [rip+cw_unmask]
 fxsave64 [rip+mask_1]
 fnstenv [rip+mask_env]
 fxsave64 [rip+mask_2]
 fldcw [rip+cw_unmask]
 fxsave64 [rip+mask_3]
 fninit
 fxsave64 [rip+mask_4]
 START fldenv_ro
.globl op_fldenv_ro
op_fldenv_ro:
 fldenv [rip+ro_env]
 END fldenv_ro

 # Invalid image has contrasting control/register state, making partial commit
 # observable; complete saved-image rawbytes are retained.
 call install_b
 fxsave64 [rip+bad_image]
 mov word ptr [rip+bad_image],0x077f
 mov qword ptr [rip+bad_image+8],0x12345678
 mov qword ptr [rip+bad_image+16],0x23456780
 mov dword ptr [rip+bad_image+24],0x10000
 mov qword ptr [rip+bad_image+160],0x11223344
 START bad_fx
.globl op_bad_fx
op_bad_fx:
 fxrstor64 [rip+bad_image]
 END bad_fx
 # Distinct selectors test actual non-W restore rather than current selectors.
 call install_b
 fxsave [rip+legacy_source]
 mov word ptr [rip+legacy_source+6],0x435
 mov dword ptr [rip+legacy_source+8],0x12345678
 mov word ptr [rip+legacy_source+12],0x1234
 mov dword ptr [rip+legacy_source+16],0x23456780
 mov word ptr [rip+legacy_source+20],0x5678
 START legacy
.globl op_legacy
op_legacy:
 fxrstor [rip+legacy_source]
 fxsave [rip+legacy_after_l]
 fnstenv [rip+legacy_env]
 END legacy
 START bad_mxcsr
.globl op_bad_mxcsr
op_bad_mxcsr:
 ldmxcsr [rip+bad_mxcsr]
 END bad_mxcsr
 START unaligned
.globl op_unaligned
op_unaligned:
 fxsave64 [rip+unaligned_buffer+1]
 END unaligned
 START ts
 mov rax,cr0
 or rax,8
 mov cr0,rax
.globl op_ts
op_ts:
 fxsave64 [rip+unaligned_buffer]
 END ts
 START em
 mov rax,cr0
 or rax,4
 mov cr0,rax
.globl op_em
op_em:
 fxsave64 [rip+unaligned_buffer]
 END em
 START fstenv_ro
 call make_pending
 fxsave64 [r15+64]
.globl op_fstenv_ro
op_fstenv_ro:
 fnstenv [rip+ro_env]
 END fstenv_ro
 START pending_wait
 call make_pending
 fxsave64 [r15+64]
.globl op_pending_wait
op_pending_wait:
 fld qword ptr [rip+operand_b]
 END pending_wait
 START pending_invalid
 call make_pending
 fxsave64 [r15+64]
.globl op_pending_invalid
op_pending_invalid:
 .byte 0xd9,0xd1
 END pending_invalid
 START pending_fresh_invalid
 call make_fresh_pending
 fxsave64 [r15+64]
.globl op_pending_fresh_invalid
op_pending_fresh_invalid:
 .byte 0xd9,0xd1
 END pending_fresh_invalid
 START pending_unmapped
 call make_pending
 fxsave64 [r15+64]
.globl op_pending_unmapped
op_pending_unmapped:
 fld qword ptr [0x40000000]
 END pending_unmapped
 START clex
 call make_pending
 fxsave64 [r15+64]
.globl op_clex
op_clex:
 fnclex
 END clex
 START init
 call make_pending
 # Craft nonzero opcode independently of masked arithmetic update semantics.
 fxsave64 [rip+valid_image]
 mov word ptr [rip+valid_image+6],0x435
 movabs rax,0x112345678
 mov [rip+valid_image+8],rax
 movabs rax,0x223456780
 mov [rip+valid_image+16],rax
 fxrstor64 [rip+valid_image]
 fxsave64 [r15+64]
.globl op_init
op_init:
 fninit
 END init

 # Record actual FS-dependent operand behavior separately; expected offset vs
 # linear interpretation comes from primary/real-host evidence, not flatDS.
 call install_b
 mov ecx,0xc0000100
 lea rax,[rip+fs_page]
 mov [rip+meta+88],rax
 mov rdx,rax
 shr rdx,32
 wrmsr
.globl op_fs_load
op_fs_load:
 fld qword ptr fs:[0x28]
 fxsave64 [rip+fs_masked_fx]
 fninit
 fld qword ptr [rip+operand_a]
 fldcw [rip+cw_unmask]
.globl op_fs_fault
op_fs_fault:
 fdiv qword ptr fs:[0x28]
 fxsave64 [rip+fs_fx]
 fnstenv [rip+fs_env]
 xor eax,eax
 xor edx,edx
 mov ecx,0xc0000100
 wrmsr
 fninit
 ret

common_isr:
 push rax
 push rbx
 push rcx
 push rdx
 push rbp
 push rsi
 push rdi
 push r8
 push r9
 push r10
 push r11
 push r12
 push r13
 push r14
 push r15
 mov rdi,[rip+active_case]
 test rdi,rdi
 jz unexpected
 mov rax,[rsp+120]
 mov [rdi],rax
 mov rax,[rsp+128]
 mov [rdi+8],rax
 mov rax,[rsp+136]
 mov [rdi+16],rax
 mov rax,cr2
 mov [rdi+24],rax
 mov rax,cr0
 mov [rdi+32],rax
 mov rax,cr4
 mov [rdi+40],rax
 mov rax,[rsp+152]
 mov [rdi+48],rax
 inc qword ptr [rdi+56]
 # Clear only EM/TS so the fault handler can capture pre-fault FP state.
 mov rax,cr0
 and rax,-13
 mov cr0,rax
 fxsave64 [rdi+576]
 mov rax,[rip+resume_pc]
 mov [rsp+136],rax
 pop r15
 pop r14
 pop r13
 pop r12
 pop r11
 pop r10
 pop r9
 pop r8
 pop rdi
 pop rsi
 pop rbp
 pop rdx
 pop rcx
 pop rbx
 pop rax
 add rsp,16
 iretq
unexpected:
 lea rsi,[rip+unexpected_text]
 call print_str
 mov dx,0xf4
 mov eax,0x12
 out dx,eax
 jmp halt
'''
# All vectors have normalized vector,error words; hardware pushes errors only
# for this exact architecture-defined subset.
err={8,10,11,12,13,14,17,21,29,30}
for n in range(32):
 head+=f'isr_{n}:\n'+(''if n in err else' push 0\n')+f' push {n}\n jmp common_isr\n'
cases=['fldenv_ro','bad_fx','legacy','bad_mxcsr','unaligned','ts','em','fstenv_ro','pending_wait','pending_invalid','pending_fresh_invalid','pending_unmapped','clex','init']
reports={'meta':('meta',128),'mask_0':('mask_0',512),'mask_1':('mask_1',512),'mask_2':('mask_2',512),'mask_3':('mask_3',512),'mask_4':('mask_4',512),'mask_env':('mask_env',28),'bad_image':('bad_image',512),'legacy_source':('legacy_source',512),'legacy_after_l':('legacy_after_l',512),'legacy_env':('legacy_env',28),'fs_fx':('fs_fx',512),'fs_masked_fx':('fs_masked_fx',512),'fs_env':('fs_env',28)}
reports.update({'case_'+n:('case_'+n,1088)for n in cases})
head+='\nreports:\n'
for n,(sym,length)in reports.items():head+=f' lea rdi,[rip+name_{n}]\n lea rsi,[rip+{sym}]\n mov edx,{length}\n call record\n'
head+=' ret\n'+utils
head+=r'''
.section .rdata,"dr"
.p2align 3
operand_a: .quad 0x3ff8000000000000
operand_b: .quad 0x4004000000000000
zero: .quad 0
cw_unmask: .word 0x037b
.p2align 2
mxcsr_b: .long 0x5f80
bad_mxcsr: .long 0x10000
.p2align 4
xmm_b: .quad 0x8877665544332211,0x0011223344556677
xmm_b15: .quad 0xdeadbeefcafebabe,0x0123012301230123
# Complete protected28 ENV: maskall,TOP0,alltagsempty,nonzero metadata.
source_env: .long 0x0b7f,0,0xffff,0x12345678,0x04350038,0x23456780,0x30
idtr: .word 32*16-1
 .quad idt
isr_table:
'''
head+=''.join(f' .quad isr_{n}\n'for n in range(32))
head+='relocation_anchor: .quad efi_main\nrecord_text: .asciz "\\nFPREC "\ndone_text: .asciz "\\nFPCTRL COMPLETE\\n"\nunsupported_text: .asciz "\\nFPCTRL UNSUPPORTED\\n"\nunexpected_text: .asciz "\\nFPCTRL UNEXPECTED\\n"\n'
for n in reports:head+=f'name_{n}: .asciz "{n}"\n'
head+='\n.bss\n.p2align 12\nbss_begin:\n'
for n in ['pml4','pdpt','pd','pt','ro_env']:head+=f'.globl {n}\n{n}: .zero 4096\n'
head+='fs_page: .zero 40\nfs_operand: .zero 8\n' # set a raw finite payload at runtime? zero is valid meaningful operand.
head+=' .zero 4096-48\n.p2align 6\nmeta: .zero 128\nactive_case: .zero 8\nresume_pc: .zero 8\n.p2align 4\nidt: .zero 512\n'
for n in ['mask_0','mask_1','mask_2','mask_3','mask_4','bad_image','valid_image','legacy_source','legacy_after_l','fs_fx','fs_masked_fx','unaligned_buffer']:head+=f'.p2align 6\n{n}: .zero 512\n'
head+='mask_env: .zero 32\nfs_env: .zero 32\nlegacy_env: .zero 32\n'
for n in cases:head+=f'.p2align 6\ncase_{n}: .zero 1088\n'
head+='.p2align 4\nstack_bottom: .zero 16384\nstack_top:\nbss_end:\n'
# Export program/site/buffer names to independently bind runtime fault RIPs.
exports=['efi_main','bss_end','ro_env','pml4','masked_divide','unmasked_divide','op_fs_load','op_fs_fault','fs_operand','bad_image','bad_mxcsr','legacy_source','legacy_after_l','legacy_env']+['op_'+n for n in cases]+['resume_'+n for n in cases]
head+='\n'+''.join('.globl '+n+'\n'for n in exports)
(B/'controls.S').write_text(head)
import json
(B/'description.json').write_text(json.dumps({'exports':exports,'cases':cases,'records':{n:l for n,(_,l)in reports.items()},'scope':'Authored oneCPU CPL0 original-emulator control diagnostic; explicit expected fault sites; no nativeOS/fullFPU admission'},indent=2)+'\n')
