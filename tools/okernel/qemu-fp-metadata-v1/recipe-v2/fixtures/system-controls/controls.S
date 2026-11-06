.intel_syntax noprefix
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
isr_0:
 push 0
 push 0
 jmp common_isr
isr_1:
 push 0
 push 1
 jmp common_isr
isr_2:
 push 0
 push 2
 jmp common_isr
isr_3:
 push 0
 push 3
 jmp common_isr
isr_4:
 push 0
 push 4
 jmp common_isr
isr_5:
 push 0
 push 5
 jmp common_isr
isr_6:
 push 0
 push 6
 jmp common_isr
isr_7:
 push 0
 push 7
 jmp common_isr
isr_8:
 push 8
 jmp common_isr
isr_9:
 push 0
 push 9
 jmp common_isr
isr_10:
 push 10
 jmp common_isr
isr_11:
 push 11
 jmp common_isr
isr_12:
 push 12
 jmp common_isr
isr_13:
 push 13
 jmp common_isr
isr_14:
 push 14
 jmp common_isr
isr_15:
 push 0
 push 15
 jmp common_isr
isr_16:
 push 0
 push 16
 jmp common_isr
isr_17:
 push 17
 jmp common_isr
isr_18:
 push 0
 push 18
 jmp common_isr
isr_19:
 push 0
 push 19
 jmp common_isr
isr_20:
 push 0
 push 20
 jmp common_isr
isr_21:
 push 21
 jmp common_isr
isr_22:
 push 0
 push 22
 jmp common_isr
isr_23:
 push 0
 push 23
 jmp common_isr
isr_24:
 push 0
 push 24
 jmp common_isr
isr_25:
 push 0
 push 25
 jmp common_isr
isr_26:
 push 0
 push 26
 jmp common_isr
isr_27:
 push 0
 push 27
 jmp common_isr
isr_28:
 push 0
 push 28
 jmp common_isr
isr_29:
 push 29
 jmp common_isr
isr_30:
 push 30
 jmp common_isr
isr_31:
 push 0
 push 31
 jmp common_isr

reports:
 lea rdi,[rip+name_meta]
 lea rsi,[rip+meta]
 mov edx,128
 call record
 lea rdi,[rip+name_mask_0]
 lea rsi,[rip+mask_0]
 mov edx,512
 call record
 lea rdi,[rip+name_mask_1]
 lea rsi,[rip+mask_1]
 mov edx,512
 call record
 lea rdi,[rip+name_mask_2]
 lea rsi,[rip+mask_2]
 mov edx,512
 call record
 lea rdi,[rip+name_mask_3]
 lea rsi,[rip+mask_3]
 mov edx,512
 call record
 lea rdi,[rip+name_mask_4]
 lea rsi,[rip+mask_4]
 mov edx,512
 call record
 lea rdi,[rip+name_mask_env]
 lea rsi,[rip+mask_env]
 mov edx,28
 call record
 lea rdi,[rip+name_bad_image]
 lea rsi,[rip+bad_image]
 mov edx,512
 call record
 lea rdi,[rip+name_legacy_source]
 lea rsi,[rip+legacy_source]
 mov edx,512
 call record
 lea rdi,[rip+name_legacy_after_l]
 lea rsi,[rip+legacy_after_l]
 mov edx,512
 call record
 lea rdi,[rip+name_legacy_env]
 lea rsi,[rip+legacy_env]
 mov edx,28
 call record
 lea rdi,[rip+name_fs_fx]
 lea rsi,[rip+fs_fx]
 mov edx,512
 call record
 lea rdi,[rip+name_fs_masked_fx]
 lea rsi,[rip+fs_masked_fx]
 mov edx,512
 call record
 lea rdi,[rip+name_fs_env]
 lea rsi,[rip+fs_env]
 mov edx,28
 call record
 lea rdi,[rip+name_case_fldenv_ro]
 lea rsi,[rip+case_fldenv_ro]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_bad_fx]
 lea rsi,[rip+case_bad_fx]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_legacy]
 lea rsi,[rip+case_legacy]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_bad_mxcsr]
 lea rsi,[rip+case_bad_mxcsr]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_unaligned]
 lea rsi,[rip+case_unaligned]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_ts]
 lea rsi,[rip+case_ts]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_em]
 lea rsi,[rip+case_em]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_fstenv_ro]
 lea rsi,[rip+case_fstenv_ro]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_pending_wait]
 lea rsi,[rip+case_pending_wait]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_pending_invalid]
 lea rsi,[rip+case_pending_invalid]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_pending_fresh_invalid]
 lea rsi,[rip+case_pending_fresh_invalid]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_pending_unmapped]
 lea rsi,[rip+case_pending_unmapped]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_clex]
 lea rsi,[rip+case_clex]
 mov edx,1088
 call record
 lea rdi,[rip+name_case_init]
 lea rsi,[rip+case_init]
 mov edx,1088
 call record
 ret
cpuid_store:
  cpuid
  mov [rdi], eax
  mov [rdi + 4], ebx
  mov [rdi + 8], ecx
  mov [rdi + 12], edx
  ret
serial_init:
  mov dx, 0x3f9
  xor eax, eax
  out dx, al
  mov dx, 0x3fb
  mov al, 0x80
  out dx, al
  mov dx, 0x3f8
  mov al, 1
  out dx, al
  mov dx, 0x3f9
  xor eax, eax
  out dx, al
  mov dx, 0x3fb
  mov al, 3
  out dx, al
  mov dx, 0x3fa
  mov al, 0xc7
  out dx, al
  mov dx, 0x3fc
  mov al, 0x0b
  out dx, al
  ret
putc:
  mov r8b, al
  mov dx, 0x3fd
serial_wait:
  in al, dx
  test al, 0x20
  jz serial_wait
  mov dx, 0x3f8
  mov al, r8b
  out dx, al
  ret
print_str:
  lodsb
  test al, al
  jz string_done
  call putc
  jmp print_str
string_done:
  ret
hex64:
  push rbx
  push rcx
  mov rbx, rax
  mov ecx, 16
hex64_loop:
  rol rbx, 4
  mov al, bl
  and al, 15
  cmp al, 10
  jb hex64_digit
  add al, 87
  jmp hex64_emit
hex64_digit:
  add al, 48
hex64_emit:
  call putc
  dec ecx
  jnz hex64_loop
  pop rcx
  pop rbx
  ret
hex8:
  push rbx
  mov bl, al
  shr al, 4
  cmp al, 10
  jb hex8_hi_digit
  add al, 87
  jmp hex8_hi_emit
hex8_hi_digit:
  add al, 48
hex8_hi_emit:
  call putc
  mov al, bl
  and al, 15
  cmp al, 10
  jb hex8_lo_digit
  add al, 87
  jmp hex8_lo_emit
hex8_lo_digit:
  add al, 48
hex8_lo_emit:
  call putc
  pop rbx
  ret
record:
  push r12
  push r13
  push r14
  mov r12, rdi
  mov r13, rsi
  mov r14, rdx
  lea rsi, [rip + record_text]
  call print_str
  mov rsi, r12
  call print_str
  mov al, 32
  call putc
  mov rax, r14
  call hex64
  mov al, 32
  call putc
record_loop:
  test r14, r14
  jz record_done
  mov al, [r13]
  call hex8
  inc r13
  dec r14
  jmp record_loop
record_done:
  mov al, 10
  call putc
  pop r14
  pop r13
  pop r12
  ret

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
 .quad isr_0
 .quad isr_1
 .quad isr_2
 .quad isr_3
 .quad isr_4
 .quad isr_5
 .quad isr_6
 .quad isr_7
 .quad isr_8
 .quad isr_9
 .quad isr_10
 .quad isr_11
 .quad isr_12
 .quad isr_13
 .quad isr_14
 .quad isr_15
 .quad isr_16
 .quad isr_17
 .quad isr_18
 .quad isr_19
 .quad isr_20
 .quad isr_21
 .quad isr_22
 .quad isr_23
 .quad isr_24
 .quad isr_25
 .quad isr_26
 .quad isr_27
 .quad isr_28
 .quad isr_29
 .quad isr_30
 .quad isr_31
relocation_anchor: .quad efi_main
record_text: .asciz "\nFPREC "
done_text: .asciz "\nFPCTRL COMPLETE\n"
unsupported_text: .asciz "\nFPCTRL UNSUPPORTED\n"
unexpected_text: .asciz "\nFPCTRL UNEXPECTED\n"
name_meta: .asciz "meta"
name_mask_0: .asciz "mask_0"
name_mask_1: .asciz "mask_1"
name_mask_2: .asciz "mask_2"
name_mask_3: .asciz "mask_3"
name_mask_4: .asciz "mask_4"
name_mask_env: .asciz "mask_env"
name_bad_image: .asciz "bad_image"
name_legacy_source: .asciz "legacy_source"
name_legacy_after_l: .asciz "legacy_after_l"
name_legacy_env: .asciz "legacy_env"
name_fs_fx: .asciz "fs_fx"
name_fs_masked_fx: .asciz "fs_masked_fx"
name_fs_env: .asciz "fs_env"
name_case_fldenv_ro: .asciz "case_fldenv_ro"
name_case_bad_fx: .asciz "case_bad_fx"
name_case_legacy: .asciz "case_legacy"
name_case_bad_mxcsr: .asciz "case_bad_mxcsr"
name_case_unaligned: .asciz "case_unaligned"
name_case_ts: .asciz "case_ts"
name_case_em: .asciz "case_em"
name_case_fstenv_ro: .asciz "case_fstenv_ro"
name_case_pending_wait: .asciz "case_pending_wait"
name_case_pending_invalid: .asciz "case_pending_invalid"
name_case_pending_fresh_invalid: .asciz "case_pending_fresh_invalid"
name_case_pending_unmapped: .asciz "case_pending_unmapped"
name_case_clex: .asciz "case_clex"
name_case_init: .asciz "case_init"

.bss
.p2align 12
bss_begin:
.globl pml4
pml4: .zero 4096
.globl pdpt
pdpt: .zero 4096
.globl pd
pd: .zero 4096
.globl pt
pt: .zero 4096
.globl ro_env
ro_env: .zero 4096
fs_page: .zero 40
fs_operand: .zero 8
 .zero 4096-48
.p2align 6
meta: .zero 128
active_case: .zero 8
resume_pc: .zero 8
.p2align 4
idt: .zero 512
.p2align 6
mask_0: .zero 512
.p2align 6
mask_1: .zero 512
.p2align 6
mask_2: .zero 512
.p2align 6
mask_3: .zero 512
.p2align 6
mask_4: .zero 512
.p2align 6
bad_image: .zero 512
.p2align 6
valid_image: .zero 512
.p2align 6
legacy_source: .zero 512
.p2align 6
legacy_after_l: .zero 512
.p2align 6
fs_fx: .zero 512
.p2align 6
fs_masked_fx: .zero 512
.p2align 6
unaligned_buffer: .zero 512
mask_env: .zero 32
fs_env: .zero 32
legacy_env: .zero 32
.p2align 6
case_fldenv_ro: .zero 1088
.p2align 6
case_bad_fx: .zero 1088
.p2align 6
case_legacy: .zero 1088
.p2align 6
case_bad_mxcsr: .zero 1088
.p2align 6
case_unaligned: .zero 1088
.p2align 6
case_ts: .zero 1088
.p2align 6
case_em: .zero 1088
.p2align 6
case_fstenv_ro: .zero 1088
.p2align 6
case_pending_wait: .zero 1088
.p2align 6
case_pending_invalid: .zero 1088
.p2align 6
case_pending_fresh_invalid: .zero 1088
.p2align 6
case_pending_unmapped: .zero 1088
.p2align 6
case_clex: .zero 1088
.p2align 6
case_init: .zero 1088
.p2align 4
stack_bottom: .zero 16384
stack_top:
bss_end:

.globl efi_main
.globl bss_end
.globl ro_env
.globl pml4
.globl masked_divide
.globl unmasked_divide
.globl op_fs_load
.globl op_fs_fault
.globl fs_operand
.globl bad_image
.globl bad_mxcsr
.globl legacy_source
.globl legacy_after_l
.globl legacy_env
.globl op_fldenv_ro
.globl op_bad_fx
.globl op_legacy
.globl op_bad_mxcsr
.globl op_unaligned
.globl op_ts
.globl op_em
.globl op_fstenv_ro
.globl op_pending_wait
.globl op_pending_invalid
.globl op_pending_fresh_invalid
.globl op_pending_unmapped
.globl op_clex
.globl op_init
.globl resume_fldenv_ro
.globl resume_bad_fx
.globl resume_legacy
.globl resume_bad_mxcsr
.globl resume_unaligned
.globl resume_ts
.globl resume_em
.globl resume_fstenv_ro
.globl resume_pending_wait
.globl resume_pending_invalid
.globl resume_pending_fresh_invalid
.globl resume_pending_unmapped
.globl resume_clex
.globl resume_init
