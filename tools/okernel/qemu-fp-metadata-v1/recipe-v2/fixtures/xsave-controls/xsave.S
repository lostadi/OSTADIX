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
 mov [rip+meta+96],ecx
 test ecx,1<<26
 jz unsupported
 mov eax,7
 xor ecx,ecx
 cpuid
 mov [rip+meta+64],ebx
 mov rax,cr0
 or rax,0x10022
 and rax,-13
 mov cr0,rax
 mov rax,cr4
 or rax,0x40600
 mov cr4,rax
 mov [rip+meta+104],rax
 xor ecx,ecx
 mov eax,3
 xor edx,edx
 xsetbv
 xgetbv
 mov [rip+meta+112],rax
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
 call xsave_tests
 call xreports
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
old_bss_end:

.globl efi_main
.globl bss_end
.globl ro_env
.globl pml4
.globl masked_divide
.globl unmasked_divide
.globl fs_operand
.globl bad_image
.globl bad_mxcsr
.globl legacy_source
.globl legacy_after_l
.globl legacy_env

.text
xreports:
 lea rdi,[rip+xname_meta]
 lea rsi,[rip+meta]
 mov edx,128
 call record
 lea rdi,[rip+xname_after_legacy]
 lea rsi,[rip+after_legacy]
 mov edx,512
 call record
 lea rdi,[rip+xname_after_legacy_env]
 lea rsi,[rip+after_legacy_env]
 mov edx,28
 call record
 lea rdi,[rip+xname_xwide]
 lea rsi,[rip+xwide]
 mov edx,1024
 call record
 lea rdi,[rip+xname_xlegacy]
 lea rsi,[rip+xlegacy]
 mov edx,1024
 call record
 lea rdi,[rip+xname_xinitfp]
 lea rsi,[rip+xinitfp]
 mov edx,1024
 call record
 lea rdi,[rip+xname_xinitall]
 lea rsi,[rip+xinitall]
 mov edx,1024
 call record
 lea rdi,[rip+xname_xbad]
 lea rsi,[rip+xbad]
 mov edx,1024
 call record
 lea rdi,[rip+xname_xbadhdr]
 lea rsi,[rip+xbadhdr]
 mov edx,1024
 call record
 lea rdi,[rip+xname_xbadbit]
 lea rsi,[rip+xbadbit]
 mov edx,1024
 call record
 lea rdi,[rip+xname_case_xrstorw]
 lea rsi,[rip+case_xrstorw]
 mov edx,1088
 call record
 lea rdi,[rip+xname_case_xrstorl]
 lea rsi,[rip+case_xrstorl]
 mov edx,1088
 call record
 lea rdi,[rip+xname_case_initfp]
 lea rsi,[rip+case_initfp]
 mov edx,1088
 call record
 lea rdi,[rip+xname_case_initall]
 lea rsi,[rip+case_initall]
 mov edx,1088
 call record
 lea rdi,[rip+xname_case_badmxcsr]
 lea rsi,[rip+case_badmxcsr]
 mov edx,1088
 call record
 lea rdi,[rip+xname_case_badheader]
 lea rsi,[rip+case_badheader]
 mov edx,1088
 call record
 lea rdi,[rip+xname_case_badstatebit]
 lea rsi,[rip+case_badstatebit]
 mov edx,1088
 call record
 ret
.section .rdata,"dr"
xname_meta: .asciz "meta"
xname_after_legacy: .asciz "after_legacy"
xname_after_legacy_env: .asciz "after_legacy_env"
xname_xwide: .asciz "xwide"
xname_xlegacy: .asciz "xlegacy"
xname_xinitfp: .asciz "xinitfp"
xname_xinitall: .asciz "xinitall"
xname_xbad: .asciz "xbad"
xname_xbadhdr: .asciz "xbadhdr"
xname_xbadbit: .asciz "xbadbit"
xname_case_xrstorw: .asciz "case_xrstorw"
xname_case_xrstorl: .asciz "case_xrstorl"
xname_case_initfp: .asciz "case_initfp"
xname_case_initall: .asciz "case_initall"
xname_case_badmxcsr: .asciz "case_badmxcsr"
xname_case_badheader: .asciz "case_badheader"
xname_case_badstatebit: .asciz "case_badstatebit"

.bss
.p2align 6
xwide: .zero 1024
.p2align 6
xlegacy: .zero 1024
.p2align 6
xinitfp: .zero 1024
.p2align 6
xinitall: .zero 1024
.p2align 6
xbad: .zero 1024
.p2align 6
xbadhdr: .zero 1024
.p2align 6
xbadbit: .zero 1024
after_legacy: .zero 512
after_legacy_env: .zero 32
.p2align 6
case_xrstorw: .zero 1088
.p2align 6
case_xrstorl: .zero 1088
.p2align 6
case_initfp: .zero 1088
.p2align 6
case_initall: .zero 1088
.p2align 6
case_badmxcsr: .zero 1088
.p2align 6
case_badheader: .zero 1088
.p2align 6
case_badstatebit: .zero 1088

bss_end:
.globl efi_main
.globl bss_end
.globl ro_env
.globl pml4
.globl op_xsavew
.globl op_xsavel
.globl after_legacy
.globl op_xrstorw
.globl op_xrstorl
.globl op_initfp
.globl op_initall
.globl op_badmxcsr
.globl op_badheader
.globl op_badstatebit
.globl resume_xrstorw
.globl resume_xrstorl
.globl resume_initfp
.globl resume_initall
.globl resume_badmxcsr
.globl resume_badheader
.globl resume_badstatebit
.globl xwide
.globl xlegacy
.globl xinitfp
.globl xinitall
.globl xbad
.globl xbadhdr
.globl xbadbit
