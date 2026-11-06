.intel_syntax noprefix
.text
.globl efi_main
.p2align 4
efi_main:
  pushfq
  pop r9
  cli
  lea rsp, [rip + stack_top]
  and rsp, -16
  lea rdi, [rip + bss_begin]
  xor eax, eax
  lea rcx, [rip + bss_end]
  sub rcx, rdi
  shr rcx, 3
  rep stosq
  mov qword ptr [rip + controls + 24], r9
  call serial_init
  movabs rax, 0x4650505452303031
  mov [rip + metadata], rax
.macro META index, symbol
  lea rax, [rip + \symbol]
  mov [rip + metadata + 8*\index], rax
.endm
  META 1, efi_main
  META 2, fp_load_normal
  META 3, operand_a
  META 4, fp_fault_a
  META 5, zero_a
  META 6, fp_load_b
  META 7, operand_b
  META 8, fp_fault_b
  META 9, zero_b
  META 10, fx_a_w
  META 11, fx_a_l
  META 12, fx_crafted
  xor eax, eax
  mov ax, cs
  mov [rip + metadata + 13*8], rax
  mov ax, ds
  mov [rip + metadata + 14*8], rax
  mov ax, ss
  mov [rip + metadata + 15*8], rax
  mov rax, cr0
  mov [rip + controls], rax
  mov rax, cr4
  mov [rip + controls + 8], rax
  mov ecx, 0xc0000080
  rdmsr
  shl rdx, 32
  or rax, rdx
  mov [rip + controls + 16], rax
  test eax, 1<<14
  jnz unsupported
  xor eax, eax
  xor ecx, ecx
  lea rdi, [rip + cpuid_words]
  call cpuid_store
  mov eax, 1
  xor ecx, ecx
  lea rdi, [rip + cpuid_words + 16]
  call cpuid_store
  mov eax, edx
  and eax, 0x07000001
  cmp eax, 0x07000001
  jne unsupported
  test ecx, 0x1c000000
  jnz unsupported
  mov eax, 7
  xor ecx, ecx
  lea rdi, [rip + cpuid_words + 32]
  call cpuid_store
  mov eax, 0x80000001
  xor ecx, ecx
  lea rdi, [rip + cpuid_words + 48]
  call cpuid_store
  mov rax, cr0
  or rax, 0x22
  and rax, -13
  mov cr0, rax
  mov [rip + controls + 32], rax
  mov rax, cr4
  or rax, 0x600
  and rax, -262145
  mov cr4, rax
  mov [rip + controls + 40], rax
  mov ecx, 0xc0000080
  rdmsr
  shl rdx, 32
  or rax, rdx
  mov [rip + controls + 48], rax
  pushfq
  pop rax
  mov [rip + controls + 56], rax

  // Ordinary masked FLD: pointers are checked; FOP is not required nonzero.
  fninit
  ldmxcsr [rip + mxcsr_a]
  movdqu xmm0, [rip + xmm_a]
  movdqu xmm15, [rip + xmm_a15]
.globl fp_load_normal
fp_load_normal:
  fld qword ptr [rip + operand_a]
  fxsave64 [rip + fx_normal]
  fnstenv [rip + env_normal]

  // Only non-waiting instructions follow the unmasked exception until FNINIT.
  fninit
  ldmxcsr [rip + mxcsr_a]
  movdqu xmm0, [rip + xmm_a]
  movdqu xmm15, [rip + xmm_a15]
  fld qword ptr [rip + operand_a]
  fldcw [rip + fcw_a]
.globl fp_fault_a
fp_fault_a:
  fdiv qword ptr [rip + zero_a]
.globl save_a_w
save_a_w:
  fxsave64 [rip + fx_a_w]
.globl save_a_l
save_a_l:
  fxsave [rip + fx_a_l]
  fnstenv [rip + env_a]

  call install_b
  fxsave64 [rip + fx_b_w]
  fnstenv [rip + env_b]
.globl restore_a_w
restore_a_w:
  fxrstor64 [rip + fx_a_w]
  fxsave64 [rip + fx_after_w]
  fnstenv [rip + env_after_w]

  // Craft only FOP/FIP/FDP in a valid captured A image; no reserved MXCSR bits.
  fninit
  lea rsi, [rip + fx_a_w]
  lea rdi, [rip + fx_crafted]
  mov ecx, 64
  rep movsq
  movzx eax, byte ptr [rip + fp_fault_a]
  and eax, 7
  shl eax, 8
  movzx edx, byte ptr [rip + fp_fault_a + 1]
  or eax, edx
  mov [rip + fx_crafted + 6], ax
  movabs rax, 0x0000000112345678
  mov [rip + fx_crafted + 8], rax
  movabs rax, 0x0000000223456780
  mov [rip + fx_crafted + 16], rax
  call install_b
.globl restore_crafted_w
restore_crafted_w:
  fxrstor64 [rip + fx_crafted]
  fxsave64 [rip + fx_after_crafted]
  fnstenv [rip + env_after_crafted]

  fninit
  call install_b
.globl restore_a_l
restore_a_l:
  fxrstor [rip + fx_a_l]
  fxsave64 [rip + fx_after_l_w]
  fxsave [rip + fx_after_l_l]
  fnstenv [rip + env_after_l]
  // Clear pending exception before any report path (which is integer only).
  fninit

.macro RECORD name, buffer, length
  lea rdi, [rip + \name]
  lea rsi, [rip + \buffer]
  mov edx, \length
  call record
.endm
  RECORD name_metadata, metadata, 128
  RECORD name_cpuid, cpuid_words, 64
  RECORD name_controls, controls, 64
  RECORD name_normal_fx, fx_normal, 512
  RECORD name_normal_env, env_normal, 28
  RECORD name_a_w, fx_a_w, 512
  RECORD name_a_l, fx_a_l, 512
  RECORD name_a_env, env_a, 28
  RECORD name_b_w, fx_b_w, 512
  RECORD name_b_env, env_b, 28
  RECORD name_after_w, fx_after_w, 512
  RECORD name_after_w_env, env_after_w, 28
  RECORD name_crafted, fx_crafted, 512
  RECORD name_after_crafted, fx_after_crafted, 512
  RECORD name_after_crafted_env, env_after_crafted, 28
  RECORD name_after_l_w, fx_after_l_w, 512
  RECORD name_after_l_l, fx_after_l_l, 512
  RECORD name_after_l_env, env_after_l, 28
  lea rsi, [rip + complete_text]
  call print_str
  mov dx, 0xf4
  mov eax, 0x10
  out dx, eax
halt_forever:
  cli
  hlt
  jmp halt_forever

unsupported:
  lea rsi, [rip + unsupported_text]
  call print_str
  mov dx, 0xf4
  mov eax, 0x11
  out dx, eax
  jmp halt_forever

install_b:
  // FNINIT is non-waiting and is first: no accidental deferred #MF in setup.
  fninit
  ldmxcsr [rip + mxcsr_b]
  movdqu xmm0, [rip + xmm_b]
  movdqu xmm15, [rip + xmm_b15]
.globl fp_load_b
fp_load_b:
  fld qword ptr [rip + operand_b]
  fldcw [rip + fcw_b]
.globl fp_fault_b
fp_fault_b:
  fdivr qword ptr [rip + zero_b]
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
.globl operand_a
operand_a: .quad 0x3ff8000000000000
.globl operand_b
operand_b: .quad 0
.globl zero_a
zero_a: .quad 0
.globl zero_b
zero_b: .quad 0
fcw_a: .word 0x037b
fcw_b: .word 0x0b7e
.p2align 2
mxcsr_a: .long 0x1f80
mxcsr_b: .long 0x5f80
.p2align 4
xmm_a: .quad 0x0123456789abcdef,0xfedcba9876543210
xmm_a15: .quad 0x1111222233334444,0xaaaabbbbccccdddd
xmm_b: .quad 0x8877665544332211,0x0011223344556677
xmm_b15: .quad 0xdeadbeefcafebabe,0x0123012301230123
// Force a real image-base relocation; all executable references are RIP-relative.
relocation_anchor: .quad efi_main
record_text: .asciz "\nFPREC "
complete_text: .asciz "\nFPEND COMPLETE\n"
unsupported_text: .asciz "\nFPEND UNSUPPORTED\n"
name_metadata: .asciz "metadata"
name_cpuid: .asciz "cpuid"
name_controls: .asciz "controls"
name_normal_fx: .asciz "normal_fx"
name_normal_env: .asciz "normal_env"
name_a_w: .asciz "a_w"
name_a_l: .asciz "a_l"
name_a_env: .asciz "a_env"
name_b_w: .asciz "b_w"
name_b_env: .asciz "b_env"
name_after_w: .asciz "after_w"
name_after_w_env: .asciz "after_w_env"
name_crafted: .asciz "crafted"
name_after_crafted: .asciz "after_crafted"
name_after_crafted_env: .asciz "after_crafted_env"
name_after_l_w: .asciz "after_l_w"
name_after_l_l: .asciz "after_l_l"
name_after_l_env: .asciz "after_l_env"

.bss
.p2align 6
bss_begin:
metadata: .zero 128
controls: .zero 64
cpuid_words: .zero 64
.p2align 6
.globl fx_a_w
fx_a_w: .zero 512
.globl fx_a_l
fx_a_l: .zero 512
.globl fx_crafted
fx_crafted: .zero 512
fx_normal: .zero 512
fx_b_w: .zero 512
fx_after_w: .zero 512
fx_after_crafted: .zero 512
fx_after_l_w: .zero 512
fx_after_l_l: .zero 512
.p2align 4
env_normal: .zero 32
env_a: .zero 32
env_b: .zero 32
env_after_w: .zero 32
env_after_crafted: .zero 32
env_after_l: .zero 32
.p2align 4
stack_bottom: .zero 16384
stack_top:
bss_end:
