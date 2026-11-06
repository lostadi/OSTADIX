.intel_syntax noprefix
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

.globl efi_main
.globl image
.globl command_loop
.globl actual_w
.globl actual_l
.globl actual_env
.globl state
