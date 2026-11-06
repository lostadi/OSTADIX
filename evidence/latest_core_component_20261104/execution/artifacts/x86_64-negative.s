.intel_syntax noprefix
.file "ocore"
.section .text,"ax",@progbits
.balign 16
.local _O_smoke__addition__add
.type _O_smoke__addition__add, @function
_O_smoke__addition__add:
  push rbp
  mov rbp, rsp
  sub rsp, 48
  mov qword ptr [rbp-8], rdi
  mov qword ptr [rbp-16], rsi
  jmp .L_ocore_0_bb0
.L_ocore_0_bb0:
  lea r11, [rbp-8]
  mov rax, qword ptr [r11]
  mov qword ptr [rbp-24], rax
  lea r11, [rbp-16]
  mov rax, qword ptr [r11]
  mov qword ptr [rbp-32], rax
  mov rax, qword ptr [rbp-24]
  mov rcx, qword ptr [rbp-32]
  add rax, rcx
  mov qword ptr [rbp-40], rax
  mov rax, qword ptr [rbp-40]
  add rsp, 48
  pop rbp
  ret
.size _O_smoke__addition__add, .-_O_smoke__addition__add
.section .note.GNU-stack,"",@progbits

.text
.balign 16
.global _start
_start:
mov rdi, 19
mov rsi, 23
call _O_smoke__addition__add
mov r10, 42
cmp rax, r10
jne .L_fail_1
mov rdi, -7
mov rsi, 11
call _O_smoke__addition__add
mov r10, 4
cmp rax, r10
jne .L_fail_2
mov rdi, 0
mov rsi, 0
call _O_smoke__addition__add
mov r10, 0
cmp rax, r10
jne .L_fail_3
mov rdi, 1099511627776
mov rsi, -3
call _O_smoke__addition__add
mov r10, 1099511627774
cmp rax, r10
jne .L_fail_4
mov rdi, 0
mov rax, 60
syscall
ud2
.L_fail_1:
mov rdi, 1
mov rax, 60
syscall
ud2
.L_fail_2:
mov rdi, 2
mov rax, 60
syscall
ud2
.L_fail_3:
mov rdi, 3
mov rax, 60
syscall
ud2
.L_fail_4:
mov rdi, 4
mov rax, 60
syscall
ud2
