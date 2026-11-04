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
