.file "ocore"
.section .text,"ax",@progbits
.balign 16
.local _O_smoke__addition__add
.type _O_smoke__addition__add, @function
_O_smoke__addition__add:
  stp x29, x30, [sp, #-16]!
  mov x29, sp
  stp x28, xzr, [sp, #-16]!
  sub sp, sp, #48
  mov x28, sp
  add x15, x28, #0
  str x0, [x15]
  add x15, x28, #8
  str x1, [x15]
  b .L_ocore_aarch64_0_bb0
.L_ocore_aarch64_0_bb0:
  add x10, x28, #0
  ldr x9, [x10]
  add x15, x28, #16
  str x9, [x15]
  add x10, x28, #8
  ldr x9, [x10]
  add x15, x28, #24
  str x9, [x15]
  add x15, x28, #16
  ldr x9, [x15]
  add x15, x28, #24
  ldr x10, [x15]
  add x9, x9, x10
  add x15, x28, #32
  str x9, [x15]
  add x15, x28, #32
  ldr x0, [x15]
  sub sp, x29, #16
  ldp x28, xzr, [sp], #16
  ldp x29, x30, [sp], #16
  ret
.size _O_smoke__addition__add, .-_O_smoke__addition__add
.section .note.GNU-stack,"",@progbits
