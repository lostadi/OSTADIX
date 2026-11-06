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

.text
.balign 16
.global _start
_start:
movz x0, #19
movz x1, #23
bl _O_smoke__addition__add
movz x9, #42
cmp x0, x9
b.ne .L_fail_1
movz x0, #65529
movk x0, #65535, lsl #16
movk x0, #65535, lsl #32
movk x0, #65535, lsl #48
movz x1, #11
bl _O_smoke__addition__add
movz x9, #4
cmp x0, x9
b.ne .L_fail_2
movz x0, #0
movz x1, #0
bl _O_smoke__addition__add
movz x9, #0
cmp x0, x9
b.ne .L_fail_3
movz x0, #0
movk x0, #256, lsl #32
movz x1, #65533
movk x1, #65535, lsl #16
movk x1, #65535, lsl #32
movk x1, #65535, lsl #48
bl _O_smoke__addition__add
movz x9, #65533
movk x9, #65535, lsl #16
movk x9, #255, lsl #32
cmp x0, x9
b.ne .L_fail_4
mov x0, #0
mov x8, #93
svc #0
brk #0
.L_fail_1:
mov x0, #1
mov x8, #93
svc #0
brk #0
.L_fail_2:
mov x0, #2
mov x8, #93
svc #0
brk #0
.L_fail_3:
mov x0, #3
mov x8, #93
svc #0
brk #0
.L_fail_4:
mov x0, #4
mov x8, #93
svc #0
brk #0
