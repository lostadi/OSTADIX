.file "ocore"
.option push
.option norelax
.section .text,"ax",@progbits
.balign 16
.local _O_smoke__addition__add
.type _O_smoke__addition__add, @function
_O_smoke__addition__add:
  addi sp, sp, -112
  sd ra, 104(sp)
  sd s0, 96(sp)
  sd s1, 88(sp)
  sd s2, 80(sp)
  sd s3, 72(sp)
  sd s4, 64(sp)
  sd s5, 56(sp)
  sd s6, 48(sp)
  sd s7, 40(sp)
  sd s8, 32(sp)
  sd s9, 24(sp)
  sd s10, 16(sp)
  sd s11, 8(sp)
  addi s0, sp, 112
  mv s1, sp
  addi sp, sp, -48
  addi t5, s1, -8
  sd a0, 0(t5)
  addi t5, s1, -16
  sd a1, 0(t5)
  j .L_ocore_riscv64_0_bb0
.L_ocore_riscv64_0_bb0:
  addi t1, s1, -8
  ld t0, 0(t1)
  addi t5, s1, -24
  sd t0, 0(t5)
  addi t1, s1, -16
  ld t0, 0(t1)
  addi t5, s1, -32
  sd t0, 0(t5)
  addi t5, s1, -24
  ld t0, 0(t5)
  addi t5, s1, -32
  ld t1, 0(t5)
  add t0, t0, t1
  addi t5, s1, -40
  sd t0, 0(t5)
  addi t5, s1, -40
  ld a0, 0(t5)
  mv sp, s0
  ld ra, -8(sp)
  ld s1, -24(sp)
  ld s2, -32(sp)
  ld s3, -40(sp)
  ld s4, -48(sp)
  ld s5, -56(sp)
  ld s6, -64(sp)
  ld s7, -72(sp)
  ld s8, -80(sp)
  ld s9, -88(sp)
  ld s10, -96(sp)
  ld s11, -104(sp)
  ld s0, -16(sp)
  ret
.size _O_smoke__addition__add, .-_O_smoke__addition__add
.option pop
.section .note.GNU-stack,"",@progbits
