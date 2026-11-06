.intel_syntax noprefix
.code16
.text
.globl _start
_start:
 cli
 xor ax,ax
 mov ds,ax
 mov ss,ax
 mov sp,0x7c00
 sti
 mov ax,0x0800
 mov es,ax
 xor bx,bx
 mov ax,0x0208
 mov cx,2
 xor dx,dx
 int 0x13
 jc failed
 .byte 0xea
 .word 0
 .word 0x0800
failed:
 mov dx,0xf4
 mov ax,0x11
 out dx,ax
 cli
 hlt
 jmp failed
.org 510
.word 0xaa55
