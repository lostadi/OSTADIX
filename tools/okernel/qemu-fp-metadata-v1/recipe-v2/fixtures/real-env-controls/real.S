.intel_syntax noprefix
.code16
.text
.globl real_entry
real_entry:
 cli
 mov ax,0x8000
 mov ss,ax
 mov sp,0xf000
 mov ax,0x9000
 mov ds,ax
 mov es,ax
 xor ax,ax
 mov di,0x1000
 mov cx,0x1100
 rep stosw
 mov ax,cs
 mov [0x1000],ax
 mov ax,ds
 mov [0x1002],ax
 mov ax,ss
 mov [0x1004],ax
 mov eax,cr0
 or eax,0x22
 and eax,0xfffffff3
 mov cr0,eax
 mov [0x1008],eax
 mov eax,cr4
 or eax,0x600
 mov cr4,eax
 mov [0x100c],eax
 mov word ptr [0x1010],offset real_fault
 mov dword ptr [0x1234],0
 mov dword ptr [0x1238],0x3ff80000
 mov dword ptr [0x1240],0
 mov dword ptr [0x1244],0
 mov word ptr [0x1300],0x037b
 mov dword ptr [0x1310],0x5f80
 mov dword ptr [0x1320],0x12345678
 mov dword ptr [0x1324],0x9abcdef0
 mov dword ptr [0x1328],0x76543210
 mov dword ptr [0x132c],0xfedcba98
 fninit
 ldmxcsr [0x1310]
 movdqu xmm0,[0x1320]
 fld qword ptr [0x1234]
 fldcw [0x1300]
.globl real_fault
real_fault:
 fdiv qword ptr [0x1240]
 fxsave [0x2000]
 .byte 0x66
 fnstenv [0x2200]
 fnstenv [0x2240]
 .byte 0x66
 fnsave [0x2a00]
 fxsave [0x2b00]
 .byte 0x66
 frstor [0x2a00]
 fxsave [0x2d00]
 fninit
 .byte 0x66
 fldenv [0x2200]
 fxsave [0x2400]
 .byte 0x66
 fnstenv [0x2600]
 fninit
 fldenv [0x2240]
 fxsave [0x2800]
 fninit
 mov ax,cs
 mov ds,ax
 call serial_init
 mov si,offset header
 mov cx,8
 call emit_code
 mov si,0x1000
 mov cx,32
 call emit_data
 mov si,0x2000
 mov cx,512
 call emit_data
 mov si,0x2200
 mov cx,28
 call emit_data
 mov si,0x2240
 mov cx,14
 call emit_data
 mov si,0x2400
 mov cx,512
 call emit_data
 mov si,0x2600
 mov cx,28
 call emit_data
 mov si,0x2800
 mov cx,512
 call emit_data
 mov si,0x2a00
 mov cx,108
 call emit_data
 mov si,0x2b00
 mov cx,512
 call emit_data
 mov si,0x2d00
 mov cx,512
 call emit_data
 mov si,offset footer
 mov cx,8
 call emit_code
 mov dx,0xf4
 mov eax,0x10
 out dx,eax
halt:
 cli
 hlt
 jmp halt
emit_code:
 lodsb
 call putc
 loop emit_code
 ret
emit_data:
 mov al,es:[si]
 inc si
 call putc
 loop emit_data
 ret
putc:
 push ax
 push dx
 mov ah,al
 mov dx,0x3fd
1: in al,dx
 test al,0x20
 jz 1b
 mov al,ah
 mov dx,0x3f8
 out dx,al
 pop dx
 pop ax
 ret
serial_init:
 mov dx,0x3f9
 xor al,al
 out dx,al
 mov dx,0x3fb
 mov al,0x80
 out dx,al
 mov dx,0x3f8
 mov al,1
 out dx,al
 mov dx,0x3f9
 xor al,al
 out dx,al
 mov dx,0x3fb
 mov al,3
 out dx,al
 mov dx,0x3fa
 mov al,0xc7
 out dx,al
 mov dx,0x3fc
 mov al,0x0b
 out dx,al
 ret
header: .ascii "FPREAL01"
footer: .ascii "FPREALOK"
