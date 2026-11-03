OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
PHDRS { text PT_LOAD FILEHDR PHDRS FLAGS(5); rodata PT_LOAD FLAGS(4); data PT_LOAD FLAGS(6); stack PT_GNU_STACK FLAGS(6); }
SECTIONS {
 . = 0x02001000;
 .text : { *(.text .text.*) } :text
 . = ALIGN(4K);
 .rodata : { *(.rodata .rodata.*) } :rodata
 . = ALIGN(4K);
 .data : { *(.data .data.*) } :data
 .bss : { *(.bss .bss.*) *(COMMON) } :data
 ASSERT(. <= 0x02100000, "fixture exceeds declared static load window")
 /DISCARD/ : { *(.comment) *(.eh_frame) *(.note*) }
}
