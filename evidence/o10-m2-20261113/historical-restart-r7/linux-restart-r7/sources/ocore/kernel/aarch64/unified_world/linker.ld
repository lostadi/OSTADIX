OUTPUT_ARCH(aarch64)
ENTRY(_start)
SECTIONS {
    . = 0x40080000;
    .text : { KEEP(*(.text.boot)) *(.text*) }
    . = ALIGN(2048);
    .vectors : { KEEP(*(.vectors)) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    . = ALIGN(4096);
    __bss_start = .;
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
    __bss_end = .;
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
    ASSERT(__bss_end < 0x41000000, "unified monitor exceeds reserved native region")
}
