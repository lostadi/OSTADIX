ENTRY(_start)
SECTIONS {
    __stack_bottom = 0x401f1000;
    __stack_top = 0x40200000;
    . = 0x40000000;
    .text : { KEEP(*(.text.entry)) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    . = ALIGN(8);
    __bss_start = .;
    .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
    . = ALIGN(8);
    __bss_end = .;
    ASSERT(__bss_end <= 0x40100000, "native fixture exceeds kernel window")
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
