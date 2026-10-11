OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS {
    . = 0x80200000;
    __image_start = .;
    .text.boot : ALIGN(16) { KEEP(*(.text.boot)) }
    .text : ALIGN(16) { *(.text) *(.text.*) }
    .rodata : ALIGN(16) { *(.rodata) *(.rodata.*) }
    .data : ALIGN(16) {
        __global_pointer$ = . + 0x800;
        *(.data) *(.data.*) *(.sdata) *(.sdata.*)
    }
    .bss (NOLOAD) : ALIGN(16) {
        __bss_start = .;
        *(.bss) *(.bss.*) *(.sbss) *(.sbss.*) *(COMMON)
        . = ALIGN(16);
        rv_kernel_stack_bottom = .;
        . += 0x10000;
        rv_kernel_stack_top = .;
        rv_trap_stack_bottom = .;
        . += 0x10000;
        rv_trap_stack_top = .;
        __bss_end = .;
    }
    __image_end = .;
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}

ASSERT((_start & 3) == 0, "RISC-V supervisor entry must be word aligned")
ASSERT((rv_trap_entry & 3) == 0, "RISC-V direct stvec must be word aligned")
ASSERT((rv_kernel_stack_top & 15) == 0, "RV64 C ABI stack alignment")
ASSERT((rv_trap_stack_top & 15) == 0, "RV64 trap stack alignment")
