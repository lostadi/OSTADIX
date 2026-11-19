/* Generated helpers deliberately lack execute permission. Explicitly placed
 * caller checks must still return or trap in their own executable domain. */
ENTRY(_start)
PHDRS {
  helpers PT_LOAD FLAGS(4);
  code PT_LOAD FLAGS(5);
  data PT_LOAD FLAGS(6);
  stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
  . = 0x00200000;
  .bounds_helpers : { *(.text.ocore_fn.__array_bounds) } :helpers
  . = ALIGN(0x1000);
  .text : { *(.text .text.*) *(.rodata .rodata.*) } :code
  . = ALIGN(0x1000);
  .data : { *(.data .data.*) *(.bss .bss.*) *(COMMON) } :data
  /DISCARD/ : { *(.comment .eh_frame .note*) }
}
