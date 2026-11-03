// Build VM platform initialization only. This is not an O-core monitor.
// The original non-Linux uImage entry needs x0 pointing at its device tree.
.text
.global _start
_start:
    mov x0, #9
    msr ICC_SRE_EL2, x0
    isb
    mov x0, #1
    msr ICC_SRE_EL1, x0
    isb
    mov x0, #3
    msr cnthctl_el2, x0
    msr cntvoff_el2, xzr
    mov x0, #0x40000000
    mov x1, #0x40100000
    br x1
