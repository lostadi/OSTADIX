# Native RV64 supervisor bootstrap ABI, version 1

This image is an architectural foundation for OSTADIX. The semantic core is
`ocore/runtime/riscv64/bootstrap.oc`, compiled by the RV64 O-core backend. The
image runs directly in supervisor mode on QEMU `virt`; OpenSBI remains in machine
mode. There is no guest Linux kernel, root filesystem, or hosted runtime.

The current profile is one RV64GC hart, LP64 integer calling convention, 128 MiB
RAM, and `satp=Bare`. Entry is `0x80200000`. OpenSBI passes the hart ID in `a0` and
the firmware device-tree address in `a1`. The bootstrap validates the DTB header
but does not yet discover arbitrary devices or memory layouts. It uses the SBI
legacy console, TIME, and SRST interfaces. Kernel and private trap stacks are
separate 64 KiB regions aligned to 16 bytes. These are the tested machine
configuration, not a bound on compiler graphs or eventual runtime size.

## TrapFrameV1

The frame is 576 bytes, naturally aligned to 16 bytes. All offsets are bytes.

| Offset | Field | Meaning |
| --- | --- | --- |
| 0 | `x[32]` | Exact XLEN64 bits of x0 through x31; x0 is zero, x2 is interrupted sp, x4 is interrupted tp |
| 256 | `sepc` | Resume PC; the compiled handler may update it |
| 264 | `sstatus` | Status captured after hardware trap entry, restored before `sret` |
| 272 | `scause` | Interrupt flag and architectural cause |
| 280 | `stval` | Architectural trap value |
| 288 | `fcsr` | Exact fflags/frm bits when FP is active; zero when FS is Off |
| 296 | reserved | Zero |
| 304 | `f[32]` | Exact FLEN64 bits of f0 through f31 when FP is active |
| 560 | `fp_present` | 0 when saved sstatus.FS is Off, otherwise 1 |
| 568 | reserved2 | Zero |

`sscratch` contains the private trap-stack top outside a trap. Entry swaps sp
with sscratch before changing any other register, records the interrupted sp,
and sets sscratch to zero while the frame is live. Nested synchronous faults
halt with failure instead of overwriting the active frame. Supervisor interrupts
remain masked during the callback. Direct stvec and all probe ebreak instructions
are word aligned and use 32-bit encodings.

Every integer register is saved, including gp and tp. If FS is active, all 32
floating-point registers and fcsr are saved and restored. When FS is Off, the
trap path executes no floating-point instruction. The handler switches to the
private kernel tp record after saving interrupted tp and restores that base on
return. Two static TLS records demonstrate per-context base switching; there is
no dynamic TLS allocation, ELF TLS loader, or userspace thread implementation.
The integer LP64 ABI does not imply floating-point argument/return lowering.

The actual ebreak/sret probes seed each register with a distinct value. The trap
path deliberately overwrites all GPRs except sp and every active FP register
before restoration. Compiled O-core checks both the captured frame and the
post-return register snapshot, the ABI offsets, stack separation/alignment,
fcsr, and the interrupted/private tp bases. The timer test schedules a real SBI
TIME event, receives supervisor timer cause 5, clears it through TIME, and resumes
the waiting code. A second snapshot checks all 32 FP registers, fcsr, and kernel
tp after that asynchronous interrupt. Every positive marker and failure code is selected by compiled
O-core, rather than an assembly transcript.

## Reproduce and inspect the proof

```bash
python3 scripts/check_ocore_riscv64_boot.py \
  --ocorec "$PWD/target/debug/ocorec" \
  --qemu /path/to/qemu-system-riscv64 \
  --opensbi /path/to/opensbi/generic/fw_dynamic.bin
```

The script can discover installed tools and scoped packages under
`/tmp/ostadix-riscv-tools-*/root`. On Ubuntu 26.04 the emulator package is
`qemu-system-riscv` (not `qemu-system-misc`). If it is missing, download and
extract packages into a task directory without installing them globally:

```bash
rv_tools=$(mktemp -d /tmp/ostadix-riscv-tools-XXXXXX)
cd "$rv_tools"
apt-get download qemu-system-riscv opensbi
mkdir root
for package in ./*.deb; do dpkg-deb --extract "$package" root; done
```

Run the script from the checkout, passing the extracted executable and firmware.
Its receipt records tool paths/versions/digests, source digests, complete command
arrays, ELF entry/load/symbol inventory, object/image digests, and lossless stdout
and stderr transcripts. It verifies both required compiled function definitions
and the absence of dynamic loader segments or unresolved symbols. Tool or source
changes during execution invalidate the proof. Default negative controls build
temporary corrupted images that omit f17 or tp restoration and require the
corresponding compiled assertion to fail. `--skip-negative-controls` is explicitly
recorded as an omission.

This proof does not establish protected userspace, address-space switching,
process/thread scheduling, SMP, dynamic TLS, POSIX, networking/filesystems,
unwinding, floating-point expression lowering, code publication, or complete
CPython/Rust/OpenJDK execution. Those platform and compiler gates remain required.
No vector context is implemented; this profile does not enable the V extension.

Architectural references: [RISC-V supervisor specification](https://docs.riscv.org/reference/isa/priv/supervisor.html),
[floating-point state in the privileged specification](https://docs.riscv.org/reference/isa/priv/machine.html),
[SBI TIME](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-time.adoc),
[SBI SRST](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-sys-reset.adoc),
and [QEMU virt](https://www.qemu.org/docs/master/system/riscv/virt.html).
