# Original Rust scalar implementations on the native RV supervisor

```bash
python3 scripts/check_ocore_riscv64_rust_bridge.py \
  --ocorec "$PWD/target/debug/ocorec" \
  --qemu /path/to/qemu-system-riscv64 \
  --opensbi /path/to/opensbi/generic/fw_dynamic.bin
```

This separate gate compiles the unchanged
`tests/fixtures/ocore_import_scalar.rs` with exact rustc 1.97.1, commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452`, for its installed
`riscv64imac-unknown-none-elf` core target. Rust emits LLVM IR only. The parser is
the matching LLVM 22.1.6 shared library from that Rust toolchain, pinned by its
actual SHA-256. Whole-unit import requires all seven original definitions, no
globals or external implementation declarations, preserved target/DataLayout,
LP64, and a verification receipt bound to the exact NativeModule bytes.

O-core emits the Rust implementation assembly. Clang is used as an assembler,
not as a replacement compiler for the functions under test. Original LLVM and
independently verified NativeModule emission must produce identical assembly and
object bytes. The linked image contains only the architectural assembly, the
baseline O-core bootstrap, the independent O-core oracle, and the seven imported
Rust implementations. There is no Rust machine-code object from rustc in that
image, and no Linux guest or hosted syscall carrier.

`rust_import_probe.oc` exports `__wrap_rv_boot_main`. The ELF linker option
`--wrap=rv_boot_main` makes the existing architecture entry invoke this wrapper.
After the scalar checks, its call to `__real_rv_boot_main` runs the unchanged
architectural bootstrap, including FP/TLS/trap/timer checks. Baseline source and
the original Rust fixture remain unchanged.

The compiled unsigned oracle checks seven functions over 4,096 deterministic
pseudo-random vectors and 144 edge/shift combinations: 29,680 comparisons. Cases
cover signed comparison represented as unsigned bits, signed/unsigned narrow
casts, high-bit u32 arguments/results, legal wrapped shifts, loops, direct calls,
and twelve full-width arguments with four values passed on the stack. A separate
Python bit-vector calculation must match the exact emitted digest and case count.

Two negative controls must fail the first compiled helper assertion. One builds
a temporary corrupted oracle; the other alters the original imported object's
helper entry bytes to return zero, while preserving the original object and all
source/IR bytes. Their object/image digests, byte mutation, failure transcripts,
and exact assertion code are retained alongside the positive run.

`target/ocore-riscv64-rust-bridge/receipt.json` binds source hashes, Rust/core/LLVM
and O-core tools, compiler flags, original/imported IR, structural verification,
assembly/objects, linked images, ELF symbol/load inventory, and lossless command
stdout/stderr. Changes to tools or sources during execution invalidate the proof.

This is original Rust scalar frontend lowering executed on the native supervisor
foundation. It does not qualify Rust core/alloc/std as complete implementations,
the native rustc/Cargo runtime, unwinding, protected userspace, or the full
CPython/Rust/OpenJDK platform gate. The full runtime completion flags remain false.
