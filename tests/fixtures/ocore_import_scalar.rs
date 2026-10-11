//! Real Rust frontend probe, not a Rust stdlib/rustc completion witness.
//!
//! The runner uses edition 2024, opt-level=1, panic=abort, overflow-checks=off,
//! relocation-model=static, and disables vectorization/unwind tables. Each ISA
//! gets freshly generated LLVM IR for its actual installed Rust core target.
#![no_std]

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rust_scalar_helper(a: u64, b: u64) -> u64 {
    a.wrapping_mul(17).wrapping_add(b)
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_scalar_mix(a: u64, b: u64, shift: u32) -> u64 {
    let count = shift & 63;
    let sum = a.wrapping_add(b);
    let difference = a.wrapping_sub(b);
    let product = a.wrapping_mul(b);
    rust_scalar_helper(sum ^ difference ^ product, b)
        ^ a.wrapping_shl(count)
        ^ a.wrapping_shr(count)
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_scalar_choose(a: i64, b: i64) -> u64 {
    if a < b {
        a.wrapping_sub(b) as u64
    } else {
        a.wrapping_add(b) as u64
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_scalar_narrow(a: u64) -> u64 {
    (a as i8 as i64 as u64)
        .wrapping_add(a as u8 as u64)
        .wrapping_add((a >> 8) as i16 as i64 as u64)
        .wrapping_add((a >> 24) as u16 as u64)
        .wrapping_add((a >> 32) as i32 as i64 as u64)
        .wrapping_add((a >> 32) as u32 as u64)
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_scalar_loop(seed: u64, count: u32) -> u64 {
    let mut value = seed;
    let mut index = 0_u32;
    while index < (count & 31) {
        value = value.wrapping_mul(33).wrapping_add(index as u64);
        index += 1;
    }
    value
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_scalar_u32(value: u32, shift: u32) -> u32 {
    value.wrapping_mul(0x9e37_79b9).wrapping_add(0xf123_4567)
        ^ value.wrapping_shr(shift)
        ^ value.wrapping_shl(shift)
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_scalar_many(
    a: u64, b: u64, c: u64, d: u64, e: u64, f: u64,
    g: u64, h: u64, i: u64, j: u64, k: u64, l: u64,
) -> u64 {
    a.wrapping_add(2_u64.wrapping_mul(b))
        .wrapping_add(3_u64.wrapping_mul(c))
        .wrapping_add(4_u64.wrapping_mul(d))
        .wrapping_add(5_u64.wrapping_mul(e))
        .wrapping_add(6_u64.wrapping_mul(f))
        .wrapping_add(7_u64.wrapping_mul(g))
        .wrapping_add(8_u64.wrapping_mul(h))
        .wrapping_add(9_u64.wrapping_mul(i))
        .wrapping_add(10_u64.wrapping_mul(j))
        .wrapping_add(11_u64.wrapping_mul(k))
        .wrapping_add(12_u64.wrapping_mul(l))
}
