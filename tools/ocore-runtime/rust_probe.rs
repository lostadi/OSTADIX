//! Small real Rust frontend/import boundary probe; not a stdlib/compiler witness.
#![no_std]

#[no_mangle]
pub extern "C" fn ocore_rust_add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

#[no_mangle]
pub extern "C" fn ocore_rust_choose(a: i64, b: i64) -> i64 {
    if a < b {
        a.wrapping_sub(b)
    } else {
        a.wrapping_add(b)
    }
}

#[no_mangle]
pub extern "C" fn ocore_rust_bits(a: u64, b: u64) -> u64 {
    a.wrapping_shl((b & 63) as u32) ^ b
}
