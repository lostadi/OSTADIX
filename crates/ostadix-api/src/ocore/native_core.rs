// Native computation core shared verbatim by the engine and generated runtimes.
// Frontend parsing, LLVM importing and the filesystem compiler driver stay outside.

#[path = "common.rs"]
mod common;
pub use common::{Diagnostic, Span, Target};

#[path = "native_abi.rs"]
pub mod native_abi;
#[path = "native_codegen.rs"]
pub mod native_codegen;
#[path = "native_eh.rs"]
pub mod native_eh;
#[path = "native_exception_codegen.rs"]
mod native_exception_codegen;
#[path = "native_floating_helpers.rs"]
pub mod native_floating_helpers;
#[path = "native_platform.rs"]
pub mod native_platform;
#[path = "native_ir.rs"]
pub mod native_ir;
#[path = "native_machine_ir.rs"]
pub mod native_machine_ir;
#[path = "native_machine_verify.rs"]
pub mod native_machine_verify;
#[path = "native_machine_asm_reader.rs"]
pub mod native_machine_asm_reader;
#[path = "native_machine_unit.rs"]
pub mod native_machine_unit;
#[path = "native_machine_lift.rs"]
pub mod native_machine_lift;
#[path = "native_machine_lift_dispatch.rs"]
pub mod native_machine_lift_dispatch;
#[path = "native_machine_lift_x86_64.rs"]
pub mod native_machine_lift_x86_64;
#[path = "native_machine_lift_aarch64.rs"]
pub mod native_machine_lift_aarch64;
#[path = "native_machine_lift_rv64.rs"]
pub mod native_machine_lift_rv64;
#[path = "native_map.rs"]
pub mod native_map;
#[path = "native_nonlocal.rs"]
pub mod native_nonlocal;
#[path = "native_verify.rs"]
pub mod native_verify;

#[path = "native_machine_emit.rs"]
pub mod native_machine_emit;
#[path = "native_machine_emit_rv64.rs"]
mod native_machine_emit_rv64;
