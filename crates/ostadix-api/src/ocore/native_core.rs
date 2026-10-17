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
#[path = "native_ir.rs"]
pub mod native_ir;
#[path = "native_map.rs"]
pub mod native_map;
#[path = "native_verify.rs"]
pub mod native_verify;
