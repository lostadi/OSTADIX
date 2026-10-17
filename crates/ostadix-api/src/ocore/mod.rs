//! Native O-core compiler pipeline.
//!
//! This module is intentionally independent of `crate::ir`: orchestration OIR
//! models backend execution, while O-core HIR/MIR model statically typed native
//! computation.

pub mod ast;
pub mod boot_info;
pub mod capability_bridge;
pub mod codegen;
pub mod codegen_aarch64;
pub mod codegen_riscv64;
pub mod driver;
pub mod hir;
pub mod lexer;
pub mod mir;
pub mod native_interpret;
pub mod parser;
pub mod typeck;

pub use driver::{
    compile, compile_with_function_sections, CompileOptions, CompileOutput, EmitKind,
};

include!("native_core.rs");
