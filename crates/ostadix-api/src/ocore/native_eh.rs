//! Explicit Itanium/DWARF exception profile for imported native modules.
//!
//! A source `i32 (...)` personality declaration is metadata, not permission to
//! emit arbitrary variadic calls. The unwinder calls it through the specified
//! five-argument C callback ABI. Any ordinary address use removes that special
//! classification, including uses in cold code and initializer relocations.

use std::collections::BTreeSet;

use super::native_ir::*;
use super::Diagnostic;

fn error(function: &Function, message: &str) -> Diagnostic {
    error_diagnostic(format!("function {:?}: {message}", function.name))
}

fn named_pointer(operand: &Operand) -> Option<(TypeId, &str)> {
    match operand {
        Operand::Symbol { ty, name }
        | Operand::SymbolOffset {
            ty,
            name,
            addend: 0,
        } => Some((*ty, name)),
        _ => None,
    }
}

fn is_int(module: &NativeModule, ty: TypeId, bits: u16) -> bool {
    matches!(module.types.get(ty), Some(Type::Int { bits: actual }) if *actual == bits)
}

fn is_pointer(module: &NativeModule, ty: TypeId) -> bool {
    matches!(
        module.types.get(ty),
        Some(Type::Pointer { address_space: 0 })
    )
}

fn metadata_signature(module: &NativeModule, function: &Function) -> bool {
    let signature = &function.signature;
    function.entry.is_none()
        && function.blocks.is_empty()
        && function.intrinsic.is_none()
        && !function.name.starts_with("llvm.")
        && function.linkage == "external"
        && signature.abi == "c"
        && signature.variadic
        && signature.params.is_empty()
        && is_int(module, signature.result, 32)
        && signature.param_attributes.is_empty()
        && signature.result_attributes.is_empty()
        && signature.return_storage.is_none()
}

fn record_symbols(operand: &Operand, names: &mut BTreeSet<String>) {
    let mut pending = vec![operand];
    while let Some(operand) = pending.pop() {
        match operand {
            Operand::Symbol { name, .. } | Operand::SymbolOffset { name, .. } => {
                names.insert(name.clone());
            }
            Operand::Aggregate { elements, .. } => pending.extend(elements),
            _ => {}
        }
    }
}

/// Source declarations used exclusively as EH personalities. This scans the
/// complete module, without reachability filtering or assumptions from names.
pub fn metadata_personality_declarations(module: &NativeModule) -> BTreeSet<String> {
    let mut personalities = BTreeSet::new();
    let mut ordinary = BTreeSet::new();
    for function in &module.functions {
        if let Some(eh) = &function.exception_handling {
            if let Some((_, name)) = named_pointer(&eh.personality) {
                personalities.insert(name.to_owned());
            }
        }
        for block in &function.blocks {
            for instruction in &block.instructions {
                for operand in super::native_verify::instruction_operands(&instruction.operation) {
                    record_symbols(operand, &mut ordinary);
                }
                if let Operation::Phi { incoming } = &instruction.operation {
                    for incoming in incoming {
                        record_symbols(&incoming.value, &mut ordinary);
                    }
                }
            }
            for operand in super::native_verify::terminator_operands(&block.terminator) {
                record_symbols(operand, &mut ordinary);
            }
        }
    }
    for global in &module.globals {
        if let Some(initializer) = &global.initializer {
            ordinary.extend(initializer.relocations.iter().map(|r| r.symbol.clone()));
        }
    }
    for alias in &module.aliases {
        ordinary.insert(alias.aliasee.clone());
    }
    module
        .functions
        .iter()
        .filter(|function| {
            personalities.contains(&function.name)
                && !ordinary.contains(&function.name)
                && metadata_signature(module, function)
        })
        .map(|function| function.name.clone())
        .collect()
}

/// The source landing-pad/resume pair uses this unpacked aggregate shape.
pub fn is_exception_aggregate(module: &NativeModule, ty: TypeId) -> bool {
    matches!(module.types.get(ty), Some(Type::Struct { fields, packed: false })
        if fields.len() == 2 && is_pointer(module, fields[0]) && is_int(module, fields[1], 32))
}

/// A catch/type-id table entry is either catch-all null or an unchanged,
/// zero-offset source GlobalValue identity. Literal addresses, SSA values and
/// undef/poison cannot be converted into type table entries.
pub fn validate_typeinfo(module: &NativeModule, operand: &Operand) -> Result<(), Diagnostic> {
    let (ty, name) = match operand {
        Operand::Null { ty } => (*ty, None),
        operand => match named_pointer(operand) {
            Some((ty, name)) => (ty, Some(name)),
            None => {
                return Err(error_diagnostic(
                    "exception typeinfo requires null or a named zero-offset AS0 pointer",
                ));
            }
        },
    };
    if !is_pointer(module, ty) {
        return Err(error_diagnostic(
            "exception typeinfo requires an address-space-zero pointer",
        ));
    }
    if let Some(name) = name {
        let root = module
            .aliases
            .iter()
            .find(|alias| alias.name == name)
            .map_or(name, |alias| alias.aliasee.as_str());
        if root == "llvm.eh.catch.all.value" {
            return Err(error_diagnostic(
                "llvm.eh.catch.all.value requires verified initializer normalization",
            ));
        }
        if let Some(function) = module.functions.iter().find(|f| f.name == root) {
            if function.intrinsic.is_some() || function.name.starts_with("llvm.") {
                return Err(error_diagnostic("intrinsic cannot be exception typeinfo"));
            }
        } else if let Some(global) = module.globals.iter().find(|g| g.name == root) {
            if global.thread_local {
                return Err(error_diagnostic("TLS exception typeinfo is unsupported"));
            }
        } else {
            return Err(error_diagnostic(format!(
                "unknown exception typeinfo symbol {name:?}"
            )));
        }
    }
    Ok(())
}

/// Validate a function's retained personality against the explicit unwinder
/// callback ABI, without modifying ordinary call signatures or function flags.
pub fn validate_function_profile(
    module: &NativeModule,
    function: &Function,
    metadata_personalities: &BTreeSet<String>,
) -> Result<(), Diagnostic> {
    let Some(eh) = &function.exception_handling else {
        return Ok(());
    };
    if function.entry.is_none() {
        return Err(error(
            function,
            "exception personality on a declaration is unsupported",
        ));
    }
    let Some((ty, name)) = named_pointer(&eh.personality) else {
        return Err(error(
            function,
            "personality requires a named zero-offset source function",
        ));
    };
    if !is_pointer(module, ty) && !matches!(module.types.get(ty), Some(Type::Function { .. })) {
        return Err(error(
            function,
            "personality requires an AS0 pointer or function value type",
        ));
    }
    let root = module
        .aliases
        .iter()
        .find(|alias| alias.name == name)
        .map_or(name, |alias| alias.aliasee.as_str());
    let personality = module
        .functions
        .iter()
        .find(|f| f.name == root)
        .ok_or_else(|| {
            error(
                function,
                "personality must resolve to an included source function",
            )
        })?;
    if personality.intrinsic.is_some() || personality.name.starts_with("llvm.") {
        return Err(error(
            function,
            "intrinsic cannot be an exception personality",
        ));
    }
    if metadata_personalities.contains(name) {
        return Ok(());
    }
    let signature = &personality.signature;
    let valid = signature.abi == "c"
        && !signature.variadic
        && is_int(module, signature.result, 32)
        && signature.return_storage.is_none()
        && signature.params.len() == 5
        && is_int(module, signature.params[0], 32)
        && is_int(module, signature.params[1], 32)
        && is_int(module, signature.params[2], 64)
        && is_pointer(module, signature.params[3])
        && is_pointer(module, signature.params[4]);
    if !valid {
        return Err(error(function, "personality must have the five-argument C unwinder callback ABI; metadata-only i32(...) declarations cannot escape into ordinary uses"));
    }
    Ok(())
}

/// Resume has one explicit generated platform interface. A same-name source
/// symbol may supply that interface only with its genuine, compatible ABI;
/// local storage/aliases must not silently hijack an unwinder operation.
pub fn validate_resume_interface(module: &NativeModule) -> Result<(), Diagnostic> {
    if !module
        .functions
        .iter()
        .flat_map(|f| &f.blocks)
        .any(|block| matches!(block.terminator, Terminator::Resume { .. }))
    {
        return Ok(());
    }
    if module.globals.iter().any(|g| g.name == "_Unwind_Resume")
        || module.aliases.iter().any(|a| a.name == "_Unwind_Resume")
    {
        return Err(error_diagnostic(
            "_Unwind_Resume source symbol must be a compatible external function",
        ));
    }
    if let Some(function) = module.functions.iter().find(|f| f.name == "_Unwind_Resume") {
        let signature = &function.signature;
        if function.linkage != "external"
            || function.visibility != Visibility::Default
            || function.intrinsic.is_some()
            || signature.abi != "c"
            || signature.variadic
            || !matches!(module.types.get(signature.result), Some(Type::Void))
            || signature.params.len() != 1
            || !is_pointer(module, signature.params[0])
            || signature.param_attributes.iter().any(|a| !a.is_empty())
            || !signature.result_attributes.is_empty()
            || signature.return_storage.is_some()
        {
            return Err(error(function, "_Unwind_Resume requires the external C void(ptrAS0) interface without ABI attributes"));
        }
    }
    Ok(())
}
