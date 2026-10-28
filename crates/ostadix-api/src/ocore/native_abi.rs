//! Shared placement of original LLVM C/fastcc integer aggregate values and
//! scalar integer/AS0-pointer C variadic arguments.
//!
//! These are LLVM IR lowering rules, after the source frontend has performed
//! its language ABI classification. They do not reclassify a C source struct.
use std::collections::{BTreeMap, HashSet};

use super::native_ir::{error_diagnostic, NativeModule, Signature, Type, TypeId};
use super::native_verify::{type_layouts, value_leaf_layouts};
use super::Diagnostic;
use super::Target;

/// Full general-register names; emitters select the narrow spelling from
/// `AbiPart::location_bits`. Stack offsets start at the caller's argument area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiLocation {
    Register(&'static str),
    Stack { offset: u64 },
    IndirectResult { offset: u64 },
}

/// Required source extension to the location width. `Any` permits a chosen
/// deterministic refinement of unspecified high bits, not a signedness claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extension {
    None,
    Any,
    Sign,
    Zero,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbiPart {
    pub param: Option<usize>,
    pub leaf: usize,
    pub ty: TypeId,
    pub offset: u64,
    pub location: AbiLocation,
    pub extension: Extension,
    pub location_bits: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnStoragePlan {
    pub explicit_param: Option<usize>,
    pub ty: TypeId,
    pub size: u64,
    pub alignment: u64,
    pub pointer_location: AbiLocation,
    pub pointer_return: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbiPlan {
    pub args: Vec<AbiPart>,
    pub results: Vec<AbiPart>,
    pub storage: Option<ReturnStoragePlan>,
    pub stack_bytes: u64,
    pub stack_alignment: u64,
    pub variadic: Option<VariadicPlan>,
}

/// State after the named arguments, before any unnamed arguments or final
/// caller stack padding. Hidden result pointers consume a GP slot except for
/// AAPCS64's dedicated x8. The callee must preserve unknown incoming FP/SIMD
/// registers too when a va_list can escape to a foreign consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariadicPlan {
    pub named_gp: usize,
    pub named_stack_bytes: u64,
    pub gp_registers: &'static [&'static str],
    /// SysV %al's vector-register upper bound. This integer-only profile uses
    /// no vector argument registers; it does not describe the callee save area.
    pub vector_register_count: u8,
}

// Integer tails use the ordinary GP allocation on all supported profiles:
// https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex
// https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
// https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#_integer_calling_convention
// Wider/aligned RISC-V register pairs, FP arguments, and unnamed aggregates
// require additional classification and are rejected before leaf expansion.

/// Borrow the emitter's once-per-module original DataLayout and leaf caches.
/// Planning calls does not parse the layout or walk the complete type graph.
pub struct AbiContext<'a> {
    module: &'a NativeModule,
    target: Target,
    leaves: &'a BTreeMap<TypeId, Vec<(TypeId, u64)>>,
    layouts: &'a [Option<(u64, u64)>],
    preferred_ints: BTreeMap<u64, u64>,
    preferred_pointer: u64,
    preferred_struct: u64,
    source_stack_alignment: u64,
}

impl<'a> AbiContext<'a> {
    pub fn new(
        module: &'a NativeModule,
        target: Target,
        leaf_layouts: &'a BTreeMap<TypeId, Vec<(TypeId, u64)>>,
        type_layouts: &'a [Option<(u64, u64)>],
    ) -> Result<Self, Diagnostic> {
        profile(module, target)?;
        if type_layouts.len() != module.types.len() {
            return Err(fail(
                "allocation cache does not match original type inventory",
            ));
        }
        // DataLayout.cpp DefaultIntSpecs and StructPrefAlignment, LLVM 22.
        // Only preferred alignment is decoded here; allocation sizes and ABI
        // alignments come exclusively from the independent verifier's cache.
        let mut preferred_ints: BTreeMap<u64, u64> = [(8, 1), (16, 2), (32, 4), (64, 8)].into();
        let mut preferred_pointer = 8;
        let mut preferred_struct = 8;
        let mut source_stack_alignment = 16;
        for field in module.target.data_layout.split('-') {
            let parts: Vec<_> = field.split(':').collect();
            let bytes = |value: &str| -> Result<u64, Diagnostic> {
                let bits = value
                    .parse::<u64>()
                    .map_err(|_| fail("malformed preferred DataLayout alignment"))?;
                if bits == 0 || bits % 8 != 0 || !(bits / 8).is_power_of_two() {
                    return Err(fail(
                        "preferred alignment must be a positive byte power of two",
                    ));
                }
                Ok(bits / 8)
            };
            if let Some(width) = parts[0].strip_prefix('i') {
                if !(2..=3).contains(&parts.len()) {
                    return Err(fail("malformed integer DataLayout alignment"));
                }
                let width = width
                    .parse::<u64>()
                    .map_err(|_| fail("malformed integer DataLayout width"))?;
                preferred_ints.insert(width, bytes(parts.last().unwrap())?);
            } else if parts[0] == "p" || parts[0] == "p0" {
                if !(3..=5).contains(&parts.len()) || parts[1] != "64" {
                    return Err(fail(
                        "only the integral 64-bit AS0 pointer profile is supported",
                    ));
                }
                preferred_pointer = bytes(parts.get(3).unwrap_or(&parts[2]))?;
            } else if parts[0] == "a" || parts[0] == "a0" {
                if !(2..=3).contains(&parts.len()) {
                    return Err(fail("malformed aggregate DataLayout alignment"));
                }
                preferred_struct = if parts.len() == 2 && parts[1] == "0" {
                    1
                } else {
                    bytes(parts.last().unwrap())?
                };
            } else if let Some(bits) = field.strip_prefix('S') {
                source_stack_alignment = bytes(bits)?;
                if source_stack_alignment > 16 {
                    return Err(fail("over-aligned incoming stack ABI requires another supported execution profile"));
                }
            }
        }
        Ok(Self {
            module,
            target,
            leaves: leaf_layouts,
            layouts: type_layouts,
            preferred_ints,
            preferred_pointer,
            preferred_struct,
            source_stack_alignment,
        })
    }

    pub fn plan(&self, signature: &Signature) -> Result<AbiPlan, Diagnostic> {
        audit_signature(self.module, self.target, signature)?;
        self.plan_arguments(
            signature,
            &signature.params,
            &signature.param_attributes,
            signature.params.len(),
        )
    }

    /// Plan the original fixed prefix and every actually supplied argument.
    /// Variadic call attributes cover all actual arguments, including an
    /// explicit empty vector for an argument without extension attributes.
    pub fn plan_call(
        &self,
        signature: &Signature,
        actual_types: &[TypeId],
        actual_attrs: &[Vec<String>],
    ) -> Result<AbiPlan, Diagnostic> {
        let fixed = prepare_call_signature(
            self.module,
            self.target,
            signature,
            actual_types,
            actual_attrs,
        )?;
        self.plan_arguments(&fixed, actual_types, actual_attrs, signature.params.len())
    }

    fn plan_arguments(
        &self,
        signature: &Signature,
        actual_types: &[TypeId],
        actual_attrs: &[Vec<String>],
        named_count: usize,
    ) -> Result<AbiPlan, Diagnostic> {
        let result_leaves = if matches!(self.ty(signature.result)?, Type::Void) {
            &[][..]
        } else {
            self.value_leaves(signature.result)?
        };
        let result_registers: &[&str] = match self.target {
            Target::X86_64UnknownNone => &["rax", "rdx", "rcx"],
            Target::Aarch64UnknownNone => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            // RISCVISelLowering uses CC_RISCV, not FastCC, for returns.
            Target::Riscv64UnknownNone => &["a0", "a1"],
        };
        let implicit = result_leaves.len() > result_registers.len();
        let mut placement = Placement::new(self.target, &signature.abi);
        let mut storage = if let Some(explicit) = &signature.return_storage {
            let (size, alignment) = self.allocation(explicit.ty)?;
            Some(ReturnStoragePlan {
                explicit_param: Some(explicit.param),
                ty: explicit.ty,
                size,
                alignment,
                // Filled from its original parameter's actual location.
                pointer_location: AbiLocation::Register(""),
                pointer_return: (self.target == Target::X86_64UnknownNone).then_some("rax"),
            })
        } else if implicit {
            let (size, _) = self.allocation(signature.result)?;
            let alignment = self.preferred_alignment(signature.result)?;
            if alignment > 16 {
                return Err(fail("implicit result storage alignment above 16 requires another supported frame profile"));
            }
            let pointer_location = if self.target == Target::Aarch64UnknownNone {
                AbiLocation::Register("x8")
            } else {
                placement.ordinary()?
            };
            Some(ReturnStoragePlan {
                explicit_param: None,
                ty: signature.result,
                size,
                alignment,
                pointer_location,
                pointer_return: (self.target == Target::X86_64UnknownNone).then_some("rax"),
            })
        } else {
            None
        };
        let mut args = Vec::new();
        let mut variadic = None;
        for (param, ty) in actual_types.iter().copied().enumerate() {
            if signature.variadic && param == named_count {
                variadic = Some(placement.variadic());
            }
            let leaves = self.value_leaves(ty)?;
            let attrs = actual_attrs.get(param).map_or(&[][..], Vec::as_slice);
            let explicit_sret = signature
                .return_storage
                .as_ref()
                .is_some_and(|s| s.param == param);
            let grouped = self.consecutive_array(ty, leaves)?;
            let block = if grouped && leaves.len() > placement.registers.len() - placement.next {
                // CC_AArch64_Custom_Block: no register/stack split, and all
                // remaining GP registers become unavailable to later args.
                placement.next = placement.registers.len();
                let leaf_align = leaves
                    .last()
                    .map_or(Ok(8), |(ty, _)| self.allocation(*ty).map(|x| x.1))?;
                Some(placement.block(
                    leaves.len(),
                    leaf_align.min(self.source_stack_alignment).max(8),
                )?)
            } else {
                None
            };
            args.try_reserve(leaves.len())
                .map_err(|e| fail(format!("argument part allocation failed: {e}")))?;
            for (leaf, (leaf_ty, offset)) in leaves.iter().copied().enumerate() {
                let location = if explicit_sret && self.target == Target::Aarch64UnknownNone {
                    AbiLocation::Register("x8")
                } else if let Some(base) = block {
                    AbiLocation::Stack {
                        offset: add(base, mul(leaf as u64, 8)?)?,
                    }
                } else {
                    placement.ordinary()?
                };
                if explicit_sret {
                    storage.as_mut().unwrap().pointer_location = location;
                }
                let bits = self.bits(leaf_ty)?;
                let location_bits = location_width(self.target, bits, false, attrs);
                args.push(AbiPart {
                    param: Some(param),
                    leaf,
                    ty: leaf_ty,
                    offset,
                    location,
                    extension: extension(bits, location_bits, attrs),
                    location_bits,
                });
            }
        }
        if signature.variadic && variadic.is_none() {
            variadic = Some(placement.variadic());
        }
        let mut results = Vec::new();
        results
            .try_reserve(result_leaves.len())
            .map_err(|e| fail(format!("result part allocation failed: {e}")))?;
        for (leaf, (ty, offset)) in result_leaves.iter().copied().enumerate() {
            let bits = self.bits(ty)?;
            let (location, location_bits, ext) = if implicit {
                (
                    AbiLocation::IndirectResult { offset },
                    bits,
                    Extension::None,
                )
            } else {
                let width = location_width(self.target, bits, true, &signature.result_attributes);
                (
                    AbiLocation::Register(result_registers[leaf]),
                    width,
                    extension(bits, width, &signature.result_attributes),
                )
            };
            results.push(AbiPart {
                param: None,
                leaf,
                ty,
                offset,
                location,
                extension: ext,
                location_bits,
            });
        }
        Ok(AbiPlan {
            args,
            results,
            storage,
            stack_bytes: align_up(placement.stack, 16)?,
            stack_alignment: 16,
            variadic,
        })
    }

    fn ty(&self, ty: TypeId) -> Result<&Type, Diagnostic> {
        self.module
            .types
            .get(ty)
            .ok_or_else(|| fail(format!("type {ty} is out of bounds")))
    }

    fn value_leaves(&self, ty: TypeId) -> Result<&[(TypeId, u64)], Diagnostic> {
        self.leaves
            .get(&ty)
            .map(Vec::as_slice)
            .ok_or_else(|| fail(format!("original leaf-layout cache lacks type {ty}")))
    }

    fn allocation(&self, ty: TypeId) -> Result<(u64, u64), Diagnostic> {
        self.layouts
            .get(ty)
            .and_then(|x| *x)
            .ok_or_else(|| fail(format!("type {ty} is missing or unsized")))
    }

    fn bits(&self, ty: TypeId) -> Result<u16, Diagnostic> {
        match self.ty(ty)? {
            Type::Int {
                bits: bits @ 1..=64,
            } => Ok(*bits),
            Type::Pointer { address_space: 0 } if self.allocation(ty)?.0 == 8 => Ok(64),
            _ => Err(fail(format!("unsupported scalar leaf type {ty}"))),
        }
    }

    fn consecutive_array(&self, ty: TypeId, leaves: &[(TypeId, u64)]) -> Result<bool, Diagnostic> {
        if self.target != Target::Aarch64UnknownNone
            || !matches!(self.ty(ty)?, Type::Array { .. })
            || leaves.is_empty()
        {
            return Ok(false);
        }
        // LLVM ComputeValueVTs compares the original EVTs, before integer
        // legalisation. AS0 pointer and i64 both have EVT i64. The custom
        // integer block handler then applies only to legal location type i64.
        let first = self.bits(leaves[0].0)?;
        if first <= 32 {
            return Ok(false);
        }
        for (ty, _) in leaves {
            if self.bits(*ty)? != first {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn preferred_alignment(&self, mut ty: TypeId) -> Result<u64, Diagnostic> {
        loop {
            match self.ty(ty)? {
                Type::Array { element, .. } => ty = *element,
                Type::Struct { .. } => {
                    return Ok(self.preferred_struct.max(self.allocation(ty)?.1))
                }
                Type::Pointer { address_space: 0 } => return Ok(self.preferred_pointer),
                Type::Int { bits } => {
                    return self
                        .preferred_ints
                        .range(u64::from(*bits)..)
                        .next()
                        .or_else(|| self.preferred_ints.last_key_value())
                        .map(|(_, align)| *align)
                        .ok_or_else(|| fail("missing integer preferred alignment"))
                }
                _ => return Err(fail("unsupported implicit return storage type")),
            }
        }
    }
}

fn fail(message: impl std::fmt::Display) -> Diagnostic {
    error_diagnostic(format!("native ABI: {message}"))
}

fn add(lhs: u64, rhs: u64) -> Result<u64, Diagnostic> {
    lhs.checked_add(rhs)
        .ok_or_else(|| fail("placement overflows u64"))
}

fn mul(lhs: u64, rhs: u64) -> Result<u64, Diagnostic> {
    lhs.checked_mul(rhs)
        .ok_or_else(|| fail("placement overflows u64"))
}

fn align_up(value: u64, alignment: u64) -> Result<u64, Diagnostic> {
    Ok(add(value, alignment - 1)? & !(alignment - 1))
}

fn extension(bits: u16, location_bits: u16, attrs: &[String]) -> Extension {
    if bits == location_bits {
        Extension::None
    } else if attrs.iter().any(|a| a == "signext") {
        Extension::Sign
    } else if attrs.iter().any(|a| a == "zeroext") {
        Extension::Zero
    } else {
        Extension::Any
    }
}

fn location_width(target: Target, bits: u16, result: bool, attrs: &[String]) -> u16 {
    match target {
        Target::Riscv64UnknownNone => 64,
        Target::Aarch64UnknownNone => {
            if bits <= 32 {
                32
            } else {
                64
            }
        }
        Target::X86_64UnknownNone if !result => {
            if bits <= 32 {
                32
            } else {
                64
            }
        }
        Target::X86_64UnknownNone => {
            // X86 getTypeForExtReturn only keeps i1/i8/i16 narrow. An
            // attributed odd-width integer (e.g. i3/i9) is promoted to i32.
            if !attrs.is_empty() && ![1, 8, 16].contains(&bits) && bits < 32 {
                32
            } else {
                bits.max(8).next_power_of_two()
            }
        }
    }
}

struct Placement {
    registers: &'static [&'static str],
    next: usize,
    stack: u64,
}

impl Placement {
    fn new(target: Target, abi: &str) -> Self {
        let registers = match target {
            Target::X86_64UnknownNone => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"][..],
            Target::Aarch64UnknownNone => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"][..],
            Target::Riscv64UnknownNone if abi == "fastcc" => &[
                "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "t3", "t4", "t5", "t6",
            ][..],
            Target::Riscv64UnknownNone => &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"][..],
        };
        Self {
            registers,
            next: 0,
            stack: 0,
        }
    }

    fn ordinary(&mut self) -> Result<AbiLocation, Diagnostic> {
        if let Some(reg) = self.registers.get(self.next) {
            self.next += 1;
            Ok(AbiLocation::Register(reg))
        } else {
            let offset = self.stack;
            self.stack = add(self.stack, 8)?;
            Ok(AbiLocation::Stack { offset })
        }
    }

    fn variadic(&self) -> VariadicPlan {
        VariadicPlan {
            named_gp: self.next,
            named_stack_bytes: self.stack,
            gp_registers: self.registers,
            vector_register_count: 0,
        }
    }

    fn block(&mut self, leaves: usize, alignment: u64) -> Result<u64, Diagnostic> {
        let base = align_up(self.stack, alignment)?;
        self.stack = add(base, mul(leaves as u64, 8)?)?;
        Ok(base)
    }
}

fn profile(module: &NativeModule, target: Target) -> Result<(), Diagnostic> {
    let architecture = match target {
        Target::X86_64UnknownNone => "x86_64",
        Target::Aarch64UnknownNone => "aarch64",
        Target::Riscv64UnknownNone => "riscv64",
    };
    let parts: Vec<_> = module.target.triple.split('-').collect();
    let bare_rv = module.target.triple == "riscv64"
        && matches!(module.target.abi.as_deref(), Some("lp64" | "lp64d"));
    let elf = matches!(parts.as_slice(), [arch, vendor, "linux", "gnu" | "musl"] if *arch == architecture && !vendor.is_empty())
        || matches!(parts.as_slice(), [arch, vendor, "none"] if *arch == architecture && !vendor.is_empty())
        || matches!(parts.as_slice(), [arch, vendor, "none", "elf" | "eabi"] if *arch == architecture && !vendor.is_empty());
    if !(elf || (architecture == "riscv64" && bare_rv))
        || module.target.pointer_bits != 64
        || !module.target.little_endian
    {
        return Err(fail(
            "only the matching little-endian LP64 ELF target profile is supported",
        ));
    }
    if module
        .target
        .abi
        .as_deref()
        .is_some_and(|a| architecture != "riscv64" || !matches!(a, "lp64" | "lp64d"))
    {
        return Err(fail("unsupported explicit target ABI"));
    }
    Ok(())
}

/// Check original ABI types before allocating scalar leaves. Arrays are
/// traversed once by element type, never instantiated for this feature check.
pub fn audit_signature(
    module: &NativeModule,
    target: Target,
    sig: &Signature,
) -> Result<(), Diagnostic> {
    profile(module, target)?;
    if !matches!(sig.abi.as_str(), "c" | "fastcc") || (sig.variadic && sig.abi != "c") {
        return Err(fail(
            "only LLVM C signatures and fixed fastcc signatures are supported",
        ));
    }
    if !sig.param_attributes.is_empty() && sig.param_attributes.len() != sig.params.len() {
        return Err(fail(
            "parameter attributes do not match original parameters",
        ));
    }
    let ty = |id: TypeId| {
        module
            .types
            .get(id)
            .ok_or_else(|| fail(format!("type {id} is out of bounds")))
    };
    audit_attributes(module, &sig.result_attributes, sig.result)?;
    for (index, param) in sig.params.iter().copied().enumerate() {
        audit_attributes(
            module,
            sig.param_attributes
                .get(index)
                .map_or(&[][..], Vec::as_slice),
            param,
        )?;
    }
    let mut roots = sig.params.clone();
    if !matches!(ty(sig.result)?, Type::Void) {
        roots.push(sig.result);
    }
    if let Some(storage) = &sig.return_storage {
        if storage.param > 1
            || !matches!(ty(sig.result)?, Type::Void)
            || !sig
                .params
                .get(storage.param)
                .is_some_and(|p| matches!(ty(*p), Ok(Type::Pointer { address_space: 0 })))
        {
            return Err(fail(
                "typed sret requires original AS0 pointer parameter0/1 and void result",
            ));
        }
        roots.push(storage.ty);
    }
    let mut seen = HashSet::new();
    while let Some(id) = roots.pop() {
        if !seen.insert(id) {
            continue;
        }
        match ty(id)? {
            Type::Int { bits: 1..=64 } | Type::Pointer { address_space: 0 } => (),
            Type::Array { element, .. } => roots.push(*element),
            Type::Struct { fields, .. } => roots.extend(fields),
            _ => return Err(fail(format!("unsupported original ABI type {id}; floating-point, i128, vectors and opaque/byval ABI require explicit lowering"))),
        }
    }
    Ok(())
}

fn audit_attributes(module: &NativeModule, attrs: &[String], ty: TypeId) -> Result<(), Diagnostic> {
    let ty = module
        .types
        .get(ty)
        .ok_or_else(|| fail(format!("type {ty} is out of bounds")))?;
    let mut seen = HashSet::new();
    for attr in attrs {
        if !matches!(attr.as_str(), "signext" | "zeroext")
            || !matches!(ty, Type::Int { .. })
            || !seen.insert(attr.as_str())
        {
            return Err(fail(format!(
                "unsupported, duplicate or misplaced ABI attribute `{attr}`"
            )));
        }
    }
    if seen.len() > 1 {
        return Err(fail("conflicting integer extension attributes"));
    }
    Ok(())
}

/// Match the supported structural ABI types without expanding arrays. Duplicate
/// type IDs with identical definitions must not change argument placement.
fn same_abi_type(module: &NativeModule, lhs: TypeId, rhs: TypeId) -> Result<bool, Diagnostic> {
    let mut pending = vec![(lhs, rhs)];
    let mut seen = HashSet::new();
    while let Some((left, right)) = pending.pop() {
        if !seen.insert((left, right)) {
            continue;
        }
        let a = module
            .types
            .get(left)
            .ok_or_else(|| fail("actual argument type is out of bounds"))?;
        let b = module
            .types
            .get(right)
            .ok_or_else(|| fail("actual argument type is out of bounds"))?;
        match (a, b) {
            (Type::Int { bits: a }, Type::Int { bits: b }) if a == b => {}
            (Type::Pointer { address_space: a }, Type::Pointer { address_space: b }) if a == b => {}
            (
                Type::Array {
                    element: a,
                    len: al,
                },
                Type::Array {
                    element: b,
                    len: bl,
                },
            ) if al == bl => {
                pending.push((*a, *b));
            }
            (
                Type::Struct {
                    fields: a,
                    packed: ap,
                },
                Type::Struct {
                    fields: b,
                    packed: bp,
                },
            ) if ap == bp && a.len() == b.len() => {
                pending.extend(a.iter().copied().zip(b.iter().copied()))
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}

fn prepare_call_signature(
    module: &NativeModule,
    target: Target,
    signature: &Signature,
    actual_types: &[TypeId],
    actual_attrs: &[Vec<String>],
) -> Result<Signature, Diagnostic> {
    let named = signature.params.len();
    if actual_types.len() < named || (!signature.variadic && actual_types.len() != named) {
        return Err(fail(
            "actual argument count does not match the fixed prefix",
        ));
    }
    if actual_attrs.len() != actual_types.len() && !(actual_attrs.is_empty() && !signature.variadic)
    {
        return Err(fail(
            "actual ABI attribute inventory must cover every argument",
        ));
    }
    let stored = signature.param_attributes.len();
    if stored != 0 && stored != named && !(signature.variadic && stored == actual_types.len()) {
        return Err(fail(
            "call signature attribute inventory does not match fixed or actual arguments",
        ));
    }
    if stored > named && signature.param_attributes != actual_attrs {
        return Err(fail(
            "call signature and actual trailing ABI attributes disagree",
        ));
    }
    let mut fixed = signature.clone();
    fixed.param_attributes.truncate(named);
    audit_signature(module, target, &fixed)?;
    for (index, ty) in actual_types.iter().copied().enumerate() {
        let attrs = actual_attrs.get(index).map_or(&[][..], Vec::as_slice);
        audit_attributes(module, attrs, ty)?;
        if index < named {
            if !same_abi_type(module, signature.params[index], ty)? {
                return Err(fail("actual argument type disagrees with the fixed prefix"));
            }
            let original = fixed
                .param_attributes
                .get(index)
                .map_or(&[][..], Vec::as_slice);
            if original != attrs {
                return Err(fail("actual ABI attributes disagree with the fixed prefix"));
            }
        } else if !matches!(
            module.types.get(ty),
            Some(Type::Int { bits: 1..=64 } | Type::Pointer { address_space: 0 })
        ) {
            return Err(fail("variadic arguments currently require scalar integers up to 64 bits or AS0 pointers; aggregates and floating-point require additional ABI lowering"));
        }
    }
    Ok(fixed)
}

/// Reject unsupported original call contracts before allocating layout caches.
/// In particular, a variadic aggregate must not be expanded into scalar leaves
/// before the scalar-only trailing-argument profile has rejected it.
pub fn audit_call_signature(
    module: &NativeModule,
    target: Target,
    signature: &Signature,
    actual_types: &[TypeId],
    actual_attrs: &[Vec<String>],
) -> Result<(), Diagnostic> {
    prepare_call_signature(module, target, signature, actual_types, actual_attrs).map(|_| ())
}

/// Convenience form. Emitters should reuse AbiContext and both module caches.
pub fn plan(module: &NativeModule, target: Target, sig: &Signature) -> Result<AbiPlan, Diagnostic> {
    audit_signature(module, target, sig)?;
    let mut roots = sig.params.clone();
    roots.push(sig.result);
    // Explicit sret needs an allocation layout, not one SSA slot per payload
    // element. The pointer's leaves already occur in the fixed parameters.
    let layouts = type_layouts(module)?;
    let leaves = value_leaf_layouts(module, &roots)?;
    AbiContext::new(module, target, &leaves, &layouts)?.plan(sig)
}

/// Convenience call planner. Unsupported trailing types are audited before any
/// aggregate leaf allocation, including empty or enormous unsupported arrays.
pub fn plan_call(
    module: &NativeModule,
    target: Target,
    sig: &Signature,
    actual_types: &[TypeId],
    actual_attrs: &[Vec<String>],
) -> Result<AbiPlan, Diagnostic> {
    let fixed = prepare_call_signature(module, target, sig, actual_types, actual_attrs)?;
    let mut roots = actual_types.to_vec();
    roots.push(sig.result);
    let layouts = type_layouts(module)?;
    let leaves = value_leaf_layouts(module, &roots)?;
    AbiContext::new(module, target, &leaves, &layouts)?.plan_arguments(
        &fixed,
        actual_types,
        actual_attrs,
        sig.params.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::super::native_ir::{
        NoAliasMetadata, Provenance, ReturnStorage, Semantics, TargetLayout, FORMAT,
    };
    use super::*;

    fn module(target: Target) -> NativeModule {
        NativeModule {
            format: FORMAT.into(),
            name: "abi-reference".into(),
            target: TargetLayout {
                triple: match target {
                    Target::X86_64UnknownNone => "x86_64-unknown-linux-gnu",
                    Target::Aarch64UnknownNone => "aarch64-unknown-linux-gnu",
                    Target::Riscv64UnknownNone => "riscv64-unknown-linux-gnu",
                }
                .into(),
                data_layout: "e-p:64:64-i64:64-S128".into(),
                pointer_bits: 64,
                little_endian: true,
                abi: None,
                tls_profile: None,
                atomic_profile: None,
            },
            semantics: Semantics::LlvmDefinedBehaviorV1,
            types: vec![
                Type::Void,
                Type::Int { bits: 64 },
                Type::Pointer { address_space: 0 },
                Type::Int { bits: 32 },
                Type::Int { bits: 8 },
                Type::Int { bits: 9 },
                Type::Int { bits: 33 },
                Type::Int { bits: 1 },
            ],
            globals: vec![],
            functions: vec![],
            aliases: vec![],
            comdats: vec![],
            noalias_metadata: NoAliasMetadata::default(),
            atomic_sync_scopes: vec![],
            provenance: Provenance {
                input_sha256: "0".repeat(64),
                frontend: "LLVM22 references".into(),
                frontend_version: "22.1.6".into(),
                importer: "unit test".into(),
                importer_version: "1".into(),
                source_function_count: 0,
                source_global_count: 0,
                source_alias_count: 0,
                referenced_comdat_count: 0,
                noalias_metadata_source: vec![],
                refinements: vec![],
            },
        }
    }

    #[test]
    fn metadata_is_unsized_and_cannot_enter_any_native_call_abi() {
        for target in [
            Target::X86_64UnknownNone,
            Target::Aarch64UnknownNone,
            Target::Riscv64UnknownNone,
        ] {
            let mut m = module(target);
            let metadata = m.types.len();
            m.types.push(Type::Metadata {});
            let empty = m.types.len();
            m.types.push(Type::Array {
                element: metadata,
                len: 0,
            });
            for sig in [
                signature(vec![metadata], 0, "c"),
                signature(vec![], metadata, "c"),
                signature(vec![empty], 0, "c"),
                signature(vec![metadata], 0, "fastcc"),
            ] {
                assert!(audit_signature(&m, target, &sig).is_err());
                assert!(plan(&m, target, &sig).is_err());
            }
        }
    }

    fn signature(params: Vec<TypeId>, result: TypeId, abi: &str) -> Signature {
        Signature {
            params,
            result,
            abi: abi.into(),
            variadic: false,
            param_attributes: vec![],
            result_attributes: vec![],
            return_storage: None,
        }
    }

    fn push(m: &mut NativeModule, ty: Type) -> TypeId {
        let id = m.types.len();
        m.types.push(ty);
        id
    }

    fn regs(parts: &[AbiPart]) -> Vec<AbiLocation> {
        parts.iter().map(|p| p.location).collect()
    }

    #[test]
    fn scalar_c_keeps_original_registers_stack_offsets_and_result_attributes() {
        for (target, names) in [
            (
                Target::X86_64UnknownNone,
                vec!["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            ),
            (
                Target::Aarch64UnknownNone,
                vec!["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            ),
            (
                Target::Riscv64UnknownNone,
                vec!["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
            ),
        ] {
            let m = module(target);
            let mut sig = signature(vec![1; 13], 3, "c");
            sig.result_attributes = vec!["signext".into()];
            let p = plan(&m, target, &sig).unwrap();
            for (i, part) in p.args.iter().enumerate() {
                assert_eq!(part.param, Some(i));
                assert_eq!(part.leaf, 0);
                assert_eq!(
                    part.location,
                    names.get(i).map_or(
                        AbiLocation::Stack {
                            offset: (i.saturating_sub(names.len()) * 8) as u64
                        },
                        |r| AbiLocation::Register(r)
                    )
                );
            }
            assert_eq!(p.stack_bytes, ((13 - names.len()) as u64 * 8 + 15) & !15);
            assert_eq!(p.stack_alignment, 16);
            assert!(p.storage.is_none());
            assert_eq!(
                p.results[0].extension,
                if target == Target::Riscv64UnknownNone {
                    Extension::Sign
                } else {
                    Extension::None
                }
            );
        }
    }

    #[test]
    fn rv_fastcc_adds_four_argument_registers_but_not_return_registers() {
        let target = Target::Riscv64UnknownNone;
        let mut m = module(target);
        let two = push(
            &mut m,
            Type::Struct {
                fields: vec![1; 2],
                packed: false,
            },
        );
        let three = push(
            &mut m,
            Type::Struct {
                fields: vec![1; 3],
                packed: false,
            },
        );
        let p = plan(&m, target, &signature(vec![1; 14], two, "fastcc")).unwrap();
        assert_eq!(
            regs(&p.args[8..12]),
            vec![
                AbiLocation::Register("t3"),
                AbiLocation::Register("t4"),
                AbiLocation::Register("t5"),
                AbiLocation::Register("t6")
            ]
        );
        assert_eq!(
            regs(&p.results),
            vec![AbiLocation::Register("a0"), AbiLocation::Register("a1")]
        );
        assert_eq!(p.args[12].location, AbiLocation::Stack { offset: 0 });
        let p = plan(&m, target, &signature(vec![1; 14], three, "fastcc")).unwrap();
        assert_eq!(
            p.storage.unwrap().pointer_location,
            AbiLocation::Register("a0")
        );
        assert_eq!(p.args[0].location, AbiLocation::Register("a1"));
        assert_eq!(p.args[10].location, AbiLocation::Register("t6"));
    }

    #[test]
    fn raw_return_leaf_boundaries_demote_to_original_typed_storage_all_three() {
        for (target, limit, first, pointer) in [
            (Target::X86_64UnknownNone, 3, "rsi", "rdi"),
            (Target::Aarch64UnknownNone, 8, "x0", "x8"),
            (Target::Riscv64UnknownNone, 2, "a1", "a0"),
        ] {
            let mut m = module(target);
            let direct = push(
                &mut m,
                Type::Struct {
                    fields: vec![1; limit],
                    packed: false,
                },
            );
            let indirect = push(
                &mut m,
                Type::Struct {
                    fields: vec![1; limit + 1],
                    packed: false,
                },
            );
            for abi in ["c", "fastcc"] {
                assert!(plan(&m, target, &signature(vec![1], direct, abi))
                    .unwrap()
                    .storage
                    .is_none());
                let p = plan(&m, target, &signature(vec![1], indirect, abi)).unwrap();
                let storage = p.storage.unwrap();
                assert_eq!(storage.explicit_param, None);
                assert_eq!(storage.ty, indirect);
                assert_eq!(storage.size, (limit + 1) as u64 * 8);
                assert_eq!(storage.pointer_location, AbiLocation::Register(pointer));
                assert_eq!(
                    storage.pointer_return,
                    (target == Target::X86_64UnknownNone).then_some("rax")
                );
                assert_eq!(p.args[0].location, AbiLocation::Register(first));
                for (i, part) in p.results.iter().enumerate() {
                    assert_eq!(part.param, None);
                    assert_eq!(part.leaf, i);
                    assert_eq!(
                        part.location,
                        AbiLocation::IndirectResult {
                            offset: i as u64 * 8
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn explicit_sret_keeps_original_parameter_position_and_a64_x8_exception() {
        for target in [
            Target::X86_64UnknownNone,
            Target::Aarch64UnknownNone,
            Target::Riscv64UnknownNone,
        ] {
            let mut m = module(target);
            let storage_ty = push(&mut m, Type::Array { element: 1, len: 9 });
            for position in [0, 1] {
                let mut params = vec![1; 11];
                params[position] = 2;
                let mut sig = signature(params, 0, "fastcc");
                sig.return_storage = Some(ReturnStorage {
                    param: position,
                    ty: storage_ty,
                });
                let p = plan(&m, target, &sig).unwrap();
                let s = p.storage.unwrap();
                let expected = match target {
                    Target::X86_64UnknownNone => {
                        if position == 0 {
                            "rdi"
                        } else {
                            "rsi"
                        }
                    }
                    Target::Aarch64UnknownNone => "x8",
                    Target::Riscv64UnknownNone => {
                        if position == 0 {
                            "a0"
                        } else {
                            "a1"
                        }
                    }
                };
                assert_eq!(s.explicit_param, Some(position));
                assert_eq!(s.pointer_location, AbiLocation::Register(expected));
                assert_eq!(s.pointer_location, p.args[position].location);
                assert!(p.results.is_empty());
                assert_eq!(s.size, 72);
                assert_eq!(s.alignment, 8);
            }
        }
    }

    #[test]
    fn a64_homogeneous_i64_array_spills_as_a_block_but_struct_and_i32_array_split() {
        let target = Target::Aarch64UnknownNone;
        let mut m = module(target);
        let array = push(&mut m, Type::Array { element: 1, len: 3 });
        let structure = push(
            &mut m,
            Type::Struct {
                fields: vec![1; 3],
                packed: false,
            },
        );
        let narrow = push(&mut m, Type::Array { element: 3, len: 3 });
        for abi in ["c", "fastcc"] {
            let p = plan(
                &m,
                target,
                &signature(vec![1, 1, 1, 1, 1, 1, array, 1], 0, abi),
            )
            .unwrap();
            assert_eq!(
                regs(&p.args[6..]),
                vec![
                    AbiLocation::Stack { offset: 0 },
                    AbiLocation::Stack { offset: 8 },
                    AbiLocation::Stack { offset: 16 },
                    AbiLocation::Stack { offset: 24 }
                ]
            );
            for ty in [structure, narrow] {
                let p = plan(
                    &m,
                    target,
                    &signature(vec![1, 1, 1, 1, 1, 1, ty, 1], 0, abi),
                )
                .unwrap();
                assert_eq!(
                    regs(&p.args[6..]),
                    vec![
                        AbiLocation::Register("x6"),
                        AbiLocation::Register("x7"),
                        AbiLocation::Stack { offset: 0 },
                        AbiLocation::Stack { offset: 8 }
                    ]
                );
            }
        }
    }

    #[test]
    fn a64_grouping_compares_original_evts_before_odd_width_promotion() {
        let target = Target::Aarch64UnknownNone;
        let mut m = module(target);
        let odd = push(&mut m, Type::Array { element: 6, len: 3 });
        let mixed = push(
            &mut m,
            Type::Struct {
                fields: vec![6, 1],
                packed: false,
            },
        );
        let mixed_array = push(
            &mut m,
            Type::Array {
                element: mixed,
                len: 2,
            },
        );
        let homogeneous = push(
            &mut m,
            Type::Struct {
                fields: vec![2, 1],
                packed: false,
            },
        );
        let homogeneous_array = push(
            &mut m,
            Type::Array {
                element: homogeneous,
                len: 2,
            },
        );
        for ty in [odd, homogeneous_array] {
            let p = plan(&m, target, &signature(vec![1, 1, 1, 1, 1, 1, ty], 0, "c")).unwrap();
            assert_eq!(p.args[6].location, AbiLocation::Stack { offset: 0 });
        }
        let p = plan(
            &m,
            target,
            &signature(vec![1, 1, 1, 1, 1, 1, mixed_array], 0, "c"),
        )
        .unwrap();
        assert_eq!(p.args[6].location, AbiLocation::Register("x6"));
        assert_eq!(p.args[7].location, AbiLocation::Register("x7"));
    }

    #[test]
    fn packed_nested_parts_keep_original_type_ids_offsets_and_array_allocation_stride() {
        let target = Target::X86_64UnknownNone;
        let mut m = module(target);
        let packed = push(
            &mut m,
            Type::Struct {
                fields: vec![4, 1],
                packed: true,
            },
        );
        let array = push(
            &mut m,
            Type::Array {
                element: packed,
                len: 2,
            },
        );
        let p = plan(&m, target, &signature(vec![array], array, "c")).unwrap();
        assert_eq!(
            p.args.iter().map(|p| (p.ty, p.offset)).collect::<Vec<_>>(),
            vec![(4, 0), (1, 1), (4, 9), (1, 10)]
        );
        let s = p.storage.unwrap();
        assert_eq!(s.size, 18);
        assert_eq!(s.alignment, 8);
        assert_eq!(
            p.results[3].location,
            AbiLocation::IndirectResult { offset: 10 }
        );
    }

    #[test]
    fn source_narrow_and_odd_integer_extension_contracts_are_not_widened_silently() {
        for target in [
            Target::X86_64UnknownNone,
            Target::Aarch64UnknownNone,
            Target::Riscv64UnknownNone,
        ] {
            for bits in 1..=64 {
                let mut m = module(target);
                let ty = push(&mut m, Type::Int { bits });
                for attr in [None, Some("signext"), Some("zeroext")] {
                    let mut sig = signature(vec![ty], ty, "c");
                    if let Some(attr) = attr {
                        sig.param_attributes = vec![vec![attr.into()]];
                        sig.result_attributes = vec![attr.into()];
                    }
                    let p = plan(&m, target, &sig).unwrap();
                    let arg_width = match target {
                        Target::Riscv64UnknownNone => 64,
                        _ if bits <= 32 => 32,
                        _ => 64,
                    };
                    let ret_width = match target {
                        Target::Riscv64UnknownNone => 64,
                        Target::Aarch64UnknownNone if bits <= 32 => 32,
                        Target::Aarch64UnknownNone => 64,
                        Target::X86_64UnknownNone
                            if attr.is_some() && ![1, 8, 16].contains(&bits) && bits < 32 =>
                        {
                            32
                        }
                        Target::X86_64UnknownNone => bits.max(8).next_power_of_two(),
                    };
                    for (part, width) in [(&p.args[0], arg_width), (&p.results[0], ret_width)] {
                        assert_eq!(part.location_bits, width);
                        assert_eq!(
                            part.extension,
                            if width == bits {
                                Extension::None
                            } else {
                                match attr {
                                    Some("signext") => Extension::Sign,
                                    Some("zeroext") => Extension::Zero,
                                    _ => Extension::Any,
                                }
                            }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn implicit_result_uses_preferred_alignment_and_explicit_storage_retains_abi_alignment() {
        let target = Target::X86_64UnknownNone;
        let mut m = module(target);
        m.target.data_layout = "e-p:64:64-i8:8:32-i64:64-S128".into();
        let array = push(&mut m, Type::Array { element: 4, len: 9 });
        let implicit = plan(&m, target, &signature(vec![], array, "c"))
            .unwrap()
            .storage
            .unwrap();
        assert_eq!((implicit.size, implicit.alignment), (9, 4));
        let mut sig = signature(vec![2], 0, "c");
        sig.return_storage = Some(ReturnStorage {
            param: 0,
            ty: array,
        });
        assert_eq!(
            plan(&m, target, &sig).unwrap().storage.unwrap().alignment,
            1
        );
        m.target.data_layout = "e-p:64:64-i8:8:256-i64:64-S128".into();
        assert!(plan(&m, target, &signature(vec![], array, "c"))
            .unwrap_err()
            .message
            .contains("alignment above 16"));
    }

    #[test]
    fn empty_aggregates_consume_no_register_or_stack_and_unused_values_are_not_expanded() {
        let target = Target::Riscv64UnknownNone;
        let mut m = module(target);
        let empty = push(
            &mut m,
            Type::Struct {
                fields: vec![],
                packed: false,
            },
        );
        let huge_empty = push(
            &mut m,
            Type::Array {
                element: empty,
                len: u64::MAX,
            },
        );
        let unused = push(
            &mut m,
            Type::Array {
                element: 1,
                len: 1_000_000,
            },
        );
        let layouts = type_layouts(&m).unwrap();
        let leaves = value_leaf_layouts(&m, &[huge_empty, 1]).unwrap();
        assert!(!leaves.contains_key(&unused));
        let context = AbiContext::new(&m, target, &leaves, &layouts).unwrap();
        let p = context
            .plan(&signature(vec![huge_empty, 1], huge_empty, "fastcc"))
            .unwrap();
        assert_eq!(p.args.len(), 1);
        assert_eq!(p.args[0].param, Some(1));
        assert_eq!(p.args[0].location, AbiLocation::Register("a0"));
        assert!(p.results.is_empty());
        assert!(p.storage.is_none());
        assert_eq!(p.stack_bytes, 0);
    }

    #[test]
    fn unsupported_source_abi_features_fail_before_aggregate_leaf_expansion() {
        let target = Target::X86_64UnknownNone;
        let mut m = module(target);
        let float = push(&mut m, Type::Float { bits: 64 });
        let wide = push(&mut m, Type::Int { bits: 128 });
        let zero_float = push(
            &mut m,
            Type::Array {
                element: float,
                len: 0,
            },
        );
        for ty in [float, wide, zero_float, 0] {
            assert!(audit_signature(&m, target, &signature(vec![ty], 0, "c")).is_err());
        }
        for attr in ["byval", "inreg", "nest", "preallocated", "signext\0"] {
            let mut sig = signature(vec![2], 0, "c");
            sig.param_attributes = vec![vec![attr.into()]];
            assert!(audit_signature(&m, target, &sig).is_err());
        }
        let mut sig = signature(vec![1], 1, "c");
        sig.variadic = true;
        sig.abi = "fastcc".into();
        assert!(audit_signature(&m, target, &sig).is_err());
        sig.variadic = false;
        sig.abi = "win64".into();
        assert!(audit_signature(&m, target, &sig).is_err());
        sig.abi = "c".into();
        sig.param_attributes = vec![vec!["signext".into(), "zeroext".into()]];
        assert!(audit_signature(&m, target, &sig).is_err());
        let mut sig = signature(vec![2, 2, 2], 0, "c");
        sig.return_storage = Some(ReturnStorage { param: 2, ty: 1 });
        assert!(audit_signature(&m, target, &sig).is_err());
        m.target.triple = "x86_64-apple-darwin".into();
        assert!(plan(&m, target, &signature(vec![1], 1, "c")).is_err());
    }

    #[test]
    fn variadic_named_boundary_and_scalar_tails_cover_register_exhaustion_all_three() {
        for target in [
            Target::X86_64UnknownNone,
            Target::Aarch64UnknownNone,
            Target::Riscv64UnknownNone,
        ] {
            let m = module(target);
            let registers = Placement::new(target, "c").registers;
            for named in [
                0,
                registers.len() - 1,
                registers.len(),
                registers.len() + 1,
                registers.len() + 2,
            ] {
                let mut sig = signature(vec![1; named], 1, "c");
                sig.variadic = true;
                let callee = plan(&m, target, &sig).unwrap();
                let mut types = sig.params.clone();
                types.extend([2, 3, 4, 1]);
                let mut attrs = vec![vec![]; types.len()];
                attrs[named + 2] = vec!["signext".into()];
                sig.param_attributes = attrs.clone();
                let call = plan_call(&m, target, &sig, &types, &attrs).unwrap();
                assert_eq!(call.variadic, callee.variadic);
                let boundary = call.variadic.as_ref().unwrap();
                assert_eq!(boundary.named_gp, named.min(registers.len()));
                assert_eq!(
                    boundary.named_stack_bytes,
                    named.saturating_sub(registers.len()) as u64 * 8
                );
                assert_eq!(boundary.gp_registers, registers);
                assert_eq!(boundary.vector_register_count, 0);
                for (index, part) in call.args.iter().enumerate() {
                    assert_eq!(part.param, Some(index));
                    assert_eq!(part.ty, types[index]);
                    assert_eq!(
                        part.location,
                        registers.get(index).map_or(
                            AbiLocation::Stack {
                                offset: index.saturating_sub(registers.len()) as u64 * 8
                            },
                            |name| AbiLocation::Register(name),
                        )
                    );
                }
                assert_eq!(call.args[named + 2].extension, Extension::Sign);
                assert_eq!(
                    call.stack_bytes,
                    (types.len().saturating_sub(registers.len()) as u64 * 8 + 15) & !15
                );
            }
        }
    }

    #[test]
    fn variadic_actual_extension_attributes_are_exact_and_do_not_mutate_signatures() {
        for target in [
            Target::X86_64UnknownNone,
            Target::Aarch64UnknownNone,
            Target::Riscv64UnknownNone,
        ] {
            let m = module(target);
            let mut sig = signature(vec![4], 1, "c");
            sig.variadic = true;
            sig.param_attributes = vec![vec!["signext".into()]];
            let before = sig.clone();
            let types = [4, 5, 2];
            let attrs = vec![vec!["signext".into()], vec!["zeroext".into()], vec![]];
            let planned = plan_call(&m, target, &sig, &types, &attrs).unwrap();
            assert_eq!(sig, before);
            assert_eq!(planned.args[0].extension, Extension::Sign);
            assert_eq!(planned.args[1].extension, Extension::Zero);
            assert_eq!(planned.args[2].extension, Extension::None);
            for wrong in [
                vec![vec![], vec!["zeroext".into()], vec![]],
                vec![
                    vec!["signext".into()],
                    vec!["signext".into(), "zeroext".into()],
                    vec![],
                ],
                vec![
                    vec!["signext".into()],
                    vec!["zeroext".into(), "zeroext".into()],
                    vec![],
                ],
                vec![vec!["signext".into()], vec!["byval".into()], vec![]],
                vec![vec!["signext".into()], vec![], vec!["signext".into()]],
            ] {
                assert!(plan_call(&m, target, &sig, &types, &wrong).is_err());
            }
            sig.param_attributes = attrs.clone();
            let mut wrong = attrs.clone();
            wrong[1].clear();
            assert!(plan_call(&m, target, &sig, &types, &wrong).is_err());
            assert_eq!(
                plan_call(&m, target, &sig, &types, &attrs).unwrap(),
                planned
            );
        }
    }

    #[test]
    fn variadic_fixed_type_equivalence_preserves_actual_type_ids() {
        let target = Target::Riscv64UnknownNone;
        let mut m = module(target);
        let duplicate = push(&mut m, Type::Int { bits: 64 });
        let mut sig = signature(vec![1], 1, "c");
        sig.variadic = true;
        let planned = plan_call(&m, target, &sig, &[duplicate, 2], &[vec![], vec![]]).unwrap();
        assert_eq!(planned.args[0].ty, duplicate);
        assert_eq!(planned.args[1].ty, 2);
        assert!(plan_call(&m, target, &sig, &[3, 2], &[vec![], vec![]]).is_err());
    }

    #[test]
    fn variadic_sret_boundary_counts_hidden_gp_but_not_aarch64_x8() {
        for target in [
            Target::X86_64UnknownNone,
            Target::Aarch64UnknownNone,
            Target::Riscv64UnknownNone,
        ] {
            let mut m = module(target);
            let result = push(
                &mut m,
                Type::Struct {
                    fields: vec![1; 9],
                    packed: false,
                },
            );
            let mut sig = signature(vec![1; 8], result, "c");
            sig.variadic = true;
            let planned = plan(&m, target, &sig).unwrap();
            let boundary = planned.variadic.as_ref().unwrap();
            let expected_stack = match target {
                Target::X86_64UnknownNone => 24,
                Target::Aarch64UnknownNone => 0,
                Target::Riscv64UnknownNone => 8,
            };
            assert_eq!(boundary.named_gp, boundary.gp_registers.len());
            assert_eq!(boundary.named_stack_bytes, expected_stack);
            assert_eq!(
                planned.storage.as_ref().unwrap().pointer_location,
                AbiLocation::Register(match target {
                    Target::X86_64UnknownNone => "rdi",
                    Target::Aarch64UnknownNone => "x8",
                    Target::Riscv64UnknownNone => "a0",
                })
            );
            for param in [0, 1] {
                let mut params = vec![1; 2];
                params[param] = 2;
                let mut explicit = signature(params, 0, "c");
                explicit.variadic = true;
                explicit.return_storage = Some(ReturnStorage { param, ty: result });
                let plan = plan(&m, target, &explicit).unwrap();
                assert_eq!(
                    plan.variadic.unwrap().named_gp,
                    if target == Target::Aarch64UnknownNone {
                        1
                    } else {
                        2
                    }
                );
            }
        }
    }

    #[test]
    fn variadic_named_aggregate_block_and_zero_sized_parameters_keep_existing_placement() {
        let target = Target::Aarch64UnknownNone;
        let mut m = module(target);
        let pair = push(&mut m, Type::Array { element: 1, len: 2 });
        let mut params = vec![1; 7];
        params.push(pair);
        let mut sig = signature(params, 1, "c");
        sig.variadic = true;
        let mut actual = sig.params.clone();
        actual.push(1);
        let plan = plan_call(&m, target, &sig, &actual, &vec![vec![]; actual.len()]).unwrap();
        let boundary = plan.variadic.unwrap();
        assert_eq!((boundary.named_gp, boundary.named_stack_bytes), (8, 16));
        assert_eq!(
            plan.args.last().unwrap().location,
            AbiLocation::Stack { offset: 16 }
        );
        let empty = push(
            &mut m,
            Type::Struct {
                fields: vec![],
                packed: false,
            },
        );
        let huge_empty = push(
            &mut m,
            Type::Array {
                element: empty,
                len: u64::MAX,
            },
        );
        let mut sig = signature(vec![huge_empty], 1, "c");
        sig.variadic = true;
        let plan = plan_call(&m, target, &sig, &[huge_empty, 1], &[vec![], vec![]]).unwrap();
        assert_eq!(plan.variadic.unwrap().named_gp, 0);
        assert_eq!(plan.args[0].param, Some(1));
        assert_eq!(plan.args[0].location, AbiLocation::Register("x0"));
    }

    #[test]
    fn unsupported_variadic_tails_reject_before_any_aggregate_leaf_expansion() {
        for target in [
            Target::X86_64UnknownNone,
            Target::Aarch64UnknownNone,
            Target::Riscv64UnknownNone,
        ] {
            let mut m = module(target);
            let float = push(&mut m, Type::Float { bits: 128 });
            let empty_float = push(
                &mut m,
                Type::Array {
                    element: float,
                    len: 0,
                },
            );
            let huge = push(
                &mut m,
                Type::Array {
                    element: 1,
                    len: u64::MAX,
                },
            );
            let empty = push(
                &mut m,
                Type::Struct {
                    fields: vec![],
                    packed: false,
                },
            );
            let wide = push(&mut m, Type::Int { bits: 128 });
            let other_as = push(&mut m, Type::Pointer { address_space: 1 });
            let mut sig = signature(vec![], 1, "c");
            sig.variadic = true;
            for tail in [float, empty_float, huge, empty, wide, other_as, 0] {
                let error = plan_call(&m, target, &sig, &[tail], &[vec![]]).unwrap_err();
                assert!(format!("{error:?}").contains("variadic arguments"));
            }
        }
    }

    #[test]
    fn variadic_call_counts_attribute_inventories_and_fixed_call_contracts_stay_closed() {
        let target = Target::X86_64UnknownNone;
        let m = module(target);
        let mut sig = signature(vec![1], 1, "c");
        sig.variadic = true;
        assert!(plan_call(&m, target, &sig, &[], &[]).is_err());
        assert!(plan_call(&m, target, &sig, &[1, 1], &[]).is_err());
        assert!(plan_call(&m, target, &sig, &[1, 1], &[vec![]]).is_err());
        sig.param_attributes = vec![vec![], vec![]];
        assert!(plan_call(&m, target, &sig, &[1, 1, 1], &[vec![], vec![], vec![]]).is_err());
        sig.param_attributes.clear();
        sig.abi = "fastcc".into();
        assert!(plan_call(&m, target, &sig, &[1], &[vec![]]).is_err());
        sig.abi = "c".into();
        sig.variadic = false;
        assert!(plan_call(&m, target, &sig, &[1, 1], &[vec![], vec![]]).is_err());
        assert!(plan_call(&m, target, &sig, &[1], &[])
            .unwrap()
            .variadic
            .is_none());
    }
}
