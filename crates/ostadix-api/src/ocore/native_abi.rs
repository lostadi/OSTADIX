//! Shared placement of original LLVM C/fastcc integer aggregate values and
//! scalar integer, AS0-pointer and C floating-point arguments.
//!
//! These are LLVM IR lowering rules, after the source frontend has performed
//! its language ABI classification. They do not reclassify a C source struct.
use std::collections::{BTreeMap, HashSet};

use super::native_ir::{
    error_diagnostic, Function, NativeModule, Signature, SourceAbiWitness, Type, TypeId,
};
use super::native_verify::{type_layouts, value_leaf_layouts};
use super::Diagnostic;
use super::Target;

/// Full general-register names; emitters select the narrow spelling from
/// `AbiPart::location_bits`. Stack offsets start at the caller's argument area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum AbiLocation {
    Register(&'static str),
    Stack { offset: u64 },
    IndirectResult { offset: u64 },
}

/// Required source extension to the location width. `Any` permits a chosen
/// deterministic refinement of unspecified high bits, not a signedness claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Extension {
    None,
    Any,
    Sign,
    Zero,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AbiPart {
    pub param: Option<usize>,
    pub leaf: usize,
    pub ty: TypeId,
    pub offset: u64,
    pub location: AbiLocation,
    pub extension: Extension,
    pub location_bits: u16,
    /// Physical transfer class, independent of the scalar's original type.
    pub class: AbiClass,
    /// Significant bits transferred, starting at bit_offset in this scalar leaf.
    pub value_bits: u16,
    pub bit_offset: u16,
    /// RV64 LP64D passes f32 in an FLEN64 register with its high bits set.
    pub nan_box: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub enum AbiClass {
    #[default]
    General,
    Float,
    X87,
}

/// LLVM's Fast argument classifier need not be its return classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiRole {
    Argument,
    Result,
}

fn result_registers(target: Target) -> &'static [&'static str] {
    match target {
        Target::X86_64UnknownNone => &["rax", "rdx", "rcx"],
        Target::Aarch64UnknownNone => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        Target::Riscv64UnknownNone => &["a0", "a1"],
    }
}

pub fn is_fast_float_signature(module: &NativeModule, signature: &Signature) -> bool {
    signature.abi == "fastcc"
        && signature
            .params
            .iter()
            .copied()
            .chain(std::iter::once(signature.result))
            .any(|ty| matches!(module.types.get(ty), Some(Type::Float { .. })))
}

/// A bounded source-to-canonical-profile proof, not CPU reconstruction. Raw
/// attributes stay in the function and independent source accounting. In
/// particular a Linux ISA enum alone is not an original Linux ABI witness.
fn fast_float_source(
    module: &NativeModule,
    target: Target,
    signature: &Signature,
    source: Option<&SourceAbiWitness>,
) -> Result<bool, Diagnostic> {
    if !is_fast_float_signature(module, signature) {
        return Ok(false);
    }
    profile(module, target)?;
    let triple: Vec<_> = module.target.triple.split('-').collect();
    if !matches!(triple.as_slice(), [_, vendor, "linux", "gnu" | "musl"] if !vendor.is_empty()) {
        return Err(fail(
            "Fast floating transport requires the original Linux ELF ABI profile",
        ));
    }
    let source = source.ok_or_else(|| {
        fail("Fast floating transport requires an original per-function source ABI witness")
    })?;
    let cpu = source
        .target_cpu
        .as_deref()
        .ok_or_else(|| fail("Fast floating source CPU is unproved"))?;
    let features = source
        .target_features
        .as_deref()
        .ok_or_else(|| fail("Fast floating source features are unproved"))?;
    let baseline_cpu = match target {
        Target::X86_64UnknownNone => matches!(cpu, "generic" | "x86-64"),
        Target::Aarch64UnknownNone => cpu == "generic",
        Target::Riscv64UnknownNone => cpu == "generic-rv64",
    };
    if !baseline_cpu || features.is_empty() || features.contains('\0') {
        return Err(fail(
            "unsupported Fast floating source CPU/feature legalization profile",
        ));
    }
    let (mut fp, mut wide, mut excluded) = (false, false, false);
    for token in features.split(',') {
        let (enabled, name) = match token.as_bytes().first() {
            Some(b'+') => (true, &token[1..]),
            Some(b'-') => (false, &token[1..]),
            _ => return Err(fail("malformed ordered source target-features witness")),
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        {
            return Err(fail("malformed source target-feature name"));
        }
        // Only the reviewed baseline positive feature sets are admitted in
        // this slice. Unknown extensions/CPUs must not silently enable another
        // floating legalization or register ABI. Negative optional extensions
        // cannot restore a disabled prerequisite; relevant prerequisites are
        // handled below. Broader source profiles need their own proof.
        if enabled {
            let known = match target {
                Target::Riscv64UnknownNone => matches!(
                    name,
                    "64bit"
                        | "a"
                        | "c"
                        | "d"
                        | "f"
                        | "i"
                        | "m"
                        | "relax"
                        | "zaamo"
                        | "zalrsc"
                        | "zca"
                        | "zcd"
                        | "zicsr"
                        | "zmmul"
                        | "e"
                        | "zfinx"
                        | "zdinx"
                        | "zhinx"
                        | "zhinxmin"
                ),
                Target::X86_64UnknownNone => matches!(
                    name,
                    "cmov" | "cx8" | "fxsr" | "mmx" | "sse" | "sse2" | "x87" | "soft-float"
                ),
                Target::Aarch64UnknownNone => matches!(
                    name,
                    "fp-armv8"
                        | "neon"
                        | "v8a"
                        | "outline-atomics"
                        | "sve"
                        | "sve2"
                        | "sme"
                        | "sme2"
                ),
            };
            if !known {
                return Err(fail("unproved Fast floating source feature implication"));
            }
        }
        if !enabled
            && match target {
                Target::Riscv64UnknownNone => name == "64bit",
                Target::X86_64UnknownNone => {
                    matches!(name, "cmov" | "cx8" | "fxsr" | "mmx" | "x87")
                }
                Target::Aarch64UnknownNone => matches!(name, "neon" | "v8a"),
            }
        {
            excluded = true;
        }
        match target {
            Target::Riscv64UnknownNone => match (enabled, name) {
                (true, "d" | "q" | "zcd" | "zve64d" | "v") => {
                    fp = true;
                    wide = true;
                }
                (true, "f") => fp = true,
                (false, "d") => wide = false,
                (false, "f" | "zicsr") => {
                    fp = false;
                    wide = false;
                }
                (true, "e" | "zfinx" | "zdinx" | "zhinx" | "zhinxmin") => excluded = true,
                // Unmodeled positive features never restore disabled F/D.
                _ => {}
            },
            Target::X86_64UnknownNone => match (enabled, name) {
                (true, "sse2") => {
                    fp = true;
                    wide = true;
                }
                (false, "sse" | "sse2") => {
                    fp = false;
                    wide = false;
                }
                (true, "soft-float") => excluded = true,
                _ => {}
            },
            Target::Aarch64UnknownNone => match (enabled, name) {
                (true, "fp-armv8") => {
                    fp = true;
                    wide = true;
                }
                (false, "fp-armv8") => {
                    fp = false;
                    wide = false;
                }
                (true, "sve" | "sve2" | "sme" | "sme2") => excluded = true,
                _ => {}
            },
        }
    }
    if excluded || !fp || !wide {
        return Err(fail("Fast scalar f32/f64 requires proved baseline floating legalization; excluded profiles remain unsupported"));
    }
    Ok(true)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReturnStoragePlan {
    pub explicit_param: Option<usize>,
    pub ty: TypeId,
    pub size: u64,
    pub alignment: u64,
    pub pointer_location: AbiLocation,
    pub pointer_return: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VariadicPlan {
    pub named_gp: usize,
    pub named_fp: usize,
    pub named_stack_bytes: u64,
    pub gp_registers: &'static [&'static str],
    /// Actual SysV XMM argument-register usage, including unnamed arguments.
    /// This does not describe the complete callee register-save area.
    pub vector_register_count: u8,
}

// Integer tails use the ordinary GP allocation on all supported profiles:
// https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex
// https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
// https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#_integer_calling_convention
// Scalar floating-point placement follows the same primary ABI documents.
// Floating aggregates/HFAs and fastcc FP require their own LLVM IR classifier.

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
        self.plan_with_source(signature, None)
    }

    pub fn plan_function(&self, function: &Function) -> Result<AbiPlan, Diagnostic> {
        self.plan_with_source(&function.signature, function.source_abi.as_ref())
    }

    fn plan_with_source(
        &self,
        signature: &Signature,
        source: Option<&SourceAbiWitness>,
    ) -> Result<AbiPlan, Diagnostic> {
        audit_signature(self.module, self.target, signature)?;
        self.plan_arguments(
            signature,
            &signature.params,
            &signature.param_attributes,
            signature.params.len(),
            source,
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
        self.plan_call_with_source(signature, actual_types, actual_attrs, None)
    }

    pub fn plan_call_from(
        &self,
        caller: &Function,
        signature: &Signature,
        actual_types: &[TypeId],
        actual_attrs: &[Vec<String>],
    ) -> Result<AbiPlan, Diagnostic> {
        self.plan_call_with_source(
            signature,
            actual_types,
            actual_attrs,
            caller.source_abi.as_ref(),
        )
    }

    /// Selected compiler-runtime interfaces are ordinary fixed C interfaces,
    /// even inside a Fast function. Primitive descriptors avoid inventing
    /// source TypeIds for the catalog's i64 numeric conversion bridges.
    pub fn plan_helper(
        &self,
        helper: &super::native_floating_helpers::HelperRequirement,
        actual_types: &[TypeId],
        result: TypeId,
    ) -> Result<AbiPlan, Diagnostic> {
        use super::native_floating_helpers::HelperType;
        if helper.params.len() != actual_types.len() || helper.params.len() > 2 {
            return Err(fail("unsupported compiler-runtime C helper arity"));
        }
        let mut arguments = Placement::with_role(self.target, "c", AbiRole::Argument);
        arguments.hard_float = self.module.target.abi.as_deref() == Some("lp64d");
        let mut args = Vec::new();
        for (index, (kind, ty)) in helper.params.iter().zip(actual_types).enumerate() {
            match kind {
                HelperType::Float {
                    bits: 32 | 64 | 128,
                } => {
                    let HelperType::Float { bits } = kind else {
                        unreachable!()
                    };
                    args.extend(
                        arguments
                            .floating(*bits, false)?
                            .into_iter()
                            .map(|p| p.part(Some(index), *ty)),
                    );
                }
                HelperType::Int { bits: 64 } => args.push(
                    FloatTransfer {
                        location: arguments.ordinary()?,
                        class: AbiClass::General,
                        value_bits: 64,
                        bit_offset: 0,
                        location_bits: 64,
                        nan_box: false,
                    }
                    .part(Some(index), *ty),
                ),
                _ => return Err(fail("unsupported compiler-runtime C helper primitive")),
            }
        }
        let mut returned = Placement::with_role(self.target, "c", AbiRole::Result);
        returned.hard_float = arguments.hard_float;
        let results = match helper.result {
            HelperType::Float {
                bits: bits @ (32 | 64 | 128),
            } => returned
                .floating(bits, false)?
                .into_iter()
                .map(|p| p.part(None, result))
                .collect(),
            HelperType::Int { bits: 64 } => vec![FloatTransfer {
                location: AbiLocation::Register(result_registers(self.target)[0]),
                class: AbiClass::General,
                value_bits: 64,
                bit_offset: 0,
                location_bits: 64,
                nan_box: false,
            }
            .part(None, result)],
            _ => return Err(fail("unsupported compiler-runtime C helper result")),
        };
        if arguments.stack != 0 {
            return Err(fail(
                "compiler-runtime C helper needs an extended call frame",
            ));
        }
        Ok(AbiPlan {
            args,
            results,
            storage: None,
            stack_bytes: 0,
            stack_alignment: 16,
            variadic: None,
        })
    }

    fn plan_call_with_source(
        &self,
        signature: &Signature,
        actual_types: &[TypeId],
        actual_attrs: &[Vec<String>],
        source: Option<&SourceAbiWitness>,
    ) -> Result<AbiPlan, Diagnostic> {
        let fixed = prepare_call_signature(
            self.module,
            self.target,
            signature,
            actual_types,
            actual_attrs,
        )?;
        self.plan_arguments(
            &fixed,
            actual_types,
            actual_attrs,
            signature.params.len(),
            source,
        )
    }

    fn plan_arguments(
        &self,
        signature: &Signature,
        actual_types: &[TypeId],
        actual_attrs: &[Vec<String>],
        named_count: usize,
        source: Option<&SourceAbiWitness>,
    ) -> Result<AbiPlan, Diagnostic> {
        let fast_float = fast_float_source(self.module, self.target, signature, source)?;
        let result_leaves = if matches!(self.ty(signature.result)?, Type::Void) {
            &[][..]
        } else {
            self.value_leaves(signature.result)?
        };
        // RISCVISelLowering uses CC_RISCV, not FastCC, for returns.
        let result_registers = result_registers(self.target);
        let result_float = match self.ty(signature.result)? {
            Type::Float { bits } => Some(*bits),
            _ => None,
        };
        let result_i128 = matches!(self.ty(signature.result)?, Type::Int { bits: 128 });
        let implicit =
            result_float.is_none() && !result_i128 && result_leaves.len() > result_registers.len();
        let mut placement = Placement::new(self.target, &signature.abi);
        placement.fast_float = fast_float;
        placement.hard_float = self.module.target.abi.as_deref() == Some("lp64d");
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
            if let Type::Float { bits } = self.ty(ty)? {
                self.audit_float_layout(ty, *bits)?;
                for transfer in placement.floating(*bits, param >= named_count)? {
                    args.push(transfer.part(Some(param), ty));
                }
                continue;
            }
            if matches!(self.ty(ty)?, Type::Int { bits: 128 }) {
                self.audit_i128_layout(ty)?;
                args.extend(
                    placement
                        .wide_integer(param >= named_count)?
                        .into_iter()
                        .map(|transfer| transfer.part(Some(param), ty)),
                );
                continue;
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
                    class: AbiClass::General,
                    value_bits: bits,
                    bit_offset: 0,
                    nan_box: false,
                });
            }
        }
        if signature.variadic && variadic.is_none() {
            variadic = Some(placement.variadic());
        }
        if let Some(metadata) = &mut variadic {
            metadata.vector_register_count = if self.target == Target::X86_64UnknownNone {
                placement.fp_next as u8
            } else {
                0
            };
        }
        let mut results = Vec::new();
        if let Some(bits) = result_float {
            self.audit_float_layout(signature.result, bits)?;
            let mut returned = Placement::with_role(self.target, &signature.abi, AbiRole::Result);
            returned.hard_float = placement.hard_float;
            let transfers = if bits == 80 {
                vec![FloatTransfer {
                    location: AbiLocation::Register("st(0)"),
                    class: AbiClass::X87,
                    value_bits: 80,
                    bit_offset: 0,
                    location_bits: 80,
                    nan_box: false,
                }]
            } else {
                returned.floating(bits, false)?
            };
            results.extend(
                transfers
                    .into_iter()
                    .map(|transfer| transfer.part(None, signature.result)),
            );
        } else if result_i128 {
            self.audit_i128_layout(signature.result)?;
            for (index, register) in result_registers[..2].iter().copied().enumerate() {
                results.push(
                    FloatTransfer {
                        location: AbiLocation::Register(register),
                        class: AbiClass::General,
                        value_bits: 64,
                        bit_offset: index as u16 * 64,
                        location_bits: 64,
                        nan_box: false,
                    }
                    .part(None, signature.result),
                );
            }
        } else {
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
                    let width =
                        location_width(self.target, bits, true, &signature.result_attributes);
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
                    class: AbiClass::General,
                    value_bits: bits,
                    bit_offset: 0,
                    nan_box: false,
                });
            }
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

    fn audit_i128_layout(&self, ty: TypeId) -> Result<(), Diagnostic> {
        if self.allocation(ty)? != (16, 16) {
            return Err(fail("i128 value ABI requires size 16 and alignment 16"));
        }
        Ok(())
    }

    fn audit_float_layout(&self, ty: TypeId, bits: u16) -> Result<(), Diagnostic> {
        let expected = match bits {
            32 => (4, 4),
            64 => (8, 8),
            80 | 128 => (16, 16),
            _ => return Err(fail("unsupported floating-point ABI width")),
        };
        if self.allocation(ty)? != expected {
            return Err(fail(format!(
                "f{bits} requires ABI size/alignment {expected:?}"
            )));
        }
        Ok(())
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

#[derive(Debug)]
struct FloatTransfer {
    location: AbiLocation,
    class: AbiClass,
    value_bits: u16,
    bit_offset: u16,
    location_bits: u16,
    nan_box: bool,
}

impl FloatTransfer {
    fn part(self, param: Option<usize>, ty: TypeId) -> AbiPart {
        AbiPart {
            param,
            leaf: 0,
            ty,
            offset: u64::from(self.bit_offset / 8),
            location: self.location,
            extension: if self.class == AbiClass::General && self.value_bits < self.location_bits {
                Extension::Any
            } else {
                Extension::None
            },
            location_bits: self.location_bits,
            class: self.class,
            value_bits: self.value_bits,
            bit_offset: self.bit_offset,
            nan_box: self.nan_box,
        }
    }
}

struct Placement {
    role: AbiRole,
    fast_float: bool,
    target: Target,
    registers: &'static [&'static str],
    next: usize,
    fp_next: usize,
    hard_float: bool,
    stack: u64,
}

impl Placement {
    fn new(target: Target, abi: &str) -> Self {
        Self::with_role(target, abi, AbiRole::Argument)
    }

    fn with_role(target: Target, abi: &str, role: AbiRole) -> Self {
        let registers = match target {
            Target::X86_64UnknownNone => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"][..],
            Target::Aarch64UnknownNone => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"][..],
            Target::Riscv64UnknownNone if abi == "fastcc" && role == AbiRole::Argument => &[
                "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "t3", "t4", "t5", "t6",
            ][..],
            Target::Riscv64UnknownNone => &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"][..],
        };
        Self {
            role,
            fast_float: false,
            target,
            registers,
            next: 0,
            fp_next: 0,
            hard_float: false,
            stack: 0,
        }
    }

    fn ordinary(&mut self) -> Result<AbiLocation, Diagnostic> {
        if let Some(reg) = self.registers.get(self.next) {
            self.next += 1;
            Ok(AbiLocation::Register(reg))
        } else {
            let offset = align_up(self.stack, 8)?;
            self.stack = add(offset, 8)?;
            Ok(AbiLocation::Stack { offset })
        }
    }

    /// Scalar i128 has two INTEGER-class eightbytes on SysV, an aligned
    /// register pair on AAPCS64, and the base integer psABI pair on RV64.
    /// This is not an aggregate classification or a fastcc legalization rule.
    fn wide_integer(&mut self, unnamed: bool) -> Result<Vec<FloatTransfer>, Diagnostic> {
        let locations = match self.target {
            Target::X86_64UnknownNone => {
                if self.next + 1 < self.registers.len() {
                    [self.ordinary()?, self.ordinary()?]
                } else {
                    // SysV reverts an unsuccessful whole-argument register
                    // allocation: the remaining register belongs to later args.
                    let base = self.block(2, 16)?;
                    [
                        AbiLocation::Stack { offset: base },
                        AbiLocation::Stack {
                            offset: add(base, 8)?,
                        },
                    ]
                }
            }
            Target::Aarch64UnknownNone => {
                // AAPCS64 C.8-C.10: 16-byte fundamental values require an
                // even NGRN and cannot split between registers and the stack.
                self.next = (self.next + 1) & !1;
                if self.next + 1 < self.registers.len() {
                    [self.ordinary()?, self.ordinary()?]
                } else {
                    self.next = self.registers.len();
                    let base = self.block(2, 16)?;
                    [
                        AbiLocation::Stack { offset: base },
                        AbiLocation::Stack {
                            offset: add(base, 8)?,
                        },
                    ]
                }
            }
            Target::Riscv64UnknownNone => {
                // A named 2*XLEN scalar may straddle a7/stack. A variadic
                // 16-byte-aligned scalar needs an even pair; failure closes
                // the GP bank for all following unnamed arguments.
                if unnamed {
                    self.next = (self.next + 1) & !1;
                }
                if self.next + 1 < self.registers.len()
                    || (!unnamed && self.next < self.registers.len())
                {
                    [self.ordinary()?, self.ordinary()?]
                } else {
                    self.next = self.registers.len();
                    let base = self.block(2, 16)?;
                    [
                        AbiLocation::Stack { offset: base },
                        AbiLocation::Stack {
                            offset: add(base, 8)?,
                        },
                    ]
                }
            }
        };
        Ok(locations
            .into_iter()
            .enumerate()
            .map(|(index, location)| FloatTransfer {
                location,
                class: AbiClass::General,
                value_bits: 64,
                bit_offset: index as u16 * 64,
                location_bits: 64,
                nan_box: false,
            })
            .collect())
    }

    fn floating(&mut self, bits: u16, unnamed: bool) -> Result<Vec<FloatTransfer>, Diagnostic> {
        if !matches!(bits, 32 | 64 | 80 | 128)
            || (bits == 80 && self.target != Target::X86_64UnknownNone)
        {
            return Err(fail("unsupported target floating-point ABI type"));
        }
        if self.target == Target::Riscv64UnknownNone {
            if self.role == AbiRole::Argument && self.fast_float {
                if unnamed || !matches!(bits, 32 | 64) {
                    return Err(fail("unsupported Fast floating argument format"));
                }
                const FAST_FP: [&str; 20] = [
                    "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7", "ft0", "ft1", "ft2",
                    "ft3", "ft4", "ft5", "ft6", "ft7", "ft8", "ft9", "ft10", "ft11",
                ];
                let location = if let Some(register) = FAST_FP.get(self.fp_next) {
                    self.fp_next += 1;
                    AbiLocation::Register(*register)
                } else {
                    let bytes = u64::from(bits / 8);
                    let offset = align_up(self.stack, bytes)?;
                    self.stack = add(offset, bytes)?;
                    AbiLocation::Stack { offset }
                };
                return Ok(vec![FloatTransfer {
                    location,
                    class: AbiClass::Float,
                    value_bits: bits,
                    bit_offset: 0,
                    location_bits: if matches!(location, AbiLocation::Register(_)) {
                        64
                    } else {
                        bits
                    },
                    nan_box: bits == 32 && matches!(location, AbiLocation::Register(_)),
                }]);
            }
            // psABI 2.2: only named f32/f64 use the LP64D FP bank.
            // Narrow FP values are NaN-boxed, not integer sign-extended.
            if self.hard_float && !unnamed && bits <= 64 && self.fp_next < 8 {
                let reg = ["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"][self.fp_next];
                self.fp_next += 1;
                return Ok(vec![FloatTransfer {
                    location: AbiLocation::Register(reg),
                    class: AbiClass::Float,
                    value_bits: bits,
                    bit_offset: 0,
                    location_bits: 64,
                    nan_box: bits == 32,
                }]);
            }
            if bits == 128 {
                return self.wide_integer(unnamed);
            }
            return Ok(vec![FloatTransfer {
                location: self.ordinary()?,
                class: AbiClass::General,
                value_bits: bits,
                bit_offset: 0,
                location_bits: 64,
                nan_box: false,
            }]);
        }
        if bits != 80 && self.fp_next < 8 {
            let index = self.fp_next;
            self.fp_next += 1;
            let reg = if self.target == Target::X86_64UnknownNone {
                [
                    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
                ][index]
            } else {
                match bits {
                    32 => ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"][index],
                    64 => ["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"][index],
                    128 => ["q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7"][index],
                    _ => unreachable!(),
                }
            };
            return Ok(vec![FloatTransfer {
                location: AbiLocation::Register(reg),
                class: AbiClass::Float,
                value_bits: bits,
                bit_offset: 0,
                location_bits: bits,
                nan_box: false,
            }]);
        }
        // SysV X87 arguments are memory values, while IEEE binary128 occupies
        // one XMM register (SSE+SSEUP). AAPCS64 scalar FP uses one v register.
        // The significant 80-bit x87 value occupies a 16-byte ABI stack slot.
        let bytes = if bits > 64 { 16 } else { 8 };
        let base = self.block(bytes / 8, bytes as u64)?;
        Ok(vec![FloatTransfer {
            location: AbiLocation::Stack { offset: base },
            class: if bits == 80 {
                AbiClass::X87
            } else {
                AbiClass::Float
            },
            value_bits: bits,
            bit_offset: 0,
            location_bits: bits,
            nan_box: false,
        }])
    }

    fn variadic(&self) -> VariadicPlan {
        VariadicPlan {
            named_gp: self.next,
            named_fp: self.fp_next,
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
    let mut roots: Vec<_> = sig
        .params
        .iter()
        .copied()
        .map(|id| (id, false, false))
        .collect();
    if !matches!(ty(sig.result)?, Type::Void) {
        roots.push((sig.result, false, false));
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
        // Payload storage is not a by-value ABI interface. Keep its
        // visitation context distinct so it cannot authorize a value root.
        roots.push((storage.ty, false, true));
    }
    let mut seen = HashSet::new();
    while let Some((id, nested, storage)) = roots.pop() {
        if !seen.insert((id, nested, storage)) {
            continue;
        }
        match ty(id)? {
            Type::Int { bits: 1..=64 } | Type::Pointer { address_space: 0 } => (),
            Type::Int { bits: 128 } if storage || (!nested && sig.abi == "c") => (),
            Type::Int { bits: 128 } => return Err(fail("i128 aggregate value ABI and fastcc require explicit lowering")),
            Type::Float { bits } if storage => audit_float_format(target, *bits)?,
            Type::Float { bits } if !nested => audit_float_type(module, target, &sig.abi, *bits)?,
            Type::Float { .. } => return Err(fail("floating-point aggregate ABI/HFA requires explicit lowering")),
            Type::Array { element, .. } => roots.push((*element, true, storage)),
            Type::Struct { fields, .. } => roots.extend(fields.iter().map(|id| (*id, true, storage))),
            _ => return Err(fail(format!("unsupported original ABI type {id}; vectors, unsupported integer widths and opaque/byval ABI require explicit lowering"))),
        }
    }
    Ok(())
}

fn audit_float_type(
    module: &NativeModule,
    target: Target,
    abi: &str,
    bits: u16,
) -> Result<(), Diagnostic> {
    if abi != "c" && !(abi == "fastcc" && matches!(bits, 32 | 64)) {
        return Err(fail(
            "floating-point ABI is currently implemented only for LLVM C signatures",
        ));
    }
    audit_float_format(target, bits)?;
    if target == Target::Riscv64UnknownNone
        && !matches!(module.target.abi.as_deref(), Some("lp64" | "lp64d"))
    {
        return Err(fail(
            "floating-point RV64 ABI requires explicit original lp64 or lp64d",
        ));
    }
    Ok(())
}

fn audit_float_format(target: Target, bits: u16) -> Result<(), Diagnostic> {
    if !matches!(bits, 32 | 64 | 80 | 128) || (bits == 80 && target != Target::X86_64UnknownNone) {
        return Err(fail("unsupported target floating-point scalar width"));
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
            || !matches!(ty, Type::Int { bits: 1..=64 })
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
            (Type::Float { bits: a }, Type::Float { bits: b }) if a == b => {}
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
        } else {
            match module.types.get(ty) {
                Some(Type::Int { bits: 1..=64 | 128 } | Type::Pointer { address_space: 0 }) => (),
                Some(Type::Float { bits }) => audit_float_type(module, target, &signature.abi, *bits)?,
                _ => return Err(fail("variadic arguments require scalar integers up to 64 bits or exactly i128, AS0 pointers or supported floating-point scalars; aggregates require additional ABI lowering")),
            }
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

pub fn plan_function(
    module: &NativeModule,
    target: Target,
    function: &Function,
) -> Result<AbiPlan, Diagnostic> {
    audit_signature(module, target, &function.signature)?;
    let mut roots = function.signature.params.clone();
    roots.push(function.signature.result);
    let layouts = type_layouts(module)?;
    let leaves = value_leaf_layouts(module, &roots)?;
    AbiContext::new(module, target, &leaves, &layouts)?.plan_function(function)
}

pub fn plan_call_from(
    module: &NativeModule,
    target: Target,
    caller: &Function,
    signature: &Signature,
    actual_types: &[TypeId],
    actual_attrs: &[Vec<String>],
) -> Result<AbiPlan, Diagnostic> {
    prepare_call_signature(module, target, signature, actual_types, actual_attrs)?;
    let mut roots = actual_types.to_vec();
    roots.push(signature.result);
    let layouts = type_layouts(module)?;
    let leaves = value_leaf_layouts(module, &roots)?;
    AbiContext::new(module, target, &leaves, &layouts)?.plan_call_from(
        caller,
        signature,
        actual_types,
        actual_attrs,
    )
}

/// After ordinary type/dominance/call verification. Layout helpers only;
/// never recurse through verify or a codegen audit.
pub fn audit_fast_float_interfaces(module: &NativeModule) -> Result<(), Diagnostic> {
    use super::native_ir::{Operand, Operation, Terminator};
    let mut roots = Vec::new();
    for function in &module.functions {
        if is_fast_float_signature(module, &function.signature) && function.entry.is_some() {
            roots.extend(function.signature.params.iter().copied());
            roots.push(function.signature.result);
        }
        for instruction in function.blocks.iter().flat_map(|block| &block.instructions) {
            if let Operation::Call { signature, .. } = &instruction.operation {
                if is_fast_float_signature(module, signature) {
                    roots.extend(signature.params.iter().copied());
                    roots.push(signature.result);
                }
            }
        }
        if function.blocks.iter().any(|block| {
            matches!(&block.terminator,
            Terminator::Invoke { signature, .. } if is_fast_float_signature(module, signature))
        }) {
            return Err(fail(
                "Fast floating invoke requires a separately qualified interface",
            ));
        }
    }
    if roots.is_empty() {
        return Ok(());
    }
    let arch = module.target.triple.split('-').next().unwrap_or("");
    let target = Target::parse(&format!("{arch}-unknown-none"))
        .ok_or_else(|| fail("unsupported original Fast floating architecture"))?;
    let layouts = type_layouts(module)?;
    let leaves = value_leaf_layouts(module, &roots)?;
    let context = AbiContext::new(module, target, &leaves, &layouts)?;
    for caller in &module.functions {
        if is_fast_float_signature(module, &caller.signature) && caller.entry.is_some() {
            context.plan_function(caller)?;
        }
        for instruction in caller.blocks.iter().flat_map(|block| &block.instructions) {
            let Operation::Call {
                callee, signature, ..
            } = &instruction.operation
            else {
                continue;
            };
            if !is_fast_float_signature(module, signature) {
                continue;
            }
            let Operand::Symbol { name, ty } = callee else {
                return Err(fail(
                    "indirect Fast floating calls require an explicit qualified interface witness",
                ));
            };
            if !matches!(
                module.types.get(*ty),
                Some(Type::Pointer { address_space: 0 })
            ) {
                return Err(fail(
                    "Fast floating calls require a direct integral AS0 function symbol",
                ));
            }
            let callee = module
                .functions
                .iter()
                .find(|function| &function.name == name)
                .ok_or_else(|| {
                    fail("Fast floating aliases and nonfunction symbols are unsupported")
                })?;
            // Actual argument types were already checked by the ordinary
            // verifier. Fast never enters a C-only extension adaptation.
            if signature != &callee.signature {
                return Err(fail(
                    "Fast floating call/declaration signatures must remain exact",
                ));
            }
            let outgoing = context.plan_call_from(
                caller,
                signature,
                &signature.params,
                &signature.param_attributes,
            )?;
            if callee.entry.is_some() {
                let incoming = context.plan_function(callee)?;
                if outgoing != incoming {
                    return Err(fail("Fast floating caller/callee transport maps differ"));
                }
            }
            // External declarations remain original open interfaces. Package
            // resolution must check the actual implementation witness/map.
        }
    }
    Ok(())
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
        None,
    )
}

/// A comparison of two retained source contracts, never signature inheritance.
/// Only proven nonnegative i32 arguments may bridge a bare call to signext.
/// Planning uses layout-only helpers, not module verification, so invoking this
/// from the independent verifier cannot recurse through verify/audit_module.
pub fn direct_i32_argument_transport(
    module: &NativeModule,
    declared: &Signature,
    call: &Signature,
    nonnegative: &[bool],
) -> Result<bool, Diagnostic> {
    if declared.abi != "c"
        || call.abi != "c"
        || declared.variadic
        || call.variadic
        || declared.params != call.params
        || nonnegative.len() != call.params.len()
        || (!declared.param_attributes.is_empty()
            && declared.param_attributes.len() != declared.params.len())
        || (!call.param_attributes.is_empty() && call.param_attributes.len() != call.params.len())
    {
        return Ok(false);
    }
    // Comparison-only replacement also keeps any future Signature fields strict.
    let mut comparison = declared.clone();
    comparison.param_attributes = call.param_attributes.clone();
    if comparison != *call {
        return Ok(false);
    }
    let mut changed = Vec::new();
    for (index, ty) in call.params.iter().enumerate() {
        let from = call
            .param_attributes
            .get(index)
            .map_or(&[][..], Vec::as_slice);
        let to = declared
            .param_attributes
            .get(index)
            .map_or(&[][..], Vec::as_slice);
        if from == to {
            continue;
        }
        if !from.is_empty()
            || to != ["signext"]
            || !nonnegative[index]
            || !matches!(module.types.get(*ty), Some(Type::Int { bits: 32 }))
        {
            return Ok(false);
        }
        changed.push(index);
    }
    if changed.is_empty() {
        return Ok(false);
    }
    let architecture = module.target.triple.split('-').next().unwrap_or("");
    let Some(target) = Target::parse(&format!("{architecture}-unknown-none")) else {
        return Ok(false);
    };
    profile(module, target)?;
    if !super::native_verify::integral_default_64_pointer_profile(module)? {
        return Ok(false);
    }
    if target == Target::Riscv64UnknownNone
        && !matches!(module.target.abi.as_deref(), Some("lp64" | "lp64d"))
    {
        return Ok(false);
    }
    let mut roots = call.params.clone();
    roots.push(call.result);
    let layouts = type_layouts(module)?;
    let leaves = value_leaf_layouts(module, &roots)?;
    let context = AbiContext::new(module, target, &leaves, &layouts)?;
    let mut caller = context.plan_call(call, &call.params, &call.param_attributes)?;
    let callee = context.plan(declared)?;
    if caller.args.len() != callee.args.len() {
        return Ok(false);
    }
    for (from, to) in caller.args.iter_mut().zip(&callee.args) {
        if from.extension == to.extension {
            continue;
        }
        let Some(index) = from.param else {
            return Ok(false);
        };
        if !changed.contains(&index)
            || from.class != AbiClass::General
            || from.value_bits != 32
            || from.bit_offset != 0
            || from.nan_box
            || from.extension != Extension::Any
            || to.extension != Extension::Sign
        {
            return Ok(false);
        }
        // This uses the concrete owned emitter's deterministic Any refinement,
        // not abstract equivalence of unspecified upper bits. Both register and
        // stack placement run extend_abi_part after reloading the original SSA
        // spill/immediate. It first clears bits above 31 (x86 eax write, AArch64
        // ubfx, RV64 logical shifts); only Sign then sign-extends. Bit31=0 makes
        // the two concrete actions equal. Stack args are placed before register
        // args, with no later caller-argument scratch overwrite.
        // The whole plan equality below checks every other field and part.
        from.extension = to.extension;
    }
    Ok(caller == callee)
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
                wide_volatile_profile: None,
                strict_fp_profile: None,
                linux_syscall_profile: None,
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
                noalias_metadata_graph_source: None,
                refinements: vec![],
            },
        }
    }

    #[test]
    fn proved_i32_arguments_compare_whole_original_plans_in_registers_and_stack() {
        for target in [
            Target::X86_64UnknownNone,
            Target::Aarch64UnknownNone,
            Target::Riscv64UnknownNone,
        ] {
            for abi in if target == Target::Riscv64UnknownNone {
                vec![Some("lp64"), Some("lp64d")]
            } else {
                vec![None]
            } {
                let mut m = module(target);
                m.target.abi = abi.map(str::to_owned);
                let mut call = signature(vec![3; 12], 1, "c");
                let mut declared = call.clone();
                declared.param_attributes = vec![vec![]; 12];
                for index in [0, 9, 11] {
                    declared.param_attributes[index] = vec!["signext".into()];
                }
                let before = (call.clone(), declared.clone());
                let mut proof = vec![false; 12];
                for index in [0, 9, 11] {
                    proof[index] = true;
                }
                assert!(direct_i32_argument_transport(&m, &declared, &call, &proof).unwrap());
                if target == Target::Riscv64UnknownNone {
                    let caller_plan = plan(&m, target, &call).unwrap();
                    let register = caller_plan
                        .args
                        .iter()
                        .find(|p| p.param == Some(0))
                        .unwrap();
                    let stack = caller_plan
                        .args
                        .iter()
                        .find(|p| p.param == Some(9))
                        .unwrap();
                    assert_eq!(register.location, AbiLocation::Register("a0"));
                    assert_eq!(stack.location, AbiLocation::Stack { offset: 8 });
                    assert_eq!(register.extension, Extension::Any);
                    assert_eq!(stack.extension, Extension::Any);
                }
                assert_eq!(before, (call.clone(), declared.clone()));
                for index in [0, 9, 11] {
                    let mut missing = proof.clone();
                    missing[index] = false;
                    assert!(
                        !direct_i32_argument_transport(&m, &declared, &call, &missing).unwrap()
                    );
                }
                call.param_attributes = vec![vec![]; 12];
                call.param_attributes[0] = vec!["zeroext".into()];
                assert!(!direct_i32_argument_transport(&m, &declared, &call, &proof).unwrap());
                let mut invalid = before.0.clone();
                invalid.result_attributes = vec!["signext".into()];
                assert!(!direct_i32_argument_transport(&m, &declared, &invalid, &proof).unwrap());
                let mut invalid = before.0.clone();
                invalid.abi = "fastcc".into();
                assert!(!direct_i32_argument_transport(&m, &declared, &invalid, &proof).unwrap());
                let mut invalid = before.0.clone();
                invalid.variadic = true;
                assert!(!direct_i32_argument_transport(&m, &declared, &invalid, &proof).unwrap());
                m.target.data_layout.push_str("-ni:1");
                assert!(!direct_i32_argument_transport(&m, &declared, &before.0, &proof).unwrap());
            }
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
        let wide = push(&mut m, Type::Int { bits: 65 });
        let zero_float = push(
            &mut m,
            Type::Array {
                element: float,
                len: 0,
            },
        );
        for ty in [wide, zero_float, 0] {
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
            let wide = push(&mut m, Type::Int { bits: 65 });
            let other_as = push(&mut m, Type::Pointer { address_space: 1 });
            let mut sig = signature(vec![], 1, "c");
            sig.variadic = true;
            for tail in [empty_float, huge, empty, wide, other_as, 0] {
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

    fn fast_witness(target: Target) -> SourceAbiWitness {
        let (cpu, features) = match target {
            Target::X86_64UnknownNone => ("x86-64", "+sse,+sse2"),
            Target::Aarch64UnknownNone => ("generic", "+fp-armv8,+neon,+v8a"),
            Target::Riscv64UnknownNone => ("generic-rv64", "+64bit,+d,+f,+zicsr,-e"),
        };
        SourceAbiWitness {
            target_cpu: Some(cpu.into()),
            target_features: Some(features.into()),
        }
    }

    fn fast_function(signature: Signature, witness: Option<SourceAbiWitness>) -> Function {
        serde_json::from_value(
            serde_json::json!({"name":"original_fast", "linkage":"external",
            "signature":signature, "source_abi":witness, "params":[], "entry":null, "blocks":[]}),
        )
        .unwrap()
    }

    #[test]
    fn fast_float_source_profiles_keep_argument_and_result_roles_separate() {
        for (target, abi) in [
            (Target::X86_64UnknownNone, None),
            (Target::Aarch64UnknownNone, None),
            (Target::Riscv64UnknownNone, Some("lp64")),
            (Target::Riscv64UnknownNone, Some("lp64d")),
        ] {
            let (m, f32, f64, _) = floating_module(target, abi);
            for ty in [f32, f64] {
                let sig = signature(vec![ty], ty, "fastcc");
                assert!(plan(&m, target, &sig).is_err());
                let function = fast_function(sig, Some(fast_witness(target)));
                let before = serde_json::to_value(&function).unwrap();
                let p = plan_function(&m, target, &function).unwrap();
                assert_eq!(p.args[0].class, AbiClass::Float);
                let expected = match target {
                    Target::X86_64UnknownNone => "xmm0",
                    Target::Aarch64UnknownNone if ty == f32 => "s0",
                    Target::Aarch64UnknownNone => "d0",
                    Target::Riscv64UnknownNone => "fa0",
                };
                assert_eq!(p.args[0].location, AbiLocation::Register(expected));
                if target == Target::Riscv64UnknownNone && abi == Some("lp64") {
                    assert_eq!(p.results[0].location, AbiLocation::Register("a0"));
                    assert_eq!(p.results[0].class, AbiClass::General);
                } else {
                    assert_eq!(p.results[0].location, AbiLocation::Register(expected));
                    assert_eq!(p.results[0].class, AbiClass::Float);
                }
                assert_eq!(serde_json::to_value(&function).unwrap(), before);
            }
        }
    }

    #[test]
    fn fast_rv_float_bank_is_twenty_aliasing_registers_then_packed_memory() {
        for abi in ["lp64", "lp64d"] {
            let target = Target::Riscv64UnknownNone;
            let (m, f32, f64, _) = floating_module(target, Some(abi));
            let mut parameters: Vec<_> = (0..20)
                .map(|n| if n % 2 == 0 { f32 } else { f64 })
                .collect();
            parameters.extend([f32, f32, f64]);
            let f = fast_function(
                signature(parameters, f64, "fastcc"),
                Some(fast_witness(target)),
            );
            let p = plan_function(&m, target, &f).unwrap();
            let names = [
                "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7", "ft0", "ft1", "ft2", "ft3",
                "ft4", "ft5", "ft6", "ft7", "ft8", "ft9", "ft10", "ft11",
            ];
            for (index, name) in names.iter().enumerate() {
                assert_eq!(p.args[index].location, AbiLocation::Register(name));
                assert_eq!(
                    p.args[index].value_bits,
                    if index % 2 == 0 { 32 } else { 64 }
                );
                assert_eq!(p.args[index].nan_box, index % 2 == 0);
            }
            for (index, offset, width) in [(20, 0, 32), (21, 4, 32), (22, 8, 64)] {
                assert_eq!(p.args[index].location, AbiLocation::Stack { offset });
                assert_eq!(p.args[index].location_bits, width);
                assert!(!p.args[index].nan_box);
            }
            assert_eq!(p.stack_bytes, 16);
        }
    }

    #[test]
    fn fast_packed_float_stack_does_not_misalign_exhausted_gp_arguments() {
        let target = Target::Riscv64UnknownNone;
        let (m, f32, f64, _) = floating_module(target, Some("lp64d"));
        let mut params = vec![f32; 21];
        params.extend(vec![1; 13]);
        params.push(f64);
        let f = fast_function(signature(params, 0, "fastcc"), Some(fast_witness(target)));
        let p = plan_function(&m, target, &f).unwrap();
        assert_eq!(p.args[20].location, AbiLocation::Stack { offset: 0 });
        assert_eq!(p.args[21].location, AbiLocation::Register("a0"));
        assert_eq!(p.args[32].location, AbiLocation::Register("t6"));
        assert_eq!(p.args[33].location, AbiLocation::Stack { offset: 8 });
        assert_eq!(p.args[34].location, AbiLocation::Stack { offset: 16 });
        assert_eq!(p.stack_bytes, 32);
    }

    #[test]
    fn fast_source_witness_is_not_borrowed_from_callee_or_linux_isa_name() {
        for (target, abi) in [
            (Target::X86_64UnknownNone, None),
            (Target::Aarch64UnknownNone, None),
            (Target::Riscv64UnknownNone, Some("lp64")),
            (Target::Riscv64UnknownNone, Some("lp64d")),
        ] {
            let (mut m, _, f64, f128) = floating_module(target, abi);
            let sig = signature(vec![f64], f64, "fastcc");
            let caller = fast_function(signature(vec![], 0, "c"), Some(fast_witness(target)));
            let callee = fast_function(sig.clone(), Some(fast_witness(target)));
            let incoming = plan_function(&m, target, &callee).unwrap();
            assert_eq!(
                plan_call_from(
                    &m,
                    target,
                    &caller,
                    &sig,
                    &sig.params,
                    &sig.param_attributes
                )
                .unwrap(),
                incoming
            );
            let mut absent = caller.clone();
            absent.source_abi = None;
            assert!(plan_call_from(
                &m,
                target,
                &absent,
                &sig,
                &sig.params,
                &sig.param_attributes
            )
            .is_err());
            let mut changed = caller.clone();
            changed
                .source_abi
                .as_mut()
                .unwrap()
                .target_features
                .as_mut()
                .unwrap()
                .push_str(",+unproved_fp_extension");
            assert!(plan_call_from(
                &m,
                target,
                &changed,
                &sig,
                &sig.params,
                &sig.param_attributes
            )
            .is_err());
            let mut changed = callee.clone();
            changed.source_abi.as_mut().unwrap().target_cpu = Some("unproved-cpu".into());
            assert!(plan_function(&m, target, &changed).is_err());
            let mut wide = callee.clone();
            wide.signature.params = vec![f128];
            assert!(plan_function(&m, target, &wide).is_err());
            m.target.triple = m.target.triple.replace("linux-gnu", "none-elf");
            assert!(plan_function(&m, target, &callee).is_err());
        }
    }

    #[test]
    fn compiler_runtime_helpers_always_use_shared_c_transport() {
        use super::super::native_floating_helpers::{HelperRequirement, HelperType};
        for (target, abi) in [
            (Target::X86_64UnknownNone, None),
            (Target::Aarch64UnknownNone, None),
            (Target::Riscv64UnknownNone, Some("lp64")),
            (Target::Riscv64UnknownNone, Some("lp64d")),
        ] {
            let (m, _, f64, _) = floating_module(target, abi);
            let layouts = type_layouts(&m).unwrap();
            let leaves = value_leaf_layouts(&m, &[f64]).unwrap();
            let context = AbiContext::new(&m, target, &leaves, &layouts).unwrap();
            let helper = HelperRequirement {
                name: "mechanism-only-C-f64-helper".into(),
                result: HelperType::Float { bits: 64 },
                params: vec![HelperType::Float { bits: 64 }; 2],
            };
            let ordinary = context.plan(&signature(vec![f64, f64], f64, "c")).unwrap();
            assert_eq!(
                context.plan_helper(&helper, &[f64, f64], f64).unwrap(),
                ordinary
            );
            if target == Target::Riscv64UnknownNone && abi == Some("lp64") {
                let fast = fast_function(
                    signature(vec![f64, f64], f64, "fastcc"),
                    Some(fast_witness(target)),
                );
                assert_ne!(context.plan_function(&fast).unwrap().args, ordinary.args);
            }
        }
    }

    fn floating_module(
        target: Target,
        abi: Option<&str>,
    ) -> (NativeModule, TypeId, TypeId, TypeId) {
        let mut m = module(target);
        m.target.abi = abi.map(str::to_owned);
        m.target.data_layout = "e-p:64:64-i64:64-f32:32-f64:64-f80:128-f128:128-S128".into();
        let f32 = push(&mut m, Type::Float { bits: 32 });
        let f64 = push(&mut m, Type::Float { bits: 64 });
        let f128 = push(&mut m, Type::Float { bits: 128 });
        (m, f32, f64, f128)
    }

    #[test]
    fn scalar_floating_abi_register_classes_and_wide_chunks_all_profiles() {
        for (target, abi) in [
            (Target::X86_64UnknownNone, None),
            (Target::Aarch64UnknownNone, None),
            (Target::Riscv64UnknownNone, Some("lp64")),
            (Target::Riscv64UnknownNone, Some("lp64d")),
        ] {
            let (m, f32, f64, f128) = floating_module(target, abi);
            for (ty, bits) in [(f32, 32), (f64, 64), (f128, 128)] {
                let p = plan(&m, target, &signature(vec![ty], ty, "c")).unwrap();
                assert!(p.storage.is_none());
                assert_eq!(p.args.len(), p.results.len());
                if target == Target::Riscv64UnknownNone && bits == 128 {
                    assert_eq!(p.args.len(), 2);
                    for parts in [&p.args, &p.results] {
                        for (index, part) in parts.iter().enumerate() {
                            assert_eq!(part.location, AbiLocation::Register(["a0", "a1"][index]));
                            assert_eq!(part.class, AbiClass::General);
                            assert_eq!((part.value_bits, part.location_bits), (64, 64));
                            assert_eq!(part.bit_offset, index as u16 * 64);
                            assert_eq!(part.offset, index as u64 * 8);
                            assert_eq!(part.ty, ty);
                            assert_eq!(part.leaf, 0);
                        }
                    }
                } else {
                    let reg = match target {
                        Target::X86_64UnknownNone => "xmm0",
                        Target::Aarch64UnknownNone => match bits {
                            32 => "s0",
                            64 => "d0",
                            _ => "q0",
                        },
                        Target::Riscv64UnknownNone if abi == Some("lp64d") => "fa0",
                        Target::Riscv64UnknownNone => "a0",
                    };
                    let general = target == Target::Riscv64UnknownNone && abi == Some("lp64");
                    for part in [&p.args[0], &p.results[0]] {
                        assert_eq!(part.location, AbiLocation::Register(reg));
                        assert_eq!(
                            part.class,
                            if general {
                                AbiClass::General
                            } else {
                                AbiClass::Float
                            }
                        );
                        assert_eq!(part.value_bits, bits);
                        assert_eq!(part.bit_offset, 0);
                        assert_eq!(
                            part.location_bits,
                            if target == Target::Riscv64UnknownNone {
                                64
                            } else {
                                bits
                            }
                        );
                        assert_eq!(
                            part.nan_box,
                            target == Target::Riscv64UnknownNone
                                && abi == Some("lp64d")
                                && bits == 32
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn x87_scalar_has_80_value_bits_and_16_byte_argument_slot() {
        let target = Target::X86_64UnknownNone;
        let (mut m, _, _, _) = floating_module(target, None);
        let f80 = push(&mut m, Type::Float { bits: 80 });
        let p = plan(&m, target, &signature(vec![f80, 1], f80, "c")).unwrap();
        assert_eq!(p.args[0].location, AbiLocation::Stack { offset: 0 });
        assert_eq!(p.args[0].class, AbiClass::X87);
        assert_eq!((p.args[0].value_bits, p.args[0].location_bits), (80, 80));
        assert_eq!(p.args[1].location, AbiLocation::Register("rdi"));
        assert_eq!(p.stack_bytes, 16);
        assert_eq!(p.results[0].location, AbiLocation::Register("st(0)"));
        assert_eq!(p.results[0].class, AbiClass::X87);
        assert_eq!(p.results[0].value_bits, 80);
    }

    #[test]
    fn scalar_floating_register_banks_exhaust_independently() {
        for (target, abi) in [
            (Target::X86_64UnknownNone, None),
            (Target::Aarch64UnknownNone, None),
            (Target::Riscv64UnknownNone, Some("lp64")),
            (Target::Riscv64UnknownNone, Some("lp64d")),
        ] {
            let (m, _, f64, _) = floating_module(target, abi);
            let params = [vec![f64; 10], vec![1; 9]].concat();
            let p = plan(&m, target, &signature(params, 0, "c")).unwrap();
            if target == Target::Riscv64UnknownNone && abi == Some("lp64") {
                assert_eq!(p.args[7].location, AbiLocation::Register("a7"));
                assert_eq!(p.args[8].location, AbiLocation::Stack { offset: 0 });
                assert_eq!(p.args[10].location, AbiLocation::Stack { offset: 16 });
                assert_eq!(p.stack_bytes, 96);
            } else if target == Target::Riscv64UnknownNone {
                assert_eq!(p.args[7].location, AbiLocation::Register("fa7"));
                assert_eq!(p.args[8].location, AbiLocation::Register("a0"));
                assert_eq!(p.args[9].location, AbiLocation::Register("a1"));
                assert_eq!(p.args[10].location, AbiLocation::Register("a2"));
                assert_eq!(p.args[16].location, AbiLocation::Stack { offset: 0 });
                assert_eq!(p.stack_bytes, 32);
            } else {
                assert_eq!(p.args[8].location, AbiLocation::Stack { offset: 0 });
                assert_eq!(p.args[9].location, AbiLocation::Stack { offset: 8 });
                assert_eq!(
                    p.args[10].location,
                    AbiLocation::Register(if target == Target::X86_64UnknownNone {
                        "rdi"
                    } else {
                        "x0"
                    })
                );
                assert_eq!(
                    p.stack_bytes,
                    if target == Target::X86_64UnknownNone {
                        48
                    } else {
                        32
                    }
                );
            }
        }
    }

    #[test]
    fn riscv_quad_named_split_and_variadic_even_pairs_preserve_named_boundary() {
        let target = Target::Riscv64UnknownNone;
        for abi in ["lp64", "lp64d"] {
            let (m, _, _, f128) = floating_module(target, Some(abi));
            let fixed = [vec![1; 7], vec![f128]].concat();
            let p = plan(&m, target, &signature(fixed, f128, "c")).unwrap();
            assert_eq!(p.args[7].location, AbiLocation::Register("a7"));
            assert_eq!(p.args[8].location, AbiLocation::Stack { offset: 0 });
            assert_eq!((p.args[7].bit_offset, p.args[8].bit_offset), (0, 64));
            for named in [5usize, 6, 7, 8, 9] {
                let mut sig = signature(vec![1; named], 0, "c");
                sig.variadic = true;
                let actual = [vec![1; named], vec![f128, 1]].concat();
                let p = plan_call(&m, target, &sig, &actual, &vec![vec![]; actual.len()]).unwrap();
                let metadata = p.variadic.unwrap();
                assert_eq!(metadata.named_gp, named.min(8));
                assert_eq!(
                    metadata.named_stack_bytes,
                    named.saturating_sub(8) as u64 * 8
                );
                assert_eq!(metadata.named_fp, 0);
                if named <= 6 {
                    assert_eq!(p.args[named].location, AbiLocation::Register("a6"));
                    assert_eq!(p.args[named + 1].location, AbiLocation::Register("a7"));
                    assert_eq!(p.args[named + 2].location, AbiLocation::Stack { offset: 0 });
                } else {
                    let base = if named == 9 { 16 } else { 0 };
                    assert_eq!(p.args[named].location, AbiLocation::Stack { offset: base });
                    assert_eq!(
                        p.args[named + 1].location,
                        AbiLocation::Stack { offset: base + 8 }
                    );
                    assert_eq!(
                        p.args[named + 2].location,
                        AbiLocation::Stack { offset: base + 16 }
                    );
                }
            }
        }
    }

    #[test]
    fn x86_variadic_vector_count_includes_actual_fp128_once_and_excludes_x87() {
        let target = Target::X86_64UnknownNone;
        let (mut m, _, f64, f128) = floating_module(target, None);
        let f80 = push(&mut m, Type::Float { bits: 80 });
        let mut sig = signature(vec![f64; 7], 0, "c");
        sig.variadic = true;
        let actual = [vec![f64; 7], vec![f128, f80, f64, 1]].concat();
        let p = plan_call(&m, target, &sig, &actual, &vec![vec![]; actual.len()]).unwrap();
        let metadata = p.variadic.unwrap();
        assert_eq!(
            (
                metadata.named_gp,
                metadata.named_fp,
                metadata.named_stack_bytes
            ),
            (0, 7, 0)
        );
        assert_eq!(metadata.vector_register_count, 8);
        assert_eq!(p.args[7].location, AbiLocation::Register("xmm7"));
        assert_eq!(p.args[7].value_bits, 128);
        assert_eq!(p.args[8].location, AbiLocation::Stack { offset: 0 });
        assert_eq!(p.args[8].class, AbiClass::X87);
        assert_eq!(p.args[9].location, AbiLocation::Stack { offset: 16 });
        assert_eq!(p.args[10].location, AbiLocation::Register("rdi"));
        assert_eq!(p.stack_bytes, 32);
    }

    #[test]
    fn aarch64_va_start_named_fp_and_unrounded_stack_geometry_are_exact() {
        let target = Target::Aarch64UnknownNone;
        let (m, _, f64, f128) = floating_module(target, None);
        let fixed = [vec![f64; 8], vec![1; 13]].concat();
        let mut sig = signature(fixed.clone(), 0, "c");
        sig.variadic = true;
        let actual = [fixed, vec![f128, f64]].concat();
        let p = plan_call(&m, target, &sig, &actual, &vec![vec![]; actual.len()]).unwrap();
        let metadata = p.variadic.unwrap();
        assert_eq!(
            (
                metadata.named_gp,
                metadata.named_fp,
                metadata.named_stack_bytes
            ),
            (8, 8, 40)
        );
        assert_eq!(p.args[21].location, AbiLocation::Stack { offset: 48 });
        assert_eq!(p.args[21].value_bits, 128);
        assert_eq!(p.args[22].location, AbiLocation::Stack { offset: 64 });
        assert_eq!(p.stack_bytes, 80);
    }

    #[test]
    fn floating_abi_feature_guards_are_closed_before_leaf_expansion() {
        for target in [
            Target::X86_64UnknownNone,
            Target::Aarch64UnknownNone,
            Target::Riscv64UnknownNone,
        ] {
            let (mut m, f32, _, f128) = floating_module(
                target,
                (target == Target::Riscv64UnknownNone).then_some("lp64d"),
            );
            let nested = push(
                &mut m,
                Type::Array {
                    element: f128,
                    len: 0,
                },
            );
            // The scalar f128 root must not accidentally authorize the same
            // Float type when reached through a separate aggregate root.
            assert!(audit_signature(&m, target, &signature(vec![f128, nested], 0, "c")).is_err());
            // Shape alone is now representable, but no source context may be invented.
            assert!(plan(&m, target, &signature(vec![f32], 0, "fastcc")).is_err());
            let f16 = push(&mut m, Type::Float { bits: 16 });
            assert!(audit_signature(&m, target, &signature(vec![f16], 0, "c")).is_err());
            let f80 = push(&mut m, Type::Float { bits: 80 });
            if target != Target::X86_64UnknownNone {
                assert!(audit_signature(&m, target, &signature(vec![f80], 0, "c")).is_err());
            }
            if target == Target::Riscv64UnknownNone {
                m.target.abi = None;
                assert!(audit_signature(&m, target, &signature(vec![f32], 0, "c")).is_err());
                assert!(audit_signature(&m, target, &signature(vec![1], 0, "c")).is_ok());
            }
        }
    }

    #[test]
    fn floating_call_type_identity_and_exact_layout_are_preserved() {
        let target = Target::X86_64UnknownNone;
        let (mut m, _, f64, f128) = floating_module(target, None);
        let duplicate = push(&mut m, Type::Float { bits: 64 });
        let sig = signature(vec![f64], f64, "c");
        let p = plan_call(&m, target, &sig, &[duplicate], &[]).unwrap();
        assert_eq!(p.args[0].ty, duplicate);
        assert_eq!(p.results[0].ty, f64);
        let mut attributed = sig.clone();
        attributed.param_attributes = vec![vec!["signext".into()]];
        assert!(plan(&m, target, &attributed).is_err());
        m.target.data_layout = m.target.data_layout.replace("f128:128", "f128:64");
        assert!(plan(&m, target, &signature(vec![f128], f128, "c")).is_err());
    }
    fn wide_integer_module(target: Target) -> (NativeModule, TypeId) {
        let mut m = module(target);
        m.target.data_layout.push_str("-i128:128-f128:128");
        let wide = push(&mut m, Type::Int { bits: 128 });
        (m, wide)
    }

    #[test]
    fn scalar_i128_preserves_two_chunks_and_two_register_results_all_isas() {
        for (target, input, output) in [
            (Target::X86_64UnknownNone, ["rdi", "rsi"], ["rax", "rdx"]),
            (Target::Aarch64UnknownNone, ["x0", "x1"], ["x0", "x1"]),
            (Target::Riscv64UnknownNone, ["a0", "a1"], ["a0", "a1"]),
        ] {
            let (m, wide) = wide_integer_module(target);
            let p = plan(&m, target, &signature(vec![wide], wide, "c")).unwrap();
            assert!(p.storage.is_none());
            for (parts, registers) in [(&p.args, input), (&p.results, output)] {
                assert_eq!(parts.len(), 2);
                for (index, part) in parts.iter().enumerate() {
                    assert_eq!(part.location, AbiLocation::Register(registers[index]));
                    assert_eq!(
                        (part.ty, part.leaf, part.offset),
                        (wide, 0, index as u64 * 8)
                    );
                    assert_eq!(
                        (part.value_bits, part.bit_offset, part.location_bits),
                        (64, index as u16 * 64, 64)
                    );
                    assert_eq!(part.class, AbiClass::General);
                    assert_eq!(part.extension, Extension::None);
                }
            }
        }
    }

    #[test]
    fn sysv_i128_rolls_back_failed_pair_and_keeps_last_gp_for_following_scalar() {
        let target = Target::X86_64UnknownNone;
        let (m, wide) = wide_integer_module(target);
        let params = [vec![1; 5], vec![wide, 1, wide]].concat();
        let p = plan(&m, target, &signature(params, 0, "c")).unwrap();
        assert_eq!(
            regs(&p.args[5..]),
            vec![
                AbiLocation::Stack { offset: 0 },
                AbiLocation::Stack { offset: 8 },
                AbiLocation::Register("r9"),
                AbiLocation::Stack { offset: 16 },
                AbiLocation::Stack { offset: 24 },
            ]
        );
        assert_eq!(p.stack_bytes, 32);
    }

    #[test]
    fn aapcs_i128_even_pair_stack_alignment_and_named_metadata_are_exact() {
        let target = Target::Aarch64UnknownNone;
        let (m, wide) = wide_integer_module(target);
        let p = plan(&m, target, &signature(vec![1, wide, 1], 0, "c")).unwrap();
        assert_eq!(
            regs(&p.args),
            vec![
                AbiLocation::Register("x0"),
                AbiLocation::Register("x2"),
                AbiLocation::Register("x3"),
                AbiLocation::Register("x4")
            ]
        );
        let mut sig = signature(vec![1; 9], 0, "c");
        sig.variadic = true;
        let actual = [sig.params.clone(), vec![wide, 1]].concat();
        let p = plan_call(&m, target, &sig, &actual, &vec![vec![]; actual.len()]).unwrap();
        assert_eq!(p.variadic.unwrap().named_stack_bytes, 8);
        assert_eq!(
            regs(&p.args[9..]),
            vec![
                AbiLocation::Stack { offset: 16 },
                AbiLocation::Stack { offset: 24 },
                AbiLocation::Stack { offset: 32 }
            ]
        );
        let p = plan(
            &m,
            target,
            &signature([vec![1; 7], vec![wide, 1]].concat(), 0, "c"),
        )
        .unwrap();
        assert_eq!(
            regs(&p.args[7..]),
            vec![
                AbiLocation::Stack { offset: 0 },
                AbiLocation::Stack { offset: 8 },
                AbiLocation::Stack { offset: 16 }
            ]
        );
    }

    #[test]
    fn rv_i128_named_split_and_unnamed_even_pair_sticky_stack_are_distinct() {
        let target = Target::Riscv64UnknownNone;
        let (m, wide) = wide_integer_module(target);
        let p = plan(
            &m,
            target,
            &signature([vec![1; 7], vec![wide, 1]].concat(), 0, "c"),
        )
        .unwrap();
        assert_eq!(
            regs(&p.args[7..]),
            vec![
                AbiLocation::Register("a7"),
                AbiLocation::Stack { offset: 0 },
                AbiLocation::Stack { offset: 8 }
            ]
        );
        for named in [5, 7] {
            let mut sig = signature(vec![1; named], 0, "c");
            sig.variadic = true;
            let actual = [sig.params.clone(), vec![wide, 1]].concat();
            let p = plan_call(&m, target, &sig, &actual, &vec![vec![]; actual.len()]).unwrap();
            let expected = if named == 5 {
                vec![
                    AbiLocation::Register("a6"),
                    AbiLocation::Register("a7"),
                    AbiLocation::Stack { offset: 0 },
                ]
            } else {
                vec![
                    AbiLocation::Stack { offset: 0 },
                    AbiLocation::Stack { offset: 8 },
                    AbiLocation::Stack { offset: 16 },
                ]
            };
            assert_eq!(regs(&p.args[named..]), expected);
            assert_eq!(p.variadic.unwrap().named_gp, named);
        }
    }

    #[test]
    fn i128_abi_guards_do_not_reject_typed_memory_or_authorize_aggregate_values() {
        for target in [
            Target::X86_64UnknownNone,
            Target::Aarch64UnknownNone,
            Target::Riscv64UnknownNone,
        ] {
            let (mut m, wide) = wide_integer_module(target);
            let fp = push(&mut m, Type::Float { bits: 128 });
            let storage = push(
                &mut m,
                Type::Struct {
                    fields: vec![wide, fp],
                    packed: false,
                },
            );
            let empty = push(
                &mut m,
                Type::Array {
                    element: wide,
                    len: 0,
                },
            );
            let mut sig = signature(vec![2], 0, "c");
            sig.return_storage = Some(ReturnStorage {
                param: 0,
                ty: storage,
            });
            assert!(plan(&m, target, &sig).is_ok());
            for value in [storage, empty] {
                let mut value_sig = sig.clone();
                value_sig.params.push(value);
                assert!(audit_signature(&m, target, &value_sig).is_err());
            }
            assert!(plan(&m, target, &signature(vec![wide], wide, "fastcc")).is_err());
            for bits in [65, 127, 129] {
                let unsupported = push(&mut m, Type::Int { bits });
                assert!(
                    audit_signature(&m, target, &signature(vec![unsupported], 0, "c")).is_err()
                );
            }
            for attr in ["signext", "zeroext"] {
                let mut attributed = signature(vec![wide], wide, "c");
                attributed.param_attributes = vec![vec![attr.into()]];
                assert!(audit_signature(&m, target, &attributed).is_err());
                attributed.param_attributes.clear();
                attributed.result_attributes = vec![attr.into()];
                assert!(audit_signature(&m, target, &attributed).is_err());
                let mut variadic = signature(vec![], 0, "c");
                variadic.variadic = true;
                assert!(plan_call(&m, target, &variadic, &[wide], &[vec![attr.into()]]).is_err());
                assert!(plan_call(&m, target, &variadic, &[wide], &[]).is_err());
            }
            m.target.data_layout = m.target.data_layout.replace("i128:128", "i128:64");
            assert!(plan(&m, target, &signature(vec![wide], wide, "c")).is_err());
        }
    }
}
