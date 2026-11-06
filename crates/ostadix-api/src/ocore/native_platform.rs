//! Typed Linux userspace ABI boundary. This is an external platform dependency,
//! not an implementation of Linux kernel services or an executable ASM payload.
use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use super::native_ir::*;
use super::Diagnostic;

type Result<T> = std::result::Result<T, Diagnostic>;
fn fail(text: impl Into<String>) -> Diagnostic {
    error_diagnostic(format!("linux_syscall_profile: {}", text.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxArchitecture { X86_64, Aarch64, Riscv64 }
impl LinuxArchitecture {
    pub fn name(self) -> &'static str {
        match self { Self::X86_64 => "x86_64", Self::Aarch64 => "aarch64", Self::Riscv64 => "riscv64" }
    }
    pub fn assembly(self) -> &'static [u8] {
        match self { Self::X86_64 => b"syscall", Self::Aarch64 => b"svc 0", Self::Riscv64 => b"ecall\n\t" }
    }
    pub fn constraints(self, arity: usize) -> String {
        let (mut fields, inputs, clobbers): (Vec<&str>, &[&str], &[&str]) = match self {
            Self::X86_64 => (vec!["={ax}", "{ax}"], &["{di}", "{si}", "{dx}", "{r10}", "{r8}", "{r9}"], &["~{rcx}", "~{r11}", "~{memory}", "~{dirflag}", "~{fpsr}", "~{flags}"]),
            Self::Aarch64 => (vec!["={x0}", "{x8}"], &["{x0}", "{x1}", "{x2}", "{x3}", "{x4}", "{x5}"], &["~{memory}", "~{cc}"]),
            Self::Riscv64 => (vec!["={x10}", "{x17}"], &["{x10}", "{x11}", "{x12}", "{x13}", "{x14}", "{x15}"], &["~{memory}"]),
        };
        fields.extend(inputs.iter().take(arity).copied());
        fields.extend(clobbers.iter().copied());
        fields.join(",")
    }
}

pub fn architecture(module: &NativeModule) -> Result<LinuxArchitecture> {
    let target = &module.target;
    let fields: Vec<_> = target.triple.split('-').collect();
    if target.pointer_bits != 64 || !target.little_endian || !fields.contains(&"linux") {
        return Err(fail("linux_user_raw_v1 requires an original little-endian Linux 64-bit target"));
    }
    match fields.first().copied() {
        Some("x86_64") => Ok(LinuxArchitecture::X86_64),
        Some("aarch64") => Ok(LinuxArchitecture::Aarch64),
        Some("riscv64") if target.abi.as_deref() == Some("lp64d") => Ok(LinuxArchitecture::Riscv64),
        _ => Err(fail("unsupported original Linux raw-syscall architecture/ABI")),
    }
}

/// Derived interface requirements are meaningful even with no ELF UND symbols.
/// A component's external Linux provider must be declared independently; this
/// record never discharges kernel, process, memory or provider closure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxProviderRequirement {
    pub schema: String,
    pub architecture: String,
    pub profile: LinuxSyscallProfile,
    pub execution_environment: LinuxProviderExecution,
    pub privilege: LinuxProviderPrivilege,
    pub sites: Vec<LinuxProviderSite>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinuxProviderExecution {
    /// Linux-compatible userspace ABI and execution context. This requirement
    /// does not identify a provider implementation: a future native O-core
    /// provider must independently qualify the complete compatible contract.
    LinuxCompatibleUserProcessV1,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinuxProviderPrivilege { UserModeOnly }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxProviderSite {
    pub function: String,
    pub block: BlockId,
    pub instruction: usize,
    pub arity: usize,
    /// None is an actual dynamic number, never an absent provider dependency.
    pub constant_number: Option<String>,
}

pub fn requirement(module: &NativeModule) -> Result<Option<LinuxProviderRequirement>> {
    let mut sites = Vec::new();
    for function in &module.functions {
        for block in &function.blocks {
            for (instruction, item) in block.instructions.iter().enumerate() {
                if let Operation::LinuxSyscall { number, arguments, .. } = &item.operation {
                    sites.push(LinuxProviderSite { function: function.name.clone(), block: block.id,
                        instruction, arity: arguments.len(), constant_number: match number {
                            Operand::Int { bits, .. } => Some(bits.clone()), _ => None,
                        }});
                }
            }
        }
    }
    if sites.is_empty() { return Ok(None); }
    Ok(Some(LinuxProviderRequirement { schema: "ocore.linux-provider-requirement/v1".into(),
        architecture: architecture(module)?.name().into(), profile: LinuxSyscallProfile::LinuxUserRawV1,
        execution_environment: LinuxProviderExecution::LinuxCompatibleUserProcessV1, privilege: LinuxProviderPrivilege::UserModeOnly, sites }))
}

pub fn verify(module: &NativeModule) -> Result<()> {
    let profile = module.target.linux_syscall_profile;
    let arch = if profile.is_some() { Some(architecture(module)?) } else { None };
    if module.target.strict_fp_profile == Some(StrictFpProfile::IntegerLinuxSyscallV1)
        && profile != Some(LinuxSyscallProfile::LinuxUserRawV1) {
        return Err(fail("integer_linux_syscall_v1 requires linux_user_raw_v1"));
    }
    let mut source_sites = BTreeSet::new();
    let mut locations: BTreeMap<usize, &LinuxSyscallSourceLocation> = BTreeMap::new();
    for function in &module.functions {
        for block in &function.blocks {
            for instruction in &block.instructions {
                let Operation::LinuxSyscall { arguments, source, .. } = &instruction.operation else { continue };
                let arch = arch.ok_or_else(|| fail("Linux platform operation requires explicit linux_user_raw_v1"))?;
                let source_schema = if source.constant_ranges.is_empty() {
                    "ocore.llvm-linux-syscall-source/v1"
                } else {
                    "ocore.llvm-linux-syscall-source/v2"
                };
                if arguments.len() > 6 || source.schema != source_schema
                    || source.site.function != function.name || source.site.block != block.id
                    || !source_sites.insert((source.site.function.as_str(), source.site.block, source.site.source_instruction))
                    || source.assembly != arch.assembly()
                    || source.constraints != arch.constraints(arguments.len()).as_bytes()
                    || !source.side_effects || source.align_stack || source.dialect != 0 || source.can_unwind
                    || source.calling_convention != 0 || !matches!(source.tail_kind, 0 | 1 | 3) {
                    return Err(fail("unsupported or inconsistent exact InlineAsm source contract"));
                }
                let signature = &source.signature;
                if signature.variadic || signature.abi != "c" || signature.return_storage.is_some()
                    || signature.params.len() != arguments.len() + 1
                    || signature.params.iter().chain(std::iter::once(&signature.result))
                        .any(|ty| !matches!(module.types.get(*ty), Some(Type::Int { bits: 64 })))
                    || !signature.result_attributes.is_empty()
                    || signature.param_attributes.len() != signature.params.len()
                    || signature.param_attributes.iter().any(|attrs| !attrs.is_empty()) {
                    return Err(fail("Linux raw-syscall source requires exact fixed i64 C signature without ABI extension attributes"));
                }
                let mut attributes = BTreeSet::new();
                for attribute in &source.attributes {
                    if !attributes.insert((attribute.index, attribute.name.as_str())) || attribute.value != 0
                        || !matches!((attribute.index, attribute.name.as_str()),
                            (u32::MAX, "strictfp" | "nounwind") | (0..=7, "noundef"))
                        || attribute.index != u32::MAX && attribute.index as usize > signature.params.len() {
                        return Err(fail("unsupported raw-syscall callsite attribute"));
                    }
                }
                if source.attributes.windows(2).any(|pair| (pair[0].index, &pair[0].name) >= (pair[1].index, &pair[1].name)) {
                    return Err(fail("raw-syscall attributes require deterministic source slot/name order"));
                }
                let mut range_slots = BTreeSet::new();
                for range in &source.constant_ranges {
                    // Check slot bounds before indexing the original signature.
                    if range.index == u32::MAX || range.index as usize > signature.params.len()
                        || !range_slots.insert(range.index)
                        || range.name != "range"
                        || range.schema != "ocore.llvm-constant-range-attribute/v1"
                        || range.storage != "context_uniqued_constant_range_attribute" {
                        return Err(fail("unsupported raw-syscall ConstantRange source position/schema/storage"));
                    }
                    let ty = if range.index == 0 { signature.result }
                        else { signature.params[range.index as usize - 1] };
                    if !matches!(module.types.get(ty), Some(Type::Int { bits }) if *bits == range.width)
                        || range.width != 64 {
                        return Err(fail("raw-syscall ConstantRange width must match its original i64 slot"));
                    }
                    for endpoint in [&range.lower, &range.upper] {
                        let bits = BigUint::parse_bytes(endpoint.as_bytes(), 10)
                            .ok_or_else(|| fail("ConstantRange endpoints require canonical unsigned decimal bits"))?;
                        if bits.bits() > u64::from(range.width) || bits.to_str_radix(10) != *endpoint {
                            return Err(fail("ConstantRange endpoint width/bits mismatch"));
                        }
                    }
                    // LLVM range attributes permit empty [0,0), not full or
                    // another equal-bound encoding. Never infer noundef here.
                    if range.lower == range.upper && range.lower != "0" {
                        return Err(fail("ConstantRange equal bounds require the empty [0,0) encoding"));
                    }
                }
                if source.constant_ranges.windows(2).any(|pair| pair[0].index >= pair[1].index) {
                    return Err(fail("raw-syscall ConstantRange witnesses require source slot order"));
                }
                if source.attributes.iter().any(|a| a.name == "strictfp")
                    && module.target.strict_fp_profile != Some(StrictFpProfile::IntegerLinuxSyscallV1) {
                    return Err(fail("strictfp raw syscall requires integer_linux_syscall_v1"));
                }
                if let Some(location) = &source.srcloc {
                    if location.operands.is_empty() { return Err(fail("srcloc requires a nonempty integer MDTuple")); }
                    for integer in &location.operands {
                        let bits = BigUint::parse_bytes(integer.bits.as_bytes(), 10)
                            .ok_or_else(|| fail("srcloc integer bits must be canonical unsigned decimal"))?;
                        if !(1..=64).contains(&integer.width) || bits.bits() > u64::from(integer.width)
                            || bits.to_str_radix(10) != integer.bits {
                            return Err(fail("srcloc integer width/bits mismatch"));
                        }
                    }
                    if let Some(previous) = locations.insert(location.node, location) {
                        if previous != location { return Err(fail("srcloc node identity has inconsistent storage/operands")); }
                    }
                }
            }
        }
    }
    if locations.keys().copied().ne(0..locations.len()) { return Err(fail("srcloc identities require dense source-order numbering")); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ocore::native_platform::*;
    use serde_json::json;

    fn module() -> NativeModule {
        let source = json!({
            "schema":"ocore.llvm-linux-syscall-source/v1","site":{"function":"raw0","block":0,"source_instruction":0},
            "assembly":LinuxArchitecture::X86_64.assembly(),"constraints":LinuxArchitecture::X86_64.constraints(0).as_bytes(),
            "side_effects":true,"align_stack":false,"dialect":0,"can_unwind":false,"calling_convention":0,"tail_kind":0,
            "signature":{"params":[0],"result":0,"abi":"c","variadic":false,"param_attributes":[[]],"result_attributes":[]},
            "attributes":[],"srcloc":null
        });
        let operation = json!({"op":"linux_syscall","number":{"kind":"int","ty":0,"bits":"102"},"arguments":[],"source":source});
        let function = json!({"name":"raw0","linkage":"external","signature":{"params":[],"result":0,"abi":"c","variadic":false},"params":[],"entry":0,
            "blocks":[{"id":0,"instructions":[{"result":{"id":0,"ty":0},"operation":operation}],"terminator":{"op":"return","value":{"kind":"value","id":0}}}]});
        serde_json::from_value(json!({
            "format":FORMAT,"name":"authored-platform-guard","semantics":"llvm_defined_behavior_v1",
            "target":{"triple":"x86_64-unknown-linux-musl","data_layout":"e-p:64:64-i64:64","pointer_bits":64,"little_endian":true,
                "linux_syscall_profile":"linux_user_raw_v1","strict_fp_profile":"integer_linux_syscall_v1"},
            "types":[{"kind":"int","bits":64}],"globals":[],"functions":[function],
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"authored-guard","frontend_version":"1","importer":"test","importer_version":"1","source_function_count":1,"source_global_count":0,"refinements":[]}
        })).unwrap()
    }

    #[test]
    fn required_interface_survives_zero_ordinary_undefined_symbols_and_dynamic_numbers() {
        let mut module = module();
        crate::ocore::native_verify::verify(&module).unwrap();
        let required = requirement(&module).unwrap().unwrap();
        assert_eq!(required.sites[0].constant_number.as_deref(), Some("102"));
        assert_eq!(required.privilege, LinuxProviderPrivilege::UserModeOnly);
        assert_eq!(required.execution_environment, LinuxProviderExecution::LinuxCompatibleUserProcessV1);
        module.functions[0].signature.params.push(0);
        module.functions[0].params.push(Value { id: 1, ty: 0 });
        let Operation::LinuxSyscall { number, .. } = &mut module.functions[0].blocks[0].instructions[0].operation else { unreachable!() };
        *number = Operand::Value { id: 1 };
        crate::ocore::native_verify::verify(&module).unwrap();
        assert_eq!(requirement(&module).unwrap().unwrap().sites[0].constant_number, None);
    }

    #[test]
    fn interpreter_refuses_platform_effect_before_any_execution() {
        let module = module();
        let error = crate::ocore::native_interpret::evaluate(&module,"raw0",&[]).unwrap_err();
        assert!(error.message.contains("Linux platform effects cannot execute"),"{}",error.message);
    }

    #[test]
    fn old_strict_profile_and_non_linux_or_wrong_privilege_target_do_not_admit_syscalls() {
        let mut module = module();
        module.target.strict_fp_profile = Some(StrictFpProfile::IntegerOnlyV1);
        assert!(crate::ocore::native_verify::verify(&module).is_err());
        module.target.strict_fp_profile = Some(StrictFpProfile::IntegerLinuxSyscallV1);
        module.target.triple="x86_64-unknown-none".into();
        assert!(crate::ocore::native_verify::verify(&module).is_err());
        module.target.triple="x86_64-unknown-linux-musl".into();
        module.target.linux_syscall_profile=None;
        assert!(crate::ocore::native_verify::verify(&module).is_err());
    }

    #[test]
    fn typed_constant_range_source_v2_retains_opaque_user_provider() {
        let mut module = module();
        let Operation::LinuxSyscall { source, .. } = &mut module.functions[0].blocks[0].instructions[0].operation else { unreachable!() };
        source.schema = "ocore.llvm-linux-syscall-source/v2".into();
        source.constant_ranges.push(LinuxSyscallConstantRangeAttribute {
            index: 1, name: "range".into(), schema: "ocore.llvm-constant-range-attribute/v1".into(),
            storage: "context_uniqued_constant_range_attribute".into(), width: 64,
            lower: "1".into(), upper: "1000".into(),
        });
        crate::ocore::native_verify::verify(&module).unwrap();
        assert_eq!(requirement(&module).unwrap().unwrap().privilege, LinuxProviderPrivilege::UserModeOnly);
        assert!(crate::ocore::native_interpret::evaluate(&module,"raw0",&[]).is_err());
        let Operation::LinuxSyscall { source, .. } = &mut module.functions[0].blocks[0].instructions[0].operation else { unreachable!() };
        source.constant_ranges[0].lower = "0".into();
        source.constant_ranges[0].upper = "0".into();
        // Empty source range is representable, not positive execution proof.
        crate::ocore::native_verify::verify(&module).unwrap();
    }

    #[test]
    fn typed_constant_range_rejects_forged_slot_schema_width_and_endpoint_geometry() {
        let mut value = serde_json::to_value(module()).unwrap();
        let source = &mut value["functions"][0]["blocks"][0]["instructions"][0]["operation"]["source"];
        source["schema"] = json!("ocore.llvm-linux-syscall-source/v2");
        source["constant_ranges"] = json!([{
            "index":1,"name":"range","schema":"ocore.llvm-constant-range-attribute/v1",
            "storage":"context_uniqued_constant_range_attribute","width":64,"lower":"1","upper":"1000"
        }]);
        let original = value.clone();
        let accepted: NativeModule = serde_json::from_value(original.clone()).unwrap();
        crate::ocore::native_verify::verify(&accepted).unwrap();
        for (field, bad) in [
            ("index",json!(u32::MAX)),("index",json!(2)),("width",json!(32)),
            ("name",json!("noundef")),("schema",json!("unknown")),("storage",json!("distinct")),
            ("lower",json!("-1")),("lower",json!("01")),("lower",json!("18446744073709551616")),
        ] {
            let mut changed = original.clone();
            changed["functions"][0]["blocks"][0]["instructions"][0]["operation"]["source"]["constant_ranges"][0][field] = bad;
            let changed: NativeModule = serde_json::from_value(changed).unwrap();
            assert!(crate::ocore::native_verify::verify(&changed).is_err(),"{field}");
        }
        for equal in ["1", "18446744073709551615"] {
            let mut changed = original.clone();
            let range = &mut changed["functions"][0]["blocks"][0]["instructions"][0]["operation"]["source"]["constant_ranges"][0];
            range["lower"] = json!(equal);range["upper"] = json!(equal);
            assert!(crate::ocore::native_verify::verify(&serde_json::from_value(changed).unwrap()).is_err());
        }
        let mut changed = original.clone();
        changed["functions"][0]["blocks"][0]["instructions"][0]["operation"]["source"]["schema"] = json!("ocore.llvm-linux-syscall-source/v1");
        assert!(crate::ocore::native_verify::verify(&serde_json::from_value(changed).unwrap()).is_err());
        let mut changed = original;
        changed["functions"][0]["blocks"][0]["instructions"][0]["operation"]["source"]["constant_ranges"] = json!([]);
        assert!(crate::ocore::native_verify::verify(&serde_json::from_value(changed).unwrap()).is_err());
    }
}
