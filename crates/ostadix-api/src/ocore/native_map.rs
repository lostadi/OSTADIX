//! Descriptive, artifact-bound maps from verified imported IR to assembly text.
//!
//! Offsets are half-open UTF-8 byte ranges in the exact generated assembly,
//! including assembler directives and local labels. They are not object offsets,
//! machine PCs, source lines, debug information, or evidence of execution. Every
//! instruction has a site, including zero-width PHIs, assumptions, lifetime and
//! alias markers, and landing-pad instructions. PHI copies belong to predecessor
//! terminator sites, or their per-invoke exception landing sites on unwind edges.
//! Global data, aliases, and module-wide directives have no instruction sites.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::native_ir::{error_diagnostic, NativeModule};
use super::Diagnostic;
use super::Target;

pub const FORMAT: &str = "ocore-native-assembly-map-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeAssemblyMap {
    pub format: String,
    pub target: String,
    /// SHA-256 of compact typed NativeModule JSON, including provenance and
    /// normalized defaults. Original input JSON whitespace/order is irrelevant.
    pub module_sha256: String,
    /// The imported module's original frontend-input digest, a retained claim.
    pub input_sha256: String,
    pub assembly_sha256: String,
    pub assembly_bytes: usize,
    pub sites: Vec<NativeAssemblySite>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeAssemblySite {
    /// Index in NativeModule.functions; declarations therefore retain indices.
    pub function_index: usize,
    pub function: String,
    /// Native IR block ID, not its position in the function's block vector.
    pub block: Option<usize>,
    /// Zero-based position in the block's instructions; terminators have none.
    pub instruction: Option<usize>,
    pub kind: NativeAssemblySiteKind,
    pub assembly_start: usize,
    pub assembly_end: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeAssemblySiteKind {
    /// Section/alignment/symbol directives, frame setup, arguments, entry jump.
    FunctionPrologue,
    BlockLabel,
    Instruction,
    /// Includes epilogue code for return and any normal-edge PHI copies.
    Terminator,
    /// Identified by the predecessor invoke's block, including unwind PHI copies.
    ExceptionLanding,
    /// CFI end, function size, and the AArch64 literal-pool directive.
    FunctionEpilogue,
    ExceptionTable,
}

impl NativeAssemblyMap {
    pub(crate) fn from_emission(
        module: &NativeModule,
        target: Target,
        assembly: &str,
        sites: Vec<NativeAssemblySite>,
    ) -> Result<Self, Diagnostic> {
        let module_bytes = serde_json::to_vec(module)
            .map_err(|error| error_diagnostic(format!("native map module: {error}")))?;
        Ok(Self {
            format: FORMAT.into(),
            target: target.name().into(),
            module_sha256: digest(&module_bytes),
            input_sha256: module.provenance.input_sha256.clone(),
            assembly_sha256: digest(assembly.as_bytes()),
            assembly_bytes: assembly.len(),
            sites,
        })
    }

    /// Decode the strict wire shape. Admission requires `verify` with the module,
    /// target, and exact assembly; decoding and hashes alone grant no authority.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Diagnostic> {
        serde_json::from_slice(bytes)
            .map_err(|error| error_diagnostic(format!("invalid native assembly map: {error}")))
    }

    pub fn to_json(&self) -> Result<Vec<u8>, Diagnostic> {
        serde_json::to_vec_pretty(self)
            .map_err(|error| error_diagnostic(format!("native assembly map: {error}")))
    }

    /// Independently verify and re-emit the native module. Exact regenerated-map
    /// equality rejects missing/extra/reordered sites, changed identities, byte
    /// ranges, target, provenance, or artifact hashes, even if hashes are forged.
    /// This checks emission correspondence, not correctness of all codegen.
    pub fn verify(
        &self,
        module: &NativeModule,
        target: Target,
        assembly: &str,
    ) -> Result<(), Diagnostic> {
        let (expected_assembly, expected_map) =
            super::native_codegen::emit_with_map(module, target)?;
        if expected_assembly != assembly {
            return Err(error_diagnostic(
                "native assembly map: assembly does not match verified module emission",
            ));
        }
        if *self != expected_map {
            return Err(error_diagnostic(
                "native assembly map: sidecar does not match verified module emission",
            ));
        }
        Ok(())
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::super::native_codegen::{emit, emit_with_map};
    use super::*;
    use serde_json::json;

    fn module(triple: &str) -> NativeModule {
        serde_json::from_value(json!({
            "format":"ocore-native-module-v1", "name":"assembly-map-test",
            "target":{"triple":triple,"data_layout":"e-p:64:64-i64:64-S128",
                "pointer_bits":64,"little_endian":true},
            "semantics":"llvm_defined_behavior_v1",
            "types":[{"kind":"void"},{"kind":"int","bits":1},{"kind":"int","bits":64}],
            "globals":[],
            "functions":[
                {"name":"declaration","linkage":"external",
                    "signature":{"params":[],"result":0,"abi":"c","variadic":false},
                    "params":[],"entry":null,"blocks":[]},
                {"name":"choose","linkage":"external",
                    "signature":{"params":[1,2,2],"result":2,"abi":"c","variadic":false},
                    "params":[{"id":0,"ty":1},{"id":1,"ty":2},{"id":2,"ty":2}],"entry":7,
                    "blocks":[
                        {"id":7,"instructions":[{"result":null,"operation":{"op":"assume","condition":{"kind":"int","ty":1,"bits":"1"}}}],
                            "terminator":{"op":"branch","condition":{"kind":"value","id":0},"on_true":11,"on_false":23}},
                        {"id":11,"instructions":[{"result":{"id":3,"ty":2},"operation":{"op":"binary","kind":"add",
                            "lhs":{"kind":"value","id":1},"rhs":{"kind":"value","id":2},"flags":[]}}],
                            "terminator":{"op":"jump","target":23}},
                        {"id":23,"instructions":[{"result":{"id":4,"ty":2},"operation":{"op":"phi","incoming":[
                            {"block":7,"value":{"kind":"value","id":1}},
                            {"block":11,"value":{"kind":"value","id":3}}]}}],
                            "terminator":{"op":"return","value":{"kind":"value","id":4}}}
                    ]}
            ],
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"unit-test","frontend_version":"1",
                "importer":"unit-test","importer_version":"1","source_function_count":2,"source_global_count":0,"refinements":[]}
        })).unwrap()
    }

    #[test]
    fn maps_every_instruction_and_terminator_without_changing_any_target_assembly() {
        for (target, triple) in [
            (Target::X86_64UnknownNone, "x86_64-unknown-linux-gnu"),
            (Target::Aarch64UnknownNone, "aarch64-unknown-linux-gnu"),
            (Target::Riscv64UnknownNone, "riscv64-unknown-linux-gnu"),
        ] {
            let module = module(triple);
            let (assembly, map) = emit_with_map(&module, target).unwrap();
            assert_eq!(assembly, emit(&module, target).unwrap());
            map.verify(&module, target, &assembly).unwrap();
            assert_eq!(map.assembly_sha256, digest(assembly.as_bytes()));
            assert_eq!(map.assembly_bytes, assembly.len());
            assert_eq!(map.target, target.name());
            assert!(map
                .sites
                .iter()
                .all(|site| site.function_index == 1 && site.function == "choose"));
            let mut previous_end = 0;
            for site in &map.sites {
                assert!(previous_end <= site.assembly_start);
                assert!(site.assembly_start <= site.assembly_end);
                assert!(assembly
                    .get(site.assembly_start..site.assembly_end)
                    .is_some());
                previous_end = site.assembly_end;
            }
            let instructions: Vec<_> = map
                .sites
                .iter()
                .filter(|site| site.kind == NativeAssemblySiteKind::Instruction)
                .collect();
            assert_eq!(instructions.len(), 3);
            assert_eq!(
                instructions
                    .iter()
                    .map(|site| (site.block, site.instruction))
                    .collect::<Vec<_>>(),
                vec![(Some(7), Some(0)), (Some(11), Some(0)), (Some(23), Some(0))]
            );
            assert_eq!(instructions[0].assembly_start, instructions[0].assembly_end);
            assert!(instructions[1].assembly_start < instructions[1].assembly_end);
            assert_eq!(instructions[2].assembly_start, instructions[2].assembly_end);
            let terms: Vec<_> = map
                .sites
                .iter()
                .filter(|site| site.kind == NativeAssemblySiteKind::Terminator)
                .collect();
            assert_eq!(terms.len(), 3);
            assert!(terms
                .iter()
                .all(|site| site.instruction.is_none() && site.assembly_start < site.assembly_end));
            let restored = NativeAssemblyMap::from_json(&map.to_json().unwrap()).unwrap();
            assert_eq!(restored, map);
            restored.verify(&module, target, &assembly).unwrap();
        }
    }

    #[test]
    fn rejects_tampered_artifacts_missing_sites_and_changed_verified_module() {
        let target = Target::X86_64UnknownNone;
        let module = module("x86_64-unknown-linux-gnu");
        let (assembly, map) = emit_with_map(&module, target).unwrap();
        let mut modified_assembly = assembly.clone();
        modified_assembly.push_str("# changed artifact\n");
        let mut forged_hash = map.clone();
        forged_hash.assembly_sha256 = digest(modified_assembly.as_bytes());
        forged_hash.assembly_bytes = modified_assembly.len();
        assert!(forged_hash
            .verify(&module, target, &modified_assembly)
            .is_err());
        let mut missing = map.clone();
        missing.sites.remove(3);
        assert!(missing.verify(&module, target, &assembly).is_err());
        let mut changed_range = map.clone();
        changed_range.sites[0].assembly_end -= 1;
        assert!(changed_range.verify(&module, target, &assembly).is_err());
        let mut changed_module = module.clone();
        changed_module.provenance.input_sha256 = "1".repeat(64);
        assert!(map.verify(&changed_module, target, &assembly).is_err());
        assert!(map
            .verify(&module, Target::Aarch64UnknownNone, &assembly)
            .is_err());
        let mut extra_field = serde_json::to_value(&map).unwrap();
        extra_field["authority"] = json!("executed");
        assert!(NativeAssemblyMap::from_json(&serde_json::to_vec(&extra_field).unwrap()).is_err());
    }

    #[test]
    fn exception_landing_stubs_and_tables_retain_invoke_predecessors_on_all_targets() {
        for (target, triple) in [
            (Target::X86_64UnknownNone, "x86_64-unknown-linux-gnu"),
            (Target::Aarch64UnknownNone, "aarch64-unknown-linux-gnu"),
            (Target::Riscv64UnknownNone, "riscv64-unknown-linux-gnu"),
        ] {
            let mut wire = serde_json::to_value(module(triple)).unwrap();
            wire["types"].as_array_mut().unwrap().extend([
                json!({"kind":"pointer","address_space":0}),
                json!({"kind":"int","bits":32}),
                json!({"kind":"struct","fields":[3,4],"packed":false}),
            ]);
            wire["functions"] = json!([
                {"name":"may_throw","linkage":"external",
                    "signature":{"params":[2],"result":2,"abi":"c","variadic":false},
                    "params":[{"id":0,"ty":2}],"entry":null,"blocks":[]},
                {"name":"catch_and_resume","linkage":"external",
                    "signature":{"params":[2],"result":2,"abi":"c","variadic":false},
                    "params":[{"id":0,"ty":2}],"entry":7,
                    "exception_handling":{"model":"itanium_dwarf_v1","personality":{"kind":"symbol","ty":3,"name":"personality"}},
                    "blocks":[
                        {"id":7,"instructions":[],"terminator":{"op":"invoke",
                            "callee":{"kind":"symbol","ty":3,"name":"may_throw"},
                            "signature":{"params":[2],"result":2,"abi":"c","variadic":false},
                            "args":[{"kind":"value","id":0}],"result":{"id":1,"ty":2},"normal":11,"unwind":23}},
                        {"id":11,"instructions":[],"terminator":{"op":"return","value":{"kind":"value","id":1}}},
                        {"id":23,"instructions":[
                            {"result":{"id":2,"ty":2},"operation":{"op":"phi","incoming":[{"block":7,"value":{"kind":"value","id":0}}]}},
                            {"result":{"id":3,"ty":5},"operation":{"op":"landing_pad","cleanup":true,"clauses":[]}}],
                            "terminator":{"op":"resume","value":{"kind":"value","id":3}}}
                    ]},
                {"name":"personality","linkage":"external",
                    "signature":{"params":[],"result":4,"abi":"c","variadic":true},
                    "params":[],"entry":null,"blocks":[]}
            ]);
            wire["provenance"]["source_function_count"] = json!(3);
            let module: NativeModule = serde_json::from_value(wire).unwrap();
            let (assembly, map) = emit_with_map(&module, target).unwrap();
            assert_eq!(assembly, emit(&module, target).unwrap());
            map.verify(&module, target, &assembly).unwrap();
            let landing: Vec<_> = map
                .sites
                .iter()
                .filter(|site| site.kind == NativeAssemblySiteKind::ExceptionLanding)
                .collect();
            assert_eq!(landing.len(), 1);
            assert_eq!(landing[0].block, Some(7));
            assert_eq!(landing[0].instruction, None);
            assert!(landing[0].assembly_start < landing[0].assembly_end);
            assert_eq!(
                map.sites
                    .iter()
                    .filter(|site| site.kind == NativeAssemblySiteKind::ExceptionTable)
                    .count(),
                1
            );
            assert!(map
                .sites
                .iter()
                .filter(|site| site.kind == NativeAssemblySiteKind::Instruction)
                .all(|site| site.block == Some(23) && site.assembly_start == site.assembly_end));
            let mut missing_stub = map.clone();
            missing_stub
                .sites
                .retain(|site| site.kind != NativeAssemblySiteKind::ExceptionLanding);
            assert!(missing_stub.verify(&module, target, &assembly).is_err());
        }
    }

    #[test]
    fn module_digest_normalizes_json_order_and_whitespace_but_binds_provenance() {
        let target = Target::X86_64UnknownNone;
        let original = module("x86_64-unknown-linux-gnu");
        let bytes = original.to_json().unwrap();
        let decoded = NativeModule::from_json(&bytes).unwrap();
        let (_, map) = emit_with_map(&original, target).unwrap();
        let (_, restored) = emit_with_map(&decoded, target).unwrap();
        assert_eq!(map.module_sha256, restored.module_sha256);
        let mut changed = original.clone();
        changed.name.push_str("-another-module");
        let (assembly, changed_map) = emit_with_map(&changed, target).unwrap();
        assert_eq!(map.assembly_sha256, digest(assembly.as_bytes()));
        assert_ne!(map.module_sha256, changed_map.module_sha256);
    }
}
