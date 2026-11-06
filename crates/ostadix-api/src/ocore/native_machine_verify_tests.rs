    use super::*;
    fn identity_fixture(digit: char) -> ArtifactIdentity { ArtifactIdentity {bytes:1024,sha256:digit.to_string().repeat(64)} }
    fn register(register: PhysicalRegister, bits: u16) -> RegisterView { RegisterView {register,low_bit:0,bits} }
    fn registers(t: Target) -> (PhysicalRegister,PhysicalRegister,PhysicalRegister,PhysicalRegister) {
        use PhysicalRegister::*;
        match t {
            Target::X86_64UnknownNone => (X86Gpr{name:Gpr::Rdi},X86Gpr{name:Gpr::Rax},X86Gpr{name:Gpr::Rsp},X86Pc),
            Target::Aarch64UnknownNone => (Aarch64Gpr{index:0},Aarch64Gpr{index:9},Aarch64Sp,Aarch64Pc),
            Target::Riscv64UnknownNone => (RiscvGpr{index:10},RiscvGpr{index:5},RiscvGpr{index:2},RiscvPc),
        }
    }
    /// Inert metadata fixture only. No assembly text, GNU provenance, parser or
    /// original-source completeness proof is manufactured by this constructor.
    fn fixture(t: Target) -> (MachineBodyContract,SelectedInstructionInventory) {
        let (arg,scratch,sp,pc)=registers(t);
        let profile=MachineProfile {architecture:architecture(t),abi:match t {Target::X86_64UnknownNone=>MachineAbi::SysvAmd64,Target::Aarch64UnknownNone=>MachineAbi::Aapcs64,Target::Riscv64UnknownNone=>MachineAbi::RiscvLp64d},address_bits:64,byte_order:ByteOrder::Little,entry_stack_alignment:16,entry_stack_remainder:if t==Target::X86_64UnknownNone {8}else{0},features:vec![StateFeature::UserRegisterBits],cfi:CfiPolicy::Required};
        let interface=MachineInterface {entry:EntryInterface {policy:EntryPolicy::NoImplicitFrameOrScratch,initialized:vec![register(arg,64),register(sp,64),register(pc,64)],memory:MemoryInterface::None},exits:vec![ExitInterface {id:0,kind:ExitKind::OrdinaryReturn,outputs:vec![register(scratch,64)],preserved:vec![register(sp,64)]}]};
        let source=SourceWitness {format:SOURCE_FORMAT.into(),input_form:MachineInputForm::ConfiguredAssemblyText,unit_id:"inert-metadata-fixture".into(),files:vec![SourceFile{id:0,logical_path:"inert-metadata-only.source".into(),identity:identity_fixture('1')}],decoded_assembly:identity_fixture('2'),build_configuration:identity_fixture('3'),frontend_event:identity_fixture('4')};
        let items=(0_u64..6).map(|id|SourceItem{id,kind:if [2,3,4].contains(&id){SourceItemKind::Instruction}else{SourceItemKind::CfiDirective},decoded_span:SourceSpan{start:id*8,end:id*8+8},origins:vec![OriginalSpan{file:0,span:SourceSpan{start:id*8,end:id*8+8}}]}).collect();
        let inventory=SelectedInstructionInventory {format:INVENTORY_FORMAT.into(),identity:identity_fixture('5'),source:source.clone(),symbol:"inert_fixture".into(),profile:profile.clone(),interface:interface.clone(),items};
        let body=MachineBodyContract {format:FORMAT.into(),selected_inventory:inventory.identity.clone(),source,symbol:"inert_fixture".into(),profile,interface,entry:0,blocks:vec![MachineBlock{id:0,source_label:None,state_parameter:0,parameters:vec![],instructions:vec![MachineInstruction{source_item:2,state_in:0,state_out:1,result:Some(Scalar{id:0,bits:64}),operation:MachineOperation::ReadRegister{view:register(arg,64)}},MachineInstruction{source_item:3,state_in:1,state_out:2,result:None,operation:MachineOperation::WriteRegister{view:register(scratch,64),value:0,mode:WriteMode::WholeStorage}}],terminator:MachineTerminator{source_item:4,state:2,control:MachineControl::Return{exit:0}}}],directives:vec![DirectiveRecord{source_item:0,directive:MachineDirective::CfiStart},DirectiveRecord{source_item:1,directive:MachineDirective::CfiDefCfa{register:register(sp,64),offset:0}},DirectiveRecord{source_item:5,directive:MachineDirective::CfiEnd}]};
        (body,inventory)
    }
    fn rejected(body:&MachineBodyContract,floor:&SelectedInstructionInventory,t:Target,message:&str) {
        let error=verify(body,floor,t).unwrap_err(); assert!(error.message.contains(message),"{} did not contain {message}",error.message);
    }
    #[test]
    fn all_canonical_targets_have_only_relative_structural_coverage() {
        for &t in Target::ALL {
            let (b,i)=fixture(t);let report=verify(&b,&i,t).unwrap();
            assert_eq!(report.checked_inventory_items,6);assert_eq!(report.checked_instruction_sites,3);
            assert!(report.structural_coverage_relative_to_supplied_inventory);
            assert!(!report.source_custody_verified && !report.inventory_authority_verified && !report.original_unit_completeness_verified);
            assert!(!report.instruction_semantics_verified && !report.native_realization_verified && !report.entry_state_realization_verified);
            assert!(!report.cfi_semantics_verified && !report.memory_access_validity_verified);
            assert!(!report.provider_qualified && !report.runtime_qualified && !report.isa_equivalence_qualified && !report.ordinary_native_admission);
        }
    }
    #[test]
    fn x86_high_byte_alias_is_not_available_on_rsi() {
        let (mut b,i)=fixture(Target::X86_64UnknownNone);let bad=RegisterView{register:PhysicalRegister::X86Gpr{name:Gpr::Rsi},low_bit:8,bits:8};
        b.blocks[0].instructions[0].operation=MachineOperation::ReadRegister{view:bad};assert_eq!(bad.low_bit,8);
        rejected(&b,&i,Target::X86_64UnknownNone,"alias/width");
    }
    #[test]
    fn overlapping_entry_aliases_do_not_create_independent_storage() {
        let (mut b,mut i)=fixture(Target::X86_64UnknownNone);let reg=PhysicalRegister::X86Gpr{name:Gpr::Rax};b.interface.entry.initialized.extend([register(reg,64),register(reg,32)]);i.interface=b.interface.clone();
        assert_eq!(b.interface.entry.initialized.len(),5);rejected(&b,&i,Target::X86_64UnknownNone,"overlapping/duplicate");
    }
    #[test]
    fn invalid_view_width_is_refused_before_any_realization() {
        let (mut b,i)=fixture(Target::Riscv64UnknownNone);let bad=register(PhysicalRegister::RiscvGpr{index:10},65);b.blocks[0].instructions[0].operation=MachineOperation::ReadRegister{view:bad};assert_eq!(bad.bits,65);
        rejected(&b,&i,Target::Riscv64UnknownNone,"alias/width");
    }
    #[test]
    fn x86_32bit_write_requires_upper_storage_zero_extension() {
        let (mut b,i)=fixture(Target::X86_64UnknownNone);let (arg,temp,_,_)=registers(Target::X86_64UnknownNone);
        b.blocks[0].instructions[0].operation=MachineOperation::ReadRegister{view:register(arg,32)};b.blocks[0].instructions[0].result=Some(Scalar{id:0,bits:32});
        b.blocks[0].instructions[1].operation=MachineOperation::WriteRegister{view:register(temp,32),value:0,mode:WriteMode::PreserveOtherBits};
        rejected(&b,&i,Target::X86_64UnknownNone,"alias write/zero-extension");
        b.blocks[0].instructions[1].operation=MachineOperation::WriteRegister{view:register(temp,32),value:0,mode:WriteMode::ZeroExtendStorage};assert!(verify(&b,&i,Target::X86_64UnknownNone).is_ok());
    }
    #[test]
    fn undeclared_entry_register_bits_cannot_be_read() {
        for &t in Target::ALL {let (mut b,mut i)=fixture(t);let arg=registers(t).0;b.interface.entry.initialized.retain(|v|v.register!=arg);i.interface=b.interface.clone();assert_eq!(b.interface.entry.initialized.len(),2);rejected(&b,&i,t,"uninitialized entry bits");}
    }
    #[test]
    fn ordinary_prologue_and_unverified_snapshot_are_not_entry_preservation_proofs() {
        for policy in [EntryPolicy::OrdinaryCompilerPrologue,EntryPolicy::UnverifiedEntrySnapshot] {let (mut b,mut i)=fixture(Target::Aarch64UnknownNone);b.interface.entry.policy=policy;i.interface=b.interface.clone();assert_eq!(b.interface.entry.policy,policy);rejected(&b,&i,Target::Aarch64UnknownNone,"ordinary prologue/unverified entry snapshot");}
    }
    #[test]
    fn state_tokens_must_follow_each_instruction_and_final_transfer() {
        let t=Target::X86_64UnknownNone;let (base,i)=fixture(t);let mut b=base.clone();b.blocks[0].instructions[1].state_in=0;assert_ne!(b.blocks[0].instructions[1].state_in,b.blocks[0].instructions[0].state_out);rejected(&b,&i,t,"state SSA chain");
        b=base;b.blocks[0].terminator.state=0;assert_ne!(b.blocks[0].terminator.state,b.blocks[0].instructions[1].state_out);rejected(&b,&i,t,"final state SSA token");
    }
    #[test]
    fn duplicate_state_and_scalar_definitions_are_rejected() {
        let t=Target::Riscv64UnknownNone;let (base,i)=fixture(t);let mut b=base.clone();b.blocks[0].instructions[1].state_out=1;rejected(&b,&i,t,"duplicate state SSA");
        b=base;b.blocks[0].instructions[1].result=Some(Scalar{id:0,bits:64});rejected(&b,&i,t,"duplicate scalar SSA");
    }
    #[test]
    fn scalar_use_before_definition_is_rejected() {
        let t=Target::Aarch64UnknownNone;let (mut b,i)=fixture(t);let temp=registers(t).1;b.blocks[0].instructions[1].operation=MachineOperation::WriteRegister{view:register(temp,64),value:99,mode:WriteMode::WholeStorage};
        assert!(matches!(b.blocks[0].instructions[1].operation,MachineOperation::WriteRegister{value:99,..}));rejected(&b,&i,t,"SSA value is not defined earlier");
    }
    #[test]
    fn ordered_memory_interface_is_required_for_loads() {
        let t=Target::Riscv64UnknownNone;let (mut b,i)=fixture(t);b.blocks[0].instructions[1].operation=MachineOperation::Load{address:0,alignment:8};b.blocks[0].instructions[1].result=Some(Scalar{id:1,bits:64});assert_eq!(b.interface.entry.memory,MemoryInterface::None);rejected(&b,&i,t,"load requires explicit ordered process-memory");
    }
    #[test]
    fn control_edges_need_existing_targets_and_one_bit_conditions() {
        let t=Target::Aarch64UnknownNone;let (base,i)=fixture(t);let mut b=base.clone();b.blocks[0].terminator.control=MachineControl::Jump{edge:Edge{target:999,arguments:vec![]}};rejected(&b,&i,t,"edge target is missing");
        b=base;b.blocks[0].terminator.control=MachineControl::Branch{condition:0,on_true:Edge{target:0,arguments:vec![]},on_false:Edge{target:0,arguments:vec![]}};rejected(&b,&i,t,"exactly one bit");
    }
    #[test]
    fn cross_block_values_require_explicit_parameters_and_unique_state_interface() {
        for &t in Target::ALL {
            let (mut b,mut i)=fixture(t);let temporary=registers(t).1;
            b.blocks[0].terminator.control=MachineControl::Jump{edge:Edge{target:1,arguments:vec![0]}};
            b.blocks.push(MachineBlock{id:1,source_label:None,state_parameter:3,parameters:vec![Scalar{id:1,bits:64}],instructions:vec![MachineInstruction{source_item:6,state_in:3,state_out:4,result:None,operation:MachineOperation::WriteRegister{view:register(temporary,64),value:1,mode:WriteMode::WholeStorage}}],terminator:MachineTerminator{source_item:7,state:4,control:MachineControl::Return{exit:0}}});
            let end=i.items.pop().unwrap();
            for id in [6,7] {let mut item=i.items[2].clone();item.id=id;i.items.push(item);}
            i.items.push(end);
            for (index,item) in i.items.iter_mut().enumerate() {item.decoded_span=SourceSpan{start:index as u64*8,end:index as u64*8+8};item.origins[0].span=item.decoded_span;}
            let report=verify(&b,&i,t).unwrap();assert_eq!(report.checked_inventory_items,8);assert_eq!(report.checked_instruction_sites,5);assert!(!report.instruction_semantics_verified);
            let mut bad=b.clone();bad.blocks[1].instructions[0].operation=MachineOperation::WriteRegister{view:register(temporary,64),value:0,mode:WriteMode::WholeStorage};rejected(&bad,&i,t,"SSA value is not defined earlier");
            bad=b.clone();bad.blocks[1].parameters[0].bits=32;rejected(&bad,&i,t,"edge/block-parameter width differs");
            bad=b;bad.blocks[1].state_parameter=1;rejected(&bad,&i,t,"duplicate state SSA definition");
        }
    }
    #[test]
    fn separately_selected_floor_catches_missing_instruction_and_directive() {
        let t=Target::X86_64UnknownNone;let (base,mut floor)=fixture(t);let mut extra=floor.items[2].clone();extra.id=6;extra.decoded_span=SourceSpan{start:48,end:56};floor.items.push(extra);assert_eq!(floor.items.len(),7);rejected(&base,&floor,t,"missing independently selected original instruction");
        let (mut b,i)=fixture(t);b.directives.pop();assert_eq!(b.directives.len(),2);rejected(&b,&i,t,"missing independently selected original instruction/directive");
    }
    #[test]
    fn duplicate_inventory_ids_and_duplicate_directive_coverage_are_not_counts() {
        let t=Target::X86_64UnknownNone;let (base,mut i)=fixture(t);let mut dupe=i.items[2].clone();dupe.decoded_span=SourceSpan{start:48,end:56};i.items.push(dupe);rejected(&base,&i,t,"duplicate independently selected source item");
        let (mut b,i)=fixture(t);b.directives.push(b.directives[0].clone());assert_eq!(b.directives.len(),4);rejected(&b,&i,t,"duplicate directive/label coverage");
    }
    #[test]
    fn inactive_cfi_restore_and_unclosed_region_are_rejected() {
        let t=Target::X86_64UnknownNone;let (base,i)=fixture(t);let mut b=base.clone();b.directives[0].directive=MachineDirective::CfiRestore{register:register(registers(t).0,64)};rejected(&b,&i,t,"CFI restore requires active CFA state");
        b=base;b.directives[2].directive=MachineDirective::CfiDefCfa{register:register(registers(t).2,64),offset:0};rejected(&b,&i,t,"required CFI region is missing or remains open");
    }
    #[test]
    fn cfi_cfa_cannot_be_a_floating_register_view() {
        let t=Target::Aarch64UnknownNone;let (mut b,i)=fixture(t);b.directives[1].directive=MachineDirective::CfiDefCfa{register:register(PhysicalRegister::Aarch64Vector{index:0},64),offset:0};rejected(&b,&i,t,"CFI CFA must use");
    }
    #[test]
    fn source_spans_and_original_file_bindings_are_required() {
        let t=Target::Riscv64UnknownNone;let (b,mut i)=fixture(t);i.items[2].origins[0].file=99;assert_eq!(i.items[2].origins[0].file,99);rejected(&b,&i,t,"unknown original source file");
        let (b,mut i)=fixture(t);i.items[2].decoded_span.end=2000;rejected(&b,&i,t,"out of selected source extent");
    }
    #[test]
    fn cross_target_profile_abi_and_registers_are_rejected() {
        let t=Target::X86_64UnknownNone;let (base,i)=fixture(t);rejected(&base,&i,Target::Aarch64UnknownNone,"selected canonical target");
        let mut b=base.clone();b.blocks[0].instructions[0].operation=MachineOperation::ReadRegister{view:register(PhysicalRegister::Aarch64Gpr{index:0},64)};rejected(&b,&i,t,"cross-target register");
        b=base;let mut i=i;b.profile.abi=MachineAbi::RiscvLp64d;i.profile=b.profile.clone();rejected(&b,&i,t,"unsupported machine ABI");
    }
    #[test]
    fn i686_armv7_and_security_or_tls_states_remain_explicitly_unsupported() {
        let t=Target::X86_64UnknownNone;
        for arch in [Architecture::I686,Architecture::Armv7] {let (mut b,mut i)=fixture(t);b.profile.architecture=arch;i.profile=b.profile.clone();rejected(&b,&i,t,"foundations are not implemented");}
        for feature in [StateFeature::ThreadPointer,StateFeature::TlsPointerMangling,StateFeature::CetShadowStack,StateFeature::PointerAuthentication,StateFeature::GuardedControlStack,StateFeature::ScalableMatrixZa,StateFeature::FloatingEnvironment] {let (mut b,mut i)=fixture(t);b.profile.features.push(feature);i.profile=b.profile.clone();assert_eq!(b.profile.features.len(),2);rejected(&b,&i,t,"state feature is not implemented");}
    }
    #[test]
    fn direct_sp_pc_writes_and_restored_control_remain_closed() {
        for &t in Target::ALL {
            let (base,i)=fixture(t);
            for target in [registers(t).2,registers(t).3] {let mut b=base.clone();b.blocks[0].instructions[1].operation=MachineOperation::WriteRegister{view:register(target,64),value:0,mode:WriteMode::WholeStorage};rejected(&b,&i,t,"SP/PC/zero/flags");}
            let mut b=base;b.blocks[0].terminator.control=MachineControl::RestoreContext{stack_pointer:0,program_counter:0};rejected(&b,&i,t,"restored SP/PC transfer is unsupported");
        }
    }
    #[test]
    fn readonly_exit_preservation_blocks_overlapping_alias_writes() {
        let t=Target::X86_64UnknownNone;let (mut b,mut i)=fixture(t);let temp=registers(t).1;b.interface.entry.initialized.push(register(temp,64));b.interface.exits[0].preserved.push(register(temp,8));i.interface=b.interface.clone();assert_eq!(b.interface.exits[0].preserved.len(),2);rejected(&b,&i,t,"write overlaps readonly exit-preserved");
    }
    #[test]
    fn changed_selected_provenance_cannot_be_relabelled_as_the_same_source() {
        let t=Target::X86_64UnknownNone;let (mut b,i)=fixture(t);b.source.files[0].identity.sha256="a".repeat(64);assert_ne!(b.source,i.source);rejected(&b,&i,t,"separately selected inventory/source/profile/interface");
    }
    #[test]
    fn data_directives_cannot_escape_as_unchecked_machine_bytes() {
        let t=Target::X86_64UnknownNone;let (mut b,mut i)=fixture(t);i.items[5].kind=SourceItemKind::DataDirective;b.directives[2].directive=MachineDirective::UnsupportedData;rejected(&b,&i,t,"data/relocation directive semantics are not implemented");
    }
    #[test]
    fn exit_output_bits_must_be_initialized_by_entry_or_body() {
        let t=Target::Aarch64UnknownNone;let (mut b,i)=fixture(t);b.blocks[0].instructions[1].operation=MachineOperation::Constant{little_endian:vec![0;8]};b.blocks[0].instructions[1].result=Some(Scalar{id:1,bits:64});
        assert_eq!(b.interface.exits[0].outputs,vec![register(registers(t).1,64)]);rejected(&b,&i,t,"uninitialized entry bits");
    }
    #[test]
    fn unknown_opcodes_architectures_and_fields_cannot_be_deserialized() {
        assert!(serde_json::from_str::<MachineOperation>(r#"{"op":"raw_assembly","text":"untrusted"}"#).is_err());
        assert!(serde_json::from_str::<Architecture>(r#""unknown_isa""#).is_err());
        let (b,_)=fixture(Target::X86_64UnknownNone);let mut value=serde_json::to_value(b).unwrap();value["qualified"]=serde_json::json!(true);assert!(serde_json::from_value::<MachineBodyContract>(value).is_err());
    }

    // Authored inert metadata controls. These do not authenticate an original
    // source inventory, interpret CFI offsets, or realize machine entry state.
    fn relative_cfi_only(report: &StructuralReport) {
        assert!(report.structural_coverage_relative_to_supplied_inventory);
        assert!(!report.source_custody_verified && !report.inventory_authority_verified && !report.original_unit_completeness_verified);
        assert!(!report.instruction_semantics_verified && !report.native_realization_verified && !report.cfi_semantics_verified);
        assert!(!report.memory_access_validity_verified && !report.entry_state_realization_verified);
        assert!(!report.provider_qualified && !report.runtime_qualified && !report.isa_equivalence_qualified && !report.ordinary_native_admission);
    }
    fn respan_cfi_fixture(inventory: &mut SelectedInstructionInventory) {
        for (index,item) in inventory.items.iter_mut().enumerate() {
            assert_eq!(item.origins.len(),1);
            let start=index as u64*8;
            item.decoded_span=SourceSpan{start,end:start+8};
            item.origins[0].span=item.decoded_span;
        }
    }
    fn cfi_saved_fixture(t: Target) -> (MachineBodyContract,SelectedInstructionInventory) {
        let (mut body,mut inventory)=fixture(t);
        let arg=register(registers(t).0,64);
        body.directives.insert(2,DirectiveRecord{source_item:6,directive:MachineDirective::CfiSaved{register:arg,offset:-8}});
        body.directives.insert(3,DirectiveRecord{source_item:7,directive:MachineDirective::CfiRestore{register:arg}});
        let mut saved=inventory.items[0].clone();saved.id=6;
        let mut restored=saved.clone();restored.id=7;
        inventory.items.insert(2,saved);inventory.items.insert(3,restored);
        respan_cfi_fixture(&mut inventory);
        (body,inventory)
    }
    #[test]
    fn required_cfi_region_covers_instructions_and_return_not_an_empty_region() {
        for &t in Target::ALL {
            let (body,baseline)=fixture(t);
            relative_cfi_only(&verify(&body,&baseline,t).unwrap());
            assert_eq!(body.profile.cfi,CfiPolicy::Required);
            assert!(matches!(body.blocks[0].terminator.control,MachineControl::Return{..}));
            // Empty closed region before the whole body; instruction before
            // Start; Return after End. Every original ID remains selected.
            for order in [[0,1,5,2,3,4],[2,0,1,3,4,5],[0,1,2,3,5,4]] {
                let mut inventory=baseline.clone();
                inventory.items=order.iter().map(|id|baseline.items.iter().find(|item|item.id==*id).unwrap().clone()).collect();
                respan_cfi_fixture(&mut inventory);
                assert_eq!(inventory.items.iter().map(|item|item.id).collect::<Vec<_>>(),order.to_vec());
                assert_eq!(inventory.items.iter().map(|item|item.id).collect::<BTreeSet<_>>(),baseline.items.iter().map(|item|item.id).collect::<BTreeSet<_>>());
                assert_eq!(body.source,inventory.source);assert_eq!(body.profile,inventory.profile);assert_eq!(body.interface,inventory.interface);
                assert_eq!(body.selected_inventory,inventory.identity);
                let error=verify(&body,&inventory,t).unwrap_err();
                assert_eq!(error.message,"machine instruction is outside the active required CFI region");
            }
        }
    }
    #[test]
    fn cfi_restore_missing_saved_rule_reaches_the_active_cfa_guard() {
        for &t in Target::ALL {
            let (baseline,inventory)=cfi_saved_fixture(t);
            let report=verify(&baseline,&inventory,t).unwrap();relative_cfi_only(&report);
            assert_eq!(report.checked_inventory_items,8);assert_eq!(report.checked_instruction_sites,3);
            let arg=register(registers(t).0,64);let scratch=register(registers(t).1,64);assert_ne!(arg,scratch);
            assert_eq!(baseline.directives[0].directive,MachineDirective::CfiStart);
            assert!(matches!(baseline.directives[1].directive,MachineDirective::CfiDefCfa{..}));
            assert_eq!(baseline.directives[2].directive,MachineDirective::CfiSaved{register:arg,offset:-8});
            assert_eq!(baseline.directives[3].directive,MachineDirective::CfiRestore{register:arg});
            let mut bad=baseline.clone();
            // ONLY the saved register changes. Start/CFA/Restore, source floor,
            // all source spans, scalar/state chain and entry/exit remain valid.
            bad.directives[2].directive=MachineDirective::CfiSaved{register:scratch,offset:-8};
            assert_eq!(&bad.directives[..2],&baseline.directives[..2]);assert_eq!(&bad.directives[3..],&baseline.directives[3..]);
            assert_eq!(bad.blocks,baseline.blocks);assert_eq!(bad.interface,baseline.interface);assert_eq!(bad.source,baseline.source);
            assert_eq!(bad.directives[2].directive,MachineDirective::CfiSaved{register:scratch,offset:-8});
            let error=verify(&bad,&inventory,t).unwrap_err();
            assert_eq!(error.message,"CFI restore has no prior saved-register rule");
        }
    }
    #[test]
    fn required_cfi_points_keep_exact_missing_duplicate_and_span_guards() {
        for &t in Target::ALL {
            let (baseline,floor)=cfi_saved_fixture(t);relative_cfi_only(&verify(&baseline,&floor,t).unwrap());
            let mut bad=baseline.clone();let removed=bad.directives.remove(2);assert_eq!(removed.source_item,6);
            assert!(floor.items.iter().any(|item|item.id==6 && item.kind==SourceItemKind::CfiDirective));
            rejected(&bad,&floor,t,"missing independently selected original instruction/directive/label coverage");
            let mut missing=floor.clone();missing.items.retain(|item|item.id!=6);
            assert!(!missing.items.iter().any(|item|item.id==6));assert_eq!(baseline.directives[2].source_item,6);
            rejected(&baseline,&missing,t,"body site has no independently selected inventory item");
            bad=baseline.clone();bad.directives.push(baseline.directives[2].clone());
            assert_eq!(bad.directives.iter().filter(|d|d.source_item==6).count(),2);
            rejected(&bad,&floor,t,"duplicate directive/label coverage");
            let mut duplicate=floor.clone();let mut extra=duplicate.items.iter().find(|item|item.id==6).unwrap().clone();
            extra.decoded_span=SourceSpan{start:64,end:72};extra.origins[0].span=extra.decoded_span;duplicate.items.push(extra);
            assert_eq!(duplicate.items.iter().filter(|item|item.id==6 && item.kind==SourceItemKind::CfiDirective).count(),2);
            rejected(&baseline,&duplicate,t,"duplicate independently selected source item");
            let mut outside=floor.clone();let item=outside.items.iter_mut().find(|item|item.id==6).unwrap();
            assert_eq!(item.kind,SourceItemKind::CfiDirective);item.decoded_span.end=baseline.source.decoded_assembly.bytes+1;
            assert!(item.decoded_span.end>baseline.source.decoded_assembly.bytes);
            rejected(&baseline,&outside,t,"out of selected source extent");
        }
    }
    #[test]
    fn no_cfi_declared_does_not_require_a_synthetic_region() {
        for &t in Target::ALL {
            let (mut body,mut inventory)=fixture(t);
            body.profile.cfi=CfiPolicy::NoCfiDeclared;inventory.profile=body.profile.clone();
            body.directives.clear();inventory.items.retain(|item|item.kind==SourceItemKind::Instruction);
            respan_cfi_fixture(&mut inventory);
            assert!(body.directives.is_empty());assert_eq!(inventory.items.iter().map(|item|item.id).collect::<Vec<_>>(),vec![2,3,4]);
            let report=verify(&body,&inventory,t).unwrap();relative_cfi_only(&report);
            assert_eq!(report.checked_inventory_items,3);assert_eq!(report.checked_instruction_sites,3);
        }
    }
// Include INSIDE native_machine_verify.rs's existing #[cfg(test)] mod tests.
// Uses its actual fixture(Target)->(MachineBodyContract,SelectedInstructionInventory)
// and verify API. Authored DATA only: no authentic assembly, run or native proof.
// Intended for the NEW definite-initialization repair; old f6ad verifier is
// source-predicted to accept the three invalidation counterexamples. UNRUN.
// R1 publication remains UNKNOWN. R2 additionally isolates stable-entry loops.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CfgFlagGraph { Successor, Diamond, Loop, RestoredDiamond, RestoredLoop, StableLoop }

struct CfgFlagBlock {
    id: usize,
    label: Option<u64>,
    state_parameter: usize,
    state: usize,
    instructions: Vec<MachineInstruction>,
}

struct CfgFlagAssembler {
    template: SourceItem,
    items: Vec<SourceItem>,
    next_item: u64,
    next_value: usize,
    next_state: usize,
}

impl CfgFlagAssembler {
    fn item(&mut self, kind: SourceItemKind) -> u64 {
        let id = self.next_item;
        self.next_item += 1;
        let mut item = self.template.clone();
        item.id = id;
        item.kind = kind;
        self.items.push(item);
        id
    }
    fn state(&mut self) -> usize {
        let state = self.next_state;
        self.next_state += 1;
        state
    }
    fn block(&mut self, id: usize) -> CfgFlagBlock {
        let label = if id == 0 { None } else { Some(self.item(SourceItemKind::Label)) };
        let state = self.state();
        CfgFlagBlock { id, label, state_parameter: state, state, instructions: vec![] }
    }
    fn emit(&mut self, block: &mut CfgFlagBlock, operation: MachineOperation, bits: Option<u16>) -> Option<Scalar> {
        let source_item = self.item(SourceItemKind::Instruction);
        let result = bits.map(|bits| {
            let id = self.next_value;
            self.next_value += 1;
            Scalar { id, bits }
        });
        let state_out = self.state();
        block.instructions.push(MachineInstruction {
            source_item, state_in: block.state, state_out, result, operation,
        });
        block.state = state_out;
        result
    }
    fn finish(&mut self, block: CfgFlagBlock, control: MachineControl) -> MachineBlock {
        let source_item = self.item(SourceItemKind::Instruction);
        MachineBlock { id: block.id, source_label: block.label,
            state_parameter: block.state_parameter, parameters: vec![],
            instructions: block.instructions,
            terminator: MachineTerminator { source_item, state: block.state, control } }
    }
    fn invalidate_af(&mut self, block: &mut CfgFlagBlock) {
        assert!(self.emit(block, MachineOperation::InvalidateRegister { view: cfg_flag_view(4) }, None).is_none());
    }
    fn restore_af(&mut self, block: &mut CfgFlagBlock, value: u8) {
        let constant = self.emit(block, MachineOperation::Constant { little_endian: vec![value] }, Some(1)).unwrap();
        assert!(self.emit(block, MachineOperation::WriteFlags { view: cfg_flag_view(4), value: constant.id }, None).is_none());
    }
}

fn cfg_flag_view(bit: u16) -> RegisterView {
    RegisterView { register: PhysicalRegister::X86Flags, low_bit: bit, bits: 1 }
}
fn cfg_jump(target: usize) -> MachineControl {
    MachineControl::Jump { edge: Edge { target, arguments: vec![] } }
}
fn cfg_branch(condition: Scalar, yes: usize, no: usize) -> MachineControl {
    MachineControl::Branch { condition: condition.id,
        on_true: Edge { target: yes, arguments: vec![] },
        on_false: Edge { target: no, arguments: vec![] } }
}

fn cfg_flag_case(kind: CfgFlagGraph) -> (MachineBodyContract, SelectedInstructionInventory) {
    let (mut body, mut floor) = fixture(Target::X86_64UnknownNone);
    // These DATA functions declare flags clobberable, so a readonly exit
    // promise or unrelated scratch output cannot mask the CFG classification.
    body.interface.entry.initialized.retain(|v| v.register != PhysicalRegister::X86Flags);
    body.interface.entry.initialized.push(RegisterView {
        register: PhysicalRegister::X86Flags, low_bit: 0, bits: 64,
    });
    for exit in &mut body.interface.exits {
        exit.outputs.clear();
        exit.preserved.retain(|v| v.register != PhysicalRegister::X86Flags);
    }
    floor.interface = body.interface.clone();
    let exit = body.interface.exits[0].id;
    let template = floor.items.iter().find(|i| i.kind == SourceItemKind::Instruction).unwrap().clone();
    let prefix: Vec<_> = floor.items.iter().filter(|i| i.id == 0 || i.id == 1).cloned().collect();
    let end = floor.items.iter().find(|i| i.id == 5).unwrap().clone();
    assert_eq!(prefix.len(), 2, "actual base fixture CFI start/CFA changed");
    let mut a = CfgFlagAssembler { template, items: vec![], next_item: 10, next_value: 0, next_state: 0 };
    let mut blocks = vec![];
    let mut entry = a.block(0);
    // A separately selected unused record isolates the coverage guard below.
    a.emit(&mut entry, MachineOperation::Constant { little_endian: vec![0; 8] }, Some(64));
    match kind {
        CfgFlagGraph::Successor => {
            a.invalidate_af(&mut entry);
            blocks.push(a.finish(entry, cfg_jump(1)));
            let mut next = a.block(1);
            a.emit(&mut next, MachineOperation::ReadFlags { view: cfg_flag_view(4) }, Some(1));
            blocks.push(a.finish(next, MachineControl::Return { exit }));
        }
        CfgFlagGraph::Diamond | CfgFlagGraph::RestoredDiamond => {
            // Entry CF is a real input, not a constant: both predecessors are
            // selectable under this explicitly declared DATA interface.
            let cf = a.emit(&mut entry, MachineOperation::ReadFlags { view: cfg_flag_view(0) }, Some(1)).unwrap();
            blocks.push(a.finish(entry, cfg_branch(cf, 1, 2)));
            let mut left = a.block(1);
            a.invalidate_af(&mut left);
            if kind == CfgFlagGraph::RestoredDiamond { a.restore_af(&mut left, 1); }
            blocks.push(a.finish(left, cfg_jump(3)));
            let mut right = a.block(2);
            if kind == CfgFlagGraph::RestoredDiamond { a.restore_af(&mut right, 0); }
            blocks.push(a.finish(right, cfg_jump(3)));
            let mut join = a.block(3);
            a.emit(&mut join, MachineOperation::ReadFlags { view: cfg_flag_view(4) }, Some(1));
            blocks.push(a.finish(join, MachineControl::Return { exit }));
        }
        CfgFlagGraph::Loop | CfgFlagGraph::RestoredLoop | CfgFlagGraph::StableLoop => {
            blocks.push(a.finish(entry, cfg_jump(1)));
            let mut header = a.block(1);
            let af = a.emit(&mut header, MachineOperation::ReadFlags { view: cfg_flag_view(4) }, Some(1)).unwrap();
            blocks.push(a.finish(header, cfg_branch(af, 2, 3)));
            let mut backedge = a.block(2);
            if kind != CfgFlagGraph::StableLoop { a.invalidate_af(&mut backedge); }
            if kind == CfgFlagGraph::RestoredLoop { a.restore_af(&mut backedge, 1); }
            blocks.push(a.finish(backedge, cfg_jump(1)));
            let end_block = a.block(3);
            blocks.push(a.finish(end_block, MachineControl::Return { exit }));
        }
    }
    body.entry = 0;
    body.blocks = blocks;
    floor.items = prefix.into_iter().chain(a.items).chain(std::iter::once(end)).collect();
    // Respan the COMPLETE selected floor under the base 1024-byte DATA claim.
    assert!(floor.items.len() * 8 <= 1024);
    for (index, item) in floor.items.iter_mut().enumerate() {
        let span = SourceSpan { start: index as u64 * 8, end: (index as u64 + 1) * 8 };
        item.decoded_span = span;
        assert!(!item.origins.is_empty());
        for origin in &mut item.origins { origin.span = span; }
    }
    cfg_assert_complete_floor(&body, &floor);
    (body, floor)
}

fn cfg_assert_complete_floor(body: &MachineBodyContract, floor: &SelectedInstructionInventory) {
    let expected: std::collections::BTreeSet<_> = floor.items.iter().map(|i| i.id).collect();
    assert_eq!(expected.len(), floor.items.len(), "duplicate selected record ID");
    let mut reached: std::collections::BTreeSet<_> = body.directives.iter().map(|d| d.source_item).collect();
    for block in &body.blocks {
        reached.extend(block.source_label);
        reached.extend(block.instructions.iter().map(|i| i.source_item));
        reached.insert(block.terminator.source_item);
    }
    assert_eq!(reached, expected, "retain the complete selected floor");
}

fn cfg_expect_uninitialized(body: &MachineBodyContract, floor: &SelectedInstructionInventory) {
    match verify(body, floor, Target::X86_64UnknownNone) {
        Ok(_) => panic!("undefined AF crossed a CFG edge and was incorrectly reinitialized"),
        Err(error) => assert!(error.message.contains("undefined/uninitialized"), "wrong reason: {}", error.message),
    }
}

#[test]
fn invalidated_flag_does_not_reappear_in_a_successor_block() {
    let (body, floor) = cfg_flag_case(CfgFlagGraph::Successor);
    assert!(body.blocks[0].instructions.iter().any(|i| matches!(i.operation,
        MachineOperation::InvalidateRegister { view } if view == cfg_flag_view(4))));
    assert!(body.blocks[1].instructions.iter().any(|i| matches!(i.operation,
        MachineOperation::ReadFlags { view } if view == cfg_flag_view(4))));
    cfg_expect_uninitialized(&body, &floor);
}

#[test]
fn join_uses_intersection_instead_of_a_preserving_predecessor_or_entry_seed() {
    let (body, floor) = cfg_flag_case(CfgFlagGraph::Diamond);
    assert!(body.blocks[1].instructions.iter().any(|i| matches!(i.operation,
        MachineOperation::InvalidateRegister { view } if view == cfg_flag_view(4))));
    assert!(body.blocks[2].instructions.is_empty(), "other predecessor retains entry AF");
    assert!(body.blocks[3].instructions.iter().any(|i| matches!(i.operation,
        MachineOperation::ReadFlags { view } if view == cfg_flag_view(4))));
    cfg_expect_uninitialized(&body, &floor);
}

#[test]
fn loop_backedge_invalidation_reaches_the_header_fixed_point() {
    let (body, floor) = cfg_flag_case(CfgFlagGraph::Loop);
    assert!(matches!(&body.blocks[2].terminator.control,
        MachineControl::Jump { edge } if edge.target == 1));
    assert!(body.blocks[2].instructions.iter().any(|i| matches!(i.operation,
        MachineOperation::InvalidateRegister { view } if view == cfg_flag_view(4))));
    cfg_expect_uninitialized(&body, &floor);
}

#[test]
fn all_predecessors_restoring_the_flag_are_accepted() {
    let (body, floor) = cfg_flag_case(CfgFlagGraph::RestoredDiamond);
    for index in [1, 2] {
        assert!(body.blocks[index].instructions.iter().any(|i| matches!(i.operation,
            MachineOperation::WriteFlags { view, .. } if view == cfg_flag_view(4))));
    }
    assert!(verify(&body, &floor, Target::X86_64UnknownNone).is_ok());
}

#[test]
fn restored_loop_backedge_retains_a_definite_flag_value() {
    let (body, floor) = cfg_flag_case(CfgFlagGraph::RestoredLoop);
    let backedge = &body.blocks[2];
    assert!(backedge.instructions.iter().any(|i| matches!(i.operation,
        MachineOperation::InvalidateRegister { view } if view == cfg_flag_view(4))));
    assert!(backedge.instructions.iter().any(|i| matches!(i.operation,
        MachineOperation::WriteFlags { view, .. } if view == cfg_flag_view(4))));
    assert!(verify(&body, &floor, Target::X86_64UnknownNone).is_ok());
}

#[test]
fn unchanged_entry_defined_flag_survives_a_loop_without_a_spurious_write() {
    let (body, floor) = cfg_flag_case(CfgFlagGraph::StableLoop);
    assert!(body.interface.entry.initialized.iter().any(|v|
        v.register == PhysicalRegister::X86Flags && v.low_bit == 0 && v.bits == 64));
    assert!(body.blocks[2].instructions.is_empty(), "backedge has no restoring write or invalidation");
    assert!(matches!(&body.blocks[2].terminator.control,
        MachineControl::Jump { edge } if edge.target == 1));
    assert!(body.blocks[1].instructions.iter().any(|i| matches!(i.operation,
        MachineOperation::ReadFlags { view } if view == cfg_flag_view(4))));
    // This rejects bottom-initialized loop analyses that lose a defined entry
    // fact forever even though every actual path preserves it.
    assert!(verify(&body, &floor, Target::X86_64UnknownNone).is_ok());
}

#[test]
fn cfg_repair_never_qualifies_a_graph_with_an_omitted_selected_record() {
    let (mut body, floor) = cfg_flag_case(CfgFlagGraph::RestoredDiamond);
    assert!(verify(&body, &floor, Target::X86_64UnknownNone).is_ok(), "pristine complete graph");
    let entry = &mut body.blocks[0];
    let omitted = entry.instructions.remove(0);
    assert!(matches!(omitted.operation, MachineOperation::Constant { .. }));
    assert!(floor.items.iter().any(|i| i.id == omitted.source_item));
    assert!(!body.blocks.iter().flat_map(|b| &b.instructions).any(|i| i.source_item == omitted.source_item));
    // Repair the state chain honestly: the reason must be missing coverage.
    let entry = &mut body.blocks[0];
    if let Some(first) = entry.instructions.first_mut() { first.state_in = entry.state_parameter; }
    else { entry.terminator.state = entry.state_parameter; }
    match verify(&body, &floor, Target::X86_64UnknownNone) {
        Ok(_) => panic!("partial selected instruction floor was accepted"),
        Err(error) => assert!(error.message.contains("missing independently selected original instruction/directive/label coverage"), "wrong reason: {}", error.message),
    }
}

// Included inside native_machine_verify::tests: actual builder/lifters/verifier.
// Test-only graph observation is DATA, not an unchanged-IR runtime or native proof.
use super::super::native_machine_asm_reader as return_syntax;
use super::super::native_machine_lift::{BlockLifter as ReturnLifter,LiftFlow as ReturnFlow,LiftIds as ReturnIds};
fn return_register(t:Target)->RegisterView {
    register(match t {Target::Riscv64UnknownNone=>PhysicalRegister::RiscvGpr{index:1},
        Target::Aarch64UnknownNone=>PhysicalRegister::Aarch64Gpr{index:30},
        Target::X86_64UnknownNone=>panic!("x86 stack return remains unsupported")},64)
}
fn return_parts(c:&MachineControl)->(u32,usize,ReturnMechanism) {
    match c {MachineControl::ReturnTo{exit,target,mechanism}=>(*exit,*target,*mechanism),other=>panic!("not computed return: {other:?}")}
}
fn return_flow_parts(f:&ReturnFlow)->(Scalar,ReturnMechanism) {
    match f {ReturnFlow::ReturnTo{target,mechanism}=>(*target,*mechanism),other=>panic!("not computed return flow: {other:?}")}
}
fn return_unqualified(r:&StructuralReport){
    assert!(!r.source_custody_verified&&!r.inventory_authority_verified&&!r.original_unit_completeness_verified);
    assert!(!r.instruction_semantics_verified&&!r.native_realization_verified&&!r.cfi_semantics_verified);
    assert!(!r.memory_access_validity_verified&&!r.entry_state_realization_verified);
    assert!(!r.provider_qualified&&!r.runtime_qualified&&!r.isa_equivalence_qualified&&!r.ordinary_native_admission);
}
fn return_case(t:Target)->(MachineBodyContract,SelectedInstructionInventory,ReturnFlow){
    let(mut body,mut floor)=fixture(t);let link=return_register(t);
    body.format=COMPUTED_CONTROL_FORMAT.into();body.interface.entry.initialized.push(link);
    body.interface.exits[0].outputs.clear();floor.interface=body.interface.clone();
    floor.items.retain(|x|[0,1,4,5].contains(&x.id));
    let profile=body.profile.clone();let mut ids=ReturnIds::new(0,1);let mut code=vec![];
    let(flow,control,state)={let mut b=ReturnLifter::new(&profile,4,0,&mut ids,&mut code);
        let flow=match t{
            Target::Riscv64UnknownNone=>super::super::native_machine_lift_rv64::lower_rv64(return_syntax::RiscvOpcode::Return,"ret",&[],&mut b).unwrap(),
            Target::Aarch64UnknownNone=>super::super::native_machine_lift_aarch64::lower_aarch64(return_syntax::Aarch64Opcode::Return,"ret",&[],&mut b).unwrap(),
            Target::X86_64UnknownNone=>panic!("x86 stack return remains unsupported")};
        let control=b.return_control(&flow,0).unwrap();(flow,control,b.state())};
    body.blocks[0].instructions=code;body.blocks[0].terminator=MachineTerminator{source_item:4,state,control};
    (body,floor,flow)
}
// This deliberately small observer consumes actual emitted primitives. It is
// never shipped or used as original-engine/ISA execution evidence.
fn return_value(code:&[MachineInstruction],target:usize,link:RegisterView,input:u64)->u64{
    let mut values=BTreeMap::<usize,u64>::new();let mut state=0;
    for i in code{
        assert_eq!(i.source_item,4);assert_eq!(i.state_in,state);state=i.state_out;
        let result=i.result.expect("return scalar");assert_eq!(result.bits,64);
        let value=match &i.operation{
            MachineOperation::ReadRegister{view}=>{assert_eq!(*view,link);input},
            MachineOperation::Constant{little_endian}=>u64::from_le_bytes(little_endian.as_slice().try_into().unwrap()),
            MachineOperation::Binary{kind,lhs,rhs}=>{let a=values[lhs];let b=values[rhs];match kind{
                BinaryKind::WrappingAdd=>a.wrapping_add(b),BinaryKind::And=>a&b,other=>panic!("unexpected return binary {other:?}")}},
            other=>panic!("unexpected return primitive {other:?}")};
        assert!(values.insert(result.id,value).is_none());
    }values[&target]
}
#[test]
fn rv_ret_target_uses_real_graph_and_odd_link_low_bit_clearing(){
    let t=Target::Riscv64UnknownNone;let(body,floor,flow)=return_case(t);
    let(scalar,kind)=return_flow_parts(&flow);let(exit,target,mechanism)=return_parts(&body.blocks[0].terminator.control);
    assert_eq!((exit,target,mechanism),(0,scalar.id,kind));assert_eq!(kind,ReturnMechanism::Rv64Jalr);
    assert_eq!(body.blocks[0].terminator.state,body.blocks[0].instructions.last().unwrap().state_out);
    for input in [0,1,2,3,0x1234,0x1235,0x8000_0000_0000_0001,u64::MAX]{
        let independent=input-input%2;
        assert_eq!(return_value(&body.blocks[0].instructions,target,return_register(t),input),independent);
    }
    return_unqualified(&verify(&body,&floor,t).unwrap());
}
#[test]
fn rv_jr_and_zero_link_jalr_aliases_keep_actual_computed_target(){
    let t=Target::Riscv64UnknownNone;let p=fixture(t).0.profile;let ra=return_register(t);
    let zero=return_syntax::Expression{first:return_syntax::ExprAtom::Integer(0),rest:vec![]};
    for(op,spelling,args)in[
        (return_syntax::RiscvOpcode::JumpRegister,"jr",vec![return_syntax::Operand::Register(ra)]),
        (return_syntax::RiscvOpcode::JumpRegister,"jalr",vec![return_syntax::Operand::ZeroRegister{bits:64},return_syntax::Operand::Register(ra),return_syntax::Operand::Immediate(zero)])]{
        let mut ids=ReturnIds::new(0,1);let mut code=vec![];
        let(flow,control)={let mut b=ReturnLifter::new(&p,4,0,&mut ids,&mut code);
            let f=super::super::native_machine_lift_rv64::lower_rv64(op,spelling,&args,&mut b).unwrap();
            let c=b.return_control(&f,0).unwrap();(f,c)};
        assert_eq!(return_parts(&control).1,return_flow_parts(&flow).0.id);
        assert_eq!(return_parts(&control).2,ReturnMechanism::Rv64Jalr);
        assert_eq!(return_value(&code,return_parts(&control).1,ra,0x1235),0x1234);
    }
}
#[test]
fn changed_return_target_is_reached_and_independent_odd_ra_oracle_distinguishes_it(){
    let t=Target::Riscv64UnknownNone;let(mut body,floor,_)=return_case(t);
    let original=return_parts(&body.blocks[0].terminator.control).1;
    let read=body.blocks[0].instructions.iter().find(|i|matches!(i.operation,MachineOperation::ReadRegister{..})).unwrap().result.unwrap().id;
    assert_ne!(read,original);
    let MachineControl::ReturnTo{target,..}=&mut body.blocks[0].terminator.control else{panic!()};*target=read;
    let reached=return_parts(&body.blocks[0].terminator.control).1;assert_eq!(reached,read);
    let input=0x1235;let observed=return_value(&body.blocks[0].instructions,reached,return_register(t),input);
    assert_eq!(observed,input);assert_ne!(observed,input-input%2);
    // A defined address-width target is structurally valid. The checker must not
    // claim it independently recovered the original instruction's intent.
    return_unqualified(&verify(&body,&floor,t).unwrap());
}
#[test]
fn changed_return_mask_is_reached_by_the_actual_target_graph(){
    let t=Target::Riscv64UnknownNone;let(mut body,floor,_)=return_case(t);
    let target=return_parts(&body.blocks[0].terminator.control).1;
    let mask=body.blocks[0].instructions.iter_mut().find(|i|matches!(&i.operation,MachineOperation::Constant{little_endian} if little_endian.as_slice()==(u64::MAX-1).to_le_bytes())).unwrap();
    let MachineOperation::Constant{little_endian}=&mut mask.operation else{panic!()};
    assert_eq!(little_endian.as_slice(),(u64::MAX-1).to_le_bytes());*little_endian=u64::MAX.to_le_bytes().to_vec();
    assert_eq!(little_endian.as_slice(),u64::MAX.to_le_bytes());assert_eq!(return_parts(&body.blocks[0].terminator.control).1,target);
    let input=0x35;let observed=return_value(&body.blocks[0].instructions,target,return_register(t),input);
    assert_eq!(observed,input);assert_ne!(observed,input-input%2);
    return_unqualified(&verify(&body,&floor,t).unwrap());
}
#[test]
fn aarch64_ret_reads_actual_lr_without_rv_mask_and_preserves_ret_class(){
    let t=Target::Aarch64UnknownNone;let(body,floor,flow)=return_case(t);
    let(target,mechanism)=return_flow_parts(&flow);assert_eq!(mechanism,ReturnMechanism::Aarch64Ret);
    assert_eq!(return_parts(&body.blocks[0].terminator.control),(0,target.id,mechanism));
    assert_eq!(body.blocks[0].instructions.len(),1);
    assert!(matches!(body.blocks[0].instructions[0].operation,MachineOperation::ReadRegister{view} if view==return_register(t)));
    assert_eq!(return_value(&body.blocks[0].instructions,target.id,return_register(t),0x1235),0x1235);
    return_unqualified(&verify(&body,&floor,t).unwrap());
}
#[test]
fn aarch64_non_lr_return_stays_a_reached_explicit_refusal(){
    let t=Target::Aarch64UnknownNone;let p=fixture(t).0.profile;let mut ids=ReturnIds::new(0,1);let mut code=vec![];
    let operand=return_syntax::Operand::Register(register(PhysicalRegister::Aarch64Gpr{index:19},64));
    let error={let mut b=ReturnLifter::new(&p,4,0,&mut ids,&mut code);
        let e=super::super::native_machine_lift_aarch64::lower_aarch64(return_syntax::Aarch64Opcode::Return,"ret",&[operand],&mut b).unwrap_err();
        assert_eq!(b.state(),0);e};
    assert_eq!(error.source_item,4);assert_eq!(error.reason,"A64 non-LR RET target lacks selected continuation realization");assert!(code.is_empty());
}
#[test]
fn checked_return_converter_rejects_nonreturn_wrong_profile_and_absent_scalar(){
    let p=fixture(Target::Riscv64UnknownNone).0.profile;let mut ids=ReturnIds::new(0,1);let mut code=vec![];
    let mut b=ReturnLifter::new(&p,4,0,&mut ids,&mut code);
    let e=b.return_control(&ReturnFlow::Continue,0).unwrap_err();assert_eq!(e.source_item,4);assert_eq!(e.reason,"flow has no explicit computed return target");
    let actual=b.read_register(return_register(Target::Riscv64UnknownNone)).unwrap();
    let wrong=ReturnFlow::ReturnTo{target:actual,mechanism:ReturnMechanism::Aarch64Ret};
    assert_eq!(return_flow_parts(&wrong),(actual,ReturnMechanism::Aarch64Ret));
    let e=b.return_control(&wrong,0).unwrap_err();assert_eq!(e.source_item,4);assert_eq!(e.reason,"return mechanism differs from machine architecture");
    let absent=Scalar{id:999_999,bits:64};let wrong=ReturnFlow::ReturnTo{target:absent,mechanism:ReturnMechanism::Rv64Jalr};
    assert_eq!(return_flow_parts(&wrong).0.id,999_999);
    let e=b.return_control(&wrong,0).unwrap_err();assert_eq!(e.source_item,4);assert_eq!(e.reason,"scalar is absent or its declared width differs from emitted SSA");
}
#[test]
fn checked_return_converter_rejects_a_known_wrong_width_scalar(){
    let p=fixture(Target::Riscv64UnknownNone).0.profile;let mut ids=ReturnIds::new(0,1);let mut code=vec![];
    let mut b=ReturnLifter::new(&p,4,0,&mut ids,&mut code);let actual=b.constant(32,7).unwrap();assert_eq!(actual.bits,32);
    let flow=ReturnFlow::ReturnTo{target:actual,mechanism:ReturnMechanism::Rv64Jalr};assert_eq!(return_flow_parts(&flow).0,actual);
    let e=b.return_control(&flow,0).unwrap_err();assert_eq!(e.source_item,4);assert_eq!(e.reason,"return target must have exact profile address width");
}
#[test]
fn computed_return_versions_reject_mixing_and_legacy_v2_stays_unqualified(){
    for &t in Target::ALL{let(mut b,i)=fixture(t);let r=verify(&b,&i,t).unwrap();assert_eq!(r.format,"ocore-machine-structure-relative-inventory-v2");return_unqualified(&r);
        b.format=COMPUTED_CONTROL_FORMAT.into();assert!(matches!(b.blocks[0].terminator.control,MachineControl::Return{..}));rejected(&b,&i,t,"legacy return marker is only a v2 structural contract");}
    let t=Target::Riscv64UnknownNone;let(mut b,i,_)=return_case(t);let r=verify(&b,&i,t).unwrap();assert_eq!(r.format,"ocore-machine-structure-relative-inventory-v3");return_unqualified(&r);
    b.format=FORMAT.into();assert!(matches!(b.blocks[0].terminator.control,MachineControl::ReturnTo{..}));rejected(&b,&i,t,"computed return requires v3 machine contract");
    b.format="ocore-machine-body-contract-v999".into();rejected(&b,&i,t,"machine/inventory contract version differs");
}
#[test]
fn computed_return_mechanism_must_match_the_actual_profile(){
    let t=Target::Riscv64UnknownNone;let(mut b,i,_)=return_case(t);
    let MachineControl::ReturnTo{mechanism,..}=&mut b.blocks[0].terminator.control else{panic!()};*mechanism=ReturnMechanism::Aarch64Ret;
    assert_eq!(return_parts(&b.blocks[0].terminator.control).2,ReturnMechanism::Aarch64Ret);rejected(&b,&i,t,"return mechanism differs from machine architecture");
}
#[test]
fn computed_return_requires_an_available_value_in_this_block(){
    let t=Target::Riscv64UnknownNone;let(mut b,i,_)=return_case(t);let absent=999_999;
    assert!(b.blocks[0].instructions.iter().all(|x|x.result.is_none_or(|r|r.id!=absent)));
    let MachineControl::ReturnTo{target,..}=&mut b.blocks[0].terminator.control else{panic!()};*target=absent;
    assert_eq!(return_parts(&b.blocks[0].terminator.control).1,absent);rejected(&b,&i,t,"SSA value is not defined earlier");
}
#[test]
fn computed_return_rejects_a_well_typed_truncated_target(){
    let t=Target::Riscv64UnknownNone;let(mut b,i,_)=return_case(t);let old=return_parts(&b.blocks[0].terminator.control).1;
    let next=b.blocks[0].instructions.iter().filter_map(|x|x.result.map(|r|r.id)).max().unwrap()+1;
    let state=b.blocks[0].terminator.state;b.blocks[0].instructions.push(MachineInstruction{source_item:4,state_in:state,state_out:state+1,result:Some(Scalar{id:next,bits:32}),operation:MachineOperation::Cast{kind:ExtensionKind::Truncate,value:old}});
    b.blocks[0].terminator.state=state+1;let MachineControl::ReturnTo{target,..}=&mut b.blocks[0].terminator.control else{panic!()};*target=next;
    assert_eq!(b.blocks[0].instructions.last().unwrap().result,Some(Scalar{id:next,bits:32}));assert_eq!(return_parts(&b.blocks[0].terminator.control).1,next);
    rejected(&b,&i,t,"return target must have exact profile address width");
}
#[test]
fn computed_returns_retain_final_state_sp_and_readonly_preservation_guards(){
    let t=Target::Riscv64UnknownNone;let(base,floor,_)=return_case(t);
    let mut bad=base.clone();assert_ne!(bad.blocks[0].terminator.state,0);bad.blocks[0].terminator.state=0;rejected(&bad,&floor,t,"control transfer must consume final state SSA token");
    for protected in [false,true]{let mut b=base.clone();let mut i=floor.clone();let target=return_parts(&b.blocks[0].terminator.control).1;
        let view=if protected{return_register(t)}else{register(PhysicalRegister::RiscvGpr{index:2},64)};
        if protected{b.interface.exits[0].preserved.push(view);i.interface=b.interface.clone();}
        let state=b.blocks[0].terminator.state;b.blocks[0].instructions.push(MachineInstruction{source_item:4,state_in:state,state_out:state+1,result:None,operation:MachineOperation::WriteRegister{view,value:target,mode:WriteMode::WholeStorage}});b.blocks[0].terminator.state=state+1;
        assert!(matches!(b.blocks[0].instructions.last().unwrap().operation,MachineOperation::WriteRegister{view:v,..} if v==view));
        rejected(&b,&i,t,if protected{"write overlaps readonly exit-preserved"}else{"SP/PC/zero/flags"});
    }
}
#[test]
fn computed_return_serialization_keeps_exact_target_and_branch_class(){
    let t=Target::Riscv64UnknownNone;let(b,i,_)=return_case(t);let expected=return_parts(&b.blocks[0].terminator.control);
    let value=serde_json::to_value(&b).unwrap();assert_eq!(value["format"],COMPUTED_CONTROL_FORMAT);
    let c=&value["blocks"][0]["terminator"]["control"];assert_eq!(c["control"],"return_to");assert_eq!(c["target"],expected.1);assert_eq!(c["mechanism"],"rv64_jalr");
    let decoded:MachineBodyContract=serde_json::from_value(value).unwrap();assert_eq!(return_parts(&decoded.blocks[0].terminator.control),expected);return_unqualified(&verify(&decoded,&i,t).unwrap());
}
