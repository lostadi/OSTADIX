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
