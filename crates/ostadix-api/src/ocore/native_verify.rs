//! Verification of the self-contained foreign-native import boundary.
//!
//! This verifier checks every declaration and definition, including dead
//! blocks. It deliberately does not interpret LLVM poison flags as `.oc`
//! arithmetic rules. Under `LlvmDefinedBehaviorV1` those flags may be refined
//! to bits, but must never become optimizer assumptions or eager traps.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use super::native_ir::*;
use super::Diagnostic;

type Result<T> = std::result::Result<T, Diagnostic>;

#[cfg(test)]
#[path = "native_atomic_verify_tests.rs"]
mod atomic_tests;

#[cfg(test)]
#[path = "native_minmax_verify_tests.rs"]
mod minmax_tests;

fn fail(context: &str, message: impl std::fmt::Display) -> Diagnostic {
    error_diagnostic(format!("{context}: {message}"))
}

fn alignment(value: u64, allow_zero: bool, context: &str) -> Result<()> {
    if (value == 0 && allow_zero) || (value.is_power_of_two() && value <= (1_u64 << 32)) {
        Ok(())
    } else {
        Err(fail(
            context,
            "alignment must be a power of two, at most 2^32 bytes",
        ))
    }
}

fn align_up(value: u64, align: u64, context: &str) -> Result<u64> {
    value
        .checked_add(align - 1)
        .map(|n| n & !(align - 1))
        .ok_or_else(|| fail(context, "type layout overflows u64"))
}

#[derive(Clone, Copy, Debug)]
struct Layout {
    size: u64,
    align: u64,
}

/// LLVM allocation size, including scalar/aggregate tail padding.
pub fn type_size(module: &NativeModule, ty: TypeId) -> Result<u64> {
    let layouts = layouts(module)?;
    layouts
        .get(ty)
        .and_then(|x| *x)
        .map(|x| x.size)
        .ok_or_else(|| fail("type_size", format!("type {ty} is missing or unsized")))
}

/// LLVM ABI alignment. Preferred alignment is not an allocation-size rule.
pub fn type_alignment(module: &NativeModule, ty: TypeId) -> Result<u64> {
    let layouts = layouts(module)?;
    layouts
        .get(ty)
        .and_then(|x| *x)
        .map(|x| x.align)
        .ok_or_else(|| fail("type_alignment", format!("type {ty} is missing or unsized")))
}

/// Original allocation size and ABI alignment, computed once for a module.
/// Missing entries are unsized void/metadata/function types; no layout is inferred.
pub fn type_layouts(module: &NativeModule) -> Result<Vec<Option<(u64, u64)>>> {
    Ok(layouts(module)?
        .into_iter()
        .map(|layout| layout.map(|value| (value.size, value.align)))
        .collect())
}

/// Select a source struct/array element without flattening or changing TypeIds.
/// Each index must select an existing child, and the path must be nonempty.
pub fn aggregate_element_type(
    module: &NativeModule,
    mut ty: TypeId,
    indices: &[u64],
) -> Result<TypeId> {
    if indices.is_empty() {
        return Err(fail("aggregate path", "aggregate indices must be nonempty"));
    }
    for index in indices {
        let value = module
            .types
            .get(ty)
            .ok_or_else(|| fail("aggregate path", format!("type {ty} is out of bounds")))?;
        ty = match value {
            Type::Struct { fields, .. } => {
                let index = usize::try_from(*index)
                    .ok()
                    .filter(|index| *index < fields.len())
                    .ok_or_else(|| fail("aggregate path", "struct index is out of bounds"))?;
                fields[index]
            }
            Type::Array { element, len } if index < len => *element,
            Type::Array { .. } => {
                return Err(fail("aggregate path", "array index is out of bounds"));
            }
            _ => return Err(fail("aggregate path", "index requires a struct or array")),
        };
    }
    if ty >= module.types.len() {
        return Err(fail(
            "aggregate path",
            format!("type {ty} is out of bounds"),
        ));
    }
    Ok(ty)
}

/// Source scalar leaves in field/element order, with DataLayout byte offsets.
/// Allocation strides include tail padding; padding is never an SSA leaf.
/// Empty aggregates have no leaves. Generic floating-point leaves are retained
/// here even when a native execution profile cannot lower them yet.
pub fn value_leaf_layout(module: &NativeModule, ty: TypeId) -> Result<Vec<(TypeId, u64)>> {
    value_leaf_layout_with_layouts(module, ty, &layouts(module)?)
}

/// Batch form for a native emitter's per-module value-layout cache. The type
/// allocation map is computed once and repeated requested TypeIds are reused.
/// Sized child types are included; an empty array does not instantiate its
/// element value. Void/metadata/function requests do not denote SSA storage and are
/// omitted rather than forcing a fictitious scalar leaf.
pub fn value_leaf_layouts(
    module: &NativeModule,
    types: &[TypeId],
) -> Result<BTreeMap<TypeId, Vec<(TypeId, u64)>>> {
    let layouts = layouts(module)?;
    let mut values = BTreeMap::new();
    let mut pending = types.to_vec();
    let mut seen = HashSet::new();
    while let Some(ty) = pending.pop() {
        if !seen.insert(ty) {
            continue;
        }
        let value = module
            .types
            .get(ty)
            .ok_or_else(|| fail("value leaf layouts", format!("type {ty} is out of bounds")))?;
        match value {
            Type::Void | Type::Metadata {} | Type::Function { .. } => continue,
            Type::Struct { fields, .. } => pending.extend(fields),
            Type::Array { element, len } if *len != 0 => pending.push(*element),
            _ => {}
        }
        values.insert(ty, value_leaf_layout_with_layouts(module, ty, &layouts)?);
    }
    Ok(values)
}

fn value_leaf_layout_with_layouts(
    module: &NativeModule,
    ty: TypeId,
    layouts: &[Option<Layout>],
) -> Result<Vec<(TypeId, u64)>> {
    enum Pending {
        Value(TypeId, u64),
        Array {
            element: TypeId,
            index: u64,
            len: u64,
            base: u64,
            stride: u64,
        },
        Struct {
            ty: TypeId,
            index: usize,
            base: u64,
            offset: u64,
        },
    }
    let context = "value leaf layout";
    let sized = |id: TypeId| {
        layouts
            .get(id)
            .and_then(|layout| *layout)
            .ok_or_else(|| fail(context, format!("type {id} is missing or unsized")))
    };
    sized(ty)?;
    let mut pending = vec![Pending::Value(ty, 0)];
    let mut leaves = Vec::new();
    while let Some(item) = pending.pop() {
        match item {
            Pending::Value(ty, base) => {
                if sized(ty)?.size == 0 {
                    continue;
                }
                match &module.types[ty] {
                    Type::Int { .. } | Type::Float { .. } | Type::Pointer { .. } => {
                        leaves.try_reserve(1).map_err(|error| {
                            fail(context, format!("scalar leaf allocation failed: {error}"))
                        })?;
                        leaves.push((ty, base));
                    }
                    Type::Array { element, len } => pending.push(Pending::Array {
                        element: *element,
                        index: 0,
                        len: *len,
                        base,
                        stride: sized(*element)?.size,
                    }),
                    Type::Struct { .. } => pending.push(Pending::Struct {
                        ty,
                        index: 0,
                        base,
                        offset: 0,
                    }),
                    Type::Void | Type::Metadata {} | Type::Function { .. } => unreachable!(),
                }
            }
            Pending::Array {
                element,
                index,
                len,
                base,
                stride,
            } => {
                if index < len {
                    let offset = index
                        .checked_mul(stride)
                        .and_then(|offset| base.checked_add(offset))
                        .ok_or_else(|| fail(context, "array leaf offset overflows u64"))?;
                    pending.push(Pending::Array {
                        element,
                        index: index + 1,
                        len,
                        base,
                        stride,
                    });
                    pending.push(Pending::Value(element, offset));
                }
            }
            Pending::Struct {
                ty,
                index,
                base,
                offset,
            } => {
                let Type::Struct { fields, packed } = &module.types[ty] else {
                    unreachable!()
                };
                if let Some(field) = fields.get(index) {
                    let field_layout = sized(*field)?;
                    let offset = align_up(
                        offset,
                        if *packed { 1 } else { field_layout.align },
                        context,
                    )?;
                    let field_base = base
                        .checked_add(offset)
                        .ok_or_else(|| fail(context, "struct leaf offset overflows u64"))?;
                    let next = offset
                        .checked_add(field_layout.size)
                        .ok_or_else(|| fail(context, "struct field extent overflows u64"))?;
                    pending.push(Pending::Struct {
                        ty,
                        index: index + 1,
                        base,
                        offset: next,
                    });
                    pending.push(Pending::Value(*field, field_base));
                }
            }
        }
    }
    Ok(leaves)
}

struct DataLayout {
    ints: BTreeMap<u64, u64>,
    floats: BTreeMap<u64, u64>,
    pointers: BTreeMap<u32, Layout>,
    pointer_indices: BTreeMap<u32, u64>,
    non_integral: BTreeSet<u32>,
    default_spaces: [u32; 3],
    aggregate_align: u64,
}

impl DataLayout {
    fn parse(module: &NativeModule) -> Result<Self> {
        let context = "target.data_layout";
        if module.target.triple.trim().is_empty() || module.target.data_layout.is_empty() {
            return Err(fail(
                context,
                "target triple and DataLayout must be present",
            ));
        }
        let pointer_bits = u64::from(module.target.pointer_bits);
        if pointer_bits == 0 || pointer_bits % 8 != 0 {
            return Err(fail(context, "pointer_bits must be a nonzero byte width"));
        }
        let mut dl = Self {
            // LLVM 21's default ABI alignments; i64 defaults to four bytes.
            ints: [(1, 1), (8, 1), (16, 2), (32, 4), (64, 4)].into(),
            floats: [(16, 2), (32, 4), (64, 8), (128, 16)].into(),
            pointers: [(0, Layout { size: 8, align: 8 })].into(),
            pointer_indices: [(0, 64)].into(),
            non_integral: BTreeSet::new(),
            default_spaces: [0; 3],
            aggregate_align: 1,
        };
        let mut endian = None;
        for token in module.target.data_layout.split('-') {
            if token.is_empty() {
                return Err(fail(context, "empty DataLayout component"));
            }
            if token == "e" || token == "E" {
                if endian.replace(token == "e").is_some() {
                    return Err(fail(context, "duplicate endianness component"));
                }
                continue;
            }
            let parts: Vec<&str> = token.split(':').collect();
            let number = |s: &str| -> Result<u64> {
                s.parse()
                    .map_err(|_| fail(context, format!("invalid numeric component {token:?}")))
            };
            let bits_align = |s: &str, zero: bool| -> Result<u64> {
                let bits = number(s)?;
                if bits == 0 && zero {
                    return Ok(1);
                }
                if bits == 0 || bits % 8 != 0 || !(bits / 8).is_power_of_two() || bits >= (1 << 16)
                {
                    return Err(fail(
                        context,
                        format!("invalid alignment component {token:?}"),
                    ));
                }
                Ok(bits / 8)
            };
            match token.as_bytes()[0] {
                b'i' | b'f' | b'v' => {
                    if !(2..=3).contains(&parts.len()) {
                        return Err(fail(context, format!("malformed component {token:?}")));
                    }
                    let bits = number(&parts[0][1..])?;
                    if bits == 0 || bits >= (1 << 24) {
                        return Err(fail(context, "primitive width is out of range"));
                    }
                    let abi = bits_align(parts[1], false)?;
                    if parts.len() == 3 && bits_align(parts[2], false)? < abi {
                        return Err(fail(
                            context,
                            "preferred alignment is smaller than ABI alignment",
                        ));
                    }
                    if token.starts_with('i') {
                        if bits == 8 && abi != 1 {
                            return Err(fail(context, "i8 must be byte aligned"));
                        }
                        dl.ints.insert(bits, abi);
                    } else if token.starts_with('f') {
                        dl.floats.insert(bits, abi);
                    }
                }
                b'p' => {
                    if !(3..=5).contains(&parts.len()) {
                        return Err(fail(
                            context,
                            format!("malformed pointer component {token:?}"),
                        ));
                    }
                    let space = if parts[0].len() == 1 {
                        0
                    } else {
                        number(&parts[0][1..])?
                    };
                    if space >= (1 << 24) {
                        return Err(fail(context, "pointer address space is out of range"));
                    }
                    let bits = number(parts[1])?;
                    if bits == 0 || bits % 8 != 0 || bits >= (1 << 24) {
                        return Err(fail(context, "pointer width is invalid"));
                    }
                    let abi = bits_align(parts[2], false)?;
                    if parts.len() >= 4 && bits_align(parts[3], false)? < abi {
                        return Err(fail(
                            context,
                            "pointer preferred alignment is smaller than ABI alignment",
                        ));
                    }
                    let index = if parts.len() == 5 {
                        let index = number(parts[4])?;
                        if index == 0 || index > bits {
                            return Err(fail(context, "pointer index width is invalid"));
                        }
                        index
                    } else {
                        bits
                    };
                    dl.pointer_indices.insert(space as u32, index);
                    dl.pointers.insert(
                        space as u32,
                        Layout {
                            size: bits / 8,
                            align: abi,
                        },
                    );
                }
                b'a' => {
                    if !(2..=3).contains(&parts.len())
                        || (!parts[0][1..].is_empty() && number(&parts[0][1..])? != 0)
                    {
                        return Err(fail(
                            context,
                            format!("malformed aggregate component {token:?}"),
                        ));
                    }
                    dl.aggregate_align = bits_align(parts[1], true)?;
                    if parts.len() == 3 && bits_align(parts[2], false)? < dl.aggregate_align {
                        return Err(fail(
                            context,
                            "aggregate preferred alignment is smaller than ABI alignment",
                        ));
                    }
                }
                // These components do not change the sizes of schema types.
                b'm' if parts.len() == 2
                    && ["e", "o", "m", "w", "x", "a", "l"].contains(&parts[1]) => {}
                b'n' if parts[0] == "ni" && parts.len() > 1 => {
                    for s in &parts[1..] {
                        let space = number(s)?;
                        if space == 0 || space >= (1 << 24) {
                            return Err(fail(context, "invalid non-integral address space"));
                        }
                        dl.non_integral.insert(space as u32);
                    }
                }
                b'n' => {
                    for (i, s) in parts.iter().enumerate() {
                        if number(if i == 0 { &s[1..] } else { s })? == 0 {
                            return Err(fail(context, "invalid native integer width"));
                        }
                    }
                }
                b'S' => {
                    bits_align(&token[1..], false)?;
                }
                b'A' | b'P' | b'G' => {
                    let space = number(&token[1..])?;
                    if space >= (1 << 24) {
                        return Err(fail(context, "address space is out of range"));
                    }
                    let slot = match token.as_bytes()[0] {
                        b'A' => 0,
                        b'P' => 1,
                        _ => 2,
                    };
                    dl.default_spaces[slot] = space as u32;
                }
                b'F' if token.starts_with("Fi") || token.starts_with("Fn") => {
                    bits_align(&token[2..], false)?;
                }
                _ => {
                    return Err(fail(
                        context,
                        format!("unsupported DataLayout component {token:?}"),
                    ));
                }
            }
        }
        if endian != Some(module.target.little_endian) {
            return Err(fail(
                context,
                "endianness does not match target.little_endian",
            ));
        }
        if dl.pointers[&0].size * 8 != pointer_bits {
            return Err(fail(
                context,
                "default pointer width does not match target.pointer_bits",
            ));
        }
        Ok(dl)
    }

    fn primitive(&self, ty: &Type, context: &str) -> Result<Option<Layout>> {
        let (bytes, align) = match ty {
            Type::Void | Type::Metadata {} | Type::Function { .. } => return Ok(None),
            Type::Int { bits } => {
                if *bits == 0 {
                    return Err(fail(context, "zero-width integer"));
                }
                let width = u64::from(*bits);
                let align = self
                    .ints
                    .range(width..)
                    .next()
                    .or_else(|| self.ints.last_key_value())
                    .unwrap()
                    .1;
                (width.div_ceil(8), *align)
            }
            Type::Float { bits } => {
                if ![16, 32, 64, 80, 128].contains(bits) {
                    return Err(fail(context, "invalid floating-point width"));
                }
                let bytes = u64::from(*bits).div_ceil(8);
                (
                    bytes,
                    self.floats
                        .get(&u64::from(*bits))
                        .copied()
                        .unwrap_or(bytes.next_power_of_two()),
                )
            }
            Type::Pointer { address_space } => {
                if *address_space >= (1 << 24) {
                    return Err(fail(context, "pointer address space is out of range"));
                }
                let p = self
                    .pointers
                    .get(address_space)
                    .unwrap_or(&self.pointers[&0]);
                return Ok(Some(Layout {
                    size: align_up(p.size, p.align, context)?,
                    align: p.align,
                }));
            }
            Type::Array { .. } | Type::Struct { .. } => return Ok(None),
        };
        Ok(Some(Layout {
            size: align_up(bytes, align, context)?,
            align,
        }))
    }
}

fn layouts(module: &NativeModule) -> Result<Vec<Option<Layout>>> {
    let dl = DataLayout::parse(module)?;
    let mut output: Vec<Option<Layout>> = vec![None; module.types.len()];
    let mut state = vec![0_u8; module.types.len()];
    for root in 0..module.types.len() {
        if state[root] == 2 {
            continue;
        }
        let mut pending = vec![(root, false)];
        while let Some((id, finish)) = pending.pop() {
            let context = format!("types[{id}]");
            let ty = module
                .types
                .get(id)
                .ok_or_else(|| fail(&context, "type reference is out of bounds"))?;
            if finish {
                let value = match ty {
                    Type::Array { element, len } => {
                        let e = output[*element]
                            .ok_or_else(|| fail(&context, "array element is unsized"))?;
                        Layout {
                            size: e
                                .size
                                .checked_mul(*len)
                                .ok_or_else(|| fail(&context, "array layout overflows u64"))?,
                            align: e.align,
                        }
                    }
                    Type::Struct { fields, packed } => {
                        let mut offset = 0_u64;
                        let mut align = if *packed { 1 } else { dl.aggregate_align };
                        for field in fields {
                            let f = output[*field]
                                .ok_or_else(|| fail(&context, "struct field is unsized"))?;
                            let field_align = if *packed { 1 } else { f.align };
                            align = align.max(field_align);
                            offset = align_up(offset, field_align, &context)?
                                .checked_add(f.size)
                                .ok_or_else(|| fail(&context, "struct layout overflows u64"))?;
                        }
                        Layout {
                            size: align_up(offset, align, &context)?,
                            align,
                        }
                    }
                    _ => unreachable!(),
                };
                output[id] = Some(value);
                state[id] = 2;
                continue;
            }
            if state[id] == 2 {
                continue;
            }
            if state[id] == 1 {
                return Err(fail(
                    &context,
                    "recursive by-value type has no finite layout",
                ));
            }
            state[id] = 1;
            let children: &[TypeId] = match ty {
                Type::Array { element, .. } => std::slice::from_ref(element),
                Type::Struct { fields, .. } => fields,
                _ => {
                    output[id] = dl.primitive(ty, &context)?;
                    state[id] = 2;
                    continue;
                }
            };
            pending.push((id, true));
            for child in children.iter().rev() {
                if *child >= module.types.len() {
                    return Err(fail(&context, format!("type {child} is out of bounds")));
                }
                pending.push((*child, false));
            }
        }
    }
    Ok(output)
}

fn sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Validate the typed, module-local graph, never recovering node identity or
/// graph operands from LLVM's display labels. Arbitrary original string bytes
/// and distinct wrappers remain intact, including unused retained nodes.
fn noalias_metadata(module: &NativeModule) -> Result<HashMap<usize, &NoAliasScopeList>> {
    let context = "noalias metadata";
    let graph = &module.noalias_metadata;
    let mut nodes = HashMap::new();
    for (id, storage) in graph
        .domains
        .iter()
        .map(|node| (node.id, node.storage))
        .chain(graph.scopes.iter().map(|node| (node.id, node.storage)))
        .chain(graph.lists.iter().map(|node| (node.id, node.storage)))
    {
        if nodes.insert(id, storage).is_some() {
            return Err(fail(context, "duplicate node ID across metadata tables"));
        }
    }
    let domains: HashSet<_> = graph.domains.iter().map(|node| node.id).collect();
    let scopes: HashSet<_> = graph.scopes.iter().map(|node| node.id).collect();
    for scope in &graph.scopes {
        if !domains.contains(&scope.domain) {
            return Err(fail(context, "scope references an unknown domain"));
        }
    }
    let lists: HashMap<_, _> = graph.lists.iter().map(|node| (node.id, node)).collect();
    for list in &graph.lists {
        for scope in &list.scopes {
            if !scopes.contains(scope) {
                return Err(fail(context, "scope list references an unknown scope"));
            }
        }
    }
    if !module.provenance.noalias_metadata_source.is_empty() {
        if module.provenance.noalias_metadata_source.len() != nodes.len() {
            return Err(fail(
                context,
                "source node evidence inventory does not match graph",
            ));
        }
        let mut seen = HashSet::new();
        for source in &module.provenance.noalias_metadata_source {
            let storage = nodes.get(&source.id).ok_or_else(|| {
                fail(
                    context,
                    "source evidence references an unknown metadata node",
                )
            })?;
            if !seen.insert(source.id) {
                return Err(fail(context, "duplicate source metadata node evidence"));
            }
            // LLVM22 MDTupleMetadataKind is 4. Specialized node semantics may
            // not be replaced by a tuple with a coincidentally similar shape.
            if source.metadata_kind != 4 {
                return Err(fail(context, "source metadata node is not an MDTuple"));
            }
            if source.printer_sha256 != format!("{:x}", Sha256::digest(&source.printer_bytes)) {
                return Err(fail(
                    context,
                    "source metadata printer digest does not match bytes",
                ));
            }
            let separator = source
                .printer_bytes
                .windows(3)
                .position(|bytes| bytes == b" = ")
                .ok_or_else(|| fail(context, "invalid source metadata printer prefix"))?;
            let label = &source.printer_bytes[..separator];
            let slot = label
                .strip_prefix(b"!")
                .is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit));
            let fallback = label
                .strip_prefix(b"<0x")
                .and_then(|label| label.strip_suffix(b">"))
                .is_some_and(|digits| {
                    !digits.is_empty() && digits.iter().all(u8::is_ascii_hexdigit)
                });
            let body = &source.printer_bytes[separator + 3..];
            let valid_storage = match storage {
                NoAliasNodeStorage::Uniqued => body.starts_with(b"!{"),
                NoAliasNodeStorage::Distinct => body.starts_with(b"distinct !{"),
            };
            if !(slot || fallback) || !valid_storage {
                return Err(fail(
                    context,
                    "source metadata printer storage prefix does not match graph",
                ));
            }
        }
    }
    let functions: HashMap<_, _> = module
        .functions
        .iter()
        .map(|function| (function.name.as_str(), function))
        .collect();
    let blocks: HashMap<_, _> = module
        .functions
        .iter()
        .flat_map(|function| {
            function
                .blocks
                .iter()
                .map(|block| ((function.name.as_str(), block.id), block))
        })
        .collect();
    // A source instruction may produce many native instructions, or none.
    // Store one exact mapping per source site; marker mappings are implicit
    // one-instruction ranges and must agree with any retained attachment.
    type SourceRanges = BTreeMap<usize, (usize, usize)>;
    let mut sites: HashMap<(&str, BlockId), SourceRanges> = HashMap::new();
    let mut attached = HashSet::new();
    for attachment in &graph.attachments {
        if attachment.alias_scope.is_none() && attachment.noalias.is_none() {
            return Err(fail(
                context,
                "attachment has neither alias.scope nor noalias",
            ));
        }
        for list in [attachment.alias_scope, attachment.noalias]
            .into_iter()
            .flatten()
        {
            if !lists.contains_key(&list) {
                return Err(fail(context, "attachment references an unknown scope list"));
            }
        }
        let site = &attachment.site;
        functions
            .get(site.function.as_str())
            .filter(|function| function.entry.is_some())
            .ok_or_else(|| {
                fail(
                    context,
                    "attachment references an unknown function definition",
                )
            })?;
        let block = blocks
            .get(&(site.function.as_str(), site.block))
            .ok_or_else(|| fail(context, "attachment references an unknown block"))?;
        if site.instruction > block.instructions.len()
            || site
                .instruction
                .checked_add(site.instruction_count)
                .is_none_or(|end| end > block.instructions.len())
        {
            return Err(fail(
                context,
                "attachment native instruction range is out of bounds",
            ));
        }
        if !attached.insert((site.function.as_str(), site.block, site.source_instruction)) {
            return Err(fail(context, "duplicate source instruction attachment"));
        }
        sites
            .entry((site.function.as_str(), site.block))
            .or_default()
            .insert(
                site.source_instruction,
                (site.instruction, site.instruction_count),
            );
    }
    for function in &module.functions {
        for block in &function.blocks {
            let mappings = sites.entry((function.name.as_str(), block.id)).or_default();
            let mut markers = HashSet::new();
            for (position, instruction) in block.instructions.iter().enumerate() {
                if let Operation::NoAliasScopeDecl {
                    scope_list,
                    source_instruction,
                } = &instruction.operation
                {
                    let list = lists.get(scope_list).ok_or_else(|| {
                        fail(context, "declaration references an unknown scope list")
                    })?;
                    if list.scopes.len() != 1 {
                        return Err(fail(
                            context,
                            "declaration requires exactly one actual scope",
                        ));
                    }
                    if !markers.insert(*source_instruction) {
                        return Err(fail(context, "duplicate marker source instruction"));
                    }
                    if mappings
                        .insert(*source_instruction, (position, 1))
                        .is_some_and(|previous| previous != (position, 1))
                    {
                        return Err(fail(context, "marker and attachment source ranges differ"));
                    }
                }
            }
        }
    }
    for mappings in sites.values() {
        let mut end = 0;
        for (start, count) in mappings.values() {
            if *start < end {
                return Err(fail(
                    context,
                    "source instruction ranges overlap or are out of order",
                ));
            }
            end = start
                .checked_add(*count)
                .ok_or_else(|| fail(context, "source instruction range overflows"))?;
        }
    }
    Ok(lists)
}

fn symbol_name(name: &str, context: &str) -> Result<()> {
    let mut bytes = name.bytes();
    let first = bytes.next();
    if !first.is_some_and(|c| c.is_ascii_alphabetic() || b"_.$".contains(&c))
        || !bytes.all(|c| c.is_ascii_alphanumeric() || b"_.$".contains(&c))
    {
        Err(fail(
            context,
            "symbol requires assembler-safe spelling [A-Za-z_.$][A-Za-z0-9_.$]*",
        ))
    } else {
        Ok(())
    }
}

fn linkage(value: &str, definition: bool, context: &str) -> Result<()> {
    // LLVM WeakAny is a real definition with its original body/storage. An
    // unresolved weak reference is a distinct extern_weak contract, never a
    // definition synthesized from an absent initializer or function entry.
    if value == "weak" && !definition {
        return Err(fail(context, "weak linkage requires a definition"));
    }
    let valid = match value {
        "external" | "extern_weak" => true,
        "private"
        | "internal"
        | "available_externally"
        | "linkonce"
        | "weak"
        | "linkonce_odr"
        | "weak_odr"
        | "common" => definition,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(fail(
            context,
            format!("invalid linkage {value:?} for declaration/definition"),
        ))
    }
}

fn visibility(linkage: &str, value: Visibility, context: &str) -> Result<()> {
    if matches!(linkage, "internal" | "private") && value != Visibility::Default {
        Err(fail(
            context,
            "internal/private linkage requires default visibility",
        ))
    } else {
        Ok(())
    }
}

fn comdats(module: &NativeModule) -> Result<()> {
    // The inventory is the canonical LLVM bitcode's referenced group table,
    // not unused textual declarations (which LLVM serialization omits). Group
    // names have their own namespace; a signature may also name a definition.
    let mut members = HashMap::<&str, usize>::new();
    for group in &module.comdats {
        let context = format!("comdat {:?}", group.name);
        symbol_name(&group.name, &context)?;
        if members.insert(&group.name, 0).is_some() {
            return Err(fail(&context, "duplicate COMDAT group name"));
        }
        if !matches!(
            group.selection,
            ComdatSelection::Any | ComdatSelection::NoDeduplicate
        ) {
            return Err(fail(
                &context,
                "ELF COMDAT supports only any and no_deduplicate selection",
            ));
        }
    }
    for function in &module.functions {
        let Some(group) = function.comdat.as_deref() else {
            continue;
        };
        let context = format!("function {:?}", function.name);
        let count = members
            .get_mut(group)
            .ok_or_else(|| fail(&context, "unknown COMDAT group"))?;
        if function.intrinsic.is_some() || function.name.starts_with("llvm.") {
            return Err(fail(&context, "intrinsic cannot be a COMDAT member"));
        }
        if function.entry.is_none() || function.linkage == "available_externally" {
            return Err(fail(
                &context,
                "COMDAT member must be an emitted definition",
            ));
        }
        *count += 1;
    }
    for global in &module.globals {
        let Some(group) = global.comdat.as_deref() else {
            continue;
        };
        let context = format!("global {:?}", global.name);
        let count = members
            .get_mut(group)
            .ok_or_else(|| fail(&context, "unknown COMDAT group"))?;
        if global.initializer.is_none() || global.linkage == "available_externally" {
            return Err(fail(
                &context,
                "COMDAT member must be an emitted definition",
            ));
        }
        if global.linkage == "common" {
            return Err(fail(&context, "common global cannot be a COMDAT member"));
        }
        if global.thread_local
            && module.target.tls_profile != Some(TlsProfile::LinuxElfStaticNonpreemptiveV1)
        {
            return Err(fail(
                &context,
                "TLS COMDAT members require explicit storage/model lowering",
            ));
        }
        *count += 1;
    }
    for group in &module.comdats {
        if members[group.name.as_str()] == 0 {
            return Err(fail(
                &group.name,
                "referenced COMDAT has no defined members",
            ));
        }
    }
    // Aliases inherit the defined aliasee's group; adding a separate group
    // field or copying the aliasee would change original symbol identity.
    Ok(())
}

#[derive(Clone, Copy)]
enum IntrinsicArgument {
    Integer(u16),
    Pointer,
    Metadata,
}

fn builtin_signature(name: &str) -> Option<&'static [IntrinsicArgument]> {
    use IntrinsicArgument::{Integer, Metadata, Pointer};
    match name {
        NOALIAS_SCOPE_DECL => Some(&[Metadata]),
        "llvm.trap" => Some(&[]),
        "llvm.eh.typeid.for" | "llvm.eh.typeid.for.p0" => Some(&[Pointer]),
        "llvm.threadlocal.address.p0" => Some(&[Pointer]),
        "llvm.load.relative.i32" => Some(&[Pointer, Integer(32)]),
        "llvm.load.relative.i64" => Some(&[Pointer, Integer(64)]),
        "llvm.assume" => Some(&[Integer(1)]),
        "llvm.lifetime.start.p0" | "llvm.lifetime.end.p0" => Some(&[Pointer]),
        "llvm.memset.p0.i32" => Some(&[Pointer, Integer(8), Integer(32), Integer(1)]),
        "llvm.memset.p0.i64" => Some(&[Pointer, Integer(8), Integer(64), Integer(1)]),
        "llvm.memcpy.p0.p0.i32" | "llvm.memmove.p0.p0.i32" => {
            Some(&[Pointer, Pointer, Integer(32), Integer(1)])
        }
        "llvm.memcpy.p0.p0.i64" | "llvm.memmove.p0.p0.i64" => {
            Some(&[Pointer, Pointer, Integer(64), Integer(1)])
        }
        _ => None,
    }
}

/// Exact compiler builtins implemented as owned operations, without native
/// symbol dependencies. Their complete declaration contracts are verified.
pub fn is_builtin_intrinsic(name: &str) -> bool {
    builtin_signature(name).is_some()
        || integer_overflow_intrinsic(name).is_some()
        || integer_minmax_intrinsic(name).is_some()
}

/// Compiler-only declarations have no ordinary native ABI or executable
/// parameter values. This classifier is used only after whole-module verify.
pub fn is_metadata_builtin_intrinsic(name: &str) -> bool {
    name == NOALIAS_SCOPE_DECL
}

/// Canonical LLVM scalar overflow names in the supported integer profile.
/// The declaration and each operation's original result shape are verified
/// separately; a matching name alone never supplies an ABI contract.
pub fn integer_overflow_intrinsic(name: &str) -> Option<(BinaryOp, bool, u16)> {
    let name = name.strip_prefix("llvm.")?;
    let (operation, width) = name.split_once(".with.overflow.i")?;
    let (kind, signed) = match operation {
        "sadd" => (BinaryOp::Add, true),
        "uadd" => (BinaryOp::Add, false),
        "ssub" => (BinaryOp::Sub, true),
        "usub" => (BinaryOp::Sub, false),
        "smul" => (BinaryOp::Mul, true),
        "umul" => (BinaryOp::Mul, false),
        _ => return None,
    };
    let bits = width.parse::<u16>().ok()?;
    ((1..=64).contains(&bits) && width == bits.to_string()).then_some((kind, signed, bits))
}

/// Canonical names for the owned LLVM scalar integer min/max profile. Provider
/// intrinsic-ID lookup alone cannot establish either this spelling or its type.
/// Wider and vector LLVM overloads require separate supported realizations.
pub fn integer_minmax_intrinsic(name: &str) -> Option<(IntegerMinMaxKind, u16)> {
    let (operation, width) = name.strip_prefix("llvm.")?.split_once(".i")?;
    let kind = match operation {
        "smin" => IntegerMinMaxKind::Smin,
        "smax" => IntegerMinMaxKind::Smax,
        "umin" => IntegerMinMaxKind::Umin,
        "umax" => IntegerMinMaxKind::Umax,
        _ => return None,
    };
    let bits = width.parse::<u16>().ok()?;
    ((1..=64).contains(&bits) && width == bits.to_string()).then_some((kind, bits))
}

struct Verifier<'a> {
    module: &'a NativeModule,
    data_layout: DataLayout,
    layouts: Vec<Option<Layout>>,
    symbols: HashMap<&'a str, Symbol<'a>>,
    literal_pointer_profile: bool,
    native_tls_profile: bool,
    metadata_personalities: BTreeSet<String>,
    noalias_lists: HashMap<usize, &'a NoAliasScopeList>,
    atomic_scopes: HashMap<u32, &'a AtomicSyncScope>,
}

#[derive(Clone, Copy)]
enum Symbol<'a> {
    Function(&'a Function),
    Global(&'a Global),
}

impl<'a> Verifier<'a> {
    fn ty(&self, id: TypeId, context: &str) -> Result<&'a Type> {
        self.module
            .types
            .get(id)
            .ok_or_else(|| fail(context, format!("type {id} is out of bounds")))
    }

    fn sized(&self, id: TypeId, context: &str) -> Result<Layout> {
        self.ty(id, context)?;
        self.layouts[id].ok_or_else(|| fail(context, format!("type {id} is unsized")))
    }

    fn same_type(&self, lhs: TypeId, rhs: TypeId, context: &str) -> Result<()> {
        if lhs == rhs || self.ty(lhs, context)? == self.ty(rhs, context)? {
            Ok(())
        } else {
            Err(fail(context, format!("type mismatch: {lhs} versus {rhs}")))
        }
    }

    fn signature(&self, sig: &Signature, context: &str) -> Result<()> {
        if sig.abi.is_empty() || sig.abi.as_bytes().contains(&0) {
            return Err(fail(context, "calling convention is missing or invalid"));
        }
        let result = self.ty(sig.result, context)?;
        if !matches!(result, Type::Void) {
            self.sized(sig.result, context)?;
        }
        for ty in &sig.params {
            self.sized(*ty, context)?;
        }
        if !sig.param_attributes.is_empty() && sig.param_attributes.len() != sig.params.len() {
            return Err(fail(
                context,
                "parameter attribute inventory must match fixed parameters",
            ));
        }
        for (index, attrs) in sig.param_attributes.iter().enumerate() {
            self.attributes(attrs, sig.params[index], context)?;
        }
        self.attributes(&sig.result_attributes, sig.result, context)?;
        if let Some(storage) = &sig.return_storage {
            if storage.param > 1 {
                return Err(fail(
                    context,
                    "return storage must annotate the first or second parameter",
                ));
            }
            let param = sig.params.get(storage.param).ok_or_else(|| {
                fail(
                    context,
                    "return storage parameter is missing from fixed signature",
                )
            })?;
            if !matches!(
                self.ty(*param, context)?,
                Type::Pointer { address_space: 0 }
            ) {
                return Err(fail(
                    context,
                    "return storage requires an address-space-zero pointer parameter",
                ));
            }
            if !matches!(result, Type::Void) {
                return Err(fail(context, "return storage requires a void result"));
            }
            self.sized(storage.ty, context)?;
        }
        Ok(())
    }

    fn metadata_signature(&self, sig: &Signature, context: &str) -> Result<()> {
        if sig.abi != "c"
            || sig.variadic
            || !matches!(self.ty(sig.result, context)?, Type::Void)
            || sig.params.len() != 1
            || !matches!(self.ty(sig.params[0], context)?, Type::Metadata {})
            || (!sig.param_attributes.is_empty() && sig.param_attributes.len() != 1)
            || sig.param_attributes.iter().any(|attrs| !attrs.is_empty())
            || !sig.result_attributes.is_empty()
            || sig.return_storage.is_some()
        {
            return Err(fail(
                context,
                "invalid compiler-only metadata intrinsic signature",
            ));
        }
        Ok(())
    }

    // An LLVM function value type carries parameter/result types and varargs,
    // but not a declaration's calling convention or parameter ABI attributes.
    // Explicitly attributed native types still require the complete contract.
    fn function_value_signature_matches(&self, value: &Signature, declared: &Signature) -> bool {
        let bare = value.return_storage.is_none()
            && value.result_attributes.is_empty()
            && value.param_attributes.iter().all(Vec::is_empty);
        if !bare {
            return signatures_equal(value, declared);
        }
        value.variadic == declared.variadic
            && value.params.len() == declared.params.len()
            && self
                .same_type(value.result, declared.result, "function value type")
                .is_ok()
            && value
                .params
                .iter()
                .zip(&declared.params)
                .all(|(lhs, rhs)| self.same_type(*lhs, *rhs, "function value type").is_ok())
    }

    fn attributes(&self, attributes: &[String], ty: TypeId, context: &str) -> Result<()> {
        let mut seen = HashSet::new();
        for attribute in attributes {
            if attribute.is_empty() || attribute.as_bytes().contains(&0) || !seen.insert(attribute)
            {
                return Err(fail(
                    context,
                    "empty, duplicate, or malformed ABI attribute",
                ));
            }
            if !["signext", "zeroext"].contains(&attribute.as_str()) {
                return Err(fail(
                    context,
                    format!("unsupported imported ABI attribute {attribute:?}"),
                ));
            }
            if ["signext", "zeroext"].contains(&attribute.as_str())
                && !matches!(self.ty(ty, context)?, Type::Int { .. })
            {
                return Err(fail(
                    context,
                    "integer extension attribute requires an integer",
                ));
            }
            if ["nonnull", "noalias", "nocapture"].contains(&attribute.as_str())
                && !matches!(self.ty(ty, context)?, Type::Pointer { .. })
            {
                return Err(fail(context, "pointer attribute requires a pointer"));
            }
        }
        if seen.contains(&String::from("signext")) && seen.contains(&String::from("zeroext")) {
            return Err(fail(context, "conflicting signext and zeroext attributes"));
        }
        Ok(())
    }

    fn operand(
        &self,
        value: &Operand,
        definitions: &HashMap<ValueId, Definition>,
        context: &str,
    ) -> Result<TypeId> {
        let ty = match value {
            Operand::Value { id } => {
                definitions
                    .get(id)
                    .ok_or_else(|| fail(context, format!("undefined SSA value {id}")))?
                    .ty
            }
            Operand::Int { ty, bits } => {
                let Type::Int { bits: width } = self.ty(*ty, context)? else {
                    return Err(fail(context, "integer constant has non-integer type"));
                };
                if bits.is_empty() || !bits.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(fail(
                        context,
                        "integer constant must be unsigned decimal bits",
                    ));
                }
                let digits = bits.trim_start_matches('0');
                if !digits.is_empty() {
                    // Avoid allocating a bignum for a manifestly out-of-range literal.
                    if digits.len() as u64 > u64::from(*width) * 30103 / 100000 + 1 {
                        return Err(fail(context, "integer constant exceeds its bit width"));
                    }
                    let n = BigUint::parse_bytes(digits.as_bytes(), 10).unwrap();
                    if n.bits() > u64::from(*width) {
                        return Err(fail(context, "integer constant exceeds its bit width"));
                    }
                }
                *ty
            }
            Operand::PointerBits { ty, bits } => {
                if !matches!(self.ty(*ty, context)?, Type::Pointer { address_space: 0 }) {
                    return Err(fail(
                        context,
                        "pointer bits require an address-space-zero pointer type",
                    ));
                }
                if !self.literal_pointer_profile {
                    return Err(fail(context, "pointer bits require the integral AS0 little-endian 64-bit pointer/index profile with default address spaces"));
                }
                if bits.is_empty() || !bits.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(fail(
                        context,
                        "pointer bits must be unsigned decimal address bits",
                    ));
                }
                let digits = bits.trim_start_matches('0');
                if !digits.is_empty() && digits.parse::<u64>().is_err() {
                    return Err(fail(
                        context,
                        "pointer bits exceed the 64-bit address width",
                    ));
                }
                *ty
            }
            Operand::Null { ty } => {
                if !matches!(self.ty(*ty, context)?, Type::Pointer { .. }) {
                    return Err(fail(context, "null requires pointer type"));
                }
                *ty
            }
            Operand::Symbol { ty, name } | Operand::SymbolOffset { ty, name, .. } => {
                if matches!(value, Operand::SymbolOffset { .. })
                    && (!self.literal_pointer_profile
                        || !matches!(self.ty(*ty, context)?, Type::Pointer { address_space: 0 }))
                {
                    return Err(fail(context, "symbol offset requires the integral AS0 little-endian 64-bit pointer/index profile"));
                }
                let symbol = self
                    .symbols
                    .get(name.as_str())
                    .ok_or_else(|| fail(context, format!("unknown symbol {name:?}")))?;
                if matches!(symbol, Symbol::Function(f) if f.intrinsic.is_some()) {
                    return Err(fail(
                        context,
                        "intrinsic address cannot escape or be called as a native symbol",
                    ));
                }
                if matches!(symbol, Symbol::Global(global) if global.thread_local) {
                    return Err(fail(
                        context,
                        "TLS symbol address requires a current-thread address operation",
                    ));
                }
                match self.ty(*ty, context)? {
                    Type::Pointer { .. } => {}
                    Type::Function { signature } => match symbol {
                        Symbol::Function(f)
                            if self.function_value_signature_matches(signature, &f.signature) => {}
                        _ => {
                            return Err(fail(
                                context,
                                "function symbol type does not match its declaration",
                            ));
                        }
                    },
                    _ => {
                        return Err(fail(
                            context,
                            "symbol address requires pointer or function type",
                        ));
                    }
                }
                *ty
            }
            Operand::Aggregate { ty, .. } | Operand::AggregateZero { ty } => {
                self.aggregate_constant(value, definitions, context)?;
                *ty
            }
            Operand::Undef { ty } | Operand::Poison { ty } => {
                self.sized(*ty, context)?;
                *ty
            }
        };
        self.ty(ty, context)?;
        Ok(ty)
    }

    fn aggregate_constant(
        &self,
        value: &Operand,
        definitions: &HashMap<ValueId, Definition>,
        context: &str,
    ) -> Result<()> {
        // Constants form trees. Traverse explicitly so type depth is not a
        // verifier call-stack limit, and validate every nested symbol/bit pattern.
        let mut pending = vec![(value, None)];
        while let Some((constant, expected)) = pending.pop() {
            let actual = match constant {
                Operand::Value { .. } => {
                    return Err(fail(context, "aggregate constant contains an SSA value"));
                }
                Operand::Aggregate { ty, elements } => {
                    self.sized(*ty, context)?;
                    match self.ty(*ty, context)? {
                        Type::Struct { fields, .. } => {
                            if fields.len() != elements.len() {
                                return Err(fail(
                                    context,
                                    "aggregate constant field count mismatch",
                                ));
                            }
                            pending.extend(
                                elements
                                    .iter()
                                    .zip(fields)
                                    .map(|(value, ty)| (value, Some(*ty))),
                            );
                        }
                        Type::Array { element, len } => {
                            if u64::try_from(elements.len()).ok() != Some(*len) {
                                return Err(fail(
                                    context,
                                    "aggregate constant element count mismatch",
                                ));
                            }
                            pending.extend(elements.iter().map(|value| (value, Some(*element))));
                        }
                        _ => {
                            return Err(fail(
                                context,
                                "aggregate constant requires a struct or array",
                            ))
                        }
                    }
                    *ty
                }
                Operand::AggregateZero { ty } => {
                    if !matches!(
                        self.ty(*ty, context)?,
                        Type::Struct { .. } | Type::Array { .. }
                    ) {
                        return Err(fail(context, "aggregate zero requires a struct or array"));
                    }
                    self.sized(*ty, context)?;
                    *ty
                }
                _ => self.operand(constant, definitions, context)?,
            };
            if let Some(expected) = expected {
                self.same_type(actual, expected, context)?;
            }
        }
        Ok(())
    }
}

fn signatures_equal(lhs: &Signature, rhs: &Signature) -> bool {
    let attrs = |sig: &Signature| -> Vec<Vec<String>> {
        if sig.param_attributes.is_empty() {
            vec![vec![]; sig.params.len()]
        } else {
            sig.param_attributes.clone()
        }
    };
    lhs.params == rhs.params
        && lhs.result == rhs.result
        && lhs.abi == rhs.abi
        && lhs.variadic == rhs.variadic
        && attrs(lhs) == attrs(rhs)
        && lhs.result_attributes == rhs.result_attributes
        && lhs.return_storage == rhs.return_storage
}

#[derive(Clone, Copy)]
struct Definition {
    ty: TypeId,
    block: Option<usize>,
    position: usize,
    alloca: bool,
}

fn atomic_sync_scopes(module: &NativeModule) -> Result<HashMap<u32, &AtomicSyncScope>> {
    let mut scopes = HashMap::new();
    let mut names = HashSet::new();
    for scope in &module.atomic_sync_scopes {
        // LLVM22 stores these context-local identities in uint8_t. A wider
        // wire integer must not fabricate a source context identity.
        if scope.id > u32::from(u8::MAX) {
            return Err(fail(
                "atomic scopes",
                "synchronization scope ID exceeds LLVM22's uint8_t identity",
            ));
        }
        if scopes.insert(scope.id, scope).is_some() || !names.insert(scope.name.as_slice()) {
            return Err(fail(
                "atomic scopes",
                "duplicate synchronization scope ID or name",
            ));
        }
        let reserved = match scope.name.as_slice() {
            b"singlethread" => Some(0),
            b"" => Some(1),
            _ => None,
        };
        if (scope.id == 0 && scope.name != b"singlethread")
            || (scope.id == 1 && !scope.name.is_empty())
            || reserved.is_some_and(|id| id != scope.id)
        {
            return Err(fail(
                "atomic scopes",
                "synchronization scope built-in identity/name mismatch",
            ));
        }
    }
    if !scopes.is_empty() && (!scopes.contains_key(&0) || !scopes.contains_key(&1)) {
        return Err(fail(
            "atomic scopes",
            "nonempty synchronization scope inventory requires both LLVM built-ins",
        ));
    }
    Ok(scopes)
}

/// Validate a complete module before target-specific support checks/emission.
pub fn verify(module: &NativeModule) -> Result<()> {
    if module.format != FORMAT {
        return Err(fail("format", "unsupported native module format"));
    }
    if module.name.trim().is_empty() {
        return Err(fail("name", "module name must be present"));
    }
    match module.semantics {
        Semantics::LlvmDefinedBehaviorV1 => {}
    }
    if !sha256(&module.provenance.input_sha256) {
        return Err(fail("provenance", "input_sha256 must be a SHA-256 digest"));
    }
    for text in [
        &module.provenance.frontend,
        &module.provenance.frontend_version,
        &module.provenance.importer,
        &module.provenance.importer_version,
    ] {
        if text.trim().is_empty() {
            return Err(fail(
                "provenance",
                "frontend/importer names and versions must be present",
            ));
        }
    }
    if module.provenance.source_function_count != module.functions.len()
        || module.provenance.source_global_count != module.globals.len()
        || module.provenance.source_alias_count != module.aliases.len()
        || module.provenance.referenced_comdat_count != module.comdats.len()
    {
        return Err(fail(
            "provenance",
            "source declaration/definition inventory does not match module",
        ));
    }
    comdats(module)?;
    super::native_eh::validate_resume_interface(module)?;
    let data_layout = DataLayout::parse(module)?;
    let literal_pointer_profile = module.target.pointer_bits == 64
        && module.target.little_endian
        && data_layout.pointers[&0].size == 8
        && data_layout.pointer_indices[&0] == 64
        && data_layout.non_integral.is_empty()
        && data_layout.default_spaces == [0; 3];
    let native_tls_profile = module.target.tls_profile.is_some();
    let atomic_pointer_profile = module.target.pointer_bits == 64
        && module.target.little_endian
        && data_layout.pointers[&0].size == 8
        && data_layout.pointer_indices[&0] == 64
        && !data_layout.non_integral.contains(&0)
        && data_layout.default_spaces == [0; 3];
    if module.target.atomic_profile.is_some() && !atomic_pointer_profile {
        return Err(fail("target", "coherent RAM atomic profile requires integral AS0 little-endian 64-bit pointers/indices and default address spaces"));
    }
    if native_tls_profile {
        // Source access models may be specialized to local-exec only within
        // this declared static Linux image. The declaration is not evidence
        // that the eventual platform has initialized each thread's TLS.
        let triple: Vec<_> = module.target.triple.split('-').collect();
        if !literal_pointer_profile
            || triple.get(2) != Some(&"linux")
            || !matches!(
                triple.first().copied(),
                Some("x86_64" | "aarch64" | "riscv64")
            )
            || (triple.first().copied() == Some("riscv64")
                && !matches!(module.target.abi.as_deref(), None | Some("lp64" | "lp64d")))
        {
            return Err(fail("target", "native TLS profile requires Linux x86-64, AArch64 or RV64 with integral AS0 little-endian 64-bit pointers/indices and default address spaces"));
        }
    }
    let mut v = Verifier {
        module,
        data_layout,
        layouts: layouts(module)?,
        symbols: HashMap::new(),
        metadata_personalities: super::native_eh::metadata_personality_declarations(module),
        literal_pointer_profile,
        native_tls_profile,
        noalias_lists: noalias_metadata(module)?,
        atomic_scopes: atomic_sync_scopes(module)?,
    };
    for function in &module.functions {
        symbol_name(&function.name, "functions")?;
        if v.symbols
            .insert(&function.name, Symbol::Function(function))
            .is_some()
        {
            return Err(fail("functions", "duplicate symbol"));
        }
    }
    for global in &module.globals {
        symbol_name(&global.name, "globals")?;
        if v.symbols
            .insert(&global.name, Symbol::Global(global))
            .is_some()
        {
            return Err(fail("globals", "duplicate global/function symbol"));
        }
    }
    // Reserve every alias spelling before resolving any target, so collisions
    // and unsupported chains do not depend on source-list ordering. The map
    // keeps the alias key while borrowing the original body/storage contract.
    let mut alias_names = BTreeSet::new();
    for alias in &module.aliases {
        symbol_name(&alias.name, "aliases")?;
        symbol_name(&alias.aliasee, &alias.name)?;
        if v.symbols.contains_key(alias.name.as_str()) || !alias_names.insert(alias.name.as_str()) {
            return Err(fail(&alias.name, "duplicate alias/global/function symbol"));
        }
    }
    for (id, ty) in module.types.iter().enumerate() {
        if let Type::Function { signature } = ty {
            let context = format!("types[{id}]");
            if signature
                .params
                .iter()
                .any(|ty| matches!(module.types.get(*ty), Some(Type::Metadata {})))
            {
                v.metadata_signature(signature, &context)?;
                if !module.functions.iter().any(|function| {
                    function.name == NOALIAS_SCOPE_DECL
                        && function.intrinsic.as_deref() == Some(NOALIAS_SCOPE_DECL)
                        && v.function_value_signature_matches(signature, &function.signature)
                }) {
                    return Err(fail(
                        &context,
                        "metadata function type requires its included owned intrinsic declaration",
                    ));
                }
            } else {
                v.signature(signature, &context)?;
            }
        }
    }
    for alias in &module.aliases {
        if alias_names.contains(alias.aliasee.as_str()) {
            return Err(fail(
                &alias.name,
                "alias chains and cycles require explicit lowering",
            ));
        }
        let target = v.alias(alias)?;
        v.symbols.insert(&alias.name, target);
    }
    for global in &module.globals {
        v.global(global)?;
    }
    let mut managed = BTreeSet::new();
    for function in &module.functions {
        if let Some(method) = &function.managed_method {
            if !sha256(&method.class_sha256)
                || !sha256(&method.code_sha256)
                || [
                    &method.module,
                    &method.loader_namespace,
                    &method.class_name,
                    &method.method_name,
                    &method.descriptor,
                ]
                .iter()
                .any(|s| s.is_empty() || s.as_bytes().contains(&0))
            {
                return Err(fail(
                    &function.name,
                    "managed method identity is incomplete or malformed",
                ));
            }
            if !managed.insert(method) {
                return Err(fail(&function.name, "duplicate managed method identity"));
            }
        }
        v.function(function)?;
    }
    Ok(())
}

impl<'a> Verifier<'a> {
    fn alias(&self, alias: &Alias) -> Result<Symbol<'a>> {
        let context = format!("alias {:?}", alias.name);
        // Aliases never create a declaration, a body, or a relocation. LLVM's
        // available_externally aliases need a separate non-emission contract;
        // extern_weak/common/appending are not definition-alias linkage kinds.
        if !matches!(
            alias.linkage.as_str(),
            "private" | "internal" | "external" | "weak" | "linkonce" | "linkonce_odr" | "weak_odr"
        ) {
            return Err(fail(&context, "unsupported definition-alias linkage"));
        }
        visibility(&alias.linkage, alias.visibility, &context)?;
        let alias_type = self.ty(alias.ty, &context)?;
        let target = self
            .symbols
            .get(alias.aliasee.as_str())
            .copied()
            .ok_or_else(|| fail(&context, "alias references unknown same-module symbol"))?;
        match target {
            Symbol::Function(function) => {
                if function.entry.is_none() || function.linkage == "available_externally" {
                    return Err(fail(&context, "alias target must be an emitted definition"));
                }
                if function.intrinsic.is_some() {
                    return Err(fail(
                        &context,
                        "alias cannot reference an intrinsic address",
                    ));
                }
                let Type::Function { signature } = alias_type else {
                    return Err(fail(
                        &context,
                        "function alias requires a function value type",
                    ));
                };
                // LLVM function value types contain parameter/result types and
                // varargs, not a declaration's ABI extension attributes. Calls
                // through this spelling still compare the actual target ABI.
                if signature.params.len() != function.signature.params.len()
                    || signature.variadic != function.signature.variadic
                {
                    return Err(fail(&context, "function alias value type mismatch"));
                }
                self.same_type(signature.result, function.signature.result, &context)?;
                for (lhs, rhs) in signature.params.iter().zip(&function.signature.params) {
                    self.same_type(*lhs, *rhs, &context)?;
                }
                if !self.function_value_signature_matches(signature, &function.signature) {
                    return Err(fail(&context, "function alias ABI contract mismatch"));
                }
            }
            Symbol::Global(global) => {
                if global.initializer.is_none() || global.linkage == "available_externally" {
                    return Err(fail(&context, "alias target must be an emitted definition"));
                }
                if global.thread_local {
                    return Err(fail(
                        &context,
                        "TLS aliases require explicit storage/model lowering",
                    ));
                }
                self.same_type(alias.ty, global.ty, &context)?;
            }
        }
        Ok(target)
    }

    fn global(&self, global: &Global) -> Result<()> {
        let context = format!("global {:?}", global.name);
        let layout = self.sized(global.ty, &context)?;
        linkage(&global.linkage, global.initializer.is_some(), &context)?;
        visibility(&global.linkage, global.visibility, &context)?;
        alignment(global.alignment, true, &context)?;
        if global.thread_local {
            if !self.native_tls_profile || global.tls_model.is_none() {
                return Err(fail(
                    &context,
                    "TLS storage requires an explicit native TLS profile and original access model",
                ));
            }
        } else if global.tls_model.is_some() {
            return Err(fail(
                &context,
                "TLS access model requires thread-local storage",
            ));
        }
        let Some(initializer) = &global.initializer else {
            return Ok(());
        };
        if initializer.bytes.len() as u64 != layout.size {
            return Err(fail(
                &context,
                "initializer byte extent does not equal type allocation size",
            ));
        }
        let mut regions = BTreeMap::<u64, u64>::new();
        for relocation in &initializer.relocations {
            if relocation.width == 0 || relocation.width % 8 != 0 {
                return Err(fail(
                    &context,
                    "relocation width must be a nonzero bit width in whole bytes",
                ));
            }
            if !self.symbols.contains_key(relocation.symbol.as_str()) {
                return Err(fail(
                    &context,
                    format!(
                        "relocation references unknown symbol {:?}",
                        relocation.symbol
                    ),
                ));
            }
            if matches!(self.symbols.get(relocation.symbol.as_str()), Some(Symbol::Function(f)) if f.intrinsic.is_some())
            {
                return Err(fail(
                    &context,
                    "relocation cannot reference an intrinsic address",
                ));
            }
            if matches!(self.symbols.get(relocation.symbol.as_str()), Some(Symbol::Global(target)) if target.thread_local)
            {
                return Err(fail(
                    &context,
                    "initializer cannot contain a static address of TLS storage",
                ));
            }
            if let Some(base) = &relocation.relative_to {
                if relocation.width != 32 {
                    return Err(fail(
                        &context,
                        "relative relocation requires exactly 32 bits",
                    ));
                }
                if !self.literal_pointer_profile {
                    return Err(fail(&context, "relative relocation requires the integral AS0 little-endian 64-bit pointer/index profile with default address spaces"));
                }
                if base != &global.name {
                    return Err(fail(
                        &context,
                        "relative relocation base must be its containing global",
                    ));
                }
                if !matches!(global.linkage.as_str(), "private" | "internal") || global.thread_local
                {
                    return Err(fail(
                        &context,
                        "relative relocation base must be an initialized private/internal non-TLS global",
                    ));
                }
                if matches!(self.symbols.get(relocation.symbol.as_str()), Some(Symbol::Global(target)) if target.thread_local)
                {
                    return Err(fail(
                        &context,
                        "relative relocation cannot reference TLS storage",
                    ));
                }
            }
            let end = relocation
                .offset
                .checked_add(u64::from(relocation.width) / 8)
                .ok_or_else(|| fail(&context, "relocation range overflows"))?;
            if end > layout.size {
                return Err(fail(&context, "relocation extends beyond initializer"));
            }
            if regions
                .range(..=relocation.offset)
                .next_back()
                .is_some_and(|(_, previous_end)| *previous_end > relocation.offset)
                || regions
                    .range(relocation.offset..)
                    .next()
                    .is_some_and(|(next, _)| *next < end)
            {
                return Err(fail(&context, "overlapping relocations"));
            }
            regions.insert(relocation.offset, end);
        }
        if global.linkage == "common"
            && (global.constant
                || global.thread_local
                || !initializer.relocations.is_empty()
                || initializer.bytes.iter().any(|b| *b != 0))
        {
            return Err(fail(
                &context,
                "common global must be mutable, zero initialized, non-TLS, and relocation-free",
            ));
        }
        Ok(())
    }

    fn function(&self, function: &Function) -> Result<()> {
        let context = format!("function {:?}", function.name);
        alignment(function.alignment, true, &context)?;
        if function.name == NOALIAS_SCOPE_DECL {
            self.metadata_signature(&function.signature, &context)?;
        } else {
            self.signature(&function.signature, &context)?;
        }
        super::native_eh::validate_function_profile(
            self.module,
            function,
            &self.metadata_personalities,
        )?;
        if let Some(eh) = &function.exception_handling {
            self.operand(&eh.personality, &HashMap::new(), &context)?;
        }
        if function.name.starts_with("llvm.") || function.intrinsic.is_some() {
            if function.name == "llvm.threadlocal.address.p0" && !self.native_tls_profile {
                return Err(fail(
                    &context,
                    "thread-local intrinsic requires an explicit native TLS profile",
                ));
            }
            let sig = &function.signature;
            let shape = if let Some((_, _, bits)) = integer_overflow_intrinsic(&function.name) {
                sig.params.len() == 2
                    && sig.params.iter().all(|ty| {
                        matches!(self.module.types.get(*ty), Some(Type::Int { bits: actual }) if *actual == bits)
                    })
                    && matches!(self.module.types.get(sig.result), Some(Type::Struct { fields, packed: false })
                        if fields.len() == 2
                        && matches!(self.module.types.get(fields[0]), Some(Type::Int { bits: actual }) if *actual == bits)
                        && matches!(self.module.types.get(fields[1]), Some(Type::Int { bits: 1 })))
            } else if let Some((_, bits)) = integer_minmax_intrinsic(&function.name) {
                sig.params.len() == 2
                    && sig.params.iter().all(|ty| {
                        matches!(self.module.types.get(*ty), Some(Type::Int { bits: actual }) if *actual == bits)
                    })
                    && matches!(self.module.types.get(sig.result), Some(Type::Int { bits: actual }) if *actual == bits)
            } else {
                let expected = builtin_signature(&function.name).ok_or_else(|| {
                    fail(&context, "invalid or unsupported intrinsic declaration")
                })?;
                sig.params.len() == expected.len()
                    && match function.name.as_str() {
                        "llvm.eh.typeid.for" | "llvm.eh.typeid.for.p0" => {
                            matches!(self.ty(sig.result, &context)?, Type::Int { bits: 32 })
                        }
                        "llvm.load.relative.i32"
                        | "llvm.load.relative.i64"
                        | "llvm.threadlocal.address.p0" => matches!(
                            self.ty(sig.result, &context)?,
                            Type::Pointer { address_space: 0 }
                        ),
                        _ => matches!(self.ty(sig.result, &context)?, Type::Void),
                    }
                    && sig.params.iter().zip(expected).all(|(ty, expected)| {
                        match (self.module.types.get(*ty), expected) {
                            (Some(Type::Int { bits }), IntrinsicArgument::Integer(expected)) => {
                                bits == expected
                            }
                            (
                                Some(Type::Pointer { address_space: 0 }),
                                IntrinsicArgument::Pointer,
                            ) => true,
                            (Some(Type::Metadata {}), IntrinsicArgument::Metadata) => true,
                            _ => false,
                        }
                    })
            };
            if function.intrinsic.as_deref() != Some(function.name.as_str())
                || function.entry.is_some()
                || function.linkage != "external"
                || function.visibility != Visibility::Default
                || sig.abi != "c"
                || sig.variadic
                || !shape
                || sig.param_attributes.iter().any(|attrs| !attrs.is_empty())
                || !sig.result_attributes.is_empty()
                || sig.return_storage.is_some()
            {
                return Err(fail(
                    &context,
                    "invalid or unsupported intrinsic declaration",
                ));
            }
        }
        linkage(&function.linkage, function.entry.is_some(), &context)?;
        visibility(&function.linkage, function.visibility, &context)?;
        if function.linkage == "common" {
            return Err(fail(&context, "common linkage is only valid for globals"));
        }
        if function.params.len() != function.signature.params.len() {
            return Err(fail(
                &context,
                "fixed parameter inventory does not match signature",
            ));
        }
        let mut definitions = HashMap::new();
        for (param, expected) in function.params.iter().zip(&function.signature.params) {
            self.same_type(param.ty, *expected, &context)?;
            if definitions
                .insert(
                    param.id,
                    Definition {
                        ty: param.ty,
                        block: None,
                        position: 0,
                        alloca: false,
                    },
                )
                .is_some()
            {
                return Err(fail(&context, "duplicate SSA parameter definition"));
            }
        }
        let Some(entry_id) = function.entry else {
            if !function.blocks.is_empty() || function.managed_method.is_some() {
                return Err(fail(
                    &context,
                    "declaration has a body or managed implementation metadata",
                ));
            }
            return Ok(());
        };
        let mut indices = HashMap::new();
        // Each invoke normal edge has its own node. Its result is defined
        // there, not in either endpoint block, including self/loopback edges.
        let mut normal_nodes = vec![None; function.blocks.len()];
        let mut node_count = function.blocks.len();
        let mut landingpad_type = None;
        for (index, block) in function.blocks.iter().enumerate() {
            if indices.insert(block.id, index).is_some() {
                return Err(fail(&context, "duplicate block ID"));
            }
            let mut ordinary = false;
            for (position, instruction) in block.instructions.iter().enumerate() {
                if matches!(instruction.operation, Operation::Phi { .. }) {
                    if ordinary {
                        return Err(fail(&context, "phi must precede ordinary instructions"));
                    }
                } else {
                    if matches!(instruction.operation, Operation::LandingPad { .. }) {
                        if ordinary {
                            return Err(fail(
                                &context,
                                "landingpad must be the first non-phi instruction",
                            ));
                        }
                        if function.exception_handling.is_none() {
                            return Err(fail(
                                &context,
                                "landingpad requires an exception personality",
                            ));
                        }
                        if let Some(result) = instruction.result {
                            if let Some(previous) = landingpad_type {
                                self.same_type(result.ty, previous, &context)?;
                            } else {
                                landingpad_type = Some(result.ty);
                            }
                        }
                    }
                    ordinary = true;
                }
                if let Some(result) = instruction.result {
                    self.sized(result.ty, &context)?;
                    if definitions
                        .insert(
                            result.id,
                            Definition {
                                ty: result.ty,
                                block: Some(index),
                                position,
                                alloca: matches!(instruction.operation, Operation::Alloca { .. }),
                            },
                        )
                        .is_some()
                    {
                        return Err(fail(
                            &context,
                            format!("duplicate SSA definition {}", result.id),
                        ));
                    }
                }
            }
            if let Terminator::Invoke { result, .. } = &block.terminator {
                normal_nodes[index] = Some(node_count);
                if let Some(result) = result {
                    self.sized(result.ty, &context)?;
                    if definitions
                        .insert(
                            result.id,
                            Definition {
                                ty: result.ty,
                                block: Some(node_count),
                                position: 0,
                                alloca: false,
                            },
                        )
                        .is_some()
                    {
                        return Err(fail(
                            &context,
                            format!("duplicate SSA definition {}", result.id),
                        ));
                    }
                }
                node_count += 1;
            }
        }
        let entry = *indices
            .get(&entry_id)
            .ok_or_else(|| fail(&context, "entry block does not exist"))?;
        let mut successors = vec![Vec::new(); function.blocks.len()];
        let mut predecessors = vec![BTreeSet::new(); function.blocks.len()];
        for (index, block) in function.blocks.iter().enumerate() {
            let targets = match &block.terminator {
                Terminator::Jump { target } => vec![*target],
                Terminator::Branch {
                    on_true, on_false, ..
                } => vec![*on_true, *on_false],
                Terminator::Switch { default, cases, .. } => std::iter::once(*default)
                    .chain(cases.iter().map(|case| case.target))
                    .collect(),
                Terminator::Invoke { normal, unwind, .. } => {
                    if normal == unwind {
                        return Err(fail(
                            &context,
                            "invoke normal and unwind destinations must differ",
                        ));
                    }
                    vec![*normal, *unwind]
                }
                Terminator::Return { .. } | Terminator::Resume { .. } | Terminator::Unreachable => {
                    vec![]
                }
            };
            let mut seen = HashSet::new();
            for target in targets {
                let next = *indices.get(&target).ok_or_else(|| {
                    fail(&context, format!("branch targets unknown block {target}"))
                })?;
                if seen.insert(next) {
                    successors[index].push(next);
                    predecessors[next].insert(index);
                }
            }
        }
        if !predecessors[entry].is_empty() {
            return Err(fail(&context, "entry block has predecessors"));
        }
        // Structural EH edges are checked even when their blocks are dead.
        for (index, block) in function.blocks.iter().enumerate() {
            let first = block
                .instructions
                .iter()
                .find(|instruction| !matches!(instruction.operation, Operation::Phi { .. }));
            if first.is_some_and(|instruction| {
                matches!(instruction.operation, Operation::LandingPad { .. })
            }) {
                if index == entry {
                    return Err(fail(&context, "landingpad cannot be in the entry block"));
                }
                for predecessor in &predecessors[index] {
                    if !matches!(&function.blocks[*predecessor].terminator,
                        Terminator::Invoke { normal, unwind, .. }
                        if *unwind == block.id && *normal != block.id)
                    {
                        return Err(fail(
                            &context,
                            "landingpad block must be entered only through invoke unwind edges",
                        ));
                    }
                }
            }
            if let Terminator::Invoke { unwind, .. } = &block.terminator {
                let target = &function.blocks[indices[unwind]];
                if !target
                    .instructions
                    .iter()
                    .find(|instruction| !matches!(instruction.operation, Operation::Phi { .. }))
                    .is_some_and(|instruction| {
                        matches!(instruction.operation, Operation::LandingPad { .. })
                    })
                {
                    return Err(fail(
                        &context,
                        "invoke unwind destination must start with a landingpad after phis",
                    ));
                }
            }
        }
        let mut dominance_successors = successors.clone();
        let mut dominance_predecessors = predecessors.clone();
        dominance_successors.resize_with(node_count, Vec::new);
        dominance_predecessors.resize_with(node_count, BTreeSet::new);
        for (index, block) in function.blocks.iter().enumerate() {
            if let Terminator::Invoke { normal, unwind, .. } = &block.terminator {
                let edge = normal_nodes[index].unwrap();
                let target = indices[normal];
                dominance_successors[index] = vec![edge, indices[unwind]];
                dominance_successors[edge].push(target);
                dominance_predecessors[edge].insert(index);
                dominance_predecessors[target].remove(&index);
                dominance_predecessors[target].insert(edge);
            }
        }
        let dominance = Dominance::compute(entry, &dominance_successors, &dominance_predecessors);
        for (index, block) in function.blocks.iter().enumerate() {
            let here = format!("{context}, block {}", block.id);
            for (position, instruction) in block.instructions.iter().enumerate() {
                self.instruction(instruction, &definitions, &here)?;
                if let Operation::Phi { incoming } = &instruction.operation {
                    let mut actual = BTreeSet::new();
                    for edge in incoming {
                        let predecessor = *indices
                            .get(&edge.block)
                            .ok_or_else(|| fail(&here, "phi names an unknown predecessor"))?;
                        if !actual.insert(predecessor) {
                            return Err(fail(&here, "phi has duplicate predecessor"));
                        }
                        let (use_node, use_position) =
                            match &function.blocks[predecessor].terminator {
                                Terminator::Invoke { normal, .. } if *normal == block.id => {
                                    (normal_nodes[predecessor].unwrap(), 1)
                                }
                                _ => (predecessor, function.blocks[predecessor].instructions.len()),
                            };
                        self.check_use(
                            &edge.value,
                            &definitions,
                            use_node,
                            use_position,
                            &dominance,
                            &here,
                        )?;
                    }
                    if actual != predecessors[index] {
                        return Err(fail(&here, "phi predecessor set differs from CFG"));
                    }
                } else {
                    for operand in instruction_operands(&instruction.operation) {
                        self.check_use(operand, &definitions, index, position, &dominance, &here)?;
                    }
                }
            }
            let position = block.instructions.len();
            match &block.terminator {
                Terminator::Return { value } => {
                    if matches!(self.ty(function.signature.result, &here)?, Type::Void) {
                        if value.is_some() {
                            return Err(fail(&here, "void function returns a value"));
                        }
                    } else {
                        let value = value
                            .as_ref()
                            .ok_or_else(|| fail(&here, "non-void function returns no value"))?;
                        self.same_type(
                            self.operand(value, &definitions, &here)?,
                            function.signature.result,
                            &here,
                        )?;
                    }
                    if let Some(value) = value {
                        self.check_use(value, &definitions, index, position, &dominance, &here)?;
                    }
                }
                Terminator::Branch { condition, .. } => {
                    self.boolean(self.operand(condition, &definitions, &here)?, &here)?;
                    self.check_use(condition, &definitions, index, position, &dominance, &here)?;
                }
                Terminator::Switch {
                    condition, cases, ..
                } => {
                    let ty = self.operand(condition, &definitions, &here)?;
                    if !matches!(self.ty(ty, &here)?, Type::Int { .. }) {
                        return Err(fail(&here, "switch condition requires an integer"));
                    }
                    self.check_use(condition, &definitions, index, position, &dominance, &here)?;
                    let mut patterns = HashSet::new();
                    for case in cases {
                        let Operand::Int { bits, .. } = &case.value else {
                            return Err(fail(
                                &here,
                                "switch case requires a typed integer constant",
                            ));
                        };
                        self.same_type(self.operand(&case.value, &definitions, &here)?, ty, &here)?;
                        // Leading zeroes do not distinguish equal bit patterns.
                        // Range checking above bounds the significant digits.
                        let digits = bits.trim_start_matches('0');
                        let pattern = if digits.is_empty() {
                            BigUint::default()
                        } else {
                            BigUint::parse_bytes(digits.as_bytes(), 10).unwrap()
                        };
                        if !patterns.insert(pattern) {
                            return Err(fail(&here, "switch has duplicate case bit patterns"));
                        }
                    }
                }
                Terminator::Invoke {
                    callee,
                    signature,
                    args,
                    result,
                    ..
                } => {
                    self.call(callee, signature, args, *result, &definitions, &here)?;
                    for operand in std::iter::once(callee).chain(args) {
                        self.check_use(operand, &definitions, index, position, &dominance, &here)?;
                    }
                }
                Terminator::Resume { value } => {
                    if function.exception_handling.is_none() {
                        return Err(fail(&here, "resume requires an exception personality"));
                    }
                    let ty = self.operand(value, &definitions, &here)?;
                    if !super::native_eh::is_exception_aggregate(self.module, ty) {
                        return Err(fail(
                            &here,
                            "resume requires original unpacked {ptrAS0,i32}",
                        ));
                    }
                    if let Some(previous) = landingpad_type {
                        self.same_type(ty, previous, &here)?;
                    }
                    self.check_use(value, &definitions, index, position, &dominance, &here)?;
                }
                Terminator::Jump { .. } | Terminator::Unreachable => {}
            }
        }
        self.noalias_dominance(function, &dominance, &context)?;
        Ok(())
    }

    fn noalias_dominance(
        &self,
        function: &Function,
        dominance: &Dominance,
        context: &str,
    ) -> Result<()> {
        let mut groups: HashMap<usize, Vec<(usize, usize)>> = HashMap::new();
        for (block, body) in function.blocks.iter().enumerate() {
            for (position, instruction) in body.instructions.iter().enumerate() {
                if let Operation::NoAliasScopeDecl { scope_list, .. } = &instruction.operation {
                    let scope = self
                        .noalias_lists
                        .get(scope_list)
                        .and_then(|list| list.scopes.first())
                        .ok_or_else(|| fail(context, "noalias declaration scope is missing"))?;
                    // The scope itself is the key. Distinct list wrappers and
                    // equal display strings must not change this relation.
                    groups.entry(*scope).or_default().push((block, position));
                }
            }
        }
        if groups.values().all(|group| group.len() < 2) {
            return Ok(());
        }
        let (preorder, end) = dominance.intervals();
        for (scope, group) in &mut groups {
            if group.len() < 2 {
                continue;
            }
            // Pinned LLVM instruction dominance considers any unreachable
            // target dominated, even by an unreachable source. The comparison
            // excludes identical instruction sites, not dead blocks.
            if group.iter().any(|(block, _)| preorder[*block].is_none()) {
                return Err(fail(context, format!("noalias scope declaration dominates another declaration of the same actual scope {scope} (unreachable target)")));
            }
            group.sort_unstable_by_key(|(block, position)| (preorder[*block], *position));
            // In dominator-tree preorder, an ancestor's subtree is contiguous.
            // If any pair is related, the first subsequent site after that
            // ancestor is related too. Adjacent checks therefore suffice.
            for pair in group.windows(2) {
                let (from, _) = pair[0];
                let (to, _) = pair[1];
                if from == to || preorder[to].unwrap() < end[from] {
                    return Err(fail(context, format!("noalias scope declaration dominates another declaration of the same actual scope {scope}")));
                }
            }
        }
        Ok(())
    }

    fn boolean(&self, ty: TypeId, context: &str) -> Result<()> {
        if matches!(self.ty(ty, context)?, Type::Int { bits: 1 }) {
            Ok(())
        } else {
            Err(fail(context, "condition/result requires i1"))
        }
    }

    fn pointer(&self, ty: TypeId, context: &str) -> Result<()> {
        if matches!(self.ty(ty, context)?, Type::Pointer { .. }) {
            Ok(())
        } else {
            Err(fail(context, "memory address requires pointer type"))
        }
    }

    fn memory_pointer(&self, ty: TypeId, context: &str) -> Result<()> {
        if matches!(self.ty(ty, context)?, Type::Pointer { address_space: 0 }) {
            Ok(())
        } else {
            Err(fail(
                context,
                "memory intrinsic address requires an address-space-zero pointer",
            ))
        }
    }

    fn memory_length(&self, ty: TypeId, context: &str) -> Result<()> {
        if matches!(self.ty(ty, context)?, Type::Int { bits: 32 | 64 }) {
            Ok(())
        } else {
            Err(fail(context, "memory intrinsic length requires i32 or i64"))
        }
    }

    fn atomic_scope(&self, id: u32, context: &str) -> Result<()> {
        if self.atomic_scopes.contains_key(&id) {
            Ok(())
        } else {
            Err(fail(
                context,
                "atomic synchronization scope is missing from the module inventory",
            ))
        }
    }

    fn atomic_value(&self, ty: TypeId, context: &str) -> Result<()> {
        // Value size differs from allocation stride when DataLayout assigns a
        // larger ABI alignment. Atomic i8 remains eight bits even with i8:64.
        let bits =
            match self.ty(ty, context)? {
                Type::Int { bits } | Type::Float { bits } => u64::from(*bits),
                Type::Pointer { address_space } => {
                    self.data_layout
                        .pointers
                        .get(address_space)
                        .unwrap_or(&self.data_layout.pointers[&0])
                        .size
                        * 8
                }
                _ => return Err(fail(
                    context,
                    "atomic value type requires scalar integer, pointer or floating-point storage",
                )),
            };
        if bits < 8 || !bits.is_power_of_two() {
            return Err(fail(
                context,
                "atomic value width must be a power of two of at least eight bits",
            ));
        }
        self.sized(ty, context)?;
        Ok(())
    }

    fn atomic_no_result(&self, instruction: &Instruction, context: &str) -> Result<()> {
        if instruction.result.is_some() {
            Err(fail(
                context,
                "atomic store/fence cannot define an SSA result",
            ))
        } else {
            Ok(())
        }
    }

    fn instruction(
        &self,
        instruction: &Instruction,
        definitions: &HashMap<ValueId, Definition>,
        context: &str,
    ) -> Result<()> {
        let operand = |o| self.operand(o, definitions, context);
        let result = || {
            instruction
                .result
                .map(|v| v.ty)
                .ok_or_else(|| fail(context, "instruction requires an SSA result"))
        };
        match &instruction.operation {
            Operation::NoAliasScopeDecl { scope_list, .. } => {
                if instruction.result.is_some() {
                    return Err(fail(
                        context,
                        "noalias scope declaration cannot define an SSA value",
                    ));
                }
                if !self
                    .noalias_lists
                    .get(scope_list)
                    .is_some_and(|list| list.scopes.len() == 1)
                {
                    return Err(fail(
                        context,
                        "noalias scope declaration requires one included actual scope",
                    ));
                }
            }
            Operation::ThreadLocalAddress { global } => {
                if !self.native_tls_profile {
                    return Err(fail(
                        context,
                        "current-thread address requires an explicit native TLS profile",
                    ));
                }
                match self.symbols.get(global.as_str()) {
                    Some(Symbol::Global(storage))
                        if storage.thread_local && storage.tls_model.is_some() => {}
                    _ => {
                        return Err(fail(
                            context,
                            "current-thread address requires an included TLS global",
                        ))
                    }
                }
                if !matches!(
                    self.ty(result()?, context)?,
                    Type::Pointer { address_space: 0 }
                ) {
                    return Err(fail(
                        context,
                        "current-thread address result requires an address-space-zero pointer",
                    ));
                }
            }
            Operation::Trap {} => {
                if instruction.result.is_some() {
                    return Err(fail(context, "trap cannot define an SSA value"));
                }
            }
            Operation::Assume { condition } => {
                if instruction.result.is_some() {
                    return Err(fail(context, "assume cannot define an SSA value"));
                }
                self.boolean(operand(condition)?, context)?;
            }
            Operation::Lifetime { pointer, .. } => {
                if instruction.result.is_some() {
                    return Err(fail(context, "lifetime cannot define an SSA value"));
                }
                self.memory_pointer(operand(pointer)?, context)?;
                match pointer {
                    Operand::Poison { .. } => {}
                    Operand::Value { id } if definitions.get(id).is_some_and(|d| d.alloca) => {}
                    _ => {
                        return Err(fail(
                            context,
                            "lifetime pointer must be an alloca SSA value or poison",
                        ));
                    }
                }
            }
            Operation::MemorySet {
                destination,
                value,
                length,
                alignment: align,
                ..
            } => {
                if instruction.result.is_some() {
                    return Err(fail(context, "memory operation cannot define an SSA value"));
                }
                self.memory_pointer(operand(destination)?, context)?;
                if !matches!(self.ty(operand(value)?, context)?, Type::Int { bits: 8 }) {
                    return Err(fail(context, "memory fill requires an i8 value"));
                }
                self.memory_length(operand(length)?, context)?;
                alignment(*align, false, context)?;
            }
            Operation::MemoryCopy {
                destination,
                source,
                length,
                destination_alignment,
                source_alignment,
                ..
            } => {
                if instruction.result.is_some() {
                    return Err(fail(context, "memory operation cannot define an SSA value"));
                }
                self.memory_pointer(operand(destination)?, context)?;
                self.memory_pointer(operand(source)?, context)?;
                self.memory_length(operand(length)?, context)?;
                alignment(*destination_alignment, false, context)?;
                alignment(*source_alignment, false, context)?;
            }
            Operation::Binary {
                kind,
                lhs,
                rhs,
                flags,
            } => {
                let ty = operand(lhs)?;
                self.same_type(ty, operand(rhs)?, context)?;
                self.same_type(ty, result()?, context)?;
                if !matches!(self.ty(ty, context)?, Type::Int { .. }) {
                    return Err(fail(context, "integer operation has non-integer operands"));
                }
                let mut seen = HashSet::new();
                for flag in flags {
                    let allowed = match flag.as_str() {
                        "nsw" | "nuw" => matches!(
                            kind,
                            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Shl
                        ),
                        "exact" => matches!(
                            kind,
                            BinaryOp::UDiv | BinaryOp::SDiv | BinaryOp::LShr | BinaryOp::AShr
                        ),
                        "disjoint" => *kind == BinaryOp::Or,
                        _ => false,
                    };
                    if !allowed || !seen.insert(flag) {
                        return Err(fail(
                            context,
                            "unknown, duplicate, or inapplicable LLVM poison flag",
                        ));
                    }
                }
            }
            Operation::IntegerOverflow { kind, lhs, rhs, .. } => {
                let ty = operand(lhs)?;
                self.same_type(ty, operand(rhs)?, context)?;
                if !matches!(kind, BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul)
                    || !matches!(self.ty(ty, context)?, Type::Int { bits: 1..=64 })
                {
                    return Err(fail(
                        context,
                        "integer overflow requires scalar i1..i64 add/sub/mul operands",
                    ));
                }
                match self.ty(result()?, context)? {
                    Type::Struct {
                        fields,
                        packed: false,
                    } if fields.len() == 2 => {
                        self.same_type(fields[0], ty, context)?;
                        self.boolean(fields[1], context)?;
                    }
                    _ => {
                        return Err(fail(
                            context,
                            "integer overflow result must be original unpacked {iN,i1}",
                        ))
                    }
                }
            }
            Operation::IntegerMinMax { lhs, rhs, .. } => {
                let ty = operand(lhs)?;
                self.same_type(ty, operand(rhs)?, context)?;
                self.same_type(ty, result()?, context)?;
                if !matches!(self.ty(ty, context)?, Type::Int { bits: 1..=64 }) {
                    return Err(fail(
                        context,
                        "integer min/max requires same-type scalar i1..i64 operands and result",
                    ));
                }
            }
            Operation::ICmp { lhs, rhs, .. } => {
                let ty = operand(lhs)?;
                self.same_type(ty, operand(rhs)?, context)?;
                if !matches!(
                    self.ty(ty, context)?,
                    Type::Int { .. } | Type::Pointer { .. }
                ) {
                    return Err(fail(context, "icmp requires integer or pointer operands"));
                }
                self.boolean(result()?, context)?;
            }
            Operation::Cast { kind, value } => {
                let from = self.ty(operand(value)?, context)?;
                let to = self.ty(result()?, context)?;
                let valid = match (kind, from, to) {
                    (CastOp::Trunc, Type::Int { bits: a }, Type::Int { bits: b }) => a > b,
                    (CastOp::ZExt | CastOp::SExt, Type::Int { bits: a }, Type::Int { bits: b }) => {
                        a < b
                    }
                    (CastOp::PtrToInt, Type::Pointer { .. }, Type::Int { .. }) => true,
                    (CastOp::IntToPtr, Type::Int { .. }, Type::Pointer { .. }) => true,
                    (
                        CastOp::Bitcast,
                        Type::Pointer { address_space: a },
                        Type::Pointer { address_space: b },
                    ) => a == b,
                    (
                        CastOp::Bitcast,
                        Type::Int { bits: a } | Type::Float { bits: a },
                        Type::Int { bits: b } | Type::Float { bits: b },
                    ) => a == b,
                    _ => false,
                };
                if !valid {
                    return Err(fail(context, "invalid cast kind/type/width combination"));
                }
            }
            Operation::Select {
                condition,
                on_true,
                on_false,
            } => {
                self.boolean(operand(condition)?, context)?;
                let ty = operand(on_true)?;
                self.same_type(ty, operand(on_false)?, context)?;
                self.same_type(ty, result()?, context)?;
            }
            Operation::Freeze { value } => {
                self.same_type(operand(value)?, result()?, context)?;
            }
            Operation::ExtractValue { aggregate, indices } => {
                let ty = operand(aggregate)?;
                self.sized(ty, context)?;
                let selected = aggregate_element_type(self.module, ty, indices)?;
                self.same_type(selected, result()?, context)?;
            }
            Operation::InsertValue {
                aggregate,
                value,
                indices,
            } => {
                let ty = operand(aggregate)?;
                self.sized(ty, context)?;
                self.same_type(ty, result()?, context)?;
                let selected = aggregate_element_type(self.module, ty, indices)?;
                self.same_type(selected, operand(value)?, context)?;
            }
            Operation::Alloca {
                alignment: align, ..
            } => {
                self.pointer(result()?, context)?;
                alignment(*align, true, context)?;
            }
            Operation::Gep { base, offset, .. } => {
                let ty = operand(base)?;
                self.pointer(ty, context)?;
                self.same_type(ty, result()?, context)?;
                if !matches!(self.ty(operand(offset)?, context)?, Type::Int { .. }) {
                    return Err(fail(context, "GEP byte offset requires integer type"));
                }
            }
            Operation::Load {
                pointer,
                alignment: align,
                ..
            } => {
                self.pointer(operand(pointer)?, context)?;
                self.sized(result()?, context)?;
                alignment(*align, true, context)?;
            }
            Operation::Store {
                pointer,
                value,
                alignment: align,
                ..
            } => {
                if instruction.result.is_some() {
                    return Err(fail(context, "store cannot define an SSA value"));
                }
                self.pointer(operand(pointer)?, context)?;
                self.sized(operand(value)?, context)?;
                alignment(*align, true, context)?;
            }
            Operation::AtomicLoad {
                pointer,
                alignment: align,
                ordering,
                sync_scope,
                ..
            } => {
                self.pointer(operand(pointer)?, context)?;
                self.atomic_value(result()?, context)?;
                alignment(*align, false, context)?;
                self.atomic_scope(*sync_scope, context)?;
                if !matches!(
                    ordering,
                    AtomicOrdering::Unordered
                        | AtomicOrdering::Monotonic
                        | AtomicOrdering::Acquire
                        | AtomicOrdering::SequentiallyConsistent
                ) {
                    return Err(fail(context, "atomic load ordering cannot release"));
                }
            }
            Operation::AtomicStore {
                pointer,
                value,
                alignment: align,
                ordering,
                sync_scope,
                ..
            } => {
                self.atomic_no_result(instruction, context)?;
                self.pointer(operand(pointer)?, context)?;
                self.atomic_value(operand(value)?, context)?;
                alignment(*align, false, context)?;
                self.atomic_scope(*sync_scope, context)?;
                if !matches!(
                    ordering,
                    AtomicOrdering::Unordered
                        | AtomicOrdering::Monotonic
                        | AtomicOrdering::Release
                        | AtomicOrdering::SequentiallyConsistent
                ) {
                    return Err(fail(context, "atomic store ordering cannot acquire"));
                }
            }
            Operation::AtomicFence {
                ordering,
                sync_scope,
            } => {
                self.atomic_no_result(instruction, context)?;
                self.atomic_scope(*sync_scope, context)?;
                if !matches!(
                    ordering,
                    AtomicOrdering::Acquire
                        | AtomicOrdering::Release
                        | AtomicOrdering::AcquireRelease
                        | AtomicOrdering::SequentiallyConsistent
                ) {
                    return Err(fail(
                        context,
                        "atomic fence ordering must be acquire, release, acq_rel or seq_cst",
                    ));
                }
            }
            Operation::AtomicRmw {
                kind,
                pointer,
                value,
                alignment: align,
                ordering,
                sync_scope,
                ..
            } => {
                self.pointer(operand(pointer)?, context)?;
                let ty = operand(value)?;
                self.same_type(ty, result()?, context)?;
                self.atomic_value(ty, context)?;
                alignment(*align, false, context)?;
                self.atomic_scope(*sync_scope, context)?;
                if *ordering == AtomicOrdering::Unordered {
                    return Err(fail(
                        context,
                        "atomic RMW ordering must be at least monotonic",
                    ));
                }
                let compatible = match kind {
                    AtomicRmwOp::Xchg => true,
                    AtomicRmwOp::Fadd
                    | AtomicRmwOp::Fsub
                    | AtomicRmwOp::Fmax
                    | AtomicRmwOp::Fmin
                    | AtomicRmwOp::Fmaximum
                    | AtomicRmwOp::Fminimum => matches!(self.ty(ty, context)?, Type::Float { .. }),
                    _ => matches!(self.ty(ty, context)?, Type::Int { .. }),
                };
                if !compatible {
                    return Err(fail(context, "atomic RMW operation/value type mismatch"));
                }
            }
            Operation::AtomicCompareExchange {
                pointer,
                expected,
                replacement,
                alignment: align,
                success_ordering,
                failure_ordering,
                sync_scope,
                ..
            } => {
                self.pointer(operand(pointer)?, context)?;
                let ty = operand(expected)?;
                self.same_type(ty, operand(replacement)?, context)?;
                if !matches!(
                    self.ty(ty, context)?,
                    Type::Int { .. } | Type::Pointer { .. }
                ) {
                    return Err(fail(
                        context,
                        "atomic compare-exchange value type requires integer or pointer",
                    ));
                }
                self.atomic_value(ty, context)?;
                alignment(*align, false, context)?;
                self.atomic_scope(*sync_scope, context)?;
                if *success_ordering == AtomicOrdering::Unordered
                    || !matches!(
                        failure_ordering,
                        AtomicOrdering::Monotonic
                            | AtomicOrdering::Acquire
                            | AtomicOrdering::SequentiallyConsistent
                    )
                {
                    return Err(fail(context, "atomic compare-exchange ordering is invalid"));
                }
                // LLVM22 permits failure to be stronger than success. Do not
                // impose the .oc/C++ API's older relative-strength restriction.
                match self.ty(result()?, context)? {
                    Type::Struct {
                        fields,
                        packed: false,
                    } if fields.len() == 2 => {
                        self.same_type(ty, fields[0], context)?;
                        self.boolean(fields[1], context)?;
                    }
                    _ => {
                        return Err(fail(
                            context,
                            "atomic compare-exchange result requires original unpacked {T,i1}",
                        ))
                    }
                }
            }
            Operation::Call {
                callee,
                signature,
                args,
            } => {
                self.call(
                    callee,
                    signature,
                    args,
                    instruction.result,
                    definitions,
                    context,
                )?;
            }
            Operation::LandingPad { cleanup, clauses } => {
                if !super::native_eh::is_exception_aggregate(self.module, result()?) {
                    return Err(fail(
                        context,
                        "landingpad requires original unpacked {ptrAS0,i32}",
                    ));
                }
                if !cleanup && clauses.is_empty() {
                    return Err(fail(
                        context,
                        "landingpad requires cleanup or at least one clause",
                    ));
                }
                for clause in clauses {
                    match clause {
                        ExceptionClause::Catch { typeinfo } => {
                            operand(typeinfo)?;
                            super::native_eh::validate_typeinfo(self.module, typeinfo)?;
                        }
                        ExceptionClause::Filter { typeinfos } => {
                            for typeinfo in typeinfos {
                                if !matches!(
                                    typeinfo,
                                    Operand::Symbol { .. }
                                        | Operand::SymbolOffset { addend: 0, .. }
                                ) {
                                    return Err(fail(context, "nonempty filter entries require named zero-offset GlobalValues"));
                                }
                                operand(typeinfo)?;
                                super::native_eh::validate_typeinfo(self.module, typeinfo)?;
                            }
                        }
                    }
                }
            }
            Operation::EhTypeId { typeinfo } => {
                if !matches!(self.ty(result()?, context)?, Type::Int { bits: 32 }) {
                    return Err(fail(context, "exception typeid result requires i32"));
                }
                operand(typeinfo)?;
                super::native_eh::validate_typeinfo(self.module, typeinfo)?;
            }
            Operation::Phi { incoming } => {
                let ty = result()?;
                if incoming.is_empty() {
                    return Err(fail(context, "phi has no incoming values"));
                }
                for edge in incoming {
                    self.same_type(operand(&edge.value)?, ty, context)?;
                }
            }
        }
        Ok(())
    }

    fn call(
        &self,
        callee: &Operand,
        signature: &Signature,
        args: &[Operand],
        result: Option<Value>,
        definitions: &HashMap<ValueId, Definition>,
        context: &str,
    ) -> Result<()> {
        self.signature(signature, context)?;
        let ty = self.ty(self.operand(callee, definitions, context)?, context)?;
        match ty {
            Type::Pointer { .. } => {}
            Type::Function {
                signature: declared,
            } if self.function_value_signature_matches(declared, signature) => {}
            _ => {
                return Err(fail(
                    context,
                    "callee is not a pointer with the declared call signature",
                ));
            }
        }
        if let Operand::Symbol { name, .. }
        | Operand::SymbolOffset {
            name, addend: 0, ..
        } = callee
        {
            match self.symbols.get(name.as_str()) {
                Some(Symbol::Function(function))
                    if signatures_equal(&function.signature, signature) => {}
                _ => return Err(fail(context, "direct callee symbol/signature mismatch")),
            }
        }
        if args.len() < signature.params.len()
            || (!signature.variadic && args.len() != signature.params.len())
        {
            return Err(fail(
                context,
                "call argument count does not match signature",
            ));
        }
        for (index, arg) in args.iter().enumerate() {
            let actual = self.operand(arg, definitions, context)?;
            self.sized(actual, context)?;
            if let Some(expected) = signature.params.get(index) {
                self.same_type(actual, *expected, context)?;
            }
        }
        if matches!(self.ty(signature.result, context)?, Type::Void) {
            if result.is_some() {
                return Err(fail(context, "void call defines a value"));
            }
        } else {
            self.same_type(
                result
                    .ok_or_else(|| fail(context, "call requires an SSA result"))?
                    .ty,
                signature.result,
                context,
            )?;
        }
        Ok(())
    }

    fn check_use(
        &self,
        operand: &Operand,
        definitions: &HashMap<ValueId, Definition>,
        block: usize,
        position: usize,
        dominance: &Dominance,
        context: &str,
    ) -> Result<()> {
        let Operand::Value { id } = operand else {
            self.operand(operand, definitions, context)?;
            return Ok(());
        };
        let definition = definitions
            .get(id)
            .ok_or_else(|| fail(context, format!("undefined SSA value {id}")))?;
        let Some(from) = definition.block else {
            return Ok(());
        };
        // LLVM treats unreachable uses as vacuously dominated. They cannot be
        // reached through this module's CFG, but remain fully type checked.
        if dominance.idom[block].is_none() {
            return Ok(());
        }
        if (from == block && definition.position >= position) || !dominance.dominates(from, block) {
            return Err(fail(
                context,
                format!("SSA value {id} does not dominate its use"),
            ));
        }
        Ok(())
    }
}

pub(crate) fn instruction_operands(operation: &Operation) -> Vec<&Operand> {
    match operation {
        Operation::Assume { condition } => vec![condition],
        Operation::Lifetime { pointer, .. } => vec![pointer],
        Operation::MemorySet {
            destination,
            value,
            length,
            ..
        } => vec![destination, value, length],
        Operation::MemoryCopy {
            destination,
            source,
            length,
            ..
        } => vec![destination, source, length],
        Operation::Binary { lhs, rhs, .. }
        | Operation::IntegerOverflow { lhs, rhs, .. }
        | Operation::IntegerMinMax { lhs, rhs, .. }
        | Operation::ICmp { lhs, rhs, .. } => vec![lhs, rhs],
        Operation::Cast { value, .. } | Operation::Freeze { value } => vec![value],
        Operation::ExtractValue { aggregate, .. } => vec![aggregate],
        Operation::InsertValue {
            aggregate, value, ..
        } => vec![aggregate, value],
        Operation::Select {
            condition,
            on_true,
            on_false,
        } => vec![condition, on_true, on_false],
        Operation::Trap {}
        | Operation::NoAliasScopeDecl { .. }
        | Operation::AtomicFence { .. }
        | Operation::Alloca { .. }
        | Operation::ThreadLocalAddress { .. } => {
            vec![]
        }
        Operation::Gep { base, offset, .. } => vec![base, offset],
        Operation::Load { pointer, .. } | Operation::AtomicLoad { pointer, .. } => vec![pointer],
        Operation::Store { pointer, value, .. }
        | Operation::AtomicStore { pointer, value, .. }
        | Operation::AtomicRmw { pointer, value, .. } => vec![pointer, value],
        Operation::AtomicCompareExchange {
            pointer,
            expected,
            replacement,
            ..
        } => vec![pointer, expected, replacement],
        Operation::Call { callee, args, .. } => std::iter::once(callee).chain(args).collect(),
        Operation::EhTypeId { typeinfo } => vec![typeinfo],
        Operation::LandingPad { clauses, .. } => clauses
            .iter()
            .flat_map(|clause| match clause {
                ExceptionClause::Catch { typeinfo } => vec![typeinfo],
                ExceptionClause::Filter { typeinfos } => typeinfos.iter().collect(),
            })
            .collect(),
        Operation::Phi { .. } => vec![],
    }
}

/// All terminator operands, including the original invoke call and resume
/// aggregate. Invoke SSA results are definitions, not operands.
pub(crate) fn terminator_operands(terminator: &Terminator) -> Vec<&Operand> {
    match terminator {
        Terminator::Return { value } => value.iter().collect(),
        Terminator::Branch { condition, .. } | Terminator::Switch { condition, .. } => {
            vec![condition]
        }
        Terminator::Invoke { callee, args, .. } => std::iter::once(callee).chain(args).collect(),
        Terminator::Resume { value } => vec![value],
        Terminator::Jump { .. } | Terminator::Unreachable => vec![],
    }
}

/// Immediate dominators in reverse-postorder. No quadratic dominance bitset
/// and no recursive DFS stack: large frontend CFGs remain ordinary inputs.
struct Dominance {
    idom: Vec<Option<usize>>,
}

impl Dominance {
    fn compute(entry: usize, successors: &[Vec<usize>], predecessors: &[BTreeSet<usize>]) -> Self {
        let mut seen = vec![false; successors.len()];
        let mut postorder = Vec::new();
        let mut stack = vec![(entry, 0_usize)];
        seen[entry] = true;
        while let Some((node, cursor)) = stack.last_mut() {
            if *cursor < successors[*node].len() {
                let next = successors[*node][*cursor];
                *cursor += 1;
                if !seen[next] {
                    seen[next] = true;
                    stack.push((next, 0));
                }
            } else {
                postorder.push(*node);
                stack.pop();
            }
        }
        postorder.reverse();
        let mut order = vec![usize::MAX; successors.len()];
        for (index, block) in postorder.iter().enumerate() {
            order[*block] = index;
        }
        let mut idom = vec![None; successors.len()];
        idom[entry] = Some(entry);
        let mut changed = true;
        while changed {
            changed = false;
            for block in postorder.iter().copied().skip(1) {
                let mut candidates = predecessors[block]
                    .iter()
                    .copied()
                    .filter(|p| idom[*p].is_some());
                let Some(mut parent) = candidates.next() else {
                    continue;
                };
                for mut candidate in candidates {
                    while parent != candidate {
                        while order[parent] > order[candidate] {
                            parent = idom[parent].unwrap();
                        }
                        while order[candidate] > order[parent] {
                            candidate = idom[candidate].unwrap();
                        }
                    }
                }
                if idom[block] != Some(parent) {
                    idom[block] = Some(parent);
                    changed = true;
                }
            }
        }
        Self { idom }
    }

    fn intervals(&self) -> (Vec<Option<usize>>, Vec<usize>) {
        let mut children = vec![Vec::new(); self.idom.len()];
        let mut entry = None;
        for (node, parent) in self.idom.iter().enumerate() {
            if let Some(parent) = parent {
                if *parent == node {
                    entry = Some(node);
                } else {
                    children[*parent].push(node);
                }
            }
        }
        let mut preorder = vec![None; self.idom.len()];
        let mut end = vec![0; self.idom.len()];
        let mut clock = 0;
        let mut stack = entry
            .into_iter()
            .map(|node| (node, false))
            .collect::<Vec<_>>();
        while let Some((node, leaving)) = stack.pop() {
            if leaving {
                end[node] = clock;
            } else {
                preorder[node] = Some(clock);
                clock += 1;
                stack.push((node, true));
                stack.extend(children[node].iter().rev().map(|node| (*node, false)));
            }
        }
        (preorder, end)
    }

    fn dominates(&self, definition: usize, mut block: usize) -> bool {
        loop {
            if definition == block {
                return self.idom[block].is_some();
            }
            let Some(parent) = self.idom[block] else {
                return false;
            };
            if parent == block {
                return false;
            }
            block = parent;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn value(id: usize) -> Operand {
        Operand::Value { id }
    }
    fn integer(ty: usize, bits: u64) -> Operand {
        Operand::Int {
            ty,
            bits: bits.to_string(),
        }
    }

    fn module() -> NativeModule {
        serde_json::from_value(json!({
            "format": FORMAT, "name": "test",
            "target": { "triple": "x86_64-unknown-linux-gnu", "data_layout": "e-p:64:64-i64:64-i128:128-f80:128", "pointer_bits": 64, "little_endian": true },
            "semantics": "llvm_defined_behavior_v1",
            "types": [ {"kind":"void"}, {"kind":"int","bits":1}, {"kind":"int","bits":64}, {"kind":"pointer","address_space":0}, {"kind":"int","bits":8} ],
            "globals": [],
            "functions": [{
                "name":"choose", "linkage":"external",
                "signature":{"params":[2],"result":2,"abi":"c","variadic":false},
                "params":[{"id":7,"ty":2}], "entry":10,
                "blocks":[
                    {"id":10,"instructions":[{"result":{"id":8,"ty":1},"operation":{"op":"i_cmp","predicate":"eq","lhs":{"kind":"value","id":7},"rhs":{"kind":"int","ty":2,"bits":"0"}}}],"terminator":{"op":"branch","condition":{"kind":"value","id":8},"on_true":20,"on_false":30}},
                    {"id":20,"instructions":[{"result":{"id":20,"ty":2},"operation":{"op":"binary","kind":"add","lhs":{"kind":"value","id":7},"rhs":{"kind":"int","ty":2,"bits":"1"},"flags":["nsw"]}}],"terminator":{"op":"jump","target":40}},
                    {"id":30,"instructions":[{"result":{"id":30,"ty":2},"operation":{"op":"binary","kind":"sub","lhs":{"kind":"value","id":7},"rhs":{"kind":"int","ty":2,"bits":"1"},"flags":[]}}],"terminator":{"op":"jump","target":40}},
                    {"id":40,"instructions":[{"result":{"id":40,"ty":2},"operation":{"op":"phi","incoming":[{"block":20,"value":{"kind":"value","id":20}},{"block":30,"value":{"kind":"value","id":30}}]}}],"terminator":{"op":"return","value":{"kind":"value","id":40}}}
                ]
            }],
            "provenance": {"input_sha256":"0000000000000000000000000000000000000000000000000000000000000000","frontend":"test","frontend_version":"1","importer":"test","importer_version":"1","source_function_count":1,"source_global_count":0,"refinements":[]}
        })).unwrap()
    }

    fn rejects(module: &NativeModule, text: &str) {
        let error = verify(module).expect_err("invalid native module was accepted");
        assert!(
            error.message.contains(text),
            "expected {text:?}, got {}",
            error.message
        );
    }

    fn global(module: &mut NativeModule) {
        module.globals.push(Global {
            name: "slot".into(),
            ty: 2,
            linkage: "external".into(),
            visibility: Visibility::Default,
            comdat: None,
            alignment: 0,
            constant: false,
            thread_local: false,
            tls_model: None,
            initializer: Some(Initializer {
                bytes: vec![0; 8],
                relocations: vec![],
            }),
        });
        module.provenance.source_global_count += 1;
    }

    #[test]
    fn symbolic_pointer_offsets_keep_the_named_dependency_and_exact_signed_bits() {
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "riscv64-unknown-linux-gnu",
        ] {
            for addend in [0, 16, -16, i64::MIN, i64::MAX] {
                let mut m = module();
                m.target.triple = target.into();
                global(&mut m);
                let function = &mut m.functions[0];
                function.signature.params.clear();
                function.signature.result = 3;
                function.params.clear();
                function.blocks = vec![Block {
                    id: 10,
                    instructions: vec![],
                    terminator: Terminator::Return {
                        value: Some(Operand::SymbolOffset {
                            ty: 3,
                            name: "slot".into(),
                            addend,
                        }),
                    },
                }];
                verify(&m).unwrap();
                let encoded = m.to_json().unwrap();
                let restored = NativeModule::from_json(&encoded).unwrap();
                assert!(matches!(&restored.functions[0].blocks[0].terminator,
                    Terminator::Return { value: Some(Operand::SymbolOffset { ty: 3, name, addend: actual }) } if name == "slot" && *actual == addend));
                verify(&restored).unwrap();
                let mut invalid = restored.clone();
                let Terminator::Return {
                    value: Some(Operand::SymbolOffset { name, .. }),
                } = &mut invalid.functions[0].blocks[0].terminator
                else {
                    unreachable!()
                };
                *name = "missing".into();
                rejects(&invalid, "unknown symbol");
                let mut invalid = restored.clone();
                let Terminator::Return {
                    value: Some(Operand::SymbolOffset { ty, .. }),
                } = &mut invalid.functions[0].blocks[0].terminator
                else {
                    unreachable!()
                };
                *ty = 2;
                rejects(&invalid, "symbol offset requires");
                let mut invalid = restored;
                invalid.target.data_layout.push_str("-ni:1");
                rejects(&invalid, "symbol offset requires");
            }
        }
    }

    fn grouped_alias_module() -> NativeModule {
        let mut m = alias_module();
        let function_group = m.functions[0].name.clone();
        m.comdats = vec![
            Comdat {
                name: function_group.clone(),
                selection: ComdatSelection::Any,
            },
            Comdat {
                name: "cold.pointer.table".into(),
                selection: ComdatSelection::NoDeduplicate,
            },
        ];
        m.provenance.referenced_comdat_count = m.comdats.len();
        m.functions[0].comdat = Some(function_group.clone());
        m.globals[0].comdat = Some(function_group);
        m.globals[2].comdat = Some("cold.pointer.table".into());
        m
    }

    #[test]
    fn comdat_groups_preserve_mixed_members_alias_identity_and_all_three_roundtrips() {
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "riscv64-unknown-linux-gnu",
        ] {
            for selection in [ComdatSelection::Any, ComdatSelection::NoDeduplicate] {
                let mut m = grouped_alias_module();
                m.target.triple = target.into();
                m.comdats[0].selection = selection;
                m.functions[0].linkage = "weak_odr".into();
                m.functions[0].visibility = Visibility::Hidden;
                m.functions[0].alignment = 64;
                m.globals[0].linkage = "internal".into();
                m.aliases[0].linkage = "linkonce_odr".into();
                verify(&m).unwrap();
                let roundtrip = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
                assert_eq!(roundtrip.comdats[0].selection, selection);
                assert_eq!(roundtrip.provenance.referenced_comdat_count, 2);
                assert_eq!(roundtrip.functions[0].comdat, roundtrip.globals[0].comdat);
                assert_eq!(roundtrip.functions[0].linkage, "weak_odr");
                assert_eq!(roundtrip.functions[0].visibility, Visibility::Hidden);
                assert_eq!(roundtrip.functions[0].alignment, 64);
                assert_eq!(roundtrip.aliases[0].aliasee, roundtrip.functions[0].name);
                assert_eq!(roundtrip.aliases[0].linkage, "linkonce_odr");
                assert_eq!(
                    roundtrip.globals[2]
                        .initializer
                        .as_ref()
                        .unwrap()
                        .relocations[0]
                        .symbol,
                    "function_alias"
                );
                assert_eq!(
                    roundtrip.globals[2]
                        .initializer
                        .as_ref()
                        .unwrap()
                        .relocations[1]
                        .symbol,
                    "pointer_alias"
                );
                assert_ne!(roundtrip.functions[0].comdat, roundtrip.globals[2].comdat);
            }
        }
    }

    #[test]
    fn comdat_inventory_names_and_members_must_be_complete_and_unambiguous() {
        let m = grouped_alias_module();
        let mut invalid = m.clone();
        invalid.provenance.referenced_comdat_count -= 1;
        rejects(&invalid, "source declaration/definition inventory");
        let mut invalid = m.clone();
        invalid.comdats.push(invalid.comdats[0].clone());
        invalid.provenance.referenced_comdat_count += 1;
        rejects(&invalid, "duplicate COMDAT group name");
        for name in [
            "",
            "bad,group",
            "bad\n.section.inject",
            "bad group",
            "bad\0group",
        ] {
            let mut invalid = m.clone();
            invalid.comdats[0].name = name.into();
            rejects(&invalid, "assembler-safe spelling");
        }
        for function in [false, true] {
            let mut invalid = m.clone();
            if function {
                invalid.functions[0].comdat = Some("missing".into());
            } else {
                invalid.globals[0].comdat = Some("missing".into());
            }
            rejects(&invalid, "unknown COMDAT group");
        }
        let mut invalid = m.clone();
        invalid.comdats.push(Comdat {
            name: "only.nonexecutable.declaration".into(),
            selection: ComdatSelection::Any,
        });
        invalid.provenance.referenced_comdat_count += 1;
        rejects(&invalid, "referenced COMDAT has no defined members");
        // A signature name shares the symbol namespace only by spelling, not
        // as an extra function/global/alias declaration.
        assert_eq!(m.comdats[0].name, m.functions[0].name);
        verify(&m).unwrap();
    }

    #[test]
    fn unsupported_comdat_selection_rejects_even_cold_members_before_emission() {
        for selection in [
            ComdatSelection::ExactMatch,
            ComdatSelection::Largest,
            ComdatSelection::SameSize,
        ] {
            let mut invalid = grouped_alias_module();
            // This group contains only static pointer storage. Selection still
            // changes whole-object behavior and cannot be silently erased.
            invalid.comdats[1].selection = selection;
            rejects(&invalid, "ELF COMDAT supports only any and no_deduplicate");
        }
        let mut invalid = serde_json::to_value(grouped_alias_module()).unwrap();
        invalid["comdats"][1]["selection"] = json!("future_unknown_selection");
        assert!(serde_json::from_value::<NativeModule>(invalid).is_err());
    }

    #[test]
    fn comdat_members_cannot_be_declarations_nonemitted_common_tls_or_intrinsics() {
        for function in [false, true] {
            for declaration in [false, true] {
                let mut invalid = grouped_alias_module();
                if function {
                    if declaration {
                        invalid.functions[0].entry = None;
                        invalid.functions[0].blocks.clear();
                    } else {
                        invalid.functions[0].linkage = "available_externally".into();
                    }
                } else if declaration {
                    invalid.globals[0].initializer = None;
                } else {
                    invalid.globals[0].linkage = "available_externally".into();
                }
                rejects(&invalid, "COMDAT member must be an emitted definition");
            }
        }
        let mut invalid = grouped_alias_module();
        invalid.globals[0].linkage = "common".into();
        rejects(&invalid, "common global cannot be a COMDAT member");
        let mut invalid = grouped_alias_module();
        invalid.globals[0].thread_local = true;
        rejects(
            &invalid,
            "TLS COMDAT members require explicit storage/model lowering",
        );
        let mut invalid = grouped_alias_module();
        let mut intrinsic = builtin("llvm.assume", &[1]);
        intrinsic.comdat = invalid.functions[0].comdat.clone();
        invalid.functions.push(intrinsic);
        invalid.provenance.source_function_count += 1;
        rejects(&invalid, "intrinsic cannot be a COMDAT member");
    }

    #[test]
    fn grouped_odr_linkages_retain_definition_bodies_and_never_synthesize_declarations() {
        for family in ["linkonce", "linkonce_odr", "weak_odr"] {
            let mut m = grouped_alias_module();
            m.functions[0].linkage = family.into();
            m.globals[0].linkage = family.into();
            m.aliases[0].linkage = family.into();
            verify(&m).unwrap();
            for function in [false, true] {
                let mut invalid = m.clone();
                invalid.aliases.clear();
                invalid.provenance.source_alias_count = 0;
                // Remove referencing table and caller to isolate the original
                // linkage/definition contract, rather than a dangling alias.
                invalid.globals.truncate(2);
                invalid.provenance.source_global_count = 2;
                invalid.functions.truncate(1);
                invalid.provenance.source_function_count = 1;
                invalid.comdats.truncate(1);
                invalid.provenance.referenced_comdat_count = 1;
                if function {
                    invalid.functions[0].entry = None;
                    invalid.functions[0].blocks.clear();
                    invalid.functions[0].comdat = None;
                } else {
                    invalid.globals[0].initializer = None;
                    invalid.globals[0].comdat = None;
                }
                rejects(&invalid, "invalid linkage");
            }
        }
        // Private members are legal on ELF; LLVM's private-signature
        // restriction applies to COFF, whose selection kinds stay unsupported.
        let mut m = grouped_alias_module();
        m.functions[0].linkage = "private".into();
        m.globals[0].linkage = "private".into();
        verify(&m).unwrap();
    }

    #[test]
    fn comdat_alias_membership_is_inherited_and_unencoded_contracts_fail_closed() {
        let m = grouped_alias_module();
        for field in ["comdat", "section", "partition", "tls_model"] {
            let mut invalid = serde_json::to_value(&m).unwrap();
            invalid["aliases"][0][field] = json!("independent.alias.group");
            assert!(
                serde_json::from_value::<NativeModule>(invalid).is_err(),
                "alias field {field}"
            );
        }
        let mut invalid = serde_json::to_value(&m).unwrap();
        invalid["functions"][0]["comdat"] = json!([m.comdats[0].name, m.comdats[1].name]);
        assert!(serde_json::from_value::<NativeModule>(invalid).is_err());
        let mut invalid = serde_json::to_value(&m).unwrap();
        invalid["comdats"][0]["members"] = json!([]);
        assert!(serde_json::from_value::<NativeModule>(invalid).is_err());
        let mut invalid = serde_json::to_value(&m).unwrap();
        invalid["provenance"]["source_comdat_count"] = json!(2);
        assert!(serde_json::from_value::<NativeModule>(invalid).is_err());
    }

    fn pointer_bits(bits: impl std::fmt::Display) -> Operand {
        Operand::PointerBits {
            ty: 3,
            bits: bits.to_string(),
        }
    }

    fn pointer_comparison(bits: impl std::fmt::Display) -> NativeModule {
        let mut m = module();
        m.functions[0].blocks[0].instructions[0].operation = Operation::ICmp {
            predicate: IntPredicate::Eq,
            lhs: Operand::Null { ty: 3 },
            rhs: pointer_bits(bits),
        };
        m
    }

    #[test]
    fn literal_pointer_bits_preserve_the_complete_unsigned_address_and_json_identity() {
        for triple in [
            "x86_64-unknown-none",
            "aarch64-unknown-none",
            "riscv64-unknown-none",
        ] {
            for layout in [
                "e-i64:64",
                "e-p:64:64-i64:64",
                "e-p0:64:64:64:64-i64:64-A0-P0-G0",
                "e-p0:00064:64:64:00064-p270:32:32-i64:64",
            ] {
                for bits in [
                    "0",
                    "1",
                    "255",
                    "9223372036854775807",
                    "9223372036854775808",
                    "18446744073709551615",
                    "000255",
                ] {
                    let mut m = pointer_comparison(bits);
                    m.target.triple = triple.into();
                    m.target.data_layout = layout.into();
                    let bytes = m.to_json().unwrap();
                    let encoded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(
                        encoded["functions"][0]["blocks"][0]["instructions"][0]["operation"]["rhs"],
                        json!({"kind":"pointer_bits", "ty":3, "bits":bits})
                    );
                    let decoded = NativeModule::from_json(&bytes).unwrap();
                    assert!(
                        matches!(&decoded.functions[0].blocks[0].instructions[0].operation,
                        Operation::ICmp { rhs: Operand::PointerBits { ty: 3, bits: actual }, .. } if actual == bits)
                    );
                    assert!(decoded.globals.is_empty());
                    assert_eq!(decoded.functions[0].name, "choose");
                }
            }
        }
        // A long spelling of the same legal address is not a graph/resource cap.
        verify(&pointer_comparison(format!("{}1", "0".repeat(65536)))).unwrap();
    }

    #[test]
    fn literal_pointer_bits_reject_non_decimal_overflow_and_non_pointer_types() {
        for bits in [
            "",
            "-1",
            "+1",
            " 1",
            "1 ",
            "0x1",
            "1.0",
            "1e2",
            "١",
            "1\n",
            "18446744073709551616",
            "999999999999999999999999",
        ] {
            let m = pointer_comparison(bits);
            rejects(
                &m,
                if bits.bytes().all(|b| b.is_ascii_digit()) && !bits.is_empty() {
                    "64-bit address width"
                } else {
                    "unsigned decimal"
                },
            );
        }
        for ty in [0, 1, 2, 4, usize::MAX] {
            let mut m = pointer_comparison(1);
            let Operation::ICmp { rhs, .. } =
                &mut m.functions[0].blocks[0].instructions[0].operation
            else {
                unreachable!()
            };
            *rhs = Operand::PointerBits {
                ty,
                bits: "1".into(),
            };
            rejects(
                &m,
                if ty == usize::MAX {
                    "out of bounds"
                } else {
                    "address-space-zero pointer type"
                },
            );
        }
        let mut m = pointer_comparison(1);
        m.types[3] = Type::Pointer { address_space: 1 };
        rejects(&m, "address-space-zero pointer type");
    }

    #[test]
    fn literal_pointer_bits_require_the_admitted_integral_64_bit_target_profile() {
        for layout in [
            "e-p:32:32",
            "e-p:64:64:64:32",
            "e-p:64:64-ni:1",
            "e-p:64:64-A1",
            "e-p:64:64-P1",
            "e-p:64:64-G1",
        ] {
            let mut m = pointer_comparison(1);
            m.target.data_layout = layout.into();
            if layout == "e-p:32:32" {
                m.target.pointer_bits = 32;
            }
            rejects(
                &m,
                "integral AS0 little-endian 64-bit pointer/index profile",
            );
        }
        let mut m = pointer_comparison(1);
        m.target.little_endian = false;
        m.target.data_layout = "E-p:64:64".into();
        rejects(
            &m,
            "integral AS0 little-endian 64-bit pointer/index profile",
        );
        for layout in ["e-pe:64:64", "e-pu0:64:64", "e-ni:0", "e-p:64:64:64:65"] {
            let mut m = pointer_comparison(1);
            m.target.data_layout = layout.into();
            assert!(
                verify(&m).is_err(),
                "invalid integral-pointer layout {layout} was accepted"
            );
        }
    }

    fn pointer_uses() -> NativeModule {
        let mut m = module();
        global(&mut m);
        let f = &mut m.functions[0];
        f.signature.params = vec![3];
        f.signature.result = 3;
        f.params[0].ty = 3;
        f.blocks[0].instructions = vec![
            Instruction {
                result: Some(Value { id: 8, ty: 1 }),
                operation: Operation::ICmp {
                    predicate: IntPredicate::Eq,
                    lhs: value(7),
                    rhs: pointer_bits(0),
                },
            },
            Instruction {
                result: Some(Value { id: 9, ty: 3 }),
                operation: Operation::Select {
                    condition: value(8),
                    on_true: pointer_bits(u64::MAX),
                    on_false: Operand::Symbol {
                        ty: 3,
                        name: "slot".into(),
                    },
                },
            },
            Instruction {
                result: Some(Value { id: 11, ty: 3 }),
                operation: Operation::Freeze {
                    value: pointer_bits(1),
                },
            },
            Instruction {
                result: Some(Value { id: 12, ty: 3 }),
                operation: Operation::Gep {
                    base: pointer_bits(2),
                    offset: integer(2, 0),
                    inbounds: false,
                },
            },
            Instruction {
                result: Some(Value { id: 13, ty: 2 }),
                operation: Operation::Cast {
                    kind: CastOp::PtrToInt,
                    value: pointer_bits(255),
                },
            },
            Instruction {
                result: Some(Value { id: 14, ty: 2 }),
                operation: Operation::Load {
                    pointer: pointer_bits(4096),
                    alignment: 1,
                    volatile: false,
                },
            },
            Instruction {
                result: None,
                operation: Operation::Store {
                    pointer: pointer_bits(4096),
                    value: pointer_bits(2000),
                    alignment: 1,
                    volatile: false,
                },
            },
            Instruction {
                result: Some(Value { id: 15, ty: 3 }),
                operation: Operation::Call {
                    callee: pointer_bits(4096),
                    signature: Signature {
                        params: vec![3],
                        result: 3,
                        abi: "c".into(),
                        variadic: false,
                        param_attributes: vec![],
                        result_attributes: vec![],
                        return_storage: None,
                    },
                    args: vec![pointer_bits(2000)],
                },
            },
            Instruction {
                result: Some(Value { id: 16, ty: 3 }),
                operation: Operation::Call {
                    callee: Operand::Symbol {
                        ty: 3,
                        name: "choose".into(),
                    },
                    signature: f.signature.clone(),
                    args: vec![pointer_bits(77)],
                },
            },
        ];
        f.blocks[1].instructions.clear();
        f.blocks[2].instructions.clear();
        f.blocks[3].instructions[0].result.as_mut().unwrap().ty = 3;
        f.blocks[3].instructions[0].operation = Operation::Phi {
            incoming: vec![
                PhiIncoming {
                    block: 20,
                    value: pointer_bits(1),
                },
                PhiIncoming {
                    block: 30,
                    value: pointer_bits(2),
                },
            ],
        };
        m
    }

    #[test]
    fn literal_pointer_bits_are_verified_in_every_operand_position_without_becoming_symbols() {
        let m = pointer_uses();
        let encoded: serde_json::Value = serde_json::from_slice(&m.to_json().unwrap()).unwrap();
        fn paths(value: &serde_json::Value, path: &str, output: &mut Vec<String>) {
            if value.get("kind").and_then(serde_json::Value::as_str) == Some("pointer_bits") {
                output.push(path.into());
                return;
            }
            match value {
                serde_json::Value::Object(fields) => {
                    for (key, value) in fields {
                        paths(value, &format!("{path}/{key}"), output);
                    }
                }
                serde_json::Value::Array(values) => {
                    for (index, value) in values.iter().enumerate() {
                        paths(value, &format!("{path}/{index}"), output);
                    }
                }
                _ => {}
            }
        }
        let mut locations = vec![];
        paths(&encoded, "", &mut locations);
        assert_eq!(locations.len(), 13);
        for location in locations {
            let mut corrupted = encoded.clone();
            corrupted.pointer_mut(&location).unwrap()["bits"] = json!("18446744073709551616");
            let error =
                NativeModule::from_json(&serde_json::to_vec(&corrupted).unwrap()).unwrap_err();
            assert!(
                error.message.contains("64-bit address width"),
                "{location}: {}",
                error.message
            );
        }
        assert!(m.globals[0]
            .initializer
            .as_ref()
            .unwrap()
            .relocations
            .is_empty());
        assert_eq!(
            encoded["functions"][0]["blocks"][0]["instructions"][1]["operation"]["on_false"],
            json!({"kind":"symbol", "ty":3, "name":"slot"})
        );
        assert_eq!(
            encoded["functions"][0]["blocks"][0]["instructions"][3]["operation"]["offset"]["kind"],
            "int"
        );
        assert_eq!(
            encoded["functions"][0]["blocks"][0]["instructions"][8]["operation"]["callee"]["kind"],
            "symbol"
        );
    }

    #[test]
    fn literal_pointer_bits_do_not_hide_ssa_dominance_or_phi_predecessor_errors() {
        let mut m = pointer_uses();
        m.functions[0].blocks[1].instructions.push(Instruction {
            result: Some(Value { id: 25, ty: 3 }),
            operation: Operation::Freeze {
                value: pointer_bits(1),
            },
        });
        m.functions[0].blocks[2].instructions.push(Instruction {
            result: Some(Value { id: 35, ty: 3 }),
            operation: Operation::Freeze { value: value(25) },
        });
        rejects(&m, "does not dominate");
        let mut m = pointer_uses();
        let Operation::Phi { incoming } = &mut m.functions[0].blocks[3].instructions[0].operation
        else {
            unreachable!()
        };
        incoming[0].block = 10;
        rejects(&m, "predecessor");
    }

    #[test]
    fn literal_pointer_bits_unknown_fields_and_non_string_bits_are_rejected() {
        let encoded = serde_json::to_value(pointer_comparison(1)).unwrap();
        for field in [
            "name",
            "symbol",
            "addend",
            "relocation",
            "alignment",
            "address_space",
        ] {
            let mut m = encoded.clone();
            m["functions"][0]["blocks"][0]["instructions"][0]["operation"]["rhs"][field] = json!(0);
            assert!(NativeModule::from_json(&serde_json::to_vec(&m).unwrap())
                .unwrap_err()
                .message
                .contains("unknown field"));
        }
        for bits in [json!(0), json!(null), json!({"address":1})] {
            let mut m = encoded.clone();
            m["functions"][0]["blocks"][0]["instructions"][0]["operation"]["rhs"]["bits"] = bits;
            assert!(NativeModule::from_json(&serde_json::to_vec(&m).unwrap()).is_err());
        }
    }

    #[test]
    fn accepts_sparse_ids_diamond_phi_and_roundtrip() {
        let m = module();
        verify(&m).unwrap();
        let bytes = m.to_json().unwrap();
        let decoded = NativeModule::from_json(&bytes).unwrap();
        assert_eq!(decoded.functions[0].blocks[3].id, 40);
    }

    fn weak_module() -> NativeModule {
        let mut m = module();
        let f = &mut m.functions[0];
        f.name = "ordinary_weak_function".into();
        f.linkage = "weak".into();
        f.signature.params = vec![4];
        f.signature.result = 4;
        f.signature.param_attributes = vec![vec!["zeroext".into()]];
        f.signature.result_attributes = vec!["signext".into()];
        f.params = vec![Value { id: 7, ty: 4 }];
        f.blocks = vec![Block {
            id: 10,
            instructions: vec![],
            terminator: Terminator::Return {
                value: Some(value(7)),
            },
        }];
        global(&mut m);
        m.globals[0].name = "ordinary_weak_pointer".into();
        m.globals[0].ty = 3;
        m.globals[0].linkage = "weak".into();
        m.globals[0].alignment = 8;
        m.globals[0].initializer.as_mut().unwrap().relocations = vec![Relocation {
            offset: 0,
            width: 64,
            symbol: "ordinary_dependency".into(),
            addend: 0,
            relative_to: None,
        }];
        global(&mut m);
        m.globals[1].name = "ordinary_dependency".into();
        m.globals[1].initializer = None;
        m
    }

    fn alias_module() -> NativeModule {
        let mut m = weak_module();
        m.functions[0].name = "original_function".into();
        m.functions[0].linkage = "external".into();
        m.globals[0].name = "original_pointer".into();
        m.globals[0].linkage = "external".into();
        // The bare LLVM function value type has no signext/zeroext attributes;
        // the original function and every direct call retain their own ABI.
        let mut bare = m.functions[0].signature.clone();
        bare.param_attributes.clear();
        bare.result_attributes.clear();
        let function_type = m.types.len();
        m.types.push(Type::Function { signature: bare });
        m.aliases = vec![
            Alias {
                name: "function_alias".into(),
                ty: function_type,
                aliasee: "original_function".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
            },
            Alias {
                name: "pointer_alias".into(),
                ty: 3,
                aliasee: "original_pointer".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
            },
        ];
        m.provenance.source_alias_count = m.aliases.len();
        let mut caller = m.functions[0].clone();
        caller.name = "call_alias".into();
        caller.blocks[0].instructions = vec![Instruction {
            result: Some(Value { id: 8, ty: 4 }),
            operation: Operation::Call {
                callee: Operand::Symbol {
                    ty: 3,
                    name: "function_alias".into(),
                },
                signature: caller.signature.clone(),
                args: vec![value(7)],
            },
        }];
        caller.blocks[0].terminator = Terminator::Return {
            value: Some(value(8)),
        };
        m.functions.push(caller);
        m.provenance.source_function_count += 1;
        let table_type = m.types.len();
        m.types.push(Type::Array { element: 3, len: 2 });
        m.globals.push(Global {
            name: "alias_addresses".into(),
            ty: table_type,
            linkage: "external".into(),
            visibility: Visibility::Default,
            comdat: None,
            alignment: 8,
            constant: true,
            thread_local: false,
            tls_model: None,
            initializer: Some(Initializer {
                bytes: vec![0; 16],
                relocations: vec![
                    Relocation {
                        offset: 0,
                        width: 64,
                        symbol: "function_alias".into(),
                        addend: 0,
                        relative_to: None,
                    },
                    Relocation {
                        offset: 8,
                        width: 64,
                        symbol: "pointer_alias".into(),
                        addend: 0,
                        relative_to: None,
                    },
                ],
            }),
        });
        m.provenance.source_global_count += 1;
        m
    }

    #[test]
    fn direct_aliases_keep_source_identity_types_calls_relocations_and_inventory() {
        for target in [
            "x86_64-unknown-none",
            "aarch64-unknown-none",
            "riscv64-unknown-none-elf",
        ] {
            for linkage in [
                "external",
                "private",
                "internal",
                "weak",
                "linkonce",
                "linkonce_odr",
                "weak_odr",
            ] {
                for visible in [
                    Visibility::Default,
                    Visibility::Hidden,
                    Visibility::Protected,
                ] {
                    if matches!(linkage, "private" | "internal") && visible != Visibility::Default {
                        continue;
                    }
                    let mut m = alias_module();
                    m.target.triple = target.into();
                    for alias in &mut m.aliases {
                        alias.linkage = linkage.into();
                        alias.visibility = visible;
                    }
                    verify(&m).unwrap();
                    let bytes = m.to_json().unwrap();
                    let restored = NativeModule::from_json(&bytes).unwrap();
                    assert_eq!(
                        serde_json::to_value(&m).unwrap(),
                        serde_json::to_value(&restored).unwrap()
                    );
                    assert_eq!(restored.functions.len(), 2);
                    assert_eq!(restored.globals.len(), 3);
                    assert_eq!(restored.aliases.len(), 2);
                    assert_eq!(restored.provenance.source_alias_count, 2);
                    assert_eq!(restored.functions[0].name, "original_function");
                    assert_eq!(restored.aliases[0].aliasee, "original_function");
                    let Operation::Call {
                        callee, signature, ..
                    } = &restored.functions[1].blocks[0].instructions[0].operation
                    else {
                        unreachable!()
                    };
                    assert!(
                        matches!(callee, Operand::Symbol { name, .. } if name == "function_alias")
                    );
                    assert!(signatures_equal(
                        signature,
                        &restored.functions[0].signature
                    ));
                    let relocations = &restored.globals[2]
                        .initializer
                        .as_ref()
                        .unwrap()
                        .relocations;
                    assert_eq!(relocations[0].symbol, "function_alias");
                    assert_eq!(relocations[1].symbol, "pointer_alias");
                    assert_eq!(type_size(&restored, restored.aliases[1].ty).unwrap(), 8);
                }
            }
        }
    }

    #[test]
    fn aliases_require_complete_inventory_unique_safe_names_and_real_roots() {
        let mut invalid = alias_module();
        invalid.provenance.source_alias_count -= 1;
        rejects(&invalid, "inventory does not match");
        let mut encoded = serde_json::to_value(alias_module()).unwrap();
        encoded["provenance"]
            .as_object_mut()
            .unwrap()
            .remove("source_alias_count");
        assert!(
            NativeModule::from_json(&serde_json::to_vec(&encoded).unwrap())
                .unwrap_err()
                .message
                .contains("inventory does not match")
        );
        let mut legacy = serde_json::to_value(module()).unwrap();
        legacy.as_object_mut().unwrap().remove("aliases");
        legacy["provenance"]
            .as_object_mut()
            .unwrap()
            .remove("source_alias_count");
        let restored = NativeModule::from_json(&serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(restored.aliases.is_empty());
        assert_eq!(restored.provenance.source_alias_count, 0);

        for name in ["original_function", "original_pointer", "pointer_alias"] {
            let mut invalid = alias_module();
            invalid.aliases[0].name = name.into();
            rejects(&invalid, "duplicate alias/global/function symbol");
        }
        for (field, name) in [
            ("name", "bad\n.text"),
            ("aliasee", "original_function\nret"),
        ] {
            let mut invalid = serde_json::to_value(alias_module()).unwrap();
            invalid["aliases"][0][field] = json!(name);
            assert!(
                NativeModule::from_json(&serde_json::to_vec(&invalid).unwrap())
                    .unwrap_err()
                    .message
                    .contains("assembler-safe spelling")
            );
        }
        let mut invalid = alias_module();
        invalid.aliases[0].aliasee = "missing_symbol".into();
        rejects(&invalid, "unknown same-module symbol");
        let mut invalid = alias_module();
        invalid.functions[0].entry = None;
        invalid.functions[0].blocks.clear();
        rejects(&invalid, "alias target must be an emitted definition");
        let mut invalid = alias_module();
        invalid.aliases[1].aliasee = "ordinary_dependency".into();
        rejects(&invalid, "alias target must be an emitted definition");
        let mut invalid = alias_module();
        invalid.functions[0].intrinsic = Some("llvm.assume".into());
        rejects(&invalid, "alias cannot reference an intrinsic address");
        for function in [false, true] {
            let mut invalid = alias_module();
            if function {
                invalid.functions[0].linkage = "available_externally".into();
            } else {
                invalid.globals[0].linkage = "available_externally".into();
            }
            rejects(&invalid, "alias target must be an emitted definition");
        }
    }

    #[test]
    fn alias_value_types_require_the_exact_root_function_or_storage_type() {
        for ty in [usize::MAX, 0, 2, 3] {
            let mut invalid = alias_module();
            invalid.aliases[0].ty = ty;
            assert!(verify(&invalid).is_err());
        }
        for part in ["result", "parameter", "count", "variadic"] {
            let mut invalid = alias_module();
            let Type::Function { signature } = &mut invalid.types[5] else {
                unreachable!()
            };
            match part {
                "result" => signature.result = 2,
                "parameter" => signature.params[0] = 2,
                "count" => signature.params.push(4),
                "variadic" => signature.variadic = true,
                _ => unreachable!(),
            }
            assert!(verify(&invalid).is_err(), "mismatched {part} was accepted");
        }
        let mut invalid = alias_module();
        invalid.aliases[1].ty = 2; // i64 and ptr share size, not a value type.
        rejects(&invalid, "type mismatch");
        let mut invalid = alias_module();
        invalid.aliases[1].ty = invalid.types.len();
        invalid.types.push(Type::Array { element: 4, len: 8 });
        rejects(&invalid, "type mismatch");
        let mut invalid = alias_module();
        invalid.aliases[0].aliasee = "original_pointer".into();
        rejects(&invalid, "type mismatch");
        let mut invalid = alias_module();
        invalid.aliases[1].aliasee = "original_function".into();
        rejects(&invalid, "function alias requires a function value type");
    }

    #[test]
    fn alias_calls_still_require_the_original_functions_complete_abi_contract() {
        for mismatch in ["parameter", "result", "convention"] {
            let mut invalid = alias_module();
            let Operation::Call { signature, .. } =
                &mut invalid.functions[1].blocks[0].instructions[0].operation
            else {
                unreachable!()
            };
            match mismatch {
                "parameter" => signature.param_attributes.clear(),
                "result" => signature.result_attributes.clear(),
                "convention" => signature.abi = "ocore".into(),
                _ => unreachable!(),
            }
            rejects(&invalid, "direct callee symbol/signature mismatch");
        }
        let mut invalid = alias_module();
        let Operation::Call { callee, .. } =
            &mut invalid.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!()
        };
        *callee = Operand::Symbol {
            ty: 3,
            name: "pointer_alias".into(),
        };
        rejects(&invalid, "direct callee symbol/signature mismatch");
        let mut invalid = alias_module();
        invalid.globals[2].initializer.as_mut().unwrap().relocations[0].symbol =
            "missing_alias".into();
        rejects(&invalid, "relocation references unknown symbol");
    }

    #[test]
    fn alias_chains_cycles_tls_and_unencoded_contracts_fail_before_emission() {
        for aliasee in ["function_alias", "pointer_alias"] {
            let mut invalid = alias_module();
            invalid.aliases[0].aliasee = aliasee.into();
            rejects(
                &invalid,
                "alias chains and cycles require explicit lowering",
            );
            invalid.aliases.reverse();
            rejects(
                &invalid,
                "alias chains and cycles require explicit lowering",
            );
        }
        let mut invalid = alias_module();
        invalid.globals[0].thread_local = true;
        rejects(
            &invalid,
            "TLS aliases require explicit storage/model lowering",
        );
        for field in [
            "addend",
            "address_space",
            "thread_local",
            "dll_storage_class",
            "comdat",
            "partition",
            "resolver",
        ] {
            let mut invalid = serde_json::to_value(alias_module()).unwrap();
            invalid["aliases"][0][field] = json!(0);
            assert!(
                NativeModule::from_json(&serde_json::to_vec(&invalid).unwrap())
                    .unwrap_err()
                    .message
                    .contains("unknown field")
            );
        }
        for linkage in [
            "extern_weak",
            "common",
            "appending",
            "available_externally",
            "external_weak",
        ] {
            let mut invalid = alias_module();
            invalid.aliases[0].linkage = linkage.into();
            rejects(&invalid, "unsupported definition-alias linkage");
        }
        for linkage in ["private", "internal"] {
            for visible in [Visibility::Hidden, Visibility::Protected] {
                let mut invalid = alias_module();
                invalid.aliases[0].linkage = linkage.into();
                invalid.aliases[0].visibility = visible;
                rejects(
                    &invalid,
                    "internal/private linkage requires default visibility",
                );
            }
        }
    }

    #[test]
    fn function_alignment_is_retained_for_definitions_and_declarations_on_all_targets() {
        for target in [
            "x86_64-unknown-none",
            "aarch64-unknown-none",
            "riscv64-unknown-none-elf",
        ] {
            for align in [0, 1, 2, 4, 64, 4096, 1_u64 << 32] {
                for declaration in [false, true] {
                    let mut m = module();
                    m.target.triple = target.into();
                    m.functions[0].alignment = align;
                    if declaration {
                        m.functions[0].entry = None;
                        m.functions[0].blocks.clear();
                    }
                    verify(&m).unwrap();
                    let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
                    assert_eq!(restored.functions[0].alignment, align);
                    assert_eq!(restored.functions[0].entry.is_none(), declaration);
                    assert_eq!(
                        serde_json::to_value(&restored).unwrap(),
                        serde_json::to_value(&m).unwrap()
                    );
                }
            }
        }
        let mut encoded = serde_json::to_value(module()).unwrap();
        encoded["functions"][0]
            .as_object_mut()
            .unwrap()
            .remove("alignment");
        let restored = NativeModule::from_json(&serde_json::to_vec(&encoded).unwrap()).unwrap();
        assert_eq!(restored.functions[0].alignment, 0);
    }

    #[test]
    fn malformed_function_alignment_fails_verification_and_json_constructors() {
        for align in [3, 6, 4095, (1_u64 << 32) + 1, u64::MAX] {
            for declaration in [false, true] {
                let mut invalid = module();
                invalid.functions[0].alignment = align;
                if declaration {
                    invalid.functions[0].entry = None;
                    invalid.functions[0].blocks.clear();
                }
                rejects(&invalid, "alignment must be a power of two");
                assert!(invalid.to_json().unwrap_err().message.contains("alignment"));
                let bytes = serde_json::to_vec(&invalid).unwrap();
                assert!(NativeModule::from_json(&bytes)
                    .unwrap_err()
                    .message
                    .contains("alignment"));
            }
        }
    }

    #[test]
    fn weak_real_definitions_retain_body_storage_relocations_abi_and_visibility_in_constructors() {
        for target in [
            "x86_64-unknown-none",
            "aarch64-unknown-none",
            "riscv64-unknown-none",
        ] {
            for style in [
                Visibility::Default,
                Visibility::Hidden,
                Visibility::Protected,
            ] {
                let mut m = weak_module();
                m.target.triple = target.into();
                m.functions[0].visibility = style;
                m.globals[0].visibility = style;
                verify(&m).unwrap();
                let encoded = m.to_json().unwrap();
                let restored = NativeModule::from_json(&encoded).unwrap();
                assert_eq!(
                    serde_json::to_value(&m).unwrap(),
                    serde_json::to_value(&restored).unwrap()
                );
                assert_eq!(restored.functions[0].linkage, "weak");
                assert_eq!(restored.globals[0].linkage, "weak");
                assert_eq!(restored.functions[0].visibility, style);
                assert_eq!(restored.globals[0].visibility, style);
                assert_eq!(restored.functions[0].entry, Some(10));
                assert_eq!(restored.functions[0].blocks.len(), 1);
                assert!(restored.functions[0].intrinsic.is_none());
                assert_eq!(
                    restored.functions[0].signature.param_attributes,
                    vec![vec!["zeroext"]]
                );
                assert_eq!(
                    restored.functions[0].signature.result_attributes,
                    vec!["signext"]
                );
                let initializer = restored.globals[0].initializer.as_ref().unwrap();
                assert_eq!(initializer.bytes, vec![0; 8]);
                assert_eq!(initializer.relocations.len(), 1);
                assert_eq!(initializer.relocations[0].symbol, "ordinary_dependency");
                assert_eq!(initializer.relocations[0].width, 64);
                assert_eq!(type_size(&restored, restored.globals[0].ty).unwrap(), 8);
                assert_eq!(restored.provenance.source_function_count, 1);
                assert_eq!(restored.provenance.source_global_count, 2);
                assert!(restored.globals[1].initializer.is_none());
                assert_eq!(restored.globals[1].linkage, "external");
            }
        }
    }

    #[test]
    fn weak_declarations_are_rejected_by_verification_and_json_constructors() {
        let m = weak_module();
        for category in ["functions", "globals"] {
            let mut invalid = m.clone();
            if category == "functions" {
                invalid.functions[0].entry = None;
                invalid.functions[0].blocks.clear();
            } else {
                invalid.globals[0].initializer = None;
            }
            rejects(&invalid, "weak linkage requires a definition");
            assert!(invalid
                .to_json()
                .unwrap_err()
                .message
                .contains("weak linkage requires a definition"));
            let encoded = serde_json::to_vec(&invalid).unwrap();
            assert!(NativeModule::from_json(&encoded)
                .unwrap_err()
                .message
                .contains("weak linkage requires a definition"));
            if category == "functions" {
                invalid.functions[0].linkage = "external".into();
            } else {
                invalid.globals[0].linkage = "external".into();
            }
            verify(&invalid).unwrap();
        }
    }

    #[test]
    fn weak_definition_marker_does_not_bypass_real_body_storage_or_type_checks() {
        let m = weak_module();
        let mut invalid = m.clone();
        invalid.functions[0].blocks.clear();
        assert!(verify(&invalid).is_err());
        invalid = m.clone();
        invalid.globals[0].initializer.as_mut().unwrap().bytes.pop();
        rejects(&invalid, "initializer byte extent");
        invalid = m.clone();
        invalid.globals[0].initializer.as_mut().unwrap().relocations[0].symbol =
            "missing_dependency".into();
        rejects(&invalid, "relocation references unknown symbol");
        invalid = m.clone();
        invalid.functions[0].params[0].ty = 2;
        rejects(&invalid, "type mismatch");
        invalid = m.clone();
        invalid.functions[0].signature.param_attributes[0] = vec!["byval".into()];
        assert!(verify(&invalid).is_err());
        invalid = m.clone();
        invalid.globals[0].alignment = 3;
        rejects(&invalid, "alignment must be a power of two");
        invalid = m.clone();
        invalid.provenance.source_global_count -= 1;
        assert!(verify(&invalid).is_err());
    }

    #[test]
    fn weak_definition_admission_does_not_create_intrinsics_or_unencoded_comdat_contracts() {
        let mut m = weak_module();
        m.functions[0].intrinsic = Some("llvm.assume".into());
        rejects(&m, "intrinsic declaration");
        let input = serde_json::to_value(weak_module()).unwrap();
        for category in ["functions", "globals"] {
            let mut invalid = input.clone();
            invalid[category][0]["comdat"] = json!("missing-retained-group");
            assert!(
                NativeModule::from_json(&serde_json::to_vec(&invalid).unwrap())
                    .unwrap_err()
                    .message
                    .contains("unknown COMDAT group")
            );
            invalid = input.clone();
            invalid[category][0]["linkage"] = json!("external_weak");
            assert!(NativeModule::from_json(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
    }

    #[test]
    fn visibility_defaults_for_legacy_inputs_and_retains_all_styles_on_roundtrip() {
        let mut m = module();
        global(&mut m);
        let mut legacy = serde_json::to_value(&m).unwrap();
        for category in ["functions", "globals"] {
            legacy[category][0]
                .as_object_mut()
                .unwrap()
                .remove("visibility");
        }
        let restored = NativeModule::from_json(&serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(restored.functions[0].visibility, Visibility::Default);
        assert_eq!(restored.globals[0].visibility, Visibility::Default);
        let styles = [
            (Visibility::Default, "default"),
            (Visibility::Hidden, "hidden"),
            (Visibility::Protected, "protected"),
        ];
        for target in [
            "x86_64-unknown-none",
            "aarch64-unknown-none",
            "riscv64-unknown-none",
        ] {
            for (function_visibility, function_name) in styles {
                for (global_visibility, global_name) in styles {
                    let mut m = restored.clone();
                    m.target.triple = target.into();
                    m.functions[0].visibility = function_visibility;
                    m.globals[0].visibility = global_visibility;
                    let encoded = m.to_json().unwrap();
                    let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
                    assert_eq!(json["functions"][0]["visibility"], function_name);
                    assert_eq!(json["globals"][0]["visibility"], global_name);
                    let roundtrip = NativeModule::from_json(&encoded).unwrap();
                    assert_eq!(roundtrip.functions[0].visibility, function_visibility);
                    assert_eq!(roundtrip.globals[0].visibility, global_visibility);
                    assert_eq!(roundtrip.functions[0].linkage, "external");
                    assert_eq!(roundtrip.globals[0].linkage, "external");
                    assert_eq!(type_size(&roundtrip, roundtrip.globals[0].ty).unwrap(), 8);
                    assert_eq!(roundtrip.provenance.source_function_count, 1);
                    assert_eq!(roundtrip.provenance.source_global_count, 1);
                    assert_eq!(json, serde_json::to_value(&roundtrip).unwrap());
                }
            }
        }
    }

    #[test]
    fn retains_visibility_on_declarations_without_creating_definitions() {
        let mut m = module();
        global(&mut m);
        m.functions[0].entry = None;
        m.functions[0].blocks.clear();
        m.globals[0].initializer = None;
        for style in [
            Visibility::Default,
            Visibility::Hidden,
            Visibility::Protected,
        ] {
            m.functions[0].visibility = style;
            m.globals[0].visibility = style;
            let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
            assert_eq!(restored.functions[0].visibility, style);
            assert_eq!(restored.globals[0].visibility, style);
            assert!(restored.functions[0].entry.is_none());
            assert!(restored.functions[0].blocks.is_empty());
            assert!(restored.globals[0].initializer.is_none());
        }
    }

    #[test]
    fn local_linkage_requires_default_visibility_for_functions_and_globals() {
        let mut m = module();
        global(&mut m);
        for local_linkage in ["internal", "private"] {
            let mut local = m.clone();
            local.functions[0].linkage = local_linkage.into();
            local.globals[0].linkage = local_linkage.into();
            verify(&local).unwrap();
            for style in [Visibility::Hidden, Visibility::Protected] {
                let mut bad_function = local.clone();
                bad_function.functions[0].visibility = style;
                rejects(
                    &bad_function,
                    "internal/private linkage requires default visibility",
                );
                let mut bad_global = local.clone();
                bad_global.globals[0].visibility = style;
                rejects(
                    &bad_global,
                    "internal/private linkage requires default visibility",
                );
            }
        }
    }

    #[test]
    fn rejects_invalid_visibility_and_unencoded_symbol_contracts_without_erasure() {
        let mut m = module();
        global(&mut m);
        let original = serde_json::to_value(&m).unwrap();
        for category in ["functions", "globals"] {
            for bad in [
                json!("internal"),
                json!("public"),
                json!("Hidden"),
                json!(""),
                json!(null),
                json!(2),
                json!({"hidden": true}),
            ] {
                let mut input = original.clone();
                input[category][0]["visibility"] = bad;
                assert!(NativeModule::from_json(&serde_json::to_vec(&input).unwrap()).is_err());
            }
            for field in ["section", "comdat", "dll_storage_class"] {
                let mut input = original.clone();
                input[category][0][field] = json!("unsupported-retained-contract");
                assert!(
                    NativeModule::from_json(&serde_json::to_vec(&input).unwrap())
                        .unwrap_err()
                        .message
                        .contains(if field == "comdat" {
                            "unknown COMDAT group"
                        } else {
                            "unknown field"
                        })
                );
            }
        }
    }

    #[test]
    fn verifies_assumption_contract_and_intrinsic_inventory_without_address_escapes() {
        let mut m = module();
        m.functions[0].blocks[0].instructions.push(Instruction {
            result: None,
            operation: Operation::Assume {
                condition: value(8),
            },
        });
        let declaration: Function = serde_json::from_value(json!({
            "name":"llvm.assume","linkage":"external","intrinsic":"llvm.assume",
            "signature":{"params":[1],"result":0,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":1}],"entry":null,"blocks":[]
        }))
        .unwrap();
        m.functions.push(declaration);
        m.provenance.source_function_count += 1;
        verify(&m).unwrap();
        for style in [Visibility::Hidden, Visibility::Protected] {
            let mut invalid = m.clone();
            invalid.functions[1].visibility = style;
            rejects(&invalid, "intrinsic declaration");
        }
        let mut invalid = m.clone();
        invalid.functions[0].blocks[0].instructions[1].result = Some(Value { id: 9, ty: 1 });
        rejects(&invalid, "assume cannot define");
        invalid = m.clone();
        invalid.functions[0].blocks[0].instructions[1].operation = Operation::Assume {
            condition: value(7),
        };
        rejects(&invalid, "i1");
        invalid = m.clone();
        invalid.functions[1].intrinsic = None;
        rejects(&invalid, "intrinsic declaration");
        invalid = m.clone();
        invalid.functions[1].name = "foreign".into();
        rejects(&invalid, "intrinsic declaration");
        invalid = m.clone();
        invalid.functions[0].blocks[0].instructions[1].operation = Operation::Call {
            callee: Operand::Symbol {
                ty: 3,
                name: "llvm.assume".into(),
            },
            signature: m.functions[1].signature.clone(),
            args: vec![value(8)],
        };
        rejects(&invalid, "intrinsic address");
        invalid = m;
        global(&mut invalid);
        invalid.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .relocations
            .push(Relocation {
                offset: 0,
                width: 64,
                symbol: "llvm.assume".into(),
                addend: 0,
                relative_to: None,
            });
        rejects(&invalid, "intrinsic address");
    }

    fn builtin(name: &str, params: &[TypeId]) -> Function {
        serde_json::from_value(json!({
            "name":name,"linkage":"external","intrinsic":name,
            "signature":{"params":params,"result":0,"abi":"c","variadic":false},
            "params":params.iter().enumerate().map(|(id, ty)| json!({"id":id,"ty":ty})).collect::<Vec<_>>(),
            "entry":null,"blocks":[]
        }))
        .unwrap()
    }

    fn overflow_module(bits: u16, kind: BinaryOp, signed: bool) -> NativeModule {
        let mut m = module();
        m.types[2] = Type::Int { bits };
        m.types.push(Type::Struct {
            fields: vec![2, 1],
            packed: false,
        });
        let function = &mut m.functions[0];
        function.signature.params = vec![2, 2];
        function.signature.result = 5;
        function.params = vec![Value { id: 7, ty: 2 }, Value { id: 9, ty: 2 }];
        function.blocks = vec![Block {
            id: 10,
            instructions: vec![Instruction {
                result: Some(Value { id: 8, ty: 5 }),
                operation: Operation::IntegerOverflow {
                    kind,
                    signed,
                    lhs: value(7),
                    rhs: value(9),
                },
            }],
            terminator: Terminator::Return {
                value: Some(value(8)),
            },
        }];
        let operation = match kind {
            BinaryOp::Add => "add",
            BinaryOp::Sub => "sub",
            BinaryOp::Mul => "mul",
            _ => unreachable!(),
        };
        let name = format!(
            "llvm.{}{operation}.with.overflow.i{bits}",
            if signed { "s" } else { "u" }
        );
        let mut declaration = builtin(&name, &[2, 2]);
        declaration.signature.result = 5;
        m.functions.push(declaration);
        m.provenance.source_function_count += 1;
        m
    }

    #[test]
    fn integer_overflow_preserves_all_six_intrinsic_contracts_at_every_supported_width() {
        for bits in 1..=64 {
            for kind in [BinaryOp::Add, BinaryOp::Sub, BinaryOp::Mul] {
                for signed in [false, true] {
                    let m = overflow_module(bits, kind, signed);
                    let name = &m.functions[1].name;
                    assert_eq!(integer_overflow_intrinsic(name), Some((kind, signed, bits)));
                    assert!(is_builtin_intrinsic(name));
                    verify(&m).unwrap();
                    let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
                    assert_eq!(restored.functions[1].intrinsic.as_ref(), Some(name));
                    assert_eq!(restored.provenance.source_function_count, 2);
                    assert!(
                        matches!(restored.functions[0].blocks[0].instructions[0].operation,
                        Operation::IntegerOverflow { kind: actual, signed: sign, .. }
                        if actual == kind && sign == signed)
                    );
                }
            }
        }
    }

    #[test]
    fn integer_overflow_rejects_bad_operands_result_shapes_and_unrelated_operations() {
        let m = overflow_module(9, BinaryOp::Mul, true);
        for kind in [BinaryOp::And, BinaryOp::UDiv, BinaryOp::Shl] {
            let mut invalid = m.clone();
            let Operation::IntegerOverflow { kind: actual, .. } =
                &mut invalid.functions[0].blocks[0].instructions[0].operation
            else {
                unreachable!()
            };
            *actual = kind;
            rejects(&invalid, "overflow requires scalar");
        }
        for ty in [
            Type::Struct {
                fields: vec![2, 1],
                packed: true,
            },
            Type::Array { element: 2, len: 2 },
            Type::Int { bits: 9 },
            Type::Struct {
                fields: vec![2],
                packed: false,
            },
        ] {
            let mut invalid = m.clone();
            invalid.types.push(ty);
            let bad = invalid.types.len() - 1;
            invalid.functions[0].signature.result = bad;
            invalid.functions[0].blocks[0].instructions[0]
                .result
                .as_mut()
                .unwrap()
                .ty = bad;
            rejects(&invalid, "overflow result must be original unpacked");
        }
        let mut invalid = m.clone();
        invalid.functions[0].blocks[0].instructions[0].result = None;
        rejects(&invalid, "requires an SSA result");
        let mut invalid = m.clone();
        let Operation::IntegerOverflow { lhs, .. } =
            &mut invalid.functions[0].blocks[0].instructions[0].operation
        else {
            unreachable!()
        };
        *lhs = value(8);
        assert!(verify(&invalid).is_err()); // A result cannot dominate its own operands.
        let mut invalid = m;
        let Operation::IntegerOverflow { rhs, .. } =
            &mut invalid.functions[0].blocks[0].instructions[0].operation
        else {
            unreachable!()
        };
        *rhs = integer(4, 1);
        rejects(&invalid, "type mismatch");
    }

    #[test]
    fn integer_overflow_intrinsics_require_exact_ownership_shape_and_canonical_widths() {
        let m = overflow_module(21, BinaryOp::Add, false);
        for name in [
            "llvm.uadd.with.overflow.i0",
            "llvm.uadd.with.overflow.i65",
            "llvm.uadd.with.overflow.i128",
            "llvm.uadd.with.overflow.i01",
            "llvm.uadd.with.overflow.i064",
            "llvm.uadd.with.overflow.i+21",
            "llvm.uadd.with.overflow.v4i21",
            "llvm.udiv.with.overflow.i21",
            "llvm.uadd.with.overflow.i21.suffix",
        ] {
            assert_eq!(integer_overflow_intrinsic(name), None);
            let mut invalid = m.clone();
            invalid.functions[1].name = name.into();
            invalid.functions[1].intrinsic = Some(name.into());
            rejects(
                &invalid,
                if name.contains('+') {
                    "assembler-safe spelling"
                } else {
                    "intrinsic declaration"
                },
            );
        }
        for change in 0..8 {
            let mut invalid = m.clone();
            let f = &mut invalid.functions[1];
            match change {
                0 => f.intrinsic = None,
                1 => f.signature.params[0] = 4,
                2 => f.signature.result = 2,
                3 => f.signature.param_attributes = vec![vec!["zeroext".into()], vec![]],
                4 => f.signature.result_attributes = vec!["zeroext".into()],
                5 => f.signature.abi = "fastcc".into(),
                6 => f.visibility = Visibility::Hidden,
                7 => f.signature.params.truncate(1),
                _ => unreachable!(),
            }
            rejects(
                &invalid,
                if change == 4 {
                    "integer extension attribute requires an integer"
                } else {
                    "intrinsic declaration"
                },
            );
        }
        let mut invalid = m.clone();
        invalid.functions[0].blocks[0].instructions[0].operation = Operation::Call {
            callee: Operand::Symbol {
                ty: 3,
                name: m.functions[1].name.clone(),
            },
            signature: m.functions[1].signature.clone(),
            args: vec![value(7), value(9)],
        };
        rejects(&invalid, "intrinsic address");
        let mut invalid = m;
        invalid.types[2] = Type::Int { bits: 128 };
        rejects(&invalid, "overflow requires scalar");
    }

    #[test]
    fn trap_is_an_effect_without_a_result_and_keeps_all_source_blocks() {
        for (triple, target, opcode) in [
            (
                "x86_64-unknown-linux-gnu",
                super::super::Target::X86_64UnknownNone,
                "  ud2\n",
            ),
            (
                "aarch64-unknown-linux-gnu",
                super::super::Target::Aarch64UnknownNone,
                "  brk #1\n",
            ),
            (
                "riscv64-unknown-linux-gnu",
                super::super::Target::Riscv64UnknownNone,
                "  unimp\n",
            ),
        ] {
            let mut m = module();
            m.target.triple = triple.into();
            m.functions.push(builtin("llvm.trap", &[]));
            m.provenance.source_function_count += 1;
            m.functions[0].blocks[1].instructions.insert(
                0,
                Instruction {
                    result: None,
                    operation: Operation::Trap {},
                },
            );
            verify(&m).unwrap();
            let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
            assert!(matches!(
                restored.functions[0].blocks[1].instructions[0].operation,
                Operation::Trap {}
            ));
            assert_eq!(restored.functions[0].blocks.len(), 4);
            assert_eq!(restored.functions[0].blocks[1].instructions.len(), 2);
            assert_eq!(
                restored.functions[1].intrinsic.as_deref(),
                Some("llvm.trap")
            );
            let assembly = super::super::native_codegen::emit(&restored, target).unwrap();
            assert_eq!(assembly.matches(opcode).count(), 1);
            assert!(!assembly.contains("call llvm.trap"));
            assert!(!assembly.contains("bl llvm.trap"));
            let mut invalid = m.clone();
            invalid.functions[0].blocks[1].instructions[0].result = Some(Value { id: 500, ty: 2 });
            rejects(&invalid, "trap cannot define an SSA value");
            let mut wire = serde_json::to_value(&m).unwrap();
            wire["functions"][0]["blocks"][1]["instructions"][0]["operation"]["callee"] =
                json!("foreign");
            assert!(
                serde_json::from_value::<NativeModule>(wire).is_err(),
                "trap must not accept hidden operands"
            );
        }
    }

    #[test]
    fn native_scalar_widths_keep_exact_layout_and_reject_unqualified_volatile_splits() {
        for (triple, target) in [
            (
                "x86_64-unknown-linux-gnu",
                super::super::Target::X86_64UnknownNone,
            ),
            (
                "aarch64-unknown-linux-gnu",
                super::super::Target::Aarch64UnknownNone,
            ),
            (
                "riscv64-unknown-linux-gnu",
                super::super::Target::Riscv64UnknownNone,
            ),
        ] {
            for width in 1_u16..=64 {
                let mut m = module();
                m.target.triple = triple.into();
                m.types[2] = Type::Int { bits: width };
                m.functions[0].blocks[0].instructions.splice(
                    0..0,
                    [
                        Instruction {
                            result: Some(Value { id: 500, ty: 3 }),
                            operation: Operation::Alloca {
                                size: 16,
                                alignment: 16,
                            },
                        },
                        Instruction {
                            result: None,
                            operation: Operation::Store {
                                pointer: value(500),
                                value: value(7),
                                alignment: 16,
                                volatile: false,
                            },
                        },
                        Instruction {
                            result: Some(Value { id: 501, ty: 2 }),
                            operation: Operation::Load {
                                pointer: value(500),
                                alignment: 16,
                                volatile: false,
                            },
                        },
                    ],
                );
                verify(&m).unwrap();
                let original_size = type_size(&m, 2).unwrap();
                super::super::native_codegen::emit(&m, target).unwrap();
                assert_eq!(type_size(&m, 2).unwrap(), original_size);
                assert!(original_size >= u64::from(width.div_ceil(8)));
                if !width.div_ceil(8).is_power_of_two() {
                    for index in [1, 2] {
                        let mut invalid = m.clone();
                        match &mut invalid.functions[0].blocks[0].instructions[index].operation {
                            Operation::Load { volatile, .. }
                            | Operation::Store { volatile, .. } => *volatile = true,
                            _ => unreachable!(),
                        }
                        verify(&invalid).unwrap();
                        let diagnostic =
                            super::super::native_codegen::emit(&invalid, target).unwrap_err();
                        assert!(
                            diagnostic.message.contains("odd-byte volatile access"),
                            "{}",
                            diagnostic.message
                        );
                    }
                }
            }
            let mut too_wide = module();
            too_wide.target.triple = triple.into();
            too_wide.types[2] = Type::Int { bits: 65 };
            verify(&too_wide).unwrap();
            assert!(super::super::native_codegen::emit(&too_wide, target)
                .unwrap_err()
                .message
                .contains("not implemented for type"));
        }
    }

    fn memory_module() -> NativeModule {
        let mut m = module();
        m.types.push(Type::Int { bits: 32 }); // 5.
        m.functions[0].blocks[0].instructions.insert(
            0,
            Instruction {
                result: Some(Value { id: 500, ty: 3 }),
                operation: Operation::Alloca {
                    size: 64,
                    alignment: 16,
                },
            },
        );
        m
    }

    #[test]
    fn preserves_exact_builtin_profiles_and_rejects_signature_and_identity_changes() {
        let profiles: [(&str, &[TypeId]); 10] = [
            ("llvm.trap", &[]),
            ("llvm.assume", &[1]),
            ("llvm.lifetime.start.p0", &[3]),
            ("llvm.lifetime.end.p0", &[3]),
            ("llvm.memset.p0.i32", &[3, 4, 5, 1]),
            ("llvm.memset.p0.i64", &[3, 4, 2, 1]),
            ("llvm.memcpy.p0.p0.i32", &[3, 3, 5, 1]),
            ("llvm.memcpy.p0.p0.i64", &[3, 3, 2, 1]),
            ("llvm.memmove.p0.p0.i32", &[3, 3, 5, 1]),
            ("llvm.memmove.p0.p0.i64", &[3, 3, 2, 1]),
        ];
        for (name, params) in profiles {
            assert!(is_builtin_intrinsic(name));
            let mut m = memory_module();
            m.functions.push(builtin(name, params));
            m.provenance.source_function_count += 1;
            verify(&m).unwrap();
            let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
            assert_eq!(restored.functions[1].intrinsic.as_deref(), Some(name));
            assert_eq!(restored.provenance.source_function_count, 2);
            for (index, expected) in params.iter().enumerate() {
                let mut invalid = m.clone();
                // Change each parameter independently to a distinct integer
                // width; pointer parameters cannot silently become integers.
                invalid.functions[1].signature.params[index] = if *expected == 2 { 4 } else { 2 };
                rejects(&invalid, "intrinsic declaration");
            }
            let mut invalid = m.clone();
            invalid.functions[1].intrinsic = None;
            rejects(&invalid, "intrinsic declaration");
            invalid = m.clone();
            invalid.functions[1].intrinsic = Some("llvm.assume.wrong".into());
            rejects(&invalid, "intrinsic declaration");
            for visibility in [Visibility::Hidden, Visibility::Protected] {
                invalid = m.clone();
                invalid.functions[1].visibility = visibility;
                rejects(&invalid, "intrinsic declaration");
            }
            invalid = m.clone();
            invalid.functions[1].entry = Some(10);
            rejects(&invalid, "intrinsic declaration");
            invalid = m.clone();
            invalid.functions[1].signature.result = 1;
            rejects(&invalid, "intrinsic declaration");
            invalid = m.clone();
            invalid.functions[1].signature.abi = "sysv64".into();
            rejects(&invalid, "intrinsic declaration");
            invalid = m.clone();
            invalid.functions[1].signature.variadic = true;
            rejects(&invalid, "intrinsic declaration");
            invalid = m.clone();
            if params.is_empty() {
                invalid.functions[1].signature.params.push(2);
            } else {
                invalid.functions[1].signature.params.clear();
            }
            rejects(&invalid, "intrinsic declaration");
            invalid = m.clone();
            global(&mut invalid);
            invalid.globals[0].initializer.as_mut().unwrap().relocations = vec![Relocation {
                offset: 0,
                width: 64,
                symbol: name.into(),
                addend: 0,
                relative_to: None,
            }];
            rejects(&invalid, "intrinsic address");
        }
        for name in [
            "llvm.trap.extra",
            "llvm.assume.extra",
            "llvm.lifetime.start.p1",
            "llvm.lifetime.start",
            "llvm.memset.p0.i8",
            "llvm.memcpy.inline.p0.p0.i64",
            "llvm.memmove.p1.p0.i64",
            "llvm.memset.element.unordered.atomic.p0.i64",
        ] {
            assert!(!is_builtin_intrinsic(name));
            let mut m = memory_module();
            m.functions.push(builtin(name, &[3]));
            m.provenance.source_function_count += 1;
            rejects(&m, "intrinsic declaration");
        }
        let mut m = memory_module();
        m.functions
            .push(builtin("llvm.memset.p0.i64", &[3, 4, 2, 1]));
        m.provenance.source_function_count += 1;
        m.functions[1].signature.param_attributes =
            vec![vec![], vec![], vec!["zeroext".into()], vec![]];
        rejects(&m, "intrinsic declaration");
        m.functions[1].signature.param_attributes.clear();
        m.types.push(Type::Pointer { address_space: 1 });
        m.functions[1].signature.params[0] = 6;
        rejects(&m, "intrinsic declaration");
    }

    #[test]
    fn lifetime_requires_direct_alloca_or_poison_and_dominating_void_use() {
        for end in [false, true] {
            for pointer in [value(500), Operand::Poison { ty: 3 }] {
                let mut m = memory_module();
                m.functions[0].blocks[0].instructions.push(Instruction {
                    result: None,
                    operation: Operation::Lifetime { pointer, end },
                });
                verify(&m).unwrap();
                let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
                assert!(matches!(
                    restored.functions[0].blocks[0].instructions.last().unwrap().operation,
                    Operation::Lifetime { end: restored_end, .. } if restored_end == end
                ));
            }
        }
        for pointer in [Operand::Null { ty: 3 }, Operand::Undef { ty: 3 }] {
            let mut m = memory_module();
            m.functions[0].blocks[0].instructions.push(Instruction {
                result: None,
                operation: Operation::Lifetime {
                    pointer,
                    end: false,
                },
            });
            rejects(&m, "alloca SSA value or poison");
        }
        let mut m = memory_module();
        m.functions[0].signature.params.push(3);
        m.functions[0].params.push(Value { id: 600, ty: 3 });
        m.functions[0].blocks[0].instructions.push(Instruction {
            result: None,
            operation: Operation::Lifetime {
                pointer: value(600),
                end: false,
            },
        });
        rejects(&m, "alloca SSA value or poison");
        for operation in [
            Operation::Gep {
                base: value(500),
                offset: integer(2, 0),
                inbounds: false,
            },
            Operation::Freeze { value: value(500) },
        ] {
            let mut m = memory_module();
            m.functions[0].blocks[0].instructions.extend([
                Instruction {
                    result: Some(Value { id: 501, ty: 3 }),
                    operation,
                },
                Instruction {
                    result: None,
                    operation: Operation::Lifetime {
                        pointer: value(501),
                        end: false,
                    },
                },
            ]);
            rejects(&m, "alloca SSA value or poison");
        }
        let mut m = memory_module();
        m.functions[0].blocks[0].instructions.insert(
            0,
            Instruction {
                result: None,
                operation: Operation::Lifetime {
                    pointer: value(500),
                    end: false,
                },
            },
        );
        rejects(&m, "does not dominate");
        let mut m = memory_module();
        let allocation = m.functions[0].blocks[0].instructions.remove(0);
        m.functions[0].blocks[1].instructions.insert(0, allocation);
        m.functions[0].blocks[2].instructions.push(Instruction {
            result: None,
            operation: Operation::Lifetime {
                pointer: value(500),
                end: true,
            },
        });
        rejects(&m, "does not dominate");
        let mut m = memory_module();
        m.functions[0].blocks[0].instructions.push(Instruction {
            result: Some(Value { id: 601, ty: 1 }),
            operation: Operation::Lifetime {
                pointer: value(500),
                end: false,
            },
        });
        rejects(&m, "lifetime cannot define");
        m.functions[0].blocks[0]
            .instructions
            .last_mut()
            .unwrap()
            .result = None;
        m.types.push(Type::Pointer { address_space: 1 });
        m.functions[0].blocks[0]
            .instructions
            .last_mut()
            .unwrap()
            .operation = Operation::Lifetime {
            pointer: Operand::Poison { ty: 6 },
            end: false,
        };
        rejects(&m, "address-space-zero pointer");
    }

    #[test]
    fn memory_intrinsics_preserve_widths_alignment_volatile_and_overlap_contracts() {
        for length_type in [2, 5] {
            for volatile in [false, true] {
                for allow_overlap in [false, true] {
                    let mut m = memory_module();
                    let max = if length_type == 2 {
                        u64::MAX
                    } else {
                        u64::from(u32::MAX)
                    };
                    m.functions[0].blocks[0].instructions.extend([
                        Instruction {
                            result: None,
                            operation: Operation::MemorySet {
                                destination: value(500),
                                value: integer(4, 255),
                                length: integer(length_type, max),
                                alignment: 1,
                                volatile,
                            },
                        },
                        Instruction {
                            result: None,
                            operation: Operation::MemoryCopy {
                                destination: value(500),
                                source: value(500),
                                length: integer(length_type, 0),
                                destination_alignment: 16,
                                source_alignment: 1_u64 << 32,
                                volatile,
                                allow_overlap,
                            },
                        },
                    ]);
                    verify(&m).unwrap();
                    let json = m.to_json().unwrap();
                    assert_eq!(
                        serde_json::to_value(&m).unwrap(),
                        serde_json::to_value(NativeModule::from_json(&json).unwrap()).unwrap()
                    );
                }
            }
        }
        let valid = Operation::MemorySet {
            destination: value(500),
            value: integer(4, 165),
            length: integer(2, 64),
            alignment: 1,
            volatile: false,
        };
        let mut m = memory_module();
        m.functions[0].blocks[0].instructions.push(Instruction {
            result: None,
            operation: valid.clone(),
        });
        for align in [0, 3, (1_u64 << 32) + 1, u64::MAX] {
            let mut invalid = m.clone();
            if let Operation::MemorySet { alignment, .. } = &mut invalid.functions[0].blocks[0]
                .instructions
                .last_mut()
                .unwrap()
                .operation
            {
                *alignment = align;
            }
            rejects(&invalid, "alignment must be a power of two");
        }
        for length_type in [1, 4, 3] {
            let mut invalid = m.clone();
            if let Operation::MemorySet { length, .. } = &mut invalid.functions[0].blocks[0]
                .instructions
                .last_mut()
                .unwrap()
                .operation
            {
                *length = if length_type == 3 {
                    Operand::Null { ty: 3 }
                } else {
                    integer(length_type, 0)
                };
            }
            rejects(&invalid, "length requires i32 or i64");
        }
        let mut invalid = m.clone();
        if let Operation::MemorySet { value, .. } = &mut invalid.functions[0].blocks[0]
            .instructions
            .last_mut()
            .unwrap()
            .operation
        {
            *value = integer(2, 165);
        }
        rejects(&invalid, "fill requires an i8");
        let mut invalid = m.clone();
        invalid.functions[0].blocks[0]
            .instructions
            .last_mut()
            .unwrap()
            .result = Some(Value { id: 601, ty: 1 });
        rejects(&invalid, "memory operation cannot define");
        let mut invalid = m.clone();
        invalid.types.push(Type::Pointer { address_space: 1 });
        if let Operation::MemorySet { destination, .. } = &mut invalid.functions[0].blocks[0]
            .instructions
            .last_mut()
            .unwrap()
            .operation
        {
            *destination = Operand::Null { ty: 6 };
        }
        rejects(&invalid, "address-space-zero pointer");
        for (destination_alignment, source_alignment) in [(0, 1), (1, 0), (3, 1), (1, 3)] {
            let mut invalid = m.clone();
            invalid.functions[0].blocks[0]
                .instructions
                .last_mut()
                .unwrap()
                .operation = Operation::MemoryCopy {
                destination: value(500),
                source: value(500),
                length: integer(2, 8),
                destination_alignment,
                source_alignment,
                volatile: false,
                allow_overlap: true,
            };
            rejects(&invalid, "alignment must be a power of two");
        }
    }

    #[test]
    fn memory_operand_dominance_includes_dynamic_length_fill_and_both_pointers() {
        let mut m = memory_module();
        m.functions[0].blocks[2].instructions.push(Instruction {
            result: None,
            operation: Operation::MemorySet {
                destination: value(500),
                value: integer(4, 165),
                length: value(20),
                alignment: 1,
                volatile: false,
            },
        });
        rejects(&m, "does not dominate");
        let mut m = memory_module();
        m.functions[0].blocks[1].instructions.push(Instruction {
            result: Some(Value { id: 22, ty: 4 }),
            operation: Operation::Cast {
                kind: CastOp::Trunc,
                value: value(20),
            },
        });
        m.functions[0].blocks[2].instructions.push(Instruction {
            result: None,
            operation: Operation::MemorySet {
                destination: value(500),
                value: value(22),
                length: integer(2, 8),
                alignment: 1,
                volatile: false,
            },
        });
        rejects(&m, "does not dominate");
        for bad_destination in [false, true] {
            let mut m = memory_module();
            m.functions[0].blocks[1].instructions.push(Instruction {
                result: Some(Value { id: 501, ty: 3 }),
                operation: Operation::Alloca {
                    size: 8,
                    alignment: 1,
                },
            });
            m.functions[0].blocks[2].instructions.push(Instruction {
                result: None,
                operation: Operation::MemoryCopy {
                    destination: value(if bad_destination { 501 } else { 500 }),
                    source: value(if bad_destination { 500 } else { 501 }),
                    length: integer(2, 8),
                    destination_alignment: 1,
                    source_alignment: 1,
                    volatile: true,
                    allow_overlap: true,
                },
            });
            rejects(&m, "does not dominate");
        }
    }

    #[test]
    fn rejects_duplicate_definitions_blocks_and_symbols() {
        let mut m = module();
        m.functions[0].blocks[1].instructions[0]
            .result
            .as_mut()
            .unwrap()
            .id = 7;
        rejects(&m, "duplicate SSA");
        let mut m = module();
        m.functions[0].blocks[1].id = 10;
        rejects(&m, "duplicate block");
        let mut m = module();
        global(&mut m);
        m.globals[0].name = "choose".into();
        rejects(&m, "duplicate global/function symbol");
    }

    #[test]
    fn rejects_symbol_injection_and_missing_inventory() {
        for name in [
            "valid\n.globl injected",
            "name:ret",
            "a b",
            "1symbol",
            "é",
            "a\0b",
        ] {
            let mut m = module();
            m.functions[0].name = name.into();
            rejects(&m, "assembler-safe");
        }
        let mut m = module();
        m.provenance.source_function_count = 0;
        rejects(&m, "inventory");
        let mut m = module();
        m.provenance.input_sha256 = "unverified".into();
        rejects(&m, "SHA-256");
    }

    #[test]
    fn rejects_forward_use_and_branch_local_value_at_merge() {
        let mut m = module();
        m.functions[0].blocks[1].instructions[0].operation = Operation::Binary {
            kind: BinaryOp::Add,
            lhs: value(20),
            rhs: integer(2, 1),
            flags: vec![],
        };
        rejects(&m, "does not dominate");
        let mut m = module();
        m.functions[0].blocks[3].terminator = Terminator::Return {
            value: Some(value(20)),
        };
        rejects(&m, "does not dominate");
    }

    #[test]
    fn validates_phi_uses_on_edges_and_exact_predecessor_sets() {
        let mut m = module();
        let Operation::Phi { incoming } = &mut m.functions[0].blocks[3].instructions[0].operation
        else {
            unreachable!()
        };
        incoming[0].value = value(30);
        rejects(&m, "does not dominate");
        let mut m = module();
        let Operation::Phi { incoming } = &mut m.functions[0].blocks[3].instructions[0].operation
        else {
            unreachable!()
        };
        incoming.pop();
        rejects(&m, "predecessor set");
        let mut m = module();
        let Operation::Phi { incoming } = &mut m.functions[0].blocks[3].instructions[0].operation
        else {
            unreachable!()
        };
        incoming[1].block = 20;
        rejects(&m, "duplicate predecessor");
    }

    #[test]
    fn accepts_loop_carried_phi_backedge_definition() {
        let mut m = module();
        let f = &mut m.functions[0];
        f.blocks = vec![
            Block {
                id: 10,
                instructions: vec![],
                terminator: Terminator::Jump { target: 20 },
            },
            Block {
                id: 20,
                instructions: vec![
                    Instruction {
                        result: Some(Value { id: 20, ty: 2 }),
                        operation: Operation::Phi {
                            incoming: vec![
                                PhiIncoming {
                                    block: 10,
                                    value: integer(2, 0),
                                },
                                PhiIncoming {
                                    block: 30,
                                    value: value(30),
                                },
                            ],
                        },
                    },
                    Instruction {
                        result: Some(Value { id: 21, ty: 1 }),
                        operation: Operation::ICmp {
                            predicate: IntPredicate::Ult,
                            lhs: value(20),
                            rhs: value(7),
                        },
                    },
                ],
                terminator: Terminator::Branch {
                    condition: value(21),
                    on_true: 30,
                    on_false: 40,
                },
            },
            Block {
                id: 30,
                instructions: vec![Instruction {
                    result: Some(Value { id: 30, ty: 2 }),
                    operation: Operation::Binary {
                        kind: BinaryOp::Add,
                        lhs: value(20),
                        rhs: integer(2, 1),
                        flags: vec![],
                    },
                }],
                terminator: Terminator::Jump { target: 20 },
            },
            Block {
                id: 40,
                instructions: vec![],
                terminator: Terminator::Return {
                    value: Some(value(20)),
                },
            },
        ];
        verify(&m).unwrap();
        let Operation::Phi { incoming } = &mut m.functions[0].blocks[1].instructions[0].operation
        else {
            unreachable!()
        };
        incoming[0].value = value(30);
        rejects(&m, "does not dominate");
    }

    #[test]
    fn rejects_unknown_blocks_values_and_out_of_range_types_without_panicking() {
        let mut m = module();
        m.functions[0].blocks[1].terminator = Terminator::Jump { target: usize::MAX };
        rejects(&m, "unknown block");
        let mut m = module();
        m.functions[0].blocks[3].terminator = Terminator::Return {
            value: Some(value(usize::MAX)),
        };
        rejects(&m, "undefined SSA");
        let mut m = module();
        m.functions[0].params[0].ty = usize::MAX;
        rejects(&m, "out of bounds");
        let mut m = module();
        m.functions[0].blocks[0].instructions[0]
            .result
            .as_mut()
            .unwrap()
            .ty = 0;
        rejects(&m, "unsized");
    }

    #[test]
    fn checks_all_dead_blocks_but_dominance_is_vacuous_there() {
        let mut m = module();
        m.functions[0].blocks.push(Block {
            id: 999,
            instructions: vec![],
            terminator: Terminator::Return {
                value: Some(value(20)),
            },
        });
        verify(&m).unwrap();
        m.functions[0].blocks.last_mut().unwrap().terminator = Terminator::Return {
            value: Some(value(111)),
        };
        rejects(&m, "undefined SSA");
    }

    #[test]
    fn computes_frontend_allocation_stride_and_packed_layout() {
        let mut m = module();
        m.types.extend([
            Type::Int { bits: 24 },
            Type::Array { element: 5, len: 3 },
            Type::Struct {
                fields: vec![4, 2],
                packed: false,
            },
            Type::Struct {
                fields: vec![4, 2],
                packed: true,
            },
            Type::Pointer { address_space: 1 },
        ]);
        m.target.data_layout.push_str("-p1:32:32");
        assert_eq!(type_size(&m, 5).unwrap(), 4);
        assert_eq!(type_size(&m, 6).unwrap(), 12);
        assert_eq!(type_size(&m, 7).unwrap(), 16);
        assert_eq!(type_size(&m, 8).unwrap(), 9);
        assert_eq!(type_alignment(&m, 8).unwrap(), 1);
        assert_eq!(type_size(&m, 9).unwrap(), 4);
        let mut m = module();
        m.target.data_layout = "e-p:64:64".into();
        assert_eq!(
            type_alignment(&m, 2).unwrap(),
            4,
            "LLVM default i64 ABI alignment"
        );
    }

    fn aggregate_module() -> NativeModule {
        let mut m = module();
        m.types.extend([
            Type::Array { element: 2, len: 2 }, // 5
            Type::Struct {
                fields: vec![4, 5, 3],
                packed: true,
            }, // 6
            Type::Struct {
                fields: vec![6, 2],
                packed: false,
            }, // 7
            Type::Array { element: 7, len: 2 }, // 8
            Type::Struct {
                fields: vec![],
                packed: false,
            }, // 9
            Type::Array {
                element: 9,
                len: u64::MAX,
            }, // 10
            Type::Float { bits: 32 },           // 11
            Type::Struct {
                fields: vec![11, 4],
                packed: false,
            }, // 12
        ]);
        m
    }

    fn aggregate_constant() -> Operand {
        Operand::Aggregate {
            ty: 6,
            elements: vec![
                integer(4, 7),
                Operand::Aggregate {
                    ty: 5,
                    elements: vec![integer(2, 8), integer(2, 9)],
                },
                Operand::Null { ty: 3 },
            ],
        }
    }

    fn aggregate_constant_instruction(m: &mut NativeModule, value: Operand) {
        m.functions[0].blocks[0].instructions.push(Instruction {
            result: Some(Value { id: 100, ty: 6 }),
            operation: Operation::Freeze { value },
        });
    }

    #[test]
    fn aggregate_leaves_keep_original_packed_offsets_allocation_stride_and_float_types() {
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "riscv64-unknown-linux-gnu",
        ] {
            let mut m = aggregate_module();
            m.target.triple = target.into();
            let first = vec![(4, 0), (2, 1), (2, 9), (3, 17), (2, 32)];
            assert_eq!(type_size(&m, 6).unwrap(), 25);
            assert_eq!(type_size(&m, 7).unwrap(), 40);
            assert_eq!(value_leaf_layout(&m, 7).unwrap(), first);
            let expected = first
                .iter()
                .copied()
                .chain(first.iter().map(|(ty, offset)| (*ty, offset + 40)))
                .collect::<Vec<_>>();
            assert_eq!(value_leaf_layout(&m, 8).unwrap(), expected);
            assert_eq!(value_leaf_layout(&m, 12).unwrap(), [(11, 0), (4, 4)]);
            assert!(value_leaf_layout(&m, 9).unwrap().is_empty());
            assert!(value_leaf_layout(&m, 10).unwrap().is_empty());
            assert_eq!(aggregate_element_type(&m, 8, &[1, 0, 1, 1]).unwrap(), 2);
            let bulk = value_leaf_layouts(&m, &[8, 8, 0]).unwrap();
            assert_eq!(bulk[&8], expected);
            for ty in [2, 3, 4, 5, 6, 7, 8] {
                assert!(bulk.contains_key(&ty));
            }
            assert!(!bulk.contains_key(&0));
            assert!(
                !bulk.contains_key(&12),
                "unused value types are not flattened"
            );
            verify(&m).unwrap();
        }
        let mut m = aggregate_module();
        m.types.extend([
            Type::Int { bits: 24 }, // 13
            Type::Array {
                element: 13,
                len: 3,
            }, // 14
            Type::Struct {
                fields: vec![4, 13, 4],
                packed: true,
            }, // 15
        ]);
        assert_eq!(
            value_leaf_layout(&m, 14).unwrap(),
            [(13, 0), (13, 4), (13, 8)]
        );
        assert_eq!(
            value_leaf_layout(&m, 15).unwrap(),
            [(4, 0), (13, 1), (4, 5)]
        );
    }

    #[test]
    fn aggregate_paths_reject_empty_scalar_and_out_of_bounds_selections() {
        let m = aggregate_module();
        for (ty, indices, message) in [
            (6, vec![], "nonempty"),
            (6, vec![3], "struct index"),
            (6, vec![u64::MAX], "struct index"),
            (5, vec![2], "array index"),
            (6, vec![1, 2], "array index"),
            (6, vec![0, 0], "struct or array"),
            (2, vec![0], "struct or array"),
            (usize::MAX, vec![0], "out of bounds"),
        ] {
            assert!(aggregate_element_type(&m, ty, &indices)
                .unwrap_err()
                .message
                .contains(message));
        }
        assert!(value_leaf_layout(&m, 0)
            .unwrap_err()
            .message
            .contains("unsized"));
        assert!(value_leaf_layouts(&m, &[usize::MAX])
            .unwrap_err()
            .message
            .contains("out of bounds"));
    }

    #[test]
    fn aggregate_layout_walk_has_no_depth_cap_or_empty_array_element_expansion() {
        let mut m = aggregate_module();
        let huge = m.types.len();
        m.types.push(Type::Array {
            element: 4,
            len: u64::MAX,
        });
        let empty = m.types.len();
        m.types.push(Type::Array {
            element: huge,
            len: 0,
        });
        let values = value_leaf_layouts(&m, &[empty]).unwrap();
        assert_eq!(values.len(), 1);
        assert!(values[&empty].is_empty());
        let mut ty = 2;
        for _ in 0..5000 {
            let next = m.types.len();
            m.types.push(Type::Struct {
                fields: vec![ty],
                packed: false,
            });
            ty = next;
        }
        assert_eq!(value_leaf_layout(&m, ty).unwrap(), [(2, 0)]);
        let overflow = m.types.len();
        m.types.push(Type::Array {
            element: 2,
            len: u64::MAX,
        });
        assert!(value_leaf_layout(&m, overflow)
            .unwrap_err()
            .message
            .contains("overflows"));
    }

    #[test]
    fn aggregate_constants_are_typed_compact_and_validate_all_nested_symbols() {
        let mut m = aggregate_module();
        aggregate_constant_instruction(&mut m, aggregate_constant());
        verify(&m).unwrap();
        let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
        verify(&restored).unwrap();
        assert!(matches!(
            restored.functions[0].blocks[0].instructions[1].operation,
            Operation::Freeze {
                value: Operand::Aggregate { ty: 6, .. }
            }
        ));
        for pointer in [
            Operand::Symbol {
                ty: 3,
                name: "choose".into(),
            },
            Operand::SymbolOffset {
                ty: 3,
                name: "choose".into(),
                addend: i64::MIN,
            },
            Operand::PointerBits {
                ty: 3,
                bits: u64::MAX.to_string(),
            },
            Operand::Undef { ty: 3 },
            Operand::Poison { ty: 3 },
        ] {
            let mut m = aggregate_module();
            let Operand::Aggregate { mut elements, .. } = aggregate_constant() else {
                unreachable!()
            };
            elements[2] = pointer;
            aggregate_constant_instruction(&mut m, Operand::Aggregate { ty: 6, elements });
            verify(&m).unwrap();
        }
        let mut m = aggregate_module();
        aggregate_constant_instruction(&mut m, Operand::AggregateZero { ty: 6 });
        verify(&m).unwrap();
        let mut m = aggregate_module();
        let mut constant = aggregate_constant();
        let Operand::Aggregate { elements, .. } = &mut constant else {
            unreachable!()
        };
        elements[1] = Operand::AggregateZero { ty: 5 };
        aggregate_constant_instruction(&mut m, constant);
        verify(&m).unwrap();
        for constant in [
            Operand::AggregateZero { ty: 9 },
            Operand::Aggregate {
                ty: 9,
                elements: vec![],
            },
            Operand::AggregateZero { ty: 10 },
        ] {
            let mut m = aggregate_module();
            let ty = match &constant {
                Operand::Aggregate { ty, .. } | Operand::AggregateZero { ty } => *ty,
                _ => unreachable!(),
            };
            m.functions[0].blocks[0].instructions.push(Instruction {
                result: Some(Value { id: 100, ty }),
                operation: Operation::Freeze { value: constant },
            });
            verify(&m).unwrap();
            let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
            verify(&restored).unwrap();
        }
    }

    #[test]
    fn aggregate_constants_reject_hidden_ssa_arity_type_and_literal_errors() {
        for (value, message) in [
            (Operand::AggregateZero { ty: 2 }, "struct or array"),
            (
                Operand::Aggregate {
                    ty: 2,
                    elements: vec![],
                },
                "struct or array",
            ),
            (
                Operand::Aggregate {
                    ty: 6,
                    elements: vec![],
                },
                "field count",
            ),
            (
                Operand::Aggregate {
                    ty: 5,
                    elements: vec![integer(2, 0)],
                },
                "element count",
            ),
        ] {
            let mut m = aggregate_module();
            aggregate_constant_instruction(&mut m, value);
            rejects(&m, message);
        }
        for (nested, message) in [
            (Operand::Value { id: 7 }, "contains an SSA value"),
            (integer(4, 1), "type mismatch"),
            (
                Operand::Int {
                    ty: 2,
                    bits: "18446744073709551616".into(),
                },
                "bit width",
            ),
            (Operand::AggregateZero { ty: 3 }, "struct or array"),
        ] {
            let mut m = aggregate_module();
            let mut constant = aggregate_constant();
            let Operand::Aggregate { elements, .. } = &mut constant else {
                unreachable!()
            };
            let Operand::Aggregate { elements, .. } = &mut elements[1] else {
                unreachable!()
            };
            elements[0] = nested;
            aggregate_constant_instruction(&mut m, constant);
            rejects(&m, message);
        }
        let mut m = aggregate_module();
        let mut constant = aggregate_constant();
        let Operand::Aggregate { elements, .. } = &mut constant else {
            unreachable!()
        };
        elements[2] = Operand::Symbol {
            ty: 3,
            name: "missing".into(),
        };
        aggregate_constant_instruction(&mut m, constant);
        rejects(&m, "unknown symbol");
    }

    fn aggregate_phi_module() -> NativeModule {
        let mut m = module();
        m.types.push(Type::Struct {
            fields: vec![2, 2],
            packed: false,
        });
        for (block, scalar, aggregate) in [(1, 20, 25), (2, 30, 35)] {
            m.functions[0].blocks[block].instructions.push(Instruction {
                result: Some(Value {
                    id: aggregate,
                    ty: 5,
                }),
                operation: Operation::InsertValue {
                    aggregate: Operand::AggregateZero { ty: 5 },
                    value: value(scalar),
                    indices: vec![0],
                },
            });
        }
        m.functions[0].blocks[3].instructions = vec![
            Instruction {
                result: Some(Value { id: 45, ty: 5 }),
                operation: Operation::Phi {
                    incoming: vec![
                        PhiIncoming {
                            block: 20,
                            value: value(25),
                        },
                        PhiIncoming {
                            block: 30,
                            value: value(35),
                        },
                    ],
                },
            },
            Instruction {
                result: Some(Value { id: 46, ty: 5 }),
                operation: Operation::Freeze { value: value(45) },
            },
            Instruction {
                result: Some(Value { id: 47, ty: 5 }),
                operation: Operation::Select {
                    condition: value(8),
                    on_true: value(46),
                    on_false: Operand::AggregateZero { ty: 5 },
                },
            },
            Instruction {
                result: Some(Value { id: 40, ty: 2 }),
                operation: Operation::ExtractValue {
                    aggregate: value(47),
                    indices: vec![0],
                },
            },
        ];
        m
    }

    #[test]
    fn aggregate_ssa_phi_freeze_select_and_extraction_keep_dominance_checks() {
        let m = aggregate_phi_module();
        verify(&m).unwrap();
        let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
        verify(&restored).unwrap();
        let mut invalid = m.clone();
        let Operation::Phi { incoming } =
            &mut invalid.functions[0].blocks[3].instructions[0].operation
        else {
            unreachable!()
        };
        incoming[0].value = value(35);
        rejects(&invalid, "does not dominate");
        let mut invalid = m.clone();
        invalid.functions[0].blocks[3].instructions[1].operation =
            Operation::Freeze { value: value(47) };
        rejects(&invalid, "does not dominate");
        for indices in [vec![], vec![2], vec![0, 0]] {
            let mut invalid = m.clone();
            let Operation::ExtractValue { indices: path, .. } =
                &mut invalid.functions[0].blocks[3].instructions[3].operation
            else {
                unreachable!()
            };
            *path = indices;
            assert!(verify(&invalid).is_err());
        }
        let mut invalid = m;
        invalid.functions[0].blocks[3].instructions[3]
            .result
            .as_mut()
            .unwrap()
            .ty = 4;
        rejects(&invalid, "type mismatch");
    }

    #[test]
    fn aggregate_insertion_requires_exact_selected_value_and_result_types() {
        let m = aggregate_phi_module();
        for indices in [vec![], vec![2], vec![0, 0]] {
            let mut invalid = m.clone();
            let Operation::InsertValue { indices: path, .. } =
                &mut invalid.functions[0].blocks[1].instructions[1].operation
            else {
                unreachable!()
            };
            *path = indices;
            assert!(verify(&invalid).is_err());
        }
        let mut invalid = m.clone();
        let Operation::InsertValue { value, .. } =
            &mut invalid.functions[0].blocks[1].instructions[1].operation
        else {
            unreachable!()
        };
        *value = integer(4, 0);
        rejects(&invalid, "type mismatch");
        let mut invalid = m;
        invalid.functions[0].blocks[1].instructions[1]
            .result
            .as_mut()
            .unwrap()
            .ty = 2;
        rejects(&invalid, "type mismatch");
    }

    #[test]
    fn aggregate_memory_values_and_nested_subaggregate_paths_remain_typed() {
        let mut m = aggregate_module();
        m.functions[0].blocks[0].instructions.extend([
            Instruction {
                result: Some(Value { id: 500, ty: 3 }),
                operation: Operation::Alloca {
                    size: 25,
                    alignment: 1,
                },
            },
            Instruction {
                result: None,
                operation: Operation::Store {
                    pointer: value(500),
                    value: aggregate_constant(),
                    alignment: 1,
                    volatile: false,
                },
            },
            Instruction {
                result: Some(Value { id: 501, ty: 6 }),
                operation: Operation::Load {
                    pointer: value(500),
                    alignment: 1,
                    volatile: false,
                },
            },
            Instruction {
                result: Some(Value { id: 502, ty: 5 }),
                operation: Operation::ExtractValue {
                    aggregate: value(501),
                    indices: vec![1],
                },
            },
            Instruction {
                result: Some(Value { id: 503, ty: 6 }),
                operation: Operation::InsertValue {
                    aggregate: value(501),
                    value: value(502),
                    indices: vec![1],
                },
            },
            Instruction {
                result: Some(Value { id: 504, ty: 2 }),
                operation: Operation::ExtractValue {
                    aggregate: value(503),
                    indices: vec![1, 1],
                },
            },
        ]);
        verify(&m).unwrap();
        let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
        verify(&restored).unwrap();
        let mut invalid = m;
        let Operation::InsertValue {
            value: inserted, ..
        } = &mut invalid.functions[0].blocks[0].instructions[5].operation
        else {
            unreachable!()
        };
        *inserted = Operand::AggregateZero { ty: 6 };
        rejects(&invalid, "type mismatch");
    }

    #[test]
    fn rejects_recursive_unsized_and_overflowing_type_layouts() {
        let mut m = module();
        m.types.push(Type::Array { element: 5, len: 1 });
        rejects(&m, "recursive by-value");
        let mut m = module();
        m.types.push(Type::Array { element: 0, len: 0 });
        rejects(&m, "array element is unsized");
        let mut m = module();
        m.types.push(Type::Array {
            element: 2,
            len: u64::MAX,
        });
        rejects(&m, "overflows");
        let mut m = module();
        m.types.push(Type::Array {
            element: usize::MAX,
            len: 1,
        });
        rejects(&m, "out of bounds");
        let mut m = module();
        m.target.pointer_bits = 32;
        rejects(&m, "pointer width");
    }

    #[test]
    fn validates_global_extent_and_relocation_ranges_symbols_and_overlap() {
        let mut m = module();
        global(&mut m);
        m.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .relocations
            .push(Relocation {
                offset: 0,
                width: 64,
                symbol: "choose".into(),
                addend: 0,
                relative_to: None,
            });
        verify(&m).unwrap();
        m.globals[0].initializer.as_mut().unwrap().relocations[0].offset = 1;
        rejects(&m, "beyond initializer");
        let mut m = module();
        global(&mut m);
        m.globals[0].initializer.as_mut().unwrap().relocations = vec![
            Relocation {
                offset: 0,
                width: 32,
                symbol: "choose".into(),
                addend: 0,
                relative_to: None,
            },
            Relocation {
                offset: 2,
                width: 32,
                symbol: "choose".into(),
                addend: 0,
                relative_to: None,
            },
        ];
        rejects(&m, "overlapping");
        let mut m = module();
        global(&mut m);
        m.globals[0].initializer.as_mut().unwrap().relocations = vec![Relocation {
            offset: 0,
            width: 64,
            symbol: "missing".into(),
            addend: 0,
            relative_to: None,
        }];
        rejects(&m, "unknown symbol");
        let mut m = module();
        global(&mut m);
        m.globals[0].initializer.as_mut().unwrap().bytes.pop();
        rejects(&m, "byte extent");
    }

    fn return_storage_module(param: usize) -> NativeModule {
        let mut m = module();
        let storage_ty = m.types.len();
        m.types.push(Type::Struct {
            fields: vec![2, 2, 2],
            packed: false,
        });
        let function = &mut m.functions[0];
        function.name = "make_result".into();
        function.signature = Signature {
            params: vec![3, 3],
            result: 0,
            abi: "c".into(),
            variadic: false,
            param_attributes: vec![],
            result_attributes: vec![],
            return_storage: Some(ReturnStorage {
                param,
                ty: storage_ty,
            }),
        };
        function.params = vec![Value { id: 7, ty: 3 }, Value { id: 8, ty: 3 }];
        function.blocks = vec![Block {
            id: 10,
            instructions: vec![Instruction {
                result: None,
                operation: Operation::Store {
                    pointer: value(7 + param),
                    value: integer(2, 42),
                    alignment: 8,
                    volatile: false,
                },
            }],
            terminator: Terminator::Return { value: None },
        }];
        let mut caller = function.clone();
        caller.name = "forward_result".into();
        caller.blocks[0].instructions = vec![Instruction {
            result: None,
            operation: Operation::Call {
                callee: Operand::Symbol {
                    ty: 3,
                    name: "make_result".into(),
                },
                signature: function.signature.clone(),
                args: vec![value(7), value(8)],
            },
        }];
        m.functions.push(caller);
        m.provenance.source_function_count = m.functions.len();
        m
    }

    #[test]
    fn typed_return_storage_preserves_positions_and_sized_memory_types_on_all_targets() {
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "riscv64-unknown-linux-gnu",
        ] {
            for param in [0, 1] {
                let mut m = return_storage_module(param);
                m.target.triple = target.into();
                let array = m.types.len();
                m.types.push(Type::Array {
                    element: 4,
                    len: 25,
                });
                let packed = m.types.len();
                m.types.push(Type::Struct {
                    fields: vec![4, 2],
                    packed: true,
                });
                let empty = m.types.len();
                m.types.push(Type::Struct {
                    fields: vec![],
                    packed: false,
                });
                let float = m.types.len();
                m.types.push(Type::Float { bits: 64 });
                for ty in [2, 3, 5, array, packed, empty, float] {
                    m.functions[0].signature.return_storage.as_mut().unwrap().ty = ty;
                    let signature = m.functions[0].signature.clone();
                    m.functions[1].signature = signature.clone();
                    let Operation::Call {
                        signature: call, ..
                    } = &mut m.functions[1].blocks[0].instructions[0].operation
                    else {
                        unreachable!()
                    };
                    *call = signature;
                    verify(&m).unwrap();
                    let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
                    verify(&restored).unwrap();
                    assert_eq!(
                        restored.functions[0].signature.return_storage,
                        Some(ReturnStorage { param, ty })
                    );
                    assert_eq!(restored.functions[0].signature.params, vec![3, 3]);
                    assert_eq!(restored.functions[0].signature.result, 0);
                    let mut declaration = restored;
                    declaration.functions[0].entry = None;
                    declaration.functions[0].blocks.clear();
                    verify(&declaration).unwrap();
                }
            }
        }
        assert!(module().functions[0].signature.return_storage.is_none());
    }

    #[test]
    fn return_storage_rejects_invalid_positions_pointer_profiles_results_and_payloads() {
        let mut invalid = return_storage_module(0);
        invalid.functions[0]
            .signature
            .return_storage
            .as_mut()
            .unwrap()
            .param = 2;
        rejects(&invalid, "first or second parameter");
        let mut invalid = return_storage_module(1);
        invalid.functions[0].signature.params.pop();
        rejects(&invalid, "missing from fixed signature");
        let mut invalid = return_storage_module(0);
        invalid.functions[0].signature.params[0] = 2;
        rejects(&invalid, "address-space-zero pointer parameter");
        let mut invalid = return_storage_module(0);
        let nonzero_space = invalid.types.len();
        invalid.types.push(Type::Pointer { address_space: 1 });
        invalid.functions[0].signature.params[0] = nonzero_space;
        rejects(&invalid, "address-space-zero pointer parameter");
        let mut invalid = return_storage_module(0);
        invalid.functions[0].signature.result = 2;
        rejects(&invalid, "requires a void result");
        let mut invalid = return_storage_module(0);
        invalid.functions[0]
            .signature
            .return_storage
            .as_mut()
            .unwrap()
            .ty = invalid.types.len();
        rejects(&invalid, "out of bounds");
        let mut invalid = return_storage_module(0);
        invalid.functions[0]
            .signature
            .return_storage
            .as_mut()
            .unwrap()
            .ty = 0;
        rejects(&invalid, "unsized");
        let mut invalid = return_storage_module(0);
        let function_ty = invalid.types.len();
        invalid.types.push(Type::Function {
            signature: module().functions[0].signature.clone(),
        });
        invalid.functions[0]
            .signature
            .return_storage
            .as_mut()
            .unwrap()
            .ty = function_ty;
        rejects(&invalid, "unsized");
    }

    #[test]
    fn return_storage_has_one_typed_contract_and_cannot_be_encoded_as_an_erased_string() {
        for attribute in ["sret", "byval", "byref", "returned", "inreg", "nest"] {
            let mut invalid = return_storage_module(0);
            invalid.functions[0].signature.param_attributes = vec![vec![attribute.into()], vec![]];
            rejects(&invalid, "unsupported imported ABI attribute");
        }
        for attribute in ["signext", "zeroext"] {
            let mut invalid = return_storage_module(0);
            invalid.functions[0].signature.param_attributes = vec![vec![attribute.into()], vec![]];
            rejects(&invalid, "integer extension attribute requires an integer");
        }
        let original = serde_json::to_value(return_storage_module(0)).unwrap();
        let mut invalid = original.clone();
        invalid["functions"][0]["signature"]["return_storage"] =
            json!([{"param":0,"ty":5},{"param":1,"ty":5}]);
        assert!(serde_json::from_value::<NativeModule>(invalid).is_err());
        for field in ["alignment", "second_param", "copy", "zero_initialize"] {
            let mut invalid = original.clone();
            invalid["functions"][0]["signature"]["return_storage"][field] = json!(1);
            assert!(serde_json::from_value::<NativeModule>(invalid).is_err());
        }
    }

    #[test]
    fn direct_calls_reject_erased_moved_or_differently_typed_return_storage() {
        for mismatch in ["erase", "move", "storage_type"] {
            let mut invalid = return_storage_module(0);
            let array = invalid.types.len();
            invalid.types.push(Type::Array { element: 2, len: 3 });
            assert_eq!(
                type_size(&invalid, array).unwrap(),
                type_size(&invalid, 5).unwrap()
            );
            let Operation::Call { signature, .. } =
                &mut invalid.functions[1].blocks[0].instructions[0].operation
            else {
                unreachable!()
            };
            match mismatch {
                "erase" => signature.return_storage = None,
                "move" => signature.return_storage.as_mut().unwrap().param = 1,
                "storage_type" => signature.return_storage.as_mut().unwrap().ty = array,
                _ => unreachable!(),
            }
            rejects(&invalid, "direct callee symbol/signature mismatch");
        }
        let mut invalid = return_storage_module(0);
        invalid.functions[0].signature.return_storage = None;
        rejects(&invalid, "direct callee symbol/signature mismatch");
    }

    fn return_storage_alias_module() -> NativeModule {
        let mut m = return_storage_module(0);
        let mut bare = m.functions[0].signature.clone();
        bare.return_storage = None;
        let function_ty = m.types.len();
        m.types.push(Type::Function { signature: bare });
        m.aliases.push(Alias {
            name: "result_alias".into(),
            ty: function_ty,
            aliasee: "make_result".into(),
            linkage: "external".into(),
            visibility: Visibility::Default,
        });
        m.provenance.source_alias_count = 1;
        let Operation::Call { callee, .. } =
            &mut m.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!()
        };
        *callee = Operand::Symbol {
            ty: function_ty,
            name: "result_alias".into(),
        };
        m
    }

    #[test]
    fn alias_and_bare_function_types_preserve_the_real_return_storage_call_contract() {
        let m = return_storage_alias_module();
        verify(&m).unwrap();
        let mut direct = m.clone();
        let Operation::Call { callee, .. } =
            &mut direct.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!()
        };
        let Operand::Symbol { name, .. } = callee else {
            unreachable!()
        };
        *name = "make_result".into();
        verify(&direct).unwrap();
        for mismatch in ["erase", "move", "storage_type"] {
            let mut invalid = m.clone();
            let Operation::Call { signature, .. } =
                &mut invalid.functions[1].blocks[0].instructions[0].operation
            else {
                unreachable!()
            };
            match mismatch {
                "erase" => signature.return_storage = None,
                "move" => signature.return_storage.as_mut().unwrap().param = 1,
                "storage_type" => signature.return_storage.as_mut().unwrap().ty = 2,
                _ => unreachable!(),
            }
            rejects(&invalid, "direct callee symbol/signature mismatch");
        }
        let mut invalid = m;
        let Type::Function { signature } = &mut invalid.types[6] else {
            unreachable!()
        };
        signature.return_storage = Some(ReturnStorage { param: 1, ty: 5 });
        rejects(&invalid, "function alias ABI contract mismatch");
    }

    #[test]
    fn attributed_function_values_check_storage_and_indirect_calls_keep_their_contract() {
        let mut m = return_storage_module(0);
        let function_ty = m.types.len();
        m.types.push(Type::Function {
            signature: m.functions[0].signature.clone(),
        });
        let Operation::Call { callee, .. } =
            &mut m.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!()
        };
        *callee = Operand::Symbol {
            ty: function_ty,
            name: "make_result".into(),
        };
        verify(&m).unwrap();
        let mut invalid = m.clone();
        let Type::Function { signature } = &mut invalid.types[function_ty] else {
            unreachable!()
        };
        signature.return_storage.as_mut().unwrap().param = 1;
        rejects(
            &invalid,
            "function symbol type does not match its declaration",
        );
        let Operation::Call { callee, .. } =
            &mut m.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!()
        };
        *callee = value(8);
        verify(&m).unwrap();
        let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
        let Operation::Call { signature, .. } =
            &restored.functions[1].blocks[0].instructions[0].operation
        else {
            unreachable!()
        };
        assert_eq!(
            signature.return_storage,
            Some(ReturnStorage { param: 0, ty: 5 })
        );
    }

    #[test]
    fn exact_builtin_signatures_reject_a_return_storage_contract() {
        let mut m = module();
        m.functions.push(builtin("llvm.lifetime.start.p0", &[3]));
        m.provenance.source_function_count += 1;
        m.functions[1].signature.return_storage = Some(ReturnStorage { param: 0, ty: 2 });
        rejects(&m, "invalid or unsupported intrinsic declaration");
    }

    #[test]
    fn checks_direct_call_signatures_and_extension_attributes() {
        let mut m = module();
        let signature = m.functions[0].signature.clone();
        m.functions.push(Function {
            name: "external".into(),
            linkage: "external".into(),
            visibility: Visibility::Default,
            comdat: None,
            alignment: 0,
            signature: signature.clone(),
            params: vec![Value { id: 0, ty: 2 }],
            entry: None,
            blocks: vec![],
            managed_method: None,
            intrinsic: None,
            exception_handling: None,
        });
        m.provenance.source_function_count = 2;
        m.functions[0].blocks[3].instructions.push(Instruction {
            result: Some(Value { id: 41, ty: 2 }),
            operation: Operation::Call {
                callee: Operand::Symbol {
                    ty: 3,
                    name: "external".into(),
                },
                signature,
                args: vec![value(40)],
            },
        });
        m.functions[0].blocks[3].terminator = Terminator::Return {
            value: Some(value(41)),
        };
        verify(&m).unwrap();
        let Operation::Call { signature, .. } =
            &mut m.functions[0].blocks[3].instructions[1].operation
        else {
            unreachable!()
        };
        signature.param_attributes = vec![vec!["signext".into()]];
        rejects(&m, "callee symbol/signature mismatch");
        m.functions[1].signature.param_attributes = vec![vec!["signext".into()]];
        verify(&m).unwrap();
        m.functions[1].signature.param_attributes = vec![vec!["byval".into()]];
        let Operation::Call { signature, .. } =
            &mut m.functions[0].blocks[3].instructions[1].operation
        else {
            unreachable!()
        };
        signature.param_attributes = vec![vec!["byval".into()]];
        rejects(&m, "unsupported imported ABI");
    }

    #[test]
    fn checks_constant_bit_width_cast_width_and_memory_types() {
        let mut m = module();
        m.functions[0].blocks[0].terminator = Terminator::Branch {
            condition: integer(1, 2),
            on_true: 20,
            on_false: 30,
        };
        rejects(&m, "bit width");
        let mut m = module();
        m.functions[0].blocks[1].instructions[0].operation = Operation::Cast {
            kind: CastOp::ZExt,
            value: value(7),
        };
        rejects(&m, "cast kind/type/width");
        let mut m = module();
        m.functions[0].blocks[1].instructions[0].operation = Operation::Load {
            pointer: value(7),
            alignment: 8,
            volatile: false,
        };
        rejects(&m, "pointer type");
        let mut m = module();
        m.functions[0].blocks[1].instructions[0].operation = Operation::Store {
            pointer: Operand::Null { ty: 3 },
            value: value(7),
            alignment: 8,
            volatile: false,
        };
        rejects(&m, "store cannot define");
    }

    #[test]
    fn validates_poison_refinement_flags_without_eager_rejection() {
        let mut m = module();
        m.functions[0].blocks[1].instructions[0].operation = Operation::Binary {
            kind: BinaryOp::Add,
            lhs: integer(2, u64::MAX),
            rhs: integer(2, 1),
            flags: vec!["nuw".into(), "nsw".into()],
        };
        m.functions[0].blocks[1].instructions.push(Instruction {
            result: Some(Value { id: 22, ty: 2 }),
            operation: Operation::Select {
                condition: integer(1, 0),
                on_true: Operand::Poison { ty: 2 },
                on_false: integer(2, 5),
            },
        });
        verify(&m).unwrap();
        let Operation::Binary { flags, .. } =
            &mut m.functions[0].blocks[1].instructions[0].operation
        else {
            unreachable!()
        };
        flags.push("exact".into());
        rejects(&m, "inapplicable LLVM poison flag");
    }

    #[test]
    fn rejects_unknown_json_fields_before_verification() {
        let mut json = serde_json::to_value(module()).unwrap();
        json["unknown_semantics_override"] = true.into();
        assert!(NativeModule::from_json(&serde_json::to_vec(&json).unwrap())
            .unwrap_err()
            .message
            .contains("unknown field"));
    }

    #[test]
    fn handles_deep_type_chains_without_recursive_stack_growth() {
        let mut m = module();
        for _ in 0..20_000 {
            m.types.push(Type::Array {
                element: m.types.len() - 1,
                len: 1,
            });
        }
        assert_eq!(type_size(&m, m.types.len() - 1).unwrap(), 1);
    }

    fn switch_module() -> NativeModule {
        let mut m = module();
        m.functions[0].blocks[0].instructions.clear();
        m.functions[0].blocks[0].terminator = Terminator::Switch {
            condition: value(7),
            default: 30,
            cases: vec![
                SwitchCase {
                    value: integer(2, 0),
                    target: 20,
                },
                SwitchCase {
                    value: integer(2, 2),
                    target: 20,
                },
                SwitchCase {
                    value: integer(2, u64::MAX),
                    target: 30,
                },
            ],
        };
        m
    }

    #[test]
    fn switch_duplicate_destinations_have_one_phi_predecessor() {
        let mut m = switch_module();
        m.functions[0].blocks[1].instructions.insert(
            0,
            Instruction {
                result: Some(Value { id: 19, ty: 2 }),
                operation: Operation::Phi {
                    incoming: vec![PhiIncoming {
                        block: 10,
                        value: value(7),
                    }],
                },
            },
        );
        verify(&m).unwrap();
        let Operation::Phi { incoming } = &mut m.functions[0].blocks[1].instructions[0].operation
        else {
            unreachable!()
        };
        incoming.push(PhiIncoming {
            block: 10,
            value: value(7),
        });
        rejects(&m, "phi has duplicate predecessor");
    }

    #[test]
    fn switch_requires_integer_condition_and_constant_matching_width_cases() {
        let mut m = switch_module();
        let Terminator::Switch { condition, .. } = &mut m.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        *condition = Operand::Undef { ty: 3 };
        rejects(&m, "switch condition requires an integer");
        for nonconstant in [
            value(7),
            Operand::Undef { ty: 2 },
            Operand::Poison { ty: 2 },
        ] {
            let mut m = switch_module();
            let Terminator::Switch { cases, .. } = &mut m.functions[0].blocks[0].terminator else {
                unreachable!()
            };
            cases[0].value = nonconstant;
            rejects(&m, "switch case requires a typed integer constant");
        }
        let mut m = switch_module();
        let Terminator::Switch { cases, .. } = &mut m.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        cases[0].value = integer(4, 0);
        rejects(&m, "type mismatch");
        let mut m = switch_module();
        let Terminator::Switch { cases, .. } = &mut m.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        cases[0].value = Operand::Int {
            ty: 2,
            bits: "18446744073709551616".into(),
        };
        rejects(&m, "integer constant exceeds its bit width");
    }

    #[test]
    fn switch_case_uniqueness_uses_bit_patterns_not_decimal_spelling() {
        let mut m = switch_module();
        let Terminator::Switch { cases, .. } = &mut m.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        cases[1].value = Operand::Int {
            ty: 2,
            bits: "0000".into(),
        };
        rejects(&m, "duplicate case bit patterns");
        let mut m = switch_module();
        let Terminator::Switch { cases, .. } = &mut m.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        cases[0].value = integer(2, 1);
        cases[1].value = Operand::Int {
            ty: 2,
            bits: "001".into(),
        };
        rejects(&m, "duplicate case bit patterns");
    }

    #[test]
    fn switch_checks_all_targets_and_condition_dominance() {
        let mut m = switch_module();
        let Terminator::Switch { default, .. } = &mut m.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        *default = usize::MAX;
        rejects(&m, "branch targets unknown block");
        let mut m = switch_module();
        let Terminator::Switch { cases, .. } = &mut m.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        cases[2].target = usize::MAX;
        rejects(&m, "branch targets unknown block");
        let mut m = switch_module();
        let Terminator::Switch { condition, .. } = &mut m.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        *condition = value(20);
        rejects(&m, "does not dominate");
    }

    #[test]
    fn switch_preserves_wide_cases_and_rejects_unknown_case_fields() {
        let mut m = switch_module();
        m.types[2] = Type::Int { bits: 257 };
        let Terminator::Switch { cases, .. } = &mut m.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        cases[2].value = Operand::Int {
            ty: 2,
            bits: (BigUint::from(1_u8) << 256_usize).to_string(),
        };
        let bytes = m.to_json().unwrap();
        let restored = NativeModule::from_json(&bytes).unwrap();
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            serde_json::to_value(&restored).unwrap()
        );
        let mut json = serde_json::to_value(&m).unwrap();
        json["functions"][0]["blocks"][0]["terminator"]["cases"][0]["implicit_signedness"] =
            true.into();
        assert!(NativeModule::from_json(&serde_json::to_vec(&json).unwrap())
            .unwrap_err()
            .message
            .contains("unknown field"));
    }

    #[test]
    fn switch_accepts_every_case_in_large_real_world_sized_dispatch() {
        let mut m = switch_module();
        let Terminator::Switch { cases, .. } = &mut m.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        *cases = (0..1922)
            .map(|bits| SwitchCase {
                value: integer(2, bits),
                target: 20,
            })
            .collect();
        verify(&m).unwrap();
        // Equal types may have different table IDs; the width is the contract.
        m.types.push(Type::Int { bits: 64 });
        let equivalent = m.types.len() - 1;
        let Terminator::Switch { cases, .. } = &mut m.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        cases[0].value = integer(equivalent, 0);
        verify(&m).unwrap();
    }

    fn reaches_without(successors: &[Vec<usize>], target: usize, removed: Option<usize>) -> bool {
        if removed == Some(0) {
            return false;
        }
        let mut seen = vec![false; successors.len()];
        let mut stack = vec![0];
        seen[0] = true;
        while let Some(node) = stack.pop() {
            if node == target {
                return true;
            }
            for next in &successors[node] {
                if removed != Some(*next) && !seen[*next] {
                    seen[*next] = true;
                    stack.push(*next);
                }
            }
        }
        false
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(80))]
        #[test]
        fn dominance_matches_independent_node_removal_oracle(masks in prop::collection::vec(any::<u16>(),2..13)) {
            let n=masks.len();let mut successors=vec![vec![];n];let mut predecessors=vec![BTreeSet::new();n];
            for (from, mask) in masks.iter().enumerate() {
                for (to, predecessors) in predecessors.iter_mut().enumerate().skip(1) {
                    if mask & (1 << to) != 0 {
                        successors[from].push(to);
                        predecessors.insert(from);
                    }
                }
            }
            let dom=Dominance::compute(0,&successors,&predecessors);
            for use_block in 0..n {
                if !reaches_without(&successors,use_block,None) {continue;}
                for definition in 0..n {
                    prop_assert_eq!(dom.dominates(definition,use_block), !reaches_without(&successors,use_block,Some(definition)), "def={}, use={}", definition, use_block);
                }
            }
        }
    }
    fn eh_module() -> NativeModule {
        let mut m = module();
        m.types.push(Type::Int { bits: 32 }); // 5
        m.types.push(Type::Struct {
            fields: vec![3, 5],
            packed: false,
        }); // 6
        m.functions[0].exception_handling = Some(ExceptionHandling {
            model: ExceptionModel::ItaniumDwarfV1,
            personality: Operand::Symbol {
                ty: 3,
                name: "personality".into(),
            },
        });
        m.functions[0].blocks = vec![
            Block {
                id: 10,
                instructions: vec![],
                terminator: eh_invoke(8, value(7), 20, 30),
            },
            Block {
                id: 20,
                instructions: vec![],
                terminator: Terminator::Return {
                    value: Some(value(8)),
                },
            },
            eh_landingpad(30, 9),
        ];
        m.functions.push(
            serde_json::from_value(json!({
                "name":"may_throw", "linkage":"external",
                "signature":{"params":[2],"result":2,"abi":"c","variadic":false},
                "params":[{"id":0,"ty":2}],"entry":null,"blocks":[]
            }))
            .unwrap(),
        );
        m.functions.push(
            serde_json::from_value(json!({
                "name":"personality", "linkage":"external",
                "signature":{"params":[],"result":5,"abi":"c","variadic":true},
                "params":[],"entry":null,"blocks":[]
            }))
            .unwrap(),
        );
        m.provenance.source_function_count = m.functions.len();
        m
    }

    fn eh_invoke(id: ValueId, arg: Operand, normal: BlockId, unwind: BlockId) -> Terminator {
        Terminator::Invoke {
            callee: Operand::Symbol {
                ty: 3,
                name: "may_throw".into(),
            },
            signature: Signature {
                params: vec![2],
                result: 2,
                abi: "c".into(),
                variadic: false,
                param_attributes: vec![],
                result_attributes: vec![],
                return_storage: None,
            },
            args: vec![arg],
            result: Some(Value { id, ty: 2 }),
            normal,
            unwind,
        }
    }

    fn eh_landingpad(id: BlockId, result: ValueId) -> Block {
        Block {
            id,
            instructions: vec![Instruction {
                result: Some(Value { id: result, ty: 6 }),
                operation: Operation::LandingPad {
                    cleanup: true,
                    clauses: vec![],
                },
            }],
            terminator: Terminator::Resume {
                value: value(result),
            },
        }
    }

    #[test]
    fn eh_roundtrips_all_three_targets_with_ordered_clauses_and_exact_typeid() {
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "riscv64-unknown-linux-gnu",
        ] {
            let mut m = eh_module();
            m.target.triple = target.into();
            global(&mut m);
            let slot = Operand::Symbol {
                ty: 3,
                name: "slot".into(),
            };
            let clauses = vec![
                ExceptionClause::Catch {
                    typeinfo: slot.clone(),
                },
                ExceptionClause::Filter {
                    typeinfos: vec![slot.clone(), slot.clone()],
                },
                ExceptionClause::Catch {
                    typeinfo: Operand::Null { ty: 3 },
                },
                ExceptionClause::Filter { typeinfos: vec![] },
                ExceptionClause::Catch {
                    typeinfo: slot.clone(),
                },
            ];
            m.functions[0].blocks[2].instructions[0].operation = Operation::LandingPad {
                cleanup: true,
                clauses,
            };
            m.functions[0].blocks[0].instructions.push(Instruction {
                result: Some(Value { id: 11, ty: 5 }),
                operation: Operation::EhTypeId { typeinfo: slot },
            });
            let mut intrinsic = builtin("llvm.eh.typeid.for", &[3]);
            intrinsic.signature.result = 5;
            m.functions.push(intrinsic);
            m.provenance.source_function_count += 1;
            verify(&m).unwrap();
            let restored = NativeModule::from_json(&m.to_json().unwrap()).unwrap();
            let Operation::LandingPad { cleanup, clauses } =
                &restored.functions[0].blocks[2].instructions[0].operation
            else {
                unreachable!()
            };
            assert!(*cleanup);
            assert_eq!(clauses.len(), 5);
            assert!(
                matches!(&clauses[1], ExceptionClause::Filter { typeinfos } if typeinfos.len() == 2)
            );
            assert!(
                matches!(&clauses[3], ExceptionClause::Filter { typeinfos } if typeinfos.is_empty())
            );
            assert!(
                super::super::native_eh::metadata_personality_declarations(&restored)
                    .contains("personality")
            );
        }
    }

    #[test]
    fn invoke_result_phi_uses_normal_edge_without_claiming_destination_dominance() {
        let mut m = eh_module();
        m.functions[0].blocks = vec![
            Block {
                id: 10,
                instructions: vec![],
                terminator: Terminator::Branch {
                    condition: integer(1, 1),
                    on_true: 11,
                    on_false: 12,
                },
            },
            Block {
                id: 11,
                instructions: vec![],
                terminator: eh_invoke(8, value(7), 20, 30),
            },
            Block {
                id: 12,
                instructions: vec![],
                terminator: Terminator::Jump { target: 20 },
            },
            Block {
                id: 20,
                instructions: vec![Instruction {
                    result: Some(Value { id: 40, ty: 2 }),
                    operation: Operation::Phi {
                        incoming: vec![
                            PhiIncoming {
                                block: 11,
                                value: value(8),
                            },
                            PhiIncoming {
                                block: 12,
                                value: integer(2, 7),
                            },
                        ],
                    },
                }],
                terminator: Terminator::Return {
                    value: Some(value(40)),
                },
            },
            eh_landingpad(30, 9),
        ];
        verify(&m).unwrap();
        let mut wrong = m.clone();
        wrong.functions[0].blocks[3].terminator = Terminator::Return {
            value: Some(value(8)),
        };
        rejects(&wrong, "does not dominate");
        let mut wrong = m.clone();
        let Operation::Phi { incoming } =
            &mut wrong.functions[0].blocks[3].instructions[0].operation
        else {
            unreachable!()
        };
        incoming[1].value = value(8);
        rejects(&wrong, "does not dominate");
        let mut wrong = m;
        let Operation::Phi { incoming } =
            &mut wrong.functions[0].blocks[3].instructions[0].operation
        else {
            unreachable!()
        };
        incoming[0].block = 10;
        incoming[0].value = integer(2, 0);
        rejects(&wrong, "phi predecessor set differs");
    }

    #[test]
    fn invoke_normal_edges_dominate_loopbacks_and_same_block_phi_incoming() {
        let mut m = eh_module();
        m.functions[0].blocks = vec![
            Block {
                id: 10,
                instructions: vec![],
                terminator: eh_invoke(8, value(7), 20, 30),
            },
            Block {
                id: 20,
                instructions: vec![],
                terminator: Terminator::Branch {
                    condition: integer(1, 1),
                    on_true: 20,
                    on_false: 40,
                },
            },
            eh_landingpad(30, 9),
            Block {
                id: 40,
                instructions: vec![],
                terminator: Terminator::Return {
                    value: Some(value(8)),
                },
            },
        ];
        verify(&m).unwrap(); // More than one normal-destination predecessor is legal.
        m.functions[0].blocks = vec![
            Block {
                id: 10,
                instructions: vec![],
                terminator: Terminator::Jump { target: 20 },
            },
            Block {
                id: 20,
                instructions: vec![Instruction {
                    result: Some(Value { id: 40, ty: 2 }),
                    operation: Operation::Phi {
                        incoming: vec![
                            PhiIncoming {
                                block: 10,
                                value: integer(2, 0),
                            },
                            PhiIncoming {
                                block: 20,
                                value: value(8),
                            },
                        ],
                    },
                }],
                terminator: eh_invoke(8, value(40), 20, 30),
            },
            eh_landingpad(30, 9),
        ];
        verify(&m).unwrap();
        let Terminator::Invoke { args, .. } = &mut m.functions[0].blocks[1].terminator else {
            unreachable!()
        };
        args[0] = value(8);
        rejects(&m, "does not dominate");
    }

    #[test]
    fn invoke_unwind_can_rejoin_normal_destination_only_through_correct_phi_edges() {
        let mut m = eh_module();
        m.functions[0].blocks[2].terminator = Terminator::Jump { target: 20 };
        m.functions[0].blocks[1].instructions.push(Instruction {
            result: Some(Value { id: 40, ty: 2 }),
            operation: Operation::Phi {
                incoming: vec![
                    PhiIncoming {
                        block: 10,
                        value: value(8),
                    },
                    PhiIncoming {
                        block: 30,
                        value: integer(2, 0),
                    },
                ],
            },
        });
        m.functions[0].blocks[1].terminator = Terminator::Return {
            value: Some(value(40)),
        };
        verify(&m).unwrap();
        let mut wrong = m.clone();
        wrong.functions[0].blocks[1].terminator = Terminator::Return {
            value: Some(value(8)),
        };
        rejects(&wrong, "does not dominate");
        let Operation::Phi { incoming } = &mut m.functions[0].blocks[1].instructions[0].operation
        else {
            unreachable!()
        };
        incoming[1].value = value(8);
        rejects(&m, "does not dominate");
    }

    #[test]
    fn shared_unwind_phi_can_use_previous_invoke_result_but_not_current_result() {
        let mut m = eh_module();
        m.functions[0].blocks[1].terminator = eh_invoke(12, value(8), 40, 30);
        m.functions[0].blocks.push(Block {
            id: 40,
            instructions: vec![],
            terminator: Terminator::Return {
                value: Some(value(12)),
            },
        });
        m.functions[0].blocks[2].instructions.insert(
            0,
            Instruction {
                result: Some(Value { id: 44, ty: 2 }),
                operation: Operation::Phi {
                    incoming: vec![
                        PhiIncoming {
                            block: 10,
                            value: value(7),
                        },
                        PhiIncoming {
                            block: 20,
                            value: value(8),
                        },
                    ],
                },
            },
        );
        verify(&m).unwrap();
        let mut wrong = m.clone();
        let Operation::Phi { incoming } =
            &mut wrong.functions[0].blocks[2].instructions[0].operation
        else {
            unreachable!()
        };
        incoming[0].value = value(8);
        rejects(&wrong, "does not dominate");
        let Operation::Phi { incoming } = &mut m.functions[0].blocks[2].instructions[0].operation
        else {
            unreachable!()
        };
        incoming[1].value = value(12);
        rejects(&m, "does not dominate");
    }

    #[test]
    fn unreachable_invoke_uses_remain_type_checked_and_vacuously_dominated() {
        let mut m = eh_module();
        m.functions[0].blocks.extend([
            Block {
                id: 40,
                instructions: vec![],
                terminator: eh_invoke(100, value(100), 50, 60),
            },
            Block {
                id: 50,
                instructions: vec![],
                terminator: Terminator::Return {
                    value: Some(value(100)),
                },
            },
            eh_landingpad(60, 101),
        ]);
        verify(&m).unwrap();
        let mut wrong = m.clone();
        wrong.functions[0].blocks[1].terminator = Terminator::Return {
            value: Some(value(100)),
        };
        rejects(&wrong, "does not dominate");
        let mut wrong = m.clone();
        let Terminator::Invoke { args, .. } = &mut wrong.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        args[0] = value(8);
        rejects(&wrong, "does not dominate");
        let Terminator::Invoke { args, .. } = &mut m.functions[0].blocks[3].terminator else {
            unreachable!()
        };
        args[0] = integer(1, 1);
        rejects(&m, "type mismatch");
    }

    #[test]
    fn landingpad_cfg_placement_and_resume_pair_are_mandatory_even_in_dead_blocks() {
        let m = eh_module();
        let mut wrong = m.clone();
        wrong.functions[0].exception_handling = None;
        rejects(&wrong, "landingpad requires an exception personality");
        let mut wrong = m.clone();
        wrong.functions[0].blocks[0].terminator = Terminator::Jump { target: 30 };
        rejects(&wrong, "only through invoke unwind edges");
        let mut wrong = m.clone();
        let Terminator::Invoke { normal, .. } = &mut wrong.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        *normal = 30;
        rejects(&wrong, "normal and unwind destinations must differ");
        let mut wrong = m.clone();
        wrong.functions[0].blocks[2].instructions.clear();
        wrong.functions[0].blocks[2].terminator = Terminator::Unreachable;
        rejects(&wrong, "unwind destination must start with a landingpad");
        let mut wrong = m.clone();
        wrong.functions[0].blocks[2].instructions.insert(
            0,
            Instruction {
                result: Some(Value { id: 99, ty: 2 }),
                operation: Operation::Freeze {
                    value: integer(2, 0),
                },
            },
        );
        rejects(&wrong, "first non-phi");
        let mut wrong = m.clone();
        wrong.functions[0].blocks[0].instructions =
            wrong.functions[0].blocks[2].instructions.clone();
        wrong.functions[0].blocks[0].instructions[0]
            .result
            .as_mut()
            .unwrap()
            .id = 99;
        rejects(&wrong, "cannot be in the entry block");
        let mut wrong = m.clone();
        wrong.functions[0].blocks[2].instructions[0].operation = Operation::LandingPad {
            cleanup: false,
            clauses: vec![],
        };
        rejects(&wrong, "cleanup or at least one clause");
        let mut wrong = m.clone();
        wrong.types[6] = Type::Struct {
            fields: vec![3, 5],
            packed: true,
        };
        rejects(&wrong, "original unpacked");
        let mut wrong = m.clone();
        wrong.functions[0].blocks[2].terminator = Terminator::Resume { value: value(7) };
        rejects(&wrong, "resume requires original unpacked");
        let mut wrong = m;
        wrong.functions[0].blocks.push(Block {
            id: 90,
            instructions: vec![],
            terminator: Terminator::Resume {
                value: Operand::Undef { ty: 2 },
            },
        });
        rejects(&wrong, "resume requires original unpacked");
    }

    #[test]
    fn invoke_call_signatures_and_ssa_result_inventory_are_not_relaxed() {
        let m = eh_module();
        let mut wrong = m.clone();
        let Terminator::Invoke { result, .. } = &mut wrong.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        *result = None;
        rejects(&wrong, "call requires an SSA result");
        let mut wrong = m.clone();
        let Terminator::Invoke { result, .. } = &mut wrong.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        result.as_mut().unwrap().id = 7;
        rejects(&wrong, "duplicate SSA definition");
        let mut wrong = m.clone();
        let Terminator::Invoke { args, .. } = &mut wrong.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        args.clear();
        rejects(&wrong, "call argument count");
        let mut wrong = m.clone();
        let Terminator::Invoke { signature, .. } = &mut wrong.functions[0].blocks[0].terminator
        else {
            unreachable!()
        };
        signature.abi = "fast".into();
        rejects(&wrong, "direct callee symbol/signature mismatch");
        let mut good = m;
        good.functions[1].signature.result = 0;
        let Terminator::Invoke {
            signature, result, ..
        } = &mut good.functions[0].blocks[0].terminator
        else {
            unreachable!()
        };
        signature.result = 0;
        *result = None;
        good.functions[0].blocks[1].terminator = Terminator::Return {
            value: Some(integer(2, 5)),
        };
        verify(&good).unwrap();
        let Terminator::Invoke { result, .. } = &mut good.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        *result = Some(Value { id: 8, ty: 2 });
        rejects(&good, "void call defines a value");
    }

    #[test]
    fn exception_typeinfo_profile_preserves_null_named_identity_and_filter_order() {
        let m = eh_module();
        for typeinfo in [
            value(7),
            Operand::PointerBits {
                ty: 3,
                bits: "0".into(),
            },
            Operand::Poison { ty: 3 },
            Operand::SymbolOffset {
                ty: 3,
                name: "may_throw".into(),
                addend: 8,
            },
        ] {
            let mut wrong = m.clone();
            wrong.functions[0].blocks[2].instructions[0].operation = Operation::LandingPad {
                cleanup: false,
                clauses: vec![ExceptionClause::Catch { typeinfo }],
            };
            rejects(&wrong, "null or a named zero-offset");
        }
        let mut wrong = m.clone();
        wrong.functions[0].blocks[2].instructions[0].operation = Operation::LandingPad {
            cleanup: false,
            clauses: vec![ExceptionClause::Filter {
                typeinfos: vec![Operand::Null { ty: 3 }],
            }],
        };
        rejects(&wrong, "filter entries require named");
        let mut wrong = m.clone();
        wrong.types.push(Type::Pointer { address_space: 1 });
        wrong.functions[0].blocks[2].instructions[0].operation = Operation::LandingPad {
            cleanup: false,
            clauses: vec![ExceptionClause::Catch {
                typeinfo: Operand::Null { ty: 7 },
            }],
        };
        rejects(&wrong, "address-space-zero");
        let mut wrong = m.clone();
        global(&mut wrong);
        wrong.globals[0].name = "llvm.eh.catch.all.value".into();
        wrong.functions[0].blocks[2].instructions[0].operation = Operation::LandingPad {
            cleanup: false,
            clauses: vec![ExceptionClause::Catch {
                typeinfo: Operand::Symbol {
                    ty: 3,
                    name: "llvm.eh.catch.all.value".into(),
                },
            }],
        };
        rejects(&wrong, "verified initializer normalization");
        let mut no_eh = module();
        no_eh.types.push(Type::Int { bits: 32 });
        no_eh.functions[0].blocks[0].instructions.push(Instruction {
            result: Some(Value { id: 99, ty: 5 }),
            operation: Operation::EhTypeId {
                typeinfo: Operand::Null { ty: 3 },
            },
        });
        verify(&no_eh).unwrap(); // The intrinsic itself does not require a personality.
        no_eh.functions[0].blocks[0]
            .instructions
            .last_mut()
            .unwrap()
            .result
            .as_mut()
            .unwrap()
            .ty = 2;
        rejects(&no_eh, "typeid result requires i32");
    }

    #[test]
    fn metadata_personality_cannot_escape_via_calls_cold_operands_relocations_or_aliases() {
        let m = eh_module();
        assert_eq!(
            super::super::native_eh::metadata_personality_declarations(&m),
            BTreeSet::from(["personality".to_owned()])
        );
        let signature = m.functions[2].signature.clone();
        let mut wrong = m.clone();
        wrong.functions[0].blocks.push(Block {
            id: 80,
            instructions: vec![Instruction {
                result: Some(Value { id: 80, ty: 5 }),
                operation: Operation::Call {
                    callee: Operand::Symbol {
                        ty: 3,
                        name: "personality".into(),
                    },
                    signature,
                    args: vec![],
                },
            }],
            terminator: Terminator::Return {
                value: Some(integer(2, 0)),
            },
        });
        rejects(&wrong, "metadata-only i32(...)");
        let mut wrong = m.clone();
        global(&mut wrong);
        wrong.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .relocations
            .push(Relocation {
                offset: 0,
                width: 64,
                symbol: "personality".into(),
                addend: 0,
                relative_to: None,
            });
        rejects(&wrong, "metadata-only i32(...)");
        let mut scanned = m.clone();
        scanned.functions[0].blocks[1].terminator = Terminator::Return {
            value: Some(Operand::Aggregate {
                ty: 6,
                elements: vec![
                    Operand::Symbol {
                        ty: 3,
                        name: "personality".into(),
                    },
                    integer(5, 0),
                ],
            }),
        };
        assert!(super::super::native_eh::metadata_personality_declarations(&scanned).is_empty());
        let mut scanned = m.clone();
        scanned.functions[0].blocks[1]
            .instructions
            .push(Instruction {
                result: Some(Value { id: 99, ty: 3 }),
                operation: Operation::Phi {
                    incoming: vec![PhiIncoming {
                        block: 10,
                        value: Operand::Symbol {
                            ty: 3,
                            name: "personality".into(),
                        },
                    }],
                },
            });
        assert!(super::super::native_eh::metadata_personality_declarations(&scanned).is_empty());
        let mut scanned = m;
        scanned.aliases.push(Alias {
            name: "personality_alias".into(),
            ty: 3,
            aliasee: "personality".into(),
            linkage: "external".into(),
            visibility: Visibility::Default,
        });
        assert!(super::super::native_eh::metadata_personality_declarations(&scanned).is_empty());
    }

    #[test]
    fn actual_fixed_personality_callbacks_keep_their_ordinary_five_argument_abi() {
        let mut m = eh_module();
        m.functions[2].signature.variadic = false;
        m.functions[2].signature.params = vec![5, 5, 2, 3, 3];
        m.functions[2].params = [5, 5, 2, 3, 3]
            .iter()
            .enumerate()
            .map(|(id, ty)| Value { id, ty: *ty })
            .collect();
        let callback_signature = m.functions[2].signature.clone();
        m.functions[0].blocks[0].instructions.push(Instruction {
            result: Some(Value { id: 90, ty: 5 }),
            operation: Operation::Call {
                callee: Operand::Symbol {
                    ty: 3,
                    name: "personality".into(),
                },
                signature: callback_signature,
                args: vec![
                    integer(5, 1),
                    integer(5, 2),
                    integer(2, 0),
                    Operand::Null { ty: 3 },
                    Operand::Null { ty: 3 },
                ],
            },
        });
        verify(&m).unwrap();
        assert!(super::super::native_eh::metadata_personality_declarations(&m).is_empty());
        let mut defined = m.clone();
        defined.functions[2].entry = Some(10);
        defined.functions[2].blocks = vec![Block {
            id: 10,
            instructions: vec![],
            terminator: Terminator::Return {
                value: Some(integer(5, 8)),
            },
        }];
        verify(&defined).unwrap();
        let mut wrong = m.clone();
        wrong.functions[2].signature.params[1] = 2;
        wrong.functions[2].params[1].ty = 2;
        rejects(&wrong, "five-argument C unwinder callback ABI");
        let mut wrong = m;
        wrong.functions[0]
            .exception_handling
            .as_mut()
            .unwrap()
            .personality = Operand::SymbolOffset {
            ty: 3,
            name: "personality".into(),
            addend: 1,
        };
        rejects(&wrong, "named zero-offset source function");
    }

    #[test]
    fn resume_generated_interface_rejects_local_or_incompatible_source_shadows() {
        let m = eh_module();
        let mut declared = m.clone();
        declared.functions.push(
            serde_json::from_value(json!({
                "name":"_Unwind_Resume","linkage":"external",
                "signature":{"params":[3],"result":0,"abi":"c","variadic":false},
                "params":[{"id":0,"ty":3}],"entry":null,"blocks":[]
            }))
            .unwrap(),
        );
        declared.provenance.source_function_count += 1;
        verify(&declared).unwrap();
        for contract in [
            "linkage",
            "visibility",
            "variadic",
            "result",
            "params",
            "abi",
        ] {
            let mut wrong = declared.clone();
            match contract {
                "linkage" => {
                    wrong.functions[3].linkage = "internal".into();
                    wrong.functions[3].entry = Some(1);
                    wrong.functions[3].blocks = vec![Block {
                        id: 1,
                        instructions: vec![],
                        terminator: Terminator::Return { value: None },
                    }];
                }
                "visibility" => wrong.functions[3].visibility = Visibility::Hidden,
                "variadic" => wrong.functions[3].signature.variadic = true,
                "result" => wrong.functions[3].signature.result = 2,
                "params" => wrong.functions[3].signature.params[0] = 2,
                "abi" => wrong.functions[3].signature.abi = "fast".into(),
                _ => unreachable!(),
            }
            rejects(&wrong, "_Unwind_Resume requires");
        }
        let mut wrong = m;
        global(&mut wrong);
        wrong.globals[0].name = "_Unwind_Resume".into();
        rejects(&wrong, "must be a compatible external function");
    }

    fn owned_typeid_module(name: &str) -> NativeModule {
        let mut m = module();
        m.types.push(Type::Int { bits: 32 });
        let mut declaration = builtin(name, &[3]);
        declaration.signature.result = 5;
        m.functions.push(declaration);
        m.provenance.source_function_count += 1;
        m.functions[0].blocks[0].instructions.push(Instruction {
            result: Some(Value { id: 99, ty: 5 }),
            operation: Operation::EhTypeId {
                typeinfo: Operand::Null { ty: 3 },
            },
        });
        m
    }

    #[test]
    fn canonical_pointer_overloaded_typeid_keeps_its_name_and_owned_operation_on_all_isas() {
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "riscv64-unknown-linux-gnu",
        ] {
            for name in ["llvm.eh.typeid.for.p0", "llvm.eh.typeid.for"] {
                let mut m = owned_typeid_module(name);
                m.target.triple = target.into();
                verify(&m).unwrap();
                assert!(is_builtin_intrinsic(name));
                let before = m.to_json().unwrap();
                let restored = NativeModule::from_json(&before).unwrap();
                assert_eq!(restored.functions[1].name, name);
                assert_eq!(restored.functions[1].intrinsic.as_deref(), Some(name));
                assert_eq!(restored.functions.len(), 2);
                assert_eq!(restored.provenance.source_function_count, 2);
                assert!(matches!(
                    restored.functions[0].blocks[0]
                        .instructions
                        .last()
                        .unwrap()
                        .operation,
                    Operation::EhTypeId { .. }
                ));
                assert_eq!(restored.to_json().unwrap(), before);
            }
        }
    }

    #[test]
    fn canonical_typeid_declaration_requires_exact_c_i32_as0_pointer_contract() {
        let m = owned_typeid_module("llvm.eh.typeid.for.p0");
        for mutation in [
            "abi",
            "variadic",
            "void_result",
            "wide_result",
            "integer_parameter",
            "as1_parameter",
            "missing_parameter",
            "result_attribute",
            "marker",
            "missing_marker",
            "hidden",
            "protected",
            "linkage",
        ] {
            let mut wrong = m.clone();
            match mutation {
                "abi" => wrong.functions[1].signature.abi = "fast".into(),
                "variadic" => wrong.functions[1].signature.variadic = true,
                "void_result" => wrong.functions[1].signature.result = 0,
                "wide_result" => wrong.functions[1].signature.result = 2,
                "integer_parameter" => {
                    wrong.functions[1].signature.params[0] = 2;
                    wrong.functions[1].params[0].ty = 2;
                }
                "as1_parameter" => {
                    wrong.types.push(Type::Pointer { address_space: 1 });
                    wrong.functions[1].signature.params[0] = 6;
                    wrong.functions[1].params[0].ty = 6;
                }
                "missing_parameter" => {
                    wrong.functions[1].signature.params.clear();
                    wrong.functions[1].params.clear();
                }
                "result_attribute" => {
                    wrong.functions[1].signature.result_attributes = vec!["zeroext".into()]
                }
                "marker" => wrong.functions[1].intrinsic = Some("llvm.eh.typeid.for".into()),
                "missing_marker" => wrong.functions[1].intrinsic = None,
                "hidden" => wrong.functions[1].visibility = Visibility::Hidden,
                "protected" => wrong.functions[1].visibility = Visibility::Protected,
                "linkage" => wrong.functions[1].linkage = "weak".into(),
                _ => unreachable!(),
            }
            rejects(&wrong, "invalid or unsupported intrinsic declaration");
        }
        let mut wrong = m;
        wrong.functions[1].signature.param_attributes = vec![vec!["signext".into()]];
        rejects(&wrong, "integer extension attribute requires an integer");
        for name in [
            "llvm.eh.typeid.for.p1",
            "llvm.eh.typeid.for.p00",
            "llvm.eh.typeid.for.p0.i32",
            "llvm.eh.typeid.for.extra",
        ] {
            assert!(!is_builtin_intrinsic(name));
            rejects(
                &owned_typeid_module(name),
                "invalid or unsupported intrinsic declaration",
            );
        }
    }

    #[test]
    fn canonical_typeid_address_cannot_escape_or_become_an_ordinary_native_call() {
        let m = owned_typeid_module("llvm.eh.typeid.for.p0");
        for callee in [
            Operand::Symbol {
                ty: 3,
                name: "llvm.eh.typeid.for.p0".into(),
            },
            Operand::SymbolOffset {
                ty: 3,
                name: "llvm.eh.typeid.for.p0".into(),
                addend: 0,
            },
        ] {
            let mut wrong = m.clone();
            wrong.functions[0].blocks[0].instructions.push(Instruction {
                result: Some(Value { id: 100, ty: 3 }),
                operation: Operation::Freeze {
                    value: callee.clone(),
                },
            });
            rejects(&wrong, "intrinsic address cannot escape");
            let mut wrong = m.clone();
            wrong.functions[0].blocks[0].instructions.push(Instruction {
                result: Some(Value { id: 100, ty: 5 }),
                operation: Operation::Call {
                    callee,
                    signature: m.functions[1].signature.clone(),
                    args: vec![Operand::Null { ty: 3 }],
                },
            });
            rejects(&wrong, "intrinsic address cannot escape");
        }
        let mut wrong = m;
        global(&mut wrong);
        wrong.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .relocations
            .push(Relocation {
                offset: 0,
                width: 64,
                symbol: "llvm.eh.typeid.for.p0".into(),
                addend: 0,
                relative_to: None,
            });
        rejects(&wrong, "intrinsic address");
    }

    fn relative_initializer_module() -> NativeModule {
        let mut m = module();
        m.types.push(Type::Int { bits: 32 });
        m.types.push(Type::Array { element: 5, len: 4 });
        m.types.push(Type::Function {
            signature: m.functions[0].signature.clone(),
        });
        m.globals = serde_json::from_value(json!([
            {"name":"relative_table","ty":6,"linkage":"private","alignment":4,"constant":true,"thread_local":false,
             "initializer":{"bytes":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"relocations":[
                 {"offset":0,"width":32,"symbol":"cold_external","addend":0,"relative_to":"relative_table"},
                 {"offset":4,"width":32,"symbol":"choose","addend":7,"relative_to":"relative_table"},
                 {"offset":8,"width":32,"symbol":"cold_function_alias","addend":-3,"relative_to":"relative_table"},
                 {"offset":12,"width":32,"symbol":"cold_local","addend":0,"relative_to":"relative_table"}]}},
            {"name":"cold_external","ty":4,"linkage":"external","alignment":1,"constant":true,"thread_local":false,"initializer":null},
            {"name":"cold_local","ty":4,"linkage":"private","alignment":1,"constant":true,"thread_local":false,
             "initializer":{"bytes":[91],"relocations":[]}}
        ])).unwrap();
        m.aliases = vec![Alias {
            name: "cold_function_alias".into(),
            ty: 7,
            aliasee: "choose".into(),
            linkage: "external".into(),
            visibility: Visibility::Default,
        }];
        m.provenance.source_global_count = m.globals.len();
        m.provenance.source_alias_count = m.aliases.len();
        m
    }

    #[test]
    fn relative_initializers_preserve_all_cold_symbols_and_signed_addends_on_all_isas() {
        for triple in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "riscv64-unknown-linux-gnu",
        ] {
            for linkage in ["private", "internal"] {
                let mut m = relative_initializer_module();
                m.target.triple = triple.into();
                m.globals[0].linkage = linkage.into();
                let source = serde_json::to_vec(&m).unwrap();
                verify(&m).unwrap();
                assert_eq!(serde_json::to_vec(&m).unwrap(), source);
                let restored = NativeModule::from_json(&source).unwrap();
                assert_eq!(restored.globals.len(), 3);
                assert_eq!(restored.aliases[0].aliasee, "choose");
                let slots = &restored.globals[0]
                    .initializer
                    .as_ref()
                    .unwrap()
                    .relocations;
                assert_eq!(slots.len(), 4);
                assert_eq!(slots[1].symbol, "choose");
                assert_eq!(slots[1].addend, 7);
                assert_eq!(slots[2].symbol, "cold_function_alias");
                assert_eq!(slots[2].addend, -3);
                assert!(slots
                    .iter()
                    .all(|r| r.relative_to.as_deref() == Some("relative_table")));
            }
        }
    }

    #[test]
    fn relative_initializers_reject_nonlocal_wrong_width_base_tls_and_intrinsic_targets() {
        for width in [8, 16, 24, 64] {
            let mut m = relative_initializer_module();
            m.globals[0].initializer.as_mut().unwrap().relocations[0].width = width;
            rejects(&m, "relative relocation requires exactly 32 bits");
        }
        for base in ["missing", "cold_local", "choose", "cold_function_alias", ""] {
            let mut m = relative_initializer_module();
            m.globals[0].initializer.as_mut().unwrap().relocations[0].relative_to =
                Some(base.into());
            rejects(&m, "base must be its containing global");
        }
        for linkage in ["external", "weak", "linkonce_odr"] {
            let mut m = relative_initializer_module();
            m.globals[0].linkage = linkage.into();
            rejects(&m, "initialized private/internal non-TLS global");
        }
        let mut m = relative_initializer_module();
        m.globals[0].thread_local = true;
        rejects(&m, "TLS storage requires an explicit native TLS profile");
        let mut m = relative_initializer_module();
        m.globals[2].thread_local = true;
        rejects(
            &m,
            "initializer cannot contain a static address of TLS storage",
        );
        let mut m = relative_initializer_module();
        m.globals[0].initializer.as_mut().unwrap().relocations[0].symbol = "missing".into();
        rejects(&m, "unknown symbol");
        let mut m = relative_initializer_module();
        m.functions.push(builtin("llvm.assume", &[1]));
        m.provenance.source_function_count += 1;
        m.globals[0].initializer.as_mut().unwrap().relocations[0].symbol = "llvm.assume".into();
        rejects(&m, "intrinsic address");
    }

    #[test]
    fn relative_initializers_require_integral_as0_little_endian_64_bit_indices() {
        for layout in [
            "e-p:32:32",
            "e-p:64:64:64:32",
            "e-p:64:64-ni:1",
            "e-p:64:64-A1",
            "e-p:64:64-P1",
            "e-p:64:64-G1",
        ] {
            let mut m = relative_initializer_module();
            m.target.data_layout = layout.into();
            if layout == "e-p:32:32" {
                m.target.pointer_bits = 32;
            }
            rejects(
                &m,
                "integral AS0 little-endian 64-bit pointer/index profile",
            );
        }
        let mut m = relative_initializer_module();
        m.target.little_endian = false;
        m.target.data_layout = "E-p:64:64".into();
        rejects(
            &m,
            "integral AS0 little-endian 64-bit pointer/index profile",
        );
    }

    #[test]
    fn relative_and_absolute_slots_keep_extent_overlap_and_serde_contracts() {
        let mut m = relative_initializer_module();
        let slots = &mut m.globals[0].initializer.as_mut().unwrap().relocations;
        slots.truncate(2);
        slots.push(Relocation {
            offset: 8,
            width: 64,
            symbol: "choose".into(),
            addend: 9,
            relative_to: None,
        });
        verify(&m).unwrap();
        let mut old = serde_json::to_value(&m).unwrap();
        old["globals"][0]["initializer"]["relocations"][2]
            .as_object_mut()
            .unwrap()
            .remove("relative_to");
        let restored = NativeModule::from_json(&serde_json::to_vec(&old).unwrap()).unwrap();
        assert_eq!(
            restored.globals[0]
                .initializer
                .as_ref()
                .unwrap()
                .relocations[2]
                .relative_to,
            None
        );
        // Absolute verifier widths remain independent of the emitter profile.
        let mut absolute = m.clone();
        absolute.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .relocations[2]
            .width = 32;
        verify(&absolute).unwrap();
        let mut invalid = m.clone();
        invalid.globals[0].initializer.as_mut().unwrap().relocations[1].offset = 2;
        rejects(&invalid, "overlapping relocations");
        let mut invalid = relative_initializer_module();
        invalid.globals[0].initializer.as_mut().unwrap().relocations[3].offset = 14;
        rejects(&invalid, "extends beyond initializer");
        for bad in [
            json!(1),
            json!(["relative_table"]),
            json!({"symbol":"relative_table"}),
        ] {
            let mut input = old.clone();
            input["globals"][0]["initializer"]["relocations"][0]["relative_to"] = bad;
            assert!(serde_json::from_value::<NativeModule>(input).is_err());
        }
        let mut input = old;
        input["globals"][0]["initializer"]["relocations"][0]["relative_addend"] = json!(0);
        assert!(serde_json::from_value::<NativeModule>(input).is_err());
    }

    fn relative_load_declaration_module(bits: u16) -> NativeModule {
        let mut m = module();
        m.types.push(Type::Int { bits });
        let mut f = builtin(&format!("llvm.load.relative.i{bits}"), &[3, 5]);
        f.signature.result = 3;
        m.functions.push(f);
        m.provenance.source_function_count += 1;
        m
    }

    #[test]
    fn exact_relative_load_declarations_are_owned_without_invented_native_calls() {
        for bits in [32, 64] {
            for triple in [
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
                "riscv64-unknown-linux-gnu",
            ] {
                let mut m = relative_load_declaration_module(bits);
                m.target.triple = triple.into();
                let source = serde_json::to_vec(&m).unwrap();
                verify(&m).unwrap();
                assert!(is_builtin_intrinsic(&m.functions[1].name));
                assert_eq!(
                    m.functions[1].intrinsic.as_deref(),
                    Some(m.functions[1].name.as_str())
                );
                assert_eq!(serde_json::to_vec(&m).unwrap(), source);
                assert_eq!(m.provenance.source_function_count, 2);
            }
        }
        for name in [
            "llvm.load.relative",
            "llvm.load.relative.i8",
            "llvm.load.relative.i032",
            "llvm.load.relative.i128",
            "llvm.load.relative.i64.p0",
            "llvm.load.relative.p1.i64",
        ] {
            assert!(!is_builtin_intrinsic(name));
            let mut m = relative_load_declaration_module(64);
            m.functions[1].name = name.into();
            m.functions[1].intrinsic = Some(name.into());
            rejects(&m, "invalid or unsupported intrinsic declaration");
        }
    }

    #[test]
    fn relative_load_declarations_reject_wrong_signatures_abi_and_escapes() {
        for bits in [32, 64] {
            for case in [
                "result",
                "offset",
                "base",
                "params",
                "abi",
                "variadic",
                "linkage",
                "visibility",
                "marker",
                "attributes",
            ] {
                let mut m = relative_load_declaration_module(bits);
                let f = &mut m.functions[1];
                match case {
                    "result" => f.signature.result = 2,
                    "offset" => {
                        f.signature.params[1] = 4;
                        f.params[1].ty = 4;
                    }
                    "base" => {
                        f.signature.params[0] = 2;
                        f.params[0].ty = 2;
                    }
                    "params" => {
                        f.signature.params.pop();
                        f.params.pop();
                    }
                    "abi" => f.signature.abi = "ocore".into(),
                    "variadic" => f.signature.variadic = true,
                    "linkage" => f.linkage = "internal".into(),
                    "visibility" => f.visibility = Visibility::Hidden,
                    "marker" => f.intrinsic = None,
                    "attributes" => f.signature.result_attributes = vec!["nonnull".into()],
                    _ => unreachable!(),
                }
                assert!(
                    verify(&m).is_err(),
                    "invalid relative intrinsic accepted: {bits}/{case}"
                );
            }
            let mut m = relative_load_declaration_module(bits);
            m.types[3] = Type::Pointer { address_space: 1 };
            rejects(&m, "invalid or unsupported intrinsic declaration");
            let m = relative_load_declaration_module(bits);
            for callee in [
                Operand::Symbol {
                    ty: 3,
                    name: m.functions[1].name.clone(),
                },
                Operand::SymbolOffset {
                    ty: 3,
                    name: m.functions[1].name.clone(),
                    addend: 0,
                },
            ] {
                let mut invalid = m.clone();
                invalid.functions[0].blocks[0]
                    .instructions
                    .push(Instruction {
                        result: Some(Value { id: 93, ty: 3 }),
                        operation: Operation::Freeze {
                            value: callee.clone(),
                        },
                    });
                rejects(&invalid, "intrinsic address");
                let mut invalid = m.clone();
                let signature = invalid.functions[1].signature.clone();
                invalid.functions[0].blocks[0]
                    .instructions
                    .push(Instruction {
                        result: Some(Value { id: 93, ty: 3 }),
                        operation: Operation::Call {
                            callee,
                            signature,
                            args: vec![Operand::Null { ty: 3 }, integer(5, 0)],
                        },
                    });
                rejects(&invalid, "intrinsic address");
            }
            let mut invalid = m.clone();
            global(&mut invalid);
            invalid.globals[0]
                .initializer
                .as_mut()
                .unwrap()
                .relocations
                .push(Relocation {
                    offset: 0,
                    width: 64,
                    symbol: m.functions[1].name.clone(),
                    addend: 0,
                    relative_to: None,
                });
            rejects(&invalid, "intrinsic address");
        }
    }

    fn tls_signature(params: &[TypeId], result: TypeId) -> Signature {
        Signature {
            params: params.to_vec(),
            result,
            abi: "c".into(),
            variadic: false,
            param_attributes: vec![],
            result_attributes: vec![],
            return_storage: None,
        }
    }

    fn tls_module(triple: &str) -> NativeModule {
        let mut m = module();
        m.target.triple = triple.into();
        m.target.tls_profile = Some(TlsProfile::LinuxElfStaticNonpreemptiveV1);
        global(&mut m);
        m.globals[0].name = "tls_counter".into();
        m.globals[0].thread_local = true;
        m.globals[0].tls_model = Some(TlsModel::GeneralDynamic);
        m.functions[0].signature = tls_signature(&[], 3);
        m.functions[0].params.clear();
        m.functions[0].entry = Some(10);
        m.functions[0].blocks = vec![Block {
            id: 10,
            instructions: vec![Instruction {
                result: Some(Value { id: 77, ty: 3 }),
                operation: Operation::ThreadLocalAddress {
                    global: "tls_counter".into(),
                },
            }],
            terminator: Terminator::Return {
                value: Some(value(77)),
            },
        }];
        m
    }

    #[test]
    fn tls_profile_preserves_all_source_models_and_cold_declarations_on_each_linux_isa() {
        for triple in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "riscv64-unknown-linux-gnu",
        ] {
            for model in [
                TlsModel::GeneralDynamic,
                TlsModel::LocalDynamic,
                TlsModel::InitialExec,
                TlsModel::LocalExec,
            ] {
                for constant in [false, true] {
                    let mut m = tls_module(triple);
                    m.globals[0].tls_model = Some(model);
                    m.globals[0].constant = constant;
                    let mut declaration = m.globals[0].clone();
                    declaration.name = "cold_tls_provider".into();
                    declaration.initializer = None;
                    declaration.tls_model = Some(TlsModel::InitialExec);
                    m.globals.push(declaration);
                    m.provenance.source_global_count += 1;
                    m.functions[0].blocks.push(Block {
                        id: 999,
                        instructions: vec![Instruction {
                            result: Some(Value { id: 999, ty: 3 }),
                            operation: Operation::ThreadLocalAddress {
                                global: "cold_tls_provider".into(),
                            },
                        }],
                        terminator: Terminator::Return {
                            value: Some(value(999)),
                        },
                    });
                    let before = serde_json::to_value(&m).unwrap();
                    verify(&m).unwrap();
                    assert_eq!(serde_json::to_value(&m).unwrap(), before);
                    let restored =
                        NativeModule::from_json(&serde_json::to_vec(&m).unwrap()).unwrap();
                    assert_eq!(restored.globals[0].tls_model, Some(model));
                    assert_eq!(restored.provenance.source_global_count, 2);
                    assert!(instruction_operands(
                        &restored.functions[0].blocks[0].instructions[0].operation
                    )
                    .is_empty());
                }
            }
        }
        for triple in [
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
            "riscv64-unknown-linux-musl",
        ] {
            verify(&tls_module(triple)).unwrap();
        }
        for abi in [None, Some("lp64"), Some("lp64d")] {
            let mut m = tls_module("riscv64-unknown-linux-gnu");
            m.target.abi = abi.map(str::to_owned);
            verify(&m).unwrap();
        }
    }

    #[test]
    fn tls_requires_explicit_profile_model_and_exact_linux_pointer_layout_even_when_cold() {
        let good = tls_module("x86_64-unknown-linux-gnu");
        let mut invalid = good.clone();
        invalid.target.tls_profile = None;
        rejects(
            &invalid,
            "TLS storage requires an explicit native TLS profile",
        );
        invalid = good.clone();
        invalid.globals[0].tls_model = None;
        rejects(&invalid, "original access model");
        invalid = good.clone();
        invalid.globals[0].thread_local = false;
        rejects(&invalid, "TLS access model requires thread-local storage");
        for triple in [
            "x86_64-unknown-none",
            "aarch64-apple-darwin",
            "riscv64-unknown-none",
            "i686-unknown-linux-gnu",
            "aarch64_be-unknown-linux-gnu",
            "x86_64-unknown-none-linux-gnu",
        ] {
            invalid = good.clone();
            invalid.target.triple = triple.into();
            rejects(&invalid, "native TLS profile requires Linux");
        }
        for layout in [
            "e-p:32:32-i64:64",
            "e-p:64:64:64:32-i64:64",
            "e-p:64:64-i64:64-ni:1",
            "e-p:64:64-i64:64-A1",
            "e-p:64:64-i64:64-P1",
            "e-p:64:64-i64:64-G1",
        ] {
            invalid = good.clone();
            invalid.target.data_layout = layout.into();
            if layout.contains("p:32") {
                invalid.target.pointer_bits = 32;
            }
            rejects(&invalid, "native TLS profile requires Linux");
        }
        invalid = good.clone();
        invalid.target.data_layout = "E-p:64:64-i64:64".into();
        invalid.target.little_endian = false;
        rejects(&invalid, "native TLS profile requires Linux");
        invalid = tls_module("riscv64-unknown-linux-gnu");
        invalid.target.abi = Some("ilp32".into());
        rejects(&invalid, "native TLS profile requires Linux");
        for (owner, field, text) in [
            ("target", "tls_profile", "linux_dynamic_v1"),
            ("global", "tls_model", "emulated"),
        ] {
            let mut json = serde_json::to_value(&good).unwrap();
            if owner == "target" {
                json["target"][field] = json!(text);
            } else {
                json["globals"][0][field] = json!(text);
            }
            assert!(serde_json::from_value::<NativeModule>(json).is_err());
        }
        // An unused declared execution profile is still a checked contract.
        invalid = module();
        invalid.target.tls_profile = Some(TlsProfile::LinuxElfStaticNonpreemptiveV1);
        invalid.target.triple = "x86_64-unknown-none".into();
        rejects(&invalid, "native TLS profile requires Linux");
    }

    #[test]
    fn current_thread_address_requires_exact_tls_identity_and_pointer_ssa_result() {
        let good = tls_module("x86_64-unknown-linux-gnu");
        for name in ["missing", "choose"] {
            let mut invalid = good.clone();
            invalid.functions[0].blocks[0].instructions[0].operation =
                Operation::ThreadLocalAddress {
                    global: name.into(),
                };
            rejects(
                &invalid,
                "current-thread address requires an included TLS global",
            );
        }
        let mut invalid = good.clone();
        global(&mut invalid);
        invalid.functions[0].blocks[0].instructions[0].operation = Operation::ThreadLocalAddress {
            global: "slot".into(),
        };
        rejects(
            &invalid,
            "current-thread address requires an included TLS global",
        );
        for ty in [1, 2] {
            invalid = good.clone();
            invalid.functions[0].blocks[0].instructions[0].result = Some(Value { id: 77, ty });
            rejects(
                &invalid,
                "current-thread address result requires an address-space-zero pointer",
            );
        }
        invalid = good.clone();
        invalid.functions[0].blocks[0].instructions[0].result = Some(Value { id: 77, ty: 0 });
        rejects(&invalid, "type 0 is unsized");
        invalid = good.clone();
        let ty = invalid.types.len();
        invalid.types.push(Type::Pointer { address_space: 1 });
        invalid.functions[0].blocks[0].instructions[0].result = Some(Value { id: 77, ty });
        rejects(
            &invalid,
            "current-thread address result requires an address-space-zero pointer",
        );
        invalid = good.clone();
        invalid.functions[0].blocks[0].instructions[0].result = None;
        rejects(&invalid, "instruction requires an SSA result");
        // The explicit operation itself cannot be used outside its profile,
        // even when there is no TLS definition that would diagnose it first.
        invalid = module();
        invalid.functions[0].blocks[0]
            .instructions
            .push(Instruction {
                result: Some(Value { id: 999, ty: 3 }),
                operation: Operation::ThreadLocalAddress {
                    global: "missing".into(),
                },
            });
        rejects(
            &invalid,
            "current-thread address requires an explicit native TLS profile",
        );
        let mut json = serde_json::to_value(&good).unwrap();
        json["functions"][0]["blocks"][0]["instructions"][0]["operation"]["offset"] = json!(0);
        assert!(serde_json::from_value::<NativeModule>(json).is_err());
    }

    #[test]
    fn raw_tls_symbol_pointers_reject_in_dead_nested_phi_and_initializer_uses() {
        let good = tls_module("x86_64-unknown-linux-gnu");
        let symbols = [
            Operand::Symbol {
                ty: 3,
                name: "tls_counter".into(),
            },
            Operand::SymbolOffset {
                ty: 3,
                name: "tls_counter".into(),
                addend: 0,
            },
            Operand::SymbolOffset {
                ty: 3,
                name: "tls_counter".into(),
                addend: i64::MIN,
            },
        ];
        for symbol in symbols {
            let mut invalid = good.clone();
            invalid.functions[0].blocks.push(Block {
                id: 999,
                instructions: vec![],
                terminator: Terminator::Return {
                    value: Some(symbol.clone()),
                },
            });
            rejects(
                &invalid,
                "TLS symbol address requires a current-thread address operation",
            );
            invalid = good.clone();
            let ty = invalid.types.len();
            invalid.types.push(Type::Struct {
                fields: vec![3],
                packed: false,
            });
            invalid.functions[0].blocks.push(Block {
                id: 999,
                instructions: vec![Instruction {
                    result: Some(Value { id: 999, ty }),
                    operation: Operation::Freeze {
                        value: Operand::Aggregate {
                            ty,
                            elements: vec![symbol.clone()],
                        },
                    },
                }],
                terminator: Terminator::Unreachable,
            });
            rejects(
                &invalid,
                "TLS symbol address requires a current-thread address operation",
            );
            invalid = good.clone();
            invalid.functions[0].blocks.push(Block {
                id: 999,
                instructions: vec![Instruction {
                    result: Some(Value { id: 999, ty: 3 }),
                    operation: Operation::Phi {
                        incoming: vec![PhiIncoming {
                            block: 999,
                            value: symbol,
                        }],
                    },
                }],
                terminator: Terminator::Jump { target: 999 },
            });
            rejects(
                &invalid,
                "TLS symbol address requires a current-thread address operation",
            );
        }
        for tls_template in [false, true] {
            let mut invalid = good.clone();
            let mut storage = invalid.globals[0].clone();
            storage.name = "static_address_template".into();
            storage.ty = 3;
            if !tls_template {
                storage.thread_local = false;
                storage.tls_model = None;
            }
            storage.initializer.as_mut().unwrap().relocations = vec![Relocation {
                offset: 0,
                width: 64,
                symbol: "tls_counter".into(),
                addend: 0,
                relative_to: None,
            }];
            invalid.globals.push(storage);
            invalid.provenance.source_global_count += 1;
            rejects(
                &invalid,
                "initializer cannot contain a static address of TLS storage",
            );
        }
    }

    #[test]
    fn tls_templates_keep_static_pointer_initializers_but_not_tls_relative_addresses() {
        for triple in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "riscv64-unknown-linux-gnu",
        ] {
            let mut m = tls_module(triple);
            global(&mut m);
            for target in ["slot", "choose"] {
                let mut storage = m.globals[0].clone();
                storage.name = format!("tls_pointer_{target}");
                storage.ty = 3;
                storage.initializer.as_mut().unwrap().relocations = vec![Relocation {
                    offset: 0,
                    width: 64,
                    symbol: target.into(),
                    addend: 0,
                    relative_to: None,
                }];
                m.globals.push(storage);
                m.provenance.source_global_count += 1;
            }
            verify(&m).unwrap();
            let mut invalid = m.clone();
            invalid.globals[0].linkage = "private".into();
            invalid.globals[0].initializer.as_mut().unwrap().relocations = vec![Relocation {
                offset: 0,
                width: 32,
                symbol: "slot".into(),
                addend: -1,
                relative_to: Some("tls_counter".into()),
            }];
            rejects(&invalid, "initialized private/internal non-TLS global");
            invalid = m.clone();
            invalid.globals[0].linkage = "common".into();
            rejects(
                &invalid,
                "common global must be mutable, zero initialized, non-TLS",
            );
        }
    }

    #[test]
    fn tls_comdat_storage_is_supported_only_with_the_explicit_profile_while_aliases_stay_rejected()
    {
        for selection in [ComdatSelection::Any, ComdatSelection::NoDeduplicate] {
            let mut m = tls_module("x86_64-unknown-linux-gnu");
            m.comdats.push(Comdat {
                name: "tls.group".into(),
                selection,
            });
            m.provenance.referenced_comdat_count = 1;
            m.globals[0].comdat = Some("tls.group".into());
            m.functions[0].comdat = Some("tls.group".into());
            global(&mut m);
            m.globals[1].comdat = Some("tls.group".into());
            verify(&m).unwrap();
            let mut invalid = m.clone();
            invalid.target.tls_profile = None;
            rejects(
                &invalid,
                "TLS COMDAT members require explicit storage/model lowering",
            );
            invalid = m.clone();
            invalid.globals[0].initializer = None;
            rejects(&invalid, "COMDAT member must be an emitted definition");
            invalid = m.clone();
            invalid.aliases.push(Alias {
                name: "tls_alias".into(),
                ty: 2,
                aliasee: "tls_counter".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
            });
            invalid.provenance.source_alias_count += 1;
            rejects(
                &invalid,
                "TLS aliases require explicit storage/model lowering",
            );
        }
    }

    #[test]
    fn current_thread_pointers_flow_through_ordinary_calls_returns_and_simultaneous_phi_edges() {
        let mut m = tls_module("x86_64-unknown-linux-gnu");
        let mut provider = m.functions[0].clone();
        provider.name = "consume_pointer".into();
        provider.signature = tls_signature(&[3], 0);
        provider.params = vec![Value { id: 0, ty: 3 }];
        provider.entry = None;
        provider.blocks.clear();
        m.functions.push(provider);
        m.provenance.source_function_count += 1;
        m.functions[0].blocks[0].instructions.push(Instruction {
            result: None,
            operation: Operation::Call {
                callee: Operand::Symbol {
                    ty: 3,
                    name: "consume_pointer".into(),
                },
                signature: tls_signature(&[3], 0),
                args: vec![value(77)],
            },
        });
        verify(&m).unwrap();
        m.functions[0].signature = tls_signature(&[1], 3);
        m.functions[0].params = vec![Value { id: 0, ty: 1 }];
        m.functions[0].blocks = vec![
            Block {
                id: 10,
                instructions: vec![],
                terminator: Terminator::Branch {
                    condition: value(0),
                    on_true: 20,
                    on_false: 30,
                },
            },
            Block {
                id: 20,
                instructions: vec![Instruction {
                    result: Some(Value { id: 77, ty: 3 }),
                    operation: Operation::ThreadLocalAddress {
                        global: "tls_counter".into(),
                    },
                }],
                terminator: Terminator::Jump { target: 40 },
            },
            Block {
                id: 30,
                instructions: vec![Instruction {
                    result: Some(Value { id: 78, ty: 3 }),
                    operation: Operation::ThreadLocalAddress {
                        global: "tls_counter".into(),
                    },
                }],
                terminator: Terminator::Jump { target: 40 },
            },
            Block {
                id: 40,
                instructions: vec![Instruction {
                    result: Some(Value { id: 79, ty: 3 }),
                    operation: Operation::Phi {
                        incoming: vec![
                            PhiIncoming {
                                block: 20,
                                value: value(77),
                            },
                            PhiIncoming {
                                block: 30,
                                value: value(78),
                            },
                        ],
                    },
                }],
                terminator: Terminator::Return {
                    value: Some(value(79)),
                },
            },
        ];
        verify(&m).unwrap();
        let Operation::Phi { incoming } = &mut m.functions[0].blocks[3].instructions[0].operation
        else {
            panic!()
        };
        incoming[1].value = value(77);
        rejects(&m, "does not dominate");
    }

    #[test]
    fn exact_threadlocal_intrinsic_declaration_retains_inventory_and_rejects_native_escape() {
        for triple in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "riscv64-unknown-linux-gnu",
        ] {
            let mut m = tls_module(triple);
            let mut declaration = builtin("llvm.threadlocal.address.p0", &[3]);
            declaration.signature.result = 3;
            m.functions.push(declaration);
            m.provenance.source_function_count += 1;
            verify(&m).unwrap();
            assert!(is_builtin_intrinsic("llvm.threadlocal.address.p0"));
            for name in [
                "llvm.threadlocal.address",
                "llvm.threadlocal.address.p1",
                "llvm.threadlocal.address.p0.extra",
                "llvm.threadlocal.address.i64",
            ] {
                let mut invalid = m.clone();
                invalid.functions[1].name = name.into();
                invalid.functions[1].intrinsic = Some(name.into());
                rejects(&invalid, "unsupported intrinsic declaration");
                assert!(!is_builtin_intrinsic(name));
            }
            for mutation in 0..11 {
                let mut invalid = m.clone();
                let f = &mut invalid.functions[1];
                match mutation {
                    0 => f.signature.result = 2,
                    1 => {
                        f.signature.params = vec![2];
                        f.params[0].ty = 2;
                    }
                    2 => {
                        f.signature.params.clear();
                        f.params.clear();
                    }
                    3 => f.signature.abi = "fast".into(),
                    4 => f.signature.variadic = true,
                    5 => f.visibility = Visibility::Hidden,
                    6 => f.linkage = "internal".into(),
                    7 => f.intrinsic = None,
                    8 => f.signature.param_attributes = vec![vec!["nonnull".into()]],
                    9 => f.signature.result_attributes = vec!["nonnull".into()],
                    10 => f.intrinsic = Some("llvm.load.relative.i32".into()),
                    _ => unreachable!(),
                }
                rejects(
                    &invalid,
                    if matches!(mutation, 8 | 9) {
                        "unsupported imported ABI attribute"
                    } else {
                        "unsupported intrinsic declaration"
                    },
                );
            }
            let mut invalid = m.clone();
            let ty = invalid.types.len();
            invalid.types.push(Type::Pointer { address_space: 1 });
            invalid.functions[1].signature.params[0] = ty;
            invalid.functions[1].params[0].ty = ty;
            invalid.functions[1].signature.result = ty;
            rejects(&invalid, "unsupported intrinsic declaration");
            for callee in [
                Operand::Symbol {
                    ty: 3,
                    name: "llvm.threadlocal.address.p0".into(),
                },
                Operand::SymbolOffset {
                    ty: 3,
                    name: "llvm.threadlocal.address.p0".into(),
                    addend: 0,
                },
            ] {
                invalid = m.clone();
                invalid.functions[0].blocks[0]
                    .instructions
                    .push(Instruction {
                        result: Some(Value { id: 99, ty: 3 }),
                        operation: Operation::Freeze {
                            value: callee.clone(),
                        },
                    });
                rejects(&invalid, "intrinsic address");
                invalid = m.clone();
                invalid.functions[0].blocks[0]
                    .instructions
                    .push(Instruction {
                        result: Some(Value { id: 99, ty: 3 }),
                        operation: Operation::Call {
                            callee,
                            signature: tls_signature(&[3], 3),
                            args: vec![value(77)],
                        },
                    });
                rejects(&invalid, "intrinsic address");
            }
            invalid = m.clone();
            invalid.target.tls_profile = None;
            invalid.globals.clear();
            invalid.provenance.source_global_count = 0;
            invalid.functions[0].blocks.clear();
            invalid.functions[0].entry = None;
            rejects(
                &invalid,
                "thread-local intrinsic requires an explicit native TLS profile",
            );
        }
    }

    // Authored structural fixtures. Printed evidence below exercises the
    // verifier's anchored prefix/digest contract, not an upstream import claim.
    fn noalias_module() -> NativeModule {
        let mut m = module();
        m.types.push(Type::Metadata {});
        let signature = Signature {
            params: vec![5],
            result: 0,
            abi: "c".into(),
            variadic: false,
            param_attributes: vec![vec![]],
            result_attributes: vec![],
            return_storage: None,
        };
        m.types.push(Type::Function {
            signature: signature.clone(),
        });
        let mut declaration = m.functions[0].clone();
        declaration.name = NOALIAS_SCOPE_DECL.into();
        declaration.signature = signature;
        declaration.params = vec![Value { id: 900, ty: 5 }];
        declaration.entry = None;
        declaration.blocks.clear();
        declaration.intrinsic = Some(NOALIAS_SCOPE_DECL.into());
        m.functions.push(declaration);
        m.provenance.source_function_count += 1;
        m.noalias_metadata = NoAliasMetadata {
            domains: vec![NoAliasDomain {
                id: 100,
                storage: NoAliasNodeStorage::Distinct,
                identity: NoAliasIdentity::SelfReference {},
                description: Some(vec![b'd', 0, 255]),
            }],
            scopes: vec![
                NoAliasScope {
                    id: 101,
                    storage: NoAliasNodeStorage::Distinct,
                    identity: NoAliasIdentity::SelfReference {},
                    domain: 100,
                    description: Some(b"same label".to_vec()),
                },
                NoAliasScope {
                    id: 102,
                    storage: NoAliasNodeStorage::Uniqued,
                    identity: NoAliasIdentity::Bytes {
                        bytes: vec![b's', 0, 254],
                    },
                    domain: 100,
                    description: None,
                },
            ],
            lists: vec![
                NoAliasScopeList {
                    id: 201,
                    storage: NoAliasNodeStorage::Distinct,
                    scopes: vec![101],
                },
                NoAliasScopeList {
                    id: 202,
                    storage: NoAliasNodeStorage::Distinct,
                    scopes: vec![101],
                },
                NoAliasScopeList {
                    id: 203,
                    storage: NoAliasNodeStorage::Uniqued,
                    scopes: vec![102],
                },
                NoAliasScopeList {
                    id: 204,
                    storage: NoAliasNodeStorage::Uniqued,
                    scopes: vec![],
                },
            ],
            attachments: vec![
                NoAliasAttachment {
                    site: NoAliasSite {
                        function: "choose".into(),
                        block: 10,
                        instruction: 0,
                        instruction_count: 1,
                        source_instruction: 7,
                    },
                    alias_scope: Some(201),
                    noalias: Some(203),
                },
                NoAliasAttachment {
                    site: NoAliasSite {
                        function: "choose".into(),
                        block: 20,
                        instruction: 0,
                        instruction_count: 1,
                        source_instruction: 1,
                    },
                    alias_scope: Some(202),
                    noalias: None,
                },
                NoAliasAttachment {
                    site: NoAliasSite {
                        function: "choose".into(),
                        block: 40,
                        instruction: 1,
                        instruction_count: 0,
                        source_instruction: 3,
                    },
                    alias_scope: None,
                    noalias: Some(204),
                },
            ],
        };
        m.functions[0].blocks[1]
            .instructions
            .push(noalias_marker(201, 2));
        m.functions[0].blocks[2]
            .instructions
            .push(noalias_marker(202, 2));
        m
    }

    fn noalias_marker(list: usize, source: usize) -> Instruction {
        Instruction {
            result: None,
            operation: Operation::NoAliasScopeDecl {
                scope_list: list,
                source_instruction: source,
            },
        }
    }

    fn noalias_source(m: &mut NativeModule) {
        let mut nodes: Vec<_> = m
            .noalias_metadata
            .domains
            .iter()
            .map(|x| (x.id, x.storage))
            .chain(m.noalias_metadata.scopes.iter().map(|x| (x.id, x.storage)))
            .chain(m.noalias_metadata.lists.iter().map(|x| (x.id, x.storage)))
            .collect();
        nodes.sort_unstable_by_key(|x| x.0);
        m.provenance.noalias_metadata_source = nodes
            .into_iter()
            .map(|(id, storage)| {
                let prefix = if storage == NoAliasNodeStorage::Distinct {
                    "distinct "
                } else {
                    ""
                };
                let printer_bytes =
                    format!("!{id} = {prefix}!{{!\"distinct is just a description\"}}")
                        .into_bytes();
                NoAliasNodeSource {
                    id,
                    metadata_kind: 4,
                    printer_sha256: format!("{:x}", Sha256::digest(&printer_bytes)),
                    printer_bytes,
                }
            })
            .collect();
    }

    fn noalias_cfg(successors: &[Vec<usize>], sites: &[(usize, usize)]) -> NativeModule {
        let mut m = noalias_module();
        m.noalias_metadata.attachments.clear();
        let function = &mut m.functions[0];
        function.signature.params.clear();
        function.signature.result = 0;
        function.params.clear();
        function.entry = Some(0);
        function.blocks = successors
            .iter()
            .enumerate()
            .map(|(id, next)| Block {
                id,
                instructions: vec![],
                terminator: match next.as_slice() {
                    [] => Terminator::Return { value: None },
                    [target] => Terminator::Jump { target: *target },
                    [on_true, on_false] => Terminator::Branch {
                        condition: integer(1, 1),
                        on_true: *on_true,
                        on_false: *on_false,
                    },
                    [default, rest @ ..] => Terminator::Switch {
                        condition: integer(2, 0),
                        default: *default,
                        cases: rest
                            .iter()
                            .enumerate()
                            .map(|(value, target)| SwitchCase {
                                value: integer(2, value as u64),
                                target: *target,
                            })
                            .collect(),
                    },
                },
            })
            .collect();
        for (block, list) in sites {
            let body = &mut function.blocks[*block];
            body.instructions
                .push(noalias_marker(*list, body.instructions.len()));
        }
        m
    }

    #[test]
    fn noalias_metadata_retains_exact_unsized_declaration_graph_and_bytes() {
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "riscv64-unknown-linux-gnu",
        ] {
            let mut m = noalias_module();
            m.target.triple = target.into();
            noalias_source(&mut m);
            verify(&m).unwrap();
            assert!(is_builtin_intrinsic(NOALIAS_SCOPE_DECL));
            assert!(is_metadata_builtin_intrinsic(NOALIAS_SCOPE_DECL));
            assert!(!is_metadata_builtin_intrinsic(
                "llvm.experimental.noalias.scope.decl.p0"
            ));
            assert!(type_size(&m, 5).is_err());
            assert!(type_alignment(&m, 5).is_err());
            assert!(value_leaf_layout(&m, 5).is_err());
            assert_eq!(type_layouts(&m).unwrap()[5], None);
            assert!(!value_leaf_layouts(&m, &[5]).unwrap().contains_key(&5));
            let source = m.to_json().unwrap();
            let restored = NativeModule::from_json(&source).unwrap();
            assert_eq!(source, restored.to_json().unwrap());
            assert_eq!(restored.functions[1].signature.params, vec![5]);
            assert_eq!(restored.functions[1].params, vec![Value { id: 900, ty: 5 }]);
            assert_eq!(
                restored.noalias_metadata.domains[0].description,
                Some(vec![b'd', 0, 255])
            );
            assert!(matches!(&restored.noalias_metadata.scopes[1].identity,
                NoAliasIdentity::Bytes {bytes} if bytes == &[b's',0,254]));
            assert_eq!(restored.noalias_metadata.scopes[1].description, None);
            verify(&restored).unwrap();
            // Native opcodes may stand alone, like Trap and memory operations;
            // retaining a compiler declaration does not create an ABI call.
            let mut standalone = restored;
            standalone.functions.pop();
            standalone.types.pop();
            standalone.provenance.source_function_count -= 1;
            verify(&standalone).unwrap();
        }
        let mut encoded = serde_json::to_value(module()).unwrap();
        encoded.as_object_mut().unwrap().remove("noalias_metadata");
        encoded["provenance"]
            .as_object_mut()
            .unwrap()
            .remove("noalias_metadata_source");
        verify(&serde_json::from_value(encoded).unwrap()).unwrap();
    }

    #[test]
    fn noalias_graph_references_and_shared_node_namespace_are_checked() {
        let m = noalias_module();
        let mut bad = m.clone();
        bad.noalias_metadata.domains[0].id = 101;
        rejects(&bad, "duplicate node ID");
        bad = m.clone();
        bad.noalias_metadata.scopes[0].domain = 999;
        rejects(&bad, "unknown domain");
        bad = m.clone();
        bad.noalias_metadata.scopes[0].domain = 101;
        rejects(&bad, "unknown domain");
        bad = m.clone();
        bad.noalias_metadata.lists[0].scopes = vec![999];
        rejects(&bad, "unknown scope");
        bad = m.clone();
        bad.noalias_metadata.lists[0].scopes.clear();
        rejects(&bad, "exactly one actual scope");
        bad = m.clone();
        bad.noalias_metadata.lists[0].scopes.push(101);
        rejects(&bad, "exactly one actual scope");
        // Lists on accesses retain repetitions/order and may be empty. Unused
        // typed graph nodes are retained rather than falsely declared dropped.
        let mut valid = m;
        valid.noalias_metadata.lists[3].scopes = vec![102, 101, 102];
        valid.noalias_metadata.domains.push(NoAliasDomain {
            id: 800,
            storage: NoAliasNodeStorage::Uniqued,
            identity: NoAliasIdentity::Bytes { bytes: vec![] },
            description: Some(vec![]),
        });
        verify(&valid).unwrap();
    }

    #[test]
    fn noalias_source_node_evidence_is_complete_hashed_and_storage_anchored() {
        let mut m = noalias_module();
        noalias_source(&mut m);
        verify(&m).unwrap();
        let mut bad = m.clone();
        bad.provenance.noalias_metadata_source.pop();
        rejects(&bad, "inventory does not match graph");
        bad = m.clone();
        bad.provenance.noalias_metadata_source[1].id = 100;
        rejects(&bad, "duplicate source");
        bad = m.clone();
        bad.provenance.noalias_metadata_source[0].id = 999;
        rejects(&bad, "unknown metadata node");
        bad = m.clone();
        bad.provenance.noalias_metadata_source[0].metadata_kind = 5;
        rejects(&bad, "not an MDTuple");
        bad = m.clone();
        bad.provenance.noalias_metadata_source[0].printer_sha256 = "0".repeat(64);
        rejects(&bad, "digest does not match");
        for body in [
            b"!100 = !{!\"distinct\"}".as_slice(),
            b"!100 = <temporary!> !{}",
            b"!<0xab> = distinct !{}",
            b"untrusted = distinct !{}",
        ] {
            bad = m.clone();
            let node = &mut bad.provenance.noalias_metadata_source[0];
            node.printer_bytes = body.to_vec();
            node.printer_sha256 = format!("{:x}", Sha256::digest(body));
            rejects(&bad, "storage prefix");
        }
        // A process-address fallback is evidence only, not a portable node ID.
        let node = &mut m.provenance.noalias_metadata_source[0];
        node.printer_bytes = b"<0x123ABC> = distinct !{}".to_vec();
        node.printer_sha256 = format!("{:x}", Sha256::digest(&node.printer_bytes));
        assert_eq!(node.id, 100);
        verify(&m).unwrap();
    }

    #[test]
    fn noalias_attachment_ranges_source_order_and_cold_sites_are_verified() {
        let m = noalias_module();
        for name in ["missing", NOALIAS_SCOPE_DECL] {
            let mut bad = m.clone();
            bad.noalias_metadata.attachments[0].site.function = name.into();
            rejects(&bad, "function definition");
        }
        let mut bad = m.clone();
        bad.noalias_metadata.attachments[0].site.block = 999;
        rejects(&bad, "unknown block");
        for (start, count) in [(2, 0), (1, 1), (0, usize::MAX), (usize::MAX, 1)] {
            bad = m.clone();
            bad.noalias_metadata.attachments[0].site.instruction = start;
            bad.noalias_metadata.attachments[0].site.instruction_count = count;
            rejects(&bad, "range is out of bounds");
        }
        bad = m.clone();
        bad.noalias_metadata.attachments[0].alias_scope = None;
        bad.noalias_metadata.attachments[0].noalias = None;
        rejects(&bad, "neither alias.scope nor noalias");
        bad = m.clone();
        bad.noalias_metadata.attachments[0].noalias = Some(999);
        rejects(&bad, "unknown scope list");
        bad = m.clone();
        bad.noalias_metadata
            .attachments
            .push(bad.noalias_metadata.attachments[0].clone());
        rejects(&bad, "duplicate source instruction attachment");
        bad = m.clone();
        bad.noalias_metadata.attachments[1].site.instruction_count = 2;
        rejects(&bad, "overlap or are out of order");
        bad = m.clone();
        bad.noalias_metadata.attachments[1].site.source_instruction = 2;
        rejects(&bad, "marker and attachment source ranges differ");
        bad = m.clone();
        bad.functions[0].blocks[1]
            .instructions
            .push(noalias_marker(203, 2));
        rejects(&bad, "duplicate marker source instruction");
        // Zero-length erased source instructions can share an anchor in
        // source order, while preserving the separately retained source IDs.
        let mut valid = m;
        valid.noalias_metadata.attachments.push(NoAliasAttachment {
            site: NoAliasSite {
                function: "choose".into(),
                block: 10,
                instruction: 0,
                instruction_count: 0,
                source_instruction: 5,
            },
            alias_scope: Some(204),
            noalias: None,
        });
        valid.noalias_metadata.attachments.push(NoAliasAttachment {
            site: NoAliasSite {
                function: "choose".into(),
                block: 10,
                instruction: 0,
                instruction_count: 0,
                source_instruction: 6,
            },
            alias_scope: None,
            noalias: Some(204),
        });
        verify(&valid).unwrap();
        valid.functions[0].blocks.push(Block {
            id: 999,
            instructions: vec![noalias_marker(203, 0)],
            terminator: Terminator::Return {
                value: Some(integer(2, 0)),
            },
        });
        valid.noalias_metadata.attachments.push(NoAliasAttachment {
            site: NoAliasSite {
                function: "choose".into(),
                block: 999,
                instruction: 0,
                instruction_count: 1,
                source_instruction: 0,
            },
            alias_scope: Some(201),
            noalias: None,
        });
        verify(&valid).unwrap();
        valid
            .noalias_metadata
            .attachments
            .last_mut()
            .unwrap()
            .site
            .instruction_count = 2;
        rejects(&valid, "range is out of bounds");
    }

    #[test]
    fn noalias_dominance_uses_actual_scope_not_wrapper_or_description() {
        let mut m = noalias_cfg(
            &[vec![1, 2], vec![3], vec![3], vec![]],
            &[(1, 201), (2, 202)],
        );
        verify(&m).unwrap();
        m.functions[0].blocks[0]
            .instructions
            .push(noalias_marker(203, 0));
        verify(&m).unwrap();
        // The different actual scope may have the same description and string
        // bytes; only graph identity controls declaration dominance.
        m.noalias_metadata.scopes[1].description = m.noalias_metadata.scopes[0].description.clone();
        verify(&m).unwrap();
        m.functions[0].blocks[0].instructions[0] = noalias_marker(202, 0);
        rejects(&m, "dominates another declaration of the same actual scope");
        let mut same_block = noalias_cfg(&[vec![]], &[(0, 201), (0, 202)]);
        rejects(
            &same_block,
            "dominates another declaration of the same actual scope",
        );
        same_block.functions[0].blocks[0].instructions[1] = noalias_marker(203, 1);
        verify(&same_block).unwrap();
    }

    #[test]
    fn noalias_dominance_scales_without_a_scope_count_ceiling() {
        for count in [32, 33, 65, 4096] {
            let mut successors = vec![(1..=count).collect()];
            successors.resize_with(count + 1, Vec::new);
            let sites: Vec<_> = (1..=count)
                .map(|block| (block, if block % 2 == 0 { 201 } else { 202 }))
                .collect();
            let m = noalias_cfg(&successors, &sites);
            verify(&m).unwrap();
            let mut bad = m.clone();
            bad.functions[0].blocks[0]
                .instructions
                .push(noalias_marker(202, 0));
            rejects(
                &bad,
                "dominates another declaration of the same actual scope",
            );
            bad = m;
            bad.functions[0].blocks[count]
                .instructions
                .push(noalias_marker(201, 1));
            rejects(
                &bad,
                "dominates another declaration of the same actual scope",
            );
        }
    }

    #[test]
    fn noalias_dominance_handles_dynamic_loops_unreachable_targets_and_functions() {
        let single_loop = noalias_cfg(&[vec![1], vec![1, 2], vec![]], &[(1, 201)]);
        verify(&single_loop).unwrap();
        let duplicated_loop = noalias_cfg(
            &[vec![1], vec![2, 3], vec![1], vec![]],
            &[(1, 201), (2, 202)],
        );
        rejects(
            &duplicated_loop,
            "dominates another declaration of the same actual scope",
        );
        let dead = noalias_cfg(&[vec![], vec![], vec![]], &[(1, 201)]);
        verify(&dead).unwrap();
        let mut bad = dead.clone();
        bad.functions[0].blocks[2]
            .instructions
            .push(noalias_marker(202, 0));
        rejects(&bad, "unreachable target");
        bad = dead.clone();
        bad.functions[0].blocks[0]
            .instructions
            .push(noalias_marker(202, 0));
        rejects(&bad, "unreachable target");
        let mut different = dead;
        different.functions[0].blocks[2]
            .instructions
            .push(noalias_marker(203, 0));
        verify(&different).unwrap();
        let mut other = different.functions[0].clone();
        other.name = "other_function".into();
        different.functions.push(other);
        different.provenance.source_function_count += 1;
        verify(&different).unwrap();
    }

    #[test]
    fn noalias_metadata_has_no_ordinary_storage_ssa_or_calling_abi() {
        let m = noalias_module();
        let mut bad = m.clone();
        bad.functions[0].signature.params[0] = 5;
        bad.functions[0].params[0].ty = 5;
        rejects(&bad, "unsized");
        bad = m.clone();
        bad.functions[0].signature.result = 5;
        rejects(&bad, "unsized");
        bad = m.clone();
        bad.types.push(Type::Array { element: 5, len: 0 });
        rejects(&bad, "array element is unsized");
        bad = m.clone();
        bad.types.push(Type::Struct {
            fields: vec![5],
            packed: true,
        });
        rejects(&bad, "struct field is unsized");
        bad = m.clone();
        global(&mut bad);
        bad.globals[0].ty = 5;
        bad.globals[0].initializer = None;
        rejects(&bad, "unsized");
        bad = m.clone();
        bad.functions[0].blocks[0].instructions.push(Instruction {
            result: Some(Value { id: 950, ty: 5 }),
            operation: Operation::Freeze {
                value: Operand::Undef { ty: 5 },
            },
        });
        rejects(&bad, "unsized");
        bad = m.clone();
        bad.functions[0].blocks[0].instructions.push(Instruction {
            result: Some(Value { id: 950, ty: 2 }),
            operation: Operation::Freeze {
                value: Operand::Poison { ty: 5 },
            },
        });
        rejects(&bad, "unsized");
        bad = m.clone();
        let call_signature = bad.functions[1].signature.clone();
        bad.functions[0].blocks[0].instructions.push(Instruction {
            result: None,
            operation: Operation::Call {
                callee: Operand::Null { ty: 3 },
                signature: call_signature,
                args: vec![Operand::Undef { ty: 5 }],
            },
        });
        rejects(&bad, "unsized");
        let mut ordinary = m.functions[1].clone();
        ordinary.name = "ordinary_metadata".into();
        ordinary.intrinsic = None;
        bad = m.clone();
        bad.functions.push(ordinary);
        bad.provenance.source_function_count += 1;
        rejects(&bad, "unsized");
        for target in [
            crate::ocore::Target::X86_64UnknownNone,
            crate::ocore::Target::Aarch64UnknownNone,
            crate::ocore::Target::Riscv64UnknownNone,
        ] {
            let mut target_module = m.clone();
            target_module.target.triple = match target {
                crate::ocore::Target::X86_64UnknownNone => "x86_64-unknown-linux-gnu",
                crate::ocore::Target::Aarch64UnknownNone => "aarch64-unknown-linux-gnu",
                crate::ocore::Target::Riscv64UnknownNone => "riscv64-unknown-linux-gnu",
            }
            .into();
            let error =
                crate::ocore::native_abi::plan(&target_module, target, &m.functions[1].signature)
                    .unwrap_err();
            assert!(
                error.message.contains("unsupported original ABI type"),
                "{}",
                error.message
            );
        }
        let mut detached = m;
        detached.functions.pop();
        detached.provenance.source_function_count -= 1;
        rejects(
            &detached,
            "metadata function type requires its included owned intrinsic declaration",
        );
    }

    #[test]
    fn noalias_intrinsic_ownership_signature_and_addresses_remain_exact() {
        let m = noalias_module();
        for variant in 0..9 {
            let mut bad = m.clone();
            bad.types.pop();
            let f = &mut bad.functions[1];
            match variant {
                0 => f.signature.abi = "fastcc".into(),
                1 => f.signature.variadic = true,
                2 => f.signature.result = 2,
                3 => f.signature.params = vec![3],
                4 => f.signature.params.push(5),
                5 => f.signature.param_attributes = vec![vec!["signext".into()]],
                6 => f.signature.result_attributes = vec!["zeroext".into()],
                7 => f.signature.return_storage = Some(ReturnStorage { param: 0, ty: 2 }),
                8 => f.signature.param_attributes = vec![vec![], vec![]],
                _ => unreachable!(),
            }
            assert!(verify(&bad).is_err(), "variant {variant} was accepted");
        }
        for variant in 0..5 {
            let mut bad = m.clone();
            bad.types.pop();
            let f = &mut bad.functions[1];
            match variant {
                0 => f.visibility = Visibility::Hidden,
                1 => f.linkage = "private".into(),
                2 => f.intrinsic = None,
                3 => f.intrinsic = Some("llvm.experimental.noalias.scope.decl.p0".into()),
                4 => {
                    f.entry = Some(0);
                    f.blocks = vec![Block {
                        id: 0,
                        instructions: vec![],
                        terminator: Terminator::Return { value: None },
                    }];
                }
                _ => unreachable!(),
            }
            assert!(
                verify(&bad).is_err(),
                "header variant {variant} was accepted"
            );
        }
        let mut bad = m.clone();
        bad.functions[0].blocks[1].instructions[1].result = Some(Value { id: 950, ty: 2 });
        rejects(&bad, "cannot define an SSA value");
        bad = m.clone();
        bad.functions[0].blocks[0].instructions.push(Instruction {
            result: Some(Value { id: 950, ty: 3 }),
            operation: Operation::Freeze {
                value: Operand::Symbol {
                    ty: 3,
                    name: NOALIAS_SCOPE_DECL.into(),
                },
            },
        });
        rejects(&bad, "intrinsic address");
        bad = m.clone();
        global(&mut bad);
        bad.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .relocations
            .push(Relocation {
                offset: 0,
                symbol: NOALIAS_SCOPE_DECL.into(),
                addend: 0,
                width: 64,
                relative_to: None,
            });
        rejects(&bad, "intrinsic address");
        bad = m;
        bad.aliases.push(Alias {
            name: "escaped".into(),
            ty: 6,
            aliasee: NOALIAS_SCOPE_DECL.into(),
            linkage: "external".into(),
            visibility: Visibility::Default,
        });
        bad.provenance.source_alias_count += 1;
        rejects(&bad, "alias target must be an emitted definition");
    }

    #[test]
    fn noalias_wire_rejects_unencoded_nodes_and_executable_metadata_operands() {
        let m = noalias_module();
        for (field, value) in [
            ("storage", json!("temporary")),
            ("specialized_kind", json!("DIExpression")),
        ] {
            let mut encoded = serde_json::to_value(&m).unwrap();
            encoded["noalias_metadata"]["domains"][0][field] = value;
            assert!(serde_json::from_value::<NativeModule>(encoded).is_err());
        }
        let mut encoded = serde_json::to_value(&m).unwrap();
        encoded["noalias_metadata"]["domains"][0]["identity"]["node"] = json!(101);
        assert!(serde_json::from_value::<NativeModule>(encoded).is_err());
        encoded = serde_json::to_value(&m).unwrap();
        encoded["noalias_metadata"]["scopes"][1]["identity"]["bytes"] = json!([256]);
        assert!(serde_json::from_value::<NativeModule>(encoded).is_err());
        assert!(serde_json::from_value::<Operand>(
            json!({"kind":"metadata","ty":5,"scope_list":201})
        )
        .is_err());
    }

    proptest! {
        #[test]
        fn noalias_complete_dominance_matches_independent_remove_block_oracle(
            edges in prop::collection::vec((0_usize..16,1_usize..16),0..64),
            declarations in prop::collection::vec((0_usize..16,0_usize..3),0..40)
        ) {
            let mut successors = vec![Vec::new();16];
            for (from,to) in edges {
                if !successors[from].contains(&to) {successors[from].push(to);}
            }
            let sites:Vec<_> = declarations.iter().map(|(block,list)| (*block,[201,202,203][*list])).collect();
            let m = noalias_cfg(&successors,&sites);
            let reaches = |target:usize,excluded:Option<usize>| {
                if excluded == Some(0) {return false;}
                let mut seen = HashSet::from([0]);let mut stack = vec![0];
                while let Some(block) = stack.pop() {
                    if block == target {return true;}
                    for next in &successors[block] {
                        if excluded != Some(*next) && seen.insert(*next) {stack.push(*next);}
                    }
                }
                false
            };
            let mut flat = Vec::new();
            for (block,body) in m.functions[0].blocks.iter().enumerate() {
                for (position,instruction) in body.instructions.iter().enumerate() {
                    let Operation::NoAliasScopeDecl {scope_list,..} = &instruction.operation else {unreachable!()};
                    flat.push((block,position,if *scope_list == 203 {102} else {101}));
                }
            }
            let mut valid = true;
            for (i,(from,p,scope)) in flat.iter().enumerate() {
                for (j,(to,q,other_scope)) in flat.iter().enumerate() {
                    if i == j || scope != other_scope {continue;}
                    let dominates = if !reaches(*to,None) {true}
                        else if !reaches(*from,None) {false}
                        else if from == to {p < q}
                        else {!reaches(*to,Some(*from))};
                    if dominates {valid=false;}
                }
            }
            let actual = verify(&m);
            if let Err(error) = &actual {
                prop_assert!(error.message.contains("dominates another declaration of the same actual scope"),"{}",error.message);
            }
            prop_assert_eq!(actual.is_ok(),valid);
        }
    }
}
