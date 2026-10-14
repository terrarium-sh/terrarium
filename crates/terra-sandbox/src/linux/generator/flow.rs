//! A function's control flow and the values its registers can hold at an instruction.

use super::image::Image;
use super::isa::{Callee, Effect, Flow, Insn, RETURN_VALUE, Reg, RegisterFile as _};
use std::collections::{BTreeSet, HashSet};
use std::ops::Range;

/// The most jump-table entries read before giving up on finding the table's end.
const MAX_TABLE_ENTRIES: u64 = 4096;
/// How far back a jump-table dispatch's address computation may start.
const TABLE_DISPATCH_WINDOW: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Value {
    Constant(u64),
    /// The register's value when the function was entered, then each transform in order.
    Entry(Reg, Vec<Transform>),
    Unknown(String),
}

/// A computation the analysis replays on a value once a caller supplies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Transform {
    Mask(u64),
    /// `(value + addend) & mask`.
    Add {
        addend: u64,
        mask: u64,
    },
    SignExtend32,
    /// Replaces `width` bits at `shift` with `bits`.
    Insert {
        bits: u64,
        shift: u32,
        width: u32,
    },
}

impl Transform {
    pub(super) fn apply(self, value: u64) -> u64 {
        match self {
            Self::Mask(mask) => value & mask,
            Self::Add { addend, mask } => value.wrapping_add(addend) & mask,
            Self::SignExtend32 => {
                let low = u32::try_from(value & 0xffff_ffff).unwrap_or_default();
                i64::from(low.cast_signed()).cast_unsigned()
            }
            Self::Insert { bits, shift, width } => {
                let field = ((1_u64 << width) - 1) << shift;
                (value & !field) | (bits << shift)
            }
        }
    }
}

/// The addresses of a function's interior that exist as values, which an indirect jump could use.
pub(super) struct InteriorReferences<'a> {
    /// Data locations holding an interior address.
    pub(super) data: &'a [u64],
    /// Interior addresses code materializes, such as an `AArch64` jump table's `adr` base.
    pub(super) materialized: &'a [u64],
}

/// The state each forward-analysis state was first reached from.
type CameFrom = std::collections::HashMap<(usize, u64), (usize, u64)>;

/// What the rest of the program says about one function's control flow.
pub(super) struct Surroundings<'b> {
    /// Addresses inside the function that other functions jump to.
    pub(super) foreign_entries: &'b [u64],
    /// Starts of functions a call never returns from.
    pub(super) no_return: &'b HashSet<u64>,
    pub(super) interior: InteriorReferences<'b>,
}

/// Where a function pointer in registers goes from some point on.
#[derive(Default)]
pub(super) struct PointerUses {
    /// Indirect calls and jumps through it.
    pub(super) calls: Vec<usize>,
    /// Direct calls that receive it in argument registers, with those registers.
    pub(super) passes: Vec<(usize, u64)>,
}

/// A decoded function whose every intra-function edge is known, or a reason it is not.
pub(super) struct FunctionFlow<'a> {
    image: &'a Image,
    pub(super) name: String,
    pub(super) insns: Vec<Insn>,
    preds: Vec<Vec<usize>>,
    succs: Vec<Vec<usize>>,
    /// Why some edges are unknown; every query then fails.
    incomplete: Option<String>,
}

impl<'a> FunctionFlow<'a> {
    pub(super) fn new(
        image: &'a Image,
        name: &str,
        range: Range<u64>,
        (insns, has_gaps): (Vec<Insn>, bool),
        surroundings: &Surroundings<'_>,
    ) -> Self {
        let Surroundings {
            foreign_entries,
            no_return,
            interior,
        } = surroundings;
        let mut flow = Self {
            image,
            name: name.to_owned(),
            preds: vec![Vec::new(); insns.len()],
            succs: vec![Vec::new(); insns.len()],
            insns,
            incomplete: has_gaps.then(|| "has bytes that do not decode".to_owned()),
        };
        if let Some(entry) = foreign_entries.first() {
            flow.incomplete = Some(format!("is entered from another function at {entry:#x}"));
        }
        let edges = flow.direct_edges(&range, no_return);
        flow.add_edges(edges);
        let (unrecovered, table_spans, table_bases) = flow.recover_tables(&range);
        // An indirect jump can only stay inside the function through an address of its interior:
        // a jump table, or an interior address held as data or materialized by code. Without
        // either, an unrecovered indirect jump leaves the function, as a tail call does.
        let is_interior_referenced = interior
            .materialized
            .iter()
            .any(|value| !table_bases.contains(value))
            || interior.data.iter().any(|location| {
                !table_spans
                    .iter()
                    .any(|span| span.start <= *location && *location + 8 <= span.end)
                    && image
                        .read_u64(*location)
                        .is_some_and(|target| flow.index_of(target).is_some())
            });
        let unresolved = unrecovered.into_iter().find(|&index| {
            is_interior_referenced
                || match flow.insns[index].flow {
                    // A table dispatch computes the target from an indexed entry; a target
                    // loaded from a fixed offset, such as a vtable slot, is a tail call.
                    Flow::RegisterJump(reg) => matches!(
                        flow.find_definition(index, reg),
                        Some((
                            _,
                            Effect::AddShifted { .. }
                                | Effect::Load {
                                    has_index: true,
                                    ..
                                }
                        ))
                    ),
                    Flow::UnknownJump => false,
                    _ => true,
                }
        });
        if let Some(index) = unresolved {
            flow.incomplete.get_or_insert_with(|| {
                format!(
                    "has an unrecovered indirect jump at {:#x}",
                    flow.insns[index].address
                )
            });
        }
        if let Some(reason) = &mut flow.incomplete {
            *reason = format!("{} {reason}", flow.name);
        }
        flow
    }

    /// Adds jump-table edges, returning the indirect jumps no table explains, the data spans
    /// recovered absolute tables read, and the bases relative tables add their entries to.
    fn recover_tables(
        &mut self,
        range: &Range<u64>,
    ) -> (Vec<usize>, Vec<Range<u64>>, HashSet<u64>) {
        // A dispatch block may itself be reachable only through another table, so recover
        // tables until a pass finds nothing new.
        let mut unrecovered: Vec<usize> = (0..self.insns.len())
            .filter(|&index| {
                matches!(
                    self.insns[index].flow,
                    Flow::RegisterJump(_) | Flow::AbsoluteTableJump { .. } | Flow::UnknownJump
                )
            })
            .collect();
        // Data spans that recovered absolute tables read, and the bases relative tables add their
        // entries to; both are accounted-for interior references.
        let mut table_spans = Vec::new();
        let mut table_bases = HashSet::new();
        loop {
            let mut recovered = Vec::new();
            for &index in &unrecovered {
                let targets = match self.insns[index].flow {
                    Flow::RegisterJump(reg) => {
                        self.recover_relative_table(index, reg, range)
                            .map(|(targets, bases)| {
                                table_bases.extend(bases);
                                targets
                            })
                    }
                    Flow::AbsoluteTableJump { table, scale: 8 } => {
                        let targets = read_absolute_table(self.image, table, range);
                        table_spans.push(table..table + 8 * targets.len() as u64);
                        Some(targets)
                    }
                    _ => None,
                };
                if let Some(targets) = targets.filter(|targets| !targets.is_empty()) {
                    recovered.push((index, targets));
                }
            }
            if recovered.is_empty() {
                break;
            }
            for (index, targets) in recovered {
                unrecovered.retain(|&other| other != index);
                let edges: Vec<_> = targets
                    .into_iter()
                    .filter_map(|target| self.index_of(target))
                    .map(|target| (index, target))
                    .collect();
                self.add_edges(edges);
            }
        }
        (unrecovered, table_spans, table_bases)
    }

    fn index_of(&self, address: u64) -> Option<usize> {
        self.insns
            .binary_search_by_key(&address, |insn| insn.address)
            .ok()
    }

    /// Edges from jumps and fall-through; a call into a function in `no_return` ends its path.
    fn direct_edges(
        &mut self,
        range: &Range<u64>,
        no_return: &HashSet<u64>,
    ) -> Vec<(usize, usize)> {
        let mut edges = Vec::new();
        for (index, insn) in self.insns.iter().enumerate() {
            let falls_through = match insn.flow {
                Flow::Call(Callee::Direct(target)) => !no_return.contains(&target),
                Flow::Call(Callee::Slot(slot)) => self
                    .image
                    .read_u64(slot)
                    .is_none_or(|target| !no_return.contains(&target)),
                Flow::Next | Flow::Syscall | Flow::LegacySyscall | Flow::Call(_) => true,
                Flow::Jump {
                    target,
                    is_conditional,
                } => {
                    if range.contains(&target) {
                        match self.index_of(target) {
                            Some(target) => edges.push((index, target)),
                            None => {
                                self.incomplete.get_or_insert_with(|| {
                                    format!("jumps into an instruction at {target:#x}")
                                });
                            }
                        }
                    }
                    is_conditional
                }
                Flow::TailCall(_)
                | Flow::RegisterJump(_)
                | Flow::AbsoluteTableJump { .. }
                | Flow::UnknownJump
                | Flow::Return
                | Flow::Stop => false,
            };
            if falls_through && index + 1 < self.insns.len() {
                edges.push((index, index + 1));
            }
        }
        edges
    }

    fn add_edges(&mut self, edges: Vec<(usize, usize)>) {
        for (from, to) in edges {
            if !self.preds[to].contains(&from) {
                self.preds[to].push(from);
                self.succs[from].push(to);
            }
        }
    }

    /// Targets of an LLVM relative jump table: `jmp reg` where `reg = base + (entry << shift)`
    /// and `entry` is loaded from `table[index]`. A dispatch only works when `base` and `table`
    /// hold the table's addresses, so their constant values are the only feasible ones.
    fn recover_relative_table(
        &self,
        jump: usize,
        target: Reg,
        range: &Range<u64>,
    ) -> Option<(Vec<u64>, Vec<u64>)> {
        if self.incomplete.is_some() {
            return None;
        }
        let (
            add,
            &Effect::AddShifted {
                left, right, shift, ..
            },
        ) = self.find_definition(jump, target)?
        else {
            return None;
        };
        let mut targets = Vec::new();
        let mut used_bases = Vec::new();
        for (entry, base, entry_shift) in [(left, right, 0), (right, left, shift)] {
            let Some((
                load,
                &Effect::Load {
                    base: table_register,
                    has_index: true,
                    displacement,
                    width,
                    is_signed,
                    ..
                },
            )) = self.find_definition(add, entry)
            else {
                continue;
            };
            let bases = self.constants(add, base);
            // One register serves as both, so it holds the same value for both on every path.
            let pairs: Vec<(u64, u64)> = if table_register == base {
                bases.iter().map(|&base| (base, base)).collect()
            } else {
                let tables = self.constants(load, table_register);
                tables
                    .iter()
                    .flat_map(|&table| bases.iter().map(move |&base| (table, base)))
                    .collect()
            };
            for (table, base) in pairs {
                used_bases.push(base);
                targets.extend(read_relative_table(
                    self.image,
                    table.wrapping_add_signed(displacement),
                    base,
                    width,
                    is_signed,
                    entry_shift,
                    range,
                ));
            }
        }
        (!targets.is_empty()).then_some((targets, used_bases))
    }

    /// The nearest earlier instruction that writes `reg` within a straight-line dispatch window.
    fn find_definition(&self, before: usize, reg: Reg) -> Option<(usize, &Effect)> {
        (before.saturating_sub(TABLE_DISPATCH_WINDOW)..before)
            .rev()
            .find(|&index| self.insns[index].writes(reg))
            .map(|index| (index, &self.insns[index].effect))
    }

    fn constants(&self, before: usize, reg: Reg) -> Vec<u64> {
        self.values_before(before, reg)
            .into_iter()
            .filter_map(|value| match value {
                Value::Constant(value) => Some(value),
                Value::Entry(..) | Value::Unknown(_) => None,
            })
            .collect()
    }

    /// Every value `reg` may hold just before instruction `index` executes.
    pub(super) fn values_before(&self, index: usize, reg: Reg) -> BTreeSet<Value> {
        if let Some(reason) = &self.incomplete {
            return BTreeSet::from([Value::Unknown(reason.clone())]);
        }
        let architecture = self.image.architecture;
        let mut values = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut pending = vec![(index, reg)];
        while let Some((index, reg)) = pending.pop() {
            if !seen.insert((index, reg)) {
                continue;
            }
            if self.preds[index].is_empty() {
                values.insert(if index == 0 {
                    Value::Entry(reg, Vec::new())
                } else {
                    Value::Unknown(format!(
                        "{} reaches {:#x} by no known path",
                        self.name, self.insns[index].address
                    ))
                });
                continue;
            }
            for &pred in &self.preds[index] {
                let insn = &self.insns[pred];
                if matches!(insn.flow, Flow::Call(_)) && architecture.call_clobbers(reg) {
                    values.insert(Value::Unknown(format!(
                        "{} clobbers the register with a call at {:#x}",
                        self.name, insn.address
                    )));
                    continue;
                }
                if !insn.writes(reg) {
                    pending.push((pred, reg));
                    continue;
                }
                match insn.effect {
                    Effect::Copy {
                        dst,
                        src,
                        mask: u64::MAX,
                    } if dst == reg => pending.push((pred, src)),
                    effect if effect.destination() == Some(reg) => {
                        values.extend(self.evaluate(pred, effect));
                    }
                    _ => {
                        values.insert(self.unfollowed(pred));
                    }
                }
            }
        }
        values
    }

    /// The values `effect`, executed by instruction `index`, leaves in its destination.
    fn evaluate(&self, index: usize, effect: Effect) -> BTreeSet<Value> {
        match effect {
            Effect::Constant { value, .. } => BTreeSet::from([Value::Constant(value)]),
            Effect::Copy { src, mask, .. } => self.map_values(index, src, Transform::Mask(mask)),
            Effect::AddImmediate {
                src, value, mask, ..
            } => self.map_values(
                index,
                src,
                Transform::Add {
                    addend: value,
                    mask,
                },
            ),
            Effect::Insert {
                dst,
                value,
                shift,
                width,
            } => self.map_values(
                index,
                dst,
                Transform::Insert {
                    bits: value,
                    shift,
                    width,
                },
            ),
            Effect::SignExtend { src, .. } => self.map_values(index, src, Transform::SignExtend32),
            Effect::LoadAbsolute { address, .. } => BTreeSet::from([self.got_value(address)]),
            Effect::Load {
                base,
                has_index: false,
                displacement,
                width: 8,
                ..
            } => self
                .values_before(index, base)
                .into_iter()
                .map(|value| match value {
                    Value::Constant(base) => self.got_value(base.wrapping_add_signed(displacement)),
                    Value::Entry(..) | Value::Unknown(_) => self.unfollowed(index),
                })
                .collect(),
            Effect::Opaque | Effect::AddShifted { .. } | Effect::Load { .. } => {
                BTreeSet::from([self.unfollowed(index)])
            }
        }
    }

    fn got_value(&self, address: u64) -> Value {
        self.image.got_entry(address).map_or_else(
            || {
                Value::Unknown(format!(
                    "{} loads from memory at {address:#x} that is not a GOT slot",
                    self.name
                ))
            },
            Value::Constant,
        )
    }

    fn unfollowed(&self, index: usize) -> Value {
        Value::Unknown(format!(
            "{} computes the register at {:#x} in a way the analysis does not follow",
            self.name, self.insns[index].address
        ))
    }

    fn map_values(&self, index: usize, reg: Reg, transform: Transform) -> BTreeSet<Value> {
        self.values_before(index, reg)
            .into_iter()
            .map(|value| match value {
                Value::Constant(value) => Value::Constant(transform.apply(value)),
                Value::Entry(reg, mut transforms) => {
                    transforms.push(transform);
                    Value::Entry(reg, transforms)
                }
                unknown @ Value::Unknown(_) => unknown,
            })
            .collect()
    }

    /// Where a function pointer goes once instruction `load` puts it in `reg`.
    pub(super) fn pointer_uses_after(&self, load: usize, reg: Reg) -> Result<PointerUses, String> {
        let starts = self.succs[load]
            .iter()
            .map(|&next| (next, 1_u64 << reg))
            .collect();
        self.pointer_uses(starts)
    }

    /// Where a function pointer goes when it arrives in the `holding` registers at entry.
    pub(super) fn pointer_uses_from_entry(&self, holding: u64) -> Result<PointerUses, String> {
        if self.insns.is_empty() {
            return Ok(PointerUses::default());
        }
        self.pointer_uses(vec![(0, holding)])
    }

    /// Follows the registers holding a function pointer to the calls through it. Storing,
    /// returning, an indirect call receiving it, or any other read is an escape the analysis
    /// cannot follow.
    fn pointer_uses(&self, mut pending: Vec<(usize, u64)>) -> Result<PointerUses, String> {
        if let Some(reason) = &self.incomplete {
            return Err(reason.clone());
        }
        let architecture = self.image.architecture;
        let arguments = architecture
            .arguments()
            .iter()
            .fold(0_u64, |bits, reg| bits | (1 << reg));
        let caller_saved = (0..32)
            .filter(|reg| architecture.call_clobbers(*reg))
            .fold(0_u64, |bits, reg| bits | (1 << reg));
        // The block entries a state was first reached through, to show the path of an escape.
        let mut came_from = CameFrom::new();
        let escape = |index: usize, holding: u64, came_from: &CameFrom, how: &str| {
            Err(format!(
                "{} {how} the function pointer at {:#x} (reached through {})",
                self.name,
                self.insns[index].address,
                self.describe_path((index, holding), came_from)
            ))
        };
        let mut uses = PointerUses::default();
        let mut seen = HashSet::new();
        while let Some((index, holding)) = pending.pop() {
            if holding == 0 || !seen.insert((index, holding)) {
                continue;
            }
            let insn = &self.insns[index];
            let target = match insn.flow {
                Flow::Call(Callee::Register(target)) | Flow::RegisterJump(target) => Some(target),
                _ => None,
            }
            .filter(|target| holding & (1 << target) != 0);
            if target.is_some() {
                uses.calls.push(index);
            }
            let copied = match insn.effect {
                Effect::Copy {
                    dst,
                    src,
                    mask: u64::MAX,
                } if holding & (1 << src) != 0 => Some((dst, src)),
                _ => None,
            };
            // A zeroing idiom such as `xor eax, eax` names its register without reading it.
            let overwritten = match insn.effect {
                Effect::Constant { dst, .. } => 1 << dst,
                _ => 0,
            };
            let allowed = target.map_or(0, |target| 1 << target)
                | copied.map_or(0, |(_, src)| 1 << src)
                | overwritten;
            if insn.reads & holding & !allowed != 0 {
                return escape(index, holding, &came_from, "reads");
            }
            let passed = holding & arguments & !target.map_or(0, |target| 1 << target);
            match insn.flow {
                Flow::Call(Callee::Direct(_) | Callee::Slot(_)) | Flow::TailCall(_)
                    if passed != 0 =>
                {
                    uses.passes.push((index, passed));
                }
                Flow::Jump { target, .. } if passed != 0 && self.index_of(target).is_none() => {
                    uses.passes.push((index, passed));
                }
                Flow::Call(_) | Flow::Syscall | Flow::LegacySyscall if passed != 0 => {
                    return escape(index, holding, &came_from, "passes");
                }
                Flow::Return if holding & (1 << RETURN_VALUE) != 0 => {
                    return escape(index, holding, &came_from, "returns");
                }
                _ => {}
            }
            let mut next = holding & !insn.writes;
            if matches!(insn.flow, Flow::Call(_)) {
                next &= !caller_saved;
            }
            if let Some((dst, _)) = copied {
                next |= 1 << dst;
            }
            for &successor in &self.succs[index] {
                came_from
                    .entry((successor, next))
                    .or_insert((index, holding));
                pending.push((successor, next));
            }
        }
        Ok(uses)
    }
}

impl FunctionFlow<'_> {
    /// The block entries on the path to `state`, oldest first.
    fn describe_path(&self, mut state: (usize, u64), came_from: &CameFrom) -> String {
        let mut path = Vec::new();
        while let Some(&previous) = came_from.get(&state) {
            if previous.0 + 1 != state.0 {
                path.push(format!("{:#x}", self.insns[state.0].address));
            }
            state = previous;
            if path.len() > 12 {
                break;
            }
        }
        path.reverse();
        path.join(" -> ")
    }
}

/// Reads entries until the first target outside `function`, which ends the table. Reading into
/// a following table only adds edges, which can make values less precise, never wrong.
fn read_relative_table(
    image: &Image,
    table: u64,
    base: u64,
    width: u8,
    is_signed: bool,
    shift: u32,
    function: &Range<u64>,
) -> Vec<u64> {
    let mut targets = Vec::new();
    for index in 0..MAX_TABLE_ENTRIES {
        let Some(bytes) = image.read(table + index * u64::from(width), usize::from(width)) else {
            break;
        };
        let mut raw = [0_u8; 8];
        raw[..bytes.len()].copy_from_slice(bytes);
        let mut entry = u64::from_le_bytes(raw);
        if is_signed && width < 8 {
            let unused = 64 - u32::from(width) * 8;
            entry = ((entry << unused).cast_signed() >> unused).cast_unsigned();
        }
        let target = base.wrapping_add(entry << shift);
        if !function.contains(&target) {
            break;
        }
        targets.push(target);
    }
    targets
}

/// Reads absolute entries until the first target outside `function`, as
/// [`read_relative_table`] does.
fn read_absolute_table(image: &Image, table: u64, function: &Range<u64>) -> Vec<u64> {
    (0..MAX_TABLE_ENTRIES)
        .map_while(|index| image.read_u64(table + index * 8))
        .take_while(|target| function.contains(target))
        .collect()
}
