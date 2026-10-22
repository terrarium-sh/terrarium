//! Finds every syscall a role binary can make, failing wherever the analysis cannot be sure.

use super::flow::{FunctionFlow, InteriorReferences, PointerUses, Surroundings, Value};
use super::image::Image;
use super::isa::{
    Architecture, Callee, Decoder, Effect, Flow, Insn, Reference, Reg, RegisterFile as _,
};
use anyhow::{Result, bail};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;

/// What each (function, register) receives from its callers; `None` marks a resolution in progress.
type CallerValues = HashMap<(usize, Reg), Option<BTreeSet<Value>>>;

/// The most problems listed before the rest are summarized.
const MAX_REPORTED_PROBLEMS: usize = 40;

/// The syscall numbers and `ioctl` requests one role binary can issue.
pub(super) struct RoleScan {
    pub(super) architecture: Architecture,
    pub(super) syscalls: BTreeSet<u64>,
    pub(super) ioctls: BTreeSet<u64>,
    /// Functions the binary runs before `main` or after it returns, by name.
    pub(super) constructors: BTreeSet<String>,
}

pub(super) fn scan(path: &Path) -> Result<RoleScan> {
    scan_image(&Image::load(path)?)
        .map_err(|error| anyhow::anyhow!("{}: {error:#}", path.display()))
}

fn scan_image(image: &Image) -> Result<RoleScan> {
    let decoder = Decoder::new(image.architecture)?;
    let program = Program::discover(image, &decoder)?;
    let architecture = image.architecture;
    let ioctl = u64::from(
        architecture
            .resolve_syscall_number("ioctl")
            .map_err(anyhow::Error::msg)?,
    );
    let mut problems = program.legacy_entries.clone();
    problems.extend(program.check_raw_syscall_bytes()?);
    let mut syscalls = BTreeSet::new();
    let mut ioctls = BTreeSet::new();
    for &(function, index) in &program.sites {
        let address = program.flow(function)?.insns[index].address;
        for number in program.syscall_numbers(function, index)? {
            let Value::Constant(number) = number else {
                problems.push(format!("syscall at {address:#x}: {}", describe(&number)));
                continue;
            };
            syscalls.insert(number);
            if number != ioctl {
                continue;
            }
            let mut callers = CallerValues::new();
            for request in program.resolve(
                function,
                index,
                architecture.second_argument(),
                &mut callers,
            )? {
                match request {
                    Value::Constant(request) => {
                        ioctls.insert(request & 0xffff_ffff);
                    }
                    other => problems.push(format!(
                        "ioctl request at {address:#x}: {}",
                        describe(&other)
                    )),
                }
            }
        }
    }
    if !problems.is_empty() {
        problems.sort();
        problems.dedup();
        let total = problems.len();
        problems.truncate(MAX_REPORTED_PROBLEMS);
        bail!(
            "the syscall analysis cannot vouch for {total} site(s):\n  {}",
            problems.join("\n  ")
        );
    }
    Ok(RoleScan {
        architecture,
        syscalls,
        ioctls,
        constructors: image.constructors.clone(),
    })
}

fn describe(value: &Value) -> String {
    match value {
        Value::Constant(value) => format!("{value:#x}"),
        Value::Entry(reg, _) => format!("register {reg} from an unknown caller"),
        Value::Unknown(reason) => reason.clone(),
    }
}

/// An instruction that puts a function's address in a register, or reads it some other way.
#[derive(Clone, Copy)]
struct Materialization {
    function: usize,
    index: usize,
    /// `None` when the address is consumed some way other than landing in a register.
    register: Option<Reg>,
}

/// A function's callers: the call sites the analysis can resolve, or why some cannot be known.
#[derive(Clone, Default)]
struct Callers {
    sites: Vec<(usize, usize)>,
    problems: Vec<String>,
}

/// The `(function, instruction)` calls a function pointer reaches, or how it escapes.
type CallSites = Result<Vec<(usize, usize)>, String>;

/// Facts gathered from every function, and function flows built on demand.
struct Program<'a> {
    image: &'a Image,
    decoder: &'a Decoder,
    sites: Vec<(usize, usize)>,
    legacy_entries: Vec<String>,
    /// Direct call, tail-call and GOT-slot call sites by callee.
    direct_callers: HashMap<usize, Vec<(usize, usize)>>,
    /// Addresses inside a function that another function jumps or calls to.
    foreign_entries: HashMap<usize, Vec<u64>>,
    /// Starts of functions that cannot return to their caller.
    no_return: HashSet<u64>,
    /// Data locations holding an address inside each function, past its start.
    interior_pointers: HashMap<usize, Vec<u64>>,
    /// Interior addresses code materializes, by function.
    interior_materialized: HashMap<usize, Vec<u64>>,
    /// Data locations holding each function start, by that start.
    function_start_locations: HashMap<u64, Vec<u64>>,
    /// Where code materializes each function start, by that start.
    materializations: HashMap<u64, Vec<Materialization>>,
    flows: RefCell<HashMap<usize, Rc<FunctionFlow<'a>>>>,
    callers: RefCell<HashMap<usize, Rc<Callers>>>,
    /// Calls reached by a function pointer that enters a function in the given registers.
    entry_uses: RefCell<HashMap<(usize, u64), Rc<CallSites>>>,
}

impl<'a> Program<'a> {
    fn discover(image: &'a Image, decoder: &'a Decoder) -> Result<Self> {
        let mut program = Self {
            image,
            decoder,
            sites: Vec::new(),
            legacy_entries: Vec::new(),
            direct_callers: HashMap::new(),
            foreign_entries: HashMap::new(),
            materializations: HashMap::new(),
            function_start_locations: image.function_start_locations(),
            no_return: HashSet::new(),
            interior_pointers: image.interior_pointers(),
            interior_materialized: HashMap::new(),
            flows: RefCell::new(HashMap::new()),
            callers: RefCell::new(HashMap::new()),
            entry_uses: RefCell::new(HashMap::new()),
        };
        // Per function: whether it can leave other than by a tail call, and its tail-call targets.
        let mut exits = Vec::with_capacity(image.functions.len());
        for (function, range) in image.functions.iter().enumerate() {
            let (insns, has_gaps) = decoder.decode(image.code(range)?, range.start)?;
            exits.push(function_exits(image, range, &insns, has_gaps));
            let mut pages = [None::<u64>; 32];
            for (index, insn) in insns.iter().enumerate() {
                program.record_instruction(function, index, insn, &mut pages);
            }
        }
        program.no_return = find_no_return(image, &exits);
        Ok(program)
    }

    /// Records what instruction `index` of `function` contributes: syscall sites, call edges,
    /// and the function addresses it materializes. `pages` tracks `AArch64` `adrp` results.
    fn record_instruction(
        &mut self,
        function: usize,
        index: usize,
        insn: &Insn,
        pages: &mut [Option<u64>; 32],
    ) {
        let range = &self.image.functions[function];
        match insn.flow {
            Flow::Syscall => self.sites.push((function, index)),
            Flow::LegacySyscall => self.legacy_entries.push(format!(
                "{} uses a legacy syscall entry at {:#x}",
                range.name, insn.address
            )),
            Flow::Call(callee) | Flow::TailCall(callee) => {
                self.record_callee(callee, (function, index));
            }
            Flow::Jump { target, .. } if !(range.start..range.end).contains(&target) => {
                self.record_callee(Callee::Direct(target), (function, index));
            }
            _ => {}
        }
        let destination = insn.effect.destination();
        let at = |register| Materialization {
            function,
            index,
            register,
        };
        match insn.reference {
            Some(Reference::Value(address)) => {
                self.record_materialization(address, at(destination));
            }
            Some(Reference::Memory(slot)) => {
                let is_load = matches!(insn.effect, Effect::LoadAbsolute { .. });
                if let Some(target) = self.image.read_u64(slot) {
                    self.record_materialization(target, at(destination.filter(|_| is_load)));
                }
            }
            None => {}
        }
        match insn.effect {
            Effect::AddImmediate { src, value, .. } => {
                if let Some(page) = pages[usize::from(src)] {
                    self.record_materialization(page.wrapping_add(value), at(destination));
                }
            }
            Effect::Load {
                base,
                has_index: false,
                displacement,
                width: 8,
                ..
            } => {
                if let Some(page) = pages[usize::from(base)]
                    && let Some(target) =
                        self.image.read_u64(page.wrapping_add_signed(displacement))
                {
                    self.record_materialization(target, at(destination));
                }
            }
            _ => {}
        }
        let mut written = insn.writes;
        while written != 0 {
            pages[written.trailing_zeros() as usize] = None;
            written &= written - 1;
        }
        if let Some((reg, page)) = insn.page {
            pages[usize::from(reg)] = Some(page);
        }
    }

    fn record_callee(&mut self, callee: Callee, site: (usize, usize)) {
        let target = match callee {
            Callee::Direct(target) => target,
            Callee::Slot(slot) => {
                let Some(target) = self.image.read_u64(slot) else {
                    return;
                };
                target
            }
            Callee::Register(_) | Callee::Indirect => return,
        };
        if let Some(&callee) = self.image.by_start.get(&target) {
            self.direct_callers.entry(callee).or_default().push(site);
        } else if let Some(callee) = self.image.function_at(target) {
            self.foreign_entries.entry(callee).or_default().push(target);
        }
    }

    fn record_materialization(&mut self, address: u64, materialization: Materialization) {
        if let Some(function) = self.image.function_at(address)
            && self.image.functions[function].start != address
        {
            self.interior_materialized
                .entry(function)
                .or_default()
                .push(address);
        }
        if self.image.by_start.contains_key(&address) {
            self.materializations
                .entry(address)
                .or_default()
                .push(materialization);
        }
    }

    fn flow(&self, function: usize) -> Result<Rc<FunctionFlow<'a>>> {
        if let Some(flow) = self.flows.borrow().get(&function) {
            return Ok(Rc::clone(flow));
        }
        let range = &self.image.functions[function];
        let decoded = self.decoder.decode(self.image.code(range)?, range.start)?;
        let flow = Rc::new(FunctionFlow::new(
            self.image,
            &range.name,
            range.start..range.end,
            decoded,
            &Surroundings {
                foreign_entries: self
                    .foreign_entries
                    .get(&function)
                    .map_or(&[], Vec::as_slice),
                no_return: &self.no_return,
                interior: InteriorReferences {
                    data: self
                        .interior_pointers
                        .get(&function)
                        .map_or(&[], Vec::as_slice),
                    materialized: self
                        .interior_materialized
                        .get(&function)
                        .map_or(&[], Vec::as_slice),
                },
            },
        ));
        self.flows.borrow_mut().insert(function, Rc::clone(&flow));
        Ok(flow)
    }

    /// Every site that can call `function`: direct calls, and indirect calls through a pointer
    /// to it that never escapes the function that loaded it.
    fn callers_of(&self, function: usize) -> Result<Rc<Callers>> {
        if let Some(callers) = self.callers.borrow().get(&function) {
            return Ok(Rc::clone(callers));
        }
        let range = &self.image.functions[function];
        let mut callers = Callers {
            sites: self
                .direct_callers
                .get(&function)
                .cloned()
                .unwrap_or_default(),
            problems: Vec::new(),
        };
        for &location in self
            .function_start_locations
            .get(&range.start)
            .map_or(&[][..], Vec::as_slice)
        {
            if self.image.got_entry(location) != Some(range.start) {
                callers.problems.push(format!(
                    "{}'s address is stored in data at {location:#x}",
                    range.name
                ));
            }
        }
        for materialization in self
            .materializations
            .get(&range.start)
            .map_or(&[][..], Vec::as_slice)
        {
            let flow = self.flow(materialization.function)?;
            let Some(register) = materialization.register else {
                callers.problems.push(format!(
                    "{} reads {}'s address at {:#x} without loading it into a register",
                    flow.name, range.name, flow.insns[materialization.index].address
                ));
                continue;
            };
            let uses = flow
                .pointer_uses_after(materialization.index, register)
                .and_then(|uses| self.follow_pointer_uses(materialization.function, uses));
            match uses {
                Ok(sites) => callers.sites.extend(sites),
                Err(reason) => callers
                    .problems
                    .push(format!("{reason}, which may call {}", range.name)),
            }
        }
        let callers = Rc::new(callers);
        self.callers
            .borrow_mut()
            .insert(function, Rc::clone(&callers));
        Ok(callers)
    }

    /// The call sites a function pointer reaches, following it into the direct callees it is
    /// passed to.
    fn follow_pointer_uses(
        &self,
        function: usize,
        uses: PointerUses,
    ) -> Result<Vec<(usize, usize)>, String> {
        let mut sites: Vec<_> = uses
            .calls
            .into_iter()
            .map(|site| (function, site))
            .collect();
        for (index, holding) in uses.passes {
            let flow = self.flow(function).map_err(|error| format!("{error:#}"))?;
            let insn = &flow.insns[index];
            let target = match insn.flow {
                Flow::Call(Callee::Direct(target))
                | Flow::TailCall(Callee::Direct(target))
                | Flow::Jump { target, .. } => Some(target),
                Flow::Call(Callee::Slot(slot)) | Flow::TailCall(Callee::Slot(slot)) => {
                    self.image.read_u64(slot)
                }
                _ => None,
            };
            let Some(callee) = target.and_then(|target| self.image.by_start.get(&target).copied())
            else {
                return Err(format!(
                    "{} passes the function pointer to an unknown callee at {:#x}",
                    flow.name, insn.address
                ));
            };
            sites.extend(self.pointer_uses_from_entry(callee, holding)?);
        }
        Ok(sites)
    }

    fn pointer_uses_from_entry(
        &self,
        function: usize,
        holding: u64,
    ) -> Result<Vec<(usize, usize)>, String> {
        if let Some(uses) = self.entry_uses.borrow().get(&(function, holding)) {
            return (**uses).clone();
        }
        // A cycle back into a function already being followed adds no new sites.
        self.entry_uses
            .borrow_mut()
            .insert((function, holding), Rc::new(Ok(Vec::new())));
        let uses = self
            .flow(function)
            .map_err(|error| format!("{error:#}"))
            .and_then(|flow| flow.pointer_uses_from_entry(holding))
            .and_then(|uses| self.follow_pointer_uses(function, uses));
        self.entry_uses
            .borrow_mut()
            .insert((function, holding), Rc::new(uses.clone()));
        uses
    }

    fn syscall_numbers(&self, function: usize, index: usize) -> Result<BTreeSet<Value>> {
        let architecture = self.image.architecture;
        let mut callers = CallerValues::new();
        // musl's do_setxid runs on every thread with the number __setxid stored in a struct, so
        // the number is __setxid's first argument, provided __setxid alone hands do_setxid out.
        if self.image.functions[function].name == "do_setxid"
            && let Some(setxid) = self.image.function_named("__setxid")
        {
            let start = self.image.functions[function].start;
            let handed_out_by = self
                .materializations
                .get(&start)
                .map_or(&[][..], Vec::as_slice);
            if handed_out_by.is_empty()
                || handed_out_by.iter().any(|use_| use_.function != setxid)
                || self.function_start_locations.contains_key(&start)
            {
                return Ok(BTreeSet::from([Value::Unknown(
                    "do_setxid's address reaches code other than __setxid".into(),
                )]));
            }
            return self.resolve_from_callers(setxid, architecture.arguments()[0], &mut callers);
        }
        self.resolve(function, index, architecture.syscall_number(), &mut callers)
    }

    /// The values `reg` holds before `index`, following incoming arguments into every caller.
    fn resolve(
        &self,
        function: usize,
        index: usize,
        reg: Reg,
        callers: &mut CallerValues,
    ) -> Result<BTreeSet<Value>> {
        let flow = self.flow(function)?;
        let mut resolved = BTreeSet::new();
        for value in flow.values_before(index, reg) {
            let Value::Entry(argument, transforms) = value else {
                resolved.insert(value);
                continue;
            };
            if !self.image.architecture.arguments().contains(&argument) {
                resolved.insert(Value::Unknown(format!(
                    "{} takes register {argument} from its caller outside the calling convention",
                    flow.name
                )));
                continue;
            }
            let from_callers = self.resolve_from_callers(function, argument, callers)?;
            resolved.extend(from_callers.into_iter().map(|value| {
                match value {
                    Value::Constant(value) => Value::Constant(
                        transforms
                            .iter()
                            .fold(value, |value, transform| transform.apply(value)),
                    ),
                    other => other,
                }
            }));
        }
        Ok(resolved)
    }

    fn resolve_from_callers(
        &self,
        function: usize,
        argument: Reg,
        resolved_callers: &mut CallerValues,
    ) -> Result<BTreeSet<Value>> {
        match resolved_callers.get(&(function, argument)) {
            Some(Some(resolved)) => return Ok(resolved.clone()),
            Some(None) => {
                return Ok(BTreeSet::from([Value::Unknown(format!(
                    "{} receives register {argument} back through its own callers",
                    self.image.functions[function].name
                ))]));
            }
            None => {}
        }
        resolved_callers.insert((function, argument), None);
        let mut resolved = BTreeSet::new();
        let callers = self.callers_of(function)?;
        resolved.extend(callers.problems.iter().cloned().map(Value::Unknown));
        if callers.sites.is_empty() && callers.problems.is_empty() {
            resolved.insert(Value::Unknown(format!(
                "{} has no caller the analysis can see",
                self.image.functions[function].name
            )));
        }
        for &(caller, site) in &callers.sites {
            resolved.extend(self.resolve(caller, site, argument, resolved_callers)?);
        }
        resolved_callers.insert((function, argument), Some(resolved.clone()));
        Ok(resolved)
    }

    /// Every syscall instruction encoding in executable memory must be an analyzed site or lie
    /// inside another instruction.
    fn check_raw_syscall_bytes(&self) -> Result<Vec<String>> {
        let mut problems = Vec::new();
        for (section, bytes) in self.image.executable_sections() {
            let candidates: Vec<u64> = match self.image.architecture {
                Architecture::X86_64 => bytes
                    .windows(2)
                    .enumerate()
                    .filter(|(_, pair)| matches!(pair, [0x0f, 0x05 | 0x34] | [0xcd, 0x80]))
                    .map(|(offset, _)| section + offset as u64)
                    .collect(),
                Architecture::Aarch64 => bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .enumerate()
                    .filter(|(_, word)| u32::from_le_bytes(**word) & 0xffe0_001f == 0xd400_0001)
                    .map(|(index, _)| section + index as u64 * 4)
                    .collect(),
            };
            for address in candidates {
                if let Some(problem) = self.check_raw_candidate(address)? {
                    problems.push(problem);
                }
            }
        }
        Ok(problems)
    }

    fn check_raw_candidate(&self, address: u64) -> Result<Option<String>> {
        let Some(function) = self.image.function_at(address) else {
            return Ok(Some(format!(
                "syscall instruction bytes at {address:#x} lie outside every function"
            )));
        };
        let range = &self.image.functions[function];
        let flow = self.flow(function)?;
        let containing = flow
            .insns
            .iter()
            .find(|insn| insn.address <= address && address < insn.end());
        Ok(match containing {
            Some(insn)
                if insn.address < address
                    || matches!(insn.flow, Flow::Syscall | Flow::LegacySyscall) =>
            {
                None
            }
            Some(_) => Some(format!(
                "syscall instruction bytes at {address:#x} in {} decode as another instruction",
                range.name
            )),
            None => Some(format!(
                "syscall instruction bytes at {address:#x} in {} were not decoded as code",
                range.name
            )),
        })
    }
}

/// Functions with no return instruction, no indirect exit, and tail calls only into other such
/// functions: with `panic = "abort"` nothing unwinds, so a call into one never comes back.
fn find_no_return(image: &Image, exits: &[(bool, Vec<u64>)]) -> HashSet<u64> {
    let mut no_return: HashSet<u64> = image
        .functions
        .iter()
        .zip(exits)
        .filter(|(_, (can_return, _))| !can_return)
        .map(|(function, _)| function.start)
        .collect();
    loop {
        let returning: Vec<u64> = image
            .functions
            .iter()
            .zip(exits)
            .filter(|(function, (_, tails))| {
                no_return.contains(&function.start)
                    && tails.iter().any(|target| !no_return.contains(target))
            })
            .map(|(function, _)| function.start)
            .collect();
        if returning.is_empty() {
            return no_return;
        }
        for start in returning {
            no_return.remove(&start);
        }
    }
}

/// Whether a function can leave other than by a tail call, and its tail-call targets.
fn function_exits(
    image: &Image,
    range: &super::image::Function,
    insns: &[Insn],
    has_gaps: bool,
) -> (bool, Vec<u64>) {
    let mut can_return = has_gaps;
    let mut tail_targets = Vec::new();
    for insn in insns {
        match insn.flow {
            Flow::Return
            | Flow::RegisterJump(_)
            | Flow::AbsoluteTableJump { .. }
            | Flow::UnknownJump
            | Flow::TailCall(Callee::Register(_) | Callee::Indirect) => can_return = true,
            Flow::TailCall(Callee::Direct(target)) => tail_targets.push(target),
            Flow::TailCall(Callee::Slot(slot)) => match image.read_u64(slot) {
                Some(target) => tail_targets.push(target),
                None => can_return = true,
            },
            Flow::Jump { target, .. } if !(range.start..range.end).contains(&target) => {
                tail_targets.push(target);
            }
            _ => {}
        }
    }
    (can_return, tail_targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSCALL: [u8; 2] = [0x0f, 0x05];
    const RET: u8 = 0xc3;

    fn x86(functions: &[(&str, u64, Vec<u8>)]) -> Result<RoleScan> {
        let borrowed: Vec<_> = functions
            .iter()
            .map(|(name, start, code)| (*name, *start, code.as_slice()))
            .collect();
        scan_image(&Image::from_code(Architecture::X86_64, &borrowed))
    }

    fn mov_eax(value: u32) -> Vec<u8> {
        let mut code = vec![0xb8];
        code.extend(value.to_le_bytes());
        code
    }

    fn call(from: u64, to: u64) -> Vec<u8> {
        let offset = i32::try_from(to.cast_signed() - (from.cast_signed() + 5)).unwrap();
        let mut code = vec![0xe8];
        code.extend(offset.to_le_bytes());
        code
    }

    #[test]
    fn constant_numbers_and_partial_register_writes_resolve() -> Result<()> {
        let constant = [mov_eax(39), SYSCALL.to_vec(), vec![RET]].concat();
        // xor eax, eax; mov al, 0x38 builds the number in the low byte, as musl's __clone does.
        let partial = [vec![0x31, 0xc0, 0xb0, 0x38], SYSCALL.to_vec(), vec![RET]].concat();
        let scanned = x86(&[("getpid", 0x1000, constant), ("clone", 0x2000, partial)])?;
        assert_eq!(scanned.syscalls, BTreeSet::from([39, 0x38]));
        Ok(())
    }

    /// A wrapper's number arrives as an argument, so every direct caller supplies one.
    #[test]
    fn wrapper_numbers_resolve_through_every_caller() -> Result<()> {
        // mov rax, rdi; syscall; ret
        let wrapper = [vec![0x48, 0x89, 0xf8], SYSCALL.to_vec(), vec![RET]].concat();
        // mov edi, n; call wrapper; ret
        let caller = |start: u64, number: u32| {
            let mut code = vec![0xbf];
            code.extend(number.to_le_bytes());
            [code, call(start + 5, 0x1000), vec![RET]].concat()
        };
        let scanned = x86(&[
            ("syscall", 0x1000, wrapper),
            ("first", 0x2000, caller(0x2000, 202)),
            ("second", 0x3000, caller(0x3000, 231)),
        ])?;
        assert_eq!(scanned.syscalls, BTreeSet::from([202, 231]));
        Ok(())
    }

    /// Two paths reach one caller with different transforms; a caller resolved once must give
    /// its values to the second path too, or that path's number is silently dropped.
    #[test]
    fn numbers_resolve_through_every_path_to_a_shared_caller() -> Result<()> {
        // mov rax, rdi; syscall; ret
        let wrapper = [vec![0x48, 0x89, 0xf8], SYSCALL.to_vec(), vec![RET]].concat();
        // call wrapper; ret
        let unchanged = [call(0x2000, 0x1000), vec![RET]].concat();
        // add edi, 1; call wrapper; ret
        let incremented = [vec![0x83, 0xc7, 0x01], call(0x3003, 0x1000), vec![RET]].concat();
        // mov ebx, edi; call unchanged; mov edi, ebx; call incremented; ret
        let shared = [
            vec![0x89, 0xfb],
            call(0x4002, 0x2000),
            vec![0x89, 0xdf],
            call(0x4009, 0x3000),
            vec![RET],
        ]
        .concat();
        // mov edi, 200; call shared; ret
        let mut entry = vec![0xbf];
        entry.extend(200_u32.to_le_bytes());
        let entry = [entry, call(0x5005, 0x4000), vec![RET]].concat();
        let scanned = x86(&[
            ("syscall", 0x1000, wrapper),
            ("unchanged", 0x2000, unchanged),
            ("incremented", 0x3000, incremented),
            ("shared", 0x4000, shared),
            ("entry", 0x5000, entry),
        ])?;
        assert_eq!(scanned.syscalls, BTreeSet::from([200, 201]));
        Ok(())
    }

    #[test]
    fn ioctl_requests_resolve() -> Result<()> {
        // mov esi, 0x5413; syscall(ioctl)
        let mut fixed = mov_eax(16);
        fixed.extend([0xbe, 0x13, 0x54, 0x00, 0x00]);
        fixed.extend(SYSCALL);
        fixed.push(RET);
        let scanned = x86(&[("ioctl", 0x1000, fixed)])?;
        assert_eq!(scanned.ioctls, BTreeSet::from([0x5413]));
        Ok(())
    }

    /// A number loaded from ordinary memory could be anything, so generation must refuse.
    #[test]
    fn numbers_the_analysis_cannot_follow_fail_generation() {
        // mov rax, [rdi]; syscall; ret
        let loaded = [vec![0x48, 0x8b, 0x07], SYSCALL.to_vec(), vec![RET]].concat();
        let error = x86(&[("loaded", 0x1000, loaded)]).err().unwrap();
        assert!(error.to_string().contains("cannot vouch"), "{error:#}");
        // A wrapper nobody calls directly may be called with any number.
        let wrapper = [vec![0x48, 0x89, 0xf8], SYSCALL.to_vec(), vec![RET]].concat();
        assert!(x86(&[("syscall", 0x1000, wrapper)]).is_err());
    }

    /// A wrapper whose address is stored straight into memory can be called through that slot
    /// with any number, so its direct callers no longer vouch for it.
    #[test]
    fn function_addresses_stored_as_immediates_escape() {
        let wrapper = [vec![0x48, 0x89, 0xf8], SYSCALL.to_vec(), vec![RET]].concat();
        let mut caller = vec![0xbf];
        caller.extend(39_u32.to_le_bytes());
        let caller = [caller, call(0x2005, 0x1000), vec![RET]].concat();
        let functions = |stash: Vec<u8>| {
            x86(&[
                ("syscall", 0x1000, wrapper.clone()),
                ("caller", 0x2000, caller.clone()),
                ("stash", 0x3000, stash),
            ])
        };
        // mov qword ptr [rip + 0x100], 0x2001 (inside caller, not a function start); ret
        let harmless = [0x48, 0xc7, 0x05, 0, 1, 0, 0, 1, 0x20, 0, 0, RET].to_vec();
        assert_eq!(functions(harmless).unwrap().syscalls, BTreeSet::from([39]));
        // mov qword ptr [rip + 0x100], 0x1000; ret
        let escaping = [0x48, 0xc7, 0x05, 0, 1, 0, 0, 0, 0x10, 0, 0, RET].to_vec();
        assert!(functions(escaping).is_err());
    }

    /// Syscall bytes outside every function would be code the analysis never read.
    #[test]
    fn syscall_bytes_outside_functions_fail_generation() {
        let image = Image::from_code(
            Architecture::X86_64,
            &[("getpid", 0x1000, &[0xb8, 39, 0, 0, 0, 0x0f, 0x05, RET])],
        );
        let mut truncated = image;
        truncated.functions[0].end -= 3;
        assert!(scan_image(&truncated).is_err());
    }

    /// A data word holding an instruction start inside a function could be the target of its
    /// indirect jump, so generation must refuse; a word pointing between instructions is only a
    /// byte pattern (such as embedded metadata) and must not block the vtable tail call.
    #[test]
    fn interior_data_words_block_indirect_jumps_only_at_instruction_starts() -> Result<()> {
        // mov eax, 39; syscall; jmp [rcx + 8]
        let code = [mov_eax(39), SYSCALL.to_vec(), vec![0xff, 0x61, 0x08]].concat();
        let with_word = |word: u64| {
            let mut image = Image::from_code(Architecture::X86_64, &[("f", 0x1000, &code)]);
            image.add_data(0x8000, &word.to_le_bytes());
            scan_image(&image)
        };
        assert_eq!(with_word(0x1001)?.syscalls, BTreeSet::from([39]));
        let error = with_word(0x1005).err().unwrap();
        assert!(error.to_string().contains("cannot vouch"), "{error:#}");
        Ok(())
    }

    #[test]
    fn aarch64_svc_numbers_resolve_from_x8() -> Result<()> {
        let code: Vec<u8> = [0xd280_07e8_u32, 0xd400_0001, 0xd65f_03c0]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let scanned = scan_image(&Image::from_code(
            Architecture::Aarch64,
            &[("getpid", 0x1000, code.as_slice())],
        ))?;
        assert_eq!(scanned.syscalls, BTreeSet::from([63]));
        Ok(())
    }
}
