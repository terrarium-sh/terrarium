//! Decodes x86-64 and `AArch64` instructions into the facts the syscall analysis needs.

use anyhow::{Context as _, Result};
use capstone::arch::arm64::{Arm64CC, Arm64Insn, Arm64OperandType, Arm64Shift};
use capstone::arch::x86::{X86Insn, X86OperandType};
use capstone::arch::{ArchOperand, BuildsCapstone as _};
use capstone::{Capstone, InsnGroupType, RegId};
pub(super) use terra_build::seccomp::Architecture;

/// A general-purpose register: `rax`..`r15` in x86 encoding order, or `x0`..`x30` and `sp`.
pub(super) type Reg = u8;

const X86_REGS: [[&str; 4]; 16] = [
    ["rax", "eax", "ax", "al"],
    ["rcx", "ecx", "cx", "cl"],
    ["rdx", "edx", "dx", "dl"],
    ["rbx", "ebx", "bx", "bl"],
    ["rsp", "esp", "sp", "spl"],
    ["rbp", "ebp", "bp", "bpl"],
    ["rsi", "esi", "si", "sil"],
    ["rdi", "edi", "di", "dil"],
    ["r8", "r8d", "r8w", "r8b"],
    ["r9", "r9d", "r9w", "r9b"],
    ["r10", "r10d", "r10w", "r10b"],
    ["r11", "r11d", "r11w", "r11b"],
    ["r12", "r12d", "r12w", "r12b"],
    ["r13", "r13d", "r13w", "r13b"],
    ["r14", "r14d", "r14w", "r14b"],
    ["r15", "r15d", "r15w", "r15b"],
];
const X86_HIGH_BYTES: [(&str, Reg); 4] = [("ah", 0), ("ch", 1), ("dh", 2), ("bh", 3)];
const AARCH64_SP: Reg = 31;
/// `rax` and `x0` both carry a function's return value.
pub(super) const RETURN_VALUE: Reg = 0;

/// The register facts of an architecture's calling and syscall conventions.
pub(super) trait RegisterFile {
    fn syscall_number(self) -> Reg;
    /// The register holding a syscall's second argument, an `ioctl` request.
    fn second_argument(self) -> Reg;
    /// Integer argument registers of the C calling convention, in order.
    fn arguments(self) -> &'static [Reg];
    /// Registers a call may change.
    fn call_clobbers(self, reg: Reg) -> bool;
    fn disassembler(self) -> Result<Capstone>;
    /// The register and its value width in bits, or `None` for a partial or untracked register.
    fn register(self, name: &str) -> Option<(Reg, u32)>;
    /// An x86 register that names only some bits of one: its register, bit offset and width.
    fn partial_register(self, name: &str) -> Option<(Reg, u32, u32)>;
    /// Every general-purpose register `name` touches, partial ones included.
    fn touched_register(self, name: &str) -> Option<Reg>;
}

impl RegisterFile for Architecture {
    fn syscall_number(self) -> Reg {
        match self {
            Architecture::X86_64 => 0,
            Architecture::Aarch64 => 8,
        }
    }

    fn second_argument(self) -> Reg {
        match self {
            Architecture::X86_64 => 6,
            Architecture::Aarch64 => 1,
        }
    }

    fn arguments(self) -> &'static [Reg] {
        match self {
            Architecture::X86_64 => &[7, 6, 2, 1, 8, 9],
            Architecture::Aarch64 => &[0, 1, 2, 3, 4, 5, 6, 7],
        }
    }

    fn call_clobbers(self, reg: Reg) -> bool {
        match self {
            Architecture::X86_64 => matches!(reg, 0 | 1 | 2 | 6 | 7 | 8..=11),
            Architecture::Aarch64 => reg <= 18 || reg == 30,
        }
    }

    fn disassembler(self) -> Result<Capstone> {
        let disassembler = match self {
            Architecture::X86_64 => Capstone::new()
                .x86()
                .mode(capstone::arch::x86::ArchMode::Mode64)
                .detail(true)
                .build(),
            Architecture::Aarch64 => Capstone::new()
                .arm64()
                .mode(capstone::arch::arm64::ArchMode::Arm)
                .detail(true)
                .build(),
        };
        disassembler.context("creating the disassembler")
    }

    fn register(self, name: &str) -> Option<(Reg, u32)> {
        match self {
            Architecture::X86_64 => X86_REGS.iter().enumerate().find_map(|(index, names)| {
                let width = match names.iter().position(|alias| *alias == name)? {
                    0 => 64,
                    1 => 32,
                    _ => return None,
                };
                Some((Reg::try_from(index).ok()?, width))
            }),
            Architecture::Aarch64 => {
                let (width, number) = match name {
                    "sp" => return Some((AARCH64_SP, 64)),
                    "wsp" => return Some((AARCH64_SP, 32)),
                    "fp" => return Some((29, 64)),
                    "lr" => return Some((30, 64)),
                    _ => (
                        match name.as_bytes().first()? {
                            b'x' => 64,
                            b'w' => 32,
                            _ => return None,
                        },
                        name[1..].parse::<Reg>().ok()?,
                    ),
                };
                (number <= 30).then_some((number, width))
            }
        }
    }

    fn partial_register(self, name: &str) -> Option<(Reg, u32, u32)> {
        if self != Architecture::X86_64 {
            return None;
        }
        X86_REGS
            .iter()
            .enumerate()
            .find_map(|(index, names)| {
                let width = match names.iter().position(|alias| *alias == name)? {
                    2 => 16,
                    3 => 8,
                    _ => return None,
                };
                Some((Reg::try_from(index).ok()?, 0, width))
            })
            .or_else(|| {
                X86_HIGH_BYTES
                    .iter()
                    .find_map(|(high, reg)| (*high == name).then_some((*reg, 8, 8)))
            })
    }

    fn touched_register(self, name: &str) -> Option<Reg> {
        match self {
            Architecture::X86_64 => X86_REGS
                .iter()
                .position(|names| names.contains(&name))
                .and_then(|index| Reg::try_from(index).ok())
                .or_else(|| {
                    X86_HIGH_BYTES
                        .iter()
                        .find_map(|(high, reg)| (*high == name).then_some(*reg))
                }),
            Architecture::Aarch64 => self.register(name).map(|(reg, _)| reg),
        }
    }
}

/// Where a call goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Callee {
    Direct(u64),
    /// Through the function pointer stored at this address, such as a GOT slot.
    Slot(u64),
    Register(Reg),
    Indirect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Flow {
    Next,
    Syscall,
    /// `int 0x80` or `sysenter`: syscall entries the analysis does not model.
    LegacySyscall,
    Call(Callee),
    TailCall(Callee),
    Jump {
        target: u64,
        is_conditional: bool,
    },
    /// Through a register, as LLVM's relative jump tables do.
    RegisterJump(Reg),
    /// Through a table of absolute addresses at `table`, indexed in `scale`-byte entries.
    AbsoluteTableJump {
        table: u64,
        scale: u8,
    },
    UnknownJump,
    Return,
    Stop,
}

/// What an instruction does to the one register it is understood to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Effect {
    Opaque,
    Constant {
        dst: Reg,
        value: u64,
    },
    /// `dst = src & mask`.
    Copy {
        dst: Reg,
        src: Reg,
        mask: u64,
    },
    /// `dst = (src + value) & mask`.
    AddImmediate {
        dst: Reg,
        src: Reg,
        value: u64,
        mask: u64,
    },
    /// Replaces `width` bits of `dst` at `shift`, as `AArch64` `movk` or an x86 partial move.
    Insert {
        dst: Reg,
        value: u64,
        shift: u32,
        width: u32,
    },
    /// `dst = left + (right << shift)`.
    AddShifted {
        dst: Reg,
        left: Reg,
        right: Reg,
        shift: u32,
    },
    Load {
        dst: Reg,
        base: Reg,
        has_index: bool,
        displacement: i64,
        width: u8,
        is_signed: bool,
    },
    /// `dst = sign_extend(src & 0xffff_ffff)`.
    SignExtend {
        dst: Reg,
        src: Reg,
    },
    /// A 64-bit load from a fixed address, such as a GOT slot.
    LoadAbsolute {
        dst: Reg,
        address: u64,
    },
}

/// An address an instruction puts into a register or reads through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reference {
    /// Materialized as a value, such as `lea` or `adr`.
    Value(u64),
    /// Read as a pointer by an instruction other than a call or jump.
    Memory(u64),
}

#[derive(Clone, Debug)]
pub(super) struct Insn {
    pub(super) address: u64,
    pub(super) size: u8,
    pub(super) flow: Flow,
    pub(super) effect: Effect,
    /// Bit `reg` is set for every register the instruction may write.
    pub(super) writes: u64,
    /// Bit `reg` is set for every register the instruction may read.
    pub(super) reads: u64,
    pub(super) reference: Option<Reference>,
    /// `adrp`'s page, which the next `add` or load completes into a [`Reference`].
    pub(super) page: Option<(Reg, u64)>,
}

impl Effect {
    /// The register the effect writes, when the analysis understands the instruction.
    pub(super) const fn destination(self) -> Option<Reg> {
        match self {
            Self::Opaque => None,
            Self::Constant { dst, .. }
            | Self::Copy { dst, .. }
            | Self::AddImmediate { dst, .. }
            | Self::Insert { dst, .. }
            | Self::AddShifted { dst, .. }
            | Self::Load { dst, .. }
            | Self::SignExtend { dst, .. }
            | Self::LoadAbsolute { dst, .. } => Some(dst),
        }
    }
}

impl Insn {
    pub(super) const fn end(&self) -> u64 {
        self.address + self.size as u64
    }

    pub(super) const fn writes(&self, reg: Reg) -> bool {
        self.writes & (1 << reg) != 0
    }
}

/// A disassembler with register names resolved once, not per instruction.
pub(super) struct Decoder {
    architecture: Architecture,
    disassembler: Capstone,
    /// Indexed by capstone register id.
    registers: Vec<Option<(Reg, u32)>>,
    partials: Vec<Option<(Reg, u32, u32)>>,
    touched: Vec<Option<Reg>>,
}

impl Decoder {
    pub(super) fn new(architecture: Architecture) -> Result<Self> {
        let disassembler = architecture.disassembler()?;
        let names: Vec<Option<String>> = (0..1024_u16)
            .map(|id| disassembler.reg_name(RegId(id)))
            .collect();
        Ok(Self {
            architecture,
            registers: names
                .iter()
                .map(|name| name.as_deref().and_then(|name| architecture.register(name)))
                .collect(),
            partials: names
                .iter()
                .map(|name| {
                    name.as_deref()
                        .and_then(|name| architecture.partial_register(name))
                })
                .collect(),
            touched: names
                .iter()
                .map(|name| {
                    name.as_deref()
                        .and_then(|name| architecture.touched_register(name))
                })
                .collect(),
            disassembler,
        })
    }

    fn register(&self, id: RegId) -> Option<(Reg, u32)> {
        self.registers.get(usize::from(id.0)).copied().flatten()
    }

    /// Decodes `code` at `address`; bytes that do not decode are skipped and reported as gaps.
    pub(super) fn decode(&self, code: &[u8], address: u64) -> Result<(Vec<Insn>, bool)> {
        let step = match self.architecture {
            Architecture::X86_64 => 1,
            Architecture::Aarch64 => 4,
        };
        let mut insns = Vec::new();
        let mut has_gaps = false;
        let mut offset = 0;
        while offset < code.len() {
            let batch = self
                .disassembler
                .disasm_all(&code[offset..], address + offset as u64)
                .context("disassembling")?;
            for insn in batch.iter() {
                let insn = self.translate(insn)?;
                offset += usize::from(insn.size);
                insns.push(insn);
            }
            if offset < code.len() {
                has_gaps = true;
                offset += step;
            }
        }
        Ok((insns, has_gaps))
    }

    fn translate(&self, insn: &capstone::Insn<'_>) -> Result<Insn> {
        let detail = self
            .disassembler
            .insn_detail(insn)
            .context("reading instruction detail")?;
        let registers = |ids: &[RegId]| {
            ids.iter()
                .filter_map(|id| self.touched.get(usize::from(id.0)).copied().flatten())
                .fold(0, |bits, reg| bits | (1_u64 << reg))
        };
        let mut writes = registers(detail.regs_write());
        let reads = registers(detail.regs_read());
        let operands = detail.arch_detail().operands();
        let mut decoded = Insn {
            address: insn.address(),
            size: u8::try_from(insn.len()).context("instruction longer than 255 bytes")?,
            flow: Flow::Next,
            effect: Effect::Opaque,
            writes: 0,
            reads,
            reference: None,
            page: None,
        };
        let register = |id: RegId| self.register(id);
        let partial = |id: RegId| self.partials.get(usize::from(id.0)).copied().flatten();
        match self.architecture {
            Architecture::X86_64 => {
                let is_jump = detail
                    .groups()
                    .iter()
                    .any(|id| u32::from(id.0) == InsnGroupType::CS_GRP_JUMP);
                translate_x86(
                    &mut decoded,
                    insn.id().0,
                    &operands,
                    &register,
                    &partial,
                    is_jump,
                );
            }
            Architecture::Aarch64 => {
                let condition =
                    if let capstone::arch::ArchDetail::Arm64Detail(arm64) = detail.arch_detail() {
                        arm64.cc()
                    } else {
                        Arm64CC::ARM64_CC_INVALID
                    };
                translate_aarch64(&mut decoded, insn.id().0, &operands, &register, condition);
            }
        }
        // A call to the next instruction is a no-op call: AArch64 linkers resolve calls to an
        // undefined weak symbol that way, and x86 uses it to read the instruction pointer.
        if decoded.flow == Flow::Call(Callee::Direct(decoded.end())) {
            decoded.flow = Flow::Next;
        }
        // An explicit destination the access lists leave out still counts as written.
        if let Some(reg) = decoded.effect.destination() {
            writes |= 1 << reg;
        }
        if decoded.flow == Flow::Syscall {
            writes |= match self.architecture {
                Architecture::X86_64 => 1 << 0 | 1 << 1 | 1 << 11,
                Architecture::Aarch64 => 1 << 0,
            };
        }
        decoded.writes = writes;
        Ok(decoded)
    }
}

const fn mask(width: u32) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1 << width) - 1
    }
}

#[allow(
    clippy::cast_sign_loss,
    clippy::enum_glob_use,
    clippy::too_many_lines,
    reason = "one arm per instruction kind, named as capstone names the mnemonics; addresses and immediates are bit patterns"
)]
fn translate_x86(
    decoded: &mut Insn,
    id: u32,
    operands: &[ArchOperand],
    register: &dyn Fn(RegId) -> Option<(Reg, u32)>,
    partial: &dyn Fn(RegId) -> Option<(Reg, u32, u32)>,
    is_jump: bool,
) {
    use X86Insn::*;
    let next = decoded.end();
    let operand = |index: usize| match operands.get(index) {
        Some(ArchOperand::X86Operand(operand)) => Some(operand.op_type.clone()),
        _ => None,
    };
    let rip_relative = |memory: &capstone::arch::x86::X86OpMem| {
        let is_rip =
            register(memory.base()).is_none() && memory.base().0 != 0 && memory.index().0 == 0;
        is_rip.then(|| next.wrapping_add(memory.disp() as u64))
    };
    if id == X86_INS_SYSCALL as u32 {
        decoded.flow = Flow::Syscall;
        return;
    }
    if id == X86_INS_SYSENTER as u32
        || (id == X86_INS_INT as u32 && matches!(operand(0), Some(X86OperandType::Imm(0x80))))
    {
        decoded.flow = Flow::LegacySyscall;
        return;
    }
    if id == X86_INS_RET as u32 {
        decoded.flow = Flow::Return;
        return;
    }
    if id == X86_INS_UD2 as u32 || id == X86_INS_HLT as u32 || id == X86_INS_INT3 as u32 {
        decoded.flow = Flow::Stop;
        return;
    }
    if id == X86_INS_CALL as u32 || id == X86_INS_JMP as u32 {
        let callee = match operand(0) {
            Some(X86OperandType::Imm(target)) => Callee::Direct(target as u64),
            Some(X86OperandType::Mem(memory)) => {
                rip_relative(&memory).map_or(Callee::Indirect, Callee::Slot)
            }
            Some(X86OperandType::Reg(reg)) if id == X86_INS_CALL as u32 => {
                register(reg).map_or(Callee::Indirect, |(reg, _)| Callee::Register(reg))
            }
            _ => Callee::Indirect,
        };
        decoded.flow = if id == X86_INS_CALL as u32 {
            Flow::Call(callee)
        } else {
            match (callee, operand(0)) {
                (Callee::Direct(target), _) => Flow::Jump {
                    target,
                    is_conditional: false,
                },
                (Callee::Slot(_), _) => Flow::TailCall(callee),
                (_, Some(X86OperandType::Reg(reg))) => {
                    register(reg).map_or(Flow::UnknownJump, |(reg, _)| Flow::RegisterJump(reg))
                }
                (_, Some(X86OperandType::Mem(memory)))
                    if memory.base().0 == 0 && memory.index().0 != 0 =>
                {
                    u8::try_from(memory.scale()).map_or(Flow::UnknownJump, |scale| {
                        Flow::AbsoluteTableJump {
                            table: memory.disp() as u64,
                            scale,
                        }
                    })
                }
                _ => Flow::UnknownJump,
            }
        };
        return;
    }
    if is_jump {
        decoded.flow = match operand(0) {
            Some(X86OperandType::Imm(target)) => Flow::Jump {
                target: target as u64,
                is_conditional: true,
            },
            _ => Flow::UnknownJump,
        };
        return;
    }
    for index in 0..operands.len() {
        if let Some(X86OperandType::Mem(memory)) = operand(index)
            && let Some(address) = rip_relative(&memory)
        {
            decoded.reference = Some(if id == X86_INS_LEA as u32 {
                Reference::Value(address)
            } else {
                Reference::Memory(address)
            });
        }
    }
    let Some(X86OperandType::Reg(destination)) = operand(0) else {
        if id == X86_INS_MOV as u32
            && let Some(X86OperandType::Imm(value)) = operand(1)
        {
            decoded.reference = Some(Reference::Value(value as u64));
        }
        return;
    };
    if let (Some((dst, shift, width)), Some(X86OperandType::Imm(value)), None) =
        (partial(destination), operand(1), operand(2))
        && id == X86_INS_MOV as u32
    {
        decoded.effect = Effect::Insert {
            dst,
            value: value as u64 & mask(width),
            shift,
            width,
        };
        return;
    }
    let Some((dst, width)) = register(destination) else {
        return;
    };
    decoded.effect = match (operand(1), operand(2)) {
        (Some(X86OperandType::Imm(value)), None)
            if id == X86_INS_MOV as u32 || id == X86_INS_MOVABS as u32 =>
        {
            decoded.reference = Some(Reference::Value(value as u64));
            Effect::Constant {
                dst,
                value: value as u64 & mask(width),
            }
        }
        (Some(X86OperandType::Imm(value)), None) if id == X86_INS_ADD as u32 => {
            Effect::AddImmediate {
                dst,
                src: dst,
                value: value as u64,
                mask: mask(width),
            }
        }
        (Some(X86OperandType::Reg(source)), None) => match register(source) {
            Some((src, _)) if id == X86_INS_XOR as u32 && src == dst => {
                Effect::Constant { dst, value: 0 }
            }
            Some((src, source_width)) if id == X86_INS_MOV as u32 && source_width == width => {
                Effect::Copy {
                    dst,
                    src,
                    mask: mask(width),
                }
            }
            Some((src, 32)) if id == X86_INS_MOVSXD as u32 && width == 64 => {
                Effect::SignExtend { dst, src }
            }
            Some((src, 64)) if id == X86_INS_ADD as u32 && width == 64 => Effect::AddShifted {
                dst,
                left: dst,
                right: src,
                shift: 0,
            },
            _ => Effect::Opaque,
        },
        (Some(X86OperandType::Mem(memory)), None) if id == X86_INS_MOV as u32 && width == 64 => {
            rip_relative(&memory).map_or(Effect::Opaque, |address| Effect::LoadAbsolute {
                dst,
                address,
            })
        }
        (Some(X86OperandType::Mem(memory)), None) if id == X86_INS_LEA as u32 && width == 64 => {
            rip_relative(&memory).map_or(Effect::Opaque, |value| Effect::Constant { dst, value })
        }
        (Some(X86OperandType::Mem(memory)), None) if id == X86_INS_MOVSXD as u32 => {
            register(memory.base()).map_or(Effect::Opaque, |(base, _)| Effect::Load {
                dst,
                base,
                has_index: memory.index().0 != 0,
                displacement: memory.disp(),
                width: 4,
                is_signed: true,
            })
        }
        _ => Effect::Opaque,
    };
}

#[allow(
    clippy::cast_sign_loss,
    clippy::enum_glob_use,
    clippy::too_many_lines,
    reason = "one arm per instruction kind, named as capstone names the mnemonics; addresses and immediates are bit patterns"
)]
fn translate_aarch64(
    decoded: &mut Insn,
    id: u32,
    operands: &[ArchOperand],
    register: &dyn Fn(RegId) -> Option<(Reg, u32)>,
    condition: Arm64CC,
) {
    use Arm64Insn::*;
    let operand = |index: usize| match operands.get(index) {
        Some(ArchOperand::Arm64Operand(operand)) => Some((operand.op_type.clone(), operand.shift)),
        _ => None,
    };
    let immediate = |index: usize| match operand(index) {
        Some((Arm64OperandType::Imm(value), _)) => Some(value as u64),
        _ => None,
    };
    let left_shift = |shift: Arm64Shift| match shift {
        Arm64Shift::Invalid => Some(0),
        Arm64Shift::Lsl(amount) => Some(amount),
        _ => None,
    };
    let is = |instruction: Arm64Insn| id == instruction as u32;
    if is(ARM64_INS_SVC) {
        decoded.flow = Flow::Syscall;
        return;
    }
    if is(ARM64_INS_RET) || is(ARM64_INS_RETAA) || is(ARM64_INS_RETAB) || is(ARM64_INS_ERET) {
        decoded.flow = Flow::Return;
        return;
    }
    if is(ARM64_INS_BRK) || is(ARM64_INS_HLT) || is(ARM64_INS_UDF) {
        decoded.flow = Flow::Stop;
        return;
    }
    if is(ARM64_INS_BL) {
        decoded.flow = Flow::Call(immediate(0).map_or(Callee::Indirect, Callee::Direct));
        return;
    }
    if is(ARM64_INS_BLR) {
        decoded.flow = Flow::Call(match operand(0) {
            Some((Arm64OperandType::Reg(reg), _)) => {
                register(reg).map_or(Callee::Indirect, |(reg, _)| Callee::Register(reg))
            }
            _ => Callee::Indirect,
        });
        return;
    }
    if is(ARM64_INS_BLRAA) || is(ARM64_INS_BLRAAZ) || is(ARM64_INS_BLRAB) || is(ARM64_INS_BLRABZ) {
        decoded.flow = Flow::Call(Callee::Indirect);
        return;
    }
    if is(ARM64_INS_B) {
        decoded.flow = immediate(0).map_or(Flow::UnknownJump, |target| Flow::Jump {
            target,
            is_conditional: !matches!(
                condition,
                Arm64CC::ARM64_CC_INVALID | Arm64CC::ARM64_CC_AL | Arm64CC::ARM64_CC_NV
            ),
        });
        return;
    }
    if is(ARM64_INS_CBZ) || is(ARM64_INS_CBNZ) || is(ARM64_INS_TBZ) || is(ARM64_INS_TBNZ) {
        decoded.flow =
            immediate(operands.len().saturating_sub(1)).map_or(Flow::UnknownJump, |target| {
                Flow::Jump {
                    target,
                    is_conditional: true,
                }
            });
        return;
    }
    if is(ARM64_INS_BR) {
        decoded.flow = match operand(0) {
            Some((Arm64OperandType::Reg(reg), _)) => {
                register(reg).map_or(Flow::UnknownJump, |(reg, _)| Flow::RegisterJump(reg))
            }
            _ => Flow::UnknownJump,
        };
        return;
    }
    if is(ARM64_INS_BRAA) || is(ARM64_INS_BRAAZ) || is(ARM64_INS_BRAB) || is(ARM64_INS_BRABZ) {
        decoded.flow = Flow::UnknownJump;
        return;
    }
    let Some((Arm64OperandType::Reg(destination), _)) = operand(0) else {
        return;
    };
    let Some((dst, width)) = register(destination) else {
        return;
    };
    let is_zero = |id: RegId| register(id).is_none();
    decoded.effect = match (operand(1), operand(2)) {
        (Some((Arm64OperandType::Imm(value), shift)), None)
            if is(ARM64_INS_MOV) || is(ARM64_INS_MOVZ) =>
        {
            left_shift(shift).map_or(Effect::Opaque, |amount| Effect::Constant {
                dst,
                value: ((value as u64) << amount) & mask(width),
            })
        }
        (Some((Arm64OperandType::Imm(value), shift)), None) if is(ARM64_INS_MOVN) => {
            left_shift(shift).map_or(Effect::Opaque, |amount| Effect::Constant {
                dst,
                value: !((value as u64) << amount) & mask(width),
            })
        }
        (Some((Arm64OperandType::Imm(value), shift)), None) if is(ARM64_INS_MOVK) => {
            left_shift(shift).map_or(Effect::Opaque, |amount| Effect::Insert {
                width: 16,
                dst,
                value: value as u64 & 0xffff,
                shift: amount,
            })
        }
        (Some((Arm64OperandType::Imm(value), _)), None) if is(ARM64_INS_ADR) => {
            decoded.reference = Some(Reference::Value(value as u64));
            Effect::Constant {
                dst,
                value: value as u64,
            }
        }
        (Some((Arm64OperandType::Imm(value), _)), None) if is(ARM64_INS_ADRP) => {
            decoded.page = Some((dst, value as u64));
            Effect::Constant {
                dst,
                value: value as u64,
            }
        }
        (Some((Arm64OperandType::Reg(source), _)), None) if is(ARM64_INS_SXTW) && width == 64 => {
            register(source).map_or(Effect::Opaque, |(src, _)| Effect::SignExtend { dst, src })
        }
        (Some((Arm64OperandType::Reg(source), _)), None) if is(ARM64_INS_MOV) => {
            match register(source) {
                Some((src, _)) => Effect::Copy {
                    dst,
                    src,
                    mask: mask(width),
                },
                None if is_zero(source) => Effect::Constant { dst, value: 0 },
                None => Effect::Opaque,
            }
        }
        (Some((Arm64OperandType::Reg(source), _)), Some((Arm64OperandType::Imm(value), shift)))
            if is(ARM64_INS_ADD) =>
        {
            match (register(source), left_shift(shift)) {
                (Some((src, _)), Some(amount)) => Effect::AddImmediate {
                    dst,
                    src,
                    value: (value as u64) << amount,
                    mask: mask(width),
                },
                _ => Effect::Opaque,
            }
        }
        (Some((Arm64OperandType::Reg(left), _)), Some((Arm64OperandType::Reg(right), shift)))
            if is(ARM64_INS_ADD) && width == 64 =>
        {
            match (register(left), register(right), left_shift(shift)) {
                (Some((left, 64)), Some((right, _)), Some(amount)) => Effect::AddShifted {
                    dst,
                    left,
                    right,
                    shift: amount,
                },
                _ => Effect::Opaque,
            }
        }
        (Some((Arm64OperandType::Mem(memory), _)), None) => aarch64_load(id, width)
            .and_then(|(load_width, is_signed)| {
                register(memory.base()).map(|(base, _)| Effect::Load {
                    dst,
                    base,
                    has_index: memory.index().0 != 0,
                    displacement: i64::from(memory.disp()),
                    width: load_width,
                    is_signed,
                })
            })
            .unwrap_or(Effect::Opaque),
        _ => Effect::Opaque,
    };
}

/// The width and signedness of a single-register `AArch64` load, by instruction.
#[allow(
    clippy::enum_glob_use,
    reason = "capstone names instructions by their mnemonics"
)]
fn aarch64_load(id: u32, destination_width: u32) -> Option<(u8, bool)> {
    use Arm64Insn::*;
    let table = [
        (ARM64_INS_LDRB, 1, false),
        (ARM64_INS_LDURB, 1, false),
        (ARM64_INS_LDRSB, 1, true),
        (ARM64_INS_LDURSB, 1, true),
        (ARM64_INS_LDRH, 2, false),
        (ARM64_INS_LDURH, 2, false),
        (ARM64_INS_LDRSH, 2, true),
        (ARM64_INS_LDURSH, 2, true),
        (ARM64_INS_LDRSW, 4, true),
        (ARM64_INS_LDURSW, 4, true),
    ];
    if let Some((_, width, is_signed)) = table.iter().find(|(insn, _, _)| *insn as u32 == id) {
        return Some((*width, *is_signed));
    }
    (id == ARM64_INS_LDR as u32 || id == ARM64_INS_LDUR as u32)
        .then_some((if destination_width == 64 { 8 } else { 4 }, false))
}
