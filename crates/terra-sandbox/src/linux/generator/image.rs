//! A static Linux executable's functions and memory, as the analysis reads them.

use super::isa::Architecture;
use anyhow::{Context as _, Result, bail, ensure};
use object::elf::{SHF_ALLOC, SHF_EXECINSTR};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SectionFlags, SymbolKind};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

pub(super) struct Function {
    pub(super) name: String,
    pub(super) start: u64,
    pub(super) end: u64,
}

/// A loaded section's address range and file bytes.
struct Section {
    name: String,
    address: u64,
    bytes: Vec<u8>,
    is_executable: bool,
}

impl Section {
    fn end(&self) -> u64 {
        self.address + self.bytes.len() as u64
    }

    fn contains(&self, address: u64) -> bool {
        (self.address..self.end()).contains(&address)
    }
}

pub(super) struct Image {
    pub(super) architecture: Architecture,
    pub(super) functions: Vec<Function>,
    /// Function index by start address.
    pub(super) by_start: BTreeMap<u64, usize>,
    /// Every symbol name, aliases included, to its function's start.
    names: HashMap<String, u64>,
    sections: Vec<Section>,
    /// The functions registered to run before `main` or after it returns.
    pub(super) constructors: BTreeSet<String>,
}

/// Sections whose functions run before `main` or after it returns.
const CONSTRUCTOR_SECTIONS: [&str; 5] = [
    ".preinit_array",
    ".init_array",
    ".fini_array",
    ".ctors",
    ".dtors",
];

impl Image {
    pub(super) fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let file = object::File::parse(&*data)
            .with_context(|| format!("parsing {} as ELF", path.display()))?;
        let architecture = match file.architecture() {
            object::Architecture::X86_64 => Architecture::X86_64,
            object::Architecture::Aarch64 => Architecture::Aarch64,
            other => bail!("{}: unsupported architecture {other:?}", path.display()),
        };
        let mut sections = Vec::new();
        for section in file.sections() {
            let SectionFlags::Elf { sh_flags, .. } = section.flags() else {
                continue;
            };
            if !sh_flags.contains(SHF_ALLOC) || section.address() == 0 {
                continue;
            }
            sections.push(Section {
                name: section.name().unwrap_or_default().to_owned(),
                address: section.address(),
                bytes: section.data().unwrap_or_default().to_vec(),
                is_executable: sh_flags.contains(SHF_EXECINSTR),
            });
        }
        // Assembly routines often carry no size; such a symbol extends to the next one.
        let mut sized: BTreeMap<u64, (String, u64)> = BTreeMap::new();
        let mut names = HashMap::new();
        for symbol in file.symbols() {
            let Ok(name) = symbol.name() else { continue };
            if symbol.kind() != SymbolKind::Text || name.is_empty() {
                continue;
            }
            names.insert(name.to_owned(), symbol.address());
            let entry = sized
                .entry(symbol.address())
                .or_insert_with(|| (name.to_owned(), symbol.size()));
            entry.1 = entry.1.max(symbol.size());
        }
        ensure!(
            !sized.is_empty(),
            "{} has no function symbols; build it with `strip = \"none\"`",
            path.display()
        );
        // A size-less symbol inside a sized one is a label, not a function.
        let mut covered_until = 0;
        sized.retain(|start, (_, size)| {
            if *size == 0 && *start < covered_until {
                return false;
            }
            covered_until = covered_until.max(*start + *size);
            true
        });
        let starts: Vec<u64> = sized.keys().copied().collect();
        let mut functions = Vec::with_capacity(sized.len());
        for (position, (start, (name, size))) in sized.into_iter().enumerate() {
            let end = if size > 0 {
                start + size
            } else {
                let section_end = sections
                    .iter()
                    .find(|section| section.is_executable && section.contains(start))
                    .map_or(start, Section::end);
                starts
                    .get(position + 1)
                    .copied()
                    .map_or(section_end, |next| next.min(section_end))
            };
            if end > start {
                functions.push(Function { name, start, end });
            }
        }
        let constructors = read_constructors(&file, path)?;
        Ok(Self::new(
            architecture,
            functions,
            names,
            sections,
            constructors,
        ))
    }

    fn new(
        architecture: Architecture,
        functions: Vec<Function>,
        names: HashMap<String, u64>,
        sections: Vec<Section>,
        constructors: BTreeSet<String>,
    ) -> Self {
        let by_start = functions
            .iter()
            .enumerate()
            .map(|(index, function)| (function.start, index))
            .collect();
        Self {
            architecture,
            functions,
            by_start,
            names,
            sections,
            constructors,
        }
    }

    /// An image of `functions`, each its own executable section, for tests.
    #[cfg(test)]
    pub(super) fn from_code(architecture: Architecture, functions: &[(&str, u64, &[u8])]) -> Self {
        Self::new(
            architecture,
            functions
                .iter()
                .map(|(name, start, code)| Function {
                    name: (*name).to_owned(),
                    start: *start,
                    end: start + code.len() as u64,
                })
                .collect(),
            functions
                .iter()
                .map(|(name, start, _)| ((*name).to_owned(), *start))
                .collect(),
            functions
                .iter()
                .map(|(_, start, code)| Section {
                    name: ".text".to_owned(),
                    address: *start,
                    bytes: code.to_vec(),
                    is_executable: true,
                })
                .collect(),
            BTreeSet::new(),
        )
    }

    #[cfg(test)]
    pub(super) fn add_data(&mut self, address: u64, bytes: &[u8]) {
        self.sections.push(Section {
            name: ".rodata".to_owned(),
            address,
            bytes: bytes.to_vec(),
            is_executable: false,
        });
    }

    pub(super) fn read(&self, address: u64, length: usize) -> Option<&[u8]> {
        self.sections.iter().find_map(|section| {
            let offset = usize::try_from(address.checked_sub(section.address)?).ok()?;
            section.bytes.get(offset..offset.checked_add(length)?)
        })
    }

    /// The function pointer a GOT slot holds. The scanned role binaries are static executables
    /// that are not position independent, so their GOT is fixed at link time and read-only once
    /// relocation-read-only protection applies.
    pub(super) fn got_entry(&self, address: u64) -> Option<u64> {
        self.sections
            .iter()
            .any(|section| section.name.starts_with(".got") && section.contains(address))
            .then(|| self.read_u64(address))
            .flatten()
    }

    pub(super) fn read_u64(&self, address: u64) -> Option<u64> {
        Some(u64::from_le_bytes(self.read(address, 8)?.try_into().ok()?))
    }

    pub(super) fn code(&self, function: &Function) -> Result<&[u8]> {
        let length = usize::try_from(function.end - function.start)?;
        self.read(function.start, length)
            .with_context(|| format!("reading the code of {}", function.name))
    }

    /// The function containing `address`, if any.
    pub(super) fn function_at(&self, address: u64) -> Option<usize> {
        let (_, &index) = self.by_start.range(..=address).next_back()?;
        (address < self.functions[index].end).then_some(index)
    }

    pub(super) fn function_named(&self, name: &str) -> Option<usize> {
        self.by_start.get(self.names.get(name)?).copied()
    }

    pub(super) fn executable_sections(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.sections
            .iter()
            .filter(|section| section.is_executable)
            .map(|section| (section.address, section.bytes.as_slice()))
    }

    fn data_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections
            .iter()
            .filter(|section| !section.is_executable)
    }

    /// For each function, the aligned data locations holding a 64-bit address inside it, past its
    /// start. Compilers keep code pointers (vtables, jump tables, function-pointer statics)
    /// naturally aligned, and an unaligned scan finds byte patterns that only look like addresses.
    pub(super) fn interior_pointers(&self) -> HashMap<usize, Vec<u64>> {
        let mut pointers: HashMap<usize, Vec<u64>> = HashMap::new();
        for section in self.data_sections() {
            let skip = usize::try_from(section.address.next_multiple_of(8) - section.address)
                .unwrap_or_default();
            let (slots, _) = section
                .bytes
                .get(skip..)
                .unwrap_or_default()
                .as_chunks::<8>();
            for (index, slot) in slots.iter().enumerate() {
                let value = u64::from_le_bytes(*slot);
                if let Some(function) = self.function_at(value)
                    && self.functions[function].start != value
                {
                    pointers
                        .entry(function)
                        .or_default()
                        .push(section.address + (skip + index * 8) as u64);
                }
            }
        }
        pointers
    }

    /// Every data location, aligned or not, holding a function's start address, keyed by that
    /// start; a pointer to a function anywhere in data may be called through.
    pub(super) fn function_start_locations(&self) -> HashMap<u64, Vec<u64>> {
        let mut locations: HashMap<u64, Vec<u64>> = HashMap::new();
        let (Some(first), Some(last)) = (self.functions.first(), self.functions.last()) else {
            return locations;
        };
        let code = first.start..last.end;
        for section in self.data_sections() {
            for (offset, window) in section.bytes.windows(8).enumerate() {
                let value = u64::from_le_bytes(window.try_into().unwrap_or_default());
                if code.contains(&value) && self.by_start.contains_key(&value) {
                    locations
                        .entry(value)
                        .or_default()
                        .push(section.address + offset as u64);
                }
            }
        }
        locations
    }
}

/// The functions `path` registers to run before `main` or after it returns, by symbol name.
pub(super) fn constructors(path: &Path) -> Result<BTreeSet<String>> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let file = object::File::parse(&*data)
        .with_context(|| format!("parsing {} as ELF", path.display()))?;
    read_constructors(&file, path)
}

fn read_constructors(file: &object::File<'_>, path: &Path) -> Result<BTreeSet<String>> {
    let names: HashMap<u64, &str> = file
        .symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::Text)
        .filter_map(|symbol| Some((symbol.address(), symbol.name().ok()?)))
        .collect();
    let mut constructors = BTreeSet::new();
    for section in file.sections() {
        if !CONSTRUCTOR_SECTIONS.contains(&section.name().unwrap_or_default()) {
            continue;
        }
        for entry in section.data().unwrap_or_default().as_chunks::<8>().0 {
            let address = u64::from_le_bytes(*entry);
            // `.ctors` and `.dtors` delimit their lists with 0 and -1.
            if address == 0 || address == u64::MAX {
                continue;
            }
            let name = names.get(&address).with_context(|| {
                format!(
                    "{} registers an unnamed constructor at {address:#x}",
                    path.display()
                )
            })?;
            constructors.insert((*name).to_owned());
        }
    }
    Ok(constructors)
}
