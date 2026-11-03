#![forbid(unsafe_code)]
//! Bounded, read-only ELF inventory. Reports evidence; it never approves compatibility.

use goblin::elf::{Elf, header};
use serde::Serialize;
use std::{error::Error, fmt};

pub const MAX_ELF_BYTES: usize = 128 * 1024 * 1024;
const MAX_RECORDED_STRINGS: usize = 16_384;
const MAX_RECORDED_STRING_BYTES: usize = 1_048_576;
const MAX_STRING_BYTES: usize = 4096;
const MAX_DYNAMIC_SYMBOLS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    TooLarge,
    Malformed,
    MetadataLimit,
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ELF analysis failed: {self:?}")
    }
}
impl Error for ElfError {}

/// Structural facts from an ELF header and its dynamic metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElfReport {
    pub class_bits: u8,
    pub little_endian: bool,
    pub object_type: u16,
    /// ELF machine number as specified by the ELF ABI.
    pub machine: u16,
    pub interpreter: Option<String>,
    pub soname: Option<String>,
    pub needed: Vec<String>,
    pub rpath: Vec<String>,
    pub runpath: Vec<String>,
    pub required_symbol_versions: Vec<String>,
    /// Direct imports that suggest runtime loading not captured by `DT_NEEDED` alone.
    pub dynamic_loading_symbols: Vec<String>,
    /// Undefined dynamic imports; an empty list is required by the standalone DSO subset.
    pub undefined_symbols: Vec<String>,
    pub is_shared_object: bool,
    pub has_initializers: bool,
    pub executable_stack_required: bool,
    pub writable_executable_segment: bool,
    pub has_ifunc_symbols: bool,
    /// Null-terminated printable absolute path literals found in file-backed sections.
    pub absolute_path_literals: Vec<String>,
}

/// Return `None` for non-ELF bytes. A file bearing ELF magic but malformed is an error.
/// Input and copied metadata are bounded; no code from the input is executed.
pub fn inspect_elf(bytes: &[u8]) -> Result<Option<ElfReport>, ElfError> {
    if bytes.len() > MAX_ELF_BYTES {
        return Err(ElfError::TooLarge);
    }
    if !bytes.starts_with(b"\x7fELF") {
        return Ok(None);
    }
    let elf = std::panic::catch_unwind(|| Elf::parse(bytes))
        .map_err(|_| ElfError::Malformed)?
        .map_err(|_| ElfError::Malformed)?;
    if elf.dynsyms.len() > MAX_DYNAMIC_SYMBOLS {
        return Err(ElfError::MetadataLimit);
    }
    let mut budget = MetadataBudget::default();
    let class_bits = match elf.header.e_ident[header::EI_CLASS] {
        header::ELFCLASS32 => 32,
        header::ELFCLASS64 => 64,
        _ => return Err(ElfError::Malformed),
    };
    let interpreter = copy_optional(elf.interpreter, &mut budget)?;
    let soname = copy_optional(elf.soname, &mut budget)?;
    let needed = copy_list(&elf.libraries, &mut budget)?;
    let rpath = copy_list(&elf.rpaths, &mut budget)?;
    let runpath = copy_list(&elf.runpaths, &mut budget)?;
    let mut dynamic_loading_symbols = Vec::new();
    let mut undefined_symbols = Vec::new();
    let mut has_ifunc_symbols = false;
    for symbol in &elf.dynsyms {
        has_ifunc_symbols |= symbol.st_type() == goblin::elf::sym::STT_GNU_IFUNC;
        if symbol.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(symbol.st_name) else {
            continue;
        };
        if !name.is_empty() {
            push_string(&mut undefined_symbols, name, &mut budget)?;
        }
        if matches!(name, "dlopen" | "dlmopen" | "dlsym" | "dlvsym")
            && !dynamic_loading_symbols.iter().any(|v| v == name)
        {
            push_string(&mut dynamic_loading_symbols, name, &mut budget)?;
        }
    }
    let has_initializers = elf.section_headers.iter().any(|section| {
        matches!(
            section.sh_type,
            goblin::elf::section_header::SHT_INIT_ARRAY
                | goblin::elf::section_header::SHT_PREINIT_ARRAY
        )
    }) || elf.dynamic.as_ref().is_some_and(|dynamic| {
        dynamic.dyns.iter().any(|entry| {
            matches!(
                entry.d_tag,
                goblin::elf::dynamic::DT_INIT
                    | goblin::elf::dynamic::DT_INIT_ARRAY
                    | goblin::elf::dynamic::DT_PREINIT_ARRAY
            )
        })
    });
    let executable_stack_required = elf.program_headers.iter().any(|header| {
        header.p_type == goblin::elf::program_header::PT_GNU_STACK
            && header.p_flags & goblin::elf::program_header::PF_X != 0
    });
    let writable_executable_segment = elf.program_headers.iter().any(|header| {
        header.p_type == goblin::elf::program_header::PT_LOAD
            && header.p_flags & goblin::elf::program_header::PF_W != 0
            && header.p_flags & goblin::elf::program_header::PF_X != 0
    });
    let mut absolute_path_literals = Vec::new();
    let mut section_bytes = 0usize;
    for section in &elf.section_headers {
        if section.sh_type != goblin::elf::section_header::SHT_PROGBITS {
            continue;
        }
        let start = usize::try_from(section.sh_offset).map_err(|_| ElfError::Malformed)?;
        let size = usize::try_from(section.sh_size).map_err(|_| ElfError::Malformed)?;
        section_bytes = section_bytes
            .checked_add(size)
            .ok_or(ElfError::MetadataLimit)?;
        if section_bytes > MAX_ELF_BYTES {
            return Err(ElfError::MetadataLimit);
        }
        let end = start.checked_add(size).ok_or(ElfError::Malformed)?;
        let section = bytes.get(start..end).ok_or(ElfError::Malformed)?;
        for literal in section.split(|byte| *byte == 0) {
            if literal.first() != Some(&b'/') || literal.len() > MAX_STRING_BYTES {
                continue;
            }
            let Ok(path) = std::str::from_utf8(literal) else {
                continue;
            };
            if path.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
                push_string(&mut absolute_path_literals, path, &mut budget)?;
            }
        }
    }
    let mut required_symbol_versions = Vec::new();
    if let Some(verneed) = &elf.verneed {
        for need in verneed {
            for auxiliary in &need {
                let version = elf
                    .dynstrtab
                    .get_at(auxiliary.vna_name)
                    .ok_or(ElfError::Malformed)?;
                push_string(&mut required_symbol_versions, version, &mut budget)?;
            }
        }
    }
    Ok(Some(ElfReport {
        class_bits,
        little_endian: elf.little_endian,
        object_type: elf.header.e_type,
        machine: elf.header.e_machine,
        interpreter,
        soname,
        needed,
        rpath,
        runpath,
        required_symbol_versions,
        dynamic_loading_symbols,
        undefined_symbols,
        is_shared_object: elf.is_lib,
        has_initializers,
        executable_stack_required,
        writable_executable_segment,
        has_ifunc_symbols,
        absolute_path_literals,
    }))
}

#[derive(Default)]
struct MetadataBudget {
    strings: usize,
    bytes: usize,
}

fn copy_optional(
    value: Option<&str>,
    budget: &mut MetadataBudget,
) -> Result<Option<String>, ElfError> {
    value.map(|s| copy_string(s, budget)).transpose()
}

fn copy_list(values: &[&str], budget: &mut MetadataBudget) -> Result<Vec<String>, ElfError> {
    values.iter().map(|s| copy_string(s, budget)).collect()
}

fn push_string(
    values: &mut Vec<String>,
    value: &str,
    budget: &mut MetadataBudget,
) -> Result<(), ElfError> {
    values.push(copy_string(value, budget)?);
    Ok(())
}

fn copy_string(value: &str, budget: &mut MetadataBudget) -> Result<String, ElfError> {
    budget.strings = budget
        .strings
        .checked_add(1)
        .ok_or(ElfError::MetadataLimit)?;
    budget.bytes = budget
        .bytes
        .checked_add(value.len())
        .ok_or(ElfError::MetadataLimit)?;
    if value.len() > MAX_STRING_BYTES
        || budget.strings > MAX_RECORDED_STRINGS
        || budget.bytes > MAX_RECORDED_STRING_BYTES
    {
        return Err(ElfError::MetadataLimit);
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventories_dynamic_elf_evidence_from_fixed_fixture() {
        let bytes = include_bytes!("../tests/fixtures/ubuntu-true");
        let report = inspect_elf(bytes).unwrap().unwrap();
        assert_eq!(report.class_bits, 64);
        assert_eq!(report.machine, 62); // EM_X86_64
        assert_eq!(report.object_type, header::ET_DYN); // PIE executable
        assert_eq!(
            report.interpreter.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
        assert!(report.needed.iter().any(|name| name == "libc.so.6"));
        assert!(
            report
                .required_symbol_versions
                .iter()
                .any(|name| name.starts_with("GLIBC_"))
        );
        assert!(report.runpath.is_empty());
    }

    #[test]
    fn rejects_truncated_or_oversized_elf_and_ignores_non_elf() {
        assert_eq!(inspect_elf(b"data").unwrap(), None);
        assert_eq!(inspect_elf(b"\x7fELF\x02"), Err(ElfError::Malformed));
        let bytes = vec![0u8; MAX_ELF_BYTES + 1];
        assert_eq!(inspect_elf(&bytes), Err(ElfError::TooLarge));
    }

    #[test]
    fn flags_direct_runtime_loading_that_needed_entries_do_not_describe() {
        let bytes = include_bytes!("../tests/fixtures/dlopen-probe");
        let report = inspect_elf(bytes).unwrap().unwrap();
        assert_eq!(report.dynamic_loading_symbols, ["dlopen"]);
        assert!(report.needed.iter().any(|name| name == "libc.so.6"));
    }

    #[test]
    fn recognizes_only_dependency_free_shared_object_evidence() {
        let bytes = include_bytes!("../tests/fixtures/libdich-fixture.so");
        let report = inspect_elf(bytes).unwrap().unwrap();
        assert!(report.is_shared_object);
        assert_eq!(report.soname.as_deref(), Some("libdich-fixture.so"));
        assert!(report.needed.is_empty());
        assert!(report.undefined_symbols.is_empty());
        assert!(report.required_symbol_versions.is_empty());
    }

    #[test]
    fn detects_dynamic_initializers() {
        let bytes = include_bytes!("../tests/fixtures/constructor-library.so");
        let report = inspect_elf(bytes).unwrap().unwrap();
        assert!(report.has_initializers);
    }

    #[test]
    fn detects_absolute_path_literals_in_elf_sections() {
        let bytes = include_bytes!("../tests/fixtures/path-library.so");
        let report = inspect_elf(bytes).unwrap().unwrap();
        assert!(
            report
                .absolute_path_literals
                .iter()
                .any(|path| path == "/etc/dich-fixture.conf")
        );
    }
}
