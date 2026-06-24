use pelite::pe64::Pe;
use std::path::Path;

/// Information about the code (.text / __text) section
#[derive(Clone)]
pub struct SectionInfo {
    pub va: u64,
    pub file_offset: u64,
    pub size: u64,
    pub raw_data: Vec<u8>,
}

impl SectionInfo {
    pub fn va_to_file_offset(&self, va: u64) -> anyhow::Result<u64> {
        if va < self.va {
            anyhow::bail!(
                "VA {va:#x} is before text section (start VA {:#x})",
                self.va
            );
        }
        let offset = va - self.va;
        if offset >= self.size {
            anyhow::bail!("VA {va:#x} is outside text section bounds");
        }
        Ok(self.file_offset + offset)
    }
}

pub trait BinaryFormat {
    fn load(path: &Path) -> anyhow::Result<Self>
    where
        Self: Sized;
    fn arch_name(&self) -> &'static str;
    fn text_section(&self) -> &SectionInfo;
}

// ── PE64 (x86-64) via pelite ──────────────────────────────────────

pub struct PeFormat {
    #[allow(dead_code)]
    map: pelite::FileMap,
    text: SectionInfo,
}

impl BinaryFormat for PeFormat {
    fn load(path: &Path) -> anyhow::Result<Self> {
        let map = pelite::FileMap::open(path)
            .map_err(|e| anyhow::anyhow!("failed to open PE file: {e}"))?;

        let view = pelite::pe64::PeView::from_bytes(&map)
            .map_err(|e| anyhow::anyhow!("not a valid PE file: {e}"))?;

        let sections = view.section_headers();
        let text = sections
            .iter()
            .find(|sh| sh.Name.starts_with(b".text"))
            .ok_or_else(|| anyhow::anyhow!(".text section not found"))?;

        let va = text.VirtualAddress as u64;
        let file_offset = text.PointerToRawData as u64;
        let size = text.VirtualSize as u64;

        let file_start = text.PointerToRawData as usize;
        let file_size = text.SizeOfRawData as usize;
        let file_end = file_start + file_size;

        let text_bytes = {
            let raw_data = map.as_ref();
            if file_end > raw_data.len() {
                anyhow::bail!(
                    ".text section file bounds ({file_end}) exceed file size ({})",
                    raw_data.len()
                );
            }
            raw_data[file_start..file_end].to_vec()
        };

        Ok(Self {
            map,
            text: SectionInfo {
                va,
                file_offset,
                size,
                raw_data: text_bytes,
            },
        })
    }

    fn arch_name(&self) -> &'static str {
        "PE64 (x86-64)"
    }

    fn text_section(&self) -> &SectionInfo {
        &self.text
    }
}

// ── ELF (x86-64) via goblin ────────────────────────────────────────

pub struct ElfFormat {
    #[allow(dead_code)]
    file_data: Vec<u8>,
    text: SectionInfo,
}

impl BinaryFormat for ElfFormat {
    fn load(path: &Path) -> anyhow::Result<Self> {
        let file_data =
            std::fs::read(path).map_err(|e| anyhow::anyhow!("failed to read file: {e}"))?;

        let elf = goblin::elf::Elf::parse(&file_data)
            .map_err(|e| anyhow::anyhow!("not a valid ELF file: {e}"))?;

        let text_shdr = elf
            .section_headers
            .iter()
            .find(|sh| {
                elf.shdr_strtab
                    .get_at(sh.sh_name)
                    .map(|name| name == ".text")
                    .unwrap_or(false)
            })
            .ok_or_else(|| anyhow::anyhow!(".text section not found in ELF"))?;

        let va = text_shdr.sh_addr;
        let file_offset = text_shdr.sh_offset;
        let size = text_shdr.sh_size;

        let file_start = text_shdr.sh_offset as usize;
        let file_size = text_shdr.sh_size as usize;
        let file_end = file_start + file_size;

        if file_end > file_data.len() {
            anyhow::bail!(
                ".text section bounds ({file_end}) exceed file size ({})",
                file_data.len()
            );
        }

        let raw_data = file_data[file_start..file_end].to_vec();

        Ok(Self {
            file_data,
            text: SectionInfo {
                va,
                file_offset,
                size,
                raw_data,
            },
        })
    }

    fn arch_name(&self) -> &'static str {
        "ELF x86-64"
    }

    fn text_section(&self) -> &SectionInfo {
        &self.text
    }
}

// ── Mach-O (fat + thin, ARM64 / x86-64) via goblin ────────────────

pub struct MachoFormat {
    #[allow(dead_code)]
    file_data: Vec<u8>,
    text: SectionInfo,
    arch: &'static str,
}

impl BinaryFormat for MachoFormat {
    fn load(path: &Path) -> anyhow::Result<Self> {
        let file_data =
            std::fs::read(path).map_err(|e| anyhow::anyhow!("failed to read file: {e}"))?;

        let mach = goblin::mach::Mach::parse(&file_data)
            .map_err(|e| anyhow::anyhow!("not a valid Mach-O file: {e}"))?;

        match mach {
            goblin::mach::Mach::Binary(macho) => Self::from_thin(&file_data, &macho, 0),
            goblin::mach::Mach::Fat(multi_arch) => {
                let arches = multi_arch
                    .arches()
                    .map_err(|e| anyhow::anyhow!("fat arch parse error: {e}"))?;

                // Prefer ARM64, fall back to x86-64, then first arch
                let target = arches
                    .iter()
                    .find(|a| a.cputype == goblin::mach::cputype::CPU_TYPE_ARM64)
                    .or_else(|| {
                        arches
                            .iter()
                            .find(|a| a.cputype == goblin::mach::cputype::CPU_TYPE_X86_64)
                    })
                    .or_else(|| arches.first())
                    .ok_or_else(|| anyhow::anyhow!("no architectures found in fat binary"))?;

                let start = target.offset as usize;
                let end = start + target.size as usize;
                if end > file_data.len() {
                    anyhow::bail!("slice for arch {:x} exceeds file bounds", target.cputype);
                }

                let thin = goblin::mach::MachO::parse(&file_data[start..end], 0)
                    .map_err(|e| anyhow::anyhow!("invalid Mach-O slice: {e}"))?;

                Self::from_thin(&file_data, &thin, target.offset as u64)
            }
        }
    }

    fn arch_name(&self) -> &'static str {
        self.arch
    }

    fn text_section(&self) -> &SectionInfo {
        &self.text
    }
}

impl MachoFormat {
    fn from_thin(
        file_data: &[u8],
        macho: &goblin::mach::MachO<'_>,
        slice_offset: u64,
    ) -> anyhow::Result<Self> {
        for segment in &macho.segments {
            let seg_name = segment
                .name()
                .map_err(|e| anyhow::anyhow!("segment name error: {e}"))?;
            if seg_name != "__TEXT" {
                continue;
            }

            let sections = segment
                .sections()
                .map_err(|e| anyhow::anyhow!("section parse error: {e}"))?;

            for section in sections.iter() {
                let sec_name = section
                    .0
                    .name()
                    .map_err(|e| anyhow::anyhow!("section name error: {e}"))?;
                if sec_name != "__text" {
                    continue;
                }

                let va = section.0.addr;
                let sec_offset = section.0.offset as u64;
                let size = section.0.size;

                // Section data lives within the thin slice, not the fat file
                let data_start = sec_offset as usize;
                let data_end = data_start + size as usize;

                let raw_data = if slice_offset == 0 {
                    file_data[data_start..data_end].to_vec()
                } else {
                    let abs_start = slice_offset as usize + data_start;
                    let abs_end = abs_start + size as usize;
                    file_data[abs_start..abs_end].to_vec()
                };

                let file_offset = slice_offset + sec_offset;

                let arch = match macho.header.cputype {
                    goblin::mach::cputype::CPU_TYPE_ARM64 => "Mach-O ARM64 (AArch64)",
                    goblin::mach::cputype::CPU_TYPE_X86_64 => "Mach-O x86-64",
                    _ => "Mach-O",
                };

                return Ok(Self {
                    file_data: file_data.to_vec(),
                    text: SectionInfo {
                        va,
                        file_offset,
                        size,
                        raw_data,
                    },
                    arch,
                });
            }
        }
        anyhow::bail!("__text section not found in Mach-O");
    }
}
