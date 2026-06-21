use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PatchSite {
    #[allow(dead_code)]
    pub rva: u32,
    pub file_offset: u64,
    #[allow(dead_code)]
    pub original_bytes: Vec<u8>,
    pub patch_bytes: Vec<u8>,
}

impl PatchSite {
    pub fn new(rva: u32, file_offset: u64, original: Vec<u8>, patch: Vec<u8>) -> Self {
        Self {
            rva,
            file_offset,
            original_bytes: original,
            patch_bytes: patch,
        }
    }
}

pub fn backup_file(target: &Path) -> anyhow::Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let stem = target.file_stem().unwrap_or_default().to_string_lossy();
    let ext = target
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();

    let bak_name = format!("{stem}.{timestamp}.bak{ext}");
    let bak_path = target.with_file_name(&bak_name);

    // If timestamped backup already exists, try numbered suffixes
    let final_path = if bak_path.exists() {
        let mut counter = 1u32;
        loop {
            let name = format!("{stem}.{timestamp}.bak.{counter}{ext}");
            let candidate = target.with_file_name(&name);
            if !candidate.exists() {
                break candidate;
            }
            counter += 1;
            if counter > 999 {
                anyhow::bail!("too many backup files (overflow)");
            }
        }
    } else {
        bak_path
    };

    fs::copy(target, &final_path)?;
    Ok(final_path)
}

pub fn read_bytes_at(path: &Path, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
    let mut file = fs::OpenOptions::new().read(true).open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_bytes_at(path: &Path, offset: u64, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

pub fn verify_patch(path: &Path, site: &PatchSite) -> anyhow::Result<()> {
    let current = read_bytes_at(path, site.file_offset, site.patch_bytes.len())?;
    if current == site.patch_bytes {
        Ok(())
    } else {
        let expected = hex_str(&site.patch_bytes);
        let got = hex_str(&current);
        anyhow::bail!(
            "patch verification failed at offset {:#x}\n  expected: {expected}\n  got:      {got}",
            site.file_offset
        );
    }
}

#[allow(dead_code)]
pub fn check_already_patched(
    path: &Path,
    offset: u64,
    expected_bytes: &[u8],
) -> anyhow::Result<bool> {
    let current = read_bytes_at(path, offset, expected_bytes.len())?;
    Ok(current == expected_bytes)
}

pub fn hex_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn hex_diff(old: &[u8], new: &[u8]) -> String {
    let old_str = hex_str(old);
    let new_str = hex_str(new);
    format!("{old_str} -> {new_str}")
}
