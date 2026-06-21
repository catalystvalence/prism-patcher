mod format;
mod patcher;
mod scanner;

use clap::Parser;
use format::BinaryFormat;
use log::{debug, error, info, warn};
use std::io::Read;
use std::path::PathBuf;

struct PatchRule {
    name: &'static str,
    signature: &'static str,
    offset_from_match: i64,
    patch_kind: PatchKind,
}

enum PatchKind {
    Fixed(&'static [u8]),
    JnzToJmp,
}

// x86-64 PE rules

const RULES_X86_64: &[PatchRule] = &[
    PatchRule {
        name: "anyAccountIsValid unconditional return",
        signature: "48 8d 71 50 48 8b 06 48 85 c0 74 07 8b 00 83 f8 01 7e 0d",
        offset_from_match: -0x14,
        patch_kind: PatchKind::Fixed(&[0xB0, 0x01, 0xC3]),
    },
    PatchRule {
        name: "decideLaunchMode type check (Offline -> MSA path)",
        signature: "48 8B 0B 44 39 79 20 0F 84 ?? ?? ?? ??",
        offset_from_match: 7,
        patch_kind: PatchKind::Fixed(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90]),
    },
    PatchRule {
        name: "decideLaunchMode ownsMinecraft check (always pass)",
        signature: "38 91 38 02 00 00 75 ??",
        offset_from_match: 6,
        patch_kind: PatchKind::JnzToJmp,
    },
];

// ARM64 Mach-O rules

const RULES_ARM64: &[PatchRule] = &[
    PatchRule {
        name: "anyAccountIsValid unconditional return",
        signature: "f8 5f bc a9 ?? ?? ?? a9 ?? ?? ?? a9 ?? ?? ?? a9 ?? ?? ?? 91 f3 03 00 aa f4 03 00 aa",
        offset_from_match: 0,
        patch_kind: PatchKind::Fixed(&[0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6]),
    },
    PatchRule {
        name: "decideLaunchMode use m_accountToUse directly (bypass owner check)",
        signature: "e0 4b 40 f9 60 0b 00 b4 17 78 42 b9 ff 16 00 71",
        offset_from_match: 0,
        patch_kind: PatchKind::Fixed(&[0x60, 0x72, 0x40, 0xF9]),
    },
];

#[derive(Parser)]
#[command(
    name = "prism-patcher",
    version,
    about = "Unlock Prism Launcher for offline account use"
)]
struct Cli {
    #[arg(value_name = "TARGET")]
    target: Option<PathBuf>,
    #[arg(short = 'd', long)]
    dry_run: bool,
    #[arg(short = 'f', long)]
    force: bool,
    #[arg(short = 'v', long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp(None)
        .init();
    if let Err(e) = run(cli) {
        error!("{e}");
        std::process::exit(1);
    }
}

fn detect_format(path: &PathBuf) -> anyhow::Result<Box<dyn BinaryFormat>> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", path.display()))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;

    match &magic {
        // PE
        b"MZ\x90\x00" => Ok(Box::new(format::PeFormat::load(path)?)),
        // Mach-O thin (LE + BE) + fat
        [0xcf, 0xfa, 0xed, 0xfe]
        | [0xce, 0xfa, 0xed, 0xfe]
        | [0xfe, 0xed, 0xfa, 0xcf]
        | [0xfe, 0xed, 0xfa, 0xce]
        | [0xca, 0xfe, 0xba, 0xbe] => Ok(Box::new(format::MachoFormat::load(path)?)),
        _ => anyhow::bail!(
            "unknown binary format (magic: {:02X?}); expected PE or Mach-O",
            &magic
        ),
    }
}

fn find_installation() -> anyhow::Result<PathBuf> {
    let candidates: Vec<PathBuf> = if cfg!(target_os = "macos") {
        vec![
            PathBuf::from("/Applications/Prism Launcher.app/Contents/MacOS/prismlauncher"),
            dirs_fallback().join("Applications/Prism Launcher.app/Contents/MacOS/prismlauncher"),
            dirs_fallback().join(".local/share/PrismLauncher/prismlauncher"),
            std::env::current_dir()
                .unwrap_or_default()
                .join("prismlauncher"),
        ]
    } else {
        let exe_name = "prismlauncher.exe";
        vec![
            std::env::var("LOCALAPPDATA")
                .ok()
                .map(|p| {
                    PathBuf::from(p)
                        .join("Programs")
                        .join("PrismLauncher")
                        .join(exe_name)
                })
                .unwrap_or_default(),
            std::env::var("ProgramFiles")
                .ok()
                .map(|p| PathBuf::from(p).join("PrismLauncher").join(exe_name))
                .unwrap_or_default(),
            std::env::current_dir().unwrap_or_default().join(exe_name),
        ]
    };

    for candidate in &candidates {
        if candidate.as_os_str().is_empty() {
            continue;
        }
        debug!("Checking: {}", candidate.display());
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }
    let searched: Vec<String> = candidates.iter().map(|p| p.display().to_string()).collect();
    anyhow::bail!(
        "prismlauncher binary not found. Searched:\n  {}\n\n\
         Specify the path manually: prism-patcher <TARGET>",
        searched.join("\n  "),
    );
}

fn dirs_fallback() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn handle_codesign(target: &PathBuf) -> anyhow::Result<()> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }

    info!("Removing existing code signature...");
    let status = std::process::Command::new("codesign")
        .args(["--remove-signature"])
        .arg(target)
        .status();

    match status {
        Ok(s) if s.success() => debug!("Existing signature removed"),
        Ok(s) => warn!("codesign --remove-signature exited with {s}"),
        Err(e) => warn!("codesign --remove-signature failed: {e} (may not be signed)"),
    }

    info!("Applying ad-hoc code signature...");
    let status = std::process::Command::new("codesign")
        .args(["-s", "-"])
        .arg(target)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run codesign: {e}"))?;

    if status.success() {
        info!("Ad-hoc code signature applied");
        Ok(())
    } else {
        anyhow::bail!("codesign -s - failed with exit status {status}");
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let target = match cli.target {
        Some(ref t) => {
            if !t.exists() {
                anyhow::bail!("target file not found: {}", t.display());
            }
            t.clone()
        }
        None => {
            info!("No target specified, searching for Prism Launcher installation...");
            let found = find_installation()?;
            info!("Found: {}", found.display());
            found
        }
    };

    info!("Loading: {}", target.display());
    let fmt = detect_format(&target)?;
    let arch = fmt.arch_name();
    info!("Architecture: {arch}");

    let text = fmt.text_section();
    info!(
        "Scanning .text section at VA {:#x} ({} bytes)...",
        text.va,
        format_size(text.size),
    );

    let rules: &[PatchRule] = if arch.contains("ARM64") || arch.contains("AArch64") {
        RULES_ARM64
    } else if arch.contains("x86-64") || arch.contains("PE64") {
        RULES_X86_64
    } else {
        anyhow::bail!("unsupported architecture: {arch}");
    };

    let mut patched_count = 0;
    let mut backed_up = false;

    for (i, rule) in rules.iter().enumerate() {
        let label = format!("[{}/{}] {}", i + 1, rules.len(), rule.name);
        let sig = scanner::Signature::parse(rule.signature)?;
        let matches = sig.scan(&text.raw_data);

        if matches.is_empty() {
            if cli.dry_run {
                warn!("{label}: signature not found; skipping");
            } else {
                error!("{label}: signature not found; binary may be unsupported");
            }
            continue;
        }

        if matches.len() > 1 {
            warn!(
                "{label}: signature matched at {} locations (using first)",
                matches.len()
            );
        }

        let match_offset = matches[0];

        let patch_offset = if rule.offset_from_match >= 0 {
            match_offset
                .checked_add(rule.offset_from_match as usize)
                .ok_or_else(|| anyhow::anyhow!("{label}: patch offset overflow"))?
        } else {
            match_offset
                .checked_sub((-rule.offset_from_match) as usize)
                .ok_or_else(|| anyhow::anyhow!("{label}: patch offset would underflow"))?
        };

        let patch_va = text.va + patch_offset as u64;
        let patch_file_offset = text.va_to_file_offset(patch_va)?;

        let patch_bytes = match &rule.patch_kind {
            PatchKind::Fixed(bytes) => bytes.to_vec(),
            PatchKind::JnzToJmp => {
                let raw = patcher::read_bytes_at(&target, patch_file_offset, 2)?;
                if raw.len() != 2 || raw[0] != 0x75 {
                    anyhow::bail!(
                        "{label}: expected jnz (0x75) at patch site, found {}",
                        patcher::hex_str(&raw)
                    );
                }
                vec![0xEB, raw[1]]
            }
        };

        let original = patcher::read_bytes_at(&target, patch_file_offset, patch_bytes.len())?;

        let changed = original != patch_bytes;

        debug!(
            "{label}: VA {patch_va:#x} | {} | {}",
            patcher::hex_str(&original),
            if changed {
                patcher::hex_str(&patch_bytes)
            } else {
                "(already patched)".to_string()
            }
        );

        if !changed {
            if !cli.force {
                warn!("{label}: already patched; skipping");
            } else {
                debug!("{label}: re-patching");
            }
        }

        if cli.dry_run || (!changed && !cli.force) {
            let prefix = if changed {
                "would patch"
            } else {
                "already patched"
            };
            info!(
                "{label}: {prefix} at VA {patch_va:#x} ({})",
                if changed {
                    patcher::hex_diff(&original, &patch_bytes)
                } else {
                    "no change needed".to_string()
                }
            );
            if changed {
                patched_count += 1;
            }
            continue;
        }

        if !backed_up {
            info!("Creating backup...");
            let bak_path = patcher::backup_file(&target)?;
            info!(
                "Backup created: {}",
                bak_path.file_name().unwrap_or_default().to_string_lossy()
            );
            backed_up = true;
        }

        info!(
            "{label}: patching at offset {patch_file_offset:#x} ({})",
            patcher::hex_diff(&original, &patch_bytes),
        );

        patcher::write_bytes_at(&target, patch_file_offset, &patch_bytes)?;
        let site = patcher::PatchSite::new(
            patch_va as u32,
            patch_file_offset,
            original,
            patch_bytes.clone(),
        );
        patcher::verify_patch(&target, &site)?;
        info!("{label}: verified");
        patched_count += 1;
    }

    if cli.dry_run {
        if patched_count > 0 {
            info!("Dry run: {patched_count} patch(es) would be applied. No changes made.");
        } else {
            info!("Dry run: binary is already fully patched. No changes needed.");
        }
    } else if patched_count > 0 {
        info!(
            "All {patched_count} patch(es) applied. Prism Launcher is unlocked for offline account use."
        );
        handle_codesign(&target)?;
    } else {
        info!("Binary was already fully patched. No changes made.");
    }

    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}
