# Prism Patcher

Unlocks Prism Launcher for offline account use by patching three authentication
gates in the binary.

## How It Works

Prism Launcher blocks offline play with three checks in its C++/Qt6 codebase:

1. **Offline account creation blocked** unless a Microsoft account already exists
   (`anyAccountIsValid()`)
2. **Offline accounts ignored** during launch; the launcher searches for an MSA
   account instead (`decideLaunchMode` type branch)
3. **Demo mode forced** when no MSA account owns Minecraft (`askPlayDemo` dialog)

The patcher finds each check in the compiled binary using byte signatures (with
wildcards for relative offsets) and replaces them with equivalent "always pass"
instructions.

## Supported Platforms

| Platform | Format | Architecture | Patches |
|---|---|---|---|
| Windows | PE64 | x86-64 (Intel/AMD) | 3 |
| Linux | ELF | x86-64 (Intel/AMD) | 3 |
| macOS | Mach-O (fat) | ARM64 (Apple Silicon) | 2 |

The struct layout of `MinecraftAccount` is identical across all platforms. On
macOS ARM64 the compiler inlines `decideLaunchMode` into `executeTask` and emits
separate `ownsMinecraft` checks per code path, requiring a convergence-point
redirect instead of individual branch patches.

## Usage

```
prism-patcher [OPTIONS] [TARGET]

Arguments:
  [TARGET]  Path to prismlauncher binary (auto-detected if omitted)

Options:
  -d, --dry-run  Scan and report, do not modify
  -f, --force    Re-patch even if already patched
  -v, --verbose  Show debug output
  -h, --help     Print help
```

### Examples

```
# Dry run (safe, no changes):
prism-patcher --dry-run

# Apply patches:
prism-patcher

# Specify a custom binary:
prism-patcher --dry-run /Applications/Prism\ Launcher.app/Contents/MacOS/prismlauncher
```

## Auto-Detection

If no target is specified, the patcher searches:

**Windows:**
1. `%LOCALAPPDATA%\Programs\PrismLauncher\prismlauncher.exe`
2. `%ProgramFiles%\PrismLauncher\prismlauncher.exe`
3. `.\prismlauncher.exe`

**macOS:**
1. `/Applications/Prism Launcher.app/Contents/MacOS/prismlauncher`
2. `~/Applications/Prism Launcher.app/Contents/MacOS/prismlauncher`
3. `~/.local/share/PrismLauncher/prismlauncher`
4. `./prismlauncher`

**Linux:**
1. `/var/lib/flatpak/app/org.prismlauncher.PrismLauncher/current/active/files/bin/prismrun` (Flatpak)
2. `~/.local/share/flatpak/app/org.prismlauncher.PrismLauncher/current/active/files/bin/prismrun` (user Flatpak)
3. `/usr/bin/prismlauncher`
4. `/usr/local/bin/prismlauncher`
5. `/app/bin/prismrun`
6. `./prismrun`

## macOS Code Signing

After patching, the existing code signature is invalid. The patcher automatically
removes it and applies an ad-hoc signature:

```
codesign --remove-signature <binary>
codesign -s - <binary>
```

## Build

```
cargo build --release
```

## Patching Details

### x86-64 Windows (3 patches)

| Patch | Target | Change |
|---|---|---|
| 1 | `anyAccountIsValid()` entry | `mov al,1; ret` |
| 2 | Type check branch in `decideLaunchMode` | NOP the `jz` (6 bytes) |
| 3 | OwnsMinecraft check in `decideLaunchMode` | `jnz` to `jmp` (always pass) |

### Linux ELF x86-64 (3 patches)

| Patch | Target | Change |
|---|---|---|
| 1 | `anyAccountIsValid()` entry | `mov al,1; ret` |
| 2 | Type check branch in `decideLaunchMode` | NOP the `jz` (6 bytes) |
| 3 | OwnsMinecraft check in `decideLaunchMode` | NOP the `jz` (6 bytes) |

The Linux binary uses the same strategy as Windows: two 6-byte conditional jump
NOPs in `decideLaunchMode` to bypass both the type check (which redirects offline
accounts to MSA-only refresh logic) and the `ownsMinecraft` check (which rejects
accounts that don't own the game).

### ARM64 macOS (2 patches)

| Patch | Target | Change |
|---|---|---|
| 1 | `anyAccountIsValid()` entry | `mov w0,#1; ret` (8 bytes) |
| 2 | Convergence point in `executeTask` | Load `m_accountToUse` directly instead of `accountToCheck` from the stack, bypassing the entire account selection cascade |

Patch 2 replaces `ldr x0,[sp,#var_1C0]` with `ldr x0,[x19,#0xE0]`. Since
`m_accountToUse` is always non-null, the null check that triggers Demo mode
never branches. Account state flows to the default switch case which sets
launch mode to Offline, never reaching the `askPlayDemo` dialog.
