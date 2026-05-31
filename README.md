# WindowsAutoCleanup

WindowsAutoCleanup is an administrator-only PowerShell cleanup utility for Windows systems. It removes only explicitly allow-listed temporary files and cache locations on drive `C:`, runs supported Windows cleanup tools, and can install itself as a hidden daily scheduled task.

The project is designed for unattended maintenance on Windows 10, Windows 11, and supported Windows Server versions. It prefers PowerShell 7 when available, falls back to Windows PowerShell 5.1 when needed, and records concise logs for every run.

## Features

- Cleans drive `C:` only.
- Uses explicit allow-list cleanup targets instead of broad recursive deletion.
- Permanently deletes temporary files and cache data from approved locations.
- Cleans Windows temp folders, user temp folders, thumbnail/icon cache databases, DirectX shader cache, internet cache folders, Microsoft Edge cache folders, Delivery Optimization cache, Windows Update download cache, downloaded program files, location cache, selected Defender cleanup/history paths, `C:\Windows.old`, and the Recycle Bin on drive `C:`.
- Runs `DISM /Online /Cleanup-Image /StartComponentCleanup /Quiet /ResetBase` by default for Windows component store cleanup.
- Runs the Windows Plug and Play cleanup handler (`pnpclean.dll`) and a conservative locale-safe `pnputil` duplicate/superseded driver package cleanup pass.
- Uses `cleanmgr.exe /sagerun` only on Windows client systems; Windows Server skips cleanmgr because legacy Disk Cleanup handlers can hang on Server builds.
- Keeps cleanmgr bounded by a five-minute watchdog on Windows client systems.
- Avoids clearing File Explorer history, Recent items, Quick Access state, pinned/frequent destinations, or recommended items.
- Avoids restarting File Explorer and does not reboot the computer.
- Skips locked, inaccessible, unsafe, or out-of-scope files.
- Avoids following symlink, junction, and other reparse-point roots.
- Logs every run to a local `Logs` folder, with fallback logs under `ProgramData\WindowsAutoCleanup\Logs` or `Windows\Logs\WindowsAutoCleanup` if the project folder is not writable.
- Includes installer and uninstaller scripts for a hidden scheduled task.
- On the first elevated cleanup run, hardens the project folder ACL so normal users cannot accidentally modify or delete the scripts. Pass `-SkipAclHardening` to opt out for development/Git checkouts.

## Supported Platforms

- Windows 10
- Windows 11
- Supported Windows Server versions

The scripts require PowerShell 5.1 or newer. PowerShell 7 is preferred and used automatically when available.

## Requirements

- Administrator privileges.
- Windows PowerShell 5.1 or PowerShell 7.
- `DISM.exe`, `rundll32.exe`, and `pnputil.exe`, which are included with supported Windows versions.
- `cleanmgr.exe` is optional. It is used only on Windows client systems and skipped on Windows Server.

## Safety Notes

This project modifies the local Windows installation and permanently deletes cleanup files. Review the code and run it first on a non-critical machine if you are unsure.

Important behavior:

- Deleted files are not moved to the Recycle Bin.
- Cleanup is limited to drive `C:`.
- Non-`C:` drives are rejected by target validation.
- `DISM /ResetBase` is enabled by default. After this cleanup, installed Windows updates cannot be uninstalled.
- To avoid `DISM /ResetBase`, run the cleanup or install the scheduled task with `-ResetWindowsUpdateBase:$false`.
- The first elevated cleanup run hardens the project folder ACL. `SYSTEM` and `BUILTIN\Administrators` receive Full Control; regular users receive Read & Execute only. A local `.WindowsAutoCleanupAclHardened` marker is written and ignored by Git. Use `-SkipAclHardening` when running from a development clone where normal-user Git/edit access must remain available.
- The script does not intentionally delete browser history, cookies, saved passwords, File Explorer history, Quick Access state, or pinned/frequent destinations.
- Windows Defender Tamper Protection can lock Defender scan history files. Locked files are skipped or scheduled for deletion on reboot only when Windows allows it.

## What It Cleans

### Direct Allow-List Targets

The script directly cleans only known temporary/cache locations, including:

- `C:\Windows\Temp`
- Current user `%TEMP%` when it resolves to drive `C:`
- `C:\Users\*\AppData\Local\Temp`
- `C:\Windows\SoftwareDistribution\Download`
- `C:\Windows\Prefetch`
- Windows Explorer shell cache files counted by Disk Cleanup (thumbnail and icon cache database files):
  - `thumbcache_*.db`
  - `iconcache_*.db`
- DirectX shader cache (`D3DSCache`) for user, system, and service profiles
- Delivery Optimization cache locations
- `C:\Windows\Downloaded Program Files`
- Location cache locations
- WinINET and legacy Internet cache locations
- Microsoft Edge Chromium cache locations under each local profile
- Microsoft Defender cleanup/history paths, best effort
- `C:\Windows.old`, when present
- Recycle Bin on drive `C:` only

### Windows Cleanup Tools

The script also uses supported Windows cleanup tools:

- `DISM /Online /Cleanup-Image /StartComponentCleanup /Quiet /ResetBase`
- `rundll32.exe pnpclean.dll,RunDLL_PnpClean /DRIVERS /MAXCLEAN`
- `pnputil /enum-drivers` plus conservative deletion of duplicate/superseded driver packages
- `cleanmgr.exe /sagerun:9999` on Windows client only

On Windows Server, cleanmgr is skipped by default because its legacy handlers can hang even when Windows Update Cleanup is excluded. DISM, pnpclean, pnputil, and direct allow-list cleanup still run.

## Repository Files

| Path | Purpose |
| --- | --- |
| `Run.ps1` | Main cleanup script. |
| `Install-WindowsAutoCleanupTask.ps1` | Installs or updates the daily scheduled task. |
| `Uninstall-WindowsAutoCleanupTask.ps1` | Removes the scheduled task. |
| `Tests/Invoke-Validation.ps1` | Static and function-level validation for the scripts and README. |
| `.github/workflows/powershell-validation.yml` | GitHub Actions workflow for validation on Windows runners. |
| `.gitignore` | Keeps logs, local notes, markers, caches, secrets, and generated output out of Git. |
| `LICENSE` | MIT License. |
| `GITHUB_RELEASE_NOTES.md` | Draft release notes for v1.0.0. |

Local `Logs/`, `.Comments/`, `.Commands/`, and `.WindowsAutoCleanupAclHardened` files are not intended for public release.

## Installation

Clone the repository after it is published, or download and extract a release archive:

```powershell
git clone https://github.com/KiaroSama/WindowsAutoCleanup.git
cd WindowsAutoCleanup
```

If Windows marks downloaded scripts as blocked, unblock them before running:

```powershell
Get-ChildItem -LiteralPath . -Filter *.ps1 | Unblock-File
```

## Usage

### Run Cleanup Manually

Run from an elevated PowerShell 7 terminal:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Run.ps1
```

If the script is started without administrator privileges, it attempts to relaunch elevated. Manual elevated relaunch prefers Windows Terminal with PowerShell 7 when both are installed.

### Run Without DISM ResetBase

Use this when you want Windows updates to remain uninstallable:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Run.ps1 -ResetWindowsUpdateBase:$false
```

### Install the Scheduled Task

The installer registers a task named `WindowsAutoCleanup` under the root task path (`\`). The task runs as `SYSTEM`, uses highest privileges, is hidden, uses PowerShell 7 when available, and runs daily at 20:00 by default.

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-WindowsAutoCleanupTask.ps1
```

Set a different daily run time:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-WindowsAutoCleanupTask.ps1 -DailyRunTime 03:00
```

Install the scheduled task without `DISM /ResetBase`:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-WindowsAutoCleanupTask.ps1 -ResetWindowsUpdateBase:$false
```

For automation, add `-NoPause` to installer or uninstaller commands.

### Remove the Scheduled Task

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-WindowsAutoCleanupTask.ps1
```

### Validate the Project

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Tests\Invoke-Validation.ps1
```

## Scheduled Task Details

The scheduled task installer configures:

- Task name: `WindowsAutoCleanup`
- Task path: `\`
- Principal: `SYSTEM`
- Logon type: `ServiceAccount`
- Run level: `Highest`
- Hidden task: enabled
- Compatibility: `Win8`
- Default schedule: daily at `20:00`
- Multiple instances: `IgnoreNew`
- Restart on failure: 3 attempts, 10-minute interval
- Execution time limit: 4 hours
- Action host: PowerShell 7 (`pwsh.exe`) when installed, otherwise Windows PowerShell 5.1

## Logs and Output

Each script writes timestamped logs to a local `Logs` folder next to the scripts:

- `WindowsAutoCleanup_yyyyMMdd_HHmmss.log`
- `Install-WindowsAutoCleanupTask_yyyyMMdd_HHmmss.log`
- `Uninstall-WindowsAutoCleanupTask_yyyyMMdd_HHmmss.log`

Logs can contain local usernames, local paths, host details, and cleanup results. The `Logs/` folder is ignored by Git and should not be published. If the project `Logs/` folder cannot be created, the scripts fall back to `C:\ProgramData\WindowsAutoCleanup\Logs` and then `C:\Windows\Logs\WindowsAutoCleanup`.

The cleanup log includes per-category counts for removed files, removed directories, removed reparse points, skipped items, failed items, and best-effort free-space delta for drive `C:`. The free-space delta can be negative if Windows writes new data during the run.

## Troubleshooting

### PowerShell execution policy blocks the script

Run with `-ExecutionPolicy Bypass` for the current process, as shown in the usage examples.

### Administrator privileges are required

Cleanup and scheduled task installation require elevation. Start PowerShell as Administrator or allow the UAC prompt when the script relaunches itself.

### Windows Update Cleanup still shows a size in Disk Cleanup

Windows Update Cleanup is part of the Windows component store, not a normal folder. The script uses DISM with `/ResetBase` by default. Windows may still report component metadata or pending reboot state until Windows allows it to be finalized.

### cleanmgr.exe hangs or is unavailable

On Windows Server, cleanmgr is skipped by default. On Windows client, cleanmgr has a five-minute watchdog. If it does not exit in time, the process is killed, the legacy Disk Cleanup step is logged as skipped, and the rest of the cleanup continues.

### Defender cleanup still shows a size

Tamper Protection or the Defender service can lock Defender files even for elevated callers and `SYSTEM`. The script records skipped files and continues. Disable Tamper Protection only if you understand the security tradeoff.

### Some items are skipped

Skipped items are normal when paths do not exist, belong to another profile, are locked by Windows, are unsafe targets, or are reparse-point roots. The script avoids forcing deletion in those cases.

### The folder became read-only for normal users

This is expected after the first elevated cleanup run. The ACL hardening step is meant to protect the scripts from accidental modification or deletion by normal users. Use `-SkipAclHardening` before the first run if this folder is a development/Git checkout, or reset the ACL manually from an elevated terminal if you need to restore write access.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

Copyright (c) 2026 Kiaro Sama

## Attribution

Author: Kiaro Sama  
GitHub: https://github.com/KiaroSama

## Donate

If this project helps you, donations are appreciated.

| Currency | Network | Address |
| --- | --- | --- |
| Bitcoin (BTC) | Bitcoin | `bc1qmth5m03pu5hujw5xw5jmywam3jj3sqwqupesdt` |
| USDT, BNB, USDC, etc. | BEP20 | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
| USDT, TRX, USDC, etc. | TRC20 | `TWBA3xFTqgZAeAYMxqo85xWnzvty3DcAhw` |
| Ethereum (ETH) | ERC20 | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
| TON | TON | `UQCN8Umo_OfOWqImZetQsrNStPcmLkMAKajFyiCOhso23NDb` |
| Litecoin (LTC) | LTC | `ltc1qntqnnrunadurnw4cshv3qgspywrueyyeyngwuy` |
| Solana (SOL) | Solana | `7B2wkczUjmkDhETwQuknBL8sUsbuV7nErxc317TmQuwR` |
| Polygon (POL) | Polygon | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |

