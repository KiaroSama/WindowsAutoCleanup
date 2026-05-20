# WindowsAutoCleanup v1.0.0

## Summary

WindowsAutoCleanup v1.0.0 is the first public release of an administrator-only PowerShell cleanup utility for Windows client and Windows Server systems. It cleans only explicit drive `C:` allow-list locations, runs supported Windows cleanup tools, and can install a hidden daily scheduled task.

## Features

- PowerShell cleanup script for Windows 10, Windows 11, and supported Windows Server versions.
- Drive `C:` cleanup only.
- Direct allow-list cleanup for Windows temp, user temp, Windows Update download cache, Prefetch, thumbnail/icon cache databases, DirectX shader cache, Internet cache, Microsoft Edge cache, Delivery Optimization cache, downloaded program files, location cache, selected Defender cleanup/history paths, `C:\Windows.old`, and Recycle Bin on drive `C:`.
- DISM component store cleanup with `/ResetBase` enabled by default.
- Windows driver cleanup through `pnpclean.dll` and conservative `pnputil` handling.
- Windows client cleanmgr support with a five-minute watchdog.
- Windows Server skips cleanmgr because legacy Disk Cleanup handlers can hang on Server builds.
- Scheduled task installer runs as `SYSTEM`, hidden, with highest privileges, using PowerShell 7 when available.
- First elevated cleanup run hardens the project folder ACL to reduce accidental deletion or modification by normal users.
- Validation script and GitHub Actions workflow included.

## Requirements

- Windows 10, Windows 11, or a supported Windows Server version.
- Administrator privileges.
- PowerShell 5.1 or newer; PowerShell 7 is preferred.
- Built-in Windows tools: DISM, rundll32, pnputil. cleanmgr is optional and skipped on Windows Server.

## Safety Notes

- Files are permanently deleted and are not moved to the Recycle Bin.
- Cleanup is limited to drive `C:`.
- `DISM /ResetBase` is enabled by default; installed Windows updates cannot be uninstalled after that cleanup.
- File Explorer history, Quick Access state, Recent items, browser history, cookies, and saved passwords are not intentionally cleared.
- Logs can contain local usernames and paths. Do not publish local `Logs/` output.

## Quick Start

Run cleanup manually from elevated PowerShell:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Run.ps1
```

Run without `DISM /ResetBase`:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Run.ps1 -ResetWindowsUpdateBase:$false
```

Install the daily scheduled task:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-WindowsAutoCleanupTask.ps1
```

Install the scheduled task for a custom time:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-WindowsAutoCleanupTask.ps1 -DailyRunTime 03:00
```

Remove the scheduled task:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-WindowsAutoCleanupTask.ps1
```

Run validation:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Tests\Invoke-Validation.ps1
```

## Included Files

- `Run.ps1`
- `Install-WindowsAutoCleanupTask.ps1`
- `Uninstall-WindowsAutoCleanupTask.ps1`
- `Tests/Invoke-Validation.ps1`
- `.github/workflows/powershell-validation.yml`
- `.gitignore`
- `README.md`
- `LICENSE`

## License

MIT License

Copyright (c) 2026 Kiaro Sama
