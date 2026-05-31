# WindowsAutoCleanup v1.1.0

## Summary

WindowsAutoCleanup v1.1.0 is a reliability and safety update for the Windows cleanup script and scheduled-task installer. This release keeps the original cleanup scope and behavior, while fixing parameter forwarding during elevation, locale-safe driver parsing, Recycle Bin empty-state handling, logging fallback paths, and development-friendly ACL hardening controls.

## What's Fixed

- Preserves explicit `-ResetWindowsUpdateBase:$false` through UAC self-elevation in both `Run.ps1` and `Install-WindowsAutoCleanupTask.ps1`.
- Adds `-SkipAclHardening` for manual runs and scheduled-task installation when the folder is a development or Git checkout.
- Replaces English-only `pnputil` parsing with structured `pnputil /enum-drivers /format csv` parsing, with a safe text fallback.
- Parses driver dates with slash, dash, and dot separators, including values such as `14.02.2022`.
- Excludes driver records with unparseable date/version data instead of treating them as oldest packages.
- Makes superseded-driver selection more conservative so a higher-version side branch is not removed only because its date is older.
- Treats an empty Recycle Bin as a skipped cleanup using state checks instead of localized exception-message text.
- Moves fallback logs out of temporary folders and into `ProgramData\WindowsAutoCleanup\Logs` or `Windows\Logs\WindowsAutoCleanup`.
- Filters non-interactive `Public` and `Default` profile folders from per-user cleanup target generation.
- Accepts extended-length `\?\C:\...` paths while rejecting drive-relative inputs such as `C:foo`.
- Adds additional Microsoft Edge cache directories: `Cache\js`, `Cache\wasm`, `DawnCache`, `DawnWebGPUCache`, and `ShaderCache\GPUCache`.
- Logs `pnputil` delete-driver refusal exit codes for easier diagnosis.
- Logs a one-time warning if pending-delete registration via `MoveFileEx` is unavailable.
- Makes PowerShell host discovery robust when multiple `pwsh.exe` entries exist.
- Logs the next scheduled run time after task registration.

## Requirements

- Windows 10, Windows 11, or a supported Windows Server version.
- Administrator privileges for cleanup and scheduled-task installation.
- PowerShell 5.1 or newer; PowerShell 7 is preferred.
- Built-in Windows tools: DISM, rundll32, and pnputil. cleanmgr is optional and skipped on Windows Server.

## Safety Notes

- Files are permanently deleted and are not moved to the Recycle Bin.
- Cleanup remains limited to drive `C:`.
- `DISM /ResetBase` remains enabled by default; installed Windows updates cannot be uninstalled after that cleanup.
- Use `-ResetWindowsUpdateBase:$false` to disable `DISM /ResetBase` for a manual run or scheduled-task install.
- Use `-SkipAclHardening` when running from a development clone where normal-user Git/edit access must remain available.
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

Run without project-folder ACL hardening:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Run.ps1 -SkipAclHardening
```

Install the daily scheduled task:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-WindowsAutoCleanupTask.ps1
```

Install the scheduled task without `DISM /ResetBase`:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-WindowsAutoCleanupTask.ps1 -ResetWindowsUpdateBase:$false
```

Install the scheduled task without ACL hardening:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-WindowsAutoCleanupTask.ps1 -SkipAclHardening
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
- `GITHUB_RELEASE_NOTES.md`

## Validation

This release was validated with both PowerShell 7 and Windows PowerShell 5.1:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Tests\Invoke-Validation.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Tests\Invoke-Validation.ps1
```

## License

MIT License

Copyright (c) 2026 Kiaro Sama
