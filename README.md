# WindowsAutoCleanup

WindowsAutoCleanup is an administrator-only PowerShell cleanup utility for Windows. It removes only explicitly allow-listed temporary files and cache locations on drive `C:`, runs supported Windows cleanup tools, and can install itself as a hidden daily scheduled task.

The project targets unattended maintenance on Windows 10, Windows 11, and supported Windows Server versions. It runs on Windows PowerShell 5.1 and PowerShell 7, and writes a structured UTC log for every run.

## Safety guarantees

These are the invariants the code and its regression tests are written against:

- Default cleanup affects drive `C:` only.
- `-ResetWindowsUpdateBase:$false` never results in a DISM `/ResetBase`, including across a UAC relaunch.
- Nothing PATH-resolved or user-writable is ever registered to run as `SYSTEM`. The scheduled task references a machine-wide deployment and a canonical PowerShell host, both verified before registration.
- Cleanup never follows a junction, symbolic link, mount point, or a reparse point swapped in mid-traversal. Every deletion re-proves by handle that the path still resolves to itself, immediately before the delete — not once per directory, which would leave a window as long as that directory takes to sweep. A reparse point found inside a target is deleted as a link without touching what it points at, and a locked file is only queued for deletion at the next boot once it has passed the same check.
- The project folder, the deployment folder, the active log, browser history, cookies, saved passwords, Recent items, Quick Access state, and unrelated scheduled tasks survive every run.
- Every external process and every traversal has a deadline, and the total internal budget stays below the scheduled task's execution time limit.
- An unverifiable safety condition fails closed. A failed security check is never reported as success.

## What changed in v1.2.0

If you used an earlier version, read this section before upgrading.

- **The project-folder ACL hardening capability was removed.** Earlier versions rewrote the owner and DACL of the whole script folder on the first elevated run, which made a normal checkout hard to edit or delete. Nothing in this project changes an ACL any more; the installer only *verifies* that its own deployment directory is not user-writable. See [Restoring a folder hardened by an older version](#restoring-a-folder-hardened-by-an-older-version).
- **The scheduled task no longer runs your source checkout.** The installer copies the runtime into `%ProgramFiles%\WindowsAutoCleanup` and registers that copy.
- **Logs moved to `%ProgramData%\WindowsAutoCleanup\Logs`.** Logs must not live inside a directory the tool cleans, and a `SYSTEM` task must not depend on the checkout being writable.
- **`cleanmgr /sagerun` is no longer part of the default run.** Microsoft documents that `/sagerun` enumerates every drive and that `/d` is not honoured with it, so it cannot be part of a `C:`-only default. It is still available behind `-EnableLegacyDiskCleanup`.
- **Superseded driver-package pruning is now opt-in** (`-PruneSupersededDrivers`) and exports a recoverable backup before deleting anything.
- **The Recycle Bin is now actually emptied under `SYSTEM`.** `Clear-RecycleBin` only clears the calling identity's bin, so a scheduled run used to clear essentially nothing while reporting success.
- `-SkipAclHardening` is accepted but ignored, so a task registered by an older installer keeps working.

## Requirements

- Administrator privileges.
- Windows PowerShell 5.1 or PowerShell 7.
- `dism.exe` and `rundll32.exe`, which ship with supported Windows versions.
- `pnputil.exe` only when `-PruneSupersededDrivers` is used.
- `cleanmgr.exe` only when `-EnableLegacyDiskCleanup` is used. It is absent by default on Windows Server before 2016 without Desktop Experience.

## Installation

```powershell
git clone https://github.com/KiaroSama/WindowsAutoCleanup.git
cd WindowsAutoCleanup
```

If Windows marks downloaded scripts as blocked, unblock them first:

```bash
Get-ChildItem -LiteralPath . -Recurse -Filter *.ps1 | Unblock-File
```

## Usage

### Run cleanup manually

```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Run.ps1
```

Started without administrator privileges, the script relaunches itself elevated through a canonical PowerShell host, waits for the child, and returns the child's real exit code.

### Keep Windows updates uninstallable

```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Run.ps1 -ResetWindowsUpdateBase:$false
```

### Install the scheduled task

```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-WindowsAutoCleanupTask.ps1
```

The installer deploys the runtime to `%ProgramFiles%\WindowsAutoCleanup`, verifies that no non-administrative principal can write to it, and only then registers the task. Pass `-DailyRunTime 03:00` to change the schedule and `-NoPause` for automation.

### Remove the scheduled task

```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-WindowsAutoCleanupTask.ps1
```

The uninstaller refuses to remove a task that does not carry this project's ownership marker, and verifies the removal afterwards. Pass `-RemoveLogs` to delete the log directory as well.

### Run the tests

```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Tests\Run-Tests.ps1
```

## Parameters

| Parameter | Default | Effect |
| --- | --- | --- |
| `-Scheduled` | off | Set by the scheduled task. A scheduled run fails fast instead of attempting a UAC relaunch. |
| `-ResetWindowsUpdateBase` | `$true` | Adds `/ResetBase` to DISM component cleanup. Updates installed before the run can no longer be uninstalled. |
| `-PruneSupersededDrivers` | off | Opt in to removing superseded OEM driver packages. Exports a backup first. |
| `-EnableLegacyDiskCleanup` | off | Opt in to `cleanmgr /sagerun`. **Affects every drive, not just `C:`.** |
| `-SkipRecycleBin` | off | Leave the Recycle Bin alone. |
| `-SkipCategory` | none | Allow-list categories to skip, comma-separated. |
| `-LogLevel` | `INFO` | `DEBUG` adds one line per cleanup target. |
| `-BudgetMinutes` | `210` | Total internal run budget. Must stay below the task's 4-hour execution limit. |
| `-MutexName` | `Global\WindowsAutoCleanup` | Single-instance lock name. Only tests should change this. |
| `-SkipAclHardening` | ignored | Deprecated no-op kept for compatibility with older installed tasks. |

Parameters bind **by name only**. `-ResetWindowsUpdateBase $false` — with a space instead of a colon — is a binding error rather than a silent success, because under positional binding it used to set the switch to `$true` and push the leftover token into `-SkipCategory`. Use the colon form:

```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Run.ps1 -ResetWindowsUpdateBase:$false
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Error, missing privileges, or an unhandled failure. |
| `2` | Completed, but at least one cleanup item failed. |
| `3` | Another run already holds the machine-wide lock. |
| `4` | Elevation was cancelled or failed. |
| `5` | Unsupported environment: the online system drive is not `C:`. |

## Concurrency

A machine-wide named mutex (`Global\WindowsAutoCleanup`) is taken before anything is mutated. Task Scheduler's `MultipleInstances IgnoreNew` is documented only in terms of task instances and says nothing about a manual run overlapping a scheduled one, so the mutex is the real guard. A run that cannot take the lock exits with code `3` without touching anything.

Log files are created with create-new semantics and a collision suffix, so two runs starting in the same second can never share or truncate one file.

## What it cleans

### Allow-list targets

Only these locations are deleted directly:

- `C:\Windows\Temp`
- `%TEMP%` for each real user profile, discovered through `Win32_UserProfile` / the `ProfileList` registry key rather than by listing `C:\Users`
- Windows Explorer shell cache databases (`thumbcache_*.db`, `iconcache_*.db`) — matched files only, the surrounding folder is left alone
- `INetCache`, `Temporary Internet Files`, `IECompatCache`, `IECompatUaCache`
- DirectX shader cache (`D3DSCache`) for user, system and service profiles
- Location and `LocationProvider` caches
- Microsoft Edge Chromium caches under each `Default` / `Profile N` profile
- Microsoft Defender `LocalCopy`, `Support` and scan-history paths, best effort
- `C:\Windows\SoftwareDistribution\Download`
- `C:\Windows\Downloaded Program Files`
- Delivery Optimization caches
- `C:\Windows\Prefetch`
- `C:\Windows.old`, when present
- The Recycle Bin on drive `C:`

### Windows cleanup tools

- `dism.exe /Online /Cleanup-Image /StartComponentCleanup [/ResetBase] /Quiet`
- `rundll32.exe pnpclean.dll,RunDLL_PnpClean /DRIVERS /MAXCLEAN`
- `Delete-DeliveryOptimizationCache` when that cmdlet is present
- `pnputil /export-driver` then `/delete-driver`, only under `-PruneSupersededDrivers`
- `cleanmgr.exe /sagerun`, only under `-EnableLegacyDiskCleanup`

### What it never touches

Browser history, cookies, saved passwords, `WebCache`, File Explorer history, Recent items, Quick Access state, pinned or frequent destinations, the project folder, the deployment folder, and the active log.

## Behaviour worth knowing

- Deleted files do not go to the Recycle Bin.
- A file locked by another process is queued for deletion at the next boot. Windows only records the pending operation; it does not guarantee the delete will succeed, so the log says `queuedForReboot`, never "deleted".
- `DISM /ResetBase` is enabled by default. After it runs, the Windows updates installed before that point can no longer be uninstalled. Future updates are unaffected.
- DISM exit code `3010` is treated as success with a pending reboot. Microsoft publishes no DISM exit-code table, so this maps the generic `ERROR_SUCCESS_REBOOT_REQUIRED` constant; `3017` is treated as a failure.
- Defender Tamper Protection can lock scan-history files even for `SYSTEM`. Those are reported as skipped, with the reason.
- Emptying other users' Recycle Bins has no documented supported API. The tool sweeps `$I`/`$R` file pairs under `C:\$Recycle.Bin\<SID>` directly, never deleting a per-SID folder or `desktop.ini`. That on-disk layout is undocumented by Microsoft, and per-user Recycle Bin size shown in Explorer may stay stale until the shell refreshes.

## Logs

Where the log goes depends on whether the run is elevated:

| Run | Log directory |
| --- | --- |
| Elevated (the scheduled task, the installer, an elevated manual run) | `%ProgramData%\WindowsAutoCleanup\Logs`, falling back to `%SystemRoot%\Logs\WindowsAutoCleanup` |
| Not elevated | `%LOCALAPPDATA%\WindowsAutoCleanup\Logs` |

The split is deliberate. Whoever *creates* `%ProgramData%\WindowsAutoCleanup` becomes its owner and, through `CREATOR OWNER` inheritance, gains full control of the directory the `SYSTEM` task later writes its audit log and driver backups into — so a standard user must never be the one to create it.

If no log file can be created anywhere, the run aborts rather than proceeding silently.

Format is one structured line per event:

```text
[2026-08-23 13:29:18 UTC] [INFO] [Run] Configuration. | enableLegacyDiskCleanup=False pruneSupersededDrivers=False resetWindowsUpdateBase=True scope="C: only" skipRecycleBin=False
[2026-08-23 13:29:19 UTC] [INFO] [Result] Target complete. | bytes=160 category="Windows Temp contents" dirs=2 files=53 links=1 path=C:\Windows\Temp skipLocked=1 skipProtected=1
[2026-08-23 13:29:19 UTC] [INFO] [Dism] Step complete. | attempted=True category="Windows component store cleanup (DISM)" detail="exit 3010" durationMs=17422 failed=False reboot=True skipped=False succeeded=True
```

Values are quoted only when they contain a space, and keys are sorted so two runs can be diffed.

Levels are `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Skips are broken out by reason — `skipLocked`, `skipDenied`, `skipNotEmpty`, `skipReparse`, `skipProtected`, `skipOutOfRoot`, `skipVanished`, `skipDeadline` — so a large skip count can be diagnosed instead of guessed at. The newest 30 run logs are kept; older ones are deleted at the start of each run.

Logs contain local usernames, paths and host details. They are ignored by Git and should not be published.

## Restoring a folder hardened by an older version

Versions before 1.2.0 could leave your checkout owned by a group, with inheritance disabled and your own account reduced to read and execute. They also dropped a `.WindowsAutoCleanupAclHardened` marker file.

From an **elevated** PowerShell, take ownership back, then restore inheritance from the parent folder:

```bash
icacls "C:\path\to\WindowsAutoCleanup" /setowner "$env:USERNAME" /t /c /q
```

```bash
icacls "C:\path\to\WindowsAutoCleanup" /reset /t /c /q
```

`/setowner` must run first: only the owner (or an administrator) may rewrite the DACL, and `/reset` replaces the explicit entries with the ones inherited from the parent directory. Then delete the leftover marker:

```bash
Remove-Item "C:\path\to\WindowsAutoCleanup\.WindowsAutoCleanupAclHardened" -Force -ErrorAction SilentlyContinue
```

Nothing in v1.2.0 recreates any of this — the capability is gone, and a test fails the build if a call to `Set-Acl`, `SetOwner`, `SetAccessRuleProtection`, `icacls` or `takeown` reappears in the shipped code.

## Troubleshooting

**Execution policy blocks the script.** Use `-ExecutionPolicy Bypass` for the process, as in the examples above.

**Windows Update Cleanup still shows a size in Disk Cleanup.** That data lives in the component store, not a folder. The tool uses DISM; Windows may keep reporting metadata until a reboot finalises it.

**A lot of items are skipped.** Read the reason fields in the log. `skipLocked` means files were open in another process and were queued for the next boot. `skipDenied` means the ACL blocked deletion even for `SYSTEM`, which is normal for Defender scan history. `skipProtected` means a protected root (your checkout, the deployment, the log directory) lives inside that target and was deliberately left alone.

**The installer refuses to register the task.** The deployment directory failed the machine-trust check, meaning a non-administrative principal could still write to what `SYSTEM` would execute. The log names the exact path and principal. This fails closed on purpose.

**The uninstaller says the task is not ours.** A task with the same name exists but does not carry this project's ownership marker. It is left untouched; remove it yourself if you are sure.

## Repository files

| Path | Purpose |
| --- | --- |
| `Run.ps1` | Entry point: parameters, elevation, single-instance lock, orchestration, exit codes. |
| `src/WindowsAutoCleanup.Core.psm1` | Logging, path safety, run deadline, bounded process runner, machine-trust checks. |
| `src/WindowsAutoCleanup.FileSystem.psm1` | The single no-follow, reparse-safe, long-path-safe deletion primitive. |
| `src/WindowsAutoCleanup.Targets.psm1` | The `C:`-only allow-list. |
| `src/WindowsAutoCleanup.Steps.psm1` | DISM, pnpclean, driver pruning, Recycle Bin, Delivery Optimization, legacy cleanmgr. |
| `src/WindowsAutoCleanup.Deploy.psm1` | Deployment copy, machine-trust verification, scheduled-task ownership. |
| `Install-WindowsAutoCleanupTask.ps1` | Deploys the runtime and registers the daily task. |
| `Uninstall-WindowsAutoCleanupTask.ps1` | Removes the task and the deployment. |
| `Tests/` | Self-contained test harness, bounded parallel runner, and behavioural suites. |
| `.github/workflows/ci.yml` | Analyzer and tests on Windows PowerShell 5.1 and PowerShell 7. |
| `GITHUB_RELEASE_NOTES.md` | Release notes for the current version. |
| `LICENSE` | MIT License. |

## License

MIT. See [LICENSE](LICENSE).

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
