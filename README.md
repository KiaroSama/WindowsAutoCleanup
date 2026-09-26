# WindowsAutoCleanup

WindowsAutoCleanup is an administrator-only PowerShell cleanup utility for Windows. It removes only explicitly allow-listed temporary files and cache locations on drive `C:`, runs supported Windows cleanup tools, and can install itself as a hidden daily scheduled task.

The project targets unattended maintenance on Windows 10, Windows 11, and supported Windows Server versions. It runs on Windows PowerShell 5.1 and PowerShell 7, and writes a structured UTC log for every run.

## Safety guarantees

These are the invariants the code and its regression tests are written against:

- Default cleanup affects drive `C:` only.
- `-ResetWindowsUpdateBase:$false` never results in a DISM `/ResetBase`, including across a UAC relaunch.
- Nothing PATH-resolved or user-writable is ever registered to run as `SYSTEM`. The scheduled task references a machine-wide deployment and a canonical PowerShell host, both verified before registration — and so is every **ancestor** of each, up to and including the volume root, because write access to a parent directory is enough to rename the whole deployment aside and drop a different one in its place. An ancestor is held to a deliberately narrower rule than the deployment itself: creating a *new* name beside it is harmless, so only the rights that let a non-administrator replace, rename, or re-permission an existing child count against it. The default Windows `C:\` grants `Authenticated Users` the right to create directories, and a check that ignored that distinction would refuse every correct installation.
- Cleanup never leaves an allow-listed root through a junction, symbolic link, mount point, or a reparse point swapped in mid-traversal. Every deletion re-proves by handle that the path still resolves to itself immediately before the delete — not once per directory, which would leave a window as long as that directory takes to sweep. **The object deleted is the object whose identity was proved**: one handle is opened, the path is verified on that handle, and the unlink is issued on the same handle, so there is no second resolution of the name for an attacker to win. A reparse point found inside a target is deleted as a link without touching what it points at. A locked file is left alone and reported skipped — queuing it for deletion at the next boot was removed, because Session Manager re-resolves the stored *name* hours later and nothing checked at registration time binds it.
- The project folder, the deployment folder, the active log, browser history, cookies, saved passwords, Recent items, Quick Access state, and unrelated scheduled tasks survive every run.
- Every external process and every traversal has a deadline, and the total internal budget stays below the scheduled task's execution time limit.
- An unverifiable safety condition fails closed. A failed security check is never reported as success.

## What changed in v1.2.0

If you used an earlier version, read this section before upgrading.

- **The project-folder ACL hardening capability was removed.** Earlier versions rewrote the owner and DACL of the whole script folder on the first elevated run, which made a normal checkout hard to edit or delete. Nothing in this project changes an ACL any more; the installer only *verifies* that its own deployment directory is not user-writable. See [Restoring a folder hardened by an older version](#restoring-a-folder-hardened-by-an-older-version).
- **The scheduled task no longer runs your source checkout.** The installer copies the runtime into `%ProgramFiles%\WindowsAutoCleanup` and registers that copy.
- **Logs moved to `%ProgramData%\WindowsAutoCleanup\Logs`.** Logs must not live inside a directory the tool cleans, and a `SYSTEM` task must not depend on the checkout being writable.
- **`cleanmgr /sagerun` is no longer part of the default run.** Microsoft documents that `/sagerun` enumerates every drive and that `/d` is not honoured with it, so it cannot be part of a `C:`-only default. It is still available behind `-EnableLegacyDiskCleanup`.
- Its borrowed registry profile explicitly sets every registered handler to DWORD `2` (selected) or `0` (not selected), then verifies both states before starting. An absent value is not treated as an explicit off selection. Original values, types and absence are restored afterwards, including on failure or timeout.
- **Superseded driver-package pruning is now opt-in** (`-PruneSupersededDrivers`) and exports a recoverable backup before deleting anything. A package is only ever a candidate when the documented structured inventory shows it installed on **no device**, connected or disconnected; uncertainty always means skip. **Backups moved to `%SystemRoot%\Logs\WindowsAutoCleanup\DriverBackup`.** An export is the only copy of a package about to be deleted, so nobody outside the administrators may be able to create a name beside it — and `%ProgramData%` cannot offer that: it carries an inherited `BUILTIN\Users:(CI)(WD,AD,WEA,WA)` that every child inherits and no healthy install can shed, which would let a standard user plant the manifest, the pending marker or the commit file before the run writes them. This project is not allowed to rewrite an ACL, so the location is the whole lever. Pruning now **refuses** rather than warning when its root has any non-administrative writer, and the verdict is taken on the object that was actually opened or created, through that object's own handle — checking the parent by name is not enough, because an ACE that is *inherit-only* there grants nothing on the parent and everything on the child created under it. The three predictable control files are created collision-failing and no-follow, so a manifest, pending marker or commit file already sitting at the name — as an ordinary file, a link, or an extra hard link to something outside — is refused rather than truncated, replaced or followed. Anything left in the old location is never read, written or deleted — the reason that location was abandoned is exactly that its evidence cannot be trusted, so nothing there is believed. It is not ignored either: every run **counts** what is still sitting in it, and while anything remains the driver step cannot report a clean outcome, only `Incomplete`. Clearing it is deliberately an operator's job — inspect those exports by hand, recover what you need, and remove the rest. Until you do, the run keeps telling you they are there. The step-by-step procedure for finding a backup, verifying its hashes and re-adding the package is under [Recovering a pruned driver package](#recovering-a-pruned-driver-package). Each backup sits in a directory named for the package identity rather than its recyclable `oem<n>.inf` number, with a `wac-driver-backup.json` manifest carrying the deletion evidence and a SHA-256 per exported file. If you ever find a `wac-driver-delete.pending` file beside that manifest, a deletion was attempted and its record never became durable: the package may already be gone, that export is protected from every later run, and recovering it and removing the marker is a manual step. A `wac-driver-delete.abandoned` file beside it says something stronger — the `pnputil` that made the attempt could not be proven to have stopped, so no later run may settle it against a store reading taken beside a writer that may still be running. That directory is held until you restart the machine and clear it yourself. Every started deletion is confirmed against the driver store itself rather than believed on `pnputil`'s exit code, so a removal that happened behind a non-success exit is counted but still reports the run as failed. **A reboot-required result is no exception.** `3010` and `1641` used to skip the check on the reasoning that the package is legitimately still listed until the restart — true, but not a reason to assert a removal nobody observed. The store is now asked after every started deletion, and a package still present behind a reboot-required exit keeps its export and its pending marker, counts nothing, and reports the run incomplete. A later run reconciles that marker: only a confirmed absence after the restart commits the backup and counts the removal, and a package still there stays incomplete rather than being quietly forgotten. The backup root, and every identity directory already inside it, must pass the same machine-trust walk the log directory gets; pruning refuses rather than writing a recovery export somewhere a standard user could tamper with it.
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

### See what a run would do, without doing any of it

```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Run.ps1 -Preview
```

Prints the destructive options as this invocation sets them, the categories `-SkipCategory` excludes, and every allow-list target that would be swept — then exits without deleting anything. The list comes from the same builder the real run uses, so it cannot drift from what would actually happen.

It is **not** a dry run of the whole run, and says so. The maintenance steps — the component store, the driver handler, `cleanmgr`, the Recycle Bin — cannot enumerate what they would remove without doing it, so the preview reports whether each is switched on rather than listing its contents. An empty allow-list does not mean nothing would happen.

The preview is carried into the elevated relaunch, so starting it from an ordinary session previews there too. `-Preview` and `-Scheduled` are refused together: a trigger that only previews is a machine nobody is cleaning, reporting success every night.

### Keep Windows updates uninstallable

```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Run.ps1 -ResetWindowsUpdateBase:$false
```

### Install the scheduled task

```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-WindowsAutoCleanupTask.ps1
```

The installer deploys the runtime to `%ProgramFiles%\WindowsAutoCleanup`, verifies that no non-administrative principal can write to it, and only then registers the task. Pass `-DailyRunTime 03:00` to change the schedule and `-NoPause` for automation; the opt-in switches that decide what the daily run actually does are listed under [Installer and uninstaller parameters](#installer-and-uninstaller-parameters).

### Remove the scheduled task

```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-WindowsAutoCleanupTask.ps1
```

The uninstaller refuses to remove a task that does not carry this project's ownership marker, and verifies the removal afterwards. Pass `-RemoveLogs` to delete the log directory as well.

### Run the tests

```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Tests\Run-Tests.ps1 -Host both
```

`-Host both` runs every suite as a child process under Windows PowerShell 5.1 *and* PowerShell 7, which is what CI does. `-Filter <name>` runs a single suite.

A case that cannot run in the current environment declares itself **skipped with a reason**; a skip is never counted as a pass, it makes its suite exit `3`, and the runner fails the whole run. Missing evidence and proven behaviour are not the same outcome, and treating them as one is how a suite reports green while asserting nothing.

Three exit paths cannot be reached without administrator rights, so they live in a separate harness that refuses to run unelevated. Run it only inside a disposable Windows VM or snapshot:

```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Tests\Invoke-ElevatedVerification.ps1 -Scenario Sandboxed
```

`-Scenario Sandboxed` proves exit codes `5`, `3`, and `2` end to end inside redirected sandboxes. `-Scenario All` additionally runs `DRIVERS` and `CLEANMGR`, which exercise the two opt-in switches against the real `pnputil` and `cleanmgr` and therefore **change the machine they run on**. No scenario ever passes `/ResetBase`.

Here, "Sandboxed" means redirected test folders, not Windows Sandbox: these scenarios still invoke real Windows maintenance. The contention test holds a real, unique mutex until the contender finishes, then verifies an uncontended control can acquire the released lock and remove its own test file. It does not depend on another cleanup being slow enough to overlap.

A second gated lane covers the whole deployment lifecycle against the real Task Scheduler - install, a scheduled SYSTEM run, an idempotent reinstall, an upgrade, a refused recovery from a tampered deployment, and an uninstall that proves both the task and the deployment root are gone. It is refused unless it is elevated **and** `WAC_VM_DEPLOYMENT_LIFECYCLE` is set to `1`, so an ordinary run reports it as refused and touches nothing:

```bash
$env:WAC_VM_DEPLOYMENT_LIFECYCLE = '1'; pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\Tests\VmDeploymentLifecycle.Tests.ps1
```

Arm it only in a disposable guest with a checkpoint taken first: it installs to the real deployment root and registers a real SYSTEM task. ResetBase stays disabled and the lane asserts that from the registered action.

CI runs this lane armed, in its own `deployment-lifecycle` job on both Windows images. A GitHub-hosted runner is the disposable guest the lane asks for - an ephemeral VM, elevated, destroyed when the job ends - and the job refuses outright on a self-hosted runner, which is somebody's machine. Because the lane owns exclusive machine state (one deployment root, one registration, one machine-wide lock) it runs single-worker: the two PowerShell hosts go one after the other, not together. The job also fails when the lane reports *refused*, since a refusal is a pass that has validated nothing.

### Before you open a pull request

CI enforces four gates. All four are runnable locally, and running them first is faster than
learning about them from a red build.

**Whitespace and conflict markers.** Diffing against the empty-tree object lints every tracked file,
not just your last commit — a trailing space that arrived three commits ago still fails.

```bash
git diff --check 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD
```

**Static analysis.** Scanning the shipped set rather than `.` gives the same answer as CI in a
working tree that also holds git-ignored tooling. Install the analyzer once with
`Install-Module -Name PSScriptAnalyzer -Scope CurrentUser`; it is installed at job time in CI and is
not a repository dependency.

```powershell
$shipped = @('Run.ps1', 'Install-WindowsAutoCleanupTask.ps1', 'Uninstall-WindowsAutoCleanupTask.ps1', 'src', 'Tests')
@($shipped | ForEach-Object { Invoke-ScriptAnalyzer -Path $_ -Recurse -Settings .\Tests\PSScriptAnalyzerSettings.psd1 })
```

**Every suite on both hosts**, with `Run-Tests.ps1 -Host both` as above. Use `-Filter <name>` while
iterating and run the full set before pushing.

When every run exits `0` the runner deletes its per-suite captures. When any run does not, it keeps
them and prints where, so a failure inside a parallel pass can still be read afterwards:

```text
EVIDENCE 1 run(s) did not exit 0; their captures are kept at <temp>\wac-run-<id>
  ! Deadline.Tests.ps1|pwsh|exit=1
```

Delete that directory once you are done with it; nothing else will.

**Four hard rules**, each enforced by a test rather than by review:

- Every PowerShell file is pure ASCII with no byte-order mark — `Tests/RepositoryHygiene.Tests.ps1`.
- No PowerShell file reaches 800 lines — same suite. Split by responsibility rather than deleting an
  assertion to fit.
- Shipped code never calls an ACL, owner or terminal-wrapper cmdlet, and never resolves an
  executable through `Get-Command` — `Tests/ShippedCodeBan.Tests.ps1`.
- Every `Tests\*.Tests.ps1` file is discovered and must actually run — a CI guard compares the
  discovered set against the manifest the runner writes, so a suite cannot be silently skipped.
  A run is identified by its suite path under `Tests\` **and** the host it ran on, and the entry is
  written when the run finishes, carrying its status. So two suites sharing a name in different
  subdirectories stay two entries rather than folding into one, one host cannot stand in for the
  other, and a suite that was started and then vanished cannot certify itself as covered.

## Parameters

### `Run.ps1` parameters

| Parameter | Default | Effect |
| --- | --- | --- |
| `-Scheduled` | off | Set by the scheduled task. A scheduled run fails fast instead of attempting a UAC relaunch. |
| `-Preview` | off | Print what would be swept and exit without changing anything. Refused together with `-Scheduled`. |
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

### Installer and uninstaller parameters

The three opt-in switches are passed to the **installer**, which writes them into the registered
task action — so a daily scheduled run performs them. They are not manual-run-only, and hand-editing
the registered task instead is what the ownership proof and the exact action parsing exist to catch.

| Script | Parameter | Default | Effect |
| --- | --- | --- | --- |
| Install | `-DailyRunTime` | `20:00` | Daily task run time, 24-hour `HH:mm`. |
| Install | `-NoPause` | off | Do not wait for a key press before exiting. For automation and tests. |
| Install | `-ResetWindowsUpdateBase` | `$true` | Registers the task with DISM `/ResetBase` enabled. Pass `-ResetWindowsUpdateBase:$false` to register it without; that value survives the elevation relaunch and is always written into the task action explicitly. |
| Install | `-PruneSupersededDrivers` | off | Adds `-PruneSupersededDrivers` to the task action. |
| Install | `-EnableLegacyDiskCleanup` | off | Adds `-EnableLegacyDiskCleanup` to the task action. **`cleanmgr /sagerun` enumerates every drive, which breaks the `C:`-only guarantee.** |
| Uninstall | `-NoPause` | off | As above. |
| Uninstall | `-RemoveLogs` | off | Also delete the log files under `%ProgramData%\WindowsAutoCleanup\Logs`. The log this run is writing survives, so the uninstall stays auditable. |
| Uninstall | `-KeepLogs` | — | Keep the logs even when `-RemoveLogs` is also passed. Makes the safe choice explicit in a script whose flags come from somewhere else. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Error, missing privileges, or an unhandled failure. |
| `2` | Completed, but at least one cleanup item failed. |
| `3` | Another run already holds the machine-wide lock. |
| `4` | Elevation was cancelled or failed. |
| `5` | Unsupported environment: the online system drive is not `C:`. |
| `6` | Incomplete: the run did not finish what it was asked to do, or cannot prove it did. The budget expired, a step hit its deadline, an elevated child had to be terminated, the durable audit log could not be produced, or the run inherited an unfinished mutation and refused to change anything further (see below). |
| `7` | Security refusal: a safety check refused to proceed on evidence. A cleanup path failed its identity or containment re-check, the directory holding the run state and audit log is not machine-trusted, or an earlier installer left a deployment transaction outstanding beside this deployment (see below). If no state directory passes verification, no run log is written and the refusal goes to the Windows event log or console; a directory created before a later trust refusal may remain. |

A run reports its **worst** outcome: a refusal outranks a failure, which outranks incomplete work. A benign skip does not affect the code — a reparse point left alone, a protected path stepped around, or an opt-in step that is switched off all keep the run at `0`.

The installer and uninstaller use the same `6` and `7`, and add an `8` of their own: the elevated child outran its budget and could **not** be proven terminated, so it may still be running and holding the machine-wide lock — do not re-run until it exits. Their full tables are in each script's `.NOTES` block.

### A run that refuses to clean from an unfinished installation

The runtime tree and scheduled registration are one recovery transaction. A record beside the
deployment root can describe either an unfinished generation or committed cleanup still pending.
The runtime refuses while either half is unresolved. Re-run the installer only when installation,
not removal, is the intended operation; it reconciles task definitions and file identities before
staging a new generation.

The durable commit includes the verified replacement task definition. Recovery restores the
original pair before commit, or the exact replacement pair after commit. An empty original task
set or deployment directory is explicit evidence, not a missing capture. Different generation IDs,
corrupted replacement contents and incomplete inspections refuse recovery without deleting evidence.
A locked capture keeps its authoritative commit record and recovery copy; an incomplete retirement
is not a successful installation.

An authorized uninstall first writes `<deployment-root>.uninstall.json`. While it remains, runtime
and install admission refuse rather than resurrecting a task from an older upgrade capture. Resume
the uninstaller to complete removal. It retires task captures, then the swap record, and the uninstall
intent last. Do not delete transaction records merely to clear a warning.

### A run that refuses to mutate anything

A timed-out mutator can leave work outside the thread or process that started it. The run records
`abandoned-mutation.json` in `%SystemRoot%\Logs\WindowsAutoCleanup\Control` and stops conflicting
mutations. Cleanup, installation and removal all honor this gate.

Only explicitly host-confined work is classified `InProcess`; its recorded process ID and creation
time can establish that the host is gone. Other mutating bounded blocks default to `External`,
including service-dispatching cmdlets. An external marker cannot retire just because the WAC host
exited, its pipes closed, or civil time advanced. A recorded monotonic system uptime followed by a
lower current uptime supplies conservative restart evidence. Missing evidence, a failed probe or a
current counter not lower than the recorded one keeps the marker. A late check after a genuine
restart may therefore still require operator verification; changing the wall clock is not a remedy.

A quarantined run still writes its diagnostic report but starts no conflicting cleanup step.
Job ownership proves completion only for job members, not arbitrary service/WMI-dispatched work.
Old markers under `%ProgramData%\WindowsAutoCleanup` remain untrusted and are neither followed nor
silently removed. Inspect unresolved work and recovery data before manually retiring any evidence.

The same strict control store protects the originals of a borrowed cleanmgr profile. Only a snapshot
created by the current attempt belongs to that attempt. A pre-existing snapshot blocks another
legacy-cleanmgr invocation with `Incomplete` and remains intact for controlled recovery. Verified
restoration retires the owned snapshot; a zero-write attempt retires only its own unnecessary copy.
A failed retirement remains `Incomplete`. Never overwrite or delete an earlier original to make a
later run appear clean.

## Concurrency

One machine-wide named mutex (`Global\WindowsAutoCleanup`) is taken before anything is mutated, and it is shared by the cleanup runtime, the installer, the upgrade path and the uninstaller — so a cleanup run cannot overlap a deployment being replaced or removed. Task Scheduler's `MultipleInstances IgnoreNew` is documented only in terms of task instances and says nothing about a manual run overlapping a scheduled one, so the mutex is the real guard. A run that cannot take the lock exits with code `3` without touching anything.

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
- `C:\Windows\Downloaded Program Files`
- `C:\Windows\Prefetch`
- `C:\Windows.old`, when present
- The Recycle Bin on drive `C:`

### Windows cleanup tools

- `dism.exe /Online /Cleanup-Image /StartComponentCleanup [/ResetBase] /Quiet`
- `rundll32.exe pnpclean.dll,RunDLL_PnpClean /DRIVERS /MAXCLEAN`
- `Delete-DeliveryOptimizationCache`, and only when `Get-DOConfig -Verbose` reports the cache's `WorkingDirectory` on `C:`
- `pnputil /export-driver` then `/delete-driver`, only under `-PruneSupersededDrivers`
- `cleanmgr.exe /sagerun`, only under `-EnableLegacyDiskCleanup`

### What it never touches

Browser history, cookies, saved passwords, `WebCache`, File Explorer history, Recent items, Quick Access state, pinned or frequent destinations, the project folder, the deployment folder, and the active log.

## Behaviour worth knowing

- Deleted files do not go to the Recycle Bin.
- A file locked by another process is **left alone** and reported as skipped. Earlier versions queued it for deletion at the next boot through `MoveFileEx`; that was removed. Session Manager resolves the stored *name* at the next boot, so nothing checked at registration time binds what actually gets deleted hours later, and an ancestor swapped in the meantime redirects the deletion. The cost is real — a locked file survives until something releases it — and it is deliberate.
- **A path segment that canonicalisation would rename is left alone, never cleaned.** Win32 normalisation strips trailing dots and spaces from *every* component, so `note.txt.` canonicalises to `note.txt` and `root\dir.\victim.txt` to `root\dir\victim.txt` — a different file, and a different *directory*. Asking to delete the first used to delete the second and report it as a success, and the handle-bound identity proof could not catch it, because the expected path went through the same normalisation and the two corrupted names matched. Every segment is now checked, and one that would not survive canonicalisation is refused and recorded as a skip. The cost is that it survives every run; the alternative was destroying a neighbour that was never enumerated.
- **Which names those are is decided by the host, not by a list.** The two supported hosts genuinely disagree: a trailing U+00A0 NO-BREAK SPACE survives canonicalisation on PowerShell 7 and is stripped by it on Windows PowerShell 5.1. Each segment is therefore asked of the platform rather than matched against a character set that would be wrong on one of them. The consequence is visible: such an entry is cleaned on PowerShell 7 and refused on 5.1. What is identical on both is the part that matters — the name is never converted into its ordinary-looking neighbour.
- **Threat model, decided rather than left open.** A local standard user who can write into an allow-listed target is an attacker this tool defends against. That is not hypothetical: it runs as `SYSTEM`, and `C:\Windows\Temp` grants `BUILTIN\Users` write access by default.
- **The deletion race is closed at the leaf.** Two earlier designs were not enough. Verifying once per directory left a window as long as that directory took to sweep; verifying per leaf and then deleting *by pathname* still left the gap between the check returning and the kernel resolving the same name again. Deletion now opens one handle, proves the identity on that handle, and issues the unlink on the same handle through `NtSetInformationFile` — managed code cannot express this, and it was measured on both hosts that no `File`/`Directory` overload accepts a handle.
- **What remains pathname-based is enumeration.** Children are discovered by walking the parent's path, so an ancestor swapped mid-sweep can change which children are *found*. Every directory is re-verified before it is descended into, and any leaf reached through a swap fails the handle-bound identity proof and is refused. Losing that race produces a wrong **refusal**, never a wrong deletion. A concurrent junction-swap adversary test asserts external sentinels survive every iteration. A reparse **leaf** is no exception, and used to be: skipping the proof there looked right, because resolving a link is exactly what must not happen when the link is the thing being removed. But `FILE_FLAG_OPEN_REPARSE_POINT` only stops the *final* component being followed, so a swapped ancestor still redirected the open to a different link entirely. The parent is now opened and proved first, and the leaf is opened relative to that handle.
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

The split is deliberate. Whoever *creates* `%ProgramData%\WindowsAutoCleanup` becomes its owner and, through `CREATOR OWNER` inheritance, gains full control of the directory the `SYSTEM` task later writes its audit log into — so a standard user must never be the one to create it. Driver backups no longer live under that root at all; see the pruning entry above for why they were held to a stricter rule than a log.

The directory is created through a **pinned handle**, not by pathname. The old sequence tested whether the directory existed and then called `New-Item -Force`, which does not create-or-fail but create-or-**adopt**: a directory that appeared in the window between the two was silently taken over, and since the pre-flight can only verify the nearest *existing* ancestor when the root does not exist yet, a standard user able to create names under that ancestor could plant the predictable directory and have the `SYSTEM` audit log written into something they own. Every missing component is now created relative to a proved parent handle with a collision-failing disposition, the owner, DACL, reparse state, volume and resolved identity of the object actually created are read *from that handle*, and the log file itself is created relative to it — so it lands inside the directory that was verified or it is not created at all. One consequence worth stating: this makes the audit log depend on the native surface compiling, and a host where it cannot compile now gets no log rather than an unverified one. It fails loudly — the run refuses and exits non-zero.

If no log file can be created anywhere, the run aborts rather than proceeding silently.

An elevated run checks each candidate's ancestor trust before creation, then checks the resulting directory's identity and descriptor through its pinned handle. A missing directory is created with collision-failing semantics; the log file is created relative to the verified directory handle. If the new directory inherits an unsafe descriptor, it is refused before any log file is written. When no candidate is usable, the refusal goes to the Windows event log or console instead; an empty directory created before that refusal may remain.

Format is one structured line per event:

```text
[2026-08-23 13:29:18 UTC] [INFO] [Run] Configuration. | enableLegacyDiskCleanup=False pruneSupersededDrivers=False resetWindowsUpdateBase=True scope="C: only" skipRecycleBin=False
[2026-08-23 13:29:19 UTC] [INFO] [Result] Target complete. | bytes=160 category="Windows Temp contents" dirs=2 files=53 links=1 path=C:\Windows\Temp skipLocked=1 skipProtected=1
[2026-08-23 13:29:19 UTC] [INFO] [Dism] Step complete. | attempted=True category="Windows component store cleanup (DISM)" detail="exit 3010" durationMs=17422 failed=False reboot=True skipped=False succeeded=True
```

Values containing whitespace or quotes are quoted, and keys are sorted so two runs can be diffed. Message and value control characters are escaped as `<CR>`, `<LF>`, `<TAB>` or `<0xNN>` so a filename cannot forge another physical log record. Ordinary Windows paths are unchanged.

Levels are `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Skips are broken out by reason — `skipLocked`, `skipDenied`, `skipNotEmpty`, `skipReparse`, `skipProtected`, `skipOutOfRoot`, `skipVanished`, `skipDeadline` — so a large skip count can be diagnosed instead of guessed at. The newest 30 run logs are kept; older ones are deleted at the start of each run.

Logs contain local usernames, paths and host details. They are ignored by Git and should not be published.

### Machine-readable run summary

Every run that reaches its log also writes one JSON document beside that log, with the same base name and a `.summary.json` extension, on every exit path - completion, refusal, busy lock, missing module, expired preflight - with `exitCode` equal to the process's real exit code. The log is written for a person, one line per event in the order the events happened; the summary answers "did last night's run clean, or did it refuse?" without parsing prose.

```json
{
  "schema": 1,
  "mode": "cleanup",
  "version": "1.2.0",
  "executionId": "6a2f...",
  "elapsed": "00:04:11",
  "completedUtc": "2026-09-19T02:31:44Z",
  "outcome": "Succeeded",
  "exitCode": 0,
  "rebootRequired": false,
  "logPath": "C:\\ProgramData\\WindowsAutoCleanup\\Logs\\WindowsAutoCleanup_2026-09-19_02-27-33_UTC.log",
  "steps": [
    { "category": "Delivery Optimization cache", "state": "executed", "outcome": "Succeeded", "detail": "", "durationMs": 1204, "rebootRequired": false }
  ],
  "removed": { "entries": 812, "bytes": 1596440576, "failed": 0, "refused": 0 },
  "freeBytes": { "before": 41203499008, "after": 42799939584 }
}
```

`mode` says what kind of run the summary describes:

| `mode` | Meaning |
| --- | --- |
| `cleanup` | A cleanup run; it may have changed the machine. |
| `preview` | A `-Preview` run; it reports the selection and changes nothing. |
| `delegated` | An unelevated parent that handed the work to an elevated relaunch and did none itself; the child writes its own summary. |

Each step carries one of four states, and the distinction is the point of the file:

| `state` | Meaning |
| --- | --- |
| `executed` | The step ran. Whatever it concluded is in `outcome`. |
| `refused` | The step did not start because the run declined it: a security refusal, an unresolved mutation this run inherited (`Incomplete`), or a failed precondition (`Failed`). |
| `unarmed` | The step did not start because it was not switched on. |
| `unstated` | The step did not state a real true/false fact about starting. Nobody can classify it, and it is recorded as such rather than folded into one of the other three. |

A reader that sees only "0 files removed" cannot tell a quiet night from a refusal; these states can. `schema` changes only when a field changes meaning, never when one is added (`mode` was added under `schema` 1), so a reader that ignores unknown fields keeps working.

The file is created exclusively inside the trusted log directory: an existing name, a hard link or a redirected parent folder is refused, never overwritten or followed. Creation is not an atomic rename, so a run killed mid-write can leave incomplete JSON; a reader must reject a document it cannot parse rather than infer success from the file existing.

The summary holds outcomes, categories, counts and durations. It carries no command line, no environment, no per-path inventory and no credential of any kind. If it cannot be written the run logs a warning and carries on: the run's verdict is the log's and the exit code's, and this only repeats it.

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

**A lot of items are skipped.** Read the reason fields in the log. `skipLocked` means files were open in another process and were left alone. Delayed deletion is deliberately disabled — `MoveFileEx(..., MOVEFILE_DELAY_UNTIL_REBOOT)` stores a literal path string that Session Manager resolves hours later, with nothing bound to the name that gets resolved then, so those files stay on disk until the process holding them exits and the next daily run removes them. `skipDenied` means the ACL blocked deletion even for `SYSTEM`, which is normal for Defender scan history. `skipProtected` means a protected root (your checkout, the deployment, the log directory) lives inside that target and was deliberately left alone.

**The installer refuses to register the task.** The deployment directory failed the machine-trust check, meaning a non-administrative principal could still write to what `SYSTEM` would execute. The log names the exact path and principal. This fails closed on purpose.

### Recovering a pruned driver package

Driver pruning exports a package before it deletes it, so a device that stops working can be put
back. Re-adding a driver package is a machine change **you** make by hand, outside this tool — the
tool deletes and reports, it has never installed anything and will not do this for you.

Backups live at `%SystemRoot%\Logs\WindowsAutoCleanup\DriverBackup`, one directory per package
identity. The directory is named by a content hash rather than by the `oem<n>.inf` name, because
Windows recycles those numbers and two different packages can both call themselves `oem5.inf`.

**1. Find the right package.** Each identity directory holds a `wac-driver-backup.json` manifest
recording the original INF name, provider, version and the published name:

```powershell
Get-ChildItem 'C:\Windows\Logs\WindowsAutoCleanup\DriverBackup' -Directory | ForEach-Object {
    $manifest = Join-Path $_.FullName 'wac-driver-backup.json'
    if (Test-Path -LiteralPath $manifest) {
        $m = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
        [PSCustomObject]@{
            Directory  = $_.Name
            Original   = $m.OriginalName
            Published  = $m.DriverName
            Provider   = $m.ProviderName
            Version    = $m.VersionText
            DeletedUtc = $m.DeletedUtc
            Pending    = (Test-Path -LiteralPath (Join-Path $_.FullName 'wac-driver-delete.pending'))
            Abandoned  = (Test-Path -LiteralPath (Join-Path $_.FullName 'wac-driver-delete.abandoned'))
        }
    }
} | Format-Table -AutoSize
```

An empty `DeletedUtc` means removal was not durably confirmed, **not** that the driver is still
installed. A pending marker can survive a successful deletion when confirmation or manifest commit
failed. Preserve the backup and inspect the current driver inventory before deciding what to restore.

**2. Verify the export before you trust it.** The manifest records a SHA-256 for every exported
file. A mismatch means the backup is not usable and must not be installed:

```powershell
$dir = 'C:\Windows\Logs\WindowsAutoCleanup\DriverBackup\<identity-directory>'
$m = Get-Content -LiteralPath (Join-Path $dir 'wac-driver-backup.json') -Raw | ConvertFrom-Json
@($m.File | ForEach-Object {
    $entry = $_
    $file = Join-Path $dir $entry.Path
    $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    [PSCustomObject]@{ Path = $entry.Path; Matches = ($actual -eq $entry.Sha256.ToUpperInvariant()) }
}) | Format-Table -AutoSize
```

**3. Put it back.** From an **elevated** prompt, point `pnputil` at the exported INF:

```powershell
pnputil /add-driver "C:\Windows\Logs\WindowsAutoCleanup\DriverBackup\<identity-directory>\<name>.inf" /install
```

**4. Confirm it landed** by looking for the published name in the store:

```powershell
pnputil /enum-drivers
```

**A `wac-driver-delete.pending` marker.** The tool started a deletion and could not confirm how it
ended, so it kept both the marker and the copy, and the driver step will not report better than
`Incomplete` until it is resolved. Inspect `pnputil /enum-drivers`, comparing the package's original
INF, provider, class and version as well as its published name: Windows can reuse `oem<n>.inf`.
Do not delete the marker or an unstamped backup merely to clear the warning; it may be the only
recoverable copy of a removed package. A matching published name alone does not prove otherwise.

**A `wac-driver-delete.abandoned` marker.** The stronger of the two, and the only state this tool
will never resolve for you. Pending means *the result is not known yet* — a later run asks the driver
store and settles it. Abandoned means the `pnputil` that made the attempt could not be proven to have
stopped: part of its process tree outlived it, or its output never finished arriving. No later run
can settle that by asking again, because every answer it got would be read beside a writer that may
never have stopped. So the directory is held, the run reports `Incomplete`, and that run changes
nothing further on the machine.

**Restart the machine first.** A restart is what actually ends work this tool cannot see. After it,
use `pnputil /enum-drivers` to check whether the package is still in the store, recover the export by
the steps above if it is gone, and only then remove both markers by hand. Until you do, every run
keeps reporting it — which is the intent: this is the one state where the tool would rather be noisy
than guess.

**`Get-ScheduledTask` does not show the task.**
The task is registered under `\WindowsAutoCleanup\` with a `SYSTEM` principal, and its security descriptor is not readable by a standard user, so an unelevated `Get-ScheduledTask` or `schtasks /query` reports nothing at all. Query it from an elevated shell, or read the Task Scheduler operational event log, which records registration (event 106) and each run (events 100/102/201) regardless of privilege.

**The uninstaller says the task is not ours.** A task with the same name exists but does not carry this project's ownership marker. It is left untouched; remove it yourself if you are sure.

**Repository fixes are not taking effect.** The task runs the deployed snapshot, not your Git
checkout. Check `scriptRoot`, version and configuration in its newest operational log. Updating the
repository alone does not update that snapshot or the task's saved switches; redeployment requires
the installer and the corresponding elevated verification. TEMP cleanup can remove active tools'
unlocked scratch files, so do not run it during work that depends on those files.

## Repository files

| Path | Purpose |
| --- | --- |
| `Run.ps1` | Entry point: parameters, elevation, single-instance lock, orchestration, exit codes. |
| `src/WindowsAutoCleanup.Core.psm1` | Package entry point over `Native`, `Path`, `TrustedStore`, `Locations`, `Budget`, `ControlFile`, `Quarantine`, `RunState`, `Process`, `Environment` and `Trust`: the P/Invoke surface, path safety, pinned-handle directory creation, the fixed machine locations, the run deadline and recovery reserve, the audit log, bounded execution, machine facts, and the owner/DACL rules. |
| `src/WindowsAutoCleanup.Budget.ps1` | The run's two time budgets: the deadline ordinary work is held to, and the single reserve that recovery work draws from after that deadline is gone, so a rollback still runs but twenty of them cannot add up to an unbounded shutdown. Every shutdown-critical wait draws from the same two numbers - a termination wait, a pipe drain and a tree kill each used to take a fixed allowance charged to nothing, once per tool. The remaining budget is the smaller of the civil deadline and a stopwatch armed with it, so an NTP or DST correction cannot hand the run time it never earned. |
| `src/WindowsAutoCleanup.ControlFile.ps1` | The small CONTROL files that decide what a later run may do, in a store where nobody but an administrator can create a name. Under `%SystemRoot%\Logs`, not the state root - the state root's own trust rule permits a standard user to create new names there, which for a file that decides whether the next run may change the machine is the decision itself. A write is ONE collision-failing create bound to the directory handle: there is no temporary name and no replace, so a link or a file preplanted at either name is refused rather than written through. A read is judged from the open - a reparse point and an extra hard link are refused, and only the open's own "not there" counts as absence. |
| `src/WindowsAutoCleanup.Quarantine.ps1` | Durable mutation admission in the strict control store. In-process and external lifetimes are distinct; only positive process or monotonic restart evidence can retire uncertainty. |
| `src/WindowsAutoCleanup.OwnedProcess.ps1` | Ownership at creation: every external tool is launched suspended, bound to a kill-on-close Job Object before its first instruction, then resumed. Termination is one call over the whole tree, and "did everything this run started finish?" is answered from the job rather than from a process snapshot. The launch also reports how far it got — nothing created, created but never resumed, or resumed — because only the first of those makes starting the same command again safe. |
| `src/WindowsAutoCleanup.OwnedRun.ps1` | The policy that consumes that mechanism: waiting for the owned work rather than just its root, draining output inside the run budget, terminating only on a deadline or an error, and turning root exit, owned-tree state and output completeness into one result the steps can read. |
| `src/WindowsAutoCleanup.BoundedWork.ps1` | In-process work under a real wall-clock bound, in its own runspace - including the rule that a block declaring itself a mutator, once abandoned, stops every later mutation in the run and records that fact where the next process will find it. |
| `src/WindowsAutoCleanup.FileSystem.psm1` | The single no-follow, reparse-safe, long-path-safe traversal, over the handle-bound delete in `BoundDelete`. |
| `src/WindowsAutoCleanup.Targets.psm1` | The `C:`-only allow-list. |
| `src/WindowsAutoCleanup.Steps.psm1` | Package entry point over `StepContract`, `RecycleBin` and `DiskCleanup`: the shared result vocabulary, DISM, Delivery Optimization, the Recycle Bin sweep and the opt-in cleanmgr step. |
| `src/WindowsAutoCleanup.Drivers.psm1` | Package entry point over `DriverHandler`, `DriverInventory` and `DriverBackup`: the structured pnputil inventory and opt-in package pruning with content-addressed backups. |
| `src/WindowsAutoCleanup.DriverHandler.ps1` | The other driver step: the pnpclean sweep of packages Windows itself reports as orphaned, and the driver-store size it reports before and after. |
| `src/WindowsAutoCleanup.Deploy.psm1` | Package entry point over `DeploymentTree`, `DeploymentProof`, `DeploymentJournal`, `ScheduledTask` and `TaskRemoval`: the shared operation lock, staging and rollback, ownership proof, and task action parsing. |
| `Install-WindowsAutoCleanupTask.ps1` | Deploys the runtime and registers the daily task. |
| `Uninstall-WindowsAutoCleanupTask.ps1` | Removes the task and the deployment. |
| `src/WindowsAutoCleanup.EntryGate.ps1` | The pre-flight safety verdict, dot-sourced by **both** entry points so the two cannot drift: log health and state trust are decided before the first mutation, and an unknown answer refuses just as a false one does. |
| `src/WindowsAutoCleanup.DeploymentJournal.ps1` | The two durable records a deployment operation leaves behind, and the corroboration a recovery slot must pass. The swap record says a tree replacement started and did not finish; the task-capture record says a scheduled task was unregistered and its exact definition is in here. They are separate files because the swap record is rewritten at every stage of one move pair while the capture has to outlive all of them. Both are read through a schema **window** rather than an exact match, so a record written by an older build still drives recovery instead of refusing the upgrade that would read it. |
| `src/WindowsAutoCleanup.TaskRemoval.ps1` | Removing one scheduled task: prove it is ours, export its exact definition, hand that capture to the caller to make DURABLE, and only then unregister. A capture that could not be recorded leaves the task registered - that ordering is the transaction boundary, not a detail. |
| `src/WindowsAutoCleanup.DeploymentRecovery.ps1` | The ONE commit decision an interrupted deployment generation gets. Files and the scheduled-task registration are two durable records carrying the same generation id, and this reads both plus the disk and answers once - restore the original, commit the replacement, or refuse and touch nothing. Two individually durable records do not make the pair atomic; one verdict both halves execute does. |
| `src/WindowsAutoCleanup.TaskMatch.ps1` | Comparing a scheduled task to the definition that was captured, by SEMANTICS rather than by name: normalised execution conditions and documented defaults, trigger repetition and weekly day selections included, paths compared apart from case-sensitive arguments, and an unexpected trigger on a capture that declared none treated as a difference rather than a match. |
| `src/WindowsAutoCleanup.InstallerRecovery.ps1` | The installer's task-capture transaction: resolving the conflicting registration behind that durable record, reconciling a record an earlier interrupted run left, and ending the transaction when the replacement is proven registered or the removal is proven undone. |
| `src/WindowsAutoCleanup.InstallerTask.ps1` | The installer's scheduled-task lifecycle: trigger, conflict resolution with definition capture, post-registration read-back, and the rollback that restores both the tree and the task. |
| `src/WindowsAutoCleanup.RunReport.ps1` | Dot-sourced by `Run.ps1`: the header, the run-level verdicts and the footer. |
| `src/WindowsAutoCleanup.RunPreview.ps1` | Dot-sourced by `Run.ps1`: `-Preview`, the read-only report of what a run would sweep. |
| `src/WindowsAutoCleanup.RunSummary.ps1` | Dot-sourced by `Run.ps1`: the versioned `.summary.json` written beside each run's log. |
| `Tests/` | Self-contained test harness, bounded parallel runner, and behavioural suites. |
| `Tests/Campaign/` | The protected, opt-in disposable-VM campaign: the power-loss, real-restart and service-dispatched scenarios continuous integration structurally cannot run. Its own README holds the arming procedure. |
| `Tests/Invoke-ElevatedVerification.ps1` | Elevated-only harness (with its `_ElevatedVerification.*.ps1` parts) for the exit paths and the opt-in switches that cannot be reached unprivileged. Refuses to run without administrator rights, and is not one of the discovered `*.Tests.ps1` suites. |
| `.github/workflows/ci.yml` | Whitespace and conflict markers over the whole tracked tree, the analyzer, and every suite on Windows PowerShell 5.1 and PowerShell 7, plus a guard that each discovered suite actually ran - the guard checks the manifest's case totals and exit-code consistency, not just that a `TOTAL` line is present. The matrix runs both `windows-2025` and `windows-2022` without fail-fast, and the transcript, executed manifest and environment record are uploaded on success **and** on failure, so a red run leaves reproducible evidence rather than only a red mark. Pure-ASCII source, no byte-order mark, and the 800-line file ceiling are enforced by `Tests/RepositoryHygiene.Tests.ps1` rather than by a bespoke CI step, so they hold locally too. |
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
