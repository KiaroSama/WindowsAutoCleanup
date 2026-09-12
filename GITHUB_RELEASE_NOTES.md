# WindowsAutoCleanup v1.2.0

Security, correctness and reliability release.

The behaviour below is covered by a behavioural suite that runs every case on both Windows
PowerShell 5.1 and PowerShell 7. The safety-critical ones are **mutation-proven**: reverting the fix
in a scratch copy of the tree was confirmed to turn the corresponding test red, so a green suite
means the guard is really there rather than merely alleged. That check was added after an
adversarial review showed thirteen documented guarantees could be reverted with the old suite still
passing, and it has since caught more than a dozen further assertions that asserted nothing.

## The deletion race is closed, and the threat model is stated

Earlier drafts of this release said containment was guaranteed while the code could not deliver it.
That is resolved rather than reworded.

**Threat model:** a local standard user who can write into an allow-listed target is an attacker this
tool defends against. It runs as `SYSTEM`, and `C:\Windows\Temp` grants `BUILTIN\Users` write access
by default, so that user is real.

**What changed:** deletion used to verify a path and then delete it *by name*, which is a second,
independent resolution of the same name. Every leaf is now removed through a handle bound to it - one
open, the identity proved on that handle, the unlink issued on the same handle - so there is nothing
for an attacker to swap in between. Managed code cannot express that; it goes through
`NtSetInformationFile`.

**What is still pathname-based, said plainly:** enumeration. An ancestor swapped mid-sweep can change
which children are *found*, but any leaf reached that way fails the handle-bound proof and is
refused. Losing that race produces a wrong **refusal**, never a wrong deletion.

## Other correctness work in this release

- **A safety refusal now happens before the first mutation, not in the footer.** An untrusted or
  *unknown* state path refuses the run, the installer and the uninstaller with nothing written, and
  the refusal is reported without writing through the path it just refused.
- **A scheduler error is no longer read as "no task is registered".** Task lookup is Found, Absent or
  Failed, and only a positively identified not-found is Absent. The same distinction now blocks
  removal, rollback and uninstall rather than letting an unanswerable query look clean.
- **An incomplete directory walk can no longer look like an empty one.** Deployment traversal reports
  its own completeness, and every decision that depends on it refuses to mutate when it is incomplete.
- **A kill is only reported when it is proven, and the tool is owned before it runs.** Every external
  tool is now created SUSPENDED and bound to a kill-on-close Job Object before its first instruction,
  then resumed. Membership is decided at creation, so a grandchild stays accounted for even when the
  process that started it has already exited - the case a process snapshot cannot answer, because a
  snapshot shows only who is alive NOW. Stopping the tool is one call over the whole job, "did
  everything this run started finish?" is read from the job rather than inferred, and if this process
  dies the job's last handle closing takes the tree with it. When a job cannot be created the tool
  still runs, the older handle-binding walk still proves what it can, and the result says plainly that
  it was not owned rather than implying otherwise. The installer wrappers no longer time out before
  the elevated child they started.
- **Driver deletion and its backup are one commit.** A marker is written before `pnputil` is asked to
  remove anything and cleared only once the backup record is durable on disk, so an interrupted
  deletion can never leave an export that a later run mistakes for residue and reclaims.
- **`cleanmgr` runs exactly the categories you selected.** The `/sagerun` profile is written exact and
  read back before launch, so handlers a previous `sageset` left enabled are no longer swept along.

> **Upgrading from 1.0.x or 1.1.0?** Read *Breaking changes* first. The scheduled task now runs a
> machine-wide deployment instead of your checkout, logs moved, and the folder-ACL hardening
> capability was removed.

## Breaking changes

- **Project-folder ACL hardening was removed.** Earlier versions rewrote the owner and DACL of the
  entire script folder on the first elevated run and dropped a `.WindowsAutoCleanupAclHardened`
  marker, which made a normal checkout hard to edit or delete. Nothing in this project changes an ACL
  any more. The installer only *verifies* that its own deployment directory is not writable by a
  non-administrative principal, and fails closed if it is. The README documents how to restore a
  folder an older version hardened.
- **`-SkipAclHardening` is now a deprecated no-op.** It is still accepted so a task registered by an
  older installer keeps working.
- **The scheduled task no longer executes your source checkout.** `Install-WindowsAutoCleanupTask.ps1`
  copies the runtime into `%ProgramFiles%\WindowsAutoCleanup` atomically and registers that copy.
- **Logs moved to `%ProgramData%\WindowsAutoCleanup\Logs`** (fallback `%SystemRoot%\Logs\WindowsAutoCleanup`).
  Logs must not live inside a directory the tool cleans.
- **`cleanmgr /sagerun` is no longer part of the default run**; it is available behind
  `-EnableLegacyDiskCleanup`.
- **Superseded driver-package pruning is now opt-in** behind `-PruneSupersededDrivers`.

## Security fixes found by adversarial review

These were found by three independent reviewers attacking the finished tree, and each was reproduced
before it was fixed.

- **A junction swapped in mid-sweep could redirect deletion out of the allow-list, as `SYSTEM`.** The
  containment checks were all string comparisons, and a string cannot notice that an ancestor
  directory was replaced since the last time it was checked. Verifying once per directory left a
  window as long as that directory took to sweep — measured at roughly twelve seconds for three
  thousand entries — and `C:\Windows\Temp` grants `BUILTIN\Users` write access by default. Every
  deletion now re-proves by handle that the path still resolves to itself, immediately before the
  delete. The cost was paid for by caching the protected-root list, which had been the larger
  per-file expense.
- **Delete-on-reboot is gone entirely.** `MoveFileEx` stores the literal path string and Session
  Manager re-resolves it at the next boot, so a locked file queued today could be redirected at
  leisure and the delete would land anywhere, before anything loaded that could object. A check at
  registration time cannot fix that - nothing verified today binds the name resolved hours later -
  so the mechanism was removed rather than guarded. A locked file is now left alone and reported as
  skipped.
- **`-ResetWindowsUpdateBase $false` with a space instead of a colon silently did the opposite.**
  Positional binding bound the switch to `$true` and dropped the leftover `$false` token into
  `-SkipCategory`, so DISM ran `/ResetBase` after the user explicitly asked it not to. `Run.ps1` now
  binds by name only, and that spelling is a parameter-binding error instead.
- **The relaunch could not work at all on a machine without PowerShell 7.** Windows PowerShell 5.1
  refuses to bind a valued switch under `-File` — every token after the script path is a literal
  string — so `-ResetWindowsUpdateBase:$false` died during parameter binding before the child could
  even open a log. No `-File` spelling carries "false" to both hosts. The relaunch and the scheduled
  task action now use `-Command`, which also lets an array parameter arrive as a real array and
  propagates the child's real exit code.
- **A total failure was reported as success.** The relaunch payload ended with
  `exit $LASTEXITCODE`, but a child that never ran leaves that variable undefined and `exit $null`
  is exit 0. The payload now seeds it with a failure value first.
- **The traversal was not actually bounded.** The deadline was checked once per directory, so a
  single flat directory — exactly the never-cleaned `%TEMP%` this release exists to fix — swept to
  completion without ever looking at the clock. It is now checked per entry, and the first
  directory-deletion pass checks it too.
- **A standard user could come to own the machine-wide state directory.** An unelevated run created
  `%ProgramData%\WindowsAutoCleanup`, making that user its owner with `CREATOR OWNER` inheritance
  over the tree the `SYSTEM` task later writes its audit log and driver backups into. An unelevated
  run now logs under the user's own profile instead.
- **The machine-trust check had three holes**: a NULL DACL grants everyone everything but surfaces as
  zero access rules, which read as "no untrusted writers"; `GENERIC_WRITE`/`GENERIC_ALL` are not
  translated into specific rights inside a raw ACE and slipped past the mask entirely; and the
  inherit-only `CREATOR OWNER` entry that System32 and `%ProgramFiles%` both carry was being treated
  as effective. All three are handled, and an empty rule set now fails closed.
- **The task ownership proof accepted any rooted executable.** A task carrying this project's
  sentinel but running an arbitrary binary as `SYSTEM` was judged "ours". The executable must now be
  a canonical machine-wide PowerShell host.
- **The state-trust verdict was reached after the log directory and log file had already been
  created.** An elevated run created its state directory, opened the run log inside it, and only then
  asked whether that directory was machine-trusted -- so the refusal itself travelled through the path
  being refused. Every candidate root is now verified BEFORE anything is created, and a run with no
  trusted candidate creates nothing at all. The ordering is fixed; the binding is not. The directory
  is verified by pathname and the log file is then created by pathname, so a residual window remains
  between the two -- unlike deletion, which proves identity on the handle it unlinks through. Closing
  it needs a handle-relative create, which managed code cannot express.
- **The wrapper treated an unproven termination as proof.** Both UAC wrappers branched on a
  `PSCustomObject`, which is always truthy, so an elevated child that could not be proven terminated
  was reported "proven gone; re-run". They now branch on the boolean, name the surviving process, and
  return a new exit code `8` that forbids a retry.
- **A driver-package deletion was believed on the tool's exit code.** Every started
  `pnputil /delete-driver` is now confirmed against the driver store itself, so exit `259` and any
  undocumented non-zero exit no longer clear the pending marker or reclaim the backup on the tool's
  word alone.
- **A trailing-dot or trailing-space name deleted its neighbour and called it a success.** Win32
  path normalisation strips both from the final component, so `note.txt.` canonicalised to
  `note.txt` and the delete destroyed that instead, recording `FilesDeleted=1`. The handle-bound
  identity proof could not catch it: the expected path is produced by the same normalisation, so
  both sides of the comparison were corrupted identically and matched. Such a name is now refused
  at canonicalisation and recorded as a skip -- it is never cleaned, which is the right way round.
- **The driver backup root was trusted without being checked.** Driver pruning now refuses with a
  security refusal when its backup root, or an existing identity directory inside it, is not
  machine-trusted -- the same walk the log directory already got.

## Security fixes

- **Explicit `-ResetWindowsUpdateBase:$false` is no longer lost across a UAC relaunch.** The relaunch
  helper read its own empty `$PSBoundParameters` instead of the script's, so a non-elevated call that
  explicitly disabled `/ResetBase` relaunched with the default `$true` and could make installed
  Windows updates permanently non-uninstallable. Bound parameters are now captured at script scope
  and every boolean switch is forwarded in the explicit `-Name:$true|$false` form.
- **The `SYSTEM` task no longer trusts mutable or PATH-resolved binaries.** `Get-Command pwsh.exe` and
  `wt.exe` can resolve to a user-writable or per-user path; both are gone. Only canonical machine
  locations are considered, and the host plus the whole deployment must pass an owner-and-DACL trust
  check before the task is registered. Windows Terminal is never used as an elevation wrapper.
- **Scheduled-task replacement and removal now require ownership proof.** The task lives in its own
  `\WindowsAutoCleanup\` folder and carries a fixed identity marker; a foreign task with the same
  name is never overwritten or deleted. A pre-1.2 task is adopted only when its own action proves it
  belongs to this project. Removal is verified afterwards.
- **Path containment is enforced by handle, not by string.** One deletion primitive now serves every
  target. A reparse-point root is refused, every directory is re-verified against a handle before it
  is descended into so a junction swapped in mid-traversal is caught, and a reparse point inside a
  target is deleted as a link without touching what it points at.
- **The project and deployment directories are protected in both directions.** A cleanup target that
  is equal to, inside, or an ancestor of a protected root is handled correctly: the protected subtree
  is skipped and everything around it is still cleaned, so a checkout living under `%TEMP%` can no
  longer be deleted by the run that cleans `%TEMP%`.

## Correctness fixes

- **`cleanmgr /sagerun` violated the `C:`-only guarantee.** Microsoft documents that `/sagerun`
  enumerates every drive and that `/d` is not honoured with it. It is now opt-in, warns that it
  affects all drives, and snapshots and restores any pre-existing `StateFlags9999` values instead of
  clobbering them.
- **The Recycle Bin is now actually emptied under `SYSTEM`.** `Clear-RecycleBin` only clears the
  calling identity's bin, so a scheduled run cleared essentially nothing while reporting success, and
  the pre-check scanned every SID directory — a scope mismatch that could report a false success. The
  sweep now uses one scope for enumeration, deletion and the post-condition.
- **Driver pruning now requires device evidence, not a name match.** Grouping by name, class,
  provider and signer and deciding on the version alone does not prove a package is removable, and
  on the reference machine it was measurably wrong: that logic nominated an `oem*.inf` with **two
  running adapters bound to it**, while the package installed on nothing was the newer one. Nothing
  was lost only because the feature is opt-in and `pnputil` declined the deletion. Removal now needs
  the documented structured inventory (`/enum-drivers /devices /format xml`) to show a package
  installed on no device, connected or disconnected; uncertainty always means skip. Backups are
  content-addressed with a manifest and cryptographic hashes and a collision is refused rather than
  overwritten, because an `oem` number can be reused and would otherwise overwrite the only copy.
  It never passes `/force`, `/uninstall` or `/reboot`.
- **External tools and in-process work are both bounded.** An injectable process runner gives every
  external tool a deadline derived from the remaining run budget, captures output without
  deadlocking, and terminates the whole process tree on timeout — a parent-only `Kill()` left
  children running, and the terminator now binds a real kernel handle and verifies the target is
  gone instead of treating `taskkill` merely exiting as proof. It also refuses to kill anything when
  the target had **already exited** before it was asked: Windows never clears a recorded parent
  process id when the parent dies and it reuses ids, so a dead target still appears to have children
  — measured here at 3% of attempts under load, and they were live unrelated processes. Reading the
  tree before checking the root meant terminating those strangers. Blocking work that never leaves the
  process — the Delivery Optimization cmdlets, WMI profile discovery, the registry snapshot, the
  Recycle Bin scan, building the allow-list — runs under its own bound too, because a call blocked
  in the OS blocks every deadline check behind it. That bound now covers the PREPARATION as well:
  opening a runspace and importing a module is charged to the same allowance, so a call can no longer
  cost "setup plus its timeout", and a tool's watchdog is re-derived immediately before the launch
  rather than when the step began. Work that must still run after the budget is gone — putting a
  borrowed registry value back, undoing a half-finished swap — draws from ONE recovery reserve for
  the whole run, so a rollback still gets time while twenty of them cannot add up to an unbounded
  shutdown. The default internal budget is 210 minutes, below the task's 4-hour limit.
- **Concurrent runs can no longer corrupt shared state.** ONE machine-wide mutex, shared by the
  cleanup runtime, the installer, the upgrade path and the uninstaller, guards every mutation, so a
  cleanup run can no longer race a deployment being replaced or removed. A run that cannot take it
  exits with code `3`. Log files are created with create-new semantics
  and a collision suffix, so two runs starting in the same second can no longer share one file and
  truncate the first.
- **Elevation and exit semantics are honest.** A manual run now waits for its elevated child and
  propagates the child's real exit code instead of returning `0` immediately. Installer and
  uninstaller elevation happens inside the main `try`, so a cancelled UAC prompt is logged and
  honours `-NoPause`.
- **Profiles are discovered properly.** User profiles come from `Win32_UserProfile` (falling back to
  the `ProfileList` registry key, skipping the well-known SIDs and `.bak` entries and requiring
  `ntuser.dat`/`ntuser.man`) instead of treating every directory under `C:\Users` as a profile. A run
  on a non-`C:` system drive now fails with exit code `5` instead of silently mixing two Windows
  installations.
- **The Delivery Optimization cache is purged only when it is actually on `C:`.** The cache can be
  relocated to another drive by the `DOModifyCacheDrive` policy, so the effective location is
  resolved first through the supported `Get-DOConfig -Verbose` (`WorkingDirectory`); a cache on
  another drive is a named safe skip, and a location that cannot be determined purges nothing. The
  raw `SoftwareDistribution\Download` and Delivery Optimization cache directories left the
  allow-list altogether: they belong to running services this tool will not stop, because it cannot
  guarantee it could restore them.

## Cleanup actually reaches the files now

The previous version left large parts of a live `%TEMP%` behind. On the reference machine a single
run reported 1138 files deleted and **486 skipped**, with zero items queued for reboot. Four causes,
all fixed:

- read-only, hidden and system attributes are cleared and the delete retried;
- paths longer than `MAX_PATH` get the `\\?\` prefix, so Windows PowerShell 5.1 can reach them at all;
- a locked file is queued for deletion at the next boot instead of being silently skipped;
- directories are deleted deepest-first and retried once after the file sweep, because a directory
  that was non-empty on the first attempt is usually empty by the second.

## Logging

- UTC timestamps with a component field: `[2026-08-23 11:04:07 UTC] [INFO] [Result] ... | key=value`.
- One `StreamWriter` with auto-flush replaces the previous `Add-Content` call, which reopened and
  closed the log file on every single line.
- **Skips are broken out by reason** — `skipLocked`, `skipDenied`, `skipNotEmpty`, `skipReparse`,
  `skipProtected`, `skipOutOfRoot`, `skipVanished`, `skipDeadline` — so a large skip count can be
  diagnosed instead of guessed at.
- Execution id, host, OS build, resolved paths, effective configuration, per-step duration and exit
  code, reboot-required state, remaining budget and free-space delta are all recorded.
- The run aborts instead of continuing silently when no log file can be created anywhere. Retention
  keeps the newest 30 run logs.
- **A security refusal can now be log-less.** When no candidate state directory is machine-trusted the
  run creates nothing -- no directory, no log file -- and the refusal goes to the Windows event log, or
  the console, instead of to a run log. Look there, not in `%ProgramData%\WindowsAutoCleanup\Logs`,
  after an exit `7` that left no log behind.
- The pre-import bootstrap log in `%TEMP%` now carries a per-run GUID as well as the process id, so
  anything matching `WindowsAutoCleanup-bootstrap-<PID>.log` exactly must match
  `WindowsAutoCleanup-bootstrap-*.log` instead.

## Other correctness fixes from the review

- The Recycle Bin step could not tell "the bin was empty" from "the bin could not be enumerated" —
  both produced an empty list and both reported success. An unreadable bin is now a failure.
- `Run.ps1` logged every step twice, under two different component names, because each step already
  logs its own result. Found by reading a real log rather than by an assertion.
- cleanmgr's `Update Cleanup` handler was skipped based on the `-ResetWindowsUpdateBase` parameter
  rather than on whether DISM actually succeeded, so a failed DISM left the component store
  untouched by both mechanisms.
- The elevation parent waited only for the time left in its OWN budget, so it terminated a child a
  few seconds before that child would have finished cleanly and reported the run as failed.
- A dot-formatted date (`14.02.2022`) is shaped exactly like a three-part version and could be read
  as one, letting a date influence a deletion after all. Note that `DateTime.TryParse` is useless
  here and actively misleading: under the invariant culture `14/02/2022` fails while the legitimate
  two-part version `10.2` parses as a date.
- Driver backups were keyed on the recyclable `oem<n>.inf` name, so a later run could overwrite the
  only recovery copy of an already-deleted package.
- The uninstaller never pruned its own logs, so the documented retention did not hold for them.
- `SkippedProtected` was missing from the run summary totals, and directory ordering used a
  culture-sensitive sort where the code claimed ordinal — the two hosts could disagree.

## Tests and CI

- The suite is now behavioural rather than a set of source-text greps. The old tests could pass while
  the feature was broken: they asserted that a variable *contained* the text `-ResetWindowsUpdateBase`
  without ever checking the child argument vector, and they required a pnputil invocation shape that
  Windows does not document.
- A self-contained harness replaces the framework dependency, so the same suites run identically on
  Windows PowerShell 5.1 and PowerShell 7 with no install step.
- Suites run as bounded parallel child processes with a wall timeout, an idle timeout, a
  resource-aware worker ceiling and owned-process-tree termination. Suites are discovered from disk,
  so a new suite is automatically covered by CI.
- CI runs the analyzer and the full matrix on both hosts with explicit job-level and step-level
  timeouts, and upgrades `actions/checkout` from the stale v4 to v7.
- The "every discovered suite ran" guard used the same non-recursive glob as the runner, so a suite
  in a subdirectory would have been invisible to both — the guard could not detect the one thing it
  existed for. Both now discover recursively.
- The runner discarded a suite's entire captured output on a file-sharing race (1–5 of every 18 runs,
  on both hosts) and still reported success, so a CI failure would have been undiagnosable. The read
  now retries, and a run that produces no `TOTAL` line is a failure: missing evidence is not success.
- The analyzer step scans the shipped file set rather than `.`, so the same command gives the same
  answer in CI and in a working tree that also holds untracked tooling.
- **A skipped case is no longer counted as a pass.** The harness had no notion of a skip, so a case
  that returned early because the environment could not support it was recorded as green. One case
  did exactly that on any elevated host — which every GitHub runner is — so in CI it asserted
  nothing and still reported success. A case now declares itself skipped *with a reason*, a skip is
  excluded from `passed=`, and it makes its suite exit `3` and fails the run. Missing evidence and
  proven behaviour are different outcomes.
- That case now genuinely runs on an elevated host: it launches its child through a restricted
  (Basic User) token, so the unprivileged path is asserted in both environments instead of being
  waved through in one of them. The de-elevated child is self-bounded, so it cannot outlive its own
  deadline even if the runner force-kills its parent.
- **New: `Tests/Invoke-ElevatedVerification.ps1`.** Exit codes `5`, `3`, and `2` could not be reached
  without administrator rights and were previously covered only through injected stubs. They are now
  proven end to end against the real `Run.ps1` inside redirected sandboxes, and the two opt-in
  switches can be exercised against the real `pnputil` and `cleanmgr`. The harness refuses to run
  unelevated, derives every child's budget from its own wall timeout so it can never terminate a
  live DISM servicing operation from outside, and never passes `/ResetBase`.

## Documentation

README and these notes now describe the shipped behaviour. Removed the false claims about a
`C:`-only `cleanmgr`, a locale-safe pnputil CSV contract, all-user Recycle Bin cleanup under `SYSTEM`
and guaranteed parameter forwarding. Added exit codes, mutex behaviour, the deployment path, log
location and retention, the opt-in destructive features, reboot-required state, uninstall and
migration behaviour, and which behaviours this project relies on that Microsoft does not document.
