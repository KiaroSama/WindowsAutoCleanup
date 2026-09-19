# Implementation Plan: Restartable installation, uninstall and abandonment transactions

**Feature directory**: `specs/001-recovery-transaction-contract` | **Date**: 2026-09-19 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-recovery-transaction-contract/spec.md`

## Summary

The implementation already exists, delivered by an external reviewer as **PR #1** on branch
`audit/review6-recovery-regressions`, head `f0dcb66`, against `main` at `4be74c8`: +1348/-285 across
40 files in 37 commits. This plan therefore covers **verification and integration**, not construction:
prove the delivered code satisfies each requirement in the spec, correct what it does not, and land it.

Two corrections are already decided by the owner and are part of this plan rather than follow-ups:

1. Remove `.github/workflows/review-regressions.yml` and `.github/workflows/source-provenance.yml`.
   They are the reviewer's delivery scaffolding, not product: the first re-runs suites the `validate`
   matrix already runs on both images and both hosts (the handoff says so itself), and the second
   uploads a full source archive on every push. Merging them would make a one-off delivery mechanism
   a permanent cost.
2. Satisfy **FR-015**: every refusal caused by a record that was not retired names the blocking file
   and the manual step that clears it.

## Technical Context

**Language/Version**: Windows PowerShell 5.1 and PowerShell 7, both, under `Set-StrictMode -Version 2.0`
**Primary Dependencies**: none added by this work; `ScheduledTasks` module and the project's own
`WacNative` P/Invoke surface
**Storage**: durable JSON records written beside the deployment root (swap, task capture, uninstall
intent) and the machine control store (quarantine)
**Testing**: the project's own harness under `Tests/`, run through `Tests/Run-Tests.ps1`; the heavy
pass runs in GitHub CI on the pushed SHA
**Target Platform**: Windows 10/11 and Windows Server, `windows-2022` and `windows-2025` in CI
**Project Type**: single-project PowerShell tool (CLI entry points plus a scheduled SYSTEM runtime)
**Performance Goals**: none in scope; bounds are correctness bounds, not throughput targets
**Constraints**: the safety boundaries in the constitution; 800-line file ceiling; ASCII/no-BOM/CRLF;
no trailing blank line at EOF
**Scale/Scope**: 40 changed files, of which 18 are `src/` and entry points and 22 are tests and CI

## Constitution Check

| Principle | Gate | Verdict |
|---|---|---|
| I. Unknown is never absence | Does any new path read unreadable/obstructed as absent? | To verify per task; the delivered code's stated design matches (`Get-WacJournalPathState` distinguishes Absent/Unreadable, and `Remove-WacDeploymentJournal` treats only PROVEN absence as nothing-to-do — verified). |
| II. Conclude only from what was proven | Is commitment written, never inferred? | Matches: an explicit commit decision bound to generation and replacement identity; the reader of the replacement task set is gated on that decision. |
| III. Safety boundaries do not move | Any ACL rewriting, recursive fallback, reboot queue, forced removal/reboot, unrelated termination, silent default change? | To verify across the whole diff; none seen in the source review so far. |
| IV. Bounded and owned | One budget per operation, monotonic clock | Matches: the outer entry point measures the whole duration and native preparation is charged; restart proof moves to a monotonic counter. |
| V. Evidence, not assertion | Does each acceptance item have a test that fails when the behaviour is removed? | The PR ships red-first evidence for 9 counterexamples; this plan verifies that claim rather than accepting it. |
| Engineering constraints | 800-line ceiling, encoding, both hosts | To verify mechanically before merge. |

No principle is waived. Nothing in this plan requires an entry in `.ai/DECISIONS.md`.

## Project Structure

### Documentation (this feature)

```
specs/001-recovery-transaction-contract/
├── spec.md
├── plan.md
├── tasks.md
├── research.md
├── data-model.md
├── quickstart.md
└── checklists/requirements.md
```

### Source Code (repository root)

```
Install-WindowsAutoCleanupTask.ps1      # installer entry point
Uninstall-WindowsAutoCleanupTask.ps1    # uninstaller entry point
Run.ps1                                 # scheduled runtime entry point
src/
├── WindowsAutoCleanup.Deploy.psm1          # deployment module; dot-sources the parts below
├── WindowsAutoCleanup.DeploymentRecovery.ps1
├── WindowsAutoCleanup.DeploymentCommit.ps1
├── WindowsAutoCleanup.DeploymentJournal.ps1
├── WindowsAutoCleanup.UninstallIntent.ps1  # new in this work
├── WindowsAutoCleanup.InstallerRecovery.ps1
├── WindowsAutoCleanup.DeploymentFence.ps1
├── WindowsAutoCleanup.Quarantine.ps1
├── WindowsAutoCleanup.StepContract.psm1
├── WindowsAutoCleanup.DiskCleanup.psm1
├── WindowsAutoCleanup.Process.ps1 / .OwnedProcess.ps1 / .OwnedRun.ps1 / .ProcessTree.ps1
└── WindowsAutoCleanup.Core.psm1 / .Native.ps1 / .BoundedWork.ps1
Tests/                                   # one suite per behaviour, discovered recursively
.github/workflows/ci.yml                 # validate matrix + armed deployment-lifecycle job
```

**Structure Decision**: unchanged. The work adds one source file
(`WindowsAutoCleanup.UninstallIntent.ps1`, dot-sourced by `Deploy.psm1`) and nine test suites; no
layer, module boundary or entry point moves.

## Phase 0: Research

See [research.md](./research.md). Two questions had to be settled from evidence rather than assumed:
what the delivered workflows actually cost if merged, and whether the delivered restart proof works
on both hosts.

## Phase 1: Design

- [data-model.md](./data-model.md) — the four durable records, their fields, their lifetimes and the
  retirement order each outcome requires.
- [quickstart.md](./quickstart.md) — how to run the verification this plan depends on.
- No `contracts/` directory: this project exposes no API, endpoint or schema to another system. Its
  external surface is three PowerShell entry points and their exit codes, which are already specified
  in each script's `.NOTES` block and in the README, and are covered by tasks rather than by a new
  contract artifact.

## Complexity Tracking

| Item | Why it is not simpler | Accepted |
|---|---|---|
| Four record kinds rather than one | They have different lifetimes: the swap record is rewritten at every stage of one move pair, the capture record must outlive all of them, the uninstall intent must outlive both, and the quarantine record belongs to the machine rather than to a deployment. One file for all four would have each write destroy the others' evidence. | yes |
| Two opposite retirement orders | A single order is wrong for one of the two outcomes: whichever record is retired first must be the one the surviving retry does not need. | yes |
| A P/Invoke for the uptime counter | The managed property that would answer it is absent on older hosts, so the managed route degrades to "inconclusive" exactly where the proof is needed. | yes |
