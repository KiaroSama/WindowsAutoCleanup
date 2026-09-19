# Tasks: Restartable installation, uninstall and abandonment transactions

**Input**: Design documents from `specs/001-recovery-transaction-contract/`
**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `quickstart.md`

**Nature of this task list**: the implementation already exists as PR #1 on branch
`audit/review6-recovery-regressions` (head `f0dcb66`). These tasks VERIFY it against the spec,
CORRECT what it does not satisfy, and INTEGRATE it. A task is complete when its evidence is in hand —
not when the delivered document says it is.

**Standing rule for every verification task**: a passing suite over unchanged code proves only that
the suite runs. Where a task says *prove*, the proof is that the named behaviour goes RED when it is
removed from the source, with the failure landing on the assertion.

## Phase 1: Setup

- [ ] T001 Fetch and pin the review target: record `origin/audit/review6-recovery-regressions` head and confirm it equals the handoff's claimed `f0dcb66`, in the session record
- [ ] T002 [P] Confirm the reviewed baseline is `main` at `4be74c8` and that the branch is mergeable with no conflict, via `gh pr view 1`
- [ ] T003 [P] Enumerate the branch's 37 commits and identify anything they would drag into history that the final tree does not contain, per `git log main..origin/audit/review6-recovery-regressions`

## Phase 2: Foundational — claims that everything else rests on

**These block the story phases: if the delivered evidence is not what the handoff says, every later verification changes meaning.**

- [ ] T004 Verify the handoff's claimed CI evidence by reading the runs themselves, not the document: full matrix 35446596342, focused regressions 35446596346, provenance 35446596339, and the two red-first checkpoints 35421391604 and 35444868246 — confirm conclusion, head SHA and that the red-first runs really failed
- [ ] T005 Verify the delivered tree satisfies the mechanical gates on its own head: `git diff --check` from the empty tree, PSScriptAnalyzer 1.25.0 with `Tests/PSScriptAnalyzerSettings.psd1`, ASCII/no-BOM/CRLF and no trailing blank line at EOF, and the 800-line ceiling across all changed files
- [ ] T006 Verify no safety boundary in the constitution moved anywhere in the diff: no ACL or owner rewriting, no broad recursive fallback, no reboot deletion queue, no forced driver removal, no forced reboot, no unrelated process termination, no silently changed destructive default

## Phase 3: User Story 1 — an interrupted upgrade leaves a coherent pair (Priority: P1)

**Goal**: prove the machine can never be left with one generation's files under another generation's registration.

**Independent test**: kill a fresh process at each transition, recover in a NEW process, and assert the whole pair on disk plus both records — not the verdict label.

- [ ] T007 [P] [US1] Prove FR-001: `Absent`, `Empty` and `Substantive` are carried end to end in `src/WindowsAutoCleanup.DeploymentRecovery.ps1` and neither collapses into another
- [ ] T008 [P] [US1] Prove FR-002: proven absence leads to `RestoreOriginal`, and an unreadable or obstructed path is not absence, in `Resolve-WacPlanWithoutSlot`
- [ ] T009 [US1] Prove FR-003: commitment is read from the written decision and never inferred from a matching manifest, a missing recovery copy or a name that exists — in `Resolve-WacPlanWithoutSlot` and `Resolve-WacPlanWithSlot`
- [ ] T010 [US1] Prove FR-004: a committed generation restores/verifies the REPLACEMENT registration and a rollback restores the ORIGINAL, in `Resolve-InterruptedTaskCapture` in `src/WindowsAutoCleanup.InstallerRecovery.ps1`
- [ ] T011 [US1] Prove FR-005: the task half's durable acknowledgement precedes the file half, in `Set-WacRecoveryTaskAcknowledgement` in `src/WindowsAutoCleanup.DeploymentCommit.ps1`
- [ ] T012 [US1] Prove FR-006 and FR-007: the two retirement orders in `Resolve-WacDeploymentRecoverySlot`, and that a failed retirement propagates rather than warning-then-succeeding, against `Tests/Review6RetirementControl.Tests.ps1`
- [ ] T013 [P] [US1] Verify the empty-original and first-install rollback paths against `Tests/Review6Recovery.Tests.ps1` and `Tests/Review6RecoveryRestart.Tests.ps1`
- [ ] T014 [US1] Verify SC-002 idempotence: recovery over a state it already produced returns the same verdict and changes nothing

## Phase 4: User Story 2 — an interrupted uninstall is never resurrected (Priority: P1)

**Goal**: prove a removal the operator asked for cannot be undone by a later installer reading leftovers.

**Independent test**: interrupt an uninstall at each point, then run an installer and a scheduled cleanup and assert both refuse and say why.

- [ ] T015 [US2] Prove FR-008: intent is written before anything is removed and retired LAST, in `src/WindowsAutoCleanup.UninstallIntent.ps1` and `Close-OutstandingJournal` in `Uninstall-WindowsAutoCleanupTask.ps1`
- [ ] T016 [P] [US2] Verify installer and runtime admission refuse while an intent stands, in `src/WindowsAutoCleanup.DeploymentFence.ps1` and the installer entry point
- [ ] T017 [P] [US2] Verify a directory-shaped, malformed or unreadable intent is neither valid permission nor absence, against `Tests/Review6Uninstall.Tests.ps1`
- [ ] T018 [US2] **Correction** — satisfy FR-015: every refusal caused by a record that was not retired names the exact blocking file and the manual step that clears it. Covers the uninstaller's refused-task path (which today fences the machine without saying so) and the legacy-commit refusal in `Resolve-InterruptedTaskCapture`
- [ ] T019 [US2] Add the regression that goes red when a refusal stops naming the blocking file, in `Tests/Review6Uninstall.Tests.ps1`

## Phase 5: User Story 3 — incomplete evidence never becomes permission (Priority: P1)

**Goal**: prove no gap in evidence is readable as a licence to mutate.

**Independent test**: supply each shape of missing, contradictory and inconclusive evidence and assert the machine is not mutated.

- [ ] T020 [US3] Prove FR-009: restart proof comes from a DECREASE of the persisted native counter, and a fabricated old civil timestamp on the same boot proves nothing, in `Test-WacMachineRestartedSince` in `src/WindowsAutoCleanup.Quarantine.ps1`
- [ ] T021 [P] [US3] Verify FR-010: bounded mutators default to `External`, and only demonstrably host-confined work is `InProcess`, across `src/WindowsAutoCleanup.BoundedWork.ps1` and its call sites
- [ ] T022 [P] [US3] Prove FR-011: `Test-WacToolLifetimeSettled` in `src/WindowsAutoCleanup.StepContract.psm1` refuses a result whose stated facts contradict each other, including never-started results
- [ ] T023 [US3] Prove FR-012: only a newly created snapshot licenses profile mutation and a pre-existing record yields `Incomplete`, in `Invoke-WacLegacyDiskCleanup` in `src/WindowsAutoCleanup.DiskCleanup.psm1`, against `Tests/Review6Snapshot.Tests.ps1`
- [ ] T024 [US3] Prove FR-013: one budget spans preparation, execution and cleanup and no phase renews it, in `Invoke-WacProcess` in `src/WindowsAutoCleanup.Process.ps1`, against `Tests/Review6Completion.Tests.ps1` and `Tests/BudgetBoundary.Tests.ps1`

## Phase 6: Integration corrections

- [ ] T025 [P] Remove `.github/workflows/review-regressions.yml` on the review branch — the `validate` matrix already runs those suites on both images and both hosts
- [ ] T026 [P] Remove `.github/workflows/source-provenance.yml` on the review branch — its delivery purpose is discharged
- [ ] T027 Verify the removals leave the suite-coverage guard intact: every suite on disk is still claimed by a CI job
- [ ] T028 Verify FR-014 on both hosts: the changed suites pass under Windows PowerShell 5.1 and PowerShell 7

## Phase 7: Landing

- [ ] T029 Push the corrected branch and verify EVERY required check on the NEW head: both `validate` legs and both `deployment-lifecycle` legs — never a previous green run
- [ ] T030 Squash-merge PR #1 into `main`, then verify the required checks on the resulting `main` commit
- [ ] T031 Verify the exact-SHA gate: local `HEAD` = `origin/main` = the `headSha` of every required check
- [ ] T032 [P] Update `.ai/` memory and the public docs the merged change makes stale, and acknowledge the documentation gate
- [ ] T033 [P] Run the survivor sweep and confirm no process this work started is alive, and no disposable capture remains

## Dependencies

- Phase 1 → Phase 2 → Phases 3, 4, 5 (the three stories are independent of each other) → Phase 6 → Phase 7.
- T018 depends on T015–T017 (the refusal paths must be understood before their messages are changed).
- T029 depends on every correction being in the tree; T030 depends on T029; T031 depends on T030.

## Parallel opportunities

- T002 and T003 after T001.
- Within Phase 3: T007, T008 and T013 are independent reads of different functions.
- Phases 3, 4 and 5 are independent of one another and can be verified in any order.
- T025 and T026 touch different files; T032 and T033 are independent.

## Implementation strategy

The MVP of this task list is Phase 2 plus Phase 3: if the foundational claims hold and User Story 1
is proven, the most dangerous defect class in the project — a machine running one generation's
schedule against another's files — is closed. Phases 4 and 5 are equally P1 by severity but do not
block it. Nothing is merged before Phase 6, because merging the delivery scaffolding is a decision
the owner has already made against.
