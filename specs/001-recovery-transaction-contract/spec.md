# Feature Specification: Restartable installation, uninstall and abandonment transactions

**Feature directory**: `specs/001-recovery-transaction-contract`
**Created**: 2026-09-19
**Ledger**: WAC-02R, WAC-05R, WAC-06R
**Source**: external audit handoff `15.md`; the implementation under review is PR #1 on branch
`audit/review6-recovery-regressions`.

## Why this exists

This tool changes a machine while nobody is watching, with full privilege. Each of its three
mutating operations — installing, uninstalling, and running an external tool that may outlive the
process that started it — leaves evidence behind. The next process reads that evidence and decides
whether it may delete something.

Every defect in this scope has the same shape: a process left evidence that was *incomplete*, and a
later process read the gap as permission. The specification below is the contract that makes the gap
unreadable as permission.

## Clarifications

### Session 2026-09-19

- Q: When a machine is fenced by a record that was never retired, what way out does this feature owe
  the operator? → A: the message only. Every refusal caused by a stranded record names the exact file
  that is blocking and the manual step that clears it. No new recovery command is added in this scope.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - An upgrade is interrupted and the machine is put back whole (Priority: P1)

An operator upgrades the tool. The machine loses power, or the process is killed, at an arbitrary
point: before the swap, between the two directory moves, after the new registration but before the
commit, after the commit but before the evidence was retired. The operator re-runs the installer.

**Why this priority**: this is the only story in which the machine can be left executing one version's
schedule against another version's files. Nothing else in the tool can do that.

**Acceptance scenarios**

1. **Given** a committed installation A (files A, task A) and an upgrade to B killed before it
   committed, **When** any later process reconciles, **Then** the machine holds exactly files A and
   task A — not files A with task B, and not files B with task A.
2. **Given** a first install (there was no previous installation) killed after it registered its task,
   **When** recovery runs, **Then** both the new files and the new registration are removed together;
   a rollback that removes files and leaves the task is a failure.
3. **Given** a first install whose original deployment directory existed but was EMPTY, **When**
   recovery runs, **Then** the empty original is restored as an empty original and its absence of a
   task is recorded — an empty directory is neither "absent" nor "a substantive tree".
4. **Given** an installation that committed, **When** recovery runs, **Then** the replacement task is
   restored or verified — never the original task over the committed files.
5. **Given** any recovery, **When** it finishes, **Then** re-running it over the state it produced
   changes nothing and reports the same verdict.

### User Story 2 - An uninstall is interrupted and no later install resurrects it (Priority: P1)

An operator uninstalls. The process dies after the task is unregistered, or after the files are
removed, but before the leftover installation records are gone.

**Why this priority**: the leftover records describe an installation that the operator deliberately
removed. A later installer that reads them as "an interrupted installation" re-creates exactly what
the operator asked to be gone.

**Acceptance scenarios**

1. **Given** an uninstall interrupted at any point after it began, **When** a later installer or a
   scheduled cleanup run starts, **Then** it refuses while the uninstall intent stands, and says so.
2. **Given** an interrupted uninstall, **When** the operator re-runs the uninstaller, **Then** it
   resumes and completes, retiring the dependent records before the intent itself, last.
3. **Given** an uninstall whose intent record cannot be written, **When** it starts, **Then** no task
   and no file is removed.
4. **Given** an uninstall that refused to remove a registration it could not prove was ours, **When**
   it ends, **Then** the operator is told the machine is now fenced, which file fences it, and the
   manual step that clears it.

### User Story 3 - Incomplete evidence never becomes permission (Priority: P1)

A run starts an external tool, or an earlier run left a mutation nobody could prove had finished.

**Why this priority**: this is the difference between a cleanup that skipped a night and one that
deleted files under an authority that was never established.

**Acceptance scenarios**

1. **Given** an earlier run recorded an abandoned external mutation, **When** a later run starts,
   **Then** it mutates nothing until the machine is *proven* to have restarted since — and a wall
   clock moved forward is not that proof.
2. **Given** an uptime counter that is missing, unreadable, equal or larger than the recorded one,
   **When** a later run reads it, **Then** the outcome is inconclusive and the quarantine stands.
3. **Given** a tool result whose stated facts contradict each other, **When** a consumer reads it,
   **Then** it is refused rather than reconciled into permission.
4. **Given** a maintenance profile snapshot, **When** a later attempt runs, **Then** only a snapshot
   this attempt newly created licenses mutating the profile; a pre-existing record is preserved and
   the outcome is incomplete.

### Edge Cases

- A record path that is a directory, malformed, or unreadable is not an absence and is not permission.
- A registration standing at the captured name that is not the captured task is foreign: it is left
  alone and it blocks, rather than being overwritten.
- A recovery copy that is healthy, trusted and ours but was rewritten since it was set aside no
  longer answers to the record that describes it.
- Retirement of one record failing must not leave the other retired: each outcome has its own order,
  and the surviving record must always be the one a retry can act on.
- An operation whose budget is exhausted during preparation must not start the tool at all.
- A descendant still alive at the deadline must not inherit the exited root's success.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Recovery MUST treat an original deployment as exactly one of Absent, Empty, or
  Substantive, and MUST carry that distinction through planning, restoration and retirement.
- **FR-002**: Proven absence of an original MUST lead to restoring that absence, never to certifying
  a replacement. An unreadable or obstructed path MUST NOT be read as absence.
- **FR-003**: A generation is committed only when the process that verified BOTH the replacement
  files and the matching replacement registration wrote that decision down. A matching manifest, a
  missing recovery copy, or a registration existing under the expected name MUST NOT imply it.
- **FR-004**: A committed generation's recovery MUST restore or verify the REPLACEMENT registration;
  a rollback MUST restore the ORIGINAL. Neither may be substituted for the other.
- **FR-005**: The task half MUST be reconciled, and its acknowledgement made durable, before the file
  half acts.
- **FR-006**: Retirement order MUST differ by outcome — on rollback the swap record goes before the
  original capture; on commit the original capture goes before the commit decision — so that a crash
  at any point leaves a record a retry can still act on.
- **FR-007**: A failed retirement MUST propagate as a non-clean result and MUST preserve the evidence
  it could not retire. It MUST NOT be downgraded to a warning followed by success.
- **FR-008**: An uninstall MUST record a durable intent before removing anything, and MUST retire that
  intent last. Installation and ordinary cleanup MUST refuse while an intent stands.
- **FR-009**: Proof that the machine restarted MUST come from a monotonic counter that cannot move
  backwards with the civil clock. Missing, unreadable, equal or increased readings are inconclusive.
- **FR-010**: Work whose lifetime this process cannot bound MUST default to being treated as external;
  only demonstrably host-confined work may be treated as ending with its host.
- **FR-011**: A result MUST state whether the tool started, whether its termination was proven,
  whether its output was complete, and what became of its owned tree. A result missing or
  contradicting any of those MUST NOT authorize a mutation.
- **FR-012**: A maintenance profile snapshot MUST be owned by exactly one attempt: only a newly
  created snapshot licenses mutation, ownership is tracked separately from whether anything was
  written, and a failed restore keeps both recoverability and a non-clean outcome.
- **FR-013**: One operation MUST have one time budget covering preparation, execution and cleanup. No
  phase may renew it, and a tool MUST NOT be created or resumed once it is spent.
- **FR-014**: Every guarantee above MUST hold identically on Windows PowerShell 5.1 and PowerShell 7.
- **FR-015**: Every refusal caused by a record that was not retired MUST name the exact blocking file
  and the manual step that clears it. The operator MUST NOT have to infer which artifact fenced the
  machine. No automated clearing of an unresolved record is in scope.

### Key Entities

- **Swap record** — what a tree replacement was in the middle of: the original's state and content
  identity, the replacement's identity, and the commit decision with the replacement registration it
  was verified against.
- **Task capture record** — the exact definitions of registrations taken away, so a process that dies
  before restoring them leaves something that can.
- **Uninstall intent record** — that a removal began; retired last, and refused past by everything
  else while it stands.
- **Quarantine record** — that a mutation was abandoned, with the monotonic reading that a later
  process compares against to decide whether the machine has restarted since.
- **Generation** — the identity binding the records of one operation together, so two records found
  side by side are known to be two halves of one thing rather than debris from two.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Terminating a fresh process at each transition — before and after each unregister,
  register, journal write, directory move, verification, commit and record retirement — and then
  recovering in a NEW process leaves a coherent pair every time, with no duplicate registration, no
  wrong-generation files and no stranded record.
- **SC-002**: A recovery that has already succeeded is recognised on a second run: the same state
  yields the same verdict and no further change.
- **SC-003**: No sequence of interruptions during an uninstall results in a later install
  re-creating the removed registration.
- **SC-004**: Every acceptance scenario has a test that fails when the behaviour it names is removed
  from the source, with the failure landing on the assertion rather than on an unrelated error.
- **SC-005**: The whole suite passes on both Windows baselines and both PowerShell hosts, and the
  live install/run/upgrade/uninstall lifecycle passes against the real scheduler on a disposable
  guest.
- **SC-006**: No test writes machine-scoped state, and no run leaves a process behind.

## Assumptions

- Crash and retry coverage uses real files, real sharing violations, real journals and fresh
  processes, with a persistent substitute for the scheduler; the real scheduler is exercised only in
  the separately armed lifecycle lane on a disposable guest. Physical power loss is not simulated.
- The reviewed baseline is `main` at `4be74c8`; the implementation under verification is PR #1.
- Safety boundaries recorded in the project constitution are unchanged by this work: no ACL or owner
  rewriting, no broad recursive fallback, no reboot deletion queue, no forced driver removal, no
  forced reboot, no termination of unrelated processes, and no silent change to destructive defaults.
