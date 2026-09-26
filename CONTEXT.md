# WindowsAutoCleanup

An administrator-only maintenance utility that removes allow-listed temporary data from drive `C:`
and runs supported Windows cleanup tools, either on demand or as an installed daily task. This file
is the project's glossary: the words the code, the tests and the reviews use, and the ones they avoid.

## Runs and their evidence

**Run**:
One invocation of the cleanup entry point, from its lock to its exit code, with one log and one
summary.
_Avoid_: job, session, execution (except in `executionId`)

**Mode**:
What kind of run a summary describes: `cleanup` (it may change the machine), `preview` (it reports
the selection and changes nothing), or `delegated` (it handed the work to an elevated relaunch and
did none itself).
_Avoid_: dry run, what-if

**Run summary**:
The versioned machine-readable record of one run's outcome, written once beside that run's log.
_Avoid_: report, result file, status file

**Step state**:
Whether a cleanup step started, stated for every step: `executed`, `refused` (it did not start
because the run declined it), `unarmed` (it did not start because it was not switched on), or
`unstated` (it said neither, and nobody guesses).
_Avoid_: skipped, disabled

**Refusal**:
A run or step that declined to act because a safety condition was not proven; a refusal is a
correct outcome, never an error to retry around.
_Avoid_: failure, abort

## Deployment

**Deployment**:
The verified copy of the utility that the scheduled task runs, separate from any source checkout.
_Avoid_: install folder, checkout

**Transaction record**:
A durable file beside the deployment that says an install or uninstall started and has not
finished, so a later run can recover it instead of guessing.
_Avoid_: journal (as a noun for one file), marker, lock file

**Uninstall intent**:
The transaction record an interrupted uninstall leaves behind; while it stands, no install may
resurrect what the uninstall was removing.
_Avoid_: pending uninstall

## The disposable-guest campaign

**Campaign**:
An opt-in run of real-machine scenarios inside a disposable virtual machine, for the things
continuous integration cannot do - lose power, restart, be dispatched by the scheduler.
_Avoid_: integration test, VM test

**Guest**:
The disposable virtual machine a campaign runs in, armed once by its owner.
_Avoid_: VM (in prose), test machine

**Agent**:
The campaign's program inside the guest; it runs the scenarios and publishes what it observes.
_Avoid_: bot, worker

**Baseline**:
The proven-clean machine state a campaign must start from - nothing installed and no transaction
record standing - or the campaign does not start.
_Avoid_: clean state, reset

**Beacon**:
A timestamped value the agent publishes for the host to read; it counts only when stamped after
the event being waited on, because a published value outlives the boot that wrote it.
_Avoid_: heartbeat (that is the hypervisor's), signal

**Cut**:
A deliberate hard power loss the host applies to the guest at the instant the agent asks for it.
_Avoid_: crash, shutdown, reboot

**Owned launch**:
A child process the campaign started inside its own job, so its whole tree can be ended and its
completion proven without touching anything the campaign did not start.
_Avoid_: spawned process, background process
