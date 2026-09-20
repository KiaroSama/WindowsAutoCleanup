# The disposable-VM campaign

A protected, opt-in campaign that runs the scenarios continuous integration **structurally cannot**, inside a virtual machine you are willing to throw away.

## What CI already covers, and what it cannot

A GitHub-hosted runner is a disposable, elevated, explicitly armed Windows machine, and this project already uses it for everything it can honestly cover: every suite on both shipped hosts, the analyzer, the repository hygiene gates, and a live deployment-lifecycle lane that registers, starts and removes the real scheduled task.

Four things it cannot do, at all:

| | Why a runner cannot | What the campaign does |
| --- | --- | --- |
| A real power cut mid-transaction | A runner cannot lose power on cue. A simulated interruption proves the code path, never the state the transaction left the machine in. | `Stop-VM -TurnOff` at an instant **the guest itself asks for**, then start it again and verify recovery |
| A real restart | The restart proof reads a monotonic native counter; only an actual reboot moves it, and a test that fakes the counter proves arithmetic | `reboot-recovery` restarts the guest for real, across an open transaction |
| Service-dispatched maintenance | The live lane's task pointed at a deployment root that did not exist, so the scheduler started an action that failed on its working directory. **The cleanup itself has never run end to end in a guest.** | `service-dispatched-maintenance` installs for real, lets the Task Scheduler dispatch it as SYSTEM, and reads the run's own `.summary.json` |
| A representative Windows 11 client | Real drivers, a real component store, a real profile | The guest is one |

**Nothing here reinterprets CI as having performed any of it.** A scenario that did not run is reported in the report's own `notRun` list, never omitted into looking like a pass.

## The credential boundary, which is also the protection

The host never asks for, accepts, stores or logs a guest credential. It has exactly two channels:

- **host to guest** — `Copy-VMFile`, over the Guest Service Interface. Delivers files. **Cannot start anything.**
- **guest to host** — Key-Value Pair Exchange. The guest writes its own values under `HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest`; the host reads them off the running machine's KVP component. No logon, no share, no port.

Because neither channel can run code in the guest, a campaign requires a guest that was armed **once, deliberately, by its owner**. That is what makes this opt-in structural rather than a flag somebody can set by accident.

## Arming a guest

**A guest that has the agent arms itself.** On every clean boot the agent waits for WMI, registers
its own scheduled task through `Register-WacCampaignAgent.ps1`, and removes whatever weaker start
path brought it up, so one durable path remains. It reports the result to the host as
`AgentArming = task-registered+gp-removed`, then `task-already-present` on later boots. Nothing has
to be typed in the guest for a machine that is already running the agent.

### The first arming, inside the VM, elevated

A guest with no agent at all still needs one deliberate act by its owner - the host can deliver files
and read what the guest publishes, but it cannot start anything in there:


**This step cannot be done from the host, and that is not a gap in the tooling.** Every credential-free
route from outside the guest is a technique in its own right: reaching into the offline disk to write
a startup entry in the registry is how credentials are extracted offline, and writing a boot-time
script into the guest's local Group Policy is persistence. Both were tried from the host here and both
were refused by the platform, correctly. The one remaining route, PowerShell Direct, requires guest
credentials by design. So arming is a deliberate act performed by the person who owns the machine —
which is exactly the property that makes a campaign opt-in.


1. Copy this `Tests/Campaign` folder into the guest.
2. Run, elevated, in the guest:

```bash
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Register-WacCampaignAgent.ps1
```

It refuses to arm anything that looks like physical hardware, registers one SYSTEM scheduled task that starts the agent at every boot — which is how the agent comes back after a scenario cuts the power — and publishes a probe value to the host.

3. Back on the **host**, confirm the return channel before trusting it:

```bash
. .\Tests\Campaign\WacCampaignChannel.ps1
(Read-WacCampaignReport -VMName 'Test VM')['ArmingProbe']
```

It must print the timestamp the arming step showed. If it prints nothing, the guest has no way to report results and no campaign should be run until that is fixed.

Disarm with `-Unregister`.

## Running a campaign (on the host)

```bash
$env:WAC_VM_CAMPAIGN = '1'
pwsh -NoProfile -File .\Tests\Campaign\Invoke-WacVmCampaign.ps1 -VMName 'Test VM'
```

The driver takes a checkpoint **before** anything is delivered, stages the project from committed `HEAD` (never the working tree — evidence bound to uncommitted edits is bound to no reviewable state), runs the scenarios, restores the checkpoint, and leaves the machine **off**, verified.

| Exit | Meaning |
| --- | --- |
| 0 | every requested scenario ran and passed |
| 1 | the campaign ran and something failed — read the report |
| 2 | refused: not armed, or a destructive scenario without its own authorization |
| 3 | blocked: it did not run. **Not evidence about the product.** |

### Scenarios

`service-dispatched-maintenance`, `power-loss-during-install`, `power-loss-during-uninstall` and `reboot-recovery` run by default.

`driver-prune` and `reset-base` are **destructive** and gated twice, on the host and again in the guest:

```bash
$env:WAC_VM_CAMPAIGN = '1'
$env:WAC_VM_CAMPAIGN_DESTRUCTIVE = '1'
pwsh -NoProfile -File .\Tests\Campaign\Invoke-WacVmCampaign.ps1 -VMName 'Test VM' -Scenario reset-base -AllowDestructive
```

`reset-base` permanently removes the ability to uninstall updates installed before the run, and `driver-prune` removes superseded driver packages. Both are isolated by the checkpoint the driver takes, and `-AllowDestructive` never implies `WAC_VM_CAMPAIGN_DESTRUCTIVE` or the other way round: one authorizes driving a guest, the other authorizes what may happen inside it.

## How an interruption is timed

Not on a stopwatch. The agent starts the real operation, waits for the record the **product itself** writes when it enters the transaction — `<deployment root>.transaction.json`, `.taskcapture.json` or `.uninstall.json`, which live beside the root so no move or delete carries them off — and only then asks the host to cut the power. A cut on a timer lands wherever the machine happened to be, which makes a pass unrepeatable and a failure undiagnosable.

The resume point is written to disk **before** the cut is requested. After the power goes there is nothing left but that file, and a resume point written afterwards is one that was never written.

## Status

**The campaign has run for real** on a Hyper-V Windows 11 guest, repeatedly on 2026-09-19 and
2026-09-20. Two scenarios pass; two are blocked by something now identified.

| scenario | verdict | evidence |
| --- | --- | --- |
| `service-dispatched-maintenance` | **passed** (twice) | the Task Scheduler dispatched the installed action as SYSTEM and the cleanup ran to completion: `lastResult=0`, outcome `Succeeded`, 203 and 204 entries / 13.4 and 14.8 MB actually removed, read from the run's own `.summary.json` |
| `reboot-recovery` | **passed** (twice) | a REAL restart across an open transaction; recovery left the files, the registration and the records agreeing |
| `power-loss-during-install` | no trustworthy verdict | the harness between the cut and the verdict had to be repaired six times; campaign-to-campaign isolation is still open |
| `power-loss-during-uninstall` | the same | the product's FR-015 fence WAS seen working after a real cut - see below |

### Two product findings were filed from these scenarios and both were RETRACTED

On 2026-09-20 the first complete run produced `recoveryExit=0 tasksRegistered=0` and
`installerRefused=False`, and those were published as two product defects. Both were wrong:

- The "recovery that succeeded without registering" was a **crash**, on
  `src/WindowsAutoCleanup.TrustedStore.ps1:1 char:1` - a file whose first bytes never reached the
  disk, because the campaign extracts the project and the very next thing the scenario does is cut
  the power. The product was running from a half-written copy of itself.
- The "fence that did not engage" **did** engage, word for word as FR-015 requires: *Refusing to
  install: An uninstall intent is outstanding or unreadable. Resume the uninstaller; no task or
  deployment was resurrected.* It returned 1; the campaign read 0.

Both misreadings share one cause. `Invoke-WacCampaignHost` never touched the child's `.Handle`
before it exited, and under Windows PowerShell 5.1 - which is what the guest agent runs - that
returns an empty exit code. Measured here with a child that definitely exits 1:

```text
Windows PowerShell 5.1   no handle read -> ExitCode=(empty)    handle touched -> ExitCode=1
PowerShell 7             both shapes    -> ExitCode=1
```

**The standing lesson: a red test is a claim about the system under test only once the harness
between them is known good.** Six harness defects were removed before these scenarios said anything
about the product at all - a sticky beacon read as a fresh signal (twice), two files documented as
flushed that were not, the exit code above, and a killed run's state inherited by the next campaign.
Full list and evidence: `.ai/BUGS.md`.

### What is still open

Isolation between SCENARIOS works: one guest boot each, base checkpoint restored between them.
Isolation between CAMPAIGNS is now handled in code but **not yet proven on the guest**. The driver
takes its base checkpoint at campaign start, so residue from a previous run sat inside the baseline
every scenario was returned to. The agent now brings the machine back to a clean state before any
scenario runs - using the product's own uninstaller, which is the documented way to resolve an
outstanding intent - then reads the machine AGAIN and **refuses the entire campaign** if it still is
not clean. The verdict comes from looking, never from an exit code, and the post-cut resume path
never resets, because there the machine's state is the evidence. It publishes
`Baseline = clean | polluted` so the host can see which happened.

Unit-tested and mutation-proved; the live run to confirm it has not completed. Until it has, neither
cut scenario has a verdict worth quoting.

### Reading a silent guest, so the next run is not wasted

| what the host sees after the cut | what it means |
| --- | --- |
| heartbeat never returns, `MemoryAssigned` stuck at the floor | the HOST starved the guest. No evidence about the product, the campaign or the arming. |
| heartbeat OK, memory assigned, no `AgentBoot` | nothing started inside the guest. That is a real finding about the arming. |

Do not wait for an idle host, which is a condition nobody can prove. Give the guest **static** memory
for the run: Hyper-V must then commit the whole allocation at start, so either the guest holds all of
it or `Start-VM` fails immediately and says so. Note that restoring a checkpoint also restores the
memory configuration recorded in it.

A task-armed guest does come back from a hard cut - **13 to 20 seconds**, measured repeatedly - and
the Group Policy arming it replaced did not. That much is settled.
