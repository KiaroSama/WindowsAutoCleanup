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

## Arming a guest (once, inside the VM, elevated)

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

The host driver, the guest agent, the scenarios and the refusals are implemented and the refusals are covered by `Tests/VmCampaign.Tests.ps1`. **The scenarios themselves have not yet been executed against an armed guest** — arming is the owner's step, and until a campaign has actually run, nothing in here is evidence about the product. That is the same rule the campaign applies to itself.
