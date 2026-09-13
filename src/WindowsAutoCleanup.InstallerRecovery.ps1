<#
.SYNOPSIS
    The scheduled-task capture transaction: opening it before the unregister that makes a machine
    lose a registration, and reconciling one an earlier process left open.

.DESCRIPTION
    Dot-sourced by Install-WindowsAutoCleanupTask.ps1 into that script's own scope, beside
    WindowsAutoCleanup.InstallerTask.ps1, and used by nothing else. Split out of that file because
    it had reached the size at which nobody reads it and because these two functions are one
    responsibility: the transaction that starts when a registration is removed to make room, and
    ends when a registration stands in its place again.

    Ledger WAC-02R. The old shape kept every captured definition ONLY on the in-memory result, so a
    process killed between the unregister and the next durable write left a machine with no
    registration and nothing on disk that said one had ever existed. The rollback that would have
    put it back died with the process. What fixes that is the ORDER: the capture is made durable
    BEFORE the unregister, and the unregister does not happen when it could not be made durable.

    Write-InstallerMessage, Restore-CapturedTask and the module functions these call live in the
    host script and in the modules it imports. PowerShell resolves a command when it is CALLED, not
    when it is defined, and nothing here runs before Invoke-Main, so the load order is no constraint.
#>

Set-StrictMode -Version 2.0

function Resolve-ConflictingTask {
    <#
    .SYNOPSIS
        Clears our own registration - current or pre-1.2 - before re-registering, refuses to touch
        anyone else's, and hands back the exact definition of everything it removed.
    .DESCRIPTION
        Register-ScheduledTask -Force is documented only as "without prompting for confirmation";
        nothing says it overwrites. So the installer explicitly Gets, proves ownership, then
        Unregisters (ledger P0-4).

        Ledger B2-3: a foreign task at EITHER path is a REFUSAL rather than a warning-and-carry-on,
        because the pre-1.2 task ran a PATH-resolved host as SYSTEM and leaving an unrecognised one
        registered while adding a second one beside it is how a machine ends up running two cleanup
        tasks, one of them the vulnerable one. A lookup that FAILED is fatal too, and separately: a
        scheduler that will not answer is not evidence that nothing is registered.

        -RequireDefinitionCapture, and the captured definitions back on the result: this removal is
        one step of an upgrade, so it has to be undoable. Undo-Installation puts them back.

        -OnCaptured is what makes that undoable across the death of THIS PROCESS (ledger WAC-02R).
        The callback appends the new capture to the durable record and answers whether the record
        landed; the removal proceeds only on $true. The record therefore names every task removed so
        far before any of them is unregistered, and a write that fails costs the upgrade rather than
        the machine's registration. It is rewritten per task rather than once up front because the
        capture only exists after the export, and a record naming the LAST removal alone would
        strand the ones before it.

        Called BEFORE anything is switched into the live deployment root, and with the machine-wide
        lock already held, so no cleanup run can start out of the tree between here and the swap.
    .OUTPUTS
        Ok, Refused, Reason, Captured.
    #>
    param([Parameter(Mandatory = $true)][string]$DeploymentRoot)

    $captured = New-Object 'System.Collections.Generic.List[object]'
    $result = [PSCustomObject]@{ Ok = $true; Refused = $false; Reason = $null; Captured = @() }

    $discovery = Get-WacInstalledTask -IncludeLegacy
    if ($discovery.State -eq 'Failed') {
        $result.Ok = $false
        $result.Reason = ('The Task Scheduler could not be queried, so whether a task is already registered is unknown: {0}' -f
            ((@($discovery.Failure | ForEach-Object { '{0}: {1}' -f $_.TaskPath, $_.Reason })) -join '; '))
        return $result
    }

    # The list, not the removal result, is what the record is built from: it accumulates across the
    # loop, so each write names every task this run has captured rather than only the current one.
    $recorded = New-Object 'System.Collections.Generic.List[object]'
    $onCaptured = {
        param($capture)
        [void]$recorded.Add($capture)
        return (Write-WacTaskCaptureRecord -DeploymentRoot $DeploymentRoot -Capture @($recorded.ToArray()))
    }.GetNewClosure()

    foreach ($existing in @($discovery.Task)) {
        $label = '{0}{1}' -f [string]$existing.TaskPath, [string]$existing.TaskName

        $removal = Remove-WacInstalledTask -Task $existing -DeploymentRoot $DeploymentRoot -AllowLegacyMigration -RequireDefinitionCapture -OnCaptured $onCaptured

        # A removal the durability gate refused returned BEFORE the unregister, so this task never
        # left the machine and putting it back would rewrite a live registration nobody asked to
        # change. Every other captured removal goes on the list, including one whose unregister
        # threw: that one may have taken effect anyway, and re-registering what is already there is
        # the safe half of that uncertainty.
        $keptByGate = ($null -ne $removal.CaptureDurable -and -not [bool]$removal.CaptureDurable)
        if ($removal.Captured -and -not $keptByGate) { [void]$captured.Add($removal) }
        $result.Captured = @($captured.ToArray())

        if ($removal.Verified) {
            Write-InstallerMessage -Level INFO -Message 'Removed the previously registered WindowsAutoCleanup task and kept its definition for a rollback.' -Data @{
                task = $label; reason = [string]$removal.Reason
            }
            continue
        }

        $result.Ok = $false

        if ($removal.Removed) {
            $result.Reason = ('The task at {0} was unregistered but its removal could not be verified: {1}' -f $label, [string]$removal.Reason)
            return $result
        }

        # Its own answer, ahead of the two below: the task is ours and the unregister never ran,
        # because this run could not first record what it was about to remove. Reporting that as a
        # failed unregister would name the wrong step and send the operator to the scheduler.
        if ($keptByGate) {
            $result.Reason = ('The task at {0} was left registered and nothing was changed: {1}' -f $label, [string]$removal.Reason)
            return $result
        }

        if ($removal.Captured) {
            # The capture only happens after the ownership proof, so this task IS ours and the
            # unregister itself is what failed. Not a refusal: nothing was left in place by choice.
            $result.Reason = ('Our task at {0} could not be unregistered: {1}' -f $label, [string]$removal.Reason)
            return $result
        }

        # Nothing removed and nothing captured: the task is not ours, or its definition could not be
        # captured and removing it would not have been undoable. Both left it exactly as found.
        $result.Refused = $true
        $result.Reason = ('The task at {0} was left untouched and nothing was registered beside it: {1}' -f $label, [string]$removal.Reason)
        return $result
    }

    return $result
}

function Complete-TaskCaptureTransaction {
    <#
    .SYNOPSIS
        Puts back everything this run captured and ends the durable record, on a path that stops
        before a replacement registration ever exists.
    .DESCRIPTION
        The record exists to survive this process, so it is deleted only once the thing it describes
        has stopped being true: every task this run removed is registered again. A restoration that
        could not be PROVEN keeps it, because the record is then the only thing on the machine that
        says which registration is missing and what its definition was - and the next run reconciles
        from exactly that.
    .OUTPUTS
        [bool] $true only when every captured task was put back and the record was ended.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$DeploymentRoot,
        [AllowNull()][AllowEmptyCollection()][object[]]$CapturedTask = @()
    )

    $ok = $true
    foreach ($definition in @($CapturedTask)) {
        if (-not (Restore-CapturedTask -Definition $definition)) { $ok = $false }
    }

    if (-not $ok) {
        Write-InstallerMessage -Level CRITICAL -Message 'A task this run removed could not be put back, so its durable capture record was KEPT for the next run to reconcile from.' -Data @{
            root = $DeploymentRoot; record = [string](Get-WacDeploymentJournalPath -DeploymentRoot $DeploymentRoot -Kind 'TaskCapture')
        }
        return $false
    }

    return ([bool](Remove-WacTaskCaptureRecord -DeploymentRoot $DeploymentRoot))
}

function Resolve-InterruptedTaskCapture {
    <#
    .SYNOPSIS
        Puts back a registration an earlier run removed and never replaced, BEFORE this run stages
        anything. Ok is $false when that could not be finished, and then nothing may proceed.
    .DESCRIPTION
        Ledger WAC-02R. A capture record left on disk means exactly one thing: this machine may be
        missing a task whose exact definition is in that record. It is reconciled first because
        staging deletes slots and the swap replaces the tree the missing task would have run, and
        neither should happen over a state nobody has accounted for.

        Per captured task, two cases and no guessing between them. A task that IS registered was
        never lost - the run that removed it got far enough to put one back, or this record is the
        debris of a run that committed - so nothing is done to it. A task that is NOT registered is
        re-registered from the record and read back through the same proof a rollback uses, which
        compares what came back against the captured definition rather than merely finding something
        under that name.

        The record is cleared only once EVERY task it names is accounted for. A reconciliation that
        could not finish keeps it and refuses the install: leaving the record is what gives the next
        run - or a human - the definitions, and proceeding would bury the question under a new
        deployment.
    .OUTPUTS
        Ok, Restored, Accounted, Recorded, Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$DeploymentRoot,
        [Parameter(Mandatory = $true)]$Lookup
    )

    $result = [PSCustomObject]@{
        Ok = $true; Restored = 0; Accounted = 0; Recorded = 0
        Reason = 'No interrupted task capture was recorded.'
    }

    $record = Read-WacTaskCaptureRecord -DeploymentRoot $DeploymentRoot

    # UNKNOWN IS NOT ABSENT, the same rule the swap record follows: a torn, foreign or unparsable
    # record means a task may have been removed and its shape cannot be read, and installing over
    # that is how the one piece of evidence about a missing registration gets buried.
    if ([string]$record.State -ceq 'Unreadable') {
        $result.Ok = $false
        $result.Reason = ('A task-capture record from an earlier run is present but could not be read, so whether this machine is missing a scheduled task is unknown: {0}' -f [string]$record.Reason)
        return $result
    }
    if ([string]$record.State -cne 'Valid') { return $result }

    $result.Recorded = @($record.Capture).Count
    if ($result.Recorded -eq 0) {
        # A valid record naming nothing describes no missing task, so it is debris rather than a
        # transaction. Clearing it is the whole reconciliation.
        [void](Remove-WacTaskCaptureRecord -DeploymentRoot $DeploymentRoot)
        $result.Reason = 'A task-capture record from an earlier run named no task and was cleared.'
        return $result
    }

    # Ternary, like every other lookup in this project: a scheduler that will not answer is not a
    # machine with nothing registered, and re-registering on that answer could put a second task
    # beside one nobody could see.
    if ([string]$Lookup.State -ceq 'Failed') {
        $result.Ok = $false
        $result.Reason = 'A task-capture record from an earlier run is present and the Task Scheduler could not be queried, so whether the task it names is still registered is unknown.'
        return $result
    }

    $registered = @(@($Lookup.Task) | ForEach-Object { '{0}{1}' -f [string]$_.TaskPath, [string]$_.TaskName })

    foreach ($capture in @($record.Capture)) {
        $label = '{0}{1}' -f [string]$capture.TaskPath, [string]$capture.TaskName

        # ORDINAL, not -ieq: this decides whether a registration is missing.
        $present = @(@($registered) | Where-Object {
            [string]::Equals($_, $label, [System.StringComparison]::OrdinalIgnoreCase)
        }).Count -gt 0

        if ($present) {
            $result.Accounted = [int]$result.Accounted + 1
            continue
        }

        Write-InstallerMessage -Level WARNING -Message 'An earlier run removed a scheduled task and was interrupted before it registered a replacement; putting it back from the durable record.' -Data @{
            task = $label; recordedAt = [string]$record.Reason
        }

        if (Restore-CapturedTask -Definition $capture) {
            $result.Restored = [int]$result.Restored + 1
            $result.Accounted = [int]$result.Accounted + 1
        }
        else {
            $result.Ok = $false
        }
    }

    if (-not $result.Ok) {
        $result.Reason = ('{0} of {1} recorded task(s) could not be accounted for, so the record was kept and nothing was staged over an unknown state.' -f
            ([int]$result.Recorded - [int]$result.Accounted), [int]$result.Recorded)
        return $result
    }

    [void](Remove-WacTaskCaptureRecord -DeploymentRoot $DeploymentRoot)
    $result.Reason = ('{0} recorded task(s) accounted for, {1} of them re-registered from the durable record.' -f
        [int]$result.Accounted, [int]$result.Restored)

    if ([int]$result.Restored -gt 0) {
        Write-InstallerMessage -Level WARNING -Message 'A scheduled task lost to an interrupted run was put back before this run staged anything.' -Data @{
            root = $DeploymentRoot; restored = [int]$result.Restored; accounted = [int]$result.Accounted
        }
    }
    return $result
}
