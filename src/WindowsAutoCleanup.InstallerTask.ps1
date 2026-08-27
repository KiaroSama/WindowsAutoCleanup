<#
.SYNOPSIS
    The installer's scheduled-task lifecycle: the trigger it builds, the conflicting registration it
    clears, the read-back that proves what landed, and the rollback that puts both the tree and the
    task back.

.DESCRIPTION
    Dot-sourced by Install-WindowsAutoCleanupTask.ps1 into that script's own scope, and used by
    nothing else. It is not part of the Deploy module: a module can only hand a script what it
    EXPORTS, and the Deploy package's export list is fixed. Split out of the installer by
    responsibility - the entry point keeps its console and log plumbing, its elevation wrapper and
    its orchestration, and this file keeps everything that decides what happens to the registered
    task.

    Write-InstallerMessage and the module functions these call live in the host script and in the
    modules it imports. PowerShell resolves a command when it is CALLED, not when it is defined, and
    nothing here runs before Invoke-Main, so the load order is not a constraint.
#>

Set-StrictMode -Version 2.0

function Get-InstallerTaskTrigger {
    param([Parameter(Mandatory = $true)][string]$RunTime)

    $parsed = $null
    try {
        $parsed = [datetime]::ParseExact($RunTime, 'HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        throw ("Invalid DailyRunTime '{0}'. Use 24-hour HH:mm, for example '03:00'." -f $RunTime)
    }

    return (New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.Add($parsed.TimeOfDay)))
}

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

    foreach ($existing in @($discovery.Task)) {
        $label = '{0}{1}' -f [string]$existing.TaskPath, [string]$existing.TaskName

        $removal = Remove-WacInstalledTask -Task $existing -DeploymentRoot $DeploymentRoot -AllowLegacyMigration -RequireDefinitionCapture
        if ($removal.Captured) { [void]$captured.Add($removal) }
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

function Restore-CapturedTask {
    <#
    .SYNOPSIS
        Re-registers one task definition Resolve-ConflictingTask captured, and reads it back.
    .OUTPUTS
        [bool] $true only when the task is registered again AND the scheduler confirms it.
    #>
    param([Parameter(Mandatory = $true)]$Definition)

    $label = '{0}{1}' -f [string]$Definition.TaskPath, [string]$Definition.TaskName
    $xml = [string]$Definition.Definition

    if (-not $Definition.Captured -or [string]::IsNullOrWhiteSpace($xml)) {
        Write-InstallerMessage -Level CRITICAL -Message 'Rollback has no captured definition for a task this run removed, so it cannot be put back.' -Data @{
            task = $label; reason = [string]$Definition.CaptureReason
        }
        return $false
    }

    try {
        Register-ScheduledTask -TaskName $Definition.TaskName -TaskPath $Definition.TaskPath -Xml $xml -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Write-InstallerMessage -Level CRITICAL -Message 'Rollback could not re-register the task this run removed; re-create it by hand.' -Data @{
            task = $label; error = $_.Exception.Message
        }
        return $false
    }

    $lookup = Get-WacInstalledTask -IncludeLegacy
    $back = @(@($lookup.Task) | Where-Object { ('{0}{1}' -f [string]$_.TaskPath, [string]$_.TaskName) -ieq $label })
    if ($lookup.State -eq 'Failed' -or $back.Count -ne 1) {
        Write-InstallerMessage -Level CRITICAL -Message 'Rollback re-registered the task this run removed but could not read it back, so its restoration is unproven.' -Data @{
            task = $label; state = [string]$lookup.State
        }
        return $false
    }

    Write-InstallerMessage -Level WARNING -Message 'Rollback: the task this run removed was re-registered and verified.' -Data @{ task = $label }
    return $true
}

function Undo-Installation {
    <#
    .SYNOPSIS
        Puts the machine back the way it was after a failure anywhere between the swap and the final
        assertion. Returns $true only when that is PROVEN.
    .DESCRIPTION
        Order matters, and so does refusing. The task this run registered is removed FIRST, through
        the same ownership proof. If that removal cannot be VERIFIED - refused, failed, or a
        scheduler that will not answer - the deployment is KEPT and this returns false: a
        registration that may still point into the tree makes deleting the tree strictly worse than
        leaving it, and a same-name task nobody could identify is never "clean".

        Only once nothing can reach the tree is the deployment restored, and only after THAT are the
        definitions Resolve-ConflictingTask captured re-registered - the task it removed pointed
        into the tree that has just been put back.
    .OUTPUTS
        [bool] $true only when the task state and the deployment were both restored and verified.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$DeploymentRoot,
        [AllowNull()][AllowEmptyCollection()][object[]]$CapturedTask = @()
    )

    $lookup = Get-WacInstalledTask
    if ($lookup.State -eq 'Failed') {
        Write-InstallerMessage -Level CRITICAL -Message 'Rollback stopped: the Task Scheduler could not be queried, so the deployment was KEPT because a task may still reference it. Remove the task and the deployment by hand.' -Data @{
            root = $DeploymentRoot
            findings = ((@($lookup.Failure | ForEach-Object { '{0}: {1}' -f $_.TaskPath, $_.Reason })) -join '; ')
        }
        return $false
    }

    foreach ($task in @($lookup.Task)) {
        $removal = Remove-WacInstalledTask -Task $task -DeploymentRoot $DeploymentRoot
        if ($removal.Verified) {
            Write-InstallerMessage -Level WARNING -Message 'Rollback: the task registered by this run was unregistered and verified absent.' -Data @{
                task = ('{0}{1}' -f $removal.TaskPath, $removal.TaskName)
            }
            continue
        }

        Write-InstallerMessage -Level CRITICAL -Message 'Rollback could not verify removal of the task at this path, so the deployment it may reference was KEPT. Remove both by hand.' -Data @{
            task = ('{0}{1}' -f $removal.TaskPath, $removal.TaskName); reason = [string]$removal.Reason; root = $DeploymentRoot
        }
        return $false
    }

    $restored = Restore-WacDeploymentPrevious
    if ($restored.Restored) {
        Write-InstallerMessage -Level WARNING -Message 'Rollback: the deployment was restored to its previous state.' -Data @{
            hadPrevious = [bool]$restored.HadPrevious; reason = [string]$restored.Reason
        }
    }
    else {
        Write-InstallerMessage -Level CRITICAL -Message 'Rollback could not restore the previous deployment.' -Data @{ reason = [string]$restored.Reason }
    }

    $ok = [bool]$restored.Restored
    foreach ($definition in @($CapturedTask)) {
        if (-not (Restore-CapturedTask -Definition $definition)) { $ok = $false }
    }

    return $ok
}

function Assert-RegisteredTask {
    <#
    .SYNOPSIS
        Reads the task back and proves every setting the installer asked for actually landed.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ExpectedHost,
        [Parameter(Mandatory = $true)][string]$ExpectedArguments,
        [Parameter(Mandatory = $true)][string]$ExpectedDescription,
        [Parameter(Mandatory = $true)][string]$ExpectedWorkingDirectory,
        [Parameter(Mandatory = $true)][string]$ExpectedRunTime
    )

    # Through the ternary lookup, so a read-back that FAILED - a scheduler that stopped answering
    # between the registration and here - cannot be mistaken for a task that is simply absent.
    $lookup = Get-WacInstalledTask
    if ($lookup.State -ne 'Found') {
        throw ("The task was registered without error but the scheduler does not report it registered (state {0}): {1}" -f
            [string]$lookup.State, ((@($lookup.Failure | ForEach-Object { $_.Reason })) -join '; '))
    }
    $task = @($lookup.Task)[0]

    $actions = @($task.Actions)
    if ($actions.Count -ne 1) {
        throw ("The registered task has {0} actions instead of exactly one." -f $actions.Count)
    }
    $action = $actions[0]

    $checks = @(
        @{ Name = 'Hidden'; Actual = [string][bool]$task.Settings.Hidden; Expected = 'True' }
        @{ Name = 'RunLevel'; Actual = [string]$task.Principal.RunLevel; Expected = 'Highest' }
        @{ Name = 'LogonType'; Actual = [string]$task.Principal.LogonType; Expected = 'ServiceAccount' }
        @{ Name = 'Compatibility'; Actual = [string]$task.Settings.Compatibility; Expected = 'Win8' }
        @{ Name = 'MultipleInstances'; Actual = [string]$task.Settings.MultipleInstances; Expected = 'IgnoreNew' }
        @{ Name = 'StartWhenAvailable'; Actual = [string][bool]$task.Settings.StartWhenAvailable; Expected = 'True' }
        @{ Name = 'Execute'; Actual = [string]$action.Execute; Expected = $ExpectedHost }
        @{ Name = 'Arguments'; Actual = [string]$action.Arguments; Expected = $ExpectedArguments }
        @{ Name = 'Description'; Actual = [string]$task.Description; Expected = $ExpectedDescription }
    )

    foreach ($check in $checks) {
        if (-not [string]::Equals([string]$check.Actual, [string]$check.Expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ("The registered task's {0} is '{1}' instead of '{2}'." -f $check.Name, $check.Actual, $check.Expected)
        }
    }

    # Compared through the canonicaliser rather than as raw text: the scheduler is free to hand a
    # directory back with a trailing separator, and a plain string compare would fail an install
    # that is in fact exactly right.
    $actualWorking = Get-WacNormalizedPath -Path ([string]$action.WorkingDirectory)
    $expectedWorking = Get-WacNormalizedPath -Path $ExpectedWorkingDirectory
    if (-not $actualWorking -or -not $expectedWorking -or ($actualWorking -ine $expectedWorking)) {
        throw ("The registered task's WorkingDirectory is '{0}' instead of '{1}'." -f [string]$action.WorkingDirectory, $ExpectedWorkingDirectory)
    }

    # UserId reads back as the account name on some builds and as the SID on others.
    $userId = [string]$task.Principal.UserId
    if ($userId -notmatch '(?i)^(SYSTEM|NT AUTHORITY\\SYSTEM|S-1-5-18)$') {
        throw ("The registered task runs as '{0}' instead of SYSTEM." -f $userId)
    }

    # ExecutionTimeLimit comes back as an ISO 8601 duration string, not a TimeSpan.
    $limit = [string]$task.Settings.ExecutionTimeLimit
    $limitSpan = [timespan]::Zero
    try { $limitSpan = [System.Xml.XmlConvert]::ToTimeSpan($limit) } catch { $limitSpan = [timespan]::Zero }
    if ($limitSpan -ne (New-TimeSpan -Hours 4)) {
        throw ("The registered task's ExecutionTimeLimit is '{0}' instead of 4 hours." -f $limit)
    }

    # The trigger is asserted too (ledger B2-3): a task registered with the wrong or an extra
    # trigger runs the cleanup at a time the operator never asked for, and until now nothing read
    # it back. StartBoundary is an ISO 8601 LOCAL datetime string, not a DateTime.
    $triggers = @($task.Triggers)
    if ($triggers.Count -ne 1) {
        throw ("The registered task has {0} triggers instead of exactly one daily trigger." -f $triggers.Count)
    }
    $triggerKind = ''
    try { $triggerKind = [string]$triggers[0].CimClass.CimClassName } catch { $triggerKind = '' }
    if ($triggerKind -and $triggerKind -notmatch '(?i)Daily') {
        throw ("The registered task's trigger is '{0}' instead of a daily trigger." -f $triggerKind)
    }
    # Unspecified, and it matters. Measured on both shipped hosts: given '...T20:00:00' the reading
    # is 20:00, and given an offset form such as '...T20:00:00+02:00' it converts to the equivalent
    # LOCAL time - which is the time the task will actually fire, and therefore the one to compare
    # against what the operator asked for. Do not "fix" this to RoundtripKind.
    $startBoundary = [string]$triggers[0].StartBoundary
    $startAt = [datetime]::MinValue
    try { $startAt = [System.Xml.XmlConvert]::ToDateTime($startBoundary, [System.Xml.XmlDateTimeSerializationMode]::Unspecified) }
    catch { throw ("The registered task's StartBoundary '{0}' is not a datetime." -f $startBoundary) }
    $actualRunTime = $startAt.ToString('HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    if (-not [string]::Equals($actualRunTime, $ExpectedRunTime, [System.StringComparison]::Ordinal)) {
        throw ("The registered task runs daily at '{0}' instead of '{1}'." -f $actualRunTime, $ExpectedRunTime)
    }

    $ownership = Test-WacTaskIsOurs -Task $task -DeploymentRoot $ExpectedWorkingDirectory
    if (-not $ownership.IsOurs) {
        throw ("The registered task does not pass its own ownership proof: {0}" -f $ownership.Reason)
    }

    return $task
}
