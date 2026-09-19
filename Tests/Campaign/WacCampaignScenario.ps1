<#
.SYNOPSIS
    The campaign scenarios. Each one performs something a continuous-integration runner structurally
    cannot, inside a disposable guest, and returns a verdict about what it actually observed.

.DESCRIPTION
    Every scenario returns Scenario, Verdict (`passed`, `failed` or `awaiting-power-cut`) and Detail.
    A scenario that could not reach its own precondition returns `failed` with the reason - never
    `passed` for want of a failure, which is the shape this project keeps finding and closing.

    The interrupted scenarios do not use a timer. The agent starts the real operation, watches for
    the record the product itself writes when it enters the transaction, and only then asks for the
    interruption. A cut on a stopwatch lands wherever the machine happened to be, which makes a pass
    unrepeatable and a failure undiagnosable.
#>

Set-StrictMode -Version 2.0

function Get-WacCampaignSummary {
    <#
    .SYNOPSIS
        The newest run summary a cleanup left behind, or $null.
    .DESCRIPTION
        The run's own machine-readable verdict is what the campaign reads, rather than re-deriving
        one from free disk space or a log scrape. It is the artifact a monitor would read, so a
        campaign that reads it is also testing the thing operators will depend on.
    #>
    param([string[]]$Directory = @("$env:ProgramData\WindowsAutoCleanup\Logs", "$env:SystemRoot\Logs\WindowsAutoCleanup"))

    $found = @()
    foreach ($candidate in $Directory) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { continue }
        $found += @(Get-ChildItem -LiteralPath $candidate -Filter '*.summary.json' -File -ErrorAction SilentlyContinue)
    }
    if ($found.Count -eq 0) { return $null }

    $newest = @($found | Sort-Object -Property LastWriteTimeUtc -Descending)[0]
    try { return ([System.IO.File]::ReadAllText($newest.FullName) | ConvertFrom-Json) }
    catch { return $null }
}

function Get-WacCampaignTail {
    <#
    .SYNOPSIS
        The last useful part of a captured stream, flattened to one line and bounded.
    .DESCRIPTION
        Bounded because it travels to the host through a key-value exchange that chunks by length,
        and the TAIL rather than the head because a refusal is the last thing an entry point says
        before it exits.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text, [int]$Max = 600)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '(it printed nothing)' }

    $flat = ($Text -replace '[\r\n\t ]+', ' ').Trim()
    if ($flat.Length -le $Max) { return $flat }
    return ('...' + $flat.Substring($flat.Length - $Max))
}

function Wait-WacCampaignFile {
    <#
    .SYNOPSIS
        Waits, bounded, for the product to create the record that marks the instant we want to
        interrupt. $true when it appeared.
    #>
    param([Parameter(Mandatory = $true)][string[]]$Path, [int]$TimeoutSeconds = 180)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        foreach ($candidate in $Path) {
            if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) { return $true }
        }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

function Suspend-WacCampaignTree {
    <#
    .SYNOPSIS
        Freezes a started process and everything it started, so the instant the power is cut at is
        the instant the guest chose rather than whenever the host got round to it.
    .DESCRIPTION
        THE RACE THIS EXISTS TO REMOVE. The guest reaches the transaction, asks the host to cut, and
        the host takes up to a poll interval to act - during which a short operation can FINISH. The
        first real campaign lost `power-loss-during-uninstall` exactly that way: nothing was
        interrupted, the installer correctly did not refuse, and the scenario proved nothing.

        A suspended process cannot write another byte, so the on-disk state stays exactly as the
        record left it for as long as the host needs. The parent is frozen FIRST so it cannot spawn
        a child that outlives the sweep, and the descendants are enumerated twice because one can be
        created between the parent's last instruction and its freeze.
    .OUTPUTS
        A result carrying Suspended (the ids frozen) and Detail.
    #>
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    if (-not ('WacCampaign.Nt' -as [type])) {
        Add-Type -Namespace 'WacCampaign' -Name 'Nt' -MemberDefinition @'
[DllImport("ntdll.dll", SetLastError = true)]
public static extern int NtSuspendProcess(System.IntPtr processHandle);
'@
    }

    $frozen = New-Object 'System.Collections.Generic.List[int]'
    $trouble = New-Object 'System.Collections.Generic.List[string]'

    $freeze = {
        param([int]$Id)
        try {
            $process = [System.Diagnostics.Process]::GetProcessById($Id)
            $status = [WacCampaign.Nt]::NtSuspendProcess($process.Handle)
            if ($status -eq 0) { [void]$frozen.Add($Id) }
            else { [void]$trouble.Add(('{0}: NtSuspendProcess returned 0x{1:X8}' -f $Id, $status)) }
        }
        catch { [void]$trouble.Add(('{0}: {1}' -f $Id, $_.Exception.Message)) }
    }

    & $freeze $ProcessId
    for ($pass = 0; $pass -lt 2; $pass++) {
        foreach ($child in @(Get-CimInstance Win32_Process -Filter ("ParentProcessId={0}" -f $ProcessId) -ErrorAction SilentlyContinue)) {
            if ($frozen -contains [int]$child.ProcessId) { continue }
            & $freeze ([int]$child.ProcessId)
        }
    }

    return [PSCustomObject]@{
        Suspended = @($frozen.ToArray())
        Detail = ('froze {0} process(es){1}' -f $frozen.Count,
            $(if ($trouble.Count -gt 0) { '; ' + ($trouble.ToArray() -join '; ') } else { '' }))
    }
}

function Stop-WacCampaignTree {
    <#
    .SYNOPSIS
        Terminates a started process and everything it started, and SAYS what happened.
    .DESCRIPTION
        The whole tree, because a killed parent leaves its dism.exe or cleanmgr.exe running inside a
        guest that is about to be checkpointed away with them. Windows PowerShell 5.1 has no
        entireProcessTree overload, so the fallback is the single process - which is worth reporting
        rather than swallowing, because the difference is exactly what leaks.
    #>
    param([Parameter(Mandatory = $true)]$Process)

    try {
        $Process.Kill($true)
        return 'the process tree was terminated'
    }
    catch {
        try {
            $Process.Kill()
            return ('only the parent process could be terminated (' + $_.Exception.Message + '); a child may still be running')
        }
        catch {
            return ('the process could not be terminated at all: ' + $_.Exception.Message)
        }
    }
}

function Invoke-WacCampaignHost {
    <#
    .SYNOPSIS
        Runs one of the project's own entry points and returns its exit code and output.
    .DESCRIPTION
        Started hidden with its streams captured. Nothing this agent runs ever draws a window: the
        guest is unattended by definition and a prompt in here is a hang nobody is watching.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSeconds = 2400,
        [switch]$PassThruProcess
    )

    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath) + @($ArgumentList)
    $outFile = [System.IO.Path]::GetTempFileName()
    $errFile = [System.IO.Path]::GetTempFileName()

    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -PassThru `
        -WindowStyle Hidden -RedirectStandardOutput $outFile -RedirectStandardError $errFile

    if ($PassThruProcess) {
        return [PSCustomObject]@{ Process = $process; OutFile = $outFile; ErrFile = $errFile; ExitCode = $null; Output = '' }
    }

    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $killed = Stop-WacCampaignTree -Process $process
        return [PSCustomObject]@{ ExitCode = -1
            Output = ('timed out after {0}s; {1}' -f $TimeoutSeconds, $killed) }
    }

    $output = ''
    foreach ($file in @($outFile, $errFile)) {
        try { $output += [System.IO.File]::ReadAllText($file) }
        catch { $output += ('[a captured stream could not be read: ' + $_.Exception.Message + ']') }
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    }
    return [PSCustomObject]@{ ExitCode = [int]$process.ExitCode; Output = $output }
}

function Invoke-WacCampaignMaintenance {
    <#
    .SYNOPSIS
        THE GAP THIS CAMPAIGN EXISTS TO CLOSE: the shipped scheduled task, dispatched by the Task
        Scheduler as SYSTEM, running a real cleanup to completion on a real Windows client.
    .DESCRIPTION
        The live lifecycle lane already proves the task can be registered, started and removed. It
        has never proved the CLEANUP runs - its task pointed at a deployment root that did not
        exist, so the scheduler started an action that failed on its working directory, and
        `lastResult=2147942667` is what that looks like.

        Here the installer really installs, so the action really exists, and the verdict is read
        from the run's own summary rather than from the scheduler's opinion of its exit code.
    #>
    param([Parameter(Mandatory = $true)][string]$ProjectRoot)

    $install = Invoke-WacCampaignHost -ScriptPath (Join-Path $ProjectRoot 'Install-WindowsAutoCleanupTask.ps1') `
        -ArgumentList @('-NoPause')
    if ($install.ExitCode -ne 0) {
        return [PSCustomObject]@{ Scenario = 'service-dispatched-maintenance'; Verdict = 'failed'
            Detail = ('the installer exited {0}; nothing downstream of it was tested. {1}' -f $install.ExitCode, $install.Output) }
    }

    $task = @(Get-ScheduledTask -TaskPath '\WindowsAutoCleanup\' -ErrorAction SilentlyContinue)
    if ($task.Count -ne 1) {
        # An exit code of 0 with nothing registered is a REFUSAL, and the refusal is in the output.
        # Reporting only the count leaves the one sentence that explains it on the floor - which is
        # exactly what the first real campaign run did.
        return [PSCustomObject]@{ Scenario = 'service-dispatched-maintenance'; Verdict = 'failed'
            Detail = ('the installer exited 0 but {0} task(s) are registered. It said: {1}' -f
                $task.Count, (Get-WacCampaignTail -Text $install.Output)) }
    }

    $before = Get-WacCampaignSummary
    $beforeId = if ($null -eq $before) { '' } else { [string]$before.executionId }

    Start-ScheduledTask -InputObject $task[0]

    # Two waits, in order: the scheduler must actually START the action before its result means
    # anything. 267011 is "task has not run"; reading it as a verdict is how a start that never
    # happened gets recorded as a finish.
    $deadline = (Get-Date).AddMinutes(45)
    $launched = $false
    while ((Get-Date) -lt $deadline) {
        $info = Get-ScheduledTaskInfo -InputObject $task[0]
        $state = [string](Get-ScheduledTask -TaskPath $task[0].TaskPath -TaskName $task[0].TaskName).State
        if ($state -ceq 'Running' -or [int]$info.LastTaskResult -ne 267011) { $launched = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $launched) {
        return [PSCustomObject]@{ Scenario = 'service-dispatched-maintenance'; Verdict = 'failed'
            Detail = 'the scheduler never started the action, so nothing about the cleanup was observed.' }
    }

    while ((Get-Date) -lt $deadline) {
        $state = [string](Get-ScheduledTask -TaskPath $task[0].TaskPath -TaskName $task[0].TaskName).State
        if ($state -cne 'Running') { break }
        Start-Sleep -Seconds 5
    }

    $info = Get-ScheduledTaskInfo -InputObject $task[0]
    $after = Get-WacCampaignSummary
    if ($null -eq $after -or [string]$after.executionId -ceq $beforeId) {
        return [PSCustomObject]@{ Scenario = 'service-dispatched-maintenance'; Verdict = 'failed'
            Detail = ('the task finished with lastResult={0} but wrote no new run summary, so no cleanup is proved.' -f $info.LastTaskResult) }
    }

    $uninstall = Invoke-WacCampaignHost -ScriptPath (Join-Path $ProjectRoot 'Uninstall-WindowsAutoCleanupTask.ps1') `
        -ArgumentList @('-NoPause')

    $verdict = if ([int]$info.LastTaskResult -eq 0 -and [string]$after.outcome -ceq 'Succeeded') { 'passed' } else { 'failed' }
    return [PSCustomObject]@{
        Scenario = 'service-dispatched-maintenance'; Verdict = $verdict
        Detail = ('lastResult={0} outcome={1} exitCode={2} removedEntries={3} removedBytes={4} uninstallExit={5}' -f
            $info.LastTaskResult, [string]$after.outcome, [int]$after.exitCode,
            [int]$after.removed.entries, [long]$after.removed.bytes, $uninstall.ExitCode)
    }
}

function Start-WacCampaignInterruption {
    <#
    .SYNOPSIS
        Starts a real transaction, waits for the product's own record of it, and then asks to be
        interrupted at that exact instant.
    .DESCRIPTION
        The record is what makes the instant reproducible. Saving the resume point BEFORE the
        interruption is requested is the whole contract: after the power goes there is nothing left
        but this file, and a resume point written afterwards is one that was never written.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [string[]]$ArgumentList = @(),
        [Parameter(Mandatory = $true)][string[]]$RecordPath,
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)][scriptblock]$Save,
        [string]$ResumeKind = 'power-cut'
    )

    $started = Invoke-WacCampaignHost -ScriptPath $ScriptPath -ArgumentList $ArgumentList -PassThruProcess
    if (-not (Wait-WacCampaignFile -Path $RecordPath -TimeoutSeconds 240)) {
        $killed = Stop-WacCampaignTree -Process $started.Process

        # WHICH record was missing, and what the operation said while not writing it. The first real
        # run reported only that no record appeared, which named neither the paths being watched nor
        # the refusal that explained them.
        $said = ''
        foreach ($capture in @($started.OutFile, $started.ErrFile)) {
            try { $said += [System.IO.File]::ReadAllText($capture) } catch { $said += '' }
        }

        return [PSCustomObject]@{ Scenario = $Scenario; Verdict = 'failed'
            Detail = ('the operation wrote none of [{0}], so there was no defined instant to interrupt. It said: {1} ({2})' -f
                ((@($RecordPath) | ForEach-Object { Split-Path -Leaf $_ }) -join ', '),
                (Get-WacCampaignTail -Text $said), $killed) }
    }

    # FREEZE FIRST, then record, then ask. In that order the on-disk state cannot move again: the
    # operation is stopped at the record, the resume point describes the state that will still be
    # there after the power goes, and the host may take as long as it likes to act.
    $held = Suspend-WacCampaignTree -ProcessId $started.Process.Id
    if (@($held.Suspended).Count -eq 0) {
        # Nothing was frozen, so the operation is still free to finish before the cut lands. That is
        # the racy scenario this replaced, and running it anyway would produce a pass or a fail that
        # means neither thing.
        [void](Stop-WacCampaignTree -Process $started.Process)
        return [PSCustomObject]@{ Scenario = $Scenario; Verdict = 'failed'
            Detail = ('the operation reached its record but could not be held there ({0}), so the cut would have been a race.' -f $held.Detail) }
    }

    $State.phase = 'awaiting-power-cut'
    $State.cutStep = $Scenario
    $State | Add-Member -NotePropertyName 'resumeKind' -NotePropertyValue $ResumeKind -Force
    $State | Add-Member -NotePropertyName 'cutHeld' -NotePropertyValue ([string]$held.Detail) -Force
    & $Save -Path $StatePath -State $State

    if ($ResumeKind -ceq 'reboot') {
        # A clean restart the guest performs itself. The restart proof reads a monotonic counter,
        # and only a real restart moves it - which is the entire point of doing this here.
        Restart-Computer -Force
        Start-Sleep -Seconds 120
    }

    return [PSCustomObject]@{ Scenario = $Scenario; Verdict = 'awaiting-power-cut'; Detail = 'the host was asked to interrupt' }
}

function Invoke-WacCampaignRecoveryCheck {
    <#
    .SYNOPSIS
        Runs after a real interruption: does the documented recovery path leave a coherent machine?
    .DESCRIPTION
        Re-running the installer IS the recovery path, and that is exactly why no separate
        "clear the record" command exists. What is asserted is the machine AFTERWARDS - the files,
        the registration and the records agreeing - not the verdict label the recovery printed.
    #>
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)][string]$ProjectRoot)

    $scenario = [string]$State.cutStep

    if ($scenario -ceq 'power-loss-during-uninstall') {
        # FIRST, before anything resolves the interrupted removal: an installer must refuse while
        # the intent stands, and FR-015 requires it to name the file that is blocking it.
        $premature = Invoke-WacCampaignHost -ScriptPath (Join-Path $ProjectRoot 'Install-WindowsAutoCleanupTask.ps1') -ArgumentList @('-NoPause')
        $refused = $premature.ExitCode -ne 0
        $named = $premature.Output -match '(?i)\.json|record|intent'

        $finish = Invoke-WacCampaignHost -ScriptPath (Join-Path $ProjectRoot 'Uninstall-WindowsAutoCleanupTask.ps1') -ArgumentList @('-NoPause')
        $tasks = @(Get-ScheduledTask -TaskPath '\WindowsAutoCleanup\' -ErrorAction SilentlyContinue)

        $verdict = if ($refused -and $named -and $finish.ExitCode -eq 0 -and $tasks.Count -eq 0) { 'passed' } else { 'failed' }
        return [PSCustomObject]@{ Scenario = $scenario; Verdict = $verdict
            Detail = ('installerRefused={0} refusalNamedTheRecord={1} uninstallExit={2} tasksRemaining={3}' -f
                $refused, $named, $finish.ExitCode, $tasks.Count) }
    }

    $recovery = Invoke-WacCampaignHost -ScriptPath (Join-Path $ProjectRoot 'Install-WindowsAutoCleanupTask.ps1') -ArgumentList @('-NoPause')
    $tasks = @(Get-ScheduledTask -TaskPath '\WindowsAutoCleanup\' -ErrorAction SilentlyContinue)
    $deploymentRoot = Join-Path -Path $env:ProgramFiles -ChildPath 'WindowsAutoCleanup'
    $runPresent = Test-Path -LiteralPath (Join-Path $deploymentRoot 'Run.ps1') -PathType Leaf

    # The pair is the claim: one generation's files under that same generation's registration. A
    # registered task pointing at files that are not there is the defect this scenario hunts.
    $coherent = ($recovery.ExitCode -eq 0) -and ($tasks.Count -eq 1) -and $runPresent
    return [PSCustomObject]@{ Scenario = $scenario; Verdict = $(if ($coherent) { 'passed' } else { 'failed' })
        Detail = ('recoveryExit={0} tasksRegistered={1} deployedRunPresent={2} resumeKind={3}' -f
            $recovery.ExitCode, $tasks.Count, $runPresent, [string]$State.resumeKind) }
}

function Invoke-WacCampaignScenario {
    <#
    .SYNOPSIS
        Dispatches one scenario by name.
    .DESCRIPTION
        The destructive pair is gated here as well as on the host, because the guest is the machine
        that would actually lose the drivers. An authorization that only existed on the host would
        be one delivered file away from not existing at all.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)][scriptblock]$Save
    )

    $projectRoot = [string]$State.projectRoot
    $installer = Join-Path $projectRoot 'Install-WindowsAutoCleanupTask.ps1'
    $uninstaller = Join-Path $projectRoot 'Uninstall-WindowsAutoCleanupTask.ps1'
    $run = Join-Path $projectRoot 'Run.ps1'

    # The durable records sit BESIDE the deployment root, never inside it, so no move or delete of a
    # slot carries them off. Those exact names are what marks the transaction instant to interrupt:
    # Get-WacDeploymentJournalPath builds them as <root>.transaction.json, .taskcapture.json and
    # .uninstall.json, and the driver backups live under ProgramData instead.
    $deploymentRoot = Join-Path -Path $env:ProgramFiles -ChildPath 'WindowsAutoCleanup'
    $swapRecord = $deploymentRoot + '.transaction.json'
    $captureRecord = $deploymentRoot + '.taskcapture.json'
    $uninstallRecord = $deploymentRoot + '.uninstall.json'
    $driverBackupRoot = Join-Path -Path $env:ProgramData -ChildPath 'WindowsAutoCleanup\DriverBackup'

    if (@('driver-prune', 'reset-base') -ccontains $Name -and -not [bool]$State.destructiveAuthorized) {
        return [PSCustomObject]@{ Scenario = $Name; Verdict = 'failed'
            Detail = 'the destructive scenarios were not authorized for this campaign, so this one did not run.' }
    }

    switch ($Name) {
        'service-dispatched-maintenance' { return (Invoke-WacCampaignMaintenance -ProjectRoot $projectRoot) }

        'power-loss-during-install' {
            return (Start-WacCampaignInterruption -Scenario $Name -ScriptPath $installer -ArgumentList @('-NoPause') `
                -RecordPath @($swapRecord, $captureRecord) `
                -State $State -StatePath $StatePath -Save $Save)
        }

        'power-loss-during-uninstall' {
            $prepare = Invoke-WacCampaignHost -ScriptPath $installer -ArgumentList @('-NoPause')
            if ($prepare.ExitCode -ne 0) {
                return [PSCustomObject]@{ Scenario = $Name; Verdict = 'failed'
                    Detail = ('nothing was installed to interrupt the removal of; installer exited {0}.' -f $prepare.ExitCode) }
            }
            return (Start-WacCampaignInterruption -Scenario $Name -ScriptPath $uninstaller -ArgumentList @('-NoPause') `
                -RecordPath @($uninstallRecord) `
                -State $State -StatePath $StatePath -Save $Save)
        }

        'reboot-recovery' {
            $prepare = Invoke-WacCampaignHost -ScriptPath $installer -ArgumentList @('-NoPause')
            if ($prepare.ExitCode -ne 0) {
                return [PSCustomObject]@{ Scenario = $Name; Verdict = 'failed'
                    Detail = ('nothing was installed to restart across; installer exited {0}.' -f $prepare.ExitCode) }
            }
            return (Start-WacCampaignInterruption -Scenario $Name -ScriptPath $installer -ArgumentList @('-NoPause') `
                -RecordPath @($swapRecord, $captureRecord) `
                -State $State -StatePath $StatePath -Save $Save -ResumeKind 'reboot')
        }

        'driver-prune' {
            $result = Invoke-WacCampaignHost -ScriptPath $run -ArgumentList @('-PruneSupersededDrivers', '-ResetWindowsUpdateBase:$false')
            $summary = Get-WacCampaignSummary
            $backup = @(Get-ChildItem -LiteralPath $driverBackupRoot -Recurse -Filter '*.inf' -File -ErrorAction SilentlyContinue)
            $step = if ($null -eq $summary) { $null } else { @(@($summary.steps) | Where-Object { [string]$_.category -match 'driver' }) }
            $verdict = if ($result.ExitCode -eq 0 -and $null -ne $step -and $step.Count -gt 0) { 'passed' } else { 'failed' }
            return [PSCustomObject]@{ Scenario = $Name; Verdict = $verdict
                Detail = ('exit={0} driverStepState={1} exportedInfFiles={2}' -f $result.ExitCode,
                    $(if ($null -ne $step -and $step.Count -gt 0) { [string]$step[0].state } else { 'absent' }), $backup.Count) }
        }

        'reset-base' {
            $result = Invoke-WacCampaignHost -ScriptPath $run -ArgumentList @('-ResetWindowsUpdateBase')
            $summary = Get-WacCampaignSummary
            $step = if ($null -eq $summary) { $null } else { @(@($summary.steps) | Where-Object { [string]$_.category -match 'DISM' }) }
            $verdict = if ($result.ExitCode -eq 0 -and $null -ne $step -and $step.Count -gt 0 -and [string]$step[0].state -ceq 'executed') { 'passed' } else { 'failed' }
            return [PSCustomObject]@{ Scenario = $Name; Verdict = $verdict
                Detail = ('exit={0} componentStoreStep={1}. Updates installed before this run can no longer be uninstalled on this guest.' -f
                    $result.ExitCode, $(if ($null -ne $step -and $step.Count -gt 0) { [string]$step[0].state } else { 'absent' })) }
        }

        default {
            return [PSCustomObject]@{ Scenario = $Name; Verdict = 'failed'; Detail = 'no such scenario' }
        }
    }
}
