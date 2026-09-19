#Requires -Version 5.1
<#
.SYNOPSIS
    The explicitly gated disposable-VM lane: install, scheduled run, upgrade, failure rollback,
    uninstall, and a second install that must be idempotent.

.DESCRIPTION
    This is the one lane that runs the REAL entry points against the REAL machine: it deploys to the
    real deployment root and registers a real SYSTEM task with the real Task Scheduler. It is
    therefore refused unless BOTH are true - WAC_VM_DEPLOYMENT_LIFECYCLE is set to 1 and the session
    is elevated - and it is meant only for a disposable Windows guest with a checkpoint taken first.
    On a workstation or an ordinary CI runner it reports refused and touches nothing, which is a
    pass: a guard test refusing a live action is not an executed lifecycle test, and this file says
    which of the two it performed.

    ResetBase stays disabled throughout and is asserted, not assumed. Driver pruning and legacy Disk
    Cleanup are left at their defaults, so nothing here deletes a driver package or sweeps every
    drive; the machine-mutating maintenance scenarios keep their own separate lane.

    VmTaskLifecycle.Tests.ps1 is the sibling lane and stays separate on purpose: that one proves the
    scheduler round trip for a task shape (including the pre-1.2 legacy body), this one proves the
    DEPLOYMENT lifecycle around it. Running them in one file would make a failure in either half
    unattributable.

    Every step returns Ok plus a Detail string, and the assertions read the step table rather than
    re-deriving state, so a failure names the phase that broke.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

$script:LifecycleSwitch = 'WAC_VM_DEPLOYMENT_LIFECYCLE'

function New-LifecycleStep {
    param(
        [Parameter(Mandatory = $true)][string]$Step,
        [Parameter(Mandatory = $true)][bool]$Ok,
        [AllowEmptyString()][string]$Detail = ''
    )
    return [PSCustomObject]@{ Step = $Step; Ok = $Ok; Detail = $Detail }
}

function Test-LifecycleScheduledCompletion {
    <#
    .SYNOPSIS
        Accepts a witnessed completed application run, never a scheduler launch error.
    #>
    param(
        [bool]$Launched,
        [AllowEmptyString()][string]$State,
        [AllowNull()]$LastTaskResult
    )
    $code = 0L
    if (-not [long]::TryParse([string]$LastTaskResult, [ref]$code)) { return $false }
    # Run.ps1 declares 0..7. HRESULTs, scheduler status codes and a missing task are not its exits.
    return ($Launched -and $State -ceq 'Ready' -and $code -ge 0 -and $code -le 7)
}

function Get-LifecycleMarkerRelativePath { return 'src\VM_UPGRADE_MARKER.txt' }

function Test-LifecycleUpgradeMarker {
    <#
    .SYNOPSIS
        Checks the actual deployed payload, independently of a manifest timestamp changing.
    #>
    param([string]$SourceRoot, [string]$DeploymentRoot)
    $relative = Get-LifecycleMarkerRelativePath
    try {
        $source = [System.IO.File]::ReadAllBytes((Join-Path $SourceRoot $relative))
        $deployed = [System.IO.File]::ReadAllBytes((Join-Path $DeploymentRoot $relative))
        return ($source.Length -gt 0 -and
            [Convert]::ToBase64String($source) -ceq [Convert]::ToBase64String($deployed))
    }
    catch { return $false }
}

function Invoke-LifecycleScript {
    <#
    .SYNOPSIS
        Runs the installer or uninstaller as a child and returns its exit code and output.
    .DESCRIPTION
        The real entry point, not the functions behind it: an installer that works only when driven
        function-by-function is not an installer anybody can run. Ownership comes from the project's
        own runner, so a hung installer is terminated with its whole tree rather than abandoned.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [hashtable]$BooleanSwitch = @{},
        [AllowEmptyCollection()][string[]]$PresentSwitch = @(),
        [int]$TimeoutMs = 300000
    )

    # -Command, built by the project's OWN Get-WacRelaunchCommand, and that is not a style choice.
    # With -File every token after the script path is a literal STRING, and Windows PowerShell 5.1
    # refuses to convert one into a SwitchParameter - so '-ResetWindowsUpdateBase:$false' arrives as
    # the six characters "$false" and the installer dies binding its parameters. The guest runs 5.1
    # only, so the first armed run failed exactly there: exit 1, nothing deployed, and every later
    # step failing for a reason that was not its own. The repository already documents this trap in
    # Get-WacRelaunchArgument; using the builder keeps the lane on the same side of it.
    $host51 = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $command = Get-WacRelaunchCommand -ScriptPath $ScriptPath -BooleanSwitch $BooleanSwitch -PresentSwitch $PresentSwitch
    $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', $command)
    return (Invoke-WacProcess -FilePath $host51 -ArgumentList $arguments -TimeoutMs $TimeoutMs -Component 'VmLifecycle')
}

function Get-WacVmDeploymentOutcome {
    <#
    .SYNOPSIS
        The whole gated sequence. Armed is $false, and Steps empty, unless the lane is authorised.
    .OUTPUTS
        Armed, Reason, Steps.
    #>
    $result = [PSCustomObject]@{ Armed = $false; Reason = $null; Steps = @() }

    if ([string]::Equals([string]$env:WAC_VM_DEPLOYMENT_LIFECYCLE, '1', [System.StringComparison]::Ordinal) -ne $true) {
        $result.Reason = ('{0} is not set to 1, so no deployment or task was touched.' -f $script:LifecycleSwitch)
        return $result
    }
    if (-not (Test-WacIsAdministrator)) {
        $result.Reason = 'Installing a SYSTEM task and writing the deployment root need elevation; nothing was touched.'
        return $result
    }

    $steps = New-Object 'System.Collections.Generic.List[object]'
    $installer = Join-Path -Path $script:RepoRoot -ChildPath 'Install-WindowsAutoCleanupTask.ps1'
    $uninstaller = Join-Path -Path $script:RepoRoot -ChildPath 'Uninstall-WindowsAutoCleanupTask.ps1'
    $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)
    # ResetBase disabled explicitly, as a BOOLEAN switch rather than a present one: the bare switch
    # defaults to $true in this installer, so only the valued form turns it off.
    $safeBoolean = @{ ResetWindowsUpdateBase = $false }
    $safePresent = @('NoPause')

    try {
      try {
        # 1. INSTALL. Exit code, deployment health and task ownership are three separate claims.
        $install = Invoke-LifecycleScript -ScriptPath $installer -BooleanSwitch $safeBoolean -PresentSwitch $safePresent
        [void]$steps.Add((New-LifecycleStep -Step 'install exits clean' -Ok ([int]$install.ExitCode -eq 0) `
            -Detail ('exit={0} timedOut={1} owned={2} err={3}' -f [string]$install.ExitCode, $install.TimedOut, $install.Owned, ([string]$install.StandardError).Trim())))

        $owned = Get-WacDeploymentOwnership -DeploymentRoot $root
        [void]$steps.Add((New-LifecycleStep -Step 'deployment is healthy' -Ok ([bool]$owned.IsHealthy) -Detail ([string]$owned.Reason)))

        $firstPrint = Get-WacDeploymentFingerprint -DeploymentRoot $root
        [void]$steps.Add((New-LifecycleStep -Step 'deployment fingerprint is complete' -Ok ([bool]$firstPrint.Complete) `
            -Detail ('fingerprint={0}' -f [string]$firstPrint.Fingerprint)))

        # Get-WacInstalledTask is TERNARY - State (Found|Absent|Failed), Task (an array of the ones
        # positively found) and Failure - not the task itself. Reading .Actions straight off it threw
        # under Set-StrictMode, which is how the first guest run died at step 4 with every earlier
        # step lost.
        $lookup = Get-WacInstalledTask
        $task = @($lookup.Task)[0]
        [void]$steps.Add((New-LifecycleStep -Step 'task lookup answered Found' -Ok ([string]$lookup.State -ceq 'Found') `
            -Detail ('state={0} count={1}' -f [string]$lookup.State, @($lookup.Task).Count)))
        $proof = $null
        if ($task) { $proof = Test-WacTaskIsOurs -Task $task -DeploymentRoot $root }
        [void]$steps.Add((New-LifecycleStep -Step 'task registered and recognised' -Ok ([bool]($proof -and $proof.IsOurs)) `
            -Detail $(if ($proof) { [string]$proof.Reason } else { 'no task was found after the install' }))))

        # ResetBase is asserted from the registered action, which is the only place it could reach
        # the machine from.
        $action = ''
        if ($task) { $action = [string]@($task.Actions)[0].Arguments }
        [void]$steps.Add((New-LifecycleStep -Step 'ResetBase stays disabled' -Ok ($action -match '(?i)-ResetWindowsUpdateBase:\$false' -and $action -notmatch '(?i)-ResetWindowsUpdateBase:\$true') `
            -Detail $action)))

        # 2. SCHEDULED RUN. Started for real through the scheduler, under SYSTEM.
        if ($task) {
            $beforeStart = Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop
            Start-ScheduledTask -InputObject $task -ErrorAction Stop

            # A stale LastTaskResult does not witness THIS start. Observe Running or a new run time.
            $launched = $false
            $launchWatch = [System.Diagnostics.Stopwatch]::StartNew()
            while ($launchWatch.Elapsed.TotalMinutes -lt 2) {
                $current = @((Get-WacInstalledTask).Task)[0]
                if (-not $current) { break }
                $probe = Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop
                if (([string]$current.State -ceq 'Running') -or
                    ($probe.LastRunTime -gt $beforeStart.LastRunTime)) { $launched = $true; break }
                Start-Sleep -Milliseconds 250
            }
            $launchWatch.Stop()

            $finishWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $state = 'Running'
            while ($finishWatch.Elapsed.TotalMinutes -lt 6) {
                $current = @((Get-WacInstalledTask).Task)[0]
                if (-not $current) { $state = 'Gone'; break }
                $state = [string]$current.State
                if ($state -ne 'Running') { break }
                Start-Sleep -Milliseconds 500
            }
            $finishWatch.Stop()
            $info = Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop
            # Application exits are 0..7; 267011 and HRESULTs are not proof that Run.ps1 executed.
            [void]$steps.Add((New-LifecycleStep -Step 'scheduled run finishes' -Ok ($state -ceq 'Ready') `
                -Detail ('state={0} lastResult={1}' -f $state, [string]$info.LastTaskResult)))
            $completed = Test-LifecycleScheduledCompletion -Launched $launched -State $state -LastTaskResult $info.LastTaskResult
            [void]$steps.Add((New-LifecycleStep -Step 'scheduled run actually launched' -Ok $completed `
                -Detail ('launched={0} lastResult={1} (application exit required)' -f $launched, [string]$info.LastTaskResult)))
        }

        # 3. SECOND INSTALL - idempotence. A healthy reinstall must stay healthy and must not leave a
        #    recovery slot behind: a .previous that survives a committed install is the shape that
        #    later gets promoted over a good deployment.
        $again = Invoke-LifecycleScript -ScriptPath $installer -BooleanSwitch $safeBoolean -PresentSwitch $safePresent
        $ownedAgain = Get-WacDeploymentOwnership -DeploymentRoot $root
        [void]$steps.Add((New-LifecycleStep -Step 'second install is clean and idempotent' `
            -Ok (([int]$again.ExitCode -eq 0) -and [bool]$ownedAgain.IsHealthy) `
            -Detail ('exit={0} health={1}' -f [string]$again.ExitCode, [string]$ownedAgain.Reason))))

        $slots = Get-WacDeploymentSlotPath -DeploymentRoot $root
        [void]$steps.Add((New-LifecycleStep -Step 'no recovery slot survives a committed install' `
            -Ok (-not (Test-Path -LiteralPath $slots.Previous)) -Detail ([string]$slots.Previous))))

        # 4. UPGRADE. The source is changed so the staged tree really differs, which is what makes
        #    the swap a swap rather than a copy over itself.
        $marker = Join-Path -Path $script:RepoRoot -ChildPath (Get-LifecycleMarkerRelativePath)
        $markerCreated = $false
        $upgraded = $false
        try {
            if (Test-Path -LiteralPath $marker) { throw 'The upgrade probe name already exists; it was not overwritten.' }
            $markerCreated = $true
            Set-Content -LiteralPath $marker -Value ('vm upgrade probe {0}' -f ([guid]::NewGuid())) -Encoding ASCII
            $upgrade = Invoke-LifecycleScript -ScriptPath $installer -BooleanSwitch $safeBoolean -PresentSwitch $safePresent
            $upgraded = ([int]$upgrade.ExitCode -eq 0)
            $secondPrint = Get-WacDeploymentFingerprint -DeploymentRoot $root
            $ownedUpgrade = Get-WacDeploymentOwnership -DeploymentRoot $root
            $markerMatches = Test-LifecycleUpgradeMarker -SourceRoot $script:RepoRoot -DeploymentRoot $root
            [void]$steps.Add((New-LifecycleStep -Step 'upgrade replaces the deployment and stays healthy' `
                -Ok ($markerMatches -and $upgraded -and [bool]$ownedUpgrade.IsHealthy -and ([string]$secondPrint.Fingerprint -ne [string]$firstPrint.Fingerprint)) `
                -Detail ('exit={0} before={1} after={2} health={3} payloadMatches={4}' -f [string]$upgrade.ExitCode, [string]$firstPrint.Fingerprint, [string]$secondPrint.Fingerprint, [string]$ownedUpgrade.Reason, $markerMatches)))
        }
        finally {
            if ($markerCreated -and (Test-Path -LiteralPath $marker)) { Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue }
        }

        # 5. FAILURE ROLLBACK, against the real root rather than a fixture. A tampered live
        #    deployment plus a good recovery slot is the one shape where guessing costs the operator
        #    both copies, so recovery must refuse and leave both exactly as found.
        $slots = Get-WacDeploymentSlotPath -DeploymentRoot $root
        $runScript = Join-Path -Path $root -ChildPath 'Run.ps1'
        $original = [System.IO.File]::ReadAllBytes($runScript)
        try {
            [void](Copy-WacDeploymentTree -Source $root -Destination $slots.Previous)
            Add-Content -LiteralPath $runScript -Value '# tampered by the VM lane' -Encoding ASCII

            $tampered = Get-WacDeploymentOwnership -DeploymentRoot $root
            [void]$steps.Add((New-LifecycleStep -Step 'a tampered deployment is ours but NOT healthy' `
                -Ok ([bool]$tampered.IsOurs -and -not [bool]$tampered.IsHealthy) -Detail ([string]$tampered.Reason))))

            # Resolve-WacDeploymentRecoverySlot is INTERNAL to the module, so it is called through
            # the module's own scope. Calling it by bare name threw "the term is not recognized" -
            # which an "it threw, so it refused" assertion happily read as a pass. A throw is only
            # a refusal when it is the REFUSAL, so the message is matched too.
            $refused = $false
            $reason = ''
            $deployModule = Get-Module -Name 'WindowsAutoCleanup.Deploy'
            try { [void](& $deployModule { param($s) Resolve-WacDeploymentRecoverySlot -Slots $s } $slots) }
            catch { $refused = $true; $reason = [string]$_.Exception.Message }

            $isRefusal = ($refused -and $reason -match 'recovery slot' -and $reason -match 'neither was touched|could not be put back')
            [void]$steps.Add((New-LifecycleStep -Step 'recovery refuses to guess and keeps both copies' `
                -Ok ($isRefusal -and (Test-Path -LiteralPath $slots.Previous) -and (Test-Path -LiteralPath $runScript)) `
                -Detail $reason)))
        }
        finally {
            [System.IO.File]::WriteAllBytes($runScript, $original)
            if (Test-Path -LiteralPath $slots.Previous) {
                Remove-Item -LiteralPath $slots.Previous -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        # 6. UNINSTALL. Both halves proven gone, not merely "the command exited 0".
        $removal = Invoke-LifecycleScript -ScriptPath $uninstaller -PresentSwitch @('NoPause', 'KeepLogs')
        [void]$steps.Add((New-LifecycleStep -Step 'uninstall exits clean' -Ok ([int]$removal.ExitCode -eq 0) `
            -Detail ('exit={0}' -f [string]$removal.ExitCode)))
        $afterRemoval = Get-WacInstalledTask
        [void]$steps.Add((New-LifecycleStep -Step 'task is gone' -Ok ([string]$afterRemoval.State -ceq 'Absent') `
            -Detail ('state={0}' -f [string]$afterRemoval.State)))
        [void]$steps.Add((New-LifecycleStep -Step 'deployment root is gone' -Ok (-not (Test-Path -LiteralPath $root)) -Detail $root))
      }
      catch {
          # A throw here used to take every step gathered so far with it, leaving a one-line
          # exception and no idea which phase had already passed. The steps ARE the evidence.
          [void]$steps.Add((New-LifecycleStep -Step 'the sequence threw' -Ok $false -Detail ([string]$_.Exception.Message)))
      }
    }
    finally {
        # The guest is disposable and restored from a checkpoint, but a lane that leaves a SYSTEM
        # task registered after a mid-sequence failure would poison the next attempt in the same
        # guest. Best effort, never destructive beyond what this lane itself created.
        try {
            $leftover = @((Get-WacInstalledTask -IncludeLegacy).Task)
            foreach ($stale in $leftover) {
                [void](Remove-WacInstalledTask -Task $stale -DeploymentRoot (Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)) -AllowLegacyMigration)
            }
        }
        catch { $null = $_ }
    }

    $result.Armed = $true
    $result.Steps = @($steps.ToArray())
    $result.Reason = 'The live deployment lifecycle ran.'
    return $result
}

Test-Case 'the deployment lifecycle lane is armed only in a disposable VM, and every step passes when it runs' {
    # Two outcomes, both legitimate, and the case says which it produced. On a workstation or an
    # ordinary runner it must REFUSE - and a refusal is not evidence that the lifecycle works, which
    # is why the armed branch asserts every step individually.
    $outcome = Get-WacVmDeploymentOutcome

    if (-not $outcome.Armed) {
        Write-Host ('    (not armed: {0})' -f $outcome.Reason)
        Assert-Equal 0 (@($outcome.Steps).Count) 'a refused lane still reported steps, so something was touched'
        Assert-True ($outcome.Reason -match ('{0}|elevation' -f $script:LifecycleSwitch)) ([string]$outcome.Reason)
        return
    }

    # PRINTED FIRST, always. Asserting the count before printing threw away the only record of how
    # far the sequence got - which is the same mistake the runner made with its captures.
    foreach ($step in @($outcome.Steps)) {
        Write-Host ('    {0}  {1}  {2}' -f $(if ($step.Ok) { 'ok  ' } else { 'FAIL' }), $step.Step, $step.Detail)
    }

    Assert-True (@($outcome.Steps).Count -ge 12) `
        ('the armed lane reported only {0} step(s), so it did not reach the end of the sequence' -f @($outcome.Steps).Count)

    $failed = @($outcome.Steps | Where-Object { -not $_.Ok })
    Assert-Equal 0 $failed.Count `
        (('these lifecycle steps failed: ' + (@($failed | ForEach-Object { '{0} ({1})' -f $_.Step, $_.Detail }) -join ' | ')))
}

Complete-TestRun
