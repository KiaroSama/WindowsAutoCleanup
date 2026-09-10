#Requires -Version 5.1
<#
.SYNOPSIS
    Real task registration, launch and removal under the live Windows scheduler: DISPOSABLE VM ONLY
    (ledger T-4 / T-5).

.DESCRIPTION
    This is the only part of the contract that cannot be proven with stubs: that the scheduler
    accepts what the installer builds, that a legacy registration can actually be replaced, and that
    Unregister-ScheduledTask plus the read-back really removes it.

    It is refused unless it is running elevated AND WAC_VM_TASK_LIFECYCLE is set to 1, and it must
    only ever be armed inside a disposable virtual machine. On this workstation the suite asserts
    the REFUSAL rather than skipping, because a skip proves nothing.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

# Set to 1 ONLY inside a disposable virtual machine. It arms the task-lifecycle checks, which
# register, start and unregister a REAL scheduled task under the live Windows scheduler. They are
# refused on any other machine, including this workstation, and the suite asserts that refusal
# instead of skipping - a skip proves nothing and would fail the run.
$script:VmLifecycleSwitch = 'WAC_VM_TASK_LIFECYCLE'

# ---------------------------------------------------------------------------------------------
# Real task registration, launch and removal: DISPOSABLE VM ONLY (ledger T-4 / T-5)
# ---------------------------------------------------------------------------------------------

function Invoke-VmTaskLifecycle {
    <#
    .SYNOPSIS
        Registers, starts and unregisters a REAL scheduled task, then proves it is gone.
    .DESCRIPTION
        This is the only part of the contract that cannot be proven with stubs: that the scheduler
        accepts what the installer builds, that a legacy registration can actually be replaced, and
        that Unregister-ScheduledTask plus the read-back really removes it.

        It is refused unless it is running elevated AND the opt-in environment variable is set, and
        it must only ever be armed inside a disposable virtual machine: it writes to the live Task
        Scheduler under a name of its own, and a mistake there is a mistake on a real machine. The
        suite asserts the refusal rather than skipping, because a skip proves nothing.
    .OUTPUTS
        Armed, Reason, Steps - Steps is empty whenever Armed is false.
    #>
    param([Parameter(Mandatory = $true)][string]$TaskName)

    $result = [PSCustomObject]@{ Armed = $false; Reason = $null; Steps = @() }

    if ([string]::Equals([string]$env:WAC_VM_TASK_LIFECYCLE, '1', [System.StringComparison]::Ordinal) -ne $true) {
        $result.Reason = ('{0} is not set to 1, so the live Task Scheduler was not touched.' -f $script:VmLifecycleSwitch)
        return $result
    }
    if (-not (Test-WacIsAdministrator)) {
        $result.Reason = 'Registering a SYSTEM task needs elevation; nothing was touched.'
        return $result
    }

    $steps = New-Object 'System.Collections.Generic.List[object]'
    $taskPath = '\WindowsAutoCleanupVmCheck\'
    $deploymentRoot = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)
    $runScript = Join-Path -Path $deploymentRoot -ChildPath 'Run.ps1'
    $taskHost = Get-WacCanonicalPowerShellHost

    Import-Module -Name 'ScheduledTasks' -ErrorAction Stop

    try {
        # 1. The pre-1.2 registration, with the PATH-resolved host that makes it dangerous, so the
        #    migration is exercised against the shape it actually has to recognise. This is the
        #    v1.1.0 body specifically - the one a machine being upgraded really carries, and the
        #    only one whose ':$true' suffix has to survive a real scheduler round trip.
        $legacyArguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Scheduled -ResetWindowsUpdateBase:$true' -f $runScript
        $legacy = New-ScheduledTask `
            -Action (New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument $legacyArguments) `
            -Trigger (New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddHours(3))) `
            -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
            -Description 'Runs WindowsAutoCleanup daily to silently remove explicitly allowed temporary files and cache locations from drive C:.'
        [void](Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -InputObject $legacy -ErrorAction Stop)

        $readLegacy = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
        $legacyProof = Test-WacTaskIsOurs -Task $readLegacy -DeploymentRoot $deploymentRoot -AllowLegacyMigration
        [void]$steps.Add([PSCustomObject]@{ Step = 'legacy recognised'; Ok = [bool]$legacyProof.IsLegacy; Detail = [string]$legacyProof.Reason })

        $legacyRemoval = Remove-WacInstalledTask -Task $readLegacy -DeploymentRoot $deploymentRoot -AllowLegacyMigration
        [void]$steps.Add([PSCustomObject]@{ Step = 'legacy removed'; Ok = [bool]$legacyRemoval.Verified; Detail = [string]$legacyRemoval.Reason })

        # 2. The current registration, read back, started for real, then removed and proven gone.
        $arguments = Get-WacTaskActionArgument -RunScript $runScript -ResetWindowsUpdateBase:$false
        $current = New-ScheduledTask `
            -Action (New-ScheduledTaskAction -Execute $taskHost -Argument $arguments -WorkingDirectory $deploymentRoot) `
            -Trigger (New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddHours(3))) `
            -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
            -Settings (New-ScheduledTaskSettingsSet -Compatibility Win8 -Hidden -StartWhenAvailable `
                -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 4)) `
            -Description (Get-WacTaskDescription)
        [void](Register-ScheduledTask -TaskName $TaskName -TaskPath $taskPath -InputObject $current -ErrorAction Stop)

        $readCurrent = Get-ScheduledTask -TaskName $TaskName -TaskPath $taskPath -ErrorAction Stop
        $proof = Test-WacTaskIsOurs -Task $readCurrent -DeploymentRoot $deploymentRoot
        [void]$steps.Add([PSCustomObject]@{ Step = 'current recognised'; Ok = [bool]$proof.IsOurs; Detail = [string]$proof.Reason })

        Start-ScheduledTask -TaskName $TaskName -TaskPath $taskPath -ErrorAction Stop
        $deadline = [datetime]::UtcNow.AddSeconds(120)
        $state = ''
        while ([datetime]::UtcNow -lt $deadline) {
            $state = [string](Get-ScheduledTask -TaskName $TaskName -TaskPath $taskPath -ErrorAction Stop).State
            if ($state -ne 'Running') { break }
            Start-Sleep -Milliseconds 250
        }
        $info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $taskPath -ErrorAction Stop
        [void]$steps.Add([PSCustomObject]@{ Step = 'started and finished'; Ok = ($state -ne 'Running'); Detail = ('state={0} lastResult={1}' -f $state, [string]$info.LastTaskResult) })

        $removal = Remove-WacInstalledTask -Task $readCurrent -DeploymentRoot $deploymentRoot
        [void]$steps.Add([PSCustomObject]@{ Step = 'current removed and verified absent'; Ok = [bool]$removal.Verified; Detail = [string]$removal.Reason })
    }
    finally {
        foreach ($path in @('\', $taskPath)) {
            try { Unregister-ScheduledTask -TaskName $TaskName -TaskPath $path -Confirm:$false -ErrorAction Stop } catch { $null = $_ }
        }
    }

    $result.Armed = $true
    $result.Steps = @($steps.ToArray())
    $result.Reason = 'The live task lifecycle ran.'
    return $result
}

Test-Case 'The live task-lifecycle check exists, is armed only in a disposable VM, and is refused here' {
    # T-4 / T-5. The check itself CANNOT run on this workstation - it registers, starts and removes
    # a real scheduled task - so what is proven here is that the code exists, that it refuses to run
    # unless explicitly armed, and that it touched nothing. On a disposable VM, set
    # WAC_VM_TASK_LIFECYCLE=1 and run this suite elevated; every step then has to report Ok.
    $name = 'WindowsAutoCleanupVmCheck_' + [guid]::NewGuid().ToString('N').Substring(0, 8)

    $before = @(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)
    Assert-Equal 0 $before.Count 'the probe name is already taken'

    $outcome = Invoke-VmTaskLifecycle -TaskName $name

    if (-not $outcome.Armed) {
        Assert-Equal 0 @($outcome.Steps).Count 'the lifecycle reported steps while refusing to run'
        Assert-True ($outcome.Reason -match ('{0}|elevation' -f $script:VmLifecycleSwitch)) ([string]$outcome.Reason)
        Assert-Equal 0 @(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue).Count `
            'the refused lifecycle registered something anyway'
        return
    }

    Assert-Equal 5 @($outcome.Steps).Count 'the armed lifecycle skipped one of its steps'
    foreach ($step in $outcome.Steps) {
        Assert-True ([bool]$step.Ok) ('{0}: {1}' -f $step.Step, [string]$step.Detail)
    }
    Assert-Equal 0 @(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue).Count `
        'the lifecycle left its probe task registered'
}

Test-Case 'the live VM action explicitly keeps ResetBase disabled' {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $PSCommandPath, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count 'the VM harness must parse'
    $calls = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -eq 'Get-WacTaskActionArgument'
            }, $true))
    Assert-Equal 1 $calls.Count 'the VM action builder changed; review the safety check'
    $runScript = 'C:\WacVerification\Run.ps1'
    # Execute only the harness's pure argument-builder expression, never its scheduler operations.
    $arguments = & ([scriptblock]::Create($calls[0].Extent.Text))
    Assert-True ($arguments.Contains($runScript)) 'the fixture script path was not used'
    Assert-True ($arguments.Contains('-ResetWindowsUpdateBase:$false')) `
        'the real VM task would execute the excluded ResetBase operation'
}

Complete-TestRun
