<#
.SYNOPSIS
    The sandboxed Run.ps1 rig: a byte-for-byte copy of the shipped script, a src\ of shim modules
    driven by one JSON plan, and the helpers that build it, run it and read its log.

.DESCRIPTION
    Dot-sourced by RunExitCode.Tests.ps1. It is not a suite: its name does not match
    Tests\*.Tests.ps1, so the runner never executes it on its own.

    The suite must set $script:RepoRoot, $script:SrcRoot and $script:RunPath, and dot-source
    _RunProbe.ps1, before dot-sourcing this file.
#>

# ---------------------------------------------------------------------------------------------
# The exit-code contract, end to end through the REAL Run.ps1
#
# Run.ps1 is COPIED byte for byte into a sandbox that also holds a src\ of shim modules, and the
# copy is the file the child executes. Each shim is the shipped module text with a few overrides
# appended, so New-WacTreeResult, New-WacStepResult, New-WacDriverStepResult, Write-WacTreeResult
# and Write-WacStepResult stay the SHIPPED code and only the functions that would touch the machine
# - the sweep, DISM, pnpclean, pnputil, cleanmgr, the Recycle Bin - return a scripted result
# instead. Nothing here deletes anything, runs a system tool or reads the real allow-list, which is
# what makes it safe to run on a developer workstation.
#
# Three environmental facts a sandboxed run cannot have are replaced in the Core shim and nothing
# else is: Test-WacIsAdministrator (the whole run body is behind the elevation gate),
# Test-WacSystemDriveSupported, and the ACL verdict for the sandbox state directory - a redirected
# %ProgramData% under TEMP is genuinely user-writable, so the real check answers "untrusted" there
# (measured) and every scenario would exit 7 for a reason unrelated to the case under test. The
# degraded log and the expired budget are NOT faked: the shim calls the real Set-WacLogDegraded and
# moves the real deadline, so the mapping reads exactly the module state a real one produces.
# ---------------------------------------------------------------------------------------------

$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# One plan file drives every shim. Read lazily and cached, so a scenario is one JSON write.
$script:PlanReaderBody = @'
$script:TestPlan = $null

function Get-WacTestPlan {
    if ($null -ne $script:TestPlan) { return $script:TestPlan }

    $table = @{
        stateEvaluated = $true
        stateTrusted = $true
        logDegraded = $false
        deadlineExpired = $false
        quarantined = $false
        targets = @()
        dismOutcome = 'Succeeded'
        deliveryOutcome = 'SafeSkip'
        pnpOutcome = 'Succeeded'
        pruneOutcome = 'SafeSkip'
        stripStepOutcome = $false
        targetTimeoutMs = 0
        targetBlockMs = 0
        targetThrow = $false
        telemetryFails = $false
        driveUnsupported = $false
    }

    $path = [string]$env:WAC_TEST_PLAN
    if ($path -and [System.IO.File]::Exists($path)) {
        $parsed = ConvertFrom-Json ([System.IO.File]::ReadAllText($path))
        foreach ($property in $parsed.PSObject.Properties) { $table[$property.Name] = $property.Value }
    }

    $script:TestPlan = $table
    return $script:TestPlan
}
'@

$script:ShimBody = @{}

$script:ShimBody['Core'] = @'
. (Join-Path -Path $PSScriptRoot -ChildPath '_Plan.ps1')
$script:RealInitializeWacRun = ${function:Initialize-WacRun}

# The elevated candidate list ends at Get-WacFallbackDataRoot, and unshimmed that is a REAL machine
# path no redirected environment variable can move. The refusal cases deliberately reject the first
# candidate, so on an elevated runner the run fell through and created C:\Windows\Logs\
# WindowsAutoCleanup on the live machine - which is why this passed on an unelevated developer shell
# and failed in CI. Redirecting %SystemRoot% instead was tried and measured to be worse: on Windows
# PowerShell 5.1 the .NET Framework resolves the GAC through it lazily and the child dies later on
# an assembly it had not loaded yet.
function Get-WacFallbackDataRoot {
    return (Join-Path -Path (Split-Path -Path $env:ProgramData -Parent) -ChildPath 'WIN\Logs\WindowsAutoCleanup')
}

function Test-WacIsAdministrator { return $true }

# Plan-driven, like the telemetry shims below, rather than a hard $true. Exit 5 - the refusal that
# stops this tool cleaning a machine whose system drive is not C: - is a documented contract row and
# one of the hard safety boundaries, and with this shim wired shut no rig scenario could reach its
# Run.ps1 site at all. CI therefore defended it with a REGEX over Run.ps1's source text, which would
# pass just as happily on a commented-out or unreachable exit.
function Test-WacSystemDriveSupported {
    if ((Get-WacTestPlan).driveUnsupported) { return $false }
    return $true
}

# Telemetry, and only telemetry. Both of these are diagnostics the run writes about itself and
# neither may reach the verdict, so the scenario that proves it has to be able to break them. They
# delegate to the real functions unless the plan says otherwise, which keeps every other scenario
# reading the real values.
$script:RealGetWacFreeBytes = ${function:Get-WacFreeBytes}
$script:RealTestWacIsWindowsServer = ${function:Test-WacIsWindowsServer}

function Get-WacFreeBytes {
    param([string]$Drive = 'C:')
    if ((Get-WacTestPlan).telemetryFails) { throw 'test shim: the free-space source is unavailable' }
    return (& $script:RealGetWacFreeBytes -Drive $Drive)
}

function Test-WacIsWindowsServer {
    if ((Get-WacTestPlan).telemetryFails) { throw 'test shim: the OS edition source is unavailable' }
    return (& $script:RealTestWacIsWindowsServer)
}

function Test-WacStatePathIsTrusted {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path, [int]$MaxDepth = 64)

    $null = $MaxDepth
    return [PSCustomObject]@{
        Path = $Path
        IsTrusted = [bool](Get-WacTestPlan).stateTrusted
        Reason = 'test shim verdict'
        Checked = @(); Failures = @(); Writers = @()
    }
}

# The second half of the same fact. Test-WacStatePathIsTrusted above answers the PATHNAME question;
# this answers the one taken from the log directory's own handle. A redirected %ProgramData% under
# TEMP is genuinely user-writable, so the real rule says "untrusted" there (measured) and every
# scenario would exit 7 before reaching the case under test. Only the DESCRIPTOR answer is stood in:
# the reparse test and the collision-failing create stay the kernel's answers.
Set-WacDirectoryTrustJudge -ScriptBlock {
    param($sddl)
    $null = $sddl
    return [PSCustomObject]@{
        IsTrusted = [bool](Get-WacTestPlan).stateTrusted
        Owner = $null
        Reason = 'test shim: handle descriptor verdict'
    }
}

# THE CONTROL STORE, inside this run's own sandbox (ledger WAC-05R). Its shipped root is under
# %SystemRoot%, which no redirected environment variable moves - and on an ELEVATED runner that
# directory is writable, so the quarantined scenarios below armed a REAL durable marker on the
# machine. An external abandonment is never retired by a later run, so that single marker refused
# every rig run for the rest of the job, and the failures landed in whatever suite happened to come
# next. None of it showed on an unelevated developer shell, where the same write simply failed.
#
# A parent suite's Set-WacControlRoot is in-process and cannot reach a child, so the child sets its
# own. The descriptor judge above is what makes a store under a user-writable %ProgramData%
# answerable at all.
#
# The path only. CREATING it here made the shim the thing that created a directory under a state
# root the run had just REFUSED, which RunStateRefusal.Tests.ps1 is precisely about: a refusal that
# leaves a tree behind has travelled through the boundary it was supposed to stop at. The store
# creates its own root when it has something to write, and a store that does not exist reads as
# nothing outstanding - which is the correct answer for a run that was never allowed to record one.
Set-WacControlRoot -Path (Join-Path -Path $env:ProgramData -ChildPath 'WindowsAutoCleanup\Control')

function Initialize-WacRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BaseName,
        [string[]]$CandidateRoot,
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$LogLevel = 'INFO',
        [int]$BudgetMinutes = 210,
        [string]$BootstrapLogPath,
        [Nullable[datetime]]$StartUtc,
        [int]$ShutdownMarginSeconds = 0
    )

    $ok = & $script:RealInitializeWacRun @PSBoundParameters
    if (-not $ok) { return $ok }

    $plan = Get-WacTestPlan
    # Real module state, not a faked return value: Get-WacLogHealth, Get-WacStateTrust and
    # Test-WacDeadlineExpired stay the shipped functions reading the shipped variables.
    if ($plan.logDegraded) { Set-WacLogDegraded -Reason 'test shim: a log write failed' }

    # AFTER the real Initialize-WacRun, which is what resolves the durable record. What these cases
    # are about is whether the STEP SEQUENCE reads the latch; QuarantineStore.Tests.ps1 is where the
    # record itself is proven. The marker this writes lands in the sandbox store above, so arming it
    # costs the machine nothing and the next scenario starts from an empty store.
    if ($plan.quarantined) { [void](Add-WacAbandonedMutator -Reason 'test shim: an abandoned mutator') }
    if ($plan.deadlineExpired) { $script:DeadlineUtc = (Get-Date).ToUniversalTime().AddMinutes(-1) }
    if (-not $plan.stateEvaluated) { $script:StateTrust = $null }

    return $ok
}
'@

$script:ShimBody['FileSystem'] = @'
. (Join-Path -Path $PSScriptRoot -ChildPath '_Plan.ps1')

function Get-WacTestTargetResult {
    param([Parameter(Mandatory = $true)][string]$Category, [Parameter(Mandatory = $true)][string]$Path)

    $stats = New-WacDeletionStats
    $attempted = $false

    foreach ($spec in @((Get-WacTestPlan).targets)) {
        if ([string]$spec.category -cne $Category) { continue }
        foreach ($property in $spec.PSObject.Properties) {
            if ($property.Name -ceq 'category' -or $property.Name -ceq 'path') { continue }
            if ($property.Name -ceq 'attempted') { $attempted = [bool]$property.Value; continue }
            $stats.($property.Name) = [int64]$property.Value
        }
    }

    return (New-WacTreeResult -Category $Category -Path $Path -Stats $stats -Attempted $attempted)
}

function Remove-WacTree {
    param([Parameter(Mandatory = $true)][string]$Category, [Parameter(Mandatory = $true)][string]$Path, [switch]$DeleteRoot)
    $null = $DeleteRoot
    return (Get-WacTestTargetResult -Category $Category -Path $Path)
}

function Remove-WacFilesByPattern {
    param([Parameter(Mandatory = $true)][string]$Category, [Parameter(Mandatory = $true)][string]$Path, [string[]]$Pattern = @())
    $null = $Pattern
    return (Get-WacTestTargetResult -Category $Category -Path $Path)
}
'@

$script:ShimBody['Targets'] = @'
. (Join-Path -Path $PSScriptRoot -ChildPath '_Plan.ps1')

# The BOUND itself, lowered so a scenario can outlast it in under a second instead of two minutes.
# Get-WacCleanupTargetSet reads this in the calling process while the builder below runs inside the
# runspace it bounds, which is exactly the separation the scenario has to exercise.
if ([int](Get-WacTestPlan).targetTimeoutMs -gt 0) {
    $script:TargetBuildTimeoutMs = [int](Get-WacTestPlan).targetTimeoutMs
}

function Get-WacCleanupTarget {
    param([string[]]$SkipCategory = @())

    # A discovery that BLOCKS. Building the real list walks the filesystem and queries CIM, and a
    # call blocked in the OS is exactly what the bound exists for; a deadline loop reproduces that
    # without needing a wedged machine.
    $blockMs = [int](Get-WacTestPlan).targetBlockMs
    if ($blockMs -gt 0) {
        $blockUntil = [DateTime]::UtcNow.AddMilliseconds($blockMs)
        while ([DateTime]::UtcNow -lt $blockUntil) { Start-Sleep -Milliseconds 100 }
    }

    if ((Get-WacTestPlan).targetThrow) { throw 'test shim: the allow-list could not be built' }

    $skip = @($SkipCategory)
    foreach ($spec in @((Get-WacTestPlan).targets)) {
        $category = [string]$spec.category
        if ($skip -contains $category) { continue }
        [PSCustomObject]@{ Category = $category; Path = [string]$spec.path; Mode = 'Tree'; Pattern = @(); DeleteRoot = $false }
    }
}
'@

$script:ShimBody['Steps'] = @'
. (Join-Path -Path $PSScriptRoot -ChildPath '_Plan.ps1')

function New-WacTestStepResult {
    <#
    .SYNOPSIS
        A step result in whichever shape New-WacStepResult currently offers.
    .DESCRIPTION
        No .Outcome is added here on purpose: this is the LEGACY shape, so these steps prove
        Get-WacStepOutcome's boolean fallback. The Drivers shim returns the Outcome-carrying shape.
    #>
    param([Parameter(Mandatory = $true)][string]$Category, [Parameter(Mandatory = $true)][string]$Outcome)

    $argument = @{ Category = $Category; Attempted = $true; Detail = ('test shim: ' + $Outcome) }
    if ((Get-Command -Name 'New-WacStepResult').Parameters.ContainsKey('Outcome')) {
        $argument['Outcome'] = $Outcome
    }
    else {
        $argument['Succeeded'] = ($Outcome -ceq 'Succeeded')
        $argument['Skipped'] = ($Outcome -ceq 'SafeSkip')
        $argument['Failed'] = ($Outcome -ceq 'Failed' -or $Outcome -ceq 'Incomplete' -or $Outcome -ceq 'SecurityRefusal')
    }

    return (Write-WacStepResult -Result (New-WacStepResult @argument) -Component 'TestStep')
}

function Invoke-WacComponentCleanup {
    param([switch]$ResetBase)
    $null = $ResetBase
    return (New-WacTestStepResult -Category 'Component store cleanup' -Outcome ([string](Get-WacTestPlan).dismOutcome))
}

function Clear-WacTestOutcomeFreeResult {
    <#
    .SYNOPSIS
        The same result with .Outcome removed - a step from before the outcome contract.
    #>
    param([Parameter(Mandatory = $true)]$Result)

    $copy = New-Object PSObject
    foreach ($property in $Result.PSObject.Properties) {
        if ($property.Name -ceq 'Outcome') { continue }
        Add-Member -InputObject $copy -MemberType NoteProperty -Name $property.Name -Value $property.Value
    }
    return $copy
}

function Clear-WacDeliveryOptimizationCache {
    $result = New-WacTestStepResult -Category 'Delivery Optimization cache' -Outcome ([string](Get-WacTestPlan).deliveryOutcome)
    if ((Get-WacTestPlan).stripStepOutcome) { return (Clear-WacTestOutcomeFreeResult -Result $result) }
    return $result
}

function Invoke-WacLegacyDiskCleanup {
    param([switch]$Enabled, [AllowEmptyCollection()][string[]]$Category = @(), [int]$SageId = 9999)
    $null = $Enabled; $null = $Category; $null = $SageId
    return (New-WacTestStepResult -Category 'Legacy Disk Cleanup' -Outcome 'SafeSkip')
}

function Clear-WacRecycleBin {
    return (New-WacTestStepResult -Category 'Recycle Bin' -Outcome 'Succeeded')
}
'@

$script:ShimBody['Drivers'] = @'
. (Join-Path -Path $PSScriptRoot -ChildPath '_Plan.ps1')

function New-WacTestDriverStepResult {
    param([Parameter(Mandatory = $true)][string]$Category, [Parameter(Mandatory = $true)][string]$Outcome)

    # The SHIPPED bridge, so these results carry .Outcome exactly as the real driver steps do.
    return (Write-WacStepResult -Component 'TestStep' -Result (New-WacDriverStepResult `
        -Category $Category -Outcome $Outcome -Attempted $true -Detail ('test shim: ' + $Outcome)))
}

function Invoke-WacPnpCleanHandler {
    return (New-WacTestDriverStepResult -Category 'Driver package cleanup' -Outcome ([string](Get-WacTestPlan).pnpOutcome))
}

function Invoke-WacDriverPackagePrune {
    param([switch]$Enabled, [string]$BackupRoot)
    $null = $Enabled

    # No driver is touched here, but a backup directory IS left behind, because that is the state a
    # later run has to stay benign over: a directory left by run 1 is exactly the shape of the
    # defect that made run 2 refuse.
    #
    # It is created under the REDIRECTED data root, not under the root the caller passed. The
    # shipped backup root moved to %SystemRoot%\Logs so that no non-administrator can create a name
    # beside an export, and this rig deliberately does not redirect %SystemRoot% - Windows
    # PowerShell 5.1 compiles Add-Type through csc.exe under the real one, and redirecting it breaks
    # every run in this suite. So the caller's root is a real, administrators-only machine path that
    # an unelevated suite cannot create and MUST NOT try to: doing so threw an unhandled error and
    # took the whole run's exit code with it, and on an elevated runner it would have quietly
    # written into the live machine instead of the sandbox.
    $null = $BackupRoot
    $residue = Join-Path -Path (Get-WacDataRoot) -ChildPath 'DriverBackup'
    try { [void][System.IO.Directory]::CreateDirectory($residue) } catch { $null = $_ }

    return (New-WacTestDriverStepResult -Category 'Driver package prune' -Outcome ([string](Get-WacTestPlan).pruneOutcome))
}
'@

function New-RunRig {
    <#
    .SYNOPSIS
        A sandbox holding a byte-identical copy of Run.ps1 and a src\ of shim modules.
    #>
    param([Parameter(Mandatory = $true)][string]$Prefix)

    $sandbox = New-TestSandbox -Prefix $Prefix
    $app = Join-Path -Path $sandbox -ChildPath 'app'
    $src = Join-Path -Path $app -ChildPath 'src'
    [void][System.IO.Directory]::CreateDirectory($src)
    foreach ($leaf in @('PD', 'LA', 'TMP', 'WIN')) {
        [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $sandbox -ChildPath $leaf))
    }

    $runCopy = Join-Path -Path $app -ChildPath 'Run.ps1'
    [System.IO.File]::Copy($script:RunPath, $runCopy)
    if ((New-Object System.IO.FileInfo($runCopy)).Length -ne (New-Object System.IO.FileInfo($script:RunPath)).Length) {
        throw 'the copied Run.ps1 is not the shipped one'
    }

    [System.IO.File]::WriteAllText((Join-Path -Path $src -ChildPath '_Plan.ps1'), $script:PlanReaderBody, $script:Utf8NoBom)

    # The five modules below are no longer the whole of src\: they dot-source .ps1 parts from beside
    # themselves and import further .psm1 modules, none of which a hand-maintained list can be
    # trusted to remember. Copy everything first and let the shim loop overwrite the five it owns,
    # so a module split later needs no change here.
    foreach ($part in @(Get-ChildItem -LiteralPath $script:SrcRoot -File |
            Where-Object { $_.Name -like 'WindowsAutoCleanup.*.ps1' -or $_.Name -like 'WindowsAutoCleanup.*.psm1' })) {
        [System.IO.File]::Copy($part.FullName, (Join-Path -Path $src -ChildPath $part.Name), $true)
    }

    foreach ($name in @('Core', 'FileSystem', 'Targets', 'Steps', 'Drivers')) {
        $leaf = 'WindowsAutoCleanup.{0}.psm1' -f $name
        $text = [System.IO.File]::ReadAllText((Join-Path -Path $script:SrcRoot -ChildPath $leaf))
        [System.IO.File]::WriteAllText((Join-Path -Path $src -ChildPath $leaf),
            ($text + [Environment]::NewLine + $script:ShimBody[$name]), $script:Utf8NoBom)
    }

    return [PSCustomObject]@{
        Sandbox      = $sandbox
        RunPath      = $runCopy
        WindowsRoot  = Join-Path -Path $sandbox -ChildPath 'WIN'
        Src          = $src
        PlanPath     = Join-Path -Path $sandbox -ChildPath 'plan.json'
        ProgramData  = Join-Path -Path $sandbox -ChildPath 'PD'
        LocalAppData = Join-Path -Path $sandbox -ChildPath 'LA'
        Temp         = Join-Path -Path $sandbox -ChildPath 'TMP'
        LogDirectory = Join-Path -Path $sandbox -ChildPath 'PD\WindowsAutoCleanup\Logs'
        # Local\, not Global\: creating a Global\ kernel object needs SeCreateGlobalPrivilege, which
        # a developer shell does not hold, so every run here would exit 3 instead of the code under
        # test. Unique per rig so concurrent suites never collide.
        MutexName    = 'Local\WacRig{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 12)
    }
}

function Remove-RunRig {
    <#
    .SYNOPSIS
        Removes a rig sandbox, retrying briefly while a just-exited child still holds a handle.
    .DESCRIPTION
        Measured: a delete issued immediately after the last child exits occasionally leaves the
        sandbox behind - Windows has not released the exited process's handles yet - and
        Remove-TestSandbox untracks the path whether or not the delete worked, so the end-of-suite
        sweep never comes back to it. Bounded by a deadline rather than by a fixed wait, and it
        never throws: this runs from a finally block, where a throw would replace the real failure
        with a cleanup one.
    #>
    param([Parameter(Mandatory = $true)]$Rig)

    $deadline = (Get-Date).AddSeconds(10)
    while ($true) {
        Remove-TestSandbox -Path $Rig.Sandbox
        if (-not (Test-Path -LiteralPath $Rig.Sandbox)) { return }
        if ((Get-Date) -ge $deadline) { break }
        Start-Sleep -Milliseconds 200
    }

    Write-Host ('      note: the rig sandbox outlived its removal bound and is left behind: {0}' -f $Rig.Sandbox)
}

function New-PlanTarget {
    <#
    .SYNOPSIS
        One scripted target result. Every counter name is a real New-WacDeletionStats field.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [bool]$Attempted = $true,
        [int]$FilesDeleted = 0,
        [int]$SkippedReparse = 0,
        [int]$SkippedOutOfRoot = 0,
        [int]$SkippedProtected = 0,
        [int]$SkippedDeadline = 0,
        [int]$RefusedIdentity = 0,
        [int]$RefusedOutOfRoot = 0,
        [int]$Failed = 0
    )

    return @{
        category         = $Category
        path             = 'C:\WacTestTarget\{0}' -f $Category
        attempted        = $Attempted
        FilesDeleted     = $FilesDeleted
        SkippedReparse   = $SkippedReparse
        SkippedOutOfRoot = $SkippedOutOfRoot
        SkippedProtected = $SkippedProtected
        SkippedDeadline  = $SkippedDeadline
        RefusedIdentity  = $RefusedIdentity
        RefusedOutOfRoot = $RefusedOutOfRoot
        Failed           = $Failed
    }
}

function Invoke-RunRig {
    <#
    .SYNOPSIS
        Writes the plan and runs the copied Run.ps1 as a bounded child. Returns the probe result.
    #>
    param(
        [Parameter(Mandatory = $true)]$Rig,
        [Parameter(Mandatory = $true)][hashtable]$Plan,
        [AllowEmptyCollection()][string[]]$ExtraArgument = @(),
        [int]$TimeoutMs = 90000
    )

    [System.IO.File]::WriteAllText($Rig.PlanPath, ($Plan | ConvertTo-Json -Depth 6), $script:Utf8NoBom)

    # No -ResetWindowsUpdateBase:$false here: under -File, Windows PowerShell 5.1 hands the child
    # the literal string '$false' and parameter binding fails before the body runs (measured). The
    # DISM step is scripted by the plan anyway, so the switch has nothing to change.
    #
    # -BudgetMinutes 5 rather than 1: nothing here does real work, but a budget the machine could
    # plausibly outlive would make "a benign run exits 0" flaky in exactly the direction that hides
    # a defect. The expired-budget case moves the deadline explicitly instead of racing it.
    $argument = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Rig.RunPath,
        '-Scheduled', '-BudgetMinutes', '5', '-MutexName', $Rig.MutexName) + @($ExtraArgument)

    return (Invoke-Probe -TimeoutMs $TimeoutMs -CommandLine (ConvertTo-WacCommandLine -ArgumentList $argument) -Environment @{
            ProgramData   = $Rig.ProgramData
            LOCALAPPDATA  = $Rig.LocalAppData
            TEMP          = $Rig.Temp
            TMP           = $Rig.Temp
            WAC_TEST_PLAN = $Rig.PlanPath
        })
}

function Get-RigLogText {
    <#
    .SYNOPSIS
        The text of the newest run log in the rig, or '' when the run wrote none.
    #>
    param([Parameter(Mandatory = $true)]$Rig)

    $logs = @(Get-ChildItem -LiteralPath $Rig.LogDirectory -Filter 'WindowsAutoCleanup_*.log' -File -ErrorAction SilentlyContinue |
            Sort-Object -Property LastWriteTimeUtc -Descending)
    if ($logs.Count -eq 0) { return '' }
    return [System.IO.File]::ReadAllText($logs[0].FullName)
}

function Assert-RigExit {
    <#
    .SYNOPSIS
        Asserts the child's exit code AND the status the footer recorded, with the log as evidence.
    #>
    param(
        [Parameter(Mandatory = $true)]$Rig,
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][string]$Status
    )

    $text = Get-RigLogText -Rig $Rig
    Assert-True $Result.Exited ('the run did not finish inside its bound. stderr: ' + $Result.ErrorText)
    Assert-Equal $ExitCode $Result.ExitCode ('stderr: {0}{1}log: {2}' -f $Result.ErrorText, [Environment]::NewLine, $text)
    Assert-True ($text -cmatch ('(^|\s)status={0}($|\s)' -f $Status)) `
    ('the footer did not record status={0}: {1}' -f $Status, $text)
    Assert-True ($text -cmatch ('(^|\s)exitCode={0}($|\s)' -f $ExitCode)) `
    ('the footer did not record exitCode={0}: {1}' -f $ExitCode, $text)
}
