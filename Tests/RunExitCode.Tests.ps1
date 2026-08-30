#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for Run.ps1's exit-code contract, end to end through the real script.

.DESCRIPTION
    Run.ps1 is COPIED byte for byte into a sandbox that also holds a src\ of shim modules, so the
    orchestration, the totals, the verdict and the exit code under test are the shipped ones while
    nothing this machine owns is touched. The rig that builds and drives that sandbox lives in
    _RunRig.ps1; one JSON plan per scenario is all a case has to write.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'

Import-Module -Name (Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_RunProbe.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_RunRig.ps1')

# ---------------------------------------------------------------------------------------------
# Two additions to the rig's Core shim, appended from HERE so the shared rig file is left alone.
# They are defined after the rig's own overrides, so these are the definitions that win.
#
#   * Test-WacStatePathIsTrusted RECORDS every question it is asked, and whether the path existed
#     at the moment of the question. That record is the ORDER proof: a verdict reached while the
#     candidate root did not yet exist cannot have been reached after the root was created. It also
#     answers in whichever SHAPE the plan names, including two shapes that are not answers at all.
#
#   * The owner/DACL verdict taken from the log directory's OWN HANDLE follows the same plan flag.
#     It is the second of the two answers a redirected %ProgramData% under TEMP cannot give
#     honestly: that directory is genuinely user-writable, so the real rule says "untrusted" there
#     (measured) and every scenario would fail to open a log for a reason unrelated to the case
#     under test. Only the DESCRIPTOR answer is stood in. The reparse test and the collision-failing
#     create are the kernel's answers, not this shim's, which is why the junction case below still
#     exercises the real guard.
#
#   * The degraded-mode sink is redirected into the sandbox. Write-WacFallbackLine tries the
#     machine's Application event log first and a test may not write there; Set-WacLogFallbackWriter
#     is the seam that exists for exactly this, and it reports 'Injected', so a line is PROVEN to
#     have reached a sink rather than merely not to have thrown.
# ---------------------------------------------------------------------------------------------

$script:ShimBody['Core'] = $script:ShimBody['Core'] + @'

function Test-WacStatePathIsTrusted {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path, [int]$MaxDepth = 64)
    $null = $MaxDepth

    $plan = Get-WacTestPlan
    [System.IO.File]::AppendAllText(([string]$env:WAC_TEST_PLAN + '.trustlog'),
        ('{0}|{1}{2}' -f $Path, [System.IO.Directory]::Exists($Path), [Environment]::NewLine),
        (New-Object System.Text.UTF8Encoding($false)))

    if ($plan['stateTrustThrows']) { throw 'test shim: the trust question cannot be answered here' }
    if ($plan['stateTrustNull']) { return $null }

    $reason = [string]$plan['stateReason']
    if (-not $reason) { $reason = 'test shim verdict' }

    return [PSCustomObject]@{
        Path = $Path
        IsTrusted = [bool]$plan['stateTrusted']
        Reason = $reason
        Checked = @(); Failures = @(); Writers = @()
    }
}

Set-WacLogFallbackWriter -Writer {
    param($line)
    [System.IO.File]::AppendAllText(([string]$env:WAC_TEST_PLAN + '.fallback'),
        ($line + [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false)))
}

Set-WacDirectoryTrustJudge -ScriptBlock {
    param($sddl)
    $null = $sddl
    return [PSCustomObject]@{
        IsTrusted = [bool](Get-WacTestPlan).stateTrusted
        Owner = $null
        Reason = 'test shim: handle descriptor verdict'
    }
}
'@

function Get-RigFallbackText {
    <#
    .SYNOPSIS
        Everything the run wrote to its degraded-mode sink, or '' when it wrote nothing there.
    #>
    param([Parameter(Mandatory = $true)]$Rig)

    $path = [string]$Rig.PlanPath + '.fallback'
    if (-not [System.IO.File]::Exists($path)) { return '' }
    return [System.IO.File]::ReadAllText($path)
}

function Get-RigTrustQuestion {
    <#
    .SYNOPSIS
        Every path the trust check was asked about, and whether it existed when it was asked.
    #>
    param([Parameter(Mandatory = $true)]$Rig)

    $path = [string]$Rig.PlanPath + '.trustlog'
    if (-not [System.IO.File]::Exists($path)) { return @() }

    return @([System.IO.File]::ReadAllLines($path) | Where-Object { $_ } | ForEach-Object {
            $field = $_.Split('|')
            [PSCustomObject]@{ Path = $field[0]; Existed = ([string]$field[1] -ceq 'True') }
        })
}

function Clear-RigProbeRecord {
    <#
    .SYNOPSIS
        Drops the trust and fallback records so one rig can carry several scenarios.
    #>
    param([Parameter(Mandatory = $true)]$Rig)

    foreach ($suffix in @('.trustlog', '.fallback')) {
        $path = [string]$Rig.PlanPath + $suffix
        if ([System.IO.File]::Exists($path)) { [System.IO.File]::Delete($path) }
    }
}

function Get-DirectoryFingerprint {
    <#
    .SYNOPSIS
        Everything about a directory that ANY create, write, append, copy or delete would move.
    .DESCRIPTION
        The directory's own LastWriteTimeUtc changes whenever an entry is added to it or removed
        from it, and every child contributes its name, its length, its own LastWriteTimeUtc and its
        bytes. Comparing the whole thing is a stronger proof than recording calls would be: it sees
        a FileStream(CreateNew) and a [System.IO.File]::Delete, neither of which is a cmdlet any
        recorder could intercept. 'ABSENT' is its own answer, so "never created" is not confused
        with "created and left empty".
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [System.IO.Directory]::Exists($Path)) { return 'ABSENT' }

    # Every -f expression is parenthesised: inside a method call the argument list splits on commas,
    # so .Add('{0}|{1}' -f $a, $b) passes TWO arguments and formats {1} against nothing.
    $line = New-Object 'System.Collections.Generic.List[string]'
    [void]$line.Add(('DIR|{0}' -f [System.IO.Directory]::GetLastWriteTimeUtc($Path).Ticks))

    foreach ($entry in @([System.IO.Directory]::GetFileSystemEntries($Path) | Sort-Object)) {
        if ([System.IO.Directory]::Exists($entry)) {
            [void]$line.Add(('SUBDIR|{0}|{1}' -f $entry, [System.IO.Directory]::GetLastWriteTimeUtc($entry).Ticks))
            continue
        }
        $info = New-Object System.IO.FileInfo($entry)
        [void]$line.Add(('FILE|{0}|{1}|{2}|{3}' -f $entry, $info.Length, $info.LastWriteTimeUtc.Ticks,
                [System.IO.File]::ReadAllText($entry)))
    }

    return ($line -join [Environment]::NewLine)
}

Test-Case 'A benign run exits 0, and the same state a second time still exits 0' {
    # The trap this case exists for: a previous wave left a directory behind on run 1 that made
    # every later run refuse, so run 2 exited 7 with nothing wrong. Both runs use the SAME sandbox
    # and the same redirected %ProgramData%, so run 2 really does run over what run 1 left: the
    # first run's log, the retention sweep that now has a file to consider, and the driver-backup
    # directory the prune step creates under the machine-wide data root.
    #
    # What it does NOT cover, because the rig stands that function in: the trust verdict on that
    # directory. Test-WacStatePathIsTrusted returns the plan's answer here, so this case proves the
    # run stays benign over its own leftovers - not that a real ACL check would agree.
    #
    # The counters are the ones a real elevated run really scores (measured: skipReparse=3,
    # skipOutOfRoot=1). They are benign and must not move the exit code.
    $rig = New-RunRig -Prefix 'rig-benign'
    try {
        $plan = @{ targets = @(
                (New-PlanTarget -Category 'Temp' -FilesDeleted 12 -SkippedReparse 3 -SkippedOutOfRoot 1),
                (New-PlanTarget -Category 'Caches' -SkippedProtected 2))
        }

        $first = Invoke-RunRig -Rig $rig -Plan $plan
        Assert-RigExit -Rig $rig -Result $first -ExitCode 0 -Status 'Succeeded'

        $second = Invoke-RunRig -Rig $rig -Plan $plan
        Assert-RigExit -Rig $rig -Result $second -ExitCode 0 -Status 'Succeeded'

        $logs = @(Get-ChildItem -LiteralPath $rig.LogDirectory -Filter 'WindowsAutoCleanup_*.log' -File)
        Assert-Equal 2 $logs.Count 'the second run did not write its own log beside the first'

        $backupRoot = Join-Path -Path (Join-Path -Path $rig.ProgramData -ChildPath 'WindowsAutoCleanup') -ChildPath 'DriverBackup'
        Assert-True (Test-Path -LiteralPath $backupRoot -PathType Container) `
        ('run 1 left no state under the data root for run 2 to run over: ' + $backupRoot)

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text -cmatch '(^|\s)skipReparse=3($|\s)') ('the benign counters never reached the totals: ' + $text)

        # Free space is now read through System.IO.DriveInfo rather than Win32_LogicalDisk. Real
        # values here are what proves the replacement actually answers on both shipped hosts; the
        # broken-telemetry case below proves an unreadable one degrades to Unknown instead.
        Assert-False ($text -cmatch '(^|\s)before=Unknown(\s|$)') `
        ('free space came back unreadable on a healthy machine: ' + $text)
        Assert-False ($text.Contains('[CRITICAL]')) ('a benign run logged a CRITICAL line: ' + $text)
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A refused target exits 7 and is the one line the log cannot lose' {
    # Attempted is false: the target was refused BEFORE any deletion, which is the shape that used
    # to produce no [Result] line at all - the one event driving exit 7, invisible in the audit log.
    $rig = New-RunRig -Prefix 'rig-refusal'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ targets = @(
                (New-PlanTarget -Category 'Refused' -Attempted $false -RefusedIdentity 1)) }

        Assert-RigExit -Rig $rig -Result $result -ExitCode 7 -Status 'SecurityRefusal'

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text.Contains('[Result] Target complete.')) `
        ('a target refused before it was attempted produced no result line: ' + $text)
        Assert-True ($text -cmatch '(^|\s)refusedIdentity=1($|\s)') $text
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A refusal outranks a failure: both together still exit 7' {
    $rig = New-RunRig -Prefix 'rig-precedence'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{
            dismOutcome = 'Failed'
            targets     = @((New-PlanTarget -Category 'Refused' -Attempted $false -RefusedOutOfRoot 1))
        }

        Assert-RigExit -Rig $rig -Result $result -ExitCode 7 -Status 'SecurityRefusal'

        # Both events are in the totals, so the 7 is a precedence decision and not a lost failure.
        $text = Get-RigLogText -Rig $rig
        Assert-True ($text -cmatch '(^|\s)failed=1($|\s)') ('the failure was dropped rather than outranked: ' + $text)
        Assert-True ($text -cmatch '(^|\s)refusedOutOfRoot=1($|\s)') $text
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A step failure exits 2, and so does a target failure' {
    $rig = New-RunRig -Prefix 'rig-failed'
    try {
        $step = Invoke-RunRig -Rig $rig -Plan @{ dismOutcome = 'Failed'; targets = @() }
        Assert-RigExit -Rig $rig -Result $step -ExitCode 2 -Status 'Failed'

        $target = Invoke-RunRig -Rig $rig -Plan @{ targets = @((New-PlanTarget -Category 'Temp' -Failed 3)) }
        Assert-RigExit -Rig $rig -Result $target -ExitCode 2 -Status 'Failed'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'An expired budget exits 6 rather than reporting success' {
    # The defect in its literal shape: incomplete work used to exit 0.
    $rig = New-RunRig -Prefix 'rig-budget'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ deadlineExpired = $true; targets = @(
                (New-PlanTarget -Category 'Temp' -FilesDeleted 1))
        }

        Assert-RigExit -Rig $rig -Result $result -ExitCode 6 -Status 'Incomplete'
        Assert-True ((Get-RigLogText -Rig $rig).Contains('The run budget expired')) 'the incomplete run never said why'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A target that ran out of deadline exits 6' {
    $rig = New-RunRig -Prefix 'rig-deadline'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ targets = @(
                (New-PlanTarget -Category 'Temp' -FilesDeleted 4 -SkippedDeadline 9))
        }

        Assert-RigExit -Rig $rig -Result $result -ExitCode 6 -Status 'Incomplete'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'An Incomplete step outcome exits 6, not 2' {
    # Only reachable by READING .Outcome. The derived booleans make an Incomplete step Failed too,
    # so a mapping that trusted them would exit 2 here and this case would be red.
    $rig = New-RunRig -Prefix 'rig-stepincomplete'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ pruneOutcome = 'Incomplete'; targets = @() }
        Assert-RigExit -Rig $rig -Result $result -ExitCode 6 -Status 'Incomplete'

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text -cmatch '(^|\s)stepIncomplete=1($|\s)') `
        ('the totals reported the step as a plain failure: ' + $text)
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A SecurityRefusal step outcome exits 7' {
    $rig = New-RunRig -Prefix 'rig-steprefusal'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ pruneOutcome = 'SecurityRefusal'; targets = @() }
        Assert-RigExit -Rig $rig -Result $result -ExitCode 7 -Status 'SecurityRefusal'

        Assert-True ((Get-RigLogText -Rig $rig) -cmatch '(^|\s)stepRefused=1($|\s)') 'the refusing step is not in the totals'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'An audit log that is not durable exits 6' {
    # Set-WacLogDegraded is the real function and Get-WacLogHealth the real reader; only the event
    # that trips it is injected, because a real write failure needs a broken volume.
    $rig = New-RunRig -Prefix 'rig-durable'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ logDegraded = $true; targets = @() }
        Assert-RigExit -Rig $rig -Result $result -ExitCode 6 -Status 'Incomplete'

        Assert-True ((Get-RigLogText -Rig $rig).Contains('durable audit log')) 'the incomplete run never said why'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A step result that states no outcome is never read as a success' {
    # Every shipped step returns .Outcome now. One that does not is a step this mapping cannot
    # classify, and the only safe reading of an unclassifiable step is that it did not succeed -
    # the alternative is a silent 0 for work whose result nobody could interpret.
    $rig = New-RunRig -Prefix 'rig-nooutcome'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ stripStepOutcome = $true; targets = @() }
        Assert-RigExit -Rig $rig -Result $result -ExitCode 2 -Status 'Failed'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A module that cannot be imported is bootstrap-logged, folded into the run log and exits 1' {
    $rig = New-RunRig -Prefix 'rig-bootstrap'
    try {
        # A module that throws at import. Nothing inside a module can log that, which is the whole
        # reason the bootstrap log exists.
        [System.IO.File]::AppendAllText((Join-Path -Path $rig.Src -ChildPath 'WindowsAutoCleanup.Drivers.psm1'),
            ([Environment]::NewLine + "throw 'test shim: this module refuses to import'" + [Environment]::NewLine),
            $script:Utf8NoBom)

        $result = Invoke-RunRig -Rig $rig -Plan @{ targets = @() }

        Assert-True $result.Exited ('the run did not finish inside its bound. stderr: ' + $result.ErrorText)
        Assert-Equal 1 $result.ExitCode ('stderr: ' + $result.ErrorText)

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text.Contains('[Bootstrap]')) ('the import failure never reached the durable run log: ' + $text)
        Assert-True ($text.Contains('WindowsAutoCleanup.Drivers.psm1')) $text
        Assert-True ($text.Contains('A required module could not be loaded')) $text
        Assert-False ($text.Contains('[Summary]')) 'the run cleaned with a module missing'

        # Adopted, so the bootstrap file is gone and the run leaves ONE audit artifact.
        $leftover = @(Get-ChildItem -LiteralPath $rig.Temp -Filter 'WindowsAutoCleanup-bootstrap-*.log' -File -ErrorAction SilentlyContinue)
        Assert-Equal 0 $leftover.Count 'the bootstrap log survived a run whose log adopted it'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A system drive that is not C: exits 5 and cleans nothing' {
    # Exit 5 stops this tool cleaning a machine whose online system drive is not C:. Every allow-list
    # location is written for C:, so running against a different Windows installation could delete
    # data belonging to it.
    #
    # Until this case existed, CI defended that boundary with a REGEX over Run.ps1's source text
    # (Orchestration.Tests.ps1 matches Test-WacSystemDriveSupported.{0,600}?exit 5), which passes
    # just as happily on a commented-out or unreachable exit. The regex is KEPT: it catches the call
    # being deleted, this catches the branch being neutered. The gap was structural - _RunRig.ps1
    # hard-coded the drive check to succeed, unlike every other environmental fact it shims, so no
    # scenario could reach the branch. That shim is plan-driven now.
    $rig = New-RunRig -Prefix 'rig-drive5'
    try {
        # A target that WOULD be swept, so "cleaned nothing" is an observation rather than the
        # trivially true statement it would be over an empty allow-list.
        $result = Invoke-RunRig -Rig $rig -Plan @{
            driveUnsupported = $true
            targets = @((New-PlanTarget -Category 'Temp' -FilesDeleted 7))
        }

        Assert-True $result.Exited ('the run did not finish inside its bound. stderr: ' + $result.ErrorText)
        Assert-Equal 5 $result.ExitCode ('an unsupported system drive did not exit with the documented code 5. stderr: ' + $result.ErrorText)

        $log = Get-RigLogText -Rig $rig
        Assert-True ($log.Contains('The online system drive is not C:')) ('the refusal never said why: ' + $log)
        Assert-True ($log -cmatch '(^|\s)\[CRITICAL\]') ('the refusal was not written at a level nothing can gate out: ' + $log)

        # The gate sits before every cleanup step, so nothing may have been swept. A run that exited
        # 5 AFTER sweeping would satisfy the exit-code assertion on its own.
        Assert-False ($log.Contains('files=7')) ('a target was swept before the drive gate refused: ' + $log)
        Assert-False ($log.Contains('status=Succeeded')) ('the run recorded a success verdict behind exit 5: ' + $log)
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A run that cannot take the lock exits 3 and says so at a level nothing can gate out' {
    # Exit 3 had no coverage in the fast suites at all. The lock is held HERE, by this process, on
    # the rig's own Local\ name - so the child meets a lock that is genuinely taken without a
    # second run existing to race against.
    $rig = New-RunRig -Prefix 'rig-lock'
    $created = $false
    $held = New-Object System.Threading.Mutex($true, $rig.MutexName, [ref]$created)
    try {
        Assert-True $created 'the rig mutex name was already taken, so this case would prove nothing'

        $result = Invoke-RunRig -Rig $rig -ExtraArgument @('-LogLevel', 'CRITICAL') -Plan @{ targets = @(
                (New-PlanTarget -Category 'Temp' -FilesDeleted 1))
        }

        Assert-True $result.Exited ('the run did not finish inside its bound. stderr: ' + $result.ErrorText)
        Assert-Equal 3 $result.ExitCode ('stderr: ' + $result.ErrorText)

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text.Contains('already holds the machine-wide lock')) `
        ('the only thing this run says about its exit 3 was written below -LogLevel CRITICAL: ' + $text)
        Assert-False ($text.Contains('[Summary]')) ('the locked-out run cleaned anyway: ' + $text)
    }
    finally {
        try { $held.ReleaseMutex() } catch { $null = $_ }
        try { $held.Dispose() } catch { $null = $_ }
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'The verdict and the evidence behind it survive -LogLevel ERROR' {
    # -LogLevel is a choice about detail, not a choice to lose the verdict. Measured before the fix:
    # at ERROR the process still exited 7 while the audit log held not one line about it - the
    # status line, the totals carrying refusedIdentity and the refusal itself were all written
    # below the level the operator had set.
    $rig = New-RunRig -Prefix 'rig-loglevel'
    try {
        $result = Invoke-RunRig -Rig $rig -ExtraArgument @('-LogLevel', 'ERROR') -Plan @{ targets = @(
                (New-PlanTarget -Category 'Refused' -Attempted $false -RefusedIdentity 1))
        }

        Assert-RigExit -Rig $rig -Result $result -ExitCode 7 -Status 'SecurityRefusal'

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text -cmatch '(^|\s)refusedIdentity=1($|\s)') `
        ('the evidence that produced the 7 did not survive the log level: ' + $text)

        # The INFO half of the footer is still gone, which is what -LogLevel ERROR was asked for:
        # an assertion that passed because everything survived would prove nothing.
        Assert-False ($text.Contains('Free space on C:.')) ('-LogLevel ERROR kept an INFO line: ' + $text)
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A pre-import failure survives -LogLevel ERROR, in the run log or in the bootstrap log' {
    # The bootstrap log exists to preserve the one failure nothing inside a module can report. It is
    # folded into the run log at WARNING, so at -LogLevel ERROR that copy is gated out - and
    # deleting the file on top of that destroyed the only remaining record of it.
    $rig = New-RunRig -Prefix 'rig-bootstraplevel'
    try {
        [System.IO.File]::AppendAllText((Join-Path -Path $rig.Src -ChildPath 'WindowsAutoCleanup.Drivers.psm1'),
            ([Environment]::NewLine + "throw 'test shim: this module refuses to import'" + [Environment]::NewLine),
            $script:Utf8NoBom)

        $result = Invoke-RunRig -Rig $rig -ExtraArgument @('-LogLevel', 'ERROR') -Plan @{ targets = @() }

        Assert-True $result.Exited ('the run did not finish inside its bound. stderr: ' + $result.ErrorText)
        Assert-Equal 1 $result.ExitCode ('stderr: ' + $result.ErrorText)

        $text = Get-RigLogText -Rig $rig
        $leftover = @(Get-ChildItem -LiteralPath $rig.Temp -Filter 'WindowsAutoCleanup-bootstrap-*.log' -File -ErrorAction SilentlyContinue)

        $preserved = ''
        if ($leftover.Count -eq 1) { $preserved = [System.IO.File]::ReadAllText($leftover[0].FullName) }

        Assert-True (($text + $preserved).Contains('WindowsAutoCleanup.Drivers.psm1')) `
        ('the import failure survived nowhere: log=[{0}] bootstrap=[{1}]' -f $text, $preserved)
        Assert-True ($text.Contains('A required module could not be loaded')) `
        ('the refusal to run was written below the level the operator set: ' + $text)
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A discovery that outlasts its bound is Incomplete, not an empty allow-list' {
    # The defect in its literal shape. Run.ps1 called the UNBOUNDED builder, so a discovery that
    # blocked in the OS produced no targets and no complaint: the run swept nothing, cleaned nothing
    # and exited 0. Here the builder blocks for 4 s inside a 400 ms bound, so the run has to say the
    # allow-list was never finished - and it has to finish saying it well inside its own budget.
    $rig = New-RunRig -Prefix 'rig-discoveryslow'
    try {
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-RunRig -Rig $rig -TimeoutMs 60000 -Plan @{
            targetTimeoutMs = 400
            targetBlockMs   = 4000
            targets         = @((New-PlanTarget -Category 'Temp' -FilesDeleted 1))
        }
        $watch.Stop()

        Assert-RigExit -Rig $rig -Result $result -ExitCode 6 -Status 'Incomplete'
        Assert-True ($watch.Elapsed.TotalSeconds -lt 45) `
        ('the run did not come back inside its asserted budget: {0:N1}s' -f $watch.Elapsed.TotalSeconds)

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text.Contains('The cleanup allow-list could not be built')) `
        ('a discovery that never finished was not reported at all: ' + $text)
        Assert-True ($text -cmatch '(^|\s)category="Cleanup allow-list"') `
        ('the discovery outcome never became a step: ' + $text)

        # The target the plan offers must NOT have been swept: a list that was never built cannot
        # have produced one.
        Assert-False ($text.Contains('[Result] Target complete.')) `
        ('a target was swept out of an allow-list that was never finished: ' + $text)
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A discovery that fails outright is a step failure, not a clean run' {
    $rig = New-RunRig -Prefix 'rig-discoveryfail'
    try {
        $result = Invoke-RunRig -Rig $rig -TimeoutMs 60000 -Plan @{
            targetThrow = $true
            targets     = @((New-PlanTarget -Category 'Temp' -FilesDeleted 1))
        }

        Assert-RigExit -Rig $rig -Result $result -ExitCode 2 -Status 'Failed'
        Assert-True ((Get-RigLogText -Rig $rig).Contains('The cleanup allow-list could not be built')) `
        'a failed discovery never said so'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A telemetry failure degrades the header and never erases a cleanup failure' {
    # Free space and the OS edition are diagnostics. Neither is an input to the verdict, so breaking
    # both has to leave a run that still reaches its footer and still reports the failure it found.
    # Before the guard, a throwing diagnostic reached the run's outer handler and turned an exit 2
    # into a plain exit 1 - the cleanup result erased by the line that was only describing it.
    $rig = New-RunRig -Prefix 'rig-telemetry'
    try {
        $result = Invoke-RunRig -Rig $rig -TimeoutMs 60000 -Plan @{
            telemetryFails = $true
            dismOutcome    = 'Failed'
            targets        = @((New-PlanTarget -Category 'Temp' -FilesDeleted 2))
        }

        Assert-RigExit -Rig $rig -Result $result -ExitCode 2 -Status 'Failed'

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text.Contains('A diagnostic could not be read')) `
        ('the broken diagnostics were swallowed instead of degraded: ' + $text)
        Assert-True ($text.Contains('Free space on C:.')) 'the footer lost the free-space line entirely'
        Assert-True ($text -cmatch '(^|\s)before=Unknown(\s|$)') `
        ('an unreadable free-space value was not reported as Unknown: ' + $text)
        Assert-True ($text.Contains('[Result] Target complete.')) `
        'the run stopped cleaning because a diagnostic failed'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A refusing pre-cleanup check mutates nothing at all' {
    # The Group 1 defect end to end. The run-level verdicts were consulted only in the footer, so a
    # run exited AFTER the sweep, DISM, the driver steps and the Recycle Bin had all already run.
    # Same exit code, same status, and now no cleanup line anywhere in the log.
    #
    # Driven by the expired budget rather than by an untrusted state directory: the trust verdict is
    # now reached before the log is even opened, so it can no longer arrive at this gate as a
    # refusal. The budget can - it expires while the run is working - and it exercises the same
    # single gate, ahead of the same mutations.
    $rig = New-RunRig -Prefix 'rig-gate'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{
            deadlineExpired = $true
            targets         = @((New-PlanTarget -Category 'Temp' -FilesDeleted 5))
        }

        Assert-RigExit -Rig $rig -Result $result -ExitCode 6 -Status 'Incomplete'

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text.Contains('nothing on this machine was mutated')) `
        ('the gate did not report that it refused before mutating: ' + $text)
        Assert-False ($text.Contains('[Result] Target complete.')) `
        ('the refused run swept a target anyway: ' + $text)
        Assert-False ($text.Contains('Step complete.')) `
        ('the refused run ran a cleanup step anyway: ' + $text)
        Assert-False ($text.Contains('Cleanup totals.')) `
        ('the refused run reached the footer, so it had already cleaned: ' + $text)

        # And the retention sweep - the first thing that deletes anything - never ran either, so the
        # gate really is ahead of every mutation and not merely ahead of the allow-list.
        $logs = @(Get-ChildItem -LiteralPath $rig.LogDirectory -Filter 'WindowsAutoCleanup_*.log' -File)
        Assert-Equal 1 $logs.Count 'the refusing run left more or fewer logs than the one it wrote'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A benign run stays benign over a state directory the gate has already approved twice' {
    # The steady-state trap, now with the gate in front of it: a check that refuses on a leftover
    # from run 1 would refuse BEFORE run 2 cleans, which is worse than refusing after. Both runs use
    # the same sandbox, the same redirected %ProgramData% and the same driver-backup directory.
    $rig = New-RunRig -Prefix 'rig-gatebenign'
    try {
        $plan = @{ targets = @((New-PlanTarget -Category 'Temp' -FilesDeleted 3 -SkippedReparse 3 -SkippedOutOfRoot 1)) }

        Assert-RigExit -Rig $rig -Result (Invoke-RunRig -Rig $rig -Plan $plan) -ExitCode 0 -Status 'Succeeded'
        Assert-RigExit -Rig $rig -Result (Invoke-RunRig -Rig $rig -Plan $plan) -ExitCode 0 -Status 'Succeeded'

        $text = Get-RigLogText -Rig $rig
        Assert-False ($text.Contains('A pre-cleanup check refused this run')) `
        ('the gate refused a benign steady state on the second run: ' + $text)
        Assert-False ($text.Contains('[CRITICAL]')) ('a benign second run logged a CRITICAL line: ' + $text)
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Complete-TestRun
