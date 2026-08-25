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

Test-Case 'An untrusted state directory exits 7, and a verdict never reached does not' {
    $rig = New-RunRig -Prefix 'rig-trust'
    try {
        $untrusted = Invoke-RunRig -Rig $rig -Plan @{ stateTrusted = $false; targets = @() }
        Assert-RigExit -Rig $rig -Result $untrusted -ExitCode 7 -Status 'SecurityRefusal'
        Assert-True ((Get-RigLogText -Rig $rig).Contains('not machine-trusted')) 'the refusal was not explained'

        # $null is NOT EVALUATED - the shape an unelevated run produces, whose log lives in the
        # user's own profile. It carries no claim to refuse, so it must refuse nothing.
        $notEvaluated = Invoke-RunRig -Rig $rig -Plan @{ stateEvaluated = $false; targets = @() }
        Assert-RigExit -Rig $rig -Result $notEvaluated -ExitCode 0 -Status 'Succeeded'
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

Complete-TestRun
