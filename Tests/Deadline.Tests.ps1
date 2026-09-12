#Requires -Version 5.1
<#
.SYNOPSIS
    Pins the run budget: the traversal must stop when the deadline expires (ledger P1-10, R-3).

.DESCRIPTION
    The deadline used to be checked once per DIRECTORY popped from the stack, which is not a bound at
    all: one flat directory of a million files - exactly the never-cleaned %TEMP% this release exists
    to fix - swept to completion without ever looking at the clock. Measured throughput is 230-520
    entries per second, so a single large directory could run tens of minutes past a 210-minute
    budget and into the scheduled task's four-hour execution limit, where it is killed mid-delete
    rather than stopping cleanly.

    These cases use ONE directory with more entries than the check interval, because that is the
    shape a per-directory check cannot see.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.FileSystem.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

function New-FlatFixture {
    <#
    .SYNOPSIS
        One directory holding $Count files. More than the 256-entry check interval on purpose.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Count = 900
    )

    [void][System.IO.Directory]::CreateDirectory($Path)
    for ($i = 0; $i -lt $Count; $i++) {
        [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath ('f{0}.tmp' -f $i)), 'x')
    }
}

function Reset-WacTestDeadline {
    # Leaving an expired deadline armed would poison every later case in this process.
    Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddHours(1))
}

Test-Case 'A deadline that expires MID-directory stops the sweep' {
    $sandbox = New-TestSandbox -Prefix 'deadline-flat'
    try {
        $target = Join-Path -Path $sandbox -ChildPath 'flat'
        $count = 1500
        New-FlatFixture -Path $target -Count $count

        # The budget must still be live when the directory is POPPED and expire while its entries are
        # being deleted. Arming it in the past instead would be caught by the per-directory gate at
        # the top of the loop, and the case would pass even with the per-entry check deleted - which
        # is exactly how this assertion was defeated the first time it was written.
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddMilliseconds(250))

        $stats = New-WacDeletionStats
        [void](Invoke-WacTreeSweep -Root (Get-WacNormalizedPath -Path $target) -Stats $stats)

        Assert-True ($stats.SkippedDeadline -ge 1) 'the sweep never noticed the deadline pass'
        $remaining = @(Get-ChildItem -LiteralPath $target -File).Count
        Assert-True ($remaining -gt 0) `
            ('the sweep emptied the whole directory past its deadline (deleted {0} of {1})' -f $stats.FilesDeleted, $count)
        Assert-True ([int]$stats.FilesDeleted -lt $count) 'every file was deleted past the deadline'
    }
    finally {
        Reset-WacTestDeadline
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacTree refuses a target outright once the deadline has passed' {
    $sandbox = New-TestSandbox -Prefix 'deadline-root'
    try {
        $target = Join-Path -Path $sandbox -ChildPath 'target'
        New-FlatFixture -Path $target -Count 5

        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddMinutes(-1))
        $result = Remove-WacTree -Category 'expired' -Path $target

        Assert-False $result.Attempted 'a target was swept after the run budget expired'
        Assert-Equal 0 ([int]$result.FilesDeleted)
        Assert-True ($result.SkippedDeadline -ge 1)
        Assert-Equal 5 (@(Get-ChildItem -LiteralPath $target -File).Count)
    }
    finally {
        Reset-WacTestDeadline
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A live deadline lets the same sweep finish' {
    $sandbox = New-TestSandbox -Prefix 'deadline-live'
    try {
        $target = Join-Path -Path $sandbox -ChildPath 'flat'
        New-FlatFixture -Path $target -Count 400

        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddMinutes(10))
        $result = Remove-WacTree -Category 'live' -Path $target

        # The control: without it, "always stop" would satisfy every other case in this file.
        Assert-True $result.Attempted
        Assert-Equal 400 ([int]$result.FilesDeleted) 'the sweep stopped even though the budget was live'
        Assert-Equal 0 ([int]$result.SkippedDeadline)
        Assert-Equal 0 (@(Get-ChildItem -LiteralPath $target -File).Count)
    }
    finally {
        Reset-WacTestDeadline
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Get-WacStepTimeoutMs never hands a step more time than the budget has left' {
    try {
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddSeconds(5))
        $remaining = Get-WacRemainingMs
        Assert-True ($remaining -gt 0 -and $remaining -le 6000) ('remaining was {0}' -f $remaining)

        # A two-hour step request must be clamped to what is actually left.
        $clamped = Get-WacStepTimeoutMs -RequestedMs (1000 * 60 * 120)
        Assert-True ($clamped -le $remaining) ('the step was granted {0} ms of a {1} ms budget' -f $clamped, $remaining)

        # A request smaller than the remaining budget is honoured as-is.
        Assert-Equal 250 (Get-WacStepTimeoutMs -RequestedMs 250)
    }
    finally {
        Reset-WacTestDeadline
    }
}

Test-Case 'An exhausted budget yields a zero timeout and an expired verdict' {
    try {
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddMinutes(-5))

        Assert-Equal 0 (Get-WacRemainingMs)
        Assert-True (Test-WacDeadlineExpired)
        Assert-Equal 0 (Get-WacStepTimeoutMs -RequestedMs 60000) `
            'an exhausted budget still granted a step some time'
    }
    finally {
        Reset-WacTestDeadline
    }
}

Test-Case 'A deadline that expires MID-PATTERN stops the matched-file loop' {
    <#
        Remove-WacFilesByPattern looked at the clock once per PATTERN and then materialised
        GetFiles, so one pattern over one large directory ran to completion however long it took.
        Same defect as the per-directory check the sweep used to have, in the function a
        per-directory check was never going to cover, and the fixture is the same flat shape.
    #>
    $sandbox = New-TestSandbox -Prefix 'deadline-pattern'
    try {
        $target = Join-Path -Path $sandbox -ChildPath 'flat'
        $count = 1500
        New-FlatFixture -Path $target -Count $count

        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddMilliseconds(250))
        $result = Remove-WacFilesByPattern -Category 'patexpire' -Path $target -Pattern @('*.tmp')

        Assert-True $result.Attempted
        # skipDeadline is what the run report raises to the Incomplete outcome. Without it this
        # target reads as an ordinary clean success that merely happened to delete fewer files.
        Assert-True ($result.SkippedDeadline -ge 1) 'the matched-file loop never noticed the deadline pass'
        Assert-True ([int]$result.FilesDeleted -lt $count) `
            ('every matched file was deleted past the deadline ({0} of {1})' -f $result.FilesDeleted, $count)
        Assert-True ((@(Get-ChildItem -LiteralPath $target -File).Count) -gt 0) `
            'the pattern emptied the whole directory past its deadline'
    }
    finally {
        Reset-WacTestDeadline
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A live deadline lets the same pattern target finish' {
    # The control. Without it, "always stop early" would satisfy the case above.
    $sandbox = New-TestSandbox -Prefix 'deadline-pattern-live'
    try {
        $target = Join-Path -Path $sandbox -ChildPath 'flat'
        New-FlatFixture -Path $target -Count 400

        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddMinutes(10))
        $result = Remove-WacFilesByPattern -Category 'patlive' -Path $target -Pattern @('*.tmp')

        Assert-True $result.Attempted
        Assert-Equal 400 ([int]$result.FilesDeleted) 'the pattern stopped even though the budget was live'
        Assert-Equal 0 ([int]$result.SkippedDeadline)
        Assert-Equal 0 (@(Get-ChildItem -LiteralPath $target -File).Count)
    }
    finally {
        Reset-WacTestDeadline
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'An expired budget stops the FINAL root deletion, even with the tree already empty' {
    <#
        Both directory passes break out on expiry, so -DeleteRoot used to fire on a tree that had
        just been abandoned: one more mutation, performed entirely past the budget, at the single
        point where "it is almost done anyway" is most tempting to wave through.

        The budget is expired from the delete seam rather than by waiting, so the case is exact
        rather than timing-dependent: the tree is provably EMPTY and the clock provably out, which
        is the only state in which the old code would really have removed the root.
    #>
    $sandbox = New-TestSandbox -Prefix 'deadline-deleteroot'
    try {
        $target = Join-Path -Path $sandbox -ChildPath 'target'
        [void][System.IO.Directory]::CreateDirectory($target)
        [System.IO.File]::WriteAllText((Join-Path -Path $target -ChildPath 'only.tmp'), 'x')

        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddMinutes(10))
        Set-WacBoundDeleteOverride -ScriptBlock {
            param($longPath, $expected, $openReparsePoint, $win32, $ntStatus)
            [void]$expected; [void]$openReparsePoint
            $win32.Value = 0
            $ntStatus.Value = 0

            # The real removal, so the tree genuinely empties; only the syscall is stubbed.
            if ([System.IO.Directory]::Exists($longPath)) { [System.IO.Directory]::Delete($longPath, $false) }
            else { [System.IO.File]::Delete($longPath) }

            # ...and the budget runs out the instant the last child is gone.
            Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddMinutes(-1))
            return 0
        }

        try { $result = Remove-WacTree -Category 'rootexpire' -Path $target -DeleteRoot }
        finally { Set-WacBoundDeleteOverride -ScriptBlock $null }

        Assert-True $result.Attempted
        Assert-Equal 1 ([int]$result.FilesDeleted) 'the child was not swept before the budget expired'
        Assert-True ($result.SkippedDeadline -ge 1) 'the root deletion was not accounted to the deadline'
        Assert-Equal 0 ([int]$result.DirectoriesDeleted) 'the root was removed past the run deadline'
        Assert-Equal 0 ([int]$result.SkippedOutOfRoot) 'the root deletion was refused for the wrong reason'
        Assert-True (Test-Path -LiteralPath $target) 'the root was removed past the run deadline'
    }
    finally {
        Set-WacBoundDeleteOverride -ScriptBlock $null
        Reset-WacTestDeadline
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# In-process work (ledger B2-6 part B)
# ---------------------------------------------------------------------------------------------
#
# The budget used to cover external tools and the traversal only. The Delivery Optimization cmdlet,
# a CIM profile query, registry work, a Recycle Bin scan, target construction and the deployment
# walk all run INSIDE this process, and a call blocked in the OS blocks every deadline check queued
# behind it. These cases pin the mechanism that bounds them.

Test-Case 'Invoke-WacBounded returns the block output and succeeds inside its bound' {
    try {
        Reset-WacTestDeadline
        $result = Invoke-WacBounded -ScriptBlock { param($a, $b) $a + $b } -ArgumentList @(2, 5) -TimeoutMs 30000

        Assert-Equal 'Succeeded' $result.Outcome
        Assert-True $result.Started
        Assert-False $result.TimedOut
        Assert-False $result.HadErrors
        Assert-Equal 7 ([int]$result.Output[0])
    }
    finally {
        Reset-WacTestDeadline
    }
}

Test-Case 'Invoke-WacBounded cuts off in-process work that blocks, and calls it Incomplete' {
    try {
        Reset-WacTestDeadline

        # Thread.Sleep, not Start-Sleep: a cooperative check cannot see this, which is exactly the
        # class of call the run budget used to miss. Kept to four seconds so the abandoned runspace
        # thread finishes on its own well inside the suite.
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-WacBounded -ScriptBlock { [System.Threading.Thread]::Sleep(4000); 'never' } -TimeoutMs 500
        $watch.Stop()

        Assert-Equal 'Incomplete' $result.Outcome 'blocked work that was cut off must never read as success'
        Assert-True $result.Started
        Assert-True $result.TimedOut
        Assert-Equal 0 @($result.Output).Count
        Assert-True ($watch.Elapsed.TotalMilliseconds -lt 3500) `
            ('the bound was not enforced: ' + [int]$watch.Elapsed.TotalMilliseconds + ' ms')
    }
    finally {
        Reset-WacTestDeadline
    }
}

Test-Case 'An expired run budget refuses to schedule new in-process work' {
    try {
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddMinutes(-1))

        $result = Invoke-WacBounded -ScriptBlock { 'ran anyway' } -TimeoutMs 30000

        Assert-Equal 'Incomplete' $result.Outcome
        Assert-False $result.Started 'work was scheduled after the run budget expired'
        Assert-True $result.TimedOut
        Assert-Equal 0 @($result.Output).Count
    }
    finally {
        Reset-WacTestDeadline
    }
}

Test-Case 'A bounded rollback can still run after the budget is gone' {
    # Expiry has to stop NEW work without stopping the cleanup that expiry itself makes necessary,
    # so rollback carries its own explicit bound.
    try {
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddMinutes(-1))

        $result = Invoke-WacBounded -ScriptBlock { 'rolled back' } -TimeoutMs 30000 -IgnoreRunBudget

        Assert-Equal 'Succeeded' $result.Outcome
        Assert-True $result.Started
        Assert-Equal 'rolled back' ([string]$result.Output[0])
    }
    finally {
        Reset-WacTestDeadline
    }
}

Test-Case 'A terminating error inside bounded work is Failed, never Succeeded' {
    try {
        Reset-WacTestDeadline
        $result = Invoke-WacBounded -ScriptBlock { throw 'the step broke' } -TimeoutMs 30000

        Assert-Equal 'Failed' $result.Outcome
        Assert-True $result.Started
        Assert-False $result.TimedOut
        Assert-True ($result.Error -match 'the step broke') ('error was: ' + $result.Error)
    }
    finally {
        Reset-WacTestDeadline
    }
}

Test-Case 'Bounded work reaches this module, and a non-terminating error is reported not swallowed' {
    try {
        Reset-WacTestDeadline

        # The module import is the default, so a block can call the project's own helpers.
        $resolved = Invoke-WacBounded -ScriptBlock { param($p) Get-WacNormalizedPath -Path $p } `
            -ArgumentList @('c:\temp\') -TimeoutMs 30000
        Assert-Equal 'Succeeded' $resolved.Outcome ('error was: ' + $resolved.Error)
        Assert-Equal 'C:\temp' ([string]$resolved.Output[0]) 'the block could not reach the module'

        # A non-terminating error did not stop the work, so the outcome stays Succeeded - but it is
        # handed back rather than dropped, which is what lets the caller decide.
        $noisy = Invoke-WacBounded -TimeoutMs 30000 -ScriptBlock {
            Get-Item -LiteralPath 'C:\wac-does-not-exist-4f2a' -ErrorAction Continue
            'finished anyway'
        }
        Assert-Equal 'Succeeded' $noisy.Outcome
        Assert-True $noisy.HadErrors 'the error stream was swallowed'
        Assert-True ([bool]$noisy.Error) 'an error was recorded with no text to explain it'
        Assert-Equal 'finished anyway' ([string]$noisy.Output[0])
    }
    finally {
        Reset-WacTestDeadline
    }
}

Complete-TestRun
