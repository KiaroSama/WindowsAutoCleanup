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
        [int]$Count = 700
    )

    [void][System.IO.Directory]::CreateDirectory($Path)
    for ($i = 0; $i -lt $Count; $i++) {
        [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath ('f{0}.tmp' -f $i)), 'x')
    }
}

# An abandoned MUTATOR is no longer only a module variable: it writes a durable marker under the
# state root so the next process on this machine learns about it. Two cases here drive that path
# deliberately, so the state root is redirected into a sandbox for the whole suite - otherwise a test
# run would leave a real quarantine marker in the operator's %ProgramData% and the next real run
# would refuse to clean anything. The variable is process-local and this suite is its own process.
$env:ProgramData = New-TestSandbox -Prefix 'deadline-state'

function Reset-WacTestDeadline {
    # Leaving an expired deadline armed would poison every later case in this process, and so would
    # a spent reserve or an outstanding abandoned mutator: all three are run-scoped state and are
    # reset together or not at all. The durable marker goes with them - Reset-WacAbandonedMutator
    # deliberately cannot retire one, so a case that wrote it removes the file itself.
    Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddHours(1))
    Reset-WacShutdownReserve
    Reset-WacAbandonedMutator
    $marker = Get-WacQuarantineMarkerPath
    if ($marker -and [System.IO.File]::Exists($marker)) { [System.IO.File]::Delete($marker) }
}

Test-Case 'A deadline that expires MID-directory stops the sweep' {
    $sandbox = New-TestSandbox -Prefix 'deadline-flat'
    try {
        $target = Join-Path -Path $sandbox -ChildPath 'flat'
        # 700, not 1500. The check interval is 256, so anything comfortably past it proves a
        # mid-directory stop; the extra 800 files were pure fixture-build cost, paid four times in
        # this file and twice again per host. Measured: 1500 -> 700 cuts this case roughly in half
        # and changes nothing it asserts.
        $count = 700
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
        $count = 700
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
        # class of call the run budget used to miss.
        #
        # The bound is 2000 ms and not the 500 it used to be. Setup - creating the runspace, opening
        # it, importing this module - is now charged to the same bound, so a 500 ms budget is one a
        # loaded eight-worker runner can legitimately spend entirely on the prologue: the block is
        # then never scheduled, Started is $false, and this case failed for a reason that is not its
        # own. That outcome is correct and has its own case ("setup that outlasts the bound schedules
        # bound"); THIS one is about work that really starts and really blocks, so it gets a budget
        # the prologue cannot swallow. The sleep stays comfortably longer than the bound and short
        # enough that the abandoned runspace thread finishes well inside the suite.
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-WacBounded -ScriptBlock { [System.Threading.Thread]::Sleep(6000); 'never' } -TimeoutMs 2000
        $watch.Stop()

        Assert-Equal 'Incomplete' $result.Outcome 'blocked work that was cut off must never read as success'
        Assert-True $result.Started 'the block was never scheduled, so nothing was cut off'
        Assert-True $result.TimedOut
        Assert-Equal 0 @($result.Output).Count
        Assert-True ($watch.Elapsed.TotalMilliseconds -lt 5000) `
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


# ---------------------------------------------------------------------------------------------
# WAC-06R: the phase that starts AFTER expiry must not get a fresh 255-entry allowance
# ---------------------------------------------------------------------------------------------

Test-Case 'the directory phase consults a deadline that expired during the sweep, before deleting anything' {
    # The counter for this phase restarted at 0 and the clock is only read on every 256th entry, so
    # a run whose budget expired during the sweep was followed by up to 255 real deletions before
    # the phase asked once. Fewer than 256 directories is the whole point: with the old code the
    # modulo never fires, so the phase never asks at all.
    #
    # Reaching that state needs care. The sweep consults the deadline once per directory it pops, so
    # simply expiring the clock early stops the sweep instead and leaves the phase nothing to delete
    # - a fixture shaped that way passes whether or not the fix is present, which is how the first
    # version of this case failed to discriminate. The sweep is therefore replaced by one that hands
    # back real directories without touching the clock, which is exactly the state the defect needs:
    # a populated work list and an already-expired budget.
    $sandbox = New-TestSandbox -Prefix 'fs-phase'
    $module = Get-Module -Name 'WindowsAutoCleanup.FileSystem'
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'root'
        [void][System.IO.Directory]::CreateDirectory($root)
        $expected = New-Object 'System.Collections.Generic.List[string]'
        foreach ($index in 1..5) {
            $directory = Join-Path -Path $root -ChildPath ('dir{0}' -f $index)
            [void][System.IO.Directory]::CreateDirectory($directory)
            [void]$expected.Add($directory)
        }

        $sweepResult = @($expected.ToArray())
        & $module {
            param($found)
            # Invoke-WacTreeSweep is defined IN this module, so Set-Item REPLACES it rather than
            # shadowing it: without keeping the original, the teardown's Remove-Item would delete a
            # shipped function out of the loaded module and break every later case in this process.
            $script:WacSavedSweep = (Get-Item -Path 'function:Invoke-WacTreeSweep').ScriptBlock

            # Deepest-first, deadline-free: the real sweep's contract minus its own clock reads.
            Set-Item -Path 'function:script:Invoke-WacTreeSweep' -Value ([scriptblock]::Create(
                'param($Root, $Stats) return @(' + (($found | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ',') + ')'))

            # The entry guard consumes the first answer, so the run is admitted and every later
            # phase sees an expired budget.
            $script:WacTestDeadlineCalls = 0
            Set-Item -Path 'function:script:Test-WacDeadlineExpired' -Value {
                $script:WacTestDeadlineCalls++
                return ($script:WacTestDeadlineCalls -gt 1)
            }
        } $sweepResult

        $result = Remove-WacTree -Category 'phase' -Path $root

        Assert-True ([bool]$result.Attempted) 'the run was not admitted, so the phase under test never ran'
        Assert-Equal 0 ([int]$result.DirectoriesDeleted) `
            'the directory phase deleted after the budget had already expired'
        Assert-True ([int]$result.SkippedDeadline -gt 0) `
            'the phase stopped for the deadline without recording that it had'

        foreach ($directory in $expected) {
            Assert-True (Test-Path -LiteralPath $directory) `
                ('a directory was removed after the deadline expired: ' + $directory)
        }
    }
    finally {
        & $module {
            # The sweep is put BACK, not deleted. Test-WacDeadlineExpired is imported from Core, so
            # its module-scope copy is a shadow and removing it simply reveals the real one again.
            if ($script:WacSavedSweep) {
                Set-Item -Path 'function:script:Invoke-WacTreeSweep' -Value $script:WacSavedSweep
                Remove-Item -Path 'variable:script:WacSavedSweep' -Force -ErrorAction SilentlyContinue
            }
            Remove-Item -Path 'function:Test-WacDeadlineExpired' -Force -ErrorAction SilentlyContinue
        }
        Reset-WacTestDeadline
    }
}

# ---------------------------------------------------------------------------------------------
# WAC-06R: setup is charged to the same bound as the work
# ---------------------------------------------------------------------------------------------

Test-Case 'setup that outlasts the bound schedules no work at all' {
    # Creating and opening the runspace is still synchronous, still costs real milliseconds, and is
    # still charged to the same bound - so a budget smaller than that prologue must schedule nothing
    # rather than grant the work its full allowance afterwards.
    #
    # A blocked MODULE IMPORT is no longer this case's business. The import moved inside the bounded
    # pipeline, where the same wait that cuts off the work cuts it off too, and
    # BudgetBoundary.Tests.ps1 proves it returns inside the bound instead of when the import
    # eventually finishes. What is left here is the prologue itself, driven with a bound no runspace
    # open can fit into.
    try {
        Reset-WacTestDeadline

        $result = Invoke-WacBounded -ScriptBlock { 'ran anyway' } -TimeoutMs 1

        Assert-Equal 'Incomplete' ([string]$result.Outcome) `
            ('setup that outlasted the bound did not report unfinished work: ' + [string]$result.Error)
        Assert-True (-not $result.Started) `
            'the block was scheduled although preparing it had already spent the entire bound'
        Assert-True ([bool]$result.TimedOut) 'an exhausted bound was not reported as a timeout'
        Assert-Equal 0 (@($result.Output).Count) 'a block that must never run produced output'
    }
    finally {
        Reset-WacTestDeadline
    }
}

# ---------------------------------------------------------------------------------------------
# WAC-06R: one recovery reserve for the whole run
# ---------------------------------------------------------------------------------------------

Test-Case 'the recovery reserve is one allowance for the whole run, not a fresh one per rollback' {
    # -IgnoreRunBudget used to mean "no bound from the run at all": every rollback got its own full
    # timeout, so N of them was an unbounded shutdown. That is how a run already told to stop
    # scheduling work still walks into Task Scheduler's four-hour kill, mid-write.
    #
    # The reserve is claimed at GRANT time, not measured afterwards, because the call that matters is
    # the one that hangs for its whole allowance - measuring after the fact would leave the reserve
    # looking untouched for the next caller.
    try {
        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddMilliseconds(-1))
        # 6000 rather than 1000, and it costs nothing: both blocks return immediately, so the whole
        # case is two runspace prologues. A 1000 ms grant, on the other hand, is one a loaded
        # eight-worker runner can spend entirely on that prologue - the first rollback was then
        # refused for lack of TIME rather than lack of RESERVE, which is not what this case is about.
        Reset-WacShutdownReserve -ReserveMs 6000

        $first = Invoke-WacBounded -ScriptBlock { 'one' } -TimeoutMs 6000 -IgnoreRunBudget
        $afterFirst = Get-WacShutdownReserveMs
        $second = Invoke-WacBounded -ScriptBlock { 'two' } -TimeoutMs 6000 -IgnoreRunBudget

        Assert-Equal 'Succeeded' ([string]$first.Outcome) 'the first rollback was refused although the reserve was full'
        Assert-Equal 'one' ([string]@($first.Output)[0]) 'the first rollback did not actually run'
        Assert-Equal 0 $afterFirst 'the first claim did not draw the reserve down'

        Assert-True (-not $second.Started) `
            'a second rollback was granted a fresh allowance after the reserve was already spent'
        Assert-Equal 'Incomplete' ([string]$second.Outcome) 'a refused rollback was not reported as unfinished work'
        Assert-True ($second.Error -match 'recovery reserve') `
            ('the refusal did not say the reserve was the reason: ' + [string]$second.Error)

        # The arithmetic itself, so a partial grant is covered without a second timed run.
        Reset-WacShutdownReserve -ReserveMs 500
        Assert-Equal 300 (Request-WacShutdownReserveMs -RequestedMs 300) 'a claim inside the reserve was not granted in full'
        Assert-Equal 200 (Request-WacShutdownReserveMs -RequestedMs 400) 'a claim larger than the remainder was not clamped to it'
        Assert-Equal 0 (Request-WacShutdownReserveMs -RequestedMs 100) 'a spent reserve still granted time'
        Assert-Equal 0 (Get-WacShutdownReserveMs) 'a spent reserve reported time it no longer has'
    }
    finally {
        Reset-WacTestDeadline
    }
}

Test-Case 'an abandoned MUTATING block closes the door on every later mutation, but not on reads' {
    # Abandoning a runspace is not termination: BeginStop is a request, and a thread inside a
    # blocking native call never comes back to honour it. For a read that costs two or three threads
    # and nothing else. For a block that WRITES it means the run would schedule the next mutation on
    # top of one still in progress, and nothing in this process can ever observe that one finishing.
    #
    # External mutators are not covered here and do not need to be: every one of them is a child
    # process under job ownership, where a timeout is a proven TerminateJobObject.
    try {
        Reset-WacTestDeadline

        # The GUARD, driven from its own state rather than from a race. Recording the abandonment is
        # the timing-dependent half and it has its own case below; everything the guard then does is
        # deterministic and costs two runspace prologues.
        # Through the module's own scope: recording an abandonment is internal, and widening the
        # shipped surface so a test can reach it is the wrong trade.
        [void](& (Get-Module -Name 'WindowsAutoCleanup.Core') { Add-WacAbandonedMutator })
        Assert-True (-not (Test-WacMutationAllowed)) 'an outstanding abandoned mutator still allowed mutation'

        $second = Invoke-WacBounded -ScriptBlock { 'wrote anyway' } -TimeoutMs 30000 -Mutating
        Assert-True (-not $second.Started) `
            'a second mutation was scheduled while an abandoned one could still be writing'
        Assert-Equal 'Incomplete' ([string]$second.Outcome) 'a refused mutation was not reported as unfinished work'
        Assert-Equal 0 (@($second.Output).Count) 'a refused mutation still produced output'
        Assert-True ($second.Error -match 'abandoned') `
            ('the refusal did not say why: ' + [string]$second.Error)

        # The control, and the reason this is a switch rather than a blanket rule: a blocked READ
        # costs threads, never correctness, so it must stay allowed.
        $read = Invoke-WacBounded -ScriptBlock { 'read ok' } -TimeoutMs 30000
        Assert-Equal 'Succeeded' ([string]$read.Outcome) 'an ordinary read was blocked by an abandoned mutator'
        Assert-Equal 'read ok' ([string]@($read.Output)[0]) 'the read did not run'
    }
    finally {
        Reset-WacTestDeadline
    }
}

Test-Case 'a mutating block that is really abandoned is what sets that flag' {
    # The one link the case above deliberately does not race: an actual timeout must RECORD the
    # abandonment. It is timing-dependent by nature - the block has to be scheduled before it can be
    # abandoned, and setup is charged to the same bound - so the budget is generous enough that a
    # loaded eight-worker runner cannot spend it all on the prologue. At 2000 ms it could, and this
    # assertion failed reading "expected [1] but got [0]" because the block never started at all.
    try {
        Reset-WacTestDeadline

        $blocked = Invoke-WacBounded -ScriptBlock { [System.Threading.Thread]::Sleep(12000); 'never' } `
            -TimeoutMs 6000 -Mutating

        Assert-True ([bool]$blocked.Started) `
            'the prologue consumed the whole bound, so nothing was scheduled and nothing could be abandoned'
        Assert-Equal 'Incomplete' ([string]$blocked.Outcome) 'an abandoned mutator was not reported as unfinished work'
        Assert-True ([bool]$blocked.TimedOut) 'the mutator was not cut off at its bound'
        Assert-Equal 1 (Get-WacAbandonedMutatorCount) 'the abandonment was not recorded against the run'
    }
    finally {
        Reset-WacTestDeadline
    }
}

Complete-TestRun
