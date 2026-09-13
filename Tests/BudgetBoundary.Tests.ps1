#Requires -Version 5.1
<#
.SYNOPSIS
    WAC-06R: the bound has to be a bound on the WHOLE call, and the clock behind it has to be one
    nobody can move.

.DESCRIPTION
    Two defects that both looked fixed and were not.

    CHARGING IS NOT BOUNDING. Setup time was deducted from the budget after the runspace had already
    opened, which measures an overshoot rather than preventing one: a module whose top-level code
    blocks made `Open()` block too, so the call returned whenever initialization eventually finished
    - for a wedged initializer, never. The open is now asynchronous and waited on inside the bound,
    and an initializer that misses it is abandoned exactly the way a wedged work item is.

    A CIVIL CLOCK IS NOT A DURATION. The remaining budget was `deadline - Get-Date`, and that clock
    moves: NTP corrections, DST, a user setting the time. A backward jump handed the run extra time
    it had never earned - potentially hours, mid-sweep. A stopwatch armed with the deadline measures
    elapsed time instead, and the smaller of the two answers wins.

    Deadline.Tests.ps1 covers the budget's ordinary arithmetic and the traversal it stops; this file
    covers the BOUNDARY - what happens when setup blocks and when the clock is not trustworthy - and
    stays separate because that suite is already at its size limit.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

$script:CoreModule = Get-Module -Name 'WindowsAutoCleanup.Core'

function Reset-WacTestBudget {
    Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddHours(1))
    Reset-WacShutdownReserve
    Reset-WacAbandonedMutator
}

function New-BlockingModule {
    <#
    .SYNOPSIS
        A module whose TOP-LEVEL code blocks for $Seconds while it is being imported.
    .DESCRIPTION
        Imported by InitialSessionState, so the block happens during the runspace open - which is
        precisely the phase that used to sit outside the bound.
    #>
    param([Parameter(Mandatory = $true)][string]$Path, [int]$Seconds = 8)

    $body = "[System.Threading.Thread]::Sleep({0}); function Get-BlockingMarker {{ 'imported' }}" -f ($Seconds * 1000)
    [System.IO.File]::WriteAllText($Path, $body, (New-Object 'System.Text.UTF8Encoding' -ArgumentList $false))
}

Test-Case 'a blocked initializer returns inside the bound instead of when it eventually finishes' {
    # THE regression. The import blocks for eight seconds and the bound is under one, so the only
    # acceptable behaviour is to come back quickly and say the work was never scheduled. Charging the
    # setup afterwards - the previous fix - still waited out the whole eight seconds first.
    $sandbox = New-TestSandbox -Prefix 'budget-open'
    try {
        Reset-WacTestBudget
        $slow = Join-Path -Path $sandbox -ChildPath 'BlockingImport.psm1'
        New-BlockingModule -Path $slow -Seconds 8

        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-WacBounded -ScriptBlock { 'ran anyway' } -TimeoutMs 800 -ImportModule @($slow)
        $watch.Stop()

        Assert-Equal 'Incomplete' ([string]$result.Outcome) `
            ('an initializer that never finished was not reported as unfinished work: ' + [string]$result.Error)
        Assert-True ([bool]$result.TimedOut) 'a bound that was hit was not reported as a timeout'
        Assert-Equal 0 (@($result.Output).Count) 'a block whose import never finished produced output'

        # Started is $true, and that is the change rather than a regression: the import is the FIRST
        # STATEMENT OF THE BOUNDED PIPELINE now, so the pipeline genuinely was scheduled and the
        # conservative answer for a caller asking "could this have had effects" is yes. What must
        # never happen is waiting the import out, and that is the assertion below.
        Assert-True ([bool]$result.Started) 'the pipeline carrying the import was not scheduled at all'

        # The whole point: the CALL returned, not the import. Four seconds is half the import and
        # five times the bound - generous enough for a loaded runner, far short of waiting it out.
        Assert-True ($watch.Elapsed.TotalMilliseconds -lt 4000) `
            ('the call waited for the initializer to finish: {0} ms for an 800 ms bound' -f [int]$watch.Elapsed.TotalMilliseconds)
    }
    finally {
        Reset-WacTestBudget
    }
}

Test-Case 'an initializer that fits still runs its work normally' {
    # The control. Without it, "always abandon" would satisfy the case above and every bounded call
    # in the project would stop working.
    $sandbox = New-TestSandbox -Prefix 'budget-open-ok'
    try {
        Reset-WacTestBudget
        $quick = Join-Path -Path $sandbox -ChildPath 'QuickImport.psm1'
        New-BlockingModule -Path $quick -Seconds 0

        $result = Invoke-WacBounded -ScriptBlock { Get-BlockingMarker } -TimeoutMs 30000 -ImportModule @($quick)

        Assert-Equal 'Succeeded' ([string]$result.Outcome) ('a module that imports quickly was abandoned: ' + [string]$result.Error)
        Assert-True ([bool]$result.Started) 'the work was never scheduled'
        Assert-Equal 'imported' ([string]@($result.Output)[0]) 'the imported module was not reachable from the block'
    }
    finally {
        Reset-WacTestBudget
    }
}

Test-Case 'a clock moved backwards cannot hand the run time it never earned' {
    # `deadline - Get-Date` is a civil-time subtraction, and the civil clock moves. An NTP correction
    # or a DST adjustment backwards used to ADD that much to the remaining budget - hours, in the
    # middle of a sweep that is supposed to be stopping. The stopwatch armed with the deadline cannot
    # be moved, so the smaller of the two answers is the one that counts.
    # Get-Date is a CMDLET, so there is no ScriptBlock to save: the module-scope function created
    # below simply shadows it, and removing that function reveals the cmdlet again.
    try {
        Reset-WacTestBudget
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddSeconds(30))
        $before = Get-WacRemainingMs
        Assert-True ($before -gt 0 -and $before -le 31000) ('the armed budget was {0} ms' -f $before)

        # The machine's clock jumps two hours BACKWARD. Nothing about the run has changed.
        & $script:CoreModule {
            Set-Item -Path 'function:script:Get-Date' -Value { return ([datetime]::Now.AddHours(-2)) }
        }

        $after = Get-WacRemainingMs
        Assert-True ($after -le $before) `
            ('a backward clock jump granted extra budget: {0} ms became {1} ms' -f $before, $after)
        Assert-True ($after -le 31000) `
            ('the remaining budget grew past the whole armed budget: {0} ms' -f $after)
    }
    finally {
        & $script:CoreModule {
            Remove-Item -Path 'function:Get-Date' -Force -ErrorAction SilentlyContinue
        }
        Reset-WacTestBudget
    }
}

Test-Case 'a clock moved forwards still stops the run' {
    # The other direction, and deliberately NOT symmetric. A forward jump means the civil deadline
    # has passed; for a tool that deletes files, stopping early is the safe way to be wrong.
    try {
        Reset-WacTestBudget
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddMinutes(30))
        Assert-True ((Get-WacRemainingMs) -gt 0) 'the budget was not armed'

        & $script:CoreModule {
            Set-Item -Path 'function:script:Get-Date' -Value { return ([datetime]::Now.AddHours(2)) }
        }

        Assert-Equal 0 (Get-WacRemainingMs) 'a run whose deadline the clock says has passed kept going'
        Assert-True (Test-WacDeadlineExpired) 'the expired verdict disagreed with the remaining budget'
    }
    finally {
        & $script:CoreModule {
            Remove-Item -Path 'function:Get-Date' -Force -ErrorAction SilentlyContinue
        }
        Reset-WacTestBudget
    }
}

Test-Case 'a shutdown wait past the deadline draws from the one reserve and cannot draw twice' {
    # WAC-06R, the half that stayed open. Termination waits and pipe drains each took a FIXED
    # allowance - ten seconds after a kill, five seconds per pipe with a 250 ms floor under it -
    # charged to nothing at all. Past the deadline the run-budget clamp returned 0 and the floor
    # went straight back on top, once per pipe per tool, which is an unbounded shutdown dressed up
    # as a bounded one.
    try {
        Reset-WacTestBudget
        Reset-WacShutdownReserve -ReserveMs 4000
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddSeconds(-1))
        Assert-Equal 0 (Get-WacRemainingMs) 'the deadline under test was not actually expired'

        $first = Request-WacWaitMs -RequestedMs 5000
        Assert-Equal 4000 $first 'a wait past the deadline was not capped by what the reserve holds'
        Assert-Equal 0 (Get-WacShutdownReserveMs) 'the reserve was not debited by the wait it granted'

        # The whole point of ONE reserve: the second tool does not get a fresh allowance, and the
        # zero is the honest answer - the caller reports an unproven stop rather than waiting on
        # time nobody can pay for.
        Assert-Equal 0 (Request-WacWaitMs -RequestedMs 5000) 'a second shutdown wait was granted from an empty reserve'
    }
    finally {
        Reset-WacTestBudget
    }
}

Test-Case 'a wait inside the run budget leaves the recovery reserve alone' {
    # The control. Without it, "always charge the reserve" satisfies the case above and every
    # ordinary tool would eat the allowance rollbacks depend on.
    try {
        Reset-WacTestBudget
        Reset-WacShutdownReserve -ReserveMs 4000
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddHours(1))

        Assert-Equal 5000 (Request-WacWaitMs -RequestedMs 5000) 'a wait well inside the budget was shortened'
        Assert-Equal 4000 (Get-WacShutdownReserveMs) 'an ordinary wait spent the recovery reserve'
    }
    finally {
        Reset-WacTestBudget
    }
}

Test-Case 'a timed-out tool charges its own shutdown waits to the reserve' {
    # The CALL SITE, not the helper. An isolated gate proves the arithmetic and nothing about
    # whether Invoke-WacProcess actually asks for it, which is precisely the gap this round exists
    # to close. The child is told to sleep far past its bound, so the termination wait and both
    # pipe drains all run with the run budget already gone.
    $host5 = if ($env:WAC_PROBE_HOST) { [string]$env:WAC_PROBE_HOST } else { [string](Get-Process -Id $PID).Path }

    try {
        Reset-WacTestBudget
        Reset-WacShutdownReserve -ReserveMs 3000
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddSeconds(-1))

        $result = Invoke-WacProcess -FilePath $host5 -TimeoutMs 500 `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 300')

        Assert-True ([bool]$result.TimedOut) 'the child under test did not reach its deadline'
        Assert-True ((Get-WacShutdownReserveMs) -lt 3000) `
            ('a timed-out tool took its shutdown waits without charging the reserve: {0} ms still there' -f (Get-WacShutdownReserveMs))
    }
    finally {
        Reset-WacTestBudget
    }
}

Complete-TestRun
