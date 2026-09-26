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

function Set-BudgetExpiryAfterLaunch {
    param([switch]$Unowned)
    # Warm compilation separately: these cases measure running-child teardown, not cold setup.
    Assert-True (Initialize-WacOwnedProcessNative) 'the native fixture launcher could not be initialized'
    if ($Unowned) { [void](Set-WacOwnedProcessFault -Phase JobAssign) }
    Set-WacOwnedProcessLauncher -Launcher {
        param($FilePath, $ArgumentList)
        Set-WacOwnedProcessLauncher -Launcher $null
        $launch = Start-WacOwnedProcess -FilePath $FilePath -ArgumentList $ArgumentList
        # The unowned fixture measures drains after root exit, not a pre-start timeout.
        if (-not $launch.Owned) { [void][WacOwnedProcess]::WaitForExit($launch.Process, 10000) }
        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddSeconds(-1))
        return $launch
    }
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

        # Two shapes are correct, and which one a run gets depends on the machine, not the code.
        # Normally the pipeline carrying the import was scheduled (Started, conservatively: it could
        # have had effects). On a loaded runner, creating and opening the runspace alone can spend
        # the whole 800 ms - measured twice on windows-2025 / 5.1 in CI on 2026-09-26 - and then
        # nothing was scheduled at all. What must never happen is waiting the import out, and that
        # is the assertion below; each shape is still checked for being the one it claims to be.
        if (-not [bool]$result.Started) {
            Assert-True ([string]$result.Error -match 'Preparing the bounded work used') `
                ('work that was never scheduled did not say its preparation spent the bound: ' + [string]$result.Error)
        }

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
        Set-BudgetExpiryAfterLaunch

        $result = Invoke-WacProcess -FilePath $host5 -TimeoutMs 500 `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 300')

        Assert-True ([bool]$result.TimedOut) 'the child under test did not reach its deadline'
        Assert-True ((Get-WacShutdownReserveMs) -lt 3000) `
            ('a timed-out tool took its shutdown waits without charging the reserve: {0} ms still there' -f (Get-WacShutdownReserveMs))
    }
    finally {
        Set-WacOwnedProcessLauncher -Launcher $null
        Reset-WacTestBudget
    }
}

function New-PipeHolderArgument {
    <#
    .SYNOPSIS
        A root that starts a grandchild inheriting its stdout/stderr, then exits 0 immediately.
    .DESCRIPTION
        The grandchild keeps the pipes open, so both reads are still outstanding when the root is
        already gone - which is the only shape in which the drain budget is actually spent. The
        marker file carries the grandchild's id so the case can reap it.
    #>
    param([Parameter(Mandatory = $true)][string]$MarkerPath, [int]$HoldSeconds = 30, [int]$RootSleepMs = 0)

    $source = ("`$p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','ping -n {0} 127.0.0.1 >nul' " +
        "-NoNewWindow -PassThru; Set-Content -LiteralPath '{1}' -Value ([string]`$p.Id); " +
        "Start-Sleep -Milliseconds {2}; exit 0") -f $HoldSeconds, $MarkerPath, $RootSleepMs
    return @('-NoProfile', '-NonInteractive', '-Command', $source)
}

function Stop-MarkedChild {
    param([Parameter(Mandatory = $true)][string]$MarkerPath)

    if (-not (Test-Path -LiteralPath $MarkerPath)) { return 0 }
    $recorded = (Get-Content -LiteralPath $MarkerPath -Raw).Trim()
    if ($recorded -notmatch '^[0-9]+$') { return 0 }
    Stop-Process -Id ([int]$recorded) -Force -ErrorAction SilentlyContinue
    return [int]$recorded
}

Test-Case 'two held pipes drain against ONE grant, not one grant each' {
    # WAC-06R. Request-WacWaitMs CLAIMS what it grants - a reserve that cannot refill only means
    # something if the claim matches the spend - and the same grant was passed to BOTH waits. With
    # a grandchild holding both pipes neither read ever completes, so the run spent up to DOUBLE the
    # allowance it had reserved. The grant is a deadline now, and the two waits share it.
    $sandbox = New-TestSandbox -Prefix 'budget-drain'
    $marker = Join-Path -Path $sandbox -ChildPath 'grandchild.pid'
    $host5 = if ($env:WAC_PROBE_HOST) { [string]$env:WAC_PROBE_HOST } else { [string](Get-Process -Id $PID).Path }
    try {
        Reset-WacTestBudget
        Reset-WacShutdownReserve -ReserveMs 3000
        Set-BudgetExpiryAfterLaunch -Unowned

        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-WacProcess -FilePath $host5 -TimeoutMs 20000 `
            -ArgumentList (New-PipeHolderArgument -MarkerPath $marker) -Component 'Test'
        $watch.Stop()

        Assert-True ([bool]$result.Started) 'the fixture root never started, so the case proves nothing'
        Assert-False ([bool]$result.OutputComplete) `
            'the grandchild did not hold the pipes, so no drain budget was spent and the case proves nothing'

        # The whole call, not just the drain: 3000 ms was reserved, so anything near 6000 is the two
        # waits each taking the full grant. The ceiling is generous enough for a loaded runner and
        # still far below what the defect produced.
        # BOTH bounds. Without the lower one this case passes when the drain was granted nothing at
        # all - which is exactly how it first passed, because an unrelated per-launch claim had
        # already emptied the reserve.
        Assert-True ($watch.Elapsed.TotalMilliseconds -gt 2000) `
            ('the drain was granted nothing, so this case proves nothing: {0} ms' -f [int]$watch.Elapsed.TotalMilliseconds)
        Assert-True ($watch.Elapsed.TotalMilliseconds -lt 5500) `
            ('the two drains spent more than the one grant that was reserved: {0} ms' -f [int]$watch.Elapsed.TotalMilliseconds)
    }
    finally {
        Set-WacOwnedProcessLauncher -Launcher $null
        [void](Set-WacOwnedProcessFault -Phase None)
        [void](Stop-MarkedChild -MarkerPath $marker)
        Reset-WacTestBudget
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a root that exits leaves the tree what is LEFT of the operation, not a fresh budget' {
    # The other half. A root exiting normally used to hand the tree another full -TimeoutMs, so a
    # tool given 4 seconds could legitimately occupy twelve: four for the root, four more for the
    # tree, and a drain on top. One operation, one deadline.
    $sandbox = New-TestSandbox -Prefix 'budget-tree'
    $marker = Join-Path -Path $sandbox -ChildPath 'grandchild.pid'
    $host5 = if ($env:WAC_PROBE_HOST) { [string]$env:WAC_PROBE_HOST } else { [string](Get-Process -Id $PID).Path }
    try {
        Reset-WacTestBudget
        Assert-True (Initialize-WacOwnedProcessNative)

        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        # The root holds MOST of the budget on purpose: what is left for the tree is then about a
        # second, while a fresh budget would be another four - so the two answers are seconds apart
        # rather than within the noise of a loaded runner.
        $result = Invoke-WacProcess -FilePath $host5 -TimeoutMs 4000 `
            -ArgumentList (New-PipeHolderArgument -MarkerPath $marker -RootSleepMs 3000) -Component 'Test'
        $watch.Stop()

        Assert-True ([bool]$result.Started) 'the fixture root never started, so the case proves nothing'
        Assert-True ($watch.Elapsed.TotalMilliseconds -gt 3000) `
            ('the root did not hold its share of the budget, so this case proves nothing: {0} ms' -f [int]$watch.Elapsed.TotalMilliseconds)

        # One 4000 ms operation plus start-up and cleanup. A fresh tree budget on top of a root that
        # already spent three seconds is what this rules out.
        Assert-True ($watch.Elapsed.TotalMilliseconds -lt 6000) `
            ('the operation ran past one deadline: {0} ms for a 4000 ms bound' -f [int]$watch.Elapsed.TotalMilliseconds)
    }
    finally {
        [void](Stop-MarkedChild -MarkerPath $marker)
        Reset-WacTestBudget
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
