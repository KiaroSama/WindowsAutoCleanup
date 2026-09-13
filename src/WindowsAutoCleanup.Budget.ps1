<#
.SYNOPSIS
    The run's two time budgets: the deadline ordinary work is held to, and the reserve recovery work
    draws from after that deadline is gone.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Core.psm1 alongside WindowsAutoCleanup.RunState.ps1, whose
    Initialize-WacRun arms both. Split out of that file because they answer a different question:
    RunState is where a run's identity, roots and trust are established once; this is the arithmetic
    every step consults for the rest of the run.

    Both numbers come from the same place. Initialize-WacRun subtracts -ShutdownMarginSeconds from
    the deadline so a run cannot spend its last millisecond inside a cleanup step, and arms the
    reserve with that same margin so recovery work cannot spend more than the wall clock set aside
    for it. Before that, the margin was reserved on one side and unenforced on the other.
#>

# ---------------------------------------------------------------------------------------------
# Deadline
# ---------------------------------------------------------------------------------------------

# Armed together with the deadline and never adjusted afterwards: the civil deadline says WHEN, this
# says HOW MUCH REAL TIME is left regardless of what happens to the clock.
$script:DeadlineWatch = $null
$script:DeadlineBudgetMs = 0

function Set-WacDeadline {
    param([Parameter(Mandatory = $true)][datetime]$DeadlineUtc)

    $script:DeadlineUtc = $DeadlineUtc
    $script:DeadlineBudgetMs = ($DeadlineUtc - (Get-Date).ToUniversalTime()).TotalMilliseconds
    $script:DeadlineWatch = [System.Diagnostics.Stopwatch]::StartNew()
}

function Get-WacRemainingMs {
    <#
    .SYNOPSIS
        Milliseconds left in the overall run budget, or [int]::MaxValue when no budget is armed.
    .DESCRIPTION
        Two clocks, and the SMALLER answer wins.

        The civil clock (Get-Date) is what the deadline is expressed in, and it is not monotonic: an
        NTP correction, a time-zone or DST adjustment, or a user setting the clock moves it. A
        backward jump used to hand the run extra time it had not earned - hours of it, mid-sweep -
        and a forward jump expired a run that had barely started.

        The stopwatch armed alongside the deadline measures ELAPSED time and cannot be adjusted, so
        it is what stops a backward jump granting more. Taking the minimum keeps the forward-jump
        case conservative too: a clock that now says the deadline has passed still stops the run,
        which for a tool that deletes files is the safe direction to be wrong in.
    #>
    if (-not $script:DeadlineUtc) { return [int]::MaxValue }

    $remaining = ($script:DeadlineUtc - (Get-Date).ToUniversalTime()).TotalMilliseconds

    if ($script:DeadlineWatch) {
        $monotonic = $script:DeadlineBudgetMs - $script:DeadlineWatch.Elapsed.TotalMilliseconds
        if ($monotonic -lt $remaining) { $remaining = $monotonic }
    }

    if ($remaining -le 0) { return 0 }
    if ($remaining -ge [int]::MaxValue) { return [int]::MaxValue }
    return [int]$remaining
}

function Test-WacDeadlineExpired {
    return ((Get-WacRemainingMs) -le 0)
}

# The recovery reserve. Work that must still run AFTER the run budget is gone - a rollback putting
# somebody else's registry value back, a restore undoing a half-finished swap - cannot be held to a
# budget that has already expired, or nothing would ever be undone. It also cannot be unbounded, or
# "stop scheduling new work" means nothing: N rollbacks at their own full timeout is an unbounded
# shutdown, which is exactly how a run meets Task Scheduler's four-hour kill mid-write.
#
# So there is ONE reserve for the whole run, every -IgnoreRunBudget call draws from it, and it never
# refills. A rollback still gets time after expiry; the twentieth one does not get a fresh 30 seconds.
$script:ShutdownReserveMs = 1000 * 60
$script:ShutdownSpentMs = 0

function Reset-WacShutdownReserve {
    param([int]$ReserveMs = 0)
    if ($ReserveMs -gt 0) { $script:ShutdownReserveMs = $ReserveMs }
    $script:ShutdownSpentMs = 0
}

function Get-WacShutdownReserveMs {
    <#
    .SYNOPSIS
        Milliseconds of recovery allowance the whole run has left. Never negative.
    #>
    $left = $script:ShutdownReserveMs - $script:ShutdownSpentMs
    if ($left -lt 0) { return 0 }
    return [int]$left
}

function Request-WacShutdownReserveMs {
    <#
    .SYNOPSIS
        Claims up to $RequestedMs from the run's single recovery reserve and records the claim.
    .DESCRIPTION
        Claimed at grant time rather than measured afterwards, deliberately: a block that hangs for
        its whole allowance is exactly the one that must not leave the reserve looking untouched for
        the next caller. Returns 0 once the reserve is spent, which the caller reports as unfinished
        recovery rather than silently skipping it.
    #>
    param([Parameter(Mandatory = $true)][int]$RequestedMs)

    if ($RequestedMs -le 0) { return 0 }
    $granted = $RequestedMs
    $left = Get-WacShutdownReserveMs
    if ($granted -gt $left) { $granted = $left }
    if ($granted -le 0) { return 0 }

    $script:ShutdownSpentMs += $granted
    return [int]$granted
}

function Get-WacStepTimeoutMs {
    <#
    .SYNOPSIS
        A step never gets more time than the run budget still has.
    #>
    param([Parameter(Mandatory = $true)][int]$RequestedMs)

    $remaining = Get-WacRemainingMs
    if ($RequestedMs -lt $remaining) { return $RequestedMs }
    return $remaining
}

function Request-WacWaitMs {
    <#
    .SYNOPSIS
        Milliseconds a shutdown-critical wait may take: the run budget first, then the single
        recovery reserve, then zero.
    .DESCRIPTION
        ONE rule for every wait this run cannot skip - a post-termination WaitForExit, a pipe drain,
        a tree kill. Each of them used to take a fixed allowance of its own (10 s after a kill, 5 s
        per pipe with a 250 ms floor under it), charged to nothing, so N tools cost N times that on
        top of a budget that was already gone. That is how a run meets Task Scheduler's four-hour
        kill in the middle of a write.

        While the run budget still has time the wait draws from it, which the deadline already
        accounts for. Once it is gone the wait draws from the same reserve rollbacks use, claimed at
        grant time so a wait that burns its whole allowance cannot leave the reserve looking
        untouched for the next caller. When both are spent this returns 0 - and 0 means do not wait,
        which the caller reports as an unproven stop or an incomplete read. That is the honest
        answer: a wait nobody can pay for did not happen.
    #>
    param([Parameter(Mandatory = $true)][int]$RequestedMs)

    if ($RequestedMs -le 0) { return 0 }

    $fromRun = Get-WacStepTimeoutMs -RequestedMs $RequestedMs
    if ($fromRun -gt 0) { return [int]$fromRun }

    return (Request-WacShutdownReserveMs -RequestedMs $RequestedMs)
}
