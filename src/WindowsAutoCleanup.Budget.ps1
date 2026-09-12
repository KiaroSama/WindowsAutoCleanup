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

function Set-WacDeadline {
    param([Parameter(Mandatory = $true)][datetime]$DeadlineUtc)
    $script:DeadlineUtc = $DeadlineUtc
}

function Get-WacRemainingMs {
    <#
    .SYNOPSIS
        Milliseconds left in the overall run budget, or [int]::MaxValue when no budget is armed.
    #>
    if (-not $script:DeadlineUtc) { return [int]::MaxValue }

    $remaining = ($script:DeadlineUtc - (Get-Date).ToUniversalTime()).TotalMilliseconds
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

# ---------------------------------------------------------------------------------------------
# Abandoned mutators
# ---------------------------------------------------------------------------------------------

# Abandoning a runspace stuck inside a blocking NATIVE call is not termination and never was
# (ledger WAC-06R). PowerShell.Stop() cannot interrupt one and Thread.Abort does not exist on
# .NET Core, so the thread keeps running whatever it was doing while the caller moves on.
#
# For a blocking READ - a CIM query, a registry snapshot, a Recycle Bin scan - that costs two or
# three threads and nothing else, which is the trade this project accepts. For a block that MUTATES
# it is a different fact entirely: the run would schedule the next mutation on top of one that is
# still in progress. External mutators are not affected because every one of them is a child process
# under job ownership, where a timeout is a proven TerminateJobObject rather than an abandonment.
# This counter covers the remaining case - an in-process block that writes.
$script:AbandonedMutatorCount = 0

function Reset-WacAbandonedMutator { $script:AbandonedMutatorCount = 0 }

function Get-WacAbandonedMutatorCount { return [int]$script:AbandonedMutatorCount }

function Add-WacAbandonedMutator {
    $script:AbandonedMutatorCount++
    return [int]$script:AbandonedMutatorCount
}

function Test-WacMutationAllowed {
    <#
    .SYNOPSIS
        $false once a mutating bounded block has been abandoned without proof that it stopped.
    .DESCRIPTION
        Fail-closed and deliberately not self-clearing: nothing in this process can observe the
        abandoned thread finishing, so there is no evidence that would justify clearing it. The run
        reports the remaining mutations as unfinished rather than racing one it cannot see.
    #>
    return ($script:AbandonedMutatorCount -eq 0)
}
