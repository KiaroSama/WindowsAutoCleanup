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
        Assert-True (-not $result.Started) 'work was scheduled on a runspace that never opened'
        Assert-Equal 0 (@($result.Output).Count) 'a block that must never run produced output'

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

Complete-TestRun
