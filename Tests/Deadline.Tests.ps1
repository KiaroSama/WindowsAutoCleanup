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

Complete-TestRun
