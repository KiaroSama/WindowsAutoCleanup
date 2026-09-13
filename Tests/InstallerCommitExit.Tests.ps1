#Requires -Version 5.1
<#
.SYNOPSIS
    The exit code the installer really gives when the install landed but a transaction record
    outlived the commit that ended it (ledger WAC-02R).

.DESCRIPTION
    DeploymentTransactionState.Tests.ps1 proves the same rule from the installer's source text and
    its AST: both record deletions are read as results, and the incomplete branch is reached through
    them. That guards the ordering and nothing else - it would pass just as happily if the branch
    returned 0. These cases run the real installer to completion in a child process over the rig's
    stub tree and read the code that process actually exited with.

    The control earns its place as much as the two failures do: all three scenarios are the same
    clean upgrade and differ only in whether one record deletion succeeds, so an exit of 6 cannot
    have come from anywhere else in the run.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_InstallerRollbackRig.ps1')

function Assert-InstallLanded {
    <#
    .SYNOPSIS
        The shared premise: the task and the tree are in place and proven, and nothing was rolled
        back.
    .DESCRIPTION
        Without it a 6 could be any other refusal and a 1 could be a rollback, and the three cases
        would no longer differ only in the thing they name.
    #>
    param([Parameter(Mandatory = $true)]$Run)

    Assert-False $Run.TimedOut 'the installer never finished inside its bound'
    Assert-True (Test-JournalHas -Run $Run -Pattern '^Switch-WacDeploymentStage$') ($Run.Journal -join ' / ')
    Assert-True (Test-JournalHas -Run $Run -Pattern '^Register-ScheduledTask\|task$') ($Run.Journal -join ' / ')
    Assert-False (Test-JournalHas -Run $Run -Pattern '^Restore-WacDeploymentPrevious$') `
        ('the install rolled itself back, so this case proves nothing about a committed one: ' + ($Run.Journal -join ' / '))
    Assert-True ($Run.ConsoleText -match 'Scheduled task registered and verified') $Run.Console
}

Test-Case 'A clean install ends both transaction records and exits 0' {
    # The control. Everything the two cases below assert is a difference from this run.
    $sandbox = New-TestSandbox -Prefix 'ce-clean'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Found' -Remove 'Verified' -Commit 'clean'

        Assert-InstallLanded -Run $run
        Assert-Equal 0 $run.ExitCode $run.Console
        Assert-True ($run.ConsoleText -match 'Final status: success') $run.Console
        Assert-False ($run.ConsoleText -match 'Final status: incomplete') `
            ('a run with nothing left over reported an unfinished transaction: ' + $run.Console)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A swap record that outlived its own commit exits 6, not 0' {
    # The install succeeded, so this is not a rollback: it is an install whose audit state is not
    # what a success would be claiming, because the next run reads a settled deployment as a
    # candidate for rollback.
    $sandbox = New-TestSandbox -Prefix 'ce-swap'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Found' -Remove 'Verified' -Commit 'swap-stays'

        Assert-InstallLanded -Run $run
        Assert-Equal 6 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacDeploymentPrevious$') ($run.Journal -join ' / ')
        Assert-True ($run.ConsoleText -match 'Final status: incomplete') $run.Console
        Assert-True ($run.ConsoleText -match 'transaction record beside the deployment outlived the install that committed it') $run.Console

        # Which record it was: the capture half ended cleanly here, so its own line must be absent.
        Assert-False ($run.ConsoleText -match 'task-capture record beside the deployment could not be deleted') `
            ('the capture half ended cleanly, so this 6 is not being attributed to the record that caused it: ' + $run.Console)
        Assert-False ($run.ConsoleText -match 'Final status: success') `
            ('an install that left a record behind still signed off as success: ' + $run.Console)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A capture record that outlived its own commit exits 6, not 0' {
    # The other half of the same rule, and the one with a file to point at: the record is still on
    # disk, so a later run goes looking for a registration that is not missing.
    $sandbox = New-TestSandbox -Prefix 'ce-capture'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $record = Join-Path -Path $sandbox -ChildPath 'WindowsAutoCleanup.taskcapture.json'
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Found' -Remove 'Verified' -Commit 'capture-stays'

        Assert-InstallLanded -Run $run
        Assert-Equal 6 $run.ExitCode $run.Console
        Assert-True ($run.ConsoleText -match 'Final status: incomplete') $run.Console
        Assert-True ($run.ConsoleText -match 'task-capture record beside the deployment could not be deleted') $run.Console
        Assert-False ($run.ConsoleText -match 'Final status: success') `
            ('an install that left a record behind still signed off as success: ' + $run.Console)

        Assert-True (Test-Path -LiteralPath $record -PathType Leaf) `
            'the capture record was deleted after all, so nothing outlived the commit and this case proves nothing'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
