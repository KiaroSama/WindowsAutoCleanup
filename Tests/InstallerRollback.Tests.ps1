#Requires -Version 5.1
<#
.SYNOPSIS
    What the installer leaves behind when a step between the swap and the final assertion fails
    (ledger G2-b, G2-c).

.DESCRIPTION
    The REAL Install-WindowsAutoCleanupTask.ps1 runs here, unmodified, over the stub tree that
    _InstallerRollbackRig.ps1 builds - read that file for the mechanism.

    Each scenario asks the same question: is the pair (registered task, deployment on disk) still
    consistent afterwards, or was the live tree conservatively retained because something could not
    be proven? What the installer does once the pair IS consistent and only its transaction records
    are not lives in InstallerCommitExit.Tests.ps1.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_InstallerRollbackRig.ps1')

Test-Case 'A registration that fails after the old task was removed restores BOTH the tree and the task' {
    # Ledger G2-c. Rollback used to restore the deployment and unregister whatever this run
    # registered, and stop there - the task the upgrade had already removed to make room was simply
    # gone, on a machine the installer had just reported as rolled back.
    $sandbox = New-TestSandbox -Prefix 'rb-register'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Absent,Absent,Found' -Remove 'Verified' -Register 'throw'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacInstalledTask\|Verified\|captured=True$') ($run.Journal -join ' / ')
        Assert-True (Test-JournalHas -Run $run -Pattern '^Switch-WacDeploymentStage$') ($run.Journal -join ' / ')
        Assert-True (Test-JournalHas -Run $run -Pattern '^Restore-WacDeploymentPrevious$') ($run.Journal -join ' / ')

        # The exact definition that was captured, put back through the scheduler and read back.
        Assert-True (Test-JournalHas -Run $run -Pattern ([regex]::Escape('Register-ScheduledTask|xml|' + (Get-CapturedTaskXml -Sandbox $sandbox)))) `
            ($run.Journal -join ' / ')
        Assert-True ($run.ConsoleText -match 're-registered and verified') $run.Console

        # And the commit never happened: the previous tree is not thrown away on a failed run.
        Assert-False (Test-JournalHas -Run $run -Pattern '^Remove-WacDeploymentPrevious$') ($run.Journal -join ' / ')

        # Order matters: the tree the restored task points into has to be back before the task is.
        $restore = [array]::IndexOf($run.Journal, 'Restore-WacDeploymentPrevious')
        $reregister = @(0..($run.Journal.Count - 1) | Where-Object { $run.Journal[$_] -match '^Register-ScheduledTask\|xml' })
        Assert-True ($reregister.Count -eq 1 -and $restore -lt $reregister[0]) `
            ('the task was restored before the tree it runs: ' + ($run.Journal -join ' / '))
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A rollback that cannot prove the new task is gone KEEPS the deployment it may reference' {
    # Deleting the tree under a registration that may still point at it turns a recoverable state
    # into a scheduled task that fails every night with a missing file.
    $sandbox = New-TestSandbox -Prefix 'rb-unverified'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Bad,Found' -Remove 'Verified,Unverified'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacInstalledTask\|Unverified') ($run.Journal -join ' / ')
        Assert-False (Test-JournalHas -Run $run -Pattern '^Restore-WacDeploymentPrevious$') `
            ('the deployment was rolled back under a task whose removal was never proven: ' + ($run.Journal -join ' / '))
        Assert-False (Test-JournalHas -Run $run -Pattern '^Remove-WacDeploymentPrevious$') ($run.Journal -join ' / ')
        Assert-True ($run.ConsoleText -match 'KEPT') $run.Console
        Assert-True ($run.ConsoleText -match 'rollback is INCOMPLETE') $run.Console
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A rollback whose scheduler will not answer KEEPS the deployment too' {
    # Ledger G2-b at its sharpest: "the query failed" is not "there is no task", and a rollback that
    # reads it as one deletes the tree out from under a registration it never saw.
    $sandbox = New-TestSandbox -Prefix 'rb-failed'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Bad,Failed' -Remove 'Verified'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Get-WacInstalledTask\|Failed$') ($run.Journal -join ' / ')
        Assert-False (Test-JournalHas -Run $run -Pattern '^Restore-WacDeploymentPrevious$') `
            ('the deployment was rolled back on an unanswered lookup: ' + ($run.Journal -join ' / '))
        Assert-True ($run.ConsoleText -match 'could not be queried') $run.Console
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'An upgrade refuses before the swap when the scheduler cannot be queried at all' {
    # Staging already clears the .staging and .previous slots, which is a deletion, so a lookup that
    # cannot be answered has to stop the run before that - not after.
    $sandbox = New-TestSandbox -Prefix 'rb-discovery'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Failed'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-False (Test-JournalHas -Run $run -Pattern '^New-WacDeploymentStage$') `
            ('the run staged a deployment on an unanswered lookup: ' + ($run.Journal -join ' / '))
        Assert-False (Test-JournalHas -Run $run -Pattern '^Switch-WacDeploymentStage$') ($run.Journal -join ' / ')
        Assert-False (Test-JournalHas -Run $run -Pattern '^Register-ScheduledTask') ($run.Journal -join ' / ')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'An old task whose definition cannot be captured is left registered and nothing goes live' {
    # A removal that could not be undone is not a step an upgrade is allowed to take.
    $sandbox = New-TestSandbox -Prefix 'rb-nocapture'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found' -Capture 'no'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 7 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern 'captured=False') ($run.Journal -join ' / ')
        Assert-False (Test-JournalHas -Run $run -Pattern '^Switch-WacDeploymentStage$') `
            ('a refused conflict still swapped the tree into place: ' + ($run.Journal -join ' / '))
        Assert-False (Test-JournalHas -Run $run -Pattern '^Register-ScheduledTask') ($run.Journal -join ' / ')
        Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacDeployment\|') 'the staged tree was left behind after the refusal'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A clean upgrade commits, rolls nothing back, and the second identical run is still clean' {
    # The benign steady state. A machine where everything works must not be turned into a refusal or
    # an incomplete by any of the guards above, on the first run or on the one after it.
    $sandbox = New-TestSandbox -Prefix 'rb-clean'
    try {
        New-RollbackSandbox -Sandbox $sandbox

        foreach ($pass in @('first', 'second')) {
            $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Found' -Remove 'Verified'

            Assert-False $run.TimedOut ('{0} pass: the installer never finished inside its bound' -f $pass)
            Assert-Equal 0 $run.ExitCode ('{0} pass: {1}' -f $pass, $run.Console)
            Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacDeploymentPrevious$') `
                ('{0} pass: the previous tree was never discarded, so the install did not commit' -f $pass)
            Assert-False (Test-JournalHas -Run $run -Pattern '^Restore-WacDeploymentPrevious$') `
                ('{0} pass: a successful install rolled itself back' -f $pass)
            Assert-False (Test-JournalHas -Run $run -Pattern '^Register-ScheduledTask\|xml') `
                ('{0} pass: a successful install re-registered the old task' -f $pass)
            Assert-False ($run.ConsoleText -match 'Refused|refused|INCOMPLETE') `
                ('{0} pass: a benign upgrade reported a refusal: {1}' -f $pass, $run.Console)
            Assert-True ($run.ConsoleText -match 'Final status: success') ('{0} pass: {1}' -f $pass, $run.Console)
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A conflict phase that removed a task before it refused puts that task back' {
    # The removal happens one phase before the swap, so a refusal there leaves no deployment to roll
    # back - but the machine has still lost a registration to make room for one that will now never
    # exist. Whatever was captured has to go back on the way out.
    $sandbox = New-TestSandbox -Prefix 'rb-conflict'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Absent,Found' -Remove 'Unverified'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacInstalledTask\|Unverified') ($run.Journal -join ' / ')
        Assert-True (Test-JournalHas -Run $run -Pattern ([regex]::Escape('Register-ScheduledTask|xml|' + (Get-CapturedTaskXml -Sandbox $sandbox)))) `
            ('the removed task was not put back: ' + ($run.Journal -join ' / '))
        Assert-False (Test-JournalHas -Run $run -Pattern '^Switch-WacDeploymentStage$') `
            ('a refused conflict phase still swapped the tree into place: ' + ($run.Journal -join ' / '))
        Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacDeployment\|.*\.staging$') `
            ('the staged tree was left behind: ' + ($run.Journal -join ' / '))
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A budget that runs out before the staging phase leaves the machine untouched' {
    # The advertised child budget used to be armed by Initialize-WacRun and then read by nothing:
    # the parent waited 40 minutes for a 30-minute deadline no operation ever observed. The first
    # check sits before anything is inspected, the second before the tree is copied.
    $sandbox = New-TestSandbox -Prefix 'rb-budget-early'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Found' -Budget 1

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True ($run.ConsoleText -match 'run budget expired before the runtime was staged') $run.Console

        # The margin is what makes the deadline enforceable: without it the budget the phases stop
        # at is the same instant the rollback would have to start from.
        Assert-True (Test-JournalHas -Run $run -Pattern '^Initialize-WacRun\|budget=30\|margin=600$') `
            ('the child budget was armed without a shutdown margin: ' + ($run.Journal -join ' / '))

        foreach ($forbidden in @('^New-WacDeploymentStage$', '^Switch-WacDeploymentStage$', '^Register-ScheduledTask')) {
            Assert-False (Test-JournalHas -Run $run -Pattern $forbidden) `
                ('an expired budget still reached ' + $forbidden + ': ' + ($run.Journal -join ' / '))
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A budget that runs out after the swap rolls the tree and the task back instead of registering' {
    # The late-mutation case at the phase level: the new tree IS live by the time the budget goes,
    # so stopping is not enough - the swap has to be undone and the registration this upgrade
    # removed to make room has to go back. Index 5 is the check inside the rollback try.
    $sandbox = New-TestSandbox -Prefix 'rb-budget-late'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Absent,Absent,Found' -Budget 5

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Switch-WacDeploymentStage$') `
            ('the budget expired before the swap, so this case proves nothing about undoing one: ' + ($run.Journal -join ' / '))
        Assert-False (Test-JournalHas -Run $run -Pattern '^Register-ScheduledTask\|task$') `
            ('the task was registered with no budget left to read it back: ' + ($run.Journal -join ' / '))
        Assert-True (Test-JournalHas -Run $run -Pattern '^Restore-WacDeploymentPrevious$') `
            ('the live tree was left swapped after the budget expired: ' + ($run.Journal -join ' / '))
        Assert-True (Test-JournalHas -Run $run -Pattern ([regex]::Escape('Register-ScheduledTask|xml|' + (Get-CapturedTaskXml -Sandbox $sandbox)))) `
            ('the task the upgrade removed was not put back: ' + ($run.Journal -join ' / '))
        Assert-False (Test-JournalHas -Run $run -Pattern '^Remove-WacDeploymentPrevious$') `
            ('the rollback point was discarded on a run that did not commit: ' + ($run.Journal -join ' / '))
        Assert-True ($run.ConsoleText -match 'budget expired after the swap') $run.Console
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A capture that cannot be made durable leaves the machine exactly as it was found' {
    # Ledger WAC-02R, at the phase level. The unregister is what costs the machine its registration,
    # so the record of what is about to be removed has to be on disk FIRST - and when it cannot be
    # written, the upgrade stops before it has changed anything at all.
    $sandbox = New-TestSandbox -Prefix 'rb-record-fail'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Found' -Remove 'Verified' -Record 'fail'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Write-WacTaskCaptureRecord\|1$') `
            ('the conflict phase never tried to record what it was about to remove: ' + ($run.Journal -join ' / '))
        Assert-True ($run.ConsoleText -match 'left registered and nothing was changed') $run.Console

        foreach ($forbidden in @('^Switch-WacDeploymentStage$', '^Register-ScheduledTask', '^Remove-WacDeploymentPrevious$')) {
            Assert-False (Test-JournalHas -Run $run -Pattern $forbidden) `
                ('a run that could not record its capture still reached ' + $forbidden + ': ' + ($run.Journal -join ' / '))
        }

        # And no record was left behind either: a write that failed leaves nothing to reconcile.
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $sandbox -ChildPath 'WindowsAutoCleanup.taskcapture.json')) `
            'a record survived the write that failed'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A clean upgrade records the capture, commits, and ends the transaction' {
    # The steady state of the new record: written before the removal, deleted once a registration
    # this run read back stands in place of the one it removed. Left behind, it would send every
    # later run looking for a task that is not missing.
    $sandbox = New-TestSandbox -Prefix 'rb-record-clean'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $record = Join-Path -Path $sandbox -ChildPath 'WindowsAutoCleanup.taskcapture.json'
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Found' -Remove 'Verified'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 0 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Write-WacTaskCaptureRecord\|1$') ($run.Journal -join ' / ')
        Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacTaskCaptureRecord$') `
            ('the committed install left its capture transaction open: ' + ($run.Journal -join ' / '))
        Assert-False (Test-Path -LiteralPath $record) 'the committed install left its capture record on disk'

        # Order: the record is written before the task is removed, and ended only after the commit.
        $write = [array]::IndexOf($run.Journal, 'Write-WacTaskCaptureRecord|1')
        $remove = @(0..($run.Journal.Count - 1) | Where-Object { $run.Journal[$_] -match '^Remove-WacInstalledTask\|' })
        $commit = [array]::IndexOf($run.Journal, 'Remove-WacDeploymentPrevious')
        $ended = [array]::IndexOf($run.Journal, 'Remove-WacTaskCaptureRecord')
        Assert-True ($remove.Count -eq 1 -and $remove[0] -lt $write) `
            ('the record was written outside the removal it describes: ' + ($run.Journal -join ' / '))
        Assert-True ($commit -ge 0 -and $commit -lt $ended) `
            ('the capture transaction ended before the install committed: ' + ($run.Journal -join ' / '))
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A run that finds a capture record re-registers the lost task before it stages anything' {
    # The defect, at the phase level: an earlier run removed the registration and died, so the record
    # is on disk and the scheduler reports nothing. The next run has to put the task back BEFORE it
    # stages - staging deletes slots and the swap replaces the tree that task would have run.
    $sandbox = New-TestSandbox -Prefix 'rb-record-reconcile'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $xml = Get-CapturedTaskXml -Sandbox $sandbox
        $record = Join-Path -Path $sandbox -ChildPath 'WindowsAutoCleanup.taskcapture.json'
        [System.IO.File]::WriteAllText($record, (ConvertTo-Json -InputObject @(@{
            TaskName = 'WindowsAutoCleanup'; TaskPath = '\WindowsAutoCleanup\'
            Definition = $xml; Captured = $true; CaptureReason = 'recorded by the run that died'
        }) -Depth 5))

        # Absent at the first lookup - the registration the dead run removed - and found from then on.
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Absent,Absent,Found,Found,Found' -Remove 'Verified'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 0 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Read-WacTaskCaptureRecord\|1$') `
            ('the run never read the record left by the one that died: ' + ($run.Journal -join ' / '))
        Assert-True (Test-JournalHas -Run $run -Pattern ([regex]::Escape('Register-ScheduledTask|xml|' + $xml))) `
            ('the lost registration was not put back: ' + ($run.Journal -join ' / '))
        Assert-True ($run.ConsoleText -match 'putting it back') $run.Console

        # Before anything was staged, and the record is gone once the task is accounted for.
        $reregister = @(0..($run.Journal.Count - 1) | Where-Object { $run.Journal[$_] -match '^Register-ScheduledTask\|xml' })
        $stage = [array]::IndexOf($run.Journal, 'New-WacDeploymentStage')
        Assert-True ($reregister.Count -eq 1 -and $stage -ge 0 -and $reregister[0] -lt $stage) `
            ('the lost task was put back after the run had already staged over it: ' + ($run.Journal -join ' / '))
        Assert-False (Test-Path -LiteralPath $record) 'the reconciled record was left on disk'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
