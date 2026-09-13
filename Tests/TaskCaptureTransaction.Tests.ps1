#Requires -Version 5.1
<#
.SYNOPSIS
    The transaction around the unregister an upgrade performs to make room for its own registration
    (ledger WAC-02R): the capture is durable BEFORE the task is removed, and a capture an earlier
    process never replaced is reconciled before anything else is staged.

.DESCRIPTION
    The defect this suite pins: the captured definition lived only on an in-memory result, so a
    process that died between the unregister and the first durable write of the swap left a machine
    with no registration and nothing on disk saying one had ever existed. The in-memory rollback
    died with the process.

    Nothing is registered with the live Task Scheduler. The module's own Get-ScheduledTask,
    Export-ScheduledTask and Unregister-ScheduledTask are replaced inside its scope, and
    Register-ScheduledTask is shadowed in this script's scope - which is where Restore-CapturedTask
    resolves it - so the REAL Remove-WacInstalledTask, Resolve-ConflictingTask,
    Resolve-InterruptedTaskCapture and Restore-CapturedTask run end to end against a scheduler the
    case controls. The durable record is real: %ProgramFiles% is redirected into a disposable
    sandbox and the assertions read the file the code actually wrote.

    Every ordering assertion is made against a list the stubs append to in the order they are
    called, so "the record was written before the unregister" is observed rather than inferred.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_DeployFixtures.ps1')

# The two installer parts, dot-sourced the way the installer dot-sources them: Resolve-ConflictingTask
# and Resolve-InterruptedTaskCapture live in one, the restore-and-prove path they call in the other.
. (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.InstallerTask.ps1')
. (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.InstallerRecovery.ps1')

$script:DeployModule = Get-Module -Name 'WindowsAutoCleanup.Deploy'
$script:WindowsPowerShell = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:Message = New-Object 'System.Collections.Generic.List[string]'

function Write-InstallerMessage {
    <#
    .SYNOPSIS
        The installer's console-and-log writer, which these functions call and this suite records.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Data = @{},
        [switch]$NoLog
    )

    $null = $Data, $NoLog
    [void]$script:Message.Add(('{0}|{1}' -f $Level, $Message))
}

function Set-ModuleFunctionBody {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    & $Module { param($n, $b) Set-Item -Path ('function:script:' + $n) -Value $b } $Name $Body
}

function Remove-ModuleFunctionBody {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    & $Module { param($n) if (Test-Path -LiteralPath ('function:script:' + $n)) { Remove-Item -LiteralPath ('function:script:' + $n) -Force } } $Name
}

function New-TestCapturedXml {
    <#
    .SYNOPSIS
        A captured definition in the shape Export-ScheduledTask really emits, for one deployment root.
    .DESCRIPTION
        It carries a real Exec, because the restore proof compares the action, the principal, the
        settings and the triggers the capture declares - a fixture with no Exec would exercise none
        of that and a rollback would be "proven" by a task with the right name.
    #>
    param([Parameter(Mandatory = $true)][string]$Root)

    $arguments = Get-WacTaskActionArgument -RunScript (Join-Path -Path $Root -ChildPath 'Run.ps1')

    return ('<?xml version="1.0" encoding="UTF-16"?>' +
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' +
        '<RegistrationInfo><Description>the previous task</Description></RegistrationInfo>' +
        '<Settings><Hidden>true</Hidden></Settings>' +
        ('<Actions Context="Author"><Exec><Command>{0}</Command><Arguments>{1}</Arguments><WorkingDirectory>{2}</WorkingDirectory></Exec></Actions>' -f
            [System.Security.SecurityElement]::Escape($script:WindowsPowerShell),
            [System.Security.SecurityElement]::Escape($arguments),
            [System.Security.SecurityElement]::Escape($Root)) +
        '</Task>')
}

function New-TestOwnedTask {
    <#
    .SYNOPSIS
        The registered task the captured XML above describes, in the shape the scheduler hands back.
    #>
    param([Parameter(Mandatory = $true)][string]$Root)

    $action = New-StubAction -Execute $script:WindowsPowerShell -WorkingDirectory $Root `
        -Arguments (Get-WacTaskActionArgument -RunScript (Join-Path -Path $Root -ChildPath 'Run.ps1'))

    $task = New-StubTask -TaskPath '\WindowsAutoCleanup\' -Description (Get-WacTaskDescription) -Action @($action)
    Add-Member -InputObject $task -MemberType NoteProperty -Name 'Settings' -Value ([PSCustomObject]@{ Hidden = $true })
    Add-Member -InputObject $task -MemberType NoteProperty -Name 'Principal' -Value ([PSCustomObject]@{ UserId = 'SYSTEM'; LogonType = 'ServiceAccount'; RunLevel = 'Highest' })
    Add-Member -InputObject $task -MemberType NoteProperty -Name 'Triggers' -Value @([PSCustomObject]@{ StartBoundary = '2026-01-01T20:00:00' })
    return $task
}

function New-TestScheduler {
    <#
    .SYNOPSIS
        A scheduler the case drives: what a query answers, what an export returns, and the order in
        which every call arrived.
    .DESCRIPTION
        A hashtable rather than a variable per hook, and deliberately: .GetNewClosure() captures a
        variable's VALUE, so a closure over a $script: variable never sees a later assignment to it.
        Capturing one reference and reaching through it is what lets a case change the scheduler's
        answers between assertions.
    #>
    param([Parameter(Mandatory = $true)][string]$Root)

    $behaviour = @{
        Registered = @(New-TestOwnedTask -Root $Root)
        Export = (New-TestCapturedXml -Root $Root)
        ExportThrows = $false
        RegisterThrows = $false
        Order = (New-Object 'System.Collections.Generic.List[string]')
        RegisteredXml = (New-Object 'System.Collections.Generic.List[string]')
    }
    $null = $behaviour

    Set-ModuleFunctionBody -Module $script:DeployModule -Name 'Get-ScheduledTask' -Body {
        param([string]$TaskName, [string]$TaskPath, [string]$ErrorAction)
        $null = $TaskName, $ErrorAction
        [void]$Behaviour.Order.Add('query')
        # Only the canonical folder ever holds the fixture's task; the legacy root answers empty,
        # which is the same shape the real lookup turns into Absent.
        if ($TaskPath -ne '\WindowsAutoCleanup\') { return @() }
        return @($Behaviour.Registered)
    }.GetNewClosure()

    Set-ModuleFunctionBody -Module $script:DeployModule -Name 'Export-ScheduledTask' -Body {
        param([string]$TaskName, [string]$TaskPath, [string]$ErrorAction)
        $null = $TaskName, $TaskPath, $ErrorAction
        [void]$Behaviour.Order.Add('export')
        if ($Behaviour.ExportThrows) { throw 'the scheduler refused to export the definition' }
        return $Behaviour.Export
    }.GetNewClosure()

    Set-ModuleFunctionBody -Module $script:DeployModule -Name 'Unregister-ScheduledTask' -Body {
        param([string]$TaskName, [string]$TaskPath, $Confirm, [string]$ErrorAction)
        $null = $TaskName, $TaskPath, $Confirm, $ErrorAction
        [void]$Behaviour.Order.Add('unregister')
        $Behaviour.Registered = @()
    }.GetNewClosure()

    return $behaviour
}

function Clear-TestScheduler {
    foreach ($name in @('Get-ScheduledTask', 'Export-ScheduledTask', 'Unregister-ScheduledTask')) {
        Remove-ModuleFunctionBody -Module $script:DeployModule -Name $name
    }
}

function Register-ScheduledTask {
    <#
    .SYNOPSIS
        Shadows the cmdlet for Restore-CapturedTask, which resolves it in THIS scope.
    .DESCRIPTION
        A function beats a cmdlet in command resolution, which is what lets the real restore path -
        register, read back, compare against the captured definition - run without the live
        scheduler. The XML it is given is recorded, so a case can assert that what went back is
        byte for byte what was captured.
    #>
    param($TaskName, $TaskPath, $InputObject, $Xml, [switch]$Force, $ErrorAction)

    $null = $InputObject, $Force, $ErrorAction
    [void]$script:Scheduler.Order.Add('register')
    [void]$script:Scheduler.RegisteredXml.Add([string]$Xml)
    if ($script:Scheduler.RegisterThrows) { throw 'the scheduler refused the registration' }

    $script:Scheduler.Registered = @(New-TestOwnedTask -Root $script:Scheduler.Root)
    return ([PSCustomObject]@{ TaskName = $TaskName; TaskPath = $TaskPath })
}

function Initialize-TestCase {
    <#
    .SYNOPSIS
        One scheduler, one deployment root, one clean message list, for the body of one case.
    #>
    param([Parameter(Mandatory = $true)][string]$Root)

    $script:Message.Clear()
    $script:Scheduler = New-TestScheduler -Root $Root
    $script:Scheduler.Root = $Root
    return $script:Scheduler
}

function Get-TestCaptureRecordPath {
    param([Parameter(Mandatory = $true)][string]$Root)

    return (Get-WacDeploymentJournalPath -DeploymentRoot $Root -Kind 'TaskCapture')
}

# ---------------------------------------------------------------------------------------------
# The seam: the capture is made durable before the task is unregistered
# ---------------------------------------------------------------------------------------------

Test-Case 'The capture callback runs after the export and BEFORE the unregister' {
    Invoke-InDeploymentSandbox -Prefix 'wac02r-capture-order' -Body {
        param($sandbox)

        $null = $sandbox
        $root = (Get-WacDeploymentSlotPath).Root
        $scheduler = Initialize-TestCase -Root $root
        try {
            $seen = New-Object 'System.Collections.Generic.List[object]'
            $removal = Remove-WacInstalledTask -Task (New-TestOwnedTask -Root $root) -DeploymentRoot $root -RequireDefinitionCapture -OnCaptured {
                param($capture)
                [void]$scheduler.Order.Add('durable')
                [void]$seen.Add($capture)
                return $true
            }.GetNewClosure()

            Assert-True $removal.Verified ([string]$removal.Reason)
            Assert-Equal 'export,durable,unregister,query' ($scheduler.Order -join ',') `
                'the capture was made durable somewhere other than between the export and the unregister'
            Assert-True ([bool]$removal.CaptureDurable) 'a callback that confirmed durability was not recorded as having done so'

            # The callback is handed the capture itself, not a promise of one: a record built from
            # anything less could not be re-registered by the run that finds it.
            Assert-Equal 1 $seen.Count 'the callback was not given exactly one capture'
            Assert-Equal ($scheduler.Export) ([string]$seen[0].Definition) 'the callback was handed something other than the captured definition'
        }
        finally {
            Clear-TestScheduler
        }
    }
}

Test-Case 'A capture that could not be made durable leaves the task REGISTERED' {
    # The transaction boundary. Unregistering on a record that never landed is what leaves a machine
    # with no task and nothing describing the one it lost, and leaving the task exactly as it was
    # found costs only this upgrade.
    Invoke-InDeploymentSandbox -Prefix 'wac02r-capture-refused' -Body {
        param($sandbox)

        $null = $sandbox
        $root = (Get-WacDeploymentSlotPath).Root
        $scheduler = Initialize-TestCase -Root $root
        try {
            $removal = Remove-WacInstalledTask -Task (New-TestOwnedTask -Root $root) -DeploymentRoot $root -RequireDefinitionCapture -OnCaptured {
                param($capture)
                $null = $capture
                return $false
            }

            Assert-False $removal.Removed 'a task whose capture could not be recorded was unregistered anyway'
            Assert-False $removal.Verified 'a removal that never happened was reported as verified'
            Assert-True $removal.Captured 'the definition itself was captured, so the refusal is about recording it'
            Assert-False ([bool]$removal.CaptureDurable) 'the refusal was not reported on the result'
            Assert-False ($scheduler.Order -contains 'unregister') ('the unregister ran anyway: ' + ($scheduler.Order -join ','))
            Assert-True ([string]$removal.Reason -match 'could not be recorded where a later run would find it') ([string]$removal.Reason)

            # A callback that THROWS is the same fact as one that answered no: nothing is durable.
            $scheduler.Order.Clear()
            $threw = Remove-WacInstalledTask -Task (New-TestOwnedTask -Root $root) -DeploymentRoot $root -RequireDefinitionCapture -OnCaptured {
                param($capture)
                $null = $capture
                throw 'the record could not be written'
            }
            Assert-False $threw.Removed 'a callback that threw was read as a successful durable write'
            Assert-False ($scheduler.Order -contains 'unregister') ('the unregister ran after a callback threw: ' + ($scheduler.Order -join ','))
        }
        finally {
            Clear-TestScheduler
        }
    }
}

Test-Case 'Without a callback the removal behaves exactly as it did before' {
    # The uninstaller passes no callback and must be unaffected: there is nothing to roll back to, so
    # a scheduler that will not record anything must not be able to block a removal it asked for.
    Invoke-InDeploymentSandbox -Prefix 'wac02r-capture-none' -Body {
        param($sandbox)

        $null = $sandbox
        $root = (Get-WacDeploymentSlotPath).Root
        $scheduler = Initialize-TestCase -Root $root
        try {
            $removal = Remove-WacInstalledTask -Task (New-TestOwnedTask -Root $root) -DeploymentRoot $root

            Assert-True $removal.Verified ([string]$removal.Reason)
            Assert-Equal 'export,unregister,query' ($scheduler.Order -join ',') `
                'the removal without a callback no longer takes the path it always took'
            Assert-Equal $null $removal.CaptureDurable 'a removal with no callback reported a durability verdict it never asked for'
            Assert-False (Test-Path -LiteralPath (Get-TestCaptureRecordPath -Root $root)) `
                'a removal with no callback wrote a durable capture record'
        }
        finally {
            Clear-TestScheduler
        }
    }
}

# ---------------------------------------------------------------------------------------------
# The installer's conflict phase writes the record before it removes anything
# ---------------------------------------------------------------------------------------------

Test-Case 'The conflict phase records the captured definition on disk before the unregister' {
    Invoke-InDeploymentSandbox -Prefix 'wac02r-conflict-record' -Body {
        param($sandbox)

        $null = $sandbox
        $root = (Get-WacDeploymentSlotPath).Root
        $scheduler = Initialize-TestCase -Root $root
        try {
            $conflict = Resolve-ConflictingTask -DeploymentRoot $root

            Assert-True $conflict.Ok ([string]$conflict.Reason)
            Assert-False $conflict.Refused ([string]$conflict.Reason)
            # Two queries first: the discovery lookup covers the canonical folder and the pre-1.2
            # root path, and a scheduler that answered neither would have stopped the phase.
            Assert-Equal 'query,query,export,unregister,query' ($scheduler.Order -join ',') `
                ('the conflict phase did not export before it unregistered: ' + ($scheduler.Order -join ','))

            # The record is on disk and names the task, the path and the exact definition: everything
            # a later run needs to put the registration back without this process.
            $record = Read-WacTaskCaptureRecord -DeploymentRoot $root
            Assert-Equal 'Valid' ([string]$record.State) ([string]$record.Reason)
            Assert-Equal 1 @($record.Capture).Count 'the record does not name the task that was removed'
            Assert-Equal 'WindowsAutoCleanup' ([string]@($record.Capture)[0].TaskName)
            Assert-Equal '\WindowsAutoCleanup\' ([string]@($record.Capture)[0].TaskPath)
            Assert-Equal ($scheduler.Export) ([string]@($record.Capture)[0].Definition) 'the record does not carry the captured definition'

            # And it was on disk BEFORE the unregister: the file's own write time cannot prove an
            # order, so the durable write is observed through the record the callback wrote - the
            # unregister ran only because that write returned true, which is what the refusal case
            # below proves from the other side.
            Assert-True ($scheduler.Order -contains 'unregister') ('the fixture never removed the task: ' + ($scheduler.Order -join ','))
        }
        finally {
            Clear-TestScheduler
        }
    }
}

Test-Case 'A record that cannot be written leaves the task registered and the conflict phase refusing' {
    # The write is the transaction boundary, so the machine keeps its registration and the upgrade
    # stops. Forced at the journal writer rather than by breaking the filesystem: what is under test
    # is what the caller does with a failed write, not how a write fails.
    Invoke-InDeploymentSandbox -Prefix 'wac02r-conflict-nowrite' -Body {
        param($sandbox)

        $null = $sandbox
        $root = (Get-WacDeploymentSlotPath).Root
        $scheduler = Initialize-TestCase -Root $root
        try {
            # A directory standing where the record's own temporary file has to be written. The
            # write then really fails, through the real writer, rather than through a stand-in whose
            # answer the case chose - and it is one of the shapes a machine can genuinely be in.
            [void][System.IO.Directory]::CreateDirectory((Get-TestCaptureRecordPath -Root $root) + '.new')

            $conflict = Resolve-ConflictingTask -DeploymentRoot $root

            Assert-False $conflict.Ok 'a conflict phase that could not record what it was about to remove reported success'
            Assert-False $conflict.Refused 'a failed write was reported as a refusal to touch somebody else''s task'
            Assert-True ([string]$conflict.Reason -match 'left registered and nothing was changed') ([string]$conflict.Reason)
            Assert-False ($scheduler.Order -contains 'unregister') `
                ('the task was unregistered without a durable record of it: ' + ($scheduler.Order -join ','))
            Assert-False (Test-Path -LiteralPath (Get-TestCaptureRecordPath -Root $root)) 'a record was left behind by a write that failed'

            # Still registered, which is the whole point: the machine is exactly as it was found.
            $lookup = Get-WacInstalledTask -IncludeLegacy
            Assert-Equal 'Found' ([string]$lookup.State) 'the task the upgrade refused to remove is gone anyway'
        }
        finally {
            Clear-TestScheduler
        }
    }
}

# ---------------------------------------------------------------------------------------------
# The process died. The next run reconciles from the record
# ---------------------------------------------------------------------------------------------

Test-Case 'A task removed by a process that then died is re-registered by the next run' {
    # The defect, end to end. The conflict phase removes the registration and the process dies before
    # anything replaces it - no swap, no rollback, no in-memory result. All the next run has is the
    # record, and that has to be enough.
    Invoke-InDeploymentSandbox -Prefix 'wac02r-reconcile' -Body {
        param($sandbox)

        $null = $sandbox
        $root = (Get-WacDeploymentSlotPath).Root
        $scheduler = Initialize-TestCase -Root $root
        try {
            $conflict = Resolve-ConflictingTask -DeploymentRoot $root
            Assert-True $conflict.Ok ([string]$conflict.Reason)
            Assert-Equal 'Absent' ([string](Get-WacInstalledTask -IncludeLegacy).State) 'the fixture did not reach the state this case is about'
            Assert-True (Test-Path -LiteralPath (Get-TestCaptureRecordPath -Root $root) -PathType Leaf) `
                'the removal left no durable record, so a later process has nothing to reconcile from'

            # The death: everything the dead process held in memory goes, the disk stays.
            $captured = $scheduler.Export
            $scheduler = Initialize-TestCase -Root $root
            $scheduler.Registered = @()

            $reconciled = Resolve-InterruptedTaskCapture -DeploymentRoot $root -Lookup (Get-WacInstalledTask -IncludeLegacy)

            Assert-True $reconciled.Ok ([string]$reconciled.Reason)
            Assert-Equal 1 ([int]$reconciled.Restored) 'the lost registration was not put back'
            Assert-Equal 1 @($scheduler.RegisteredXml).Count 'the task was registered more or fewer than once'
            Assert-Equal $captured ([string]@($scheduler.RegisteredXml)[0]) 'what went back is not the definition that was captured'
            Assert-Equal 'Found' ([string](Get-WacInstalledTask).State) 'the machine is still missing the task'
            Assert-False (Test-Path -LiteralPath (Get-TestCaptureRecordPath -Root $root)) `
                'the reconciled record was left on disk for the next run to act on again'
            Assert-True ((($script:Message -join ' / ') -match 'WARNING\|.*putting it back')) ($script:Message -join ' / ')
        }
        finally {
            Clear-TestScheduler
        }
    }
}

Test-Case 'A recorded task that is still registered is left alone and the record is cleared' {
    # The benign half. A record beside a machine that HAS the task is the debris of a run that got
    # far enough, and re-registering over a live task would replace a definition nobody asked to
    # change.
    Invoke-InDeploymentSandbox -Prefix 'wac02r-reconcile-present' -Body {
        param($sandbox)

        $null = $sandbox
        $root = (Get-WacDeploymentSlotPath).Root
        $scheduler = Initialize-TestCase -Root $root
        try {
            [void](Write-WacTaskCaptureRecord -DeploymentRoot $root -Capture @([PSCustomObject]@{
                TaskName = 'WindowsAutoCleanup'; TaskPath = '\WindowsAutoCleanup\'; Definition = $scheduler.Export
            }))

            $reconciled = Resolve-InterruptedTaskCapture -DeploymentRoot $root -Lookup (Get-WacInstalledTask -IncludeLegacy)

            Assert-True $reconciled.Ok ([string]$reconciled.Reason)
            Assert-Equal 0 ([int]$reconciled.Restored) 'a task that was still registered was re-registered over'
            Assert-Equal 1 ([int]$reconciled.Accounted) 'the registered task was not accounted for'
            Assert-False ($scheduler.Order -contains 'register') ('the scheduler was written to: ' + ($scheduler.Order -join ','))
            Assert-False (Test-Path -LiteralPath (Get-TestCaptureRecordPath -Root $root)) 'a fully accounted record was kept'
        }
        finally {
            Clear-TestScheduler
        }
    }
}

Test-Case 'A reconciliation that cannot finish KEEPS the record and refuses the install' {
    # The record is the only thing on the machine that says which registration is missing and what it
    # was. Deleting it on a failed restore would destroy that, and installing over the question would
    # bury it under a new deployment.
    Invoke-InDeploymentSandbox -Prefix 'wac02r-reconcile-stuck' -Body {
        param($sandbox)

        $null = $sandbox
        $root = (Get-WacDeploymentSlotPath).Root
        $scheduler = Initialize-TestCase -Root $root
        try {
            [void](Write-WacTaskCaptureRecord -DeploymentRoot $root -Capture @([PSCustomObject]@{
                TaskName = 'WindowsAutoCleanup'; TaskPath = '\WindowsAutoCleanup\'; Definition = $scheduler.Export
            }))
            $scheduler.Registered = @()
            $scheduler.RegisterThrows = $true

            $reconciled = Resolve-InterruptedTaskCapture -DeploymentRoot $root -Lookup (Get-WacInstalledTask -IncludeLegacy)

            Assert-False $reconciled.Ok 'a reconciliation that could not put the task back reported success'
            Assert-Equal 0 ([int]$reconciled.Restored) 'a failed re-registration was counted as a restoration'
            Assert-True ([string]$reconciled.Reason -match 'could not be accounted for') ([string]$reconciled.Reason)
            Assert-True (Test-Path -LiteralPath (Get-TestCaptureRecordPath -Root $root) -PathType Leaf) `
                'the only description of the missing registration was deleted'
        }
        finally {
            Clear-TestScheduler
        }
    }
}

Test-Case 'A record that cannot be read refuses the install rather than burying the question' {
    # UNKNOWN IS NOT ABSENT, the same rule the swap record follows: something wrote this, a task may
    # be missing, and its shape cannot be read.
    Invoke-InDeploymentSandbox -Prefix 'wac02r-reconcile-torn' -Body {
        param($sandbox)

        $null = $sandbox
        $root = (Get-WacDeploymentSlotPath).Root
        [void](Initialize-TestCase -Root $root)
        try {
            # A write that stopped half way: valid JSON never starts and ends like this.
            [System.IO.File]::WriteAllText((Get-TestCaptureRecordPath -Root $root), '{"Schema":2,"CapturedTask":[{"TaskN')

            $reconciled = Resolve-InterruptedTaskCapture -DeploymentRoot $root -Lookup (Get-WacInstalledTask -IncludeLegacy)

            Assert-False $reconciled.Ok 'a torn record was treated as proof that no task had been removed'
            Assert-True ([string]$reconciled.Reason -match 'could not be read') ([string]$reconciled.Reason)
            Assert-True (Test-Path -LiteralPath (Get-TestCaptureRecordPath -Root $root) -PathType Leaf) `
                'the record nobody could read was deleted instead of being left for a human'
        }
        finally {
            Clear-TestScheduler
        }
    }
}

Test-Case 'An ended transaction clears the record only once every task is back' {
    Invoke-InDeploymentSandbox -Prefix 'wac02r-complete' -Body {
        param($sandbox)

        $null = $sandbox
        $root = (Get-WacDeploymentSlotPath).Root
        $scheduler = Initialize-TestCase -Root $root
        try {
            $conflict = Resolve-ConflictingTask -DeploymentRoot $root
            Assert-True $conflict.Ok ([string]$conflict.Reason)
            Assert-True (Test-Path -LiteralPath (Get-TestCaptureRecordPath -Root $root) -PathType Leaf) 'the fixture wrote no record'

            # A restore that FAILS keeps the record: it is what the next run reconciles from.
            $scheduler.RegisterThrows = $true
            Assert-False (Complete-TaskCaptureTransaction -DeploymentRoot $root -CapturedTask @($conflict.Captured)) `
                'a transaction whose task could not be put back reported itself complete'
            Assert-True (Test-Path -LiteralPath (Get-TestCaptureRecordPath -Root $root) -PathType Leaf) `
                'the record was cleared while the registration it describes was still missing'

            # And once it is proven back, the transaction is over for every later process too.
            $scheduler.RegisterThrows = $false
            Assert-True (Complete-TaskCaptureTransaction -DeploymentRoot $root -CapturedTask @($conflict.Captured)) ($script:Message -join ' / ')
            Assert-False (Test-Path -LiteralPath (Get-TestCaptureRecordPath -Root $root)) 'a completed transaction left its record on disk'
        }
        finally {
            Clear-TestScheduler
        }
    }
}

Complete-TestRun
