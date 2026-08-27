#Requires -Version 5.1
<#
.SYNOPSIS
    Ternary task lookup, definition capture and verified removal (ledger G2-b, G2-c).

.DESCRIPTION
    Split out of ScheduledTask.Tests.ps1, whose subject is the pure ownership proof over stub
    objects and which states that it never calls Register-ScheduledTask or Unregister-ScheduledTask.
    These cases DO exercise those calls, so they get their own file and their own contract: the
    scheduler is replaced INSIDE the Deploy module for every one of them, and nothing here
    registers, unregisters or exports a task on this machine.

    The one thing that is real is the error record a genuine not-found produces. It is captured from
    a read-only query for a name that does not exist, so the classifier is proven against what the
    live scheduler actually raises rather than against an invented shape.
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

$script:WindowsPowerShell = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'

# ---------------------------------------------------------------------------------------------
# Lookup, capture and verified removal (ledger G2-b, G2-c)
#
# The scheduler is replaced INSIDE the module for these, never on this machine: nothing here
# registers, unregisters or exports a real task. The one thing that is real is the error record a
# genuine not-found produces - captured from a read-only query for a name that does not exist - so
# the classifier is proven against what the live scheduler actually raises rather than against an
# invented shape.
# ---------------------------------------------------------------------------------------------

$script:DeployModule = Get-Module -Name 'WindowsAutoCleanup.Deploy'

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

    & $Module { param($n) if (Test-Path -Path ('function:' + $n)) { Remove-Item -Path ('function:' + $n) -Force } } $Name
}

function Get-TestRealNotFoundError {
    <#
    .SYNOPSIS
        The error record the live scheduler raises for a task that is not registered.
    .DESCRIPTION
        A read-only query for a random name. Nothing is created, changed or removed - and the
        record it returns is the one the classifier has to recognise, measured rather than assumed:
        FullyQualifiedErrorId 'CmdletizationQuery_NotFound,Get-ScheduledTask', category
        ObjectNotFound.
    #>
    Import-Module -Name 'ScheduledTasks' -ErrorAction Stop

    $name = 'WacAbsentProbe_{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 12)
    try {
        Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop | Out-Null
    }
    catch {
        return $_
    }

    return $null
}

function New-TestSchedulerFailure {
    <#
    .SYNOPSIS
        An error record that is NOT a not-found: the scheduler could not answer the question.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][string]$ErrorId,
        [Parameter(Mandatory = $true)][System.Management.Automation.ErrorCategory]$Category
    )

    return (New-Object System.Management.Automation.ErrorRecord(
        (New-Object System.InvalidOperationException($Message)), $ErrorId, $Category, $null))
}

Test-Case 'A lookup tells a real Absent apart from a scheduler that could not answer' {
    $notFound = Get-TestRealNotFoundError
    Assert-True ($null -ne $notFound) 'the live scheduler answered a query for a task that does not exist'
    Assert-Equal 'CmdletizationQuery_NotFound,Get-ScheduledTask' ([string]$notFound.FullyQualifiedErrorId) `
        'the not-found record the scheduler raises has changed shape'

    # The classifier, against the real record and against the three ways a lookup fails instead.
    $classify = { param($record) & $script:DeployModule { param($r) Test-WacTaskQueryIsNotFound -ErrorRecord $r } $record }

    Assert-True (& $classify $notFound) 'a genuine not-found was not recognised as absence'

    foreach ($failure in @(
        (New-TestSchedulerFailure -Message 'The RPC server is unavailable.' -ErrorId 'HRESULT 0x800706ba' -Category 'ConnectionError'),
        (New-TestSchedulerFailure -Message 'Access is denied.' -ErrorId 'HRESULT 0x80070005' -Category 'PermissionDenied'),
        (New-TestSchedulerFailure -Message 'The operation timed out.' -ErrorId 'HRESULT 0x800705b4' -Category 'OperationTimeout'))) {
        Assert-False (& $classify $failure) ('a {0} was read as "the task is not there"' -f $failure.CategoryInfo.Category)
    }

    # The one that hides in plain sight: a missing ScheduledTasks module raises
    # CommandNotFoundException, which ALSO carries the ObjectNotFound category (measured on both
    # hosts). Reading that as absence turns a machine that cannot ask the question into a machine
    # with nothing registered.
    $missingCommand = $null
    try { Get-WacNoSuchCommandProbe -ErrorAction Stop } catch { $missingCommand = $_ }
    Assert-Equal 'ObjectNotFound' ([string]$missingCommand.CategoryInfo.Category) 'the probe no longer reproduces the ambiguity'
    Assert-False (& $classify $missingCommand) 'a missing Get-ScheduledTask was read as "no task is registered"'
}

function Set-TestSchedulerStub {
    <#
    .SYNOPSIS
        Points the module's three scheduler calls at scriptblocks held in a hashtable.
    .DESCRIPTION
        A hashtable rather than a variable per hook, and deliberately: .GetNewClosure() captures a
        variable's VALUE, so a closure over a $script: variable never sees a later assignment to it.
        Capturing one hashtable reference and reaching through it is what lets a case swap the
        scheduler's behaviour between assertions.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Behaviour)

    # Read only from inside the closures below, which the unused-parameter rule cannot see through.
    $null = $Behaviour

    # Every stub below declares the parameters the module really passes, so the calls under test
    # bind exactly as they do against the live cmdlets; the ones a stub has no use for are consumed
    # here rather than dropped.
    Set-ModuleFunctionBody -Module $script:DeployModule -Name 'Get-ScheduledTask' -Body {
        param([string]$TaskName, [string]$TaskPath, [string]$ErrorAction)
        $null = $TaskName, $ErrorAction
        return (& $Behaviour.Query $TaskPath)
    }.GetNewClosure()

    Set-ModuleFunctionBody -Module $script:DeployModule -Name 'Export-ScheduledTask' -Body {
        param([string]$TaskName, [string]$TaskPath, [string]$ErrorAction)
        $null = $TaskName, $TaskPath, $ErrorAction
        [void]$Behaviour.Order.Add('export')
        return (& $Behaviour.Export)
    }.GetNewClosure()

    Set-ModuleFunctionBody -Module $script:DeployModule -Name 'Unregister-ScheduledTask' -Body {
        param([string]$TaskName, [string]$TaskPath, $Confirm, [string]$ErrorAction)
        $null = $TaskName, $TaskPath, $Confirm, $ErrorAction
        [void]$Behaviour.Order.Add('unregister')
    }.GetNewClosure()
}

function Clear-TestSchedulerStub {
    foreach ($name in @('Get-ScheduledTask', 'Unregister-ScheduledTask', 'Export-ScheduledTask')) {
        Remove-ModuleFunctionBody -Module $script:DeployModule -Name $name
    }
}

function New-TestOwnedTask {
    param([Parameter(Mandatory = $true)][string]$DeploymentRoot)

    return (New-StubTask -TaskPath '\WindowsAutoCleanup\' -Description (Get-WacTaskDescription) -Action @(
        New-StubAction -Execute $script:WindowsPowerShell -WorkingDirectory $DeploymentRoot `
            -Arguments (Get-WacTaskActionArgument -RunScript (Join-Path -Path $DeploymentRoot -ChildPath 'Run.ps1'))))
}

Test-Case 'Discovery is Found, Absent or Failed - and a failure at either path poisons the whole answer' {
    $notFound = Get-TestRealNotFoundError
    Assert-True ($null -ne $notFound) 'the live scheduler answered a query for a task that does not exist'

    $ours = New-StubTask -TaskPath '\WindowsAutoCleanup\' -Description (Get-WacTaskDescription) -Action @()
    $denied = New-TestSchedulerFailure -Message 'Access is denied.' -ErrorId 'HRESULT 0x80070005' -Category 'PermissionDenied'
    $behaviour = @{ Query = { throw $notFound }.GetNewClosure(); Export = { '' }; Order = (New-Object 'System.Collections.Generic.List[string]') }

    Set-TestSchedulerStub -Behaviour $behaviour
    try {
        $absent = Get-WacInstalledTask -IncludeLegacy
        Assert-Equal 'Absent' ([string]$absent.State) 'a positively reported not-found is not Absent'
        Assert-Equal 0 @($absent.Task).Count 'an absent lookup produced tasks'
        Assert-Equal 0 @($absent.Failure).Count 'an absent lookup produced failures'

        $behaviour.Query = { return $ours }.GetNewClosure()
        $found = Get-WacInstalledTask
        Assert-Equal 'Found' ([string]$found.State) 'a registered task was not found'
        Assert-Equal 1 @($found.Task).Count 'the found task was not returned'

        $behaviour.Query = { throw $denied }.GetNewClosure()
        $failed = Get-WacInstalledTask -IncludeLegacy
        Assert-Equal 'Failed' ([string]$failed.State) 'a scheduler that refused the query was read as a clean machine'
        Assert-Equal 0 @($failed.Task).Count 'a failed lookup invented tasks'
        Assert-Equal 2 @($failed.Failure).Count 'both paths should have reported the failure'
        Assert-True ([string]@($failed.Failure)[0].Reason -match 'neither present nor absent') ([string]@($failed.Failure)[0].Reason)

        # The half-known picture: our folder answers, the legacy path does not. Acting on that would
        # register a second task beside one nobody could see, so the WHOLE answer is Failed.
        $behaviour.Query = {
            param($path)
            if ($path -eq '\') { throw $denied }
            return $ours
        }.GetNewClosure()
        $partial = Get-WacInstalledTask -IncludeLegacy
        Assert-Equal 'Failed' ([string]$partial.State) 'one unanswered path was allowed to pass as a complete answer'
        Assert-Equal 1 @($partial.Task).Count 'the task that WAS found should still be reported'
        Assert-Equal 1 @($partial.Failure).Count 'the unanswered path was not reported'
    }
    finally {
        Clear-TestSchedulerStub
    }
}

Test-Case 'A removal is verified only by a positive absence, and never by an exception' {
    $notFound = Get-TestRealNotFoundError
    Assert-True ($null -ne $notFound) 'the live scheduler answered a query for a task that does not exist'

    $root = 'C:\Program Files\WindowsAutoCleanup'
    $task = New-TestOwnedTask -DeploymentRoot $root
    $behaviour = @{
        Query = { throw $notFound }.GetNewClosure()
        Export = { '<Task><Settings /></Task>' }
        Order = (New-Object 'System.Collections.Generic.List[string]')
    }

    Set-TestSchedulerStub -Behaviour $behaviour
    try {
        $clean = Remove-WacInstalledTask -Task $task -DeploymentRoot $root
        Assert-True $clean.Removed ([string]$clean.Reason)
        Assert-True $clean.Verified ([string]$clean.Reason)

        # An unreadable read-back is NOT a removal. This is the exact line that used to read
        # `try { Get-ScheduledTask } catch { $null }`, which took every exception as "it is gone".
        $denied = New-TestSchedulerFailure -Message 'Access is denied.' -ErrorId 'HRESULT 0x80070005' -Category 'PermissionDenied'
        $behaviour.Query = { throw $denied }.GetNewClosure()
        $unverified = Remove-WacInstalledTask -Task $task -DeploymentRoot $root
        Assert-True $unverified.Removed 'the unregister itself should still have been attempted'
        Assert-False $unverified.Verified 'an unreadable read-back was reported as a verified removal'
        Assert-True ([string]$unverified.Reason -match 'could not be verified') ([string]$unverified.Reason)

        $behaviour.Query = { return $task }.GetNewClosure()
        $survived = Remove-WacInstalledTask -Task $task -DeploymentRoot $root
        Assert-False $survived.Verified 'a task that is still registered was reported as removed'
        Assert-True ([string]$survived.Reason -match 'still registered') ([string]$survived.Reason)
    }
    finally {
        Clear-TestSchedulerStub
    }
}

Test-Case 'The definition is captured before the unregister, and a removal that could not be undone is refused' {
    $notFound = Get-TestRealNotFoundError
    Assert-True ($null -ne $notFound) 'the live scheduler answered a query for a task that does not exist'

    $root = 'C:\Program Files\WindowsAutoCleanup'
    $task = New-TestOwnedTask -DeploymentRoot $root
    $behaviour = @{
        Query = { throw $notFound }.GetNewClosure()
        Export = { '<Task><RegistrationInfo /></Task>' }
        Order = (New-Object 'System.Collections.Generic.List[string]')
    }

    Set-TestSchedulerStub -Behaviour $behaviour
    try {
        $captured = Remove-WacInstalledTask -Task $task -DeploymentRoot $root -RequireDefinitionCapture

        Assert-True $captured.Verified ([string]$captured.Reason)
        Assert-True $captured.Captured ([string]$captured.CaptureReason)
        Assert-Equal '<Task><RegistrationInfo /></Task>' ([string]$captured.Definition) 'the captured definition was not returned'
        Assert-Equal 'export,unregister' ($behaviour.Order -join ',') 'the definition was captured after the task was already gone'

        # An upgrade that removes a task it cannot put back is a step it is not allowed to take, so
        # the unregister must never happen at all.
        $behaviour.Order.Clear()
        $behaviour.Export = { throw (New-TestSchedulerFailure -Message 'Access is denied.' -ErrorId 'export' -Category 'PermissionDenied') }
        $refused = Remove-WacInstalledTask -Task $task -DeploymentRoot $root -RequireDefinitionCapture

        Assert-False $refused.Removed 'a task whose definition could not be captured was unregistered anyway'
        Assert-False $refused.Captured 'the capture was reported as successful'
        Assert-False ($behaviour.Order -contains 'unregister') ('the unregister ran anyway: ' + ($behaviour.Order -join ','))
        Assert-True ([string]$refused.Reason -match 'could not have been undone') ([string]$refused.Reason)

        # The uninstaller does not pass the switch: there is nothing to roll back to, and a scheduler
        # that will not export must not be able to block a removal the operator asked for.
        $behaviour.Order.Clear()
        $anyway = Remove-WacInstalledTask -Task $task -DeploymentRoot $root
        Assert-True $anyway.Verified ([string]$anyway.Reason)
        Assert-False $anyway.Captured ([string]$anyway.CaptureReason)
        Assert-True ($behaviour.Order -contains 'unregister') 'the removal was blocked without the switch that requires a capture'
    }
    finally {
        Clear-TestSchedulerStub
    }
}

Complete-TestRun
