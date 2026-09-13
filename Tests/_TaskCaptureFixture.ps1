#Requires -Version 5.1
<#
.SYNOPSIS
    The Task Scheduler TaskCaptureTransaction.Tests.ps1 drives the real capture transaction against.

.DESCRIPTION
    Dot-sourced by TaskCaptureTransaction.Tests.ps1. It is not a suite: its name does not match
    Tests\*.Tests.ps1, so the runner never executes it alone.

    It is a responsibility of its own because the production code reaches the scheduler through TWO
    seams that have to be faked in two different places, and getting that split right is mechanism
    rather than assertion: Get-ScheduledTask, Export-ScheduledTask and Unregister-ScheduledTask are
    replaced INSIDE the Deploy module's scope, where Remove-WacInstalledTask resolves them, while
    Register-ScheduledTask is shadowed in the consuming script's scope, where Restore-CapturedTask
    resolves it. So the REAL removal, conflict, reconciliation and restore paths run end to end
    against a scheduler the case controls.

    Every hook reaches its case through the ONE hashtable New-TestScheduler returns, deliberately:
    .GetNewClosure() captures a variable's VALUE, so a closure over a $script: variable would never
    see a later assignment to it. Every call appends to .Order, which is what lets the suite OBSERVE
    that the record was written before the unregister instead of inferring it.

    The durable record is not modelled at all: %ProgramFiles% is redirected by the caller's
    Invoke-InDeploymentSandbox and the real journal writer writes the real file.

    What a consuming suite owes this file, in this order: $script:RepoRoot; an import of
    src\WindowsAutoCleanup.Deploy.psm1, because the module handle below is taken at dot-source time;
    _DeployFixtures.ps1 for New-StubTask, New-StubAction and Invoke-InDeploymentSandbox; and the
    dot-sources of src\WindowsAutoCleanup.InstallerTask.ps1 and
    src\WindowsAutoCleanup.InstallerRecovery.ps1, whose restore path binds against the
    Register-ScheduledTask shadow below.
#>

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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Shadowing the real cmdlet IS the mechanism: the production caller resolves the name in this scope, and the shadow lives and dies with this test script.')]
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

function New-TestRegisteredTask {
    <#
    .SYNOPSIS
        A registered task that is OURS and points into the deployment root, but is not the task the
        fixture's capture describes - the shape an interrupted upgrade leaves standing.
    .DESCRIPTION
        Same name, same path, same host, same working directory, DIFFERENT arguments: exactly what
        an upgrade that added a switch to the command line produces. Nothing but the semantic
        comparison can tell it from the captured task, which is the whole point.
    #>
    param([Parameter(Mandatory = $true)][string]$Root)

    $task = New-TestOwnedTask -Root $Root
    $task.Actions[0].Arguments = [string]$task.Actions[0].Arguments + ' -PruneSupersededDrivers'
    return $task
}
