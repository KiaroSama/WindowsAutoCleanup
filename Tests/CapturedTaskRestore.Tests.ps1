#Requires -Version 5.1
<#
.SYNOPSIS
    What Restore-CapturedTask will and will not register a captured definition over (ledger WAC-02R).

.DESCRIPTION
    Register-ScheduledTask -Force OVERWRITES whatever is registered under the name it is given. That
    is correct when this run is the one that emptied the name, and it is a silent replacement of
    somebody else's task otherwise - so the name is checked immediately before the registration.

    It has three callers and only one of them asks the question itself. Resolve-InterruptedTaskCapture
    compares what stands at the name before it decides anything, and TaskCaptureTransaction.Tests.ps1
    covers that; Undo-Installation and Complete-TaskCaptureTransaction do not, and for them this
    check is the only thing between -Force and a foreign registration. It is therefore driven
    directly here rather than through the reconciliation that would shadow it.

    Nothing is registered with the live Task Scheduler: Get-WacInstalledTask is replaced inside the
    Deploy module's scope, and Register-ScheduledTask is shadowed in this script's scope, which is
    where Restore-CapturedTask resolves it.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.InstallerTask.ps1')

$script:DeployModule = Get-Module -Name 'WindowsAutoCleanup.Deploy'
$script:Message = New-Object 'System.Collections.Generic.List[string]'
$script:Registered = New-Object 'System.Collections.Generic.List[string]'
$script:TaskHost = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:TaskRoot = 'C:\Program Files\WindowsAutoCleanup'

function Write-InstallerMessage {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Data = @{},
        [switch]$NoLog
    )

    $null = $Data, $NoLog
    [void]$script:Message.Add(('{0}|{1}' -f $Level, $Message))
}

function Register-ScheduledTask {
    <#
    .SYNOPSIS
        Shadows the cmdlet for Restore-CapturedTask, which resolves it in THIS scope. Records the
        XML it is given, so a case can assert whether anything was written at all.
    #>
    param($TaskName, $TaskPath, $InputObject, $Xml, [switch]$Force, $ErrorAction)

    $null = $InputObject, $Force, $ErrorAction
    [void]$script:Registered.Add([string]$Xml)
    return ([PSCustomObject]@{ TaskName = $TaskName; TaskPath = $TaskPath })
}

function New-RestoreXml {
    <#
    .SYNOPSIS
        A captured definition for our deployment root, in the shape Export-ScheduledTask emits.
    #>
    param([string]$Arguments)

    if (-not $Arguments) {
        $Arguments = Get-WacTaskActionArgument -RunScript (Join-Path -Path $script:TaskRoot -ChildPath 'Run.ps1')
    }

    return ('<?xml version="1.0" encoding="UTF-16"?>' +
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' +
        ('<RegistrationInfo><Description>{0}</Description></RegistrationInfo>' -f [System.Security.SecurityElement]::Escape((Get-WacTaskDescription))) +
        '<Triggers><CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>' +
        '<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>ServiceAccount</LogonType></Principal></Principals>' +
        '<Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings>' +
        ('<Actions Context="Author"><Exec><Command>{0}</Command><Arguments>{1}</Arguments><WorkingDirectory>{2}</WorkingDirectory></Exec></Actions>' -f
            [System.Security.SecurityElement]::Escape($script:TaskHost),
            [System.Security.SecurityElement]::Escape($Arguments),
            [System.Security.SecurityElement]::Escape($script:TaskRoot)) +
        '</Task>')
}

function New-RestoreTask {
    <#
    .SYNOPSIS
        A registered task in the shape the scheduler hands back, agreeing with New-RestoreXml unless
        a case changes something.
    #>
    param(
        [string]$Arguments,
        [string]$Description
    )

    if (-not $Arguments) {
        $Arguments = Get-WacTaskActionArgument -RunScript (Join-Path -Path $script:TaskRoot -ChildPath 'Run.ps1')
    }
    if (-not $Description) { $Description = Get-WacTaskDescription }

    return [PSCustomObject]@{
        TaskName = (Get-WacTaskName)
        TaskPath = (Get-WacTaskFolder)
        Description = $Description
        Actions = @([PSCustomObject]@{ Execute = $script:TaskHost; Arguments = $Arguments; WorkingDirectory = $script:TaskRoot })
        Principal = [PSCustomObject]@{ UserId = 'SYSTEM'; LogonType = 'ServiceAccount'; RunLevel = 'Highest' }
        Settings = [PSCustomObject]@{ Enabled = $true; Hidden = $true }
        Triggers = @([PSCustomObject]@{ StartBoundary = '2026-01-01T03:00:00'; Enabled = $true; DaysInterval = 1 })
    }
}

function Set-RestoreLookup {
    <#
    .SYNOPSIS
        What the scheduler answers, in order, for the lookups one case makes.
    .DESCRIPTION
        Get-ScheduledTask is stubbed rather than Get-WacInstalledTask, and that is not a detail: the
        module EXPORTS Get-WacInstalledTask, and an export is bound to the function object at import
        time, so replacing the module-scope function leaves the dot-sourced caller still resolving
        the original. Stubbing the cmdlet the module itself calls puts the real lookup - ternary
        state, legacy path and all - between the case and its answer.

        A list, because Restore-CapturedTask asks twice on the path that registers: once to see what
        stands at the name, once to read back what it wrote. Only the CANONICAL folder consumes an
        answer; the legacy root always answers empty, which the real lookup turns into Absent.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Answer)

    & $script:DeployModule { param($answers, $folder)
        $script:RestoreAnswers = $answers
        $script:RestoreFolder = $folder
        $script:RestoreIndex = 0
        Set-Item -Path 'function:script:Get-ScheduledTask' -Value {
            param([string]$TaskName, [string]$TaskPath, [string]$ErrorAction)
            $null = $TaskName, $ErrorAction
            if (-not [string]::Equals($TaskPath, $script:RestoreFolder, [System.StringComparison]::OrdinalIgnoreCase)) { return @() }

            $index = $script:RestoreIndex
            if ($index -ge @($script:RestoreAnswers).Count) { $index = @($script:RestoreAnswers).Count - 1 }
            $script:RestoreIndex = $script:RestoreIndex + 1

            $answer = @($script:RestoreAnswers)[$index]
            if ([string]$answer.State -ceq 'Failed') { throw 'the scheduler could not be queried' }
            return @($answer.Task)
        }
    } $Answer (Get-WacTaskFolder)
}

function Clear-RestoreLookup {
    & $script:DeployModule {
        if (Test-Path -LiteralPath 'function:script:Get-ScheduledTask') {
            Remove-Item -LiteralPath 'function:script:Get-ScheduledTask' -Force
        }
    }
}

function New-RestoreLookupResult {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Found', 'Absent', 'Failed')][string]$State,
        [AllowNull()]$Task
    )

    $found = @()
    if ($Task) { $found = @($Task) }
    return ([PSCustomObject]@{ State = $State; Task = $found; Failure = @() })
}

function Initialize-RestoreCase {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Answer)

    $script:Message.Clear()
    $script:Registered.Clear()
    Set-RestoreLookup -Answer $Answer
}

# ---------------------------------------------------------------------------------------------
# The name is checked BEFORE -Force gets near it
# ---------------------------------------------------------------------------------------------

Test-Case 'A captured definition goes back when nothing stands at its name' {
    $xml = New-RestoreXml
    Initialize-RestoreCase -Answer @(
        (New-RestoreLookupResult -State 'Absent' -Task $null),
        (New-RestoreLookupResult -State 'Found' -Task (New-RestoreTask)))
    try {
        Assert-True (Restore-CapturedTask -Definition ([PSCustomObject]@{
            TaskName = (Get-WacTaskName); TaskPath = (Get-WacTaskFolder); Definition = $xml
            Captured = $true; CaptureReason = 'captured by this run'
        })) ($script:Message -join ' / ')

        Assert-Equal 1 @($script:Registered).Count 'the captured definition was not registered'
        Assert-Equal $xml ([string]@($script:Registered)[0]) 'what went back is not the definition that was captured'
    }
    finally {
        Clear-RestoreLookup
    }
}

Test-Case 'A DIFFERENT task standing at the captured name is never registered over' {
    # The hard boundary. -Force would have replaced it outright, and the caller would have been told
    # the rollback succeeded.
    $xml = New-RestoreXml
    $occupant = New-RestoreTask -Description 'somebody else entirely' `
        -Arguments '-NoProfile -Command "& ''C:\Windows\System32\cmd.exe''"'
    Initialize-RestoreCase -Answer @((New-RestoreLookupResult -State 'Found' -Task $occupant))
    try {
        Assert-False (Restore-CapturedTask -Definition ([PSCustomObject]@{
            TaskName = (Get-WacTaskName); TaskPath = (Get-WacTaskFolder); Definition = $xml
            Captured = $true; CaptureReason = 'captured by this run'
        })) 'a task that is not the captured one was overwritten and reported as restored'

        Assert-Equal 0 @($script:Registered).Count `
            ('the scheduler was written to anyway: ' + (@($script:Registered) -join ' / '))
        Assert-True ((($script:Message -join ' / ') -match 'CRITICAL\|A different task now stands at the name')) `
            ($script:Message -join ' / ')
    }
    finally {
        Clear-RestoreLookup
    }
}

Test-Case 'A task ALREADY back exactly as captured is left alone and reported restored' {
    # The benign half: re-registering over an identical live task would rewrite a definition nobody
    # asked to change, and reporting failure would turn an idempotent rollback into an incomplete.
    $xml = New-RestoreXml
    Initialize-RestoreCase -Answer @((New-RestoreLookupResult -State 'Found' -Task (New-RestoreTask)))
    try {
        Assert-True (Restore-CapturedTask -Definition ([PSCustomObject]@{
            TaskName = (Get-WacTaskName); TaskPath = (Get-WacTaskFolder); Definition = $xml
            Captured = $true; CaptureReason = 'captured by this run'
        })) ($script:Message -join ' / ')

        Assert-Equal 0 @($script:Registered).Count 'a task that was already exactly right was re-registered over'
        Assert-True ((($script:Message -join ' / ') -match 'already registered exactly as it was captured')) ($script:Message -join ' / ')
    }
    finally {
        Clear-RestoreLookup
    }
}

Test-Case 'A scheduler that will not say what stands at the name registers nothing' {
    # "The query failed" is not "the name is free", and acting on it is how -Force reaches a task
    # nobody could see.
    Initialize-RestoreCase -Answer @((New-RestoreLookupResult -State 'Failed' -Task $null))
    try {
        Assert-False (Restore-CapturedTask -Definition ([PSCustomObject]@{
            TaskName = (Get-WacTaskName); TaskPath = (Get-WacTaskFolder); Definition = (New-RestoreXml)
            Captured = $true; CaptureReason = 'captured by this run'
        })) 'a definition was registered over a name nothing could be read from'

        Assert-Equal 0 @($script:Registered).Count 'the scheduler was written to on an unanswered lookup'
        Assert-True ((($script:Message -join ' / ') -match 'whether something already stands at the name')) ($script:Message -join ' / ')
    }
    finally {
        Clear-RestoreLookup
    }
}

Test-Case 'A registration whose read-back is not the captured task reports failure' {
    # The existing rule, kept: a task with the right name is not the task that was removed.
    # The account the task runs AS, not its description: the description carries the ownership
    # sentinel and is not part of what the capture declares, while the principal is - a task with
    # the same program under a different identity is the same program run by somebody else.
    $wrongUser = New-RestoreTask
    $wrongUser.Principal.UserId = 'MACHINE\someone'
    Initialize-RestoreCase -Answer @(
        (New-RestoreLookupResult -State 'Absent' -Task $null),
        (New-RestoreLookupResult -State 'Found' -Task $wrongUser))
    try {
        Assert-False (Restore-CapturedTask -Definition ([PSCustomObject]@{
            TaskName = (Get-WacTaskName); TaskPath = (Get-WacTaskFolder); Definition = (New-RestoreXml)
            Captured = $true; CaptureReason = 'captured by this run'
        })) 'a read-back that is not the captured task was reported as a restoration'

        Assert-Equal 1 @($script:Registered).Count 'the definition was never registered, so the read-back proves nothing'
        Assert-True ((($script:Message -join ' / ') -match 'what came back is not the task that was captured')) ($script:Message -join ' / ')
    }
    finally {
        Clear-RestoreLookup
    }
}

Complete-TestRun
