#Requires -Version 5.1
<#
.SYNOPSIS
    What the installer's rollback accepts as "the task that was captured" (ledger WAC-02R).

.DESCRIPTION
    Test-CapturedTaskDefinition is the only thing standing between "a task with that name exists
    again" and "the machine has the registration it lost". It used to compare the Exec action and,
    when the capture declared one, Hidden - so a task with the same program running as a DIFFERENT
    user, on a DIFFERENT schedule, or disabled outright, was reported as restored.

    The function is exercised directly here rather than through the installer: the comparison is a
    pure function of an exported definition and a read-back task object, and driving it directly is
    what makes it possible to change one field at a time and read the exact reason back.
    DeploymentRollback.Tests.ps1 covers the same rules end to end, through Undo-Installation.

    Write-InstallerMessage lives in the host script in production; nothing in this file's code path
    calls it, so the dot-source needs no stub.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

$script:TaskHost = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$script:TaskRoot = 'C:\Program Files\WindowsAutoCleanup'
$script:TaskArguments = '-NoProfile -Command "& ''C:\Program Files\WindowsAutoCleanup\Run.ps1'' -Scheduled"'

function New-CapturedXml {
    <#
    .SYNOPSIS
        An exported definition in the shape Export-ScheduledTask really emits: the UTF-16
        declaration, the default namespace, and one section per part of the task.
    .DESCRIPTION
        Each section is a whole XML fragment so a case can declare LESS as well as differently - an
        empty section is a capture that never carried that part, which the comparison must treat as
        nothing to prove rather than as a mismatch.
    #>
    param(
        [string]$Command = $script:TaskHost,
        [string]$Arguments = $script:TaskArguments,
        [string]$WorkingDirectory = $script:TaskRoot,
        [string]$Principals = '<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>ServiceAccount</LogonType></Principal></Principals>',
        [string]$Settings = '<Settings><Enabled>true</Enabled><Hidden>true</Hidden><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><ExecutionTimeLimit>PT4H</ExecutionTimeLimit><RestartOnFailure><Interval>PT10M</Interval><Count>3</Count></RestartOnFailure></Settings>',
        [string]$Triggers = '<Triggers><CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>'
    )

    return ('<?xml version="1.0" encoding="UTF-16"?>' +
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' +
        '<RegistrationInfo><Description>the task this run removed</Description></RegistrationInfo>' +
        $Triggers + $Principals + $Settings +
        ('<Actions Context="Author"><Exec><Command>{0}</Command><Arguments>{1}</Arguments><WorkingDirectory>{2}</WorkingDirectory></Exec></Actions>' -f
            [System.Security.SecurityElement]::Escape($Command),
            [System.Security.SecurityElement]::Escape($Arguments),
            [System.Security.SecurityElement]::Escape($WorkingDirectory)) +
        '</Task>')
}

function New-RestoredTask {
    <#
    .SYNOPSIS
        A stand-in for what Get-ScheduledTask hands back, populated to agree with New-CapturedXml's
        defaults. A case changes one field and asserts what that costs.
    .DESCRIPTION
        The spellings are deliberately the SCHEDULER's rather than the XML's - SYSTEM for S-1-5-18,
        Highest for HighestAvailable, MultipleInstances for MultipleInstancesPolicy - because the
        normalisation that folds those is exactly what must not be allowed to fold a real change.
    #>
    param()

    return [PSCustomObject]@{
        TaskName = 'WindowsAutoCleanup'
        TaskPath = '\WindowsAutoCleanup\'
        Description = 'the task this run removed'
        Actions = @([PSCustomObject]@{
            Execute = $script:TaskHost
            Arguments = $script:TaskArguments
            WorkingDirectory = $script:TaskRoot
        })
        Principal = [PSCustomObject]@{
            UserId = 'SYSTEM'
            LogonType = 'ServiceAccount'
            RunLevel = 'Highest'
        }
        Settings = [PSCustomObject]@{
            Enabled = $true
            Hidden = $true
            DisallowStartIfOnBatteries = $false
            StopIfGoingOnBatteries = $false
            StartWhenAvailable = $true
            MultipleInstances = 'IgnoreNew'
            ExecutionTimeLimit = 'PT4H'
            RestartCount = 3
            RestartInterval = 'PT10M'
        }
        Triggers = @([PSCustomObject]@{
            StartBoundary = '2026-01-01T03:00:00'
            Enabled = $true
            DaysInterval = 1
            CimClass = [PSCustomObject]@{ CimClassName = 'MSFT_TaskDailyTrigger' }
        })
    }
}

function Assert-NotRestored {
    <#
    .SYNOPSIS
        The comparison refuses, for the stated reason.
    #>
    param(
        [Parameter(Mandatory = $true)]$Verdict,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Message
    )

    Assert-False $Verdict.Match $Message
    Assert-True ([string]$Verdict.Reason -match $Pattern) ([string]$Verdict.Reason)
}

# ---------------------------------------------------------------------------------------------
# The definition that really did come back
# ---------------------------------------------------------------------------------------------

Test-Case 'A task restored exactly as captured matches, action, principal, settings and trigger' {
    $verdict = Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task (New-RestoredTask)
    Assert-True $verdict.Match ([string]$verdict.Reason)
}

Test-Case 'A capture that declares only its action is still matched on its action alone' {
    # The pre-1.2 shape, and what a scheduler that omitted a default emits. Demanding equality on a
    # part the capture never carried would fail a rollback that put the task back exactly as it was.
    $xml = New-CapturedXml -Principals '' -Settings '' -Triggers ''
    $task = New-RestoredTask
    $task.Principal.UserId = 'MACHINE\someone'
    $task.Settings.Enabled = $false

    $verdict = Test-WacCapturedTaskDefinition -Xml $xml -Task $task
    Assert-True $verdict.Match ([string]$verdict.Reason)
}

# ---------------------------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------------------------

Test-Case 'A task restored under a different user is not the task that was captured' {
    $task = New-RestoredTask
    $task.Principal.UserId = 'MACHINE\mobin'

    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $task) `
        -Pattern 'user' -Message 'a SYSTEM task that came back as a user task was reported as restored'
}

Test-Case 'A task restored at a lower run level or a different logon type is not restored' {
    $lowered = New-RestoredTask
    $lowered.Principal.RunLevel = 'Limited'
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $lowered) `
        -Pattern 'run level' -Message 'a task that came back without its elevation was reported as restored'

    $logon = New-RestoredTask
    $logon.Principal.LogonType = 'Password'
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $logon) `
        -Pattern 'logon type' -Message 'a task that came back with a different logon type was reported as restored'
}

Test-Case 'The spellings the two sides use for the SAME identity are not differences' {
    # Documented normalisation, and the reason it has to be bounded: SYSTEM, NT AUTHORITY\SYSTEM and
    # S-1-5-18 are one account; HighestAvailable and Highest one privilege level; ServiceAccount and
    # its enumeration index one logon type. Folding these is what keeps a correct rollback from
    # failing on a build that words them differently.
    foreach ($spelling in @('SYSTEM', 'NT AUTHORITY\SYSTEM', 's-1-5-18')) {
        $task = New-RestoredTask
        $task.Principal.UserId = $spelling
        $task.Principal.RunLevel = 1
        $task.Principal.LogonType = 5

        $verdict = Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $task
        Assert-True $verdict.Match ('[{0}] {1}' -f $spelling, [string]$verdict.Reason)
    }

    # And the fold is not a general case-insensitive compare: a different account stays different.
    $other = New-RestoredTask
    $other.Principal.UserId = 'S-1-5-19'
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $other) `
        -Pattern 'user' -Message 'LOCAL SERVICE was folded into SYSTEM'
}

# ---------------------------------------------------------------------------------------------
# Enabledness, and the settings that decide whether the task ever runs
# ---------------------------------------------------------------------------------------------

Test-Case 'A task restored DISABLED is not restored' {
    $task = New-RestoredTask
    $task.Settings.Enabled = $false

    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $task) `
        -Pattern 'enabled state' -Message 'a task that came back disabled was reported as restored'
}

Test-Case 'Execution, restart and battery settings are compared, and equal durations are equal' {
    foreach ($change in @(
        @{ Field = 'ExecutionTimeLimit'; Value = 'PT1H'; Pattern = 'execution time limit' },
        @{ Field = 'RestartCount'; Value = 1; Pattern = 'restart count' },
        @{ Field = 'RestartInterval'; Value = 'PT1M'; Pattern = 'restart interval' },
        @{ Field = 'DisallowStartIfOnBatteries'; Value = $true; Pattern = 'DisallowStartIfOnBatteries' },
        @{ Field = 'StopIfGoingOnBatteries'; Value = $true; Pattern = 'StopIfGoingOnBatteries' },
        @{ Field = 'StartWhenAvailable'; Value = $false; Pattern = 'StartWhenAvailable' },
        @{ Field = 'MultipleInstances'; Value = 'Parallel'; Pattern = 'multiple-instances' },
        @{ Field = 'Hidden'; Value = $false; Pattern = 'hidden state' })) {

        $task = New-RestoredTask
        $task.Settings.($change.Field) = $change.Value
        Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $task) `
            -Pattern $change.Pattern -Message ('a task whose {0} came back changed was reported as restored' -f $change.Field)
    }

    # PT4H and PT240M are the same four hours, and an enumeration's index is its name: neither is a
    # change in what the task will do.
    $normalised = New-RestoredTask
    $normalised.Settings.ExecutionTimeLimit = 'PT240M'
    $normalised.Settings.MultipleInstances = 2
    $verdict = Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $normalised
    Assert-True $verdict.Match ([string]$verdict.Reason)
}

Test-Case 'A setting the restored task cannot be read back for is unproven, not a match' {
    # Missing evidence is not agreement. A read-back that cannot see the field has not proven the
    # scheduler kept it.
    $task = New-RestoredTask
    $task.Settings.PSObject.Properties.Remove('Enabled')

    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $task) `
        -Pattern 'unproven' -Message 'a field the restored task does not expose was treated as matching'
}

# ---------------------------------------------------------------------------------------------
# The schedule
# ---------------------------------------------------------------------------------------------

Test-Case 'A task restored on a different schedule is not restored' {
    $hour = New-RestoredTask
    $hour.Triggers[0].StartBoundary = '2026-01-01T20:00:00'
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $hour) `
        -Pattern 'starts at' -Message 'a daily task that came back firing at another hour was reported as restored'

    $interval = New-RestoredTask
    $interval.Triggers[0].DaysInterval = 2
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $interval) `
        -Pattern 'day interval' -Message 'a daily task that came back running every other day was reported as restored'

    $disabled = New-RestoredTask
    $disabled.Triggers[0].Enabled = $false
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $disabled) `
        -Pattern 'enabled state' -Message 'a task whose only trigger came back disabled was reported as restored'
}

Test-Case 'A trigger that came back as a different KIND, or an extra one, is caught' {
    $kind = New-RestoredTask
    $kind.Triggers[0].CimClass.CimClassName = 'MSFT_TaskBootTrigger'
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $kind) `
        -Pattern 'Daily trigger' -Message 'a daily trigger that came back as a boot trigger was reported as restored'

    # By the COUNT, and the message has to say so. Get-TaskCollection used to hand the whole
    # collection back as one object, so this read as "1 trigger against 1 declared" and only the
    # field comparison - over member enumeration across the array - caught it by accident. A
    # two-trigger task where BOTH triggers match the captured one would then have passed outright.
    $extra = New-RestoredTask
    $extra.Triggers = @($extra.Triggers[0], $extra.Triggers[0])
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $extra) `
        -Pattern 'has 2 trigger\(s\) where the captured definition declares 1' `
        -Message 'a task that came back with a second identical trigger was reported as restored'

    # Same primitive, the other collection: a second action is a second program run as SYSTEM.
    $actions = New-RestoredTask
    $actions.Actions = @($actions.Actions[0], $actions.Actions[0])
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $actions) `
        -Pattern 'has 2 action\(s\) where the captured definition declares 1' `
        -Message 'a task that came back running a second program was reported as restored'

    $none = New-RestoredTask
    $none.Triggers = @()
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $none) `
        -Pattern 'trigger' -Message 'a scheduled task that came back with no schedule at all was reported as restored'
}

Test-Case 'A capture that declares NO trigger is not matched by a task that has one' {
    # Ledger WAC-02R. An EMPTY Triggers element says the task fires on nothing, and the comparison
    # returned "nothing to report" for it - so the one difference between a registration that runs
    # and one that does not was the one difference it could not see. ABSENT stays different from
    # EMPTY: a capture carrying no Triggers element at all never declared that part, and the case
    # above proves it is still matched on what it does declare.
    $xml = New-CapturedXml -Triggers '<Triggers></Triggers>'
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml $xml -Task (New-RestoredTask)) `
        -Pattern 'trigger' -Message 'a task that fires daily was reported as the captured task that fires on nothing'

    # And the pair of it: a task that really does have no trigger matches that capture.
    $none = New-RestoredTask
    $none.Triggers = @()
    $verdict = Test-WacCapturedTaskDefinition -Xml $xml -Task $none
    Assert-True $verdict.Match ([string]$verdict.Reason)
}

Test-Case 'A trigger that came back REPEATING is not the trigger that was captured' {
    # A daily trigger that comes back repeating every ten minutes for a day runs the cleanup 144
    # times instead of once, and every field the comparison used to read agrees perfectly.
    $xml = New-CapturedXml -Triggers ('<Triggers><CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary><Enabled>true</Enabled>' +
        '<Repetition><Interval>PT1H</Interval><Duration>PT12H</Duration><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>' +
        '<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>')

    $matching = New-RestoredTask
    Add-Member -InputObject $matching.Triggers[0] -MemberType NoteProperty -Name 'Repetition' `
        -Value ([PSCustomObject]@{ Interval = 'PT60M'; Duration = 'PT12H'; StopAtDurationEnd = $false })
    $verdict = Test-WacCapturedTaskDefinition -Xml $xml -Task $matching
    Assert-True $verdict.Match ('equal repetitions written differently were reported as a change: ' + [string]$verdict.Reason)

    $faster = New-RestoredTask
    Add-Member -InputObject $faster.Triggers[0] -MemberType NoteProperty -Name 'Repetition' `
        -Value ([PSCustomObject]@{ Interval = 'PT10M'; Duration = 'PT12H'; StopAtDurationEnd = $false })
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml $xml -Task $faster) `
        -Pattern 'repetition interval' -Message 'a trigger that came back repeating six times as often was reported as restored'
}

Test-Case 'The DAYS a weekly trigger fires on are compared, element names against the day mask' {
    # The two sides say this completely differently - one empty child element per day against a
    # single bit mask - so nothing the general normaliser does can compare them. Monday is 2.
    $monday = '<Triggers><CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary><Enabled>true</Enabled>' +
        '<ScheduleByWeek><WeeksInterval>1</WeeksInterval><DaysOfWeek><Monday /></DaysOfWeek></ScheduleByWeek></CalendarTrigger></Triggers>'

    $task = New-RestoredTask
    $task.Triggers[0].CimClass.CimClassName = 'MSFT_TaskWeeklyTrigger'
    $task.Triggers[0].PSObject.Properties.Remove('DaysInterval')
    Add-Member -InputObject $task.Triggers[0] -MemberType NoteProperty -Name 'WeeksInterval' -Value 1
    Add-Member -InputObject $task.Triggers[0] -MemberType NoteProperty -Name 'DaysOfWeek' -Value 2

    $verdict = Test-WacCapturedTaskDefinition -Xml (New-CapturedXml -Triggers $monday) -Task $task
    Assert-True $verdict.Match ('a weekly trigger on the captured day was reported as a change: ' + [string]$verdict.Reason)

    # Sunday instead of Monday: same interval, same hour, a task that never runs when it should.
    $task.Triggers[0].DaysOfWeek = 1
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml -Triggers $monday) -Task $task) `
        -Pattern 'day mask' -Message 'a weekly task that came back on another day was reported as restored'
}

Test-Case 'The conditions that decide whether the task runs at all are compared' {
    # A task that comes back wanting the network, or no longer waking the machine, is a task that
    # runs at times the operator never chose - and is exactly what an upgrade can change.
    $declared = '<Settings><Enabled>true</Enabled><Hidden>true</Hidden><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>' +
        '<RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>true</WakeToRun><AllowStartOnDemand>true</AllowStartOnDemand>' +
        '<Priority>7</Priority></Settings>'

    $task = New-RestoredTask
    foreach ($pair in @(@{ Name = 'RunOnlyIfNetworkAvailable'; Value = $false }, @{ Name = 'RunOnlyIfIdle'; Value = $false },
        @{ Name = 'WakeToRun'; Value = $true }, @{ Name = 'AllowDemandStart'; Value = $true }, @{ Name = 'Priority'; Value = 7 })) {
        Add-Member -InputObject $task.Settings -MemberType NoteProperty -Name $pair.Name -Value $pair.Value
    }

    $verdict = Test-WacCapturedTaskDefinition -Xml (New-CapturedXml -Settings $declared) -Task $task
    Assert-True $verdict.Match ([string]$verdict.Reason)

    foreach ($change in @(@{ Name = 'RunOnlyIfNetworkAvailable'; Value = $true; Pattern = 'RunOnlyIfNetworkAvailable' },
        @{ Name = 'WakeToRun'; Value = $false; Pattern = 'WakeToRun' },
        @{ Name = 'AllowDemandStart'; Value = $false; Pattern = 'AllowStartOnDemand' },
        @{ Name = 'Priority'; Value = 4; Pattern = 'priority' })) {

        $was = $task.Settings.($change.Name)
        $task.Settings.($change.Name) = $change.Value
        Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml -Settings $declared) -Task $task) `
            -Pattern $change.Pattern -Message ('a task whose {0} changed was reported as restored' -f $change.Name)
        $task.Settings.($change.Name) = $was
    }
}

Test-Case 'A boundary written with an offset is the local time the task will fire' {
    # The same rule Assert-RegisteredTask records: Unspecified, so an offset form converts to the
    # LOCAL time - which is the time the task actually runs and therefore the one to compare.
    $local = [datetime]::new(2026, 1, 1, 3, 0, 0, [System.DateTimeKind]::Local)
    $xml = New-CapturedXml -Triggers ('<Triggers><CalendarTrigger><StartBoundary>{0}</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>' -f
        [System.Xml.XmlConvert]::ToString($local, [System.Xml.XmlDateTimeSerializationMode]::Local))

    $verdict = Test-WacCapturedTaskDefinition -Xml $xml -Task (New-RestoredTask)
    Assert-True $verdict.Match ([string]$verdict.Reason)
}

# ---------------------------------------------------------------------------------------------
# The action: a path is not an argument
# ---------------------------------------------------------------------------------------------

Test-Case 'The program is compared as a path and the arguments are compared byte for byte' {
    # Windows resolves an executable path case-insensitively and hands a working directory back with
    # or without its trailing separator, so neither is a change. A command LINE is not a path: the
    # case of a switch, a quoted script path or a parameter value is what SYSTEM actually runs.
    $path = New-RestoredTask
    $path.Actions[0].Execute = 'c:\WINDOWS\system32\windowspowershell\v1.0\POWERSHELL.EXE'
    $path.Actions[0].WorkingDirectory = ($script:TaskRoot + '\')
    $verdict = Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $path
    Assert-True $verdict.Match ([string]$verdict.Reason)

    $arguments = New-RestoredTask
    $arguments.Actions[0].Arguments = $script:TaskArguments.Replace('-Scheduled', '-scheduled')
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $arguments) `
        -Pattern "action 1's Arguments" -Message 'a command line that came back differing in case was reported as restored'

    $program = New-RestoredTask
    $program.Actions[0].Execute = 'C:\Windows\System32\cmd.exe'
    Assert-NotRestored -Verdict (Test-WacCapturedTaskDefinition -Xml (New-CapturedXml) -Task $program) `
        -Pattern "action 1's Command" -Message 'a task that came back running a different program was reported as restored'
}

Test-Case 'A capture with no readable action proves nothing and is refused' {
    $verdict = Test-WacCapturedTaskDefinition -Xml '<Task><Settings><Hidden>true</Hidden></Settings></Task>' -Task (New-RestoredTask)
    Assert-NotRestored -Verdict $verdict -Pattern 'declares no program to run' -Message 'a definition with no action was accepted'

    $broken = Test-WacCapturedTaskDefinition -Xml 'not xml at all' -Task (New-RestoredTask)
    Assert-NotRestored -Verdict $broken -Pattern 'not readable XML' -Message 'unreadable XML was accepted'
}

Complete-TestRun
