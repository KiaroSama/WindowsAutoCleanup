<#
.SYNOPSIS
    The installer's scheduled-task lifecycle: the trigger it builds, the conflicting registration it
    clears, the read-back that proves what landed, and the rollback that puts both the tree and the
    task back.

.DESCRIPTION
    Dot-sourced by Install-WindowsAutoCleanupTask.ps1 into that script's own scope, and used by
    nothing else. It is not part of the Deploy module: a module can only hand a script what it
    EXPORTS, and the Deploy package's export list is fixed. Split out of the installer by
    responsibility - the entry point keeps its console and log plumbing, its elevation wrapper and
    its orchestration, and this file keeps everything that decides what happens to the registered
    task.

    Write-InstallerMessage and the module functions these call live in the host script and in the
    modules it imports. PowerShell resolves a command when it is CALLED, not when it is defined, and
    nothing here runs before Invoke-Main, so the load order is not a constraint.
#>

Set-StrictMode -Version 2.0

function Get-InstallerTaskTrigger {
    param([Parameter(Mandatory = $true)][string]$RunTime)

    $parsed = $null
    try {
        $parsed = [datetime]::ParseExact($RunTime, 'HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        throw ("Invalid DailyRunTime '{0}'. Use 24-hour HH:mm, for example '03:00'." -f $RunTime)
    }

    return (New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.Add($parsed.TimeOfDay)))
}

function Resolve-ConflictingTask {
    <#
    .SYNOPSIS
        Clears our own registration - current or pre-1.2 - before re-registering, refuses to touch
        anyone else's, and hands back the exact definition of everything it removed.
    .DESCRIPTION
        Register-ScheduledTask -Force is documented only as "without prompting for confirmation";
        nothing says it overwrites. So the installer explicitly Gets, proves ownership, then
        Unregisters (ledger P0-4).

        Ledger B2-3: a foreign task at EITHER path is a REFUSAL rather than a warning-and-carry-on,
        because the pre-1.2 task ran a PATH-resolved host as SYSTEM and leaving an unrecognised one
        registered while adding a second one beside it is how a machine ends up running two cleanup
        tasks, one of them the vulnerable one. A lookup that FAILED is fatal too, and separately: a
        scheduler that will not answer is not evidence that nothing is registered.

        -RequireDefinitionCapture, and the captured definitions back on the result: this removal is
        one step of an upgrade, so it has to be undoable. Undo-Installation puts them back.

        Called BEFORE anything is switched into the live deployment root, and with the machine-wide
        lock already held, so no cleanup run can start out of the tree between here and the swap.
    .OUTPUTS
        Ok, Refused, Reason, Captured.
    #>
    param([Parameter(Mandatory = $true)][string]$DeploymentRoot)

    $captured = New-Object 'System.Collections.Generic.List[object]'
    $result = [PSCustomObject]@{ Ok = $true; Refused = $false; Reason = $null; Captured = @() }

    $discovery = Get-WacInstalledTask -IncludeLegacy
    if ($discovery.State -eq 'Failed') {
        $result.Ok = $false
        $result.Reason = ('The Task Scheduler could not be queried, so whether a task is already registered is unknown: {0}' -f
            ((@($discovery.Failure | ForEach-Object { '{0}: {1}' -f $_.TaskPath, $_.Reason })) -join '; '))
        return $result
    }

    foreach ($existing in @($discovery.Task)) {
        $label = '{0}{1}' -f [string]$existing.TaskPath, [string]$existing.TaskName

        $removal = Remove-WacInstalledTask -Task $existing -DeploymentRoot $DeploymentRoot -AllowLegacyMigration -RequireDefinitionCapture
        if ($removal.Captured) { [void]$captured.Add($removal) }
        $result.Captured = @($captured.ToArray())

        if ($removal.Verified) {
            Write-InstallerMessage -Level INFO -Message 'Removed the previously registered WindowsAutoCleanup task and kept its definition for a rollback.' -Data @{
                task = $label; reason = [string]$removal.Reason
            }
            continue
        }

        $result.Ok = $false

        if ($removal.Removed) {
            $result.Reason = ('The task at {0} was unregistered but its removal could not be verified: {1}' -f $label, [string]$removal.Reason)
            return $result
        }

        if ($removal.Captured) {
            # The capture only happens after the ownership proof, so this task IS ours and the
            # unregister itself is what failed. Not a refusal: nothing was left in place by choice.
            $result.Reason = ('Our task at {0} could not be unregistered: {1}' -f $label, [string]$removal.Reason)
            return $result
        }

        # Nothing removed and nothing captured: the task is not ours, or its definition could not be
        # captured and removing it would not have been undoable. Both left it exactly as found.
        $result.Refused = $true
        $result.Reason = ('The task at {0} was left untouched and nothing was registered beside it: {1}' -f $label, [string]$removal.Reason)
        return $result
    }

    return $result
}

function Get-CapturedText {
    <#
    .SYNOPSIS
        The trimmed text of one element of the captured definition, or $null when the capture does
        not declare it.
    .DESCRIPTION
        Absent is not empty, and the difference decides whether a field is compared at all. A
        scheduler default the export omitted reads back from the registered task as a concrete
        value, so demanding equality on an element the capture never carried would fail a rollback
        that in fact put the task back exactly as it was. $null therefore means "not declared, not
        compared" everywhere below.

        Read through local-name() XPath rather than the XML adapter's dotted properties, for two
        reasons: Export-ScheduledTask emits a default namespace, and under Set-StrictMode -Version
        2.0 a missing element is a terminating error rather than $null.
    #>
    param(
        [AllowNull()]$Node,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not $Node) { return $null }
    $child = $Node.SelectSingleNode($Path)
    if (-not $child) { return $null }
    return ([string]$child.InnerText).Trim()
}

function Get-TaskValue {
    <#
    .SYNOPSIS
        A dotted property path off the read-back task as a trimmed string, or $null when the object
        does not expose it.
    .DESCRIPTION
        Every hop is guarded because under Set-StrictMode -Version 2.0 reading a property an object
        does not have is a TERMINATING error: an older scheduler build, a partly populated CIM
        instance or a stand-in object answers $null here instead of taking the whole rollback down.
        $null is NOT a match - the caller reports a field it cannot read as unproven.
    #>
    param(
        [Parameter(Mandatory = $true)]$Task,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $current = $Task
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current) { return $null }
        try { $current = $current.$segment } catch { return $null }
    }

    if ($null -eq $current) { return $null }
    return ([string]$current).Trim()
}

function Get-TaskCollection {
    <#
    .SYNOPSIS
        One collection member of the read-back task as an array, empty when it is absent or null.
    .DESCRIPTION
        @($null) is an array of ONE null element, not an empty array, so a task with no triggers
        would otherwise read as a task with one unreadable trigger.

        Every return carries the unary comma, because PowerShell UNROLLS a returned collection: a
        one-action task would arrive at the caller as a bare action object and an empty one as
        $null, and under Set-StrictMode -Version 2.0 asking either for .Count is a terminating
        error rather than 1 or 0 (measured: Windows PowerShell 5.1 fails on the scalar, both hosts
        on the $null).
    #>
    param(
        [Parameter(Mandatory = $true)]$Task,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $value = $null
    try { $value = $Task.$Name } catch { return (, @()) }
    if ($null -eq $value) { return (, @()) }
    return (, @($value))
}

function ConvertTo-TaskComparableValue {
    <#
    .SYNOPSIS
        One canonical spelling for the fields the exported XML and the registered task word
        differently.
    .DESCRIPTION
        The two sides of this comparison are two representations of the same task and neither is
        wrong, so each normalisation is named and bounded rather than applied as a general
        case-insensitive fold:

          Boolean  - the XML says true/false, the object hands back a [bool] or 1/0.
          Duration - ISO 8601 on both sides, so PT4H and PT240M are the same limit; compared as
                     ticks. Unparseable text is compared as text rather than silently equal.
          Moment   - a trigger boundary is an ISO 8601 datetime; Unspecified so an offset form
                     converts to the LOCAL time the task will actually fire, exactly as
                     Assert-RegisteredTask reads it.
          RunLevel - HighestAvailable/LeastPrivilege in the XML, Highest/Limited from the object,
                     and an integer on some builds.
          LogonType and Instances - the object returns the enumeration's NAME on one build and its
                     NUMBER on another; both fold to the name.
          UserId   - SYSTEM reads back as SYSTEM, NT AUTHORITY\SYSTEM or S-1-5-18 depending on the
                     build. The three are one account; anything else is left alone, so a DIFFERENT
                     account can never fold into a match.
          Path     - an executable or working directory: Windows compares those case-insensitively
                     and a directory may arrive with or without its trailing separator. ARGUMENTS
                     are deliberately NOT paths - they are compared byte for byte, because a case
                     change inside them changes what SYSTEM runs.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )

    $text = $Value.Trim()
    if ($text.Length -eq 0) { return '' }

    switch ($Kind) {
        'Boolean' {
            if ($text -match '(?i)^(true|1)$') { return 'TRUE' }
            if ($text -match '(?i)^(false|0)$') { return 'FALSE' }
            return $text.ToUpperInvariant()
        }
        'Duration' {
            try { return ([string]([System.Xml.XmlConvert]::ToTimeSpan($text)).Ticks) }
            catch { return $text.ToUpperInvariant() }
        }
        'Moment' {
            try {
                return ([System.Xml.XmlConvert]::ToDateTime($text, [System.Xml.XmlDateTimeSerializationMode]::Unspecified)).ToString(
                    'yyyy-MM-ddTHH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
            }
            catch { return $text.ToUpperInvariant() }
        }
        'RunLevel' {
            if ($text -match '(?i)^(1|highest|highestavailable)$') { return 'HIGHEST' }
            if ($text -match '(?i)^(0|limited|leastprivilege)$') { return 'LIMITED' }
            return $text.ToUpperInvariant()
        }
        'LogonType' {
            # MSFT_TaskPrincipal's enumeration, in its documented order.
            return (Get-TaskEnumerationName -Value $text -Name @('None', 'Password', 'S4U', 'Interactive', 'Group', 'ServiceAccount', 'InteractiveOrPassword'))
        }
        'Instances' {
            return (Get-TaskEnumerationName -Value $text -Name @('Parallel', 'Queue', 'IgnoreNew', 'StopExisting'))
        }
        'UserId' {
            if ($text -match '(?i)^(system|nt authority\\system|s-1-5-18)$') { return 'S-1-5-18' }
            if ($text -match '(?i)^(local service|nt authority\\local service|s-1-5-19)$') { return 'S-1-5-19' }
            if ($text -match '(?i)^(network service|nt authority\\network service|s-1-5-20)$') { return 'S-1-5-20' }
            return $text.ToUpperInvariant()
        }
        'Path' {
            $trimmed = $text.Trim('"')
            # Longer than 3, so C:\ keeps the separator that makes it a root rather than a volume.
            if ($trimmed.Length -gt 3) { $trimmed = $trimmed.TrimEnd('\') }
            return $trimmed.ToUpperInvariant()
        }
        default { return $text }
    }
}

function Get-TaskEnumerationName {
    <#
    .SYNOPSIS
        The upper-case name of an enumeration value that may arrive as a name or as its index.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string[]]$Name
    )

    if ($Value -match '^\d+$') {
        $index = [int]$Value
        if ($index -ge 0 -and $index -lt $Name.Count) { return $Name[$index].ToUpperInvariant() }
    }
    return $Value.ToUpperInvariant()
}

function Test-CapturedField {
    <#
    .SYNOPSIS
        Compares one field the capture declares. Returns $null when there is nothing to report, or
        the reason the restored task does not match.
    .DESCRIPTION
        A $null Want means the capture did not declare the field, so there is nothing to prove. A
        $null Have means the restored task does not expose it, which is MISSING EVIDENCE and is
        reported as a mismatch: a rollback that cannot read a field back has not proven it landed.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Kind,
        [AllowNull()]$Want,
        [AllowNull()]$Have
    )

    if ($null -eq $Want) { return $null }
    if ($null -eq $Have) {
        return ("{0} cannot be read back from the restored task, so the captured value '{1}' is unproven" -f $Label, [string]$Want)
    }

    # Ordinal, always: the normaliser above has already folded every difference that is a spelling
    # rather than a change, so whatever is left is a real difference in what the task will do.
    $left = ConvertTo-TaskComparableValue -Kind $Kind -Value ([string]$Want)
    $right = ConvertTo-TaskComparableValue -Kind $Kind -Value ([string]$Have)
    if ([string]::Equals($left, $right, [System.StringComparison]::Ordinal)) { return $null }

    return ("{0} is '{1}' where the captured definition says '{2}'" -f $Label, [string]$Have, [string]$Want)
}

function Test-CapturedTaskPrincipal {
    <#
    .SYNOPSIS
        The account the restored task runs as, and with what rights. Returns $null or the reason.
    .DESCRIPTION
        A task with the same action under a DIFFERENT identity is not the task that was removed: it
        is the same program run by somebody else, at somebody else's privilege level, and calling
        that a restoration is how a SYSTEM task quietly becomes a user task (ledger WAC-02R).
    #>
    param(
        [Parameter(Mandatory = $true)]$Document,
        [Parameter(Mandatory = $true)]$Task
    )

    $principal = $Document.SelectSingleNode("//*[local-name()='Principals']/*[local-name()='Principal']")
    if (-not $principal) { return $null }

    foreach ($field in @(
        @{ Element = 'UserId'; Property = 'Principal.UserId'; Kind = 'UserId'; Label = 'the restored task''s user' },
        @{ Element = 'GroupId'; Property = 'Principal.GroupId'; Kind = 'UserId'; Label = 'the restored task''s group' },
        @{ Element = 'LogonType'; Property = 'Principal.LogonType'; Kind = 'LogonType'; Label = 'the restored task''s logon type' },
        @{ Element = 'RunLevel'; Property = 'Principal.RunLevel'; Kind = 'RunLevel'; Label = 'the restored task''s run level' })) {

        $reason = Test-CapturedField -Label $field.Label -Kind $field.Kind `
            -Want (Get-CapturedText -Node $principal -Path ("*[local-name()='{0}']" -f $field.Element)) `
            -Have (Get-TaskValue -Task $Task -Path $field.Property)
        if ($reason) { return $reason }
    }

    return $null
}

function Test-CapturedTaskSettings {
    <#
    .SYNOPSIS
        Enabledness, and the execution, restart and battery settings that decide whether the task
        ever runs. Returns $null or the reason.
    .DESCRIPTION
        A task that is back but DISABLED, or back with its four-hour limit gone, or back without the
        battery settings that let a laptop run it at all, is a task the machine still does not have.
        Only what the capture declares is compared - see Get-CapturedText.
    #>
    param(
        [Parameter(Mandatory = $true)]$Document,
        [Parameter(Mandatory = $true)]$Task
    )

    $settings = $Document.SelectSingleNode("//*[local-name()='Settings']")
    if (-not $settings) { return $null }

    foreach ($field in @(
        @{ Element = "*[local-name()='Enabled']"; Property = 'Settings.Enabled'; Kind = 'Boolean'; Label = 'the restored task''s enabled state' },
        @{ Element = "*[local-name()='Hidden']"; Property = 'Settings.Hidden'; Kind = 'Boolean'; Label = 'the restored task''s hidden state' },
        @{ Element = "*[local-name()='DisallowStartIfOnBatteries']"; Property = 'Settings.DisallowStartIfOnBatteries'; Kind = 'Boolean'; Label = 'the restored task''s DisallowStartIfOnBatteries' },
        @{ Element = "*[local-name()='StopIfGoingOnBatteries']"; Property = 'Settings.StopIfGoingOnBatteries'; Kind = 'Boolean'; Label = 'the restored task''s StopIfGoingOnBatteries' },
        @{ Element = "*[local-name()='StartWhenAvailable']"; Property = 'Settings.StartWhenAvailable'; Kind = 'Boolean'; Label = 'the restored task''s StartWhenAvailable' },
        @{ Element = "*[local-name()='MultipleInstancesPolicy']"; Property = 'Settings.MultipleInstances'; Kind = 'Instances'; Label = 'the restored task''s multiple-instances policy' },
        @{ Element = "*[local-name()='ExecutionTimeLimit']"; Property = 'Settings.ExecutionTimeLimit'; Kind = 'Duration'; Label = 'the restored task''s execution time limit' },
        @{ Element = "*[local-name()='RestartOnFailure']/*[local-name()='Count']"; Property = 'Settings.RestartCount'; Kind = 'Text'; Label = 'the restored task''s restart count' },
        @{ Element = "*[local-name()='RestartOnFailure']/*[local-name()='Interval']"; Property = 'Settings.RestartInterval'; Kind = 'Duration'; Label = 'the restored task''s restart interval' })) {

        $reason = Test-CapturedField -Label $field.Label -Kind $field.Kind `
            -Want (Get-CapturedText -Node $settings -Path $field.Element) `
            -Have (Get-TaskValue -Task $Task -Path $field.Property)
        if ($reason) { return $reason }
    }

    return $null
}

function Test-CapturedTaskTrigger {
    <#
    .SYNOPSIS
        When the restored task will fire, and how often. Returns $null or the reason.
    .DESCRIPTION
        The schedule is half of what a scheduled task IS. A daily cleanup that comes back as a
        one-shot, at a different hour, or disabled at the trigger rather than at the task, runs at a
        time the operator never asked for - or never.

        The CIM class name is checked only when the object exposes one: it is an object-model detail
        that a real scheduler always provides, so its absence never silences the boundary and
        interval checks, which are compared for every declared trigger.
    #>
    param(
        [Parameter(Mandatory = $true)]$Document,
        [Parameter(Mandatory = $true)]$Task
    )

    $expected = @($Document.SelectNodes("//*[local-name()='Triggers']/*"))
    if ($expected.Count -eq 0) { return $null }

    $actual = @(Get-TaskCollection -Task $Task -Name 'Triggers')
    if ($actual.Count -ne $expected.Count) {
        return ('the restored task has {0} trigger(s) where the captured definition declares {1}' -f $actual.Count, $expected.Count)
    }

    for ($index = 0; $index -lt $expected.Count; $index++) {
        $label = 'trigger {0}' -f ($index + 1)
        $kind = Get-TaskTriggerKind -Node $expected[$index]
        $className = Get-TaskValue -Task $actual[$index] -Path 'CimClass.CimClassName'
        if ($className -and $kind -and $className -notmatch ('(?i){0}' -f [regex]::Escape($kind))) {
            return ("{0} is a '{1}' where the captured definition declares a {2} trigger" -f $label, $className, $kind)
        }

        foreach ($field in @(
            @{ Element = "*[local-name()='StartBoundary']"; Property = 'StartBoundary'; Kind = 'Moment'; Label = ('{0} starts at' -f $label) },
            @{ Element = "*[local-name()='EndBoundary']"; Property = 'EndBoundary'; Kind = 'Moment'; Label = ('{0} ends at' -f $label) },
            @{ Element = "*[local-name()='Enabled']"; Property = 'Enabled'; Kind = 'Boolean'; Label = ('{0}''s enabled state' -f $label) },
            @{ Element = "*[local-name()='ScheduleByDay']/*[local-name()='DaysInterval']"; Property = 'DaysInterval'; Kind = 'Text'; Label = ('{0}''s day interval' -f $label) },
            @{ Element = "*[local-name()='ScheduleByWeek']/*[local-name()='WeeksInterval']"; Property = 'WeeksInterval'; Kind = 'Text'; Label = ('{0}''s week interval' -f $label) })) {

            $reason = Test-CapturedField -Label $field.Label -Kind $field.Kind `
                -Want (Get-CapturedText -Node $expected[$index] -Path $field.Element) `
                -Have (Get-TaskValue -Task $actual[$index] -Path $field.Property)
            if ($reason) { return $reason }
        }
    }

    return $null
}

function Get-TaskTriggerKind {
    <#
    .SYNOPSIS
        The word the scheduler's CIM class name for a trigger element contains, or $null.
    .DESCRIPTION
        A CalendarTrigger is Daily, Weekly or Monthly according to its schedule child, which is why
        the element name alone does not answer this.
    #>
    param([Parameter(Mandatory = $true)]$Node)

    $element = [string]$Node.LocalName
    if ([string]::Equals($element, 'CalendarTrigger', [System.StringComparison]::OrdinalIgnoreCase)) {
        foreach ($schedule in @('ScheduleByDay|Daily', 'ScheduleByWeek|Weekly', 'ScheduleByMonthDayOfWeek|MonthlyDOW', 'ScheduleByMonth|Monthly')) {
            $name = $schedule.Split('|')[0]
            if ($Node.SelectSingleNode(("*[local-name()='{0}']" -f $name))) { return $schedule.Split('|')[1] }
        }
        return $null
    }

    if ($element -match '(?i)^(\w+)Trigger$') { return $Matches[1] }
    return $null
}

function Test-CapturedTaskDefinition {
    <#
    .SYNOPSIS
        Compares the task a rollback read back against the definition it re-registered.
    .DESCRIPTION
        A task with the right name is not the task that was removed, and that name was once the
        whole of the proof. Register-ScheduledTask can land a definition the scheduler normalised or
        partly rejected, and a same-name task something else created between the removal and the
        rollback reads back exactly as convincingly.

        The ACTION alone is not the whole of it either (ledger WAC-02R). What the machine lost when
        this run unregistered its task was a program, run under a particular IDENTITY, on a
        particular SCHEDULE, with the settings that decide whether it runs at all - so a task whose
        Exec matches while it runs as a different user, at a different hour, or disabled, is not
        restored. Every part the capture declares is compared: actions, principal, settings and
        triggers.
    .OUTPUTS
        Match ([bool]) and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Xml,
        [Parameter(Mandatory = $true)]$Task
    )

    $result = [PSCustomObject]@{ Match = $false; Reason = $null }

    $document = New-Object System.Xml.XmlDocument
    try { $document.LoadXml($Xml) }
    catch {
        $result.Reason = ('the captured definition is not readable XML: {0}' -f $_.Exception.Message)
        return $result
    }

    $expected = @($document.SelectNodes("//*[local-name()='Actions']/*[local-name()='Exec']"))
    if ($expected.Count -eq 0) {
        $result.Reason = 'the captured definition declares no program to run, so nothing about the restored task can be checked against it'
        return $result
    }

    $actual = @(Get-TaskCollection -Task $Task -Name 'Actions')
    if ($actual.Count -ne $expected.Count) {
        $result.Reason = ('the restored task has {0} action(s) where the captured definition declares {1}' -f $actual.Count, $expected.Count)
        return $result
    }

    for ($index = 0; $index -lt $expected.Count; $index++) {
        # Command and WorkingDirectory are PATHS and compared as such; Arguments are not, and are
        # compared byte for byte - a case change there is a different command line for SYSTEM.
        foreach ($field in @(
            @{ Element = 'Command'; Property = 'Execute'; Kind = 'Path' },
            @{ Element = 'Arguments'; Property = 'Arguments'; Kind = 'Text' },
            @{ Element = 'WorkingDirectory'; Property = 'WorkingDirectory'; Kind = 'Path' })) {

            # An Exec element that declares no Arguments means exactly that: no arguments. Absent
            # here is '' rather than "not compared", because the action is the one part of the
            # definition the capture is required to carry in full.
            $want = Get-CapturedText -Node $expected[$index] -Path ("*[local-name()='{0}']" -f $field.Element)
            if ($null -eq $want) { $want = '' }
            $have = Get-TaskValue -Task $actual[$index] -Path $field.Property
            if ($null -eq $have) { $have = '' }

            $reason = Test-CapturedField -Label ("action {0}'s {1}" -f ($index + 1), $field.Element) `
                -Kind $field.Kind -Want $want -Have $have
            if ($reason) {
                $result.Reason = $reason
                return $result
            }
        }
    }

    foreach ($part in @(
        (Test-CapturedTaskPrincipal -Document $document -Task $Task),
        (Test-CapturedTaskSettings -Document $document -Task $Task),
        (Test-CapturedTaskTrigger -Document $document -Task $Task))) {

        if ($part) {
            $result.Reason = [string]$part
            return $result
        }
    }

    $result.Match = $true
    $result.Reason = ('all {0} captured action(s), and every principal, setting and trigger the capture declares, are back unchanged' -f $expected.Count)
    return $result
}

function Restore-CapturedTask {
    <#
    .SYNOPSIS
        Re-registers one task definition Resolve-ConflictingTask captured, and reads it back.
    .OUTPUTS
        [bool] $true only when the task is registered again AND the scheduler confirms it is the
        task that was captured, not merely that something with that name exists.
    #>
    param([Parameter(Mandatory = $true)]$Definition)

    $label = '{0}{1}' -f [string]$Definition.TaskPath, [string]$Definition.TaskName
    $xml = [string]$Definition.Definition

    if (-not $Definition.Captured -or [string]::IsNullOrWhiteSpace($xml)) {
        Write-InstallerMessage -Level CRITICAL -Message 'Rollback has no captured definition for a task this run removed, so it cannot be put back.' -Data @{
            task = $label; reason = [string]$Definition.CaptureReason
        }
        return $false
    }

    try {
        Register-ScheduledTask -TaskName $Definition.TaskName -TaskPath $Definition.TaskPath -Xml $xml -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Write-InstallerMessage -Level CRITICAL -Message 'Rollback could not re-register the task this run removed; re-create it by hand.' -Data @{
            task = $label; error = $_.Exception.Message
        }
        return $false
    }

    $lookup = Get-WacInstalledTask -IncludeLegacy
    # ORDINAL, not -ieq: this identifies which task was read back after a rollback.
    $back = @(@($lookup.Task) | Where-Object {
        [string]::Equals(('{0}{1}' -f [string]$_.TaskPath, [string]$_.TaskName), $label, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($lookup.State -eq 'Failed' -or $back.Count -ne 1) {
        Write-InstallerMessage -Level CRITICAL -Message 'Rollback re-registered the task this run removed but could not read it back, so its restoration is unproven.' -Data @{
            task = $label; state = [string]$lookup.State
        }
        return $false
    }

    $semantics = Test-CapturedTaskDefinition -Xml $xml -Task $back[0]
    if (-not $semantics.Match) {
        Write-InstallerMessage -Level CRITICAL -Message 'Rollback re-registered the task this run removed but what came back is not the task that was captured; re-create it by hand.' -Data @{
            task = $label; reason = [string]$semantics.Reason
        }
        return $false
    }

    Write-InstallerMessage -Level WARNING -Message 'Rollback: the task this run removed was re-registered and verified.' -Data @{
        task = $label; proof = [string]$semantics.Reason
    }
    return $true
}

function Undo-Installation {
    <#
    .SYNOPSIS
        Puts the machine back the way it was after a failure anywhere between the swap and the final
        assertion. Returns $true only when that is PROVEN.
    .DESCRIPTION
        Order matters, and so does refusing. The task this run registered is removed FIRST, through
        the same ownership proof. If that removal cannot be VERIFIED - refused, failed, or a
        scheduler that will not answer - the deployment is KEPT and this returns false: a
        registration that may still point into the tree makes deleting the tree strictly worse than
        leaving it, and a same-name task nobody could identify is never "clean".

        Only once nothing can reach the tree is the deployment restored, and only after THAT are the
        definitions Resolve-ConflictingTask captured re-registered - the task it removed pointed
        into the tree that has just been put back.
    .OUTPUTS
        [bool] $true only when the task state and the deployment were both restored and verified.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$DeploymentRoot,
        [AllowNull()][AllowEmptyCollection()][object[]]$CapturedTask = @()
    )

    $lookup = Get-WacInstalledTask
    if ($lookup.State -eq 'Failed') {
        Write-InstallerMessage -Level CRITICAL -Message 'Rollback stopped: the Task Scheduler could not be queried, so the deployment was KEPT because a task may still reference it. Remove the task and the deployment by hand.' -Data @{
            root = $DeploymentRoot
            findings = ((@($lookup.Failure | ForEach-Object { '{0}: {1}' -f $_.TaskPath, $_.Reason })) -join '; ')
        }
        return $false
    }

    foreach ($task in @($lookup.Task)) {
        $removal = Remove-WacInstalledTask -Task $task -DeploymentRoot $DeploymentRoot
        if ($removal.Verified) {
            Write-InstallerMessage -Level WARNING -Message 'Rollback: the task registered by this run was unregistered and verified absent.' -Data @{
                task = ('{0}{1}' -f $removal.TaskPath, $removal.TaskName)
            }
            continue
        }

        Write-InstallerMessage -Level CRITICAL -Message 'Rollback could not verify removal of the task at this path, so the deployment it may reference was KEPT. Remove both by hand.' -Data @{
            task = ('{0}{1}' -f $removal.TaskPath, $removal.TaskName); reason = [string]$removal.Reason; root = $DeploymentRoot
        }
        return $false
    }

    $restored = Restore-WacDeploymentPrevious
    if ($restored.Restored) {
        Write-InstallerMessage -Level WARNING -Message 'Rollback: the deployment was restored to its previous state.' -Data @{
            hadPrevious = [bool]$restored.HadPrevious; reason = [string]$restored.Reason
        }
    }
    else {
        Write-InstallerMessage -Level CRITICAL -Message 'Rollback could not restore the previous deployment.' -Data @{ reason = [string]$restored.Reason }
    }

    $ok = [bool]$restored.Restored
    foreach ($definition in @($CapturedTask)) {
        if (-not (Restore-CapturedTask -Definition $definition)) { $ok = $false }
    }

    return $ok
}

function Assert-RegisteredTask {
    <#
    .SYNOPSIS
        Reads the task back and proves every setting the installer asked for actually landed.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ExpectedHost,
        [Parameter(Mandatory = $true)][string]$ExpectedArguments,
        [Parameter(Mandatory = $true)][string]$ExpectedDescription,
        [Parameter(Mandatory = $true)][string]$ExpectedWorkingDirectory,
        [Parameter(Mandatory = $true)][string]$ExpectedRunTime
    )

    # Through the ternary lookup, so a read-back that FAILED - a scheduler that stopped answering
    # between the registration and here - cannot be mistaken for a task that is simply absent.
    $lookup = Get-WacInstalledTask
    if ($lookup.State -ne 'Found') {
        throw ("The task was registered without error but the scheduler does not report it registered (state {0}): {1}" -f
            [string]$lookup.State, ((@($lookup.Failure | ForEach-Object { $_.Reason })) -join '; '))
    }
    $task = @($lookup.Task)[0]

    $actions = @($task.Actions)
    if ($actions.Count -ne 1) {
        throw ("The registered task has {0} actions instead of exactly one." -f $actions.Count)
    }
    $action = $actions[0]

    $checks = @(
        @{ Name = 'Hidden'; Actual = [string][bool]$task.Settings.Hidden; Expected = 'True' }
        @{ Name = 'RunLevel'; Actual = [string]$task.Principal.RunLevel; Expected = 'Highest' }
        @{ Name = 'LogonType'; Actual = [string]$task.Principal.LogonType; Expected = 'ServiceAccount' }
        @{ Name = 'Compatibility'; Actual = [string]$task.Settings.Compatibility; Expected = 'Win8' }
        @{ Name = 'MultipleInstances'; Actual = [string]$task.Settings.MultipleInstances; Expected = 'IgnoreNew' }
        @{ Name = 'StartWhenAvailable'; Actual = [string][bool]$task.Settings.StartWhenAvailable; Expected = 'True' }
        @{ Name = 'Execute'; Actual = [string]$action.Execute; Expected = $ExpectedHost }
        @{ Name = 'Arguments'; Actual = [string]$action.Arguments; Expected = $ExpectedArguments }
        @{ Name = 'Description'; Actual = [string]$task.Description; Expected = $ExpectedDescription }
    )

    foreach ($check in $checks) {
        if (-not [string]::Equals([string]$check.Actual, [string]$check.Expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ("The registered task's {0} is '{1}' instead of '{2}'." -f $check.Name, $check.Actual, $check.Expected)
        }
    }

    # Compared through the canonicaliser rather than as raw text: the scheduler is free to hand a
    # directory back with a trailing separator, and a plain string compare would fail an install
    # that is in fact exactly right.
    $actualWorking = Get-WacNormalizedPath -Path ([string]$action.WorkingDirectory)
    $expectedWorking = Get-WacNormalizedPath -Path $ExpectedWorkingDirectory
    if (-not $actualWorking -or -not $expectedWorking -or
        -not [string]::Equals($actualWorking, $expectedWorking, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("The registered task's WorkingDirectory is '{0}' instead of '{1}'." -f [string]$action.WorkingDirectory, $ExpectedWorkingDirectory)
    }

    # UserId reads back as the account name on some builds and as the SID on others.
    $userId = [string]$task.Principal.UserId
    if ($userId -notmatch '(?i)^(SYSTEM|NT AUTHORITY\\SYSTEM|S-1-5-18)$') {
        throw ("The registered task runs as '{0}' instead of SYSTEM." -f $userId)
    }

    # ExecutionTimeLimit comes back as an ISO 8601 duration string, not a TimeSpan.
    $limit = [string]$task.Settings.ExecutionTimeLimit
    $limitSpan = [timespan]::Zero
    try { $limitSpan = [System.Xml.XmlConvert]::ToTimeSpan($limit) } catch { $limitSpan = [timespan]::Zero }
    if ($limitSpan -ne (New-TimeSpan -Hours 4)) {
        throw ("The registered task's ExecutionTimeLimit is '{0}' instead of 4 hours." -f $limit)
    }

    # The trigger is asserted too (ledger B2-3): a task registered with the wrong or an extra
    # trigger runs the cleanup at a time the operator never asked for, and until now nothing read
    # it back. StartBoundary is an ISO 8601 LOCAL datetime string, not a DateTime.
    $triggers = @($task.Triggers)
    if ($triggers.Count -ne 1) {
        throw ("The registered task has {0} triggers instead of exactly one daily trigger." -f $triggers.Count)
    }
    $triggerKind = ''
    try { $triggerKind = [string]$triggers[0].CimClass.CimClassName } catch { $triggerKind = '' }
    if ($triggerKind -and $triggerKind -notmatch '(?i)Daily') {
        throw ("The registered task's trigger is '{0}' instead of a daily trigger." -f $triggerKind)
    }
    # Unspecified, and it matters. Measured on both shipped hosts: given '...T20:00:00' the reading
    # is 20:00, and given an offset form such as '...T20:00:00+02:00' it converts to the equivalent
    # LOCAL time - which is the time the task will actually fire, and therefore the one to compare
    # against what the operator asked for. Do not "fix" this to RoundtripKind.
    $startBoundary = [string]$triggers[0].StartBoundary
    $startAt = [datetime]::MinValue
    try { $startAt = [System.Xml.XmlConvert]::ToDateTime($startBoundary, [System.Xml.XmlDateTimeSerializationMode]::Unspecified) }
    catch { throw ("The registered task's StartBoundary '{0}' is not a datetime." -f $startBoundary) }
    $actualRunTime = $startAt.ToString('HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    if (-not [string]::Equals($actualRunTime, $ExpectedRunTime, [System.StringComparison]::Ordinal)) {
        throw ("The registered task runs daily at '{0}' instead of '{1}'." -f $actualRunTime, $ExpectedRunTime)
    }

    $ownership = Test-WacTaskIsOurs -Task $task -DeploymentRoot $ExpectedWorkingDirectory
    if (-not $ownership.IsOurs) {
        throw ("The registered task does not pass its own ownership proof: {0}" -f $ownership.Reason)
    }

    return $task
}
