<#
.SYNOPSIS
    Whether a scheduled task the machine is showing us is the one a captured definition describes:
    the exact program, the identity that runs it, the conditions it runs under and the schedule it
    runs on.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Deploy.psm1; see that file for why the parts are dot-sourced
    rather than imported. Split out of WindowsAutoCleanup.InstallerTask.ps1, which had reached the
    size at which nobody reads it, and moved into the package rather than kept beside the installer
    because it answers the same KIND of question as Test-WacTaskIsOurs and now has two consumers.

    A rollback asks whether the task it just re-registered is the one it captured. Recovery asks
    whether a task already standing under that name IS the captured one or a different task wearing
    its name (ledger WAC-02R) - and that second question is what turned "a task with the right name"
    from a convenience into a decision that can destroy evidence. One answer, one implementation:
    two copies of this comparison would be one that gets fixed and one that does not.

    Nothing here registers, unregisters or writes anything. Every function is a question.
#>

Set-StrictMode -Version 2.0

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
        The members of one collection on the read-back task, for a caller that wraps the call in
        @(). Nothing is emitted when the collection is absent, unreadable or null.
    .DESCRIPTION
        @($null) is an array of ONE null element, not an empty array, so a task with no triggers
        would otherwise read as a task with one unreadable trigger.

        NO unary comma, and that is the fix rather than an oversight (ledger WAC-02R). Every return
        used to carry one, to stop PowerShell unrolling the collection - but the comma made the
        function emit the collection AS A SINGLE OBJECT, so `@(Get-TaskCollection ...)` came back
        with Count 1 for every task on earth: none, one, or nine triggers all counted as one, and
        $actual[0] was the ARRAY rather than a trigger. Every count comparison built on it was
        therefore comparing 1 against what the capture declared, and only member enumeration on the
        array - which happens to work for exactly one element - kept the field comparisons looking
        right. Measured: an empty collection, a one-element one and a two-element one all returned 1.

        The caller wraps in @() instead, which is what both of them already do, so a bare scalar and
        an emitted-nothing both arrive as a real array with a real Count under Set-StrictMode.
    #>
    param(
        [Parameter(Mandatory = $true)]$Task,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $value = $null
    try { $value = $Task.$Name } catch { return @() }
    if ($null -eq $value) { return @() }
    return @($value)
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

        Every DECLARED execution condition, not a sample of them (ledger WAC-02R). A task that comes
        back wanting the network, wanting the machine idle, no longer waking it, or unable to be
        started on demand, runs at times the operator never chose - and is nonetheless exactly the
        kind of difference an upgrade can introduce, so a comparison that skipped them would call an
        upgraded task and the one it replaced the same task.
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
        @{ Element = "*[local-name()='AllowStartOnDemand']"; Property = 'Settings.AllowDemandStart'; Kind = 'Boolean'; Label = 'the restored task''s AllowStartOnDemand' },
        @{ Element = "*[local-name()='RunOnlyIfNetworkAvailable']"; Property = 'Settings.RunOnlyIfNetworkAvailable'; Kind = 'Boolean'; Label = 'the restored task''s RunOnlyIfNetworkAvailable' },
        @{ Element = "*[local-name()='RunOnlyIfIdle']"; Property = 'Settings.RunOnlyIfIdle'; Kind = 'Boolean'; Label = 'the restored task''s RunOnlyIfIdle' },
        @{ Element = "*[local-name()='WakeToRun']"; Property = 'Settings.WakeToRun'; Kind = 'Boolean'; Label = 'the restored task''s WakeToRun' },
        @{ Element = "*[local-name()='AllowHardTerminate']"; Property = 'Settings.AllowHardTerminate'; Kind = 'Boolean'; Label = 'the restored task''s AllowHardTerminate' },
        @{ Element = "*[local-name()='Priority']"; Property = 'Settings.Priority'; Kind = 'Text'; Label = 'the restored task''s priority' },
        @{ Element = "*[local-name()='DeleteExpiredTaskAfter']"; Property = 'Settings.DeleteExpiredTaskAfter'; Kind = 'Duration'; Label = 'the restored task''s DeleteExpiredTaskAfter' },
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

        ABSENT IS NOT EMPTY here too, and the difference is the defect (ledger WAC-02R). No Triggers
        element at all means the capture never carried that part - the pre-1.2 shape - and there is
        nothing to prove. An EMPTY Triggers element means the capture declares a task that fires on
        nothing, and that used to return "nothing to report" as well, so a task the capture says
        never fires and the machine says fires every hour read as the same task. Zero declared
        against N registered is a mismatch like any other; only the per-trigger loop is skipped,
        because there is nothing to loop over.

        Repetition and the weekly day selection are compared with the rest. A daily trigger that
        comes back repeating every ten minutes for a day runs the cleanup 144 times, and a weekly
        one that comes back on Sunday instead of Monday never runs when the operator expects it -
        neither of which any of the fields above can see.
    #>
    param(
        [Parameter(Mandatory = $true)]$Document,
        [Parameter(Mandatory = $true)]$Task
    )

    $declared = $Document.SelectSingleNode("//*[local-name()='Triggers']")
    if (-not $declared) { return $null }

    $expected = @($declared.SelectNodes('*'))
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
            @{ Element = "*[local-name()='ExecutionTimeLimit']"; Property = 'ExecutionTimeLimit'; Kind = 'Duration'; Label = ('{0}''s execution time limit' -f $label) },
            @{ Element = "*[local-name()='RandomDelay']"; Property = 'RandomDelay'; Kind = 'Duration'; Label = ('{0}''s random delay' -f $label) },
            @{ Element = "*[local-name()='Delay']"; Property = 'Delay'; Kind = 'Duration'; Label = ('{0}''s delay' -f $label) },
            @{ Element = "*[local-name()='Repetition']/*[local-name()='Interval']"; Property = 'Repetition.Interval'; Kind = 'Duration'; Label = ('{0}''s repetition interval' -f $label) },
            @{ Element = "*[local-name()='Repetition']/*[local-name()='Duration']"; Property = 'Repetition.Duration'; Kind = 'Duration'; Label = ('{0}''s repetition duration' -f $label) },
            @{ Element = "*[local-name()='Repetition']/*[local-name()='StopAtDurationEnd']"; Property = 'Repetition.StopAtDurationEnd'; Kind = 'Boolean'; Label = ('{0}''s repetition stop-at-end' -f $label) },
            @{ Element = "*[local-name()='ScheduleByDay']/*[local-name()='DaysInterval']"; Property = 'DaysInterval'; Kind = 'Text'; Label = ('{0}''s day interval' -f $label) },
            @{ Element = "*[local-name()='ScheduleByWeek']/*[local-name()='WeeksInterval']"; Property = 'WeeksInterval'; Kind = 'Text'; Label = ('{0}''s week interval' -f $label) })) {

            $reason = Test-CapturedField -Label $field.Label -Kind $field.Kind `
                -Want (Get-CapturedText -Node $expected[$index] -Path $field.Element) `
                -Have (Get-TaskValue -Task $actual[$index] -Path $field.Property)
            if ($reason) { return $reason }
        }

        $reason = Test-CapturedTriggerDayOfWeek -Node $expected[$index] -Trigger $actual[$index] -Label $label
        if ($reason) { return $reason }
    }

    return $null
}

function Test-CapturedTriggerDayOfWeek {
    <#
    .SYNOPSIS
        The days a weekly trigger fires on. Returns $null or the reason.
    .DESCRIPTION
        The two sides say this completely differently and neither is convertible by the general
        normaliser: the XML carries one empty CHILD ELEMENT per day inside DaysOfWeek, while the
        registered object hands back a single bit MASK. Both fold to the mask, which is the
        scheduler's own documented encoding, so the comparison is over what the task will do rather
        than over two spellings of it.

        Not compared when the capture declares no DaysOfWeek: absent is "not declared, not
        compared", exactly as it is for every other element.
    #>
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter(Mandatory = $true)]$Trigger,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $days = $Node.SelectSingleNode("*[local-name()='ScheduleByWeek']/*[local-name()='DaysOfWeek']")
    if (-not $days) { return $null }

    # MSFT_TaskWeeklyTrigger's DaysOfWeek mask, in the scheduler's documented bit order.
    $bit = @{ SUNDAY = 1; MONDAY = 2; TUESDAY = 4; WEDNESDAY = 8; THURSDAY = 16; FRIDAY = 32; SATURDAY = 64 }
    $want = 0
    foreach ($day in @($days.SelectNodes('*'))) {
        $name = ([string]$day.LocalName).ToUpperInvariant()
        if (-not $bit.ContainsKey($name)) {
            return ("{0} declares a day this build does not recognise: '{1}'" -f $Label, [string]$day.LocalName)
        }
        $want = $want -bor [int]$bit[$name]
    }

    $have = Get-TaskValue -Task $Trigger -Path 'DaysOfWeek'
    if ($null -eq $have) {
        return ("{0}'s days of the week cannot be read back from the restored task, so the captured selection is unproven" -f $Label)
    }
    if ($have -notmatch '^\d+$') {
        return ("{0}'s days of the week read back as '{1}', which is not the scheduler's day mask" -f $Label, [string]$have)
    }
    if ([int]$have -ne $want) {
        return ("{0} fires on day mask {1} where the captured definition declares {2}" -f $Label, [int]$have, $want)
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

function Test-WacCapturedTaskDefinition {
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
