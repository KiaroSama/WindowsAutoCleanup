#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.DriverInventory (ledger T-6): the feature-detected
    structured enumeration that fails closed, and the device-evidence gate that no uncertainty may
    get past.

.DESCRIPTION
    pnputil.exe is never executed and no real driver is ever touched: the parser and the supersedence
    decision are pure functions over the fixtures in _DriverFixtures.ps1.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
foreach ($moduleLeaf in @('Core', 'FileSystem', 'Steps', 'Drivers')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

$script:DriversModule = Get-Module -Name 'WindowsAutoCleanup.Drivers'

. (Join-Path -Path $PSScriptRoot -ChildPath '_DriverFixtures.ps1')

# ---------------------------------------------------------------------------------------------
# Structured enumeration: parsed by element name, feature-detected, fail-closed
# ---------------------------------------------------------------------------------------------

Test-Case 'the structured enumeration is parsed by element name, with ExtensionId optional' {
    $row = New-PnpUtilRow -DriverName 'oem7.inf' -OriginalName 'widget.inf' -ProviderName 'Widget Ltd' `
        -ClassGuid '{aaaaaaaa-1111-2222-3333-444444444444}' -ExtensionId '{bbbbbbbb-1111-2222-3333-444444444444}' `
        -DriverVersion '31/12/2021 4.5.6.7' -SignerName 'Widget Signer' -DeviceStatus @('Started', 'Stopped')

    $parsed = ConvertFrom-WacPnpUtilDriverXml -Text (New-PnpUtilDriverXml -Row @($row))

    Assert-True $parsed.IsValid $parsed.Reason
    Assert-True $parsed.HasDeviceEvidence 'a fixture with devices reported no device evidence'
    Assert-Equal 1 (@($parsed.Driver)).Count
    Assert-Equal 'oem7.inf' $parsed.Driver[0].DriverName
    Assert-Equal 'widget.inf' $parsed.Driver[0].OriginalName
    Assert-Equal 'Widget Ltd' $parsed.Driver[0].ProviderName
    Assert-Equal '{aaaaaaaa-1111-2222-3333-444444444444}' $parsed.Driver[0].ClassGuid
    Assert-Equal '{bbbbbbbb-1111-2222-3333-444444444444}' $parsed.Driver[0].ExtensionId
    Assert-Equal 'Widget Signer' $parsed.Driver[0].SignerName
    Assert-Equal ([version]'4.5.6.7') $parsed.Driver[0].Version
    Assert-Equal '31/12/2021 4.5.6.7' $parsed.Driver[0].VersionText
    Assert-Equal 2 $parsed.Driver[0].DeviceCount

    # Measured: a non-extension package has no <ExtensionId> element at all, and reading it as a
    # property under Set-StrictMode 2.0 would throw rather than return empty.
    $plain = @((ConvertFrom-WacPnpUtilDriverXml -Text (New-PnpUtilDriverXml -Row @((New-PnpUtilRow -DriverName 'oem8.inf')))).Driver)
    Assert-Equal 1 $plain.Count
    Assert-Equal '' $plain[0].ExtensionId
}

Test-Case 'a package installed on nothing carries no Devices element and counts zero' {
    $parsed = ConvertFrom-WacPnpUtilDriverXml -Text (New-PnpUtilDriverXml -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DeviceStatus @()),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DeviceStatus @('Started'))
    ))

    Assert-True $parsed.IsValid $parsed.Reason
    Assert-Equal 0 $parsed.Driver[0].DeviceCount 'an absent <Devices> element was not read as zero devices'
    Assert-Equal 1 $parsed.Driver[1].DeviceCount
}

Test-Case 'a disconnected device is still a device' {
    # Measured on a real store: Status comes back as Started, Stopped AND Disconnected, so a package
    # whose only device is currently unplugged is still reported as installed on something.
    foreach ($status in @('Disconnected', 'Stopped', 'Unknown')) {
        $parsed = ConvertFrom-WacPnpUtilDriverXml -Text (New-PnpUtilDriverXml -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -DeviceStatus @($status))
        ))

        Assert-Equal 1 $parsed.Driver[0].DeviceCount ('a {0} device was not counted' -f $status)
        Assert-True $parsed.HasDeviceEvidence $status
    }
}

Test-Case 'malformed structured output fails closed' {
    $wellFormed = New-PnpUtilDriverXml -Row @((New-PnpUtilRow -DriverName 'oem1.inf'))

    $malformed = @(
        $wellFormed.Substring(0, [int]($wellFormed.Length / 2)),
        '<PnpUtil><Driver DriverName="oem1.inf"></PnpUtil>',
        'not xml at all',
        '{ "driver": [] }',
        '<?xml version="1.0"?>'
    )

    foreach ($text in $malformed) {
        $parsed = ConvertFrom-WacPnpUtilDriverXml -Text $text
        Assert-False $parsed.IsValid ('malformed output was accepted: {0}' -f $text)
        Assert-Equal 0 (@($parsed.Driver)).Count
        Assert-False $parsed.HasDeviceEvidence
        Assert-True ($parsed.Reason.Length -gt 0) 'a rejection carried no reason'
    }
}

Test-Case 'empty output and a foreign root element fail closed' {
    foreach ($text in @('', '   ', "`r`n`r`n")) {
        $parsed = ConvertFrom-WacPnpUtilDriverXml -Text $text
        Assert-False $parsed.IsValid 'empty output was accepted as a driver list'
        Assert-Equal 0 (@($parsed.Driver)).Count
    }

    Assert-False (ConvertFrom-WacPnpUtilDriverXml -Text $null).IsValid

    # /enum-containers is the command whose /format switch the syntax reference DOES document. Its
    # output must never be mistaken for a driver list.
    $foreign = ConvertFrom-WacPnpUtilDriverXml -Text (New-PnpUtilDriverXml -Row @((New-PnpUtilRow -DriverName 'oem1.inf')) -RootElement 'Containers')
    Assert-False $foreign.IsValid 'a foreign root element was accepted'
    Assert-True ($foreign.Reason -match '(?i)PnpUtil. root element') $foreign.Reason

    $noDriver = ConvertFrom-WacPnpUtilDriverXml -Text '<PnpUtil Version="10.0.26200"></PnpUtil>'
    Assert-False $noDriver.IsValid 'an enumeration with no <Driver> was accepted'
}

Test-Case 'the localized text output is never parsed as a driver list' {
    # Microsoft: "Don't use scripts to process the default output or the 'text' /format option since
    # that output can change and is localized."
    $text = @(
        'Microsoft PnP Utility',
        '',
        'Published Name:     oem1.inf',
        'Original Name:      acme.inf',
        'Provider Name:      ACME Corporation',
        'Class Name:         Net',
        'Class GUID:         {4d36e972-e325-11ce-bfc1-08002be10318}',
        'Driver Version:     01/01/2020 1.0.0.0',
        'Signer Name:        Microsoft Windows Hardware Compatibility Publisher'
    ) -join "`r`n"

    $parsed = ConvertFrom-WacPnpUtilDriverXml -Text $text

    Assert-False $parsed.IsValid 'the localized text output was accepted'
    Assert-Equal 0 (@($parsed.Driver)).Count
}

Test-Case 'an enumeration with no device association anywhere reports no device evidence' {
    # This is the feature detection: /devices either produced associations or it did not, and no
    # version table is consulted anywhere to decide that.
    $parsed = ConvertFrom-WacPnpUtilDriverXml -Text (New-PnpUtilDriverXml -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @()),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @())
    ))

    Assert-True $parsed.IsValid 'a well-formed enumeration was rejected as malformed'
    Assert-False $parsed.HasDeviceEvidence 'an enumeration with no association at all claimed device evidence'
    Assert-True ($parsed.Reason -match '(?i)device association') $parsed.Reason
}

Test-Case 'a row missing any required field is dropped, not guessed at' {
    foreach ($required in @('OriginalName', 'ProviderName', 'ClassGuid', 'SignerName', 'DriverVersion')) {
        foreach ($shape in @('omitted', 'empty')) {
            $row = New-PnpUtilRow -DriverName 'oem1.inf'
            if ($shape -eq 'omitted') { $row['Omit'] = @($required) } else { $row[$required] = '' }

            $parsed = ConvertFrom-WacPnpUtilDriverXml -Text (New-PnpUtilDriverXml -Row @($row, (New-PnpUtilRow -DriverName 'oem2.inf')))

            Assert-True $parsed.IsValid $parsed.Reason
            Assert-Equal 1 (@($parsed.Driver)).Count ('a row with {0} {1} survived' -f $shape, $required)
            Assert-Equal 'oem2.inf' $parsed.Driver[0].DriverName
            Assert-Equal 1 $parsed.DroppedRow ('the dropped row was not counted ({0} {1})' -f $shape, $required)
        }
    }

    # A DriverName attribute that is absent or blank is the same class of uncertainty.
    $blank = ConvertFrom-WacPnpUtilDriverXml -Text (New-PnpUtilDriverXml -Row @(
        (New-PnpUtilRow -DriverName ''), (New-PnpUtilRow -DriverName 'oem2.inf')
    ))
    Assert-Equal 1 (@($blank.Driver)).Count
    Assert-Equal 1 $blank.DroppedRow
}

Test-Case 'the driver version is read from the trailing token, never from the ambiguous date' {
    Assert-Equal ([version]'1.0.0.0') (Get-WacDriverVersionPart -Text '03/04/2024 1.0.0.0')
    Assert-Equal ([version]'2.0.0.0') (Get-WacDriverVersionPart -Text '12/07/2020 2.0.0.0')
    Assert-Equal ([version]'10.2') (Get-WacDriverVersionPart -Text '2024-03-04 10.2')
    Assert-Equal ([version]'1.2.3.4') (Get-WacDriverVersionPart -Text '   1.2.3.4   ')

    # A bare date has no version token at all, and a date must never be mistaken for one.
    Assert-Equal $null (Get-WacDriverVersionPart -Text '03/04/2024')
    Assert-Equal $null (Get-WacDriverVersionPart -Text 'not a version')
    Assert-Equal $null (Get-WacDriverVersionPart -Text '')
    Assert-Equal $null (Get-WacDriverVersionPart -Text $null)
}

# ---------------------------------------------------------------------------------------------
# The deletion decision: device evidence first, supersedence second
# ---------------------------------------------------------------------------------------------

Test-Case 'a package a device is still installed on is never a candidate' {
    # THE GUARD. oem1.inf is strictly superseded by oem2.inf and, under version grouping alone, was
    # a deletion candidate. One device - of any status - is enough to refuse it.
    foreach ($status in @('Started', 'Stopped', 'Disconnected')) {
        $driver = Get-ParsedDriver -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '03/04/2024 1.0.0.0' -DeviceStatus @($status)),
            (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '12/07/2020 2.0.0.0' -DeviceStatus @('Started'))
        )

        Assert-Equal 0 (@(Get-WacSupersededDriver -Driver $driver)).Count `
            ('a package with a {0} device was nominated for deletion' -f $status)
    }
}

Test-Case 'a superseded package installed on nothing is the candidate, and records what supersedes it' {
    # oem1 carries the NEWER date and the LOWER version. A date-driven decision would delete oem2.
    $driver = Get-ParsedDriver -Row (New-SupersededPair)

    $superseded = @(Get-WacSupersededDriver -Driver $driver)

    Assert-Equal 1 $superseded.Count (($superseded | ForEach-Object { $_.DriverName }) -join ',')
    Assert-Equal 'oem1.inf' $superseded[0].DriverName
    Assert-Equal ([version]'1.0.0.0') $superseded[0].Version
    Assert-Equal 0 $superseded[0].DeviceCount
    Assert-Equal 'oem2.inf' $superseded[0].SupersededByName 'the candidate does not record which package supersedes it'
    Assert-Equal '2.0.0.0' $superseded[0].SupersededByVersion
}

Test-Case 'a deviceless package with no higher-versioned sibling is kept' {
    # Installed on nothing is not on its own a reason to delete: without a newer sibling there would
    # be no driver left for a device that has never been attached to this machine.
    $driver = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @()),
        (New-PnpUtilRow -DriverName 'oem2.inf' -OriginalName 'widget.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @('Started'))
    )

    Assert-Equal 0 (@(Get-WacSupersededDriver -Driver $driver)).Count 'a lone deviceless package was deleted'
}

Test-Case 'packages differing by class, extension, provider, signer or INF name are separate groups' {
    $case = @(
        @{ Name = 'ClassGuid';    A = @{ ClassGuid = '{4d36e972-e325-11ce-bfc1-08002be10318}' }; B = @{ ClassGuid = '{4d36e968-e325-11ce-bfc1-08002be10318}' } },
        @{ Name = 'ExtensionId';  A = @{ ExtensionId = '' };                                     B = @{ ExtensionId = '{11111111-2222-3333-4444-555555555555}' } },
        @{ Name = 'ProviderName'; A = @{ ProviderName = 'ACME Corporation' };                    B = @{ ProviderName = 'Rival Corporation' } },
        @{ Name = 'SignerName';   A = @{ SignerName = 'Signer One' };                            B = @{ SignerName = 'Signer Two' } },
        @{ Name = 'OriginalName'; A = @{ OriginalName = 'acme.inf' };                            B = @{ OriginalName = 'widget.inf' } }
    )

    foreach ($entry in $case) {
        $low = New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @()
        $high = New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @('Started')
        foreach ($field in @($entry['A'].Keys)) { $low[$field] = $entry['A'][$field] }
        foreach ($field in @($entry['B'].Keys)) { $high[$field] = $entry['B'][$field] }

        $driver = Get-ParsedDriver -Row @($low, $high)
        Assert-Equal 0 (@(Get-WacSupersededDriver -Driver $driver)).Count ('two packages differing by {0} were merged into one group' -f $entry['Name'])
    }
}

Test-Case 'a group whose top version is shared keeps every member' {
    $driver = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2024 3.0.0.0' -DeviceStatus @()),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2020 3.0.0.0' -DeviceStatus @('Started'))
    )

    Assert-Equal 0 (@(Get-WacSupersededDriver -Driver $driver)).Count 'an equal version was treated as superseded'
}

Test-Case 'every deviceless member strictly below the top version is a candidate' {
    $driver = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @()),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @()),
        (New-PnpUtilRow -DriverName 'oem3.inf' -DriverVersion '01/01/2022 3.0.0.0' -DeviceStatus @('Started'))
    )

    $name = @(Get-WacSupersededDriver -Driver $driver | ForEach-Object { $_.DriverName } | Sort-Object)
    Assert-Equal 'oem1.inf,oem2.inf' ($name -join ',')
}

Test-Case 'a driver that is not a published oem package is never a candidate' {
    $driver = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'nvlddmkm.inf' -OriginalName 'nvlddmkm.inf' -DriverVersion '01/01/2010 1.0.0.0' -DeviceStatus @()),
        (New-PnpUtilRow -DriverName 'nvlddmkm.inf' -OriginalName 'nvlddmkm.inf' -DriverVersion '01/01/2024 2.0.0.0' -DeviceStatus @('Started')),
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @()),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @('Started'))
    )

    $superseded = @(Get-WacSupersededDriver -Driver $driver)

    Assert-Equal 1 $superseded.Count (($superseded | ForEach-Object { $_.DriverName }) -join ',')
    Assert-Equal 'oem1.inf' $superseded[0].DriverName
}

Test-Case 'a lone package and an empty list produce no candidate' {
    Assert-Equal 0 (@(Get-WacSupersededDriver -Driver (Get-ParsedDriver -Row @((New-PnpUtilRow -DriverName 'oem1.inf'))))).Count
    Assert-Equal 0 (@(Get-WacSupersededDriver -Driver @())).Count
    Assert-Equal 0 (@(Get-WacSupersededDriver -Driver $null)).Count
}

Test-Case 'hardware IDs, architecture, rank and rollback state are absent, so none of them decides' {
    # The brief asks for fixtures that differ by hardware ID, architecture, rank, target OS and
    # rollback requirement. This enumeration publishes NONE of those, which is exactly why the
    # decision may not rest on them: the parser ignores unknown elements, and the only thing that
    # changes the answer is the device association.
    $extra = @{ HardwareId = 'PCI\VEN_8086&DEV_1234'; Architecture = 'amd64'; Rank = '0x00FF0000'; TargetOS = 'NTamd64.10.0...25398'; RollbackAvailable = 'true' }

    $withExtra = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @() -Extra $extra),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @('Started') -Extra $extra)
    )

    foreach ($unknown in @($extra.Keys)) {
        Assert-False (@($withExtra[0].PSObject.Properties.Name) -ccontains $unknown) ('{0} leaked into the decision record' -f $unknown)
    }
    Assert-Equal 1 (@(Get-WacSupersededDriver -Driver $withExtra)).Count 'an unknown element changed the decision'

    # Same unknown elements, one device: still refused. Only the device association moves the answer.
    $attached = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @('Disconnected') -Extra $extra),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @('Started') -Extra $extra)
    )
    Assert-Equal 0 (@(Get-WacSupersededDriver -Driver $attached)).Count
}

Complete-TestRun
