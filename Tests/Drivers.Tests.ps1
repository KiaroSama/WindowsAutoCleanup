#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.Drivers (ledger T-6): the feature-detected structured
    enumeration that fails closed, the device-evidence gate that no uncertainty may get past, and
    backups that are uniquely identified, verified and never overwritten.

.DESCRIPTION
    pnputil.exe is never executed and no real driver is ever touched. The parser, the supersedence
    decision, the backup identity and the manifest verifier are pure functions; the pruning step runs
    against Core's injected process invoker, which records every file path and argument vector,
    fabricates an export inside a disposable sandbox, and returns a canned result. The invoker and
    the forced privilege check are installed together and removed together in a finally block, so
    outside a fixture the module can only ever skip.

    The fixtures are built from output measured on build 10.0.26200 against a real driver store:
    <PnpUtil> root, <Driver DriverName="oem9.inf">, <ExtensionId> present only on extensions, no
    <Devices> element at all on a package installed on nothing, and Status values of Started,
    Stopped and Disconnected.
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
$script:PnpUtilPath = Join-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -ChildPath 'pnputil.exe'
$script:ManifestName = 'wac-driver-backup.json'

$script:StubCall = New-Object 'System.Collections.Generic.List[object]'
$script:StubResult = @{}

$script:RecordingInvoker = {
    param($FilePath, $ArgumentList, $TimeoutMs)

    $argv = @($ArgumentList)
    [void]$script:StubCall.Add([PSCustomObject]@{
        FilePath  = [string]$FilePath
        Arguments = $argv
        TimeoutMs = [int]$TimeoutMs
    })

    $exitCode = 0
    $timedOut = $false
    $standardOutput = ''

    $key = ''
    if ($argv.Count -gt 0) { $key = [string]$argv[0] }

    $canned = @{}
    if ($script:StubResult.ContainsKey($key)) { $canned = $script:StubResult[$key] }
    if ($canned.ContainsKey('ExitCode')) { $exitCode = $canned['ExitCode'] }
    if ($canned.ContainsKey('TimedOut')) { $timedOut = [bool]$canned['TimedOut'] }
    if ($canned.ContainsKey('Out')) { $standardOutput = [string]$canned['Out'] }

    # A real /export-driver writes the package into the directory it was given. Without that the
    # export verification would have nothing to verify and every prune case would pass vacuously.
    if ($key -eq '/export-driver' -and -not $timedOut -and $exitCode -eq 0 -and $argv.Count -ge 3) {
        $file = @{ 'exported.inf' = 'inf-content' }
        if ($canned.ContainsKey('File')) { $file = $canned['File'] }

        foreach ($relative in @($file.Keys)) {
            $full = Join-Path -Path ([string]$argv[2]) -ChildPath ([string]$relative)
            $parent = Split-Path -Parent $full
            if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                [void](New-Item -Path $parent -ItemType Directory -Force)
            }
            Set-Content -LiteralPath $full -Value ([string]$file[$relative]) -Encoding ASCII -NoNewline
        }
    }

    return [PSCustomObject]@{
        ExitCode       = $exitCode
        TimedOut       = $timedOut
        StandardOutput = $standardOutput
        StandardError  = ''
        DurationMs     = 5
        Started        = (-not $timedOut)
    }
}

function Set-ModuleFunctionBody {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    & $Module { param($n, $b) Set-Item -Path ('function:script:' + $n) -Value $b } $Name $Body
}

function Get-ModuleFunctionBody {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return (& $Module { param($n) (Get-Item -Path ('function:' + $n)).ScriptBlock } $Name)
}

function Invoke-WithStubbedTool {
    <#
    .SYNOPSIS
        Runs a body with the recording invoker installed and the privilege check forced on, then
        restores both. Outside this window the module sees the real privilege check, so a stray call
        can only be skipped, never executed.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [switch]$StubToolPath
    )

    $script:StubCall.Clear()
    $script:StubResult = @{}

    $originalAdmin = Get-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacIsAdministrator'
    Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacIsAdministrator' -Body { return $true }

    $originalToolPath = $null
    if ($StubToolPath) {
        # Existence is not probed, so whether the runner happens to ship a given System32 component
        # cannot decide whether the behaviour under test is covered.
        $originalToolPath = Get-ModuleFunctionBody -Module $script:DriversModule -Name 'Get-WacSystemToolPath'
        Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Get-WacSystemToolPath' -Body {
            param([Parameter(Mandatory = $true)][string]$Leaf)
            return (Join-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -ChildPath $Leaf)
        }
    }

    Set-WacProcessInvoker -Invoker $script:RecordingInvoker
    try {
        & $Body
    }
    finally {
        Set-WacProcessInvoker -Invoker $null
        Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacIsAdministrator' -Body $originalAdmin
        if ($originalToolPath) {
            Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Get-WacSystemToolPath' -Body $originalToolPath
        }
        $script:StubResult = @{}
    }
}

function Get-DeleteCall {
    return @($script:StubCall | Where-Object { @($_.Arguments).Count -gt 0 -and $_.Arguments[0] -eq '/delete-driver' })
}

function Get-ExportCall {
    return @($script:StubCall | Where-Object { @($_.Arguments).Count -gt 0 -and $_.Arguments[0] -eq '/export-driver' })
}

# ---------------------------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------------------------

function New-PnpUtilRow {
    <#
    .SYNOPSIS
        One /enum-drivers /devices record. Every field a decision reads is overridable, any element
        can be omitted entirely, and -DeviceStatus decides how many devices the package is on.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$DriverName,
        [string]$OriginalName = 'acme.inf',
        [string]$ProviderName = 'ACME Corporation',
        [string]$ClassName = 'Net',
        [string]$ClassGuid = '{4d36e972-e325-11ce-bfc1-08002be10318}',
        [string]$ExtensionId = '',
        [string]$DriverVersion = '01/01/2020 1.0.0.0',
        [string]$SignerName = 'Microsoft Windows Hardware Compatibility Publisher',
        [AllowEmptyCollection()][string[]]$DeviceStatus = @('Started'),
        [AllowEmptyCollection()][string[]]$Omit = @(),
        [hashtable]$Extra = @{}
    )

    return @{
        DriverName    = $DriverName
        OriginalName  = $OriginalName
        ProviderName  = $ProviderName
        ClassName     = $ClassName
        ClassGuid     = $ClassGuid
        ExtensionId   = $ExtensionId
        DriverVersion = $DriverVersion
        SignerName    = $SignerName
        DeviceStatus  = @($DeviceStatus)
        Omit          = @($Omit)
        Extra         = $Extra
    }
}

function New-PnpUtilDriverXml {
    <#
    .SYNOPSIS
        Renders rows as 'pnputil /enum-drivers /devices /format xml' output.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][hashtable[]]$Row,
        [string]$RootElement = 'PnpUtil'
    )

    $order = @('OriginalName', 'ProviderName', 'ClassName', 'ClassGuid', 'ExtensionId', 'DriverVersion', 'SignerName')
    $lines = New-Object 'System.Collections.Generic.List[string]'
    [void]$lines.Add('<?xml version="1.0" encoding="utf-8"?>')
    [void]$lines.Add(('<{0} Version="10.0.26200" Command="/enum-drivers /devices /format xml">' -f $RootElement))

    foreach ($record in $Row) {
        [void]$lines.Add(('    <Driver DriverName="{0}">' -f [System.Security.SecurityElement]::Escape([string]$record['DriverName'])))

        foreach ($name in $order) {
            if (@($record['Omit']) -ccontains $name) { continue }
            $value = [string]$record[$name]
            # ExtensionId is absent on every package that is not an extension - measured, not assumed.
            if ($name -eq 'ExtensionId' -and [string]::IsNullOrEmpty($value)) { continue }
            [void]$lines.Add(('        <{0}>{1}</{0}>' -f $name, [System.Security.SecurityElement]::Escape($value)))
        }

        foreach ($extraName in @($record['Extra'].Keys)) {
            [void]$lines.Add(('        <{0}>{1}</{0}>' -f $extraName, [System.Security.SecurityElement]::Escape([string]$record['Extra'][$extraName])))
        }

        $status = @($record['DeviceStatus'])
        if ($status.Count -gt 0) {
            [void]$lines.Add('        <Devices>')
            for ($i = 0; $i -lt $status.Count; $i++) {
                [void]$lines.Add(('            <Device InstanceId="ROOT\FAKE\{0}&amp;{1}">' -f $record['DriverName'], $i))
                [void]$lines.Add('                <DeviceDescription>Fixture device</DeviceDescription>')
                [void]$lines.Add(('                <Status>{0}</Status>' -f [System.Security.SecurityElement]::Escape($status[$i])))
                [void]$lines.Add('            </Device>')
            }
            [void]$lines.Add('        </Devices>')
        }

        [void]$lines.Add('    </Driver>')
    }

    [void]$lines.Add(('</{0}>' -f $RootElement))
    return ($lines -join "`r`n")
}

function Get-ParsedDriver {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][hashtable[]]$Row)

    $parsed = ConvertFrom-WacPnpUtilDriverXml -Text (New-PnpUtilDriverXml -Row $Row)
    Assert-True $parsed.IsValid $parsed.Reason
    return @($parsed.Driver)
}

function New-SupersededPair {
    <#
    .SYNOPSIS
        The canonical prune fixture: oem1.inf is superseded AND installed on nothing, oem2.inf is the
        newer package and carries the device that proves /devices took effect.
    #>
    param([string]$CandidateName = 'oem1.inf', [string]$KeeperName = 'oem2.inf', [string]$OriginalName = 'acme.inf')

    return @(
        (New-PnpUtilRow -DriverName $CandidateName -OriginalName $OriginalName -DriverVersion '03/04/2024 1.0.0.0' -DeviceStatus @()),
        (New-PnpUtilRow -DriverName $KeeperName -OriginalName $OriginalName -DriverVersion '12/07/2020 2.0.0.0' -DeviceStatus @('Started'))
    )
}

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

# ---------------------------------------------------------------------------------------------
# Backup identity: never the recyclable oem number
# ---------------------------------------------------------------------------------------------

Test-Case 'the backup identity ignores the recyclable oem number and separates different packages' {
    $driver = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem5.inf' -OriginalName 'acme.inf' -DriverVersion '01/01/2020 1.0.0.0'),
        (New-PnpUtilRow -DriverName 'oem9.inf' -OriginalName 'acme.inf' -DriverVersion '01/01/2020 1.0.0.0'),
        (New-PnpUtilRow -DriverName 'oem5.inf' -OriginalName 'widget.inf' -DriverVersion '01/01/2020 1.0.0.0'),
        (New-PnpUtilRow -DriverName 'oem5.inf' -OriginalName 'acme.inf' -DriverVersion '01/01/2020 2.0.0.0')
    )

    $same = Get-WacDriverBackupIdentity -Driver $driver[0]
    $renumbered = Get-WacDriverBackupIdentity -Driver $driver[1]
    $otherPackage = Get-WacDriverBackupIdentity -Driver $driver[2]
    $otherVersion = Get-WacDriverBackupIdentity -Driver $driver[3]

    Assert-Equal $same.Name $renumbered.Name 'the same package under a different oem number changed identity'
    Assert-False ($same.Name -ceq $otherPackage.Name) 'a different package reusing oem5.inf collided with it'
    Assert-False ($same.Name -ceq $otherVersion.Name) 'a different version of the same package shared its identity'

    Assert-Equal 64 $same.Hash.Length 'the identity hash is not a full SHA-256'
    Assert-True ($same.Hash -cmatch '^[0-9a-f]{64}$') $same.Hash
    Assert-True ($same.Name -clike ('*{0}*' -f $same.Hash.Substring(0, 16))) $same.Name
    Assert-True ($same.Name -clike 'acme_1.0.0.0_*') $same.Name
    Assert-False ($same.Name -match '(?i)oem\d') ('the recyclable oem number reached the backup identity: {0}' -f $same.Name)
}

Test-Case 'a hostile original name cannot escape the backup root' {
    $driver = Get-ParsedDriver -Row @((New-PnpUtilRow -DriverName 'oem1.inf' -OriginalName '..\..\..\Windows\System32\evil.inf'))
    $identity = Get-WacDriverBackupIdentity -Driver $driver[0]

    Assert-False ($identity.Name -match '[\\/:]') ('the identity is not a single path segment: {0}' -f $identity.Name)
    Assert-False ($identity.Name -match '\.\.') $identity.Name

    $sandbox = New-TestSandbox -Prefix 'dr-escape'
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        [void](New-Item -Path $root -ItemType Directory -Force)
        $resolved = Get-WacNormalizedPath -Path (Join-Path -Path $root -ChildPath $identity.Name)
        Assert-True (Test-WacIsWithinRoot -ChildPath $resolved -RootPath $root) $resolved
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Export hashing, manifest and verification
# ---------------------------------------------------------------------------------------------

Test-Case 'an export is hashed file by file, the manifest is excluded, and an unreadable path is not an empty one' {
    $sandbox = New-TestSandbox -Prefix 'dr-hash'
    try {
        $export = Join-Path -Path $sandbox -ChildPath 'export'
        [void](New-Item -Path (Join-Path -Path $export -ChildPath 'sub') -ItemType Directory -Force)
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'acme.inf') -Value 'abc' -Encoding ASCII -NoNewline
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'sub\acme.sys') -Value 'abcd' -Encoding ASCII -NoNewline
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath $script:ManifestName) -Value '{}' -Encoding ASCII -NoNewline

        $hashed = Get-WacDriverBackupFileHash -Path $export

        Assert-True $hashed.Ok $hashed.Reason
        $file = @($hashed.File)
        Assert-Equal 2 $file.Count (($file | ForEach-Object { $_.Path }) -join ',')
        Assert-Equal 'acme.inf' $file[0].Path
        Assert-Equal 'sub\acme.sys' $file[1].Path
        Assert-Equal 3 $file[0].Bytes
        # SHA-256 of the three ASCII bytes 'abc' - a fixed, host-independent constant.
        Assert-Equal 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' $file[0].Sha256
        Assert-False ($file[0].Sha256 -ceq $file[1].Sha256)

        $missing = Get-WacDriverBackupFileHash -Path (Join-Path -Path $sandbox -ChildPath 'nothing-here')
        Assert-False $missing.Ok 'a directory that does not exist was reported as readable'
        Assert-Equal 0 (@($missing.File)).Count
        Assert-True ($missing.Reason.Length -gt 0)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the verifier catches a changed byte, a missing file and an added file' {
    $sandbox = New-TestSandbox -Prefix 'dr-verify'
    try {
        $export = Join-Path -Path $sandbox -ChildPath 'export'
        [void](New-Item -Path $export -ItemType Directory -Force)
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'acme.inf') -Value 'abc' -Encoding ASCII -NoNewline
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'acme.sys') -Value 'abcd' -Encoding ASCII -NoNewline

        $driver = (Get-ParsedDriver -Row @((New-PnpUtilRow -DriverName 'oem1.inf')))[0]
        $identity = Get-WacDriverBackupIdentity -Driver $driver
        $manifest = New-WacDriverBackupManifest -Driver $driver -Identity $identity -File (Get-WacDriverBackupFileHash -Path $export).File

        Assert-True (Test-WacDriverBackupIntact -Path $export -Manifest $manifest).Intact 'an unchanged export failed verification'

        # Same length, different content: only the hash can see this one.
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'acme.inf') -Value 'abd' -Encoding ASCII -NoNewline
        $changed = Test-WacDriverBackupIntact -Path $export -Manifest $manifest
        Assert-False $changed.Intact 'a changed byte passed verification'
        Assert-True ($changed.Reason -match '(?i)SHA-256') $changed.Reason

        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'acme.inf') -Value 'abc' -Encoding ASCII -NoNewline
        Remove-Item -LiteralPath (Join-Path -Path $export -ChildPath 'acme.sys') -Force
        Assert-False (Test-WacDriverBackupIntact -Path $export -Manifest $manifest).Intact 'a missing file passed verification'

        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'acme.sys') -Value 'abcd' -Encoding ASCII -NoNewline
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'extra.dll') -Value 'x' -Encoding ASCII -NoNewline
        Assert-False (Test-WacDriverBackupIntact -Path $export -Manifest $manifest).Intact 'an added file passed verification'

        Remove-Item -LiteralPath (Join-Path -Path $export -ChildPath 'extra.dll') -Force
        Assert-True (Test-WacDriverBackupIntact -Path $export -Manifest $manifest).Intact 'the restored export failed verification'

        $gone = Test-WacDriverBackupIntact -Path (Join-Path -Path $sandbox -ChildPath 'gone') -Manifest $manifest
        Assert-False $gone.Intact 'a vanished export directory passed verification'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the manifest records the package, the identity hash and the exact deletion evidence' {
    $driver = @(Get-WacSupersededDriver -Driver (Get-ParsedDriver -Row (New-SupersededPair)))[0]
    $identity = Get-WacDriverBackupIdentity -Driver $driver
    $file = @([PSCustomObject]@{ Path = 'acme.inf'; Bytes = 3L; Sha256 = 'ba7816bf' })

    $manifest = New-WacDriverBackupManifest -Driver $driver -Identity $identity -File $file -EnumeratedPackage 42

    Assert-Equal 'oem1.inf' $manifest.DriverName 'the manifest cannot map the backup back to the package it came from'
    Assert-Equal 'acme.inf' $manifest.OriginalName
    Assert-Equal '1.0.0.0' $manifest.Version
    Assert-Equal $identity.Hash $manifest.IdentityHash
    Assert-Equal $identity.Name $manifest.IdentityName
    Assert-Equal 0 $manifest.Evidence.DeviceCount 'the manifest does not record the device evidence'
    Assert-Equal 'oem2.inf' $manifest.Evidence.SupersededByName
    Assert-Equal '2.0.0.0' $manifest.Evidence.SupersededByVersion
    Assert-Equal 42 $manifest.Evidence.EnumeratedPackage
    Assert-True ($manifest.Evidence.Command -match '/enum-drivers /devices /format xml') $manifest.Evidence.Command
    Assert-Equal 1 $manifest.FileCount
    Assert-Equal 3 $manifest.TotalBytes
    Assert-Equal 'ba7816bf' $manifest.File[0].Sha256

    # It has to survive the round trip that actually gets written to disk.
    $rehydrated = ($manifest | ConvertTo-Json -Depth 6) | ConvertFrom-Json
    Assert-Equal 'oem1.inf' $rehydrated.DriverName
    Assert-Equal $identity.Hash $rehydrated.IdentityHash
    Assert-Equal 'oem2.inf' $rehydrated.Evidence.SupersededByName
}

Test-Case 'residue is any export directory whose manifest does not record this package being deleted' {
    # The classifier the collision guard rests on. Everything this tool leaves behind before a
    # package is really gone is reclaimable; the record of the deletion is what makes a directory
    # untouchable, and a manifest belonging to some other package is neither.
    $driver = @(Get-WacSupersededDriver -Driver (Get-ParsedDriver -Row (New-SupersededPair)))[0]
    $identity = Get-WacDriverBackupIdentity -Driver $driver
    $manifest = New-WacDriverBackupManifest -Driver $driver -Identity $identity `
        -File @([PSCustomObject]@{ Path = 'acme.inf'; Bytes = 3L; Sha256 = ('b' * 64) })

    Assert-Equal '' $manifest.DeletedUtc 'a fresh manifest already claims its package was deleted'

    $sandbox = New-TestSandbox -Prefix 'dr-residue'
    try {
        $directory = Join-Path -Path $sandbox -ChildPath 'export'
        [void](New-Item -Path $directory -ItemType Directory -Force)
        $manifestPath = Join-Path -Path $directory -ChildPath $script:ManifestName

        Assert-True (Test-WacDriverBackupIsResidue -Path $directory -Identity $identity).IsResidue `
            'a directory with no manifest at all was not treated as an export that never finished'

        Set-Content -LiteralPath $manifestPath -Value 'not json {' -Encoding ASCII
        Assert-True (Test-WacDriverBackupIsResidue -Path $directory -Identity $identity).IsResidue `
            'a half-written manifest was not treated as an export that never finished'

        Set-Content -LiteralPath $manifestPath -Value ($manifest | ConvertTo-Json -Depth 6) -Encoding ASCII
        Assert-True (Test-WacDriverBackupIsResidue -Path $directory -Identity $identity).IsResidue `
            'a manifest recording no deletion was not treated as an export whose package is still installed'

        $manifest.DeletedUtc = '2026-08-24T09:00:00Z'
        Set-Content -LiteralPath $manifestPath -Value ($manifest | ConvertTo-Json -Depth 6) -Encoding ASCII
        $completed = Test-WacDriverBackupIsResidue -Path $directory -Identity $identity
        Assert-False $completed.IsResidue 'the only copy of a deleted package was classified as residue'
        Assert-True ($completed.Reason -match '2026-08-24T09:00:00Z') $completed.Reason

        # A manifest for some other package, in a directory named after this one, is not something
        # to explain away by deleting it.
        $manifest.IdentityHash = 'f' * 64
        Set-Content -LiteralPath $manifestPath -Value ($manifest | ConvertTo-Json -Depth 6) -Encoding ASCII
        Assert-False (Test-WacDriverBackupIsResidue -Path $directory -Identity $identity).IsResidue `
            'a manifest belonging to a different package was classified as residue'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Invoke-WacPnpCleanHandler
# ---------------------------------------------------------------------------------------------

Test-Case 'the pnpclean handler is invoked through rundll32 with only /DRIVERS and /MAXCLEAN' {
    Invoke-WithStubbedTool -StubToolPath -Body {
        $result = Invoke-WacPnpCleanHandler

        Assert-Equal 1 $script:StubCall.Count 'the pnpclean step must run exactly one process'
        Assert-Equal (Join-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -ChildPath 'rundll32.exe') $script:StubCall[0].FilePath

        $argv = @($script:StubCall[0].Arguments)
        Assert-Equal 3 $argv.Count ('vector: {0}' -f ($argv -join ' '))
        Assert-Equal ('{0}\System32\pnpclean.dll,RunDLL_PnpClean' -f $env:SystemRoot) $argv[0]
        Assert-Equal '/DRIVERS' $argv[1]
        Assert-Equal '/MAXCLEAN' $argv[2]

        Assert-Equal 'Succeeded' $result.Outcome $result.Detail
        Assert-True $result.Succeeded $result.Detail
        Assert-False $result.Failed
        # Measuring the store walks the whole FileRepository, so it must stay opt-in.
        Assert-False ($result.Detail -match 'Driver store change') $result.Detail
    }
}

Test-Case 'a pnpclean timeout is incomplete, not a clean run, and is bounded by the step ceiling' {
    Invoke-WithStubbedTool -StubToolPath -Body {
        $script:StubResult[('{0}\System32\pnpclean.dll,RunDLL_PnpClean' -f $env:SystemRoot)] = @{ ExitCode = $null; TimedOut = $true }
        $result = Invoke-WacPnpCleanHandler

        Assert-Equal 'Incomplete' $result.Outcome $result.Detail
        Assert-True $result.Failed $result.Detail
        Assert-False $result.Succeeded
        Assert-True ($script:StubCall[0].TimeoutMs -gt 0)
        Assert-True ($script:StubCall[0].TimeoutMs -le (1000 * 60 * 120)) ('timeout was {0} ms' -f $script:StubCall[0].TimeoutMs)
    }
}

Test-Case 'a non-zero pnpclean exit code is a failure' {
    Invoke-WithStubbedTool -StubToolPath -Body {
        $script:StubResult[('{0}\System32\pnpclean.dll,RunDLL_PnpClean' -f $env:SystemRoot)] = @{ ExitCode = 2 }
        $result = Invoke-WacPnpCleanHandler

        Assert-Equal 'Failed' $result.Outcome $result.Detail
        Assert-True $result.Failed $result.Detail
        Assert-False $result.Succeeded
        Assert-True $result.Attempted
    }
}

# ---------------------------------------------------------------------------------------------
# Invoke-WacDriverPackagePrune
# ---------------------------------------------------------------------------------------------

Test-Case 'driver pruning is disabled by default and runs no process at all' {
    Invoke-WithStubbedTool -Body {
        $result = Invoke-WacDriverPackagePrune

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-True $result.Skipped $result.Detail
        Assert-False $result.Attempted
        Assert-False $result.Succeeded
        Assert-Equal 0 $script:StubCall.Count 'the disabled pruning step still started a process'
    }
}

Test-Case 'pruning without a backup root is skipped before anything is enumerated' {
    Invoke-WithStubbedTool -Body {
        foreach ($result in @((Invoke-WacDriverPackagePrune -Enabled), (Invoke-WacDriverPackagePrune -Enabled -BackupRoot '   '))) {
            Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
            Assert-True $result.Skipped $result.Detail
            Assert-False $result.Attempted
        }

        Assert-Equal 0 $script:StubCall.Count 'pruning enumerated the driver store with nowhere to export to'
    }
}

Test-Case 'the enumeration asks for device associations in the structured format' {
    $sandbox = New-TestSandbox -Prefix 'dr-enumargs'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row (New-SupersededPair)) }
            [void](Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot)

            $argv = @($script:StubCall[0].Arguments)
            Assert-Equal '/enum-drivers /devices /format xml' ($argv -join ' ') 'the enumeration no longer asks for device associations'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a superseded deviceless package is exported into its identity directory before it is deleted' {
    $sandbox = New-TestSandbox -Prefix 'dr-prune'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        # Computed out here, from pure functions only: a scriptblock invoked with & gets its own
        # scope, so a value assigned inside the stub body would never reach these assertions.
        $candidate = @(Get-WacSupersededDriver -Driver (ConvertFrom-WacPnpUtilDriverXml -Text $xml).Driver)[0]
        $identity = Get-WacDriverBackupIdentity -Driver $candidate

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            # Wrapped at the CALL: a one-element return unrolls to a scalar, and .Count on a scalar
            # throws under Set-StrictMode 2.0 on Windows PowerShell 5.1.
            $export = @(Get-ExportCall)
            $delete = @(Get-DeleteCall)

            Assert-Equal 1 $export.Count 'exactly one package should have been exported'
            Assert-Equal 1 $delete.Count 'exactly one package should have been deleted'
            Assert-True ($script:StubCall.IndexOf($export[0]) -lt $script:StubCall.IndexOf($delete[0])) 'the package was deleted before it was exported'

            Assert-Equal 'oem1.inf' $export[0].Arguments[1]
            Assert-Equal 2 $delete[0].Arguments.Count ('delete vector: {0}' -f ($delete[0].Arguments -join ' '))
            Assert-Equal 'oem1.inf' $delete[0].Arguments[1] 'the wrong package was deleted'

            Assert-Equal (Get-WacNormalizedPath -Path (Join-Path -Path $backupRoot -ChildPath $identity.Name)) $export[0].Arguments[2] `
                'the export directory is not the immutable package identity'

            foreach ($call in $script:StubCall) {
                Assert-Equal $script:PnpUtilPath $call.FilePath
                foreach ($forbidden in @('/force', '/uninstall', '/reboot')) {
                    Assert-False (@($call.Arguments) -ccontains $forbidden) ('{0} reached pnputil: {1}' -f $forbidden, ($call.Arguments -join ' '))
                }
                Assert-True ($call.TimeoutMs -gt 0)
                Assert-True ($call.TimeoutMs -le (1000 * 60 * 2)) ('timeout was {0} ms' -f $call.TimeoutMs)
            }

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'deleted=1 skipped=0 refused=0 incomplete=0') $result.Detail
            Assert-False $result.Failed $result.Detail
            Assert-False $result.RebootRequired
        }

        $exportDirectory = Join-Path -Path $backupRoot -ChildPath $identity.Name
        Assert-True (Test-Path -LiteralPath $exportDirectory -PathType Container) 'no export directory was created for the deleted package'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $backupRoot -ChildPath 'oem1.inf')) 'the export was still named after the recyclable oem number'

        $manifestPath = Join-Path -Path $exportDirectory -ChildPath $script:ManifestName
        Assert-True (Test-Path -LiteralPath $manifestPath -PathType Leaf) 'the deletion left no manifest behind'

        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        Assert-Equal 'oem1.inf' $manifest.DriverName
        Assert-Equal 'oem2.inf' $manifest.Evidence.SupersededByName
        Assert-Equal 0 $manifest.Evidence.DeviceCount
        Assert-Equal 1 $manifest.FileCount
        Assert-Equal 'exported.inf' $manifest.File[0].Path
        Assert-True ($manifest.File[0].Sha256 -cmatch '^[0-9a-f]{64}$') $manifest.File[0].Sha256
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a backup collision is refused rather than overwritten' {
    # THE GUARD. oem numbers are recycled, so a directory that already carries this identity may be
    # the only recoverable copy of an earlier deletion. Refusing beats merging into it.
    $sandbox = New-TestSandbox -Prefix 'dr-collision'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)
        $driver = @(Get-WacSupersededDriver -Driver (ConvertFrom-WacPnpUtilDriverXml -Text $xml).Driver)[0]
        $identity = Get-WacDriverBackupIdentity -Driver $driver

        $existing = Join-Path -Path $backupRoot -ChildPath $identity.Name
        [void](New-Item -Path $existing -ItemType Directory -Force)
        Set-Content -LiteralPath (Join-Path -Path $existing -ChildPath 'earlier.inf') -Value 'the only copy' -Encoding ASCII -NoNewline

        # What makes it the only copy is the manifest record that its package really was deleted.
        # Without that record the same directory is only this tool's own leftovers.
        $earlier = New-WacDriverBackupManifest -Driver $driver -Identity $identity `
            -File @([PSCustomObject]@{ Path = 'earlier.inf'; Bytes = 13L; Sha256 = ('a' * 64) })
        $earlier.DeletedUtc = '2020-01-01T00:00:00Z'
        Set-Content -LiteralPath (Join-Path -Path $existing -ChildPath $script:ManifestName) `
            -Value ($earlier | ConvertTo-Json -Depth 6) -Encoding ASCII

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 0 @(Get-ExportCall).Count 'a colliding identity was exported over'
            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its backup collided'
            Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
            Assert-True $result.Failed 'a refusal was reported as a clean run'
            Assert-True ($result.Detail -match 'refused=1') $result.Detail
        }

        Assert-Equal 'the only copy' (Get-Content -LiteralPath (Join-Path -Path $existing -ChildPath 'earlier.inf') -Raw) `
            'the earlier backup was modified'
        Assert-Equal 2 (@(Get-ChildItem -LiteralPath $existing -File)).Count 'the earlier backup was merged into'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a second run against the same persistent backup root is never a refusal' {
    # THE REGRESSION. Run.ps1 hands this step a PERSISTENT root under the data directory, so run 2
    # walks into whatever run 1 left behind - and nothing here clears the root between the two runs,
    # because nothing clears it on a real machine either.
    #
    # Every run-1 ending below is benign: pnputil declining the deletion is the protection working,
    # and an export that failed or was killed deleted nothing. None of them may turn the next run
    # into a SecurityRefusal, which under the run-level precedence is exit 7 on a healthy machine.
    $scenario = @(
        @{ Name = 'pnputil declined the deletion'; Key = '/delete-driver'; Canned = @{ ExitCode = 5 } },
        @{ Name = 'the export failed';             Key = '/export-driver'; Canned = @{ ExitCode = 87 } },
        @{ Name = 'the export was killed';         Key = '/export-driver'; Canned = @{ ExitCode = $null; TimedOut = $true } }
    )

    foreach ($entry in $scenario) {
        $sandbox = New-TestSandbox -Prefix 'dr-rerun'
        try {
            $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
            $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $script:StubResult[$entry['Key']] = $entry['Canned']
                $first = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-False ($first.Outcome -ceq 'SecurityRefusal') ('run 1, {0}: {1}' -f $entry['Name'], $first.Detail)
            }

            # The machine is unchanged and the next day's run enumerates the same package.
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $second = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 'Succeeded' $second.Outcome ('run 2 after {0}: {1}' -f $entry['Name'], $second.Detail)
                Assert-True ($second.Detail -match 'deleted=1 skipped=0 refused=0 incomplete=0') `
                    ('run 2 after {0}: {1}' -f $entry['Name'], $second.Detail)
                Assert-Equal 1 @(Get-ExportCall).Count ('run 2 after {0} exported nothing' -f $entry['Name'])
            }
        }
        finally {
            Remove-TestSandbox -Path $sandbox
        }
    }
}

Test-Case 'the guard keeps refusing the only copy of a package that really was deleted' {
    # The other half of the same decision: the guard has to survive the fix. A directory whose
    # manifest records a completed deletion is unrecoverable once it is overwritten. The same
    # directory without that record is a run that died before its deletion, and the package it holds
    # is still installed - which is the only reason it can be a candidate again at all.
    $sandbox = New-TestSandbox -Prefix 'dr-guard'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)
        $candidate = @(Get-WacSupersededDriver -Driver (ConvertFrom-WacPnpUtilDriverXml -Text $xml).Driver)[0]
        $identity = Get-WacDriverBackupIdentity -Driver $candidate
        $directory = Join-Path -Path $backupRoot -ChildPath $identity.Name
        $manifestPath = Join-Path -Path $directory -ChildPath $script:ManifestName

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot
            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-Equal 1 @(Get-DeleteCall).Count $result.Detail
        }

        $stamped = Get-Content -LiteralPath $manifestPath -Raw
        Assert-True ($stamped -cmatch '"DeletedUtc":\s+"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"') `
            ('the deletion was never recorded in the manifest: {0}' -f $stamped)
        Assert-True ($stamped -cmatch '"CreatedUtc":\s+"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"') `
            ('stamping the deletion rewrote CreatedUtc into another form: {0}' -f $stamped)

        # The identical package is installed again and superseded again. THAT is a real collision.
        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
            Assert-Equal 0 @(Get-ExportCall).Count 'the only copy of a deleted package was exported over'
            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its backup collided'
            Assert-True ($result.Detail -match 'refused=1') $result.Detail
        }

        Assert-Equal 'inf-content' (Get-Content -LiteralPath (Join-Path -Path $directory -ChildPath 'exported.inf') -Raw) `
            'the only copy of the deleted package was modified'

        # Strip the record the deletion left behind: a run killed between its export and its
        # deletion leaves exactly this, and its package is still in the store. Edited as TEXT so
        # the rest of the manifest reaches the module exactly as the module itself wrote it.
        Set-Content -LiteralPath $manifestPath -Encoding ASCII `
            -Value ($stamped -replace '"DeletedUtc":\s+"[^"]*"', '"DeletedUtc":  ""')

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-Equal 1 @(Get-DeleteCall).Count 'the leftovers of an interrupted run were not reclaimed'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'two different packages that both call themselves oem5.inf get separate backups' {
    # The reuse case the oem-named directory could not survive: oem5.inf is deleted, its number is
    # handed to an unrelated package, and the next run backs that one up too.
    $sandbox = New-TestSandbox -Prefix 'dr-reuse'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $first = New-PnpUtilDriverXml -Row (New-SupersededPair -CandidateName 'oem5.inf' -KeeperName 'oem6.inf' -OriginalName 'acme.inf')
        $second = New-PnpUtilDriverXml -Row (New-SupersededPair -CandidateName 'oem5.inf' -KeeperName 'oem7.inf' -OriginalName 'widget.inf')

        foreach ($xml in @($first, $second)) {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot
                Assert-Equal 'Succeeded' $result.Outcome $result.Detail
                Assert-Equal 1 @(Get-DeleteCall).Count $result.Detail
            }
        }

        $directory = @(Get-ChildItem -LiteralPath $backupRoot -Directory)
        Assert-Equal 2 $directory.Count 'the reused oem number collapsed two packages into one backup'

        $original = @($directory | ForEach-Object {
            (Get-Content -LiteralPath (Join-Path -Path $_.FullName -ChildPath $script:ManifestName) -Raw | ConvertFrom-Json).OriginalName
        } | Sort-Object)
        Assert-Equal 'acme.inf,widget.inf' ($original -join ',')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an export that does not match its manifest is refused before the deletion' {
    $sandbox = New-TestSandbox -Prefix 'dr-mismatch'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        # The re-hash that happens between writing the manifest and deleting the package sees a
        # different digest - which is exactly what a concurrent write to the backup would look like.
        $script:HashCall = 0
        $original = Get-ModuleFunctionBody -Module $script:DriversModule -Name 'Get-WacDriverBackupFileHash'
        Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Get-WacDriverBackupFileHash' -Body {
            param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)
            if ([string]::IsNullOrWhiteSpace($Path)) { throw 'the export was hashed without a path' }
            $script:HashCall++
            $digest = 'a' * 64
            if ($script:HashCall -ge 2) { $digest = 'b' * 64 }
            return [PSCustomObject]@{ Ok = $true; Reason = ''; File = @([PSCustomObject]@{ Path = 'exported.inf'; Bytes = 11L; Sha256 = $digest }) }
        }

        try {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 1 @(Get-ExportCall).Count
                Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its backup no longer matched its manifest'
                Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
                Assert-True ($result.Detail -match 'refused=1') $result.Detail
            }
        }
        finally {
            Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Get-WacDriverBackupFileHash' -Body $original
        }

        Assert-Equal 2 $script:HashCall 'the export was never re-verified against its manifest'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an export that produces no inf deletes nothing' {
    $sandbox = New-TestSandbox -Prefix 'dr-emptyexport'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        foreach ($file in @(@{}, @{ 'readme.txt' = 'not a driver' })) {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $script:StubResult['/export-driver'] = @{ ExitCode = 0; File = $file }
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its export held no driver'
                Assert-True ($result.Detail -match 'deleted=0 skipped=1') $result.Detail
            }
            # NOT cleared between iterations, on purpose: an export that produced nothing worth
            # keeping has to clean up after itself, or it becomes tomorrow's collision.
            Assert-Equal 0 (@(Get-ChildItem -LiteralPath $backupRoot -Directory)).Count `
                'an export that left no driver behind still left its directory behind'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a failed export leaves the package in place, and a timed-out export is incomplete' {
    $sandbox = New-TestSandbox -Prefix 'dr-badexport'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/export-driver'] = @{ ExitCode = 87 }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its export failed'
            Assert-False $result.Failed $result.Detail
            Assert-True ($result.Detail -match 'deleted=0 skipped=1') $result.Detail
        }

        Assert-Equal 0 (@(Get-ChildItem -LiteralPath $backupRoot -Directory)).Count `
            'a failed export left its directory behind for the next run to collide with'

        # Same root, deliberately not cleared: the killed export has to survive whatever the failed
        # one left, because on a real machine it would have to.
        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/export-driver'] = @{ ExitCode = $null; TimedOut = $true }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted after its export was killed'
            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'incomplete=1') $result.Detail
        }

        Assert-Equal 0 (@(Get-ChildItem -LiteralPath $backupRoot -Directory)).Count `
            'a killed export left a directory whose contents are unknown'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'no uncertain enumeration ever reaches a deletion' {
    # One table, one assertion: whatever the structured output turns out to be, if it does not prove
    # a package is superseded AND installed on nothing, nothing is exported and nothing is deleted.
    $pair = New-SupersededPair
    $uncertain = @(
        @{ Name = 'a failed enumeration';        Canned = @{ ExitCode = 1; Out = (New-PnpUtilDriverXml -Row $pair) };          Outcome = 'SafeSkip' },
        @{ Name = 'a timed-out enumeration';     Canned = @{ ExitCode = $null; TimedOut = $true; Out = (New-PnpUtilDriverXml -Row $pair) }; Outcome = 'Incomplete' },
        @{ Name = 'empty output';                Canned = @{ ExitCode = 0; Out = '' };                                        Outcome = 'SafeSkip' },
        @{ Name = 'the localized text output';   Canned = @{ ExitCode = 0; Out = "Microsoft PnP Utility`r`n`r`nPublished Name: oem1.inf" }; Outcome = 'SafeSkip' },
        @{ Name = 'truncated xml';               Canned = @{ ExitCode = 0; Out = '<PnpUtil><Driver DriverName="oem1.inf">' }; Outcome = 'SafeSkip' },
        @{ Name = 'a foreign root';              Canned = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row $pair -RootElement 'Containers') }; Outcome = 'SafeSkip' },
        @{ Name = 'no device association at all'; Canned = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row @(
                (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @()),
                (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @()))) };          Outcome = 'SafeSkip' },
        @{ Name = 'the candidate still has a device'; Canned = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row @(
                (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @('Disconnected')),
                (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @('Started')))) };  Outcome = 'Succeeded' },
        @{ Name = 'the candidate row is incomplete'; Canned = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row @(
                (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @() -Omit @('SignerName')),
                (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @('Started')))) };  Outcome = 'Succeeded' }
    )

    $sandbox = New-TestSandbox -Prefix 'dr-uncertain'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'

        foreach ($entry in $uncertain) {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = $entry['Canned']
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 0 @(Get-DeleteCall).Count ('{0} reached a deletion' -f $entry['Name'])
                Assert-Equal 0 @(Get-ExportCall).Count ('{0} reached an export' -f $entry['Name'])
                Assert-Equal $entry['Outcome'] $result.Outcome ('{0}: {1}' -f $entry['Name'], $result.Detail)
            }
        }

        Assert-Equal 0 (@(Get-ChildItem -LiteralPath $backupRoot -Directory)).Count 'an uncertain enumeration still created a backup directory'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'pnputil exit 259 is benign and exit 3010 is success plus RebootRequired' {
    $sandbox = New-TestSandbox -Prefix 'dr-exitcode'
    try {
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 259 }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot (Join-Path -Path $sandbox -ChildPath 'b259')

            Assert-Equal 'Succeeded' $result.Outcome 'ERROR_NO_MORE_ITEMS was reported as a failure'
            Assert-False $result.Failed $result.Detail
            Assert-False $result.RebootRequired
        }

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 3010 }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot (Join-Path -Path $sandbox -ChildPath 'b3010')

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True $result.RebootRequired 'a reboot-required deletion did not surface a reboot'
            Assert-False $result.Failed
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a package pnputil refuses is skipped, and a deletion timeout is incomplete' {
    $sandbox = New-TestSandbox -Prefix 'dr-refused'
    try {
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 5 }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot (Join-Path -Path $sandbox -ChildPath 'refused')

            Assert-False $result.Failed 'a package still in use must not be a run failure'
            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'deleted=0 skipped=1') $result.Detail
        }

        # The package is still installed, so its export is a copy of something, not the only copy of
        # it. Keeping it would waste the space and collide with every later run.
        Assert-Equal 0 (@(Get-ChildItem -LiteralPath (Join-Path -Path $sandbox -ChildPath 'refused') -Directory)).Count `
            'a package pnputil declined to remove kept a backup nothing can ever recover from'

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/delete-driver'] = @{ ExitCode = $null; TimedOut = $true }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot (Join-Path -Path $sandbox -ChildPath 'killed')

            Assert-Equal 'Incomplete' $result.Outcome 'a killed pnputil was reported as a clean run'
            Assert-True $result.Failed
            Assert-False $result.Succeeded
            Assert-True ($result.Detail -match 'incomplete=1') $result.Detail
        }

        # The opposite case: whether the package survived a killed deletion is unknown, so the one
        # copy that might be all there is stays exactly where it is.
        Assert-Equal 1 (@(Get-ChildItem -LiteralPath (Join-Path -Path $sandbox -ChildPath 'killed') -Directory)).Count `
            'a killed deletion threw away the export that might be the only copy left'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a deadline that expires mid-prune stops the loop and reports the rest as incomplete' {
    $sandbox = New-TestSandbox -Prefix 'dr-deadline'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @()),
            (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @()),
            (New-PnpUtilRow -DriverName 'oem3.inf' -DriverVersion '01/01/2022 3.0.0.0' -DeviceStatus @('Started'))
        )

        # Forced rather than timed: a real clock would make this case flaky, and the branch under
        # test is "what does the loop do once the budget is gone", not how long that takes.
        $originalExpired = Get-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacDeadlineExpired'
        Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacDeadlineExpired' -Body { return $true }

        try {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 0 @(Get-ExportCall).Count 'the prune kept working past its deadline'
                Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted after the deadline expired'
                Assert-Equal 'Incomplete' $result.Outcome $result.Detail
                Assert-True ($result.Detail -match 'candidates=2 deleted=0 skipped=0 refused=0 incomplete=2') $result.Detail
            }
        }
        finally {
            Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacDeadlineExpired' -Body $originalExpired
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an enumeration with nothing to prune succeeds and touches nothing' {
    $sandbox = New-TestSandbox -Prefix 'dr-nothing'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -OriginalName 'acme.inf' -DriverVersion '03/04/2024 1.0.0.0' -DeviceStatus @('Started')),
            (New-PnpUtilRow -DriverName 'oem2.inf' -OriginalName 'widget.inf' -DriverVersion '12/07/2020 2.0.0.0' -DeviceStatus @('Started'))
        )

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True $result.Attempted
            Assert-False $result.Failed
            Assert-Equal 1 $script:StubCall.Count 'a package was touched although nothing was superseded'
            Assert-True ($result.Detail -match '2 driver package\(s\) enumerated') $result.Detail
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
