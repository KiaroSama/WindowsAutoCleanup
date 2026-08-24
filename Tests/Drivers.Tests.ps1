#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.Drivers: header-name CSV parsing that fails closed
    (ledger P1-7), the superseded-package equivalence decision that ignores the culture-ambiguous
    date (ledger P1-8), and the export-before-delete pruning sequence.

.DESCRIPTION
    pnputil.exe is never executed. The parser and the equivalence decision are pure functions, and
    the pruning step runs against Core's injected process invoker, which records every file path and
    argument vector and returns a canned result. The invoker and the forced privilege check are
    installed together and removed together in a finally block, so nothing outside a fixture can
    reach a real driver-store command.
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

$script:RequiredColumn = @('DriverName', 'OriginalName', 'ProviderName', 'ClassGuid', 'ExtensionId', 'DriverVersion', 'SignerName')
$script:DefaultColumn = @('DriverName', 'OriginalName', 'ProviderName', 'ClassName', 'ClassGuid', 'ClassVersion',
    'ExtensionId', 'DriverVersion', 'SignerName', 'CatalogAttributes', 'WhcpVersion')

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
    if ($script:StubResult.ContainsKey($key)) {
        $canned = $script:StubResult[$key]
        if ($canned.ContainsKey('ExitCode')) { $exitCode = $canned['ExitCode'] }
        if ($canned.ContainsKey('TimedOut')) { $timedOut = [bool]$canned['TimedOut'] }
        if ($canned.ContainsKey('Out')) { $standardOutput = [string]$canned['Out'] }
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

function New-PnpUtilRow {
    <#
    .SYNOPSIS
        One /enum-drivers record. Every field an equivalence decision reads is overridable.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$DriverName,
        [string]$OriginalName = 'acme.inf',
        [string]$ProviderName = 'ACME Corporation',
        [string]$ClassName = 'Net',
        [string]$ClassGuid = '{4d36e972-e325-11ce-bfc1-08002be10318}',
        [string]$ExtensionId = '{00000000-0000-0000-0000-000000000000}',
        [string]$DriverVersion = '01/01/2020 1.0.0.0',
        [string]$SignerName = 'Microsoft Windows Hardware Compatibility Publisher'
    )

    return @{
        DriverName        = $DriverName
        OriginalName      = $OriginalName
        ProviderName      = $ProviderName
        ClassName         = $ClassName
        ClassGuid         = $ClassGuid
        ClassVersion      = '1.0'
        ExtensionId       = $ExtensionId
        DriverVersion     = $DriverVersion
        SignerName        = $SignerName
        CatalogAttributes = ''
        WhcpVersion       = ''
    }
}

function New-PnpUtilCsvText {
    <#
    .SYNOPSIS
        Renders rows as 'pnputil /enum-drivers /format csv' output in the given column order.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][hashtable[]]$Row,
        [string[]]$Column = $script:DefaultColumn
    )

    $lines = New-Object 'System.Collections.Generic.List[string]'
    [void]$lines.Add(($Column -join ','))

    foreach ($record in $Row) {
        $field = foreach ($name in $Column) {
            $value = ''
            if ($record.ContainsKey($name)) { $value = [string]$record[$name] }
            '"{0}"' -f $value
        }
        [void]$lines.Add(($field -join ','))
    }

    return ($lines -join "`r`n")
}

function Get-ParsedDriver {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][hashtable[]]$Row)

    $parsed = ConvertFrom-WacPnpUtilCsv -Text (New-PnpUtilCsvText -Row $Row)
    Assert-True $parsed.IsValid $parsed.Reason
    return @($parsed.Driver)
}

# ---------------------------------------------------------------------------------------------
# CSV parsing, by name and fail-closed (ledger P1-7)
# ---------------------------------------------------------------------------------------------

Test-Case 'the pnputil CSV is parsed by header name, not by column position' {
    # Same record, columns in a deliberately different order, plus a column the parser does not know.
    $shuffled = @('SignerName', 'DriverVersion', 'Surprise', 'ExtensionId', 'ClassGuid', 'ClassName',
        'ProviderName', 'OriginalName', 'DriverName')

    $row = New-PnpUtilRow -DriverName 'oem7.inf' -OriginalName 'widget.inf' -ProviderName 'Widget Ltd' `
        -ClassGuid '{aaaaaaaa-1111-2222-3333-444444444444}' -ExtensionId '{bbbbbbbb-1111-2222-3333-444444444444}' `
        -DriverVersion '31/12/2021 4.5.6.7' -SignerName 'Widget Signer'

    $parsed = ConvertFrom-WacPnpUtilCsv -Text (New-PnpUtilCsvText -Row @($row) -Column $shuffled)

    Assert-True $parsed.IsValid $parsed.Reason
    Assert-Equal 1 $parsed.Driver.Count
    Assert-Equal 'oem7.inf' $parsed.Driver[0].DriverName
    Assert-Equal 'widget.inf' $parsed.Driver[0].OriginalName
    Assert-Equal 'Widget Ltd' $parsed.Driver[0].ProviderName
    Assert-Equal '{aaaaaaaa-1111-2222-3333-444444444444}' $parsed.Driver[0].ClassGuid
    Assert-Equal '{bbbbbbbb-1111-2222-3333-444444444444}' $parsed.Driver[0].ExtensionId
    Assert-Equal 'Widget Signer' $parsed.Driver[0].SignerName
    Assert-Equal ([version]'4.5.6.7') $parsed.Driver[0].Version
    Assert-Equal '31/12/2021 4.5.6.7' $parsed.Driver[0].VersionText
}

Test-Case 'every required column that goes missing fails the parse closed and is named' {
    foreach ($required in $script:RequiredColumn) {
        $column = @($script:DefaultColumn | Where-Object { $_ -ne $required })
        $text = New-PnpUtilCsvText -Row @((New-PnpUtilRow -DriverName 'oem1.inf')) -Column $column

        $parsed = ConvertFrom-WacPnpUtilCsv -Text $text

        Assert-False $parsed.IsValid ('a header without {0} was accepted' -f $required)
        Assert-Equal 0 (@($parsed.Driver)).Count ('drivers were returned from an invalid header ({0})' -f $required)

        if ($required -eq 'DriverName') {
            # DriverName is the column the header row is FOUND by, so its absence is reported as a
            # missing header rather than a missing column. Still fail-closed, different reason.
            Assert-True ($parsed.Reason -match '(?i)no csv header row') $parsed.Reason
            continue
        }

        Assert-True (@($parsed.MissingColumn) -ccontains $required) ('{0} was not named as missing: {1}' -f $required, (@($parsed.MissingColumn) -join ','))
        Assert-True ($parsed.Reason -match '(?i)missing required columns') $parsed.Reason
    }
}

Test-Case 'empty pnputil output fails closed' {
    foreach ($text in @('', '   ', "`r`n`r`n")) {
        $parsed = ConvertFrom-WacPnpUtilCsv -Text $text
        Assert-False $parsed.IsValid 'empty output was accepted as a driver list'
        Assert-Equal 0 (@($parsed.Driver)).Count
    }

    $nullParsed = ConvertFrom-WacPnpUtilCsv -Text $null
    Assert-False $nullParsed.IsValid
}

Test-Case 'the localized text output is never parsed as a driver list' {
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

    $parsed = ConvertFrom-WacPnpUtilCsv -Text $text

    Assert-False $parsed.IsValid 'the text output was accepted as CSV'
    Assert-Equal 0 (@($parsed.Driver)).Count
    Assert-True ($parsed.Reason -match '(?i)no csv header') $parsed.Reason
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

Test-Case 'a row without a usable name or version is dropped, not guessed at' {
    # Wrapped: Windows PowerShell 5.1 has no .Count on the single object a one-element return unrolls to.
    $driver = @(Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf'),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion 'unavailable'),
        (New-PnpUtilRow -DriverName '' -DriverVersion '01/01/2020 3.0.0.0')
    ))

    Assert-Equal 1 $driver.Count (($driver | ForEach-Object { $_.DriverName }) -join ',')
    Assert-Equal 'oem1.inf' $driver[0].DriverName
}

# ---------------------------------------------------------------------------------------------
# The superseded decision (ledger P1-8)
# ---------------------------------------------------------------------------------------------

Test-Case 'the ambiguous date never decides: the lower version is the candidate' {
    # oem1 carries the NEWER date and the LOWER version. A date-driven decision would delete oem2.
    $driver = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '03/04/2024 1.0.0.0'),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '12/07/2020 2.0.0.0')
    )

    $superseded = @(Get-WacSupersededDriver -Driver $driver)

    Assert-Equal 1 $superseded.Count (($superseded | ForEach-Object { $_.DriverName }) -join ',')
    Assert-Equal 'oem1.inf' $superseded[0].DriverName
    Assert-Equal ([version]'1.0.0.0') $superseded[0].Version
}

Test-Case 'rows differing only by ClassGuid are separate groups' {
    $driver = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -ClassGuid '{4d36e972-e325-11ce-bfc1-08002be10318}'),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -ClassGuid '{4d36e968-e325-11ce-bfc1-08002be10318}')
    )

    Assert-Equal 0 (@(Get-WacSupersededDriver -Driver $driver)).Count 'a different device class was treated as the same package'
}

Test-Case 'rows differing only by ExtensionId are separate groups' {
    $driver = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -ExtensionId '{00000000-0000-0000-0000-000000000000}'),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -ExtensionId '{11111111-2222-3333-4444-555555555555}')
    )

    Assert-Equal 0 (@(Get-WacSupersededDriver -Driver $driver)).Count 'an extension package was treated as the same package as its base'
}

Test-Case 'rows differing only by ProviderName or SignerName are separate groups' {
    $byProvider = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -ProviderName 'ACME Corporation'),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -ProviderName 'Rival Corporation')
    )
    Assert-Equal 0 (@(Get-WacSupersededDriver -Driver $byProvider)).Count 'two providers were merged into one group'

    $bySigner = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -SignerName 'Signer One'),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -SignerName 'Signer Two')
    )
    Assert-Equal 0 (@(Get-WacSupersededDriver -Driver $bySigner)).Count 'two signers were merged into one group'

    $byOriginal = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -OriginalName 'acme.inf'),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -OriginalName 'widget.inf')
    )
    Assert-Equal 0 (@(Get-WacSupersededDriver -Driver $byOriginal)).Count 'two INF names were merged into one group'
}

Test-Case 'a group whose top version is shared keeps every member' {
    $driver = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2024 3.0.0.0'),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2020 3.0.0.0')
    )

    Assert-Equal 0 (@(Get-WacSupersededDriver -Driver $driver)).Count 'an equal version was treated as superseded'
}

Test-Case 'every member strictly below the top version is a candidate' {
    $driver = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0'),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0'),
        (New-PnpUtilRow -DriverName 'oem3.inf' -DriverVersion '01/01/2022 3.0.0.0')
    )

    $name = @(Get-WacSupersededDriver -Driver $driver | ForEach-Object { $_.DriverName } | Sort-Object)
    Assert-Equal 'oem1.inf,oem2.inf' ($name -join ',')
}

Test-Case 'a driver that is not a published oem package is never a candidate' {
    $driver = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'nvlddmkm.inf' -DriverVersion '01/01/2010 1.0.0.0' -OriginalName 'nvlddmkm.inf'),
        (New-PnpUtilRow -DriverName 'nvlddmkm.inf' -DriverVersion '01/01/2024 2.0.0.0' -OriginalName 'nvlddmkm.inf'),
        (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0'),
        (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0')
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

        Assert-True $result.Succeeded $result.Detail
        Assert-False $result.Failed
        # Measuring the store walks the whole FileRepository, so it must stay opt-in.
        Assert-False ($result.Detail -match 'Driver store change') $result.Detail
    }
}

Test-Case 'a pnpclean timeout is a failure, bounded by the step ceiling' {
    Invoke-WithStubbedTool -StubToolPath -Body {
        $script:StubResult[('{0}\System32\pnpclean.dll,RunDLL_PnpClean' -f $env:SystemRoot)] = @{ ExitCode = $null; TimedOut = $true }
        $result = Invoke-WacPnpCleanHandler

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

        Assert-True $result.Skipped $result.Detail
        Assert-False $result.Attempted
        Assert-False $result.Succeeded
        Assert-Equal 0 $script:StubCall.Count 'the disabled pruning step still started a process'
    }
}

Test-Case 'pruning without a backup root is skipped before anything is enumerated' {
    Invoke-WithStubbedTool -Body {
        foreach ($result in @((Invoke-WacDriverPackagePrune -Enabled), (Invoke-WacDriverPackagePrune -Enabled -BackupRoot '   '))) {
            Assert-True $result.Skipped $result.Detail
            Assert-False $result.Attempted
        }

        Assert-Equal 0 $script:StubCall.Count 'pruning enumerated the driver store with nowhere to export to'
    }
}

Test-Case 'a superseded package is exported before it is deleted, and never forcibly' {
    $sandbox = New-TestSandbox -Prefix 'dr-prune'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $csv = New-PnpUtilCsvText -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '03/04/2024 1.0.0.0'),
            (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '12/07/2020 2.0.0.0')
        )

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $csv }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            $export = @($script:StubCall | Where-Object { $_.Arguments[0] -eq '/export-driver' })
            $delete = @($script:StubCall | Where-Object { $_.Arguments[0] -eq '/delete-driver' })

            Assert-Equal 1 $export.Count 'exactly one package should have been exported'
            Assert-Equal 1 $delete.Count 'exactly one package should have been deleted'
            Assert-True ($script:StubCall.IndexOf($export[0]) -lt $script:StubCall.IndexOf($delete[0])) 'the package was deleted before it was exported'

            Assert-Equal 'oem1.inf' $export[0].Arguments[1]
            Assert-Equal (Get-WacNormalizedPath -Path (Join-Path -Path $backupRoot -ChildPath 'oem1.inf')) $export[0].Arguments[2]
            Assert-Equal 2 $delete[0].Arguments.Count ('delete vector: {0}' -f ($delete[0].Arguments -join ' '))
            Assert-Equal 'oem1.inf' $delete[0].Arguments[1] 'the wrong package was deleted'

            foreach ($call in $script:StubCall) {
                Assert-Equal $script:PnpUtilPath $call.FilePath
                foreach ($forbidden in @('/force', '/uninstall', '/reboot')) {
                    Assert-False (@($call.Arguments) -ccontains $forbidden) ('{0} reached pnputil: {1}' -f $forbidden, ($call.Arguments -join ' '))
                }
                Assert-True ($call.TimeoutMs -gt 0)
                Assert-True ($call.TimeoutMs -le (1000 * 60 * 2)) ('timeout was {0} ms' -f $call.TimeoutMs)
            }

            Assert-True $result.Succeeded $result.Detail
            Assert-False $result.Failed $result.Detail
            Assert-False $result.RebootRequired
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $backupRoot -ChildPath 'oem1.inf') -PathType Container) 'no export directory was created for the deleted package'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an unparsable enumeration deletes nothing' {
    $sandbox = New-TestSandbox -Prefix 'dr-badcsv'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $badCsv = New-PnpUtilCsvText -Column @($script:DefaultColumn | Where-Object { $_ -ne 'ClassGuid' }) -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '03/04/2024 1.0.0.0'),
            (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '12/07/2020 2.0.0.0')
        )

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $badCsv }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-True $result.Skipped $result.Detail
            Assert-Equal 0 (@($script:StubCall | Where-Object { $_.Arguments[0] -eq '/delete-driver' })).Count 'a package was deleted from an invalid enumeration'
            Assert-Equal 0 (@($script:StubCall | Where-Object { $_.Arguments[0] -eq '/export-driver' })).Count
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an enumeration that fails or times out deletes nothing' {
    $sandbox = New-TestSandbox -Prefix 'dr-badenum'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $csv = New-PnpUtilCsvText -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '03/04/2024 1.0.0.0'),
            (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '12/07/2020 2.0.0.0')
        )

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 1; Out = $csv }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-True $result.Skipped $result.Detail
            Assert-Equal 1 $script:StubCall.Count 'pruning continued past a failed enumeration'
        }

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = $null; TimedOut = $true; Out = $csv }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-True $result.Skipped $result.Detail
            Assert-Equal 1 $script:StubCall.Count 'pruning continued past a timed-out enumeration'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a failed export leaves the package in place' {
    $sandbox = New-TestSandbox -Prefix 'dr-badexport'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $csv = New-PnpUtilCsvText -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '03/04/2024 1.0.0.0'),
            (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '12/07/2020 2.0.0.0')
        )

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $csv }
            $script:StubResult['/export-driver'] = @{ ExitCode = 87 }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 0 (@($script:StubCall | Where-Object { $_.Arguments[0] -eq '/delete-driver' })).Count 'a package was deleted although its export failed'
            Assert-False $result.Failed $result.Detail
            Assert-True ($result.Detail -match 'deleted=0') $result.Detail
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'pnputil exit 259 is benign and exit 3010 is success plus RebootRequired' {
    $sandbox = New-TestSandbox -Prefix 'dr-exitcode'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $csv = New-PnpUtilCsvText -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '03/04/2024 1.0.0.0'),
            (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '12/07/2020 2.0.0.0')
        )

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $csv }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 259 }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-False $result.Failed 'ERROR_NO_MORE_ITEMS was reported as a failure'
            Assert-True $result.Succeeded $result.Detail
            Assert-False $result.RebootRequired
        }

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $csv }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 3010 }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-True $result.Succeeded $result.Detail
            Assert-True $result.RebootRequired 'a reboot-required deletion did not surface a reboot'
            Assert-False $result.Failed
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a package pnputil refuses is skipped, and a deletion timeout is a failure' {
    $sandbox = New-TestSandbox -Prefix 'dr-refused'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $csv = New-PnpUtilCsvText -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '03/04/2024 1.0.0.0'),
            (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '12/07/2020 2.0.0.0')
        )

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $csv }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 5 }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-False $result.Failed 'a package still in use must not be a run failure'
            Assert-True ($result.Detail -match 'deleted=0 skipped=1') $result.Detail
        }

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $csv }
            $script:StubResult['/delete-driver'] = @{ ExitCode = $null; TimedOut = $true }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-True $result.Failed 'a killed pnputil was reported as a clean run'
            Assert-False $result.Succeeded
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an enumeration with nothing superseded succeeds and deletes nothing' {
    $sandbox = New-TestSandbox -Prefix 'dr-nothing'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $csv = New-PnpUtilCsvText -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '03/04/2024 1.0.0.0' -OriginalName 'acme.inf'),
            (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '12/07/2020 2.0.0.0' -OriginalName 'widget.inf')
        )

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $csv }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-True $result.Succeeded $result.Detail
            Assert-True $result.Attempted
            Assert-False $result.Failed
            Assert-Equal 1 $script:StubCall.Count 'a package was touched although nothing was superseded'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
