#Requires -Version 5.1
<#
.SYNOPSIS
    The pnputil output fixtures and the recording-invoker seam every WindowsAutoCleanup.Drivers
    package suite installs.

.DESCRIPTION
    Dot-sourced by Drivers.Tests.ps1, DriverInventory.Tests.ps1 and DriverBackup.Tests.ps1. It is
    not a suite: its name does not match Tests\*.Tests.ps1, so the runner never executes it alone.

    The fixtures are built from output measured on build 10.0.26200 against a real driver store:
    <PnpUtil> root, <Driver DriverName="oem9.inf">, <ExtensionId> present only on extensions, no
    <Devices> element at all on a package installed on nothing, and Status values of Started,
    Stopped and Disconnected. They are shared rather than copied because a second copy that drifted
    would quietly stop being the shape pnputil really produces.

    Invoke-WithStubbedTool reaches inside the code under test through $script:DriversModule, which
    each suite sets after it imports the module.
#>

$script:PnpUtilPath = Join-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -ChildPath 'pnputil.exe'
$script:ManifestName = 'wac-driver-backup.json'

# Invoke-WacDriverPackagePrune creates its backup root through Open-WacTrustedDirectory with
# -RequireMachineTrust, which reads the owner and DACL from the directory's OWN handle rather than
# through any stub - deliberately, because a trust decision that a test can fake proves nothing.
# Every suite here drives a prune against a sandbox under %TEMP%, which is owned by whoever ran the
# suite, so the real rule refuses it and every one of those cases would fail for a reason unrelated
# to what it asserts. This is the seam the primitive documents for exactly that, installed once
# here rather than copied into three suites where it would drift.
#
# It does not soften the cases that matter. The collision-failing create and the reparse refusal
# are judged by the kernel and never reach this scriptblock, and the case asserting that a non-empty
# Writers list is refused reaches its verdict from Test-WacStatePathIsTrusted before this is
# consulted at all. What is NOT covered here, and is stated rather than implied: the real
# owner/DACL rule on the real backup root is exercised only by Trust.Tests, never from a sandbox.
Set-WacDirectoryTrustJudge -ScriptBlock {
    param($Sddl)
    $null = $Sddl
    [PSCustomObject]@{ IsTrusted = $true; Reason = 'sandbox descriptor accepted for the driver suites' }
}

$script:StubCall = New-Object 'System.Collections.Generic.List[object]'
$script:StubResult = @{}

# The stub models the driver STORE, not a recording of one enumeration. A package pnputil really
# removed has to disappear from the next /enum-drivers, because the step now re-enumerates to prove
# its own postcondition and a replayed constant would make that proof always fail. Set
# LeaveInStore on the /delete-driver result to keep a package listed after a reported success -
# that is the "pnputil lied" case, and it must be reachable.
$script:StubDeleted = New-Object 'System.Collections.Generic.List[string]'

function Remove-StubDriverFromXml {
    <#
    .SYNOPSIS
        Drops one whole <Driver DriverName="..."> element from rendered enumeration output.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Xml,
        [Parameter(Mandatory = $true)][string]$DriverName
    )

    if ([string]::IsNullOrEmpty($Xml)) { return $Xml }

    $pattern = '(?s)[ \t]*<Driver DriverName="' + [regex]::Escape($DriverName) + '">.*?</Driver>\r?\n'
    return [regex]::Replace($Xml, $pattern, '')
}

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

    # Exit 0 only, and the reason is about the STORE this stub models rather than about the step.
    # 3010 and 1641 mean the removal finishes at the next restart, so the package really is still
    # listed until then - a fixture that removed it immediately would model a machine that does not
    # exist. The step no longer skips its postcondition for those codes; it runs the check for every
    # started attempt and reads a reboot-required Present differently, keeping the export rather
    # than reclaiming it. DriverPostcondition.Tests crosses 1641 and 3010 with all three answers.
    if ($key -eq '/delete-driver' -and -not $timedOut -and $exitCode -eq 0 -and $argv.Count -ge 2) {
        if (-not $canned.ContainsKey('LeaveInStore') -or -not [bool]$canned['LeaveInStore']) {
            [void]$script:StubDeleted.Add([string]$argv[1])
        }
    }

    if ($key -eq '/enum-drivers') {
        foreach ($gone in @($script:StubDeleted)) {
            $standardOutput = Remove-StubDriverFromXml -Xml $standardOutput -DriverName $gone
        }
    }

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
    $script:StubDeleted.Clear()

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
