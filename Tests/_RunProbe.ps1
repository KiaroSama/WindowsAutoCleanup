<#
.SYNOPSIS
    Reading and driving the shipped Run.ps1 from outside: its parsed AST, and the bounded child
    processes that execute it.

.DESCRIPTION
    Dot-sourced by RunRelaunch.Tests.ps1, RunSurface.Tests.ps1 and RunExitCode.Tests.ps1. It is not
    a suite: its name does not match Tests\*.Tests.ps1, so the runner never executes it on its own.

    The suite must set $script:RunPath before dot-sourcing this file, because Run.ps1 is parsed at
    dot-source time.
#>

. (Join-Path -Path $PSScriptRoot -ChildPath '_ProbeProcess.ps1')

# ---------------------------------------------------------------------------------------------
# Lifting the function under test out of Run.ps1
# ---------------------------------------------------------------------------------------------

$script:RunTokens = $null
$script:RunErrors = $null
$script:RunAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $script:RunPath, [ref]$script:RunTokens, [ref]$script:RunErrors)

function Get-RunFunctionText {
    <#
    .SYNOPSIS
        The verbatim source of one function defined in Run.ps1.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)

    $found = @($script:RunAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true) | Where-Object { $_.Name -eq $Name })

    if ($found.Count -ne 1) {
        throw ('Run.ps1 must define exactly one {0}; found {1}.' -f $Name, $found.Count)
    }
    return [string]$found[0].Extent.Text
}

# ---------------------------------------------------------------------------------------------
# Child processes
# ---------------------------------------------------------------------------------------------

function Invoke-Probe {
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [hashtable]$Environment = @{},
        [int]$TimeoutMs = 90000,
        [string]$HostExe
    )

    $process = $null
    try {
        $process = Start-ProbeProcess -CommandLine $CommandLine -Environment $Environment -HostExe $HostExe
        return (Wait-ProbeProcess -Process $process -TimeoutMs $TimeoutMs)
    }
    finally {
        if ($process) { try { $process.Dispose() } catch { $null = $_ } }
    }
}

function Get-ProbeValue {
    <#
    .SYNOPSIS
        Reads one KEY=value line out of a probe's stdout.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Output,
        [Parameter(Mandatory = $true)][string]$Key
    )

    foreach ($line in @($Output -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith($Key + '=', [System.StringComparison]::Ordinal)) {
            return $trimmed.Substring($Key.Length + 1)
        }
    }
    return $null
}

# A parameter block that mirrors Run.ps1's, so a value that does not survive the command line shows
# up as the DEFAULT the parent never asked for - which is exactly how P0-2 behaved.
$script:ArgumentProbeBody = @'
[CmdletBinding()]
param(
    [switch]$Scheduled,
    [switch]$ResetWindowsUpdateBase = $true,
    [switch]$PruneSupersededDrivers,
    [switch]$EnableLegacyDiskCleanup,
    [switch]$SkipRecycleBin,
    [string[]]$SkipCategory = @(),
    [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$LogLevel = 'INFO',
    [ValidateRange(1, 235)][int]$BudgetMinutes = 210,
    [string]$MutexName = 'Global\WindowsAutoCleanup'
)

Set-StrictMode -Version 2.0
$split = @($SkipCategory | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

Write-Output ('SELF=' + $PSCommandPath)
Write-Output ('RESET=' + [bool]$ResetWindowsUpdateBase)
Write-Output ('PRUNE=' + [bool]$PruneSupersededDrivers)
Write-Output ('LEGACY=' + [bool]$EnableLegacyDiskCleanup)
Write-Output ('SKIPBIN=' + [bool]$SkipRecycleBin)
Write-Output ('LOGLEVEL=' + $LogLevel)
Write-Output ('BUDGET=' + $BudgetMinutes)
Write-Output ('MUTEX=' + $MutexName)
Write-Output ('CATEGORY=' + ($split -join '|'))
exit 0
'@

$script:InspectProbeBody = @'
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:WAC_PROBE_MODE -eq 'help') {
    $help = Get-Help -Full -Name $env:WAC_PROBE_RUN
    Write-Output ('PARAMS=' + ((@($help.parameters.parameter) | ForEach-Object { $_.name }) -join ','))
    Write-Output ('SYNOPSIS=' + ((($help.Synopsis) -replace '\s+', ' ').Trim()))
    Write-Output ('DESCRIPTION=' + (((($help.description | Out-String)) -replace '\s+', ' ').Trim()))
    Write-Output ('NOTES=' + ((($help.alertSet.alert | Out-String) -replace '\s+', ' ').Trim()))
    exit 0
}

if ($env:WAC_PROBE_MODE -eq 'surface') {
    foreach ($name in @('Core', 'FileSystem', 'Targets', 'Steps', 'Drivers')) {
        $path = Join-Path -Path $env:WAC_PROBE_SRC -ChildPath ('WindowsAutoCleanup.{0}.psm1' -f $name)
        Import-Module -Name $path -Force -DisableNameChecking -ErrorAction Stop
        Write-Output ('IMPORTED=' + $name)
    }

    $missing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($command in @($env:WAC_PROBE_COMMAND -split ',' | Where-Object { $_ })) {
        if (-not (Get-Command -Name $command -CommandType Function -ErrorAction SilentlyContinue)) {
            [void]$missing.Add($command)
        }
    }

    Write-Output ('MISSING=' + ($missing -join ','))
    Write-Output ('CHECKED=' + @($env:WAC_PROBE_COMMAND -split ',' | Where-Object { $_ }).Count)
    exit 0
}

Write-Output 'MODE=unknown'
exit 9
'@

function New-ProbeScript {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Body
    )

    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
    [System.IO.File]::WriteAllText($Path, $Body, (New-Object System.Text.UTF8Encoding($false)))
    return $Path
}
