#Requires -Version 5.1
<#
.SYNOPSIS
    Transparent child adapter for the campaign's four supported switches.
.DESCRIPTION
    No generated or encoded commands. Integer values cross the native -File boundary and are
    converted into typed booleans only inside PowerShell, including Windows PowerShell 5.1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ScriptPath,
    [ValidateRange(-1, 1)][int]$NoPauseValue = -1,
    [ValidateRange(-1, 1)][int]$ResetValue = -1,
    [ValidateRange(-1, 1)][int]$PruneValue = -1,
    [ValidateRange(-1, 1)][int]$ScheduledValue = -1
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
try {
    $file = Get-Item -LiteralPath $ScriptPath -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Extension -ine '.ps1') { throw 'Expected a PowerShell script file.' }
    $parameters = @{}
    if ($NoPauseValue -ge 0) { $parameters.NoPause = [bool]$NoPauseValue }
    if ($ResetValue -ge 0) { $parameters.ResetWindowsUpdateBase = [bool]$ResetValue }
    if ($PruneValue -ge 0) { $parameters.PruneSupersededDrivers = [bool]$PruneValue }
    if ($ScheduledValue -ge 0) { $parameters.Scheduled = [bool]$ScheduledValue }
    $global:LASTEXITCODE = 0
    & $file.FullName @parameters
    exit $LASTEXITCODE
}
catch { Write-Error $_ -ErrorAction Continue; exit 1 }
