#Requires -Version 5.1
<#
.SYNOPSIS
    Machine-readable terminal verdicts must include the refusing paths, not just the full footer.
.DESCRIPTION
    Real shipped Run.ps1 in the existing disposable rig; machine mutators remain scripted results.
    Exit codes are independently observed from the child, not inferred from the summary.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path $script:RepoRoot 'src'
$script:RunPath = Join-Path $script:RepoRoot 'Run.ps1'
Import-Module (Join-Path $script:SrcRoot 'WindowsAutoCleanup.Core.psm1') -Force -DisableNameChecking
. (Join-Path $PSScriptRoot '_RunProbe.ps1')
. (Join-Path $PSScriptRoot '_RunRig.ps1')

function Assert-TerminalSummary {
    param($Rig, $Result, [int]$Code, [string]$Mode = 'cleanup')
    Assert-True $Result.Exited ('child timed out: ' + $Result.ErrorText)
    Assert-Equal $Code ([int]$Result.ExitCode) (Get-RigLogText -Rig $Rig)
    $logs = @(Get-ChildItem -LiteralPath $Rig.LogDirectory -Filter 'WindowsAutoCleanup_*.log' -File)
    Assert-Equal 1 $logs.Count 'the case never acquired exactly one durable log'
    $path = [System.IO.Path]::ChangeExtension($logs[0].FullName, '.summary.json')
    Assert-True ([System.IO.File]::Exists($path)) 'a durably logged terminal path wrote no summary'
    $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
    Assert-Equal $Code ([int]$value.exitCode) 'summary and observed process exit disagree'
    Assert-Equal $Mode ([string]$value.mode) 'the summary misstates what kind of run this was'
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$value.outcome)) 'no terminal outcome was recorded'
    if ($Code -ne 0) { Assert-False ([string]$value.outcome -ceq 'Succeeded') 'a refusal was summarized as success' }
    Assert-Equal 0 ([int]$value.removed.entries) 'pre-cleanup refusal invented deleted entries'
}

Test-Case 'A normal empty run still emits one matching terminal summary' {
    $rig = New-RunRig -Prefix 'review7-summary-normal'
    try { Assert-TerminalSummary -Rig $rig -Result (Invoke-RunRig -Rig $rig -Plan @{ targets = @() }) -Code 0 }
    finally { Remove-RunRig -Rig $rig }
}

Test-Case 'Unsupported system drive exit 5 has a terminal summary' {
    $rig = New-RunRig -Prefix 'review7-summary-drive'
    try { Assert-TerminalSummary -Rig $rig -Result (Invoke-RunRig -Rig $rig -Plan @{ driveUnsupported = $true }) -Code 5 }
    finally { Remove-RunRig -Rig $rig }
}

Test-Case 'An expired preflight exit 6 has a terminal summary' {
    $rig = New-RunRig -Prefix 'review7-summary-budget'
    try { Assert-TerminalSummary -Rig $rig -Result (Invoke-RunRig -Rig $rig -Plan @{ deadlineExpired = $true }) -Code 6 }
    finally { Remove-RunRig -Rig $rig }
}

Test-Case 'A missing required module exit 1 has a terminal summary' {
    $rig = New-RunRig -Prefix 'review7-summary-module'
    try {
        [System.IO.File]::Delete((Join-Path $rig.Src 'WindowsAutoCleanup.Drivers.psm1'))
        Assert-TerminalSummary -Rig $rig -Result (Invoke-RunRig -Rig $rig -Plan @{}) -Code 1
    }
    finally { Remove-RunRig -Rig $rig }
}

Test-Case 'A busy operation lock exit 3 has a terminal summary without owning that lock' {
    $rig = New-RunRig -Prefix 'review7-summary-busy'
    $mutex = New-Object System.Threading.Mutex($false, $rig.MutexName)
    $held = $false
    try {
        $held = $mutex.WaitOne(0)
        Assert-True $held 'fixture could not hold its unique mutex'
        Assert-TerminalSummary -Rig $rig -Result (Invoke-RunRig -Rig $rig -Plan @{}) -Code 3
    }
    finally {
        if ($held) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'An invalid scheduled preview exit 1 has a terminal summary' {
    $rig = New-RunRig -Prefix 'review7-summary-options'
    try { Assert-TerminalSummary -Rig $rig -Result (Invoke-RunRig -Rig $rig -Plan @{} -ExtraArgument @('-Preview')) -Code 1 -Mode 'preview' }
    finally { Remove-RunRig -Rig $rig }
}
Complete-TestRun
