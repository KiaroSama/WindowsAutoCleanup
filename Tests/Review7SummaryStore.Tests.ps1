#Requires -Version 5.1
<#
.SYNOPSIS
    Summary creation must retain the log store's collision and containment guarantees.
.DESCRIPTION
    Real NTFS file, hard-link and junction operations in a disposable sandbox. Only the descriptor
    verdict is replaced, just as in the existing trusted-store tests. No system file is targeted.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Core.psm1') -Force -DisableNameChecking
. (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.RunSummary.ps1')
$script:Version = 'test'
$script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Invoke-SummaryStoreFixture {
    param([scriptblock]$Body)
    $sandbox = New-TestSandbox -Prefix 'review7-summary-store'
    $store = Join-Path $sandbox 'store'
    $outside = Join-Path $sandbox 'outside'
    [void][System.IO.Directory]::CreateDirectory($store)
    [void][System.IO.Directory]::CreateDirectory($outside)
    Set-WacDirectoryTrustJudge -ScriptBlock {
        param($Sddl, $Strict)
        $null = $Sddl; $null = $Strict
        return [PSCustomObject]@{ IsTrusted = $true; Owner = $null; Reason = 'fixture descriptor'; Writers = @() }
    }
    try { & $Body $store $outside }
    finally {
        Set-WacDirectoryTrustJudge -ScriptBlock $null
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A fresh summary is valid UTF-8 JSON and releases its file handle' {
    Invoke-SummaryStoreFixture {
        param($store, $outside)
        $null = $outside
        $path = Join-Path $store 'run.summary.json'
        Assert-True (Write-WacRunSummaryDocument -Path $path -Outcome 'Succeeded' -ExitCode 0)
        $bytes = [System.IO.File]::ReadAllBytes($path)
        Assert-False ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) 'unexpected BOM'
        $value = [System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        Assert-Equal 'Succeeded' ([string]$value.outcome)
        Assert-Equal 0 ([int]$value.exitCode)
        $exclusive = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $exclusive.Dispose()
    }
}

Test-Case 'An existing summary is never truncated by a second publication' {
    Invoke-SummaryStoreFixture {
        param($store, $outside)
        $null = $outside
        $path = Join-Path $store 'run.summary.json'
        [System.IO.File]::WriteAllText($path, 'EXISTING-EVIDENCE')
        try { [void](Write-WacRunSummaryDocument -Path $path -Outcome 'Succeeded' -ExitCode 0) } catch { $null = $_ }
        Assert-Equal 'EXISTING-EVIDENCE' ([System.IO.File]::ReadAllText($path)) 'the existing name was opened and overwritten'
    }
}

Test-Case 'A preplanted hard link cannot turn summary publication into an outside write' {
    Invoke-SummaryStoreFixture {
        param($store, $outside)
        $sentinel = Join-Path $outside 'sentinel.txt'
        $path = Join-Path $store 'run.summary.json'
        [System.IO.File]::WriteAllText($sentinel, 'OUTSIDE-ORIGINAL')
        [void](New-Item -ItemType HardLink -Path $path -Target $sentinel -ErrorAction Stop)
        try { [void](Write-WacRunSummaryDocument -Path $path -Outcome 'Succeeded' -ExitCode 0) } catch { $null = $_ }
        Assert-Equal 'OUTSIDE-ORIGINAL' ([System.IO.File]::ReadAllText($sentinel)) 'summary publication wrote through a hard link'
    }
}

Test-Case 'A junction in the summary parent is refused rather than followed' {
    Invoke-SummaryStoreFixture {
        param($store, $outside)
        $link = Join-Path $store 'redirect'
        [void](New-Item -ItemType Junction -Path $link -Target $outside -ErrorAction Stop)
        try {
            try { [void](Write-WacRunSummaryDocument -Path (Join-Path $link 'run.summary.json') -Outcome 'Succeeded' -ExitCode 0) } catch { $null = $_ }
            Assert-False ([System.IO.File]::Exists((Join-Path $outside 'run.summary.json'))) 'summary publication escaped through the parent junction'
        }
        finally { [System.IO.Directory]::Delete($link) }
    }
}
Complete-TestRun
