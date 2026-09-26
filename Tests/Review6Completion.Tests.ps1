#Requires -Version 5.1
<#
.SYNOPSIS
    Positive controls and adjacent regressions for the completion protocol.
.DESCRIPTION
    Uses disposable process/control fixtures. No machine clock or production state is changed.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Core.psm1') -Force -DisableNameChecking
$script:Core = Get-Module WindowsAutoCleanup.Core

Test-Case 'A monotonic uptime decrease proves a restart regardless of wall-clock text' {
    $saved = & $script:Core { (Get-Command Get-WacMachineUptimeMs).ScriptBlock }
    try {
        & $script:Core { function script:Get-WacMachineUptimeMs { return 1000L } }
        $proof = Test-WacMachineRestartedSince -RaisedUtc 'not a clock' -RaisedUptimeMs (2000L)
        Assert-True ([bool]$proof.Restarted) 'positive monotonic restart evidence was rejected'
        $same = Test-WacMachineRestartedSince -RaisedUtc '1900-01-01' -RaisedUptimeMs (500L)
        Assert-False ([bool]$same.Restarted) 'a larger current counter is not proof of a new boot'
    }
    finally { & $script:Core { param($body) Set-Item function:script:Get-WacMachineUptimeMs $body } $saved }
}

Test-Case 'Native preparation that exhausts the operation starts no tool' {
    & $script:Core { [void](Initialize-WacOwnedProcessNative) }
    $saved = & $script:Core { (Get-Command Initialize-WacOwnedProcessNative).ScriptBlock }
    try {
        & $script:Core { function script:Initialize-WacOwnedProcessNative { Start-Sleep -Milliseconds 350; return $true } }
        $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $run = Invoke-WacProcess -FilePath $exe -ArgumentList @('-NoProfile', '-Command', 'exit 0') -TimeoutMs 100
        Assert-False ([bool]$run.Started) 'the command was resumed after its setup spent the whole deadline'
        Assert-True ([bool]$run.TimedOut) 'deadline exhaustion was not reported'
        Assert-True ($run.DurationMs -ge 300) 'the reported duration omitted native preparation'
    }
    finally { & $script:Core { param($body) Set-Item function:script:Initialize-WacOwnedProcessNative $body } $saved }
}

Test-Case 'A bounded mutator is external unless its caller proves host-confined work' {
    # The suite's TEMP control store cannot pass the strict owner check unelevated; the verdict is
    # shimmed exactly as Quarantine.Tests.ps1 does, and the store stays this suite's own.
    Set-WacDirectoryTrustJudge -ScriptBlock {
        param($Sddl, $Strict)
        $null = $Sddl; $null = $Strict
        return [PSCustomObject]@{ IsTrusted = $true; Owner = $null; Reason = 'test shim: descriptor verdict'; Writers = @() }
    }
    Reset-WacAbandonedMutator
    try {
        $run = Invoke-WacBounded -TimeoutMs 500 -Mutating -ScriptBlock { [System.Threading.Thread]::Sleep(2000) }
        Assert-True ([bool]$run.Started) 'the fixture never entered the bounded work'
        Assert-True ([bool]$run.TimedOut) 'the fixture did not reach abandonment'
        $record = Read-WacQuarantineMarker
        Assert-Equal 'Valid' ([string]$record.State) 'no durable abandonment was recorded'
        Assert-Equal 'External' ([string]$record.Record.OperationKind) 'service-dispatching work was incorrectly tied to host lifetime'
    }
    finally {
        Start-Sleep -Milliseconds 2200
        [void](Remove-WacQuarantineMarker)
        Reset-WacAbandonedMutator
        Set-WacDirectoryTrustJudge -ScriptBlock $null
    }
}
Complete-TestRun
