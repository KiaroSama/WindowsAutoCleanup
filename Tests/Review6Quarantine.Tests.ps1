#Requires -Version 5.1
<#
.SYNOPSIS
    Counterexamples for completion evidence, without changing the machine clock or real state.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Core.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.StepContract.psm1') -Force -DisableNameChecking
$script:Core = Get-Module WindowsAutoCleanup.Core

Test-Case 'Elapsed civil time without monotonic evidence can never prove a machine restart' {
    $saved = & $script:Core { (Get-Command Get-WacMachineUptimeMs).ScriptBlock }
    try {
        & $script:Core { function script:Get-WacMachineUptimeMs { return 1000000L } }
        # This is the observation made after a forward clock correction, on the SAME boot.
        # No OS clock is adjusted: the evidence is supplied at the public comparison boundary.
        $raised = (Get-Date).ToUniversalTime().AddDays(-30).ToString('o')
        $answer = Test-WacMachineRestartedSince -RaisedUtc $raised
        Assert-False ([bool]$answer.Restarted) 'a wall-clock age was accepted as proof that an external mutator cannot survive'
    }
    finally { & $script:Core { param($body) Set-Item function:script:Get-WacMachineUptimeMs $body } $saved }
}

Test-Case 'Never-started results do not override contradictory termination and output facts' {
    $run = [PSCustomObject]@{
        Started = $false; TerminationProven = $false; OutputComplete = $false
        Owned = $false; OwnedTreeState = 'Complete'; ExitCode = $null; TimedOut = $false
    }
    $answer = Test-WacToolLifetimeSettled -Run $run
    Assert-False ([bool]$answer.Settled) 'a contradictory result licensed the next mutation'
    Assert-False ([bool]$answer.OutputTrustworthy) 'unproven output was declared trustworthy'
}
Complete-TestRun
