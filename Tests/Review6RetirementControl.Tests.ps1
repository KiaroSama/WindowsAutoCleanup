#Requires -Version 5.1
<#
.SYNOPSIS
    Commit and rollback deliberately retire their two records in opposite orders.
.DESCRIPTION
    A real open file handle blocks capture deletion. Every retry is a fresh process. File operations
    and records are real; scheduling is the persistent JSON fixture and touches no production task.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Core.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Deploy.psm1') -Force -DisableNameChecking
. (Join-Path $PSScriptRoot '_DeployFixtures.ps1')
. (Join-Path $PSScriptRoot '_PairRecoveryFixture.ps1')

foreach ($committed in @($false, $true)) {
    $label = if ($committed) { 'Commit' } else { 'Rollback' }
    Test-Case ($label + ' preserves the correct pair across a locked capture and a fresh retry') {
        $sandbox = New-TestSandbox -Prefix 'review6-retirement-order'
        $held = $null
        try {
            $fixture = New-PairSandbox -Sandbox $sandbox
            $a = New-TestCheckout -Path (Join-Path $sandbox 'A') -RunContent '# original A'
            $b = New-TestCheckout -Path (Join-Path $sandbox 'B') -RunContent '# replacement B'
            $initial = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $a
            Assert-Equal 0 $initial.ExitCode $initial.JournalText
            $wantFiles = Get-PairInventory -Path $fixture.Root
            $wantTask = Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]
            $arguments = Get-WacTaskActionArgument -RunScript (Join-Path $fixture.Root 'Run.ps1') -PruneSupersededDrivers
            $stop = if ($committed) { 'after-decision' } else { 'after-register' }
            $changed = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $b -NewArguments $arguments -Stop $stop
            Assert-Equal 70 $changed.ExitCode $changed.JournalText
            if ($committed) {
                $wantFiles = Get-PairInventory -Path $fixture.Root
                $wantTask = Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]
            }
            $held = New-Object System.IO.FileStream($fixture.CaptureRecord, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $blocked = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $b -Stop 'after-recover'
            Assert-False $blocked.TimedOut 'a sharing violation hung recovery'
            Assert-True (Test-Path -LiteralPath $fixture.CaptureRecord) 'the locked capture unexpectedly disappeared'
            Assert-Equal ([bool]$committed) ([bool](Test-Path -LiteralPath $fixture.SwapRecord)) 'commit and rollback used the same unsafe retirement order'
            Assert-Equal $wantFiles (Get-PairInventory -Path $fixture.Root) 'the wrong file generation survived'
            Assert-Equal $wantTask (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) 'the wrong task generation survived'
            $held.Dispose()
            $held = $null

            $retry = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $b -Stop 'after-recover'
            Assert-Equal 70 $retry.ExitCode $retry.JournalText
            Assert-False (Test-Path -LiteralPath $fixture.SwapRecord) 'the retry left a swap record'
            Assert-False (Test-Path -LiteralPath $fixture.CaptureRecord) 'the retry left a task capture'
            Assert-Equal $wantFiles (Get-PairInventory -Path $fixture.Root) 'the retry changed the correct file generation'
            Assert-Equal $wantTask (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) 'the retry changed the correct task generation'
            Assert-Equal 1 @(Get-PairTask -Fixture $fixture).Count 'the retry duplicated the registration'
        }
        finally {
            if ($held) { $held.Dispose() }
            Remove-TestSandbox -Path $sandbox
        }
    }
}
Complete-TestRun
