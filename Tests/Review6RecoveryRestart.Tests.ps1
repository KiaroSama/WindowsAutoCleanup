#Requires -Version 5.1
<#
.SYNOPSIS
    Recovery must itself survive interruption at record-retirement and original-state boundaries.
.DESCRIPTION
    Real child processes, files, rename operations and file-sharing failures. The scheduler is the
    existing persistent JSON fixture, not the real machine scheduler. Reachable intermediate file
    states are constructed explicitly where the fixture has no instruction-level crash hook.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Core.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Deploy.psm1') -Force -DisableNameChecking
. (Join-Path $PSScriptRoot '_DeployFixtures.ps1')
. (Join-Path $PSScriptRoot '_PairRecoveryFixture.ps1')

Test-Case 'Rollback keeps the original task capture until its swap record can be retired' {
    $sandbox = New-TestSandbox -Prefix 'review6-rollback-retire'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        $a = New-TestCheckout -Path (Join-Path $sandbox 'A') -RunContent '# original A'
        $b = New-TestCheckout -Path (Join-Path $sandbox 'B') -RunContent '# replacement B'
        $initial = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $a
        Assert-Equal 0 $initial.ExitCode $initial.JournalText
        $originalFiles = Get-PairInventory -Path $fixture.Root
        $originalTask = Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]
        $arguments = Get-WacTaskActionArgument -RunScript (Join-Path $fixture.Root 'Run.ps1') -PruneSupersededDrivers
        $upgrade = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $b -NewArguments $arguments -Stop 'after-register'
        Assert-Equal 70 $upgrade.ExitCode $upgrade.JournalText

        # Acquire the real delete-denying handle AFTER acknowledgement has been written, so the
        # failure is record retirement, not an earlier attempted atomic acknowledgement write.
        $driver = [System.IO.File]::ReadAllText($fixture.Driver)
        $call = '$recovered = Resolve-WacDeploymentRecoverySlot -Slots $slots'
        $replacement = @'
$recordHold = New-Object System.IO.FileStream(($slots.Root + '.transaction.json'), [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
try { $recovered = Resolve-WacDeploymentRecoverySlot -Slots $slots }
finally { $recordHold.Dispose() }
'@
        Assert-True ($driver.Contains($call)) 'the fixture recovery boundary was not located'
        [System.IO.File]::WriteAllText($fixture.Driver, $driver.Replace($call, $replacement))
        $blocked = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $b -Stop 'after-recover'
        Assert-False $blocked.TimedOut 'the sharing violation hung recovery'
        Assert-True (Test-Path -LiteralPath $fixture.SwapRecord) 'the locked record unexpectedly disappeared'
        Assert-True (Test-Path -LiteralPath $fixture.CaptureRecord) 'rollback deleted the only original task definition while its journal survived'
        Assert-Equal $originalFiles (Get-PairInventory -Path $fixture.Root) 'rollback failed to restore files A'
        Assert-Equal $originalTask (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) 'rollback failed to restore task A'

        [System.IO.File]::WriteAllText($fixture.Driver, $driver)
        $retry = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $b -Stop 'after-recover'
        Assert-Equal 70 $retry.ExitCode $retry.JournalText
        Assert-False (Test-Path -LiteralPath $fixture.SwapRecord) 'the retry did not retire the journal'
        Assert-False (Test-Path -LiteralPath $fixture.CaptureRecord) 'the retry did not retire the capture'
        Assert-Equal $originalFiles (Get-PairInventory -Path $fixture.Root) 'the retry changed the restored original'
        Assert-Equal $originalTask (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) 'the retry changed the restored task'
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'A first-install rollback interrupted after removal recognizes the original absence' {
    $sandbox = New-TestSandbox -Prefix 'review6-absent-restart'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        $source = New-TestCheckout -Path (Join-Path $sandbox 'source')
        $started = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $source -Stop 'after-swap'
        Assert-Equal 70 $started.ExitCode $started.JournalText
        Assert-Equal 0 @(Get-PairTask -Fixture $fixture).Count 'the pre-registration fixture registered a task'
        $ack = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $source -Stop 'after-reconcile'
        Assert-Equal 70 $ack.ExitCode $ack.JournalText
        # Exactly the next completed filesystem operation in first-install rollback.
        [System.IO.Directory]::Delete($fixture.Root, $true)
        $retry = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $source -Stop 'after-recover'
        Assert-Equal 70 $retry.ExitCode $retry.JournalText
        Assert-False (Test-Path -LiteralPath $fixture.Root) 'the original absence was not preserved'
        Assert-Equal 0 @(Get-PairTask -Fixture $fixture).Count 'the retry resurrected a task'
        Assert-False (Test-Path -LiteralPath $fixture.SwapRecord) 'the absent original left an unresolved swap'
        Assert-False (Test-Path -LiteralPath $fixture.CaptureRecord) 'the absent original left an unresolved capture'
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'Recovery promotes a corroborated empty original when the replacement root is absent' {
    $sandbox = New-TestSandbox -Prefix 'review6-empty-restart'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        [void][System.IO.Directory]::CreateDirectory($fixture.Root)
        $source = New-TestCheckout -Path (Join-Path $sandbox 'source')
        $started = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $source -Stop 'after-swap'
        Assert-Equal 70 $started.ExitCode $started.JournalText
        Assert-Equal 0 @([System.IO.Directory]::GetFileSystemEntries($fixture.Previous)).Count 'the original slot was not empty'
        # The reachable interval after replacement removal and before original promotion.
        [System.IO.Directory]::Delete($fixture.Root, $true)
        $retry = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $source -Stop 'after-recover'
        Assert-Equal 70 $retry.ExitCode $retry.JournalText
        Assert-True ([System.IO.Directory]::Exists($fixture.Root)) 'the original empty directory was discarded'
        Assert-Equal 0 @([System.IO.Directory]::GetFileSystemEntries($fixture.Root)).Count 'the restored original was not empty'
        Assert-Equal 0 @(Get-PairTask -Fixture $fixture).Count 'the empty original acquired a task'
        Assert-False (Test-Path -LiteralPath $fixture.Previous) 'the promoted original still occupies the previous slot'
        Assert-False (Test-Path -LiteralPath $fixture.SwapRecord) 'the empty original left an unresolved swap'
        Assert-False (Test-Path -LiteralPath $fixture.CaptureRecord) 'the empty original left an unresolved capture'
    }
    finally { Remove-TestSandbox -Path $sandbox }
}
Complete-TestRun
