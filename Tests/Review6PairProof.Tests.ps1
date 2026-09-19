#Requires -Version 5.1
<#
.SYNOPSIS
    The committed task definition and the task/file recovery ordering are independent proofs.
.DESCRIPTION
    Real process/file/journal operations; the scheduler is the persistent JSON fixture.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Core.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Deploy.psm1') -Force -DisableNameChecking
. (Join-Path $PSScriptRoot '_DeployFixtures.ps1')
. (Join-Path $PSScriptRoot '_PairRecoveryFixture.ps1')

Test-Case 'Committed recovery restores the replacement task, never the original task' {
    $sandbox = New-TestSandbox -Prefix 'review6-committed-task'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        $a = New-TestCheckout -Path (Join-Path $sandbox 'A') -RunContent '# A'
        $b = New-TestCheckout -Path (Join-Path $sandbox 'B') -RunContent '# B'
        $initial = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $a
        Assert-Equal 0 $initial.ExitCode $initial.JournalText
        $arguments = Get-WacTaskActionArgument -RunScript (Join-Path $fixture.Root 'Run.ps1') -PruneSupersededDrivers
        $committed = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $b -NewArguments $arguments -Stop 'after-decision'
        Assert-Equal 70 $committed.ExitCode $committed.JournalText
        $wantTask = Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]
        $wantFiles = Get-PairInventory -Path $fixture.Root
        [System.IO.File]::WriteAllText($fixture.Tasks, '[]')
        $recovered = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $a -Stop 'after-recover'
        Assert-Equal 70 $recovered.ExitCode $recovered.JournalText
        Assert-Equal 1 @(Get-PairTask -Fixture $fixture).Count 'the committed registration was not restored exactly once'
        Assert-Equal $wantTask (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) 'task A was restored over committed files B'
        Assert-Equal $wantFiles (Get-PairInventory -Path $fixture.Root) 'committed files changed during task recovery'
        Assert-False (Test-Path -LiteralPath $fixture.CaptureRecord) 'the completed capture was not retired'
        Assert-False (Test-Path -LiteralPath $fixture.SwapRecord) 'the completed decision was not retired'
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'The file recovery half cannot discard a capture before task reconciliation' {
    Invoke-InDeploymentSandbox -Prefix 'review6-task-proof' -Body {
        param($sandbox)
        $slots = Get-WacDeploymentSlotPath
        $a = New-TestCheckout -Path (Join-Path $sandbox 'A') -RunContent '# A'
        $b = New-TestCheckout -Path (Join-Path $sandbox 'B') -RunContent '# B'
        [void](Install-WacDeployment -SourceRoot $a)
        [void](Write-WacTaskCaptureRecord -DeploymentRoot $slots.Root -Capture @([PSCustomObject]@{
            TaskName = (Get-WacTaskName); TaskPath = (Get-WacTaskFolder)
            Definition = (New-PairTaskXml -Root $slots.Root)
        }))
        [void](New-WacDeploymentStage -SourceRoot $b)
        [void](Switch-WacDeploymentStage -KeepPrevious)
        $before = Get-PairInventory -Path $slots.Root
        $refused = $false
        try { [void](Resolve-WacDeploymentRecoverySlot -Slots $slots) } catch { $refused = $true }
        Assert-True $refused 'the file-only caller bypassed task reconciliation'
        Assert-Equal $before (Get-PairInventory -Path $slots.Root) 'files changed before task proof'
        Assert-True (Test-Path -LiteralPath (Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root -Kind TaskCapture)) 'the task evidence was discarded'
    }
}
Complete-TestRun
