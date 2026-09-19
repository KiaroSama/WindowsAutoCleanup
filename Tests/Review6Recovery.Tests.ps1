#Requires -Version 5.1
<#
.SYNOPSIS
    Fresh-process and real-filesystem counterexamples for the review-6 recovery transaction.
.DESCRIPTION
    The scheduler in the pair fixture is a persistent JSON stand-in. File moves, records and
    installer recovery functions are real. No production task or deployment is changed.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Core.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Deploy.psm1') -Force -DisableNameChecking
. (Join-Path $PSScriptRoot '_DeployFixtures.ps1')
. (Join-Path $PSScriptRoot '_PairRecoveryFixture.ps1')
$script:DeployModule = Get-Module WindowsAutoCleanup.Deploy

Test-Case 'An interrupted installation onto an empty original can restore that empty original' {
    Invoke-InDeploymentSandbox -Prefix 'review6-empty' -Body {
        param($sandbox)
        $slots = Get-WacDeploymentSlotPath
        [void][System.IO.Directory]::CreateDirectory($slots.Root)
        $source = New-TestCheckout -Path (Join-Path $sandbox 'source')
        [void](New-WacDeploymentStage -SourceRoot $source)
        [void](Switch-WacDeploymentStage -KeepPrevious)
        & $script:DeployModule { $script:DeploymentTransaction = $null }
        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'RestoreOriginal' ([string]$plan.Verdict) ([string]$plan.Reason)
        [void](Resolve-WacDeploymentRecoverySlot -Slots $slots)
        Assert-True ([System.IO.Directory]::Exists($slots.Root)) 'the originally empty directory was not restored'
        Assert-Equal 0 @([System.IO.Directory]::GetFileSystemEntries($slots.Root)).Count 'the original was not empty after recovery'
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'the restored slot survived under its old name'
    }
}

Test-Case 'A capture that cannot retire preserves the authoritative commit decision and recovery copy' {
    Invoke-InDeploymentSandbox -Prefix 'review6-retire' -Body {
        param($sandbox)
        $sourceA = New-TestCheckout -Path (Join-Path $sandbox 'A') -RunContent '# A'
        [void](Install-WacDeployment -SourceRoot $sourceA)
        $sourceB = New-TestCheckout -Path (Join-Path $sandbox 'B') -RunContent '# B'
        [void](New-WacDeploymentStage -SourceRoot $sourceB)
        [void](Switch-WacDeploymentStage -KeepPrevious)
        $slots = Get-WacDeploymentSlotPath
        $capture = [PSCustomObject]@{
            TaskName = (Get-WacTaskName); TaskPath = (Get-WacTaskFolder)
            Definition = (New-PairTaskXml -Root $slots.Root)
        }
        Assert-True (Write-WacTaskCaptureRecord -DeploymentRoot $slots.Root -Capture @($capture))
        Assert-True ([bool](Set-WacDeploymentCommitted).Recorded)
        $path = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root -Kind TaskCapture
        $held = New-Object System.IO.FileStream($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            Assert-False (Remove-WacDeploymentPrevious) 'cleanup reported success while a dependent capture was locked'
            $record = Read-WacDeploymentJournal -DeploymentRoot $slots.Root
            Assert-Equal 'Valid' ([string]$record.State) 'the commit decision was deleted before its dependent capture'
            Assert-True ([bool]$record.Record.Committed) 'the durable commit decision changed'
            Assert-True (Test-Path -LiteralPath $slots.Previous) 'the recovery copy was discarded before evidence retirement succeeded'
        }
        finally { $held.Dispose() }
        Assert-True (Remove-WacDeploymentPrevious) 'retry after releasing the capture did not finish cleanup'
        Assert-False (Test-Path -LiteralPath $path) 'the capture outlived its commit evidence'
        Assert-Equal 'Absent' ([string](Read-WacDeploymentJournal -DeploymentRoot $slots.Root).State)
    }
}

Test-Case 'First-install recovery never removes files while leaving its newly registered task behind' {
    $sandbox = New-TestSandbox -Prefix 'review6-first-pair'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        $source = New-TestCheckout -Path (Join-Path $sandbox 'source') -RunContent '# first install'
        $killed = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $source -Stop 'after-register'
        Assert-Equal 70 $killed.ExitCode ($killed.Journal -join ' / ')
        Assert-Equal 1 @(Get-PairTask -Fixture $fixture).Count 'the failure fixture never registered its task'
        $next = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $source -Stop 'after-recover'
        Assert-Equal 70 $next.ExitCode ($next.Journal -join ' / ')
        Assert-Equal 0 @(Get-PairTask -Fixture $fixture).Count 'the first-install task survived rollback of its files'
        Assert-False (Test-Path -LiteralPath $fixture.Root) 'a first-install rollback kept its replacement tree'
        Assert-False (Test-Path -LiteralPath $fixture.SwapRecord) 'the recovered first install kept its swap record'
        Assert-False (Test-Path -LiteralPath $fixture.CaptureRecord) 'the recovered first install kept its task record'
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'A committed record with no previous slot does not certify a corrupted replacement' {
    Invoke-InDeploymentSandbox -Prefix 'review6-corrupt' -Body {
        param($sandbox)
        $source = New-TestCheckout -Path (Join-Path $sandbox 'source')
        [void](New-WacDeploymentStage -SourceRoot $source)
        [void](Switch-WacDeploymentStage -KeepPrevious)
        Assert-True ([bool](Set-WacDeploymentCommitted).Recorded)
        $slots = Get-WacDeploymentSlotPath
        [System.IO.File]::AppendAllText((Join-Path $slots.Root 'Run.ps1'), ' corruption')
        & $script:DeployModule { $script:DeploymentTransaction = $null }
        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'Refuse' ([string]$plan.Verdict) 'a commit flag alone authorized retiring evidence of an unhealthy replacement'
        Assert-Equal 'Valid' ([string](Read-WacDeploymentJournal -DeploymentRoot $slots.Root).State)
    }
}
Complete-TestRun
