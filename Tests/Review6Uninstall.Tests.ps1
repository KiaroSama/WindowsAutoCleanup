#Requires -Version 5.1
<#
.SYNOPSIS
    An interrupted authorized uninstall must not become an install recovery on the next run.
.DESCRIPTION
    Uses the persistent scheduler fixture, actual files, journals and a real open-file lock.
    The closing function is parsed from the shipped uninstaller, not reimplemented by this test.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Core.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Deploy.psm1') -Force -DisableNameChecking
. (Join-Path $PSScriptRoot '_DeployFixtures.ps1')
. (Join-Path $PSScriptRoot '_PairRecoveryFixture.ps1')
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $script:RepoRoot 'Uninstall-WindowsAutoCleanupTask.ps1'), [ref]$tokens, [ref]$errors)
Assert-Equal 0 @($errors).Count 'the shipped uninstaller did not parse'
$closer = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Close-OutstandingJournal'
}, $true)
. ([scriptblock]::Create($closer.Extent.Text))
function Write-UninstallerMessage {
    param($Level, $Message, $Data)
    $null = $Level; $null = $Message; $null = $Data
}

Test-Case 'An install cannot resurrect a captured task after an interrupted authorized uninstall' {
    $sandbox = New-TestSandbox -Prefix 'review6-uninstall-crash'
    $programFiles = $env:ProgramFiles
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        $source = New-TestCheckout -Path (Join-Path $sandbox 'A') -RunContent '# original'
        $initial = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $source
        Assert-Equal 0 $initial.ExitCode $initial.JournalText
        $interrupted = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $source -Stop 'after-unregister'
        Assert-Equal 70 $interrupted.ExitCode $interrupted.JournalText
        Assert-Equal 0 @(Get-PairTask -Fixture $fixture).Count 'the old task was not removed by the fixture'
        $env:ProgramFiles = $fixture.ProgramFiles
        Assert-True (Set-WacUninstallIntent -DeploymentRoot $fixture.Root) 'the intent was not recorded'
        $before = [System.IO.File]::ReadAllText($fixture.CaptureRecord)
        [void](Remove-WacDeployment -Path $fixture.Root)
        $retry = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $source
        Assert-Equal 1 $retry.ExitCode 'installation did not refuse pending uninstall intent'
        Assert-Equal 0 @(Get-PairTask -Fixture $fixture).Count 'the removed task was resurrected'
        Assert-Equal $before ([System.IO.File]::ReadAllText($fixture.CaptureRecord)) 'the old recovery evidence changed'
        Assert-False ([bool](Test-WacDeploymentGenerationSettled -DeploymentRoot $fixture.Root).Settled)
        Assert-True (Close-OutstandingJournal -Slots (Get-WacDeploymentSlotPath)) 'authorized cleanup could not retire the intent'
        $again = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $source
        Assert-Equal 0 $again.ExitCode $again.JournalText
        Assert-Equal 1 @(Get-PairTask -Fixture $fixture).Count 'fresh installation was not admitted after cleanup'
    }
    finally { $env:ProgramFiles = $programFiles; Remove-TestSandbox -Path $sandbox }
}

Test-Case 'An uninstall with locked capture evidence retains its intent until cleanup can finish' {
    Invoke-InDeploymentSandbox -Prefix 'review6-uninstall-lock' -Body {
        param($sandbox)
        $null = $sandbox
        $slots = Get-WacDeploymentSlotPath
        Assert-True (Set-WacUninstallIntent -DeploymentRoot $slots.Root)
        Assert-True (Write-WacTaskCaptureRecord -DeploymentRoot $slots.Root -Capture @())
        $capture = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root -Kind TaskCapture
        $held = New-Object System.IO.FileStream($capture, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            Assert-False (Close-OutstandingJournal -Slots $slots) 'locked evidence was reported retired'
            Assert-Equal 'Valid' ([string](Read-WacDeploymentJournal -DeploymentRoot $slots.Root -Kind Uninstall).State)
            Assert-Equal 'Refuse' ([string](Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root).Verdict)
        }
        finally { $held.Dispose() }
        Assert-True (Close-OutstandingJournal -Slots $slots)
        Assert-Equal 'Absent' ([string](Read-WacDeploymentJournal -DeploymentRoot $slots.Root -Kind Uninstall).State)
        Assert-True ([bool](Test-WacDeploymentGenerationSettled -DeploymentRoot $slots.Root).Settled)
    }
}

Test-Case 'A directory at the uninstall intent name is neither absence nor an authorized intent' {
    Invoke-InDeploymentSandbox -Prefix 'review6-uninstall-dir' -Body {
        param($sandbox)
        $null = $sandbox
        $slots = Get-WacDeploymentSlotPath
        $path = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root -Kind Uninstall
        [void][System.IO.Directory]::CreateDirectory($path)
        Assert-False (Set-WacUninstallIntent -DeploymentRoot $slots.Root)
        Assert-Equal 'Refuse' ([string](Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root).Verdict)
        Assert-True ([System.IO.Directory]::Exists($path)) 'the untrusted intent object was altered'
    }
}
Complete-TestRun
