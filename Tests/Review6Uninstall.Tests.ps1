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
# The installer's own recovery surface is not part of the deployment module: the entry point
# dot-sources it, and so does every suite that exercises it directly.
. (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.InstallerTask.ps1')
. (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.InstallerRecovery.ps1')
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $script:RepoRoot 'Uninstall-WindowsAutoCleanupTask.ps1'), [ref]$tokens, [ref]$errors)
Assert-Equal 0 @($errors).Count 'the shipped uninstaller did not parse'
foreach ($wanted in @('Close-OutstandingJournal', 'Write-OutstandingIntentNotice')) {
    $found = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $wanted
    }.GetNewClosure(), $true)
    Assert-True ($null -ne $found) ('the shipped uninstaller no longer defines {0}' -f $wanted)
    . ([scriptblock]::Create($found.Extent.Text))
}

# The stub RECORDS rather than swallows: what the fence notice says, and which record it names, is
# the behaviour under test in the last case here.
$script:LastUninstallerMessage = ''
$script:LastUninstallerData = $null
function Write-UninstallerMessage {
    param($Level, $Message, $Data)
    $null = $Level
    $script:LastUninstallerMessage = [string]$Message
    $script:LastUninstallerData = $Data
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
Test-Case 'A run that leaves the machine fenced names the record that fences it' {
    # FR-015. The intent record is written before anything is removed, and while it stands every
    # install and every scheduled cleanup refuses. A run that ended without retiring it used to say
    # only that the files had been kept, so the operator had to work out both that the machine was
    # fenced and which artifact was doing it.
    Invoke-InDeploymentSandbox -Prefix 'review6-uninstall-notice' -Body {
        param($sandbox)
        $null = $sandbox
        $slots = Get-WacDeploymentSlotPath
        Assert-True (Set-WacUninstallIntent -DeploymentRoot $slots.Root)
        $path = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root -Kind Uninstall

        $script:LastUninstallerMessage = ''
        $script:LastUninstallerData = $null
        Write-OutstandingIntentNotice -Slots $slots

        # Read the key rather than the property: under Set-StrictMode 2.0 a missing member THROWS,
        # and a mutation that drops the path would then fail on a language error instead of on the
        # sentence that names the defect.
        $named = ''
        if ($null -ne $script:LastUninstallerData -and @($script:LastUninstallerData.Keys) -ccontains 'record') {
            $named = [string]$script:LastUninstallerData['record']
        }
        Assert-Equal $path $named 'the notice did not name the record that fences the machine'
        Assert-True ($script:LastUninstallerMessage -match 'refuses to change anything') `
            ('the notice did not say the machine is fenced: ' + $script:LastUninstallerMessage)
        Assert-True ($script:LastUninstallerMessage -match 'Re-run the uninstaller') `
            ('the notice did not name the step that clears it: ' + $script:LastUninstallerMessage)

        # And it says nothing at all once there is no fence to report.
        Assert-True (Remove-WacDeploymentJournal -DeploymentRoot $slots.Root -Kind Uninstall)
        $script:LastUninstallerMessage = ''
        Write-OutstandingIntentNotice -Slots $slots
        Assert-Equal '' $script:LastUninstallerMessage 'a settled machine was told it was fenced'
    }
}

Test-Case 'A legacy commit refusal names both records it is retaining' {
    # FR-015 on the migration path: a machine whose PREVIOUS build committed but could not retire its
    # records arrives at this branch, and the refusal is permanent until a person acts. "Both records"
    # is not something an operator can act on without first finding out which two files that means.
    Invoke-InDeploymentSandbox -Prefix 'review6-legacy-commit' -Body {
        param($sandbox)
        $null = $sandbox
        $slots = Get-WacDeploymentSlotPath
        $plan = [PSCustomObject]@{
            Verdict = 'CommitReplacement'
            Swap = [PSCustomObject]@{ State = 'Valid'; Record = ([PSCustomObject]@{ Committed = $true }) }
            Capture = [PSCustomObject]@{ State = 'Valid'; Capture = @() }
            Slots = $slots
        }
        $result = Resolve-InterruptedTaskCapture -DeploymentRoot $slots.Root `
            -Lookup ([PSCustomObject]@{ State = 'Found'; Task = @() }) -Plan $plan

        Assert-False ([bool]$result.Ok) 'a legacy commit with no replacement proof was accepted'
        foreach ($kind in @('Swap', 'TaskCapture')) {
            $record = [string](Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root -Kind $kind)
            Assert-True ([string]$result.Reason).Contains($record) `
                ('the refusal did not name the {0} record it retains: {1}' -f $kind, [string]$result.Reason)
        }
    }
}

Complete-TestRun
