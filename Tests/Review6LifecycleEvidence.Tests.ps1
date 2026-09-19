#Requires -Version 5.1
<#
.SYNOPSIS
    The live lane must prove application execution and deployment payload changes, not metadata.
.DESCRIPTION
    Loads only the lane's pure proof functions through the AST. It never arms the live lane.
    The deployment-copy case uses the existing redirected ProgramFiles sandbox.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Core.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Deploy.psm1') -Force -DisableNameChecking
. (Join-Path $PSScriptRoot '_DeployFixtures.ps1')
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'VmDeploymentLifecycle.Tests.ps1'), [ref]$tokens, [ref]$errors)
if (@($errors).Count -gt 0) { throw (@($errors | ForEach-Object { $_.Message }) -join '; ') }
foreach ($name in @('Test-LifecycleScheduledCompletion', 'Get-LifecycleMarkerRelativePath', 'Test-LifecycleUpgradeMarker')) {
    $function = @($ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true))
    if ($function.Count -ne 1) { throw ('Expected one proof function: ' + $name) }
    . ([scriptblock]::Create($function[0].Extent.Text))
}

Test-Case 'Scheduler errors cannot masquerade as completed application runs' {
    foreach ($code in @(267011L, 267009L, 2147942667L, -2147024629L, 999L, $null, 'not-a-code')) {
        Assert-False (Test-LifecycleScheduledCompletion -Launched $true -State Ready -LastTaskResult $code) `
            ('a scheduler error was accepted as application completion: ' + [string]$code)
    }
}

Test-Case 'Only an observed Ready task with a documented application exit counts as completed' {
    foreach ($code in 0..7) {
        Assert-True (Test-LifecycleScheduledCompletion -Launched $true -State Ready -LastTaskResult $code)
    }
    foreach ($state in @('Running', 'Gone', 'Disabled', 'Unknown', '')) {
        Assert-False (Test-LifecycleScheduledCompletion -Launched $true -State $state -LastTaskResult 0)
    }
    Assert-False (Test-LifecycleScheduledCompletion -Launched $false -State Ready -LastTaskResult 0) `
        'a stale success code alone proved this invocation ran'
}

Test-Case 'The upgrade probe actually travels through the shipped deployment copy' {
    Invoke-InDeploymentSandbox -Prefix 'review6-payload' -Body {
        param($sandbox)
        $source = New-TestCheckout -Path (Join-Path $sandbox 'source')
        $relative = Get-LifecycleMarkerRelativePath
        $probe = Join-Path $source $relative
        # The old root-level marker was outside the copy list. This negative control keeps that
        # fact visible rather than treating a changed manifest timestamp as an upgraded payload.
        [System.IO.File]::WriteAllText((Join-Path $source 'VM_UPGRADE_MARKER.txt'), 'excluded root probe')
        [System.IO.File]::WriteAllText($probe, 'unique deployed payload')
        [void](Install-WacDeployment -SourceRoot $source)
        $root = Get-WacDeploymentRoot
        Assert-False (Test-Path -LiteralPath (Join-Path $root 'VM_UPGRADE_MARKER.txt'))
        Assert-True (Test-LifecycleUpgradeMarker -SourceRoot $source -DeploymentRoot $root) `
            'the upgrade marker is not part of the actual deployed payload'
        [System.IO.File]::WriteAllText((Join-Path $root $relative), 'wrong payload')
        Assert-False (Test-LifecycleUpgradeMarker -SourceRoot $source -DeploymentRoot $root)
        [System.IO.File]::Delete((Join-Path $root $relative))
        Assert-False (Test-LifecycleUpgradeMarker -SourceRoot $source -DeploymentRoot $root)
    }
}
Complete-TestRun
