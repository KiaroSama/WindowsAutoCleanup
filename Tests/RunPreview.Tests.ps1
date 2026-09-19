#Requires -Version 5.1
<#
.SYNOPSIS
    The preview shows what a run would sweep, and changes nothing while it does.

.DESCRIPTION
    The second claim is the one that matters. A preview that is only MOSTLY read-only is worse than
    no preview at all, because it is invoked by exactly the operator who is not yet willing to let
    the tool touch the machine.

    Two of the three cases are therefore about ORDER and REACH rather than about output, and they are
    AST assertions for the same reason Orchestration.Tests.ps1 makes one: a preview that deleted
    something before printing would still print, so only the position of the exit and the absence of
    a deletion call can say which one this is. The third case runs the shipped entry point for real.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

# The rig reads these three before it can copy the entry point into its sandbox, so they are set
# BEFORE it is dot-sourced, exactly as RunExitCode.Tests.ps1 sets them.
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'

Import-Module -Name (Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_RunProbe.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_RunRig.ps1')

function Get-ParsedFile {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path -Path $script:RepoRoot -ChildPath $RelativePath), [ref]$null, [ref]$errors)
    Assert-Equal 0 @($errors).Count ('{0} did not parse' -f $RelativePath)
    return $ast
}

Test-Case 'The preview exits BEFORE the first thing a run deletes' {
    # Log retention is the run's first mutation and it runs a handful of lines after the gate. A
    # preview that returned anywhere below it would already have deleted files on the machine it
    # promised not to touch, and would still have printed a correct-looking plan.
    $ast = Get-ParsedFile -RelativePath 'Run.ps1'
    $text = [string]$ast.Extent.Text

    $previewAt = $text.IndexOf('Show-WacRunPreview', [System.StringComparison]::Ordinal)
    Assert-True ($previewAt -ge 0) 'Run.ps1 no longer invokes the preview at all'

    foreach ($mutator in @('Remove-WacOldLog', 'Clear-WacDeliveryOptimizationCache', 'Remove-WacTree',
            'Remove-WacFilesByPattern', 'Invoke-WacComponentCleanup', 'Invoke-WacPnpCleanHandler',
            'Invoke-WacDriverPackagePrune', 'Invoke-WacLegacyDiskCleanup', 'Clear-WacRecycleBin')) {
        $at = $text.IndexOf($mutator, [System.StringComparison]::Ordinal)
        Assert-True ($at -ge 0) ('Run.ps1 no longer calls {0}, so this ordering proves nothing' -f $mutator)
        Assert-True ($previewAt -lt $at) `
            ('the preview is invoked AFTER {0}, so a preview would already have changed the machine' -f $mutator)
    }
}

Test-Case 'The preview itself reaches no mutating primitive' {
    # Position is not enough on its own: the preview could call a deleter of its own. The whole
    # function body is searched, not just its first lines.
    $ast = Get-ParsedFile -RelativePath 'src\WindowsAutoCleanup.RunPreview.ps1'
    $body = $ast.Find({ param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Show-WacRunPreview'
        }, $true)
    Assert-True ($null -ne $body) 'the preview no longer defines Show-WacRunPreview'

    $called = @($body.FindAll({ param($node)
                $node -is [System.Management.Automation.Language.CommandAst]
            }, $true) | ForEach-Object { [string]$_.GetCommandName() } | Where-Object { $_ })

    foreach ($forbidden in @('Remove-WacTree', 'Remove-WacFilesByPattern', 'Remove-WacOldLog',
            'Clear-WacDeliveryOptimizationCache', 'Clear-WacRecycleBin', 'Invoke-WacComponentCleanup',
            'Invoke-WacPnpCleanHandler', 'Invoke-WacDriverPackagePrune', 'Invoke-WacLegacyDiskCleanup',
            'Remove-Item', 'Set-ItemProperty', 'New-Item', 'Start-Process')) {
        Assert-False ($called -ccontains $forbidden) `
            ('the preview calls {0}; a preview that mutates is the one thing it may never do' -f $forbidden)
    }
}

Test-Case 'A preview refuses to be a scheduled run' {
    # A trigger that previews for ever is a machine that silently stopped being cleaned while
    # reporting success every night. The two switches refuse together rather than one quietly
    # winning - and the rig always supplies -Scheduled, so adding -Preview is the whole fixture.
    $rig = New-RunRig -Prefix 'rig-preview-scheduled'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ targets = @() } -ExtraArgument @('-Preview')

        Assert-True $result.Exited ('the run did not finish inside its bound. stderr: ' + $result.ErrorText)
        Assert-Equal 1 ([int]$result.ExitCode) ('a scheduled preview was allowed to run: ' + (Get-RigLogText -Rig $rig))
        Assert-True ((Get-RigLogText -Rig $rig) -match 'cannot be used together') `
            ('the refusal did not say why: ' + (Get-RigLogText -Rig $rig))
    }
    finally { Remove-RunRig -Rig $rig }
}

Complete-TestRun
