#Requires -Version 5.1
<#
.SYNOPSIS
    Preview and JSON state labels must not disguise selected maintenance or failed admission.
.DESCRIPTION
    Calls the real reporting functions with read-only discovery and log-output seams. No cleanup,
    registry write, external tool or real profile enumeration is performed by this suite.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'src\WindowsAutoCleanup.RunSummary.ps1')
. (Join-Path $root 'src\WindowsAutoCleanup.RunPreview.ps1')

Test-Case 'A failed unattempted step is refused, never merely unarmed' {
    Assert-Equal 'refused' (Get-WacStepExecutionState -Result ([PSCustomObject]@{ Attempted = $false; Outcome = 'Failed' }))
}

Test-Case 'A missing attempted fact remains unstated even when an outcome exists' {
    Assert-Equal 'unstated' (Get-WacStepExecutionState -Result ([PSCustomObject]@{ Outcome = 'Succeeded' }))
}

Test-Case 'Known attempted and safely disabled steps retain their distinct states' {
    Assert-Equal 'executed' (Get-WacStepExecutionState -Result ([PSCustomObject]@{ Attempted = $true; Outcome = 'Failed' }))
    Assert-Equal 'unarmed' (Get-WacStepExecutionState -Result ([PSCustomObject]@{ Attempted = $false; Outcome = 'SafeSkip' }))
}

Test-Case 'An empty allow-list preview still discloses every always-selected maintenance step' {
    $script:Lines = New-Object 'System.Collections.Generic.List[string]'
    function Write-WacPreviewLine { param([string]$Text = '') [void]$script:Lines.Add($Text) }
    function Get-WacCleanupTargetSet {
        param([string[]]$SkipCategory)
        $null = $SkipCategory
        return [PSCustomObject]@{ Target = @(); Outcome = 'Succeeded'; Detail = '' }
    }
    function Write-WacRunVerdict { param([string]$Outcome) if ($Outcome -ceq 'Succeeded') { return 0 }; return 6 }
    Assert-Equal 0 (Show-WacRunPreview -SkipRecycleBin)
    $text = $script:Lines -join "`n"
    foreach ($required in @('Delivery Optimization', 'StartComponentCleanup', 'pnpclean')) {
        Assert-True ($text -match [regex]::Escape($required)) ('preview omitted selected maintenance: ' + $required)
    }
}
Complete-TestRun
