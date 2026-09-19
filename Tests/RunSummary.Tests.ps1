#Requires -Version 5.1
<#
.SYNOPSIS
    Every run leaves a machine-readable verdict beside its log, and it tells a refusal from a skip.

.DESCRIPTION
    The summary exists so a reader that is not a person can answer "did last night's run clean, or
    did it refuse?" without parsing prose. The distinction it has to carry is the one this project
    keeps finding collapsed: a step that never started because it was switched OFF and a step that
    never started because the run REFUSED look identical in any count of deleted files, and only one
    of them means the machine is fine.

    The run is the shipped entry point under the rig, so the document under test is one a real run
    wrote - not one this suite assembled.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'

Import-Module -Name (Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_RunProbe.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_RunRig.ps1')

function Get-RigSummary {
    <#
    .SYNOPSIS
        The summary document the run wrote, read from disk. $null when it wrote none.
    #>
    param([Parameter(Mandatory = $true)]$Rig)

    $found = @(Get-ChildItem -LiteralPath $Rig.LogDirectory -Filter '*.summary.json' -File -ErrorAction SilentlyContinue |
            Sort-Object -Property LastWriteTimeUtc -Descending)
    if ($found.Count -eq 0) { return $null }
    return ([System.IO.File]::ReadAllText($found[0].FullName) | ConvertFrom-Json)
}

Test-Case 'A run writes its verdict beside its log, and the two agree' {
    $rig = New-RunRig -Prefix 'rig-summary-clean'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ targets = @((New-PlanTarget -Category 'Temp' -FilesDeleted 4)) }
        Assert-True $result.Exited ('the run did not finish inside its bound. stderr: ' + $result.ErrorText)

        $summary = Get-RigSummary -Rig $rig
        Assert-True ($null -ne $summary) 'the run wrote no machine-readable summary'
        Assert-Equal 1 ([int]$summary.schema) 'the summary does not declare the schema a reader binds to'
        Assert-Equal ([int]$result.ExitCode) ([int]$summary.exitCode) `
            'the summary and the process disagree about how the run ended'
        Assert-True (-not [string]::IsNullOrWhiteSpace([string]$summary.outcome)) `
            'the summary carries an exit code but not the outcome that produced it'
        Assert-Equal 4 ([int]$summary.removed.entries) 'the summary did not carry what the run removed'
    }
    finally { Remove-RunRig -Rig $rig }
}

Test-Case 'A refused step and a step that never ran are DIFFERENT states in the summary' {
    # The whole point of the file. A quarantined run attempts nothing, and a reader that sees only
    # "0 files removed" cannot tell that from a quiet night with nothing to do.
    $rig = New-RunRig -Prefix 'rig-summary-refused'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ targets = @(); quarantined = $true }
        Assert-True $result.Exited ('the run did not finish inside its bound. stderr: ' + $result.ErrorText)

        $summary = Get-RigSummary -Rig $rig
        Assert-True ($null -ne $summary) 'the quarantined run wrote no summary'

        $states = @(@($summary.steps) | ForEach-Object { [string]$_.state } | Sort-Object -Unique)
        Assert-True ($states -ccontains 'refused') `
            ('a quarantined run recorded no refused step; states were: ' + ($states -join ','))

        # Discovery is NOT a mutation, so a quarantined run still executes it - which is exactly why
        # "did any step execute?" is the wrong question to ask this file. The claim is narrower and
        # truer: every step that would have CHANGED the machine is marked refused.
        foreach ($category in @('Delivery Optimization cache', 'Windows component store cleanup (DISM)',
                'Device driver packages (pnpclean)')) {
            $step = @(@($summary.steps) | Where-Object { [string]$_.category -ceq $category })
            Assert-Equal 1 $step.Count ('the summary does not carry the {0} step at all' -f $category)
            Assert-Equal 'refused' ([string]$step[0].state) `
                ('a quarantined run marked {0} as {1}' -f $category, [string]$step[0].state)
        }
        Assert-Equal 0 ([int]$summary.removed.entries) 'a quarantined run reported entries removed'
    }
    finally { Remove-RunRig -Rig $rig }
}

Test-Case 'The summary carries no path from inside a profile, and no command line' {
    # It is a verdict, not an inventory. A per-path listing of what was found in somebody's profile
    # is a different artifact with different handling, and a command line is where a secret would
    # arrive if one ever did.
    $rig = New-RunRig -Prefix 'rig-summary-shape'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ targets = @((New-PlanTarget -Category 'Caches' -FilesDeleted 2)) }
        Assert-True $result.Exited ('the run did not finish inside its bound. stderr: ' + $result.ErrorText)

        $raw = @(Get-ChildItem -LiteralPath $rig.LogDirectory -Filter '*.summary.json' -File |
                Sort-Object -Property LastWriteTimeUtc -Descending)
        Assert-True ($raw.Count -gt 0) 'the run wrote no summary'
        $text = [System.IO.File]::ReadAllText($raw[0].FullName)

        foreach ($forbidden in @('-MutexName', 'WAC_TEST_PLAN', 'ExecutionPolicy')) {
            Assert-False ($text.Contains($forbidden)) `
                ('the summary carries invocation detail it has no reason to hold: {0}' -f $forbidden)
        }
        Assert-False ($text -match '(?i)password|secret|token|credential') `
            'the summary carries something that reads like a credential field'
    }
    finally { Remove-RunRig -Rig $rig }
}

Complete-TestRun
