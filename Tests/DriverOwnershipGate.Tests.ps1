#Requires -Version 5.1
<#
.SYNOPSIS
    WAC-05R: a pnputil this run could not prove stopped must not let its export be reclaimed.

.DESCRIPTION
    Invoke-WacProcess reports TerminationProven honestly - a bounded timeout whose tree could not be
    proven gone, or a pipe still held open after the root exited, both answer $false. Until now the
    driver prune was the only DESTRUCTIVE consumer of that verdict and it ignored it: the exit code
    alone decided, so a root that exited 0 while something it started was still writing to the driver
    store could have its export and pending marker reclaimed. The export is frequently the only
    remaining copy of a package, so the reclaim is the irreversible half of the step.

    An unproven stop is treated exactly like a killed tool: the marker stays, the copy stays, and the
    step reports Incomplete rather than a removal nobody observed.

    This suite owns its own file rather than joining the three existing driver suites: all of them
    are past the point where new cases belong in them. No real pnputil runs - everything goes through
    Core's injected process invoker, and the backup root is a TEMP sandbox.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
foreach ($moduleLeaf in @('Core', 'FileSystem', 'Steps', 'Drivers')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

$script:DriversModule = Get-Module -Name 'WindowsAutoCleanup.Drivers'

. (Join-Path -Path $PSScriptRoot -ChildPath '_DriverFixtures.ps1')

# A TEMP sandbox is genuinely user-writable and therefore genuinely untrusted, on this machine and on
# an elevated runner alike. Answering that one walk yes keeps these cases about the behaviour they
# name; the walk itself is measured against real injected roots in DriverBackup.Tests.ps1.
$script:RealStatePathTrust = Get-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacStatePathIsTrusted'
Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacStatePathIsTrusted' -Body {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path,
        [ValidateRange(1, 128)][int]$MaxDepth = 64
    )
    $null = $MaxDepth
    return [PSCustomObject]@{
        Path = $Path; IsTrusted = $true; Reason = 'sandbox trust forced for this suite'
        Checked = @($Path); Failures = @(); Writers = @()
    }
}

$script:PendingName = 'wac-driver-delete.pending'

function Get-GateBackupDirectory {
    param([Parameter(Mandatory = $true)][string]$Root)

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue)
}

Test-Case 'a delete whose tree could not be proven stopped keeps its export and its pending marker' {
    # The exit code says the TOOL believes it finished. TerminationProven says whether anything this
    # run started is still alive. Only the second one licenses reclaiming the export, and the store
    # is deliberately left agreeing that the package is gone - so with the gate removed the step
    # reaches a clean, confident, wrong "deleted=1" and destroys the only copy.
    $sandbox = New-TestSandbox -Prefix 'dr-gate-unproven'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 0 }

            Set-WacProcessInvoker -Invoker {
                param($FilePath, $ArgumentList, $TimeoutMs)
                $answer = & $script:RecordingInvoker $FilePath $ArgumentList $TimeoutMs
                $argv = @($ArgumentList)
                if (@($argv).Count -gt 0 -and $argv[0] -eq '/delete-driver') {
                    # Exactly the shape the runner now produces for an inherited pipe: the root
                    # exited cleanly, and something it started is still holding the handle.
                    Add-Member -InputObject $answer -NotePropertyName 'TerminationProven' -NotePropertyValue $false -Force
                    Add-Member -InputObject $answer -NotePropertyName 'OutputComplete' -NotePropertyValue $false -Force
                }
                return $answer
            }

            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'deleted=0') `
                ('a delete whose tree was still alive was counted as a removal: {0}' -f $result.Detail)
            Assert-True ($result.Detail -match 'incomplete=1') $result.Detail

            $left = @(Get-GateBackupDirectory -Root $backupRoot)
            Assert-Equal 1 $left.Count 'the only copy of a package whose deletion was still running was thrown away'
            Assert-True (Test-Path -LiteralPath (Join-Path -Path $left[0].FullName -ChildPath $script:PendingName)) `
                'the pending marker came off while a process that may still be deleting was alive'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the same delete with a proven stop still completes normally' {
    # The control. Without it the gate above would also pass if the step had simply stopped being
    # able to delete anything at all, and every real prune would start reporting Incomplete.
    $sandbox = New-TestSandbox -Prefix 'dr-gate-proven'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 0 }

            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'deleted=1') `
                ('a proven, confirmed removal was not counted: {0}' -f $result.Detail)
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
