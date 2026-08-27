#Requires -Version 5.1
<#
.SYNOPSIS
    The removal postcondition: a package counts as deleted only when the driver STORE says so.

.DESCRIPTION
    pnputil's exit code is what the TOOL believes. The step now re-enumerates afterwards and asks
    the store itself, because a tool that reports success and does nothing is exactly the failure a
    count derived from its own exit code cannot see.

    Three answers, three different outcomes, and the difference between them is the whole point:

      Removed  the store no longer lists it        -> the deletion may be committed and counted
      Present  pnputil said success, it is there   -> Failed, and the export is reclaimed because
                                                     the package is provably still installed
      Unknown  the enumeration could not be read   -> Incomplete, and the export and its pending
                                                     marker STAY, because it may be the only copy
                                                     left of something that is already gone

    A reboot-required exit code (3010 / 1641) deliberately SKIPS the check: the removal finishes at
    the next restart, so the package is legitimately still listed and 'Present' would be a false
    alarm that failed every such run.

    No real pnputil ever runs. Everything goes through Core's injected process invoker, and the
    fixture models the store rather than replaying one enumeration - a package it really removed
    disappears from the next /enum-drivers.
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

$script:PendingName = 'wac-driver-delete.pending'

function Get-BackupDirectory {
    <#
    .SYNOPSIS
        Every directory under the backup root, or an empty array when the root was never created.
    #>
    param([Parameter(Mandatory = $true)][string]$Root)

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue)
}

Test-Case 'a package the store still lists after a reported success is a failure, not a deletion' {
    $sandbox = New-TestSandbox -Prefix 'dr-post-present'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            # pnputil reports success and the package stays in the store. That is the lie the
            # postcondition exists to catch; without LeaveInStore the fixture would remove it.
            $script:StubResult['/delete-driver'] = @{ ExitCode = 0; LeaveInStore = $true }

            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Failed' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'deleted=0') ('a package that is still installed was counted as deleted: {0}' -f $result.Detail)
            Assert-True ($result.Detail -match 'failed=1') $result.Detail

            # Provably still installed, so the export is a copy of a live package. Keeping it
            # protected would refuse this package on every later run - the permanent-refusal trap.
            Assert-Equal 0 @(Get-BackupDirectory -Root $backupRoot).Count 'a copy of a still-installed package was left behind and protected'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a removal that cannot be confirmed is Incomplete, and the only possible copy is kept' {
    $sandbox = New-TestSandbox -Prefix 'dr-post-unknown'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            # The FIRST enumeration succeeds and finds the candidate; the confirming one is killed on
            # its deadline. The stub answers by argument, so both share this result - which is why
            # the case asserts the outcome rather than the call count.
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 0; LeaveInStore = $true }

            # Make only the SECOND enumeration unreadable: the store still lists the package, so a
            # parse failure is what separates "still there" from "cannot tell".
            Set-WacProcessInvoker -Invoker {
                param($FilePath, $ArgumentList, $TimeoutMs)
                $argv = @($ArgumentList)
                if (@($argv).Count -gt 0 -and $argv[0] -eq '/enum-drivers' -and $script:StubDeleted.Count -ge 0 -and $script:SeenEnum) {
                    return [PSCustomObject]@{ ExitCode = $null; TimedOut = $true; StandardOutput = ''; StandardError = ''; DurationMs = 1; Started = $true }
                }
                if (@($argv).Count -gt 0 -and $argv[0] -eq '/enum-drivers') { $script:SeenEnum = $true }
                return (& $script:RecordingInvoker $FilePath $ArgumentList $TimeoutMs)
            }
            $script:SeenEnum = $false

            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'deleted=0') ('an unconfirmed removal was counted as deleted: {0}' -f $result.Detail)
            Assert-True ($result.Detail -match 'incomplete=1') $result.Detail

            $left = @(Get-BackupDirectory -Root $backupRoot)
            Assert-Equal 1 $left.Count 'the only possible copy of a maybe-removed package was thrown away'
            Assert-True (Test-Path -LiteralPath (Join-Path -Path $left[0].FullName -ChildPath $script:PendingName)) `
                'the pending marker came off while the removal was still unproven'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a reboot-required removal skips the check, because the package is legitimately still listed' {
    $sandbox = New-TestSandbox -Prefix 'dr-post-reboot'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            # 3010 is ERROR_SUCCESS_REBOOT_REQUIRED: the removal completes at the next restart, so
            # the fixture leaves the package listed exactly as a real store would.
            $script:StubResult['/delete-driver'] = @{ ExitCode = 3010 }

            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'deleted=1') ('a reboot-pending removal was not counted: {0}' -f $result.Detail)
            Assert-True $result.RebootRequired 'the run did not report that a reboot is required'

            # Exactly two enumerations would mean the postcondition ran anyway. It must not.
            $enumerations = @($script:StubCall | Where-Object { @($_.Arguments).Count -gt 0 -and $_.Arguments[0] -eq '/enum-drivers' })
            Assert-Equal 1 $enumerations.Count 'the postcondition ran for a reboot-pending removal and would have failed it'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a confirmed removal enumerates twice and only then counts the package' {
    $sandbox = New-TestSandbox -Prefix 'dr-post-removed'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 0 }

            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'deleted=1') $result.Detail

            $enumerations = @($script:StubCall | Where-Object { @($_.Arguments).Count -gt 0 -and $_.Arguments[0] -eq '/enum-drivers' })
            Assert-Equal 2 $enumerations.Count 'the removal was counted without asking the store whether it happened'

            # The order is load-bearing: confirming before the delete would prove nothing.
            $delete = @($script:StubCall | Where-Object { @($_.Arguments).Count -gt 0 -and $_.Arguments[0] -eq '/delete-driver' })
            Assert-True ($script:StubCall.IndexOf($delete[0]) -lt $script:StubCall.IndexOf($enumerations[1])) `
                'the confirming enumeration ran before the deletion'

            $left = @(Get-BackupDirectory -Root $backupRoot)
            Assert-Equal 1 $left.Count 'a confirmed deletion did not keep its backup'
            Assert-False (Test-Path -LiteralPath (Join-Path -Path $left[0].FullName -ChildPath $script:PendingName)) `
                'the pending marker survived a fully committed deletion'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Test-WacDriverPackageRemoved separates gone, still-there and cannot-tell' {
    # The classifier on its own, with no prune loop around it, so each answer is isolated.
    $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

    Invoke-WithStubbedTool -Body {
        $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
        $present = Test-WacDriverPackageRemoved -PnpUtil $script:PnpUtilPath -DriverName 'oem1.inf' -TimeoutMs 5000
        Assert-Equal 'Present' $present.State 'a package the store still lists was not reported present'
        Assert-True ($present.Reason -match 'still in the driver store') $present.Reason

        $gone = Test-WacDriverPackageRemoved -PnpUtil $script:PnpUtilPath -DriverName 'oem-never-existed.inf' -TimeoutMs 5000
        Assert-Equal 'Removed' $gone.State 'a package the store does not list was not reported removed'

        $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; TimedOut = $true; Out = '' }
        $killed = Test-WacDriverPackageRemoved -PnpUtil $script:PnpUtilPath -DriverName 'oem1.inf' -TimeoutMs 5000
        Assert-Equal 'Unknown' $killed.State 'a killed enumeration was read as proof'

        $script:StubResult['/enum-drivers'] = @{ ExitCode = 1; Out = '' }
        $refused = Test-WacDriverPackageRemoved -PnpUtil $script:PnpUtilPath -DriverName 'oem1.inf' -TimeoutMs 5000
        Assert-Equal 'Unknown' $refused.State 'a non-zero enumeration was read as proof'

        $exhausted = Test-WacDriverPackageRemoved -PnpUtil $script:PnpUtilPath -DriverName 'oem1.inf' -TimeoutMs 0
        Assert-Equal 'Unknown' $exhausted.State 'an exhausted budget was read as proof'
    }
}

Complete-TestRun
