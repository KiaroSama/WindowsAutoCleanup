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

    A reboot-required exit code (3010 / 1641) is confirmed like every other started attempt, and it
    is the ANSWER that is read differently. The removal does finish at the next restart, so a
    package the store still lists is not a refuted deletion - but it is not a proved one either, and
    it used to be counted as one on the exit code alone. It is now Incomplete with its export and
    marker kept, and Resolve-WacDriverBackupPending settles it on the first run after the restart.

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

# The step now walks its backup root for machine trust before it exports anything, and every case in
# this suite drives a root inside a TEMP sandbox - which is genuinely user-writable and therefore
# genuinely untrusted, on this developer machine and on an elevated runner alike. Answering that one
# walk yes keeps each case about the behaviour it names. The walk itself, and the refusals it
# produces, are measured against real injected roots in DriverBackup.Tests.ps1.
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


# ---------------------------------------------------------------------------------------------
# The classifier reads the NAME inventory, not the pruning list
# ---------------------------------------------------------------------------------------------

Test-Case 'a package the store still lists in a row it could not fully parse is Present, not Removed' {
    # The dropped row IS the requested package. Every field a PRUNING decision reads is required and
    # a row missing one is dropped, so the package disappeared from the list this check used to
    # scan - and an absence there read as a removal. The XML is well formed and the package is right
    # there in it.
    foreach ($missing in @('SignerName', 'ProviderName', 'ClassGuid', 'OriginalName', 'DriverVersion')) {
        $xml = New-PnpUtilDriverXml -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -Omit @($missing)),
            (New-PnpUtilRow -DriverName 'oem2.inf')
        )

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $state = Test-WacDriverPackageRemoved -PnpUtil $script:PnpUtilPath -DriverName 'oem1.inf' -TimeoutMs 5000

            Assert-Equal 'Present' $state.State ('a package listed in a row missing {0} was reported removed' -f $missing)
            Assert-True ($state.Reason -match 'still in the driver store') $state.Reason
        }
    }
}

Test-Case 'an unrelated unparsable row does not poison an otherwise conclusive answer' {
    # The other half of the same rule. Dropping a row must not make every answer Unknown, or one
    # incomplete package anywhere in the store would block every removal from ever being confirmed -
    # which is its own permanent-refusal defect.
    $xml = New-PnpUtilDriverXml -Row @(
        (New-PnpUtilRow -DriverName 'oem1.inf'),
        (New-PnpUtilRow -DriverName 'oem99.inf' -Omit @('SignerName'))
    )

    Invoke-WithStubbedTool -Body {
        $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }

        $gone = Test-WacDriverPackageRemoved -PnpUtil $script:PnpUtilPath -DriverName 'oem-never-existed.inf' -TimeoutMs 5000
        Assert-Equal 'Removed' $gone.State ('an unrelated incomplete row blocked a conclusive answer: {0}' -f $gone.Reason)

        # And the incomplete row is still evidence about ITSELF.
        $other = Test-WacDriverPackageRemoved -PnpUtil $script:PnpUtilPath -DriverName 'oem99.inf' -TimeoutMs 5000
        Assert-Equal 'Present' $other.State $other.Reason
    }
}

Test-Case 'an element the enumeration could not name makes absence inconclusive, never a removal' {
    $xml = New-PnpUtilDriverXml -Row @(
        (New-PnpUtilRow -DriverName ''), (New-PnpUtilRow -DriverName 'oem2.inf')
    )

    Invoke-WithStubbedTool -Body {
        $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }

        $unknown = Test-WacDriverPackageRemoved -PnpUtil $script:PnpUtilPath -DriverName 'oem1.inf' -TimeoutMs 5000
        Assert-Equal 'Unknown' $unknown.State 'an incomplete store listing was read as proof of removal'
        Assert-True ($unknown.Reason -match 'incomplete') $unknown.Reason

        # A package that IS in the listing stays conclusive: the gap only removes the ability to
        # argue from absence.
        $present = Test-WacDriverPackageRemoved -PnpUtil $script:PnpUtilPath -DriverName 'oem2.inf' -TimeoutMs 5000
        Assert-Equal 'Present' $present.State $present.Reason
    }
}

# ---------------------------------------------------------------------------------------------
# The postcondition runs for EVERY started attempt, not only for a documented success
# ---------------------------------------------------------------------------------------------

# The shared fixture only takes a package out of its modelled store on exit 0, because that is the
# only combination the shipped code used to act on. Proving the store is now asked after 259 and
# after an undocumented non-zero needs the two halves decoupled: what the tool REPORTS, and what the
# store actually holds afterwards.
$script:DeleteExitCode = 0
$script:DeleteRemovesFromStore = $false
$script:ConfirmUnreadable = $false
$script:SeenEnumeration = $false

$script:DecoupledInvoker = {
    param($FilePath, $ArgumentList, $TimeoutMs)

    $argv = @($ArgumentList)
    $key = ''
    if ($argv.Count -gt 0) { $key = [string]$argv[0] }

    if ($key -eq '/delete-driver') {
        [void]$script:StubCall.Add([PSCustomObject]@{ FilePath = [string]$FilePath; Arguments = $argv; TimeoutMs = [int]$TimeoutMs })
        if ($script:DeleteRemovesFromStore -and $argv.Count -ge 2) { [void]$script:StubDeleted.Add([string]$argv[1]) }
        return [PSCustomObject]@{
            ExitCode = $script:DeleteExitCode; TimedOut = $false; StandardOutput = ''
            StandardError = ''; DurationMs = 5; Started = $true
        }
    }

    # Only the CONFIRMING enumeration is made unreadable: the first one still has to find the
    # candidate, or the case would prove nothing about what happens after a deletion.
    if ($key -eq '/enum-drivers') {
        if ($script:ConfirmUnreadable -and $script:SeenEnumeration) {
            [void]$script:StubCall.Add([PSCustomObject]@{ FilePath = [string]$FilePath; Arguments = $argv; TimeoutMs = [int]$TimeoutMs })
            return [PSCustomObject]@{
                ExitCode = $null; TimedOut = $true; StandardOutput = ''
                StandardError = ''; DurationMs = 1; Started = $true
            }
        }
        $script:SeenEnumeration = $true
    }

    return (& $script:RecordingInvoker $FilePath $ArgumentList $TimeoutMs)
}

function Set-DeleteOutcome {
    <#
    .SYNOPSIS
        Installs the decoupled invoker for one prune run: the exit code pnputil reports, whether the
        store really loses the package, and whether the confirming enumeration can be read.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [switch]$StoreRemoves,
        [switch]$ConfirmUnreadable
    )

    $script:DeleteExitCode = $ExitCode
    $script:DeleteRemovesFromStore = [bool]$StoreRemoves
    $script:ConfirmUnreadable = [bool]$ConfirmUnreadable
    $script:SeenEnumeration = $false
    Set-WacProcessInvoker -Invoker $script:DecoupledInvoker
}

function Get-EnumerationCall {
    return @($script:StubCall | Where-Object { @($_.Arguments).Count -gt 0 -and $_.Arguments[0] -eq '/enum-drivers' })
}

Test-Case 'an undocumented non-zero exit still asks the store, and a package that is gone is committed' {
    # The trap this closes: every non-zero code that was not 259 deleted the export outright and
    # counted a benign skip, without ever asking whether the mutating process it had just run
    # removed the package. If it had, that threw away the only copy of it.
    $sandbox = New-TestSandbox -Prefix 'dr-post-nz-gone'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            Set-DeleteOutcome -ExitCode 87 -StoreRemoves

            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 2 @(Get-EnumerationCall).Count 'an undocumented exit code skipped the store postcondition'
            Assert-True ($result.Detail -match 'deleted=1') ('a proven removal was not counted: {0}' -f $result.Detail)
            # The removal is real and its backup is committed, so nothing is lost - but a tool that
            # mutates the store while reporting outside its documented success set has not produced
            # a clean run, and an exit code is never again what decides that.
            Assert-Equal 'Failed' $result.Outcome ('an undocumented exit code that really removed a package was reported clean: {0}' -f $result.Detail)
            Assert-False $result.Succeeded $result.Detail
        }

        $left = @(Get-BackupDirectory -Root $backupRoot)
        Assert-Equal 1 $left.Count 'the only copy of a removed package was thrown away on its exit code'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $left[0].FullName -ChildPath $script:PendingName)) `
            'a committed backup still carries its pending marker'

        $manifest = [System.IO.File]::ReadAllText((Join-Path -Path $left[0].FullName -ChildPath $script:ManifestName)) | ConvertFrom-Json
        Assert-True (-not [string]::IsNullOrWhiteSpace([string]$manifest.DeletedUtc)) `
            'the backup of a proven removal was never stamped, so a later run may reclaim it'

        # Run 2 over the same persistent state: the package is gone, so there is no candidate and
        # nothing to refuse.
        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = (Remove-StubDriverFromXml -Xml $xml -DriverName 'oem1.inf') }
            $second = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Succeeded' $second.Outcome ('run 2 over a committed backup was not benign: {0}' -f $second.Detail)
            Assert-Equal 0 @(Get-DeleteCall).Count $second.Detail
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an undocumented non-zero exit whose package is proved still installed stays a benign skip' {
    $sandbox = New-TestSandbox -Prefix 'dr-post-nz-there'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        foreach ($pass in @('run 1', 'run 2')) {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                Set-DeleteOutcome -ExitCode 87

                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 2 @(Get-EnumerationCall).Count ('{0}: the refusal was believed without asking the store' -f $pass)
                Assert-Equal 'Succeeded' $result.Outcome ('{0}: pnputil declining a package in use is not a failure: {1}' -f $pass, $result.Detail)
                Assert-True ($result.Detail -match 'deleted=0 skipped=1') ('{0}: {1}' -f $pass, $result.Detail)
            }

            # Reclaimed only now that the non-deletion is proved - and reclaimed rather than kept,
            # because a protected directory here would refuse this package on every later run.
            Assert-Equal 0 @(Get-BackupDirectory -Root $backupRoot).Count `
                ('{0}: a copy of a provably still-installed package was left behind' -f $pass)
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an undocumented non-zero exit with an unreadable confirmation keeps the marker and the copy' {
    $sandbox = New-TestSandbox -Prefix 'dr-post-nz-unknown'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            Set-DeleteOutcome -ExitCode 87 -ConfirmUnreadable

            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'deleted=0 skipped=0 refused=0 incomplete=1') $result.Detail
        }

        $left = @(Get-BackupDirectory -Root $backupRoot)
        Assert-Equal 1 $left.Count 'the only possible copy of a maybe-removed package was thrown away'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $left[0].FullName -ChildPath $script:PendingName)) `
            'the marker came off although whether the package went is unknown'

        # NOT a benign steady state: the attempt stays unresolved and the directory stays protected
        # until a human settles it. It is reported as Incomplete rather than SecurityRefusal because
        # the reconciliation now owns every directory carrying a marker - it re-asks the store, and
        # an unresolved deletion is an incomplete run, not a security boundary that failed. The
        # refusal it used to produce came from Export-WacDriverBackup being handed the candidate,
        # which is exactly what the reconciliation withholds.
        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $second = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Incomplete' $second.Outcome $second.Detail
            Assert-True ($second.Detail -match 'pending=1') $second.Detail
            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although an earlier attempt on it is unresolved'
            Assert-Equal 0 @(Get-ExportCall).Count 'a package was exported again although an earlier attempt on it is unresolved'
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $left[0].FullName -ChildPath $script:PendingName)) `
            'the second run cleared the marker of an attempt that is still unresolved'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'ERROR_NO_MORE_ITEMS is confirmed against the store in all three of its answers' {
    # 259 is documented benign - pnputil removed nothing - and that used to be enough to clear the
    # marker on the tool's word alone. It is a report, not a postcondition.
    $case = @(
        @{ Name = 'the store agrees nothing went'; Removes = $false; Unreadable = $false
           Outcome = 'Succeeded'; Match = 'deleted=0 skipped=1'; Retained = 1; Marker = $false },
        @{ Name = 'the package is gone anyway'; Removes = $true; Unreadable = $false
           Outcome = 'Failed'; Match = 'deleted=1'; Retained = 1; Marker = $false },
        @{ Name = 'the store could not be read'; Removes = $false; Unreadable = $true
           Outcome = 'Incomplete'; Match = 'deleted=0 skipped=0 refused=0 incomplete=1'; Retained = 1; Marker = $true }
    )

    foreach ($entry in $case) {
        $sandbox = New-TestSandbox -Prefix 'dr-post-259'
        try {
            $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
            $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                Set-DeleteOutcome -ExitCode 259 -StoreRemoves:([bool]$entry['Removes']) -ConfirmUnreadable:([bool]$entry['Unreadable'])

                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 2 @(Get-EnumerationCall).Count ('{0}: 259 skipped the store postcondition' -f $entry['Name'])
                Assert-Equal $entry['Outcome'] $result.Outcome ('{0}: {1}' -f $entry['Name'], $result.Detail)
                Assert-True ($result.Detail -match $entry['Match']) ('{0}: {1}' -f $entry['Name'], $result.Detail)
            }

            $left = @(Get-BackupDirectory -Root $backupRoot)
            Assert-Equal $entry['Retained'] $left.Count ('{0}: the wrong number of exports was kept' -f $entry['Name'])
            Assert-Equal $entry['Marker'] (Test-Path -LiteralPath (Join-Path -Path $left[0].FullName -ChildPath $script:PendingName)) `
                ('{0}: the pending marker is in the wrong state' -f $entry['Name'])
        }
        finally {
            Remove-TestSandbox -Path $sandbox
        }
    }
}

Test-Case 'a 259 the store agrees with leaves the next run benign over the same persistent state' {
    # The permanent-refusal trap, checked twice over one backup root: the marker must not outlive an
    # attempt the store proved removed nothing, and the export it leaves must stay reclaimable.
    $sandbox = New-TestSandbox -Prefix 'dr-post-259twice'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        foreach ($pass in @('run 1', 'run 2')) {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                Set-DeleteOutcome -ExitCode 259

                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 'Succeeded' $result.Outcome ('{0}: {1}' -f $pass, $result.Detail)
                Assert-Equal 1 @(Get-ExportCall).Count ('{0} exported nothing' -f $pass)
                Assert-True ($result.Detail -match 'deleted=0 skipped=1') ('{0}: {1}' -f $pass, $result.Detail)
            }

            Assert-Equal 0 @(Get-ChildItem -LiteralPath $backupRoot -Recurse -Filter $script:PendingName -File).Count `
                ('{0} left a pending marker behind after an attempt the store proved removed nothing' -f $pass)
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# A reboot-required exit code is confirmed like every other started attempt
# ---------------------------------------------------------------------------------------------

function Get-BackupStamp {
    <#
    .SYNOPSIS
        The DeletedUtc a backup directory records, or '' when it carries none. Normalised, because
        ConvertFrom-Json leaves an ISO-8601 string alone on 5.1 and returns a [datetime] on 7.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $manifestPath = Join-Path -Path $Path -ChildPath $script:ManifestName
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { return '' }

    $manifest = [System.IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    if (@($manifest.PSObject.Properties.Name) -cnotcontains 'DeletedUtc') { return '' }

    $stamp = $manifest.DeletedUtc
    if ($stamp -is [datetime]) { $stamp = ([datetime]$stamp).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return [string]$stamp
}

Test-Case 'a reboot-required exit is confirmed against the store in all three of its answers' {
    # 3010 (ERROR_SUCCESS_REBOOT_REQUIRED) and 1641 (ERROR_SUCCESS_REBOOT_INITIATED) used to skip
    # the postcondition outright: state was initialised to Removed, the backup was committed and
    # deleted= advanced on the exit code alone, while the package could still be sitting in the
    # store. The code says a RESTART is needed. It does not say the store has already lost anything.
    $case = @(
        @{ Name = 'the store has already lost it'; Removes = $true; Unreadable = $false
           Outcome = 'Succeeded'; Match = 'deleted=1 skipped=0 refused=0 incomplete=0'; Marker = $false; Stamped = $true },
        @{ Name = 'the store still lists it'; Removes = $false; Unreadable = $false
           Outcome = 'Incomplete'; Match = 'deleted=0 skipped=0 refused=0 incomplete=1'; Marker = $true; Stamped = $false },
        @{ Name = 'the store could not be read'; Removes = $false; Unreadable = $true
           Outcome = 'Incomplete'; Match = 'deleted=0 skipped=0 refused=0 incomplete=1'; Marker = $true; Stamped = $false }
    )

    foreach ($code in @(1641, 3010)) {
        foreach ($entry in $case) {
            $label = '{0} and {1}' -f $code, $entry['Name']
            $sandbox = New-TestSandbox -Prefix 'dr-post-reboot'
            try {
                $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
                $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

                Invoke-WithStubbedTool -Body {
                    $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                    Set-DeleteOutcome -ExitCode $code -StoreRemoves:([bool]$entry['Removes']) -ConfirmUnreadable:([bool]$entry['Unreadable'])

                    $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                    $enumeration = @(Get-EnumerationCall)
                    Assert-Equal 2 $enumeration.Count ('{0}: the postcondition was skipped for a reboot-required exit' -f $label)

                    # Order is load-bearing: confirming before the deletion would prove nothing.
                    $delete = @(Get-DeleteCall)
                    Assert-Equal 1 $delete.Count ('{0}: the wrong number of deletions ran' -f $label)
                    Assert-True ($script:StubCall.IndexOf($delete[0]) -lt $script:StubCall.IndexOf($enumeration[1])) `
                        ('{0}: the confirming enumeration ran before the deletion' -f $label)

                    Assert-Equal $entry['Outcome'] $result.Outcome ('{0}: {1}' -f $label, $result.Detail)
                    Assert-True ($result.Detail -match $entry['Match']) ('{0}: {1}' -f $label, $result.Detail)
                    Assert-True ($result.Detail -match 'pending=0') ('{0}: {1}' -f $label, $result.Detail)

                    # Reported from what the tool asked for, not from what could be proved: a
                    # restart is what resolves the attempt either way.
                    Assert-True $result.RebootRequired ('{0}: the run did not report that a reboot is required' -f $label)
                }

                # The export is kept in every one of the three. Two of them are unresolved and it
                # may be the only copy of something that is already gone; the third is committed.
                $left = @(Get-BackupDirectory -Root $backupRoot)
                Assert-Equal 1 $left.Count ('{0}: the wrong number of exports was kept' -f $label)
                Assert-Equal $entry['Marker'] (Test-Path -LiteralPath (Join-Path -Path $left[0].FullName -ChildPath $script:PendingName)) `
                    ('{0}: the pending marker is in the wrong state' -f $label)
                Assert-Equal $entry['Stamped'] (-not [string]::IsNullOrWhiteSpace((Get-BackupStamp -Path $left[0].FullName))) `
                    ('{0}: the manifest stamp is in the wrong state' -f $label)
            }
            finally {
                Remove-TestSandbox -Path $sandbox
            }
        }
    }
}

Test-Case 'a reboot-pending package that is gone after the restart is committed by the next run' {
    # The cross-run half. Run 1 sees 3010 with the package still listed and can prove nothing, so it
    # keeps the export and the marker. After the restart the package is no longer enumerated at all,
    # so it is no longer a candidate - nothing in the per-candidate loop would ever reach its
    # directory again, and without the reconciliation the marker and the unstamped manifest would
    # outlive the deletion they record for the life of the machine.
    $sandbox = New-TestSandbox -Prefix 'dr-post-reboot-recover'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)
        $afterRestart = Remove-StubDriverFromXml -Xml $xml -DriverName 'oem1.inf'

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            Set-DeleteOutcome -ExitCode 3010

            $first = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot
            Assert-Equal 'Incomplete' $first.Outcome $first.Detail
            Assert-True ($first.Detail -match 'candidates=1 deleted=0') $first.Detail
        }

        $left = @(Get-BackupDirectory -Root $backupRoot)
        Assert-Equal 1 $left.Count 'run 1 threw away the export of a removal pending a restart'
        $exportPath = $left[0].FullName
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $exportPath -ChildPath $script:PendingName)) `
            'run 1 cleared the marker of an unproved removal'

        # Run 2 is the first run after the restart. The store has lost the package.
        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $afterRestart }

            $second = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Succeeded' $second.Outcome ('run 2 after the restart was not benign: {0}' -f $second.Detail)
            Assert-True ($second.Detail -match 'candidates=0 deleted=1') ('run 2 did not settle the pending deletion: {0}' -f $second.Detail)
            Assert-True ($second.Detail -match 'pending=1') $second.Detail
            Assert-False $second.RebootRequired 'run 2 still asked for a restart that has already happened'

            # Reconciled, not redone: one enumeration to read the store and one to confirm the
            # pending package, and no /export-driver or /delete-driver at all.
            Assert-Equal 2 @(Get-EnumerationCall).Count 'run 2 did not confirm the pending deletion against the store'
            Assert-Equal 0 @(Get-DeleteCall).Count 'run 2 asked pnputil to remove a package again'
            Assert-Equal 0 @(Get-ExportCall).Count 'run 2 exported a package again'
        }

        Assert-Equal 1 @(Get-BackupDirectory -Root $backupRoot).Count 'the committed backup was thrown away'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $exportPath -ChildPath $script:PendingName)) `
            'the marker survived a deletion the store has now proved'
        Assert-True (-not [string]::IsNullOrWhiteSpace((Get-BackupStamp -Path $exportPath))) `
            'the backup of a proved removal was never stamped, so a later run may reclaim it'

        # Run 3 over the same persistent state: nothing pending, nothing enumerated, nothing to do.
        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $afterRestart }

            $third = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Succeeded' $third.Outcome ('run 3 over a settled backup was not benign: {0}' -f $third.Detail)
            Assert-Equal 1 @(Get-EnumerationCall).Count 'run 3 re-confirmed a deletion that is already committed'
            Assert-Equal 0 @(Get-DeleteCall).Count $third.Detail
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a reboot-pending package that is still there after the restart stays a stable Incomplete' {
    # The other side of the same state, and the invariant that has shipped broken twice: a package
    # the restart did not remove must keep being reported, and it must never escalate into a
    # SecurityRefusal. Export-WacDriverBackup refuses a directory carrying an unresolved attempt, so
    # without the reconciliation withholding that candidate from the loop this run would refuse the
    # package it is describing - on every later run, forever.
    $sandbox = New-TestSandbox -Prefix 'dr-post-reboot-stuck'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            Set-DeleteOutcome -ExitCode 1641

            $first = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot
            Assert-Equal 'Incomplete' $first.Outcome $first.Detail
        }

        $exportPath = @(Get-BackupDirectory -Root $backupRoot)[0].FullName

        foreach ($pass in @('run 2', 'run 3')) {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }

                $later = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 'Incomplete' $later.Outcome ('{0}: an unresolved reboot-pending deletion changed outcome: {1}' -f $pass, $later.Detail)
                Assert-True ($later.Detail -match 'candidates=1 deleted=0 skipped=0 refused=0 incomplete=1') ('{0}: {1}' -f $pass, $later.Detail)
                Assert-True ($later.Detail -match 'pending=1') ('{0}: {1}' -f $pass, $later.Detail)

                Assert-Equal 2 @(Get-EnumerationCall).Count ('{0}: the pending deletion was not re-confirmed against the store' -f $pass)
                Assert-Equal 0 @(Get-DeleteCall).Count ('{0}: a package with an unresolved attempt was deleted again' -f $pass)
                Assert-Equal 0 @(Get-ExportCall).Count ('{0}: a package with an unresolved attempt was exported again' -f $pass)
            }

            Assert-Equal 1 @(Get-BackupDirectory -Root $backupRoot).Count ('{0}: the only possible copy was thrown away' -f $pass)
            Assert-True (Test-Path -LiteralPath (Join-Path -Path $exportPath -ChildPath $script:PendingName)) `
                ('{0}: the marker came off while the removal is still unproved' -f $pass)
            Assert-Equal '' (Get-BackupStamp -Path $exportPath) `
                ('{0}: a removal nobody has observed was stamped into the manifest' -f $pass)
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
