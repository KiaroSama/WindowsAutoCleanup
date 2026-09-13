#Requires -Version 5.1
<#
.SYNOPSIS
    What the driver step is allowed to conclude from an external tool it could not prove had
    finished, and what it must leave behind for the run after it (ledger WAC-05R).

.DESCRIPTION
    An exit code is what the ROOT process believes about itself. It says nothing about a child the
    tool started, and nothing about output that never arrived. The per-candidate deletion loop has
    asked that question for a round now; three other places that act on the same tool did not, and
    each of them turns an unproven answer into a mutation:

      the EXPORT       hashed the directory while something might still be writing into it, and
                       then - on any outcome short of Succeeded - deleted that directory in a
                       finally clause. Deleting a tree a live process still has open is the worse
                       half: it is a mutation made on the strength of a state nobody established.
      the ENUMERATION  that decides WHICH packages the loop may touch. Truncated output still parses,
                       and a package whose device rows never arrived reads as installed on nothing -
                       which is exactly what makes a package a deletion candidate.
      the CONFIRMATION that decides whether a package really went. Absence from a truncated
                       enumeration is indistinguishable from absence from the store, and only one of
                       those may commit a backup and clear the protection over an export.

    And one thing no run can settle by asking again. A pending marker means "the result is not known
    YET", which a later run resolves against the driver store. An attempt whose tool could not be
    proven finished is not that: every reading a later run takes is taken beside a writer that may
    never have stopped. So it is recorded durably and held for a person, rather than settled by a
    machine that cannot see the thing it would need to see.
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

# A TEMP sandbox is genuinely user-writable, so the ancestor walk refuses it on every runner - for a
# reason that has nothing to do with a tool's lifetime. The walk itself is measured against real
# injected roots in DriverBackup.Tests.ps1 and DriverBackupHardening.Tests.ps1.
Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacStatePathIsTrusted' -Body {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path,
        [switch]$RequireDirectory
    )

    $null = $RequireDirectory
    # The full shape, not just the verdict: callers read Writers to name a principal in a refusal,
    # and under Set-StrictMode 2.0 a property a stub leaves off THROWS rather than reading as empty.
    return ([PSCustomObject]@{
        Path = $Path; IsTrusted = $true; Reason = 'sandbox walk accepted for this suite'
        Checked = @(); Failures = @(); Writers = @()
    })
}

$script:AbandonedName = 'wac-driver-delete.abandoned'
$script:PendingName = 'wac-driver-delete.pending'

function Get-LifetimeDriver {
    return @(Get-ParsedDriver -Row @((New-PnpUtilRow -DriverName 'oem1.inf' -DeviceStatus @())))[0]
}

function Get-LifetimeDirectory {
    <#
    .SYNOPSIS
        Where the export for this driver lands, without running one.
    #>
    param([Parameter(Mandatory = $true)][string]$BackupRoot, [Parameter(Mandatory = $true)]$Driver)

    return (Join-Path -Path $BackupRoot -ChildPath (Get-WacDriverBackupIdentity -Driver $Driver).Name)
}

function Set-LifetimeAbandoned {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Reason)

    return (& $script:DriversModule { param($p, $r) Set-WacDriverBackupAbandoned -Path $p -Reason $r } $Path $Reason)
}

function Resolve-LifetimePending {
    param([Parameter(Mandatory = $true)][string]$BackupRoot)

    return (& $script:DriversModule { param($tool, $root) Resolve-WacDriverBackupPending -PnpUtil $tool -BackupRoot $root } `
        $script:PnpUtilPath $BackupRoot)
}

Test-Case 'An export nobody could prove finished keeps its directory, records why, and stops the run' {
    # The directory is the only evidence on the machine that the export was attempted at all, and it
    # may still be growing. The finally clause used to take it on every outcome short of Succeeded,
    # which reads "not a usable backup" as "safe to delete" - two different claims, and only the
    # first of them is known here.
    $sandbox = New-TestSandbox -Prefix 'dr-lifetime-export'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        [void][System.IO.Directory]::CreateDirectory($backupRoot)
        $driver = Get-LifetimeDriver
        $directory = Get-LifetimeDirectory -BackupRoot $backupRoot -Driver $driver

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/export-driver'] = @{ ExitCode = 0; TerminationProven = $false }

            $result = Export-WacDriverBackup -PnpUtil $script:PnpUtilPath -Driver $driver -BackupRoot $backupRoot

            Assert-Equal 'Incomplete' ([string]$result.Outcome) ([string]$result.Reason)
            Assert-True ([string]$result.Reason).Contains('could not be proven finished') `
                ('the refusal did not say what was unproven: {0}' -f [string]$result.Reason)

            Assert-True (Test-Path -LiteralPath $directory -PathType Container) `
                'the export directory was deleted although something may still have been writing into it'
            Assert-True (Test-Path -LiteralPath (Join-Path -Path $directory -ChildPath $script:AbandonedName) -PathType Leaf) `
                'nothing on disk records that this directory holds an attempt nobody could finish, so a later run would reclaim it'

            Assert-False (Test-WacMutationAllowed) `
                'the run carried on after a tool it could not prove had stopped'
        }
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'A directory holding an abandoned attempt is refused, never reclaimed' {
    # Reclaiming is a RECURSIVE DELETE decided by what the directory says about itself. The residue
    # rule already refuses an uncommitted deletion; an abandoned one is the stronger case, because
    # what is unknown is not only whether a package went but whether anything still has the tree
    # open.
    $sandbox = New-TestSandbox -Prefix 'dr-lifetime-residue'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $driver = Get-LifetimeDriver
        $directory = Get-LifetimeDirectory -BackupRoot $backupRoot -Driver $driver
        [void][System.IO.Directory]::CreateDirectory($directory)
        [System.IO.File]::WriteAllText((Join-Path -Path $directory -ChildPath 'partial.inf'), 'half an export',
            (New-Object System.Text.UTF8Encoding($false)))

        Assert-True (Set-LifetimeAbandoned -Path $directory -Reason 'planted by the fixture') `
            'the fixture could not record an abandoned attempt'

        Invoke-WithStubbedTool -Body {
            $result = Export-WacDriverBackup -PnpUtil $script:PnpUtilPath -Driver $driver -BackupRoot $backupRoot

            Assert-Equal 'SecurityRefusal' ([string]$result.Outcome) ([string]$result.Reason)
            Assert-True ([string]$result.Reason).Contains('abandoned') `
                ('the refusal did not name the abandoned attempt: {0}' -f [string]$result.Reason)
            Assert-Equal 0 @(Get-ExportCall).Count 'a package was exported over a directory nobody had finished with'
            Assert-True (Test-Path -LiteralPath (Join-Path -Path $directory -ChildPath 'partial.inf') -PathType Leaf) `
                'the contents of an abandoned attempt were reclaimed'
        }
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'A confirming enumeration that cannot be proven finished answers Unknown, never Removed' {
    # Removed is the single answer that commits a backup and clears the protection over an export.
    # A truncated enumeration is missing the package for a reason that has nothing to do with the
    # driver store, and the tri-state exists precisely so that reason cannot be read as removal.
    $sandbox = New-TestSandbox -Prefix 'dr-lifetime-confirm'
    try {
        Invoke-WithStubbedTool -Body {
            # The package really is absent from this output, so ONLY the lifetime fact separates
            # this from a genuine Removed.
            $script:StubResult['/enum-drivers'] = @{
                ExitCode = 0
                Out = (New-PnpUtilDriverXml -Row @((New-PnpUtilRow -DriverName 'oem9.inf' -DeviceStatus @())))
                OutputComplete = $false
            }

            $confirm = Test-WacDriverPackageRemoved -PnpUtil $script:PnpUtilPath -DriverName 'oem1.inf' `
                -TimeoutMs 5000 -Component 'DriverPrune'

            Assert-Equal 'Unknown' ([string]$confirm.State) `
                ('a half-read enumeration was accepted as proof that a package is gone: {0}' -f [string]$confirm.Reason)
            Assert-True ([string]$confirm.Reason).Contains('could not be proven finished') `
                ('the answer did not say what was unproven: {0}' -f [string]$confirm.Reason)
            Assert-False (Test-WacMutationAllowed) `
                'the run stayed free to delete beside a pnputil it could not prove had stopped'
        }
        $null = $sandbox
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'A store enumeration that cannot be proven finished nominates nothing for deletion' {
    # The candidate list is only as good as the run that produced it. This is the more dangerous of
    # the two enumerations: a package whose device rows never arrived looks like a package installed
    # on nothing, which is the whole definition of a prune candidate.
    $sandbox = New-TestSandbox -Prefix 'dr-lifetime-enum'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'

        Invoke-WithStubbedTool -StubToolPath -Body {
            $script:StubResult['/enum-drivers'] = @{
                ExitCode = 0
                Out = (New-PnpUtilDriverXml -Row (New-SupersededPair))
                OwnedTreeState = 'Alive'
            }

            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot `
                -LegacyBackupRoot (Join-Path -Path $sandbox -ChildPath 'no-legacy')

            # The two claims that matter come FIRST. A step that reaches a package at all has already
            # done the damage, and an aggregate outcome or a wording check failing ahead of them
            # would report the least informative half of that.
            Assert-Equal 0 @(Get-ExportCall).Count 'a package was exported from a store that was only half read'
            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted on the strength of a half-read enumeration'
            Assert-Equal 'Incomplete' ([string]$result.Outcome) ([string]$result.Detail)
            Assert-True ([string]$result.Detail).Contains('still alive') `
                ('the step did not say why the list could not be used: {0}' -f [string]$result.Detail)
        }
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'A deletion one run abandoned is HELD by the next, not settled against the store' {
    # The two-run story, which is the whole point of recording it on disk. Run one asks pnputil to
    # remove a package and cannot prove the tool finished. Run two finds the package gone from the
    # store - the answer that ordinarily commits the backup, clears the marker and lets the run carry
    # on deleting - and must not act on it, because that reading was taken beside a writer nobody
    # established had stopped.
    $sandbox = New-TestSandbox -Prefix 'dr-lifetime-hold'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $pair = New-SupersededPair

        # RUN ONE: the delete is asked for, and its tool cannot be proven stopped.
        Invoke-WithStubbedTool -StubToolPath -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row $pair) }
            $script:StubResult['/export-driver'] = @{ ExitCode = 0 }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 0; TerminationProven = $false }

            $first = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot `
                -LegacyBackupRoot (Join-Path -Path $sandbox -ChildPath 'no-legacy')
            Assert-Equal 'Incomplete' ([string]$first.Outcome) ([string]$first.Detail)
        }

        $held = @(Get-ChildItem -LiteralPath $backupRoot -Directory)
        Assert-Equal 1 $held.Count 'the abandoned attempt did not leave exactly one directory behind'
        $directory = $held[0].FullName
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $directory -ChildPath $script:PendingName) -PathType Leaf) `
            'the pending marker did not survive an attempt nobody could finish'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $directory -ChildPath $script:AbandonedName) -PathType Leaf) `
            'nothing on disk tells the next run that this attempt was abandoned rather than merely unresolved'

        # RUN TWO: the store now says the package is gone. That must change nothing.
        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{
                ExitCode = 0
                Out = (New-PnpUtilDriverXml -Row @((New-PnpUtilRow -DriverName 'oem9.inf' -DeviceStatus @())))
            }

            $second = Resolve-LifetimePending -BackupRoot $backupRoot

            Assert-Equal 1 ([int]$second.Incomplete) 'an abandoned attempt was not reported as unresolved'
            Assert-Equal 0 ([int]$second.Deleted) 'an abandoned attempt was settled against a store reading it cannot trust'
            Assert-Equal 'Incomplete' ([string]$second.Outcome) 'holding an abandoned attempt did not carry into the step outcome'
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $directory -ChildPath $script:PendingName) -PathType Leaf) `
            'the protection over an abandoned attempt was cleared by a later run'
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Complete-TestRun
