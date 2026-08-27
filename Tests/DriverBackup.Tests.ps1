#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.DriverBackup (ledger T-6): backups that are uniquely
    identified, hashed, recorded in a manifest, verified, and never overwritten.

.DESCRIPTION
    pnputil.exe is never executed and no real driver is ever touched. The backup identity, the
    export hashing, the manifest and the residue guard are pure functions over the fixtures in
    _DriverFixtures.ps1 and files written into a disposable sandbox. What the pruning step does with
    them end to end is covered by Drivers.Tests.ps1.
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

# The pending-deletion marker and the commit that clears it are internal to the module on purpose -
# nothing outside the pruning step may stamp a backup - so these reach them through the module's own
# session state rather than through the exported surface.
$script:PendingName = 'wac-driver-delete.pending'

function Set-BackupDeletePending {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$DriverName)
    return (& $script:DriversModule { param($p, $d) Set-WacDriverBackupDeletePending -Path $p -DriverName $d } $Path $DriverName)
}

function Test-BackupDeletePending {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (& $script:DriversModule { param($p) Test-WacDriverBackupDeletePending -Path $p } $Path)
}

function Clear-BackupDeletePending {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (& $script:DriversModule { param($p) Clear-WacDriverBackupDeletePending -Path $p } $Path)
}

function Complete-BackupUnderTest {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Manifest)
    return (& $script:DriversModule { param($p, $m) Complete-WacDriverBackup -Path $p -Manifest $m } $Path $Manifest)
}

# ---------------------------------------------------------------------------------------------
# Backup identity: never the recyclable oem number
# ---------------------------------------------------------------------------------------------

Test-Case 'the backup identity ignores the recyclable oem number and separates different packages' {
    $driver = Get-ParsedDriver -Row @(
        (New-PnpUtilRow -DriverName 'oem5.inf' -OriginalName 'acme.inf' -DriverVersion '01/01/2020 1.0.0.0'),
        (New-PnpUtilRow -DriverName 'oem9.inf' -OriginalName 'acme.inf' -DriverVersion '01/01/2020 1.0.0.0'),
        (New-PnpUtilRow -DriverName 'oem5.inf' -OriginalName 'widget.inf' -DriverVersion '01/01/2020 1.0.0.0'),
        (New-PnpUtilRow -DriverName 'oem5.inf' -OriginalName 'acme.inf' -DriverVersion '01/01/2020 2.0.0.0')
    )

    $same = Get-WacDriverBackupIdentity -Driver $driver[0]
    $renumbered = Get-WacDriverBackupIdentity -Driver $driver[1]
    $otherPackage = Get-WacDriverBackupIdentity -Driver $driver[2]
    $otherVersion = Get-WacDriverBackupIdentity -Driver $driver[3]

    Assert-Equal $same.Name $renumbered.Name 'the same package under a different oem number changed identity'
    Assert-False ($same.Name -ceq $otherPackage.Name) 'a different package reusing oem5.inf collided with it'
    Assert-False ($same.Name -ceq $otherVersion.Name) 'a different version of the same package shared its identity'

    Assert-Equal 64 $same.Hash.Length 'the identity hash is not a full SHA-256'
    Assert-True ($same.Hash -cmatch '^[0-9a-f]{64}$') $same.Hash
    Assert-True ($same.Name -clike ('*{0}*' -f $same.Hash.Substring(0, 16))) $same.Name
    Assert-True ($same.Name -clike 'acme_1.0.0.0_*') $same.Name
    Assert-False ($same.Name -match '(?i)oem\d') ('the recyclable oem number reached the backup identity: {0}' -f $same.Name)
}

Test-Case 'a hostile original name cannot escape the backup root' {
    $driver = Get-ParsedDriver -Row @((New-PnpUtilRow -DriverName 'oem1.inf' -OriginalName '..\..\..\Windows\System32\evil.inf'))
    $identity = Get-WacDriverBackupIdentity -Driver $driver[0]

    Assert-False ($identity.Name -match '[\\/:]') ('the identity is not a single path segment: {0}' -f $identity.Name)
    Assert-False ($identity.Name -match '\.\.') $identity.Name

    $sandbox = New-TestSandbox -Prefix 'dr-escape'
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        [void](New-Item -Path $root -ItemType Directory -Force)
        $resolved = Get-WacNormalizedPath -Path (Join-Path -Path $root -ChildPath $identity.Name)
        Assert-True (Test-WacIsWithinRoot -ChildPath $resolved -RootPath $root) $resolved
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Export hashing, manifest and verification
# ---------------------------------------------------------------------------------------------

Test-Case 'an export is hashed file by file, the manifest is excluded, and an unreadable path is not an empty one' {
    $sandbox = New-TestSandbox -Prefix 'dr-hash'
    try {
        $export = Join-Path -Path $sandbox -ChildPath 'export'
        [void](New-Item -Path (Join-Path -Path $export -ChildPath 'sub') -ItemType Directory -Force)
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'acme.inf') -Value 'abc' -Encoding ASCII -NoNewline
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'sub\acme.sys') -Value 'abcd' -Encoding ASCII -NoNewline
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath $script:ManifestName) -Value '{}' -Encoding ASCII -NoNewline

        $hashed = Get-WacDriverBackupFileHash -Path $export

        Assert-True $hashed.Ok $hashed.Reason
        $file = @($hashed.File)
        Assert-Equal 2 $file.Count (($file | ForEach-Object { $_.Path }) -join ',')
        Assert-Equal 'acme.inf' $file[0].Path
        Assert-Equal 'sub\acme.sys' $file[1].Path
        Assert-Equal 3 $file[0].Bytes
        # SHA-256 of the three ASCII bytes 'abc' - a fixed, host-independent constant.
        Assert-Equal 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' $file[0].Sha256
        Assert-False ($file[0].Sha256 -ceq $file[1].Sha256)

        $missing = Get-WacDriverBackupFileHash -Path (Join-Path -Path $sandbox -ChildPath 'nothing-here')
        Assert-False $missing.Ok 'a directory that does not exist was reported as readable'
        Assert-Equal 0 (@($missing.File)).Count
        Assert-True ($missing.Reason.Length -gt 0)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the verifier catches a changed byte, a missing file and an added file' {
    $sandbox = New-TestSandbox -Prefix 'dr-verify'
    try {
        $export = Join-Path -Path $sandbox -ChildPath 'export'
        [void](New-Item -Path $export -ItemType Directory -Force)
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'acme.inf') -Value 'abc' -Encoding ASCII -NoNewline
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'acme.sys') -Value 'abcd' -Encoding ASCII -NoNewline

        $driver = (Get-ParsedDriver -Row @((New-PnpUtilRow -DriverName 'oem1.inf')))[0]
        $identity = Get-WacDriverBackupIdentity -Driver $driver
        $manifest = New-WacDriverBackupManifest -Driver $driver -Identity $identity -File (Get-WacDriverBackupFileHash -Path $export).File

        Assert-True (Test-WacDriverBackupIntact -Path $export -Manifest $manifest).Intact 'an unchanged export failed verification'

        # Same length, different content: only the hash can see this one.
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'acme.inf') -Value 'abd' -Encoding ASCII -NoNewline
        $changed = Test-WacDriverBackupIntact -Path $export -Manifest $manifest
        Assert-False $changed.Intact 'a changed byte passed verification'
        Assert-True ($changed.Reason -match '(?i)SHA-256') $changed.Reason

        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'acme.inf') -Value 'abc' -Encoding ASCII -NoNewline
        Remove-Item -LiteralPath (Join-Path -Path $export -ChildPath 'acme.sys') -Force
        Assert-False (Test-WacDriverBackupIntact -Path $export -Manifest $manifest).Intact 'a missing file passed verification'

        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'acme.sys') -Value 'abcd' -Encoding ASCII -NoNewline
        Set-Content -LiteralPath (Join-Path -Path $export -ChildPath 'extra.dll') -Value 'x' -Encoding ASCII -NoNewline
        Assert-False (Test-WacDriverBackupIntact -Path $export -Manifest $manifest).Intact 'an added file passed verification'

        Remove-Item -LiteralPath (Join-Path -Path $export -ChildPath 'extra.dll') -Force
        Assert-True (Test-WacDriverBackupIntact -Path $export -Manifest $manifest).Intact 'the restored export failed verification'

        $gone = Test-WacDriverBackupIntact -Path (Join-Path -Path $sandbox -ChildPath 'gone') -Manifest $manifest
        Assert-False $gone.Intact 'a vanished export directory passed verification'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the manifest records the package, the identity hash and the exact deletion evidence' {
    $driver = @(Get-WacSupersededDriver -Driver (Get-ParsedDriver -Row (New-SupersededPair)))[0]
    $identity = Get-WacDriverBackupIdentity -Driver $driver
    $file = @([PSCustomObject]@{ Path = 'acme.inf'; Bytes = 3L; Sha256 = 'ba7816bf' })

    $manifest = New-WacDriverBackupManifest -Driver $driver -Identity $identity -File $file -EnumeratedPackage 42

    Assert-Equal 'oem1.inf' $manifest.DriverName 'the manifest cannot map the backup back to the package it came from'
    Assert-Equal 'acme.inf' $manifest.OriginalName
    Assert-Equal '1.0.0.0' $manifest.Version
    Assert-Equal $identity.Hash $manifest.IdentityHash
    Assert-Equal $identity.Name $manifest.IdentityName
    Assert-Equal 0 $manifest.Evidence.DeviceCount 'the manifest does not record the device evidence'
    Assert-Equal 'oem2.inf' $manifest.Evidence.SupersededByName
    Assert-Equal '2.0.0.0' $manifest.Evidence.SupersededByVersion
    Assert-Equal 42 $manifest.Evidence.EnumeratedPackage
    Assert-True ($manifest.Evidence.Command -match '/enum-drivers /devices /format xml') $manifest.Evidence.Command
    Assert-Equal 1 $manifest.FileCount
    Assert-Equal 3 $manifest.TotalBytes
    Assert-Equal 'ba7816bf' $manifest.File[0].Sha256

    # It has to survive the round trip that actually gets written to disk.
    $rehydrated = ($manifest | ConvertTo-Json -Depth 6) | ConvertFrom-Json
    Assert-Equal 'oem1.inf' $rehydrated.DriverName
    Assert-Equal $identity.Hash $rehydrated.IdentityHash
    Assert-Equal 'oem2.inf' $rehydrated.Evidence.SupersededByName
}

Test-Case 'residue is any export directory whose manifest does not record this package being deleted' {
    # The classifier the collision guard rests on. Everything this tool leaves behind before a
    # package is really gone is reclaimable; the record of the deletion is what makes a directory
    # untouchable, and a manifest belonging to some other package is neither.
    $driver = @(Get-WacSupersededDriver -Driver (Get-ParsedDriver -Row (New-SupersededPair)))[0]
    $identity = Get-WacDriverBackupIdentity -Driver $driver
    $manifest = New-WacDriverBackupManifest -Driver $driver -Identity $identity `
        -File @([PSCustomObject]@{ Path = 'acme.inf'; Bytes = 3L; Sha256 = ('b' * 64) })

    Assert-Equal '' $manifest.DeletedUtc 'a fresh manifest already claims its package was deleted'

    $sandbox = New-TestSandbox -Prefix 'dr-residue'
    try {
        $directory = Join-Path -Path $sandbox -ChildPath 'export'
        [void](New-Item -Path $directory -ItemType Directory -Force)
        $manifestPath = Join-Path -Path $directory -ChildPath $script:ManifestName

        Assert-True (Test-WacDriverBackupIsResidue -Path $directory -Identity $identity).IsResidue `
            'a directory with no manifest at all was not treated as an export that never finished'

        Set-Content -LiteralPath $manifestPath -Value 'not json {' -Encoding ASCII
        Assert-True (Test-WacDriverBackupIsResidue -Path $directory -Identity $identity).IsResidue `
            'a half-written manifest was not treated as an export that never finished'

        Set-Content -LiteralPath $manifestPath -Value ($manifest | ConvertTo-Json -Depth 6) -Encoding ASCII
        Assert-True (Test-WacDriverBackupIsResidue -Path $directory -Identity $identity).IsResidue `
            'a manifest recording no deletion was not treated as an export whose package is still installed'

        $manifest.DeletedUtc = '2026-08-24T09:00:00Z'
        Set-Content -LiteralPath $manifestPath -Value ($manifest | ConvertTo-Json -Depth 6) -Encoding ASCII
        $completed = Test-WacDriverBackupIsResidue -Path $directory -Identity $identity
        Assert-False $completed.IsResidue 'the only copy of a deleted package was classified as residue'
        Assert-True ($completed.Reason -match '2026-08-24T09:00:00Z') $completed.Reason

        # A manifest for some other package, in a directory named after this one, is not something
        # to explain away by deleting it.
        $manifest.IdentityHash = 'f' * 64
        Set-Content -LiteralPath $manifestPath -Value ($manifest | ConvertTo-Json -Depth 6) -Encoding ASCII
        Assert-False (Test-WacDriverBackupIsResidue -Path $directory -Identity $identity).IsResidue `
            'a manifest belonging to a different package was classified as residue'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# The deletion commit: one transaction, or nothing
# ---------------------------------------------------------------------------------------------

Test-Case 'an uncommitted deletion attempt is protected however unreadable the manifest is' {
    # The rule the old classifier got wrong. Age and a missing timestamp cannot tell an export that
    # died before its deletion from one that died after it, and the second is the only copy of a
    # package that is gone. The recorded attempt is what tells them apart, so every manifest state
    # below is reclaimable without one and untouchable with one.
    $driver = @(Get-WacSupersededDriver -Driver (Get-ParsedDriver -Row (New-SupersededPair)))[0]
    $identity = Get-WacDriverBackupIdentity -Driver $driver
    $manifest = New-WacDriverBackupManifest -Driver $driver -Identity $identity `
        -File @([PSCustomObject]@{ Path = 'acme.inf'; Bytes = 3L; Sha256 = ('b' * 64) })

    $sandbox = New-TestSandbox -Prefix 'dr-pending'
    try {
        $directory = Join-Path -Path $sandbox -ChildPath 'export'
        [void](New-Item -Path $directory -ItemType Directory -Force)
        $manifestPath = Join-Path -Path $directory -ChildPath $script:ManifestName

        $state = @(
            @{ Name = 'no manifest at all';               Write = $null },
            @{ Name = 'a half-written manifest';          Write = 'not json {' },
            @{ Name = 'a manifest with no deletion stamp'; Write = ($manifest | ConvertTo-Json -Depth 6) }
        )

        foreach ($entry in $state) {
            Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue
            if ($null -ne $entry['Write']) { Set-Content -LiteralPath $manifestPath -Value $entry['Write'] -Encoding ASCII }

            Assert-True (Test-WacDriverBackupIsResidue -Path $directory -Identity $identity).IsResidue `
                ('{0} with no deletion attempt behind it stopped being reclaimable' -f $entry['Name'])

            Assert-True (Set-BackupDeletePending -Path $directory -DriverName 'oem1.inf') 'the marker could not be written'
            Assert-True (Test-BackupDeletePending -Path $directory) 'the marker was written but does not read back'

            $marked = Test-WacDriverBackupIsResidue -Path $directory -Identity $identity
            Assert-False $marked.IsResidue ('{0} behind a recorded deletion attempt was reclaimed' -f $entry['Name'])
            Assert-True ($marked.Reason -match 'uncommitted deletion attempt') $marked.Reason

            Assert-True (Clear-BackupDeletePending -Path $directory) 'the marker could not be cleared'
            Assert-False (Test-BackupDeletePending -Path $directory) 'the cleared marker is still there'
        }

        # The marker must not swallow the other refusal: a manifest for a DIFFERENT package is
        # refused for its own reason, and losing that reason would hide a real identity collision.
        $manifest.IdentityHash = 'f' * 64
        Set-Content -LiteralPath $manifestPath -Value ($manifest | ConvertTo-Json -Depth 6) -Encoding ASCII
        $foreign = Test-WacDriverBackupIsResidue -Path $directory -Identity $identity
        Assert-False $foreign.IsResidue 'a manifest belonging to a different package was reclaimed'
        Assert-True ($foreign.Reason -match 'different package identity') $foreign.Reason
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the commit is atomic, and the marker comes off only once the stamp is on disk' {
    $sandbox = New-TestSandbox -Prefix 'dr-commit'
    try {
        $directory = Join-Path -Path $sandbox -ChildPath 'export'
        [void](New-Item -Path $directory -ItemType Directory -Force)
        Set-Content -LiteralPath (Join-Path -Path $directory -ChildPath 'acme.inf') -Value 'abc' -Encoding ASCII -NoNewline

        $driver = @(Get-WacSupersededDriver -Driver (Get-ParsedDriver -Row (New-SupersededPair)))[0]
        $identity = Get-WacDriverBackupIdentity -Driver $driver
        $manifest = New-WacDriverBackupManifest -Driver $driver -Identity $identity -File (Get-WacDriverBackupFileHash -Path $directory).File
        $manifestPath = Join-Path -Path $directory -ChildPath $script:ManifestName
        Set-Content -LiteralPath $manifestPath -Value ($manifest | ConvertTo-Json -Depth 6) -Encoding ASCII

        Assert-True (Set-BackupDeletePending -Path $directory -DriverName 'oem1.inf') 'the marker could not be written'

        # A directory where the staged file has to go. WriteAllText cannot write over a directory,
        # so this is the commit failing on real I/O rather than on a stubbed return value.
        $staging = $manifestPath + '.commit'
        [void](New-Item -Path $staging -ItemType Directory -Force)

        Assert-False (Complete-BackupUnderTest -Path $directory -Manifest $manifest) 'a commit that could not write reported success'
        Assert-True (Test-BackupDeletePending -Path $directory) 'a failed commit cleared the marker that protects the export'

        $failedState = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        Assert-Equal '' ([string]$failedState.DeletedUtc) 'a failed commit stamped the manifest anyway'
        Assert-Equal $identity.Hash ([string]$failedState.IdentityHash) 'a failed commit left a torn manifest behind'
        Assert-False (Test-WacDriverBackupIsResidue -Path $directory -Identity $identity).IsResidue `
            'the export a failed commit left behind is reclaimable'

        # The retry, once whatever blocked the write is gone.
        Remove-Item -LiteralPath $staging -Recurse -Force
        Assert-True (Complete-BackupUnderTest -Path $directory -Manifest $manifest) 'the retry could not commit'
        Assert-False (Test-BackupDeletePending -Path $directory) 'the marker outlived a durable commit'
        Assert-False (Test-Path -LiteralPath $staging) 'the commit left its staging file behind'

        $stamped = Get-Content -LiteralPath $manifestPath -Raw
        Assert-True ($stamped -cmatch '"DeletedUtc":\s+"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"') ('the commit is not on disk: {0}' -f $stamped)
        Assert-True ($stamped -cmatch '"CreatedUtc":\s+"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"') ('the commit rewrote CreatedUtc: {0}' -f $stamped)
        Assert-Equal 'abc' (Get-Content -LiteralPath (Join-Path -Path $directory -ChildPath 'acme.inf') -Raw) 'the commit touched the export itself'
        Assert-False (Test-WacDriverBackupIsResidue -Path $directory -Identity $identity).IsResidue 'a committed backup was classified as residue'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a package removed but not committed fails the run, and the next run refuses its export' {
    # THE WHOLE POINT OF THE COMMIT. pnputil said the package is gone and the stamp did not become
    # durable, so this export is now the only copy of something that is not in the store. The run
    # must not count a deletion, and no later run may reclaim the directory as export residue.
    $sandbox = New-TestSandbox -Prefix 'dr-commitfail'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        $original = Get-ModuleFunctionBody -Module $script:DriversModule -Name 'Complete-WacDriverBackup'
        Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Complete-WacDriverBackup' -Body {
            param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Manifest)
            # The signature has to match the real one; the values themselves are unused here.
            $null = $Path, $Manifest
            return $false
        }

        try {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 1 @(Get-DeleteCall).Count 'the package was never deleted'
                Assert-Equal 'Failed' $result.Outcome $result.Detail
                Assert-True $result.Failed $result.Detail
                Assert-False $result.Succeeded
                Assert-True ($result.Detail -match 'deleted=0 .*failed=1') ('a package that is gone was counted as deleted: {0}' -f $result.Detail)
            }
        }
        finally {
            Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Complete-WacDriverBackup' -Body $original
        }

        $directory = @(Get-ChildItem -LiteralPath $backupRoot -Directory)
        Assert-Equal 1 $directory.Count 'the only copy of a removed package was thrown away'
        Assert-True (Test-BackupDeletePending -Path $directory[0].FullName) `
            'the export of a package that may be gone carries no pending-deletion marker'

        # Completion metadata that did not survive the crash it was written in. Without the marker
        # this is indistinguishable from an export that never finished, which is what made it
        # reclaimable - and reclaiming it here would destroy the only copy of a deleted package.
        Set-Content -LiteralPath (Join-Path -Path $directory[0].FullName -ChildPath $script:ManifestName) `
            -Value '{"Schema":2,"DeletedU' -Encoding ASCII -NoNewline

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
            Assert-Equal 0 @(Get-ExportCall).Count 'the only copy of a removed package was exported over'
            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its backup was ambiguous'
            Assert-True ($result.Detail -match 'refused=1') $result.Detail
        }

        Assert-Equal 'inf-content' (Get-Content -LiteralPath (Join-Path -Path $directory[0].FullName -ChildPath 'exported.inf') -Raw) `
            'the export that may be the only copy left was modified'

        # And the refusal is resolvable rather than permanent: once the attempt is settled - here by
        # an operator who recovered the package and cleared the record - the same corrupt manifest
        # is ordinary residue again and the next run is benign.
        Assert-True (Clear-BackupDeletePending -Path $directory[0].FullName) 'the marker could not be cleared'

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Succeeded' $result.Outcome ('a settled attempt still refused: {0}' -f $result.Detail)
            Assert-Equal 1 @(Get-DeleteCall).Count $result.Detail
            Assert-True ($result.Detail -match 'deleted=1') $result.Detail
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
