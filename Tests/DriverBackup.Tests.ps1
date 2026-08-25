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

Complete-TestRun
