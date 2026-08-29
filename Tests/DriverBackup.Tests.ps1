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


# ---------------------------------------------------------------------------------------------
# Backup-root trust: the walk the sibling Logs directory has always had
# ---------------------------------------------------------------------------------------------

function Invoke-WithRealPathTrust {
    <#
    .SYNOPSIS
        Runs a body with the REAL machine-trust walk restored inside the module, then puts the
        suite's stub back.
    .DESCRIPTION
        Every other case here forces that walk to yes, because a TEMP sandbox is genuinely
        user-writable and would otherwise refuse before the behaviour under test was reached. These
        cases are about the walk itself, so they get the real one - and every root they hand it is
        injected to be untrusted for a reason that holds on a developer shell and on an elevated
        runner alike.
    #>
    param([Parameter(Mandatory = $true)][scriptblock]$Body)

    $stub = Get-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacStatePathIsTrusted'
    Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacStatePathIsTrusted' -Body $script:RealStatePathTrust
    try { & $Body }
    finally { Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacStatePathIsTrusted' -Body $stub }
}

function Grant-TestEveryoneWrite {
    <#
    .SYNOPSIS
        Adds an explicit Allow(Everyone, Modify) ACE so a sandbox path is untrusted on ANY runner.
    .DESCRIPTION
        A sandbox under TEMP is already user-writable on a developer machine, but on an elevated
        runner its owner is an administrator and its writers may all be administrative, which the
        walk correctly accepts. Everyone (S-1-1-0) is on the module's never-administrative list and
        Modify carries DELETE and DELETE_CHILD, which is exactly the grant that lets a standard user
        rename the whole directory aside. Only ever called on a path this suite created.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')),
        [System.Security.AccessControl.FileSystemRights]::Modify,
        [System.Security.AccessControl.AccessControlType]::Allow)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-TestUnusedDriveRoot {
    <#
    .SYNOPSIS
        A rooted path on a drive letter this machine has no volume for, or '' when there is none.
    #>
    $used = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
    foreach ($letter in @([char[]](78..90))) {
        if ($used -notcontains ([string]$letter)) { return ('{0}:\WindowsAutoCleanup\DriverBackup' -f $letter) }
    }
    return ''
}

Test-Case 'a backup root a standard user can replace is refused before anything is enumerated' {
    # DEFECT 1, backup half. %ProgramData%\WindowsAutoCleanup\Logs has always been walked for this;
    # its SIBLING DriverBackup never was, and a sibling is not an ancestor - so a weaker owner or
    # DACL here was invisible while log trust still passed. A backup a standard user can rename
    # aside is not a backup, and finding that out after the package is deleted is too late.
    $sandbox = New-TestSandbox -Prefix 'dr-roottrust'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        [void][System.IO.Directory]::CreateDirectory($backupRoot)
        Grant-TestEveryoneWrite -Path $backupRoot

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row (New-SupersededPair)) }

            Invoke-WithRealPathTrust -Body {
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
                Assert-True ($result.Detail -match 'not machine-trusted') $result.Detail
                Assert-True ($result.Detail -match 'S-1-1-0') ('the refusal never named the principal: {0}' -f $result.Detail)
                # Before ANYTHING: not one process ran, so nothing was enumerated, exported, marked
                # or deleted under a root that cannot be trusted to hold the backup.
                Assert-Equal 0 $script:StubCall.Count ('a process ran under an untrusted backup root: {0}' -f $result.Detail)
            }
        }

        Assert-Equal 0 @(Get-ChildItem -LiteralPath $backupRoot -Force).Count 'the refused run still wrote into the untrusted root'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a reparse point in the backup root chain is refused' {
    # A junction anywhere in the chain redirects the whole backup elsewhere, so the directory a
    # restore would read is not the directory this run proved anything about.
    $sandbox = New-TestSandbox -Prefix 'dr-rootlink'
    $link = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
    try {
        $real = Join-Path -Path $sandbox -ChildPath 'elsewhere'
        [void][System.IO.Directory]::CreateDirectory($real)

        # mklink /J needs no elevation, so this runs identically on a developer shell and on CI.
        $cmd = Join-Path -Path $env:SystemRoot -ChildPath 'System32\cmd.exe'
        [void](Invoke-WacProcess -FilePath $cmd -TimeoutMs 30000 -ArgumentList @('/c', 'mklink', '/J', $link, $real))
        if (-not (Test-Path -LiteralPath $link)) { Set-TestSkipped -Reason 'this filesystem refused to create a junction' }

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row (New-SupersededPair)) }

            Invoke-WithRealPathTrust -Body {
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $link

                Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
                Assert-True ($result.Detail -match 'reparse point') $result.Detail
                Assert-Equal 0 $script:StubCall.Count 'a process ran under a redirected backup root'
            }
        }

        Assert-Equal 0 @(Get-ChildItem -LiteralPath $real -Force).Count 'the refused run wrote through the junction into its target'
    }
    finally {
        if (Test-Path -LiteralPath $link) { try { [System.IO.Directory]::Delete($link, $false) } catch { $null = $_ } }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a backup root whose volume cannot be inspected is refused, not assumed local' {
    # The fixed-local-volume half of the same rule. An unanswerable trust question is not a yes, and
    # a backup on a removable or absent volume is not recoverable evidence of anything.
    $absent = Get-TestUnusedDriveRoot
    if (-not $absent) { Set-TestSkipped -Reason 'every drive letter from N to Z is in use on this machine' }

    Invoke-WithStubbedTool -Body {
        $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row (New-SupersededPair)) }

        Invoke-WithRealPathTrust -Body {
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $absent

            Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'not machine-trusted') $result.Detail
            Assert-Equal 0 $script:StubCall.Count 'a process ran under a backup root on an uninspectable volume'
        }
    }

    Assert-False (Test-Path -LiteralPath $absent) 'the refused run created the backup root anyway'
}

Test-Case 'an untrusted identity directory is refused before its manifest decides anything' {
    # The root passing is not the whole answer: an ACE that is inherit-only on the root grants
    # nothing THERE and everything on the children created under it, so each existing identity
    # directory is asked in its own right - and asked BEFORE its manifest is read, because the very
    # next thing this function does is believe that manifest.
    #
    # Both shapes go through the same directory: one where the manifest would say "reclaim me" and
    # one where it would say "refuse me". Without the check the first is silently emptied and
    # re-exported into, which is the destructive half.
    $sandbox = New-TestSandbox -Prefix 'dr-identitytrust'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        [void][System.IO.Directory]::CreateDirectory($backupRoot)

        $driver = @(Get-ParsedDriver -Row @((New-PnpUtilRow -DriverName 'oem1.inf' -DeviceStatus @())))[0]
        $identity = Get-WacDriverBackupIdentity -Driver $driver
        $directory = Join-Path -Path $backupRoot -ChildPath $identity.Name
        [void][System.IO.Directory]::CreateDirectory($directory)
        Grant-TestEveryoneWrite -Path $directory

        # Residue by every rule the guard knows: no marker and no manifest at all. This is the shape
        # the module RECLAIMS, so the trust refusal is the only thing standing between a directory a
        # standard user controls and a recursive delete driven by what it contains.
        Set-Content -LiteralPath (Join-Path -Path $directory -ChildPath 'planted.txt') -Value 'planted' -Encoding ASCII -NoNewline

        Invoke-WithStubbedTool -Body {
            Invoke-WithRealPathTrust -Body {
                $result = Export-WacDriverBackup -PnpUtil $script:PnpUtilPath -Driver $driver -BackupRoot $backupRoot

                Assert-Equal 'SecurityRefusal' $result.Outcome $result.Reason
                Assert-True ($result.Reason -match 'not machine-trusted') $result.Reason
                Assert-Equal 0 @(Get-ExportCall).Count 'a package was exported into a directory a standard user controls'
            }
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $directory -ChildPath 'planted.txt')) `
            'an untrusted directory was reclaimed on the say-so of what it contained'

        # Same directory, now carrying a manifest that records a completed deletion of this very
        # package - the shape that refuses for COLLISION. The refusal has to name trust, or the
        # trust question was never asked and the manifest was read first after all.
        $manifest = New-WacDriverBackupManifest -Driver $driver -Identity $identity -File @()
        $manifest.DeletedUtc = '2026-01-01T00:00:00Z'
        Set-Content -LiteralPath (Join-Path -Path $directory -ChildPath $script:ManifestName) `
            -Value ($manifest | ConvertTo-Json -Depth 6) -Encoding ASCII

        Invoke-WithStubbedTool -Body {
            Invoke-WithRealPathTrust -Body {
                $result = Export-WacDriverBackup -PnpUtil $script:PnpUtilPath -Driver $driver -BackupRoot $backupRoot

                Assert-Equal 'SecurityRefusal' $result.Outcome $result.Reason
                Assert-True ($result.Reason -match 'not machine-trusted') `
                    ('the manifest decided before the trust question was asked: {0}' -f $result.Reason)
                Assert-False ($result.Reason -match 'records the deletion') $result.Reason
            }
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the backup trust rule is Core''s state-path walk, not a second copy living in the driver package' {
    # Ledger B2-3 applied here: two copies of a security rule is one copy that gets fixed and one
    # that does not. The gate must delegate to the walk Core owns, and the driver package must not
    # start decoding access rules of its own.
    $package = @('WindowsAutoCleanup.Drivers.psm1', 'WindowsAutoCleanup.DriverInventory.ps1',
        'WindowsAutoCleanup.DriverBackup.ps1')
    $source = (@($package | ForEach-Object {
        [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath ('src\' + $_)))
    }) -join [Environment]::NewLine)

    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count 'the driver package no longer parses'
    $code = @(@($tokens) | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text })

    # Three call sites, every one of them load-bearing: the persistent root, each existing identity
    # directory inside it, and - added with the cross-run reconciliation of a pending deletion -
    # each directory still holding an unresolved marker, asked BEFORE its manifest is read so a
    # directory a standard user can rewrite cannot name the package that run then commits.
    #
    # The count is deliberately exact so a silently removed gate cannot pass. Raising it is a
    # decision, not a formality: a later change may only do so together with the gate that earns it.
    Assert-Equal 3 @($code | Where-Object { $_ -eq 'Test-WacStatePathIsTrusted' }).Count `
        'the backup-root, identity-directory and pending-reconciliation trust gates are not all delegating to Core''s walk'
    foreach ($forbidden in @('GetAccessRules', 'GetOwner', 'Get-Acl')) {
        Assert-Equal 0 @($code | Where-Object { $_ -eq $forbidden }).Count `
            ('the driver package is deciding {0} for itself instead of delegating to Core' -f $forbidden)
    }
}

Test-Case 'The backup root is somewhere a standard user cannot create a name, and it is not the data root' {
    <#
        The rule the brief asked for is "Writers must be empty", and the only lever this project has
        for it is WHERE the root is: rewriting an ACL is banned and a test fails the build if
        Set-Acl, SetOwner, icacls or takeown reappears.

        So the assertion is about the location, and about the two things that make it the right one:
        it is not under the data root, whose inherited BUILTIN\Users grant no healthy install can
        shed, and it is not the deployment root's fallback, which the installer swaps out on upgrade
        and would take the only copy of a deleted package with it.
    #>
    $backup = Get-WacDriverBackupRoot
    $data = Get-WacDataRoot
    $deployment = Get-WacDeploymentRoot

    Assert-False ($backup.StartsWith($data + '\', [System.StringComparison]::OrdinalIgnoreCase)) `
        ('the backup root is still under the data root: ' + $backup)
    Assert-False ($backup -ieq $deployment) 'the backup root is the deployment root'
    Assert-False ($backup.StartsWith($deployment + '\', [System.StringComparison]::OrdinalIgnoreCase)) `
        'the backup root sits inside the deployment tree the installer replaces on upgrade'
    Assert-True ($backup.StartsWith($env:SystemRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) `
        ('the backup root left the Windows directory entirely: ' + $backup)

    # The legacy location is still NAMED, because an unresolved deletion left there must never
    # become invisible - but it is only ever reported, and it is not where anything is written now.
    Assert-False ((Get-WacLegacyDriverBackupRoot) -ieq $backup) 'the legacy root and the new root are the same path'
}

Test-Case 'A backup root a standard user can create names in is refused, not merely warned about' {
    <#
        This shipped as a WARNING and a continue, which is not a guard: a principal who can create a
        name in the backup root can plant wac-driver-backup.json, the pending marker or the commit
        file before the step writes them, and the export is then not the only copy of anything.

        The refusal is only affordable because the root moved (see the case above). Asserting it
        against a directory whose Writers are non-empty is the whole point - on the old root every
        healthy machine looked like this.
    #>
    $sandbox = New-TestSandbox -Prefix 'dr-writers'
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        [void][System.IO.Directory]::CreateDirectory($root)

        $result = Invoke-WithStubbedTool -Body {
            # Trusted in every other respect, but a non-administrator can create names here.
            Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacStatePathIsTrusted' -Body {
                param($Path)
                [PSCustomObject]@{ Path = $Path; IsTrusted = $true; Reason = 'stub'; Writers = @('S-1-5-32-545') }
            }
            Invoke-WacDriverPackagePrune -Enabled -BackupRoot $root
        }

        Assert-Equal 'SecurityRefusal' ([string]$result.Outcome) `
            'a backup root a standard user can create names in was accepted'
        Assert-True ($result.Detail -match 'S-1-5-32-545') 'the refusal does not name the principal that caused it'
        Assert-Equal 0 @(Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue).Count `
            'the refused root was written into anyway'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
