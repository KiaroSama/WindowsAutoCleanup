<#
.SYNOPSIS
    Content-addressed driver backups: the immutable identity, the hashed export, the manifest that
    records the deletion evidence, and the guard that tells residue from the only copy of a package.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Drivers.psm1; see that file for why the parts are dot-sourced
    rather than imported. Every failure mode here ends with the package still installed: only an
    Outcome of Succeeded from Export-WacDriverBackup may be followed by a deletion, and only
    Complete-WacDriverBackup - called after pnputil really removed the package - stamps DeletedUtc,
    which is what turns an export into a backup no later run may reclaim.

    The manifest constants are declared here because the manifest is what they describe. All parts
    share one session state, so the pnputil constants this file reads are the ones Drivers.psm1
    declares, not copies.
#>

# Written into every export directory. Excluded from its own hash list, and the name a recovery tool
# reads to find out which oem<n>.inf a backup directory holds.
$script:BackupManifestName   = 'wac-driver-backup.json'
# 2 added DeletedUtc: the record that tells a backup apart from an export of a package that is
# still installed. A schema-1 manifest has no such record and is therefore reclaimable.
$script:BackupManifestSchema = 2

# Written before pnputil is asked to remove a package, cleared only once the stamped manifest is
# durable. While it exists a deletion MAY have happened - a killed run, a torn write and a commit
# that failed all look alike from outside - so the directory is protected until a human resolves it.
$script:BackupPendingName = 'wac-driver-delete.pending'

# ---------------------------------------------------------------------------------------------
# 4. Recoverable backups
# ---------------------------------------------------------------------------------------------

function Get-WacDriverBackupIdentity {
    <#
    .SYNOPSIS
        The immutable backup directory name for a package, and the hash it is derived from. Pure.
    .DESCRIPTION
        oem<n>.inf is a RECYCLABLE name: the number is released when a package is removed and the
        next /add-driver can hand the same number to something completely unrelated. Naming an export
        directory after it lets a later run merge into - or overwrite - the only recoverable copy of
        an earlier deletion.

        The identity is therefore built from package data that does not move (original INF name,
        provider, class, extension, signer, exact version) and stamped with a SHA-256 of that same
        data. Two different packages cannot land in one directory, and the same package always lands
        in its own.
    #>
    param([Parameter(Mandatory = $true)]$Driver)

    $field = @(
        [string]$Driver.OriginalName,
        [string]$Driver.ProviderName,
        [string]$Driver.ClassGuid,
        [string]$Driver.ExtensionId,
        [string]$Driver.SignerName,
        [string]$Driver.VersionText,
        [string]$Driver.Version
    )
    $canonical = ($field -join '|').ToLowerInvariant()

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonical))
    }
    finally {
        $sha.Dispose()
    }
    $hash = (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')

    # GetFileNameWithoutExtension throws on an invalid path character under .NET Framework, and
    # OriginalName is tool output. The hash already carries the identity, so the stem is only a
    # human-readable label and 'driver' is a perfectly good one.
    $stem = ''
    try { $stem = [System.IO.Path]::GetFileNameWithoutExtension([string]$Driver.OriginalName) }
    catch { $stem = '' }
    $stem = ($stem -replace '[^A-Za-z0-9._-]', '_')
    if ($stem.Length -gt 32) { $stem = $stem.Substring(0, 32) }
    if ([string]::IsNullOrWhiteSpace($stem)) { $stem = 'driver' }

    $version = (([string]$Driver.Version) -replace '[^0-9.]', '_')
    if ([string]::IsNullOrWhiteSpace($version)) { $version = '0' }

    return [PSCustomObject]@{
        Name      = ('{0}_{1}_{2}' -f $stem, $version, $hash.Substring(0, 16))
        Hash      = $hash
        Canonical = $canonical
    }
}

function Get-WacDriverBackupFileHash {
    <#
    .SYNOPSIS
        Every exported file under a backup directory with its size and SHA-256, ordered.
    .DESCRIPTION
        Ok is separate from an empty File list on purpose: a directory that could not be READ must
        never be mistaken for a directory that is empty, because one of those two answers is allowed
        to precede a deletion and the other is not.

        The manifest itself is excluded - it records this list, so it cannot be part of what it
        records. Paths are relative and ordinal-sorted so the same export hashes identically on both
        hosts.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $result = [PSCustomObject]@{ Ok = $false; Reason = ''; File = @() }

    $root = Get-WacNormalizedPath -Path $Path
    if (-not $root) {
        $result.Reason = 'The backup directory path could not be normalised.'
        return $result
    }

    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        $result.Reason = 'The backup directory does not exist.'
        return $result
    }

    $prefix = Get-WacLongPath -Path $root
    $entry = New-Object 'System.Collections.Generic.List[object]'
    $sha = [System.Security.Cryptography.SHA256]::Create()

    try {
        $info = New-Object System.IO.DirectoryInfo($prefix)
        foreach ($file in $info.EnumerateFiles('*', [System.IO.SearchOption]::AllDirectories)) {
            $relative = [string]$file.FullName
            if ($relative.Length -gt $prefix.Length) {
                $relative = $relative.Substring($prefix.Length).TrimStart('\')
            }
            # The manifest records this list so it cannot be part of it, and the pending marker is
            # only ever written after the list was verified. Neither is export content.
            if ($relative -ieq $script:BackupManifestName -or $relative -ieq $script:BackupPendingName) { continue }

            $stream = New-Object System.IO.FileStream($file.FullName, [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                $bytes = $sha.ComputeHash($stream)
            }
            finally {
                $stream.Dispose()
            }

            [void]$entry.Add([PSCustomObject]@{
                Path   = $relative
                Bytes  = [int64]$file.Length
                Sha256 = (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
            })
        }
    }
    catch {
        # Classified, never caught by type: PowerShell wraps a .NET method exception in
        # MethodInvocationException and the two hosts disagree about typed clauses.
        $result.Reason = 'The backup directory could not be read ({0}): {1}' -f (Get-WacIoFailureKind -ErrorRecord $_), $_.Exception.Message
        return $result
    }
    finally {
        $sha.Dispose()
    }

    $result.Ok = $true
    # ORDINAL, not Sort-Object. This list is compared INDEX BY INDEX when an export is verified, so
    # its order is part of the contract - and Sort-Object is culture-sensitive. Measured on this
    # machine, both hosts under en-US, over realistic driver file names: the two hosts disagree with
    # EACH OTHER (oem-a.inf sorts 5th under pwsh 7 and 7th under Windows PowerShell 5.1, and the two
    # cat files swap), while the ordinal order is identical on both. A manifest written by the
    # scheduled task under one host and verified by an operator under the other would therefore
    # report 'expected <a>, found <b>' for a backup whose files and hashes are all intact - declaring
    # a usable recovery copy unusable, which is the one thing this whole protocol exists to prevent.
    # OrdinalIgnoreCase rather than Ordinal, so the sort and the -ine comparison below share a case
    # rule. FileSystem.psm1 carries the same fix in its ordering form.
    $ordered = @($entry.ToArray())
    [array]::Sort($ordered, [System.Comparison[object]] {
            param($x, $y)
            [string]::Compare([string]$x.Path, [string]$y.Path, [System.StringComparison]::OrdinalIgnoreCase)
        })
    $result.File = @($ordered)
    return $result
}

function New-WacDriverBackupManifest {
    <#
    .SYNOPSIS
        The record written beside an export: what was deleted, why it was safe, and what was kept.
    .DESCRIPTION
        The manifest is the only thing that maps a content-addressed backup directory back to the
        oem<n>.inf it came from, and the only record of the evidence the deletion rested on. Both
        matter for recovery: the number is reusable, the evidence is not reconstructible afterwards.

        It is also what the collision guard reads. DeletedUtc is written here as empty and stamped
        only once pnputil has really removed the package, so the manifest states which of the two
        things a directory is: the only copy of a package that is gone, or an export of a package
        that is still installed.
    #>
    param(
        [Parameter(Mandatory = $true)]$Driver,
        [Parameter(Mandatory = $true)]$Identity,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()][object[]]$File,
        [int]$EnumeratedPackage = 0
    )

    $list = @($File)
    $total = 0L
    foreach ($item in $list) { $total += [int64]$item.Bytes }

    $supersededByName = ''
    $supersededByVersion = ''
    if (@($Driver.PSObject.Properties.Name) -ccontains 'SupersededByName') { $supersededByName = [string]$Driver.SupersededByName }
    if (@($Driver.PSObject.Properties.Name) -ccontains 'SupersededByVersion') { $supersededByVersion = [string]$Driver.SupersededByVersion }

    return [PSCustomObject]@{
        Schema       = $script:BackupManifestSchema
        CreatedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        # Empty until the deletion this export exists for actually happens. Until then the package
        # is still in the store, so this directory is a copy of something, not the only copy of it.
        DeletedUtc   = ''
        ExecutionId  = [string](Get-WacExecutionId)
        DriverName   = [string]$Driver.DriverName
        OriginalName = [string]$Driver.OriginalName
        ProviderName = [string]$Driver.ProviderName
        ClassGuid    = [string]$Driver.ClassGuid
        ExtensionId  = [string]$Driver.ExtensionId
        SignerName   = [string]$Driver.SignerName
        VersionText  = [string]$Driver.VersionText
        Version      = [string]$Driver.Version
        IdentityName = [string]$Identity.Name
        IdentityHash = [string]$Identity.Hash
        Evidence     = [PSCustomObject]@{
            Command             = ('pnputil {0}' -f ($script:PnpUtilEnumArgument -join ' '))
            DeviceCount         = [int]$Driver.DeviceCount
            SupersededByName    = $supersededByName
            SupersededByVersion = $supersededByVersion
            EnumeratedPackage   = $EnumeratedPackage
        }
        FileCount    = $list.Count
        TotalBytes   = $total
        File         = $list
    }
}

function Test-WacDriverBackupIntact {
    <#
    .SYNOPSIS
        Re-hashes an export and compares it to the manifest that recorded it.
    .DESCRIPTION
        Run immediately before the deletion. Anything that changed the export between writing the
        manifest and removing the package - a file gone, a byte different, a file added - means the
        recoverable copy is not the copy that was verified, and the deletion must not go ahead.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path,
        [Parameter(Mandatory = $true)]$Manifest
    )

    $result = [PSCustomObject]@{ Intact = $false; Reason = '' }

    $current = Get-WacDriverBackupFileHash -Path $Path
    if (-not $current.Ok) {
        $result.Reason = $current.Reason
        return $result
    }

    $recorded = @($Manifest.File)
    $observed = @($current.File)

    if ($recorded.Count -ne $observed.Count) {
        $result.Reason = 'the export holds {0} file(s), the manifest recorded {1}' -f $observed.Count, $recorded.Count
        return $result
    }

    for ($i = 0; $i -lt $recorded.Count; $i++) {
        if ([string]$recorded[$i].Path -ine [string]$observed[$i].Path) {
            $result.Reason = 'expected {0}, found {1}' -f $recorded[$i].Path, $observed[$i].Path
            return $result
        }
        if ([int64]$recorded[$i].Bytes -ne [int64]$observed[$i].Bytes) {
            $result.Reason = '{0} is {1} byte(s), the manifest recorded {2}' -f $observed[$i].Path, $observed[$i].Bytes, $recorded[$i].Bytes
            return $result
        }
        if ([string]$recorded[$i].Sha256 -ine [string]$observed[$i].Sha256) {
            $result.Reason = '{0} does not match its recorded SHA-256' -f $observed[$i].Path
            return $result
        }
    }

    $result.Intact = $true
    return $result
}

function Test-WacDriverBackupIsResidue {
    <#
    .SYNOPSIS
        Tells this tool's own leftovers apart from the only copy of a package that really was deleted.
    .DESCRIPTION
        The backup root is PERSISTENT, so whatever a run leaves behind is what every later run walks
        into, and a guard that refuses every existing directory refuses that package forever.

        Reclaiming needs BOTH halves, and age or a missing timestamp is neither of them:

          1. NO DELETION AMBIGUITY. No pending marker, and a manifest that is absent, unreadable or
             unstamped. The marker is written before pnputil is asked to remove anything and cleared
             only once the stamped manifest is durable, so its absence is what proves no deletion
             was ever attempted here.
          2. THE PACKAGE IS STILL INSTALLED. The only caller reaches this for a candidate taken from
             the CURRENT structured inventory, and the directory is addressed by that candidate's
             content identity - so this directory, holding either that same identity or no manifest
             at all, describes a package this run has just enumerated as present.

        Everything else is protected. A manifest recording a DIFFERENT identity is not ours to
        explain away by deleting it, a stamped manifest is the only copy of a package that is gone,
        and an uncommitted deletion attempt may be.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Identity
    )

    $result = [PSCustomObject]@{ IsResidue = $true; Reason = 'it carries no backup manifest, so an earlier export never completed' }

    # Checked FIRST and without reading anything: once a deletion may have happened, no manifest
    # state - absent, unreadable or unstamped - can turn this directory back into ordinary residue.
    # Only a PROVED absence clears it; a marker this tool cannot open, or a directory whose trust
    # cannot be established, both read as an attempt that may still be outstanding.
    $marker = Read-WacDriverBackupControlFile -Path $Path -Name $script:BackupPendingName
    if ($marker.Kind -cne 'Missing') {
        $result.IsResidue = $false
        $result.Reason = 'it carries an uncommitted deletion attempt, so the package it holds may already be gone'
        if ($marker.Kind -cne 'Read') {
            $result.Reason = ('its deletion marker could not be read ({0}: {1}), so whether a deletion was attempted here is unknown' -f
                $marker.Kind, [string]$marker.Reason)
        }
        return $result
    }

    # Through the directory's own pinned handle, no-follow and link-counted. Reclaiming is a
    # RECURSIVE DELETE decided by what this file says, so a planted symlink or hard link at this
    # name must not be what says it.
    $record = Read-WacDriverBackupControlFile -Path $Path -Name $script:BackupManifestName
    if ($record.Kind -ceq 'Missing') { return $result }
    if ($record.Kind -cne 'Read') {
        $result.IsResidue = $false
        $result.Reason = ('its manifest could not be read ({0}: {1}), so what it holds is unknown' -f
            $record.Kind, [string]$record.Reason)
        return $result
    }

    $manifest = $null
    try {
        $manifest = $record.Text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $result.Reason = 'its manifest is not readable JSON, so an earlier export never completed'
        return $result
    }

    # Read defensively: this is a file on disk, and under Set-StrictMode 2.0 an absent property
    # throws rather than returning empty.
    $property = @()
    if ($null -ne $manifest) { $property = @($manifest.PSObject.Properties.Name) }

    if ($property -cnotcontains 'IdentityHash') {
        $result.Reason = 'its manifest records no package identity, so an earlier export never completed'
        return $result
    }

    if ([string]$manifest.IdentityHash -ine [string]$Identity.Hash) {
        $result.IsResidue = $false
        $result.Reason = 'its manifest records a different package identity'
        return $result
    }

    if ($property -cnotcontains 'DeletedUtc' -or [string]::IsNullOrWhiteSpace([string]$manifest.DeletedUtc)) {
        $result.Reason = 'its manifest records no completed deletion, so the package it holds is still installed'
        return $result
    }

    # Measured on both shipped hosts, and it is the opposite way round from what an earlier comment
    # here claimed: Windows PowerShell 5.1 leaves an ISO-8601 string as a System.String, while
    # PowerShell 7 parses it into a System.DateTime with Kind=Utc. So the raw value renders
    # differently on the two hosts, and only the PowerShell 7 shape needs normalising back.
    $stamp = $manifest.DeletedUtc
    if ($stamp -is [datetime]) { $stamp = $stamp.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

    $result.IsResidue = $false
    $result.Reason = 'its manifest records the deletion of that package on {0}' -f [string]$stamp
    return $result
}

function Remove-WacDriverBackupDirectory {
    <#
    .SYNOPSIS
        Removes one export directory this module owns. True when nothing is left at the path.
    .DESCRIPTION
        Directory.Delete's recursive form is used rather than Remove-Item -Recurse, which does not
        reliably stop at a reparse point under Windows PowerShell 5.1. Measured on both hosts
        against a junction planted inside the directory: the junction is unlinked, its TARGET is
        left completely untouched, and the call then throws UnauthorizedAccessException - so the
        worst case here is a directory that stays and a package that is never pruned, never a
        deletion that walked out of the backup root. The root itself is refused outright when it is
        a link, because an export directory this module created never is one.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    if (Test-WacIsReparsePoint -Path $Path) { return $false }

    try {
        [System.IO.Directory]::Delete((Get-WacLongPath -Path $Path), $true)
    }
    catch {
        # A locked or denied directory is reported by what is still there, not by the exception:
        # the caller only ever needs to know whether the path is clear.
        return (-not (Test-Path -LiteralPath $Path))
    }

    return (-not (Test-Path -LiteralPath $Path))
}

function Export-WacDriverBackup {
    <#
    .SYNOPSIS
        Exports one package into its own immutable directory and proves the copy before returning.
    .DESCRIPTION
        Everything a deletion depends on happens here, and every failure mode ends with the package
        still installed:

          collision  - the identity directory already holds a backup whose manifest records a
                       completed deletion. REFUSED, never merged or overwritten: that directory is
                       the only copy of a package that is gone. The same directory WITHOUT that
                       record is this tool's own residue and is reclaimed instead, because the
                       package it holds is still installed.
          containment- the identity directory would fall outside the backup root. REFUSED.
          trust      - the identity directory is not on a local fixed volume, has a reparse point
                       in its chain, or a non-administrator may write to, replace or own it.
                       REFUSED, and for an EXISTING directory the refusal comes before its manifest
                       is read: a directory a standard user can rewrite must not be allowed to say
                       whether an earlier deletion is reclaimable, and must not be deleted on its
                       say-so either. The verdict is taken by the STRICT rule from the directory's
                       OWN handle, which is what catches the case a pathname pre-check cannot: an
                       inherit-only ancestor ACE grants nothing on the parent and becomes effective
                       on the child the moment this function creates it.
          collision  - the identity directory name appeared between the check and the create, or a
                       control file name inside it is already taken. REFUSED rather than adopted.
          timeout    - the export was killed on its deadline, so what is on disk is unknown.
          empty      - /export-driver reported success and produced no .inf. Nothing recoverable.
          mismatch   - the export changed between being hashed and being trusted.

        Only an Outcome of Succeeded may be followed by a deletion.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$PnpUtil,
        [Parameter(Mandatory = $true)]$Driver,
        [Parameter(Mandatory = $true)][string]$BackupRoot,
        [int]$EnumeratedPackage = 0,
        [string]$Component = 'DriverPrune'
    )

    $result = [PSCustomObject]@{ Outcome = 'SafeSkip'; Reason = ''; Directory = ''; FileCount = 0; Manifest = $null }

    $identity = Get-WacDriverBackupIdentity -Driver $Driver
    $directory = Get-WacNormalizedPath -Path (Join-Path -Path $BackupRoot -ChildPath $identity.Name)
    if (-not $directory) {
        $result.Reason = 'the export directory path could not be normalised'
        return $result
    }

    if (-not (Test-WacIsWithinRoot -ChildPath $directory -RootPath $BackupRoot)) {
        # The identity is built from tool output, so it is untrusted input until this passes.
        $result.Outcome = 'SecurityRefusal'
        $result.Reason = 'the export directory resolved outside the backup root'
        return $result
    }
    $result.Directory = $directory

    if (Test-Path -LiteralPath $directory) {
        # BEFORE anything inside is read, in two halves that answer different questions.
        #
        # The walk answers for the ancestor CHAIN - a reparse point or a weak DACL anywhere above
        # this directory - which a handle bound to the directory itself deliberately says nothing
        # about.
        $existingTrust = Test-WacStatePathIsTrusted -Path $directory
        if (-not $existingTrust.IsTrusted) {
            $result.Outcome = 'SecurityRefusal'
            $result.Reason = 'an export directory with the same package identity already exists and is not machine-trusted ({0})' -f [string]$existingTrust.Reason
            return $result
        }

        # The strict proof answers for THIS directory, from its own handle. Test-WacStatePathIsTrusted
        # only REPORTS its Writers list and applies the relaxed replace-rule, so a directory an
        # inherit-only ancestor ACE made writable passes the walk and is refused here - which is the
        # whole point, because the next thing this function does is believe this directory's
        # manifest, and then delete the directory on the strength of it.
        $existingProof = Open-WacDriverBackupDirectory -Path $directory
        Close-WacTrustedDirectory -Handle $existingProof.Handle
        if (-not $existingProof.IsTrusted) {
            $result.Outcome = 'SecurityRefusal'
            $result.Reason = 'an export directory with the same package identity already exists and is not machine-trusted ({0}{1})' -f `
                [string]$existingProof.Reason, $(if (@($existingProof.Writers).Count -gt 0) { ' writers=' + (@($existingProof.Writers) -join ', ') } else { '' })
            return $result
        }

        # The root is persistent, so refusing on sight refused this package on every later run - and
        # the two states that got it there, a declined deletion and a failed export, are both
        # benign. Only a directory that is the only copy of something may refuse.
        $residue = Test-WacDriverBackupIsResidue -Path $directory -Identity $identity
        if (-not $residue.IsResidue) {
            $result.Outcome = 'SecurityRefusal'
            $result.Reason = 'an export directory with the same package identity already exists and {0}, so overwriting it could destroy the only copy of an earlier deletion' -f $residue.Reason
            return $result
        }

        if (-not (Remove-WacDriverBackupDirectory -Path $directory)) {
            $result.Reason = 'an earlier export left a directory that could not be reclaimed ({0})' -f $residue.Reason
            return $result
        }

        Write-WacLog -Level INFO -Component $Component -Message 'Reclaimed the directory an earlier export left behind.' -Data @{
            driver = [string]$Driver.DriverName; directory = $directory; reason = $residue.Reason
        }
    }

    # Created through the pinned-handle primitive, never Test-Path then New-Item. Three properties
    # the pathname create did not have, and all three are load-bearing here:
    #   * COLLISION-FAILING, so a name that appeared after the check above - the second half of the
    #     creation race - is refused rather than adopted. New-Item without -Force had this much.
    #   * BOUND, so the create is anchored to the proved parent rather than to a path walked from
    #     the volume root, and no swap of any ancestor can move where it lands.
    #   * PROVED AFTERWARDS BY THE STRICT RULE, from the handle of the directory that was actually
    #     created. This is the half nothing had: the pre-create verdict was taken on the PARENT, and
    #     an inherit-only ACE there grants nothing on the parent and full write on this new child.
    $made = Open-WacDriverBackupDirectory -Path $directory -MayCreate
    Close-WacTrustedDirectory -Handle $made.Handle
    if (-not $made.IsTrusted) {
        $result.Outcome = 'SecurityRefusal'
        $result.Reason = 'the export directory could not be created and proved ({0}{1})' -f `
            [string]$made.Reason, $(if (@($made.Writers).Count -gt 0) { ' writers=' + (@($made.Writers) -join ', ') } else { '' })
        return $result
    }

    try {
        $timeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpUtilTimeoutMs
        if ($timeoutMs -le 0) {
            $result.Outcome = 'Incomplete'
            $result.Reason = 'the run budget was exhausted before the export could start'
            return $result
        }

        $export = Invoke-WacProcess -FilePath $PnpUtil -ArgumentList @('/export-driver', [string]$Driver.DriverName, $directory) `
            -TimeoutMs $timeoutMs -Component $Component

        if ($export.TimedOut) {
            $result.Outcome = 'Incomplete'
            $result.Reason = 'the export exceeded its deadline and its process tree was terminated'
            return $result
        }

        if ($script:PnpUtilSuccessCode -notcontains $export.ExitCode) {
            $result.Reason = 'the export exited with {0}' -f $export.ExitCode
            return $result
        }

        $hashed = Get-WacDriverBackupFileHash -Path $directory
        if (-not $hashed.Ok) {
            $result.Reason = $hashed.Reason
            return $result
        }

        $file = @($hashed.File)
        $inf = @($file | Where-Object { [string]$_.Path -match '(?i)\.inf$' })
        if ($file.Count -eq 0 -or $inf.Count -eq 0) {
            $result.Reason = 'the export reported success but left no .inf behind, so nothing is recoverable'
            return $result
        }

        $manifest = New-WacDriverBackupManifest -Driver $Driver -Identity $identity -File $file -EnumeratedPackage $EnumeratedPackage

        # Created collision-failing inside the directory's own pinned handle. The directory was
        # created by this call a moment ago, so the name should be free - and 'should be' is exactly
        # the assumption a planted file, symlink or hard link at this name exists to break. An
        # ordinary WriteAllText would have truncated all three.
        $written = Write-WacDriverBackupControlFile -Path $directory -Name $script:BackupManifestName `
            -Content ($manifest | ConvertTo-Json -Depth 6)
        if (-not $written.Ok) {
            $result.Outcome = 'SecurityRefusal'
            $result.Reason = 'the backup manifest could not be written ({0})' -f [string]$written.Reason
            return $result
        }

        $intact = Test-WacDriverBackupIntact -Path $directory -Manifest $manifest
        if (-not $intact.Intact) {
            $result.Outcome = 'SecurityRefusal'
            $result.Reason = 'the export did not match its own manifest ({0})' -f $intact.Reason
            return $result
        }

        $result.Outcome = 'Succeeded'
        $result.FileCount = $file.Count
        $result.Manifest = $manifest
        return $result
    }
    finally {
        # Nothing that fails to reach Succeeded deleted anything, so the directory is a copy of a
        # package that is still installed - worth nothing, and in the way of every later run.
        if ($result.Outcome -cne 'Succeeded') { [void](Remove-WacDriverBackupDirectory -Path $directory) }
    }
}
