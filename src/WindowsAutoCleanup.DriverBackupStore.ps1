<#
.SYNOPSIS
    The trusted store a driver backup lives in: the strict directory proof, the bound reads and
    writes of the three fixed-name control records, the commit that stamps a deletion, and the
    cross-run reconciliation that settles an attempt nobody could prove.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Drivers.psm1; see that file for why the parts are dot-sourced
    rather than imported.

    WHY THIS IS ITS OWN PART. Every name inside a backup directory is PREDICTABLE:
    wac-driver-backup.json, wac-driver-delete.pending and the staging name the commit writes are all
    derived from constants, so anyone who can create a name in that directory can put something of
    their own choosing at one of them before this code gets there. The three attacks that follow are
    not variations on one problem, and only one of them is caught by the reparse-point check this
    project already had:

      an ordinary file    - a pathname WriteAllText opens it and TRUNCATES it, so a planted record
                            becomes this run's record, or this run's write destroys a file it never
                            chose.
      a link              - a symlink or mount point at the name redirects the whole operation
                            somewhere else entirely.
      a HARD LINK         - a second directory entry for a file that lives elsewhere. It carries no
                            reparse attribute and resolves to a perfectly ordinary path, so a
                            reparse check misses it completely; writing through it overwrites the
                            other name's bytes in place.

    So the rule here is uniform and has no exceptions: a control file is either CREATED
    collision-failing, in which case every one of the three is refused rather than written through,
    or it is OPENED through Open-WacBoundFile, which refuses a link, a multi-link file and a
    directory before a single byte is read. Both happen inside a directory handle that has already
    been proved by the STRICT rule and is pinned for the duration of the operation, so the object
    written to is the object that was judged.

    WHAT THE PIN IS AND IS NOT. Each operation here takes its own pin and drops it when it is done,
    rather than one pin being held across the whole export-delete-commit cycle. Within an operation
    that is the full guarantee: the directory cannot be renamed or deleted, and every name inside is
    resolved against the handle. Between operations the directory is unpinned - and it does not need
    to be, because it sits inside a root that the same strict rule has proved no non-administrator
    may create, delete or rename anything in, and because every operation re-proves the directory
    from scratch before touching it. An administrator can still interfere, which is true of every
    guarantee in this project and is stated in the threat model rather than papered over.
#>

# ---------------------------------------------------------------------------------------------
# The trusted-store layer
# ---------------------------------------------------------------------------------------------

function Open-WacDriverBackupDirectory {
    <#
    .SYNOPSIS
        Opens - or, with -MayCreate, creates - ONE backup directory and proves it by the STRICT rule
        through its own handle. The caller owns the returned pin.
    .DESCRIPTION
        The relaxed rule Open-WacTrustedDirectory applies by default is not enough here, and the gap
        is measurable rather than theoretical: an ACE that is inherit-only on the parent grants
        nothing THERE, so the pre-create pathname verdict reports no writers, and the directory this
        call then creates inherits the same mask with the inherit-only flag cleared. Measured,
        (A;OICIIO;0x100116;;;BU) on the parent becomes (A;OICIID;0x100116;;;BU) on the child -
        BUILTIN\Users may write into the only copy of a package about to be deleted, and the relaxed
        rule accepts it because those bits are none of the replace bits it looks for.

        -MayCreate is deliberately not the default. A caller that means to settle, read or commit an
        EXISTING directory must never conjure one instead: a backup directory that has vanished is a
        fact to report, not a hole to fill. When it is passed, -MaxCreate missing components may be
        created, collision-failing, so a name that appeared after the check is refused rather than
        adopted. Only the LEAF is judged: what stands above it is Test-WacStatePathIsTrusted's
        question, and the caller must have asked it first.
    .OUTPUTS
        The Open-WacTrustedDirectory verdict, with Handle to close and Writers naming any
        non-administrative principal that may write there.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path,
        [switch]$MayCreate,
        [ValidateRange(1, 32)][int]$MaxCreate = 1
    )

    $verdict = Open-WacTrustedDirectory -Path $Path -RequireStrictTrust -MaxCreate $MaxCreate

    if ($verdict.IsTrusted -and -not $MayCreate -and @($verdict.Created).Count -gt 0) {
        # It was not there. Refusing AFTER the create is the honest order: the primitive has no
        # open-only mode, and undoing a directory this process legitimately created under a proved
        # anchor would be a destructive act taken to tidy up a caller's mistake.
        Close-WacTrustedDirectory -Handle $verdict.Handle
        $verdict.Handle = [IntPtr]::Zero
        $verdict.IsTrusted = $false
        $verdict.Reason = ('{0} did not exist, and this caller may only open an existing backup directory.' -f $Path)
    }

    return $verdict
}

function Write-WacDriverBackupControlFile {
    <#
    .SYNOPSIS
        Creates ONE fixed-name record inside a backup directory. Refuses a name that is already
        taken, whatever is standing at it.
    .OUTPUTS
        Ok / Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content
    )

    $result = [PSCustomObject]@{ Ok = $false; Reason = '' }

    $directory = Open-WacDriverBackupDirectory -Path $Path
    if (-not $directory.IsTrusted) {
        $result.Reason = [string]$directory.Reason
        return $result
    }

    try {
        $file = New-WacBoundFile -DirectoryHandle $directory.Handle -Name $Name
        if ($file.Kind -cne 'Created') {
            $result.Reason = ('{0} could not be created inside {1} ({2}); it was refused rather than written through.' -f $Name, $Path, $file.Kind)
            return $result
        }

        try {
            $writer = New-Object System.IO.StreamWriter($file.Stream, (New-Object System.Text.UTF8Encoding($false)))
            try {
                $writer.Write($Content)
                $writer.Flush()
            }
            finally {
                # Disposes the underlying stream too, which is what puts the bytes on disk.
                $writer.Dispose()
            }
        }
        catch {
            try { $file.Stream.Dispose() } catch { $null = $_ }
            $result.Reason = ('{0} could not be written ({1}): {2}' -f $Name, (Get-WacIoFailureKind -ErrorRecord $_), $_.Exception.Message)
            return $result
        }

        $result.Ok = $true
        return $result
    }
    finally {
        Close-WacTrustedDirectory -Handle $directory.Handle
    }
}

function Read-WacDriverBackupControlFile {
    <#
    .SYNOPSIS
        Reads ONE fixed-name record out of a backup directory, or says exactly why it would not.
    .DESCRIPTION
        Kind is the answer callers branch on, and the three non-success values mean different
        things. 'Missing' is the only one that means the name is free: it is proved by
        STATUS_OBJECT_NAME_NOT_FOUND from a bound open, not by a Test-Path that a dangling symlink
        would answer the same way. 'Refused' means something is there and it is not an ordinary
        single-linked file. 'Failed' means the question could not be asked at all - an untrusted
        directory, an unreadable file - and an unanswered question is never a no.
    .OUTPUTS
        Kind ('Read' / 'Missing' / 'Refused' / 'Failed'), Text, Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $result = [PSCustomObject]@{ Kind = 'Failed'; Text = ''; Reason = '' }

    $directory = Open-WacDriverBackupDirectory -Path $Path
    if (-not $directory.IsTrusted) {
        $result.Reason = [string]$directory.Reason
        return $result
    }

    try {
        $file = Open-WacBoundFile -DirectoryHandle $directory.Handle -Name $Name
        $result.Reason = [string]$file.Reason

        if ($file.Kind -cne 'Opened') {
            $result.Kind = [string]$file.Kind
            return $result
        }

        try {
            $reader = New-Object System.IO.StreamReader($file.Stream, (New-Object System.Text.UTF8Encoding($false)), $true)
            try { $result.Text = $reader.ReadToEnd() }
            finally { $reader.Dispose() }
        }
        catch {
            try { $file.Stream.Dispose() } catch { $null = $_ }
            $result.Kind = 'Failed'
            $result.Reason = ('{0} could not be read ({1}): {2}' -f $Name, (Get-WacIoFailureKind -ErrorRecord $_), $_.Exception.Message)
            return $result
        }

        $result.Kind = 'Read'
        return $result
    }
    finally {
        Close-WacTrustedDirectory -Handle $directory.Handle
    }
}

function Remove-WacDriverBackupControlFile {
    <#
    .SYNOPSIS
        Removes ONE fixed-name record, having first proved through a bound handle that the name
        holds an ordinary single-linked file. True when nothing is left at the name.
    .DESCRIPTION
        The proof is the point. Unlinking a hard link would not destroy the other name's bytes and
        unlinking a symlink would not follow it, so neither is a data-loss bug - but deleting an
        object this tool never created, on the strength of its NAME alone, is exactly the habit that
        produces one. A refusal here leaves the record standing, which for the pending marker is the
        protective direction: the backup stays protected and a human settles it.

        The unlink itself is by pathname, inside the pinned directory the strict rule has just
        proved no non-administrator may write to. An administrator could still race it, which is
        true of everything here and is what the threat model says.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $full = Join-Path -Path $Path -ChildPath $Name

    $directory = Open-WacDriverBackupDirectory -Path $Path
    if (-not $directory.IsTrusted) { return $false }

    try {
        $file = Open-WacBoundFile -DirectoryHandle $directory.Handle -Name $Name
        if ($file.Kind -ceq 'Missing') { return $true }
        if ($file.Kind -cne 'Opened') { return $false }
        $file.Stream.Dispose()

        try { [System.IO.File]::Delete((Get-WacLongPath -Path $full)) }
        catch { $null = $_ }
    }
    finally {
        Close-WacTrustedDirectory -Handle $directory.Handle
    }

    return (-not (Test-Path -LiteralPath $full))
}

# ---------------------------------------------------------------------------------------------
# The pending-deletion marker
# ---------------------------------------------------------------------------------------------

function Set-WacDriverBackupDeletePending {
    <#
    .SYNOPSIS
        Records that a deletion is about to be attempted. True only once the marker is on disk.
    .DESCRIPTION
        A caller that cannot write this must not delete: without the marker an interrupted deletion
        looks exactly like an export that never finished, and the next run would reclaim the only
        copy left of a package that is gone.

        The create is collision-failing, so a name already taken - by a planted file, a link, a hard
        link or a directory - is a refusal and therefore a reason not to delete. That is the right
        answer twice over: this run cannot record its attempt, and something it did not put there is
        sitting in the directory it was about to trust.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$DriverName
    )

    $record = 'driver={0} attemptedUtc={1} executionId={2}' -f $DriverName,
        (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), [string](Get-WacExecutionId)

    $written = Write-WacDriverBackupControlFile -Path $Path -Name $script:BackupPendingName -Content $record
    if (-not $written.Ok) { return $false }

    return (Test-WacDriverBackupDeletePending -Path $Path)
}

function Test-WacDriverBackupDeletePending {
    <#
    .SYNOPSIS
        True while a recorded deletion attempt against this directory has not been committed.
    .DESCRIPTION
        Only a PROVED absence answers no. Anything else - a file, a link, a hard link, a directory,
        or a directory whose trust could not be established at all - reads as pending, because the
        consequence of a wrong no is that a later run reclaims the only copy of a deleted package.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    return ((Read-WacDriverBackupControlFile -Path $Path -Name $script:BackupPendingName).Kind -cne 'Missing')
}

function Clear-WacDriverBackupDeletePending {
    <#
    .SYNOPSIS
        Removes the marker. True only when nothing is left at its path.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Remove-WacDriverBackupControlFile -Path $Path -Name $script:BackupPendingName)
}

# ---------------------------------------------------------------------------------------------
# The commit
# ---------------------------------------------------------------------------------------------

function Complete-WacDriverBackup {
    <#
    .SYNOPSIS
        Stamps the deletion into the manifest, which is what turns an export into a backup.
    .DESCRIPTION
        Called only once pnputil has really removed the package, and the ONLY thing that may turn an
        export into a backup. The commit is a staged write plus File.Replace, so a reader sees either
        the whole old manifest or the whole new one: a torn manifest reads as "no completed deletion"
        and would invite the next run to reclaim the only copy of a package that is gone.
        Delete-then-move is the fallback for a volume that refuses Replace, and it is safe here only
        because the pending marker is still standing over it.

        BOTH NAMES ARE PROVED BEFORE EITHER IS TOUCHED, and neither is ever adopted. The staging name is CREATED collision-
        failing, so anything already standing at it is refused instead of truncated, and the manifest
        itself is opened through a bound handle and refused unless it is an ordinary, single-linked,
        non-reparse file. Without the second proof, File.Replace would happily replace a planted
        symlink or hard link at the manifest name - and while that would not damage the file on the
        other end, it would mean this commit was writing over an object nobody verified.

        The marker comes off LAST, after the committed file has been read back through the same
        bound path, because an in-memory stamp proves nothing about what survived on disk. A false
        return therefore leaves the directory protected - the correct end state for a package that is
        gone and a backup that is not provably recoverable.

        It rewrites the object THIS run built rather than re-reading the file. Measured on both
        hosts: ConvertFrom-Json leaves an ISO-8601 string alone on Windows PowerShell 5.1 but parses
        it into a [datetime] on PowerShell 7, so a read-modify-write would round-trip CreatedUtc
        through a different type on one host and could rewrite it in another form.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Manifest
    )

    $stagingName = $script:BackupManifestName + '.commit'
    $manifestPath = Get-WacLongPath -Path (Join-Path -Path $Path -ChildPath $script:BackupManifestName)
    $stagingPath = Get-WacLongPath -Path (Join-Path -Path $Path -ChildPath $stagingName)

    # The manifest this is about to replace, proved to be an ordinary file reachable under this name
    # alone. A read that comes back anything but 'Read' stops the commit before the staging file is
    # even created.
    $existing = Read-WacDriverBackupControlFile -Path $Path -Name $script:BackupManifestName
    if ($existing.Kind -cne 'Read') { return $false }

    # A staging file left by a commit that was killed between the write and the replace is THIS
    # tool's own leftover, and the create below is collision-failing, so without this a crash there
    # would make every later retry fail forever. It is removed through the same verified-then-unlink
    # path as any other record, so a planted link, hard link or directory at the name is refused
    # instead - and the create then collides with it, which fails the commit closed.
    [void](Remove-WacDriverBackupControlFile -Path $Path -Name $stagingName)

    $Manifest.DeletedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $staged = Write-WacDriverBackupControlFile -Path $Path -Name $stagingName -Content ($Manifest | ConvertTo-Json -Depth 6)
    if (-not $staged.Ok) { return $false }

    try {
        try { [System.IO.File]::Replace($stagingPath, $manifestPath, $null) }
        catch {
            [System.IO.File]::Delete($manifestPath)
            [System.IO.File]::Move($stagingPath, $manifestPath)
        }
    }
    catch {
        try { [System.IO.File]::Delete($stagingPath) } catch { $null = $_ }
        return $false
    }

    $committed = $null
    $readBack = Read-WacDriverBackupControlFile -Path $Path -Name $script:BackupManifestName
    if ($readBack.Kind -cne 'Read') { return $false }
    try { $committed = $readBack.Text | ConvertFrom-Json -ErrorAction Stop }
    catch { return $false }

    if ($null -eq $committed) { return $false }
    if (@($committed.PSObject.Properties.Name) -cnotcontains 'DeletedUtc') { return $false }
    if ([string]::IsNullOrWhiteSpace([string]$committed.DeletedUtc)) { return $false }

    return (Clear-WacDriverBackupDeletePending -Path $Path)
}

# ---------------------------------------------------------------------------------------------
# The pre-relocation root
# ---------------------------------------------------------------------------------------------

function Test-WacLegacyDriverBackupRootUnresolved {
    <#
    .SYNOPSIS
        Reports whether the pre-relocation backup root still holds anything. It is never read,
        moved, committed or deleted.
    .DESCRIPTION
        The backup root moved to %SystemRoot%\Logs because %ProgramData% carries an inherited
        BUILTIN\Users grant no healthy install can shed - so the old location is, by the same
        argument, a directory whose contents cannot be trusted. Both halves of that follow:

          IT MUST BE DETECTED. An unresolved deletion left in the old root is the only copy of a
          package that may already be gone, and nothing in the new root will ever mention it. Left
          undetected it is forgotten for the life of the machine, and this step would go on
          reporting clean runs over the top of it.

          IT MUST NOT BE BELIEVED. Reading a manifest there to decide whether the deletion was
          resolved would be deciding on exactly the evidence that is not trustworthy, and moving or
          committing one would be acting on it. So this counts ENTRIES and stops: no file is opened,
          nothing is written, nothing is removed. A directory that is a reparse point is not even
          enumerated - following it would leave the location entirely.

        THE RECOVERY RULE, because a durable non-success needs an action that ends it: an operator
        inspects the directory by hand, recovers or discards each export in it, and removes the
        directory. There is no automatic migration and there is deliberately not going to be one -
        the whole reason the location changed is that this tool cannot establish who wrote what is
        in it.
    .OUTPUTS
        Unresolved / Path / EntryCount / Detail.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $result = [PSCustomObject]@{ Unresolved = $false; Path = [string]$Path; EntryCount = 0; Detail = '' }

    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }
    if (-not (Test-Path -LiteralPath $Path)) { return $result }

    if (Test-WacIsReparsePoint -Path $Path) {
        $result.Unresolved = $true
        $result.Detail = ('The pre-relocation driver backup root {0} is a reparse point, so what it holds cannot be established; inspect and clear it by hand. Nothing there was read, moved or removed.' -f $Path)
        return $result
    }

    try {
        $info = New-Object System.IO.DirectoryInfo((Get-WacLongPath -Path $Path))
        # Names only, one level, no recursion into anything: this is a count, not an inspection.
        $result.EntryCount = @($info.EnumerateFileSystemInfos()).Count
    }
    catch {
        $result.Unresolved = $true
        $result.Detail = ('The pre-relocation driver backup root {0} could not be listed ({1}), so an unresolved deletion left there cannot be ruled out; inspect and clear it by hand.' -f $Path, (Get-WacIoFailureKind -ErrorRecord $_))
        return $result
    }

    if ($result.EntryCount -le 0) { return $result }

    $result.Unresolved = $true
    $result.Detail = ('The pre-relocation driver backup root {0} still holds {1} entry(ies), which may include the only copy of an already-deleted package; recover or discard them by hand and remove the directory. Nothing there was read, moved or removed.' -f $Path, $result.EntryCount)
    return $result
}

# ---------------------------------------------------------------------------------------------
# Cross-run reconciliation
# ---------------------------------------------------------------------------------------------

function Resolve-WacDriverBackupPending {
    <#
    .SYNOPSIS
        Settles the deletion attempts an earlier run recorded but could not prove, against the store
        as it is NOW. Returns the counts it contributed and the directories it has spoken for.
    .DESCRIPTION
        A pending marker means pnputil was asked to remove a package and nobody established what
        happened. Reboot-required is the ordinary way to get there: 3010 and 1641 say the removal
        finishes at the next restart, so the run that saw them cannot observe it at all.

        WHY IT RUNS IN THE PRUNE STEP, after the store has been enumerated and before the candidate
        list is used. The two ways a restart can end up are on opposite sides of the per-candidate
        loop, so neither of them can be handled inside it:

          the package went   - it is no longer enumerated, so it is no longer a candidate and
                               nothing in that loop would ever reach its directory again. Its marker
                               and its unstamped manifest would outlive the deletion they record for
                               the life of the machine, and a recovery tool would read the only copy
                               of a removed package as an export that never finished.
          the package stayed - it IS a candidate again, and Export-WacDriverBackup refuses a
                               directory carrying an unresolved attempt. Left to the loop, a known
                               pending state would become a SecurityRefusal on every later run.

        So the directories are settled first, and the ones still unresolved are withheld from the
        loop by name. Nothing here re-exports or re-deletes anything: only a store postcondition of
        Removed may commit, clear and count one, and Present or Unknown keep the export, keep the
        marker and report Incomplete.

        It asks Test-WacDriverPackageRemoved rather than re-reading the enumeration this step
        already has, so the Removed/Present/Unknown rule lives in exactly one place. That costs one
        extra enumeration per pending directory, which is zero on every healthy run: a marker only
        exists while a deletion attempt is unresolved.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$PnpUtil,
        [Parameter(Mandatory = $true)][string]$BackupRoot,
        [string]$Component = 'DriverPrune'
    )

    $result = [PSCustomObject]@{
        Count = 0; Deleted = 0; Incomplete = 0; Refused = 0; Failed = 0; Outcome = 'Succeeded'; Held = @()
    }
    $held = New-Object 'System.Collections.Generic.List[string]'

    $child = @()
    try {
        $info = New-Object System.IO.DirectoryInfo((Get-WacLongPath -Path $BackupRoot))
        $child = @($info.EnumerateDirectories() | ForEach-Object { [string]$_.Name })
    }
    catch {
        # A root that cannot be listed has not been shown to hold nothing, and an unresolved
        # deletion it hides is exactly the state that must not be forgotten.
        $result.Incomplete = 1
        $result.Outcome = 'Incomplete'
        Write-WacLog -Level WARNING -Component $Component -Message 'The driver backup root could not be listed, so an earlier unresolved deletion cannot be ruled out.' -Data @{
            root = $BackupRoot; kind = (Get-WacIoFailureKind -ErrorRecord $_)
        }
        return $result
    }

    foreach ($name in $child) {
        $path = Join-Path -Path $BackupRoot -ChildPath $name
        if (-not (Test-WacDriverBackupDeletePending -Path $path)) { continue }

        $result.Count++
        [void]$held.Add($name)

        # Asked in its own right and BEFORE its manifest is read, for the reason Export-WacDriverBackup
        # gives: a directory a standard user can rewrite must not be allowed to name the package
        # this run then confirms and commits. The walk answers for the ancestor CHAIN, which the
        # handle-bound proof deliberately says nothing about; the strict proof of the directory
        # itself is taken by every read below, through its own handle.
        $trust = Test-WacStatePathIsTrusted -Path $path
        if (-not $trust.IsTrusted) {
            $result.Refused++
            $result.Outcome = Get-WacHigherOutcome -Current $result.Outcome -Candidate 'SecurityRefusal'
            Write-WacLog -Level ERROR -Component $Component -Message 'An unresolved deletion attempt sits in a directory that is not machine-trusted; it was left untouched.' -Data @{
                directory = $path; reason = [string]$trust.Reason
            }
            continue
        }

        $manifest = $null
        $record = Read-WacDriverBackupControlFile -Path $path -Name $script:BackupManifestName
        if ($record.Kind -ceq 'Read') {
            try { $manifest = $record.Text | ConvertFrom-Json -ErrorAction Stop }
            catch { $manifest = $null }
        }

        $driverName = ''
        if ($null -ne $manifest -and (@($manifest.PSObject.Properties.Name) -ccontains 'DriverName')) {
            $driverName = [string]$manifest.DriverName
        }

        if ([string]::IsNullOrWhiteSpace($driverName)) {
            # An attempt that cannot even name its package can be neither settled nor reclaimed by
            # any rule: it may be the only copy of something that is gone, and nothing on disk says
            # what. That is the state Test-WacDriverBackupIsResidue already refuses through
            # Export-WacDriverBackup, and it keeps refusing here rather than being downgraded to a
            # merely incomplete run just because this function looked at the directory first.
            $result.Refused++
            $result.Outcome = Get-WacHigherOutcome -Current $result.Outcome -Candidate 'SecurityRefusal'
            Write-WacLog -Level ERROR -Component $Component -Message 'An unresolved deletion attempt carries no readable package name, so it cannot be settled automatically.' -Data @{
                directory = $path; manifest = [string]$record.Kind
            }
            continue
        }

        $confirm = Test-WacDriverPackageRemoved -PnpUtil $PnpUtil -DriverName $driverName `
            -TimeoutMs (Get-WacStepTimeoutMs -RequestedMs $script:PnpUtilTimeoutMs) -Component $Component

        if ([string]$confirm.State -cne 'Removed') {
            # Present means the restart has not happened or did not remove it; Unknown means the
            # store could not be read. Both keep the export and the marker, and both are Incomplete:
            # the attempt is still unresolved and only a later Removed may ever settle it.
            $result.Incomplete++
            $result.Outcome = Get-WacHigherOutcome -Current $result.Outcome -Candidate 'Incomplete'
            Write-WacLog -Level WARNING -Component $Component -Message 'An earlier deletion attempt is still unresolved against the driver store.' -Data @{
                driver = $driverName; directory = $path; state = [string]$confirm.State; reason = [string]$confirm.Reason
            }
            continue
        }

        # Read back off disk, so the two hosts must be normalised before it is written again:
        # ConvertFrom-Json leaves an ISO-8601 string alone on Windows PowerShell 5.1 and parses it
        # into a [datetime] on PowerShell 7, and Complete-WacDriverBackup serialises the object it
        # is handed. Without this the commit would rewrite CreatedUtc in a different form on one
        # host - the same trap Complete-WacDriverBackup avoids by never re-reading its own file.
        foreach ($stampName in @('CreatedUtc', 'DeletedUtc')) {
            if (@($manifest.PSObject.Properties.Name) -cnotcontains $stampName) { continue }
            if ($manifest.$stampName -is [datetime]) {
                $manifest.$stampName = ([datetime]$manifest.$stampName).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
        }

        if (-not (Complete-WacDriverBackup -Path $path -Manifest $manifest)) {
            $result.Failed++
            $result.Outcome = Get-WacHigherOutcome -Current $result.Outcome -Candidate 'Failed'
            Write-WacLog -Level ERROR -Component $Component -Message 'A package proved gone could not have its backup committed; the export is protected and needs manual recovery.' -Data @{
                driver = $driverName; directory = $path
            }
            continue
        }

        $result.Deleted++
        Write-WacLog -Level INFO -Component $Component -Message 'An earlier deletion is now proved against the store; its backup was committed.' -Data @{
            driver = $driverName; directory = $path
        }
    }

    $result.Held = @($held.ToArray())
    return $result
}
