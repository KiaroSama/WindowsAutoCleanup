<#
.SYNOPSIS
    The small CONTROL files that decide what a later run is allowed to do, in a store where nobody
    but an administrator can create a name.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Core.psm1. It is the file half of the quarantine, split out of
    WindowsAutoCleanup.Quarantine.ps1 because the two answer different questions: that file decides
    what an abandoned mutator MEANS, and this one decides how a record of it may be written, read
    and retired at all.

    WHY IT EXISTS (ledger WAC-14). The marker used to live directly under Get-WacDataRoot, and this
    project's own state-trust rule explicitly PERMITS a non-administrative principal to create new
    names there - %ProgramData% carries an inherited BUILTIN\Users:(CI)(WD,AD,WEA,WA) that every
    child inherits and no healthy install can shed. For an audit log a planted name is noise. For a
    file that decides whether the next run may change this machine it is the decision itself. Worse,
    the writer checked only the FINAL name for a reparse point and then wrote a predictable
    `<name>.new` with no check at all, so a link preplanted at the temporary name was written
    through to wherever it pointed before the swap was ever attempted.

    THE THREE PROPERTIES THAT REPLACE THAT, none of them a second pathname check:

      * A STRICT STORE. Get-WacControlRoot is under %SystemRoot%\Logs, measured to carry no
        non-administrative writer, and the directory is opened through Open-WacTrustedDirectory with
        -RequireStrictTrust: the owner and DACL are read from the HANDLE of the object that was
        really opened, the volume must be a local fixed disk, and the handle withholds DELETE so
        the directory cannot be renamed out from under the files while it is held.

      * NO TEMPORARY NAME AT ALL. There is no `.new`, no `.last` and no replace. A write is one
        collision-failing create bound to the directory handle: an existing name - ordinary file,
        directory, symlink, junction or extra hard link - comes back as a COLLISION and is never
        opened, truncated, appended to or followed. The temporary-name attack surface is not
        guarded, it is absent. A collision also means a record is already there, which for this
        store is the answer rather than a problem: the machine is already quarantined.

      * READS ARE JUDGED FROM THE HANDLE. Open-WacBoundFile refuses a reparse point (bound as the
        link, never followed) and a multi-link file (NumberOfLinks above 1 means these bytes are
        reachable under a name somebody else chose - the case a reparse check misses entirely).

    ABSENCE IS PROVEN, NOT INFERRED. `Test-Path -PathType Leaf` answering false covers "nothing is
    there", "a directory is there", "the probe was denied" and "a dangling link is there" with one
    word, and only the first of those may license mutating a machine. The open's own outcome
    separates them: Missing is absence, everything else is Unreadable.
#>

$script:ControlStoreMaxCreate = 4

function Open-WacControlStore {
    <#
    .SYNOPSIS
        Opens the control directory and pins it. The caller MUST close the handle it returns.
    .OUTPUTS
        The Open-WacTrustedDirectory verdict: IsTrusted, Handle, FinalPath, Reason, Writers.
    #>
    $root = Get-WacControlRoot
    if ([string]::IsNullOrWhiteSpace($root)) {
        return [PSCustomObject]@{
            IsTrusted = $false; Handle = [IntPtr]::Zero; FinalPath = $null
            Reason = 'the control-file root could not be resolved'; Writers = @(); Created = @()
        }
    }

    return (Open-WacTrustedDirectory -Path $root -RequireStrictTrust -MaxCreate $script:ControlStoreMaxCreate)
}

function Test-WacControlStorePresence {
    <#
    .SYNOPSIS
        Whether the control directory is THERE, asked without needing to trust it.
    .OUTPUTS
        Absent | Present | Unknown.
    .DESCRIPTION
        This is what keeps a fail-closed rule from becoming a fail-shut one. "The store could not be
        proven" and "the store does not exist" are different facts, and only the first can be hiding
        a record: a container that is not there has never held anything, so its absence IS proven
        absence of every record in it. Without this distinction a machine whose %SystemRoot%\Logs
        carried an unexpected descriptor would stop cleaning anything, for ever, on the strength of a
        record that could not exist.

        Answered by Get-WacPathPresence, the one inspection in this project that separates the two.
        This probe used to ask Directory.Exists about the root's PARENT, which answers false for
        "denied" exactly as it does for "not there" - so a %SystemRoot%\Logs whose own parent
        refused an attribute read reported a store that is really there as Absent, and Absent is
        what licenses clearing a quarantine. The shared probe classifies by the exception a single
        enumeration THROWS instead: DirectoryNotFoundException is the container genuinely not being
        there, and denial, a security refusal or an I/O error are not answers at all.
    #>
    $root = Get-WacControlRoot
    if ([string]::IsNullOrWhiteSpace($root)) { return 'Unknown' }

    $presence = [string](Get-WacPathPresence -Path $root)
    if ($presence -ceq 'Present') { return 'Present' }
    if ($presence -ceq 'Absent') { return 'Absent' }
    return 'Unknown'
}

function Write-WacControlFile {
    <#
    .SYNOPSIS
        Records one control file. Never overwrites, never follows, never uses a temporary name.
    .DESCRIPTION
        'Present' is a SUCCESS for this store, and the distinction is deliberate: these files say
        "something is unresolved on this machine", so a second run finding the first run's record
        still there has exactly the fact it was going to write. Overwriting it would only discard
        the older, more conservative evidence.
    .OUTPUTS
        Kind ('Created' | 'Present' | 'Failed') and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content
    )

    $result = [PSCustomObject]@{ Kind = 'Failed'; Reason = '' }

    $store = Open-WacControlStore
    if (-not $store.IsTrusted) {
        $result.Reason = ('the control store could not be proven administrative: {0}' -f [string]$store.Reason)
        if ($store.Handle -ne [IntPtr]::Zero) { [void](Close-WacTrustedDirectory -Handle $store.Handle) }
        return $result
    }

    try {
        $created = New-WacBoundFile -DirectoryHandle $store.Handle -Name $Name

        if ([string]$created.Kind -ceq 'Collision') {
            $result.Kind = 'Present'
            $result.Reason = 'a control file of this name is already recorded'
            return $result
        }
        if ([string]$created.Kind -cne 'Created') {
            $result.Reason = ('the control file could not be created (status 0x{0:X8})' -f [int]$created.NtStatus)
            return $result
        }

        try {
            $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Content)
            $created.Stream.Write($bytes, 0, $bytes.Length)
            $created.Stream.Flush()
            $result.Kind = 'Created'
            $result.Reason = 'the control file was created and written'
        }
        catch {
            $result.Reason = ('the control file was created but could not be written: {0}' -f $_.Exception.Message)
        }
        finally {
            try { $created.Stream.Dispose() } catch { $null = $_ }
        }
    }
    finally {
        [void](Close-WacTrustedDirectory -Handle $store.Handle)
    }

    return $result
}

function Read-WacControlFile {
    <#
    .SYNOPSIS
        The text of one control file. Three answers, never two.
    .OUTPUTS
        State ('Absent' | 'Valid' | 'Unreadable'), Text and Reason.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)

    $result = [PSCustomObject]@{ State = 'Unreadable'; Text = ''; Reason = '' }

    $store = Open-WacControlStore
    if (-not $store.IsTrusted) {
        if ($store.Handle -ne [IntPtr]::Zero) { [void](Close-WacTrustedDirectory -Handle $store.Handle) }

        # A store that is NOT THERE has never held a record, so this is proven absence rather than
        # an unresolved inspection - and the difference is what stops a machine that simply has no
        # control directory yet from refusing to clean anything for ever.
        if ([string](Test-WacControlStorePresence) -ceq 'Absent') {
            $result.State = 'Absent'
            $result.Reason = 'the control store does not exist, so no control file has ever been recorded in it'
            return $result
        }

        # It IS there and could not be proven, so its contents cannot be ruled out.
        $result.Reason = ('the control store could not be proven administrative: {0}' -f [string]$store.Reason)
        return $result
    }

    try {
        $opened = Open-WacBoundFile -DirectoryHandle $store.Handle -Name $Name

        switch ([string]$opened.Kind) {
            'Missing' {
                $result.State = 'Absent'
                $result.Reason = 'no control file of this name exists in the store'
                return $result
            }
            'Opened' {
                try {
                    $reader = New-Object System.IO.StreamReader($opened.Stream, (New-Object System.Text.UTF8Encoding($false)))
                    try { $result.Text = $reader.ReadToEnd() } finally { $reader.Dispose() }
                    $result.State = 'Valid'
                    $result.Reason = 'the control file was read from its own handle'
                }
                catch {
                    $result.Reason = ('the control file could not be read: {0}' -f $_.Exception.Message)
                }
                finally {
                    try { $opened.Stream.Dispose() } catch { $null = $_ }
                }
                return $result
            }
            default {
                # Refused (a reparse point or an extra hard link) or Failed. Both are unresolved
                # inspections, and an unresolved inspection is not an absence.
                $result.Reason = ('the control file could not be bound: {0}' -f [string]$opened.Reason).Trim()
                return $result
            }
        }
    }
    finally {
        [void](Close-WacTrustedDirectory -Handle $store.Handle)
    }
}

function Remove-WacControlFile {
    <#
    .SYNOPSIS
        Retires one control file. $true only when it is PROVEN gone.
    .DESCRIPTION
        Absence counts as retired - there is nothing left to act on either way. Anything else is
        reported false, because a caller that believes a record was retired when it was not is
        exactly how uncertainty gets lost.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)

    $store = Open-WacControlStore
    if (-not $store.IsTrusted) {
        if ($store.Handle -ne [IntPtr]::Zero) { [void](Close-WacTrustedDirectory -Handle $store.Handle) }
        return $false
    }

    try {
        # Asked FIRST, so a genuine absence is not confused with a delete that could not open its
        # target - Invoke-WacBoundDelete reports both as "could not open".
        $present = Open-WacBoundFile -DirectoryHandle $store.Handle -Name $Name
        if ([string]$present.Kind -ceq 'Missing') { return $true }
        if ([string]$present.Kind -cne 'Opened') { return $false }
        try { $present.Stream.Dispose() } catch { $null = $_ }

        # By PATH, and the reason that is sound here rather than anywhere else: the leaf was just
        # proven through its own handle to be an ordinary, single-linked, non-reparse file, and the
        # directory it sits in is pinned by a handle that withholds DELETE, so it cannot be renamed
        # or replaced while this runs. What remains is an administrator racing the delete inside a
        # store only administrators can write to - which is not the actor this store defends
        # against. Invoke-WacBoundDelete would close even that, but it belongs to the FileSystem
        # package and reaching it from here would mean exporting the sweep's own test seam.
        $target = Join-Path -Path ([string]$store.FinalPath) -ChildPath $Name
        try {
            [System.IO.File]::Delete((Get-WacLongPath -Path $target))
            return $true
        }
        catch { return $false }
    }
    finally {
        [void](Close-WacTrustedDirectory -Handle $store.Handle)
    }
}

function Test-WacLegacyControlFile {
    <#
    .SYNOPSIS
        Whether a control file written by a build before the store moved is still sitting in the
        old, non-administrative location.
    .DESCRIPTION
        PRESENCE only, and the answer is deliberately three-valued. Its contents are never read and
        it is never deleted: the reason that location stopped being the store is that anyone could
        create a name there, so believing what is in it would be believing exactly the evidence the
        move exists to distrust - and deleting it would throw away a real operator's real
        uncertainty on the strength of the same distrust.
    .OUTPUTS
        Absent | Present | Unknown.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)

    $root = Get-WacLegacyControlRoot
    if ([string]::IsNullOrWhiteSpace($root)) { return 'Absent' }

    # Get-WacPathPresence rather than Test-Path or a bare Directory.Exists: it answers for a
    # directory or a link at the name just as it does for a file, and it keeps "the old root could
    # not be read" apart from "the old root has nothing in it". The version before this one asked
    # Directory.Exists about the root and read false as absence - which is also what a denied
    # %ProgramData% answers, and an absence here is what lets a run out of quarantine.
    $presence = [string](Get-WacPathPresence -Path (Join-Path -Path $root -ChildPath $Name))
    if ($presence -ceq 'Present') { return 'Present' }
    if ($presence -ceq 'Absent') { return 'Absent' }
    return 'Unknown'
}
