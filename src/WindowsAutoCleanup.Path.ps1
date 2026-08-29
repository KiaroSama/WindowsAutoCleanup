<#
.SYNOPSIS
    Path safety: canonicalisation, the protected-root registry, handle-verified resolution, and the
    delete-on-reboot queue.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Core.psm1; see that file for why the parts are dot-sourced
    rather than imported. Every path comparison and every "may this be deleted" decision in the
    project routes through this file, which is why the fixed roots are cached and the hot-path
    handle check is flattened.

    $script:TargetDrive is declared here because the target drive is a path concept, but it is read
    by Test-WacSystemDriveSupported in WindowsAutoCleanup.Environment.ps1 as well; all parts share
    one session state, so that read is the same variable, not a copy.
#>

$script:TargetDrive         = 'C:'
$script:ProtectedRoots      = New-Object 'System.Collections.Generic.List[string]'
$script:PendingDeleteWarned = $false

# ---------------------------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------------------------

function Get-WacNormalizedPath {
    <#
    .SYNOPSIS
        Canonicalises a path to 'X:' or 'X:\some\path' with no trailing separator, or $null.
    .DESCRIPTION
        Every path comparison in this project routes through this one function. Mixing it with
        Resolve-Path is a real defect: GetFullPath expands 8.3 short names and Resolve-Path does not,
        which is invisible on a long-profile developer machine and breaks on an 8.3 CI runner.
        UNC, device, volume-GUID and drive-relative forms are rejected outright: none can ever be a
        valid C: cleanup target, and drive-relative forms resolve against a mutable per-drive
        working directory.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    # A name whose final component ends in a dot or a space cannot be canonicalised without
    # changing WHICH OBJECT it names, so it is refused here rather than resolved into a different
    # file. Win32 path normalisation strips both during preprocessing, and GetFullPath below
    # performs it: measured on PowerShell 7.6.5/.NET 10, 'note.txt.' comes back as 'note.txt'.
    # That is not a cosmetic difference. Before this guard, asking Remove-WacLeaf to delete
    # 'note.txt.' deleted 'note.txt' and recorded FilesDeleted=1 - a wrong object, destroyed by a
    # SYSTEM process, reported as success. The handle-bound identity proof could not catch it
    # because expectedFinalPath was normalised through this same function, so both sides of the
    # comparison were corrupted identically and matched.
    #
    # Refusing costs a real thing: such an entry is never cleaned, and it survives every run. That
    # is the same trade already taken for locked files, and it is the right way round - the
    # alternative is deleting a neighbour that was never enumerated. Only \\?\ opens reach these
    # names, and every comparison in this project is done on the canonical form this function
    # returns, so there is nowhere safe to carry the literal name to.
    #
    # '.' and '..' are navigation rather than names; GetFullPath resolves them correctly and they
    # are left alone. A trailing separator is also normal and is handled further down.
    $finalComponent = $Path.TrimEnd([char[]]@('\', '/'))
    $separator = $finalComponent.LastIndexOfAny([char[]]@('\', '/'))
    if ($separator -ge 0) { $finalComponent = $finalComponent.Substring($separator + 1) }
    if ($finalComponent -ne '.' -and $finalComponent -ne '..' -and $finalComponent -match '[. ]$') {
        return $null
    }

    $candidate = $Path.Trim()

    if ($candidate.StartsWith('\\?\', [System.StringComparison]::OrdinalIgnoreCase)) {
        if ($candidate -match '^\\\\\?\\([A-Za-z]:\\.*)$') { $candidate = $Matches[1] }
        elseif ($candidate -match '^\\\\\?\\([A-Za-z]:)\\?$') { return $Matches[1].ToUpperInvariant() }
        else { return $null }
    }

    if ($candidate -match '^[A-Za-z]:$') { return $candidate.ToUpperInvariant() }
    if ($candidate -match '^[A-Za-z]:(?!\\)') { return $null }
    if ($candidate.StartsWith('\\')) { return $null }

    try {
        $full = [System.IO.Path]::GetFullPath($candidate)
    }
    catch {
        return $null
    }

    if ($full -notmatch '^[A-Za-z]:\\') { return $null }

    $trimmed = $full.TrimEnd('\')
    if ($trimmed -match '^[A-Za-z]:$') { return $trimmed.ToUpperInvariant() }
    return ($trimmed.Substring(0, 2).ToUpperInvariant() + $trimmed.Substring(2))
}

function Get-WacLongPath {
    <#
    .SYNOPSIS
        Adds the \\?\ extended-length prefix when a path is long enough to need it.
    .DESCRIPTION
        Windows PowerShell 5.1 runs on .NET Framework, which throws PathTooLongException above
        MAX_PATH unless the prefix is used. The prefix disables all further normalisation, so it is
        only ever applied to an already fully-normalised absolute drive path.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path.Length -lt 240) { return $Path }
    if ($Path.StartsWith('\\?\', [System.StringComparison]::OrdinalIgnoreCase)) { return $Path }
    if ($Path -notmatch '^[A-Za-z]:\\') { return $Path }
    return ('\\?\' + $Path)
}

function Get-WacTargetDrive {
    return $script:TargetDrive
}

function Test-WacIsOnTargetDrive {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $false }

    return ($normalized -ieq $script:TargetDrive -or
            $normalized.StartsWith($script:TargetDrive + '\', [System.StringComparison]::OrdinalIgnoreCase))
}

function Add-WacProtectedRoot {
    <#
    .SYNOPSIS
        Registers a path cleanup must never delete, descend into, or be contained by.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return }
    foreach ($existing in $script:ProtectedRoots) {
        if ($existing -ieq $normalized) { return }
    }
    [void]$script:ProtectedRoots.Add($normalized)
}

function Clear-WacProtectedRoot {
    $script:ProtectedRoots.Clear()
}

$script:FixedProtectedRootCache = $null

function Get-WacFixedProtectedRoot {
    <#
    .SYNOPSIS
        The never-delete system roots, normalised once.
    .DESCRIPTION
        These are constants, but re-normalising all eleven on every call made Test-WacIsProtectedPath
        cost about a millisecond - measured as the single dominant per-leaf cost of a sweep, larger
        than the delete itself. Caching turns the protection check from the bottleneck into noise,
        which is what makes the per-leaf handle verification in Remove-WacLeaf affordable.
    #>
    if ($null -ne $script:FixedProtectedRootCache) { return $script:FixedProtectedRootCache }

    $roots = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @(
        'C:', 'C:\Windows', 'C:\Users', 'C:\ProgramData',
        'C:\Program Files', 'C:\Program Files (x86)',
        'C:\Windows\System32', 'C:\Windows\SysWOW64',
        'C:\Windows\WinSxS', 'C:\Windows\System32\DriverStore',
        'C:\$Recycle.Bin'
    )) {
        $p = Get-WacNormalizedPath -Path $item
        if ($p) { [void]$roots.Add($p) }
    }

    $script:FixedProtectedRootCache = $roots.ToArray()
    return $script:FixedProtectedRootCache
}

function Test-WacIsProtectedPath {
    <#
    .SYNOPSIS
        True when the path must never be deleted.
    .DESCRIPTION
        Protection is bidirectional for registered roots: a target equal to, inside, OR an ancestor
        of a protected root is refused. The ancestor direction is what stops a checkout living under
        %TEMP% from deleting itself while %TEMP% is being cleaned.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $true }

    foreach ($p in (Get-WacFixedProtectedRoot)) {
        if ($normalized -ieq $p) { return $true }
    }

    foreach ($root in $script:ProtectedRoots) {
        if ($normalized -ieq $root) { return $true }
        if ($normalized.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($root.StartsWith($normalized + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }

    return $false
}

function Test-WacIsProtectedSubtree {
    <#
    .SYNOPSIS
        True when the path IS a protected root or lives inside one, so nothing under it may be touched.
    .DESCRIPTION
        This is the one-directional half of the protection rule, and the distinction matters.
        Test-WacIsProtectedPath is bidirectional: it also refuses an ANCESTOR of a protected root, so
        the ancestor is never deleted. But a checkout installed under %TEMP% makes %TEMP% such an
        ancestor, and refusing the whole target there would silently stop cleaning temp altogether.
        So: a target root or a traversal entry is tested with THIS function (skip the protected
        subtree, keep cleaning everything around it), while an individual delete is tested with
        Test-WacIsProtectedPath (never delete an ancestor of a protected root either).
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $true }

    foreach ($p in (Get-WacFixedProtectedRoot)) {
        if ($normalized -ieq $p) { return $true }
    }

    foreach ($root in $script:ProtectedRoots) {
        if ($normalized -ieq $root) { return $true }
        if ($normalized.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }

    return $false
}

function Test-WacIsSafeTargetPath {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $false }
    if (-not (Test-WacIsOnTargetDrive -Path $normalized)) { return $false }
    if (Test-WacIsProtectedSubtree -Path $normalized) { return $false }

    return $true
}

function Test-WacIsWithinRoot {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$ChildPath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$RootPath
    )

    $child = Get-WacNormalizedPath -Path $ChildPath
    $root = Get-WacNormalizedPath -Path $RootPath
    if (-not $child -or -not $root) { return $false }

    return ($child -ieq $root -or $child.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase))
}

function Get-WacFinalPath {
    <#
    .SYNOPSIS
        Handle-verified final path, or $null when the object cannot be opened.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Initialize-WacNative)) { return $null }

    try {
        # Always follow. Only that direction has documented semantics; the no-follow answer is
        # undocumented, so nothing here may depend on it.
        $raw = [WacNative]::GetFinalPath((Get-WacLongPath -Path $Path), $true)
    }
    catch {
        return $null
    }

    if (-not $raw) { return $null }
    return (Get-WacNormalizedPath -Path $raw)
}

function Test-WacFinalPathMatches {
    <#
    .SYNOPSIS
        Fast handle check: does this ALREADY-NORMALISED path still resolve to itself?
    .DESCRIPTION
        Same guarantee as Test-WacPathResolvesToItself, but flattened for the hot path. The nested
        advanced-function calls in the general version cost about 1.5 ms per call, which is far too
        much to pay once per deleted file; this version does one P/Invoke and one ordinal compare and
        the caller guarantees the input is already normalised.

        This is the check that closes the junction-swap race properly. Verifying once per DIRECTORY
        leaves a window that is as long as the directory takes to sweep - measured at roughly 12
        seconds for 3000 entries - during which an attacker who can write to an allow-listed target
        (C:\Windows\Temp grants BUILTIN\Users write by default) can replace the directory with a
        junction and have every subsequent delete resolve through it as SYSTEM.

        A path that cannot be opened returns $false, so callers fail closed.
    #>
    param([Parameter(Mandatory = $true)][string]$NormalizedPath)

    if (-not (Initialize-WacNative)) { return $false }

    $raw = $null
    try {
        $long = if ($NormalizedPath.Length -ge 240) { '\\?\' + $NormalizedPath } else { $NormalizedPath }
        $raw = [WacNative]::GetFinalPath($long, $true)
    }
    catch {
        return $false
    }

    if (-not $raw) { return $false }
    if ($raw.StartsWith('\\?\', [System.StringComparison]::OrdinalIgnoreCase)) { $raw = $raw.Substring(4) }

    return [string]::Equals($raw.TrimEnd('\'), $NormalizedPath, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-WacPathResolvesToItself {
    <#
    .SYNOPSIS
        Proves no component of the path is a reparse point that redirects somewhere else.
    .DESCRIPTION
        This is the junction-swap defence. It binds a handle to the object and asks Windows for that
        object's real path; a swapped component makes the answer differ from the requested path.
        A path that cannot be opened is reported as NOT self-resolving, so every caller fails closed.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $expected = Get-WacNormalizedPath -Path $Path
    if (-not $expected) { return $false }

    $final = Get-WacFinalPath -Path $expected
    if (-not $final) { return $false }

    return ($final -ieq $expected)
}

function Test-WacIsReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $attributes = [System.IO.File]::GetAttributes((Get-WacLongPath -Path $Path))
        return (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    }
    catch {
        # Unreadable attributes are an unverifiable safety condition: fail closed.
        return $true
    }
}

function Test-WacIsDeleteOnRebootAllowed {
    <#
    .SYNOPSIS
        Every guard that must pass before a path may be queued for deletion at the next boot.
    .DESCRIPTION
        Separated from Register-WacDeleteOnReboot so the decision can be asserted directly. It has to
        be: MoveFileEx only works for an administrator or LocalSystem, so on an unelevated shell the
        registration fails anyway and a test that asserts only the return value passes for the wrong
        reason - it would go green even with the guard deleted, and only turn red on an elevated CI
        runner. Testing the decision instead makes the guard verifiable at any privilege level.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $false }
    if (-not (Test-WacIsOnTargetDrive -Path $normalized)) { return $false }
    if (Test-WacIsProtectedPath -Path $normalized) { return $false }

    # The handle check is the one that matters here. MoveFileEx stores the literal path string and
    # the session manager re-resolves it at the next boot, so a path accepted now can be redirected
    # at leisure - an arbitrary delete as SYSTEM with no timing window at all.
    if (-not (Test-WacFinalPathMatches -NormalizedPath $normalized)) { return $false }

    return $true
}

function Register-WacDeleteOnReboot {
    <#
    .SYNOPSIS
        Queues a locked file or empty directory for deletion at the next boot.
    .DESCRIPTION
        The handle check here is not optional. MoveFileEx stores the literal PATH STRING in
        PendingFileRenameOperations and the session manager re-resolves it at the next boot, before
        anything is loaded that could object. Without proving the path resolves to itself now, an
        attacker who can write to an allow-listed target could get a locked file queued, then replace
        an ancestor directory with a junction at leisure and have the boot-time delete land anywhere
        - a race-free arbitrary delete as SYSTEM, with hours or days to set it up.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-WacIsDeleteOnRebootAllowed -Path $Path)) { return $false }
    $normalized = Get-WacNormalizedPath -Path $Path

    if (-not (Initialize-WacNative)) {
        if (-not $script:PendingDeleteWarned) {
            Write-WacLog -Level WARNING -Component 'FileSystem' -Message 'Pending-delete registration is unavailable; locked files are skipped instead.'
            $script:PendingDeleteWarned = $true
        }
        return $false
    }

    try {
        return [WacNative]::DeleteOnReboot((Get-WacLongPath -Path $normalized))
    }
    catch {
        return $false
    }
}

function Get-WacIoFailureKind {
    <#
    .SYNOPSIS
        Classifies an I/O failure from the error record instead of relying on a typed catch clause.
    .DESCRIPTION
        PowerShell wraps an exception thrown by a .NET METHOD in MethodInvocationException, and the
        two hosts do not agree on whether a typed `catch [T]` then matches the inner exception.
        Measured here: under Windows PowerShell 5.1, after other cases had already run in the same
        process, an IOException ("The directory is not empty") from
        [System.IO.Directory]::Delete was caught by `catch [System.UnauthorizedAccessException]`.
        That mattered: Remove-WacTree builds its retry queue from SkippedNotEmpty, so the
        misclassification silently disabled the second directory pass - one half of the
        "temp is never really emptied" defect.

        Order is load-bearing. DirectoryNotFoundException, FileNotFoundException and
        PathTooLongException all derive from IOException, so they must be tested first.
    #>
    param([Parameter(Mandatory = $true)]$ErrorRecord)

    $exception = $null
    try { $exception = $ErrorRecord.Exception } catch { $exception = $null }

    while ($exception -and
           ($exception -is [System.Management.Automation.MethodInvocationException]) -and
           $exception.InnerException) {
        $exception = $exception.InnerException
    }

    if (-not $exception) { return 'Other' }
    if ($exception -is [System.IO.DirectoryNotFoundException]) { return 'NotFound' }
    if ($exception -is [System.IO.FileNotFoundException]) { return 'NotFound' }
    if ($exception -is [System.IO.PathTooLongException]) { return 'TooLong' }
    if ($exception -is [System.UnauthorizedAccessException]) { return 'Denied' }
    if ($exception -is [System.IO.IOException]) { return 'Busy' }

    return 'Other'
}
