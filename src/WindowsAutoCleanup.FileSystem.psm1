<#
.SYNOPSIS
    The single no-follow deletion primitive used by every cleanup target.

.DESCRIPTION
    One traversal, one leaf-deletion routine, one set of rules. The previous version had two
    independent deletion paths with different safety checks, which is how a reparse-point root could
    be rejected in one and accepted in the other.

    Safety model, in order:
      1. the root must normalise, live on the target drive, be a safe (non-protected) target, exist,
         and prove by handle that it resolves to itself;
      2. every directory is re-verified by handle before it is descended into, and every leaf is
         re-verified by handle immediately before it is deleted;
      3. a reparse point found during traversal is deleted as a LEAF - the link is removed, its
         target is never touched, and it is never descended into;
      4. nothing that normalised and then failed a containment test is passed to a delete call.

    WHAT THE HANDLE CHECKS DO AND DO NOT GUARANTEE. Read this before changing them.

    Every delete here is issued BY PATHNAME, and every check is a SEPARATE pathname resolution, so
    the checks cannot be race-free. .NET exposes no delete that takes a handle and no open that is
    relative to a directory handle - measured on both hosts (PowerShell 5.1 / .NET Framework
    4.0.30319 and PowerShell 7.6.5 / .NET 10): zero File/Directory overloads accept a SafeFileHandle,
    zero accept a root-directory handle, and FileOptions.DeleteOnClose (the only handle-bound delete
    managed code has) cannot open a directory or a file another process holds without FILE_SHARE.
    A genuinely handle-relative design needs NtOpenFile with RootDirectory in OBJECT_ATTRIBUTES plus
    NtSetInformationFile(FileDispositionInformation), which is native code this module does not own.

    So, precisely:
      * GUARANTEED - a redirection that is already in place when the check runs, or that persists
        past it, is caught: the handle-verified final path will not equal the requested path and the
        operation is refused and counted as a refusal, not a skip.
      * NOT GUARANTEED - a redirection installed INSIDE the window between the check returning and
        the kernel resolving the same name for the delete. That window is narrow, not absent:
        measured over 2000 leaves per host it is at most 0.66 ms at p99 (0.39 ms on 5.1, 0.66 ms on
        7.6.5) and 2.8 ms worst observed, where the upper bound charges the ENTIRE File.Delete call
        to the attacker. The predecessor design verified once per DIRECTORY and left a window of
        roughly twelve seconds per three thousand entries, so this is four orders of magnitude
        narrower - and still not zero. Do not describe it as closed.

    DELAYED DELETION IS DISABLED HERE. MoveFileEx(..., MOVEFILE_DELAY_UNTIL_REBOOT) stores the
    literal path STRING; Session Manager resolves it at the next boot, hours later, before anything
    that could object is loaded. No check made at registration time binds the name that gets
    resolved then, and there is no variant of the API that binds identity instead - a locked file
    cannot be relocated to a SYSTEM-only directory first, because being unmovable is what made it
    locked. Every root this tool cleans is user-writable (see Targets.psm1), so the guard would have
    to refuse all of them anyway. What this costs, measured on a real elevated run: 43 queued items
    became skipLocked - 34 in the user's TEMP, 2 in C:\Windows\Temp, 7 under Defender Support. Those
    files stay on disk until the process holding them exits, and the next daily run removes them.

    Effectiveness model, which is what actually empties a live %TEMP%:
      * read-only / hidden / system attributes are cleared and the delete retried;
      * long paths get the \\?\ prefix so Windows PowerShell 5.1 can reach them at all;
      * directories are deleted deepest-first and retried once after the file sweep, because a
         directory that was non-empty on the first attempt is usually empty by the second.
#>

Set-StrictMode -Version 2.0

# No -Force here on purpose: force-reloading a nested module tears it out of the CALLER's session
# too, so the caller's own Core imports silently vanish. Callers import Core first, then this module.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop

# How often the traversal checks the run deadline, counted in filesystem ENTRIES. A per-DIRECTORY
# check is not a bound at all: one flat directory of a million files - exactly the never-cleaned
# %TEMP% this release exists to fix - would sweep to completion without ever looking at the clock.
# Measured throughput is 230-520 entries/s, so 256 entries is well under a second of overshoot.
$script:DeadlineCheckInterval = 256

function New-WacDeletionStats {
    <#
    .SYNOPSIS
        The per-target counters. Skips are broken out by REASON, because "486 skipped" told a user
        nothing about whether cleanup was working.
    .DESCRIPTION
        Skipped* and Refused* are deliberately separate families, because the run's exit code is
        derived from them and a counter that mixes the two cannot carry a decision.

        A Skipped* counter means "deliberately not done, and that is correct". SkippedReparse in
        particular is ORDINARY: a real elevated run on this machine reported skipReparse=3, all three
        the per-profile 'Temporary Internet Files' junction that ships on every Windows install. Any
        mapping that turned a reparse skip into a security signal would fire on every single run.

        A Refused* counter means a safety check refused to proceed on evidence: a path that
        canonicalised and then failed containment (RefusedOutOfRoot), or an identity re-check that
        failed on a path that is still there (RefusedIdentity). These are the only two counters that
        may drive a security-refusal outcome, and a clean run must produce zero of them.

        Note what is NOT a refusal: a path that will not canonicalise at all. Measured on the same
        real run, the single skipOutOfRoot it reported was C:\Users\<user>\AppData\Local\Temp\nul -
        a DOS device name, which GetFullPath resolves to \\.\nul on BOTH hosts, so
        Get-WacNormalizedPath returns $null. Nothing escaped and nothing was deleted; that stays a
        skip.
    #>
    return [PSCustomObject]@{
        FilesDeleted         = 0L
        DirectoriesDeleted   = 0L
        ReparsePointsDeleted = 0L
        BytesDeleted         = 0L
        PendingDeletes       = 0L
        SkippedLocked        = 0L
        SkippedDenied        = 0L
        SkippedNotEmpty      = 0L
        SkippedReparse       = 0L
        SkippedProtected     = 0L
        SkippedOutOfRoot     = 0L
        SkippedVanished      = 0L
        SkippedDeadline      = 0L
        RefusedIdentity      = 0L
        RefusedOutOfRoot     = 0L
        Failed               = 0L
    }
}

function Get-WacSkippedTotal {
    param([Parameter(Mandatory = $true)]$Stats)

    return [int64]($Stats.SkippedLocked + $Stats.SkippedDenied + $Stats.SkippedNotEmpty +
                   $Stats.SkippedReparse + $Stats.SkippedProtected + $Stats.SkippedOutOfRoot +
                   $Stats.SkippedVanished + $Stats.SkippedDeadline)
}

function Get-WacRefusedTotal {
    <#
    .SYNOPSIS
        The refusals only. Deliberately NOT part of Get-WacSkippedTotal: a refusal is not a skip.
    #>
    param([Parameter(Mandatory = $true)]$Stats)

    return [int64]($Stats.RefusedIdentity + $Stats.RefusedOutOfRoot)
}

function Test-WacPathVanished {
    <#
    .SYNOPSIS
        True when a path that just failed a handle check is simply GONE rather than redirected.
    .DESCRIPTION
        Every handle check in Core reports "could not be opened" and "resolves somewhere else" with
        the same $false, so without this the ordinary race of another process removing its own temp
        directory would be recorded - and, through the run's exit code, reported to the user - as a
        security refusal. Existence is tested through the long-path form because a >MAX_PATH path is
        unreachable from Windows PowerShell 5.1 otherwise, and would read as vanished.

        [System.IO.Path]::Exists is deliberately not used: it does not exist on .NET Framework.
    #>
    param([Parameter(Mandatory = $true)][string]$NormalizedPath)

    $long = Get-WacLongPath -Path $NormalizedPath
    return (-not [System.IO.File]::Exists($long) -and -not [System.IO.Directory]::Exists($long))
}

function Clear-WacBlockingAttribute {
    <#
    .SYNOPSIS
        Strips ReadOnly/Hidden/System so a delete that failed on attributes can succeed.
    .DESCRIPTION
        This is the single biggest reason a temp sweep leaves files behind: File.Delete throws
        UnauthorizedAccessException on a read-only file, and the old code counted that as "skipped"
        without ever trying to clear the attribute.
    #>
    param([Parameter(Mandatory = $true)][string]$LongPath)

    try {
        $attributes = [System.IO.File]::GetAttributes($LongPath)
        $blocking = [System.IO.FileAttributes]::ReadOnly -bor
                    [System.IO.FileAttributes]::Hidden -bor
                    [System.IO.FileAttributes]::System

        if (([int]$attributes -band [int]$blocking) -eq 0) { return $false }

        [System.IO.File]::SetAttributes($LongPath, ([System.IO.FileAttributes]([int]$attributes -band -bnot [int]$blocking)))
        return $true
    }
    catch {
        return $false
    }
}

function Remove-WacLeaf {
    <#
    .SYNOPSIS
        Deletes exactly one file, empty directory, or reparse point, and records why if it cannot.
    .DESCRIPTION
        Never recursive. A reparse point is removed with the non-recursive Directory.Delete /
        File.Delete pair rather than Remove-Item, which throws a spurious NullReferenceException on
        some junctions under Windows PowerShell 5.1.

        The delete is issued BY PATHNAME and the identity check below is a separate resolution of
        that same name, so this is a narrow window, not a closed one. See the module header for the
        measured size and for why no handle-bound alternative exists on the supported surface.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)]$Stats,
        [switch]$IsDirectory,
        [switch]$IsReparsePoint,
        [int64]$Length = 0
    )

    # A path that will not canonicalise is not an escape: nothing resolved, so nothing could have
    # been redirected. The measured real-world case is a file named 'nul'. It stays a plain skip.
    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { $Stats.SkippedOutOfRoot++; return }

    # These two DID canonicalise and then failed containment, which is the shape of an escape and
    # nothing else. They are the counters a security-refusal outcome is allowed to key off.
    if (-not (Test-WacIsWithinRoot -ChildPath $normalized -RootPath $RootPath)) { $Stats.RefusedOutOfRoot++; return }
    if (-not (Test-WacIsOnTargetDrive -Path $normalized)) { $Stats.RefusedOutOfRoot++; return }
    if (Test-WacIsProtectedPath -Path $normalized) { $Stats.SkippedProtected++; return }

    # Every check above is a STRING comparison, and a string cannot notice that an ancestor directory
    # was replaced by a junction since the last time it was verified. Verifying once per directory
    # left a window as long as that directory took to sweep, so the resolution is re-proved here,
    # immediately before the delete, for anything that is not itself a link. This does not make the
    # delete atomic with its check - it makes the window sub-millisecond instead of multi-second.
    #
    # A reparse point is exempt because resolving it is the whole point of deleting it: the link is
    # removed by name and its target is never touched.
    if (-not $IsReparsePoint -and -not (Test-WacFinalPathMatches -NormalizedPath $normalized)) {
        # An object that simply disappeared between enumeration and deletion also fails to open, and
        # that is the desired end state rather than a redirection attempt. Separate the two so an
        # ordinary race is not reported - or exit-coded - as a security refusal.
        if (Test-WacPathVanished -NormalizedPath $normalized) { $Stats.SkippedVanished++ }
        else { $Stats.RefusedIdentity++ }
        return
    }

    $longPath = Get-WacLongPath -Path $normalized

    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        try {
            if ($IsDirectory -or $IsReparsePoint) {
                if ($IsDirectory) { [System.IO.Directory]::Delete($longPath, $false) }
                else { [System.IO.File]::Delete($longPath) }
            }
            else {
                [System.IO.File]::Delete($longPath)
            }

            if ($IsReparsePoint) { $Stats.ReparsePointsDeleted++ }
            elseif ($IsDirectory) { $Stats.DirectoriesDeleted++ }
            else {
                $Stats.FilesDeleted++
                $Stats.BytesDeleted += $Length
            }
            return
        }
        catch {
            # if/elseif rather than switch: `break` and `continue` inside a switch that sits inside a
            # loop are ambiguous in PowerShell, and getting that wrong here would either skip the
            # attribute-clearing retry or loop forever.
            $kind = Get-WacIoFailureKind -ErrorRecord $_

            if ($kind -eq 'NotFound') {
                # Something else removed it first. That is the desired end state, not a failure.
                $Stats.SkippedVanished++
                return
            }

            if ($kind -eq 'Denied') {
                if ($attempt -eq 0 -and (Clear-WacBlockingAttribute -LongPath $longPath)) { continue }
                $Stats.SkippedDenied++
                return
            }

            if ($kind -eq 'Busy') {
                # For a directory this means "not empty" (children were locked); the retry pass picks
                # it up. For a file it means the file is open in another process. That used to be
                # queued for deletion at the next boot; it is not any more - Session Manager resolves
                # the stored NAME hours later, which nothing checked here can bind. See the module
                # header. The file simply stays until its owner exits and the next run takes it.
                if ($IsDirectory -and -not $IsReparsePoint) {
                    $Stats.SkippedNotEmpty++
                    return
                }

                $Stats.SkippedLocked++
                return
            }

            $Stats.Failed++
            return
        }
    }
}

function Test-WacDirectorySafeToDescend {
    <#
    .SYNOPSIS
        Re-proves, immediately before descending, that a directory is still the object we expect.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RootPath
    )

    if (-not (Test-WacIsWithinRoot -ChildPath $Path -RootPath $RootPath)) { return $false }
    if (Test-WacIsReparsePoint -Path $Path) { return $false }
    if (-not (Test-WacPathResolvesToItself -Path $Path)) { return $false }

    return $true
}

function Invoke-WacTreeSweep {
    <#
    .SYNOPSIS
        One depth-first pass: deletes files and links, and returns the directories found, deepest first.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)]$Stats
    )

    $directories = New-Object 'System.Collections.Generic.List[string]'
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Root)
    $counter = 0

    $expired = $false

    while ($stack.Count -gt 0 -and -not $expired) {
        $current = $stack.Pop()

        if (Test-WacDeadlineExpired) {
            $Stats.SkippedDeadline++
            break
        }

        if (-not (Test-WacDirectorySafeToDescend -Path $current -RootPath $Root)) {
            # Nothing that is a reparse point is ever pushed onto this stack - the entry loop below
            # deletes those as leaves - so a directory that fails here has CHANGED since it was
            # enumerated. Two ways that happens: another process removed it, which is an ordinary
            # race, or something re-pointed it, which is not. Only the second is a refusal.
            if (Test-WacPathVanished -NormalizedPath $current) { $Stats.SkippedVanished++ }
            else { $Stats.RefusedIdentity++ }
            continue
        }

        $entries = $null
        try {
            $info = New-Object System.IO.DirectoryInfo((Get-WacLongPath -Path $current))
            $entries = $info.EnumerateFileSystemInfos()
        }
        catch {
            $kind = Get-WacIoFailureKind -ErrorRecord $_
            if ($kind -eq 'Denied') { $Stats.SkippedDenied++ }
            elseif ($kind -eq 'NotFound') { $Stats.SkippedVanished++ }
            else { $Stats.Failed++ }
            continue
        }

        try {
            foreach ($entry in $entries) {
                if ((++$counter % $script:DeadlineCheckInterval) -eq 0 -and (Test-WacDeadlineExpired)) {
                    $Stats.SkippedDeadline++
                    $expired = $true
                    break
                }

                $entryPath = Get-WacNormalizedPath -Path $entry.FullName
                if (-not $entryPath) { $Stats.SkippedOutOfRoot++; continue }

                # Enumerating a directory inside the root handed back a path that is NOT inside it.
                # There is no benign way for that to happen.
                if (-not (Test-WacIsWithinRoot -ChildPath $entryPath -RootPath $Root)) {
                    $Stats.RefusedOutOfRoot++
                    continue
                }

                # A protected root (the checkout, the deployment, the log directory) can legitimately
                # live INSIDE a cleanup target. Skip that subtree and keep cleaning around it rather
                # than abandoning the whole target.
                if (Test-WacIsProtectedSubtree -Path $entryPath) {
                    $Stats.SkippedProtected++
                    continue
                }

                $attributes = 0
                try { $attributes = [int]$entry.Attributes } catch { $attributes = 0 }

                if (($attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    # Delete the link itself. Its target is never touched and never descended into.
                    Remove-WacLeaf -Path $entryPath -RootPath $Root -Stats $Stats `
                        -IsDirectory:($entry -is [System.IO.DirectoryInfo]) -IsReparsePoint
                    continue
                }

                if ($entry -is [System.IO.DirectoryInfo]) {
                    [void]$directories.Add($entryPath)
                    $stack.Push($entryPath)
                }
                else {
                    $length = 0L
                    try { $length = [int64]$entry.Length } catch { $length = 0L }
                    Remove-WacLeaf -Path $entryPath -RootPath $Root -Stats $Stats -Length $length
                }
            }
        }
        catch {
            # Lazy enumeration can throw partway through the sequence, not only at creation.
            $kind = Get-WacIoFailureKind -ErrorRecord $_
            if ($kind -eq 'Denied') { $Stats.SkippedDenied++ }
            elseif ($kind -eq 'NotFound') { $Stats.SkippedVanished++ }
            else { $Stats.Failed++ }
        }
    }

    # Descending ORDINAL order puts every child ahead of its parent, so an empty tree collapses in a
    # single pass. Sort-Object is culture-sensitive and the two hosts do not always agree on the
    # order for the same input, so sort the array directly with an ordinal comparer.
    $ordered = $directories.ToArray()
    [array]::Sort($ordered, [System.StringComparer]::OrdinalIgnoreCase)
    [array]::Reverse($ordered)
    return @($ordered)
}

function Remove-WacTree {
    <#
    .SYNOPSIS
        Deletes the contents of one allow-listed directory, and optionally the directory itself.
    .OUTPUTS
        A result object carrying the per-reason counters. Never throws for an expected condition.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$DeleteRoot
    )

    $stats = New-WacDeletionStats
    $normalizedRoot = Get-WacNormalizedPath -Path $Path

    if (-not $normalizedRoot -or -not (Test-WacIsSafeTargetPath -Path $normalizedRoot)) {
        Write-WacLog -Level WARNING -Component 'FileSystem' -Message 'Refused an unsafe cleanup target.' -Data @{ category = $Category; path = $Path }
        $stats.SkippedOutOfRoot++
        return (New-WacTreeResult -Category $Category -Path $Path -Stats $stats -Attempted $false)
    }

    if (-not (Test-Path -LiteralPath $normalizedRoot -PathType Container)) {
        return (New-WacTreeResult -Category $Category -Path $normalizedRoot -Stats $stats -Attempted $false)
    }

    if (Test-WacIsReparsePoint -Path $normalizedRoot) {
        Write-WacLog -Level INFO -Component 'FileSystem' -Message 'Skipped a reparse-point root; following it could redirect deletion outside the allow-list.' -Data @{ category = $Category; path = $normalizedRoot }
        $stats.SkippedReparse++
        return (New-WacTreeResult -Category $Category -Path $normalizedRoot -Stats $stats -Attempted $false)
    }

    if (-not (Test-WacPathResolvesToItself -Path $normalizedRoot)) {
        # Unlike the reparse-point root above, this one is not routine: the target existed a moment
        # ago and now resolves somewhere else. A target that merely disappeared in between is the
        # ordinary race and is recorded as such, silently.
        if (Test-WacPathVanished -NormalizedPath $normalizedRoot) {
            $stats.SkippedVanished++
        }
        else {
            Write-WacLog -Level WARNING -Component 'FileSystem' -Message 'Refused a root whose final path does not match the requested path.' -Data @{ category = $Category; path = $normalizedRoot }
            $stats.RefusedIdentity++
        }
        return (New-WacTreeResult -Category $Category -Path $normalizedRoot -Stats $stats -Attempted $false)
    }

    if (Test-WacDeadlineExpired) {
        $stats.SkippedDeadline++
        return (New-WacTreeResult -Category $Category -Path $normalizedRoot -Stats $stats -Attempted $false)
    }

    Write-WacLog -Level DEBUG -Component 'FileSystem' -Message 'Cleaning target.' -Data @{ category = $Category; path = $normalizedRoot }

    $directories = Invoke-WacTreeSweep -Root $normalizedRoot -Stats $stats

    # Pass 1: delete the directories we found, deepest first.
    $retry = New-Object 'System.Collections.Generic.List[string]'
    $checked = 0
    foreach ($directory in $directories) {
        if ((++$checked % $script:DeadlineCheckInterval) -eq 0 -and (Test-WacDeadlineExpired)) {
            $stats.SkippedDeadline++
            break
        }
        $before = $stats.SkippedNotEmpty
        Remove-WacLeaf -Path $directory -RootPath $normalizedRoot -Stats $stats -IsDirectory
        if ($stats.SkippedNotEmpty -gt $before) { [void]$retry.Add($directory) }
    }

    # Pass 2: a directory that was non-empty a moment ago is usually empty now, because the file
    # sweep and any late handle release have caught up. Queue whatever is still stuck for reboot.
    foreach ($directory in $retry) {
        if (Test-WacDeadlineExpired) { $stats.SkippedDeadline++; break }
        $stats.SkippedNotEmpty--
        Remove-WacLeaf -Path $directory -RootPath $normalizedRoot -Stats $stats -IsDirectory
    }

    if ($DeleteRoot) {
        if ((Test-WacIsSafeTargetPath -Path $normalizedRoot) -and -not (Test-WacIsProtectedPath -Path $normalizedRoot)) {
            Remove-WacLeaf -Path $normalizedRoot -RootPath $normalizedRoot -Stats $stats -IsDirectory
        }
        else {
            $stats.SkippedOutOfRoot++
        }
    }

    return (New-WacTreeResult -Category $Category -Path $normalizedRoot -Stats $stats -Attempted $true)
}

function Remove-WacFilesByPattern {
    <#
    .SYNOPSIS
        Deletes only the files in one directory matching the given patterns. Never recursive.
    .DESCRIPTION
        Used for the shell cache databases, where the surrounding directory holds live state that
        must survive. It applies the same root, reparse-point and handle checks as Remove-WacTree;
        the previous pattern path had none of them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Pattern
    )

    $stats = New-WacDeletionStats
    $normalizedRoot = Get-WacNormalizedPath -Path $Path

    if (-not $normalizedRoot -or -not (Test-WacIsSafeTargetPath -Path $normalizedRoot)) {
        Write-WacLog -Level WARNING -Component 'FileSystem' -Message 'Refused an unsafe pattern target.' -Data @{ category = $Category; path = $Path }
        $stats.SkippedOutOfRoot++
        return (New-WacTreeResult -Category $Category -Path $Path -Stats $stats -Attempted $false)
    }

    if (-not (Test-Path -LiteralPath $normalizedRoot -PathType Container)) {
        return (New-WacTreeResult -Category $Category -Path $normalizedRoot -Stats $stats -Attempted $false)
    }

    # Split, not fused. These two conditions used to share one counter, and they are not the same
    # event: a pattern root that IS a reparse point is routine (every profile ships one), whereas a
    # pattern root that is not a link and still resolves elsewhere is a redirection.
    if (Test-WacIsReparsePoint -Path $normalizedRoot) {
        Write-WacLog -Level INFO -Component 'FileSystem' -Message 'Skipped a reparse-point pattern root; following it could redirect deletion outside the allow-list.' -Data @{ category = $Category; path = $normalizedRoot }
        $stats.SkippedReparse++
        return (New-WacTreeResult -Category $Category -Path $normalizedRoot -Stats $stats -Attempted $false)
    }

    if (-not (Test-WacPathResolvesToItself -Path $normalizedRoot)) {
        if (Test-WacPathVanished -NormalizedPath $normalizedRoot) {
            $stats.SkippedVanished++
        }
        else {
            Write-WacLog -Level WARNING -Component 'FileSystem' -Message 'Refused a pattern root whose final path does not match the requested path.' -Data @{ category = $Category; path = $normalizedRoot }
            $stats.RefusedIdentity++
        }
        return (New-WacTreeResult -Category $Category -Path $normalizedRoot -Stats $stats -Attempted $false)
    }

    Write-WacLog -Level DEBUG -Component 'FileSystem' -Message 'Cleaning pattern target.' -Data @{ category = $Category; path = $normalizedRoot; patterns = ($Pattern -join ',') }

    foreach ($singlePattern in $Pattern) {
        if (Test-WacDeadlineExpired) { $stats.SkippedDeadline++; break }

        $matched = $null
        try {
            $info = New-Object System.IO.DirectoryInfo((Get-WacLongPath -Path $normalizedRoot))
            $matched = @($info.GetFiles($singlePattern))
        }
        catch {
            $kind = Get-WacIoFailureKind -ErrorRecord $_
            if ($kind -eq 'Denied') { $stats.SkippedDenied++ }
            elseif ($kind -eq 'NotFound') { $stats.SkippedVanished++ }
            else { $stats.Failed++ }
            continue
        }

        foreach ($file in $matched) {
            $filePath = Get-WacNormalizedPath -Path $file.FullName
            if (-not $filePath) { $stats.SkippedOutOfRoot++; continue }
            if (-not (Test-WacIsWithinRoot -ChildPath $filePath -RootPath $normalizedRoot)) {
                $stats.RefusedOutOfRoot++
                continue
            }

            $attributes = 0
            try { $attributes = [int]$file.Attributes } catch { $attributes = 0 }
            if (($attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                Remove-WacLeaf -Path $filePath -RootPath $normalizedRoot -Stats $stats -IsReparsePoint
                continue
            }

            $length = 0L
            try { $length = [int64]$file.Length } catch { $length = 0L }
            Remove-WacLeaf -Path $filePath -RootPath $normalizedRoot -Stats $stats -Length $length
        }
    }

    return (New-WacTreeResult -Category $Category -Path $normalizedRoot -Stats $stats -Attempted $true)
}

function New-WacTreeResult {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Stats,
        [Parameter(Mandatory = $true)][bool]$Attempted
    )

    return [PSCustomObject]@{
        Category             = $Category
        Path                 = $Path
        Attempted            = $Attempted
        FilesDeleted         = [int64]$Stats.FilesDeleted
        DirectoriesDeleted   = [int64]$Stats.DirectoriesDeleted
        ReparsePointsDeleted = [int64]$Stats.ReparsePointsDeleted
        BytesDeleted         = [int64]$Stats.BytesDeleted
        # Always 0 since delayed deletion was disabled (see the module header). The field is kept so
        # the orchestrator's summary and the Recycle Bin step keep binding; drop it once both do.
        PendingDeletes       = [int64]$Stats.PendingDeletes
        SkippedLocked        = [int64]$Stats.SkippedLocked
        SkippedDenied        = [int64]$Stats.SkippedDenied
        SkippedNotEmpty      = [int64]$Stats.SkippedNotEmpty
        SkippedReparse       = [int64]$Stats.SkippedReparse
        SkippedProtected     = [int64]$Stats.SkippedProtected
        SkippedOutOfRoot     = [int64]$Stats.SkippedOutOfRoot
        SkippedVanished      = [int64]$Stats.SkippedVanished
        SkippedDeadline      = [int64]$Stats.SkippedDeadline
        Skipped              = (Get-WacSkippedTotal -Stats $Stats)
        RefusedIdentity      = [int64]$Stats.RefusedIdentity
        RefusedOutOfRoot     = [int64]$Stats.RefusedOutOfRoot
        # The single field a caller needs to decide the security-refusal outcome for this target.
        Refused              = (Get-WacRefusedTotal -Stats $Stats)
        Failed               = [int64]$Stats.Failed
    }
}

function Write-WacTreeResult {
    <#
    .SYNOPSIS
        Emits one result line. Skip reasons are only printed when they are non-zero, so a clean
        target stays a single short line and a problem target says exactly what blocked it.
    #>
    param([Parameter(Mandatory = $true)]$Result)

    $data = [ordered]@{
        category = $Result.Category
        path     = $Result.Path
        files    = $Result.FilesDeleted
        dirs     = $Result.DirectoriesDeleted
        bytes    = $Result.BytesDeleted
    }

    if ($Result.ReparsePointsDeleted -gt 0) { $data['links'] = $Result.ReparsePointsDeleted }
    if ($Result.PendingDeletes -gt 0) { $data['queuedForReboot'] = $Result.PendingDeletes }
    if ($Result.SkippedLocked -gt 0) { $data['skipLocked'] = $Result.SkippedLocked }
    if ($Result.SkippedDenied -gt 0) { $data['skipDenied'] = $Result.SkippedDenied }
    if ($Result.SkippedNotEmpty -gt 0) { $data['skipNotEmpty'] = $Result.SkippedNotEmpty }
    if ($Result.SkippedReparse -gt 0) { $data['skipReparse'] = $Result.SkippedReparse }
    if ($Result.SkippedProtected -gt 0) { $data['skipProtected'] = $Result.SkippedProtected }
    if ($Result.SkippedOutOfRoot -gt 0) { $data['skipOutOfRoot'] = $Result.SkippedOutOfRoot }
    if ($Result.SkippedVanished -gt 0) { $data['skipVanished'] = $Result.SkippedVanished }
    if ($Result.SkippedDeadline -gt 0) { $data['skipDeadline'] = $Result.SkippedDeadline }
    if ($Result.RefusedIdentity -gt 0) { $data['refusedIdentity'] = $Result.RefusedIdentity }
    if ($Result.RefusedOutOfRoot -gt 0) { $data['refusedOutOfRoot'] = $Result.RefusedOutOfRoot }
    if ($Result.Failed -gt 0) { $data['failed'] = $Result.Failed }

    # A refusal is louder than a skip and is never routine, so it lifts the line to WARNING even when
    # the target otherwise completed cleanly.
    $level = if ($Result.Failed -gt 0 -or $Result.Refused -gt 0) { 'WARNING' } else { 'INFO' }
    Write-WacLog -Level $level -Component 'Result' -Message 'Target complete.' -Data ([hashtable]$data)
}

Export-ModuleMember -Function @(
    'New-WacDeletionStats', 'Get-WacSkippedTotal', 'Get-WacRefusedTotal', 'Test-WacPathVanished',
    'Clear-WacBlockingAttribute', 'Remove-WacLeaf', 'Test-WacDirectorySafeToDescend',
    'Invoke-WacTreeSweep', 'Remove-WacTree', 'Remove-WacFilesByPattern', 'New-WacTreeResult',
    'Write-WacTreeResult'
)
