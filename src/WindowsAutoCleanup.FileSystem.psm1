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

    THE DELETION RACE, AND WHY IT IS NOW CLOSED AT THE LEAF. Read this before changing anything.

    THREAT MODEL, decided once and in scope: a local standard user who can write into an
    allow-listed target IS an attacker this code defends against. That is not hypothetical - the
    tool runs as SYSTEM and the default Windows Temp grants BUILTIN\Users write.

    Every leaf is now removed by Invoke-WacBoundDelete (WindowsAutoCleanup.BoundDelete.ps1), which
    opens ONE handle, proves on that handle that it still resolves to the intended path, and sets
    the disposition on the SAME handle. There is no second resolution of the name for an attacker to
    win. Two predecessors were not enough: verifying once per DIRECTORY left a window of roughly
    twelve seconds per three thousand entries, and verifying per leaf but then deleting BY PATHNAME
    still left the sub-millisecond gap between the check returning and the kernel resolving the same
    name again. Managed code cannot express this - measured on both hosts, zero File/Directory
    overloads accept a SafeFileHandle - so the delete goes through
    NtSetInformationFile(FileDispositionInformation) in WacNative.

    So, precisely:
      * GUARANTEED - the object deleted is the object whose identity was proved. A redirection that
        is in place at any point up to and including the delete makes the handle resolve elsewhere,
        and the operation is refused and counted as a refusal, not a skip. A reparse point is exempt
        from the proof by design: it is opened with FILE_FLAG_OPEN_REPARSE_POINT and the LINK is
        removed, never its target.
      * STILL PATHNAME-BASED - ENUMERATION. Children are still discovered by walking the parent's
        path, so an ancestor swapped mid-sweep can change which children are FOUND.
        Test-WacDirectorySafeToDescend re-verifies before descending, and any leaf reached through a
        swap fails the handle-bound identity proof and is refused rather than deleted. The
        consequence of losing that race is therefore a wrong REFUSAL, never a wrong deletion.

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
      * a read-only object is unlinked through the disposition that tolerates the attribute,
        so nothing is left behind AND nothing shared with its other hard links is rewritten;
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

# Test seam for the handle-bound delete; $null means use the real native call.
$script:BoundDeleteOverride = $null

. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.BoundDelete.ps1')

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
        NOT FOR AN ALLOW-LISTED CLEANUP TARGET, and no longer used by one. Both calls here resolve
        $LongPath from the volume root, which is a fresh, unbound resolution of a name any caller
        that is defending against an ancestor swap has just spent a handle proving. The cleanup
        path gave this up entirely: DeleteBoundLeaf tolerates the read-only attribute on the handle
        it already proved, so it never needs the attribute changed at all.

        What is left is the deployment tree (Remove-WacDeploymentEntry), whose paths sit under the
        SYSTEM-owned protected deployment root rather than in a user-writable target, and which
        deletes with File.Delete - an API that has no handle-bound form to move to. The one thing
        that can be tightened without a containment proof is done below: a reparse point is refused
        outright, because a write aimed at a link must never be allowed to land on its target.

        A future caller over user-writable content must use the bound delete, not this.
    #>
    param([Parameter(Mandatory = $true)][string]$LongPath)

    try {
        $attributes = [System.IO.File]::GetAttributes($LongPath)
        $blocking = [System.IO.FileAttributes]::ReadOnly -bor
                    [System.IO.FileAttributes]::Hidden -bor
                    [System.IO.FileAttributes]::System

        # A link's attributes are not this tool's to change, and SetAttributes offers no documented
        # no-follow form, so the target could be what actually gets written.
        if (([int]$attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }

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

        The delete is handle-bound: DeleteBoundLeaf opens the parent, proves the parent's identity
        on that handle, opens the leaf RELATIVE to it, and sets the disposition on the leaf handle.
        There is no second resolution of the name for an attacker to win. This paragraph used to
        describe the predecessor - verify, then delete by pathname - and outlived it.

        It is one call and one attempt. There used to be two, because a read-only leaf came back
        Denied and the second attempt followed a pathname attribute rewrite that nothing had
        proved; the bound delete absorbs the read-only case itself now, so the retry has no work
        left to do and the unbound window it opened is gone with it.
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

    # Every check above is a STRING comparison, and a string cannot notice that an ancestor
    # directory was replaced by a junction since it was last verified. The delete below closes that
    # for good: DeleteBoundLeaf opens ONE handle, proves on that handle that it still resolves to
    # the path we intend, and sets the disposition on the SAME handle. There is no second name
    # resolution for an attacker to win, which is what the predecessor - verify, close, delete by
    # pathname - still left open however small the window became.
    #
    # A reparse point is NO LONGER exempt from the identity proof, and the exemption was a hole.
    # Skipping it looked right - resolving a link is exactly what must not happen when the link is
    # the thing being removed - but FILE_FLAG_OPEN_REPARSE_POINT only stops the FINAL component
    # being followed. Every intermediate still resolves, so a swapped ancestor redirected the open
    # to a different link entirely and it was unlinked. The parent is proved first and the leaf is
    # opened relative to that handle, which keeps the link unresolved AND the ancestry proved.
    $longPath = Get-WacLongPath -Path $normalized
    $expected = $normalized

    $win32 = 0
    $ntStatus = 0
    $code = Invoke-WacBoundDelete -LongPath $longPath -ExpectedFinalPath $expected `
        -OpenReparsePoint:$IsReparsePoint -Win32Error ([ref]$win32) -NtStatus ([ref]$ntStatus)

    if ($code -eq 0) {
        if ($IsReparsePoint) { $Stats.ReparsePointsDeleted++ }
        elseif ($IsDirectory) { $Stats.DirectoriesDeleted++ }
        else {
            $Stats.FilesDeleted++
            $Stats.BytesDeleted += $Length
        }
        return
    }

    $kind = Get-WacBoundDeleteKind -Code $code -Win32Error $win32 -NtStatus $ntStatus

    if ($kind -eq 'NotFound') {
        # Something else removed it first. That is the desired end state, not a failure.
        $Stats.SkippedVanished++
        return
    }

    if ($kind -eq 'Identity') {
        # An object that simply disappeared between enumeration and deletion also fails to
        # resolve, and that is the desired end state rather than a redirection attempt. Separate
        # the two so an ordinary race is not reported - or exit-coded - as a security refusal.
        if (Test-WacPathVanished -NormalizedPath $normalized) { $Stats.SkippedVanished++ }
        else { $Stats.RefusedIdentity++ }
        return
    }

    if ($kind -eq 'Denied') {
        # Denied now only ever means the delete itself could not be performed on the handle that
        # was proved - a DACL, or a volume that will not honour the read-only-tolerant disposition.
        # The predecessor answered it by clearing ReadOnly/Hidden/System through the PATHNAME,
        # after both proved handles had already closed, so an ancestor swapped in between
        # redirected that WRITE onto a different object; and because attributes belong to the FILE
        # rather than to the directory entry, doing it through an allow-listed hard link mutated
        # the file under its outside names as well. DeleteBoundLeaf now retries the disposition
        # itself with FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE on the handle it has already
        # proved, so nothing here resolves the name a second time and no metadata is written at
        # all. Whatever cannot be removed that way is left on disk and counted right here.
        $Stats.SkippedDenied++
        return
    }

    if ($kind -eq 'NotEmpty') {
        # Children were locked or refused; the retry pass picks the directory up again.
        $Stats.SkippedNotEmpty++
        return
    }

    if ($kind -eq 'Busy') {
        # Open in another process. That used to be queued for deletion at the next boot; it is
        # not any more - Session Manager resolves the stored NAME hours later, which nothing
        # checked here can bind. See the module header. It stays until its owner exits.
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

    # A sweep DELETES. It must not start while an earlier mutator this run could not prove stopped
    # might still be writing into the same tree, so the same latch that stops the next driver
    # candidate stops the next file pass.
    if (-not (Test-WacMutationAllowed)) {
        $stats.SkippedDeadline++
        Write-WacLog -Level ERROR -Component 'FileSystem' -Message 'A cleanup target was skipped: an earlier operation could not be proven stopped.' -Data @{ category = $Category; path = $normalizedRoot }
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

    # The counter restarted at 0 here, and the deadline is only consulted on every 256th entry, so a
    # sweep that had ALREADY run the budget out was followed by up to 255 more deletions before this
    # phase asked the question once. The budget is a promise about when mutation stops, and "255
    # directories after expiry" is not that promise. Asking once on entry costs a single clock read
    # and makes the phase honour a deadline that expired before it started; the periodic check below
    # still bounds overshoot within the phase.
    $checked = 0
    $alreadyExpired = Test-WacDeadlineExpired
    foreach ($directory in $directories) {
        if ($alreadyExpired -or ((++$checked % $script:DeadlineCheckInterval) -eq 0 -and (Test-WacDeadlineExpired))) {
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
        # Both passes above can break out on expiry, so finishing the tree off here would be work
        # done past the budget - and this is the one place where "it is almost done anyway" is most
        # tempting to wave through. The root is a mutation like any other: it asks the clock first.
        if (Test-WacDeadlineExpired) {
            $stats.SkippedDeadline++
        }
        elseif ((Test-WacIsSafeTargetPath -Path $normalizedRoot) -and -not (Test-WacIsProtectedPath -Path $normalizedRoot)) {
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

    # The matched-file loop is bounded exactly like the traversal, and for the same reason: one
    # pattern over one never-cleaned directory can match more files than the rest of the run
    # touches, and a check placed per PATTERN cannot see time pass inside a single one of them.
    # Counting ENTRIES is what makes the bound real. Enumerating lazily rather than materialising
    # GetFiles puts the enumeration itself inside that bound too, at the cost of the throw moving
    # from the call into the loop - which is why the body now carries the same catch the sweep does.
    $counter = 0
    $expired = $false

    foreach ($singlePattern in $Pattern) {
        if ($expired) { break }
        if (Test-WacDeadlineExpired) { $stats.SkippedDeadline++; break }

        $matched = $null
        try {
            $info = New-Object System.IO.DirectoryInfo((Get-WacLongPath -Path $normalizedRoot))
            $matched = $info.EnumerateFiles($singlePattern)
        }
        catch {
            $kind = Get-WacIoFailureKind -ErrorRecord $_
            if ($kind -eq 'Denied') { $stats.SkippedDenied++ }
            elseif ($kind -eq 'NotFound') { $stats.SkippedVanished++ }
            else { $stats.Failed++ }
            continue
        }

        try {
            foreach ($file in $matched) {
                if ((++$counter % $script:DeadlineCheckInterval) -eq 0 -and (Test-WacDeadlineExpired)) {
                    $stats.SkippedDeadline++
                    $expired = $true
                    break
                }

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
        catch {
            # Lazy enumeration can throw partway through the sequence, not only at creation.
            $kind = Get-WacIoFailureKind -ErrorRecord $_
            if ($kind -eq 'Denied') { $stats.SkippedDenied++ }
            elseif ($kind -eq 'NotFound') { $stats.SkippedVanished++ }
            else { $stats.Failed++ }
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
    'Write-WacTreeResult', 'Get-WacBoundDeleteKind', 'Set-WacBoundDeleteOverride'
)
