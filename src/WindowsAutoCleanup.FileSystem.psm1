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
      2. every directory is re-verified by handle before it is descended into, so a junction swapped
         in mid-traversal is caught rather than followed;
      3. a reparse point found during traversal is deleted as a LEAF - the link is removed, its
         target is never touched, and it is never descended into;
      4. nothing outside the root is ever passed to a delete call.

    Effectiveness model, which is what actually empties a live %TEMP%:
      * read-only / hidden / system attributes are cleared and the delete retried;
      * long paths get the \\?\ prefix so Windows PowerShell 5.1 can reach them at all;
      * a locked file is queued for deletion at the next boot instead of being silently skipped;
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
        Failed               = 0L
    }
}

function Get-WacSkippedTotal {
    param([Parameter(Mandatory = $true)]$Stats)

    return [int64]($Stats.SkippedLocked + $Stats.SkippedDenied + $Stats.SkippedNotEmpty +
                   $Stats.SkippedReparse + $Stats.SkippedProtected + $Stats.SkippedOutOfRoot +
                   $Stats.SkippedVanished + $Stats.SkippedDeadline)
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
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)]$Stats,
        [switch]$IsDirectory,
        [switch]$IsReparsePoint,
        [int64]$Length = 0,
        [switch]$NoPendingDelete
    )

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { $Stats.SkippedOutOfRoot++; return }
    if (-not (Test-WacIsWithinRoot -ChildPath $normalized -RootPath $RootPath)) { $Stats.SkippedOutOfRoot++; return }
    if (-not (Test-WacIsOnTargetDrive -Path $normalized)) { $Stats.SkippedOutOfRoot++; return }
    if (Test-WacIsProtectedPath -Path $normalized) { $Stats.SkippedProtected++; return }

    # Every check above is a STRING comparison, and a string cannot notice that an ancestor directory
    # was replaced by a junction since the last time it was verified. Verifying once per directory
    # leaves a window as long as that directory takes to sweep, so the resolution is re-proved here,
    # immediately before the delete, for anything that is not itself a link.
    #
    # A reparse point is exempt because resolving it is the whole point of deleting it: the link is
    # removed by name and its target is never touched.
    if (-not $IsReparsePoint -and -not (Test-WacFinalPathMatches -NormalizedPath $normalized)) {
        # An object that simply disappeared between enumeration and deletion also fails to open, and
        # that is the desired end state rather than a redirection attempt. Separate the two so the
        # log does not report an ordinary race as a security refusal.
        $longCheck = Get-WacLongPath -Path $normalized
        if (-not [System.IO.File]::Exists($longCheck) -and -not [System.IO.Directory]::Exists($longCheck)) {
            $Stats.SkippedVanished++
        }
        else {
            $Stats.SkippedReparse++
        }
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

                if (-not $NoPendingDelete -and (Register-WacDeleteOnReboot -Path $normalized)) {
                    $Stats.PendingDeletes++
                }
                else {
                    $Stats.SkippedDenied++
                }
                return
            }

            if ($kind -eq 'Busy') {
                # For a directory this means "not empty" (children were locked); the retry pass picks
                # it up. For a file it means the file is open in another process, which is exactly
                # what delete-on-reboot exists for.
                if ($IsDirectory -and -not $IsReparsePoint) {
                    $Stats.SkippedNotEmpty++
                    return
                }

                if (-not $NoPendingDelete -and (Register-WacDeleteOnReboot -Path $normalized)) {
                    $Stats.PendingDeletes++
                }
                else {
                    $Stats.SkippedLocked++
                }
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
            $Stats.SkippedReparse++
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
                if (-not $entryPath -or -not (Test-WacIsWithinRoot -ChildPath $entryPath -RootPath $Root)) {
                    $Stats.SkippedOutOfRoot++
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
                        -IsDirectory:($entry -is [System.IO.DirectoryInfo]) -IsReparsePoint -NoPendingDelete
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
        Write-WacLog -Level WARNING -Component 'FileSystem' -Message 'Refused a root whose final path does not match the requested path.' -Data @{ category = $Category; path = $normalizedRoot }
        $stats.SkippedReparse++
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
        Remove-WacLeaf -Path $directory -RootPath $normalizedRoot -Stats $stats -IsDirectory -NoPendingDelete
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
            Remove-WacLeaf -Path $normalizedRoot -RootPath $normalizedRoot -Stats $stats -IsDirectory -NoPendingDelete
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

    if ((Test-WacIsReparsePoint -Path $normalizedRoot) -or -not (Test-WacPathResolvesToItself -Path $normalizedRoot)) {
        Write-WacLog -Level INFO -Component 'FileSystem' -Message 'Skipped a reparse-point or redirected pattern root.' -Data @{ category = $Category; path = $normalizedRoot }
        $stats.SkippedReparse++
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
            if (-not $filePath -or -not (Test-WacIsWithinRoot -ChildPath $filePath -RootPath $normalizedRoot)) {
                $stats.SkippedOutOfRoot++
                continue
            }

            $attributes = 0
            try { $attributes = [int]$file.Attributes } catch { $attributes = 0 }
            if (($attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                Remove-WacLeaf -Path $filePath -RootPath $normalizedRoot -Stats $stats -IsReparsePoint -NoPendingDelete
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
    if ($Result.Failed -gt 0) { $data['failed'] = $Result.Failed }

    $level = if ($Result.Failed -gt 0) { 'WARNING' } else { 'INFO' }
    Write-WacLog -Level $level -Component 'Result' -Message 'Target complete.' -Data ([hashtable]$data)
}

Export-ModuleMember -Function @(
    'New-WacDeletionStats', 'Get-WacSkippedTotal', 'Clear-WacBlockingAttribute',
    'Remove-WacLeaf', 'Test-WacDirectorySafeToDescend', 'Invoke-WacTreeSweep',
    'Remove-WacTree', 'Remove-WacFilesByPattern', 'New-WacTreeResult', 'Write-WacTreeResult'
)
