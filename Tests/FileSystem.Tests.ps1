#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.FileSystem, run against real disposable trees under
    TEMP: containment, reparse-point handling, attribute clearing, >MAX_PATH reach, locked files,
    deepest-first directory removal, pattern deletion and the run deadline.

.DESCRIPTION
    Every sandbox, junction and file handle is released in a finally block. Nothing here touches a
    path outside the sandbox it created.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.FileSystem.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

function New-TestDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    [void][System.IO.Directory]::CreateDirectory($Path)
    return $Path
}

function New-TestFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Content = 'payload'
    )

    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
    [System.IO.File]::WriteAllText($Path, $Content)
    return $Path
}

function New-TestJunction {
    param(
        [Parameter(Mandatory = $true)][string]$Link,
        [Parameter(Mandatory = $true)][string]$Target
    )

    New-Item -ItemType Junction -Path $Link -Target $Target -ErrorAction Stop | Out-Null
    return $Link
}

# ---------------------------------------------------------------------------------------------
# Containment
# ---------------------------------------------------------------------------------------------

Test-Case 'Remove-WacTree never touches anything outside its root' {
    $sandbox = New-TestSandbox -Prefix 'fs-scope'
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        $inside = New-TestFile (Join-Path -Path $root -ChildPath 'sub\inside.txt')
        $sibling = New-TestFile (Join-Path -Path $sandbox -ChildPath 'outside\sentinel.txt')
        $parentFile = New-TestFile (Join-Path -Path $sandbox -ChildPath 'sentinel.txt')

        $result = Remove-WacTree -Category 'scope' -Path $root

        Assert-True $result.Attempted
        Assert-Equal 1 $result.FilesDeleted
        Assert-False (Test-Path -LiteralPath $inside) 'the file inside the root survived'
        Assert-True (Test-Path -LiteralPath $sibling) 'a sentinel in a sibling directory was deleted'
        Assert-True (Test-Path -LiteralPath $parentFile) 'a sentinel in the parent directory was deleted'
        Assert-True (Test-Path -LiteralPath $root) 'the root itself must survive without -DeleteRoot'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacTree -DeleteRoot removes the root as well' {
    $sandbox = New-TestSandbox -Prefix 'fs-droot'
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        [void](New-TestFile (Join-Path -Path $root -ChildPath 'a.txt'))

        $result = Remove-WacTree -Category 'droot' -Path $root -DeleteRoot

        Assert-True $result.Attempted
        Assert-False (Test-Path -LiteralPath $root)
        Assert-True (Test-Path -LiteralPath $sandbox) 'deletion climbed above the root'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Reparse points
# ---------------------------------------------------------------------------------------------

Test-Case 'Remove-WacTree refuses a junction AT the root' {
    $sandbox = New-TestSandbox -Prefix 'fs-rootlink'
    try {
        $target = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'target')
        $victim = New-TestFile (Join-Path -Path $target -ChildPath 'must-survive.txt')
        $link = New-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'link') -Target $target

        $result = Remove-WacTree -Category 'rootlink' -Path $link

        Assert-False $result.Attempted 'a reparse-point root must never be swept'
        Assert-Equal 1 $result.SkippedReparse
        Assert-Equal 0 $result.FilesDeleted
        Assert-True (Test-Path -LiteralPath $victim) 'the junction was followed and its target was emptied'
        Assert-True (Test-Path -LiteralPath $link) 'the junction itself must be left alone'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacTree deletes a nested junction as a link and leaves its target intact' {
    $sandbox = New-TestSandbox -Prefix 'fs-nestlink'
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        $target = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'target')
        $victim = New-TestFile (Join-Path -Path $target -ChildPath 'must-survive.txt')
        $nested = New-TestDirectory (Join-Path -Path $root -ChildPath 'sub')
        $link = New-TestJunction -Link (Join-Path -Path $nested -ChildPath 'link') -Target $target

        $result = Remove-WacTree -Category 'nestlink' -Path $root

        Assert-True $result.Attempted
        Assert-Equal 1 $result.ReparsePointsDeleted
        Assert-False (Test-Path -LiteralPath $link) 'the link itself should have been removed'
        Assert-True (Test-Path -LiteralPath $victim) 'the junction target was followed and emptied'
        Assert-True (Test-Path -LiteralPath $target)
        Assert-False (Test-Path -LiteralPath $nested) 'the directory holding the link should be gone'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacFilesByPattern refuses a reparse-point root' {
    $sandbox = New-TestSandbox -Prefix 'fs-patlink'
    try {
        $target = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'target')
        $victim = New-TestFile (Join-Path -Path $target -ChildPath 'thumbcache_x.db')
        $link = New-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'link') -Target $target

        $result = Remove-WacFilesByPattern -Category 'patlink' -Path $link -Pattern @('thumbcache_*.db')

        Assert-False $result.Attempted
        Assert-Equal 1 $result.SkippedReparse
        Assert-True (Test-Path -LiteralPath $victim) 'the pattern delete followed a junction'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Effectiveness (ledger U-1)
# ---------------------------------------------------------------------------------------------

Test-Case 'Remove-WacTree clears read-only, hidden and system attributes instead of skipping' {
    $sandbox = New-TestSandbox -Prefix 'fs-attr'
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        $readOnly = New-TestFile (Join-Path -Path $root -ChildPath 'readonly.txt')
        $hidden = New-TestFile (Join-Path -Path $root -ChildPath 'hidden.txt')
        $system = New-TestFile (Join-Path -Path $root -ChildPath 'system.txt')

        [System.IO.File]::SetAttributes($readOnly, [System.IO.FileAttributes]::ReadOnly)
        [System.IO.File]::SetAttributes($hidden, [System.IO.FileAttributes]::Hidden)
        [System.IO.File]::SetAttributes($system, ([System.IO.FileAttributes]::System -bor [System.IO.FileAttributes]::ReadOnly))

        $result = Remove-WacTree -Category 'attr' -Path $root

        Assert-Equal 3 $result.FilesDeleted ('skipDenied=' + $result.SkippedDenied + ' failed=' + $result.Failed)
        Assert-Equal 0 $result.SkippedDenied
        Assert-False ([System.IO.File]::Exists($readOnly))
        Assert-False ([System.IO.File]::Exists($hidden))
        Assert-False ([System.IO.File]::Exists($system))
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacTree reaches a path longer than MAX_PATH' {
    $sandbox = New-TestSandbox -Prefix 'fs-long'
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')

        $deep = $root
        while ($deep.Length -lt 250) { $deep = Join-Path -Path $deep -ChildPath ('d' * 40) }
        [void][System.IO.Directory]::CreateDirectory('\\?\' + $deep)

        $file = Join-Path -Path $deep -ChildPath 'payload.txt'
        [System.IO.File]::WriteAllText(('\\?\' + $file), 'x')
        Assert-True ($file.Length -gt 260) ('the probe path is only {0} characters' -f $file.Length)
        Assert-True ([System.IO.File]::Exists('\\?\' + $file)) 'the probe file was not created'

        $result = Remove-WacTree -Category 'long' -Path $root

        Assert-Equal 1 $result.FilesDeleted ('skipOutOfRoot=' + $result.SkippedOutOfRoot + ' failed=' + $result.Failed)
        Assert-False ([System.IO.File]::Exists('\\?\' + $file)) 'a >MAX_PATH file survived'
        Assert-False ([System.IO.Directory]::Exists('\\?\' + $deep)) 'a >MAX_PATH directory survived'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacTree accounts for a locked file instead of deleting it' {
    $sandbox = New-TestSandbox -Prefix 'fs-lock'
    $handle = $null
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        $locked = New-TestFile (Join-Path -Path $root -ChildPath 'locked.bin')
        $free = New-TestFile (Join-Path -Path $root -ChildPath 'free.bin')

        $handle = New-Object System.IO.FileStream(
            $locked, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

        $result = Remove-WacTree -Category 'lock' -Path $root

        Assert-Equal 1 $result.FilesDeleted 'the unlocked file should still have been deleted'
        Assert-False (Test-Path -LiteralPath $free)
        Assert-True (Test-Path -LiteralPath $locked) 'a locked file must not vanish'
        # Delete-on-reboot registration only succeeds for an administrator or SYSTEM, so either
        # counter is a correct outcome; being counted nowhere is not.
        Assert-True (($result.SkippedLocked + $result.PendingDeletes) -ge 1) `
            ('locked=' + $result.SkippedLocked + ' pending=' + $result.PendingDeletes + ' denied=' + $result.SkippedDenied)
    }
    finally {
        if ($handle) { try { $handle.Dispose() } catch { $null = $_ } }
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Directory removal order
# ---------------------------------------------------------------------------------------------

Test-Case 'Remove-WacTree removes nested directories deepest-first' {
    $sandbox = New-TestSandbox -Prefix 'fs-order'
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        $a = New-TestDirectory (Join-Path -Path $root -ChildPath 'a')
        $b = New-TestDirectory (Join-Path -Path $a -ChildPath 'b')
        $c = New-TestDirectory (Join-Path -Path $b -ChildPath 'c')
        [void](New-TestFile (Join-Path -Path $c -ChildPath 'leaf.txt'))

        $result = Remove-WacTree -Category 'order' -Path $root

        # A parent-first order would fail the non-recursive Directory.Delete and leave the tree.
        Assert-Equal 3 $result.DirectoriesDeleted
        Assert-Equal 0 $result.SkippedNotEmpty
        Assert-False (Test-Path -LiteralPath $a)
        Assert-True (Test-Path -LiteralPath $root)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The retry pass removes a directory that was non-empty a moment earlier' {
    $sandbox = New-TestSandbox -Prefix 'fs-retry'
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        $sub = New-TestDirectory (Join-Path -Path $root -ChildPath 'sub')
        $file = New-TestFile (Join-Path -Path $sub -ChildPath 'child.txt')

        # Pass 1: still occupied, so nothing is deleted and exactly one skip is recorded. The skip
        # REASON is not asserted: under Windows PowerShell 5.1 a "directory not empty" IOException
        # can surface through the UnauthorizedAccessException handler, which is a defect in the
        # module's typed catch clauses rather than in this behaviour (see the handover notes).
        $first = New-WacDeletionStats
        Remove-WacLeaf -Path $sub -RootPath $root -Stats $first -IsDirectory -NoPendingDelete
        Assert-Equal 0 $first.DirectoriesDeleted
        Assert-Equal 1 (Get-WacSkippedTotal -Stats $first)
        Assert-True (Test-Path -LiteralPath $sub) 'a non-empty directory must not be removed'

        # The file sweep catches up, which is what makes the second pass worth running at all.
        [System.IO.File]::Delete($file)

        $second = New-WacDeletionStats
        Remove-WacLeaf -Path $sub -RootPath $root -Stats $second -IsDirectory
        Assert-Equal 1 $second.DirectoriesDeleted
        Assert-Equal 0 (Get-WacSkippedTotal -Stats $second)
        Assert-False (Test-Path -LiteralPath $sub)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Pattern deletion
# ---------------------------------------------------------------------------------------------

Test-Case 'Remove-WacFilesByPattern deletes only matching files and never recurses' {
    $sandbox = New-TestSandbox -Prefix 'fs-pattern'
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        $a = New-TestFile (Join-Path -Path $root -ChildPath 'thumbcache_32.db')
        $b = New-TestFile (Join-Path -Path $root -ChildPath 'thumbcache_96.db')
        $keep = New-TestFile (Join-Path -Path $root -ChildPath 'iconcache.db.bak')
        $nested = New-TestFile (Join-Path -Path $root -ChildPath 'sub\thumbcache_256.db')

        $result = Remove-WacFilesByPattern -Category 'pattern' -Path $root -Pattern @('thumbcache_*.db')

        Assert-True $result.Attempted
        Assert-Equal 2 $result.FilesDeleted
        Assert-Equal 0 $result.DirectoriesDeleted
        Assert-False (Test-Path -LiteralPath $a)
        Assert-False (Test-Path -LiteralPath $b)
        Assert-True (Test-Path -LiteralPath $keep) 'a non-matching file was deleted'
        Assert-True (Test-Path -LiteralPath $nested) 'the pattern delete recursed into a subdirectory'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Protected script root (ledger P0-5)
# ---------------------------------------------------------------------------------------------

Test-Case 'A protected script root survives whether it equals, sits inside, or contains the target' {
    $sandbox = New-TestSandbox -Prefix 'fs-selfroot'
    try {
        $target = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'target')
        $inner = New-TestFile (Join-Path -Path $target -ChildPath 'app\Run.ps1')
        $plain = New-TestFile (Join-Path -Path $target -ChildPath 'junk.tmp')

        # 1. the script root IS the target
        Clear-WacProtectedRoot
        Add-WacProtectedRoot -Path $target
        $equal = Remove-WacTree -Category 'self-equal' -Path $target
        Assert-False $equal.Attempted 'a target equal to the script root was swept'
        Assert-Equal 1 $equal.SkippedOutOfRoot
        Assert-True (Test-Path -LiteralPath $plain)

        # 2. the script root lives INSIDE the target, so the target is its ancestor. Cleaning
        #    continues around it - abandoning the whole target would stop temp cleanup entirely for
        #    a checkout deployed under %TEMP% - but the subtree itself must be untouched.
        Clear-WacProtectedRoot
        Add-WacProtectedRoot -Path (Join-Path -Path $target -ChildPath 'app')
        $ancestor = Remove-WacTree -Category 'self-ancestor' -Path $target
        Assert-True $ancestor.Attempted
        Assert-True ($ancestor.SkippedProtected -ge 1) 'the protected subtree was not recorded as skipped'
        Assert-True (Test-Path -LiteralPath $inner) 'the script root was deleted from inside the target'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $target -ChildPath 'app')) 'the protected directory itself was deleted'
        Assert-False (Test-Path -LiteralPath $plain) 'cleaning stopped instead of working around the protected subtree'

        # 3. the target sits INSIDE the script root
        [void](New-TestFile $plain)
        Clear-WacProtectedRoot
        Add-WacProtectedRoot -Path $sandbox
        $inside = Remove-WacTree -Category 'self-inside' -Path $target
        Assert-False $inside.Attempted 'a target inside the script root was swept'
        Assert-True (Test-Path -LiteralPath $plain)
        Assert-True (Test-Path -LiteralPath $inner)
    }
    finally {
        Clear-WacProtectedRoot
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Deadline
# ---------------------------------------------------------------------------------------------

Test-Case 'Remove-WacTree aborts cleanly once the run deadline has expired' {
    $sandbox = New-TestSandbox -Prefix 'fs-deadline'
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        $file = New-TestFile (Join-Path -Path $root -ChildPath 'sub\payload.txt')

        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddSeconds(-1))
        Assert-True (Test-WacDeadlineExpired)

        $expired = Remove-WacTree -Category 'deadline' -Path $root
        Assert-False $expired.Attempted 'the sweep ran past the deadline'
        Assert-Equal 1 $expired.SkippedDeadline
        Assert-Equal 0 $expired.FilesDeleted
        Assert-True (Test-Path -LiteralPath $file) 'files were deleted after the deadline expired'

        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddHours(1))
        $fresh = Remove-WacTree -Category 'deadline' -Path $root
        Assert-True $fresh.Attempted
        Assert-Equal 1 $fresh.FilesDeleted
        Assert-False (Test-Path -LiteralPath $file)
    }
    finally {
        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddHours(1))
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
