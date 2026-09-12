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

function Get-TestResultLogLine {
    <#
    .SYNOPSIS
        The one 'Target complete.' line in a run log that carries the given category, or $null.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$Category
    )

    $needle = 'category=' + $Category
    foreach ($line in [System.IO.File]::ReadAllLines($LogPath)) {
        if ($line.Contains('[Result] Target complete.') -and $line.Contains($needle)) { return $line }
    }
    return $null
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

Test-Case 'A root whose parent is the volume root is deleted, not refused as an identity mismatch' {
    # The fixture has to sit DIRECTLY under C:\ - that is the whole point. Every other -DeleteRoot
    # case builds several levels under %TEMP%, which is why nine adversarial audits never saw this.
    # The handle-bound delete proves the parent by comparing two strings built by rules that disagree
    # about exactly one case: SplitLeaf keeps the volume root's trailing separator (the open needs
    # it, since "C:" names the current directory) and FinalPathOf strips it. They could never match,
    # so C:\Windows.old - the only allow-list target with this shape, and the only one whose own root
    # is deleted - was emptied but never removed, and the resulting RefusedIdentity raised the entire
    # run to SecurityRefusal. RefusedIdentity is the assertion that fails against the unfixed code.
    $root = 'C:\wac-test-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
    try {
        [void][System.IO.Directory]::CreateDirectory($root)
        [void](New-TestFile (Join-Path -Path $root -ChildPath 'a.txt'))

        $result = Remove-WacTree -Category 'volroot' -Path $root -DeleteRoot

        Assert-True $result.Attempted
        Assert-Equal 0 ([int]$result.RefusedIdentity) 'the volume-root parent failed its own identity proof'
        Assert-False ([System.IO.Directory]::Exists($root)) 'the root survived a -DeleteRoot sweep'
        Assert-True ([System.IO.Directory]::Exists('C:\')) 'deletion climbed above the root'
    }
    finally {
        if ([System.IO.Directory]::Exists($root)) {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        }
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

Test-Case 'Remove-WacTree removes read-only, hidden and system files instead of skipping them' {
    # The outcome is what it always was; the mechanism is not. Nothing clears an attribute any more
    # - the bound delete tolerates ReadOnly on the handle it has already proved - so this case says
    # "removed", not "cleared". Hidden and System never blocked a delete in the first place.
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

Test-Case 'A read-only object is removed on every shape the sweep meets, target and all' {
    <#
        The read-only retry used to be a pathname attribute rewrite, so it was only ever written
        against the plain file in the case above. The replacement is a disposition on the handle the
        delete already proved, and it has to hold for every shape a real sweep meets: a LINK, whose
        target must stay untouched, and a path past MAX_PATH, which Windows PowerShell 5.1 cannot
        reach at all without the \\?\ form. Any of the three coming back skipDenied would mean the
        tool leaves read-only rubbish behind - the effectiveness problem the old retry existed for.
    #>
    $sandbox = New-TestSandbox -Prefix 'fs-ro-shapes'
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        $linkTarget = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'linktarget')
        $keep = New-TestFile (Join-Path -Path $linkTarget -ChildPath 'keep.txt') -Content 'untouched'

        $plain = New-TestFile (Join-Path -Path $root -ChildPath 'plain.tmp')
        [System.IO.File]::SetAttributes($plain, [System.IO.FileAttributes]::ReadOnly)

        # Measured on both hosts: SetAttributes through a junction marks the LINK, not its target,
        # so this really is a read-only reparse leaf rather than a read-only directory elsewhere.
        $link = New-TestJunction -Link (Join-Path -Path $root -ChildPath 'link') -Target $linkTarget
        [System.IO.File]::SetAttributes(
            $link, ([System.IO.File]::GetAttributes($link) -bor [System.IO.FileAttributes]::ReadOnly))

        $deep = Join-Path -Path $root -ChildPath 'deep'
        while ($deep.Length -lt 250) { $deep = Join-Path -Path $deep -ChildPath ('d' * 40) }
        [void][System.IO.Directory]::CreateDirectory('\\?\' + $deep)
        $long = Join-Path -Path $deep -ChildPath 'long.tmp'
        [System.IO.File]::WriteAllText(('\\?\' + $long), 'x')
        [System.IO.File]::SetAttributes(('\\?\' + $long), [System.IO.FileAttributes]::ReadOnly)
        Assert-True ($long.Length -gt 260) ('the probe path is only {0} characters' -f $long.Length)

        $result = Remove-WacTree -Category 'roshapes' -Path $root

        Assert-Equal 2 ([int]$result.FilesDeleted) ('skipDenied=' + $result.SkippedDenied + ' failed=' + $result.Failed)
        Assert-Equal 1 ([int]$result.ReparsePointsDeleted) 'the read-only link was not unlinked'
        Assert-Equal 0 ([int]$result.SkippedDenied) 'a read-only object was left on disk'
        Assert-Equal 0 ([int]$result.Refused) 'an ordinary read-only object is not a security refusal'
        Assert-False ([System.IO.File]::Exists($plain)) 'a read-only file survived'
        Assert-False ([System.IO.File]::Exists('\\?\' + $long)) 'a read-only >MAX_PATH file survived'
        Assert-False (Test-Path -LiteralPath $link) 'the read-only link survived'
        Assert-True ([System.IO.File]::Exists($keep)) 'the link was followed and its target emptied'
    }
    finally {
        $planted = Join-Path -Path $sandbox -ChildPath 'root\link'
        if (Test-Path -LiteralPath $planted) {
            try { [System.IO.Directory]::Delete($planted, $false) } catch { $null = $_ }
        }
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

Test-Case 'A locked file is accounted as locked and is never queued for deletion at the next boot' {
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

        # This used to allow EITHER counter, because delete-on-reboot registration only succeeds for
        # an administrator or SYSTEM and the suite runs at both privilege levels. Now there is one
        # correct answer at every privilege level: MoveFileEx is not called at all, so the outcome
        # cannot depend on whether the shell happens to be elevated. See the module header for what
        # that costs and why the alternative could not be made safe.
        Assert-Equal 1 ([int]$result.SkippedLocked) `
            ('locked=' + $result.SkippedLocked + ' pending=' + $result.PendingDeletes + ' denied=' + $result.SkippedDenied)
        Assert-Equal 0 ([int]$result.PendingDeletes) 'a path was queued for deletion at the next boot'
        Assert-Equal 0 ([int]$result.Refused) 'a locked file is not a security refusal'
    }
    finally {
        if ($handle) { try { $handle.Dispose() } catch { $null = $_ } }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A target shaped like a real one produces no refusals at all' {
    <#
        The counter split only means something if an ORDINARY run scores zero on the new counters:
        they drive a security-refusal exit code, and a code that fires every day means nothing. The
        shape here is taken from a real elevated run's log - nested directories, a junction, a
        protected subtree, a locked file, blocked attributes and a >MAX_PATH path - and the whole of
        it must come back Refused=0.
    #>
    $sandbox = New-TestSandbox -Prefix 'fs-realshape'
    $handle = $null
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        $outside = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'outside')

        [void](New-TestFile (Join-Path -Path $root -ChildPath 'a\b\c\deep.tmp'))
        [void](New-TestFile (Join-Path -Path $root -ChildPath 'a\b\other.tmp'))
        [void](New-TestFile (Join-Path -Path $root -ChildPath 'loose.tmp'))
        [void](New-TestJunction -Link (Join-Path -Path $root -ChildPath 'a\link') -Target $outside)

        $readOnly = New-TestFile (Join-Path -Path $root -ChildPath 'a\readonly.tmp')
        [System.IO.File]::SetAttributes($readOnly, [System.IO.FileAttributes]::ReadOnly)

        $deep = Join-Path -Path $root -ChildPath 'a\b'
        while ($deep.Length -lt 250) { $deep = Join-Path -Path $deep -ChildPath ('d' * 40) }
        [void][System.IO.Directory]::CreateDirectory('\\?\' + $deep)
        [System.IO.File]::WriteAllText(('\\?\' + (Join-Path -Path $deep -ChildPath 'long.tmp')), 'x')

        $lockedPath = New-TestFile (Join-Path -Path $root -ChildPath 'a\locked.bin')
        $handle = New-Object System.IO.FileStream(
            $lockedPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

        $protectedRoot = New-TestDirectory (Join-Path -Path $root -ChildPath 'keepme')
        [void](New-TestFile (Join-Path -Path $protectedRoot -ChildPath 'app.ps1'))
        Clear-WacProtectedRoot
        Add-WacProtectedRoot -Path $protectedRoot

        $result = Remove-WacTree -Category 'realshape' -Path $root

        Assert-True $result.Attempted
        # Per counter as well as on the roll-up: a roll-up hard-wired to 0 would make the benign
        # direction pass vacuously, which is the same defect from the other side.
        Assert-Equal 0 ([int]$result.RefusedIdentity) 'a realistic run reported an identity refusal'
        Assert-Equal 0 ([int]$result.RefusedOutOfRoot) 'a realistic run reported an out-of-root refusal'
        Assert-Equal 0 ([int]$result.Refused) `
            ('a realistic run reported a security refusal: identity=' + $result.RefusedIdentity +
             ' outOfRoot=' + $result.RefusedOutOfRoot)
        Assert-Equal 0 ([int]$result.Failed)
        # ...and it really did the work, so Refused=0 is not the trivial answer.
        Assert-True ($result.FilesDeleted -ge 4) ('only ' + $result.FilesDeleted + ' files were deleted')
        Assert-Equal 1 ([int]$result.ReparsePointsDeleted)
        Assert-Equal 1 ([int]$result.SkippedLocked)
        Assert-True ($result.SkippedProtected -ge 1)
        Assert-True (Test-Path -LiteralPath $protectedRoot) 'the protected subtree was removed'
        Assert-True (Test-Path -LiteralPath $outside) 'the junction target was followed'

        # ...and AGAIN, over the same persistent state. A benign steady state that scores clean once
        # and refuses on the next run would exit 7 every day but the first, which is precisely the
        # defect this counter split exists to prevent. The protected subtree, the locked file and
        # the junction target are all still here, so this pass is the state a scheduled task
        # actually spends its life in.
        $again = Remove-WacTree -Category 'realshape' -Path $root
        Assert-True $again.Attempted
        Assert-Equal 0 ([int]$again.RefusedIdentity) 'the second pass over the same state reported an identity refusal'
        Assert-Equal 0 ([int]$again.RefusedOutOfRoot) 'the second pass over the same state reported an out-of-root refusal'
        Assert-Equal 0 ([int]$again.Refused) 'a benign steady state was reported as a security refusal on its second run'
        Assert-Equal 0 ([int]$again.Failed)
        Assert-Equal 1 ([int]$again.SkippedLocked) 'the still-locked file changed classification on the second pass'
        Assert-True ($again.SkippedProtected -ge 1) 'the protected subtree stopped being skipped'

        # A real elevated run also skips reparse-point ROOTS - it scored skipReparse=3, every one of
        # them the per-profile 'Temporary Internet Files' junction. A benign reparse skip and a
        # benign protected skip inside the same run must still add up to zero refusals, twice.
        $inetCache = New-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'Temporary Internet Files') -Target $outside
        foreach ($pass in 1, 2) {
            $routine = Remove-WacTree -Category 'realshape-inetcache' -Path $inetCache
            Assert-False $routine.Attempted ('pass ' + $pass + ': a reparse-point root was swept')
            Assert-Equal 1 ([int]$routine.SkippedReparse) ('pass ' + $pass + ': the reparse-point root was not a routine skip')
            Assert-Equal 0 ([int]$routine.RefusedIdentity) ('pass ' + $pass + ': a routine reparse-point root was an identity refusal')
            Assert-Equal 0 ([int]$routine.Refused) ('pass ' + $pass + ': a routine reparse-point root reached the refusal roll-up')
        }
        Assert-True (Test-Path -LiteralPath $inetCache) 'the reparse-point root itself was deleted'
    }
    finally {
        if ($handle) { try { $handle.Dispose() } catch { $null = $_ } }
        Clear-WacProtectedRoot
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A path that cannot be canonicalised is a skip, never a refusal' {
    <#
        Measured on a real elevated run: its only skipOutOfRoot was a file named 'nul' in the user's
        TEMP. GetFullPath resolves that to \\.\nul on BOTH hosts, so Get-WacNormalizedPath returns
        $null. Nothing resolved and nothing was deleted, so classifying it as a security refusal
        would have exit-coded an ordinary daily run as an attack. No file is created here: the
        classification is asserted directly, because a real 'nul' in TEMP is not removable by the
        same path APIs that would have to clean the sandbox up.
    #>
    $sandbox = New-TestSandbox -Prefix 'fs-device'
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        $device = Join-Path -Path $root -ChildPath 'nul'

        Assert-Equal $null (Get-WacNormalizedPath -Path $device) `
            'the premise changed: a DOS device name now canonicalises'

        $stats = New-WacDeletionStats
        Remove-WacLeaf -Path $device -RootPath $root -Stats $stats

        Assert-Equal 1 ([int]$stats.SkippedOutOfRoot)
        Assert-Equal 0 (Get-WacRefusedTotal -Stats $stats) 'an unresolvable path was called a refusal'
        Assert-Equal 0 ([int]$stats.FilesDeleted)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# The result line
# ---------------------------------------------------------------------------------------------

Test-Case 'Write-WacTreeResult names both refusal counters and lifts the line to WARNING' {
    <#
        Write-WacTreeResult is what an operator and an incident reviewer actually read, and nothing
        in the tree referenced it at all - so the refusal keys could be dropped and the WARNING lift
        removed with every case still green.

        Both counters here come from REAL refusals routed through Remove-WacLeaf - one path that is
        lexically inside the root but resolves outside it, one that is not inside it at all - rather
        than from hand-set fields, so this case fails if the counting, the roll-up, the log key or
        the level lift breaks.
    #>
    $fixture = New-TestSandbox -Prefix 'fs-resultlog'
    $logRoot = New-TestSandbox -Prefix 'fs-resultlog-log'
    try {
        Clear-WacProtectedRoot

        $root = New-TestDirectory (Join-Path -Path $fixture -ChildPath 'root')
        $outside = New-TestDirectory (Join-Path -Path $fixture -ChildPath 'outside')
        $sentinel = New-TestFile -Path (Join-Path -Path $outside -ChildPath 'SENTINEL.dll') -Content 'MUST SURVIVE'
        $link = New-TestJunction -Link (Join-Path -Path $root -ChildPath 'swapped') -Target $outside

        $stats = New-WacDeletionStats
        Remove-WacLeaf -Path (Join-Path -Path $link -ChildPath 'SENTINEL.dll') -RootPath $root -Stats $stats
        Remove-WacLeaf -Path $sentinel -RootPath $root -Stats $stats

        Assert-Equal 1 ([int]$stats.RefusedIdentity) 'the redirected path was not an identity refusal'
        Assert-Equal 1 ([int]$stats.RefusedOutOfRoot) 'the out-of-root path was not an out-of-root refusal'
        Assert-Equal 2 (Get-WacRefusedTotal -Stats $stats) 'the refusal roll-up does not add up its members'
        Assert-True ([System.IO.File]::Exists($sentinel)) 'a refused path was deleted anyway'

        $refusing = New-WacTreeResult -Category 'refusing' -Path $root -Stats $stats -Attempted $true
        Assert-Equal 2 ([int]$refusing.Refused) 'the result object dropped the refusal roll-up'
        $clean = New-WacTreeResult -Category 'clean' -Path $root -Stats (New-WacDeletionStats) -Attempted $true

        Assert-True (Initialize-WacRun -BaseName 'resultlog' -CandidateRoot @($logRoot) -BudgetMinutes 60) `
            'the run log was not created, so no line could be captured'

        Write-WacTreeResult -Result $refusing
        Write-WacTreeResult -Result $clean

        $logPath = Get-WacLogPath
        Close-WacLog

        $refusedLine = Get-TestResultLogLine -LogPath $logPath -Category 'refusing'
        Assert-True ($null -ne $refusedLine) 'Write-WacTreeResult emitted no line for a refusing target'
        Assert-True ($refusedLine.Contains('refusedIdentity=1')) `
            ('the identity refusal is not named in the line: ' + $refusedLine)
        Assert-True ($refusedLine.Contains('refusedOutOfRoot=1')) `
            ('the out-of-root refusal is not named in the line: ' + $refusedLine)
        Assert-True ($refusedLine.Contains('] [WARNING] [Result] ')) `
            ('a refusal was logged below WARNING: ' + $refusedLine)

        # The other direction, or a line hard-wired to WARNING would satisfy the assertion above and
        # every ordinary target would shout.
        $cleanLine = Get-TestResultLogLine -LogPath $logPath -Category 'clean'
        Assert-True ($null -ne $cleanLine) 'Write-WacTreeResult emitted no line for a clean target'
        Assert-True ($cleanLine.Contains('] [INFO] [Result] ')) `
            ('a clean target was not logged at INFO: ' + $cleanLine)
        Assert-False ($cleanLine.Contains('refused')) `
            ('a clean target reported a refusal: ' + $cleanLine)
    }
    finally {
        Close-WacLog
        Clear-WacProtectedRoot
        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddHours(1))
        Remove-TestSandbox -Path $logRoot
        Remove-TestSandbox -Path $fixture
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
        Remove-WacLeaf -Path $sub -RootPath $root -Stats $first -IsDirectory
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

Test-Case 'A leaf inside a protected root is a protected skip and never an identity refusal' {
    <#
        Remove-WacLeaf carries its own protected-path check, and nothing reached it. The case above
        exercises the SWEEP's protected branch, which drops the whole subtree during enumeration so
        no leaf inside it is ever handed to Remove-WacLeaf; every other route into this function
        arrives with the protection already cleared. Mutating this skip to RefusedIdentity left
        every suite green - and that is the contract-violating direction, because an everyday target
        that happens to contain the deployment or the log directory would then score a security
        refusal and exit 7 on EVERY run, with nothing whatsoever wrong.

        Run twice over the same persistent state for exactly that reason: a benign steady state has
        to still be benign on the second pass, which is the pass a scheduled task actually spends
        its life in.
    #>
    $sandbox = New-TestSandbox -Prefix 'fs-leafprotected'
    try {
        $root = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'root')
        $deployment = New-TestDirectory (Join-Path -Path $root -ChildPath 'deployment')
        $keep = New-TestFile -Path (Join-Path -Path $deployment -ChildPath 'Run.ps1') -Content 'MUST SURVIVE'

        Clear-WacProtectedRoot
        Add-WacProtectedRoot -Path $deployment

        foreach ($pass in 1, 2) {
            $stats = New-WacDeletionStats
            Remove-WacLeaf -Path $keep -RootPath $root -Stats $stats

            Assert-Equal 1 ([int]$stats.SkippedProtected) `
                ('pass ' + $pass + ': a protected leaf was not recorded as a protected skip')
            Assert-Equal 0 ([int]$stats.RefusedIdentity) `
                ('pass ' + $pass + ': a protected leaf was reported as an identity refusal')
            Assert-Equal 0 (Get-WacRefusedTotal -Stats $stats) `
                ('pass ' + $pass + ': a benign protected skip reached the refusal roll-up the exit code reads')
            Assert-Equal 0 ([int]$stats.FilesDeleted)
            Assert-True ([System.IO.File]::Exists($keep)) ('pass ' + $pass + ': the protected file was deleted')
        }

        # The protected directory itself takes the same branch, and it is the one -DeleteRoot would
        # reach on a target that IS the deployment.
        $directory = New-WacDeletionStats
        Remove-WacLeaf -Path $deployment -RootPath $root -Stats $directory -IsDirectory
        Assert-Equal 1 ([int]$directory.SkippedProtected) 'the protected root itself was not a protected skip'
        Assert-Equal 0 (Get-WacRefusedTotal -Stats $directory) 'deleting the protected root was reported as a refusal'
        Assert-True (Test-Path -LiteralPath $deployment) 'the protected root was removed'

        # ...and an unprotected sibling still goes, so "skip everything" fails here.
        $junk = New-TestFile (Join-Path -Path $root -ChildPath 'junk.tmp')
        $ordinary = New-WacDeletionStats
        Remove-WacLeaf -Path $junk -RootPath $root -Stats $ordinary
        Assert-Equal 1 ([int]$ordinary.FilesDeleted) 'an ordinary file beside a protected root was not deleted'
        Assert-Equal 0 ([int]$ordinary.SkippedProtected) 'an ordinary file was written off as protected'
        Assert-False ([System.IO.File]::Exists($junk))
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
