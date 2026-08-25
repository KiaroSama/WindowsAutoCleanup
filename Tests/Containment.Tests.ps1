#Requires -Version 5.1
<#
.SYNOPSIS
    Pins the STATIC containment guards: every check refuses a path that escapes its root.

.DESCRIPTION
    An adversarial review proved the old containment was purely lexical. Test-WacIsWithinRoot,
    Test-WacIsOnTargetDrive and Test-WacIsProtectedPath are all STRING comparisons, and a string
    cannot notice that an ancestor directory was replaced by a junction since the last time it was
    checked. Verifying once per directory left a window as long as that directory took to sweep -
    measured at roughly twelve seconds for three thousand entries - during which anyone who can write
    to an allow-listed target (C:\Windows\Temp grants BUILTIN\Users write by default) could redirect
    every subsequent delete out of the allow-list, as SYSTEM.

    Register-WacDeleteOnReboot was worse: it hands the literal PATH STRING to MoveFileEx, and the
    session manager re-resolves it at the next boot. No race at all - the attacker had until the next
    restart to swap an ancestor.

    Every case here builds the real shape (a sentinel outside the root, reachable only through a
    junction inside it) rather than simulating it, and each is written so that deleting the guard it
    covers makes it fail.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.FileSystem.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

function New-TestJunction {
    <#
    .SYNOPSIS
        Creates a real directory junction, or throws if the OS refused.
    .DESCRIPTION
        cmd's mklink /J needs no elevation, unlike a symbolic link, so these cases run identically
        on a developer shell and on an elevated CI runner.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Link,
        [Parameter(Mandatory = $true)][string]$Target
    )

    $cmd = Join-Path -Path $env:SystemRoot -ChildPath 'System32\cmd.exe'
    & $cmd /c mklink /J "$Link" "$Target" | Out-Null
    if (-not (Test-Path -LiteralPath $Link)) {
        throw ('the junction could not be created: {0} -> {1}' -f $Link, $Target)
    }
}

function Remove-TestJunction {
    param([Parameter(Mandatory = $true)][string]$Link)

    # Never Remove-Item a junction: Windows PowerShell 5.1 throws a spurious NullReferenceException
    # on some of them, and a failure here would leave the sandbox undeletable.
    try {
        if (Test-Path -LiteralPath $Link) { [System.IO.Directory]::Delete($Link, $false) }
    }
    catch {
        $null = $_
    }
}

function New-EscapeFixture {
    <#
    .SYNOPSIS
        An allow-listed root containing a junction that points at a sentinel outside it.
    .OUTPUTS
        Root, Outside, Link, Sentinel, SentinelThroughLink.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $root = Join-Path -Path $Sandbox -ChildPath 'allowlisted'
    $outside = Join-Path -Path $Sandbox -ChildPath 'outside'
    $link = Join-Path -Path $root -ChildPath 'swapped'

    [void][System.IO.Directory]::CreateDirectory($root)
    [void][System.IO.Directory]::CreateDirectory($outside)

    $sentinel = Join-Path -Path $outside -ChildPath 'SENTINEL.dll'
    [System.IO.File]::WriteAllText($sentinel, 'must survive')

    New-TestJunction -Link $link -Target $outside

    return [PSCustomObject]@{
        Root = $root
        Outside = $outside
        Link = $link
        Sentinel = $sentinel
        SentinelThroughLink = (Join-Path -Path $link -ChildPath 'SENTINEL.dll')
    }
}

# ---------------------------------------------------------------------------------------------
# The lexical checks alone are not containment

# ---------------------------------------------------------------------------------------------

Test-Case 'Every string-based check accepts a path that escapes through a junction' {
    $sandbox = New-TestSandbox -Prefix 'contain-lexical'
    try {
        $fixture = New-EscapeFixture -Sandbox $sandbox
        $victim = $fixture.SentinelThroughLink

        # This case documents WHY the handle check exists. If any of these three ever starts
        # returning the safe answer on its own, the comment in Remove-WacLeaf is wrong and the
        # guard's justification needs rewriting.
        Assert-True (Test-WacIsWithinRoot -ChildPath $victim -RootPath $fixture.Root) `
            'the lexical containment check no longer accepts the escaping path'
        Assert-True (Test-WacIsOnTargetDrive -Path $victim)
        Assert-False (Test-WacIsProtectedPath -Path $victim)

        # ...and the handle check is the one that catches it.
        $normalized = Get-WacNormalizedPath -Path $victim
        Assert-False (Test-WacFinalPathMatches -NormalizedPath $normalized) `
            'the handle check failed to notice the redirection'
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'allowlisted\swapped')
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacLeaf refuses a path that resolves outside its root' {
    $sandbox = New-TestSandbox -Prefix 'contain-leaf'
    try {
        $fixture = New-EscapeFixture -Sandbox $sandbox

        $stats = New-WacDeletionStats
        Remove-WacLeaf -Path $fixture.SentinelThroughLink -RootPath $fixture.Root -Stats $stats

        Assert-True ([System.IO.File]::Exists($fixture.Sentinel)) `
            'the sentinel outside the allow-listed root was deleted'
        Assert-Equal 0 ([int]$stats.FilesDeleted) 'something was counted as deleted'
        Assert-Equal 0 ([int]$stats.Failed) 'the refusal was recorded as a failure'

        # RefusedIdentity, not SkippedReparse. The two used to share a counter, which made the whole
        # family useless for an exit code: an ordinary run legitimately skips reparse roots (a real
        # elevated run scored skipReparse=3, all of them the per-profile Temporary Internet Files
        # junction), so a refusal had to get a counter no ordinary run can touch.
        Assert-Equal 1 ([int]$stats.RefusedIdentity) `
            'the refusal was not recorded as an identity refusal, so the exit code cannot see it'
        Assert-Equal 0 ([int]$stats.SkippedReparse) 'a refusal is still being counted as a benign skip'

        # The individual counter is not the field the exit code reads - the roll-up is, and nothing
        # pinned it. Get-WacRefusedTotal could return a constant 0 and every other Refused assertion
        # in this tree still passed, because every one of them expects 0.
        Assert-Equal 1 (Get-WacRefusedTotal -Stats $stats) `
            'the refusal roll-up does not see an identity refusal'
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'allowlisted\swapped')
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A path that canonicalises outside the root is refused on the out-of-root counter' {
    <#
        The other half of the split, and the half nothing else in this file reaches: the escaping
        path in the case above is LEXICALLY inside the root (it goes through a junction), so it lands
        on RefusedIdentity. A counter no test can produce is a counter nobody can trust, and this one
        feeds an exit code.
    #>
    $sandbox = New-TestSandbox -Prefix 'contain-outofroot'
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'allowlisted'
        $outside = Join-Path -Path $sandbox -ChildPath 'outside'
        [void][System.IO.Directory]::CreateDirectory($root)
        [void][System.IO.Directory]::CreateDirectory($outside)
        $sentinel = Join-Path -Path $outside -ChildPath 'SENTINEL.dll'
        [System.IO.File]::WriteAllText($sentinel, 'MUST SURVIVE')

        $stats = New-WacDeletionStats
        Remove-WacLeaf -Path $sentinel -RootPath $root -Stats $stats

        Assert-True ([System.IO.File]::Exists($sentinel)) 'a file outside the root was deleted'
        Assert-Equal 1 ([int]$stats.RefusedOutOfRoot) 'the containment refusal was counted somewhere else'
        Assert-Equal 0 ([int]$stats.SkippedOutOfRoot) 'a real escape was filed as a benign skip'
        Assert-Equal 0 ([int]$stats.FilesDeleted)
        Assert-Equal 1 (Get-WacRefusedTotal -Stats $stats) `
            'the refusal roll-up does not see an out-of-root refusal'

        # ...and it has to survive the trip through the object the orchestrator actually reads.
        $result = New-WacTreeResult -Category 'outofroot' -Path $root -Stats $stats -Attempted $true
        Assert-Equal 1 ([int]$result.RefusedOutOfRoot)
        Assert-Equal 1 ([int]$result.Refused) 'New-WacTreeResult dropped the refusal on the way out'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacTree refuses a root reached only through a junction' {
    <#
        The whole-target shape of the identity refusal, and the only case that proves Refused is
        wired all the way out to the caller. The target is not itself a reparse point - so the cheap
        attribute test at the top of Remove-WacTree cannot catch it - but its path reaches the object
        only through one, so the handle check has to. Everything above pins refusals on a raw stats
        object, which left New-WacTreeResult free to drop the roll-up the exit code keys off.
    #>
    $sandbox = New-TestSandbox -Prefix 'contain-rootswap'
    try {
        $fixture = New-EscapeFixture -Sandbox $sandbox

        $realSub = Join-Path -Path $fixture.Outside -ChildPath 'nested'
        [void][System.IO.Directory]::CreateDirectory($realSub)
        $victim = Join-Path -Path $realSub -ChildPath 'SENTINEL.dll'
        [System.IO.File]::WriteAllText($victim, 'MUST SURVIVE')

        $target = Join-Path -Path $fixture.Link -ChildPath 'nested'
        Assert-False (Test-WacIsReparsePoint -Path $target) `
            'the fixture is wrong: the target itself must not be a reparse point'

        $result = Remove-WacTree -Category 'rootswap' -Path $target

        Assert-False $result.Attempted 'a redirected root was swept'
        Assert-Equal 1 ([int]$result.RefusedIdentity) 'a redirected root was not counted as an identity refusal'
        Assert-Equal 1 ([int]$result.Refused) 'the refusal never reached the field the exit code reads'
        Assert-Equal 0 ([int]$result.SkippedVanished) 'a live redirected root was written off as vanished'
        Assert-Equal 0 ([int]$result.SkippedReparse) 'a refusal was filed as a routine reparse skip'
        Assert-Equal 0 ([int]$result.FilesDeleted)
        Assert-True ([System.IO.File]::Exists($victim)) 'the sweep ran out through the junction'
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'allowlisted\swapped')
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacFilesByPattern refuses a pattern root reached only through a junction' {
    <#
        The pattern path carries its own copy of the root checks, and its identity refusal was the
        one refusal counter in this module that nothing reached: every other pattern case here uses
        a root that IS a reparse point, which lands on SkippedReparse and returns before the handle
        check ever runs. Mutating that refusal to SkippedReparse left FileSystem AND Containment
        green on both hosts, so a real redirection of a shell-cache target would have exited 0
        instead of 7.

        Same shape as the tree case above, because it is the same defect one function over: the
        target is a REAL directory - so the cheap attribute test cannot catch it - reached only
        through a junction that sits inside the allow-listed root.
    #>
    $sandbox = New-TestSandbox -Prefix 'contain-patternswap'
    try {
        $fixture = New-EscapeFixture -Sandbox $sandbox

        $realSub = Join-Path -Path $fixture.Outside -ChildPath 'nested'
        [void][System.IO.Directory]::CreateDirectory($realSub)
        $victim = Join-Path -Path $realSub -ChildPath 'thumbcache_9.db'
        [System.IO.File]::WriteAllText($victim, 'MUST SURVIVE')

        $target = Join-Path -Path $fixture.Link -ChildPath 'nested'
        Assert-False (Test-WacIsReparsePoint -Path $target) `
            'the fixture is wrong: the pattern root itself must not be a reparse point'

        $result = Remove-WacFilesByPattern -Category 'patternswap' -Path $target -Pattern @('thumbcache_*.db')

        Assert-False $result.Attempted 'a redirected pattern root was swept'
        Assert-Equal 1 ([int]$result.RefusedIdentity) `
            'a redirected pattern root was not counted as an identity refusal, so the exit code cannot see it'
        Assert-Equal 1 ([int]$result.Refused) 'the refusal never reached the field the exit code reads'
        Assert-Equal 0 ([int]$result.SkippedReparse) 'a refusal was filed as a routine reparse skip'
        Assert-Equal 0 ([int]$result.SkippedVanished) 'a live redirected pattern root was written off as vanished'
        Assert-Equal 0 ([int]$result.FilesDeleted)
        Assert-True ([System.IO.File]::Exists($victim)) 'the pattern delete ran out through the junction'

        # Without this the case would also pass against a pattern path that refuses everything, and
        # the shell-cache targets would silently stop being cleaned.
        $plain = Join-Path -Path $fixture.Root -ChildPath 'plain'
        [void][System.IO.Directory]::CreateDirectory($plain)
        [System.IO.File]::WriteAllText((Join-Path -Path $plain -ChildPath 'thumbcache_1.db'), 'delete me')

        $ordinary = Remove-WacFilesByPattern -Category 'patternplain' -Path $plain -Pattern @('thumbcache_*.db')
        Assert-True $ordinary.Attempted
        Assert-Equal 1 ([int]$ordinary.FilesDeleted) 'an ordinary pattern root was not cleaned'
        Assert-Equal 0 ([int]$ordinary.Refused) 'an ordinary pattern root was reported as a security refusal'
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'allowlisted\swapped')
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The sweep refuses a directory that no longer resolves to itself and writes off one that vanished' {
    <#
        Invoke-WacTreeSweep re-proves every directory by handle when it POPS it, not when it
        enumerated it, and splits the failure two ways: gone is SkippedVanished, re-pointed is
        RefusedIdentity. Mutating that refusal to SkippedReparse left every suite green, because the
        race cases in this file all land on the copy of that split inside Remove-WacLeaf instead.

        HOW FAR THIS GOES, stated rather than implied. The branch is reached here through the
        sweep's FIRST pop - the root it was handed - because that is the only pop a single-threaded
        test can control. A swap landed on a directory already sitting on the stack runs the same
        code over the same inputs, but arranging one needs a second thread, and that is the
        live-fire race case below, which measurement showed is assurance and not a regression
        detector. So the site is pinned here, deterministically, on both hosts; the timing is not.
    #>
    $sandbox = New-TestSandbox -Prefix 'contain-sweepswap'
    try {
        $fixture = New-EscapeFixture -Sandbox $sandbox

        $realSub = Join-Path -Path $fixture.Outside -ChildPath 'nested'
        [void][System.IO.Directory]::CreateDirectory($realSub)
        $victim = Join-Path -Path $realSub -ChildPath 'SENTINEL.dll'
        [System.IO.File]::WriteAllText($victim, 'MUST SURVIVE')

        $swapped = Join-Path -Path $fixture.Link -ChildPath 'nested'
        Assert-False (Test-WacIsReparsePoint -Path $swapped) `
            'the fixture is wrong: the swept directory must not itself be a reparse point'
        Assert-False (Test-WacPathVanished -NormalizedPath $swapped) `
            'the fixture is wrong: the swept directory must still exist, or this proves the other branch'

        $redirected = New-WacDeletionStats
        $found = @(Invoke-WacTreeSweep -Root $swapped -Stats $redirected)

        Assert-Equal 1 ([int]$redirected.RefusedIdentity) 'a live redirected directory was not an identity refusal'
        Assert-Equal 0 ([int]$redirected.SkippedVanished) 'a live redirected directory was written off as vanished'
        Assert-Equal 0 ([int]$redirected.SkippedReparse) 'a refusal was filed as a routine reparse skip'
        Assert-Equal 1 (Get-WacRefusedTotal -Stats $redirected) 'the refusal roll-up cannot see a sweep refusal'
        Assert-Equal 0 $found.Count 'the sweep enumerated a directory it had just refused'
        Assert-Equal 0 ([int]$redirected.FilesDeleted)
        Assert-True ([System.IO.File]::Exists($victim)) 'the sweep ran out through the junction'

        # The other half of the same split, and the reason it has to exist: a directory that simply
        # went away between enumeration and descent is an everyday race, not an attack. Fold the two
        # together and an ordinary run exit-codes as a security event.
        $gone = New-WacDeletionStats
        [void](Invoke-WacTreeSweep -Root (Join-Path -Path $fixture.Root -ChildPath 'never-existed') -Stats $gone)
        Assert-Equal 1 ([int]$gone.SkippedVanished) 'a directory that had vanished was not recorded as vanished'
        Assert-Equal 0 ([int]$gone.RefusedIdentity) 'an ordinary race was recorded as an identity refusal'
        Assert-Equal 0 (Get-WacRefusedTotal -Stats $gone) 'an ordinary race reached the refusal roll-up'

        # ...and an ordinary directory still sweeps, so "refuse everything" fails here too.
        $plain = Join-Path -Path $fixture.Root -ChildPath 'plain'
        [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $plain -ChildPath 'sub'))
        [System.IO.File]::WriteAllText((Join-Path -Path $plain -ChildPath 'sub\junk.tmp'), 'delete me')

        $ordinary = New-WacDeletionStats
        $ordinaryDirs = @(Invoke-WacTreeSweep -Root $plain -Stats $ordinary)
        Assert-Equal 1 ([int]$ordinary.FilesDeleted) 'an ordinary sweep deleted nothing'
        Assert-Equal 1 $ordinaryDirs.Count 'an ordinary sweep returned no directory to remove'
        Assert-Equal 0 (Get-WacRefusedTotal -Stats $ordinary) 'an ordinary sweep reported a security refusal'
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'allowlisted\swapped')
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Delete-on-reboot refuses the same escaping path' {
    $sandbox = New-TestSandbox -Prefix 'contain-reboot'
    try {
        $fixture = New-EscapeFixture -Sandbox $sandbox

        # Assert the DECISION, not the API's return value. MoveFileEx only works for an administrator
        # or LocalSystem, so on an unelevated shell the registration fails regardless and a test that
        # checked only the return would pass even with the guard deleted - going red solely on an
        # elevated CI runner. This is the race-free half of the escape: the path string is stored and
        # re-resolved at the next boot, so an accepted path can be redirected at leisure.
        Assert-False (Test-WacIsDeleteOnRebootAllowed -Path $fixture.SentinelThroughLink) `
            'a redirected path was accepted for deletion at the next boot'

        $direct = Join-Path -Path $fixture.Root -ChildPath 'ordinary.tmp'
        [System.IO.File]::WriteAllText($direct, 'x')
        Assert-True (Test-WacIsDeleteOnRebootAllowed -Path $direct) `
            'an ordinary file inside the root was refused, so the guard refuses everything'

        # And the public entry point must not queue it either.
        Assert-False (Register-WacDeleteOnReboot -Path $fixture.SentinelThroughLink)
        Assert-True ([System.IO.File]::Exists($fixture.Sentinel))
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'allowlisted\swapped')
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The containment guard does not refuse ordinary deletions' {
    $sandbox = New-TestSandbox -Prefix 'contain-control'
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'allowlisted'
        [void][System.IO.Directory]::CreateDirectory($root)
        $ordinary = Join-Path -Path $root -ChildPath 'ordinary.tmp'
        [System.IO.File]::WriteAllText($ordinary, 'delete me')

        $stats = New-WacDeletionStats
        Remove-WacLeaf -Path $ordinary -RootPath $root -Stats $stats

        # Without this control, "refuse everything" would pass every other case in this file.
        Assert-Equal 1 ([int]$stats.FilesDeleted) 'a normal file inside the root was not deleted'
        Assert-False ([System.IO.File]::Exists($ordinary))
        Assert-Equal 0 ([int]$stats.SkippedReparse)
        Assert-Equal 0 (Get-WacRefusedTotal -Stats $stats) 'an ordinary deletion was reported as a refusal'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A nested junction is deleted as a link and its target survives' {
    $sandbox = New-TestSandbox -Prefix 'contain-link'
    try {
        $fixture = New-EscapeFixture -Sandbox $sandbox

        # A reparse point is exempt from the handle check on purpose: removing the LINK is the
        # intended outcome, and resolving it would make the check refuse its own job.
        $stats = New-WacDeletionStats
        Remove-WacLeaf -Path $fixture.Link -RootPath $fixture.Root -Stats $stats -IsDirectory -IsReparsePoint

        Assert-Equal 1 ([int]$stats.ReparsePointsDeleted) 'the junction itself was not removed'
        Assert-False (Test-Path -LiteralPath $fixture.Link)
        Assert-True ([System.IO.File]::Exists($fixture.Sentinel)) 'deleting the link destroyed its target'
        Assert-True (Test-Path -LiteralPath $fixture.Outside)
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'allowlisted\swapped')
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Test-WacDirectorySafeToDescend refuses a redirected directory' {
    $sandbox = New-TestSandbox -Prefix 'contain-descend'
    try {
        $fixture = New-EscapeFixture -Sandbox $sandbox

        # The junction itself is caught by the cheap attribute test.
        Assert-False (Test-WacDirectorySafeToDescend -Path $fixture.Link -RootPath $fixture.Root) `
            'the traversal would have descended into a junction'

        # This is the case the attribute test CANNOT catch and the handle check exists for: a
        # directory that is not itself a reparse point, but whose path reaches it only through one.
        # Without Test-WacPathResolvesToItself the traversal walks straight out of the allow-list.
        $realSub = Join-Path -Path $fixture.Outside -ChildPath 'nested'
        [void][System.IO.Directory]::CreateDirectory($realSub)
        $subThroughLink = Join-Path -Path $fixture.Link -ChildPath 'nested'

        Assert-False (Test-WacIsReparsePoint -Path $subThroughLink) `
            'the fixture is wrong: the nested directory must not itself be a reparse point'
        Assert-False (Test-WacDirectorySafeToDescend -Path $subThroughLink -RootPath $fixture.Root) `
            'a directory reached only through a junction was accepted for descent'

        $plain = Join-Path -Path $fixture.Root -ChildPath 'plain'
        [void][System.IO.Directory]::CreateDirectory($plain)
        Assert-True (Test-WacDirectorySafeToDescend -Path $plain -RootPath $fixture.Root) `
            'an ordinary directory inside the root was refused'
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'allowlisted\swapped')
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A whole sweep leaves everything reachable only through a junction untouched' {
    $sandbox = New-TestSandbox -Prefix 'contain-sweep'
    try {
        $fixture = New-EscapeFixture -Sandbox $sandbox

        # More sentinels than the junction itself, so a sweep that followed the link would be
        # obvious in the counters rather than in a single missing file.
        foreach ($name in @('a.dll', 'b.sys', 'c.exe')) {
            [System.IO.File]::WriteAllText((Join-Path -Path $fixture.Outside -ChildPath $name), 'must survive')
        }
        foreach ($name in @('junk1.tmp', 'junk2.tmp')) {
            [System.IO.File]::WriteAllText((Join-Path -Path $fixture.Root -ChildPath $name), 'delete me')
        }

        $result = Remove-WacTree -Category 'containment sweep' -Path $fixture.Root

        Assert-Equal 4 (@(Get-ChildItem -LiteralPath $fixture.Outside -File).Count) `
            'the sweep followed the junction and deleted files outside the root'
        Assert-True ([System.IO.File]::Exists($fixture.Sentinel))
        Assert-Equal 2 ([int]$result.FilesDeleted) 'the ordinary files inside the root were not cleaned'
        Assert-Equal 1 ([int]$result.ReparsePointsDeleted) 'the junction was not removed as a link'
        Assert-Equal 0 ([int]$result.Failed)
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'allowlisted\swapped')
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A junction AT the root is refused before anything is enumerated' {
    $sandbox = New-TestSandbox -Prefix 'contain-root'
    try {
        $outside = Join-Path -Path $sandbox -ChildPath 'outside'
        [void][System.IO.Directory]::CreateDirectory($outside)
        [System.IO.File]::WriteAllText((Join-Path -Path $outside -ChildPath 'SENTINEL.txt'), 'must survive')

        $rootLink = Join-Path -Path $sandbox -ChildPath 'rootlink'
        New-TestJunction -Link $rootLink -Target $outside

        $result = Remove-WacTree -Category 'reparse root' -Path $rootLink

        Assert-False $result.Attempted 'a reparse-point root was accepted as a cleanup target'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $outside -ChildPath 'SENTINEL.txt'))
        Assert-Equal 0 ([int]$result.FilesDeleted)
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'rootlink')
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
