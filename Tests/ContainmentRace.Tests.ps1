#Requires -Version 5.1
<#
.SYNOPSIS
    Pins containment against a LIVE adversary: a junction swapped while the sweep is running.

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

function New-SandboxDirectory {
    <#
    .SYNOPSIS
        Creates a directory inside the sandbox and returns its path.
    .DESCRIPTION
        Local to this suite on purpose: the equivalent helper lives in FileSystem.Tests.ps1, and a
        suite that borrows a function from another suite only works while both happen to be loaded
        in the same process - which they never are, because every suite runs as its own child.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    [void][System.IO.Directory]::CreateDirectory($Path)
    return $Path
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
# The ancestor-swap race (ledger B2-2 / T-3)
#
# The claim under test is NOT "this is race-free". It cannot be: the delete is issued by pathname
# and the identity check is a separate resolution of the same name, and .NET offers no delete that
# takes a handle on either host. What is claimed, and what these cases pin, is that a swap already
# in place when the check runs is refused, that the refusal is counted where an exit code can see
# it, and that the window left over is the sub-millisecond one between the check and the syscall
# rather than the multi-second one the predecessor design left open per directory.
# ---------------------------------------------------------------------------------------------

Test-Case 'A swap after the path was captured kills a sentinel unguarded, and is refused guarded' {
    <#
        Two runs of the identical sequence over the identical fixture, differing only in which
        deleter is used. The first is the positive control: without it, "the sentinel survived" would
        also be true of a fixture that was never lethal, and every other case in this file would pass
        against a guard that does nothing.
    #>

    # 1. UNGUARDED. Capture the pathname the way enumeration does, let the ancestor be swapped, then
    #    delete by that captured name. This is the attack, and it must succeed here.
    $control = New-TestSandbox -Prefix 'contain-swap-control'
    try {
        $root = Join-Path -Path $control -ChildPath 'allowlisted'
        $spool = Join-Path -Path $root -ChildPath 'spool'
        $outside = Join-Path -Path $control -ChildPath 'outside'
        [void][System.IO.Directory]::CreateDirectory($spool)
        [void][System.IO.Directory]::CreateDirectory($outside)

        $captured = Join-Path -Path $spool -ChildPath 'victim.tmp'
        [System.IO.File]::WriteAllText($captured, 'inside the root')
        $sentinel = Join-Path -Path $outside -ChildPath 'victim.tmp'
        [System.IO.File]::WriteAllText($sentinel, 'MUST SURVIVE')

        # the swap
        [System.IO.File]::Delete($captured)
        [System.IO.Directory]::Delete($spool, $false)
        New-TestJunction -Link $spool -Target $outside

        [System.IO.File]::Delete($captured)
        Assert-False ([System.IO.File]::Exists($sentinel)) `
            'the fixture is not lethal, so nothing in this file proves the guard does anything'
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $control -ChildPath 'allowlisted\spool')
        Remove-TestSandbox -Path $control
    }

    # 2. GUARDED. Same fixture, same sequence, same captured pathname - routed through the module.
    $guarded = New-TestSandbox -Prefix 'contain-swap-guarded'
    try {
        $root = Join-Path -Path $guarded -ChildPath 'allowlisted'
        $spool = Join-Path -Path $root -ChildPath 'spool'
        $outside = Join-Path -Path $guarded -ChildPath 'outside'
        [void][System.IO.Directory]::CreateDirectory($spool)
        [void][System.IO.Directory]::CreateDirectory($outside)

        $captured = Join-Path -Path $spool -ChildPath 'victim.tmp'
        [System.IO.File]::WriteAllText($captured, 'inside the root')
        $sentinel = Join-Path -Path $outside -ChildPath 'victim.tmp'
        [System.IO.File]::WriteAllText($sentinel, 'MUST SURVIVE')

        [System.IO.File]::Delete($captured)
        [System.IO.Directory]::Delete($spool, $false)
        New-TestJunction -Link $spool -Target $outside

        $stats = New-WacDeletionStats
        Remove-WacLeaf -Path $captured -RootPath $root -Stats $stats

        Assert-True ([System.IO.File]::Exists($sentinel)) 'the swap reached the sentinel through the guard'
        Assert-Equal 'MUST SURVIVE' ([System.IO.File]::ReadAllText($sentinel))
        Assert-Equal 0 ([int]$stats.FilesDeleted)
        Assert-Equal 1 ([int]$stats.RefusedIdentity) 'the swap was not counted as an identity refusal'
        Assert-Equal 0 ([int]$stats.SkippedVanished) 'a live redirected path was written off as vanished'
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $guarded -ChildPath 'allowlisted\spool')
        Remove-TestSandbox -Path $guarded
    }
}

Test-Case 'A concurrent junction-swap adversary never reaches a sentinel outside the swept tree' {
    <#
        The real shape of the attack: a second thread races the sweep, emptying and re-pointing a
        directory the sweep is walking, for as long as the sweep runs. Sentinels live in a SEPARATE
        sandbox that the sweep has no path to, and they are named to collide with the files inside
        the swept tree, so a delete that resolved through a swapped ancestor lands on one of them.

        Bounded by an iteration count AND a wall deadline; synchronised by an event and a stop flag,
        never by a sleep; the adversary is torn down and disposed in the finally.

        WHAT THIS CASE IS NOT. It is live-fire assurance, not a regression detector. Measured: with
        Remove-WacLeaf's identity re-check, the descend re-check AND the entry within-root check all
        replaced by 'if ($false)', this case still PASSED on both hosts (37 and 61 swaps, zero
        refusals) - the adversary simply never landed a swap in the sub-millisecond window where a
        colliding name was about to be deleted. That is itself the measurement of how narrow the
        residual window is, but it means a future regression will be caught by the deterministic
        case above, which fails on both hosts under the same mutation, and not by this one. Do not
        delete that case and keep this one.
    #>
    $swept = New-TestSandbox -Prefix 'contain-race'
    $keep = New-TestSandbox -Prefix 'contain-race-keep'
    $runspace = $null
    $shell = $null
    $async = $null
    $ready = New-Object System.Threading.ManualResetEventSlim($false)
    $state = [hashtable]::Synchronized(@{ stop = $false; swaps = 0; errors = 0 })

    $root = Join-Path -Path $swept -ChildPath 'allowlisted'
    $spool = Join-Path -Path $root -ChildPath 'spool'

    try {
        [void][System.IO.Directory]::CreateDirectory($root)

        $names = New-Object 'System.Collections.Generic.List[string]'
        [void]$names.Add('SENTINEL.dll')
        for ($i = 0; $i -lt 40; $i++) { [void]$names.Add(('f{0:000}.tmp' -f $i)) }
        foreach ($name in $names) {
            [System.IO.File]::WriteAllText((Join-Path -Path $keep -ChildPath $name), 'MUST SURVIVE')
        }
        $expected = $names.Count

        $adversary = {
            param($SpoolPath, $EscapeTarget, $State, $Ready)

            $Ready.Set()
            while (-not $State['stop']) {
                try {
                    if ([System.IO.Directory]::Exists($SpoolPath)) {
                        $isLink = $false
                        try {
                            $isLink = ((([int][System.IO.File]::GetAttributes($SpoolPath)) -band
                                        ([int][System.IO.FileAttributes]::ReparsePoint)) -ne 0)
                        }
                        catch { $isLink = $false }

                        if (-not $isLink) {
                            foreach ($file in [System.IO.Directory]::GetFiles($SpoolPath)) {
                                try { [System.IO.File]::Delete($file) } catch { $null = $_ }
                            }
                        }
                        # Directory.Delete removes a junction as a link and a real directory only
                        # when it is empty, which is exactly the two behaviours wanted here.
                        try { [System.IO.Directory]::Delete($SpoolPath, $false) } catch { $null = $_ }
                    }
                    else {
                        New-Item -ItemType Junction -Path $SpoolPath -Target $EscapeTarget -ErrorAction Stop | Out-Null
                        $State['swaps'] = [int]$State['swaps'] + 1
                    }
                }
                catch {
                    $State['errors'] = [int]$State['errors'] + 1
                }
            }
        }

        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.Open()
        $shell = [powershell]::Create()
        $shell.Runspace = $runspace
        [void]$shell.AddScript([string]$adversary)
        [void]$shell.AddArgument($spool)
        [void]$shell.AddArgument($keep)
        [void]$shell.AddArgument($state)
        [void]$shell.AddArgument($ready)
        $async = $shell.BeginInvoke()

        Assert-True ($ready.Wait(10000)) 'the adversary runspace never started'

        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $iterations = 0
        $refusals = 0L
        while ($iterations -lt 10 -and $watch.Elapsed.TotalMilliseconds -lt 8000) {
            $iterations++

            # Rebuilding the bait races the adversary by design, so every step of it is tolerant.
            try {
                if (-not [System.IO.Directory]::Exists($spool)) {
                    [void][System.IO.Directory]::CreateDirectory($spool)
                }
                foreach ($name in $names) {
                    try { [System.IO.File]::WriteAllText((Join-Path -Path $spool -ChildPath $name), 'delete me') }
                    catch { $null = $_ }
                }
            }
            catch {
                $null = $_
            }

            $result = Remove-WacTree -Category 'race' -Path $root
            $refusals += [int64]$result.Refused

            # THE assertion. Nothing in the other sandbox may be touched, on any iteration, ever.
            $survivors = 0
            try { $survivors = @([System.IO.Directory]::GetFiles($keep)).Count } catch { $survivors = -1 }
            Assert-Equal $expected $survivors `
                ('iteration ' + $iterations + ': the sweep reached outside the swept sandbox (swaps=' +
                 $state['swaps'] + ' refusals=' + $refusals + ')')
        }
        $watch.Stop()

        # Without this the case would pass against an adversary that never managed a single swap.
        Assert-True ([int]$state['swaps'] -ge 1) `
            ('the adversary never installed a junction, so nothing was actually raced (errors=' +
             $state['errors'] + ')')
        Assert-True ($iterations -ge 1)

        Write-Host ('      race evidence: iterations={0} swaps={1} refusals={2} elapsedMs={3}' -f `
            $iterations, $state['swaps'], $refusals, [int]$watch.Elapsed.TotalMilliseconds)
    }
    finally {
        $state['stop'] = $true
        if ($async -and $shell) {
            try {
                if (-not $async.AsyncWaitHandle.WaitOne(10000)) { $shell.Stop() }
                else { [void]$shell.EndInvoke($async) }
            }
            catch { $null = $_ }
        }
        if ($shell) { try { $shell.Dispose() } catch { $null = $_ } }
        if ($runspace) { try { $runspace.Dispose() } catch { $null = $_ } }
        try { $ready.Dispose() } catch { $null = $_ }
        Remove-TestJunction -Link $spool
        Remove-TestSandbox -Path $swept
        Remove-TestSandbox -Path $keep
    }
}

Test-Case 'Delayed deletion is never used, because no check made now can bind the name resolved at boot' {
    <#
        MoveFileEx(..., MOVEFILE_DELAY_UNTIL_REBOOT) stores the literal path STRING and Session
        Manager resolves it at the next boot. Part 2 below measures precisely why a pre-registration
        check cannot help: the same string, authorised while it named a file inside the root, names a
        file outside it a moment later. Nothing is registered with the OS by this case - queueing a
        real deletion against the machine running the suite is exactly what must never happen.
    #>
    $sandbox = New-TestSandbox -Prefix 'contain-delayed'
    $handle = $null
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'allowlisted'
        $spool = Join-Path -Path $root -ChildPath 'spool'
        $outside = Join-Path -Path $sandbox -ChildPath 'outside'
        [void][System.IO.Directory]::CreateDirectory($spool)
        [void][System.IO.Directory]::CreateDirectory($outside)

        $locked = Join-Path -Path $spool -ChildPath 'locked.bin'
        [System.IO.File]::WriteAllText($locked, 'inside the root')
        [System.IO.File]::WriteAllText((Join-Path -Path $outside -ChildPath 'locked.bin'), 'MUST SURVIVE')

        # 1. A locked file is accounted as locked. It is not queued, at any privilege level.
        $handle = New-Object System.IO.FileStream(
            $locked, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

        $result = Remove-WacTree -Category 'delayed' -Path $root

        Assert-Equal 0 ([int]$result.PendingDeletes) 'a path was queued for deletion at the next boot'
        Assert-Equal 1 ([int]$result.SkippedLocked) `
            ('locked=' + $result.SkippedLocked + ' denied=' + $result.SkippedDenied)
        Assert-True ([System.IO.File]::Exists($locked))

        # 2. The reason. Core would have authorised this exact path a moment ago...
        Assert-True (Test-WacIsDeleteOnRebootAllowed -Path $locked) `
            'the premise changed: the registration guard now refuses an ordinary in-root file'

        $handle.Dispose()
        $handle = $null

        # ...and here is the swap an attacker has until the next restart to perform.
        [System.IO.File]::Delete($locked)
        [System.IO.Directory]::Delete($spool, $false)
        New-TestJunction -Link $spool -Target $outside

        # Same string. Different file. Outside the root. Nothing re-checks it at boot.
        Assert-Equal 'MUST SURVIVE' ([System.IO.File]::ReadAllText($locked)) `
            'the fixture failed to re-point the path, so this proves nothing'
        Assert-False (Test-WacIsDeleteOnRebootAllowed -Path $locked) `
            'the guard cannot even see the redirection when asked again'
    }
    finally {
        if ($handle) { try { $handle.Dispose() } catch { $null = $_ } }
        Remove-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'allowlisted\spool')
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'An ordinary reparse-point root is a skip and never a refusal' {
    <#
        The counter that decides the exit code has to stay quiet on the shapes a real run meets. A
        real elevated run reported skipReparse=3, every one of them the 'Temporary Internet Files'
        junction that ships in every Windows profile. If that scored as a refusal the tool would
        report a security event on every machine, every day.
    #>
    $sandbox = New-TestSandbox -Prefix 'contain-benign'
    try {
        $outside = Join-Path -Path $sandbox -ChildPath 'INetCache'
        [void][System.IO.Directory]::CreateDirectory($outside)
        [System.IO.File]::WriteAllText((Join-Path -Path $outside -ChildPath 'cached.dat'), 'must survive')

        $link = Join-Path -Path $sandbox -ChildPath 'Temporary Internet Files'
        New-TestJunction -Link $link -Target $outside

        $tree = Remove-WacTree -Category 'Internet cache (Temporary Internet Files)' -Path $link
        Assert-False $tree.Attempted
        Assert-Equal 1 ([int]$tree.SkippedReparse)
        Assert-Equal 0 ([int]$tree.RefusedIdentity)
        Assert-Equal 0 ([int]$tree.RefusedOutOfRoot)
        Assert-Equal 0 ([int]$tree.Refused) 'a routine reparse-point root was reported as a security refusal'

        $pattern = Remove-WacFilesByPattern -Category 'thumbs' -Path $link -Pattern @('*.dat')
        Assert-False $pattern.Attempted
        Assert-Equal 1 ([int]$pattern.SkippedReparse)
        Assert-Equal 0 ([int]$pattern.RefusedIdentity)
        Assert-Equal 0 ([int]$pattern.RefusedOutOfRoot)
        Assert-Equal 0 ([int]$pattern.Refused) 'a routine reparse-point pattern root was reported as a refusal'

        Assert-True ([System.IO.File]::Exists((Join-Path -Path $outside -ChildPath 'cached.dat')))
    }
    finally {
        Remove-TestJunction -Link (Join-Path -Path $sandbox -ChildPath 'Temporary Internet Files')
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A reparse LEAF reached through a swapped ancestor is refused, not unlinked' {
    <#
        The hole this closes, and it was the orchestrator's own: DeleteBoundLeaf used to skip the
        identity proof whenever openReparsePoint was set, on the reasoning that resolving a link is
        exactly what must not happen when the link is the thing being removed.

        That reasoning was half right. FILE_FLAG_OPEN_REPARSE_POINT stops the FINAL component being
        followed; every INTERMEDIATE component is still resolved. So an ancestor swapped to a
        junction redirected the open to a DIFFERENT link entirely - one outside the allow-list - and
        because the identity branch was skipped, expectedFinalPath was ignored and that outside link
        was unlinked.

        The fix is structural: the parent is opened and proved, then the leaf is opened RELATIVE to
        that handle. Here the ancestor is swapped BEFORE the call, so the parent's proved final path
        does not match and the whole operation is refused with nothing touched.
    #>
    $sandbox = New-TestSandbox -Prefix 'race-reparse-leaf'
    try {
        $root = New-SandboxDirectory -Path (Join-Path -Path $sandbox -ChildPath 'root')
        $real = New-SandboxDirectory -Path (Join-Path -Path $root -ChildPath 'real')

        # What the sweep believes it is deleting: a junction inside the allow-listed root.
        $ownTarget = New-SandboxDirectory -Path (Join-Path -Path $sandbox -ChildPath 'ownTarget')
        $ownLink = Join-Path -Path $real -ChildPath 'link'
        New-TestJunction -Link $ownLink -Target $ownTarget

        # What an ancestor swap would substitute: a junction the tool has no business touching,
        # pointing at a sentinel that must survive.
        $decoy = New-SandboxDirectory -Path (Join-Path -Path $sandbox -ChildPath 'decoy')
        $outsideTarget = New-SandboxDirectory -Path (Join-Path -Path $sandbox -ChildPath 'outsideTarget')
        $sentinel = Join-Path -Path $outsideTarget -ChildPath 'sentinel.txt'
        [System.IO.File]::WriteAllText($sentinel, 'must survive')
        $decoyLink = Join-Path -Path $decoy -ChildPath 'link'
        New-TestJunction -Link $decoyLink -Target $outsideTarget

        # The swap. 'root\real' now resolves to 'decoy', so 'root\real\link' names decoy\link.
        Remove-TestJunction -Link $ownLink
        [System.IO.Directory]::Delete($real, $true)
        New-TestJunction -Link $real -Target $decoy

        $stats = New-WacDeletionStats
        Remove-WacLeaf -Path (Join-Path -Path $real -ChildPath 'link') -RootPath $root -Stats $stats -IsReparsePoint

        Assert-Equal 1 ([int]$stats.RefusedIdentity) 'the redirected reparse leaf was not refused on identity'
        Assert-Equal 0 ([int]$stats.ReparsePointsDeleted) 'a redirected link was counted as deleted'
        Assert-True (Test-Path -LiteralPath $decoyLink) 'the link OUTSIDE the allow-list was unlinked'
        Assert-True (Test-Path -LiteralPath $sentinel) 'the sentinel behind the outside link did not survive'
    }
    finally {
        foreach ($link in @((Join-Path -Path $sandbox -ChildPath 'root\real'),
                            (Join-Path -Path $sandbox -ChildPath 'decoy\link'))) {
            if (Test-Path -LiteralPath $link) { Remove-TestJunction -Link $link }
        }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'An ordinary reparse leaf inside its real parent is still deleted as a link' {
    <#
        The other direction, and the one that matters for every normal run: the containment proof
        must not turn routine link removal into a refusal. A junction inside the allow-list is
        unlinked and whatever it points at is untouched.
    #>
    $sandbox = New-TestSandbox -Prefix 'race-reparse-benign'
    try {
        $root = New-SandboxDirectory -Path (Join-Path -Path $sandbox -ChildPath 'root')
        $target = New-SandboxDirectory -Path (Join-Path -Path $sandbox -ChildPath 'target')
        $keep = Join-Path -Path $target -ChildPath 'keep.txt'
        [System.IO.File]::WriteAllText($keep, 'untouched')

        $link = Join-Path -Path $root -ChildPath 'link'
        New-TestJunction -Link $link -Target $target

        $stats = New-WacDeletionStats
        Remove-WacLeaf -Path $link -RootPath $root -Stats $stats -IsReparsePoint

        Assert-Equal 1 ([int]$stats.ReparsePointsDeleted) 'an ordinary link inside the root was not deleted'
        Assert-Equal 0 ([int]$stats.RefusedIdentity) 'an ordinary link was refused as an identity mismatch'
        Assert-False (Test-Path -LiteralPath $link) 'the link is still there'
        Assert-True (Test-Path -LiteralPath $keep) 'the link target was followed and its content deleted'
    }
    finally {
        $link = Join-Path -Path $sandbox -ChildPath 'root\link'
        if (Test-Path -LiteralPath $link) { Remove-TestJunction -Link $link }
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
