#Requires -Version 5.1
<#
.SYNOPSIS
    A name whose canonical form points at a DIFFERENT object must never reach that object.

.DESCRIPTION
    Split out of FileSystem.Tests because it answers a different question. That suite asks whether a
    tree is swept correctly - containment, reparse points, attributes, long paths, deepest-first
    order, the deadline. These three ask whether the NAME the sweep was handed still means what it
    said by the time the kernel resolves it, which is a property of canonicalisation rather than of
    traversal, and every one of them was a live containment hole that reported FilesDeleted=1.

    Each case builds its own disposable tree under TEMP and releases it in a finally block. The
    entries with trailing dots and spaces can only be created through the extended-length namespace,
    which is why the fixtures reach for it directly rather than through the ordinary cmdlets.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.FileSystem.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

# Carried rather than shared: five suites already keep their own copies of these two, so a shared
# fixture would be a refactor of all of them and this split is not the place for it.
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

Test-Case 'A trailing-dot leaf never destroys the neighbour it normalises onto' {
    <#
        The defect this pins, measured before the fix: asking Remove-WacLeaf to delete 'note.txt.'
        deleted 'note.txt' and recorded FilesDeleted=1. A wrong object, destroyed by a process
        running as SYSTEM, reported as a success.

        The handle-bound identity proof did not catch it and could not: expectedFinalPath is
        produced by Get-WacNormalizedPath, the same function that dropped the dot, so both sides of
        the comparison were corrupted identically and matched. That is why the guard belongs in
        normalisation and why this case asserts the SURVIVOR rather than only the counter - a fix
        that merely stopped counting would leave the neighbour just as dead.

        Both entry kinds are covered because the two took different paths through the delete: the
        file case reported FilesDeleted, the directory case DirectoriesDeleted.
    #>
    $sandbox = New-TestSandbox -Prefix 'fs-trailing-dot'
    try {
        # \\?\ is the only way to create these names; Win32 would strip the dot on the way in.
        $neighbourFile = New-TestFile -Path (Join-Path -Path $sandbox -ChildPath 'note.txt') -Content 'MUST SURVIVE'
        [System.IO.File]::WriteAllText(('\\?\' + (Join-Path -Path $sandbox -ChildPath 'note.txt.')), 'the intended target')

        $stats = New-WacDeletionStats
        Remove-WacLeaf -Path (Join-Path -Path $sandbox -ChildPath 'note.txt.') -RootPath $sandbox -Stats $stats

        Assert-Equal 0 ([int]$stats.FilesDeleted) 'a file was deleted for a name that cannot be canonicalised'
        Assert-True (Test-Path -LiteralPath $neighbourFile) 'the neighbour the dotted name normalises onto was destroyed'
        Assert-Equal 'MUST SURVIVE' ([System.IO.File]::ReadAllText($neighbourFile)) 'the neighbour was replaced rather than removed'
        Assert-Equal 0 ([int]$stats.RefusedOutOfRoot) 'an unresolvable name was reported as a containment escape'

        $neighbourDir = New-TestDirectory -Path (Join-Path -Path $sandbox -ChildPath 'sub')
        $null = [System.IO.Directory]::CreateDirectory('\\?\' + (Join-Path -Path $sandbox -ChildPath 'sub.'))

        $dirStats = New-WacDeletionStats
        Remove-WacLeaf -Path (Join-Path -Path $sandbox -ChildPath 'sub.') -RootPath $sandbox -Stats $dirStats -IsDirectory

        Assert-Equal 0 ([int]$dirStats.DirectoriesDeleted) 'a directory was deleted for a name that cannot be canonicalised'
        Assert-True (Test-Path -LiteralPath $neighbourDir) 'the neighbouring directory was destroyed'

        # The control, in the same sandbox: the guard must not have stopped ordinary deletion.
        $ordinary = New-TestFile -Path (Join-Path -Path $sandbox -ChildPath 'ordinary.txt') -Content 'x'
        $okStats = New-WacDeletionStats
        Remove-WacLeaf -Path $ordinary -RootPath $sandbox -Stats $okStats
        Assert-Equal 1 ([int]$okStats.FilesDeleted) 'the guard stopped an ordinary delete'
        Assert-False (Test-Path -LiteralPath $ordinary) 'an ordinary file survived its own deletion'
    }
    finally {
        foreach ($odd in @('note.txt.', 'sub.')) {
            $p = '\\?\' + (Join-Path -Path $sandbox -ChildPath $odd)
            try {
                if ([System.IO.Directory]::Exists($p)) { [System.IO.Directory]::Delete($p, $true) }
                elseif ([System.IO.File]::Exists($p)) { [System.IO.File]::Delete($p) }
            }
            catch { $null = $_ }
        }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'An 8.3 alias carrying a trailing character never reaches the object it expands to' {
    <#
        WHAT THIS PROVES, and what it does NOT - stated because the difference caught me out.

        It proves end to end that an alias-SHAPED name carrying a trailing character is refused and
        that the object the alias expands to survives: the directory, the file inside it, and its
        contents are all still there afterwards, on a sandbox where the volume really did generate
        the short name (the evidence line records which).

        It does NOT pin the alias-plus-trailing-character COMPOSITION that brief 9 reported, and
        mutation says so plainly: reverted to the old predicate this case still passes. The reason
        is that the old rule canonicalised each segment under 'C:\', where a sandbox's short name
        does not resolve, so only an alias for a child of the VOLUME ROOT ever triggered it. The
        only reproducer is therefore a real one - 'C:\PROGRA~1.' - and proving it end to end would
        mean asking the deletion path to act inside C:\Program Files. That test is not worth its
        risk. The composition is pinned in Path.Tests instead, where it is a string question with
        nothing to destroy, and mutation shows that assertion failing with
        'expected [] but got [C:\Program Files]'.

        So this case stays as an end-to-end regression guard on alias-shaped names, not as the
        evidence for that fix.
    #>
    $sandbox = New-TestSandbox -Prefix 'fs-shortname'
    try {
        $victimDir = New-TestDirectory -Path (Join-Path -Path $sandbox -ChildPath 'LongDirectoryName')
        $sentinel = New-TestFile -Path (Join-Path -Path $victimDir -ChildPath 'sentinel.txt') -Content 'MUST SURVIVE'

        # The real generated alias when there is one; otherwise a literal of the same shape.
        $alias = 'LONGDI~1'
        try {
            $fso = New-Object -ComObject Scripting.FileSystemObject
            $alias = Split-Path -Path ($fso.GetFolder($victimDir).ShortPath) -Leaf
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($fso)
        }
        catch { $null = $_ }

        $aliasExpands = ($alias -cne 'LongDirectoryName') -and
                        ((Get-WacNormalizedPath -Path (Join-Path -Path $sandbox -ChildPath $alias)) -ceq $victimDir)

        foreach ($trailing in @('.', ' ')) {
            $ambiguous = Join-Path -Path $sandbox -ChildPath ($alias + $trailing)
            Assert-Equal $null (Get-WacNormalizedPath -Path $ambiguous) `
                ('an 8.3 alias with a trailing character was canonicalised: ' + $ambiguous)

            $stats = New-WacDeletionStats
            Remove-WacLeaf -Path (Join-Path -Path $ambiguous -ChildPath 'sentinel.txt') -RootPath $sandbox -Stats $stats
            Assert-Equal 0 ([int]$stats.FilesDeleted) 'a file was deleted through an 8.3 alias with a trailing character'

            $dirStats = New-WacDeletionStats
            Remove-WacLeaf -Path $ambiguous -RootPath $sandbox -Stats $dirStats -IsDirectory
            Assert-Equal 0 ([int]$dirStats.DirectoriesDeleted) 'a directory was deleted through an 8.3 alias with a trailing character'
        }

        Assert-True (Test-Path -LiteralPath $sentinel) 'the object the alias expands to was destroyed'
        Assert-Equal 'MUST SURVIVE' ([System.IO.File]::ReadAllText($sentinel)) 'the neighbour was rewritten'
        Assert-True (Test-Path -LiteralPath $victimDir) 'the directory the alias expands to was destroyed'

        # Recorded as evidence, not asserted as a requirement: a volume with 8.3 creation disabled
        # still runs every assertion above, it just proves less about what the alias pointed at.
        Write-Host ('      evidence: alias={0} expandsToTheNeighbour={1}' -f $alias, $aliasExpands)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'An ambiguous INTERMEDIATE segment never redirects the delete into the wrong directory' {
    <#
        Guarding only the final component left this alias wide open, and it is the worse of the
        two: 'root\dir.\victim.txt' canonicalises to 'root\dir\victim.txt', so the delete does not
        merely hit the wrong FILE, it descends into the wrong DIRECTORY. Measured before the fix -
        the file inside 'dir' was destroyed and the run recorded FilesDeleted=1.

        The decoy here is a file that WOULD die. An earlier probe of this defect used a non-empty
        directory as the decoy, whose delete failed for an unrelated reason, and that masked a live
        containment hole for a whole round of review.
    #>
    $sandbox = New-TestSandbox -Prefix 'fs-mid-segment'
    try {
        $plainDir = New-TestDirectory -Path (Join-Path -Path $sandbox -ChildPath 'dir')
        $victim = New-TestFile -Path (Join-Path -Path $plainDir -ChildPath 'victim.txt') -Content 'MUST SURVIVE'

        $null = [System.IO.Directory]::CreateDirectory('\\?\' + (Join-Path -Path $sandbox -ChildPath 'dir.'))
        [System.IO.File]::WriteAllText(
            ('\\?\' + (Join-Path -Path $sandbox -ChildPath 'dir.\victim.txt')), 'the intended target')

        $stats = New-WacDeletionStats
        Remove-WacLeaf -Path (Join-Path -Path $sandbox -ChildPath 'dir.\victim.txt') -RootPath $sandbox -Stats $stats

        Assert-Equal 0 ([int]$stats.FilesDeleted) 'a file was deleted through an ambiguous intermediate segment'
        Assert-True (Test-Path -LiteralPath $victim) 'the file in the neighbouring directory was destroyed'
        Assert-Equal 'MUST SURVIVE' ([System.IO.File]::ReadAllText($victim)) 'the neighbour was replaced rather than removed'
        Assert-True (Test-Path -LiteralPath $plainDir) 'the neighbouring directory itself was destroyed'

        # A trailing U+00A0 is the other alias the whole-string .Trim() used to open. The two hosts
        # disagree about whether the name survives canonicalisation at all (see Path.Tests.ps1), so
        # only the safety property is asserted here - it is the half that must hold on both.
        $nbsp = [char]0x00A0
        $neighbour = New-TestFile -Path (Join-Path -Path $sandbox -ChildPath 'victim') -Content 'MUST SURVIVE'
        [System.IO.File]::WriteAllText(
            ('\\?\' + (Join-Path -Path $sandbox -ChildPath ('victim' + $nbsp))), 'the intended target')

        $trimStats = New-WacDeletionStats
        Remove-WacLeaf -Path (Join-Path -Path $sandbox -ChildPath ('victim' + $nbsp)) -RootPath $sandbox -Stats $trimStats

        Assert-True (Test-Path -LiteralPath $neighbour) 'a trailing U+00A0 was trimmed and the neighbour was destroyed'
        Assert-Equal 'MUST SURVIVE' ([System.IO.File]::ReadAllText($neighbour)) 'the neighbour was replaced rather than removed'
    }
    finally {
        $nbsp = [char]0x00A0
        foreach ($odd in @('dir.\victim.txt', 'dir.', ('victim' + $nbsp))) {
            $p = '\\?\' + (Join-Path -Path $sandbox -ChildPath $odd)
            try {
                if ([System.IO.Directory]::Exists($p)) { [System.IO.Directory]::Delete($p, $true) }
                elseif ([System.IO.File]::Exists($p)) { [System.IO.File]::Delete($p) }
            }
            catch { $null = $_ }
        }
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
