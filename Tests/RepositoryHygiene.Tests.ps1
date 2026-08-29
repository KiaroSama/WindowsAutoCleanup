#Requires -Version 5.1
<#
.SYNOPSIS
    Mechanical enforcement of the two repository rules that were previously only ever checked by
    hand: pure-ASCII source with no byte-order mark, and the 800-line file ceiling.

.DESCRIPTION
    Both rules are project policy, and until this suite existed neither was enforced by anything.
    That is not a theoretical gap. During the sixth-brief work three agents each appended "a bit" to
    src\WindowsAutoCleanup.Core.psm1 and drove it to 2433 lines; CI was green throughout, because
    nothing in CI or in any suite looked at file length. A rule only the reviewer applies is not a
    rule, it is a habit - and habits do not survive a subagent.

    The encoding rule matters for a different reason. This project ships PowerShell that must parse
    identically on Windows PowerShell 5.1 and PowerShell 7, and 5.1 reads a BOM-less file as the
    host's ANSI code page. A stray non-ASCII byte therefore means one thing on the developer's
    machine and another on a machine with a different locale, which is exactly the class of defect
    that only shows up on someone else's computer.

    THE SCANNER PROVES IT IS NOT BLIND. An enumeration that silently matched nothing would let both
    rules pass forever while asserting nothing, which is the failure shape this project has already
    shipped eight times. So the file set has a floor, and the detectors are run against a synthetic
    file that violates all three conditions.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot

# The ceiling the user set. It is a hard limit on what may be written or edited, not a review hint.
$script:LineCeiling = 800

# A broken enumeration is the one way this suite could pass while checking nothing, so the count has
# a floor. It is deliberately well below the real total (73 at the time of writing) so an ordinary
# split or merge does not trip it, while a set that collapsed to a handful of files does.
$script:MinimumFileCount = 50

function Get-HygieneFile {
    <#
    .SYNOPSIS
        Every PowerShell file this repository ships or tests with.
    .DESCRIPTION
        The repository root, src\ and Tests\ only. Agent runtimes (.claude, .kiro, .codex) and any
        other dot-directory are excluded: they are git-ignored, they are not ours, and their size and
        encoding are not this project's business.
    #>
    $files = New-Object 'System.Collections.Generic.List[System.IO.FileInfo]'

    foreach ($file in @(Get-ChildItem -LiteralPath $script:RepoRoot -File)) {
        if ($file.Extension -imatch '^\.psm?1$') { [void]$files.Add($file) }
    }

    foreach ($directory in @('src', 'Tests')) {
        $path = Join-Path -Path $script:RepoRoot -ChildPath $directory
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $path -File -Recurse)) {
            if ($file.Extension -imatch '^\.psd?1$' -or $file.Extension -imatch '^\.psm?1$') {
                [void]$files.Add($file)
            }
        }
    }

    return @($files.ToArray())
}

function Test-HygieneHasBom {
    param([Parameter(Mandatory = $true)][byte[]]$Byte)

    if ($Byte.Length -lt 3) { return $false }
    return ($Byte[0] -eq 0xEF -and $Byte[1] -eq 0xBB -and $Byte[2] -eq 0xBF)
}

function Get-HygieneNonAsciiOffset {
    <#
    .SYNOPSIS
        The offset of the first byte above 0x7F, or -1 when the content is pure ASCII.
    .DESCRIPTION
        Reports the OFFSET rather than a count, because "there is a non-ASCII byte somewhere in a
        700-line file" is not an actionable failure message.
    #>
    param([Parameter(Mandatory = $true)][byte[]]$Byte)

    for ($i = 0; $i -lt $Byte.Length; $i++) {
        if ($Byte[$i] -gt 127) { return $i }
    }
    return -1
}

function Get-HygieneLineCount {
    param([Parameter(Mandatory = $true)][string]$Path)

    return @([System.IO.File]::ReadAllLines($Path)).Count
}

# ---------------------------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------------------------

Test-Case 'Every PowerShell file is pure ASCII with no byte-order mark' {
    $files = Get-HygieneFile
    Assert-True ($files.Count -ge $script:MinimumFileCount) `
        ('the file scan collapsed to {0} files, below the floor of {1} - the scan is broken, not the repository' -f $files.Count, $script:MinimumFileCount)

    $offenders = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in $files) {
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        if (Test-HygieneHasBom -Byte $bytes) {
            [void]$offenders.Add(('{0}: byte-order mark' -f $file.Name))
            continue
        }
        $offset = Get-HygieneNonAsciiOffset -Byte $bytes
        if ($offset -ge 0) {
            [void]$offenders.Add(('{0}: non-ASCII byte 0x{1:X2} at offset {2}' -f $file.Name, $bytes[$offset], $offset))
        }
    }

    Assert-Equal 0 $offenders.Count ($offenders -join '; ')
}

Test-Case 'No PowerShell file crosses the 800-line ceiling' {
    $files = Get-HygieneFile
    Assert-True ($files.Count -ge $script:MinimumFileCount) `
        ('the file scan collapsed to {0} files, below the floor of {1}' -f $files.Count, $script:MinimumFileCount)

    $offenders = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in $files) {
        $lines = Get-HygieneLineCount -Path $file.FullName
        if ($lines -ge $script:LineCeiling) {
            [void]$offenders.Add(('{0}: {1} lines' -f $file.Name, $lines))
        }
    }

    # The message names every offender and its size, because "something is too long" sends the
    # reader back to the same measurement this test just made.
    Assert-Equal 0 $offenders.Count `
        ('split by responsibility before adding more: {0}' -f ($offenders -join '; '))
}

Test-Case 'The hygiene scanner detects the violations it exists to catch' {
    <#
        Without this, an enumeration that stopped matching, or a detector that always returned the
        clean answer, would leave both rules above passing forever while checking nothing.
    #>
    $sandbox = New-TestSandbox -Prefix 'hygiene-control'
    try {
        $bomPath = Join-Path -Path $sandbox -ChildPath 'bom.ps1'
        $bytes = @(0xEF, 0xBB, 0xBF) + [System.Text.Encoding]::ASCII.GetBytes("'ok'")
        [System.IO.File]::WriteAllBytes($bomPath, [byte[]]$bytes)
        Assert-True (Test-HygieneHasBom -Byte ([System.IO.File]::ReadAllBytes($bomPath))) `
            'a file that starts with a byte-order mark was reported clean'

        $wide = [System.IO.File]::ReadAllBytes($bomPath)
        Assert-Equal -1 (Get-HygieneNonAsciiOffset -Byte ([System.Text.Encoding]::ASCII.GetBytes("plain ascii"))) `
            'pure ASCII content was reported as non-ASCII'
        Assert-True ((Get-HygieneNonAsciiOffset -Byte $wide) -ge 0) `
            'a byte above 0x7F was not detected'

        $longPath = Join-Path -Path $sandbox -ChildPath 'long.ps1'
        [System.IO.File]::WriteAllLines($longPath, [string[]]@(1..$script:LineCeiling | ForEach-Object { "# $_" }))
        Assert-True ((Get-HygieneLineCount -Path $longPath) -ge $script:LineCeiling) `
            'a file at the ceiling was measured as under it'

        $shortPath = Join-Path -Path $sandbox -ChildPath 'short.ps1'
        [System.IO.File]::WriteAllLines($shortPath, [string[]]@('# one', '# two'))
        Assert-Equal 2 (Get-HygieneLineCount -Path $shortPath) 'the line counter does not count lines'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
