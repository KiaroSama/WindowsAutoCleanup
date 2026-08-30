#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for the audit log's record boundary: one Write-WacLog call is one physical
    line, whatever a filename or an external process put in the values.

.DESCRIPTION
    Values reaching Write-WacLog come from the filesystem and from external process output, and NTFS
    permits CR and LF in a name even though Explorer cannot type one. Before ConvertTo-WacLogSafeText
    existed, one call with a CR+LF in a -Data value produced TWO lines, the second of which was a
    complete forged record carrying its own timestamp, level, component and status - written into the
    audit log of a run that had refused. Several swept locations are world-writable by design, which
    is exactly why they are swept, so the name is attacker-chosen.

    This suite lives apart from RunState.Tests.ps1 only because that file is near the 800-line
    ceiling; the subject is the same module.

    No case creates a file whose NAME contains a control character. It is possible through the \\?\
    form and leaves a file ordinary tooling cannot remove; the string-level cases reach the same code
    path without that residue.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

function New-LogProbe {
    <#
    .SYNOPSIS
        A real run log in a disposable directory. Returns the sandbox and the log path.
    #>
    $sandbox = New-TestSandbox -Prefix 'logenc'
    [void](Initialize-WacRun -BaseName 'logenc' -CandidateRoot @($sandbox))
    return [PSCustomObject]@{ Sandbox = $sandbox; Log = (Get-WacLogPath) }
}

function Close-LogProbe {
    param([Parameter(Mandatory = $true)]$Probe)

    # Close before removing, or the live FileStream keeps the .log locked and the sandbox leaks.
    Close-WacLog
    Set-WacLogWriter -Writer $null
    Remove-TestSandbox -Path $Probe.Sandbox
}

# The payload every forgery case uses: a value that closes the record and opens a convincing one.
$script:ForgedTail = '[2026-01-01 00:00:00 UTC] [INFO] [Summary] status=Succeeded'
$script:Hostile = 'ok' + [char]13 + [char]10 + $script:ForgedTail

Test-Case 'a CR and LF in a Data value produce one record, not two' {
    $probe = New-LogProbe
    try {
        Write-WacLog -Level INFO -Component 'Enc' -Message 'subject' -Data @{ path = $script:Hostile }

        $lines = @(Get-Content -LiteralPath $probe.Log | Where-Object { $_ -match '\[Enc\]' })
        Assert-Equal 1 $lines.Count 'one Write-WacLog call wrote more than one physical line'

        $forged = @(Get-Content -LiteralPath $probe.Log | Where-Object { $_.StartsWith('[2026-01-01', [System.StringComparison]::Ordinal) })
        Assert-Equal 0 $forged.Count 'a forged record reached the audit log'
    }
    finally { Close-LogProbe -Probe $probe }
}

Test-Case 'a CR and LF in the Message produce one record too' {
    # $Message had no protection at all, and it is the parameter a caller is most likely to build by
    # interpolating an external string into a sentence.
    $probe = New-LogProbe
    try {
        Write-WacLog -Level INFO -Component 'EncMsg' -Message $script:Hostile

        $lines = @(Get-Content -LiteralPath $probe.Log | Where-Object { $_ -match '\[EncMsg\]' })
        Assert-Equal 1 $lines.Count 'a hostile Message split the record'

        $forged = @(Get-Content -LiteralPath $probe.Log | Where-Object { $_.StartsWith('[2026-01-01', [System.StringComparison]::Ordinal) })
        Assert-Equal 0 $forged.Count 'a forged record reached the audit log through the Message'
    }
    finally { Close-LogProbe -Probe $probe }
}

Test-Case 'the escape keeps the evidence readable rather than discarding it' {
    # A guard that deleted the control characters would also delete the proof that someone tried.
    $probe = New-LogProbe
    try {
        Write-WacLog -Level INFO -Component 'EncEv' -Message 'subject' -Data @{ path = $script:Hostile }

        $line = @(Get-Content -LiteralPath $probe.Log | Where-Object { $_ -match '\[EncEv\]' })[0]
        Assert-True ($line.Contains('<CR>')) ('the CR was not recorded: ' + $line)
        Assert-True ($line.Contains('<LF>')) ('the LF was not recorded: ' + $line)
        Assert-True ($line.Contains($script:ForgedTail)) ('the attempted payload was discarded: ' + $line)
    }
    finally { Close-LogProbe -Probe $probe }
}

Test-Case 'an ordinary Windows path is not altered at all' {
    # The reason the escape uses angle brackets rather than backslash escapes. Windows forbids < and
    # > in a file name, so <CR> cannot be produced by any real path - whereas a \r escape would be
    # ambiguous against C:\reports, and disambiguating THAT would mean doubling every backslash and
    # rewriting every path in the log as C:\\Windows\\Temp.
    $probe = New-LogProbe
    try {
        Write-WacLog -Level INFO -Component 'EncPlain' -Message 'ordinary' `
            -Data @{ path = 'C:\Windows\Temp'; reports = 'C:\reports\a.txt' }

        $line = @(Get-Content -LiteralPath $probe.Log | Where-Object { $_ -match '\[EncPlain\]' })[0]
        Assert-True ($line.Contains('path=C:\Windows\Temp')) ('an ordinary path was rewritten: ' + $line)
        Assert-True ($line.Contains('reports=C:\reports\a.txt')) ('a path containing \r was rewritten: ' + $line)
    }
    finally { Close-LogProbe -Probe $probe }
}

Test-Case 'the documented key=value quoting still behaves exactly as it did' {
    # The escape runs BEFORE the space/quote rule, and must not disturb it.
    $probe = New-LogProbe
    try {
        Write-WacLog -Level INFO -Component 'EncQuote' -Message 'subject' `
            -Data @{ spaced = 'a b'; quoted = 'say "hi"'; plain = 'simple' }

        $line = @(Get-Content -LiteralPath $probe.Log | Where-Object { $_ -match '\[EncQuote\]' })[0]
        Assert-True ($line.Contains('spaced="a b"')) ('a spaced value lost its quoting: ' + $line)
        Assert-True ($line.Contains("quoted=""say 'hi'""")) ('an embedded quote is no longer folded: ' + $line)
        Assert-True ($line.Contains('plain=simple')) ('an unremarkable value was quoted: ' + $line)
    }
    finally { Close-LogProbe -Probe $probe }
}

Test-Case 'a tab and a bare control character cannot reach the file raw' {
    $probe = New-LogProbe
    try {
        $payload = 'a' + [char]9 + 'b' + [char]7 + 'c'
        Write-WacLog -Level INFO -Component 'EncCtl' -Message 'subject' -Data @{ path = $payload }

        $line = @(Get-Content -LiteralPath $probe.Log | Where-Object { $_ -match '\[EncCtl\]' })[0]
        Assert-True ($line.Contains('<TAB>')) ('the tab reached the file raw: ' + $line)
        Assert-True ($line.Contains('<0x07>')) ('a bare control character reached the file raw: ' + $line)
        Assert-False ($line.Contains([string][char]9)) 'a literal tab survived into the record'
        Assert-False ($line.Contains([string][char]7)) 'a literal BEL survived into the record'
    }
    finally { Close-LogProbe -Probe $probe }
}

Complete-TestRun
