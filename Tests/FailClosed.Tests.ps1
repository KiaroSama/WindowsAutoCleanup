#Requires -Version 5.1
<#
.SYNOPSIS
    Pins the "an unverifiable safety condition fails CLOSED" invariant, and the log-file guarantees
    that make a run auditable (ledger P1-11, R-4, R-5).

.DESCRIPTION
    Two of these were flipped to fail OPEN by a reviewer with the whole suite still green, and one -
    the same-second log collision - had an assertion that passed even when the truncating FileMode
    was restored, because the case held BOTH writers open and FileShare, not CreateNew, was doing the
    work. Every case here is written so the corresponding revert turns it red.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.FileSystem.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

# ---------------------------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------------------------

Test-Case 'A path that cannot be opened does not resolve to itself' {
    $sandbox = New-TestSandbox -Prefix 'closed-resolve'
    try {
        $missing = Join-Path -Path $sandbox -ChildPath 'no\such\path\at\all.txt'

        # The handle cannot be opened, so the answer is "unverifiable", which must read as unsafe.
        Assert-False (Test-WacPathResolvesToItself -Path $missing) `
            'an unopenable path was reported as resolving to itself'
        Assert-False (Test-WacFinalPathMatches -NormalizedPath (Get-WacNormalizedPath -Path $missing))

        # Control: a real directory does resolve to itself, so the check is not simply always false.
        Assert-True (Test-WacPathResolvesToItself -Path $sandbox)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Unreadable attributes are treated as a reparse point' {
    # A path whose attributes cannot be read is unverifiable, and the traversal must refuse it rather
    # than assume it is an ordinary directory it may descend into.
    Assert-True (Test-WacIsReparsePoint -Path 'C:\this\path\does\not\exist\anywhere') `
        'an unreadable path was reported as a plain directory'

    $sandbox = New-TestSandbox -Prefix 'closed-attr'
    try {
        Assert-False (Test-WacIsReparsePoint -Path $sandbox) 'an ordinary directory was called a reparse point'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A cleanup target that cannot be verified is refused, not swept' {
    $sandbox = New-TestSandbox -Prefix 'closed-target'
    try {
        $missing = Join-Path -Path $sandbox -ChildPath 'gone'
        $result = Remove-WacTree -Category 'unverifiable' -Path $missing
        Assert-False $result.Attempted
        Assert-Equal 0 ([int]$result.FilesDeleted)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Machine trust fails closed on a path that cannot be read' {
    $missing = Join-Path -Path $env:TEMP -ChildPath ('wac-absent-' + [guid]::NewGuid().ToString('N'))
    $result = Test-WacPathIsMachineTrusted -Path $missing

    Assert-False $result.IsTrusted 'a non-existent path was reported as machine-trusted'
    Assert-True ([string]::IsNullOrWhiteSpace($result.Reason) -eq $false) 'no reason was given for the refusal'
}

Test-Case 'An inherit-only CREATOR OWNER entry does not make a Windows directory untrusted' {
    # System32 and %ProgramFiles% both carry an inherit-only CREATOR OWNER GENERIC_ALL ACE. It grants
    # nothing on the object itself - it is a template for children - so treating it as effective
    # would report every Windows directory as unsafe and the installer would never register a task.
    $system32 = Join-Path -Path $env:SystemRoot -ChildPath 'System32'
    $result = Test-WacPathIsMachineTrusted -Path $system32

    Assert-True $result.IsTrusted ('System32 was reported untrusted: {0}' -f $result.Reason)
    Assert-Equal 0 (@($result.UntrustedWriters).Count) `
        (('unexpected untrusted writers: ' + (@($result.UntrustedWriters) -join ', ')))
}

Test-Case 'A directory a non-administrative principal can write is never trusted' {
    $sandbox = New-TestSandbox -Prefix 'closed-trust'
    try {
        # A sandbox under TEMP is user-writable on a developer machine, but on an ELEVATED runner its
        # owner is BUILTIN\Administrators and its only writers are administrators, which the module
        # correctly accepts. Introducing Everyone makes the case mean the same thing on both.
        $acl = Get-Acl -LiteralPath $sandbox
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')),
            [System.Security.AccessControl.FileSystemRights]::Modify,
            [System.Security.AccessControl.AccessControlType]::Allow)))
        Set-Acl -LiteralPath $sandbox -AclObject $acl

        $result = Test-WacPathIsMachineTrusted -Path $sandbox
        Assert-False $result.IsTrusted 'a directory Everyone can modify was reported as machine-trusted'
        Assert-True (@($result.UntrustedWriters) -contains 'S-1-1-0') `
            (('Everyone was not named as an untrusted writer: ' + (@($result.UntrustedWriters) -join ', ')))
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The canonical PowerShell host resolves to a machine-trusted binary' {
    $host51 = Get-WacCanonicalPowerShellHost
    Assert-True ($null -ne $host51) 'no canonical host was found on a machine that has Windows PowerShell'
    Assert-True ([System.IO.File]::Exists($host51)) $host51

    # It must be a canonical machine location, never something resolved through PATH.
    $normalized = Get-WacNormalizedPath -Path $host51
    $expected = @(
        (Get-WacNormalizedPath -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'))
    )
    if ($env:ProgramFiles) {
        $expected += (Get-WacNormalizedPath -Path (Join-Path -Path $env:ProgramFiles -ChildPath 'PowerShell\7\pwsh.exe'))
    }
    Assert-True ($expected -contains $normalized) ('the host was {0}' -f $normalized)
    Assert-True (Test-WacPathIsMachineTrusted -Path $host51).IsTrusted 'the selected host is not machine-trusted'
}

# ---------------------------------------------------------------------------------------------
# Log files
# ---------------------------------------------------------------------------------------------

Test-Case 'A same-second collision never truncates the finished run log' {
    $sandbox = New-TestSandbox -Prefix 'closed-log'
    try {
        # The ordering is the whole point. An earlier version of this case held BOTH writers open, so
        # the second creation was blocked by FileShare rather than by CreateNew - and it kept passing
        # when the truncating FileMode::Create was restored. Create, DISPOSE, then create again: only
        # CreateNew survives that.
        $first = New-WacLogFile -BaseName 'Collide' -CandidateRoot @($sandbox)
        Assert-True ($null -ne $first) 'the first log file was not created'
        $first.Writer.WriteLine('FIRST RUN CONTENT')
        $first.Writer.Flush()
        $first.Writer.Dispose()

        $second = New-WacLogFile -BaseName 'Collide' -CandidateRoot @($sandbox)
        Assert-True ($null -ne $second) 'the second log file was not created'
        $second.Writer.WriteLine('SECOND RUN CONTENT')
        $second.Writer.Dispose()

        Assert-False ([string]::Equals($first.Path, $second.Path, [System.StringComparison]::OrdinalIgnoreCase)) `
            ('both runs wrote to the same file: {0}' -f $first.Path)

        $firstText = [System.IO.File]::ReadAllText($first.Path)
        Assert-True ($firstText.Contains('FIRST RUN CONTENT')) `
            'the first run''s log was truncated by the second run'
        Assert-True ([System.IO.File]::ReadAllText($second.Path).Contains('SECOND RUN CONTENT'))
        Assert-Equal 2 (@(Get-ChildItem -LiteralPath $sandbox -Filter 'Collide_*.log' -File).Count)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacOldLog keeps exactly the newest N and never the active log' {
    $sandbox = New-TestSandbox -Prefix 'closed-retain'
    try {
        $active = New-WacLogFile -BaseName 'Retain' -CandidateRoot @($sandbox)
        $active.Writer.WriteLine('active')
        $active.Writer.Dispose()

        # Stamp the decoys in the FUTURE so the active log sorts last and is a genuine deletion
        # candidate; otherwise the case would pass without the active-log guard existing at all.
        for ($i = 0; $i -lt 8; $i++) {
            $path = Join-Path -Path $sandbox -ChildPath ('Retain_decoy{0}.log' -f $i)
            [System.IO.File]::WriteAllText($path, 'decoy')
            [System.IO.File]::SetLastWriteTimeUtc($path, (Get-Date).ToUniversalTime().AddDays($i + 1))
        }

        $removed = Remove-WacOldLog -LogDirectory $sandbox -Pattern 'Retain_*.log' -KeepCount 3
        $left = @(Get-ChildItem -LiteralPath $sandbox -Filter 'Retain_*.log' -File)

        Assert-True ($removed -ge 1) 'nothing was pruned'
        Assert-Equal 3 $left.Count (('files left: ' + ((@($left | ForEach-Object { $_.Name })) -join ', ')))
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacOldLog is a no-op below the retention limit' {
    $sandbox = New-TestSandbox -Prefix 'closed-retain-noop'
    try {
        for ($i = 0; $i -lt 3; $i++) {
            [System.IO.File]::WriteAllText((Join-Path -Path $sandbox -ChildPath ('Few_{0}.log' -f $i)), 'x')
        }

        Assert-Equal 0 (Remove-WacOldLog -LogDirectory $sandbox -Pattern 'Few_*.log' -KeepCount 30)
        Assert-Equal 3 (@(Get-ChildItem -LiteralPath $sandbox -Filter 'Few_*.log' -File).Count)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
