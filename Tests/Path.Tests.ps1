#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.Path.ps1: path canonicalisation and the bidirectional
    protected-root rule.

.DESCRIPTION
    These exercise the real functions against real files. Nothing here inspects source text, and
    nothing asserts on the test process's own privilege level: the hosted Windows runner is
    elevated and a developer shell usually is not, so an assertion on that would pass in exactly
    one of the two places it has to work.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

# ---------------------------------------------------------------------------------------------
# Path canonicalisation
# ---------------------------------------------------------------------------------------------

Test-Case 'Get-WacNormalizedPath normalises drive, case and trailing separator' {
    Assert-Equal 'C:' (Get-WacNormalizedPath -Path 'c:')
    Assert-Equal 'C:' (Get-WacNormalizedPath -Path 'C:\')
    Assert-Equal 'C:\Temp' (Get-WacNormalizedPath -Path 'C:\Temp\')
    Assert-Equal 'C:\Temp\sub' (Get-WacNormalizedPath -Path 'c:\Temp\sub')
    Assert-Equal 'C:\Temp' (Get-WacNormalizedPath -Path 'C:\Temp\sub\..')
}

Test-Case 'Get-WacNormalizedPath rejects drive-relative, UNC and empty forms' {
    Assert-Equal $null (Get-WacNormalizedPath -Path 'C:foo')
    Assert-Equal $null (Get-WacNormalizedPath -Path 'C:foo\bar')
    Assert-Equal $null (Get-WacNormalizedPath -Path '\\server\share\x')
    Assert-Equal $null (Get-WacNormalizedPath -Path '\\?\UNC\server\share')
    Assert-Equal $null (Get-WacNormalizedPath -Path '')
    Assert-Equal $null (Get-WacNormalizedPath -Path '   ')
    Assert-Equal $null (Get-WacNormalizedPath -Path $null)
}

Test-Case 'Get-WacNormalizedPath accepts the extended-length form and strips its prefix' {
    Assert-Equal 'C:\Temp\x' (Get-WacNormalizedPath -Path '\\?\C:\Temp\x')
    Assert-Equal 'C:' (Get-WacNormalizedPath -Path '\\?\C:\')
    Assert-Equal 'C:' (Get-WacNormalizedPath -Path '\\?\C:')
}

Test-Case 'Get-WacNormalizedPath expands 8.3 names so both sides of a comparison agree' {
    # A hosted runner has an 8.3 TEMP (C:\Users\RUNNER~1\...). Mixing an expanded and an unexpanded
    # spelling is invisible locally and breaks there, so the expansion must be part of the contract.
    Assert-Equal (Get-WacNormalizedPath -Path $env:ProgramFiles) (Get-WacNormalizedPath -Path 'C:\PROGRA~1')

    $sandbox = New-TestSandbox -Prefix 'norm'
    $once = Get-WacNormalizedPath -Path $sandbox
    Assert-Equal $once (Get-WacNormalizedPath -Path $once) 'normalisation must be idempotent'
    Assert-Equal $once (Get-WacNormalizedPath -Path ($sandbox + '\'))
    Remove-TestSandbox -Path $sandbox
}

Test-Case 'Test-WacIsOnTargetDrive accepts only the C: drive' {
    Assert-True (Test-WacIsOnTargetDrive -Path 'C:')
    Assert-True (Test-WacIsOnTargetDrive -Path 'c:\Windows\Temp')
    Assert-False (Test-WacIsOnTargetDrive -Path 'D:\payload')
    Assert-False (Test-WacIsOnTargetDrive -Path 'C:foo')
    Assert-False (Test-WacIsOnTargetDrive -Path '\\server\share')
    Assert-False (Test-WacIsOnTargetDrive -Path '')
}

# ---------------------------------------------------------------------------------------------
# Path protection (ledger P0-5)
# ---------------------------------------------------------------------------------------------

Test-Case 'Test-WacIsProtectedPath refuses the fixed system roots' {
    Clear-WacProtectedRoot
    foreach ($fixed in @('C:', 'C:\Windows', 'C:\Users', 'C:\ProgramData', 'C:\Windows\System32',
                         'C:\Windows\WinSxS', 'C:\Windows\System32\DriverStore', 'C:\$Recycle.Bin')) {
        Assert-True (Test-WacIsProtectedPath -Path $fixed) ('{0} must be protected' -f $fixed)
    }
    Assert-False (Test-WacIsProtectedPath -Path 'C:\Windows\Temp')
}

Test-Case 'Test-WacIsProtectedPath protects a registered root in BOTH directions' {
    Clear-WacProtectedRoot
    Add-WacProtectedRoot -Path 'C:\Temp\wacproj'

    Assert-True (Test-WacIsProtectedPath -Path 'C:\Temp\wacproj') 'the root itself'
    Assert-True (Test-WacIsProtectedPath -Path 'C:\Temp\wacproj\src\file.ps1') 'a path inside the root'
    Assert-True (Test-WacIsProtectedPath -Path 'C:\Temp') 'an ANCESTOR of the root'
    Assert-True (Test-WacIsProtectedPath -Path 'c:\temp\WACPROJ') 'comparison is case-insensitive'

    Assert-False (Test-WacIsProtectedPath -Path 'C:\Temp\wacprojx') 'a sibling sharing a name prefix'
    Assert-False (Test-WacIsProtectedPath -Path 'C:\Other\wacproj2')
    Clear-WacProtectedRoot
}

Test-Case 'Test-WacIsProtectedPath fails closed on an unusable path' {
    Clear-WacProtectedRoot
    Assert-True (Test-WacIsProtectedPath -Path 'C:relative')
    Assert-True (Test-WacIsProtectedPath -Path '\\server\share')
    Assert-True (Test-WacIsProtectedPath -Path '')
}

Test-Case 'Get-WacLongPath adds the extended-length prefix only above the threshold' {
    $short = 'C:\' + ('a' * 200)
    Assert-Equal $short (Get-WacLongPath -Path $short)

    $atThreshold = 'C:\' + ('a' * 237)
    Assert-Equal 240 $atThreshold.Length
    Assert-Equal ('\\?\' + $atThreshold) (Get-WacLongPath -Path $atThreshold)

    $justUnder = 'C:\' + ('a' * 236)
    Assert-Equal 239 $justUnder.Length
    Assert-Equal $justUnder (Get-WacLongPath -Path $justUnder)

    $already = '\\?\C:\' + ('a' * 300)
    Assert-Equal $already (Get-WacLongPath -Path $already)

    $relative = 'sub\' + ('a' * 300)
    Assert-Equal $relative (Get-WacLongPath -Path $relative)
}

Complete-TestRun
