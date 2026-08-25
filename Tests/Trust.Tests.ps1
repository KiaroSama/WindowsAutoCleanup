#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.Trust.ps1: the machine-trust check for executable
    code, the state-root ancestor walk, and the ancestor rule itself.

.DESCRIPTION
    These exercise the real functions against real security descriptors. Nothing here inspects
    source text, and nothing asserts on the test process's own privilege level: the hosted Windows
    runner is elevated and a developer shell usually is not, so an assertion on that would pass in
    exactly one of the two places it has to work.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

# ---------------------------------------------------------------------------------------------
# Machine trust
# ---------------------------------------------------------------------------------------------

Test-Case 'Test-WacPathIsMachineTrusted trusts the canonical Windows PowerShell host' {
    $canonical = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $trust = Test-WacPathIsMachineTrusted -Path $canonical
    Assert-True $trust.IsTrusted ('reason: ' + $trust.Reason + ' owner: ' + $trust.Owner)
    Assert-Equal 0 @($trust.UntrustedWriters).Count
}

Test-Case 'Test-WacPathIsMachineTrusted refuses a path a non-administrative group can write' {
    $sandbox = New-TestSandbox -Prefix 'trust'
    try {
        # Granting BUILTIN\Users write access to a directory this test created is what makes the
        # expectation deterministic: asserting on the sandbox's inherited ACL instead would depend
        # on whether the current account happens to be an administrator.
        $acl = Get-Acl -LiteralPath $sandbox
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')),
            [System.Security.AccessControl.FileSystemRights]::Modify,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $sandbox -AclObject $acl

        $trust = Test-WacPathIsMachineTrusted -Path $sandbox
        Assert-False $trust.IsTrusted 'a user-writable path must never be trusted for SYSTEM execution'
        # The REASON differs by who owns the sandbox (an elevated runner owns it as an administrator,
        # a developer shell does not), so only the verdict is asserted.
        Assert-True ([bool]$trust.Reason) 'a refusal must say why'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Test-WacPathIsMachineTrusted fails closed on a path that does not exist' {
    $trust = Test-WacPathIsMachineTrusted -Path 'C:\wac-does-not-exist-4f2a\host.exe'
    Assert-False $trust.IsTrusted
    Assert-True ($trust.Reason -match 'does not exist')
}

# ---------------------------------------------------------------------------------------------
# State-root trust (ledger B2-8)
# ---------------------------------------------------------------------------------------------

Test-Case 'Test-WacStatePathIsTrusted accepts a machine state root and reports who can still write' {
    $system32 = Join-Path -Path $env:SystemRoot -ChildPath 'System32'
    $trust = Test-WacStatePathIsTrusted -Path $system32

    Assert-True $trust.IsTrusted ('reason: ' + $trust.Reason)
    Assert-Equal 0 @($trust.Failures).Count
    Assert-Equal 0 @($trust.Writers).Count 'System32 must have no non-administrative writers'
    # System32 -> C:\Windows -> C:. The ancestors are the point: write access one level up is enough
    # to rename the whole directory aside.
    Assert-Equal 3 @($trust.Checked).Count ('checked: ' + (@($trust.Checked) -join ', '))
}

Test-Case 'Test-WacStatePathIsTrusted refuses a state root a non-administrative group can replace' {
    $sandbox = New-TestSandbox -Prefix 'statetrust'
    try {
        $acl = Get-Acl -LiteralPath $sandbox
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')),
            [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $sandbox -AclObject $acl

        $trust = Test-WacStatePathIsTrusted -Path $sandbox
        Assert-False $trust.IsTrusted 'a directory BUILTIN\Users can empty was accepted as a state root'
        Assert-True (@($trust.Failures).Count -ge 1) 'the refusal recorded no failure to explain itself'
        Assert-True ($trust.Reason -match 'S-1-5-32-545') ('reason: ' + $trust.Reason)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Test-WacStatePathIsTrusted refuses a reparse point in the chain' {
    $sandbox = New-TestSandbox -Prefix 'statelink'
    try {
        $real = Join-Path -Path $sandbox -ChildPath 'real'
        [void][System.IO.Directory]::CreateDirectory($real)
        $link = Join-Path -Path $sandbox -ChildPath 'link'

        # mklink /J needs no elevation, so this runs identically on a developer shell and on CI.
        $cmd = Join-Path -Path $env:SystemRoot -ChildPath 'System32\cmd.exe'
        [void](Invoke-WacProcess -FilePath $cmd -TimeoutMs 30000 `
                -ArgumentList @('/c', 'mklink', '/J', $link, $real))
        if (-not (Test-Path -LiteralPath $link)) { Set-TestSkipped -Reason 'this filesystem refused to create a junction' }

        $trust = Test-WacStatePathIsTrusted -Path $link
        Assert-False $trust.IsTrusted 'a junction was accepted as a state root'
        Assert-True ($trust.Reason -match 'reparse point') ('reason: ' + $trust.Reason)
    }
    finally {
        $link = Join-Path -Path $sandbox -ChildPath 'link'
        if (Test-Path -LiteralPath $link) { try { [System.IO.Directory]::Delete($link, $false) } catch { $null = $_ } }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Test-WacStatePathIsTrusted records a depth-limit refusal instead of passing quietly' {
    $trust = Test-WacStatePathIsTrusted -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -MaxDepth 1

    Assert-False $trust.IsTrusted 'a chain that was never walked to the root was reported trusted'
    Assert-Equal 1 @($trust.Failures).Count
    Assert-True ($trust.Reason -match 'depth limit') ('reason: ' + $trust.Reason)
}

Test-Case 'Test-WacStatePathIsTrusted judges a not-yet-created root by the directory it will live in' {
    $sandbox = New-TestSandbox -Prefix 'statenew'
    try {
        $future = Join-Path -Path $sandbox -ChildPath 'WindowsAutoCleanup\Logs'
        $trust = Test-WacStatePathIsTrusted -Path $future

        Assert-Equal (Get-WacNormalizedPath -Path $sandbox) $trust.Path `
            'the nearest existing ancestor was not the thing verified'
        Assert-True ($trust.Reason -match [regex]::Escape($sandbox)) ('reason: ' + $trust.Reason)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# The ancestor trust rule, over descriptors no on-disk fixture can produce
# ---------------------------------------------------------------------------------------------

function Invoke-AncestorAclVerdict {
    <#
    .SYNOPSIS
        Runs Core's PRIVATE Test-WacAncestorAclIsAdministrative over a descriptor built from SDDL.
    .DESCRIPTION
        Reached through the module's own scope rather than by adding it to Export-ModuleMember: a
        function is not made public to give a test somewhere to stand.

        SDDL rather than a real directory because two of the shapes below cannot be built on disk
        here at all - assigning an arbitrary owner needs SeRestorePrivilege, and emptying a DACL is
        a write this project refuses to make anywhere. The function reads a descriptor, never a
        path, so a descriptor is the whole of its input either way.
    #>
    param([Parameter(Mandatory = $true)][string]$Sddl)

    $descriptor = New-Object System.Security.AccessControl.DirectorySecurity
    $descriptor.SetSecurityDescriptorSddlForm($Sddl)
    return (& (Get-Module WindowsAutoCleanup.Core) { param($a) Test-WacAncestorAclIsAdministrative -Acl $a } $descriptor)
}

Test-Case 'The ancestor trust rule refuses every descriptor that cannot prove administrative control' {
    <#
        Five refusals and one acceptance. Two of the refusals - a non-administrative OWNER, and a
        descriptor carrying no access rules at all - had their only coverage in the duplicate of
        this function that used to live in Deploy; deleting the duplicate deleted the tests with it
        and left both branches unpinned, and these are the branches that decide whether the state
        root holding the audit log and the driver backups is accepted.
    #>

    # An owner keeps WRITE_DAC implicitly, so a non-administrative one can grant itself anything at
    # any moment and the DACL below it proves nothing.
    $owner = Invoke-AncestorAclVerdict -Sddl 'O:AUG:BAD:(A;;FA;;;BA)'
    Assert-False $owner.IsTrusted 'a directory owned by Authenticated Users was trusted on an administrative DACL'
    Assert-Equal 'S-1-5-11' ([string]$owner.Owner) 'the refusal did not report the owner it refused'
    Assert-True ($owner.Reason -match 'Owner') ('reason: ' + $owner.Reason)

    # No owner at all is not "no problem": nothing was proved about who controls the object.
    $ownerless = Invoke-AncestorAclVerdict -Sddl 'G:BAD:(A;;FA;;;BA)'
    Assert-False $ownerless.IsTrusted 'a descriptor carrying no owner was trusted'

    # An EMPTY DACL and a NULL DACL read alike from a distance and are opposites: the first grants
    # nobody anything, the second grants Everyone everything. Neither may be accepted blind, and the
    # second is why the rule cannot simply treat "no non-administrative writer found" as trust.
    $noRules = Invoke-AncestorAclVerdict -Sddl 'O:BAG:BAD:'
    Assert-False $noRules.IsTrusted 'a descriptor exposing no access rules was trusted'
    Assert-True ($noRules.Reason -match 'no access rules') ('reason: ' + $noRules.Reason)

    $nullDacl = Invoke-AncestorAclVerdict -Sddl 'O:BAG:BAD:NO_ACCESS_CONTROL'
    Assert-False $nullDacl.IsTrusted 'a NULL DACL, which materialises as Allow(Everyone, all), was trusted'
    Assert-True ($nullDacl.Reason -match 'S-1-1-0') ('reason: ' + $nullDacl.Reason)

    # DELETE | FILE_DELETE_CHILD is exactly the pair that lets a non-administrator replace an
    # existing child, which is the only question this function asks of an ancestor.
    $deleter = Invoke-AncestorAclVerdict -Sddl 'O:BAG:BAD:(A;;FA;;;BA)(A;;0x10040;;;AU)'
    Assert-False $deleter.IsTrusted 'a directory Authenticated Users can empty was trusted'
    Assert-True ($deleter.Reason -match 'S-1-5-11') ('reason: ' + $deleter.Reason)

    # The acceptance, and deliberately not the trivial one: a Deny ACE, the administrative Allows,
    # the harmless CreateDirectories grant the real C:\ hands Authenticated Users, and an
    # INHERIT-ONLY full-control ACE that grants nothing on the container itself. Without this the
    # rule could refuse everything and still satisfy every assertion above - and a rule that refuses
    # every volume root accepts no state root on any healthy Windows install.
    $ok = Invoke-AncestorAclVerdict -Sddl 'O:BAG:BAD:(D;;FA;;;AU)(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x4;;;AU)(A;OICIIO;FA;;;AU)'
    Assert-True $ok.IsTrusted ('an administrative-only ancestor was refused: ' + $ok.Reason)
    Assert-Equal 'S-1-5-32-544' ([string]$ok.Owner)
}

Complete-TestRun
