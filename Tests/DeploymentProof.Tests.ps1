#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.DeploymentProof: machine-trust VERIFICATION including
    the ancestor chains, and the deployment ownership proof (ledger P0-6 / U-2, R-22, B2-3).

.DESCRIPTION
    %ProgramFiles% is redirected into a disposable sandbox for every case that touches a deployment
    root and restored in a finally block, so nothing is written outside the directory the case
    created. Nothing here mutates an ACL: the removed ACL-hardening capability is proven absent by
    ShippedCodeBan.Tests.ps1, and the only Set-Acl in this suite is the fixture that MAKES a sandbox
    tree untrusted so the verification has something to find.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_DeployFixtures.ps1')

$script:WindowsPowerShell = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Grant-TestEveryoneWrite {
    <#
    .SYNOPSIS
        Adds an explicit Allow(Everyone, Modify) ACE so a sandbox tree is untrusted on ANY runner.
    .DESCRIPTION
        A sandbox under TEMP is user-writable on a developer machine, but on an ELEVATED runner its
        owner is BUILTIN\Administrators and its only writers are administrators, which
        Test-WacPathIsMachineTrusted correctly accepts. Proving "fails closed on a user-writable
        tree" therefore needs a genuinely non-administrative writer, and Everyone (S-1-1-0) is on
        the module's never-admin list. Only ever called on a path the test itself created.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')),
        [System.Security.AccessControl.FileSystemRights]::Modify,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-TestAncestor {
    <#
    .SYNOPSIS
        Every ancestor directory of a path, nearest parent first, up to the volume root in rooted
        form. Test-local on purpose.
    .DESCRIPTION
        The module used to export its own copy of this walk beside its own copy of the ancestor ACL
        rule. Both were duplicates of what Core already owns (Test-WacStatePathIsTrusted), so both
        were deleted (ledger B2-3). The EXPECTED path set still has to be computed independently of
        the function under test, or a CheckedCount assertion becomes a tautology - hence this, which
        walks names only and makes no trust decision at all.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $ancestors = New-Object 'System.Collections.Generic.List[string]'
    $current = Get-WacNormalizedPath -Path $Path
    if (-not $current) { return @($ancestors.ToArray()) }

    while ($true) {
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent)) { break }

        $normalized = Get-WacNormalizedPath -Path $parent
        if (-not $normalized -or $normalized -ieq $current) { break }

        if ($normalized -match '^[A-Za-z]:$') { [void]$ancestors.Add($normalized + '\') }
        else { [void]$ancestors.Add($normalized) }

        $current = $normalized
    }

    return @($ancestors.ToArray())
}

function Get-ExpectedCheckedCount {
    <#
    .SYNOPSIS
        How many DISTINCT paths Test-WacDeploymentTrusted must have inspected for one deployment
        root: the root, its deployed directories and modules, and both ancestor chains.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [AllowNull()][string]$TaskHost
    )

    $set = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    [void]$set.Add((Get-WacNormalizedPath -Path $Root))

    foreach ($item in @((Get-WacDeploymentItem -Root $Root).Entry)) {
        if ($item.IsReparsePoint) { continue }
        if ($item.IsDirectory -or ($item.Path -match '(?i)\.psm?1$')) { [void]$set.Add($item.Path) }
    }
    foreach ($ancestor in @(Get-TestAncestor -Path $Root)) { [void]$set.Add($ancestor) }

    if ($TaskHost) {
        [void]$set.Add((Get-WacNormalizedPath -Path $TaskHost))
        foreach ($ancestor in @(Get-TestAncestor -Path $TaskHost)) { [void]$set.Add($ancestor) }
    }

    return $set.Count
}

# ---------------------------------------------------------------------------------------------
# Machine-trust verification (ledger P0-6 / U-2). Verification only; nothing here mutates an ACL.
# ---------------------------------------------------------------------------------------------

Test-Case 'Test-WacDeploymentTrusted fails closed on a user-writable deployment' {
    Invoke-InDeploymentSandbox -Prefix 'dep-trust' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source
        Grant-TestEveryoneWrite -Path $deployment.DeploymentRoot

        $trust = Test-WacDeploymentTrusted -DeploymentRoot $deployment.DeploymentRoot

        Assert-False $trust.IsTrusted ('a world-writable deployment was reported trusted: ' + [string]$trust.Reason)
        Assert-True (@($trust.Untrusted).Count -gt 0) 'no untrusted path was reported'
        Assert-True ($trust.CheckedCount -gt 1) ('only {0} path was checked' -f $trust.CheckedCount)
        Assert-True ([bool]$trust.Reason) 'a failure must carry a reason'
        Assert-True ([bool](@($trust.Untrusted) | Where-Object { $_.Path -ieq $deployment.DeploymentRoot })) 'the root itself was not reported'
    }
}

Test-Case 'Test-WacDeploymentTrusted checks the deployed .ps1 and .psm1 files, not only directories' {
    Invoke-InDeploymentSandbox -Prefix 'dep-trustfiles' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source
        $module = Join-Path -Path $deployment.DeploymentRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1'
        foreach ($path in @($deployment.RunScript, $module, (Join-Path -Path $deployment.DeploymentRoot -ChildPath 'LICENSE'))) {
            Grant-TestEveryoneWrite -Path $path
        }

        $trust = Test-WacDeploymentTrusted -DeploymentRoot $deployment.DeploymentRoot
        $paths = @(@($trust.Untrusted) | ForEach-Object { $_.Path })

        Assert-True ($paths -contains $deployment.RunScript) 'Run.ps1 was never checked'
        Assert-True ($paths -contains $module) 'a deployed module was never checked'
        Assert-False ($paths -contains (Join-Path -Path $deployment.DeploymentRoot -ChildPath 'LICENSE')) 'a non-executable file was checked'
    }
}

Test-Case 'Test-WacDeploymentTrusted reports a missing root as untrusted' {
    Invoke-InDeploymentSandbox -Prefix 'dep-trustgone' -Body {
        param($sandbox)

        $trust = Test-WacDeploymentTrusted -DeploymentRoot (Join-Path -Path $sandbox -ChildPath 'does-not-exist')

        Assert-False $trust.IsTrusted
        Assert-Equal 0 $trust.CheckedCount
        Assert-True ([bool]$trust.Reason)
    }
}

Test-Case 'Test-WacDeploymentTrusted reports a reparse point inside the deployment' {
    Invoke-InDeploymentSandbox -Prefix 'dep-trustlink' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source
        $target = Join-Path -Path $sandbox -ChildPath 'elsewhere'
        [void][System.IO.Directory]::CreateDirectory($target)
        $link = Join-Path -Path $deployment.DeploymentRoot -ChildPath 'link'

        New-Item -ItemType Junction -Path $link -Target $target -ErrorAction Stop | Out-Null
        try {
            $trust = Test-WacDeploymentTrusted -DeploymentRoot $deployment.DeploymentRoot
            $reported = @(@($trust.Untrusted) | Where-Object { $_.Path -ieq $link })

            Assert-False $trust.IsTrusted
            Assert-Equal 1 $reported.Count 'the junction was not reported'
            Assert-True ($reported[0].Reason -match 'reparse point') ([string]$reported[0].Reason)
        }
        finally {
            try { [System.IO.Directory]::Delete($link, $false) } catch { $null = $_ }
        }
    }
}

Test-Case 'Test-WacDeploymentTrusted passes on a real machine-owned directory' {
    $candidates = @(
        (Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Host'),
        (Join-Path -Path $env:SystemRoot -ChildPath 'System32\drivers\etc')
    )

    $machineOwned = $null
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Container) { $machineOwned = $candidate; break }
    }

    Assert-True ([bool]$machineOwned) 'no machine-owned probe directory exists on this machine'

    # Read-only: the check never writes to, or re-permissions, the directory it inspects.
    $trust = Test-WacDeploymentTrusted -DeploymentRoot $machineOwned

    Assert-True $trust.IsTrusted ([string]$trust.Reason)
    Assert-Equal 0 @($trust.Untrusted).Count
    Assert-True ($trust.CheckedCount -ge 1)
}

# ---------------------------------------------------------------------------------------------
# Ancestor trust (ledger R-22): write access to a PARENT replaces everything inside it
# ---------------------------------------------------------------------------------------------

Test-Case 'The ancestor walk is Core''s, not a second copy living in Deploy' {
    # Ledger B2-3. Deploy carried its own Get-WacPathAncestor and its own ancestor ACL rule, which
    # were duplicates of the decision Core already owns. Two copies of a security rule is one copy
    # that gets fixed and one that does not, so the copies were deleted. This pins that: the module
    # must no longer export them, and the walk it does use has to be Core's.
    $exported = @((Get-Module WindowsAutoCleanup.Deploy).ExportedFunctions.Keys)
    foreach ($gone in @('Get-WacPathAncestor', 'Test-WacAncestorIsMachineTrusted', 'Test-WacAncestorDescriptorIsTrusted')) {
        Assert-False ($exported -contains $gone) ('{0} came back as a second copy of Core''s ancestor rule' -f $gone)
    }

    # Every file of the package, not just the entry point: the walk moved into
    # WindowsAutoCleanup.DeploymentProof.ps1 when the module was split by responsibility, and a
    # second copy of the rule could come back in any of them. The list is the module's dot-source
    # list, and a part added there without being added here is a part this scan never opens.
    $package = @('WindowsAutoCleanup.Deploy.psm1', 'WindowsAutoCleanup.DeploymentTree.ps1',
        'WindowsAutoCleanup.DeploymentProof.ps1', 'WindowsAutoCleanup.DeploymentJournal.ps1',
        'WindowsAutoCleanup.DeploymentRecovery.ps1', 'WindowsAutoCleanup.TaskMatch.ps1',
        'WindowsAutoCleanup.ScheduledTask.ps1', 'WindowsAutoCleanup.TaskRemoval.ps1')

    $module = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1'))
    foreach ($part in @($package | Where-Object { $_ -ne 'WindowsAutoCleanup.Deploy.psm1' })) {
        Assert-True ($module -match ([regex]::Escape($part))) ('{0} is scanned here but the module no longer loads it' -f $part)
    }
    Assert-Equal (@($package).Count - 1) @([regex]::Matches($module, "ChildPath 'WindowsAutoCleanup\.[A-Za-z]+\.ps1'")).Count `
        'the Deploy module dot-sources a part this scan never opens'
    $source = (@($package | ForEach-Object {
        [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath ('src\' + $_)))
    }) -join [Environment]::NewLine)
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
    $code = @(@($tokens) | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text })

    Assert-True ($code -contains 'Test-WacStatePathIsTrusted') 'Deploy no longer calls Core''s ancestor walk at all'
    Assert-Equal 0 @($code | Where-Object { $_ -eq 'GetAccessRules' }).Count `
        'Deploy is decoding access rules again instead of delegating the decision to Core'
}

Test-Case 'Test-WacDeploymentTrusted names a user-writable PARENT of the deployment root' {
    Invoke-InDeploymentSandbox -Prefix 'dep-parent' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source
        $parent = Get-WacNormalizedPath -Path (Split-Path -Parent $deployment.DeploymentRoot)

        # Everyone:Modify carries DELETE and DELETE_CHILD, which is precisely the grant that lets a
        # standard user rename the whole deployment aside and drop a different one in its place.
        # The ACE is not inheritable, so the deployment root's own descriptor is left alone and the
        # only new failure can come from the ancestor walk.
        Grant-TestEveryoneWrite -Path $parent

        $trust = Test-WacDeploymentTrusted -DeploymentRoot $deployment.DeploymentRoot
        $reported = @(@($trust.Untrusted) | ForEach-Object { $_.Path })
        $named = @($reported | Where-Object { $_ -ieq $parent })
        $expected = Get-ExpectedCheckedCount -Root $deployment.DeploymentRoot -TaskHost (Get-WacCanonicalPowerShellHost)

        Assert-False $trust.IsTrusted ('a deployment under a user-writable parent was trusted: ' + [string]$trust.Reason)
        Assert-Equal 1 $named.Count ('the parent {0} was never checked; reported: {1}' -f $parent, ($reported -join '; '))
        Assert-Equal $expected $trust.CheckedCount `
            ('the ancestor chains were not all walked: {0} checked, {1} expected' -f $trust.CheckedCount, $expected)
    }
}

Test-Case 'Test-WacDeploymentTrusted trusts the real machine chain up to the volume root' {
    $probe = Get-WacDeploymentRoot
    if (-not (Test-Path -LiteralPath $probe -PathType Container)) {
        $probe = Join-Path -Path $env:SystemRoot -ChildPath 'System32\drivers\etc'
    }
    Assert-True (Test-Path -LiteralPath $probe -PathType Container) ('no real machine-owned probe exists: ' + $probe)

    $taskHost = Get-WacCanonicalPowerShellHost
    Assert-True ([bool]$taskHost) 'no machine-trusted PowerShell host exists on this machine'

    # CheckedCount is asserted EXACTLY, not as a lower bound. A lower bound is already satisfied
    # by the deployed paths alone, so it stays green when the ancestor walk is removed and
    # therefore proves nothing. The expectation covers BOTH chains: the deployment root and the
    # PowerShell host the task will run.
    $ancestors = @()
    foreach ($chain in @($probe, $taskHost)) {
        foreach ($ancestor in @(Get-TestAncestor -Path $chain)) {
            if ($ancestors -notcontains $ancestor) { $ancestors += $ancestor }
        }
    }

    # Read-only: the check never writes to, or re-permissions, anything it inspects.
    $trust = Test-WacDeploymentTrusted -DeploymentRoot $probe
    $reported = @(@($trust.Untrusted) | ForEach-Object { $_.Path })

    Assert-True $trust.IsTrusted ([string]$trust.Reason + ' :: ' + ($reported -join '; '))
    Assert-Equal 0 $reported.Count ($reported -join '; ')
    Assert-True ($ancestors -contains 'C:\') ('the walk did not reach the volume root: ' + ($ancestors -join '; '))
    Assert-Equal (Get-ExpectedCheckedCount -Root $probe -TaskHost $taskHost) $trust.CheckedCount `
        ('the host and root ancestors were not all checked; ancestors: ' + ($ancestors -join '; '))
}

Test-Case 'Test-WacDeploymentTrusted keeps its findings when no canonical PowerShell host exists' {
    Invoke-InDeploymentSandbox -Prefix 'dep-nohost' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source
        $root = Get-WacNormalizedPath -Path $deployment.DeploymentRoot
        Grant-TestEveryoneWrite -Path $root

        $taskHost = Get-WacCanonicalPowerShellHost
        Assert-True ([bool]$taskHost) 'no machine-trusted PowerShell host exists on this machine'

        $expectedWithHost = Get-ExpectedCheckedCount -Root $root -TaskHost $taskHost
        $expectedWithoutHost = Get-ExpectedCheckedCount -Root $root -TaskHost $null

        # The comparison the early return used to lose. Both readings are taken against the same
        # tree, so the ONLY difference between them may be the host chain.
        $withHost = Test-WacDeploymentTrusted -DeploymentRoot $root

        # Get-WacCanonicalPowerShellHost reads %ProgramFiles% and %SystemRoot% and nothing else;
        # %ProgramFiles% already points into this sandbox, so an empty %SystemRoot% leaves it with
        # no candidate at all. Restored in the finally, because the whole suite shares this process.
        $savedSystemRoot = $env:SystemRoot
        try {
            $empty = Join-Path -Path $sandbox -ChildPath 'no-windows'
            [void][System.IO.Directory]::CreateDirectory($empty)
            $env:SystemRoot = $empty
            Assert-Equal $null (Get-WacCanonicalPowerShellHost) 'a host was still reachable, so this case proves nothing'
            $withoutHost = Test-WacDeploymentTrusted -DeploymentRoot $root
        }
        finally {
            $env:SystemRoot = $savedSystemRoot
        }

        $namedWith = @(@($withHost.Untrusted) | Where-Object { [string]$_.Path -ieq $root })
        $namedWithout = @(@($withoutHost.Untrusted) | Where-Object { [string]$_.Path -ieq $root })
        $hostFindings = @(@($withoutHost.Untrusted) | Where-Object { [string]$_.Reason -like '*No machine-trusted PowerShell host*' })

        Assert-Equal $false $withHost.IsTrusted ([string]$withHost.Reason)
        Assert-Equal $false $withoutHost.IsTrusted ([string]$withoutHost.Reason)

        # The user-writable deployment root is the finding the installer has to print. An early
        # return discards it and reports UntrustedCount=0, so the installer's loop over
        # $trust.Untrusted names nothing and the operator is told only that something is wrong.
        Assert-Equal 1 $namedWith.Count ('the writable root was not reported at all: ' + ($namedWith -join '; '))
        Assert-Equal 1 $namedWithout.Count 'the writable root was dropped once no host was available'
        Assert-Equal 1 $hostFindings.Count 'the missing host was not reported as a finding of its own'
        Assert-Equal '<PowerShell host>' ([string]$hostFindings[0].Path) 'the missing-host finding has no printable path'
        Assert-Equal 0 @(@($withHost.Untrusted) | Where-Object { [string]$_.Reason -like '*No machine-trusted PowerShell host*' }).Count `
            'a missing host was reported while a host was available'

        # Exact, not a lower bound: the deployed paths alone already satisfy '-ge', which is how an
        # ancestor walk can be removed and stay green. Losing the host chain must cost exactly the
        # ancestors that only the host contributed, and nothing else.
        Assert-True ($expectedWithHost -gt $expectedWithoutHost) 'the host chain contributes nothing, so this case proves nothing'
        Assert-Equal $expectedWithHost $withHost.CheckedCount 'the two chains were not both walked'
        Assert-Equal $expectedWithoutHost $withoutHost.CheckedCount `
            'CheckedCount stopped counting the paths that were actually checked'
        Assert-Equal (@($withHost.Untrusted).Count + 1) @($withoutHost.Untrusted).Count `
            'the findings collected before the host lookup did not survive it'
    }
}

# ---------------------------------------------------------------------------------------------
# Deployment ownership: a directory at the expected path is not evidence (ledger B2-3)
# ---------------------------------------------------------------------------------------------

function Block-TestDirectoryListing {
    <#
    .SYNOPSIS
        Denies THIS account the right to list a directory, so an enumeration really fails.
    .DESCRIPTION
        The owner of a directory keeps READ_CONTROL and WRITE_DAC implicitly, so the ACE can always
        be lifted again in a finally - but owner rights do NOT include listing, so the denial bites
        on an elevated runner too. Only ever called on a directory the test created.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        ([System.Security.Principal.WindowsIdentity]::GetCurrent().User),
        [System.Security.AccessControl.FileSystemRights]::ListDirectory,
        [System.Security.AccessControl.AccessControlType]::Deny)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Unblock-TestDirectoryListing {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $acl = Get-Acl -LiteralPath $Path
        [void]$acl.RemoveAccessRuleAll((New-Object System.Security.AccessControl.FileSystemAccessRule(
            ([System.Security.Principal.WindowsIdentity]::GetCurrent().User),
            [System.Security.AccessControl.FileSystemRights]::ListDirectory,
            [System.Security.AccessControl.AccessControlType]::Deny)))
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    catch {
        $null = $_
    }
}

Test-Case 'Test-WacDeploymentTrusted fails closed when part of the deployment cannot be walked' {
    # "We could not look" has to fail exactly like "we looked and a standard user can write there":
    # the paths the walk never reached are precisely the ones nothing has verified.
    Invoke-InDeploymentSandbox -Prefix 'dep-trustwalk' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source
        $closed = Join-Path -Path $deployment.DeploymentRoot -ChildPath 'src'

        Block-TestDirectoryListing -Path $closed
        try {
            $trust = Test-WacDeploymentTrusted -DeploymentRoot $deployment.DeploymentRoot

            Assert-False $trust.IsTrusted 'a deployment that could not be fully walked was called trusted'
            $reported = @(@($trust.Untrusted) | Where-Object { $_.Reason -match 'could not be fully enumerated' })
            Assert-True ($reported.Count -ge 1) ((@($trust.Untrusted) | ForEach-Object { [string]$_.Reason }) -join '; ')
            Assert-True ($reported[0].Path -ieq $closed) ([string]$reported[0].Path)
        }
        finally {
            Unblock-TestDirectoryListing -Path $closed
        }
    }
}

Test-Case 'Ownership refuses a deployment root it cannot enumerate instead of adopting it' {
    # The old top-level scan used -ErrorAction SilentlyContinue, and an unreadable directory
    # enumerates as EMPTY. Empty plus no readable manifest walked straight into the pre-manifest
    # adoption branch, so a deployment path nothing could read came back Unmanaged and IsOurs - safe
    # to replace, safe to delete.
    Invoke-InDeploymentSandbox -Prefix 'own-unreadable' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source

        Block-TestDirectoryListing -Path $deployment.DeploymentRoot
        try {
            $ownership = Get-WacDeploymentOwnership -DeploymentRoot $deployment.DeploymentRoot

            Assert-False $ownership.IsOurs 'an unreadable deployment path was proven to be ours'
            Assert-Equal 'Indeterminate' $ownership.Kind ([string]$ownership.Reason)
            Assert-True ([string]$ownership.Reason -match 'could not be enumerated') ([string]$ownership.Reason)
        }
        finally {
            Unblock-TestDirectoryListing -Path $deployment.DeploymentRoot
        }

        # Readable again, and the same tree is Managed and ours: the refusal was about the evidence,
        # and a benign steady state is not turned into a permanent security refusal.
        $again = Get-WacDeploymentOwnership -DeploymentRoot $deployment.DeploymentRoot
        Assert-Equal 'Managed' $again.Kind ([string]$again.Reason)
        Assert-True $again.IsOurs ([string]$again.Reason)
        Assert-False $again.Tampered ((@($again.Findings)) -join '; ')
    }
}

Test-Case 'A fresh deployment is Managed, and a SECOND identical run is still benign' {
    # The trap this case exists for: a previous wave shipped a check whose own leftovers made every
    # LATER run refuse. The steady state after an install is an installed deployment, so the proof
    # is run twice against the same persistent tree and both answers have to be benign.
    Invoke-InDeploymentSandbox -Prefix 'own-managed' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source

        $first = Get-WacDeploymentOwnership -DeploymentRoot $deployment.DeploymentRoot
        Assert-Equal 'Managed' $first.Kind ([string]$first.Reason)
        Assert-True $first.IsOurs ([string]$first.Reason)
        Assert-False $first.Tampered (((@($first.Findings)) -join '; '))
        Assert-Equal (Get-WacDeploymentVersion) ([string]$first.Version)

        # Same state, asked again. Nothing the first call did may change the answer.
        $second = Get-WacDeploymentOwnership -DeploymentRoot $deployment.DeploymentRoot
        Assert-Equal 'Managed' $second.Kind ([string]$second.Reason)
        Assert-True $second.IsOurs ([string]$second.Reason)
        Assert-False $second.Tampered 'the second reading of an untouched deployment reported tampering'

        # The task run 1 registered, exactly as the installer builds it. Run 2 has to recognise it
        # as ours; if it did not, the installer would refuse to replace it (exit 7) on every machine
        # that already has WindowsAutoCleanup installed - a benign steady state producing a security
        # refusal, which is the defect a previous wave shipped and an adversarial reviewer caught.
        $runOneTask = New-StubTask -TaskPath (Get-WacTaskFolder) -Description (Get-WacTaskDescription) `
            -Action @((New-StubAction -Execute $script:WindowsPowerShell `
                -Arguments (Get-WacTaskActionArgument -RunScript $deployment.RunScript) `
                -WorkingDirectory $deployment.DeploymentRoot))

        # And a reinstall over it - the real second run - still lands Managed rather than refusing.
        $again = Install-WacDeployment -SourceRoot $source
        $third = Get-WacDeploymentOwnership -DeploymentRoot $again.DeploymentRoot
        Assert-Equal 'Managed' $third.Kind ([string]$third.Reason)
        Assert-False $third.Tampered 'a reinstall left the deployment disagreeing with its own manifest'

        $recognised = Test-WacTaskIsOurs -Task $runOneTask -DeploymentRoot $again.DeploymentRoot
        Assert-True $recognised.IsOurs `
            ('run 2 did not recognise the task run 1 registered, so every installed machine would be refused: ' + [string]$recognised.Reason)
        Assert-False $recognised.IsLegacy
    }
}

Test-Case 'Ownership adopts a pre-manifest deployment instead of stranding every installed machine' {
    # A BENIGN, EXPECTED steady state - a machine that installed before manifests existed - must
    # never produce a security refusal. Refusing it would mean the upgrade could not replace the old
    # tree and the uninstaller could not remove it, forever.
    Invoke-InDeploymentSandbox -Prefix 'own-unmanaged' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source
        [System.IO.File]::Delete((Get-WacDeploymentManifestPath -DeploymentRoot $deployment.DeploymentRoot))

        $ownership = Get-WacDeploymentOwnership -DeploymentRoot $deployment.DeploymentRoot
        Assert-Equal 'Unmanaged' $ownership.Kind ([string]$ownership.Reason)
        Assert-True $ownership.IsOurs 'a pre-manifest deployment was refused, stranding every already-installed machine'

        # Twice, for the same reason as above.
        $second = Get-WacDeploymentOwnership -DeploymentRoot $deployment.DeploymentRoot
        Assert-Equal 'Unmanaged' $second.Kind ([string]$second.Reason)
        Assert-True $second.IsOurs ([string]$second.Reason)
    }
}

Test-Case 'Ownership refuses a same-name directory that is not ours' {
    Invoke-InDeploymentSandbox -Prefix 'own-foreign' -Body {
        param($sandbox)

        $null = $sandbox
        $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)

        # A directory sitting exactly where we deploy, belonging to something else entirely.
        [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $root -ChildPath 'bin'))
        [System.IO.File]::WriteAllText((Join-Path -Path $root -ChildPath 'bin\other.exe'), 'x')

        $foreign = Get-WacDeploymentOwnership -DeploymentRoot $root
        Assert-Equal 'Foreign' $foreign.Kind ([string]$foreign.Reason)
        Assert-False $foreign.IsOurs 'a directory holding somebody else''s files was claimed as ours'
        Assert-True (@($foreign.Findings) -contains 'bin') (((@($foreign.Findings)) -join '; '))
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $root -ChildPath 'bin\other.exe')) `
            'the ownership check is read-only and must not have touched anything'
    }
}

Test-Case 'Ownership refuses a manifest carrying somebody else''s project identity' {
    Invoke-InDeploymentSandbox -Prefix 'own-otherid' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source
        $manifestPath = Get-WacDeploymentManifestPath -DeploymentRoot $deployment.DeploymentRoot

        $text = [System.IO.File]::ReadAllText($manifestPath)
        Assert-True ($text.Contains((Get-WacDeploymentProjectId))) 'the manifest does not record the project id at all'
        [System.IO.File]::WriteAllText($manifestPath, $text.Replace((Get-WacDeploymentProjectId), 'SomeOtherProduct=1'))

        $ownership = Get-WacDeploymentOwnership -DeploymentRoot $deployment.DeploymentRoot
        Assert-Equal 'Foreign' $ownership.Kind ([string]$ownership.Reason)
        Assert-False $ownership.IsOurs ([string]$ownership.Reason)
        Assert-True ($ownership.Reason -match 'different project identity') ([string]$ownership.Reason)
    }
}

Test-Case 'Ownership refuses a reparse point standing in for the deployment root' {
    Invoke-InDeploymentSandbox -Prefix 'own-link' -Body {
        param($sandbox)

        $target = Join-Path -Path $sandbox -ChildPath 'somewhere-else'
        [void][System.IO.Directory]::CreateDirectory($target)
        $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)

        $made = $false
        try {
            [void](New-Item -ItemType Junction -Path $root -Target $target -ErrorAction Stop)
            $made = $true
        }
        catch { $made = $false }
        if (-not $made) { Set-TestSkipped -Reason 'this host cannot create a junction, so a redirected deployment root cannot be built' }

        $ownership = Get-WacDeploymentOwnership -DeploymentRoot $root
        Assert-Equal 'Foreign' $ownership.Kind ([string]$ownership.Reason)
        Assert-False $ownership.IsOurs 'deleting a reparse point at the deployment path would act on whatever it points at'
        Assert-True ($ownership.Reason -match 'reparse point') ([string]$ownership.Reason)
        Assert-True (Test-Path -LiteralPath $target -PathType Container) 'the junction target was touched'
    }
}

Test-Case 'Ownership reports a modified file without making the deployment unremovable' {
    # Tampering is EVIDENCE, not a refusal. Flipping ownership on a hash mismatch would mean one
    # edited file locks the tree in place forever: neither replaceable nor removable.
    Invoke-InDeploymentSandbox -Prefix 'own-tamper' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source
        [System.IO.File]::WriteAllText((Join-Path -Path $deployment.DeploymentRoot -ChildPath 'Run.ps1'), '# edited')

        $ownership = Get-WacDeploymentOwnership -DeploymentRoot $deployment.DeploymentRoot
        Assert-Equal 'Managed' $ownership.Kind ([string]$ownership.Reason)
        Assert-True $ownership.IsOurs 'an edited file made our own deployment impossible to replace or remove'
        Assert-True $ownership.Tampered 'a changed file was not reported at all'
        Assert-Equal 1 @($ownership.Findings).Count (((@($ownership.Findings)) -join '; '))
        Assert-True (((@($ownership.Findings)) -join '; ') -match 'Run\.ps1') (((@($ownership.Findings)) -join '; '))
    }
}

Test-Case 'Ownership treats an absent and an empty deployment path as safe to create' {
    Invoke-InDeploymentSandbox -Prefix 'own-absent' -Body {
        param($sandbox)

        $null = $sandbox
        $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)

        $absent = Get-WacDeploymentOwnership -DeploymentRoot $root
        Assert-Equal 'Absent' $absent.Kind ([string]$absent.Reason)
        Assert-True $absent.IsOurs ([string]$absent.Reason)
        Assert-False $absent.Exists

        [void][System.IO.Directory]::CreateDirectory($root)
        $empty = Get-WacDeploymentOwnership -DeploymentRoot $root
        Assert-Equal 'Unmanaged' $empty.Kind ([string]$empty.Reason)
        Assert-True $empty.IsOurs 'an empty directory at the deployment path blocked the install'
    }
}

Complete-TestRun
