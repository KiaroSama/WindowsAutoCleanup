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

function New-TestDirectorySecurity {
    <#
    .SYNOPSIS
        A DirectorySecurity carrying exactly the SDDL given, with nothing on disk behind it.
    .DESCRIPTION
        The ancestor DECISION is reachable this way and no other. A directory whose owner is an
        arbitrary account cannot be created without SeRestorePrivilege, and one with an empty DACL
        cannot be created without a write this project refuses to make - so the owner and rule-less
        refusals had no fixture, and deleting either of them left the whole suite green. Get-Acl is
        not involved here, so the descriptor is exactly what the SDDL says and nothing else.
    #>
    param([Parameter(Mandatory = $true)][string]$Sddl)

    $descriptor = New-Object System.Security.AccessControl.DirectorySecurity
    $descriptor.SetSecurityDescriptorSddlForm($Sddl)
    return $descriptor
}

function New-StubAction {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Execute,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Arguments
    )

    return [PSCustomObject]@{ Execute = $Execute; Arguments = $Arguments }
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

        Assert-Equal 4 $deployment.FileCount 'Run.ps1, LICENSE and two src modules'
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

Test-Case 'Get-WacPathAncestor walks to the volume root and returns it in rooted form' {
    $ancestors = @(Get-WacPathAncestor -Path 'C:\Program Files\WindowsAutoCleanup\Run.ps1')

    Assert-Equal 3 $ancestors.Count ($ancestors -join '; ')
    Assert-Equal 'C:\Program Files\WindowsAutoCleanup' $ancestors[0]
    Assert-Equal 'C:\Program Files' $ancestors[1]
    Assert-Equal 'C:\' $ancestors[2] 'the walk must reach the volume root, in rooted form'

    Assert-Equal 0 @(Get-WacPathAncestor -Path 'C:\').Count 'the volume root has no ancestor'
    Assert-Equal 0 @(Get-WacPathAncestor -Path '').Count
    Assert-Equal 0 @(Get-WacPathAncestor -Path '\\server\share\x').Count 'a UNC path is not a supported local path'
}

Test-Case 'Test-WacAncestorIsMachineTrusted accepts every legitimate Windows ancestor' {
    # The default DACL of C:\ grants Authenticated Users CreateDirectories on the folder ITSELF, so
    # an ancestor check that asked the strict "can anyone write here at all" question would report
    # the volume root of a healthy machine as untrusted and refuse every correct install.
    $taskHost = Get-WacCanonicalPowerShellHost
    Assert-True ([bool]$taskHost) 'no machine-trusted PowerShell host exists on this machine'

    $paths = @(
        'C:\',
        $env:ProgramFiles,
        (Join-Path -Path $env:SystemRoot -ChildPath 'System32'),
        (Split-Path -Parent $taskHost)
    )

    foreach ($path in $paths) {
        $trust = Test-WacAncestorIsMachineTrusted -Path $path
        Assert-True $trust.IsTrusted ('{0}: {1}' -f $path, [string]$trust.Reason)
    }
}

Test-Case 'Test-WacAncestorIsMachineTrusted reads the volume root, not the session location on that drive' {
    # Measured on pwsh 7.6.5: Get-Acl -LiteralPath 'C:' returns the descriptor of whichever
    # directory the session sits in on drive C, so the root has to be re-rooted before it is read.
    # An installer is normally launched from somewhere on C:, which is exactly when this bites.
    $sandbox = New-TestSandbox -Prefix 'dep-driverel'
    Grant-TestEveryoneWrite -Path $sandbox

    $qualifier = Split-Path -Qualifier $sandbox
    Assert-False (Test-WacAncestorIsMachineTrusted -Path $sandbox).IsTrusted `
        'the probe directory must be distinguishable from the volume root'

    $outside = Test-WacAncestorIsMachineTrusted -Path $qualifier

    $saved = (Get-Location).Path
    try {
        Set-Location -LiteralPath $sandbox
        $inside = Test-WacAncestorIsMachineTrusted -Path $qualifier
    }
    finally {
        Set-Location -LiteralPath ($qualifier + '\')
        Set-Location -LiteralPath $saved
    }

    # Both sides are asserted TRUE, not merely equal: with the re-rooting removed both readings
    # degrade to a user-writable directory and an equality-only assertion stays green.
    Assert-True $outside.IsTrusted ('the volume root itself must be trusted for this case to mean anything: ' + [string]$outside.Reason)
    Assert-True $inside.IsTrusted ('the session location on the drive was inspected instead of the volume root: ' + [string]$inside.Reason)
    Assert-Equal ([string]$outside.Owner) ([string]$inside.Owner) 'a different object was inspected'
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
        $expected = 1 + @(Get-WacPathAncestor -Path $deployment.DeploymentRoot).Count

        Assert-False $trust.IsTrusted ('a deployment under a user-writable parent was trusted: ' + [string]$trust.Reason)
        Assert-Equal 1 $named.Count ('the parent {0} was never checked; reported: {1}' -f $parent, ($reported -join '; '))
        Assert-True ($trust.CheckedCount -ge $expected) `
            ('ancestors were not counted: {0} checked, {1} expected at minimum' -f $trust.CheckedCount, $expected)
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
        foreach ($ancestor in @(Get-WacPathAncestor -Path $chain)) {
            if ($ancestors -notcontains $ancestor) { $ancestors += $ancestor }
        }
    }

    $strict = @(@(Get-WacDeploymentItem -Root $probe) | Where-Object {
        (-not $_.IsReparsePoint) -and ($_.IsDirectory -or ($_.Path -match '(?i)\.psm?1$'))
    })

    # Read-only: the check never writes to, or re-permissions, anything it inspects.
    $trust = Test-WacDeploymentTrusted -DeploymentRoot $probe
    $reported = @(@($trust.Untrusted) | ForEach-Object { $_.Path })

    Assert-True $trust.IsTrusted ([string]$trust.Reason + ' :: ' + ($reported -join '; '))
    Assert-Equal 0 $reported.Count ($reported -join '; ')
    Assert-True ($ancestors -contains 'C:\') ('the walk did not reach the volume root: ' + ($ancestors -join '; '))
    Assert-Equal (1 + $strict.Count + $ancestors.Count) $trust.CheckedCount `
        ('the host and root ancestors were not all checked; ancestors: ' + ($ancestors -join '; '))
}

Test-Case 'Test-WacAncestorDescriptorIsTrusted refuses every descriptor no fixture can produce' {
    # These two refusals were unreachable while the decision was welded to Get-Acl. Assigning an
    # arbitrary owner to a directory needs SeRestorePrivilege, which this session does not hold,
    # and emptying a DACL is a write this project refuses to make - so every sandbox on this
    # machine is owned by an administrative account and carries rules, and deleting either guard
    # left the whole suite green. Feeding the decision a descriptor directly reaches both.
    $cases = @(
        @{ Sddl = 'O:AUG:BAD:(A;;FA;;;BA)'
           Owner = 'S-1-5-11'
           Reason = 'Owner S-1-5-11 is not an administrative principal'
           Why = 'a non-administrative owner keeps WRITE_DAC and can grant itself anything' },
        @{ Sddl = 'G:BAD:(A;;FA;;;BA)'
           Owner = ''
           Reason = 'is not an administrative principal'
           Why = 'an ownerless descriptor names nobody to hold accountable' },
        @{ Sddl = 'O:BAG:BAD:'
           Owner = 'S-1-5-32-544'
           Reason = 'exposes no access rules to evaluate'
           Why = 'an empty rule set is nothing to evaluate, not proof that nobody can write' },
        @{ Sddl = 'O:BAG:BAD:NO_ACCESS_CONTROL'
           Owner = 'S-1-5-32-544'
           Reason = 'can replace a child of this directory: S-1-1-0'
           Why = 'a NULL DACL arrives as one Allow(Everyone, every right) ACE' },
        @{ Sddl = 'O:BAG:BAD:(A;;FA;;;BA)(A;;0x10040;;;AU)'
           Owner = 'S-1-5-32-544'
           Reason = 'can replace a child of this directory: S-1-5-11'
           Why = 'DELETE|FILE_DELETE_CHILD for a non-administrator replaces the deployment' }
    )

    foreach ($case in $cases) {
        $decision = Test-WacAncestorDescriptorIsTrusted -SecurityDescriptor (New-TestDirectorySecurity -Sddl $case.Sddl)

        Assert-Equal $false $decision.IsTrusted ('[{0}] was trusted: {1}' -f $case.Sddl, $case.Why)
        Assert-Equal $case.Owner ([string]$decision.Owner) $case.Sddl
        Assert-True ([string]$decision.Reason -like ('*{0}*' -f $case.Reason)) `
            ('[{0}] refused for the wrong reason: {1}' -f $case.Sddl, [string]$decision.Reason)
    }
}

Test-Case 'Test-WacAncestorDescriptorIsTrusted still accepts what a healthy ancestor carries' {
    # Every clause the refusals above must not have broken, in one descriptor: a Deny ACE, the
    # administrative Allow ACEs, the harmless CreateDirectories grant the real C:\ hands
    # Authenticated Users, and an INHERIT-ONLY full-control ACE that grants nothing on the
    # container itself. Asking the strict "can anyone write here at all" question would refuse it.
    $healthy = 'O:BAG:BAD:(D;;FA;;;AU)(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x4;;;AU)(A;OICIIO;FA;;;AU)'
    $decision = Test-WacAncestorDescriptorIsTrusted -SecurityDescriptor (New-TestDirectorySecurity -Sddl $healthy)

    Assert-Equal $true $decision.IsTrusted ([string]$decision.Reason)
    Assert-Equal 'S-1-5-32-544' ([string]$decision.Owner)

    # And the path reader still agrees with the decision it delegates to.
    $volumeRoot = Test-WacAncestorIsMachineTrusted -Path 'C:\'
    $direct = Test-WacAncestorDescriptorIsTrusted -SecurityDescriptor (Get-Acl -LiteralPath 'C:\')
    Assert-Equal $direct.IsTrusted $volumeRoot.IsTrusted ('the reader and the decision disagree about C:\ : ' + [string]$volumeRoot.Reason)
    Assert-Equal ([string]$direct.Owner) ([string]$volumeRoot.Owner)
    Assert-Equal ([string]$direct.Reason) ([string]$volumeRoot.Reason)
}

Test-Case 'Test-WacDeploymentTrusted keeps its findings when no canonical PowerShell host exists' {
    Invoke-InDeploymentSandbox -Prefix 'dep-nohost' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source
        $root = Get-WacNormalizedPath -Path $deployment.DeploymentRoot
        Grant-TestEveryoneWrite -Path $root

        $strict = @(@(Get-WacDeploymentItem -Root $root) | Where-Object {
            (-not $_.IsReparsePoint) -and ($_.IsDirectory -or ($_.Path -match '(?i)\.psm?1$'))
        })
        $rootAncestors = @(Get-WacPathAncestor -Path $root)

        $taskHost = Get-WacCanonicalPowerShellHost
        Assert-True ([bool]$taskHost) 'no machine-trusted PowerShell host exists on this machine'
        $bothChains = @($rootAncestors)
        foreach ($ancestor in @(Get-WacPathAncestor -Path $taskHost)) {
            if ($bothChains -notcontains $ancestor) { $bothChains += $ancestor }
        }

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
        Assert-Equal (1 + $strict.Count + $bothChains.Count) $withHost.CheckedCount 'the two chains were not both walked'
        Assert-Equal (1 + $strict.Count + $rootAncestors.Count) $withoutHost.CheckedCount `
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

Test-Case 'Test-WacTaskIsOurs accepts the sentinel plus a script inside the deployment root' {
    Invoke-InDeploymentSandbox -Prefix 'task-ours' -Body {
        param($sandbox)

        $null = $sandbox
        $root = Get-WacDeploymentRoot
        $arguments = '-NoProfile -File "{0}" -Scheduled -ResetWindowsUpdateBase:$true' -f (Join-Path -Path $root -ChildPath 'Run.ps1')
        $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description ('anything ' + (Get-WacTaskSentinel)) `
            -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $arguments))

        $proof = Test-WacTaskIsOurs -Task $task

        Assert-True $proof.IsOurs ([string]$proof.Reason)
        Assert-False $proof.IsLegacy
        Assert-Equal 'WindowsAutoCleanup' $proof.TaskName
        Assert-Equal (Get-WacTaskFolder) $proof.TaskPath
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

Test-Case 'Test-WacTaskIsOurs rejects a sentinel task whose -File is outside the deployment root' {
    Invoke-InDeploymentSandbox -Prefix 'task-outside' -Body {
        param($sandbox)

        $foreign = Join-Path -Path $sandbox -ChildPath 'elsewhere\Run.ps1'
        $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description ('x ' + (Get-WacTaskSentinel)) `
            -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments ('-File "{0}" -Scheduled' -f $foreign)))

        $proof = Test-WacTaskIsOurs -Task $task

        Assert-False $proof.IsOurs
        Assert-True ($proof.Reason -match 'outside the deployment root') ([string]$proof.Reason)
    }
}

Test-Case 'Test-WacTaskIsOurs rejects a sentinel task with no -File argument at all' {
    Invoke-InDeploymentSandbox -Prefix 'task-nofile' -Body {
        param($sandbox)

        $null = $sandbox
        $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description ('x ' + (Get-WacTaskSentinel)) `
            -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments '-NoProfile -Command Get-Date'))

        $proof = Test-WacTaskIsOurs -Task $task

        Assert-False $proof.IsOurs
        Assert-True ($proof.Reason -match 'no -File argument') ([string]$proof.Reason)
    }
}

Test-Case 'Test-WacTaskIsOurs rejects a PATH-resolved executable' {
    Invoke-InDeploymentSandbox -Prefix 'task-path' -Body {
        param($sandbox)

        $null = $sandbox
        $arguments = '-NoProfile -File "{0}" -Scheduled' -f (Join-Path -Path (Get-WacDeploymentRoot) -ChildPath 'Run.ps1')
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
        $arguments = '-NoProfile -File "{0}" -Scheduled' -f (Join-Path -Path (Get-WacDeploymentRoot) -ChildPath 'Run.ps1')
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

Test-Case 'Test-WacTaskIsOurs refuses the pre-1.2 task unless legacy migration is requested' {
    Invoke-InDeploymentSandbox -Prefix 'task-legacy' -Body {
        param($sandbox)

        $null = $sandbox
        $description = 'Runs WindowsAutoCleanup daily to silently remove explicitly allowed temporary files and cache locations from drive C:.'
        $task = New-StubTask -TaskPath '\' -Description $description `
            -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments '-NoProfile -File "C:\Users\me\WindowsAutoCleanup\Run.ps1" -Scheduled -ResetWindowsUpdateBase:$true'))

        $refused = Test-WacTaskIsOurs -Task $task
        Assert-False $refused.IsOurs 'the legacy task was adopted without -AllowLegacyMigration'

        $adopted = Test-WacTaskIsOurs -Task $task -AllowLegacyMigration
        Assert-True $adopted.IsOurs ([string]$adopted.Reason)
        Assert-True $adopted.IsLegacy 'an adopted pre-1.2 task must be flagged legacy'
    }
}

Test-Case 'Test-WacTaskIsOurs refuses every near-miss legacy task' {
    Invoke-InDeploymentSandbox -Prefix 'task-legacy-miss' -Body {
        param($sandbox)

        $null = $sandbox
        $description = 'Runs WindowsAutoCleanup daily to silently remove explicitly allowed temporary files and cache locations from drive C:.'
        $good = '-NoProfile -File "C:\Users\me\WindowsAutoCleanup\Run.ps1" -Scheduled'

        $cases = @(
            @{ Name = 'no -Scheduled'; TaskPath = '\'; Description = $description; Arguments = '-NoProfile -File "C:\Users\me\WindowsAutoCleanup\Run.ps1"'; Pattern = '-Scheduled' },
            @{ Name = 'foreign description'; TaskPath = '\'; Description = 'Unrelated cleanup task'; Arguments = $good; Pattern = 'pre-1\.2 WindowsAutoCleanup description' },
            @{ Name = 'not at the root task path'; TaskPath = (Get-WacTaskFolder); Description = $description; Arguments = $good; Pattern = 'root task path' },
            @{ Name = 'not a Run.ps1'; TaskPath = '\'; Description = $description; Arguments = '-NoProfile -File "C:\Users\me\WindowsAutoCleanup\Other.ps1" -Scheduled'; Pattern = 'Run\.ps1' },
            @{ Name = 'no -File'; TaskPath = '\'; Description = $description; Arguments = '-NoProfile -Command Get-Date'; Pattern = 'Run\.ps1' }
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
    $arguments = '-NoProfile -File "C:\Custom\Deployment\Run.ps1" -Scheduled'
    $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description ('x ' + (Get-WacTaskSentinel)) `
        -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $arguments))

    $matched = Test-WacTaskIsOurs -Task $task -DeploymentRoot 'C:\Custom\Deployment'
    Assert-True $matched.IsOurs ([string]$matched.Reason)

    $mismatched = Test-WacTaskIsOurs -Task $task -DeploymentRoot 'C:\Custom\Other'
    Assert-False $mismatched.IsOurs 'the supplied deployment root was ignored'
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
