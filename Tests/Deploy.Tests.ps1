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
