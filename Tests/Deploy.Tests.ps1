#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for the WindowsAutoCleanup.Deploy entry point: what the deployment copy is
    allowed to carry, the deletion allow-list, the one machine-wide operation lock, and the
    stage / switch / roll back lifecycle (ledger P0-3, B2-3).

.DESCRIPTION
    %ProgramFiles% is redirected into a disposable sandbox for every case that touches a deployment
    root and restored in a finally block, so nothing is written outside the directory the case
    created. The ownership and machine-trust proofs those cases rest on are covered by
    DeploymentProof.Tests.ps1, and the scheduled-task proof by ScheduledTask.Tests.ps1.
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

$script:DeployModule = Get-Module -Name 'WindowsAutoCleanup.Deploy'

function Get-ModuleFunctionBody {
    <#
    .SYNOPSIS
        The scriptblock a name currently resolves to inside a module, so it can be put back
        exactly. Same seam Steps.Tests.ps1 and Drivers.Tests.ps1 already use.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return (& $Module { param($n) (Get-Item -Path ('function:' + $n)).ScriptBlock } $Name)
}

function Set-ModuleFunctionBody {
    <#
    .SYNOPSIS
        Replaces a name inside a module's own scope. Only the module sees the replacement.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    & $Module { param($n, $b) Set-Item -Path ('function:script:' + $n) -Value $b } $Name $Body
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

Test-Case 'New-WacDeploymentStage itself refuses and deletes a staged tree that stopped verifying' {
    Invoke-InDeploymentSandbox -Prefix 'stage-refused' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout') -RunContent '# live v1'
        $live = Install-WacDeployment -SourceRoot $source
        $liveHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        # The gate fires when the bytes on disk stop agreeing with the manifest just written FROM
        # them: a torn copy, a half-flushed write, another writer in the slot. Corrupting the
        # source cannot reproduce that, because the manifest is built from the staged copy and is
        # therefore self-consistent however broken the source was. So the tear is injected exactly
        # where a real one happens - between the manifest and the verification - and the rest of
        # New-WacDeploymentStage (slot clearing, copy, real manifest, ownership proof) runs for
        # real around it.
        $original = Get-ModuleFunctionBody -Module $script:DeployModule -Name 'New-WacDeploymentManifest'
        Set-ModuleFunctionBody -Module $script:DeployModule -Name 'New-WacDeploymentManifest' -Body {
            param([Parameter(Mandatory = $true)][string]$StagingRoot)

            $manifest = & $original -StagingRoot $StagingRoot
            [System.IO.File]::WriteAllText((Join-Path -Path $StagingRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1'), '# torn copy')
            return $manifest
        }.GetNewClosure()

        try {
            $second = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout2') -RunContent '# staged v2'
            Assert-Throws { New-WacDeploymentStage -SourceRoot $second } 'did not verify against its own manifest' `
                'a staged tree that no longer matches its own manifest was accepted'
        }
        finally {
            Set-ModuleFunctionBody -Module $script:DeployModule -Name 'New-WacDeploymentManifest' -Body $original
        }

        # Refusing is only half of it. A staging slot left behind is what the NEXT
        # Switch-WacDeploymentStage swaps into the deployment root: the very tree just rejected.
        Assert-False (Test-Path -LiteralPath $slots.Staging) 'the refused staging slot was left on disk'
        Assert-Equal '# live v1' ([System.IO.File]::ReadAllText($live.RunScript)) 'the refusal reached the live deployment'
        Assert-Equal $liveHash (Get-WacDeploymentFileHash -Path $live.RunScript)

        # And the refusal leaves no sticky state: staging a GOOD tree over the same persistent
        # deployment immediately afterwards still succeeds.
        $again = New-WacDeploymentStage -SourceRoot $source
        Assert-Equal 4 $again.FileCount
        $ownership = Get-WacDeploymentOwnership -DeploymentRoot $again.StagingRoot
        Assert-Equal 'Managed' $ownership.Kind ([string]$ownership.Reason)
        Assert-False $ownership.Tampered 'the recovery stage did not verify'
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

Complete-TestRun
