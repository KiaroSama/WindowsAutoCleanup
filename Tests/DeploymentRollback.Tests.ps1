#Requires -Version 5.1
<#
.SYNOPSIS
    The deployment switch transaction and the ONE rollback that reads it, over REAL temporary
    deployment trees driven through the installer's own Undo-Installation (ledger B2-3).

.DESCRIPTION
    Deploy.Tests.ps1 covers the happy stage / switch / roll back lifecycle. This suite covers what
    happens when a move FAILS, which is where the double rollback lived: Switch-WacDeploymentStage
    moved the old root to .previous, its own catch moved it back when the second move failed, and
    the installer's outer Restore-WacDeploymentPrevious then saw no .previous, read that as "this
    was a first install", deleted the live root - the machine's ORIGINAL deployment - and reported
    a successful rollback.

    Nothing here stubs the switch or the restore. %ProgramFiles% is redirected into a disposable
    sandbox, real trees are built through New-WacDeploymentStage, the moves are made to fail the way
    the filesystem really fails them, and the assertions are the SHA-256 of the original's own
    sentinel file - a rollback that deleted it cannot pass by journalling the right call order.

    The scheduled-task side is stubbed, because the rollback's own contract is what is under test
    and registering a real SYSTEM task is not something a unit suite may do. _RollbackFixture.ps1
    builds that stub and the deployments each case starts from - read that file for the mechanism.
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

# Undo-Installation resolves Restore-WacDeploymentPrevious out of the module and its scheduler names
# out of the stubs the fixture defines in this scope, so it needs both to be loaded to run at all.
. (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.InstallerTask.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_RollbackFixture.ps1')

# ---------------------------------------------------------------------------------------------
# A failed swap must never cost the machine its original deployment
# ---------------------------------------------------------------------------------------------

Test-Case 'A swap whose FIRST move fails leaves the original in place, and the rollback keeps it there' {
    Reset-RollbackFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02-first-move' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        Assert-True $originalHash 'the fixture deployment could not be hashed'

        $slots = Get-WacDeploymentSlotPath
        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')

        # The first move's destination already exists, so Directory.Move refuses before anything is
        # renamed - the shape an earlier run interrupted between the two moves leaves behind.
        [void][System.IO.Directory]::CreateDirectory($slots.Previous)
        [System.IO.File]::WriteAllText((Join-Path -Path $slots.Previous -ChildPath 'stale.txt'), 'x')

        Assert-Throws { Switch-WacDeploymentStage -KeepPrevious } '' 'the first move was expected to fail'

        # Nothing moved, so there is nothing to undo. The old rollback deleted the deployment root
        # here, because it read "no .previous of my own" as "this was a first install".
        $ok = Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @()
        Assert-True $ok (($script:InstallerMessage -join ' / '))
        Assert-True (Test-Path -LiteralPath $live.RunScript -PathType Leaf) 'the rollback deleted a deployment this run never touched'
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'the original deployment changed'
        Assert-Equal '# original v1' ([System.IO.File]::ReadAllText($live.RunScript))
    }
}

Test-Case 'A swap whose SECOND move fails and is internally restored survives the outer rollback' {
    # This is the double rollback. Switch-WacDeploymentStage's own catch puts the original back, so
    # .previous is gone by the time Undo-Installation runs - and the tree standing at the deployment
    # root is the machine's ORIGINAL, not this run's replacement.
    Reset-RollbackFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02-second-move' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath
        $stage = New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2'

        # Renaming a directory one of whose files is open with FileShare.None is refused (measured
        # on both hosts), so the SECOND move fails after the first has already happened.
        $handle = [System.IO.File]::Open((Join-Path -Path $stage.StagingRoot -ChildPath 'Run.ps1'),
            [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            Assert-Throws { Switch-WacDeploymentStage -KeepPrevious } 'could not be swapped into place' `
                'the second move was expected to fail'
        }
        finally {
            $handle.Dispose()
        }

        # The state that used to be misread: the original is back at the root and .previous is gone.
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'the switch did not put the original back'
        Assert-Equal '# original v1' ([System.IO.File]::ReadAllText($live.RunScript))

        $transaction = Get-DeploymentTransaction
        Assert-True $transaction.OriginalRestored 'the switch did not record that it had already restored the original'
        Assert-False $transaction.ReplacementLive 'the switch recorded a replacement that never went live'

        $ok = Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @()
        Assert-True $ok (($script:InstallerMessage -join ' / '))
        Assert-True (Test-Path -LiteralPath $live.RunScript -PathType Leaf) 'the rollback deleted the original deployment'
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'the original deployment did not survive the rollback'

        $ownership = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root
        Assert-Equal 'Managed' $ownership.Kind ([string]$ownership.Reason)
        Assert-False $ownership.Tampered 'the surviving deployment no longer matches its own manifest'
    }
}

Test-Case 'A swap whose internal restore ALSO fails leaves the original recoverable, and the rollback recovers it' {
    Reset-RollbackFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02-restore-failed' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath
        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')

        # The first move succeeds and every later one fails, so the switch cannot put the original
        # back and leaves it in the recovery slot. A hashtable rather than a plain variable because
        # GetNewClosure captures values, not references.
        $state = @{ Moves = 0 }
        $original = Get-ModuleFunctionBody -Module $script:DeployModule -Name 'Move-WacDeploymentSlot'
        Set-ModuleFunctionBody -Module $script:DeployModule -Name 'Move-WacDeploymentSlot' -Body {
            param(
                [Parameter(Mandatory = $true)][string]$From,
                [Parameter(Mandatory = $true)][string]$To
            )

            $state.Moves++
            if ($state.Moves -eq 1) { return (& $original -From $From -To $To) }
            throw ('the slot move was refused (injected, move {0})' -f $state.Moves)
        }.GetNewClosure()

        try {
            Assert-Throws { Switch-WacDeploymentStage -KeepPrevious } 'could not be swapped into place' `
                'the second move was expected to fail'
        }
        finally {
            Set-ModuleFunctionBody -Module $script:DeployModule -Name 'Move-WacDeploymentSlot' -Body $original
        }

        Assert-Equal 3 $state.Moves 'the switch did not attempt to put the original back'
        Assert-False (Test-Path -LiteralPath $slots.Root) 'the deployment root is occupied by something the failed swap left'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $slots.Previous -ChildPath 'Run.ps1') -PathType Leaf) `
            'the original is not in the recovery slot'

        $transaction = Get-DeploymentTransaction
        Assert-True $transaction.OriginalMovedAside 'the transaction lost track of the original it moved aside'
        Assert-False $transaction.OriginalRestored 'the switch claimed a restore that failed'

        $ok = Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @()
        Assert-True $ok (($script:InstallerMessage -join ' / '))
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'the rollback did not put the original back'
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'the recovery slot was left behind'

        # And once more, because the installer may reach its catch again: a rollback that has
        # already succeeded must not delete what it just restored.
        $again = Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @()
        Assert-True $again (($script:InstallerMessage -join ' / '))
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'a repeated rollback destroyed the restored original'
    }
}

# ---------------------------------------------------------------------------------------------
# After the swap: verification, registration, and rolling back twice
# ---------------------------------------------------------------------------------------------

Test-Case 'A post-swap verification failure rolls the original back with its exact contents' {
    Reset-RollbackFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02-postswap' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        $switched = Switch-WacDeploymentStage -KeepPrevious
        Assert-True $switched.PreviousKept 'the previous tree was discarded, so nothing could be rolled back to'

        # The installer's own phase-4 gate: what went live must still match the manifest that was
        # staged. Replacing a file after the swap is exactly the condition it refuses on.
        [System.IO.File]::WriteAllText($switched.RunScript, '# something else wrote here')
        $liveOwnership = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root
        Assert-True $liveOwnership.Tampered 'the post-swap verification would not have failed'

        $ok = Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @()
        Assert-True $ok (($script:InstallerMessage -join ' / '))
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'the original was not restored byte for byte'
        Assert-Equal '# original v1' ([System.IO.File]::ReadAllText($live.RunScript))
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'the recovery slot was left behind'
    }
}

Test-Case 'Rolling back TWICE after a successful restore changes nothing' {
    # The old rollback was not idempotent: the second call saw no .previous, concluded there had
    # never been one, and deleted the tree the first call had just put back.
    Reset-RollbackFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02-twice' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)

        $first = Restore-WacDeploymentPrevious
        Assert-True $first.Restored ([string]$first.Reason)
        Assert-True $first.HadPrevious 'the rollback forgot that there had been a previous deployment'
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript)

        $second = Restore-WacDeploymentPrevious
        Assert-True $second.Restored ([string]$second.Reason)
        Assert-True (Test-Path -LiteralPath $live.RunScript -PathType Leaf) 'the second rollback deleted the restored deployment'
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'the second rollback changed the restored deployment'

        # And through the installer's own entry point, which is how it really arrives twice.
        $ok = Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @()
        Assert-True $ok (($script:InstallerMessage -join ' / '))
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'a third rollback destroyed the restored original'
    }
}

Test-Case 'Rollback refuses to delete a deployment root it cannot prove this run installed' {
    # Delete only a replacement PROVEN to belong to this transaction. A tree standing at the
    # deployment path carries the right name, the right layout and the right project id whoever
    # put it there; only the manifest this switch wrote identifies one particular build.
    Reset-RollbackFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02-not-ours' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        $switched = Switch-WacDeploymentStage -KeepPrevious
        $replacementHash = Get-WacDeploymentFileHash -Path (Get-WacDeploymentManifestPath -DeploymentRoot $slots.Root)

        # Another install of this same project completes at this path between the swap and the
        # rollback: same name, same layout, same project id, a different BUILD. Removing it would
        # destroy a deployment this run never installed.
        [System.IO.File]::WriteAllText($switched.RunScript, '# a different build')
        [void](New-WacDeploymentManifest -StagingRoot $slots.Root)
        Assert-True ($replacementHash -ne (Get-WacDeploymentFileHash -Path (Get-WacDeploymentManifestPath -DeploymentRoot $slots.Root))) `
            'the fixture did not actually change what stands at the deployment root'

        $restored = Restore-WacDeploymentPrevious
        Assert-False $restored.Restored 'the rollback deleted a tree it could not prove this run installed'
        Assert-True ([string]$restored.Reason -match 'not the tree this run switched into place') ([string]$restored.Reason)
        Assert-Equal '# a different build' ([System.IO.File]::ReadAllText((Join-Path -Path $slots.Root -ChildPath 'Run.ps1')))

        # Both trees are still there: nothing was destroyed to tidy up an ambiguous state.
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path (Join-Path -Path $slots.Previous -ChildPath 'Run.ps1')) `
            'the original in the recovery slot was changed'
    }
}

Test-Case 'A rollback whose restored tree stopped matching what was moved aside reports failure' {
    # Verify the restored deployment, not merely that a directory landed at the right path. A tree
    # that changed while it sat in the recovery slot is back where it belongs but is no longer what
    # this run moved aside, and calling that a clean rollback hides the only evidence there is.
    Reset-RollbackFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02-restored-identity' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $slots = Get-WacDeploymentSlotPath

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)

        # Something rewrites a file inside the recovery slot between the swap and the rollback.
        [System.IO.File]::WriteAllText((Join-Path -Path $slots.Previous -ChildPath 'Run.ps1'), '# not what was moved aside')

        $restored = Restore-WacDeploymentPrevious
        Assert-False $restored.Restored 'a tree that no longer matches what was moved aside was reported as restored'
        Assert-True ([string]$restored.Reason -match 'different files') ([string]$restored.Reason)

        # Refused BEFORE the delete (ledger WAC-02R). The check used to run after the promotion, so
        # the failure it reported had already thrown away the verified replacement and put the
        # rewritten tree at the path SYSTEM executes. Reported, not destroyed: the operator keeps
        # both trees AND keeps running the one this run proved.
        Assert-Equal '# replacement v2' ([System.IO.File]::ReadAllText($live.RunScript)) `
            'the refusal deleted the verified deployment to put back a tree it could not vouch for'
        Assert-Equal '# not what was moved aside' `
            ([System.IO.File]::ReadAllText((Join-Path -Path $slots.Previous -ChildPath 'Run.ps1'))) `
            'the refusal destroyed the rewritten tree it was reporting on'

        $ok = Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @()
        Assert-False $ok 'the installer was told the rollback succeeded'
        Assert-True ($script:InstallerMessage -join ' / ' -match 'could not restore the previous deployment') ($script:InstallerMessage -join ' / ')
    }
}

Test-Case 'A registration failure restores the tree AND the exact task definition that was captured' {
    Reset-RollbackFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02-register' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)

        # The upgrade removed the old registration in phase 3 and registered its own in phase 4;
        # the read-back then failed. Both have to be undone.
        $captured = New-CapturedDefinition -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
            -Arguments ('-NoProfile -Command "& ''{0}'' -Scheduled"' -f $live.RunScript) `
            -WorkingDirectory $slots.Root
        [void]$script:RegisteredTask.Add((New-StubScheduledTask -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
            -Arguments '-NoProfile -Command "the registration this run made"' -WorkingDirectory $slots.Root))

        $ok = Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @($captured)
        Assert-True $ok (($script:InstallerMessage -join ' / '))
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'the original deployment was not restored'

        Assert-Equal 1 $script:RegisteredTask.Count 'the captured task was not put back'
        $back = @($script:RegisteredTask.ToArray())[0]
        Assert-Equal ('-NoProfile -Command "& ''{0}'' -Scheduled"' -f $live.RunScript) ([string]@($back.Actions)[0].Arguments) `
            'the task that came back is not the one that was captured'
        Assert-Equal $slots.Root ([string]@($back.Actions)[0].WorkingDirectory)
        Assert-True ($script:InstallerMessage -join ' / ' -match 're-registered and verified') ($script:InstallerMessage -join ' / ')
    }
}

Test-Case 'A rollback whose restored task is not the one that was captured reports failure' {
    # Restore-CapturedTask used to accept any task registered at that path with that name. What the
    # machine lost was the ACTION, so a definition that came back different is not a restoration.
    Reset-RollbackFixture -Drift 'arguments'
    Invoke-InDeploymentSandbox -Prefix 'wac02-task-drift' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)

        $captured = New-CapturedDefinition -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
            -Arguments ('-NoProfile -Command "& ''{0}'' -Scheduled"' -f $live.RunScript) `
            -WorkingDirectory $slots.Root

        $ok = Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @($captured)
        Assert-False $ok 'a task that came back with a different action was reported as restored'
        Assert-True ($script:InstallerMessage -join ' / ' -match 'not the task that was captured') ($script:InstallerMessage -join ' / ')

        # The deployment half still succeeded and is reported separately: an unrestorable task is
        # not a reason to leave the machine on the half-installed tree.
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'the deployment rollback was abandoned too'
    }
}

Test-Case 'A task that came back under another user, at another hour, or disabled is not restored' {
    # The same refusal as above, for the parts of a task that are not its action (ledger WAC-02R).
    # Each of these is a machine that still does not have the registration it lost: the cleanup runs
    # as somebody else, or at a time nobody asked for, or never.
    foreach ($drift in @('user', 'schedule', 'enabled')) {
        Reset-RollbackFixture -Drift $drift
        Invoke-InDeploymentSandbox -Prefix ('wac02r-task-' + $drift) -Body {
            param($sandbox)

            $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
            $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
            $slots = Get-WacDeploymentSlotPath

            [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
            [void](Switch-WacDeploymentStage -KeepPrevious)

            $captured = New-CapturedDefinition -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
                -Arguments ('-NoProfile -Command "& ''{0}'' -Scheduled"' -f $live.RunScript) `
                -WorkingDirectory $slots.Root

            $ok = Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @($captured)
            Assert-False $ok 'a task that came back changed was reported as restored'
            Assert-True ($script:InstallerMessage -join ' / ' -match 'not the task that was captured') ($script:InstallerMessage -join ' / ')

            # And the deployment half is still reported separately and still succeeded.
            Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'the deployment rollback was abandoned too'
        }
    }
}

# ---------------------------------------------------------------------------------------------
# A first install, and a recovery slot an earlier run left behind
# ---------------------------------------------------------------------------------------------

Test-Case 'Rolling back a genuine FIRST installation removes the tree it installed and nothing else' {
    Reset-RollbackFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02-first-install' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        [void](New-FixtureStage -Sandbox $sandbox -Name 'v1' -RunContent '# first install')
        $switched = Switch-WacDeploymentStage -KeepPrevious
        Assert-False $switched.PreviousKept 'there was no previous deployment to keep'
        Assert-True (Test-Path -LiteralPath $switched.RunScript -PathType Leaf)

        $ok = Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @()
        Assert-True $ok (($script:InstallerMessage -join ' / '))
        Assert-False (Test-Path -LiteralPath $slots.Root) 'the half-installed deployment was left behind'
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'a recovery slot appeared out of a first install'

        # Twice, again: there is nothing to remove and nothing to report as unrestored.
        $again = Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @()
        Assert-True $again (($script:InstallerMessage -join ' / '))
        Assert-False (Test-Path -LiteralPath $slots.Root)
    }
}

Test-Case 'Staging preserves a recovery slot that is the only deployment left on the machine' {
    # An install interrupted between the two moves leaves .previous holding the only copy and the
    # deployment root empty. Clearing both slots to prepare another attempt destroyed it.
    Reset-RollbackFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02-orphan-previous' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        [System.IO.Directory]::Move($slots.Root, $slots.Previous)
        Assert-False (Test-Path -LiteralPath $slots.Root) 'the interrupted-install fixture did not take effect'

        $stage = New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2'
        Assert-True (Test-Path -LiteralPath $stage.StagingRoot -PathType Container)

        Assert-True (Test-Path -LiteralPath $live.RunScript -PathType Leaf) 'staging destroyed the only deployment left on the machine'
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'the recovered deployment is not the one that was orphaned'
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'the recovery slot was left behind after it was reconciled'

        # And the run continues normally from there: the recovered tree is the one moved aside.
        $switched = Switch-WacDeploymentStage -KeepPrevious
        Assert-True $switched.PreviousKept 'the recovered deployment was not treated as a previous tree'
        Assert-Equal '# replacement v2' ([System.IO.File]::ReadAllText($switched.RunScript))
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path (Join-Path -Path $slots.Previous -ChildPath 'Run.ps1'))
    }
}

Test-Case 'Staging refuses when a recovery slot survives beside a deployment root that is not ours' {
    Reset-RollbackFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02-ambiguous' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        # The original ends up in the recovery slot and something unrecognisable stands at the
        # deployment path. Clearing either one guesses which of them the operator still needs.
        [System.IO.Directory]::Move($slots.Root, $slots.Previous)
        [void][System.IO.Directory]::CreateDirectory($slots.Root)
        [System.IO.File]::WriteAllText((Join-Path -Path $slots.Root -ChildPath 'someone-elses-product.exe'), 'x')

        Assert-Throws { New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2' } `
            'cannot be proven ours' 'staging cleared an ambiguous recovery slot instead of refusing'

        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path (Join-Path -Path $slots.Previous -ChildPath 'Run.ps1')) `
            'the refused stage destroyed the original in the recovery slot'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $slots.Root -ChildPath 'someone-elses-product.exe') -PathType Leaf) `
            'the refused stage touched the directory at the deployment path'
    }
}

Complete-TestRun
