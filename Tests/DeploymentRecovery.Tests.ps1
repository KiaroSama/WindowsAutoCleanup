#Requires -Version 5.1
<#
.SYNOPSIS
    What the deployment slots are allowed to throw away, and what a swap interrupted by the death of
    its own process leaves for the next run to reconcile (ledger WAC-02R).

.DESCRIPTION
    DeploymentRollback.Tests.ps1 covers a rollback inside ONE process, driven by the transaction
    that process recorded in memory. This suite covers the two things that record cannot answer:

      * whether the tree standing at the deployment root is a HEALTHY, COMMITTED replacement, or
        merely "ours" - an empty directory and a managed tree whose files no longer match its
        manifest are both ours, and treating either as a replacement is what deleted the only good
        copy the machine had left;
      * what happens when the process that started the swap is gone. A $script: flag dies with it,
        so the only evidence left is the directories and the durable record written beside them.

    Nothing is stubbed. %ProgramFiles% is redirected into a disposable sandbox, real trees are built
    through New-WacDeploymentStage, process death is simulated by discarding the module's in-memory
    transaction while leaving the disk exactly as the dead process left it, and every assertion is
    the SHA-256 of a file that was in the original - a recovery that deleted it cannot pass by
    reporting the right words.
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

function Reset-RecoveryFixture {
    & $script:DeployModule { $script:DeploymentTransaction = $null }
}

function Stop-FixtureProcess {
    <#
    .SYNOPSIS
        Simulates the death of the process that started a swap: the in-memory transaction goes, the
        disk stays exactly as it was.
    .DESCRIPTION
        This is the whole point of the durable record. A later run gets no $script: state from the
        run before it, so everything it does has to come from what is on disk - and that is what
        this fixture leaves behind.
    #>
    & $script:DeployModule { $script:DeploymentTransaction = $null }
}

function Install-FixtureDeployment {
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RunContent
    )

    return (Install-WacDeployment -SourceRoot (New-TestCheckout -Path (Join-Path -Path $Sandbox -ChildPath $Name) -RunContent $RunContent))
}

function New-FixtureStage {
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RunContent
    )

    # BOTH halves, in the installer's order (ledger WAC-02R). Reconciling the recovery slot was
    # New-WacDeploymentStage's own first act until that put the file half behind the new install's
    # source validation; the caller performs it now, and this fixture stands in for that caller.
    [void](Resolve-WacDeploymentRecoverySlot -Slots (Get-WacDeploymentSlotPath))
    return (New-WacDeploymentStage -SourceRoot (New-TestCheckout -Path (Join-Path -Path $Sandbox -ChildPath $Name) -RunContent $RunContent))
}

function Get-SlotRunContent {
    <#
    .SYNOPSIS
        The text of a slot's Run.ps1, or $null when there is none. What actually survived, rather
        than whether a directory exists.
    #>
    param([Parameter(Mandatory = $true)][string]$Slot)

    $path = Join-Path -Path $Slot -ChildPath 'Run.ps1'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    return ([System.IO.File]::ReadAllText($path))
}

function Test-WacRecoverySlotIsPromotableProbe {
    <#
    .SYNOPSIS
        The module's own promotion gate, reached through its scope rather than by adding it to the
        export list.
    .DESCRIPTION
        A case that asserts a slot was refused for one reason has to show it passed the OTHER checks
        first, or the refusal it observed could be coming from anywhere.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    return [bool](& $script:DeployModule { param($p) (Test-WacRecoverySlotIsPromotable -Path $p).Promotable } $Path)
}

# ---------------------------------------------------------------------------------------------
# "Ours" is not "a healthy replacement"
# ---------------------------------------------------------------------------------------------

Test-Case 'An EMPTY deployment root does not authorise deleting the only copy left in the recovery slot' {
    # The exact shape a move interrupted half way leaves: an empty directory at the root, which
    # ownership deliberately adopts as Unmanaged AND OURS so that a first install is not refused.
    # That adoption used to be the whole test before .previous was cleared.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-empty-root' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        [System.IO.Directory]::Move($slots.Root, $slots.Previous)
        [void][System.IO.Directory]::CreateDirectory($slots.Root)

        $empty = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root
        Assert-True $empty.IsOurs 'the fixture no longer reproduces the adoption this case is about'
        Assert-True $empty.IsEmpty 'the deployment root is not empty, so this is not the interrupted-move shape'
        Assert-False $empty.IsHealthy 'an empty directory was reported as a healthy deployment'

        $stage = New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2'
        Assert-True (Test-Path -LiteralPath $stage.StagingRoot -PathType Container)

        # Restored, not merely spared: the empty directory held nothing, so putting the original
        # back is the only outcome that leaves the machine with an installation.
        Assert-Equal '# original v1' (Get-SlotRunContent -Slot $slots.Root) 'the only deployment left on the machine was destroyed to make room for a new attempt'
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'the recovered deployment is not the one that was orphaned'
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'the recovery slot was left behind after it was reconciled'
    }
}

Test-Case 'A TAMPERED deployment root does not authorise deleting the recovery slot either' {
    # Ownership reports tampering rather than refusing on it, so a managed tree three of whose files
    # were overwritten is still "ours". It is not, however, a replacement anything verified, and
    # nothing about it says the copy in the recovery slot is superseded.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-tampered-root' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        [System.IO.Directory]::Move($slots.Root, $slots.Previous)
        Copy-WacDeploymentTree -Source $slots.Previous -Destination $slots.Root
        [System.IO.File]::WriteAllText((Join-Path -Path $slots.Root -ChildPath 'Run.ps1'), '# half-written')

        $broken = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root
        Assert-True $broken.IsOurs 'the fixture no longer reproduces the adoption this case is about'
        Assert-True $broken.Tampered 'the tree at the deployment root still matches its manifest'
        Assert-False $broken.IsHealthy 'a tree that stopped matching its own manifest was reported healthy'

        Assert-Throws { New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2' } `
            'not a verified replacement' 'staging discarded the recovery slot on the strength of a broken deployment'

        Assert-Equal '# original v1' (Get-SlotRunContent -Slot $slots.Previous) 'the good copy in the recovery slot was deleted'
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path (Join-Path -Path $slots.Previous -ChildPath 'Run.ps1'))
        Assert-Equal '# half-written' (Get-SlotRunContent -Slot $slots.Root) 'the refusal changed what stands at the deployment root'
    }
}

# ---------------------------------------------------------------------------------------------
# What comes OUT of the recovery slot becomes what SYSTEM executes
# ---------------------------------------------------------------------------------------------

Test-Case 'A recovery slot that cannot be proven ours is never promoted onto the deployment root' {
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-foreign-previous' -Body {
        param($sandbox)

        # Read only inside the Assert-Throws block below, which static analysis cannot see into.
        $null = $sandbox
        $slots = Get-WacDeploymentSlotPath
        [void][System.IO.Directory]::CreateDirectory($slots.Previous)
        [System.IO.File]::WriteAllText((Join-Path -Path $slots.Previous -ChildPath 'someone-elses-product.exe'), 'x')

        Assert-Throws { New-FixtureStage -Sandbox $sandbox -Name 'v1' -RunContent '# first install' } `
            'could not be put back' 'a tree nothing could prove ours was moved onto the deployment root'

        Assert-False (Test-Path -LiteralPath $slots.Root) 'somebody else''s directory was installed as the deployment'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $slots.Previous -ChildPath 'someone-elses-product.exe') -PathType Leaf) `
            'the refusal touched the directory it refused'
    }
}

Test-Case 'A recovery slot that is a reparse point is never promoted onto the deployment root' {
    # Test-Path -PathType Container answers TRUE for a junction, so the promotion used to move the
    # LINK into place and hand SYSTEM whatever it points at.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-link-previous' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        $elsewhere = Join-Path -Path $sandbox -ChildPath 'elsewhere'
        [void][System.IO.Directory]::CreateDirectory($elsewhere)
        [System.IO.File]::WriteAllText((Join-Path -Path $elsewhere -ChildPath 'Run.ps1'), '# whatever the link points at')
        [void](New-TestJunction -Link $slots.Previous -Target $elsewhere)

        Assert-Throws { New-FixtureStage -Sandbox $sandbox -Name 'v1' -RunContent '# first install' } `
            'could not be put back' 'a reparse point was promoted onto the deployment root'

        Assert-False (Test-Path -LiteralPath $slots.Root) 'the deployment root now stands for whatever the link points at'
        Assert-Equal '# whatever the link points at' (Get-SlotRunContent -Slot $elsewhere) 'the junction target was written through'
    }
}

# ---------------------------------------------------------------------------------------------
# The rollback proves WHICH BUILD came back, not merely that one did
# ---------------------------------------------------------------------------------------------

Test-Case 'A rollback refuses a DIFFERENT build that shares the version it moved aside' {
    # Kind, version and "matches its own manifest" all agree between two builds of 1.2.0, so the
    # rollback reported a tree it had never seen as the one it had moved aside. Only an inventory
    # taken from the bytes before the first move tells them apart.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-same-version' -Body {
        param($sandbox)

        [void](Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1')
        $slots = Get-WacDeploymentSlotPath

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)

        # A different build of the same version replaces the contents of the recovery slot, manifest
        # and all, so it is internally consistent in every way the old check could see.
        [System.IO.File]::WriteAllText((Join-Path -Path $slots.Previous -ChildPath 'Run.ps1'), '# a different build of 1.2.0')
        [void](New-WacDeploymentManifest -StagingRoot $slots.Previous)

        $swapped = Get-WacDeploymentOwnership -DeploymentRoot $slots.Previous
        Assert-Equal 'Managed' $swapped.Kind ([string]$swapped.Reason)
        Assert-False $swapped.Tampered 'the fixture is not a self-consistent build, so the old check would have caught it anyway'
        Assert-Equal (Get-WacDeploymentVersion) ([string]$swapped.Version) 'the fixture does not share the version it must be told apart by'

        $restored = Restore-WacDeploymentPrevious
        Assert-False $restored.Restored 'a build this run never moved aside was reported as the one it put back'
        Assert-True ([string]$restored.Reason -match 'different files') ([string]$restored.Reason)

        # And it is caught BEFORE the delete, not after it (ledger WAC-02R). The in-process rollback
        # used to check only that a directory existed in the recovery slot, promote whatever was in
        # it, and compare afterwards - so the refusal it reported had already deleted the verified
        # tree and put the unidentifiable one at the path SYSTEM executes. Both trees survive now,
        # and the one the machine runs is still the one this run proved.
        Assert-Equal '# replacement v2' (Get-SlotRunContent -Slot $slots.Root) `
            'the refusal deleted the verified deployment to put back a tree it could not identify'
        Assert-Equal '# a different build of 1.2.0' (Get-SlotRunContent -Slot $slots.Previous) `
            'the refusal destroyed the tree it could not identify'
    }
}

Test-Case 'A rollback still accepts the tree it really did move aside' {
    # The other half of the case above: the inventory must not make a correct rollback fail.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-same-build' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)

        $restored = Restore-WacDeploymentPrevious
        Assert-True $restored.Restored ([string]$restored.Reason)
        Assert-Equal '# original v1' (Get-SlotRunContent -Slot $slots.Root)
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript)
        Assert-False (Test-Path -LiteralPath (Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root)) `
            'a completed rollback left its transaction record on disk for the next run to act on'
    }
}

# ---------------------------------------------------------------------------------------------
# The process that started the swap is gone
# ---------------------------------------------------------------------------------------------

Test-Case 'An install killed after the swap and before it committed is rolled back by the next run' {
    # The dangerous shape: the root holds a replacement that verifies perfectly against its own
    # manifest, so "is the live tree ours and healthy" answers yes - while the task read-backs that
    # would have made it a committed installation never ran. Nothing in the directories says which
    # of the two trees the machine last trusted; the durable record does.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-death-after-swap' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)
        Assert-Equal '# replacement v2' (Get-SlotRunContent -Slot $slots.Root) 'the fixture did not reach the state this case is about'
        Assert-True (Test-Path -LiteralPath (Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root) -PathType Leaf) `
            'the swap left no durable record, so a later process has nothing to reconcile from'

        Stop-FixtureProcess

        $stage = New-FixtureStage -Sandbox $sandbox -Name 'v3' -RunContent '# replacement v3'
        Assert-True (Test-Path -LiteralPath $stage.StagingRoot -PathType Container)

        Assert-Equal '# original v1' (Get-SlotRunContent -Slot $slots.Root) 'the uncommitted install was kept and the deployment it replaced was deleted'
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'the tree put back is not the one that was moved aside'
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'the recovery slot was left behind after it was reconciled'
        Assert-False (Test-Path -LiteralPath (Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root)) `
            'the reconciled transaction record was left on disk'

        # And the run carries on from a known state: the recovered tree is the one moved aside next.
        $switched = Switch-WacDeploymentStage -KeepPrevious
        Assert-True $switched.PreviousKept 'the recovered deployment was not treated as a previous tree'
        Assert-Equal '# replacement v3' (Get-SlotRunContent -Slot $slots.Root)
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path (Join-Path -Path $slots.Previous -ChildPath 'Run.ps1'))
    }
}

Test-Case 'An install killed between the two moves is put back by the next run, provenance first' {
    # Death with the original in the recovery slot and nothing at the root at all.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-death-between' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        # The move that puts the original aside, and nothing after it - the disk state a process
        # killed between its two moves leaves behind.
        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [System.IO.Directory]::Move($slots.Root, $slots.Previous)
        [void](Remove-WacDeployment -Path $slots.Staging)
        Stop-FixtureProcess

        Assert-False (Test-Path -LiteralPath $slots.Root) 'the fixture did not reach the state this case is about'

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v3' -RunContent '# replacement v3')

        Assert-Equal '# original v1' (Get-SlotRunContent -Slot $slots.Root) 'the only deployment left on the machine was not put back'
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript)
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'the recovery slot was left behind after it was reconciled'
    }
}

# ---------------------------------------------------------------------------------------------
# The steady states this must not break
# ---------------------------------------------------------------------------------------------

Test-Case 'Two clean installs in a row leave no recovery slot and no transaction record' {
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-reinstall' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        $journal = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root

        foreach ($pass in @(1, 2)) {
            [void](New-FixtureStage -Sandbox $sandbox -Name ('pass{0}' -f $pass) -RunContent ('# build {0}' -f $pass))
            [void](Switch-WacDeploymentStage -KeepPrevious)
            Assert-True (Remove-WacDeploymentPrevious) ('the commit of pass {0} did not complete' -f $pass)

            Assert-Equal ('# build {0}' -f $pass) (Get-SlotRunContent -Slot $slots.Root)
            Assert-False (Test-Path -LiteralPath $slots.Previous) ('pass {0} left a recovery slot behind' -f $pass)
            Assert-False (Test-Path -LiteralPath $slots.Staging) ('pass {0} left a staging slot behind' -f $pass)
            Assert-False (Test-Path -LiteralPath $journal) ('pass {0} left its transaction record on disk' -f $pass)

            $ownership = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root
            Assert-True $ownership.IsHealthy ([string]$ownership.Reason)
        }
    }
}

Test-Case 'A committed install still discards the copy it superseded' {
    # The legitimate discard, kept: a recovery slot beside a live, verified deployment of ours and
    # no record of an unfinished swap is a superseded copy, and preserving it forever would leave a
    # second tree in %ProgramFiles% after every upgrade.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-supersede' -Body {
        param($sandbox)

        [void](Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1')
        $slots = Get-WacDeploymentSlotPath

        # A committed upgrade whose final delete failed: the root is healthy, nothing claims an
        # unfinished swap, and the slot is debris.
        Copy-WacDeploymentTree -Source $slots.Root -Destination $slots.Previous
        Assert-True (Test-Path -LiteralPath $slots.Previous -PathType Container)

        $stage = New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2'
        Assert-True (Test-Path -LiteralPath $stage.StagingRoot -PathType Container)
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'a superseded copy was preserved forever beside a healthy deployment'
    }
}

Test-Case 'A pre-manifest deployment is still adopted, replaced and committed' {
    # Legacy adoption, unchanged: IsHealthy is false for a tree with no manifest, and that must
    # narrow only what may be DISCARDED - never strand a machine that installed before manifests.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-legacy' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# legacy v1'
        $slots = Get-WacDeploymentSlotPath
        [System.IO.File]::Delete((Get-WacDeploymentManifestPath -DeploymentRoot $slots.Root))

        $legacy = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root
        Assert-Equal 'Unmanaged' $legacy.Kind ([string]$legacy.Reason)
        Assert-True $legacy.IsOurs 'a pre-manifest deployment stopped being adoptable'

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        $switched = Switch-WacDeploymentStage -KeepPrevious
        Assert-True $switched.PreviousKept 'the legacy tree was discarded instead of being kept for a rollback'
        Assert-Equal '# replacement v2' (Get-SlotRunContent -Slot $slots.Root)

        # And it can still be rolled back to, inventory and all, even with no manifest of its own.
        $restored = Restore-WacDeploymentPrevious
        Assert-True $restored.Restored ([string]$restored.Reason)
        Assert-Equal '# legacy v1' (Get-SlotRunContent -Slot $slots.Root)
        Assert-Equal ($live.RunScript) (Join-Path -Path $slots.Root -ChildPath 'Run.ps1')
    }
}

Test-Case 'A TORN transaction record preserves both trees instead of authorising a discard' {
    # The data-loss path. A record that is present but unparsable used to read exactly like absence -
    # both became $null - so the resolver saw "a healthy root and no unfinished swap", concluded the
    # slot was superseded debris, and DELETED the only other copy. A torn record means the opposite:
    # something was mid-transaction and its shape cannot be read, which is the one state where
    # guessing costs the operator both trees.
    #
    # The same fixture as the legitimate discard above, with one difference - the record is there and
    # is garbage - so the two cases differ by exactly the fact under test.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-torn' -Body {
        param($sandbox)

        [void](Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1')
        $slots = Get-WacDeploymentSlotPath
        Copy-WacDeploymentTree -Source $slots.Root -Destination $slots.Previous
        Assert-True (Test-Path -LiteralPath $slots.Previous -PathType Container)

        # A write that stopped half way: valid JSON never starts and ends like this.
        $journalPath = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root
        [System.IO.File]::WriteAllText($journalPath, '{"Schema":1,"ProjectId":"wind')

        $read = Read-WacDeploymentJournal -DeploymentRoot $slots.Root
        Assert-Equal 'Unreadable' ([string]$read.State) `
            ('a torn record was not reported as unreadable: ' + [string]$read.Reason)

        # Through the real staging entry point, which is where recovery is reconciled - the same
        # route the legitimate-discard case above takes, so the two differ only in the record.
        $refused = $false
        $reason = ''
        try { [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2') }
        catch { $refused = $true; $reason = [string]$_.Exception.Message }

        Assert-True $refused 'a torn transaction record was treated as proof that no transaction happened'
        Assert-True ($reason -match 'could not be read') ('the refusal did not name the reason: ' + $reason)
        Assert-True (Test-Path -LiteralPath $slots.Previous -PathType Container) `
            'the only other copy was deleted on the strength of a record nobody could read'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $slots.Root -ChildPath 'Run.ps1')) `
            'the live deployment was disturbed as well'
    }
}

Test-Case 'A recovery slot nobody can vouch for is never promoted onto the deployment root' {
    # Being OURS is not being SAFE. A slot is promoted into the path SYSTEM executes, so it gets the
    # same trust walk the deployment root gets, and this case proves what the gate DOES with an
    # untrusted answer. The answer is forced rather than inherited from the machine's TEMP ACL: the
    # first version left the walk real, passed on a developer profile and failed on the CI runner,
    # because it was measuring the runner rather than the code. Everything else about the fixture is
    # the "empty root" shape that normally promotes.
    #
    # Nothing is touched on refusal: an operator who has lost the live tree still has the copy.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-untrusted' -UntrustedSandbox -Body {
        param($sandbox)

        [void](Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1')
        $slots = Get-WacDeploymentSlotPath
        Copy-WacDeploymentTree -Source $slots.Root -Destination $slots.Previous
        [void](Remove-WacDeployment -Path $slots.Root)
        [void][System.IO.Directory]::CreateDirectory($slots.Root)

        $refused = $false
        $reason = ''
        try { [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2') }
        catch { $refused = $true; $reason = [string]$_.Exception.Message }

        Assert-True $refused 'a recovery slot on a user-writable path was promoted onto the deployment root'
        Assert-True ($reason -match 'cannot be trusted') ('the refusal did not name the trust walk: ' + $reason)
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $slots.Previous -ChildPath 'Run.ps1')) `
            'the copy was destroyed by the very refusal that exists to protect it'
    }
}

# ---------------------------------------------------------------------------------------------
# The schema window, and what the record is allowed to corroborate
# ---------------------------------------------------------------------------------------------

function Set-FixtureJournalSchema {
    <#
    .SYNOPSIS
        Rewrites the Schema number of the record on disk and leaves every other field alone.
    .DESCRIPTION
        Exactly the shape a record written by a DIFFERENT build has: same fields, same values,
        different version number. Nothing else is touched, so a case using this differs from the
        same case without it by precisely the number under test.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][int]$Schema
    )

    $path = Get-WacDeploymentJournalPath -DeploymentRoot $Root
    $record = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path))
    $record.Schema = $Schema
    [System.IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $record -Depth 5),
        (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

Test-Case 'A record written at the OLDEST schema this build supports still drives recovery' {
    # The compatibility state's whole reason for existing. Adding fields bumped the schema this build
    # WRITES, and an exact-match test on that number would make every already-installed machine read
    # its own in-flight record as unreadable - which Resolve-WacDeploymentRecoverySlot turns into a
    # THROW, so the upgrade that carried the new schema could never run on the machines that needed
    # it. The window is one-sided on purpose: older, down to the declared minimum, is still actionable.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-schema-old' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $originalHash = Get-WacDeploymentFileHash -Path $live.RunScript
        $slots = Get-WacDeploymentSlotPath

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)
        [void](Set-FixtureJournalSchema -Root $slots.Root -Schema 1)
        Stop-FixtureProcess

        $read = Read-WacDeploymentJournal -DeploymentRoot $slots.Root
        Assert-Equal 'Valid' ([string]$read.State) ('a record one schema old was refused: ' + [string]$read.Reason)
        Assert-Equal 1 ([int]$read.Schema) 'the read did not report the schema it actually found'

        # And it is not merely readable: the interrupted install it describes is still rolled back.
        [void](New-FixtureStage -Sandbox $sandbox -Name 'v3' -RunContent '# replacement v3')

        Assert-Equal '# original v1' (Get-SlotRunContent -Slot $slots.Root) `
            'a machine carrying the previous schema could not recover its own interrupted install'
        Assert-Equal $originalHash (Get-WacDeploymentFileHash -Path $live.RunScript) 'the tree put back is not the one that was moved aside'
        Assert-False (Test-Path -LiteralPath $slots.Previous) 'the recovery slot was left behind after it was reconciled'
    }
}

Test-Case 'A record from a NEWER build than this one is refused rather than half-understood' {
    # The other side of the window. A later build's record may carry fields that change what the ones
    # here mean, and acting on a guess about them is exactly what the three-state read exists to stop:
    # it is Unreadable, so both trees are left for the build that wrote it.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-schema-new' -Body {
        param($sandbox)

        [void](Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1')
        $slots = Get-WacDeploymentSlotPath

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)

        # One past whatever this build actually wrote, read off the record itself rather than
        # hard-coded. A literal went stale the moment the schema was bumped for the generation id:
        # the number this case called "newer" became the number this build writes, so the case
        # started proving that a CURRENT record is readable and nothing about a future one.
        $newer = [int](Read-WacDeploymentJournal -DeploymentRoot $slots.Root).Schema + 1
        [void](Set-FixtureJournalSchema -Root $slots.Root -Schema $newer)
        Stop-FixtureProcess

        $read = Read-WacDeploymentJournal -DeploymentRoot $slots.Root
        Assert-Equal 'Unreadable' ([string]$read.State) 'a record from a build this one knows nothing about was acted on'
        Assert-Equal $newer ([int]$read.Schema) 'the read did not report the schema it actually found'

        $refused = $false
        $reason = ''
        try { [void](New-FixtureStage -Sandbox $sandbox -Name 'v3' -RunContent '# replacement v3') }
        catch { $refused = $true; $reason = [string]$_.Exception.Message }

        Assert-True $refused 'a record this build cannot understand was treated as no record at all'
        Assert-True ($reason -match 'could not be read') ('the refusal did not name the reason: ' + $reason)
        Assert-Equal '# original v1' (Get-SlotRunContent -Slot $slots.Previous) 'the copy in the recovery slot was destroyed'
        Assert-Equal '# replacement v2' (Get-SlotRunContent -Slot $slots.Root) 'the refusal changed what stands at the deployment root'
    }
}

Test-Case 'A recovery slot REWRITTEN since the record was taken is not promoted onto an empty root' {
    # Ledger WAC-02R, the promotion half. The empty-root branch promoted on provenance alone - ours,
    # holds a Run.ps1, healthy against its own manifest, trusted - and a slot rewritten after the
    # record was taken answers yes to every one of those. What it does NOT match is the inventory the
    # durable record took of the tree that was actually moved aside, and what comes out of the slot
    # becomes what SYSTEM executes.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-slot-rewritten' -Body {
        param($sandbox)

        [void](Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1')
        $slots = Get-WacDeploymentSlotPath

        [void](New-FixtureStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)
        Assert-True (Test-Path -LiteralPath (Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root) -PathType Leaf) `
            'the swap left no durable record, so this case would prove nothing about corroborating one'

        # The empty directory a half-finished move leaves, which is the shape that promotes.
        [void](Remove-WacDeployment -Path $slots.Root)
        [void][System.IO.Directory]::CreateDirectory($slots.Root)

        # And a slot that is still ours and still self-consistent - manifest regenerated - but is no
        # longer the tree the record describes.
        [System.IO.File]::WriteAllText((Join-Path -Path $slots.Previous -ChildPath 'Run.ps1'), '# rewritten since the record was taken')
        [void](New-WacDeploymentManifest -StagingRoot $slots.Previous)
        Stop-FixtureProcess

        $promotable = Test-WacRecoverySlotIsPromotableProbe -Path $slots.Previous
        Assert-True $promotable 'the fixture no longer reproduces a slot that passes every provenance check'

        $refused = $false
        $reason = ''
        try { [void](New-FixtureStage -Sandbox $sandbox -Name 'v3' -RunContent '# replacement v3') }
        catch { $refused = $true; $reason = [string]$_.Exception.Message }

        Assert-True $refused 'a slot rewritten since the record was taken was promoted onto the path SYSTEM executes'
        Assert-True ($reason -match 'no longer matches the durable record') ('the refusal did not name the corroboration: ' + $reason)
        Assert-Equal '# rewritten since the record was taken' (Get-SlotRunContent -Slot $slots.Previous) `
            'the refusal destroyed the tree it could not identify'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $slots.Root -ChildPath 'Run.ps1')) `
            'the unidentified slot was moved onto the deployment root anyway'
    }
}

Test-Case 'With no record to corroborate against, the provenance checks still stand alone' {
    # The benign half, and the reason Matches and Corroborated are two answers rather than one: a
    # first install, or any run whose transaction committed, leaves no record - and refusing then
    # would strand every machine whose recovery slot is the only installation it has left.
    Reset-RecoveryFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-no-record' -Body {
        param($sandbox)

        $live = Install-FixtureDeployment -Sandbox $sandbox -Name 'v1' -RunContent '# original v1'
        $slots = Get-WacDeploymentSlotPath
        Assert-False (Test-Path -LiteralPath (Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root)) `
            'the committed install left a record, so this case would not be the no-record shape'

        $verdict = Test-WacRecoverySlotMatchesRecord -Path $slots.Root -Record $null
        Assert-True $verdict.Matches 'a slot with no record to check against was reported as a mismatch'
        Assert-False $verdict.Corroborated 'an unchecked slot was reported as corroborated, which is the one thing it must never read as'
        Assert-True ([string]$verdict.Reason -match 'no durable record') ([string]$verdict.Reason)

        # And a real record naming this very tree does corroborate, so the comparison is load-bearing
        # rather than a function that answers yes to everything.
        $inventory = Get-WacDeploymentFingerprint -DeploymentRoot $slots.Root
        Assert-True $inventory.Complete ([string]$inventory.Reason)
        $matched = Test-WacRecoverySlotMatchesRecord -Path $slots.Root -Record ([PSCustomObject]@{ OriginalFingerprint = [string]$inventory.Fingerprint })
        Assert-True $matched.Matches ([string]$matched.Reason)
        Assert-True $matched.Corroborated ([string]$matched.Reason)

        $wrong = Test-WacRecoverySlotMatchesRecord -Path $slots.Root -Record ([PSCustomObject]@{ OriginalFingerprint = ('0' * 64) })
        Assert-False $wrong.Matches 'a fingerprint that does not match was accepted'
        Assert-False $wrong.Corroborated 'a mismatch was reported as corroboration'
        Assert-Equal ($live.RunScript) (Join-Path -Path $slots.Root -ChildPath 'Run.ps1')
    }
}

Complete-TestRun
