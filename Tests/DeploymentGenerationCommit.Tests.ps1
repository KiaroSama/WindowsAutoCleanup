#Requires -Version 5.1
<#
.SYNOPSIS
    What authorises retiring a recovery copy, and what an interrupted generation leaves behind that
    a later run has to recognise rather than refuse for ever (ledger WAC-02R).

.DESCRIPTION
    Two defects, one mistake in both: reading a SHAPE ON DISK as a DECISION nobody wrote down.

      * Commitment was inferred. A replacement manifest that matched the record, or a healthy tree
        beside an original that could not be promoted, was treated as proof that the generation
        which put it there had finished - and a run can leave both of those behind and still have
        died before it registered the task that went with them. Retiring the recovery copy on that
        reading discards the only installation the machine ever had working. Commitment is now
        WRITTEN, and a record that does not say it describes a transaction still open.
      * Recovery was not idempotent across its own crash window. Putting the recovery copy back and
        deleting the record are two steps; a process killed between them leaves the ORIGINAL at the
        root, no slot, and a record naming the replacement - which is the state the rollback was
        aiming for, and which used to read as a transaction nobody could account for, for ever.

    DeploymentRecovery.Tests.ps1 owns what a slot may be promoted from, and DeploymentTransactionState
    owns the three-valued reads underneath both. This file owns the single question those two do not
    ask: given the same disk, what does the COMMIT FIELD change, and what happens to the pair.

    Nothing is stubbed but the sandbox trust walk. %ProgramFiles% is redirected into a disposable
    directory, every tree is built through the real staging path, and every assertion is an inventory
    of the files actually standing on disk afterwards - so a recovery that reported the right words
    while deleting the wrong tree cannot pass. The commit flag is stamped onto the record BY THIS
    SUITE rather than through the module that writes it, because what is under test is what the
    reader concludes from a record, not how one comes to be written.
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

function Reset-CommitFixture {
    <#
    .SYNOPSIS
        The death of the process that started a swap: the in-memory transaction goes, the disk stays
        exactly as it was, so everything that follows comes off the durable record alone.
    #>
    & $script:DeployModule { $script:DeploymentTransaction = $null }
}

function Invoke-RecoveryHalf {
    <#
    .SYNOPSIS
        The file half of the recovery plan, reached through the module's own scope.
    .DESCRIPTION
        Through the scope rather than the export list on purpose: which functions this module
        exports is a separate decision from what they do, and a case about reconciliation should not
        start failing because an export line moved.
    #>
    param([Parameter(Mandatory = $true)]$Slots)

    return (& $script:DeployModule { param($s) Resolve-WacDeploymentRecoverySlot -Slots $s } $Slots)
}

function New-CommitStage {
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RunContent
    )

    return (New-WacDeploymentStage -SourceRoot (New-TestCheckout -Path (Join-Path -Path $Sandbox -ChildPath $Name) -RunContent $RunContent))
}

function Set-RecordCommitted {
    <#
    .SYNOPSIS
        Stamps, clears or REMOVES the Committed field of the swap record on disk.
    .DESCRIPTION
        Written here rather than through Set-WacDeploymentCommitted so a case measures what the
        reader concludes from a record rather than what the writer happens to produce, and so the
        pre-schema-4 shape is reachable at all: -Absent deletes the property, which is what every
        machine installed before this build has beside its deployment, and an absent member is a
        different route into the reader from a present one carrying $false.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [switch]$Committed,
        [switch]$Absent
    )

    $path = Get-WacDeploymentJournalPath -DeploymentRoot $Root
    $record = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path))

    if ($Absent) { $record.PSObject.Properties.Remove('Committed') }
    elseif (@($record.PSObject.Properties.Name) -ccontains 'Committed') { $record.Committed = [bool]$Committed }
    else { Add-Member -InputObject $record -MemberType NoteProperty -Name 'Committed' -Value ([bool]$Committed) }

    [System.IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $record -Depth 6),
        (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

function Get-RecordField {
    <#
    .SYNOPSIS
        One field of the swap record as it sits on disk, read without the module's own reader.
    .DESCRIPTION
        Not through Get-WacJournalField: that is the very accessor the resolver reads a record with,
        so a case using it to check its own fixture would be asking the code under test whether the
        state it set up exists. The absent-member case is handled here for the same reason it is
        there - under Set-StrictMode a plain property read of a missing member is terminating.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $path = Get-WacDeploymentJournalPath -DeploymentRoot $Root
    $record = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path))
    if (-not (@($record.PSObject.Properties.Name) -ccontains $Name)) { return $null }
    return $record.$Name
}

function Get-CommitInventory {
    <#
    .SYNOPSIS
        The files standing in one slot - relative path and content hash, sorted - computed HERE and
        not by the code under test, so a case compares trees independently of what the module says
        about them.
    .DESCRIPTION
        The manifest is excluded because it records the moment it was written, so two stagings of
        one checkout never share it; excluding it is what lets a case ask whether the FILES are the
        build it expects rather than whether two timestamps agree.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return '<absent>' }

    $prefix = $Path.TrimEnd('\') + '\'
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        if ([string]::Equals($file.Name, 'wac-deployment.json', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $relative = $file.FullName
        if ($relative.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relative = $relative.Substring($prefix.Length)
        }
        [void]$lines.Add(('{0}|{1}' -f $relative.ToUpperInvariant(), (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash))
    }
    if ($lines.Count -eq 0) { return '<empty>' }

    $ordered = [string[]]$lines.ToArray()
    [array]::Sort($ordered, [System.StringComparer]::Ordinal)
    return ($ordered -join '; ')
}

function Get-CommitShape {
    <#
    .SYNOPSIS
        The WHOLE state one reconciliation left behind, as one comparable string: both trees and
        both records.
    .DESCRIPTION
        A verdict label is the cheapest thing a wrong implementation can get right. What a case
        actually has to pin down is the pair on disk afterwards - which tree is at the root, whether
        the recovery copy survived, and whether the evidence of the transaction is still there for
        the run after this one.
    #>
    param([Parameter(Mandatory = $true)]$Slots)

    $swap = Get-WacDeploymentJournalPath -DeploymentRoot $Slots.Root
    $capture = Get-WacDeploymentJournalPath -DeploymentRoot $Slots.Root -Kind 'TaskCapture'

    return (@(
        'root=' + (Get-CommitInventory -Path $Slots.Root)
        'previous=' + (Get-CommitInventory -Path $Slots.Previous)
        'swapRecord=' + $(if (Test-Path -LiteralPath $swap -PathType Leaf) { 'present' } else { 'absent' })
        'captureRecord=' + $(if (Test-Path -LiteralPath $capture -PathType Leaf) { 'present' } else { 'absent' })
    ) -join '; ')
}

function New-InterruptedUpgrade {
    <#
    .SYNOPSIS
        The disk an upgrade killed after its swap and before its commit leaves: original A in the
        recovery slot, replacement B live, and an OPEN record naming B.
    .OUTPUTS
        Slots, Original (A's inventory), Replacement (B's inventory).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [string]$OriginalContent = '# original A',
        [string]$ReplacementContent = '# replacement B'
    )

    $slots = Get-WacDeploymentSlotPath
    [void](Install-WacDeployment -SourceRoot (New-TestCheckout -Path (Join-Path -Path $Sandbox -ChildPath 'A') -RunContent $OriginalContent))
    Reset-CommitFixture
    $original = Get-CommitInventory -Path $slots.Root

    [void](New-CommitStage -Sandbox $Sandbox -Name 'B' -RunContent $ReplacementContent)
    [void](Switch-WacDeploymentStage -KeepPrevious)
    Reset-CommitFixture

    return ([PSCustomObject]@{
        Slots = $slots
        Original = $original
        Replacement = (Get-CommitInventory -Path $slots.Root)
    })
}

# ---------------------------------------------------------------------------------------------
# A generation with no recovery copy behind it
# ---------------------------------------------------------------------------------------------

Test-Case 'A first install interrupted with no recovery copy undoes only what it added, and a missing one refuses' {
    # Two shapes that both arrive at "there is no slot", and they are opposites. A first install
    # moved nothing aside, so the tree at the root is the only thing that generation touched and
    # removing it costs the machine nothing it had before. An upgrade whose recovery copy is GONE
    # moved something aside that nobody can now produce - and that used to be read as a commit
    # purely because the replacement manifest matched, which says which tree is standing there and
    # nothing whatever about the run that put it there having finished.
    Reset-CommitFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-commit-firstinstall' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        [void](New-CommitStage -Sandbox $sandbox -Name 'first' -RunContent '# first install')
        [void](Switch-WacDeploymentStage -KeepPrevious)
        Reset-CommitFixture

        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'Valid' ([string]$plan.Swap.State) 'the fixture left no readable record, so it proves nothing about one'
        Assert-Equal 'Absent' ([string]$plan.SlotState) 'a first install created a recovery slot, so this is not the shape the case is about'
        Assert-Equal 'Absent' ([string](Get-RecordField -Root $slots.Root -Name 'OriginalState')) `
            'the record says something was moved aside, so this is not a first install'
        Assert-Equal 'RestoreOriginal' ([string]$plan.Verdict) `
            ('an interrupted first install that never recorded a commit was not undone: {0}' -f [string]$plan.Reason)

        $acted = Invoke-RecoveryHalf -Slots $slots
        Assert-Equal 'Restored' ([string]$acted.Action) ([string]$acted.Reason)
        Assert-Equal 'root=<absent>; previous=<absent>; swapRecord=absent; captureRecord=absent' (Get-CommitShape -Slots $slots) `
            'undoing a first install left something of it behind, or took something it never installed'
    }

    Reset-CommitFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-commit-slot-gone' -Body {
        param($sandbox)

        $fixture = New-InterruptedUpgrade -Sandbox $sandbox
        $slots = $fixture.Slots
        [void](Remove-WacDeployment -Path $slots.Previous)

        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'Absent' ([string]$plan.SlotState) 'the fixture did not reach the state this half of the case is about'
        Assert-True $plan.Live.IsHealthy 'the live tree is not the healthy replacement whose manifest used to answer for the whole transaction'
        Assert-Equal 'Refuse' ([string]$plan.Verdict) `
            ('a swap whose recovery copy is gone was closed on the strength of the manifest standing at the root: {0}' -f [string]$plan.Reason)

        Assert-Throws -ScriptBlock { Invoke-RecoveryHalf -Slots $slots } -Pattern 'recovery copy is no longer where it was put'
        Assert-Equal ('root=' + $fixture.Replacement + '; previous=<absent>; swapRecord=present; captureRecord=absent') (Get-CommitShape -Slots $slots) `
            'the refusal changed the disk it exists to preserve'
    }
}

# ---------------------------------------------------------------------------------------------
# The written commit is what retires a recovery copy
# ---------------------------------------------------------------------------------------------

Test-Case 'A healthy replacement beside an OPEN record does not retire the copy it replaced' {
    # The dangerous inference, at its sharpest. Everything an outside observer can see says success:
    # the root holds a tree of ours that verifies against its own manifest, the slot holds a copy
    # that is merely older. What nobody can see is whether the run that made that arrangement lived
    # long enough to register the task pointing into it - so the record, which does not say it
    # committed, is the only honest witness and the copy stays.
    Reset-CommitFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-commit-open' -Body {
        param($sandbox)

        $fixture = New-InterruptedUpgrade -Sandbox $sandbox
        $slots = $fixture.Slots

        # Read back first, so a failure below says whether the fixture or the rule is wrong.
        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-True $plan.Live.IsHealthy 'the live replacement is not healthy, so the case would refuse for a reason it is not about'
        Assert-True $plan.Promotable.Promotable ([string]$plan.Promotable.Reason)
        Assert-True $plan.Corroboration.Corroborated ([string]$plan.Corroboration.Reason)
        Assert-False (Get-RecordField -Root $slots.Root -Name 'Committed') 'the fixture left a record that already says it committed'

        Assert-Equal 'RestoreOriginal' ([string]$plan.Verdict) `
            ('a healthy tree was read as a finished generation and the copy it replaced was retired: {0}' -f [string]$plan.Reason)

        $acted = Invoke-RecoveryHalf -Slots $slots
        Assert-Equal 'Restored' ([string]$acted.Action) ([string]$acted.Reason)
        Assert-Equal ('root=' + $fixture.Original + '; previous=<absent>; swapRecord=absent; captureRecord=absent') (Get-CommitShape -Slots $slots) `
            'the deployment the interrupted run replaced was not what ended up at the root'
    }
}

Test-Case 'The same record stamped COMMITTED does retire the copy, and leaves the replacement alone' {
    # The other half, and the only thing that makes the rule above a rule rather than a refusal to
    # ever clean up: one field, written by the process that established the commitment, turns the
    # same disk from an open transaction into a superseded copy. Without this case a resolver that
    # simply never commits anything would pass the one above.
    Reset-CommitFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-commit-stamped' -Body {
        param($sandbox)

        $fixture = New-InterruptedUpgrade -Sandbox $sandbox
        $slots = $fixture.Slots
        [void](Set-RecordCommitted -Root $slots.Root -Committed)

        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-True ([bool](Get-RecordField -Root $slots.Root -Name 'Committed')) 'the fixture did not stamp the record it meant to'
        Assert-Equal 'CommitReplacement' ([string]$plan.Verdict) `
            ('a generation that recorded its own commit was still treated as unfinished: {0}' -f [string]$plan.Reason)

        $acted = Invoke-RecoveryHalf -Slots $slots
        Assert-Equal 'Discarded' ([string]$acted.Action) ([string]$acted.Reason)
        Assert-Equal ('root=' + $fixture.Replacement + '; previous=<absent>; swapRecord=absent; captureRecord=absent') (Get-CommitShape -Slots $slots) `
            'the committed replacement was disturbed, or the copy it superseded was preserved for ever'
    }
}

Test-Case 'A replacement whose FILES are damaged is rolled back, and a commit stamp does not license discarding beside it' {
    # The manifest file is what identifies the tree a generation put live, and it keeps identifying
    # it after the files beside it have been edited - which is exactly the state where "the recorded
    # replacement is standing there" must not mean "and therefore all is well". Open: the copy goes
    # back. Committed: the copy is still not thrown away, because the live tree it would be
    # superseded by no longer verifies.
    Reset-CommitFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-commit-damaged-open' -Body {
        param($sandbox)

        $fixture = New-InterruptedUpgrade -Sandbox $sandbox
        $slots = $fixture.Slots
        [System.IO.File]::WriteAllText((Join-Path -Path $slots.Root -ChildPath 'src\WindowsAutoCleanup.Core.psm1'), '# damaged after the swap')

        $live = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root
        Assert-True $live.Tampered ('the fixture did not damage the replacement: {0}' -f [string]$live.Reason)
        Assert-False $live.IsHealthy 'a damaged tree still read as healthy, so this case would prove nothing'

        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'RestoreOriginal' ([string]$plan.Verdict) `
            ('an interrupted run whose replacement is damaged did not put back the copy it replaced: {0}' -f [string]$plan.Reason)

        $acted = Invoke-RecoveryHalf -Slots $slots
        Assert-Equal 'Restored' ([string]$acted.Action) ([string]$acted.Reason)
        Assert-Equal ('root=' + $fixture.Original + '; previous=<absent>; swapRecord=absent; captureRecord=absent') (Get-CommitShape -Slots $slots) `
            'the damaged replacement was kept, or the copy that was good was destroyed'
    }

    Reset-CommitFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-commit-damaged-done' -Body {
        param($sandbox)

        $fixture = New-InterruptedUpgrade -Sandbox $sandbox
        $slots = $fixture.Slots
        [System.IO.File]::WriteAllText((Join-Path -Path $slots.Root -ChildPath 'src\WindowsAutoCleanup.Core.psm1'), '# damaged after the commit')
        [void](Set-RecordCommitted -Root $slots.Root -Committed)
        $damaged = Get-CommitInventory -Path $slots.Root

        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'Refuse' ([string]$plan.Verdict) `
            ('a committed record retired the last good copy while the tree that superseded it no longer verified: {0}' -f [string]$plan.Reason)

        Assert-Throws -ScriptBlock { Invoke-RecoveryHalf -Slots $slots } -Pattern 'recovery slot from an earlier run is still present'
        Assert-Equal ('root=' + $damaged + '; previous=' + $fixture.Original + '; swapRecord=present; captureRecord=absent') (Get-CommitShape -Slots $slots) `
            'the refusal touched one of the two trees it exists to preserve'
    }
}

# ---------------------------------------------------------------------------------------------
# A transaction that could not be ended stays unfinished for everyone
# ---------------------------------------------------------------------------------------------

Test-Case 'A record that cannot be deleted keeps the transaction open, and no later generation may overwrite it' {
    # Ending a transaction is a deletion, and a deletion can fail. The failure used to be discarded,
    # so a reconciliation that had put the tree back reported a closed transaction over a record
    # still sitting on disk. It must stay open instead - and the write protocol must not let the
    # NEXT generation stamp its own swap over the unfinished one, because two generations sharing
    # one record is how a rollback ends up restoring a tree from somebody else's evidence.
    Reset-CommitFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-commit-undeletable' -Body {
        param($sandbox)

        $fixture = New-InterruptedUpgrade -Sandbox $sandbox
        $slots = $fixture.Slots
        $record = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root
        $recorded = [string](Get-RecordField -Root $slots.Root -Name 'ReplacementManifestHash')
        Assert-True ($recorded.Length -gt 0) 'the record names no replacement, so this case could not tell one generation from another'

        # Read-only stops File.Delete, so the record survives the reconciliation; a DIRECTORY at the
        # staging name stops the write protocol's first step, so nothing can replace it either.
        # Both are shapes the shipped code reaches on its own error paths.
        [System.IO.File]::SetAttributes($record, [System.IO.FileAttributes]::ReadOnly)
        [void][System.IO.Directory]::CreateDirectory($record + '.new')

        # Restoring bytes is not a clean transaction close. The caller must receive the retirement
        # failure while the original remains restored and the unfinished record remains on disk.
        Assert-Throws -ScriptBlock { Invoke-RecoveryHalf -Slots $slots } -Pattern 'rollback journal could not be retired'
        Assert-Equal $fixture.Original (Get-CommitInventory -Path $slots.Root) 'the tree the record described was not the one put back'
        Assert-True (Test-Path -LiteralPath $record -PathType Leaf) `
            'a record that could not be deleted vanished anyway, so the failure this case is about did not happen'
        Assert-False (Remove-WacDeploymentJournal -DeploymentRoot $slots.Root) `
            'a removal that cannot finish reported the transaction closed'

        # Staging prepares an isolated copy; it does not authorize switching the live generation.
        # The installer reconciles before staging, while this lower-level test deliberately tries
        # the switch directly to prove an unfinished journal cannot be overwritten.
        [void](New-CommitStage -Sandbox $sandbox -Name 'C' -RunContent '# replacement C')
        Assert-Throws -ScriptBlock { Switch-WacDeploymentStage -KeepPrevious } -Pattern 'transaction could not be recorded'
        Reset-CommitFixture

        Assert-Equal $fixture.Original (Get-CommitInventory -Path $slots.Root) 'a swap that could not record itself moved the deployment anyway'
        Assert-Equal $recorded ([string](Get-RecordField -Root $slots.Root -Name 'ReplacementManifestHash')) `
            'a later generation overwrote the record of the unfinished one'

        [System.IO.File]::SetAttributes($record, [System.IO.FileAttributes]::Normal)
        [System.IO.Directory]::Delete($record + '.new')
        $retry = Invoke-RecoveryHalf -Slots $slots
        Assert-Equal 'Restored' ([string]$retry.Action) ([string]$retry.Reason)
        Assert-False (Test-Path -LiteralPath $record) 'recovery still could not retire its record after the obstruction was removed'
        Assert-Equal $fixture.Original (Get-CommitInventory -Path $slots.Root) 'a successful retirement retry changed the original'
    }
}

# ---------------------------------------------------------------------------------------------
# The two halves of one generation, and the two halves of two
# ---------------------------------------------------------------------------------------------

Test-Case 'A capture from a DIFFERENT generation is never closed by this one, committed or not' {
    # The link is what says two durable files are two halves of one transaction, and the commit is
    # what says that transaction finished. They are independent claims and a case has to hold one
    # still while it moves the other: an unlinked pair with an OPEN record touches nothing, and the
    # same pair with the record committed may retire the FILE half it owns while the capture - the
    # only description on this machine of a registration that may be missing - survives untouched.
    Reset-CommitFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-commit-unlinked' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        [void](Install-WacDeployment -SourceRoot (New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'A') -RunContent '# original A'))
        Reset-CommitFixture
        $original = Get-CommitInventory -Path $slots.Root

        Assert-True (Write-WacTaskCaptureRecord -DeploymentRoot $slots.Root -Capture @([PSCustomObject]@{
            TaskName = 'WindowsAutoCleanup'; TaskPath = '\WindowsAutoCleanup\'; Definition = '<Task />'
        })) 'the fixture could not write a capture record'

        [void](New-CommitStage -Sandbox $sandbox -Name 'B' -RunContent '# replacement B')
        [void](Switch-WacDeploymentStage -KeepPrevious)
        Reset-CommitFixture
        $replacement = Get-CommitInventory -Path $slots.Root

        # A capture belonging to some other run entirely.
        $capturePath = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root -Kind 'TaskCapture'
        $capture = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($capturePath))
        $capture.TransactionId = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
        [System.IO.File]::WriteAllText($capturePath, (ConvertTo-Json -InputObject $capture -Depth 6),
            (New-Object System.Text.UTF8Encoding($false)))

        $open = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-False $open.Linked 'two records from different runs were read as one transaction'
        Assert-Equal 'Refuse' ([string]$open.Verdict) `
            ('an open swap beside a capture it does not account for was closed anyway: {0}' -f [string]$open.Reason)

        [void](Set-RecordCommitted -Root $slots.Root -Committed)
        $done = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-False $done.Linked 'stamping the swap record committed changed which generation the capture belongs to'
        Assert-Equal 'Refuse' ([string]$done.Verdict) ([string]$done.Reason)

        Assert-Throws { Resolve-WacDeploymentRecoverySlot -Slots $slots } -Pattern 'different generations'
        Assert-Equal ('root=' + $replacement + '; previous=' + $original + '; swapRecord=present; captureRecord=present') (Get-CommitShape -Slots $slots) `
            'generation disagreement altered files or erased either recovery record'
        Assert-True ($original.Length -gt 0) 'the fixture never inventoried the original it was meant to supersede'
    }
}

# ---------------------------------------------------------------------------------------------
# What the recovery copy has to still BE
# ---------------------------------------------------------------------------------------------

Test-Case 'An ALTERED original is preserved rather than discarded, and an EMPTY one is retired only on a commit' {
    # A slot that passes every provenance check - ours, holds a Run.ps1, self-consistent, trusted -
    # and no longer hashes to the inventory the record took of it is the single worst thing to throw
    # away: nothing on the machine can say what it is, which is a reason to keep it and was being
    # read as permission to delete it, because the tree beside it looked healthy.
    Reset-CommitFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-commit-altered' -Body {
        param($sandbox)

        $fixture = New-InterruptedUpgrade -Sandbox $sandbox
        $slots = $fixture.Slots

        # Still ours and still self-consistent - the manifest is regenerated - but no longer the
        # tree the record describes.
        [System.IO.File]::WriteAllText((Join-Path -Path $slots.Previous -ChildPath 'Run.ps1'), '# altered while it sat in the slot')
        [void](New-WacDeploymentManifest -StagingRoot $slots.Previous)
        $altered = Get-CommitInventory -Path $slots.Previous

        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-True $plan.Promotable.Promotable ('the fixture no longer reproduces a slot that passes every provenance check: {0}' -f [string]$plan.Promotable.Reason)
        Assert-False $plan.Corroboration.Corroborated 'an altered slot still corroborated against the record, so this case proves nothing'
        Assert-True $plan.Live.IsHealthy 'the live tree is not the healthy replacement that used to authorise the discard'
        Assert-Equal 'Refuse' ([string]$plan.Verdict) `
            ('a copy nothing could vouch for was deleted because the tree beside it looked healthy: {0}' -f [string]$plan.Reason)

        Assert-Throws -ScriptBlock { Invoke-RecoveryHalf -Slots $slots } -Pattern 'does not say the run that filled it ever finished'
        Assert-Equal ('root=' + $fixture.Replacement + '; previous=' + $altered + '; swapRecord=present; captureRecord=absent') (Get-CommitShape -Slots $slots) `
            'the refusal destroyed the tree it could not identify'
    }

    Reset-CommitFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-commit-empty' -Body {
        param($sandbox)

        # An existing but EMPTY deployment root is adopted as ours and moved aside like any other
        # original, so the slot holds a directory with nothing in it. There is nothing to lose by
        # discarding it and that is still not a reason to close a transaction nobody finished.
        $slots = Get-WacDeploymentSlotPath
        [void][System.IO.Directory]::CreateDirectory($slots.Root)
        [void](New-CommitStage -Sandbox $sandbox -Name 'B' -RunContent '# replacement B')
        [void](Switch-WacDeploymentStage -KeepPrevious)
        Reset-CommitFixture
        $replacement = Get-CommitInventory -Path $slots.Root

        $open = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'Empty' ([string](Get-RecordField -Root $slots.Root -Name 'OriginalState')) `
            'the record does not describe the empty original this half of the case is about'
        Assert-True $open.Corroboration.Corroborated ([string]$open.Corroboration.Reason)
        Assert-Equal 'RestoreOriginal' ([string]$open.Verdict) `
            ('an empty original was not recognized as a recoverable pre-install state: {0}' -f [string]$open.Reason)
        Assert-Equal ('root=' + $replacement + '; previous=<empty>; swapRecord=present; captureRecord=absent') (Get-CommitShape -Slots $slots) `
            'reading the plan changed the disk'

        [void](Set-RecordCommitted -Root $slots.Root -Committed)
        $done = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'CommitReplacement' ([string]$done.Verdict) ([string]$done.Reason)

        $acted = Invoke-RecoveryHalf -Slots $slots
        Assert-Equal 'Discarded' ([string]$acted.Action) ([string]$acted.Reason)
        Assert-Equal ('root=' + $replacement + '; previous=<absent>; swapRecord=absent; captureRecord=absent') (Get-CommitShape -Slots $slots) `
            'a committed generation left its empty recovery copy behind, or disturbed the tree it installed'
    }
}

# ---------------------------------------------------------------------------------------------
# The crash window of the recovery itself
# ---------------------------------------------------------------------------------------------

Test-Case 'A rollback killed before it ended its transaction is recognised, not refused for ever' {
    # Putting the copy back and deleting the record are two steps, so there is a window between
    # them, and what it leaves is the ORIGINAL at the root with no slot beside it and a record
    # naming the replacement. Every check asked whether the root was the RECORDED REPLACEMENT, which
    # it deliberately is not any more, so the state a completed rollback was aiming for read as a
    # transaction nobody could account for - permanently, because nothing that happens next changes
    # any of those three facts. The identity of what IS standing there answers it.
    Reset-CommitFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-commit-crashwindow' -Body {
        param($sandbox)

        $fixture = New-InterruptedUpgrade -Sandbox $sandbox
        $slots = $fixture.Slots
        $record = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root

        # The rollback's own two moves, and nothing after them.
        Assert-True (Remove-WacDeployment -Path $slots.Root).Removed 'the fixture could not clear the replacement'
        [System.IO.Directory]::Move($slots.Previous, $slots.Root)
        $evidence = [System.IO.File]::ReadAllBytes($record)

        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'Absent' ([string]$plan.SlotState) 'the fixture did not reach the state this case is about'
        Assert-Equal 'RestoreOriginal' ([string]$plan.Verdict) `
            ('a rollback that had already succeeded was read as a transaction nobody could account for: {0}' -f [string]$plan.Reason)

        $acted = Invoke-RecoveryHalf -Slots $slots
        Assert-Equal 'Restored' ([string]$acted.Action) ([string]$acted.Reason)
        Assert-Equal ('root=' + $fixture.Original + '; previous=<absent>; swapRecord=absent; captureRecord=absent') (Get-CommitShape -Slots $slots) `
            'recognising a finished rollback moved or removed something'

        # The same disk a second time. The record is put back because the deletion that ends the
        # transaction is itself a step that can fail, so the state this case is about can arrive
        # twice - and the answer has to be the same one, not a different one.
        [System.IO.File]::WriteAllBytes($record, $evidence)
        $again = Invoke-RecoveryHalf -Slots $slots
        Assert-Equal 'Restored' ([string]$again.Action) ([string]$again.Reason)
        Assert-Equal ('root=' + $fixture.Original + '; previous=<absent>; swapRecord=absent; captureRecord=absent') (Get-CommitShape -Slots $slots) `
            'reconciling the same state twice did not leave it where the first pass did'

        # And with nothing outstanding at all there is simply nothing to reconcile.
        $settled = Invoke-RecoveryHalf -Slots $slots
        Assert-Equal 'None' ([string]$settled.Action) ([string]$settled.Reason)
        Assert-Equal ('root=' + $fixture.Original + '; previous=<absent>; swapRecord=absent; captureRecord=absent') (Get-CommitShape -Slots $slots) `
            'a machine with no transaction outstanding was changed by being asked about one'
    }
}

Complete-TestRun
