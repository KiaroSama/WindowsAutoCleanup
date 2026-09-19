<#
.SYNOPSIS
    Deployment, machine-trust VERIFICATION and scheduled-task ownership proof.

.DESCRIPTION
    Three safety-critical responsibilities:

      * Copy the runtime into %ProgramFiles%\WindowsAutoCleanup through a staging directory and an
        atomic rename, so the SYSTEM task never executes the user's mutable checkout (ledger P0-3).
      * VERIFY that the deployed tree is machine-trusted. The v1.1.0 ACL-hardening capability was
        REMOVED on request (ledger P0-6 / U-2): it rewrote the owner and DACL of the user's own
        checkout and left the folder hard to delete. Nothing in this module calls Set-Acl,
        SetOwner, SetAccessRuleProtection, icacls or takeown. An unreadable or user-writable path
        is reported untrusted so every caller fails closed.
      * Prove a scheduled task belongs to this project before overwriting or deleting it. Both the
        installer and the uninstaller used to act on ANY task named WindowsAutoCleanup (P0-4).

    The FileSystem module's deletion primitives cannot be used here: Initialize-WacRun registers the
    deployment root as a PROTECTED root, so Remove-WacTree correctly refuses it. Deletion in this
    module is therefore direct, bounded, never follows a reparse point, and is restricted by an
    allow-list of exactly three canonical paths.

    The implementation lives in the WindowsAutoCleanup.*.ps1 files beside this one, one per
    responsibility, and they are DOT-SOURCED rather than imported, for the reason Core.psm1
    records at length: a nested Import-Module gives each part its own session state, so a part
    could neither call another part reliably nor see its $script: state. This file keeps the
    stage-and-switch lifecycle, the one machine-wide operation lock, and the export list.
#>

Set-StrictMode -Version 2.0

# No -Force: force-reloading a nested module tears it out of the caller's session too.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop

# Only for Clear-WacBlockingAttribute: Copy-Item preserves a read-only attribute, and File.Delete
# throws on a read-only file. The FileSystem deletion primitives themselves are unusable here,
# because Initialize-WacRun registers the deployment root as a protected root and they refuse it.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.FileSystem.psm1') -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.DeploymentTree.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.DeploymentProof.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.DeploymentJournal.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.DeploymentRecovery.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.DeploymentCommit.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.ScheduledTask.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.TaskMatch.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.TaskRemoval.ps1')

# ONE machine-wide lock covers runtime, install, upgrade and uninstall (ledger B2-3). Until now the
# entry points took 'Global\WindowsAutoCleanupInstaller' while Run.ps1 took 'Global\WindowsAutoCleanup',
# so a cleanup run and a deployment replacement held DIFFERENT locks and could not see each other:
# the uninstaller could delete the tree a live run was executing out of.
#
# The value is deliberately the one Run.ps1 already defaults its -MutexName to, so the runtime needs
# no change and every existing command line keeps working. Run.ps1 cannot call this function - it does
# not import this module - so Deploy.Tests.ps1 parses Run.ps1's parameter default and fails if the two
# ever drift.
$script:OperationLockName = 'Global\WindowsAutoCleanup'

function Get-WacOperationLockName { return $script:OperationLockName }

# The rollback transaction (ledger B2-3). Rollback used to work out what to undo by looking at the
# filesystem, where the absence of a .previous directory meant "this was a first install, so remove
# the root". That inference is wrong in precisely the case that matters: when the second move of a
# switch fails, the switch's own catch moves the original back OUT of .previous, so the outer
# rollback then saw no .previous, deleted the machine's ORIGINAL installation and reported success.
# A failed FIRST move arrived at the same place with nothing moved at all.
#
# The record is written before the first move and updated after every one of them, so
# Restore-WacDeploymentPrevious acts on what happened rather than on what is missing. It is
# per-process state deliberately: it describes a swap this process is in the middle of, and a swap
# that outlived its process is reconciled from disk by Resolve-WacDeploymentRecoverySlot instead.
$script:DeploymentTransaction = $null

function Move-WacDeploymentSlot {
    <#
    .SYNOPSIS
        Renames one deployment slot directory onto another slot path.
    .DESCRIPTION
        Every slot rename in this module goes through here, so the transaction record and the
        directory that actually moved cannot drift apart, and so one specific move can be made to
        fail without disturbing the rest of the lifecycle.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string]$To
    )

    [System.IO.Directory]::Move($From, $To)
}

function Save-WacDeploymentJournal {
    <#
    .SYNOPSIS
        Writes the current stage of the in-flight swap to the durable record beside the slots.
    .DESCRIPTION
        The record carries what a LATER PROCESS needs and cannot otherwise obtain: which root is
        being swapped, and the content identity of the tree that was at it before the first move.
        Stage is evidence for a human reading the file; nothing branches on it, because a stage
        update can itself be the write that never landed. What the recovery path branches on is the
        pair of fingerprints, each re-checked against the bytes on disk.
    #>
    param(
        [Parameter(Mandatory = $true)]$Transaction,
        [Parameter(Mandatory = $true)][string]$Stage
    )

    return (Write-WacDeploymentJournal -DeploymentRoot $Transaction.Root -Record ([PSCustomObject]@{
        Schema = $script:DeploymentJournalSchema
        ProjectId = $script:DeploymentProjectId
        Root = $Transaction.Root
        Previous = $Transaction.Previous
        Stage = $Stage
        TransactionId = (Get-WacDeploymentGeneration)
        StartedUtc = [string]$Transaction.StartedUtc
        OriginalState = [string]$Transaction.OriginalState
        ProcessId = $PID
        OriginalKind = [string]$Transaction.OriginalKind
        OriginalVersion = [string]$Transaction.OriginalVersion
        OriginalTampered = [bool]$Transaction.OriginalTampered
        OriginalFingerprint = [string]$Transaction.OriginalFingerprint
        OriginalFileCount = [int]$Transaction.OriginalFileCount
        ReplacementManifestHash = [string]$Transaction.ReplacementManifestHash
        Committed = [bool]$Transaction.Committed
        ReplacementTask = @(Get-WacJournalField -Record $Transaction -Name 'ReplacementTask')
        TaskDecision = [bool](Get-WacJournalField -Record $Transaction -Name 'TaskDecision')
    }))
}

function New-WacDeploymentStage {
    <#
    .SYNOPSIS
        Builds the complete new deployment in the .staging slot and writes its manifest. Nothing the
        running task can reach is touched.
    .DESCRIPTION
        Split out of Install-WacDeployment for ledger B2-3's ordering rule: the caller must be able
        to VERIFY the tree, and resolve the existing scheduled task, before anything goes live. The
        staging slot is a different directory from the deployment root, so building it cannot change
        a file the currently registered task would execute.
    .OUTPUTS
        StagingRoot, Manifest, FileCount, Version.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SourceRoot)

    $source = Get-WacNormalizedPath -Path $SourceRoot
    if (-not $source -or -not (Test-Path -LiteralPath $source -PathType Container)) {
        throw ("The source directory does not exist: {0}" -f $SourceRoot)
    }

    $slots = Get-WacDeploymentSlotPath
    if (-not $slots) { throw 'The deployment root could not be resolved.' }

    if ((Test-WacIsWithinRoot -ChildPath $source -RootPath $slots.Root) -or
        (Test-WacIsWithinRoot -ChildPath $slots.Root -RootPath $source)) {
        throw ("The source checkout overlaps the deployment root ({0}); move the checkout elsewhere and re-run." -f $slots.Root)
    }

    $sourceRun = Join-Path -Path $source -ChildPath 'Run.ps1'
    $sourceSrc = Join-Path -Path $source -ChildPath 'src'
    if (-not (Test-Path -LiteralPath $sourceRun -PathType Leaf)) { throw ("Run.ps1 was not found in {0}." -f $source) }
    if (-not (Test-Path -LiteralPath $sourceSrc -PathType Container)) { throw ("The src directory was not found in {0}." -f $source) }

    # The recovery slot is NOT reconciled here any more (ledger WAC-02R). It used to be, which put
    # the file half of a recovery behind every prerequisite of the NEW installation: the checks
    # above reject a source that is missing, malformed or overlapping, and the caller's own host and
    # budget checks sit in front of this function entirely. A run that had already restored the task
    # half and then failed one of those returned with task A standing over files B - an unfinished
    # pair, exposed, with no further attempt scheduled to close it. Both halves now run back to back
    # in the caller, before anything about the new install is asked.
    #
    # The staging slot carries no such risk - it only ever holds a build in progress - so it is
    # still cleared unconditionally.
    $cleared = Remove-WacDeployment -Path $slots.Staging
    if (-not $cleared.Removed) {
        throw ("A leftover deployment slot could not be cleared: {0} ({1})" -f $slots.Staging, $cleared.Reason)
    }

    Write-WacLog -Level INFO -Component 'Deploy' -Message 'Staging the deployment.' -Data @{ source = $source; staging = $slots.Staging }

    New-Item -Path $slots.Staging -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Copy-Item -LiteralPath $sourceRun -Destination (Join-Path -Path $slots.Staging -ChildPath 'Run.ps1') -Force -ErrorAction Stop
    # -Depth 1 because the destination IS level 1 of the deployment - see Copy-WacDeploymentTree for
    # what the missing 1 used to cost.
    Copy-WacDeploymentTree -Source $sourceSrc -Destination (Join-Path -Path $slots.Staging -ChildPath 'src') -Depth 1

    $sourceLicense = Join-Path -Path $source -ChildPath 'LICENSE'
    if (Test-Path -LiteralPath $sourceLicense -PathType Leaf) {
        Copy-Item -LiteralPath $sourceLicense -Destination (Join-Path -Path $slots.Staging -ChildPath 'LICENSE') -Force -ErrorAction Stop
    }

    $manifest = New-WacDeploymentManifest -StagingRoot $slots.Staging

    # Read the staged tree back through the same ownership proof the deployment root will face. Here
    # a hash mismatch IS fatal - it means the copy did not land intact - unlike on an installed tree,
    # where refusing on it would make an edited file impossible to replace.
    $staged = Get-WacDeploymentOwnership -DeploymentRoot $slots.Staging
    if ($staged.Kind -ne 'Managed' -or $staged.Tampered) {
        [void](Remove-WacDeployment -Path $slots.Staging)
        throw ("The staged deployment did not verify against its own manifest: {0}" -f $staged.Reason)
    }

    return [PSCustomObject]@{
        StagingRoot = $slots.Staging
        Manifest = $manifest
        FileCount = @($manifest.File).Count
        Version = $script:DeploymentVersion
    }
}

function Switch-WacDeploymentStage {
    <#
    .SYNOPSIS
        Atomically swaps the staged tree into the deployment root, under a recorded transaction.
    .DESCRIPTION
        Move-old-aside / move-staging-in, with the old tree restored if the second move fails. With
        -KeepPrevious the old tree is LEFT in the .previous slot so the caller can roll back after a
        later step - registering the task, or asserting what it registered - fails.

        $script:DeploymentTransaction is written BEFORE the first move and updated after each one,
        because the directories left behind afterwards do not say what happened: .previous is absent
        both when there never was an original and when the catch below has already put one back, and
        rollback used to treat those two opposite states identically. The record also carries what
        the original WAS, so a restored tree can be checked against it rather than merely counted.
    .OUTPUTS
        DeploymentRoot, RunScript, FileCount, PreviousKept.
    #>
    [CmdletBinding()]
    param([switch]$KeepPrevious)

    $slots = Get-WacDeploymentSlotPath
    if (-not $slots) { throw 'The deployment root could not be resolved.' }
    if (-not (Test-Path -LiteralPath $slots.Staging -PathType Container)) {
        throw ("There is no staged deployment to switch into place: {0}" -f $slots.Staging)
    }

    # THREE states, not two (ledger WAC-02R). HadOriginal was a [bool] over "is there a directory
    # here", and Get-WacDeploymentFingerprint refuses a tree with no files in it - so an EXISTING
    # BUT EMPTY deployment root, which Get-WacDeploymentOwnership deliberately adopts as ours, was
    # recorded as an original whose content could not be inventoried and every install onto one
    # threw. Absent, Empty and Substantive are now separate answers: what has to be moved aside
    # (Empty and Substantive) is a different question from what has to be fingerprinted
    # (Substantive alone), and one flag could not carry both.
    $originalState = 'Absent'
    if (Test-Path -LiteralPath $slots.Root -PathType Container) {
        $existing = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root
        if ([string]$existing.Kind -ceq 'Indeterminate') {
            throw ("The deployment about to be replaced could not be read, so a rollback could not prove what it put back: {0}" -f [string]$existing.Reason)
        }
        $originalState = if ([bool]$existing.IsEmpty) { 'Empty' } else { 'Substantive' }
    }

    $transaction = [PSCustomObject]@{
        Root = $slots.Root
        Previous = $slots.Previous
        StartedUtc = ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
        OriginalState = $originalState
        HadOriginal = (-not [string]::Equals($originalState, 'Absent', [System.StringComparison]::Ordinal))
        OriginalKind = $null
        OriginalVersion = $null
        OriginalTampered = $false
        OriginalFingerprint = $null
        OriginalFileCount = 0
        OriginalMovedAside = $false
        ReplacementLive = $false
        ReplacementManifestHash = $null
        Committed = $false
        OriginalRestored = $false
        RestoreVerdict = $null
    }

    # THE REPLACEMENT'S IDENTITY, TAKEN BEFORE ANYTHING IRREVERSIBLE (ledger WAC-02R). The manifest
    # is hashed at the STAGING path, whose bytes are the ones that will stand at the root: a
    # Directory.Move moves the file, it does not rewrite it. Taking it here rather than after the
    # swap is the whole point - the record that says which tree this generation put live is durable
    # BEFORE the move that puts it there, so a process killed in that window leaves evidence of
    # what it was doing instead of a tree nobody can attribute.
    #
    # Refusing here is free: nothing has moved, so the cost is the staged copy.
    $transaction.ReplacementManifestHash = [string](Get-WacDeploymentFileHash `
            -Path (Get-WacDeploymentManifestPath -DeploymentRoot $slots.Staging))
    if ([string]::IsNullOrWhiteSpace($transaction.ReplacementManifestHash)) {
        throw ("The staged deployment's manifest could not be hashed, so the swap could not record what it was about to put live: {0}" -f $slots.Staging)
    }

    if ($transaction.HadOriginal) {
        # Read while the original is still at the root. After the swap nothing at this path
        # describes it any more, and a rollback that cannot say what it put back has not proven it.
        $original = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root
        $transaction.OriginalKind = [string]$original.Kind
        $transaction.OriginalVersion = [string]$original.Version
        $transaction.OriginalTampered = [bool]$original.Tampered
    }

    if ([string]::Equals($originalState, 'Substantive', [System.StringComparison]::Ordinal)) {
        # And its CONTENT identity, which kind and version are not: two builds of 1.2.0 agree on
        # both and each carries its own self-consistent manifest (ledger WAC-02R). Taken here
        # because this is the last moment the original is at a path anything can name. Refusing on
        # a tree that cannot be inventoried costs only the staged copy - nothing has moved yet -
        # whereas swapping it out would leave a rollback with nothing to compare what it restores to.
        $inventory = Get-WacDeploymentFingerprint -DeploymentRoot $slots.Root
        if (-not $inventory.Complete) {
            throw ("The deployment about to be replaced could not be inventoried, so a rollback could not prove what it put back: {0}" -f [string]$inventory.Reason)
        }
        $transaction.OriginalFingerprint = [string]$inventory.Fingerprint
        $transaction.OriginalFileCount = [int]$inventory.FileCount
    }

    $script:DeploymentTransaction = $transaction

    # Durable BEFORE the first move, and mandatory. A $script: record dies with its process, so a
    # run killed mid-swap leaves the next one unable to tell an original from a replacement - and
    # refusing here costs only the staged copy, because nothing has moved yet.
    if (-not (Save-WacDeploymentJournal -Transaction $transaction -Stage 'Staged')) {
        throw ("The deployment transaction could not be recorded, so the swap was not started: {0}" -f
            [string](Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root))
    }

    if ($transaction.HadOriginal) {
        Move-WacDeploymentSlot -From $slots.Root -To $slots.Previous
        $transaction.OriginalMovedAside = $true
        [void](Save-WacDeploymentJournal -Transaction $transaction -Stage 'OriginalMovedAside')
    }

    try {
        Move-WacDeploymentSlot -From $slots.Staging -To $slots.Root
        $transaction.ReplacementLive = $true

        # A stage update, no longer the write that carries the identity - that one landed before the
        # move. So its failure costs the reader a detail rather than the ability to attribute the
        # tree, and it stays non-fatal: the caller is inside its rollback try, and throwing here
        # would undo a good swap over a failed log line.
        if (-not (Save-WacDeploymentJournal -Transaction $transaction -Stage 'ReplacementLive')) {
            Write-WacLog -Level WARNING -Component 'Deploy' -Message 'The deployment transaction record could not be updated to say the replacement is live; the identity it recorded before the move still stands.' -Data @{
                path = [string](Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root)
            }
        }
    }
    catch {
        # Captured before the nested catch below can rebind $_ in this same scope.
        $failure = $_
        if ($transaction.OriginalMovedAside) {
            try {
                Move-WacDeploymentSlot -From $slots.Previous -To $slots.Root
                $transaction.OriginalMovedAside = $false
                $transaction.OriginalRestored = $true
                # The original is back and the slot is empty, so there is no longer an unfinished
                # swap for a later process to reconcile. A restore that FAILED keeps its record: it
                # is the only thing that can tell that process which tree is which.
                [void](Remove-WacDeploymentJournal -DeploymentRoot $slots.Root)
            }
            catch { Write-WacLog -Level CRITICAL -Component 'Deploy' -Message 'The previous deployment could not be restored.' -Data @{ previous = $slots.Previous; root = $slots.Root } }
        }
        throw ("The staging directory could not be swapped into place: {0}" -f $failure.Exception.Message)
    }

    $keptPrevious = $false
    if ($KeepPrevious) {
        $keptPrevious = [bool]$transaction.OriginalMovedAside
    }
    else {
        if ($transaction.OriginalMovedAside) {
            $discarded = Remove-WacDeployment -Path $slots.Previous
            if ($discarded.Removed) {
                $transaction.OriginalMovedAside = $false
            }
            else {
                # The new deployment is already live, so this is untidy rather than fatal.
                Write-WacLog -Level WARNING -Component 'Deploy' -Message 'The previous deployment could not be deleted.' -Data @{ path = $slots.Previous; reason = $discarded.Reason }
            }
        }

        # Without -KeepPrevious the caller has said it will not roll back, and the original has just
        # been discarded, so there is nothing left to restore. Forgetting the transaction is what
        # stops a rollback that arrives anyway from deleting a live deployment it cannot replace -
        # and the durable record has to go with it, for the same reason and for the next process.
        $script:DeploymentTransaction = $null
        [void](Remove-WacDeploymentJournal -DeploymentRoot $slots.Root)
    }

    # Throwing here is deliberate and the caller must be inside its rollback try: a deployment whose
    # contents cannot be enumerated is one nothing can verify, manifest or later delete, and it has
    # just gone live.
    $walk = Get-WacDeploymentItem -Root $slots.Root
    if (-not $walk.Complete) {
        throw ("The deployment that was switched into place could not be fully enumerated: {0}" -f
            ((@($walk.Failure | ForEach-Object { '{0}: {1}' -f $_.Path, $_.Reason }) | Select-Object -First 3) -join '; '))
    }

    $fileCount = @($walk.Entry | Where-Object { -not $_.IsDirectory }).Count
    Write-WacLog -Level INFO -Component 'Deploy' -Message 'Deployment switched into place.' -Data @{ root = $slots.Root; files = $fileCount; previousKept = $keptPrevious }

    return [PSCustomObject]@{
        DeploymentRoot = $slots.Root
        RunScript = (Join-Path -Path $slots.Root -ChildPath 'Run.ps1')
        FileCount = $fileCount
        PreviousKept = $keptPrevious
    }
}

function Remove-WacDeploymentReplacement {
    <#
    .SYNOPSIS
        Removes the tree a switch put live, but only once it is PROVEN to be that tree and only once
        what it replaced can still be put back.
    .DESCRIPTION
        "Can still be put back" used to mean only that a directory existed at the recovery slot
        (ledger WAC-02R). That is the same weak test the startup path had already outgrown: the slot
        is proven ours, substantive and trusted, and corroborated against the inventory taken before
        the first move, only AFTER it has been promoted - by which point the replacement is already
        deleted and refusing costs the machine its deployment. The in-process twin now asks the same
        questions in the same order the startup path does, BEFORE it deletes anything, so an altered
        or untrusted slot keeps the live tree instead of taking both.
    .OUTPUTS
        Removed and Reason.
    #>
    param([Parameter(Mandatory = $true)]$Transaction)

    $result = [PSCustomObject]@{ Removed = $false; Reason = $null }

    if (-not (Test-Path -LiteralPath $Transaction.Root -PathType Container)) {
        $Transaction.ReplacementLive = $false
        $result.Removed = $true
        $result.Reason = 'Nothing stands at the deployment root.'
        return $result
    }

    $live = Get-WacDeploymentFileHash -Path (Get-WacDeploymentManifestPath -DeploymentRoot $Transaction.Root)
    if ([string]::IsNullOrWhiteSpace([string]$Transaction.ReplacementManifestHash) -or
        [string]::IsNullOrWhiteSpace([string]$live) -or
        -not [string]::Equals([string]$live, [string]$Transaction.ReplacementManifestHash, [System.StringComparison]::OrdinalIgnoreCase)) {
        $result.Reason = 'What stands at the deployment root is not the tree this run switched into place, so it was left exactly as found.'
        Write-WacLog -Level CRITICAL -Component 'Deploy' -Message 'Rollback refused to delete a deployment it cannot prove this run installed.' -Data @{ root = $Transaction.Root }
        return $result
    }

    # Proven before the delete, never after it. Removing the replacement first and only then finding
    # there is nothing to put back is how a rollback leaves a machine with no deployment at all.
    if ($Transaction.HadOriginal) {
        $slot = Test-WacDeploymentRecoverySlotIsRestorable -Transaction $Transaction
        if (-not $slot.Restorable) {
            $result.Reason = [string]$slot.Reason
            Write-WacLog -Level CRITICAL -Component 'Deploy' -Message 'Rollback kept the new deployment because the one it replaced could not be vouched for.' -Data @{
                root = $Transaction.Root; previous = $Transaction.Previous; reason = [string]$slot.Reason
            }
            return $result
        }
    }

    $removed = Remove-WacDeployment -Path $Transaction.Root
    if (-not $removed.Removed) {
        $result.Reason = ('The new deployment could not be removed, so the previous one was not restored: {0}' -f [string]$removed.Reason)
        return $result
    }

    $Transaction.ReplacementLive = $false
    $result.Removed = $true
    return $result
}

function Restore-WacDeploymentPrevious {
    <#
    .SYNOPSIS
        Undoes the switch this process recorded: discards the replacement it put live and puts the
        original back. Idempotent.
    .DESCRIPTION
        The ONE owner of deployment rollback, and it reads the transaction Switch-WacDeploymentStage
        recorded before its first move. It infers nothing from the presence or absence of .previous,
        because that absence has two opposite meanings - there was no original, or the switch has
        already put the original back - and acting on the wrong one deletes the machine's
        installation and calls it a successful rollback.

        Every refusal keeps what is on disk. A tree that cannot be proven to be this run's
        replacement, an original that is no longer in the recovery slot, a removal that failed: each
        leaves the live deployment alone and says why. A second call after a successful one changes
        nothing, so the installer may roll back once per failure without counting.
    .OUTPUTS
        Restored, HadPrevious, Reason.
    #>
    [CmdletBinding()]
    param()

    $result = [PSCustomObject]@{ Restored = $false; HadPrevious = $false; Reason = $null }

    $transaction = $script:DeploymentTransaction
    if (-not $transaction) {
        $result.Restored = $true
        $result.Reason = 'No deployment switch is in flight, so there was nothing to undo and nothing was removed.'
        return $result
    }

    if ([bool]$transaction.Committed) {
        $result.Reason = 'This generation is committed; a late rollback cannot remove it.'
        return $result
    }
    $result.HadPrevious = [bool]$transaction.HadOriginal

    # OriginalRestored means the tree is back where it belongs; RestoreVerdict carries the reason it
    # is nonetheless not a clean rollback. A second call cannot improve either, so it repeats the
    # same answer rather than starting over on a machine that is already in its final state.
    if ($transaction.OriginalRestored) {
        $result.Restored = [string]::IsNullOrEmpty([string]$transaction.RestoreVerdict)
        $result.Reason = if ($result.Restored) { 'The switch had already been undone, so nothing was changed.' }
            else { [string]$transaction.RestoreVerdict }
        return $result
    }

    if (-not $transaction.ReplacementLive -and -not $transaction.OriginalMovedAside) {
        $transaction.OriginalRestored = $true
        [void](Remove-WacDeploymentJournal -DeploymentRoot $transaction.Root)
        $result.Restored = $true
        $result.Reason = 'The switch failed before anything moved, so the deployment was never changed.'
        return $result
    }

    if ($transaction.ReplacementLive) {
        $removal = Remove-WacDeploymentReplacement -Transaction $transaction
        if (-not $removal.Removed) {
            $result.Reason = [string]$removal.Reason
            return $result
        }
    }

    if (-not $transaction.HadOriginal) {
        $transaction.OriginalRestored = $true
        [void](Remove-WacDeploymentJournal -DeploymentRoot $transaction.Root)
        $result.Restored = $true
        $result.Reason = 'There was no previous deployment; the one this run installed was removed.'
        return $result
    }

    try {
        Move-WacDeploymentSlot -From $transaction.Previous -To $transaction.Root
        $transaction.OriginalMovedAside = $false
    }
    catch {
        $result.Reason = ('The previous deployment could not be restored: {0}' -f $_.Exception.Message)
        return $result
    }

    # Identity and content, not merely a directory at the right path. The tree that comes back has
    # to read as the same KIND of deployment, carry the same version, not have stopped matching its
    # own manifest between the two moves - and hash, file for file, to the inventory taken before
    # the first move. The first three are kept ahead of the fourth because they say WHICH WAY a tree
    # differs; the inventory is what catches the case none of them can, a different build of the
    # same version whose own manifest agrees with it perfectly (ledger WAC-02R).
    $back = Get-WacDeploymentOwnership -DeploymentRoot $transaction.Root
    $transaction.OriginalRestored = $true
    if (-not [string]::Equals([string]$back.Kind, [string]$transaction.OriginalKind, [System.StringComparison]::Ordinal)) {
        $transaction.RestoreVerdict = ('The tree put back at the deployment root reads as {0} where the one this run replaced was {1}: {2}' -f
            [string]$back.Kind, [string]$transaction.OriginalKind, [string]$back.Reason)
    }
    elseif (-not [string]::Equals([string]$back.Version, [string]$transaction.OriginalVersion, [System.StringComparison]::Ordinal)) {
        $transaction.RestoreVerdict = ('The tree put back at the deployment root is version {0} where the one this run replaced was version {1}.' -f
            [string]$back.Version, [string]$transaction.OriginalVersion)
    }
    elseif ($back.Tampered -and -not $transaction.OriginalTampered) {
        $transaction.RestoreVerdict = ('The tree put back at the deployment root no longer matches its own manifest: {0}' -f [string]$back.Reason)
    }
    else {
        # Through the same comparison the recovery path uses, which is what keeps an EMPTY original
        # - a shape that has no fingerprint because it has no files - provable rather than a tree
        # "that could not be inventoried".
        $corroboration = Test-WacRecoverySlotMatchesRecord -Path $transaction.Root -Record ([PSCustomObject]@{
            OriginalState = [string]$transaction.OriginalState
            OriginalFingerprint = [string]$transaction.OriginalFingerprint
        })
        if (-not $corroboration.Matches) {
            $transaction.RestoreVerdict = ('The tree put back at the deployment root is not the one this run moved aside: {0}' -f [string]$corroboration.Reason)
        }
    }

    if ($transaction.RestoreVerdict) {
        $result.Reason = [string]$transaction.RestoreVerdict
        return $result
    }

    # The swap is undone and proven undone, so the transaction is over for every later process too.
    [void](Remove-WacDeploymentJournal -DeploymentRoot $transaction.Root)

    $result.Restored = $true
    $result.Reason = ('The previous deployment was restored and verified: {0}' -f [string]$back.Reason)
    return $result
}

function Remove-WacDeploymentPrevious {
    <#
    .SYNOPSIS
        Discards the kept previous deployment once the new one is registered and verified.
    .DESCRIPTION
        This is the commit point, so the transaction ends here whether or not the old tree could be
        deleted. Leaving it recorded would let a rollback arriving afterwards delete the deployment
        this run has just proven good.

        The caller reaches this only once the replacement verified, the task registered and every
        read-back passed, which is what makes discarding the recovery copy safe at all - and the
        durable record is ended FIRST. While that file exists a later run reads the swap as
        unfinished, so a crash between the two deletions would leave the next install rolling back
        an installation this one committed. The other order has no such failure.
    #>
    [CmdletBinding()]
    param()

    $slots = Get-WacDeploymentSlotPath
    if (-not $slots) { return $false }

    # The task capture depends on the commit decision. Retire it FIRST; a crash or a sharing
    # violation must never leave an old capture without the decision that superseded it.
    if (-not (Remove-WacTaskCaptureRecord -DeploymentRoot $slots.Root)) {
        Write-WacLog -Level CRITICAL -Component 'Deploy' -Message 'The committed task capture could not be retired; the commit decision and recovery copy were kept.'
        return $false
    }

    $script:DeploymentTransaction = $null

    $ended = Remove-WacDeploymentJournal -DeploymentRoot $slots.Root
    if (-not $ended) {
        Write-WacLog -Level CRITICAL -Component 'Deploy' -Message 'This install is committed but its transaction record could not be deleted; a later run may read the committed swap as unfinished. Delete it by hand.' -Data @{
            path = [string](Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root)
        }
    }

    if (-not (Test-Path -LiteralPath $slots.Previous)) { return $ended }

    # The old tree failing to delete is untidy, not unfinished: nothing reads it once the record is
    # gone, and the next run's plan discards it as a superseded copy beside a healthy deployment.
    # The RECORD is the one that changes what a later run believes, so it alone decides the answer -
    # the caller reports an install whose transaction outlived it as incomplete, and would otherwise
    # be reporting that over a locked directory.
    $discarded = Remove-WacDeployment -Path $slots.Previous
    if (-not $discarded.Removed) {
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'The previous deployment could not be deleted.' -Data @{ path = $slots.Previous; reason = [string]$discarded.Reason }
    }
    return $ended
}

function Install-WacDeployment {
    <#
    .SYNOPSIS
        Stage-and-switch in one call, discarding the previous tree. The installer uses the two phases
        separately so it can verify and roll back between them.
    .OUTPUTS
        DeploymentRoot, RunScript, FileCount.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SourceRoot)

    # The file half of any outstanding recovery, first - the same order the installer performs it in
    # since ledger WAC-02R, and the reason this one call still equals the two phases the installer
    # runs separately. It used to be New-WacDeploymentStage's own first act.
    [void](Resolve-WacDeploymentRecoverySlot -Slots (Get-WacDeploymentSlotPath))

    [void](New-WacDeploymentStage -SourceRoot $SourceRoot)
    $switched = Switch-WacDeploymentStage

    return [PSCustomObject]@{
        DeploymentRoot = $switched.DeploymentRoot
        RunScript = $switched.RunScript
        FileCount = $switched.FileCount
    }
}

Export-ModuleMember -Function @(
    'Get-WacTaskName', 'Get-WacTaskFolder', 'Get-WacTaskSentinel', 'Get-WacTaskDescription',
    'Get-WacOperationLockName', 'Get-WacDeploymentVersion', 'Get-WacDeploymentProjectId',
    'Get-WacDeploymentManifestPath', 'New-WacDeploymentManifest', 'Read-WacDeploymentManifest',
    'Get-WacDeploymentFileHash', 'Get-WacDeploymentOwnership', 'Get-WacDeploymentFingerprint',
    'Get-WacDeploymentJournalPath', 'Read-WacDeploymentJournal', 'Test-WacRecoverySlotMatchesRecord',
    'Get-WacDeploymentGeneration', 'Get-WacDeploymentRecoveryPlan', 'Remove-WacDeploymentJournal',
    'Write-WacTaskCaptureRecord', 'Read-WacTaskCaptureRecord', 'Remove-WacTaskCaptureRecord',
    'Test-WacIsExcludedDeploymentName', 'Get-WacDeploymentItem', 'Copy-WacDeploymentTree',
    'Get-WacDeploymentSlotPath', 'Install-WacDeployment', 'Remove-WacDeployment',
    'New-WacDeploymentStage', 'Switch-WacDeploymentStage', 'Resolve-WacDeploymentRecoverySlot',
    'Set-WacDeploymentCommitted', 'Set-WacRecoveryTaskAcknowledgement', 'Get-WacJournalField',
    'Restore-WacDeploymentPrevious', 'Remove-WacDeploymentPrevious',
    'Test-WacDeploymentTrusted',
    'Get-WacTaskScriptPath', 'Get-WacLegacyTaskScriptPath', 'Test-WacTaskExecuteIsCanonicalHost',
    'Get-WacInstalledTask', 'Test-WacTaskIsOurs', 'Test-WacTaskReferencesRoot', 'Remove-WacInstalledTask',
    'Test-WacCapturedTaskDefinition',
    'Get-WacInstallerRelaunchArgument', 'Get-WacTaskActionArgument', 'Get-WacTaskActionArgumentCandidate'
)
