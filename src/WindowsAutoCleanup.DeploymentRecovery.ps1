<#
.SYNOPSIS
    The ONE commit decision an interrupted deployment generation gets, and the file half of carrying
    it out.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Deploy.psm1; see that file for why the parts are dot-sourced
    rather than imported. Split out of it because that file had reached the size at which nobody
    reads it, and because this is one responsibility: deciding what an earlier run's leftovers mean
    and putting the tree back on that decision.

    Ledger WAC-02R. The defect this file exists to close: the swap record and the task-capture
    record were reconciled INDEPENDENTLY, by two different pieces of code, each reaching its own
    conclusion from its own half of the evidence. Files A with task A, upgraded to files B with task
    B and interrupted before the commit, gave the task half "something with that name is registered,
    so the capture is accounted for - delete it" and the file half "the swap never committed, so put
    files A back". The machine ended with files A under task B and no record that task A had ever
    existed. Two individually durable records are not an atomic pair.

    Get-WacDeploymentRecoveryPlan is the fix. It reads BOTH records and the disk, and returns ONE
    verdict for the generation. Resolve-WacDeploymentRecoverySlot carries out the FILE half of that
    verdict; Resolve-InterruptedTaskCapture in the installer carries out the TASK half of the same
    one. Neither may reach its own conclusion, and the task half runs FIRST - it needs the tree the
    restored registration points into to still be the tree that was there when the registration was
    taken away.

    The plan is derived rather than passed between the two halves, because deriving it twice over an
    unchanged filesystem is deterministic and passing it would let a caller hand the file half a
    verdict the disk no longer supports. Registering a task changes nothing either half reads.
#>

function Get-WacDeploymentRecoveryPathState {
    <#
    .SYNOPSIS
        What is at a slot path, as THREE answers: Directory, Absent or Unreadable.
    .DESCRIPTION
        Test-Path -PathType Container answers $false for a FILE standing at the slot's name, for a
        dangling link and for a probe the filesystem refused, and the recovery path used to read
        every one of those as "there is no recovery slot" - and then delete the swap record that was
        the only evidence a transaction had been in flight.
    .OUTPUTS
        State and Reason.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path)

    $result = [PSCustomObject]@{ State = 'Unreadable'; Reason = '' }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $result.Reason = 'the recovery slot path could not be resolved'
        return $result
    }

    try {
        if ([System.IO.Directory]::Exists($Path)) {
            $result.State = 'Directory'
            $result.Reason = 'a recovery slot is present'
            return $result
        }
        if ([System.IO.File]::Exists($Path)) {
            $result.Reason = 'a file stands where the recovery slot should be'
            return $result
        }

        $parent = [System.IO.Path]::GetDirectoryName($Path)
        if ([string]::IsNullOrWhiteSpace($parent) -or -not [System.IO.Directory]::Exists($parent)) {
            $result.Reason = 'the directory the recovery slot would live in could not be read'
            return $result
        }
        [void][System.IO.Directory]::GetFileSystemEntries($parent, [System.IO.Path]::GetFileName($Path))
    }
    catch {
        $result.Reason = ('the recovery slot path could not be inspected: {0}' -f $_.Exception.Message)
        return $result
    }

    $result.State = 'Absent'
    $result.Reason = 'no recovery slot is present'
    return $result
}

function Test-WacDeploymentIsRecordedReplacement {
    <#
    .SYNOPSIS
        Whether the tree at the deployment root is the one the swap record says was moved in.
    .DESCRIPTION
        The manifest hashes every staged file and the moment it was written, so it identifies one
        particular build - which the project id, the name and the layout do not, because the tree
        that was moved ASIDE carries all three.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [AllowNull()]$Record
    )

    $recorded = [string](Get-WacJournalField -Record $Record -Name 'ReplacementManifestHash')
    if ([string]::IsNullOrWhiteSpace($recorded)) { return $false }

    $live = [string](Get-WacDeploymentFileHash -Path (Get-WacDeploymentManifestPath -DeploymentRoot $Root))
    if ([string]::IsNullOrWhiteSpace($live)) { return $false }

    return [string]::Equals($live, $recorded, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-WacDeploymentRecoveryPlan {
    <#
    .SYNOPSIS
        The single commit decision an interrupted generation gets, read off both durable records and
        the disk, for both halves of the transaction to act on.
    .DESCRIPTION
        Four verdicts, and each one says what happens to the files AND what happens to the captured
        registrations:

          None              - nothing an earlier run left is outstanding. A capture record, if there
                              is one, belongs to no swap and is resolved on its own terms.
          RestoreOriginal   - a swap that never committed. The tree goes back to what was moved
                              aside, so the registration that was taken away has to go back with it.
          CommitReplacement - the tree this generation installed is live and verified and nothing is
                              outstanding but the leftovers. The recovery copy is superseded, and so
                              is the capture of the registration the new one replaced.
          Refuse            - anything that cannot be read, or that both halves cannot be made
                              coherent over. Nothing is touched and nothing is deleted.

        Linked says whether the two records carry the same generation id. It gates exactly one
        decision - retiring a capture whose task is no longer the registered one - because that is
        the only place where believing two separate files describe one transaction can destroy
        evidence. A record written before generation ids existed carries none and is never linked,
        so an old pair is reconciled conservatively rather than assumed.
    .OUTPUTS
        Verdict, Reason, Slots, Swap, Capture, Linked, SlotState, Promotable, Corroboration, Live.
    #>
    [CmdletBinding()]
    param([string]$DeploymentRoot)

    $slots = Get-WacDeploymentSlotPath -DeploymentRoot $DeploymentRoot
    $plan = [PSCustomObject]@{
        Verdict = 'Refuse'
        Reason = 'The deployment root could not be resolved.'
        Slots = $slots
        Swap = $null
        Capture = $null
        Linked = $false
        SlotState = 'Unreadable'
        Promotable = $null
        Corroboration = $null
        Live = $null
    }
    if (-not $slots) { return $plan }

    $swap = Read-WacDeploymentJournal -DeploymentRoot $slots.Root
    $capture = Read-WacTaskCaptureRecord -DeploymentRoot $slots.Root
    $plan.Swap = $swap
    $plan.Capture = $capture
    $plan.Linked = (-not [string]::IsNullOrWhiteSpace([string]$swap.Generation)) -and
        [string]::Equals([string]$swap.Generation, [string]$capture.Generation, [System.StringComparison]::OrdinalIgnoreCase)

    # UNKNOWN IS NOT ABSENT, for either half. A torn, foreign or partly decodable record means a
    # transaction may have been in flight and its shape cannot be read; treating that as "nothing
    # happened" is what let a healthy-looking tree authorise deleting the only good previous copy.
    if ([string]$swap.State -ceq 'Unreadable') {
        $plan.Reason = ('A deployment transaction record is present but could not be read: {0}' -f [string]$swap.Reason)
        return $plan
    }
    if ([string]$capture.State -ceq 'Unreadable') {
        $plan.Reason = ('A task-capture record from an earlier run is present but could not be read, so whether this machine is missing a scheduled task is unknown: {0}' -f [string]$capture.Reason)
        return $plan
    }

    $slotProbe = Get-WacDeploymentRecoveryPathState -Path $slots.Previous
    $plan.SlotState = [string]$slotProbe.State
    if ([string]$slotProbe.State -ceq 'Unreadable') {
        $plan.Reason = ('The recovery slot of an earlier run could not be inspected, so neither the deployment nor its recovery copy was touched: {0} ({1})' -f
            $slots.Previous, [string]$slotProbe.Reason)
        return $plan
    }

    $plan.Live = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root

    if ([string]$slotProbe.State -cne 'Directory') {
        return (Resolve-WacPlanWithoutSlot -Plan $plan)
    }

    return (Resolve-WacPlanWithSlot -Plan $plan)
}

function Resolve-WacPlanWithoutSlot {
    <#
    .SYNOPSIS
        The verdict when the recovery slot is PROVEN absent.
    .DESCRIPTION
        Recovery used to delete the swap record outright here, on the grounds that there is nothing
        left to put back - which is true and is not the point (ledger WAC-02R). The record also says
        whether the tree standing at the root ever committed, and a first install that got as far as
        moving its tree in and no further left exactly this shape: no recovery slot, because there
        was nothing to move aside, and an open transaction that deleting the record would bury.
    #>
    param([Parameter(Mandatory = $true)]$Plan)

    if ([string]$Plan.Swap.State -cne 'Valid') {
        $Plan.Verdict = 'None'
        $Plan.Reason = 'There was no recovery slot to reconcile.'
        return $Plan
    }

    $root = [string]$Plan.Slots.Root
    if (Test-WacDeploymentIsRecordedReplacement -Root $root -Record $Plan.Swap.Record) {
        # The swap reached the point where its replacement went live, and there is no copy of what
        # it replaced. What stands at the root IS this generation's deployment, so the transaction
        # is over in substance and the leftovers may be retired.
        $Plan.Verdict = 'CommitReplacement'
        $Plan.Reason = 'An earlier run put its replacement live and left no recovery copy, so the deployment at the root is that replacement and its transaction is over.'
        return $Plan
    }

    $state = [string](Get-WacJournalField -Record $Plan.Swap.Record -Name 'OriginalState')
    $movedAside = -not ([string]::Equals($state, 'Absent', [System.StringComparison]::Ordinal))
    if ($movedAside) {
        $Plan.Reason = ('A deployment transaction record describes a swap whose recovery copy is no longer where it was put, and what stands at the deployment root is not the replacement that record names: {0}' -f $root)
        return $Plan
    }

    # The record names nothing that was moved aside, so no copy is missing. If the root is empty or
    # gone the swap never got its replacement in, and there is nothing left of that attempt.
    if ((-not $Plan.Live.Exists) -or ($Plan.Live.IsOurs -and $Plan.Live.IsEmpty)) {
        $Plan.Verdict = 'CommitReplacement'
        $Plan.Reason = 'An earlier first install moved nothing aside and never got its own tree in place, so there is nothing of it left to reconcile.'
        return $Plan
    }

    $Plan.Reason = ('A deployment transaction record describes a first install whose outcome the tree at the deployment root does not confirm: {0}' -f $root)
    return $Plan
}

function Resolve-WacPlanWithSlot {
    <#
    .SYNOPSIS
        The verdict when a recovery slot from an earlier run is standing there.
    .DESCRIPTION
        Clearing that slot is safe only once the tree that replaced it is a COMMITTED, verified
        deployment. "The root is ours" is not that test and never was: an empty directory is
        deliberately adopted as ours, and so is a managed tree three of whose files no longer match
        the manifest, so an interrupted or broken install could talk this into deleting the last
        good copy on the machine.

        Promotion is never a bare Directory.Move either: what comes out of the slot becomes what
        SYSTEM executes, so it is proven ours, substantive and trusted first - and then corroborated
        against the inventory the durable record took of it before the swap, because a slot that is
        ours, healthy and trusted but REWRITTEN since is none of the things the record describes.
    #>
    param([Parameter(Mandatory = $true)]$Plan)

    $slots = $Plan.Slots
    $journal = $Plan.Swap.Record
    $live = $Plan.Live

    $promotable = Test-WacRecoverySlotIsPromotable -Path $slots.Previous
    $corroboration = Test-WacRecoverySlotMatchesRecord -Path $slots.Previous -Record $journal
    $Plan.Promotable = $promotable
    $Plan.Corroboration = $corroboration

    # ONE comparison, read by BOTH promotion branches. It used to be computed only for the
    # "interrupted" determination, so the branch below promoted whatever stood in the slot with no
    # content check at all.
    $interrupted = ($promotable.Promotable -and [bool]$corroboration.Corroborated)

    if ((-not $live.Exists) -or ($live.IsOurs -and $live.IsEmpty)) {
        # The slot holds the only installation left on the machine.
        if (-not $promotable.Promotable) {
            # An empty original is the one shape that is legitimately not promotable: there is no
            # Run.ps1 in it because there never was one. Nothing is lost by discarding it.
            if ([bool]$corroboration.Corroborated -and
                [string]::Equals([string](Get-WacJournalField -Record $journal -Name 'OriginalState'), 'Empty', [System.StringComparison]::Ordinal)) {
                $Plan.Verdict = 'CommitReplacement'
                $Plan.Reason = 'The recovery slot holds the empty directory an earlier run moved aside, which is nothing to put back.'
                return $Plan
            }

            $Plan.Reason = ('A recovery slot from an earlier run is still present and could not be put back, so nothing was touched: {0} ({1})' -f
                $slots.Previous, [string]$promotable.Reason)
            return $Plan
        }

        # Matches is TRUE when no record names a fingerprint - there is then nothing to corroborate
        # against and the provenance checks stand alone. It is FALSE only when a record does name
        # one and the slot no longer answers to it, and that is a slot nothing can vouch for.
        if (-not $corroboration.Matches) {
            $Plan.Reason = ('A recovery slot from an earlier run is still present and no longer matches the durable record of what was moved aside, so nothing was touched: {0} ({1})' -f
                $slots.Previous, [string]$corroboration.Reason)
            return $Plan
        }

        $Plan.Verdict = 'RestoreOriginal'
        $Plan.Reason = 'The deployment root held nothing of its own, so the recovery slot held the only installation on this machine and was put back.'
        return $Plan
    }

    if ($interrupted -and (Test-WacDeploymentIsRecordedReplacement -Root $slots.Root -Record $journal)) {
        $Plan.Verdict = 'RestoreOriginal'
        $Plan.Reason = 'An earlier run was interrupted after the swap and before it committed, so its replacement is discarded and the deployment it replaced is put back.'
        return $Plan
    }

    if ($live.IsHealthy -and -not $interrupted) {
        $Plan.Verdict = 'CommitReplacement'
        $Plan.Reason = 'The recovery slot holds a superseded copy while a verified deployment of ours is live, so it is discarded.'
        return $Plan
    }

    if (-not $live.IsOurs) {
        $Plan.Reason = ('A recovery slot from an earlier run is still present and what stands at the deployment root cannot be proven ours, so neither was touched: {0} ({1})' -f
            $slots.Previous, [string]$live.Reason)
        return $Plan
    }

    $Plan.Reason = ('A recovery slot from an earlier run is still present and what stands at the deployment root is not a verified replacement for it, so neither was touched: {0} ({1})' -f
        $slots.Previous, [string]$live.Reason)
    return $Plan
}

function Resolve-WacDeploymentRecoverySlot {
    <#
    .SYNOPSIS
        Carries out the FILE half of the recovery plan, BEFORE a new stage would clear anything.
    .DESCRIPTION
        The decision is not made here - Get-WacDeploymentRecoveryPlan makes it once for both halves
        of the generation, and this executes the part of it that moves directories. A Refuse throws,
        because staging is a deletion and the one shape in which guessing costs the operator both
        trees is exactly this one.

        The task half has already run by the time this is reached (the installer reconciles
        registrations before it stages), so a restore here puts the tree back under a registration
        that is already pointing at it rather than the other way round.
    .OUTPUTS
        Action (None, Restored or Discarded), Reason and Plan.
    #>
    param([Parameter(Mandatory = $true)]$Slots)

    $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $Slots.Root
    $result = [PSCustomObject]@{ Action = 'None'; Reason = [string]$plan.Reason; Plan = $plan }

    if ([string]$plan.Verdict -ceq 'Refuse') { throw ([string]$plan.Reason) }

    if ([string]$plan.Verdict -ceq 'None') {
        $result.Reason = 'There was no recovery slot to reconcile.'
        return $result
    }

    if ([string]$plan.Verdict -ceq 'RestoreOriginal') {
        if ($plan.Live.Exists) {
            # Proven promotable BEFORE the delete, never after it: removing what is at the root
            # first and only then finding nothing may take its place is how a recovery leaves a
            # machine bare. The plan has already proven the slot promotable and corroborated.
            $emptied = Remove-WacDeployment -Path $Slots.Root
            if (-not $emptied.Removed) {
                throw ("What stands at the deployment root could not be cleared, so the recovery slot was left where it is: {0} ({1})" -f
                    $Slots.Root, [string]$emptied.Reason)
            }
        }

        Move-WacDeploymentSlot -From $Slots.Previous -To $Slots.Root
        $result.Action = 'Restored'
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'An interrupted run left a deployment in the recovery slot; it was restored before staging.' -Data @{
            previous = $Slots.Previous; root = $Slots.Root; reason = [string]$plan.Reason
            corroborated = [bool](Test-WacPlanCorroborated -Plan $plan)
        }
    }
    else {
        if ([string]$plan.SlotState -ceq 'Directory') {
            $cleared = Remove-WacDeployment -Path $Slots.Previous
            if (-not $cleared.Removed) {
                throw ("A leftover deployment slot could not be cleared: {0} ({1})" -f $Slots.Previous, [string]$cleared.Reason)
            }
        }
        $result.Action = 'Discarded'
    }

    # The transaction is over either way, so its record goes - and a record that could not be
    # deleted is reported, never swallowed: the next run would read a settled state as unfinished.
    if (-not (Remove-WacDeploymentJournal -DeploymentRoot $Slots.Root)) {
        Write-WacLog -Level CRITICAL -Component 'Deploy' -Message 'A reconciled deployment transaction record could not be deleted; a later run may read a settled state as unfinished. Delete it by hand.' -Data @{
            path = [string](Get-WacDeploymentJournalPath -DeploymentRoot $Slots.Root)
        }
    }

    return $result
}

function Test-WacDeploymentRecoverySlotIsRestorable {
    <#
    .SYNOPSIS
        Whether the recovery slot this PROCESS filled can still be put back, asked before the
        replacement over it is deleted.
    .DESCRIPTION
        The in-process twin of the questions Get-WacDeploymentRecoveryPlan asks a slot an earlier
        process left: ours, substantive, trusted, and still hashing to the inventory taken before
        the first move. It runs through the very same comparison - Test-WacRecoverySlotMatchesRecord
        over a stand-in record built from the live transaction - so the two paths cannot drift into
        accepting different things.

        An EMPTY original is the one shape that is legitimately not promotable, because there is no
        Run.ps1 in it and never was. It still has to be there and still has to be empty.
    .OUTPUTS
        Restorable and Reason.
    #>
    param([Parameter(Mandatory = $true)]$Transaction)

    $result = [PSCustomObject]@{ Restorable = $false; Reason = $null }

    $probe = Get-WacDeploymentRecoveryPathState -Path $Transaction.Previous
    if ([string]$probe.State -cne 'Directory') {
        $result.Reason = ('The deployment this run replaced is no longer in the recovery slot, so removing what replaced it would leave this machine with nothing installed: {0}' -f [string]$probe.Reason)
        return $result
    }

    $state = [string]$Transaction.OriginalState
    if ([string]::IsNullOrWhiteSpace($state)) { $state = 'Substantive' }

    $stand = [PSCustomObject]@{
        OriginalState = $state
        OriginalFingerprint = [string]$Transaction.OriginalFingerprint
    }
    $corroboration = Test-WacRecoverySlotMatchesRecord -Path $Transaction.Previous -Record $stand
    if (-not $corroboration.Matches) {
        $result.Reason = ('The deployment this run replaced is no longer what it was when it was moved aside, so what replaced it was left in place: {0}' -f [string]$corroboration.Reason)
        return $result
    }

    if ([string]::Equals($state, 'Empty', [System.StringComparison]::Ordinal)) {
        $result.Restorable = $true
        $result.Reason = [string]$corroboration.Reason
        return $result
    }

    $promotable = Test-WacRecoverySlotIsPromotable -Path $Transaction.Previous
    if (-not $promotable.Promotable) {
        $result.Reason = ('The deployment this run replaced cannot be put back, so what replaced it was left in place: {0}' -f [string]$promotable.Reason)
        return $result
    }

    $result.Restorable = $true
    $result.Reason = [string]$corroboration.Reason
    return $result
}

function Test-WacPlanCorroborated {
    <#
    .SYNOPSIS
        Whether the plan's slot comparison had a record to corroborate against at all.
    #>
    param([Parameter(Mandatory = $true)]$Plan)

    if (-not $Plan.Corroboration) { return $false }
    return [bool]$Plan.Corroboration.Corroborated
}
