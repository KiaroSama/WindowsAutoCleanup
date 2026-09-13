<#
.SYNOPSIS
    The durable records a deployment operation leaves on disk: the swap transaction, the captured
    scheduled-task definitions, and the corroboration a recovery slot has to pass before promotion.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Deploy.psm1; see that file for why the parts are dot-sourced
    rather than imported. Split out of WindowsAutoCleanup.DeploymentProof.ps1, which answers a
    different question: that file proves what a TREE ON DISK is, while this one owns what an
    interrupted process LEFT BEHIND to say what it was in the middle of. The two were one file only
    because the swap record was born beside the manifest, and keeping them together would have
    pushed the proof file past the size at which nobody reads it. All parts share one session state,
    so no call and no $script: reference changes meaning by moving here.

    Two records, one shape and one reader. They are separate FILES because they have separate
    lifetimes: the swap record is rewritten at every stage of one Directory.Move pair, while the
    task-capture record has to outlive all of them - the machine can be missing a registration
    whatever the tree at the deployment root is doing. One file for both would have meant the swap's
    first write silently destroying the only evidence that a task had been unregistered.

    Neither record is ever believed on its own. Every action either one triggers is re-proven
    against the bytes on disk - a hash of the tree, or the scheduler's own answer about what is
    registered - so a stale, copied or hand-written record can start no deletion by itself.
#>

# WHAT THIS BUILD WRITES, and the oldest it can still ACT ON. Schema 2 added the task-capture record
# and its CapturedTask list; schema 1 is what every machine installed before this build has sitting
# beside its deployment.
#
# An exact-match test here is not conservatism, it is a self-inflicted outage: Read refuses anything
# it does not recognise, Resolve-WacDeploymentRecoverySlot THROWS on a refusal, and every installed
# machine carrying a schema-1 record would therefore refuse its own next upgrade. The window is the
# fix, and it is deliberately one-sided - older than the minimum is refused because this build no
# longer knows what those fields meant, and NEWER than what this build writes is refused because a
# later build's record may mean something this one cannot know. Guessing is the thing to refuse.
#
# Every field added at schema 2 is therefore read through Get-WacJournalField: absence has to read as
# "not recorded", never as an error, and Set-StrictMode -Version 2.0 makes a plain property read of a
# missing member terminating.
$script:DeploymentJournalSchema = 2
$script:DeploymentJournalMinSchema = 1

# The DURABLE half of the swap transaction (ledger WAC-02R). $script:DeploymentTransaction describes
# a swap the current process is in the middle of and dies with that process, so a run killed between
# the two moves leaves a machine whose only evidence is the directories themselves - and those
# cannot say whether the run that made them ever committed. This record is written beside the slots
# before the first move and deleted at the commit point, so its PRESENCE means "a swap started and
# did not finish".
$script:DeploymentJournalSuffix = '.transaction.json'

# The DURABLE half of the task-capture transaction (ledger WAC-02R). The installer unregisters the
# task an upgrade is about to replace and used to keep the captured definition ONLY in memory, so a
# process that died between that unregister and the swap left a machine with no registration and no
# record that one had ever existed. This record is written BEFORE the first unregister and deleted
# when the transaction ends, so its presence means "a task may be missing and its exact definition
# is in here".
$script:TaskCaptureJournalSuffix = '.taskcapture.json'

function Get-WacJournalField {
    <#
    .SYNOPSIS
        One optional field of a record read off disk, or $null when the record does not carry it.
    .DESCRIPTION
        The schema window means a record can legitimately be older than the fields this build knows
        about, and under Set-StrictMode -Version 2.0 reading a member an object does not have is a
        TERMINATING error rather than $null. Absence therefore has to be asked about rather than
        tripped over, or a schema-1 record would crash the very recovery the window exists to allow.
    #>
    param(
        [AllowNull()]$Record,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Record) { return $null }

    $names = @()
    try { $names = @($Record.PSObject.Properties.Name) } catch { return $null }
    if (-not ($names -ccontains $Name)) { return $null }

    try { return $Record.$Name } catch { return $null }
}

function Get-WacDeploymentJournalPath {
    <#
    .SYNOPSIS
        Where a durable record lives: beside the slots, never inside one, so no move or delete of a
        slot can carry it off with them.
    #>
    param(
        [string]$DeploymentRoot,
        [ValidateSet('Swap', 'TaskCapture')][string]$Kind = 'Swap'
    )

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }
    $root = Get-WacNormalizedPath -Path $DeploymentRoot
    if (-not $root) { return $null }

    if ($Kind -ceq 'TaskCapture') { return ($root + $script:TaskCaptureJournalSuffix) }
    return ($root + $script:DeploymentJournalSuffix)
}

function Write-WacDeploymentJournal {
    <#
    .SYNOPSIS
        Records one in-flight transaction. $false when it could not be written; what that costs is
        the caller's decision, not this function's.
    #>
    param(
        [Parameter(Mandatory = $true)]$Record,
        [string]$DeploymentRoot,
        [ValidateSet('Swap', 'TaskCapture')][string]$Kind = 'Swap'
    )

    $path = Get-WacDeploymentJournalPath -DeploymentRoot $DeploymentRoot -Kind $Kind
    if (-not $path) { return $false }

    # Never through a link. The record sits in an administrative directory, and writing through a
    # reparse point somebody else left at that name would write wherever they chose.
    #
    # Only when something is already THERE: Test-WacIsReparsePoint reads the attributes and fails
    # closed, so it answers true for a path that does not exist yet - which is every first write.
    if ((Test-Path -LiteralPath $path) -and (Test-WacIsReparsePoint -Path $path)) {
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'A deployment transaction record could not be written: a reparse point stands at its path.' -Data @{ path = $path }
        return $false
    }

    # WRITTEN BESIDE, THEN SWAPPED IN. Writing over the live record meant a crash mid-write left a
    # TORN file - and a torn record is worse than none, because it destroyed the last complete one
    # while looking like an answer. The temporary file absorbs a partial write; the swap is what the
    # next process ever sees, and the displaced record is kept as the previous complete one.
    $staging = $path + '.new'
    $previous = $path + '.last'

    try {
        [System.IO.File]::WriteAllText($staging, (ConvertTo-Json -InputObject $Record -Depth 5),
            (New-Object System.Text.UTF8Encoding($false)))

        if (Test-Path -LiteralPath $path -PathType Leaf) {
            # Replace keeps a copy of what it displaced, so a record that is later found unreadable
            # still has a complete predecessor to reconcile against.
            [System.IO.File]::Replace($staging, $path, $previous, $true)
        }
        else {
            [System.IO.File]::Move($staging, $path)
        }
        return $true
    }
    catch {
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'A deployment transaction record could not be written.' -Data @{ path = $path; error = $_.Exception.Message }
        try { if (Test-Path -LiteralPath $staging -PathType Leaf) { [System.IO.File]::Delete($staging) } } catch { $null = $_ }
        return $false
    }
}

function Read-WacDeploymentJournal {
    <#
    .SYNOPSIS
        The transaction an earlier PROCESS left behind, or nothing this run may act on.
    .DESCRIPTION
        Validated before it is handed back, because it comes off disk and a caller acts on it: a
        schema inside this build's window, our project id, and the deployment root it names has to be
        the root being reconciled. A record that fails any of those is not evidence about this
        machine, so it is discarded rather than half-believed - and one that passes still proves
        nothing on its own, because the caller re-hashes the trees it describes before touching
        either.
    .OUTPUTS
        State (Absent, Valid or Unreadable), Record, Schema and Reason.
    #>
    param(
        [string]$DeploymentRoot,
        [ValidateSet('Swap', 'TaskCapture')][string]$Kind = 'Swap'
    )

    $result = [PSCustomObject]@{ State = 'Absent'; Record = $null; Schema = 0; Reason = '' }

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }
    $expectedRoot = Get-WacNormalizedPath -Path $DeploymentRoot
    $path = Get-WacDeploymentJournalPath -DeploymentRoot $DeploymentRoot -Kind $Kind

    # THREE ANSWERS, NOT TWO. Absent, Valid and Unreadable are different facts and only one of them
    # is permission to act: "there was no transaction" can license discarding a recovery copy, while
    # "there is a record and it cannot be read" must never do so. Collapsing both to $null let a
    # torn or foreign record be read as "nothing happened here".
    if (-not $expectedRoot -or -not $path) {
        $result.State = 'Unreadable'
        $result.Reason = 'the transaction record path could not be resolved'
        return $result
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $result }
    if (Test-WacIsReparsePoint -Path $path) {
        $result.State = 'Unreadable'
        $result.Reason = 'a reparse point stands where the transaction record should be'
        return $result
    }

    $record = $null
    $failure = ''
    try { $record = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path)) }
    catch { $record = $null; $failure = [string]$_.Exception.Message }

    if (-not $record) {
        $result.State = 'Unreadable'
        $result.Reason = ('the transaction record could not be parsed: {0}' -f $failure).Trim()
        return $result
    }

    $schema = 0
    $projectId = ''
    $root = ''
    try { $schema = [int]$record.Schema } catch { $schema = 0 }
    try { $projectId = [string]$record.ProjectId } catch { $projectId = '' }
    try { $root = [string]$record.Root } catch { $root = '' }
    $result.Schema = $schema

    # The WINDOW, not equality: a record older than this build writes is still one this build knows
    # how to act on, down to the declared minimum. Newer than it writes is refused with everything
    # else, because a field a later build added may change what the fields here mean.
    if ($schema -lt $script:DeploymentJournalMinSchema -or $schema -gt $script:DeploymentJournalSchema -or
        -not [string]::Equals($projectId, $script:DeploymentProjectId, [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($root, $expectedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        # A record that is readable but describes something else is NOT absence either: something
        # wrote it, and guessing which deployment it belongs to is exactly the guess to refuse.
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'A deployment transaction record does not describe this deployment.' -Data @{
            path = $path; schema = $schema; root = $root
        }
        $result.State = 'Unreadable'
        $result.Reason = 'the transaction record does not describe this deployment'
        return $result
    }

    $result.State = 'Valid'
    $result.Record = $record
    return $result
}

function Remove-WacDeploymentJournal {
    <#
    .SYNOPSIS
        Ends a recorded transaction. Deleting this file is what says the transaction it describes is
        no longer in flight, so it happens at the commit point and after a completed rollback - never
        merely because one step succeeded.
    #>
    param(
        [string]$DeploymentRoot,
        [ValidateSet('Swap', 'TaskCapture')][string]$Kind = 'Swap'
    )

    $path = Get-WacDeploymentJournalPath -DeploymentRoot $DeploymentRoot -Kind $Kind
    if (-not $path) { return $false }
    if (-not (Test-Path -LiteralPath $path)) { return $true }

    try {
        [System.IO.File]::Delete((Get-WacLongPath -Path $path))
        return $true
    }
    catch {
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'A deployment transaction record could not be deleted.' -Data @{ path = $path; error = $_.Exception.Message }
        return $false
    }
}

# ---------------------------------------------------------------------------------------------
# The task-capture transaction
# ---------------------------------------------------------------------------------------------

function Write-WacTaskCaptureRecord {
    <#
    .SYNOPSIS
        Records the scheduled-task definitions an upgrade has captured but not yet replaced. $true
        only when the record is on disk.
    .DESCRIPTION
        Ledger WAC-02R. The unregister is what makes the machine lose a registration, so this write
        is what has to happen BEFORE it: the caller lets the unregister proceed only on $true, and on
        $false leaves the task registered. A machine left exactly as it was found is strictly better
        than one missing a task nothing on it can describe.

        Called once per captured task and given every capture so far, because the record grows with
        each one and a record naming only the LAST removal would strand the ones before it.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Capture,
        [string]$DeploymentRoot
    )

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }
    $root = Get-WacNormalizedPath -Path $DeploymentRoot
    if (-not $root) { return $false }

    $entries = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in @($Capture)) {
        if (-not $item) { continue }
        $definition = [string](Get-WacJournalField -Record $item -Name 'Definition')
        if ([string]::IsNullOrWhiteSpace($definition)) { continue }

        [void]$entries.Add([PSCustomObject]@{
            TaskName = [string](Get-WacJournalField -Record $item -Name 'TaskName')
            TaskPath = [string](Get-WacJournalField -Record $item -Name 'TaskPath')
            Definition = $definition
        })
    }

    # A record naming nothing is not a transaction, and writing one would leave the next run
    # reconciling a capture that never happened.
    if ($entries.Count -eq 0) { return $false }

    return (Write-WacDeploymentJournal -DeploymentRoot $root -Kind 'TaskCapture' -Record ([PSCustomObject]@{
        Schema = $script:DeploymentJournalSchema
        ProjectId = $script:DeploymentProjectId
        Root = $root
        Stage = 'TaskCapture'
        StartedUtc = ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
        ProcessId = $PID
        CapturedTask = @($entries.ToArray())
    }))
}

function Read-WacTaskCaptureRecord {
    <#
    .SYNOPSIS
        The task definitions an earlier process captured and may never have replaced.
    .DESCRIPTION
        Shaped so each entry can go straight back through the installer's own restore-and-prove path:
        Captured and CaptureReason are what that path reads before it will re-register anything, so a
        record entry and a live capture are the same object to it.
    .OUTPUTS
        State (Absent, Valid or Unreadable), Schema, Capture and Reason.
    #>
    param([string]$DeploymentRoot)

    $read = Read-WacDeploymentJournal -DeploymentRoot $DeploymentRoot -Kind 'TaskCapture'
    $result = [PSCustomObject]@{
        State = [string]$read.State
        Schema = [int]$read.Schema
        Capture = @()
        Reason = [string]$read.Reason
    }
    if ([string]$read.State -cne 'Valid') { return $result }

    $entries = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in @(Get-WacJournalField -Record $read.Record -Name 'CapturedTask')) {
        if (-not $item) { continue }
        $definition = [string](Get-WacJournalField -Record $item -Name 'Definition')
        if ([string]::IsNullOrWhiteSpace($definition)) { continue }

        [void]$entries.Add([PSCustomObject]@{
            TaskName = [string](Get-WacJournalField -Record $item -Name 'TaskName')
            TaskPath = [string](Get-WacJournalField -Record $item -Name 'TaskPath')
            Definition = $definition
            Captured = $true
            CaptureReason = 'The definition was read from the durable capture record of an interrupted run.'
        })
    }

    $result.Capture = @($entries.ToArray())
    $result.Reason = ('{0} captured task definition(s) recorded at schema {1}.' -f $entries.Count, [int]$read.Schema)
    return $result
}

function Remove-WacTaskCaptureRecord {
    <#
    .SYNOPSIS
        Ends the task-capture transaction: every task it named is either registered again or has been
        replaced by the registration this run made.
    #>
    param([string]$DeploymentRoot)

    return (Remove-WacDeploymentJournal -DeploymentRoot $DeploymentRoot -Kind 'TaskCapture')
}

# ---------------------------------------------------------------------------------------------
# What the record says the recovery slot should still be
# ---------------------------------------------------------------------------------------------

function Test-WacRecoverySlotMatchesRecord {
    <#
    .SYNOPSIS
        Whether the tree in a recovery slot still hashes to the inventory the durable record took of
        it before the swap that moved it there.
    .DESCRIPTION
        Ledger WAC-02R. Promotion used to ask only whether the slot was ours, healthy and trusted -
        all three of which a slot REWRITTEN since the record was taken still answers yes to - and what
        comes out of the slot becomes what SYSTEM executes. The record's own inventory is the only
        thing that can tell "the tree this machine moved aside" from "a tree of ours that is now
        standing in that slot".

        Corroborated and Matches are deliberately separate answers. When no record names a
        fingerprint there is nothing to corroborate against, and the slot stands on its provenance
        checks alone - which is a WEAKER position than a match, not the same one, so a caller can say
        which of the two it had. "We could not check" and "it matched" must never read alike.
    .OUTPUTS
        Matches, Corroborated, Fingerprint and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()]$Record
    )

    $result = [PSCustomObject]@{ Matches = $true; Corroborated = $false; Fingerprint = $null; Reason = $null }

    $recorded = [string](Get-WacJournalField -Record $Record -Name 'OriginalFingerprint')
    if ([string]::IsNullOrWhiteSpace($recorded)) {
        $result.Reason = 'no durable record names the content of what was moved aside, so the recovery slot stands on its provenance checks alone'
        return $result
    }

    $inventory = Get-WacDeploymentFingerprint -DeploymentRoot $Path
    if (-not $inventory.Complete) {
        $result.Matches = $false
        $result.Reason = ('the recovery slot could not be inventoried, so it cannot be proven to be the tree the durable record describes: {0}' -f [string]$inventory.Reason)
        return $result
    }

    $result.Fingerprint = [string]$inventory.Fingerprint
    if (-not [string]::Equals([string]$inventory.Fingerprint, $recorded, [System.StringComparison]::OrdinalIgnoreCase)) {
        $result.Matches = $false
        $result.Reason = ('the recovery slot holds different files from the tree the durable record describes ({0} file(s) inventoried)' -f [int]$inventory.FileCount)
        return $result
    }

    $result.Corroborated = $true
    $result.Reason = ('the recovery slot still hashes to the inventory the durable record took of it ({0} file(s))' -f [int]$inventory.FileCount)
    return $result
}
