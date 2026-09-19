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

    THE LINKING PROTOCOL, and why two files are still one transaction (ledger WAC-02R).

    Two individually durable records do not make the pair atomic. The counterexample that forced
    this: files A and task A; an upgrade leaves files B, the recovery slot holding A, task B
    registered, and both records uncommitted. A restart that resolved the two records INDEPENDENTLY
    retired the task capture because something with that name was registered, then restored files A
    from the swap record - leaving files A under task B with task A's evidence destroyed.

    What binds them is a GENERATION: one process performs at most one deployment operation, mints
    one TransactionId for it (Get-WacDeploymentGeneration), and stamps that id into BOTH records.
    The protocol is:

      1. The capture record is written, carrying the generation id, BEFORE the first unregister.
      2. The swap record is written, carrying the SAME generation id, BEFORE the first move.
      3. Every later write of either record repeats that id.
      4. The swap record is stamped Committed - after the replacement task AND the replacement
         files are verified, and BEFORE either recovery copy is retired.
      5. Commit deletes the swap record first, then the capture record.

    Step 4 is what makes step 5's leftovers readable. Commitment used to be INFERRED by the next
    process - a manifest hash that matched the record, or a healthy tree beside an original it could
    not promote - and neither of those is the same claim. A tree can be healthy, be exactly the one
    the record names, and still belong to a run that died before it registered the task that goes
    with it; retiring the recovery copy on that reading discards the only installation that ever
    worked. So commitment is now WRITTEN by the process that established it, and a record that does
    not say it is treated as a transaction still open.

    It is crash-consistent because each record is durable before the mutation it describes, and
    because the id is what a later process reads to decide whether the two records are two halves of
    ONE interrupted operation or debris from two different ones. Equal ids means one generation, and
    one generation gets ONE commit decision (Get-WacDeploymentRecoveryPlan) applied to both halves.
    Unequal ids, or a capture whose generation no swap record accounts for, is ambiguity - and
    ambiguity preserves both halves rather than guessing which run owned which.

    A record written by a build older than the generation id carries none, which reads as "not
    recorded" and therefore as unlinked: such a pair is reconciled conservatively, never silently
    treated as one transaction.

    ARTIFACT LIFECYCLE. A write stages to '<record>.new' and replaces the live record with it, so a
    crash mid-write cannot tear the only copy. The staging name is transient by construction: it
    exists between one File.WriteAllText and the File.Replace or File.Move on the next line, and
    both the failure path and Remove-WacDeploymentJournal sweep it. Builds before this one also left
    a '<record>.last' backup that nothing ever read; it is no longer created, and the sweep deletes
    one an older build left behind, so ending a transaction leaves no artifact of it on disk.
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
#
# Schema 4 added Committed: the DECISION that a generation finished, rather than a shape a later
# process infers from what it finds. Absence reads as "not recorded", which is "not committed" -
# the safe direction, and the only one a record written before this build can honestly support.
$script:DeploymentJournalSchema = 4
$script:DeploymentJournalMinSchema = 1

# The GENERATION this process's records belong to (ledger WAC-02R). One process performs at most one
# deployment operation, so one id per process is exactly the granularity the linking protocol above
# needs: both halves of one operation carry it, and a later process compares the two ids rather than
# guessing that two records found together describe the same run.
#
# Minted lazily rather than at load, so importing the module writes nothing and costs nothing.
$script:DeploymentGeneration = $null

function Get-WacDeploymentGeneration {
    <#
    .SYNOPSIS
        The transaction id every record this process writes carries. Stable for the life of the
        process, so the swap record and the capture record are provably the same operation.
    #>

    if ([string]::IsNullOrWhiteSpace([string]$script:DeploymentGeneration)) {
        $script:DeploymentGeneration = [guid]::NewGuid().ToString('N').ToUpperInvariant()
    }
    return [string]$script:DeploymentGeneration
}

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

function Get-WacJournalPathState {
    <#
    .SYNOPSIS
        What is at a record's path, as THREE answers: File, Absent, or Unreadable.
    .DESCRIPTION
        Ledger WAC-02R. Both readers used to ask Test-Path -PathType Leaf and read $false as "no
        record here", which is wrong for every shape that is not a readable regular file: a
        DIRECTORY standing at the record's name answers $false, so does a dangling link, and so does
        a probe the filesystem refused. Each of those means "something is there and this build
        cannot say what", and reading them as absence is what lets a run delete a recovery copy
        because it believed no transaction was open.

        Proven absence is narrow on purpose: the name must not exist as a file OR as a directory,
        and the shared inspection must then agree that the parent does not list it - either because
        it listed the parent and the name was not in it, or because the parent itself is proven not
        to exist, which is the one error that IS an answer. A parent that merely could not be read
        has proven nothing about what is in it.
    .OUTPUTS
        State (File, Absent or Unreadable) and Reason.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path)

    $result = [PSCustomObject]@{ State = 'Unreadable'; Reason = '' }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $result.Reason = 'the transaction record path could not be resolved'
        return $result
    }

    try {
        if ([System.IO.Directory]::Exists($Path)) {
            $result.Reason = 'a directory stands where the transaction record should be'
            return $result
        }
        if ([System.IO.File]::Exists($Path)) {
            $result.State = 'File'
            $result.Reason = 'a transaction record is present'
            return $result
        }

        # Neither a file nor a directory BY ITS OWN TYPE PROBE, which is not the same as nothing
        # being there. Get-WacPathPresence is what may turn it into absence, and it is the only
        # thing here allowed to: it classifies by the exception a single enumeration of the parent
        # THROWS, so a container that could not be listed answers for none of the names in it, and
        # it READS that enumeration's result, so a name the filesystem does list under a shape
        # neither probe above reports is something standing there rather than nothing.
        #
        # The result used to be discarded with [void] and the fall-through said Absent regardless,
        # which made the enumeration a gesture: the one piece of positive evidence it collects was
        # thrown away, and the answer it was collected for was given anyway.
        $presence = [string](Get-WacPathPresence -Path $Path)
        if ($presence -ceq 'Present') {
            $result.Reason = 'something this build cannot identify stands where the transaction record should be'
            return $result
        }
        if ($presence -cne 'Absent') {
            $result.Reason = 'the directory the transaction record would live in could not be read'
            return $result
        }
    }
    catch {
        $result.Reason = ('the transaction record path could not be inspected: {0}' -f $_.Exception.Message)
        return $result
    }

    $result.State = 'Absent'
    $result.Reason = 'no transaction record is present'
    return $result
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
    # next process ever sees.
    #
    # No backup copy. File.Replace used to displace the live record to '<record>.last' so an
    # unreadable record would have a predecessor to reconcile against - and nothing in this project
    # ever read one, so the only thing it produced was an artifact outliving the transaction that
    # made it. A null backup name keeps the replace atomic and leaves the lifecycle above true.
    $staging = $path + '.new'

    try {
        [System.IO.File]::WriteAllText($staging, (ConvertTo-Json -InputObject $Record -Depth 5),
            (New-Object System.Text.UTF8Encoding($false)))

        if ([System.IO.File]::Exists($path)) {
            # [NullString]::Value, not $null. PowerShell converts $null to an EMPTY STRING when it
            # binds a [string] parameter, and File.Replace rejects an empty path - measured on both
            # shipped hosts: "The path is empty. (Parameter 'path')". The write then failed
            # silently, leaving the record frozen at whatever stage last managed a File.Move.
            [System.IO.File]::Replace($staging, $path, [NullString]::Value, $true)
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
        State (Absent, Valid or Unreadable), Record, Schema, Generation and Reason.
    #>
    param(
        [string]$DeploymentRoot,
        [ValidateSet('Swap', 'TaskCapture')][string]$Kind = 'Swap'
    )

    $result = [PSCustomObject]@{ State = 'Absent'; Record = $null; Schema = 0; Generation = ''; Reason = '' }

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

    # Through the three-valued probe, so a DIRECTORY at the record's name, a dangling link or a
    # refused inspection is unreadable rather than absent.
    $probe = Get-WacJournalPathState -Path $path
    if ([string]$probe.State -ceq 'Unreadable') {
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'A deployment transaction record path could not be inspected.' -Data @{ path = $path; reason = [string]$probe.Reason }
        $result.State = 'Unreadable'
        $result.Reason = [string]$probe.Reason
        return $result
    }
    if ([string]$probe.State -cne 'File') { return $result }

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
    $result.Generation = [string](Get-WacJournalField -Record $record -Name 'TransactionId')
    return $result
}

function Remove-WacDeploymentJournal {
    <#
    .SYNOPSIS
        Ends a recorded transaction. Deleting this file is what says the transaction it describes is
        no longer in flight, so it happens at the commit point and after a completed rollback - never
        merely because one step succeeded.
    .DESCRIPTION
        $false is a REAL answer and every caller has to carry it: a transaction whose record could
        not be deleted is still open on disk, so an installation that committed can read back as
        unfinished to the next run. The artifacts of the write protocol go with the record - one
        call ends the transaction and leaves nothing of it behind.
    #>
    param(
        [string]$DeploymentRoot,
        [ValidateSet('Swap', 'TaskCapture')][string]$Kind = 'Swap'
    )

    $path = Get-WacDeploymentJournalPath -DeploymentRoot $DeploymentRoot -Kind $Kind
    if (-not $path) { return $false }

    $ok = $true
    # '.last' is swept for machines carrying one an older build left; nothing writes it any more.
    foreach ($target in @($path, ($path + '.new'), ($path + '.last'))) {
        $probe = Get-WacJournalPathState -Path $target
        # Proven absence is the only "nothing to do". An unreadable probe is a failure, because the
        # record may still be there and a caller that reads $true would call the transaction closed.
        if ([string]$probe.State -ceq 'Absent') { continue }
        if ([string]$probe.State -ceq 'Unreadable') {
            Write-WacLog -Level WARNING -Component 'Deploy' -Message 'A deployment transaction record could not be deleted.' -Data @{ path = $target; error = [string]$probe.Reason }
            $ok = $false
            continue
        }

        try { [System.IO.File]::Delete((Get-WacLongPath -Path $target)) }
        catch {
            Write-WacLog -Level WARNING -Component 'Deploy' -Message 'A deployment transaction record could not be deleted.' -Data @{ path = $target; error = $_.Exception.Message }
            $ok = $false
        }
    }

    return $ok
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

        ALL OR NOTHING. An entry that carries no definition used to be skipped, so a record could
        land describing three removals when four had happened - and the caller read $true and went
        on to unregister the fourth. A capture this function cannot record in full is recorded not
        at all, which leaves the task registered and costs the upgrade instead of the machine.
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
        $definition = [string](Get-WacJournalField -Record $item -Name 'Definition')
        $taskName = [string](Get-WacJournalField -Record $item -Name 'TaskName')
        if (-not $item -or [string]::IsNullOrWhiteSpace($definition) -or [string]::IsNullOrWhiteSpace($taskName)) {
            Write-WacLog -Level ERROR -Component 'Deploy' -Message 'A task capture could not be recorded because one of the captures it must name is incomplete; nothing was written.' -Data @{ root = $root }
            return $false
        }

        [void]$entries.Add([PSCustomObject]@{
            TaskName = $taskName
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
        TransactionId = (Get-WacDeploymentGeneration)
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

        A PARTIAL RECORD IS AN UNREADABLE ONE (ledger WAC-02R). An entry with no definition, or with
        no task name, used to be dropped on the floor - and a record every one of whose entries was
        dropped came back Valid, naming nothing, which the installer retired as debris. Schema,
        project id and root prove the record describes THIS deployment; they prove nothing about the
        transaction being complete. Anything this build cannot decode in full is refused whole, so
        the one piece of evidence about a missing registration survives for a human to read.
    .OUTPUTS
        State (Absent, Valid or Unreadable), Schema, Generation, Capture and Reason.
    #>
    param([string]$DeploymentRoot)

    $read = Read-WacDeploymentJournal -DeploymentRoot $DeploymentRoot -Kind 'TaskCapture'
    $result = [PSCustomObject]@{
        State = [string]$read.State
        Schema = [int]$read.Schema
        Generation = [string]$read.Generation
        Capture = @()
        Reason = [string]$read.Reason
    }
    if ([string]$read.State -cne 'Valid') { return $result }

    $entries = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in @(Get-WacJournalField -Record $read.Record -Name 'CapturedTask')) {
        $definition = [string](Get-WacJournalField -Record $item -Name 'Definition')
        $taskName = [string](Get-WacJournalField -Record $item -Name 'TaskName')
        if (-not $item -or [string]::IsNullOrWhiteSpace($definition) -or [string]::IsNullOrWhiteSpace($taskName)) {
            Write-WacLog -Level WARNING -Component 'Deploy' -Message 'A task-capture record carries an entry this build cannot decode, so the whole record is refused rather than half-read.' -Data @{
                root = [string]$DeploymentRoot; schema = [int]$read.Schema
            }
            $result.State = 'Unreadable'
            $result.Capture = @()
            $result.Reason = 'the task-capture record carries an entry with no task name or no definition, so the transaction it describes cannot be read in full'
            return $result
        }

        [void]$entries.Add([PSCustomObject]@{
            TaskName = $taskName
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

        THREE original states, not two (ledger WAC-02R). An existing but EMPTY deployment root is
        deliberately adopted as ours, and a tree with no files in it has no fingerprint to record -
        so "no fingerprint" used to mean both "an older build wrote this record" and "what was moved
        aside was an empty directory", and the second is a state that can be corroborated exactly.
        OriginalState says which: Absent, Empty or Substantive.
    .OUTPUTS
        Matches, Corroborated, Fingerprint and Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()]$Record
    )

    $result = [PSCustomObject]@{ Matches = $true; Corroborated = $false; Fingerprint = $null; Reason = $null }

    $recorded = [string](Get-WacJournalField -Record $Record -Name 'OriginalFingerprint')
    $state = [string](Get-WacJournalField -Record $Record -Name 'OriginalState')

    if ([string]::Equals($state, 'Empty', [System.StringComparison]::Ordinal)) {
        # An empty tree is identified by being empty, which is a fact the slot can be asked for
        # directly. Get-WacDeploymentFingerprint refuses a tree with no files in it, so demanding a
        # fingerprint here would refuse the one state this branch exists to corroborate.
        $ownership = Get-WacDeploymentOwnership -DeploymentRoot $Path
        if ([string]$ownership.Kind -ceq 'Indeterminate' -or -not $ownership.Exists) {
            $result.Matches = $false
            $result.Reason = ('the recovery slot could not be read, so it cannot be proven to be the empty tree the durable record describes: {0}' -f [string]$ownership.Reason)
            return $result
        }
        if (-not [bool]$ownership.IsEmpty) {
            $result.Matches = $false
            $result.Reason = 'the recovery slot holds files where the durable record says an empty directory was moved aside'
            return $result
        }

        $result.Corroborated = $true
        $result.Reason = 'the recovery slot is still the empty directory the durable record says was moved aside'
        return $result
    }

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
