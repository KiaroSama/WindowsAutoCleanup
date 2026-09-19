<#
.SYNOPSIS
    The abandoned-mutator quarantine: the in-memory latch, and the durable marker that carries its
    uncertainty past the death of the process that raised it.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Core.psm1 beside WindowsAutoCleanup.Budget.ps1, which is where
    the latch used to live. It moved because the two answer different questions: Budget.ps1 is
    arithmetic over the run's clocks, and this is a fact about the MACHINE that has to outlive one
    run of one process.

    Abandoning a runspace stuck inside a blocking NATIVE call is not termination and never was
    (ledger WAC-06R). PowerShell.Stop() cannot interrupt one and Thread.Abort does not exist on
    .NET Core, so the thread keeps running whatever it was doing while the caller moves on.

    For a blocking READ - a CIM query, a registry snapshot, a Recycle Bin scan - that costs two or
    three threads and nothing else, which is the trade this project accepts. For a block that
    MUTATES it is a different fact entirely: the run would schedule the next mutation on top of one
    that is still in progress. External mutators are not affected because every one of them is a
    child process under job ownership, where a timeout is a proven TerminateJobObject rather than an
    abandonment. The latch covers the remaining case - an in-process block that writes.

    WHY IT HAD TO BECOME DURABLE (ledger WAC-05R). The latch was per-run and in-memory, so the
    uncertainty ended when the process did. But the machine-wide operation lock is released in
    Run.ps1's finally block and the process then exits, and NOTHING made the next holder of that
    lock - the next scheduled run, an installer, the uninstaller - aware that a mutation of unknown
    completion had been left behind. Releasing the mutex erased the one fact that mattered.

    WHERE IT LIVES (ledger WAC-14). Not under the state root any more. That root's own trust rule
    explicitly permits a non-administrative principal to create new names in it, which for a file
    that decides whether the next run may change this machine is the decision itself - and the old
    writer also wrote a predictable `.new` with no check on it at all. The record is now one
    collision-failing create in the strict, administrator-only control store; there is no temporary
    name and no replace. WindowsAutoCleanup.ControlFile.ps1 carries that contract and the reasoning
    behind each of its three properties.

    WHAT CLEARS IT. Evidence, never time and never a fresh start. The marker records the process
    that raised it by id AND creation time, which is the same identity proof the termination path
    uses, because an id on its own is recycled. The next run binds that identity:

      still alive  - the abandoned thread may still be writing. The run starts quarantined.
      gone         - a thread cannot outlive its process, so nothing that process started can begin
                     a new write. The uncertainty is over; the marker is cleared and the event is
                     logged, loudly, at the level an operator reads.
      unreadable   - unknown is not absence. The run starts quarantined.

    Within a run it is still not self-clearing: nothing in this process can observe its own
    abandoned thread finishing, so there is no evidence here that would justify clearing it.
#>

$script:AbandonedMutatorCount = 0
$script:QuarantineMarkerName = 'abandoned-mutation.json'

function Reset-WacAbandonedMutator {
    <#
    .SYNOPSIS
        Clears the IN-MEMORY latch only. The durable marker is untouched.
    .DESCRIPTION
        Deliberately narrow. A suite that drove the abandoned path needs the door open again for the
        next case in the same host, and that is all this does - it is not a way to discard a fact
        about the machine. Resolve-WacQuarantine is the only thing that may retire a marker, and it
        does so only on proof that the process which wrote it is gone.
    #>
    $script:AbandonedMutatorCount = 0
}

function Get-WacAbandonedMutatorCount { return [int]$script:AbandonedMutatorCount }

function Test-WacMutationAllowed {
    <#
    .SYNOPSIS
        $false once a mutating bounded block has been abandoned without proof that it stopped.
    #>
    return ($script:AbandonedMutatorCount -eq 0)
}

function Get-WacQuarantineMarkerName {
    <#
    .SYNOPSIS
        The control file this quarantine is recorded in. A NAME, never a path.
    .DESCRIPTION
        It used to be a path under the state root, and that was the defect (ledger WAC-14): the
        caller then owned resolving it, and resolving a predictable name in a directory other people
        may create names in is the whole attack. The store owns resolution now, and the only thing
        outside it is which name to ask for.
    #>
    return $script:QuarantineMarkerName
}

function Write-WacQuarantineMarker {
    <#
    .SYNOPSIS
        Records the abandonment durably. $false when it could not be recorded at all.
    .DESCRIPTION
        One collision-failing create in the strict control store. There is no temporary name and no
        replace: an existing record means this machine is ALREADY carrying an unresolved mutation,
        which is exactly the fact this call was going to write, and overwriting it would discard the
        older and more conservative evidence.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Reason,
        [ValidateSet('InProcess', 'External')][string]$Kind = 'External'
    )

    # THE KIND IS THE FIELD THAT DECIDES WHETHER THIS RECORD CAN EVER RETIRE ITSELF (ledger
    # WAC-05R). The host's pid and creation stamp identify the process that REPORTED the
    # abandonment, which is a different thing from the work that was abandoned, and the resolver
    # used to treat them as the same: it retired any record whose reporting host was proven gone.
    # That reasoning holds for an in-process block and for nothing else.
    $record = [PSCustomObject]@{
        ProcessId = [int]$PID
        ProcessCreated = [string](Get-WacCurrentProcessCreated)
        RaisedUtc = ((Get-Date).ToUniversalTime().ToString('o'))
        Count = [int]$script:AbandonedMutatorCount
        OperationKind = [string]$Kind
        RaisedUptimeMs = (Get-WacMachineUptimeMs)
        Reason = [string]$Reason
    }

    $written = Write-WacControlFile -Name (Get-WacQuarantineMarkerName) `
        -Content (ConvertTo-Json -InputObject $record -Depth 3)

    return ([string]$written.Kind -ceq 'Created' -or [string]$written.Kind -ceq 'Present')
}

function Read-WacQuarantineMarker {
    <#
    .SYNOPSIS
        The abandonment an earlier PROCESS left behind. Three answers, never two.
    .DESCRIPTION
        Absent, Valid and Unreadable are different facts and only the first is permission to
        proceed. The store separates them from the OPEN's own outcome rather than from a pathname
        probe, so a directory standing at the name, a denied open, a dangling link and a file that
        genuinely is not there stop reading alike.
    .OUTPUTS
        State (Absent | Valid | Unreadable), Record, Reason.
    #>
    $result = [PSCustomObject]@{ State = 'Absent'; Record = $null; Reason = '' }

    $file = Read-WacControlFile -Name (Get-WacQuarantineMarkerName)

    if ([string]$file.State -ceq 'Unreadable') {
        $result.State = 'Unreadable'
        $result.Reason = [string]$file.Reason
        return $result
    }
    if ([string]$file.State -ceq 'Absent') {
        $result.Reason = [string]$file.Reason
        return $result
    }

    $record = $null
    $failure = ''
    try { $record = ConvertFrom-Json -InputObject ([string]$file.Text) }
    catch { $record = $null; $failure = [string]$_.Exception.Message }

    if (-not $record) {
        $result.State = 'Unreadable'
        $result.Reason = ('the quarantine marker could not be parsed: {0}' -f $failure).Trim()
        return $result
    }

    # Set-StrictMode 2.0 throws on a property that is not there, so the field is probed by name
    # first. A marker that carries no identity cannot be retired by one, which is exactly what
    # Unreadable means here.
    $names = @()
    try { $names = @($record.PSObject.Properties.Name) } catch { $names = @() }
    if (-not ($names -ccontains 'ProcessId')) {
        $result.State = 'Unreadable'
        $result.Reason = 'the quarantine marker names no process, so nothing can prove it is over'
        return $result
    }

    foreach ($field in @('RaisedUtc', 'Reason')) {
        if ($names -cnotcontains $field) {
            Add-Member -InputObject $record -MemberType NoteProperty -Name $field -Value ''
        }
    }
    $result.State = 'Valid'
    $result.Record = $record
    return $result
}

function Remove-WacQuarantineMarker {
    <#
    .SYNOPSIS
        Retires the marker. Only Resolve-WacQuarantine calls this, and only on proof.
    #>
    return (Remove-WacControlFile -Name (Get-WacQuarantineMarkerName))
}

function Get-WacCurrentProcessCreated {
    <#
    .SYNOPSIS
        This process's creation time as the termination path reads it, or 0 when it cannot be read.
    .DESCRIPTION
        Through the same binding every other identity proof in this project uses, so the value a
        marker records and the value a later run compares against come from one source. A 0 is
        recorded honestly and read fail-closed: a marker with no creation time can never be retired,
        because a recycled id could not then be ruled out.
    #>
    $created = 0L
    try {
        [void](Initialize-WacNative)
        $binding = Open-WacProcessBinding -ProcessId $PID
        if ($binding.Handle -ne [IntPtr]::Zero) {
            try { if ($binding.IdentityKnown) { $created = [long]$binding.Created } }
            finally { try { [WacNative]::CloseProcessHandle($binding.Handle) } catch { $null = $_ } }
        }
    }
    catch { $created = 0L }
    return [long]$created
}

function Test-WacQuarantineProcessGone {
    <#
    .SYNOPSIS
        Whether the process that raised a marker is PROVEN gone. Never a guess.
    .DESCRIPTION
        Binds the recorded id and compares creation times, because an id alone is recycled: a
        stranger that inherited the number would otherwise keep a finished quarantine armed forever,
        and - the direction that actually costs something - a live stranger would read as the
        original and keep it armed on this machine for good.

        ERROR_INVALID_PARAMETER from the bind means nothing owns the id at all, which is the one
        failure that is positive evidence of absence. Every other failure is unverifiable, and
        unverifiable is not proof.
    .OUTPUTS
        Gone (bool) and Reason.
    #>
    param([Parameter(Mandatory = $true)]$Record)

    $processId = 0
    try { $processId = [int]$Record.ProcessId } catch { $processId = 0 }
    if ($processId -le 0) {
        return [PSCustomObject]@{ Gone = $false; Reason = 'the marker names no usable process id' }
    }

    $recorded = 0L
    $names = @()
    try { $names = @($Record.PSObject.Properties.Name) } catch { $names = @() }
    if ($names -ccontains 'ProcessCreated') {
        try { $recorded = [long]$Record.ProcessCreated } catch { $recorded = 0L }
    }

    [void](Initialize-WacNative)
    $binding = Open-WacProcessBinding -ProcessId $processId

    if ($binding.Handle -eq [IntPtr]::Zero) {
        if ($binding.Win32Error -eq 87) {
            return [PSCustomObject]@{ Gone = $true; Reason = 'nothing owns the recorded process id' }
        }
        return [PSCustomObject]@{
            Gone = $false
            Reason = ('the recorded process could not be bound, so whether it is gone is unknown (win32 {0})' -f [int]$binding.Win32Error)
        }
    }

    try {
        if (-not $binding.IdentityKnown) {
            return [PSCustomObject]@{ Gone = $false; Reason = 'the recorded process identity could not be read' }
        }
        if ($recorded -le 0) {
            return [PSCustomObject]@{ Gone = $false; Reason = 'the marker recorded no creation time, so a recycled id cannot be ruled out' }
        }
        if ([long]$binding.Created -ne $recorded) {
            return [PSCustomObject]@{ Gone = $true; Reason = 'the recorded id belongs to a different process now' }
        }
        return [PSCustomObject]@{ Gone = $false; Reason = 'the process that abandoned a mutation is still running' }
    }
    finally {
        try { [WacNative]::CloseProcessHandle($binding.Handle) } catch { $null = $_ }
    }
}

function Add-WacAbandonedMutator {
    <#
    .SYNOPSIS
        Arms the quarantine and records it durably. Returns the new count.
    .DESCRIPTION
        The in-memory latch is raised FIRST and unconditionally: a marker that could not be written
        must not also cost this run its own guard. A failed write is logged at CRITICAL because it
        is the one case where the next process on this machine will not learn what happened here.
    #>
    param(
        [AllowEmptyString()][string]$Reason = '',
        # EXTERNAL BY DEFAULT, because that is the answer that keeps the record (ledger WAC-05R).
        # Only work this process ran ON ITS OWN THREAD may ever be retired by proving this process
        # died - a thread cannot outlive its host. Work handed to another process, to a service or
        # to the PnP subsystem can outlive it easily, so a caller claiming otherwise has to say so.
        [ValidateSet('InProcess', 'External')][string]$Kind = 'External'
    )

    $script:AbandonedMutatorCount++

    if (-not (Write-WacQuarantineMarker -Reason $Reason -Kind $Kind)) {
        Write-WacLog -Level CRITICAL -Component 'Budget' -Message 'A mutation was abandoned and the durable quarantine marker could not be written, so the next operation on this machine will not know about it.' -Data @{
            count = [int]$script:AbandonedMutatorCount; reason = $Reason
        }
    }

    return [int]$script:AbandonedMutatorCount
}

# Absorbs ordinary clock skew and the record's own second-resolution stamp, so a restart has to be
# clear of both before it settles anything.

function Get-WacMachineUptimeMs {
    <#
    .SYNOPSIS
        Native 64-bit uptime, available on Windows PowerShell 5.1 as well as PowerShell 7.
    #>
    try {
        if (-not (Initialize-WacNative)) { return $null }
        return [long][WacNative]::GetTickCount64()
    }
    catch { return $null }
}

function Test-WacMachineRestartedSince {
    <#
    .SYNOPSIS
        Proves a reset only from a decrease of the persisted native uptime counter.
    .DESCRIPTION
        Civil-clock age is never evidence of a reboot. A forward clock correction can make a
        month-old-looking record on the same boot, while its external mutator is still alive.
        A decreasing 64-bit uptime is positive reset evidence; an equal or greater value is
        inconclusive, NOT proof that no restart occurred. In particular, a late check after a
        restart may have overtaken the old counter. Keep that record for operator recovery.
        Legacy records without a counter are retained. RaisedUtc remains a compatibility and
        diagnostic parameter only; it never authorizes retirement.
    #>
    param(
        [AllowNull()]$RaisedUtc,
        [AllowNull()]$RaisedUptimeMs = $null
    )

    $null = $RaisedUtc
    $result = [PSCustomObject]@{ Restarted = $false; Reason = '' }
    $recorded = 0L
    if ($null -eq $RaisedUptimeMs -or
        -not [long]::TryParse([string]$RaisedUptimeMs, [ref]$recorded) -or $recorded -lt 0) {
        $result.Reason = 'the record has no valid monotonic uptime evidence; inspect it before explicitly retiring it'
        return $result
    }
    $current = Get-WacMachineUptimeMs
    if ($null -eq $current -or [long]$current -lt 0) {
        $result.Reason = 'the native uptime could not be read; restart evidence is unavailable'
        return $result
    }
    if ([long]$current -lt $recorded) {
        $result.Restarted = $true
        $result.Reason = 'the native 64-bit uptime counter reset after this record was written'
        return $result
    }
    $result.Reason = 'no monotonic reset is proven; elapsed wall time and the reporting host exiting cannot retire this record'
    return $result
}

function Resolve-WacQuarantine {
    <#
    .SYNOPSIS
        Starts a run's quarantine state from what earlier processes left on this machine.
    .DESCRIPTION
        Called by Initialize-WacRun, after the state root has been proven machine-trusted and before
        any step runs. It replaces the bare per-run reset that used to sit there: a new run starts
        with no outstanding mutation OF ITS OWN, which is not the same as a machine with none.

        Fail-closed in every direction but one. Only a marker whose process is PROVEN gone is
        retired, and that retirement is logged at WARNING with what was abandoned, so an operator
        reading the log sees the whole episode rather than its disappearance.
    .OUTPUTS
        State (Clear | Quarantined | Retired) and Reason.
    #>
    $script:AbandonedMutatorCount = 0

    # MIGRATION, and deliberately conservative. A build before the store moved wrote this marker
    # into the state root, where a name can be created by somebody else - so its contents may not be
    # believed AND it may not be deleted, because deleting it would discard a real operator's real
    # uncertainty on the strength of the same distrust. Present or Unknown both quarantine.
    $legacy = Test-WacLegacyControlFile -Name (Get-WacQuarantineMarkerName)
    if ([string]$legacy -cne 'Absent') {
        $script:AbandonedMutatorCount++
        Write-WacLog -Level CRITICAL -Component 'Budget' -Message 'A quarantine marker from an earlier build is still in the old, non-administrative location; it is neither believed nor removed, and this run will not mutate anything. Inspect it and delete it by hand once you are satisfied nothing from that run is still going.' -Data @{
            root = [string](Get-WacLegacyControlRoot); name = (Get-WacQuarantineMarkerName); state = [string]$legacy
        }
        return [PSCustomObject]@{ State = 'Quarantined'; Reason = 'a marker from an earlier build is still in the old location' }
    }

    $marker = Read-WacQuarantineMarker
    if ([string]$marker.State -ceq 'Absent') {
        return [PSCustomObject]@{ State = 'Clear'; Reason = 'no earlier run left an unfinished mutation' }
    }

    if ([string]$marker.State -ceq 'Unreadable') {
        $script:AbandonedMutatorCount++
        Write-WacLog -Level CRITICAL -Component 'Budget' -Message 'A quarantine marker is present and could not be read, so this run will not mutate anything.' -Data @{
            store = [string](Get-WacControlRoot); reason = [string]$marker.Reason
        }
        return [PSCustomObject]@{ State = 'Quarantined'; Reason = [string]$marker.Reason }
    }

    # WHAT WAS ABANDONED, before asking about the host that reported it. A record that does not say
    # - one written by a build before this field existed - reads as External, because that is the
    # answer that keeps it.
    $kind = 'External'
    try {
        if (@($marker.Record.PSObject.Properties.Name) -ccontains 'OperationKind') {
            $kind = [string]$marker.Record.OperationKind
        }
    }
    catch { $kind = 'External' }

    if ($kind -cne 'InProcess') {
        # THE HOST'S DEATH SETTLES NOTHING HERE. An external tool, a service-dispatched operation or
        # a descendant nobody owned goes on running after the process that launched it exits, so
        # proving that process gone is proving the wrong thing.
        #
        # A RESTART DOES settle it, and shipping that path is not optional: a latch with no way back
        # turns one abandoned operation - or one leaky test - into a machine that refuses every
        # mutation for ever. Measured, not theorised: without this a single leaked record made every
        # later run in the same CI job refuse, down to Remove-WacTree deleting nothing.
        $uptime = $null
        if (@($marker.Record.PSObject.Properties.Name) -ccontains 'RaisedUptimeMs') {
            $uptime = $marker.Record.RaisedUptimeMs
        }
        $restart = Test-WacMachineRestartedSince -RaisedUtc $marker.Record.RaisedUtc -RaisedUptimeMs $uptime
        if (-not $restart.Restarted) {
            $script:AbandonedMutatorCount++
            Write-WacLog -Level CRITICAL -Component 'Budget' -Message 'An earlier run abandoned work outside this process and a subsequent restart is not proven, so this run will not mutate anything. Inspect the operation and its recovery evidence; a legacy record or a late uptime check requires explicit operator retirement.' -Data @{
                processId = [int]$marker.Record.ProcessId; kind = $kind
                raisedUtc = [string]$marker.Record.RaisedUtc; reason = [string]$marker.Record.Reason
                unsettled = [string]$restart.Reason
                store = [string](Get-WacControlRoot); name = (Get-WacQuarantineMarkerName)
            }
            return [PSCustomObject]@{ State = 'Quarantined'; Reason = 'an earlier run abandoned work outside this process' }
        }

        if (-not (Remove-WacQuarantineMarker)) {
            $script:AbandonedMutatorCount++
            Write-WacLog -Level CRITICAL -Component 'Budget' -Message 'A restart ended the work an earlier run abandoned, but its marker could not be removed, so this run will not mutate anything rather than act against a marker it cannot retire.' -Data @{
                store = [string](Get-WacControlRoot); name = (Get-WacQuarantineMarkerName)
            }
            return [PSCustomObject]@{ State = 'Quarantined'; Reason = 'the marker of a settled abandonment could not be removed' }
        }

        Write-WacLog -Level WARNING -Component 'Budget' -Message 'An earlier run abandoned work outside this process; the machine has restarted since, which ended it, so the record was retired.' -Data @{
            processId = [int]$marker.Record.ProcessId; raisedUtc = [string]$marker.Record.RaisedUtc
            reason = [string]$marker.Record.Reason
        }
        return [PSCustomObject]@{ State = 'Retired'; Reason = 'the machine restarted after the abandonment was recorded' }
    }

    $gone = Test-WacQuarantineProcessGone -Record $marker.Record
    if (-not $gone.Gone) {
        $script:AbandonedMutatorCount++
        Write-WacLog -Level CRITICAL -Component 'Budget' -Message 'An earlier run abandoned a mutation whose completion is still unproven, so this run will not mutate anything.' -Data @{
            processId = [int]$marker.Record.ProcessId; reason = [string]$gone.Reason
        }
        return [PSCustomObject]@{ State = 'Quarantined'; Reason = [string]$gone.Reason }
    }

    if (-not (Remove-WacQuarantineMarker)) {
        $script:AbandonedMutatorCount++
        Write-WacLog -Level CRITICAL -Component 'Budget' -Message 'An earlier abandonment is over but its marker could not be removed, so this run will not mutate anything rather than act against a marker it cannot retire.' -Data @{
            store = [string](Get-WacControlRoot); name = (Get-WacQuarantineMarkerName)
        }
        return [PSCustomObject]@{ State = 'Quarantined'; Reason = 'the quarantine marker could not be removed' }
    }

    Write-WacLog -Level WARNING -Component 'Budget' -Message 'An earlier run abandoned a mutation; the process that raised it is gone, so the quarantine was retired.' -Data @{
        processId = [int]$marker.Record.ProcessId; proof = [string]$gone.Reason
    }
    return [PSCustomObject]@{ State = 'Retired'; Reason = [string]$gone.Reason }
}
