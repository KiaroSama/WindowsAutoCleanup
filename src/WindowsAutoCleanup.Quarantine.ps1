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

function Get-WacQuarantineMarkerPath {
    <#
    .SYNOPSIS
        Where the durable marker lives: in the machine-wide state root, beside the logs.
    .DESCRIPTION
        Not in TEMP and not beside the deployment. The state root is the one location every entry
        point already proves machine-trusted before it writes anything, and Initialize-WacRun has
        done that by the time either side of this file runs.
    #>
    $root = Get-WacDataRoot
    if ([string]::IsNullOrWhiteSpace($root)) { return $null }
    return (Join-Path -Path $root -ChildPath $script:QuarantineMarkerName)
}

function Write-WacQuarantineMarker {
    <#
    .SYNOPSIS
        Records the abandonment durably. $false when it could not be written.
    .DESCRIPTION
        Written beside and swapped in, for the reason the deployment journal is: a crash mid-write
        would otherwise leave a torn file, and a torn marker is worse than none because it destroys
        a complete one while looking like an answer. Here the torn case is also read fail-closed, so
        the cost of a bad write is a quarantined run rather than a silent one.

        Never through a reparse point. The marker sits in an administrative directory and writing
        through a link somebody else left at that name would write wherever they chose.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Reason)

    $path = Get-WacQuarantineMarkerPath
    if (-not $path) { return $false }

    if ((Test-Path -LiteralPath $path) -and (Test-WacIsReparsePoint -Path $path)) { return $false }

    $record = [PSCustomObject]@{
        ProcessId = [int]$PID
        ProcessCreated = [string](Get-WacCurrentProcessCreated)
        RaisedUtc = ((Get-Date).ToUniversalTime().ToString('o'))
        Count = [int]$script:AbandonedMutatorCount
        Reason = [string]$Reason
    }

    $staging = $path + '.new'
    try {
        $directory = Split-Path -Path $path -Parent
        if ($directory -and -not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        [System.IO.File]::WriteAllText($staging, (ConvertTo-Json -InputObject $record -Depth 3),
            (New-Object System.Text.UTF8Encoding($false)))

        if (Test-Path -LiteralPath $path -PathType Leaf) {
            [System.IO.File]::Replace($staging, $path, $null, $true)
        }
        else {
            [System.IO.File]::Move($staging, $path)
        }
        return $true
    }
    catch {
        try { if (Test-Path -LiteralPath $staging -PathType Leaf) { [System.IO.File]::Delete($staging) } } catch { $null = $_ }
        return $false
    }
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

function Read-WacQuarantineMarker {
    <#
    .SYNOPSIS
        The abandonment an earlier PROCESS left behind. Three answers, never two.
    .DESCRIPTION
        Absent, Valid and Unreadable are different facts and only one of them is permission to
        proceed. "There was no abandonment" may license mutating this machine; "there is a marker
        and it cannot be read" must never do so.
    .OUTPUTS
        State (Absent | Valid | Unreadable), Record, Reason.
    #>
    $result = [PSCustomObject]@{ State = 'Absent'; Record = $null; Reason = '' }

    $path = Get-WacQuarantineMarkerPath
    if (-not $path) {
        $result.State = 'Unreadable'
        $result.Reason = 'the quarantine marker path could not be resolved'
        return $result
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $result }
    if (Test-WacIsReparsePoint -Path $path) {
        $result.State = 'Unreadable'
        $result.Reason = 'a reparse point stands where the quarantine marker should be'
        return $result
    }

    $record = $null
    $failure = ''
    try { $record = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path)) }
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

    $result.State = 'Valid'
    $result.Record = $record
    return $result
}

function Remove-WacQuarantineMarker {
    <#
    .SYNOPSIS
        Retires the marker. Only Resolve-WacQuarantine calls this, and only on proof.
    #>
    $path = Get-WacQuarantineMarkerPath
    if (-not $path) { return $false }
    if (-not (Test-Path -LiteralPath $path)) { return $true }

    try {
        [System.IO.File]::Delete((Get-WacLongPath -Path $path))
        return $true
    }
    catch { return $false }
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
    param([AllowEmptyString()][string]$Reason = '')

    $script:AbandonedMutatorCount++

    if (-not (Write-WacQuarantineMarker -Reason $Reason)) {
        Write-WacLog -Level CRITICAL -Component 'Budget' -Message 'A mutation was abandoned and the durable quarantine marker could not be written, so the next operation on this machine will not know about it.' -Data @{
            count = [int]$script:AbandonedMutatorCount; reason = $Reason
        }
    }

    return [int]$script:AbandonedMutatorCount
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

    $marker = Read-WacQuarantineMarker
    if ([string]$marker.State -ceq 'Absent') {
        return [PSCustomObject]@{ State = 'Clear'; Reason = 'no earlier run left an unfinished mutation' }
    }

    if ([string]$marker.State -ceq 'Unreadable') {
        $script:AbandonedMutatorCount++
        Write-WacLog -Level CRITICAL -Component 'Budget' -Message 'A quarantine marker is present and could not be read, so this run will not mutate anything.' -Data @{
            path = [string](Get-WacQuarantineMarkerPath); reason = [string]$marker.Reason
        }
        return [PSCustomObject]@{ State = 'Quarantined'; Reason = [string]$marker.Reason }
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
            path = [string](Get-WacQuarantineMarkerPath)
        }
        return [PSCustomObject]@{ State = 'Quarantined'; Reason = 'the quarantine marker could not be removed' }
    }

    Write-WacLog -Level WARNING -Component 'Budget' -Message 'An earlier run abandoned a mutation; the process that raised it is gone, so the quarantine was retired.' -Data @{
        processId = [int]$marker.Record.ProcessId; proof = [string]$gone.Reason
    }
    return [PSCustomObject]@{ State = 'Retired'; Reason = [string]$gone.Reason }
}
