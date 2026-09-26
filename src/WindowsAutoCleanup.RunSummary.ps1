<#
.SYNOPSIS
    A versioned machine-readable summary of one run, written beside that run's own log.

.DESCRIPTION
    The audit log is written for a person: one line per event, in the order the events happened.
    Answering "did last night's run actually clean, or did it refuse?" from it means reading it.
    That is the wrong shape for monitoring, for a fleet, and for the next run's own reasoning.

    This writes the same verdict a second way - as one JSON document per run, beside the log file,
    with the same base name - so a reader can ask the question without parsing prose.

    THREE STATES, NOT TWO. A step that ran and a step that never started are different facts, and
    collapsing them is the defect class this project keeps finding: an operator who reads "no work
    done" as "nothing needed doing" has misread a refusal. Every step therefore carries one of
    `executed`, `refused` or `unarmed`, derived from what the step result actually states rather
    than inferred from a count of deleted files.

    IT NEVER CARRIES A SECRET, and it never carries anything the log would not. It holds outcomes,
    categories, counts and durations - no command lines, no environment, no credential of any kind,
    and no file content. A summary that could not be written is a WARNING and never fails the run:
    the run's verdict is the log's and the exit code's, and this is a second copy of it.
#>

# The version is the contract with whatever reads this. It changes when a field changes meaning -
# never when one is added, because a reader that ignores unknown fields is not broken by them.
$script:RunSummarySchema = 1

function Get-WacRunSummaryPath {
    <#
    .SYNOPSIS
        Beside this run's log, same base name, different extension. $null when there is no log to
        sit beside.
    #>
    $log = Get-WacLogPath
    if ([string]::IsNullOrWhiteSpace([string]$log)) { return $null }

    try { return ([System.IO.Path]::ChangeExtension([string]$log, '.summary.json')) }
    catch { return $null }
}

function Get-WacStepExecutionState {
    <#
    .SYNOPSIS
        Which of the four states one step result describes.
    .DESCRIPTION
        Read off the result's own facts. A step that was attempted ran, whatever it concluded. A
        step that was not attempted either refused on evidence - a security refusal, or an
        unresolved mutation this run inherited - or was simply not switched on, and those two are
        not the same thing to anybody reading this afterwards.
    #>
    param([Parameter(Mandatory = $true)]$Result)

    # Read by NAME, not by access. Under StrictMode a property that is not there throws, and a step
    # result that states nothing is exactly the shape this file has to survive - the run's verdict
    # may never depend on whether its own report could be assembled.
    $stated = @($Result.PSObject.Properties.Name)

    if ($stated -cnotcontains 'Attempted' -or $Result.Attempted -isnot [bool]) { return 'unstated' }
    if ([bool]$Result.Attempted) { return 'executed' }
    if ($stated -ccontains 'Outcome') {
        if ([string]$Result.Outcome -ceq 'SecurityRefusal') { return 'refused' }
        if ([string]$Result.Outcome -ceq 'Incomplete') { return 'refused' }
        if ([string]$Result.Outcome -ceq 'Failed') { return 'refused' }
        if (@('Succeeded', 'SafeSkip') -ccontains [string]$Result.Outcome) { return 'unarmed' }
        return 'unstated'
    }

    # Neither fact is stated. That is not a step that ran quietly; it is a step nobody can classify,
    # and it is recorded as such rather than folded into one of the three.
    return 'unstated'
}

function Write-WacRunSummary {
    <#
    .SYNOPSIS
        Writes the run summary. $true when it landed, $false when it did not; the caller logs the
        failure and carries on, because this is a report of the run and never part of it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Outcome,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [object[]]$StepResult = @(),
        [object[]]$TargetResult = @(),
        [Nullable[long]]$FreeBytesBefore,
        [Nullable[long]]$FreeBytesAfter,
        [bool]$RebootRequired,
        [ValidateSet('cleanup', 'preview', 'delegated')][string]$Mode = 'cleanup'
    )

    $path = Get-WacRunSummaryPath
    if ([string]::IsNullOrWhiteSpace([string]$path)) { return $false }

    try {
        return (Write-WacRunSummaryDocument -Path $path -Outcome $Outcome -ExitCode $ExitCode `
                -StepResult $StepResult -TargetResult $TargetResult -FreeBytesBefore $FreeBytesBefore `
                -FreeBytesAfter $FreeBytesAfter -RebootRequired $RebootRequired -Mode $Mode)
    }
    catch {
        # EVERYTHING, not just the write. Assembling the document reads whatever the steps and
        # targets happen to state, and a run whose exit code changed because its report could not be
        # built would be the report breaking the thing it reports on.
        Write-WacLog -Level WARNING -Component 'Summary' -Message 'The machine-readable run summary could not be produced; the audit log and the exit code are unaffected.' -Data @{
            path = [string]$path; error = $_.Exception.Message
        }
        return $false
    }
}

function Write-WacRunSummaryDocument {
    <#
    .SYNOPSIS
        Builds and writes the document. Every failure in here is caught by the caller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Outcome,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [object[]]$StepResult = @(),
        [object[]]$TargetResult = @(),
        [Nullable[long]]$FreeBytesBefore,
        [Nullable[long]]$FreeBytesAfter,
        [bool]$RebootRequired,
        [ValidateSet('cleanup', 'preview', 'delegated')][string]$Mode = 'cleanup'
    )

    $steps = New-Object 'System.Collections.Generic.List[object]'
    foreach ($step in @($StepResult)) {
        if (-not $step) { continue }
        [void]$steps.Add([PSCustomObject]@{
                category = [string]$step.Category
                state = (Get-WacStepExecutionState -Result $step)
                outcome = [string]$step.Outcome
                detail = [string]$step.Detail
                durationMs = [int]$step.DurationMs
                rebootRequired = [bool]$step.RebootRequired
            })
    }

    # The targets are summed, not listed. A path is not a secret, but a per-path inventory of a
    # user's profile is a different artifact from a run verdict, and this file is the verdict.
    $swept = [long]0
    $failed = [long]0
    $refused = [long]0
    $bytes = [long]0
    foreach ($target in @($TargetResult)) {
        if (-not $target) { continue }
        $swept += [long]$target.FilesDeleted + [long]$target.DirectoriesDeleted
        $failed += [long]$target.Failed
        # Refused is ALREADY the total of the identity and out-of-root refusals. Adding those to it
        # would report every refusal twice, which is the kind of number nobody can un-believe once
        # it has been in a dashboard.
        $refused += [long]$target.Refused
        $bytes += [long]$target.BytesDeleted
    }

    $document = [PSCustomObject]@{
        schema = $script:RunSummarySchema
        mode = $Mode
        # $script:Version and $script:Stopwatch are the RUN's own state, shared with this part the
        # same way the report's are. The deployment module is deliberately not imported by the
        # runtime, so its version helper is not reachable from here and must not be reached for.
        version = [string]$script:Version
        executionId = (Get-WacExecutionId)
        elapsed = [string]$script:Stopwatch.Elapsed.ToString('hh\:mm\:ss')
        completedUtc = ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
        outcome = [string]$Outcome
        exitCode = [int]$ExitCode
        rebootRequired = [bool]$RebootRequired
        logPath = [string](Get-WacLogPath)
        steps = @($steps.ToArray())
        removed = [PSCustomObject]@{
            entries = [int]$swept
            bytes = [long]$bytes
            failed = [int]$failed
            refused = [int]$refused
        }
        freeBytes = [PSCustomObject]@{
            before = $(if ($null -eq $FreeBytesBefore) { $null } else { [long]$FreeBytesBefore })
            after = $(if ($null -eq $FreeBytesAfter) { $null } else { [long]$FreeBytesAfter })
        }
    }

    # Serialize BEFORE creating a name. A collision is not our file, even when it is a hard link
    # to an ordinary file: never open, truncate or replace it. Bind creation to the same trusted
    # directory primitive used by the audit log rather than resolving its pathname a second time.
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((ConvertTo-Json -InputObject $document -Depth 6))
    $full = [System.IO.Path]::GetFullPath($Path)
    $directory = Open-WacTrustedDirectory -Path ([System.IO.Path]::GetDirectoryName($full)) `
        -RequireMachineTrust:(Test-WacIsAdministrator)
    try {
        if (-not $directory.IsTrusted) { throw ('The summary directory was refused: ' + [string]$directory.Reason) }
        $created = New-WacBoundFile -DirectoryHandle $directory.Handle -Name ([System.IO.Path]::GetFileName($full))
        if ([string]$created.Kind -cne 'Created') {
            throw ('The summary name could not be exclusively created: ' + [string]$created.Kind)
        }
        try {
            $created.Stream.Write($bytes, 0, $bytes.Length)
            $created.Stream.Flush($true)
        }
        finally { $created.Stream.Dispose() }
    }
    finally {
        if ($directory.Handle -ne [IntPtr]::Zero) { [void](Close-WacTrustedDirectory -Handle $directory.Handle) }
    }
    # This is not an atomic-rename protocol. A process kill or storage failure can leave incomplete
    # JSON; readers must reject it and must never infer success from file existence alone.
    return $true
}
