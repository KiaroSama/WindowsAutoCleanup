<#
.SYNOPSIS
    What one run says about itself: the header, the shared outcome vocabulary, the run-level
    verdicts and the footer that turns them into an exit code.

.DESCRIPTION
    Dot-sourced by Run.ps1 rather than imported, so it shares that script's scope: the outcome
    tables, the stopwatch and the version below are the run's own state and belong to exactly one
    execution of exactly one script.

    It is its own file because it is its own responsibility. Run.ps1 decides WHAT the run does -
    elevate or refuse, take the lock, sweep, run the tools; everything here decides what the run
    then CLAIMS, at which level it says it, and which of the documented exit codes that claim maps
    to. Splitting them is also why the pre-cleanup gate and the footer can share one implementation
    of the run-level verdicts instead of the footer owning them alone, which is the defect that put
    a security refusal after the deletions it was supposed to prevent.
#>
function Get-WacRunTelemetry {
    <#
    .SYNOPSIS
        Runs one diagnostic probe and returns $null instead of throwing.
    .DESCRIPTION
        Every value this run writes about its environment - the OS name, the OS edition, free space
        before and after - is a diagnostic, and not one of them is an input to the verdict. Each has
        its own catch already; this is the guarantee that stands even if one of them stops having
        one, because a diagnostic that throws out of the header would be caught by the run's own
        outer handler and turn a cleanup failure into a plain exit 1 - erasing the result the run
        exists to report.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Probe,
        [Parameter(Mandatory = $true)][string]$What
    )

    try { return (& $Probe) }
    catch {
        Write-WacLog -Level WARNING -Component 'Run' -Message ('A diagnostic could not be read: ' + $What) -Data @{ error = $_.Exception.Message }
        return $null
    }
}

function Write-WacRunHeader {
    param([Parameter(Mandatory = $true)][string]$LogPath)

    $edition = if ($PSVersionTable.ContainsKey('PSEdition')) { [string]$PSVersionTable.PSEdition } else { 'Desktop' }
    $hostPath = $null
    try { $hostPath = [string](Get-Process -Id $PID -ErrorAction Stop).Path } catch { $hostPath = $null }

    Write-WacLog -Level INFO -Component 'Run' -Message 'WindowsAutoCleanup started.' -Data @{
        version     = $script:Version
        executionId = Get-WacExecutionId
        logPath     = $LogPath
        scriptRoot  = $script:ScriptRoot
        scheduled   = [bool]$Scheduled
        elevated    = (Test-WacIsAdministrator)
        psVersion   = [string]$PSVersionTable.PSVersion
        psEdition   = $edition
        psHost      = $hostPath
        budgetMin   = $BudgetMinutes
        logLevel    = $LogLevel
    }

    # Diagnostics, and diagnostics only. This used to be a Win32_OperatingSystem query - an RPC
    # round trip to the WMI service, made before a single cleanup step starts and outside every
    # step contract, so a wedged repository could stall the run here with no bound at all. The
    # registry holds the same two facts and cannot wait on a service.
    Write-WacLog -Level INFO -Component 'Run' -Message 'Operating system.' -Data @{
        caption = [string](Get-WacRunTelemetry -What 'the operating system name' -Probe {
                (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                    -Name 'ProductName' -ErrorAction Stop).ProductName
            })
        build   = [string][Environment]::OSVersion.Version.Build
        server  = (Get-WacRunTelemetry -What 'the operating system edition' -Probe { Test-WacIsWindowsServer })
    }

    Write-WacLog -Level INFO -Component 'Run' -Message 'Configuration.' -Data @{
        scope                   = 'C: only'
        resetWindowsUpdateBase  = [bool]$ResetWindowsUpdateBase
        pruneSupersededDrivers  = [bool]$PruneSupersededDrivers
        enableLegacyDiskCleanup = [bool]$EnableLegacyDiskCleanup
        skipRecycleBin          = [bool]$SkipRecycleBin
        skipCategory            = ($SkipCategory -join ',')
    }

    if ($SkipAclHardening) {
        Write-WacLog -Level WARNING -Component 'Run' -Message '-SkipAclHardening is deprecated and ignored; the ACL hardening capability was removed in v1.2.0.'
    }
}

# ------------------------------------------------------------------------------------------------
# The run outcome
#
# Every module reports in one five-value vocabulary. Rank is the RUN-level precedence - a single
# security refusal outranks any number of failures, a failure outranks incomplete work, and only a
# run with none of the three exits 0. Succeeded and SafeSkip share rank 0 on purpose: a step that
# was correctly not run (an opt-in that is off, a tool that is absent) is not a defect.
# ------------------------------------------------------------------------------------------------

# The rank table and Get-WacHigherOutcome live in StepContract.psm1 - ONE copy. This file used to
# hold a second, and Run.ps1 a third as a raw index.
$script:OutcomeExitCode = @{ 'Succeeded' = 0; 'SafeSkip' = 0; 'Incomplete' = 6; 'Failed' = 2; 'SecurityRefusal' = 7 }

# The level the run's verdict and the evidence behind it are written at, decided by the OUTCOME.
# -LogLevel is the operator's choice about detail; it is not a choice to lose the verdict. A footer
# hard-wired to INFO/WARNING wrote 'status=SecurityRefusal exitCode=7' into a log that -LogLevel
# ERROR then dropped on the floor, leaving the audit log of a refusing run empty. CRITICAL is the
# highest level the parameter accepts, so it is the only one no setting can gate out.
$script:OutcomeLogLevel = @{
    'Succeeded' = 'INFO'; 'SafeSkip' = 'INFO'
    'Incomplete' = 'CRITICAL'; 'Failed' = 'CRITICAL'; 'SecurityRefusal' = 'CRITICAL'
}

function Get-WacStepOutcome {
    <#
    .SYNOPSIS
        One step result's outcome. Fails closed on a result that does not state one.
    .DESCRIPTION
        .Outcome is the contract and the Succeeded/Skipped/Failed booleans are derived from it, so
        the outcome is the only thing worth reading: those booleans cannot express Incomplete or
        SecurityRefusal, and deriving from them would exit 2 for work that was merely unfinished.

        A step that states no outcome is one this mapping cannot classify, and an unclassifiable
        step is not a success. Strict mode makes a missing property a terminating error, so the
        property is proven present rather than probed by reading it.
    #>
    param([Parameter(Mandatory = $true)]$Step)

    if (@($Step.PSObject.Properties.Name) -ccontains 'Outcome') { return [string]$Step.Outcome }
    return 'Failed'
}

function Get-WacRunLevelOutcome {
    <#
    .SYNOPSIS
        The worst of the three run-level verdicts that no step or target result carries, logged as
        each one is reached.
    .DESCRIPTION
        Shared by the pre-cleanup gate and the footer, which is the whole point. The footer used to
        own these three checks alone, so the state directory's trust verdict - a SECURITY refusal -
        was first consulted after every deletion, every DISM run and every driver removal had
        already happened. A refusal reached after the damage is a report, not a control.

        Reading it twice is deliberate and not a duplicate: the budget can expire and the audit log
        can lose a line DURING the run, so the footer has to ask again. The gate exits when it
        refuses, so nothing is logged twice on that path.
    #>
    param([Parameter(Mandatory = $true)][ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Current)

    $outcome = $Current

    if (Test-WacDeadlineExpired) {
        Write-WacLog -Level $script:OutcomeLogLevel['Incomplete'] -Component 'Summary' -Message 'The run budget expired, so not everything this run was asked to do was attempted.'
        $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
    }

    $logHealth = Get-WacLogHealth
    if (-not $logHealth.IsDurable) {
        Write-WacLog -Level $script:OutcomeLogLevel['Incomplete'] -Component 'Summary' -Message 'The durable audit log this run was asked to produce is incomplete.' -Data @{
            reason = [string]$logHealth.Reason; fallback = [string]$logHealth.FallbackKind; failedWrites = $logHealth.FailedWrites
        }
        $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
    }

    # $null is NOT EVALUATED, which is the correct answer for an unelevated run whose log lives in
    # the invoking user's own profile. It must never refuse anything; only a verdict that was
    # actually reached and came back untrusted can.
    # An installation whose two halves were never reconciled is not a state to clean FROM: the
    # registration that started this run and the tree it is running were last touched by a process
    # that did not finish, so neither vouches for the other. An installer under the common lock
    # closes that generation; a cleanup run refuses until one has.
    $settled = Test-WacDeploymentGenerationSettled
    if (-not $settled.Settled) {
        Write-WacLog -Level $script:OutcomeLogLevel['SecurityRefusal'] -Component 'Summary' -Message 'A deployment transaction left outstanding by an earlier installer has not been reconciled, so this run will not mutate anything. Re-run the installer to close it.' -Data @{
            reason = [string]$settled.Reason; outstanding = ((@($settled.Outstanding)) -join ',')
        }
        $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'SecurityRefusal'
    }

    $stateTrust = Get-WacStateTrust
    if ($null -ne $stateTrust -and -not $stateTrust.IsTrusted) {
        Write-WacLog -Level $script:OutcomeLogLevel['SecurityRefusal'] -Component 'Summary' -Message 'The directory holding this run state and audit log is not machine-trusted.' -Data @{
            path = [string]$stateTrust.Path; reason = [string]$stateTrust.Reason
        }
        $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'SecurityRefusal'
    }

    return $outcome
}

function Write-WacRunVerdict {
    <#
    .SYNOPSIS
        Writes the run's Final status line at the level its OUTCOME deserves and returns the exit
        code.
    .DESCRIPTION
        Its own function because a run can end in two places now - the pre-cleanup gate and the
        footer - and both have to leave the same one line behind. Anything reading a run's log finds
        status= and exitCode= exactly once, whichever end it stopped at.
    #>
    param([Parameter(Mandatory = $true)][ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Outcome)

    $script:Stopwatch.Stop()
    $exitCode = [int]$script:OutcomeExitCode[$Outcome]

    Write-WacLog -Level ([string]$script:OutcomeLogLevel[$Outcome]) -Component 'Run' -Message 'Final status.' -Data @{
        status = $Outcome
        exitCode = $exitCode
        elapsed = $script:Stopwatch.Elapsed.ToString('hh\:mm\:ss')
        remainingBudgetMs = (Get-WacRemainingMs)
    }

    return $exitCode
}

function Write-WacRunFooter {
    <#
    .SYNOPSIS
        Writes the run's summary lines and returns the process exit code.
    .DESCRIPTION
        The exit code is the run's WORST outcome, not a count of failures. Incomplete work used to
        exit 0: a run that stopped at its budget, that hit a step deadline, or that could not
        produce the durable audit log it was asked for, all reported success.

        The benign counters are deliberately NOT inputs. A real elevated run scores skipReparse and
        skipOutOfRoot on the shipped allow-list with nothing wrong (measured: 3 and 1), so keying a
        refusal off them would make every healthy run refuse. Only the Refused* pair - a path that
        failed its identity or containment re-check while it was still there - and a non-trusted
        state directory can reach 7.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$TargetResult,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$StepResult,
        [Nullable[Int64]]$FreeBytesBefore,
        [Nullable[Int64]]$FreeBytesAfter,
        [bool]$RebootRequired
    )

    $totals = [ordered]@{
        files = 0L; dirs = 0L; links = 0L; bytes = 0L; queuedForReboot = 0L
        skipLocked = 0L; skipDenied = 0L; skipNotEmpty = 0L; skipReparse = 0L
        skipProtected = 0L; skipOutOfRoot = 0L; skipVanished = 0L; skipDeadline = 0L; failed = 0L
        # The two counters that decide a security refusal, and the two step outcomes that used to be
        # invisible here because the derived Failed flag swallowed them.
        refusedIdentity = 0L; refusedOutOfRoot = 0L; stepIncomplete = 0L; stepRefused = 0L
    }

    foreach ($result in $TargetResult) {
        $totals.files += $result.FilesDeleted
        $totals.dirs += $result.DirectoriesDeleted
        $totals.links += $result.ReparsePointsDeleted
        $totals.bytes += $result.BytesDeleted
        $totals.queuedForReboot += $result.PendingDeletes
        $totals.skipLocked += $result.SkippedLocked
        $totals.skipDenied += $result.SkippedDenied
        $totals.skipNotEmpty += $result.SkippedNotEmpty
        $totals.skipReparse += $result.SkippedReparse
        $totals.skipProtected += $result.SkippedProtected
        $totals.skipOutOfRoot += $result.SkippedOutOfRoot
        $totals.skipVanished += $result.SkippedVanished
        $totals.skipDeadline += $result.SkippedDeadline
        $totals.failed += $result.Failed
        $totals.refusedIdentity += $result.RefusedIdentity
        $totals.refusedOutOfRoot += $result.RefusedOutOfRoot
    }

    $outcome = 'Succeeded'

    # Each step already logged itself through Write-WacStepResult as it completed, so the footer only
    # rolls its outcome into the totals rather than repeating every line.
    foreach ($step in $StepResult) {
        $stepOutcome = Get-WacStepOutcome -Step $step
        $outcome = Get-WacHigherOutcome -Current $outcome -Candidate $stepOutcome

        if ($stepOutcome -ceq 'Failed') { $totals.failed++ }
        elseif ($stepOutcome -ceq 'Incomplete') { $totals.stepIncomplete++ }
        elseif ($stepOutcome -ceq 'SecurityRefusal') { $totals.stepRefused++ }
    }

    if ($totals.failed -gt 0) { $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Failed' }
    if ($totals.skipDeadline -gt 0) { $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete' }
    if (($totals.refusedIdentity + $totals.refusedOutOfRoot) -gt 0) {
        $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'SecurityRefusal'
    }

    $delta = $null
    if ($null -ne $FreeBytesBefore -and $null -ne $FreeBytesAfter) { $delta = [int64]($FreeBytesAfter - $FreeBytesBefore) }
    Write-WacLog -Level INFO -Component 'Summary' -Message 'Free space on C:.' -Data @{
        before = (Format-WacBytes -Bytes $FreeBytesBefore)
        after  = (Format-WacBytes -Bytes $FreeBytesAfter)
        delta  = (Format-WacBytes -Bytes $delta)
    }

    if ($RebootRequired) {
        Write-WacLog -Level WARNING -Component 'Summary' -Message 'A reboot is required to finish at least one cleanup step.'
    }
    if ($totals.queuedForReboot -gt 0) {
        Write-WacLog -Level INFO -Component 'Summary' -Message 'Locked items were queued for deletion at the next boot. Windows only records the pending operation; it does not guarantee the delete will succeed.' -Data @{ queued = $totals.queuedForReboot }
    }

    # Asked again at the end because the budget can expire and the audit log can lose a line while
    # the run is working; the gate before the first mutation asked the same question of the state
    # this run STARTED in.
    $outcome = Get-WacRunLevelOutcome -Current $outcome

    # The totals are written HERE, not where they are computed: they carry refusedIdentity,
    # refusedOutOfRoot, stepIncomplete and stepRefused - the evidence for whatever the verdict
    # turned out to be - so they are written at the verdict's level and cannot outlive it.
    Write-WacLog -Level ([string]$script:OutcomeLogLevel[$outcome]) -Component 'Summary' -Message 'Cleanup totals.' -Data ([hashtable]$totals)

    # The verdict is published as well as returned. The exit code alone cannot name it - 0 is both
    # Succeeded and SafeSkip - so a reader that needs the OUTCOME, such as the machine-readable run
    # summary, would otherwise have to guess which of the two it was.
    $script:FinalOutcome = [string]$outcome

    return (Write-WacRunVerdict -Outcome $outcome)
}
