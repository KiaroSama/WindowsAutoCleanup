<#
.SYNOPSIS
    Running an owned launch to completion, and the verdicts that come out of it.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.OwnedProcess.ps1, which is the MECHANISM: creating a process
    suspended, binding it to a kill-on-close job, resuming it. This file is the POLICY that consumes
    that mechanism - waiting, draining, terminating, and turning three independent facts into the
    shared Invoke-WacProcess result contract.

    They are separated because they fail differently. A mechanism failure is answered by the launch
    State (NeverCreated / Created / Resumed) and decides whether a retry is even legal. A policy
    failure is answered by the result contract - Started, ExitCode, TerminationProven, OutputComplete,
    Owned, OwnedTreeState - and must be produced even when something throws, because a tool that has
    already run cannot be un-run by reporting an exception instead of a result.
#>

$script:OwnedRunFault = $null

function Set-WacOwnedRunFault {
    <#
    .SYNOPSIS
        Arms or clears ONE post-start failure inside the runner. Injects failure only, never success.
    .DESCRIPTION
        The same contract as Set-WacOwnedProcessFault and for the same reason: the window this seam
        reaches - a tool that is ALREADY RUNNING when the runner throws - cannot be produced on
        demand, and a test that replaces the runner would be asserting about the replacement.

        It is null in production and each phase can only make one step FAIL. -Phase None clears it;
        always clear in a finally, or every later launch in the process throws.
    #>
    param([Parameter(Mandatory = $true)][ValidateSet('None', 'ReadAcquire', 'Wait')][string]$Phase)

    $script:OwnedRunFault = if ($Phase -ceq 'None') { $null } else { $Phase }
    return $true
}

function Wait-WacOwnedTreeQuiet {
    <#
    .SYNOPSIS
        Waits, within the remaining run budget, for an owned job to hold no processes.
    .DESCRIPTION
        The root exiting is not the work finishing. A tool that hands its real work to a child -
        several Windows servicing tools do - leaves the root gone and the job still populated, and
        the runner used to drain the pipes for a moment and then CLOSE the job. Closing it fires
        kill-on-close, so a legitimate descendant was killed while the run still had budget left.
        Forced termination belongs to a timeout, an error or a cancellation; it is not what "the
        root returned" means.

        Bounded polling against a deadline, never a blind sleep, and never longer than the budget the
        run has left: an unfinished tree at the end of it is reported Alive, not waited on forever.
    .OUTPUTS
        State (Complete | Alive | Unknown), ActiveProcesses, WaitedMs.
    #>
    param(
        [Parameter(Mandatory = $true)]$Launch,
        [Parameter(Mandatory = $true)][int]$BudgetMs
    )

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $state = Get-WacOwnedTreeState -Launch $Launch

    if ($state.State -cne 'Alive' -or $BudgetMs -le 0) {
        $watch.Stop()
        return [PSCustomObject]@{
            State = [string]$state.State; ActiveProcesses = [int]$state.ActiveProcesses
            WaitedMs = [int]$watch.Elapsed.TotalMilliseconds
        }
    }

    # The STOPWATCH, not UtcNow (ledger WAC-06R). This loop is the last thing standing between a
    # live descendant and the run moving on, and a civil clock moved backwards by an NTP or DST
    # correction extends it by however far it jumped - inside the one wait whose whole purpose is to
    # be bounded. Get-WacRemainingMs made exactly this correction for the run budget; the same clock
    # had been left in here.
    while ($watch.Elapsed.TotalMilliseconds -lt $BudgetMs) {
        Start-Sleep -Milliseconds 100
        $state = Get-WacOwnedTreeState -Launch $Launch
        if ($state.State -cne 'Alive') { break }
    }

    $watch.Stop()
    return [PSCustomObject]@{
        State = [string]$state.State; ActiveProcesses = [int]$state.ActiveProcesses
        WaitedMs = [int]$watch.Elapsed.TotalMilliseconds
    }
}

function Get-WacOwnedTreeState {
    <#
    .SYNOPSIS
        Whether every process in an owned job has finished.
    .DESCRIPTION
        Three answers, never two. 'Complete' is the only one that licenses reclaiming state a
        mutator may still be touching; 'Alive' says something this run started is still running even
        though the root is gone; 'Unknown' is an unreadable job and is not a synonym for either.
    .OUTPUTS
        Complete | Alive | Unknown, and the active count (-1 when unreadable).
    #>
    param([Parameter(Mandatory = $true)]$Launch)

    if ($null -eq $Launch -or -not $Launch.Owned) {
        return [PSCustomObject]@{ State = 'Unknown'; ActiveProcesses = -1 }
    }

    $active = -1
    try { $active = [int][WacOwnedProcess]::ActiveProcessesInJob($Launch.Job) } catch { $active = -1 }

    $state = 'Unknown'
    if ($active -eq 0) { $state = 'Complete' }
    elseif ($active -gt 0) { $state = 'Alive' }

    return [PSCustomObject]@{ State = $state; ActiveProcesses = $active }
}

function Invoke-WacOwnedTool {
    <#
    .SYNOPSIS
        Runs an already-owned launch to completion and returns the shared Invoke-WacProcess contract.
    .DESCRIPTION
        Lives beside the mechanism rather than in Process.ps1 because it IS the mechanism's policy:
        every verdict below is read off the job, and none of it means anything without one.

        Three facts are kept apart, which is the whole point of the ledger item:

          Root exit          - the root process handle is signalled. Says nothing about descendants.
          Owned-tree state   - ActiveProcesses on the job. 'Complete' is the only answer that
                               licenses reclaiming state a mutator may still be touching.
          Output completion  - both pipes reached EOF within the budget. A pipe EOFs only when every
                               write handle closes, so an outstanding read is a second, independent
                               witness that a descendant is alive.

        A timeout is one TerminateJobObject call: the entire tree, no enumeration, no pid, no race
        with a recycled parent id, and nothing unrelated can be caught by it because membership is
        decided by creation, not by a name or a number.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Launch,
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string]$Component = 'Process'
    )

    # ONE DEADLINE FOR THE WHOLE OPERATION, and it is this stopwatch (ledger WAC-06R). -TimeoutMs is
    # what the operation gets in total - root, tree, output capture and the cleanup after them - not
    # what each of those phases gets in turn. Before this, a root that exited normally just inside
    # its bound handed the tree another full TimeoutMs, and each pipe drain took its own grant on
    # top, so one "30 second" tool could legitimately occupy a minute and a half.
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $operationBudgetMs = [int]$TimeoutMs

    # Closes over the stopwatch, so every later phase asks the same monotonic clock what is left.
    $remaining = { [int][Math]::Max(0, $operationBudgetMs - $stopwatch.Elapsed.TotalMilliseconds) }

    $outReader = New-Object System.IO.StreamReader($Launch.StandardOutput, [System.Text.Encoding]::UTF8)
    $errReader = New-Object System.IO.StreamReader($Launch.StandardError, [System.Text.Encoding]::UTF8)
    $outTask = $outReader.ReadToEndAsync()
    $errTask = $errReader.ReadToEndAsync()

    if ($script:OwnedRunFault -ceq 'ReadAcquire') {
        throw ('injected runner failure while acquiring the output reads of {0}' -f $FilePath)
    }

    # Reclamped immediately before the wait: acquiring the readers above is cheap but not free, and
    # a phase that starts from the ORIGINAL number has already overrun by whatever preceded it.
    $exited = [WacOwnedProcess]::WaitForExit($Launch.Process, (& $remaining))
    if ($script:OwnedRunFault -ceq 'Wait') {
        throw ('injected runner failure while waiting for {0}' -f $FilePath)
    }
    $timedOut = -not $exited
    $killedJob = $false
    $walkProven = $false

    if ($timedOut) {
        Write-WacLog -Level WARNING -Component $Component -Message 'External tool exceeded its deadline; terminating what this run owns.' -Data @{
            tool = $FilePath; pid = $Launch.ProcessId; timeoutMs = $TimeoutMs; owned = [bool]$Launch.Owned
        }

        if ($Launch.Owned) {
            $killedJob = [bool][WacOwnedProcess]::TerminateJob($Launch.Job)
        }
        else {
            # A job-less launch has no job to terminate, and calling TerminateJob(0) simply answered
            # $false while the tool kept running - a timed-out root that was never stopped at all.
            # Without a job the only honest stop is the handle-binding walk, and ITS verdict is what
            # gets reported: a degraded launch behaves exactly like the managed fallback, and Owned
            # says which one produced the answer.
            $stopped = Stop-WacProcessTree -ProcessId $Launch.ProcessId -TimeoutMs (Request-WacWaitMs -RequestedMs 10000)
            $walkProven = [bool]$stopped.Proven
            if (-not $walkProven) {
                Write-WacLog -Level CRITICAL -Component $Component -Message 'An unowned tool could not be proven terminated; part of its tree may still be running.' -Data @{
                    tool = $FilePath; pid = $Launch.ProcessId
                    survivors = (@($stopped.Survivor) -join ','); reason = [string]$stopped.Reason
                }
            }
        }

        # Even the wait that confirms a termination is charged. It is the last thing a run does for
        # a tool it has already given up on, so it draws from the recovery reserve like any other
        # shutdown work rather than adding a flat ten seconds per tool to a budget already spent.
        [void][WacOwnedProcess]::WaitForExit($Launch.Process, (Request-WacWaitMs -RequestedMs 10000))
    }

    $exitCode = $null
    if (-not $timedOut) {
        try { $exitCode = [WacOwnedProcess]::GetExitCode($Launch.Process) } catch { $exitCode = $null }
    }

    # THE LIFECYCLE IS SETTLED BEFORE THE OUTPUT IS FINALISED (ledger WAC-05R). The reads have been
    # running since before the root was waited on, so nothing here starts a drain - but the ANSWER
    # used to be taken before the tree was given its time to finish. A child that held a pipe a
    # little longer than the drain allowance and then exited well inside the tree allowance was
    # recorded as incomplete output and an EMPTY STRING, which a caller parsing stdout reads as a
    # real, empty answer. Settle what is alive first; read what arrived once, afterwards.
    #
    # The job is also more truthful here than it was earlier: by now the root's own accounting has
    # settled, so a job that still reports members is reporting real descendants rather than a
    # not-yet-reaped root. A populated job after a CLEAN root exit gets the rest of the operation to
    # empty rather than being killed by the job handle closing - only a timeout, an error or a
    # cancellation may terminate.
    if ($timedOut) {
        $tree = Get-WacOwnedTreeState -Launch $Launch
    }
    else {
        # What is LEFT of this operation, not another TimeoutMs. A descendant still alive when that
        # runs out is reported Alive and the verdict below refuses to call the tool settled - which
        # is the honest answer for an operation that has reached its deadline.
        $tree = Wait-WacOwnedTreeQuiet -Launch $Launch -BudgetMs (Get-WacStepTimeoutMs -RequestedMs (& $remaining))
        if ([int]$tree.WaitedMs -gt 0) {
            Write-WacLog -Level DEBUG -Component $Component -Message 'The root exited while owned work continued; waited for the job inside the remaining budget.' -Data @{
                tool = $FilePath; waitedMs = [int]$tree.WaitedMs; state = [string]$tree.State
                activeProcesses = [int]$tree.ActiveProcesses
            }
        }
    }
    if (-not $timedOut -and [string]$tree.State -ceq 'Alive' -and (& $remaining) -le 0) {
        $timedOut = $true
        $exitCode = $null
        $killedJob = [bool][WacOwnedProcess]::TerminateJob($Launch.Job)
        $tree = Wait-WacOwnedTreeQuiet -Launch $Launch -BudgetMs (Request-WacWaitMs -RequestedMs 5000)
    }
    # ONE allowance, ONE deadline, BOTH pipes, and only now. Request-WacWaitMs CLAIMS what it grants
    # - that is the whole point of a reserve that cannot refill - so passing the same grant to two
    # waits spent the reservation once and consumed it twice, up to double what the run had set
    # aside. The grant becomes a deadline and each wait takes only what is still left of it.
    $drainGrantMs = Request-WacWaitMs -RequestedMs ([Math]::Min(5000, [Math]::Max(0, (& $remaining))))
    $drainWatch = [System.Diagnostics.Stopwatch]::StartNew()
    [void]$outTask.Wait([int][Math]::Max(0, $drainGrantMs - $drainWatch.Elapsed.TotalMilliseconds))
    [void]$errTask.Wait([int][Math]::Max(0, $drainGrantMs - $drainWatch.Elapsed.TotalMilliseconds))
    $drainWatch.Stop()
    $readBudgetMs = $drainGrantMs

    # RanToCompletion, not IsCompleted. IsCompleted is true for a task that FAULTED or was cancelled
    # as well as one that succeeded, so a read that threw was being reported as complete output and
    # then had its .Result accessed - which rethrows. "It finished" and "it worked" are two facts.
    $outOk = ($outTask.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion)
    $errOk = ($errTask.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion)
    $outputComplete = ($outOk -and $errOk)
    $stdout = if ($outOk) { [string]$outTask.Result } else { '' }
    $stderr = if ($errOk) { [string]$errTask.Result } else { '' }

    if (-not $outputComplete -and ($outTask.IsFaulted -or $errTask.IsFaulted)) {
        Write-WacLog -Level WARNING -Component $Component -Message 'An output read failed rather than finishing, so the tool output is not the whole output.' -Data @{
            tool = $FilePath; stdoutStatus = [string]$outTask.Status; stderrStatus = [string]$errTask.Status
        }
    }

    if ($Launch.Owned) {
        $terminationProven = ($tree.State -ceq 'Complete')
    }
    elseif ($timedOut) {
        # The walk's own answer, never an assumption.
        $terminationProven = $walkProven
    }
    else {
        # The root exited on its own and there is no job to ask about descendants. The pipe is the
        # only witness left: if it reached EOF nothing this run started still holds it.
        $terminationProven = $outputComplete
    }

    if (-not $terminationProven) {
        Write-WacLog -Level CRITICAL -Component $Component -Message 'The owned job still holds live processes, so the tool cannot be reported as stopped.' -Data @{
            tool = $FilePath; pid = $Launch.ProcessId; treeState = [string]$tree.State
            activeProcesses = [int]$tree.ActiveProcesses; timedOut = $timedOut; jobTerminated = $killedJob
        }
    }
    elseif (-not $outputComplete) {
        # The job is empty and a read still has not finished. Nothing this run owns can be holding
        # the pipe, so the handle went to something outside the job - a service or COM activation
        # started on our behalf. The output is still not the whole output, and the verdict says so.
        Write-WacLog -Level WARNING -Component $Component -Message 'The owned tree finished but an output pipe is still held, so a process outside the job inherited it.' -Data @{
            tool = $FilePath; pid = $Launch.ProcessId; readBudgetMs = $readBudgetMs
        }
    }

    $stopwatch.Stop()
    return [PSCustomObject]@{
        ExitCode = $exitCode
        TimedOut = $timedOut
        StandardOutput = $stdout
        StandardError = $stderr
        DurationMs = [int]$stopwatch.Elapsed.TotalMilliseconds
        Started = $true
        TerminationProven = $terminationProven
        OutputComplete = $outputComplete
        # Ownership is reported, never assumed: a caller that needs to know whether the verdict above
        # rests on a job or on a best-effort walk can ask.
        Owned = [bool]$Launch.Owned
        OwnedTreeState = [string]$tree.State
    }
}
