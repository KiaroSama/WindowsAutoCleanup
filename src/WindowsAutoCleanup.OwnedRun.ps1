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

    $deadline = [datetime]::UtcNow.AddMilliseconds($BudgetMs)
    while ([datetime]::UtcNow -lt $deadline) {
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

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $outReader = New-Object System.IO.StreamReader($Launch.StandardOutput, [System.Text.Encoding]::UTF8)
    $errReader = New-Object System.IO.StreamReader($Launch.StandardError, [System.Text.Encoding]::UTF8)
    $outTask = $outReader.ReadToEndAsync()
    $errTask = $errReader.ReadToEndAsync()

    $exited = [WacOwnedProcess]::WaitForExit($Launch.Process, $TimeoutMs)
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
            $stopped = Stop-WacProcessTree -ProcessId $Launch.ProcessId
            $walkProven = [bool]$stopped.Proven
            if (-not $walkProven) {
                Write-WacLog -Level CRITICAL -Component $Component -Message 'An unowned tool could not be proven terminated; part of its tree may still be running.' -Data @{
                    tool = $FilePath; pid = $Launch.ProcessId
                    survivors = (@($stopped.Survivor) -join ','); reason = [string]$stopped.Reason
                }
            }
        }

        [void][WacOwnedProcess]::WaitForExit($Launch.Process, 10000)
    }

    # Same accounting rule as the unowned path: the read waits are part of the run budget, not an
    # extra ten seconds per tool on top of it.
    $readBudgetMs = Get-WacStepTimeoutMs -RequestedMs 5000
    if ($readBudgetMs -lt 250) { $readBudgetMs = 250 }
    [void]$outTask.Wait($readBudgetMs)
    [void]$errTask.Wait($readBudgetMs)

    $outputComplete = ($outTask.IsCompleted -and $errTask.IsCompleted)
    $stdout = if ($outTask.IsCompleted) { [string]$outTask.Result } else { '' }
    $stderr = if ($errTask.IsCompleted) { [string]$errTask.Result } else { '' }

    $exitCode = $null
    if (-not $timedOut) {
        try { $exitCode = [WacOwnedProcess]::GetExitCode($Launch.Process) } catch { $exitCode = $null }
    }

    # Queried AFTER the reads on purpose: by then the root's own accounting has settled, so a job
    # that still reports members is reporting real descendants rather than a not-yet-reaped root.
    #
    # And when it IS still populated after a clean root exit, the work gets the rest of the run's
    # budget to finish rather than being killed by the job handle closing. Only a timeout, an error
    # or a cancellation may terminate; a root that returned while its child still works is not one.
    if ($timedOut) {
        $tree = Get-WacOwnedTreeState -Launch $Launch
    }
    else {
        $tree = Wait-WacOwnedTreeQuiet -Launch $Launch -BudgetMs (Get-WacStepTimeoutMs -RequestedMs $TimeoutMs)
        if ([int]$tree.WaitedMs -gt 0) {
            Write-WacLog -Level DEBUG -Component $Component -Message 'The root exited while owned work continued; waited for the job inside the remaining budget.' -Data @{
                tool = $FilePath; waitedMs = [int]$tree.WaitedMs; state = [string]$tree.State
                activeProcesses = [int]$tree.ActiveProcesses
            }
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
