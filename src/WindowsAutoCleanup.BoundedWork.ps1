<#
.SYNOPSIS
    In-process work under a real wall-clock bound, in its own runspace.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Process.ps1. Split out of it because the two answer different
    questions with different mechanisms: that file runs EXTERNAL tools, which this project owns from
    creation through a job object and can therefore prove it stopped. This one runs work inside this
    process, where the only bound available is "stop waiting", and a thread wedged in a blocking
    native call cannot be interrupted at all.

    That asymmetry is the whole reason for the abandoned-mutator guard below, and for the rule that
    a bounded block should hold one blocking call and leave the logic outside it.
#>

# ---------------------------------------------------------------------------------------------
# Bounded in-process work
# ---------------------------------------------------------------------------------------------

function Invoke-WacBounded {
    <#
    .SYNOPSIS
        Runs IN-PROCESS work under a real wall-clock bound and returns a shared-contract outcome.
    .DESCRIPTION
        The run budget used to cover only external tools and the traversal loop. Everything else -
        the Delivery Optimization cmdlet, a CIM/WMI profile query, registry work, a Recycle Bin
        scan, target construction, a deployment walk - runs inside this process, and a call that
        blocks in the OS blocks every deadline check sitting behind it. A 210-minute budget can be
        blown by one of them without a single clock read.

        Cooperative checking cannot fix that, because the thread never comes back to check. So the
        work runs in its own runspace and the caller waits on a handle: expiry is a real bound, not
        a request. Measured cost of the runspace on BOTH shipped hosts: ~80 ms bare, ~100 ms with
        this module imported into it. That is fine per PHASE and far too expensive per file - this
        is for phase-level blocking calls, never for the traversal loop's inner steps.

        Expiry is NOT success. The outcome is 'Incomplete', which the shared result contract maps to
        exit code 6. An exhausted run budget also refuses to START the work, which is what "stop
        scheduling new work" means; a bounded rollback that must still run after expiry passes
        -IgnoreRunBudget and supplies its own explicit bound.

        The pipeline holds exactly ONE AddScript, and that is not cosmetic. Arming strict mode as a
        separate first statement was tried and had to be rejected on measured evidence:

          * AddScript / AddStatement / AddScript turns a THROW inside the block into an ordinary
            error-stream record instead of an exception out of EndInvoke, so a broken step reported
            Succeeded;
          * with a batched pipeline, abandoning a blocked runspace crashes the HOST at process exit
            when the worker wakes into a closing runspace - measured on both hosts, pwsh exited
            -532462766 (unhandled InvalidRunspaceStateException from BatchInvocationWorkItem) and
            Windows PowerShell 5.1 exited 2. A single AddScript exits 0 in the same scenario.

        Prefixing the block's own text is not an alternative either: a param() block has to be the
        first statement in a script. So a bounded block runs WITHOUT strict mode, which is one more
        reason to keep it down to the single blocking call and leave the logic outside.

        A terminating error is Failed. A non-terminating one leaves Outcome Succeeded with
        HadErrors set and Error populated - reported, never swallowed, and the caller decides.

        ponytail: a runspace whose thread is stuck inside a blocking NATIVE call is abandoned rather
        than aborted - PowerShell.Stop() cannot interrupt one and Thread.Abort does not exist on
        .NET Core. Measured cost of one abandoned call: 2-3 threads until the process exits. That is
        the right trade for a tool that runs once a day and then leaves; if a caller ever abandons
        many, move that work to a child process and kill it with Stop-WacProcessTree instead.
    .OUTPUTS
        Outcome (Succeeded | Incomplete | Failed), Started, TimedOut, Output, HadErrors, Error,
        DurationMs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [AllowEmptyCollection()][object[]]$ArgumentList = @(),
        [AllowEmptyCollection()][string[]]$ImportModule = @(),
        [string]$Component = 'Bounded',
        [switch]$IgnoreRunBudget,
        # Declares that this block WRITES. Abandoning a mutator is not termination, so an abandoned
        # one closes the door on every later mutation in the run instead of letting the next one
        # start on top of it. Reads are unaffected: abandoning a blocked CIM query costs threads,
        # not correctness.
        [switch]$Mutating
    )

    if ($Mutating -and -not (Test-WacMutationAllowed)) {
        Write-WacLog -Level ERROR -Component $Component -Message 'A mutating block was refused because an earlier one was abandoned and cannot be proven stopped.' -Data @{
            abandoned = (Get-WacAbandonedMutatorCount)
        }
        return [PSCustomObject]@{
            Outcome = 'Incomplete'; Started = $false; TimedOut = $false
            Output = @(); HadErrors = $false
            Error = 'An earlier mutating block was abandoned and may still be running, so this one was not started.'
            DurationMs = 0
        }
    }

    $budgetMs = $TimeoutMs
    if ($IgnoreRunBudget) {
        # Ignoring the RUN budget is not the same as having no bound (ledger WAC-06R). Recovery work
        # draws from the run's single shutdown reserve, so a rollback still gets time after expiry
        # while twenty of them cannot add up to an unbounded shutdown.
        $budgetMs = Request-WacShutdownReserveMs -RequestedMs $TimeoutMs
    }
    else { $budgetMs = Get-WacStepTimeoutMs -RequestedMs $TimeoutMs }

    if ($budgetMs -le 0) {
        $exhausted = 'Run budget exhausted before the work could be scheduled.'
        if ($IgnoreRunBudget) { $exhausted = 'The recovery reserve is spent, so this rollback could not be scheduled.' }
        Write-WacLog -Level WARNING -Component $Component -Message $exhausted -Data @{ requestedMs = $TimeoutMs; recovery = [bool]$IgnoreRunBudget }
        return [PSCustomObject]@{
            Outcome = 'Incomplete'; Started = $false; TimedOut = $true
            Output = @(); HadErrors = $false
            Error = $exhausted
            DurationMs = 0
        }
    }

    $modules = New-Object 'System.Collections.Generic.List[string]'
    if ($script:CoreModulePath) { [void]$modules.Add($script:CoreModulePath) }
    foreach ($module in $ImportModule) {
        if (-not [string]::IsNullOrWhiteSpace($module)) { [void]$modules.Add($module) }
    }

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $runspace = $null
    $shell = $null
    $abandoned = $false

    try {
        $state = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
        if ($modules.Count -gt 0) { $state.ImportPSModule([string[]]$modules.ToArray()) }

        $runspace = [runspacefactory]::CreateRunspace($state)

        # OpenAsync, not Open. Charging the setup to the budget afterwards measured the overshoot; it
        # did not BOUND it. A module whose top-level code blocks forever made Open() block forever
        # too, and the promised bound was never returned within - the call simply came back whenever
        # initialization finished, which for a wedged initializer is never.
        #
        # Opening on its own thread lets the caller give up on it. An initializer that has not
        # finished inside the bound is ABANDONED exactly the way a wedged work item is: not disposed,
        # because disposing waits for the very thing that is stuck.
        $runspace.OpenAsync()

        # BOTH signals. RunspaceStateInfo reaches Opened while the InitialSessionState's own module
        # import is still running on it, and handing that runspace a pipeline answers "a pipeline is
        # already running". Availability is what says the runspace will actually accept work.
        $openDeadline = [datetime]::UtcNow.AddMilliseconds([Math]::Max(1, $budgetMs))
        $opened = $false
        while ([datetime]::UtcNow -lt $openDeadline) {
            $openState = $runspace.RunspaceStateInfo.State
            if ($openState -eq [System.Management.Automation.Runspaces.RunspaceState]::Opened -and
                $runspace.RunspaceAvailability -eq [System.Management.Automation.Runspaces.RunspaceAvailability]::Available) {
                $opened = $true
                break
            }
            if ($openState -eq [System.Management.Automation.Runspaces.RunspaceState]::Broken -or
                $openState -eq [System.Management.Automation.Runspaces.RunspaceState]::Closed) { break }
            Start-Sleep -Milliseconds 20
        }

        if (-not $opened) {
            $abandoned = $true
            $watch.Stop()
            $openState = '{0}/{1}' -f [string]$runspace.RunspaceStateInfo.State, [string]$runspace.RunspaceAvailability
            if ($Mutating) { [void](Add-WacAbandonedMutator) }

            Write-WacLog -Level WARNING -Component $Component -Message 'The bounded work could not be initialised inside its bound; it was abandoned rather than waited on.' -Data @{
                budgetMs = $budgetMs; runspaceState = $openState; mutating = [bool]$Mutating
            }
            return [PSCustomObject]@{
                Outcome = 'Incomplete'; Started = $false; TimedOut = $true
                Output = @(); HadErrors = $false
                Error = ('Preparing the bounded work did not complete within {0} ms (runspace state {1}).' -f $budgetMs, $openState)
                DurationMs = [int]$watch.Elapsed.TotalMilliseconds
            }
        }

        $shell = [powershell]::Create()
        $shell.Runspace = $runspace
        [void]$shell.AddScript($ScriptBlock.ToString())
        foreach ($argument in $ArgumentList) { [void]$shell.AddArgument($argument) }

        # The budget was measured before the runspace existed. Creating one, opening it and
        # importing this module is SYNCHRONOUS and costs ~80-100 ms on both hosts - more on a cold
        # or contended machine, and an arbitrary amount when a module's own top-level code blocks.
        # Waiting the ORIGINAL budget after that makes this call's real upper bound "setup + budget"
        # rather than "budget", which is precisely the accounting hole the run deadline exists to
        # close. Charge the setup to the same budget and reclamp against the live deadline here,
        # immediately before the work is scheduled, not at the top of the function.
        $setupMs = [int]$watch.Elapsed.TotalMilliseconds
        $waitMs = $budgetMs - $setupMs
        if (-not $IgnoreRunBudget) { $waitMs = Get-WacStepTimeoutMs -RequestedMs $waitMs }

        if ($waitMs -le 0) {
            # Nothing has been invoked, so there is nothing to abandon: the runspace disposes
            # normally in the finally block and the machine is untouched.
            $watch.Stop()
            Write-WacLog -Level WARNING -Component $Component -Message 'Preparation consumed the whole bound, so the work was never scheduled.' -Data @{ budgetMs = $budgetMs; setupMs = $setupMs }
            return [PSCustomObject]@{
                Outcome = 'Incomplete'; Started = $false; TimedOut = $true
                Output = @(); HadErrors = $false
                Error = ('Preparing the bounded work used {0} ms of its {1} ms bound, so nothing was started.' -f $setupMs, $budgetMs)
                DurationMs = [int]$watch.Elapsed.TotalMilliseconds
            }
        }

        $handle = $shell.BeginInvoke()

        if (-not $handle.AsyncWaitHandle.WaitOne($waitMs)) {
            $abandoned = $true
            try { [void]$shell.BeginStop($null, $null) } catch { $null = $_ }
            $watch.Stop()

            # BeginStop is a REQUEST. A thread inside a blocking native call never comes back to
            # honour it, so a mutator abandoned here may still be writing - and nothing in this
            # process can ever observe it finishing. The run stops scheduling mutations rather than
            # racing one it cannot see.
            if ($Mutating) {
                [void](Add-WacAbandonedMutator)
                Write-WacLog -Level CRITICAL -Component $Component -Message 'A mutating block was abandoned and cannot be proven stopped; no further mutation will be scheduled.' -Data @{
                    budgetMs = $budgetMs; waitMs = $waitMs
                }
            }

            Write-WacLog -Level WARNING -Component $Component -Message 'In-process work exceeded its bound and was abandoned.' -Data @{ budgetMs = $budgetMs; setupMs = $setupMs; waitMs = $waitMs }
            return [PSCustomObject]@{
                Outcome = 'Incomplete'; Started = $true; TimedOut = $true
                Output = @(); HadErrors = $false
                Error = ('The work did not finish within {0} ms.' -f $waitMs)
                DurationMs = [int]$watch.Elapsed.TotalMilliseconds
            }
        }

        $output = @()
        $failure = $null
        try {
            $output = @($shell.EndInvoke($handle))
        }
        catch {
            # A terminating error inside the block surfaces HERE, wrapped, not in the error stream.
            $failure = [string]$_.Exception.Message
        }

        $errors = @()
        try { $errors = @($shell.Streams.Error) } catch { $errors = @() }

        $watch.Stop()
        $outcome = 'Succeeded'
        if ($failure) { $outcome = 'Failed' }

        $errorText = $failure
        if (-not $errorText -and $errors.Count -gt 0) {
            $errorText = (@($errors | ForEach-Object { [string]$_ }) -join '; ')
        }

        return [PSCustomObject]@{
            Outcome = $outcome; Started = $true; TimedOut = $false
            Output = $output; HadErrors = ($errors.Count -gt 0)
            Error = $errorText
            DurationMs = [int]$watch.Elapsed.TotalMilliseconds
        }
    }
    catch {
        $watch.Stop()
        Write-WacLog -Level WARNING -Component $Component -Message 'Bounded work could not be started.' -Data @{ error = $_.Exception.Message }
        return [PSCustomObject]@{
            Outcome = 'Failed'; Started = $false; TimedOut = $false
            Output = @(); HadErrors = $true
            Error = [string]$_.Exception.Message
            DurationMs = [int]$watch.Elapsed.TotalMilliseconds
        }
    }
    finally {
        # Disposing either object waits for the pipeline, so an abandoned runspace must be left
        # alone: cleaning it up here would reintroduce exactly the unbounded wait this function
        # exists to prevent.
        if (-not $abandoned) {
            if ($shell) { try { $shell.Dispose() } catch { $null = $_ } }
            if ($runspace) { try { $runspace.Dispose() } catch { $null = $_ } }
        }
    }
}
