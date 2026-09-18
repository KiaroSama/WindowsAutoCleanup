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
        # The runspace opens with NOTHING of ours in it, and the modules are imported by the FIRST
        # statement of the bounded pipeline instead of by the InitialSessionState.
        #
        # Three attempts got here. ImportPSModule with a synchronous Open() imports reliably but
        # blocks: a module whose top-level code hangs hangs the open, so the promised bound was never
        # returned within (measured 8293 ms for an 800 ms bound). OpenAsync makes the open
        # interruptible but not the import - RunspaceStateInfo says Opened and RunspaceAvailability
        # says Available while the import is still in flight, and a probe pipeline runs fine and
        # still cannot see the imported commands, so work started against a runspace whose modules
        # were missing ("The term 'Get-WacCleanupTarget' is not recognized"). Polling for the module
        # names instead simply spent the whole budget waiting and got a full run force-killed.
        #
        # Importing inside the pipeline makes the import subject to the ONE bound this function
        # already enforces, which is what was wanted all along: a blocked import is now abandoned by
        # exactly the same path as a blocked work item.
        $state = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
        $runspace = [runspacefactory]::CreateRunspace($state)
        $runspace.Open()

        # ONE AddScript, still. The header records why a batched pipeline is not an option: it turns
        # a throw into an error-stream record, and abandoning a batched pipeline crashes the host at
        # process exit. The wrapper therefore carries the import AND the caller's block, and the
        # block is rebuilt from its own text so its param() is still the first statement of ITS
        # scriptblock rather than of this one.
        $wrapper = @'
param($WacModulePath, $WacSource, $WacArgument)
foreach ($module in @($WacModulePath)) {
    if ([string]::IsNullOrWhiteSpace($module)) { continue }
    Import-Module -Name $module -DisableNameChecking -ErrorAction Stop
}
& ([scriptblock]::Create($WacSource)) @WacArgument
'@

        $shell = [powershell]::Create()
        $shell.Runspace = $runspace
        [void]$shell.AddScript($wrapper)
        [void]$shell.AddArgument([string[]]$modules.ToArray())
        [void]$shell.AddArgument($ScriptBlock.ToString())
        [void]$shell.AddArgument([object[]]$ArgumentList)

        # The budget was measured before the runspace existed. Creating one, opening it and
        # opening it costs ~80-100 ms on both hosts and more on a cold or contended machine. The
        # module import no longer happens here at all - it is the first statement of the pipeline
        # below, so it is bounded by the same wait as the work.
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
                # InProcess, and this is the ONLY caller entitled to say so: the work is a
                # scriptblock on a runspace inside this process, so it cannot outlive it. Every other
                # abandonment hands work to something that can.
                [void](Add-WacAbandonedMutator -Kind 'InProcess' `
                    -Reason ('{0} exceeded its {1} ms bound' -f $Component, $budgetMs))
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
