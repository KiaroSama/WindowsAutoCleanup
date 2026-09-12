<#
.SYNOPSIS
    Bounded execution: external tools, the payloads a relaunched child runs, in-process work in its
    own runspace, and the machine-wide single-instance lock.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Core.psm1; see that file for why the parts are dot-sourced
    rather than imported. Everything here answers the same question - how does this run start work
    it does not control and hold it to a deadline - so the command-line quoting the child is handed,
    the deadline the tool is given and the mutex that stops a second run starting at all belong on
    one page.

    The other half of that sentence - proving the work STOPPED - grew its own evidence model and
    now lives in WindowsAutoCleanup.ProcessTree.ps1, dot-sourced from here.
#>

$script:ProcessInvoker = $null

# Proving a tree is dead is its own responsibility and its own file; see the header there.
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.ProcessTree.ps1')

# ---------------------------------------------------------------------------------------------
# Bounded external process execution
# ---------------------------------------------------------------------------------------------

function ConvertTo-WacCommandLineArgument {
    <#
    .SYNOPSIS
        Quotes one argument per the CommandLineToArgvW rules.
    .DESCRIPTION
        ProcessStartInfo.ArgumentList does not exist on .NET Framework, so Windows PowerShell 5.1
        must be handed a single command-line string. Building that string by hand is exactly where
        injection and "path with spaces" defects come from, so it happens in one tested place.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')

    for ($i = 0; $i -lt $Value.Length; $i++) {
        $backslashes = 0
        while ($i -lt $Value.Length -and $Value[$i] -eq '\') { $backslashes++; $i++ }

        if ($i -eq $Value.Length) {
            [void]$builder.Append('\', $backslashes * 2)
            break
        }
        elseif ($Value[$i] -eq '"') {
            [void]$builder.Append('\', $backslashes * 2 + 1)
            [void]$builder.Append('"')
        }
        else {
            [void]$builder.Append('\', $backslashes)
            [void]$builder.Append($Value[$i])
        }
    }

    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-WacCommandLine {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ArgumentList)

    if ($ArgumentList.Count -eq 0) { return '' }
    return (($ArgumentList | ForEach-Object { ConvertTo-WacCommandLineArgument -Value $_ }) -join ' ')
}

function ConvertTo-WacPowerShellLiteral {
    <#
    .SYNOPSIS
        Wraps a value as a single-quoted PowerShell string literal.
    .DESCRIPTION
        A single-quoted literal is inert - PowerShell expands nothing inside it - so escaping the
        characters that CLOSE it is the whole rule. Everything interpolated into a -Command payload
        goes through here, so a value must never terminate the literal and become code.

        The escape is delegated to CodeGeneration::EscapeSingleQuotedStringContent rather than
        hand-written, because the parser closes a single-quoted literal on MORE than the ASCII
        apostrophe: U+2018 and U+2019 terminate it too. The previous `-replace "'", "''"` doubled
        only the ASCII one, so an ordinary path was enough to break the boundary - measured on both
        hosts, `C:\O<U+2019>Neil\Run.ps1` encoded to 'C:\O<U+2019>Neil\Run.ps1' and the parser
        answered "The string is missing the terminator". Office and OneDrive autocorrect an ASCII
        apostrophe into U+2019 inside user and folder names, so this was reachable without any
        crafted input, and crafted input could close the literal and append code.

        The API ships with both supported hosts (verified on Windows PowerShell 5.1 and PowerShell 7)
        and is the same one PowerShell itself uses when it renders a literal.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Value)

    if ($null -eq $Value) { return "''" }
    return ("'" + [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($Value) + "'")
}

function Get-WacRelaunchCommand {
    <#
    .SYNOPSIS
        The PowerShell source a relaunched child executes. Pure, so it can be asserted on directly.
    .DESCRIPTION
        Boolean switches are always emitted in the explicit -Name:$true / -Name:$false form, so the
        child can never fall back to a default the parent did not ask for (ledger P0-2). Keys are
        emitted in sorted order so a test can assert on the exact string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [hashtable]$BooleanSwitch = @{},
        [AllowEmptyCollection()][string[]]$PresentSwitch = @(),
        [hashtable]$NamedValue = @{},
        [hashtable]$ArrayValue = @{}
    )

    $parts = New-Object 'System.Collections.Generic.List[string]'
    [void]$parts.Add('&')
    [void]$parts.Add((ConvertTo-WacPowerShellLiteral -Value $ScriptPath))

    foreach ($name in @($BooleanSwitch.Keys | Sort-Object)) {
        [void]$parts.Add(('-{0}:${1}' -f $name, ([bool]$BooleanSwitch[$name]).ToString().ToLowerInvariant()))
    }

    foreach ($name in @($PresentSwitch | Sort-Object)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        [void]$parts.Add(('-{0}' -f $name))
    }

    foreach ($name in @($NamedValue.Keys | Sort-Object)) {
        [void]$parts.Add(('-{0}' -f $name))
        [void]$parts.Add((ConvertTo-WacPowerShellLiteral -Value ([string]$NamedValue[$name])))
    }

    foreach ($name in @($ArrayValue.Keys | Sort-Object)) {
        $values = @($ArrayValue[$name] | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($values.Count -eq 0) { continue }
        [void]$parts.Add(('-{0}' -f $name))
        [void]$parts.Add((($values | ForEach-Object { ConvertTo-WacPowerShellLiteral -Value ([string]$_) }) -join ','))
    }

    # Two halves, both load-bearing:
    #   * the child script ends with `exit <code>`, which leaves the HOST at its default 0 unless the
    #     code is re-raised, so the payload ends by re-raising it;
    #   * $LASTEXITCODE is UNDEFINED until something sets it, and `exit $null` is exit 0 - so a child
    #     that never ran at all (missing file, parameter-binding failure) would report SUCCESS.
    #     Seeding it with 1 first means the default answer is failure and only the child can change it.
    return ('$LASTEXITCODE = 1; ' + ($parts -join ' ') + '; exit $LASTEXITCODE')
}

function Get-WacRelaunchArgument {
    <#
    .SYNOPSIS
        The child argument VECTOR for an elevated relaunch or a scheduled-task action.
    .DESCRIPTION
        -Command, not -File, and that is load-bearing rather than a style choice.

        Measured on this machine against a `[switch]$Flag = $true` script:

            host             -File "s.ps1" -Flag:$false     -Command "& 's.ps1' -Flag:$false"
            powershell.exe   exit 1, binding error          exit 0, Flag=False
            pwsh 7           exit 0, Flag=False             exit 0, Flag=False

        With -File every token after the script path is a literal STRING, and Windows PowerShell 5.1
        refuses to convert one into a SwitchParameter, so a valued switch cannot be expressed at all.
        There is NO -File spelling that carries "false" to both hosts. Because both the relaunch host
        and the scheduled-task host are powershell.exe whenever PowerShell 7 is absent, keeping -File
        would have made the ledger P0-2 fix work only on machines that happen to have pwsh 7 - and on
        every other machine the child would die during parameter binding before it could open a log.

        -Command is parsed by PowerShell, so the explicit form binds on both hosts, arrays arrive as
        real arrays instead of one comma-joined string, and `exit $LASTEXITCODE` carries the child's
        real exit code back. Everything interpolated into the payload is emitted through
        ConvertTo-WacPowerShellLiteral, and the payload deliberately contains no double quote, so
        quoting it for CreateProcess stays one unambiguous step.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [hashtable]$BooleanSwitch = @{},
        [AllowEmptyCollection()][string[]]$PresentSwitch = @(),
        [hashtable]$NamedValue = @{},
        [hashtable]$ArrayValue = @{},
        [AllowEmptyCollection()][string[]]$HostSwitch = @()
    )

    $arguments = New-Object 'System.Collections.Generic.List[string]'
    [void]$arguments.Add('-NoProfile')
    [void]$arguments.Add('-ExecutionPolicy')
    [void]$arguments.Add('Bypass')
    foreach ($switch in $HostSwitch) {
        if ([string]::IsNullOrWhiteSpace($switch)) { continue }
        [void]$arguments.Add($switch)
    }
    [void]$arguments.Add('-Command')
    [void]$arguments.Add((Get-WacRelaunchCommand -ScriptPath $ScriptPath -BooleanSwitch $BooleanSwitch `
        -PresentSwitch $PresentSwitch -NamedValue $NamedValue -ArrayValue $ArrayValue))

    return @($arguments.ToArray())
}


function Set-WacProcessInvoker {
    <#
    .SYNOPSIS
        Replaces the real process runner. This is the injection seam that lets tests exercise DISM,
        pnputil and cleanmgr behaviour without ever running them.
    .DESCRIPTION
        The scriptblock receives (FilePath, ArgumentList, TimeoutMs) and must return an object with
        ExitCode, TimedOut, StandardOutput, StandardError and DurationMs. Pass $null to restore the
        real runner.
    #>
    param([scriptblock]$Invoker)
    $script:ProcessInvoker = $Invoker
}

function Get-WacProcessInvoker { return $script:ProcessInvoker }

function Invoke-WacProcess {
    <#
    .SYNOPSIS
        Runs an external tool with a hard deadline, full output capture and process-tree termination.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [AllowEmptyCollection()][string[]]$ArgumentList = @(),
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [string]$Component = 'Process'
    )

    if ($script:ProcessInvoker) {
        return (& $script:ProcessInvoker $FilePath $ArgumentList $TimeoutMs)
    }

    if ($TimeoutMs -le 0) {
        Write-WacLog -Level WARNING -Component $Component -Message 'Run budget exhausted before the tool could start.' -Data @{ tool = $FilePath }
        return [PSCustomObject]@{
            ExitCode = $null; TimedOut = $true; StandardOutput = ''; StandardError = ''
            DurationMs = 0; Started = $false; TerminationProven = $true
        }
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $process = $null
    # Set once, immediately after a successful Start, and never cleared. The catch below reads it to
    # tell "never ran" apart from "ran, and we lost track of it"; those need opposite answers and the
    # exception itself cannot distinguish them.
    $started = $false
    $processId = 0

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = ConvertTo-WacCommandLine -ArgumentList $ArgumentList
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

        Write-WacLog -Level DEBUG -Component $Component -Message 'Starting external tool.' -Data @{
            tool = $FilePath; args = $psi.Arguments; timeoutMs = $TimeoutMs
        }

        $process = [System.Diagnostics.Process]::Start($psi)
        if (-not $process) { throw 'Process.Start returned no process.' }

        # The first statements after a proven start, so nothing between here and the reads below can
        # leave the catch unable to tell that a real process exists. The id is captured too, because
        # reading $process.Id later is itself one of the calls that can throw.
        $started = $true
        $processId = [int]$process.Id

        # ReadToEndAsync avoids the classic full-pipe deadlock without needing event handlers.
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()

        $exited = $process.WaitForExit($TimeoutMs)
        $timedOut = -not $exited

        $terminationProven = $true
        if ($timedOut) {
            Write-WacLog -Level WARNING -Component $Component -Message 'External tool exceeded its deadline; terminating the process tree.' -Data @{
                tool = $FilePath; pid = $process.Id; timeoutMs = $TimeoutMs
            }

            # The stop result used to be discarded, which made "we asked taskkill to kill it" and
            # "the whole tree is provably gone" the same event to every caller. A tool this run
            # started and could not prove it stopped is a mutator that may still be writing while
            # the run reports its verdict, so it is recorded and written at CRITICAL - the one level
            # -LogLevel cannot gate out.
            $stopped = Stop-WacProcessTree -ProcessId $process.Id
            $terminationProven = [bool]$stopped.Proven
            if (-not $terminationProven) {
                Write-WacLog -Level CRITICAL -Component $Component -Message 'The external tool could not be proven terminated; part of its process tree may still be running.' -Data @{
                    tool = $FilePath; pid = $process.Id
                    survivors = (@($stopped.Survivor) -join ',')
                    reason = [string]$stopped.Reason
                }
            }

            [void]$process.WaitForExit(10000)
        }

        [void]$outTask.Wait(5000)
        [void]$errTask.Wait(5000)

        $stdout = if ($outTask.IsCompleted) { [string]$outTask.Result } else { '' }
        $stderr = if ($errTask.IsCompleted) { [string]$errTask.Result } else { '' }

        $exitCode = $null
        if (-not $timedOut) {
            try { $exitCode = [int]$process.ExitCode } catch { $exitCode = $null }
        }

        $stopwatch.Stop()
        return [PSCustomObject]@{
            ExitCode = $exitCode
            TimedOut = $timedOut
            StandardOutput = $stdout
            StandardError = $stderr
            DurationMs = [int]$stopwatch.Elapsed.TotalMilliseconds
            Started = $true
            # $true whenever the tool was not terminated at all. Only a bounded timeout whose tree
            # could not be proven gone sets it $false.
            TerminationProven = $terminationProven
        }
    }
    catch {
        $stopwatch.Stop()

        # PRE-START and POST-START are different claims and this catch covers both. It used to
        # answer Started=$false and TerminationProven=$true for either, so an exception raised
        # AFTER Process.Start succeeded - a failed output read, a failed wait, an unreadable exit
        # code, a failed termination - reported that the tool never ran and that nothing was left
        # alive. Both were fabrications: the process had started and might still be running, and
        # nothing had been terminated. Downstream that mattered, because opt-in driver pruning
        # reads Started to decide it may delete the backup directory and the pending marker, and a
        # destructive pnputil delete may already have executed.
        if (-not $started) {
            Write-WacLog -Level WARNING -Component $Component -Message 'External tool failed to start.' -Data @{
                tool = $FilePath; error = $_.Exception.Message
            }
            return [PSCustomObject]@{
                ExitCode = $null; TimedOut = $false; StandardOutput = ''; StandardError = [string]$_.Exception.Message
                DurationMs = [int]$stopwatch.Elapsed.TotalMilliseconds; Started = $false
                TerminationProven = $true
            }
        }

        # It really started. Terminate what this run owns, and report the proof HONESTLY rather than
        # asserting it: an unproven kill leaves TerminationProven false so the caller treats the work
        # as unfinished instead of benign.
        $terminationProven = $false
        $survivors = ''
        try {
            $stopped = Stop-WacProcessTree -ProcessId $processId
            $terminationProven = [bool]$stopped.Proven
            $survivors = (@($stopped.Survivor) -join ',')
        }
        catch {
            $terminationProven = $false
        }

        Write-WacLog -Level CRITICAL -Component $Component -Message 'The external tool started, then failed before its result was known; its effects cannot be ruled out.' -Data @{
            tool = $FilePath; pid = $processId; error = $_.Exception.Message
            terminationProven = $terminationProven; survivors = $survivors
        }

        return [PSCustomObject]@{
            ExitCode = $null
            # NOT a deadline: this is an unknown outcome, and calling it a timeout would let a caller
            # treat it as the one failure shape it already has a benign story for.
            TimedOut = $false
            StandardOutput = ''
            StandardError = [string]$_.Exception.Message
            DurationMs = [int]$stopwatch.Elapsed.TotalMilliseconds
            Started = $true
            TerminationProven = $terminationProven
        }
    }
    finally {
        # Dispose releases the WRAPPER. It has never terminated anything, so it is not cleanup for a
        # process this run started and may have lost track of - that is what the catch above does.
        if ($process) { try { $process.Dispose() } catch { $null = $_ } }
    }
}

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
        [switch]$IgnoreRunBudget
    )

    $budgetMs = $TimeoutMs
    if (-not $IgnoreRunBudget) { $budgetMs = Get-WacStepTimeoutMs -RequestedMs $TimeoutMs }

    if ($budgetMs -le 0) {
        Write-WacLog -Level WARNING -Component $Component -Message 'Run budget exhausted before the work could be scheduled.' -Data @{ requestedMs = $TimeoutMs }
        return [PSCustomObject]@{
            Outcome = 'Incomplete'; Started = $false; TimedOut = $true
            Output = @(); HadErrors = $false
            Error = 'The run budget expired before this work was scheduled.'
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
        $runspace.Open()

        $shell = [powershell]::Create()
        $shell.Runspace = $runspace
        [void]$shell.AddScript($ScriptBlock.ToString())
        foreach ($argument in $ArgumentList) { [void]$shell.AddArgument($argument) }

        $handle = $shell.BeginInvoke()

        if (-not $handle.AsyncWaitHandle.WaitOne($budgetMs)) {
            $abandoned = $true
            try { [void]$shell.BeginStop($null, $null) } catch { $null = $_ }
            $watch.Stop()

            Write-WacLog -Level WARNING -Component $Component -Message 'In-process work exceeded its bound and was abandoned.' -Data @{ budgetMs = $budgetMs }
            return [PSCustomObject]@{
                Outcome = 'Incomplete'; Started = $true; TimedOut = $true
                Output = @(); HadErrors = $false
                Error = ('The work did not finish within {0} ms.' -f $budgetMs)
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

# ---------------------------------------------------------------------------------------------
# Single instance
# ---------------------------------------------------------------------------------------------

function Enter-WacSingleInstance {
    <#
    .SYNOPSIS
        Takes the machine-wide mutation lock, or returns $null when another run already owns it.
    .DESCRIPTION
        Task Scheduler's IgnoreNew only stops a second SCHEDULED start; it does nothing about a
        manual run overlapping the scheduled one. The mutex name is a parameter so concurrent test
        suites can use a unique Local\ name instead of observing production's Global\ lock.
    #>
    param([string]$Name = 'Global\WindowsAutoCleanup')

    $mutex = $null
    try {
        $createdNew = $false
        $mutex = New-Object System.Threading.Mutex($false, $Name, [ref]$createdNew)
    }
    catch {
        return $null
    }

    $owned = $false
    try {
        $owned = $mutex.WaitOne(0)
    }
    catch {
        # AbandonedMutexException means a previous run died holding the lock and WE NOW OWN IT.
        # WaitOne is a .NET method, so the exception can arrive wrapped in a
        # MethodInvocationException; treating that as "not acquired" would make every run after a
        # crash exit with code 3 and never clean again.
        $exception = $_.Exception
        while ($exception -and
               ($exception -is [System.Management.Automation.MethodInvocationException]) -and
               $exception.InnerException) {
            $exception = $exception.InnerException
        }
        $owned = ($exception -is [System.Threading.AbandonedMutexException])
    }

    if (-not $owned) {
        try { $mutex.Dispose() } catch { $null = $_ }
        return $null
    }

    return $mutex
}

function Exit-WacSingleInstance {
    param($Mutex)

    if (-not $Mutex) { return }
    try { $Mutex.ReleaseMutex() } catch { $null = $_ }
    try { $Mutex.Dispose() } catch { $null = $_ }
}
