#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for the Run.ps1 contract: the elevated-relaunch argument vector, parameter
    binding, the rendered help, and the module surface the entry point depends on.

.DESCRIPTION
    Run.ps1 executes its main body on load, so the relaunch builder is lifted out of the script's
    AST and defined on its own instead of dot-sourcing the whole file. Every assertion is made on
    the REAL returned vector, on the REAL command line built from it, or on what a REAL child
    process received - never on the text of the script, because a test that greps the source for
    '-ResetWindowsUpdateBase' is exactly what let ledger P0-2 ship: an explicit
    -ResetWindowsUpdateBase:$false was lost across the UAC relaunch while the old suite stayed green.

    Nothing here asserts on this process's own privilege level: the hosted Windows runner is
    elevated and a developer shell usually is not. The one case that needs a non-elevated child
    MAKES one, through Invoke-DeElevatedRun, which is INTENDED to assert the same thing in both
    places. That intent is only half measured: every run so far has been from a non-elevated
    session, where the code this replaced took the same branch anyway, so no run has yet shown the
    elevated path behaving. The case prints an evidence line naming the token it held, the
    mechanism it used and the child's exit code, so a single elevated run of this suite settles it.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'

Import-Module -Name (Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

# The host running this suite, taken from the live process rather than PATH, so the child is the
# same edition that is currently under test.
$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

# ---------------------------------------------------------------------------------------------
# Lifting the function under test out of Run.ps1
# ---------------------------------------------------------------------------------------------

$script:RunTokens = $null
$script:RunErrors = $null
$script:RunAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $script:RunPath, [ref]$script:RunTokens, [ref]$script:RunErrors)

$script:RelaunchAst = @($script:RunAst.FindAll({
            param($node)
            ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and
            ($node.Name -eq 'Get-WacRunRelaunchArgument')
        }, $true))

if ($script:RelaunchAst.Count -ne 1) {
    throw ('Run.ps1 must define exactly one Get-WacRunRelaunchArgument; found {0}.' -f $script:RelaunchAst.Count)
}

# Defining the extracted function is the whole point: the vector it returns is then produced by the
# shipped code, not by a copy of it living in this suite.
. ([scriptblock]::Create($script:RelaunchAst[0].Extent.Text))

function Get-RelaunchVector {
    <#
    .SYNOPSIS
        Sets the script-scope variables Run.ps1 would have bound, then returns the real vector.
    #>
    param(
        [hashtable]$Bound = @{},
        [bool]$Reset = $true,
        [bool]$Prune = $false,
        [bool]$Legacy = $false,
        [bool]$SkipBin = $false,
        [string]$Level = 'INFO',
        [int]$Budget = 210,
        [AllowEmptyCollection()][string[]]$Category = @(),
        [string]$Mutex = 'Global\WindowsAutoCleanup',
        [string]$ScriptFile = 'C:\Tools\WindowsAutoCleanup\Run.ps1'
    )

    $script:ResetWindowsUpdateBase = $Reset
    $script:PruneSupersededDrivers = $Prune
    $script:EnableLegacyDiskCleanup = $Legacy
    $script:SkipRecycleBin = $SkipBin
    $script:LogLevel = $Level
    $script:BudgetMinutes = $Budget
    $script:SkipCategory = @($Category)
    $script:MutexName = $Mutex
    $script:ScriptPath = $ScriptFile

    return @(Get-WacRunRelaunchArgument -Bound $Bound)
}

function Get-RelaunchPayload {
    <#
    .SYNOPSIS
        The PowerShell source the child will execute: the element after -Command.
    .DESCRIPTION
        The vector is -NoProfile -ExecutionPolicy Bypass [-HostSwitch...] -Command <payload>.
        -Command rather than -File is deliberate and load-bearing: Windows PowerShell 5.1 refuses to
        bind -Switch:$false under -File at all, so every switch value in this file is asserted on the
        payload PowerShell will actually parse.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Vector)

    for ($i = 0; $i -lt $Vector.Count; $i++) {
        if ([string]::Equals($Vector[$i], '-Command', [System.StringComparison]::Ordinal)) {
            if ($i + 1 -lt $Vector.Count) { return $Vector[$i + 1] }
        }
    }
    return ''
}

function Test-PayloadHasSwitch {
    <#
    .SYNOPSIS
        Ordinal check for an exact '-Name:$value' token in the payload.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Payload,
        [Parameter(Mandatory = $true)][string]$Token
    )

    return $Payload.IndexOf($Token, [System.StringComparison]::Ordinal) -ge 0
}

function Test-PayloadHasBareSwitch {
    <#
    .SYNOPSIS
        True when the payload carries '-Name' with no ':value' suffix, which would let the child fall
        back to its own default.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Payload,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return [regex]::IsMatch($Payload, ('(?<![\w:$])-' + [regex]::Escape($Name) + '(?![\w:])'))
}

function Test-VectorContains {
    <#
    .SYNOPSIS
        Ordinal membership. PowerShell's -contains is case-insensitive and would pass a casing
        regression in a switch name.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Vector,
        [Parameter(Mandatory = $true)][string]$Value
    )

    foreach ($element in $Vector) {
        if ([string]::Equals($element, $Value, [System.StringComparison]::Ordinal)) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------------------------
# Child processes
# ---------------------------------------------------------------------------------------------

function Start-ProbeProcess {
    <#
    .SYNOPSIS
        Starts a child of the host running this suite with one pre-quoted command line.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [hashtable]$Environment = @{},
        [string]$HostExe
    )

    if (-not $HostExe) { $HostExe = $script:HostExe }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $HostExe
    $psi.Arguments = $CommandLine
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $script:RepoRoot
    foreach ($key in $Environment.Keys) { $psi.EnvironmentVariables[$key] = [string]$Environment[$key] }

    return [System.Diagnostics.Process]::Start($psi)
}

function Stop-ProbeTree {
    <#
    .SYNOPSIS
        Kills a process and everything it started, by PID.
    .DESCRIPTION
        Taken by PID rather than by Process object because the de-elevated wrapper is ORPHANED by
        design - runas.exe returns before it finishes - so the only handle on that tree is the PID
        the wrapper recorded for itself.
    #>
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Join-Path -Path $env:SystemRoot -ChildPath 'System32\taskkill.exe')
    $psi.Arguments = '/T /F /PID {0}' -f $ProcessId
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $killer = $null
    try { $killer = [System.Diagnostics.Process]::Start($psi) } catch { $killer = $null }
    if ($killer) {
        [void]$killer.StandardOutput.ReadToEndAsync()
        [void]$killer.StandardError.ReadToEndAsync()
        [void]$killer.WaitForExit(10000)
        try { $killer.Dispose() } catch { $null = $_ }
    }
}

function Wait-ProbeProcess {
    <#
    .SYNOPSIS
        Bounded wait plus process-tree kill, so a child that never exits cannot hang this suite:
        "did not finish inside the bound" is the detected signal, not a stalled run.
    #>
    param(
        [Parameter(Mandatory = $true)]$Process,
        [int]$TimeoutMs = 90000
    )

    $outTask = $Process.StandardOutput.ReadToEndAsync()
    $errTask = $Process.StandardError.ReadToEndAsync()
    $exited = $Process.WaitForExit($TimeoutMs)

    if (-not $exited) {
        Stop-ProbeTree -ProcessId $Process.Id
        [void]$Process.WaitForExit(10000)
    }

    [void]$outTask.Wait(5000)
    [void]$errTask.Wait(5000)

    $exitCode = -1
    if ($exited) { try { $exitCode = [int]$Process.ExitCode } catch { $exitCode = -1 } }

    return [PSCustomObject]@{
        Exited    = $exited
        ExitCode  = $exitCode
        Output    = $(if ($outTask.IsCompleted) { [string]$outTask.Result } else { '' })
        ErrorText = $(if ($errTask.IsCompleted) { [string]$errTask.Result } else { '' })
    }
}

function Invoke-Probe {
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [hashtable]$Environment = @{},
        [int]$TimeoutMs = 90000,
        [string]$HostExe
    )

    $process = $null
    try {
        $process = Start-ProbeProcess -CommandLine $CommandLine -Environment $Environment -HostExe $HostExe
        return (Wait-ProbeProcess -Process $process -TimeoutMs $TimeoutMs)
    }
    finally {
        if ($process) { try { $process.Dispose() } catch { $null = $_ } }
    }
}

function Get-ProbeValue {
    <#
    .SYNOPSIS
        Reads one KEY=value line out of a probe's stdout.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Output,
        [Parameter(Mandatory = $true)][string]$Key
    )

    foreach ($line in @($Output -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith($Key + '=', [System.StringComparison]::Ordinal)) {
            return $trimmed.Substring($Key.Length + 1)
        }
    }
    return $null
}

# The script runas.exe launches under the restricted token. It is not a probe: it runs the REAL
# Run.ps1, and everything it reports back travels through files because a de-elevated grandchild
# inherits neither this process's stdout handles nor its exit code.
$script:DeElevatedWrapperBody = @'
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# IDENTITY, not a bare PID, and written first, before anything can block. runas.exe has already
# returned by now, so this file is the caller's only handle on the tree - but it may be read up to
# a whole timeout later, by which point Windows can have handed this PID to something else
# entirely. NAME and START let the caller prove the PID is still THIS process before killing it.
$self = Get-Process -Id $PID
[System.IO.File]::WriteAllText($env:WAC_DEELEVATE_PID, ('PID={0}{3}NAME={1}{3}START={2}{3}' -f `
        $PID, $self.ProcessName, $self.StartTime.Ticks, [Environment]::NewLine))

# SELF-BOUND, and this is the only bound that survives the caller dying. runas orphaned this
# wrapper, so if the caller is force-killed - by its own test runner's idle deadline, say - nothing
# left alive knows this process exists. The deadline therefore has to live in here. It runs in its
# own runspace, which gets its own thread, so it still fires when the main thread is wedged; and it
# kills the TREE by PID, so the Run.ps1 grandchild goes with it rather than being orphaned again.
$watchdog = [powershell]::Create()
[void]$watchdog.AddScript({
        param($OwnPid, $Ms, $TaskKill)
        Start-Sleep -Milliseconds $Ms
        & $TaskKill '/T' '/F' '/PID' $OwnPid | Out-Null
    }).AddArgument($PID).AddArgument([int]$env:WAC_DEELEVATE_SELF_MS).AddArgument(
    (Join-Path -Path $env:SystemRoot -ChildPath 'System32\taskkill.exe'))
[void]$watchdog.BeginInvoke()

$admin = $true
$code = -1
$note = ''
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # Run.ps1 is started ONLY once the token is known to be unprivileged. If a machine ever fails to
    # de-elevate, an elevated -Scheduled run here would perform a real cleanup of the host, so this
    # reports the token instead and lets the caller decide.
    if (-not $admin) {
        # Started as a bounded process rather than called inline: an inline call has no deadline, so
        # a Run.ps1 that hung would hold this wrapper past its own bound and force the watchdog to
        # do the reporting - i.e. report nothing. Redirected and drained so a full pipe buffer
        # cannot deadlock it either.
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $env:WAC_DEELEVATE_HOST
        $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Scheduled -BudgetMinutes 1 -MutexName "{1}"' -f `
            $env:WAC_DEELEVATE_RUN, $env:WAC_DEELEVATE_MUTEX
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true

        $child = [System.Diagnostics.Process]::Start($psi)
        [void]$child.StandardOutput.ReadToEndAsync()
        [void]$child.StandardError.ReadToEndAsync()

        if ($child.WaitForExit([int]$env:WAC_DEELEVATE_CHILD_MS)) {
            $code = $child.ExitCode
        }
        else {
            & (Join-Path -Path $env:SystemRoot -ChildPath 'System32\taskkill.exe') '/T' '/F' '/PID' $child.Id | Out-Null
            $note = 'CHILD-TIMEOUT'
        }
    }
}
catch {
    $note = 'WRAPPER-ERROR ' + $_.Exception.Message
}
finally {
    # Moved into place rather than written in place: the caller polls for this path, and a
    # half-written file would be read as a finished run. Written from finally so even a wrapper that
    # threw reports something - silence is the one outcome the caller can only time out on.
    $partial = $env:WAC_DEELEVATE_RESULT + '.partial'
    [System.IO.File]::WriteAllText($partial, ('ADMIN={0}{1}EXIT={2}{1}NOTE={3}{1}' -f `
            $admin, [Environment]::NewLine, $code, $note))
    [System.IO.File]::Move($partial, $env:WAC_DEELEVATE_RESULT)
}

exit 0
'@

function Stop-DeElevatedOrphan {
    <#
    .SYNOPSIS
        Kills the recorded wrapper tree, but ONLY after proving the PID is still that wrapper.
    .DESCRIPTION
        The PID in DeElevate.pid was written by a deliberately orphaned process up to a whole
        timeout earlier. If that wrapper has since exited, Windows is free to reissue its PID, and
        handing a recycled PID to taskkill /T /F would force-kill an unrelated process tree on the
        machine running the tests. So the wrapper records its image name and start time too, and
        nothing is killed unless both still match. Failing to confirm means NOT killing: the
        wrapper is self-bounded, so leaving it alone costs at most one bounded wait, whereas
        killing the wrong tree is unbounded damage.
    .OUTPUTS
        A sentence describing what was done, for the caller's Detail line.
    #>
    param([Parameter(Mandatory = $true)][string]$PidFile)

    if (-not (Test-Path -LiteralPath $PidFile -PathType Leaf)) {
        return 'the wrapper recorded no PID, so it had not started; nothing was killed'
    }

    $recordedPid = 0
    $recordedName = ''
    $recordedStart = 0L
    try {
        foreach ($line in @([System.IO.File]::ReadAllLines($PidFile))) {
            if ($line.StartsWith('PID=', [System.StringComparison]::Ordinal)) { $recordedPid = [int]$line.Substring(4).Trim() }
            elseif ($line.StartsWith('NAME=', [System.StringComparison]::Ordinal)) { $recordedName = $line.Substring(5).Trim() }
            elseif ($line.StartsWith('START=', [System.StringComparison]::Ordinal)) { $recordedStart = [long]$line.Substring(6).Trim() }
        }
    }
    catch {
        return ('the recorded wrapper identity could not be read ({0}); nothing was killed' -f $_.Exception.Message)
    }

    if ($recordedPid -le 0 -or -not $recordedName -or $recordedStart -le 0) {
        return 'the recorded wrapper identity was incomplete; nothing was killed'
    }

    $live = @(Get-Process -Id $recordedPid -ErrorAction SilentlyContinue)
    if ($live.Count -ne 1) {
        return ('the recorded wrapper PID {0} is no longer running; nothing was killed' -f $recordedPid)
    }

    $liveName = ''
    $liveStart = 0L
    try {
        $liveName = [string]$live[0].ProcessName
        $liveStart = [long]$live[0].StartTime.Ticks
    }
    catch {
        return ('PID {0} could not be identified ({1}); nothing was killed' -f $recordedPid, $_.Exception.Message)
    }

    if (-not [string]::Equals($liveName, $recordedName, [System.StringComparison]::OrdinalIgnoreCase) -or $liveStart -ne $recordedStart) {
        return ('PID {0} is now [{1}] started at {2}, not the recorded [{3}] started at {4}, so the PID was recycled and nothing was killed' -f `
                $recordedPid, $liveName, $liveStart, $recordedName, $recordedStart)
    }

    Stop-ProbeTree -ProcessId $recordedPid

    # Bounded settle: taskkill returns once the kill is issued, and the sandbox cannot be deleted
    # while the wrapper still holds its script file open.
    for ($i = 0; $i -lt 30; $i++) {
        if (@(Get-Process -Id $recordedPid -ErrorAction SilentlyContinue).Count -eq 0) {
            return ('the recorded wrapper tree (PID {0}, {1}) was identified and killed' -f $recordedPid, $recordedName)
        }
        Start-Sleep -Milliseconds 100
    }

    return ('PID {0} was identified and taskkill /T /F was issued, but it was still alive 3 s later' -f $recordedPid)
}

function Invoke-InheritedTokenRun {
    <#
    .SYNOPSIS
        Fallback when runas cannot hand out a restricted token: run Run.ps1 under THIS process's token.
    .DESCRIPTION
        Legitimate only while this process is itself unprivileged, and then it proves exactly the
        same thing the de-elevated path does - an unelevated -Scheduled run must refuse to clean.
        On an ELEVATED host there is nothing to fall back to: starting Run.ps1 -Scheduled with a
        full token would perform a real cleanup of the machine running the tests, which is not a
        price a test may pay. That combination returns 'no-unprivileged-token' and the caller turns
        it into a skip, which fails the suite. See the risk note on the case itself.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Environment,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    if (Test-WacIsAdministrator) {
        return [PSCustomObject]@{
            Status    = 'no-unprivileged-token'
            ExitCode  = -1
            Mechanism = 'none'
            Detail    = ('{0}; this host is elevated, so no unprivileged token is left to fall back to and a -Scheduled run here would clean the machine for real' -f $Reason)
        }
    }

    $probe = Invoke-Probe -TimeoutMs 25000 -Environment $Environment -CommandLine (
        ConvertTo-WacCommandLine -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:RunPath,
            '-Scheduled', '-BudgetMinutes', '1',
            '-MutexName', ('Global\WacTest{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))))

    if (-not $probe.Exited) {
        return [PSCustomObject]@{
            Status    = 'timeout'
            ExitCode  = -1
            Mechanism = 'inherited-unprivileged-token'
            Detail    = ('{0}; the fallback run under the token this suite already holds did not finish inside 25000 ms' -f $Reason)
        }
    }

    return [PSCustomObject]@{
        Status    = 'ok'
        ExitCode  = $probe.ExitCode
        Mechanism = 'inherited-unprivileged-token'
        Detail    = ('{0}; asserted against the unprivileged token this suite already holds instead' -f $Reason)
    }
}

function Invoke-DeElevatedRun {
    <#
    .SYNOPSIS
        Runs Run.ps1 -Scheduled under a genuinely unprivileged token, whatever token this suite holds.
    .DESCRIPTION
        runas.exe /trustlevel:0x20000 is SAFER_LEVELID_NORMALUSER: the child receives a token whose
        Administrators SID is deny-only, the same shape UAC gives a filtered token. It needs no
        password, no consent prompt, no scheduled task and no elevation of its own, so it runs
        unattended on a developer shell and on the elevated GitHub windows-latest runner alike.
        Measured cost on both hosts: about 2.6 seconds.

        Two runas behaviours shape the rest of this function. It RETURNS IMMEDIATELY, before the
        command it launched has finished, and it propagates neither that command's exit code nor
        its output - the grandchild does not inherit the redirected handles. So the wrapper records
        its PID, runs Run.ps1, and MOVES a result file into place, and this function polls for that
        file under a deadline and kills the recorded tree if it never appears.

        The inner command's quotes have to be escaped as \" . A plainly nested "..." is rejected the
        moment the program path contains a space - measured: with C:\Program Files\PowerShell\7\
        pwsh.exe, runas exits 1 and launches nothing at all, silently.

        Everything it creates lives in the caller's sandbox, so Remove-TestSandbox is the cleanup.

        THE BUDGET, and why it is this small. Measured normal cost of the whole case on this
        machine, 2026-08-24: 2.8 s pwsh / 3.0 s powershell running the suite alone, and 2.2 s /
        4.6 s inside a full 26-run both-hosts pass at 8 workers, where it competes for the machine.
        Run-Tests.ps1 force-kills a suite that produces no output for IdleTimeoutSeconds, default
        120, and this call prints nothing while it polls - so its entire duration is idle time. A
        deadline ABOVE that budget is worse than no deadline: the runner wins the race, the caller
        is killed before its own cleanup, finally never runs, and the orphan and the sandbox both
        survive. So the default is 40 s, about 9x the worst measured cost and a third of the runner's
        budget, which leaves the caller's cleanup comfortably inside it. Worst case for the whole
        case is the still-elevated path: 40 s of polling plus a 25 s fallback run, 65 s, still
        inside 120. The two derived bounds keep the same ordering: the wrapper gives Run.ps1
        TimeoutMs-15 s so it can always report a child hang BEFORE this poll gives up, and
        self-destructs at TimeoutMs+15 s so an orphan nobody kills still dies inside the runner's
        idle budget.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][hashtable]$Environment,
        # The two derived budgets below are only ordered correctly for part of the int range, and a
        # default value is not an invariant - it is one edit away from being wrong. The bounds make
        # both relations hold by construction:
        #   lower 20000 keeps CHILD_MS (TimeoutMs-15 s) genuinely below TimeoutMs, so the wrapper can
        #     still report a child hang before this poll gives up; under it Math::Max clamps to 5 s
        #     and CHILD_MS would meet or exceed the poll it is supposed to pre-empt.
        #   upper 100000 keeps SELF_MS (TimeoutMs+15 s = 115 s) inside Run-Tests.ps1's 120 s default
        #     idle budget, so a wrapper nobody kills still dies before the runner force-kills the
        #     suite - which is the exact ordering whose absence leaked an orphan process.
        # The upper bound is coupled to that runner default: Run-Tests.ps1 accepts
        # -IdleTimeoutSeconds down to 10, and no ValidateRange here can see it, so lowering the
        # runner's idle budget below ~115 s reintroduces the leak. The runner prints a NOTE when it
        # force-kills a suite for exactly that reason.
        [ValidateRange(20000, 100000)][int]$TimeoutMs = 40000
    )

    $wrapper = Join-Path -Path $Sandbox -ChildPath 'DeElevate.ps1'
    $resultFile = Join-Path -Path $Sandbox -ChildPath 'DeElevate.result'
    $pidFile = Join-Path -Path $Sandbox -ChildPath 'DeElevate.pid'
    [System.IO.File]::WriteAllText($wrapper, $script:DeElevatedWrapperBody)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Join-Path -Path $env:SystemRoot -ChildPath 'System32\runas.exe')
    # -WindowStyle Hidden is not cosmetic. runas.exe composes its child's startup info itself, so the
    # CreateNoWindow set below applies to the runas PROCESS and never reaches the process runas
    # launches: without this the wrapper opens a real console that pops to the foreground and steals
    # focus every time this case runs. Asking the host to hide its own window at startup is the only
    # lever the parent has left once runas is in the middle.
    $psi.Arguments = '/trustlevel:0x20000 "{0}"' -f (
        '\"{0}\" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{1}\"' -f $script:HostExe, $wrapper)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $script:RepoRoot
    foreach ($key in $Environment.Keys) { $psi.EnvironmentVariables[$key] = [string]$Environment[$key] }
    $psi.EnvironmentVariables['WAC_DEELEVATE_HOST'] = $script:HostExe
    $psi.EnvironmentVariables['WAC_DEELEVATE_RUN'] = $script:RunPath
    $psi.EnvironmentVariables['WAC_DEELEVATE_MUTEX'] = 'Global\WacTest{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8)
    $psi.EnvironmentVariables['WAC_DEELEVATE_RESULT'] = $resultFile
    $psi.EnvironmentVariables['WAC_DEELEVATE_PID'] = $pidFile
    $psi.EnvironmentVariables['WAC_DEELEVATE_CHILD_MS'] = [string][Math]::Max(5000, $TimeoutMs - 15000)
    $psi.EnvironmentVariables['WAC_DEELEVATE_SELF_MS'] = [string]($TimeoutMs + 15000)

    $launchCode = -1
    $launchText = ''
    $launcher = $null
    try {
        $launcher = [System.Diagnostics.Process]::Start($psi)
        $outTask = $launcher.StandardOutput.ReadToEndAsync()
        $errTask = $launcher.StandardError.ReadToEndAsync()

        if ($launcher.WaitForExit(30000)) {
            try { $launchCode = [int]$launcher.ExitCode } catch { $launchCode = -1 }
        }
        else {
            Stop-ProbeTree -ProcessId $launcher.Id
        }

        [void]$outTask.Wait(5000)
        [void]$errTask.Wait(5000)
        $launchText = ('{0} {1}' -f `
                $(if ($outTask.IsCompleted) { [string]$outTask.Result } else { '' }),
            $(if ($errTask.IsCompleted) { [string]$errTask.Result } else { '' })).Trim()
    }
    finally {
        if ($launcher) { try { $launcher.Dispose() } catch { $null = $_ } }
    }

    if ($launchCode -ne 0) {
        # runas could not produce a restricted token at all. That is a property of the MACHINE, not
        # of Run.ps1, so rather than proving nothing this degrades to the token this suite already
        # holds - which still asserts the contract whenever that token is unprivileged.
        return (Invoke-InheritedTokenRun -Environment $Environment -Reason (
                'runas.exe /trustlevel:0x20000 exited {0} and started nothing: [{1}]' -f $launchCode, $launchText))
    }

    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([datetime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath $resultFile -PathType Leaf)) {
        Start-Sleep -Milliseconds 200
    }

    if (-not (Test-Path -LiteralPath $resultFile -PathType Leaf)) {
        return [PSCustomObject]@{
            Status    = 'timeout'
            ExitCode  = -1
            Mechanism = 'runas-trustlevel-0x20000'
            Detail    = ('the de-elevated run wrote no result inside {0} ms; {1}' -f $TimeoutMs, (Stop-DeElevatedOrphan -PidFile $pidFile))
        }
    }

    $admin = ''
    $note = ''
    $exitCode = -1
    foreach ($line in @([System.IO.File]::ReadAllLines($resultFile))) {
        if ($line.StartsWith('ADMIN=', [System.StringComparison]::Ordinal)) { $admin = $line.Substring(6) }
        elseif ($line.StartsWith('EXIT=', [System.StringComparison]::Ordinal)) { $exitCode = [int]($line.Substring(5)) }
        elseif ($line.StartsWith('NOTE=', [System.StringComparison]::Ordinal)) { $note = $line.Substring(5) }
    }

    if (-not [string]::Equals($admin, 'False', [System.StringComparison]::Ordinal)) {
        # Same reasoning as a failed launch: the token came back privileged, so this machine cannot
        # de-elevate, but the suite's own token may still be able to prove the contract.
        return (Invoke-InheritedTokenRun -Environment $Environment -Reason (
                'the restricted token still reported IsInRole(Administrator)=[{0}], so Run.ps1 was deliberately not started' -f $admin))
    }

    if ($note) {
        # The wrapper reached its own reporting path, so this is a real hang inside Run.ps1 rather
        # than an unexplained silence, and it is reported as the failure it is.
        return [PSCustomObject]@{
            Status    = 'timeout'
            ExitCode  = -1
            Mechanism = 'runas-trustlevel-0x20000'
            Detail    = ('the de-elevated wrapper reported [{0}] instead of a clean Run.ps1 exit' -f $note)
        }
    }

    return [PSCustomObject]@{
        Status    = 'ok'
        ExitCode  = $exitCode
        Mechanism = 'runas-trustlevel-0x20000'
        Detail    = ''
    }
}

# A parameter block that mirrors Run.ps1's, so a value that does not survive the command line shows
# up as the DEFAULT the parent never asked for - which is exactly how P0-2 behaved.
$script:ArgumentProbeBody = @'
[CmdletBinding()]
param(
    [switch]$Scheduled,
    [switch]$ResetWindowsUpdateBase = $true,
    [switch]$PruneSupersededDrivers,
    [switch]$EnableLegacyDiskCleanup,
    [switch]$SkipRecycleBin,
    [string[]]$SkipCategory = @(),
    [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$LogLevel = 'INFO',
    [ValidateRange(1, 235)][int]$BudgetMinutes = 210,
    [string]$MutexName = 'Global\WindowsAutoCleanup'
)

Set-StrictMode -Version 2.0
$split = @($SkipCategory | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

Write-Output ('SELF=' + $PSCommandPath)
Write-Output ('RESET=' + [bool]$ResetWindowsUpdateBase)
Write-Output ('PRUNE=' + [bool]$PruneSupersededDrivers)
Write-Output ('LEGACY=' + [bool]$EnableLegacyDiskCleanup)
Write-Output ('SKIPBIN=' + [bool]$SkipRecycleBin)
Write-Output ('LOGLEVEL=' + $LogLevel)
Write-Output ('BUDGET=' + $BudgetMinutes)
Write-Output ('MUTEX=' + $MutexName)
Write-Output ('CATEGORY=' + ($split -join '|'))
exit 0
'@

$script:InspectProbeBody = @'
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:WAC_PROBE_MODE -eq 'help') {
    $help = Get-Help -Full -Name $env:WAC_PROBE_RUN
    Write-Output ('PARAMS=' + ((@($help.parameters.parameter) | ForEach-Object { $_.name }) -join ','))
    Write-Output ('SYNOPSIS=' + ((($help.Synopsis) -replace '\s+', ' ').Trim()))
    Write-Output ('DESCRIPTION=' + (((($help.description | Out-String)) -replace '\s+', ' ').Trim()))
    Write-Output ('NOTES=' + ((($help.alertSet.alert | Out-String) -replace '\s+', ' ').Trim()))
    exit 0
}

if ($env:WAC_PROBE_MODE -eq 'surface') {
    foreach ($name in @('Core', 'FileSystem', 'Targets', 'Steps', 'Drivers')) {
        $path = Join-Path -Path $env:WAC_PROBE_SRC -ChildPath ('WindowsAutoCleanup.{0}.psm1' -f $name)
        Import-Module -Name $path -Force -DisableNameChecking -ErrorAction Stop
        Write-Output ('IMPORTED=' + $name)
    }

    $missing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($command in @($env:WAC_PROBE_COMMAND -split ',' | Where-Object { $_ })) {
        if (-not (Get-Command -Name $command -CommandType Function -ErrorAction SilentlyContinue)) {
            [void]$missing.Add($command)
        }
    }

    Write-Output ('MISSING=' + ($missing -join ','))
    Write-Output ('CHECKED=' + @($env:WAC_PROBE_COMMAND -split ',' | Where-Object { $_ }).Count)
    exit 0
}

Write-Output 'MODE=unknown'
exit 9
'@

function New-ProbeScript {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Body
    )

    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
    [System.IO.File]::WriteAllText($Path, $Body, (New-Object System.Text.UTF8Encoding($false)))
    return $Path
}

# ---------------------------------------------------------------------------------------------
# The relaunch vector
# ---------------------------------------------------------------------------------------------

Test-Case 'Run.ps1 parses cleanly and keeps the relaunch vector in one testable function' {
    Assert-Equal 0 (@($script:RunErrors).Count) (($script:RunErrors | ForEach-Object { [string]$_ }) -join ' ; ')
    Assert-True (@($script:RunTokens).Count -gt 100) 'the parser produced no tokens for Run.ps1'

    $vector = Get-RelaunchVector
    Assert-True (Test-VectorContains -Vector $vector -Value '-Command') `
        ('the relaunch must go through -Command, not -File: ' + ($vector -join ' '))
    Assert-True ((Get-RelaunchPayload -Vector $vector).Length -gt 0) 'the -Command payload was empty'
}

Test-Case 'The default relaunch vector states every switch explicitly' {
    $vector = Get-RelaunchVector

    $expected = "-NoProfile -ExecutionPolicy Bypass -Command " +
        "`$LASTEXITCODE = 1; & 'C:\Tools\WindowsAutoCleanup\Run.ps1' -EnableLegacyDiskCleanup:`$false " +
        "-PruneSupersededDrivers:`$false -ResetWindowsUpdateBase:`$true -SkipRecycleBin:`$false " +
        "-BudgetMinutes '210' -LogLevel 'INFO'; exit `$LASTEXITCODE"

    Assert-Equal $expected ($vector -join ' ')
}

Test-Case 'An explicit -ResetWindowsUpdateBase:$false survives the relaunch (ledger P0-2)' {
    $vector = Get-RelaunchVector -Reset $false -Bound @{ ResetWindowsUpdateBase = $false }

    # The load-bearing assertion. A vector that merely CONTAINS the text '-ResetWindowsUpdateBase'
    # is the defect: the child then applies the $true default and DISM runs /ResetBase anyway.
    $payload = Get-RelaunchPayload -Vector $vector

    Assert-True (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$false') `
        ('the payload was ' + $payload)
    Assert-False (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$true') `
        'the child was told the opposite of what the parent was given'
    Assert-False (Test-PayloadHasBareSwitch -Payload $payload -Name 'ResetWindowsUpdateBase') `
        'a bare switch lets the child fall back to its default'

    $expected = "`$LASTEXITCODE = 1; & 'C:\Tools\WindowsAutoCleanup\Run.ps1' -EnableLegacyDiskCleanup:`$false " +
        "-PruneSupersededDrivers:`$false -ResetWindowsUpdateBase:`$false -SkipRecycleBin:`$false " +
        "-BudgetMinutes '210' -LogLevel 'INFO'; exit `$LASTEXITCODE"
    Assert-Equal $expected $payload
}

Test-Case 'An explicit -ResetWindowsUpdateBase:$true is emitted explicitly too' {
    $vector = Get-RelaunchVector -Reset $true -Bound @{ ResetWindowsUpdateBase = $true }

    $payload = Get-RelaunchPayload -Vector $vector
    Assert-True (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$true') $payload
    Assert-False (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$false') $payload
    Assert-False (Test-PayloadHasBareSwitch -Payload $payload -Name 'ResetWindowsUpdateBase') $payload
}

Test-Case 'The three opt-in switches round-trip in both states' {
    $off = Get-RelaunchPayload -Vector (Get-RelaunchVector)
    foreach ($name in @('PruneSupersededDrivers', 'EnableLegacyDiskCleanup', 'SkipRecycleBin')) {
        Assert-True (Test-PayloadHasSwitch -Payload $off -Token ('-{0}:$false' -f $name)) ('missing off state for ' + $name)
        Assert-False (Test-PayloadHasBareSwitch -Payload $off -Name $name) ('bare switch emitted for ' + $name)
    }

    $on = Get-RelaunchPayload -Vector (Get-RelaunchVector -Prune $true -Legacy $true -SkipBin $true `
        -Bound @{ PruneSupersededDrivers = $true; EnableLegacyDiskCleanup = $true; SkipRecycleBin = $true })
    foreach ($name in @('PruneSupersededDrivers', 'EnableLegacyDiskCleanup', 'SkipRecycleBin')) {
        Assert-True (Test-PayloadHasSwitch -Payload $on -Token ('-{0}:$true' -f $name)) ('missing on state for ' + $name)
        Assert-False (Test-PayloadHasSwitch -Payload $on -Token ('-{0}:$false' -f $name)) ('both states emitted for ' + $name)
    }

    # An opt-in switch the caller never asked for must still be stated, and stated as false.
    Assert-True (Test-PayloadHasSwitch -Payload $off -Token '-EnableLegacyDiskCleanup:$false')
}

Test-Case 'A script path containing spaces is quoted exactly once on the command line' {
    $spaced = 'C:\Program Files\Windows Auto Cleanup\Run.ps1'
    $vector = Get-RelaunchVector -ScriptFile $spaced

    # Two quoting layers, each applied exactly once: the payload single-quotes the path for the
    # PowerShell parser, and ConvertTo-WacCommandLine double-quotes the payload for CreateProcess.
    # Doing either twice is how a relaunch ends up looking for a directory called '"C:\Program'.
    $payload = Get-RelaunchPayload -Vector $vector
    Assert-True ($payload.StartsWith(("`$LASTEXITCODE = 1; & '" + $spaced + "' "), [System.StringComparison]::Ordinal)) $payload

    $commandLine = ConvertTo-WacCommandLine -ArgumentList $vector
    $expected = '-NoProfile -ExecutionPolicy Bypass -Command "' + $payload + '"'
    Assert-Equal $expected $commandLine
}

Test-Case 'SkipCategory appears only when it was bound and travels as one token' {
    $absent = Get-RelaunchVector -Category @('Temp')
    Assert-False (Test-VectorContains -Vector $absent -Value '-SkipCategory') `
        'an unbound -SkipCategory was forwarded to the child'

    $empty = Get-RelaunchVector -Category @() -Bound @{ SkipCategory = @() }
    Assert-False (Test-VectorContains -Vector $empty -Value '-SkipCategory') `
        'an empty -SkipCategory was forwarded as a value-less switch'

    $bound = Get-RelaunchPayload -Vector (Get-RelaunchVector -Category @('Windows Update cache', 'Temp') `
        -Bound @{ SkipCategory = @('Windows Update cache', 'Temp') })

    # Under -Command the child's parser sees a real ARRAY, so each category keeps its own quoting and
    # a space inside a category name can no longer split it into two elements.
    $expectedFragment = "-SkipCategory 'Windows Update cache','Temp'"
    Assert-True ($bound.IndexOf($expectedFragment, [System.StringComparison]::Ordinal) -ge 0) `
        ('the payload was ' + $bound)
}

Test-Case 'MutexName appears only when it was bound' {
    $absent = Get-RelaunchPayload -Vector (Get-RelaunchVector -Mutex 'Global\WindowsAutoCleanup')
    Assert-False ($absent.IndexOf('-MutexName', [System.StringComparison]::Ordinal) -ge 0) `
        'the default mutex name was forwarded even though it was never bound'

    $bound = Get-RelaunchPayload -Vector (Get-RelaunchVector -Mutex 'Global\WacTestProbe' `
        -Bound @{ MutexName = 'Global\WacTestProbe' })
    $expectedFragment = "-MutexName 'Global\WacTestProbe'"
    Assert-True ($bound.IndexOf($expectedFragment, [System.StringComparison]::Ordinal) -ge 0) $bound
}

Test-Case 'The elevated relaunch host binds the values the vector carries' {
    $sandbox = New-TestSandbox -Prefix 'orch-relaunch'
    try {
        # The child must be started by the host Run.ps1 would really elevate through, not by the
        # host running this suite: the two do not agree on -File and switch values (see the
        # companion case below), so testing the wrong one would prove nothing about the relaunch.
        $relaunchHost = Get-WacCanonicalPowerShellHost
        Assert-True ([bool]$relaunchHost) 'no machine-trusted PowerShell host was found, so the relaunch cannot be tested'

        $probe = New-ProbeScript -Body $script:ArgumentProbeBody `
            -Path (Join-Path -Path $sandbox -ChildPath 'Windows Auto Cleanup\Relaunch Probe.ps1')

        $vector = Get-RelaunchVector -ScriptFile $probe -Reset $false -Prune $true -Level 'DEBUG' -Budget 42 `
            -Category @('Windows Update cache', 'Temp') -Mutex 'Global\WacTestProbe' `
            -Bound @{
            ResetWindowsUpdateBase = $false
            PruneSupersededDrivers = $true
            SkipCategory           = @('Windows Update cache', 'Temp')
            MutexName              = 'Global\WacTestProbe'
        }

        $result = Invoke-Probe -CommandLine (ConvertTo-WacCommandLine -ArgumentList $vector) -TimeoutMs 90000 -HostExe $relaunchHost

        Assert-True $result.Exited 'the probe child did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ('the relaunch vector did not bind in ' + $relaunchHost + ': ' + $result.ErrorText)
        Assert-Equal $probe (Get-ProbeValue -Output $result.Output -Key 'SELF') 'the spaced script path did not survive quoting'
        Assert-Equal 'False' (Get-ProbeValue -Output $result.Output -Key 'RESET') 'the child fell back to the default (ledger P0-2)'
        Assert-Equal 'True' (Get-ProbeValue -Output $result.Output -Key 'PRUNE')
        Assert-Equal 'False' (Get-ProbeValue -Output $result.Output -Key 'LEGACY')
        Assert-Equal 'False' (Get-ProbeValue -Output $result.Output -Key 'SKIPBIN')
        Assert-Equal 'DEBUG' (Get-ProbeValue -Output $result.Output -Key 'LOGLEVEL')
        Assert-Equal '42' (Get-ProbeValue -Output $result.Output -Key 'BUDGET')
        Assert-Equal 'Global\WacTestProbe' (Get-ProbeValue -Output $result.Output -Key 'MUTEX')
        Assert-Equal 'Windows Update cache|Temp' (Get-ProbeValue -Output $result.Output -Key 'CATEGORY')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The named half of the vector survives -File on the host running this suite' {
    $sandbox = New-TestSandbox -Prefix 'orch-named'
    try {
        $probe = New-ProbeScript -Body $script:ArgumentProbeBody `
            -Path (Join-Path -Path $sandbox -ChildPath 'Windows Auto Cleanup\Named Probe.ps1')

        # Named values and the script path only. The boolean half is covered by the case above,
        # against the host that actually receives it.
        $vector = Get-WacRelaunchArgument -ScriptPath $probe -NamedValue @{
            LogLevel      = 'WARNING'
            BudgetMinutes = '7'
            SkipCategory  = 'Windows Update cache,Temp'
            MutexName     = 'Global\WacTestProbe'
        }

        $result = Invoke-Probe -CommandLine (ConvertTo-WacCommandLine -ArgumentList $vector) -TimeoutMs 90000

        Assert-True $result.Exited 'the probe child did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ($result.ErrorText)
        Assert-Equal $probe (Get-ProbeValue -Output $result.Output -Key 'SELF') 'the spaced script path did not survive quoting'
        Assert-Equal 'WARNING' (Get-ProbeValue -Output $result.Output -Key 'LOGLEVEL')
        Assert-Equal '7' (Get-ProbeValue -Output $result.Output -Key 'BUDGET')
        Assert-Equal 'Global\WacTestProbe' (Get-ProbeValue -Output $result.Output -Key 'MUTEX')
        # One -File token has to re-split into two categories, spaces and all.
        Assert-Equal 'Windows Update cache|Temp' (Get-ProbeValue -Output $result.Output -Key 'CATEGORY')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# The Run.ps1 command-line contract
# ---------------------------------------------------------------------------------------------

Test-Case 'A scheduled run that is not elevated fails instead of cleaning' {
    # The child is DE-ELEVATED rather than merely inherited, so the assertions below are made
    # against a genuinely unprivileged token no matter which token this suite holds. The old shape
    # returned early when this process was elevated, which made it a guaranteed silent pass in
    # CI - ledger R-23.
    #
    # WHAT HAS BEEN MEASURED, AND WHAT HAS NOT. Every run of this case so far was made from a
    # NON-elevated session. On a non-elevated host the pre-R-23 code took the same branch and made
    # the same assertions, so those runs do not yet distinguish this shape from the old one: the
    # difference only shows on an ELEVATED host, and no elevated run has been made. That is what
    # the evidence line below is for - it names the token this suite held, the de-elevation
    # mechanism actually used and the exit code the child returned, so ONE elevated run of this
    # suite settles which path was taken instead of leaving it to be argued.
    #
    # RISK, stated plainly. If runas /trustlevel:0x20000 ever fails to hand out a restricted token
    # on an elevated GitHub windows-latest runner, Invoke-DeElevatedRun degrades to the token this
    # suite already holds - but on an elevated runner there is no unprivileged token to degrade to,
    # so the case SKIPS, which exits the suite 3 and turns the whole CI run red. That is accepted
    # deliberately: the only other option on an elevated host is to start Run.ps1 -Scheduled with a
    # full token, which would perform a real cleanup of the runner. A red run saying "this machine
    # could not produce an unprivileged token" is a correct report; a green run that proved nothing
    # is what R-23 was. The obvious dependency scare does not apply: Secondary Logon (seclogon) is
    # Stopped/Manual on the machine these numbers came from and runas /trustlevel:0x20000 still
    # worked, so the mechanism does not need that service running.
    $sandbox = New-TestSandbox -Prefix 'orch-scheduled'
    try {
        # An UNELEVATED run logs under the user's own profile on purpose: whoever CREATES
        # %ProgramData%\WindowsAutoCleanup becomes its owner and, through CREATOR OWNER inheritance,
        # gains full control of the directory the SYSTEM task later writes its audit log into. Both
        # roots are redirected so the case proves the log went to the per-user one and NOT to the
        # machine-wide one.
        #
        # -TimeoutMs is deliberately NOT passed: the shipped default is the value under test, and a
        # second number here is exactly how the deadline drifted past the test runner's idle budget.
        $result = Invoke-DeElevatedRun -Sandbox $sandbox -Environment @{
            ProgramData  = (Join-Path -Path $sandbox -ChildPath 'PD')
            LOCALAPPDATA = (Join-Path -Path $sandbox -ChildPath 'LA')
        }

        Write-Host ('      evidence: suiteElevated={0} mechanism={1} status={2} childExit={3}{4}' -f `
                (Test-WacIsAdministrator), $result.Mechanism, $result.Status, $result.ExitCode,
            $(if ($result.Detail) { ' detail=' + $result.Detail } else { '' }))

        # A hang is a real defect, so it fails. A machine that cannot hand out an unprivileged token
        # at all proved nothing, so it SKIPS - which is its own outcome, is excluded from passed=,
        # and exits the suite 3. It can no longer be mistaken for a pass.
        if ($result.Status -eq 'timeout') { Assert-True $false $result.Detail }
        if ($result.Status -ne 'ok') { Set-TestSkipped -Reason $result.Detail }

        Assert-Equal 1 $result.ExitCode 'a scheduled run without elevation must exit 1 rather than clean'

        $logs = @(Get-ChildItem -LiteralPath (Join-Path -Path $sandbox -ChildPath 'LA\WindowsAutoCleanup\Logs') `
                -Filter 'WindowsAutoCleanup_*.log' -File -ErrorAction SilentlyContinue)
        Assert-Equal 1 $logs.Count 'the run did not create exactly one log file in the redirected per-user root'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $sandbox -ChildPath 'PD\WindowsAutoCleanup')) `
            'an unelevated run created the machine-wide state directory and would therefore own it'

        $text = [System.IO.File]::ReadAllText($logs[0].FullName)
        Assert-True ($text.Contains('[ERROR] [Run] Administrator privileges are required')) $text
        Assert-False ($text.Contains('[Summary]')) 'the run reached the cleanup summary without being elevated'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The deprecated -SkipAclHardening switch is still accepted by parameter binding' {
    $sandbox = New-TestSandbox -Prefix 'orch-acl'
    try {
        # -LogLevel NOPE is a poison pill: binding fails before the script body runs, so this proves
        # acceptance of -SkipAclHardening without ever letting a cleanup start.
        $accepted = Invoke-Probe -TimeoutMs 90000 -Environment @{ ProgramData = $sandbox } -CommandLine (
            ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:RunPath,
                '-SkipAclHardening', '-LogLevel', 'NOPE'))

        Assert-True $accepted.Exited 'the binding probe did not finish inside its bound'
        Assert-True ($accepted.ExitCode -ne 0) 'the poison-pill argument was accepted, so the body may have run'

        # Console line wrapping differs per host, so compare with whitespace removed.
        $acceptedText = ($accepted.ErrorText -replace '\s', '')
        Assert-True ($acceptedText.Contains('LogLevel')) $accepted.ErrorText
        Assert-False ($acceptedText.Contains('SkipAclHardening')) `
            'a task registered by an older installer would now fail to bind'

        $unknown = Invoke-Probe -TimeoutMs 90000 -Environment @{ ProgramData = $sandbox } -CommandLine (
            ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:RunPath,
                '-SkipAclHardeningX'))

        # The control: an unknown switch really is rejected by name, which is what makes the
        # assertion above evidence rather than a coincidence.
        Assert-True $unknown.Exited
        Assert-True ($unknown.ExitCode -ne 0)
        Assert-True ((($unknown.ErrorText -replace '\s', '')).Contains('SkipAclHardeningX')) $unknown.ErrorText

        $logs = @(Get-ChildItem -LiteralPath (Join-Path -Path $sandbox -ChildPath 'WindowsAutoCleanup\Logs') `
                -Filter '*.log' -File -ErrorAction SilentlyContinue)
        Assert-Equal 0 $logs.Count 'a binding failure still executed the script body'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Get-Help renders every parameter and the exit-code table' {
    $sandbox = New-TestSandbox -Prefix 'orch-help'
    try {
        $probe = New-ProbeScript -Body $script:InspectProbeBody -Path (Join-Path -Path $sandbox -ChildPath 'inspect.ps1')

        $result = Invoke-Probe -TimeoutMs 90000 -Environment @{ WAC_PROBE_MODE = 'help'; WAC_PROBE_RUN = $script:RunPath } `
            -CommandLine (ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $probe))

        Assert-True $result.Exited 'the help probe did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ($result.ErrorText)

        # Comment-based help only renders when the block is separated from #Requires by a blank
        # line; without it Get-Help falls back to a stub with no parameters and no notes.
        $expected = 'Scheduled,ResetWindowsUpdateBase,PruneSupersededDrivers,EnableLegacyDiskCleanup,SkipRecycleBin,' +
        'SkipCategory,LogLevel,BudgetMinutes,MutexName,SkipAclHardening'
        Assert-Equal $expected (Get-ProbeValue -Output $result.Output -Key 'PARAMS')

        $synopsis = [string](Get-ProbeValue -Output $result.Output -Key 'SYNOPSIS')
        Assert-True ($synopsis.Length -gt 20) ('the synopsis was [' + $synopsis + ']')

        $notes = [string](Get-ProbeValue -Output $result.Output -Key 'NOTES')
        Assert-True ($notes -match 'Exit codes') $notes
        foreach ($pair in @('0 success', '1 error', '2 completed', '3 another run', '4 elevation', '5 unsupported')) {
            Assert-True ($notes.Contains($pair)) ('the exit-code table is missing "' + $pair + '": ' + $notes)
        }

        $description = [string](Get-ProbeValue -Output $result.Output -Key 'DESCRIPTION')
        Assert-True ($description.Contains('-PruneSupersededDrivers')) `
            'the description no longer documents the opt-in destructive capabilities'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The five modules import together and every Wac command Run.ps1 calls resolves' {
    $sandbox = New-TestSandbox -Prefix 'orch-surface'
    try {
        $called = @{}
        foreach ($node in $script:RunAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $name = $node.GetCommandName()
            if ($name -and $name -match '^[A-Za-z]+-Wac[A-Za-z]+$') { $called[$name] = $true }
        }
        foreach ($node in $script:RunAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            # Run.ps1 declares a few helpers of its own; those are not part of the module surface.
            if ($called.ContainsKey($node.Name)) { [void]$called.Remove($node.Name) }
        }

        $names = @($called.Keys | Sort-Object)
        Assert-True ($names.Count -ge 20) ('only {0} module commands were found in Run.ps1' -f $names.Count)

        $probe = New-ProbeScript -Body $script:InspectProbeBody -Path (Join-Path -Path $sandbox -ChildPath 'inspect.ps1')
        $result = Invoke-Probe -TimeoutMs 120000 -CommandLine (ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $probe)) -Environment @{
            WAC_PROBE_MODE    = 'surface'
            WAC_PROBE_SRC     = $script:SrcRoot
            WAC_PROBE_COMMAND = ($names -join ',')
        }

        Assert-True $result.Exited 'the module-surface probe did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ($result.ErrorText)
        Assert-Equal '' ([string](Get-ProbeValue -Output $result.Output -Key 'MISSING')) 'Run.ps1 calls commands the modules do not export'
        Assert-Equal ([string]$names.Count) ([string](Get-ProbeValue -Output $result.Output -Key 'CHECKED'))
        foreach ($module in @('Core', 'FileSystem', 'Targets', 'Steps', 'Drivers')) {
            Assert-True ($result.Output.Contains('IMPORTED=' + $module)) ('module ' + $module + ' did not import: ' + $result.ErrorText)
        }
        Assert-Equal '' $result.ErrorText 'a module wrote to stderr while importing'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
