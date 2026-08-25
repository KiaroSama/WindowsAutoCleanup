#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.Process.ps1: command-line quoting, the bounded
    external-process runner, handle-verified process-tree termination and single-instance locking.

.DESCRIPTION
    These exercise the real functions against real child processes. Nothing here inspects source
    text, and nothing asserts on the test process's own privilege level: the hosted Windows runner
    is elevated and a developer shell usually is not, so an assertion on that would pass in exactly
    one of the two places it has to work.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

# The host running this suite, taken from the live process rather than PATH.
$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

function Start-ProbeProcess {
    <#
    .SYNOPSIS
        Starts a probe script in its own process. Values arrive through the environment, so a
        quoting defect in the code under test cannot corrupt the probe's own inputs.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][hashtable]$Environment
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:HostExe
    $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $ScriptPath
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($key in $Environment.Keys) { $psi.EnvironmentVariables[$key] = [string]$Environment[$key] }

    return [System.Diagnostics.Process]::Start($psi)
}

function Wait-ProbeProcess {
    <#
    .SYNOPSIS
        Bounded wait plus process-tree kill, so a probe that proves a hang cannot hang this suite.
    #>
    param(
        [Parameter(Mandatory = $true)]$Process,
        [int]$TimeoutMs = 90000
    )

    $outTask = $Process.StandardOutput.ReadToEndAsync()
    $errTask = $Process.StandardError.ReadToEndAsync()
    $exited = $Process.WaitForExit($TimeoutMs)

    if (-not $exited) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = (Join-Path -Path $env:SystemRoot -ChildPath 'System32\taskkill.exe')
        $psi.Arguments = '/T /F /PID {0}' -f $Process.Id
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $killer = [System.Diagnostics.Process]::Start($psi)
        if ($killer) {
            [void]$killer.StandardOutput.ReadToEndAsync()
            [void]$killer.StandardError.ReadToEndAsync()
            [void]$killer.WaitForExit(10000)
            try { $killer.Dispose() } catch { $null = $_ }
        }
        [void]$Process.WaitForExit(10000)
    }

    [void]$outTask.Wait(5000)
    [void]$errTask.Wait(5000)

    $exitCode = -1
    if ($exited) { try { $exitCode = [int]$Process.ExitCode } catch { $exitCode = -1 } }

    return [PSCustomObject]@{
        Exited     = $exited
        ExitCode   = $exitCode
        Output     = $(if ($outTask.IsCompleted) { [string]$outTask.Result } else { '' })
        ErrorText  = $(if ($errTask.IsCompleted) { [string]$errTask.Result } else { '' })
    }
}

$script:ProbeBody = @'
Set-StrictMode -Version 2.0
Import-Module -Name $env:WAC_PROBE_MODULE -Force -DisableNameChecking -ErrorAction Stop

if ($env:WAC_PROBE_MODE -eq 'process') {
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $hung = Invoke-WacProcess -FilePath $env:WAC_PROBE_HOST `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 300') `
        -TimeoutMs 4000
    $watch.Stop()
    Write-Output ('TIMEDOUT={0}' -f $hung.TimedOut)
    Write-Output ('STARTED={0}' -f $hung.Started)
    Write-Output ('ELAPSEDMS={0}' -f [int]$watch.Elapsed.TotalMilliseconds)
    exit 0
}

if ($env:WAC_PROBE_MODE -eq 'mutex') {
    $held = Enter-WacSingleInstance -Name $env:WAC_PROBE_MUTEX
    if (-not $held) { Write-Output 'HELD=0'; exit 1 }
    Set-Content -LiteralPath $env:WAC_PROBE_READY -Value 'ready' -Encoding ASCII

    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $env:WAC_PROBE_STOP)) {
        Start-Sleep -Milliseconds 100
    }

    Exit-WacSingleInstance -Mutex $held
    Write-Output 'HELD=1'
    exit 0
}

Write-Output 'MODE=unknown'
exit 9
'@

# ---------------------------------------------------------------------------------------------
# Fixtures for the process-tree cases (ledger T-9)
# ---------------------------------------------------------------------------------------------

$script:TreeProbeBody = @'
Set-StrictMode -Version 2.0

if ($env:WAC_TREE_MODE -eq 'exit') { exit 0 }

if ($env:WAC_TREE_MODE -eq 'parent') {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:WAC_TREE_HOST
    $psi.Arguments = '-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 240"'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $spawned = [System.Diagnostics.Process]::Start($psi)
    Set-Content -LiteralPath $env:WAC_TREE_PIDFILE -Value ([string]$spawned.Id) -Encoding ASCII
}

Start-Sleep -Seconds 240
exit 0
'@

# A stand-in taskkill.exe. It records the argument vector it was handed and exits with whatever
# code the environment asks for, WITHOUT terminating anything - which is precisely the shape that
# used to be indistinguishable from a real kill.
$script:FakeTaskkillSource = @'
using System;
using System.IO;

public class WacFakeTaskkill
{
    public static int Main(string[] args)
    {
        string log = Environment.GetEnvironmentVariable("WAC_FAKE_TASKKILL_LOG");
        if (!string.IsNullOrEmpty(log))
        {
            File.AppendAllText(log, string.Join(" ", args) + Environment.NewLine);
        }

        int code = 0;
        int.TryParse(Environment.GetEnvironmentVariable("WAC_FAKE_TASKKILL_EXIT"), out code);
        return code;
    }
}
'@

$script:FakeTaskkillRoot = $null

function Get-FakeTaskkillRoot {
    <#
    .SYNOPSIS
        A directory that can stand in for %SystemRoot%, holding System32\taskkill.exe.
    .DESCRIPTION
        Stop-WacProcessTree resolves taskkill under $env:SystemRoot, so redirecting that variable
        inside the running process is enough to substitute it. Setting it is safe here and only
        here: the loader resolved this process's DLLs long before a test can touch the variable.

        The stand-in is COMPILED rather than faked with a copied Windows binary, because the cases
        need a chosen exit code and a recorded argument vector, and no shipped executable offers
        both. Add-Type -OutputType ConsoleApplication is not an option - measured, it works on
        Windows PowerShell 5.1 and fails on PowerShell 7 with "Both the assembly types
        'ConsoleApplication' and 'WindowsApplication' are not currently supported" - so the .NET
        Framework csc.exe every Windows install ships is used instead (measured 209-335 ms).

        Built once per suite. Returns $null when no compiler is present.
    #>
    if ($script:FakeTaskkillRoot) { return $script:FakeTaskkillRoot }

    $compiler = $null
    foreach ($relative in @('Microsoft.NET\Framework64\v4.0.30319\csc.exe', 'Microsoft.NET\Framework\v4.0.30319\csc.exe')) {
        $candidate = Join-Path -Path $env:SystemRoot -ChildPath $relative
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $compiler = $candidate; break }
    }
    if (-not $compiler) { return $null }

    $sandbox = New-TestSandbox -Prefix 'fakekill'
    $system32 = Join-Path -Path $sandbox -ChildPath 'System32'
    [void][System.IO.Directory]::CreateDirectory($system32)

    $source = Join-Path -Path $sandbox -ChildPath 'FakeTaskkill.cs'
    Set-Content -LiteralPath $source -Value $script:FakeTaskkillSource -Encoding ASCII
    $exe = Join-Path -Path $system32 -ChildPath 'taskkill.exe'

    [void](Invoke-WacProcess -FilePath $compiler -TimeoutMs 120000 `
            -ArgumentList @('/nologo', '/target:exe', ('/out:' + $exe), $source))

    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { return $null }

    $script:FakeTaskkillRoot = $sandbox
    return $sandbox
}

function Wait-ForTestFile {
    <#
    .SYNOPSIS
        Bounded wait for a probe to publish a value. Polling with a deadline, never a blind sleep.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$TimeoutMs = 30000
    )

    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([datetime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $text = ''
            try { $text = ([System.IO.File]::ReadAllText($Path)).Trim() } catch { $text = '' }
            if ($text) { return $text }
        }
        Start-Sleep -Milliseconds 50
    }

    return $null
}

function Start-TestSleeper {
    <#
    .SYNOPSIS
        One disposable child that sleeps until it is killed. The caller MUST dispose it.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $probe = Join-Path -Path $Sandbox -ChildPath 'tree.ps1'
    if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) {
        Set-Content -LiteralPath $probe -Value $script:TreeProbeBody -Encoding ASCII
    }

    return (Start-ProbeProcess -ScriptPath $probe -Environment @{ WAC_TREE_MODE = 'leaf' })
}

function Stop-TestProcess {
    param($Process)

    if (-not $Process) { return }
    try { if (-not $Process.HasExited) { $Process.Kill() } } catch { $null = $_ }
    try { [void]$Process.WaitForExit(10000) } catch { $null = $_ }
    try { $Process.Dispose() } catch { $null = $_ }
}

function Reset-WacTestLog {
    <#
    .SYNOPSIS
        Puts module logging back to a clean, non-degraded state.
    .DESCRIPTION
        The degraded flag is sticky by design, so a case that breaks logging on purpose would
        otherwise route every LATER case's lines to a fallback that is no longer injected.
    #>
    Set-WacLogWriter -Writer $null
    Set-WacLogFallbackWriter -Writer $null

    $sandbox = New-TestSandbox -Prefix 'logreset'
    try {
        [void](Initialize-WacRun -BaseName 'reset' -CandidateRoot @($sandbox) -BudgetMinutes 60)
        Close-WacLog
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Command-line quoting
# ---------------------------------------------------------------------------------------------

Test-Case 'ConvertTo-WacCommandLineArgument follows the CommandLineToArgvW rules' {
    Assert-Equal 'plain' (ConvertTo-WacCommandLineArgument -Value 'plain')
    Assert-Equal '"with space"' (ConvertTo-WacCommandLineArgument -Value 'with space')
    Assert-Equal '""' (ConvertTo-WacCommandLineArgument -Value '')
    Assert-Equal '"has\"quote"' (ConvertTo-WacCommandLineArgument -Value 'has"quote')
    Assert-Equal '"a b\\"' (ConvertTo-WacCommandLineArgument -Value 'a b\')
    Assert-Equal '"C:\Program Files\\"' (ConvertTo-WacCommandLineArgument -Value 'C:\Program Files\')
    Assert-Equal '"a\\\"b"' (ConvertTo-WacCommandLineArgument -Value 'a\"b')

    # No whitespace and no quote means no quoting: a trailing backslash is already literal there.
    Assert-Equal 'C:\trail\' (ConvertTo-WacCommandLineArgument -Value 'C:\trail\')
}

Test-Case 'ConvertTo-WacCommandLine joins the argument vector' {
    Assert-Equal '' (ConvertTo-WacCommandLine -ArgumentList @())
    Assert-Equal '-File "C:\Program Files\x.ps1" plain' `
        (ConvertTo-WacCommandLine -ArgumentList @('-File', 'C:\Program Files\x.ps1', 'plain'))
}

Test-Case 'Invoke-WacProcess hands the child the exact argument vector' {
    $sandbox = New-TestSandbox -Prefix 'argv'
    try {
        $echo = Join-Path -Path $sandbox -ChildPath 'echo args.ps1'
        Set-Content -LiteralPath $echo -Value 'foreach ($a in $args) { Write-Output ("ARG[" + $a + "]") }' -Encoding ASCII

        $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 60000 -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $echo,
            'plain', 'with space', 'C:\Program Files\', 'trailing\')

        Assert-Equal 0 $result.ExitCode
        Assert-False $result.TimedOut

        $lines = @(($result.StandardOutput -split "`r?`n") | Where-Object { $_.Trim() })
        Assert-Equal 4 $lines.Count ('child echoed: ' + ($lines -join ' | '))
        Assert-Equal 'ARG[plain]' $lines[0]
        Assert-Equal 'ARG[with space]' $lines[1]
        Assert-Equal 'ARG[C:\Program Files\]' $lines[2]
        Assert-Equal 'ARG[trailing\]' $lines[3]
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Bounded process execution
# ---------------------------------------------------------------------------------------------

Test-Case 'Invoke-WacProcess propagates a child exit code' {
    $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 60000 `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'exit 7')

    Assert-Equal 7 $result.ExitCode
    Assert-False $result.TimedOut
    Assert-True $result.Started
}

Test-Case 'Invoke-WacProcess kills a hung child at its deadline' {
    $sandbox = New-TestSandbox -Prefix 'hang'
    $probeProcess = $null
    try {
        $probe = Join-Path -Path $sandbox -ChildPath 'probe.ps1'
        Set-Content -LiteralPath $probe -Value $script:ProbeBody -Encoding ASCII

        # Run through a child: if the deadline is broken the probe hangs, not this suite.
        $probeProcess = Start-ProbeProcess -ScriptPath $probe -Environment @{
            WAC_PROBE_MODE   = 'process'
            WAC_PROBE_MODULE = (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1')
            WAC_PROBE_HOST   = $script:HostExe
        }

        $outcome = Wait-ProbeProcess -Process $probeProcess -TimeoutMs 90000
        Assert-True $outcome.Exited ('probe did not finish inside its bound: ' + $outcome.ErrorText)
        Assert-Equal 0 $outcome.ExitCode ('probe failed: ' + $outcome.ErrorText)
        Assert-True ($outcome.Output -match 'TIMEDOUT=True') ('probe said: ' + $outcome.Output)
        Assert-True ($outcome.Output -match 'STARTED=True') ('probe said: ' + $outcome.Output)

        $elapsed = 0
        if ($outcome.Output -match 'ELAPSEDMS=(\d+)') { $elapsed = [int]$Matches[1] }
        Assert-True ($elapsed -ge 4000) ('returned before the deadline: ' + $elapsed)
        Assert-True ($elapsed -lt 45000) ('deadline overshot badly: ' + $elapsed)
    }
    finally {
        if ($probeProcess) { try { $probeProcess.Dispose() } catch { $null = $_ } }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Set-WacProcessInvoker replaces the real runner and restores it' {
    Assert-Equal $null (Get-WacProcessInvoker)
    try {
        $captured = New-Object 'System.Collections.Generic.List[string]'
        Set-WacProcessInvoker -Invoker {
            param($FilePath, $ArgumentList, $TimeoutMs)
            $captured.Add(('{0}|{1}|{2}' -f $FilePath, ($ArgumentList -join ','), $TimeoutMs))
            return [PSCustomObject]@{
                ExitCode = 3010; TimedOut = $false; StandardOutput = 'injected'
                StandardError = ''; DurationMs = 1; Started = $true
            }
        }.GetNewClosure()

        Assert-True ($null -ne (Get-WacProcessInvoker))

        $result = Invoke-WacProcess -FilePath 'C:\Windows\System32\dism.exe' -TimeoutMs 1234 `
            -ArgumentList @('/Online', '/Cleanup-Image', '/StartComponentCleanup')

        Assert-Equal 3010 $result.ExitCode
        Assert-Equal 'injected' $result.StandardOutput
        Assert-Equal 1 $captured.Count
        Assert-Equal 'C:\Windows\System32\dism.exe|/Online,/Cleanup-Image,/StartComponentCleanup|1234' $captured[0]
    }
    finally {
        Set-WacProcessInvoker -Invoker $null
    }

    Assert-Equal $null (Get-WacProcessInvoker) 'the real runner must be restored'
}

# ---------------------------------------------------------------------------------------------
# Single instance
# ---------------------------------------------------------------------------------------------

Test-Case 'Enter-WacSingleInstance excludes a second process and releases on exit' {
    # A UNIQUE Local\ name: touching production's Global\ lock would make concurrent suites observe
    # each other and take the "already running" early exit, which reads exactly like a logic fault.
    $mutexName = 'Local\WacTest_{0}' -f [guid]::NewGuid().ToString('N')
    $sandbox = New-TestSandbox -Prefix 'mutex'
    $probeProcess = $null

    try {
        $probe = Join-Path -Path $sandbox -ChildPath 'probe.ps1'
        Set-Content -LiteralPath $probe -Value $script:ProbeBody -Encoding ASCII
        $readyFile = Join-Path -Path $sandbox -ChildPath 'ready.txt'
        $stopFile = Join-Path -Path $sandbox -ChildPath 'stop.txt'

        $probeProcess = Start-ProbeProcess -ScriptPath $probe -Environment @{
            WAC_PROBE_MODE   = 'mutex'
            WAC_PROBE_MODULE = (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1')
            WAC_PROBE_MUTEX  = $mutexName
            WAC_PROBE_READY  = $readyFile
            WAC_PROBE_STOP   = $stopFile
        }

        $deadline = (Get-Date).AddSeconds(45)
        while (-not (Test-Path -LiteralPath $readyFile) -and (Get-Date) -lt $deadline -and -not $probeProcess.HasExited) {
            Start-Sleep -Milliseconds 100
        }
        Assert-True (Test-Path -LiteralPath $readyFile) 'the probe never took the lock'

        $blocked = Enter-WacSingleInstance -Name $mutexName
        Assert-Equal $null $blocked 'a second run must be refused while the lock is held'

        Set-Content -LiteralPath $stopFile -Value 'stop' -Encoding ASCII
        $outcome = Wait-ProbeProcess -Process $probeProcess -TimeoutMs 45000
        Assert-True $outcome.Exited 'the probe did not release the lock inside its bound'
        Assert-True ($outcome.Output -match 'HELD=1') ('probe said: ' + $outcome.Output)

        $acquired = Enter-WacSingleInstance -Name $mutexName
        Assert-True ($null -ne $acquired) 'the lock must be available once the holder exits'
        Exit-WacSingleInstance -Mutex $acquired

        $again = Enter-WacSingleInstance -Name $mutexName
        Assert-True ($null -ne $again) 'Exit-WacSingleInstance must really release the lock'
        Exit-WacSingleInstance -Mutex $again
    }
    finally {
        if ($probeProcess) { try { $probeProcess.Dispose() } catch { $null = $_ } }
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Process-tree termination (ledger B2-6 part A, T-9)
# ---------------------------------------------------------------------------------------------

Test-Case 'Stop-WacProcessTree terminates a hung parent AND its child' {
    $sandbox = New-TestSandbox -Prefix 'tree'
    $parent = $null
    $child = $null
    try {
        $probe = Join-Path -Path $sandbox -ChildPath 'tree.ps1'
        Set-Content -LiteralPath $probe -Value $script:TreeProbeBody -Encoding ASCII
        $pidFile = Join-Path -Path $sandbox -ChildPath 'child.pid'

        $parent = Start-ProbeProcess -ScriptPath $probe -Environment @{
            WAC_TREE_MODE    = 'parent'
            WAC_TREE_HOST    = $script:HostExe
            WAC_TREE_PIDFILE = $pidFile
        }

        $childId = Wait-ForTestFile -Path $pidFile
        Assert-True ([bool]$childId) 'the probe never reported the child it started'

        # Bound to a HANDLE before the kill, so neither answer below can be forged by PID reuse.
        $child = Get-Process -Id ([int]$childId) -ErrorAction Stop
        Assert-False $child.HasExited 'the child was not running before the kill'

        Assert-True (Stop-WacProcessTree -ProcessId $parent.Id -TimeoutMs 20000) 'the tree kill reported failure'
        Assert-True ($parent.WaitForExit(15000)) 'the parent survived the tree kill'
        Assert-True ($child.WaitForExit(15000)) 'the child survived the tree kill'
    }
    finally {
        Stop-TestProcess -Process $parent
        Stop-TestProcess -Process $child
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Stop-WacProcessTree treats an already-exited target as done and never runs taskkill' {
    $fakeRoot = Get-FakeTaskkillRoot
    if (-not $fakeRoot) { Set-TestSkipped -Reason 'no .NET Framework csc.exe to build the stand-in taskkill' }

    $sandbox = New-TestSandbox -Prefix 'gone'
    $realRoot = $env:SystemRoot
    $probeProcess = $null
    try {
        $probe = Join-Path -Path $sandbox -ChildPath 'tree.ps1'
        Set-Content -LiteralPath $probe -Value $script:TreeProbeBody -Encoding ASCII

        $probeProcess = Start-ProbeProcess -ScriptPath $probe -Environment @{ WAC_TREE_MODE = 'exit' }
        Assert-True ($probeProcess.WaitForExit(60000)) 'the probe never exited'

        # THE PREMISE, asserted instead of assumed. This case used to reach a different branch
        # entirely: Get-Process cannot see a process that has exited, so the old body returned on
        # its "no such process" path and the already-exited test below it was never evaluated -
        # deleting that test left the whole suite green. What keeps the id openable here is the
        # handle $probeProcess still holds from Process.Start, and an OPEN handle that is already
        # signalled is precisely the state the fast path exists for. It is also the only way this
        # case can pass at all now, since nothing in the path under test asks about the id.
        Assert-True (Initialize-WacNative) 'the native helpers did not load'
        $handle = [IntPtr]::Zero
        Assert-Equal 0 ([WacNative]::OpenProcessForTermination($probeProcess.Id, [ref]$handle)) `
            'the exited target could not be opened, so the branch under test was not reachable'
        try {
            Assert-Equal 0 ([WacNative]::WaitForProcessExit($handle, 0)) `
                'the exited target was not signalled, so this is not the already-exited branch'
        }
        finally {
            [WacNative]::CloseProcessHandle($handle)
        }

        $log = Join-Path -Path $sandbox -ChildPath 'taskkill.log'
        $env:WAC_FAKE_TASKKILL_LOG = $log
        $env:WAC_FAKE_TASKKILL_EXIT = '255'
        $env:SystemRoot = $fakeRoot

        $verdict = Stop-WacProcessTree -ProcessId $probeProcess.Id -TimeoutMs 3000
        $env:SystemRoot = $realRoot

        # "Already gone" must never become a false alarm: the caller wanted it gone and it is gone.
        Assert-True $verdict 'a target that had already exited was reported as not terminated'
        Assert-False (Test-Path -LiteralPath $log) 'taskkill was run against a process that had already exited'
    }
    finally {
        $env:SystemRoot = $realRoot
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_LOG' -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_EXIT' -ErrorAction SilentlyContinue
        Stop-TestProcess -Process $probeProcess
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Stop-WacProcessTree reports an id that nothing owns as gone, without running taskkill' {
    $fakeRoot = Get-FakeTaskkillRoot
    if (-not $fakeRoot) { Set-TestSkipped -Reason 'no .NET Framework csc.exe to build the stand-in taskkill' }

    $sandbox = New-TestSandbox -Prefix 'noowner'
    $realRoot = $env:SystemRoot
    try {
        # The OTHER way a target can be gone, and the one the code must not confuse with "the state
        # could not be read". 2147483647 is above every id Windows allocates, so this is the arm
        # itself rather than a race against a real process that might still be exiting.
        Assert-True (Initialize-WacNative) 'the native helpers did not load'
        $handle = [IntPtr]::Zero
        Assert-Equal 87 ([WacNative]::OpenProcessForTermination(2147483647, [ref]$handle)) `
            'the premise failed: that id did not report ERROR_INVALID_PARAMETER'

        $log = Join-Path -Path $sandbox -ChildPath 'taskkill.log'
        $env:WAC_FAKE_TASKKILL_LOG = $log
        $env:WAC_FAKE_TASKKILL_EXIT = '0'
        $env:SystemRoot = $fakeRoot

        $verdict = Stop-WacProcessTree -ProcessId 2147483647 -TimeoutMs 1000
        $env:SystemRoot = $realRoot

        Assert-True $verdict 'an id no process owns was not reported as gone'
        Assert-False (Test-Path -LiteralPath $log) 'taskkill was run against an id nothing owns'
    }
    finally {
        $env:SystemRoot = $realRoot
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_LOG' -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_EXIT' -ErrorAction SilentlyContinue
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Stop-WacProcessTree does not report a target it could not open as terminated' {
    $lines = New-Object 'System.Collections.Generic.List[string]'
    try {
        Set-WacLogWriter -Writer (
            [PSCustomObject]@{} | Add-Member -MemberType ScriptMethod -Name WriteLine `
                -Value { param($text) [void]$lines.Add([string]$text) }.GetNewClosure() -PassThru)

        # "Cannot tell" is not "it is gone". Only a protected process really refuses
        # SYNCHRONIZE|PROCESS_TERMINATE - PID 4 and csrss both measured 5 ERROR_ACCESS_DENIED on
        # each host - and handing one of those to a kill path is not a case to run on a
        # workstation, so the failure is injected. The id stays one nothing can own, so a seam that
        # silently failed to take could still not reach a real process.
        Set-WacProcessHandleOpener -Opener {
            param($processId)
            $null = $processId
            [PSCustomObject]@{ Handle = [IntPtr]::Zero; Win32Error = 5 }
        }

        Assert-False (Stop-WacProcessTree -ProcessId 2147483647 -TimeoutMs 500) `
            'a target whose state could not be read at all was reported as terminated'

        $warned = @($lines | Where-Object { $_ -match 'unverifiable' })
        Assert-Equal 1 $warned.Count 'unreadable state was swallowed instead of warned about'
        Assert-True ($warned[0] -match '\[WARNING\]') ('the reason was not a WARNING: ' + $warned[0])
        Assert-True ($warned[0] -match 'win32Error=5') ('the reason did not survive: ' + $warned[0])
    }
    finally {
        Set-WacProcessHandleOpener -Opener $null
        Reset-WacTestLog
    }
}

Test-Case 'Stop-WacProcessTree does not accept a taskkill that exits 0 without killing anything' {
    # THE false positive this rewrite exists for. The stand-in exits 0 and terminates nothing, which
    # is exactly what the old body accepted as proof; the target must still end up dead.
    $fakeRoot = Get-FakeTaskkillRoot
    if (-not $fakeRoot) { Set-TestSkipped -Reason 'no .NET Framework csc.exe to build the stand-in taskkill' }

    $sandbox = New-TestSandbox -Prefix 'liar'
    $realRoot = $env:SystemRoot
    $target = $null
    try {
        $target = Start-TestSleeper -Sandbox $sandbox
        Assert-False $target.HasExited 'the target was not running before the kill'

        $log = Join-Path -Path $sandbox -ChildPath 'taskkill.log'
        $env:WAC_FAKE_TASKKILL_LOG = $log
        $env:WAC_FAKE_TASKKILL_EXIT = '0'
        $env:SystemRoot = $fakeRoot

        $verdict = Stop-WacProcessTree -ProcessId $target.Id -TimeoutMs 1500
        $env:SystemRoot = $realRoot

        Assert-True $verdict 'the escalation failed to terminate a target this process owns'
        Assert-True (Test-Path -LiteralPath $log) 'the stand-in taskkill was never invoked'
        Assert-Equal ('/T /F /PID ' + $target.Id) (([System.IO.File]::ReadAllText($log)).Trim()) `
            'taskkill was handed the wrong argument vector'

        # The whole point: a taskkill that merely EXITED proves nothing about the target.
        Assert-True ($target.WaitForExit(15000)) `
            'the target survived, so taskkill exiting 0 was accepted as proof of a kill'
    }
    finally {
        $env:SystemRoot = $realRoot
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_LOG' -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_EXIT' -ErrorAction SilentlyContinue
        Stop-TestProcess -Process $target
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Stop-WacProcessTree escalates when taskkill exits non-zero' {
    $fakeRoot = Get-FakeTaskkillRoot
    if (-not $fakeRoot) { Set-TestSkipped -Reason 'no .NET Framework csc.exe to build the stand-in taskkill' }

    $sandbox = New-TestSandbox -Prefix 'refused'
    $realRoot = $env:SystemRoot
    $target = $null
    try {
        $target = Start-TestSleeper -Sandbox $sandbox

        $log = Join-Path -Path $sandbox -ChildPath 'taskkill.log'
        $env:WAC_FAKE_TASKKILL_LOG = $log
        # 255 is what a real taskkill returns when it refuses; 128 is "not found". Measured on both
        # shipped hosts. Neither may be reported as a kill on its own.
        $env:WAC_FAKE_TASKKILL_EXIT = '255'
        $env:SystemRoot = $fakeRoot

        $verdict = Stop-WacProcessTree -ProcessId $target.Id -TimeoutMs 1500
        $env:SystemRoot = $realRoot

        Assert-True $verdict 'the escalation failed to terminate a target this process owns'
        Assert-True (Test-Path -LiteralPath $log) 'the stand-in taskkill was never invoked'
        Assert-True ($target.WaitForExit(15000)) 'the target survived a taskkill that had already failed'
    }
    finally {
        $env:SystemRoot = $realRoot
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_LOG' -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_EXIT' -ErrorAction SilentlyContinue
        Stop-TestProcess -Process $target
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Stop-WacProcessTree still terminates the target when taskkill cannot be started' {
    $sandbox = New-TestSandbox -Prefix 'notaskkill'
    $realRoot = $env:SystemRoot
    $target = $null
    try {
        $target = Start-TestSleeper -Sandbox $sandbox

        # An empty stand-in root: there is no System32\taskkill.exe at all, so Process.Start throws.
        $env:SystemRoot = $sandbox
        $verdict = Stop-WacProcessTree -ProcessId $target.Id -TimeoutMs 1500
        $env:SystemRoot = $realRoot

        Assert-True $verdict 'a target this process owns was not terminated when taskkill was missing'
        Assert-True ($target.WaitForExit(15000)) 'the target survived'
    }
    finally {
        $env:SystemRoot = $realRoot
        Stop-TestProcess -Process $target
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
