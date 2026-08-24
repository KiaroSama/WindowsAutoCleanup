#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.Core: path canonicalisation, bidirectional path
    protection, command-line quoting, the bounded process runner, single-instance locking,
    collision-proof logging, log retention and the machine-trust check.

.DESCRIPTION
    These exercise the real functions against real files and real child processes. Nothing here
    inspects source text, and nothing asserts on the test process's own privilege level: the hosted
    Windows runner is elevated and a developer shell usually is not, so an assertion on that would
    pass in exactly one of the two places it has to work.
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
# Path canonicalisation
# ---------------------------------------------------------------------------------------------

Test-Case 'Get-WacNormalizedPath normalises drive, case and trailing separator' {
    Assert-Equal 'C:' (Get-WacNormalizedPath -Path 'c:')
    Assert-Equal 'C:' (Get-WacNormalizedPath -Path 'C:\')
    Assert-Equal 'C:\Temp' (Get-WacNormalizedPath -Path 'C:\Temp\')
    Assert-Equal 'C:\Temp\sub' (Get-WacNormalizedPath -Path 'c:\Temp\sub')
    Assert-Equal 'C:\Temp' (Get-WacNormalizedPath -Path 'C:\Temp\sub\..')
}

Test-Case 'Get-WacNormalizedPath rejects drive-relative, UNC and empty forms' {
    Assert-Equal $null (Get-WacNormalizedPath -Path 'C:foo')
    Assert-Equal $null (Get-WacNormalizedPath -Path 'C:foo\bar')
    Assert-Equal $null (Get-WacNormalizedPath -Path '\\server\share\x')
    Assert-Equal $null (Get-WacNormalizedPath -Path '\\?\UNC\server\share')
    Assert-Equal $null (Get-WacNormalizedPath -Path '')
    Assert-Equal $null (Get-WacNormalizedPath -Path '   ')
    Assert-Equal $null (Get-WacNormalizedPath -Path $null)
}

Test-Case 'Get-WacNormalizedPath accepts the extended-length form and strips its prefix' {
    Assert-Equal 'C:\Temp\x' (Get-WacNormalizedPath -Path '\\?\C:\Temp\x')
    Assert-Equal 'C:' (Get-WacNormalizedPath -Path '\\?\C:\')
    Assert-Equal 'C:' (Get-WacNormalizedPath -Path '\\?\C:')
}

Test-Case 'Get-WacNormalizedPath expands 8.3 names so both sides of a comparison agree' {
    # A hosted runner has an 8.3 TEMP (C:\Users\RUNNER~1\...). Mixing an expanded and an unexpanded
    # spelling is invisible locally and breaks there, so the expansion must be part of the contract.
    Assert-Equal (Get-WacNormalizedPath -Path $env:ProgramFiles) (Get-WacNormalizedPath -Path 'C:\PROGRA~1')

    $sandbox = New-TestSandbox -Prefix 'norm'
    $once = Get-WacNormalizedPath -Path $sandbox
    Assert-Equal $once (Get-WacNormalizedPath -Path $once) 'normalisation must be idempotent'
    Assert-Equal $once (Get-WacNormalizedPath -Path ($sandbox + '\'))
    Remove-TestSandbox -Path $sandbox
}

Test-Case 'Test-WacIsOnTargetDrive accepts only the C: drive' {
    Assert-True (Test-WacIsOnTargetDrive -Path 'C:')
    Assert-True (Test-WacIsOnTargetDrive -Path 'c:\Windows\Temp')
    Assert-False (Test-WacIsOnTargetDrive -Path 'D:\payload')
    Assert-False (Test-WacIsOnTargetDrive -Path 'C:foo')
    Assert-False (Test-WacIsOnTargetDrive -Path '\\server\share')
    Assert-False (Test-WacIsOnTargetDrive -Path '')
}

# ---------------------------------------------------------------------------------------------
# Path protection (ledger P0-5)
# ---------------------------------------------------------------------------------------------

Test-Case 'Test-WacIsProtectedPath refuses the fixed system roots' {
    Clear-WacProtectedRoot
    foreach ($fixed in @('C:', 'C:\Windows', 'C:\Users', 'C:\ProgramData', 'C:\Windows\System32',
                         'C:\Windows\WinSxS', 'C:\Windows\System32\DriverStore', 'C:\$Recycle.Bin')) {
        Assert-True (Test-WacIsProtectedPath -Path $fixed) ('{0} must be protected' -f $fixed)
    }
    Assert-False (Test-WacIsProtectedPath -Path 'C:\Windows\Temp')
}

Test-Case 'Test-WacIsProtectedPath protects a registered root in BOTH directions' {
    Clear-WacProtectedRoot
    Add-WacProtectedRoot -Path 'C:\Temp\wacproj'

    Assert-True (Test-WacIsProtectedPath -Path 'C:\Temp\wacproj') 'the root itself'
    Assert-True (Test-WacIsProtectedPath -Path 'C:\Temp\wacproj\src\file.ps1') 'a path inside the root'
    Assert-True (Test-WacIsProtectedPath -Path 'C:\Temp') 'an ANCESTOR of the root'
    Assert-True (Test-WacIsProtectedPath -Path 'c:\temp\WACPROJ') 'comparison is case-insensitive'

    Assert-False (Test-WacIsProtectedPath -Path 'C:\Temp\wacprojx') 'a sibling sharing a name prefix'
    Assert-False (Test-WacIsProtectedPath -Path 'C:\Other\wacproj2')
    Clear-WacProtectedRoot
}

Test-Case 'Test-WacIsProtectedPath fails closed on an unusable path' {
    Clear-WacProtectedRoot
    Assert-True (Test-WacIsProtectedPath -Path 'C:relative')
    Assert-True (Test-WacIsProtectedPath -Path '\\server\share')
    Assert-True (Test-WacIsProtectedPath -Path '')
}

Test-Case 'Get-WacLongPath adds the extended-length prefix only above the threshold' {
    $short = 'C:\' + ('a' * 200)
    Assert-Equal $short (Get-WacLongPath -Path $short)

    $atThreshold = 'C:\' + ('a' * 237)
    Assert-Equal 240 $atThreshold.Length
    Assert-Equal ('\\?\' + $atThreshold) (Get-WacLongPath -Path $atThreshold)

    $justUnder = 'C:\' + ('a' * 236)
    Assert-Equal 239 $justUnder.Length
    Assert-Equal $justUnder (Get-WacLongPath -Path $justUnder)

    $already = '\\?\C:\' + ('a' * 300)
    Assert-Equal $already (Get-WacLongPath -Path $already)

    $relative = 'sub\' + ('a' * 300)
    Assert-Equal $relative (Get-WacLongPath -Path $relative)
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
# Logging
# ---------------------------------------------------------------------------------------------

Test-Case 'New-WacLogFile never truncates a same-second collision' {
    $sandbox = New-TestSandbox -Prefix 'log'
    try {
        # Start early in the second so both creations share one timestamp and really collide.
        while ((Get-Date).Millisecond -gt 600) { Start-Sleep -Milliseconds 50 }

        $first = New-WacLogFile -BaseName 'collide' -CandidateRoot @($sandbox)
        $second = New-WacLogFile -BaseName 'collide' -CandidateRoot @($sandbox)

        Assert-True ($null -ne $first) 'the first log was not created'
        Assert-True ($null -ne $second) 'the second log was not created'
        Assert-False ($first.Path -ieq $second.Path) 'both runs took the same log path'

        $first.Writer.WriteLine('FIRST')
        $second.Writer.WriteLine('SECOND')
        $first.Writer.Dispose()
        $second.Writer.Dispose()

        Assert-True ((Get-Content -LiteralPath $first.Path -Raw) -match 'FIRST') 'the first log was truncated'
        Assert-True ((Get-Content -LiteralPath $second.Path -Raw) -match 'SECOND')

        Assert-Equal 2 @(Get-ChildItem -LiteralPath $sandbox -Filter 'collide_*.log' -File).Count
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Write-WacLog refuses a level outside the documented set' {
    # Never omit a mandatory parameter here instead: an interactive host would prompt and the suite
    # would hang rather than fail.
    Assert-Throws { Write-WacLog -Level 'CHATTY' -Component 'Test' -Message 'x' } 'does not belong to the set'
    Assert-Throws { Initialize-WacRun -BaseName 'x' -LogLevel 'CHATTY' } 'does not belong to the set'
}

Test-Case 'Remove-WacOldLog keeps exactly the newest N files' {
    $sandbox = New-TestSandbox -Prefix 'ret'
    try {
        $stamp = [datetime]::UtcNow.AddHours(-10)
        for ($i = 0; $i -lt 5; $i++) {
            $path = Join-Path -Path $sandbox -ChildPath ('keep_{0}.log' -f $i)
            Set-Content -LiteralPath $path -Value $i -Encoding ASCII
            [System.IO.File]::SetLastWriteTimeUtc($path, $stamp.AddMinutes($i))
        }
        Set-Content -LiteralPath (Join-Path -Path $sandbox -ChildPath 'unrelated.txt') -Value 'x' -Encoding ASCII

        $removed = Remove-WacOldLog -LogDirectory $sandbox -Pattern 'keep_*.log' -KeepCount 2
        Assert-Equal 3 $removed

        $left = @(Get-ChildItem -LiteralPath $sandbox -Filter 'keep_*.log' -File | ForEach-Object { $_.Name } | Sort-Object)
        Assert-Equal 2 $left.Count
        Assert-Equal 'keep_3.log' $left[0]
        Assert-Equal 'keep_4.log' $left[1]
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $sandbox -ChildPath 'unrelated.txt')) 'a non-matching file was deleted'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacOldLog never deletes the active log' {
    $sandbox = New-TestSandbox -Prefix 'active'
    try {
        Clear-WacProtectedRoot
        Assert-True (Initialize-WacRun -BaseName 'active' -CandidateRoot @($sandbox) -BudgetMinutes 60) 'the run log was not created'

        $activePath = Get-WacLogPath
        Assert-True ($null -ne $activePath)

        # Release the writer first. While the handle is open the file cannot be deleted anyway, so
        # leaving it open would let this case pass without the retention guard existing at all.
        Close-WacLog

        # Three decoys stamped in the future, so retention sorts the ACTIVE log last and would
        # delete it were it not explicitly excluded.
        $future = [datetime]::UtcNow.AddHours(5)
        for ($i = 0; $i -lt 3; $i++) {
            $path = Join-Path -Path $sandbox -ChildPath ('active_decoy_{0}.log' -f $i)
            Set-Content -LiteralPath $path -Value $i -Encoding ASCII
            [System.IO.File]::SetLastWriteTimeUtc($path, $future.AddMinutes($i))
        }

        $removed = Remove-WacOldLog -LogDirectory $sandbox -Pattern 'active*.log' -KeepCount 3
        Assert-Equal 0 $removed 'the active log was deleted by retention'
        Assert-True (Test-Path -LiteralPath $activePath) 'the active log file is gone'
        Assert-Equal $activePath (Get-WacLogPath)
    }
    finally {
        Close-WacLog
        Clear-WacProtectedRoot
        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddHours(1))
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Deadline
# ---------------------------------------------------------------------------------------------

Test-Case 'Get-WacStepTimeoutMs never hands a step more time than the run budget has' {
    try {
        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddSeconds(2))
        $granted = Get-WacStepTimeoutMs -RequestedMs 3600000
        Assert-True ($granted -le 2000) ('step got more than the budget: ' + $granted)
        Assert-True ($granted -gt 0)

        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddHours(1))
        Assert-Equal 5000 (Get-WacStepTimeoutMs -RequestedMs 5000)
        Assert-False (Test-WacDeadlineExpired)

        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddSeconds(-1))
        Assert-True (Test-WacDeadlineExpired)
        Assert-Equal 0 (Get-WacStepTimeoutMs -RequestedMs 5000)
    }
    finally {
        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddHours(1))
    }
}

# ---------------------------------------------------------------------------------------------
# Machine trust
# ---------------------------------------------------------------------------------------------

Test-Case 'Test-WacPathIsMachineTrusted trusts the canonical Windows PowerShell host' {
    $canonical = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $trust = Test-WacPathIsMachineTrusted -Path $canonical
    Assert-True $trust.IsTrusted ('reason: ' + $trust.Reason + ' owner: ' + $trust.Owner)
    Assert-Equal 0 @($trust.UntrustedWriters).Count
}

Test-Case 'Test-WacPathIsMachineTrusted refuses a path a non-administrative group can write' {
    $sandbox = New-TestSandbox -Prefix 'trust'
    try {
        # Granting BUILTIN\Users write access to a directory this test created is what makes the
        # expectation deterministic: asserting on the sandbox's inherited ACL instead would depend
        # on whether the current account happens to be an administrator.
        $acl = Get-Acl -LiteralPath $sandbox
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')),
            [System.Security.AccessControl.FileSystemRights]::Modify,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $sandbox -AclObject $acl

        $trust = Test-WacPathIsMachineTrusted -Path $sandbox
        Assert-False $trust.IsTrusted 'a user-writable path must never be trusted for SYSTEM execution'
        # The REASON differs by who owns the sandbox (an elevated runner owns it as an administrator,
        # a developer shell does not), so only the verdict is asserted.
        Assert-True ([bool]$trust.Reason) 'a refusal must say why'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Test-WacPathIsMachineTrusted fails closed on a path that does not exist' {
    $trust = Test-WacPathIsMachineTrusted -Path 'C:\wac-does-not-exist-4f2a\host.exe'
    Assert-False $trust.IsTrusted
    Assert-True ($trust.Reason -match 'does not exist')
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

# ---------------------------------------------------------------------------------------------
# Audit health (ledger B2-8, T-10)
# ---------------------------------------------------------------------------------------------

Test-Case 'A log directory that cannot be created leaves the run not durable, and the reason is not lost' {
    $sandbox = New-TestSandbox -Prefix 'nolog'
    $captured = New-Object 'System.Collections.Generic.List[string]'
    try {
        # A FILE where the log directory is supposed to be: New-Item -ItemType Directory refuses it,
        # so every candidate root fails and no log file exists.
        $blocked = Join-Path -Path $sandbox -ChildPath 'Logs'
        [System.IO.File]::WriteAllText($blocked, 'not a directory')

        Set-WacLogFallbackWriter -Writer { param($line) $captured.Add($line) }.GetNewClosure()

        Assert-False (Initialize-WacRun -BaseName 'nolog' -CandidateRoot @($blocked) -BudgetMinutes 5) `
            'a run with no log file reported that logging was ready'

        $health = Get-WacLogHealth
        Assert-False $health.IsDurable 'a run with no log file must not claim a durable audit trail'
        Assert-True $health.Degraded
        Assert-Equal 'Injected' $health.FallbackKind 'the reason never reached a verified fallback sink'
        Assert-True ($health.Reason -match 'No log file could be created')

        Assert-Equal 1 $captured.Count 'the failure reason was swallowed instead of written to the fallback'
        Assert-True ($captured[0] -match [regex]::Escape($blocked)) ('the fallback line said: ' + $captured[0])

        # A degraded run keeps auditing: later lines go to the fallback rather than evaporating.
        Write-WacLog -Level ERROR -Component 'Probe' -Message 'still audited'
        Assert-Equal 2 $captured.Count 'a log line written after the failure went nowhere'
        Assert-True ($captured[1] -match 'still audited')
    }
    finally {
        Reset-WacTestLog
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Retention and the log directory survive a run that has no log at all' {
    $sandbox = New-TestSandbox -Prefix 'nullpath'
    try {
        $blocked = Join-Path -Path $sandbox -ChildPath 'Logs'
        [System.IO.File]::WriteAllText($blocked, 'not a directory')
        Set-WacLogFallbackWriter -Writer { param($line) $null = $line }

        Assert-False (Initialize-WacRun -BaseName 'nullpath' -CandidateRoot @($blocked) -BudgetMinutes 5)
        Assert-Equal $null (Get-WacLogPath)
        Assert-Equal $null (Get-WacLogDirectory) 'the accessor must answer $null rather than throw'

        # The crash this replaces: the uninstaller composed Split-Path -Parent (Get-WacLogPath) and
        # a null there is a terminating parameter-binding error on BOTH shipped hosts.
        Assert-Throws { Split-Path -Parent (Get-WacLogPath) } 'null' `
            'Split-Path stopped rejecting a null path, so the accessor is no longer needed'

        Assert-Equal 0 (Remove-WacOldLog -LogDirectory (Get-WacLogDirectory) -Pattern '*.log' -KeepCount 5) `
            'retention threw or deleted something when there was no log directory'
    }
    finally {
        Reset-WacTestLog
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A log write that fails mid-run stops the run claiming a durable audit trail' {
    $sandbox = New-TestSandbox -Prefix 'writefail'
    $captured = New-Object 'System.Collections.Generic.List[string]'
    try {
        Assert-True (Initialize-WacRun -BaseName 'writefail' -CandidateRoot @($sandbox) -BudgetMinutes 5)
        Assert-True (Get-WacLogHealth).IsDurable 'the control failed: a healthy log is not durable'

        Set-WacLogFallbackWriter -Writer { param($line) $captured.Add($line) }.GetNewClosure()
        Set-WacLogWriter -Writer (
            [PSCustomObject]@{} | Add-Member -MemberType ScriptMethod -Name WriteLine `
                -Value { param($text) $null = $text; throw 'the volume is full' } -PassThru)

        Write-WacLog -Level ERROR -Component 'Probe' -Message 'this line must not vanish'

        $health = Get-WacLogHealth
        Assert-False $health.IsDurable 'a run that lost a log line still claimed a durable audit trail'
        Assert-True $health.Degraded
        Assert-Equal 1 $health.FailedWrites
        Assert-True ($health.Reason -match 'A log write failed')
        Assert-Equal 1 $captured.Count 'the lost line never reached the fallback'
        Assert-True ($captured[0] -match 'this line must not vanish')
    }
    finally {
        Reset-WacTestLog
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A module import failure captured before the log existed is folded into the run log' {
    $sandbox = New-TestSandbox -Prefix 'bootstrap'
    try {
        # Exactly the shape an entry point must use: a bootstrap line written BEFORE the import, so
        # a parse or import failure has somewhere to land, then adopted once the real log opens.
        $broken = Join-Path -Path $sandbox -ChildPath 'Broken.psm1'
        Set-Content -LiteralPath $broken -Value 'function Broken { if ($true) {' -Encoding ASCII

        $bootstrap = Join-Path -Path $sandbox -ChildPath 'bootstrap.log'
        try {
            Import-Module -Name $broken -Force -DisableNameChecking -ErrorAction Stop
            Assert-True $false 'the deliberately broken module imported cleanly'
        }
        catch {
            [System.IO.File]::AppendAllText($bootstrap, ('IMPORT FAILED {0}' -f $_.Exception.Message))
        }

        $logRoot = Join-Path -Path $sandbox -ChildPath 'Logs'
        Assert-True (Initialize-WacRun -BaseName 'bootstrap' -CandidateRoot @($logRoot) `
                -BudgetMinutes 5 -BootstrapLogPath $bootstrap) 'the run log was not created'

        $logPath = Get-WacLogPath
        Assert-True (Get-WacLogHealth).IsDurable 'adopting a readable bootstrap log must not degrade the run'
        Close-WacLog

        # Closing the log must not retroactively make a healthy run look incomplete: computing the
        # exit code after the log is closed is the normal order.
        Assert-True (Get-WacLogHealth).IsDurable 'Close-WacLog turned a durable audit trail into a broken one'

        $text = [System.IO.File]::ReadAllText($logPath)
        Assert-True ($text -match '\[Bootstrap\]') 'the bootstrap lines were never folded into the run log'
        Assert-True ($text -match 'IMPORT FAILED') 'the import failure was lost'
    }
    finally {
        Reset-WacTestLog
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A bootstrap log that cannot be read is a lost audit log, not a silent success' {
    $sandbox = New-TestSandbox -Prefix 'bootlock'
    $lock = $null
    try {
        $bootstrap = Join-Path -Path $sandbox -ChildPath 'bootstrap.log'
        [System.IO.File]::WriteAllText($bootstrap, 'IMPORT FAILED something')

        # Opened with FileShare.None, so ReadAllLines cannot get at it.
        $lock = New-Object System.IO.FileStream(
            $bootstrap, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

        $logRoot = Join-Path -Path $sandbox -ChildPath 'Logs'
        Assert-True (Initialize-WacRun -BaseName 'bootlock' -CandidateRoot @($logRoot) `
                -BudgetMinutes 5 -BootstrapLogPath $bootstrap) 'the run log itself should still open'

        $health = Get-WacLogHealth
        Assert-False $health.IsDurable 'a bootstrap log that could not be adopted still reported a durable audit trail'
        Assert-True ($health.Reason -match 'could not be read')
    }
    finally {
        if ($lock) { try { $lock.Dispose() } catch { $null = $_ } }
        Reset-WacTestLog
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# State-root trust (ledger B2-8)
# ---------------------------------------------------------------------------------------------

Test-Case 'Test-WacStatePathIsTrusted accepts a machine state root and reports who can still write' {
    $system32 = Join-Path -Path $env:SystemRoot -ChildPath 'System32'
    $trust = Test-WacStatePathIsTrusted -Path $system32

    Assert-True $trust.IsTrusted ('reason: ' + $trust.Reason)
    Assert-Equal 0 @($trust.Failures).Count
    Assert-Equal 0 @($trust.Writers).Count 'System32 must have no non-administrative writers'
    # System32 -> C:\Windows -> C:. The ancestors are the point: write access one level up is enough
    # to rename the whole directory aside.
    Assert-Equal 3 @($trust.Checked).Count ('checked: ' + (@($trust.Checked) -join ', '))
}

Test-Case 'Test-WacStatePathIsTrusted refuses a state root a non-administrative group can replace' {
    $sandbox = New-TestSandbox -Prefix 'statetrust'
    try {
        $acl = Get-Acl -LiteralPath $sandbox
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')),
            [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $sandbox -AclObject $acl

        $trust = Test-WacStatePathIsTrusted -Path $sandbox
        Assert-False $trust.IsTrusted 'a directory BUILTIN\Users can empty was accepted as a state root'
        Assert-True (@($trust.Failures).Count -ge 1) 'the refusal recorded no failure to explain itself'
        Assert-True ($trust.Reason -match 'S-1-5-32-545') ('reason: ' + $trust.Reason)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Test-WacStatePathIsTrusted refuses a reparse point in the chain' {
    $sandbox = New-TestSandbox -Prefix 'statelink'
    try {
        $real = Join-Path -Path $sandbox -ChildPath 'real'
        [void][System.IO.Directory]::CreateDirectory($real)
        $link = Join-Path -Path $sandbox -ChildPath 'link'

        # mklink /J needs no elevation, so this runs identically on a developer shell and on CI.
        $cmd = Join-Path -Path $env:SystemRoot -ChildPath 'System32\cmd.exe'
        [void](Invoke-WacProcess -FilePath $cmd -TimeoutMs 30000 `
                -ArgumentList @('/c', 'mklink', '/J', $link, $real))
        if (-not (Test-Path -LiteralPath $link)) { Set-TestSkipped -Reason 'this filesystem refused to create a junction' }

        $trust = Test-WacStatePathIsTrusted -Path $link
        Assert-False $trust.IsTrusted 'a junction was accepted as a state root'
        Assert-True ($trust.Reason -match 'reparse point') ('reason: ' + $trust.Reason)
    }
    finally {
        $link = Join-Path -Path $sandbox -ChildPath 'link'
        if (Test-Path -LiteralPath $link) { try { [System.IO.Directory]::Delete($link, $false) } catch { $null = $_ } }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Test-WacStatePathIsTrusted records a depth-limit refusal instead of passing quietly' {
    $trust = Test-WacStatePathIsTrusted -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -MaxDepth 1

    Assert-False $trust.IsTrusted 'a chain that was never walked to the root was reported trusted'
    Assert-Equal 1 @($trust.Failures).Count
    Assert-True ($trust.Reason -match 'depth limit') ('reason: ' + $trust.Reason)
}

Test-Case 'Test-WacStatePathIsTrusted judges a not-yet-created root by the directory it will live in' {
    $sandbox = New-TestSandbox -Prefix 'statenew'
    try {
        $future = Join-Path -Path $sandbox -ChildPath 'WindowsAutoCleanup\Logs'
        $trust = Test-WacStatePathIsTrusted -Path $future

        Assert-Equal (Get-WacNormalizedPath -Path $sandbox) $trust.Path `
            'the nearest existing ancestor was not the thing verified'
        Assert-True ($trust.Reason -match [regex]::Escape($sandbox)) ('reason: ' + $trust.Reason)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
