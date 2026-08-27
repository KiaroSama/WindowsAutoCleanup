#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.Process.ps1: command-line quoting, the bounded external
    process runner and single-instance locking.

.DESCRIPTION
    These exercise the real functions against real child processes. Nothing here inspects source
    text, and nothing asserts on the test process's own privilege level: the hosted Windows runner
    is elevated and a developer shell usually is not, so an assertion on that would pass in exactly
    one of the two places it has to work.

    Proving a tree has STOPPED is its own source file and its own suite; see ProcessTree.Tests.ps1.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_ProcessFixtures.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
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


Test-Case 'Invoke-WacProcess does not report a deadline kill it could not prove' {
    # The stop result used to be discarded entirely: [void](Stop-WacProcessTree ...). A bounded
    # timeout therefore looked identical whether the tool was provably gone or still deleting files,
    # and the run went on to report its verdict either way.
    #
    # Only the handle OPEN is injected. A protected process is the only thing that really refuses
    # SYNCHRONIZE|PROCESS_TERMINATE - PID 4 and csrss measured 5 ERROR_ACCESS_DENIED on both hosts -
    # and handing one of those to a kill path is not a case to run on a workstation. The child is a
    # real one and exits on its own a few seconds later, so nothing is left behind by a kill that
    # deliberately cannot land.
    $lines = New-Object 'System.Collections.Generic.List[string]'
    try {
        Set-WacLogWriter -Writer (
            [PSCustomObject]@{} | Add-Member -MemberType ScriptMethod -Name WriteLine `
                -Value { param($text) [void]$lines.Add([string]$text) }.GetNewClosure() -PassThru)

        Set-WacProcessHandleOpener -Opener {
            param($processId)
            $null = $processId
            [PSCustomObject]@{ Handle = [IntPtr]::Zero; Win32Error = 5 }
        }

        $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 2000 -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-Command',
            '$d = [DateTime]::UtcNow.AddSeconds(6); while ([DateTime]::UtcNow -lt $d) { Start-Sleep -Milliseconds 200 }')

        Assert-True $result.TimedOut 'the child was not held to its deadline'
        Assert-False $result.TerminationProven `
            'a termination that could not be established was reported as a clean bounded timeout'

        $critical = @($lines | Where-Object { $_ -match 'could not be proven terminated' })
        Assert-Equal 1 $critical.Count ('the unproven kill was never reported: ' + ($lines -join "`n"))
        Assert-True ($critical[0] -match '\[CRITICAL\]') `
            ('a tool that may still be running was reported below the highest level -LogLevel accepts: ' + $critical[0])
    }
    finally {
        Set-WacProcessHandleOpener -Opener $null
        Reset-WacTestLog
    }
}
Complete-TestRun
