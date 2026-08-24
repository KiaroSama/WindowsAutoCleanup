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

Complete-TestRun
