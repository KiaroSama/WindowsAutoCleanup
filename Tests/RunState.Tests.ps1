#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.RunState.ps1: collision-proof log creation, log
    retention, the run budget, and the audit-health verdict a run's exit code rests on.

.DESCRIPTION
    These exercise the real functions against real files. Nothing here inspects source text, and
    nothing asserts on the test process's own privilege level: the hosted Windows runner is
    elevated and a developer shell usually is not, so an assertion on that would pass in exactly
    one of the two places it has to work.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

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

Test-Case 'The run budget is measured from the caller start and holds a shutdown margin back' {
    # Initialize-WacRun armed its deadline from wherever it was called, so everything a caller had
    # to do FIRST - five module imports, the machine-wide lock, the trust preflight - fell outside
    # the budget entirely, and the caller had nothing left to write its own verdict with at the far
    # end. Both ends are asserted here because either one alone would pass a half fix.
    $sandbox = New-TestSandbox -Prefix 'budget'
    try {
        Assert-True (Initialize-WacRun -BaseName 'budget' -CandidateRoot @($sandbox) -BudgetMinutes 10 `
                -StartUtc ([datetime]::UtcNow.AddMinutes(-9)) -ShutdownMarginSeconds 30) 'the log was not opened'

        # 10 minutes from 9 minutes ago is 1 minute, less a 30 second margin: about 30 seconds left.
        # Ignoring -StartUtc would leave ~9.5 minutes; ignoring the margin would leave ~60 seconds.
        $remaining = Get-WacRemainingMs
        Assert-True ($remaining -gt 20000 -and $remaining -lt 45000) `
        ('the budget did not run from the caller start with a margin held back: {0} ms left' -f $remaining)

        Close-WacLog

        # And the default is unchanged for a caller with nothing to account for: the installer and
        # the uninstaller pass neither.
        Assert-True (Initialize-WacRun -BaseName 'budget2' -CandidateRoot @($sandbox) -BudgetMinutes 10) 'the log was not opened'
        $plain = Get-WacRemainingMs
        Assert-True ($plain -gt 570000 -and $plain -le 600000) `
        ('a caller that names no start instant lost part of its budget: {0} ms left' -f $plain)
    }
    finally {
        Close-WacLog
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
