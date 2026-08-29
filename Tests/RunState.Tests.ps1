#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.RunState.ps1: collision-proof log creation, the
    directory a log may be created in, log retention, the run budget, and the audit-health verdict
    a run's exit code rests on.

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
    # Close the log the CASE opened, before anything else. Initialize-WacRun below does not
    # close a log that is already open - it just replaces the writer - so without this the old
    # FileStream stays live on the case's own sandbox, Remove-TestSandbox cannot delete the
    # locked .log, and it fails silently. Measured: 12 leaked sandbox directories in %TEMP%.
    Close-WacLog

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

Test-Case 'A caller that names its own log root gets NOT EVALUATED, never a machine-trust verdict' {
    # $null is the whole vocabulary for "this question was never asked", and both readers of it -
    # Get-WacRunLevelOutcome and Get-OperationSafetyVerdict - depend on that meaning.
    #
    # It is asserted here rather than assumed because the answer used to depend on the PRIVILEGE of
    # whoever ran the suite: the old code recorded a real verdict for any root whenever the process
    # was elevated, so an elevated host - which every hosted CI runner is - got a verdict for a
    # sandbox under TEMP that no caller had claimed anything about. Now the claim follows the roots
    # the module chose, so this holds at either privilege level and on both hosts.
    $sandbox = New-TestSandbox -Prefix 'trustnull'
    try {
        Assert-True (Initialize-WacRun -BaseName 'trustnull' -CandidateRoot @($sandbox) -BudgetMinutes 5) `
            'the run log was not created'
        Assert-True (Get-WacLogHealth).IsDurable 'the control failed: a healthy log is not durable'
        Assert-Equal $null (Get-WacStateTrust) `
            'a caller-named log root produced a machine-trust verdict nobody had claimed'
    }
    finally {
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

# ---------------------------------------------------------------------------------------------
# The log directory is never ADOPTED (audit brief 8, root 1 - the log/state half)
#
# The defect: New-WacLogFile did Test-Path followed by New-Item -Force, and New-Item -Force
# creates-or-ADOPTS. Initialize-WacRun's preflight can only verify the nearest EXISTING ancestor
# when the candidate root does not exist yet, so a local standard user allowed to create names in
# that ancestor - which the default %ProgramData% descriptor allows - could introduce the
# predictable candidate directory in the window and have the SYSTEM audit log written into it. The
# object actually written to was never verified at all.
#
# Both interleavings are covered below: the attacker gets there BEFORE the check, and the attacker
# gets there AFTER the check but BEFORE the create. The second one needs a deterministic seam, not
# a sleep or a thread - the window is microseconds wide and blind waits are banned - so
# Set-WacDirectoryCreateProbe stands inside it, the same way Set-WacProcessInvoker stands inside
# the process runner.
# ---------------------------------------------------------------------------------------------

function Format-TestRefusal {
    <#
    .SYNOPSIS
        The Path/Reason pairs New-WacLogFile appends to -Refusal, as one readable line.
    #>
    param([Parameter(Mandatory = $true)][AllowNull()]$Refusal)

    if ($null -eq $Refusal -or $Refusal.Count -eq 0) { return '<no refusal was recorded>' }
    return ((@($Refusal | ForEach-Object { '{0}: {1}' -f $_.Path, $_.Reason })) -join ' | ')
}

function Get-TestTreeFingerprint {
    <#
    .SYNOPSIS
        Every entry under a directory, with its bytes. 'ABSENT' when the directory is not there.
    .DESCRIPTION
        Content and not merely names, so "was written through" and "was created under" are both
        visible. Compared against itself before and after, it sees a FileStream and a File.Delete -
        neither of which a recorder of cmdlet calls could intercept.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [System.IO.Directory]::Exists($Path)) { return 'ABSENT' }

    $line = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in @([System.IO.Directory]::GetFileSystemEntries($Path, '*', [System.IO.SearchOption]::AllDirectories) | Sort-Object)) {
        if ([System.IO.Directory]::Exists($entry)) { [void]$line.Add(('DIR|{0}' -f $entry)); continue }
        [void]$line.Add(('FILE|{0}|{1}' -f $entry, [System.IO.File]::ReadAllText($entry)))
    }
    return ($line -join [Environment]::NewLine)
}

function Close-TestLogHandle {
    <#
    .SYNOPSIS
        Releases a writer a REFUSAL case did not expect to get, so a failing case cannot leave its
        own sandbox on disk.
    .DESCRIPTION
        Every case below asserts that New-WacLogFile returned $null. When one of them fails - which
        is exactly what the mutation runs make it do - it returned an OPEN writer instead, and the
        assertion throws before anything disposes it. Remove-TestSandbox then fails SILENTLY on the
        locked log file and the sandbox survives the run. Measured: 14 leaked directories across the
        mutation runs. Called from finally, so it runs on the failing path as well as the passing one.
    #>
    param([AllowNull()]$Created)

    if ($null -eq $Created) { return }
    try { $Created.Writer.Dispose() } catch { $null = $_ }
}

function Invoke-PlantedDirectoryProbe {
    <#
    .SYNOPSIS
        Plants a junction where a log directory is about to be created, and proves the run refuses
        it without writing a byte through it.
    .DESCRIPTION
        Interleaving (a) of the two the brief asks for: the attacker is already there when the check
        runs. The plant is a JUNCTION rather than a plain directory on purpose - a plain directory's
        owner depends on who ran the suite, and a hosted Windows runner is elevated while a developer
        shell usually is not, so the refusal would be privilege-dependent and would assert nothing in
        one of the two places it has to work. A reparse point is the kernel's own answer at either
        privilege level.

        The two shapes fail at different points, and each is its own case so one cannot hide the
        other's result. 'leaf' puts the junction AT the candidate root; 'anchor' puts it one level
        up, where the log directory has still to be CREATED - the shape that would otherwise create
        a directory inside the attacker's target before anything looked at it.
    #>
    param([Parameter(Mandatory = $true)][ValidateSet('leaf', 'anchor')][string]$Shape)

    $sandbox = New-TestSandbox -Prefix ('adopt-' + $Shape)
    $created = $null
    try {
        $outside = Join-Path -Path $sandbox -ChildPath 'outside'
        [void][System.IO.Directory]::CreateDirectory($outside)
        [System.IO.File]::WriteAllText((Join-Path -Path $outside -ChildPath 'sentinel.txt'), 'untouched')

        $state = Join-Path -Path $sandbox -ChildPath 'state'
        [void][System.IO.Directory]::CreateDirectory($state)

        if ($Shape -eq 'leaf') {
            $root = Join-Path -Path $state -ChildPath 'Logs'
            New-Item -ItemType Junction -Path $root -Target $outside -ErrorAction Stop | Out-Null
        }
        else {
            $link = Join-Path -Path $state -ChildPath 'link'
            New-Item -ItemType Junction -Path $link -Target $outside -ErrorAction Stop | Out-Null
            $root = Join-Path -Path $link -ChildPath 'Logs'
        }

        $before = Get-TestTreeFingerprint -Path $outside
        Assert-True ($before.Contains('untouched')) 'the fixture never wrote the sentinel it is about to protect'

        $refusal = New-Object 'System.Collections.Generic.List[object]'
        $created = New-WacLogFile -BaseName 'adopt' -CandidateRoot @($root) -Refusal $refusal

        Assert-Equal $null $created 'a planted directory was adopted and a log was opened in it'
        Assert-Equal $before (Get-TestTreeFingerprint -Path $outside) `
            'the attacker''s target was created under or written to'
        Assert-Equal 1 $refusal.Count ('refusals: ' + (Format-TestRefusal -Refusal $refusal))
        Assert-True ($refusal[0].Reason -match 'reparse point') ('refusal said: ' + (Format-TestRefusal -Refusal $refusal))
    }
    finally {
        Close-TestLogHandle -Created $created
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A log directory that IS a planted link is refused, and nothing is written through it' {
    Invoke-PlantedDirectoryProbe -Shape 'leaf'
}

Test-Case 'A log directory REACHED THROUGH a planted link is refused before anything is created' {
    Invoke-PlantedDirectoryProbe -Shape 'anchor'
}

Test-Case 'A log directory that appears between the check and the create is refused, not adopted' {
    # Interleaving (b), and the reason the create probe exists. The probe runs in the one place the
    # attacker would have to reach - after the existence probe, before the create - so the race is
    # DETERMINISTIC rather than a sleep and a hope.
    $sandbox = New-TestSandbox -Prefix 'adopt-window'
    $seen = New-Object 'System.Collections.Generic.List[string]'
    $created = $null
    try {
        $state = Join-Path -Path $sandbox -ChildPath 'state'
        [void][System.IO.Directory]::CreateDirectory($state)
        $root = Join-Path -Path $state -ChildPath 'Logs'
        Assert-False ([System.IO.Directory]::Exists($root)) 'the fixture pre-created the directory the attacker is supposed to plant'

        Set-WacDirectoryCreateProbe -ScriptBlock {
            param($path)
            $seen.Add([string]$path)
            [void][System.IO.Directory]::CreateDirectory($path)
            [System.IO.File]::WriteAllText((Join-Path -Path $path -ChildPath 'planted.txt'), 'attacker content')
        }.GetNewClosure()

        $refusal = New-Object 'System.Collections.Generic.List[object]'
        $created = New-WacLogFile -BaseName 'window' -CandidateRoot @($root) -Refusal $refusal

        # The seam really did fire. Without this the case could pass because nothing ever raced.
        Assert-Equal 1 $seen.Count 'the create probe never ran, so no race was staged at all'
        Assert-True ($seen[0] -ieq $root) (('the probe was handed the wrong path: ' + $seen[0]))

        Assert-Equal $null $created 'the directory that appeared in the window was adopted and written to'
        Assert-Equal 1 $refusal.Count (Format-TestRefusal -Refusal $refusal)
        Assert-True ($refusal[0].Reason -match 'appeared after it was checked for') ('refusal said: ' + (Format-TestRefusal -Refusal $refusal))

        # The attacker's directory is left exactly as the attacker made it: one file, its own.
        Assert-Equal ('FILE|{0}|attacker content' -f (Join-Path -Path $root -ChildPath 'planted.txt')) `
        (Get-TestTreeFingerprint -Path $root) 'something was created or written inside the planted directory'
    }
    finally {
        Set-WacDirectoryCreateProbe -ScriptBlock $null
        Close-TestLogHandle -Created $created
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A benign steady state creates the log directory once and never refuses it afterwards' {
    # The control, and the trap this project has fallen into twice: a guard that refuses a perfectly
    # ordinary second run. The same candidate is used TWICE over the state the first run left.
    $sandbox = New-TestSandbox -Prefix 'benign-root'
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'state\WindowsAutoCleanup\Logs'

        $refusal = New-Object 'System.Collections.Generic.List[object]'
        $first = New-WacLogFile -BaseName 'benign' -CandidateRoot @($root) -Refusal $refusal
        Assert-True ($null -ne $first) ('the first run created no log: ' + (Format-TestRefusal -Refusal $refusal))
        $first.Writer.WriteLine('FIRST')
        $first.Writer.Dispose()

        $second = New-WacLogFile -BaseName 'benign' -CandidateRoot @($root) -Refusal $refusal
        Assert-True ($null -ne $second) ('the second run over the first run''s own state refused: ' + (Format-TestRefusal -Refusal $refusal))
        $second.Writer.Dispose()

        Assert-Equal 0 $refusal.Count (Format-TestRefusal -Refusal $refusal)
        Assert-Equal 2 @(Get-ChildItem -LiteralPath $root -Filter 'benign_*.log' -File).Count 'both logs should be side by side'
        Assert-True ([System.IO.File]::ReadAllText($first.Path).Contains('FIRST')) 'the first log lost its content'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A refused owner or DACL stops the log before any child of the directory is touched' {
    # -RequireMachineTrust is the switch a SYSTEM run passes, and the judge is the seam that makes
    # its answer reproducible at either privilege level. What is asserted is the CONSEQUENCE: a "no"
    # leaves the directory without a single child. The directory itself may exist - this call is
    # allowed to have created it under a proved anchor before the descriptor was read, and undoing
    # that would be a destructive act taken on an unproven belief - which is exactly what the
    # primitive's contract says.
    $sandbox = New-TestSandbox -Prefix 'judge-no'
    $created = $null
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'state\Logs'

        Set-WacDirectoryTrustJudge -ScriptBlock {
            param($sddl)
            $null = $sddl
            return [PSCustomObject]@{ IsTrusted = $false; Owner = $null; Reason = 'test judge: not administrative' }
        }

        $refusal = New-Object 'System.Collections.Generic.List[object]'
        $created = New-WacLogFile -BaseName 'judged' -CandidateRoot @($root) -RequireMachineTrust -Refusal $refusal

        Assert-Equal $null $created 'a directory the descriptor rule refused was written to anyway'
        Assert-Equal 1 $refusal.Count (Format-TestRefusal -Refusal $refusal)
        Assert-True ($refusal[0].Reason -match 'not administrative') ('refusal said: ' + (Format-TestRefusal -Refusal $refusal))
        Assert-Equal 0 @(Get-ChildItem -LiteralPath $root -Force).Count 'a child was created inside a refused directory'
    }
    finally {
        Close-TestLogHandle -Created $created
        Set-WacDirectoryTrustJudge -ScriptBlock $null
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The descriptor judged is the one read from the directory''s own handle' {
    # The other half of the same guarantee. A verdict reached on some other object's descriptor
    # would be worth nothing, so the SDDL the rule is handed is compared against the descriptor of
    # the directory that was really opened. The owner SID is used as the comparison because it is
    # the field the whole rule turns on and it does not depend on the suite's privilege level.
    $sandbox = New-TestSandbox -Prefix 'judge-sddl'
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'state\Logs'
        [void][System.IO.Directory]::CreateDirectory($root)
        $expectedOwner = [string](Get-Acl -LiteralPath $root).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        Assert-True ($expectedOwner -match '^S-1-') (('the fixture could not read an owner SID: ' + $expectedOwner))

        $judged = New-Object 'System.Collections.Generic.List[string]'
        Set-WacDirectoryTrustJudge -ScriptBlock {
            param($sddl)
            $judged.Add([string]$sddl)
            return [PSCustomObject]@{ IsTrusted = $true; Owner = $null; Reason = 'test judge: accepted' }
        }.GetNewClosure()

        $created = New-WacLogFile -BaseName 'sddl' -CandidateRoot @($root) -RequireMachineTrust
        Assert-True ($null -ne $created) 'the log was not created'
        $created.Writer.Dispose()

        Assert-Equal 1 $judged.Count 'the descriptor rule was never asked, so nothing was verified'

        # The owner is PARSED out of the SDDL, never matched as a substring. SDDL abbreviates the
        # well-known SIDs, so a directory owned by BUILTIN\Administrators renders as 'O:BA' and a
        # Contains('O:S-1-5-32-544') check fails on it - which is exactly what happened: it passed in
        # an unelevated shell, where the owner is a plain user SID with no alias, and failed on the
        # elevated CI runner, where it is Administrators. RawSecurityDescriptor resolves both forms
        # to the same SecurityIdentifier, so this now asserts the same thing at either privilege.
        $judgedOwner = (New-Object System.Security.AccessControl.RawSecurityDescriptor($judged[0])).Owner
        Assert-Equal $expectedOwner ([string]$judgedOwner.Value) `
        ('the descriptor judged was not this directory''s. sddl {0}' -f $judged[0])
    }
    finally {
        Set-WacDirectoryTrustJudge -ScriptBlock $null
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A bound file refuses a name that is already taken instead of writing through it' {
    # The primitive the driver-backup half needs for its manifest, pending marker and commit file,
    # proved here once. A planted name must come back as a collision with its bytes intact - not be
    # opened, truncated, appended to, or followed somewhere else.
    $sandbox = New-TestSandbox -Prefix 'bound-file'
    $directory = $null
    $fresh = $null
    try {
        $directory = Open-WacTrustedDirectory -Path $sandbox
        Assert-True $directory.IsTrusted (('the sandbox could not be opened: ' + [string]$directory.Reason))

        $planted = Join-Path -Path $sandbox -ChildPath 'planted.log'
        [System.IO.File]::WriteAllText($planted, 'attacker content')

        $collision = New-WacBoundFile -DirectoryHandle $directory.Handle -Name 'planted.log'
        Assert-Equal 'Collision' $collision.Kind ('NTSTATUS 0x{0:X8}' -f $collision.NtStatus)
        Assert-Equal $null $collision.Stream 'a refused create still handed back a writable stream'
        Assert-Equal 'attacker content' ([System.IO.File]::ReadAllText($planted)) 'the planted file was written through'

        # And a free name still works, so the refusal is about collision and not about failing.
        $fresh = New-WacBoundFile -DirectoryHandle $directory.Handle -Name 'fresh.log'
        Assert-Equal 'Created' $fresh.Kind ('NTSTATUS 0x{0:X8}' -f $fresh.NtStatus)
        $fresh.Stream.Dispose()
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $sandbox -ChildPath 'fresh.log')) 'the bound create wrote nothing'
    }
    finally {
        if ($fresh -and $fresh.Stream) { try { $fresh.Stream.Dispose() } catch { $null = $_ } }
        if ($directory) { Close-WacTrustedDirectory -Handle $directory.Handle }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A directory held by the primitive cannot be renamed out from under the creation' {
    # The pin. The share mode withholds DELETE, so between the verification and the create nothing
    # can move the verified object aside - which is what makes the verification worth having rather
    # than a statement about a directory that is no longer there.
    $sandbox = New-TestSandbox -Prefix 'pinned'
    $directory = $null
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'state'
        [void][System.IO.Directory]::CreateDirectory($root)
        $aside = Join-Path -Path $sandbox -ChildPath 'aside'

        $directory = Open-WacTrustedDirectory -Path $root
        Assert-True $directory.IsTrusted (('the directory was not opened: ' + [string]$directory.Reason))

        Assert-Throws { [System.IO.Directory]::Move($root, $aside) } '' `
            'the verified directory was renamed away while the primitive held it'
        Assert-False ([System.IO.Directory]::Exists($aside)) 'the rename went through after all'

        Close-WacTrustedDirectory -Handle $directory.Handle
        $directory = $null

        # And the pin really is released, so nothing is left locked behind a finished run.
        [System.IO.Directory]::Move($root, $aside)
        Assert-True ([System.IO.Directory]::Exists($aside)) 'the directory stayed pinned after it was closed'
    }
    finally {
        if ($directory) { Close-WacTrustedDirectory -Handle $directory.Handle }
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
