#Requires -Version 5.1

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot '_ProbeProcess.ps1')
Import-Module (Join-Path $script:RepoRoot 'src\WindowsAutoCleanup.Core.psm1') -Force -DisableNameChecking
$script:CoreModule = Get-Module WindowsAutoCleanup.Core

function Assert-ForeignProcessSurvives {
    param([switch]$OlderParentRelation)
    $replace = {
        param($Name, $Body)
        & $script:CoreModule { param($n, $b) Set-Item -LiteralPath ('Function:script:' + $n) -Value $b } $Name $Body
    }
    $decoy = $null
    $root = $null
    $originalRead = & $script:CoreModule { (Get-Command Get-WacProcessDescendantId).ScriptBlock }
    $originalBind = & $script:CoreModule { (Get-Command Open-WacProcessBinding).ScriptBlock }
    $originalKill = & $script:CoreModule {
        $command = Get-Command Invoke-WacTaskkillTree -ErrorAction SilentlyContinue
        if ($command) { $command.ScriptBlock }
    }
    try {
        $payload = '-NoProfile -NonInteractive -Command "[void]([Threading.ManualResetEvent]::new($false).WaitOne(30000))"'
        $decoy = Start-ProbeProcess -CommandLine $payload
        $root = Start-ProbeProcess -CommandLine $payload
        # Injected scriptblocks retain the defining script's session state.
        $script:OwnershipRootId = $root.Id
        $script:OwnershipDecoyId = $decoy.Id
        $script:OwnershipOriginalBind = $originalBind
        # A stale/reused parent id makes a snapshot nominate a process which is not ours.
        # Only these two owned fixture processes are ever candidates; no host processes are killed.
        & $replace -Name Get-WacProcessDescendantId -Body {
            param([int]$ProcessId)
            $null = $ProcessId
            return , ([int[]]@($script:OwnershipDecoyId))
        }
        & $replace -Name Invoke-WacTaskkillTree -Body {
            param([int]$ProcessId, [int]$TimeoutMs)
            $null = $ProcessId; $null = $TimeoutMs
            return 0
        }
        if ($OlderParentRelation) {
            & $replace -Name Open-WacProcessBinding -Body {
                param([int]$ProcessId)
                $binding = & $script:OwnershipOriginalBind -ProcessId $ProcessId
                if ($binding.Handle -ne [IntPtr]::Zero) {
                    $stamp = (Get-Process -Id $ProcessId).StartTime.ToUniversalTime().ToFileTimeUtc()
                    Add-Member -InputObject $binding -MemberType NoteProperty -Name Created -Value $stamp -Force
                    if ($ProcessId -eq $script:OwnershipDecoyId) {
                        Add-Member -InputObject $binding -MemberType NoteProperty -Name ParentId -Value $script:OwnershipRootId -Force
                    }
                }
                return $binding
            }
        }
        $verdict = Stop-WacProcessTree -ProcessId $root.Id -TimeoutMs 2000
        Assert-True ($root.WaitForExit(5000)) 'the owned root survived'
        Assert-False $decoy.HasExited 'a foreign snapshot candidate was terminated'
        Assert-False (@($verdict.Bound) -contains $decoy.Id) 'a foreign identity entered the owned set'
    }
    finally {
        foreach ($process in @($root, $decoy)) {
            if ($null -eq $process) { continue }
            try { if (-not $process.HasExited) { $process.Kill() }; [void]$process.WaitForExit(5000) }
            finally { $process.Dispose() }
        }
        & $replace -Name Get-WacProcessDescendantId -Body $originalRead
        & $replace -Name Open-WacProcessBinding -Body $originalBind
        if ($originalKill) { & $replace -Name Invoke-WacTaskkillTree -Body $originalKill }
        else { & $script:CoreModule { Remove-Item -LiteralPath Function:script:Invoke-WacTaskkillTree } }
    }
}

Test-Case 'a nominated sibling with a different bound parent is not killed' {
    Assert-ForeignProcessSurvives
}

Test-Case 'a child older than the process now holding its recorded parent id is not killed' {
    Assert-ForeignProcessSurvives -OlderParentRelation
}

Test-Case 'probe cleanup still stops its owned child when output acquisition throws' {
    $child = Start-ProbeProcess -CommandLine (
        '-NoProfile -NonInteractive -Command "[void]([Threading.ManualResetEvent]::new($false).WaitOne(30000))"')
    try {
        $wrapper = [PSCustomObject]@{ Inner = $child; Id = $child.Id }
        Add-Member -InputObject $wrapper -MemberType ScriptProperty -Name StandardOutput -Value { throw 'controlled stream failure' }
        Add-Member -InputObject $wrapper -MemberType ScriptProperty -Name HasExited -Value { $this.Inner.HasExited }
        Add-Member -InputObject $wrapper -MemberType ScriptMethod -Name WaitForExit -Value {
            param([int]$Milliseconds)
            $this.Inner.WaitForExit($Milliseconds)
        }
        $failed = $false
        try { $null = Wait-ProbeProcess -Process $wrapper -TimeoutMs 1000 }
        catch { $failed = $true }
        Assert-True $failed 'the controlled output failure was swallowed'
        Assert-True ($child.WaitForExit(5000)) 'exceptional unwinding left the probe running'
    }
    finally {
        try { if (-not $child.HasExited) { $child.Kill() }; [void]$child.WaitForExit(5000) }
        finally { $child.Dispose() }
    }
}

# ---------------------------------------------------------------------------------------------
# WAC-04: an exception AFTER the process started must not claim it never ran
# ---------------------------------------------------------------------------------------------

Test-Case 'a failure after the tool started reports Started true and never fabricates termination' {
    # One catch used to cover both sides of Process.Start, answering Started=$false and
    # TerminationProven=$true for either. So a post-start fault - a failed output read, a failed
    # wait, an unreadable exit code - reported that the tool never ran and that nothing was left
    # alive, while the process could still be executing. Driver pruning reads Started to decide it
    # may delete the backup directory and the pending marker, so that lie authorised discarding the
    # only recovery copy of a package a destructive pnputil delete may already have removed.
    #
    # The fault is injected at the first log line INSIDE the timeout branch, which is reached only
    # after a real child has started and outlived its bound. Nothing before Process.Start throws, so
    # a red result here can only come from the post-start path.
    $replace = {
        param($Name, $Body)
        & $script:CoreModule { param($n, $b) Set-Item -LiteralPath ('Function:script:' + $n) -Value $b } $Name $Body
    }
    $originalLog = & $script:CoreModule { (Get-Command Write-WacLog).ScriptBlock }

    try {
        # This case is about the FALLBACK path's catch block, which only runs when ownership was
        # unavailable. Pinning the launcher to $null is what selects that path deliberately instead
        # of letting the case pass or fail on whether this machine happens to support job objects.
        # The owned path's own lifecycle verdicts are covered in OwnedProcess.Tests.ps1.
        Set-WacOwnedProcessLauncher -Launcher { return $null }

        & $replace 'Write-WacLog' {
            param(
                [Parameter(Mandatory = $true)][string]$Level,
                [Parameter(Mandatory = $true)][string]$Component,
                [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
                [hashtable]$Data
            )
            # The shim has to accept the real signature so every caller still binds, but only
            # $Message selects the injection point. Discarding the rest explicitly keeps the
            # analyzer's unused-parameter rule satisfied without weakening the parameter list.
            $null = $Level, $Component, $Data
            if ($Message -like '*exceeded its deadline*') { throw 'injected post-start failure' }
        }

        $host51 = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $result = Invoke-WacProcess -FilePath $host51 `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 120') `
            -TimeoutMs 1500 -Component 'Test'

        Assert-True ([bool]$result.Started) `
            'a tool that really started was reported as never started'
        Assert-False ([bool]$result.TimedOut) `
            'an unknown post-start outcome was reported as the deadline case it is not'
        Assert-True ($result.PSObject.Properties.Name -ccontains 'TerminationProven') `
            'the result dropped its termination claim entirely'
        Assert-Equal $null $result.ExitCode 'an exit code was reported for a run whose result was never read'
    }
    finally {
        & $replace 'Write-WacLog' $originalLog
        Set-WacOwnedProcessLauncher -Launcher $null
    }
}

Test-Case 'a genuine pre-start failure still reports Started false' {
    # The control case. Without it the fix above could be "always say it started", which would be a
    # different lie rather than a repair.
    $missing = Join-Path -Path $env:TEMP -ChildPath ('wac-no-such-tool-' + [guid]::NewGuid().ToString('N') + '.exe')

    $result = Invoke-WacProcess -FilePath $missing -ArgumentList @() -TimeoutMs 5000 -Component 'Test'

    Assert-False ([bool]$result.Started) 'a tool that never started was reported as started'
    Assert-True ([bool]$result.TerminationProven) `
        'nothing was started, so there is nothing whose termination could be in doubt'
    Assert-Equal $null $result.ExitCode 'an exit code was reported for a tool that never ran'
}

# ---------------------------------------------------------------------------------------------
# WAC-05R (partial): a root that exits is not proof that its children, or its output, are finished
# ---------------------------------------------------------------------------------------------

Test-Case 'a child holding the inherited pipe after the root exits is reported, not silently dropped' {
    # A pipe reaches EOF only when EVERY write handle on it closes, so a read still outstanding after
    # the root has exited is positive evidence that a process this run started inherited the handle
    # and is still alive.
    #
    # Both halves used to lie about that. TerminationProven was set $true for any run that was not
    # killed on a timeout - a normal exit 0 "proved" the tree was gone - and the two fixed 5 s read
    # waits turned an unfinished read into the EMPTY STRING, which a caller parsing stdout reads as a
    # real answer ("pnputil listed no drivers") rather than as a missing one.
    #
    # The fixture owns both processes: the root is this host, the grandchild is a bounded PowerShell child whose
    # pid the root writes out, and the teardown kills it. Force the managed fallback: the owned
    # path now correctly waits for and terminates descendants rather than returning this state.
    # A live admission deadline lets the root run; the operation allowance bounds both pipe reads.
    $marker = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('wacpipe-{0}.txt' -f [guid]::NewGuid().ToString('N').Substring(0, 10))
    $grandchildId = 0
    try {
        $payload = "`$p = Start-Process -FilePath '$script:HostExe' -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 15' -NoNewWindow -PassThru; Set-Content -LiteralPath '$marker' -Value ([string]`$p.Id); exit 0"
        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddHours(1))
        Set-WacOwnedProcessLauncher -Launcher { param($FilePath, $ArgumentList); $null = $FilePath; $null = $ArgumentList; return $null }
        Reset-WacShutdownReserve -ReserveMs 250

        $held = Invoke-WacProcess -FilePath $script:HostExe `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $payload) -TimeoutMs 4000

        if (Test-Path -LiteralPath $marker) {
            $recorded = (Get-Content -LiteralPath $marker -Raw).Trim()
            if ($recorded -match '^\d+$') { $grandchildId = [int]$recorded }
        }
        Assert-True ($grandchildId -gt 0) 'the fixture never recorded the child that was supposed to hold the pipe'

        Assert-True ([bool]$held.Started) 'the root did not start, so the case proves nothing'
        Assert-True (-not $held.TimedOut) 'the root did not exit on its own, so this is not the shape under test'
        Assert-Equal 0 ([int]$held.ExitCode) 'the root did not exit cleanly, so its exit code is not the reassuring one'
        Assert-True (-not $held.OutputComplete) `
            'an output read that never finished was handed over as though it were the whole output'
        Assert-True (-not $held.TerminationProven) `
            'a clean root exit was reported as proof that the tree had stopped, while a child still held its pipe'
    }
    finally {
        if ($grandchildId -gt 0) { Stop-Process -Id $grandchildId -Force -ErrorAction SilentlyContinue }
        Set-WacOwnedProcessLauncher -Launcher $null
        Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddHours(1))
        Reset-WacShutdownReserve
    }
}

Test-Case 'an ordinary tool that leaves nothing behind still reports complete output and a proven stop' {
    # The control. Without it the assertions above would also pass if OutputComplete were hard-wired
    # to $false, and every real tool call in the project would start reporting an unproven stop.
    $clean = Invoke-WacProcess -FilePath $script:HostExe `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', "'done'; exit 0") -TimeoutMs 20000

    Assert-True ([bool]$clean.Started) 'the control tool did not start'
    Assert-Equal 0 ([int]$clean.ExitCode) 'the control tool did not exit cleanly'
    Assert-True ([bool]$clean.OutputComplete) 'a tool that finished normally was reported as having incomplete output'
    Assert-True ([bool]$clean.TerminationProven) 'a tool that exited on its own was reported as not proven stopped'
    Assert-True ($clean.StandardOutput -match 'done') 'the control tool output did not reach the caller'
}

Complete-TestRun
