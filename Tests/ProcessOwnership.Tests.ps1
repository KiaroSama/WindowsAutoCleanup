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

Complete-TestRun
