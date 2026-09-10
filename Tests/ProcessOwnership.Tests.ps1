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

Complete-TestRun
