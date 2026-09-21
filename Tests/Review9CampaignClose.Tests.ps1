#Requires -Version 5.1
<#
.SYNOPSIS
    Verify bounded close, both native completion facts and retained exactly-once close evidence.
.DESCRIPTION
    Only harmless disposable child processes are created. No VM or cleanup operation is performed.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
. (Join-Path $PSScriptRoot 'Campaign\WacCampaignScenario.ps1')
Test-Case 'The campaign closer terminates an identified held root using its live handles' {
    $sandbox = New-TestSandbox -Prefix 'campaign-close-proof'
    $started = $null; $held = $null
    try {
        $path = Join-Path $sandbox 'sleep.ps1'
        [IO.File]::WriteAllText($path, 'Start-Sleep -Seconds 60; exit 0')
        $started = Invoke-WacCampaignHost -ScriptPath $path -PassThruProcess -TimeoutSeconds 60
        $held = Suspend-WacCampaignTree -ProcessId $started.Process.Id -ExpectedCreatedUtc $started.Process.StartTime.ToUniversalTime() -Job $started.Launch.Job
        Write-Host ('Hold: {0}; {1}; job={2}; root={3}' -f $held.RootHeld, $held.Detail, $started.Launch.Job, $started.Launch.Process)
        Assert-True $held.RootHeld $held.Detail
        Close-WacCampaignLaunch -Started $started
        Assert-True $started.CloseProof.TerminationProven
        Assert-True $started.CloseProof.RootSignalled
        Assert-Equal 0 $started.CloseProof.ActiveProcesses
        Assert-Equal ([IntPtr]::Zero) $started.Launch.Job 'the owned job handle was not released'
        Assert-Equal ([IntPtr]::Zero) $started.Launch.Process 'the root handle was not released'
        $first = $started.CloseProof
        Close-WacCampaignLaunch -Started $started
        Assert-True ([object]::ReferenceEquals($first, $started.CloseProof)) 'repeat close replaced the original observations'
    }
    catch {
        Write-Host ('Primary failure: ' + $_.Exception.Message + ' / ' + $_.ScriptStackTrace)
        throw
    }
    finally {
        if ($held) { foreach ($one in @($held.Processes)) { $one.Dispose() } }
        if ($started -and $started.Launch.Job -ne [IntPtr]::Zero) {
            [void][WacOwnedProcess]::TerminateJob($started.Launch.Job)
            [void][WacOwnedProcess]::WaitForExit($started.Launch.Process, 5000)
            [WacOwnedProcess]::Close($started.Launch)
            $started.Process.Dispose(); $started.OutReader.Dispose(); $started.ErrReader.Dispose()
        }
        Remove-TestSandbox -Path $sandbox
    }
}
Test-Case 'Unknown handles remain a failed close on every retry, never a clean no-op' {
    $launch = New-Object WacOwnedLaunch
    $started = [PSCustomObject]@{ Launch = $launch; Process = $null; OutReader = $null; ErrReader = $null }
    Assert-Throws -ScriptBlock { Close-WacCampaignLaunch -Started $started } -Pattern 'no live owned job/root handles'
    $first = [string]$started.CloseProof.Failure
    Assert-True $started.CloseProof.Finalized
    Assert-False $started.CloseProof.TerminationProven
    Assert-Equal -1 $started.CloseProof.ActiveProcesses
    Assert-Throws -ScriptBlock { Close-WacCampaignLaunch -Started $started } -Pattern 'no live owned job/root handles'
    Assert-Equal $first ([string]$started.CloseProof.Failure) 'retry erased or changed the original failure'
}
Test-Case 'An already-exited root does not hide a living owned descendant' {
    $sandbox = New-TestSandbox -Prefix 'campaign-exited-root'
    $started = $null
    try {
        $child = Join-Path $sandbox 'child.ps1'
        $rootScript = Join-Path $sandbox 'root.ps1'
        [IO.File]::WriteAllText($child, '[IO.File]::WriteAllText((Join-Path $PSScriptRoot ''child.pid''), [string]$PID); Start-Sleep -Seconds 60')
        [IO.File]::WriteAllText($rootScript, '$exe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName; Start-Process -FilePath $exe -NoNewWindow -ArgumentList (''-NoProfile -File "'' + (Join-Path $PSScriptRoot ''child.ps1'') + ''"''); exit 0')
        $started = Invoke-WacCampaignHost -ScriptPath $rootScript -PassThruProcess -TimeoutSeconds 60
        Assert-True ([WacOwnedProcess]::WaitForExit($started.Launch.Process, 10000)) 'the root did not exit'
        Assert-True ([WacOwnedProcess]::ActiveProcessesInJob($started.Launch.Job) -gt 0) 'the fixture created no live descendant'
        Close-WacCampaignLaunch -Started $started
        Assert-True $started.CloseProof.TerminationProven
        Assert-True $started.CloseProof.RootSignalled
        Assert-Equal 0 $started.CloseProof.ActiveProcesses 'an exited root substituted for child termination'
    }
    finally { if ($started) { Close-WacCampaignLaunch -Started $started }; Remove-TestSandbox -Path $sandbox }
}
Test-Case 'Closing one owned job leaves a separately owned harmless job alive' {
    $sandbox = New-TestSandbox -Prefix 'campaign-separate-job'
    $first = $null; $second = $null
    try {
        $path = Join-Path $sandbox 'sleep.ps1'
        [IO.File]::WriteAllText($path, 'Start-Sleep -Seconds 60')
        $first = Invoke-WacCampaignHost -ScriptPath $path -PassThruProcess -TimeoutSeconds 60
        $second = Invoke-WacCampaignHost -ScriptPath $path -PassThruProcess -TimeoutSeconds 60
        Close-WacCampaignLaunch -Started $first
        Assert-True $first.CloseProof.TerminationProven
        Assert-False ([WacOwnedProcess]::WaitForExit($second.Launch.Process, 0)) 'a different owned root was terminated'
        Assert-True ([WacOwnedProcess]::ActiveProcessesInJob($second.Launch.Job) -gt 0)
        Close-WacCampaignLaunch -Started $first
        Assert-False ([WacOwnedProcess]::WaitForExit($second.Launch.Process, 0)) 'repeat close affected another job'
    }
    finally {
        try { if ($first) { Close-WacCampaignLaunch -Started $first } }
        finally { try { if ($second) { Close-WacCampaignLaunch -Started $second } } finally { Remove-TestSandbox -Path $sandbox } }
    }
}
Complete-TestRun
