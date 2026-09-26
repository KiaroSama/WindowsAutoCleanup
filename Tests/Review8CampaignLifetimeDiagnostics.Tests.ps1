#Requires -Version 5.1
<#
.SYNOPSIS
    Real harmless process diagnostics bind each observed handle and membership fact.
.DESCRIPTION
    Runs no cleanup or VM operation. Keeps exact native failure evidence instead of masking it in finally.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
. (Join-Path $PSScriptRoot 'Campaign\WacCampaignScenario.ps1')
Test-Case 'A held job reports its actual root and member termination evidence' {
    $sandbox = New-TestSandbox -Prefix 'campaign-native-proof'
    $started = $null; $held = $null
    try {
        $path = Join-Path $sandbox 'sleep.ps1'
        [IO.File]::WriteAllText($path, 'Start-Sleep -Seconds 60; exit 0')
        $started = Invoke-WacCampaignHost -ScriptPath $path -PassThruProcess -TimeoutSeconds 60
        Write-Host ('Before hold: id={0} job={1} rootHandle={2} active={3}' -f $started.Process.Id, $started.Launch.Job, $started.Launch.Process, [WacOwnedProcess]::ActiveProcessesInJob($started.Launch.Job))
        $held = Suspend-WacCampaignTree -ProcessId $started.Process.Id -ExpectedCreatedUtc $started.Process.StartTime.ToUniversalTime() -Job $started.Launch.Job
        Write-Host ('Hold result: rootHeld={0} detail={1} count={2}' -f $held.RootHeld, $held.Detail, @($held.Processes).Count)
        foreach ($one in @($held.Processes)) { Write-Host ('Held: name={0} id={1} handle={2}' -f $one.ProcessName, $one.Id, $one.Handle) }
        $terminated = [WacOwnedProcess]::TerminateJob($started.Launch.Job)
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $signalled = [WacOwnedProcess]::WaitForExit($started.Launch.Process, 5000)
        $active = [WacOwnedProcess]::ActiveProcessesInJob($started.Launch.Job)
        Write-Host ('After terminate: requested={0} win32={1} rootSignalled={2} active={3} rootExit={4}' -f $terminated, $errorCode, $signalled, $active, [WacOwnedProcess]::GetExitCode($started.Launch.Process))
        Assert-True $held.RootHeld $held.Detail
        Assert-True $terminated 'native termination request failed'
        Assert-True $signalled 'native root did not signal'
        Assert-Equal 0 $active 'owned job remained populated'
    }
    finally {
        if ($held) {
            foreach ($one in @($held.Processes)) {
                try { [void][WacCampaign.Hold]::NtResumeProcess($one.Handle) } catch { $null = $_ }
                $one.Dispose()
            }
        }
        if ($started) {
            [void][WacOwnedProcess]::TerminateJob($started.Launch.Job)
            [WacOwnedProcess]::Close($started.Launch)
            $started.Process.Dispose(); $started.OutReader.Dispose(); $started.ErrReader.Dispose()
        }
        Remove-TestSandbox -Path $sandbox
    }
}
Complete-TestRun
