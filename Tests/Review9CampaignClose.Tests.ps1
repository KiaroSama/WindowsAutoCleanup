#Requires -Version 5.1
<#
.SYNOPSIS
    Exercise the actual campaign closer and retain its primary error and native observations.
.DESCRIPTION
    Only a harmless disposable sleeping child is created. No VM or cleanup operation is performed.
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
        Assert-Equal ([IntPtr]::Zero) $started.Launch.Job 'the owned job handle was not released'
        Assert-Equal ([IntPtr]::Zero) $started.Launch.Process 'the root handle was not released'
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
Complete-TestRun
