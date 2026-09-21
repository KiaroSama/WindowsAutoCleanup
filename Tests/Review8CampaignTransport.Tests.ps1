#Requires -Version 5.1
<#
.SYNOPSIS
    Real harmless child scripts test native quoting, typed switches and owned interruption handles.
.DESCRIPTION
    No cleanup tool or VM command executes. All children and files belong to disposable test fixtures.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
. (Join-Path $PSScriptRoot 'Campaign\WacCampaignScenario.ps1')
foreach ($value in @('false', 'true', 'omitted')) {
    Test-Case ('Native adapter preserves switch value: ' + $value) {
        $sandbox = New-TestSandbox -Prefix 'campaign path with spaces'
        try {
            $leaf = 'payload' + [char]0x2019 + [char]0x00E9 + '.ps1'
            $path = Join-Path $sandbox $leaf
            [IO.File]::WriteAllText($path, 'param([switch]$ResetWindowsUpdateBase = $true) Write-Output ("VALUE=" + [bool]$ResetWindowsUpdateBase); exit 37')
            $arguments = if ($value -ceq 'omitted') { @() } else { @('-ResetWindowsUpdateBase:$' + $value) }
            $answer = Invoke-WacCampaignHost -ScriptPath $path -ArgumentList $arguments -TimeoutSeconds 30
            Assert-Equal 37 ([int]$answer.ExitCode) $answer.Output
            $expected = if ($value -ceq 'false') { 'VALUE=False' } else { 'VALUE=True' }
            Assert-True ($answer.Output -match [regex]::Escape($expected)) $answer.Output
        }
        finally { Remove-TestSandbox -Path $sandbox }
    }
}
Test-Case 'Invalid or duplicate switches never launch the supplied script' {
    $sandbox = New-TestSandbox -Prefix 'campaign-invalid-switch'
    try {
        $path = Join-Path $sandbox 'payload.ps1'
        [IO.File]::WriteAllText($path, 'exit 37')
        Assert-Throws -ScriptBlock { Invoke-WacCampaignHost -ScriptPath $path -ArgumentList @('-Unknown') }
        Assert-Throws -ScriptBlock { Invoke-WacCampaignHost -ScriptPath $path -ArgumentList @('-NoPause', '-nopause') }
        Assert-Throws -ScriptBlock { Invoke-WacCampaignHost -ScriptPath $path -ArgumentList @('-ResetWindowsUpdateBase:maybe') }
    }
    finally { Remove-TestSandbox -Path $sandbox }
}
Test-Case 'A timeout is not converted into a successful campaign process' {
    $sandbox = New-TestSandbox -Prefix 'campaign-timeout'
    try {
        $path = Join-Path $sandbox 'sleep.ps1'
        [IO.File]::WriteAllText($path, 'Start-Sleep -Seconds 30; exit 0')
        $answer = Invoke-WacCampaignHost -ScriptPath $path -TimeoutSeconds 1
        Assert-Equal -1 ([int]$answer.ExitCode)
        Assert-False $answer.Settled
    }
    finally { Remove-TestSandbox -Path $sandbox }
}
Test-Case 'An owned harmless root can be held, observed, and terminated without leaking handles' {
    $sandbox = New-TestSandbox -Prefix 'campaign-held'
    $started = $null; $held = $null
    try {
        $path = Join-Path $sandbox 'sleep.ps1'
        [IO.File]::WriteAllText($path, 'Start-Sleep -Seconds 30; exit 0')
        $started = Invoke-WacCampaignHost -ScriptPath $path -PassThruProcess -TimeoutSeconds 30
        $held = Suspend-WacCampaignTree -ProcessId $started.Process.Id -ExpectedCreatedUtc $started.Process.StartTime.ToUniversalTime() -Job $started.Launch.Job
        Assert-True $held.RootHeld $held.Detail
        $ids = @($held.Processes | ForEach-Object { $_.Id })
        Write-Output ('Held witnesses: ' + (@($held.Processes | ForEach-Object { $_.ProcessName + ':' + $_.Id }) -join ', '))
        Assert-True ($ids -contains $started.Process.Id) 'the exact owned root was not held'
        Assert-Equal $ids.Count @($ids | Select-Object -Unique).Count 'duplicate process witness'
        Assert-Equal ([int](Get-WacOwnedTreeState -Launch $started.Launch).ActiveProcesses) $ids.Count 'not every owned job member was held'
        Assert-Equal 'Alive' ([string](Get-WacOwnedTreeState -Launch $started.Launch).State)
        $processId = $started.Process.Id
        Close-WacCampaignLaunch -Started $started
        $started = $null
        foreach ($process in @($held.Processes)) { $process.Dispose() }
        $held = $null
        Assert-Equal 0 @(Get-Process -Id $processId -ErrorAction SilentlyContinue).Count 'the owned root survived cleanup'
    }
    finally {
        if ($held) { foreach ($process in @($held.Processes)) { $process.Dispose() } }
        if ($started) { Close-WacCampaignLaunch -Started $started }
        Remove-TestSandbox -Path $sandbox
    }
}
Test-Case 'A real grandchild is held recursively while root identity mismatches are refused' {
    $sandbox = New-TestSandbox -Prefix 'campaign-grandchild'
    $started = $null; $held = $null
    try {
        $grand = Join-Path $sandbox 'grand.ps1'
        $middle = Join-Path $sandbox 'middle.ps1'
        $rootScript = Join-Path $sandbox 'root.ps1'
        [IO.File]::WriteAllText($grand, '[IO.File]::WriteAllText((Join-Path $PSScriptRoot ''grand.pid''), [string]$PID); Start-Sleep -Seconds 60')
        [IO.File]::WriteAllText($middle, '$exe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName; Start-Process -FilePath $exe -NoNewWindow -ArgumentList (''-NoProfile -File "'' + (Join-Path $PSScriptRoot ''grand.ps1'') + ''"''); [IO.File]::WriteAllText((Join-Path $PSScriptRoot ''middle.pid''), [string]$PID); Start-Sleep -Seconds 60')
        [IO.File]::WriteAllText($rootScript, '$exe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName; Start-Process -FilePath $exe -NoNewWindow -ArgumentList (''-NoProfile -File "'' + (Join-Path $PSScriptRoot ''middle.ps1'') + ''"''); Start-Sleep -Seconds 60')
        $started = Invoke-WacCampaignHost -ScriptPath $rootScript -PassThruProcess -TimeoutSeconds 60
        $watch = [Diagnostics.Stopwatch]::StartNew()
        do {
            if ([IO.File]::Exists((Join-Path $sandbox 'grand.pid'))) { break }
            Start-Sleep -Milliseconds 100
        } while ($watch.Elapsed.TotalSeconds -lt 20)
        Assert-True ([IO.File]::Exists((Join-Path $sandbox 'grand.pid'))) 'the grandchild witness never started'
        $wrong = Suspend-WacCampaignTree -ProcessId $started.Process.Id -ExpectedCreatedUtc ($started.Process.StartTime.ToUniversalTime().AddDays(-1)) -Job $started.Launch.Job
        Assert-False $wrong.RootHeld 'a recycled identity was held'
        Assert-Equal 0 @($wrong.Processes).Count
        $held = Suspend-WacCampaignTree -ProcessId $started.Process.Id -ExpectedCreatedUtc $started.Process.StartTime.ToUniversalTime() -Job $started.Launch.Job
        Assert-True $held.RootHeld $held.Detail
        $ids = @($held.Processes | ForEach-Object { $_.Id })
        Assert-True ($ids -contains ([int][IO.File]::ReadAllText((Join-Path $sandbox 'middle.pid')))) 'middle escaped the hold'
        Assert-True ($ids -contains ([int][IO.File]::ReadAllText((Join-Path $sandbox 'grand.pid')))) 'grandchild escaped the hold'
        Assert-True ($ids -contains $started.Process.Id)
        Assert-Equal ([int](Get-WacOwnedTreeState -Launch $started.Launch).ActiveProcesses) $ids.Count
    }
    finally {
        if ($held) { foreach ($process in @($held.Processes)) { $process.Dispose() } }
        if ($started) { Close-WacCampaignLaunch -Started $started }
        Remove-TestSandbox -Path $sandbox
    }
}
Complete-TestRun
