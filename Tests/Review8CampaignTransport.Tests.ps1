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
        $held = Suspend-WacCampaignTree -ProcessId $started.Process.Id -ExpectedCreatedUtc $started.Process.StartTime.ToUniversalTime()
        Assert-True $held.RootHeld $held.Detail
        Assert-Equal 1 @($held.Processes).Count
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
Complete-TestRun
