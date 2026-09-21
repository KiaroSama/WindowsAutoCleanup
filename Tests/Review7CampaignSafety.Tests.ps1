#Requires -Version 5.1
<#
.SYNOPSIS
    Original red-first campaign counterexamples, with the extracted hardware predicate called directly.
.DESCRIPTION
    VM observations are fixtures. The transport case runs only a disposable Boolean/exit-code script.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$campaign = Join-Path $PSScriptRoot 'Campaign'
. (Join-Path $campaign 'WacCampaignChannel.ps1')
. (Join-Path $campaign 'WacCampaignScenario.ps1')
function Get-VM {
    [CmdletBinding()]param([string]$Name)
    $null = $Name
    return [PSCustomObject]@{ Name = 'DisposableExact'; Id = [guid]'db743cdd-c3b8-4024-91ed-0c5e8a012f4c' }
}
function Get-VMIntegrationService {
    [CmdletBinding()]param($VM)
    $null = $VM
    return @([PSCustomObject]@{ Name = 'Guest Service Interface'; Enabled = $true },
        [PSCustomObject]@{ Name = 'Key-Value Pair Exchange'; Enabled = $true })
}
Test-Case 'A literal exact VM name remains accepted' {
    Assert-Equal 'DisposableExact' ([string](Get-WacCampaignVm -VMName 'DisposableExact').Name)
}
Test-Case 'A wildcard resolving to one VM is still not explicit authorization' {
    Assert-Throws -ScriptBlock { Get-WacCampaignVm -VMName '*' }
}
Test-Case 'A returned different VM cannot satisfy literal selection' {
    Assert-Throws -ScriptBlock { Get-WacCampaignVm -VMName 'AnotherMachine' }
}
Test-Case 'The arming predicate refuses a physical Microsoft workstation' {
    Assert-False (Test-WacCampaignGuest -Computer ([PSCustomObject]@{ Model = 'Surface Pro 9'; Manufacturer = 'Microsoft Corporation' }))
    Assert-True (Test-WacCampaignGuest -Computer ([PSCustomObject]@{ Model = 'Virtual Machine'; Manufacturer = 'Microsoft Corporation' }))
}
Test-Case 'All ordinary installer calls explicitly disable ResetBase' {
    $script:InstallArguments = @()
    function Invoke-WacCampaignHost {
        param($ScriptPath, $ArgumentList)
        $null = $ScriptPath; $script:InstallArguments = @($ArgumentList)
        return [PSCustomObject]@{ ExitCode = 37; Output = 'deliberate fixture refusal' }
    }
    [void](Invoke-WacCampaignMaintenance -ProjectRoot 'C:\Fixture')
    Assert-True ($script:InstallArguments -contains '-ResetWindowsUpdateBase:$false')
    $state = [PSCustomObject]@{ projectRoot = 'C:\Fixture'; destructiveAuthorized = $false }
    foreach ($scenario in @('power-loss-during-uninstall', 'reboot-recovery')) {
        [void](Invoke-WacCampaignScenario -Name $scenario -State $state -StatePath 'unused' -Save {})
        Assert-True ($script:InstallArguments -contains '-ResetWindowsUpdateBase:$false') $scenario
    }
}
Test-Case 'Campaign PowerShell transport preserves a spaced path and an explicit false switch' {
    $sandbox = New-TestSandbox -Prefix 'review7 transport'
    try {
        $path = Join-Path $sandbox 'payload with spaces.ps1'
        [IO.File]::WriteAllText($path, 'param([switch]$ResetWindowsUpdateBase = $true) Write-Output ("VALUE=" + [bool]$ResetWindowsUpdateBase); exit 37')
        $result = Invoke-WacCampaignHost -ScriptPath $path -ArgumentList @('-ResetWindowsUpdateBase:$false') -TimeoutSeconds 20
        Assert-Equal 37 ([int]$result.ExitCode) $result.Output
        Assert-True ($result.Output -match 'VALUE=False') $result.Output
    }
    finally { Remove-TestSandbox -Path $sandbox }
}
Test-Case 'A preview summary can never certify a real maintenance campaign' {
    $sandbox = New-TestSandbox -Prefix 'review7-reader'
    try {
        [IO.File]::WriteAllText((Join-Path $sandbox 'preview.summary.json'), '{"schema":1,"mode":"preview","executionId":"not-cleanup","outcome":"Succeeded","exitCode":0}')
        Assert-True ($null -eq (Get-WacCampaignSummary -Directory @($sandbox)))
    }
    finally { Remove-TestSandbox -Path $sandbox }
}
Test-Case 'A disabled pnputil step and successful pnpclean cannot certify driver pruning' {
    function Invoke-WacCampaignHost { param($ScriptPath, $ArgumentList) $null = $ScriptPath; $null = $ArgumentList; return [PSCustomObject]@{ ExitCode = 0; Output = '' } }
    function Get-WacCampaignSummary {
        return [PSCustomObject]@{ executionId = 'unchanged-old-run'; mode = 'cleanup'; outcome = 'Succeeded'; exitCode = 0
            steps = @([PSCustomObject]@{ category = 'Device driver packages (pnpclean)'; state = 'executed'; outcome = 'Succeeded' },
                [PSCustomObject]@{ category = 'Superseded driver packages (pnputil)'; state = 'unarmed'; outcome = 'SafeSkip' }) }
    }
    $state = [PSCustomObject]@{ projectRoot = 'C:\Fixture'; destructiveAuthorized = $true }
    $result = Invoke-WacCampaignScenario -Name 'driver-prune' -State $state -StatePath 'unused' -Save {}
    Assert-Equal 'failed' ([string]$result.Verdict)
}
Complete-TestRun
