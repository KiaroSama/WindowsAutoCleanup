#Requires -Version 5.1
<#
.SYNOPSIS
    Campaign admission and command transport must preserve explicit operator scope.
.DESCRIPTION
    VM cmdlets are harmless fixtures. Actual child-process tests execute only a disposable script
    printing a switch value and exiting 37. No VM, task, installed package or update is changed.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$campaign = Join-Path $PSScriptRoot 'Campaign'
. (Join-Path $campaign 'WacCampaignChannel.ps1')
. (Join-Path $campaign 'WacCampaignScenario.ps1')

function Get-VM {
    [CmdletBinding()]
    param([string]$Name)
    $null = $Name
    return [PSCustomObject]@{ Name = 'DisposableExact'; Id = [guid]'db743cdd-c3b8-4024-91ed-0c5e8a012f4c' }
}
function Get-VMIntegrationService {
    param($VM)
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
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $campaign 'Register-WacCampaignAgent.ps1'), [ref]$tokens, [ref]$errors)
    $condition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text -match '\$model -notmatch'
    }, $true)
    Assert-True ($null -ne $condition) 'the real hardware refusal predicate was not located'
    $model = 'Surface Pro 9'; $manufacturer = 'Microsoft Corporation'
    $expression = [scriptblock]::Create($condition.Clauses[0].Item1.Extent.Text)
    Assert-True ([bool](& $expression)) 'a physical Microsoft machine passed the VM arming guard'
    $model = 'Virtual Machine'
    Assert-False ([bool](& $expression)) 'the genuine Hyper-V model lost its positive control'
}

Test-Case 'All ordinary installer calls explicitly disable ResetBase' {
    $script:InstallArguments = @()
    function Invoke-WacCampaignHost {
        param($ScriptPath, $ArgumentList)
        $null = $ScriptPath
        $script:InstallArguments = @($ArgumentList)
        return [PSCustomObject]@{ ExitCode = 37; Output = 'deliberate fixture refusal' }
    }
    [void](Invoke-WacCampaignMaintenance -ProjectRoot 'C:\Fixture')
    Assert-True ($script:InstallArguments -contains '-ResetWindowsUpdateBase:$false') 'ordinary maintenance inherited the destructive product default'
    $state = [PSCustomObject]@{ projectRoot = 'C:\Fixture'; destructiveAuthorized = $false }
    foreach ($scenario in @('power-loss-during-uninstall', 'reboot-recovery')) {
        [void](Invoke-WacCampaignScenario -Name $scenario -State $state -StatePath 'unused' -Save {})
        Assert-True ($script:InstallArguments -contains '-ResetWindowsUpdateBase:$false') ($scenario + ' inherited the destructive product default')
    }
}

Test-Case 'Campaign PowerShell transport preserves a spaced path and an explicit false switch' {
    $sandbox = New-TestSandbox -Prefix 'review7 transport'
    try {
        $path = Join-Path $sandbox 'payload with spaces.ps1'
        [System.IO.File]::WriteAllText($path, 'param([switch]$ResetWindowsUpdateBase = $true) Write-Output ("VALUE=" + [bool]$ResetWindowsUpdateBase); exit 37')
        $result = Invoke-WacCampaignHost -ScriptPath $path -ArgumentList @('-ResetWindowsUpdateBase:$false') -TimeoutSeconds 20
        Assert-Equal 37 ([int]$result.ExitCode) $result.Output
        Assert-True ($result.Output -match 'VALUE=False') 'false was converted into a literal string or ignored'
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'A preview summary can never certify a real maintenance campaign' {
    $sandbox = New-TestSandbox -Prefix 'review7-reader'
    try {
        $path = Join-Path $sandbox 'preview.summary.json'
        [System.IO.File]::WriteAllText($path, '{"schema":1,"mode":"preview","executionId":"not-cleanup","outcome":"Succeeded","exitCode":0}')
        Assert-True ($null -eq (Get-WacCampaignSummary -Directory @($sandbox))) 'the reader accepted a successful preview as cleanup evidence'
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
    Assert-Equal 'failed' ([string]$result.Verdict) 'a stale disabled or unrelated driver step was called a successful pruning campaign'
}
Complete-TestRun
