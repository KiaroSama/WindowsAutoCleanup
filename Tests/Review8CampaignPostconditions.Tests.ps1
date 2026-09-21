#Requires -Version 5.1
<#
.SYNOPSIS
    Operation success is the conjunction of fresh evidence and verified teardown, not an exit alone.
.DESCRIPTION
    Scheduler, maintenance and inventory observations are fixtures. Nothing on the machine changes.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
. (Join-Path $PSScriptRoot 'Campaign\WacCampaignScenario.ps1')
function Invoke-MaintenanceFixture {
    param([string]$Fault = '')
    $script:UninstallCalls = 0; $script:InfoCalls = 0; $script:SummaryCalls = 0; $script:TaskStarts = 0
    function Invoke-WacCampaignHost {
        param([string]$ScriptPath, $ArgumentList)
        if ($ScriptPath -like '*Uninstall*') {
            $script:UninstallCalls++
            return [PSCustomObject]@{ ExitCode = $(if ($Fault -ceq 'uninstall') { 1 } else { 0 }); Output = '' }
        }
        Assert-True ($ArgumentList -contains '-ResetWindowsUpdateBase:$false')
        return [PSCustomObject]@{ ExitCode = 0; Output = '' }
    }
    function Get-WacCampaignMachine {
        param($ProjectRoot, [switch]$Installed)
        $null = $ProjectRoot
        return [PSCustomObject]@{ Known = $Fault -cne 'denied'; SafeMaintenance = $Fault -cne 'policy'
            Tasks = @([PSCustomObject]@{ TaskName = 'fixture'; TaskPath = '\fixture\' })
            Clean = (-not $Installed -and @('residue', 'denied') -cnotcontains $Fault) }
    }
    function Get-ScheduledTaskInfo {
        [CmdletBinding()]param($InputObject)
        $null = $InputObject; $script:InfoCalls++
        $stamp = if ($script:InfoCalls -eq 1 -or $Fault -ceq 'staleTask') { (Get-Date).AddDays(-1) } else { Get-Date }
        return [PSCustomObject]@{ LastRunTime = $stamp; LastTaskResult = $(if ($Fault -ceq 'schedulerError') { 267009 } else { 0 }) }
    }
    function Get-ScheduledTask {
        [CmdletBinding()]param($TaskPath, $TaskName)
        return [PSCustomObject]@{ TaskPath = $TaskPath; TaskName = $TaskName; State = 'Ready' }
    }
    function Start-ScheduledTask { [CmdletBinding()]param($InputObject) $null = $InputObject; $script:TaskStarts++ }
    function Get-WacCampaignSummary {
        $script:SummaryCalls++
        $id = if ($script:SummaryCalls -eq 1 -or $Fault -ceq 'staleSummary') { 'old' } else { 'new' }
        return [PSCustomObject]@{ schema = 1; mode = 'cleanup'; executionId = $id; completedUtc = [datetime]::UtcNow.ToString('o')
            exitCode = 0; outcome = 'Succeeded'; steps = @() }
    }
    return (Invoke-WacCampaignMaintenance -ProjectRoot 'C:\fixture' -TimeoutSeconds 1)
}
Test-Case 'Fresh scheduled completion plus verified teardown is the successful control' {
    $result = Invoke-MaintenanceFixture
    Assert-Equal 'passed' $result.Verdict $result.Detail
    Assert-Equal 1 $script:TaskStarts
    Assert-Equal 1 $script:UninstallCalls
}
foreach ($fault in @('uninstall', 'residue', 'denied')) {
    Test-Case ('A teardown problem cannot pass: ' + $fault) {
        $result = Invoke-MaintenanceFixture -Fault $fault
        Assert-Equal 'failed' $result.Verdict $result.Detail
    }
}
foreach ($fault in @('policy', 'staleTask', 'staleSummary', 'schedulerError')) {
    Test-Case ('Unproven execution cannot authorize teardown: ' + $fault) {
        $result = Invoke-MaintenanceFixture -Fault $fault
        Assert-Equal 'failed' $result.Verdict $result.Detail
        Assert-Equal 0 $script:UninstallCalls 'a possibly live installation was removed'
        if ($fault -ceq 'policy') { Assert-Equal 0 $script:TaskStarts }
    }
}
Complete-TestRun
