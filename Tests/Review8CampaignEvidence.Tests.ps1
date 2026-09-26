#Requires -Version 5.1
<#
.SYNOPSIS
    Safe positive/negative controls for campaign evidence and machine/VM admission.
.DESCRIPTION
    No scenario is armed. VM and scheduler observations are fixtures; there are no machine mutations.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
. (Join-Path $PSScriptRoot 'Campaign\WacCampaignChecks.ps1')
. (Join-Path $PSScriptRoot 'Campaign\WacCampaignChannel.ps1')
function New-Evidence {
    return [PSCustomObject]@{ schema = 1; mode = 'cleanup'; executionId = 'fresh'; outcome = 'Succeeded'; exitCode = 0
        completedUtc = [datetime]::UtcNow.ToString('o')
        steps = @([PSCustomObject]@{ category = 'Superseded driver packages (pnputil)'; state = 'executed'; outcome = 'Succeeded' }) }
}
Test-Case 'A fresh exact operation with matching success is accepted' {
    Assert-True (Test-WacCampaignRunEvidence -Summary (New-Evidence) -PreviousId 'old' -StartedUtc ([datetime]::UtcNow.AddSeconds(-1)) `
        -ObservedExit 0 -Category 'Superseded driver packages (pnputil)')
}
foreach ($mode in @('preview', 'delegated', '', 'unknown')) {
    Test-Case ('Non-cleanup mode is refused: ' + $mode) {
        $value = New-Evidence; $value.mode = $mode
        Assert-False (Test-WacCampaignRunEvidence -Summary $value -ObservedExit 0)
    }
}
foreach ($change in @('staleId', 'staleTime', 'futureTime', 'missingMode', 'stringExit', 'badSchema', 'badTime', 'noSteps', 'badOutcome')) {
    Test-Case ('Evidence ambiguity is refused: ' + $change) {
        $value = New-Evidence
        switch ($change) {
            'staleId' { $value.executionId = 'old' }
            'staleTime' { $value.completedUtc = [datetime]::UtcNow.AddHours(-1).ToString('o') }
            'futureTime' { $value.completedUtc = [datetime]::UtcNow.AddHours(1).ToString('o') }
            'missingMode' { $value.PSObject.Properties.Remove('mode') }
            'stringExit' { $value.exitCode = '0' }
            'badSchema' { $value.schema = '1' }
            'badTime' { $value.completedUtc = 'not-a-date' }
            'noSteps' { $value.PSObject.Properties.Remove('steps') }
            'badOutcome' { $value.outcome = 'Failed' }
        }
        Assert-False (Test-WacCampaignRunEvidence -Summary $value -PreviousId 'old' -StartedUtc ([datetime]::UtcNow.AddSeconds(-1)) -ObservedExit 0)
    }
}
foreach ($state in @('unarmed', 'refused', 'unstated')) {
    Test-Case ('A nonexecuted requested category cannot pass: ' + $state) {
        $value = New-Evidence; $value.steps[0].state = $state
        Assert-False (Test-WacCampaignRunEvidence -Summary $value -ObservedExit 0 -Category 'Superseded driver packages (pnputil)')
    }
}
Test-Case 'Wrong duplicate or failed categories cannot pass' {
    $value = New-Evidence
    Assert-False (Test-WacCampaignRunEvidence -Summary $value -ObservedExit 0 -Category 'Device driver packages (pnpclean)')
    $value.steps += $value.steps[0]
    Assert-False (Test-WacCampaignRunEvidence -Summary $value -ObservedExit 0 -Category 'Superseded driver packages (pnputil)')
    $value = New-Evidence; $value.steps[0].outcome = 'Incomplete'
    Assert-False (Test-WacCampaignRunEvidence -Summary $value -ObservedExit 0 -Category 'Superseded driver packages (pnputil)')
    Assert-False (Test-WacCampaignRunEvidence -Summary (New-Evidence) -ObservedExit 37)
}
Test-Case 'Missing physical or incoherent hardware cannot authorize a guest' {
    foreach ($computer in @($null, [PSCustomObject]@{}, [PSCustomObject]@{ Model = 'Surface Pro 9'; Manufacturer = 'Microsoft Corporation' },
        [PSCustomObject]@{ Model = 'Virtual Machine'; Manufacturer = 'unknown' })) {
        Assert-False (Test-WacCampaignGuest -Computer $computer)
    }
    Assert-True (Test-WacCampaignGuest -Computer ([PSCustomObject]@{ Model = 'Virtual Machine'; Manufacturer = 'Microsoft Corporation' }))
    Assert-True (Test-WacCampaignGuest -Computer ([PSCustomObject]@{ Model = 'VMware Virtual Platform'; Manufacturer = 'VMware, Inc.' }))
}
Test-Case 'Renaming a VM does not retarget a state observation' {
    $wanted = [guid]::NewGuid()
    function Get-VM {
        [CmdletBinding()]param([guid]$Id)
        Assert-Equal $wanted $Id
        return [PSCustomObject]@{ Id = $Id; Name = 'renamed'; State = 'Off' }
    }
    Assert-Equal 'Off' (Get-WacCampaignVmState -Vm ([PSCustomObject]@{ Id = $wanted; Name = 'old name' }))
}
Test-Case 'A denied or foreign VM observation never proves shutdown' {
    function Get-VM { [CmdletBinding()]param([guid]$Id) $null = $Id; throw 'denied' }
    $vm = [PSCustomObject]@{ Id = [guid]::NewGuid(); Name = 'fixture' }
    Assert-Equal 'Unknown' (Get-WacCampaignVmState -Vm $vm)
    function Get-VM { [CmdletBinding()]param([guid]$Id) $null = $Id; return [PSCustomObject]@{ Id = [guid]::NewGuid(); State = 'Off' } }
    Assert-Equal 'Unknown' (Get-WacCampaignVmState -Vm $vm)
}
Test-Case 'A foreign checkpoint is never restored or removed' {
    $script:Mutation = 0
    function Get-VMSnapshot { [CmdletBinding()]param($VM, $Name) $null = $VM; return [PSCustomObject]@{ Name = $Name; VMId = [guid]::NewGuid() } }
    function Restore-VMSnapshot { param($VMSnapshot) $null = $VMSnapshot; $script:Mutation++ }
    function Remove-VMSnapshot { param($VMSnapshot) $null = $VMSnapshot; $script:Mutation++ }
    $answer = Restore-WacCampaignCheckpoint -Vm ([PSCustomObject]@{ Id = [guid]::NewGuid() }) -Name 'fixture'
    Assert-False $answer.Restored
    Assert-Equal 0 $script:Mutation
}
Test-Case 'Aggregate report identity and category are not inferred from a green status' {
    $report = [PSCustomObject]@{ schema = 1; campaignId = 'run'; commit = 'sha'; requested = @('one'); notRun = @()
        results = @([PSCustomObject]@{ Scenario = 'one'; Verdict = 'passed' }); status = 'complete' }
    Assert-True (Test-WacCampaignReportEvidence -Report $report -CampaignId 'run' -Commit 'sha' -Scenario 'one')
    Assert-False (Test-WacCampaignReportEvidence -Report $report -CampaignId 'old' -Commit 'sha' -Scenario 'one')
    Assert-False (Test-WacCampaignReportEvidence -Report $report -CampaignId 'run' -Commit 'other' -Scenario 'one')
    Assert-False (Test-WacCampaignReportEvidence -Report $report -CampaignId 'run' -Commit 'sha' -Scenario 'two')
    $report.results += $report.results[0]
    Assert-False (Test-WacCampaignReportEvidence -Report $report -CampaignId 'run' -Commit 'sha' -Scenario 'one')
}
Complete-TestRun
