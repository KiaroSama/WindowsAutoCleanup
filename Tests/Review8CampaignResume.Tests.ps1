#Requires -Version 5.1
<#
.SYNOPSIS
    Resume uses the actual monotonic comparison, staged bytes and the recorded campaign identity.
.DESCRIPTION
    Files and hashes are real. The uptime observation is supplied; no clock change or reboot occurs.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
. (Join-Path $PSScriptRoot 'Campaign\WacCampaignState.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\WindowsAutoCleanup.Quarantine.ps1')
Test-Case 'Same-boot relaunch, missing proof and changed payload refuse; a counter reset with intact bytes passes' {
    $sandbox = New-TestSandbox -Prefix 'campaign-resume'
    try {
        $commit = 'b' * 40; $project = Join-Path $sandbox $commit.Substring(0, 12)
        [void][IO.Directory]::CreateDirectory($project)
        $file = Join-Path $project 'payload.txt'; [IO.File]::WriteAllText($file, 'original')
        $state = [PSCustomObject]@{ commit = $commit; projectRoot = $project; cutUptimeMs = 1000L
            payloadFingerprint = (Get-WacCampaignPayloadFingerprint -Directory $project) }
        # The actual comparison function above is retained; only its native observation is supplied.
        function Import-Module { [CmdletBinding()]param($Name, [switch]$DisableNameChecking) $null = $Name; $null = $DisableNameChecking }
        $script:ObservedUptime = 1500L
        function Get-WacMachineUptimeMs { return $script:ObservedUptime }
        Assert-False (Test-WacCampaignResume -State $state -WorkRoot $sandbox) 'agent restart was treated as a reboot'
        $script:ObservedUptime = 500L
        Assert-True (Test-WacCampaignResume -State $state -WorkRoot $sandbox) 'positive monotonic reset and intact payload were not accepted'
        $state.cutUptimeMs = $null
        Assert-False (Test-WacCampaignResume -State $state -WorkRoot $sandbox) 'legacy missing counter was accepted'
        $state.cutUptimeMs = 1000L
        $script:ObservedUptime = $null
        Assert-False (Test-WacCampaignResume -State $state -WorkRoot $sandbox) 'unreadable counter was accepted'
        $script:ObservedUptime = 500L
        [IO.File]::WriteAllText($file, 'changed')
        Assert-False (Test-WacCampaignResume -State $state -WorkRoot $sandbox) 'changed payload was accepted'
        [IO.File]::WriteAllText($file, 'original')
        $state.projectRoot = Join-Path $sandbox 'foreign'
        Assert-False (Test-WacCampaignResume -State $state -WorkRoot $sandbox) 'foreign payload location was accepted'
    }
    finally { Remove-TestSandbox -Path $sandbox }
}
Test-Case 'A valid but different campaign cannot replace authoritative state' {
    $sandbox = New-TestSandbox -Prefix 'campaign-identity'
    try {
        $path = Join-Path $sandbox 'state.json'
        $state = [PSCustomObject]@{ schema = 1; campaignId = ('a' * 32); commit = ('b' * 40); projectRoot = 'C:\fixture'
            destructiveAuthorized = $false; scenarios = @('reboot-recovery'); completed = @(); results = @(); phase = 'running'; cutStep = '' }
        Save-WacCampaignState -Path $path -State $state
        $old = [IO.File]::ReadAllText($path)
        $state.campaignId = 'c' * 32
        Assert-Throws -ScriptBlock { Save-WacCampaignState -Path $path -State $state }
        Assert-Equal $old ([IO.File]::ReadAllText($path))
        Assert-True (Test-Path -LiteralPath ($path + '.pending'))
    }
    finally { Remove-TestSandbox -Path $sandbox }
}
Test-Case 'A payload root junction is rejected before traversing it' {
    $sandbox = New-TestSandbox -Prefix 'campaign-junction'
    $link = Join-Path $sandbox 'link'
    try {
        $outside = Join-Path $sandbox 'outside'; [void][IO.Directory]::CreateDirectory($outside)
        [IO.File]::WriteAllText((Join-Path $outside 'sentinel.txt'), 'outside')
        [void](New-Item -ItemType Junction -Path $link -Target $outside -ErrorAction Stop)
        Assert-Throws -ScriptBlock { Get-WacCampaignPayloadFingerprint -Directory $link -Flush }
        Assert-Equal 'outside' ([IO.File]::ReadAllText((Join-Path $outside 'sentinel.txt')))
    }
    finally { if ([IO.Directory]::Exists($link)) { [IO.Directory]::Delete($link) }; Remove-TestSandbox -Path $sandbox }
}
Complete-TestRun
