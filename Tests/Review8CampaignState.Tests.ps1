#Requires -Version 5.1
<#
.SYNOPSIS
    Actual file-sharing, parsing and publication failures preserve prior campaign evidence.
.DESCRIPTION
    All files live in the harness sandbox. No VM, policy configuration, installed task or clock is changed.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
. (Join-Path $PSScriptRoot 'Campaign\WacCampaignState.ps1')
function New-State {
    return [PSCustomObject]@{ schema = 1; campaignId = ('a' * 32); commit = ('b' * 40); projectRoot = 'C:\fixture'
        destructiveAuthorized = $false; scenarios = @('power-loss-during-install'); completed = @(); results = @()
        phase = 'running'; cutStep = ''; payloadFingerprint = '' }
}
Test-Case 'State round trips through exclusive staging and replacement without leftover files' {
    $sandbox = New-TestSandbox -Prefix 'campaign-state'
    try {
        $path = Join-Path $sandbox 'state.json'
        Assert-True ($null -eq (Get-WacCampaignState -Path $path))
        $state = New-State
        Save-WacCampaignState -Path $path -State $state
        Assert-Equal 'running' (Get-WacCampaignState -Path $path).phase
        $state.phase = 'awaiting-power-cut'; $state.cutStep = 'power-loss-during-install'
        Save-WacCampaignState -Path $path -State $state
        Assert-Equal 'awaiting-power-cut' (Get-WacCampaignState -Path $path).phase
        Assert-False (Test-Path -LiteralPath ($path + '.pending'))
        $held = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $held.Dispose()
    }
    finally { Remove-TestSandbox -Path $sandbox }
}
foreach ($bad in @('', '{', 'null', '{"phase":"running"}')) {
    Test-Case ('Unreadable state is not absence: ' + $bad) {
        $sandbox = New-TestSandbox -Prefix 'campaign-invalid'
        try {
            $path = Join-Path $sandbox 'state.json'
            [IO.File]::WriteAllText($path, $bad)
            Assert-Throws -ScriptBlock { Get-WacCampaignState -Path $path }
            Assert-Equal $bad ([IO.File]::ReadAllText($path))
        }
        finally { Remove-TestSandbox -Path $sandbox }
    }
}
Test-Case 'A state directory and an orphan publication are retained as unresolved' {
    $sandbox = New-TestSandbox -Prefix 'campaign-shapes'
    try {
        $path = Join-Path $sandbox 'state.json'
        [void][IO.Directory]::CreateDirectory($path)
        Assert-Throws -ScriptBlock { Get-WacCampaignState -Path $path }
        [IO.Directory]::Delete($path)
        [IO.File]::WriteAllText(($path + '.pending'), 'partial')
        Assert-Throws -ScriptBlock { Get-WacCampaignState -Path $path }
        Assert-Throws -ScriptBlock { Save-WacCampaignState -Path $path -State (New-State) }
        Assert-Equal 'partial' ([IO.File]::ReadAllText(($path + '.pending')))
    }
    finally { Remove-TestSandbox -Path $sandbox }
}
Test-Case 'A real sharing violation cannot truncate the previous authoritative state' {
    $sandbox = New-TestSandbox -Prefix 'campaign-sharing'
    $held = $null
    try {
        $path = Join-Path $sandbox 'state.json'
        Save-WacCampaignState -Path $path -State (New-State)
        $before = [IO.File]::ReadAllText($path)
        $held = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $next = New-State; $next.phase = 'failed'
        Assert-Throws -ScriptBlock { Save-WacCampaignState -Path $path -State $next }
        Assert-Equal $before ([IO.File]::ReadAllText($path))
        Assert-True (Test-Path -LiteralPath ($path + '.pending'))
        $held.Dispose(); $held = $null
        Assert-Throws -ScriptBlock { Get-WacCampaignState -Path $path }
        Assert-Equal $before ([IO.File]::ReadAllText($path))
    }
    finally { if ($held) { $held.Dispose() }; Remove-TestSandbox -Path $sandbox }
}
Test-Case 'Invalid Boolean authorization and unknown scenarios are rejected before publication' {
    $state = New-State; $state.destructiveAuthorized = 'false'
    Assert-False (Test-WacCampaignStateShape -State $state)
    $state = New-State; $state.scenarios = @('unknown')
    Assert-False (Test-WacCampaignStateShape -State $state)
    $state = New-State; $state.scenarios += $state.scenarios[0]
    Assert-False (Test-WacCampaignStateShape -State $state)
}
Test-Case 'Payload byte changes and unreadable files invalidate durability evidence' {
    $sandbox = New-TestSandbox -Prefix 'campaign-payload'
    $held = $null
    try {
        $path = Join-Path $sandbox 'payload.txt'
        [IO.File]::WriteAllText($path, 'original')
        $first = Get-WacCampaignPayloadFingerprint -Directory $sandbox -Flush
        Assert-Equal $first (Get-WacCampaignPayloadFingerprint -Directory $sandbox)
        [IO.File]::WriteAllText($path, 'changed')
        Assert-False ($first -ceq (Get-WacCampaignPayloadFingerprint -Directory $sandbox))
        $held = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        Assert-Throws -ScriptBlock { Get-WacCampaignPayloadFingerprint -Directory $sandbox -Flush }
    }
    finally { if ($held) { $held.Dispose() }; Remove-TestSandbox -Path $sandbox }
}
Test-Case 'Legacy startup policy has no delete or rewrite path in the agent' {
    $agent = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Campaign\WacCampaignAgent.ps1'))
    Assert-False ($agent -match 'scripts\.ini|wac-campaign-boot\.cmd') 'the agent again targets shared legacy policy files'
    Assert-True ($agent -match 'AgentMutex') 'duplicate startup paths need a singleton owner'
}
Complete-TestRun
