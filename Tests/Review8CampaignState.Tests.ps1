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
Test-Case 'Publication renames with write-through, so a power cut right after it cannot roll it back' {
    # Measured live on 2026-09-27: File.Replace returned, the agent raised Await, the host cut the
    # power within seconds and NTFS rolled the rename back - leaving state.json.pending, which the
    # next boot correctly refused. Flushing the file's DATA does not make its RENAME durable.
    $scriptPath = Join-Path $PSScriptRoot 'Campaign\WacCampaignState.ps1'
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
    Assert-Equal 0 @($parseErrors).Count 'the state library no longer parses'
    $save = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Save-WacCampaignState' }, $true))
    Assert-Equal 1 $save.Count 'exactly one Save-WacCampaignState must exist'
    $text = $save[0].Extent.Text
    Assert-True ($text -match 'Move-WacCampaignFileDurable') 'publication no longer goes through the durable rename'
    Assert-False ($text -match '\[IO\.File\]::(Replace|Move)\(') 'publication renames through an API with no write-through'
    Assert-Equal 9 ([WacCampaignDurableMove]::Flags($true)) 'a replacing publication must be MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH'
    Assert-Equal 8 ([WacCampaignDurableMove]::Flags($false)) 'a first publication must be MOVEFILE_WRITE_THROUGH and must not replace'
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
