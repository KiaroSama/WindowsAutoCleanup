#Requires -Version 5.1
<#
.SYNOPSIS
    Preserved campaign authorization, channel, shutdown-order and durability contracts.
.DESCRIPTION
    Structural checks follow the extracted helpers. Actual file/process failure controls live in
    Review8CampaignState/Transport; no physical guest is armed by this suite.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:CampaignRoot = Join-Path $PSScriptRoot 'Campaign'
. (Join-Path $script:CampaignRoot 'WacCampaignChannel.ps1')
function Use-CampaignEnvironment {
    param([AllowNull()][string]$Campaign, [AllowNull()][string]$Destructive, [scriptblock]$Body)
    $prior = $env:WAC_VM_CAMPAIGN; $priorDestructive = $env:WAC_VM_CAMPAIGN_DESTRUCTIVE
    try { $env:WAC_VM_CAMPAIGN = $Campaign; $env:WAC_VM_CAMPAIGN_DESTRUCTIVE = $Destructive; return (& $Body) }
    finally { $env:WAC_VM_CAMPAIGN = $prior; $env:WAC_VM_CAMPAIGN_DESTRUCTIVE = $priorDestructive }
}
function Get-CampaignAst {
    param([string]$File)
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $script:CampaignRoot $File), [ref]$null, [ref]$errors)
    Assert-Equal 0 @($errors).Count ($errors -join ' ; ')
    return $ast
}
function Get-CampaignFunction {
    param([string]$File, [string]$Name)
    $found = @((Get-CampaignAst -File $File).FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name
    }, $true))
    Assert-Equal 1 $found.Count ('Expected one ' + $Name)
    return $found[0]
}
Test-Case 'A campaign refuses to run at all until it is explicitly armed' {
    foreach ($near in @($null, '0', 'true', 'yes', '1 ', 'True')) {
        Assert-False (Use-CampaignEnvironment -Campaign $near -Destructive $null -Body { Test-WacCampaignArmed }).Armed
    }
    Assert-True (Use-CampaignEnvironment -Campaign '1' -Destructive $null -Body { Test-WacCampaignArmed }).Armed
}
Test-Case 'The destructive scenarios need their OWN authorization, and neither switch implies the other' {
    Assert-False (Use-CampaignEnvironment -Campaign '1' -Destructive $null -Body { Test-WacCampaignArmed -WantDestructive }).Armed
    Assert-False (Use-CampaignEnvironment -Campaign $null -Destructive '1' -Body { Test-WacCampaignArmed }).Armed
    $both = Use-CampaignEnvironment -Campaign '1' -Destructive '1' -Body { Test-WacCampaignArmed -WantDestructive }
    Assert-True $both.Armed; Assert-True $both.Destructive
    Assert-False (Use-CampaignEnvironment -Campaign '1' -Destructive '1' -Body { Test-WacCampaignArmed }).Destructive
}
Test-Case 'There is no default target, and the destructive list is explicit rather than guessed' {
    Assert-Throws -ScriptBlock { Get-WacCampaignVm -VMName '  ' }
    $driver = [IO.File]::ReadAllText((Join-Path $script:CampaignRoot 'Invoke-WacVmCampaign.ps1'))
    Assert-True ($driver -match "DestructiveScenario\s*=\s*@\('driver-prune',\s*'reset-base'\)")
}
Test-Case 'A partial report is never read as a short one' {
    Assert-True ($null -eq (Join-WacCampaignParts -Item @{ 'Report.0' = 'half' }))
    Assert-True ($null -eq (Join-WacCampaignParts -Item @{ ReportParts = 3; 'Report.0' = 'a'; 'Report.2' = 'c' }))
    Assert-Equal 'abc' (Join-WacCampaignParts -Item @{ ReportParts = 3; 'Report.0' = 'a'; 'Report.1' = 'b'; 'Report.2' = 'c' })
    foreach ($bad in @('0', '-1', 'three', '', '9999999')) {
        Assert-True ($null -eq (Join-WacCampaignParts -Item @{ ReportParts = $bad; 'Report.0' = 'a' }))
    }
}
Test-Case 'Reading a machine that is not there is an empty READ, not a crash and not a finding' {
    $item = Read-WacCampaignReport -VMName 'wac-no-such-virtual-machine-b9f2'
    Assert-True ($item -is [hashtable]); Assert-Equal 0 $item.Count
}
Test-Case 'No part of the campaign handles a guest credential' {
    foreach ($file in @(Get-ChildItem -LiteralPath $script:CampaignRoot -Filter '*.ps1' -File)) {
        $text = [IO.File]::ReadAllText($file.FullName)
        foreach ($forbidden in @('Get-Credential', '-Credential', 'New-PSSession', 'Enter-PSSession', 'Invoke-Command', 'PSCredential', 'ConvertTo-SecureString')) {
            Assert-False ($text.IndexOf($forbidden, [StringComparison]::Ordinal) -ge 0) ($file.Name + ':' + $forbidden)
        }
    }
}
Test-Case 'The FIRST thing the driver does on its way out is stop the guest' {
    $ast = Get-CampaignAst -File 'Invoke-WacVmCampaign.ps1'
    $tries = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.TryStatementAst] -and $null -ne $node.Finally }, $true) | Where-Object {
        $parent = $_.Parent; $inside = $false
        while ($null -ne $parent) { if ($parent -is [Management.Automation.Language.FunctionDefinitionAst]) { $inside = $true; break }; $parent = $parent.Parent }
        -not $inside
    })
    Assert-Equal 1 $tries.Count
    $first = @($tries[0].Finally.Statements)[0]
    Assert-True ($first -is [Management.Automation.Language.IfStatementAst])
    Assert-True (@($first.Clauses[0].Item2.Statements)[0].Extent.Text -match 'Stop-WacCampaignVm')
    Assert-True ($tries[0].Finally.Extent.Text -match 'Restore-WacCampaignCheckpoint')
}
Test-Case 'A sticky beacon is judged by its OWN timestamp, not by being present' {
    $fn = Get-CampaignFunction -File 'Invoke-WacVmCampaign.ps1' -Name 'Get-CampaignBeaconUtc'
    . ([scriptblock]::Create($fn.Extent.Text))
    $cut = [datetime]::Parse('2026-09-20T00:45:38Z').ToUniversalTime()
    Assert-False ((Get-CampaignBeaconUtc -Item @{ AgentReady = '2026-09-19T23:07:57Z' } -Name 'AgentReady') -gt $cut)
    Assert-True ((Get-CampaignBeaconUtc -Item @{ AgentReady = '2026-09-20T00:45:52Z' } -Name 'AgentReady') -gt $cut)
    foreach ($item in @($null, @{}, @{ AgentReady = '' }, @{ AgentReady = 'System.Object[]' })) {
        Assert-True ($null -eq (Get-CampaignBeaconUtc -Item $item -Name 'AgentReady'))
    }
}
Test-Case 'After restoring power the campaign waits for the new boot before reading the guest again' {
    $fn = Get-CampaignFunction -File 'Invoke-WacVmCampaign.ps1' -Name 'Invoke-CampaignPowerCut'
    $commands = @($fn.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
    $start = [array]::IndexOf($commands, 'Start-VM'); $wait = [array]::IndexOf($commands, 'Wait-WacCampaignSignal')
    Assert-True ($start -ge 0 -and $wait -gt $start)
}
Test-Case 'A cut is answered only by a beacon newer than the cut and a cleared request' {
    # H-1 and H-2 at the call site: the predicate the driver really waits on after restoring power.
    foreach ($name in @('Get-CampaignBeaconUtc', 'Invoke-CampaignPowerCut')) {
        . ([scriptblock]::Create((Get-CampaignFunction -File 'Invoke-WacVmCampaign.ps1' -Name $name).Extent.Text))
    }
    function Write-CampaignLine { param($Text) $null = $Text }
    function Stop-WacCampaignVm { param($Vm, [switch]$PowerCut) $null = $Vm, $PowerCut; return [PSCustomObject]@{ Off = $true } }
    function Start-VM { [CmdletBinding()]param($VM) $null = $VM }
    function Wait-WacCampaignSignal {
        param($VMName, $VmId, $TimeoutSeconds, $IdleSeconds, [scriptblock]$Until)
        $null = $VMName, $VmId, $TimeoutSeconds, $IdleSeconds
        $stale = [datetime]::UtcNow.AddHours(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $fresh = [datetime]::UtcNow.AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $script:Verdicts = @([bool](& $Until @{ AgentReady = $stale }),
            [bool](& $Until @{ AgentReady = $fresh; Await = 'power-cut:x' }),
            [bool](& $Until @{ AgentReady = $fresh; Await = '' }))
        return [PSCustomObject]@{ Signalled = $true; Item = @{}; Reason = '' }
    }
    Assert-True (Invoke-CampaignPowerCut -Vm ([PSCustomObject]@{ Name = 'x'; Id = [guid]::NewGuid() }) -AtStep 'x')
    Assert-False $script:Verdicts[0] 'a beacon older than the cut answered it'
    Assert-False $script:Verdicts[1] 'a request still standing answered the cut'
    Assert-True $script:Verdicts[2] 'a fresh beacon with a cleared request was refused'
}
Test-Case 'No reader in the campaign takes a beacon on presence alone' {
    foreach ($file in @(Get-ChildItem -LiteralPath $script:CampaignRoot -Filter '*.ps1' -File)) {
        $text = [IO.File]::ReadAllText($file.FullName)
        foreach ($beacon in @('AgentReady', 'AgentBoot')) { Assert-False ($text -match ("ContainsKey\('" + $beacon + "'\)")) }
    }
}
Test-Case 'The resume point is flushed before publication and remains readable' {
    . (Join-Path $script:CampaignRoot 'WacCampaignState.ps1')
    $fn = Get-CampaignFunction -File 'WacCampaignState.ps1' -Name 'Save-WacCampaignState'
    Assert-False ($fn.Extent.Text -match '\[IO.File\]::WriteAllText')
    Assert-True ($fn.Extent.Text -match '\.Flush\(\$true\)')
    $sandbox = New-TestSandbox -Prefix 'campaign-roundtrip'
    try {
        $path = Join-Path $sandbox 'state.json'
        $state = [PSCustomObject]@{ schema = 1; campaignId = ('a' * 32); commit = ('b' * 40); projectRoot = 'C:\fixture'
            destructiveAuthorized = $false; scenarios = @('power-loss-during-install'); completed = @(); results = @()
            phase = 'awaiting-power-cut'; cutStep = 'power-loss-during-install' }
        Save-WacCampaignState -Path $path -State $state
        Assert-Equal 'awaiting-power-cut' (Get-WacCampaignState -Path $path).phase
    }
    finally { Remove-TestSandbox -Path $sandbox }
}
Test-Case 'Synchronous campaign children use the owned runner and require complete evidence' {
    $fn = Get-CampaignFunction -File 'WacCampaignScenario.ps1' -Name 'Invoke-WacCampaignHost'
    foreach ($required in @('Invoke-WacProcess', 'TerminationProven', 'OutputComplete', 'OwnedTreeState')) { Assert-True ($fn.Extent.Text.Contains($required)) }
    Assert-False ($fn.Extent.Text -match 'Start-Process')
}
Test-Case 'The extracted project is flushed and fingerprinted before a cut' {
    $fn = Get-CampaignFunction -File 'WacCampaignAgent.ps1' -Name 'Expand-WacCampaignProject'
    Assert-True ($fn.Extent.Text -match 'Get-WacCampaignPayloadFingerprint.+-Flush')
    $flusher = Get-CampaignFunction -File 'WacCampaignState.ps1' -Name 'Get-WacCampaignPayloadFingerprint'
    Assert-True ($flusher.Extent.Text -match '\.Flush\(\$true\)')
    Assert-False ($flusher.Extent.Text -match 'SilentlyContinue')
}
Test-Case 'A campaign starts from a proven-clean machine, or it does not start' {
    $reset = Get-CampaignFunction -File 'WacCampaignAgent.ps1' -Name 'Reset-WacCampaignMachine'
    Assert-True ($reset.Extent.Text -match '\$after\s*=\s*Get-WacCampaignMachine')
    Assert-True ($reset.Extent.Text -match '\$ran\.ExitCode\s*-eq\s*0\s*-and\s*\$after\.Clean')
    $ast = Get-CampaignAst -File 'WacCampaignAgent.ps1'
    $resume = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text -match "\`$state\.phase\s*-ceq\s*'awaiting-power-cut'"
    }, $true))
    Assert-Equal 1 $resume.Count
    Assert-False ($resume[0].Clauses[0].Item2.Extent.Text -match 'Reset-WacCampaignMachine')
    Assert-True ($ast.Extent.Text -match 'if \(-not \$baseline\.Clean\)')
}
Test-Case 'A state left by a killed campaign is refused, never replayed or discarded' {
    # H-6. Only a finished state may be cleared and only awaiting-power-cut may resume; anything
    # else - a campaign killed mid-run - must stop the agent rather than vanish.
    $ast = Get-CampaignAst -File 'WacCampaignAgent.ps1'
    $gate = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses.Count -ge 2 -and
        $node.Clauses[1].Item1.Extent.Text -match "\`$state\.phase\s*-cne\s*'awaiting-power-cut'"
    }, $true))
    Assert-Equal 1 $gate.Count 'the unfinished-state gate is missing'
    $body = $gate[0].Clauses[1].Item2
    Assert-Equal 1 @($body.Statements).Count 'the unfinished-state gate does more than refuse'
    Assert-True ($body.Statements[0] -is [Management.Automation.Language.ThrowStatementAst]) 'an unfinished state is not refused'
}
Complete-TestRun
