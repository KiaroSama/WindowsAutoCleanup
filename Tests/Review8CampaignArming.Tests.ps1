#Requires -Version 5.1
<#
.SYNOPSIS
    Legacy owner-started arming preserves shared policy and verifies registration independently.
.DESCRIPTION
    The real arming function is extracted; task observations and its registration script are fixtures.
    Mixed startup/shutdown policy bytes are actual sandbox files and must remain identical.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$path = Join-Path $PSScriptRoot 'Campaign\WacCampaignAgent.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
$fn = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Set-WacCampaignDurableArming'
}, $true)
. ([scriptblock]::Create($fn.Extent.Text))
function Write-WacCampaignAgentLog { param($Text) $null = $Text }
foreach ($fault in @('', 'register', 'missing', 'foreign')) {
    Test-Case ('Arming preserves policy and proves the registration: ' + $fault) {
        $sandbox = New-TestSandbox -Prefix 'campaign-arming'
        try {
            $Root = $sandbox
            $expected = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Root "{1}"' -f
                (Join-Path (Join-Path $Root 'agent') 'WacCampaignAgent.ps1'), $Root.TrimEnd('\')
            $script:Lookups = 0
            function Get-ScheduledTask {
                [CmdletBinding()]param()
                $script:Lookups++
                if (($script:Lookups -eq 1 -and $fault -cne 'foreign') -or $fault -ceq 'missing') { return @() }
                return [PSCustomObject]@{ TaskPath = '\WindowsAutoCleanupCampaign\'; TaskName = 'CampaignAgent'
                    Actions = @([PSCustomObject]@{ Arguments = $(if ($fault -ceq 'foreign') { 'foreign' } else { $expected }) })
                    Principal = [PSCustomObject]@{ UserId = 'SYSTEM' } }
            }
            $policy = Join-Path $sandbox 'scripts.ini'
            $original = "[Startup]`r`n0CmdLine=unrelated.cmd`r`n1CmdLine=wac-campaign-boot.cmd`r`n[Shutdown]`r`n0CmdLine=preserve.cmd`r`n"
            [IO.File]::WriteAllText($policy, $original)
            $register = Join-Path $sandbox 'registration.ps1'
            $code = if ($fault -ceq 'register') { 37 } else { 0 }
            [IO.File]::WriteAllText($register, ('param($Root, $AgentPath) [IO.File]::WriteAllText((Join-Path $Root ''called.txt''), $AgentPath); exit ' + $code))
            if ($fault) {
                Assert-Throws -ScriptBlock { Set-WacCampaignDurableArming -RegistrationScript $register -AgentSource 'fixture-agent.ps1' }
                if ($fault -ceq 'foreign') { Assert-False (Test-Path -LiteralPath (Join-Path $sandbox 'called.txt')) }
            }
            else {
                Assert-Equal 'task-registered' (Set-WacCampaignDurableArming -RegistrationScript $register -AgentSource 'fixture-agent.ps1')
                Assert-Equal 'fixture-agent.ps1' ([IO.File]::ReadAllText((Join-Path $sandbox 'called.txt')))
                Assert-Equal 'task-already-present' (Set-WacCampaignDurableArming -RegistrationScript $register -AgentSource 'fixture-agent.ps1')
            }
            Assert-Equal $original ([IO.File]::ReadAllText($policy)) 'shared policy bytes changed'
        }
        finally { Remove-TestSandbox -Path $sandbox }
    }
}
Complete-TestRun
