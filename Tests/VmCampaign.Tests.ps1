#Requires -Version 5.1
<#
.SYNOPSIS
    The campaign's refusals, and the credential boundary that makes it opt-in structurally.

.DESCRIPTION
    A campaign cuts a machine's power on purpose, installs a SYSTEM task in it, and - when
    separately authorized - permanently removes driver packages and the ability to uninstall
    updates. What can be proved here without a virtual machine is exactly the part that decides
    whether any of that is allowed to begin, and that is worth proving on every run.

    The last two cases are AST assertions about the whole Tests/Campaign folder rather than about
    one function. "The host never handles a guest credential" and "the guest is always left off" are
    properties of the code as a body; a function-by-function test would pass while a single added
    line somewhere else quietly broke either one.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:CampaignRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Campaign'
. (Join-Path -Path $script:CampaignRoot -ChildPath 'WacCampaignChannel.ps1')

function Use-CampaignEnvironment {
    <#
    .SYNOPSIS
        Runs a body with the two arming variables set, and always puts them back.
    #>
    param(
        [AllowNull()][string]$Campaign,
        [AllowNull()][string]$Destructive,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    $priorCampaign = $env:WAC_VM_CAMPAIGN
    $priorDestructive = $env:WAC_VM_CAMPAIGN_DESTRUCTIVE
    try {
        $env:WAC_VM_CAMPAIGN = $Campaign
        $env:WAC_VM_CAMPAIGN_DESTRUCTIVE = $Destructive
        return (& $Body)
    }
    finally {
        $env:WAC_VM_CAMPAIGN = $priorCampaign
        $env:WAC_VM_CAMPAIGN_DESTRUCTIVE = $priorDestructive
    }
}

function Get-CampaignFileText {
    <#
    .SYNOPSIS
        Every PowerShell file in the campaign folder, as name and text.
    #>
    return @(Get-ChildItem -LiteralPath $script:CampaignRoot -Filter '*.ps1' -File | ForEach-Object {
            [PSCustomObject]@{ Name = $_.Name; Text = [System.IO.File]::ReadAllText($_.FullName) }
        })
}

Test-Case 'A campaign refuses to run at all until it is explicitly armed' {
    # The opt-in is the whole protection. Anything that made it a default would make this a tool
    # that drives somebody's virtual machine because it was on the disk.
    $unset = Use-CampaignEnvironment -Campaign $null -Destructive $null -Body { Test-WacCampaignArmed }
    Assert-False $unset.Armed 'an unset WAC_VM_CAMPAIGN armed the campaign'
    Assert-True ($unset.Reason -match 'WAC_VM_CAMPAIGN') ('the refusal did not name what to set: ' + $unset.Reason)

    foreach ($near in @('0', 'true', 'yes', '1 ', 'True')) {
        $result = Use-CampaignEnvironment -Campaign $near -Destructive $null -Body { Test-WacCampaignArmed }
        Assert-False $result.Armed ('WAC_VM_CAMPAIGN="{0}" armed the campaign; only an exact 1 may' -f $near)
    }

    $armed = Use-CampaignEnvironment -Campaign '1' -Destructive $null -Body { Test-WacCampaignArmed }
    Assert-True $armed.Armed 'an exact WAC_VM_CAMPAIGN=1 did not arm the campaign'
}

Test-Case 'The destructive scenarios need their OWN authorization, and neither switch implies the other' {
    # Driving a disposable guest and permanently removing its driver packages are different
    # decisions. An operator who armed the first has not agreed to the second.
    $campaignOnly = Use-CampaignEnvironment -Campaign '1' -Destructive $null -Body {
        Test-WacCampaignArmed -WantDestructive
    }
    Assert-False $campaignOnly.Armed 'the campaign opt-in alone authorized the destructive scenarios'
    Assert-True ($campaignOnly.Reason -match 'WAC_VM_CAMPAIGN_DESTRUCTIVE') `
        ('the refusal did not name the second variable: ' + $campaignOnly.Reason)

    $destructiveOnly = Use-CampaignEnvironment -Campaign $null -Destructive '1' -Body { Test-WacCampaignArmed }
    Assert-False $destructiveOnly.Armed 'the destructive authorization alone armed a campaign'

    $both = Use-CampaignEnvironment -Campaign '1' -Destructive '1' -Body { Test-WacCampaignArmed -WantDestructive }
    Assert-True $both.Armed 'both authorizations together still refused'
    Assert-True $both.Destructive 'the destructive authorization was not carried into the result'

    # An armed campaign that did not ASK for a destructive scenario never reports itself as
    # authorized for one, whatever the environment happens to hold.
    $notAsked = Use-CampaignEnvironment -Campaign '1' -Destructive '1' -Body { Test-WacCampaignArmed }
    Assert-False $notAsked.Destructive 'a campaign that asked for no destructive scenario claimed the authorization anyway'
}

Test-Case 'There is no default target, and the destructive list is explicit rather than guessed' {
    $threw = $false
    try { [void](Get-WacCampaignVm -VMName '  ') } catch { $threw = $true }
    Assert-True $threw 'an empty -VMName was accepted; a campaign must never pick its own target'

    # Read off the driver: the two destructive scenarios are NAMED. Deriving them from a keyword
    # would mean a future scenario inherits the safe classification by being called something else.
    $driver = [System.IO.File]::ReadAllText((Join-Path -Path $script:CampaignRoot -ChildPath 'Invoke-WacVmCampaign.ps1'))
    Assert-True ($driver -match "DestructiveScenario\s*=\s*@\('driver-prune',\s*'reset-base'\)") `
        'the destructive scenarios are no longer an explicit list in the driver'
}

Test-Case 'A partial report is never read as a short one' {
    # The failure this prevents: a verdict that arrives half-written, parses, and is believed.
    $missingCount = @{ 'Report.0' = 'half a ' }
    Assert-True ($null -eq (Join-WacCampaignParts -Item $missingCount)) `
        'a report with parts but no count was reassembled anyway'

    $missingPart = @{ 'ReportParts' = '3'; 'Report.0' = 'a'; 'Report.2' = 'c' }
    Assert-True ($null -eq (Join-WacCampaignParts -Item $missingPart)) `
        'a report with a hole in the middle was reassembled anyway'

    $whole = @{ 'ReportParts' = '3'; 'Report.0' = 'a'; 'Report.1' = 'b'; 'Report.2' = 'c' }
    Assert-Equal 'abc' (Join-WacCampaignParts -Item $whole) 'a complete report was not reassembled'

    foreach ($nonsense in @('0', '-1', 'three', '')) {
        Assert-True ($null -eq (Join-WacCampaignParts -Item @{ 'ReportParts' = $nonsense; 'Report.0' = 'a' })) `
            ('a part count of "{0}" was treated as a real one' -f $nonsense)
    }
}

Test-Case 'Reading a machine that is not there is an empty READ, not a crash and not a finding' {
    # The distinction this project is built on. An empty read means the host learned nothing; it
    # never means the guest reported that nothing happened.
    $item = Read-WacCampaignReport -VMName 'wac-no-such-virtual-machine-b9f2'
    Assert-True ($item -is [hashtable]) 'reading an absent machine did not return a readable result'
    Assert-Equal 0 $item.Count 'reading an absent machine invented values'
}

Test-Case 'No part of the campaign handles a guest credential' {
    # The boundary is what makes arming a deliberate act by the guest's owner. If the host could
    # log in, the opt-in would be a flag rather than a property, and this file is where that gets
    # noticed - in the folder as a whole, not in whichever function someone remembered to check.
    foreach ($file in (Get-CampaignFileText)) {
        foreach ($forbidden in @('Get-Credential', '-Credential', 'New-PSSession', 'Enter-PSSession',
                'Invoke-Command', 'PSCredential', 'ConvertTo-SecureString')) {
            Assert-False ($file.Text.IndexOf($forbidden, [System.StringComparison]::Ordinal) -ge 0) `
                ('{0} references {1}; the campaign must not be able to log into the guest' -f $file.Name, $forbidden)
        }
    }
}

Test-Case 'The FIRST thing the driver does on its way out is stop the guest' {
    # An unattended campaign that throws and leaves somebody's machine running is the one outcome
    # the driver may not produce. Order is the claim, not presence: "Stop-WacCampaignVm appears
    # somewhere in the finally" is also true of a driver whose only remaining stop is a conditional
    # last resort three branches deep, which is exactly the shape that leaves a guest running when
    # the condition is false. So the assertion is on the FIRST statement that runs.
    $path = Join-Path -Path $script:CampaignRoot -ChildPath 'Invoke-WacVmCampaign.ps1'
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
    Assert-Equal 0 @($errors).Count (($errors | ForEach-Object { [string]$_ }) -join ' ; ')

    # The ENTRY POINT's try/finally: the one at the top level of the script, not a helper's own.
    # Selected structurally rather than by what its body mentions, so the selection cannot be made
    # to pass by adding the word this case is looking for.
    $try = @($ast.FindAll({ param($node)
                $node -is [System.Management.Automation.Language.TryStatementAst] -and $null -ne $node.Finally
            }, $true) | Where-Object {
            $parent = $_.Parent
            $inFunction = $false
            while ($null -ne $parent) {
                if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $inFunction = $true; break }
                $parent = $parent.Parent
            }
            -not $inFunction
        })
    Assert-Equal 1 $try.Count 'the driver does not have exactly one top-level try/finally'

    # The finally opens by testing that a machine was resolved at all - a campaign that never got
    # that far has nothing to stop - and the first thing inside that branch is the stop.
    $finally = $try[0].Finally
    $first = @($finally.Statements)[0]
    Assert-True ($first -is [System.Management.Automation.Language.IfStatementAst]) `
        ('the finally does not open with the machine-resolved guard; it opens with: ' + [string]$first.Extent.Text)

    $branch = @($first.Clauses)[0].Item2
    $firstAction = [string](@($branch.Statements)[0].Extent.Text)
    Assert-True ($firstAction.IndexOf('Stop-WacCampaignVm', [System.StringComparison]::Ordinal) -ge 0) `
        ('the first thing the driver does on its way out is not stopping the guest; it is: ' + $firstAction)

    $finallyText = [string]$finally.Extent.Text
    Assert-True ($finallyText.IndexOf('Restore-WacCampaignCheckpoint', [System.StringComparison]::Ordinal) -ge 0) `
        'the checkpoint is not restored from the finally, so a failure can leave the guest modified'
    Assert-True ($finallyText.IndexOf('Stop-WacCampaignVm', [System.StringComparison]::Ordinal) -lt
        $finallyText.IndexOf('Restore-WacCampaignCheckpoint', [System.StringComparison]::Ordinal)) `
        'the guest is restored before it is stopped; a running machine cannot be restored coherently'
}


Test-Case 'A sticky beacon is judged by its OWN timestamp, not by being present' {
    # The defect this replaces cost a real run twice over. Key-Value Pair Exchange keeps the last
    # value the guest wrote until something overwrites it, so after a reboot the previous session's
    # timestamp is sitting right there. The driver used to accept `AgentReady` merely for EXISTING,
    # and did so on a value from an hour earlier - delivering a payload to a guest whose agent had
    # not started. Presence is not freshness.
    #
    # The function is lifted out of the driver by AST rather than dot-sourced, because the driver
    # has a mandatory parameter and running it here would start a campaign.
    $driverPath = Join-Path -Path $script:CampaignRoot -ChildPath 'Invoke-WacVmCampaign.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($driverPath, [ref]$null, [ref]$null)
    $fn = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Get-CampaignBeaconUtc'
            }, $true))
    Assert-Equal 1 $fn.Count 'the driver no longer defines exactly one Get-CampaignBeaconUtc'
    . ([scriptblock]::Create($fn[0].Extent.Text))

    $cut = [datetime]::SpecifyKind([datetime]::Parse('2026-09-20T00:45:38Z', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal), [System.DateTimeKind]::Utc)

    $stale = Get-CampaignBeaconUtc -Item @{ AgentReady = '2026-09-19T23:07:57Z' } -Name 'AgentReady'
    Assert-True ($null -ne $stale) 'a well-formed stale beacon was not parsed at all'
    Assert-False ($stale -gt $cut) 'a beacon from the PREVIOUS session counted as this boot'

    $fresh = Get-CampaignBeaconUtc -Item @{ AgentReady = '2026-09-20T00:45:52Z' } -Name 'AgentReady'
    Assert-True ($fresh -gt $cut) 'a beacon stamped after the cut was not accepted'

    # Anything unreadable is absent, never guessed at: a guess here is a payload delivered to a
    # guest that is not listening.
    Assert-True ($null -eq (Get-CampaignBeaconUtc -Item @{ } -Name 'AgentReady')) 'a missing beacon was not reported as absent'
    Assert-True ($null -eq (Get-CampaignBeaconUtc -Item @{ AgentReady = '' } -Name 'AgentReady')) 'a blank beacon was not reported as absent'
    Assert-True ($null -eq (Get-CampaignBeaconUtc -Item @{ AgentReady = 'System.Object[]' } -Name 'AgentReady')) 'an unparseable beacon was not reported as absent'
    Assert-True ($null -eq (Get-CampaignBeaconUtc -Item $null -Name 'AgentReady')) 'a null item was not reported as absent'
}

Test-Case 'After restoring power the campaign waits for the new boot before reading the guest again' {
    # `Await` still holds the request that was just serviced - the guest was powered off before it
    # could clear it. Returning straight to the read loop cut the power a SECOND time for the same
    # step, observed live: two cuts eighteen seconds apart during one power-loss-during-install.
    # That is not the scenario's contract, and a verdict from it answers a different question.
    #
    # Asserted as ORDER inside the function, because a Wait- call sitting anywhere in the file would
    # satisfy a mere text search while the defect stayed exactly where it was.
    $driverPath = Join-Path -Path $script:CampaignRoot -ChildPath 'Invoke-WacVmCampaign.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($driverPath, [ref]$null, [ref]$null)
    $fn = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Invoke-CampaignPowerCut'
            }, $true))
    Assert-Equal 1 $fn.Count 'the driver no longer defines exactly one Invoke-CampaignPowerCut'

    $commands = @($fn[0].FindAll({
                param($node) $node -is [System.Management.Automation.Language.CommandAst]
            }, $true) | ForEach-Object { [string]$_.GetCommandName() })

    $startIndex = [array]::IndexOf($commands, 'Start-VM')
    Assert-True ($startIndex -ge 0) 'the power cut no longer starts the guest again'
    $waitIndex = -1
    for ($i = $startIndex + 1; $i -lt $commands.Count; $i++) {
        if ($commands[$i] -ceq 'Wait-WacCampaignSignal') { $waitIndex = $i; break }
    }
    Assert-True ($waitIndex -gt $startIndex) `
        'nothing waits for the guest between restoring its power and handing control back, so a stale Await can cut it again'
}

Test-Case 'No reader in the campaign takes a beacon on presence alone' {
    # The whole class, not the two instances repaired. A future `ContainsKey` on one of these
    # timestamps reintroduces exactly the same false signal somewhere new.
    foreach ($file in (Get-CampaignFileText)) {
        foreach ($beacon in @('AgentReady', 'AgentBoot')) {
            $pattern = "ContainsKey\('" + $beacon + "'\)"
            Assert-False ($file.Text -match $pattern) `
                ('{0} tests {1} for presence instead of freshness; use its timestamp against the event' -f $file.Name, $beacon)
        }
    }
}

Complete-TestRun
