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

Test-Case 'The resume point is on the DISK before the cut, not merely in the write cache' {
    # The one file in this project whose only purpose is to survive a power cut. Its writer used to
    # say "written and flushed first, every time" and call File::WriteAllText, which flushes
    # nothing - it returns once Windows has the bytes in its cache, and the cache is exactly what
    # the cut discards. Measured on 2026-09-20: the guest was cut mid-install, came back in twenty
    # seconds, read NO resume state and went to "waiting for the host to deliver a request", so the
    # scenario stopped testing recovery and waited instead.
    #
    # Asserted on the writer rather than by cutting power in a unit test, because the difference is
    # invisible to any read that happens while the machine is still on: a cached write and a durable
    # one both read back perfectly.
    $agentPath = Join-Path -Path $script:CampaignRoot -ChildPath 'WacCampaignAgent.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($agentPath, [ref]$null, [ref]$null)
    $fn = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Save-WacCampaignState'
            }, $true))
    Assert-Equal 1 $fn.Count 'the agent no longer defines exactly one Save-WacCampaignState'
    $body = [string]$fn[0].Extent.Text

    # Asserted over the CALLS the function makes, not over its text: the explanation above names
    # WriteAllText to say why it is wrong, and a text search cannot tell an argument from a warning.
    $calls = @($fn[0].FindAll({
                param($node) $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
            }, $true))
    $members = @($calls | ForEach-Object { [string]$_.Member.Extent.Text })

    Assert-False ($members -ccontains 'WriteAllText') `
        'the resume point is written with WriteAllText again, which returns before the bytes reach the disk'

    $flush = @($calls | Where-Object {
            [string]$_.Member.Extent.Text -ceq 'Flush' -and
            ([string]$_.Extent.Text).Replace(' ', '').EndsWith('.Flush($true)', [System.StringComparison]::Ordinal)
        })
    Assert-Equal 1 $flush.Count `
        'the resume point is not flushed to the device with Flush($true); a cut in the cache window loses the only file that matters'

    # And it still has to produce a file the reader can parse, or durability bought nothing.
    . ([scriptblock]::Create($body))
    $tmp = Join-Path -Path ([System.IO.Path]::GetTempPath()) ('wac-state-' + [guid]::NewGuid().ToString('N') + '.json')
    try {
        Save-WacCampaignState -Path $tmp -State ([PSCustomObject]@{ phase = 'awaiting-power-cut'; cutStep = 'power-loss-during-install' })
        $read = [System.IO.File]::ReadAllText($tmp) | ConvertFrom-Json
        Assert-Equal 'awaiting-power-cut' ([string]$read.phase) 'the durable writer did not round-trip the phase'
        Assert-Equal 'power-loss-during-install' ([string]$read.cutStep) 'the durable writer did not round-trip the cut step'
    }
    finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force } }
}

Test-Case 'Every exit code the campaign reads is cached before the child exits' {
    # Windows PowerShell 5.1 returns 0 from `Start-Process -PassThru`'s ExitCode unless the handle
    # was touched while the child was still alive. This project measured that across three shapes
    # and wrote it down, and the product's own elevation path applies it - the campaign did not.
    # The cost, on 2026-09-20: a correct FR-015 refusal that exited 1 with its message printed was
    # read as a successful install, and a recovery run that crashed on a damaged source file was
    # read as a clean exit 0. Two verdicts about the PRODUCT that were verdicts about one line.
    $scenarioPath = Join-Path -Path $script:CampaignRoot -ChildPath 'WacCampaignScenario.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scenarioPath, [ref]$null, [ref]$null)
    $fn = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Invoke-WacCampaignHost'
            }, $true))
    Assert-Equal 1 $fn.Count 'the campaign no longer defines exactly one Invoke-WacCampaignHost'

    # ADJACENCY, not just order. "Somewhere before the wait" is too weak twice over: a fast child
    # can exit inside any gap left before the read, and this function returns EARLY on
    # -PassThruProcess, so a read placed after that branch never happens at all on the path the
    # interruption scenarios use. The property is that the handle is taken in the very next
    # statement after the child is started.
    $statements = @($fn[0].Body.EndBlock.Statements | ForEach-Object { [string]$_.Extent.Text })
    $start = -1
    for ($i = 0; $i -lt $statements.Count; $i++) {
        if ($statements[$i].IndexOf('Start-Process', [System.StringComparison]::Ordinal) -ge 0) { $start = $i; break }
    }
    Assert-True ($start -ge 0) 'the campaign no longer starts the child with Start-Process'
    Assert-True (($start + 1) -lt $statements.Count) 'nothing follows the Start-Process call at all'
    Assert-True ($statements[$start + 1].IndexOf('.Handle', [System.StringComparison]::Ordinal) -ge 0) `
        ('the statement right after Start-Process does not read the child handle, so an ExitCode this campaign reports can be a false 0 on 5.1; it is: ' + $statements[$start + 1])
}

Test-Case 'The extracted project is on the disk before a scenario can cut the power' {
    # The guest unpacks the project and the very next thing a power-cut scenario does is cut the
    # power. `ExtractToDirectory` returns with the files in the write cache, so without this the
    # recovery boot runs the product from a half-written copy of ITSELF. Measured 2026-09-20: the
    # resumed installer died on `src\WindowsAutoCleanup.TrustedStore.ps1:1 char:1` with "the term
    # ' ' is not recognized" - a file whose first bytes never landed - and the scenario reported
    # that as a product defect.
    $agentPath = Join-Path -Path $script:CampaignRoot -ChildPath 'WacCampaignAgent.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($agentPath, [ref]$null, [ref]$null)
    $fn = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Expand-WacCampaignProject'
            }, $true))
    Assert-Equal 1 $fn.Count 'the agent no longer defines exactly one Expand-WacCampaignProject'

    $calls = @($fn[0].FindAll({
                param($node) $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
            }, $true))
    $flush = @($calls | Where-Object {
            [string]$_.Member.Extent.Text -ceq 'Flush' -and
            ([string]$_.Extent.Text).Replace(' ', '').EndsWith('.Flush($true)', [System.StringComparison]::Ordinal)
        })
    Assert-Equal 1 $flush.Count 'the extracted tree is not flushed to the device, so a cut can leave the product half-written'
}

Test-Case 'A campaign starts from a proven-clean machine, or it does not start' {
    # Isolation between SCENARIOS already worked - the host restores its base checkpoint between
    # them. Isolation between CAMPAIGNS did not, because that checkpoint is taken at campaign START:
    # residue from a previous run sits inside the baseline every scenario is returned to. Measured
    # 2026-09-20, a killed campaign left an outstanding uninstall intent and every later
    # power-loss-during-uninstall failed in its prepare step, with the product correctly refusing to
    # install over it. A verdict from that machine is a verdict about the previous campaign.
    $agentPath = Join-Path -Path $script:CampaignRoot -ChildPath 'WacCampaignAgent.ps1'
    $text = [System.IO.File]::ReadAllText($agentPath)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($agentPath, [ref]$null, [ref]$null)

    $reset = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Reset-WacCampaignMachine'
            }, $true))
    Assert-Equal 1 $reset.Count 'the agent does not bring the machine to a baseline before a campaign'

    # The verdict has to come from LOOKING again, never from the uninstaller's exit code: "the
    # command succeeded" and "the machine is clean" are different claims, and only the second one
    # is what the next scenario depends on.
    $body = [string]$reset[0].Extent.Text
    Assert-True ($body -match 'Clean\s*=\s*\$after\.Clean') `
        'the baseline verdict is not read back from the machine after the attempt'
    Assert-False ($body -match 'Clean\s*=\s*\(?\$ran\.ExitCode') `
        'the baseline is declared clean from an exit code instead of from the machine'

    # And it must FAIL CLOSED at the call site: a polluted machine that produces verdicts is worse
    # than one that says it cannot.
    $guard = [regex]::Match($text, 'if \(-not \$baseline\.Clean\) \{(?<body>[^}]*)\}')
    Assert-True $guard.Success 'nothing refuses the campaign when the baseline could not be restored'
    Assert-True ($guard.Groups['body'].Value -match 'Publish-WacCampaignFault') `
        'the refusal is silent; the host would see a campaign that simply stopped'
    Assert-True ($guard.Groups['body'].Value -match 'exit\s') `
        'the agent reports the polluted baseline and then runs the scenarios anyway'

    # The resume path must NOT touch it: after a power cut the machine's state IS the evidence, and
    # resetting it would destroy exactly what the scenario came back to verify.
    $resume = [regex]::Match($text, "if \(\`$null -ne \`$state -and \[string\]\`$state\.phase -ceq 'awaiting-power-cut'\) \{(?<body>(?s).*?)\r?\n\}")
    Assert-True $resume.Success 'the post-crash resume branch could not be located'
    Assert-False ($resume.Groups['body'].Value -match 'Reset-WacCampaignMachine') `
        'the resume path resets the machine, which erases the state the cut was taken to produce'
}

Complete-TestRun
