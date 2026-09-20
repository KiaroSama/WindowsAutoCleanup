#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the protected, opt-in disposable-VM campaign: the scenarios continuous integration
    structurally cannot perform.

.DESCRIPTION
    A GitHub-hosted runner is a disposable, elevated, explicitly armed Windows machine, and this
    project already uses it for everything it can honestly cover. Four things it cannot cover:

      * A REAL power cut in the middle of an installation or an uninstall. A runner cannot lose
        power on cue, and a simulated interruption proves the code path, never the machine state
        the transaction is actually left in.
      * A REAL restart. The restart proof reads a monotonic native counter; only an actual reboot
        moves it, and a test that fakes the counter proves the arithmetic rather than the claim.
      * SERVICE-DISPATCHED maintenance: the shipped scheduled task, started by the Task Scheduler
        as SYSTEM, with the deployment root actually present, running a real cleanup to completion.
        The live lifecycle lane proves registration, start and removal; the CLEANUP ITSELF has
        never run end to end inside a guest.
      * A representative Windows 11 client: real drivers, a real component store, a real profile.

    THIS DOES NOT REINTERPRET CI AS HAVING PERFORMED ANY OF THAT. Whatever this campaign has not
    run is reported as not run.

.NOTES
    No credential is asked for, accepted, stored or logged. The host delivers files over the Guest
    Service Interface and reads the guest's own published values back over Key-Value Pair Exchange;
    neither can start code in the guest. The guest must therefore have been armed once by its owner
    (Tests/Campaign/README.md), which is what makes this opt-in structurally rather than by flag.

    The guest is checkpointed before anything is delivered and restored afterwards, and the machine
    is always left OFF.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][string]$VMName,
    [ValidateSet('service-dispatched-maintenance', 'power-loss-during-install',
        'power-loss-during-uninstall', 'reboot-recovery', 'driver-prune', 'reset-base')]
    [string[]]$Scenario = @('service-dispatched-maintenance', 'power-loss-during-install',
        'power-loss-during-uninstall', 'reboot-recovery'),
    [switch]$AllowDestructive,
    [switch]$KeepCheckpoint,
    [ValidateRange(5, 240)][int]$TimeoutMinutes = 60,
    [string]$OutputPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath 'WacCampaignChannel.ps1')

# The two scenarios that remove things a machine cannot simply put back. They are listed here rather
# than inferred from a name, so adding a scenario can never quietly inherit the safe classification.
$script:DestructiveScenario = @('driver-prune', 'reset-base')

function Write-CampaignLine {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'The campaign is an operator-run report; its console text is the product.')]
    param([string]$Text = '')
    Write-Host $Text
}

function New-CampaignPayload {
    <#
    .SYNOPSIS
        A zip of the project at committed HEAD, plus the request the guest agent reads.
    .DESCRIPTION
        From HEAD, never the working tree. A campaign staged from uncommitted edits produces
        evidence bound to no reviewable state - the lesson this project already paid for once.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string[]]$Scenario,
        [Parameter(Mandatory = $true)][string]$CampaignId,
        [bool]$Destructive
    )

    # Its own directory, because each scenario now stages into a subdirectory of its own and
    # `git archive --output` fails on a path whose parent does not exist.
    [void](New-Item -ItemType Directory -Path $StageRoot -Force)

    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Push-Location -LiteralPath $repoRoot
    try {
        $head = (& git rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$head)) {
            throw 'Could not read HEAD. The campaign stages the project from a committed commit, never from the working tree.'
        }
        $head = ([string]$head).Trim()

        $dirty = @(& git status --porcelain 2>$null | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        $archive = Join-Path -Path $StageRoot -ChildPath 'project.zip'
        & git archive --format=zip --output="$archive" HEAD 2>$null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $archive -PathType Leaf)) {
            throw 'git archive did not produce the project package.'
        }
    }
    finally { Pop-Location }

    $request = [PSCustomObject]@{
        campaignId = $CampaignId
        commit = $head
        scenarios = @($Scenario)
        destructiveAuthorized = [bool]$Destructive
        requestedUtc = ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
    }
    $requestPath = Join-Path -Path $StageRoot -ChildPath 'request.json'
    [System.IO.File]::WriteAllText($requestPath, (ConvertTo-Json -InputObject $request -Depth 5),
        (New-Object System.Text.UTF8Encoding($false)))

    return [PSCustomObject]@{
        Archive = $archive
        Request = $requestPath
        Commit = $head
        UncommittedFiles = $dirty.Count
    }
}

function Get-CampaignBeaconUtc {
    <#
    .SYNOPSIS
        One of the guest's ISO-8601 beacons as a UTC DateTime, or $null when it has published none
        this host can read.
    .DESCRIPTION
        Key-Value Pair Exchange is STICKY. The guest writes these values into its own registry and
        they stay there until something overwrites them, so a beacon read just after a reboot is
        very often the PREVIOUS session's. Presence therefore proves nothing about this boot, and
        the only sound test is the beacon's own timestamp against the instant of the event being
        waited on. A value that cannot be parsed is reported as absent rather than guessed at.
    #>
    param($Item, [Parameter(Mandatory = $true)][string]$Name)

    if ($null -eq $Item -or -not $Item.ContainsKey($Name)) { return $null }
    $raw = [string]$Item[$Name]
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if (-not [datetime]::TryParse($raw, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $null
    }
    return $parsed
}

function Invoke-CampaignPowerCut {
    <#
    .SYNOPSIS
        Pulls the guest's power at the point the guest itself said it had reached, starts it again,
        and does not return until the agent has come back and spoken for THIS boot.
    .DESCRIPTION
        The cut is taken on the GUEST's signal rather than on a host timer. A timed cut lands
        wherever the guest happened to be, which makes a pass unrepeatable and a failure
        undiagnosable: the interesting instant is a specific one, and only the guest knows when it
        is standing on it.

        Returning as soon as the power is back is not enough, and cost a real run: the guest was
        powered off mid-step, so `Await` still holds the request that was just serviced - the guest
        never got the chance to clear it. The caller's loop reads that stale value and cuts the
        power a SECOND time for the same step, which silently turns "one cut during install" into a
        different experiment whose verdict answers a question nobody asked. So this waits for the
        agent's own proof of a new boot: an `AgentReady` stamped after the cut, and `Await` blank
        again, which is the order the agent publishes them in.
    #>
    param(
        [Parameter(Mandatory = $true)]$Vm,
        [Parameter(Mandatory = $true)][string]$AtStep,
        [int]$ReturnTimeoutSeconds = 1200
    )

    Write-CampaignLine ('  power cut requested by the guest at: {0}' -f $AtStep)
    $cutUtc = [datetime]::UtcNow
    $stopped = Stop-WacCampaignVm -Vm $Vm -PowerCut
    if (-not $stopped.Off) {
        throw ('The guest did not power off for the cut; it is {0}.' -f $stopped.State)
    }

    Start-VM -VM $Vm -ErrorAction Stop
    Write-CampaignLine '  power restored; waiting for the agent to speak for the new boot'

    $back = Wait-WacCampaignSignal -VMName $Vm.Name -TimeoutSeconds $ReturnTimeoutSeconds -IdleSeconds $ReturnTimeoutSeconds -Until {
        param($item)
        $ready = Get-CampaignBeaconUtc -Item $item -Name 'AgentReady'
        if ($null -eq $ready -or $ready -le $cutUtc) { return $false }
        return (-not $item.ContainsKey('Await') -or [string]::IsNullOrWhiteSpace([string]$item['Await']))
    }
    if (-not $back.Signalled) {
        throw ('The guest did not come back after the cut at {0}. {1}{2}' -f
            $AtStep, $back.Reason, (Get-CampaignGuestAccount -Item $back.Item))
    }

    $returned = Get-CampaignBeaconUtc -Item $back.Item -Name 'AgentReady'
    Write-CampaignLine ('  the agent is back {0:N0}s after the cut' -f ($returned - $cutUtc).TotalSeconds)
    return $true
}

function Get-CampaignGuestAccount {
    <#
    .SYNOPSIS
        Whatever the guest managed to say about its own failure, appended to a host-side reason.
    .DESCRIPTION
        The agent publishes `AgentFault` and the tail of its own log when it stops, precisely because
        the host has no credential-bearing way to read a file in there. Leaving those out of the
        reason is how a campaign reports silence when the guest was not silent at all.
    #>
    param([hashtable]$Item)

    $said = @()
    foreach ($key in @('AgentBoot', 'AgentFault', 'AgentLog')) {
        if ($null -ne $Item -and $Item.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace([string]$Item[$key])) {
            $said += ('{0}={1}' -f $key, [string]$Item[$key])
        }
    }
    if ($said.Count -eq 0) { return ' The guest said nothing at all, not even that it booted.' }
    return (' The guest said: ' + ($said -join ' | '))
}

function Invoke-CampaignOneScenario {
    <#
    .SYNOPSIS
        One scenario, start to verdict, on a guest that is already at the base state.
    #>
    param(
        [Parameter(Mandatory = $true)]$Vm,
        [Parameter(Mandatory = $true)]$Payload,
        [Parameter(Mandatory = $true)][datetime]$Deadline
    )

    $deadline = $Deadline

    Write-CampaignLine '  starting the guest'
    $startedUtc = [datetime]::UtcNow
    Start-VM -VM $Vm -ErrorAction Stop

    # The agent publishes this as soon as it is alive. Until it does, the guest is either still
    # booting or was never armed, and those are told apart by waiting rather than assumed.
    # It must be THIS boot's value: the beacon is sticky, so merely finding one present accepted a
    # timestamp from a previous session and delivered the payload to a guest whose agent had not
    # started yet.
    $ready = Wait-WacCampaignSignal -VMName $Vm.Name -TimeoutSeconds 600 -IdleSeconds 600 -Until {
        param($item)
        $beacon = Get-CampaignBeaconUtc -Item $item -Name 'AgentReady'
        ($null -ne $beacon -and $beacon -gt $startedUtc)
    }
    if (-not $ready.Signalled) {
        throw ('The guest agent never reported in. Either this guest was never armed, or the agent is not running. ' +
            'Arm it once with the procedure in Tests/Campaign/README.md. Detail: ' + $ready.Reason +
            (Get-CampaignGuestAccount -Item $ready.Item))
    }
    Write-CampaignLine ('  agent ready: {0}' -f [string]$ready.Item['AgentReady'])

    Send-WacCampaignPayload -Vm $Vm -SourcePath $Payload.Archive -GuestPath 'C:\wac-campaign\in\project.zip' | Out-Null
    Send-WacCampaignPayload -Vm $Vm -SourcePath $Payload.Request -GuestPath 'C:\wac-campaign\in\request.json' | Out-Null
    Write-CampaignLine ('  payload delivered at commit {0}' -f $Payload.Commit)

    # The agent drives the scenarios. The host only answers the one thing the guest cannot do for
    # itself - lose power - and waits for the verdict.
    while ($true) {
        $remaining = [int]([Math]::Max(60, ($deadline - (Get-Date)).TotalSeconds))
        $signal = Wait-WacCampaignSignal -VMName $Vm.Name -TimeoutSeconds $remaining -IdleSeconds 900 -Until {
            param($item)
            ($item.ContainsKey('Await') -and -not [string]::IsNullOrWhiteSpace([string]$item['Await'])) -or
            ($item.ContainsKey('Status') -and [string]$item['Status'] -cin @('complete', 'failed'))
        }

        if (-not $signal.Signalled) {
            return [PSCustomObject]@{ Status = 'blocked'
                Reason = ($signal.Reason + (Get-CampaignGuestAccount -Item $signal.Item))
                Item = $signal.Item; Report = $null }
        }

        $item = $signal.Item
        if ($item.ContainsKey('Await') -and -not [string]::IsNullOrWhiteSpace([string]$item['Await'])) {
            $await = [string]$item['Await']
            if ($await.StartsWith('power-cut:', [System.StringComparison]::Ordinal)) {
                [void](Invoke-CampaignPowerCut -Vm $Vm -AtStep $await.Substring('power-cut:'.Length))
                continue
            }
            return [PSCustomObject]@{ Status = 'blocked'
                Reason = ('the guest asked for something this host does not perform: {0}' -f $await)
                Item = $item; Report = $null }
        }

        $report = Join-WacCampaignParts -Item $item -Key 'Report'
        if ($null -eq $report) {
            return [PSCustomObject]@{ Status = 'blocked'
                Reason = ('the guest declared itself finished but its report did not arrive whole; a partial verdict is not read as a short one.' +
                    (Get-CampaignGuestAccount -Item $item))
                Item = $item; Report = $null }
        }

        return [PSCustomObject]@{ Status = [string]$item['Status']; Reason = ''; Item = $item; Report = $report }
    }
}

function Invoke-CampaignRun {
    <#
    .SYNOPSIS
        Every requested scenario, each on a guest returned to the same base state first.
    .DESCRIPTION
        ISOLATION IS THE POINT. Running them in one sequence on an accumulating machine is how the
        first real campaign lost `reboot-recovery`: the scenario before it left an uninstall intent
        standing, so the installer refused and the scenario was over before it began - a result that
        says nothing about reboots. A scenario that starts anywhere other than the base state is
        measuring the scenario before it.

        The cost is a boot per scenario, which is the cheapest part of a campaign.
    #>
    param(
        [Parameter(Mandatory = $true)]$Vm,
        [Parameter(Mandatory = $true)][string[]]$ScenarioList,
        [Parameter(Mandatory = $true)][string]$CampaignId,
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$BaseCheckpoint,
        [bool]$Destructive,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $results = New-Object 'System.Collections.Generic.List[object]'
    $notRun = New-Object 'System.Collections.Generic.List[string]'
    $commit = ''
    $index = 0

    foreach ($scenario in @($ScenarioList)) {
        $index++
        Write-CampaignLine ''
        Write-CampaignLine ('[{0}/{1}] {2}' -f $index, @($ScenarioList).Count, $scenario)

        if ((Get-Date) -ge $deadline) {
            [void]$notRun.Add($scenario)
            continue
        }

        if ($index -gt 1) {
            $stopped = Stop-WacCampaignVm -Vm $Vm
            if (-not $stopped.Off) { throw ('the guest could not be stopped between scenarios; it is {0}.' -f $stopped.State) }
            $base = @(Get-VMSnapshot -VMName $Vm.Name -Name $BaseCheckpoint -ErrorAction SilentlyContinue)
            if ($base.Count -ne 1) { throw ('the base checkpoint {0} is gone, so the next scenario has no known state to start from.' -f $BaseCheckpoint) }
            Restore-VMSnapshot -VMSnapshot $base[0] -Confirm:$false -ErrorAction Stop
            Write-CampaignLine ('  guest returned to {0}' -f $BaseCheckpoint)
        }

        $payload = New-CampaignPayload -StageRoot (Join-Path $StageRoot ('s{0}' -f $index)) `
            -Scenario @($scenario) -CampaignId $CampaignId -Destructive $Destructive
        $commit = $payload.Commit

        $one = Invoke-CampaignOneScenario -Vm $Vm -Payload $payload -Deadline $deadline
        if ($null -eq $one.Report) {
            [void]$results.Add([PSCustomObject]@{ Scenario = $scenario; Verdict = 'failed'
                    Detail = ('the guest returned no whole report: ' + [string]$one.Reason) })
            continue
        }

        $parsed = $null
        try { $parsed = $one.Report | ConvertFrom-Json } catch { $parsed = $null }
        if ($null -eq $parsed) {
            [void]$results.Add([PSCustomObject]@{ Scenario = $scenario; Verdict = 'failed'
                    Detail = 'the guest returned a report that did not parse' })
            continue
        }

        foreach ($entry in @($parsed.results)) { [void]$results.Add($entry) }
        foreach ($missed in @($parsed.notRun)) { if ($missed) { [void]$notRun.Add([string]$missed) } }
    }

    $status = 'complete'
    if ($notRun.Count -gt 0) { $status = 'failed' }
    foreach ($entry in @($results.ToArray())) {
        if ([string]$entry.Verdict -cne 'passed') { $status = 'failed' }
    }

    $report = [PSCustomObject]@{
        schema = 1
        campaignId = $CampaignId
        commit = $commit
        finishedUtc = ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
        requested = @($ScenarioList)
        # Kept separate so a reader never subtracts one list from another to find what did not
        # happen. A scenario missing from `results` is not a scenario that passed.
        notRun = @($notRun.ToArray())
        isolated = $true
        results = @($results.ToArray())
        status = $status
    }

    return [PSCustomObject]@{ Status = $status; Reason = ''; Item = @{}
        Report = (ConvertTo-Json -InputObject $report -Depth 8) }
}

# ---------------------------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------------------------

$wantDestructive = @($Scenario | Where-Object { $script:DestructiveScenario -ccontains $_ }).Count -gt 0
if ($wantDestructive -and -not $AllowDestructive) {
    Write-CampaignLine 'REFUSED: a destructive scenario was requested without -AllowDestructive.'
    exit 2
}

$arming = Test-WacCampaignArmed -WantDestructive:$wantDestructive
if (-not $arming.Armed) {
    Write-CampaignLine ('REFUSED: ' + $arming.Reason)
    exit 2
}

$campaignId = [guid]::NewGuid().ToString('N')
$checkpointName = 'wac-campaign-{0}' -f ([datetime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
$stageRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('wac-campaign-' + $campaignId)
$vm = $null
$checkpointTaken = $false
$outcome = [PSCustomObject]@{ Status = 'blocked'; Reason = 'the campaign did not start'; Item = @{}; Report = $null }

try {
    $vm = Get-WacCampaignVm -VMName $VMName
    Write-CampaignLine ('Campaign {0} against "{1}" (currently {2})' -f $campaignId, $vm.Name, $vm.State)
    Write-CampaignLine ('Scenarios: {0}' -f (@($Scenario) -join ', '))
    Write-CampaignLine ''

    [void](New-Item -ItemType Directory -Path $stageRoot -Force)

    # Staged once here only to report what the payload will and will not contain; each scenario gets
    # its own package, because each is delivered to a guest that was just put back to the base state.
    $preview = New-CampaignPayload -StageRoot (Join-Path $stageRoot 'preview') -Scenario $Scenario `
        -CampaignId $campaignId -Destructive $arming.Destructive
    if ($preview.UncommittedFiles -gt 0) {
        Write-CampaignLine ('  note: {0} uncommitted file(s) in the working tree are NOT in this payload' -f $preview.UncommittedFiles)
    }

    if ($vm.State -cne 'Off') {
        Write-CampaignLine '  the guest was running; stopping it so the checkpoint is of a settled machine'
        $pre = Stop-WacCampaignVm -Vm $vm
        if (-not $pre.Off) { throw ('The guest could not be stopped before checkpointing; it is {0}.' -f $pre.State) }
    }

    [void](New-WacCampaignCheckpoint -Vm $vm -Name $checkpointName)
    $checkpointTaken = $true
    Write-CampaignLine ('  checkpoint taken: {0}' -f $checkpointName)

    $outcome = Invoke-CampaignRun -Vm $vm -ScenarioList @($Scenario) -CampaignId $campaignId `
        -StageRoot $stageRoot -BaseCheckpoint $checkpointName -Destructive $arming.Destructive `
        -TimeoutSeconds ($TimeoutMinutes * 60)
}
catch {
    $outcome = [PSCustomObject]@{ Status = 'blocked'; Reason = $_.Exception.Message; Item = @{}; Report = $null }
}
finally {
    if ($null -ne $vm) {
        $final = Stop-WacCampaignVm -Vm $vm
        Write-CampaignLine ''
        Write-CampaignLine ('Guest stopped: {0} (state {1})' -f $final.Off, $final.State)

        if ($checkpointTaken) {
            # A campaign that did NOT complete is the one whose guest is worth keeping. Rolling it
            # back here deletes the logs, the records and the half-finished state that explain the
            # failure - which is exactly what the first real run did to itself, leaving a report
            # that said what failed and nothing that said why. A clean campaign is rolled back.
            $keep = [bool]$KeepCheckpoint -or ([string]$outcome.Status -cne 'complete')
            $restore = Restore-WacCampaignCheckpoint -Vm $vm -Name $checkpointName -Keep:$keep
            Write-CampaignLine ('Checkpoint: {0}' -f $restore.Detail)
            if ($keep -and -not $KeepCheckpoint) {
                Write-CampaignLine ('The guest was LEFT as the campaign left it, so the failure can be diagnosed.')
                Write-CampaignLine ('Roll it back with: Restore-VMSnapshot -VMName "{0}" -Name "{1}" -Confirm:$false' -f $vm.Name, $checkpointName)
            }

            # Restoring a checkpoint of a stopped machine leaves it stopped, but the state is read
            # back rather than assumed: this is the last line of defence against leaving somebody's
            # machine running after an unattended campaign.
            $after = [string](Get-VM -Name $vm.Name -ErrorAction SilentlyContinue).State
            if ($after -cne 'Off') { [void](Stop-WacCampaignVm -Vm $vm) }
            Write-CampaignLine ('Final state: {0}' -f [string](Get-VM -Name $vm.Name -ErrorAction SilentlyContinue).State)
        }
    }

    if (Test-Path -LiteralPath $stageRoot) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-CampaignLine ''
if ($null -ne $outcome.Report) {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path -Path (Get-Location).Path -ChildPath ('wac-campaign-{0}.json' -f $campaignId)
    }
    [System.IO.File]::WriteAllText($OutputPath, $outcome.Report, (New-Object System.Text.UTF8Encoding($false)))
    Write-CampaignLine ('Report: {0}' -f $OutputPath)
}

switch ([string]$outcome.Status) {
    'complete' { Write-CampaignLine 'CAMPAIGN: COMPLETE'; exit 0 }
    'failed' { Write-CampaignLine 'CAMPAIGN: FAILED - read the report; the scenarios it did not reach are not claims about the product'; exit 1 }
    default {
        Write-CampaignLine ('CAMPAIGN: BLOCKED - ' + [string]$outcome.Reason)
        Write-CampaignLine 'Nothing here is evidence about the product. A blocked campaign proves only that it did not run.'
        exit 3
    }
}
