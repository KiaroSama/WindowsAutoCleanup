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

function Invoke-CampaignPowerCut {
    <#
    .SYNOPSIS
        Pulls the guest's power at the point the guest itself said it had reached, then starts it
        again so its recovery path runs on a real post-crash machine.
    .DESCRIPTION
        The cut is taken on the GUEST's signal rather than on a host timer. A timed cut lands
        wherever the guest happened to be, which makes a pass unrepeatable and a failure
        undiagnosable: the interesting instant is a specific one, and only the guest knows when it
        is standing on it.
    #>
    param([Parameter(Mandatory = $true)]$Vm, [Parameter(Mandatory = $true)][string]$AtStep)

    Write-CampaignLine ('  power cut requested by the guest at: {0}' -f $AtStep)
    $stopped = Stop-WacCampaignVm -Vm $Vm -PowerCut
    if (-not $stopped.Off) {
        throw ('The guest did not power off for the cut; it is {0}.' -f $stopped.State)
    }

    Start-VM -VM $Vm -ErrorAction Stop
    Write-CampaignLine '  power restored; the guest agent resumes on its own at startup'
    return $true
}

function Invoke-CampaignRun {
    <#
    .SYNOPSIS
        The whole campaign, from checkpoint to verified-off, returning its report.
    #>
    param(
        [Parameter(Mandatory = $true)]$Vm,
        [Parameter(Mandatory = $true)]$Payload,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    Write-CampaignLine '  starting the guest'
    Start-VM -VM $Vm -ErrorAction Stop

    # The agent publishes this as soon as it is alive. Until it does, the guest is either still
    # booting or was never armed, and those are told apart by waiting rather than assumed.
    $ready = Wait-WacCampaignSignal -VMName $Vm.Name -TimeoutSeconds 600 -IdleSeconds 600 -Until {
        param($item) $item.ContainsKey('AgentReady')
    }
    if (-not $ready.Signalled) {
        throw ('The guest agent never reported in. Either this guest was never armed, or the agent is not running. ' +
            'Arm it once with the procedure in Tests/Campaign/README.md. Detail: ' + $ready.Reason)
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
            return [PSCustomObject]@{ Status = 'blocked'; Reason = $signal.Reason; Item = $signal.Item; Report = $null }
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
                Reason = 'the guest declared itself finished but its report did not arrive whole; a partial verdict is not read as a short one'
                Item = $item; Report = $null }
        }

        return [PSCustomObject]@{ Status = [string]$item['Status']; Reason = ''; Item = $item; Report = $report }
    }
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
    $payload = New-CampaignPayload -StageRoot $stageRoot -Scenario $Scenario -CampaignId $campaignId -Destructive $arming.Destructive
    if ($payload.UncommittedFiles -gt 0) {
        Write-CampaignLine ('  note: {0} uncommitted file(s) in the working tree are NOT in this payload' -f $payload.UncommittedFiles)
    }

    if ($vm.State -cne 'Off') {
        Write-CampaignLine '  the guest was running; stopping it so the checkpoint is of a settled machine'
        $pre = Stop-WacCampaignVm -Vm $vm
        if (-not $pre.Off) { throw ('The guest could not be stopped before checkpointing; it is {0}.' -f $pre.State) }
    }

    [void](New-WacCampaignCheckpoint -Vm $vm -Name $checkpointName)
    $checkpointTaken = $true
    Write-CampaignLine ('  checkpoint taken: {0}' -f $checkpointName)

    $outcome = Invoke-CampaignRun -Vm $vm -Payload $payload -TimeoutSeconds ($TimeoutMinutes * 60)
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
            $restore = Restore-WacCampaignCheckpoint -Vm $vm -Name $checkpointName -Keep:$KeepCheckpoint
            Write-CampaignLine ('Checkpoint: {0}' -f $restore.Detail)

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
