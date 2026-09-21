#Requires -Version 5.1
<#
.SYNOPSIS
    Explicitly opted-in, isolated disposable-VM campaigns with identity-bound return evidence.
.DESCRIPTION
    The owner must first arm the guest. The host does not authenticate inside it. Each scenario
    starts from a verified checkpoint; power loss follows only that scenario's current request.
    Failures preserve the guest for inspection. Success is conditional on confirmed final shutdown.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][string]$VMName,
    [ValidateSet('service-dispatched-maintenance', 'power-loss-during-install', 'power-loss-during-uninstall',
        'reboot-recovery', 'driver-prune', 'reset-base')]
    [string[]]$Scenario = @('service-dispatched-maintenance', 'power-loss-during-install', 'power-loss-during-uninstall', 'reboot-recovery'),
    [switch]$AllowDestructive, [switch]$KeepCheckpoint,
    [ValidateRange(5, 240)][int]$TimeoutMinutes = 60, [string]$OutputPath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'WacCampaignChannel.ps1')
$script:DestructiveScenario = @('driver-prune', 'reset-base')
function Write-CampaignLine { param([string]$Text = '') Write-Host $Text }

function New-CampaignPayload {
    param([string]$StageRoot, [string[]]$Scenario, [string]$CampaignId, [bool]$Destructive)
    [void](New-Item -ItemType Directory -Path $StageRoot -Force)
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Push-Location -LiteralPath $repoRoot
    try {
        $head = [string](& git rev-parse HEAD)
        if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[a-fA-F0-9]{40}$') { throw 'Cannot identify a committed source revision.' }
        $dirty = @(& git status --porcelain | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect the source checkout.' }
        $archive = Join-Path $StageRoot 'project.zip'
        & git archive --format=zip --output="$archive" HEAD
        if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($archive)) { throw 'The source archive was not created.' }
    }
    finally { Pop-Location }
    $request = [PSCustomObject]@{ campaignId = $CampaignId; commit = $head; scenarios = @($Scenario)
        destructiveAuthorized = $Destructive; archiveSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256 -ErrorAction Stop).Hash
        requestedUtc = [datetime]::UtcNow.ToString('o') }
    $requestPath = Join-Path $StageRoot 'request.json'
    [IO.File]::WriteAllText($requestPath, (ConvertTo-Json -InputObject $request -Depth 5), (New-Object Text.UTF8Encoding($false)))
    return [PSCustomObject]@{ Archive = $archive; Request = $requestPath; Commit = $head; UncommittedFiles = $dirty.Count
        CampaignId = $CampaignId; Scenario = [string]$Scenario[0] }
}

function Get-CampaignBeaconUtc {
    param($Item, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Item -or -not $Item.ContainsKey($Name)) { return $null }
    $raw = [string]$Item[$Name]
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $parsed = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if (-not [datetime]::TryParse($raw, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $null }
    return $parsed
}
function Get-CampaignGuestAccount {
    param([hashtable]$Item)
    $said = @()
    foreach ($key in @('AgentBoot', 'AgentFault', 'AgentLog')) {
        if ($null -ne $Item -and $Item.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace([string]$Item[$key])) {
            $said += $key + '=' + [string]$Item[$key]
        }
    }
    return (' Guest account: ' + ($said -join ' | '))
}
function Invoke-CampaignPowerCut {
    param([Parameter(Mandatory = $true)]$Vm, [Parameter(Mandatory = $true)][string]$AtStep, [int]$ReturnTimeoutSeconds = 1200)
    Write-CampaignLine ('Cut requested at ' + $AtStep)
    $cutUtc = [datetime]::UtcNow
    $stopped = Stop-WacCampaignVm -Vm $Vm -PowerCut
    if (-not $stopped.Off) { throw 'The admitted VM was not confirmed off.' }
    Start-VM -VM $Vm -ErrorAction Stop
    # Do not service sticky Await twice: require the new boot's beacon and cleared request.
    $back = Wait-WacCampaignSignal -VMName $Vm.Name -VmId $Vm.Id -TimeoutSeconds $ReturnTimeoutSeconds -IdleSeconds $ReturnTimeoutSeconds -Until {
        param($item)
        $ready = Get-CampaignBeaconUtc -Item $item -Name 'AgentReady'
        if ($null -eq $ready -or $ready -le $cutUtc) { return $false }
        return (-not $item.ContainsKey('Await') -or [string]::IsNullOrWhiteSpace([string]$item['Await']))
    }
    if (-not $back.Signalled) { throw ('No verified return after the cut. ' + $back.Reason + (Get-CampaignGuestAccount -Item $back.Item)) }
    return $true
}

function Invoke-CampaignOneScenario {
    param([Parameter(Mandatory = $true)]$Vm, [Parameter(Mandatory = $true)]$Payload,
        [Parameter(Mandatory = $true)][datetime]$Deadline)
    $budget = [Math]::Max(0, ($Deadline.ToUniversalTime() - [datetime]::UtcNow).TotalSeconds)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $startedUtc = [datetime]::UtcNow
    Start-VM -VM $Vm -ErrorAction Stop
    $ready = Wait-WacCampaignSignal -VMName $Vm.Name -VmId $Vm.Id -TimeoutSeconds ([int][Math]::Min(600, $budget)) -IdleSeconds 600 -Until {
        param($item)
        $beacon = Get-CampaignBeaconUtc -Item $item -Name 'AgentReady'
        return ($null -ne $beacon -and $beacon -gt $startedUtc)
    }
    if (-not $ready.Signalled) { throw ('The armed guest did not report ready. ' + $ready.Reason + (Get-CampaignGuestAccount -Item $ready.Item)) }
    [void](Send-WacCampaignPayload -Vm $Vm -SourcePath $Payload.Archive -GuestPath 'C:\wac-campaign\in\project.zip')
    [void](Send-WacCampaignPayload -Vm $Vm -SourcePath $Payload.Request -GuestPath 'C:\wac-campaign\in\request.json')
    $cutPerformed = $false
    while ($watch.Elapsed.TotalSeconds -lt $budget) {
        $remaining = [int][Math]::Ceiling([Math]::Max(0, $budget - $watch.Elapsed.TotalSeconds))
        $signal = Wait-WacCampaignSignal -VMName $Vm.Name -VmId $Vm.Id -TimeoutSeconds $remaining -IdleSeconds 900 -Until {
            param($item)
            if ($item.ContainsKey('AgentFault') -and -not [string]::IsNullOrWhiteSpace([string]$item.AgentFault)) { return $true }
            if (-not $item.ContainsKey('ActiveCampaign') -or -not $item.ContainsKey('ActiveScenario')) { return $false }
            if ($item.ActiveCampaign -cne $Payload.CampaignId -or $item.ActiveScenario -cne $Payload.Scenario) { return $false }
            return ($item.ContainsKey('Await') -and -not [string]::IsNullOrWhiteSpace([string]$item.Await)) -or
                ($item.ContainsKey('Status') -and @('complete', 'failed') -ccontains [string]$item.Status)
        }
        if (-not $signal.Signalled) { throw ($signal.Reason + (Get-CampaignGuestAccount -Item $signal.Item)) }
        $item = $signal.Item
        if ($item.ContainsKey('AgentFault') -and -not [string]::IsNullOrWhiteSpace([string]$item.AgentFault)) {
            throw ('Guest refused the campaign: ' + [string]$item.AgentFault)
        }
        if ($item.ContainsKey('Await') -and -not [string]::IsNullOrWhiteSpace([string]$item.Await)) {
            if ($cutPerformed -or [string]$item.Await -cne ('power-cut:' + $Payload.Scenario) -or
                @('power-loss-during-install', 'power-loss-during-uninstall') -cnotcontains $Payload.Scenario) {
                throw 'The guest asked for an unauthorized or repeated cut.'
            }
            [void](Invoke-CampaignPowerCut -Vm $Vm -AtStep $Payload.Scenario -ReturnTimeoutSeconds ([int][Math]::Min(1200, $remaining)))
            $cutPerformed = $true
            continue
        }
        $text = Join-WacCampaignParts -Item $item
        if ($null -eq $text) { throw 'The complete report did not arrive.' }
        $parsed = $text | ConvertFrom-Json -ErrorAction Stop
        if (-not (Test-WacCampaignReportEvidence -Report $parsed -CampaignId $Payload.CampaignId -Commit $Payload.Commit -Scenario $Payload.Scenario)) {
            throw 'The report does not prove the exact requested campaign, revision and scenario.'
        }
        if ($Payload.Scenario -like 'power-loss-*' -and -not $cutPerformed) { throw 'The host performed no requested power cut.' }
        return [PSCustomObject]@{ Status = [string]$parsed.status; Reason = ''; Item = $item; Report = $text }
    }
    throw 'The scenario exhausted its shared monotonic deadline.'
}

function Invoke-CampaignRun {
    param([Parameter(Mandatory = $true)]$Vm, [string[]]$ScenarioList, [string]$CampaignId,
        [string]$StageRoot, [string]$BaseCheckpoint, [bool]$Destructive, [int]$TimeoutSeconds)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $results = New-Object 'Collections.Generic.List[object]'
    $notRun = New-Object 'Collections.Generic.List[string]'
    $commit = ''; $index = 0
    foreach ($scenario in $ScenarioList) {
        $index++
        if ($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { [void]$notRun.Add($scenario); continue }
        if ($index -gt 1) {
            $stopped = Stop-WacCampaignVm -Vm $Vm
            if (-not $stopped.Off) { throw 'The admitted VM could not be stopped between scenarios.' }
            $base = @(Get-VMSnapshot -VM $Vm -Name $BaseCheckpoint -ErrorAction Stop)
            if ($base.Count -ne 1 -or $base[0].Name -cne $BaseCheckpoint -or [guid]$base[0].VMId -ne [guid]$Vm.Id) { throw 'The base checkpoint identity changed.' }
            Restore-VMSnapshot -VMSnapshot $base[0] -Confirm:$false -ErrorAction Stop
        }
        $payload = New-CampaignPayload -StageRoot (Join-Path $StageRoot ('s' + $index)) -Scenario @($scenario) -CampaignId $CampaignId -Destructive $Destructive
        if ($commit -and $payload.Commit -cne $commit) { throw 'The source revision changed between scenarios.' }
        $commit = $payload.Commit
        try {
            $one = Invoke-CampaignOneScenario -Vm $Vm -Payload $payload -Deadline ([datetime]::UtcNow.AddSeconds([Math]::Max(0, $TimeoutSeconds - $watch.Elapsed.TotalSeconds)))
            $parsed = $one.Report | ConvertFrom-Json -ErrorAction Stop
            foreach ($entry in @($parsed.results)) { [void]$results.Add($entry) }
        }
        catch { [void]$results.Add([PSCustomObject]@{ Scenario = $scenario; Verdict = 'failed'; Detail = $_.Exception.Message }) }
    }
    $status = if ($notRun.Count -eq 0 -and @($results.ToArray() | Where-Object { $_.Verdict -cne 'passed' }).Count -eq 0) { 'complete' } else { 'failed' }
    $report = [PSCustomObject]@{ schema = 1; campaignId = $CampaignId; commit = $commit
        finishedUtc = [datetime]::UtcNow.ToString('o'); requested = @($ScenarioList); notRun = @($notRun.ToArray())
        isolated = $true; results = @($results.ToArray()); status = $status }
    return [PSCustomObject]@{ Status = $status; Reason = ''; Item = @{}; Report = (ConvertTo-Json -InputObject $report -Depth 12) }
}

$wantDestructive = @($Scenario | Where-Object { $script:DestructiveScenario -ccontains $_ }).Count -gt 0
if ($wantDestructive -and -not $AllowDestructive) { Write-CampaignLine 'REFUSED: -AllowDestructive is required.'; exit 2 }
$arming = Test-WacCampaignArmed -WantDestructive:$wantDestructive
if (-not $arming.Armed) { Write-CampaignLine ('REFUSED: ' + $arming.Reason); exit 2 }
if (@($Scenario).Count -eq 0 -or @($Scenario | Select-Object -Unique).Count -ne @($Scenario).Count) { throw 'Scenario selection must be nonempty and unique.' }
$campaignId = [guid]::NewGuid().ToString('N')
$checkpointName = 'wac-campaign-' + $campaignId
$stageRoot = Join-Path ([IO.Path]::GetTempPath()) ('wac-campaign-' + $campaignId)
$vm = $null; $checkpointTaken = $false
$outcome = [PSCustomObject]@{ Status = 'blocked'; Reason = 'not started'; Item = @{}; Report = $null }
try {
    $vm = Get-WacCampaignVm -VMName $VMName
    Write-CampaignLine ('Campaign {0} on {1}, immutable Id {2}' -f $campaignId, $vm.Name, $vm.Id)
    [void](New-Item -ItemType Directory -Path $stageRoot -Force)
    $pre = Stop-WacCampaignVm -Vm $vm
    if (-not $pre.Off) { throw 'The base VM is not confirmed off.' }
    [void](New-WacCampaignCheckpoint -Vm $vm -Name $checkpointName)
    $checkpointTaken = $true
    $outcome = Invoke-CampaignRun -Vm $vm -ScenarioList @($Scenario) -CampaignId $campaignId -StageRoot $stageRoot `
        -BaseCheckpoint $checkpointName -Destructive $arming.Destructive -TimeoutSeconds ($TimeoutMinutes * 60)
}
catch { $outcome.Status = 'blocked'; $outcome.Reason = $_.Exception.Message }
finally {
    if ($null -ne $vm) {
        $final = Stop-WacCampaignVm -Vm $vm
        if (-not $final.Off) { $outcome.Status = 'blocked'; $outcome.Reason = 'Final shutdown was not proven; the guest needs operator attention.' }
        if ($checkpointTaken -and $final.Off) {
            $keep = [bool]$KeepCheckpoint -or $outcome.Status -cne 'complete'
            $restore = Restore-WacCampaignCheckpoint -Vm $vm -Name $checkpointName -Keep:$keep
            Write-CampaignLine ('Checkpoint: ' + $restore.Detail)
            if (-not $keep -and -not $restore.Restored) { $outcome.Status = 'blocked'; $outcome.Reason = $restore.Detail }
            if ((Get-WacCampaignVmState -Vm $vm) -cne 'Off') {
                $again = Stop-WacCampaignVm -Vm $vm
                if (-not $again.Off) { $outcome.Status = 'blocked'; $outcome.Reason = 'The restored guest is not confirmed off.' }
            }
        }
    }
    if (Test-Path -LiteralPath $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
if ($null -ne $outcome.Report) {
    $document = $outcome.Report | ConvertFrom-Json
    if ($outcome.Status -cne 'complete') { $document.status = $outcome.Status }
    $document | Add-Member -NotePropertyName cleanupReason -NotePropertyValue $outcome.Reason -Force
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path (Get-Location).Path ('wac-campaign-' + $campaignId + '.json') }
    [IO.File]::WriteAllText($OutputPath, (ConvertTo-Json -InputObject $document -Depth 12), (New-Object Text.UTF8Encoding($false)))
    Write-CampaignLine ('Report: ' + $OutputPath)
}
switch ([string]$outcome.Status) {
    'complete' { Write-CampaignLine 'CAMPAIGN: COMPLETE'; exit 0 }
    'failed' { Write-CampaignLine 'CAMPAIGN: FAILED'; exit 1 }
    default { Write-CampaignLine ('CAMPAIGN: BLOCKED - ' + $outcome.Reason); exit 3 }
}
