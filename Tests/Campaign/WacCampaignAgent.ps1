#Requires -Version 5.1
<#
.SYNOPSIS
    Guest agent for an explicitly armed disposable VM. Preserves unresolved recovery evidence.
.DESCRIPTION
    The host delivers a committed archive and reads KVP reports; it never logs into the guest.
    A held owned job stays alive until the requested cut/reboot. Agent restart is not boot proof.
    Legacy startup policy is never deleted. Only one agent runs, even with two startup entry paths.
#>
[CmdletBinding()]
param([string]$Root = 'C:\wac-campaign', [ValidateRange(1, 720)][int]$WatchMinutes = 30)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:KvpKey = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest'
$script:Prefix = 'WacCampaign.'
$script:Chunk = 900
$script:LogPath = Join-Path $Root 'agent.log'
$script:CampaignChannelAvailable = $false

function Write-WacCampaignAgentLog {
    param([AllowEmptyString()][string]$Text, [ValidateSet('INFO', 'WARNING', 'ERROR', 'DEBUG')][string]$Level = 'INFO')
    try {
        $stamp = [datetime]::UtcNow.ToString('o')
        $directory = Split-Path -Parent $script:LogPath
        if (-not (Test-Path -LiteralPath $directory)) { [void](New-Item -ItemType Directory -Path $directory -Force) }
        [IO.File]::AppendAllText($script:LogPath, ('[{0}] [{1}] {2}{3}' -f $stamp, $Level, $Text, [Environment]::NewLine))
    }
    catch { $null = $_ }
}
function Publish-WacCampaignValue {
    param([Parameter(Mandatory = $true)][string]$Name, [AllowEmptyString()][string]$Value = '')
    if (-not (Test-Path -LiteralPath $script:KvpKey)) { [void](New-Item -Path $script:KvpKey -Force) }
    Set-ItemProperty -LiteralPath $script:KvpKey -Name ($script:Prefix + $Name) -Value $Value -Type String -Force
}
function Publish-WacCampaignFault {
    param([Parameter(Mandatory = $true)][string]$Reason)
    Write-WacCampaignAgentLog -Level ERROR -Text $Reason
    try {
        $text = ([IO.File]::ReadAllText($script:LogPath) -replace '\s+', ' ').Trim()
        $tail = if ($text.Length -le 700) { $text } else { '...' + $text.Substring($text.Length - 700) }
        Publish-WacCampaignValue -Name 'AgentFault' -Value $Reason
        Publish-WacCampaignValue -Name 'AgentLog' -Value $tail
        Publish-WacCampaignValue -Name 'Status' -Value 'failed'
    }
    catch { $null = $_ }
}
function Publish-WacCampaignReport {
    param([Parameter(Mandatory = $true)][string]$Json)
    $parts = [Math]::Max(1, [int][Math]::Ceiling($Json.Length / [double]$script:Chunk))
    Publish-WacCampaignValue -Name 'ReportParts' -Value '0'
    for ($i = 0; $i -lt $parts; $i++) {
        $start = $i * $script:Chunk
        Publish-WacCampaignValue -Name ('Report.{0}' -f $i) -Value $Json.Substring($start, [Math]::Min($script:Chunk, $Json.Length - $start))
    }
    Publish-WacCampaignValue -Name 'ReportParts' -Value ([string]$parts)
}
function Reset-WacCampaignMachine {
    param([Parameter(Mandatory = $true)][string]$ProjectRoot)
    $before = Get-WacCampaignMachine
    if (-not $before.Known) { return [PSCustomObject]@{ Clean = $false; Attempted = $false; Detail = 'The baseline inventory is unreadable.' } }
    if ($before.Clean) { return [PSCustomObject]@{ Clean = $true; Attempted = $false; Detail = 'already clean' } }
    $ran = Invoke-WacCampaignHost -ScriptPath (Join-Path $ProjectRoot 'Uninstall-WindowsAutoCleanupTask.ps1') -ArgumentList @('-NoPause')
    $after = Get-WacCampaignMachine
    return [PSCustomObject]@{ Clean = ($ran.ExitCode -eq 0 -and $after.Clean); Attempted = $true
        Detail = ('uninstaller exit={0}; independently clean={1}' -f $ran.ExitCode, $after.Clean) }
}
function Set-WacCampaignDurableArming {
    <# Preserve the owner's legacy startup entry while upgrading to the verified durable task. #>
    param([string]$RegistrationScript = (Join-Path $PSScriptRoot 'Register-WacCampaignAgent.ps1'),
        [string]$AgentSource = (Join-Path $PSScriptRoot 'WacCampaignAgent.ps1'))
    $existing = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $_.TaskPath -ieq '\WindowsAutoCleanupCampaign\' -and $_.TaskName -ieq 'CampaignAgent'
    })
    $wasRegistered = $false
    if ($existing.Count -eq 0) {
        # The owner-started guest agent may install its existing dedicated registration helper.
        # Call the script with typed parameters; never rewrite or delete shared startup policy.
        $global:LASTEXITCODE = 0
        & $RegistrationScript -Root $Root -AgentPath $AgentSource
        if ($LASTEXITCODE -ne 0) { throw 'Durable campaign registration failed.' }
        $existing = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.TaskPath -ieq '\WindowsAutoCleanupCampaign\' -and $_.TaskName -ieq 'CampaignAgent'
        })
        $wasRegistered = $true
    }
    if ($existing.Count -ne 1) { throw 'Exactly one verified agent registration is required.' }
    $expected = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Root "{1}"' -f
        (Join-Path (Join-Path $Root 'agent') 'WacCampaignAgent.ps1'), $Root.TrimEnd('\')
    if (@($existing[0].Actions).Count -ne 1 -or $existing[0].Actions[0].Arguments -cne $expected -or
        @('SYSTEM', 'S-1-5-18') -inotcontains [string]$existing[0].Principal.UserId) {
        throw 'The registered agent definition is not the explicitly armed definition for this directory.'
    }
    Write-WacCampaignAgentLog -Text 'Durable task verified; legacy startup policy remains untouched.'
    return $(if ($wasRegistered) { 'task-registered' } else { 'task-already-present' })
}
function Expand-WacCampaignProject {
    param([Parameter(Mandatory = $true)][string]$Archive, [Parameter(Mandatory = $true)][string]$Destination)
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction Stop }
    [void](New-Item -ItemType Directory -Path $Destination -Force)
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [IO.Compression.ZipFile]::ExtractToDirectory($Archive, $Destination)
    if (-not (Test-Path -LiteralPath (Join-Path $Destination 'Run.ps1') -PathType Leaf)) { throw 'The archive contains no entry point.' }
    $null = Get-WacCampaignPayloadFingerprint -Directory $Destination -Flush
    return $Destination
}
function Wait-WacCampaignRequest {
    param([Parameter(Mandatory = $true)][string]$Path, [int]$Minutes, [string]$PreviousCampaignId = '')
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalMinutes -lt $Minutes) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            try {
                $request = [IO.File]::ReadAllText($Path) | ConvertFrom-Json -ErrorAction Stop
                if ($null -ne $request -and $request.campaignId -cne $PreviousCampaignId -and
                    -not [string]::IsNullOrWhiteSpace([string]$request.campaignId)) { return $request }
            }
            catch { $null = $_ }
        }
        Start-Sleep -Seconds 1
    }
    return $null
}

$script:AgentMutex = New-Object Threading.Mutex($false, 'Global\WindowsAutoCleanupCampaignAgent')
$admitted = $false
try { $admitted = $script:AgentMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $admitted = $true }
if (-not $admitted) { $script:AgentMutex.Dispose(); exit 0 }
try {
    . (Join-Path $PSScriptRoot 'WacCampaignChecks.ps1')
    $hardware = $null
    $probeWatch = [Diagnostics.Stopwatch]::StartNew()
    do {
        try { $hardware = @(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop) } catch { $hardware = @() }
        if (@($hardware).Count -eq 1) { break }
        Start-Sleep -Seconds 1
    } while ($probeWatch.Elapsed.TotalSeconds -lt 180)
    if (@($hardware).Count -ne 1 -or -not (Test-WacCampaignGuest -Computer $hardware[0])) {
        throw 'Positive supported virtual hardware evidence is required; the agent is not armed here.'
    }
    $script:CampaignChannelAvailable = $true
    Publish-WacCampaignValue -Name 'AgentBoot' -Value ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
    Publish-WacCampaignValue -Name 'AgentFault' -Value ''
    . (Join-Path $PSScriptRoot 'WacCampaignState.ps1')
    . (Join-Path $PSScriptRoot 'WacCampaignScenario.ps1')
    Publish-WacCampaignValue -Name 'AgentArming' -Value (Set-WacCampaignDurableArming)
    $statePath = Join-Path $Root 'state.json'
    $requestPath = Join-Path $Root 'in\request.json'
    $archivePath = Join-Path $Root 'in\project.zip'
    $workRoot = Join-Path $Root 'work'
    Publish-WacCampaignValue -Name 'Await' -Value ''
    Publish-WacCampaignValue -Name 'ActiveCampaign' -Value ''
    Publish-WacCampaignValue -Name 'ActiveScenario' -Value ''
    Publish-WacCampaignValue -Name 'AgentReady' -Value ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
    $previousCampaign = ''
    $state = Get-WacCampaignState -Path $statePath
    if ($null -ne $state -and @('complete', 'failed') -ccontains [string]$state.phase) {
        $previousCampaign = [string]$state.campaignId
        Remove-Item -LiteralPath $statePath -Force -ErrorAction Stop
        $state = $null
    }
    elseif ($null -ne $state -and $state.phase -cne 'awaiting-power-cut') {
        throw 'An unfinished campaign is preserved; restore the approved baseline before another request.'
    }

    if ($null -ne $state -and [string]$state.phase -ceq 'awaiting-power-cut') {
        if (-not (Test-WacCampaignResume -State $state -WorkRoot $workRoot)) {
            throw 'A changed boot and intact staged payload are not proven; no recovery scenario ran.'
        }
        Publish-WacCampaignValue -Name 'ActiveCampaign' -Value $state.campaignId
        Publish-WacCampaignValue -Name 'ActiveScenario' -Value $state.cutStep
        Publish-WacCampaignValue -Name 'Status' -Value 'resuming'
        $result = Invoke-WacCampaignRecoveryCheck -State $state -ProjectRoot $state.projectRoot
        $state.results = @(@($state.results) + $result)
        $state.completed = @(@($state.completed) + [string]$state.cutStep)
        $state.phase = 'running'; $state.cutStep = ''
        Save-WacCampaignState -Path $statePath -State $state
    }
    elseif ($null -eq $state) {
        Publish-WacCampaignValue -Name 'Status' -Value 'waiting'
        $request = Wait-WacCampaignRequest -Path $requestPath -Minutes $WatchMinutes -PreviousCampaignId $previousCampaign
        if ($null -eq $request) { Publish-WacCampaignValue -Name 'Status' -Value 'idle'; exit 0 }
        if ($request.destructiveAuthorized -isnot [bool] -or
            [string]$request.campaignId -notmatch '^[a-fA-F0-9]{32}$' -or
            [string]$request.commit -notmatch '^[a-fA-F0-9]{40}$' -or
            [string]$request.archiveSha256 -notmatch '^[a-fA-F0-9]{64}$' -or
            (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256 -ErrorAction Stop).Hash -ine $request.archiveSha256) {
            throw 'The request authorization or archive identity is invalid.'
        }
        $projectRoot = Join-Path $workRoot ([string]$request.commit).Substring(0, 12)
        $state = [PSCustomObject]@{ schema = 1; campaignId = [string]$request.campaignId; commit = [string]$request.commit
            projectRoot = $projectRoot; scenarios = @($request.scenarios); destructiveAuthorized = $request.destructiveAuthorized
            completed = @(); results = @(); phase = 'running'; cutStep = ''; payloadFingerprint = ''
            startedUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }
        if (-not (Test-WacCampaignStateShape -State $state)) { throw 'Invalid scenario request; no baseline mutation was attempted.' }
        Publish-WacCampaignValue -Name 'ActiveCampaign' -Value $state.campaignId
        Publish-WacCampaignValue -Name 'ActiveScenario' -Value ([string]$state.scenarios[0])
        Publish-WacCampaignValue -Name 'Status' -Value 'preparing'
        [void](Expand-WacCampaignProject -Archive $archivePath -Destination $projectRoot)
        $state.payloadFingerprint = Get-WacCampaignPayloadFingerprint -Directory $projectRoot
        $baseline = Reset-WacCampaignMachine -ProjectRoot $projectRoot
        if (-not $baseline.Clean) {
            Publish-WacCampaignFault -Reason ('The disposable baseline was not restored: ' + $baseline.Detail)
            exit 1
        }
        Save-WacCampaignState -Path $statePath -State $state
    }

    $status = 'complete'
    try {
        foreach ($scenario in @($state.scenarios)) {
            if (@($state.completed) -ccontains $scenario) { continue }
            Publish-WacCampaignValue -Name 'ActiveScenario' -Value $scenario
            Publish-WacCampaignValue -Name 'Status' -Value 'running'
            Publish-WacCampaignValue -Name 'Step' -Value $scenario
            $outcome = Invoke-WacCampaignScenario -Name $scenario -State $state -StatePath $statePath -Save ${function:Save-WacCampaignState}
            if ($outcome.Verdict -ceq 'awaiting-power-cut') {
                if ($state.resumeKind -cne 'reboot') { Publish-WacCampaignValue -Name 'Await' -Value ('power-cut:' + $scenario) }
                # The job owner must survive until the event. Exiting would kill the test before the cut.
                Start-Sleep -Seconds 900
                Close-WacCampaignLaunch -Started $script:CampaignHeldLaunch
                throw 'No requested cut/reboot occurred within the bounded witness lifetime.'
            }
            $state.results = @(@($state.results) + $outcome)
            $state.completed = @(@($state.completed) + $scenario)
            Save-WacCampaignState -Path $statePath -State $state
        }
    }
    catch {
        $status = 'failed'
        $remaining = @($state.scenarios | Where-Object { @($state.completed) -cnotcontains $_ })
        if ($remaining.Count -gt 0) {
            $state.results = @(@($state.results) + [PSCustomObject]@{ Scenario = [string]$remaining[0]; Verdict = 'failed'; Detail = $_.Exception.Message })
            $state.completed = @(@($state.completed) + [string]$remaining[0])
        }
        Write-WacCampaignAgentLog -Level ERROR -Text $_.Exception.Message
    }
    if (@($state.results | Where-Object { $_.Verdict -cne 'passed' }).Count -gt 0) { $status = 'failed' }
    $state.phase = $status
    Save-WacCampaignState -Path $statePath -State $state
    $report = [PSCustomObject]@{ schema = 1; campaignId = $state.campaignId; commit = $state.commit
        startedUtc = $state.startedUtc; finishedUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        requested = @($state.scenarios); notRun = @($state.scenarios | Where-Object { @($state.completed) -cnotcontains $_ })
        results = @($state.results); status = $status }
    Publish-WacCampaignValue -Name 'Await' -Value ''
    Publish-WacCampaignReport -Json (ConvertTo-Json -InputObject $report -Depth 12 -Compress)
    Publish-WacCampaignValue -Name 'Status' -Value $status
    exit $(if ($status -ceq 'complete') { 0 } else { 1 })
}
catch {
    if ($script:CampaignChannelAvailable) { Publish-WacCampaignFault -Reason $_.Exception.Message }
    else { Write-Error $_ -ErrorAction Continue }
    exit 1
}
finally {
    $script:AgentMutex.ReleaseMutex()
    $script:AgentMutex.Dispose()
}
