#Requires -Version 5.1
<#
.SYNOPSIS
    The guest half of the campaign. Runs INSIDE the disposable virtual machine, as SYSTEM, started
    by the scheduled task its owner armed once.

.DESCRIPTION
    The host cannot start anything in here. This agent is what the guest's owner armed, and it is
    the only thing that runs: it watches one directory for a request the host delivered, performs
    the scenarios, and publishes what happened back to the host over Key-Value Pair Exchange.

    IT MUST SURVIVE ITS OWN MACHINE BEING SWITCHED OFF. The power-loss scenarios work by the agent
    reaching a specific instant, asking the host to cut the power, and then being started again by
    the same scheduled task on the next boot to verify what the interrupted transaction left behind.
    Everything needed to resume therefore lives in a file on disk, written before the cut is
    requested - never in memory, and never inferred afterwards from what happens to be present.

    The distinction this whole project is built on applies here too: a scenario that did not run is
    reported as not run. It never becomes a scenario that passed quietly.

.NOTES
    Arm with Register-WacCampaignAgent (see Tests/Campaign/README.md). Nothing here reads, writes or
    transports a credential.
#>

[CmdletBinding()]
param(
    [string]$Root = 'C:\wac-campaign',
    [ValidateRange(1, 720)][int]$WatchMinutes = 30
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# The guest's own half of the exchange. The integration service publishes anything written here to
# the host; the sibling Parameters key belongs to the service and is left alone.
$script:KvpKey = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest'
$script:Prefix = 'WacCampaign.'
$script:Chunk = 900

. (Join-Path -Path $PSScriptRoot -ChildPath 'WacCampaignScenario.ps1')

function Publish-WacCampaignValue {
    <#
    .SYNOPSIS
        Publishes one value to the host, or reports that it could not.
    .DESCRIPTION
        A failure here is never swallowed: if the guest cannot speak, the host's only correct
        conclusion is that it does not know what happened, and a silent agent produces exactly the
        blocked verdict it should.
    #>
    param([Parameter(Mandatory = $true)][string]$Name, [AllowEmptyString()][string]$Value = '')

    if (-not (Test-Path -LiteralPath $script:KvpKey)) {
        [void](New-Item -Path $script:KvpKey -Force)
    }
    Set-ItemProperty -LiteralPath $script:KvpKey -Name ($script:Prefix + $Name) -Value $Value -Type String -Force
}

function Publish-WacCampaignReport {
    <#
    .SYNOPSIS
        Publishes a report of any length, in numbered parts, with the count written LAST.
    .DESCRIPTION
        The count is written last on purpose: the host treats a report as whole only when the count
        is present AND every numbered part it names has arrived. Writing it first would let the host
        read a report that was still being written as a complete short one.
    #>
    param([Parameter(Mandatory = $true)][string]$Json)

    $parts = [Math]::Max(1, [int][Math]::Ceiling($Json.Length / [double]$script:Chunk))
    for ($i = 0; $i -lt $parts; $i++) {
        $start = $i * $script:Chunk
        $length = [Math]::Min($script:Chunk, $Json.Length - $start)
        Publish-WacCampaignValue -Name ('Report.{0}' -f $i) -Value $Json.Substring($start, $length)
    }
    Publish-WacCampaignValue -Name 'ReportParts' -Value ([string]$parts)
}

function Get-WacCampaignState {
    <#
    .SYNOPSIS
        What a previous boot of this agent left behind, or $null on a first run.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }

    $state = $null
    try { $state = [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json }
    catch { return $null }
    if ($null -eq $state) { return $null }

    # ConvertFrom-Json gives back a SCALAR for a one-element array and $null for an empty one, and
    # this state is written and read across a power cut, so every list here has been both at some
    # point. Normalising on the way in keeps `-ccontains` and `+` meaning what they look like.
    foreach ($list in @('scenarios', 'completed', 'results')) {
        $current = @()
        if (@($state.PSObject.Properties.Name) -ccontains $list -and $null -ne $state.$list) {
            $current = @($state.$list)
        }
        $state | Add-Member -NotePropertyName $list -NotePropertyValue $current -Force
    }
    return $state
}

function Save-WacCampaignState {
    <#
    .SYNOPSIS
        Writes the resume point to disk BEFORE the action it describes.
    .DESCRIPTION
        Written and flushed first, every time. A state file written after the thing it records is a
        state file that does not exist when the power goes - which is the only moment it is for.
    #>
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$State)

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { [void](New-Item -ItemType Directory -Path $directory -Force) }
    [System.IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $State -Depth 8),
        (New-Object System.Text.UTF8Encoding($false)))
}

function Expand-WacCampaignProject {
    <#
    .SYNOPSIS
        Unpacks the delivered project package into its own directory, named for the commit.
    #>
    param([Parameter(Mandatory = $true)][string]$Archive, [Parameter(Mandatory = $true)][string]$Destination)

    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    [void](New-Item -ItemType Directory -Path $Destination -Force)

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    [System.IO.Compression.ZipFile]::ExtractToDirectory($Archive, $Destination)

    $run = Join-Path -Path $Destination -ChildPath 'Run.ps1'
    if (-not (Test-Path -LiteralPath $run -PathType Leaf)) {
        throw ('The delivered package does not contain Run.ps1 at {0}.' -f $run)
    }
    return $Destination
}

function Wait-WacCampaignRequest {
    <#
    .SYNOPSIS
        The request the host delivered, or $null when none arrives inside the watch window.
    .DESCRIPTION
        Bounded. An agent that waited for ever would keep a disposable guest busy until somebody
        noticed, and "no request arrived" is a perfectly good thing for it to conclude and stop on.
    #>
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][int]$Minutes)

    $deadline = (Get-Date).AddMinutes($Minutes)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            # Written by Copy-VMFile, which is not atomic from in here: a file that is present but
            # not yet complete parses as nothing, so a failed parse means "wait", not "malformed".
            try {
                $request = [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json
                if ($null -ne $request -and -not [string]::IsNullOrWhiteSpace([string]$request.campaignId)) {
                    return $request
                }
            }
            catch {
                # Present but not yet whole. Waiting is the correct response; treating a failed parse
                # as a malformed request would abandon a campaign over a file still being written.
                Start-Sleep -Milliseconds 200
            }
        }
        Start-Sleep -Seconds 3
    }
    return $null
}

# ---------------------------------------------------------------------------------------------
# The agent
# ---------------------------------------------------------------------------------------------

$statePath = Join-Path -Path $Root -ChildPath 'state.json'
$requestPath = Join-Path -Path $Root -ChildPath 'in\request.json'
$archivePath = Join-Path -Path $Root -ChildPath 'in\project.zip'
$workRoot = Join-Path -Path $Root -ChildPath 'work'

try {
    Publish-WacCampaignValue -Name 'AgentReady' -Value ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
    Publish-WacCampaignValue -Name 'Await' -Value ''
}
catch {
    # No channel, no campaign. Exiting is correct: the host will report a guest that never reported
    # in, which is exactly what happened.
    exit 1
}

$state = Get-WacCampaignState -Path $statePath

if ($null -ne $state -and [string]$state.phase -ceq 'awaiting-power-cut') {
    # THIS IS THE POST-CRASH BOOT. The machine really did lose power between the previous line of
    # this agent and this one, which is the only way to reach here.
    Publish-WacCampaignValue -Name 'Status' -Value 'resuming'
    Publish-WacCampaignValue -Name 'Step' -Value ('verifying recovery after: ' + [string]$state.cutStep)

    $result = Invoke-WacCampaignRecoveryCheck -State $state -ProjectRoot ([string]$state.projectRoot)

    # THE SCENARIO IS NOW FINISHED. Recording only its result and not its completion is what made the
    # first armed run loop: the scenario loop below skips what `completed` names, so an interrupted
    # scenario that was never named there was interrupted again, for ever.
    $state.results = @(@($state.results) + $result)
    $state.completed = @(@($state.completed) + [string]$state.cutStep)
    $state.phase = 'running'
    $state.cutStep = ''
    Save-WacCampaignState -Path $statePath -State $state
}
elseif ($null -eq $state) {
    Publish-WacCampaignValue -Name 'Status' -Value 'waiting'
    Publish-WacCampaignValue -Name 'Step' -Value 'waiting for the host to deliver a request'

    $request = Wait-WacCampaignRequest -Path $requestPath -Minutes $WatchMinutes
    if ($null -eq $request) {
        Publish-WacCampaignValue -Name 'Status' -Value 'idle'
        exit 0
    }

    Publish-WacCampaignValue -Name 'Status' -Value 'preparing'
    Publish-WacCampaignValue -Name 'Step' -Value ('unpacking the project at commit ' + [string]$request.commit)

    $projectRoot = Expand-WacCampaignProject -Archive $archivePath `
        -Destination (Join-Path -Path $workRoot -ChildPath ([string]$request.commit).Substring(0, 12))

    $state = [PSCustomObject]@{
        campaignId = [string]$request.campaignId
        commit = [string]$request.commit
        projectRoot = $projectRoot
        scenarios = @($request.scenarios)
        destructiveAuthorized = [bool]$request.destructiveAuthorized
        completed = @()
        results = @()
        phase = 'running'
        cutStep = ''
        startedUtc = ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
    }
    Save-WacCampaignState -Path $statePath -State $state
}

# From here the loop is the same on a first boot and on a post-crash one: take the next scenario the
# state file says is not finished. Nothing is inferred from what the machine looks like.
$status = 'complete'
try {
    foreach ($scenario in @($state.scenarios)) {
        if (@($state.completed) -ccontains $scenario) { continue }

        Publish-WacCampaignValue -Name 'Status' -Value 'running'
        Publish-WacCampaignValue -Name 'Step' -Value $scenario

        $outcome = Invoke-WacCampaignScenario -Name $scenario -State $state -StatePath $statePath `
            -Save ${function:Save-WacCampaignState}

        if ([string]$outcome.Verdict -ceq 'awaiting-power-cut') {
            # The state file already names the resume point; the agent now stops existing. The host
            # cuts the power and starts the machine, and the scheduled task runs this file again.
            Publish-WacCampaignValue -Name 'Await' -Value ('power-cut:' + $scenario)
            exit 0
        }

        $state.results = @(@($state.results) + $outcome)
        $state.completed = @(@($state.completed) + $scenario)
        Save-WacCampaignState -Path $statePath -State $state

        if ([string]$outcome.Verdict -ceq 'failed') { $status = 'failed' }
    }
}
catch {
    # The SCENARIO, not the phase. Labelling the failure `running` - which is what `phase` holds
    # while the loop is working - produced a report whose first line named a scenario that does not
    # exist and left the real one in `notRun`, so the reader had to guess which one died.
    $status = 'failed'
    $failed = @(@($state.scenarios) | Where-Object { @($state.completed) -cnotcontains $_ })
    $state.results = @(@($state.results) + [PSCustomObject]@{
            Scenario = [string]$(if ($failed.Count -gt 0) { $failed[0] } else { 'the agent itself' })
            Verdict = 'failed'
            Detail = ('the agent stopped on an error: ' + $_.Exception.Message) })
    if ($failed.Count -gt 0) { $state.completed = @(@($state.completed) + [string]$failed[0]) }
}

$report = [PSCustomObject]@{
    schema = 1
    campaignId = [string]$state.campaignId
    commit = [string]$state.commit
    startedUtc = [string]$state.startedUtc
    finishedUtc = ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
    requested = @($state.scenarios)
    # Named separately so a reader never has to subtract one list from another to find out what did
    # not happen. A scenario missing from `results` is not a scenario that passed.
    notRun = @(@($state.scenarios) | Where-Object { @($state.completed) -cnotcontains $_ })
    results = @($state.results)
    status = $status
}

Publish-WacCampaignValue -Name 'Await' -Value ''
Publish-WacCampaignReport -Json (ConvertTo-Json -InputObject $report -Depth 8 -Compress)
Publish-WacCampaignValue -Name 'Status' -Value $status
exit 0
