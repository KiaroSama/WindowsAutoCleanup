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
$script:LogPath = Join-Path -Path $Root -ChildPath 'agent.log'

function Write-WacCampaignAgentLog {
    <#
    .SYNOPSIS
        Appends one line to the guest-side log, and never throws.
    .DESCRIPTION
        It runs before anything in this file is known to work, so it cannot be allowed to become the
        thing that fails. The log survives reboots and power cuts, which is what makes it the record
        of a boot the host could not see - and its tail is published on any fault, because a log
        nobody can retrieve is a log nobody has.
    #>
    param([AllowEmptyString()][string]$Text)

    try {
        $stamp = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        $directory = Split-Path -Parent $script:LogPath
        if (-not (Test-Path -LiteralPath $directory)) { [void](New-Item -ItemType Directory -Path $directory -Force) }
        [System.IO.File]::AppendAllText($script:LogPath, ('[{0}] {1}{2}' -f $stamp, $Text, [Environment]::NewLine))
    }
    catch { $null = $_ }
}

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

# ---------------------------------------------------------------------------------------------
# THE FIRST ACT, before anything else can throw
# ---------------------------------------------------------------------------------------------
#
# The scenario library used to be dot-sourced above, ahead of every publish. Under StrictMode with
# $ErrorActionPreference = 'Stop', a load that fails - "the system cannot find the file specified" is
# what a missing or unreadable file gives - killed the agent having published NOTHING. From the host
# that is indistinguishable from a guest that never booted: a running machine with an empty exchange
# and no way to tell which. A campaign then waits out its whole idle bound learning nothing.
#
# So the beacon goes out first, and the load is guarded and reports its own failure.

try {
    Publish-WacCampaignValue -Name 'AgentBoot' -Value ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
    Publish-WacCampaignValue -Name 'AgentFault' -Value ''
}
catch {
    # No channel at all. The log is the only place left to say so, and the host will report a guest
    # that never reported in - which is exactly what happened.
    Write-WacCampaignAgentLog -Text ('the key-value channel is unavailable: ' + $_.Exception.Message)
    exit 1
}
Write-WacCampaignAgentLog -Text '--- agent started ---'

function Reset-WacCampaignMachine {
    <#
    .SYNOPSIS
        Brings this guest to the baseline a campaign assumes - nothing installed, no records
        outstanding - and PROVES it, or refuses to let the campaign start.
    .DESCRIPTION
        Isolation between SCENARIOS already worked: the host restores its base checkpoint between
        them. Isolation between CAMPAIGNS did not, because that checkpoint is taken at campaign
        START, so whatever the previous campaign left is inside the baseline every scenario is
        returned to. Measured 2026-09-20: a killed run left an outstanding uninstall intent in
        Program Files, and every later `power-loss-during-uninstall` then failed in its prepare
        step - the product correctly refusing to install over residue the campaign had left itself.
        A verdict from that machine is a verdict about the previous campaign.

        The host cannot clean this up: it can deliver files and read what the guest publishes, and
        nothing else. So the guest does it, using the product's OWN uninstaller - the documented way
        to resolve an outstanding intent is to resume it, which is exactly what running the
        uninstaller does - and then verifies the result rather than assuming it.

        Fail-closed by design. The return value is the evidence, not the attempt: if a task, a
        deployment root or a transaction record is still there afterwards, the caller refuses to run
        a campaign at all. A polluted machine that produces verdicts is worse than one that says so.
    #>
    param([Parameter(Mandatory = $true)][string]$ProjectRoot)

    $deploymentRoot = Join-Path -Path $env:ProgramFiles -ChildPath 'WindowsAutoCleanup'
    $records = @('.transaction.json', '.taskcapture.json', '.uninstall.json')

    $describe = {
        $found = @()
        foreach ($suffix in $records) {
            if (Test-Path -LiteralPath ($deploymentRoot + $suffix) -PathType Leaf) { $found += $suffix.Trim('.') }
        }
        $tasks = @(Get-ScheduledTask -TaskPath '\WindowsAutoCleanup\' -ErrorAction SilentlyContinue)
        return [PSCustomObject]@{
            Records = $found
            Tasks = $tasks.Count
            Root = (Test-Path -LiteralPath $deploymentRoot)
            Clean = ($found.Count -eq 0 -and $tasks.Count -eq 0 -and -not (Test-Path -LiteralPath $deploymentRoot))
        }
    }

    $before = & $describe
    if ($before.Clean) {
        Write-WacCampaignAgentLog -Text 'machine baseline: already clean'
        return [PSCustomObject]@{ Clean = $true; Detail = 'already clean'; Attempted = $false }
    }

    Write-WacCampaignAgentLog -Text ('machine baseline: residue found - records=[{0}] tasks={1} root={2}; resuming the uninstaller' -f
        ($before.Records -join ','), $before.Tasks, $before.Root)

    $uninstaller = Join-Path -Path $ProjectRoot -ChildPath 'Uninstall-WindowsAutoCleanupTask.ps1'
    $ran = Invoke-WacCampaignHost -ScriptPath $uninstaller -ArgumentList @('-NoPause')

    $after = & $describe
    $detail = ('before: records=[{0}] tasks={1} root={2} | uninstaller exit={3} | after: records=[{4}] tasks={5} root={6}' -f
        ($before.Records -join ','), $before.Tasks, $before.Root, $ran.ExitCode,
        ($after.Records -join ','), $after.Tasks, $after.Root)

    if ($after.Clean) {
        Write-WacCampaignAgentLog -Text ('machine baseline: restored. ' + $detail)
    }
    else {
        Write-WacCampaignAgentLog -Text ('machine baseline: NOT restored. ' + $detail + ' | it said: ' +
            (Get-WacCampaignTail -Text ([string]$ran.Output)))
    }
    return [PSCustomObject]@{ Clean = $after.Clean; Detail = $detail; Attempted = $true }
}

function Set-WacCampaignDurableArming {
    <#
    .SYNOPSIS
        Makes this guest's arming survive a power cut, by replacing whatever started the agent with
        the scheduled task the arming script registers.
    .DESCRIPTION
        A guest armed from the HOST can only be armed with a local Group Policy machine startup
        script, and that registration lives in the registry where a dirty shutdown can roll it back -
        measured here: `AgentBoot` appears within seconds of every clean boot and never after a cut.
        A scheduled task goes through Task Scheduler's own store instead.

        The agent runs as SYSTEM, so it can register that task itself, which is the same act the
        machine's owner performs with Register-WacCampaignAgent.ps1 - just reached from the one
        place that is already inside the guest.

        The Group Policy script is REMOVED once the task exists, because two start paths would run
        two agents at the next boot, and two agents publishing to one exchange is worse than a
        fragile one.
    #>
    $taskPath = '\WindowsAutoCleanupCampaign\'
    $taskName = 'CampaignAgent'

    try {
        # WAIT FOR WMI FIRST. The agent starts very early in the boot, and both the task query here
        # and the arming script's own hardware check go through it. The first attempt returned
        # "Cannot connect to CIM server. A system shutdown is in progress." and then
        # "task-registration-failed" - the same thing said twice: the service was not ready, and
        # giving up on the first try turned a wait into a failure.
        $cimReady = $false
        $waitUntil = (Get-Date).AddSeconds(180)
        while ((Get-Date) -lt $waitUntil) {
            try {
                if ($null -ne (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop)) { $cimReady = $true; break }
            }
            catch { Start-Sleep -Milliseconds 3000 }
        }
        if (-not $cimReady) {
            Write-WacCampaignAgentLog -Text 'WMI never became available, so durable arming was not even attempted'
            return 'cim-unavailable'
        }
        Write-WacCampaignAgentLog -Text 'WMI is available; checking the scheduled task'

        $existing = @(Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue)
        if ($existing.Count -eq 0) {
            $register = Join-Path -Path $PSScriptRoot -ChildPath 'Register-WacCampaignAgent.ps1'
            if (-not (Test-Path -LiteralPath $register -PathType Leaf)) {
                Write-WacCampaignAgentLog -Text 'the arming script is not beside the agent, so the task was not registered'
                return 'no-arming-script'
            }

            $out = [System.IO.Path]::GetTempFileName()
            $process = Start-Process -FilePath 'powershell.exe' -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput $out -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive',
                    '-ExecutionPolicy', 'Bypass', '-File', $register)
            [void]$process.WaitForExit(120000)
            Write-WacCampaignAgentLog -Text ('the arming script exited ' + [string]$process.ExitCode)

            # What it SAID, carried home. A failure that names only itself is the shape this project
            # keeps closing.
            $said = '(no output)'
            try { $said = ([System.IO.File]::ReadAllText($out) -replace '\s+', ' ').Trim() } catch { $null = $_ }
            if ($said.Length -gt 300) { $said = '...' + $said.Substring($said.Length - 300) }
            Write-WacCampaignAgentLog -Text ('the arming script said: ' + $said)
            try { [System.IO.File]::Delete($out) } catch { $null = $_ }

            $existing = @(Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue)
            if ($existing.Count -eq 0) {
                return ('task-registration-failed: exit {0}; {1}' -f [string]$process.ExitCode, $said)
            }
            $result = 'task-registered'
        }
        else { $result = 'task-already-present' }

        # Only now, with a durable path proven to exist, is the fragile one taken away.
        $gpScripts = Join-Path -Path $env:SystemRoot -ChildPath 'System32\GroupPolicy\Machine\Scripts'
        $bootCmd = Join-Path -Path $gpScripts -ChildPath 'Startup\wac-campaign-boot.cmd'
        if (Test-Path -LiteralPath $bootCmd -PathType Leaf) {
            [System.IO.File]::Delete($bootCmd)
            $ini = Join-Path -Path $gpScripts -ChildPath 'scripts.ini'
            if (Test-Path -LiteralPath $ini -PathType Leaf) { [System.IO.File]::Delete($ini) }
            Write-WacCampaignAgentLog -Text 'the Group Policy startup script was removed; the task is now the only start path'
            $result += '+gp-removed'
        }
        return $result
    }
    catch {
        Write-WacCampaignAgentLog -Text ('durable arming failed: ' + $_.Exception.Message)
        return ('failed: ' + $_.Exception.Message)
    }
}

$arming = Set-WacCampaignDurableArming
try {
    Publish-WacCampaignValue -Name 'AgentArming' -Value $arming

    # The log tail goes out HERE, not only on a fault. Arming is the one step whose failure the host
    # cannot otherwise see at all, and a result string that says only "failed" is what sent this
    # round in circles twice.
    $armingTail = '(no log)'
    try {
        $armingText = [System.IO.File]::ReadAllText($script:LogPath)
        $armingFlat = ($armingText -replace '\s+', ' ').Trim()
        $armingTail = $(if ($armingFlat.Length -le 700) { $armingFlat } else { '...' + $armingFlat.Substring($armingFlat.Length - 700) })
    }
    catch { $null = $_ }
    Publish-WacCampaignValue -Name 'AgentLog' -Value $armingTail
}
catch { $null = $_ }

function Publish-WacCampaignFault {
    <#
    .SYNOPSIS
        Publishes why the agent is stopping, with the tail of its own log behind it.
    .DESCRIPTION
        The tail travels because the host has no credential-bearing way to read a file in here. A
        failure the host can see only as silence is a failure nobody can act on.
    #>
    param([Parameter(Mandatory = $true)][string]$Reason)

    Write-WacCampaignAgentLog -Text ('FAULT: ' + $Reason)
    $tail = ''
    try {
        $text = [System.IO.File]::ReadAllText($script:LogPath)
        $flat = ($text -replace '\s+', ' ').Trim()
        $tail = $(if ($flat.Length -le 700) { $flat } else { '...' + $flat.Substring($flat.Length - 700) })
    }
    catch { $tail = '(the agent log could not be read)' }

    try {
        Publish-WacCampaignValue -Name 'AgentFault' -Value $Reason
        Publish-WacCampaignValue -Name 'AgentLog' -Value $tail
        Publish-WacCampaignValue -Name 'Status' -Value 'failed'
    }
    catch { $null = $_ }
}

try {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'WacCampaignScenario.ps1')
    Write-WacCampaignAgentLog -Text 'scenario library loaded'
}
catch {
    Publish-WacCampaignFault -Reason ('the scenario library did not load: ' + $_.Exception.Message)
    exit 1
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
        Writes the resume point BEFORE the action it describes, and does not return until the bytes
        are on the DEVICE rather than merely in the operating system's write cache.
    .DESCRIPTION
        The previous version said "written and flushed first, every time" and called
        `File::WriteAllText`, which flushes nothing: it returns once Windows has accepted the data
        into its cache, and the cache is exactly what a power cut discards. The comment asserted a
        property the code did not implement, on the one file in this project whose only purpose is
        to survive that cut.

        Measured cost, 2026-09-20: the guest was cut mid-install, came back in twenty seconds, read
        NO resume state and went to "waiting for the host to deliver a request". `ConvertFrom-Json`
        returns $null for an absent or half-written file and the agent cannot tell those apart from
        a first run, so the scenario stopped testing recovery and quietly waited instead - a harness
        that measures crash durability, not being crash durable itself.

        `FileStream.Flush($true)` issues FlushFileBuffers, which is the difference between "Windows
        has the bytes" and "the disk has the bytes".
    #>
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$State)

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { [void](New-Item -ItemType Directory -Path $directory -Force) }

    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((ConvertTo-Json -InputObject $State -Depth 8))
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
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

    # Force the whole tree onto the DEVICE before anything runs against it. `ExtractToDirectory`
    # returns with the files in the operating system's write cache, and the very next thing a
    # power-cut scenario does is cut the power - so the recovery boot runs the product from a
    # half-written copy of itself. Measured on 2026-09-20: the resumed installer died on
    # `src\WindowsAutoCleanup.TrustedStore.ps1:1 char:1` with "the term ' ' is not recognized",
    # which is a file whose first bytes never landed, and the scenario reported that as a product
    # defect. Re-opening each file and flushing is a second or two on a tree this size and it is
    # the difference between testing the product and testing the cache.
    foreach ($file in @(Get-ChildItem -LiteralPath $Destination -Recurse -File -ErrorAction SilentlyContinue)) {
        $stream = $null
        try {
            $stream = [System.IO.File]::Open($file.FullName, [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $stream.Flush($true)
        }
        catch { $null = $_ }
        finally { if ($null -ne $stream) { $stream.Dispose() } }
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
    # The beacon already went out, so the channel worked a moment ago and this is a NEW failure.
    Publish-WacCampaignFault -Reason ('the agent could not announce itself: ' + $_.Exception.Message)
    exit 1
}
Write-WacCampaignAgentLog -Text 'announced; reading the resume state'

$state = Get-WacCampaignState -Path $statePath

# ONLY a run standing at a cut point may be resumed. A state in any other phase is business the
# previous campaign did not finish - it was killed, or it ended - and carrying it into the next
# request makes the guest replay somebody else's plan: measured 2026-09-20, a campaign inherited a
# killed run's `completed` list, skipped the scenario it had been asked for, and filed the OTHER
# scenario's verdict twice under both names. The host cannot clear this file (it can deliver files
# and read what the guest publishes, and nothing else), so the guest has to refuse to inherit it.
if ($null -ne $state -and [string]$state.phase -cne 'awaiting-power-cut') {
    Write-WacCampaignAgentLog -Text ('discarding a stale campaign state: phase=' + [string]$state.phase +
        ' campaign=' + [string]$state.campaignId + '; only a run stopped at a cut point is resumable')
    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    $state = $null
}

if ($null -ne $state -and [string]$state.phase -ceq 'awaiting-power-cut') {
    # THIS IS THE POST-CRASH BOOT. The machine really did lose power between the previous line of
    # this agent and this one, which is the only way to reach here.
    Publish-WacCampaignValue -Name 'Status' -Value 'resuming'
    Publish-WacCampaignValue -Name 'Step' -Value ('verifying recovery after: ' + [string]$state.cutStep)

    Write-WacCampaignAgentLog -Text ('resuming after an interruption at: ' + [string]$state.cutStep)
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

    # A campaign starts from a known machine or it does not start. The host's base checkpoint is
    # taken around whatever is here, so residue left by a previous campaign would otherwise be
    # restored between every scenario as if it were the baseline.
    Publish-WacCampaignValue -Name 'Step' -Value 'returning the machine to a clean baseline'
    $baseline = Reset-WacCampaignMachine -ProjectRoot $projectRoot
    Publish-WacCampaignValue -Name 'Baseline' -Value $(if ($baseline.Clean) { 'clean' } else { 'polluted' })
    if (-not $baseline.Clean) {
        Publish-WacCampaignFault -Reason ('this guest could not be returned to a clean baseline, so no scenario ran: ' + $baseline.Detail)
        exit 1
    }

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

        Write-WacCampaignAgentLog -Text ('starting scenario: ' + $scenario)
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
    Write-WacCampaignAgentLog -Text ('the scenario loop threw: ' + $_.Exception.Message)
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

Write-WacCampaignAgentLog -Text ('--- agent finished: ' + $status + ' ---')
Publish-WacCampaignValue -Name 'Await' -Value ''
Publish-WacCampaignReport -Json (ConvertTo-Json -InputObject $report -Depth 8 -Compress)
if ($status -cne 'complete') {
    # The guest's own account travels with a failure, because the host cannot go and read it.
    try {
        $text = [System.IO.File]::ReadAllText($script:LogPath)
        $flat = ($text -replace '\s+', ' ').Trim()
        Publish-WacCampaignValue -Name 'AgentLog' -Value $(if ($flat.Length -le 700) { $flat } else { '...' + $flat.Substring($flat.Length - 700) })
    }
    catch { $null = $_ }
}
Publish-WacCampaignValue -Name 'Status' -Value $status
exit 0
