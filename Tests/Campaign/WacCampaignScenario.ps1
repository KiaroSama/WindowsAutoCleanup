<#
.SYNOPSIS
    Explicitly authorized disposable-guest scenarios with independently verified postconditions.
.DESCRIPTION
    Loading this library performs no cleanup. A scenario returns passed, failed or awaiting-power-cut.
    Process completion, fresh operation evidence, and task/file coherence are separate requirements.
#>
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'WacCampaignChecks.ps1')

function Get-WacCampaignSummary {
    param([string[]]$Directory = @("$env:ProgramData\WindowsAutoCleanup\Logs", "$env:SystemRoot\Logs\WindowsAutoCleanup"))
    $found = @()
    foreach ($candidate in $Directory) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { continue }
        $found += @(Get-ChildItem -LiteralPath $candidate -Filter '*.summary.json' -File -ErrorAction Stop)
    }
    if ($found.Count -eq 0) { return $null }
    $newest = @($found | Sort-Object LastWriteTimeUtc -Descending)[0]
    try {
        $summary = [IO.File]::ReadAllText($newest.FullName) | ConvertFrom-Json -ErrorAction Stop
        if (Test-WacCampaignSummaryShape -Summary $summary) { return $summary }
        return $null
    }
    catch { return $null }
}

function Get-WacCampaignTail {
    param([AllowEmptyString()][AllowNull()][string]$Text, [int]$Max = 600)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '(it printed nothing)' }
    $flat = ($Text -replace '[\r\n\t ]+', ' ').Trim()
    if ($flat.Length -le $Max) { return $flat }
    return ('...' + $flat.Substring($flat.Length - $Max))
}

function Wait-WacCampaignFile {
    param([Parameter(Mandatory = $true)][string[]]$Path, [int]$TimeoutSeconds = 180)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        foreach ($candidate in $Path) {
            if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) { return $true }
        }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

function Suspend-WacCampaignTree {
    <# Freeze only the identified root and verified descendants; unwind partial holds. #>
    param([Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][datetime]$ExpectedCreatedUtc,
        [Parameter(Mandatory = $true)][IntPtr]$Job)
    if (-not ('WacCampaign.Hold' -as [type])) {
        Add-Type -Namespace WacCampaign -Name Hold -MemberDefinition @'
[DllImport("ntdll.dll")]
public static extern int NtSuspendProcess(System.IntPtr processHandle);
[DllImport("ntdll.dll")]
public static extern int NtResumeProcess(System.IntPtr processHandle);
[DllImport("kernel32.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool IsProcessInJob(System.IntPtr processHandle, System.IntPtr jobHandle,
    [MarshalAs(UnmanagedType.Bool)] out bool belongs);
'@
    }
    if ($Job -eq [IntPtr]::Zero) { throw 'A campaign hold requires the owned job identity.' }
    $held = New-Object 'Collections.Generic.List[object]'
    $queue = New-Object 'Collections.Generic.Queue[object]'
    $seen = @{}
    $queue.Enqueue([PSCustomObject]@{ Id = $ProcessId; Born = $ExpectedCreatedUtc; Exact = $true })
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        while ($queue.Count -gt 0) {
            if ($watch.Elapsed.TotalSeconds -ge 20 -or $held.Count -ge 256) { throw 'The bounded hold limit was reached.' }
            $next = $queue.Dequeue()
            if ($seen.ContainsKey([int]$next.Id)) { continue }
            $process = [Diagnostics.Process]::GetProcessById($next.Id)
            try {
                $born = $process.StartTime.ToUniversalTime()
                $belongs = $false
                if (-not [WacCampaign.Hold]::IsProcessInJob($process.Handle, $Job, [ref]$belongs)) { throw 'Cannot verify owned job membership.' }
                if (-not $belongs) {
                    if ($next.Exact) { throw 'The root no longer belongs to the owned job.' }
                    # An OS-created auxiliary child may not belong to this job; never suspend it.
                    $process.Dispose()
                    continue
                }
                if (($next.Exact -and $born -ne $next.Born) -or
                    (-not $next.Exact -and [Math]::Abs(($born - $next.Born).TotalMilliseconds) -gt 1)) { throw 'A process identity changed.' }
                if ([WacCampaign.Hold]::NtSuspendProcess($process.Handle) -ne 0) { throw 'A process could not be held.' }
            }
            catch { $process.Dispose(); throw }
            [void]$held.Add($process)
            $seen[[int]$process.Id] = $true
            # A held parent cannot spawn after this query. Traverse recursively, not twice at root.
            foreach ($child in @(Get-CimInstance Win32_Process -Filter ('ParentProcessId={0}' -f $process.Id) -ErrorAction Stop)) {
                $queue.Enqueue([PSCustomObject]@{ Id = [int]$child.ProcessId; Born = $child.CreationDate.ToUniversalTime(); Exact = $false })
            }
        }
        if ([WacOwnedProcess]::ActiveProcessesInJob($Job) -ne $held.Count) { throw 'An owned job member was not held; no cut is authorized.' }
        return [PSCustomObject]@{ RootHeld = $true; Processes = @($held.ToArray()); Detail = ('held ' + $held.Count + ' identified processes') }
    }
    catch {
        $reason = $_.Exception.Message
        foreach ($process in @($held.ToArray())) {
            try { [void][WacCampaign.Hold]::NtResumeProcess($process.Handle) } finally { $process.Dispose() }
        }
        return [PSCustomObject]@{ RootHeld = $false; Processes = @(); Detail = $reason }
    }
}

function Invoke-WacCampaignHost {
    <# A transparent fixed adapter, with typed booleans, uses the existing owned-process runner. #>
    param([Parameter(Mandatory = $true)][string]$ScriptPath, [string[]]$ArgumentList = @(),
        [ValidateRange(1, 3600)][int]$TimeoutSeconds = 2400, [switch]$PassThruProcess)
    $core = Join-Path (Split-Path -Parent $ScriptPath) 'src\WindowsAutoCleanup.Core.psm1'
    if (-not (Test-Path -LiteralPath $core -PathType Leaf)) {
        $core = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\WindowsAutoCleanup.Core.psm1'
    }
    Import-Module $core -DisableNameChecking -ErrorAction Stop
    $map = @{ NoPause = 'NoPauseValue'; ResetWindowsUpdateBase = 'ResetValue'
        PruneSupersededDrivers = 'PruneValue'; Scheduled = 'ScheduledValue' }
    $seen = @{}
    $argv = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File',
        (Join-Path $PSScriptRoot 'Invoke-WacCampaignScript.ps1'), '-ScriptPath', [IO.Path]::GetFullPath($ScriptPath))
    foreach ($argument in $ArgumentList) {
        if ($argument -notmatch '^-(NoPause|ResetWindowsUpdateBase|PruneSupersededDrivers|Scheduled)(?::\$?(true|false))?$') {
            throw 'Only the four documented campaign switches are accepted.'
        }
        $name = $Matches[1]
        if ($seen.ContainsKey($name)) { throw ('Duplicate campaign switch: ' + $name) }
        $seen[$name] = $true
        $value = if ($Matches.ContainsKey(2) -and $Matches[2] -ieq 'false') { '0' } else { '1' }
        $argv += ('-' + $map[$name])
        $argv += [string]$value
    }
    $exe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ([IO.Path]::GetFileName($exe) -notmatch '^(powershell|pwsh)\.exe$') {
        $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    if (-not $PassThruProcess) {
        $ran = Invoke-WacProcess -FilePath $exe -ArgumentList $argv -TimeoutMs ($TimeoutSeconds * 1000)
        $settled = $ran.Started -and -not $ran.TimedOut -and $ran.TerminationProven -and $ran.OutputComplete -and
            $null -ne $ran.ExitCode -and $ran.Owned -and $ran.OwnedTreeState -ceq 'Complete'
        return [PSCustomObject]@{ ExitCode = $(if ($settled) { [int]$ran.ExitCode } else { -1 })
            Output = ([string]$ran.StandardOutput + [string]$ran.StandardError); Settled = $settled }
    }
    $tick = [Diagnostics.Stopwatch]::GetTimestamp() + [long]($TimeoutSeconds * [Diagnostics.Stopwatch]::Frequency)
    $launch = Start-WacOwnedProcess -FilePath $exe -ArgumentList $argv -DeadlineTick $tick
    if ($null -eq $launch) { throw 'The campaign requires an owned launch; no fallback was started.' }
    if (-not $launch.Owned -or $launch.State -cne 'Resumed' -or $launch.Failure) {
        try {
            if ($launch.Owned) { [void][WacOwnedProcess]::TerminateJob($launch.Job) }
            else { [void](Stop-WacProcessTree -ProcessId $launch.ProcessId -TimeoutMs 5000) }
        }
        finally { [WacOwnedProcess]::Close($launch) }
        throw 'The campaign could not establish launch ownership.'
    }
    $process = $null; $outReader = $null; $errReader = $null
    try {
        $process = [Diagnostics.Process]::GetProcessById($launch.ProcessId)
        $null = $process.Handle
        $outReader = New-Object IO.StreamReader($launch.StandardOutput, [Text.Encoding]::UTF8)
        $errReader = New-Object IO.StreamReader($launch.StandardError, [Text.Encoding]::UTF8)
        return [PSCustomObject]@{ Process = $process; Launch = $launch; OutReader = $outReader; ErrReader = $errReader
            OutTask = $outReader.ReadToEndAsync(); ErrTask = $errReader.ReadToEndAsync(); ExitCode = $null; Output = '' }
    }
    catch {
        [void][WacOwnedProcess]::TerminateJob($launch.Job)
        [WacOwnedProcess]::Close($launch)
        if ($process) { $process.Dispose() }
        if ($outReader) { $outReader.Dispose() }; if ($errReader) { $errReader.Dispose() }
        throw
    }
}

function Close-WacCampaignLaunch {
    param([Parameter(Mandatory = $true)]$Started)
    try {
        [void][WacOwnedProcess]::TerminateJob($Started.Launch.Job)
        $watch = [Diagnostics.Stopwatch]::StartNew()
        do {
            $active = [WacOwnedProcess]::ActiveProcessesInJob($Started.Launch.Job)
            if ($active -eq 0) { break }
            Start-Sleep -Milliseconds 50
        } while ($watch.ElapsedMilliseconds -lt 5000)
        if ($active -ne 0 -or -not [WacOwnedProcess]::WaitForExit($Started.Launch.Process, 0)) {
            throw 'The failed campaign launch did not prove whole-job termination.'
        }
    }
    finally {
        [WacOwnedProcess]::Close($Started.Launch)
        $Started.Process.Dispose()
        $Started.OutReader.Dispose(); $Started.ErrReader.Dispose()
    }
}

function Invoke-WacCampaignMaintenance {
    <# Require a fresh scheduler invocation, its own summary and positively successful teardown. #>
    param([Parameter(Mandatory = $true)][string]$ProjectRoot, [ValidateRange(1, 2700)][int]$TimeoutSeconds = 2700)
    $scenario = 'service-dispatched-maintenance'
    $install = Invoke-WacCampaignHost -ScriptPath (Join-Path $ProjectRoot 'Install-WindowsAutoCleanupTask.ps1') `
        -ArgumentList @('-NoPause', '-ResetWindowsUpdateBase:$false')
    if ($install.ExitCode -ne 0) {
        return [PSCustomObject]@{ Scenario = $scenario; Verdict = 'failed'; Detail = ('installer exit=' + $install.ExitCode) }
    }
    $machine = Get-WacCampaignMachine -ProjectRoot $ProjectRoot -Installed
    if (-not $machine.SafeMaintenance) {
        return [PSCustomObject]@{ Scenario = $scenario; Verdict = 'failed'; Detail = 'The registered task and safe maintenance policy were not proven.' }
    }
    $task = $machine.Tasks[0]
    $before = Get-WacCampaignSummary
    $beforeId = if ($null -eq $before) { '' } else { [string]$before.executionId }
    $old = Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop
    $started = [datetime]::UtcNow
    $watch = [Diagnostics.Stopwatch]::StartNew()
    Start-ScheduledTask -InputObject $task -ErrorAction Stop
    $complete = $false; $info = $null; $after = $null
    while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $current = Get-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -ErrorAction Stop
        $info = Get-ScheduledTaskInfo -InputObject $current -ErrorAction Stop
        if ($current.State -ceq 'Ready' -and $info.LastRunTime -gt $old.LastRunTime -and
            $info.LastRunTime.ToUniversalTime() -ge $started.AddSeconds(-1)) {
            $after = Get-WacCampaignSummary
            if (Test-WacCampaignRunEvidence -Summary $after -PreviousId $beforeId -StartedUtc $started -ObservedExit ([int]$info.LastTaskResult)) {
                $complete = $true; break
            }
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $complete) {
        # Never tear down a possibly active installation after an unproven completion.
        return [PSCustomObject]@{ Scenario = $scenario; Verdict = 'failed'; Detail = 'No fresh successful scheduler/summary pair completed within the deadline.' }
    }
    $uninstall = Invoke-WacCampaignHost -ScriptPath (Join-Path $ProjectRoot 'Uninstall-WindowsAutoCleanupTask.ps1') -ArgumentList @('-NoPause')
    $clean = Get-WacCampaignMachine
    $ok = $uninstall.ExitCode -eq 0 -and $clean.Clean
    return [PSCustomObject]@{ Scenario = $scenario; Verdict = $(if ($ok) { 'passed' } else { 'failed' })
        Detail = ('executionId={0} taskExit={1} uninstallExit={2} clean={3}' -f $after.executionId, $info.LastTaskResult, $uninstall.ExitCode, $clean.Clean) }
}

function Start-WacCampaignInterruption {
    <# A cut needs an owned root, the complete owned tree held and records reread while held. #>
    param([Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][string]$ScriptPath, [string[]]$ArgumentList = @(),
        [Parameter(Mandatory = $true)][string[]]$RecordPath,
        [Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)][scriptblock]$Save, [string]$ResumeKind = 'power-cut')
    $started = Invoke-WacCampaignHost -ScriptPath $ScriptPath -ArgumentList $ArgumentList -PassThruProcess
    $armed = $false; $held = $null
    try {
        if (-not (Wait-WacCampaignFile -Path $RecordPath -TimeoutSeconds 240)) { throw 'No transaction record was observed.' }
        $held = Suspend-WacCampaignTree -ProcessId $started.Process.Id -ExpectedCreatedUtc $started.Process.StartTime.ToUniversalTime() -Job $started.Launch.Job
        $tree = Get-WacOwnedTreeState -Launch $started.Launch
        if (-not $held.RootHeld -or $tree.State -cne 'Alive' -or
            $tree.ActiveProcesses -ne @($held.Processes).Count) { throw 'The complete owned tree was not proven held.' }
        $records = @{}
        foreach ($path in $RecordPath) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            $text = [IO.File]::ReadAllText($path)
            $record = $text | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $record) { throw 'The transaction record is not valid JSON.' }
            $records[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
        }
        if ($records.Count -eq 0) { throw 'The transaction finished before the root was held.' }
        $uptime = Get-WacMachineUptimeMs
        if ($null -eq $uptime) { throw 'Monotonic restart evidence is unavailable.' }
        $State.phase = 'awaiting-power-cut'
        $State.cutStep = $Scenario
        $State | Add-Member -NotePropertyName resumeKind -NotePropertyValue $ResumeKind -Force
        $State | Add-Member -NotePropertyName cutUptimeMs -NotePropertyValue ([long]$uptime) -Force
        $State | Add-Member -NotePropertyName cutRecords -NotePropertyValue $records -Force
        & $Save -Path $StatePath -State $State
        # Service-dispatched work is not silently described as frozen by a descendant hold.
        foreach ($path in $records.Keys) {
            if ((Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash -cne $records[$path]) { throw 'The transaction record moved during capture.' }
        }
        $script:CampaignHeldLaunch = $started
        $armed = $true
        if ($ResumeKind -ceq 'reboot') { Restart-Computer -Force -ErrorAction Stop }
        return [PSCustomObject]@{ Scenario = $Scenario; Verdict = 'awaiting-power-cut'; Detail = $held.Detail }
    }
    catch {
        $armed = $false
        return [PSCustomObject]@{ Scenario = $Scenario; Verdict = 'failed'; Detail = $_.Exception.Message }
    }
    finally {
        if ($null -ne $held) { foreach ($process in @($held.Processes)) { $process.Dispose() } }
        if (-not $armed) { Close-WacCampaignLaunch -Started $started }
    }
}

function Invoke-WacCampaignRecoveryCheck {
    <# Exit zero alone is not task/file coherence. Read postconditions independently. #>
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)][string]$ProjectRoot)
    $scenario = [string]$State.cutStep
    if ($scenario -ceq 'power-loss-during-uninstall') {
        $premature = Invoke-WacCampaignHost -ScriptPath (Join-Path $ProjectRoot 'Install-WindowsAutoCleanupTask.ps1') `
            -ArgumentList @('-NoPause', '-ResetWindowsUpdateBase:$false')
        $refused = $premature.ExitCode -ne 0 -and $premature.Output -match '(?i)record|intent|\.json'
        $finish = Invoke-WacCampaignHost -ScriptPath (Join-Path $ProjectRoot 'Uninstall-WindowsAutoCleanupTask.ps1') -ArgumentList @('-NoPause')
        $machine = Get-WacCampaignMachine
        $ok = $refused -and $finish.ExitCode -eq 0 -and $machine.Clean
    }
    else {
        $finish = Invoke-WacCampaignHost -ScriptPath (Join-Path $ProjectRoot 'Install-WindowsAutoCleanupTask.ps1') `
            -ArgumentList @('-NoPause', '-ResetWindowsUpdateBase:$false')
        $machine = Get-WacCampaignMachine -ProjectRoot $ProjectRoot -Installed
        $ok = $finish.ExitCode -eq 0 -and $machine.Coherent -and $machine.SafeMaintenance
    }
    return [PSCustomObject]@{ Scenario = $scenario; Verdict = $(if ($ok) { 'passed' } else { 'failed' })
        Detail = ('recoveryExit={0} known={1} clean={2} coherent={3}' -f $finish.ExitCode, $machine.Known, $machine.Clean, $machine.Coherent) }
}

function Invoke-WacCampaignScenario {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$StatePath, [Parameter(Mandatory = $true)][scriptblock]$Save)
    $projectRoot = [string]$State.projectRoot
    $installer = Join-Path $projectRoot 'Install-WindowsAutoCleanupTask.ps1'
    $uninstaller = Join-Path $projectRoot 'Uninstall-WindowsAutoCleanupTask.ps1'
    $run = Join-Path $projectRoot 'Run.ps1'
    $deploymentRoot = Join-Path $env:ProgramFiles 'WindowsAutoCleanup'
    $swapRecord = $deploymentRoot + '.transaction.json'
    $captureRecord = $deploymentRoot + '.taskcapture.json'
    $uninstallRecord = $deploymentRoot + '.uninstall.json'
    if (@('driver-prune', 'reset-base') -ccontains $Name -and ($State.destructiveAuthorized -isnot [bool] -or -not $State.destructiveAuthorized)) {
        return [PSCustomObject]@{ Scenario = $Name; Verdict = 'failed'; Detail = 'The destructive scenario was not authorized.' }
    }
    switch ($Name) {
        'service-dispatched-maintenance' { return (Invoke-WacCampaignMaintenance -ProjectRoot $projectRoot) }
        'power-loss-during-install' {
            return (Start-WacCampaignInterruption -Scenario $Name -ScriptPath $installer -ArgumentList @('-NoPause', '-ResetWindowsUpdateBase:$false') `
                -RecordPath @($swapRecord, $captureRecord) -State $State -StatePath $StatePath -Save $Save)
        }
        'power-loss-during-uninstall' {
            $prepare = Invoke-WacCampaignHost -ScriptPath $installer -ArgumentList @('-NoPause', '-ResetWindowsUpdateBase:$false')
            if ($prepare.ExitCode -ne 0) {
                return [PSCustomObject]@{ Scenario = $Name; Verdict = 'failed'; Detail = ('installer exit=' + $prepare.ExitCode) }
            }
            return (Start-WacCampaignInterruption -Scenario $Name -ScriptPath $uninstaller -ArgumentList @('-NoPause') `
                -RecordPath @($uninstallRecord) -State $State -StatePath $StatePath -Save $Save)
        }
        'reboot-recovery' {
            $prepare = Invoke-WacCampaignHost -ScriptPath $installer -ArgumentList @('-NoPause', '-ResetWindowsUpdateBase:$false')
            if ($prepare.ExitCode -ne 0) {
                return [PSCustomObject]@{ Scenario = $Name; Verdict = 'failed'; Detail = ('installer exit=' + $prepare.ExitCode) }
            }
            return (Start-WacCampaignInterruption -Scenario $Name -ScriptPath $installer -ArgumentList @('-NoPause', '-ResetWindowsUpdateBase:$false') `
                -RecordPath @($swapRecord, $captureRecord) -State $State -StatePath $StatePath -Save $Save -ResumeKind 'reboot')
        }
        'driver-prune' {
            $previous = Get-WacCampaignSummary
            $previousId = if ($null -eq $previous) { '' } else { [string]$previous.executionId }
            $began = [datetime]::UtcNow
            $result = Invoke-WacCampaignHost -ScriptPath $run -ArgumentList @('-PruneSupersededDrivers', '-ResetWindowsUpdateBase:$false')
            $summary = Get-WacCampaignSummary
            $ok = Test-WacCampaignRunEvidence -Summary $summary -PreviousId $previousId -StartedUtc $began `
                -ObservedExit $result.ExitCode -Category 'Superseded driver packages (pnputil)'
            return [PSCustomObject]@{ Scenario = $Name; Verdict = $(if ($ok) { 'passed' } else { 'failed' })
                Detail = ('Fresh executed pnputil pruning evidence={0}; exit={1}' -f $ok, $result.ExitCode) }
        }
        'reset-base' {
            $previous = Get-WacCampaignSummary
            $previousId = if ($null -eq $previous) { '' } else { [string]$previous.executionId }
            $began = [datetime]::UtcNow
            $result = Invoke-WacCampaignHost -ScriptPath $run -ArgumentList @('-ResetWindowsUpdateBase')
            $summary = Get-WacCampaignSummary
            $ok = Test-WacCampaignRunEvidence -Summary $summary -PreviousId $previousId -StartedUtc $began `
                -ObservedExit $result.ExitCode -Category 'Windows component store cleanup (DISM)'
            return [PSCustomObject]@{ Scenario = $Name; Verdict = $(if ($ok) { 'passed' } else { 'failed' })
                Detail = ('Fresh authorized component-store evidence={0}; exit={1}' -f $ok, $result.ExitCode) }
        }
        default { return [PSCustomObject]@{ Scenario = $Name; Verdict = 'failed'; Detail = 'No such scenario.' } }
    }
}
