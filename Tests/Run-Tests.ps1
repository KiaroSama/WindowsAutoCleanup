#Requires -Version 5.1
<#
.SYNOPSIS
    Discovers and runs every Tests\*.Tests.ps1 suite as a bounded parallel child process.

.DESCRIPTION
    Suites are DISCOVERED, never listed, so a new suite file is covered by CI the moment it is
    added. Each suite runs in its own process under a wall-clock deadline and a no-progress (idle)
    deadline; exceeding either kills the whole owned process tree and counts as a FAILURE, because
    a timeout is missing evidence, not success.

    Output is redirected to files rather than pipes: the file length doubles as the progress
    heartbeat, so the runner needs no async pipe pump and cannot deadlock on a full buffer.

    KNOWN BOUNDARY of the leak accounting. leakedSuiteProcesses counts only processes this runner
    OWNS: the suite process it started and whatever taskkill /T reaches from it. A suite that
    deliberately launches a process OUT of its own tree - runas.exe, WMI Win32_Process.Create, a
    scheduled task - creates something that is not a descendant, so /T never sees it and this
    counter cannot see it either. It is named leakedSuiteProcesses, not leakedProcesses, so the 0
    is not read as a machine-wide all-clear it never measured; a suite that orphans by design is
    responsible for bounding its own orphan.

.PARAMETER Filter
    Substring matched against the suite file name.

.PARAMETER TestHost
    pwsh, powershell, or both. Aliased to -Host. Defaults to the host running this script.

.PARAMETER TimeoutSeconds
    Wall-clock ceiling for one suite process.

.PARAMETER IdleTimeoutSeconds
    Ceiling on the time a suite may run without producing output.

.PARAMETER ManifestPath
    Optional file receiving the name of every suite that actually executed. CI compares it against
    the discovered set so a suite cannot be silently skipped.

.EXAMPLE
    .\Tests\Run-Tests.ps1 -Host both -Filter FileSystem
#>

[CmdletBinding()]
param(
    # -Suite is the spelling the project's own docs and task notes use; without the alias that
    # documented command line fails outright with "A parameter cannot be found".
    [Alias('Suite')]
    [string]$Filter,

    [Alias('Host')]
    [ValidateSet('pwsh', 'powershell', 'both')]
    [string]$TestHost,

    [ValidateRange(15, 3600)][int]$TimeoutSeconds = 300,
    [ValidateRange(10, 3600)][int]$IdleTimeoutSeconds = 120,
    [string]$ManifestPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-TestHostExecutable {
    param([Parameter(Mandatory = $true)][string]$Kind)

    if ($Kind -eq 'powershell') {
        return (Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe')
    }

    if ($env:ProgramFiles) {
        $canonical = Join-Path -Path $env:ProgramFiles -ChildPath 'PowerShell\7\pwsh.exe'
        if (Test-Path -LiteralPath $canonical -PathType Leaf) { return $canonical }
    }

    $found = @(Get-Command -Name 'pwsh.exe' -CommandType Application -ErrorAction SilentlyContinue)
    if ($found.Count -gt 0) { return $found[0].Source }
    return $null
}

function Stop-TestProcessTree {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = (Join-Path -Path $env:SystemRoot -ChildPath 'System32\taskkill.exe')
        $psi.Arguments = '/T /F /PID {0}' -f $ProcessId
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true

        $killer = [System.Diagnostics.Process]::Start($psi)
        if ($killer) {
            [void]$killer.StandardOutput.ReadToEndAsync()
            [void]$killer.StandardError.ReadToEndAsync()
            [void]$killer.WaitForExit(10000)
            try { $killer.Dispose() } catch { $null = $_ }
        }
    }
    catch {
        $null = $_
    }
}

function Get-JobOutputSize {
    param([Parameter(Mandatory = $true)]$Job)

    $size = 0L
    foreach ($file in @($Job.OutFile, $Job.ErrFile)) {
        try {
            $info = New-Object System.IO.FileInfo($file)
            if ($info.Exists) { $size += $info.Length }
        }
        catch {
            $null = $_
        }
    }
    return $size
}

function Get-JobText {
    <#
    .SYNOPSIS
        Reads a finished child's redirect file, retrying while the handle is still being released.
    .DESCRIPTION
        The parent still holds the redirect FileStream for a moment after Process.HasExited flips, so
        a plain ReadAllText throws "the process cannot access the file" and the old bare catch turned
        that into an empty string. Measured on 1-5 of every 18 suite runs on both hosts: the suite's
        entire case list and its TOTAL line vanished while the run still reported exit=0, and the
        work directory holding the real output is deleted immediately afterwards - so a CI failure
        became undiagnosable. Opening with FileShare ReadWrite|Delete plus a short bounded retry
        fixes the read; the caller treats a still-unreadable result as a suite failure, because
        missing evidence is not success.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }

    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        try {
            $stream = New-Object System.IO.FileStream(
                $Path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
            try {
                $reader = New-Object System.IO.StreamReader($stream)
                try { return $reader.ReadToEnd() }
                finally { $reader.Dispose() }
            }
            finally {
                $stream.Dispose()
            }
        }
        catch {
            Start-Sleep -Milliseconds 25
        }
    }

    return $null
}

$repoRoot = Split-Path -Parent $PSScriptRoot

if (-not $TestHost) {
    $TestHost = 'powershell'
    if ($PSVersionTable.PSEdition -eq 'Core') { $TestHost = 'pwsh' }
}

$hostKinds = @($TestHost)
if ($TestHost -eq 'both') { $hostKinds = @('pwsh', 'powershell') }

$hostExecutables = @{}
foreach ($kind in $hostKinds) {
    $exe = Get-TestHostExecutable -Kind $kind
    # A missing host is a hard failure: silently skipping it is a false green.
    if (-not $exe -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        Write-Host ('ERROR requested host "{0}" was not found on this machine.' -f $kind)
        exit 3
    }
    $hostExecutables[$kind] = $exe
}

# -Recurse so a suite parked in a subdirectory is discovered rather than silently never run. The CI
# guard uses the same recursive glob; if the two disagree, a failing suite can hide from both.
$suites = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.Tests.ps1' -File -Recurse -ErrorAction Stop |
    Sort-Object -Property Name)

if ($Filter) {
    $suites = @($suites | Where-Object { $_.Name -like ('*{0}*' -f $Filter) })
}

# A run that discovered nothing must never look like success.
if ($suites.Count -eq 0) {
    Write-Host ('ERROR no suite matched Tests\*.Tests.ps1{0}.' -f $(if ($Filter) { " with filter '$Filter'" } else { '' }))
    exit 3
}

$cores = [Environment]::ProcessorCount
$workers = [Math]::Max(2, [Math]::Min(8, $cores - 2))
if ($env:HOOKMAKER_MAX_TEST_WORKERS) {
    $cap = 0
    if ([int]::TryParse($env:HOOKMAKER_MAX_TEST_WORKERS, [ref]$cap) -and $cap -ge 1) {
        $workers = [Math]::Min($workers, $cap)
    }
}

$workRoot = [System.IO.Path]::GetFullPath((Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('wac-run-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 12))))
[void][System.IO.Directory]::CreateDirectory($workRoot)

$pending = New-Object 'System.Collections.Generic.Queue[object]'
foreach ($kind in $hostKinds) {
    foreach ($suite in $suites) {
        $pending.Enqueue([PSCustomObject]@{ Suite = $suite; HostKind = $kind })
    }
}

$totalJobs = $pending.Count
Write-Host ('Running {0} suite run(s) on {1} with {2} worker(s); wall {3}s, idle {4}s.' -f `
    $totalJobs, ($hostKinds -join '+'), $workers, $TimeoutSeconds, $IdleTimeoutSeconds)

$running = New-Object 'System.Collections.Generic.List[object]'
$results = New-Object 'System.Collections.Generic.List[object]'
$executed = New-Object 'System.Collections.Generic.List[string]'
$leaked = 0

# A child of the other host kind must not inherit this process's PSModulePath: Windows PowerShell
# cannot load its own Microsoft.PowerShell.Security out of PowerShell 7's module directories, and
# the failure surfaces as a missing Get-Acl instead of anything naming the real cause. Removing the
# variable makes each host compute its own default at startup.
$savedModulePath = $env:PSModulePath
Remove-Item -LiteralPath 'Env:PSModulePath' -ErrorAction SilentlyContinue

try {
    while ($pending.Count -gt 0 -or $running.Count -gt 0) {

        while ($running.Count -lt $workers -and $pending.Count -gt 0) {
            $item = $pending.Dequeue()
            $stem = '{0}.{1}' -f $item.Suite.BaseName, $item.HostKind
            $job = [PSCustomObject]@{
                Name         = $item.Suite.Name
                HostKind     = $item.HostKind
                OutFile      = Join-Path -Path $workRoot -ChildPath ('{0}.out' -f $stem)
                ErrFile      = Join-Path -Path $workRoot -ChildPath ('{0}.err' -f $stem)
                Process      = $null
                Start        = [datetime]::UtcNow
                LastProgress = [datetime]::UtcNow
                LastSize     = -1L
            }

            # One pre-quoted string: Start-Process joins an array with plain spaces on Windows
            # PowerShell 5.1, which breaks the moment the repository path contains a space.
            $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $item.Suite.FullName

            $job.Process = Start-Process -FilePath $hostExecutables[$item.HostKind] `
                -ArgumentList $argLine -WorkingDirectory $repoRoot -NoNewWindow -PassThru `
                -RedirectStandardOutput $job.OutFile -RedirectStandardError $job.ErrFile

            [void]$running.Add($job)
            [void]$executed.Add($item.Suite.Name)
        }

        Start-Sleep -Milliseconds 200

        for ($i = $running.Count - 1; $i -ge 0; $i--) {
            $job = $running[$i]
            $now = [datetime]::UtcNow
            $elapsed = ($now - $job.Start).TotalSeconds

            $size = Get-JobOutputSize -Job $job
            if ($size -ne $job.LastSize) {
                $job.LastSize = $size
                $job.LastProgress = $now
            }

            $idle = ($now - $job.LastProgress).TotalSeconds
            $timeoutReason = $null
            if (-not $job.Process.HasExited) {
                if ($elapsed -ge $TimeoutSeconds) { $timeoutReason = 'wall' }
                elseif ($idle -ge $IdleTimeoutSeconds) { $timeoutReason = 'idle' }
            }

            if ($timeoutReason) {
                Stop-TestProcessTree -ProcessId $job.Process.Id
                [void]$job.Process.WaitForExit(10000)
            }
            elseif (-not $job.Process.HasExited) {
                continue
            }

            $exitCode = -1
            try { $exitCode = [int]$job.Process.ExitCode } catch { $exitCode = -1 }

            $stillRunning = $false
            try { $stillRunning = -not $job.Process.HasExited } catch { $stillRunning = $false }
            if ($stillRunning) { $leaked++ }

            [void]$results.Add([PSCustomObject]@{
                Name       = $job.Name
                HostKind   = $job.HostKind
                ExitCode   = $exitCode
                TimedOut   = $timeoutReason
                DurationS  = [math]::Round(([datetime]::UtcNow - $job.Start).TotalSeconds, 1)
                Output     = (Get-JobText -Path $job.OutFile)
                ErrorText  = (Get-JobText -Path $job.ErrFile)
            })

            try { $job.Process.Dispose() } catch { $null = $_ }
            $running.RemoveAt($i)
        }
    }
}
finally {
    if ($null -ne $savedModulePath) { $env:PSModulePath = $savedModulePath }

    foreach ($job in @($running.ToArray())) {
        try {
            if (-not $job.Process.HasExited) {
                Stop-TestProcessTree -ProcessId $job.Process.Id
                [void]$job.Process.WaitForExit(10000)
                if (-not $job.Process.HasExited) { $leaked++ }
            }
        }
        catch {
            $null = $_
        }
    }

    if ($ManifestPath) {
        try {
            $manifestDir = Split-Path -Parent $ManifestPath
            if ($manifestDir -and -not (Test-Path -LiteralPath $manifestDir -PathType Container)) {
                [void][System.IO.Directory]::CreateDirectory($manifestDir)
            }
            [System.IO.File]::WriteAllLines($ManifestPath, [string[]]@($executed.ToArray() | Sort-Object -Unique))
        }
        catch {
            Write-Host ('WARNING could not write the manifest: {0}' -f $_.Exception.Message)
        }
    }

    try { if (Test-Path -LiteralPath $workRoot) { Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction Stop } }
    catch { Write-Host ('WARNING could not remove {0}: {1}' -f $workRoot, $_.Exception.Message) }
}

$failures = 0
$skipped = 0
foreach ($result in @($results | Sort-Object -Property HostKind, Name)) {
    Write-Host ''
    Write-Host ('--- {0} [{1}] exit={2} {3}s{4}' -f $result.Name, $result.HostKind, $result.ExitCode, $result.DurationS,
        $(if ($result.TimedOut) { ' TIMEOUT:' + $result.TimedOut } else { '' }))

    foreach ($line in @(($result.Output -split "`r?`n"))) {
        if ($line.Trim()) { Write-Host ('    {0}' -f $line) }
    }
    foreach ($line in @(($result.ErrorText -split "`r?`n"))) {
        if ($line.Trim()) { Write-Host ('  ! {0}' -f $line) }
    }

    # Skips are rolled up by name so the tail of a long CI log still shows them. The suite itself
    # already exited 3 for them, so this only has to COUNT them, never decide the outcome.
    if ($result.Output -and ($result.Output -match 'TOTAL cases=\d+ passed=\d+ failed=\d+ skipped=(\d+)')) {
        $skipped += [int]$Matches[1]
    }

    if ($result.TimedOut -or $result.ExitCode -ne 0) {
        $failures++
    }
    elseif ($null -eq $result.Output -or ($result.Output -notmatch 'TOTAL cases=')) {
        # A run that exited 0 but produced no TOTAL line proved nothing: either the capture was lost
        # or the suite never reached Complete-TestRun. Missing evidence is not success.
        Write-Host ('  ! no TOTAL line was captured for this run, so its result is unproven')
        $failures++
    }
}

Write-Host ''
Write-Host ('SUMMARY runs={0} failed={1} skippedCases={2} workers={3} leakedSuiteProcesses={4}' -f `
        $results.Count, $failures, $skipped, $workers, $leaked)

# Printed only after a timeout, which is the one outcome where an out-of-tree orphan is plausible:
# the suite was force-killed mid-flight, so anything it had launched outside its own tree outlived
# it unseen. Saying so beats letting leakedSuiteProcesses=0 be read as "nothing survived".
$timedOut = @($results | Where-Object { $_.TimedOut })
if ($timedOut.Count -gt 0) {
    Write-Host ('NOTE {0} run(s) were force-killed; leakedSuiteProcesses counts only this runner''s own process tree, so a process a suite launched OUT of that tree is not covered by the number above.' -f $timedOut.Count)
}

if ($skipped -gt 0) {
    Write-Host ('ERROR {0} case(s) declared themselves unable to run here; a skip proves nothing and is counted as a failure above.' -f $skipped)
}

if ($results.Count -ne $totalJobs) {
    Write-Host ('ERROR {0} of {1} suite run(s) produced no result.' -f ($totalJobs - $results.Count), $totalJobs)
    exit 3
}

if ($leaked -gt 0) { exit 4 }
if ($failures -gt 0) { exit 1 }
exit 0
