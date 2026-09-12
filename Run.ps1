#Requires -Version 5.1

<#
.SYNOPSIS
    Removes allow-listed temporary and cache locations on drive C: and runs the supported Windows
    cleanup tools.

.DESCRIPTION
    WindowsAutoCleanup permanently deletes files from an explicit allow-list of cleanup locations on
    drive C:, runs DISM component store cleanup and the Windows Plug and Play driver cleanup handler,
    and empties the Recycle Bin on drive C:. Locked or inaccessible files are skipped or queued for
    deletion at the next boot. The script never prompts and writes a structured UTC log for every run
    under %ProgramData%\WindowsAutoCleanup\Logs.

    Two destructive capabilities are opt-in because they cannot satisfy the safety guarantees by
    default: superseded driver-package pruning (-PruneSupersededDrivers) and the legacy Disk Cleanup
    handler (-EnableLegacyDiskCleanup), which enumerates EVERY drive on the machine.

.PARAMETER Scheduled
    Set by the scheduled task. A scheduled run fails fast instead of attempting an interactive UAC
    relaunch.

.PARAMETER ResetWindowsUpdateBase
    Adds /ResetBase to the DISM component cleanup. Enabled by default. After a /ResetBase run the
    Windows updates installed before it can no longer be uninstalled. Pass
    -ResetWindowsUpdateBase:$false to disable it; that value is now forwarded correctly across an
    elevation relaunch.

.PARAMETER PruneSupersededDrivers
    Opt in to removing superseded OEM driver packages from the driver store. Disabled by default
    because package equivalence cannot be proven from the data pnputil exposes. Each package is
    exported to a recoverable backup first.

.PARAMETER EnableLegacyDiskCleanup
    Opt in to cleanmgr.exe /sagerun. Microsoft documents that /sagerun enumerates ALL drives and that
    /d is not honoured with it, so this breaks the C:-only guarantee. Off by default.

.PARAMETER SkipRecycleBin
    Do not touch the Recycle Bin on drive C:.

.PARAMETER SkipCategory
    Allow-list categories to leave alone, matched case-insensitively against the category name.

.PARAMETER LogLevel
    DEBUG, INFO, WARNING, ERROR or CRITICAL. DEBUG adds a line per cleanup target. The run's own
    verdict, and whatever produced a non-zero exit code, are written at CRITICAL whatever this is
    set to: no level can leave a failing run with nothing to read.

.PARAMETER BudgetMinutes
    Total internal run budget. Must stay below the scheduled task's execution time limit (4 hours),
    because every step's timeout is clamped to whatever is left of this budget.

    It is measured from process start, so loading the modules and reaching the trust preflight come
    out of it, and the last 30 seconds are held back so the run can always write its own verdict.

.PARAMETER MutexName
    Overrides the machine-wide single-instance mutex name. Only tests should use this.

.PARAMETER SkipAclHardening
    Deprecated and ignored. The project-folder ACL hardening capability was removed in v1.2.0 because
    it changed the owner and DACL of the user's own checkout and made it hard to delete. The switch
    is still accepted so a scheduled task registered by an older installer keeps working.

.NOTES
    Exit codes:
      0  success
      1  error, missing privileges, or an unhandled failure
      2  completed, but at least one cleanup item failed
      3  another run already holds the machine-wide lock
      4  elevation was cancelled or failed
      5  unsupported environment (the online system drive is not C:)
      6  incomplete: work the run was asked to do was not done and not proven safe to skip - the
         run budget expired, a step hit its deadline, an elevated child had to be terminated, or
         the durable audit log could not be produced
      7  security refusal: a safety check refused to proceed on evidence - a cleanup path failed
         its identity or containment re-check, or the directory holding this run's state and audit
         log is not machine-trusted

    A run reports the WORST outcome it saw: a security refusal outranks a failure, which outranks
    incomplete work. A benign skip - a reparse point left alone, a protected path stepped around,
    an opt-in step that is off - is not one of these and keeps the run at 0.
#>

# PositionalBinding=$false is a safety control, not a style choice. With the default binding,
# `-ResetWindowsUpdateBase $false` (a space instead of a colon - the spelling most people reach for)
# bound the SWITCH to $true and dropped the leftover '$false' token into the positional
# [string[]]$SkipCategory, so DISM ran /ResetBase after the user explicitly asked for it to be off.
# Named-only binding turns that spelling into an immediate parameter-binding error instead.
[CmdletBinding(PositionalBinding = $false)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidDefaultValueSwitchParameter', '',
    Justification = 'ResetWindowsUpdateBase has shipped as a default-on switch since v1.0.0 and the documented way to disable it is -ResetWindowsUpdateBase:$false. Changing it to [bool] would break every existing scheduled task and command line that passes it bare.')]
param(
    [switch]$Scheduled,
    [switch]$ResetWindowsUpdateBase = $true,
    [switch]$PruneSupersededDrivers,
    [switch]$EnableLegacyDiskCleanup,
    [switch]$SkipRecycleBin,
    [string[]]$SkipCategory = @(),
    [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$LogLevel = 'INFO',
    [ValidateRange(1, 235)][int]$BudgetMinutes = 210,
    [string]$MutexName = 'Global\WindowsAutoCleanup',
    [switch]$SkipAclHardening
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# Snapshot the SCRIPT's bound parameters before entering any function. A function declares its own
# param() block and therefore gets its own empty $PSBoundParameters, which is exactly how an explicit
# -ResetWindowsUpdateBase:$false used to be lost across the elevation relaunch (ledger P0-2).
$script:BoundParameter = @{}
foreach ($key in $PSBoundParameters.Keys) { $script:BoundParameter[$key] = $PSBoundParameters[$key] }

# Kept for anyone still invoking the script through -File, where an array parameter arrives as one
# comma-joined element. The relaunch and the scheduled task both use -Command now, so they already
# pass a real array; splitting here makes every invocation shape behave the same.
$SkipCategory = @($SkipCategory | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

$script:ScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$script:ScriptRoot = Split-Path -Parent $script:ScriptPath
$script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$script:ExitCode = 0

# The budget is measured from HERE rather than from wherever Initialize-WacRun happens to arm it.
# Loading five modules, taking the lock and reaching the trust verdict is work this run performs,
# and a budget that starts after them is a budget that does not cover them. The margin is taken off
# the other end for the same reason: a run that spends its final millisecond inside a cleanup step
# has nothing left to write its own verdict with, and an unwritten verdict is the one failure mode
# the whole exit-code contract exists to prevent.
$script:StartUtc = (Get-Date).ToUniversalTime()
$script:CleanupMarginSeconds = 30

# ------------------------------------------------------------------------------------------------
# Bootstrap logging
#
# Nothing inside a module can log its own import or parse failure, so the few lines that capture one
# are written here, before any module exists. The file is only ever touched when something is wrong;
# Initialize-WacRun folds whatever landed in it into the run log, and it is deleted again once that
# log is known to be durable, so one run leaves ONE audit artifact.
#
# The name carries a per-run GUID as well as the pid. %TEMP% for the SYSTEM task is C:\Windows\Temp,
# which grants BUILTIN\Users write by default, so a PREDICTABLE name is one a standard user can
# create first - as a link - and have this appended to, read back into the run log and deleted, all
# as SYSTEM. A name nobody can predict cannot be pre-created. This is the earliest write the process
# makes, before any module and therefore before any verification exists to lean on.
# ------------------------------------------------------------------------------------------------

$script:BootstrapLogPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) `
    -ChildPath ('WindowsAutoCleanup-bootstrap-{0}-{1}.log' -f $PID, [guid]::NewGuid().ToString('N'))

function Write-WacBootstrapLine {
    <#
    .SYNOPSIS
        Appends one CRITICAL line to the pre-import bootstrap log. Never throws.
    #>
    param([Parameter(Mandatory = $true)][string]$Message)

    $line = '[{0} UTC] [CRITICAL] [Bootstrap] {1}' -f `
        (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $Message

    try {
        [System.IO.File]::AppendAllText($script:BootstrapLogPath, ($line + [Environment]::NewLine),
            (New-Object System.Text.UTF8Encoding($false)))
    }
    catch {
        # The bootstrap log is the fallback; it has no fallback of its own. Losing it must still
        # leave the operator with the message, so it goes to the error stream instead.
        Write-Error ('{0} (the bootstrap log at {1} could not be written: {2})' -f `
            $line, $script:BootstrapLogPath, $_.Exception.Message)
    }
}

function Remove-WacBootstrapLog {
    <#
    .SYNOPSIS
        Deletes the bootstrap log once the run log has adopted its content and is durable.
    .DESCRIPTION
        Only then: while the run log is degraded the bootstrap file may be the only surviving record
        of why, and deleting it would destroy the evidence it exists to preserve. Durable is also
        what makes this delete safe to make early: the run log it hands the content to lives in a
        directory Initialize-WacRun verified before creating anything in it.
    #>
    if (-not (Test-Path -LiteralPath $script:BootstrapLogPath -PathType Leaf)) { return }
    if (-not (Get-WacLogHealth).IsDurable) { return }

    # The same doctrine one level up: the run log adopts this file's lines at WARNING, and at
    # -LogLevel ERROR or CRITICAL every one of them is gated out - so the run log did NOT keep the
    # content, and deleting the file would destroy the only surviving record of a pre-import
    # failure. One artifact is the goal; it is not worth the evidence.
    if ($LogLevel -ceq 'ERROR' -or $LogLevel -ceq 'CRITICAL') { return }
    try { [System.IO.File]::Delete($script:BootstrapLogPath) } catch { $null = $_ }
}

# ------------------------------------------------------------------------------------------------
# The machine-wide operation lock
#
# Taken HERE, before the first Import-Module, and not where the run used to take it. ONE lock covers
# a cleanup run, an install and an uninstall, and an installer that holds it is free to replace the
# very deployment this script is about to load its modules out of - so a lock taken after the import
# does not protect the import, which is the part that most needs it.
#
# It is acquired before the elevation gate and released again if this run turns out to be the
# unelevated parent of a relaunch, because the elevated child re-runs this script and takes the same
# lock. Failing to acquire it is NOT reported here: exit 3 belongs in the durable audit log, and
# there is no log until Initialize-WacRun has run.
#
# ponytail: a second, deliberately minimal copy of Core's Enter-WacSingleInstance. Nothing under
# src\ may be loaded before the lock exists and Core lives under src\, so the alternative is no lock
# at this point at all. Keep the two in step - Core's copy carries the reasoning behind each branch.
# ------------------------------------------------------------------------------------------------

$script:OperationLock = $null

function Enter-WacBootstrapLock {
    <#
    .SYNOPSIS
        Takes the machine-wide operation lock, or returns $null when another operation owns it.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)

    $mutex = $null
    try {
        $createdNew = $false
        $mutex = New-Object System.Threading.Mutex($false, $Name, [ref]$createdNew)
    }
    catch {
        Write-WacBootstrapLine -Message ('The machine-wide lock {0} could not be created: {1}' -f $Name, $_.Exception.Message)
        return $null
    }

    $owned = $false
    try {
        $owned = $mutex.WaitOne(0)
    }
    catch {
        # AbandonedMutexException means a previous operation died holding the lock and WE NOW OWN IT.
        # WaitOne is a .NET method, so the exception can arrive wrapped in a
        # MethodInvocationException; treating that as "not acquired" would make every run after a
        # crash exit 3 and never clean again.
        $exception = $_.Exception
        while ($exception -and
               ($exception -is [System.Management.Automation.MethodInvocationException]) -and
               $exception.InnerException) {
            $exception = $exception.InnerException
        }
        $owned = ($exception -is [System.Threading.AbandonedMutexException])
    }

    if (-not $owned) {
        try { $mutex.Dispose() } catch { $null = $_ }
        return $null
    }

    return $mutex
}

function Exit-WacBootstrapLock {
    <#
    .SYNOPSIS
        Releases the operation lock. Idempotent, and safe before any module exists.
    #>
    if (-not $script:OperationLock) { return }

    $lock = $script:OperationLock
    $script:OperationLock = $null
    try { $lock.ReleaseMutex() } catch { $null = $_ }
    try { $lock.Dispose() } catch { $null = $_ }
}

$script:OperationLock = Enter-WacBootstrapLock -Name $MutexName

$moduleRoot = Join-Path -Path $script:ScriptRoot -ChildPath 'src'
$script:ImportFailure = New-Object 'System.Collections.Generic.List[string]'
foreach ($moduleName in @('Core', 'FileSystem', 'Targets', 'Steps', 'Drivers')) {
    $modulePath = Join-Path -Path $moduleRoot -ChildPath ('WindowsAutoCleanup.{0}.psm1' -f $moduleName)
    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        Write-WacBootstrapLine -Message ('Required module is missing: {0}' -f $modulePath)
        [void]$script:ImportFailure.Add($moduleName)
        continue
    }

    try {
        Import-Module -Name $modulePath -Force -DisableNameChecking -ErrorAction Stop
    }
    catch {
        # Recorded and survived rather than thrown, so the failure reaches the durable run log
        # instead of only the console of whatever started this. The run still refuses to clean.
        Write-WacBootstrapLine -Message ('Module {0} failed to load from {1}: {2}' -f `
            $moduleName, $modulePath, $_.Exception.Message)
        [void]$script:ImportFailure.Add($moduleName)
    }
}

# The run's own report - the header, the shared outcome model and the footer - is DOT-SOURCED, not
# imported: it reads and writes this script's $script: state, and an imported module would get its
# own copy of all of it. It is treated exactly like a required module, because a run that cannot
# state its verdict must not clean.
$reportPart = Join-Path -Path $moduleRoot -ChildPath 'WindowsAutoCleanup.RunReport.ps1'
try {
    . $reportPart
}
catch {
    Write-WacBootstrapLine -Message ('The run report part failed to load from {0}: {1}' -f $reportPart, $_.Exception.Message)
    [void]$script:ImportFailure.Add('RunReport')
}

if ($script:ImportFailure.Contains('Core')) {
    # Without Core there is no log, no deadline and no path safety, so there is nothing left to
    # continue into and nowhere to write but the error stream and the bootstrap file.
    Write-Error ('WindowsAutoCleanup cannot start: the Core module failed to load. See {0}' -f $script:BootstrapLogPath)
    exit 1
}

function Get-WacRunRelaunchArgument {
    <#
    .SYNOPSIS
        The exact child argument vector for an elevated relaunch of this script.
    .DESCRIPTION
        Boolean switches are always emitted explicitly, so the child can never fall back to a default
        the parent did not ask for. Kept as its own function so a test can assert on the vector
        without ever launching a process.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Bound)

    $booleanSwitch = @{
        ResetWindowsUpdateBase = [bool]$ResetWindowsUpdateBase
        PruneSupersededDrivers = [bool]$PruneSupersededDrivers
        EnableLegacyDiskCleanup = [bool]$EnableLegacyDiskCleanup
        SkipRecycleBin = [bool]$SkipRecycleBin
    }

    $namedValue = @{ LogLevel = $LogLevel; BudgetMinutes = [string]$BudgetMinutes }
    if ($Bound.ContainsKey('MutexName')) { $namedValue['MutexName'] = $MutexName }

    # The child is launched with -Command, so PowerShell parses the payload and an array parameter
    # arrives as a real array. Under the old -File form it would have collapsed into one string.
    $arrayValue = @{}
    if ($Bound.ContainsKey('SkipCategory') -and $SkipCategory.Count -gt 0) {
        $arrayValue['SkipCategory'] = $SkipCategory
    }

    return (Get-WacRelaunchArgument -ScriptPath $script:ScriptPath `
        -BooleanSwitch $booleanSwitch -NamedValue $namedValue -ArrayValue $arrayValue)
}

function Invoke-WacElevatedRelaunch {
    <#
    .SYNOPSIS
        Relaunches elevated, waits for the child with a deadline, and returns the child's exit code.
    .DESCRIPTION
        The old behaviour returned 0 immediately after starting the child, so a failed cleanup looked
        like a success to anything that read the exit code (ledger P1-12).
    #>
    # The three lines below are written at CRITICAL for the same reason the footer's verdict is:
    # each one IS the verdict of a run that never reaches the footer, and CRITICAL is the only
    # level -LogLevel cannot gate out. A 4 or a 6 with an empty log explains nothing.
    $host51 = Get-WacCanonicalPowerShellHost
    if (-not $host51) {
        Write-WacLog -Level CRITICAL -Component 'Elevation' -Message 'No canonical, machine-trusted PowerShell host was found; refusing to relaunch.'
        return 4
    }

    $childArguments = Get-WacRunRelaunchArgument -Bound $script:BoundParameter
    $commandLine = ConvertTo-WacCommandLine -ArgumentList $childArguments

    Write-WacLog -Level INFO -Component 'Elevation' -Message 'Relaunching elevated.' -Data @{
        host = $host51; args = $commandLine
    }

    # The child re-runs this script and takes the SAME machine-wide lock, so the parent has to let
    # go of it first or the elevated run it just started would be refused by its own parent. Nothing
    # below this line mutates anything: the parent waits, reports the child's verdict and exits.
    Exit-WacBootstrapLock

    try {
        # -ArgumentList joins an array without quoting, which corrupts any path containing a space.
        # A single pre-quoted command line is the only reliable shape here.
        $process = Start-Process -FilePath $host51 -ArgumentList $commandLine -Verb RunAs -PassThru -ErrorAction Stop
    }
    catch {
        Write-WacLog -Level CRITICAL -Component 'Elevation' -Message 'Elevation was cancelled or failed.' -Data @{ error = $_.Exception.Message }
        return 4
    }

    if (-not $process) { return 4 }

    # Windows PowerShell 5.1's Start-Process -PassThru returns a Process whose handle was never
    # cached, and ExitCode then answers 0 for ANY real exit code once the child has gone. Measured
    # on both shipped hosts with a child that exited 1: PowerShell 7 reported 1, 5.1 reported 0.
    # This function's whole purpose is to hand the child's exit code back as the run's exit code, so
    # without this a FAILED elevated cleanup reports success to the scheduler. WaitForExit below is
    # not a substitute - the installer and uninstaller call it too and still cache the handle first.
    try { $null = $process.Handle } catch { $null = $_ }

    # The child arms the SAME budget from its own start time, so waiting only for what the parent
    # has left would kill it seconds before it finished cleanly. Give the child its full budget plus
    # a small margin for process start-up.
    $waitMs = ($BudgetMinutes * 60 * 1000) + 60000
    if (-not $process.WaitForExit($waitMs)) {
        Write-WacLog -Level CRITICAL -Component 'Elevation' -Message 'The elevated child exceeded the run budget; terminating its process tree.' -Data @{ pid = $process.Id }

        # Stop-WacProcessTree binds a real kernel handle to the child AND to every descendant it
        # can see, so Proven=$false is not "probably fine": it means termination could not be
        # ESTABLISHED and part of the tree may still be deleting files. Discarding that answer is
        # what made a leaked cleanup process indistinguishable from a clean kill.
        $stopped = Stop-WacProcessTree -ProcessId $process.Id
        if (-not $stopped.Proven) {
            Write-WacLog -Level CRITICAL -Component 'Elevation' -Message 'Termination of the elevated child could not be established; it may still be running.' -Data @{
                pid = $process.Id
                survivors = (@($stopped.Survivor) -join ',')
                reason = [string]$stopped.Reason
            }
        }

        # Either way the child never finished the work it was started for: Incomplete, not success
        # and not a plain error.
        return 6
    }

    $childExit = 1
    try { $childExit = [int]$process.ExitCode } catch { $childExit = 1 }
    Write-WacLog -Level INFO -Component 'Elevation' -Message 'The elevated child finished.' -Data @{ exitCode = $childExit }
    return $childExit
}


# ------------------------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------------------------

$script:Version = '1.2.0'

try {
    # -StartUtc and -ShutdownMarginSeconds are what make the budget cover this run rather than the
    # part of it that happens to come after this line. Module import, the machine-wide lock and the
    # trust preflight all ran before it; the footer still has to run after it.
    $logInitialised = Initialize-WacRun -BaseName 'WindowsAutoCleanup' -LogLevel $LogLevel -BudgetMinutes $BudgetMinutes `
        -BootstrapLogPath $script:BootstrapLogPath -StartUtc $script:StartUtc `
        -ShutdownMarginSeconds $script:CleanupMarginSeconds
    if (-not $logInitialised) {
        # Nothing was created, opened or written in any candidate state directory - Initialize-WacRun
        # verifies each one BEFORE it touches it, and returns false rather than logging through a
        # path it is about to refuse. So there is no log to write the verdict into, and Write-WacLog
        # routes a degraded run's lines to the verified fallback (Event Log, then console) instead.
        $stateTrust = Get-WacStateTrust
        if ($null -ne $stateTrust -and -not $stateTrust.IsTrusted) {
            Write-WacLog -Level CRITICAL -Component 'Run' -Message 'No machine-trusted state directory was found; nothing was created in any of them and nothing on this machine was mutated.' -Data @{
                path = [string]$stateTrust.Path; reason = [string]$stateTrust.Reason
            }
            exit (Write-WacRunVerdict -Outcome 'SecurityRefusal')
        }

        Write-Error ('No log file could be created in any candidate location; refusing to run silently. Any pre-import failure is in {0}.' -f $script:BootstrapLogPath)
        exit 1
    }

    # The run log has adopted whatever the bootstrap file held, so the run is back to one artifact.
    #
    # It stays HERE, ahead of the run-level gate, and that is a decision rather than an oversight.
    # It is a delete, but not one that can travel through a refused path: it removes a per-run file
    # in %TEMP%, and only once Get-WacLogHealth says the content is safe in a log whose directory
    # Initialize-WacRun verified BEFORE creating it - a sink separately proven, which is what this
    # delete is conditioned on. Moving it past the gate would also make it dead: every path that
    # WRITES a bootstrap line exits before the gate (exit 1 for a module that would not load, exit 3
    # for a lock that could not be created), so a later call could only ever find nothing to remove.
    Remove-WacBootstrapLog

    if ($script:ImportFailure.Count -gt 0) {
        Write-WacLog -Level CRITICAL -Component 'Run' -Message 'A required module could not be loaded; refusing to run.' -Data @{
            modules = ($script:ImportFailure.ToArray() -join ',')
        }
        exit 1
    }

    Add-WacProtectedRoot -Path $script:ScriptRoot
    Add-WacProtectedRoot -Path (Get-WacDeploymentRoot)
    Add-WacProtectedRoot -Path (Get-WacDataRoot)

    Write-WacRunHeader -LogPath (Get-WacLogPath)

    if (-not (Test-WacIsAdministrator)) {
        if ($Scheduled) {
            # CRITICAL, not ERROR: this is the whole audit trail of a run that exits 1 here.
            Write-WacLog -Level CRITICAL -Component 'Run' -Message 'Administrator privileges are required and a scheduled run is not elevated.'
            exit 1
        }
        exit (Invoke-WacElevatedRelaunch)
    }

    if (-not (Test-WacSystemDriveSupported)) {
        Write-WacLog -Level CRITICAL -Component 'Run' -Message 'The online system drive is not C:. Every cleanup location in this tool is written for C:, so mixing the two could delete data belonging to a different Windows installation.' -Data @{ systemDrive = $env:SystemDrive }
        exit 5
    }

    # Taken in the bootstrap, before the first Import-Module; reported here, because exit 3 belongs
    # in the durable audit log and there was no log to write it to back then.
    if (-not $script:OperationLock) {
        # Benign as an event, and still the only thing this run will ever say about why it exited 3.
        Write-WacLog -Level CRITICAL -Component 'Run' -Message 'Another WindowsAutoCleanup operation already holds the machine-wide lock; exiting without mutating anything.' -Data @{ mutex = $MutexName }
        exit 3
    }

    # THE GATE. Everything below this line mutates the machine - log retention deletes files, the
    # Delivery Optimization cmdlet purges a cache, the sweep deletes, DISM and pnputil and cleanmgr
    # run. So the run-level verdicts are reached HERE, on the state this run started in, and a
    # refusal costs nothing because nothing has happened yet. They are asked again in the footer for
    # what changes during the run.
    $preflight = Get-WacRunLevelOutcome -Current 'Succeeded'
    if (-not (Test-WacOutcomeIsClean -Outcome $preflight)) {
        Write-WacLog -Level CRITICAL -Component 'Run' -Message 'A pre-cleanup check refused this run; nothing on this machine was mutated.' -Data @{ outcome = $preflight }
        exit (Write-WacRunVerdict -Outcome $preflight)
    }

    # Get-WacLogDirectory, not Split-Path -Parent (Get-WacLogPath): a null path is a TERMINATING
    # binding error on both shipped hosts, so the old spelling crashed the run in its own retention
    # step on exactly the path where logging had already failed.
    [void](Remove-WacOldLog -LogDirectory (Get-WacLogDirectory) -Pattern 'WindowsAutoCleanup_*.log' -KeepCount 30)

    $freeBefore = Get-WacRunTelemetry -What 'free space on C:' -Probe { Get-WacFreeBytes -Drive 'C:' }
    $targetResults = New-Object 'System.Collections.Generic.List[object]'
    $stepResults = New-Object 'System.Collections.Generic.List[object]'
    $effectiveSkip = New-Object 'System.Collections.Generic.List[string]'
    foreach ($category in $SkipCategory) { [void]$effectiveSkip.Add($category) }

    # Delivery Optimization first. The supported cmdlet is the documented way to purge that cache,
    # and the cache directory can be relocated off C: by policy, so when the cmdlet does the work the
    # hard-coded directory targets are redundant and only add noise to the log.
    $deliveryOptimization = Clear-WacDeliveryOptimizationCache
    [void]$stepResults.Add($deliveryOptimization)
    if ($deliveryOptimization.Succeeded) {
        [void]$effectiveSkip.Add('Delivery Optimization cache')
    }

    # Get-WacCleanupTargetSet, not the bare builder. Building the list walks every profile's Edge
    # directory and queries Win32_UserProfile through CIM, both of which block in the OS and are
    # therefore outside every cooperative deadline check behind them. The bounded form returns an
    # OUTCOME beside the list, which is the distinction the bare call cannot make: an empty
    # allow-list and an allow-list that was never finished look identical, and the second one must
    # not be reported as "nothing to clean" on a successful run. It is recorded as a step, so an
    # Incomplete or Failed discovery reaches the footer's verdict like any other unfinished work.
    $targetSet = Get-WacCleanupTargetSet -SkipCategory @($effectiveSkip.ToArray())
    [void]$stepResults.Add((Write-WacStepResult -Component 'Targets' -Result (New-WacStepResult `
        -Category 'Cleanup allow-list' -Outcome ([string]$targetSet.Outcome) -Attempted $true `
        -Detail ([string]$targetSet.Detail) -DurationMs ([int]$targetSet.DurationMs))))

    foreach ($target in @($targetSet.Target)) {
        if (Test-WacDeadlineExpired) {
            Write-WacLog -Level WARNING -Component 'Run' -Message 'The run budget expired; the remaining allow-list targets were not attempted.'
            break
        }

        $result = if ($target.Mode -eq 'Pattern') {
            Remove-WacFilesByPattern -Category $target.Category -Path $target.Path -Pattern $target.Pattern
        }
        else {
            Remove-WacTree -Category $target.Category -Path $target.Path -DeleteRoot:([bool]$target.DeleteRoot)
        }

        # Refused is in the gate because a target refused BEFORE it was attempted logged nothing at
        # all - so the one event that drives exit 7 was the one event missing from the log.
        if ($result.Attempted -or $result.Failed -gt 0 -or $result.SkippedReparse -gt 0 -or $result.Refused -gt 0) {
            Write-WacTreeResult -Result $result
        }
        [void]$targetResults.Add($result)
    }

    # Every step logs its own result line before returning, so the orchestrator only collects them.
    # Calling Write-WacStepResult again here logged each step twice, under two different component
    # names - caught by reading a real log rather than by a unit assertion.
    #
    # DISM runs before the optional legacy handler so Windows Update cleanup stays on the supported
    # path even when the caller opts in to cleanmgr.
    $componentCleanup = Invoke-WacComponentCleanup -ResetBase:([bool]$ResetWindowsUpdateBase)
    [void]$stepResults.Add($componentCleanup)
    [void]$stepResults.Add((Invoke-WacPnpCleanHandler))
    # NOT (Get-WacDataRoot)\DriverBackup any more. An export is the only copy of a package about to
    # be deleted, and %ProgramData% grants BUILTIN\Users the right to create names under every child
    # it has - a grant no healthy install can shed and this project may not rewrite. The backup root
    # moved somewhere that grant does not reach; Get-WacDriverBackupRoot carries the measurement.
    [void]$stepResults.Add((Invoke-WacDriverPackagePrune -Enabled:([bool]$PruneSupersededDrivers) `
        -BackupRoot (Get-WacDriverBackupRoot)))

    # cleanmgr's own "Update Cleanup" handler duplicates what DISM already did on the supported path.
    # Gate it on whether DISM actually SUCCEEDED, not on the parameter: a DISM that failed or was
    # skipped would otherwise leave the component store uncleaned by both mechanisms.
    $legacyCategory = Get-WacDiskCleanupCategory
    if ($componentCleanup.Succeeded) {
        $legacyCategory = @($legacyCategory | Where-Object { $_ -ne 'Update Cleanup' })
    }
    [void]$stepResults.Add((Invoke-WacLegacyDiskCleanup -Enabled:([bool]$EnableLegacyDiskCleanup) -Category $legacyCategory))

    if (-not $SkipRecycleBin) {
        [void]$stepResults.Add((Clear-WacRecycleBin))
    }

    $freeAfter = Get-WacRunTelemetry -What 'free space on C:' -Probe { Get-WacFreeBytes -Drive 'C:' }
    $rebootRequired = @($stepResults | Where-Object { $_.RebootRequired }).Count -gt 0

    # The footer owns the mapping: the run exits on its worst outcome, not on a failure count.
    $script:ExitCode = Write-WacRunFooter -TargetResult @($targetResults.ToArray()) -StepResult @($stepResults.ToArray()) `
        -FreeBytesBefore $freeBefore -FreeBytesAfter $freeAfter -RebootRequired $rebootRequired

    exit $script:ExitCode
}
catch {
    Write-WacLog -Level CRITICAL -Component 'Run' -Message 'Unhandled error.' -Data @{
        error = $_.Exception.Message
        at    = if ($_.InvocationInfo) { [string]$_.InvocationInfo.PositionMessage } else { '' }
    }
    exit 1
}
finally {
    # The log is closed BEFORE the lock is released. Anything waiting on the lock is the next
    # operation on this machine - an installer replacing this deployment, the uninstaller removing
    # it - and letting it start while this run still has an open handle on its own audit log is how
    # a run ends up without the record of how it ended.
    Close-WacLog
    Exit-WacBootstrapLock
}
