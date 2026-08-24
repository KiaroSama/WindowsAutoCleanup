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
    DEBUG, INFO, WARNING, ERROR or CRITICAL. DEBUG adds a line per cleanup target.

.PARAMETER BudgetMinutes
    Total internal run budget. Must stay below the scheduled task's execution time limit (4 hours),
    because every step's timeout is clamped to whatever is left of this budget.

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

$moduleRoot = Join-Path -Path $script:ScriptRoot -ChildPath 'src'
foreach ($moduleName in @('Core', 'FileSystem', 'Targets', 'Steps', 'Drivers')) {
    $modulePath = Join-Path -Path $moduleRoot -ChildPath ('WindowsAutoCleanup.{0}.psm1' -f $moduleName)
    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        Write-Error ("Required module is missing: {0}" -f $modulePath)
        exit 1
    }
    Import-Module -Name $modulePath -Force -DisableNameChecking -ErrorAction Stop
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
    $host51 = Get-WacCanonicalPowerShellHost
    if (-not $host51) {
        Write-WacLog -Level ERROR -Component 'Elevation' -Message 'No canonical, machine-trusted PowerShell host was found; refusing to relaunch.'
        return 4
    }

    $childArguments = Get-WacRunRelaunchArgument -Bound $script:BoundParameter
    $commandLine = ConvertTo-WacCommandLine -ArgumentList $childArguments

    Write-WacLog -Level INFO -Component 'Elevation' -Message 'Relaunching elevated.' -Data @{
        host = $host51; args = $commandLine
    }

    try {
        # -ArgumentList joins an array without quoting, which corrupts any path containing a space.
        # A single pre-quoted command line is the only reliable shape here.
        $process = Start-Process -FilePath $host51 -ArgumentList $commandLine -Verb RunAs -PassThru -ErrorAction Stop
    }
    catch {
        Write-WacLog -Level ERROR -Component 'Elevation' -Message 'Elevation was cancelled or failed.' -Data @{ error = $_.Exception.Message }
        return 4
    }

    if (-not $process) { return 4 }

    # The child arms the SAME budget from its own start time, so waiting only for what the parent
    # has left would kill it seconds before it finished cleanly. Give the child its full budget plus
    # a small margin for process start-up.
    $waitMs = ($BudgetMinutes * 60 * 1000) + 60000
    if (-not $process.WaitForExit($waitMs)) {
        Write-WacLog -Level ERROR -Component 'Elevation' -Message 'The elevated child exceeded the run budget; terminating its process tree.' -Data @{ pid = $process.Id }
        [void](Stop-WacProcessTree -ProcessId $process.Id)
        return 1
    }

    $childExit = 1
    try { $childExit = [int]$process.ExitCode } catch { $childExit = 1 }
    Write-WacLog -Level INFO -Component 'Elevation' -Message 'The elevated child finished.' -Data @{ exitCode = $childExit }
    return $childExit
}

function Write-WacRunHeader {
    param([Parameter(Mandatory = $true)][string]$LogPath)

    $edition = if ($PSVersionTable.ContainsKey('PSEdition')) { [string]$PSVersionTable.PSEdition } else { 'Desktop' }
    $hostPath = $null
    try { $hostPath = [string](Get-Process -Id $PID -ErrorAction Stop).Path } catch { $hostPath = $null }

    Write-WacLog -Level INFO -Component 'Run' -Message 'WindowsAutoCleanup started.' -Data @{
        version     = $script:Version
        executionId = Get-WacExecutionId
        logPath     = $LogPath
        scriptRoot  = $script:ScriptRoot
        scheduled   = [bool]$Scheduled
        elevated    = (Test-WacIsAdministrator)
        psVersion   = [string]$PSVersionTable.PSVersion
        psEdition   = $edition
        psHost      = $hostPath
        budgetMin   = $BudgetMinutes
        logLevel    = $LogLevel
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        Write-WacLog -Level INFO -Component 'Run' -Message 'Operating system.' -Data @{
            caption = [string]$os.Caption; build = [string]$os.BuildNumber; server = (Test-WacIsWindowsServer)
        }
    }
    catch {
        Write-WacLog -Level WARNING -Component 'Run' -Message 'Could not query the operating system version.' -Data @{ error = $_.Exception.Message }
    }

    Write-WacLog -Level INFO -Component 'Run' -Message 'Configuration.' -Data @{
        scope                   = 'C: only'
        resetWindowsUpdateBase  = [bool]$ResetWindowsUpdateBase
        pruneSupersededDrivers  = [bool]$PruneSupersededDrivers
        enableLegacyDiskCleanup = [bool]$EnableLegacyDiskCleanup
        skipRecycleBin          = [bool]$SkipRecycleBin
        skipCategory            = ($SkipCategory -join ',')
    }

    if ($SkipAclHardening) {
        Write-WacLog -Level WARNING -Component 'Run' -Message '-SkipAclHardening is deprecated and ignored; the ACL hardening capability was removed in v1.2.0.'
    }
}

function Write-WacRunFooter {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$TargetResult,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$StepResult,
        [Nullable[Int64]]$FreeBytesBefore,
        [Nullable[Int64]]$FreeBytesAfter,
        [bool]$RebootRequired
    )

    $script:Stopwatch.Stop()

    $totals = [ordered]@{
        files = 0L; dirs = 0L; links = 0L; bytes = 0L; queuedForReboot = 0L
        skipLocked = 0L; skipDenied = 0L; skipNotEmpty = 0L; skipReparse = 0L
        skipProtected = 0L; skipOutOfRoot = 0L; skipVanished = 0L; skipDeadline = 0L; failed = 0L
    }

    foreach ($result in $TargetResult) {
        $totals.files += $result.FilesDeleted
        $totals.dirs += $result.DirectoriesDeleted
        $totals.links += $result.ReparsePointsDeleted
        $totals.bytes += $result.BytesDeleted
        $totals.queuedForReboot += $result.PendingDeletes
        $totals.skipLocked += $result.SkippedLocked
        $totals.skipDenied += $result.SkippedDenied
        $totals.skipNotEmpty += $result.SkippedNotEmpty
        $totals.skipReparse += $result.SkippedReparse
        $totals.skipProtected += $result.SkippedProtected
        $totals.skipOutOfRoot += $result.SkippedOutOfRoot
        $totals.skipVanished += $result.SkippedVanished
        $totals.skipDeadline += $result.SkippedDeadline
        $totals.failed += $result.Failed
    }

    # Each step already logged itself through Write-WacStepResult as it completed, so the footer only
    # rolls their failures into the totals rather than repeating every line.
    foreach ($step in $StepResult) {
        if ($step.Failed) { $totals.failed++ }
    }

    Write-WacLog -Level INFO -Component 'Summary' -Message 'Cleanup totals.' -Data ([hashtable]$totals)

    $delta = $null
    if ($null -ne $FreeBytesBefore -and $null -ne $FreeBytesAfter) { $delta = [int64]($FreeBytesAfter - $FreeBytesBefore) }
    Write-WacLog -Level INFO -Component 'Summary' -Message 'Free space on C:.' -Data @{
        before = (Format-WacBytes -Bytes $FreeBytesBefore)
        after  = (Format-WacBytes -Bytes $FreeBytesAfter)
        delta  = (Format-WacBytes -Bytes $delta)
    }

    if ($RebootRequired) {
        Write-WacLog -Level WARNING -Component 'Summary' -Message 'A reboot is required to finish at least one cleanup step.'
    }
    if ($totals.queuedForReboot -gt 0) {
        Write-WacLog -Level INFO -Component 'Summary' -Message 'Locked items were queued for deletion at the next boot. Windows only records the pending operation; it does not guarantee the delete will succeed.' -Data @{ queued = $totals.queuedForReboot }
    }

    $status = 'success'
    $statusLevel = 'INFO'
    if ($totals.failed -gt 0) {
        $status = 'completed with failures'
        $statusLevel = 'WARNING'
    }

    Write-WacLog -Level $statusLevel -Component 'Run' -Message 'Final status.' -Data @{
        status = $status
        elapsed = $script:Stopwatch.Elapsed.ToString('hh\:mm\:ss')
        remainingBudgetMs = (Get-WacRemainingMs)
    }

    return [int64]$totals.failed
}

# ------------------------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------------------------

$script:Version = '1.2.0'
$mutex = $null

try {
    $logInitialised = Initialize-WacRun -BaseName 'WindowsAutoCleanup' -LogLevel $LogLevel -BudgetMinutes $BudgetMinutes
    if (-not $logInitialised) {
        Write-Error 'No log file could be created in any candidate location; refusing to run silently.'
        exit 1
    }

    Add-WacProtectedRoot -Path $script:ScriptRoot
    Add-WacProtectedRoot -Path (Get-WacDeploymentRoot)
    Add-WacProtectedRoot -Path (Get-WacDataRoot)

    Write-WacRunHeader -LogPath (Get-WacLogPath)

    if (-not (Test-WacIsAdministrator)) {
        if ($Scheduled) {
            Write-WacLog -Level ERROR -Component 'Run' -Message 'Administrator privileges are required and a scheduled run is not elevated.'
            exit 1
        }
        exit (Invoke-WacElevatedRelaunch)
    }

    if (-not (Test-WacSystemDriveSupported)) {
        Write-WacLog -Level CRITICAL -Component 'Run' -Message 'The online system drive is not C:. Every cleanup location in this tool is written for C:, so mixing the two could delete data belonging to a different Windows installation.' -Data @{ systemDrive = $env:SystemDrive }
        exit 5
    }

    $mutex = Enter-WacSingleInstance -Name $MutexName
    if (-not $mutex) {
        Write-WacLog -Level WARNING -Component 'Run' -Message 'Another WindowsAutoCleanup run already holds the machine-wide lock; exiting without mutating anything.' -Data @{ mutex = $MutexName }
        exit 3
    }

    [void](Remove-WacOldLog -LogDirectory (Split-Path -Parent (Get-WacLogPath)) -Pattern 'WindowsAutoCleanup_*.log' -KeepCount 30)

    $freeBefore = Get-WacFreeBytes -Drive 'C:'
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

    foreach ($target in (Get-WacCleanupTarget -SkipCategory @($effectiveSkip.ToArray()))) {
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

        if ($result.Attempted -or $result.Failed -gt 0 -or $result.SkippedReparse -gt 0) {
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
    [void]$stepResults.Add((Invoke-WacDriverPackagePrune -Enabled:([bool]$PruneSupersededDrivers) `
        -BackupRoot (Join-Path -Path (Get-WacDataRoot) -ChildPath 'DriverBackup')))

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

    $freeAfter = Get-WacFreeBytes -Drive 'C:'
    $rebootRequired = @($stepResults | Where-Object { $_.RebootRequired }).Count -gt 0

    $failed = Write-WacRunFooter -TargetResult @($targetResults.ToArray()) -StepResult @($stepResults.ToArray()) `
        -FreeBytesBefore $freeBefore -FreeBytesAfter $freeAfter -RebootRequired $rebootRequired

    $script:ExitCode = if ($failed -gt 0) { 2 } else { 0 }
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
    Exit-WacSingleInstance -Mutex $mutex
    Close-WacLog
}
