#Requires -Version 5.1

<#
.SYNOPSIS
    Deploys WindowsAutoCleanup to %ProgramFiles% and registers the hidden daily SYSTEM task.

.DESCRIPTION
    The runtime is copied out of this checkout into %ProgramFiles%\WindowsAutoCleanup before the
    task is registered, because a SYSTEM task must never execute a directory a standard user can
    rewrite. The deployed tree and the PowerShell host are then VERIFIED to be machine-trusted;
    registration is refused if they are not. Nothing here changes an ACL or an owner - the v1.1.0
    hardening capability was removed because it made the user's own checkout hard to delete.

    Actions are written to %ProgramData%\WindowsAutoCleanup\Logs and printed to the console.

.PARAMETER DailyRunTime
    Daily task run time, 24-hour HH:mm.

.PARAMETER NoPause
    Do not wait for a key press before exiting. For automation and tests.

.PARAMETER ResetWindowsUpdateBase
    Registers the task with DISM /ResetBase enabled. Default $true. After a /ResetBase run the
    Windows updates installed before it can no longer be uninstalled. Pass
    -ResetWindowsUpdateBase:$false to register the task without it; that value now survives the
    elevation relaunch and is always written into the task action explicitly.

.PARAMETER PruneSupersededDrivers
    Adds -PruneSupersededDrivers to the task action. Off by default.

.PARAMETER EnableLegacyDiskCleanup
    Adds -EnableLegacyDiskCleanup to the task action. Off by default: cleanmgr /sagerun enumerates
    every drive on the machine, which breaks the C:-only guarantee.

.EXAMPLE
    .\Install-WindowsAutoCleanupTask.ps1 -DailyRunTime 03:00 -ResetWindowsUpdateBase:$false

.NOTES
    Exit codes:
      0  success
      1  error, or an unverifiable safety condition
      3  another WindowsAutoCleanup operation - a cleanup run, an install or an uninstall - already
         holds the machine-wide lock
      4  elevation was cancelled or failed
      5  unsupported environment (the online system drive is not C:)
      6  refused before any change, or the task and deployment landed, but either way this run's
         audit log is not durable
      7  refused: the machine state directory could not be proven machine-trusted, or something at
         the task path or the deployment path could not be proven ours. Nothing was changed
#>

# Write-Host is deliberate: the installer is a user-facing console tool and the structured
# record goes to the file log separately.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Console output is the point of an interactive installer; the file log is written through Write-WacLog.')]
[CmdletBinding()]
param(
    [ValidatePattern('^(?:[01]\d|2[0-3]):[0-5]\d$')]
    [string]$DailyRunTime = '20:00',

    [switch]$NoPause,

    [switch]$ResetWindowsUpdateBase = $true,

    [switch]$PruneSupersededDrivers,

    [switch]$EnableLegacyDiskCleanup
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Ledger P0-2. Inside a function $PSBoundParameters is that FUNCTION's, which is how an explicit
# -ResetWindowsUpdateBase:$false used to be lost across the UAC relaunch and DISM ran /ResetBase
# anyway. Snapshot the script's own bound parameters here, before any function call.
$script:BoundParameter = @{}
foreach ($key in $PSBoundParameters.Keys) { $script:BoundParameter[$key] = $PSBoundParameters[$key] }

$script:ScriptRoot = Split-Path -Parent $PSCommandPath
$script:LogReady = $false
$script:InstanceLock = $null
$script:Relaunched = $false
$script:Refused = $false

# The elevated child's own budget, armed by Initialize-WacRun below, and the parent bound derived
# FROM it. The parent used to wait 20 minutes for a child whose own deadline was 30, and on expiry
# it returned while that still-mutating elevated child carried on with nobody watching. A wrapper's
# deadline has to outlast everything the child can legitimately do - operation, rollback and
# shutdown - or it is not waiting for the child, it is abandoning it.
$script:RunBudgetMinutes = 30
$script:ChildShutdownMarginMinutes = 10
$script:ElevationTimeoutMs = ($script:RunBudgetMinutes + $script:ChildShutdownMarginMinutes) * 60000

Import-Module -Name (Join-Path -Path $script:ScriptRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') -DisableNameChecking -Force -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:ScriptRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') -DisableNameChecking -Force -ErrorAction Stop

# Dot-sourced, not imported: a module can only hand a script what it EXPORTS, the Deploy package's
# export list is fixed, and both of these are script-scope bodies rather than module surface. The
# gate is shared with the uninstaller; the task-lifecycle part belongs to this script alone and
# calls back into Write-InstallerMessage, which is defined below and resolved when it runs.
. (Join-Path -Path $script:ScriptRoot -ChildPath 'src\WindowsAutoCleanup.EntryGate.ps1')
. (Join-Path -Path $script:ScriptRoot -ChildPath 'src\WindowsAutoCleanup.InstallerTask.ps1')

function Write-InstallerMessage {
    <#
    .SYNOPSIS
        One line to the console and, unless -NoLog, one structured record to the run log.
    .DESCRIPTION
        -NoLog exists for the refusal raised when the directory this run's audit log lives in is not
        machine-trusted: explaining that refusal through the very path it just refused would be a
        write into a location a standard user can replace.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Data,
        [switch]$NoLog
    )

    if ($script:LogReady -and -not $NoLog) {
        if ($Data) { Write-WacLog -Level $Level -Component 'Installer' -Message $Message -Data $Data }
        else { Write-WacLog -Level $Level -Component 'Installer' -Message $Message }
    }

    $colour = switch ($Level) {
        'WARNING' { 'Yellow' }
        'ERROR' { 'Red' }
        'CRITICAL' { 'Red' }
        default { 'Gray' }
    }
    Write-Host ('[{0}] {1}' -f $Level, $Message) -ForegroundColor $colour
}

function Wait-InstallerExit {
    if ($NoPause) { return }
    # The elevated child already paused; a second prompt in the parent window helps nobody.
    if ($script:Relaunched) { return }
    # A redirected stdin means no user is there to press anything; waiting would hang CI.
    try { if ([System.Console]::IsInputRedirected) { return } } catch { return }

    try {
        Write-Host ''
        Write-Host 'Press any key to close this window...' -ForegroundColor Cyan
        $null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    catch {
        try { Read-Host -Prompt 'Press Enter to close this window' | Out-Null } catch { $null = $_ }
    }
}

function Invoke-InstallerElevation {
    <#
    .SYNOPSIS
        Relaunches this script elevated and returns the child's real exit code.
    .DESCRIPTION
        Called from INSIDE the main try (ledger P1-12), so a cancelled UAC prompt is logged, honours
        -NoPause and produces exit code 4 instead of an unhandled terminating error.
        wt.exe is never used as the elevation wrapper: it is PATH-resolved, it may not be present,
        and it exits as soon as it hands the command to its own window, so the exit code is lost.
    #>
    $hostPath = Get-WacCanonicalPowerShellHost
    if (-not $hostPath) {
        Write-InstallerMessage -Level ERROR -Message 'No machine-trusted PowerShell host was found for the elevated relaunch.'
        return 4
    }

    $vector = Get-WacInstallerRelaunchArgument `
        -ScriptPath $PSCommandPath `
        -DailyRunTime $DailyRunTime `
        -ResetWindowsUpdateBase ([bool]$ResetWindowsUpdateBase) `
        -PruneSupersededDrivers:$PruneSupersededDrivers `
        -EnableLegacyDiskCleanup:$EnableLegacyDiskCleanup `
        -NoPause:$NoPause

    # Start-Process joins an array argument with plain spaces and no quoting, so the vector has to
    # be turned into one correctly quoted command line first.
    $commandLine = ConvertTo-WacCommandLine -ArgumentList $vector

    Write-InstallerMessage -Level INFO -Message 'Requesting elevation.' -Data @{
        host = $hostPath
        arguments = $commandLine
        explicitParameters = (@($script:BoundParameter.Keys | Sort-Object) -join ',')
    }

    $script:Relaunched = $true
    $child = $null
    try {
        $child = Start-Process -FilePath $hostPath -ArgumentList $commandLine -Verb RunAs -PassThru -ErrorAction Stop
    }
    catch {
        Write-InstallerMessage -Level ERROR -Message ('Elevation was cancelled or failed: {0}' -f $_.Exception.Message)
        return 4
    }

    if (-not $child) {
        Write-InstallerMessage -Level ERROR -Message 'Elevation returned no child process.'
        return 4
    }

    # Touching Handle caches it, which is what keeps ExitCode readable after the child exits.
    try { $null = $child.Handle } catch { $null = $_ }

    if (-not $child.WaitForExit($script:ElevationTimeoutMs)) {
        # Past this point the child has outrun its OWN deadline plus the shutdown margin, so it is
        # not "still working" - it is wedged. The outcome is reported from proof: Stop-WacProcessTree
        # returns $true only when the target is known to have exited, and an unelevated parent cannot
        # terminate an elevated child at all, so the operator is told which of the two happened
        # instead of the wrapper walking away from a mutating installer in silence.
        Write-InstallerMessage -Level ERROR -Message 'The elevated installer outran its own budget and the parent deadline.' -Data @{ pid = $child.Id; timeoutMs = $script:ElevationTimeoutMs }

        if (Stop-WacProcessTree -ProcessId $child.Id) {
            Write-InstallerMessage -Level ERROR -Message 'The elevated installer was terminated and proven gone. The deployment may be mid-install; re-run the installer.'
        }
        else {
            Write-InstallerMessage -Level CRITICAL -Message 'The elevated installer could NOT be proven terminated and may still be running as administrator. Do not re-run the installer until it has exited.' -Data @{ pid = $child.Id }
        }
        return 1
    }

    $code = 1
    try { $code = [int]$child.ExitCode } catch { $code = 1 }
    Write-InstallerMessage -Level INFO -Message 'The elevated installer finished.' -Data @{ exitCode = $code }
    return $code
}

function Invoke-Main {
    if (-not (Test-WacIsAdministrator)) {
        return (Invoke-InstallerElevation)
    }

    # ONE lock for the runtime, the install, the upgrade and the uninstall (ledger B2-3). The
    # installer used to take a DIFFERENT name from Run.ps1, so a scheduled cleanup could be running
    # out of the very tree this script was about to replace. Taken before anything is inspected, and
    # released in the finally at the bottom of the file, so it covers verification and rollback too.
    $script:InstanceLock = Enter-WacSingleInstance -Name (Get-WacOperationLockName)
    if (-not $script:InstanceLock) {
        Write-InstallerMessage -Level ERROR -Message 'Another WindowsAutoCleanup operation - a cleanup run, an install or an uninstall - already holds the machine-wide lock.' -Data @{ lock = (Get-WacOperationLockName) }
        return 3
    }

    # Every trust question this run can be refused on is asked HERE, before the first filesystem,
    # task or registry change. A false or unknown answer costs nothing but the mutex.
    $safety = Get-OperationSafetyVerdict -LogHealth (Get-WacLogHealth) -StateTrust (Get-WacStateTrust)
    if (-not $safety.Ok) {
        $script:Refused = $true
        # -NoLog: the path being refused is the one the log lives in, so the refusal must not be
        # written through it. Nothing below this line runs, so nothing else writes there either.
        Write-InstallerMessage -Level ERROR -Message $safety.Reason -NoLog
        return $safety.ExitCode
    }

    if (-not (Test-WacSystemDriveSupported)) {
        Write-InstallerMessage -Level ERROR -Message ('WindowsAutoCleanup only supports an online system drive of C:; this machine reports {0}.' -f $env:SystemDrive)
        return 5
    }

    Write-InstallerMessage -Level INFO -Message 'Running elevated.' -Data @{ log = [string](Get-WacLogPath) }

    Import-Module -Name 'ScheduledTasks' -ErrorAction Stop

    # Fail before deploying if the run time is unusable.
    $trigger = Get-InstallerTaskTrigger -RunTime $DailyRunTime

    $slots = Get-WacDeploymentSlotPath
    if (-not $slots) {
        Write-InstallerMessage -Level ERROR -Message 'The deployment root cannot be resolved on this machine.'
        return 5
    }

    # Prove ownership of the deployment path BEFORE anything is written or removed (ledger B2-3). A
    # directory sitting at the expected path is not evidence that we put it there.
    $ownership = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root
    if (-not $ownership.IsOurs) {
        Write-InstallerMessage -Level ERROR -Message 'Refusing to replace a directory at the deployment path that cannot be proven to belong to WindowsAutoCleanup. It was left exactly as it was found.' -Data @{
            root = $ownership.Root; kind = $ownership.Kind; reason = $ownership.Reason
            findings = ((@($ownership.Findings) | Sort-Object) -join '; ')
        }
        return 7
    }
    Write-InstallerMessage -Level INFO -Message 'Deployment path ownership proven.' -Data @{
        root = $ownership.Root; kind = $ownership.Kind; version = [string]$ownership.Version
        tampered = [bool]$ownership.Tampered; reason = $ownership.Reason
    }

    # Asked before anything is written, and ternary: a scheduler that cannot be queried is not a
    # machine with no task on it. Staging already clears the .staging and .previous slots, which is
    # a deletion, so this cannot wait until the conflict is resolved in phase 3.
    $discovery = Get-WacInstalledTask -IncludeLegacy
    if ($discovery.State -eq 'Failed') {
        Write-InstallerMessage -Level ERROR -Message 'Refusing to install: the Task Scheduler could not be queried, so whether a WindowsAutoCleanup task is already registered is unknown. Nothing was staged, swapped or registered.' -Data @{
            findings = ((@($discovery.Failure | ForEach-Object { '{0}: {1}' -f $_.TaskPath, $_.Reason })) -join '; ')
        }
        return 1
    }

    $taskHost = Get-WacCanonicalPowerShellHost
    if (-not $taskHost) {
        Write-InstallerMessage -Level ERROR -Message 'No machine-trusted PowerShell host is available for the task action.'
        return 1
    }

    # Phase 1: build the whole new tree in the .staging slot. Nothing the currently registered task
    # can reach is touched, so this cannot pull a file out from under a run that is already going.
    $stage = New-WacDeploymentStage -SourceRoot $script:ScriptRoot
    Write-InstallerMessage -Level INFO -Message 'Runtime staged and hashed.' -Data @{
        staging = $stage.StagingRoot; files = $stage.FileCount; version = $stage.Version
    }

    # Phase 2: verify the STAGED tree, so an untrusted one never goes live at all. Its ancestors are
    # the deployment root's ancestors, and the PowerShell host chain is walked here too.
    $trust = Test-WacDeploymentTrusted -DeploymentRoot $stage.StagingRoot
    if (-not $trust.IsTrusted) {
        foreach ($entry in $trust.Untrusted) {
            Write-InstallerMessage -Level ERROR -Message 'A staged path is not machine-trusted.' -Data @{ path = $entry.Path; owner = [string]$entry.Owner; reason = $entry.Reason }
        }
        Write-InstallerMessage -Level ERROR -Message ('Refusing to install against an untrusted location: {0}' -f $trust.Reason)
        [void](Remove-WacDeployment -Path $stage.StagingRoot)
        return 1
    }
    Write-InstallerMessage -Level INFO -Message 'Staged deployment trust verified.' -Data @{ checked = $trust.CheckedCount }

    # Phase 3: resolve the existing task BEFORE the swap. Doing it the other way round leaves a
    # window in which the OLD task can start against the NEW files.
    $conflict = Resolve-ConflictingTask -DeploymentRoot $slots.Root
    if (-not $conflict.Ok) {
        Write-InstallerMessage -Level ERROR -Message $conflict.Reason
        [void](Remove-WacDeployment -Path $stage.StagingRoot)

        # Nothing went live, but this phase may already have removed one task before refusing on the
        # next, or removed one whose disappearance it could not prove. Either way a registration the
        # machine had is gone and the one that was to replace it will never exist, so whatever was
        # captured goes back before this returns.
        foreach ($definition in @($conflict.Captured)) { [void](Restore-CapturedTask -Definition $definition) }

        if ($conflict.Refused) { return 7 }
        return 1
    }

    # Phase 4: the swap, then register, then read everything back - all INSIDE the rollback try. The
    # swap used to sit outside it, so a failure in the switch itself, or in the walk that proves what
    # actually went live, returned without restoring anything. The previous tree is KEPT until the
    # last assertion passes, so every failure from here on is reversible.
    $registered = $null
    $description = Get-WacTaskDescription
    $arguments = Get-WacTaskActionArgument `
        -RunScript (Join-Path -Path $slots.Root -ChildPath 'Run.ps1') `
        -ResetWindowsUpdateBase ([bool]$ResetWindowsUpdateBase) `
        -PruneSupersededDrivers:$PruneSupersededDrivers `
        -EnableLegacyDiskCleanup:$EnableLegacyDiskCleanup

    try {
        [void](Switch-WacDeploymentStage -KeepPrevious)

        $live = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root
        if ($live.Kind -ne 'Managed' -or $live.Tampered) {
            throw ("What went live does not match the manifest that was staged: {0}" -f $live.Reason)
        }

        $definition = New-ScheduledTask `
            -Action (New-ScheduledTaskAction -Execute $taskHost -Argument $arguments -WorkingDirectory $slots.Root) `
            -Trigger $trigger `
            -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
            -Settings (New-ScheduledTaskSettingsSet `
                -Compatibility Win8 `
                -Hidden `
                -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries `
                -StartWhenAvailable `
                -MultipleInstances IgnoreNew `
                -ExecutionTimeLimit (New-TimeSpan -Hours 4) `
                -RestartCount 3 `
                -RestartInterval (New-TimeSpan -Minutes 10)) `
            -Description $description

        Write-InstallerMessage -Level INFO -Message 'Registering the scheduled task.' -Data @{ task = ('{0}{1}' -f (Get-WacTaskFolder), (Get-WacTaskName)) }
        Register-ScheduledTask -TaskName (Get-WacTaskName) -TaskPath (Get-WacTaskFolder) -InputObject $definition -ErrorAction Stop | Out-Null

        $registered = Assert-RegisteredTask -ExpectedHost $taskHost -ExpectedArguments $arguments `
            -ExpectedDescription $description -ExpectedWorkingDirectory $slots.Root -ExpectedRunTime $DailyRunTime
    }
    catch {
        Write-InstallerMessage -Level ERROR -Message ('The installation could not be completed: {0}' -f $_.Exception.Message)
        if (Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @($conflict.Captured)) {
            Write-InstallerMessage -Level ERROR -Message 'Final status: failed and rolled back. The machine is as it was before this run; re-run the installer once the cause above is fixed.'
        }
        else {
            Write-InstallerMessage -Level CRITICAL -Message 'Final status: failed and the rollback is INCOMPLETE. Read the CRITICAL lines above before re-running the installer.'
        }
        return 1
    }

    [void](Remove-WacDeploymentPrevious)

    Write-InstallerMessage -Level INFO -Message 'Scheduled task registered and verified.' -Data @{
        task = ('{0}{1}' -f $registered.TaskPath, $registered.TaskName)
        execute = $taskHost
        arguments = $arguments
        workingDirectory = $slots.Root
        dailyRunTime = $DailyRunTime
        executionTimeLimit = [string]$registered.Settings.ExecutionTimeLimit
    }

    try {
        $info = Get-ScheduledTaskInfo -TaskName (Get-WacTaskName) -TaskPath (Get-WacTaskFolder) -ErrorAction Stop
        Write-InstallerMessage -Level INFO -Message 'Next run time read from the scheduler.' -Data @{ nextRun = [string]$info.NextRunTime }
    }
    catch {
        Write-InstallerMessage -Level WARNING -Message ('The next run time could not be read: {0}' -f $_.Exception.Message)
    }

    # The install itself succeeded, but a run whose audit trail was lost did not fully do what it
    # was asked to. Reported as INCOMPLETE (6), never as success.
    $logHealth = Get-WacLogHealth
    if (-not $logHealth.IsDurable) {
        Write-InstallerMessage -Level ERROR -Message 'Final status: incomplete. The task and the deployment are in place, but this run has no durable audit log.' -Data @{
            degraded = [bool]$logHealth.Degraded; failedWrites = [int]$logHealth.FailedWrites; reason = [string]$logHealth.Reason
        }
        return 6
    }

    Write-InstallerMessage -Level INFO -Message 'Final status: success.'
    return 0
}

$script:LogReady = Initialize-WacRun -BaseName 'Install-WindowsAutoCleanupTask' -BudgetMinutes $script:RunBudgetMinutes
if (-not $script:LogReady) {
    Write-Host '[WARNING] No log file could be created; continuing with console output only.' -ForegroundColor Yellow
}

# Logged before the admin branch so a relaunch that never happens is still explained by the log.
Write-InstallerMessage -Level INFO -Message 'Installer invoked.' -Data @{
    host = ('{0} {1}' -f $PSVersionTable.PSEdition, $PSVersionTable.PSVersion)
    source = $script:ScriptRoot
    elevated = [bool](Test-WacIsAdministrator)
    resetBase = [bool]$ResetWindowsUpdateBase
    pruneDrivers = [bool]$PruneSupersededDrivers
    legacyDiskCleanup = [bool]$EnableLegacyDiskCleanup
    explicitParameters = (@($script:BoundParameter.Keys | Sort-Object) -join ',')
}

$exitCode = 1
try {
    $exitCode = Invoke-Main
}
catch {
    Write-InstallerMessage -Level ERROR -Message ('Installer failed: {0}' -f $_.Exception.Message)
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-InstallerMessage -Level ERROR -Message ('At: {0}' -f $_.InvocationInfo.PositionMessage)
    }
    $exitCode = 1
}
finally {
    Exit-WacSingleInstance -Mutex $script:InstanceLock
    # Get-WacLogDirectory, not Split-Path -Parent (Get-WacLogPath): the log path is $null exactly
    # when logging failed, and Split-Path -Parent $null is a TERMINATING parameter-binding error on
    # both shipped hosts (measured). The old spelling therefore crashed the cleanup of the very run
    # that was in the middle of reporting a log failure.
    # Skipped after a refusal: the verdict that refused the run can BE that this directory is not
    # machine-trusted, and pruning files inside it would be a delete through the refused path.
    $logDirectory = Get-WacLogDirectory
    if ($logDirectory -and -not $script:Refused) {
        [void](Remove-WacOldLog -LogDirectory $logDirectory -Pattern 'Install-WindowsAutoCleanupTask_*.log' -KeepCount 30)
    }
    Close-WacLog
}

Wait-InstallerExit
exit $exitCode
