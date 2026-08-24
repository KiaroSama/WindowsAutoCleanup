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
      6  the task and deployment landed, but this run's audit log is not durable
      7  refused: something at the task path or the deployment path could not be proven to be ours,
         and it was left exactly as it was found
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

# The elevated child does the whole install; 20 minutes is well beyond a copy plus a registration.
$script:ElevationTimeoutMs = 1200000

Import-Module -Name (Join-Path -Path $script:ScriptRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') -DisableNameChecking -Force -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:ScriptRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') -DisableNameChecking -Force -ErrorAction Stop

function Write-InstallerMessage {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Data
    )

    if ($script:LogReady) {
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
        Write-InstallerMessage -Level ERROR -Message 'The elevated installer did not finish inside its deadline; it was left running rather than killed mid-install.' -Data @{ pid = $child.Id; timeoutMs = $script:ElevationTimeoutMs }
        return 1
    }

    $code = 1
    try { $code = [int]$child.ExitCode } catch { $code = 1 }
    Write-InstallerMessage -Level INFO -Message 'The elevated installer finished.' -Data @{ exitCode = $code }
    return $code
}

function Get-InstallerTaskTrigger {
    param([Parameter(Mandatory = $true)][string]$RunTime)

    $parsed = $null
    try {
        $parsed = [datetime]::ParseExact($RunTime, 'HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        throw ("Invalid DailyRunTime '{0}'. Use 24-hour HH:mm, for example '03:00'." -f $RunTime)
    }

    return (New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.Add($parsed.TimeOfDay)))
}

function Resolve-ConflictingTask {
    <#
    .SYNOPSIS
        Clears our own registration - current or pre-1.2 - before re-registering, and refuses to
        touch anyone else's.
    .DESCRIPTION
        Register-ScheduledTask -Force is documented only as "without prompting for confirmation";
        nothing says it overwrites. So the installer explicitly Gets, proves ownership, then
        Unregisters (ledger P0-4).

        Ledger B2-3 changes two things here. A foreign task at EITHER path is now a REFUSAL rather
        than a warning-and-carry-on: the pre-1.2 task ran a PATH-resolved host as SYSTEM, so leaving
        an unrecognised one registered while adding a second one beside it is how a machine ends up
        running two cleanup tasks, one of them the vulnerable one. And a legacy task that we DID
        prove and could not remove is fatal too, for the same reason.

        Called BEFORE anything is switched into the live deployment root, and with the machine-wide
        lock already held, so no cleanup run can start out of the tree between here and the swap.
    .OUTPUTS
        Ok, Refused, Reason.
    #>
    param([Parameter(Mandatory = $true)][string]$DeploymentRoot)

    $result = [PSCustomObject]@{ Ok = $true; Refused = $false; Reason = $null }

    foreach ($existing in (Get-WacInstalledTask -IncludeLegacy)) {
        $label = '{0}{1}' -f [string]$existing.TaskPath, [string]$existing.TaskName

        $removal = Remove-WacInstalledTask -Task $existing -DeploymentRoot $DeploymentRoot -AllowLegacyMigration
        if ($removal.Verified) {
            Write-InstallerMessage -Level INFO -Message 'Removed the previously registered WindowsAutoCleanup task.' -Data @{
                task = $label; reason = [string]$removal.Reason
            }
            continue
        }

        if ($removal.Removed) {
            $result.Ok = $false
            $result.Reason = ('The task at {0} was unregistered but is still present: {1}' -f $label, [string]$removal.Reason)
            return $result
        }

        $result.Ok = $false
        $result.Refused = $true
        $result.Reason = ('A task already occupies {0} and it could not be proven to be ours, so it was left untouched and nothing was registered beside it: {1}' -f $label, [string]$removal.Reason)
        return $result
    }

    return $result
}

function Undo-Installation {
    <#
    .SYNOPSIS
        Puts the machine back the way it was after a failure between the swap and the final assert.
    .DESCRIPTION
        Unregisters whatever this run registered - through the same ownership proof, so a task that
        somehow is not ours is left alone rather than deleted on the way out - and restores the
        deployment tree that Switch-WacDeploymentStage -KeepPrevious set aside.
    #>
    param([Parameter(Mandatory = $true)][string]$DeploymentRoot)

    foreach ($task in (Get-WacInstalledTask)) {
        $removal = Remove-WacInstalledTask -Task $task -DeploymentRoot $DeploymentRoot
        if ($removal.Verified) {
            Write-InstallerMessage -Level WARNING -Message 'Rollback: the task registered by this run was unregistered.' -Data @{
                task = ('{0}{1}' -f $removal.TaskPath, $removal.TaskName)
            }
        }
        else {
            Write-InstallerMessage -Level CRITICAL -Message 'Rollback could not unregister the task; remove it by hand before re-running.' -Data @{
                task = ('{0}{1}' -f $removal.TaskPath, $removal.TaskName); reason = [string]$removal.Reason
            }
        }
    }

    $restored = Restore-WacDeploymentPrevious
    if ($restored.Restored) {
        Write-InstallerMessage -Level WARNING -Message 'Rollback: the deployment was restored to its previous state.' -Data @{
            hadPrevious = [bool]$restored.HadPrevious; reason = [string]$restored.Reason
        }
    }
    else {
        Write-InstallerMessage -Level CRITICAL -Message 'Rollback could not restore the previous deployment.' -Data @{ reason = [string]$restored.Reason }
    }
}

function Assert-RegisteredTask {
    <#
    .SYNOPSIS
        Reads the task back and proves every setting the installer asked for actually landed.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ExpectedHost,
        [Parameter(Mandatory = $true)][string]$ExpectedArguments,
        [Parameter(Mandatory = $true)][string]$ExpectedDescription,
        [Parameter(Mandatory = $true)][string]$ExpectedWorkingDirectory,
        [Parameter(Mandatory = $true)][string]$ExpectedRunTime
    )

    $task = $null
    try {
        $task = Get-ScheduledTask -TaskName (Get-WacTaskName) -TaskPath (Get-WacTaskFolder) -ErrorAction Stop
    }
    catch {
        throw ("The task was registered without error but cannot be read back: {0}" -f $_.Exception.Message)
    }
    if (-not $task) { throw 'The task was registered without error but cannot be read back.' }

    $actions = @($task.Actions)
    if ($actions.Count -ne 1) {
        throw ("The registered task has {0} actions instead of exactly one." -f $actions.Count)
    }
    $action = $actions[0]

    $checks = @(
        @{ Name = 'Hidden'; Actual = [string][bool]$task.Settings.Hidden; Expected = 'True' }
        @{ Name = 'RunLevel'; Actual = [string]$task.Principal.RunLevel; Expected = 'Highest' }
        @{ Name = 'LogonType'; Actual = [string]$task.Principal.LogonType; Expected = 'ServiceAccount' }
        @{ Name = 'Compatibility'; Actual = [string]$task.Settings.Compatibility; Expected = 'Win8' }
        @{ Name = 'MultipleInstances'; Actual = [string]$task.Settings.MultipleInstances; Expected = 'IgnoreNew' }
        @{ Name = 'StartWhenAvailable'; Actual = [string][bool]$task.Settings.StartWhenAvailable; Expected = 'True' }
        @{ Name = 'Execute'; Actual = [string]$action.Execute; Expected = $ExpectedHost }
        @{ Name = 'Arguments'; Actual = [string]$action.Arguments; Expected = $ExpectedArguments }
        @{ Name = 'Description'; Actual = [string]$task.Description; Expected = $ExpectedDescription }
    )

    foreach ($check in $checks) {
        if (-not [string]::Equals([string]$check.Actual, [string]$check.Expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ("The registered task's {0} is '{1}' instead of '{2}'." -f $check.Name, $check.Actual, $check.Expected)
        }
    }

    # Compared through the canonicaliser rather than as raw text: the scheduler is free to hand a
    # directory back with a trailing separator, and a plain string compare would fail an install
    # that is in fact exactly right.
    $actualWorking = Get-WacNormalizedPath -Path ([string]$action.WorkingDirectory)
    $expectedWorking = Get-WacNormalizedPath -Path $ExpectedWorkingDirectory
    if (-not $actualWorking -or -not $expectedWorking -or ($actualWorking -ine $expectedWorking)) {
        throw ("The registered task's WorkingDirectory is '{0}' instead of '{1}'." -f [string]$action.WorkingDirectory, $ExpectedWorkingDirectory)
    }

    # UserId reads back as the account name on some builds and as the SID on others.
    $userId = [string]$task.Principal.UserId
    if ($userId -notmatch '(?i)^(SYSTEM|NT AUTHORITY\\SYSTEM|S-1-5-18)$') {
        throw ("The registered task runs as '{0}' instead of SYSTEM." -f $userId)
    }

    # ExecutionTimeLimit comes back as an ISO 8601 duration string, not a TimeSpan.
    $limit = [string]$task.Settings.ExecutionTimeLimit
    $limitSpan = [timespan]::Zero
    try { $limitSpan = [System.Xml.XmlConvert]::ToTimeSpan($limit) } catch { $limitSpan = [timespan]::Zero }
    if ($limitSpan -ne (New-TimeSpan -Hours 4)) {
        throw ("The registered task's ExecutionTimeLimit is '{0}' instead of 4 hours." -f $limit)
    }

    # The trigger is asserted too (ledger B2-3): a task registered with the wrong or an extra
    # trigger runs the cleanup at a time the operator never asked for, and until now nothing read
    # it back. StartBoundary is an ISO 8601 LOCAL datetime string, not a DateTime.
    $triggers = @($task.Triggers)
    if ($triggers.Count -ne 1) {
        throw ("The registered task has {0} triggers instead of exactly one daily trigger." -f $triggers.Count)
    }
    $triggerKind = ''
    try { $triggerKind = [string]$triggers[0].CimClass.CimClassName } catch { $triggerKind = '' }
    if ($triggerKind -and $triggerKind -notmatch '(?i)Daily') {
        throw ("The registered task's trigger is '{0}' instead of a daily trigger." -f $triggerKind)
    }
    # Unspecified, and it matters. Measured on both shipped hosts: given '...T20:00:00' the reading
    # is 20:00, and given an offset form such as '...T20:00:00+02:00' it converts to the equivalent
    # LOCAL time - which is the time the task will actually fire, and therefore the one to compare
    # against what the operator asked for. Do not "fix" this to RoundtripKind.
    $startBoundary = [string]$triggers[0].StartBoundary
    $startAt = [datetime]::MinValue
    try { $startAt = [System.Xml.XmlConvert]::ToDateTime($startBoundary, [System.Xml.XmlDateTimeSerializationMode]::Unspecified) }
    catch { throw ("The registered task's StartBoundary '{0}' is not a datetime." -f $startBoundary) }
    $actualRunTime = $startAt.ToString('HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    if (-not [string]::Equals($actualRunTime, $ExpectedRunTime, [System.StringComparison]::Ordinal)) {
        throw ("The registered task runs daily at '{0}' instead of '{1}'." -f $actualRunTime, $ExpectedRunTime)
    }

    $ownership = Test-WacTaskIsOurs -Task $task -DeploymentRoot $ExpectedWorkingDirectory
    if (-not $ownership.IsOurs) {
        throw ("The registered task does not pass its own ownership proof: {0}" -f $ownership.Reason)
    }

    return $task
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
        if ($conflict.Refused) { return 7 }
        return 1
    }

    # Phase 4: the swap, then register, then read everything back. The previous tree is KEPT until
    # the last assertion passes, so any failure from here on is fully reversible.
    $switched = Switch-WacDeploymentStage -KeepPrevious
    $description = Get-WacTaskDescription
    $arguments = Get-WacTaskActionArgument `
        -RunScript $switched.RunScript `
        -ResetWindowsUpdateBase ([bool]$ResetWindowsUpdateBase) `
        -PruneSupersededDrivers:$PruneSupersededDrivers `
        -EnableLegacyDiskCleanup:$EnableLegacyDiskCleanup

    $registered = $null
    try {
        $live = Get-WacDeploymentOwnership -DeploymentRoot $switched.DeploymentRoot
        if ($live.Kind -ne 'Managed' -or $live.Tampered) {
            throw ("What went live does not match the manifest that was staged: {0}" -f $live.Reason)
        }

        $definition = New-ScheduledTask `
            -Action (New-ScheduledTaskAction -Execute $taskHost -Argument $arguments -WorkingDirectory $switched.DeploymentRoot) `
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
            -ExpectedDescription $description -ExpectedWorkingDirectory $switched.DeploymentRoot -ExpectedRunTime $DailyRunTime
    }
    catch {
        Write-InstallerMessage -Level ERROR -Message ('The task could not be registered and verified: {0}' -f $_.Exception.Message)
        Undo-Installation -DeploymentRoot $switched.DeploymentRoot
        Write-InstallerMessage -Level ERROR -Message 'Final status: failed and rolled back. No WindowsAutoCleanup task is registered; re-run the installer once the cause above is fixed.'
        return 1
    }

    [void](Remove-WacDeploymentPrevious)

    Write-InstallerMessage -Level INFO -Message 'Scheduled task registered and verified.' -Data @{
        task = ('{0}{1}' -f $registered.TaskPath, $registered.TaskName)
        execute = $taskHost
        arguments = $arguments
        workingDirectory = $switched.DeploymentRoot
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

$script:LogReady = Initialize-WacRun -BaseName 'Install-WindowsAutoCleanupTask' -BudgetMinutes 30
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
    $logDirectory = Get-WacLogDirectory
    if ($logDirectory) {
        [void](Remove-WacOldLog -LogDirectory $logDirectory -Pattern 'Install-WindowsAutoCleanupTask_*.log' -KeepCount 30)
    }
    Close-WacLog
}

Wait-InstallerExit
exit $exitCode
