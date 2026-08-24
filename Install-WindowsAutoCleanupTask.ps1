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
      3  another installer or uninstaller instance is already running
      4  elevation was cancelled or failed
      5  unsupported environment (the online system drive is not C:)
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

function Remove-ConflictingTask {
    <#
    .SYNOPSIS
        Clears our own registration before re-registering, and refuses to touch anyone else's.
    .DESCRIPTION
        Register-ScheduledTask -Force is documented only as "without prompting for confirmation";
        nothing says it overwrites. So the installer explicitly Gets, proves ownership, then
        Unregisters (ledger P0-4). A foreign task sitting on our canonical path is fatal, because
        registering over it would destroy something we do not own.
    #>
    param([Parameter(Mandatory = $true)][string]$DeploymentRoot)

    foreach ($existing in (Get-WacInstalledTask -IncludeLegacy)) {
        $isCanonical = ([string]$existing.TaskPath -eq (Get-WacTaskFolder))

        $removal = Remove-WacInstalledTask -Task $existing -DeploymentRoot $DeploymentRoot -AllowLegacyMigration
        if ($removal.Verified) {
            Write-InstallerMessage -Level INFO -Message 'Removed the previous WindowsAutoCleanup task.' -Data @{ task = ('{0}{1}' -f $removal.TaskPath, $removal.TaskName) }
            continue
        }

        if ($isCanonical) {
            throw ("A task already occupies {0}{1} and it is not ours, so it will not be replaced: {2}" -f $existing.TaskPath, $existing.TaskName, $removal.Reason)
        }

        Write-InstallerMessage -Level WARNING -Message 'A task named WindowsAutoCleanup at the root task path was left untouched because ownership could not be proven.' -Data @{ reason = $removal.Reason }
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
        [Parameter(Mandatory = $true)][string]$ExpectedDescription
    )

    $task = $null
    try {
        $task = Get-ScheduledTask -TaskName (Get-WacTaskName) -TaskPath (Get-WacTaskFolder) -ErrorAction Stop
    }
    catch {
        throw ("The task was registered without error but cannot be read back: {0}" -f $_.Exception.Message)
    }
    if (-not $task) { throw 'The task was registered without error but cannot be read back.' }

    $action = @($task.Actions)[0]

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

    $ownership = Test-WacTaskIsOurs -Task $task
    if (-not $ownership.IsOurs) {
        throw ("The registered task does not pass its own ownership proof: {0}" -f $ownership.Reason)
    }

    return $task
}

function Invoke-Main {
    if (-not (Test-WacIsAdministrator)) {
        return (Invoke-InstallerElevation)
    }

    $script:InstanceLock = Enter-WacSingleInstance -Name 'Global\WindowsAutoCleanupInstaller'
    if (-not $script:InstanceLock) {
        Write-InstallerMessage -Level ERROR -Message 'Another WindowsAutoCleanup installer or uninstaller is already running.'
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

    $deployment = Install-WacDeployment -SourceRoot $script:ScriptRoot
    Write-InstallerMessage -Level INFO -Message 'Runtime deployed.' -Data @{ root = $deployment.DeploymentRoot; files = $deployment.FileCount }

    $trust = Test-WacDeploymentTrusted -DeploymentRoot $deployment.DeploymentRoot
    if (-not $trust.IsTrusted) {
        foreach ($entry in $trust.Untrusted) {
            Write-InstallerMessage -Level ERROR -Message 'A deployed path is not machine-trusted.' -Data @{ path = $entry.Path; owner = [string]$entry.Owner; reason = $entry.Reason }
        }
        Write-InstallerMessage -Level ERROR -Message ('Refusing to register a SYSTEM task against an untrusted deployment: {0}' -f $trust.Reason)
        return 1
    }
    Write-InstallerMessage -Level INFO -Message 'Deployment trust verified.' -Data @{ checked = $trust.CheckedCount }

    $taskHost = Get-WacCanonicalPowerShellHost
    if (-not $taskHost) {
        Write-InstallerMessage -Level ERROR -Message 'No machine-trusted PowerShell host is available for the task action.'
        return 1
    }

    $arguments = Get-WacTaskActionArgument `
        -RunScript $deployment.RunScript `
        -ResetWindowsUpdateBase ([bool]$ResetWindowsUpdateBase) `
        -PruneSupersededDrivers:$PruneSupersededDrivers `
        -EnableLegacyDiskCleanup:$EnableLegacyDiskCleanup

    $description = Get-WacTaskDescription

    Remove-ConflictingTask -DeploymentRoot $deployment.DeploymentRoot

    $definition = New-ScheduledTask `
        -Action (New-ScheduledTaskAction -Execute $taskHost -Argument $arguments -WorkingDirectory $deployment.DeploymentRoot) `
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

    $registered = Assert-RegisteredTask -ExpectedHost $taskHost -ExpectedArguments $arguments -ExpectedDescription $description

    Write-InstallerMessage -Level INFO -Message 'Scheduled task registered and verified.' -Data @{
        task = ('{0}{1}' -f $registered.TaskPath, $registered.TaskName)
        execute = $taskHost
        arguments = $arguments
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
    if ($script:LogReady) {
        [void](Remove-WacOldLog -LogDirectory (Split-Path -Parent (Get-WacLogPath)) -Pattern 'Install-WindowsAutoCleanupTask_*.log' -KeepCount 30)
    }
    Close-WacLog
}

Wait-InstallerExit
exit $exitCode
