#Requires -Version 5.1

<#
.SYNOPSIS
    Removes the WindowsAutoCleanup scheduled task and the %ProgramFiles% deployment.

.DESCRIPTION
    The task is unregistered only after it proves it belongs to this project: v1.1.0 deleted any
    task named WindowsAutoCleanup by name alone. The pre-1.2 task at the root task path is adopted
    when its description and action still match what the old installer wrote.

    Only %ProgramFiles%\WindowsAutoCleanup and its swap slots are deleted. This checkout is never
    touched, and neither is anything outside those three paths.

    Actions are written to %ProgramData%\WindowsAutoCleanup\Logs and printed to the console.

.PARAMETER NoPause
    Do not wait for a key press before exiting. For automation and tests.

.PARAMETER RemoveLogs
    Also delete the log files under %ProgramData%\WindowsAutoCleanup\Logs. Logs are kept by
    default. The log this run is writing survives so the uninstall stays auditable.

.PARAMETER KeepLogs
    Keep the log files even when -RemoveLogs is also passed. Use it to make the safe choice
    explicit in a script whose flags come from somewhere else.

.EXAMPLE
    .\Uninstall-WindowsAutoCleanupTask.ps1 -NoPause -RemoveLogs

.NOTES
    Exit codes:
      0  success
      1  error, or a removal that could not be verified
      3  another installer or uninstaller instance is already running
      4  elevation was cancelled or failed
      5  unsupported environment (the deployment root cannot be resolved)
#>

# Write-Host is deliberate: the uninstaller is a user-facing console tool and the structured
# record goes to the file log separately.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Console output is the point of an interactive installer; the file log is written through Write-WacLog.')]
[CmdletBinding()]
param(
    [switch]$NoPause,

    [switch]$RemoveLogs,

    [switch]$KeepLogs
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Same reason as the installer (ledger P0-2): inside a function $PSBoundParameters is that
# function's own, so the script's must be captured here, before anything else runs.
$script:BoundParameter = @{}
foreach ($key in $PSBoundParameters.Keys) { $script:BoundParameter[$key] = $PSBoundParameters[$key] }

$script:ScriptRoot = Split-Path -Parent $PSCommandPath
$script:LogReady = $false
$script:InstanceLock = $null
$script:Relaunched = $false
$script:ElevationTimeoutMs = 600000

Import-Module -Name (Join-Path -Path $script:ScriptRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') -DisableNameChecking -Force -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:ScriptRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') -DisableNameChecking -Force -ErrorAction Stop

function Write-UninstallerMessage {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Data
    )

    if ($script:LogReady) {
        if ($Data) { Write-WacLog -Level $Level -Component 'Uninstaller' -Message $Message -Data $Data }
        else { Write-WacLog -Level $Level -Component 'Uninstaller' -Message $Message }
    }

    $colour = switch ($Level) {
        'WARNING' { 'Yellow' }
        'ERROR' { 'Red' }
        'CRITICAL' { 'Red' }
        default { 'Gray' }
    }
    Write-Host ('[{0}] {1}' -f $Level, $Message) -ForegroundColor $colour
}

function Wait-UninstallerExit {
    if ($NoPause) { return }
    if ($script:Relaunched) { return }
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

function Invoke-UninstallerElevation {
    <#
    .SYNOPSIS
        Relaunches this script elevated and returns the child's real exit code.
    .DESCRIPTION
        Inside the main try (ledger P1-12) so a cancelled UAC prompt is logged, honours -NoPause and
        exits 4. wt.exe is never used as the wrapper: it is PATH-resolved and swallows the exit code.
    #>
    $hostPath = Get-WacCanonicalPowerShellHost
    if (-not $hostPath) {
        Write-UninstallerMessage -Level ERROR -Message 'No machine-trusted PowerShell host was found for the elevated relaunch.'
        return 4
    }

    $present = New-Object 'System.Collections.Generic.List[string]'
    if ($NoPause) { [void]$present.Add('NoPause') }
    if ($RemoveLogs) { [void]$present.Add('RemoveLogs') }
    if ($KeepLogs) { [void]$present.Add('KeepLogs') }

    $vector = Get-WacRelaunchArgument -ScriptPath $PSCommandPath -PresentSwitch @($present.ToArray())
    $commandLine = ConvertTo-WacCommandLine -ArgumentList $vector

    Write-UninstallerMessage -Level INFO -Message 'Requesting elevation.' -Data @{
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
        Write-UninstallerMessage -Level ERROR -Message ('Elevation was cancelled or failed: {0}' -f $_.Exception.Message)
        return 4
    }

    if (-not $child) {
        Write-UninstallerMessage -Level ERROR -Message 'Elevation returned no child process.'
        return 4
    }

    try { $null = $child.Handle } catch { $null = $_ }

    if (-not $child.WaitForExit($script:ElevationTimeoutMs)) {
        Write-UninstallerMessage -Level ERROR -Message 'The elevated uninstaller did not finish inside its deadline.' -Data @{ pid = $child.Id; timeoutMs = $script:ElevationTimeoutMs }
        return 1
    }

    $code = 1
    try { $code = [int]$child.ExitCode } catch { $code = 1 }
    Write-UninstallerMessage -Level INFO -Message 'The elevated uninstaller finished.' -Data @{ exitCode = $code }
    return $code
}

function Remove-InstalledTask {
    <#
    .SYNOPSIS
        Removes our task wherever it is registered. Returns $true when nothing of ours is left.
    #>
    param([Parameter(Mandatory = $true)][string]$DeploymentRoot)

    $tasks = @(Get-WacInstalledTask -IncludeLegacy)
    if ($tasks.Count -eq 0) {
        Write-UninstallerMessage -Level INFO -Message 'No WindowsAutoCleanup task is registered. Nothing to remove.'
        return $true
    }

    $clean = $true
    foreach ($task in $tasks) {
        $removal = Remove-WacInstalledTask -Task $task -DeploymentRoot $DeploymentRoot -AllowLegacyMigration
        $label = '{0}{1}' -f $removal.TaskPath, $removal.TaskName

        if ($removal.Verified) {
            Write-UninstallerMessage -Level INFO -Message 'Scheduled task removed and verified absent.' -Data @{ task = $label }
            continue
        }

        if ($removal.Removed) {
            Write-UninstallerMessage -Level ERROR -Message 'The task was unregistered but is still present.' -Data @{ task = $label; reason = $removal.Reason }
            $clean = $false
            continue
        }

        # Not ours: leaving someone else's task alone is the correct outcome, not a failure.
        Write-UninstallerMessage -Level WARNING -Message 'A task with this name was left in place because it does not belong to WindowsAutoCleanup.' -Data @{ task = $label; reason = $removal.Reason }
    }

    return $clean
}

function Remove-InstalledDeployment {
    <#
    .SYNOPSIS
        Deletes the deployment root and any leftover swap slot. Returns $true on success.
    #>
    param([Parameter(Mandatory = $true)]$Slots)

    $source = Get-WacNormalizedPath -Path $script:ScriptRoot
    if ($source -and (Test-WacIsWithinRoot -ChildPath $source -RootPath $Slots.Root)) {
        Write-UninstallerMessage -Level WARNING -Message 'This script is running from inside the deployment root, so the deployment was left in place. Run the uninstaller from your own checkout.' -Data @{ root = $Slots.Root }
        return $false
    }

    $clean = $true
    foreach ($path in @($Slots.Root, $Slots.Staging, $Slots.Previous)) {
        if (-not (Test-Path -LiteralPath $path)) { continue }

        $removal = Remove-WacDeployment -Path $path
        if ($removal.Removed) {
            Write-UninstallerMessage -Level INFO -Message 'Deployment directory removed.' -Data @{ path = $path }
        }
        else {
            Write-UninstallerMessage -Level ERROR -Message 'The deployment directory could not be fully removed.' -Data @{ path = $path; reason = [string]$removal.Reason }
            $clean = $false
        }
    }

    return $clean
}

function Remove-RetainedLog {
    <#
    .SYNOPSIS
        Deletes the stored log files, except the one this run is writing.
    #>
    $logPath = Get-WacLogPath
    $directory = if ($logPath) { Split-Path -Parent $logPath } else { Join-Path -Path (Get-WacDataRoot) -ChildPath 'Logs' }
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { return }

    $removed = 0
    foreach ($file in @(Get-ChildItem -LiteralPath $directory -Filter '*.log' -File -ErrorAction SilentlyContinue)) {
        if ($logPath -and $file.FullName -ieq $logPath) { continue }
        try { [System.IO.File]::Delete($file.FullName); $removed++ } catch { $null = $_ }
    }

    Write-UninstallerMessage -Level INFO -Message 'Log files removed.' -Data @{ directory = $directory; removed = $removed; kept = [string]$logPath }
}

function Invoke-Main {
    if (-not (Test-WacIsAdministrator)) {
        return (Invoke-UninstallerElevation)
    }

    $script:InstanceLock = Enter-WacSingleInstance -Name 'Global\WindowsAutoCleanupInstaller'
    if (-not $script:InstanceLock) {
        Write-UninstallerMessage -Level ERROR -Message 'Another WindowsAutoCleanup installer or uninstaller is already running.'
        return 3
    }

    $slots = Get-WacDeploymentSlotPath
    if (-not $slots) {
        Write-UninstallerMessage -Level ERROR -Message 'The deployment root cannot be resolved on this machine.'
        return 5
    }

    Write-UninstallerMessage -Level INFO -Message 'Running elevated.' -Data @{ root = $slots.Root; log = [string](Get-WacLogPath) }

    # The installer and Run.ps1 both prune to 30; without this, repeated uninstall attempts grow
    # %ProgramData%\WindowsAutoCleanup\Logs forever and the documented retention is simply untrue.
    [void](Remove-WacOldLog -LogDirectory (Split-Path -Parent (Get-WacLogPath)) `
        -Pattern 'Uninstall-WindowsAutoCleanupTask_*.log' -KeepCount 30)

    Import-Module -Name 'ScheduledTasks' -ErrorAction Stop

    $taskClean = Remove-InstalledTask -DeploymentRoot $slots.Root
    $deploymentClean = Remove-InstalledDeployment -Slots $slots

    if ($RemoveLogs -and $KeepLogs) {
        Write-UninstallerMessage -Level WARNING -Message '-KeepLogs overrides -RemoveLogs; the log files were kept.'
    }
    elseif ($RemoveLogs) {
        Remove-RetainedLog
    }
    else {
        Write-UninstallerMessage -Level INFO -Message 'Log files were kept. Pass -RemoveLogs to delete them.' -Data @{ directory = (Join-Path -Path (Get-WacDataRoot) -ChildPath 'Logs') }
    }

    if (-not $taskClean -or -not $deploymentClean) {
        Write-UninstallerMessage -Level ERROR -Message 'Final status: incomplete. See the errors above.'
        return 1
    }

    Write-UninstallerMessage -Level INFO -Message 'Final status: success.'
    return 0
}

$script:LogReady = Initialize-WacRun -BaseName 'Uninstall-WindowsAutoCleanupTask' -BudgetMinutes 30
if (-not $script:LogReady) {
    Write-Host '[WARNING] No log file could be created; continuing with console output only.' -ForegroundColor Yellow
}

# Logged before the admin branch so a relaunch that never happens is still explained by the log.
Write-UninstallerMessage -Level INFO -Message 'Uninstaller invoked.' -Data @{
    host = ('{0} {1}' -f $PSVersionTable.PSEdition, $PSVersionTable.PSVersion)
    source = $script:ScriptRoot
    elevated = [bool](Test-WacIsAdministrator)
    explicitParameters = (@($script:BoundParameter.Keys | Sort-Object) -join ',')
}

$exitCode = 1
try {
    $exitCode = Invoke-Main
}
catch {
    Write-UninstallerMessage -Level ERROR -Message ('Uninstaller failed: {0}' -f $_.Exception.Message)
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-UninstallerMessage -Level ERROR -Message ('At: {0}' -f $_.InvocationInfo.PositionMessage)
    }
    $exitCode = 1
}
finally {
    Exit-WacSingleInstance -Mutex $script:InstanceLock
    Close-WacLog
}

Wait-UninstallerExit
exit $exitCode
